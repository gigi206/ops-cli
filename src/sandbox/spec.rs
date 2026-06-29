//! The declarative description of a sandbox and the invariants enforced when one
//! is built.
//!
//! The Spec is the single source of truth for everything the sandbox exposes;
//! [`super::argv::to_argv`] turns it into a bubblewrap argv as a pure function.
//! Construction goes through [`SandboxSpec::new`], which fails closed: it refuses
//! a spec it could not launch safely. The mandatory hardening (cleared
//! environment, all namespaces incl. pid, dropped capabilities, fresh session)
//! is deliberately *not* expressed here as toggleable state — it is emitted
//! unconditionally by `to_argv`, so an unhardened sandbox is unrepresentable.

use std::ffi::OsString;
use std::path::PathBuf;

/// One filesystem exposure inside the sandbox. The set of `Mount`s is the *only*
/// source of filesystem visibility: the sandbox starts from nothing, so a path
/// absent from this list is absent from the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mount {
    /// Host `src` visible read-only at `dest`. Read-only protects integrity, not
    /// confidentiality — a secret must be *absent*, not merely read-only.
    RoBind { src: PathBuf, dest: PathBuf },
    /// Like [`Mount::RoBind`] but a missing `src` is skipped rather than fatal —
    /// for host paths that may legitimately be absent (TLS certs, `resolv.conf`).
    RoBindTry { src: PathBuf, dest: PathBuf },
    /// Host `src` visible read-write at `dest`. The work surface (project, home).
    Bind { src: PathBuf, dest: PathBuf },
    /// A symlink created at `dest` pointing at `target`, resolved inside the
    /// sandbox.
    Symlink { target: PathBuf, dest: PathBuf },
    /// A fresh procfs at `dest`.
    Proc { dest: PathBuf },
    /// A minimal device tree at `dest` (null/zero/urandom/tty…), never the host's.
    Dev { dest: PathBuf },
    /// A fresh, private tmpfs at `dest`.
    Tmpfs { dest: PathBuf },
}

/// Network posture. The egress allowlist is future work; for now a sandbox
/// either shares the host network or is fully isolated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetPolicy {
    /// Keep the host network namespace — no network isolation (the `network = "shared"` posture).
    Shared,
    /// A fresh, empty network namespace. Used by `network = "none"` (no connectivity at all) and
    /// as the substrate for the egress allowlist — under a filtering posture the cage's only egress
    /// is a bound Unix socket to the host MITM proxy, so the filtering lives in that proxy, not in
    /// the netns.
    Isolated,
}

/// How the sandbox's terminal session is established. Both options keep the
/// sandbox unable to reach the *launching* terminal — they differ only in how.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TerminalPolicy {
    /// bubblewrap starts a fresh session (`--new-session`, a fresh `setsid`). The
    /// sandbox ends up with no controlling terminal, which blocks terminal
    /// injection (`TIOCSTI`) but also leaves no job control — right for a
    /// non-interactive command.
    NewSession,
    /// The launcher hands the sandbox a *private* controlling terminal: a pty
    /// whose master only the launcher holds. Job control works inside, and the
    /// launching terminal stays unreachable (it is not the sandbox's terminal,
    /// and the master is never bound in). `--new-session` is therefore *omitted*
    /// — it would `setsid` away from that private terminal — so this is only safe
    /// when the launcher actually provides the pty.
    PrivateTty,
}

/// Why a [`SandboxSpec`] could not be built. Construction fails closed rather
/// than launch something underspecified.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SpecError {
    /// `workdir` was not absolute; bubblewrap's `--chdir` needs an absolute path
    /// that exists inside the sandbox.
    WorkdirNotAbsolute(PathBuf),
    /// `cmd` was empty; there would be nothing to exec.
    EmptyCommand,
}

/// A fully-resolved, declarative description of one sandbox. Built only through
/// [`SandboxSpec::new`]; [`super::argv::to_argv`] is a pure function of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SandboxSpec {
    /// Working directory inside the sandbox; must be absolute.
    pub(super) workdir: PathBuf,
    /// The sandbox's entire filesystem exposure, in apply order (a later mount
    /// shadows an earlier one at the same path, so the order is load-bearing).
    pub(super) mounts: Vec<Mount>,
    /// Variables to set *after* the environment is cleared, in declaration
    /// order. The clear itself is unconditional, so nothing leaks in by
    /// inheritance.
    pub(super) env: Vec<(String, String)>,
    /// Whether the host network is shared or fully cut off.
    pub(super) net: NetPolicy,
    /// How the terminal session is established. [`SandboxSpec::new`] defaults it
    /// to [`TerminalPolicy::NewSession`]; the pty supervisor opts into
    /// [`TerminalPolicy::PrivateTty`] via [`SandboxSpec::with_private_tty`].
    pub(super) terminal: TerminalPolicy,
    /// The program and its arguments; `cmd[0]` is the executable.
    pub(super) cmd: Vec<OsString>,
}

impl SandboxSpec {
    /// Build a spec, failing closed on anything that could not be launched
    /// safely. The mandatory *removals* (cleared environment, dropped
    /// capabilities, every namespace) are not parameters — they are emitted
    /// unconditionally at argv time. The terminal session defaults to the
    /// non-interactive [`TerminalPolicy::NewSession`]; an interactive launcher
    /// opts into a private pty via [`SandboxSpec::with_private_tty`].
    pub(crate) fn new(
        workdir: PathBuf,
        mounts: Vec<Mount>,
        env: Vec<(String, String)>,
        net: NetPolicy,
        cmd: Vec<OsString>,
    ) -> Result<Self, SpecError> {
        if !workdir.is_absolute() {
            return Err(SpecError::WorkdirNotAbsolute(workdir));
        }
        if cmd.is_empty() {
            return Err(SpecError::EmptyCommand);
        }
        Ok(Self {
            workdir,
            mounts,
            env,
            net,
            terminal: TerminalPolicy::NewSession,
            cmd,
        })
    }

    /// Switch to a private-pty terminal (see [`TerminalPolicy::PrivateTty`]).
    /// The caller **must** then launch through the pty supervisor; otherwise the
    /// sandbox would inherit the launching terminal. The interactive `ops shell`
    /// path opts in through this.
    pub(crate) fn with_private_tty(mut self) -> Self {
        self.terminal = TerminalPolicy::PrivateTty;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> SandboxSpec {
        SandboxSpec::new(
            PathBuf::from("/work"),
            vec![],
            vec![],
            NetPolicy::Shared,
            vec![OsString::from("/bin/true")],
        )
        .expect("minimal spec is valid")
    }

    #[test]
    fn new_accepts_a_minimal_valid_spec() {
        let spec = minimal();
        assert_eq!(spec.workdir, PathBuf::from("/work"));
        assert_eq!(spec.net, NetPolicy::Shared);
        assert_eq!(spec.cmd, vec![OsString::from("/bin/true")]);
    }

    #[test]
    fn new_rejects_a_relative_workdir() {
        let err = SandboxSpec::new(
            PathBuf::from("relative/dir"),
            vec![],
            vec![],
            NetPolicy::Shared,
            vec![OsString::from("/bin/true")],
        )
        .unwrap_err();
        assert_eq!(
            err,
            SpecError::WorkdirNotAbsolute(PathBuf::from("relative/dir"))
        );
    }

    #[test]
    fn new_rejects_an_empty_command() {
        let err = SandboxSpec::new(
            PathBuf::from("/work"),
            vec![],
            vec![],
            NetPolicy::Shared,
            vec![],
        )
        .unwrap_err();
        assert_eq!(err, SpecError::EmptyCommand);
    }
}
