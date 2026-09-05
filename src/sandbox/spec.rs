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
//! [`SandboxSpec::dies_with_launcher`] is the one hardening flag that is a field, and it is
//! here precisely because it is not a removal: `--die-with-parent` names a *relationship*
//! to a supervising process, so the one launch that has no such process cannot be described
//! without it.

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
    /// A host device node (or a directory of them) bound at `dest` **with device access** — the
    /// escape hatch a [`Mount::Dev`] tree deliberately lacks. Emitted only from a trusted
    /// `[devices] allow`, and only *after* the [`Mount::Dev`] that sets up the minimal `/dev`, so it
    /// layers a real device (`/dev/dri`, `/dev/kvm`, `/dev/net/tun`) over the hostless default. A
    /// `-try` mount: a source absent on this host is skipped, so a portable profile still launches.
    DevBind { src: PathBuf, dest: PathBuf },
    /// A fresh, private tmpfs at `dest`.
    Tmpfs { dest: PathBuf },
}

impl Mount {
    /// The in-cage destination this mount occupies; every variant has exactly one.
    ///
    /// Read by the distribution-userland filter, which drops the synthetic FHS an image supplies
    /// itself, and by the test that pins the structural-mount destination list against what
    /// `assemble` emits.
    pub(crate) fn dest(&self) -> &std::path::Path {
        match self {
            Mount::RoBind { dest, .. }
            | Mount::RoBindTry { dest, .. }
            | Mount::Bind { dest, .. }
            | Mount::Symlink { dest, .. }
            | Mount::Proc { dest }
            | Mount::Dev { dest }
            | Mount::DevBind { dest, .. }
            | Mount::Tmpfs { dest } => dest,
        }
    }
}

/// Network posture at the namespace level: the cage either shares the host network or gets a fresh
/// empty netns. The egress allowlist (a filtering posture) is built ON `Isolated` — the cage's only
/// egress is then a bound Unix socket to the host MITM proxy, where the filtering actually lives (see
/// the `Isolated` variant), so this enum stays the two namespace choices, not the policy.
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
    ///
    /// None of it appears in bubblewrap's argument list. A process's arguments are world-readable
    /// (`/proc/<pid>/cmdline` is mode `444`) while its environment is not (`400`), so every variable
    /// reaches bwrap through `--args` on an anonymous in-memory file and only a descriptor number is
    /// ever visible to another uid.
    pub(super) env: Vec<(String, String)>,
    /// Credentials sbx resolved for this cage, kept apart from [`SandboxSpec::env`] for one reason:
    /// they are applied **before** it. A credential that took the name of the cage's own plumbing
    /// (`PATH`, `HOME`) must lose to the plumbing, not displace it — a name declared as both is
    /// refused where the two are declared. Both travel the same way, on the same descriptor.
    pub(super) secret_env: Vec<(String, String)>,
    /// Whether the host network is shared or fully cut off.
    pub(super) net: NetPolicy,
    /// How the terminal session is established. [`SandboxSpec::new`] defaults it
    /// to [`TerminalPolicy::NewSession`]; the pty supervisor opts into
    /// [`TerminalPolicy::PrivateTty`] via [`SandboxSpec::with_private_tty`].
    pub(super) terminal: TerminalPolicy,
    /// The program and its arguments; `cmd[0]` is the executable.
    pub(super) cmd: Vec<OsString>,
    /// The cage's readable name slug (the app or project the launch is for), shown on
    /// every face a cage surfaces through — the systemd scope, the in-cage hostname, the
    /// session listing. [`SandboxSpec::new`] defaults it to `cage`; the real launch path
    /// sets it via [`SandboxSpec::with_cage_slug`].
    pub(super) cage_slug: String,
    /// The relaxation of the mandatory seccomp denylist, from a trusted `[seccomp] allow`.
    ///
    /// [`SandboxSpec::new`] defaults it to empty — the full mandatory denylist, identical to a
    /// cage with no `[seccomp]` config; the launch path sets a non-empty one via
    /// [`SandboxSpec::with_seccomp`]. Read by [`super::argv::compose`], which compiles the filters
    /// and prepends them as `--add-seccomp-fd` descriptors, and not by [`super::argv::to_argv`],
    /// which stays a pure function of the rest of this type.
    pub(super) seccomp: super::seccomp::SeccompPolicy,
    /// When set, the cage's network namespace is provided by the netns holder (which pre-creates
    /// it with a dummy interface up) instead of by bwrap's own `--unshare-net`. A graphical app
    /// under an isolated netns (empty except loopback) sees itself as *offline* — Chromium's
    /// connectivity detection reports "no network interface" for a loopback-only namespace — so a
    /// black-hole `dummy0` is added purely to make it report online; egress stays forced through
    /// the proxy on loopback (the dummy has no route). Some means the launch is holder-wrapped and
    /// `to_argv` maps the cage back to these host credentials (the holder runs root-in-userns);
    /// None is the ordinary path (bwrap emits `--unshare-net`). See [`NetnsDummy`].
    pub(super) netns_dummy: Option<NetnsDummy>,
    /// Whether bwrap is given `--die-with-parent`, which arms `PR_SET_PDEATHSIG` so the cage cannot
    /// outlive the process supervising it. True for every launch but one, and
    /// [`SandboxSpec::outliving_its_launcher`] is the only thing that clears it.
    ///
    /// The exception is a detached launch with no guard, where the daemon `exec`s bwrap in place
    /// rather than supervising it. bwrap then inherits the daemon's parent — the short-lived
    /// launcher that reports the session id and exits — so the flag names a process whose whole
    /// purpose is to go away, and `--detach` promises the cage outlives exactly that. Whether the
    /// signal fires is a race between the launcher's exit and bwrap's `prctl`: measured on this
    /// host, a launcher still alive at that instant kills the session the moment it exits, four
    /// times out of four, while the ordinary ordering (launcher gone first, cage reparented to the
    /// user's subreaper) leaves it running. The supervised branch keeps the flag, and must: there
    /// the daemon is a real long-lived parent whose death should cascade.
    pub(super) dies_with_launcher: bool,
    /// Whether the cage is mapped to uid 0 **inside its own user namespace** (`--uid 0 --gid 0`).
    ///
    /// False for every launch, which keeps the same-uid model the rest of this type is built
    /// around: a process in the cage runs as the invoking user, so what it may touch on a bind is
    /// what that user may touch.
    ///
    /// True only for a `[distro] run` build, and there because a distribution's own package tools
    /// refuse to run otherwise: `dpkg` exits with "requested operation requires superuser
    /// privilege" on a `geteuid()` check, before touching anything. It buys no privilege on the
    /// host — the mapping is inside an unprivileged user namespace, so uid 0 there is the invoking
    /// user outside, and a file the build writes is owned by that user. Exactly one uid can be
    /// mapped without a setuid helper, so it is 0 and nothing else: a package that insists on
    /// giving a file to some *other* uid still fails, and fails saying so.
    pub(super) as_root: bool,
}

/// The netns-holder wiring for a cage that needs a `dummy0` interface (see
/// [`SandboxSpec::netns_dummy`]). Carries the host credentials the cage is mapped back to and the
/// path to sbx's own binary (the `__netns-holder` subcommand), resolved once at build time so the
/// launch never falls back to a namespace without `--unshare-net` (which would share the host
/// network — a fail-open the holder path must never reach).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetnsDummy {
    /// The host uid the cage is mapped to (`--uid`), preserving the same-uid model.
    pub(super) uid: u32,
    /// The host gid the cage is mapped to (`--gid`).
    pub(super) gid: u32,
    /// Absolute path to sbx's own binary, invoked as `<exe> __netns-holder <bwrap> <args…>`.
    pub(super) holder_exe: PathBuf,
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
            secret_env: Vec::new(),
            net,
            terminal: TerminalPolicy::NewSession,
            cmd,
            cage_slug: "cage".to_string(),
            as_root: false,
            seccomp: super::seccomp::SeccompPolicy::default(),
            netns_dummy: None,
            dies_with_launcher: true,
        })
    }

    /// Map this cage to uid 0 inside its own user namespace. See [`Self::as_root`] for what that
    /// does and does not buy; only a `[distro] run` build calls it.
    pub(crate) fn rooted_in_its_namespace(mut self) -> Self {
        self.as_root = true;
        self
    }

    /// Drop `--die-with-parent` for a cage that has no supervising parent to die with — the
    /// detached, guardless branch that replaces its own daemon with bwrap. See
    /// [`SandboxSpec::dies_with_launcher`] for what the flag would otherwise be armed against, and
    /// why keeping it there can only ever kill a session `--detach` promised to keep.
    pub(super) fn outliving_its_launcher(mut self) -> Self {
        self.dies_with_launcher = false;
        self
    }

    /// Route this launch through the netns holder so the cage's network namespace carries a
    /// black-hole `dummy0` interface (see [`SandboxSpec::netns_dummy`]). The launch path sets it
    /// only for a graphical (`gui = "wayland"`) cage under an isolated netns, and only once sbx's
    /// own binary path is known — so `to_argv` can safely drop `--unshare-net` in favour of the
    /// holder-provided namespace without ever risking a namespace-less (host-network) fallback.
    pub(crate) fn with_netns_dummy(mut self, holder: NetnsDummy) -> Self {
        self.netns_dummy = Some(holder);
        self
    }

    /// Set the variables whose values must stay out of the argument list — see
    /// [`SandboxSpec::secret_env`]. Only [`super::argv::compose`] can turn such a spec into a
    /// runnable argv, because only it can create the descriptor they travel on.
    pub(crate) fn with_secret_env(mut self, env: Vec<(String, String)>) -> Self {
        self.secret_env = env;
        self
    }

    /// Set the cage's readable name slug (see [`SandboxSpec::cage_slug`]). The launch path
    /// derives it from the app or project via [`super::naming::cage_slug`].
    pub(crate) fn with_cage_slug(mut self, slug: String) -> Self {
        self.cage_slug = slug;
        self
    }

    /// Set the trusted seccomp relaxation (see [`SandboxSpec::seccomp`]). The launch path derives
    /// it from the resolved `[seccomp] allow`; a default (empty) policy is the mandatory denylist.
    pub(crate) fn with_seccomp(mut self, seccomp: super::seccomp::SeccompPolicy) -> Self {
        self.seccomp = seccomp;
        self
    }

    /// This cage's filesystem exposure, for deriving a **sibling** cage from it (the task engine
    /// filters it down to the structural skeleton). Read-only: a derived cage is built by
    /// constructing a new spec, never by mutating this one.
    pub(crate) fn mounts(&self) -> &[Mount] {
        &self.mounts
    }

    /// This cage's environment, for the same derivation.
    pub(crate) fn env(&self) -> &[(String, String)] {
        &self.env
    }

    /// This cage's readable slug, for naming a derived cage's cgroup scope.
    pub(crate) fn cage_slug(&self) -> &str {
        &self.cage_slug
    }

    /// Switch to a private-pty terminal (see [`TerminalPolicy::PrivateTty`]).
    ///
    /// The caller **must** then launch through the pty supervisor; otherwise the
    /// sandbox would inherit the launching terminal. An interactive `sbx run`
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
