//! Translation of a [`SandboxSpec`] into a bubblewrap argv.
//!
//! This is the security keystone's second half: [`to_argv`] adds *no* exposure
//! of its own. Every mount, variable, and namespace it emits comes from the
//! Spec; the only things it adds unconditionally are the mandatory hardening
//! flags, and those only ever *remove* privilege. The returned vector is the
//! argument list for `bwrap` — the `bwrap` program itself is not included.
//!
//! Two hardening flags are read off the Spec rather than added unconditionally, and both
//! describe a relationship rather than a removal: `--new-session` (omitted for the private-pty
//! terminal, which establishes its own) and `--die-with-parent` (omitted for the one launch with
//! no supervising process to die with — see [`SandboxSpec::dies_with_launcher`]).
//!
//! The cage's **environment** is the one thing that does not travel in that list. A process's
//! arguments are world-readable (`/proc/<pid>/cmdline` is mode `444`) while its environment is not
//! (`400`), so `--setenv VAR <value>` publishes every value to every uid on the machine for as long
//! as the cage runs. The variables go on a descriptor instead ([`compose`]), which is where the two
//! halves meet: [`to_argv`] stays pure and marks the place, and `compose` — the one impure step —
//! creates the descriptor and fills its number in.
//!
//! The mandatory seccomp filters are compiled in that same impure step, and for the same reason
//! they are here rather than at each call site: they are descriptors too, so only a step that may
//! create one can name them, and every path from a spec to a process goes through this one. What
//! that buys is that an unfiltered cage is not something a caller can assemble by forgetting a
//! line.

use super::spec::{Mount, NetPolicy, SandboxSpec, TerminalPolicy};
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

fn lit(s: &str) -> OsString {
    OsString::from(s)
}

fn path(p: &Path) -> OsString {
    p.as_os_str().to_os_string()
}

/// What stands in for the descriptor carrying the cage's environment until [`compose`] can create
/// it. Not a number, so a spec that skipped that step cannot accidentally name a descriptor this
/// process happens to hold — bwrap refuses it loudly instead.
const ENV_ARGS_PLACEHOLDER: &str = "@sbx-env-args";

/// `bwrap` running `spec`: its argument list, and the descriptors that list makes it read, the
/// compiled seccomp filters then the cage's environment, bound in one [`CageCommand`].
///
/// This is the **one** place a spec becomes a runnable argument list, and that is why the filters
/// are compiled here rather than by each caller. They are mandatory on every launch path, and a
/// step a caller has to remember is a step some caller will not take: a cage assembled without it
/// is indistinguishable from a hardened one until something inside it makes a syscall the denylist
/// exists to refuse. Folding them in leaves nothing to remember and nothing to get wrong. The
/// relaxation a trusted `[seccomp] allow` grants travels on the spec ([`SandboxSpec::seccomp`]), so
/// a cage that declared none gets the full mandatory denylist.
///
/// The descriptors come back inside the command rather than beside it for the same reason: a step
/// the caller has to take to keep them, and another to hand them to the exec, are steps some caller
/// will not take ([`CageCommand`]).
pub(crate) fn compose(bwrap: &Path, spec: &SandboxSpec) -> io::Result<CageCommand> {
    compose_with(bwrap, spec, None)
}

/// [`compose`], with bubblewrap also asked to report on `status` (`--json-status-fd`), the write end
/// of a pipe the caller reads once the cage has been reaped.
///
/// What it writes there is bubblewrap's own word on whether it set the cage up: an `exit-code` line
/// comes only once its setup reached the `execvp` and that call succeeded, and not when the setup
/// failed or the program could not be run (`report_child_exit_status`, which reads the byte the
/// child writes just before its `execvp`). The sandboxed child closes the descriptor before its
/// setup, so the cage never holds it. A duplicate travels in the command like the other
/// descriptors, and `None` builds exactly what [`compose`] builds.
pub(crate) fn compose_with(
    bwrap: &Path,
    spec: &SandboxSpec,
    status: Option<&File>,
) -> io::Result<CageCommand> {
    let mut argv = to_argv(spec);
    // Each held bind source a mount takes travels as a copy of its descriptor, owned by the command
    // like the others, so the spec keeps its own and can be composed again; the list names the copy.
    // One no mount takes is not handed at all: bwrap closes only the descriptors it mounts, and the
    // cage would inherit the rest, a host directory open beneath whatever read-only bind shows it.
    let mut sources: Vec<File> = Vec::with_capacity(spec.held_sources.len());
    for held in &spec.held_sources {
        let spec_number = OsString::from(held.fd.as_raw_fd().to_string());
        let Some(at) = held_slots(&argv).find(|&at| argv[at] == spec_number) else {
            continue;
        };
        let copy = File::from(held.fd.try_clone()?);
        argv[at] = OsString::from(copy.as_raw_fd().to_string());
        sources.push(copy);
    }
    let mut filters = crate::sandbox::seccomp::memfds(&spec.seccomp)?;
    // A cage rooted in its own namespace holds one id, so a change of ownership can only fail
    // there; it is answered with success instead (`seccomp::ownership_noop_memfd`).
    if spec.as_root {
        filters.push(crate::sandbox::seccomp::ownership_noop_memfd()?);
    }
    // The prefix names the filter descriptors and only those, so it is built before the
    // environment's descriptor joins them: the two kinds share a lifetime, not a meaning.
    let mut full = argv_prefix(&filters);
    let mut held = filters;
    if let Some(status) = status {
        let status = status.try_clone()?;
        full.push(lit("--json-status-fd"));
        full.push(OsString::from(status.as_raw_fd().to_string()));
        held.push(status);
    }
    if let Some(file) = env_fd(spec)? {
        let at = env_args_slot(&argv)?;
        argv[at] = OsString::from(file.as_raw_fd().to_string());
        held.push(file);
    }
    held.extend(sources);
    full.extend(argv);
    Ok(CageCommand {
        program: bwrap.to_path_buf(),
        args: full,
        files: held,
    })
}

/// A cage's launch command before it is a process: the program, its argument list, and the
/// descriptors that list names by number (the compiled seccomp filters, the cage's environment,
/// and whatever a caller [hands](CageCommand::hand) or [stages](CageCommand::stage) on it).
///
/// The three travel together because none of them works alone. bwrap reads each descriptor by the
/// number its argument list carries, and the descriptors are close-on-exec in this process
/// ([`super::memfd::write`]). A command started from the list without them, or with them but
/// without the preparation that clears the flag in its child, reaches bwrap with those numbers
/// already closed, and the cage refuses with `Bad file descriptor` on whichever path that was. Here
/// the only ways out carry the descriptors along, so neither mistake can be written:
///
/// - [`CageCommand::into_command`], a `Command` that owns the descriptors and hands them to its own
///   exec and to no other;
/// - [`CageCommand::into_command_alone`], the same for a process that holds inheritable descriptors
///   of its own and must pass none of them on;
/// - [`CageCommand::fork_parts`], the one place the raw numbers leave, for the pty supervisor's fork
///   written by hand. The value it borrows from holds the descriptors, so that caller keeps it
///   until its child has exec'd.
///
/// What this does **not** check: that the list carries the filters and the resource scope its
/// launch owes, which the guard in this module's tests does, and that a number a caller wrote into
/// the cage's own command is among the descriptors held here. Two such numbers exist: the proxy's
/// `__proxy <fd>` and `selfcage`'s `/proc/self/fd/<binary>`. A number [`CageCommand::stage`]
/// returns is held by construction.
#[derive(Debug)]
pub(crate) struct CageCommand {
    program: PathBuf,
    args: Vec<OsString>,
    files: Vec<File>,
}

impl CageCommand {
    /// The same command behind a wrapper that rewrites what is executed first: the netns holder,
    /// the resource scope. `wrap` is handed the program and its arguments and never sees the
    /// descriptors, which are the same after it, since a wrapper changes what runs bwrap and never
    /// what bwrap reads.
    pub(crate) fn wrapped(
        self,
        wrap: impl FnOnce(&Path, Vec<OsString>) -> (PathBuf, Vec<OsString>),
    ) -> Self {
        let (program, args) = wrap(&self.program, self.args);
        Self {
            program,
            args,
            files: self.files,
        }
    }

    /// Hand the cage one more descriptor, one its spec already names by number: the binary
    /// [`super::selfcage`] binds, the proxy's end of its link.
    pub(crate) fn hand(&mut self, file: File) {
        self.files.push(file);
    }

    /// Stage `bytes` on a descriptor this command carries to its exec, and return the number that
    /// names it there: for a wrapper handed something its argument list must not show, as the netns
    /// holder is handed the report socket's token ([`super::netns::behind_holder`]).
    pub(crate) fn stage(&mut self, name: &std::ffi::CStr, bytes: &[u8]) -> io::Result<RawFd> {
        let file = super::memfd::write(name, bytes)?;
        let fd = file.as_raw_fd();
        self.files.push(file);
        Ok(fd)
    }

    /// The command, prepared: it owns the descriptors, so they stay open exactly as long as it does,
    /// and its exec inherits them while no other does ([`super::memfd::inherit_across_exec`]). Once
    /// it has spawned, dropping it closes this process's copies.
    pub(crate) fn into_command(self) -> std::process::Command {
        let mut command = std::process::Command::new(self.program);
        command.args(self.args);
        super::memfd::inherit_across_exec(&mut command, self.files);
        command
    }

    /// [`Self::into_command`] for a process that holds inheritable descriptors of its own, as the
    /// netns holder does: every descriptor past the standard three is marked close-on-exec in the
    /// child before these are cleared ([`super::memfd::inherit_only`]).
    pub(crate) fn into_command_alone(self) -> std::process::Command {
        let mut command = std::process::Command::new(self.program);
        command.args(self.args);
        super::memfd::inherit_only(&mut command, self.files);
        command
    }

    /// The program, its arguments, and the numbers its child clears close-on-exec on, for a fork
    /// that cannot go through `Command`: the pty supervisor's. Borrowed, so the descriptors stay
    /// open for as long as the caller holds this command.
    pub(in crate::sandbox) fn fork_parts(&self) -> (&Path, &[OsString], Vec<libc::c_int>) {
        let fds = self.files.iter().map(AsRawFd::as_raw_fd).collect();
        (&self.program, &self.args, fds)
    }

    /// The argument list, for a test that asserts on it.
    #[cfg(test)]
    pub(crate) fn args(&self) -> &[OsString] {
        &self.args
    }

    /// The descriptors held, for a test that asserts on them.
    #[cfg(test)]
    pub(crate) fn files(&self) -> &[File] {
        &self.files
    }
}

/// The bwrap flags that load `filters` as seccomp filters, placed before the rest of the argv. Each
/// is applied on top of the others.
///
/// Private to this module, so an argument list that loads the mandatory filters is always one
/// [`compose`] built.
fn argv_prefix(filters: &[File]) -> Vec<OsString> {
    let mut a = Vec::with_capacity(filters.len() * 2);
    for f in filters {
        a.push(lit("--add-seccomp-fd"));
        a.push(OsString::from(f.as_raw_fd().to_string()));
    }
    a
}

/// Where in `argv` the held bind sources have their numbers written: the word after each
/// `--bind-fd` and `--ro-bind-fd` [`to_argv`] wrote.
///
/// Read only up to the `--` that opens the cage's own command, for the reason [`env_args_slot`]
/// reads by position: that command is the caller's, and a word in it that spells a flag is not
/// one. Nothing ahead of the separator is a bare `--`: the flags are named and every path is
/// absolute.
fn held_slots(argv: &[OsString]) -> impl Iterator<Item = usize> + '_ {
    let command = argv.iter().position(|a| a == "--").unwrap_or(argv.len());
    argv[..command]
        .windows(2)
        .enumerate()
        .filter(|(_, w)| w[0] == "--bind-fd" || w[0] == "--ro-bind-fd")
        .map(|(at, _)| at + 1)
}

/// Where in `argv` the descriptor carrying the cage's environment has its number written: the word
/// after the `--args` [`to_argv`] wrote.
///
/// The slot is found by its **position** and not by comparing every element to the placeholder
/// text. That vector also carries every bind path and the cage's own command, so a substitution by
/// value rewrote any of them that happened to equal the marker: `sbx run -- printf` with the marker
/// as an argument printed a descriptor number. The literal is special in exactly one slot, the one
/// sbx put it in; everywhere else it is a word the caller chose and sbx has no business touching.
///
/// The first `--args` pair is that slot: [`to_argv`] writes it before the cage command, which is
/// pushed last, so nothing a caller supplies can be found ahead of it.
fn env_args_slot(argv: &[OsString]) -> io::Result<usize> {
    argv.windows(2)
        .position(|w| w[0] == "--args" && w[1] == ENV_ARGS_PLACEHOLDER)
        .map(|i| i + 1)
        .ok_or_else(|| {
            io::Error::other(
                "the composed argv carries no `--args` placeholder for the environment descriptor",
            )
        })
}

/// The descriptor carrying the cage's environment, in bwrap's own `--args` encoding (NUL-separated
/// arguments), or `None` when the cage sets no variables.
///
/// Credentials are written **first**, so a variable named after the cage's own plumbing (`PATH`,
/// `HOME`) wins over a credential that took its name — the plumbing is what the cage needs to work,
/// and a credential is never the right answer to `PATH`. (Declaring one name as both is already
/// refused at load: one name, one source.)
///
/// **A NUL byte in a name or a value refuses the launch.** NUL is the separator here, so a value
/// carrying one would end its own argument and turn everything after it into further bwrap
/// arguments — `--bind /home /home` written by whoever supplied the value. Refused rather than
/// stripped: silently removing a byte would change a credential's value, and a launch that ran with
/// a *different* secret than the one declared is worse than one that did not run.
fn env_fd(spec: &SandboxSpec) -> io::Result<Option<File>> {
    if spec.env.is_empty() && spec.secret_env.is_empty() {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    for (key, value) in spec.secret_env.iter().chain(spec.env.iter()) {
        // Which half carried it decides what the message may quote, and the two are not the same
        // case. A NUL in the *value* is reported by naming the key: that is what a person needs to
        // find the declaration, and printing the value would print a credential. A NUL in the
        // *name* is reported without quoting anything — the old message said "the value of `{key}`"
        // and then printed `key`, so it both mislabelled the half and echoed the poisoned bytes it
        // exists to refuse into the terminal reading it.
        let carrier = if key.as_bytes().contains(&0) {
            Some("a variable name".to_string())
        } else if value.as_bytes().contains(&0) {
            Some(format!("the value of `{key}`"))
        } else {
            None
        };
        if let Some(carrier) = carrier {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "refusing to launch: {carrier} contains a NUL byte, which would break out of \
                     its own argument and add arguments of its own"
                ),
            ));
        }
        for part in ["--setenv", key.as_str(), value.as_str()] {
            bytes.extend_from_slice(part.as_bytes());
            bytes.push(0);
        }
    }
    super::memfd::write(c"sbx-args", &bytes).map(Some)
}

/// Build the bubblewrap argument list for `spec`. Pure: same Spec in, same argv
/// out, no I/O and no globals read. The environment is represented by the
/// [`ENV_ARGS_PLACEHOLDER`] that [`compose`] resolves — nothing here is what
/// bwrap is finally given.
///
/// A held bind source ([`HeldSource`](super::spec::HeldSource)) is mounted from its descriptor
/// (`--bind-fd`, `--ro-bind-fd`), written with the number the spec holds it under, which
/// [`compose`] replaces with the number of the copy it hands bwrap ([`held_slots`]). The descriptor
/// goes to the **last** mount of its path onto itself, the one the cage sees there: the config bind
/// it was opened for is laid before every structural mount, and a control-plane pin of the same
/// directory is laid after it ([`lay_pins`](super::binds::lay_pins)), so a descriptor given to the
/// first would leave the visible mount resolved by path. bwrap 0.10.0 and later close such a
/// descriptor once they have mounted it, so an earlier mount of the same path goes by path,
/// shadowed by the one that does not. A `RoBindTry` so chosen is written as `--ro-bind-fd`: its
/// source is open, so it exists.
pub(in crate::sandbox) fn to_argv(spec: &SandboxSpec) -> Vec<OsString> {
    let mut a: Vec<OsString> = Vec::new();
    let mut handed: Vec<Option<RawFd>> = vec![None; spec.mounts.len()];
    for held in &spec.held_sources {
        let last = spec.mounts.iter().rposition(|m| match m {
            Mount::Bind { src, dest }
            | Mount::RoBind { src, dest }
            | Mount::RoBindTry { src, dest } => src == dest && *src == held.path,
            _ => false,
        });
        // Two sources of one path meet at one mount, and the second is not handed: it goes
        // unmounted, which [`compose`] leaves out of the command.
        if let Some(at) = last {
            handed[at].get_or_insert(held.fd.as_raw_fd());
        }
    }

    // Namespaces: isolate everything. The pid namespace is mandatory — the
    // same-uid model is only safe behind a pid + user namespace — and the rest
    // remove ambient access to host IPC, hostname, and the cgroup tree.
    for ns in [
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-cgroup",
    ] {
        a.push(lit(ns));
    }
    match &spec.netns_dummy {
        // Ordinary path: bwrap creates the cage's network namespace itself. An isolated posture
        // gets an empty namespace (loopback only); a shared one inherits the host's.
        None => {
            if spec.net == NetPolicy::Isolated {
                a.push(lit("--unshare-net"));
            }
            // A build maps itself to uid 0 *inside* this namespace, which is what a distribution's
            // package tools check for. Only on this branch: the holder path already sets the pair
            // below, and for the opposite reason.
            if spec.as_root {
                a.push(lit("--uid"));
                a.push(lit("0"));
                a.push(lit("--gid"));
                a.push(lit("0"));
            }
        }
        // Holder path: the network namespace is pre-created by the netns holder (with a `dummy0`
        // interface up) and inherited across the holder's exec, so bwrap must *not* unshare its
        // own — that would replace the holder's namespace with an empty one and lose the dummy.
        // The holder runs as root in its user namespace, so map the cage back to the host uid/gid
        // to keep the same-uid model (bwrap's default would otherwise leave the cage as uid 0).
        Some(nd) => {
            a.push(lit("--uid"));
            a.push(OsString::from(nd.uid.to_string()));
            a.push(lit("--gid"));
            a.push(OsString::from(nd.gid.to_string()));
        }
    }
    // A fresh UTS namespace inherits the host's hostname at creation, so set the cage's own —
    // `sbx-<slug>`, naming the cage after its app/project. It still never reveals the *host's*
    // hostname (the reason the UTS namespace is unshared), and it makes `$HOSTNAME`, `uname -n`,
    // and a `\h`-based shell prompt identify which cage this is instead of a shared `sandbox`.
    a.push(lit("--hostname"));
    a.push(OsString::from(super::naming::cage_hostname(
        &spec.cage_slug,
    )));

    // Free hardening — pure removals, always emitted: start from a clean
    // environment (before anything is set into it) and drop every capability.
    a.push(lit("--clearenv"));
    a.push(lit("--cap-drop"));
    a.push(lit("ALL"));

    // Die with the launcher, so no sandbox outlives the process that supervises it. Conditional
    // for one shape only, and [`SandboxSpec::dies_with_launcher`] states which: a detached launch
    // that replaces its own daemon with bwrap has no supervisor to outlive, and the flag would
    // arm `PR_SET_PDEATHSIG` against the short-lived launcher instead.
    if spec.dies_with_launcher {
        a.push(lit("--die-with-parent"));
    }

    // Terminal session: a new session blocks terminal injection for a
    // non-interactive launch. The private-pty path establishes its own session
    // (and holds the pty master), so it must omit this — `--new-session` would
    // `setsid` away from that private controlling terminal.
    if spec.terminal == TerminalPolicy::NewSession {
        a.push(lit("--new-session"));
    }

    // Environment: rebuilt from nothing, entry by entry in declaration order — but on a descriptor,
    // never here. A value in the argument list is readable by every uid on the machine; the same
    // value in the environment is not. This is only the placeholder marking where the descriptor's
    // arguments are spliced in, filled in by `compose`; one that reached bwrap is refused as an
    // invalid fd, loudly, rather than silently dropping the cage's environment.
    //
    // Position is load-bearing: after `--clearenv`, which would otherwise wipe everything the
    // descriptor sets. What is *inside* it is ordered by `env_fd`.
    if !spec.env.is_empty() || !spec.secret_env.is_empty() {
        a.push(lit("--args"));
        a.push(lit(ENV_ARGS_PLACEHOLDER));
    }

    // Filesystem: the Spec's mounts, in order. A later mount shadows an earlier
    // one at the same path, so the order is load-bearing — it is the Spec's
    // responsibility and is faithfully preserved here.
    for (m, held) in spec.mounts.iter().zip(handed) {
        if let Some(fd) = held {
            let flag = match m {
                Mount::Bind { .. } => "--bind-fd",
                _ => "--ro-bind-fd",
            };
            a.push(lit(flag));
            a.push(OsString::from(fd.to_string()));
            a.push(path(m.dest()));
            continue;
        }
        match m {
            Mount::RoBind { src, dest } => {
                a.push(lit("--ro-bind"));
                a.push(path(src));
                a.push(path(dest));
            }
            Mount::RoBindTry { src, dest } => {
                a.push(lit("--ro-bind-try"));
                a.push(path(src));
                a.push(path(dest));
            }
            Mount::Bind { src, dest } => {
                a.push(lit("--bind"));
                a.push(path(src));
                a.push(path(dest));
            }
            Mount::Symlink { target, dest } => {
                a.push(lit("--symlink"));
                a.push(path(target));
                a.push(path(dest));
            }
            Mount::Proc { dest } => {
                a.push(lit("--proc"));
                a.push(path(dest));
            }
            Mount::Dev { dest } => {
                a.push(lit("--dev"));
                a.push(path(dest));
            }
            Mount::DevBind { src, dest } => {
                // `-try` so a device absent on this host is skipped rather than aborting the
                // launch — a portable profile may grant a device (a GPU, kvm) some hosts lack.
                a.push(lit("--dev-bind-try"));
                a.push(path(src));
                a.push(path(dest));
            }
            Mount::Tmpfs { dest } => {
                a.push(lit("--tmpfs"));
                a.push(path(dest));
            }
            Mount::Copy { fd, dest } => {
                a.push(lit("--perms"));
                a.push(lit("0555"));
                a.push(lit("--file"));
                a.push(OsString::from(fd.to_string()));
                a.push(path(dest));
            }
        }
    }

    // Working directory, then the command after `--` so the command's own flags
    // are never parsed by bwrap.
    a.push(lit("--chdir"));
    a.push(path(&spec.workdir));
    a.push(lit("--"));
    a.extend(spec.cmd.iter().cloned());

    a
}

/// Launch `spec` through the real bwrap and wait for it.
///
/// Deliberately not the launch path: nothing here wraps the cage in a resource scope, because a
/// scope's unit name has to be unique among live units and a test binary stands many cages up under
/// one process id. What it does exercise is the argument list itself, filters included, which is
/// what the callers of this helper are asking about.
#[cfg(test)]
pub(super) fn run_bwrap(bwrap: &Path, spec: &SandboxSpec) -> io::Result<std::process::Output> {
    compose(bwrap, spec)?.into_command().output()
}

/// The arguments the descriptor carries, read back as bwrap will parse them — the cage's
/// environment, which is no longer anywhere in the argv. The one way a test can ask "what variables
/// does this cage actually get?", so no module has to reimplement the encoding to find out.
#[cfg(test)]
pub(super) fn env_args(spec: &SandboxSpec) -> Vec<OsString> {
    use std::io::Read;
    let Some(mut file) = env_fd(spec).expect("a descriptor for the cage environment") else {
        return Vec::new();
    };
    let mut raw = Vec::new();
    file.read_to_end(&mut raw).expect("read the descriptor");
    raw.split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| OsString::from(String::from_utf8_lossy(part).into_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec(mounts: Vec<Mount>, env: Vec<(String, String)>, net: NetPolicy) -> SandboxSpec {
        SandboxSpec::new(
            PathBuf::from("/work"),
            mounts,
            env,
            net,
            vec![
                OsString::from("/bin/sh"),
                OsString::from("-c"),
                OsString::from("id"),
            ],
        )
        .expect("valid spec")
    }

    /// Positions of `needle` in the argv, as a convenience for ordering asserts.
    fn index_of(argv: &[OsString], needle: &str) -> Option<usize> {
        argv.iter().position(|a| a == needle)
    }

    /// A held bind source reaches bwrap as a descriptor, by the last mount of its path onto itself
    /// (the one the cage sees there), and the command hands that descriptor over: the number in the
    /// argument list is one of the descriptors held, and it names the object the spec holds, not a
    /// fresh look-up. An earlier mount of the same path, a mount from elsewhere onto it, and a bind
    /// nobody held go by path: bwrap closes a descriptor once it has mounted it. A source no mount
    /// takes, or whose path another source already took, is not handed at all.
    #[test]
    fn a_held_bind_source_reaches_bwrap_as_the_descriptor_the_command_hands_over() {
        use std::os::unix::fs::MetadataExt;
        let tmp = crate::testutil::TmpDir::new();
        let (rw, ro, free) = (tmp.join("rw"), tmp.join("ro"), tmp.join("free"));
        let (tried, spare) = (tmp.join("tried"), tmp.join("spare"));
        for dir in [&rw, &ro, &free, &tried, &spare] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let hold = |p: &PathBuf| {
            let fd = std::fs::File::open(p).unwrap();
            super::super::spec::HeldSource::new(p.clone(), fd.into())
        };
        let mounts = vec![
            Mount::Bind {
                src: rw.clone(),
                dest: rw.clone(),
            },
            Mount::RoBind {
                src: ro.clone(),
                dest: ro.clone(),
            },
            Mount::RoBind {
                src: free.clone(),
                dest: free.clone(),
            },
            Mount::Bind {
                src: rw.clone(),
                dest: rw.clone(),
            },
            Mount::RoBind {
                src: free.clone(),
                dest: ro.clone(),
            },
            Mount::RoBindTry {
                src: tried.clone(),
                dest: tried.clone(),
            },
        ];
        let mut held_spec = spec(mounts, Vec::new(), NetPolicy::Shared).with_held_sources(vec![
            hold(&rw),
            hold(&ro),
            hold(&spare),
            hold(&tried),
            hold(&ro),
        ]);
        // The cage's own command spells the flag and the number the spec holds a source under,
        // one no mount takes, so the command is the only place that number is written: it is the
        // caller's, and composing must leave it as written.
        let spec_number = held_spec.held_sources[2].fd.as_raw_fd().to_string();
        let command = vec![
            OsString::from("printf"),
            OsString::from("--bind-fd"),
            OsString::from(&spec_number),
        ];
        held_spec.cmd = command.clone();
        let cage = compose(Path::new("/bwrap"), &held_spec).expect("compose");
        let (argv, files) = (cage.args(), cage.files());
        let words: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let separator = argv
            .iter()
            .position(|a| a == "--")
            .expect("the command separator");
        assert_eq!(
            argv[separator + 1..],
            command[..],
            "the cage's command is left as written"
        );
        let after = |flag: &str| -> Vec<(usize, String, String)> {
            words[..separator]
                .windows(3)
                .enumerate()
                .filter(|(_, w)| w[0] == flag)
                .map(|(at, w)| (at, w[1].clone(), w[2].clone()))
                .collect()
        };
        let shown = |p: &PathBuf| p.display().to_string();
        let object = |p: &PathBuf| {
            let meta = std::fs::metadata(p).unwrap();
            (meta.dev(), meta.ino())
        };
        let handed_of = |p: &PathBuf| {
            files
                .iter()
                .filter(|f| {
                    let meta = f.metadata().unwrap();
                    (meta.dev(), meta.ino()) == object(p)
                })
                .count()
        };

        for (flag, paths) in [
            ("--bind-fd", vec![&rw]),
            ("--ro-bind-fd", vec![&ro, &tried]),
        ] {
            let found = after(flag);
            let dests: Vec<String> = found.iter().map(|(_, _, dest)| dest.clone()).collect();
            let expected: Vec<String> = paths.iter().map(|p| shown(p)).collect();
            assert_eq!(dests, expected, "{flag} once per held path: {words:?}");
            for ((_, number, _), path) in found.iter().zip(paths) {
                let handed = files
                    .iter()
                    .find(|f| f.as_raw_fd().to_string() == *number)
                    .unwrap_or_else(|| {
                        panic!("{flag} {number} is not a descriptor held: {words:?}")
                    });
                let meta = handed.metadata().unwrap();
                assert_eq!(
                    (meta.dev(), meta.ino()),
                    object(path),
                    "{flag} {number} is the object held"
                );
            }
        }
        let by_path = after("--bind");
        assert_eq!(
            by_path
                .iter()
                .map(|(_, src, dest)| (src.clone(), dest.clone()))
                .collect::<Vec<_>>(),
            [(shown(&rw), shown(&rw))],
            "the earlier mount of a held path goes by path: {words:?}"
        );
        assert!(
            by_path[0].0 < after("--bind-fd")[0].0,
            "the descriptor goes to the mount the cage sees, the last of its path: {words:?}"
        );
        assert_eq!(
            after("--ro-bind")
                .iter()
                .map(|(_, src, dest)| (src.clone(), dest.clone()))
                .collect::<Vec<_>>(),
            [(shown(&free), shown(&free)), (shown(&free), shown(&ro))],
            "an unheld bind, and a mount from elsewhere onto a held path, go by path: {words:?}"
        );
        assert!(
            after("--ro-bind-try").is_empty(),
            "a held source is open, so its mount needs no `-try`: {words:?}"
        );
        assert_eq!(
            handed_of(&spare),
            0,
            "a source no mount takes stays out of the command, where the cage would inherit it"
        );
        assert_eq!(
            handed_of(&ro),
            1,
            "a second source of one path is not handed: one mount takes one descriptor"
        );

        let unheld = spec(
            vec![Mount::Bind {
                src: rw.clone(),
                dest: rw.clone(),
            }],
            Vec::new(),
            NetPolicy::Shared,
        );
        let cage = compose(Path::new("/bwrap"), &unheld).expect("compose");
        assert!(
            !cage
                .args()
                .iter()
                .any(|a| a == "--bind-fd" || a == "--ro-bind-fd"),
            "a spec that holds nothing is the path-only argument list it always was"
        );
    }

    /// A control-plane pin laid over a held config bind of its own path is the mount the cage sees
    /// there, so it is the one mounted from the descriptor, and the config bind beneath it goes by
    /// path. Given to the config bind, the descriptor would leave what the cage sees resolved by
    /// path again, after the launch opened the source.
    #[test]
    fn a_pin_laid_over_a_held_bind_is_the_mount_the_descriptor_goes_to() {
        use crate::sandbox::binds::{ExtraBind, lay_pins};
        let tmp = crate::testutil::TmpDir::new();
        let (root, held) = (tmp.join("root"), tmp.join("root/held"));
        std::fs::create_dir_all(&held).unwrap();
        let mut mounts = vec![
            Mount::Bind {
                src: root.clone(),
                dest: root.clone(),
            },
            Mount::RoBind {
                src: held.clone(),
                dest: held.clone(),
            },
        ];
        let pin = ExtraBind {
            src: held.clone(),
            dest: held.clone(),
            writable: false,
        };
        assert_eq!(lay_pins(&mut mounts, &[pin]), Vec::new(), "the pin is laid");
        assert_eq!(
            mounts.len(),
            3,
            "the pin lands over the bind it pins: {mounts:?}"
        );
        let hold = |p: &PathBuf| {
            let fd = std::fs::File::open(p).unwrap();
            super::super::spec::HeldSource::new(p.clone(), fd.into())
        };
        let held_spec = spec(mounts, Vec::new(), NetPolicy::Shared)
            .with_held_sources(vec![hold(&root), hold(&held)]);
        let cage = compose(Path::new("/bwrap"), &held_spec).expect("compose");
        let words: Vec<String> = cage
            .args()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let shown = held.display().to_string();
        let at_held: Vec<&str> = words
            .windows(3)
            .filter(|w| w[0].starts_with("--") && w[2] == shown)
            .map(|w| w[0].as_str())
            .collect();
        assert_eq!(
            at_held,
            ["--ro-bind", "--ro-bind-fd"],
            "the last mount at the held path, the pin, is mounted from the descriptor: {words:?}"
        );
    }

    #[test]
    fn hardening_is_emitted_unconditionally() {
        let argv = to_argv(&spec(vec![], vec![], NetPolicy::Shared));
        for flag in [
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-cgroup",
            "--clearenv",
            "--new-session",
        ] {
            assert!(index_of(&argv, flag).is_some(), "missing {flag}: {argv:?}");
        }
        // capabilities are dropped as a pair
        let i = index_of(&argv, "--cap-drop").expect("--cap-drop present");
        assert_eq!(argv[i + 1], OsString::from("ALL"));
        // the cage's own hostname is set as a pair (`sbx-<slug>`, here the default-slug spec's
        // `sbx-cage`), so the fresh UTS namespace never inherits — nor reveals — the host's
        let h = index_of(&argv, "--hostname").expect("--hostname present");
        assert_eq!(argv[h + 1], OsString::from("sbx-cage"));
    }

    #[test]
    fn die_with_parent_rides_every_launch_but_the_one_with_no_parent_to_die_with() {
        // The flag is armed against the process supervising the cage, so it belongs on every
        // launch that has one — which is every launch but the detached, guardless branch, where
        // the daemon `exec`s bwrap and leaves it parented to a launcher whose job is to exit.
        let supervised = spec(vec![], vec![], NetPolicy::Shared);
        assert!(
            index_of(&to_argv(&supervised), "--die-with-parent").is_some(),
            "a supervised launch keeps the flag"
        );

        let detached = spec(vec![], vec![], NetPolicy::Shared).outliving_its_launcher();
        let argv = to_argv(&detached);
        assert!(
            index_of(&argv, "--die-with-parent").is_none(),
            "the detached exec-replace drops it: {argv:?}"
        );

        // Nothing else moves. Written as the whole-argv difference rather than as a second list of
        // flags to re-assert, so a hardening flag added later is covered here without being named
        // twice — and so this cannot pass by dropping something it never thought to check.
        let expected: Vec<_> = to_argv(&supervised)
            .into_iter()
            .filter(|a| a != "--die-with-parent")
            .collect();
        assert_eq!(argv, expected, "only the one flag differs");
    }

    #[test]
    fn the_hostname_names_the_cage_after_its_slug() {
        let s = spec(vec![], vec![], NetPolicy::Shared).with_cage_slug("demo-app".to_string());
        let argv = to_argv(&s);
        let h = index_of(&argv, "--hostname").expect("--hostname present");
        assert_eq!(argv[h + 1], OsString::from("sbx-demo-app"));
    }

    #[test]
    fn the_private_tty_terminal_omits_new_session() {
        // the default (non-interactive) terminal keeps --new-session
        let default = to_argv(&spec(vec![], vec![], NetPolicy::Shared));
        assert!(index_of(&default, "--new-session").is_some());

        // the private-pty terminal omits it (the supervisor owns the session)
        let pty = to_argv(&spec(vec![], vec![], NetPolicy::Shared).with_private_tty());
        assert!(
            index_of(&pty, "--new-session").is_none(),
            "private-tty must omit --new-session: {pty:?}"
        );
        // the pure-removal hardening is unchanged
        for flag in [
            "--clearenv",
            "--cap-drop",
            "--unshare-pid",
            "--die-with-parent",
        ] {
            assert!(index_of(&pty, flag).is_some(), "missing {flag}: {pty:?}");
        }
    }

    #[test]
    fn shared_network_is_not_unshared_isolated_is() {
        let shared = to_argv(&spec(vec![], vec![], NetPolicy::Shared));
        assert!(index_of(&shared, "--unshare-net").is_none());

        let isolated = to_argv(&spec(vec![], vec![], NetPolicy::Isolated));
        assert!(index_of(&isolated, "--unshare-net").is_some());
    }

    #[test]
    fn the_holder_netns_replaces_unshare_net_with_a_uid_gid_map() {
        // With the netns holder providing the (dummy-carrying) namespace, bwrap must NOT unshare its
        // own network namespace — that would discard the holder's namespace — and must map the cage
        // back to the host credentials (the holder runs root-in-userns).
        let s = spec(vec![], vec![], NetPolicy::Isolated).with_netns_dummy(
            super::super::spec::NetnsDummy {
                uid: 4242,
                gid: 4343,
                holder_exe: PathBuf::from("/opt/sbx"),
                tap: None,
            },
        );
        let argv = to_argv(&s);
        assert!(
            index_of(&argv, "--unshare-net").is_none(),
            "holder mode must not unshare-net: {argv:?}"
        );
        let uid = index_of(&argv, "--uid").expect("--uid present");
        assert_eq!(argv[uid + 1], OsString::from("4242"));
        let gid = index_of(&argv, "--gid").expect("--gid present");
        assert_eq!(argv[gid + 1], OsString::from("4343"));
    }

    /// The environment is set from nothing, and set **off the argument list**: a value there is
    /// readable by every uid on the machine (`/proc/<pid>/cmdline` is mode `444`) while the same
    /// value in the environment is not (`400`).
    #[test]
    fn the_environment_is_cleared_and_then_set_off_the_argument_list() {
        let env = vec![
            ("HOME".to_string(), "/home/sandbox".to_string()),
            ("TERM".to_string(), "dumb".to_string()),
        ];
        let s = spec(vec![], env, NetPolicy::Shared);
        let argv = to_argv(&s);

        assert!(
            index_of(&argv, "--setenv").is_none(),
            "no variable may be an argument: {argv:?}"
        );
        let clear = index_of(&argv, "--clearenv").expect("--clearenv present");
        let args = index_of(&argv, "--args").expect("--args present");
        assert!(
            clear < args,
            "spliced before the clear, the descriptor's variables would be wiped: {argv:?}"
        );
        assert_eq!(argv[args + 1], OsString::from(ENV_ARGS_PLACEHOLDER));

        // On the descriptor, each variable is the same triple bwrap would have taken as arguments.
        let carried = env_args(&s);
        assert_eq!(
            carried,
            [
                "--setenv",
                "HOME",
                "/home/sandbox",
                "--setenv",
                "TERM",
                "dumb"
            ]
            .map(OsString::from)
            .to_vec()
        );
    }

    /// Credentials are written ahead of the plain environment, so a credential that took the name of
    /// the cage's own plumbing loses to the plumbing rather than replacing it.
    #[test]
    fn a_credential_is_applied_before_the_plumbing_that_could_share_its_name() {
        let s = spec(
            vec![],
            vec![("PATH".to_string(), "/bin".to_string())],
            NetPolicy::Shared,
        )
        .with_secret_env(vec![("TOKEN".to_string(), "s3cret".to_string())]);
        let carried = env_args(&s);
        let token = carried.iter().position(|a| a == "TOKEN").expect("TOKEN");
        let path = carried.iter().position(|a| a == "PATH").expect("PATH");
        assert!(token < path, "{carried:?}");
    }

    /// A cage that sets nothing needs no descriptor, and says nothing about one.
    #[test]
    fn a_cage_with_no_environment_names_no_descriptor() {
        let argv = to_argv(&spec(vec![], vec![], NetPolicy::Shared));
        assert!(index_of(&argv, "--args").is_none(), "{argv:?}");
    }

    /// NUL is the separator on the descriptor, so a value carrying one ends its own argument and
    /// everything after it becomes further bwrap arguments — a mount of the author's choosing.
    ///
    /// Measured on a live launch: an untrusted `.sbx.toml` bound the host `$HOME` into the cage.
    ///
    /// Refused, not stripped. Removing the byte would run the cage with a *different* value than the
    /// one declared, which for a credential is worse than not running at all. Checked here rather
    /// than at config load because this is the single choke point every source passes through: a
    /// project's `[env]`, a resolver plugin's `allow_env` pass-through, and a resolved credential.
    #[test]
    fn a_nul_in_the_environment_refuses_the_launch_rather_than_adding_bwrap_arguments() {
        let injected = "a\0--bind\0/home\0/home".to_string();

        let plain = spec(
            vec![],
            vec![("FOO".to_string(), injected.clone())],
            NetPolicy::Shared,
        );
        let e = compose(Path::new("/bwrap"), &plain)
            .expect_err("a NUL-bearing value must refuse the launch");
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("FOO"), "{e}");
        assert!(
            !e.to_string().contains("--bind"),
            "the message names the variable, never its value: {e}"
        );

        // The same for a resolved credential, whose value is third-party bytes (a resolver plugin's
        // stdout), and for a name — bwrap reads both off the same descriptor.
        let secret = spec(vec![], vec![], NetPolicy::Shared)
            .with_secret_env(vec![("TOKEN".to_string(), injected)]);
        assert!(compose(Path::new("/bwrap"), &secret).is_err());
        let named = spec(
            vec![],
            vec![("A\0--bind".to_string(), "x".to_string())],
            NetPolicy::Shared,
        );
        assert!(compose(Path::new("/bwrap"), &named).is_err());

        // An ordinary environment is untouched by the check.
        let fine = spec(
            vec![],
            vec![("PATH".to_string(), "/bin".to_string())],
            NetPolicy::Shared,
        );
        assert!(compose(Path::new("/bwrap"), &fine).is_ok());
    }

    #[test]
    fn mounts_map_to_flags_in_declaration_order() {
        let mounts = vec![
            Mount::RoBind {
                src: PathBuf::from("/nix"),
                dest: PathBuf::from("/nix"),
            },
            Mount::Symlink {
                target: PathBuf::from("usr/bin"),
                dest: PathBuf::from("/bin"),
            },
            Mount::Proc {
                dest: PathBuf::from("/proc"),
            },
            Mount::Dev {
                dest: PathBuf::from("/dev"),
            },
            Mount::Tmpfs {
                dest: PathBuf::from("/tmp"),
            },
            Mount::Bind {
                src: PathBuf::from("/host/proj"),
                dest: PathBuf::from("/host/proj"),
            },
        ];
        let argv = to_argv(&spec(mounts, vec![], NetPolicy::Shared));

        // the mount region of the argv, in order
        let expected: Vec<OsString> = [
            "--ro-bind",
            "/nix",
            "/nix",
            "--symlink",
            "usr/bin",
            "/bin",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--bind",
            "/host/proj",
            "/host/proj",
        ]
        .iter()
        .map(|s| OsString::from(*s))
        .collect();

        let start = index_of(&argv, "--ro-bind").expect("mounts present");
        assert_eq!(&argv[start..start + expected.len()], expected.as_slice());
    }

    #[test]
    fn dev_bind_maps_to_the_dev_bind_try_variant() {
        // A `[devices]` grant is a `--dev-bind-try` (skips a device absent on this host) binding the
        // host device at its own path with device access.
        let mounts = vec![Mount::DevBind {
            src: PathBuf::from("/dev/dri"),
            dest: PathBuf::from("/dev/dri"),
        }];
        let argv = to_argv(&spec(mounts, vec![], NetPolicy::Shared));
        let i = index_of(&argv, "--dev-bind-try").expect("--dev-bind-try present");
        assert_eq!(argv[i + 1], OsString::from("/dev/dri"));
        assert_eq!(argv[i + 2], OsString::from("/dev/dri"));
    }

    #[test]
    fn ro_bind_try_maps_to_the_try_variant() {
        let mounts = vec![Mount::RoBindTry {
            src: PathBuf::from("/etc/resolv.conf"),
            dest: PathBuf::from("/etc/resolv.conf"),
        }];
        let argv = to_argv(&spec(mounts, vec![], NetPolicy::Shared));
        let i = index_of(&argv, "--ro-bind-try").expect("--ro-bind-try present");
        assert_eq!(argv[i + 1], OsString::from("/etc/resolv.conf"));
        assert_eq!(argv[i + 2], OsString::from("/etc/resolv.conf"));
    }

    #[test]
    fn the_command_comes_last_after_a_double_dash_preceded_by_chdir() {
        let argv = to_argv(&spec(vec![], vec![], NetPolicy::Shared));

        let dashes = index_of(&argv, "--").expect("-- present");
        // --chdir <workdir> immediately precedes the `--` separator
        assert_eq!(argv[dashes - 2], OsString::from("--chdir"));
        assert_eq!(argv[dashes - 1], OsString::from("/work"));
        // everything after `--` is exactly the command
        let cmd: Vec<OsString> = argv[dashes + 1..].to_vec();
        assert_eq!(
            cmd,
            vec![
                OsString::from("/bin/sh"),
                OsString::from("-c"),
                OsString::from("id")
            ]
        );
    }

    /// Only the slot [`to_argv`] wrote becomes a descriptor number — a cage argument that happens
    /// to equal the marker is left alone.
    ///
    /// The substitution used to be a value comparison over the whole vector, which also carries
    /// every bind path and the cage's own command: `sbx run -- printf '%s\n' @sbx-env-args`
    /// printed a descriptor number instead of the word the caller wrote.
    #[test]
    fn compose_resolves_the_slot_it_wrote_and_not_a_cage_argument_that_looks_like_it() {
        let mut with_env = spec(
            Vec::new(),
            vec![("SHELL".to_string(), "/bin/sh".to_string())],
            NetPolicy::Shared,
        );
        with_env.cmd = vec![
            OsString::from("printf"),
            OsString::from("%s\n"),
            OsString::from(ENV_ARGS_PLACEHOLDER),
        ];
        let cage = compose(Path::new("/bwrap"), &with_env).expect("compose");
        let (argv, held) = (cage.args(), cage.files());

        let args = argv
            .iter()
            .position(|a| a == "--args")
            .expect("`to_argv` writes `--args` when the cage has an environment");
        let fd: i32 = argv[args + 1]
            .to_string_lossy()
            .parse()
            .expect("a descriptor number, not the placeholder");
        assert!(
            held.iter().any(|f| f.as_raw_fd() == fd),
            "the slot after `--args` names one of the descriptors kept alive: {argv:?}"
        );
        assert_eq!(
            argv.iter().filter(|a| *a == ENV_ARGS_PLACEHOLDER).count(),
            1,
            "the cage's own argument still reads as the word the caller wrote: {argv:?}"
        );
        assert_eq!(
            argv.last().map(|a| a.as_os_str()),
            Some(OsString::from(ENV_ARGS_PLACEHOLDER).as_os_str()),
            "and it is still the last argument, where the command was put"
        );
    }

    /// A NUL in a variable *name* and a NUL in its *value* are different refusals, and neither
    /// quotes the bytes it exists to reject.
    ///
    /// One message served both: it said "the value of `{key}`" and then printed `key`, so a
    /// poisoned name was both mislabelled and echoed into the terminal reading the refusal.
    #[test]
    fn a_nul_refusal_names_the_half_that_carried_it_and_quotes_no_payload() {
        let poisoned_value = spec(
            Vec::new(),
            vec![("API_KEY".to_string(), "a\0b".to_string())],
            NetPolicy::Shared,
        );
        let err = compose(Path::new("/bwrap"), &poisoned_value)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("the value of `API_KEY`"),
            "a poisoned value is found by naming its key: {err}"
        );

        let poisoned_name = spec(
            Vec::new(),
            vec![("PO\0ISON".to_string(), "harmless".to_string())],
            NetPolicy::Shared,
        );
        let err = compose(Path::new("/bwrap"), &poisoned_name)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("a variable name contains a NUL byte"),
            "a poisoned name is described, not quoted: {err}"
        );
        assert!(
            !err.contains("PO"),
            "the refusal must not echo the bytes it refuses: {err:?}"
        );
    }

    /// Nothing a cage's environment carries may reach bubblewrap's **argument list**:
    /// `/proc/<pid>/cmdline` is mode `444`, so every uid on the machine could read it for as long as
    /// the cage runs, while `/proc/<pid>/environ` is `400`. The sentinel used to sit there next to
    /// `--setenv`.
    ///
    /// This asserts on the production function, so the property holds for whatever a spec is built
    /// from rather than for one hand-written argv.
    #[test]
    fn no_variable_reaches_the_world_readable_argument_list() {
        use std::io::Read;
        const SENTINEL: &str = "s3nt1nel-v4lue-xyz";
        const WRITTEN: &str = "hardcoded-in-a-config";

        let spec = SandboxSpec::new(
            PathBuf::from("/w"),
            Vec::new(),
            vec![
                ("PATH".to_string(), "/bin".to_string()),
                ("API_TOKEN".to_string(), WRITTEN.to_string()),
            ],
            NetPolicy::Isolated,
            vec![OsString::from("/bin/true")],
        )
        .expect("spec")
        .with_secret_env(vec![("PGPASSWORD".to_string(), SENTINEL.to_string())]);

        let cage = compose(Path::new("/bwrap"), &spec).expect("argv");

        let (argv, files) = (cage.args(), cage.files());
        let flat: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for hidden in [SENTINEL, WRITTEN] {
            assert!(
                !flat.iter().any(|a| a.contains(hidden)),
                "no value may be in the argument list: {flat:?}"
            );
        }
        for name in ["PGPASSWORD", "API_TOKEN"] {
            assert!(
                !flat.iter().any(|a| a == name),
                "nor a name, which would say which variable to go and read: {flat:?}"
            );
        }
        assert!(
            !flat.iter().any(|a| a == "--setenv"),
            "the whole environment travels on the descriptor: {flat:?}"
        );

        // It reaches bwrap on a descriptor instead, spliced where the placeholder was — after
        // `--clearenv`, which would otherwise wipe everything it sets.
        let at = flat.iter().position(|a| a == "--args").expect("--args");
        let fd: i32 = flat[at + 1]
            .parse()
            .expect("a descriptor number, not the placeholder");
        assert!(
            flat.iter()
                .position(|a| a == "--clearenv")
                .expect("--clearenv")
                < at,
            "spliced before the clear, its variables would be wiped: {flat:?}"
        );

        let mut carried = String::new();
        files
            .iter()
            .find(|f| f.as_raw_fd() == fd)
            .expect("the descriptor the argv names is one of the files kept alive")
            .try_clone()
            .expect("clone")
            .read_to_string(&mut carried)
            .expect("read");
        // Credentials first, so a variable named after the cage's own plumbing wins over one that
        // took its name. bwrap reads NUL-separated arguments.
        assert_eq!(
            carried,
            format!(
                "--setenv\0PGPASSWORD\0{SENTINEL}\0--setenv\0PATH\0/bin\0--setenv\0API_TOKEN\0{WRITTEN}\0"
            )
        );
    }

    /// A cage that sets no variables at all is given no `--args` slot — an unused mechanism leaves
    /// no trace to explain. The filter descriptors are unconditional and stand apart from it.
    #[test]
    fn a_spec_with_no_environment_is_given_no_args_slot() {
        let spec = SandboxSpec::new(
            PathBuf::from("/w"),
            Vec::new(),
            Vec::new(),
            NetPolicy::Isolated,
            vec![OsString::from("/bin/true")],
        )
        .expect("spec");
        let cage = compose(Path::new("/bwrap"), &spec).expect("argv");
        let (argv, _files) = (cage.args(), cage.files());
        assert!(
            !argv.iter().any(|a| a == "--args"),
            "an unused mechanism must leave no trace in the argv"
        );
    }

    /// Every composed list carries the mandatory filters, whatever the caller went on to do with
    /// it. The prefix names descriptors, so what it names has to be among the files handed back:
    /// a prefix pointing at a number this process does not hold is a cage bubblewrap refuses.
    #[test]
    fn every_composed_argument_list_loads_the_mandatory_seccomp_filters() {
        let cage = compose(
            Path::new("/bwrap"),
            &spec(vec![], vec![], NetPolicy::Shared),
        )
        .expect("compose");
        let (argv, held) = (cage.args(), cage.files());
        let named: Vec<i32> = argv
            .windows(2)
            .filter(|w| w[0] == "--add-seccomp-fd")
            .map(|w| {
                w[1].to_string_lossy()
                    .parse()
                    .expect("a descriptor number follows the flag")
            })
            .collect();
        assert!(
            !named.is_empty(),
            "a cage with no filter is not a cage this crate can produce: {argv:?}"
        );
        for fd in named {
            assert!(
                held.iter().any(|f| f.as_raw_fd() == fd),
                "the argv names a filter descriptor nothing keeps alive: {argv:?}"
            );
        }
    }

    /// A cage rooted in its own namespace carries one filter more, the one that answers a change
    /// of ownership with success; every other cage carries exactly the mandatory ones, since a
    /// launch runs as the user's own uid, where a `chown` means what it says.
    #[test]
    fn only_a_cage_rooted_in_its_namespace_ignores_ownership() {
        let count = |spec: &SandboxSpec| {
            let cage = compose(Path::new("/bwrap"), spec).expect("compose");
            let (argv, _held) = (cage.args(), cage.files());
            argv.iter().filter(|a| *a == "--add-seccomp-fd").count()
        };
        let launch = spec(vec![], vec![], NetPolicy::Shared);
        let build = spec(vec![], vec![], NetPolicy::Shared).rooted_in_its_namespace();
        assert_eq!(
            count(&build),
            count(&launch) + 1,
            "the build carries the ownership filter on top of the mandatory ones"
        );
    }

    /// Every bubblewrap argument list this crate starts a cage with comes from [`compose`], which
    /// loads the mandatory filters; and every cage that runs code sbx did not write also carries
    /// the resource scope.
    ///
    /// The population is every file that holds a `bwrap` path and spawns a process or builds a
    /// cage's command, plus every file calling [`to_argv`] outside the one that defines it. The
    /// spawning half is the one that matters: a list written by hand names no function, and the
    /// process it starts is the only trace it leaves. Sorting the population into kinds is the whole point of the
    /// guard: it asks a new file's author which kind it is, and each kind carries an obligation the
    /// guard then checks. Nothing in the type system asks that question, and the failure it
    /// prevents is an absence: an argument list assembled beside the one definition, running a cage
    /// that behaves exactly like a hardened one until something inside it makes a syscall the
    /// denylist exists to refuse.
    ///
    /// A kind states two things, because a cage owes two: the filters, and whether it runs inside
    /// sbx's resource scope. The scope is owed by every cage that runs something sbx did not write
    /// (a configuration's own command, a plugin, mise over a project's files), so that a runaway
    /// there is bounded the way a runaway in a session is; a cage running one of sbx's own fixed
    /// probes is named as such and stays outside, and the kind it is listed under says so.
    ///
    /// The lists are this guard's upkeep. A file that starts spawning bubblewrap, or assembling a
    /// list of its own, belongs in one of them the day it is written.
    #[test]
    fn every_bubblewrap_argument_list_outside_compose_is_accounted_for() {
        // These spawn their cage through the shared launch command, which is what carries the
        // filters, the netns holder and the scope in one step. Each runs code sbx did not write: a
        // profile's own `resolve` command, a plugin from a store, a declared task's command, and an
        // image's own build steps.
        const RUNS_THE_SHARED_LAUNCH_COMMAND: &[&str] = &[
            "src/sandbox/distro/build.rs",
            "src/sandbox/resolve.rs",
            "src/sandbox/resolver.rs",
            "src/sandbox/task.rs",
        ];
        // Spawn bubblewrap themselves rather than through the launch command, with the composed
        // list inside the resource scope. Each runs a project's own code, or reads what a project
        // wrote: the session launcher, the task pool, mise driven over the files a project
        // declared, and nix registering a seed in the database a project's cage writes.
        const SPAWNS_THE_COMPOSED_LIST_IN_A_SCOPE: &[&str] = &[
            "src/sandbox/launch/cage.rs",
            "src/sandbox/mise.rs",
            "src/sandbox/projectstore.rs",
            "src/sandbox/taskpool.rs",
        ];
        // The same, and outside the scope, because what runs is sbx's own and fixed. `doctor`'s
        // probe reports on the host rather than running anything for a project; `selfcage` builds
        // the cage sbx's own binary runs in, the egress proxy's and the capture tap's, for the
        // module that starts it, and that binary bounds its own memory (`[network] body_max_mb`,
        // `max_connections`); and the storage helper formats an image sbx owns.
        const SPAWNS_THE_COMPOSED_LIST: &[&str] = &[
            "src/sandbox/selfcage.rs",
            "src/sandbox/smoke.rs",
            "src/storage.rs",
        ];
        // Holds a `bwrap` path to hand on and starts no cage with it. The process each does spawn
        // is a host-side one of its own: `sops` decrypting a secret, sbx's `__net-probe` asking
        // for a throwaway namespace, and the host's `git` asked a setting by `doctor`, which hands
        // its path to the smoke probe. The netns holder passes its path to `selfcage` for the tap
        // and becomes the command the launch composed, so what each owes is that the path travels
        // and nothing here starts a cage beside the ones above.
        const HANDS_THE_PATH_ON: &[&str] = &[
            "src/cli/doctor.rs",
            "src/sandbox/egress.rs",
            "src/sandbox/netns.rs",
        ];
        // These read the pure list to assert something about what it contains, and run nothing.
        const READS_THE_LIST: &[&str] = &[];
        // The definitions themselves: this module, the one that compiles the filters into
        // descriptors, and the one that wraps a launch in its resource scope.
        const DEFINES_THEM: &[&str] = &[
            "src/sandbox/argv.rs",
            "src/sandbox/cgroup.rs",
            "src/sandbox/seccomp.rs",
        ];

        /// Whether `text` holds a `bwrap` path in code **and** starts a process or builds a cage's
        /// command.
        ///
        /// Not "does the token `bwrap` sit between the parentheses of a `Command::new`", which is
        /// what this asked before and which is a question about a local variable's name:
        /// `Command::new(bwrap)` was seen and `Command::new(prog)` was not, one rename apart, and
        /// the four launchers that already spell it the second way were outside the population
        /// this guard is named for. A file cannot start a cage without holding the path from
        /// somewhere, and every source of it in this crate is spelled `bwrap` — a field, a
        /// parameter, a lookup by that name — so the file-level mention is the durable half. Comment
        /// lines are dropped first: a file that only *mentions* bubblewrap in prose is talking about
        /// it, not running it.
        ///
        /// Building counts as well as starting because a composed command carries its descriptors
        /// ([`CageCommand`]) and becomes a process inside this module, so most launchers no longer
        /// write `Command::new(` at all. What they write instead is a call to [`compose`] or to the
        /// shared launch command, which is the only way to come by a cage's command.
        ///
        /// The limit, since a text scan has one: a file that holds the path under a name of its own
        /// invention and never writes `bwrap` anywhere in its code is still invisible here. Closing
        /// that means carrying a type rather than a path through every launcher, which is the
        /// answer if a shape appears that this cannot see.
        fn holds_bwrap_and_spawns(text: &str) -> bool {
            let code: String = text
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            code.contains("bwrap")
                && (code.contains("Command::new(")
                    || crate::testutil::calls_function(&code, "argv::compose(")
                    || crate::testutil::calls_function(&code, "argv::compose_with(")
                    || crate::testutil::calls_function(&code, "cage_command("))
        }

        let root = format!("{}/", env!("CARGO_MANIFEST_DIR"));
        let mut population: Vec<String> = Vec::new();
        let mut owes: Vec<String> = Vec::new();
        let declared_test_only = crate::testutil::test_only_sources();
        for file in crate::testutil::crate_sources() {
            // Production code only. A test that stands up a cage of its own answers to the suite
            // it is in, and nothing it builds is shipped; carrying test files here would mean
            // classifying each smoke test as a launcher kind, which says nothing about the binary.
            if crate::testutil::is_test_only_source(&file) || declared_test_only.contains(&file) {
                continue;
            }
            let text = std::fs::read_to_string(&file).unwrap_or_default();
            // The production half: a file's own `cfg(test)` module builds nothing the binary
            // ships, and reading it here would put a module in a launcher category for a fixture.
            // The attribute is named without its brackets on purpose: `production_half` splits on
            // the last literal occurrence of the bracketed form, so writing it here would move this
            // file's own cut past its test module and offer these fixtures to every guard that
            // reads a production half -- which is exactly what it did.
            let production = crate::testutil::production_half(&text);
            let names_the_list = crate::testutil::calls_function(production, "to_argv(");
            let spawns = holds_bwrap_and_spawns(production);
            if !names_the_list && !spawns {
                continue;
            }
            let relative = file.display().to_string().replacen(&root, "", 1);
            if DEFINES_THEM.contains(&relative.as_str()) {
                continue;
            }
            let calls = |needle: &str| crate::testutil::calls_function(production, needle);
            // `compose_with` is `compose` with bubblewrap's setup report asked for, the same
            // compile of the filters behind either name.
            let composes = calls("argv::compose(") || calls("argv::compose_with(");
            // What each kind owes. A cage run through the shared launch command owes that call,
            // which carries the filters and the scope; a composed list owes the call that compiles
            // the filters, and the scope's own call too where the kind says so; a file that only
            // reads the list owes nothing, and spawning bubblewrap is what would make it something
            // else.
            let honoured = if RUNS_THE_SHARED_LAUNCH_COMMAND.contains(&relative.as_str()) {
                calls("cage_command(")
            } else if SPAWNS_THE_COMPOSED_LIST_IN_A_SCOPE.contains(&relative.as_str()) {
                composes && calls("cgroup::wrap(")
            } else if SPAWNS_THE_COMPOSED_LIST.contains(&relative.as_str()) {
                composes
            } else if HANDS_THE_PATH_ON.contains(&relative.as_str()) {
                // Nothing to check in the text: the claim is that no cage starts here, and the
                // two calls above are what starting one looks like.
                !composes && !calls("cage_command(")
            } else {
                !spawns
            };
            if !honoured {
                owes.push(relative.clone());
            }
            population.push(relative);
        }
        population.sort();

        let mut declared: Vec<String> = RUNS_THE_SHARED_LAUNCH_COMMAND
            .iter()
            .chain(SPAWNS_THE_COMPOSED_LIST_IN_A_SCOPE)
            .chain(SPAWNS_THE_COMPOSED_LIST)
            .chain(HANDS_THE_PATH_ON)
            .chain(READS_THE_LIST)
            .map(|s| (*s).to_string())
            .collect();
        declared.sort();
        assert_eq!(
            population, declared,
            "a file spawns bubblewrap or assembles its argument list outside `compose` without \
             saying which kind it is; add it to the list that describes it"
        );
        assert!(
            owes.is_empty(),
            "these start a cage without the mandatory seccomp filters, without the resource scope \
             their kind owes, or read the list and spawn from it: {owes:?}"
        );
    }

    /// bubblewrap is asked for its setup report only when a caller hands a pipe for it, so every
    /// other launch builds the argument list it built before. The flag names a descriptor the
    /// command carries, and comes before the cage's own command, where bubblewrap reads its options.
    #[test]
    fn the_setup_report_is_asked_for_only_with_a_pipe_and_travels_with_the_command() {
        let spec = spec(vec![], vec![], NetPolicy::Shared);
        let plain = compose(Path::new("/bwrap"), &spec).expect("compose");
        assert!(
            index_of(plain.args(), "--json-status-fd").is_none(),
            "no report unless asked"
        );

        let (_read, write) = std::os::unix::net::UnixStream::pair().expect("a pair");
        let write = File::from(std::os::fd::OwnedFd::from(write));
        let asked = compose_with(Path::new("/bwrap"), &spec, Some(&write)).expect("compose");
        let at = index_of(asked.args(), "--json-status-fd").expect("the report is asked for");
        let named: libc::c_int = asked.args()[at + 1]
            .to_str()
            .and_then(|n| n.parse().ok())
            .expect("a descriptor number");
        assert!(
            asked.files().iter().any(|f| f.as_raw_fd() == named),
            "the number names a descriptor the command carries"
        );
        assert_ne!(
            named,
            write.as_raw_fd(),
            "a duplicate travels, the caller keeps its own"
        );
        let command = index_of(asked.args(), "/bin/sh").expect("the cage's command");
        assert!(at < command, "an option, ahead of the command");
        assert_eq!(
            asked.files().len(),
            plain.files().len() + 1,
            "one descriptor more, and nothing else changes"
        );
    }
}
