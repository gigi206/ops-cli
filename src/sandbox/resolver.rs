//! The host-side sandboxed runner for resolver plugins.
//!
//! A resolver plugin turns a secret reference (`scheme://locator`) into the secret's
//! plaintext. sbx runs it **host-side, in its own bubblewrap cage** — never inside the
//! agent's cage — because a resolver is in the trusted computing base (it touches the
//! plaintext) yet is third-party code, so it is confined to exactly the least-privilege
//! grant its manifest declares ([`crate::plugins::SandboxGrant`]).
//!
//! The contract the runner implements:
//!
//! - the full ref is passed as the program's single argument (`argv[1]`);
//! - the program prints the plaintext to **stdout** and nothing else;
//! - **exit 0 with non-empty stdout** is a resolved secret; **exit 0 with empty stdout** is a
//!   clean *absent* (the caller falls through to the next source in a `from` chain); a
//!   **non-zero exit** is a hard, fail-closed error (the launch aborts, named, the next source
//!   is *not* tried — a resolver error must never silently downgrade to a weaker source). The
//!   absent-vs-resolved split is applied by the caller's shared `classify_value`, so a plugin is
//!   uniform with the `env`/`file`/`sops` built-ins and is safe in a non-terminal chain position.
//! - **stderr** is the program's diagnostic channel and must never carry the value. It is folded
//!   into the error of a failed run, and relayed as a warning when a run resolves *nothing* — so a
//!   plugin can say *why* it found nothing (a misspelled entry, an empty field) without turning a
//!   fall-through into a hard failure. A run that resolves a value stays silent: relaying its
//!   stderr could put a plaintext a careless plugin logged in front of the user.
//!
//! The plaintext lives only in sbx's own memory (host-side, in the trusted computing base) and is
//! never logged: neither the error nor the warning ever carries the plugin's stdout. What is
//! relayed is reduced to one bounded line first — a plugin is third-party code, and a diagnostic
//! is the wrong place to let it drive the user's terminal with escape sequences.
//!
//! The cage is built from the audited [`SandboxSpec`]/[`to_argv`](super::argv::to_argv) keystone, so every cage gets
//! the unconditional hardening (all namespaces, dropped capabilities, a cleared environment, a
//! fresh session, die-with-parent) for free; the runner only adds the manifest's grant on top.

use super::spec::{Mount, NetPolicy, SandboxSpec, SpecError};
use crate::plugins::ResolverPlugin;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The cage's scratch directory, which doubles as `HOME`: a private tmpfs, so a resolver that
/// writes a cache or a lockfile has somewhere ephemeral to do it without any host path.
const CAGE_HOME: &str = "/tmp";

/// Where a manifest's `programs` are bound, and the first entry of the cage's `PATH`, so a plugin
/// invokes each one by name. Deliberately not under `/opt/sbx`, which the *agent's* cage already
/// uses for its own furniture (the proc shim, the fonts config, the egress CA): the two cages
/// never meet, but one prefix meaning two unrelated things is a trap for a later reader.
const CAGE_PROGRAMS: &str = "/run/sbx-programs";

/// Where a `state = true` plugin's private directory is bound, and the value of
/// `SBX_PLUGIN_STATE`. The one writable path in an otherwise read-only cage, so it is named
/// separately from `HOME` (a tmpfs that dies with the run) to make the distinction visible in the
/// argv: this one survives, and is the only thing that does.
const CAGE_STATE: &str = "/run/sbx-state";

/// The host directory backing [`CAGE_STATE`] for `plugin`, under `<data>/plugin-state/<name>`.
///
/// Derived from the plugin's own installed directory rather than from its manifest `name`: the
/// directory name is what the installer already validated as a safe path component, so it cannot
/// traverse, and two plugins cannot collide on it the way two manifests could.
pub(crate) fn state_dir(plugin: &ResolverPlugin) -> Option<PathBuf> {
    let name = plugin.dir.file_name()?;
    Some(
        plugin
            .dir
            .parent()?
            .parent()?
            .join("plugin-state")
            .join(name),
    )
}

/// Run `plugin` to resolve `reff`, returning its raw stdout on success (the caller classifies
/// empty-as-absent). Fails closed: a non-zero exit, a runner that cannot spawn, or non-UTF-8
/// output is a hard error naming the resolver — never the secret, and never the resolver's stdout.
/// One plugin's cage, described independently of which *kind* of plugin asked for it.
///
/// A resolver and a broker differ in what they are run for, never in what a cage owes them: the
/// same grant fields, the same host answers, the same vetting of the executable. Naming that
/// overlap once is what keeps a broker from growing a second, drifting copy of this file.
pub(super) struct CagePlan<'a> {
    /// What kind of plugin this is. Carried because the grant rules a *type* imposes are re-applied
    /// here, where the grant is honoured, and not only where the manifest was read.
    pub(super) kind: crate::plugins::PluginKind,
    /// The plugin's installed directory, bound read-only at its real path.
    pub(super) dir: &'a Path,
    /// The executable to run, inside that directory.
    pub(super) exec: &'a Path,
    /// The least-privilege grant its manifest declared.
    pub(super) grant: &'a crate::plugins::SandboxGrant,
    /// What this host answers to what the manifest asked for.
    pub(super) host: &'a crate::plugins::HostConfig,
    /// How the plugin is named in a diagnostic. The scheme for a resolver, the name for a broker:
    /// each is what its own user would search for.
    pub(super) called: &'a str,
    /// The manifest `name`, which is the key a `[plugin.<name>]` table answers under. Distinct
    /// from `called` because a resolver is spoken of by the scheme it claims, while the table that
    /// configures it is keyed by its name, and a remedy naming the wrong one does not work.
    pub(super) configured_as: &'a str,
    /// What follows the executable in its argument list.
    pub(super) args: Vec<OsString>,
    /// The brokers standing for this launch, of which this plugin gets the ones its grant names.
    ///
    /// The whole set rather than the matched subset, so the rule that decides which a plugin sees —
    /// and the warning for a name nothing bound — lives in one place and reads the grant itself.
    pub(super) brokers: &'a [super::broker::Reachable],
}

/// The private state directory for a plugin installed at `dir`, by the rule [`state_dir`] applies.
fn state_dir_of(dir: &Path) -> Option<PathBuf> {
    let name = dir.file_name()?;
    Some(dir.parent()?.parent()?.join("plugin-state").join(name))
}

/// Vet the executable, resolve everything the grant asks of this host, and build the argv that
/// runs the plugin under it. Everything up to the point where a caller decides *how* to run it:
/// a resolver waits for its output, a broker keeps talking to it.
///
/// The returned files are descriptors bwrap is told to read: the cage's environment, and the
/// compiled seccomp filters. They must stay open until bwrap has read them — which for a
/// long-running child means for as long as the child lives.
///
/// The filters are the same mandatory denylist every agent cage carries, and they are here because
/// this cage is the one running code sbx did not write. Until they were, a plugin from a store had
/// the `ptrace`/`bpf`/`perf_event_open`/`userfaultfd`/keyring set and the whole mount-and-namespace
/// family available to it, while the agent's own cage refused them: the wrong way round, since the
/// plugin is also the process that may be told a credential. A plugin has no config of its own, so
/// nothing relaxes them here — [`SandboxSpec`] carries the unrelaxed policy by default and this path
/// never sets another.
pub(super) fn compose_cage(plan: &CagePlan<'_>) -> io::Result<(Vec<OsString>, Vec<std::fs::File>)> {
    // The grant rules this plugin's *type* imposes, applied again where the grant is honoured. The
    // manifest loader already refused them, so nothing reaches here today — which is the point: the
    // check that matters is the one standing between a grant and the cage it builds, not the one
    // standing between a file and a struct. A second way to build a `BrokerPlugin` (a cache, an
    // alternate loader, a regression) would otherwise hand a broker the host network, and a signer
    // holding a credential in plaintext the same, with nothing left to refuse it.
    //
    // First, before the executable is even looked at: this needs nothing from the filesystem, and a
    // grant the type forbids is refused whatever the file turns out to be.
    crate::plugins::check_kind_sandbox(plan.kind, plan.grant).map_err(|why| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing to run the `{}` plugin: {why}", plan.called),
        )
    })?;

    // The executable is in the trusted computing base. The perimeter is the data directory's
    // owner-only permissions (a project cannot write there), but defend the thing we actually
    // exec directly: refuse it unless it is a regular file owned by us and not writable by group
    // or other. An attacker can only create files owned by *their* uid, so the owner check is the
    // load-bearing one against a planted executable. (`sbx plugins` surfaces the same verdict.)
    crate::plugins::check_exec_at(plan.exec).map_err(|why| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing to run the plugin {}: {why}", plan.exec.display()),
        )
    })?;

    // The private state directory has to exist before bwrap binds it, and owner-only from the
    // start: it will hold a refresh token, and a directory created world-readable and tightened
    // afterwards is readable in between.
    if plan.grant.state
        && let Some(dir) = state_dir_of(plan.dir)
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|e| {
                io::Error::other(format!(
                    "could not create the state directory for the `{}` plugin at {}: {e}",
                    plan.called,
                    dir.display()
                ))
            })?;
    }

    let plugin = plan;
    let mut allow_env = resolve_allow_env(&plugin.grant.allow_env);
    // The path-valued variables resolve the same way, and their values are additionally bound.
    // They join `allow_env` because naming one in `allow_env_paths` *is* the pass-through: binding
    // the path without handing the tool the variable pointing at it would leave the tool reading
    // its default, with the grant paid for nothing.
    let mut env_paths = resolve_env_paths(&plugin.grant.allow_env_paths);
    allow_env.extend(env_paths.iter().cloned());
    // What the host's `[plugin.<name>]` table answers, applied last so it WINS over the same name
    // in sbx's environment: a config that names a value is more deliberate than whatever the
    // invoking shell happened to export. Each name was already checked against the manifest by the
    // config layer, so nothing here can introduce a variable the plugin does not read.
    for (key, value) in &plugin.host.env {
        allow_env.retain(|(k, _)| k != key);
        allow_env.push((key.clone(), value.clone()));
        // A path-valued one is bound as well as passed, exactly as when it comes from the
        // environment — otherwise configuring a relocated store would aim the tool at a path the
        // cage does not have, the failure `allow_env_paths` exists to remove.
        if plugin.grant.allow_env_paths.iter().any(|k| k == key) {
            env_paths.retain(|(k, _)| k != key);
            if Path::new(value).is_absolute() {
                env_paths.push((key.clone(), value.clone()));
            } else {
                crate::diag::warn(&format!(
                    "not binding ${key} for the `{}` plugin — the value `{value}` configured for \
                     it is not an absolute path",
                    plugin.called
                ));
            }
        }
    }
    let brokers = resolve_brokers(plugin);
    let programs = resolve_programs(plugin)?;
    // A nix-installed program is not a self-contained file, so the paths it needs come with it.
    let closure = nix_closures(&programs)?;
    let mut binds = Vec::with_capacity(programs.len());
    for program in &programs {
        binds.push((program.name.clone(), program.bind_src()?));
    }
    let spec =
        cage_spec(plugin, &allow_env, &env_paths, &binds, &closure, &brokers).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "cannot build the plugin sandbox for `{}`: {e:?}",
                    plugin.called
                ),
            )
        })?;

    // The returned descriptor is where the cage's environment is read from, and the reason it is a
    // descriptor is this cage in particular: a plugin's `allow_env` is how it is handed its *own*
    // credential (a vault token, an age key), and an argument list is world-readable.
    super::launch::seccomp_argv(&spec)
}

/// How long sbx waits on one host-side resolution that reaches nothing but itself.
///
/// The line is not invented here: the project already draws it once, for the resource a broker
/// fronts. Past [`MAX_HOST_DEADLINE_SECS`](crate::plugins::broker::MAX_HOST_DEADLINE_SECS),
/// "whatever is on the other side is wedged rather than thinking, and no pinentry prompt a person
/// answers takes that long". A resolver plugin is a program rather than a protocol — it may be
/// reaching a remote vault across a link sbx knows nothing about — so a tighter bound would be a
/// number rather than a rule, and it would kill a plugin that is still working.
///
/// What it buys is the difference between finite and infinite on the launch's critical path: the
/// same call runs from `egress::start` before the agent exists and from the refresh thread while it
/// does, and neither may be held open forever by a plugin that never answers.
///
/// What would reopen the number: a resolver manifest declaring its own bound, the way a broker
/// manifest declares `host_deadline`. Until a shipped plugin needs one, there is nothing to
/// configure and nothing to keep in step.
pub(super) const HOST_RESOLUTION_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(crate::plugins::broker::MAX_HOST_DEADLINE_SECS as u64);

/// The deadline for one run of a plugin whose cage can reach `brokers`.
///
/// A resolver may wait on a broker, and a broker may hold one exchange for as long as its own
/// manifest declares — a gpg-agent opening a pinentry answers when the person does. A resolution
/// bounded tighter than a wait it is allowed to contain would kill a plugin behaving exactly as a
/// manifest permits, so the longest reachable broker wait is **added** to the base rather than
/// compared against it: the two waits happen one inside the other, not instead of one another.
fn deadline_for(brokers: &[super::broker::Reachable]) -> std::time::Duration {
    HOST_RESOLUTION_DEADLINE
        + brokers
            .iter()
            .map(|b| b.host_deadline)
            .max()
            .unwrap_or_default()
}

/// The most sbx will read from one host-side step of the secret chain, on each stream.
///
/// The same ceiling a broker frame meets, and deliberately not a second number: it is the largest
/// thing sbx will take from a plugin on any channel, and two ceilings would only mean the smaller
/// one had been chosen rather than derived. What it guards is what a time bound cannot — a plugin
/// answering forever is stopped by the deadline, but a plugin answering *fast* is not, and
/// `read_to_end` on a pipe grows sbx at the speed of the writer.
const MAX_RESOLUTION_BYTES: usize = crate::plugins::broker::MAX_FRAME_CEILING;

/// Read one of a child's pipes on its own thread, handing the bytes back over `tx`.
///
/// Two pipes need two readers: a process that fills stderr while sbx is reading stdout would
/// otherwise block on a pipe nobody is draining, and sbx would block on the one it is draining —
/// a deadlock neither side can see. Reading on threads sbx does not have to join is also what
/// lets a bounded wait *be* bounded: the reader is abandoned, not waited for.
fn drain<R: io::Read + Send + 'static>(
    pipe: R,
    is_stdout: bool,
    tx: std::sync::mpsc::Sender<(bool, Vec<u8>)>,
) {
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        // One byte past the ceiling, so a stream that sits exactly on it stays readable and only
        // the stream that crosses it is refused.
        let _ = pipe
            .take(MAX_RESOLUTION_BYTES as u64 + 1)
            .read_to_end(&mut buf);
        // The read end closes here, which is what keeps an over-long answer from becoming a
        // timeout: a process still writing takes EPIPE and stops, instead of blocking on a pipe
        // nobody is draining until the deadline runs out.
        let _ = tx.send((is_stdout, buf));
    });
}

/// Run `cmd` and return its output, or fail once `deadline` has passed. `what` names the subject
/// in the timeout error ("the `pass` resolver plugin"), which carries [`io::ErrorKind::TimedOut`]
/// so a caller can tell it apart from the command's own failures; a spawn failure comes back
/// untouched, so its kind still reads (`NotFound` for a binary that is not installed).
///
/// The one definition of how long a host-side step of the secret chain may take: the resolver
/// runner and the sops path both come through here, so "this did not answer" means the same thing
/// whichever source a secret came from.
///
/// **What is bounded is the wait, not the process** — and the difference is the whole design.
/// Killing what sbx spawned does not end the wait, because a pipe stays open as long as *anything*
/// holds its write end: a shell that forks a helper, sops that forks gpg. Measured, not assumed —
/// killing `sh -c 'sleep 30'` and then reading to EOF takes thirty seconds, because `sleep`
/// inherited the descriptor and outlived its parent. So the process is killed *and* the readers
/// are abandoned where they stand, and the call returns on time whatever still holds the pipe.
///
/// The kill goes through a **pidfd**. It pins one process, so it cannot land on whatever inherited
/// a pid — and the resolver cage, whose `--die-with-parent` init is the process being signalled,
/// comes down whole with it, the same teardown a session stop relies on.
pub(super) fn output_within(
    cmd: &mut Command,
    deadline: std::time::Duration,
    what: &str,
) -> io::Result<std::process::Output> {
    output_within_armed_by(cmd, deadline, what, crate::session::open_pidfd)
}

/// [`output_within`] with the arming passed in, so the one branch a machine will not produce on
/// demand — the kernel refusing a pidfd, out of descriptors — is reachable from a test. What that
/// branch has to get right is not the message but the process: it must not be left running.
fn output_within_armed_by(
    cmd: &mut Command,
    deadline: std::time::Duration,
    what: &str,
    arm: fn(u32) -> Result<libc::c_int, i32>,
) -> io::Result<std::process::Output> {
    use std::os::unix::process::ExitStatusExt;

    let started = std::time::Instant::now();
    let mut child = cmd
        // Set here rather than left to each caller, because `spawn` and `output` do not agree on
        // them: `output` captures both pipes and closes stdin, `spawn` inherits all three. A host
        // step of the secret chain reads no stdin — it must not block on a terminal, and a plugin
        // prompting there would be prompting *as* sbx — and its stdout is the value, which belongs
        // to sbx rather than to sbx's own output.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let pidfd = match arm(child.id()) {
        Ok(fd) => fd,
        Err(errno) => {
            // Nothing would be bounding this process, so it does not get to run at all. Failing
            // here rather than falling back to an unbounded run keeps the promise this function
            // makes: a silent second path would be an untested degradation on the chain that
            // carries the plaintext.
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other(format!(
                "the deadline could not be armed: {}",
                io::Error::from_raw_os_error(errno)
            )));
        }
    };
    let (tx, rx) = std::sync::mpsc::channel();
    if let Some(pipe) = child.stdout.take() {
        drain(pipe, true, tx.clone());
    }
    if let Some(pipe) = child.stderr.take() {
        drain(pipe, false, tx.clone());
    }
    // The last sender the caller holds, so a reader that died leaves the channel disconnected
    // rather than making the collection below wait out the deadline for a message never coming.
    drop(tx);

    let exited = crate::session::wait_for_exit(pidfd, deadline);
    if !exited {
        let _ = crate::session::send_signal(pidfd, libc::SIGKILL);
    }
    crate::session::close_fd(pidfd);
    // Immediate either way: the poll said the process is gone, or SIGKILL just made it so.
    let status = child.wait()?;

    // Collect what the readers have, against what is left of the same deadline — the bound covers
    // reading the answer, not only producing it.
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut read_both = true;
    for _ in 0..2 {
        let left = deadline.saturating_sub(started.elapsed());
        match rx.recv_timeout(left) {
            Ok((true, bytes)) => stdout = bytes,
            Ok((false, bytes)) => stderr = bytes,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                read_both = false;
                break;
            }
        }
    }

    // A process exiting on its own in the instant the poll timed out is not a timeout: SIGKILL is
    // the one exit no program produces for itself, so the signal is proof of what sbx did. The
    // second half is the pipe that never closed — the answer was not read in time, whoever is
    // still holding the descriptor.
    // What the process said is the value, so an answer past the ceiling is refused rather than
    // truncated: half a secret is not a smaller secret. An over-long *stderr* is not a failure —
    // it is a diagnostic, already cut to one bounded line before anything sees it — so it stops at
    // the ceiling and the run carries on.
    if stdout.len() > MAX_RESOLUTION_BYTES {
        return Err(io::Error::other(format!(
            "{what} answered with more than {MAX_RESOLUTION_BYTES} bytes"
        )));
    }
    if (!exited && status.signal() == Some(libc::SIGKILL)) || !read_both {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "{what} did not answer within {} seconds and was killed",
                deadline.as_secs()
            ),
        ));
    }
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

/// Run `plugin` to resolve `reff`, returning its raw stdout on success (the caller classifies
/// empty-as-absent). The run is bounded — see [`deadline_for`].
pub(crate) fn run(
    bwrap: &Path,
    plugin: &ResolverPlugin,
    reff: &str,
    brokers: &[super::broker::Reachable],
) -> io::Result<String> {
    run_within(bwrap, plugin, reff, brokers, deadline_for(brokers))
}

/// [`run`], with the deadline passed in so a test can prove the bound without waiting out a real
/// one.
fn run_within(
    bwrap: &Path,
    plugin: &ResolverPlugin,
    reff: &str,
    brokers: &[super::broker::Reachable],
    deadline: std::time::Duration,
) -> io::Result<String> {
    let plan = CagePlan {
        kind: crate::plugins::PluginKind::Resolver,
        dir: &plugin.dir,
        exec: &plugin.exec,
        grant: &plugin.sandbox,
        host: &plugin.host,
        called: &plugin.scheme,
        configured_as: &plugin.name,
        args: vec![OsString::from(reff)],
        brokers,
    };
    // `_env` holds the environment descriptor open until bwrap has run.
    let (argv, _env) = compose_cage(&plan)?;
    let mut cmd = Command::new(bwrap);
    cmd.args(argv);
    let out = match output_within(
        &mut cmd,
        deadline,
        &format!("the `{}` resolver plugin", plugin.scheme),
    ) {
        Ok(out) => out,
        // The timeout already names the plugin and what happened to it; a spawn failure does not.
        Err(e) if e.kind() == io::ErrorKind::TimedOut => return Err(e),
        Err(e) => {
            return Err(io::Error::other(format!(
                "could not run the `{}` resolver plugin: {e}",
                plugin.scheme
            )));
        }
    };

    if !out.status.success() {
        // Fold in the plugin's stderr (its diagnostics) but never its stdout (the plaintext).
        let detail = one_line_detail(&out.stderr);
        return Err(io::Error::other(format!(
            "the `{}` resolver plugin failed{}",
            plugin.scheme,
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        )));
    }

    let value = String::from_utf8(out.stdout).map_err(|_| {
        io::Error::other(format!(
            "the `{}` resolver plugin produced output that is not valid UTF-8",
            plugin.scheme
        ))
    })?;

    // This run resolved nothing, so the caller is about to fall through in silence. Relay the
    // plugin's own account of why: a misspelled locator and a source that genuinely does not hold
    // the secret are otherwise indistinguishable, and only the plugin can tell them apart.
    if let Some(detail) = absent_detail(&value, &out.stderr) {
        crate::diag::warn(&format!(
            "the `{}` resolver plugin resolved nothing: {detail}",
            plugin.scheme
        ));
    }
    Ok(value)
}

/// The longest plugin diagnostic sbx repeats. A resolver's stderr is text of its own choosing, so
/// bound how much of it can reach a terminal or a log line.
const DETAIL_MAX: usize = 200;

/// Reduce a plugin's stderr to one safe display line: control characters (a newline that would
/// forge a second diagnostic, an escape that would drive the terminal) become spaces, runs of
/// whitespace collapse, and the result is truncated. Never rejects — a diagnostic is a label, so a
/// sloppy one is cleaned rather than dropped. Non-UTF-8 bytes are replaced, not refused: a plugin
/// that garbles its own message must still be able to name the problem.
fn one_line_detail(raw: &[u8]) -> String {
    let cleaned: String = String::from_utf8_lossy(raw)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut out = String::with_capacity(cleaned.len());
    for word in cleaned.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    if out.chars().count() > DETAIL_MAX {
        out = out.chars().take(DETAIL_MAX - 1).collect::<String>() + "…";
    }
    out
}

/// The diagnostic to relay for a **successful** run, or `None` for silence. Pure, so the rule that
/// decides whether a plugin gets a voice is testable without launching bubblewrap.
///
/// A run that produced a value has nothing to explain and is kept silent — its stderr is dropped
/// rather than repeated, because a careless plugin that logged the secret there would otherwise put
/// the plaintext in front of the user. Only a run that produced **nothing** speaks, and "nothing"
/// is decided by the very rule the caller classifies values with
/// ([`super::egress::strip_trailing_line_ending`]), so the warning cannot disagree with the
/// fall-through it explains.
fn absent_detail(stdout: &str, stderr: &[u8]) -> Option<String> {
    if !super::egress::strip_trailing_line_ending(stdout).is_empty() {
        return None;
    }
    let detail = one_line_detail(stderr);
    (!detail.is_empty()).then_some(detail)
}

/// Read each declared `allow_env` variable from sbx's environment, keeping only the ones that
/// are set: an unset variable is simply not passed (the resolver sees a cleared environment plus
/// exactly these). A non-Unicode value cannot become a `--setenv` value, so it is skipped with a
/// warning rather than silently dropped.
fn resolve_allow_env(keys: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for key in keys {
        match std::env::var(key) {
            Ok(v) => out.push((key.clone(), v)),
            Err(std::env::VarError::NotPresent) => {}
            Err(std::env::VarError::NotUnicode(_)) => {
                crate::diag::warn(&format!(
                    "not passing ${key} to a resolver plugin — its value is not valid Unicode"
                ));
            }
        }
    }
    out
}

/// Match a plugin's declared `brokers` against the ones standing for this launch.
///
/// The grant is answered only where a global `[broker.<name>]` bound that name and the broker came
/// up: a name nothing bound yields no socket, never the raw resource the broker fences. Said once
/// per pairing rather than once per resolution — a launch with five `pass://` secrets runs this
/// plugin five times, and five identical lines read as five faults.
fn resolve_brokers<'a>(plugin: &CagePlan<'a>) -> Vec<&'a super::broker::Reachable> {
    let mut out = Vec::with_capacity(plugin.grant.brokers.len());
    for name in &plugin.grant.brokers {
        match plugin.brokers.iter().find(|b| &b.name == name) {
            Some(reachable) => out.push(reachable),
            None => warn_once(&format!(
                "the `{}` plugin needs the `{name}` broker, which this launch has not stood up — \
                 bind it with `[broker.{name}] socket` in the global config, or the plugin runs \
                 without it",
                plugin.called
            )),
        }
    }
    out
}

/// Emit a warning the first time this process is asked to. The state is the message itself, so two
/// callers that would say the same thing say it once and two that differ both speak.
fn warn_once(message: &str) {
    use std::collections::BTreeSet;
    use std::sync::{Mutex, OnceLock};
    static SAID: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    let said = SAID.get_or_init(|| Mutex::new(BTreeSet::new()));
    // A poisoned lock is not a reason to lose a warning: recover the set and speak anyway.
    let mut said = said.lock().unwrap_or_else(|e| e.into_inner());
    if said.insert(message.to_string()) {
        crate::diag::warn(message);
    }
}

/// Read each declared `allow_env_paths` variable from sbx's environment, keeping the ones that
/// are set to a usable path. The caller both passes these through as environment *and* binds
/// their values, so this is the single place the two can agree.
///
/// A **relative** value is dropped with a warning rather than bound. It is the user's own value,
/// not a plugin's, so it is a mistake to report rather than a grant to refuse a launch over — but
/// it cannot be bound: `--ro-bind-try foo foo` names a path relative to a working directory the
/// cage does not share, so it would silently mean something other than what the user wrote. This
/// mirrors the posture `$SBX_DATA_DIR` takes on a relative override.
///
/// A value naming a path that does not exist is kept for the environment and simply binds
/// nothing (the mount is a `try`): the tool then reports what it could not find, which is a
/// better diagnostic than a bind failure the user cannot place.
fn resolve_env_paths(keys: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (key, value) in resolve_allow_env(keys) {
        if !Path::new(&value).is_absolute() {
            crate::diag::warn(&format!(
                "not binding ${key} for a resolver plugin — its value `{value}` is not an \
                 absolute path"
            ));
            continue;
        }
        out.push((key, value));
    }
    out
}

/// Locate every program the manifest declares, on **sbx's own `PATH`** — the one the user's
/// shell hands us, so a tool found by the user is found by the resolver, whatever installed it.
/// Returns each name with the path to bind, or fails closed naming what is missing.
///
/// The resolved binary enters the trusted computing base: it is `execve`d inside the resolver's
/// cage, on the plaintext path. So each candidate is held to the verdict sbx applies to an engine
/// it picks off `PATH` ([`crate::store::host_exec_verdict`]): a regular file, owned by us or by
/// root, not world-writable. Every match is scanned rather than just the first, so a
/// world-writable early entry does not shadow a legitimate binary further down `PATH` — it is
/// skipped, with a warning, exactly as the engine lookup does.
///
/// The path is canonicalized because binding the *symlink* would bind a dangling name: a nix
/// profile's `bin/x` points into `/nix/store`, which the cage does not have.
/// Where `PATH` has no answer, a program the host configured under `[plugin.<name>] programs` and
/// `sbx plugins install` already built is used instead. Only the out-link is read here — a launch
/// never builds — so the fallback costs one `readlink` and never stalls a secret on a nix build.
fn resolve_programs(plugin: &CagePlan<'_>) -> io::Result<Vec<Program>> {
    let mut out = Vec::with_capacity(plugin.grant.programs.len());
    for name in &plugin.grant.programs {
        if let Some(path) = locate_program(name) {
            out.push(Program {
                name: name.clone(),
                path,
                origin: Origin::Host,
            });
            continue;
        }
        if let Some(path) = crate::store::Layout::from_env().and_then(|l| {
            let dir_name = plugin
                .dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            crate::plugins::programs::provisioned(&l, dir_name, name)
        }) {
            out.push(Program {
                name: name.clone(),
                path,
                origin: Origin::Provisioned,
            });
            continue;
        }
        // Both answers are exhausted, so this is the terminal state: name the two remedies, since
        // which one applies is the user's to know. The configured-but-unbuilt case reads as the
        // second one, and re-running the install is what turns a `programs` entry added after the
        // fact into a built program.
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "the `{}` plugin needs the program `{name}`, which is not on sbx's PATH and has \
                 not been provisioned — install it (or add its directory to PATH), or name it in \
                 `[plugin.{}] programs` as `{name} = \"nix:<attribute>\"` and re-run \
                 `sbx plugins install`",
                plugin.called, plugin.configured_as
            ),
        ));
    }
    Ok(out)
}

/// A declared program, resolved, with **how** it was found.
///
/// The distinction is load-bearing rather than descriptive: a host tool's path is also what its own
/// interpreter line and library references name, whereas a provisioned one's content lives at a
/// physical path under sbx's store while every reference inside it names the *logical* path. Both
/// live under `/nix/store` often enough that inspecting the path cannot tell them apart, so the
/// origin is recorded when the program is found and never re-derived.
struct Program {
    name: String,
    /// The host path for [`Origin::Host`]; the **logical** store path for [`Origin::Provisioned`].
    path: PathBuf,
    origin: Origin,
}

/// How a declared program was found. See [`Program`].
#[derive(PartialEq, Eq, Clone, Copy)]
enum Origin {
    /// On sbx's own `PATH`.
    Host,
    /// Built into sbx's store for this plugin by `sbx plugins install`.
    Provisioned,
}

impl Program {
    /// The host path a launch binds this program **from**.
    ///
    /// Equal to [`Self::path`] for a host tool. For a provisioned one it is not: `path` is the
    /// logical store path, which nothing outside a cage can open, so the source has to be the
    /// physical location of the same content under sbx's store root.
    fn bind_src(&self) -> io::Result<PathBuf> {
        match self.origin {
            Origin::Host => Ok(self.path.clone()),
            Origin::Provisioned => crate::store::Layout::from_env()
                .map(|l| crate::store::physical_path(&l, &self.path))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "cannot locate sbx's data directory to bind a provisioned program",
                    )
                }),
        }
    }
}

/// How many store paths a launch would bind for these declared programs, or `None` when none of
/// them lives in the nix store and no closure is involved.
///
/// For `sbx plugins info`. A closure is the one part of a grant a reader cannot infer from the
/// manifest, which names no store path at all, so leaving it off the inspection view would hide
/// the largest thing a launch binds. Resolved exactly as a launch resolves it. An error is
/// reported as no closure rather than failing the inspection: `info` describes a grant, and a
/// launch is where an unreadable closure has to be fatal.
pub(crate) fn nix_closure_paths(programs: &[String]) -> Option<usize> {
    let resolved: Vec<Program> = programs
        .iter()
        .filter_map(|n| {
            locate_program(n).map(|p| Program {
                name: n.clone(),
                path: p,
                origin: Origin::Host,
            })
        })
        .collect();
    if !resolved.iter().any(|p| p.path.starts_with(NIX_STORE)) {
        return None;
    }
    nix_closures(&resolved).ok().map(|c| c.len())
}

/// The store paths every nix-resolved program among `programs` needs, deduplicated, each as the
/// `(source, destination)` pair a launch binds it with.
///
/// The pair is what makes a provisioned program work at all. A host tool's closure entries are
/// bound at their own location, source and destination alike. A provisioned one's are not: the
/// content sits under sbx's own store root while the program's interpreter line and library
/// references name the *logical* `/nix/store/…` path, so each entry must be bound with the physical
/// path as source and the logical one as destination. Bound at the physical path instead, a wrapper
/// script fails at `execve` with nothing pointing at why.
///
/// Only programs that actually resolved under `/nix/store` are queried, so a host with no nix
/// package pays nothing — no subprocess, no requirement that `nix-store` exist. Deduplicated
/// because two programs from one profile share most of their closure, and each entry becomes a
/// bind argument.
fn nix_closures(programs: &[Program]) -> io::Result<Vec<(PathBuf, PathBuf)>> {
    let mut seen = std::collections::BTreeMap::new();
    for program in programs {
        if !program.path.starts_with(NIX_STORE) {
            continue;
        }
        // A provisioned path is only known to sbx's own store database, so the query has to name
        // that store; the host's database does not hold it and reports it invalid.
        let layout = match program.origin {
            Origin::Host => None,
            Origin::Provisioned => Some(crate::store::Layout::from_env().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "cannot locate sbx's data directory to read a provisioned program's store paths",
                )
            })?),
        };
        for logical in nix_closure(&program.path, layout.as_ref())? {
            let src = match &layout {
                None => logical.clone(),
                Some(l) => crate::store::physical_path(l, &logical),
            };
            seen.insert(logical, src);
        }
    }
    Ok(seen.into_iter().map(|(dest, src)| (src, dest)).collect())
}

/// The nix store prefix. A program resolving under it is not a self-contained file: its
/// interpreter line, its libraries and the helpers it shells out to are all other store paths.
const NIX_STORE: &str = "/nix/store/";

/// Every store path a nix-installed program needs, itself included, or an error naming why the
/// question could not be answered.
///
/// A `pass` from nix is a wrapper script whose shebang is a store path and whose helpers are
/// more of them; a `keepassxc-cli` from nix links against a Qt closure. Binding the resolved
/// file alone leaves both unable to start, which is why manifests used to grant the **whole**
/// store to run one program. `nix-store -qR` names exactly the paths that program needs, so the
/// grant becomes the closure rather than the store.
///
/// Fails rather than falling back to binding nothing. A silent fallback would reproduce the trap
/// this repository already paid for once: a binary that is present and executable and still dies
/// at `execve`, surfacing as a bare exit 127 with nothing pointing at the cause.
fn nix_closure(program: &Path, layout: Option<&crate::store::Layout>) -> io::Result<Vec<PathBuf>> {
    let nix_store = crate::store::resolve_nix_store(None).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "`{}` is a nix store path, so the paths it needs must be read with `nix-store`, \
                 which is not on sbx's PATH — install nix, or use a build of that program which \
                 does not come from the store",
                program.display()
            ),
        )
    })?;
    let mut cmd = Command::new(&nix_store);
    // A path sbx provisioned lives in sbx's own store, which is a different database: without this
    // the query reports the path invalid, since the host's nix knows nothing of it.
    if let Some(layout) = layout {
        cmd.arg("--store").arg(layout.store_dir());
    }
    // The one subprocess in this file that does **not** go through `output_within`, and the
    // exemption is deliberate rather than an oversight of the same rule. What that helper bounds is
    // an untrusted writer: a plugin chooses what to say and how long to take. This is nix's own
    // binary, run on sbx's side of every boundary, and what it says is a list of store paths whose
    // size follows the closure being queried. Bounding it by size would refuse a large closure,
    // and bounding it by time would make a cold query look like a hostile one.
    let out = cmd
        .arg("--query")
        .arg("--requisites")
        .arg(program)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| io::Error::other(format!("could not run {}: {e}", nix_store.display())))?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "could not read the store paths `{}` needs: {}",
            program.display(),
            one_line_detail(&out.stderr)
        )));
    }
    let text = String::from_utf8(out.stdout)
        .map_err(|_| io::Error::other("`nix-store --query --requisites` produced non-UTF-8"))?;
    Ok(text.lines().map(PathBuf::from).collect())
}

/// Whether the cage will hold what a binary at this path needs to *load*, not merely the file.
///
/// The runner binds the host userland read-only and computes a closure for anything in the nix
/// store, so a binary from either place brings its shared libraries with it. A binary from
/// anywhere else — a Homebrew cellar, an `/opt` tree, a language package manager — is bound as one
/// file whose libraries stay outside, and the cage answers `cannot execute: required file not
/// found`: an error from the dynamic loader that names neither the missing library nor the reason.
///
/// Measured on this machine: Homebrew's `curl` needs 24 libraries under `/home/linuxbrew`, while
/// `/usr/bin/curl` needs none outside the userland the cage already has.
fn cage_can_load(path: &Path) -> bool {
    ["/usr/", "/bin/", "/sbin/", NIX_STORE]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// The path a declared program resolves to, or `None` when nothing usable is on `PATH`. Shared
/// with `sbx plugins info`, so what a user is shown is what a launch would bind — a second
/// lookup would be a second chance to disagree.
pub(crate) fn locate_program(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let euid = unsafe { libc::geteuid() };
    let mut usable = Vec::new();
    for cand in crate::pathfind::find_all_on_path(name) {
        let Ok(meta) = std::fs::metadata(&cand) else {
            continue;
        };
        match crate::store::host_exec_verdict(meta.uid(), meta.mode(), euid) {
            // Canonicalized: binding the *symlink* would bind a dangling name, since a nix
            // profile's `bin/x` points into `/nix/store`, which the cage does not have.
            Ok(()) => usable.push(std::fs::canonicalize(&cand).unwrap_or(cand)),
            Err(why) => crate::diag::warn(&format!(
                "ignoring {} for the program `{name}` ({why})",
                cand.display()
            )),
        }
    }

    // Prefer a candidate the cage can actually load over an earlier one it cannot. `PATH` order
    // expresses which build the *host* prefers, and that is a different question: a package manager
    // placed ahead of the system usually wins on your shell and loses in here, for reasons no
    // manifest can express and no error message explains.
    if let Some(loadable) = usable.iter().find(|p| cage_can_load(p)) {
        if usable.first() != Some(loadable) {
            crate::diag::warn(&format!(
                "using {} for the program `{name}` rather than {}, whose libraries live outside \
                 the resolver sandbox",
                loadable.display(),
                usable[0].display()
            ));
        }
        return Some(loadable.clone());
    }
    // Nothing the cage is known to hold. Take the first anyway — a statically linked binary or a
    // self-contained bundle runs fine, and refusing here would break a working setup on a guess —
    // but say what will break if it does not, since the loader's own message will not.
    let first = usable.into_iter().next()?;
    crate::diag::warn(&format!(
        "the program `{name}` resolves to {}, outside the host userland the resolver sandbox \
         binds — if it fails with `cannot execute: required file not found`, its shared libraries \
         are the reason, and a system build of `{name}` would resolve it",
        first.display()
    ));
    Some(first)
}

/// Build the cage for one resolver run. Pure: a plugin grant, the already-resolved `allow_env`
/// values and the already-located `programs` in, a [`SandboxSpec`] out, so the bind/env/network
/// shape is testable without launching bubblewrap.
fn cage_spec(
    plugin: &CagePlan<'_>,
    allow_env: &[(String, String)],
    env_paths: &[(String, String)],
    programs: &[(String, PathBuf)],
    closure: &[(PathBuf, PathBuf)],
    brokers: &[&super::broker::Reachable],
) -> Result<SandboxSpec, SpecError> {
    let ro = |p: &str| Mount::RoBind {
        src: PathBuf::from(p),
        dest: PathBuf::from(p),
    };
    let ro_try = |p: &str| Mount::RoBindTry {
        src: PathBuf::from(p),
        dest: PathBuf::from(p),
    };
    let symlink = |target: &str, dest: &str| Mount::Symlink {
        target: PathBuf::from(target),
        dest: PathBuf::from(dest),
    };

    let mut mounts = vec![
        // The host userland, read-only — every resolver runs host tools (gpg, vault, curl).
        ro("/usr"),
        symlink("usr/lib", "/lib"),
        symlink("usr/lib64", "/lib64"),
        symlink("usr/bin", "/bin"),
        // The dynamic loader cache, where the host has one.
        ro_try("/etc/ld.so.cache"),
        // The plugin itself, read-only at its real path so `exec` resolves and any sibling helper
        // it ships is reachable; a same-uid write cannot tamper with it through a read-only bind.
        Mount::RoBind {
            src: plugin.dir.to_path_buf(),
            dest: plugin.dir.to_path_buf(),
        },
    ];

    // The structural pseudo-filesystems first, so the grant's own binds layer ON TOP of them. In
    // particular the `/tmp` tmpfs must precede the grant paths: `CAGE_HOME` is `/tmp`, and bwrap
    // applies mounts in argv order, so a tmpfs mounted AFTER a grant path under `/tmp` would shadow
    // it (a manifest granting e.g. an agent socket under `/tmp/...` would silently vanish).
    mounts.push(Mount::Proc {
        dest: PathBuf::from("/proc"),
    });
    mounts.push(Mount::Dev {
        dest: PathBuf::from("/dev"),
    });
    mounts.push(Mount::Tmpfs {
        dest: PathBuf::from(CAGE_HOME),
    });

    // The grant's extra read-only paths, layered over the structural mounts above. Each becomes a
    // separate `--ro-bind-try <src> <dest>` argv pair (see [`to_argv`](super::argv::to_argv)) — never interpolated into a
    // shell string — so a residual `$` a manifest's small path expansion left behind is an inert
    // literal here, not an injection. `try` keeps a manifest portable: a path that names a runtime
    // artifact (e.g. the gpg-agent socket directory under `$XDG_RUNTIME_DIR`) is skipped where it is
    // absent, and the resolver fails closed inside if it genuinely needs what is missing.
    for p in &plugin.grant.allow_paths {
        mounts.push(Mount::RoBindTry {
            src: p.clone(),
            dest: p.clone(),
        });
    }

    // The paths named by `allow_env_paths`, bound at their own location so the variable the tool
    // reads and the path it finds are the same string. `try`, like the grant paths above: a
    // variable pointing at something that is not there yet is the user's problem to see reported
    // by the tool, not a launch sbx refuses to start.
    for (_, value) in env_paths {
        mounts.push(Mount::RoBindTry {
            src: PathBuf::from(value),
            dest: PathBuf::from(value),
        });
    }

    // The declared programs, each bound read-only under one directory that the cage's `PATH`
    // starts with, so the plugin calls the tool by name and never has to guess where a package
    // manager put it. `RoBind` rather than `RoBindTry`: the path was just resolved, so a failure
    // to bind it is a real fault and not a portability allowance. Same layering rule as the
    // grant paths above — after the structural pseudo-filesystems, never before.
    for (name, host) in programs {
        mounts.push(Mount::RoBind {
            src: host.clone(),
            dest: PathBuf::from(CAGE_PROGRAMS).join(name),
        });
    }

    // The store paths a nix-installed program needs, each at the location its own interpreter line
    // and library references name, which is the only place they can be found. This is what a
    // manifest used to buy by granting the entire store: the closure is what the program actually
    // reads, and nothing else in the store comes with it. Source and destination differ for a
    // program sbx provisioned, whose content lives under sbx's own store root while every reference
    // inside it names `/nix/store` — see [`nix_closures`].
    for (src, dest) in closure {
        mounts.push(Mount::RoBindTry {
            src: src.clone(),
            dest: dest.clone(),
        });
    }

    // The brokers this grant named, each bound where its protocol's clients look for it. **After**
    // the grant paths above, and that order is the point: a manifest that also binds the raw
    // resource — the case this grant exists to replace — must not end up shadowing the fence with
    // it. Read-only, like every other socket the cage connects to.
    for reachable in brokers {
        mounts.push(Mount::RoBind {
            src: reachable.src.clone(),
            dest: reachable.dest.clone(),
        });
    }

    // A network grant shares the host network and binds the DNS + TLS files a resolver needs to
    // reach a remote secret store; without it the cage gets an empty network namespace (no egress
    // at all — fail-closed). The files are `try`, so a host missing one does not fail the launch.
    // The private state directory, writable, for a plugin that declared it. Bound rather than
    // created inside the cage so it outlives the run: what a rotating credential's resolver writes
    // here is the only copy of the token that buys the next one.
    if plugin.grant.state
        && let Some(src) = state_dir_of(plugin.dir)
    {
        mounts.push(Mount::Bind {
            src,
            dest: PathBuf::from(CAGE_STATE),
        });
    }

    let net = if plugin.grant.network {
        for f in [
            "/etc/resolv.conf",
            "/etc/nsswitch.conf",
            "/etc/hosts",
            "/etc/ssl",
        ] {
            mounts.push(ro_try(f));
        }
        NetPolicy::Shared
    } else {
        NetPolicy::Isolated
    };

    // The masks, laid over everything the grant bound. After the binds, never before: a tmpfs put
    // down first would simply be covered by the bind that follows it. `Tmpfs` rather than an
    // unbind because bwrap has no unbind — an empty filesystem is how a path is made to hold
    // nothing, and it is what makes a wide grant survivable (`~/.gnupg` whole, minus its private
    // keys).
    for p in &plugin.grant.mask_paths {
        mounts.push(Mount::Tmpfs { dest: p.clone() });
    }

    // The grant's pass-throughs first, then sbx's structural HOME/PATH last so the cage's own
    // identity always wins over a manifest that happens to name them (self-harm at worst).
    let mut env: Vec<(String, String)> = allow_env.to_vec();
    // Each broker's own variables, for a client that is told where its socket is rather than
    // computing it. After the pass-throughs, so a stale value inherited from sbx's environment
    // cannot aim the tool past the fence at the resource behind it.
    for reachable in brokers {
        for (key, value) in &reachable.env {
            env.retain(|(k, _)| k != key);
            env.push((key.clone(), value.clone()));
        }
    }
    env.push(("HOME".to_string(), CAGE_HOME.to_string()));
    // Where the private state landed, for a plugin that asked for it. Named rather than assumed, so
    // a plugin never hardcodes the path and sbx stays free to move it.
    if plugin.grant.state {
        env.push(("SBX_PLUGIN_STATE".to_string(), CAGE_STATE.to_string()));
    }
    // The programs directory leads the cage's `PATH` when the manifest declares any, so a
    // declared tool wins over a same-named one in the host userland: the plugin runs the binary
    // sbx resolved and vetted, not whatever `/usr/bin` happens to hold.
    let path = if programs.is_empty() {
        "/usr/bin:/bin".to_string()
    } else {
        format!("{CAGE_PROGRAMS}:/usr/bin:/bin")
    };
    env.push(("PATH".to_string(), path));

    SandboxSpec::new(
        PathBuf::from(CAGE_HOME),
        mounts,
        env,
        net,
        std::iter::once(plugin.exec.as_os_str().to_os_string())
            .chain(plugin.args.iter().cloned())
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::{ResolverPlugin, SandboxGrant};
    use crate::testutil::{EnvVar, TmpDir, env_lock};
    use std::os::unix::fs::PermissionsExt;

    /// A plugin's cage carries the same mandatory syscall denylist an agent's cage does.
    ///
    /// It did not, and the asymmetry ran the wrong way. This is the cage that runs code sbx did not
    /// write, fetched from a store, and it is also the process a signer's credential is handed to;
    /// the agent's own cage, running the user's own agent, was the hardened one. A plugin had
    /// `ptrace`, `bpf`, `perf_event_open`, `userfaultfd`, the keyring calls and the whole
    /// mount-and-namespace family available to it.
    ///
    /// Read off the composed argv rather than the spec, because the filters are not in the spec's
    /// argv at all: they are descriptors prefixed at the invocation, which is exactly the step this
    /// path was skipping.
    #[test]
    fn a_plugin_cage_carries_the_mandatory_seccomp_denylist() {
        use std::os::unix::fs::PermissionsExt;

        let dir = crate::testutil::TmpDir::new();
        let exec = dir.path().join("resolve");
        std::fs::write(&exec, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        let p = plugin_in(dir.path(), SandboxGrant::default());
        let (argv, keep_open) = compose_cage(&plan_for(&p, "test://x")).expect("a cage argv");

        // Two filters, each on its own descriptor, ahead of everything else — the same shape the
        // agent's launch emits.
        let fds: Vec<usize> = argv
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--add-seccomp-fd")
            .map(|(i, _)| i)
            .collect();
        assert_eq!(fds, vec![0, 2], "{argv:?}");
        assert!(
            keep_open.len() >= 2,
            "the descriptors bwrap is told to read are held open by the caller"
        );
        // ...and the namespace hardening is still there behind them.
        for flag in [
            "--unshare-user",
            "--unshare-net",
            "--cap-drop",
            "--clearenv",
            "--unshare-pid",
            "--die-with-parent",
        ] {
            assert!(argv.iter().any(|a| a == flag), "missing {flag}: {argv:?}");
        }
    }

    /// The plan `cage_spec` takes, built from a resolver the way `run` builds it — so a test
    /// exercises the very composition a launch does.
    fn plan_for<'a>(p: &'a ResolverPlugin, reff: &str) -> CagePlan<'a> {
        CagePlan {
            kind: crate::plugins::PluginKind::Resolver,
            dir: &p.dir,
            exec: &p.exec,
            grant: &p.sandbox,
            host: &p.host,
            called: &p.scheme,
            configured_as: &p.name,
            args: vec![OsString::from(reff)],
            brokers: &[],
        }
    }

    /// The grant a plugin's *type* forbids is refused where the grant is honoured, not only where
    /// the manifest was read. Driven through `compose_cage` with a plan built by hand, which is
    /// exactly the shape a second loader — a cache, a regression — would produce: the manifest
    /// check cannot see it, so this one has to.
    #[test]
    fn a_broker_or_signer_that_asks_for_the_network_is_refused_at_the_spawn() {
        let dir = crate::testutil::TmpDir::new();
        let networked = SandboxGrant {
            network: true,
            ..Default::default()
        };
        let stateful = SandboxGrant {
            state: true,
            ..Default::default()
        };
        let plugin = plugin_in(dir.path(), networked.clone());

        for (kind, grant, needle) in [
            (crate::plugins::PluginKind::Broker, &networked, "network"),
            (crate::plugins::PluginKind::Signer, &networked, "network"),
            (crate::plugins::PluginKind::Broker, &stateful, "state"),
            (crate::plugins::PluginKind::Signer, &stateful, "state"),
        ] {
            let plan = CagePlan {
                kind,
                dir: &plugin.dir,
                exec: &plugin.exec,
                grant,
                host: &plugin.host,
                called: "probe",
                configured_as: "probe",
                args: Vec::new(),
                brokers: &[],
            };
            let err = compose_cage(&plan).expect_err("the type forbids this grant");
            assert_eq!(
                err.kind(),
                io::ErrorKind::PermissionDenied,
                "{kind:?}: {err}"
            );
            assert!(
                err.to_string().contains(needle),
                "{kind:?} must be refused for its `{needle}`: {err}"
            );
        }
    }

    /// The other half of the same rule, and the one a symmetric fix would have broken: a resolver
    /// *may* declare the network — reaching a vault over it is what most of them are for. The guard
    /// above must be keyed on the type, not applied to every plugin that passes through here.
    #[test]
    fn a_resolver_that_asks_for_the_network_still_composes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::testutil::TmpDir::new();
        let exec = dir.path().join("resolve");
        std::fs::write(&exec, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let plugin = plugin_in(
            dir.path(),
            SandboxGrant {
                network: true,
                ..Default::default()
            },
        );
        compose_cage(&plan_for(&plugin, "test://x"))
            .expect("a resolver may reach the network; the type guard must not touch it");
    }

    fn plugin_in(dir: &Path, grant: SandboxGrant) -> ResolverPlugin {
        ResolverPlugin {
            name: "test".to_string(),
            scheme: "test".to_string(),
            dir: dir.to_path_buf(),
            exec: dir.join("resolve"),
            sandbox: grant,
            version: None,
            description: None,
            host: Default::default(),
        }
    }

    /// A standing broker, as the launcher would hand one over.
    fn standing(name: &str, dest: &str, env: &[(&str, &str)]) -> super::super::broker::Reachable {
        super::super::broker::Reachable {
            host_deadline: crate::plugins::broker::DEFAULT_HOST_DEADLINE,
            name: name.to_string(),
            src: PathBuf::from(format!("/data/sbx/broker/{name}-1.sock")),
            dest: PathBuf::from(dest),
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    /// The grant a manifest makes by naming a broker: the fenced socket is bound where the
    /// protocol's clients look, and the variables that name it point there too.
    #[test]
    fn a_declared_broker_is_bound_into_the_resolvers_cage() {
        let dir = TmpDir::new();
        let grant = SandboxGrant {
            brokers: vec!["gpg-agent".to_string()],
            ..Default::default()
        };
        let p = plugin_in(dir.path(), grant);
        let reachable = standing(
            "gpg-agent",
            "/run/user/1000/gnupg/S.gpg-agent",
            &[("GPG_AGENT_SOCK", "/run/user/1000/gnupg/S.gpg-agent")],
        );
        let plan = CagePlan {
            brokers: std::slice::from_ref(&reachable),
            ..plan_for(&p, "test://x")
        };
        let spec = cage_spec(&plan, &[], &[], &[], &[], &[&reachable]).expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        assert!(
            argv.windows(3).any(|w| w[0] == "--ro-bind"
                && w[1] == *reachable.src.to_string_lossy()
                && w[2] == "/run/user/1000/gnupg/S.gpg-agent"),
            "the broker's socket must be bound where the client looks: {argv:?}"
        );
        assert!(
            spec.env()
                .iter()
                .any(|(k, v)| k == "GPG_AGENT_SOCK" && v == "/run/user/1000/gnupg/S.gpg-agent"),
            "the declared variable must name it: {:?}",
            spec.env()
        );
    }

    /// The ordering that makes this grant a *replacement*: a manifest which also binds the raw
    /// resource — the shape every such plugin has today — must not shadow the fence with it.
    #[test]
    fn the_broker_bind_lands_after_a_grant_path_naming_the_same_socket() {
        let dir = TmpDir::new();
        let socket = "/run/user/1000/gnupg/S.gpg-agent";
        let grant = SandboxGrant {
            allow_paths: vec![PathBuf::from(socket)],
            brokers: vec!["gpg-agent".to_string()],
            ..Default::default()
        };
        let p = plugin_in(dir.path(), grant);
        let reachable = standing("gpg-agent", socket, &[]);
        let plan = CagePlan {
            brokers: std::slice::from_ref(&reachable),
            ..plan_for(&p, "test://x")
        };
        let spec = cage_spec(&plan, &[], &[], &[], &[], &[&reachable]).expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        let raw = argv
            .iter()
            .position(|a| *a == *reachable.dest.to_string_lossy())
            .expect("the grant path is bound");
        let fenced = argv
            .iter()
            .position(|a| *a == *reachable.src.to_string_lossy())
            .expect("the broker socket is bound");
        assert!(
            fenced > raw,
            "bwrap applies mounts in argv order, so the fence must come last: {argv:?}"
        );
    }

    /// A grant nothing answers binds nothing. The raw resource is not a fallback: a plugin that
    /// asked for a fence and got none fails on its own terms, which is the fail-closed direction.
    #[test]
    fn a_broker_this_launch_did_not_stand_up_binds_nothing() {
        let dir = TmpDir::new();
        let grant = SandboxGrant {
            brokers: vec!["gpg-agent".to_string()],
            ..Default::default()
        };
        let p = plugin_in(dir.path(), grant);
        let plan = plan_for(&p, "test://x");
        assert!(
            resolve_brokers(&plan).is_empty(),
            "a name no `[broker.<name>]` bound resolves to nothing"
        );
        let spec = cage_spec(&plan, &[], &[], &[], &[], &[]).expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        assert!(
            !argv.iter().any(|a| a.to_string_lossy().contains("broker")),
            "nothing broker-shaped may reach the cage: {argv:?}"
        );
    }

    #[test]
    fn cage_spec_isolates_the_network_and_passes_the_ref_as_argv1() {
        let dir = TmpDir::new();
        let grant = SandboxGrant {
            state: false,
            programs: vec![],
            allow_paths: vec![PathBuf::from("/home/u/.gnupg")],
            allow_env: vec![],
            allow_env_paths: vec![],
            mask_paths: vec![],
            network: false,
            brokers: vec![],
        };
        let p = plugin_in(dir.path(), grant);
        let spec = cage_spec(
            &plan_for(&p, "test://secret"),
            &[("GNUPGHOME".into(), "/home/u/.gnupg".into())],
            &[],
            &[],
            &[],
            &[],
        )
        .expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        // The cage's variables are not in the argument list at all — a plugin's `allow_env` is how a
        // resolver is handed its own credential, so they travel on a descriptor.
        let env = super::super::argv::env_args(&spec);

        // an empty network namespace when the grant does not ask for the network
        assert!(argv.iter().any(|a| a == "--unshare-net"), "{argv:?}");
        // the command is exactly the executable plus the ref
        let dashes = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(
            &argv[dashes + 1..],
            &[
                p.exec.as_os_str().to_os_string(),
                OsString::from("test://secret"),
            ]
        );
        // the plugin directory is bound read-only, the allow_path read-only (try)
        assert!(contains_pair(&argv, "--ro-bind", &p.dir.to_string_lossy()));
        assert!(contains_pair(&argv, "--ro-bind-try", "/home/u/.gnupg"));
        // the pass-through env is present, and structural HOME/PATH are set
        assert!(contains_pair(&env, "--setenv", "GNUPGHOME"));
        assert!(contains_setenv(&env, "HOME", CAGE_HOME));
        assert!(contains_setenv(&env, "PATH", "/usr/bin:/bin"));
        // structural HOME/PATH come last, so they win over any pass-through naming them
        let gnupg = setenv_index(&env, "GNUPGHOME").unwrap();
        let home = setenv_index(&env, "HOME").unwrap();
        assert!(home > gnupg, "structural env must follow the pass-throughs");
        // and none of it is readable off `/proc/<pid>/cmdline`
        assert!(
            !argv.iter().any(|a| a == "--setenv"),
            "no variable may reach the argument list: {argv:?}"
        );
    }

    #[test]
    fn cage_spec_shares_the_network_and_binds_dns_tls_under_a_network_grant() {
        let dir = TmpDir::new();
        let grant = SandboxGrant {
            state: false,
            programs: vec![],
            allow_paths: vec![],
            allow_env: vec![],
            allow_env_paths: vec![],
            mask_paths: vec![],
            network: true,
            brokers: vec![],
        };
        let staged = plugin_in(dir.path(), grant);
        let spec = cage_spec(&plan_for(&staged, "vault://x"), &[], &[], &[], &[], &[])
            .expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        assert!(
            !argv.iter().any(|a| a == "--unshare-net"),
            "network grant shares the net"
        );
        assert!(contains_pair(&argv, "--ro-bind-try", "/etc/resolv.conf"));
        assert!(contains_pair(&argv, "--ro-bind-try", "/etc/ssl"));
    }

    #[test]
    fn cage_spec_binds_declared_programs_and_leads_the_cage_path_with_them() {
        let dir = TmpDir::new();
        let grant = SandboxGrant {
            state: false,
            programs: vec!["vault".to_string()],
            ..SandboxGrant::default()
        };
        let p = plugin_in(dir.path(), grant);
        // The runner resolved it to a store path a nix profile would have symlinked to; the cage
        // must see it under its own name, not under that one.
        let resolved = PathBuf::from("/nix/store/abc-vault-1.2.3/bin/vault");
        let spec = cage_spec(
            &plan_for(&p, "test://x"),
            &[],
            &[],
            &[("vault".to_string(), resolved.clone())],
            &[],
            &[],
        )
        .expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        let env = super::super::argv::env_args(&spec);

        assert!(
            argv.windows(3).any(|w| w[0] == "--ro-bind"
                && w[1] == resolved.as_os_str()
                && w[2] == "/run/sbx-programs/vault"),
            "the resolved binary is bound under its plain name: {argv:?}"
        );
        assert!(
            contains_setenv(&env, "PATH", "/run/sbx-programs:/usr/bin:/bin"),
            "the programs directory leads the cage PATH: {env:?}"
        );
        // The tmpfs must still precede it, as it does for the grant paths.
        let tmpfs = argv.iter().position(|a| a == "--tmpfs").expect("tmpfs");
        let bind = argv
            .iter()
            .position(|a| a == "/run/sbx-programs/vault")
            .expect("program bind");
        assert!(tmpfs < bind, "structural mounts come first: {argv:?}");
    }

    #[test]
    fn cage_spec_leaves_the_path_alone_when_no_program_is_declared() {
        let dir = TmpDir::new();
        let staged = plugin_in(dir.path(), SandboxGrant::default());
        let spec =
            cage_spec(&plan_for(&staged, "test://x"), &[], &[], &[], &[], &[]).expect("valid spec");
        let env = super::super::argv::env_args(&spec);
        assert!(contains_setenv(&env, "PATH", "/usr/bin:/bin"), "{env:?}");
        assert!(
            !super::super::argv::to_argv(&spec)
                .iter()
                .any(|a| a.to_string_lossy().contains("sbx-programs")),
            "no programs directory is created for a plugin that declares none"
        );
    }

    // --- helpers over the bwrap argv ------------------------------------------------

    fn contains_pair(argv: &[OsString], flag: &str, first: &str) -> bool {
        argv.windows(2).any(|w| w[0] == flag && w[1] == first)
    }
    fn contains_setenv(argv: &[OsString], key: &str, val: &str) -> bool {
        argv.windows(3)
            .any(|w| w[0] == "--setenv" && w[1] == key && w[2] == val)
    }
    fn setenv_index(argv: &[OsString], key: &str) -> Option<usize> {
        argv.windows(2)
            .position(|w| w[0] == "--setenv" && w[1] == key)
    }

    #[test]
    fn a_mask_covers_a_granted_path_and_comes_after_every_bind() {
        let dir = TmpDir::new();
        let grant = SandboxGrant {
            state: false,
            allow_paths: vec![PathBuf::from("/home/u/.gnupg")],
            mask_paths: vec![PathBuf::from("/home/u/.gnupg/private-keys-v1.d")],
            ..SandboxGrant::default()
        };
        let staged = plugin_in(dir.path(), grant);
        let spec =
            cage_spec(&plan_for(&staged, "test://x"), &[], &[], &[], &[], &[]).expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        let bind = argv
            .iter()
            .position(|a| a == "/home/u/.gnupg")
            .expect("the grant path is bound");
        let mask = argv
            .iter()
            .position(|a| a == "/home/u/.gnupg/private-keys-v1.d")
            .expect("the mask is applied");
        // Order is the whole mechanism: a tmpfs laid before the bind would be covered by it, so
        // the mask must come later in the argv bwrap replays in order.
        assert!(
            mask > bind,
            "the mask must follow the bind it hides part of: {argv:?}"
        );
        assert_eq!(argv[mask - 1], "--tmpfs", "a mask is an empty filesystem");
    }

    #[test]
    fn cage_spec_binds_a_nix_closure_at_its_own_paths() {
        let dir = TmpDir::new();
        // Store paths must be bound where they say they are: a nix wrapper's interpreter line and
        // its library references are absolute store paths, so anywhere else is unreachable.
        let closure = [
            (
                PathBuf::from("/nix/store/aaa-bash-5.3/bin/bash"),
                PathBuf::from("/nix/store/aaa-bash-5.3/bin/bash"),
            ),
            (
                PathBuf::from("/nix/store/bbb-pass-1.7.4"),
                PathBuf::from("/nix/store/bbb-pass-1.7.4"),
            ),
        ];
        let staged = plugin_in(dir.path(), SandboxGrant::default());
        let spec = cage_spec(&plan_for(&staged, "test://x"), &[], &[], &[], &closure, &[])
            .expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        for (_, dest) in &closure {
            let p = dest.to_string_lossy().to_string();
            assert!(
                argv.windows(3)
                    .any(|w| w[0] == "--ro-bind-try" && w[1] == p.as_str() && w[2] == p.as_str()),
                "closure path {p} bound at its own location: {argv:?}"
            );
        }
    }

    #[test]
    fn a_provisioned_closure_binds_the_physical_source_at_the_logical_destination() {
        let dir = TmpDir::new();
        // The whole reason the closure carries a pair. A program sbx provisioned has its content
        // under sbx's own store root, while its interpreter line and library references name
        // `/nix/store/…`; binding such an entry at the physical path leaves the wrapper unable to
        // start, with nothing in the failure pointing at why.
        let physical = PathBuf::from("/data/sbx/store/nix/store/aaa-bash-5.3");
        let logical = PathBuf::from("/nix/store/aaa-bash-5.3");
        let staged = plugin_in(dir.path(), SandboxGrant::default());
        let spec = cage_spec(
            &plan_for(&staged, "test://x"),
            &[],
            &[],
            &[],
            &[(physical.clone(), logical.clone())],
            &[],
        )
        .expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        assert!(
            argv.windows(3).any(|w| w[0] == "--ro-bind-try"
                && w[1] == *physical.to_string_lossy()
                && w[2] == *logical.to_string_lossy()),
            "the source must be the physical path and the destination the logical one: {argv:?}"
        );
    }

    #[test]
    fn run_binds_a_nix_programs_closure_so_a_wrapper_script_can_start() {
        let Some(bwrap) = sandbox_prereqs() else {
            skip_incapable!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        // Needs a real nix-installed program to be meaningful; skip where there is none.
        let Some(pass) = locate_program("pass") else {
            return;
        };
        if !pass.starts_with(NIX_STORE) {
            skip_incapable!("skipping nix closure run: `pass` is not a store path here");
            return;
        }
        // The case the closure exists for. A nix `pass` is a wrapper script whose shebang is a
        // store path, so binding the resolved file alone leaves it unable to start — which is why
        // the manifest used to grant the whole store. Nothing here grants /nix/store: if the
        // closure were not bound, this exec would fail.
        let (_dir, p) = fake_resolver_with(
            "pass --help >/dev/null 2>&1; echo started=$?",
            SandboxGrant {
                programs: vec!["pass".to_string()],
                ..SandboxGrant::default()
            },
        );
        let out = run(&bwrap, &p, "test://x", &[]).expect("the resolver should run");
        assert_eq!(out.trim_end(), "started=0");
    }

    #[test]
    fn a_program_outside_the_nix_store_is_never_queried_for_a_closure() {
        // The guard that keeps a host without nix from paying anything: no subprocess, and no
        // requirement that `nix-store` exist. A regression here would fail closed on every
        // non-nix host, so it is pinned rather than left to the happy path.
        let programs = [Program {
            name: "env".to_string(),
            path: PathBuf::from("/usr/bin/env"),
            origin: Origin::Host,
        }];
        assert_eq!(
            nix_closures(&programs).expect("no query, no error"),
            Vec::<(PathBuf, PathBuf)>::new()
        );
    }

    #[test]
    fn cage_spec_binds_an_env_path_at_its_own_location() {
        let dir = TmpDir::new();
        let staged = plugin_in(dir.path(), SandboxGrant::default());
        let spec = cage_spec(
            &plan_for(&staged, "test://x"),
            &[("PASSWORD_STORE_DIR".into(), "/data/secrets".into())],
            &[("PASSWORD_STORE_DIR".into(), "/data/secrets".into())],
            &[],
            &[],
            &[],
        )
        .expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        // Bound at its own path, so the value the tool reads and the path it finds are one string.
        assert!(
            argv.windows(3).any(|w| w[0] == "--ro-bind-try"
                && w[1] == "/data/secrets"
                && w[2] == "/data/secrets"),
            "the env path is bound at its own location: {argv:?}"
        );
        // The variable itself travels on the descriptor, never in the argument list — it can name
        // a private location, and an argv is readable by every user on the machine.
        let env = super::super::argv::env_args(&spec);
        assert!(
            contains_setenv(&env, "PASSWORD_STORE_DIR", "/data/secrets"),
            "and the variable naming it is passed through: {env:?}"
        );
    }

    // --- live runs through real bwrap (skipped where the host cannot sandbox) -------

    /// `bwrap` plus a capability-bearing user namespace, or `None` to skip.
    fn sandbox_prereqs() -> Option<PathBuf> {
        let bwrap = crate::pathfind::find_on_path("bwrap")?;
        matches!(crate::probe_userns(), crate::Userns::Ok).then_some(bwrap)
    }

    /// Stage an executable fake resolver `resolve` in a fresh plugin directory.
    fn fake_resolver(body: &str) -> (TmpDir, ResolverPlugin) {
        fake_resolver_with(body, SandboxGrant::default())
    }

    /// The same, under a chosen grant.
    fn fake_resolver_with(body: &str, grant: SandboxGrant) -> (TmpDir, ResolverPlugin) {
        let dir = TmpDir::new();
        let exec = dir.join("resolve");
        std::fs::write(&exec, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
        let p = plugin_in(dir.path(), grant);
        (dir, p)
    }

    /// The cage binds the host userland and computes a nix closure; it holds nothing else. So a
    /// binary from either place brings its libraries, and one from a package manager's own prefix
    /// does not — which is the difference between a program that runs in the resolver sandbox and
    /// one that dies in the loader with a message naming neither the library nor the cause.
    #[test]
    fn only_a_binary_the_cage_holds_the_libraries_for_counts_as_loadable() {
        for path in [
            "/usr/bin/curl",
            "/bin/sh",
            "/sbin/ip",
            "/nix/store/abc-curl-8.0/bin/curl",
        ] {
            assert!(
                cage_can_load(Path::new(path)),
                "{path} is inside what the cage binds"
            );
        }
        for path in [
            "/home/linuxbrew/.linuxbrew/Cellar/curl/8.21.0/bin/curl",
            "/opt/homebrew/bin/curl",
            "/home/u/.local/bin/curl",
        ] {
            assert!(
                !cage_can_load(Path::new(path)),
                "{path} brings libraries the cage does not bind"
            );
        }
    }

    /// A plugin installed the way the installer places one — `<data>/plugins/<name>` — so
    /// [`state_dir`] resolves to a sibling `<data>/plugin-state/<name>` inside the temp tree.
    fn installed_resolver(body: &str, grant: SandboxGrant) -> (TmpDir, ResolverPlugin) {
        let root = TmpDir::new();
        let dir = root.join("plugins").join("stateful");
        std::fs::create_dir_all(&dir).unwrap();
        let exec = dir.join("resolve");
        std::fs::write(&exec, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut p = plugin_in(&dir, grant);
        p.exec = exec;
        (root, p)
    }

    /// The one writable path in the cage exists only when the manifest asked for it, and the plugin
    /// is told where it landed rather than having to know the path.
    #[test]
    fn cage_spec_binds_a_writable_state_dir_only_under_the_grant() {
        for state in [false, true] {
            let (_root, p) = installed_resolver(
                "true",
                SandboxGrant {
                    state,
                    ..SandboxGrant::default()
                },
            );
            let spec = cage_spec(&plan_for(&p, "test://x"), &[], &[], &[], &[], &[]).unwrap();
            let env = super::super::argv::env_args(&spec);
            let argv: Vec<String> = super::super::argv::to_argv(&spec)
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            // A writable bind is `--bind`; every other path this cage gets is `--ro-bind`.
            let writable = argv
                .windows(2)
                .any(|w| w[0] == "--bind" && w[1].ends_with("plugin-state/stateful"));
            assert_eq!(
                writable, state,
                "a writable state bind must appear exactly when the grant asked (state={state})"
            );
            assert_eq!(
                contains_setenv(&env, "SBX_PLUGIN_STATE", CAGE_STATE),
                state,
                "the location is named to the plugin only under the grant (state={state})"
            );
        }
    }

    /// What the grant is for: a resolver that receives a single-use, rotating credential must be
    /// able to keep what it just received, or the next run has nothing to exchange. The counter
    /// stands in for that token — it survives the cage, which the `HOME` tmpfs would not.
    #[test]
    fn run_keeps_state_across_invocations_under_the_grant() {
        let Some(bwrap) = sandbox_prereqs() else {
            skip_incapable!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        let (_root, p) = installed_resolver(
            r#"n=$(cat "$SBX_PLUGIN_STATE/n" 2>/dev/null || echo 0)
n=$((n+1))
echo "$n" > "$SBX_PLUGIN_STATE/n"
printf 'run-%s' "$n""#,
            SandboxGrant {
                state: true,
                ..SandboxGrant::default()
            },
        );
        assert_eq!(run(&bwrap, &p, "test://x", &[]).unwrap(), "run-1");
        assert_eq!(
            run(&bwrap, &p, "test://x", &[]).unwrap(),
            "run-2",
            "the second run must see what the first wrote"
        );
    }

    /// Without the grant there is no writable path at all: `HOME` is a tmpfs that dies with the
    /// run, so a plugin that tries to keep something starts over every time.
    #[test]
    fn run_keeps_nothing_across_invocations_without_the_grant() {
        let Some(bwrap) = sandbox_prereqs() else {
            skip_incapable!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        let (_root, p) = installed_resolver(
            r#"n=$(cat "$HOME/n" 2>/dev/null || echo 0)
n=$((n+1))
echo "$n" > "$HOME/n"
printf 'run-%s' "$n""#,
            SandboxGrant::default(),
        );
        assert_eq!(run(&bwrap, &p, "test://x", &[]).unwrap(), "run-1");
        assert_eq!(
            run(&bwrap, &p, "test://x", &[]).unwrap(),
            "run-1",
            "an ungranted plugin starts from nothing on every run"
        );
    }

    #[test]
    fn run_binds_a_declared_program_so_the_plugin_calls_it_by_name() {
        let Some(bwrap) = sandbox_prereqs() else {
            skip_incapable!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        // `env` exists on every host this runs on, so what the test pins is not its presence but
        // where the cage resolves it: the bound copy, not the one in the host userland. That is
        // the whole point of the mechanism — a plugin never has to know where a tool was installed.
        let (_dir, p) = fake_resolver_with(
            "command -v env",
            SandboxGrant {
                programs: vec!["env".to_string()],
                ..SandboxGrant::default()
            },
        );
        let out = run(&bwrap, &p, "test://x", &[]).expect("the resolver should run");
        assert_eq!(out.trim_end(), "/run/sbx-programs/env");
    }

    #[test]
    fn run_binds_the_path_an_allow_env_paths_variable_names() {
        let Some(bwrap) = sandbox_prereqs() else {
            skip_incapable!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        // The case the field exists for: a user whose store is not where the manifest guessed.
        // The manifest cannot name this directory — it did not exist when the plugin was signed —
        // so the only thing that can reach it is the variable the user set.
        const VAR: &str = "SBX_TEST_RESOLVER_ABS_STORE";
        let _lock = env_lock();
        let store = TmpDir::new();
        std::fs::write(store.join("entry"), "the-fixture-wrote-this").unwrap();
        let (_dir, p) = fake_resolver_with(
            &format!("cat \"${VAR}/entry\""),
            SandboxGrant {
                allow_env_paths: vec![VAR.to_string()],
                ..SandboxGrant::default()
            },
        );
        let _var = EnvVar::set(VAR, store.path());
        let out = run(&bwrap, &p, "test://x", &[]);
        // A hard-coded literal, so the assertion cannot be met by the test recomputing whatever
        // the code produced. Dropping the bind in `cage_spec` makes `cat` fail instead.
        assert_eq!(
            out.expect("the resolver should run"),
            "the-fixture-wrote-this"
        );
    }

    #[test]
    fn run_drops_a_relative_allow_env_paths_value_rather_than_binding_it() {
        let Some(bwrap) = sandbox_prereqs() else {
            skip_incapable!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        // A relative value cannot mean what it says inside a cage sharing no working directory, so
        // it is dropped rather than bound — and the variable goes with it, because passing it while
        // binding nothing would aim the tool at a path the cage does not have, which is the exact
        // failure this field exists to remove.
        const VAR: &str = "SBX_TEST_RESOLVER_REL_STORE";
        let _lock = env_lock();
        let (_dir, p) = fake_resolver_with(
            &format!("echo \"[${{{VAR}-unset}}]\""),
            SandboxGrant {
                allow_env_paths: vec![VAR.to_string()],
                ..SandboxGrant::default()
            },
        );
        let _var = EnvVar::set(VAR, "relative/store");
        let out = run(&bwrap, &p, "test://x", &[]);
        assert_eq!(out.expect("the resolver should run").trim_end(), "[unset]");
    }

    #[test]
    fn run_fails_closed_when_a_declared_program_is_not_on_the_path() {
        let Some(bwrap) = sandbox_prereqs() else {
            skip_incapable!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        let (_dir, p) = fake_resolver_with(
            "printf x",
            SandboxGrant {
                programs: vec!["sbx-no-such-program".to_string()],
                ..SandboxGrant::default()
            },
        );
        let err = run(&bwrap, &p, "test://x", &[]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        let msg = err.to_string();
        // The terminal state is now BOTH answers exhausted, not just the `PATH` one: a program can
        // also come from `[plugin.<name>] programs`, provisioned at install. Asserting only the
        // `PATH` half would keep this green while saying nothing about the branch it is named for,
        // since the fixture has no config entry either way.
        assert!(
            msg.contains("sbx-no-such-program"),
            "the refusal names the program: {msg}"
        );
        assert!(
            msg.contains("PATH"),
            "the refusal names the first place a program is looked for: {msg}"
        );
        assert!(
            msg.contains("has not been provisioned") && msg.contains("programs"),
            "the refusal names the second answer, and the config field that supplies it: {msg}"
        );
        assert!(
            msg.contains("sbx plugins install"),
            "the refusal names the command that turns a configured program into a built one: {msg}"
        );
    }

    #[test]
    fn run_returns_the_plugins_stdout_for_the_passed_ref() {
        let Some(bwrap) = sandbox_prereqs() else {
            skip_incapable!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        let (_dir, p) = fake_resolver("printf 'resolved:%s' \"$1\"");
        let out = run(&bwrap, &p, "test://hello", &[]).expect("the resolver should run");
        assert_eq!(out, "resolved:test://hello");
    }

    // --- the deadline ---

    /// The base bound applies when the cage reaches nothing, and a reachable broker's own wait is
    /// added to it rather than compared against it.
    ///
    /// A resolver holding a broker socket is entitled to wait as long as that broker's manifest
    /// declares — a gpg-agent stopping at a pinentry answers when the person does — so a bound
    /// that ignored the brokers would kill a plugin behaving exactly as the manifest permits.
    #[test]
    fn a_reachable_brokers_own_wait_is_added_to_the_resolution_deadline() {
        assert_eq!(deadline_for(&[]), HOST_RESOLUTION_DEADLINE);

        let mut quick = standing("quick", "/run/quick.sock", &[]);
        quick.host_deadline = std::time::Duration::from_secs(5);
        let mut human = standing("gpg-agent", "/run/gpg.sock", &[]);
        human.host_deadline = std::time::Duration::from_secs(300);

        // The longest of them, and only once: the waits nest, they do not queue.
        assert_eq!(
            deadline_for(&[quick, human]),
            HOST_RESOLUTION_DEADLINE + std::time::Duration::from_secs(300)
        );
    }

    /// A deadline the kernel refuses to arm stops the process instead of running it unbounded.
    ///
    /// The elapsed bound is the assertion that matters: the message could be produced while
    /// leaving the process running, which is the outcome this branch exists to prevent. Thirty
    /// seconds of `sleep` is what a leaked process would cost.
    #[test]
    fn a_deadline_that_cannot_be_armed_stops_the_process_instead_of_running_it_unbounded() {
        let started = std::time::Instant::now();
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("sleep 30");
        let err = output_within_armed_by(
            &mut cmd,
            std::time::Duration::from_secs(30),
            "the probe",
            |_| Err(libc::EMFILE),
        )
        .expect_err("an unbounded run must not happen");
        assert!(
            err.to_string().contains("the deadline could not be armed"),
            "{err}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the process was left running: {:?}",
            started.elapsed()
        );
    }

    /// The call returns on time even though the pipe it was reading stays open.
    ///
    /// This is the property killing the process does *not* give: `sh` forks `sleep`, `sleep`
    /// inherits the descriptor, and killing the shell leaves the write end held for another thirty
    /// seconds. So the wait is what is bounded — the readers are abandoned where they stand — and
    /// the elapsed time is the only thing that says so. Measured before it was written: reading to
    /// EOF after the kill took the full thirty seconds.
    #[test]
    fn a_command_whose_pipe_outlives_it_does_not_hold_the_call() {
        let started = std::time::Instant::now();
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("sleep 30");
        let err = output_within(&mut cmd, std::time::Duration::from_millis(300), "the probe")
            .expect_err("a command past its deadline must not resolve");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
        assert!(err.to_string().contains("the probe"), "{err}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the call waited on a pipe nothing was going to close: {:?}",
            started.elapsed()
        );
    }

    /// A command that outlives its deadline is killed, not merely left behind.
    ///
    /// Separate from the bound on the wait, because the two are independent: the call returns by
    /// abandoning its readers, which it would do even if nothing were signalled. The marker is
    /// what measures the kill — the command ignores SIGTERM and would write it a second later, so
    /// a signal that can be caught, or no signal at all, leaves the file behind.
    #[test]
    fn a_command_that_outlives_its_deadline_is_killed_rather_than_left_running() {
        let dir = TmpDir::new();
        let marker = dir.join("survived");
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("trap '' TERM; sleep 2; : > '{}'", marker.display()));
        output_within(&mut cmd, std::time::Duration::from_millis(300), "the probe")
            .expect_err("a command past its deadline must not resolve");

        // Past the moment the command would have reached its own write, had it lived.
        std::thread::sleep(std::time::Duration::from_secs(3));
        assert!(
            !marker.exists(),
            "the command outlived its deadline instead of being killed"
        );
    }

    /// An answer past the ceiling is refused, and refused rather than truncated: what the command
    /// wrote is the secret, and half a secret is not a smaller secret.
    ///
    /// The elapsed bound is part of the assertion. Stopping the read without closing the pipe
    /// would leave the command blocked on a buffer nobody drains, and the refusal would arrive as
    /// a timeout ten minutes later instead; here the deadline is thirty seconds, so a refusal that
    /// came from the clock rather than from the ceiling would take thirty.
    #[test]
    fn an_answer_past_the_ceiling_is_refused_rather_than_truncated() {
        let started = std::time::Instant::now();
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(format!(
            "dd if=/dev/zero bs=1024 count={} 2>/dev/null",
            MAX_RESOLUTION_BYTES / 1024 + 64
        ));
        let err = output_within(&mut cmd, std::time::Duration::from_secs(30), "the probe")
            .expect_err("an answer past the ceiling must not resolve");
        assert!(
            err.to_string()
                .contains(&format!("more than {MAX_RESOLUTION_BYTES} bytes")),
            "{err}"
        );
        assert_ne!(
            err.kind(),
            io::ErrorKind::TimedOut,
            "refused by the clock: {err}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the writer blocked on a pipe that was never closed: {:?}",
            started.elapsed()
        );
    }

    /// The negative control for the ceiling: an answer sitting exactly on it still reads, whole.
    #[test]
    fn an_answer_at_the_top_of_the_ceiling_still_reads() {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(format!(
            "dd if=/dev/zero bs=1024 count={} 2>/dev/null",
            MAX_RESOLUTION_BYTES / 1024
        ));
        let out = output_within(&mut cmd, std::time::Duration::from_secs(30), "the probe")
            .expect("an answer at the ceiling resolves");
        assert_eq!(out.stdout.len(), MAX_RESOLUTION_BYTES);
    }

    /// A chatty *stderr* is a diagnostic, not an answer: it stops at the ceiling and the run still
    /// resolves. It is already cut to one bounded line before anything reads it, so the only thing
    /// at stake here is how much sbx holds while doing that.
    #[test]
    fn a_flood_of_diagnostics_is_capped_without_failing_the_run() {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(format!(
            "printf resolved; dd if=/dev/zero bs=1024 count={} >&2 2>/dev/null",
            MAX_RESOLUTION_BYTES / 1024 + 64
        ));
        let out = output_within(&mut cmd, std::time::Duration::from_secs(30), "the probe")
            .expect("a chatty run still resolves");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "resolved");
        assert!(
            out.stderr.len() <= MAX_RESOLUTION_BYTES + 1,
            "{}",
            out.stderr.len()
        );
    }

    /// The negative control: a command that answers keeps its output, and neither pipe is lost.
    ///
    /// It also pins the stdio the helper sets. `spawn` inherits all three descriptors where
    /// `output` captures two and closes one, so a helper built on the first has to say so — a
    /// resolver's stdout is the secret, and inheriting it would print the value instead of
    /// returning it.
    #[test]
    fn a_command_that_answers_within_its_deadline_keeps_its_output() {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("printf out; printf err >&2");
        let out = output_within(&mut cmd, std::time::Duration::from_secs(30), "the probe")
            .expect("a command inside its deadline resolves");
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout), "out");
        assert_eq!(String::from_utf8_lossy(&out.stderr), "err");
    }

    /// A resolver plugin that never answers is killed, and the cage goes down with it.
    ///
    /// The plugin writes into the one path that survives its own run — the state directory — a
    /// second after the deadline, and ignores SIGTERM on the way. So the marker is a fact about
    /// the whole cage: it appears if the plugin was not signalled, if it was signalled with
    /// something it could catch, or if killing the process sbx spawned left the pid namespace
    /// standing. sbx sees only its own child; this is how the rest of the cage is measured.
    #[test]
    fn a_resolver_that_never_answers_is_killed_and_the_cage_with_it() {
        let Some(bwrap) = sandbox_prereqs() else {
            skip_incapable!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        let (root, p) = installed_resolver(
            "trap '' TERM\nsleep 2\n: > \"$SBX_PLUGIN_STATE/survived\"",
            SandboxGrant {
                state: true,
                ..SandboxGrant::default()
            },
        );
        let marker = root.join("plugin-state").join("stateful").join("survived");
        let started = std::time::Instant::now();
        let err = run_within(
            &bwrap,
            &p,
            "test://x",
            &[],
            std::time::Duration::from_millis(500),
        )
        .expect_err("a plugin past its deadline must not resolve");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
        assert!(err.to_string().contains("test"), "{err}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the call waited the plugin out rather than returning: {:?}",
            started.elapsed()
        );

        // Past the moment the plugin would have reached its own write, had the cage lived.
        std::thread::sleep(std::time::Duration::from_secs(3));
        assert!(
            !marker.exists(),
            "the plugin outlived its deadline inside a cage that was not torn down"
        );
    }

    #[test]
    fn run_fails_closed_on_a_nonzero_exit_folding_stderr_not_stdout() {
        let Some(bwrap) = sandbox_prereqs() else {
            skip_incapable!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        // prints a plaintext to stdout but exits non-zero — the error must fold stderr, never stdout
        let (_dir, p) = fake_resolver("printf 'the-secret' ; echo 'boom: no key' >&2 ; exit 7");
        let err = run(&bwrap, &p, "test://x", &[]).unwrap_err().to_string();
        assert!(
            err.contains("test") && err.contains("boom: no key"),
            "{err}"
        );
        assert!(
            !err.contains("the-secret"),
            "stdout must never leak into the error: {err}"
        );
    }

    #[test]
    fn run_returns_empty_for_a_clean_absent_so_the_caller_can_fall_through() {
        let Some(bwrap) = sandbox_prereqs() else {
            skip_incapable!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        // exit 0, nothing on stdout — the contract's "absent"; the caller's classify_value turns
        // this empty string into a fall-through to the next source.
        let (_dir, p) = fake_resolver("exit 0");
        assert_eq!(
            run(&bwrap, &p, "test://x", &[]).expect("absent is exit 0"),
            ""
        );
    }

    // --- what a plugin is allowed to say -------------------------------------------

    #[test]
    fn a_run_that_resolved_a_value_never_repeats_its_stderr() {
        // The load-bearing half: a plugin that logged the secret to stderr must not have it echoed
        // back at the user just because it was chatty. The trailing newline case matters too — the
        // caller strips one before classifying, so "resolved" must be read the same way here.
        assert_eq!(
            absent_detail("the-secret", b"debug: opened the vault"),
            None
        );
        assert_eq!(absent_detail("the-secret\n", b"debug: the-secret"), None);
    }

    #[test]
    fn a_run_that_resolved_nothing_relays_the_plugins_account() {
        assert_eq!(
            absent_detail("", b"entry 'agents/githb' is not in the vault\n"),
            Some("entry 'agents/githb' is not in the vault".to_string())
        );
        // A bare line ending is the same "absent" the caller sees, so the plugin still gets a voice.
        assert_eq!(
            absent_detail("\n", b"the `password` field is empty"),
            Some("the `password` field is empty".to_string())
        );
    }

    #[test]
    fn an_absent_run_from_a_silent_plugin_says_nothing() {
        // Nothing to relay must stay nothing — never an empty `resolved nothing:` line.
        assert_eq!(absent_detail("", b""), None);
        assert_eq!(absent_detail("", b"  \n \t "), None);
    }

    #[test]
    fn a_relayed_diagnostic_is_one_bounded_line() {
        // A plugin's text reaches a terminal: no escape may survive to drive it, and no newline may
        // forge a second diagnostic line.
        let out = one_line_detail(b"\x1b[31mred\x1b[0m\nsecond line");
        assert!(!out.contains('\u{1b}'), "{out}");
        assert!(!out.contains('\n'), "{out}");
        assert_eq!(out, "[31mred [0m second line");

        let long = one_line_detail(&b"a".repeat(DETAIL_MAX * 2));
        assert_eq!(long.chars().count(), DETAIL_MAX);
        assert!(long.ends_with('…'), "{long}");
    }

    #[test]
    fn run_returns_the_value_of_a_chatty_plugin_untouched() {
        let Some(bwrap) = sandbox_prereqs() else {
            skip_incapable!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        // A plugin that logs while it resolves. The value comes back verbatim, and the run is not
        // an absent — so the runner stays silent about that stderr rather than repeating a line in
        // which a careless plugin put the plaintext.
        let (_dir, p) = fake_resolver("printf 'the-secret' ; echo 'debug: the-secret' >&2");
        assert_eq!(
            run(&bwrap, &p, "test://x", &[]).expect("the resolver should run"),
            "the-secret"
        );
    }

    #[test]
    fn run_sanitizes_the_stderr_it_folds_into_an_error() {
        let Some(bwrap) = sandbox_prereqs() else {
            skip_incapable!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        let (_dir, p) = fake_resolver("printf 'boom\\033[2J\\nsbx: fake line' >&2 ; exit 3");
        let err = run(&bwrap, &p, "test://x", &[]).unwrap_err().to_string();
        assert!(err.contains("boom"), "{err}");
        assert!(
            !err.contains('\u{1b}'),
            "no escape reaches the terminal: {err}"
        );
        assert!(!err.contains('\n'), "no forged second line: {err}");
    }

    #[test]
    fn run_refuses_a_group_writable_executable() {
        let Some(bwrap) = sandbox_prereqs() else {
            skip_incapable!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        let (_dir, p) = fake_resolver("printf x");
        std::fs::set_permissions(&p.exec, std::fs::Permissions::from_mode(0o775)).unwrap();
        let err = run(&bwrap, &p, "test://x", &[]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("group or other"), "{err}");
    }
}
