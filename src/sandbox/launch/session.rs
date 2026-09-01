//! The two verbs that address a cage somebody else built: `sbx session attach` and
//! `sbx session stop`, with the confirmation renderers they share with the foreground GUI hint.
//!
//! Nothing here is part of a launch. Neither verb resolves a configuration, provisions a package or
//! builds a spec: `attach` enters namespaces bubblewrap already made and `stop` signals a pid the
//! registry vouched for, so the whole file shares no state with the pipeline in [`super`] — the
//! same criterion that keeps [`crate::sandbox::projects`] out of it. The mechanism `attach` drives
//! lives in [`mod@crate::sandbox::attach`]; what is decided here is which session is meant, how it
//! is entered, and what the operator is told afterwards.

use super::cage::cstring;
use super::*;

/// Render the line `sbx session attach` prints before entering a live cage (stderr). Attaching is an
/// announcement, not a completed change, so the verb stays plain; the session pid and label are the
/// identifier (cyan) and the parenthetical is secondary detail (dim).
fn render_attaching(pid: u32, label: &str, pal: &crate::style::Palette) -> String {
    let (n, r) = (pal.name, pal.reset);
    format!(
        "sbx: attaching to session {n}{pid}{r} ({n}{label}{r}) {}",
        crate::style::dim_prose(
            "(a shell in its live cage — type `exit` to leave the agent running)",
            pal
        )
    )
}

/// The name a launch shows in the graphical-app stop hint: the app name for an `sbx app`, else the
/// program's own basename for a plain `sbx run` into a GUI project. Falls back to a generic word if
/// the command is somehow empty, so the hint is always well-formed.
pub(super) fn launch_display_name(runtime: &binds::Runtime, cmd: &[OsString]) -> String {
    match runtime {
        binds::Runtime::GlobalApp(name) | binds::Runtime::ProjectApp(name) => (*name).to_string(),
        binds::Runtime::ProjectDefault => cmd
            .first()
            .map(|c| {
                Path::new(c)
                    .file_name()
                    .unwrap_or(c.as_os_str())
                    .to_string_lossy()
                    .into_owned()
            })
            .unwrap_or_else(|| "the app".to_string()),
    }
}

/// The line a foreground graphical launch prints (stderr) so the user knows how to stop it: its UI
/// is the window, and a single Ctrl+C — though forwarded — is ignored by a GUI app (and a tray-backed
/// window may not quit on close), so the escape hatches are named: a double Ctrl+C force-quits the
/// session, and `sbx session stop <pid>` works from any other terminal. The app name is the identifier
/// (cyan); the rest is plain, matching the restraint of the attach announcements.
pub(super) fn render_gui_stop_hint(name: &str, pid: u32, pal: &crate::style::Palette) -> String {
    let (n, r) = (pal.name, pal.reset);
    format!(
        "sbx: {n}{name}{r} {}",
        crate::style::prose(
            &format!(
                "is graphical — press Ctrl+C twice here to quit (closing its window may only \
                 hide it — a tray app keeps running); `sbx session stop {pid}` also stops it."
            ),
            pal
        )
    )
}

/// `sbx session attach <id> [-- command [args...]]`: join a *running* session's cage and either
/// open an interactive shell **inside** it or run one command there — the agent's live processes,
/// its real `/tmp`, its network — the way `docker exec` / `docker exec -it` works. `<id>` is the
/// PID `sbx session ls` shows. With no command it opens the interactive rc shell (needs a terminal);
/// with `-- command` it runs that command, driven through a pty when stdin is a terminal (so an
/// interactive tool keeps job control) or through inherited stdio when it is a pipe/script (so bytes
/// pass through clean for scripting). Unlike a launch, this enters namespaces bubblewrap already
/// built (via `setns`), so it provisions nothing and re-resolves no config; it re-applies the cage's
/// confinement (seccomp denylist + `no_new_privs` + capability drop) so the joined process is
/// confined at least as tightly as the agent. See [`mod@crate::sandbox::attach`] for the mechanism and its
/// one inherent residual (the command binary comes from the agent's own mount namespace).
pub(crate) fn attach(id: &str, cmd: Vec<OsString>) -> ExitCode {
    let Some(layout) = Layout::from_env() else {
        eprintln!(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)."
        );
        return ExitCode::FAILURE;
    };
    let sessions = match crate::session::Registry::at(layout.data_dir()).list() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sbx session attach: cannot read the session registry: {e}");
            return ExitCode::FAILURE;
        }
    };
    // A pid is unique among live processes, so this is a 0-or-1 match. Resolve the target before
    // the terminal check, so an unknown id is reported even without a tty.
    let Some(target) = sessions.into_iter().find(|s| s.pid.to_string() == id) else {
        crate::diag::error(&format!(
            "sbx session attach: no live session '{id}' — run `sbx session ls` to list them."
        ));
        return ExitCode::from(2);
    };
    // SAFETY: `isatty` only inspects fd 0. A bare attach opens an interactive shell, which needs a
    // real terminal (like `shell`); a command drives its terminal setup from this — a pty when it
    // has one, inherited stdio otherwise — so it imposes no terminal requirement.
    let stdin_tty = unsafe { libc::isatty(0) } == 1;
    if cmd.is_empty() && !stdin_tty {
        crate::diag::error(
            "sbx: `sbx session attach` needs a terminal on stdin (or pass `-- command`).",
        );
        return ExitCode::from(2);
    }

    // Locate a live process inside the cage (the session pid is the cage's host-side anchor). The
    // record's project is what identifies *this session's* cage among the supervisor's other
    // sandboxed children — the broker and signer plugin fences — since only the payload cage mounts
    // it. A `None` here means the cage has no in-namespace process left — it exited between
    // `sbx session ls` and now, or the host has no user namespaces (then it never had a cage).
    let Some(cage_pid) = crate::sandbox::attach::find_cage_pid(target.pid, &target.project) else {
        crate::diag::error(&format!(
            "sbx session attach: session '{id}' has no live process to enter — it may have just exited \
             (run `sbx session ls`)."
        ));
        return ExitCode::FAILURE;
    };
    let cage = match crate::sandbox::attach::open_cage_handle(cage_pid, &target.project) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("sbx session attach: cannot open a handle to session '{id}''s cage: {e}");
            return ExitCode::FAILURE;
        }
    };
    let environ = crate::sandbox::attach::read_environ(cage_pid);

    // The in-cage argv: the interactive rc shell for a bare attach, or the command run through
    // `bash -c 'exec "$@"'` so bash resolves it on the cage PATH and execs it in place.
    let argv_owned = match attach_argv(&cmd) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("sbx session attach: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Only the interactive shell announces itself ("type `exit` to leave"); a command is silent
    // like `sbx run`, so its stdout/stderr are exactly the command's.
    if cmd.is_empty() {
        let epal = crate::style::Palette::for_stream(io::stderr().is_terminal());
        eprintln!("{}", render_attaching(target.pid, &target.label(), &epal));
    }

    // A terminal on stdin drives the command through a pty (interactive, job control); a pipe or
    // script through inherited stdio (clean bytes). A bare shell always takes the pty path — it is
    // gated to a terminal above, so `stdin_tty` holds here.
    let result = if stdin_tty {
        supervise_attach(cage, &environ, &argv_owned)
    } else {
        run_attach_direct(cage, &environ, &argv_owned)
    };
    match result {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("sbx: attach session failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Build the in-cage argv for an attach. With no command this is the interactive shell reading the
/// in-cage rc (mise activation + the `(sbx-<slug>)` prompt), exactly like an interactive `sbx run`. With a
/// command it is `bash -c 'exec "$@"' bash <cmd> [args…]`: bash resolves `<cmd>` on the cage PATH
/// (from the cage environment passed as its `envp`) and execs it **in place**, so the command's
/// exit status propagates; the command is passed **positionally** (`"$@"`), so no argument is ever
/// interpreted as shell syntax — zero injection surface. `/bin/bash` and the rc are absolute cage
/// paths that resolve in the cage's own mount namespace once the child has entered it.
fn attach_argv(cmd: &[OsString]) -> io::Result<Vec<CString>> {
    if cmd.is_empty() {
        return Ok(vec![
            cstring(binds::SANDBOX_BASH.as_bytes())?,
            cstring(b"--rcfile")?,
            cstring(binds::SHELL_RC_INCAGE.as_bytes())?,
        ]);
    }
    let mut argv = vec![
        cstring(binds::SANDBOX_BASH.as_bytes())?,
        cstring(b"-c")?,
        cstring(b"exec \"$@\"")?,
        cstring(b"bash")?,
    ];
    for arg in cmd {
        argv.push(cstring(arg.as_bytes())?);
    }
    Ok(argv)
}

/// Supervise a real attach: open a pty, fork a child that joins the cage's namespaces and execs the
/// confined `argv_owned` inside it, and relay the terminal — the same pty machinery as
/// [`supervise`], but the child enters an *existing* cage rather than launching a new one, so there
/// is no bwrap argv, no cgroup scope, and no session record (the attach guest is a transient guest
/// of the agent's cage, not a session of its own). Used for a bare interactive shell and for a
/// command run from a terminal (so an interactive tool keeps job control).
fn supervise_attach(
    cage: crate::sandbox::attach::CageHandle,
    environ: &[u8],
    argv_owned: &[CString],
) -> io::Result<i32> {
    // The baseline mandatory denylist — never a project's `[seccomp] allow` relaxation — so the
    // joined process is confined at least as tightly as the agent. Compiled before the fork.
    let filters =
        crate::sandbox::seccomp::filter_bytes(&crate::sandbox::seccomp::SeccompPolicy::default());

    // argv: prebuilt by `attach_argv` (the interactive rc shell, or `bash -c 'exec "$@"' …`),
    // resolving in the cage's own mount namespace once the child has entered it.
    let mut argv: Vec<*const libc::c_char> = argv_owned.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());

    // envp: the agent's own cage environment (its PATH, proxy, and CA settings), with TERM set to
    // the attaching terminal's so rendering and resize match.
    let term = std::env::var("TERM").ok();
    let envp_owned = crate::sandbox::attach::build_env(environ, term.as_deref());
    let mut envp: Vec<*const libc::c_char> = envp_owned.iter().map(|c| c.as_ptr()).collect();
    envp.push(std::ptr::null());

    // The child of the fork below: it calls only async-signal-safe code — `attach::enter_and_exec`
    // uses raw syscalls only — on the argv/envp/filters/pidfd prepared above, and never returns.
    // The capture is by value, so the parent's copy of the cage handle (and its pidfd) is released
    // as soon as the fork returns rather than held for the session; the child has its own.
    let in_child = move |slave: libc::c_int| -> std::convert::Infallible {
        unsafe {
            crate::sandbox::attach::enter_and_exec(
                &cage,
                &filters,
                crate::sandbox::attach::TtyMode::Pty(slave),
                argv.as_ptr(),
                envp.as_ptr(),
            )
        }
    };
    // SAFETY: the closure honours the async-signal-safe contract above, and the parent is
    // single-threaded here (attach starts no egress proxy thread). No GUI double-Ctrl+C on this
    // path, so the relay runs with `gui` false.
    unsafe { fork_with_pty(false, in_child) }
}

/// Run an attach command with **inherited** stdio (no pty): fork a child that joins the cage's
/// namespaces and execs the confined `argv_owned` inside it, keeping sbx's own stdin/stdout/stderr,
/// then wait and mirror its exit status. This is the pipe/script path — bytes pass through clean
/// (no pty `\n`→`\r\n` translation), so `sbx session attach <id> -- cmd` composes with pipes and
/// redirection. Only reached when stdin is not a terminal (a command from a terminal takes the pty
/// path in [`supervise_attach`] for interactive job control).
fn run_attach_direct(
    cage: crate::sandbox::attach::CageHandle,
    environ: &[u8],
    argv_owned: &[CString],
) -> io::Result<i32> {
    // The same baseline denylist the pty path installs — the command is confined at least as
    // tightly as the agent, never a project's `[seccomp] allow` relaxation. Compiled before the fork.
    let filters =
        crate::sandbox::seccomp::filter_bytes(&crate::sandbox::seccomp::SeccompPolicy::default());

    let mut argv: Vec<*const libc::c_char> = argv_owned.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());

    // envp: the agent's own cage environment (PATH/proxy/CA), TERM carried through from sbx.
    let term = std::env::var("TERM").ok();
    let envp_owned = crate::sandbox::attach::build_env(environ, term.as_deref());
    let mut envp: Vec<*const libc::c_char> = envp_owned.iter().map(|c| c.as_ptr()).collect();
    envp.push(std::ptr::null());

    // SAFETY: between fork and exec the child touches only async-signal-safe code
    // (`attach::enter_and_exec` — raw syscalls only) with the prebuilt argv/envp/filters/pidfd. The
    // parent is single-threaded here (attach starts no egress proxy thread). The child inherits
    // sbx's stdin/stdout/stderr (`TtyMode::Inherit`), so the command's I/O passes through clean.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }
    if child == 0 {
        unsafe {
            crate::sandbox::attach::enter_and_exec(
                &cage,
                &filters,
                crate::sandbox::attach::TtyMode::Inherit,
                argv.as_ptr(),
                envp.as_ptr(),
            );
        }
    }

    // Parent: the child holds its own copy of the cage handle across the fork, so drop ours.
    drop(cage);
    // Reap the child (the `enter_and_exec` intermediary), which has already normalized its
    // grandchild's exit into a plain status (`128 + signo` for a signal death, `126`/`127` on a
    // setup failure), so `WEXITSTATUS` alone carries the command's exit code.
    let mut status: libc::c_int = 0;
    loop {
        if unsafe { libc::waitpid(child, &mut status, 0) } >= 0 {
            break;
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINTR) {
            return Err(e);
        }
    }
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Ok(128 + libc::WTERMSIG(status))
    } else {
        Ok(126)
    }
}

/// Render the `sbx session stop --all` line for an empty registry (stdout): nothing to stop is a no-op
/// success, so the message is secondary detail (dim).
fn render_no_active_sessions(pal: &crate::style::Palette) -> String {
    let (dim, r) = (pal.dim, pal.reset);
    format!("sbx session stop: {dim}no active sessions to stop.{r}")
}

/// `sbx session stop <id>...` / `sbx session stop --all`: stop running sessions. With ids, stop the named ones (the
/// pids `sbx session ls` shows); with `all`, stop every live session. Each session is sent SIGTERM, then
/// SIGKILL if it has not exited within `grace`. Targets are resolved through the same
/// liveness-validated registry `attach` uses, so a stale or reused pid is never signalled. For ids,
/// reports each and exits 2 if any matched no live session, else 0; for `--all`, stopping nothing is
/// a no-op success (there is simply nothing to do). A session the host refused a *handle* on — not
/// the same thing as one that had already exited — is reported and exits 1 under either form: it
/// may still be running, which outranks a name that matched nothing.
///
/// Residuals (named, not fixed here), both because a signal terminates a supervisor without running
/// its RAII drops:
/// - the `network = "deny"` supervisor leaves its per-session egress socket and CA under
///   `<data>/egress/` on disk — the same leak any crash or `SIGKILL` of that process already
///   produces; a future sweep of stale egress artefacts (alongside the session housekeeping) is the
///   clean fix.
/// - stopping an interactive `sbx run` session signals its pty supervisor, whose terminal-state restore is
///   also a RAII guard, so the owner's terminal (where that an interactive `sbx run` runs) is left in raw mode
///   and needs a `reset`. Stopping a backgrounded agent — the verb's purpose — is unaffected; this
///   only bites the unusual case of stopping an interactive shell from another terminal. `--all`
///   targets *every* session, interactive shells included (a deliberate choice — "all" means all,
///   matching how `sbx session stop <id>` already treats a shell), so it can trip this residual on a shell
///   open elsewhere; stop a single agent by pid to avoid it.
pub(crate) fn stop(ids: &[&str], grace: Duration, all: bool) -> ExitCode {
    let Some(layout) = crate::store::Layout::from_env() else {
        eprintln!(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)."
        );
        return ExitCode::FAILURE;
    };
    let registry = crate::session::Registry::at(layout.data_dir());
    let sessions = match registry.list() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sbx session stop: cannot read the session registry: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The outcome lines go to stderr, so they take their hue from stderr — built once, not per
    // session in the `--all` loop.
    let epal = crate::style::Palette::for_stream(io::stderr().is_terminal());

    if all {
        if sessions.is_empty() {
            let pal = crate::style::Palette::for_stream(io::stdout().is_terminal());
            println!("{}", render_no_active_sessions(&pal));
            return ExitCode::SUCCESS;
        }
        // Sessions are independent cages (separate pid namespaces), so they are torn down one after
        // another — never interfering. A well-behaved agent exits on SIGTERM well before its grace
        // window elapses, so this is not grace-per-session in practice.
        let mut all_accounted = true;
        for target in &sessions {
            all_accounted &= stop_session(&registry, target, grace, &epal);
        }
        return ExitCode::from(stop_exit_code(!all_accounted, false));
    }

    let mut any_missing = false;
    let mut any_unstopped = false;
    for id in ids {
        let Some(target) = sessions.iter().find(|s| s.pid.to_string() == *id) else {
            crate::diag::error(&format!(
                "sbx session stop: no live session '{id}' — run `sbx session ls` to list them."
            ));
            any_missing = true;
            continue;
        };
        any_unstopped |= !stop_session(&registry, target, grace, &epal);
    }

    ExitCode::from(stop_exit_code(any_unstopped, any_missing))
}

/// Render one session's stop outcome (stderr): a clean SIGTERM stop is a real change (green
/// `stopped`), an already-exited session is a no-op (dim), and a forced SIGKILL is the caution hue
/// (yellow). The pid and label identify the session (cyan).
fn render_stop_outcome(
    pid: u32,
    label: &str,
    outcome: &crate::session::StopOutcome,
    grace: Duration,
    pal: &crate::style::Palette,
) -> String {
    let (n, ok, warn, err, dim, r) = (pal.name, pal.ok, pal.warn, pal.err, pal.dim, pal.reset);
    match outcome {
        crate::session::StopOutcome::AlreadyGone => {
            format!(
                "sbx session stop: session {n}{pid}{r} ({n}{label}{r}) {dim}had already exited{r}."
            )
        }
        crate::session::StopOutcome::Terminated => {
            format!("sbx session stop: {ok}stopped{r} session {n}{pid}{r} ({n}{label}{r}).")
        }
        crate::session::StopOutcome::Killed => {
            format!(
                "sbx session stop: session {n}{pid}{r} ({n}{label}{r}) did not exit within {}s — \
                 {warn}sent SIGKILL{r}.",
                grace.as_secs()
            )
        }
        crate::session::StopOutcome::NotSignalled(errno) => {
            format!(
                "sbx session stop: {err}cannot stop{r} session {n}{pid}{r} ({n}{label}{r}): {} — \
                 it was not signalled and may still be running.",
                io::Error::from_raw_os_error(*errno)
            )
        }
    }
}

/// Stop one resolved session and, when it is accounted for, reap its record: SIGTERM, then
/// SIGKILL after `grace`, report the outcome by pid and label, and drop the record so
/// `sbx session ls` is clean at once rather than waiting for the killed process to stop reading as
/// a zombie.
///
/// Returns whether the session is accounted for — stopped, or already gone. The one case that is
/// neither keeps its record: when the host refused a handle on the process, nothing was signalled
/// and the cage may still be up, so the record is what still names it to a listing and to a second
/// attempt. Dropping it there would trade a stop that failed for a cage nothing can address.
fn stop_session(
    registry: &crate::session::Registry,
    target: &crate::session::Session,
    grace: Duration,
    pal: &crate::style::Palette,
) -> bool {
    let outcome = target.stop(grace);
    eprintln!(
        "{}",
        render_stop_outcome(target.pid, &target.label(), &outcome, grace, pal)
    );
    if matches!(outcome, crate::session::StopOutcome::NotSignalled(_)) {
        return false;
    }
    registry.reap(target);
    true
}

/// The exit code a `stop` run reports, from what its loops observed — one definition for both
/// forms of the verb, so `--all` and a list of ids answer a caller the same way.
///
/// A session that was never signalled outranks an id that matched nothing: both are failures, and
/// the one that leaves a cage running is the one the caller must act on — the other is a typo.
fn stop_exit_code(any_unstopped: bool, any_missing: bool) -> u8 {
    if any_unstopped {
        1
    } else if any_missing {
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests;
