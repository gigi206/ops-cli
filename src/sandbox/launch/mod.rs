//! Launching a sandbox: turning a [`SandboxSpec`] into a running bubblewrap
//! process.
//!
//! Two launch models, by terminal policy:
//! - **non-interactive** (`sbx run` with a piped/non-tty stdin, or `--detach`): it execs
//!   bwrap and lets it *replace* the sbx process, so the command inherits the real stdio
//!   and its exit status becomes sbx's. The spec uses [`TerminalPolicy::NewSession`].
//! - **interactive** (`sbx run` on a real terminal — a shell when no command is given, or
//!   an interactive command): sbx stays alive as a **pty supervisor**. It
//!   gives the sandbox a private controlling terminal (so job control works
//!   inside) and relays bytes to and from the real terminal (which the sandbox
//!   therefore cannot reach). The spec uses [`TerminalPolicy::PrivateTty`], which
//!   omits `--new-session` — bubblewrap's `setsid` would `setsid` away from that
//!   private terminal.
//!
//! The supervisor also relays terminal resizes: it catches `SIGWINCH` on the real
//! terminal and pushes the new window size onto the pty master, so the kernel
//! delivers `SIGWINCH` to the cage's foreground process group and an interactive
//! TUI reflows live. Interactive `sbx app` launches ride this same supervisor.
//!
//! Known gaps in the supervisor (named, not silent):
//! - terminal-state restore is a RAII guard, so it covers normal/error/panic
//!   exits but not a `SIGTERM`/`SIGHUP` kill;
//! - the relay is single-threaded with a blocking `write_all` to the master, so a
//!   pathological simultaneous flood (the inner shell not draining its input while
//!   also flooding output) could stall it. Humans don't trigger it and `script(1)`
//!   shares the limitation; a split-direction or non-blocking relay is the fix.
//!
//! What lives where. The pipeline itself stays in this file: the [`Prepared`] prerequisites, the
//! `prepare*` chain that fills them, the launch-mode decision, and the `run`/`app`/`mise` verbs.
//! The rest of the directory takes one concern each — [`mod@build`] stands a cage up,
//! [`mod@cage`] turns the finished spec into a running process, [`mod@startup`] writes the script
//! that process begins with and [`mod@equip`] the tool-equip vocabulary that script speaks.
//! Beside them are the callers that borrow the machinery without being a launch: [`mod@detach`]
//! (the background daemon and the format of its log), [`mod@session`] (`attach` and `stop`),
//! [`mod@reclaim`] (`sbx gc`) and [`mod@roll`] (the two `sbx upgrade` rolls that need a cage).
//!
//! The prerequisites stay here rather than moving down with their biggest reader because a child
//! module sees every private item of its parent with no annotation, so one copy in this file is
//! reachable from all eight without widening anything.

use super::binds::{self, Userland};
use super::broker;
use super::egress;
use super::forward;
use super::pty::fork_with_pty;
use super::spec::{NetPolicy, SandboxSpec, TerminalPolicy};
use super::sshagent;
use crate::session::{Kind, RecordGuard, Session};
use crate::store::Layout;
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io;
use std::io::IsTerminal;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::{Arc, RwLock};
use std::time::Duration;

// The launch pipeline's own parts, in the order a launch meets them: the cage that gets built, the
// script it starts with, the equip vocabulary that script speaks, and the four ways to run it.
mod build;
mod cage;
mod equip;
mod startup;
// The verbs that borrow the machinery above without being a launch: the detached daemon and its
// log, the two session verbs, `sbx gc`, and the two `sbx upgrade` rolls.
mod detach;
mod reclaim;
mod roll;
mod session;

use build::{LaunchGuard, build};
use cage::{exec, register, run_supervised, supervise};
use detach::launch_detached;
use session::{launch_display_name, render_gui_stop_hint};

pub(crate) use detach::{SessionHeader, detach_log_path, parse_session_header};
pub(crate) use reclaim::{gc, superseded_reclaimable_hint};
pub(crate) use roll::{upgrade_mise_packages, upgrade_provision_steps};
pub(crate) use session::{attach, stop};
// Re-exported at the width they had as one file: `pub(super)` on a child would now mean "visible in
// `launch`", and these four are read from `sandbox` itself.
pub(in crate::sandbox) use cage::{cage_command, seccomp_argv, status_code};
pub(in crate::sandbox) use reclaim::{session_housekeeping, shared_store_gc};

/// The hard prerequisites and per-launch resolution shared by `run` and `shell`:
/// the engine, sbx's store layout, the current directory, the resolved
/// configuration, the effective nixpkgs reference for this launch, and the base
/// userland (provisioned against that same reference).
///
/// A single effective reference drives the **whole** sandbox — both the base
/// userland and the project's tools. They must share it: the base glibc is exported
/// on `LD_LIBRARY_PATH` (for foreign binaries) and is searched before a tool's own
/// `RUNPATH`, so a tool resolved against a *different* glibc would load the base
/// `libc.so.6` under its own loader and crash on a `GLIBC_PRIVATE` skew. One channel
/// per launch keeps base, tools, and `LD_LIBRARY_PATH` on one glibc.
struct Prepared {
    bwrap: PathBuf,
    nix: PathBuf,
    /// The `nix-store` command, used to seed and register the per-project store the
    /// cage's writable `/nix` is backed by.
    nix_store: PathBuf,
    layout: Layout,
    cwd: PathBuf,
    cfg: crate::config::Resolved,
    /// The effective reference for this launch: a project pin when one is set,
    /// otherwise the global channel. Drives the base userland (its OS substrate) and
    /// the project's tools. **Not** the reference for the mise engine — see `engine`.
    nixpkgs: String,
    /// The reference for the mise engine, from its dedicated lock (it tracks the global
    /// channel but rolls independently via `sbx upgrade mise`). mise runs in its own
    /// store view, free of the one-channel rule, so it may sit on a different revision
    /// than `nixpkgs`. Drives both the in-cage mise (the base userland) and the
    /// host-side `[env]` driver.
    engine_ref: String,
    userland: Userland,
    /// Whether this launch is one cage of a batch — set on the `sbx upgrade` rolls, which build one
    /// cage per app, and left `false` for an ordinary launch.
    ///
    /// It gates the narration a launch prints about how its own cage was assembled: the "equipping
    /// app packages in-cage" line and the standing broker's note. Each tells an ordinary launch
    /// something it wants (what is being equipped, which host resource is fenced); repeated once per
    /// app across a fifty-app roll, both bury the one thing that matters — which app actually
    /// rolled — and they land on stderr while the roll's own report is on stdout, so they interleave
    /// with it rather than group. The flag names the situation rather than a policy, so a third such
    /// line joins by reading it. It suppresses narration only: no warning, no refusal, and nothing
    /// the cage does is conditioned on it.
    in_batch: bool,
    /// What an unresolvable credential costs this launch. `Abort` everywhere but the batch rolls,
    /// which run one captured command per app and must not let a credential that command never
    /// sends decide whether the app is upgraded — see [`crate::sandbox::egress::Unresolved`].
    unresolved_secret: crate::sandbox::egress::Unresolved,
}

/// `sbx run [--] [<cmd>]`: run a command inside the project sandbox, or — with no command — open
/// the project shell. The launch mode follows stdin: a real terminal (and not `--detach`) runs
/// interactively under the pty supervisor, so a shell or a TUI gets a private controlling terminal
/// with job control; a piped/non-tty stdin, or `--detach`, keeps the exec-replace / supervised path
/// (stdio inherited, exit status propagated).
pub(crate) fn run(
    cmd: Vec<OsString>,
    detach: bool,
    observe: bool,
    ov: crate::config::Override,
) -> ExitCode {
    // With no command, `sbx run` opens the project shell — which needs a terminal, so a detached
    // no-command launch is refused rather than started into the void.
    if cmd.is_empty() && detach {
        crate::diag::error(
            "sbx: `sbx run --detach` needs a command (a detached shell has no terminal).",
        );
        return ExitCode::from(2);
    }
    let mut prep = match prepare_with(&ov, None) {
        Ok(p) => p,
        Err(code) => return code,
    };
    // The override is the authoritative final word over the resolved baseline (`sbx run` has no app
    // overlay, so here is that final point).
    if let Err(code) = apply_launch_override(&mut prep.cfg, ov) {
        return code;
    }

    // SAFETY: `isatty` only inspects fd 0.
    let interactive = !detach && unsafe { libc::isatty(0) } == 1;

    // Observation runs on any path where a parent sbx survives the cage. Its inline stderr feed rides
    // only the non-tty foreground path under a non-enforcing `[proc]` mode; the launches that take it
    // away are told so, and pointed at `sbx proc logs`/`sbx proc live` for the same events.
    warn_observe_feed_absent(observe, interactive, &prep.cfg.proc);

    if cmd.is_empty() {
        // No command: open the project shell. Interactive gets the full pty shell (mise activation
        // and the `(sbx-<slug>)` prompt via the synthetic rc); a piped stdin runs a non-interactive
        // shell reading its script from stdin, reaching activated tools through the shims on PATH.
        return if interactive {
            launch_interactive_shell(&prep, binds::Runtime::ProjectDefault, observe)
        } else {
            let shell = vec![prep.userland.shell_bin.clone().into_os_string()];
            launch(
                prep,
                binds::Runtime::ProjectDefault,
                Kind::Shell,
                shell,
                false,
                "run",
                observe,
            )
        };
    }

    if interactive {
        launch_pty_supervised(
            &prep,
            binds::Runtime::ProjectDefault,
            Kind::Run,
            cmd,
            observe,
        )
    } else {
        launch(
            prep,
            binds::Runtime::ProjectDefault,
            Kind::Run,
            cmd,
            detach,
            "run",
            observe,
        )
    }
}

/// Which observation lenses a launch runs, from its resolved `[proc]` policy and the `--observe` flag.
/// The poll exec lens runs when observation is asked for but enforcement is **not** in effect — an
/// enforcing launch (`enforce`/`ask`) uses the seccomp user-notification supervisor as its exec source
/// instead, and that supervisor already owns the proc control socket, so the poll observer must not
/// also bind it. The inotify fs lens follows the `--observe` flag. Returns `(exec_poll, fs)`.
fn observation_flags(proc: &crate::proc_policy::ProcPolicy, observe: bool) -> (bool, bool) {
    let exec_poll = !proc.enforcing()
        && (observe || matches!(proc.mode, crate::proc_policy::ProcMode::Observe));
    (exec_poll, observe)
}

/// Whether a guardless cage may `exec`-replace this process instead of forking and supervising it.
///
/// An [`Observation`](super::observe_feed::Observation) lives in host threads rooted on *this*
/// process, so anything that starts one needs a live parent for the cage's lifetime — an `exec`
/// would replace the supervisor out from under it and drop the socket, the ring and the poll
/// thread on the floor. The decision used to be written against the `--observe` flag alone, which
/// silently lost a config-declared `[proc] mode = "observe"`: the detached path started the
/// observer and then exec'd it away (so `sbx proc logs` had nothing to read), and the foreground
/// path never started one at all. Ask [`observation_flags`] — the same pair that decides whether
/// to start the observer — so the two answers cannot disagree.
fn may_exec_replace(proc: &crate::proc_policy::ProcPolicy, observe: bool) -> bool {
    let (exec_poll, fs) = observation_flags(proc, observe);
    !(exec_poll || fs)
}

/// Why `--observe`'s inline `[sbx:exec]` feed will not appear, or `None` when it will.
///
/// The feed rides one path only: a non-tty foreground launch whose exec observation is the poller.
/// Two things take it away, and both otherwise leave the flag reading as applied — the launch
/// accepts it, prints nothing, and streams nothing:
///
/// - an interactive terminal, where the feed would fight the command's own screen;
/// - an enforcing `[proc]` mode, where the exec lens is the seccomp supervisor rather than the
///   poller ([`observation_flags`] clears `exec_poll` for exactly this set of modes), so nothing
///   feeds the inline stream.
///
/// The enforcing case is worth stating plainly rather than implying a loss: the lens then sees
/// *more* than the poller ever does, intercepting every `execve` including processes far too
/// short-lived to appear in a sampled snapshot of `/proc`. The events exist; only the inline path is
/// missing. Both cases therefore point at the same place to read them.
///
/// Separated from the printing so the decision can be asserted without capturing stderr, and so the
/// two launch paths that warn cannot drift apart.
fn observe_feed_absent_reason(
    observe: bool,
    interactive: bool,
    proc: &crate::proc_policy::ProcPolicy,
) -> Option<&'static str> {
    if !observe {
        return None;
    }
    if proc.enforcing() {
        return Some(
            "an enforcing `[proc]` mode watches every exec through the seccomp lens instead of the \
             inline feed",
        );
    }
    interactive.then_some("the inline feed is not shown for an interactive terminal")
}

/// Warn that `--observe`'s inline stderr feed is not shown for an interactive terminal (it would
/// fight a TUI for the screen), pointing at the out-of-band viewers instead. Observation itself still
/// runs — the ring and its control socket are populated so `sbx proc logs`/`sbx proc live` can watch
/// this session from another terminal; only the inline echo is suppressed, and that decision is made
/// per launch path where the observer is started (interactive/detached never echo inline). Shared by
/// `run`/`app`.
fn warn_observe_feed_absent(
    observe: bool,
    interactive: bool,
    proc: &crate::proc_policy::ProcPolicy,
) {
    if let Some(reason) = observe_feed_absent_reason(observe, interactive, proc) {
        crate::diag::warn(&format!(
            "--observe: {reason} — watch this session with `sbx proc logs`/`sbx proc live`"
        ));
    }
}

/// Apply the (non-channel) part of a one-shot override to a prepared config, aborting the launch
/// with a pointed error (exit 2) when it sets an invalid scalar security value — there is no safe
/// baseline fallback for one, so it is refused rather than run at the wrong posture. Shared by
/// `run`/`shell`/`app`, each applying the override at its own final point (after any app overlay).
fn apply_launch_override(
    cfg: &mut crate::config::Resolved,
    ov: crate::config::Override,
) -> Result<(), ExitCode> {
    cfg.apply_override(ov).map_err(|errs| {
        for e in errs {
            crate::diag::error(&format!("sbx: {e}"));
        }
        ExitCode::from(2)
    })
}

/// Build the cage, register it, and run it — either in the foreground (this process becomes or
/// supervises the cage) or detached into a background daemon. The single seam `run`, `app`, and
/// the mise passthrough share, so the build → register → launch sequence is identical on both
/// paths and lives in one place. `label` names the session in the detached startup message.
#[allow(clippy::too_many_arguments)]
fn launch(
    prep: Prepared,
    runtime: binds::Runtime,
    kind: Kind,
    cmd: Vec<OsString>,
    detach: bool,
    label: &str,
    observe: bool,
) -> ExitCode {
    if detach {
        warn_ask_under_detach(&prep.cfg.network);
        launch_detached(prep, runtime, kind, cmd, label, observe)
    } else {
        launch_foreground(prep, runtime, kind, cmd, observe)
    }
}

/// Warn when an `ask`-posture launch is detached with no timeout. A background session has no
/// terminal to surface the park notice, so an undecided request waits indefinitely (the default).
/// The launch still proceeds — the user chose both `ask` and `--detach` — but the footgun is named,
/// with the two ways out. A configured `ask_timeout`, or a non-ask posture, is silent.
fn warn_ask_under_detach(network: &crate::config::NetworkPolicy) {
    use crate::allowlist::DefaultAction;
    if let crate::config::NetworkPolicy::Allowlist(policy) = network
        && policy.default_action() == DefaultAction::Ask
        && policy.ask_timeout().is_none()
    {
        crate::diag::warn(
            "`ask` egress under --detach with no `ask_timeout`: a background session has no \
                 terminal to prompt, so an undecided request parks indefinitely. Set \
                 `[network] ask_timeout`, or answer it with `sbx net pending`.",
        );
    }
}

/// Run the cage in the foreground: this process becomes the cage (exec) or supervises it
/// (allowlist), and its exit status becomes sbx's.
fn launch_foreground(
    prep: Prepared,
    runtime: binds::Runtime,
    kind: Kind,
    cmd: Vec<OsString>,
    observe: bool,
) -> ExitCode {
    let (spec, guard) = match build(&prep, runtime, cmd) {
        Ok(v) => v,
        Err(code) => return code,
    };

    register(prep.layout.data_dir(), &spec, kind, runtime, false);

    // Decided before the match: the same pair drives both the exec/supervise choice and the
    // observer below, so a config-declared `[proc] mode = "observe"` cannot be seen by one and
    // missed by the other.
    let (exec_poll, fs) = observation_flags(&prep.cfg.proc, observe);

    match guard {
        // The default postures with no observation: exec-replace, so the command's exit status
        // becomes sbx's. The pid and its start time survive the exec, so the registry record keeps
        // matching the sandbox and is reclaimed by liveness pruning once it exits.
        None if may_exec_replace(&prep.cfg.proc, observe) => {
            // On success this never returns; reaching past it means exec itself failed.
            let err = exec(&prep.bwrap, &spec, &prep.cfg.limits);
            crate::diag::error(&format!("sbx: failed to launch the sandbox: {err}"));
            ExitCode::FAILURE
        }
        // Supervise instead of exec-replace — fork bwrap, wait, propagate the exit status — whenever
        // a host-side thing must outlive the cage. That is a guard (a network allowlist's filtering
        // proxy, a forward forwarder, a filtered D-Bus proxy, or an in-cage portal whose runtime dir
        // must be cleaned up), OR observation: the observer runs in a host thread that needs a live
        // parent for the cage's lifetime, so observation forces supervision even with no guard. The
        // observer roots on this supervisor's own pid — the cage is its descendant in host pid-space —
        // and its socket + poll thread are torn down on drop, before the guard is released. `inline`
        // is true here: this is the non-tty foreground path, the one place the `[sbx:exec]` feed
        // streams to stderr (as well as into the ring `sbx proc logs` reads).
        maybe_guard => {
            let observer = (exec_poll || fs).then(|| {
                super::observe_feed::Observation::start(
                    prep.layout.data_dir(),
                    &spec.workdir,
                    exec_poll,
                    fs,
                    true,
                )
            });
            let code = run_supervised(&prep.bwrap, &spec, &prep.cfg.limits);
            drop(observer);
            drop(maybe_guard);
            code
        }
    }
}

/// The result of an `sbx app <name>` launch: the exit code, plus — for a `--net-learn` run — the
/// rules synthesized from the egress the run was refused. The caller (`app_cmd`) writes them to the
/// chosen profile (or prints them under `--dry-run`); keeping the write in `main` keeps the trust
/// gating and re-trust out of the sandbox module.
pub(crate) struct AppOutcome {
    pub(crate) code: ExitCode,
    pub(crate) learned: Option<super::Synthesis>,
}

impl AppOutcome {
    fn plain(code: ExitCode) -> Self {
        AppOutcome {
            code,
            learned: None,
        }
    }
}

/// The shells whose `-c` binds the *next* argv element to `$0`. All four are POSIX-family and
/// agree on it, so the rule is theirs, not a per-shell quirk.
const ARGV0_SHELLS: [&str; 4] = ["bash", "sh", "zsh", "dash"];

/// Whether `cmd` ends in `<shell> -<flags>c <script>` — the shape whose trailing element is a
/// script, not a program, so anything appended after it starts at `$0`.
///
/// The script must be *last*: an argv that already carries an element after it has its `$0`, and a
/// profile that wrote one is saying which name its script should report. The shell is matched on
/// its file name so an absolute `/bin/bash` counts, and the flag must *end* in `c` because that is
/// what makes the following element the script (`-c`, `-lc`, `-euc`); a flag with anything after
/// the `c` consumes it differently and is left alone.
fn ends_with_shell_payload(cmd: &[OsString]) -> bool {
    let [shell, flag, _script] = &cmd[cmd.len().saturating_sub(3)..] else {
        return false;
    };
    let is_shell = Path::new(shell)
        .file_name()
        .is_some_and(|s| ARGV0_SHELLS.iter().any(|k| s == *k));
    let is_c_flag = flag.to_str().is_some_and(|f| {
        f.strip_prefix('-')
            .is_some_and(|rest| rest.ends_with('c') && rest.bytes().all(|b| b.is_ascii_lowercase()))
    });
    is_shell && is_c_flag
}

/// `sbx app <name>`: launch the named application profile — the project sandbox baseline
/// plus the app's gated overlay, running the command the app declares. Apps run in the same
/// locked-down posture as `sbx run`; the overlay's security fields took effect only if their
/// source was trusted (the global config or a trusted project), so launching an app on
/// untrusted code is as safe as `sbx run` there.
#[allow(clippy::too_many_arguments)]
pub(crate) fn app(
    name: &str,
    detach: bool,
    observe: bool,
    extra: Vec<OsString>,
    ov: crate::config::Override,
    net_learn: Option<super::Granularity>,
) -> AppOutcome {
    // The configuration is read before the engines are probed, because both refusals below are
    // answers about the *project*, not about the host: an app the project does not declare is
    // undeclared on a machine with no bubblewrap too, and saying so is more use to the caller than
    // being told to install a sandbox engine they were not about to reach.
    let mut pc = match launch_cwd().and_then(|cwd| prepare_config(cwd, &ov)) {
        Ok(p) => p,
        Err(code) => return AppOutcome::plain(code),
    };
    let Some(app) = pc.cfg.apps.remove(name) else {
        crate::diag::error(&format!(
            "sbx: no app named `{name}`.{}",
            available_apps(&pc.cfg)
        ));
        return AppOutcome::plain(ExitCode::from(2));
    };
    if app.cmd.is_empty() {
        // Both declaration shapes are named, because only one of them is a table. A hand-written
        // profile file reaches here (`sbx app import` refuses a `cmd`-less one, a file dropped into
        // the directory is simply read), and telling its author to add an `[app.<name>]` table
        // would ask for the very wrapper `validate_profile` tells them to remove.
        crate::diag::error(&format!(
            "sbx: app `{name}` declares no command — add a `cmd` to its declaration (at the top \
             level of `apps/{name}.toml`, or in the `[app.{name}]` table of a project config)."
        ));
        return AppOutcome::plain(ExitCode::FAILURE);
    }
    // The argv and the home scope are owned by the app; read them before the overlay is folded
    // in (which moves the app but does not touch them). The scope keys this app's persistent
    // home: one shared across projects (`Global`) or one per project (`Project`). Any trailing
    // `sbx app <name> -- <args>` are appended to the declared `cmd`, so the caller can pass a flag
    // to the launched program (e.g. `-c` to resume) without editing the profile.
    let mut cmd: Vec<OsString> = app.cmd.iter().map(OsString::from).collect();
    if !extra.is_empty() && ends_with_shell_payload(&cmd) {
        // The shell's own `$0`, so the caller's first argument lands on `$1`. `<shell> -c <script>`
        // binds the element right after the script to `$0`, not to `$1`: without this filler the
        // append above silently eats one argument, and the profile sees a short `"$@"`. The app's
        // name is the filler because `$0` is what the shell prints in its own diagnostics.
        //
        // Only when there is something to append: with no trailing arguments nothing can be eaten,
        // and leaving the argv untouched keeps `$0` at whatever the shell defaults to.
        cmd.push(OsString::from(name));
    }
    cmd.extend(extra);
    // A bundle's install step and a declared service both run BEFORE the app's command, in this same
    // cage — same posture, same allowlist, same environment — and never in its place: the app's
    // command stays its identity. Both are composed in `build`, once the app overlay and any
    // one-shot override have been folded in, so the whole start-up is written in one place and one
    // order rather than by whichever wrapper happened to be applied first.
    let runtime = match app.home_scope {
        crate::config::AppHomeScope::Global => binds::Runtime::GlobalApp(name),
        crate::config::AppHomeScope::Project => binds::Runtime::ProjectApp(name),
    };
    // The host's half, now that every answer that belongs to the project has been given: the
    // engines, the user namespace, and the channel this app's own lock resolves against.
    let mut prep = match prepare_engines(pc, Some(name)) {
        Ok(p) => p,
        Err(code) => return AppOutcome::plain(code),
    };
    crate::diag::hint(&format!("sbx: launching app `{name}`"));
    prep.cfg.merge_app(app);
    // The override is the authoritative final word — applied *after* the app overlay so a one-shot
    // `sbx app <name> --config …`/`SBX_*` beats the app's own posture, not the other way round.
    if let Err(code) = apply_launch_override(&mut prep.cfg, ov) {
        return AppOutcome::plain(code);
    }

    // SAFETY: `isatty` only inspects fd 0.
    let interactive = !detach && unsafe { libc::isatty(0) } == 1;
    warn_observe_feed_absent(observe, interactive, &prep.cfg.proc);

    // `--net-learn`: run the app under its real (unchanged) posture, capture the egress it was
    // refused for lack of a rule, and hand the synthesized rules back for the caller to write. It is
    // foreground-only (the parser refuses `--detach`) and needs a filtering posture — a `shared` or
    // `none` app has no proxy logging egress, so there is nothing to learn.
    if let Some(gran) = net_learn {
        let policy = match &prep.cfg.network {
            crate::config::NetworkPolicy::Allowlist(p) => p.clone(),
            other => {
                crate::diag::error(&format!(
                    "sbx: --net-learn needs a filtering network posture (mode allow/deny/ask); \
                     app `{name}` has `{}` — nothing logs egress to learn from.",
                    network_posture_name(other)
                ));
                return AppOutcome::plain(ExitCode::from(2));
            }
        };
        // A build failure (a provisioning error, a host that cannot sandbox) must NOT be reported as
        // "nothing to learn": return it as a plain failure so its code propagates and the caller
        // never enters the write path. Only a cage that actually ran yields events to learn from —
        // an empty log from a real run (the app was refused nothing) is a genuine "no new rules".
        let (code, events) =
            match launch_foreground_learning(&prep, runtime, Kind::Run, cmd, interactive) {
                Ok(v) => v,
                Err(code) => return AppOutcome::plain(code),
            };
        // Subsume against the SAME effective policy the proxy enforced — the config allowlist unioned
        // with the always-on built-in allow-set — so a built-in-allowed host is never re-proposed.
        let effective = super::union_with_builtin((*policy).clone());
        let learned = super::netlearn::synthesize(&events, &effective, gran);
        return AppOutcome {
            code,
            learned: Some(learned),
        };
    }

    // An interactive foreground launch (a real terminal on stdin) runs under the pty supervisor:
    // the agent's TUI gets a private controlling terminal and live terminal-resize propagation
    // (the same isolation an interactive `sbx run` uses — the real terminal stays unreachable). A detached
    // agent has no terminal, and a piped/non-tty invocation must not be handed one, so both keep
    // the exec-replace / supervised `NewSession` path.
    let code = if interactive {
        launch_pty_supervised(&prep, runtime, Kind::Run, cmd, observe)
    } else {
        launch(prep, runtime, Kind::Run, cmd, detach, name, observe)
    };
    AppOutcome::plain(code)
}

/// The posture name for a `--net-learn` refusal message — the config vocabulary, not the internal
/// `NetworkPolicy` variant.
fn network_posture_name(network: &crate::config::NetworkPolicy) -> &'static str {
    match network {
        crate::config::NetworkPolicy::Shared => "shared",
        crate::config::NetworkPolicy::Isolated => "none",
        crate::config::NetworkPolicy::Allowlist(_) => "allowlist",
    }
}

/// Run an `sbx app` launch in the foreground and return the egress it logged, for `--net-learn`.
/// Interactive launches use the pty supervisor (a private controlling terminal, like an interactive `sbx run`);
/// a non-tty one supervises directly. Either way the egress guard is held for the whole run, then
/// its log is snapshotted before the guard is dropped — so the returned events are the run's full
/// record. A `build()` failure is `Err(code)`, distinct from a clean run with no denials (`Ok` with
/// an empty log): the caller must not treat a failed build as "nothing to learn".
fn launch_foreground_learning(
    prep: &Prepared,
    runtime: binds::Runtime,
    kind: Kind,
    cmd: Vec<OsString>,
    interactive: bool,
) -> Result<(ExitCode, Vec<super::control::LogEvent>), ExitCode> {
    let (spec, guard) = match build(prep, runtime, cmd) {
        Ok((s, g)) if interactive => (s.with_private_tty(), g),
        Ok((s, g)) => (s, g),
        Err(code) => return Err(code),
    };

    // A pty session unlinks its record on exit (RecordGuard); a supervised one persists it
    // (liveness-pruned), matching `launch_pty_supervised` and `launch_foreground` respectively.
    let record = register(prep.layout.data_dir(), &spec, kind, runtime, false);
    let _record = interactive.then(|| record.map(RecordGuard::new));

    let code = if interactive {
        let gui = matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland);
        match supervise(&prep.bwrap, &spec, &prep.cfg.limits, gui) {
            Ok(c) => ExitCode::from(c as u8),
            Err(e) => {
                crate::diag::error(&format!("sbx: sandbox session failed: {e}"));
                ExitCode::FAILURE
            }
        }
    } else {
        run_supervised(&prep.bwrap, &spec, &prep.cfg.limits)
    };

    let events = guard
        .as_ref()
        .map(LaunchGuard::observed_events)
        .unwrap_or_default();
    drop(guard);
    Ok((code, events))
}

/// A suffix for the "no such app" error: " (available: a, b)" listing the configured app
/// names, or a note that none are configured — so a typo or an unconfigured name points at
/// what exists.
fn available_apps(cfg: &crate::config::Resolved) -> String {
    if cfg.apps.is_empty() {
        " No apps are configured.".to_string()
    } else {
        let names: Vec<&str> = cfg.apps.keys().map(String::as_str).collect();
        format!(" (available: {})", names.join(", "))
    }
}

/// `sbx mise [args...]`: run mise inside the project's open cage, where it can
/// self-equip the project's `nix:` tools (`sbx mise install nix:<pkg>`) into the
/// project's own writable store. Sugar over `sbx run -- mise [args...]`: mise is
/// present in every cage with the `nix:` backend plugin registered, so the only
/// thing this adds is sparing the `run --` prefix.
///
/// A tool the agent *activates* (`mise use [-g] nix:<pkg>`) is on PATH in later
/// launches — through the shims dir on PATH for `sbx run`, and `mise activate` for the
/// an interactive `sbx run` — and persists in the project's store. A bare `mise install` (not
/// activated) persists too and `mise exec`/`mise which` resolve it, but it is not on
/// PATH, matching mise's own install-vs-use split. This path is intentionally open — it
/// works whether or not the project is trusted, the agent-self-equip posture — unlike
/// `sbx run`'s host-side `nix:` provisioning, which stays trusted-only and is a parallel
/// path that does not share state with what mise installs here.
pub(crate) fn run_mise(args: Vec<OsString>) -> ExitCode {
    let mut cmd = vec![OsString::from("mise")];
    cmd.extend(args);
    // `sbx mise` is a passthrough — every argument is mise's, so it takes no one-shot override.
    run(cmd, false, false, crate::config::Override::none())
}

/// The context this project's prebuilt (`deb:`/`appimage:`/`tarball:`) packages are provisioned in.
/// See [`super::prebuilt::Ctx`].
fn prebuilt_ctx(prep: &Prepared) -> super::prebuilt::Ctx<'_> {
    super::prebuilt::Ctx {
        nix: &prep.nix,
        layout: &prep.layout,
        project: &prep.cwd,
        nixpkgs: &prep.nixpkgs,
        allow_insecure_http: prep.cfg.allow_insecure_http,
    }
}

/// Launch an interactive shell in the cage for `runtime`, under a pty supervisor so job control
/// works — the shared body of `sbx run` with no command (the project's default home) and `sbx
/// session attach` (which reproduces a session's home, including an app's isolated one). The command
/// is the resolved interactive shell started with `--rcfile` at the synthetic in-cage rc, which
/// activates mise so the project's activated tools (`mise use`) manage PATH/env in the interactive
/// shell — mise's documented interactive mechanism. (A non-interactive `sbx run` instead reaches
/// activated tools through the shims dir on PATH, with no shell to hook.) Assumes stdin is a terminal
/// (the callers check).
fn launch_interactive_shell(prep: &Prepared, runtime: binds::Runtime, observe: bool) -> ExitCode {
    let cmd = vec![
        prep.userland.shell_bin.clone().into_os_string(),
        OsString::from("--rcfile"),
        OsString::from(binds::SHELL_RC_INCAGE),
    ];
    launch_pty_supervised(prep, runtime, Kind::Shell, cmd, observe)
}

/// Launch `cmd` under the pty supervisor: the cage gets a *private* controlling terminal (so job
/// control and terminal-resize propagation work inside), while the real launching terminal stays
/// unreachable — sbx holds the pty master and never execs. Shared by an interactive `sbx run`, `sbx session attach`,
/// and interactive `sbx app`.
///
/// The session is registered and its record held by a [`RecordGuard`] that unlinks it when the
/// session ends (sbx stays alive as the supervisor, so the record is cleaned promptly rather than
/// left for liveness pruning). The egress guard is held for the whole session too: under a network
/// allowlist the host filtering proxy runs on a thread alongside the supervisor, and the guard
/// unlinks its socket and CA on exit.
fn launch_pty_supervised(
    prep: &Prepared,
    runtime: binds::Runtime,
    kind: Kind,
    cmd: Vec<OsString>,
    observe: bool,
) -> ExitCode {
    // A graphical app's real interface is its window, not this terminal — Ctrl+C is forwarded
    // faithfully but a GUI app may ignore it — so note how to stop it. Only for a foreground app
    // launch (`Kind::Run`) with a display; a shell (an interactive `sbx run`/`sbx session attach`, `Kind::Shell`) uses
    // Ctrl+C normally and needs no hint. Computed before `cmd`/`runtime` move into `build`.
    let stop_hint = (matches!(kind, Kind::Run)
        && matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland))
    .then(|| launch_display_name(&runtime, &cmd));

    let (spec, guard) = match build(prep, runtime, cmd) {
        Ok((s, g)) => (s.with_private_tty(), g),
        Err(code) => return code,
    };

    let _record =
        register(prep.layout.data_dir(), &spec, kind, runtime, false).map(RecordGuard::new);
    // Hold the guard (egress proxy / forward forwarder threads) for the whole pty session.
    let _guard = guard;
    // With observation on, populate the exec ring + control socket so `sbx proc logs`/`sbx proc live`
    // can watch this interactive session from another terminal; held for the whole pty session and
    // torn down on exit. Never inline — this terminal belongs to the agent's TUI.
    let (exec_poll, fs) = observation_flags(&prep.cfg.proc, observe);
    let _observer = (exec_poll || fs).then(|| {
        super::observe_feed::Observation::start(
            prep.layout.data_dir(),
            &spec.workdir,
            exec_poll,
            fs,
            false,
        )
    });

    // The registered pid is this supervisor's own (`Session::current` records `std::process::id()`),
    // which is exactly what `sbx session ls` shows and `sbx session stop` accepts, so the hint names the real id.
    if let Some(name) = stop_hint {
        let epal = crate::style::Palette::for_stream(io::stderr().is_terminal());
        eprintln!("{}", render_gui_stop_hint(&name, std::process::id(), &epal));
    }

    let gui = matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland);
    match supervise(&prep.bwrap, &spec, &prep.cfg.limits, gui) {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            crate::diag::error(&format!("sbx: sandbox session failed: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// Hard prerequisites + per-launch resolution shared by `run` and `shell`. Returns
/// a [`Prepared`] or an `ExitCode` to return after a clean, pointed error.
///
/// The configuration is loaded here (once, infallibly) because its `nixpkgs` field
/// chooses the channel the **whole** launch resolves against — base userland and
/// tools alike (see [`Prepared`] for why they must be one).
fn prepare() -> Result<Prepared, ExitCode> {
    prepare_with(&crate::config::Override::none(), None)
}

/// [`prepare`] with a one-shot override applied. The override's **nixpkgs channel** is applied to
/// the loaded config *before* the lock target is chosen (the channel decides which lock the whole
/// launch resolves against), so a `-o nixpkgs=…` / `SBX_CONFIG` channel takes effect. The rest of
/// the override (env, binds, network, gui, limits, secret) is applied by the caller with
/// [`crate::config::Resolved::apply_override`] — after any app overlay merges, so it beats that too.
///
/// `app` names the app this launch is for, when it is one. It arrives here — before the app's
/// overlay is even looked up — because the channel is resolved here, and an app resolves against
/// its own lock ([`effective_lock_target`]). It is only ever the *identity* of the launch: nothing
/// of the app's configuration is read at this point, and nothing here can be influenced by it.
fn prepare_with(ov: &crate::config::Override, app: Option<&str>) -> Result<Prepared, ExitCode> {
    prepare_in(launch_cwd()?, ov, app)
}

/// The project directory a launch invoked without an explicit one is built from.
fn launch_cwd() -> Result<PathBuf, ExitCode> {
    std::env::current_dir().map_err(|e| {
        crate::diag::error(&format!("sbx: cannot read the current directory: {e}"));
        ExitCode::FAILURE
    })
}

/// [`prepare_with`] against an explicit project directory instead of the process's current
/// directory. The whole cage — its per-project store, home, and resolved config — is built from
/// `cwd`, so a caller that retargets another project (`sbx upgrade --project <path>`) drives the
/// in-cage roll against *that* project, not wherever the command happened to be invoked.
fn prepare_in(
    cwd: PathBuf,
    ov: &crate::config::Override,
    app: Option<&str>,
) -> Result<Prepared, ExitCode> {
    prepare_engines(prepare_config(cwd, ov)?, app)
}

/// The half of a launch's preparation that needs no engine: where sbx keeps its data, and the
/// project's configuration with the one-shot override applied and validated.
///
/// It is a separate step because **the answers it gives do not depend on the host being able to
/// sandbox**. A mistyped `--config network=…` is the caller's own error whether or not bubblewrap
/// is installed, and it exits 2 either way; an app the project does not declare is not declared on
/// a host with no engines either. Deciding those before [`prepare_engines`] is what keeps the
/// diagnosis pointed at what the caller can fix, and keeps the documented exit code from depending
/// on what the machine happens to have installed.
struct PreparedConfig {
    layout: Layout,
    cwd: PathBuf,
    cfg: crate::config::Resolved,
}

fn prepare_config(cwd: PathBuf, ov: &crate::config::Override) -> Result<PreparedConfig, ExitCode> {
    // The data directory is resolved first: it is where sbx looks for (and, under the
    // bundled features, materializes) the engines it owns, so `resolve_bwrap` needs it.
    let Some(layout) = Layout::from_env() else {
        eprintln!(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)."
        );
        return Err(ExitCode::FAILURE);
    };
    let mut cfg = crate::config::load(&cwd);
    // The override's nixpkgs channel must land before the lock target is chosen. A set-but-invalid
    // channel is a hard error (no safe baseline fallback for a supply-chain field).
    if let Err(e) = cfg.apply_override_channel(ov) {
        crate::diag::error(&format!("sbx: {e}"));
        return Err(ExitCode::from(2));
    }
    // Reject a mistyped scalar security value (network/gui/limits) now — before the engines are
    // probed and before the expensive channel/userland resolution — so a typo aborts fast rather
    // than after a provision. The full override (this plus the additive fields) is applied at the
    // launch's final point.
    if let Err(errs) = cfg.validate_override(ov) {
        for e in errs {
            crate::diag::error(&format!("sbx: {e}"));
        }
        return Err(ExitCode::from(2));
    }
    Ok(PreparedConfig { layout, cwd, cfg })
}

/// The half that needs the host to be able to sandbox: the engines, the user namespace, and the
/// channel/userland resolution they drive.
///
/// `app` is the launch's identity only — it selects which lock the resolution runs against
/// ([`effective_lock_target`]), and nothing of the app's configuration is read here. A caller that
/// has already taken the app out of the configuration (as [`app`] does, to refuse an undeclared one
/// before reaching this point) therefore loses nothing by doing so.
fn prepare_engines(pc: PreparedConfig, app: Option<&str>) -> Result<Prepared, ExitCode> {
    let PreparedConfig { layout, cwd, cfg } = pc;
    let bwrap = match crate::store::try_resolve_bwrap(Some(&layout)) {
        Ok(choice) => choice.path,
        Err(miss) => return Err(unresolved_engine("bubblewrap (the sandbox engine)", &miss)),
    };
    if !matches!(crate::probe_userns(), crate::Userns::Ok) {
        crate::diag::error(
            "sbx: no capability-bearing user namespace — the sandbox cannot run. See `sbx doctor`.",
        );
        return Err(ExitCode::FAILURE);
    }
    // A cage is going to run, so this is where the scopes of the cages that already finished are
    // reclaimed. Every launch path reaches this function, and the sweep runs once per process.
    super::cgroup::sweep_stale_scopes();
    let nix = match crate::store::try_resolve_nix(Some(&layout)) {
        Ok(nix) => nix,
        Err(miss) => return Err(unresolved_engine("nix (the store engine)", &miss)),
    };
    let nix_store = match crate::store::try_resolve_nix_store(Some(&layout)) {
        Ok(bin) => bin,
        Err(miss) => {
            return Err(unresolved_engine(
                "nix-store (the store database tool)",
                &miss,
            ));
        }
    };

    let nixpkgs = match effective_lock_target(&cwd, &layout, &cfg, app)
        .and_then(|t| t.resolve(&nix, &layout))
    {
        Ok(r) => r,
        Err(e) => {
            crate::diag::error(&format!("sbx: cannot resolve the nixpkgs channel: {e}"));
            return Err(ExitCode::FAILURE);
        }
    };
    // The mise engine resolves against its own dedicated lock (the global channel source,
    // rolled independently by `sbx upgrade mise`), never this launch's possibly-pinned
    // base reference. Resolved *after* the base so its lock can be seeded from the base's
    // on first use (no network, and a binary update never bumps the engine — see
    // `resolve_engine_ref`). Threaded to both mise consumers: the in-cage engine (the base
    // userland) and the host-side `[env]` driver.
    let engine_ref = match crate::store::resolve_engine_ref(
        &nix,
        &layout,
        cfg.mise_engine.as_deref(),
        cfg.nixpkgs_global.as_deref(),
    ) {
        Ok(r) => r,
        Err(e) => {
            crate::diag::error(&format!("sbx: cannot resolve the mise engine channel: {e}"));
            return Err(ExitCode::FAILURE);
        }
    };
    let userland = match super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &engine_ref) {
        Ok(u) => u,
        Err(e) => {
            crate::diag::error(&format!("sbx: cannot resolve the sandbox userland: {e}"));
            return Err(ExitCode::FAILURE);
        }
    };
    Ok(Prepared {
        bwrap,
        nix,
        nix_store,
        layout,
        cwd,
        cfg,
        nixpkgs,
        engine_ref,
        userland,
        in_batch: false,
        unresolved_secret: crate::sandbox::egress::Unresolved::Abort,
    })
}

/// The single channel decision for a launch — the one place that picks "which source, which lock",
/// so the launch (resolve), `sbx upgrade` (refresh), and `sbx config` (display) all act on the same
/// lock and can never drift.
///
/// Three branches, in this order:
///
/// - **A trusted per-project `nixpkgs` pin wins, app or no app.** An app launch inherits the
///   baseline's packages (`Resolved::merge_app` overrides by name, it does not replace the list),
///   so the project's declared tools build in that launch too — and they must build from the
///   pinned revision or the pin promises nothing. This is also the one-channel rule: one launch,
///   one revision, base userland and tools alike.
/// - **Otherwise an app resolves against its own lock** ([`crate::store::LockTarget::app`]), so
///   `sbx upgrade nix --app <name>` moves one app and a global roll leaves it where it is. The
///   *source* is still not the app's to choose — `nixpkgs` under an app is a refused key — only the
///   resolution is frozen per app.
/// - **Otherwise the global channel**: a global-config override, else the default.
///
/// Only the pinned case canonicalises the project to derive its lock path, so the common no-pin
/// path does no extra work and a per-project lock is never even named without a current pin.
pub(crate) fn effective_lock_target(
    cwd: &Path,
    layout: &Layout,
    cfg: &crate::config::Resolved,
    app: Option<&str>,
) -> io::Result<crate::store::LockTarget> {
    match (cfg.nixpkgs_project.as_deref(), app) {
        (Some(source), _) => {
            let id = binds::project_runtime_id(cwd)?;
            Ok(crate::store::LockTarget::project(layout, &id, source))
        }
        (None, Some(name)) => {
            crate::store::LockTarget::app(layout, name, cfg.nixpkgs_global.as_deref())
        }
        (None, None) => Ok(crate::store::LockTarget::global(
            layout,
            cfg.nixpkgs_global.as_deref(),
        )),
    }
}

/// Seed (or top up) the project's own writable store with the closure of everything
/// the cage reads through `/nix`: the base userland, the native `[packages]`, and the
/// `nix:` tools. The roots are collected from the provisioners and handed as the single
/// source the seed copies and registers, so the cage runs from its own store and an
/// agent's writes land only there.
fn seed_project_store(
    prep: &Prepared,
    pkg_roots: &[PathBuf],
    tool_roots: &[PathBuf],
    font_roots: &[PathBuf],
) -> io::Result<super::projectstore::ProjectStore> {
    let (id, canonical) = binds::project_identity(&prep.cwd)?;
    let roots = collect_roots(&prep.userland, pkg_roots, tool_roots, font_roots);
    let store = super::projectstore::prepare(&prep.nix_store, &prep.layout, &id, &roots)?;
    // Record the project's canonical path so a later `sbx gc` can recognise this tree and reclaim
    // it once the project is gone. Best-effort: a housekeeping marker must never fail a launch.
    if let Err(e) = super::projectstore::write_marker(&prep.layout, &id, &canonical) {
        crate::diag::warn(&format!("could not record the project marker: {e}"));
    }
    Ok(store)
}

/// The complete set of logical store roots the cage resolves through `/nix`: the base
/// userland's roots, then the native `[packages]`, the `nix:` tools, and (under the GUI
/// hole) the fonts. Collected from the provisioners (never reconstructed by stripping
/// sub-paths), so the seed carries every closure the cage needs — a forgotten source would
/// silently make the cage re-fetch it. Pure, so the collection is unit-tested.
fn collect_roots(
    userland: &Userland,
    pkg_roots: &[PathBuf],
    tool_roots: &[PathBuf],
    font_roots: &[PathBuf],
) -> Vec<PathBuf> {
    let mut roots = userland.base_roots.clone();
    roots.extend(pkg_roots.iter().cloned());
    roots.extend(tool_roots.iter().cloned());
    roots.extend(font_roots.iter().cloned());
    roots
}

/// Provision a trusted project's declared `nix:` mise tools into sbx's store and report
/// the `bin` directories to prepend to PATH, plus warnings. Empty when the project
/// declares no mise file. An untrusted project's `nix:` tools are withheld (warned); a tool
/// for another backend is auto-equipped in-cage instead (see [`equip::auto_equip_tokens`]), not
/// host-provisioned here. A declared, admitted `nix:` tool that fails to resolve or realise
/// is fatal, like a native `[packages]` tool. Resolution is cached per project, so nixhub is
/// queried once per `(tool, version)` rather than on every launch.
///
/// The early return below skips the reconciliation of that project's `nix-tools/` gcroots, which
/// [`super::nixhub::provision`] performs and deliberately places ahead of *its* own
/// empty-declaration return. Both returns answer the same question one level apart, and only the
/// inner one is covered: dropping the last `nix:` tool still reconciles, while dropping the last
/// mise *file* (or the `.sbx.toml` mise is anchored on) leaves the project with no config to call
/// provisioning for at all, so its tool roots hold their closures until the project tree itself is
/// reaped.
///
/// Not simply hoisted, because reconciling needs the answer this return no longer has. Pruning is
/// for a trusted project — an untrusted one's roots are left alone, and `provision` returns before
/// its own reconcile for exactly that reason — and the project's mise trust verdict lives on the
/// [`crate::config::MiseConfig`] that is absent here. Closing it means carrying the project's trust
/// state on the resolved config in its own right; the trigger is a report of `nix:` closures held
/// by a project that still exists and declares nothing.
fn mise_tools(prep: &Prepared) -> Result<super::packages::Provisioned, ExitCode> {
    let Some(mise_cfg) = &prep.cfg.mise else {
        return Ok(super::packages::Provisioned {
            bins: Vec::new(),
            roots: Vec::new(),
            warnings: Vec::new(),
        });
    };
    super::nixhub::provision(
        &prep.nix,
        &prep.layout,
        &prep.cwd,
        &mise_cfg.files,
        mise_cfg.state == crate::trust::TrustState::Trusted,
        &super::nixhub::current_system(),
    )
    .map_err(|e| {
        crate::diag::error(&format!("sbx: {e}"));
        ExitCode::FAILURE
    })
}

/// The fatal line for an engine that did not resolve, saying which of the two things happened.
///
/// A refused override is not a missing engine: the binary is installed, at the path the variable
/// names, and pointing its owner at `sbx doctor` — which would report the same engine as "not
/// found" — sends them after a package they already have instead of the ownership or permissions
/// that were actually refused. The resolver has already printed that refusal with its remedy, so
/// this line states the consequence and does not repeat it.
fn unresolved_engine(what: &str, miss: &crate::store::EngineMiss) -> ExitCode {
    let tail = match miss {
        crate::store::EngineMiss::NotFound => " See `sbx doctor`.",
        crate::store::EngineMiss::Refused { .. } => "",
    };
    crate::diag::error(&format!(
        "sbx: {} — the sandbox cannot run.{tail}",
        miss.clause(what)
    ));
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests;
