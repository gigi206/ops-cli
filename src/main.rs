//! ops — sandbox launcher (bubblewrap + daemonless nix).
//!
//! The `doctor` preflight verifies the load-bearing runtime requirements before
//! anything else can run: capability-bearing unprivileged user namespaces (the
//! security boundary everything else rests on), the bubblewrap engine, and the
//! nix binary that drives the user-owned store. A missing load-bearing
//! requirement is a hard failure with remediation — never a silent fallback to
//! a weaker engine, because that would mean no security boundary at all.

mod allowlist;
mod config;
mod diag;
mod help;
mod pathfind;
mod plugin_store;
mod plugins;
mod sandbox;
mod session;
mod store;
mod stores;
mod style;
#[cfg(test)]
mod testutil;
mod trust;

use std::ffi::{OsStr, OsString};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    // `args_os`, not `args`: a command run via `ops run` may carry non-UTF-8
    // arguments, and panicking on them would be wrong.
    let mut args = std::env::args_os().skip(1);
    let cmd = args.next();
    let rest: Vec<OsString> = args.collect();
    let name = match cmd.as_deref().and_then(|s| s.to_str()) {
        // No command at all is a usage error; an explicit help request is not. Both render
        // the same command list — to stderr/exit 2 for the error, to stdout/exit 0 for help.
        None => {
            eprint!("{}", help::top_level_usage());
            return ExitCode::from(2);
        }
        Some("help" | "--help" | "-h") => return help::dispatch(rest),
        Some(name) => name,
    };

    // A known command carrying a help flag shows the page for the deepest command path it
    // names (so `ops plugins store add --help` lands on that page). `run` (which forwards
    // `--help` after a `--`) and `mise` (a passthrough) handle a leading help flag
    // themselves; an *unknown* command is left to the dispatch below, which names it and may
    // hint a subcommand parent.
    if help::is_command(name) && !matches!(name, "run" | "mise") {
        if let Some(code) = help::maybe_help(name, &rest) {
            return code;
        }
    }

    match name {
        "doctor" => doctor(),
        "shell" => sandbox::shell(),
        "ls" => list_sessions(),
        "attach" => attach_cmd(rest),
        "stop" => stop_cmd(rest),
        "trust" => trust_cmd(rest),
        "untrust" => untrust_cmd(rest.into_iter().next()),
        "config" => config_cmd(rest),
        "upgrade" => upgrade_cmd(rest),
        "gc" => gc_cmd(rest),
        "run" => {
            let mut cmd: Vec<OsString> = rest;
            // Leading ops flags before the command: `--detach` to run in the background,
            // `--help`/`-h` for this command's page, and an optional `--` separating ops's
            // arguments from the command's. The `--` is consumed before scanning the command,
            // so `ops run -- --detach` (or `-- --help`) runs the literal argument.
            let mut detach = false;
            while let Some(first) = cmd.first().and_then(|a| a.to_str()) {
                match first {
                    "--detach" => {
                        detach = true;
                        cmd.remove(0);
                    }
                    "--help" | "-h" => return help::show(&["run"]),
                    "--" => {
                        cmd.remove(0);
                        break;
                    }
                    _ => break,
                }
            }
            sandbox::run(cmd, detach)
        }
        "mise" => {
            // A passthrough, so a help flag is only ops's when it leads: `ops mise --help`
            // shows ops's page, while `ops mise help` (and any later `--help`) reaches the
            // in-cage mise's own help.
            if matches!(rest.first().and_then(|a| a.to_str()), Some("--help" | "-h")) {
                return help::show(&["mise"]);
            }
            sandbox::run_mise(rest)
        }
        "app" => app_cmd(rest),
        "search" => search_cmd(rest),
        "test" => test_cmd(rest),
        "plugins" => plugins_cmd(rest),
        other => {
            eprintln!("ops: unknown command '{other}'");
            if let Some(path) = help::subcommand_hint(other) {
                eprintln!("       did you mean `{path}`?");
            }
            eprintln!("Run `ops --help` for the list of commands.");
            ExitCode::from(2)
        }
    }
}

/// Remediation for a missing capability-bearing user namespace — the boundary
/// the whole sandbox rests on. Distro-dependent and needs root once.
const USERNS_REMEDIATION: &str = "enable capability-bearing unprivileged user namespaces \
(no security boundary without them; no fallback): \
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, \
or an AppArmor profile allowing unprivileged userns for ops";

/// Remediation when the namespace itself is fine but a real launch still failed —
/// the fault is the engine, not the boundary.
const BWRAP_LAUNCH_REMEDIATION: &str = "bubblewrap is installed and user namespaces work, \
but launching a sandbox failed — check that bubblewrap is built to use unprivileged user \
namespaces (not a setuid helper) and review the messages above";

/// Report the runtime prerequisites and fail hard if a load-bearing one is
/// missing. Each failing check contributes its own remediation hint, so the
/// summary never points at the wrong cause.
/// A colored `[ ok ]` status tag (green when the stream is a terminal, plain otherwise).
fn tag_ok(p: &style::Palette) -> String {
    format!("{}[ ok ]{}", p.ok, p.reset)
}

/// A colored `[warn]` status tag (yellow when colored).
fn tag_warn(p: &style::Palette) -> String {
    format!("{}[warn]{}", p.warn, p.reset)
}

/// A colored `[FAIL]` status tag (bold red when colored).
fn tag_fail(p: &style::Palette) -> String {
    format!("{}[FAIL]{}", p.err, p.reset)
}

fn doctor() -> ExitCode {
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, r) = (pal.head, pal.reset);
    println!("{h}ops doctor{r} — runtime preflight\n");

    let mut remediation: Vec<&str> = Vec::new();

    // The data directory, resolved once and reused for the engines and the store/channel
    // report below. Read-only in that it derives paths from the environment; resolving the
    // engines may materialize one ops ships (the bundled-* builds), which is intended.
    let layout = store::Layout::from_env();

    // The sandbox engine itself. Hold the choice: a present engine is what lets the
    // boundary be proven by a real launch rather than a stand-in, and its source explains
    // which `bwrap` ran and why — the bundled engine, the host's, or an override.
    let bwrap = store::resolve_bwrap(layout.as_ref());
    match &bwrap {
        Some(c) => {
            println!("  {} bubblewrap        {}", tag_ok(&pal), c.path.display());
            let note = if c.apparmor_restricted {
                " — AppArmor userns restriction active (host engine required)"
            } else {
                ""
            };
            println!(
                "         {dim}· {}{note}{r}",
                c.source.label(),
                dim = pal.dim
            );
        }
        None => {
            println!("  {} bubblewrap        not found", tag_fail(&pal));
            remediation.push("install bubblewrap (the sandbox engine)");
        }
    }

    // The security boundary, proven the way ops actually uses it: a real bwrap
    // launch through the argv builder. A hardened process (CapEff=0,
    // NoNewPrivs=1) proves the user namespace is capability-bearing more
    // conclusively than a raw `unshare` can — bubblewrap cannot nest its
    // namespaces on a cap-stripped one. The `unshare` stand-in survives only to
    // classify a failure (and as the fast gate the launch path uses). The
    // sysctls below are advisory context for the remediation hint.
    report_security_boundary(
        &pal,
        bwrap.as_ref().map(|c| c.path.as_path()),
        &mut remediation,
    );
    if let Some(v) = read_sysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") {
        println!(
            "         {dim}· kernel.apparmor_restrict_unprivileged_userns = {v}{r}",
            dim = pal.dim
        );
    }
    if let Some(v) = read_sysctl("/proc/sys/kernel/unprivileged_userns_clone") {
        println!(
            "         {dim}· kernel.unprivileged_userns_clone = {v}{r}",
            dim = pal.dim
        );
    }
    report_resource_limits(&pal, &config::global_limits());

    // The nix that drives the store. Its absence is load-bearing too — without
    // nix, ops cannot provision a project's tools. Resolution is read-only here
    // (override, then an ops-owned engine, then `PATH`), so doctor writes nothing.
    match store::resolve_nix(layout.as_ref()) {
        Some(nix) => {
            println!("  {} nix               {}", tag_ok(&pal), nix.display());
            if let Some(v) = nix_version(&nix) {
                println!("         {dim}· {v}{r}", dim = pal.dim);
            }
        }
        None => {
            println!("  {} nix               not found", tag_fail(&pal));
            remediation.push("install nix (the store engine ops drives daemonlessly)");
        }
    }

    // git fetches a remote plugin store (`ops plugins store add`). It is not on the launch
    // path — a sandbox runs without it — so its absence is a feature gap reported for
    // context, never a boundary failure that blocks `ops run`.
    match store::resolve_git() {
        Some(git) => println!("  {} git               {}", tag_ok(&pal), git.display()),
        None => println!(
            "  {} git               not found on PATH — needed only for `ops plugins store`",
            tag_warn(&pal)
        ),
    }

    // Where the user-owned store lives, and which channel revision it is pinned to.
    // Both are reported read-only: ops creates the store lazily on first use and
    // seeds the channel lock on first launch, so their absence here is informational,
    // not a failure. The channel state is the host-level global lock (doctor has no
    // project context), shown straight from disk.
    match layout.as_ref() {
        Some(layout) => {
            let dir = layout.store_dir();
            let state = if dir.is_dir() {
                "present"
            } else {
                "absent — created on first use"
            };
            println!(
                "  {} store             {} ({state})",
                tag_ok(&pal),
                dir.display()
            );
            match store::read_global_lock(layout) {
                Some((source, rev)) => println!(
                    "  {} channel           {source} @ {} (locked)",
                    tag_ok(&pal),
                    short_rev(&rev)
                ),
                None => {
                    println!(
                        "  {} channel           not yet resolved — seeded on first launch",
                        tag_ok(&pal)
                    )
                }
            }
        }
        None => {
            println!(
                "  {} store             unresolved (no $HOME or $XDG_DATA_HOME)",
                tag_warn(&pal)
            );
            println!(
                "  {} channel           unresolved (no data directory)",
                tag_warn(&pal)
            );
        }
    }

    println!();
    if remediation.is_empty() {
        println!("ops: prerequisites OK.");
        ExitCode::SUCCESS
    } else {
        let epal = style::Palette::for_stream(std::io::stderr().is_terminal());
        eprintln!(
            "{}ops: missing prerequisite(s) — ops CANNOT run until these are resolved:{}",
            epal.err, epal.reset
        );
        for hint in remediation {
            eprintln!("       {}•{} {hint}", epal.err, epal.reset);
        }
        ExitCode::FAILURE
    }
}

/// Report best-effort cgroup v2 resource limiting (anti-DoS). Unlike the security
/// boundary, resource limits are hardening: where they cannot be applied the cage
/// still runs, so an unavailable limiter is reported for context and never
/// recorded as a missing prerequisite. The probe launches a real transient scope,
/// so a green line means limiting actually works on this host.
fn report_resource_limits(pal: &style::Palette, limits: &sandbox::cgroup::Limits) {
    // Reflect the *global* config's limits — they apply to every launch regardless of project,
    // and the live probe validates them, so a bad global value surfaces here. A trusted project
    // may further tune them per project; `ops config` is the project-aware view.
    let report: sandbox::LimitReport = sandbox::resource_limits(limits);
    if report.verified {
        println!(
            "  {} resource limits   cage capped via a systemd scope ({})",
            tag_ok(pal),
            report.properties.join(", ")
        );
    } else if let Some(note) = report.note {
        println!("  {} resource limits   {note}", tag_warn(pal));
    }
}

/// Report the security boundary. When bubblewrap is present, a real launch
/// decides the green path and the `unshare` stand-in does not run at all. On
/// failure — or when there is no engine to launch — the stand-in classifies the
/// cause so the report blames the right layer and never the wrong one.
fn report_security_boundary(
    pal: &style::Palette,
    bwrap: Option<&Path>,
    remediation: &mut Vec<&'static str>,
) {
    let (dim, r) = (pal.dim, pal.reset);
    let Some(bwrap) = bwrap else {
        // No engine to launch: the stand-in is the only available signal for the
        // boundary. Report it for context (the missing-engine remediation is
        // already recorded), and still flag a broken namespace as its own fault.
        match probe_userns() {
            Userns::Ok => println!(
                "         {dim}· user namespaces: capability-bearing (cannot prove without bubblewrap){r}"
            ),
            other => classify_namespace_failure(pal, other, remediation),
        }
        return;
    };

    match sandbox::smoke(bwrap) {
        Ok(report) if report.is_hardened() => {
            println!(
                "  {} sandbox           bubblewrap launched a hardened process",
                tag_ok(pal)
            );
            println!(
                "         {dim}· user namespaces: capability-bearing — proven by the launch{r}"
            );
            println!("         {dim}· no_new_privs set, every capability dropped{r}");
            if report.host_home_absent {
                println!("         {dim}· host $HOME absent — the bind layout did not leak it{r}");
            } else {
                println!(
                    "         {dim}· note: the host $HOME was visible inside the probe sandbox{r}"
                );
            }
        }
        Ok(report) => classify_launch_failure(pal, Some(&report.stderr), remediation),
        Err(e) => {
            // The probe could not even spawn bwrap; surface why, then classify.
            println!("         {dim}· could not run the launch probe: {e}{r}");
            classify_launch_failure(pal, None, remediation);
        }
    }
}

/// A real launch did not yield a hardened process. A capability-bearing namespace
/// means the engine itself failed, so blame bubblewrap and surface its own
/// diagnosis; otherwise the namespace is the cause and is classified as such.
fn classify_launch_failure(
    pal: &style::Palette,
    bwrap_stderr: Option<&str>,
    remediation: &mut Vec<&'static str>,
) {
    let (dim, r) = (pal.dim, pal.reset);
    match probe_userns() {
        Userns::Ok => {
            println!(
                "  {} sandbox           bubblewrap could not launch a hardened process",
                tag_fail(pal)
            );
            println!("         {dim}· user namespaces: capability-bearing (the failure is in bubblewrap, not the namespace){r}");
            for line in bwrap_stderr
                .unwrap_or_default()
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .take(3)
            {
                println!("         {dim}· {line}{r}");
            }
            remediation.push(BWRAP_LAUNCH_REMEDIATION);
        }
        other => classify_namespace_failure(pal, other, remediation),
    }
}

/// Report a user namespace that cannot bear the capabilities bubblewrap needs,
/// distinguishing outright absence from the capability-stripped case so the
/// remediation points at the real cause. The caller has already established the
/// namespace is not `Ok`.
fn classify_namespace_failure(
    pal: &style::Palette,
    userns: Userns,
    remediation: &mut Vec<&'static str>,
) {
    let fail = tag_fail(pal);
    match userns {
        Userns::Unsupported => {
            println!("  {fail} user namespaces   cannot create one without privilege");
        }
        Userns::CapStripped => {
            println!(
                "  {fail} user namespaces   created but stripped of capabilities (restricted)"
            );
        }
        // The caller only reaches here with a non-`Ok` namespace; a transient
        // flip to `Ok` is still a failure to launch, so it is flagged, not hidden.
        Userns::Ok => println!("  {fail} user namespaces   transient namespace probe failure"),
    }
    remediation.push(USERNS_REMEDIATION);
}

/// `ops ls`: list the live sandbox sessions from the on-disk registry. Reading
/// the registry re-validates and prunes dead records as a side effect, so the
/// list is always current without a daemon.
fn list_sessions() -> ExitCode {
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("ops: cannot resolve the data directory (no $HOME or $XDG_DATA_HOME).");
        return ExitCode::FAILURE;
    };
    let sessions = match session::Registry::at(layout.data_dir()).list() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ops: cannot read the session registry: {e}");
            return ExitCode::FAILURE;
        }
    };
    if sessions.is_empty() {
        println!("ops: no active sandbox sessions.");
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, r) = (pal.head, pal.name, pal.reset);
    // The header is padded first, then wrapped, so the color spans never count toward the
    // column widths and the alignment is identical with or without color.
    let header = format!("{:<14}  {:>8}  {:>8}  PROJECT", "KIND", "PID", "AGE");
    println!("{h}{header}{r}");
    let uptime = uptime_seconds();
    let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    for s in &sessions {
        let age = match uptime {
            Some(up) if ticks_per_sec > 0 => {
                let started = s.start_ticks as f64 / ticks_per_sec as f64;
                format_age((up - started).max(0.0) as u64)
            }
            _ => "?".to_string(),
        };
        // An app session shows its app name (`app:<name>`), so the user can tell which sessions are
        // agents — and that `ops attach`/`ops stop` act on that app's isolated environment. The
        // label is padded before coloring so the spans do not disturb the column width.
        let label = format!("{:<14}", s.label());
        println!(
            "{n}{label}{r}  {:>8}  {:>8}  {}",
            s.pid,
            age,
            s.project.display()
        );
    }
    ExitCode::SUCCESS
}

/// `ops attach <id>`: open a shell in a running session's environment. Exactly one operand — the
/// PID `ops ls` shows. A missing, extra, or non-UTF-8 operand is a usage error; a well-formed id
/// that matches no live session is reported by `attach` itself.
fn attach_cmd(args: Vec<OsString>) -> ExitCode {
    let Some(id) = (args.len() == 1).then(|| args[0].to_str()).flatten() else {
        eprintln!(
            "ops: usage: {}   (the PID shown by `ops ls`)",
            help::synopsis("attach")
        );
        return ExitCode::from(2);
    };
    sandbox::attach(id)
}

/// The default grace period between SIGTERM and SIGKILL for `ops stop`: long enough for an agent to
/// finish writing and shut down cleanly, short enough not to hang. `--delay` overrides it.
const STOP_DEFAULT_DELAY: Duration = Duration::from_secs(10);

/// `ops stop <id>... [--delay <secs>]` / `ops stop --all [--delay <secs>]`: stop running sessions.
/// With ids, stop the named ones (the pids `ops ls` shows); with `--all`, stop every live session.
/// Sends SIGTERM, then SIGKILL after the grace delay (default 10s; `--delay 0` escalates at once).
/// Either ids or `--all` is required (not both); a non-UTF-8 operand or a malformed `--delay` value
/// is a usage error.
fn stop_cmd(args: Vec<OsString>) -> ExitCode {
    let mut delay = STOP_DEFAULT_DELAY;
    let mut all = false;
    let mut ids: Vec<String> = Vec::new();
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--delay") => {
                let Some(value) = it.next() else {
                    eprintln!("ops: --delay needs a value in seconds (e.g. --delay 10).");
                    return ExitCode::from(2);
                };
                match value.to_str().and_then(|v| v.parse::<u64>().ok()) {
                    Some(secs) => delay = Duration::from_secs(secs),
                    None => {
                        eprintln!(
                            "ops: --delay must be a whole number of seconds, not '{}'.",
                            value.to_string_lossy()
                        );
                        return ExitCode::from(2);
                    }
                }
            }
            Some("--all") => all = true,
            Some(id) => ids.push(id.to_string()),
            None => {
                eprintln!("ops: stop ids must be valid text (the PID shown by `ops ls`).");
                return ExitCode::from(2);
            }
        }
    }
    if all && !ids.is_empty() {
        eprintln!("ops: stop takes either explicit ids or --all, not both.");
        return ExitCode::from(2);
    }
    if !all && ids.is_empty() {
        eprintln!(
            "ops: usage: {}\n   (ids are the PIDs shown by `ops ls`)",
            help::synopsis("stop")
        );
        return ExitCode::from(2);
    }
    let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    sandbox::stop(&id_refs, delay, all)
}

/// The config path an `ops trust`/`untrust` invocation targets: the given path,
/// or the project `.ops.toml` in the current directory by default.
fn config_path_arg(arg: Option<OsString>) -> std::path::PathBuf {
    arg.map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(".ops.toml"))
}

/// Resolve the trust store directory or report why it cannot be located. The
/// absolute-path requirement is a security control (a relative base could let a
/// cloned repo pre-approve itself), so an unresolved store is a hard failure.
fn trust_store_dir() -> Result<std::path::PathBuf, ExitCode> {
    trust::default_store_dir().ok_or_else(|| {
        eprintln!(
            "ops: cannot locate the trust store — set HOME or XDG_STATE_HOME to an absolute path."
        );
        ExitCode::FAILURE
    })
}

/// `ops trust [path]` vouches for a project config's current contents;
/// `ops trust --show [path]` reports its trust state without changing it.
fn trust_cmd(args: Vec<OsString>) -> ExitCode {
    let mut args = args.into_iter();
    let first = args.next();
    if first.as_deref().and_then(|s| s.to_str()) == Some("--show") {
        return show_trust(config_path_arg(args.next()));
    }
    record_trust(config_path_arg(first))
}

/// Record trust for a config's current contents, so its security-relevant fields
/// are honored until the file changes again.
fn record_trust(path: std::path::PathBuf) -> ExitCode {
    let store_dir = match trust_store_dir() {
        Ok(d) => d,
        Err(code) => return code,
    };
    match trust::trust(&store_dir, &path) {
        Ok(()) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_trust_recorded(&path, &pal));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ops: cannot trust {}: {e}", path.display());
            ExitCode::FAILURE
        }
    }
}

/// The confirmation line for a recorded trust — the resulting `trusted` state word in green,
/// matching how `ops trust --show` renders that state. A pure presenter (its colored layout is
/// asserted in a test); every span is empty under a non-terminal.
fn render_trust_recorded(path: &Path, pal: &style::Palette) -> String {
    format!("ops: {}trusted{} {}", pal.ok, pal.reset, path.display())
}

/// Report a config's current trust state. A query never changes anything, so it
/// succeeds whatever the state — the verdict is the message, not the exit code.
fn show_trust(path: std::path::PathBuf) -> ExitCode {
    let store_dir = match trust_store_dir() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let state = trust::state(&store_dir, &path);
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    println!("{}", render_trust_verdict(&path, state, &pal));
    ExitCode::SUCCESS
}

/// Render a trust verdict — a pure presenter (so its colored layout is asserted in a test). The
/// state word carries the conventional hue: `trusted` green, `untrusted` yellow (the default
/// state, security fields simply not applied — a caution, not an error), and `changed` red (it
/// was trusted and has since drifted, so re-approval is needed). Only the state word is colored;
/// the re-approval hint stays plain. Every span is empty under a non-terminal.
fn render_trust_verdict(path: &Path, state: trust::TrustState, pal: &style::Palette) -> String {
    let (ok, warn, err, r) = (pal.ok, pal.warn, pal.err, pal.reset);
    let verdict = match state {
        trust::TrustState::Trusted => format!("{ok}trusted{r}"),
        trust::TrustState::Untrusted => format!("{warn}untrusted{r}"),
        trust::TrustState::Changed => {
            format!("{err}changed{r} since it was trusted — re-run `ops trust` to re-approve")
        }
    };
    format!("ops: {} is {verdict}", path.display())
}

/// `ops untrust [path]`: revoke a project config's trust, so its security-relevant
/// fields stop applying until it is trusted again.
fn untrust_cmd(arg: Option<OsString>) -> ExitCode {
    let path = config_path_arg(arg);
    let store_dir = match trust_store_dir() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let result = match trust::untrust(&store_dir, &path) {
        Ok(existed) => existed,
        Err(e) => {
            eprintln!("ops: cannot revoke trust for {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    println!("{}", render_untrust_result(&path, result, &pal));
    ExitCode::SUCCESS
}

/// The confirmation line for `ops untrust`. When a marker existed it is revoked — the result is
/// the untrusted default, so `revoked` takes the caution hue that `--show` gives that state; when
/// none existed it is a benign no-op, with the note dimmed. A pure presenter, asserted in a test.
fn render_untrust_result(path: &Path, existed: bool, pal: &style::Palette) -> String {
    if existed {
        format!(
            "ops: {}revoked{} trust for {}",
            pal.warn,
            pal.reset,
            path.display()
        )
    } else {
        format!(
            "ops: {} was not trusted; {}nothing to revoke{}",
            path.display(),
            pal.dim,
            pal.reset
        )
    }
}

/// `ops config [--json]` and the management verbs `get`/`set`/`unset`/`path`. With no verb it
/// shows the resolved configuration for the current project — the layered global + project
/// environment and read-only binds, after the trust gate has dropped anything an untrusted
/// project may not set. The human form renders a colored document with warnings on stderr;
/// `--json` prints the same resolved model as a JSON document. The verbs read and edit a single
/// raw layer file (the project `.ops.toml`, the global config, or an explicit path).
fn config_cmd(args: Vec<OsString>) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("show") => config_show(&args[1..]),
        Some("get") => config_get(&args[1..]),
        Some("set") => config_set(&args[1..]),
        Some("unset") => config_unset(&args[1..]),
        Some("path") => config_path_cmd(&args[1..]),
        Some("edit") => config_edit(&args[1..]),
        // No subcommand — or an unknown one. Print the config page (which lists the subcommands)
        // to stderr and exit non-zero, so `ops config` reveals `show`/`get`/… instead of silently
        // doing one of them. Mirrors the no-command usage of bare `ops`.
        other => {
            match other {
                // The old `ops config --json` muscle memory: the resolved view (and its --json) is
                // now `show`, so point straight at it. Other flags belong to a specific subcommand
                // (get/set/… take -c/--local/--trust), so name no verb and let the page below guide.
                Some("--json") => {
                    eprintln!("ops: config: --json is now `ops config show --json`")
                }
                Some(tok) if tok.starts_with('-') => eprintln!(
                    "ops: config: {tok:?} is an option of a subcommand — pick one from the list below"
                ),
                Some(tok) => eprintln!("ops: config: unknown subcommand {tok:?}"),
                None => {}
            }
            eprint!("{}", help::page_usage(&["config"]).unwrap_or_default());
            ExitCode::from(2)
        }
    }
}

/// `ops config show [--json]`: show the resolved configuration for the current project — the
/// layered, trust-gated view a launch would use. The human render is colored when stdout is a
/// terminal; `--json` emits the whole resolved model for tooling.
/// Record a chosen single-source `config show` view flag (`--global`/`--local`/`--default`),
/// rejecting a second, conflicting one — two different sources is a user error, not last-wins. The
/// same flag repeated is harmless. On conflict, prints the usage and returns the usage exit code.
fn set_show_source(
    current: &mut Option<(&'static str, config::Source)>,
    flag: &'static str,
    source: config::Source,
) -> Result<(), ExitCode> {
    match current {
        Some((prev, _)) if *prev == flag => Ok(()),
        Some((prev, _)) => {
            eprintln!("ops: config show: `{flag}` conflicts with `{prev}` (choose one source)");
            eprintln!("ops: usage: {}", help::synopsis_of(&["config", "show"]));
            Err(ExitCode::from(2))
        }
        None => {
            *current = Some((flag, source));
            Ok(())
        }
    }
}

fn config_show(args: &[OsString]) -> ExitCode {
    let mut json = false;
    let mut details = false;
    let mut app: Option<String> = None;
    let mut source: Option<(&'static str, config::Source)> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--json") => json = true,
            Some("--details") => details = true,
            Some("--app") | Some("-a") => match it.next() {
                Some(name) => app = Some(name.to_string_lossy().into_owned()),
                None => {
                    eprintln!("ops: config show: `--app` needs an app name");
                    eprintln!("ops: usage: {}", help::synopsis_of(&["config", "show"]));
                    return ExitCode::from(2);
                }
            },
            Some("--global") | Some("-g") => {
                if let Err(code) = set_show_source(&mut source, "--global", config::Source::Global)
                {
                    return code;
                }
            }
            Some("--local") | Some("-l") => {
                if let Err(code) = set_show_source(&mut source, "--local", config::Source::Local) {
                    return code;
                }
            }
            Some("--default") | Some("-d") => {
                if let Err(code) =
                    set_show_source(&mut source, "--default", config::Source::Default)
                {
                    return code;
                }
            }
            _ => {
                eprintln!(
                    "ops: config show: unexpected argument {:?}",
                    arg.to_string_lossy()
                );
                eprintln!("ops: usage: {}", help::synopsis_of(&["config", "show"]));
                return ExitCode::from(2);
            }
        }
    }

    // A per-app view is inherently the app's effective configuration over the *full* baseline, so a
    // single-source restriction is meaningless there — reject the combination rather than silently
    // ignoring one flag.
    if app.is_some() {
        if let Some((flag, _)) = source {
            eprintln!("ops: config show: `--app` does not combine with `{flag}`");
            eprintln!("ops: usage: {}", help::synopsis_of(&["config", "show"]));
            return ExitCode::from(2);
        }
    }

    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: cannot read the current directory: {e}");
            return ExitCode::FAILURE;
        }
    };

    // `--app <name>` focuses on one app's *effective* configuration with provenance, instead of the
    // whole resolved baseline.
    if let Some(name) = app {
        return config_show_app(&cwd, &name, json, details);
    }

    // A source flag restricts the view to that one layer (over the built-in defaults); with none,
    // the full layered configuration is shown.
    let view = match source {
        Some((_, src)) => config::view::build_scoped(&cwd, src),
        None => config::view::build(&cwd),
    };

    if json {
        // The whole resolved model, warnings and all, as one JSON document — already exhaustive
        // (every app's rules in full), so `--details` is moot here whatever order the flags came.
        // Nothing goes to stderr — stdout stays pure JSON, the contract a consuming tool relies on.
        match serde_json::to_string_pretty(&view) {
            Ok(doc) => println!("{doc}"),
            Err(e) => {
                eprintln!("ops: cannot serialize the configuration: {e}");
                return ExitCode::FAILURE;
            }
        }
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_config(&view, &pal, details));
    // Warnings go to stderr, out of band from the resolved view, so the body stays a clean
    // capturable document and a warning never pollutes a piped human render.
    for w in &view.warnings {
        diag::warn(w);
    }
    ExitCode::SUCCESS
}

/// Render one app's effective configuration with provenance — the `config show --app <name>` path.
/// Errors (listing the declared apps) when no such app exists.
fn config_show_app(cwd: &Path, name: &str, json: bool, details: bool) -> ExitCode {
    let Some(view) = config::view::build_app_detail(cwd, name) else {
        eprintln!("ops: config show: no app named {name:?}");
        let declared: Vec<String> = config::view::build(cwd)
            .apps
            .into_iter()
            .map(|a| a.name)
            .collect();
        if declared.is_empty() {
            eprintln!("ops: no apps are declared for this directory");
        } else {
            eprintln!("ops: declared apps: {}", declared.join(", "));
        }
        return ExitCode::FAILURE;
    };

    if json {
        match serde_json::to_string_pretty(&view) {
            Ok(doc) => println!("{doc}"),
            Err(e) => {
                eprintln!("ops: cannot serialize the app configuration: {e}");
                return ExitCode::FAILURE;
            }
        }
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_app_detail(&view, &pal, details));
    ExitCode::SUCCESS
}

/// Render the resolved configuration for display — a pure presenter over [`config::view`]. It
/// adds only color and layout, so the management core stays presentation-agnostic and a future
/// front-end can render the same model differently. Every color span is empty under a
/// non-terminal, so captured output is byte-for-byte the plain text the integration tests pin.
/// The ` (default)` / ` (global)` / ` (project)` / ` (inherited)` provenance tag a line carries,
/// hued by level so a configured source stands out (global cyan, project green) while a built-in
/// default or an inherited baseline value stays dim. The *label text* is always emitted — color is
/// additive and (like every span) vanishes under a non-terminal — so captured output keeps the
/// bare `(global)` the integration tests pin.
fn provenance_tag(origin: config::view::ProvenanceView, pal: &style::Palette) -> String {
    let (label, span) = provenance_parts(origin, pal);
    format!("  {span}({label}){r}", r = pal.reset)
}

/// The label and color span for a provenance level — the one place the level→hue mapping lives, so
/// the end-of-line [`provenance_tag`] and any inline use (the per-field `limits` cells) cannot
/// drift. A configured source is hued (global cyan, project green); a default or inherited value
/// stays dim.
fn provenance_parts(
    origin: config::view::ProvenanceView,
    pal: &style::Palette,
) -> (&'static str, &'static str) {
    use config::view::ProvenanceView;
    match origin {
        ProvenanceView::Default => ("default", pal.dim),
        ProvenanceView::Global => ("global", pal.name),
        ProvenanceView::Project => ("project", pal.ok),
        ProvenanceView::Inherited => ("inherited", pal.dim),
    }
}

/// The provenance tag for a field in the per-app detail view, hued by the same level scale but
/// labelled in the app's vocabulary: a value the app declaration set reads `app:global`/`app:project`
/// (not the baseline `global`/`project`), one it left to the baseline reads `inherited`.
fn app_provenance_tag(origin: config::view::ProvenanceView, pal: &style::Palette) -> String {
    let (label, span) = app_provenance_parts(origin, pal);
    format!("  {span}({label}){r}", r = pal.reset)
}

/// The label and color span for a provenance level in the per-app view — the one place the app
/// vocabulary lives (so the inline `limits` cells and the end-of-line tag cannot drift). Same hues
/// as [`provenance_parts`]: a configured source is cyan/green, a default or inherited value dim.
fn app_provenance_parts(
    origin: config::view::ProvenanceView,
    pal: &style::Palette,
) -> (&'static str, &'static str) {
    use config::view::ProvenanceView;
    match origin {
        ProvenanceView::Default => ("default", pal.dim),
        ProvenanceView::Global => ("app:global", pal.name),
        ProvenanceView::Project => ("app:project", pal.ok),
        ProvenanceView::Inherited => ("inherited", pal.dim),
    }
}

/// The provenance tag for an optional origin — the free fields (`env`/`binds`) whose value may
/// carry no recorded layer. Empty when the origin is unknown.
fn opt_provenance_tag(
    origin: Option<config::view::ProvenanceView>,
    pal: &style::Palette,
) -> String {
    origin.map_or_else(String::new, |o| provenance_tag(o, pal))
}

fn render_config(view: &config::view::ConfigView, pal: &style::Palette, details: bool) -> String {
    use config::view::{AppNetworkView, GuiView, LimitView, NetworkView};
    use std::fmt::Write as _;
    let (h, n, ok, warn, dim, r) = (pal.head, pal.name, pal.ok, pal.warn, pal.dim, pal.reset);
    let mut o = String::new();

    // The hue carries the layering story the model already holds: a section header is bold, an
    // identifier (a key, a path, a rule, a channel) rides the name span, a value the trust gate
    // *withheld* is yellow while an admitted one's detail is dimmed, and every value's provenance
    // tag is hued by level — a built-in default gray, a global source cyan, a project source green
    // — so where a value came from reads at a glance. None of this is new data; it is the gating
    // outcome and the per-value origin made visible. Every span is empty under a non-terminal, so
    // captured output stays byte-for-byte the plain text the integration tests pin.
    let _ = writeln!(o, "{h}ops config{r} — resolved for {n}{}{r}", view.cwd);

    // The layered environment and read-only binds, after the trust gate.
    if view.env.is_empty() {
        let _ = writeln!(o, "  {h}env:{r}   {dim}(none){r}");
    } else {
        let _ = writeln!(o, "  {h}env:{r}");
        for e in &view.env {
            let _ = writeln!(
                o,
                "    {n}{}{r}={}{}",
                e.key,
                e.value,
                opt_provenance_tag(e.layer, pal)
            );
        }
    }
    if view.binds.is_empty() {
        let _ = writeln!(o, "  {h}binds:{r} {dim}(none){r}");
    } else {
        let _ = writeln!(o, "  {h}binds (read-only):{r}");
        for b in &view.binds {
            let _ = writeln!(
                o,
                "    {n}{}{r}{}",
                b.path,
                opt_provenance_tag(b.layer, pal)
            );
        }
    }

    // Declared tools, each with its backend and trust verdict — the launcher's decision, shown
    // without realising anything (no nix, no network). A withheld package's reason is yellow (the
    // trust gate dropped it); an admitted one's realisation detail is dimmed.
    if view.packages.is_empty() {
        let _ = writeln!(o, "  {h}packages:{r} {dim}(none){r}");
    } else {
        let _ = writeln!(o, "  {h}packages:{r}");
        for p in &view.packages {
            let _ = writeln!(o, "{}", package_line(p, pal, "    "));
        }
    }

    // The project's mise file and whether it would be honored — a tool source gated like
    // `packages`, reported as presence + verdict (no mise run). Trusted is green (it applies);
    // withheld is yellow.
    match &view.mise {
        None => {
            let _ = writeln!(o, "  {h}mise:{r}  {dim}(none){r}");
        }
        Some(m) if m.trusted => {
            let _ = writeln!(o, "  {h}mise:{r}  {n}{}{r} {ok}(trusted){r}", m.name);
        }
        Some(m) => {
            let _ = writeln!(
                o,
                "  {h}mise:{r}  {n}{}{r} {warn}(withheld: {}){r}",
                m.name,
                m.withheld_reason.as_deref().unwrap_or_default()
            );
        }
    }

    // The tools that file declares — parsed only. `nix:` tools carry the file's trust; a
    // non-`nix:` tool is equipped in-cage (so honored regardless of trust) unless `network =
    // "none"` prevents the fetch; a malformed `nix:` token is shown so it is not silently absent.
    if !view.tools.is_empty() {
        let _ = writeln!(o, "  {h}tools:{r}");
        for t in &view.tools.nix {
            match &t.withheld_reason {
                Some(reason) => {
                    let _ = writeln!(
                        o,
                        "    {n}nix:{}{r} = {}  {warn}(withheld: {reason}){r}",
                        t.pkg, t.version
                    );
                }
                None => {
                    let _ = writeln!(o, "    {n}nix:{}{r} = {}", t.pkg, t.version);
                }
            }
        }
        for t in &view.tools.non_nix {
            if t.equipped {
                let _ = writeln!(
                    o,
                    "    {n}{}{r} = {}  {dim}(equipped in-cage via mise){r}",
                    t.token, t.version
                );
            } else {
                let _ = writeln!(
                    o,
                    "    {n}{}{r} = {}  {warn}(needs network — not equipped under \
                     `network = \"none\"`){r}",
                    t.token, t.version
                );
            }
        }
        for token in &view.tools.malformed {
            let _ = writeln!(o, "    {token}  {warn}(ignored: malformed nix: token){r}");
        }
    }

    // The nixpkgs source the tools resolve against and its locked revision, then the mise
    // engine's own channel — shown so the engine's decoupling from the base channel is visible.
    // Routed through the launch's own channel decision; an unlocked source omits the revision.
    let _ = writeln!(o, "  {h}nixpkgs:{r} {}", channel_text(&view.nixpkgs, pal));
    let _ = writeln!(o, "  {h}engine:{r} {}", channel_text(&view.engine, pal));

    // The network posture — a security field. `shared` keeps the host network; `none` cuts it
    // off; an `allowlist` lists exactly what egress is permitted (deny wins over allow), plus the
    // always-allowed nix-cache set so the self-equip allowance is never silent.
    let net_tag = provenance_tag(view.network_origin, pal);
    match &view.network {
        NetworkView::Shared => {
            let _ = writeln!(o, "  {h}network:{r} shared {dim}(host network){r}{net_tag}");
        }
        NetworkView::Isolated => {
            let _ = writeln!(
                o,
                "  {h}network:{r} none {dim}(isolated — no network){r}{net_tag}"
            );
        }
        NetworkView::Allowlist {
            allow,
            deny,
            builtin,
        } => {
            let _ = writeln!(o, "  {h}network:{r} allowlist{net_tag}");
            if allow.is_empty() {
                let _ = writeln!(o, "    allow: {dim}(none declared){r}");
            } else {
                for rule in allow {
                    let _ = writeln!(o, "    allow {n}{rule}{r}");
                }
            }
            // Deny wins over allow, so the keyword takes the caution hue.
            for rule in deny {
                let _ = writeln!(o, "    {warn}deny{r}  {n}{rule}{r}");
            }
            let _ = writeln!(
                o,
                "    {dim}built-in (always allowed, so self-equip works):{r}"
            );
            for host in builtin {
                let _ = writeln!(o, "      allow {n}{host}{r}");
            }
            let _ = writeln!(o, "    {dim}(deny wins over allow){r}");
        }
    }

    // The GUI posture — shown only when opened (`wayland`), so a non-GUI config stays uncluttered.
    if matches!(view.gui, GuiView::Wayland) {
        let _ = writeln!(
            o,
            "  {h}gui:{r} wayland {dim}(exposure depends on your compositor){r}{}",
            provenance_tag(view.gui_origin, pal)
        );
    }

    // Resource limits — shown only when a config `[limits]` override customizes one, so a
    // default-profile config stays uncluttered (the effective defaults are in `ops doctor`). When
    // shown, each of the three fields carries its own provenance: the overridden ones name their
    // layer, the untouched ones read `(default)`, so the line tells exactly which limits were tuned.
    let l = &view.limits;
    let overridden = |v: &LimitView| v.origin != config::view::ProvenanceView::Default;
    if overridden(&l.memory_high) || overridden(&l.memory_max) || overridden(&l.tasks_max) {
        let cell = |name: &str, v: &LimitView| {
            let (label, span) = provenance_parts(v.origin, pal);
            format!("{name}={} {span}({label}){r}", v.value)
        };
        let _ = writeln!(
            o,
            "  {h}limits:{r} {}, {}, {}",
            cell("MemoryHigh", &l.memory_high),
            cell("MemoryMax", &l.memory_max),
            cell("TasksMax", &l.tasks_max),
        );
    }

    // Credentials the egress proxy injects — by destination and source locator, never the value.
    if !view.secrets.is_empty() {
        let _ = writeln!(
            o,
            "  {h}secrets (injected host-side by the egress proxy):{r}"
        );
        for s in &view.secrets {
            let _ = writeln!(
                o,
                "    {n}{}{r} -> {n}{}{r}  {dim}({}, from {}){r}",
                s.header, s.to, s.shape, s.sources
            );
        }
    }

    // Named application profiles, each a gated overlay over the baseline: the command it runs,
    // what its overlay adds, and its own dropped-field notes (so `ops app <name>` holds no
    // surprises). Security fields appear only when their source was trusted, exactly as at launch.
    if !view.apps.is_empty() {
        let _ = writeln!(o, "  {h}apps:{r}");
        for app in &view.apps {
            match &app.cmd {
                Some(cmd) => {
                    let _ = writeln!(o, "    {n}{}{r}: {cmd}", app.name);
                }
                // No layer declared a command — the app cannot launch, so flag it.
                None => {
                    let _ = writeln!(o, "    {n}{}{r}: {warn}(no command){r}", app.name);
                }
            }
            let _ = writeln!(o, "      {dim}home:{r} {}", app.home_scope);
            // The environment this overlay adds over the baseline — a count by default, each
            // `KEY=value` under `--details`, mirroring the baseline `env` section. A free field; the
            // value shown is the one that enters the cage (a placeholder for a credential profile),
            // never the injected secret, which ops reads host-side and never prints.
            if !app.env.is_empty() {
                if details {
                    let _ = writeln!(o, "      {dim}env:{r}");
                    for e in &app.env {
                        let _ = writeln!(o, "        {n}{}{r}={}", e.key, e.value);
                    }
                } else {
                    let _ = writeln!(o, "      {dim}env:{r} {} set", app.env.len());
                }
            }
            // The read-only host binds this overlay adds — a security field, so what host paths
            // `ops app <name>` exposes is visible here, the same as the baseline `binds` section. A
            // count by default, each canonical path under `--details`.
            if !app.binds.is_empty() {
                if details {
                    let _ = writeln!(o, "      {dim}binds (read-only):{r}");
                    for b in &app.binds {
                        let _ = writeln!(o, "        {n}{b}{r}");
                    }
                } else {
                    let _ = writeln!(o, "      {dim}binds:{r} {}", app.binds.len());
                }
            }
            // The packages this overlay declares. Compact by default — names with ` @ <rev>` for a
            // pinned `flake:` one and ` (withheld)` for one the trust gate would withhold at launch,
            // so an untrusted app package reads as withheld here without `--details`. `--details`
            // expands to one full line per package (backend, locator, realisation), the same line
            // the baseline `packages` section renders, so the two never drift.
            if !app.packages.is_empty() {
                if details {
                    let _ = writeln!(o, "      {dim}packages:{r}");
                    for p in &app.packages {
                        let _ = writeln!(o, "{}", package_line(p, pal, "        "));
                    }
                } else {
                    let pkgs = app
                        .packages
                        .iter()
                        .map(|p| {
                            // A withheld package stands as its name plus the marker — neither its
                            // pin nor its realisation, since it is not built; the same short-circuit
                            // the full `--details` line takes, so the two paths agree.
                            if p.withheld_reason.is_some() {
                                return format!("{} {warn}(withheld){r}", p.name);
                            }
                            match &p.pinned_rev {
                                Some(rev) => format!("{} @ {}", p.name, short_rev(rev)),
                                None => p.name.clone(),
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    let _ = writeln!(o, "      {dim}packages:{r} {pkgs}");
                }
            }
            // An overlay is a compact summary by default — one line per field; an allowlist shows
            // just its rule counts. `--details` expands that to the individual allow/deny rules
            // and the always-allowed built-in hosts, so what `ops app <name>` can reach is visible
            // here (the baseline `network` section shows the built-in set only when the *baseline*
            // is an allowlist, which a profile's app-overlay allowlist is not).
            if let Some(net) = &app.network {
                match net {
                    AppNetworkView::Shared => {
                        let _ = writeln!(o, "      {dim}network:{r} shared {dim}(host network){r}");
                    }
                    AppNetworkView::Isolated => {
                        let _ = writeln!(
                            o,
                            "      {dim}network:{r} none {dim}(isolated — no network){r}"
                        );
                    }
                    AppNetworkView::Allowlist {
                        allow,
                        deny,
                        builtin,
                    } if details => {
                        let _ = writeln!(o, "      {dim}network:{r} allowlist");
                        for rule in allow {
                            let _ = writeln!(o, "        allow {n}{rule}{r}");
                        }
                        for rule in deny {
                            let _ = writeln!(o, "        {warn}deny{r}  {n}{rule}{r}");
                        }
                        let _ = writeln!(
                            o,
                            "        {dim}built-in (always allowed, so self-equip works):{r}"
                        );
                        for host in builtin {
                            let _ = writeln!(o, "          allow {n}{host}{r}");
                        }
                        let _ = writeln!(o, "        {dim}(deny wins over allow){r}");
                    }
                    AppNetworkView::Allowlist { allow, deny, .. } => {
                        let _ = writeln!(
                            o,
                            "      {dim}network:{r} allowlist {dim}({} allow, {} deny){r}",
                            allow.len(),
                            deny.len()
                        );
                    }
                }
            }
            // The GUI posture the overlay sets, matched like the baseline `gui` line: `wayland`
            // carries the same compositor-exposure caveat, so an app that opens a display explains
            // it the same way; an explicit `none` (the app closing a display the baseline may open)
            // stays a bare word — there is nothing to caveat.
            match &app.gui {
                Some(GuiView::Wayland) => {
                    let _ = writeln!(
                        o,
                        "      {dim}gui:{r} wayland {dim}(exposure depends on your compositor){r}"
                    );
                }
                Some(GuiView::None) => {
                    let _ = writeln!(o, "      {dim}gui:{r} none");
                }
                None => {}
            }
            // The cgroup limits this overlay overrides — only the fields it tunes, since an app
            // does not carry the full effective set (an unset field inherits the baseline, shown in
            // `ops doctor`). Mirrors the baseline `limits:` line but lists the app's own overrides.
            if let Some(limits) = &app.limits {
                let mut parts: Vec<String> = Vec::new();
                if let Some(v) = &limits.memory_high {
                    parts.push(format!("MemoryHigh={v}"));
                }
                if let Some(v) = &limits.memory_max {
                    parts.push(format!("MemoryMax={v}"));
                }
                if let Some(v) = &limits.tasks_max {
                    parts.push(format!("TasksMax={v}"));
                }
                let _ = writeln!(o, "      {dim}limits:{r} {}", parts.join(", "));
            }
            // The credentials this overlay injects (its own `[secret]` sections, gated; the merge
            // unions them with the baseline only for the launch) — a count by default, expanded
            // under `--details` to each by destination and source, the same metadata the baseline
            // section shows. Never the value; ops reads that host-side.
            if !app.secrets.is_empty() {
                if details {
                    let _ = writeln!(o, "      {dim}secrets (injected host-side):{r}");
                    for s in &app.secrets {
                        let _ = writeln!(
                            o,
                            "        {n}{}{r} -> {n}{}{r}  {dim}({}, from {}){r}",
                            s.header, s.to, s.shape, s.sources
                        );
                    }
                } else {
                    let _ = writeln!(
                        o,
                        "      {dim}secrets:{r} {} injected host-side",
                        app.secrets.len()
                    );
                }
            }
            for note in &app.notes {
                let _ = writeln!(o, "      {warn}note: {note}{r}");
            }
        }
    }

    o
}

/// Render one app's *effective* configuration with per-field provenance — the `config show --app
/// <name>` view. Every scalar shows the value the app would launch with, tagged `app:global`/
/// `app:project` (the app set it) or `inherited` (it took the baseline's); collections show the
/// overlay's own additions and a count of the baseline entries they inherit, with the entry lists
/// and the allowlist rules expanded under `--details`. Color and layout only over
/// [`config::view::AppDetailView`]; every span empties under a non-terminal.
fn render_app_detail(
    view: &config::view::AppDetailView,
    pal: &style::Palette,
    details: bool,
) -> String {
    use config::view::{GuiView, LimitView, NetworkView};
    use std::fmt::Write as _;
    let (h, n, warn, dim, r) = (pal.head, pal.name, pal.warn, pal.dim, pal.reset);
    let mut o = String::new();

    let _ = writeln!(
        o,
        "{h}ops config{r} — app {n}{}{r} resolved for {n}{}{r}",
        view.name, view.cwd
    );

    // The command — never inherited (the baseline carries none of its own).
    match &view.cmd {
        Some(cmd) => {
            let _ = writeln!(
                o,
                "  {h}cmd:{r}     {cmd}{}",
                app_provenance_tag(view.cmd_origin, pal)
            );
        }
        None => {
            let _ = writeln!(o, "  {h}cmd:{r}     {warn}(no command){r}");
        }
    }
    let _ = writeln!(
        o,
        "  {h}home:{r}    {}{}",
        view.home_scope,
        app_provenance_tag(view.home_scope_origin, pal)
    );

    // The effective network posture + provenance; the allowlist's rules expand under `--details`.
    let net_tag = app_provenance_tag(view.network_origin, pal);
    match &view.network {
        NetworkView::Shared => {
            let _ = writeln!(o, "  {h}network:{r} shared {dim}(host network){r}{net_tag}");
        }
        NetworkView::Isolated => {
            let _ = writeln!(
                o,
                "  {h}network:{r} none {dim}(isolated — no network){r}{net_tag}"
            );
        }
        NetworkView::Allowlist {
            allow,
            deny,
            builtin,
        } => {
            let _ = writeln!(o, "  {h}network:{r} allowlist{net_tag}");
            if details {
                for rule in allow {
                    let _ = writeln!(o, "    allow {n}{rule}{r}");
                }
                for rule in deny {
                    let _ = writeln!(o, "    {warn}deny{r}  {n}{rule}{r}");
                }
                let _ = writeln!(
                    o,
                    "    {dim}built-in (always allowed, so self-equip works):{r}"
                );
                for host in builtin {
                    let _ = writeln!(o, "      allow {n}{host}{r}");
                }
                let _ = writeln!(o, "    {dim}(deny wins over allow){r}");
            } else {
                let _ = writeln!(
                    o,
                    "    {dim}({} allow, {} deny — see --details){r}",
                    allow.len(),
                    deny.len()
                );
            }
        }
    }

    // The effective GUI posture — shown even when `none`, so the inherited story is visible.
    let gui_tag = app_provenance_tag(view.gui_origin, pal);
    match view.gui {
        GuiView::Wayland => {
            let _ = writeln!(
                o,
                "  {h}gui:{r}     wayland {dim}(exposure depends on your compositor){r}{gui_tag}"
            );
        }
        GuiView::None => {
            let _ = writeln!(o, "  {h}gui:{r}     none{gui_tag}");
        }
    }

    // The effective cgroup limits — every field its provenance (inherited from the baseline, or the
    // app layer that tuned it).
    let cell = |label_name: &str, v: &LimitView| {
        let (label, span) = app_provenance_parts(v.origin, pal);
        format!("{label_name}={} {span}({label}){r}", v.value)
    };
    let l = &view.limits;
    let _ = writeln!(
        o,
        "  {h}limits:{r}  {}, {}, {}",
        cell("MemoryHigh", &l.memory_high),
        cell("MemoryMax", &l.memory_max),
        cell("TasksMax", &l.tasks_max),
    );

    // Collections: the overlay's own additions and how many baseline entries it inherits. The own
    // entry lists expand under `--details`; the inherited baseline entries are not re-listed (they
    // are one hop away in `ops config show`).
    let _ = writeln!(
        o,
        "  {h}env:{r}     {}",
        collection_summary(view.env.len(), view.env_inherited, pal)
    );
    if details {
        for e in &view.env {
            let _ = writeln!(o, "    {n}{}{r}={}", e.key, e.value);
        }
    }
    let _ = writeln!(
        o,
        "  {h}binds:{r}   {}",
        collection_summary(view.binds.len(), view.binds_inherited, pal)
    );
    if details {
        for b in &view.binds {
            let _ = writeln!(o, "    {n}{b}{r}");
        }
    }
    let _ = writeln!(
        o,
        "  {h}packages:{r} {}",
        collection_summary(view.packages.len(), view.packages_inherited, pal)
    );
    if details {
        for p in &view.packages {
            let _ = writeln!(o, "{}", package_line(p, pal, "    "));
        }
    }
    let _ = writeln!(
        o,
        "  {h}secrets:{r} {}",
        collection_summary(view.secrets.len(), view.secrets_inherited, pal)
    );
    if details {
        for s in &view.secrets {
            let _ = writeln!(
                o,
                "    {n}{}{r} -> {n}{}{r}  {dim}({}, from {}){r}",
                s.header, s.to, s.shape, s.sources
            );
        }
    }

    for note in &view.notes {
        let _ = writeln!(o, "  {warn}note: {note}{r}");
    }
    o
}

/// The compact summary for a per-app collection: `<own> own · inherits <n> baseline`. The own count
/// rides the name span (the app's own contribution), the inherited count is dim (it lives in the
/// baseline `ops config show`).
fn collection_summary(own: usize, inherited: usize, pal: &style::Palette) -> String {
    let (n, dim, r) = (pal.name, pal.dim, pal.reset);
    format!("{n}{own}{r} own  {dim}· inherits {inherited} baseline{r}")
}

/// One package's detail line, indented by `indent`: `<name> -> <backend>:<locator>  (<detail>)`,
/// with the trust verdict and any `flake:` pin folded in. A withheld package takes the caution hue
/// and carries its reason; an admitted `flake:` package shows its pinned revision and `pinned`, or
/// `floating` when unpinned; every other backend shows its plain realisation. Shared by the
/// baseline `packages` section (indented four spaces) and an app overlay's `--details` expansion
/// (eight), so the two render identically and cannot drift. The identifier rides the name span, a
/// secondary detail is dimmed, a withheld reason is yellow — every span empty under a non-terminal.
fn package_line(p: &config::view::PackageView, pal: &style::Palette, indent: &str) -> String {
    let (n, warn, dim, r) = (pal.name, pal.warn, pal.dim, pal.reset);
    match &p.withheld_reason {
        Some(reason) => format!(
            "{indent}{n}{}{r} -> {}:{}  {warn}(withheld: {reason}){r}",
            p.name, p.backend, p.locator
        ),
        None => match &p.pinned_rev {
            Some(rev) => format!(
                "{indent}{n}{}{r} -> {}:{}  {dim}@ {} ({}, pinned){r}",
                p.name,
                p.backend,
                p.locator,
                short_rev(rev),
                p.realised
            ),
            None if p.backend == "flake" => format!(
                "{indent}{n}{}{r} -> {}:{}  {dim}({}, floating){r}",
                p.name, p.backend, p.locator, p.realised
            ),
            None => format!(
                "{indent}{n}{}{r} -> {}:{}  {dim}({}){r}",
                p.name, p.backend, p.locator, p.realised
            ),
        },
    }
}

/// One channel line's text (without the colored label): `<source> @ <short-rev>  (<origin>)`, or
/// `<source>  (<origin>)` when no revision has been locked. The source rides the name span (it is
/// the channel identifier), the shortened revision is dimmed (secondary detail), and the origin —
/// the per-channel provenance — is hued by level like every other provenance tag (default gray,
/// global cyan, project green), so a channel reads consistently with its neighbors while keeping
/// its richer wording (`project pin`). The revision is shortened here, a presentation choice; the
/// view model carries the full revision.
fn channel_text(c: &config::view::ChannelView, pal: &style::Palette) -> String {
    let (n, dim, r) = (pal.name, pal.dim, pal.reset);
    let (_, span) = provenance_parts(channel_origin_kind(&c.origin), pal);
    match &c.locked_rev {
        Some(rev) => format!(
            "{n}{}{r} @ {dim}{}{r}  ({span}{}{r})",
            c.source,
            short_rev(rev),
            c.origin
        ),
        None => format!("{n}{}{r}  ({span}{}{r})", c.source, c.origin),
    }
}

/// Map a channel's origin *label* to its provenance level for coloring. The channel view carries
/// its origin as the richer display string `store::Origin::label` emits (`default`/`global`/`project
/// pin`), a closed, stable set; this colors it on the same gray/cyan/green scale as the other
/// provenance tags. The coupling to those exact labels is pinned by a test that routes the real
/// `Origin::label()` strings through here, so a rename fails loudly rather than silently degrading a
/// channel's origin to the dim default — which is also the safe fallback for any unrecognized label.
fn channel_origin_kind(label: &str) -> config::view::ProvenanceView {
    use config::view::ProvenanceView;
    match label {
        "global" => ProvenanceView::Global,
        "project pin" => ProvenanceView::Project,
        _ => ProvenanceView::Default,
    }
}

/// The trailing flags every `config` management verb accepts: the target scope (`-l`/`--local`
/// default, `-g`/`--global`, `-c`/`--config <file>`), `--trust`, and the cross-cutting
/// `-a`/`--app <name>` that rewrites a key under that app's table. A verb consumes the fields it
/// supports and rejects the rest (`path`/`edit` have no key, so they reject `--app`).
struct ScopeArgs {
    positionals: Vec<String>,
    scope: config::manage::Scope,
    trust: bool,
    app: Option<String>,
}

/// Parse a management verb's trailing flags out of `args`. `--` ends flag parsing, so a value that
/// begins with `-` can still be passed.
fn split_scope(args: &[OsString]) -> Result<ScopeArgs, String> {
    use config::manage::Scope;
    let mut positionals = Vec::new();
    let mut scope = Scope::Local;
    let mut trust = false;
    let mut app = None;
    let mut only_positional = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if only_positional {
            positionals.push(arg.to_string_lossy().into_owned());
            continue;
        }
        match arg.to_str() {
            Some("--") => only_positional = true,
            Some("--local") | Some("-l") => scope = Scope::Local,
            Some("--global") | Some("-g") => scope = Scope::Global,
            Some("-c") | Some("--config") => {
                let file = it
                    .next()
                    .ok_or_else(|| "`-c` needs a file path".to_string())?;
                scope = Scope::File(PathBuf::from(file));
            }
            Some("--app") | Some("-a") => {
                let name = it
                    .next()
                    .ok_or_else(|| "`--app` needs an app name".to_string())?;
                app = Some(name.to_string_lossy().into_owned());
            }
            Some("--trust") => trust = true,
            Some(flag) if flag.starts_with('-') && flag != "-" => {
                return Err(format!("unknown flag `{flag}`"));
            }
            _ => positionals.push(arg.to_string_lossy().into_owned()),
        }
    }
    Ok(ScopeArgs {
        positionals,
        scope,
        trust,
        app,
    })
}

/// Rewrite a dotted `key` to address it under app `name`'s table — the `--app <name>` sugar, so
/// `set --app demo network shared` writes `app.demo.network`. The name keys a single TOML table
/// segment, and the segment splitter does not handle quoting, so a name with a `.` (which is a
/// valid app name otherwise) cannot be addressed this way — it is edited directly with `ops config
/// edit`. A name that no app could ever carry is rejected outright.
fn app_prefixed_key(name: &str, key: &str) -> Result<String, String> {
    if name.contains('.') {
        return Err(format!(
            "an app name containing `.` (`{name}`) cannot be addressed with `--app`; \
             edit it directly with `ops config edit`"
        ));
    }
    if !config::is_valid_app_name(name) {
        return Err(format!("invalid app name `{name}`: 1–64 of [A-Za-z0-9._-]"));
    }
    Ok(format!("app.{name}.{key}"))
}

/// Print the usage synopsis for a `config` verb and return the usage exit code.
fn config_usage(verb: &str) -> ExitCode {
    eprintln!("ops: usage: {}", help::synopsis_of(&["config", verb]));
    ExitCode::from(2)
}

/// Resolve the working directory, mapping a failure to an error exit. Shared by the verbs.
fn config_cwd() -> Result<PathBuf, ExitCode> {
    std::env::current_dir().map_err(|e| {
        eprintln!("ops: cannot read the current directory: {e}");
        ExitCode::FAILURE
    })
}

/// `ops config get <key>`: print the value declared at a dotted key in the target layer file
/// (`--local` by default). This reads the *raw declared* value in that one file; for the
/// *effective resolved* value across layers, use `ops config show` / `ops config show --json`. An unset key
/// exits 1 (so a script can tell "absent" from a real error), a usage problem exits 2.
fn config_get(args: &[OsString]) -> ExitCode {
    let ScopeArgs {
        positionals,
        scope,
        app,
        ..
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("ops: config get: {e}");
            return config_usage("get");
        }
    };
    if positionals.len() != 1 {
        return config_usage("get");
    }
    let key = match effective_key("get", &positionals[0], &app) {
        Ok(k) => k,
        Err(code) => return code,
    };
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let path = match config::manage::scope_path(&scope, &cwd) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ops: config: {e}");
            return ExitCode::FAILURE;
        }
    };
    match config::manage::get(&path, &key) {
        Ok(Some(v)) => {
            println!("{v}");
            ExitCode::SUCCESS
        }
        Ok(None) => {
            eprintln!("ops: config: `{}` is not set in {}", key, path.display());
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("ops: config: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Reject `--app` on a verb that takes no key (`path` prints a file path; `edit` opens the whole
/// file) — there is nothing for the app rewrite to apply to. Returns the usage exit code when an
/// `--app` was passed, else `None`.
fn reject_app(verb: &str, app: &Option<String>) -> Option<ExitCode> {
    if app.is_some() {
        eprintln!("ops: config {verb}: `--app` does not apply to `{verb}` (it takes no key)");
        Some(config_usage(verb))
    } else {
        None
    }
}

/// Resolve the dotted key a key-taking verb (`get`/`set`/`unset`) operates on, applying the
/// `--app <name>` rewrite when present. Returns the verb's usage exit code on an invalid app name.
fn effective_key(verb: &str, raw_key: &str, app: &Option<String>) -> Result<String, ExitCode> {
    match app {
        Some(name) => app_prefixed_key(name, raw_key).map_err(|e| {
            eprintln!("ops: config {verb}: {e}");
            config_usage(verb)
        }),
        None => Ok(raw_key.to_string()),
    }
}

/// The confirmation for a config write: the verb (`set`/`updated`/`unset`) in green over the
/// dotted key, with the target file highlighted. A pure presenter — every span is empty under a
/// non-terminal, so captured output is byte-for-byte the plain text the management tests pin.
fn render_config_write(verb: &str, key: &str, path: &Path, pal: &style::Palette) -> String {
    let (ok, n, r) = (pal.ok, pal.name, pal.reset);
    format!(
        "ops: {ok}{verb}{r} `{n}{key}{r}` in {n}{}{r}",
        path.display()
    )
}

/// The no-op confirmation for `ops config unset` on a key that was not set — dimmed, since nothing
/// changed (and so trust is never re-armed). A pure presenter.
fn render_config_unchanged(key: &str, path: &Path, pal: &style::Palette) -> String {
    let (n, dim, r) = (pal.name, pal.dim, pal.reset);
    format!(
        "ops: `{n}{key}{r}` {dim}was not set in {}{r}",
        path.display()
    )
}

/// The confirmation that `--trust` re-blessed a whole file after a write or edit: `trusted` in
/// green over the path, the scope note dimmed. A pure presenter, shared by `set`/`unset`/`edit`.
fn render_trusted_whole_file(path: &Path, pal: &style::Palette) -> String {
    let (ok, n, dim, r) = (pal.ok, pal.name, pal.dim, pal.reset);
    format!(
        "ops: {ok}trusted{r} {n}{}{r} {dim}(the whole file is now trusted){r}",
        path.display()
    )
}

/// `ops config set <key> <value>`: write a string value at a dotted key in the target layer file
/// (`--local` by default), preserving the rest of the file's comments and formatting. Because the
/// trust gate hashes the whole file, any edit re-arms it — so a write to a trusted file warns that
/// its security fields will not apply until `ops trust`, and `--trust` re-trusts in one step.
fn config_set(args: &[OsString]) -> ExitCode {
    let ScopeArgs {
        positionals,
        scope,
        trust,
        app,
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("ops: config set: {e}");
            return config_usage("set");
        }
    };
    if positionals.len() != 2 {
        return config_usage("set");
    }
    let key = match effective_key("set", &positionals[0], &app) {
        Ok(k) => k,
        Err(code) => return code,
    };
    let val = &positionals[1];
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let path = match config::manage::scope_path(&scope, &cwd) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ops: config: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Capture the trust state before the write — the write itself changes the file and so its
    // verdict, so "was it trusted" must be read first.
    let store_dir = trust::default_store_dir();
    let was_trusted = store_dir
        .as_deref()
        .is_some_and(|d| trust::state(d, &path) == trust::TrustState::Trusted);

    match config::manage::set(&path, &key, val) {
        Ok(created) => {
            let verb = if created { "set" } else { "updated" };
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_config_write(verb, &key, &path, &pal));
            report_write_trust(&path, &key, was_trusted, trust, store_dir.as_deref());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ops: config: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `ops config unset <key>`: remove a dotted key from the target layer file. Removing a key that
/// was not set is a no-op (exit 0) that changes nothing — so it never re-arms trust. A removal
/// that does change a trusted file re-arms it, with the same warning as `set`.
fn config_unset(args: &[OsString]) -> ExitCode {
    let ScopeArgs {
        positionals,
        scope,
        trust,
        app,
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("ops: config unset: {e}");
            return config_usage("unset");
        }
    };
    if positionals.len() != 1 {
        return config_usage("unset");
    }
    let key = match effective_key("unset", &positionals[0], &app) {
        Ok(k) => k,
        Err(code) => return code,
    };
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let path = match config::manage::scope_path(&scope, &cwd) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ops: config: {e}");
            return ExitCode::FAILURE;
        }
    };
    let store_dir = trust::default_store_dir();
    let was_trusted = store_dir
        .as_deref()
        .is_some_and(|d| trust::state(d, &path) == trust::TrustState::Trusted);

    match config::manage::unset(&path, &key) {
        Ok(true) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_config_write("unset", &key, &path, &pal));
            report_write_trust(&path, &key, was_trusted, trust, store_dir.as_deref());
            ExitCode::SUCCESS
        }
        Ok(false) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_config_unchanged(&key, &path, &pal));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ops: config: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `ops config path`: print the path of the target layer file (`--local` by default) — the file
/// `set`/`unset`/`edit` would touch. Useful for scripting and for finding the global config.
fn config_path_cmd(args: &[OsString]) -> ExitCode {
    let ScopeArgs {
        positionals,
        scope,
        app,
        ..
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("ops: config path: {e}");
            return config_usage("path");
        }
    };
    if let Some(code) = reject_app("path", &app) {
        return code;
    }
    if !positionals.is_empty() {
        return config_usage("path");
    }
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    match config::manage::scope_path(&scope, &cwd) {
        Ok(p) => {
            println!("{}", p.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ops: config: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `ops config edit`: open the target layer file in `$VISUAL`/`$EDITOR` (falling back to `vi`).
/// The escape hatch for what `set` does not handle — arrays, secrets, and app tables. Runs through
/// a shell so an editor carrying arguments (e.g. `code --wait`) works, with the path passed as a
/// positional so it needs no quoting. Because the trust gate hashes the whole file, an edit that
/// changes a trusted file re-arms it — detected after the editor exits (the verdict becomes
/// Changed) and warned, or applied at once with `--trust`.
fn config_edit(args: &[OsString]) -> ExitCode {
    let ScopeArgs {
        positionals,
        scope,
        trust: trust_flag,
        app,
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("ops: config edit: {e}");
            return config_usage("edit");
        }
    };
    if let Some(code) = reject_app("edit", &app) {
        return code;
    }
    if !positionals.is_empty() {
        return config_usage("edit");
    }
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let path = match config::manage::scope_path(&scope, &cwd) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ops: config: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Make sure the parent directory exists so the editor can save a new file (the global config
    // directory may not exist yet).
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("ops: config: cannot create {}: {e}", parent.display());
            return ExitCode::FAILURE;
        }
    }

    let store_dir = trust::default_store_dir();
    let was_trusted = store_dir
        .as_deref()
        .is_some_and(|d| trust::state(d, &path) == trust::TrustState::Trusted);

    let editor_os = std::env::var_os("VISUAL")
        .or_else(|| std::env::var_os("EDITOR"))
        .unwrap_or_else(|| OsString::from("vi"));
    let editor = editor_os.to_string_lossy();
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} \"$@\""))
        .arg("sh")
        .arg(&path)
        .status();
    match status {
        // The editor ran (whatever its exit) — the file is now whatever the user saved.
        Ok(_) => {}
        Err(e) => {
            eprintln!("ops: config: could not launch the editor `{editor}`: {e}");
            return ExitCode::FAILURE;
        }
    }

    if trust_flag {
        match store_dir.as_deref() {
            Some(dir) => match trust::trust(dir, &path) {
                Ok(()) => {
                    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
                    println!("{}", render_trusted_whole_file(&path, &pal));
                }
                Err(e) => diag::warn(&format!("could not trust {}: {e}", path.display())),
            },
            None => diag::warn("no trust store available; cannot --trust"),
        }
    } else if was_trusted {
        // Only warn if the edit actually changed the file (the verdict is now Changed).
        let now = store_dir.as_deref().map(|d| trust::state(d, &path));
        if now == Some(trust::TrustState::Changed) {
            diag::warn(&format!(
                "your edit re-armed the trust gate for {}",
                path.display()
            ));
            diag::hint(&format!(
                "       run `ops trust {}` to re-apply its security fields",
                path.display()
            ));
        }
    }
    ExitCode::SUCCESS
}

/// Report the trust consequence of a write, the load-bearing UX of `set`/`unset`: the whole-file
/// trust hash means any edit re-arms the gate. `--trust` re-trusts in one step (blessing the whole
/// current file); otherwise a write to a previously-trusted file warns that its security fields
/// will not apply until `ops trust`, and a write of a security field to an untrusted file notes it
/// needs trust to take effect. A free `env` write to an untrusted file needs neither.
fn report_write_trust(
    path: &Path,
    key: &str,
    was_trusted: bool,
    trust_flag: bool,
    store_dir: Option<&Path>,
) {
    if trust_flag {
        match store_dir {
            Some(dir) => match trust::trust(dir, path) {
                Ok(()) => {
                    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
                    println!("{}", render_trusted_whole_file(path, &pal));
                }
                Err(e) => diag::warn(&format!("could not trust {}: {e}", path.display())),
            },
            None => diag::warn("no trust store available; cannot --trust"),
        }
        return;
    }
    if was_trusted {
        diag::warn(&format!(
            "this edit re-armed the trust gate for {}",
            path.display()
        ));
        diag::hint(&format!(
            "       its security fields will not apply until you run `ops trust {}`",
            path.display()
        ));
    } else if is_security_key(key) {
        diag::note(&format!(
            "`{key}` is a security field; it applies only once {} is trusted (`ops trust`)",
            path.display()
        ));
    }
}

/// Whether a dotted config key names a security-relevant field. Everything but the free `env`
/// table is gated on trust, so setting one on an untrusted file is worth a note.
fn is_security_key(key: &str) -> bool {
    key.split('.').next() != Some("env")
}

/// `ops app <name>`: launch a named application profile (an `[app.<name>]` table from the global
/// or project config, or an imported `<name>.toml` profile) inside the project sandbox. The
/// management verbs `import`/`export`/`rm`/`list` are reserved (and so can never be an app name),
/// so the first token disambiguates a subcommand from an app to launch with no overlap.
fn app_cmd(args: Vec<OsString>) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("import") => app_import(&args[1..]),
        Some("export") => app_export(&args[1..]),
        Some("rm") => app_rm(args.get(1).and_then(|a| a.to_str())),
        Some("list") => app_list(),
        // Otherwise the first non-flag token names an app to launch; `--detach` runs it in the
        // background as a session `ops ls`/`attach`/`stop` can see.
        _ => {
            let detach = args.iter().any(|a| a.to_str() == Some("--detach"));
            let name = args
                .iter()
                .filter_map(|a| a.to_str())
                .find(|a| !a.starts_with('-'));
            let Some(name) = name else {
                eprintln!("ops: usage: {}", help::synopsis("app"));
                return ExitCode::from(2);
            };
            sandbox::app(name, detach)
        }
    }
}

/// The import confirmation: `imported` in green over the app name and destination, the granted
/// posture introduced by a dimmed label (the summary lines themselves stay plain — they carry the
/// posture detail), and the launch hint dimmed with the name highlighted. A pure presenter — every
/// span is empty under a non-terminal, so a captured stream is the plain text the tests pin.
fn render_app_imported(
    name: &str,
    dest: &Path,
    summary: &[String],
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (ok, n, dim, r) = (pal.ok, pal.name, pal.dim, pal.reset);
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{ok}imported{r} app profile '{n}{name}{r}' -> {n}{}{r}",
        dest.display()
    );
    let _ = writeln!(
        o,
        "  {dim}granted posture (trusted by location — honored even on an untrusted project):{r}"
    );
    for line in summary {
        let _ = writeln!(o, "    {line}");
    }
    let _ = write!(o, "  {dim}launch it with: ops app{r} {n}{name}{r}");
    o
}

/// The export confirmation (only on `--out`, since the default writes the profile bytes to
/// stdout): `exported` in green over the app name and destination. Goes to stderr, so its palette
/// is decided from stderr's stream. A pure presenter.
fn render_app_exported(name: &str, path: &Path, pal: &style::Palette) -> String {
    let (ok, n, r) = (pal.ok, pal.name, pal.reset);
    format!(
        "{ok}exported{r} app `{n}{name}{r}` -> {n}{}{r}",
        path.display()
    )
}

/// `ops app import <file> [--as <name>] [--force]`: validate a portable app profile and place it
/// under the imported-profiles directory, where it is trusted by location (honored even on an
/// untrusted project). The deliberate command IS the consent — an agent in the cage cannot run it,
/// and the profile stays inert until `ops app <name>` launches it — so there is no interactive
/// prompt, but the granted posture is printed so the act is informed. The bytes are copied
/// verbatim (comments and formatting preserved); the name comes from `--as` or the source file
/// stem, never the file's contents, so the profile is name-agnostic and re-namable for free.
fn app_import(args: &[OsString]) -> ExitCode {
    let mut source: Option<&OsString> = None;
    let mut as_name: Option<String> = None;
    let mut force = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--as") => match it.next().and_then(|a| a.to_str()) {
                Some(n) => as_name = Some(n.to_string()),
                None => {
                    eprintln!("ops: --as needs a name");
                    return ExitCode::from(2);
                }
            },
            Some("--force") => force = true,
            Some(flag) if flag.starts_with("--") => {
                eprintln!(
                    "ops: unknown flag '{flag}' (usage: {})",
                    help::synopsis_of(&["app", "import"])
                );
                return ExitCode::from(2);
            }
            _ if source.is_none() => source = Some(arg),
            _ => {
                eprintln!("ops: ops app import takes a single file");
                return ExitCode::from(2);
            }
        }
    }
    let Some(source) = source else {
        eprintln!("ops: usage: {}", help::synopsis_of(&["app", "import"]));
        return ExitCode::from(2);
    };
    let src_path = Path::new(source);

    // The app name: `--as`, else the source file stem. It keys an on-disk file, so it is validated
    // (charset/length) and refused if it is a reserved subcommand verb — fail-closed.
    let name = match as_name {
        Some(n) => n,
        None => match src_path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => {
                eprintln!(
                    "ops: cannot derive a name from {} — pass --as <name>",
                    src_path.display()
                );
                return ExitCode::from(2);
            }
        },
    };
    if config::is_reserved_app_verb(&name) || !config::is_valid_app_name(&name) {
        eprintln!(
            "ops: '{name}' is not a usable app name (1–64 of [A-Za-z0-9._-], not `.`/`..`, and not \
             a reserved subcommand)"
        );
        return ExitCode::from(2);
    }

    let Some(dir) = config::profiles_dir() else {
        eprintln!("ops: cannot locate the config directory (set $HOME or $XDG_CONFIG_HOME)");
        return ExitCode::FAILURE;
    };

    // Read the source through the same safety gate every config file passes (owner-owned,
    // non-world-writable, regular file), then validate it is a real profile before writing.
    let bytes = match config::safety::read_safe_bytes(src_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ops: cannot read {}: {e}", src_path.display());
            return ExitCode::FAILURE;
        }
    };
    let preview = match config::validate_profile(&bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "ops: {} is not a valid app profile: {e}",
                src_path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    let dest = dir.join(format!("{name}.toml"));
    if dest.exists() && !force {
        eprintln!(
            "ops: a profile '{name}' already exists at {} (use --force to overwrite)",
            dest.display()
        );
        return ExitCode::FAILURE;
    }
    if let Err(e) = write_profile_file(&dir, &dest, &bytes) {
        eprintln!("ops: cannot write {}: {e}", dest.display());
        return ExitCode::FAILURE;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    println!(
        "{}",
        render_app_imported(&name, &dest, &preview.summary, &pal)
    );
    ExitCode::SUCCESS
}

/// Write a profile's bytes to `dest`, owner-only, creating the profiles directory owner-only if
/// it is missing. The bytes go to a sibling temp file (owner-only from creation, so a later read
/// passes the safety gate) and are then renamed into place — atomic, like every other on-disk
/// placement ops makes: a failed or interrupted write never leaves a partial profile at the real
/// name, and a `--force` overwrite keeps the previous profile until the new one is fully written.
fn write_profile_file(dir: &Path, dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let tmp = dir.join(format!(".import-{}.tmp", std::process::id()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    if let Err(e) = f.write_all(bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    drop(f);
    if let Err(e) = std::fs::rename(&tmp, dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// `ops app export <name> [--out <file>]`: write a named app out as a portable profile — an
/// imported profile verbatim, or an inline app serialized to a minimal top-level profile (as
/// authored, security fields and all; import is the trust act, not export). Writes to stdout by
/// default (composable and clobber-safe — `ops app export claude > claude.toml`), or to `--out
/// <file>` directly. The exported file re-imports identically (the round-trip the feature sells).
fn app_export(args: &[OsString]) -> ExitCode {
    let mut name: Option<&str> = None;
    let mut out: Option<&OsString> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--out") => match it.next() {
                Some(p) => out = Some(p),
                None => {
                    eprintln!("ops: --out needs a file");
                    return ExitCode::from(2);
                }
            },
            Some(flag) if flag.starts_with("--") => {
                eprintln!(
                    "ops: unknown flag '{flag}' (usage: {})",
                    help::synopsis_of(&["app", "export"])
                );
                return ExitCode::from(2);
            }
            Some(n) if name.is_none() => name = Some(n),
            None if name.is_none() => {
                eprintln!("ops: the app name must be valid UTF-8");
                return ExitCode::from(2);
            }
            _ => {
                eprintln!("ops: ops app export takes a single name");
                return ExitCode::from(2);
            }
        }
    }
    let Some(name) = name else {
        eprintln!("ops: usage: {}", help::synopsis_of(&["app", "export"]));
        return ExitCode::from(2);
    };
    // The name reaches a filesystem lookup, so validate it (and a reserved verb can never be an
    // app name anyway).
    if config::is_reserved_app_verb(name) || !config::is_valid_app_name(name) {
        eprintln!("ops: '{name}' is not a valid app name");
        return ExitCode::from(2);
    }
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: cannot read the current directory: {e}");
            return ExitCode::FAILURE;
        }
    };
    let bytes = match config::export_profile(&cwd, name) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ops: {e}");
            return ExitCode::FAILURE;
        }
    };
    match out {
        None => {
            use std::io::Write as _;
            if let Err(e) = std::io::stdout().write_all(&bytes) {
                eprintln!("ops: cannot write the profile: {e}");
                return ExitCode::FAILURE;
            }
        }
        Some(path) => {
            let path = Path::new(path);
            if let Err(e) = std::fs::write(path, &bytes) {
                eprintln!("ops: cannot write {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
            // The confirmation goes to stderr (stdout is reserved for the profile bytes), so its
            // palette is decided from stderr's stream, not stdout's.
            let epal = style::Palette::for_stream(std::io::stderr().is_terminal());
            eprintln!("{}", render_app_exported(name, path, &epal));
        }
    }
    ExitCode::SUCCESS
}

/// `ops app rm <name>`: remove an imported profile. Only an imported profile (a file in the
/// profiles directory) is removed here — an inline `[app.<name>]` lives in `ops.toml` and is the
/// user's to edit there. The name is validated before it is joined to a path (anti-traversal).
fn app_rm(name: Option<&str>) -> ExitCode {
    let Some(name) = name else {
        eprintln!("ops: usage: {}", help::synopsis_of(&["app", "rm"]));
        return ExitCode::from(2);
    };
    if config::is_reserved_app_verb(name) || !config::is_valid_app_name(name) {
        eprintln!("ops: '{name}' is not a valid app name");
        return ExitCode::from(2);
    }
    let Some(dir) = config::profiles_dir() else {
        eprintln!("ops: cannot locate the config directory (set $HOME or $XDG_CONFIG_HOME)");
        return ExitCode::FAILURE;
    };
    let path = dir.join(format!("{name}.toml"));
    match std::fs::remove_file(&path) {
        Ok(()) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_removed(Some("app profile"), name, &pal));
            ExitCode::SUCCESS
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "ops: no imported profile '{name}' (an inline [app.{name}] lives in ops.toml — \
                 edit it there)"
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("ops: cannot remove {}: {e}", path.display());
            ExitCode::FAILURE
        }
    }
}

/// `ops app list`: the imported profiles (the artifacts `import`/`rm` manage), by name. The full
/// resolved app set — inline, project, and profile apps together with their gating — is `ops
/// config`; this is the focused view of what is on disk to manage.
fn app_list() -> ExitCode {
    let Some(dir) = config::profiles_dir() else {
        eprintln!("ops: cannot locate the config directory (set $HOME or $XDG_CONFIG_HOME)");
        return ExitCode::FAILURE;
    };
    let mut names: Vec<String> = Vec::new();
    match std::fs::read_dir(&dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|x| x.to_str()) == Some("toml") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        names.push(stem.to_string());
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            eprintln!("ops: cannot read {}: {e}", dir.display());
            return ExitCode::FAILURE;
        }
    }
    names.sort();
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    if names.is_empty() {
        println!("{dim}no imported app profiles (import one with: ops app import <file>){r}");
    } else {
        println!("{h}imported app profiles{r} (in {n}{}{r}):", dir.display());
        for name in &names {
            println!("  {n}{name}{r}");
        }
        println!(
            "{dim}(remove one with: ops app rm <name>; see all resolved apps with: ops config show){r}"
        );
    }
    ExitCode::SUCCESS
}

/// `ops search <query>`: discover the `nix:` tools (and `[packages]` attributes) a
/// project can declare, by querying nixhub. Host-side and read-only — it resolves
/// nothing into the sandbox and needs no trust gate (a discovery front-end, like a plain
/// `nix search`). It needs nix only to ride its fetcher for the one network step.
fn search_cmd(args: Vec<OsString>) -> ExitCode {
    // The query is the first non-flag argument; any further words are ignored (nixhub
    // matches a single token, so a multi-word search is pointless — quote a phrase to
    // pass it as one argument if ever needed).
    let query = args
        .iter()
        .filter_map(|a| a.to_str())
        .find(|a| !a.starts_with('-'));
    let Some(query) = query else {
        eprintln!("ops: usage: {}", help::synopsis("search"));
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("ops: cannot resolve the data directory (no $HOME or $XDG_DATA_HOME).");
        return ExitCode::FAILURE;
    };
    let Some(nix) = store::resolve_nix(Some(&layout)) else {
        eprintln!("ops: nix not found — `ops search` needs it to query nixhub. See `ops doctor`.");
        return ExitCode::FAILURE;
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    match sandbox::search(&nix, &layout, query, &sandbox::current_system(), &pal) {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ops search: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `ops test <kind> <target>`: probe whether an access would be allowed and explain why —
/// a diagnostic surface meant to grow with ops's access controls (the network egress
/// allowlist now; filesystem/Landlock access later). No launch, no nix, no network.
fn test_cmd(args: Vec<OsString>) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("net") => net_test(&args[1..]),
        Some(other) => {
            eprintln!("ops: unknown test kind '{other}' (known: net)");
            ExitCode::from(2)
        }
        None => {
            eprintln!("ops: usage: {}", help::synopsis("test"));
            ExitCode::from(2)
        }
    }
}

/// `ops test net <url>`: test a URL against the resolved network policy and report the rule
/// that decides it. A diagnostic for the egress allowlist — it reflects the trust gate
/// (an untrusted project's policy is dropped, so the *effective* posture is shown) and
/// does no launch, no nix, no network. Exit status is informational only (success),
/// since "the URL would be denied" is a valid answer, not an error.
fn net_test(args: &[OsString]) -> ExitCode {
    let Some(url) = args.first().and_then(|a| a.to_str()) else {
        eprintln!("ops: usage: {}", help::synopsis("test"));
        return ExitCode::from(2);
    };
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: cannot read the current directory: {e}");
            return ExitCode::FAILURE;
        }
    };
    let resolved = config::load(&cwd);
    for w in &resolved.warnings {
        diag::warn(w);
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, r) = (pal.head, pal.reset);
    match &resolved.network {
        config::NetworkPolicy::Shared => {
            println!(
                "{h}network:{r} shared (host network) — every URL is reachable; no allowlist to test"
            );
            ExitCode::SUCCESS
        }
        config::NetworkPolicy::Isolated => {
            println!("{h}network:{r} none (isolated) — no URL is reachable");
            ExitCode::SUCCESS
        }
        config::NetworkPolicy::Allowlist(policy) => {
            let (host, port, path) = match allowlist::parse_url_target(url) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("ops: {e}");
                    return ExitCode::from(2);
                }
            };
            let decision = policy.explain(&host, port, &path);
            print!("{}", render_net_decision(url, &decision, &pal));
            ExitCode::SUCCESS
        }
    }
}

/// Render an egress allowlist decision — a pure presenter (so its colored layout is asserted in a
/// test): the verdict (`ALLOWED` green / `DENIED` red), the URL and the deciding rule as
/// identifiers (cyan, matching how `ops config` renders allow/deny rules), and the reason as
/// de-emphasized prose. Every span is empty under a non-terminal, so a capture is plain text.
fn render_net_decision(url: &str, decision: &allowlist::Decision, pal: &style::Palette) -> String {
    use std::fmt::Write as _;
    let (n, ok, err, dim, r) = (pal.name, pal.ok, pal.err, pal.dim, pal.reset);
    let mut o = String::new();
    match decision {
        allowlist::Decision::AllowedBy(rule) => {
            let _ = writeln!(o, "{ok}ALLOWED{r}  {n}{url}{r}");
            let _ = writeln!(o, "  {dim}by allow rule:{r} {n}{rule}{r}");
        }
        allowlist::Decision::DeniedBy(rule) => {
            let _ = writeln!(o, "{err}DENIED{r}   {n}{url}{r}");
            let _ = writeln!(o, "  {dim}by deny rule (deny wins):{r} {n}{rule}{r}");
        }
        allowlist::Decision::DeniedDefault => {
            let _ = writeln!(o, "{err}DENIED{r}   {n}{url}{r}");
            let _ = writeln!(o, "  {dim}no allow rule matches (deny-by-default){r}");
        }
    }
    o
}

/// `ops plugins <subcommand>`: inspect the installed resolver plugins. Host-level, like `doctor`
/// — it reads `<data>/plugins`, not a project's `.ops.toml`. A read-only diagnostic for now;
/// installation and the signed plugin store are later increments, so the dispatch only knows the
/// inspection verbs and names them on anything else (no inert stubs).
fn plugins_cmd(args: Vec<OsString>) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("list") => plugins_list(),
        Some("info") => plugins_info(args.get(1).and_then(|a| a.to_str())),
        Some("install") => plugins_install(args.get(1)),
        Some("rm") => plugins_remove(args.get(1).and_then(|a| a.to_str())),
        Some("store") => plugins_store(&args[1..]),
        Some(other) => {
            eprintln!(
                "ops: unknown plugins subcommand '{other}' (known: list, info, install, rm, store)"
            );
            ExitCode::from(2)
        }
        None => {
            eprintln!("ops: usage: {}", help::synopsis("plugins"));
            ExitCode::from(2)
        }
    }
}

/// Resolve the registry of installed resolver plugins from the data directory, or report why it
/// could not be located. Shared by `list` and `info`; the load warnings are returned so the
/// caller can surface them (the diagnostic for a plugin that was discovered but dropped).
fn load_plugin_registry() -> Option<(plugins::PluginRegistry, Vec<String>)> {
    let layout = store::Layout::from_env()?;
    let mut warnings = Vec::new();
    let registry = plugins::PluginRegistry::load(&layout.plugins_dir(), &mut warnings);
    Some((registry, warnings))
}

/// `ops plugins list`: the reserved built-in schemes (never claimable by a plugin) and every
/// installed resolver plugin — its scheme, name, version, network grant, and one-line
/// description. A plugin whose executable would be refused at launch (not owner-only, not a
/// regular file) is flagged here, using the very check the runner enforces, so the gap between
/// "discovered" and "runnable" is visible. Discovery warnings (a malformed manifest, an ambiguous
/// scheme) go to stderr. No nix, no network, no launch.
fn plugins_list() -> ExitCode {
    let Some((registry, warnings)) = load_plugin_registry() else {
        eprintln!("ops: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, dim, err, r) = (pal.head, pal.name, pal.dim, pal.err, pal.reset);
    println!(
        "{h}built-in schemes{r} (always resolve, never a plugin): {n}{}{r}",
        plugins::builtin_schemes().join(", ")
    );
    if registry.is_empty() {
        println!("{h}installed resolver plugins:{r} (none)");
    } else {
        println!("{h}installed resolver plugins:{r}");
        for p in registry.resolvers() {
            let net = if p.sandbox.network {
                "network"
            } else {
                "no-network"
            };
            print!("  {n}{}://{r}  {n}{}{r}", p.scheme, p.name);
            if let Some(v) = &p.version {
                print!("  v{v}");
            }
            print!("  {dim}{net}{r}");
            if let Err(why) = p.check_exec() {
                print!("  {err}[not runnable: {why}]{r}");
            }
            println!();
            if let Some(desc) = &p.description {
                println!("    {dim}{desc}{r}");
            }
        }
        println!("{dim}(remove one with: ops plugins rm <name>){r}");
    }
    println!("{dim}(browse the built-in store with: ops plugins store list){r}");
    for w in &warnings {
        diag::warn(w);
    }
    ExitCode::SUCCESS
}

/// The confirmation for a placed plugin: `installed` in green (the change happened), the plugin
/// name and its scheme highlighted, and the removal hint dimmed. `from_store` names the store an
/// install came from, when one did. A pure presenter — every span is empty under a non-terminal,
/// so a captured stream is byte-for-byte the plain text the integration tests pin.
fn render_plugin_installed(
    name: &str,
    scheme: &str,
    from_store: Option<&str>,
    pal: &style::Palette,
) -> String {
    let (ok, n, dim, r) = (pal.ok, pal.name, pal.dim, pal.reset);
    let from = match from_store {
        Some(s) => format!(" from store '{n}{s}{r}'"),
        None => String::new(),
    };
    format!(
        "{ok}installed{r} '{n}{name}{r}' {dim}({scheme}://){r}{from} \
         {dim}— remove with: ops plugins rm {name}{r}"
    )
}

/// The confirmation for a removed thing: `removed` in green over the name. `label` names what kind
/// (`store`, `app profile`), or `None` for a bare resolver plugin. A pure presenter.
fn render_removed(label: Option<&str>, name: &str, pal: &style::Palette) -> String {
    let (ok, n, r) = (pal.ok, pal.name, pal.reset);
    match label {
        Some(l) => format!("{ok}removed{r} {l} '{n}{name}{r}'"),
        None => format!("{ok}removed{r} '{n}{name}{r}'"),
    }
}

/// The trust-on-first-use caution for a freshly added store — yellow, since it pinned a key ops
/// could not pre-verify. The pinned key is highlighted for an out-of-band comparison; the
/// follow-up hint is dimmed. Goes to stderr, so its palette is decided from stderr's stream.
fn render_store_tofu(pubkey_hex: &str, name: &str, pal: &style::Palette) -> String {
    let (warn, n, dim, r) = (pal.warn, pal.name, pal.dim, pal.reset);
    format!(
        "{warn}⚠ trust-on-first-use: pinned the key this store ships, unverified{r}\n  \
         pinned key: {n}{pubkey_hex}{r}\n  \
         {dim}verify it out of band; re-shown by `ops plugins store info {name}`{r}"
    )
}

/// The configured-store report: `configured store` in green over the name, the revision and count
/// dimmed, then each plugin by name with its scheme and version dimmed. A pure presenter over the
/// catalogue's plugin lines as `(name, scheme, version)` triples.
fn render_store_configured(
    name: &str,
    rev: u64,
    plugins: &[(&str, &str, &str)],
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (ok, n, dim, r) = (pal.ok, pal.name, pal.dim, pal.reset);
    let plural = if plugins.len() == 1 { "" } else { "s" };
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{ok}configured store{r} '{n}{name}{r}' {dim}(rev {rev}, {} plugin{plural}):{r}",
        plugins.len()
    );
    for (pname, scheme, version) in plugins {
        let _ = write!(o, "  {n}{pname}{r}  {dim}({scheme}://){r}");
        if !version.is_empty() {
            let _ = write!(o, "  {dim}v{version}{r}");
        }
        let _ = writeln!(o);
    }
    o
}

/// The keep-the-key-secret caution after a publish — yellow, over the highlighted key path. Goes
/// to stderr, so its palette is decided from stderr's stream.
fn render_publish_key_warning(key_path: &Path, pal: &style::Palette) -> String {
    let (warn, n, r) = (pal.warn, pal.name, pal.reset);
    format!(
        "{warn}⚠ keep the signing key{r} {n}`{}`{r} \
         {warn}secret — it is this store's identity{r}",
        key_path.display()
    )
}

/// The published-store report: `published store` in green, the plugins by name, the public key
/// consumers pin highlighted, and the commit-and-host hint dimmed (with the key echoed in it). A
/// pure presenter over the published plugin lines as `(name, scheme)` pairs.
fn render_published(
    rev: u64,
    plugins: &[(&str, &str)],
    pubkey_hex: &str,
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (ok, n, dim, r) = (pal.ok, pal.name, pal.dim, pal.reset);
    let plural = if plugins.len() == 1 { "" } else { "s" };
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{ok}published store{r} at rev {rev} {dim}({} plugin{plural}):{r}",
        plugins.len()
    );
    for (name, scheme) in plugins {
        let _ = writeln!(o, "  {n}{name}{r}  {dim}({scheme}://){r}");
    }
    let _ = writeln!(o, "pubkey: {n}{pubkey_hex}{r}");
    let _ = write!(
        o,
        "{dim}commit and host the directory, then consumers add it with: \
         ops plugins store add --name <n> --url <git-url> --key {pubkey_hex}{r}"
    );
    o
}

/// The update report for one store: `updated store` in green with the revision bump when it
/// advanced, or a dimmed already-current line when nothing moved (a no-op takes the dim hue). A
/// pure presenter.
fn render_store_updated(
    name: &str,
    old_rev: u64,
    new_rev: u64,
    count: usize,
    pal: &style::Palette,
) -> String {
    let (ok, n, dim, r) = (pal.ok, pal.name, pal.dim, pal.reset);
    let plural = if count == 1 { "" } else { "s" };
    if new_rev > old_rev {
        format!(
            "{ok}updated store{r} '{n}{name}{r}' \
             {dim}(rev {old_rev} → {new_rev}, {count} plugin{plural}){r}"
        )
    } else {
        format!(
            "store '{n}{name}{r}' is {dim}already at revision {new_rev} ({count} plugin{plural}){r}"
        )
    }
}

/// `ops plugins install <name | dir>`: place a resolver plugin into the data dir, where it becomes
/// trusted by location. A bare `name` installs a plugin from the built-in store (bundled in the
/// binary); a path-like argument (`./dir`, `/abs/dir`) copies a local directory. A deliberate user
/// act (an agent in the cage cannot run it); either way the staged copy is validated exactly as the
/// launcher will and refused, fail-closed, on any flaw. No fetch, no network, no signature.
fn plugins_install(source: Option<&OsString>) -> ExitCode {
    let Some(source) = source else {
        eprintln!("ops: usage: {}", help::synopsis_of(&["plugins", "install"]));
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("ops: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    // The rule is syntactic, not based on what exists on disk, so the command's meaning never
    // depends on the current directory's contents: a path-like argument is a local directory, a
    // bare token is a built-in store name.
    let result = if is_path_like(source) {
        plugins::install(&layout, Path::new(source))
    } else if let Some(name) = source.to_str() {
        plugins::install_embedded(&layout, name)
    } else {
        eprintln!("ops: a built-in plugin name must be valid UTF-8 (use ./<dir> for a local path)");
        return ExitCode::from(2);
    };
    match result {
        Ok(installed) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!(
                "{}",
                render_plugin_installed(&installed.name, &installed.scheme, None, &pal)
            );
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("ops: cannot install plugin: {why}");
            ExitCode::FAILURE
        }
    }
}

/// Whether an install argument names a local path rather than a built-in store plugin: it begins
/// with `.` (`./dir`, `../dir`) or contains a `/` (`/abs/dir`, `sub/dir`). A bare `name` is looked
/// up in the built-in store. Syntactic by design — the dispatch must not depend on the cwd.
fn is_path_like(arg: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let bytes = arg.as_bytes();
    bytes.first() == Some(&b'.') || bytes.contains(&b'/')
}

/// `ops plugins store <subcommand>`: the plugin stores. `list` shows the built-in (embedded)
/// store and every configured remote store; `add` configures and fetches a remote signed store
/// (a git repository whose catalogue is verified against a public key); `update` re-fetches one
/// or all configured stores (re-verifying against the pinned key and refusing a revision that
/// would roll back); `install` installs a plugin a configured store lists; `info` details one
/// configured store; `rm` removes one.
fn plugins_store(args: &[OsString]) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("list") => plugins_store_list(),
        Some("add") => plugins_store_add(&args[1..]),
        Some("publish") => plugins_store_publish(&args[1..]),
        Some("update") => plugins_store_update(&args[1..]),
        Some("install") => plugins_store_install(&args[1..]),
        Some("info") => plugins_store_info(args.get(1).and_then(|a| a.to_str())),
        Some("rm") => plugins_store_remove(args.get(1).and_then(|a| a.to_str())),
        Some(other) => {
            eprintln!(
                "ops: unknown plugins store subcommand '{other}' \
                 (known: list, add, publish, update, install, info, rm)"
            );
            ExitCode::from(2)
        }
        None => {
            eprintln!("ops: usage: {}", help::synopsis_of(&["plugins", "store"]));
            ExitCode::from(2)
        }
    }
}

/// `ops plugins store add --name <n> --url <git-url> (--key <hex|@file> | --trust)`: configure a
/// remote signed plugin store and fetch it for the first time. The repository is cloned, its
/// catalogue verified, and the verified result cached under the data directory. A deliberate user
/// act (an agent in the cage cannot run it). The store's trust anchor comes from exactly one of two
/// mutually exclusive flags: `--key` pins a public key the user obtained out of band (the strong
/// form), while `--trust` accepts the key the store ships on first use (weaker — no first-fetch
/// authenticity; the pinned key's fingerprint is printed for out-of-band verification). One of the
/// two is required: a store with no verifying key would be unsigned, refused fail-closed.
fn plugins_store_add(args: &[OsString]) -> ExitCode {
    let usage = format!(
        "ops: usage: {}",
        help::synopsis_of(&["plugins", "store", "add"])
    );
    let (mut name, mut url, mut key) = (None, None, None);
    let mut trust = false;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match flag.to_str() {
            Some("--name") => name = it.next().and_then(|v| v.to_str()),
            Some("--url") => url = it.next().and_then(|v| v.to_str()),
            Some("--key") => key = it.next().and_then(|v| v.to_str()),
            Some("--trust") => trust = true,
            other => {
                eprintln!(
                    "ops: unexpected argument '{}'",
                    other.unwrap_or("(non-UTF-8)")
                );
                eprintln!("{usage}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(name), Some(url)) = (name, url) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };

    // The trust anchor is exactly one of --key (pin a known key) or --trust (accept the shipped one).
    if key.is_some() && trust {
        eprintln!(
            "ops: --key and --trust are mutually exclusive: --key pins a key you supply, \
             --trust accepts the key the store ships"
        );
        return ExitCode::from(2);
    }
    if key.is_none() && !trust {
        eprintln!(
            "ops: supply --key <hex|@file> to pin a known key, or --trust to accept the key the \
             store ships on first use"
        );
        return ExitCode::from(2);
    }

    let Some(layout) = store::Layout::from_env() else {
        eprintln!("ops: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    let Some(git) = store::resolve_git() else {
        eprintln!("ops: git is not on PATH — a remote plugin store is a git repository");
        return ExitCode::FAILURE;
    };

    let result = match key {
        Some(key) => {
            let pubkey = match stores::parse_pubkey_arg(key) {
                Ok(k) => k,
                Err(why) => {
                    eprintln!("ops: invalid --key: {why}");
                    return ExitCode::from(2);
                }
            };
            stores::add(&layout, name, url, pubkey, &git)
        }
        None => stores::add_tofu(&layout, name, url, &git),
    };

    match result {
        Ok(added) => {
            // Trust on first use pinned a key ops could not pre-verify: surface it loudly on stderr
            // (so it is never silently swallowed in a scripted run) with the full key for an
            // out-of-band comparison, while the configured-store report goes to stdout. Each line's
            // palette is decided from the stream it actually goes to.
            if added.tofu {
                let epal = style::Palette::for_stream(std::io::stderr().is_terminal());
                eprintln!(
                    "{}",
                    render_store_tofu(&plugin_store::to_hex(&added.pubkey), &added.name, &epal)
                );
            }
            let cat = &added.catalogue;
            let plugins: Vec<(&str, &str, &str)> = cat
                .plugins
                .iter()
                .map(|(p, e)| (p.as_str(), e.scheme.as_str(), e.version.as_str()))
                .collect();
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            print!(
                "{}",
                render_store_configured(&added.name, cat.rev, &plugins, &pal)
            );
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("ops: cannot add store: {why}");
            ExitCode::FAILURE
        }
    }
}

/// `ops plugins store publish <dir> --key <key-file> [--rev <n>]`: sign a directory of resolver
/// plugins into a store. It writes a `catalogue.toml` (pinning each plugin by a content digest), a
/// detached signature, the store's `pubkey`, and a `.gitattributes`; the operator then commits and
/// hosts the result. The producing counterpart of `store add` — an operator tool, never reachable
/// from a cage. The signing key is reused if the file exists (so the store keeps its identity
/// across publishes) or generated and persisted owner-only on first use; it is the store's secret
/// and never leaves the operator's host.
fn plugins_store_publish(args: &[OsString]) -> ExitCode {
    let usage = format!(
        "ops: usage: {}",
        help::synopsis_of(&["plugins", "store", "publish"])
    );
    let mut dir: Option<&OsStr> = None;
    let mut key: Option<&OsStr> = None;
    let mut rev: Option<u64> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--key") => key = it.next().map(|v| v.as_os_str()),
            Some("--rev") => {
                let Some(value) = it.next().and_then(|v| v.to_str()) else {
                    eprintln!("{usage}");
                    return ExitCode::from(2);
                };
                match value.parse::<u64>() {
                    Ok(n) => rev = Some(n),
                    Err(_) => {
                        eprintln!("ops: --rev must be a non-negative integer");
                        return ExitCode::from(2);
                    }
                }
            }
            Some(flag) if flag.starts_with('-') => {
                eprintln!("ops: unexpected argument '{flag}'");
                eprintln!("{usage}");
                return ExitCode::from(2);
            }
            // Anything else (including a non-UTF-8 path) is the positional directory.
            _ => {
                if dir.is_some() {
                    eprintln!("ops: publish takes a single directory");
                    eprintln!("{usage}");
                    return ExitCode::from(2);
                }
                dir = Some(arg.as_os_str());
            }
        }
    }
    let (Some(dir), Some(key)) = (dir, key) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };

    match stores::publish(Path::new(dir), Path::new(key), rev) {
        Ok(published) => {
            // The key file just written or reused is the store's identity; warn loudly so it is
            // never treated as a throwaway. The public key, on stdout, is what consumers pin. Each
            // line's palette is decided from the stream it actually goes to.
            let epal = style::Palette::for_stream(std::io::stderr().is_terminal());
            eprintln!("{}", render_publish_key_warning(Path::new(key), &epal));
            let pubkey = plugin_store::to_hex(&published.pubkey);
            let plugins: Vec<(&str, &str)> = published
                .plugins
                .iter()
                .map(|(name, scheme)| (name.as_str(), scheme.as_str()))
                .collect();
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!(
                "{}",
                render_published(published.rev, &plugins, &pubkey, &pal)
            );
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("ops: cannot publish store: {why}");
            ExitCode::FAILURE
        }
    }
}

/// `ops plugins store update [name]`: re-fetch one configured remote store, or every configured
/// store when no name is given. Each re-fetch re-verifies the catalogue against the store's
/// pinned key (a compromised remote cannot rotate it) and refuses a revision that would roll
/// back, replacing the cache atomically. A deliberate user act. When updating all stores, a
/// failure on one is reported and the rest still run, with a non-zero exit if any failed.
fn plugins_store_update(args: &[OsString]) -> ExitCode {
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("ops: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    let Some(git) = store::resolve_git() else {
        eprintln!("ops: git is not on PATH — a remote plugin store is a git repository");
        return ExitCode::FAILURE;
    };

    let names: Vec<String> = match args.first() {
        Some(arg) => {
            let Some(name) = arg.to_str() else {
                eprintln!("ops: a store name must be valid UTF-8");
                return ExitCode::from(2);
            };
            vec![name.to_string()]
        }
        None => {
            let all = stores::list(&layout);
            if all.is_empty() {
                let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
                let (dim, r) = (pal.dim, pal.reset);
                println!(
                    "{dim}no remote stores are configured \
                     (add one with: ops plugins store add --name <n> --url <git-url> --key <hex>){r}"
                );
                return ExitCode::SUCCESS;
            }
            all
        }
    };

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let mut failed = false;
    for name in &names {
        match stores::update(&layout, name, &git) {
            Ok(u) => {
                println!(
                    "{}",
                    render_store_updated(
                        &u.name,
                        u.old_rev,
                        u.new_rev,
                        u.catalogue.plugins.len(),
                        &pal
                    )
                );
            }
            Err(why) => {
                eprintln!("ops: cannot update store '{name}': {why}");
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// `ops plugins store install <store> <plugin>`: install a resolver plugin a configured store
/// lists, by name. The store's cached catalogue (verified when the store was added or updated)
/// pins the plugin's content by hash; the install verifies that hash, reconciles the catalogue's
/// advertised name and scheme against the plugin's manifest, and places it exactly as a local
/// install would. A deliberate user act. Reads only the owner-only cache — no fetch, no network.
fn plugins_store_install(args: &[OsString]) -> ExitCode {
    let (Some(store_name), Some(plugin_name)) = (
        args.first().and_then(|a| a.to_str()),
        args.get(1).and_then(|a| a.to_str()),
    ) else {
        eprintln!(
            "ops: usage: {}",
            help::synopsis_of(&["plugins", "store", "install"])
        );
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("ops: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    match stores::install_plugin(&layout, store_name, plugin_name) {
        Ok(installed) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!(
                "{}",
                render_plugin_installed(&installed.name, &installed.scheme, Some(store_name), &pal)
            );
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("ops: cannot install plugin: {why}");
            ExitCode::FAILURE
        }
    }
}

/// `ops plugins store info <name>`: a configured remote store in detail — its origin URL, the
/// pinned public key, the accepted catalogue revision, and each plugin it lists. Reads only the
/// owner-only cache (trusted by location): no fetch, no network.
fn plugins_store_info(name: Option<&str>) -> ExitCode {
    let Some(name) = name else {
        eprintln!(
            "ops: usage: {}",
            help::synopsis_of(&["plugins", "store", "info"])
        );
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("ops: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    let cfg = match stores::read_configured(&layout, name) {
        Ok(cfg) => cfg,
        Err(why) => {
            eprintln!("ops: {why}");
            return ExitCode::FAILURE;
        }
    };

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    println!("{h}store{r} {n}'{}'{r}", cfg.name);
    println!("  url:      {}", cfg.url);
    println!("  key:      {}", plugin_store::to_hex(&cfg.pubkey));
    println!(
        "  trust:    {}",
        if cfg.tofu {
            "trust-on-first-use (verify the key out of band)"
        } else {
            "pinned key (supplied out of band)"
        }
    );
    println!("  revision: {}", cfg.locked_rev);
    match stores::cached_catalogue(&layout, name) {
        Ok(cat) if cat.plugins.is_empty() => println!("  plugins:  (none)"),
        Ok(cat) => {
            println!("  plugins:");
            for (pname, entry) in &cat.plugins {
                print!("    {n}{pname}{r}  {dim}({}://){r}", entry.scheme);
                if !entry.version.is_empty() {
                    print!("  v{}", entry.version);
                }
                println!();
                if !entry.description.is_empty() {
                    println!("      {dim}{}{r}", entry.description);
                }
            }
        }
        Err(why) => diag::warn(&format!("cannot read the cached catalogue: {why}")),
    }
    ExitCode::SUCCESS
}

/// `ops plugins store rm <name>`: remove a configured remote store from the cache. Host-level,
/// like `add`; refuses a name that is not configured.
fn plugins_store_remove(name: Option<&str>) -> ExitCode {
    let Some(name) = name else {
        eprintln!(
            "ops: usage: {}",
            help::synopsis_of(&["plugins", "store", "rm"])
        );
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("ops: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    match stores::remove(&layout, name) {
        Ok(()) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_removed(Some("store"), name, &pal));
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("ops: cannot remove store: {why}");
            ExitCode::FAILURE
        }
    }
}

/// `ops plugins store list`: the resolver plugins bundled in the binary, each with its scheme,
/// version, description, and whether it is already installed, followed by every configured
/// remote store with its accepted revision and plugin count. No fetch, no network.
fn plugins_store_list() -> ExitCode {
    let layout = store::Layout::from_env();
    let installed_dir = layout.as_ref().map(|l| l.plugins_dir());
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    println!("{h}built-in plugin store{r} (install one with: ops plugins install <name>):");
    for entry in plugins::embedded_listing() {
        let scheme = entry.scheme.as_deref().unwrap_or("?");
        print!("  {n}{}{r}  {dim}({scheme}://){r}", entry.name);
        if let Some(v) = &entry.version {
            print!("  v{v}");
        }
        let is_installed = installed_dir
            .as_ref()
            .is_some_and(|d| d.join(&entry.name).is_dir());
        if is_installed {
            print!("  {}[installed]{r}", pal.ok);
        }
        println!();
        if let Some(desc) = &entry.description {
            println!("    {dim}{desc}{r}");
        }
    }

    // Configured remote stores, read from their owner-only caches (trusted by location).
    if let Some(layout) = &layout {
        let names = stores::list(layout);
        if !names.is_empty() {
            println!(
                "{h}configured remote stores{r} (update with: ops plugins store update <name>):"
            );
            for name in &names {
                match stores::read_configured(layout, name) {
                    Ok(cfg) => {
                        let detail = match stores::cached_catalogue(layout, name) {
                            Ok(cat) => {
                                let count = cat.plugins.len();
                                format!("{count} plugin{}", if count == 1 { "" } else { "s" })
                            }
                            Err(_) => "catalogue unreadable".to_string(),
                        };
                        let marker = if cfg.tofu {
                            format!("  {}[tofu]{r}", pal.warn)
                        } else {
                            String::new()
                        };
                        println!(
                            "  {n}{name}{r}  {dim}(rev {}, {detail}){r}{marker}",
                            cfg.locked_rev
                        );
                    }
                    Err(why) => diag::warn(&format!("store '{name}': {why}")),
                }
            }
        }
    }
    ExitCode::SUCCESS
}

/// `ops plugins rm <name>`: remove an installed resolver plugin by its name (the token `list`
/// shows). Host-level, like `install`; refuses an unsafe name or a directory that is not a plugin.
fn plugins_remove(name: Option<&str>) -> ExitCode {
    let Some(name) = name else {
        eprintln!("ops: usage: {}", help::synopsis_of(&["plugins", "rm"]));
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("ops: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    match plugins::remove(&layout, name) {
        Ok(()) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_removed(None, name, &pal));
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("ops: cannot remove plugin: {why}");
            ExitCode::FAILURE
        }
    }
}

/// `ops plugins info <scheme>`: the full manifest and sandbox grant of the plugin claiming
/// `scheme`. A built-in scheme is reported as such (not an error); an unknown scheme is a
/// non-zero "no such plugin". Like `list`, host-level and side-effect-free.
fn plugins_info(scheme: Option<&str>) -> ExitCode {
    let Some(scheme) = scheme else {
        eprintln!("ops: usage: {}", help::synopsis_of(&["plugins", "info"]));
        return ExitCode::from(2);
    };
    if plugins::builtin_schemes().contains(&scheme) {
        println!("{scheme}: a built-in resolver (compiled into ops, not a plugin)");
        return ExitCode::SUCCESS;
    }
    let Some((registry, warnings)) = load_plugin_registry() else {
        eprintln!("ops: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    let Some(p) = registry.resolver(scheme) else {
        // A scheme can be absent because nothing claims it — or because it was *dropped* (two
        // plugins claimed it, or its manifest is malformed). That reason lives in the load
        // warnings, and `info <scheme>` is exactly the command a user runs to learn why their
        // plugin is not picked up, so re-emit them before the generic miss.
        for w in &warnings {
            diag::warn(w);
        }
        eprintln!("ops: no installed resolver plugin claims the scheme '{scheme}'");
        return ExitCode::FAILURE;
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, err, r) = (pal.head, pal.name, pal.err, pal.reset);
    println!("{h}resolver plugin:{r} {n}{}{r}", p.name);
    println!("  scheme:      {n}{}://{r}", p.scheme);
    println!(
        "  version:     {}",
        p.version.as_deref().unwrap_or("(unset)")
    );
    println!(
        "  description: {}",
        p.description.as_deref().unwrap_or("(none)")
    );
    print!("  exec:        {}", p.exec.display());
    match p.check_exec() {
        Ok(()) => println!(),
        Err(why) => println!("  {err}[not runnable: {why}]{r}"),
    }
    println!("  sandbox grant:");
    println!("    network:     {}", p.sandbox.network);
    print_grant_paths("allow_paths", &p.sandbox.allow_paths);
    print_grant_env("allow_env", &p.sandbox.allow_env);
    ExitCode::SUCCESS
}

/// One `ops plugins info` grant line listing read-only path binds, or `(none)`.
fn print_grant_paths(label: &str, paths: &[PathBuf]) {
    if paths.is_empty() {
        println!("    {label}:  (none)");
    } else {
        let joined = paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("    {label}:  {joined}");
    }
}

/// One `ops plugins info` grant line listing passed-through environment variables, or `(none)`.
fn print_grant_env(label: &str, keys: &[String]) {
    if keys.is_empty() {
        println!("    {label}:    (none)");
    } else {
        println!("    {label}:    {}", keys.join(", "));
    }
}

/// `ops upgrade [all|nix|mise]`: roll managed channels forward by re-resolving and
/// rewriting their locks, so versions advance only here, never on an ops binary update.
/// `nix` rolls the nixpkgs channel the current directory tracks (a trusted project pin,
/// else the global channel) — base and native `nix:` `[packages]`. `mise` rolls the mise
/// engine (its own dedicated lock), the project's `nix:` tools, and the project's and apps'
/// `mise:` `[packages]` (the last in-cage). `all` rolls every one. The lock-rewriting parts
/// need nix (to resolve) but not the sandbox boundary; the in-cage `mise:` roll needs the
/// sandbox and degrades to a warning where it is unavailable.
fn upgrade_cmd(args: Vec<OsString>) -> ExitCode {
    // Parse the target before touching anything, so a typo fails cleanly. `all` covers
    // every managed channel: the nixpkgs channel (base + native `[packages]`) and the
    // project's `nix:` mise tools.
    let what = match args.first().and_then(|s| s.to_str()).unwrap_or("all") {
        w @ ("all" | "nix" | "mise" | "flake") => w,
        other => {
            eprintln!("ops: unknown upgrade target '{other}' (known: all, nix, mise, flake)");
            return ExitCode::from(2);
        }
    };

    let Some(layout) = store::Layout::from_env() else {
        eprintln!("ops: cannot resolve the data directory (no $HOME or $XDG_DATA_HOME).");
        return ExitCode::FAILURE;
    };
    let Some(nix) = store::resolve_nix(Some(&layout)) else {
        eprintln!("ops: nix not found — cannot upgrade. See `ops doctor`.");
        return ExitCode::FAILURE;
    };
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: cannot read the current directory: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Load the config so a project pin — and any reason one was dropped — is honored
    // exactly as a launch would; surfacing the warnings explains a pin that did not
    // take (so an untrusted pin silently rolling the global channel is never a mystery).
    let cfg = config::load(&cwd);
    for warning in &cfg.warnings {
        diag::warn(warning);
    }

    // `all` rolls every managed channel and reports the worst exit — a tool that fails to
    // re-resolve must not be masked by a clean roll elsewhere. `mise` rolls three distinct
    // things: the engine (host-global, in every cage, so it rolls regardless of any project's
    // trust), the project's `nix:` tools (trusted-only), and the project's and apps' `mise:`
    // `[packages]` (in-cage, trusted-only). Rolling them as separate, unconditional calls keeps
    // the engine's trust-independence structural rather than dependent on an earlier path not
    // early-returning.
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let mut ok = true;
    if matches!(what, "nix" | "all") {
        ok &= upgrade_nix_channel(&nix, &layout, &cwd, &cfg, &pal);
    }
    if matches!(what, "mise" | "all") {
        ok &= upgrade_mise_engine(&nix, &layout, &cfg, &pal);
        ok &= upgrade_mise_tools(&nix, &layout, &cwd, &cfg, &pal);
        // The project's and apps' `mise:` `[packages]` are equipped in-cage, not host-side, so
        // their roll runs `mise upgrade` inside a cage (per home) rather than rewriting a lock.
        // Pass the already-loaded config: the groups are computed from it before any sandbox
        // work, so a project with no `mise:` package keeps this cheap and sandbox-free.
        ok &= sandbox::upgrade_mise_packages(&cfg, &pal);
    }
    if matches!(what, "flake" | "all") {
        // The project's and apps' `flake:` `[packages]` re-resolve to a fixed revision and the
        // per-project flake lock is rewritten — a host-side lock rewrite (the new pin builds
        // in-cage at the next launch), like the `nix:` tools.
        ok &= upgrade_flake_packages(&nix, &layout, &cwd, &cfg, &pal);
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// `ops gc [--all] [--prune]`: reclaim ops's per-project store space. By default it sweeps the
/// current project's store; `--all` also reaps whole runtime trees whose project directory is
/// gone. A dry run by default (it reports what would be freed and touches nothing); `--prune`
/// actually reclaims. Reclamation is irreversible, so the destructive form is opt-in.
fn gc_cmd(args: Vec<OsString>) -> ExitCode {
    let mut prune = false;
    let mut all = false;
    for arg in &args {
        match arg.to_str() {
            Some("--prune") => prune = true,
            Some("--all") => all = true,
            _ => {
                eprintln!("ops: usage: {}", help::synopsis("gc"));
                return ExitCode::from(2);
            }
        }
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    sandbox::gc(prune, all, &pal)
}

/// Roll the nixpkgs channel the current directory tracks — a trusted project pin, else
/// the global channel — forcing a fresh resolution and rewriting that lock. Returns
/// whether it succeeded; the base and `[packages]` download on the next launch.
fn upgrade_nix_channel(
    nix: &Path,
    layout: &store::Layout,
    cwd: &Path,
    cfg: &config::Resolved,
    pal: &style::Palette,
) -> bool {
    let target = match sandbox::effective_lock_target(cwd, layout, cfg) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ops: cannot resolve the channel target: {e}");
            return false;
        }
    };
    let upgrade = match target.refresh(nix, layout) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("ops: cannot upgrade the nixpkgs channel: {e}");
            return false;
        }
    };
    for line in channel_upgrade_summary(
        "ops upgrade — nix channel",
        "channel",
        "the new base and tools download",
        target.origin().label(),
        &upgrade,
        pal,
    ) {
        println!("{line}");
    }
    true
}

/// Roll the mise engine: force a fresh resolution of its dedicated lock (the global
/// channel source, in `mise-engine.lock`) and rewrite it, so the engine advances
/// independently of the base channel that `ops upgrade nix` rolls. Host-global and
/// present in every cage, so it rolls regardless of any project's trust — unlike the
/// project's `nix:` tools. Returns whether it succeeded; the new engine is provisioned
/// on the next launch.
fn upgrade_mise_engine(
    nix: &Path,
    layout: &store::Layout,
    cfg: &config::Resolved,
    pal: &style::Palette,
) -> bool {
    let target = store::LockTarget::engine(layout, cfg.nixpkgs_global.as_deref());
    let upgrade = match target.refresh(nix, layout) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("ops: cannot upgrade the mise engine: {e}");
            return false;
        }
    };
    for line in channel_upgrade_summary(
        "ops upgrade — mise engine",
        "engine",
        "the new engine is provisioned",
        target.origin().label(),
        &upgrade,
        pal,
    ) {
        println!("{line}");
    }
    true
}

/// Roll the project's `nix:` mise tools: re-resolve the floating pins against nixhub and
/// prune stale entries, rewriting the per-project resolution lock. Returns whether it
/// succeeded — a tool that fails to re-resolve keeps its prior pin and makes this `false`,
/// but never aborts the others. Trusted-only, mirroring how the tools are provisioned: an
/// untrusted project's tools are never locked, so there is nothing to roll.
fn upgrade_mise_tools(
    nix: &Path,
    layout: &store::Layout,
    cwd: &Path,
    cfg: &config::Resolved,
    pal: &style::Palette,
) -> bool {
    let Some(mise) = &cfg.mise else {
        for line in upgrade_tools_summary(&[], pal) {
            println!("{line}");
        }
        return true;
    };
    if mise.state != trust::TrustState::Trusted {
        diag::warn(&format!(
            "mise file `{}` withheld ({}): its `nix:` tools are not rolled",
            mise.name,
            config::untrusted_reason(mise.state)
        ));
        return true;
    }
    let outcomes =
        match sandbox::upgrade_tools(nix, layout, cwd, &mise.files, &sandbox::current_system()) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("ops: cannot roll the mise tools: {e}");
                return false;
            }
        };
    for line in upgrade_tools_summary(&outcomes, pal) {
        println!("{line}");
    }
    !outcomes
        .iter()
        .any(|o| matches!(o, sandbox::ToolUpgrade::Failed { .. }))
}

/// The human-readable summary of a mise tools roll: one line per declared tool (rolled,
/// unchanged, newly pinned, or failed), the entries pruned, and any token ops does not
/// handle. Pure, so every outcome is unit-tested without invoking nix.
fn upgrade_tools_summary(outcomes: &[sandbox::ToolUpgrade], pal: &style::Palette) -> Vec<String> {
    use sandbox::ToolUpgrade::*;
    let (h, n, ok, warn, err, dim, r) = (
        pal.head, pal.name, pal.ok, pal.warn, pal.err, pal.dim, pal.reset,
    );
    let mut lines = vec![format!("{h}ops upgrade — mise tools{r}")];
    if outcomes.is_empty() {
        lines.push(format!("  {dim}no nix: tools to roll.{r}"));
        return lines;
    }
    for outcome in outcomes {
        lines.push(match outcome {
            Unchanged { pkg, version, .. } => {
                format!("  {n}nix:{pkg}{r}: {n}{version}{r} — {dim}unchanged.{r}")
            }
            Rolled { pkg, from, to, .. } => {
                format!("  {n}nix:{pkg}{r}: {n}{from}{r} → {n}{to}{r} — {ok}rolled forward.{r}")
            }
            Pinned { pkg, version, .. } => {
                format!("  {n}nix:{pkg}{r}: {n}{version}{r} — {ok}newly pinned.{r}")
            }
            Failed {
                pkg, error, kept, ..
            } => match kept {
                Some(v) => format!(
                    "  {n}nix:{pkg}{r}: {err}re-resolve failed{r}, kept {n}{v}{r} — {error}"
                ),
                None => format!("  {n}nix:{pkg}{r}: {err}re-resolve failed{r} — {error}"),
            },
            Pruned { pkg, request } => format!(
                "  {n}nix:{pkg}{r} ({request}): {dim}removed from the lock (no longer declared).{r}"
            ),
            Ignored {
                token,
                mise_managed,
            } => {
                if *mise_managed {
                    format!("  {n}{token}{r}: {dim}equipped in-cage by mise — not rolled here.{r}")
                } else {
                    format!("  {n}{token}{r}: {warn}malformed nix: token{r} — cannot resolve.")
                }
            }
        });
    }
    lines
}

/// Roll the project's and its apps' `flake:` `[packages]`: re-resolve each declared reference to
/// its current immutable revision and rewrite the per-project flake lock (pinning, rolling, and
/// pruning). Returns whether it succeeded — a reference that fails to re-resolve keeps its prior
/// pin and makes this `false`, but never aborts the others. Trusted-only, like the `nix:` tools:
/// an untrusted project's flake reference is never collected, so there is nothing to roll. Needs
/// nix (to resolve) but not the sandbox boundary — the new pin builds in-cage at the next launch.
fn upgrade_flake_packages(
    nix: &Path,
    layout: &store::Layout,
    cwd: &Path,
    cfg: &config::Resolved,
    pal: &style::Palette,
) -> bool {
    let outcomes = match sandbox::upgrade_flake(nix, layout, cwd, cfg) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("ops: cannot roll the flake packages: {e}");
            return false;
        }
    };
    for line in flake_upgrade_summary(&outcomes, sandbox::withheld_flake_packages(cfg), pal) {
        println!("{line}");
    }
    !outcomes
        .iter()
        .any(|o| matches!(o, sandbox::FlakeUpgrade::Failed { .. }))
}

/// The human-readable summary of a flake roll: one line per declared reference (newly pinned,
/// rolled, unchanged, or failed) plus the entries pruned, and a note for any reference withheld
/// for being untrusted (so an untrusted project does not read as "none declared" — parity with
/// the `nix:` tools path). Pure, so every outcome is unit-tested without invoking nix.
fn flake_upgrade_summary(
    outcomes: &[sandbox::FlakeUpgrade],
    withheld: usize,
    pal: &style::Palette,
) -> Vec<String> {
    use sandbox::FlakeUpgrade::*;
    let (h, n, ok, warn, err, dim, r) = (
        pal.head, pal.name, pal.ok, pal.warn, pal.err, pal.dim, pal.reset,
    );
    let mut lines = vec![format!("{h}ops upgrade — flake packages{r}")];
    let withheld_note = || {
        format!(
            "  {warn}{withheld} flake: package(s) withheld (untrusted){r} — not rolled; run `ops trust`."
        )
    };
    if outcomes.is_empty() {
        lines.push(if withheld > 0 {
            withheld_note()
        } else {
            format!("  {dim}no flake: packages to roll.{r}")
        });
        return lines;
    }
    for outcome in outcomes {
        lines.push(match outcome {
            Unchanged { reference, rev } => format!(
                "  {n}flake:{reference}{r}: {n}{}{r} — {dim}unchanged.{r}",
                short_rev(rev)
            ),
            Rolled {
                reference,
                from,
                to,
            } => format!(
                "  {n}flake:{reference}{r}: {n}{}{r} → {n}{}{r} — {ok}rolled forward.{r}",
                short_rev(from),
                short_rev(to)
            ),
            Pinned { reference, rev } => format!(
                "  {n}flake:{reference}{r}: {n}{}{r} — {ok}newly pinned.{r}",
                short_rev(rev)
            ),
            Pruned { reference } => format!(
                "  {n}flake:{reference}{r}: {dim}removed from the lock (no longer declared).{r}"
            ),
            Failed {
                reference,
                error,
                kept,
            } => match kept {
                Some(rev) => format!(
                    "  {n}flake:{reference}{r}: {err}re-resolve failed{r}, kept {n}{}{r} — {error}",
                    short_rev(rev)
                ),
                None => {
                    format!("  {n}flake:{reference}{r}: {err}re-resolve failed{r} — {error}")
                }
            },
        });
    }
    if withheld > 0 {
        lines.push(withheld_note());
    }
    lines
}

/// The human-readable summary of a channel-style roll (the nix channel or the mise
/// engine): the `heading`, the source under its `item` word (channel/engine) and where it
/// came from, then what changed — a first resolution, an unchanged channel, a fixed
/// revision that cannot roll, or a roll-forward — naming what `downloads`/re-provisions on
/// the next launch. Pure, so every outcome is unit-tested without invoking nix.
fn channel_upgrade_summary(
    heading: &str,
    item: &str,
    downloads: &str,
    origin: &str,
    up: &store::Upgrade,
    pal: &style::Palette,
) -> Vec<String> {
    let (h, n, ok, dim, r) = (pal.head, pal.name, pal.ok, pal.dim, pal.reset);
    let mut lines = vec![
        format!("{h}{heading}{r}"),
        format!("  {item}: {n}{}{r}  ({dim}{origin}{r})", up.source),
    ];
    let outcome = match &up.previous {
        None => format!(
            "  resolved to {n}{}{r} {ok}(first pin){r} — {downloads} on the next launch.",
            short_rev(&up.revision)
        ),
        Some(prev) if prev == &up.revision && store::is_pinned_revision(&up.source) => format!(
            "  pinned to a fixed revision {n}{}{r} — {dim}nothing to roll.{r}",
            short_rev(&up.revision)
        ),
        Some(prev) if prev == &up.revision => format!(
            "  already at the latest revision {n}{}{r} — {dim}nothing to do.{r}",
            short_rev(&up.revision)
        ),
        Some(prev) => format!(
            "  {ok}rolled forward{r} {n}{}{r} → {n}{}{r} — {downloads} on the next launch.",
            short_rev(prev),
            short_rev(&up.revision)
        ),
    };
    lines.push(outcome);
    lines
}

/// A short revision for display — the first seven hex characters, like git.
fn short_rev(rev: &str) -> &str {
    &rev[..rev.len().min(7)]
}

/// Seconds since boot, from `/proc/uptime` (its first field). Used only to show a
/// session's age, so a parse failure degrades to "unknown", never an error.
fn uptime_seconds() -> Option<f64> {
    std::fs::read_to_string("/proc/uptime")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// A compact age like `2h05m` or `4m07s`.
fn format_age(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h{m:02}m")
    } else {
        format!("{m}m{s:02}s")
    }
}

/// Best-effort nix version (the first line of `nix --version`). The version is
/// store-independent, so it runs nix directly.
fn nix_version(nix: &Path) -> Option<String> {
    let out = std::process::Command::new(nix)
        .arg("--version")
        .output()
        .ok()?;
    out.status.success().then(|| {
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_string()
    })
}

/// Outcome of probing unprivileged user-namespace support.
#[derive(Debug, PartialEq, Eq)]
enum Userns {
    /// A capability-bearing user namespace can be created — bwrap will work.
    Ok,
    /// `unshare(CLONE_NEWUSER)` itself fails — userns disabled outright.
    Unsupported,
    /// The namespace is created but stripped of capabilities (the restricted
    /// Ubuntu 24.04+ default): `unshare(CLONE_NEWUSER)` succeeds, yet the child
    /// cannot create the further namespaces bwrap needs. It looks available but
    /// is not — so it must be reported distinctly from outright absence.
    CapStripped,
}

/// Map the probe child's exit status to an outcome. Kept separate from the
/// unsafe fork machinery so this policy is unit-testable: the child exits `1`
/// when the user namespace cannot be created, `2` when it is created but lacks
/// the capabilities to nest a mount namespace, and `0` when both succeed.
fn classify_probe_exit(code: i32) -> Userns {
    match code {
        0 => Userns::Ok,
        2 => Userns::CapStripped,
        _ => Userns::Unsupported,
    }
}

/// Ground-truth probe in a forked child: create a user namespace, then create a
/// mount namespace inside it. The second step needs `CAP_SYS_ADMIN` in the new
/// userns, so it succeeds only when the namespace is capability-bearing — which
/// is exactly what bubblewrap requires. Doing it in a child keeps the parent's
/// namespaces untouched; only a real attempt is decisive (sysctls can lie).
fn probe_userns() -> Userns {
    // SAFETY: the child path touches only async-signal-safe calls (`unshare`,
    // `_exit`) before exiting; the parent only reaps it and classifies.
    unsafe {
        match libc::fork() {
            0 => {
                if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                    libc::_exit(1);
                }
                if libc::unshare(libc::CLONE_NEWNS) != 0 {
                    libc::_exit(2);
                }
                libc::_exit(0);
            }
            -1 => Userns::Unsupported,
            pid => {
                let mut status: libc::c_int = 0;
                if libc::waitpid(pid, &mut status, 0) == -1 || !libc::WIFEXITED(status) {
                    return Userns::Unsupported;
                }
                classify_probe_exit(libc::WEXITSTATUS(status))
            }
        }
    }
}

fn read_sysctl(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    #[test]
    fn read_sysctl_trims_value_and_handles_absence() {
        let dir = TmpDir::new();
        let f = dir.join("val");
        std::fs::write(&f, b"1\n").unwrap();
        assert_eq!(read_sysctl(f.to_str().unwrap()).as_deref(), Some("1"));
        assert_eq!(read_sysctl(dir.join("nope").to_str().unwrap()), None);
    }

    #[test]
    fn classify_probe_exit_maps_status_to_outcome() {
        assert_eq!(classify_probe_exit(0), Userns::Ok);
        assert_eq!(classify_probe_exit(2), Userns::CapStripped);
        assert_eq!(classify_probe_exit(1), Userns::Unsupported);
        assert_eq!(classify_probe_exit(42), Userns::Unsupported);
    }

    #[test]
    fn short_rev_takes_the_first_seven_hex() {
        assert_eq!(
            short_rev("9ae611a455b90cf061d8f332b977e387bda8e1ca"),
            "9ae611a"
        );
        assert_eq!(short_rev("abc"), "abc"); // shorter than seven is returned whole
    }

    #[test]
    fn net_decision_is_plain_text_when_uncolored() {
        // The OFF path the integration capture relies on: empty spans, byte-identical plain text.
        let p = style::Palette::plain();
        let allowed = render_net_decision("https://x/y", &allowlist::Decision::DeniedDefault, &p);
        assert_eq!(
            allowed,
            "DENIED   https://x/y\n  no allow rule matches (deny-by-default)\n"
        );
    }

    #[test]
    fn net_decision_colors_the_verdict_and_resets() {
        // The ON path: DENIED is wrapped in the error span and closed with a reset, the URL in
        // the name span — a mis-mapped verdict or a dropped reset would only ever show here.
        let p = style::Palette::colored();
        let denied = render_net_decision("https://x/y", &allowlist::Decision::DeniedDefault, &p);
        assert!(
            denied.contains(&format!("{}DENIED{}", p.err, p.reset)),
            "DENIED must be wrapped in the error span and reset:\n{denied}"
        );
        assert!(
            denied.contains(&format!("{}https://x/y{}", p.name, p.reset)),
            "the URL must be wrapped in the name span:\n{denied}"
        );
    }

    #[test]
    fn trust_verdict_is_plain_text_when_uncolored() {
        let p = style::Palette::plain();
        let path = Path::new("/p/.ops.toml");
        assert_eq!(
            render_trust_verdict(path, trust::TrustState::Trusted, &p),
            "ops: /p/.ops.toml is trusted"
        );
        assert_eq!(
            render_trust_verdict(path, trust::TrustState::Untrusted, &p),
            "ops: /p/.ops.toml is untrusted"
        );
        assert_eq!(
            render_trust_verdict(path, trust::TrustState::Changed, &p),
            "ops: /p/.ops.toml is changed since it was trusted — re-run `ops trust` to re-approve"
        );
    }

    #[test]
    fn trust_verdict_maps_each_state_to_its_hue_and_resets() {
        // The ON path: each state word takes its own span (green/yellow/red) and resets — a
        // swapped hue (the failure plain output cannot see) is caught here.
        let p = style::Palette::colored();
        let path = Path::new("/p/.ops.toml");
        let cases = [
            (trust::TrustState::Trusted, p.ok, "trusted"),
            (trust::TrustState::Untrusted, p.warn, "untrusted"),
            (trust::TrustState::Changed, p.err, "changed"),
        ];
        for (state, span, word) in cases {
            let out = render_trust_verdict(path, state, &p);
            assert!(
                out.contains(&format!("{span}{word}{}", p.reset)),
                "{word} must be wrapped in its own span and reset:\n{out}"
            );
        }
    }

    #[test]
    fn trust_confirmations_are_plain_text_when_uncolored() {
        let p = style::Palette::plain();
        let path = Path::new("/p/.ops.toml");
        assert_eq!(render_trust_recorded(path, &p), "ops: trusted /p/.ops.toml");
        assert_eq!(
            render_untrust_result(path, true, &p),
            "ops: revoked trust for /p/.ops.toml"
        );
        assert_eq!(
            render_untrust_result(path, false, &p),
            "ops: /p/.ops.toml was not trusted; nothing to revoke"
        );
    }

    #[test]
    fn trust_confirmations_carry_the_resulting_state_hue() {
        // The ON path: `trusted` green (matching the verdict), `revoked` yellow (the result is the
        // untrusted default), and the no-op note dimmed — each closed with a reset.
        let p = style::Palette::colored();
        let path = Path::new("/p/.ops.toml");
        assert!(
            render_trust_recorded(path, &p).contains(&format!("{}trusted{}", p.ok, p.reset)),
            "a recorded trust must show `trusted` in green"
        );
        assert!(
            render_untrust_result(path, true, &p)
                .contains(&format!("{}revoked{}", p.warn, p.reset)),
            "a revocation must show `revoked` in the caution hue"
        );
        assert!(
            render_untrust_result(path, false, &p)
                .contains(&format!("{}nothing to revoke{}", p.dim, p.reset)),
            "a no-op revocation must dim the note"
        );
    }

    #[test]
    fn upgrade_summary_distinguishes_the_outcomes() {
        let rev = "9ae611a455b90cf061d8f332b977e387bda8e1ca";
        let newer = "1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c";
        let text = |up| {
            channel_upgrade_summary(
                "ops upgrade — nix channel",
                "channel",
                "the new base and tools download",
                "default",
                &up,
                &style::Palette::plain(),
            )
            .join("\n")
        };

        // a first resolution
        assert!(text(store::Upgrade {
            source: "nixos-unstable".into(),
            previous: None,
            revision: rev.into(),
        })
        .contains("first pin"));

        // an unchanged channel
        assert!(text(store::Upgrade {
            source: "nixos-unstable".into(),
            previous: Some(rev.into()),
            revision: rev.into(),
        })
        .contains("already at the latest"));

        // a fixed revision pin cannot roll
        assert!(text(store::Upgrade {
            source: rev.into(),
            previous: Some(rev.into()),
            revision: rev.into(),
        })
        .contains("fixed revision"));

        // a roll-forward shows old → new
        let rolled = text(store::Upgrade {
            source: "nixos-unstable".into(),
            previous: Some(rev.into()),
            revision: newer.into(),
        });
        assert!(rolled.contains("rolled forward"));
        assert!(rolled.contains("9ae611a") && rolled.contains("1c1c1c1"));

        // the same renderer, parameterised for the mise engine: a distinct heading, the
        // `engine` item word, and the engine-specific "provisioned" tail — so the two
        // roll commands read differently.
        let engine = channel_upgrade_summary(
            "ops upgrade — mise engine",
            "engine",
            "the new engine is provisioned",
            "default",
            &store::Upgrade {
                source: "nixos-unstable".into(),
                previous: Some(rev.into()),
                revision: newer.into(),
            },
            &style::Palette::plain(),
        )
        .join("\n");
        assert!(engine.contains("mise engine"));
        assert!(engine.contains("engine: nixos-unstable"));
        assert!(engine.contains("the new engine is provisioned"));
        assert!(!engine.contains("base and tools"));

        // Colored: the heading rides the head span and the roll-forward outcome the ok span,
        // each closed by a reset — the feature a captured (plain) stream never exercises.
        let p = style::Palette::colored();
        let colored = channel_upgrade_summary(
            "ops upgrade — nix channel",
            "channel",
            "the new base and tools download",
            "default",
            &store::Upgrade {
                source: "nixos-unstable".into(),
                previous: Some(rev.into()),
                revision: newer.into(),
            },
            &p,
        )
        .join("\n");
        assert!(colored.contains(&format!("{}ops upgrade — nix channel{}", p.head, p.reset)));
        assert!(colored.contains(&format!("{}rolled forward{}", p.ok, p.reset)));
    }

    #[test]
    fn upgrade_mise_and_upgrade_nix_roll_separate_locks() {
        // The decoupling guarantee at the file level: rolling the engine must leave the
        // base channel lock byte-identical, and rolling the base must leave the engine
        // lock byte-identical. Proven deterministically with revision sources, which
        // resolve without nix — so a bogus nix path is never invoked. The roll mechanics
        // are already covered by store.rs's `refresh*` tests (which `LockTarget::engine`
        // reuses verbatim); what is net-new here is that the two commands write two
        // distinct files.
        let bogus_nix = Path::new("/nonexistent-nix");
        let rev_a = "a".repeat(40);
        let rev_b = "b".repeat(40);
        let cfg = |global: &str| config::Resolved {
            env: vec![],
            env_layer: Default::default(),
            ro_binds: vec![],
            bind_layer: Default::default(),
            packages: vec![],
            nixpkgs_global: Some(global.to_string()),
            nixpkgs_project: None,
            mise: None,
            network: config::NetworkPolicy::default(),
            network_origin: Default::default(),
            gui: config::GuiPolicy::default(),
            gui_origin: Default::default(),
            limits: Default::default(),
            limits_origin: Default::default(),
            secrets: vec![],
            apps: std::collections::BTreeMap::new(),
            warnings: vec![],
        };

        let data = TmpDir::new();
        let layout = store::Layout::under(data.path());
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        let nix_lock = layout.data_dir().join("nixpkgs.lock");
        let engine_lock = layout.data_dir().join("mise-engine.lock");

        // seed both locks at REV_A (same global override, so each resolves REV_A with no nix)
        let plain = style::Palette::plain();
        assert!(upgrade_mise_engine(
            bogus_nix,
            &layout,
            &cfg(&rev_a),
            &plain
        ));
        assert!(upgrade_nix_channel(
            bogus_nix,
            &layout,
            data.path(),
            &cfg(&rev_a),
            &plain
        ));
        let nix_seed = std::fs::read(&nix_lock).unwrap();

        // roll ONLY the engine to REV_B: the base lock is untouched, the engine advanced
        assert!(upgrade_mise_engine(
            bogus_nix,
            &layout,
            &cfg(&rev_b),
            &plain
        ));
        assert_eq!(
            std::fs::read(&nix_lock).unwrap(),
            nix_seed,
            "upgrade mise must not touch nixpkgs.lock"
        );
        assert!(
            std::fs::read_to_string(&engine_lock)
                .unwrap()
                .contains(&rev_b),
            "the engine lock advanced to REV_B"
        );

        // re-seed the engine at REV_A, then roll ONLY the base to REV_B: now the engine
        // lock is untouched and the base advanced
        assert!(upgrade_mise_engine(
            bogus_nix,
            &layout,
            &cfg(&rev_a),
            &plain
        ));
        let engine_reseed = std::fs::read(&engine_lock).unwrap();
        assert!(upgrade_nix_channel(
            bogus_nix,
            &layout,
            data.path(),
            &cfg(&rev_b),
            &plain
        ));
        assert_eq!(
            std::fs::read(&engine_lock).unwrap(),
            engine_reseed,
            "upgrade nix must not touch mise-engine.lock"
        );
        assert!(
            std::fs::read_to_string(&nix_lock).unwrap().contains(&rev_b),
            "the base lock advanced to REV_B"
        );
    }

    #[test]
    fn upgrade_tools_summary_distinguishes_the_outcomes() {
        use sandbox::ToolUpgrade::*;

        // an empty roll (no nix: tools, or no mise file) says so plainly
        let empty = upgrade_tools_summary(&[], &style::Palette::plain()).join("\n");
        assert!(empty.contains("no nix: tools"));

        let text = upgrade_tools_summary(
            &[
                Unchanged {
                    pkg: "jq".into(),
                    request: "1.7.1".into(),
                    version: "1.7.1".into(),
                },
                Rolled {
                    pkg: "ripgrep".into(),
                    request: "latest".into(),
                    from: "14.1.0".into(),
                    to: "14.1.1".into(),
                },
                Pinned {
                    pkg: "nodejs".into(),
                    request: "20".into(),
                    version: "20.11.0".into(),
                },
                Failed {
                    pkg: "fd".into(),
                    request: "latest".into(),
                    error: "nixhub unreachable".into(),
                    kept: Some("9.0.0".into()),
                },
                Failed {
                    pkg: "bat".into(),
                    request: "latest".into(),
                    error: "nixhub unreachable".into(),
                    kept: None,
                },
                Pruned {
                    pkg: "oldtool".into(),
                    request: "1.0".into(),
                },
                Ignored {
                    token: "node".into(),
                    mise_managed: true,
                },
                Ignored {
                    token: "nix:bad name".into(),
                    mise_managed: false,
                },
            ],
            &style::Palette::plain(),
        )
        .join("\n");

        assert!(text.contains("nix:jq: 1.7.1 — unchanged"));
        assert!(text.contains("nix:ripgrep: 14.1.0 → 14.1.1 — rolled forward"));
        assert!(text.contains("nix:nodejs: 20.11.0 — newly pinned"));
        assert!(text.contains("nix:fd: re-resolve failed, kept 9.0.0"));
        assert!(text.contains("nix:bat: re-resolve failed — nixhub unreachable"));
        assert!(text.contains("nix:oldtool (1.0): removed from the lock"));
        assert!(text.contains("node: equipped in-cage by mise — not rolled here"));
        assert!(text.contains("nix:bad name: malformed nix: token — cannot resolve"));

        // Colored: the package identifier rides the name span and the failure rides err.
        let p = style::Palette::colored();
        let colored = upgrade_tools_summary(
            &[Failed {
                pkg: "fd".into(),
                request: "latest".into(),
                error: "nixhub unreachable".into(),
                kept: None,
            }],
            &p,
        )
        .join("\n");
        assert!(colored.contains(&format!("{}nix:fd{}", p.name, p.reset)));
        assert!(colored.contains(&format!("{}re-resolve failed{}", p.err, p.reset)));
    }

    #[test]
    fn flake_upgrade_summary_distinguishes_the_outcomes() {
        use sandbox::FlakeUpgrade::*;

        // an empty roll (no flake: packages) says so plainly
        let empty = flake_upgrade_summary(&[], 0, &style::Palette::plain()).join("\n");
        assert!(empty.contains("no flake: packages"));

        // an empty roll on an untrusted project names the withheld package instead of "none"
        let withheld = flake_upgrade_summary(&[], 2, &style::Palette::plain()).join("\n");
        assert!(withheld.contains("2 flake: package(s) withheld (untrusted)"));
        assert!(!withheld.contains("no flake: packages"));

        let rev_a = "11707dc2f618dd54ca8739b309ec4fc024de578b";
        let rev_b = "9ae611a455b90cf061d8f332b977e387bda8e1ca";
        let text = flake_upgrade_summary(
            &[
                Unchanged {
                    reference: "github:o/a#default".into(),
                    rev: rev_a.into(),
                },
                Rolled {
                    reference: "github:o/b#default".into(),
                    from: rev_a.into(),
                    to: rev_b.into(),
                },
                Pinned {
                    reference: "github:o/c".into(),
                    rev: rev_b.into(),
                },
                Pruned {
                    reference: "github:o/old#x".into(),
                },
                Failed {
                    reference: "github:o/d#default".into(),
                    error: "metadata unreachable".into(),
                    kept: Some(rev_a.into()),
                },
                Failed {
                    reference: "github:o/e#default".into(),
                    error: "metadata unreachable".into(),
                    kept: None,
                },
            ],
            0,
            &style::Palette::plain(),
        )
        .join("\n");

        // Revisions are shortened to the first seven hex in the report.
        assert!(text.contains("flake:github:o/a#default: 11707dc — unchanged"));
        assert!(text.contains("flake:github:o/b#default: 11707dc → 9ae611a — rolled forward"));
        assert!(text.contains("flake:github:o/c: 9ae611a — newly pinned"));
        assert!(text.contains("flake:github:o/old#x: removed from the lock"));
        assert!(text.contains("flake:github:o/d#default: re-resolve failed, kept 11707dc"));
        assert!(text.contains("flake:github:o/e#default: re-resolve failed — metadata unreachable"));

        // Colored: the reference rides the name span and the withheld note rides warn.
        let p = style::Palette::colored();
        let colored = flake_upgrade_summary(
            &[Pinned {
                reference: "github:o/c".into(),
                rev: rev_b.into(),
            }],
            2,
            &p,
        )
        .join("\n");
        assert!(colored.contains(&format!("{}flake:github:o/c{}", p.name, p.reset)));
        assert!(colored.contains(&format!("{}newly pinned.{}", p.ok, p.reset)));
        assert!(colored.contains(&format!(
            "{}2 flake: package(s) withheld (untrusted){}",
            p.warn, p.reset
        )));
    }

    #[test]
    fn transactional_confirmations_are_plain_text_when_uncolored() {
        // The OFF path the integration capture and the existing substring assertions rely on:
        // empty spans, byte-identical plain text. Each line of the original wording is preserved.
        let p = style::Palette::plain();
        assert_eq!(
            render_plugin_installed("pass", "pass", None, &p),
            "installed 'pass' (pass://) — remove with: ops plugins rm pass"
        );
        assert_eq!(
            render_plugin_installed("vault", "vault", Some("hub"), &p),
            "installed 'vault' (vault://) from store 'hub' — remove with: ops plugins rm vault"
        );
        assert_eq!(render_removed(None, "pass", &p), "removed 'pass'");
        assert_eq!(
            render_removed(Some("store"), "hub", &p),
            "removed store 'hub'"
        );
        assert_eq!(
            render_removed(Some("app profile"), "demo-app", &p),
            "removed app profile 'demo-app'"
        );
        assert_eq!(
            render_store_tofu("ab12", "hub", &p),
            "⚠ trust-on-first-use: pinned the key this store ships, unverified\n  \
             pinned key: ab12\n  \
             verify it out of band; re-shown by `ops plugins store info hub`"
        );
        assert_eq!(
            render_store_configured("hub", 3, &[("vault", "vault", "1.0"), ("pass", "pass", "")], &p),
            "configured store 'hub' (rev 3, 2 plugins):\n  vault  (vault://)  v1.0\n  pass  (pass://)\n"
        );
        assert_eq!(
            render_publish_key_warning(Path::new("/k/key.pem"), &p),
            "⚠ keep the signing key `/k/key.pem` secret — it is this store's identity"
        );
        assert_eq!(
            render_published(5, &[("vault", "vault")], "deadbeef", &p),
            "published store at rev 5 (1 plugin):\n  vault  (vault://)\npubkey: deadbeef\n\
             commit and host the directory, then consumers add it with: \
             ops plugins store add --name <n> --url <git-url> --key deadbeef"
        );
        assert_eq!(
            render_store_updated("hub", 3, 5, 2, &p),
            "updated store 'hub' (rev 3 → 5, 2 plugins)"
        );
        assert_eq!(
            render_store_updated("hub", 5, 5, 1, &p),
            "store 'hub' is already at revision 5 (1 plugin)"
        );
        assert_eq!(
            render_app_imported(
                "demo-app",
                Path::new("/c/demo-app.toml"),
                &["command: x".into(), "network: allowlist".into()],
                &p
            ),
            "imported app profile 'demo-app' -> /c/demo-app.toml\n  \
             granted posture (trusted by location — honored even on an untrusted project):\n    \
             command: x\n    network: allowlist\n  launch it with: ops app demo-app"
        );
        assert_eq!(
            render_app_exported("demo-app", Path::new("/c/out.toml"), &p),
            "exported app `demo-app` -> /c/out.toml"
        );
        let cfg = Path::new("/p/.ops.toml");
        assert_eq!(
            render_config_write("set", "env.FOO", cfg, &p),
            "ops: set `env.FOO` in /p/.ops.toml"
        );
        assert_eq!(
            render_config_write("unset", "env.FOO", cfg, &p),
            "ops: unset `env.FOO` in /p/.ops.toml"
        );
        assert_eq!(
            render_config_unchanged("env.FOO", cfg, &p),
            "ops: `env.FOO` was not set in /p/.ops.toml"
        );
        assert_eq!(
            render_trusted_whole_file(cfg, &p),
            "ops: trusted /p/.ops.toml (the whole file is now trusted)"
        );
    }

    #[test]
    fn transactional_confirmations_color_their_key_spans() {
        // The ON path: the success verb takes the `ok` hue, a caution takes `warn`, a no-op takes
        // `dim`, and identifiers ride the `name` span — a swapped hue (invisible to the plain
        // assertions above) only shows here.
        let p = style::Palette::colored();

        let installed = render_plugin_installed("pass", "pass", None, &p);
        assert!(installed.contains(&format!("{}installed{}", p.ok, p.reset)));
        assert!(installed.contains(&format!("'{}pass{}'", p.name, p.reset)));

        assert!(render_removed(Some("store"), "hub", &p)
            .contains(&format!("{}removed{}", p.ok, p.reset)));

        let tofu = render_store_tofu("ab12", "hub", &p);
        assert!(
            tofu.contains(p.warn),
            "the tofu caution must ride the warn hue:\n{tofu}"
        );
        assert!(tofu.contains(&format!("{}ab12{}", p.name, p.reset)));

        let configured = render_store_configured("hub", 3, &[("vault", "vault", "1.0")], &p);
        assert!(configured.contains(&format!("{}configured store{}", p.ok, p.reset)));
        assert!(configured.contains(&format!("{}vault{}", p.name, p.reset)));

        let keywarn = render_publish_key_warning(Path::new("/k/key.pem"), &p);
        assert!(
            keywarn.contains(p.warn),
            "the key caution must ride the warn hue:\n{keywarn}"
        );

        let published = render_published(5, &[("vault", "vault")], "deadbeef", &p);
        assert!(published.contains(&format!("{}published store{}", p.ok, p.reset)));
        assert!(published.contains(&format!("{}deadbeef{}", p.name, p.reset)));

        let rolled = render_store_updated("hub", 3, 5, 2, &p);
        assert!(rolled.contains(&format!("{}updated store{}", p.ok, p.reset)));
        let noop = render_store_updated("hub", 5, 5, 1, &p);
        assert!(
            noop.contains(p.dim),
            "a no-op update must take the dim hue:\n{noop}"
        );

        let imported = render_app_imported("demo-app", Path::new("/c/demo-app.toml"), &[], &p);
        assert!(imported.contains(&format!("{}imported{}", p.ok, p.reset)));
        assert!(imported.contains(&format!("'{}demo-app{}'", p.name, p.reset)));

        let exported = render_app_exported("demo-app", Path::new("/c/out.toml"), &p);
        assert!(exported.contains(&format!("{}exported{}", p.ok, p.reset)));

        let cfg = Path::new("/p/.ops.toml");
        let set = render_config_write("set", "env.FOO", cfg, &p);
        assert!(set.contains(&format!("{}set{}", p.ok, p.reset)));
        assert!(set.contains(&format!("`{}env.FOO{}`", p.name, p.reset)));
        let unchanged = render_config_unchanged("env.FOO", cfg, &p);
        assert!(
            unchanged.contains(p.dim),
            "a no-op config write must take the dim hue:\n{unchanged}"
        );
        let retrust = render_trusted_whole_file(cfg, &p);
        assert!(retrust.contains(&format!("{}trusted{}", p.ok, p.reset)));
    }

    /// A representative resolved view: an untrusted project that withholds a `nix:` package and its
    /// mise file, a project-pinned base channel (with a locked revision) beside the default engine,
    /// and an allowlist carrying a deny rule. Built by hand so the render tests need no I/O.
    fn sample_config_view() -> config::view::ConfigView {
        use config::view::*;
        ConfigView {
            cwd: "/proj".into(),
            env: vec![EnvVar {
                key: "EDITOR".into(),
                value: "vim".into(),
                layer: Some(ProvenanceView::Project),
            }],
            binds: vec![BindView {
                path: "/data".into(),
                layer: Some(ProvenanceView::Global),
            }],
            packages: vec![PackageView {
                name: "jq".into(),
                backend: "nix".into(),
                locator: "jq".into(),
                realised: "host-side, durable".into(),
                trusted: false,
                withheld_reason: Some("the project is untrusted".into()),
                pinned_rev: None,
            }],
            mise: Some(MiseView {
                name: ".mise.toml".into(),
                trusted: false,
                withheld_reason: Some("the project is untrusted".into()),
            }),
            tools: ToolsView::default(),
            nixpkgs: ChannelView {
                source: "nixos-23.11".into(),
                origin: "project pin".into(),
                locked_rev: Some("9ae611a455b90cf061d8f332b977e387bda8e1ca".into()),
            },
            engine: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            network: NetworkView::Allowlist {
                allow: vec!["github.com".into()],
                deny: vec!["evil.com".into()],
                builtin: vec!["cache.nixos.org".into()],
            },
            network_origin: ProvenanceView::Project,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            limits: Default::default(),
            secrets: vec![],
            apps: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn config_render_is_plain_text_when_uncolored() {
        // The OFF path the `ops config show` integration assertions stand on: empty spans, so the
        // wording and spacing are exactly today's — a withheld note, a channel line (with and
        // without a locked revision), and a deny rule.
        let out = render_config(&sample_config_view(), &style::Palette::plain(), false);
        assert!(
            out.contains("    jq -> nix:jq  (withheld: the project is untrusted)"),
            "{out}"
        );
        assert!(
            out.contains("  mise:  .mise.toml (withheld: the project is untrusted)"),
            "{out}"
        );
        assert!(
            out.contains("  nixpkgs: nixos-23.11 @ 9ae611a  (project pin)"),
            "{out}"
        );
        assert!(out.contains("  engine: nixos-unstable  (default)"), "{out}");
        assert!(out.contains("    deny  evil.com"), "{out}");
        // The free-field provenance tag is plain parenthesized text on its line.
        assert!(out.contains("    EDITOR=vim  (project)"), "{out}");
        assert!(out.contains("    /data  (global)"), "{out}");
    }

    #[test]
    fn config_render_colors_the_gating_outcome_and_the_channel_provenance() {
        // The ON path: a withheld value takes the warn hue (the trust gate dropped it), a channel's
        // provenance origin is hued by level (a project pin green) and its source rides the name
        // span, its short revision is dim, and the deny keyword is warn — the inheritance/gating
        // story a swapped hue would hide.
        let p = style::Palette::colored();
        let out = render_config(&sample_config_view(), &p, false);
        assert!(
            out.contains(&format!(
                "{}(withheld: the project is untrusted){}",
                p.warn, p.reset
            )),
            "a withheld package must take the warn hue:\n{out}"
        );
        assert!(
            out.contains(&format!("{}nixos-23.11{}", p.name, p.reset)),
            "a channel source must ride the name span:\n{out}"
        );
        assert!(
            out.contains(&format!("({}project pin{})", p.ok, p.reset)),
            "a channel origin must be hued by provenance level — a project pin is green:\n{out}"
        );
        assert!(
            out.contains(&format!("{}9ae611a{}", p.dim, p.reset)),
            "a locked revision must be dimmed:\n{out}"
        );
        assert!(
            out.contains(&format!("{}deny{}", p.warn, p.reset)),
            "the deny keyword must take the caution hue:\n{out}"
        );
        // The provenance tag is hued by level: a project source is green, a global source is cyan
        // (a default/inherited one stays dim). The env value here is project-supplied, the bind
        // global-supplied, so the two tags carry their respective hues.
        assert!(
            out.contains(&format!("{}(project){}", p.ok, p.reset)),
            "a project provenance tag must take the green hue:\n{out}"
        );
        assert!(
            out.contains(&format!("{}(global){}", p.name, p.reset)),
            "a global provenance tag must take the cyan hue:\n{out}"
        );
    }

    #[test]
    fn channel_origin_kind_tracks_the_real_store_origin_labels() {
        // `channel_origin_kind` colors by matching the channel's origin *label* — a string coupling
        // to `store::Origin::label()`. Route the REAL labels through it so a rename in store.rs
        // fails here loudly, instead of silently degrading that channel's origin to the dim default.
        use config::view::ProvenanceView;
        assert_eq!(
            channel_origin_kind(store::Origin::Default.label()),
            ProvenanceView::Default
        );
        assert_eq!(
            channel_origin_kind(store::Origin::Global.label()),
            ProvenanceView::Global
        );
        assert_eq!(
            channel_origin_kind(store::Origin::ProjectPin.label()),
            ProvenanceView::Project
        );
    }

    #[test]
    fn config_render_tags_the_network_and_gui_posture_with_their_origin() {
        use config::view::{GuiView, ProvenanceView};
        let plain = style::Palette::plain();

        // The headline of the provenance work: the always-shown `network` line names where its
        // posture came from. The sample's allowlist is project-supplied, so it reads `(project)`.
        let out = render_config(&sample_config_view(), &plain, false);
        assert!(
            out.contains("network: allowlist  (project)"),
            "the network posture must carry its project origin:\n{out}"
        );

        // A posture no config set reads `(default)` — the distinction the user could not see
        // before (is the network open because I chose it, or because nothing set it?).
        let mut view = sample_config_view();
        view.network = config::view::NetworkView::Shared;
        view.network_origin = ProvenanceView::Default;
        let out = render_config(&view, &plain, false);
        assert!(
            out.contains("network: shared (host network)  (default)"),
            "an unset network posture must read default:\n{out}"
        );

        // The GUI line, shown only when opened, names its origin too.
        view.gui = GuiView::Wayland;
        view.gui_origin = ProvenanceView::Global;
        let out = render_config(&view, &plain, false);
        assert!(
            out.contains("gui: wayland (exposure depends on your compositor)  (global)"),
            "the gui posture must carry its global origin:\n{out}"
        );
    }

    #[test]
    fn render_app_detail_shows_effective_values_tagged_inherited_or_app_set() {
        use config::view::*;
        let p = style::Palette::plain();
        let view = AppDetailView {
            name: "demo".into(),
            cwd: "/proj".into(),
            cmd: Some("demo-agent".into()),
            cmd_origin: ProvenanceView::Global,
            home_scope: "global (shared across projects)".into(),
            home_scope_origin: ProvenanceView::Default,
            network: NetworkView::Allowlist {
                allow: vec!["api.example.com".into()],
                deny: vec![],
                builtin: vec!["cache.nixos.org".into()],
            },
            network_origin: ProvenanceView::Global,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Inherited,
            limits: LimitsView {
                memory_high: LimitView {
                    value: "70%".into(),
                    origin: ProvenanceView::Inherited,
                },
                memory_max: LimitView {
                    value: "90%".into(),
                    origin: ProvenanceView::Inherited,
                },
                tasks_max: LimitView {
                    value: "2048".into(),
                    origin: ProvenanceView::Project,
                },
            },
            env: vec![AppEnvVar {
                key: "DEMO_TOKEN".into(),
                value: "placeholder".into(),
            }],
            env_inherited: 2,
            binds: vec![],
            binds_inherited: 0,
            packages: vec![],
            packages_inherited: 0,
            secrets: vec![],
            secrets_inherited: 0,
            notes: vec![],
        };

        // Compact: each scalar carries its effective value + app-context provenance — the headline
        // being that an unset field reads `inherited` (its effective value comes from the baseline).
        let out = render_app_detail(&view, &p, false);
        assert!(out.contains("cmd:     demo-agent  (app:global)"), "{out}");
        assert!(out.contains("gui:     none  (inherited)"), "{out}");
        assert!(out.contains("network: allowlist  (app:global)"), "{out}");
        assert!(out.contains("(1 allow, 0 deny — see --details)"), "{out}");
        // Per-field limits: two inherited from the baseline, the task cap set by the app.
        assert!(out.contains("MemoryHigh=70% (inherited)"), "{out}");
        assert!(out.contains("TasksMax=2048 (app:project)"), "{out}");
        // Collections summarize the overlay's own count and the inherited baseline count.
        assert!(out.contains("1 own  · inherits 2 baseline"), "{out}");

        // Details expand the allowlist rules and the overlay's own env entries.
        let detailed = render_app_detail(&view, &p, true);
        assert!(detailed.contains("    allow api.example.com"), "{detailed}");
        assert!(
            detailed.contains("    DEMO_TOKEN=placeholder"),
            "{detailed}"
        );
    }

    #[test]
    fn app_prefixed_key_rewrites_a_simple_name_and_rejects_a_dotted_one() {
        // The `--app` sugar puts the key under the app's table; a dotted leaf key composes.
        assert_eq!(
            app_prefixed_key("demo", "network").unwrap(),
            "app.demo.network"
        );
        assert_eq!(
            app_prefixed_key("demo", "env.FOO").unwrap(),
            "app.demo.env.FOO"
        );
        // A name with a `.` is not one TOML segment under the naive key splitter — point at `edit`.
        let err = app_prefixed_key("my.app", "cmd").unwrap_err();
        assert!(err.contains("ops config edit"), "{err}");
        // A name no app could ever carry is rejected outright.
        assert!(app_prefixed_key("bad name", "cmd").is_err());
    }

    #[test]
    fn set_show_source_rejects_a_conflicting_second_flag() {
        let mut src: Option<(&'static str, config::Source)> = None;
        assert!(set_show_source(&mut src, "--global", config::Source::Global).is_ok());
        // The same flag repeated is harmless (no conflict).
        assert!(set_show_source(&mut src, "--global", config::Source::Global).is_ok());
        // A different source flag is a conflict, not last-wins.
        assert!(set_show_source(&mut src, "--local", config::Source::Local).is_err());
    }

    #[test]
    fn split_scope_accepts_the_short_scope_flags() {
        use config::manage::Scope;
        let osv = |parts: &[&str]| -> Vec<OsString> { parts.iter().map(OsString::from).collect() };

        // `-l`/`-g` alias `--local`/`--global`; `-a` aliases `--app`.
        let parsed = split_scope(&osv(&["network", "-g"])).unwrap();
        assert!(matches!(parsed.scope, Scope::Global));
        assert_eq!(parsed.positionals, vec!["network".to_string()]);

        let parsed = split_scope(&osv(&["-l", "network"])).unwrap();
        assert!(matches!(parsed.scope, Scope::Local));

        let parsed = split_scope(&osv(&["-a", "demo", "cmd"])).unwrap();
        assert_eq!(parsed.app.as_deref(), Some("demo"));
        assert_eq!(parsed.positionals, vec!["cmd".to_string()]);

        // `-c <file>` is unchanged and still needs its argument.
        let parsed = split_scope(&osv(&["-c", "/tmp/x.toml", "k"])).unwrap();
        assert!(matches!(parsed.scope, Scope::File(_)));
        assert!(split_scope(&osv(&["-a"])).is_err());
    }

    #[test]
    fn config_render_shows_limits_only_when_overridden() {
        let p = style::Palette::colored();
        // A default-profile config prints no `limits:` line — the section surfaces a custom cap,
        // not the documented defaults (which `ops doctor` shows).
        let out = render_config(&sample_config_view(), &p, false);
        assert!(
            !out.contains("limits:"),
            "a default profile must not print a limits line:\n{out}"
        );

        // An override of the ceiling and task cap prints the line, tagging each field with its
        // provenance: the overridden ones name their layer (`global`/`project`), the untouched
        // throttle reads `(default)` and keeps its default value.
        use config::view::ProvenanceView;
        let mut view = sample_config_view();
        view.limits = config::view::LimitsView {
            memory_high: config::view::LimitView {
                value: "80%".into(),
                origin: ProvenanceView::Default,
            },
            memory_max: config::view::LimitView {
                value: "8G".into(),
                origin: ProvenanceView::Global,
            },
            tasks_max: config::view::LimitView {
                value: "4096".into(),
                origin: ProvenanceView::Project,
            },
        };
        let out = render_config(&view, &p, false);
        assert!(
            out.contains("limits:"),
            "an override prints the line:\n{out}"
        );
        assert!(
            out.contains("MemoryMax=8G"),
            "the overridden ceiling shows:\n{out}"
        );
        assert!(
            out.contains("TasksMax=4096"),
            "the overridden task cap shows:\n{out}"
        );
        // Each field names its source, hued by level: the global-set ceiling (cyan), the
        // project-set task cap (green), and the untouched throttle's default (dim).
        assert!(
            out.contains(&format!("MemoryMax=8G {}(global){}", p.name, p.reset)),
            "the overridden ceiling is tagged global (cyan):\n{out}"
        );
        assert!(
            out.contains(&format!("TasksMax=4096 {}(project){}", p.ok, p.reset)),
            "the overridden task cap is tagged project (green):\n{out}"
        );
        assert!(
            out.contains(&format!("MemoryHigh=80% {}(default){}", p.dim, p.reset)),
            "the untouched throttle shows its default value, tagged default (dim):\n{out}"
        );
    }

    #[test]
    fn config_render_shows_an_app_limits_override() {
        use config::view::*;
        let p = style::Palette::plain();
        let app = |name: &str, limits: Option<AppLimitsView>| AppView {
            name: name.into(),
            cmd: Some(name.into()),
            home_scope: "global (shared across projects)".into(),
            env: vec![],
            binds: vec![],
            packages: vec![],
            network: None,
            gui: None,
            limits,
            secrets: vec![],
            notes: vec![],
        };
        let mut view = sample_config_view();
        view.apps = vec![
            app(
                "capped",
                Some(AppLimitsView {
                    memory_high: None,
                    memory_max: None,
                    tasks_max: Some("4096".into()),
                }),
            ),
            app("plain", None),
        ];
        let out = render_config(&view, &p, false);
        // The tuning app prints only the field it set — its task cap.
        assert!(out.contains("      limits: TasksMax=4096"), "{out}");
        // A field the app left unset is absent (it inherits the baseline, not shown per-app); the
        // baseline itself is default here, so it prints no limits line either.
        assert!(
            !out.contains("MemoryHigh"),
            "an unset app field is not rendered:\n{out}"
        );
        // Exactly one app limits line: the app that tunes nothing prints none.
        assert_eq!(
            out.matches("      limits:").count(),
            1,
            "only the tuning app shows a limits line:\n{out}"
        );
    }

    #[test]
    fn config_render_shows_flake_pins_and_floating_state() {
        // A pinned `flake:` package shows its short revision and `pinned`; an unpinned one shows
        // `floating`, so the absence of a rev reads as a state, not a gap. The same pin appears
        // compactly in an app's package list — the motivating case (a flake package in an app
        // overlay, not the baseline).
        use config::view::*;
        let rev = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
        let view = ConfigView {
            cwd: "/proj".into(),
            env: vec![],
            binds: vec![],
            packages: vec![
                PackageView {
                    name: "pinned-tool".into(),
                    backend: "flake".into(),
                    locator: "github:example/pinned-tool#default".into(),
                    realised: "in-cage via nix build, fetched at launch".into(),
                    trusted: true,
                    withheld_reason: None,
                    pinned_rev: Some(rev.into()),
                },
                PackageView {
                    name: "floating-tool".into(),
                    backend: "flake".into(),
                    locator: "github:example/floating-tool".into(),
                    realised: "in-cage via nix build, fetched at launch".into(),
                    trusted: true,
                    withheld_reason: None,
                    pinned_rev: None,
                },
            ],
            mise: None,
            tools: ToolsView::default(),
            nixpkgs: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            engine: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            network: NetworkView::Shared,
            network_origin: ProvenanceView::Default,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
                name: "demo-app".into(),
                cmd: Some("demo-app".into()),
                home_scope: "global (shared across projects)".into(),
                env: vec![],
                binds: vec![],
                packages: vec![PackageView {
                    name: "pinned-tool".into(),
                    backend: "flake".into(),
                    locator: "github:example/pinned-tool#default".into(),
                    realised: "in-cage via nix build, fetched at launch".into(),
                    trusted: true,
                    withheld_reason: None,
                    pinned_rev: Some(rev.into()),
                }],
                network: None,
                gui: None,
                limits: None,
                secrets: vec![],
                notes: vec![],
            }],
            warnings: vec![],
        };
        let out = render_config(&view, &style::Palette::plain(), false);
        assert!(
            out.contains(
                "    pinned-tool -> flake:github:example/pinned-tool#default  \
                 @ a1b2c3d (in-cage via nix build, fetched at launch, pinned)"
            ),
            "a pinned flake package must show its short rev and `pinned`:\n{out}"
        );
        assert!(
            out.contains(
                "    floating-tool -> flake:github:example/floating-tool  \
                 (in-cage via nix build, fetched at launch, floating)"
            ),
            "an unpinned flake package must read as `floating`:\n{out}"
        );
        assert!(
            out.contains("      packages: pinned-tool @ a1b2c3d"),
            "an app's pinned flake package must show its rev compactly:\n{out}"
        );
    }

    #[test]
    fn config_render_shows_an_app_allowlist_compactly_then_expands_under_details() {
        // An app overlay's allowlist is a one-line count by default and expands to its rules under
        // `--details`. The expansion includes the built-in nix-cache set, which the baseline
        // `network` section does not show here (the baseline is `shared`), so this is the only place
        // a profile's app-overlay allowlist surfaces what `ops app <name>` can actually reach.
        use config::view::*;
        let view = ConfigView {
            cwd: "/proj".into(),
            env: vec![],
            binds: vec![],
            packages: vec![],
            mise: None,
            tools: ToolsView::default(),
            nixpkgs: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            engine: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            network: NetworkView::Shared,
            network_origin: ProvenanceView::Default,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
                name: "demo-app".into(),
                cmd: Some("demo-app".into()),
                home_scope: "global (shared across projects)".into(),
                env: vec![],
                binds: vec![],
                packages: vec![],
                network: Some(AppNetworkView::Allowlist {
                    allow: vec!["api.example.com".into(), "github.com".into()],
                    deny: vec!["github.com/secret".into()],
                    builtin: vec!["cache.nixos.org".into()],
                }),
                gui: None,
                limits: None,
                secrets: vec![],
                notes: vec![],
            }],
            warnings: vec![],
        };

        // Default: a compact count, both numbers present even at zero deny, no expanded rule.
        let compact = render_config(&view, &style::Palette::plain(), false);
        assert!(
            compact.contains("      network: allowlist (2 allow, 1 deny)"),
            "the default app allowlist must read as compact counts:\n{compact}"
        );
        assert!(
            !compact.contains("allow api.example.com"),
            "the default must not expand the rules:\n{compact}"
        );

        // --details: the individual rules and the always-allowed built-in set.
        let expanded = render_config(&view, &style::Palette::plain(), true);
        assert!(
            expanded.contains("        allow api.example.com")
                && expanded.contains("        allow github.com"),
            "--details must list the allow rules:\n{expanded}"
        );
        assert!(
            expanded.contains("        deny  github.com/secret"),
            "--details must list the deny rules:\n{expanded}"
        );
        assert!(
            expanded.contains("built-in (always allowed, so self-equip works):")
                && expanded.contains("          allow cache.nixos.org"),
            "--details must surface the always-allowed built-in set:\n{expanded}"
        );
        // The overlay's allowlist closes with the same `deny wins over allow` reminder the baseline
        // `network` section shows — security-field parity between the overlay and the baseline.
        assert!(
            expanded.contains("        (deny wins over allow)"),
            "--details must explain that deny wins, as the baseline allowlist does:\n{expanded}"
        );
    }

    #[test]
    fn config_render_app_overlay_postures_carry_the_baseline_parentheticals() {
        // An app overlay's simple postures read with the same parentheticals the baseline sections
        // carry, so `ops app <name>` explains them identically: `network: shared` notes the host
        // network, `network: none` notes the isolation, and a `wayland` gui carries the
        // compositor-exposure caveat. None of these is an expandable list, so they render the same
        // with or without `--details` — the default render is enough to pin them.
        use config::view::*;
        let app = |name: &str, network: Option<AppNetworkView>, gui: Option<GuiView>| AppView {
            name: name.into(),
            cmd: Some(name.into()),
            home_scope: "global (shared across projects)".into(),
            env: vec![],
            binds: vec![],
            packages: vec![],
            network,
            gui,
            limits: None,
            secrets: vec![],
            notes: vec![],
        };
        let view = ConfigView {
            cwd: "/proj".into(),
            env: vec![],
            binds: vec![],
            packages: vec![],
            mise: None,
            tools: ToolsView::default(),
            nixpkgs: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            engine: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            network: NetworkView::Shared,
            network_origin: ProvenanceView::Default,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            limits: Default::default(),
            secrets: vec![],
            apps: vec![
                app("shared-app", Some(AppNetworkView::Shared), None),
                app("none-app", Some(AppNetworkView::Isolated), None),
                app("gui-app", None, Some(GuiView::Wayland)),
            ],
            warnings: vec![],
        };

        let out = render_config(&view, &style::Palette::plain(), false);
        // Each app line is six-space-indented, so these substrings match the overlay, not the
        // two-space baseline `network: shared (host network)` line.
        assert!(
            out.contains("      network: shared (host network)"),
            "an app's shared network must carry the baseline parenthetical:\n{out}"
        );
        assert!(
            out.contains("      network: none (isolated — no network)"),
            "an app's none network must carry the baseline parenthetical:\n{out}"
        );
        assert!(
            out.contains("      gui: wayland (exposure depends on your compositor)"),
            "an app's wayland gui must carry the baseline compositor caveat:\n{out}"
        );
    }

    #[test]
    fn config_render_shows_app_secrets_compactly_then_expands_under_details() {
        // An app overlay's injected credentials are a one-line count by default and expand to each
        // by destination and source under `--details` — the same metadata the baseline section
        // shows. The shipped profiles put their secret in the overlay, so this is the only place a
        // profile's credential surfaces in `ops config` (the baseline `secrets` section is empty).
        use config::view::*;
        let view = ConfigView {
            cwd: "/proj".into(),
            env: vec![],
            binds: vec![],
            packages: vec![],
            mise: None,
            tools: ToolsView::default(),
            nixpkgs: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            engine: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            network: NetworkView::Shared,
            network_origin: ProvenanceView::Default,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
                name: "demo-app".into(),
                cmd: Some("demo-app".into()),
                home_scope: "global (shared across projects)".into(),
                env: vec![],
                binds: vec![],
                packages: vec![],
                network: None,
                gui: None,
                limits: None,
                secrets: vec![
                    SecretView {
                        header: "x-api-key".into(),
                        to: "api.example.com".into(),
                        shape: "raw".into(),
                        sources: "env DEMO_API_KEY".into(),
                    },
                    SecretView {
                        header: "authorization".into(),
                        to: "api2.example.com".into(),
                        shape: "bearer".into(),
                        sources: "env DEMO_TOKEN".into(),
                    },
                ],
                notes: vec![],
            }],
            warnings: vec![],
        };

        // Default: a compact count, no destination or source expanded.
        let compact = render_config(&view, &style::Palette::plain(), false);
        assert!(
            compact.contains("      secrets: 2 injected host-side"),
            "the default app secrets line must read as a compact count:\n{compact}"
        );
        assert!(
            !compact.contains("api.example.com"),
            "the default must not expand the destinations:\n{compact}"
        );

        // --details: each credential by destination and source — never the value.
        let expanded = render_config(&view, &style::Palette::plain(), true);
        assert!(
            expanded.contains("      secrets (injected host-side):"),
            "--details must head the expanded secrets block:\n{expanded}"
        );
        assert!(
            expanded.contains("        x-api-key -> api.example.com  (raw, from env DEMO_API_KEY)")
                && expanded.contains(
                    "        authorization -> api2.example.com  (bearer, from env DEMO_TOKEN)"
                ),
            "--details must list each credential by destination and source:\n{expanded}"
        );
    }

    #[test]
    fn config_render_shows_app_env_and_binds_compactly_then_expands_under_details() {
        // An app overlay's env and binds are one-line counts by default and expand under
        // `--details` — env to each `KEY=value` (the value is the in-cage placeholder, a free
        // field, never an injected secret) and binds to each path. This is the only place a
        // profile's overlay env/binds surface, mirroring the baseline `env`/`binds` sections.
        use config::view::*;
        let view = ConfigView {
            cwd: "/proj".into(),
            env: vec![],
            binds: vec![],
            packages: vec![],
            mise: None,
            tools: ToolsView::default(),
            nixpkgs: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            engine: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            network: NetworkView::Shared,
            network_origin: ProvenanceView::Default,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
                name: "demo-app".into(),
                cmd: Some("demo-app".into()),
                home_scope: "global (shared across projects)".into(),
                env: vec![
                    AppEnvVar {
                        key: "DEMO_API_KEY".into(),
                        value: "placeholder".into(),
                    },
                    AppEnvVar {
                        key: "EDITOR".into(),
                        value: "vim".into(),
                    },
                ],
                binds: vec!["/data/cache".into()],
                packages: vec![],
                network: None,
                gui: None,
                limits: None,
                secrets: vec![],
                notes: vec![],
            }],
            warnings: vec![],
        };

        // Default: compact counts, no values or paths expanded.
        let compact = render_config(&view, &style::Palette::plain(), false);
        assert!(
            compact.contains("      env: 2 set") && compact.contains("      binds: 1"),
            "the default must show compact env and bind counts:\n{compact}"
        );
        assert!(
            !compact.contains("DEMO_API_KEY=placeholder") && !compact.contains("/data/cache"),
            "the default must not expand the env values or bind paths:\n{compact}"
        );

        // --details: each env entry by `KEY=value` and each bind path.
        let expanded = render_config(&view, &style::Palette::plain(), true);
        assert!(
            expanded.contains("        DEMO_API_KEY=placeholder")
                && expanded.contains("        EDITOR=vim"),
            "--details must list each env entry as KEY=value:\n{expanded}"
        );
        assert!(
            expanded.contains("      binds (read-only):")
                && expanded.contains("        /data/cache"),
            "--details must list each bind path:\n{expanded}"
        );
    }

    #[test]
    fn config_render_shows_app_packages_compactly_then_expands_under_details() {
        // An app overlay's packages are a compact name list by default — a withheld one marked
        // `(withheld)` and a pinned `flake:` one carrying ` @ <rev>`, so the trust verdict (which
        // governs whether the package is admitted at launch) and the pin are visible without
        // `--details`. `--details` expands to the full per-package line — the same one the baseline
        // `packages` section renders, just indented under the app — so the backend is visible there.
        use config::view::*;
        let rev = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
        let view = ConfigView {
            cwd: "/proj".into(),
            env: vec![],
            binds: vec![],
            packages: vec![],
            mise: None,
            tools: ToolsView::default(),
            nixpkgs: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            engine: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            network: NetworkView::Shared,
            network_origin: ProvenanceView::Default,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
                name: "demo-app".into(),
                cmd: Some("demo-app".into()),
                home_scope: "global (shared across projects)".into(),
                env: vec![],
                binds: vec![],
                packages: vec![
                    PackageView {
                        name: "admitted-tool".into(),
                        backend: "nix".into(),
                        locator: "ripgrep".into(),
                        realised: "host-side, durable".into(),
                        trusted: true,
                        withheld_reason: None,
                        pinned_rev: None,
                    },
                    PackageView {
                        name: "withheld-tool".into(),
                        backend: "nix".into(),
                        locator: "foo".into(),
                        realised: "host-side, durable".into(),
                        trusted: false,
                        withheld_reason: Some("the project is untrusted".into()),
                        pinned_rev: None,
                    },
                    PackageView {
                        name: "pinned-tool".into(),
                        backend: "flake".into(),
                        locator: "github:example/pinned-tool#default".into(),
                        realised: "in-cage via nix build, fetched at launch".into(),
                        trusted: true,
                        withheld_reason: None,
                        pinned_rev: Some(rev.into()),
                    },
                ],
                network: None,
                gui: None,
                limits: None,
                secrets: vec![],
                notes: vec![],
            }],
            warnings: vec![],
        };

        // Default: one compact line — the withheld marker and the flake pin inline, no full lines.
        let compact = render_config(&view, &style::Palette::plain(), false);
        assert!(
            compact.contains(
                "      packages: admitted-tool, withheld-tool (withheld), pinned-tool @ a1b2c3d"
            ),
            "the default must show a compact name list with the withheld marker and the pin:\n{compact}"
        );
        assert!(
            !compact.contains("-> nix:ripgrep"),
            "the default must not expand to the full package line:\n{compact}"
        );

        // --details: each package on its own full line, mirroring the baseline section — a withheld
        // one carries its reason, the flake one its pin, every other its realisation.
        let expanded = render_config(&view, &style::Palette::plain(), true);
        assert!(
            expanded.contains("        admitted-tool -> nix:ripgrep  (host-side, durable)"),
            "--details must expand an admitted package to its full backend line:\n{expanded}"
        );
        assert!(
            expanded
                .contains("        withheld-tool -> nix:foo  (withheld: the project is untrusted)"),
            "--details must show a withheld package's reason:\n{expanded}"
        );
        assert!(
            expanded.contains(
                "        pinned-tool -> flake:github:example/pinned-tool#default  \
                 @ a1b2c3d (in-cage via nix build, fetched at launch, pinned)"
            ),
            "--details must show a pinned flake package's rev:\n{expanded}"
        );
    }
}
