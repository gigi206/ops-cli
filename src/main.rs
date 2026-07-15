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
mod paths;
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
        "shell" => shell_cmd(rest),
        "ls" => list_sessions(),
        "attach" => attach_cmd(rest),
        "stop" => stop_cmd(rest),
        "trust" => trust_cmd(rest),
        "untrust" => untrust_cmd(rest.into_iter().next()),
        "config" => config_cmd(rest),
        "upgrade" => upgrade_cmd(rest),
        "gc" => gc_cmd(rest),
        "projects" | "project" => projects_cmd(rest),
        "path" => path_cmd(&rest),
        "run" => {
            let mut cmd: Vec<OsString> = rest;
            // Leading ops flags before the command: `--detach` to run in the background, a one-shot
            // override (the whole-schema `--config <toml|@file>` and the typed `--env`/`--net`/
            // `--gui`/`--nixpkgs`/`--bind`/`--limit`/`--package`, each repeatable), `--help`/`-h` for
            // this command's page, and an optional `--` separating ops's arguments from the
            // command's. The `--` is consumed before scanning the command, so `ops run -- --detach`
            // (or `-- --help`) runs the literal argument.
            let mut detach = false;
            let mut cli = config::CliOverrides::default();
            while let Some(raw) = cmd.first().and_then(|a| a.to_str()) {
                match flag_name(raw) {
                    "--detach" => {
                        detach = true;
                        cmd.remove(0);
                    }
                    "--help" | "-h" => return help::show(&["run"]),
                    "--" => {
                        cmd.remove(0);
                        break;
                    }
                    // A one-shot override flag, or the start of the command.
                    _ => match take_override_flag(&mut cmd, &mut cli, "run") {
                        Some(Ok(())) => {}
                        Some(Err(c)) => return c,
                        None => break,
                    },
                }
            }
            let ov = match build_override(cli) {
                Ok(ov) => ov,
                Err(c) => return c,
            };
            sandbox::run(cmd, detach, ov)
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
        "net" => net_cmd(rest),
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
    // nix, ops cannot provision a project's tools. Resolution follows override,
    // then an ops-owned engine, then `PATH`; it makes no store or config change,
    // though a `bundled-nix` build materializes its embedded engine under
    // `<data>/engine/` on first use (idempotent), which a launch would do anyway.
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
    let uptime = uptime_seconds();
    let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    // Each row is materialized first so the column widths can flex to the widest value: an
    // app session's KIND is `app:<name>` and a cage name is `ops-<slug>`, either of which can
    // exceed a fixed width and shift every following column out of alignment.
    let rows: Vec<(String, String, String, String, String)> = sessions
        .iter()
        .map(|s| {
            let age = match uptime {
                Some(up) if ticks_per_sec > 0 => {
                    let started = s.start_ticks as f64 / ticks_per_sec as f64;
                    format_age((up - started).max(0.0) as u64)
                }
                _ => "?".to_string(),
            };
            (
                sandbox::cage_name(s.app(), &s.project),
                s.label(),
                s.pid.to_string(),
                age,
                s.project.display().to_string(),
            )
        })
        .collect();

    // NAME/KIND are left-aligned, PID/AGE right-aligned; each width is the wider of its header
    // label and the widest value. Cage slugs and app/label names are ASCII, so a byte length
    // equals the display width.
    let name_w = rows.iter().map(|r| r.0.len()).chain([4]).max().unwrap();
    let kind_w = rows.iter().map(|r| r.1.len()).chain([4]).max().unwrap();
    let pid_w = rows.iter().map(|r| r.2.len()).chain([3]).max().unwrap();
    let age_w = rows.iter().map(|r| r.3.len()).chain([3]).max().unwrap();

    // The header is padded first, then wrapped in color, so the color spans never count toward
    // the column widths and the alignment is identical with or without color.
    let header = format!(
        "{:<name_w$}  {:<kind_w$}  {:>pid_w$}  {:>age_w$}  PROJECT",
        "NAME", "KIND", "PID", "AGE"
    );
    println!("{h}{header}{r}");
    for (name, label, pid, age, project) in &rows {
        // NAME is the cage's own name — the same `ops-<slug>` its systemd scope and in-cage
        // hostname show — so a session cross-references with the host tooling. An app session's
        // KIND is `app:<name>`, so the user can tell which sessions are agents (and that
        // `ops attach`/`ops stop` act on that app's isolated environment). NAME is padded before
        // coloring so the color span does not disturb the width.
        let name = format!("{name:<name_w$}");
        println!("{n}{name}{r}  {label:<kind_w$}  {pid:>pid_w$}  {age:>age_w$}  {project}");
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
/// `ops trust --show [path]` reports its trust state without changing it. `--show` is honored in
/// any position, and an unknown flag or a second path is a usage error — recording trust is the
/// most security-sensitive write in the tool, so a mistyped `--show` must never fall through to it.
fn trust_cmd(args: Vec<OsString>) -> ExitCode {
    let (show, path) = match parse_trust_args(args) {
        Ok(parsed) => parsed,
        Err(msg) => {
            eprintln!("ops: {msg} — usage: ops trust [--show] [path]");
            return ExitCode::from(2);
        }
    };
    let path = config_path_arg(path);
    if show {
        show_trust(path)
    } else {
        record_trust(path)
    }
}

/// Parse `ops trust`'s arguments into `(show, path)`. `--show` is honored in any position and an
/// unknown flag or a second path is an error — recording trust is the tool's most security-sensitive
/// write, so a mistyped or trailing `--show` must never fall through to it. A pure helper (tested).
fn parse_trust_args(args: Vec<OsString>) -> Result<(bool, Option<OsString>), String> {
    let mut show = false;
    let mut path: Option<OsString> = None;
    for arg in args {
        match arg.to_str() {
            Some("--show") => show = true,
            Some(tok) if tok.starts_with('-') => return Err(format!("unknown flag {tok}")),
            _ => {
                if path.is_some() {
                    return Err("trust takes a single path".to_string());
                }
                path = Some(arg);
            }
        }
    }
    Ok((show, path))
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
/// environment and host binds (each read-only or read-write), after the trust gate has dropped
/// anything an untrusted project may not set. The human form renders a colored document with
/// warnings on stderr;
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
        // A one-shot override is the final word for this invocation — flagged in warn hue so it
        // stands out from the persisted config layers.
        ProvenanceView::Override => ("override", pal.warn),
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
        ProvenanceView::Override => ("override", pal.warn),
    }
}

/// The provenance tag for an optional origin — a per-entry value (an `env` variable, a bind) whose
/// declaring layer may not be recorded (an app overlay's binds carry none). Empty when unknown.
fn opt_provenance_tag(
    origin: Option<config::view::ProvenanceView>,
    pal: &style::Palette,
) -> String {
    origin.map_or_else(String::new, |o| provenance_tag(o, pal))
}

/// The mode marker appended after a bind path: a warning-hued ` (rw)` for a read-write bind
/// (the more-privileged, exceptional case worth flagging), nothing for the read-only default.
fn bind_mode_tag(writable: bool, pal: &style::Palette) -> String {
    if writable {
        format!(" {}(rw){}", pal.warn, pal.reset)
    } else {
        String::new()
    }
}

fn render_config(view: &config::view::ConfigView, pal: &style::Palette, details: bool) -> String {
    use config::view::{AppNetworkView, GuiView, LimitView, NetDefaultView, NetworkView};
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

    // The layered environment and host binds (read-only or read-write), after the trust gate.
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
        let _ = writeln!(o, "  {h}binds:{r}");
        for b in &view.binds {
            let _ = writeln!(
                o,
                "    {n}{}{r}{}{}",
                b.path,
                bind_mode_tag(b.writable, pal),
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
    // off; a filtering posture (`deny`/`allow`/`ask`) routes egress through the proxy — `deny`
    // permits only what is listed (deny wins over allow), plus the always-allowed built-in set so
    // the self-equip allowance is never silent.
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
            default_action,
            ask_timeout,
            ask_notice,
            allow,
            deny,
            mute,
            builtin,
        } => {
            let _ = writeln!(
                o,
                "  {h}network:{r} {}{net_tag}",
                net_mode_word(*default_action)
            );
            if let Some(t) = ask_timeout {
                let shown = if t == "none" {
                    "none (wait indefinitely until answered)".to_string()
                } else {
                    t.clone()
                };
                let _ = writeln!(o, "    {dim}ask timeout: {shown}{r}");
            }
            if matches!(ask_notice, Some(false)) {
                let _ = writeln!(
                    o,
                    "    {dim}ask notice: off (parked requests are silent — answer via \
                     `ops net pending`){r}"
                );
            }
            match default_action {
                // Allowlist: only the listed (and built-in) hosts reach; everything else is denied.
                NetDefaultView::Deny => {
                    if allow.is_empty() {
                        let _ = writeln!(
                            o,
                            "    {dim}allow: (none declared beyond the built-in set){r}"
                        );
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
                    let _ = writeln!(o, "    {dim}(deny wins; an unlisted host is denied){r}");
                }
                // Denylist: every public host reaches except the deny carve-outs; the proxy stays
                // active. The allow rules only relax the SSRF private-host guard here (every public
                // host is already permitted), and the built-in set is moot, so neither is led with.
                NetDefaultView::Allow => {
                    let _ = writeln!(o, "    {dim}every public host is reachable except:{r}");
                    if deny.is_empty() {
                        let _ = writeln!(o, "    {dim}deny: (none declared){r}");
                    } else {
                        for rule in deny {
                            let _ = writeln!(o, "    {warn}deny{r}  {n}{rule}{r}");
                        }
                    }
                    if !allow.is_empty() {
                        let _ = writeln!(o, "    {dim}allow (private-host exceptions only):{r}");
                        for rule in allow {
                            let _ = writeln!(o, "      allow {n}{rule}{r}");
                        }
                    }
                }
                // Ask: an unlisted host parks for a live decision; allow rules still auto-pass and
                // deny rules still auto-fail, so list those (and the built-in set) as pre-decided.
                NetDefaultView::Ask => {
                    let _ = writeln!(
                        o,
                        "    {dim}an unlisted host parks for a live `ops net pending` decision; \
                         these are pre-decided:{r}"
                    );
                    if !allow.is_empty() {
                        let _ = writeln!(o, "    {dim}auto-allow:{r}");
                        for rule in allow {
                            let _ = writeln!(o, "      allow {n}{rule}{r}");
                        }
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
                }
            }
            // Mute (`dontaudit`) rules apply under every filtering posture — they suppress a denied
            // request's log line (never a verdict), so they are surfaced here (dimmed) whenever any
            // are declared, so the suppression is never silent.
            if !mute.is_empty() {
                let _ = writeln!(
                    o,
                    "    {dim}mute (refusals kept out of `ops net log`; see `--all`):{r}"
                );
                for rule in mute {
                    let _ = writeln!(o, "      {dim}mute{r}  {n}{rule}{r}");
                }
            }
            // The egress-stats toggle is meaningful only under a filtering posture (the proxy runs
            // only then), so it rides the network section. Shown both ways — an audit knob is worth
            // surfacing — naming the reader command when on.
            let _ = writeln!(
                o,
                "    {dim}stats: {}{r}",
                if view.egress_stats {
                    "recording (ops net stats)"
                } else {
                    "off"
                }
            );
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

    // The GPU posture — shown only when opened, so a non-GPU config stays uncluttered.
    if view.gpu {
        let _ = writeln!(
            o,
            "  {h}gpu:{r} enabled {dim}(mesa: Intel/AMD/nouveau){r}{}",
            provenance_tag(view.gpu_origin, pal)
        );
    }
    // The audio posture — shown only when opened, same as GPU.
    if view.audio {
        let _ = writeln!(
            o,
            "  {h}audio:{r} enabled {dim}(microphone + playback via PulseAudio){r}{}",
            provenance_tag(view.audio_origin, pal)
        );
    }
    // The D-Bus posture — the in-cage desktop portal; shown only when opened, same as GPU.
    if view.dbus {
        let _ = writeln!(
            o,
            "  {h}dbus:{r} in-cage portal {dim}(file chooser + theme + notifications){r}{}",
            provenance_tag(view.dbus_origin, pal)
        );
    }

    // Inbound loopback forward ports — shown only when a layer declared any, so a default-profile
    // config stays uncluttered. Each port is bound on the host's `127.0.0.1` and bridged into the
    // cage at the same port (an OAuth `localhost:<port>` callback, or a cage-run dev server).
    if !view.forward.is_empty() {
        let ports = view
            .forward
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            o,
            "  {h}forward:{r} {ports} {dim}(host loopback → cage loopback){r}{}",
            provenance_tag(view.forward_origin, pal)
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

    // Seccomp denylist relaxation — shown only when a trusted `[seccomp] allow` re-permits a
    // syscall, so the default (full mandatory denylist) stays uncluttered. The tokens read as the
    // canonical `allow` entries; the provenance names which layer relaxed the denylist.
    if !view.seccomp.is_empty() {
        let _ = writeln!(
            o,
            "  {h}seccomp allow:{r} {} {dim}(syscalls re-permitted in the cage){r}{}",
            view.seccomp.join(", "),
            provenance_tag(view.seccomp_origin, pal)
        );
    }

    // Host device grant — shown only when a trusted `[devices] allow` exposes a device, so the
    // default (minimal, hostless `/dev`) stays uncluttered. The paths read as the `allow` entries;
    // the provenance names which layer granted them.
    if !view.devices.is_empty() {
        let _ = writeln!(
            o,
            "  {h}devices:{r} {} {dim}(host device nodes exposed in the cage){r}{}",
            view.devices.join(", "),
            provenance_tag(view.devices_origin, pal)
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
            // The host binds this overlay adds — a security field, so what host paths
            // `ops app <name>` exposes (and whether read-write) is visible here, the same as the
            // baseline `binds` section. A count by default, each canonical path under `--details`.
            if !app.binds.is_empty() {
                if details {
                    let _ = writeln!(o, "      {dim}binds:{r}");
                    for b in &app.binds {
                        let _ = writeln!(
                            o,
                            "        {n}{}{r}{}",
                            b.path,
                            bind_mode_tag(b.writable, pal)
                        );
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
                        default_action,
                        ask_timeout,
                        ask_notice,
                        allow,
                        deny,
                        builtin,
                    } if details => {
                        let _ = writeln!(
                            o,
                            "      {dim}network:{r} {}",
                            net_mode_word(*default_action)
                        );
                        if let Some(t) = ask_timeout {
                            let _ = writeln!(o, "        {dim}ask timeout: {t}{r}");
                        }
                        if matches!(ask_notice, Some(false)) {
                            let _ = writeln!(o, "        {dim}ask notice: off{r}");
                        }
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
                    AppNetworkView::Allowlist {
                        default_action,
                        allow,
                        deny,
                        ..
                    } => {
                        let _ = writeln!(
                            o,
                            "      {dim}network:{r} {} {dim}({} allow, {} deny){r}",
                            net_mode_word(*default_action),
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
            // The GPU posture the overlay sets (`Some(true)`/`Some(false)`); `None` inherits.
            match app.gpu {
                Some(true) => {
                    let _ = writeln!(o, "      {dim}gpu:{r} enabled {dim}(mesa){r}");
                }
                Some(false) => {
                    let _ = writeln!(o, "      {dim}gpu:{r} disabled");
                }
                None => {}
            }
            // The audio posture the overlay sets (`Some(true)`/`Some(false)`); `None` inherits.
            match app.audio {
                Some(true) => {
                    let _ = writeln!(
                        o,
                        "      {dim}audio:{r} enabled {dim}(microphone + playback){r}"
                    );
                }
                Some(false) => {
                    let _ = writeln!(o, "      {dim}audio:{r} disabled");
                }
                None => {}
            }
            // The D-Bus posture the overlay sets; `None` inherits.
            match app.dbus {
                Some(true) => {
                    let _ = writeln!(
                        o,
                        "      {dim}dbus:{r} in-cage portal {dim}(file chooser + theme + notifications){r}"
                    );
                }
                Some(false) => {
                    let _ = writeln!(o, "      {dim}dbus:{r} disabled");
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
            // The host loopback ports this overlay adds (its own, not the baseline-merged set). A
            // compact list under the app's roster entry; the effective set is in `config show --app`.
            if !app.forward.is_empty() {
                let ports = app
                    .forward
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = writeln!(o, "      {dim}forward:{r} {ports} (host loopback → cage)");
            }
            // The seccomp relaxation this overlay adds (its own allow tokens, not the merged set).
            if !app.seccomp.is_empty() {
                let _ = writeln!(o, "      {dim}seccomp allow:{r} {}", app.seccomp.join(", "));
            }
            // The host device grant this overlay adds (its own `/dev/` paths, not the merged set).
            if !app.devices.is_empty() {
                let _ = writeln!(o, "      {dim}devices:{r} {}", app.devices.join(", "));
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
            default_action,
            ask_timeout,
            ask_notice,
            allow,
            deny,
            mute,
            builtin,
        } => {
            let _ = writeln!(
                o,
                "  {h}network:{r} {}{net_tag}",
                net_mode_word(*default_action)
            );
            if let Some(t) = ask_timeout {
                let _ = writeln!(o, "    {dim}ask timeout: {t}{r}");
            }
            if matches!(ask_notice, Some(false)) {
                let _ = writeln!(
                    o,
                    "    {dim}ask notice: off (parked requests are silent — answer via \
                     `ops net pending`){r}"
                );
            }
            if details {
                for rule in allow {
                    let _ = writeln!(o, "    allow {n}{rule}{r}");
                }
                for rule in deny {
                    let _ = writeln!(o, "    {warn}deny{r}  {n}{rule}{r}");
                }
                for rule in mute {
                    let _ = writeln!(o, "    {dim}mute{r}  {n}{rule}{r}");
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
                // The mute count rides the summary only when non-zero, so a mute-free app reads
                // exactly as before.
                let mute_note = if mute.is_empty() {
                    String::new()
                } else {
                    format!(", {} mute", mute.len())
                };
                let _ = writeln!(
                    o,
                    "    {dim}({} allow, {} deny{mute_note} — see --details){r}",
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

    // The effective GPU posture — shown either way, so the inherited story is visible.
    let gpu_tag = app_provenance_tag(view.gpu_origin, pal);
    let _ = writeln!(
        o,
        "  {h}gpu:{r}     {}{gpu_tag}",
        if view.gpu { "enabled" } else { "disabled" }
    );

    // The effective audio posture — shown either way, so the inherited story is visible.
    let audio_tag = app_provenance_tag(view.audio_origin, pal);
    let _ = writeln!(
        o,
        "  {h}audio:{r}   {}{audio_tag}",
        if view.audio { "enabled" } else { "disabled" }
    );

    // The effective D-Bus posture — shown either way, so the inherited story is visible.
    let dbus_tag = app_provenance_tag(view.dbus_origin, pal);
    let dbus_label = if view.dbus {
        "in-cage portal"
    } else {
        "disabled"
    };
    let _ = writeln!(o, "  {h}dbus:{r}    {dbus_label}{dbus_tag}");

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

    // Effective inbound loopback forward ports — the app's own ∪ the baseline's. Shown even when
    // empty so the inherited story is visible (a non-empty baseline set shows as `inherited`).
    let forward_tag = app_provenance_tag(view.forward_origin, pal);
    if view.forward.is_empty() {
        let _ = writeln!(o, "  {h}forward:{r} (none){forward_tag}");
    } else {
        let ports = view
            .forward
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            o,
            "  {h}forward:{r} {ports} {dim}(host loopback → cage loopback){r}{forward_tag}"
        );
    }

    // Effective seccomp relaxation — the app's own ∪ the baseline's. Shown even when empty so the
    // inherited story is visible (a relaxation the app takes from the baseline reads as `inherited`).
    let seccomp_tag = app_provenance_tag(view.seccomp_origin, pal);
    if view.seccomp.is_empty() {
        let _ = writeln!(o, "  {h}seccomp:{r} (mandatory denylist){seccomp_tag}");
    } else {
        let _ = writeln!(
            o,
            "  {h}seccomp:{r} allow {} {dim}(syscalls re-permitted){r}{seccomp_tag}",
            view.seccomp.join(", ")
        );
    }

    // Effective host device grant — the app's own ∪ the baseline's. Shown even when empty so the
    // inherited story is visible (a device the app takes from the baseline reads as `inherited`).
    let devices_tag = app_provenance_tag(view.devices_origin, pal);
    if view.devices.is_empty() {
        let _ = writeln!(o, "  {h}devices:{r} (none — minimal /dev){devices_tag}");
    } else {
        let _ = writeln!(
            o,
            "  {h}devices:{r} {} {dim}(host device nodes exposed){r}{devices_tag}",
            view.devices.join(", ")
        );
    }

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
            let _ = writeln!(o, "    {n}{}{r}{}", b.path, bind_mode_tag(b.writable, pal));
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
    /// Whether a scope flag (`-l`/`-g`/`-c`) was given explicitly, as opposed to the `Local`
    /// default — `ops config path` shows the resolution overview when none was.
    scope_explicit: bool,
    trust: bool,
    app: Option<String>,
}

/// Parse a management verb's trailing flags out of `args`. `--` ends flag parsing, so a value that
/// begins with `-` can still be passed.
fn split_scope(args: &[OsString]) -> Result<ScopeArgs, String> {
    use config::manage::Scope;
    let mut positionals = Vec::new();
    let mut scope = Scope::Local;
    let mut scope_explicit = false;
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
            Some("--local") | Some("-l") => {
                scope = Scope::Local;
                scope_explicit = true;
            }
            Some("--global") | Some("-g") => {
                scope = Scope::Global;
                scope_explicit = true;
            }
            Some("-c") | Some("--config") => {
                let file = it
                    .next()
                    .ok_or_else(|| "`-c` needs a file path".to_string())?;
                scope = Scope::File(PathBuf::from(file));
                scope_explicit = true;
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
        scope_explicit,
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
/// *effective resolved* value across layers, use `ops config show` / `ops config show --json`. An
/// unset key OR a read/parse error both exit 1 (each prints a distinct stderr line saying which); a
/// usage problem exits 2.
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
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let (path, key, _gated) =
        match resolve_key_target("get", &scope, app.as_deref(), &positionals[0], &cwd) {
            Ok(t) => t,
            Err(code) => return code,
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

/// Resolve the file a key-taking verb (`get`/`set`/`unset`) targets and the dotted key within it,
/// applying the `--app <name>` routing and reporting whether the target is trust-gated.
///
/// The routing mirrors `ops net … -a <name>`: a **global** app lives in its own profile file
/// `apps/<name>.toml` with **top-level** keys, so the key is used as-is; an app declared **inline**
/// (a project `.ops.toml` or a `-c` file) is addressed under its `app.<name>.` table. The name
/// asymmetry is deliberate, not a bug: a `.`-containing app name is addressable at `-g` (it keys the
/// profile *filename*) but rejected inline (the dotted-key splitter does not handle a quoted segment).
///
/// The returned `gated` flag drives the trust note: the global config and the app profiles under
/// `apps/` are trusted **by location**, so a write to either is never gated (and never re-arms a trust
/// marker); a project (or explicit `-c`) file is. Any resolution error is already reported to stderr,
/// so the caller just returns the carried exit code.
fn resolve_key_target(
    verb: &str,
    scope: &config::manage::Scope,
    app: Option<&str>,
    raw_key: &str,
    cwd: &Path,
) -> Result<(PathBuf, String, bool), ExitCode> {
    use config::manage::{self, Scope};
    let gated = !matches!(scope, Scope::Global);
    let scope_path = |scope: &Scope| {
        manage::scope_path(scope, cwd).map_err(|e| {
            eprintln!("ops: config: {e}");
            ExitCode::FAILURE
        })
    };
    match (app, scope) {
        (None, _) => Ok((scope_path(scope)?, raw_key.to_string(), gated)),
        (Some(name), Scope::Global) => {
            // A global app is its own profile file with top-level keys. The name keys that
            // filename, so validate it (anti-traversal) the way `ops net … -a <name> -g` does.
            if config::is_reserved_app_verb(name) || !config::is_valid_app_name(name) {
                eprintln!("ops: config {verb}: invalid app name `{name}`");
                return Err(config_usage(verb));
            }
            let path = manage::scope_app_path(scope, cwd, name).map_err(|e| {
                eprintln!("ops: config: {e}");
                ExitCode::FAILURE
            })?;
            Ok((path, raw_key.to_string(), false))
        }
        (Some(name), _) => {
            // An inline app (project `.ops.toml` or a `-c` file) is addressed under `app.<name>.`.
            let key = app_prefixed_key(name, raw_key).map_err(|e| {
                eprintln!("ops: config {verb}: {e}");
                config_usage(verb)
            })?;
            Ok((scope_path(scope)?, key, gated))
        }
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
        ..
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
    let val = &positionals[1];
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let (path, key, gated) =
        match resolve_key_target("set", &scope, app.as_deref(), &positionals[0], &cwd) {
            Ok(t) => t,
            Err(code) => return code,
        };
    // Capture the trust state before the write — the write itself changes the file and so its
    // verdict, so "was it trusted" must be read first. A non-gated target (the global config or an
    // app profile, both trusted by location) carries no marker, so the read is skipped.
    let store_dir = trust::default_store_dir();
    let was_trusted = gated
        && store_dir
            .as_deref()
            .is_some_and(|d| trust::state(d, &path) == trust::TrustState::Trusted);

    match config::manage::set(&path, &key, val) {
        Ok(created) => {
            let verb = if created { "set" } else { "updated" };
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_config_write(verb, &key, &path, &pal));
            report_write_trust(&path, &key, was_trusted, trust, store_dir.as_deref(), gated);
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
        ..
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
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let (path, key, gated) =
        match resolve_key_target("unset", &scope, app.as_deref(), &positionals[0], &cwd) {
            Ok(t) => t,
            Err(code) => return code,
        };
    let store_dir = trust::default_store_dir();
    let was_trusted = gated
        && store_dir
            .as_deref()
            .is_some_and(|d| trust::state(d, &path) == trust::TrustState::Trusted);

    match config::manage::unset(&path, &key) {
        Ok(true) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_config_write("unset", &key, &path, &pal));
            report_write_trust(&path, &key, was_trusted, trust, store_dir.as_deref(), gated);
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

/// `ops config path`: with no scope flag, show the config files a launch resolves, in order, each
/// with whether it exists — so it is clear where ops looks (and that a default project `.ops.toml`
/// need not exist). With an explicit scope (`-l`/`-g`/`-c`), print the single bare path that scope
/// targets — the file `set`/`unset`/`edit` would touch, for scripting and for finding the global
/// config.
/// `ops path [--json]`: show every on-disk location ops uses, grouped by XDG base
/// (data, config, state), marking which exist and enumerating the per-project /
/// per-app / per-profile entries actually on disk. Read-only, no trust gate, no
/// network — the layout map that answers "where on disk does ops put things?".
/// The counterpart of `ops config path` (the config files in resolution order)
/// for the rest of the filesystem.
fn path_cmd(args: &[OsString]) -> ExitCode {
    let mut json = false;
    for a in args {
        match a.to_str() {
            Some("--json") => json = true,
            Some(other) => {
                eprintln!("ops: path: unknown argument `{other}`");
                eprintln!("       run `ops help path` for usage.");
                return ExitCode::from(2);
            }
            None => {
                eprintln!("ops: path: argument is not valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    let layout = store::Layout::from_env();
    let view = paths::view(layout.as_ref());
    if json {
        match serde_json::to_string_pretty(&view) {
            Ok(s) => {
                println!("{s}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("ops: path: failed to serialize: {e}");
                ExitCode::FAILURE
            }
        }
    } else {
        let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
        print!("{}", paths::render(&view, &pal));
        ExitCode::SUCCESS
    }
}

fn config_path_cmd(args: &[OsString]) -> ExitCode {
    let ScopeArgs {
        positionals,
        scope,
        scope_explicit,
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

    if !scope_explicit {
        // The useful default: the resolution overview. A successful listing even when nothing
        // exists yet — that is the common first-run state, not an error.
        let layers = config::manage::resolution_layers(&cwd);
        let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
        print!("{}", render_resolution_layers(&layers, &pal));
        return ExitCode::SUCCESS;
    }

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

/// Render the config-file resolution overview: each layer in order (global base, project overlay)
/// with its path and whether the file is present. Returned as a string so a test can assert it
/// without a terminal. The label column is padded as plain text before color is applied, so the
/// path column stays aligned regardless of styling.
fn render_resolution_layers(layers: &[config::manage::Layer], pal: &style::Palette) -> String {
    use std::fmt::Write as _;
    let (h, nm, ok, dim, r) = (pal.head, pal.name, pal.ok, pal.dim, pal.reset);
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{h}config files in resolution order{r} \
         {dim}(global is the base; the project overlays it){r}"
    );
    for layer in layers {
        let label = format!("{:<8}", layer.label);
        match &layer.path {
            Some(p) => {
                let (state, hue) = if p.try_exists().unwrap_or(false) {
                    ("present", ok)
                } else {
                    ("absent", dim)
                };
                let _ = writeln!(o, "  {nm}{label}{r}{}  {hue}({state}){r}", p.display());
            }
            None => {
                let _ = writeln!(o, "  {nm}{label}{r}{dim}(no config directory){r}");
            }
        }
    }
    let _ = writeln!(o, "{dim}for the resolved values, see `ops config show`.{r}");
    o
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
        ..
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
    gated: bool,
) {
    // The global config and the app profiles under `apps/` are trusted **by location** — they carry
    // no per-file trust marker, so a write never re-arms a gate and needs no `ops trust`. Reporting
    // one would be a false positive (the field applies as soon as the file is read), so say nothing —
    // beyond noting that an explicit `--trust` is unnecessary here.
    if !gated {
        if trust_flag {
            diag::note(&format!(
                "{} is trusted by location; `--trust` is not needed",
                path.display()
            ));
        }
        return;
    }
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

/// Whether a dotted config key names a security-relevant field. The only field applied without
/// trust (minus the untrusted-env denylist) is the free `env` table — both the baseline `env.*`
/// and an app's `app.<name>.env.*`; everything else is gated, so setting one on an untrusted file
/// is worth a note.
fn is_security_key(key: &str) -> bool {
    let segs: Vec<&str> = key.split('.').collect();
    !matches!(segs.as_slice(), ["env", ..] | ["app", _, "env", ..])
}

/// Consume one leading override flag (`--config`/`--env`) and its value from `head` into `sink` —
/// the `--flag=value` inline form, or the next argument. A missing or non-text value is a usage
/// error (exit 2). Shared by the launch verbs so `--config`/`--env` parse identically everywhere.
fn take_flag_value(
    head: &mut Vec<OsString>,
    sink: &mut Vec<String>,
    verb: &str,
    flag: &str,
) -> Result<(), ExitCode> {
    let token = head.remove(0);
    // `--flag=value`: the value is inline (split on the first `=`, so `--env=K=V` keeps `K=V`).
    if let Some((_, inline)) = token.to_str().and_then(|s| s.split_once('=')) {
        sink.push(inline.to_string());
        return Ok(());
    }
    // `--flag value`: the value is the next argument.
    match head.first().and_then(|a| a.to_str()) {
        Some(v) => {
            let v = v.to_string();
            head.remove(0);
            sink.push(v);
            Ok(())
        }
        None => {
            eprintln!("ops: {verb}: `{flag}` needs a value");
            Err(ExitCode::from(2))
        }
    }
}

/// The bare flag name of `raw`, stripping a `=value` suffix — so `--config` and `--config=x` both
/// dispatch on `--config`.
fn flag_name(raw: &str) -> &str {
    raw.split_once('=').map(|(f, _)| f).unwrap_or(raw)
}

/// Consume one leading boolean override flag (`--gpu`/`--dbus`) from `head` into `sink`. Unlike
/// [`take_flag_value`], a boolean flag is *optional-value*: a bare `--gpu` means `true`, and only the
/// inline `--gpu=true`/`--gpu=false` form carries a value — the next argument is **never** consumed,
/// so `--gpu <app>` leaves the app name in place. The raw `true`/`false` string is pushed as-is; the
/// override collector validates it (a value other than true/false is a usage error there), keeping the
/// grammar identical for the CLI flag and its `OPS_GPU`/`OPS_DBUS` environment twin.
fn take_flag_bool(head: &mut Vec<OsString>, sink: &mut Vec<String>) {
    let token = head.remove(0);
    // `--gpu=value`: the value is inline; a bare `--gpu` normalizes to `true`.
    let value = match token.to_str().and_then(|s| s.split_once('=')) {
        Some((_, v)) => v.to_string(),
        None => "true".to_string(),
    };
    sink.push(value);
}

/// If the leading token of `head` is a one-shot override flag, consume it and its value into `cli`
/// and return `Some(result)` (`Ok` on success, `Err(code)` on a missing value); return `None` when
/// the token is not an override flag, so the caller handles it (a command, the app name, an unknown
/// flag). Shared by `run`/`shell`/`app`, so the whole `--config`/`--env`/`--net`/`--gui`/`--nixpkgs`/
/// `--bind`/`--limit`/`--package` set parses identically everywhere. A scalar flag (`--net`/`--gui`/
/// `--nixpkgs`) may repeat — the merge takes the last; the collection flags take them all.
fn take_override_flag(
    head: &mut Vec<OsString>,
    cli: &mut config::CliOverrides,
    verb: &str,
) -> Option<Result<(), ExitCode>> {
    // Resolve the flag name to an owned string first, ending the borrow of `head` before the value
    // is taken (which mutates `head`).
    let name = flag_name(head.first()?.to_str()?).to_string();
    // The boolean flags are optional-value (`--gpu`, `--gpu=true`, `--gpu=false`) and must never
    // consume the following argument — else `ops app --gpu <name>` would swallow the app name — so
    // they take a dedicated path rather than the value-required `take_flag_value`.
    match name.as_str() {
        "--gpu" => {
            take_flag_bool(head, &mut cli.gpu);
            return Some(Ok(()));
        }
        "--audio" => {
            take_flag_bool(head, &mut cli.audio);
            return Some(Ok(()));
        }
        "--dbus" => {
            take_flag_bool(head, &mut cli.dbus);
            return Some(Ok(()));
        }
        _ => {}
    }
    let sink = match name.as_str() {
        "--config" => &mut cli.config,
        "--env" => &mut cli.env,
        "--net" => &mut cli.net,
        "--gui" => &mut cli.gui,
        "--nixpkgs" => &mut cli.nixpkgs,
        "--bind" => &mut cli.binds,
        "--forward" => &mut cli.forward,
        "--limit" => &mut cli.limits,
        "--package" => &mut cli.packages,
        "--seccomp" => &mut cli.seccomp,
        "--device" => &mut cli.devices,
        _ => return None,
    };
    Some(take_flag_value(head, sink, verb, &name))
}

/// Build the one-shot override from the collected CLI flag values and the ambient `OPS_*`
/// environment, surfacing its notices. Fail-closed: a malformed override (bad TOML, an unreadable
/// `@file`, a `--env`/`--limit`/`--package` without `=`, a bad `--net`/`--bind` value) is a usage
/// error (exit 2), never a silent drop that would launch a different posture than asked.
fn build_override(cli: config::CliOverrides) -> Result<config::Override, ExitCode> {
    match config::overrides::collect(&cli) {
        Ok(ov) => {
            for notice in ov.notices() {
                diag::warn(notice);
            }
            Ok(ov)
        }
        Err(e) => {
            eprintln!("ops: {e}");
            Err(ExitCode::from(2))
        }
    }
}

/// `ops shell`: an interactive shell in the project sandbox. Takes no command, only the leading
/// override flags (`--config`/`--env`) and `--help`; any other argument is a usage error (a stray
/// token would otherwise be silently dropped, since a shell launch has no positional).
fn shell_cmd(mut args: Vec<OsString>) -> ExitCode {
    let mut cli = config::CliOverrides::default();
    while let Some(raw) = args.first().and_then(|a| a.to_str()) {
        match flag_name(raw) {
            "--help" | "-h" => return help::show(&["shell"]),
            // A one-shot override flag, or a stray argument (a shell takes no command).
            _ => match take_override_flag(&mut args, &mut cli, "shell") {
                Some(Ok(())) => {}
                Some(Err(c)) => return c,
                None => {
                    let tok = args.first().and_then(|a| a.to_str()).unwrap_or_default();
                    eprintln!("ops: shell: unexpected argument `{tok}` (it takes no command)");
                    return ExitCode::from(2);
                }
            },
        }
    }
    let ov = match build_override(cli) {
        Ok(ov) => ov,
        Err(c) => return c,
    };
    sandbox::shell(ov)
}

/// `ops app <name>`: launch a named application profile (an `[app.<name>]` table from the global
/// or project config, or an imported `<name>.toml` profile) inside the project sandbox. The
/// management verbs `import`/`export`/`rm`/`list` are reserved (and so can never be an app name),
/// so the first token disambiguates a subcommand from an app to launch with no overlap.
fn app_cmd(args: Vec<OsString>) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("import") => app_import(&args[1..]),
        Some("export") => app_export(&args[1..]),
        Some("rm") => app_rm(&args[1..]),
        Some("list" | "ls") => app_list(),
        // Otherwise a single non-flag token names an app to launch; `--detach` runs it in the
        // background as a session `ops ls`/`attach`/`stop` can see. Tokens after a `--` are passed
        // through to the app's command (see `parse_app_launch`).
        _ => match parse_app_launch(&args) {
            Ok(launch) => {
                let ov = match build_override(launch.cli) {
                    Ok(ov) => ov,
                    Err(code) => return code,
                };
                let outcome = sandbox::app(
                    &launch.name,
                    launch.detach,
                    launch.tail,
                    ov,
                    launch.net_learn.as_ref().map(|nl| nl.gran),
                );
                match (outcome.learned, launch.net_learn) {
                    (Some(synth), Some(nl)) => finish_net_learn(&launch.name, synth, &nl),
                    _ => outcome.code,
                }
            }
            Err(code) => code,
        },
    }
}

/// Apply the rules `ops app <name> --net-learn` synthesized from the run: surface the notes (nothing
/// is dropped silently), then either preview the diff (`--dry-run`) or write each rule to the chosen
/// profile. The exit code reflects the *learning* outcome, not the agent's exit — a `--net-learn` run
/// is expected to fail hosts it lacks rules for, so its non-zero exit is not this command's failure;
/// only a write error is.
fn finish_net_learn(name: &str, synth: sandbox::Synthesis, nl: &NetLearn) -> ExitCode {
    use config::manage::EgressList;
    for note in &synth.notes {
        diag::warn(note);
    }
    if synth.rules.is_empty() {
        println!(
            "ops net-learn: no new egress rules — app `{name}` was refused nothing it lacked a rule for."
        );
        return ExitCode::SUCCESS;
    }
    let cwd = match config_cwd() {
        Ok(c) => c,
        Err(code) => return code,
    };
    // Resolve the human target once (the file the rules land in), shared by the preview and the write
    // messages so they cannot disagree about where the rules go.
    let target = match egress_write_target(&nl.scope, Some(name), &cwd) {
        Ok((_, _, target)) => target,
        Err((code, msg)) => {
            eprintln!("ops net-learn: {msg}");
            return ExitCode::from(code);
        }
    };
    if nl.dry_run {
        println!(
            "ops net-learn ({}): {} rule(s) would be added to {target} (dry run — nothing written):",
            nl.gran.as_str(),
            synth.rules.len()
        );
        for rule in &synth.rules {
            println!("  allow {rule}");
        }
        return ExitCode::SUCCESS;
    }
    // Write each rule through the shared persister, so a project write is trust-gated and re-trusted
    // exactly like `ops net allow`. One rule per call (each re-trusts a gated project write); a batch
    // writer is a future refinement.
    let mut failed = false;
    for rule in &synth.rules {
        match persist_egress_rule(EgressList::Allow, rule, &nl.scope, Some(name), &cwd) {
            Ok(msg) => println!("{msg}"),
            Err((_, msg)) => {
                eprintln!("ops net-learn: {msg}");
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

/// Parse the launch form of `ops app`: split ops's own arguments from the app command's trailing
/// arguments at the first `--`, then read the app name and `--detach` from the head. Tokens after
/// `--` are appended verbatim to the app's declared `cmd` (e.g. `ops app claude -- -c` passes `-c`
/// to the launched command, so an agent can resume a session or tweak a flag without editing the
/// profile). An unknown flag or a second name in the head is a usage error, so a typo cannot
/// silently launch a different posture (a mistyped `--detach` running attached, or extra tokens
/// dropped without a word). The passthrough arguments are host-user input at invocation time, so
/// they carry no config trust — an untrusted project cannot inject them, and the `cmd` integrity
/// gate (which blocks a config-supplied `cmd` override) is a separate, intact vector. A pure
/// parser so the split and the head rules are unit-tested without launching a cage; the caller
/// maps `Err(code)` to an exit.
///
/// A one-shot override (`--config <toml|@file>`/`--env KEY=VALUE`, repeatable) is read from the head
/// too, in any order with the name and `--detach`; the collected values are returned for the caller
/// to build the override (kept out of this pure parser, which reads no environment). The head is
/// parsed as a mutable queue so a value-taking flag can pull its argument.
fn parse_app_launch(args: &[OsString]) -> Result<AppLaunch, ExitCode> {
    use config::manage::Scope;
    let (mut head, tail): (Vec<OsString>, Vec<OsString>) = match args.iter().position(|a| a == "--")
    {
        Some(i) => (args[..i].to_vec(), args[i + 1..].to_vec()),
        None => (args.to_vec(), Vec::new()),
    };
    let mut detach = false;
    let mut name: Option<String> = None;
    let mut cli = config::CliOverrides::default();
    // `--net-learn` state: the granularity (once seen), the write scope, and whether to only preview.
    // The scope/`--dry-run` flags are meaningful only with `--net-learn`, enforced after the loop.
    let mut learn_gran: Option<sandbox::Granularity> = None;
    let mut scope = Scope::Local;
    let mut scope_seen = false;
    let mut dry_run = false;
    while !head.is_empty() {
        // Decide on the leading token, then act — the match ends the immutable borrow so a
        // value-taking flag can mutate the queue.
        let Some(raw) = head[0].to_str().map(str::to_string) else {
            eprintln!(
                "ops: app name must be valid text — usage: {}",
                help::synopsis("app")
            );
            return Err(ExitCode::from(2));
        };
        match flag_name(&raw) {
            "--detach" => {
                detach = true;
                head.remove(0);
            }
            // `--net-learn[=domain|path|exact]`: the value after `=` picks the granularity; a bare
            // flag is the widest, `domain`.
            "--net-learn" => {
                let gran = match raw.split_once('=') {
                    Some((_, value)) => match sandbox::Granularity::parse(value) {
                        Ok(g) => g,
                        Err(e) => {
                            eprintln!("ops: {e}");
                            return Err(ExitCode::from(2));
                        }
                    },
                    None => sandbox::Granularity::default(),
                };
                learn_gran = Some(gran);
                head.remove(0);
            }
            "--dry-run" => {
                dry_run = true;
                head.remove(0);
            }
            "--global" | "-g" => {
                scope = Scope::Global;
                scope_seen = true;
                head.remove(0);
            }
            "--local" | "-l" => {
                scope = Scope::Local;
                scope_seen = true;
                head.remove(0);
            }
            // A one-shot override flag, an unknown flag, or the app name.
            _ => match take_override_flag(&mut head, &mut cli, "app") {
                Some(res) => res?,
                None => {
                    if raw.starts_with('-') {
                        eprintln!("ops: unknown flag {raw} — usage: {}", help::synopsis("app"));
                        return Err(ExitCode::from(2));
                    }
                    if name.is_some() {
                        eprintln!(
                            "ops: app takes a single name — usage: {}",
                            help::synopsis("app")
                        );
                        return Err(ExitCode::from(2));
                    }
                    name = Some(raw);
                    head.remove(0);
                }
            },
        }
    }
    let Some(name) = name else {
        // No app name and no subcommand (bare `ops app`, or only flags): print the full page so
        // its Subcommands list and launch synopsis guide, like bare `ops net`/`ops config`.
        eprint!("{}", help::page_usage(&["app"]).unwrap_or_default());
        return Err(ExitCode::from(2));
    };
    // `--net-learn` reviews and writes rules in the foreground; `--detach` has no session to observe.
    if learn_gran.is_some() && detach {
        eprintln!(
            "ops: --net-learn cannot be combined with --detach (it observes a foreground run)."
        );
        return Err(ExitCode::from(2));
    }
    // The write scope and `--dry-run` only shape where `--net-learn` puts its rules; refuse them on a
    // plain launch rather than silently ignoring a flag the user expected to matter.
    if learn_gran.is_none() && (scope_seen || dry_run) {
        eprintln!("ops: --global/--local/--dry-run apply only with --net-learn.");
        return Err(ExitCode::from(2));
    }
    let net_learn = learn_gran.map(|gran| NetLearn {
        gran,
        scope,
        dry_run,
    });
    Ok(AppLaunch {
        name,
        detach,
        tail,
        cli,
        net_learn,
    })
}

/// The parsed launch form of `ops app`: the app name, `--detach`, the passthrough args after `--`,
/// the one-shot overrides, and the optional `--net-learn` intent.
struct AppLaunch {
    name: String,
    detach: bool,
    tail: Vec<OsString>,
    cli: config::CliOverrides,
    net_learn: Option<NetLearn>,
}

/// The `--net-learn` intent: how wide to synthesize rules, which profile to write them to, and
/// whether to only preview the diff.
struct NetLearn {
    gran: sandbox::Granularity,
    scope: config::manage::Scope,
    dry_run: bool,
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

/// `ops app rm <name> [--purge] [--gc]`: remove an app.
///
/// By default this removes only the imported **profile** (a file in the profiles directory) — a
/// project `[app.<name>]` overlay lives in that project's `.ops.toml` and is the user's to edit
/// there. With `--purge` it also removes the app's isolated **runtime state**: its per-app home(s)
/// (the mise tools its `mise:` backends installed, its config, and its login/session state), which
/// is freed immediately. `--gc` (which requires `--purge`) then sweeps the **current project's**
/// nix store — reclaiming the app's now-unreferenced `nix:`/`flake:` closures in one command for the
/// common single-project case (see [`app_rm_purge`]). The name is validated before it is joined to
/// any path (anti-traversal).
fn app_rm(args: &[OsString]) -> ExitCode {
    let (purge, gc, name) = match parse_app_rm(args) {
        AppRmArgs::Ok { purge, gc, name } => (purge, gc, name),
        AppRmArgs::MissingName => {
            eprintln!("ops: usage: {}", help::synopsis_of(&["app", "rm"]));
            return ExitCode::from(2);
        }
        AppRmArgs::UnknownOption(tok) => {
            eprintln!("ops: app rm: unknown option `{tok}`");
            eprintln!("ops: usage: {}", help::synopsis_of(&["app", "rm"]));
            return ExitCode::from(2);
        }
        AppRmArgs::Extra(tok) => {
            eprintln!("ops: app rm: unexpected argument `{tok}` (one app name only)");
            return ExitCode::from(2);
        }
        AppRmArgs::NonUtf8 => {
            eprintln!("ops: app rm: argument is not valid UTF-8");
            return ExitCode::from(2);
        }
    };
    if config::is_reserved_app_verb(name) || !config::is_valid_app_name(name) {
        eprintln!("ops: '{name}' is not a valid app name");
        return ExitCode::from(2);
    }
    // `--gc` reclaims the store an app's homes referenced, so it only makes sense alongside the
    // home removal `--purge` performs — never on a bare profile removal.
    if gc && !purge {
        eprintln!(
            "ops: app rm: `--gc` requires `--purge` (it sweeps the store the purged home used)"
        );
        return ExitCode::from(2);
    }
    if purge {
        app_rm_purge(name, gc)
    } else {
        app_rm_profile(name)
    }
}

/// The structural parse of `ops app rm` arguments (before name validation). Kept pure so the flag/
/// positional handling — `--purge`, `--gc`, and the single app name in any order — is unit-tested.
/// The name's charset/reserved-verb validation and the `--gc`-requires-`--purge` rule are the
/// caller's next steps.
enum AppRmArgs<'a> {
    Ok {
        purge: bool,
        gc: bool,
        name: &'a str,
    },
    MissingName,
    UnknownOption(&'a str),
    Extra(&'a str),
    NonUtf8,
}

fn parse_app_rm(args: &[OsString]) -> AppRmArgs<'_> {
    let mut purge = false;
    let mut gc = false;
    let mut name: Option<&str> = None;
    for arg in args {
        match arg.to_str() {
            Some("--purge") => purge = true,
            Some("--gc") => gc = true,
            Some(tok) if tok.starts_with('-') => return AppRmArgs::UnknownOption(tok),
            Some(tok) if name.is_none() => name = Some(tok),
            Some(tok) => return AppRmArgs::Extra(tok),
            None => return AppRmArgs::NonUtf8,
        }
    }
    match name {
        Some(name) => AppRmArgs::Ok { purge, gc, name },
        None => AppRmArgs::MissingName,
    }
}

/// Remove app `name`'s imported profile only (the default `ops app rm`). A missing profile is an
/// error here — the user asked to remove a profile and there is none to remove (with `--purge` a
/// missing profile is tolerated, since the homes may still exist).
fn app_rm_profile(name: &str) -> ExitCode {
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
                "ops: no imported profile '{name}' (a project [app.{name}] overlay lives in a \
                 project's .ops.toml — edit it there). To also remove an app's home/tools, use \
                 `ops app rm {name} --purge`."
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("ops: cannot remove {}: {e}", path.display());
            ExitCode::FAILURE
        }
    }
}

/// `ops app rm <name> --purge`: remove the profile **and** the app's isolated runtime state.
///
/// The runtime state is the per-app home(s): the global `<data>/apps/<name>/` and each per-project
/// `<data>/projects/<id>/apps/<name>/`. They hold the tools the app's `mise:` backends installed
/// (under the home's mise data dir), the app's config, and its login/session state — all removed
/// immediately, so "delete from mise" is satisfied here, not deferred. What this does **not** touch
/// is the shared per-project nix store: it backs every app in a project, so a purged app's
/// `nix:`/`flake:` closures are reclaimed by `ops gc`, which the closing note points at.
///
/// A running session of the app is a hard stop — deleting its home mid-run would corrupt it — so
/// this refuses until the session is stopped (the same live guard `ops gc` applies). Under `--purge`
/// a missing profile is tolerated (the homes may still exist), but finding *nothing at all* — no
/// profile and no home — is reported as a no-op so a typo never silently "succeeds".
///
/// When `gc` is set (the `--gc` flag), it then sweeps the **current project's** store via the same
/// path as `ops gc --prune`, reclaiming the app's now-unreferenced closures there in one command.
/// The sweep is a distinct step with its own prerequisites (a capable host, nix); its failure is
/// reflected in the exit code but never undoes the purge that already happened.
fn app_rm_purge(name: &str, gc: bool) -> ExitCode {
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (ok, n, warn, dim, r) = (pal.ok, pal.name, pal.warn, pal.dim, pal.reset);

    let Some(layout) = store::Layout::from_env() else {
        eprintln!("ops: cannot locate ops's data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };

    // Live-session guard: a session running as this app holds its home open. Refuse until it is
    // stopped, and fail closed if the registry cannot be read (a purge must not run unproven).
    match session::Registry::at(layout.data_dir()).list() {
        Ok(sessions) => {
            let pids: Vec<String> = sessions
                .iter()
                .filter(|s| s.app() == Some(name))
                .map(|s| s.pid.to_string())
                .collect();
            if !pids.is_empty() {
                eprintln!(
                    "ops: app '{name}' has a running session (pid {}); stop it first \
                     (see `ops ls`; then `ops stop {}`).",
                    pids.join(", "),
                    pids.join(" ")
                );
                return ExitCode::FAILURE;
            }
        }
        Err(e) => {
            eprintln!("ops: cannot read the session registry ({e}); not purging '{name}'.");
            return ExitCode::FAILURE;
        }
    }

    // 1. The profile (if any). Under --purge a missing profile is not fatal — the homes may still
    //    exist (an app whose profile was already removed, or a project/inline app that has none).
    let profile_removed = match config::profile_path(name) {
        Some(path) => match std::fs::remove_file(&path) {
            Ok(()) => {
                println!("{}", render_removed(Some("app profile"), name, &pal));
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => {
                eprintln!("ops: cannot remove {}: {e}", path.display());
                false
            }
        },
        None => false,
    };

    // 2. The isolated home(s): mise tools + config + login state, freed immediately.
    let report = sandbox::purge_app_homes(layout.data_dir(), name);
    for home in &report.removed {
        println!(
            "{ok}removed{r} home {n}{}{r} {dim}({}){r}",
            home.path.display(),
            sandbox::human_bytes(home.bytes)
        );
    }
    for (path, e) in &report.failed {
        eprintln!("{warn}ops: could not remove {}: {e}{r}", path.display());
    }

    // 3. Nothing found across either source → a no-op (likely a typo); do not report success.
    if !profile_removed && report.found_nothing() {
        eprintln!("ops: nothing to purge for '{name}' (no profile and no home)");
        return ExitCode::FAILURE;
    }

    // Name only what was actually removed: a purge with no profile present must not claim one.
    let removed_what = if profile_removed {
        "profile + mise tools + login state"
    } else {
        "mise tools + login state"
    };
    // A partial failure (a home that would not delete) is not a clean purge — say so, so the green
    // summary never contradicts the non-zero exit below.
    let verb = if report.failed.is_empty() {
        format!("{ok}purged{r}")
    } else {
        format!("{warn}purged with errors{r}")
    };
    println!(
        "{verb} app {n}{name}{r} — freed {n}{}{r} {dim}({removed_what}){r}",
        sandbox::human_bytes(report.freed())
    );
    // The purge itself left state behind if a home would not delete — surface it in the exit code.
    let purge_ok = report.failed.is_empty();

    // Any `nix:`/`flake:` tool closures the app built live in the shared per-project store, which
    // backs every app in a project. `--gc` sweeps the *current* project's store now; without it, the
    // reclamation is a separate manual step, and either way other projects need their own sweep.
    if gc {
        println!();
        let gc_code = sandbox::gc(true, false, &pal);
        println!(
            "{dim}note: `--gc` swept this project's store; run `ops gc --prune` in the app's other \
             projects to reclaim their copies too.{r}"
        );
        // The purge succeeded independently of the sweep; when it did, defer to the sweep's own exit
        // code so a sweep that could not run (no capable host, nix missing) is not hidden — but never
        // undo the purge's failure signal.
        return if purge_ok { gc_code } else { ExitCode::FAILURE };
    }

    println!(
        "{dim}note: an app's nix:/flake: tool closures live in the shared per-project store; \
         run `ops gc --prune` in a project to reclaim any no longer referenced there \
         (or re-run with --gc for the current project).{r}"
    );
    if purge_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// `ops app list`: what is on disk to manage — the imported **profiles** (`import`/`rm` artifacts),
/// and the apps with an **installed home** (their mise tools + login state, which `--purge` removes).
/// The two are distinct: an app can have a profile with no home yet (never launched), or a home with
/// no profile (launched from an inline/project app, or a profile since removed). The full resolved
/// app set — inline, project, and profile apps with their gating — is `ops config show`.
fn app_list() -> ExitCode {
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);

    // Imported profiles under <config>/ops/apps/*.toml.
    let profiles_dir = config::profiles_dir();
    let mut profiles: Vec<String> = Vec::new();
    if let Some(dir) = &profiles_dir {
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|x| x.to_str()) == Some("toml") {
                        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                            profiles.push(stem.to_string());
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
    }
    profiles.sort();

    // Installed homes under the data dir (an app can have one with no profile).
    let installed = store::Layout::from_env()
        .map(|l| sandbox::installed_app_homes(l.data_dir()))
        .unwrap_or_default();

    if profiles.is_empty() && installed.is_empty() {
        println!(
            "{dim}no imported app profiles and no installed app homes \
             (import one with: ops app import <file>){r}"
        );
        return ExitCode::SUCCESS;
    }

    if let Some(dir) = &profiles_dir {
        if profiles.is_empty() {
            println!("{dim}no imported app profiles (in {}){r}", dir.display());
        } else {
            println!("{h}imported app profiles{r} (in {n}{}{r}):", dir.display());
            for name in &profiles {
                println!("  {n}{name}{r}");
            }
        }
    }

    if !installed.is_empty() {
        println!("{h}installed app homes{r} {dim}(remove with --purge){r}:");
        let width = installed.iter().map(|a| a.name.len()).max().unwrap_or(0);
        for app in &installed {
            let padded = format!("{:<width$}", app.name);
            println!(
                "  {n}{padded}{r}  {dim}{}  ({}){r}",
                sandbox::human_bytes(app.total_bytes()),
                describe_home_locations(app),
            );
        }
    }

    println!(
        "{dim}(remove a profile: ops app rm <name>; also remove its home + tools: \
         ops app rm <name> --purge){r}"
    );
    ExitCode::SUCCESS
}

/// A compact description of where an app's installed homes live — `global`, `N project home(s)`, or
/// both joined with ` + ` — for the `ops app list` installed-homes line.
fn describe_home_locations(app: &sandbox::InstalledApp) -> String {
    let mut parts = Vec::new();
    if app.global_bytes.is_some() {
        parts.push("global".to_string());
    }
    match app.project_homes {
        0 => {}
        1 => parts.push("1 project home".to_string()),
        n => parts.push(format!("{n} project homes")),
    }
    parts.join(" + ")
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
        // Unknown or no kind: name the mistake (if any), then print the full page so its
        // Subcommands list guides, like bare `ops net`/`ops config`.
        other => {
            if let Some(tok) = other {
                eprintln!("ops: test: unknown kind {tok:?}");
            }
            eprint!("{}", help::page_usage(&["test"]).unwrap_or_default());
            ExitCode::from(2)
        }
    }
}

/// Fold the named app's overlay onto the resolved baseline so a read-only diagnostic sees the
/// *effective* policy `ops app <name>` would launch with — the shared core of `ops test net --app`
/// and `ops net rules --app`. The baseline warnings are the caller's to surface; this captures the
/// warning count *before* the merge and emits only the app's own new ones (no double-print). On an
/// unknown app it returns a pointed message (the caller prepends its own `ops: <verb>:` prefix);
/// the merge itself reuses `config::load` → `merge_app`, so the trust gate and the "a global app
/// keeps its posture under an untrusted project" property hold through that path, not new code.
fn fold_app_overlay(resolved: &mut config::Resolved, name: &str) -> Result<(), String> {
    let Some(app_cfg) = resolved.apps.remove(name) else {
        let names: Vec<&str> = resolved.apps.keys().map(String::as_str).collect();
        return Err(if names.is_empty() {
            format!("no app named {name:?} (no apps are declared for this directory)")
        } else {
            format!("no app named {name:?} (declared: {})", names.join(", "))
        });
    };
    let before = resolved.warnings.len();
    resolved.merge_app(app_cfg);
    for w in &resolved.warnings[before..] {
        diag::warn(w);
    }
    Ok(())
}

/// `ops test net [--app <name>] <url>`: test a URL against the egress policy a launch serves and
/// report the rule that decides it. A diagnostic for the egress allowlist — it reflects the trust
/// gate (an untrusted project's policy is dropped, so the *effective* posture is shown), folds in a
/// named app's overlay when `--app` is given, includes the built-in allow-set the proxy
/// always unions, and notes a credential the proxy would inject (by header and source, never its
/// value). A bare host with no scheme is completed to `https://`. No launch, no nix, no network.
/// Exit status is informational only (success), since "the URL would be denied" is a valid answer.
fn net_test(args: &[OsString]) -> ExitCode {
    // An optional `--app/-a <name>`, an optional `--method/-X <verb>` (the HTTP method to test,
    // default GET), and the positional target (a URL or a bare host), in any order.
    let mut app: Option<String> = None;
    let mut method: String = "GET".to_string();
    let mut target: Option<&str> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--app") | Some("-a") => {
                let Some(name) = it.next().and_then(|n| n.to_str()) else {
                    eprintln!("ops: test net: `--app` needs an app name");
                    return ExitCode::from(2);
                };
                app = Some(name.to_string());
            }
            Some("--method") | Some("-X") => {
                let Some(m) = it.next().and_then(|n| n.to_str()) else {
                    eprintln!("ops: test net: `--method` needs an HTTP verb (e.g. GET, POST)");
                    return ExitCode::from(2);
                };
                method = m.to_ascii_uppercase();
            }
            Some(s) if target.is_none() => target = Some(s),
            Some(s) => {
                eprintln!("ops: test net: unexpected argument `{s}`");
                return ExitCode::from(2);
            }
            None => {
                eprintln!("ops: test net: an argument is not valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    let Some(target) = target else {
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
    let mut resolved = config::load(&cwd);
    for w in &resolved.warnings {
        diag::warn(w);
    }
    // Fold a named app's overlay onto the baseline so the URL is tested against the *effective*
    // policy `ops app <name>` would launch with (its own posture, allow/deny rules, credentials),
    // not the bare baseline.
    if let Some(name) = &app {
        if let Err(e) = fold_app_overlay(&mut resolved, name) {
            eprintln!("ops: test net: {e}");
            return ExitCode::from(2);
        }
    }

    // A bare host (no scheme) is completed to https — the common case for a quick check.
    let url = if target.contains("://") {
        target.to_string()
    } else {
        format!("https://{target}")
    };

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, r) = (pal.head, pal.reset);
    // Names which posture is in view: the baseline, or one app's effective overlay.
    let scope = match &app {
        Some(name) => format!(" (app {name})"),
        None => String::new(),
    };
    match &resolved.network {
        config::NetworkPolicy::Shared => {
            println!(
                "{h}network{scope}:{r} shared (host network) — every URL is reachable; no allowlist to test"
            );
            ExitCode::SUCCESS
        }
        config::NetworkPolicy::Isolated => {
            println!("{h}network{scope}:{r} none (isolated) — no URL is reachable");
            ExitCode::SUCCESS
        }
        config::NetworkPolicy::Allowlist(policy) => {
            // Build the *effective* policy a launch serves: the user rules plus the built-in
            // allow-set the proxy always unions — the single source of truth, so the verdict here
            // matches the wire (e.g. a cache host reads as allowed, not deny-default).
            let effective = sandbox::union_with_builtin(policy.clone());
            // A one-line header so an ALLOWED/DENIED verdict on an arbitrary URL is
            // self-explanatory — it names the default the policy applies to an unmatched request.
            let mode = match effective.default_action() {
                allowlist::DefaultAction::Deny => {
                    "deny (allowlist — only listed and built-in hosts reach)"
                }
                allowlist::DefaultAction::Allow => {
                    "allow (denylist — every public host reaches except the deny rules)"
                }
                allowlist::DefaultAction::Ask => {
                    "ask (an unmatched host parks for a live `ops net pending` decision)"
                }
            };
            println!("{h}network{scope}:{r} {mode}");
            // A `tcp://` target is a raw-splice question, decided on host:port alone through the same
            // `l4_decision` the proxy uses (so the tester cannot drift from the wire). The L7 default
            // action above does not apply to it — a raw splice is strictly opt-in via a `tcp://` rule.
            if target.starts_with("tcp://") {
                let (host, port) = match allowlist::parse_tcp_target(target) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("ops: {e}");
                        return ExitCode::from(2);
                    }
                };
                let l4 = effective.l4_decision(&host, port);
                print!("{}", render_l4_decision(target, &l4, &pal));
                return ExitCode::SUCCESS;
            }
            let (host, port, path) = match allowlist::parse_url_target(&url) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("ops: {e}");
                    return ExitCode::from(2);
                }
            };
            // An `http://` URL is a cleartext (L7Clear) question, decided through the same
            // `explain_clear` the proxy's absolute-form handler uses (so the tester cannot drift from
            // the wire). Cleartext is strictly opt-in: only an explicit `http://` allow permits it —
            // the L7 default action above does not open it, so a bare host stays HTTPS-only here too.
            let clear = url.starts_with("http://");
            let decision = if clear {
                effective.explain_clear(&host, port, &path, &method)
            } else {
                effective.explain(&host, port, &path, &method)
            };
            // Tag a request allowed *only* by the built-in set (not the user's own
            // rules), so "why does this pass — I never allowed it?" is answerable. The union adds
            // only allow rules, so an effective `AllowedBy` the user policy does not also allow can
            // only be the built-in set. Discriminate on the user verdict's own variant (definitely
            // "the user allowed it") rather than a separate predicate. The `clear` question is
            // decided through the same `explain_clear`, so the tag matches the wire (the built-in set
            // is all `https://` hosts, so a cleartext allow is always the user's own).
            let user_decision = if clear {
                policy.explain_clear(&host, port, &path, &method)
            } else {
                policy.explain(&host, port, &path, &method)
            };
            let user_allowed = matches!(
                user_decision,
                allowlist::Decision::AllowedBy(_) | allowlist::Decision::AllowedDefault
            );
            let builtin = matches!(decision, allowlist::Decision::AllowedBy(_)) && !user_allowed;
            print!("{}", render_net_decision(&url, &decision, builtin, &pal));
            // On an allowed request, surface any credential the proxy would inject for this exact
            // destination — by header and source locator only, never the value, and with no I/O. A
            // **cleartext** (`http://`) request never receives an injection (a bearer is not sent in
            // the clear — the proxy skips injection wholesale), so no note is shown for it.
            if !clear
                && matches!(
                    decision,
                    allowlist::Decision::AllowedBy(_) | allowlist::Decision::AllowedDefault
                )
            {
                for secret in &resolved.secrets {
                    if allowlist::rule_matches(&secret.to, &host, port, &path) {
                        print!("{}", render_injection_note(secret, &pal));
                    }
                }
            }
            ExitCode::SUCCESS
        }
    }
}

/// Render an egress allowlist decision — a pure presenter (so its colored layout is asserted in a
/// test): the verdict (`ALLOWED` green / `DENIED` red), the URL and the deciding rule as
/// identifiers (cyan, matching how `ops config` renders allow/deny rules), and the reason as
/// de-emphasized prose. Every span is empty under a non-terminal, so a capture is plain text.
fn render_net_decision(
    url: &str,
    decision: &allowlist::Decision,
    builtin: bool,
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (n, ok, err, dim, r) = (pal.name, pal.ok, pal.err, pal.dim, pal.reset);
    let mut o = String::new();
    match decision {
        allowlist::Decision::AllowedBy(rule) => {
            let _ = writeln!(o, "{ok}ALLOWED{r}  {n}{url}{r}");
            // Name the source when the allow came from the built-in self-equip set rather than a
            // user rule, so a pass the config did not declare is explained, not surprising.
            if builtin {
                let _ = writeln!(o, "  {dim}by allow rule (built-in):{r} {n}{rule}{r}");
            } else {
                let _ = writeln!(o, "  {dim}by allow rule:{r} {n}{rule}{r}");
            }
        }
        allowlist::Decision::DeniedBy(rule) => {
            let _ = writeln!(o, "{err}DENIED{r}   {n}{url}{r}");
            let _ = writeln!(o, "  {dim}by deny rule (deny wins):{r} {n}{rule}{r}");
        }
        allowlist::Decision::DeniedDefault => {
            let _ = writeln!(o, "{err}DENIED{r}   {n}{url}{r}");
            let _ = writeln!(o, "  {dim}no allow rule matches (deny-by-default){r}");
        }
        allowlist::Decision::AllowedDefault => {
            let _ = writeln!(o, "{ok}ALLOWED{r}  {n}{url}{r}");
            let _ = writeln!(o, "  {dim}no deny rule matches (allow-by-default){r}");
        }
        allowlist::Decision::Ask => {
            // No static verdict: at launch this request would park for a live decision. Use the
            // dim hue (neither pass nor fail) so a tester reading the column is not misled.
            let _ = writeln!(o, "{dim}WOULD ASK{r} {n}{url}{r}");
            let _ = writeln!(
                o,
                "  {dim}no rule matches (ask-by-default — it would park for `ops net pending`){r}"
            );
        }
    }
    o
}

/// Render an L4 (`tcp://`) raw-splice decision for `ops test net tcp://host:port` — a pure presenter
/// (its color is asserted in a test). A raw splice is strictly opt-in, so the verdict is binary:
/// SPLICED (a `tcp://` allow rule covers this host:port and no host-level deny suppresses it — the
/// proxy tunnels it uninspected) or NOT SPLICED (the connection would instead take the inspected L7
/// path, which a non-HTTP protocol cannot satisfy). Every span is empty under a non-terminal, so a
/// capture is plain text.
fn render_l4_decision(target: &str, l4: &allowlist::L4Decision, pal: &style::Palette) -> String {
    use std::fmt::Write as _;
    let (n, ok, err, dim, r) = (pal.name, pal.ok, pal.err, pal.dim, pal.reset);
    let mut o = String::new();
    match l4 {
        allowlist::L4Decision::Splice(rule) => {
            let _ = writeln!(
                o,
                "{ok}SPLICED{r}  {n}{target}{r} {dim}(raw L4 — uninspected){r}"
            );
            let _ = writeln!(o, "  {dim}by allow rule:{r} {n}{rule}{r}");
        }
        allowlist::L4Decision::Suppressed(rule) => {
            let _ = writeln!(o, "{err}NOT SPLICED{r} {n}{target}{r}");
            let _ = writeln!(
                o,
                "  {dim}a deny rule suppressed the raw splice (deny wins): the connection takes the \
                 inspected L7 path, where it is denied (or, for a non-TLS protocol, the handshake \
                 fails closed). To allow raw access, drop or narrow the deny.{r}"
            );
            let _ = writeln!(o, "  {dim}by deny rule:{r} {n}{rule}{r}");
        }
        allowlist::L4Decision::NoMatch => {
            let _ = writeln!(o, "{err}NOT SPLICED{r} {n}{target}{r}");
            let _ = writeln!(
                o,
                "  {dim}no tcp:// rule covers this host:port — a raw tunnel needs an explicit \
                 `tcp://host:port` allow (a bare/https:// rule is inspected L7, which a non-HTTP \
                 protocol cannot satisfy){r}"
            );
        }
    }
    o
}

/// Render the dim "+ a credential would be injected" note for a secret whose destination matches
/// the tested request — by header name and source locator only (never the plaintext, and with no
/// I/O), mirroring how `ops config` describes a credential. A pure presenter (its color is asserted
/// in a test); every span is empty under a non-terminal, so a capture is plain text.
fn render_injection_note(secret: &config::HeaderSecret, pal: &style::Palette) -> String {
    let (dim, n, r) = (pal.dim, pal.name, pal.reset);
    format!(
        "  {dim}+ a credential would be injected:{r} {n}{}{r} {dim}(from {}){r}\n",
        secret.header,
        secret.describe_sources()
    )
}

/// The displayed keyword for a filtered-egress policy's default action: `allow` (a denylist —
/// everything public reaches except the deny rules) or `deny` (an allowlist — only the listed and
/// built-in hosts reach). Used wherever `ops config` renders a filtered network posture.
fn net_mode_word(default_action: config::view::NetDefaultView) -> &'static str {
    match default_action {
        config::view::NetDefaultView::Deny => "deny",
        config::view::NetDefaultView::Allow => "allow",
        config::view::NetDefaultView::Ask => "ask",
    }
}

/// `ops net <subcommand>`: the interactive-egress namespace. `rules` lists the effective egress
/// rules (optionally for one app), `allow`/`deny` persist a rule to a config file, `pending`
/// drives the live `ask`-posture control plane, and `stats` reports the per-host allow/deny/blocked
/// decision counters a launch recorded. Distinct from `ops test net <url>` (the URL matcher): `net`
/// is the listing/management surface.
fn net_cmd(args: Vec<OsString>) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("rules") => net_rules(&args[1..]),
        Some("groups") => net_groups(&args[1..]),
        Some("allow") => net_add_rule(config::manage::EgressList::Allow, &args[1..]),
        Some("deny") => net_add_rule(config::manage::EgressList::Deny, &args[1..]),
        // `mute` adds a `dontaudit` log-suppression rule; `unmute` removes one. Both are
        // config-level (the same scopes as allow/deny) — a live `--session` mute is not yet wired.
        Some("mute") => net_add_rule(config::manage::EgressList::Mute, &args[1..]),
        Some("unmute") => net_remove_rule(config::manage::EgressList::Mute, &args[1..]),
        Some("pending") => net_pending(&args[1..]),
        Some("stats") => net_stats(&args[1..]),
        // `log` is an accepted alias for `logs` so a typo does not error.
        Some("logs") | Some("log") => net_logs(&args[1..]),
        // `live` is the real-time view of the tunnels *currently open*, distinct from the decided
        // requests `logs` records.
        Some("live") => net_live(&args[1..]),
        // Unknown or no subcommand: name the mistake (if any), then print the full page — its
        // Subcommands list reveals rules/allow/deny/pending/… instead of a bare one-line synopsis,
        // the way `ops config` and bare `ops` guide.
        other => {
            if let Some(tok) = other {
                eprintln!("ops: net: unknown subcommand {tok:?}");
            }
            eprint!("{}", help::page_usage(&["net"]).unwrap_or_default());
            ExitCode::from(2)
        }
    }
}

/// `ops net pending` family — the live control plane for the `ask` egress posture (see
/// [`sandbox::control`]). With no verb it lists the requests parked across every reachable ask-mode
/// session; `allow <id>`/`deny <id>` answer one (`<id>` = `<pid>.<seq>` from the listing or the
/// launch's notice), optionally persisting a matching rule with `--save` + a scope. The control
/// sockets live under `<data>/egress`, never inside any cage.
fn net_pending(args: &[OsString]) -> ExitCode {
    use sandbox::control::Verdict;
    match args.first().and_then(|a| a.to_str()) {
        Some("allow") => net_pending_answer(Verdict::Allow, &args[1..]),
        Some("deny") => net_pending_answer(Verdict::Deny, &args[1..]),
        Some("watch") => net_pending_watch(&args[1..]),
        // No verb (or `--json`): list the pending requests.
        _ => net_pending_list(args),
    }
}

/// The data directory the control sockets live under, or a pointed error.
fn egress_data_dir() -> Result<PathBuf, String> {
    store::Layout::from_env()
        .map(|l| l.data_dir().to_path_buf())
        .ok_or_else(|| "cannot locate the data directory (set $HOME or $XDG_DATA_HOME)".to_string())
}

/// The human context of the ask-mode control sockets, cross-referenced from the session registry:
/// `(pid, project root, display label)` per live session. Best-effort — a session not in the
/// registry (a race, or one that failed to register) simply lists without context, and a `--save`
/// for it falls back to the cwd. The registry is keyed by the same pid the control socket filename
/// carries, so the two line up.
fn pending_session_context(data_dir: &Path) -> Vec<(u32, PathBuf, String)> {
    session::Registry::at(data_dir)
        .list()
        .unwrap_or_default()
        .into_iter()
        .map(|s| {
            let label = s.label();
            (s.pid, s.project, label)
        })
        .collect()
}

/// The live-session pids that belong to app `name` (an `ops app <name>` session), from the registry
/// — the basis for scoping `ops net pending` to one app. A session not in the registry (a race, or a
/// plain shell) has no known app, so under a filter it is excluded: scoping to an app shows only
/// sessions the registry confirms are that app.
fn session_pids_for_app(data_dir: &Path, name: &str) -> std::collections::HashSet<u32> {
    session::Registry::at(data_dir)
        .list()
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.app() == Some(name))
        .map(|s| s.pid)
        .collect()
}

/// The app a session pid runs as (`ops app <name>`), from the registry — or `None` if the session is
/// a plain project shell, or is not in the registry. The basis for validating that a `<pid>.<seq>` id
/// the user scoped with `--app` really belongs to that app.
fn session_app_of(data_dir: &Path, pid: u32) -> Option<String> {
    session::Registry::at(data_dir)
        .list()
        .unwrap_or_default()
        .into_iter()
        .find(|s| s.pid == pid)
        .and_then(|s| s.app().map(str::to_string))
}

/// The live-session pids running in `project` (a canonical project root), from the registry — the
/// basis for scoping `ops net pending` to the current project. The match is `s.project == project`,
/// the exact comparison the launch path records and `ops gc` already uses (both sides go through
/// [`sandbox::project_identity`]), so a session and its project never disagree. A session not in the
/// registry has no known project, so under a filter it is excluded.
fn session_pids_for_project(data_dir: &Path, project: &Path) -> std::collections::HashSet<u32> {
    session::Registry::at(data_dir)
        .list()
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.project == project)
        .map(|s| s.pid)
        .collect()
}

/// Query the live control sockets for the parked requests, scoped to one app's session(s) when
/// `app` is set, and pair them with their registry context (`(pid, project, label)`). The shared
/// gather step behind both the one-shot listing and the `watch` loop. No launch / nix / network.
fn collect_pending(
    data_dir: &Path,
    app: Option<&str>,
) -> (
    Vec<sandbox::control::SessionPending>,
    Vec<(u32, PathBuf, String)>,
) {
    let mut sessions = sandbox::control::list_all(data_dir);
    // `--app <name>` scopes the listing to that app's session(s) (the registry maps pid → app).
    if let Some(name) = app {
        let pids = session_pids_for_app(data_dir, name);
        sessions.retain(|s| pids.contains(&s.pid));
    }
    let context = pending_session_context(data_dir);
    (sessions, context)
}

/// `ops net pending [-a|--app <name>] [--json]`: list every reachable ask-mode session's parked
/// requests, grouped by session (with its agent/project context); identical retries of one URL
/// collapse to a single destination carrying the `<pid>.<seq>` id to answer it (and, in `--json`, a
/// `count`). `--app <name>` limits the listing to that app's session(s). No launch / nix / network —
/// it just queries the live control sockets. An empty result is a clean success (nothing is waiting).
fn net_pending_list(args: &[OsString]) -> ExitCode {
    let mut json = false;
    let mut app: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--json") => json = true,
            Some("--app") | Some("-a") => match it.next() {
                Some(name) => app = Some(name.to_string_lossy().into_owned()),
                None => {
                    eprintln!("ops: `--app` needs an app name");
                    return ExitCode::from(2);
                }
            },
            _ => {
                eprintln!("ops: usage: {}", help::synopsis_of(&["net", "pending"]));
                return ExitCode::from(2);
            }
        }
    }
    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (sessions, context) = collect_pending(&data_dir, app.as_deref());
    let ctx_of = |pid: u32| context.iter().find(|(p, _, _)| *p == pid);

    if json {
        // Grouped like the human listing — one object per destination, not per connection — because
        // `allow <id>` now answers the whole destination: exposing every individually-addressable seq
        // would mislead a consumer into per-seq answering (the first answers the group, the rest are
        // NotFound). `count` carries how many connections collapsed; `id` is the representative.
        let rows: Vec<_> = sessions
            .iter()
            .flat_map(|s| {
                let ctx = ctx_of(s.pid);
                let project = ctx.map(|(_, p, _)| p.display().to_string());
                let label = ctx.map(|(_, _, l)| l.clone());
                group_pending(&s.rows)
                    .into_iter()
                    .map(move |g| {
                        serde_json::json!({
                            "id": sandbox::control::format_id(s.pid, g.seq),
                            "pid": s.pid,
                            "project": project,
                            "label": label,
                            "host": g.host,
                            "port": g.port,
                            "path": g.path,
                            "count": g.count,
                            "waiting_secs": g.waiting_secs,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        println!("{}", serde_json::json!({ "pending": rows }));
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!(
        "{}",
        render_pending(&sessions, &context, app.as_deref(), &pal)
    );
    ExitCode::SUCCESS
}

/// The parsed `ops net pending watch` flags: how often to refresh, and an optional app scope.
#[derive(Debug)]
struct WatchArgs {
    interval: Duration,
    app: Option<String>,
}

/// Parse `watch [-i|--interval <secs>] [-a|--app <name>]`. Pure (no I/O), so every reject path is
/// unit-testable without a terminal or entering the loop: a missing value, a non-numeric or zero
/// interval, or an unknown flag is an error. The refresh defaults to 2 seconds.
fn parse_watch_args(args: &[OsString]) -> Result<WatchArgs, String> {
    let mut interval_secs: u64 = 2;
    let mut app: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("-i") | Some("--interval") => {
                let v = it.next().ok_or("`--interval` needs a value in seconds")?;
                let secs: u64 = v.to_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
                    format!(
                        "invalid interval `{}` — expected a whole number of seconds",
                        v.to_string_lossy()
                    )
                })?;
                if secs == 0 {
                    return Err("interval must be at least 1 second".into());
                }
                interval_secs = secs;
            }
            Some("-a") | Some("--app") => {
                let name = it.next().ok_or("`--app` needs an app name")?;
                app = Some(name.to_string_lossy().into_owned());
            }
            _ => {
                return Err(format!(
                    "usage: {}",
                    help::synopsis_of(&["net", "pending", "watch"])
                ));
            }
        }
    }
    Ok(WatchArgs {
        interval: Duration::from_secs(interval_secs),
        app,
    })
}

/// `ops net pending watch [-i|--interval <secs>] [-a|--app <name>]`: redraw the parked-request
/// listing in place on an interval (default 2s) until interrupted. A `top`-style poll of the same
/// live control sockets `ops net pending` queries — no launch, nix, or network, and nothing is held
/// open between ticks. Requires a terminal (the frame is redrawn in place); the one-shot listing
/// (optionally `--json`) is the path for a pipe or a script.
fn net_pending_watch(args: &[OsString]) -> ExitCode {
    use std::io::Write as _;
    let parsed = match parse_watch_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ops: {e}");
            return ExitCode::from(2);
        }
    };
    let is_tty = std::io::stdout().is_terminal();
    if !is_tty {
        eprintln!(
            "ops: `watch` needs a terminal — use `ops net pending` for a one-shot listing, \
             or `--json` to script it"
        );
        return ExitCode::from(2);
    }
    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: {e}");
            return ExitCode::FAILURE;
        }
    };
    let pal = style::Palette::for_stream(is_tty);
    let (dim, r) = (pal.dim, pal.reset);
    let secs = parsed.interval.as_secs();
    loop {
        let (sessions, context) = collect_pending(&data_dir, parsed.app.as_deref());
        let body = render_pending(&sessions, &context, parsed.app.as_deref(), &pal);
        // `top`-style in-place redraw: home the cursor, paint the frame, then clear from the cursor to
        // the end of the screen. This keeps the terminal scrollback intact (unlike `\x1b[3J`) and
        // erases any trailing lines a shorter frame leaves behind, with no full-screen blank flicker.
        // Interrupting mid-watch just leaves the last frame on screen — no cleanup is owed.
        let mut out = std::io::stdout().lock();
        let _ = write!(
            out,
            "\x1b[H{dim}watching · refresh {secs}s · Ctrl-C to quit{r}\n{body}\x1b[J"
        );
        let _ = out.flush();
        std::thread::sleep(parsed.interval);
    }
}

/// Parsed `ops net live` options: the redraw interval, an optional app filter, and JSON output.
#[derive(Debug)]
struct LiveArgs {
    interval: Duration,
    app: Option<String>,
    json: bool,
}

/// Parse `live [-i|--interval <secs>] [-a|--app <name>] [--json]`. Pure (no I/O), so every reject path
/// is unit-testable without a terminal. The refresh defaults to 1 second — a live view wants a
/// snappier tick than the pending watch. A missing/zero/non-numeric interval or an unknown flag errors.
fn parse_live_args(args: &[OsString]) -> Result<LiveArgs, String> {
    let mut interval_secs: u64 = 1;
    let mut app: Option<String> = None;
    let mut json = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("-i") | Some("--interval") => {
                let v = it.next().ok_or("`--interval` needs a value in seconds")?;
                let secs: u64 = v.to_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
                    format!(
                        "invalid interval `{}` — expected a whole number of seconds",
                        v.to_string_lossy()
                    )
                })?;
                if secs == 0 {
                    return Err("interval must be at least 1 second".into());
                }
                interval_secs = secs;
            }
            Some("-a") | Some("--app") => {
                let name = it.next().ok_or("`--app` needs an app name")?;
                app = Some(name.to_string_lossy().into_owned());
            }
            Some("--json") => json = true,
            _ => return Err(format!("usage: {}", help::synopsis_of(&["net", "live"]))),
        }
    }
    Ok(LiveArgs {
        interval: Duration::from_secs(interval_secs),
        app,
        json,
    })
}

/// Query the live control sockets for the tunnels open right now, scoped to one app's session(s) when
/// `app` is set, and pair them with their registry context (`(pid, project, label)`). The shared
/// gather behind each `net live` tick. No launch / nix / network.
fn collect_flows(
    data_dir: &Path,
    app: Option<&str>,
) -> (
    Vec<sandbox::control::SessionFlows>,
    Vec<(u32, PathBuf, String)>,
) {
    let mut sessions = sandbox::control::flows_all(data_dir);
    if let Some(name) = app {
        let pids = session_pids_for_app(data_dir, name);
        sessions.retain(|s| pids.contains(&s.pid));
    }
    let context = pending_session_context(data_dir);
    (sessions, context)
}

/// Render a flow's age compactly: `12s`, `3m04s`, `2h05m`.
fn format_flow_age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Render the open-flow listing — a pure presenter (its layout is asserted in a test): the tunnels
/// open right now grouped under a per-session header (registry label + project), each a
/// `host:port  proto  age  ↑up ↓down` line. An empty listing says so and names what populates it.
/// `now_ms` is passed in (not read from the clock) so the age column is deterministic under test.
fn render_live(
    sessions: &[sandbox::control::SessionFlows],
    context: &[(u32, PathBuf, String)],
    app: Option<&str>,
    now_ms: u128,
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let mut o = String::new();
    let total: usize = sessions.iter().map(|s| s.flows.len()).sum();
    if total == 0 {
        match app {
            Some(name) => {
                let _ = writeln!(
                    o,
                    "{h}open egress flows:{r} {dim}(none for app `{name}` — its session(s) have no \
                     tunnel open right now){r}"
                );
            }
            None => {
                let _ = writeln!(
                    o,
                    "{h}open egress flows:{r} {dim}(none — no egress tunnel is open right now){r}"
                );
            }
        }
        return o;
    }
    let _ = writeln!(o, "{h}open egress flows:{r}");
    for session in sessions {
        if session.flows.is_empty() {
            continue;
        }
        // A per-session header from the registry, so with several agents the user can tell which one
        // each flow belongs to.
        match context.iter().find(|(pid, _, _)| *pid == session.pid) {
            Some((_, project, label)) => {
                let _ = writeln!(
                    o,
                    "  {dim}session {} [{}] {}{r}",
                    session.pid,
                    label,
                    project.display()
                );
            }
            None => {
                let _ = writeln!(o, "  {dim}session {} (unregistered){r}", session.pid);
            }
        }
        for f in &session.flows {
            // Age from the passed-in clock; saturate against any skew between the proxy and this reader
            // (a flow's start is never really in the future).
            let age = format_flow_age((now_ms.saturating_sub(f.start_epoch_ms) / 1000) as u64);
            let _ = writeln!(
                o,
                "    {n}{}:{}{r}  {}  {dim}{}{r}  {dim}↑{} ↓{}{r}",
                f.host,
                f.port,
                f.proto.as_str(),
                age,
                sandbox::human_bytes(f.up),
                sandbox::human_bytes(f.down),
            );
        }
    }
    o
}

/// Emit one `ops net live --json` snapshot object (the whole state this tick, NDJSON — one object per
/// line, not one per flow: a live view is a state, not an event stream). Each flow carries its session
/// context, destination, transport, age, and byte totals.
fn flush_live_json(
    out: &mut impl std::io::Write,
    sessions: &[sandbox::control::SessionFlows],
    context: &[(u32, PathBuf, String)],
    now_ms: u128,
) -> std::io::Result<()> {
    let flows: Vec<_> = sessions
        .iter()
        .flat_map(|s| {
            let ctx = context.iter().find(|(p, _, _)| *p == s.pid);
            let project = ctx.map(|(_, p, _)| p.display().to_string());
            let label = ctx.map(|(_, _, l)| l.clone());
            s.flows.iter().map(move |f| {
                serde_json::json!({
                    "pid": s.pid,
                    "project": project,
                    "label": label,
                    "host": f.host,
                    "port": f.port,
                    "proto": f.proto.as_str(),
                    "age_ms": now_ms.saturating_sub(f.start_epoch_ms) as u64,
                    "up": f.up,
                    "down": f.down,
                })
            })
        })
        .collect();
    let obj = serde_json::json!({ "flows": flows });
    writeln!(out, "{obj}")?;
    out.flush()
}

/// `ops net live [-i|--interval <secs>] [-a|--app <name>] [--json]`: show the egress tunnels open
/// right now — one line per flow (destination, transport, age, bytes each way) — redrawn in place on
/// an interval (default 1s) until interrupted. A `top`-style live view of the same control sockets
/// `ops net logs` reads, but of *open connections* rather than *decided requests*. Because the proxy
/// closes each inspected L7 request after one response, short API calls flash by in under a second; the
/// durable rows are raw `tcp://` tunnels (SSH/DB), WebSockets, and large L7 transfers in progress.
/// Requires a terminal (the frame redraws in place); `--json` emits one snapshot object per tick and
/// works in a pipe. No launch / nix / network — it just polls the live control sockets.
fn net_live(args: &[OsString]) -> ExitCode {
    use std::io::Write as _;
    let parsed = match parse_live_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ops: {e}");
            return ExitCode::from(2);
        }
    };
    let is_tty = std::io::stdout().is_terminal();
    if !parsed.json && !is_tty {
        eprintln!(
            "ops: `net live` needs a terminal — use `--json` to script it (one snapshot per tick)"
        );
        return ExitCode::from(2);
    }
    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: {e}");
            return ExitCode::FAILURE;
        }
    };
    let pal = style::Palette::for_stream(is_tty);
    let (dim, r) = (pal.dim, pal.reset);
    let secs = parsed.interval.as_secs();
    loop {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let (sessions, context) = collect_flows(&data_dir, parsed.app.as_deref());
        // Build this tick's frame, then write it once — a broken downstream pipe (`… | head`) is
        // detected on the single write and ends the view cleanly (Rust ignores SIGPIPE).
        let mut out = std::io::stdout().lock();
        let wrote = if parsed.json {
            // One snapshot object per tick (NDJSON) — a live state, not a per-flow event stream.
            flush_live_json(&mut out, &sessions, &context, now_ms)
        } else {
            // `top`-style in-place redraw: home the cursor, paint the frame, then clear to end of
            // screen (keeps scrollback intact and erases a shorter frame's trailing lines).
            let body = render_live(&sessions, &context, parsed.app.as_deref(), now_ms, &pal);
            write!(
                out,
                "\x1b[H{dim}live egress · refresh {secs}s · Ctrl-C to quit{r}\n{body}\x1b[J"
            )
            .and_then(|_| out.flush())
        };
        drop(out);
        if wrote.is_err() {
            return ExitCode::SUCCESS;
        }
        std::thread::sleep(parsed.interval);
    }
}

/// One collapsed group of identical pending requests (same `host:port/path`): the representative id
/// (the lowest seq — the id to answer, which wakes the whole group), how many were collapsed, and the
/// longest wait (the oldest still parked).
struct PendingGroup<'a> {
    seq: u64,
    host: &'a str,
    port: u16,
    path: &'a str,
    count: usize,
    waiting_secs: u64,
}

/// Collapse a session's parked requests by destination, preserving first-seen (lowest-seq) order. A
/// tool that retries one URL re-parks it many times; those are a single decision, so the listing
/// shows one line per destination rather than one per connection.
fn group_pending(rows: &[sandbox::control::PendingRow]) -> Vec<PendingGroup<'_>> {
    let mut groups: Vec<PendingGroup> = Vec::new();
    for row in rows {
        match groups
            .iter_mut()
            .find(|g| g.host == row.host && g.port == row.port && g.path == row.path)
        {
            Some(g) => {
                g.count += 1;
                g.seq = g.seq.min(row.seq);
                g.waiting_secs = g.waiting_secs.max(row.waiting_secs);
            }
            None => groups.push(PendingGroup {
                seq: row.seq,
                host: &row.host,
                port: row.port,
                path: &row.path,
                count: 1,
                waiting_secs: row.waiting_secs,
            }),
        }
    }
    groups
}

/// Render the pending-request listing — a pure presenter (its colored layout is asserted in a test):
/// the parked requests grouped under a per-session header (the registry label + project, so several
/// sessions are told apart), each destination a `<pid>.<seq>` id, target, and wait time. Identical
/// retries of one URL collapse to a single `×N` line. An empty listing says so and points at how
/// requests arrive (an `ask`-posture launch); under an `--app` filter it names the app, so an empty
/// result is not mistaken for "nothing parked anywhere" when other apps do have requests.
fn render_pending(
    sessions: &[sandbox::control::SessionPending],
    context: &[(u32, PathBuf, String)],
    app: Option<&str>,
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let mut o = String::new();
    let total: usize = sessions.iter().map(|s| s.rows.len()).sum();
    if total == 0 {
        match app {
            Some(name) => {
                let _ = writeln!(
                    o,
                    "{h}pending egress requests:{r} {dim}(none for app `{name}` — nothing parked in \
                     its `ask`-mode session(s)){r}"
                );
            }
            None => {
                let _ = writeln!(
                    o,
                    "{h}pending egress requests:{r} {dim}(none — a request parks here only under \
                     `[network] mode = \"ask\"`){r}"
                );
            }
        }
        return o;
    }
    let _ = writeln!(o, "{h}pending egress requests:{r}");
    for session in sessions {
        // A per-session header from the registry, so with several agents the user can tell which one
        // each request belongs to (the literal reason the control plane is multi-session).
        match context.iter().find(|(pid, _, _)| *pid == session.pid) {
            Some((_, project, label)) => {
                let _ = writeln!(
                    o,
                    "  {dim}session {} [{}] {}{r}",
                    session.pid,
                    label,
                    project.display()
                );
            }
            None => {
                let _ = writeln!(o, "  {dim}session {} (unregistered){r}", session.pid);
            }
        }
        // Collapse identical destinations: a tool that retries one URL re-parks it many times, and
        // they are a single decision. `×N` is itself a signal — an agent hammering one endpoint.
        for group in group_pending(&session.rows) {
            let id = sandbox::control::format_id(session.pid, group.seq);
            let times = if group.count > 1 {
                format!("×{}, ", group.count)
            } else {
                String::new()
            };
            let _ = writeln!(
                o,
                "    {n}{id}{r}  {}:{}{}  {dim}({times}waiting {}s){r}",
                group.host, group.port, group.path, group.waiting_secs
            );
        }
    }
    let _ = writeln!(
        o,
        "  {dim}answer: ops net pending allow <id> [--save --local|--global|--app <name>]{r}"
    );
    let _ = writeln!(
        o,
        "  {dim}        ops net pending allow|deny --all  (drain every parked request at once){r}"
    );
    o
}

/// `ops net pending allow|deny <id> [--save --local|--global|--app <name>]`: answer one parked
/// request live. The unblock is the primary action; `--save` additionally persists a matching rule
/// (the request's host) through the shared writer so the same host is pre-decided next launch — a
/// secondary step whose failure is a warning, never undoing the answer. `<id>` is `<pid>.<seq>`.
fn net_pending_answer(verdict: sandbox::control::Verdict, args: &[OsString]) -> ExitCode {
    use config::manage::EgressList;
    let verb = match verdict {
        sandbox::control::Verdict::Allow => "allow",
        sandbox::control::Verdict::Deny => "deny",
    };
    // `--all`, `--save` and `--session` are extracted before `split_scope`, which rejects any flag
    // it does not know. The id is the lone positional; the scope flags (--local/--global/--app) ride
    // `split_scope` and apply only with `--save`. `--session` remembers the decision for the live
    // session (no config write); the two combine.
    let all = args.iter().any(|a| a.to_str() == Some("--all"));
    let save = args.iter().any(|a| a.to_str() == Some("--save"));
    let session = args.iter().any(|a| a.to_str() == Some("--session"));
    let rest: Vec<OsString> = args
        .iter()
        .filter(|a| {
            !matches!(
                a.to_str(),
                Some("--save") | Some("--session") | Some("--all")
            )
        })
        .cloned()
        .collect();

    // `--all` drains every parked request across every reachable session (or, with `--app <name>`,
    // that one app's session(s)). With `--save` it also persists a rule per answered host; the drain
    // is then scoped to match the save target — `--local` (the default) writes the *current project's*
    // config and so restricts the drain to that project, which is what makes a bulk local save
    // unambiguous (it can never answer one project's requests into another's config). Without `--save`,
    // a scope flag is meaningless (there is no file to write), so it is refused.
    if all {
        let parsed = match split_scope(&rest) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("ops: {e}");
                return ExitCode::from(2);
            }
        };
        if !parsed.positionals.is_empty() {
            eprintln!(
                "ops: `--all` answers every parked request and takes no id \
                 (use `--app <name>` to limit it to one app; `--session` to remember)"
            );
            return ExitCode::from(2);
        }
        if save {
            return net_pending_drain_and_save(
                verdict,
                session,
                &parsed.scope,
                parsed.app.as_deref(),
            );
        }
        if parsed.scope_explicit {
            eprintln!(
                "ops: `--all` without `--save` takes no scope (--local/--global/-c) — add `--save` \
                 to persist a rule per host, or use `--app <name>` to limit the drain to one app"
            );
            return ExitCode::from(2);
        }
        return net_pending_answer_all(verdict, session, parsed.app.as_deref());
    }
    let parsed = match split_scope(&rest) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ops: {e}");
            return ExitCode::from(2);
        }
    };
    let id = match parsed.positionals.as_slice() {
        [id] => id.as_str(),
        _ => {
            eprintln!(
                "ops: usage: {}",
                help::synopsis_of(&["net", "pending", verb])
            );
            return ExitCode::from(2);
        }
    };
    let Some((pid, seq)) = sandbox::control::parse_id(id) else {
        eprintln!("ops: invalid pending id '{id}' (expected <pid>.<seq>, e.g. 12345.1)");
        return ExitCode::from(2);
    };
    // A *config* scope (--global / -c) without `--save` is meaningless — there is no rule to write, so
    // flag it rather than silently ignore it. `--local` is the `split_scope` default, so a bare oneshot
    // does not trip it. `--app` is deliberately *not* here: it doubles as a session scope, so it is
    // honored without `--save` too (a natural carry-over from `ops net pending -a <app>`) and validated
    // against the id below.
    if !save && !matches!(parsed.scope, config::manage::Scope::Local) {
        eprintln!("ops: --global/-c only applies with --save (it names where to persist the rule)");
        return ExitCode::from(2);
    }

    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: {e}");
            return ExitCode::FAILURE;
        }
    };
    // `--app <name>` on the by-id path asserts the id belongs to that app. The id already names the
    // exact session, so this is a consistency check, not a filter: if the registry knows this session
    // as a *different* app, the assertion is wrong → flag it (and, with `--save`, the save would land
    // in the wrong app's config). An unregistered session or a plain shell (no known app) is given the
    // benefit of the doubt — the id is authoritative.
    if let Some(name) = parsed.app.as_deref() {
        if let Some(actual) = session_app_of(&data_dir, pid) {
            if actual != name {
                eprintln!("ops: {id} is a session of app `{actual}`, not `{name}`");
                return ExitCode::from(2);
            }
        }
    }
    let (host, count) =
        match sandbox::control::answer_request(&data_dir, pid, seq, verdict, session) {
            Ok(sandbox::control::AnswerOutcome::Answered { host, count }) => (host, count),
            Ok(sandbox::control::AnswerOutcome::NotFound) => {
                eprintln!(
                "ops: no pending request '{id}' (it may have been answered already or timed out)"
            );
                return ExitCode::from(2);
            }
            Err(_) => {
                eprintln!(
                    "ops: no live session for '{id}' (the launch may have ended, or its socket is \
                 stale)"
                );
                return ExitCode::from(2);
            }
        };
    // `<id>` names one parked request, but identical retries of the same URL collapse to one decision
    // — so the answer may have woken several. `×N` mirrors the grouped listing.
    let times = if count > 1 {
        format!(" (×{count})")
    } else {
        String::new()
    };
    if session {
        println!("{verb}ed {host}{times} for {id} (remembered for this session)");
    } else {
        println!("{verb}ed {host}{times} for {id}");
    }

    // `--save` persists a matching rule (the host) so the same destination is pre-decided next
    // launch: an allow becomes an allow rule, a deny a deny rule. The live answer already stuck, so
    // a save failure is a warning, never a hard failure that would imply the answer was undone.
    if save {
        let list = match verdict {
            sandbox::control::Verdict::Allow => EgressList::Allow,
            sandbox::control::Verdict::Deny => EgressList::Deny,
        };
        // Resolve a `--local` save against the *answered session's* project (from the registry), not
        // the cwd — the rule belongs in the project the agent runs in, which may not be where the
        // user is standing. Fall back to the cwd if the session is not in the registry.
        let base = pending_session_context(&data_dir)
            .into_iter()
            .find(|(p, _, _)| *p == pid)
            .map(|(_, project, _)| project)
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        match persist_egress_rule(list, &host, &parsed.scope, parsed.app.as_deref(), &base) {
            Ok(message) => println!("{message}"),
            Err((_, message)) => {
                diag::warn(&format!("answered, but could not save the rule: {message}"));
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

/// `ops net pending allow|deny --all [-a|--app <name>] [--session]`: drain every parked request
/// across every reachable ask-mode session in one shot — or, with `--app <name>`, only that app's
/// session(s). A point-in-time bulk answer — a request that parks *after* the drain still waits. It
/// reports per session what it answered, so a cross-agent grant (one keystroke can open egress for
/// several agents at once) is visible rather than a silent aggregate count. `--session` remembers
/// each answered host for its session. A session that vanished between the socket glob and the drain
/// is skipped (best-effort, mirroring the listing).
fn net_pending_answer_all(
    verdict: sandbox::control::Verdict,
    session: bool,
    app: Option<&str>,
) -> ExitCode {
    let past = match verdict {
        sandbox::control::Verdict::Allow => "allowed",
        sandbox::control::Verdict::Deny => "denied",
    };
    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: {e}");
            return ExitCode::FAILURE;
        }
    };
    let context = pending_session_context(&data_dir);
    // `--app <name>` scopes the drain to that app's session pids (from the registry); an unregistered
    // session has no known app, so it is excluded under a filter.
    let app_pids = app.map(|name| session_pids_for_app(&data_dir, name));
    let mut answered: Vec<(u32, Vec<String>)> = Vec::new();
    let mut unsupported: Vec<u32> = Vec::new();
    for pid in sandbox::control::session_pids(&data_dir) {
        if let Some(pids) = &app_pids {
            if !pids.contains(&pid) {
                continue;
            }
        }
        match sandbox::control::drain_session(&data_dir, pid, verdict, session) {
            Ok(sandbox::control::DrainOutcome::Drained(hosts)) if !hosts.is_empty() => {
                answered.push((pid, hosts))
            }
            // A healthy session with nothing parked — nothing to report.
            Ok(sandbox::control::DrainOutcome::Drained(_)) => {}
            // A session launched by an older ops that does not understand `--all` — its requests stay
            // parked, so name it rather than fold it into a misleading "nothing parked".
            Ok(sandbox::control::DrainOutcome::Unsupported) => unsupported.push(pid),
            // A dead/stale socket (the session went away) — skip it.
            Err(_) => {}
        }
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!(
        "{}",
        render_drain(past, session, app, &answered, &unsupported, &context, &pal)
    );
    ExitCode::SUCCESS
}

/// Render a bulk `--all` drain: a per-session breakdown of the hosts it answered (so the user sees
/// exactly what was granted/refused, across which agents), then a total. An empty drain says nothing
/// was parked (naming the `--app` filter when one narrowed the scope, so an empty result is not
/// mistaken for "nothing anywhere"). A pure presenter — its palette comes from the caller (plain on a
/// captured stream).
/// Collapse a session's answered-host list — one entry per parked request, so a host repeats once per
/// request — into first-seen order paired with an occurrence count. A burst of retries (or several
/// paths) to one destination then reads as a single `host ×N` line instead of N identical lines. The
/// fold is host-granular: the drain wire format carries only `answered host=`, so distinct paths and
/// plain retries to the same host both add to the one count.
fn collapse_hosts(hosts: &[String]) -> Vec<(&str, usize)> {
    let mut order: Vec<(&str, usize)> = Vec::new();
    for host in hosts {
        match order.iter_mut().find(|(h, _)| *h == host.as_str()) {
            Some(entry) => entry.1 += 1,
            None => order.push((host.as_str(), 1)),
        }
    }
    order
}

fn render_drain(
    past: &str,
    session: bool,
    app: Option<&str>,
    answered: &[(u32, Vec<String>)],
    unsupported: &[u32],
    context: &[(u32, PathBuf, String)],
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (h, n, warn, dim, r) = (pal.head, pal.name, pal.warn, pal.dim, pal.reset);
    let mut o = String::new();
    let total: usize = answered.iter().map(|(_, hosts)| hosts.len()).sum();
    if total == 0 {
        // Nothing answered. Distinguish "every session is healthy but empty" from "the only sessions
        // present were launched by an older ops that does not understand `--all`" — the latter would
        // otherwise read as "nothing parked" while requests are in fact still blocked.
        if unsupported.is_empty() {
            match app {
                Some(name) => {
                    let _ = writeln!(
                        o,
                        "{dim}no pending requests for app `{name}` (nothing parked in its ask-mode \
                         session(s)){r}"
                    );
                }
                None => {
                    let _ = writeln!(
                        o,
                        "{dim}no pending requests (nothing parked across any ask-mode session){r}"
                    );
                }
            }
        }
        write_unsupported_note(&mut o, unsupported, warn, dim, r);
        return o;
    }
    let _ = writeln!(o, "{h}{past} {total} parked request(s):{r}");
    for (pid, hosts) in answered {
        // A per-session header from the registry, so with several agents the user can tell which one
        // each grant belongs to — the cross-agent reach made visible, not silent.
        match context.iter().find(|(p, _, _)| p == pid) {
            Some((_, project, label)) => {
                let _ = writeln!(o, "  {dim}session {pid} [{label}] {}{r}", project.display());
            }
            None => {
                let _ = writeln!(o, "  {dim}session {pid} (unregistered){r}");
            }
        }
        // One parked request emits one host, so a burst of retries (or several paths) to one
        // destination would print that host once per request. Fold the repeats into `host ×N`.
        for (host, count) in collapse_hosts(hosts) {
            if count > 1 {
                let _ = writeln!(o, "    {n}{host}{r} {dim}×{count}{r}");
            } else {
                let _ = writeln!(o, "    {n}{host}{r}");
            }
        }
    }
    if session {
        let _ = writeln!(o, "  {dim}(remembered for each session — not re-asked){r}");
    }
    write_unsupported_note(&mut o, unsupported, warn, dim, r);
    o
}

/// Append the older-session warning to a drain report: name the sessions whose control server is too
/// old to understand `--all`, and point at the only fix (relaunch the agent). Answering their requests
/// by id is deliberately *not* offered — destination grouping is server-side, so an old server's
/// `ALLOW <seq>` wakes one connection of a retried group and leaves the rest blocked.
fn write_unsupported_note(o: &mut String, unsupported: &[u32], warn: &str, dim: &str, r: &str) {
    use std::fmt::Write as _;
    if unsupported.is_empty() {
        return;
    }
    let pids = unsupported
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(
        o,
        "{warn}session(s) {pids} were launched by an older ops without `--all` support — their \
         parked requests stay blocked.{r}"
    );
    let _ = writeln!(
        o,
        "  {dim}relaunch the agent with the current ops to drain them in bulk.{r}"
    );
}

/// `ops net stats [--app <name>] [--reset] [--json]`: report the per-host egress decision counters a
/// project's launches recorded — how often each destination was allowed, denied by a rule, or
/// stopped by a security guard (SSRF, an outbound-secret tripwire, a domain-fronting mismatch).
/// Read-only and host-side: it aggregates the session files under `<data>/egress`, with no launch,
/// nix, or network. `--reset` clears this project's recorded files instead.
fn net_stats(args: &[OsString]) -> ExitCode {
    let mut app: Option<String> = None;
    let mut reset = false;
    let mut json = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--json") => json = true,
            Some("--reset") => reset = true,
            Some("--app") | Some("-a") => {
                let Some(v) = it.next().and_then(|a| a.to_str()) else {
                    eprintln!("ops: net stats: `--app` needs an app name");
                    return ExitCode::from(2);
                };
                app = Some(v.to_string());
            }
            _ => {
                eprintln!("ops: usage: {}", help::synopsis_of(&["net", "stats"]));
                return ExitCode::from(2);
            }
        }
    }
    // `--reset` reports how many files it cleared; pairing it with `--json` is meaningless — flag it
    // rather than silently pick one.
    if reset && json {
        eprintln!("ops: net stats: `--reset` does not combine with `--json`");
        return ExitCode::from(2);
    }

    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: cannot read the current directory: {e}");
            return ExitCode::FAILURE;
        }
    };
    // The canonical project identity is exactly what `egress::start` writes into each session file's
    // `project=` header, so a read here matches what a launch recorded — no canonicalization drift.
    let project = match sandbox::project_identity(&cwd) {
        Ok((_, canon)) => canon.display().to_string(),
        Err(e) => {
            eprintln!("ops: cannot resolve the project directory: {e}");
            return ExitCode::FAILURE;
        }
    };
    let egress_dir = match egress_data_dir() {
        Ok(d) => d.join("egress"),
        Err(e) => {
            eprintln!("ops: {e}");
            return ExitCode::FAILURE;
        }
    };

    if reset {
        let n = sandbox::egress_stats::reset(&egress_dir, &project, app.as_deref());
        let scope = app
            .as_ref()
            .map(|a| format!(" for app {a}"))
            .unwrap_or_default();
        println!("reset {n} egress stat file(s){scope}");
        return ExitCode::SUCCESS;
    }

    let counts = sandbox::egress_stats::aggregate(&egress_dir, &project, app.as_deref());
    if json {
        let rows: Vec<_> = counts
            .iter()
            .map(|(host, c)| {
                serde_json::json!({
                    "host": host,
                    "allow": c.allow,
                    "deny": c.deny,
                    "blocked": c.blocked,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({ "project": project, "app": app, "stats": rows })
        );
        return ExitCode::SUCCESS;
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_stats(&project, app.as_deref(), &counts, &pal));
    ExitCode::SUCCESS
}

/// Render the per-host egress stats table — a pure presenter (its colored layout is asserted in a
/// test): a project/app header, then one row per destination with its allow/deny/blocked counts,
/// busiest first (ties broken by host for stable output). An empty result says nothing has been
/// recorded yet and when recording happens.
fn render_stats(
    project: &str,
    app: Option<&str>,
    counts: &std::collections::BTreeMap<String, sandbox::egress_stats::Counts>,
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let mut o = String::new();
    let scope = app.map(|a| format!(" · app {a}")).unwrap_or_default();
    let _ = writeln!(o, "{h}egress stats{r} {dim}({project}{scope}){r}");
    if counts.is_empty() {
        let _ = writeln!(
            o,
            "  {dim}nothing recorded yet \
             (stats accrue while a filtering posture — allowlist/ask — runs){r}"
        );
        return o;
    }
    // Busiest host first; ties by host name so the order is stable run to run.
    let mut rows: Vec<(&String, &sandbox::egress_stats::Counts)> = counts.iter().collect();
    rows.sort_by(|(ha, a), (hb, b)| b.total().cmp(&a.total()).then(ha.cmp(hb)));
    let host_w = rows
        .iter()
        .map(|(host, _)| host.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let _ = writeln!(
        o,
        "  {dim}{:<host_w$}  {:>6}  {:>6}  {:>7}{r}",
        "HOST", "ALLOW", "DENY", "BLOCKED"
    );
    for (host, c) in rows {
        let _ = writeln!(
            o,
            "  {n}{:<host_w$}{r}  {:>6}  {:>6}  {:>7}",
            host, c.allow, c.deny, c.blocked
        );
    }
    o
}

/// The parsed `ops net logs` display options.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct LogView {
    json: bool,
    app: Option<String>,
    host: Option<String>,
    verdict: Option<sandbox::control::LogVerdict>,
    limit: Option<usize>,
    with_query: bool,
    /// `--with-status`: show the captured upstream HTTP status (200/404/…) — for completed L7
    /// requests only; blank/absent for an L4 splice, a refusal, or an error.
    with_status: bool,
    /// `--follow`: after the initial listing, keep polling and append new events (a `tail -f`).
    follow: bool,
    /// The `--follow` poll interval in seconds (`-i`), default 1. Ignored without `--follow`.
    interval_secs: u64,
    /// `--all`: also show refusals a `mute` (`dontaudit`) rule suppressed from the default view —
    /// tagged `muted`. They live in a separate ring and are still counted in `ops net stats`; the
    /// default view omits them.
    all: bool,
}

/// Parse `ops net logs [-a|--app <name>] [--host <h>] [--verdict allow|deny|blocked|error]
/// [-n <N>] [--with-query] [--with-status] [--follow] [-i|--interval <secs>] [--json]`. Pure (no
/// I/O), so every reject path is unit-testable — a missing value, an unknown verdict, a non-numeric
/// count or interval, a zero interval, or an unknown flag is an error.
fn parse_log_args(args: &[OsString]) -> Result<LogView, String> {
    let mut v = LogView {
        interval_secs: 1,
        ..LogView::default()
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--json") => v.json = true,
            Some("--all") => v.all = true,
            Some("--with-query") => v.with_query = true,
            Some("--with-status") => v.with_status = true,
            Some("--follow") | Some("-f") => v.follow = true,
            Some("-i") | Some("--interval") => {
                let val = it.next().ok_or("`--interval` needs a value in seconds")?;
                let secs: u64 = val.to_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
                    format!(
                        "invalid interval `{}` — expected a whole number of seconds",
                        val.to_string_lossy()
                    )
                })?;
                if secs == 0 {
                    return Err("interval must be at least 1 second".into());
                }
                v.interval_secs = secs;
            }
            Some("-a") | Some("--app") => {
                let name = it.next().ok_or("`--app` needs an app name")?;
                v.app = Some(name.to_string_lossy().into_owned());
            }
            Some("--host") => {
                let h = it.next().ok_or("`--host` needs a hostname")?;
                v.host = Some(h.to_string_lossy().into_owned());
            }
            Some("--verdict") => {
                let val = it
                    .next()
                    .ok_or("`--verdict` needs one of allow|deny|blocked|error")?;
                let parsed = val
                    .to_str()
                    .and_then(sandbox::control::LogVerdict::parse)
                    .ok_or_else(|| {
                        format!(
                            "invalid verdict `{}` — expected allow|deny|blocked|error",
                            val.to_string_lossy()
                        )
                    })?;
                v.verdict = Some(parsed);
            }
            Some("-n") => {
                let val = it.next().ok_or("`-n` needs a count")?;
                let n: usize = val.to_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
                    format!(
                        "invalid count `{}` — expected a whole number",
                        val.to_string_lossy()
                    )
                })?;
                v.limit = Some(n);
            }
            _ => {
                return Err(format!("usage: {}", help::synopsis_of(&["net", "logs"])));
            }
        }
    }
    Ok(v)
}

/// Query the live control sockets for each session's recent egress events, scoped to one app's
/// session(s) when `app` is set, and pair them with their registry context. The read-only gather
/// step behind `ops net logs` — the log's analogue of [`collect_pending`]. No launch / nix / network.
fn collect_logs(
    data_dir: &Path,
    app: Option<&str>,
    include_muted: bool,
) -> (
    Vec<sandbox::control::SessionLog>,
    Vec<(u32, PathBuf, String)>,
) {
    let mut sessions = sandbox::control::log_all(data_dir, include_muted);
    if let Some(name) = app {
        let pids = session_pids_for_app(data_dir, name);
        sessions.retain(|s| pids.contains(&s.pid));
    }
    let context = pending_session_context(data_dir);
    (sessions, context)
}

/// Whether one event passes the ongoing `--host`/`--verdict` filters (the `-n` limit is separate —
/// it caps the initial listing, not the followed stream). Shared by the one-shot listing and the
/// `--follow` stream so a filter behaves identically in both.
fn event_passes_filters(e: &sandbox::control::LogEvent, view: &LogView) -> bool {
    view.host.as_deref().is_none_or(|h| e.host == h) && view.verdict.is_none_or(|v| e.verdict == v)
}

/// The events of one session that pass the `--host`/`--verdict` filters, then the `-n` limit (the
/// most recent N, since the ring is oldest-first). Borrowed, so the render/JSON share one filter.
fn filtered_log_events<'a>(
    events: &'a [sandbox::control::LogEvent],
    view: &LogView,
) -> Vec<&'a sandbox::control::LogEvent> {
    let mut out: Vec<&sandbox::control::LogEvent> = events
        .iter()
        .filter(|e| event_passes_filters(e, view))
        .collect();
    if let Some(n) = view.limit {
        if out.len() > n {
            out = out.split_off(out.len() - n);
        }
    }
    out
}

/// The path as displayed: the query string is dropped by default (a token can ride in a query, and
/// the terminal scrollback is itself "at rest"), kept only under `--with-query` — where it is
/// already secret-redacted, since the proxy masks configured needles before the event enters the ring.
fn display_log_path(path: &str, with_query: bool) -> &str {
    if with_query {
        path
    } else {
        path.split('?').next().unwrap_or(path)
    }
}

/// An event's wall-clock time of day as local `hh:mm:ss` — a stable, correlatable stamp for a log
/// (the JSON keeps the absolute `at_epoch_ms`). Local time comes from the process timezone via the C
/// library (`localtime_r`, the reentrant/thread-safe form); a conversion failure (an implausible
/// stamp) renders `--:--:--` rather than panicking.
fn format_log_time(at_epoch_ms: u128) -> String {
    // `libc::time_t` is the exact argument type `localtime_r` expects. On musl it carries a
    // deprecation notice — a heads-up that musl 1.2 widened `time_t` to 64-bit and a future `libc`
    // will drop this alias — but it stays the correct FFI type, and on ops's x86_64 target it is
    // already 64-bit, so the widening is a no-op here. Silence the notice on the one line that names
    // it rather than reach for a hardcoded integer type that would be wrong on a 32-bit target.
    #[allow(deprecated)]
    let secs = (at_epoch_ms / 1000) as libc::time_t;
    // SAFETY: `localtime_r` writes the broken-down local time into our stack `tm` and reads only the
    // `time_t` we pass; it is the thread-safe variant, so no shared state is mutated.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&secs, &mut tm) }.is_null() {
        return "--:--:--".to_string();
    }
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

/// How many of a session's oldest events fell off the ring before the retained window. Sequence
/// numbers start at 1 and the window is contiguous, so the oldest retained event's `seq - 1` is the
/// evicted count — surfaced (not silently truncated) even for the one-shot listing, distinct from any
/// `-n`/`--host`/`--verdict` the user applied. Computed from the **unfiltered** snapshot.
fn snapshot_evicted(snapshot: &sandbox::control::LogSnapshot) -> u64 {
    snapshot.events.first().map(|e| e.seq - 1).unwrap_or(0)
}

/// `ops net logs [-a|--app <name>] [--host <h>] [--verdict …] [-n <N>] [--with-query] [--json]`:
/// the live egress event log — a chronological, per-session record of every egress decision the
/// proxy made, read from the same control sockets `ops net pending` uses. Live-only: it shows a
/// running session's egress, and nothing remains once the session exits. No launch / nix / network.
fn net_logs(args: &[OsString]) -> ExitCode {
    let view = match parse_log_args(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ops: net logs: {e}");
            return ExitCode::from(2);
        }
    };
    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: {e}");
            return ExitCode::FAILURE;
        }
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    if view.follow {
        return net_logs_follow(&data_dir, &view, &pal);
    }

    let (sessions, context) = collect_logs(&data_dir, view.app.as_deref(), view.all);

    if view.json {
        let ctx_of = |pid: u32| context.iter().find(|(p, _, _)| *p == pid);
        let rows: Vec<_> = sessions
            .iter()
            .flat_map(|s| {
                let ctx = ctx_of(s.pid);
                let project = ctx.map(|(_, p, _)| p.display().to_string());
                let label = ctx.map(|(_, _, l)| l.clone());
                // Capture `view` by reference (it is used again below), the owned project/label by move.
                let view = &view;
                filtered_log_events(&s.snapshot.events, view)
                    .into_iter()
                    .map(move |e| {
                        log_event_json(e, s.pid, project.as_deref(), label.as_deref(), view)
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        // Per-session ring-eviction counts (only where >0) — the overflow surfaced, not silent.
        let evicted: Vec<_> = sessions
            .iter()
            .filter_map(|s| {
                let n = snapshot_evicted(&s.snapshot);
                (n > 0).then(|| serde_json::json!({ "pid": s.pid, "count": n }))
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({ "logs": rows, "evicted": evicted })
        );
        return ExitCode::SUCCESS;
    }

    print!("{}", render_logs(&sessions, &context, &view, &pal, true));
    ExitCode::SUCCESS
}

/// `ops net logs --follow`: after seeding with the current listing, poll each reachable session on
/// the interval and **append** the events past a per-session seq cursor — a `tail -f` for egress. A
/// ring overflow between polls (`dropped` > 0) is announced, never dropped silently. A session that
/// ends (its control socket vanishes) is noted once; a new one is picked up. Runs until interrupted
/// (Ctrl-C); the append shape is pipe-friendly (unlike `pending watch`'s in-place redraw), so it
/// needs no terminal. The `--follow` NDJSON stream (`--json`) emits one event object per line.
fn net_logs_follow(data_dir: &Path, view: &LogView, pal: &style::Palette) -> ExitCode {
    use std::collections::HashMap;
    use std::fmt::Write as _;

    let interval = std::time::Duration::from_secs(view.interval_secs.max(1));
    // A per-session cursor: the last seq already shown, plus the amendment cursor (for retroactive
    // status). Seeded from the initial listing so the follow only ever appends genuinely new events.
    let mut cursor: HashMap<u32, (u64, u64)> = HashMap::new();
    let (dim, r) = (pal.dim, pal.reset);
    let ctx_of = |ctx: &[(u32, PathBuf, String)], pid: u32| {
        ctx.iter()
            .find(|(p, _, _)| *p == pid)
            .map(|(_, proj, label)| (proj.display().to_string(), label.clone()))
    };

    // Seed: the current listing (human render, or NDJSON of the retained events), respecting `-n`.
    // Only actual events are written — the one-shot's "nothing to show" line is skipped, so a follow
    // that pipes to `head` on an idle session emits no spurious line then spins.
    let (sessions, context) = collect_logs(data_dir, view.app.as_deref(), view.all);
    let has_events = sessions
        .iter()
        .any(|s| !filtered_log_events(&s.snapshot.events, view).is_empty());
    let mut seed = String::new();
    if view.json {
        for s in &sessions {
            let c = ctx_of(&context, s.pid);
            for e in filtered_log_events(&s.snapshot.events, view) {
                let obj = log_event_json(
                    e,
                    s.pid,
                    c.as_ref().map(|(p, _)| p.as_str()),
                    c.as_ref().map(|(_, l)| l.as_str()),
                    view,
                );
                let _ = writeln!(seed, "{obj}");
            }
        }
    } else if has_events {
        // No footer in the seed — events append below it, so the live-only note would land mid-stream.
        seed = render_logs(&sessions, &context, view, pal, false);
    }
    for s in &sessions {
        cursor.insert(s.pid, (s.snapshot.head, s.snapshot.amend_head));
    }
    // A closed downstream pipe (`… | head`) ends the follow cleanly — Rust ignores SIGPIPE, so a
    // write to a gone reader returns an error we must act on rather than spin forever.
    if flush_stream(&seed).is_err() {
        return ExitCode::SUCCESS;
    }
    eprintln!("ops: following egress (Ctrl-C to quit)");

    let mut last_pid: Option<u32> = None; // the session whose header was last printed (human view)
    loop {
        std::thread::sleep(interval);
        let context = pending_session_context(data_dir);
        let mut pids = sandbox::control::session_pids(data_dir);
        if let Some(name) = view.app.as_deref() {
            let allowed = session_pids_for_app(data_dir, name);
            pids.retain(|p| allowed.contains(p));
        }

        // Build this tick's output into a buffer, then write it once — so a broken pipe is detected on
        // the single write and ends the follow, and the ordering of every line is deterministic.
        let mut tick = String::new();

        // A session that had a cursor but no longer has a socket has ended — note it once and forget.
        let live: std::collections::HashSet<u32> = pids.iter().copied().collect();
        let ended: Vec<u32> = cursor
            .keys()
            .copied()
            .filter(|p| !live.contains(p))
            .collect();
        for pid in ended {
            cursor.remove(&pid);
            if !view.json {
                let _ = writeln!(tick, "  {dim}session {pid} ended{r}");
                if last_pid == Some(pid) {
                    last_pid = None;
                }
            }
        }

        for pid in pids {
            let entry = cursor.get(&pid).copied();
            let after = entry.map(|(seq, _)| seq);
            // Request retroactive status re-emission only under `--with-status` — otherwise a status
            // filling in is invisible and re-showing the line would be pure duplication.
            let after_amend = if view.with_status {
                entry.map(|(_, amend)| amend)
            } else {
                None
            };
            let Ok(snap) = sandbox::control::read_log(
                &sandbox::control::control_socket(data_dir, pid),
                after,
                after_amend,
                view.all,
            ) else {
                continue; // a session that vanished mid-read is handled next tick
            };
            // A gap between polls (the ring overflowed) — surfaced, never silent.
            if snap.dropped > 0 {
                if view.json {
                    let _ = writeln!(
                        tick,
                        "{}",
                        serde_json::json!({ "pid": pid, "dropped": snap.dropped })
                    );
                } else {
                    let _ = writeln!(
                        tick,
                        "  {dim}[{pid}] {} event(s) dropped — the ring overflowed between polls{r}",
                        snap.dropped
                    );
                }
            }
            let new: Vec<&sandbox::control::LogEvent> = snap
                .events
                .iter()
                .filter(|e| event_passes_filters(e, view))
                .collect();
            if !new.is_empty() {
                let c = ctx_of(&context, pid);
                for e in new {
                    if view.json {
                        let obj = log_event_json(
                            e,
                            pid,
                            c.as_ref().map(|(p, _)| p.as_str()),
                            c.as_ref().map(|(_, l)| l.as_str()),
                            view,
                        );
                        let _ = writeln!(tick, "{obj}");
                    } else {
                        // A session header only when the stream switches sessions, so a single-session
                        // follow does not repeat it every event.
                        if last_pid != Some(pid) {
                            match &c {
                                Some((proj, label)) => {
                                    let _ =
                                        writeln!(tick, "  {dim}session {pid} [{label}] {proj}{r}");
                                }
                                None => {
                                    let _ =
                                        writeln!(tick, "  {dim}session {pid} (unregistered){r}");
                                }
                            }
                            last_pid = Some(pid);
                        }
                        let _ = writeln!(tick, "{}", render_log_line(e, pid, view, pal));
                    }
                }
            }
            cursor.insert(pid, (snap.head, snap.amend_head));
        }
        if flush_stream(&tick).is_err() {
            return ExitCode::SUCCESS; // downstream pipe closed
        }
    }
}

/// Write `s` to stdout and flush, returning the I/O result — a broken pipe (a closed `… | head`
/// downstream) surfaces here rather than being swallowed, so a `--follow` loop can stop instead of
/// spinning forever (Rust ignores SIGPIPE). An empty string is a successful no-op.
fn flush_stream(s: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    if s.is_empty() {
        return Ok(());
    }
    let mut out = std::io::stdout().lock();
    out.write_all(s.as_bytes())?;
    out.flush()
}

/// The ANSI span for a verdict: green for `allow`, red for a refusal (`deny`/`blocked`), yellow for
/// `error` (allowed but failed) — so a scan of the log reads at a glance.
fn verdict_color(verdict: sandbox::control::LogVerdict, pal: &style::Palette) -> &str {
    use sandbox::control::LogVerdict::*;
    match verdict {
        Allow => pal.ok,
        Deny | Blocked => pal.err,
        Error => pal.warn,
    }
}

/// The ANSI span for an upstream HTTP status class: green for 2xx, red for 4xx/5xx, yellow for the
/// rest (1xx/3xx) — so a failing response stands out under `--with-status`.
fn status_color(code: u16, pal: &style::Palette) -> &str {
    match code {
        200..=299 => pal.ok,
        400..=599 => pal.err,
        _ => pal.warn,
    }
}

/// Render the live egress log — a pure presenter (its colored layout is asserted in a test): a
/// header, then per session a context line and one line per event
/// (`time · host:port · method path · verdict · reason`), oldest first. The `reason` is dropped for a
/// plain `allow` (it would just repeat "allowed"). An empty result explains the log is live-only.
/// `footer` appends the live-only note — on for the one-shot listing, off for the `--follow` seed
/// (where events append below it, so the note would land mid-stream).
fn render_logs(
    sessions: &[sandbox::control::SessionLog],
    context: &[(u32, PathBuf, String)],
    view: &LogView,
    pal: &style::Palette,
    footer: bool,
) -> String {
    use std::fmt::Write as _;
    let (h, dim, r) = (pal.head, pal.dim, pal.reset);
    let mut o = String::new();
    let total: usize = sessions
        .iter()
        .map(|s| filtered_log_events(&s.snapshot.events, view).len())
        .sum();
    if total == 0 {
        let scope = view
            .app
            .as_deref()
            .map(|a| format!(" for app `{a}`"))
            .unwrap_or_default();
        let _ = writeln!(
            o,
            "{h}egress log:{r} {dim}(nothing to show{scope} — the log is live while a filtering \
             posture (allowlist/ask) runs, and is not kept after a session exits){r}"
        );
        return o;
    }
    let _ = writeln!(o, "{h}egress log:{r}");
    for session in sessions {
        let events = filtered_log_events(&session.snapshot.events, view);
        if events.is_empty() {
            continue;
        }
        match context.iter().find(|(pid, _, _)| *pid == session.pid) {
            Some((_, project, label)) => {
                let _ = writeln!(
                    o,
                    "  {dim}session {} [{}] {}{r}",
                    session.pid,
                    label,
                    project.display()
                );
            }
            None => {
                let _ = writeln!(o, "  {dim}session {} (unregistered){r}", session.pid);
            }
        }
        // The ring is bounded; if it evicted older events, say so rather than truncate silently.
        let evicted = snapshot_evicted(&session.snapshot);
        if evicted > 0 {
            let _ = writeln!(
                o,
                "    {dim}({evicted} earlier event(s) evicted from the ring){r}"
            );
        }
        for e in events {
            let _ = writeln!(o, "{}", render_log_line(e, session.pid, view, pal));
        }
    }
    if footer {
        let _ = writeln!(
            o,
            "  {dim}live view — this session's egress; nothing is kept after it exits{r}"
        );
    }
    o
}

/// One event's display line (indented, no trailing newline): `session-id · time · host:port ·
/// method path · verdict · reason`. The `pid` is the session id (the one `ops ls`/`attach`/`stop`
/// use), led so a line is self-contained when scanned or piped. The `reason` is dropped for a plain
/// `allow` (it would just repeat "allowed"); a blank host (a malformed handshake) shows `-`. Shared
/// by the one-shot render and the `--follow` stream so a line looks identical in both.
fn render_log_line(
    e: &sandbox::control::LogEvent,
    pid: u32,
    view: &LogView,
    pal: &style::Palette,
) -> String {
    let (n, dim, r) = (pal.name, pal.dim, pal.reset);
    let hostport = if e.host.is_empty() {
        "-".to_string()
    } else {
        format!("{}:{}", e.host, e.port)
    };
    let time = format_log_time(e.at_epoch_ms);
    let method = e
        .method
        .as_deref()
        .map(|m| format!("{m} "))
        .unwrap_or_default();
    let path = e
        .path
        .as_deref()
        .map(|p| display_log_path(p, view.with_query))
        .unwrap_or("");
    // The transport the request used (`https`/`http`/`tcp`, or `-` when refused before it was
    // known) — shown because the port alone does not name it (a `tcp://` splice can ride 443).
    let proto = e.proto.as_str();
    let vc = verdict_color(e.verdict, pal);
    let reason = if e.verdict == sandbox::control::LogVerdict::Allow {
        String::new()
    } else {
        format!("  {dim}({}){r}", e.reason)
    };
    // A WebSocket shows a `101` status (set only by the upgrade relay; the normal path never records
    // a 1xx), so flag it explicitly — a long-lived bidirectional tunnel reads differently from a
    // one-shot request, and the marker shows even without `--with-status`.
    let ws = if e.status == Some(101) {
        format!("  {n}ws{r}")
    } else {
        String::new()
    };
    // A refusal shown only because of `--all` — flag it so a suppressed (`mute`/`dontaudit`) line is
    // never mistaken for one the default view would have shown.
    let muted = if e.muted {
        format!("  {dim}muted{r}")
    } else {
        String::new()
    };
    // The upstream status, only under `--with-status`: the code (colored by class) for a completed
    // L7 request, or `-` where none was captured (an L4 splice, a refusal, or a not-yet-returned
    // response) so the column is legible rather than mysteriously blank.
    let status = if view.with_status {
        match e.status {
            Some(code) => format!("  {}{code}{r}", status_color(code, pal)),
            None => format!("  {dim}-{r}"),
        }
    } else {
        String::new()
    };
    format!(
        "    {dim}{pid}{r}  {dim}{time}{r}  {dim}{proto}{r}  {n}{hostport}{r}  {method}{path}  {vc}{}{r}{reason}{ws}{muted}{status}",
        e.verdict.as_str()
    )
}

/// One event as a JSON object (for `--json` and the `--follow` NDJSON stream). Epoch-ms is a number
/// (it fits u64); the path honors `--with-query`. The `status` field is included only under
/// `--with-status` (a number for a completed L7 request, else null) — parity with `--with-query`.
/// Shared so the two JSON paths cannot diverge.
fn log_event_json(
    e: &sandbox::control::LogEvent,
    pid: u32,
    project: Option<&str>,
    label: Option<&str>,
    view: &LogView,
) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "pid": pid,
        "project": project,
        "label": label,
        "at_epoch_ms": e.at_epoch_ms as u64,
        "host": e.host,
        "port": e.port,
        "method": e.method,
        "path": e.path.as_deref().map(|p| display_log_path(p, view.with_query)),
        "verdict": e.verdict.as_str(),
        "proto": e.proto.as_str(),
        "reason": e.reason,
        "muted": e.muted,
    });
    if view.with_status {
        obj["status"] = e
            .status
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null);
    }
    obj
}

/// `ops net rules [--source config|builtin|session] [--filter <substr>] [--json]`: list the effective
/// egress rules, each tagged by source, optionally filtered. Reflects the trust gate (an untrusted
/// project's rules are dropped), and does no launch / nix / network — the read-only posture of
/// `ops config show` and `ops test net`.
fn net_rules(args: &[OsString]) -> ExitCode {
    use config::view::RuleSourceView;
    let mut source: Option<RuleSourceView> = None;
    let mut filter: Option<String> = None;
    let mut app: Option<String> = None;
    let mut json = false;
    let mut expand = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--json") => json = true,
            Some("--expand") | Some("-e") => expand = true,
            Some("--app") | Some("-a") => {
                let Some(v) = it.next().and_then(|a| a.to_str()) else {
                    eprintln!("ops: net rules: `--app` needs an app name");
                    return ExitCode::from(2);
                };
                app = Some(v.to_string());
            }
            Some("--source") | Some("-s") => {
                let Some(v) = it.next().and_then(|a| a.to_str()) else {
                    eprintln!("ops: `--source` needs a value (config, builtin, session)");
                    return ExitCode::from(2);
                };
                source = Some(match v {
                    "config" => RuleSourceView::Config,
                    "builtin" => RuleSourceView::Builtin,
                    // `session` is the live `--session`-answered overlay; `manual` is kept as an
                    // accepted alias for the same source.
                    "session" | "manual" => RuleSourceView::Manual,
                    other => {
                        eprintln!(
                            "ops: unknown rule source '{other}' (known: config, builtin, session)"
                        );
                        return ExitCode::from(2);
                    }
                });
            }
            Some("--filter") | Some("-f") => {
                let Some(v) = it.next().and_then(|a| a.to_str()) else {
                    eprintln!("ops: `--filter` needs a substring");
                    return ExitCode::from(2);
                };
                filter = Some(v.to_lowercase());
            }
            _ => {
                eprintln!("ops: usage: {}", help::synopsis_of(&["net", "rules"]));
                return ExitCode::from(2);
            }
        }
    }

    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: cannot read the current directory: {e}");
            return ExitCode::FAILURE;
        }
    };
    // `--source session` is live runtime state, not config: query the running sessions for the rules
    // loaded into their live overlay, rather than reading the static config policy. Scoped to this
    // project by default, or — with `-a <app>` — to that app's session(s), mirroring how
    // `ops net allow --session -a <app>` scopes the load (`--app` here filters *which sessions* to
    // query, it does not fold a config overlay the way it does for the config/builtin sources).
    if source == Some(RuleSourceView::Manual) {
        return net_rules_manual(&cwd, app.as_deref(), filter.as_deref(), json);
    }

    let mut resolved = config::load(&cwd);
    for w in &resolved.warnings {
        diag::warn(w);
    }
    // Fold a named app's overlay so the rules listed are the *effective* set `ops app <name>` would
    // launch with (its own posture, allow/deny, credentials), not the bare baseline — the same path
    // `ops test net --app` uses, so the two read the same policy.
    if let Some(name) = &app {
        if let Err(e) = fold_app_overlay(&mut resolved, name) {
            eprintln!("ops: net rules: {e}");
            return ExitCode::from(2);
        }
    }

    // A `--filter` is a search for a host, so it forces expansion: otherwise the substring would run
    // against a collapsed `@<group>` row and a host *inside* a group would be reported absent though
    // it is allowed — a filter must never hide a matching rule. (`ops test net <url>` is the
    // authoritative "does this resolve" check regardless.)
    let expand = expand || filter.is_some();

    // The effective posture decides the mode word and whether there are rules at all. The built-in
    // built-in set is unioned by the proxy, which runs only under a filtering posture, so it is
    // absent (with every other rule) under `shared`/`none`.
    let (mode, all_rules) = match &resolved.network {
        config::NetworkPolicy::Shared => ("shared", Vec::new()),
        config::NetworkPolicy::Isolated => ("none", Vec::new()),
        config::NetworkPolicy::Allowlist(policy) => (
            net_mode_word(policy.default_action().into()),
            config::view::net_rules_view(policy, expand),
        ),
    };

    // Apply the source and substring filters (the substring is matched case-insensitively against
    // the rule text). `total` is the unfiltered count, so an empty result reads as "nothing matched
    // your filter" rather than "no rules at all".
    let total = all_rules.len();
    let shown: Vec<&config::view::NetRuleView> = all_rules
        .iter()
        .filter(|r| source.is_none_or(|s| r.source == s))
        .filter(|r| {
            filter
                .as_ref()
                .is_none_or(|f| r.rule.to_lowercase().contains(f))
        })
        .collect();

    if json {
        let value = serde_json::json!({
            "mode": mode,
            "rules": shown.iter().map(|r| (*r).clone()).collect::<Vec<_>>(),
        });
        println!("{value}");
        return ExitCode::SUCCESS;
    }

    // Name the posture in view: the baseline, or one app's effective overlay (matching the label
    // `ops test net --app` prints, so the two commands read the same).
    let scope = app
        .as_ref()
        .map(|n| format!(" (app {n})"))
        .unwrap_or_default();
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_net_rules(mode, &scope, &shown, total, &pal));
    ExitCode::SUCCESS
}

/// `ops net groups` — the reusable-egress-group surface. `export`/`import` move groups between
/// configs (they are reserved subcommand verbs, so a group named `export`/`import` is listable and
/// referenceable as `@export` but not resolvable by bare name — use the listing); anything else is
/// the list/resolve reader ([`net_groups_list`]).
fn net_groups(args: &[OsString]) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("export") => net_groups_export(&args[1..]),
        Some("import") => net_groups_import(&args[1..]),
        _ => net_groups_list(args),
    }
}

/// `ops net groups [<name>…] [--json]`: list the reusable egress groups declared in the global
/// config (`[net.groups]`), or resolve named ones to their entries. Groups are global-only (the
/// resolver honors them only from the global config), so there is no scope flag — this always reads
/// the global config. Read-only, network-free. With no name it lists each group and its entry count;
/// with names it prints each named group's authored entries, flagging a malformed or nested one.
fn net_groups_list(args: &[OsString]) -> ExitCode {
    let mut json = false;
    let mut names: Vec<String> = Vec::new();
    for arg in args {
        match arg.to_str() {
            Some("--json") => json = true,
            Some(s) if s.starts_with('-') => {
                eprintln!("ops: net groups: unknown flag `{s}`");
                eprintln!("ops: usage: {}", help::synopsis_of(&["net", "groups"]));
                return ExitCode::from(2);
            }
            Some(s) => names.push(s.to_string()),
            None => {
                eprintln!("ops: net groups: a group name must be valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    let (groups, warnings) = config::net_groups();
    for w in &warnings {
        diag::warn(w);
    }

    // A named group that does not exist is an explicit error (never a blank success). Report every
    // missing name at once, and point at what *is* defined.
    if !names.is_empty() {
        let missing: Vec<&str> = names
            .iter()
            .filter(|n| !groups.contains_key(*n))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            eprintln!("ops: net groups: no such group: {}", missing.join(", "));
            if groups.is_empty() {
                eprintln!(
                    "ops: no egress groups are defined — declare them under [net.groups] in the \
                     global config"
                );
            } else {
                let avail: Vec<&str> = groups.keys().map(String::as_str).collect();
                eprintln!("ops: defined groups: {}", avail.join(", "));
            }
            return ExitCode::from(2);
        }
    }

    if json {
        // name → [ { entry, invalid } ], all groups (sorted) or the named subset (given order).
        let selected: Vec<(&String, &Vec<String>)> = if names.is_empty() {
            groups.iter().collect()
        } else {
            names
                .iter()
                .filter_map(|n| groups.get_key_value(n))
                .collect()
        };
        let obj: Vec<_> = selected
            .iter()
            .map(|(name, entries)| {
                let rows: Vec<_> = entries
                    .iter()
                    .map(|e| serde_json::json!({ "entry": e, "invalid": net_group_entry_issue(e) }))
                    .collect();
                serde_json::json!({ "name": name, "entries": rows })
            })
            .collect();
        println!("{}", serde_json::json!({ "groups": obj }));
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_net_groups(&groups, &names, &pal));
    ExitCode::SUCCESS
}

/// `ops net groups export [<name>…] [--out <file>]`: write the reusable egress groups as a portable
/// `[net.groups]` TOML fragment — every group, or the named subset — to stdout (the default,
/// composable and clobber-safe: `ops net groups export > groups.toml`) or to `--out <file>`. The
/// inverse of `import`. Read-only on the config; no launch, no nix.
fn net_groups_export(args: &[OsString]) -> ExitCode {
    let mut out: Option<PathBuf> = None;
    let mut names: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--out") | Some("-o") => {
                let Some(v) = it.next() else {
                    eprintln!("ops: net groups export: `--out` needs a file path");
                    return ExitCode::from(2);
                };
                out = Some(PathBuf::from(v));
            }
            Some(s) if s.starts_with('-') => {
                eprintln!("ops: net groups export: unknown flag `{s}`");
                eprintln!(
                    "ops: usage: {}",
                    help::synopsis_of(&["net", "groups", "export"])
                );
                return ExitCode::from(2);
            }
            Some(s) => names.push(s.to_string()),
            None => {
                eprintln!("ops: net groups export: a group name must be valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }

    let (groups, warnings) = config::net_groups();
    for w in &warnings {
        diag::warn(w);
    }

    // Select all groups (sorted) or the named subset. An unknown name is an explicit error.
    let selected: std::collections::BTreeMap<String, Vec<String>> = if names.is_empty() {
        groups.clone()
    } else {
        let missing: Vec<&str> = names
            .iter()
            .filter(|n| !groups.contains_key(*n))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            eprintln!(
                "ops: net groups export: no such group: {}",
                missing.join(", ")
            );
            return ExitCode::from(2);
        }
        names
            .iter()
            .filter_map(|n| groups.get_key_value(n).map(|(k, v)| (k.clone(), v.clone())))
            .collect()
    };
    if selected.is_empty() {
        eprintln!(
            "ops: net groups export: no egress groups to export (none are defined under \
             [net.groups] in the global config)"
        );
        return ExitCode::from(2);
    }

    let fragment = config::manage::export_net_groups(&selected);
    match &out {
        None => {
            print!("{fragment}");
            ExitCode::SUCCESS
        }
        Some(path) => match std::fs::write(path, &fragment) {
            Ok(()) => {
                let n = selected.len();
                let s = if n == 1 { "" } else { "s" };
                println!("exported {n} egress group{s} to {}", path.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!(
                    "ops: net groups export: cannot write {}: {e}",
                    path.display()
                );
                ExitCode::FAILURE
            }
        },
    }
}

/// `ops net groups import <file> [--force]`: merge a portable `[net.groups]` fragment into the
/// global config, preserving every existing group and comment (`toml_edit`). Groups are global-only,
/// so the target is always the global config; the deliberate command is the consent (an agent in the
/// cage cannot run it), and the global config is trusted by location, so there is no prompt. A name
/// that already exists is refused unless `--force` overwrites it. The imported groups are inert until
/// referenced by a `[network]` `allow`/`deny` with `@<name>`.
fn net_groups_import(args: &[OsString]) -> ExitCode {
    let mut force = false;
    let mut file: Option<PathBuf> = None;
    for arg in args {
        match arg.to_str() {
            Some("--force") | Some("-f") => force = true,
            Some(s) if s.starts_with('-') => {
                eprintln!("ops: net groups import: unknown flag `{s}`");
                eprintln!(
                    "ops: usage: {}",
                    help::synopsis_of(&["net", "groups", "import"])
                );
                return ExitCode::from(2);
            }
            _ => {
                if file.is_some() {
                    eprintln!("ops: net groups import: expected exactly one file");
                    return ExitCode::from(2);
                }
                file = Some(PathBuf::from(arg));
            }
        }
    }
    let Some(file) = file else {
        eprintln!(
            "ops: usage: {}",
            help::synopsis_of(&["net", "groups", "import"])
        );
        return ExitCode::from(2);
    };

    let groups = match config::read_net_groups_fragment(&file) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("ops: net groups import: {e}");
            return ExitCode::from(2);
        }
    };
    // Validate every name before writing (a name keys a referenceable identifier and, if invalid,
    // would be dropped at load) — fail closed, naming the offender.
    if let Some(bad) = groups.keys().find(|n| !config::is_valid_group_name(n)) {
        eprintln!(
            "ops: net groups import: invalid group name `{bad}` (1–64 of [A-Za-z0-9._-]); nothing imported"
        );
        return ExitCode::from(2);
    }

    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: cannot read the current directory: {e}");
            return ExitCode::FAILURE;
        }
    };
    let path = match config::manage::scope_path(&config::manage::Scope::Global, &cwd) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ops: net groups import: {e}");
            return ExitCode::from(1);
        }
    };
    match config::manage::import_net_groups(&path, &groups, force) {
        Ok(outcome) => {
            let mut parts = Vec::new();
            if !outcome.added.is_empty() {
                parts.push(format!("added {}", outcome.added.join(", ")));
            }
            if !outcome.overwritten.is_empty() {
                parts.push(format!("overwrote {}", outcome.overwritten.join(", ")));
            }
            let summary = if parts.is_empty() {
                "nothing to do".to_string()
            } else {
                parts.join("; ")
            };
            println!(
                "imported {} egress group(s) into {} — {summary}",
                groups.len(),
                path.display()
            );
            // Import is the one moment the user consciously brings in someone else's data, so flag any
            // entry that will not resolve (a malformed or nested one) right here — the same inspect-time
            // check `ops net groups <name>` applies — rather than let it surface only at the next launch.
            let dead: Vec<String> = groups
                .iter()
                .filter(|(_, entries)| entries.iter().any(|e| net_group_entry_issue(e).is_some()))
                .map(|(name, _)| name.clone())
                .collect();
            if !dead.is_empty() {
                diag::warn(&format!(
                    "some entries will not resolve in: {} — inspect with `ops net groups <name>`",
                    dead.join(", ")
                ));
            }
            ExitCode::SUCCESS
        }
        Err(config::manage::ManageError::GroupCollision(names)) => {
            eprintln!(
                "ops: net groups import: {} already defined: {} — re-run with --force to overwrite, \
                 or rename in the fragment (nothing was written)",
                if names.len() == 1 { "group" } else { "groups" },
                names.join(", ")
            );
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("ops: net groups import: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Why a group entry is not a usable rule, or `None` if it is fine. Mirrors what `build_net_groups`
/// does at resolve time: a leading `@` is a nested reference (a group is flat, so it is ignored);
/// anything else is classified, and a classification error is the reason. Used to flag an entry in
/// the `ops net groups <name>` listing so a typo in a group is visible where the group is inspected.
fn net_group_entry_issue(entry: &str) -> Option<String> {
    if entry.trim().starts_with('@') {
        return Some("nested group reference — ignored (a group is a flat list of entries)".into());
    }
    allowlist::classify(entry).err()
}

/// Render `ops net groups` — a pure presenter (its layout is asserted in a test). With no names it
/// lists each group and its entry count; with names it prints each named group's entries (as a
/// `@name` block), appending a note to any entry that would be ignored or is malformed.
fn render_net_groups(
    groups: &std::collections::BTreeMap<String, Vec<String>>,
    names: &[String],
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let plural = |count: usize| if count == 1 { "entry" } else { "entries" };
    let mut o = String::new();

    if names.is_empty() {
        let _ = writeln!(o, "{h}egress groups{r} {dim}({}){r}", groups.len());
        if groups.is_empty() {
            let _ = writeln!(
                o,
                "  {dim}none defined — declare them under [net.groups] in the global config{r}"
            );
            return o;
        }
        let name_w = groups.keys().map(String::len).max().unwrap_or(0);
        for (name, entries) in groups {
            let _ = writeln!(
                o,
                "  {n}{name:<name_w$}{r}  {dim}({} {}){r}",
                entries.len(),
                plural(entries.len())
            );
        }
        let _ = writeln!(o, "  {dim}resolve one with `ops net groups <name>`{r}");
        return o;
    }

    for name in names {
        let Some(entries) = groups.get(name) else {
            continue; // an unknown name was already reported by the caller
        };
        let _ = writeln!(
            o,
            "{h}@{name}{r} {dim}({} {}){r}",
            entries.len(),
            plural(entries.len())
        );
        if entries.is_empty() {
            let _ = writeln!(o, "  {dim}(empty){r}");
        }
        for e in entries {
            match net_group_entry_issue(e) {
                None => {
                    let _ = writeln!(o, "  {e}");
                }
                Some(issue) => {
                    let _ = writeln!(o, "  {e}  {dim}({issue}){r}");
                }
            }
        }
    }
    o
}

/// `ops net rules --source session`: the live overlay rules this project's running sessions carry —
/// loaded with `ops net allow|deny --session` or remembered from a `ops net pending … --session`
/// answer. These live in the sessions' memory (not config) and are gone when the sessions end. The
/// proxy folds them into its effective policy, so they apply in any filtering posture, not only
/// `ask`. Cross-references the registry to find the sessions for this project (by the
/// canonical project root the registry keys on), queries each one's control socket, and lists the
/// merged, deduped rules. No config read, no launch, no nix.
fn net_rules_manual(cwd: &Path, app: Option<&str>, filter: Option<&str>, json: bool) -> ExitCode {
    use config::view::{NetRuleKind, NetRuleView, RuleSourceView};
    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Which sessions to query: `-a <app>` selects that app's session(s) (from the registry, across
    // projects — an app's live rules are the same wherever it runs); otherwise this project's
    // sessions, keyed by the canonical project root (the registry stores canonical paths; fall back
    // to the cwd as-is if it cannot be canonicalized).
    let (pids, scope): (Vec<u32>, String) = match app {
        Some(name) => (
            session_pids_for_app(&data_dir, name).into_iter().collect(),
            format!(" (app: {name})"),
        ),
        None => {
            let project = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
            (
                pending_session_context(&data_dir)
                    .into_iter()
                    .filter(|(_, proj, _)| *proj == project)
                    .map(|(pid, _, _)| pid)
                    .collect(),
                String::new(),
            )
        }
    };

    // Merge + dedup the manual rules across this project's sessions.
    let mut rules: Vec<NetRuleView> = Vec::new();
    for pid in pids {
        let Ok(rows) = sandbox::control::query_manual(&data_dir, pid) else {
            continue; // the session ended between the registry read and the query
        };
        for row in rows {
            let view = NetRuleView {
                kind: match row.kind {
                    sandbox::control::ManualKind::Allow => NetRuleKind::Allow,
                    sandbox::control::ManualKind::Deny => NetRuleKind::Deny,
                    sandbox::control::ManualKind::Mute => NetRuleKind::Mute,
                },
                source: RuleSourceView::Manual,
                rule: row.rule,
                group: None,
            };
            if !rules
                .iter()
                .any(|r| r.kind == view.kind && r.rule == view.rule)
            {
                rules.push(view);
            }
        }
    }

    let total = rules.len();
    let shown: Vec<&NetRuleView> = rules
        .iter()
        .filter(|r| filter.is_none_or(|f| r.rule.to_lowercase().contains(f)))
        .collect();

    if json {
        let value = serde_json::json!({
            "mode": "session",
            "rules": shown.iter().map(|r| (*r).clone()).collect::<Vec<_>>(),
        });
        println!("{value}");
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!(
        "{}",
        render_net_rules("session", &scope, &shown, total, &pal)
    );
    ExitCode::SUCCESS
}

/// Render the egress rule listing — a pure presenter (so its colored layout is asserted in a test):
/// a header naming the effective mode, then one line per shown rule (`allow`/`deny` keyword, the
/// rule as a cyan identifier matching `ops config`, the source dim). `shared`/`none` carry no rules
/// and say so; an empty result distinguishes "no rules declared" from "nothing matched the filter".
fn render_net_rules(
    mode: &str,
    scope: &str,
    shown: &[&config::view::NetRuleView],
    total: usize,
    pal: &style::Palette,
) -> String {
    use config::view::{NetRuleKind, RuleSourceView};
    use std::fmt::Write as _;
    let (h, n, ok, err, dim, r) = (pal.head, pal.name, pal.ok, pal.err, pal.dim, pal.reset);
    let mut o = String::new();

    match mode {
        "shared" => {
            let _ = writeln!(
                o,
                "{h}network{scope}:{r} shared {dim}— no egress rules (host network, no proxy){r}"
            );
            return o;
        }
        "none" => {
            let _ = writeln!(
                o,
                "{h}network{scope}:{r} none {dim}— no egress rules (no network){r}"
            );
            return o;
        }
        // A filtering posture: name it and frame what the rules mean.
        "allow" => {
            let _ = writeln!(
                o,
                "{h}network{scope}:{r} allow {dim}— denylist: every public host reaches except the deny rules{r}"
            );
        }
        "ask" => {
            let _ = writeln!(
                o,
                "{h}network{scope}:{r} ask {dim}— an unmatched host parks for a live `ops net pending` decision; \
                 allow rules auto-pass, deny rules auto-fail{r}"
            );
        }
        // The live session-rule listing (`--source session`): runtime rules from `--session`
        // answers, not config — framed as such so they are not mistaken for the static policy.
        "session" => {
            // `scope` is ` (app: <name>)` when `-a` narrowed the query, else empty (this project).
            let where_ = if scope.is_empty() {
                "this project's running sessions".to_string()
            } else {
                format!("that app's running sessions{scope}")
            };
            let _ = writeln!(
                o,
                "{h}session egress rules{r} {dim}— live, loaded with `ops net allow|deny --session` \
                 (or a `ops net pending … --session` answer) into {where_} (gone when they end){r}"
            );
        }
        _ => {
            let _ = writeln!(
                o,
                "{h}network{scope}:{r} deny {dim}— allowlist: only the listed and built-in hosts reach{r}"
            );
        }
    }

    if shown.is_empty() {
        let note = if total == 0 {
            "(no rules declared)"
        } else {
            "(no rules match the filter)"
        };
        let _ = writeln!(o, "  {dim}{note}{r}");
        return o;
    }

    for rule in shown {
        let source = match rule.source {
            RuleSourceView::Config => "config",
            RuleSourceView::Builtin => "builtin",
            RuleSourceView::Manual => "session",
        };
        // A group-expanded rule notes its origin `@<group>` beside the source — but only in the
        // expanded view: a collapsed row's text is already `@<group>`, so the annotation would just
        // repeat it.
        let tag = match &rule.group {
            Some(g) if rule.rule != format!("@{g}") => format!("{source}, @{g}"),
            _ => source.to_string(),
        };
        match rule.kind {
            NetRuleKind::Allow => {
                let _ = writeln!(o, "  {ok}allow{r} {n}{}{r}  {dim}({tag}){r}", rule.rule);
            }
            NetRuleKind::Deny => {
                let _ = writeln!(o, "  {err}deny{r}  {n}{}{r}  {dim}({tag}){r}", rule.rule);
            }
            // A `mute` (`dontaudit`) rule suppresses the log line of a request that is *denied*
            // anyway — dim, so it never reads as a third verdict beside allow/deny.
            NetRuleKind::Mute => {
                let _ = writeln!(o, "  {dim}mute{r}  {n}{}{r}  {dim}({tag}){r}", rule.rule);
            }
        }
    }
    o
}

/// `ops net allow|deny <rule> [--local|--global|-c <file>] [--app <name>]`: persist an egress rule
/// to a config file. The rule is validated up front (fail-closed), then `manage::add_egress_rule`
/// places it per the posture matrix. A write to the project `.ops.toml` is trust-gated: it must be
/// absent or already trusted (else refuse — never bless an unreviewed file by appending), and is
/// re-trusted after the write so the rule takes effect. The global config is trusted by location
/// (no gate). `--app <name>` targets the app's own `[app.<name>.network]`.
fn net_add_rule(list: config::manage::EgressList, args: &[OsString]) -> ExitCode {
    use config::manage;
    let verb = match list {
        manage::EgressList::Allow => "allow",
        manage::EgressList::Deny => "deny",
        manage::EgressList::Mute => "mute",
    };

    // `--session` (load the rule into the live overlay of the running session(s) instead of a config
    // file) and its `--all` scope widener are extracted before `split_scope`, which rejects any flag
    // it does not know; the config-scope flags (`--local`/`--global`/`-c`) and `-a` ride it.
    let session = args.iter().any(|a| a.to_str() == Some("--session"));
    let all = args.iter().any(|a| a.to_str() == Some("--all"));
    let rest: Vec<OsString> = args
        .iter()
        .filter(|a| !matches!(a.to_str(), Some("--session") | Some("--all")))
        .cloned()
        .collect();
    let parsed = match split_scope(&rest) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ops: {e}");
            return ExitCode::from(2);
        }
    };
    let rule = match parsed.positionals.as_slice() {
        [r] => r.clone(),
        [] => {
            eprintln!("ops: usage: {}", help::synopsis_of(&["net", verb]));
            return ExitCode::from(2);
        }
        _ => {
            eprintln!("ops: net {verb}: expected exactly one rule");
            return ExitCode::from(2);
        }
    };
    if let Some(name) = &parsed.app {
        if config::is_reserved_app_verb(name) || !config::is_valid_app_name(name) {
            eprintln!("ops: invalid app name '{name}'");
            return ExitCode::from(2);
        }
    }
    // Validate the rule before touching any file or session (fail-closed). A `@<name>` group reference
    // is an alias for a `[net.groups]` group, expanded at load time — not itself a classifiable rule —
    // so it is validated as a group name rather than through `classify` (which would reject the `@`).
    // An undefined reference is not a write-time error (the group may be defined later); it warns
    // loudly on the next load. Any other entry is classified: a `*` catch-all, a scheme, or an
    // uncompilable regex is refused, the same classification the config resolver applies.
    let is_group = rule.trim().starts_with('@');
    if is_group {
        let group = rule.trim().strip_prefix('@').unwrap_or_default();
        if !config::is_valid_group_name(group) {
            eprintln!(
                "ops: invalid group reference {rule:?}: a group name must be 1–64 of [A-Za-z0-9._-]"
            );
            return ExitCode::from(2);
        }
    } else if let Err(e) = allowlist::classify(&rule) {
        eprintln!("ops: invalid rule {rule:?}: {e}");
        return ExitCode::from(2);
    }

    if session {
        // `--session` writes no config file, so the file-scope flags do not apply — point at the
        // session-scope flags instead of silently ignoring a `--global` the user expected to matter.
        if parsed.scope_explicit {
            eprintln!(
                "ops: --session loads a live rule and writes no file, so --local/--global/-c do not \
                 apply — use -a <app> or --all to scope the session(s)"
            );
            return ExitCode::from(2);
        }
        // A `@group` is expanded from the config at launch; the live overlay has no group vocabulary,
        // so it cannot carry one. Point at the two ways to use a group.
        if is_group {
            eprintln!(
                "ops: --session cannot load a @group (a group is expanded from the config at launch) \
                 — pass the concrete rules, or add the group to the config without --session"
            );
            return ExitCode::from(2);
        }
        let cwd = match std::env::current_dir() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("ops: cannot read the current directory: {e}");
                return ExitCode::FAILURE;
            }
        };
        return net_inject_session(list, &rule, all, parsed.app.as_deref(), &cwd);
    }

    // `--all` is a session-scope widener, meaningless for a config write (which targets one file).
    if all {
        eprintln!(
            "ops: --all only applies with --session (it widens a live rule to every session); a config \
             write targets one file — drop --all"
        );
        return ExitCode::from(2);
    }

    // `ops net allow|deny` resolves a `--local` scope against the cwd, as one expects of a command
    // run in a project.
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: cannot read the current directory: {e}");
            return ExitCode::FAILURE;
        }
    };
    match persist_egress_rule(list, &rule, &parsed.scope, parsed.app.as_deref(), &cwd) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err((code, message)) => {
            eprintln!("ops: {message}");
            ExitCode::from(code)
        }
    }
}

/// `ops net unmute <rule> [--local|--global|-c <file>] [-a <app>]`: remove a `mute` rule from a
/// config file — the inverse of `ops net mute`. Idempotent (removing a rule that is not there is a
/// reported no-op, not an error); a project `.ops.toml` write is trust-gated and re-trusted exactly
/// like `ops net mute`. There is no `--session` form — a live mute overlay is not yet wired, so a
/// session-scope flag is refused rather than silently ignored.
fn net_remove_rule(list: config::manage::EgressList, args: &[OsString]) -> ExitCode {
    if args
        .iter()
        .any(|a| matches!(a.to_str(), Some("--session") | Some("--all")))
    {
        eprintln!(
            "ops: net unmute: --session/--all do not apply — this removes a rule from a config file"
        );
        return ExitCode::from(2);
    }
    let parsed = match split_scope(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ops: {e}");
            return ExitCode::from(2);
        }
    };
    let rule = match parsed.positionals.as_slice() {
        [r] => r.clone(),
        [] => {
            eprintln!("ops: usage: {}", help::synopsis_of(&["net", "unmute"]));
            return ExitCode::from(2);
        }
        _ => {
            eprintln!("ops: net unmute: expected exactly one rule");
            return ExitCode::from(2);
        }
    };
    if let Some(name) = &parsed.app {
        if config::is_reserved_app_verb(name) || !config::is_valid_app_name(name) {
            eprintln!("ops: invalid app name '{name}'");
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
    match persist_egress_removal(list, &rule, &parsed.scope, parsed.app.as_deref(), &cwd) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err((code, message)) => {
            eprintln!("ops: {message}");
            ExitCode::from(code)
        }
    }
}

/// `ops net allow|deny <rule> --session [-a <app>] [--all]`: load a rule into the **live overlay** of
/// the running session(s) instead of a config file — the proactive sibling of `ops net pending
/// allow|deny <id> --session`, which remembers a decision for a request that already parked. It writes
/// no file (so it never re-trusts a project the way a config write does) and the rule dies with the
/// session. Scope: by default the **current project's** sessions; `-a <app>` narrows to that app's;
/// `--all` widens to every reachable session. Only an `ask`-posture session consults the overlay, so a
/// filtering-posture session reports the load as skipped (`err not-ask`) rather than a silent no-op.
fn net_inject_session(
    list: config::manage::EgressList,
    rule: &str,
    all: bool,
    app: Option<&str>,
    cwd: &Path,
) -> ExitCode {
    use config::manage::EgressList;
    // `allow`/`deny` load a verdict rule; `mute` loads a log-suppression rule (a different overlay
    // and control verb), so the injection call is dispatched per-list in the loop below.
    let verb = match list {
        EgressList::Allow => "allow",
        EgressList::Deny => "deny",
        EgressList::Mute => "mute",
    };
    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Two composing pid filters: the project (unless `--all` widens machine-wide) and the app (`-a`).
    // A session must pass every active filter to receive the rule.
    let project_pids = if all {
        None
    } else {
        let canonical = match sandbox::project_identity(cwd) {
            Ok((_, c)) => c,
            Err(e) => {
                eprintln!("ops: cannot resolve the current project directory: {e}");
                return ExitCode::FAILURE;
            }
        };
        Some(session_pids_for_project(&data_dir, &canonical))
    };
    let app_pids = app.map(|name| session_pids_for_app(&data_dir, name));

    let context = pending_session_context(&data_dir);
    let mut loaded: Vec<u32> = Vec::new();
    let mut refused: Vec<u32> = Vec::new();
    for pid in sandbox::control::session_pids(&data_dir) {
        if app_pids.as_ref().is_some_and(|p| !p.contains(&pid)) {
            continue;
        }
        if project_pids.as_ref().is_some_and(|p| !p.contains(&pid)) {
            continue;
        }
        // A mute loads through the dedicated mute overlay (`REMEMBER MUTE`); allow/deny load a
        // verdict rule (`REMEMBER ALLOW|DENY`).
        let injected = match list {
            EgressList::Mute => sandbox::control::inject_mute(&data_dir, pid, rule),
            EgressList::Allow => sandbox::control::inject_rule(
                &data_dir,
                pid,
                sandbox::control::Verdict::Allow,
                rule,
            ),
            EgressList::Deny => {
                sandbox::control::inject_rule(&data_dir, pid, sandbox::control::Verdict::Deny, rule)
            }
        };
        match injected {
            Ok(sandbox::control::InjectOutcome::Loaded) => loaded.push(pid),
            Ok(sandbox::control::InjectOutcome::Refused) => refused.push(pid),
            // A dead/stale socket (the session went away) — skip it.
            Err(_) => {}
        }
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!(
        "{}",
        render_inject(verb, rule, all, app, &loaded, &refused, &context, &pal)
    );
    ExitCode::SUCCESS
}

/// Render a `--session` rule load: which live sessions took the rule (with their agent/project
/// context, so a cross-agent reach is visible) and which an older server refused. When no session in
/// scope took it, it says so and points at the config write as the persistent alternative. A pure
/// presenter — its palette comes from the caller.
#[allow(clippy::too_many_arguments)]
fn render_inject(
    verb: &str,
    rule: &str,
    all: bool,
    app: Option<&str>,
    loaded: &[u32],
    refused: &[u32],
    context: &[(u32, PathBuf, String)],
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (h, dim, warn, r) = (pal.head, pal.dim, pal.warn, pal.reset);
    let mut o = String::new();
    if !loaded.is_empty() {
        let _ = writeln!(
            o,
            "{h}loaded {verb} rule `{rule}` into {} live session(s):{r}",
            loaded.len()
        );
        for pid in loaded {
            match context.iter().find(|(p, _, _)| p == pid) {
                Some((_, project, label)) => {
                    let _ = writeln!(o, "  {dim}session {pid} [{label}] {}{r}", project.display());
                }
                None => {
                    let _ = writeln!(o, "  {dim}session {pid} (unregistered){r}");
                }
            }
        }
        // The rule is live-only, never written to config — so plain `ops net rules` (the config
        // policy) will not show it. Point at where it *is* visible.
        let _ = writeln!(
            o,
            "  {dim}see it with `ops net rules --source session` (it is not in the config){r}"
        );
    }
    if !refused.is_empty() {
        let pids = refused
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            o,
            "{warn}session(s) {pids} refused the rule (an older ops without --session rule \
             support).{r}"
        );
    }
    // Nothing took the rule: no session with egress filtering is running in scope. Point at the
    // persistent path (which pre-decides the host for the next launch), carrying the `--app <name>`
    // scope when one was given so the hint is copy-pasteable.
    if loaded.is_empty() {
        if refused.is_empty() {
            let scope = match (app, all) {
                (Some(a), _) => format!("app `{a}`"),
                (None, true) => "any session".to_string(),
                (None, false) => "this project".to_string(),
            };
            let _ = writeln!(
                o,
                "{dim}no reachable session with egress filtering for {scope} — nothing to load the \
                 rule into.{r}"
            );
        }
        let app_flag = app.map(|a| format!(" --app {a}")).unwrap_or_default();
        let _ = writeln!(
            o,
            "  {dim}to pre-decide it for the next launch, persist it: ops net {verb} \
             {rule}{app_flag}{r}"
        );
    }
    o
}

/// Pre-flight the trust gate for a `--local` save at `cwd`, *before* any irreversible action (a bulk
/// drain unblocks agents and cannot be undone). Mirrors [`persist_egress_rule`]'s gate exactly — same
/// `scope_path`, same trust-store, same "existing config must be trusted" rule — so a save that would
/// later refuse refuses here instead, with nothing answered. Absent or already-trusted is fine (ops's
/// append is then the sole delta).
/// The write-side trust gate for a `--local` save: an existing-but-untrusted (or changed) project
/// config must not be silently blessed by an appended rule — the user reviews and re-trusts it
/// first. An absent config (bootstrap) or an already-trusted one is fine, so ops's edit is the sole
/// delta from the trusted bytes. Pure on the `(exists, state)` pair, so the refuse/allow matrix is
/// unit-testable without a filesystem.
fn local_save_permitted(exists: bool, state: trust::TrustState) -> bool {
    !exists || state == trust::TrustState::Trusted
}

fn precheck_local_save(cwd: &Path) -> Result<(), (u8, String)> {
    use config::manage::{self, Scope};
    let store = trust::default_store_dir().ok_or((
        1,
        "cannot determine the trust store (set XDG_STATE_HOME or HOME) — needed to trust the project \
         config a `--local` save writes; use --global instead"
            .to_string(),
    ))?;
    let path = manage::scope_path(&Scope::Local, cwd).map_err(|e| (1, e.to_string()))?;
    if !local_save_permitted(path.exists(), trust::state(&store, &path)) {
        return Err((
            2,
            format!(
                "{} is not trusted — review it and run `ops trust {}`, then retry (a `--local` save \
                 will not silently bless an untrusted project)",
                path.display(),
                config::PROJECT_CONFIG
            ),
        ));
    }
    Ok(())
}

/// `ops net pending allow|deny --all --save [-l|-g|-a <app>]`: drain parked requests *and* persist a
/// rule per answered host, so the same destinations are pre-decided next launch. The drain is scoped
/// to match the save target: a `--local` save (the default) writes the **current project's** config,
/// so it drains only that project's sessions — never machine-wide — which is what makes a bulk local
/// save unambiguous (one project's requests can never land in another's config). `--global` writes the
/// one global file and so may drain across projects; `-a <app>` narrows by app and composes with the
/// project scope. The drain is irreversible, so a `--local` save pre-flights the trust gate first.
fn net_pending_drain_and_save(
    verdict: sandbox::control::Verdict,
    session: bool,
    scope: &config::manage::Scope,
    app: Option<&str>,
) -> ExitCode {
    use config::manage::{EgressList, Scope};
    let (list, verb, past) = match verdict {
        sandbox::control::Verdict::Allow => (EgressList::Allow, "allow", "allowed"),
        sandbox::control::Verdict::Deny => (EgressList::Deny, "deny", "denied"),
    };
    if matches!(scope, Scope::File(_)) {
        eprintln!("ops: `--all --save` takes --local or --global, not `-c <file>`");
        return ExitCode::from(2);
    }
    let local = matches!(scope, Scope::Local);

    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: {e}");
            return ExitCode::FAILURE;
        }
    };

    // For a `--local` save, resolve the current project up front — its canonical root scopes the drain
    // AND is the save base — and pre-flight the trust gate before the irreversible drain.
    let cwd = match std::env::current_dir() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ops: cannot read the current directory: {e}");
            return ExitCode::FAILURE;
        }
    };
    let project_canonical = if local {
        if let Err((code, msg)) = precheck_local_save(&cwd) {
            eprintln!("ops: {msg}");
            return ExitCode::from(code);
        }
        match sandbox::project_identity(&cwd) {
            Ok((_, canonical)) => Some(canonical),
            Err(e) => {
                eprintln!("ops: cannot resolve the current project directory: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    // Two composing pid filters: the project (a `--local` save) and the app (`-a`). A session must
    // pass every active filter to be drained.
    let app_pids = app.map(|name| session_pids_for_app(&data_dir, name));
    let project_pids = project_canonical
        .as_deref()
        .map(|canon| session_pids_for_project(&data_dir, canon));

    let context = pending_session_context(&data_dir);
    let mut answered: Vec<(u32, Vec<String>)> = Vec::new();
    let mut hosts: Vec<String> = Vec::new();
    let mut unsupported: Vec<u32> = Vec::new();
    for pid in sandbox::control::session_pids(&data_dir) {
        if app_pids.as_ref().is_some_and(|p| !p.contains(&pid)) {
            continue;
        }
        if project_pids.as_ref().is_some_and(|p| !p.contains(&pid)) {
            continue;
        }
        match sandbox::control::drain_session(&data_dir, pid, verdict, session) {
            Ok(sandbox::control::DrainOutcome::Drained(answered_hosts))
                if !answered_hosts.is_empty() =>
            {
                hosts.extend(answered_hosts.iter().cloned());
                answered.push((pid, answered_hosts));
            }
            Ok(sandbox::control::DrainOutcome::Drained(_)) => {}
            // A session launched by an older ops that does not understand `--all` — nothing was
            // answered, so nothing is saved for it either; name it so the user knows why.
            Ok(sandbox::control::DrainOutcome::Unsupported) => unsupported.push(pid),
            Err(_) => {}
        }
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let total: usize = answered.iter().map(|(_, h)| h.len()).sum();
    if total == 0 {
        let mut out = String::new();
        if unsupported.is_empty() {
            let scope_note = if local {
                "for this project".to_string()
            } else if let Some(name) = app {
                format!("for app `{name}`")
            } else {
                "across any ask-mode session".to_string()
            };
            out.push_str(&format!(
                "{}no pending requests {scope_note} — nothing to answer or save{}\n",
                pal.dim, pal.reset
            ));
        }
        write_unsupported_note(&mut out, &unsupported, pal.warn, pal.dim, pal.reset);
        print!("{out}");
        return ExitCode::SUCCESS;
    }

    // Persist a rule per *unique* answered host (a host answered in several sessions is one rule),
    // preserving first-seen order. The base of a `--local` write is the cwd — every drained session is
    // in this project. The live answers already stuck, so a save failure is a warning, not a rollback.
    let mut seen = std::collections::HashSet::new();
    let unique: Vec<String> = hosts
        .into_iter()
        .filter(|h| seen.insert(h.clone()))
        .collect();
    let mut saved = 0usize;
    let mut save_error = None;
    for host in &unique {
        match persist_egress_rule(list, host, scope, app, &cwd) {
            Ok(_) => saved += 1,
            Err((_, msg)) => {
                save_error = Some(msg);
                break;
            }
        }
    }

    print!(
        "{}",
        render_drain(past, session, app, &answered, &unsupported, &context, &pal)
    );
    // Name the real write target — the same resolution the per-host save just used — so a global
    // app's save is reported as its profile file, not "the global config under app" (the profile is
    // where the rule actually landed). The target already carries the app, so there is no separate
    // " under app" suffix. Resolving cannot fail on this success path: every host was just persisted
    // to this same target; the fallback covers only the theoretical no-config-dir case.
    let target = egress_write_target(scope, app, &cwd)
        .map(|(_, _, t)| t)
        .unwrap_or_else(|_| {
            if local {
                "the project config".to_string()
            } else {
                "the global config".to_string()
            }
        });
    match save_error {
        None => {
            println!(
                "  saved {saved} {verb} rule(s) to {target}{}",
                if local { " (re-trusted)" } else { "" }
            );
            if local {
                println!(
                    "{}  scoped to this project — other projects' sessions are untouched \
                     (use --global to widen){}",
                    pal.dim, pal.reset
                );
            }
            ExitCode::SUCCESS
        }
        Some(msg) => {
            diag::warn(&format!(
                "answered {total} request(s) and saved {saved} of {} rule(s), then stopped: {msg}",
                unique.len()
            ));
            ExitCode::FAILURE
        }
    }
}

/// Resolve where an egress-rule write lands and how to name it, shared by the single-rule
/// [`persist_egress_rule`] and the bulk [`net_pending_drain_and_save`] so the two can never disagree
/// about the file or the target its summary reports. Returns the file to edit, the in-file app key
/// (`None` writes a top-level `[network]` — a profile's shape, or a baseline config; `Some(name)`
/// writes `[app.<name>.network]` — a project overlay), and the human target description (which
/// already carries the app, so no caller adds a separate " under app" suffix).
///
/// The one divergence from a plain scope→path map is an **app-scoped global** write: a global app
/// lives as a profile file (`apps/<name>.toml`), never an inline `[app.<name>]` in the global config
/// (which is forbidden), so it targets the profile with a top-level key.
fn egress_write_target<'a>(
    scope: &config::manage::Scope,
    app: Option<&'a str>,
    base: &Path,
) -> Result<(PathBuf, Option<&'a str>, String), (u8, String)> {
    use config::manage::{self, Scope};
    let (path, app_key) = match (scope, app) {
        (Scope::Global, Some(name)) => (
            manage::scope_app_path(scope, base, name).map_err(|e| (1, e.to_string()))?,
            None,
        ),
        (Scope::Local, Some(name)) => (
            manage::scope_path(scope, base).map_err(|e| (1, e.to_string()))?,
            Some(name),
        ),
        _ => (
            manage::scope_path(scope, base).map_err(|e| (1, e.to_string()))?,
            app,
        ),
    };
    let target = match (scope, app) {
        (Scope::Global, None) => "the global config".to_string(),
        (Scope::Global, Some(a)) => format!("the app profile `{a}` ({})", path.display()),
        (Scope::Local, None) => "the project config".to_string(),
        (Scope::Local, Some(a)) => format!("the project config (app `{a}`)"),
        (Scope::File(p), None) => p.display().to_string(),
        (Scope::File(p), Some(a)) => format!("{} (app `{a}`)", p.display()),
    };
    Ok((path, app_key, target))
}

/// Persist an egress `rule` to the scoped config file, trust-gating a project write and re-trusting
/// it after — the shared writer behind `ops net allow|deny <rule>` and the `--save` of
/// `ops net pending allow|deny`. Returns the success line to print, or `(exit-code, message)`: a
/// refusal (a `-c` file scope, an untrusted project config, a posture conflict) is code `2`; an
/// operational failure (no trust store, an unwritable path, a re-trust failure) is code `1`. A
/// `Scope::File` is refused — the vocabulary is local/global/app, and a `-c` write would be
/// silently dropped at launch (neither trusted-by-location nor the gated project path).
fn persist_egress_rule(
    list: config::manage::EgressList,
    rule: &str,
    scope: &config::manage::Scope,
    app: Option<&str>,
    base: &Path,
) -> Result<String, (u8, String)> {
    use config::manage::{self, AddOutcome, Scope};
    let verb = match list {
        manage::EgressList::Allow => "allow",
        manage::EgressList::Deny => "deny",
        manage::EgressList::Mute => "mute",
    };
    if matches!(scope, Scope::File(_)) {
        return Err((
            2,
            format!("`ops net {verb}` does not take `-c <file>` — use --local, --global, or --app"),
        ));
    }
    // Validate the app name here, in the shared writer, so every path that persists a rule is
    // covered — including `ops net pending --save --app <name>`, whose by-id form does not
    // pre-check the name. An invalid or reserved name keys a table `resolve_apps` drops at load,
    // so the rule would be silently inert; refuse it rather than report a durable restriction.
    if let Some(name) = app {
        if config::is_reserved_app_verb(name) || !config::is_valid_app_name(name) {
            return Err((2, format!("`{name}` is not a valid app name")));
        }
    }
    // `base` is the directory a `--local` scope resolves against: the cwd for `ops net allow|deny`,
    // or the *answered session's* project for `ops net pending --save` (so the rule lands in the
    // project the agent runs in, not wherever the user happens to stand). Global ignores it. The
    // file, the in-file table shape (`app_key`), and the human `target` are resolved together — and
    // shared with the drain path — so the write and the message it prints can never disagree about
    // where the rule landed.
    let (path, app_key, target) = egress_write_target(scope, app, base)?;

    // A write to the project `.ops.toml` is trust-gated; the global config and the app profiles
    // under `apps/` are trusted by location.
    let gated = matches!(scope, Scope::Local);
    let store =
        if gated {
            Some(trust::default_store_dir().ok_or((
            1,
            "cannot determine the trust store (set XDG_STATE_HOME or HOME); the rule would be \
             written but could not be trusted, so it would not take effect — use --global, or set \
             the trust store"
                .to_string(),
        ))?)
        } else {
            None
        };

    // Pre-check: an existing-but-untrusted project config must not be silently blessed by an append
    // — the user reviews and trusts it first. Absent or already-trusted is fine: ops's edit is then
    // the sole delta from the trusted bytes.
    if let Some(store) = &store {
        if !local_save_permitted(path.exists(), trust::state(store, &path)) {
            return Err((
                2,
                format!(
                    "{} is not trusted — review it and run `ops trust {}`, then retry",
                    path.display(),
                    config::PROJECT_CONFIG
                ),
            ));
        }
    }

    let outcome =
        manage::add_egress_rule(&path, app_key, list, rule).map_err(|e| (2, e.to_string()))?;

    // Re-trust the project config after the write. Ordering is fail-safe: a crash between the write
    // and the trust leaves a correct-but-untrusted file, which the next launch drops — the rule does
    // not take effect, never a security hole.
    if let Some(store) = &store {
        trust::trust(store, &path).map_err(|e| {
            (
                1,
                format!(
                    "wrote the rule but could not re-trust {}: {e} — run `ops trust {}` so it \
                     takes effect",
                    path.display(),
                    config::PROJECT_CONFIG
                ),
            )
        })?;
    }

    Ok(match outcome {
        AddOutcome::AlreadyPresent => {
            format!("{verb} {rule} is already present in {target} — no change")
        }
        AddOutcome::Added { created_mode } => {
            let mut msg = match created_mode {
                Some(mode) => {
                    format!("set network mode `{mode}` and added {verb} {rule} to {target}")
                }
                None => format!("added {verb} {rule} to {target}"),
            };
            if gated {
                msg.push_str(&format!("\nre-trusted {}", config::PROJECT_CONFIG));
            }
            msg
        }
    })
}

/// Remove an egress `rule` from the scoped config file — the removal sibling of
/// [`persist_egress_rule`], behind `ops net unmute`. A rule that is not present is a reported no-op
/// (no write, no re-trust). Same scope vocabulary, trust-gate, and error codes as the add path: a
/// `-c <file>` scope or an untrusted project config is code `2`; a trust-store/write/re-trust
/// failure is code `1`.
fn persist_egress_removal(
    list: config::manage::EgressList,
    rule: &str,
    scope: &config::manage::Scope,
    app: Option<&str>,
    base: &Path,
) -> Result<String, (u8, String)> {
    use config::manage::{self, RemoveOutcome, Scope};
    let (verb, noun) = match list {
        manage::EgressList::Allow => ("unallow", "allow"),
        manage::EgressList::Deny => ("undeny", "deny"),
        manage::EgressList::Mute => ("unmute", "mute"),
    };
    if matches!(scope, Scope::File(_)) {
        return Err((
            2,
            format!("`ops net {verb}` does not take `-c <file>` — use --local, --global, or --app"),
        ));
    }
    if let Some(name) = app {
        if config::is_reserved_app_verb(name) || !config::is_valid_app_name(name) {
            return Err((2, format!("`{name}` is not a valid app name")));
        }
    }
    let (path, app_key, target) = egress_write_target(scope, app, base)?;

    // A project `.ops.toml` edit is trust-gated and re-trusted, exactly like the add path — removing
    // a rule still rewrites the file, so it must not silently bless an untrusted one.
    let gated = matches!(scope, Scope::Local);
    let store = if gated {
        Some(trust::default_store_dir().ok_or((
            1,
            "cannot determine the trust store (set XDG_STATE_HOME or HOME)".to_string(),
        ))?)
    } else {
        None
    };
    if let Some(store) = &store {
        if !local_save_permitted(path.exists(), trust::state(store, &path)) {
            return Err((
                2,
                format!(
                    "{} is not trusted — review it and run `ops trust {}`, then retry",
                    path.display(),
                    config::PROJECT_CONFIG
                ),
            ));
        }
    }

    let outcome =
        manage::remove_egress_rule(&path, app_key, list, rule).map_err(|e| (2, e.to_string()))?;

    match outcome {
        RemoveOutcome::NotPresent => Ok(format!("{noun} {rule} was not in {target} — no change")),
        RemoveOutcome::Removed => {
            // Re-trust only after an actual change (the file bytes changed). Fail-safe ordering: a
            // crash between the write and the trust leaves a correct-but-untrusted file the next
            // launch drops — never a security hole.
            if let Some(store) = &store {
                trust::trust(store, &path).map_err(|e| {
                    (
                        1,
                        format!(
                            "removed the rule but could not re-trust {}: {e} — run `ops trust {}`",
                            path.display(),
                            config::PROJECT_CONFIG
                        ),
                    )
                })?;
            }
            let mut msg = format!("removed {noun} {rule} from {target}");
            if gated {
                msg.push_str(&format!("\nre-trusted {}", config::PROJECT_CONFIG));
            }
            Ok(msg)
        }
    }
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
        // Unknown or no subcommand: name the mistake (if any), then print the full page so its
        // Subcommands list guides, like bare `ops net`/`ops config`.
        other => {
            if let Some(tok) = other {
                eprintln!("ops: plugins: unknown subcommand {tok:?}");
            }
            eprint!("{}", help::page_usage(&["plugins"]).unwrap_or_default());
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
        // Unknown or no subcommand: name the mistake (if any), then print the full page so its
        // Subcommands list guides, like bare `ops net`/`ops config`.
        other => {
            if let Some(tok) = other {
                eprintln!("ops: plugins store: unknown subcommand {tok:?}");
            }
            eprint!(
                "{}",
                help::page_usage(&["plugins", "store"]).unwrap_or_default()
            );
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
    // No target means `all`; a target that is present but unrecognized (including one that is not
    // valid UTF-8) is an error, not a silent fall-through to `all`.
    let what = match args.first() {
        None => "all",
        Some(arg) => match arg.to_str() {
            Some(w @ ("all" | "nix" | "mise" | "flake" | "deb")) => w,
            _ => {
                eprintln!(
                    "ops: unknown upgrade target '{}' (known: all, nix, mise, flake, deb)",
                    arg.to_string_lossy()
                );
                return ExitCode::from(2);
            }
        },
    };
    // Exactly one (optional) target. A trailing token — a mistyped flag or a second target —
    // is rejected, not silently swallowed (so `ops upgrade nix mise` does not roll only `nix`).
    if args.len() > 1 {
        eprintln!("ops: usage: {}", help::synopsis("upgrade"));
        return ExitCode::from(2);
    }

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
    if matches!(what, "deb" | "all") {
        // The project's and apps' `deb:` `[packages]` re-resolve their `.deb` URL to a new content
        // hash and the per-project deb lock is rewritten — a host-side lock rewrite (the new hash
        // builds host-side at the next launch), like the `nix:` tools and `flake:` packages.
        ok &= upgrade_deb_packages(&nix, &layout, &cwd, &cfg, &pal);
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
    for a in &args {
        match a.to_str() {
            Some("--prune") => prune = true,
            Some("--all") => all = true,
            Some(_) => {
                eprintln!("ops: usage: {}", help::synopsis("gc"));
                return ExitCode::from(2);
            }
            None => {
                eprintln!("ops: gc: argument is not valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    sandbox::gc(prune, all, &pal)
}

/// `ops projects` — manage the per-project runtime trees under `<data>/projects/`: `list` (the
/// default) and `rm`. The reaping primitives it drives are shared with `ops gc` (which keeps the
/// nix-store side); this is the discoverable front-end over the project-tree lifecycle.
fn projects_cmd(args: Vec<OsString>) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("--help") | Some("-h") => help::show(&["projects"]),
        Some("rm") | Some("remove") => projects_rm_cmd(&args[1..]),
        Some("list") | Some("ls") => projects_list_cmd(&args[1..]),
        // No subcommand, or a leading flag like `--json`: default to `list` over all the args.
        _ => projects_list_cmd(&args),
    }
}

fn projects_list_cmd(args: &[OsString]) -> ExitCode {
    let mut json = false;
    for a in args {
        match a.to_str() {
            Some("--json") => json = true,
            Some("--help") | Some("-h") => return help::show(&["projects"]),
            Some(other) => {
                eprintln!("ops: projects: unknown argument `{other}`");
                eprintln!("       run `ops help projects` for usage.");
                return ExitCode::from(2);
            }
            None => {
                eprintln!("ops: projects: argument is not valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    sandbox::projects_list(json, &pal)
}

fn projects_rm_cmd(args: &[OsString]) -> ExitCode {
    let mut ids: Vec<String> = Vec::new();
    let (mut dead, mut markerless) = (false, false);
    let (mut dry_run, mut yes) = (false, false);
    let (mut do_gc, mut force) = (false, false);
    for a in args {
        match a.to_str() {
            Some("--dead") => dead = true,
            Some("--markerless") => markerless = true,
            Some("-n") | Some("--dry-run") => dry_run = true,
            Some("-y") | Some("--yes") => yes = true,
            Some("--gc") => do_gc = true,
            Some("-f") | Some("--force") => force = true,
            Some("--help") | Some("-h") => return help::show(&["projects"]),
            Some(flag) if flag.starts_with('-') => {
                eprintln!("ops: projects rm: unknown flag `{flag}`");
                eprintln!("       run `ops help projects` for usage.");
                return ExitCode::from(2);
            }
            Some(id) => ids.push(id.to_string()),
            None => {
                eprintln!("ops: projects rm: argument is not valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    if ids.is_empty() && !dead && !markerless {
        eprintln!(
            "ops: projects rm: name a project id, or use --dead / --markerless. \
             Run `ops projects` to list them."
        );
        return ExitCode::from(2);
    }
    let targeted = !ids.is_empty();
    let bulk = dead || markerless;
    let Some(apply) = sandbox::projects_rm_apply(targeted, bulk, dry_run, yes) else {
        eprintln!("ops: projects rm: `--dry-run` and `--yes` are contradictory — pick one.");
        return ExitCode::from(2);
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    sandbox::projects_rm(&ids, dead, markerless, apply, do_gc, force, &pal)
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

/// Roll the project's and apps' `deb:` `[packages]`: re-resolve each `.deb` URL to its current
/// content hash and rewrite the per-project deb lock (the new hash builds host-side at the next
/// launch), like the `nix:` tools and `flake:` packages. Returns whether every reference re-resolved.
fn upgrade_deb_packages(
    nix: &Path,
    layout: &store::Layout,
    cwd: &Path,
    cfg: &config::Resolved,
    pal: &style::Palette,
) -> bool {
    let outcomes = match sandbox::upgrade_deb(nix, layout, cwd, cfg) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("ops: cannot roll the deb packages: {e}");
            return false;
        }
    };
    for line in deb_upgrade_summary(&outcomes, sandbox::withheld_deb_packages(cfg), pal) {
        println!("{line}");
    }
    !outcomes
        .iter()
        .any(|o| matches!(o, sandbox::DebUpgrade::Failed { .. }))
}

/// A short, recognisable form of an SRI content hash for display (`sha256-<base64>` → the first
/// few base64 characters), the deb analogue of a short git revision.
fn short_hash(hash: &str) -> &str {
    let body = hash.strip_prefix("sha256-").unwrap_or(hash);
    &body[..body.len().min(8)]
}

/// The human-readable summary of a deb roll: one line per declared URL (newly pinned, rolled,
/// unchanged, or failed) plus the entries pruned, and a note for any reference withheld for being
/// untrusted. Pure, so every outcome is unit-tested without invoking nix.
fn deb_upgrade_summary(
    outcomes: &[sandbox::DebUpgrade],
    withheld: usize,
    pal: &style::Palette,
) -> Vec<String> {
    use sandbox::DebUpgrade::*;
    let (h, n, ok, warn, err, dim, r) = (
        pal.head, pal.name, pal.ok, pal.warn, pal.err, pal.dim, pal.reset,
    );
    let mut lines = vec![format!("{h}ops upgrade — deb packages{r}")];
    let withheld_note = || {
        format!(
            "  {warn}{withheld} deb: package(s) withheld (untrusted){r} — not rolled; run `ops trust`."
        )
    };
    if outcomes.is_empty() {
        lines.push(if withheld > 0 {
            withheld_note()
        } else {
            format!("  {dim}no deb: packages to roll.{r}")
        });
        return lines;
    }
    for outcome in outcomes {
        lines.push(match outcome {
            Unchanged { url, hash } => {
                format!(
                    "  {n}deb:{url}{r}: {n}{}{r} — {dim}unchanged.{r}",
                    short_hash(hash)
                )
            }
            Rolled { url, from, to } => format!(
                "  {n}deb:{url}{r}: {n}{}{r} → {n}{}{r} — {ok}rolled forward.{r}",
                short_hash(from),
                short_hash(to)
            ),
            Pinned { url, hash } => {
                format!(
                    "  {n}deb:{url}{r}: {n}{}{r} — {ok}newly pinned.{r}",
                    short_hash(hash)
                )
            }
            Pruned { url } => {
                format!("  {n}deb:{url}{r}: {dim}removed from the lock (no longer declared).{r}")
            }
            Failed { url, error } => {
                format!("  {n}deb:{url}{r}: {err}re-resolve failed{r} — {error}")
            }
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
    fn parse_app_rm_handles_flag_and_name_in_either_order() {
        let os = |s: &str| OsString::from(s);
        // name only
        assert!(matches!(
            parse_app_rm(&[os("claude")]),
            AppRmArgs::Ok {
                purge: false,
                gc: false,
                name: "claude"
            }
        ));
        // --purge before the name
        assert!(matches!(
            parse_app_rm(&[os("--purge"), os("claude")]),
            AppRmArgs::Ok {
                purge: true,
                gc: false,
                name: "claude"
            }
        ));
        // --purge after the name (either order)
        assert!(matches!(
            parse_app_rm(&[os("claude"), os("--purge")]),
            AppRmArgs::Ok {
                purge: true,
                gc: false,
                name: "claude"
            }
        ));
        // --purge and --gc together, name interleaved between the flags
        assert!(matches!(
            parse_app_rm(&[os("--gc"), os("claude"), os("--purge")]),
            AppRmArgs::Ok {
                purge: true,
                gc: true,
                name: "claude"
            }
        ));
        // --gc alone parses; the --gc-requires---purge rule is the caller's, not the parser's
        assert!(matches!(
            parse_app_rm(&[os("--gc"), os("claude")]),
            AppRmArgs::Ok {
                purge: false,
                gc: true,
                name: "claude"
            }
        ));
        // no name — even with the flag, --purge alone must never mean "purge everything"
        assert!(matches!(parse_app_rm(&[]), AppRmArgs::MissingName));
        assert!(matches!(
            parse_app_rm(&[os("--purge")]),
            AppRmArgs::MissingName
        ));
        // unknown option and a second positional are distinct errors
        assert!(matches!(
            parse_app_rm(&[os("--nope"), os("claude")]),
            AppRmArgs::UnknownOption("--nope")
        ));
        assert!(matches!(
            parse_app_rm(&[os("claude"), os("codex")]),
            AppRmArgs::Extra("codex")
        ));
    }

    #[test]
    fn describe_home_locations_names_each_scope() {
        let app = |global: Option<u64>, homes: usize| sandbox::InstalledApp {
            name: "x".to_string(),
            global_bytes: global,
            project_homes: homes,
            project_bytes: 0,
        };
        assert_eq!(describe_home_locations(&app(Some(1), 0)), "global");
        assert_eq!(describe_home_locations(&app(None, 1)), "1 project home");
        assert_eq!(describe_home_locations(&app(None, 3)), "3 project homes");
        assert_eq!(
            describe_home_locations(&app(Some(1), 2)),
            "global + 2 project homes"
        );
    }

    #[test]
    fn classify_probe_exit_maps_status_to_outcome() {
        assert_eq!(classify_probe_exit(0), Userns::Ok);
        assert_eq!(classify_probe_exit(2), Userns::CapStripped);
        assert_eq!(classify_probe_exit(1), Userns::Unsupported);
        assert_eq!(classify_probe_exit(42), Userns::Unsupported);
    }

    #[test]
    fn local_save_gate_blocks_only_an_existing_untrusted_config() {
        use trust::TrustState::{Changed, Trusted, Untrusted};
        // absent config → allowed (a `--local` save bootstraps it, then trusts it)
        assert!(local_save_permitted(false, Untrusted));
        // already-trusted config → allowed (ops's append is the sole delta)
        assert!(local_save_permitted(true, Trusted));
        // existing untrusted/changed config → refused (never silently bless it)
        assert!(!local_save_permitted(true, Untrusted));
        assert!(!local_save_permitted(true, Changed));
    }

    #[test]
    fn is_security_key_treats_only_the_env_table_as_free() {
        // the free `env` table — baseline and per-app — is not gated
        assert!(!is_security_key("env.FOO"));
        assert!(!is_security_key("env"));
        assert!(!is_security_key("app.claude.env.FOO"));
        // everything else is a security field, including an app's own security overlay
        assert!(is_security_key("binds"));
        assert!(is_security_key("network"));
        assert!(is_security_key("app.claude.network"));
        assert!(is_security_key("app.claude.cmd"));
        // a bare app table (no field) is gated too
        assert!(is_security_key("app.claude"));
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
        let allowed = render_net_decision(
            "https://x/y",
            &allowlist::Decision::DeniedDefault,
            false,
            &p,
        );
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
        let denied = render_net_decision(
            "https://x/y",
            &allowlist::Decision::DeniedDefault,
            false,
            &p,
        );
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
    fn net_decision_tags_a_built_in_allow_only_when_asked() {
        // The built-in flag controls one phrase on the ALLOWED rule line, in both directions, so a
        // user-rule pass and a built-in-only pass read differently.
        let p = style::Palette::plain();
        let rule = allowlist::classify("cache.nixos.org").unwrap();
        let d = allowlist::Decision::AllowedBy(&rule);
        let tagged = render_net_decision("https://cache.nixos.org/x", &d, true, &p);
        assert!(
            tagged.contains("ALLOWED") && tagged.contains("(built-in)"),
            "a built-in allow must be named:\n{tagged}"
        );
        let plain = render_net_decision("https://cache.nixos.org/x", &d, false, &p);
        assert!(
            plain.contains("ALLOWED") && !plain.contains("built-in"),
            "a user-rule allow must not claim the built-in source:\n{plain}"
        );
    }

    #[test]
    fn resolution_layers_render_marks_presence_and_stays_plain_uncolored() {
        use config::manage::Layer;
        let tmp = crate::testutil::TmpDir::new();
        let present = tmp.path().join("here.toml");
        std::fs::write(&present, "x = 1\n").unwrap();
        let absent = tmp.path().join("gone.toml");
        let layers = vec![
            Layer {
                label: "global",
                path: Some(absent.clone()),
            },
            Layer {
                label: "project",
                path: Some(present.clone()),
            },
        ];
        let plain = render_resolution_layers(&layers, &style::Palette::plain());
        assert!(plain.contains("resolution order"), "header:\n{plain}");
        assert!(
            plain.contains(&format!("{}  (absent)", absent.display())),
            "an absent layer must be marked absent:\n{plain}"
        );
        assert!(
            plain.contains(&format!("{}  (present)", present.display())),
            "a present layer must be marked present:\n{plain}"
        );
        // The colored path wraps the marker in its hue and resets it — pad-then-color keeps the
        // path column aligned, which only ever shows here.
        let c = style::Palette::colored();
        let colored = render_resolution_layers(&layers, &c);
        assert!(
            colored.contains(&format!("{}(present){}", c.ok, c.reset)),
            "a present marker must be wrapped in the ok span and reset:\n{colored}"
        );
    }

    #[test]
    fn resolution_layers_render_handles_a_missing_config_directory() {
        // The global layer can have no path (no $XDG_CONFIG_HOME/$HOME) — it must not error the
        // listing, just say so.
        use config::manage::Layer;
        let layers = vec![Layer {
            label: "global",
            path: None,
        }];
        let plain = render_resolution_layers(&layers, &style::Palette::plain());
        assert!(
            plain.contains("global") && plain.contains("(no config directory)"),
            "a pathless global layer must read as no config directory:\n{plain}"
        );
    }

    #[test]
    fn net_rules_render_tags_each_rule_by_source_and_kind() {
        use config::view::{NetRuleKind, NetRuleView, RuleSourceView};
        let p = style::Palette::plain();
        let mk = |kind, source, rule: &str| NetRuleView {
            kind,
            source,
            rule: rule.into(),
            group: None,
        };
        let rules = [
            mk(NetRuleKind::Allow, RuleSourceView::Config, "github.com"),
            mk(NetRuleKind::Deny, RuleSourceView::Config, "evil.com"),
            mk(
                NetRuleKind::Allow,
                RuleSourceView::Builtin,
                "cache.nixos.org",
            ),
            // A live `--session`-answered rule is tagged `session`, not `manual`.
            mk(NetRuleKind::Deny, RuleSourceView::Manual, "adhoc.test"),
        ];
        let refs: Vec<&NetRuleView> = rules.iter().collect();

        // deny mode: header frames it as an allowlist; each rule carries its kind + source.
        let out = render_net_rules("deny", "", &refs, refs.len(), &p);
        assert!(out.contains("network: deny"), "{out}");
        assert!(out.contains("allow github.com  (config)"), "{out}");
        assert!(out.contains("deny  evil.com  (config)"), "{out}");
        assert!(out.contains("allow cache.nixos.org  (builtin)"), "{out}");
        assert!(out.contains("deny  adhoc.test  (session)"), "{out}");

        // Colored: `allow` carries the green span, `deny` the red one.
        let c = render_net_rules("deny", "", &refs, refs.len(), &style::Palette::colored());
        assert!(c.contains("\x1b[32mallow\x1b[0m"), "allow is green: {c:?}");
        assert!(c.contains("\x1b[1;31mdeny\x1b[0m"), "deny is red: {c:?}");

        // allow mode frames it as a denylist.
        assert!(render_net_rules("allow", "", &refs, refs.len(), &p).contains("network: allow"));

        // A `--app` scope labels the header exactly as `ops test net --app` does, on every posture.
        assert!(
            render_net_rules("deny", " (app demo)", &refs, refs.len(), &p)
                .contains("network (app demo): deny"),
            "the app scope must label the header"
        );
        assert!(
            render_net_rules("shared", " (app demo)", &[], 0, &p).contains("network (app demo):"),
            "the app scope must label a non-filtering posture too"
        );

        // shared/none carry no rules, with an explanatory one-liner (no rule list).
        assert!(render_net_rules("shared", "", &[], 0, &p).contains("no egress rules"));
        assert!(render_net_rules("none", "", &[], 0, &p).contains("no egress rules"));

        // An empty result distinguishes "nothing declared" from "the filter matched nothing".
        assert!(render_net_rules("deny", "", &[], 0, &p).contains("no rules declared"));
        assert!(render_net_rules("deny", "", &[], 3, &p).contains("no rules match the filter"));
    }

    #[test]
    fn render_net_rules_annotates_only_an_expanded_group_rule() {
        use config::view::{NetRuleKind, NetRuleView, RuleSourceView};
        let p = style::Palette::plain();

        // A collapsed group row — the rule text is already `@mcp`, so the origin note would just
        // repeat it and is omitted.
        let collapsed = NetRuleView {
            kind: NetRuleKind::Allow,
            source: RuleSourceView::Config,
            rule: "@mcp".into(),
            group: Some("mcp".into()),
        };
        let out = render_net_rules("deny", "", &[&collapsed], 1, &p);
        assert!(out.contains("allow @mcp  (config)"), "{out}");
        assert!(
            !out.contains("@mcp, @mcp"),
            "no redundant annotation:\n{out}"
        );

        // An expanded group row — the rule is the host, so the source tag notes its `@mcp` origin.
        let expanded = NetRuleView {
            kind: NetRuleKind::Allow,
            source: RuleSourceView::Config,
            rule: "{*} https://a.example.com".into(),
            group: Some("mcp".into()),
        };
        let out = render_net_rules("deny", "", &[&expanded], 1, &p);
        assert!(
            out.contains("(config, @mcp)"),
            "an expanded group rule must note its origin:\n{out}"
        );
    }

    #[test]
    fn net_group_entry_issue_flags_malformed_and_nested_entries() {
        // A well-formed entry of any kind is fine.
        assert!(net_group_entry_issue("github.com:443").is_none());
        assert!(net_group_entry_issue("{*} api.example.com:443").is_none());
        assert!(net_group_entry_issue("re:^https://x/").is_none());
        // A nested reference is ignored (a group is flat) — reported so a typo is visible.
        let nested = net_group_entry_issue("@other").expect("a nested ref is flagged");
        assert!(nested.contains("nested group reference"), "{nested}");
        // A malformed entry carries the classifier's reason.
        assert!(net_group_entry_issue("https://*").is_some());
    }

    #[test]
    fn render_net_groups_lists_and_resolves() {
        use std::collections::BTreeMap;
        let p = style::Palette::plain();
        let groups: BTreeMap<String, Vec<String>> = [
            ("mcp".to_string(), vec!["{*} a.example.com:443".to_string()]),
            (
                "telemetry".to_string(),
                vec!["*.datadoghq.com:*".to_string(), "*.sentry.io:*".to_string()],
            ),
        ]
        .into_iter()
        .collect();

        // List mode (no names): a count header and one line per group with its entry count.
        let list = render_net_groups(&groups, &[], &p);
        assert!(list.contains("egress groups (2)"), "{list}");
        assert!(list.contains("mcp") && list.contains("(1 entry)"), "{list}");
        assert!(
            list.contains("telemetry") && list.contains("(2 entries)"),
            "{list}"
        );

        // Resolve mode (a name): a `@name` block listing the authored entries verbatim.
        let resolved = render_net_groups(&groups, &["mcp".to_string()], &p);
        assert!(resolved.contains("@mcp (1 entry)"), "{resolved}");
        assert!(resolved.contains("{*} a.example.com:443"), "{resolved}");
        // Only the named group is shown, not the whole set.
        assert!(!resolved.contains("telemetry"), "{resolved}");

        // Empty set: an explicit "none defined" line, not a blank output.
        assert!(render_net_groups(&BTreeMap::new(), &[], &p).contains("none defined"));
    }

    #[test]
    fn render_pending_groups_requests_under_a_session_header() {
        use sandbox::control::{PendingRow, SessionPending};
        let p = style::Palette::plain();

        // Empty → the "none" line with the how-it-arrives hint.
        assert!(render_pending(&[], &[], None, &p).contains("none"));
        // An empty listing under an `--app` filter names the app (not "nothing anywhere").
        let scoped = render_pending(&[], &[], Some("claude-code"), &p);
        assert!(
            scoped.contains("none for app `claude-code`"),
            "the empty filtered listing must name the app:\n{scoped}"
        );

        let row = |seq, host: &str, path: &str, waiting| PendingRow {
            seq,
            host: host.into(),
            port: 443,
            path: path.into(),
            waiting_secs: waiting,
        };
        let sessions = [
            SessionPending {
                pid: 12345,
                rows: vec![
                    row(1, "api.example.com", "/v1/x", 12),
                    // A retry of the SAME destination: it must collapse onto the lowest-seq line as
                    // `×2` with the *largest* wait, not show as its own row.
                    row(4, "api.example.com", "/v1/x", 5),
                ],
            },
            SessionPending {
                pid: 67890,
                rows: vec![row(1, "files.example.org", "/dl", 3)],
            },
        ];
        // Only the first session is in the registry context, so the two render differently.
        let context = vec![(
            12345u32,
            std::path::PathBuf::from("/home/u/proj"),
            "app:demo".to_string(),
        )];

        let out = render_pending(&sessions, &context, None, &p);
        // The collapsed destination: the lowest-seq id, the target, `×2`, and the largest wait.
        assert!(
            out.contains("12345.1")
                && out.contains("api.example.com:443/v1/x")
                && out.contains("×2, waiting 12s"),
            "{out}"
        );
        // The retry collapsed — its higher seq is not a line of its own.
        assert!(!out.contains("12345.4"), "{out}");
        // A lone request carries no `×N` prefix.
        assert!(
            out.contains("67890.1")
                && out.contains("files.example.org:443/dl")
                && out.contains("(waiting 3s)"),
            "{out}"
        );
        // The registered session shows its label + project; the other is flagged — so two sessions
        // are told apart (the literal multi-session ask).
        assert!(
            out.contains("session 12345 [app:demo] /home/u/proj"),
            "{out}"
        );
        assert!(out.contains("session 67890 (unregistered)"), "{out}");
        assert!(out.contains("ops net pending allow <id>"), "{out}");
        // The footer also advertises the bulk drain.
        assert!(out.contains("ops net pending allow|deny --all"), "{out}");
    }

    #[test]
    fn parse_watch_args_defaults_and_overrides() {
        let osv = |xs: &[&str]| xs.iter().map(OsString::from).collect::<Vec<_>>();

        // No flags → the 2s default, no app scope.
        let d = parse_watch_args(&[]).expect("bare watch parses");
        assert_eq!(d.interval, Duration::from_secs(2));
        assert!(d.app.is_none());

        // `-i` / `--interval` set the refresh; `-a` / `--app` set the scope; both spellings work.
        let a = parse_watch_args(&osv(&["-i", "5", "-a", "claude-code"])).unwrap();
        assert_eq!(a.interval, Duration::from_secs(5));
        assert_eq!(a.app.as_deref(), Some("claude-code"));
        let b = parse_watch_args(&osv(&["--interval", "10", "--app", "codex"])).unwrap();
        assert_eq!(b.interval, Duration::from_secs(10));
        assert_eq!(b.app.as_deref(), Some("codex"));
    }

    #[test]
    fn parse_watch_args_rejects_bad_input() {
        let osv = |xs: &[&str]| xs.iter().map(OsString::from).collect::<Vec<_>>();

        // A zero interval would busy-loop — refused, not silently clamped.
        assert!(parse_watch_args(&osv(&["-i", "0"])).is_err());
        // A non-numeric interval is an error naming the offending value.
        assert!(parse_watch_args(&osv(&["-i", "soon"]))
            .unwrap_err()
            .contains("soon"));
        // A flag missing its value is an error, not a panic.
        assert!(parse_watch_args(&osv(&["-i"])).is_err());
        assert!(parse_watch_args(&osv(&["--app"])).is_err());
        // An unknown flag (e.g. the contradictory `--json`) is refused with a usage hint.
        assert!(parse_watch_args(&osv(&["--json"])).is_err());
        assert!(parse_watch_args(&osv(&["bogus"])).is_err());
    }

    // ── ops net live ───────────────────────────────────────────────────────────────────────────

    #[test]
    fn parse_live_args_defaults_and_overrides() {
        let osv = |xs: &[&str]| xs.iter().map(OsString::from).collect::<Vec<_>>();

        // No flags → the 1s default, no app scope, human output.
        let d = parse_live_args(&[]).expect("bare live parses");
        assert_eq!(d.interval, Duration::from_secs(1));
        assert!(d.app.is_none());
        assert!(!d.json);

        // Every flag, both spellings.
        let a = parse_live_args(&osv(&["-i", "3", "-a", "claude", "--json"])).unwrap();
        assert_eq!(a.interval, Duration::from_secs(3));
        assert_eq!(a.app.as_deref(), Some("claude"));
        assert!(a.json);
        let b = parse_live_args(&osv(&["--interval", "5", "--app", "codex"])).unwrap();
        assert_eq!(b.interval, Duration::from_secs(5));
        assert_eq!(b.app.as_deref(), Some("codex"));
        assert!(!b.json);
    }

    #[test]
    fn parse_live_args_rejects_bad_input() {
        let osv = |xs: &[&str]| xs.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(
            parse_live_args(&osv(&["-i", "0"])).is_err(),
            "zero interval busy-loops"
        );
        assert!(parse_live_args(&osv(&["-i", "soon"]))
            .unwrap_err()
            .contains("soon"));
        assert!(
            parse_live_args(&osv(&["-i"])).is_err(),
            "missing interval value"
        );
        assert!(parse_live_args(&osv(&["-a"])).is_err(), "missing app value");
        assert!(parse_live_args(&osv(&["--nope"])).is_err(), "unknown flag");
    }

    #[test]
    fn format_flow_age_is_compact() {
        assert_eq!(format_flow_age(5), "5s");
        assert_eq!(format_flow_age(59), "59s");
        assert_eq!(format_flow_age(64), "1m04s");
        assert_eq!(format_flow_age(3661), "1h01m");
    }

    #[test]
    fn render_live_groups_open_flows_by_session() {
        let pal = style::Palette::plain();
        let now_ms = 10_000u128;
        let sessions = vec![sandbox::control::SessionFlows {
            pid: 4242,
            flows: vec![
                sandbox::control::FlowSnapshot {
                    host: "api.test".into(),
                    port: 443,
                    proto: sandbox::control::Proto::Https,
                    start_epoch_ms: 7_000,
                    up: 1024,
                    down: 4096,
                },
                sandbox::control::FlowSnapshot {
                    host: "db.test".into(),
                    port: 5432,
                    proto: sandbox::control::Proto::Tcp,
                    start_epoch_ms: 4_000,
                    up: 500,
                    down: 500,
                },
            ],
        }];
        let ctx = vec![(
            4242u32,
            PathBuf::from("/home/u/proj"),
            "app:claude".to_string(),
        )];
        let out = render_live(&sessions, &ctx, None, now_ms, &pal);
        assert!(out.contains("open egress flows:"), "header: {out}");
        assert!(
            out.contains("session 4242 [app:claude] /home/u/proj"),
            "session header: {out}"
        );
        assert!(out.contains("api.test:443"), "flow host:port shown: {out}");
        assert!(
            out.contains("https") && out.contains("tcp"),
            "protos shown: {out}"
        );
        assert!(out.contains("3s"), "age = (10000-7000)/1000 = 3s: {out}");
        assert!(
            out.contains('↑') && out.contains('↓'),
            "byte columns shown: {out}"
        );

        // An empty listing names what populates it, and an app filter names the app.
        let empty = render_live(&[], &[], None, now_ms, &pal);
        assert!(empty.contains("no egress tunnel is open"), "empty: {empty}");
        let empty_app = render_live(&[], &[], Some("claude"), now_ms, &pal);
        assert!(
            empty_app.contains("app `claude`"),
            "app-scoped empty: {empty_app}"
        );
    }

    // ── ops net logs ───────────────────────────────────────────────────────────────────────────

    fn log_event(
        seq: u64,
        host: &str,
        method: Option<&str>,
        path: Option<&str>,
        verdict: sandbox::control::LogVerdict,
        reason: &str,
    ) -> sandbox::control::LogEvent {
        sandbox::control::LogEvent {
            seq,
            at_epoch_ms: 1_000_000,
            host: host.into(),
            port: 443,
            method: method.map(str::to_string),
            path: path.map(str::to_string),
            verdict,
            reason: reason.into(),
            proto: sandbox::control::Proto::Https,
            muted: false,
            status: None,
            amend_seq: None,
        }
    }

    #[test]
    fn parse_log_args_reads_every_flag_and_rejects_bad_input() {
        use sandbox::control::LogVerdict;
        let osv = |xs: &[&str]| xs.iter().map(OsString::from).collect::<Vec<_>>();

        let v = parse_log_args(&osv(&[
            "--app",
            "claude-code",
            "--host",
            "api.test",
            "--verdict",
            "error",
            "-n",
            "5",
            "--with-query",
            "--json",
        ]))
        .unwrap();
        assert_eq!(v.app.as_deref(), Some("claude-code"));
        assert_eq!(v.host.as_deref(), Some("api.test"));
        assert_eq!(v.verdict, Some(LogVerdict::Error));
        assert_eq!(v.limit, Some(5));
        assert!(v.with_query && v.json);
        assert!(!v.follow, "follow is off unless asked");
        assert!(!v.with_status, "status is off unless asked");
        assert!(
            parse_log_args(&osv(&["--with-status"]))
                .unwrap()
                .with_status,
            "--with-status turns the status column on"
        );

        // `--follow`/`-f` with an explicit interval; the default interval is 1s.
        let f = parse_log_args(&osv(&["--follow", "--interval", "3"])).unwrap();
        assert!(f.follow && f.interval_secs == 3);
        assert!(parse_log_args(&osv(&["-f"])).unwrap().follow);
        assert_eq!(parse_log_args(&osv(&["-f"])).unwrap().interval_secs, 1);
        // A zero or non-numeric interval is refused (a zero would busy-poll).
        assert!(parse_log_args(&osv(&["-i", "0"])).is_err());
        assert!(parse_log_args(&osv(&["-i", "soon"]))
            .unwrap_err()
            .contains("soon"));
        assert!(parse_log_args(&osv(&["-i"])).is_err());

        // Every verdict token parses through the flag (in particular `error`, the log-only one).
        for (tok, want) in [
            ("allow", LogVerdict::Allow),
            ("deny", LogVerdict::Deny),
            ("blocked", LogVerdict::Blocked),
            ("error", LogVerdict::Error),
        ] {
            assert_eq!(
                parse_log_args(&osv(&["--verdict", tok])).unwrap().verdict,
                Some(want)
            );
        }

        // Rejects: an unknown verdict (naming it), a non-numeric count, a missing value, a bad flag.
        assert!(parse_log_args(&osv(&["--verdict", "nope"]))
            .unwrap_err()
            .contains("nope"));
        assert!(parse_log_args(&osv(&["-n", "lots"]))
            .unwrap_err()
            .contains("lots"));
        assert!(parse_log_args(&osv(&["--host"])).is_err());
        assert!(parse_log_args(&osv(&["--verdict"])).is_err());
        assert!(parse_log_args(&osv(&["-n"])).is_err());
        assert!(parse_log_args(&osv(&["--nonsense"])).is_err());
    }

    #[test]
    fn filtered_log_events_applies_host_verdict_and_limit() {
        use sandbox::control::LogVerdict::*;
        let events = vec![
            log_event(1, "a.test", Some("GET"), Some("/1"), Allow, "allowed"),
            log_event(2, "b.test", Some("GET"), Some("/2"), Deny, "denied-default"),
            log_event(
                3,
                "a.test",
                Some("POST"),
                Some("/3"),
                Blocked,
                "ssrf-blocked",
            ),
            log_event(4, "a.test", Some("GET"), Some("/4"), Error, "dns-failure"),
        ];
        let view = |host: Option<&str>, verdict, limit| LogView {
            host: host.map(str::to_string),
            verdict,
            limit,
            ..LogView::default()
        };

        // Host filter keeps only exact matches.
        let by_host = filtered_log_events(&events, &view(Some("a.test"), None, None));
        assert_eq!(by_host.iter().map(|e| e.seq).collect::<Vec<_>>(), [1, 3, 4]);
        // Verdict filter, including the log-only `error`.
        let errs = filtered_log_events(&events, &view(None, Some(Error), None));
        assert_eq!(errs.iter().map(|e| e.seq).collect::<Vec<_>>(), [4]);
        // `-n` keeps the most recent N (the ring is oldest-first).
        let last2 = filtered_log_events(&events, &view(None, None, Some(2)));
        assert_eq!(last2.iter().map(|e| e.seq).collect::<Vec<_>>(), [3, 4]);
        // Filters compose: host a.test, then the last 1.
        let combo = filtered_log_events(&events, &view(Some("a.test"), None, Some(1)));
        assert_eq!(combo.iter().map(|e| e.seq).collect::<Vec<_>>(), [4]);
    }

    #[test]
    fn display_log_path_drops_the_query_unless_asked() {
        assert_eq!(display_log_path("/v1/x?token=abc", false), "/v1/x");
        assert_eq!(display_log_path("/v1/x?token=abc", true), "/v1/x?token=abc");
        assert_eq!(display_log_path("/v1/x", false), "/v1/x");
    }

    #[test]
    fn status_shows_only_under_with_status_in_both_render_and_json() {
        use sandbox::control::LogVerdict::*;
        let p = style::Palette::plain();

        // A completed L7 allow carrying a 200, and an L4/error event carrying none.
        let mut ok = log_event(1, "api.test", Some("GET"), Some("/p"), Allow, "allowed");
        ok.status = Some(200);
        let raw = log_event(2, "db.test", None, None, Allow, "allowed"); // status stays None

        let on = LogView {
            with_status: true,
            ..LogView::default()
        };
        let off = LogView::default();

        // Human render: the code appears only under `--with-status`; a status-less event shows `-`.
        assert!(!render_log_line(&ok, 4242, &off, &p).contains("200"));
        let line = render_log_line(&ok, 4242, &on, &p);
        assert!(
            line.contains("200"),
            "the code shows under --with-status: {line}"
        );
        // The session id leads the line (before the time).
        assert!(
            line.trim_start().starts_with("4242"),
            "the line leads with the session id: {line}"
        );
        let bare = render_log_line(&raw, 4242, &on, &p);
        assert!(
            bare.trim_end().ends_with('-'),
            "a status-less event shows `-` under --with-status: {bare}"
        );

        // JSON: the `status` key is present only under `--with-status` (a number, or null).
        let j_off = log_event_json(&ok, 7, None, None, &off);
        assert!(j_off.get("status").is_none(), "no status key by default");
        let j_on = log_event_json(&ok, 7, None, None, &on);
        assert_eq!(j_on["status"], serde_json::json!(200));
        let j_raw = log_event_json(&raw, 7, None, None, &on);
        assert_eq!(
            j_raw["status"],
            serde_json::Value::Null,
            "null when none captured"
        );
    }

    #[test]
    fn the_proto_column_names_the_transport_in_render_and_json() {
        use sandbox::control::LogVerdict::*;
        use sandbox::control::Proto;
        let p = style::Palette::plain();
        let view = LogView::default();

        // Each transport surfaces its own token in the human line AND the JSON `proto` field — the
        // port alone would not tell them apart (a `tcp://` splice can ride 443).
        let mut https = log_event(
            1,
            "claude.ai",
            Some("WS"),
            Some("/sub"),
            Deny,
            "denied-method",
        );
        https.proto = Proto::Https;
        let mut http = log_event(
            2,
            "clients2.google.com",
            Some("GET"),
            Some("/t"),
            Deny,
            "denied-default",
        );
        http.proto = Proto::Http;
        let mut tcp = log_event(3, "db.internal", None, None, Allow, "allowed");
        tcp.proto = Proto::Tcp;

        for (ev, tok) in [(&https, "https"), (&http, "http"), (&tcp, "tcp")] {
            let line = render_log_line(ev, 42, &view, &p);
            assert!(
                line.contains(tok),
                "the {tok} transport shows in the line: {line}"
            );
            assert_eq!(
                log_event_json(ev, 7, None, None, &view)["proto"],
                serde_json::json!(tok),
                "the JSON proto field names the {tok} transport"
            );
        }

        // A request refused before its transport was known renders and serializes as `-`.
        let mut other = log_event(4, "", None, None, Blocked, "bad-request");
        other.proto = Proto::Other;
        assert_eq!(
            log_event_json(&other, 7, None, None, &view)["proto"],
            serde_json::json!("-")
        );
    }

    #[test]
    fn a_websocket_event_is_flagged_ws_even_without_with_status() {
        use sandbox::control::LogVerdict::Allow;
        let p = style::Palette::plain();
        // A WebSocket carries a 101 (set only by the upgrade relay); a normal request never does.
        let mut ws = log_event(1, "chat.test", Some("GET"), Some("/rt"), Allow, "allowed");
        ws.status = Some(101);
        let normal = {
            let mut e = log_event(2, "api.test", Some("GET"), Some("/p"), Allow, "allowed");
            e.status = Some(200);
            e
        };
        let off = LogView::default();
        // The `ws` marker shows even without `--with-status`, and only for a 101.
        assert!(
            render_log_line(&ws, 7, &off, &p).contains("ws"),
            "a 101 event is flagged ws in the default view"
        );
        assert!(
            !render_log_line(&normal, 7, &off, &p).contains(" ws"),
            "a normal request is not flagged ws"
        );
        // Under --with-status the explicit 101 code is still shown alongside the ws marker.
        let on = LogView {
            with_status: true,
            ..LogView::default()
        };
        let line = render_log_line(&ws, 7, &on, &p);
        assert!(
            line.contains("ws") && line.contains("101"),
            "with --with-status a WebSocket shows both `ws` and `101`: {line}"
        );
    }

    #[test]
    fn format_log_time_renders_local_hh_mm_ss() {
        // Shape is always HH:MM:SS with each field two digits and in range — regardless of the host
        // timezone (so the test is deterministic on any machine).
        let t = format_log_time(1_700_000_000_123);
        let parts: Vec<&str> = t.split(':').collect();
        assert_eq!(parts.len(), 3, "HH:MM:SS: {t}");
        assert!(
            parts
                .iter()
                .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_digit())),
            "two-digit fields: {t}"
        );
        let (h, m, s): (u32, u32, u32) = (
            parts[0].parse().unwrap(),
            parts[1].parse().unwrap(),
            parts[2].parse().unwrap(),
        );
        assert!(h < 24 && m < 60 && s < 60, "each field in range: {t}");
        // Seconds are timezone-independent (every real UTC offset is a whole number of minutes), so
        // this is exact without pinning `TZ`: 1_700_000_000 mod 60 == 20, and epoch 0 is ...:00.
        assert_eq!(s, 20, "the seconds field is exact across zones: {t}");
        assert!(format_log_time(0).ends_with(":00"), "epoch 0 is HH:MM:00");
    }

    #[test]
    fn render_logs_groups_events_by_session_with_verdict_and_reason() {
        use sandbox::control::{LogVerdict::*, SessionLog};
        let p = style::Palette::plain();

        // Empty → a live-only note; under `--app`, it names the app.
        assert!(render_logs(&[], &[], &LogView::default(), &p, true).contains("nothing to show"));
        let scoped = render_logs(
            &[],
            &[],
            &LogView {
                app: Some("claude-code".into()),
                ..LogView::default()
            },
            &p,
            true,
        );
        assert!(scoped.contains("for app `claude-code`"), "{scoped}");

        let sessions = [SessionLog {
            pid: 4242,
            snapshot: sandbox::control::LogSnapshot {
                events: vec![
                    log_event(
                        1,
                        "api.test",
                        Some("POST"),
                        Some("/v1/m?k=sec"),
                        Allow,
                        "allowed",
                    ),
                    log_event(
                        2,
                        "evil.test",
                        Some("GET"),
                        Some("/x"),
                        Deny,
                        "denied-default",
                    ),
                    log_event(
                        3,
                        "api.test",
                        Some("GET"),
                        Some("/dl"),
                        Error,
                        "dns-failure",
                    ),
                ],
                dropped: 0,
                head: 3,
                amend_head: 0,
            },
        }];
        let context = vec![(
            4242u32,
            std::path::PathBuf::from("/home/u/proj"),
            "app:claude-code".to_string(),
        )];

        let out = render_logs(&sessions, &context, &LogView::default(), &p, true);
        // The session header from the registry context.
        assert!(
            out.contains("session 4242 [app:claude-code] /home/u/proj"),
            "{out}"
        );
        // Each event line leads with the session id (before the time) — proven by the id and the host
        // landing on one line, not just the header.
        assert!(
            out.lines().any(|l| l.contains("4242")
                && l.contains("api.test:443")
                && l.contains("POST /v1/m")),
            "the event line leads with the session id: {out}"
        );
        // …and carries the event's wall-clock time as local HH:MM:SS (the events' 1_000_000 ms stamp).
        assert!(
            out.contains(&format_log_time(1_000_000)),
            "the line shows the local time: {out}"
        );
        assert!(
            !out.contains("k=sec"),
            "the query must be dropped by default: {out}"
        );
        assert!(
            !out.contains("(allowed)"),
            "an allow line omits the redundant reason: {out}"
        );
        // A deny line shows the reason category.
        assert!(
            out.contains("evil.test:443") && out.contains("(denied-default)"),
            "{out}"
        );
        // An error line (allowed-but-failed) shows its reason too.
        assert!(out.contains("(dns-failure)"), "{out}");
        // The live-only footer.
        assert!(out.contains("nothing is kept after it exits"), "{out}");

        // `--with-query` keeps the (already-redacted) query.
        let wq = render_logs(
            &sessions,
            &context,
            &LogView {
                with_query: true,
                ..LogView::default()
            },
            &p,
            true,
        );
        assert!(
            wq.contains("/v1/m?k=sec"),
            "--with-query keeps the query: {wq}"
        );
    }

    #[test]
    fn render_logs_surfaces_ring_eviction_rather_than_truncating_silently() {
        use sandbox::control::{LogVerdict::*, SessionLog};
        let p = style::Palette::plain();

        // A session whose ring already evicted its oldest events: the retained window starts at
        // seq 4001, so 4000 older events fell off. `snapshot_evicted` reports the gap…
        let snapshot = sandbox::control::LogSnapshot {
            events: vec![
                log_event(4001, "api.test", Some("GET"), Some("/a"), Allow, "allowed"),
                log_event(
                    4002,
                    "api.test",
                    Some("GET"),
                    Some("/b"),
                    Deny,
                    "denied-default",
                ),
            ],
            dropped: 0,
            head: 4002,
            amend_head: 0,
        };
        assert_eq!(snapshot_evicted(&snapshot), 4000);
        // …a fresh ring (seqs from 1) reports none.
        let fresh = sandbox::control::LogSnapshot {
            events: vec![log_event(
                1,
                "api.test",
                Some("GET"),
                Some("/a"),
                Allow,
                "allowed",
            )],
            dropped: 0,
            head: 1,
            amend_head: 0,
        };
        assert_eq!(snapshot_evicted(&fresh), 0);

        // The render says so, rather than silently showing the last 1000 as if they were all.
        let sessions = [SessionLog { pid: 7, snapshot }];
        let out = render_logs(&sessions, &[], &LogView::default(), &p, true);
        assert!(
            out.contains("4000 earlier event(s) evicted from the ring"),
            "the ring overflow must be surfaced, not truncated silently:\n{out}"
        );
    }

    #[test]
    fn render_drain_reports_each_session_and_a_total() {
        let p = style::Palette::plain();

        // Empty drain → the "nothing parked" line, no total.
        assert!(
            render_drain("allowed", false, None, &[], &[], &[], &p).contains("no pending requests")
        );
        // An empty drain under an `--app` filter names the app (not "nothing anywhere").
        let scoped = render_drain("allowed", false, Some("claude-code"), &[], &[], &[], &p);
        assert!(
            scoped.contains("for app `claude-code`"),
            "the empty filtered drain must name the app:\n{scoped}"
        );

        // An empty drain whose only sessions are too old to understand `--all` does NOT say "nothing
        // parked" — it names the older sessions and points at relaunching.
        let old = render_drain("allowed", false, None, &[], &[99999u32], &[], &p);
        assert!(
            !old.contains("no pending requests")
                && old.contains("99999")
                && old.contains("older ops")
                && old.contains("relaunch the agent"),
            "an unsupported-only drain must name the older session and the fix, not claim emptiness:\n{old}"
        );

        let answered = vec![
            (
                12345u32,
                vec!["api.example.com".to_string(), "cdn.example.com".to_string()],
            ),
            (67890u32, vec!["files.example.org".to_string()]),
        ];
        // Only the first session is registered, so the two headers render differently.
        let context = vec![(
            12345u32,
            std::path::PathBuf::from("/home/u/proj"),
            "app:demo".to_string(),
        )];

        let out = render_drain("allowed", true, None, &answered, &[], &context, &p);
        // The total counts every answered host across every session.
        assert!(out.contains("allowed 3 parked request(s)"), "{out}");
        // Each session is named (the cross-agent grant made visible), and each host listed.
        assert!(
            out.contains("session 12345 [app:demo] /home/u/proj"),
            "{out}"
        );
        assert!(
            out.contains("api.example.com") && out.contains("cdn.example.com"),
            "{out}"
        );
        assert!(out.contains("session 67890 (unregistered)"), "{out}");
        assert!(out.contains("files.example.org"), "{out}");
        // `--session` adds the remembered-for-each note.
        assert!(out.contains("remembered for each session"), "{out}");

        // Without `--session`, no remembered note; "denied" past tense for a deny drain.
        let out = render_drain("denied", false, None, &answered, &[], &context, &p);
        assert!(out.contains("denied 3 parked request(s)"), "{out}");
        assert!(!out.contains("remembered for each session"), "{out}");

        // Duplication collapse (the regression): a session that retried one destination many times
        // must list that host ONCE with a ×count, not once per request.
        let mut hosts = vec!["ziglang.org".to_string(); 20];
        hosts.push("downloads.claude.ai".to_string());
        let bursty = vec![(285706u32, hosts)];
        let out = render_drain("allowed", false, None, &bursty, &[], &[], &p);
        // Teeth: on the un-folded code this count is 20, so the assert fails without the fix.
        assert_eq!(
            out.matches("ziglang.org").count(),
            1,
            "a repeated host must be listed once, not once per request:\n{out}"
        );
        assert!(
            out.contains("×20"),
            "the collapsed host must carry its occurrence count:\n{out}"
        );
        // The header still counts every request (21), and the singleton host gets no ×1 noise.
        assert!(out.contains("allowed 21 parked request(s)"), "{out}");
        assert!(
            out.contains("downloads.claude.ai") && !out.contains("×1"),
            "a single-request host must not get a ×1 suffix:\n{out}"
        );
    }

    #[test]
    fn collapse_hosts_folds_repeats_in_first_seen_order_and_preserves_the_total() {
        let hosts = vec![
            "a.test".to_string(),
            "b.test".to_string(),
            "a.test".to_string(),
            "a.test".to_string(),
        ];
        let folded = collapse_hosts(&hosts);
        // First-seen order, each host once, with its count.
        assert_eq!(folded, vec![("a.test", 3), ("b.test", 1)]);
        // The counts sum back to the request total — the invariant the drain header relies on.
        assert_eq!(folded.iter().map(|(_, n)| n).sum::<usize>(), hosts.len());
    }

    #[test]
    fn egress_write_target_names_the_file_and_the_target_by_scope() {
        // The single source of truth for both the single-rule and the drain summaries. A `--local`
        // app targets the project `.ops.toml` with an `[app.<name>]` overlay key; an explicit `-c`
        // file targets that path. Both are env-independent (the `--global` app arm resolves the
        // profile path from the config home, so it is covered by the `net pending … --save -g --app`
        // integration test instead). The target string must carry the app itself — a caller adds no
        // separate " under app" suffix.
        use config::manage::Scope;
        let cwd = std::path::Path::new("/some/cwd");

        let (path, key, target) = egress_write_target(&Scope::Local, Some("demo"), cwd).unwrap();
        assert_eq!(path, cwd.join(config::PROJECT_CONFIG));
        assert_eq!(key, Some("demo")); // a project overlay writes `[app.demo.network]`
        assert_eq!(target, "the project config (app `demo`)");

        let (_, key, target) = egress_write_target(&Scope::Local, None, cwd).unwrap();
        assert_eq!(key, None);
        assert_eq!(target, "the project config");

        let explicit = std::path::PathBuf::from("/etc/ops.toml");
        let (path, key, target) =
            egress_write_target(&Scope::File(explicit.clone()), None, cwd).unwrap();
        assert_eq!(path, explicit);
        assert_eq!(key, None);
        assert_eq!(target, "/etc/ops.toml");
    }

    #[test]
    fn resolve_key_target_routes_by_scope_and_app() {
        // The routing behind `config get/set/unset`. Env-independent arms are asserted here; the
        // `--app <name> --global` profile arm resolves the config home, so it is covered by the
        // `config show --app` / profile integration tests instead (same convention as
        // `egress_write_target` above).
        use config::manage::Scope;
        let cwd = std::path::Path::new("/some/cwd");
        let proj = cwd.join(config::PROJECT_CONFIG);

        // No app: the raw key, the scope's file, and gated for a project write.
        let (path, key, gated) =
            resolve_key_target("set", &Scope::Local, None, "network", cwd).unwrap();
        assert_eq!((path, key.as_str(), gated), (proj.clone(), "network", true));

        // An inline app (project scope) addresses `app.<name>.<key>` and stays gated.
        let (path, key, gated) =
            resolve_key_target("set", &Scope::Local, Some("demo"), "network", cwd).unwrap();
        assert_eq!(
            (path, key.as_str(), gated),
            (proj, "app.demo.network", true)
        );

        // A `-c` file with an app: the file itself, the prefixed key, still gated (not trusted by
        // location).
        let explicit = std::path::PathBuf::from("/etc/ops.toml");
        let (path, key, gated) = resolve_key_target(
            "set",
            &Scope::File(explicit.clone()),
            Some("demo"),
            "cmd",
            cwd,
        )
        .unwrap();
        assert_eq!(
            (path, key.as_str(), gated),
            (explicit, "app.demo.cmd", true)
        );

        // An app name with a `.` cannot be addressed inline (the dotted-key splitter is naive).
        assert!(
            resolve_key_target("set", &Scope::Local, Some("a.b"), "network", cwd).is_err(),
            "a dotted app name is rejected inline"
        );

        // A reserved verb / an invalid charset can never key a profile filename (validated before
        // the config home is even resolved, so this arm stays env-independent).
        assert!(
            resolve_key_target("set", &Scope::Global, Some("import"), "network", cwd).is_err(),
            "a reserved app verb cannot name a global-app profile"
        );
        assert!(
            resolve_key_target("set", &Scope::Global, Some("bad/name"), "network", cwd).is_err(),
            "an invalid app name cannot name a global-app profile"
        );
    }

    #[test]
    fn parse_app_launch_splits_the_name_flags_and_passthrough_args() {
        use std::ffi::OsString;
        let v = |xs: &[&str]| -> Vec<OsString> { xs.iter().map(OsString::from).collect() };

        // A bare name: no detach, no passthrough, no override, no net-learn.
        let a = parse_app_launch(&v(&["claude"])).unwrap();
        assert_eq!((a.name.as_str(), a.detach), ("claude", false));
        assert!(a.tail.is_empty() && a.cli.config.is_empty() && a.cli.env.is_empty());
        assert!(a.net_learn.is_none());

        // `--detach` before the (absent) `--` sets the flag.
        let a = parse_app_launch(&v(&["claude", "--detach"])).unwrap();
        assert_eq!((a.name.as_str(), a.detach), ("claude", true));
        assert!(a.tail.is_empty());

        // `--` separates ops's args from the passthrough tail, appended verbatim.
        let a = parse_app_launch(&v(&["claude", "--", "-c"])).unwrap();
        assert_eq!((a.name.as_str(), a.detach), ("claude", false));
        assert_eq!(a.tail, v(&["-c"]));

        // A flag before `--` is ops's; the same token after `--` is the program's (passthrough).
        let a = parse_app_launch(&v(&["claude", "--detach", "--", "-c", "--foo"])).unwrap();
        assert_eq!((a.name.as_str(), a.detach), ("claude", true));
        assert_eq!(a.tail, v(&["-c", "--foo"]));
        let a = parse_app_launch(&v(&["claude", "--", "--detach"])).unwrap();
        assert!(
            !a.detach,
            "`--detach` after `--` is the program's, not ops's"
        );
        assert_eq!(a.tail, v(&["--detach"]));

        // A trailing `--` with nothing after it is an empty tail, not an error.
        let a = parse_app_launch(&v(&["claude", "--"])).unwrap();
        assert_eq!(a.name, "claude");
        assert!(a.tail.is_empty());

        // A one-shot override is collected from the head, in any order with the name/`--detach`, and
        // stops at `--` (a later `--config` after `--` is the program's argument, not ops's).
        let a = parse_app_launch(&v(&[
            "--env",
            "FOO=bar",
            "claude",
            "--config",
            "network=\"none\"",
            "--",
            "--config",
            "x",
        ]))
        .unwrap();
        assert_eq!(a.name, "claude");
        assert_eq!(a.cli.config, vec!["network=\"none\"".to_string()]);
        assert_eq!(a.cli.env, vec!["FOO=bar".to_string()]);
        assert_eq!(a.tail, v(&["--config", "x"]));
        // The `--flag=value` inline form is accepted too.
        let a = parse_app_launch(&v(&["claude", "--config=gui=\"wayland\"", "--env=A=1"])).unwrap();
        assert_eq!(a.cli.config, vec!["gui=\"wayland\"".to_string()]);
        assert_eq!(a.cli.env, vec!["A=1".to_string()]);

        // `--net-learn`: bare is `domain` (the default), the local scope, no dry-run.
        let a = parse_app_launch(&v(&["claude", "--net-learn"])).unwrap();
        let nl = a.net_learn.expect("net-learn set");
        assert_eq!(nl.gran, sandbox::Granularity::Domain);
        assert!(matches!(nl.scope, config::manage::Scope::Local) && !nl.dry_run);
        // `=level`, `--dry-run`, and `-g` compose, in any order with the name.
        let a = parse_app_launch(&v(&["--net-learn=path", "claude", "--dry-run", "-g"])).unwrap();
        let nl = a.net_learn.expect("net-learn set");
        assert_eq!(nl.gran, sandbox::Granularity::Path);
        assert!(matches!(nl.scope, config::manage::Scope::Global) && nl.dry_run);
        // A bad granularity, `--net-learn` with `--detach`, and a scope/`--dry-run` without
        // `--net-learn` are each usage errors (never a silently-ignored flag).
        assert!(parse_app_launch(&v(&["claude", "--net-learn=subtree"])).is_err());
        assert!(parse_app_launch(&v(&["claude", "--net-learn", "--detach"])).is_err());
        assert!(parse_app_launch(&v(&["claude", "--dry-run"])).is_err());
        assert!(parse_app_launch(&v(&["claude", "-g"])).is_err());

        // The typed security flags are collected into their own fields, in any order with the name.
        let a = parse_app_launch(&v(&[
            "--net",
            "none",
            "claude",
            "--bind",
            "/data:rw",
            "--forward",
            "1455",
            "--limit",
            "tasks_max=4096",
            "--gui",
            "wayland",
            "--nixpkgs",
            "nixos-23.11",
            "--package",
            "hello=nix:hello",
        ]))
        .unwrap();
        assert_eq!(a.name, "claude");
        assert_eq!(a.cli.net, vec!["none".to_string()]);
        assert_eq!(a.cli.gui, vec!["wayland".to_string()]);
        assert_eq!(a.cli.nixpkgs, vec!["nixos-23.11".to_string()]);
        assert_eq!(a.cli.binds, vec!["/data:rw".to_string()]);
        assert_eq!(a.cli.forward, vec!["1455".to_string()]);
        assert_eq!(a.cli.limits, vec!["tasks_max=4096".to_string()]);
        assert_eq!(a.cli.packages, vec!["hello=nix:hello".to_string()]);

        // The boolean flags are optional-value and must never consume the following token: a bare
        // `--gpu` placed right before the name still leaves `claude` as the name (not swallowed as a
        // value), normalizing to `"true"`; the inline `--dbus=false` form carries its value.
        let a = parse_app_launch(&v(&["--gpu", "claude", "--dbus=false"])).unwrap();
        assert_eq!(a.name, "claude");
        assert_eq!(a.cli.gpu, vec!["true".to_string()]);
        assert_eq!(a.cli.dbus, vec!["false".to_string()]);

        // Errors: a second name, an unknown flag, no name at all, `--` with no name before it, and a
        // value-taking flag with no value.
        assert!(parse_app_launch(&v(&["claude", "extra"])).is_err());
        assert!(parse_app_launch(&v(&["claude", "--unknown"])).is_err());
        assert!(parse_app_launch(&v(&[])).is_err());
        assert!(parse_app_launch(&v(&["--", "-c"])).is_err());
        assert!(parse_app_launch(&v(&["claude", "--config"])).is_err());
        assert!(parse_app_launch(&v(&["claude", "--net"])).is_err());
    }

    #[test]
    fn session_pids_for_app_selects_only_that_apps_live_sessions() {
        use crate::testutil::TmpDir;
        use session::{Kind, Registry, Session, SessionRuntime};

        // Register THIS process (alive, so it survives the registry's liveness pruning) as an
        // `ops app claude-code` session in a throwaway data dir.
        let data = TmpDir::new();
        let me = Session::current(
            std::path::PathBuf::from("/home/u/proj"),
            Kind::Run,
            SessionRuntime::GlobalApp("claude-code".to_string()),
        )
        .expect("read this process's session identity");
        Registry::at(data.path())
            .register(&me)
            .expect("register the session");

        // The filter returns this app's live pid...
        let pids = session_pids_for_app(data.path(), "claude-code");
        assert!(
            pids.contains(&std::process::id()),
            "the app's live session must be selected: {pids:?}"
        );
        // ...and nothing for a different app, so an `--all -a other` drain excludes this session.
        assert!(
            session_pids_for_app(data.path(), "other").is_empty(),
            "a different app must select no session"
        );
    }

    #[test]
    fn session_pids_for_project_selects_only_this_projects_live_sessions() {
        use crate::testutil::TmpDir;
        use session::{Kind, Registry, Session, SessionRuntime};

        let data = TmpDir::new();
        let proj = TmpDir::new(); // real existing dirs to stand in as project roots
        let other = TmpDir::new();

        // Register THIS process (alive) with the project the launch path WOULD record — exactly
        // `project_identity(cwd).1` — so the test drives the real key on BOTH sides. A mismatch
        // between how the record is written and how the filter resolves the cwd would silently select
        // nothing (the make-or-break fact for `--all --save --local`).
        let (_, canonical) =
            sandbox::project_identity(proj.path()).expect("resolve the project root");
        let me = Session::current(canonical, Kind::Run, SessionRuntime::Project)
            .expect("read this process's session identity");
        Registry::at(data.path())
            .register(&me)
            .expect("register the session");

        // Filtering by the same cwd (resolved the same way) selects this session...
        let here = sandbox::project_identity(proj.path()).unwrap().1;
        assert!(
            session_pids_for_project(data.path(), &here).contains(&std::process::id()),
            "this project's live session must be selected"
        );
        // ...and a different project selects nothing (so a local bulk save there drains zero).
        let elsewhere = sandbox::project_identity(other.path()).unwrap().1;
        assert!(
            session_pids_for_project(data.path(), &elsewhere).is_empty(),
            "a different project must select no session"
        );
    }

    #[test]
    fn render_stats_tabulates_hosts_busiest_first() {
        use sandbox::egress_stats::Counts;
        let p = style::Palette::plain();

        // Empty → the project header plus the "nothing recorded yet" line.
        let empty = std::collections::BTreeMap::new();
        let out = render_stats("/home/u/proj", None, &empty, &p);
        assert!(
            out.contains("/home/u/proj") && out.contains("nothing recorded yet"),
            "{out}"
        );

        let mut counts = std::collections::BTreeMap::new();
        counts.insert(
            "quiet.test".to_string(),
            Counts {
                allow: 1,
                deny: 0,
                blocked: 0,
            },
        );
        counts.insert(
            "busy.test".to_string(),
            Counts {
                allow: 40,
                deny: 2,
                blocked: 1,
            },
        );
        let out = render_stats("/home/u/proj", Some("demo"), &counts, &p);
        // The app scope is shown in the header, and the columns are present.
        assert!(out.contains("app demo"), "{out}");
        assert!(
            out.contains("HOST")
                && out.contains("ALLOW")
                && out.contains("DENY")
                && out.contains("BLOCKED"),
            "{out}"
        );
        // Busiest host first: busy.test (total 43) precedes quiet.test (total 1).
        let busy = out.find("busy.test").unwrap();
        let quiet = out.find("quiet.test").unwrap();
        assert!(busy < quiet, "busiest host must sort first:\n{out}");
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
    fn parse_trust_args_honors_show_in_any_position_and_rejects_stray_tokens() {
        let os = |s: &str| OsString::from(s);
        // `--show` after the path must SHOW, not record trust — the security-sensitive default.
        let (show, path) = parse_trust_args(vec![os("./repo/.ops.toml"), os("--show")]).unwrap();
        assert!(show, "trailing --show must be honored");
        assert_eq!(
            path.as_deref(),
            Some(std::ffi::OsStr::new("./repo/.ops.toml"))
        );
        // `--show` first, path after.
        let (show, path) = parse_trust_args(vec![os("--show"), os("p.toml")]).unwrap();
        assert!(show);
        assert_eq!(path.as_deref(), Some(std::ffi::OsStr::new("p.toml")));
        // No args: record the default path.
        assert_eq!(parse_trust_args(vec![]).unwrap(), (false, None));
        // An unknown flag or a second path is rejected (so a typo cannot fall through to a record).
        assert!(parse_trust_args(vec![os("--shwo")]).is_err());
        assert!(parse_trust_args(vec![os("a.toml"), os("b.toml")]).is_err());
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
            binds: vec![],
            bind_layer: Default::default(),
            packages: vec![],
            nixpkgs_global: Some(global.to_string()),
            nixpkgs_project: None,
            mise: None,
            network: config::NetworkPolicy::default(),
            network_origin: Default::default(),
            egress_stats: true,
            gui: config::GuiPolicy::default(),
            gui_origin: Default::default(),
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: Default::default(),
            audio_origin: Default::default(),
            dbus_origin: Default::default(),
            forward: vec![],
            forward_origin: Default::default(),
            limits: Default::default(),
            limits_origin: Default::default(),
            secrets: vec![],
            seccomp: Default::default(),
            seccomp_origin: Default::default(),
            devices: Vec::new(),
            devices_origin: Default::default(),
            declared_secrets: vec![],
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
    fn short_hash_takes_the_base64_body_prefix() {
        assert_eq!(
            short_hash("sha256-jBGtMS5lpJWVXe+KzQgRSho8BcaEzGvONzIbAWled0w="),
            "jBGtMS5l"
        );
        // no prefix and a short value degrade gracefully (no panic, min(8))
        assert_eq!(short_hash("short"), "short");
        assert_eq!(short_hash("sha256-ab"), "ab");
    }

    #[test]
    fn deb_upgrade_summary_distinguishes_the_outcomes() {
        use sandbox::DebUpgrade::*;

        // an empty roll (no deb: packages) says so plainly; an untrusted one names the withheld
        let empty = deb_upgrade_summary(&[], 0, &style::Palette::plain()).join("\n");
        assert!(empty.contains("no deb: packages"));
        let withheld = deb_upgrade_summary(&[], 1, &style::Palette::plain()).join("\n");
        assert!(withheld.contains("1 deb: package(s) withheld (untrusted)"));
        assert!(!withheld.contains("no deb: packages"));

        let h_a = "sha256-jBGtMS5lpJWVXe+KzQgRSho8BcaEzGvONzIbAWled0w=";
        let h_b = "sha256-XH0ykkcZdoyYdI7tQAS55CsvPwv96Tlr2lYF30qltkE=";
        let text = deb_upgrade_summary(
            &[
                Unchanged {
                    url: "https://e/a.deb".into(),
                    hash: h_a.into(),
                },
                Rolled {
                    url: "https://e/b.deb".into(),
                    from: h_a.into(),
                    to: h_b.into(),
                },
                Pinned {
                    url: "https://e/c.deb".into(),
                    hash: h_b.into(),
                },
                Pruned {
                    url: "https://e/old.deb".into(),
                },
                Failed {
                    url: "https://e/d.deb".into(),
                    error: "prefetch unreachable".into(),
                },
            ],
            0,
            &style::Palette::plain(),
        )
        .join("\n");
        assert!(text.contains("deb:https://e/a.deb: jBGtMS5l — unchanged"));
        assert!(text.contains("deb:https://e/b.deb: jBGtMS5l → XH0ykkcZ — rolled forward"));
        assert!(text.contains("deb:https://e/c.deb: XH0ykkcZ — newly pinned"));
        assert!(text.contains("deb:https://e/old.deb: removed from the lock"));
        assert!(text.contains("deb:https://e/d.deb: re-resolve failed — prefetch unreachable"));
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
                writable: false,
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
                default_action: config::view::NetDefaultView::Deny,
                ask_timeout: None,
                ask_notice: None,
                allow: vec!["github.com".into()],
                deny: vec!["evil.com".into()],
                mute: vec![],
                builtin: vec!["cache.nixos.org".into()],
            },
            network_origin: ProvenanceView::Project,
            egress_stats: true,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Default,
            audio_origin: ProvenanceView::Default,
            dbus_origin: ProvenanceView::Default,
            forward: vec![],
            forward_origin: ProvenanceView::Default,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Default,
            devices: vec![],
            devices_origin: ProvenanceView::Default,
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
        // A read-only bind carries no mode marker.
        assert!(
            !out.contains("/data (rw)"),
            "a read-only bind must not be marked:\n{out}"
        );
    }

    #[test]
    fn config_render_marks_a_writable_bind() {
        // The `(rw)` marker: a writable bind is flagged so a host write-through hole is
        // visible in `ops config show`; the marker precedes the provenance tag. A read-only bind
        // (the default, covered above) carries none.
        let mut view = sample_config_view();
        view.binds = vec![config::view::BindView {
            path: "/data".into(),
            writable: true,
            layer: Some(config::view::ProvenanceView::Global),
        }];
        let out = render_config(&view, &style::Palette::plain(), false);
        assert!(
            out.contains("    /data (rw)  (global)"),
            "a writable bind must be marked (rw) before its provenance tag:\n{out}"
        );
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
            out.contains("network: deny  (project)"),
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
                default_action: config::view::NetDefaultView::Deny,
                ask_timeout: None,
                ask_notice: None,
                allow: vec!["api.example.com".into()],
                deny: vec![],
                mute: vec![],
                builtin: vec!["cache.nixos.org".into()],
            },
            network_origin: ProvenanceView::Global,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Inherited,
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Inherited,
            audio_origin: ProvenanceView::Inherited,
            dbus_origin: ProvenanceView::Inherited,
            forward: vec![],
            forward_origin: ProvenanceView::Inherited,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Inherited,
            devices: vec![],
            devices_origin: ProvenanceView::Inherited,
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
        assert!(out.contains("network: deny  (app:global)"), "{out}");
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
            gpu: None,
            audio: None,
            dbus: None,
            forward: vec![],
            seccomp: vec![],
            devices: vec![],
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
            egress_stats: true,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Default,
            audio_origin: ProvenanceView::Default,
            dbus_origin: ProvenanceView::Default,
            forward: vec![],
            forward_origin: ProvenanceView::Default,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Default,
            devices: vec![],
            devices_origin: ProvenanceView::Default,
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
                gpu: None,
                audio: None,
                dbus: None,
                forward: vec![],
                seccomp: vec![],
                devices: vec![],
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
        // `--details`. The expansion includes the built-in set, which the baseline
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
            egress_stats: true,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Default,
            audio_origin: ProvenanceView::Default,
            dbus_origin: ProvenanceView::Default,
            forward: vec![],
            forward_origin: ProvenanceView::Default,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Default,
            devices: vec![],
            devices_origin: ProvenanceView::Default,
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
                    default_action: config::view::NetDefaultView::Deny,
                    ask_timeout: None,
                    ask_notice: None,
                    allow: vec!["api.example.com".into(), "github.com".into()],
                    deny: vec!["github.com/secret".into()],
                    builtin: vec!["cache.nixos.org".into()],
                }),
                gui: None,
                gpu: None,
                audio: None,
                dbus: None,
                forward: vec![],
                seccomp: vec![],
                devices: vec![],
                limits: None,
                secrets: vec![],
                notes: vec![],
            }],
            warnings: vec![],
        };

        // Default: a compact count, both numbers present even at zero deny, no expanded rule.
        let compact = render_config(&view, &style::Palette::plain(), false);
        assert!(
            compact.contains("      network: deny (2 allow, 1 deny)"),
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
            gpu: None,
            audio: None,
            dbus: None,
            forward: vec![],
            seccomp: vec![],
            devices: vec![],
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
            egress_stats: true,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Default,
            audio_origin: ProvenanceView::Default,
            dbus_origin: ProvenanceView::Default,
            forward: vec![],
            forward_origin: ProvenanceView::Default,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Default,
            devices: vec![],
            devices_origin: ProvenanceView::Default,
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
            egress_stats: true,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Default,
            audio_origin: ProvenanceView::Default,
            dbus_origin: ProvenanceView::Default,
            forward: vec![],
            forward_origin: ProvenanceView::Default,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Default,
            devices: vec![],
            devices_origin: ProvenanceView::Default,
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
                gpu: None,
                audio: None,
                dbus: None,
                forward: vec![],
                seccomp: vec![],
                devices: vec![],
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
            egress_stats: true,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Default,
            audio_origin: ProvenanceView::Default,
            dbus_origin: ProvenanceView::Default,
            forward: vec![],
            forward_origin: ProvenanceView::Default,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Default,
            devices: vec![],
            devices_origin: ProvenanceView::Default,
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
                binds: vec![BindView {
                    path: "/data/cache".into(),
                    writable: false,
                    layer: None,
                }],
                packages: vec![],
                network: None,
                gui: None,
                gpu: None,
                audio: None,
                dbus: None,
                forward: vec![],
                seccomp: vec![],
                devices: vec![],
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
            expanded.contains("      binds:") && expanded.contains("        /data/cache"),
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
            egress_stats: true,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Default,
            audio_origin: ProvenanceView::Default,
            dbus_origin: ProvenanceView::Default,
            forward: vec![],
            forward_origin: ProvenanceView::Default,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Default,
            devices: vec![],
            devices_origin: ProvenanceView::Default,
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
                gpu: None,
                audio: None,
                dbus: None,
                forward: vec![],
                seccomp: vec![],
                devices: vec![],
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
