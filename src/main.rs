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
mod pathfind;
mod plugin_store;
mod plugins;
mod sandbox;
mod session;
mod store;
mod stores;
#[cfg(test)]
mod testutil;
mod trust;

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    // `args_os`, not `args`: a command run via `ops run` may carry non-UTF-8
    // arguments, and panicking on them would be wrong.
    let mut args = std::env::args_os().skip(1);
    match args.next().as_deref().and_then(|s| s.to_str()) {
        Some("doctor") => doctor(),
        Some("shell") => sandbox::shell(),
        Some("ps") => list_sessions(),
        Some("trust") => trust_cmd(args.collect()),
        Some("untrust") => untrust_cmd(args.next()),
        Some("config") => config_cmd(),
        Some("upgrade") => upgrade_cmd(args.collect()),
        Some("run") => {
            let mut cmd: Vec<OsString> = args.collect();
            // an optional `--` separates ops's arguments from the command's
            if cmd.first().and_then(|a| a.to_str()) == Some("--") {
                cmd.remove(0);
            }
            sandbox::run(cmd)
        }
        Some("mise") => sandbox::run_mise(args.collect()),
        Some("app") => app_cmd(args.collect()),
        Some("search") => search_cmd(args.collect()),
        Some("test") => test_cmd(args.collect()),
        Some("plugins") => plugins_cmd(args.collect()),
        Some(other) => {
            eprintln!(
                "ops: unknown command '{other}' (known: doctor, shell, run, mise, app, \
                 search, test, plugins, ps, trust, untrust, config, upgrade)"
            );
            ExitCode::from(2)
        }
        None => {
            eprintln!(
                "ops: usage: ops <doctor | shell | run [--] <command> | mise <args> | \
                 app <name> | search <query> | test net <url> | \
                 plugins <list|info|install|rm|store> | \
                 ps | trust [path] | untrust [path] | config | upgrade [all|nix|mise]>"
            );
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
fn doctor() -> ExitCode {
    println!("ops doctor — runtime preflight\n");

    let mut remediation: Vec<&str> = Vec::new();

    // The sandbox engine itself. Hold the path: a present engine is what lets the
    // boundary be proven by a real launch rather than a stand-in.
    let bwrap = pathfind::find_on_path("bwrap");
    match &bwrap {
        Some(p) => println!("  [ ok ] bubblewrap        {}", p.display()),
        None => {
            println!("  [FAIL] bubblewrap        not found on PATH");
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
    report_security_boundary(bwrap.as_deref(), &mut remediation);
    if let Some(v) = read_sysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") {
        println!("         · kernel.apparmor_restrict_unprivileged_userns = {v}");
    }
    if let Some(v) = read_sysctl("/proc/sys/kernel/unprivileged_userns_clone") {
        println!("         · kernel.unprivileged_userns_clone = {v}");
    }
    report_resource_limits();

    // The nix that drives the store. Its absence is load-bearing too — without
    // nix, ops cannot provision a project's tools.
    match store::resolve_nix() {
        Some(nix) => {
            println!("  [ ok ] nix               {}", nix.display());
            if let Some(v) = nix_version(&nix) {
                println!("         · {v}");
            }
        }
        None => {
            println!("  [FAIL] nix               not found on PATH");
            remediation.push("install nix (the store engine ops drives daemonlessly)");
        }
    }

    // git fetches a remote plugin store (`ops plugins store add`). It is not on the launch
    // path — a sandbox runs without it — so its absence is a feature gap reported for
    // context, never a boundary failure that blocks `ops run`.
    match store::resolve_git() {
        Some(git) => println!("  [ ok ] git               {}", git.display()),
        None => println!(
            "  [warn] git               not found on PATH — needed only for `ops plugins store`"
        ),
    }

    // Where the user-owned store lives, and which channel revision it is pinned to.
    // Both are reported read-only: ops creates the store lazily on first use and
    // seeds the channel lock on first launch, so their absence here is informational,
    // not a failure. The channel state is the host-level global lock (doctor has no
    // project context), shown straight from disk.
    match store::Layout::from_env() {
        Some(layout) => {
            let dir = layout.store_dir();
            let state = if dir.is_dir() {
                "present"
            } else {
                "absent — created on first use"
            };
            println!("  [ ok ] store             {} ({state})", dir.display());
            match store::read_global_lock(&layout) {
                Some((source, rev)) => println!(
                    "  [ ok ] channel           {source} @ {} (locked)",
                    short_rev(&rev)
                ),
                None => {
                    println!("  [ ok ] channel           not yet resolved — seeded on first launch")
                }
            }
        }
        None => {
            println!("  [warn] store             unresolved (no $HOME or $XDG_DATA_HOME)");
            println!("  [warn] channel           unresolved (no data directory)");
        }
    }

    println!();
    if remediation.is_empty() {
        println!("ops: prerequisites OK.");
        ExitCode::SUCCESS
    } else {
        eprintln!("ops: missing prerequisite(s) — ops CANNOT run until these are resolved:");
        for hint in remediation {
            eprintln!("       • {hint}");
        }
        ExitCode::FAILURE
    }
}

/// Report best-effort cgroup v2 resource limiting (anti-DoS). Unlike the security
/// boundary, resource limits are hardening: where they cannot be applied the cage
/// still runs, so an unavailable limiter is reported for context and never
/// recorded as a missing prerequisite. The probe launches a real transient scope,
/// so a green line means limiting actually works on this host.
fn report_resource_limits() {
    let report: sandbox::LimitReport = sandbox::resource_limits();
    if report.verified {
        println!(
            "  [ ok ] resource limits   cage capped via a systemd scope ({})",
            report.properties.join(", ")
        );
    } else if let Some(note) = report.note {
        println!("  [warn] resource limits   {note}");
    }
}

/// Report the security boundary. When bubblewrap is present, a real launch
/// decides the green path and the `unshare` stand-in does not run at all. On
/// failure — or when there is no engine to launch — the stand-in classifies the
/// cause so the report blames the right layer and never the wrong one.
fn report_security_boundary(bwrap: Option<&Path>, remediation: &mut Vec<&'static str>) {
    let Some(bwrap) = bwrap else {
        // No engine to launch: the stand-in is the only available signal for the
        // boundary. Report it for context (the missing-engine remediation is
        // already recorded), and still flag a broken namespace as its own fault.
        match probe_userns() {
            Userns::Ok => println!(
                "         · user namespaces: capability-bearing (cannot prove without bubblewrap)"
            ),
            other => classify_namespace_failure(other, remediation),
        }
        return;
    };

    match sandbox::smoke(bwrap) {
        Ok(report) if report.is_hardened() => {
            println!("  [ ok ] sandbox           bubblewrap launched a hardened process");
            println!("         · user namespaces: capability-bearing — proven by the launch");
            println!("         · no_new_privs set, every capability dropped");
            if report.host_home_absent {
                println!("         · host $HOME absent — the bind layout did not leak it");
            } else {
                println!("         · note: the host $HOME was visible inside the probe sandbox");
            }
        }
        Ok(report) => classify_launch_failure(Some(&report.stderr), remediation),
        Err(e) => {
            // The probe could not even spawn bwrap; surface why, then classify.
            println!("         · could not run the launch probe: {e}");
            classify_launch_failure(None, remediation);
        }
    }
}

/// A real launch did not yield a hardened process. A capability-bearing namespace
/// means the engine itself failed, so blame bubblewrap and surface its own
/// diagnosis; otherwise the namespace is the cause and is classified as such.
fn classify_launch_failure(bwrap_stderr: Option<&str>, remediation: &mut Vec<&'static str>) {
    match probe_userns() {
        Userns::Ok => {
            println!("  [FAIL] sandbox           bubblewrap could not launch a hardened process");
            println!("         · user namespaces: capability-bearing (the failure is in bubblewrap, not the namespace)");
            for line in bwrap_stderr
                .unwrap_or_default()
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .take(3)
            {
                println!("         · {line}");
            }
            remediation.push(BWRAP_LAUNCH_REMEDIATION);
        }
        other => classify_namespace_failure(other, remediation),
    }
}

/// Report a user namespace that cannot bear the capabilities bubblewrap needs,
/// distinguishing outright absence from the capability-stripped case so the
/// remediation points at the real cause. The caller has already established the
/// namespace is not `Ok`.
fn classify_namespace_failure(userns: Userns, remediation: &mut Vec<&'static str>) {
    match userns {
        Userns::Unsupported => {
            println!("  [FAIL] user namespaces   cannot create one without privilege");
        }
        Userns::CapStripped => {
            println!(
                "  [FAIL] user namespaces   created but stripped of capabilities (restricted)"
            );
        }
        // The caller only reaches here with a non-`Ok` namespace; a transient
        // flip to `Ok` is still a failure to launch, so it is flagged, not hidden.
        Userns::Ok => println!("  [FAIL] user namespaces   transient namespace probe failure"),
    }
    remediation.push(USERNS_REMEDIATION);
}

/// `ops ps`: list the live sandbox sessions from the on-disk registry. Reading
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

    println!("{:<6}  {:>8}  {:>8}  PROJECT", "KIND", "PID", "AGE");
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
        println!(
            "{:<6}  {:>8}  {:>8}  {}",
            s.kind.as_str(),
            s.pid,
            age,
            s.project.display()
        );
    }
    ExitCode::SUCCESS
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
            println!("ops: trusted {}", path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ops: cannot trust {}: {e}", path.display());
            ExitCode::FAILURE
        }
    }
}

/// Report a config's current trust state. A query never changes anything, so it
/// succeeds whatever the state — the verdict is the message, not the exit code.
fn show_trust(path: std::path::PathBuf) -> ExitCode {
    let store_dir = match trust_store_dir() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let verdict = match trust::state(&store_dir, &path) {
        trust::TrustState::Trusted => "trusted",
        trust::TrustState::Untrusted => "untrusted",
        trust::TrustState::Changed => {
            "changed since it was trusted — re-run `ops trust` to re-approve"
        }
    };
    println!("ops: {} is {verdict}", path.display());
    ExitCode::SUCCESS
}

/// `ops untrust [path]`: revoke a project config's trust, so its security-relevant
/// fields stop applying until it is trusted again.
fn untrust_cmd(arg: Option<OsString>) -> ExitCode {
    let path = config_path_arg(arg);
    let store_dir = match trust_store_dir() {
        Ok(d) => d,
        Err(code) => return code,
    };
    match trust::untrust(&store_dir, &path) {
        Ok(true) => {
            println!("ops: revoked trust for {}", path.display());
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!("ops: {} was not trusted; nothing to revoke", path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ops: cannot revoke trust for {}: {e}", path.display());
            ExitCode::FAILURE
        }
    }
}

/// `ops config`: show the resolved configuration for the current project — the
/// layered global + project environment and read-only binds, after the trust gate
/// has dropped anything an untrusted project may not set. Warnings explain what
/// was dropped and why.
fn config_cmd() -> ExitCode {
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: cannot read the current directory: {e}");
            return ExitCode::FAILURE;
        }
    };
    let resolved = config::load(&cwd);

    println!("ops config — resolved for {}", cwd.display());
    if resolved.env.is_empty() {
        println!("  env:   (none)");
    } else {
        println!("  env:");
        for (k, v) in &resolved.env {
            println!("    {k}={v}");
        }
    }
    if resolved.ro_binds.is_empty() {
        println!("  binds: (none)");
    } else {
        println!("  binds (read-only):");
        for b in &resolved.ro_binds {
            println!("    {}", b.display());
        }
    }
    // Declared tools, each with its trust verdict. The launcher provisions the
    // trusted ones onto PATH and withholds the rest; this shows that decision
    // without realising anything (no nix, no network).
    if resolved.packages.is_empty() {
        println!("  packages: (none)");
    } else {
        println!("  packages:");
        for p in &resolved.packages {
            if p.state == trust::TrustState::Trusted {
                println!("    {} -> {}", p.name, p.attr);
            } else {
                println!(
                    "    {} -> {}  (withheld: {})",
                    p.name,
                    p.attr,
                    config::untrusted_reason(p.state)
                );
            }
        }
    }
    // The project's mise file and whether it would be honored — a tool source like
    // `packages`, gated trusted-only. Its tools are not resolved here (no mise run,
    // no nix, no network); this reports presence and the gating verdict only.
    match &resolved.mise {
        None => println!("  mise:  (none)"),
        Some(m) if m.state == trust::TrustState::Trusted => {
            println!("  mise:  {} (trusted)", m.name)
        }
        Some(m) => println!(
            "  mise:  {} (withheld: {})",
            m.name,
            config::untrusted_reason(m.state)
        ),
    }
    // The `nix:` tools the project's mise file declares — parsed only (no nixhub query,
    // no realisation), gated by the same trust as the mise file. Like `packages`, this
    // shows the launcher's decision without doing the work.
    if let Some(m) = &resolved.mise {
        let declared = sandbox::parse_nix_tools(&m.files);
        if !declared.nix.is_empty() || !declared.other.is_empty() {
            println!("  tools (nix:):");
            let trusted = m.state == trust::TrustState::Trusted;
            for t in &declared.nix {
                if trusted {
                    println!("    {} = {}", t.pkg, t.version);
                } else {
                    println!(
                        "    {} = {}  (withheld: {})",
                        t.pkg,
                        t.version,
                        config::untrusted_reason(m.state)
                    );
                }
            }
            // Non-`nix:` tools are not provisioned by ops; show why, so a `node = "20"`
            // that never appears on PATH is explained rather than silently absent.
            for token in &declared.other {
                println!("    {token}  (ignored: not a `nix:` tool)");
            }
        }
    }
    // The nixpkgs source the tools resolve against — a trusted project pin, else the
    // global override, else the default rolling channel — and the revision it is
    // currently locked to, if one has been resolved. Routed through the same channel
    // decision the launch uses, so it shows exactly the lock a launch would consult
    // (a stale per-project lock is never surfaced). Shown without resolving anything
    // (no nix, no network): an unlocked source simply omits the revision.
    println!("  {}", nixpkgs_line(&cwd, &resolved));
    // The mise engine's own channel and locked revision, from its dedicated lock — shown
    // so the decoupling from the base channel is visible: `ops upgrade mise` advances this
    // without moving `nixpkgs`, and `ops upgrade nix` the reverse.
    println!("  {}", engine_line(&resolved));
    // The network posture — a security field, gated like the binds: an untrusted
    // project's choice never reaches here. `shared` keeps the host network (the
    // default, no confidentiality guarantee yet); `none` cuts it off entirely; an
    // `allowlist` lists exactly what egress is permitted, enforced by the host filtering
    // proxy through an empty-netns cage.
    match &resolved.network {
        config::NetworkPolicy::Shared => println!("  network: shared (host network)"),
        config::NetworkPolicy::Isolated => println!("  network: none (isolated — no network)"),
        config::NetworkPolicy::Allowlist(a) => {
            println!("  network: allowlist");
            if a.allow_rules().is_empty() {
                println!("    allow: (none declared)");
            } else {
                for rule in a.allow_rules() {
                    println!("    allow {rule}");
                }
            }
            // Deny carve-outs always win over allow; show them so the effective policy is
            // visible at a glance.
            for rule in a.deny_rules() {
                println!("    deny  {rule}");
            }
            // The built-in nix-cache allow-set is unioned into every allowlist regardless of
            // trust, so a project can self-equip its nix toolchain; show it so it is never a
            // silent allowance (a user `deny` still carves it).
            println!("    built-in (always allowed, so self-equip works):");
            for host in sandbox::nix_cache_hosts() {
                println!("      allow {host}");
            }
            println!("    (deny wins over allow)");
        }
    }
    // Credentials the egress proxy injects into matching requests — a security field, gated
    // like the binds (an untrusted project's are dropped). The source is shown by locator (the
    // variable name or file path), never the value, which ops reads only host-side at launch.
    if !resolved.secrets.is_empty() {
        println!("  secrets (injected host-side by the egress proxy):");
        for s in &resolved.secrets {
            println!(
                "    {} -> {}  ({}, from {})",
                s.header,
                s.to,
                s.shape.describe(),
                s.describe_sources()
            );
        }
    }
    // Named application profiles (`[app.<name>]`), each a gated overlay over the baseline.
    // Shown without launching: the command it runs and what its overlay adds, plus each
    // app's own dropped-field notes (so `ops app <name>` holds no surprises). The overlay's
    // security fields appear only when their source was trusted, exactly as at launch.
    if !resolved.apps.is_empty() {
        println!("  apps:");
        for (name, app) in &resolved.apps {
            let cmd = if app.cmd.is_empty() {
                "(no command)".to_string()
            } else {
                app.cmd.join(" ")
            };
            println!("    {name}: {cmd}");
            if !app.packages.is_empty() {
                let names: Vec<&str> = app.packages.iter().map(|p| p.name.as_str()).collect();
                println!("      packages: {}", names.join(", "));
            }
            match &app.network {
                Some(config::NetworkPolicy::Shared) => println!("      network: shared"),
                Some(config::NetworkPolicy::Isolated) => println!("      network: none"),
                Some(config::NetworkPolicy::Allowlist(_)) => println!("      network: allowlist"),
                None => {}
            }
            if !app.secrets.is_empty() {
                println!("      secrets: {} injected host-side", app.secrets.len());
            }
            for w in &app.warnings {
                println!("      note: {w}");
            }
        }
    }
    for w in &resolved.warnings {
        eprintln!("ops: warning: {w}");
    }
    ExitCode::SUCCESS
}

/// `ops search <query>`: discover the `nix:` tools (and `[packages]` attributes) a
/// project can declare, by querying nixhub. Host-side and read-only — it resolves
/// nothing into the sandbox and needs no trust gate (a discovery front-end, like a plain
/// `nix search`). It needs nix only to ride its fetcher for the one network step.
/// `ops app <name>`: launch a named application profile (an `[app.<name>]` table from the
/// global or project config) inside the project sandbox.
fn app_cmd(args: Vec<OsString>) -> ExitCode {
    let name = args
        .iter()
        .filter_map(|a| a.to_str())
        .find(|a| !a.starts_with('-'));
    let Some(name) = name else {
        eprintln!("ops: usage: ops app <name>");
        return ExitCode::from(2);
    };
    sandbox::app(name)
}

fn search_cmd(args: Vec<OsString>) -> ExitCode {
    // The query is the first non-flag argument; any further words are ignored (nixhub
    // matches a single token, so a multi-word search is pointless — quote a phrase to
    // pass it as one argument if ever needed).
    let query = args
        .iter()
        .filter_map(|a| a.to_str())
        .find(|a| !a.starts_with('-'));
    let Some(query) = query else {
        eprintln!("ops: usage: ops search <query>");
        return ExitCode::from(2);
    };
    let Some(nix) = store::resolve_nix() else {
        eprintln!("ops: nix not found — `ops search` needs it to query nixhub. See `ops doctor`.");
        return ExitCode::FAILURE;
    };
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("ops: cannot resolve the data directory (no $HOME or $XDG_DATA_HOME).");
        return ExitCode::FAILURE;
    };
    match sandbox::search(&nix, &layout, query, &sandbox::current_system()) {
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
            eprintln!("ops: usage: ops test net <url>");
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
        eprintln!("ops: usage: ops test net <url>");
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
        eprintln!("ops: warning: {w}");
    }
    match &resolved.network {
        config::NetworkPolicy::Shared => {
            println!(
                "network: shared (host network) — every URL is reachable; no allowlist to test"
            );
            ExitCode::SUCCESS
        }
        config::NetworkPolicy::Isolated => {
            println!("network: none (isolated) — no URL is reachable");
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
            match policy.explain(&host, port, &path) {
                allowlist::Decision::AllowedBy(rule) => {
                    println!("ALLOWED  {url}");
                    println!("  by allow rule: {rule}");
                }
                allowlist::Decision::DeniedBy(rule) => {
                    println!("DENIED   {url}");
                    println!("  by deny rule (deny wins): {rule}");
                }
                allowlist::Decision::DeniedDefault => {
                    println!("DENIED   {url}");
                    println!("  no allow rule matches (deny-by-default)");
                }
            }
            ExitCode::SUCCESS
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
        Some(other) => {
            eprintln!(
                "ops: unknown plugins subcommand '{other}' (known: list, info, install, rm, store)"
            );
            ExitCode::from(2)
        }
        None => {
            eprintln!(
                "ops: usage: ops plugins <list | info <scheme> | install <name | dir> | \
                 rm <name> | store <list | add | update | install | info | rm>>"
            );
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

    println!(
        "built-in schemes (always resolve, never a plugin): {}",
        plugins::builtin_schemes().join(", ")
    );
    if registry.is_empty() {
        println!("installed resolver plugins: (none)");
    } else {
        println!("installed resolver plugins:");
        for p in registry.resolvers() {
            let net = if p.sandbox.network {
                "network"
            } else {
                "no-network"
            };
            print!("  {}://  {}", p.scheme, p.name);
            if let Some(v) = &p.version {
                print!("  v{v}");
            }
            print!("  {net}");
            if let Err(why) = p.check_exec() {
                print!("  [not runnable: {why}]");
            }
            println!();
            if let Some(desc) = &p.description {
                println!("    {desc}");
            }
        }
        println!("(remove one with: ops plugins rm <name>)");
    }
    println!("(browse the built-in store with: ops plugins store list)");
    for w in &warnings {
        eprintln!("ops: warning: {w}");
    }
    ExitCode::SUCCESS
}

/// `ops plugins install <name | dir>`: place a resolver plugin into the data dir, where it becomes
/// trusted by location. A bare `name` installs a plugin from the built-in store (bundled in the
/// binary); a path-like argument (`./dir`, `/abs/dir`) copies a local directory. A deliberate user
/// act (an agent in the cage cannot run it); either way the staged copy is validated exactly as the
/// launcher will and refused, fail-closed, on any flaw. No fetch, no network, no signature.
fn plugins_install(source: Option<&OsString>) -> ExitCode {
    let Some(source) = source else {
        eprintln!("ops: usage: ops plugins install <name | dir>");
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
            println!(
                "installed '{}' ({}://) — remove with: ops plugins rm {}",
                installed.name, installed.scheme, installed.name
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
            eprintln!(
                "ops: usage: ops plugins store <list | add --name <n> --url <git-url> \
                 (--key <hex|@file> | --trust) | publish <dir> --key <key-file> [--rev <n>] | \
                 update [name] | install <store> <plugin> | info <name> | rm <name>>"
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
    const USAGE: &str =
        "ops: usage: ops plugins store add --name <n> --url <git-url> (--key <hex|@file> | --trust)";
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
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(name), Some(url)) = (name, url) else {
        eprintln!("{USAGE}");
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
            // out-of-band comparison, while the configured-store report goes to stdout.
            if added.tofu {
                eprintln!("⚠ trust-on-first-use: pinned the key this store ships, unverified");
                eprintln!("  pinned key: {}", plugin_store::to_hex(&added.pubkey));
                eprintln!(
                    "  verify it out of band; re-shown by `ops plugins store info {}`",
                    added.name
                );
            }
            let cat = &added.catalogue;
            println!(
                "configured store '{}' (rev {}, {} plugin{}):",
                added.name,
                cat.rev,
                cat.plugins.len(),
                if cat.plugins.len() == 1 { "" } else { "s" }
            );
            for (pname, entry) in &cat.plugins {
                print!("  {pname}  ({}://)", entry.scheme);
                if !entry.version.is_empty() {
                    print!("  v{}", entry.version);
                }
                println!();
            }
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
    const USAGE: &str = "ops: usage: ops plugins store publish <dir> --key <key-file> [--rev <n>]";
    let mut dir: Option<&OsStr> = None;
    let mut key: Option<&OsStr> = None;
    let mut rev: Option<u64> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--key") => key = it.next().map(|v| v.as_os_str()),
            Some("--rev") => {
                let Some(value) = it.next().and_then(|v| v.to_str()) else {
                    eprintln!("{USAGE}");
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
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
            // Anything else (including a non-UTF-8 path) is the positional directory.
            _ => {
                if dir.is_some() {
                    eprintln!("ops: publish takes a single directory");
                    eprintln!("{USAGE}");
                    return ExitCode::from(2);
                }
                dir = Some(arg.as_os_str());
            }
        }
    }
    let (Some(dir), Some(key)) = (dir, key) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };

    match stores::publish(Path::new(dir), Path::new(key), rev) {
        Ok(published) => {
            // The key file just written or reused is the store's identity; warn loudly so it is
            // never treated as a throwaway. The public key, on stdout, is what consumers pin.
            eprintln!(
                "⚠ keep the signing key `{}` secret — it is this store's identity",
                Path::new(key).display()
            );
            let pubkey = plugin_store::to_hex(&published.pubkey);
            println!(
                "published store at rev {} ({} plugin{}):",
                published.rev,
                published.plugins.len(),
                if published.plugins.len() == 1 {
                    ""
                } else {
                    "s"
                }
            );
            for (name, scheme) in &published.plugins {
                println!("  {name}  ({scheme}://)");
            }
            println!("pubkey: {pubkey}");
            println!(
                "commit and host the directory, then consumers add it with: \
                 ops plugins store add --name <n> --url <git-url> --key {pubkey}"
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
                println!(
                    "no remote stores are configured \
                     (add one with: ops plugins store add --name <n> --url <git-url> --key <hex>)"
                );
                return ExitCode::SUCCESS;
            }
            all
        }
    };

    let mut failed = false;
    for name in &names {
        match stores::update(&layout, name, &git) {
            Ok(u) => {
                let n = u.catalogue.plugins.len();
                let plural = if n == 1 { "" } else { "s" };
                if u.new_rev > u.old_rev {
                    println!(
                        "updated store '{}' (rev {} → {}, {n} plugin{plural})",
                        u.name, u.old_rev, u.new_rev
                    );
                } else {
                    println!(
                        "store '{}' is already at revision {} ({n} plugin{plural})",
                        u.name, u.new_rev
                    );
                }
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
        eprintln!("ops: usage: ops plugins store install <store> <plugin>");
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("ops: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    match stores::install_plugin(&layout, store_name, plugin_name) {
        Ok(installed) => {
            println!(
                "installed '{}' ({}://) from store '{store_name}' — remove with: ops plugins rm {}",
                installed.name, installed.scheme, installed.name
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
        eprintln!("ops: usage: ops plugins store info <name>");
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

    println!("store '{}'", cfg.name);
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
                print!("    {pname}  ({}://)", entry.scheme);
                if !entry.version.is_empty() {
                    print!("  v{}", entry.version);
                }
                println!();
                if !entry.description.is_empty() {
                    println!("      {}", entry.description);
                }
            }
        }
        Err(why) => eprintln!("ops: warning: cannot read the cached catalogue: {why}"),
    }
    ExitCode::SUCCESS
}

/// `ops plugins store rm <name>`: remove a configured remote store from the cache. Host-level,
/// like `add`; refuses a name that is not configured.
fn plugins_store_remove(name: Option<&str>) -> ExitCode {
    let Some(name) = name else {
        eprintln!("ops: usage: ops plugins store rm <name>");
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("ops: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    match stores::remove(&layout, name) {
        Ok(()) => {
            println!("removed store '{name}'");
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
    println!("built-in plugin store (install one with: ops plugins install <name>):");
    for entry in plugins::embedded_listing() {
        let scheme = entry.scheme.as_deref().unwrap_or("?");
        print!("  {}  ({scheme}://)", entry.name);
        if let Some(v) = &entry.version {
            print!("  v{v}");
        }
        let is_installed = installed_dir
            .as_ref()
            .is_some_and(|d| d.join(&entry.name).is_dir());
        if is_installed {
            print!("  [installed]");
        }
        println!();
        if let Some(desc) = &entry.description {
            println!("    {desc}");
        }
    }

    // Configured remote stores, read from their owner-only caches (trusted by location).
    if let Some(layout) = &layout {
        let names = stores::list(layout);
        if !names.is_empty() {
            println!("configured remote stores (update with: ops plugins store update <name>):");
            for name in &names {
                match stores::read_configured(layout, name) {
                    Ok(cfg) => {
                        let detail = match stores::cached_catalogue(layout, name) {
                            Ok(cat) => {
                                let n = cat.plugins.len();
                                format!("{n} plugin{}", if n == 1 { "" } else { "s" })
                            }
                            Err(_) => "catalogue unreadable".to_string(),
                        };
                        let marker = if cfg.tofu { "  [tofu]" } else { "" };
                        println!("  {name}  (rev {}, {detail}){marker}", cfg.locked_rev);
                    }
                    Err(why) => eprintln!("ops: warning: store '{name}': {why}"),
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
        eprintln!("ops: usage: ops plugins rm <name>");
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("ops: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    match plugins::remove(&layout, name) {
        Ok(()) => {
            println!("removed '{name}'");
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
        eprintln!("ops: usage: ops plugins info <scheme>");
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
            eprintln!("ops: warning: {w}");
        }
        eprintln!("ops: no installed resolver plugin claims the scheme '{scheme}'");
        return ExitCode::FAILURE;
    };
    println!("resolver plugin: {}", p.name);
    println!("  scheme:      {}://", p.scheme);
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
        Err(why) => println!("  [not runnable: {why}]"),
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

/// The `ops config` nixpkgs line: the effective source and where it came from, plus
/// the revision it is currently locked to when one has been resolved. Routed through
/// the launch's own channel decision so it reports exactly the lock a launch would
/// consult. Best-effort: if the data directory or project identity cannot be
/// resolved, it falls back to the source and origin alone.
fn nixpkgs_line(cwd: &Path, resolved: &config::Resolved) -> String {
    if let Some(layout) = store::Layout::from_env() {
        if let Ok(target) = sandbox::effective_lock_target(cwd, &layout, resolved) {
            let origin = target.origin().label();
            return match target.locked_revision() {
                Some(rev) => format!(
                    "nixpkgs: {} @ {}  ({origin})",
                    target.source(),
                    short_rev(&rev)
                ),
                None => format!("nixpkgs: {}  ({origin})", target.source()),
            };
        }
    }
    let (source, origin) = match (&resolved.nixpkgs_project, &resolved.nixpkgs_global) {
        (Some(p), _) => (p.as_str(), "project pin"),
        (None, Some(g)) => (g.as_str(), "global"),
        (None, None) => ("nixos-unstable", "default"),
    };
    format!("nixpkgs: {source}  ({origin})")
}

/// The `ops config` mise-engine line: the engine's source (the global channel — a project
/// pin never moves it) and the revision its dedicated lock is currently pinned to, when
/// one has been resolved. Shown so the engine's independence from the base channel is
/// visible. Best-effort, like [`nixpkgs_line`]: if the data directory cannot be resolved,
/// it falls back to the source and origin alone. Resolves nothing (no nix, no network).
fn engine_line(resolved: &config::Resolved) -> String {
    if let Some(layout) = store::Layout::from_env() {
        let target = store::LockTarget::engine(&layout, resolved.nixpkgs_global.as_deref());
        let origin = target.origin().label();
        return match target.locked_revision() {
            Some(rev) => format!(
                "engine: {} @ {}  ({origin})",
                target.source(),
                short_rev(&rev)
            ),
            None => format!("engine: {}  ({origin})", target.source()),
        };
    }
    let (source, origin) = match &resolved.nixpkgs_global {
        Some(g) => (g.as_str(), "global"),
        None => ("nixos-unstable", "default"),
    };
    format!("engine: {source}  ({origin})")
}

/// `ops upgrade [all|nix|mise]`: roll managed channels forward by re-resolving and
/// rewriting their locks, so versions advance only here, never on an ops binary update.
/// `nix` rolls the nixpkgs channel the current directory tracks (a trusted project pin,
/// else the global channel) — base and native `[packages]`. `mise` rolls the mise engine
/// (its own dedicated lock) and the project's `nix:` tools. `all` rolls every one. It
/// needs nix (to resolve) but not the sandbox boundary: it only rewrites locks, so it
/// does not gate on user namespaces.
fn upgrade_cmd(args: Vec<OsString>) -> ExitCode {
    // Parse the target before touching anything, so a typo fails cleanly. `all` covers
    // every managed channel: the nixpkgs channel (base + native `[packages]`) and the
    // project's `nix:` mise tools.
    let what = match args.first().and_then(|s| s.to_str()).unwrap_or("all") {
        w @ ("all" | "nix" | "mise") => w,
        other => {
            eprintln!("ops: unknown upgrade target '{other}' (known: all, nix, mise)");
            return ExitCode::from(2);
        }
    };

    let Some(nix) = store::resolve_nix() else {
        eprintln!("ops: nix not found — cannot upgrade. See `ops doctor`.");
        return ExitCode::FAILURE;
    };
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("ops: cannot resolve the data directory (no $HOME or $XDG_DATA_HOME).");
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
        eprintln!("ops: warning: {warning}");
    }

    // `all` rolls every managed channel and reports the worst exit — a tool that fails to
    // re-resolve must not be masked by a clean roll elsewhere. `mise` rolls two distinct
    // things: the engine (host-global, in every cage, so it rolls regardless of any
    // project's trust) and the project's `nix:` tools (trusted-only). Rolling them as two
    // separate, unconditional calls keeps the engine's trust-independence structural
    // rather than dependent on the tools path not early-returning.
    let mut ok = true;
    if matches!(what, "nix" | "all") {
        ok &= upgrade_nix_channel(&nix, &layout, &cwd, &cfg);
    }
    if matches!(what, "mise" | "all") {
        ok &= upgrade_mise_engine(&nix, &layout, &cfg);
        ok &= upgrade_mise_tools(&nix, &layout, &cwd, &cfg);
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Roll the nixpkgs channel the current directory tracks — a trusted project pin, else
/// the global channel — forcing a fresh resolution and rewriting that lock. Returns
/// whether it succeeded; the base and `[packages]` download on the next launch.
fn upgrade_nix_channel(
    nix: &Path,
    layout: &store::Layout,
    cwd: &Path,
    cfg: &config::Resolved,
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
fn upgrade_mise_engine(nix: &Path, layout: &store::Layout, cfg: &config::Resolved) -> bool {
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
) -> bool {
    let Some(mise) = &cfg.mise else {
        for line in upgrade_tools_summary(&[]) {
            println!("{line}");
        }
        return true;
    };
    if mise.state != trust::TrustState::Trusted {
        eprintln!(
            "ops: warning: mise file {} withheld ({}): its nix: tools are not rolled",
            mise.name,
            config::untrusted_reason(mise.state)
        );
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
    for line in upgrade_tools_summary(&outcomes) {
        println!("{line}");
    }
    !outcomes
        .iter()
        .any(|o| matches!(o, sandbox::ToolUpgrade::Failed { .. }))
}

/// The human-readable summary of a mise tools roll: one line per declared tool (rolled,
/// unchanged, newly pinned, or failed), the entries pruned, and any token ops does not
/// handle. Pure, so every outcome is unit-tested without invoking nix.
fn upgrade_tools_summary(outcomes: &[sandbox::ToolUpgrade]) -> Vec<String> {
    use sandbox::ToolUpgrade::*;
    let mut lines = vec!["ops upgrade — mise tools".to_string()];
    if outcomes.is_empty() {
        lines.push("  no nix: tools to roll.".to_string());
        return lines;
    }
    for outcome in outcomes {
        lines.push(match outcome {
            Unchanged { pkg, version, .. } => format!("  nix:{pkg}: {version} — unchanged."),
            Rolled { pkg, from, to, .. } => format!("  nix:{pkg}: {from} → {to} — rolled forward."),
            Pinned { pkg, version, .. } => format!("  nix:{pkg}: {version} — newly pinned."),
            Failed {
                pkg, error, kept, ..
            } => match kept {
                Some(v) => format!("  nix:{pkg}: re-resolve failed, kept {v} — {error}"),
                None => format!("  nix:{pkg}: re-resolve failed — {error}"),
            },
            Pruned { pkg, request } => {
                format!("  nix:{pkg} ({request}): removed from the lock (no longer declared).")
            }
            Ignored { token } => {
                format!("  {token}: not a nix: tool — left to mise, not rolled.")
            }
        });
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
) -> Vec<String> {
    let mut lines = vec![
        heading.to_string(),
        format!("  {item}: {}  ({origin})", up.source),
    ];
    let outcome = match &up.previous {
        None => format!(
            "  resolved to {} (first pin) — {downloads} on the next launch.",
            short_rev(&up.revision)
        ),
        Some(prev) if prev == &up.revision && store::is_pinned_revision(&up.source) => format!(
            "  pinned to a fixed revision {} — nothing to roll.",
            short_rev(&up.revision)
        ),
        Some(prev) if prev == &up.revision => format!(
            "  already at the latest revision {} — nothing to do.",
            short_rev(&up.revision)
        ),
        Some(prev) => format!(
            "  rolled forward {} → {} — {downloads} on the next launch.",
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
        )
        .join("\n");
        assert!(engine.contains("mise engine"));
        assert!(engine.contains("engine: nixos-unstable"));
        assert!(engine.contains("the new engine is provisioned"));
        assert!(!engine.contains("base and tools"));
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
            ro_binds: vec![],
            packages: vec![],
            nixpkgs_global: Some(global.to_string()),
            nixpkgs_project: None,
            mise: None,
            network: config::NetworkPolicy::default(),
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
        assert!(upgrade_mise_engine(bogus_nix, &layout, &cfg(&rev_a)));
        assert!(upgrade_nix_channel(
            bogus_nix,
            &layout,
            data.path(),
            &cfg(&rev_a)
        ));
        let nix_seed = std::fs::read(&nix_lock).unwrap();

        // roll ONLY the engine to REV_B: the base lock is untouched, the engine advanced
        assert!(upgrade_mise_engine(bogus_nix, &layout, &cfg(&rev_b)));
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
        assert!(upgrade_mise_engine(bogus_nix, &layout, &cfg(&rev_a)));
        let engine_reseed = std::fs::read(&engine_lock).unwrap();
        assert!(upgrade_nix_channel(
            bogus_nix,
            &layout,
            data.path(),
            &cfg(&rev_b)
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
        let empty = upgrade_tools_summary(&[]).join("\n");
        assert!(empty.contains("no nix: tools"));

        let text = upgrade_tools_summary(&[
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
            },
        ])
        .join("\n");

        assert!(text.contains("nix:jq: 1.7.1 — unchanged"));
        assert!(text.contains("nix:ripgrep: 14.1.0 → 14.1.1 — rolled forward"));
        assert!(text.contains("nix:nodejs: 20.11.0 — newly pinned"));
        assert!(text.contains("nix:fd: re-resolve failed, kept 9.0.0"));
        assert!(text.contains("nix:bat: re-resolve failed — nixhub unreachable"));
        assert!(text.contains("nix:oldtool (1.0): removed from the lock"));
        assert!(text.contains("node: not a nix: tool"));
    }
}
