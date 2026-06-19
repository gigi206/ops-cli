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
mod sandbox;
mod session;
mod store;
#[cfg(test)]
mod testutil;
mod trust;

use std::ffi::OsString;
use std::path::Path;
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
        Some("test") => test_cmd(args.collect()),
        Some(other) => {
            eprintln!(
                "ops: unknown command '{other}' \
                 (known: doctor, shell, run, mise, test, ps, trust, untrust, config, upgrade)"
            );
            ExitCode::from(2)
        }
        None => {
            eprintln!(
                "ops: usage: ops <doctor | shell | run [--] <command> | mise <args> | \
                 test net <url> | ps | trust [path] | untrust [path] | config | upgrade [all|nix]>"
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
                s.source.describe()
            );
        }
    }
    for w in &resolved.warnings {
        eprintln!("ops: warning: {w}");
    }
    ExitCode::SUCCESS
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

/// `ops upgrade [all|nix]`: roll the nixpkgs channel forward. It re-resolves the
/// source the current directory tracks — a trusted project pin, else the global
/// channel — and rewrites that lock, so tool and base versions advance only here,
/// never on an ops binary update. It needs nix (to resolve) but not the sandbox
/// boundary: it only rewrites a lock, so it does not gate on user namespaces.
fn upgrade_cmd(args: Vec<OsString>) -> ExitCode {
    // Parse the target before touching anything, so a typo fails cleanly. `all` covers
    // every managed channel; today that is just nix (mise provisioning lands later).
    match args.first().and_then(|s| s.to_str()).unwrap_or("all") {
        "all" | "nix" => {}
        "mise" => {
            eprintln!("ops: upgrading mise is not yet available.");
            return ExitCode::from(2);
        }
        other => {
            eprintln!("ops: unknown upgrade target '{other}' (known: all, nix)");
            return ExitCode::from(2);
        }
    }

    let Some(nix) = store::resolve_nix() else {
        eprintln!("ops: nix not found — cannot upgrade the channel. See `ops doctor`.");
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

    let target = match sandbox::effective_lock_target(&cwd, &layout, &cfg) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ops: cannot resolve the channel target: {e}");
            return ExitCode::FAILURE;
        }
    };
    let upgrade = match target.refresh(&nix, &layout) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("ops: cannot upgrade the nixpkgs channel: {e}");
            return ExitCode::FAILURE;
        }
    };

    for line in upgrade_summary(target.origin().label(), &upgrade) {
        println!("{line}");
    }
    ExitCode::SUCCESS
}

/// The human-readable summary of an upgrade: the channel, then what changed — a first
/// resolution, an unchanged channel, a fixed revision that cannot roll, or a
/// roll-forward. Pure, so every outcome is unit-tested without invoking nix.
fn upgrade_summary(origin: &str, up: &store::Upgrade) -> Vec<String> {
    let mut lines = vec![
        "ops upgrade — nix channel".to_string(),
        format!("  channel: {}  ({origin})", up.source),
    ];
    let outcome = match &up.previous {
        None => format!(
            "  resolved to {} (first pin) — the new base and tools download on the next launch.",
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
            "  rolled forward {} → {} — the new base and tools download on the next launch.",
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
        let text = |up| upgrade_summary("default", &up).join("\n");

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
    }
}
