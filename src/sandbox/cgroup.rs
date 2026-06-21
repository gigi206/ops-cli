//! Best-effort cgroup v2 resource limits (anti-DoS) for the cage.
//!
//! An autonomous agent in the open cage can fork-bomb, exhaust memory, or peg the
//! CPU — accidentally (a runaway build) or deliberately — and nothing in the
//! namespace/seccomp/egress stack bounds *resource consumption*. This module caps
//! it by running the cage inside a transient **systemd user scope** carrying the
//! limits.
//!
//! **Why a systemd scope and not a hand-rolled cgroup:** under cgroup v2 the
//! kernel's delegation rule says you may only manage cgroups in a subtree systemd
//! has explicitly delegated to you; creating an ad-hoc cgroup under systemd's own
//! `app.slice` works but is unsanctioned and can be garbage-collected out from
//! under you. `systemd-run --user --scope` asks the user manager to create a
//! proper transient scope it owns, tracks, and auto-removes when empty. It
//! **exec-chains** into the wrapped command (it registers the scope, moves itself
//! in, then `execve`s), so no extra process lingers in the tree and an interactive
//! shell keeps its controlling terminal and job control — it behaves like a plain
//! argv prefix.
//!
//! **Best-effort, never the boundary:** resource limits are hardening, not the
//! security control (that is the namespace + seccomp + egress layer, which hard-
//! fails). Where there is no cgroup v2, no systemd user session, no `systemd-run`,
//! or a controller is not delegated, the cage launches **without** limits rather
//! than failing — `doctor` is where availability is surfaced.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Memory pressure threshold: above this fraction of RAM the kernel reclaims and
/// throttles the cage (a heavy build slows but survives) rather than killing it.
const MEMORY_HIGH: &str = "80%";
/// Hard per-cage memory ceiling: a single runaway allocator is OOM-killed *within
/// its own scope* here, rather than consuming host RAM without bound. Set well
/// above the throttle threshold so a legitimate toolchain build, which throttles
/// at `MEMORY_HIGH` and rarely climbs further, is not killed. The bound is
/// per-cage, not host-global — several concurrent cages each capped relative to
/// total RAM can still sum past it; the unambiguous host-wide anti-DoS win of the
/// set is the task cap, which a fork-bomb cannot evade.
const MEMORY_MAX: &str = "90%";
/// Task (process + thread) cap. A fork-bomb needs orders of magnitude more than
/// any real build, so a generous cap stops the DoS without touching even a wide
/// parallel `make -j` with threaded linkers on a many-core host. This is the
/// clearest anti-DoS win of the set: any finite bound defeats a fork-bomb, while
/// the cost of setting it too high is negligible.
const TASKS_MAX: u32 = 16384;

/// The limit profile expressed as systemd unit properties, in `KEY=VALUE` form,
/// each tagged with the cgroup controller it needs so it can be dropped when that
/// controller is not delegated.
fn profile() -> Vec<(&'static str, String)> {
    vec![
        ("memory", format!("MemoryHigh={MEMORY_HIGH}")),
        ("memory", format!("MemoryMax={MEMORY_MAX}")),
        ("pids", format!("TasksMax={TASKS_MAX}")),
    ]
}

/// The controllers the user manager has delegated, read from the unified
/// hierarchy at this session's `user@<uid>.service`. Empty when the read fails for
/// any reason (no cgroup v2, not under a user manager, a container) — the caller
/// then applies no limits.
fn delegated_controllers() -> Vec<String> {
    // `/proc/self/cgroup` under cgroup v2 is a single `0::<path>` line.
    let Ok(content) = std::fs::read_to_string("/proc/self/cgroup") else {
        return Vec::new();
    };
    let Some(path) = content.lines().find_map(|l| l.strip_prefix("0::")) else {
        return Vec::new();
    };
    // Walk up to the `user@<uid>.service` component — the root of this session's
    // delegated subtree. Anything below it (the app slice, our own scope) inherits
    // a subset, so the service's controller set is the sound upper bound.
    let Some(end) = path.find("/user@").map(|i| {
        path[i + 1..]
            .find('/')
            .map(|j| i + 1 + j)
            .unwrap_or(path.len())
    }) else {
        return Vec::new();
    };
    let service = &path[..end];
    let file = format!("/sys/fs/cgroup{service}/cgroup.controllers");
    match std::fs::read_to_string(&file) {
        Ok(s) => s.split_whitespace().map(str::to_owned).collect(),
        Err(_) => Vec::new(),
    }
}

/// The systemd unit properties that can actually be enforced here: the profile
/// filtered to the delegated controllers. Building the list from the delegated set
/// sidesteps having to know whether `systemd-run` rejects an undelegated property.
fn enforceable_properties(delegated: &[String]) -> Vec<String> {
    profile()
        .into_iter()
        .filter(|(ctrl, _)| delegated.iter().any(|d| d == ctrl))
        .map(|(_, prop)| prop)
        .collect()
}

/// The single decision both the launch path ([`wrap`]) and the `doctor` probe
/// ([`probe`]) consult: the `systemd-run` launcher and the enforceable unit
/// properties when resource limits can be applied on this host, or `None` for
/// graceful degradation. Routing both consumers through here means `doctor` can
/// never report a posture a launch would not actually take.
fn limiter() -> Option<(PathBuf, Vec<String>)> {
    let systemd_run = crate::pathfind::find_on_path("systemd-run")?;
    // `systemd-run --user` needs a *reachable* user manager, not merely a named
    // runtime dir: a detached, cron, or post-logout context can inherit
    // `XDG_RUNTIME_DIR` while the session bus is gone. Require the bus socket to
    // exist so a dead session degrades to no-limits rather than hard-failing the
    // launch on a `systemd-run` that cannot register a scope — the launch must
    // never regress where it previously worked. (A stale socket left by a crashed
    // manager is the residual: rare, and then the failure names `systemd-run`.)
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")?;
    if !Path::new(&runtime).join("bus").exists() {
        return None;
    }
    let props = enforceable_properties(&delegated_controllers());
    if props.is_empty() {
        return None;
    }
    Some((systemd_run, props))
}

/// The `systemd-run` launcher and the argv prefix (ending with `--`) that wraps a
/// command in a transient scope carrying the enforceable limits, or `None` when no
/// limit can be applied on this host (graceful degradation).
fn scope_wrapper() -> Option<(PathBuf, Vec<OsString>)> {
    let (systemd_run, props) = limiter()?;
    let mut prefix = vec![
        OsString::from("--user"),
        OsString::from("--scope"),
        // Quiet (no "Running scope as unit" banner) and collect the transient unit
        // even if it fails, so repeated launches never accumulate dead units.
        OsString::from("-q"),
        OsString::from("--collect"),
    ];
    for p in props {
        prefix.push(OsString::from("-p"));
        prefix.push(OsString::from(p));
    }
    prefix.push(OsString::from("--"));
    Some((systemd_run, prefix))
}

/// Wrap a bwrap invocation in the resource-limit scope. Returns the program to run
/// and its full argument list (excluding `argv[0]`). With limits available the
/// program becomes `systemd-run` and bwrap is spliced in after `--`; otherwise the
/// pair is returned unchanged so the caller launches bwrap directly.
pub(crate) fn wrap(bwrap: &Path, bwrap_argv: Vec<OsString>) -> (PathBuf, Vec<OsString>) {
    compose(scope_wrapper(), bwrap, bwrap_argv)
}

/// Pure composition of a launch from an optional scope wrapper: with `Some` the
/// program becomes the launcher and bwrap is spliced in after its prefix;
/// with `None` (limits unavailable) the bwrap invocation is returned unchanged.
/// Split out from [`wrap`] so the host-independent degraded branch is testable.
fn compose(
    wrapper: Option<(PathBuf, Vec<OsString>)>,
    bwrap: &Path,
    bwrap_argv: Vec<OsString>,
) -> (PathBuf, Vec<OsString>) {
    match wrapper {
        Some((launcher, mut argv)) => {
            argv.push(bwrap.as_os_str().to_owned());
            argv.extend(bwrap_argv);
            (launcher, argv)
        }
        None => (bwrap.to_path_buf(), bwrap_argv),
    }
}

/// What `doctor` reports about resource limiting: the properties that would be
/// applied and whether a real transient scope carrying them launched.
pub(crate) struct LimitReport {
    /// The enforceable unit properties (e.g. `TasksMax=16384`), empty if none.
    pub(crate) properties: Vec<String>,
    /// A live `systemd-run` scope with those properties ran a trivial command.
    pub(crate) verified: bool,
    /// Why limits are unavailable or unverified, when they are.
    pub(crate) note: Option<String>,
}

/// Probe resource limiting by actually launching a trivial transient scope with
/// the enforceable properties — the conclusive check, matching how the security
/// boundary is decided by a live launch rather than inferred. Never fails: an
/// unavailable or non-working limiter is reported, not raised.
pub(crate) fn probe() -> LimitReport {
    // The verdict comes from the same `limiter()` decision a launch takes, so the
    // report cannot drift from reality; only when limits *would* be applied does
    // the live scope confirm they actually work.
    let Some((systemd_run, props)) = limiter() else {
        let note = if crate::pathfind::find_on_path("systemd-run").is_none() {
            "systemd-run not found; the cage runs without resource limits"
        } else {
            "no reachable systemd user session or delegated controller; \
             the cage runs without resource limits"
        };
        return LimitReport {
            properties: Vec::new(),
            verified: false,
            note: Some(note.into()),
        };
    };

    let mut cmd = std::process::Command::new(&systemd_run);
    cmd.args(["--user", "--scope", "-q", "--collect"]);
    for p in &props {
        cmd.arg("-p").arg(p);
    }
    cmd.args(["--", "true"]);
    match cmd.status() {
        Ok(s) if s.success() => LimitReport {
            properties: props,
            verified: true,
            note: None,
        },
        Ok(_) => LimitReport {
            properties: props,
            verified: false,
            note: Some("systemd-run could not create a limited scope".into()),
        },
        Err(e) => LimitReport {
            properties: props,
            verified: false,
            note: Some(format!("systemd-run failed to run: {e}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn the_profile_throttles_then_caps_memory_and_bounds_tasks() {
        let p = profile();
        // Memory is both throttled (high) and hard-capped (max); tasks are bounded.
        assert!(p
            .iter()
            .any(|(c, v)| *c == "memory" && v.starts_with("MemoryHigh=")));
        assert!(p
            .iter()
            .any(|(c, v)| *c == "memory" && v.starts_with("MemoryMax=")));
        assert!(p
            .iter()
            .any(|(c, v)| *c == "pids" && v.starts_with("TasksMax=")));
    }

    #[test]
    fn properties_are_filtered_to_delegated_controllers() {
        // Only `pids` delegated → only the task cap survives.
        let only_pids = enforceable_properties(&["pids".to_string()]);
        assert_eq!(only_pids, vec![format!("TasksMax={TASKS_MAX}")]);

        // Only `memory` delegated → both memory properties, no task cap.
        let only_mem = enforceable_properties(&["memory".to_string()]);
        assert_eq!(
            only_mem,
            vec![
                format!("MemoryHigh={MEMORY_HIGH}"),
                format!("MemoryMax={MEMORY_MAX}"),
            ]
        );

        // Nothing delegated → nothing enforceable (graceful degradation).
        assert!(enforceable_properties(&[]).is_empty());
    }

    #[test]
    fn compose_is_identity_when_no_scope_is_available() {
        // The degraded branch: limits unavailable → bwrap is launched unchanged.
        let bwrap = Path::new("/usr/bin/bwrap");
        let argv = vec![OsString::from("--unshare-all"), OsString::from("/bin/sh")];
        let (prog, full) = compose(None, bwrap, argv.clone());
        assert_eq!(prog, bwrap.to_path_buf());
        assert_eq!(full, argv);
    }

    #[test]
    fn compose_splices_bwrap_after_the_scope_prefix() {
        // The wrapped branch: the launcher runs, with bwrap and its argv after the
        // prefix's `--` marker. A fabricated wrapper keeps this host-independent.
        let bwrap = Path::new("/usr/bin/bwrap");
        let argv = vec![OsString::from("--unshare-all"), OsString::from("/bin/sh")];
        let launcher = PathBuf::from("/usr/bin/systemd-run");
        let prefix = vec![
            OsString::from("--user"),
            OsString::from("--scope"),
            OsString::from("--"),
        ];
        let (prog, full) = compose(Some((launcher.clone(), prefix)), bwrap, argv.clone());
        assert_eq!(prog, launcher);
        let marker = full.iter().position(|a| a == "--").expect("a -- marker");
        assert_eq!(full[marker + 1], bwrap.as_os_str());
        assert_eq!(&full[marker + 2..], &argv[..]);
    }

    /// The profile properties must produce the intended kernel limits, not merely
    /// parse. Launch a real transient scope carrying them and read the cgroup files
    /// back from inside it. Skips (does not fail) where no systemd user session can
    /// create a scope, so it is silent in a headless CI yet has teeth on a session.
    #[test]
    fn the_profile_properties_land_as_real_cgroup_limits() {
        let Some(systemd_run) = crate::pathfind::find_on_path("systemd-run") else {
            eprintln!("skipping cgroup landing test: no systemd-run");
            return;
        };
        if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
            eprintln!("skipping cgroup landing test: no systemd user session");
            return;
        }
        let delegated = delegated_controllers();
        let props = enforceable_properties(&delegated);
        if props.is_empty() {
            eprintln!("skipping cgroup landing test: no controller delegated");
            return;
        }

        // The command reports its own scope's limit files.
        let script = "b=/sys/fs/cgroup$(sed 's/^0:://' /proc/self/cgroup); \
             echo \"P=$(cat $b/pids.max 2>/dev/null)\"; \
             echo \"H=$(cat $b/memory.high 2>/dev/null)\"; \
             echo \"M=$(cat $b/memory.max 2>/dev/null)\"";
        let mut cmd = Command::new(&systemd_run);
        cmd.args(["--user", "--scope", "-q", "--collect"]);
        for p in &props {
            cmd.arg("-p").arg(p);
        }
        cmd.args(["--", "bash", "-c", script]);
        let out = cmd.output().expect("run a transient scope");
        if !out.status.success() {
            eprintln!("skipping cgroup landing test: scope did not launch");
            return;
        }
        let s = String::from_utf8_lossy(&out.stdout);
        let field = |k: &str| {
            s.lines()
                .find_map(|l| l.strip_prefix(k))
                .unwrap_or("")
                .trim()
                .to_string()
        };

        if delegated.iter().any(|c| c == "pids") {
            assert_eq!(
                field("P="),
                TASKS_MAX.to_string(),
                "TasksMax not applied: {s}"
            );
        }
        if delegated.iter().any(|c| c == "memory") {
            // Both legs land: a throttle threshold (high) below a hard cap (max),
            // each a concrete byte count rather than the unbounded `max`.
            let high = field("H=");
            let max = field("M=");
            assert_ne!(high, "max", "MemoryHigh left unbounded: {s}");
            assert_ne!(max, "max", "MemoryMax left unbounded: {s}");
            let (h, m): (u64, u64) = (high.parse().unwrap(), max.parse().unwrap());
            assert!(h < m, "throttle {h} should sit below the hard cap {m}");
        }
    }
}
