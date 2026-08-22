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

/// Overrides for the cage's resource limits, supplied by a trusted `[limits]` config table.
///
/// Each field, when `Some`, replaces the corresponding built-in default; `None` keeps the
/// default. The values are systemd-syntax tokens already validated by [`is_valid_memory_value`]
/// / [`is_valid_tasks_value`] at config-resolution time, so anything here is a value `systemd-run
/// -p` accepts — never a launch-bricking surprise.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Limits {
    /// Override for `MemoryHigh` (the throttle threshold), or `None` for the default.
    pub(crate) memory_high: Option<String>,
    /// Override for `MemoryMax` (the hard ceiling), or `None` for the default.
    pub(crate) memory_max: Option<String>,
    /// Override for `TasksMax` (the process/thread cap), or `None` for the default.
    pub(crate) tasks_max: Option<String>,
}

impl Limits {
    /// The effective `MemoryHigh` value (the override when set, else the default) and whether it
    /// came from a config override — for display by `sbx config` / `doctor`.
    pub(crate) fn memory_high(&self) -> (String, bool) {
        effective(&self.memory_high, MEMORY_HIGH)
    }

    /// The effective `MemoryMax` value and whether it was overridden.
    pub(crate) fn memory_max(&self) -> (String, bool) {
        effective(&self.memory_max, MEMORY_MAX)
    }

    /// The effective `TasksMax` value and whether it was overridden.
    pub(crate) fn tasks_max(&self) -> (String, bool) {
        match &self.tasks_max {
            Some(v) => (v.clone(), true),
            None => (TASKS_MAX.to_string(), false),
        }
    }
}

/// An effective limit value: the override when present, else `default`, with a flag telling the
/// two apart.
fn effective(override_value: &Option<String>, default: &str) -> (String, bool) {
    match override_value {
        Some(v) => (v.clone(), true),
        None => (default.to_string(), false),
    }
}

/// Whether `s` is a memory-limit value `systemd-run -p Memory{High,Max}=` accepts: `infinity`,
/// a percentage `N%` of physical RAM (0 < N ≤ 100), or a byte quantity — a decimal number with
/// an optional single uppercase `K`/`M`/`G`/`T`/`P`/`E` suffix (base-1024; no `B`, no `i`, no
/// lowercase). The grammar is verified against a real `systemd-run` in the tests, so the
/// validator can never accept a value that would later brick a launch. Stricter than systemd on
/// whitespace (any is rejected), keeping a config value tight and the `-p` token injection-free.
pub(crate) fn is_valid_memory_value(s: &str) -> bool {
    if s == "infinity" {
        return true;
    }
    if let Some(percent) = s.strip_suffix('%') {
        return is_unit_percent(percent);
    }
    // A byte quantity: a decimal number with at most one base-1024 suffix. `strip_suffix` only
    // strips when the last char is a suffix letter, so a bare integer (last char a digit) is left
    // whole and validated as a plain decimal.
    let number = s
        .strip_suffix(|c| matches!(c, 'K' | 'M' | 'G' | 'T' | 'P' | 'E'))
        .unwrap_or(s);
    is_decimal(number)
}

/// Whether `s` is a `TasksMax=` value systemd accepts: `infinity` or a positive integer (systemd
/// rejects `0`). A percentage (`N%` of the kernel pid limit) is a valid systemd form but is
/// deliberately *not* accepted here: its upper bound is exclusive (systemd rejects `TasksMax=100%`
/// while accepting `MemoryMax=100%`), an asymmetric and surprising boundary for an esoteric
/// feature — a task cap is naturally a count or `infinity`. Verified live against `systemd-run`.
pub(crate) fn is_valid_tasks_value(s: &str) -> bool {
    // `u64::parse` rejects a sign, whitespace, or any non-digit, so a positive integer is the
    // only accepted numeric form. `0` is excluded — systemd refuses `TasksMax=0`.
    s == "infinity" || matches!(s.parse::<u64>(), Ok(n) if n >= 1)
}

/// A non-negative decimal number — `D+` or `D+.D+`, no sign, space, or other character. Rejects
/// the empty string, a bare `.`, and a missing integer or fractional part (`2.`, `.5`).
fn is_decimal(s: &str) -> bool {
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (s, None),
    };
    let all_digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    all_digits(int_part) && frac_part.map(all_digits).unwrap_or(true)
}

/// Whether `s` (the part before a `%`) is a percentage in (0, 100]: a decimal systemd accepts as
/// a fraction of a resource. `0%` and anything over `100%` are rejected, matching systemd.
fn is_unit_percent(s: &str) -> bool {
    is_decimal(s) && matches!(s.parse::<f64>(), Ok(x) if x > 0.0 && x <= 100.0)
}

/// The smallest byte count a memory limit may sensibly carry. The kernel rejects a `MemoryMax`
/// below a page-aligned floor, and a memory value this small is almost always a percentage written
/// without its `%` (the `memory_max = 90` footgun — 90 *bytes*, not 90%). 1 MiB sits comfortably
/// below any real cap yet above any plausible typo, so it separates the mistake from a deliberate
/// (if unusual) tiny value.
const MIN_MEMORY_BYTES: u64 = 1024 * 1024;

/// Whether `token` is a **bare byte count** (a plain integer — no `%`, no unit suffix) below the
/// usable floor [`MIN_MEMORY_BYTES`]. A percentage, a unit-suffixed size, or `infinity` parses as
/// a non-integer and is never flagged — only an unadorned small integer is, so the config layer
/// can turn the most likely memory typo into a warning-and-default rather than a bricked launch.
/// Syntactic validity is a separate check ([`is_valid_memory_value`]); this only judges magnitude.
pub(crate) fn is_bare_byte_count_below_floor(token: &str) -> bool {
    matches!(token.parse::<u64>(), Ok(n) if n < MIN_MEMORY_BYTES)
}

/// The limit profile expressed as systemd unit properties, in `KEY=VALUE` form,
/// each tagged with the cgroup controller it needs so it can be dropped when that
/// controller is not delegated. A `[limits]` override replaces the matching default;
/// an unset field keeps it.
fn profile(limits: &Limits) -> Vec<(&'static str, String)> {
    let memory_high = limits.memory_high.as_deref().unwrap_or(MEMORY_HIGH);
    let memory_max = limits.memory_max.as_deref().unwrap_or(MEMORY_MAX);
    let tasks_max = limits
        .tasks_max
        .clone()
        .unwrap_or_else(|| TASKS_MAX.to_string());
    vec![
        ("memory", format!("MemoryHigh={memory_high}")),
        ("memory", format!("MemoryMax={memory_max}")),
        ("pids", format!("TasksMax={tasks_max}")),
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
    // SAFETY: `getuid` always succeeds and only reads the caller's id.
    let uid = unsafe { libc::getuid() };
    let Some(service) = delegation_root(path, uid) else {
        return Vec::new();
    };
    let file = format!("/sys/fs/cgroup{service}/cgroup.controllers");
    match std::fs::read_to_string(&file) {
        Ok(s) => s.split_whitespace().map(str::to_owned).collect(),
        Err(_) => Vec::new(),
    }
}

/// The cgroup path of the user manager's delegation root (`user@<uid>.service`) for a process whose
/// own cgroup is `cgroup_path`, or `None` when there is no user manager to delegate.
///
/// When the process already runs inside that service tree (a desktop terminal spawned by the user
/// manager) its own `user@<uid>.service` component is the root. But a login/SSH/TTY session lives at
/// `/user.slice/user-<uid>.slice/session-N.scope` — a *sibling* of `user@<uid>.service`, with no
/// `/user@` in its own path — while `systemd-run --user` still registers its scope under
/// `user@<uid>.service`; so for a process under this user's slice the canonical service path is the
/// sound controller upper bound, and searching only the current path (the old behavior) wrongly
/// found nothing and dropped the limits for every SSH launch. A cgroup outside this user's slice (a
/// system service, a container) has no user manager and yields `None`.
fn delegation_root(cgroup_path: &str, uid: u32) -> Option<String> {
    if let Some(i) = cgroup_path.find("/user@") {
        let end = cgroup_path[i + 1..]
            .find('/')
            .map(|j| i + 1 + j)
            .unwrap_or(cgroup_path.len());
        return Some(cgroup_path[..end].to_string());
    }
    if cgroup_path.contains(&format!("/user-{uid}.slice")) {
        return Some(format!("/user.slice/user-{uid}.slice/user@{uid}.service"));
    }
    None
}

/// The systemd unit properties that can actually be enforced here: the profile
/// filtered to the delegated controllers. Building the list from the delegated set
/// sidesteps having to know whether `systemd-run` rejects an undelegated property.
fn enforceable_properties(delegated: &[String], limits: &Limits) -> Vec<String> {
    profile(limits)
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
fn limiter(limits: &Limits) -> Option<(PathBuf, Vec<String>)> {
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
    let props = enforceable_properties(&delegated_controllers(), limits);
    if props.is_empty() {
        return None;
    }
    Some((systemd_run, props))
}

/// The `systemd-run` launcher and the argv prefix (ending with `--`) that wraps a
/// command in a transient scope carrying the enforceable limits, or `None` when no
/// limit can be applied on this host (graceful degradation).
///
/// Nothing here is dollar-escaped, and nothing needs to be: every value in the prefix is built from
/// a charset that cannot contain a `$` — [`super::naming::cage_slug`] sanitizes to `[a-z0-9-]`, and
/// a limit value has already passed [`is_valid_memory_value`] / [`is_valid_tasks_value`], neither of
/// which admits one — while the command past `--` is protected by asking the launcher not to
/// substitute at all.
fn scope_wrapper(limits: &Limits, cage_slug: &str) -> Option<(PathBuf, Vec<OsString>)> {
    let (systemd_run, props) = limiter(limits)?;
    let prefix = scope_prefix(&systemd_run, &props, cage_slug);
    Some((systemd_run, prefix))
}

/// The argv `systemd-run` is invoked with, up to and including the `--` that ends it: how a scope is
/// asked for, separate from whether one is worth asking for.
///
/// Split from [`scope_wrapper`] so the two questions do not travel together. Whether any limit can
/// be applied here depends on a delegation root [`limiter`] looks for, and a host without one has
/// nothing to say about how the arguments past `--` are treated — which is what the dollar guard
/// asserts. Folded into one function, that guard could only run where limits were also available,
/// and it went silent on exactly the host whose launcher behaves differently.
fn scope_prefix(systemd_run: &Path, props: &[String], cage_slug: &str) -> Vec<OsString> {
    let mut prefix = vec![
        OsString::from("--user"),
        OsString::from("--scope"),
        // Quiet (no "Running scope as unit" banner) and collect the transient unit once
        // it reaches a terminal state, so repeated launches do not accumulate dead units.
        OsString::from("-q"),
        OsString::from("--collect"),
        // Name the scope after the cage so it reads legibly in `systemctl --user`,
        // `ps`, and `systemd-cgls` instead of the opaque `run-p<pid>-i<pid>.scope`
        // systemd would auto-assign. `systemd-run` fails a launch outright on a live
        // unit-name collision, so uniqueness is load-bearing, not cosmetic: the launcher
        // pid distinguishes two cages of one project (which share a slug), and the one
        // multi-cage path in a single process (`sbx upgrade`) runs its cages sequentially.
        //
        // Uniqueness rests on those two facts and not on `--collect`, which reclaims a
        // name only once systemd considers the scope finished — and systemd learns that a
        // cgroup emptied through an inotify watch on it. A host with no watch descriptors
        // left never receives that notification: the scope stays `active running` with no
        // tasks in it, so there is no terminal state to collect and the name stays taken
        // for good. Reusing a name is therefore never safe on the strength of `--collect`.
        OsString::from(format!(
            "--unit={}",
            super::naming::scope_unit(cage_slug, std::process::id())
        )),
    ];
    // Say what to do with the dollars rather than assume it. `systemd-run` substitutes variable
    // references in the command line it is handed, against the **host's** environment, which would
    // rewrite a cage argument before bwrap ever saw it. Whether it does so with `--scope` is not a
    // fixed thing: systemd 254 made it an option and left it *off* for `--scope` "for backward
    // compatibility reasons", and a later systemd turned it on. A launch that doubles its dollars
    // to survive the substitution is therefore correct on exactly one of those, and broken on the
    // other — measured, as a preamble arriving at the shell with `$$` still in it.
    //
    // Asking for it off makes the question moot: nothing substitutes, so nothing needs escaping.
    // Where the option does not exist the systemd predates it, and that is precisely the era whose
    // behaviour it was kept compatible with — no substitution with `--scope` — so passing the
    // arguments through untouched is right there too.
    if expansion_can_be_disabled(systemd_run) {
        prefix.push(OsString::from("--expand-environment=no"));
    }
    for p in props {
        prefix.push(OsString::from("-p"));
        prefix.push(OsString::from(p));
    }
    prefix.push(OsString::from("--"));
    prefix
}

/// Wrap a bwrap invocation in the resource-limit scope. Returns the program to run
/// and its full argument list (excluding `argv[0]`). With limits available the
/// program becomes `systemd-run` and bwrap is spliced in after `--`; otherwise the
/// pair is returned unchanged so the caller launches bwrap directly.
pub(crate) fn wrap(
    bwrap: &Path,
    bwrap_argv: Vec<OsString>,
    limits: &Limits,
    cage_slug: &str,
) -> (PathBuf, Vec<OsString>) {
    compose(scope_wrapper(limits, cage_slug), bwrap, bwrap_argv)
}

/// The launcher pid encoded in a cage scope's unit name, or `None` when `name` is not one.
///
/// [`super::naming::scope_unit`] builds the name as `sbx-<slug>-<pid>.scope`, and a slug may itself
/// contain dashes and digits, so the pid is the segment after the **last** dash. Reading it as a
/// suffix instead would let `sbx-probe-342.scope` answer for pid 42, which would be enough for
/// [`sweep_stale_scopes`] to stop a live cage.
pub(crate) fn scope_launcher_pid(name: &str) -> Option<u32> {
    name.strip_prefix("sbx-")?
        .strip_suffix(".scope")?
        .rsplit_once('-')?
        .1
        .parse()
        .ok()
}

/// Every cage scope's cgroup directory under this user's slice.
///
/// The user manager decides where it registers a scope — under `user@<uid>.service/app.slice/` for a
/// desktop session, elsewhere for a login session — so the walk starts at the user slice rather than
/// assuming a path. A cage scope is a leaf here: nothing below one is another cage's scope, so the
/// walk does not descend into it. Unreadable directories are skipped rather than aborting the walk,
/// since every consumer is best-effort and a partial view does less than the whole, never something
/// wrong.
pub(crate) fn cage_scope_dirs() -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![PathBuf::from("/sys/fs/cgroup/user.slice")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let is_cage_scope = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| scope_launcher_pid(n).is_some());
            if is_cage_scope {
                found.push(path);
            } else {
                stack.push(path);
            }
        }
    }
    found
}

/// Whether a cage scope can be reclaimed: its launcher is gone **and** its cgroup holds no process.
///
/// Both halves are required, and which way each one fails is the whole safety argument. A live
/// launcher means a cage is running or starting under this scope, and a starting one has a
/// momentarily empty cgroup — between the unit's creation and bwrap being moved into it — so the pid
/// is what covers that window. A cgroup that still lists processes means the cage outlived its
/// launcher (it was reparented), which is a running cage whatever the pid segment says. `procs` is
/// `None` when the file could not be read, and that reads as "not empty": an unreadable cgroup
/// leaves an orphan behind rather than risking a live cage.
fn is_reclaimable(launcher_alive: bool, procs: Option<&str>) -> bool {
    !launcher_alive && procs.is_some_and(|p| p.trim().is_empty())
}

/// Stop the cage scopes left behind by launches that are over — best-effort, once per process,
/// before this one creates a scope of its own.
///
/// systemd normally collects a transient scope unaided: it watches the scope's cgroup with inotify
/// and reclaims the unit once the cgroup empties. Installing that watch can fail (the session's
/// inotify budget is shared with every other watcher on the host), and systemd treats the failure as
/// non-fatal. The notification then never arrives, so the scope stays `active running` over an empty
/// cgroup with no path to a terminal state — which also means `--collect` has nothing to collect.
/// Those units accumulate for the life of the session, and each one is walked again by every
/// consumer of [`cage_scope_dirs`], including the teardown's member lookup. This sweep is the
/// fallback for that case and for any other reason a scope outlives its cage.
///
/// [`is_reclaimable`] holds the decision and fails toward leaving an orphan. The launcher pid is
/// checked first so a scope belonging to a live launcher is never even read. The stop is
/// `--no-block`, so finding a large backlog does not delay the launch behind it.
pub(crate) fn sweep_stale_scopes() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let Some(systemctl) = crate::pathfind::find_on_path("systemctl") else {
            return;
        };
        let stale: Vec<OsString> = cage_scope_dirs()
            .into_iter()
            .filter_map(|dir| {
                let name = dir.file_name()?.to_str()?.to_string();
                let alive = crate::session::pid_is_live(scope_launcher_pid(&name)?);
                // Read the cgroup only once the launcher is known gone.
                let procs = if alive {
                    None
                } else {
                    std::fs::read_to_string(dir.join("cgroup.procs")).ok()
                };
                is_reclaimable(alive, procs.as_deref()).then(|| OsString::from(name))
            })
            .collect();
        if stale.is_empty() {
            return;
        }
        let _ = std::process::Command::new(systemctl)
            .args(["--user", "stop", "--no-block"])
            .args(&stale)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    });
}

/// Whether this `systemd-run` understands `--expand-environment=`, probed once per process.
///
/// Asked of the binary rather than derived from a version number, because a version is a second
/// source of truth that can disagree with the program actually on `PATH` — a backport, a container
/// image, a `systemd-run` provided by nix. Reasoning about behaviour from a version is what made a
/// launch depend on a default that is not the same everywhere.
fn expansion_can_be_disabled(systemd_run: &Path) -> bool {
    static PROBED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *PROBED.get_or_init(|| {
        std::process::Command::new(systemd_run)
            .arg("--help")
            .output()
            .is_ok_and(|o| {
                String::from_utf8_lossy(&o.stdout).contains("--expand-environment")
                    || String::from_utf8_lossy(&o.stderr).contains("--expand-environment")
            })
    })
}

/// Pure composition of a launch from an optional scope wrapper: with `Some` the
/// program becomes the launcher and bwrap is spliced in after its prefix;
/// with `None` (limits unavailable) the bwrap invocation is returned unchanged.
///
/// Split out from [`wrap`] so the host-independent degraded branch is testable.
///
/// Neither branch touches a dollar. The degraded one execs bwrap directly, with nothing in between
/// to interpret one; the wrapped one asks the launcher not to substitute at all
/// ([`expansion_can_be_disabled`]), so an argument reaches bwrap as it was written. Escaping here
/// instead — doubling each `$` for the launcher to undo — is what an earlier version did, and it
/// bound every launch to a systemd default that is not the same on every host.
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
pub(crate) fn probe(limits: &Limits) -> LimitReport {
    // The verdict comes from the same `limiter()` decision a launch takes, so the
    // report cannot drift from reality; only when limits *would* be applied does
    // the live scope confirm they actually work. Passing the effective `limits`
    // means the live scope also validates a config override, surfacing a bad value
    // in `doctor` rather than at a launch.
    let Some((systemd_run, props)) = limiter(limits) else {
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
        let p = profile(&Limits::default());
        // Memory is both throttled (high) and hard-capped (max); tasks are bounded.
        assert!(
            p.iter()
                .any(|(c, v)| *c == "memory" && v.starts_with("MemoryHigh="))
        );
        assert!(
            p.iter()
                .any(|(c, v)| *c == "memory" && v.starts_with("MemoryMax="))
        );
        assert!(
            p.iter()
                .any(|(c, v)| *c == "pids" && v.starts_with("TasksMax="))
        );
    }

    #[test]
    fn delegation_root_covers_the_session_scope_not_only_the_service_tree() {
        // A desktop terminal already inside the user manager's service tree: its own service is root.
        assert_eq!(
            delegation_root(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope",
                1000
            )
            .as_deref(),
            Some("/user.slice/user-1000.slice/user@1000.service")
        );
        // An SSH/TTY login session is a SIBLING of user@<uid>.service with no `/user@` of its own —
        // the canonical service path is derived from the uid so the limits are not silently dropped.
        assert_eq!(
            delegation_root("/user.slice/user-1000.slice/session-5.scope", 1000).as_deref(),
            Some("/user.slice/user-1000.slice/user@1000.service")
        );
        // A cgroup outside this user's slice has no user manager to delegate.
        assert_eq!(delegation_root("/system.slice/sshd.service", 1000), None);
        assert_eq!(
            delegation_root("/user.slice/user-42.slice/session-1.scope", 1000),
            None
        );
    }

    #[test]
    fn an_override_replaces_the_matching_default_and_leaves_the_rest() {
        // A partial override: only the memory ceiling and task cap are set, so the throttle
        // threshold keeps its default. This is the per-field model — a set field wins, an unset
        // one is untouched.
        let limits = Limits {
            memory_high: None,
            memory_max: Some("16G".to_string()),
            tasks_max: Some("8192".to_string()),
        };
        let p = profile(&limits);
        assert!(
            p.contains(&("memory", format!("MemoryHigh={MEMORY_HIGH}"))),
            "the unset throttle keeps its default: {p:?}"
        );
        assert!(
            p.contains(&("memory", "MemoryMax=16G".to_string())),
            "the ceiling is overridden: {p:?}"
        );
        assert!(
            p.contains(&("pids", "TasksMax=8192".to_string())),
            "the task cap is overridden: {p:?}"
        );
    }

    #[test]
    fn effective_values_report_override_versus_default() {
        let default = Limits::default();
        assert_eq!(default.memory_high(), (MEMORY_HIGH.to_string(), false));
        assert_eq!(default.memory_max(), (MEMORY_MAX.to_string(), false));
        assert_eq!(default.tasks_max(), (TASKS_MAX.to_string(), false));

        let custom = Limits {
            memory_high: None,
            memory_max: Some("16G".to_string()),
            tasks_max: Some("8192".to_string()),
        };
        // The unset field reads as the default (not overridden); the set ones as their override.
        assert_eq!(custom.memory_high(), (MEMORY_HIGH.to_string(), false));
        assert_eq!(custom.memory_max(), ("16G".to_string(), true));
        assert_eq!(custom.tasks_max(), ("8192".to_string(), true));
    }

    #[test]
    fn the_value_validators_accept_systemd_forms_and_reject_the_rest() {
        // Memory: infinity, bounded percentages, and decimal byte sizes with an uppercase
        // base-1024 suffix.
        for ok in [
            "infinity",
            "1%",
            "80%",
            "100%",
            "12.5%",
            "2M",
            "2G",
            "2T",
            "1P",
            "1E",
            "1024K",
            "2.5G",
            "2147483648",
        ] {
            assert!(is_valid_memory_value(ok), "memory should accept `{ok}`");
        }
        // Rejected: a `B` suffix, lowercase, an `i` suffix, an out-of-range or zero percentage,
        // whitespace, a bare suffix, and an empty value.
        for bad in [
            "2GB",
            "2MB",
            "2B",
            "2g",
            "2Gi",
            "0%",
            "150%",
            "%",
            "G",
            "",
            "2 G",
            " 2G",
            "80 %",
            "infinity ",
            "-5",
            "2.",
        ] {
            assert!(!is_valid_memory_value(bad), "memory should reject `{bad}`");
        }

        // Tasks: infinity or a positive integer. Never `0`, a percentage (deliberately
        // unsupported), a suffix, a sign, a decimal, or whitespace.
        for ok in ["infinity", "1", "8192", "16384"] {
            assert!(is_valid_tasks_value(ok), "tasks should accept `{ok}`");
        }
        for bad in ["0", "50%", "100%", "150%", "8K", "-5", "8 ", "", "1.5"] {
            assert!(!is_valid_tasks_value(bad), "tasks should reject `{bad}`");
        }
    }

    #[test]
    fn a_bare_small_memory_integer_is_flagged_but_units_and_percentages_are_not() {
        // The `memory_max = 90` footgun: a bare integer below 1 MiB is almost certainly a
        // percentage missing its `%`, so it is flagged for the config layer to drop.
        for flagged in ["90", "0", "1", "1048575"] {
            assert!(
                is_bare_byte_count_below_floor(flagged),
                "`{flagged}` should be flagged as a likely typo"
            );
        }
        // A deliberate unit, a percentage, `infinity`, or a byte count at/above the floor is never
        // flagged — only a bare small integer is.
        for ok in [
            "1048576", "2097152", "64K", "16G", "90%", "infinity", "2.5G",
        ] {
            assert!(
                !is_bare_byte_count_below_floor(ok),
                "`{ok}` must not be flagged"
            );
        }
    }

    #[test]
    fn properties_are_filtered_to_delegated_controllers() {
        let defaults = Limits::default();
        // Only `pids` delegated → only the task cap survives.
        let only_pids = enforceable_properties(&["pids".to_string()], &defaults);
        assert_eq!(only_pids, vec![format!("TasksMax={TASKS_MAX}")]);

        // Only `memory` delegated → both memory properties, no task cap.
        let only_mem = enforceable_properties(&["memory".to_string()], &defaults);
        assert_eq!(
            only_mem,
            vec![
                format!("MemoryHigh={MEMORY_HIGH}"),
                format!("MemoryMax={MEMORY_MAX}"),
            ]
        );

        // Nothing delegated → nothing enforceable (graceful degradation).
        assert!(enforceable_properties(&[], &defaults).is_empty());
    }

    #[test]
    fn compose_is_identity_when_no_scope_is_available() {
        // The degraded branch: limits unavailable → bwrap is launched unchanged. The dollar-carrying
        // argument is the load-bearing case: nothing sits between here and bwrap to interpret it, so
        // escaping it would deliver literal doubled dollars to the cage.
        let bwrap = Path::new("/usr/bin/bwrap");
        let argv = vec![
            OsString::from("--unshare-all"),
            OsString::from("--setenv"),
            OsString::from("X"),
            OsString::from("${HOME}"),
            OsString::from("/bin/sh"),
        ];
        let (prog, full) = compose(None, bwrap, argv.clone());
        assert_eq!(prog, bwrap.to_path_buf());
        assert_eq!(full, argv);
    }

    #[test]
    fn neither_branch_rewrites_a_dollar_in_the_program_or_its_arguments() {
        // Composition hands every byte through as written, program and arguments alike: the wrapped
        // branch keeps the launcher from substituting rather than pre-escaping for it, so there is
        // no longer a form that differs between what is composed and what bwrap receives.
        let bwrap = Path::new("/opt/pre$fix/bwrap");
        let argv = vec![
            OsString::from("--setenv"),
            OsString::from("X"),
            OsString::from("${HOME}"),
            OsString::from("--bind"),
            OsString::from("/data/a$b"),
            OsString::from("/bin/sh"),
        ];
        let prefix = vec![OsString::from("--scope"), OsString::from("--")];
        let (_prog, full) = compose(
            Some((PathBuf::from("/usr/bin/systemd-run"), prefix)),
            bwrap,
            argv,
        );
        let marker = full.iter().position(|a| a == "--").expect("a -- marker");
        assert_eq!(
            full[marker + 1],
            OsString::from("/opt/pre$fix/bwrap"),
            "the program keeps its single dollar"
        );
        assert_eq!(
            &full[marker + 2..],
            &[
                OsString::from("--setenv"),
                OsString::from("X"),
                OsString::from("${HOME}"),
                OsString::from("--bind"),
                OsString::from("/data/a$b"),
                OsString::from("/bin/sh"),
            ][..]
        );
    }

    /// An argument carrying a dollar must reach the program byte-identical, or cage arguments are
    /// silently rewritten on their way in.
    ///
    /// Driven through the production composition — [`scope_wrapper`] builds the prefix and
    /// [`compose`] splices the command in — rather than through an invocation assembled here. They
    /// have to be the same one: a hand-written prefix goes on agreeing with itself while the launch
    /// it stands for breaks, and that is precisely how a doubled dollar shipped, on every host
    /// whose launcher did not undo the doubling.
    ///
    /// Skips (does not fail) where no user session can create a scope, so it is silent on a
    /// headless host yet has teeth on a session.
    #[test]
    fn a_dollar_argument_reaches_the_program_verbatim() {
        let Some(printf) = crate::pathfind::find_on_path("printf") else {
            skip_incapable!("skipping dollar test: no printf on PATH");
            return;
        };
        let Some(systemd_run) = crate::pathfind::find_on_path("systemd-run") else {
            skip_incapable!("skipping dollar test: no systemd-run on PATH");
            return;
        };
        // The production invocation, with no limit properties: what is under test is how the
        // arguments past `--` are treated, and that does not depend on whether this host delegates
        // a controller. Going through `scope_wrapper` instead would tie the guard to a delegation
        // root, and it would fall silent on precisely the hosts whose launcher differs.
        let run = |slug: &str, args: &[&str]| -> Option<std::process::Output> {
            let prefix = scope_prefix(&systemd_run, &[], slug);
            let mut argv: Vec<OsString> = vec![OsString::from("%s\n")];
            argv.extend(args.iter().map(|a| OsString::from(*a)));
            let (prog, argv) = compose(Some((systemd_run.clone(), prefix)), &printf, argv);
            Command::new(prog)
                .args(argv)
                .output()
                .ok()
                .filter(|o| o.status.success())
        };
        // A baseline scope must work here, or there is no usable session — then a failure would be
        // the host rather than a drift in what reaches the program, so skip. Its own slug, because
        // a scope is named after the launcher pid and both calls come from this one process.
        if run("dollar-baseline", &["baseline"]).is_none() {
            skip_incapable!("skipping dollar test: cannot create a user scope here");
            return;
        }

        let raw = ["${v%/}", "$HOME", "a$b", "plain"];
        let out = run("dollar-probe", &raw).expect("the scope launches");
        let got: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_string)
            .collect();
        let want: Vec<String> = raw.iter().map(|s| s.to_string()).collect();
        assert_eq!(got, want, "arguments must arrive unchanged");
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

    #[test]
    fn a_scope_wrapper_names_the_unit_after_the_cage() {
        // The scope carries a legible unit name built from the cage slug, so a running
        // cage is identifiable in `systemctl --user`/`ps`/`systemd-cgls` rather than
        // systemd's opaque `run-p<pid>-i<pid>.scope`. Skips where no user session can
        // create a scope (as the landing test does), so it is silent in a headless CI.
        if crate::pathfind::find_on_path("systemd-run").is_none()
            || std::env::var_os("XDG_RUNTIME_DIR").is_none()
        {
            skip_incapable!("skipping scope-unit test: no systemd user session");
            return;
        }
        let Some((_launcher, prefix)) = scope_wrapper(&Limits::default(), "demo-app") else {
            skip_incapable!("skipping scope-unit test: no delegated controller");
            return;
        };
        let unit = prefix
            .iter()
            .find_map(|a| a.to_str()?.strip_prefix("--unit="))
            .expect("a --unit= argument is present");
        assert!(
            unit.starts_with("sbx-demo-app-") && unit.ends_with(".scope"),
            "the unit is named after the cage slug: {unit}"
        );
        // The pid segment is the launcher's, keeping concurrent same-slug scopes distinct.
        assert!(
            unit.contains(&std::process::id().to_string()),
            "the unit carries the launcher pid: {unit}"
        );
    }

    #[test]
    fn a_scope_name_yields_the_launcher_pid_at_the_last_dash() {
        assert_eq!(scope_launcher_pid("sbx-probe-42.scope"), Some(42));
        // A slug carrying its own dashes and digits does not shift the pid segment.
        assert_eq!(scope_launcher_pid("sbx-my-app-2-42.scope"), Some(42));
        // The segment is read whole, so a longer pid ending in the same digits is a different pid.
        // This is what keeps the sweep from mistaking one cage's scope for another's.
        assert_eq!(scope_launcher_pid("sbx-probe-342.scope"), Some(342));
        // Not a cage scope: another unit's name, another unit type, no pid segment at all.
        assert_eq!(scope_launcher_pid("user-1000.slice"), None);
        assert_eq!(scope_launcher_pid("other-probe-42.scope"), None);
        assert_eq!(scope_launcher_pid("sbx-probe-42.service"), None);
        assert_eq!(scope_launcher_pid("sbx-probe-none.scope"), None);
    }

    #[test]
    fn only_a_dead_launcher_over_an_empty_cgroup_is_reclaimable() {
        // The one reclaimable shape: the launcher is gone and the cgroup holds nothing.
        assert!(is_reclaimable(false, Some("")));
        assert!(is_reclaimable(false, Some("\n")));
        // A live launcher holds its scope even while the cgroup is momentarily empty — the window
        // between the unit's creation and bwrap being moved into it.
        assert!(!is_reclaimable(true, Some("")));
        // A cage reparented off its launcher still lists processes, so the scope is in use.
        assert!(!is_reclaimable(false, Some("4711\n")));
        assert!(!is_reclaimable(true, Some("4711\n")));
        // An unreadable cgroup reads as in-use: leave an orphan rather than risk a running cage.
        assert!(!is_reclaimable(false, None));
    }

    #[test]
    fn the_cgroup_walk_yields_only_cage_scopes() {
        // Exercises the real walk against this host's cgroup tree. Finding nothing is a legitimate
        // outcome (no cage is running); what is asserted is that whatever it does find is a cage
        // scope, since the sweep acts on the result.
        for dir in cage_scope_dirs() {
            let name = dir
                .file_name()
                .and_then(|n| n.to_str())
                .expect("a cage scope directory has a utf-8 name");
            assert!(
                scope_launcher_pid(name).is_some(),
                "the walk yielded a directory that is not a cage scope: {name}"
            );
            assert!(
                dir.join("cgroup.procs").exists(),
                "a cage scope carries a cgroup.procs: {}",
                dir.display()
            );
        }
    }

    /// The profile properties must produce the intended kernel limits, not merely
    /// parse. Launch a real transient scope carrying them and read the cgroup files
    /// back from inside it. Skips (does not fail) where no systemd user session can
    /// create a scope, so it is silent in a headless CI yet has teeth on a session.
    #[test]
    fn the_profile_properties_land_as_real_cgroup_limits() {
        let Some(systemd_run) = crate::pathfind::find_on_path("systemd-run") else {
            skip_incapable!("skipping cgroup landing test: no systemd-run");
            return;
        };
        if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
            skip_incapable!("skipping cgroup landing test: no systemd user session");
            return;
        }
        let delegated = delegated_controllers();
        let props = enforceable_properties(&delegated, &Limits::default());
        if props.is_empty() {
            skip_incapable!("skipping cgroup landing test: no controller delegated");
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
            skip_incapable!("skipping cgroup landing test: scope did not launch");
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

    /// Every value form the validators accept must be one a real `systemd-run` accepts — a drift
    /// would let a config override brick *every* launch of a project (the launch execs
    /// `systemd-run`, which exits non-zero before bwrap on a rejected property). Drive a throwaway
    /// scope per form and assert it launches. Memory forms are tried on `MemoryHigh`, which has no
    /// minimum-value floor, so this proves grammar compatibility without a magnitude confound.
    ///
    /// Skips (does not fail) where no user session can create a scope, so it is silent in headless
    /// CI yet has teeth on a session.
    #[test]
    fn every_accepted_value_is_one_systemd_run_accepts() {
        let Some(systemd_run) = crate::pathfind::find_on_path("systemd-run") else {
            skip_incapable!("skipping systemd grammar test: no systemd-run");
            return;
        };
        let launches = |prop: Option<&str>| {
            let mut cmd = Command::new(&systemd_run);
            cmd.args(["--user", "--scope", "-q", "--collect"]);
            if let Some(p) = prop {
                cmd.arg("-p").arg(p);
            }
            cmd.args(["--", "true"]);
            cmd.status().map(|s| s.success()).unwrap_or(false)
        };
        // A baseline scope with no property must launch here, or there is no usable session — then
        // a per-form failure would be the host, not a validator drift, so skip rather than fail.
        if !launches(None) {
            skip_incapable!("skipping systemd grammar test: cannot create a user scope here");
            return;
        }

        let memory = [
            "infinity",
            "1%",
            "80%",
            "100%",
            "12.5%",
            "2M",
            "2G",
            "2T",
            "1P",
            "1024K",
            "2.5G",
            "2147483648",
        ];
        for v in memory {
            assert!(is_valid_memory_value(v), "validator should accept `{v}`");
            assert!(
                launches(Some(&format!("MemoryHigh={v}"))),
                "systemd-run rejected `MemoryHigh={v}` the validator accepted"
            );
        }

        let tasks = ["infinity", "1", "8192", "16384"];
        for v in tasks {
            assert!(is_valid_tasks_value(v), "validator should accept `{v}`");
            assert!(
                launches(Some(&format!("TasksMax={v}"))),
                "systemd-run rejected `TasksMax={v}` the validator accepted"
            );
        }
    }
}
