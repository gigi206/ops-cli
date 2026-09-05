//! The **task mise pool**: a mise install pool sbx fills host-side and mounts read-only into every
//! task cage.
//!
//! # Why it exists
//!
//! A task's program must come from a tree the agent cannot write, or "sbx fixes the program" is a
//! fiction. Every other package backend already satisfies that: `nix:`, a remote `flake:`, `deb:`,
//! `appimage:`, `tarball:` and `prebuilt:` all build **host-side into the shared store**, which a
//! task cage mounts read-only. Only `mise:` does not — it installs *in-cage*, under a writable
//! `$HOME`, so the pool the agent uses is agent-mutable by construction.
//!
//! Excluding `mise:` outright would cut off the npm/pipx/aqua-backed CLIs, which is too much to
//! lose. So a task declares the mise tools it needs (`[task.<name>] packages`) and sbx installs
//! them into a **third mise scope**, beside the per-project pool (`MISE_DATA_DIR`) and the
//! app-global one (`MISE_SHARED_INSTALL_DIRS`): a pool no cage ever mounts writable.
//!
//! # The two cages, and the one path they must agree on
//!
//! The pool is filled by an **install cage** — the task cage's own skeleton with the pool bound
//! read-write and the host network — and read by **task cages**, which bind it read-only. Both must
//! see it at the *same* in-cage path, [`POOL_INCAGE`], and that is not tidiness: `mise install`
//! bakes absolute paths into what it writes (npm shims, python console-script shebangs, venv
//! `pyvenv.cfg`, mise's own backend metadata). A pool installed under one path and read under
//! another yields tools that fail with `ENOENT` on their own interpreter — a failure that reads as
//! "the install broke", not "the mount moved". `the_install_and_task_cages_agree_on_the_pool_path`
//! pins it.
//!
//! # Where the network comes from
//!
//! The install runs with the **host** network, like every other host-side provisioning step
//! (`nix build` for a `nix:` package). A cage's `network` allowlist governs what the *agent* may
//! reach; it is not a budget for sbx's own setup, and routing an install through it would demand
//! that the author allowlist registries they never asked to talk to.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::inspect::{self, InstalledTool};
use super::spec::{Mount, NetPolicy, SandboxSpec};

/// Where the task pool is bound **in both cages** — read-write while it is being filled, read-only
/// once a task reads it. Under `/opt/sbx`, disjoint from every structural mount. Changing this
/// invalidates a pool already on disk (the absolute paths mise baked into it), so it is a fixed
/// path, never derived.
pub(crate) const POOL_INCAGE: &str = "/opt/sbx/task-mise";

/// The install cage's `$HOME`: a tmpfs, so a backend that insists on writing beside `$HOME` has
/// somewhere to do it without that landing in the pool a task later reads.
const INSTALL_HOME: &str = "/tmp/task-install-home";

/// The wall-clock ceiling on one pool install. Generous — a cold `npm:`/`pipx:` install legitimately
/// takes minutes — but present, because a wedged registry connection would otherwise hang the
/// launch itself, before the agent ever starts. Fixed, not a `[task.defaults]` knob.
const INSTALL_TIMEOUT: Duration = Duration::from_secs(600);

/// How often the install runner checks for exit while enforcing [`INSTALL_TIMEOUT`]. Coarser than
/// the task runner's: an install is a minutes-long operation, so a quarter-second granularity costs
/// nothing and spins far less.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// The host path of a project's task pool. Under the project's own runtime tree, so `sbx projects
/// rm` and the dead-tree reap reclaim it with the rest of the project — no pool-specific
/// housekeeping to write, and none to forget.
///
/// The cost of keying it per project is duplication: a heavy tool (a node or python runtime) is
/// installed once per project a global app launches in. That is the ship-now trade — lifecycle
/// correctness for disk — and a shared pool remains available later, since the *in-cage* path is
/// fixed and the host path is therefore free to move.
pub(crate) fn pool_dir(data_dir: &Path, project_id: &str) -> PathBuf {
    data_dir.join("projects").join(project_id).join("task-mise")
}

/// The pool's `installs/` directory, mise's own layout under a data dir.
fn installs_dir(pool: &Path) -> PathBuf {
    pool.join("installs")
}

/// Split a mise token into its tool locator and its explicit version, if it carries one.
///
/// mise's separator is `@`, which also opens an npm scope (`npm:@example/tool`), so the split is
/// looked for only in the token's **last path segment** and only past its first character:
/// `npm:@example/tool` has no version, `npm:@example/tool@1.2` has `1.2`, `node@22` has `22`.
fn split_version(token: &str) -> (&str, Option<&str>) {
    let segment_start = token.rfind('/').map(|i| i + 1).unwrap_or(0);
    let segment = &token[segment_start..];
    match segment.char_indices().skip(1).find(|(_, c)| *c == '@') {
        Some((offset, _)) => {
            let at = segment_start + offset;
            (&token[..at], Some(&token[at + 1..]))
        }
        None => (token, None),
    }
}

/// Whether an installed version directory `dir` answers the declared version `wanted`, and which:
/// exactly, or as one of mise's **partial** versions — `22` and `22.3` both name `22.3.0`.
///
/// Compared segment-wise rather than as a string prefix, or `2` would answer `22.3.0` and a
/// declaration would be served by a version it never named.
fn answers_version(dir: &str, wanted: &str) -> bool {
    dir == wanted
        || dir
            .strip_prefix(wanted)
            .is_some_and(|rest| rest.starts_with('.'))
}

/// The installed version that answers `token`'s declared version, given what the pool realized for
/// the tool — the half of the satisfaction rule that reads `installs/`.
///
/// - an exact `@version` selects the directory of that name;
/// - a **partial** `@version` (`22`, `22.3`) selects the concrete version it names. mise records the
///   spec verbatim and materializes the partial as a *symlink* beside the concrete directory, and
///   [`inspect::mise_installed_in`] keeps only real directories — so looking for a directory called
///   `22` can never find one, however successfully the tool installed;
/// - a named alias (`latest`, and mise's channel aliases) resolves like a bare token, for the same
///   reason and because the alias the config records is what a shim resolves through. `mise use -g
///   node@latest` and `mise use -g node` write the same `[tools]` entry, so they must not be two
///   different questions here;
/// - a bare token prefers mise's `latest` alias — which is exactly what a bare request resolved to
///   — and otherwise takes the highest concrete version, so a pool that accumulated two versions
///   answers with a *chosen* one rather than an arbitrary one.
///
/// Nothing is put on a task's `PATH` from this: [`shims_incage`] is. What this decides is whether
/// the pool holds the tool the declaration asked for, and a spelling it can never answer is a token
/// reported missing on every launch, forever.
fn version_dir(tool: &InstalledTool, wanted: Option<&str>) -> Option<String> {
    match wanted {
        // The alias or the exact version, whenever mise materialized it as a real directory.
        Some(v) if tool.versions.iter().any(|d| d == v) => Some(v.to_string()),
        // A version-shaped spec is honoured as declared: only a concrete version it names answers
        // it, so `node@22` is never served by an installed `node@24`.
        Some(v) if v.starts_with(|c: char| c.is_ascii_digit()) => {
            let concrete = inspect::concrete_versions(tool);
            // `mise_installed_in` sorts ascending, so the last match is the highest.
            concrete
                .iter()
                .rev()
                .find(|d| answers_version(d.as_str(), v))
                .cloned()
        }
        // A bare token, or a named alias mise resolved to something concrete.
        Some(_) | None => {
            if tool.versions.iter().any(|d| d == "latest") {
                return Some("latest".to_string());
            }
            // `mise_installed_in` sorts ascending, so the last concrete entry is the highest.
            inspect::concrete_versions(tool).last().cloned()
        }
    }
}

/// What the pool holds for a set of declared tokens.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PoolBins {
    /// In-cage directories to prepend to the task's `PATH` — mise's shims directory, once, when the
    /// pool satisfies at least one token. See [`shims_incage`] for why it is the shims and not the
    /// install directories.
    pub(crate) bins: Vec<PathBuf>,
    /// Declared tokens with no matching install — reported, never silently skipped, so a caller
    /// learns the task will fail before invoking it.
    pub(crate) missing: Vec<String>,
}

/// The in-cage directory a task's `PATH` gets: **mise's shims**, not the install directories.
///
/// Guessing where a backend puts its executables does not work — the layout is the backend's, not
/// mise's. An `aqua:` tarball extracts to `<version>/<vendor-archive-name>/<binary>`, an `npm:` tool
/// lands in `<version>/bin`, a `pipx:` one in a venv. mise's answer to that is the shim: one entry
/// per executable, in a single directory, which re-execs mise to resolve the real path at exec time.
/// That is its documented mechanism, it is what the agent cage already puts on `PATH`, and it is the
/// only thing that covers every backend.
///
/// A shim points at the mise binary in the shared store and reads the pool — both trees no cage can
/// write — so the program is still fixed by the declaration, resolved through immutable state.
fn shims_incage() -> PathBuf {
    Path::new(POOL_INCAGE).join("shims")
}

/// The version spec the pool's global config records for each tool — `<pool>/config/config.toml`'s
/// `[tools]` table, which the install's `mise use -g` writes and a shim then **resolves through**.
///
/// Parsed line-wise (it is a tiny flat table), the same way the install metadata is read, so this
/// needs no TOML dependency here. A bare request is recorded as `"latest"`, a pinned one as its
/// version — `ripgrep = "latest"`, `"aqua:cli/gh" = "2.62.0"`.
fn recorded_specs(pool: &Path) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let Ok(body) = std::fs::read_to_string(pool.join("config/config.toml")) else {
        return out;
    };
    let mut in_tools = false;
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_tools = line == "[tools]";
            continue;
        }
        if !in_tools {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().trim_matches('"');
        let value = value.trim().trim_matches('"');
        if !key.is_empty() && !value.is_empty() {
            out.insert(key.to_string(), value.to_string());
        }
    }
    out
}

/// The version spec a declared token asks the pool to record. A bare token asks for whatever mise
/// resolves, which `mise use` writes as `latest`.
fn wanted_spec(wanted: Option<&str>) -> &str {
    wanted.unwrap_or("latest")
}

/// Reduce `tokens` to one version spec per tool, and report the spellings that had to go as
/// `(dropped, kept)` pairs.
///
/// One pool is one global mise config and one `shims/` directory. `mise use -g` writes a single
/// `[tools]` entry per tool, [`recorded_specs`] reads back a single spec per tool, and mise cannot
/// put two versions of one tool on one `PATH` either — so two tasks declaring `mise:node@22` and
/// `mise:node@24` are not two installs. They are one entry, and whichever spelling the config does
/// not hold can never satisfy [`bins_for`].
///
/// Left to run, that is not a token that merely fails: [`ensure`]'s warm short-circuit never fires,
/// so every launch of the project pays a full bwrap + mise install-cage run before the agent starts,
/// and the install rewrites the one `[tools]` entry to whatever it was last asked for — so the pin
/// flips launch to launch and the two tasks take turns failing.
///
/// Declaration order decides: the first spelling of a tool is the one the pool is filled for. That
/// is the half that stops the loop; naming the rest is the half the author can act on, since only a
/// declaration change can actually resolve it. A repeat of the *same* spec is not a conflict — a
/// bare token and an explicit `@latest` are one request, which is what [`wanted_spec`] says.
fn one_spec_per_tool(tokens: &[String]) -> (Vec<String>, Vec<(String, String)>) {
    let mut kept: Vec<String> = Vec::new();
    let mut conflicting: Vec<(String, String)> = Vec::new();
    for token in tokens {
        let (locator, wanted) = split_version(token);
        // Taken by value rather than held as a reference: the `None` arm appends to the same vector
        // the search read.
        let first = kept
            .iter()
            .find(|k| split_version(k.as_str()).0 == locator)
            .cloned();
        match first {
            Some(first) if wanted_spec(split_version(&first).1) != wanted_spec(wanted) => {
                conflicting.push((token.clone(), first));
            }
            Some(_) => {}
            None => kept.push(token.clone()),
        }
    }
    (kept, conflicting)
}

/// Resolve `tokens` against the pool realized on disk. Pure filesystem reads; no mise, no network.
///
/// A token counts as satisfied only when **both** halves agree: the tool is realized under
/// `installs/`, *and* the pool's config records the version the declaration asks for. Checking only
/// the installs would drift — the shim resolves through the config, not the directory, so a pool
/// that still holds `node@24` from an earlier declaration would satisfy a re-declared `node@24`
/// while the config, last written for `node@22`, kept running 22. Silently.
///
/// A mismatch costs one install-cage run that finds everything downloaded already and just rewrites
/// the config, so failing *toward* re-running is cheap — and being wrong the other way is not.
///
/// Matching prefers the backend token mise recorded for each install over the munged directory name
/// (see [`InstalledTool::is`]) — the munge is best-effort observed naming, the recorded token is
/// what mise itself says the install is.
pub(crate) fn bins_for(pool: &Path, tokens: &[String]) -> PoolBins {
    let installed = inspect::mise_installed_in(&installs_dir(pool));
    let recorded = recorded_specs(pool);
    let mut out = PoolBins::default();
    let mut satisfied = false;
    for token in tokens {
        let (locator, wanted) = split_version(token);
        let realized = installed
            .iter()
            .find(|t| t.is(locator))
            .and_then(|t| version_dir(t, wanted))
            .is_some();
        let pinned = recorded.get(locator).map(String::as_str) == Some(wanted_spec(wanted));
        if realized && pinned {
            satisfied = true;
        } else {
            out.missing.push(token.clone());
        }
    }
    if satisfied {
        out.bins.push(shims_incage());
    }
    out
}

/// What one [`ensure`] did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PoolOutcome {
    /// Every declared token was already installed — no cage was started at all. The warm path, and
    /// the common one: a pool is filled once per project, not once per launch.
    Warm,
    /// An install ran. `installed` are the tokens it was asked for; `still_missing` are the ones the
    /// pool still does not satisfy afterwards, measured against the **whole** declaration (mise
    /// reported success for the run as a whole, or the run failed, but these tools are not there —
    /// and a spelling dropped by [`one_spec_per_tool`] is one of them, since the pool genuinely does
    /// not hold it).
    Installed {
        installed: Vec<String>,
        still_missing: Vec<String>,
    },
}

/// Fill the pool so every token in `tokens` is realized, and report what happened.
///
/// Short-circuits before doing anything when the pool already satisfies every token, so a warm
/// launch costs one directory listing. Otherwise it runs `mise install` for the missing ones in an
/// install cage: the task cage's own skeleton (hermetic FHS, `/nix` read-only from the shared
/// store, the base userland on `PATH` — `curl` and `git` are in it, which is what mise's backends
/// fetch with), the pool bound **read-write** at [`POOL_INCAGE`], a tmpfs `$HOME`, and the host
/// network.
///
/// `base_mounts` and `base_env` are the task cage's, so the pool is built by the same userland that
/// will run the tools — the one thing an install pool must not get wrong.
///
/// Tokens naming two versions of one tool are reduced to one first (see [`one_spec_per_tool`]) and
/// the rest reported: a pool cannot hold both, and filling it for the whole set would make the
/// install cage run on every launch of the project without ever converging.
#[allow(clippy::too_many_arguments)]
pub(crate) fn ensure(
    bwrap: &Path,
    base_mounts: &[Mount],
    base_env: &[(String, String)],
    mise_bin: &Path,
    pool: &Path,
    tokens: &[String],
    limits: &super::cgroup::Limits,
    slug: &str,
) -> io::Result<PoolOutcome> {
    if tokens.is_empty() {
        return Ok(PoolOutcome::Warm);
    }
    // A tool the declarations disagree about is filled for one of them and reported for the rest:
    // one pool records one version per tool, so carrying the conflict forward would run this install
    // cage on every launch of the project without ever converging.
    let (fillable, conflicting) = one_spec_per_tool(tokens);
    for (dropped, kept) in &conflicting {
        crate::diag::warn(&format!(
            "the task tool pool holds one version of each tool, so `{dropped}` cannot be installed \
             beside `{kept}` — the pool is filled for `{kept}`, and every task declaring \
             `{dropped}` will fail to find it until the declarations agree"
        ));
    }
    let missing = bins_for(pool, &fillable).missing;
    if missing.is_empty() {
        return Ok(PoolOutcome::Warm);
    }

    ensure_pool_dir(pool)?;
    // One filler at a time. Two sessions launched cold on the same project would otherwise run two
    // `mise install`s into the same tree, and mise gives no cross-process guarantee about that. The
    // lock is taken *before* the missing set is recomputed below, so the second session sees what
    // the first installed and does nothing rather than redoing it.
    let _lock = lock_pool(pool)?;
    let missing = bins_for(pool, &fillable).missing;
    if missing.is_empty() {
        return Ok(PoolOutcome::Warm);
    }
    // Say what is happening before it takes minutes. A cold install is the one launch step that can
    // stall visibly, and an unannounced stall reads as a hang.
    eprintln!("sbx: installing task tools: {}", missing.join(", "));
    let spec = install_spec(base_mounts, base_env, mise_bin, pool, &missing)?;
    let output = run(bwrap, &spec, limits, slug)?;
    // mise's own diagnostics are the only way to tell a registry outage from a typo'd token, so a
    // failed run surfaces them rather than swallowing them behind a generic message. No credential
    // is ever in scope here — a pool install carries none — so this needs no substitution pass.
    if !output.ok {
        let tail = String::from_utf8_lossy(output.diagnostics());
        let tail = tail.trim();
        crate::diag::warn(&format!(
            "the task tool pool did not install {} — {}",
            missing.join(", "),
            if tail.is_empty() { "no output" } else { tail }
        ));
    }
    let still_missing = bins_for(pool, tokens).missing;
    Ok(PoolOutcome::Installed {
        installed: missing,
        still_missing,
    })
}

/// An advisory lock serialising the fills of one pool. Held only for its `Drop` — closing the fd is
/// what releases the `flock`.
struct PoolLock(#[allow(dead_code)] std::fs::File);

/// Take the pool's fill lock, exclusive, blocking until it is granted. The lock file is a **sibling**
/// of the pool rather than a file inside it, so it never appears among the installs the resolver
/// enumerates and never travels into a cage.
fn lock_pool(pool: &Path) -> io::Result<PoolLock> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let mut path = pool.as_os_str().to_os_string();
    path.push(".lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(PathBuf::from(path))?;
    // SAFETY: `flock` on a valid owned fd; it blocks until the lock is granted and returns 0 on
    // success. The fd lives in the returned guard, so the lock is held until the guard drops.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PoolLock(file))
}

/// Roll the pool's tools forward: `mise upgrade <tokens>` in the same install cage [`ensure`] uses.
///
/// Without this a pool tool is frozen for good. `mise use -g` records a concrete spec, and once the
/// declaration and the record agree [`bins_for`] short-circuits every launch — so nothing would ever
/// re-resolve a bare `mise:jq` to a newer release. A pinned `mise:node@22` is *meant* to be frozen
/// and mise leaves it alone; this rolls the ones whose spec still floats.
///
/// Returns the install's output for the caller to report, or `None` when there is nothing to roll.
#[allow(clippy::too_many_arguments)]
pub(crate) fn upgrade(
    bwrap: &Path,
    base_mounts: &[Mount],
    base_env: &[(String, String)],
    mise_bin: &Path,
    pool: &Path,
    tokens: &[String],
    limits: &super::cgroup::Limits,
    slug: &str,
) -> io::Result<Option<InstallRun>> {
    if tokens.is_empty() || !pool.is_dir() {
        return Ok(None);
    }
    let _lock = lock_pool(pool)?;
    let mut spec = install_spec(base_mounts, base_env, mise_bin, pool, tokens)?;
    spec.cmd = upgrade_argv(mise_bin, tokens);
    Ok(Some(run(bwrap, &spec, limits, slug)?))
}

/// The roll command: `mise upgrade <tokens>`, the same verb the agent's own `mise:` packages roll
/// with. Each token is stripped of its `@version` — mise upgrades a *tool* within the spec its
/// config records, and passing `jq@1.8.2` would ask it to move to the version it is already on.
///
/// Stripping is also what the dedup runs on, and that is wider than dropping repeats of one spec:
/// [`super::task::TaskEngine::declared_packages`] dedups by the whole token, so two tasks naming
/// the same tool at different versions both reach here and the pool holds both, while the roll
/// leaves as a single argument naming the tool. The argv is therefore not a picture of the pool,
/// which is worth saying where the two stop matching.
fn upgrade_argv(mise_bin: &Path, tokens: &[String]) -> Vec<OsString> {
    let mut argv = vec![
        mise_bin.as_os_str().to_os_string(),
        OsString::from("upgrade"),
    ];
    let mut seen: Vec<&str> = Vec::new();
    for token in tokens {
        let (locator, _) = split_version(token);
        if !seen.contains(&locator) {
            seen.push(locator);
            argv.push(OsString::from(locator));
        }
    }
    argv
}

/// Create the pool directory owner-only, tightening it if it already existed with looser bits — the
/// same fail-closed stance the store and the private mise home take.
fn ensure_pool_dir(pool: &Path) -> io::Result<()> {
    use std::fs::{DirBuilder, Permissions};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    DirBuilder::new().recursive(true).mode(0o700).create(pool)?;
    std::fs::set_permissions(pool, Permissions::from_mode(0o700))
}

/// Assemble the install cage. Pure but for the spec's own validation, so what the install runs
/// under is testable without a kernel.
fn install_spec(
    base_mounts: &[Mount],
    base_env: &[(String, String)],
    mise_bin: &Path,
    pool: &Path,
    tokens: &[String],
) -> io::Result<SandboxSpec> {
    let mut mounts = base_mounts.to_vec();
    // The pool, read-write — the only writable mount that is not a tmpfs, and the whole reason this
    // cage exists.
    mounts.push(Mount::Bind {
        src: pool.to_path_buf(),
        dest: PathBuf::from(POOL_INCAGE),
    });
    mounts.push(Mount::Proc {
        dest: PathBuf::from("/proc"),
    });
    mounts.push(Mount::Dev {
        dest: PathBuf::from("/dev"),
    });
    mounts.push(Mount::Tmpfs {
        dest: PathBuf::from("/tmp"),
    });
    mounts.push(Mount::Tmpfs {
        dest: PathBuf::from(INSTALL_HOME),
    });

    let mut env = base_env.to_vec();
    env.extend(install_env());

    // `use -g` rather than a bare `install`: it installs, records the version in the pool's own
    // global config, and writes the shims. A shim resolves its version from that config, so a plain
    // `install` would leave shims that cannot decide what to run.
    let mut argv = vec![
        mise_bin.as_os_str().to_os_string(),
        OsString::from("use"),
        OsString::from("-g"),
    ];
    argv.extend(tokens.iter().map(OsString::from));

    SandboxSpec::new(
        PathBuf::from(INSTALL_HOME),
        mounts,
        env,
        NetPolicy::Shared,
        argv,
    )
    .map(|s| s.with_cage_slug("task-pool".to_string()))
    .map_err(|e| io::Error::other(format!("cannot build the task pool install cage: {e:?}")))
}

/// The install cage's mise environment. Every mise directory is pinned **inside the pool** so the
/// install is self-contained and reclaimed with it, except `$HOME`, which is the tmpfs: a backend
/// writing beside `$HOME` must not leave that in a tree a task later reads. `XDG_CACHE_HOME` is
/// pinned into the pool too, so a large npm or pip download does not have to fit in the tmpfs.
fn install_env() -> Vec<(String, String)> {
    let under = |sub: &str| format!("{POOL_INCAGE}/{sub}");
    vec![
        ("HOME".to_string(), INSTALL_HOME.to_string()),
        ("MISE_DATA_DIR".to_string(), POOL_INCAGE.to_string()),
        ("MISE_CACHE_DIR".to_string(), under("cache")),
        ("MISE_STATE_DIR".to_string(), under("state")),
        ("MISE_CONFIG_DIR".to_string(), under("config")),
        ("XDG_CACHE_HOME".to_string(), under("xdg-cache")),
        // mise's custom backends are experimental-gated, and a prompt would hang a launch that has
        // no one to answer it.
        ("MISE_EXPERIMENTAL".to_string(), "1".to_string()),
        ("MISE_YES".to_string(), "1".to_string()),
    ]
}

/// The mise environment a **task** cage needs to run a pool tool through its shim.
///
/// A shim re-execs mise, which then has to find the pool (`MISE_DATA_DIR`) and the config recording
/// which version to run (`MISE_CONFIG_DIR`, written by the install's `use -g`). Both are inside the
/// read-only pool, so the dirs mise *writes* — cache and state — are redirected under the task's
/// tmpfs `$HOME`; without that the resolution fails trying to write into a read-only tree.
///
/// `home` is the task cage's `$HOME`. Applied only when the task declares a tool: a task with none
/// gets no pool, no shims, and none of this.
pub(crate) fn task_env(home: &str) -> Vec<(String, String)> {
    vec![
        ("MISE_DATA_DIR".to_string(), POOL_INCAGE.to_string()),
        (
            "MISE_CONFIG_DIR".to_string(),
            format!("{POOL_INCAGE}/config"),
        ),
        ("MISE_CACHE_DIR".to_string(), format!("{home}/.cache/mise")),
        (
            "MISE_STATE_DIR".to_string(),
            format!("{home}/.local/state/mise"),
        ),
        // The backends a pool tool may come from are experimental-gated, and a prompt in a
        // non-interactive cage would hang until the timeout.
        ("MISE_EXPERIMENTAL".to_string(), "1".to_string()),
        ("MISE_YES".to_string(), "1".to_string()),
        // A task never fetches: its tools were installed at launch, and its cage has an empty
        // network namespace unless it declared egress. Saying so makes a resolution that would
        // otherwise reach out fail fast, instead of burning the task's whole timeout on a
        // connection that cannot complete.
        ("MISE_OFFLINE".to_string(), "1".to_string()),
    ]
}

/// One install run's result: whether it succeeded, and the tail of each of its streams for the
/// message when it did not.
pub(crate) struct InstallRun {
    pub(crate) ok: bool,
    pub(crate) stderr: Vec<u8>,
    /// The tail of the run's **stdout**. Kept because the stream that explains a failed install is
    /// not always mise's own: a backend it wraps (`npm`, `pipx`) reports its resolution failure on
    /// stdout while mise's stderr carries only progress that trims away to nothing.
    ///
    /// [`InstallRun::diagnostics`] is what a message should quote.
    pub(crate) stdout: Vec<u8>,
}

impl InstallRun {
    /// The stream to quote when the install failed: the stderr tail, or the stdout tail when stderr
    /// carried nothing but whitespace.
    ///
    /// Both streams are already tee'd live to sbx's own stderr, so this decides the *summary* line,
    /// not whether the operator ever sees the diagnostic. That line is the part that has to answer
    /// "registry outage or typo'd token", and answering it with `no output` while the explanation
    /// sits in the other buffer is the one outcome keeping two tails exists to prevent.
    pub(crate) fn diagnostics(&self) -> &[u8] {
        match self.stderr.trim_ascii().is_empty() {
            true => &self.stdout,
            false => &self.stderr,
        }
    }
}

/// How much of the install's own output is kept for the failure message. Only a tail: the useful
/// part of a mise failure is its last lines, and everything was already streamed live anyway.
const DIAGNOSTIC_TAIL: usize = 8 * 1024;

/// Run the install cage under [`INSTALL_TIMEOUT`].
///
/// **Both** of mise's streams are piped and forwarded to sbx's own stderr as they arrive — live, so
/// a minutes-long cold install shows its progress instead of looking hung, and onto stderr so a
/// piped `sbx run` keeps its stdout. The tail of each is kept for the message when the install
/// fails: mise's diagnostics are the only way to tell a registry outage from a typo'd token, and
/// which stream carries them depends on the backend — see [`InstallRun::diagnostics`].
fn run(
    bwrap: &Path,
    spec: &SandboxSpec,
    limits: &super::cgroup::Limits,
    slug: &str,
) -> io::Result<InstallRun> {
    let (argv, memfds) = super::argv::compose(spec)?;
    let (prog, args) = super::cgroup::wrap(bwrap, argv, limits, slug);
    // Through [`super::task::spawn_launcher`], which states why: an install runs for minutes, and
    // these descriptors are not close-on-exec, so every cage this process spawns while one is open
    // inherits it — including the credential-bearing task cages the pool is being filled for.
    let mut child = super::task::spawn_launcher(
        Command::new(prog)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        memfds,
    )?;

    let mut out_pipe = child.stdout.take().expect("stdout piped");
    let mut err_pipe = child.stderr.take().expect("stderr piped");
    let out_reader = std::thread::spawn(move || tee_to_stderr(&mut out_pipe));
    let reader = std::thread::spawn(move || tee_to_stderr(&mut err_pipe));

    let deadline = Instant::now() + INSTALL_TIMEOUT;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                // Killing bwrap tears the cage down with it: it is the pid-namespace init for
                // everything inside, so a wedged download does not outlive the ceiling.
                timed_out = true;
                let _ = child.kill();
                break child.wait()?;
            }
            None => std::thread::sleep(POLL_INTERVAL),
        }
    };
    let mut stderr = reader.join().unwrap_or_default();
    // Joined so the forwarding thread cannot outlive the run and interleave into a later message —
    // and its tail is kept, not dropped: it is the half a wrapped backend writes its failure to.
    let stdout = out_reader.join().unwrap_or_default();
    if timed_out {
        stderr.extend_from_slice(
            format!(
                "\n(sbx: the pool install passed its {}s ceiling and was killed)",
                INSTALL_TIMEOUT.as_secs()
            )
            .as_bytes(),
        );
    }
    Ok(InstallRun {
        ok: !timed_out && status.success(),
        stderr,
        stdout,
    })
}

/// Forward everything on `pipe` to sbx's stderr as it arrives, keeping the last
/// [`DIAGNOSTIC_TAIL`] bytes. Streaming rather than draining-then-printing is what makes a long
/// install visibly alive; keeping only a tail is what stops a chatty backend from turning a warning
/// into a wall of text.
fn tee_to_stderr(pipe: &mut impl std::io::Read) -> Vec<u8> {
    use std::io::Write as _;
    let mut kept: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let _ = std::io::stderr().write_all(&buf[..n]);
                kept.extend_from_slice(&buf[..n]);
                if kept.len() > DIAGNOSTIC_TAIL {
                    kept.drain(..kept.len() - DIAGNOSTIC_TAIL);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    /// Record the pool's global config the way `mise use -g` writes it — the half a shim resolves
    /// through, and therefore half of what makes a token satisfied.
    fn record(pool: &Path, entries: &[(&str, &str)]) {
        std::fs::create_dir_all(pool.join("config")).unwrap();
        let mut body = String::from("[tools]\n");
        for (key, spec) in entries {
            body.push_str(&format!("\"{key}\" = \"{spec}\"\n"));
        }
        std::fs::write(pool.join("config/config.toml"), body).unwrap();
    }

    /// Realize a tool in a pool the way a fill does: the install tree, the backend metadata naming
    /// the real token, **and** the config entry — `mise use -g` writes all three, and `bins_for`
    /// requires the install and the record to agree.
    fn realize(pool: &Path, munged: &str, token: Option<&str>, versions: &[&str]) {
        realize_at(pool, munged, token, versions, "latest");
    }

    /// [`realize`] with an explicit recorded spec, for the pinned case.
    fn realize_at(pool: &Path, munged: &str, token: Option<&str>, versions: &[&str], spec: &str) {
        let dir = installs_dir(pool).join(munged);
        for v in versions {
            std::fs::create_dir_all(dir.join(v).join("bin")).unwrap();
        }
        record(pool, &[(token.unwrap_or(munged), spec)]);
        if let Some(token) = token {
            std::fs::write(
                dir.join(".mise.backend.toml"),
                format!("short = \"{token}\"\n"),
            )
            .unwrap();
        }
    }

    #[test]
    fn a_version_is_split_off_only_past_an_npm_scope() {
        assert_eq!(split_version("node@22"), ("node", Some("22")));
        assert_eq!(split_version("aqua:cli/gh"), ("aqua:cli/gh", None));
        assert_eq!(
            split_version("aqua:cli/gh@2.62.0"),
            ("aqua:cli/gh", Some("2.62.0"))
        );
        // an npm scope's leading `@` opens the name, it does not open a version
        assert_eq!(
            split_version("npm:@example/tool"),
            ("npm:@example/tool", None)
        );
        assert_eq!(
            split_version("npm:@example/tool@1.2"),
            ("npm:@example/tool", Some("1.2"))
        );
    }

    // The pool is matched by the token mise *recorded*, not by the munged directory name — the munge
    // is best-effort, the record is what mise says the install is.
    #[test]
    fn a_declared_token_resolves_to_its_recorded_install() {
        let base = TmpDir::new();
        let pool = base.join("task-mise");
        realize(&pool, "aqua-cli-gh", Some("aqua:cli/gh"), &["2.62.0"]);

        let bins = bins_for(&pool, &["aqua:cli/gh".to_string()]);
        assert_eq!(bins.missing, Vec::<String>::new());
        assert_eq!(
            bins.bins,
            vec![PathBuf::from("/opt/sbx/task-mise/shims")],
            "the path handed to a task is mise's shims, and the IN-CAGE path at that"
        );
    }

    /// The path a task gets is the shims directory, whatever the backend did with its files.
    ///
    /// Observed from a real `aqua:` install: the executable lands at
    /// `installs/<tool>/<version>/<vendor-archive-name>/<binary>` — no `bin/` anywhere — so a rule
    /// that guessed install directories would put a directory holding no executable on `PATH` and
    /// the task would fail with "not found". mise's shim is the only thing that spans backends.
    #[test]
    fn a_nested_backend_layout_still_yields_the_shims_directory() {
        let base = TmpDir::new();
        let pool = base.join("task-mise");
        std::fs::create_dir_all(
            installs_dir(&pool)
                .join("ripgrep")
                .join("15.2.0")
                .join("ripgrep-15.2.0-x86_64-unknown-linux-musl"),
        )
        .unwrap();
        record(&pool, &[("ripgrep", "latest")]);
        assert_eq!(
            bins_for(&pool, &["ripgrep".to_string()]).bins,
            vec![PathBuf::from("/opt/sbx/task-mise/shims")]
        );
    }

    /// A version is honoured as declared: an explicit one the pool lacks is *missing*, never quietly
    /// served by whichever other version happens to be installed.
    #[test]
    fn an_explicit_version_the_pool_lacks_is_missing() {
        let base = TmpDir::new();
        let pool = base.join("task-mise");
        realize_at(
            &pool,
            "node",
            Some("node"),
            &["20.11.0", "22.3.0"],
            "20.11.0",
        );

        assert!(
            bins_for(&pool, &["node@20.11.0".to_string()])
                .missing
                .is_empty()
        );
        // a version the pool does not hold at all
        let absent = bins_for(&pool, &["node@18.0.0".to_string()]);
        assert!(absent.bins.is_empty());
        assert_eq!(absent.missing, vec!["node@18.0.0".to_string()]);
    }

    /// mise writes its `latest`/`15`/`15.2` aliases as **symlinks** beside the concrete version, and
    /// the install reader skips them (it keeps only real directories) — so a bare token resolves
    /// through the one concrete version rather than through an alias that may not be a directory at
    /// all. Pinned because the resolution reads as version-picking logic and this is what actually
    /// reaches it.
    #[test]
    fn misses_aliases_are_symlinks_and_do_not_masquerade_as_versions() {
        let base = TmpDir::new();
        let pool = base.join("task-mise");
        realize(&pool, "ripgrep", Some("ripgrep"), &["15.2.0"]);
        let tool_dir = installs_dir(&pool).join("ripgrep");
        for alias in ["latest", "15", "15.2"] {
            std::os::unix::fs::symlink("./15.2.0", tool_dir.join(alias)).unwrap();
        }
        let installed = inspect::mise_installed_in(&installs_dir(&pool));
        assert_eq!(
            installed[0].versions,
            vec!["15.2.0".to_string()],
            "an alias symlink is not a version directory"
        );
        assert!(bins_for(&pool, &["ripgrep".to_string()]).missing.is_empty());
    }

    /// A declared alias or partial version must be satisfiable by the concrete install it names.
    ///
    /// mise records the spec verbatim (`node = "22"`) and materializes `latest`, `22` and `22.3` as
    /// **symlinks** beside `22.3.0`, which the install reader skips — so a rule that looked for a
    /// directory of that name could never find one. The two halves of the satisfaction rule then
    /// disagreed permanently: the config half passed, the installs half could not, and the token was
    /// reported missing forever. The cost is not one failed task: `ensure`'s warm short-circuit
    /// never fires, so every launch of the project pays a bwrap + mise install-cage run before the
    /// agent starts, and the task still gets no shims on its `PATH`.
    #[test]
    fn a_declared_alias_or_partial_version_is_satisfied_by_the_concrete_install_it_names() {
        let base = TmpDir::new();
        let pool = base.join("task-mise");
        realize_at(&pool, "node", Some("node"), &["22.3.0"], "latest");
        let tool_dir = installs_dir(&pool).join("node");
        for alias in ["latest", "22", "22.3"] {
            std::os::unix::fs::symlink("./22.3.0", tool_dir.join(alias)).unwrap();
        }

        // `mise use -g node@latest` records `latest`; the explicit spelling and the bare token are
        // one request, so they must be one answer here too.
        for token in ["node@latest", "node"] {
            assert!(
                bins_for(&pool, &[token.to_string()]).missing.is_empty(),
                "`{token}` is installed and recorded, so it is not missing"
            );
        }

        // `mise use -g node@22` records `22`, and `22` names `22.3.0`.
        record(&pool, &[("node", "22")]);
        assert!(bins_for(&pool, &["node@22".to_string()]).missing.is_empty());
        record(&pool, &[("node", "22.3")]);
        assert!(
            bins_for(&pool, &["node@22.3".to_string()])
                .missing
                .is_empty()
        );

        // And a version the pool does not hold stays missing: the partial match is segment-wise, so
        // `2` does not answer `22.3.0` and `24` is not served by it either.
        for absent in ["node@24", "node@2"] {
            let (_, wanted) = split_version(absent);
            record(&pool, &[("node", wanted.unwrap())]);
            assert_eq!(
                bins_for(&pool, &[absent.to_string()]).missing,
                vec![absent.to_string()],
                "a version the pool does not hold must not be served by another one"
            );
        }
    }

    /// One pool is one global mise config and one `shims/` directory, so a locator carries one
    /// version spec. Two tasks naming different versions of the same tool are therefore not two
    /// installs: whichever spelling the config does not record can never satisfy `bins_for`, so
    /// without detection `ensure` never reaches its warm short-circuit and every launch of the
    /// project runs the install cage again — rewriting the one `[tools]` entry each time, so the two
    /// tasks take turns failing. Filling for the first declaration and reporting the rest is what
    /// makes the state converge.
    #[test]
    fn one_tool_declared_at_two_versions_is_filled_for_one_of_them_and_reported() {
        let (fillable, conflicting) = one_spec_per_tool(&[
            "node@22.3.0".to_string(),
            "aqua:cli/gh".to_string(),
            "node@24.4.1".to_string(),
            "node@22.3.0".to_string(),
        ]);
        assert_eq!(
            fillable,
            vec!["node@22.3.0".to_string(), "aqua:cli/gh".to_string()],
            "declaration order decides, and an exact repeat is not a conflict"
        );
        assert_eq!(
            conflicting,
            vec![("node@24.4.1".to_string(), "node@22.3.0".to_string())]
        );

        // A bare token and an explicit `@latest` are one request, not a conflict.
        let (fillable, conflicting) =
            one_spec_per_tool(&["node".to_string(), "node@latest".to_string()]);
        assert_eq!(fillable, vec!["node".to_string()]);
        assert!(conflicting.is_empty(), "{conflicting:?}");

        // The payload: a pool already filled for the first spelling is warm, and does not reach for
        // bwrap or mise at all. Paths that do not exist prove it — running either would fail loudly.
        let base = TmpDir::new();
        let pool = base.join("task-mise");
        realize_at(&pool, "node", Some("node"), &["22.3.0"], "22.3.0");
        let outcome = ensure(
            Path::new("/nonexistent/bwrap"),
            &[],
            &[],
            Path::new("/nonexistent/mise"),
            &pool,
            &["node@22.3.0".to_string(), "node@24.4.1".to_string()],
            &super::super::cgroup::Limits::default(),
            "test",
        )
        .unwrap();
        assert_eq!(
            outcome,
            PoolOutcome::Warm,
            "an unsatisfiable second version must not turn every launch into an install cage"
        );
    }

    /// The failure summary must quote whichever stream actually carried the diagnostic.
    ///
    /// mise wraps backends that write their own failure to stdout (`npm`, `pipx`) while mise's
    /// stderr carries only progress that trims away to nothing, so quoting the stderr tail alone
    /// answers `no output` for a failure whose explanation is in hand. This covers the choice
    /// itself; each consumer is covered where it formats its own line — `ensure` above, and the
    /// roll report's pool line in [`crate::sandbox::launch`].
    #[test]
    fn the_failure_summary_falls_back_to_the_stdout_tail_when_stderr_carried_nothing() {
        let backend_spoke_on_stdout = InstallRun {
            ok: false,
            stderr: b"  \n \n".to_vec(),
            stdout: b"npm error 404 Not Found - GET https://registry.example/no-such".to_vec(),
        };
        assert_eq!(
            backend_spoke_on_stdout.diagnostics(),
            b"npm error 404 Not Found - GET https://registry.example/no-such"
        );

        // mise's own stderr wins whenever it has something to say, so the ordinary failure message
        // is unchanged.
        let mise_spoke = InstallRun {
            ok: false,
            stderr: b"mise ERROR failed to resolve tool".to_vec(),
            stdout: b"downloading...".to_vec(),
        };
        assert_eq!(
            mise_spoke.diagnostics(),
            b"mise ERROR failed to resolve tool"
        );
    }

    #[test]
    fn an_empty_pool_reports_every_token_missing() {
        let base = TmpDir::new();
        let bins = bins_for(&base.join("task-mise"), &["node".to_string()]);
        assert!(bins.bins.is_empty());
        assert_eq!(bins.missing, vec!["node".to_string()]);
    }

    // The pool lives under the project's own runtime tree, so `sbx projects rm` and the dead-tree
    // reap reclaim it with everything else — no pool-specific housekeeping to forget.
    #[test]
    fn the_pool_lives_under_the_projects_runtime_tree() {
        assert_eq!(
            pool_dir(Path::new("/data"), "0123456789abcdef"),
            PathBuf::from("/data/projects/0123456789abcdef/task-mise")
        );
    }

    #[test]
    fn ensure_short_circuits_when_the_pool_is_already_warm() {
        let base = TmpDir::new();
        let pool = base.join("task-mise");
        realize(&pool, "node", Some("node"), &["22.3.0"]);
        // No bwrap, no mise: a warm pool must not reach either, which is what makes a warm launch
        // free. A path that does not exist proves it — running it would fail loudly.
        let outcome = ensure(
            Path::new("/nonexistent/bwrap"),
            &[],
            &[],
            Path::new("/nonexistent/mise"),
            &pool,
            &["node".to_string()],
            &super::super::cgroup::Limits::default(),
            "test",
        )
        .unwrap();
        assert_eq!(outcome, PoolOutcome::Warm);
    }

    #[test]
    fn no_declared_tool_means_no_work() {
        let base = TmpDir::new();
        let outcome = ensure(
            Path::new("/nonexistent/bwrap"),
            &[],
            &[],
            Path::new("/nonexistent/mise"),
            &base.join("task-mise"),
            &[],
            &super::super::cgroup::Limits::default(),
            "test",
        )
        .unwrap();
        assert_eq!(outcome, PoolOutcome::Warm);
        assert!(
            !base.join("task-mise").exists(),
            "a project with no task tools must not materialize a pool at all"
        );
    }

    // The install cage is the task cage's skeleton plus exactly one writable non-tmpfs mount: the
    // pool. Anything else writable there would be a tree the install could reach into.
    #[test]
    fn the_install_cage_writes_only_the_pool() {
        let skeleton = vec![Mount::RoBind {
            src: PathBuf::from("/data/shared/store/nix"),
            dest: PathBuf::from("/nix"),
        }];
        let spec = install_spec(
            &skeleton,
            &[("PATH".to_string(), "/bin".to_string())],
            Path::new("/nix/store/abc-mise/bin/mise"),
            Path::new("/data/projects/abc/task-mise"),
            &["node@22".to_string()],
        )
        .unwrap();

        let writable: Vec<&PathBuf> = spec
            .mounts()
            .iter()
            .filter_map(|m| match m {
                Mount::Bind { dest, .. } => Some(dest),
                _ => None,
            })
            .collect();
        assert_eq!(writable, vec![&PathBuf::from(POOL_INCAGE)]);

        // mise is pointed at the pool, and the tokens ride the argv — never a shell string.
        let env = |k: &str| {
            spec.env()
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(env("MISE_DATA_DIR"), Some(POOL_INCAGE));
        assert_eq!(env("HOME"), Some(INSTALL_HOME));
        assert_eq!(env("PATH"), Some("/bin"), "the base userland stays on PATH");

        // `use -g` rather than `install`: it also records the version and writes the shims a task
        // resolves through. A bare `install` leaves shims that cannot decide what to run.
        let argv: Vec<String> = spec
            .cmd
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            argv,
            vec![
                "/nix/store/abc-mise/bin/mise".to_string(),
                "use".to_string(),
                "-g".to_string(),
                "node@22".to_string()
            ]
        );
    }

    /// The roll asks mise to move a *tool*, so the `@version` comes off: `mise upgrade jq@1.8.2`
    /// would ask it to move to where it already is. Duplicates collapse — two tasks sharing a tool
    /// roll it once.
    #[test]
    fn the_roll_names_tools_without_their_versions() {
        let argv: Vec<String> = upgrade_argv(
            Path::new("/nix/store/abc-mise/bin/mise"),
            &[
                "node@22".to_string(),
                "aqua:cli/gh".to_string(),
                "node@24".to_string(),
            ],
        )
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
        assert_eq!(
            argv,
            vec![
                "/nix/store/abc-mise/bin/mise".to_string(),
                "upgrade".to_string(),
                "node".to_string(),
                "aqua:cli/gh".to_string(),
            ]
        );
    }

    /// A pool that was never filled has nothing to roll, and the roll must not create one — an
    /// upgrade is not an install.
    #[test]
    fn rolling_an_absent_pool_is_a_no_op() {
        let base = TmpDir::new();
        let pool = base.join("task-mise");
        let outcome = upgrade(
            Path::new("/nonexistent/bwrap"),
            &[],
            &[],
            Path::new("/nonexistent/mise"),
            &pool,
            &["node".to_string()],
            &super::super::cgroup::Limits::default(),
            "test",
        )
        .unwrap();
        assert!(outcome.is_none());
        assert!(!pool.exists());
    }

    /// The drift the config check exists for: a pool still holding an earlier version satisfies the
    /// *installs* half, so without reading the recorded spec a re-declared version would silently
    /// run whatever the config was last written for.
    #[test]
    fn a_config_recording_another_version_is_not_satisfied() {
        let base = TmpDir::new();
        let pool = base.join("task-mise");
        realize(&pool, "node", Some("node"), &["22.3.0", "24.4.1"]);
        std::fs::create_dir_all(pool.join("config")).unwrap();
        std::fs::write(
            pool.join("config/config.toml"),
            "[tools]\nnode = \"22.3.0\"\n",
        )
        .unwrap();

        // the version the config records is satisfied...
        assert!(
            bins_for(&pool, &["node@22.3.0".to_string()])
                .missing
                .is_empty()
        );
        // ...and the one it does not is NOT, even though its install is right there
        assert_eq!(
            bins_for(&pool, &["node@24.4.1".to_string()]).missing,
            vec!["node@24.4.1".to_string()],
            "an install without the matching record must not count as satisfied"
        );
        // a bare token expects the record mise writes for one — `latest`, not a pinned version
        assert_eq!(
            bins_for(&pool, &["node".to_string()]).missing,
            vec!["node".to_string()]
        );
    }

    /// The recorded specs are read out of the `[tools]` table only, quoted keys included, and a
    /// pool that was never filled records nothing.
    #[test]
    fn the_recorded_specs_come_from_the_tools_table() {
        let base = TmpDir::new();
        let pool = base.join("task-mise");
        assert!(recorded_specs(&pool).is_empty());
        std::fs::create_dir_all(pool.join("config")).unwrap();
        std::fs::write(
            pool.join("config/config.toml"),
            "[settings]\nexperimental = true\n\n\
             [tools]\njq = \"latest\"\n\"aqua:cli/gh\" = \"2.62.0\"\n\n\
             [env]\nFOO = \"bar\"\n",
        )
        .unwrap();
        let specs = recorded_specs(&pool);
        assert_eq!(specs.get("jq").map(String::as_str), Some("latest"));
        assert_eq!(specs.get("aqua:cli/gh").map(String::as_str), Some("2.62.0"));
        assert!(
            !specs.contains_key("FOO"),
            "only `[tools]` is read: {specs:?}"
        );
        assert!(!specs.contains_key("experimental"));
    }

    /// A task's mise environment must point resolution at the read-only pool while sending the dirs
    /// mise *writes* to the tmpfs home — a shim that tried to write its cache into the pool would
    /// fail on a read-only filesystem.
    #[test]
    fn the_task_environment_reads_the_pool_and_writes_only_the_tmpfs_home() {
        let env = task_env("/tmp/task-home");
        let get = |k: &str| {
            env.iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.as_str())
                .unwrap_or_default()
        };
        assert_eq!(get("MISE_DATA_DIR"), POOL_INCAGE);
        assert!(get("MISE_CONFIG_DIR").starts_with(POOL_INCAGE));
        for writable in ["MISE_CACHE_DIR", "MISE_STATE_DIR"] {
            assert!(
                get(writable).starts_with("/tmp/task-home"),
                "{writable} must land on the tmpfs home, not the read-only pool: {}",
                get(writable)
            );
        }
    }

    /// The invariant the whole pool rests on: the install bakes absolute paths into what it writes —
    /// the shims, the recorded config, npm wrappers, python console-script shebangs — so the cage
    /// that fills the pool and the cage that reads it must mount it at the same place. Divergence
    /// would ship tools that fail on their own interpreter.
    #[test]
    fn the_install_and_task_cages_agree_on_the_pool_path() {
        let spec = install_spec(
            &[],
            &[],
            Path::new("/nix/store/abc-mise/bin/mise"),
            Path::new("/data/projects/abc/task-mise"),
            &["node".to_string()],
        )
        .unwrap();
        let install_dest = spec
            .mounts()
            .iter()
            .find_map(|m| match m {
                Mount::Bind { src, dest } if src.ends_with("task-mise") => Some(dest.clone()),
                _ => None,
            })
            .expect("the pool is bound in the install cage");
        assert_eq!(install_dest, PathBuf::from(POOL_INCAGE));
        // And the path every resolved bin directory is rooted at is the same constant.
        let base = TmpDir::new();
        let pool = base.join("task-mise");
        realize(&pool, "node", Some("node"), &["22.3.0"]);
        assert!(bins_for(&pool, &["node".to_string()]).bins[0].starts_with(&install_dest));
    }
}
