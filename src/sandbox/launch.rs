//! Launching a sandbox: turning a [`SandboxSpec`] into a running bubblewrap
//! process.
//!
//! Two launch models, by terminal policy:
//! - `ops run` is non-interactive: it execs bwrap and lets it *replace* the ops
//!   process, so the command inherits the real stdio and its exit status becomes
//!   ops's. The spec uses [`TerminalPolicy::NewSession`].
//! - `ops shell` is interactive: ops stays alive as a **pty supervisor**. It
//!   gives the sandbox a private controlling terminal (so job control works
//!   inside) and relays bytes to and from the real terminal (which the sandbox
//!   therefore cannot reach). The spec uses [`TerminalPolicy::PrivateTty`], which
//!   omits `--new-session` — bubblewrap's `setsid` would `setsid` away from that
//!   private terminal.
//!
//! Known gaps in the supervisor (named, not silent):
//! - terminal-state restore is a RAII guard, so it covers normal/error/panic
//!   exits but not a `SIGTERM`/`SIGHUP` kill;
//! - the window size is set once at startup — dynamic `SIGWINCH` propagation is a
//!   follow-up;
//! - the relay is single-threaded with a blocking `write_all` to the master, so a
//!   pathological simultaneous flood (the inner shell not draining its input while
//!   also flooding output) could stall it. Humans don't trigger it and `script(1)`
//!   shares the limitation; a split-direction or non-blocking relay is the fix.

use super::binds::{self, Userland};
use super::egress;
use super::spec::{NetPolicy, SandboxSpec, TerminalPolicy};
use crate::session::{self, Kind, RecordGuard, Session};
use crate::store::Layout;
use std::ffi::{CString, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// The hard prerequisites and per-launch resolution shared by `run` and `shell`:
/// the engine, ops's store layout, the current directory, the resolved
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
    /// channel but rolls independently via `ops upgrade mise`). mise runs in its own
    /// store view, free of the one-channel rule, so it may sit on a different revision
    /// than `nixpkgs`. Drives both the in-cage mise (the base userland) and the
    /// host-side `[env]` driver.
    engine_ref: String,
    userland: Userland,
}

/// `ops run [--] <cmd>`: run a command inside the project sandbox, replacing the
/// ops process so the command's exit status becomes ops's.
pub(crate) fn run(cmd: Vec<OsString>) -> ExitCode {
    if cmd.is_empty() {
        eprintln!("ops: usage: ops run [--] <command> [args...]");
        return ExitCode::from(2);
    }
    let prep = match prepare() {
        Ok(p) => p,
        Err(code) => return code,
    };
    let (spec, egress) = match build(&prep, cmd) {
        Ok(v) => v,
        Err(code) => return code,
    };

    register(prep.layout.data_dir(), &spec, Kind::Run);

    match egress {
        // The default postures: exec-replace, so the command's exit status becomes ops's.
        // The pid and its start time survive the exec, so the registry record keeps matching
        // the sandbox and is reclaimed by liveness pruning once it exits.
        None => {
            // On success this never returns; reaching past it means exec itself failed.
            let err = exec(&prep.bwrap, &spec);
            eprintln!("ops: failed to launch the sandbox: {err}");
            ExitCode::FAILURE
        }
        // A network allowlist: ops cannot exec-replace, because the host filtering proxy
        // runs on a thread that must outlive the cage. Supervise instead — fork bwrap, wait,
        // propagate the exit status — keeping the proxy alive and the guard (which unlinks
        // the socket and CA) held for the whole session.
        Some(guard) => {
            let code = run_supervised(&prep.bwrap, &spec);
            drop(guard);
            code
        }
    }
}

/// `ops mise [args...]`: run mise inside the project's open cage, where it can
/// self-equip the project's `nix:` tools (`ops mise install nix:<pkg>`) into the
/// project's own writable store. Sugar over `ops run -- mise [args...]`: mise is
/// present in every cage with the `nix:` backend plugin registered, so the only
/// thing this adds is sparing the `run --` prefix.
///
/// A tool the agent *activates* (`mise use [-g] nix:<pkg>`) is on PATH in later
/// launches — through the shims dir on PATH for `ops run`, and `mise activate` for the
/// `ops shell` — and persists in the project's store. A bare `mise install` (not
/// activated) persists too and `mise exec`/`mise which` resolve it, but it is not on
/// PATH, matching mise's own install-vs-use split. This path is intentionally open — it
/// works whether or not the project is trusted, the agent-self-equip posture — unlike
/// `ops run`'s host-side `nix:` provisioning, which stays trusted-only and is a parallel
/// path that does not share state with what mise installs here.
pub(crate) fn run_mise(args: Vec<OsString>) -> ExitCode {
    let mut cmd = vec![OsString::from("mise")];
    cmd.extend(args);
    run(cmd)
}

/// `ops shell`: an interactive shell inside the project sandbox, under a pty
/// supervisor so job control works.
pub(crate) fn shell() -> ExitCode {
    // SAFETY: `isatty` only inspects fd 0. An interactive shell needs a real
    // terminal to make raw; refuse cleanly rather than corrupt a pipe.
    if unsafe { libc::isatty(0) } != 1 {
        eprintln!(
            "ops: `ops shell` needs a terminal on stdin (use `ops run` for non-interactive use)."
        );
        return ExitCode::from(2);
    }
    let prep = match prepare() {
        Ok(p) => p,
        Err(code) => return code,
    };
    // The command is the resolved interactive shell; the pty gives it a
    // controlling terminal so it starts interactively with job control. It starts with
    // `--rcfile` pointing at the synthetic in-cage rc, which activates mise so the
    // project's activated tools (`mise use`) manage PATH/env in the interactive shell —
    // mise's documented interactive mechanism. (`ops run` instead reaches activated
    // tools through the shims dir on PATH, with no shell to hook.)
    let cmd = vec![
        prep.userland.shell_bin.clone().into_os_string(),
        OsString::from("--rcfile"),
        OsString::from(binds::SHELL_RC_INCAGE),
    ];
    let (spec, egress) = match build(&prep, cmd) {
        Ok((s, e)) => (s.with_private_tty(), e),
        Err(code) => return code,
    };

    // Register the session and hold the guard for the whole supervised session;
    // it unlinks the record when the shell exits (dropped as this scope ends).
    let _record = register(prep.layout.data_dir(), &spec, Kind::Shell).map(RecordGuard::new);
    // Hold the egress guard for the session too (under an allowlist): the host proxy thread
    // runs alongside the pty supervisor, and the guard unlinks the socket and CA on exit.
    let _egress = egress;

    match supervise(&prep.bwrap, &spec) {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("ops: sandbox session failed: {e}");
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
    let Some(bwrap) = crate::pathfind::find_on_path("bwrap") else {
        return Err(missing("bubblewrap (the sandbox engine)"));
    };
    if !matches!(crate::probe_userns(), crate::Userns::Ok) {
        eprintln!(
            "ops: no capability-bearing user namespace — the sandbox cannot run. See `ops doctor`."
        );
        return Err(ExitCode::FAILURE);
    }
    let Some(nix) = crate::store::resolve_nix() else {
        return Err(missing("nix (the store engine)"));
    };
    let Some(nix_store) = crate::store::resolve_nix_store() else {
        return Err(missing("nix-store (the store database tool)"));
    };
    let Some(layout) = Layout::from_env() else {
        eprintln!("ops: cannot resolve the data directory (no $HOME or $XDG_DATA_HOME).");
        return Err(ExitCode::FAILURE);
    };
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ops: cannot read the current directory: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    let cfg = crate::config::load(&cwd);

    let nixpkgs =
        match effective_lock_target(&cwd, &layout, &cfg).and_then(|t| t.resolve(&nix, &layout)) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("ops: cannot resolve the nixpkgs channel: {e}");
                return Err(ExitCode::FAILURE);
            }
        };
    // The mise engine resolves against its own dedicated lock (the global channel source,
    // rolled independently by `ops upgrade mise`), never this launch's possibly-pinned
    // base reference. Resolved *after* the base so its lock can be seeded from the base's
    // on first use (no network, and a binary update never bumps the engine — see
    // `resolve_engine_ref`). Threaded to both mise consumers: the in-cage engine (the base
    // userland) and the host-side `[env]` driver.
    let engine_ref =
        match crate::store::resolve_engine_ref(&nix, &layout, cfg.nixpkgs_global.as_deref()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("ops: cannot resolve the mise engine channel: {e}");
                return Err(ExitCode::FAILURE);
            }
        };
    let userland = match super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &engine_ref) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("ops: cannot resolve the sandbox userland: {e}");
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
    })
}

/// The single channel decision for the current directory — the one place that picks
/// "which source, which lock", so the launch (resolve), `ops upgrade` (refresh), and
/// `ops config` (display) all act on the same lock and can never drift.
///
/// A trusted per-project `nixpkgs` pin takes precedence (its own lock); otherwise the
/// global channel — a global-config override, else the default. Only the pinned case
/// canonicalises the project to derive its lock path, so the common no-pin path does
/// no extra work and a per-project lock is never even named without a current pin.
pub(crate) fn effective_lock_target(
    cwd: &Path,
    layout: &Layout,
    cfg: &crate::config::Resolved,
) -> io::Result<crate::store::LockTarget> {
    match cfg.nixpkgs_project.as_deref() {
        Some(source) => {
            let id = binds::project_runtime_id(cwd)?;
            Ok(crate::store::LockTarget::project(layout, &id, source))
        }
        None => Ok(crate::store::LockTarget::global(
            layout,
            cfg.nixpkgs_global.as_deref(),
        )),
    }
}

/// Build the spec for `cmd`, reporting a clean error as an `ExitCode`. The
/// configuration resolved in [`prepare`] drives this: a trust-gated `.ops.toml` adds
/// environment and read-only binds (its security fields honored only once trusted)
/// and provisions its declared tools onto `PATH`. Whatever the gate dropped or
/// withheld is surfaced as a warning; a declared tool that fails to realise is fatal,
/// since it is a stated requirement.
fn build(
    prep: &Prepared,
    cmd: Vec<OsString>,
) -> Result<(SandboxSpec, Option<egress::Egress>), ExitCode> {
    for warning in &prep.cfg.warnings {
        eprintln!("ops: warning: {warning}");
    }

    // Provision the project's declared tools into ops's store, against the project's
    // effective nixpkgs reference; their bin dirs are prepended to PATH below. A
    // withheld (untrusted) tool only warns; an admitted tool that fails to realise is
    // fatal.
    let packages = match super::packages::provision(
        &prep.nix,
        &prep.layout,
        &prep.cwd,
        &prep.nixpkgs,
        &prep.cfg.packages,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ops: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    for warning in &packages.warnings {
        eprintln!("ops: warning: {warning}");
    }

    // Provision a trusted project's `nix:` mise tools — the exact-pinned dev toolchain.
    // Their bin dirs go ahead of the native `[packages]` ones, so a project's pinned
    // tool wins over the coarser package layer on a name clash.
    let tools = mise_tools(prep)?;
    for warning in &tools.warnings {
        eprintln!("ops: warning: {warning}");
    }
    let mut bin_paths = tools.bins;
    bin_paths.extend(packages.bins);

    // Seed the project's own writable store with the closure of everything the cage
    // resolves through `/nix` — the base userland plus every provisioned tool — then
    // back `/nix` with it read-write. The cage reads and writes only its own store, so
    // an agent that installs a toolchain writes into the project's copy and the shared
    // store is never in the cage. Which store backs `/nix` is ops's decision, not a
    // configurable field, so an untrusted project cannot keep the shared store mounted
    // or widen its access.
    let project_store = match seed_project_store(prep, &packages.roots, &tools.roots) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ops: cannot prepare the project's store: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    let nix_mount = binds::NixMount {
        src: project_store.store_dir().join("nix"),
        writable: true,
    };

    // A network allowlist runs the Model-B egress path: stand up the host filtering
    // proxy on a per-launch socket, wire the cage to reach it (the bound socket, the
    // CA it trusts, the proxy environment) and wrap the command so the cage starts the
    // forwarder before running it. The cage's netns is empty (`net_policy` maps the
    // allowlist to isolation), so this bound socket is the only egress. The guard keeps
    // the proxy's artifacts until the launch ends; the proxy thread outlives the cage
    // because the launcher supervises rather than exec-replacing (see `run`). Other
    // postures never touch any of this.
    let mut egress_guard = None;
    let mut egress_binds: Vec<binds::ExtraBind> = Vec::new();
    let mut egress_env: Vec<(String, String)> = Vec::new();
    let mut cmd = cmd;
    if let crate::config::NetworkPolicy::Allowlist(policy) = &prep.cfg.network {
        let (guard, wiring) = egress::start(
            &prep.layout,
            policy.clone(),
            &prep.cfg.secrets,
            &prep.cwd,
            &prep.bwrap,
        )
        .map_err(|e| {
            eprintln!("ops: cannot start the egress filtering proxy: {e}");
            ExitCode::FAILURE
        })?;
        cmd = egress::wrap_command(&prep.userland.socat_bin, &prep.userland.shell_bin, cmd);
        egress_binds = wiring.binds;
        egress_env = wiring.env;
        egress_guard = Some(guard);
    }

    // Environment, lowest precedence first: host passthrough, then ops's hermetic CA bundle,
    // then a trusted project's mise `[env]`, then the egress machinery (proxy + CA), then the
    // `.ops.toml` `[env]` (the ops-native config has the final say). The structural
    // HOME/PATH/... are added by the assembler, which upserts all of these over them. An
    // untrusted config has already lost its reserved keys upstream — including the proxy and
    // CA keys — so it can neither redirect the egress nor swap the CA; a trusted config
    // overriding them only harms its own cage.
    let extra_env = extra_cage_env(
        passthrough_env(),
        binds::cacert_env(),
        mise_env(prep)?,
        egress_env,
        &prep.cfg.env,
    );

    let overlay = binds::Overlay {
        env: &extra_env,
        ro_binds: &prep.cfg.ro_binds,
        bin_paths: &bin_paths,
    };
    let spec = binds::build_spec(
        prep.layout.data_dir(),
        &prep.cwd,
        &prep.userland,
        &nix_mount,
        &overlay,
        &egress_binds,
        net_policy(&prep.cfg.network),
        cmd,
    )
    .map_err(|e| {
        eprintln!("ops: cannot prepare the sandbox: {e}");
        ExitCode::FAILURE
    })?;
    Ok((spec, egress_guard))
}

/// Translate the resolved configuration's network posture into the cage's net
/// policy. The two enums are kept separate on purpose: the config vocabulary
/// (`none`/`shared`/`allowlist`) is the user's, while the cage's posture type is the
/// sandbox's. The allowlist posture maps to an **isolated** (empty) namespace by
/// design — that is the Model-B foundation: with no route of its own, the cage's only
/// egress is the bound socket `build` wires to the host filtering proxy. So the netns
/// is identical to `none`; the filtering lives in the proxy on top, not in the netns.
fn net_policy(network: &crate::config::NetworkPolicy) -> NetPolicy {
    match network {
        crate::config::NetworkPolicy::Shared => NetPolicy::Shared,
        crate::config::NetworkPolicy::Isolated => NetPolicy::Isolated,
        crate::config::NetworkPolicy::Allowlist(_) => NetPolicy::Isolated,
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
) -> io::Result<super::projectstore::ProjectStore> {
    let id = binds::project_runtime_id(&prep.cwd)?;
    let roots = collect_roots(&prep.userland, pkg_roots, tool_roots);
    super::projectstore::prepare(&prep.nix_store, &prep.layout, &id, &roots)
}

/// The complete set of logical store roots the cage resolves through `/nix`: the base
/// userland's roots, then the native `[packages]`, then the `nix:` tools. Collected
/// from the provisioners (never reconstructed by stripping sub-paths), so the seed
/// carries every closure the cage needs — a forgotten source would silently make the
/// cage re-fetch it. Pure, so the collection is unit-tested.
fn collect_roots(
    userland: &Userland,
    pkg_roots: &[PathBuf],
    tool_roots: &[PathBuf],
) -> Vec<PathBuf> {
    let mut roots = userland.base_roots.clone();
    roots.extend(pkg_roots.iter().cloned());
    roots.extend(tool_roots.iter().cloned());
    roots
}

/// Resolve a trusted project's mise `[env]` into environment entries. Empty when
/// the project declares no mise file, or it is withheld — an untrusted or changed
/// mise file only warns (its `[env]` is held back, like its security fields).
///
/// mise is provisioned via nix and driven from ops's store against the **engine**
/// channel — never this launch's possibly-pinned base reference (mise runs in its own
/// store view, free of the one-channel rule; see [`Prepared::engine_ref`]). The files
/// it reads are materialized from the bytes trust validated, outside any writable
/// mount, so it sees exactly the authorized, hashed inputs. A trusted `[env]` that
/// cannot be resolved is fatal, like a declared tool that fails to realise.
fn mise_env(prep: &Prepared) -> Result<Vec<(String, String)>, ExitCode> {
    let Some(mise_cfg) = &prep.cfg.mise else {
        return Ok(Vec::new());
    };
    if mise_cfg.state != crate::trust::TrustState::Trusted {
        eprintln!(
            "ops: warning: mise file {} withheld ({}): its [env] is not applied",
            mise_cfg.name,
            crate::config::untrusted_reason(mise_cfg.state)
        );
        return Ok(Vec::new());
    }

    // The same engine reference the in-cage mise uses, already resolved in `prepare`.
    let mise_root = super::mise::provision_engine(&prep.nix, &prep.layout, &prep.engine_ref)
        .map_err(|e| {
            eprintln!("ops: cannot provision the mise engine: {e}");
            ExitCode::FAILURE
        })?;
    let mise_bin = super::mise::bin(&mise_root);
    // Stage the authorized files in a per-project directory that sits outside every
    // writable mount (a sibling of the writable home, like the synthetic identity).
    let id = binds::project_runtime_id(&prep.cwd).map_err(|e| {
        eprintln!("ops: cannot identify the project: {e}");
        ExitCode::FAILURE
    })?;
    let stage = prep
        .layout
        .data_dir()
        .join("projects")
        .join(id)
        .join("mise-config");
    super::mise::resolve_env(
        &prep.bwrap,
        &prep.layout,
        &mise_bin,
        &mise_cfg.files,
        &stage,
    )
    .map_err(|e| {
        eprintln!("ops: mise [env] resolution failed: {e}");
        ExitCode::FAILURE
    })
}

/// Provision a trusted project's declared `nix:` mise tools into ops's store and report
/// the `bin` directories to prepend to PATH, plus warnings. Empty when the project
/// declares no mise file. An untrusted project's tools are withheld (warned), and a
/// non-`nix:` tool is left to mise — both surface as warnings the caller prints. A
/// declared, admitted tool that fails to resolve or realise is fatal, like a native
/// `[packages]` tool. Resolution is cached per project, so nixhub is queried once per
/// `(tool, version)` rather than on every launch.
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
        eprintln!("ops: {e}");
        ExitCode::FAILURE
    })
}

/// Record this sandbox in the on-disk registry so `ops ps` can list it. Best
/// effort: the registry is observability, not a security control, so a failure to
/// register degrades visibility but never blocks the sandbox. The session is keyed
/// on `spec.workdir` — the canonical project root, the same identity the runtime
/// layout derives from. Returns the record's path (to hand to a [`RecordGuard`])
/// when it was written.
fn register(data_dir: &Path, spec: &SandboxSpec, kind: Kind) -> Option<PathBuf> {
    let session = Session::current(spec.workdir.clone(), kind).ok()?;
    session::Registry::at(data_dir).register(&session).ok()
}

/// Run the cage as a child and propagate its exit status, keeping ops alive for the
/// whole session. Required by the network-allowlist posture, whose host filtering proxy
/// runs on a thread that an exec-replace would discard; `run` uses this exactly when an
/// egress guard is present. `Command::status` forks, waits, and yields the child's code;
/// the proxy thread was already spawned (by `egress::start`) before the launch.
fn run_supervised(bwrap: &Path, spec: &SandboxSpec) -> ExitCode {
    match Command::new(bwrap)
        .args(super::argv::to_argv(spec))
        .status()
    {
        Ok(status) => ExitCode::from(status_code(status) as u8),
        Err(e) => {
            eprintln!("ops: failed to launch the sandbox: {e}");
            ExitCode::FAILURE
        }
    }
}

/// A process's exit code in the shell convention: its own code, or 128 + the signal that
/// killed it (matching the pty supervisor's `pump`).
fn status_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| status.signal().map(|s| 128 + s).unwrap_or(1))
}

/// Replace the current process with bubblewrap running `spec`. A successful
/// `exec` never returns, so this returns *only* on failure.
fn exec(bwrap: &Path, spec: &SandboxSpec) -> io::Error {
    // Defense in depth: a private-tty spec relies on a controlling terminal that
    // only the pty supervisor provides. Exec-replace would leave it inheriting
    // the launching terminal, so refuse it here rather than weaken isolation.
    if spec.terminal == TerminalPolicy::PrivateTty {
        return io::Error::other(
            "internal error: a private-tty sandbox must be launched through the pty supervisor",
        );
    }
    Command::new(bwrap).args(super::argv::to_argv(spec)).exec()
}

/// Run `spec` under a pty supervisor and return its exit status code. ops opens
/// a pty, launches bwrap with the *slave* as its controlling terminal (via
/// `login_tty`), keeps the *master* itself, puts the real terminal in raw mode,
/// and relays bytes both ways until the session ends.
fn supervise(bwrap: &Path, spec: &SandboxSpec) -> io::Result<i32> {
    // Build the argv as C strings *before* forking: nothing between fork and
    // exec may allocate.
    let bwrap_c = cstring(bwrap.as_os_str().as_bytes())?;
    let mut argv_owned = vec![bwrap_c.clone()];
    for arg in super::argv::to_argv(spec) {
        argv_owned.push(cstring(arg.as_bytes())?);
    }
    let mut argv: Vec<*const libc::c_char> = argv_owned.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());

    // Carry the real terminal's window size onto the pty so the inner shell
    // wraps correctly from the start.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let winp = if unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) } == 0 {
        &ws as *const libc::winsize
    } else {
        std::ptr::null()
    };

    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    // SAFETY: out-params are valid; name/termios are null (defaults), winp is
    // null or a valid winsize.
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            winp,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }

    // The master must never reach the sandbox: with it the sandbox could read or
    // inject its own terminal stream. The parent keeps it (and never execs), so
    // close-on-exec is exactly right; `login_tty` handles the slave.
    unsafe {
        let flags = libc::fcntl(master, libc::F_GETFD);
        libc::fcntl(master, libc::F_SETFD, flags | libc::FD_CLOEXEC);
    }

    // SAFETY: between fork and exec the child calls only async-signal-safe
    // functions (`close`, `login_tty`, `execv`, `_exit`); the argv is prebuilt.
    let child = unsafe { libc::fork() };
    if child < 0 {
        let e = io::Error::last_os_error();
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
        return Err(e);
    }
    if child == 0 {
        unsafe {
            libc::close(master);
            // login_tty: setsid + make the slave our controlling terminal +
            // dup it onto stdin/out/err. This is what gives the sandbox a
            // controlling terminal (and thus job control).
            if libc::login_tty(slave) == 0 {
                libc::execv(bwrap_c.as_ptr(), argv.as_ptr());
            }
            // only reached if login_tty or execv failed
            libc::_exit(127);
        }
    }

    // Parent: keep the master, drop the slave, go raw, relay.
    unsafe { libc::close(slave) };
    let _raw = RawMode::enable(0)?;
    let status = pump(master, child);
    unsafe { libc::close(master) };
    status
}

/// Relay bytes between the real terminal and the pty master until the session
/// ends, then reap the child and return its exit status code.
fn pump(master: libc::c_int, child: libc::pid_t) -> io::Result<i32> {
    let mut fds = [
        libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let mut buf = [0u8; 8192];
    let mut stdin_open = true;

    loop {
        let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }

        // master -> stdout. Quit when the master closes (the child exited), which
        // on Linux surfaces as EIO rather than a clean EOF.
        if fds[1].revents != 0 {
            let n = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                write_all(1, &buf[..n as usize])?;
            } else if n == 0 {
                break;
            } else {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break; // EIO: end of session
            }
        }

        // stdin -> master. When the user's stdin ends, stop forwarding it but
        // keep relaying the master until the child exits.
        if stdin_open && fds[0].revents != 0 {
            let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                // best-effort: if the child is gone, the master read above ends us
                let _ = write_all(master, &buf[..n as usize]);
            } else if n == 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                stdin_open = false;
                fds[0].fd = -1; // poll ignores a negative fd
            }
        }
    }

    let mut status: libc::c_int = 0;
    loop {
        let r = unsafe { libc::waitpid(child, &mut status, 0) };
        if r < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    };
    Ok(code)
}

/// Write the whole buffer, retrying short writes and interrupts.
fn write_all(fd: libc::c_int, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

/// Put a terminal into raw mode, restoring the original settings on drop (covers
/// normal return, `?`, and panic — but not a `SIGKILL`/`SIGTERM`).
struct RawMode {
    fd: libc::c_int,
    original: libc::termios,
}

impl RawMode {
    fn enable(fd: libc::c_int) -> io::Result<Self> {
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(RawMode { fd, original })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original) };
    }
}

/// `CString` from raw bytes, mapping an interior NUL to an I/O error.
fn cstring(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::other("argument contains an interior NUL byte"))
}

/// Host variables worth carrying through the cleared environment for a usable
/// session. Secrets are never passed this way.
fn passthrough_env() -> Vec<(String, String)> {
    ["TERM", "LANG"]
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| ((*k).to_string(), v)))
        .collect()
}

/// Layer the cage's extra environment, lowest precedence first: host passthrough, then ops's
/// hermetic CA bundle, then a trusted project's mise `[env]`, then the egress machinery, then
/// the `.ops.toml` `[env]`. The assembler upserts these over the structural defaults and takes
/// the last occurrence of a key, so a later layer wins: the egress proxy's per-session CA
/// overrides the structural cacert under an allowlist, and a trusted config has the final say
/// (self-harm only). The CA bundle sits above passthrough on purpose — passthrough is a
/// separate channel, not filtered by the untrusted-config denylist, so a host CA variable
/// could otherwise clobber ops's hermetic bundle.
fn extra_cage_env(
    passthrough: Vec<(String, String)>,
    cacert: Vec<(String, String)>,
    mise: Vec<(String, String)>,
    egress: Vec<(String, String)>,
    config: &[(String, String)],
) -> Vec<(String, String)> {
    let mut env = passthrough;
    env.extend(cacert);
    env.extend(mise);
    env.extend(egress);
    env.extend(config.iter().cloned());
    env
}

fn missing(what: &str) -> ExitCode {
    eprintln!("ops: {what} not found — the sandbox cannot run. See `ops doctor`.");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Origin;
    use crate::testutil::TmpDir;
    use std::path::PathBuf;

    const REV: &str = "9ae611a455b90cf061d8f332b977e387bda8e1ca";

    /// A minimal resolved config carrying only the channel choices the builder reads.
    fn resolved(global: Option<&str>, project: Option<&str>) -> crate::config::Resolved {
        crate::config::Resolved {
            env: vec![],
            ro_binds: vec![],
            packages: vec![],
            nixpkgs_global: global.map(String::from),
            nixpkgs_project: project.map(String::from),
            mise: None,
            network: crate::config::NetworkPolicy::default(),
            secrets: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn no_pin_targets_the_global_lock_ignoring_any_stale_project_lock() {
        // Without a current pin the decision is the global channel, so the per-project
        // lock is never even named — a stale one left on disk cannot resurface. The
        // common path also does not canonicalise the cwd, so an arbitrary path is fine.
        let data = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        std::fs::write(
            layout.data_dir().join("nixpkgs.lock"),
            format!("nixos-unstable\n{REV}\n"),
        )
        .unwrap();

        let target =
            effective_lock_target(Path::new("/nonexistent"), &layout, &resolved(None, None))
                .expect("global target needs no canonicalisation");
        assert_eq!(target.origin(), Origin::Default);
        assert_eq!(target.source(), "nixos-unstable");
        // it reads the global lock, never a per-project one
        assert_eq!(target.locked_revision().as_deref(), Some(REV));
    }

    #[test]
    fn a_global_override_targets_the_global_lock_under_that_source() {
        let data = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let target = effective_lock_target(
            Path::new("/nonexistent"),
            &layout,
            &resolved(Some("nixos-23.11"), None),
        )
        .expect("global override needs no canonicalisation");
        assert_eq!(target.origin(), Origin::Global);
        assert_eq!(target.source(), "nixos-23.11");
    }

    #[test]
    fn a_trusted_pin_targets_a_per_project_lock() {
        // A pin canonicalises the cwd to key its own lock; resolving a revision pin
        // (no nix needed) records it there, not in the global lock.
        let data = TmpDir::new();
        let proj = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());

        let target = effective_lock_target(proj.path(), &layout, &resolved(None, Some(REV)))
            .expect("canonicalise the project");
        assert_eq!(target.origin(), Origin::ProjectPin);
        assert_eq!(target.source(), REV);

        target
            .resolve(Path::new("/nonexistent-nix"), &layout)
            .expect("a revision pin resolves without nix");
        // the global lock stays untouched; a per-project lock was written instead
        assert!(!layout.data_dir().join("nixpkgs.lock").exists());
        let projects = layout.data_dir().join("projects");
        let has_lock = std::fs::read_dir(&projects)
            .map(|e| e.flatten().any(|d| d.path().join("nixpkgs.lock").is_file()))
            .unwrap_or(false);
        assert!(has_lock, "a trusted pin must record a per-project lock");
    }

    #[test]
    fn collect_roots_unions_base_then_packages_then_tools() {
        // The seed's completeness rides on this collection: every provisioner's roots
        // must reach it. The order is base, then packages, then tools.
        let userland = Userland {
            base_roots: vec![
                PathBuf::from("/nix/store/glibc"),
                PathBuf::from("/nix/store/bash"),
            ],
            interp_src: PathBuf::from("/store/nix-ld"),
            interp_dest: PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
            ca_bundle_src: PathBuf::from("/store/cacert/etc/ssl/certs/ca-bundle.crt"),
            base_loader: PathBuf::from("/nix/store/glibc/lib/ld"),
            foreign_lib_paths: vec![],
            bin_paths: vec![],
            shell_bin: PathBuf::from("/nix/store/bash/bin/bash"),
            socat_bin: PathBuf::from("/nix/store/socat/bin/socat"),
        };
        let pkg_roots = [PathBuf::from("/nix/store/jq")];
        let tool_roots = [PathBuf::from("/nix/store/nodejs")];

        assert_eq!(
            collect_roots(&userland, &pkg_roots, &tool_roots),
            vec![
                PathBuf::from("/nix/store/glibc"),
                PathBuf::from("/nix/store/bash"),
                PathBuf::from("/nix/store/jq"),
                PathBuf::from("/nix/store/nodejs"),
            ]
        );

        // teeth: dropping a source loses exactly its roots — a launch that forgot to
        // forward the tools' (or packages') roots would seed an incomplete closure, and
        // the cage would silently re-fetch the missing one.
        assert!(!collect_roots(&userland, &pkg_roots, &[])
            .contains(&PathBuf::from("/nix/store/nodejs")));
        assert!(
            !collect_roots(&userland, &[], &tool_roots).contains(&PathBuf::from("/nix/store/jq"))
        );
    }

    #[test]
    fn egress_ca_overrides_the_structural_cacert() {
        // The assembler upserts the overlay env on last-occurrence, so the winner for a key is
        // its last entry in this layering. Under a network allowlist the cage must trust the
        // egress proxy's per-session CA, not ops's root bundle: egress is layered after cacert,
        // so it wins. A trusted config, layered last, still has the final say (self-harm only).
        let winner = |env: &[(String, String)]| {
            env.iter()
                .rev()
                .find(|(k, _)| k == "SSL_CERT_FILE")
                .map(|(_, v)| v.clone())
        };

        let cacert = vec![(
            "SSL_CERT_FILE".into(),
            "/etc/ssl/certs/ca-bundle.crt".into(),
        )];
        let egress = vec![("SSL_CERT_FILE".into(), "/opt/ops/egress-ca.pem".into())];
        let env = extra_cage_env(vec![], cacert.clone(), vec![], egress.clone(), &[]);
        assert_eq!(
            winner(&env).as_deref(),
            Some("/opt/ops/egress-ca.pem"),
            "egress CA must override the structural cacert"
        );

        let cfg = vec![("SSL_CERT_FILE".into(), "/cfg/ca.pem".into())];
        let env = extra_cage_env(vec![], cacert, vec![], egress, &cfg);
        assert_eq!(
            winner(&env).as_deref(),
            Some("/cfg/ca.pem"),
            "a trusted config has the final say over the CA"
        );

        // with no egress (shared/isolated posture) the structural cacert stands
        let cacert = vec![(
            "SSL_CERT_FILE".into(),
            "/etc/ssl/certs/ca-bundle.crt".into(),
        )];
        let env = extra_cage_env(vec![], cacert, vec![], vec![], &[]);
        assert_eq!(
            winner(&env).as_deref(),
            Some("/etc/ssl/certs/ca-bundle.crt"),
            "without egress the hermetic cacert is the trust anchor"
        );
    }

    #[test]
    fn net_policy_maps_the_config_posture_to_the_cage_posture() {
        // the cheap, total map between the two posture vocabularies — the one place
        // a `network = "none"` config becomes an isolated cage.
        assert_eq!(
            net_policy(&crate::config::NetworkPolicy::Shared),
            NetPolicy::Shared
        );
        assert_eq!(
            net_policy(&crate::config::NetworkPolicy::Isolated),
            NetPolicy::Isolated
        );
        // until the filtering proxy lands, an allowlist posture is fail-closed: it maps
        // to isolation (no network), never to the shared host network.
        assert_eq!(
            net_policy(&crate::config::NetworkPolicy::Allowlist(
                crate::allowlist::EgressPolicy::default()
            )),
            NetPolicy::Isolated
        );
    }

    #[test]
    fn exec_refuses_a_private_tty_spec() {
        // a private-tty spec must go through the pty supervisor; exec-replace has
        // no pty to offer, so it must refuse *before* actually exec'ing anything.
        let spec = SandboxSpec::new(
            PathBuf::from("/work"),
            vec![],
            vec![],
            NetPolicy::Shared,
            vec![OsString::from("/bin/true")],
        )
        .unwrap()
        .with_private_tty();

        let err = exec(Path::new("/bin/true"), &spec);
        assert!(
            err.to_string().contains("pty supervisor"),
            "exec must refuse a private-tty spec; got: {err}"
        );
    }
}
