//! The declared-task engine: run a validated [`TaskSpec`] in an **ephemeral sibling cage**, with a
//! credential resolved host-side per invocation, and return a structured result.
//!
//! # Why a sibling cage and not the agent's
//!
//! In the agent's cage `/nix` is the per-project store, mounted **read-write**, and a `mise` tool
//! lives under a read-write `$HOME`. A same-uid agent can therefore overwrite the very binary a task
//! is about to exec, which would turn "sbx fixes the program" into a fiction. `/proc/<pid>/environ`
//! is readable same-uid too, so a credential passed through the environment of a process in that
//! cage is readable by the agent. And a mount cannot be re-mounted read-only for one process — the
//! mount namespace is shared, and a new one *is* a new cage.
//!
//! So a task runs in a cage built from the agent cage's **structural skeleton** (the same hermetic
//! FHS, the same synthesized `/etc`, the same locale archive, so a task behaves like the project's
//! own tooling) with three deliberate differences: `/nix` comes **read-only from the shared store**
//! (immutable, built host-side, never writable by any cage), the project is read-only and `$HOME` is
//! a fresh tmpfs, and every non-structural exposure of the agent's cage — a config bind, a GUI hole,
//! a relay socket — is **dropped**, because a task needs none of them and each is a channel.
//!
//! The mandatory hardening comes for free: [`super::argv::to_argv`] emits every namespace
//! unconditionally, so the task cage has its own pid namespace, which is what keeps its `environ`
//! out of the agent's reach.
//!
//! # What a caller can influence
//!
//! Exactly two things: the declared `params` (each re-checked against the bound the task was
//! validated under) and the variable names in `env_allow`. Not the program, not the rest of the
//! environment, not the mounts.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::config::{OutputDisposition, TaskSpec};

use super::proxy::SecretNeedle;
use super::redact::{redact_named, Placeholder};
use super::spec::{Mount, NetPolicy, SandboxSpec};

/// Where a task's `$HOME` and scratch space live inside its cage: a fresh tmpfs, so nothing it
/// writes survives the invocation and nothing the agent wrote is visible to it.
const TASK_HOME: &str = "/tmp/task-home";

/// How often the runner checks whether the command has exited while enforcing the timeout. Short
/// enough that a fast task is not visibly delayed, long enough not to spin.
/// Distinguishes one invocation's host-side artifacts from another's — its proxy sockets and its
/// systemd scope. A session can serve two invocations at once, and both would otherwise derive
/// those names from the launcher pid alone and collide on them. Monotonic per process, which is all
/// it has to be: the pid already separates sessions.
///
/// It reaches a socket path, which the kernel caps at `SUN_LEN` (108), so its width is worth
/// knowing rather than assuming: the per-session call quota bounds it, making the suffix five bytes
/// (`.t499`) at its widest. Measured against a deliberately long install path
/// (`/home/<32 chars>/.local/share/sbx`) with a seven-digit pid, the full control-socket path is 84
/// bytes — the suffix spends five of roughly thirty spare.
///
/// It opens with a **dot**, not a dash, and that is load-bearing rather than cosmetic: the runtime
/// sweep reads a launcher pid as the digits up to the first `.`, so `control-<pid>.t3.sock` is
/// collected with the session that made it while `control-<pid>-t3.sock` would be a name the sweep
/// cannot parse and therefore never removes. A per-invocation CA is ~460 KB; leaving those
/// unsweepable is how a data directory grows without bound.
static TASK_INVOCATION: AtomicU64 = AtomicU64::new(0);

const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// The in-cage destinations a task cage keeps from the agent cage's mount set.
///
/// An **allowlist**, deliberately: a task needs the hermetic userland and the synthesized identity
/// files, and nothing else. Anything the agent's cage exposes that is not named here — a `[binds]`
/// path, a Wayland or PulseAudio socket, the D-Bus portal directory, a granted device, the egress
/// proxy socket — is dropped. A hole added to the agent cage later therefore does **not** silently
/// appear in task cages; it has to be named here on purpose.
///
/// Every entry must be a destination the agent cage actually emits, or it silently keeps nothing:
/// the entries are matched **exactly**, so `/bin` would not keep `/bin/sh` and `/etc/ssl` would not
/// keep the CA bundle. The names are taken from [`super::binds`]'s own constants rather than
/// retyped, and [`every_kept_destination_is_one_the_cage_emits`] fails on any entry the structural
/// set does not carry.
const KEPT_DESTS: &[&str] = &[
    "/nix",
    // The nix-ld shim and the three FHS names nix's ecosystem standardises. A mise-installed tool is
    // typically a *foreign* binary behind a `#!/usr/bin/env node` or `#!/bin/sh` shebang, so without
    // these a task cage can hold the program and still be unable to exec it.
    super::binds::LOADER_DEST,
    super::binds::SANDBOX_SHELL,
    super::binds::SANDBOX_BASH,
    super::binds::SANDBOX_ENV,
    // The synthesized identity: a tool that looks up its own user (git, ssh, anything calling
    // `getpwuid`) fails outright without these.
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/machine-id",
    "/etc/resolv.conf",
    // Both CA bundle names, so a task making an HTTPS call trusts the same roots the session does —
    // `SSL_CERT_FILE` in the inherited environment points at the first of these.
    super::binds::CAGE_CA_BUNDLE,
    "/etc/ssl/certs/ca-certificates.crt",
];

/// The environment variable names a task cage inherits from the agent cage's environment — the
/// hermetic-userland plumbing a provisioned binary needs to run at all. An allowlist for the same
/// reason as [`KEPT_DESTS`]: everything else (an agent's own configuration, a proxy pointer, a
/// display or bus address) is either irrelevant to a task or a channel.
const KEPT_ENV: &[&str] = &[
    "PATH",
    "LANG",
    "LC_ALL",
    "LOCALE_ARCHIVE",
    "TZDIR",
    "NIX_SSL_CERT_FILE",
    "SSL_CERT_FILE",
    "TERM",
    // What the nix-ld shim reads. A foreign binary reaching the shim with these unset gets no
    // loader and no base libraries, so keeping the shim's mount without its environment would leave
    // exactly the tools that need it — npm and pip artefacts from the task pool — unable to start.
    "NIX_LD",
    "NIX_LD_LIBRARY_PATH",
];

/// Everything the engine needs to run any of the session's tasks, captured once at launch (when the
/// launcher has already prepared the store, the userland and the identity files) so an invocation
/// never re-derives it.
#[derive(Debug, Clone)]
pub(crate) struct TaskEngine {
    /// The bubblewrap binary the launch resolved.
    bwrap: PathBuf,
    /// The structural mounts a task cage starts from — the agent cage's set, filtered through
    /// [`KEPT_DESTS`] and with `/nix` repointed at the shared store, read-only.
    base_mounts: Vec<Mount>,
    /// The environment a task cage starts from — the agent cage's, filtered through [`KEPT_ENV`].
    base_env: Vec<(String, String)>,
    /// The project root, bound read-only as the task's working directory.
    project: PathBuf,
    /// The project root a relative `sops://` file resolves against (the config's directory).
    config_root: PathBuf,
    /// The declared tasks, by name.
    tasks: Vec<TaskSpec>,
    /// The cgroup limits a task cage runs under — the session's, so a task cannot outgrow it.
    limits: super::cgroup::Limits,
    /// The cage slug tasks run under, for the systemd scope name.
    slug: String,
    /// The data-dir layout a per-invocation proxy is stood up under.
    layout: crate::store::Layout,
    /// The base root bundle a per-invocation proxy pairs its MITM CA with, so the injected CA file is
    /// a full, ordinary bundle (a lone certificate trips tools that reject a "too small" one).
    ca_bundle: Option<PathBuf>,
    /// The host path of this project's task tool pool, and the mise binary that fills it — present
    /// only when a task declares `packages`. See [`super::taskpool`] for why the pool exists and why
    /// it is filled host-side.
    pool: Option<(PathBuf, PathBuf)>,
    /// The in-cage programs that give a networked task a route out. Not optional: any task may
    /// declare `network`, and one that does with no forwarder would find the proxy socket bound, the
    /// proxy variables set, and nothing listening on the port they name.
    forwarder: CageForwarder,
}

/// The two cage programs a task's egress forwarder is built from, named rather than passed as a pair
/// of bare paths so the two cannot be handed over the wrong way round.
#[derive(Debug, Clone)]
pub(crate) struct CageForwarder {
    /// `socat`, which bridges the in-cage TCP port to the bound proxy socket.
    pub(crate) socat: PathBuf,
    /// The shell that backgrounds it before `exec`ing the task's own command.
    pub(crate) shell: PathBuf,
}

/// One invocation's result. Deliberately structured rather than a blob of text: the exit status is
/// always returned, each stream is present only if the declaration shows it, and `redacted` is the
/// host-side count of substituted values — the trustworthy signal, since `${name}` inside the text
/// could have been printed by the command itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskOutcome {
    /// The command's exit code, or 128 + signal if it was killed.
    pub(crate) exit: i32,
    /// stdout after substitution, or `None` when the declaration hides it.
    pub(crate) stdout: Option<String>,
    /// stderr after substitution, or `None` when the declaration hides it.
    pub(crate) stderr: Option<String>,
    /// Whether a stream hit `max_output` and was cut. Reported, never silent — a truncated result
    /// that looked complete would be worse than no result.
    pub(crate) truncated: bool,
    /// How many secret values were substituted out, across both streams.
    pub(crate) redacted: usize,
    /// Whether the timeout killed the command.
    pub(crate) timed_out: bool,
    /// How long the invocation took, in milliseconds.
    pub(crate) elapsed_ms: u64,
    /// This invocation's substitution nonce, when the section enabled it. Reported **out of band**
    /// (here, not in the text) on purpose: that is what makes a `${NAME@nonce}` in the output
    /// unforgeable for this invocation — the command could not have predicted it.
    pub(crate) nonce: Option<String>,
}

/// Draw this invocation's substitution nonce: 6 hex characters from the system CSPRNG (already in the
/// dependency tree via rustls/rcgen). Short, because it only has to be unpredictable *per
/// invocation* — it authenticates a placeholder inside one result, it is not a secret.
fn invocation_nonce() -> String {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 3];
    if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
        // No randomness means no unforgeable nonce; say so in the placeholder rather than emit a
        // predictable one that would read as authenticated.
        return "unseeded".to_string();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Why an invocation was refused or failed. A refusal names *what* was wrong without echoing a
/// caller's value back (a value can carry a secret the caller is probing for).
#[derive(Debug)]
pub(crate) enum TaskError {
    /// No task by that name is declared for this session.
    Unknown(String),
    /// A caller-supplied parameter or environment variable was refused.
    Refused(String),
    /// A credential could not be resolved host-side. The message names the *source*, never a value.
    Credential(String),
    /// The cage could not be built or run.
    Io(io::Error),
}

impl std::fmt::Display for TaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskError::Unknown(name) => write!(f, "no such task `{name}`"),
            TaskError::Refused(why) => write!(f, "{why}"),
            TaskError::Credential(why) => write!(f, "cannot resolve the credential: {why}"),
            TaskError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl TaskEngine {
    /// Build the engine from the agent cage's own spec, so a task cage is derived from — rather than
    /// a parallel reimplementation of — whatever the launcher assembled for this session.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_cage(
        bwrap: &Path,
        cage: &SandboxSpec,
        layout: &crate::store::Layout,
        project: &Path,
        config_root: &Path,
        tasks: Vec<TaskSpec>,
        limits: super::cgroup::Limits,
        slug: &str,
        ca_bundle: Option<&Path>,
        forwarder: CageForwarder,
    ) -> Self {
        Self {
            bwrap: bwrap.to_path_buf(),
            base_mounts: task_mounts(cage.mounts(), &layout.store_dir().join("nix")),
            base_env: task_env(cage.env()),
            project: project.to_path_buf(),
            config_root: config_root.to_path_buf(),
            tasks,
            limits,
            slug: slug.to_string(),
            layout: layout.clone(),
            ca_bundle: ca_bundle.map(Path::to_path_buf),
            pool: None,
            forwarder,
        }
    }

    /// Point the engine at this project's task tool pool, filled by `mise_bin`. Separate from
    /// [`TaskEngine::from_cage`] because it is conditional: a session whose tasks declare no
    /// `packages` never materializes a pool, and never pays for one.
    pub(crate) fn with_pool(mut self, pool: PathBuf, mise_bin: PathBuf) -> Self {
        self.pool = Some((pool, mise_bin));
        self
    }

    /// Every mise tool the session's tasks declare, deduplicated — what the pool must hold.
    pub(crate) fn declared_packages(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for token in self.tasks.iter().flat_map(|t| t.packages.iter()) {
            if !out.contains(token) {
                out.push(token.clone());
            }
        }
        out
    }

    /// Fill the pool so every declared tool is realized. A no-op when no task declares one, and a
    /// single directory listing when the pool is already warm — the common case, since a pool is
    /// filled once per project rather than once per launch.
    pub(crate) fn ensure_pool(&self) -> io::Result<super::taskpool::PoolOutcome> {
        let Some((pool, mise_bin)) = &self.pool else {
            return Ok(super::taskpool::PoolOutcome::Warm);
        };
        super::taskpool::ensure(
            &self.bwrap,
            &self.base_mounts,
            &self.base_env,
            mise_bin,
            pool,
            &self.declared_packages(),
            &self.limits,
            &format!("{}-task-pool", self.slug),
        )
    }

    /// Roll every declared pool tool whose version spec still floats. A no-op when no task declares
    /// one. See [`super::taskpool::upgrade`] for why a pool without this is frozen for good.
    pub(crate) fn upgrade_pool(&self) -> io::Result<Option<super::taskpool::InstallRun>> {
        let Some((pool, mise_bin)) = &self.pool else {
            return Ok(None);
        };
        super::taskpool::upgrade(
            &self.bwrap,
            &self.base_mounts,
            &self.base_env,
            mise_bin,
            pool,
            &self.declared_packages(),
            &self.limits,
            &format!("{}-task-pool", self.slug),
        )
    }

    /// The tools `task` declares that the pool does not hold — so a caller listing the operations
    /// can be told which ones will fail before invoking them. Empty when the task declares none.
    pub(crate) fn missing_packages(&self, task: &TaskSpec) -> Vec<String> {
        match (&self.pool, task.packages.is_empty()) {
            (_, true) => Vec::new(),
            (Some((pool, _)), false) => super::taskpool::bins_for(pool, &task.packages).missing,
            (None, false) => task.packages.clone(),
        }
    }

    /// The declared tasks, for the inventory a caller lists.
    pub(crate) fn tasks(&self) -> &[TaskSpec] {
        &self.tasks
    }

    /// Look up a task by name.
    pub(crate) fn task(&self, name: &str) -> Option<&TaskSpec> {
        self.tasks.iter().find(|t| t.name == name)
    }

    /// Run one task: check the caller's inputs, resolve the credentials host-side, build the cage,
    /// run it under its ceilings, substitute every secret value out of the captured output, and
    /// return the structured result.
    pub(crate) fn run(
        &self,
        name: &str,
        params: &BTreeMap<String, String>,
        env: &BTreeMap<String, String>,
    ) -> Result<TaskOutcome, TaskError> {
        let task = self
            .task(name)
            .ok_or_else(|| TaskError::Unknown(name.into()))?;
        let values = resolve_params(task, params).map_err(TaskError::Refused)?;
        let caller_env = caller_env(task, env).map_err(TaskError::Refused)?;
        let argv = substitute(&task.cmd, &values).map_err(TaskError::Refused)?;

        // Resolve the credentials for THIS invocation only, host-side. Nothing is cached: a
        // credential lives in this process for the duration of one command and its needles.
        let mut cage_env = self.base_env.clone();
        let mut needles = Vec::new();
        for secret in &task.secrets {
            let plaintext = resolve_secret(secret, &self.config_root, &self.bwrap)
                .map_err(TaskError::Credential)?;
            for bytes in secret.encode.variants(&plaintext) {
                needles.push(SecretNeedle::named(&secret.var, bytes));
            }
            cage_env.push((secret.var.clone(), secret.encode.render(&plaintext)));
        }
        for (k, v) in &task.env {
            cage_env.push((k.clone(), v.clone()));
        }
        cage_env.extend(caller_env);
        cage_env.push(("HOME".to_string(), TASK_HOME.to_string()));
        // A tool that caches beside `$HOME` must land on the tmpfs, not fail writing into the
        // read-only pool it was installed in.
        cage_env.push(("XDG_CACHE_HOME".to_string(), format!("{TASK_HOME}/.cache")));
        // The task's own mise tools, ahead of the base userland: a declared tool wins over a base
        // one of the same name, matching how a project's declared packages sit on the agent's PATH.
        // The pool's shims resolve through mise, so its environment comes with them.
        if let Some(dirs) = self.pool_bins(task) {
            prepend_path(&mut cage_env, &dirs);
            cage_env.extend(super::taskpool::task_env(TASK_HOME));
        }
        // A task is never interactive: say so, so a tool that would otherwise try to prompt fails
        // fast instead of hanging until the timeout.
        cage_env.push(("SBX_TASK".to_string(), name.to_string()));

        // Egress, when the task declares any: a proxy of its **own**, for this invocation only.
        //
        // Not the session's proxy, and not because that would be untidy: with no per-process identity
        // (same-uid), a shared proxy cannot tell a task's connection from the agent's, so registering
        // a task's credential in the session's injection table would let the agent trigger the
        // injection itself by aiming at that host. The socket is the only authority boundary
        // available, so a task gets its own — with its own rules and its own injections.
        // One identity for this invocation, worn by everything it stands up. Concurrent invocations
        // are ordinary — an agent may ask for two at once — and every name derived from the launcher
        // pid alone would be the same name twice.
        let invocation = TASK_INVOCATION.fetch_add(1, Ordering::Relaxed);
        let mut proxy_binds = Vec::new();
        let mut proxy_env = Vec::new();
        let mut argv = argv;
        let _proxy = if task.network.is_empty() {
            None
        } else {
            let policy = crate::allowlist::EgressPolicy::new(task.network.clone(), Vec::new());
            let (guard, wiring) = super::egress::start(
                &self.layout,
                policy,
                &task.injections,
                &self.config_root,
                &self.bwrap,
                None,
                false,
                self.ca_bundle.as_deref(),
                &format!(".t{invocation}"),
            )
            .map_err(TaskError::Io)?;
            proxy_binds = wiring.binds;
            proxy_env = wiring.env;
            argv = self.cage_argv(argv, task);
            Some(guard)
        };
        cage_env.extend(proxy_env);

        let spec = self
            .build_spec(argv, &cage_env, &proxy_binds, task, invocation)
            .map_err(|e| TaskError::Io(io::Error::other(e)))?;
        let started = Instant::now();
        // A failure message is substituted too: it can carry the command's own diagnostics, and
        // there is no reason for the one path that reports trouble to be the one that leaks.
        let placeholder = if task.nonce {
            Placeholder::Nonced(invocation_nonce())
        } else {
            Placeholder::Plain
        };
        let raw = self.exec(&spec, task).map_err(|e| {
            let (text, _) = super::redact::redact_string(&e.to_string(), &needles, &placeholder);
            TaskError::Io(io::Error::other(text))
        })?;
        let elapsed_ms = started.elapsed().as_millis() as u64;

        // Substitution happens before anything is returned or logged, and on the raw bytes: the
        // output is arbitrary, and decoding first could split a value across a replacement
        // character and hide it from the scan.
        let (out_bytes, out_hits) = redact_named(&raw.stdout, &needles, &placeholder);
        let (err_bytes, err_hits) = redact_named(&raw.stderr, &needles, &placeholder);
        Ok(TaskOutcome {
            nonce: match &placeholder {
                Placeholder::Nonced(n) => Some(n.clone()),
                Placeholder::Plain => None,
            },
            exit: raw.exit,
            stdout: match task.stdout {
                OutputDisposition::Show => Some(String::from_utf8_lossy(&out_bytes).into_owned()),
                OutputDisposition::Hide => None,
            },
            stderr: match task.stderr {
                OutputDisposition::Show => Some(String::from_utf8_lossy(&err_bytes).into_owned()),
                OutputDisposition::Hide => None,
            },
            truncated: raw.truncated,
            redacted: out_hits + err_hits,
            timed_out: raw.timed_out,
            elapsed_ms,
        })
    }

    /// The argv the cage actually runs: the task's own command, preceded by the egress forwarder
    /// when — and only when — the task declared `network`.
    ///
    /// The proxy this task gets serves a **Unix socket** bound into the cage, while the proxy
    /// variables handed to the command name a **TCP port**. Something has to bridge the two, and it
    /// can only be inside: the cage's network namespace is empty, so its loopback is its own and
    /// reachable from nowhere else. Without the bridge the socket is mounted, the variables are set,
    /// and every connection is refused — a task that declared egress would silently have none.
    ///
    /// A task with no `network` is left exactly as declared: it has no proxy to reach, and an
    /// unnecessary shell around a credential-bearing command is surface for nothing.
    fn cage_argv(&self, argv: Vec<OsString>, task: &TaskSpec) -> Vec<OsString> {
        if task.network.is_empty() {
            return argv;
        }
        super::egress::wrap_command(&self.forwarder.socat, &self.forwarder.shell, argv)
    }

    /// Assemble the cage for one invocation: the structural skeleton, the project read-only, a fresh
    /// tmpfs home, an empty network namespace.
    fn build_spec(
        &self,
        argv: Vec<OsString>,
        env: &[(String, String)],
        proxy_binds: &[super::binds::ExtraBind],
        task: &TaskSpec,
        invocation: u64,
    ) -> Result<SandboxSpec, String> {
        let mut mounts = self.base_mounts.clone();
        // The task tool pool, **read-only** and at the same in-cage path the install cage used —
        // that agreement is what keeps the absolute paths mise baked into the pool valid. Bound only
        // when this task declares a tool, so a task that needs none sees no pool at all.
        if let Some((pool, _)) = &self.pool {
            if !task.packages.is_empty() && pool.is_dir() {
                mounts.push(Mount::RoBind {
                    src: pool.clone(),
                    dest: PathBuf::from(super::taskpool::POOL_INCAGE),
                });
            }
        }
        mounts.push(Mount::Proc {
            dest: PathBuf::from("/proc"),
        });
        mounts.push(Mount::Dev {
            dest: PathBuf::from("/dev"),
        });
        // The scratch tmpfs, then the home tmpfs inside it. **Before** everything that can live
        // under `/tmp`: a later `/tmp` tmpfs mounts over whatever was bound beneath it, which would
        // silently swallow the proxy socket and — for a project that happens to live under `/tmp` —
        // the project itself.
        mounts.push(Mount::Tmpfs {
            dest: PathBuf::from("/tmp"),
        });
        mounts.push(Mount::Tmpfs {
            dest: PathBuf::from(TASK_HOME),
        });
        // This invocation's own proxy socket and CA — the only channel a task cage ever gets, and
        // only when the task declared egress. Its socket lives under `/tmp`, hence after the tmpfs.
        for bind in proxy_binds {
            mounts.push(if bind.writable {
                Mount::Bind {
                    src: bind.src.clone(),
                    dest: bind.dest.clone(),
                }
            } else {
                Mount::RoBind {
                    src: bind.src.clone(),
                    dest: bind.dest.clone(),
                }
            });
        }
        // The project, read-only: a task reads the repository it operates on, and a task that could
        // write it would be a way to edit the project through a credential-bearing command. Last,
        // so it survives wherever on the filesystem it sits.
        mounts.push(Mount::RoBind {
            src: self.project.clone(),
            dest: self.project.clone(),
        });
        SandboxSpec::new(
            self.project.clone(),
            mounts,
            env.to_vec(),
            NetPolicy::Isolated,
            argv,
        )
        // The invocation number is part of the cage's name because it is part of its identity: the
        // name becomes a systemd scope, and systemd refuses a launch outright on a live collision.
        .map(|s| s.with_cage_slug(format!("{}-task{invocation}", self.slug)))
        .map_err(|e| format!("cannot build the task cage: {e:?}"))
    }

    /// Run the assembled cage, capturing both streams up to the task's ceiling and killing it at the
    /// timeout. Returns the raw (unsubstituted) bytes — substitution is the caller's next step, so
    /// there is exactly one place it can be forgotten.
    fn exec(&self, spec: &SandboxSpec, task: &TaskSpec) -> io::Result<RawOutput> {
        let (argv, _seccomp) = super::launch::seccomp_argv(spec)?;
        let (prog, args) = super::cgroup::wrap(&self.bwrap, argv, &self.limits, spec.cage_slug());
        let mut child = Command::new(prog)
            .args(args)
            // No stdin at all: a task is non-interactive, and an inherited stdin would be a channel
            // into a credential-bearing command.
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Read both streams on their own threads so neither can block the other by filling its pipe
        // while the runner waits on the wrong one.
        let cap = task.max_output as usize;
        let mut out_pipe = child.stdout.take().expect("stdout piped");
        let mut err_pipe = child.stderr.take().expect("stderr piped");
        let out_reader = std::thread::spawn(move || read_capped(&mut out_pipe, cap));
        let err_reader = std::thread::spawn(move || read_capped(&mut err_pipe, cap));

        let deadline = Instant::now() + task.timeout;
        let mut timed_out = false;
        let status = loop {
            match child.try_wait()? {
                Some(status) => break status,
                None if Instant::now() >= deadline => {
                    // Killing bwrap tears the whole cage down: it is the pid-namespace init for
                    // everything inside, so no descendant outlives the timeout.
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait()?;
                }
                None => std::thread::sleep(POLL_INTERVAL),
            }
        };

        // A reader thread that panicked leaves no bytes rather than taking the invocation down: the
        // exit status is the part a caller most needs, and losing a stream is the safe direction.
        let (stdout, out_cut) = out_reader
            .join()
            .unwrap_or_else(|_| Ok((Vec::new(), false)))?;
        let (stderr, err_cut) = err_reader
            .join()
            .unwrap_or_else(|_| Ok((Vec::new(), false)))?;
        Ok(RawOutput {
            exit: super::launch::status_code(status),
            stdout,
            stderr,
            truncated: out_cut || err_cut,
            timed_out,
        })
    }
}

/// The in-cage `bin` directories for `task`'s declared mise tools, or `None` when it declares none.
/// A tool the pool does not hold contributes nothing rather than a dangling path entry: the command
/// then fails with a plain "not found", which is what actually happened.
impl TaskEngine {
    fn pool_bins(&self, task: &TaskSpec) -> Option<Vec<PathBuf>> {
        let (pool, _) = self.pool.as_ref()?;
        if task.packages.is_empty() {
            return None;
        }
        let bins = super::taskpool::bins_for(pool, &task.packages).bins;
        (!bins.is_empty()).then_some(bins)
    }
}

/// Put `dirs` at the front of the environment's `PATH`, preserving the rest. Upserts, so a `PATH`
/// the base environment did not carry is created rather than silently dropped.
fn prepend_path(env: &mut Vec<(String, String)>, dirs: &[PathBuf]) {
    let prefix = dirs
        .iter()
        .map(|d| d.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(":");
    match env.iter_mut().find(|(k, _)| k == "PATH") {
        Some(slot) if slot.1.is_empty() => slot.1 = prefix,
        Some(slot) => slot.1 = format!("{prefix}:{}", slot.1),
        None => env.push(("PATH".to_string(), prefix)),
    }
}

/// The unsubstituted capture of one invocation, internal to the engine.
struct RawOutput {
    exit: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
    timed_out: bool,
}

/// Read a stream up to `cap` bytes, reporting whether it was cut. Reading continues past the cap
/// (draining the pipe) so the command is never blocked on a full pipe — only the *kept* bytes are
/// bounded.
fn read_capped(pipe: &mut impl Read, cap: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut kept = Vec::new();
    let mut cut = false;
    let mut buf = [0u8; 8192];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if kept.len() < cap {
                    let room = cap - kept.len();
                    let take = room.min(n);
                    kept.extend_from_slice(&buf[..take]);
                    if take < n {
                        cut = true;
                    }
                } else {
                    cut = true;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok((kept, cut))
}

/// Derive a task cage's mounts from the agent cage's: keep the structural skeleton (see
/// [`KEPT_DESTS`]), repoint `/nix` at the shared store read-only, and demote every kept read-write
/// bind to read-only.
fn task_mounts(cage: &[Mount], shared_store_nix: &Path) -> Vec<Mount> {
    let mut out = Vec::new();
    for mount in cage {
        let dest = mount_dest(mount);
        if !KEPT_DESTS.contains(&dest.to_string_lossy().as_ref()) {
            continue;
        }
        if dest == Path::new("/nix") {
            // The agent's `/nix` is the per-project store, mounted read-write — a binary there is
            // agent-mutable. A task's program must come from the shared store, which no cage writes.
            out.push(Mount::RoBind {
                src: shared_store_nix.to_path_buf(),
                dest: PathBuf::from("/nix"),
            });
            continue;
        }
        out.push(match mount.clone() {
            // A writable exposure has no place in a task cage: demote rather than drop, so the
            // hermetic userland stays complete.
            Mount::Bind { src, dest } => Mount::RoBind { src, dest },
            other => other,
        });
    }
    out
}

/// The in-cage destination of a mount. (The spec's own accessor is test-only, so the engine keeps
/// its own read-only view of the same mapping.)
fn mount_dest(mount: &Mount) -> &Path {
    match mount {
        Mount::RoBind { dest, .. }
        | Mount::RoBindTry { dest, .. }
        | Mount::Bind { dest, .. }
        | Mount::Symlink { dest, .. }
        | Mount::Proc { dest }
        | Mount::Dev { dest }
        | Mount::DevBind { dest, .. }
        | Mount::Tmpfs { dest } => dest,
    }
}

/// The environment a task cage starts from: the agent cage's, filtered through [`KEPT_ENV`].
fn task_env(cage: &[(String, String)]) -> Vec<(String, String)> {
    cage.iter()
        .filter(|(k, _)| KEPT_ENV.contains(&k.as_str()))
        .cloned()
        .collect()
}

/// Check the caller's parameter values against the declaration and fill in the defaults. An
/// undeclared parameter is refused (rather than ignored — a caller that thinks it constrained
/// something must not be silently overruled), a missing required one is refused, and every supplied
/// value is re-checked against the bound the task was accepted under.
fn resolve_params(
    task: &TaskSpec,
    supplied: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, String> {
    if let Some(unknown) = supplied
        .keys()
        .find(|k| !task.params.iter().any(|p| &&p.name == k))
    {
        return Err(format!(
            "`{unknown}` is not a parameter of task `{}`",
            task.name
        ));
    }
    let mut out = BTreeMap::new();
    for param in &task.params {
        let value = match (supplied.get(&param.name), &param.default) {
            (Some(v), _) => {
                crate::config::check_value(&param.name, v, &param.bound)?;
                v.clone()
            }
            (None, Some(d)) => d.clone(),
            (None, None) => {
                return Err(format!("parameter `{}` is required", param.name));
            }
        };
        out.insert(param.name.clone(), value);
    }
    Ok(out)
}

/// Check the caller's environment against `env_allow`. An unlisted name is refused: the allowlist is
/// the whole control, so quietly dropping a name would leave a caller believing it was applied.
fn caller_env(
    task: &TaskSpec,
    supplied: &BTreeMap<String, String>,
) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for (name, value) in supplied {
        if !task.env_allow.iter().any(|a| a == name) {
            return Err(format!(
                "`{name}` is not settable for task `{}` (its `env_allow` lists {})",
                task.name,
                if task.env_allow.is_empty() {
                    "nothing".to_string()
                } else {
                    task.env_allow.join(", ")
                }
            ));
        }
        if value.contains('\0') {
            return Err(format!("`{name}` contains a NUL byte"));
        }
        out.push((name.clone(), value.clone()));
    }
    Ok(out)
}

/// Substitute the parameter values into the argv. A placeholder is replaced **inside** the element
/// that carries it and never splits into extra elements, so a value can add data to the command but
/// never structure. Every placeholder was validated as declared, so an unknown one here is an
/// internal inconsistency rather than a caller error — it still fails closed.
fn substitute(cmd: &[String], values: &BTreeMap<String, String>) -> Result<Vec<OsString>, String> {
    let mut out = Vec::with_capacity(cmd.len());
    for element in cmd {
        let mut rendered = String::with_capacity(element.len());
        let mut rest = element.as_str();
        while let Some(open) = rest.find('{') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('}') else {
                break;
            };
            let name = &after[..close];
            if name.is_empty() {
                // Not a placeholder — a literal `{}` stays literal.
                rendered.push_str(&rest[..open + 2]);
                rest = &after[close + 1..];
                continue;
            }
            let value = values
                .get(name)
                .ok_or_else(|| format!("no value for parameter `{name}`"))?;
            rendered.push_str(&rest[..open]);
            rendered.push_str(value);
            rest = &after[close + 1..];
        }
        rendered.push_str(rest);
        out.push(OsString::from(rendered));
    }
    Ok(out)
}

#[cfg(test)]
impl TaskEngine {
    /// An engine that knows an inventory but can launch nothing.
    ///
    /// It is enough to serve the listing verbs and to validate an invocation's parameters — so the
    /// wire protocol is exercisable end to end without provisioning a cage, which is what lets the
    /// in-cage client be tested against the real plane rather than a stand-in for it.
    pub(crate) fn inventory_only(tasks: Vec<crate::config::TaskSpec>) -> Self {
        Self {
            bwrap: PathBuf::from("/nonexistent/bwrap"),
            forwarder: CageForwarder {
                socat: PathBuf::from("/nonexistent/socat"),
                shell: PathBuf::from("/nonexistent/bash"),
            },
            base_mounts: Vec::new(),
            base_env: Vec::new(),
            project: PathBuf::from("/nonexistent"),
            config_root: PathBuf::from("/nonexistent"),
            tasks,
            limits: super::cgroup::Limits::default(),
            slug: "inventory".to_string(),
            layout: crate::store::Layout::under(Path::new("/nonexistent")),
            ca_bundle: None,
            pool: None,
        }
    }

    /// Point the engine's launcher at `bwrap`, so a test can stand in a program of its own for the
    /// cage. What that buys is timing: the real answer to an invocation is only as fast as the
    /// command behind it, and a plane that always answers instantly cannot show whether the wire
    /// survives an operation that takes a while.
    #[cfg(test)]
    pub(crate) fn with_launcher(mut self, bwrap: PathBuf) -> Self {
        self.bwrap = bwrap;
        self
    }
}

/// Read one credential host-side, trying its sources in order. The first that yields a non-empty
/// value wins; a later one is a fallback. Reuses the session's resolver layer, so `env://`,
/// `file://`, `sops://` and every installed resolver plugin work in a task exactly as they do for a
/// wire injection — one source path, no second implementation.
fn resolve_secret(
    secret: &crate::config::TaskSecret,
    config_root: &Path,
    bwrap: &Path,
) -> Result<String, String> {
    super::egress::resolve_chain(&secret.sources, &secret.var, config_root, bwrap)
        .map_err(|e| e.to_string())
}

/// End-to-end smoke: a real task, in a real sibling cage, through real bwrap.
///
/// The unit tests above pin the pure derivations (mounts, environment, substitution). Only this
/// proves the assembled thing runs: the command executes in the cage, its credential arrives through
/// the environment, the parameter value reaches it as one argument, the output comes back
/// substituted, and the ceilings actually fire. Skipped, not failed, where the prerequisites are
/// absent.
#[cfg(test)]
mod smoke {
    use super::*;
    use crate::config::{Encoding, OutputDisposition, ParamBound, TaskParam, TaskSecret};
    use crate::testutil::TmpDir;

    /// The engine, wired to a real provisioned userland — or `None` to skip. `pool`, when given,
    /// points the engine at a task tool pool already realized on disk.
    fn engine_with(
        tasks: Vec<TaskSpec>,
        project: &Path,
        pool: Option<&Path>,
    ) -> Option<(TaskEngine, TmpDir)> {
        let (engine, data) = engine_for(tasks, project)?;
        Some(match pool {
            Some(p) => (
                engine.with_pool(p.to_path_buf(), PathBuf::from("/nonexistent/mise")),
                data,
            ),
            None => (engine, data),
        })
    }

    /// The engine, wired to a real provisioned userland — or `None` to skip.
    fn engine_for(tasks: Vec<TaskSpec>, project: &Path) -> Option<(TaskEngine, TmpDir)> {
        let bwrap = crate::pathfind::find_on_path("bwrap")?;
        if !matches!(crate::probe_userns(), crate::Userns::Ok) {
            return None;
        }
        let nix = crate::store::resolve_nix(None)?;
        let data = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let nixpkgs = crate::store::LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .ok()?;
        let userland =
            super::super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &nixpkgs).ok()?;

        // Assemble an agent cage exactly as the launcher would, then derive the engine from it — the
        // same path production takes, so what this exercises is the real derivation.
        let overlay = super::super::binds::Overlay {
            env: &[("TERM".to_string(), "dumb".to_string())],
            binds: &[],
            bin_paths: &[],
        };
        let nix_mount = super::super::binds::NixMount {
            src: crate::store::physical_path(&layout, Path::new("/nix")),
            writable: false,
            on_btrfs: false,
        };
        let cage = super::super::binds::build_spec(
            data.path(),
            project,
            super::super::binds::Runtime::ProjectDefault,
            &userland,
            &nix_mount,
            &overlay,
            &[],
            NetPolicy::Isolated,
            "",
            super::super::seccomp::SeccompPolicy::default(),
            &[],
            vec![OsString::from("/bin/true")],
        )
        .ok()?;
        let engine = TaskEngine::from_cage(
            &bwrap,
            &cage,
            &layout,
            project,
            project,
            tasks,
            super::super::cgroup::Limits::default(),
            "smoke",
            None,
            CageForwarder {
                socat: crate::pathfind::find_on_path("socat")
                    .unwrap_or_else(|| PathBuf::from("/nonexistent/socat")),
                shell: crate::pathfind::find_on_path("bash")
                    .unwrap_or_else(|| PathBuf::from("/nonexistent/bash")),
            },
        );
        Some((engine, data))
    }

    /// A task that prints its credential and its parameter, so both paths are observable at once.
    fn echo_task(shell: &str) -> TaskSpec {
        TaskSpec {
            name: "echo-secret".into(),
            description: Some("prints the credential and the parameter".into()),
            cmd: vec![
                shell.to_string(),
                "-c".into(),
                "echo \"tok=$DEMO_TOKEN arg=$1\"".into(),
                "sh".into(),
                "{value}".into(),
            ],
            params: vec![TaskParam {
                name: "value".into(),
                bound: ParamBound::Pattern("^[a-z ]+$".into()),
                default: None,
            }],
            secrets: vec![TaskSecret {
                var: "DEMO_TOKEN".into(),
                sources: vec![crate::config::SecretSource::Env(
                    "SBX_SMOKE_TASK_TOKEN".into(),
                )],
                encode: Encoding::Raw,
                description: None,
            }],
            injections: vec![],
            env: BTreeMap::new(),
            env_allow: vec![],
            stdout: OutputDisposition::Show,
            stderr: OutputDisposition::Show,
            timeout: Duration::from_secs(30),
            max_output: 4096,
            network: vec![],
            nonce: false,
            packages: vec![],
        }
    }

    fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_declared_task_runs_in_a_sibling_cage_and_comes_back_substituted() {
        let project = TmpDir::new();
        std::fs::write(project.path().join("README"), b"hi").unwrap();
        // The credential is read host-side from sbx's own environment, so the value never has to be
        // written anywhere the cage can see.
        std::env::set_var("SBX_SMOKE_TASK_TOKEN", "smoke-token-abcdef");

        let shell = match crate::store::resolve_nix(None).and_then(|nix| {
            let data = TmpDir::new();
            let layout = crate::store::Layout::under(data.path());
            let nixpkgs = crate::store::LockTarget::global(&layout, None)
                .resolve(&nix, &layout)
                .ok()?;
            super::super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &nixpkgs)
                .ok()
                .map(|u| u.shell_bin)
        }) {
            Some(shell) => shell,
            None => {
                eprintln!("skipping task smoke: need nix and a provisioned userland");
                return;
            }
        };
        let Some((engine, _data)) =
            engine_for(vec![echo_task(&shell.to_string_lossy())], project.path())
        else {
            eprintln!("skipping task smoke: need bwrap, userns, and nix");
            return;
        };

        let outcome = engine
            .run(
                "echo-secret",
                &params(&[("value", "hello there")]),
                &BTreeMap::new(),
            )
            .expect("the task runs");

        assert_eq!(outcome.exit, 0, "stderr: {:?}", outcome.stderr);
        let stdout = outcome.stdout.expect("stdout is shown");
        // The credential reached the command (it printed something for it) but comes back named,
        // never in the clear — and the parameter arrived as ONE argument, spaces included.
        assert!(
            stdout.contains("tok=${DEMO_TOKEN}"),
            "the credential must come back substituted: {stdout}"
        );
        assert!(
            !stdout.contains("smoke-token-abcdef"),
            "the plaintext must never reach the caller: {stdout}"
        );
        assert!(
            stdout.contains("arg=hello there"),
            "the parameter must arrive as one argument: {stdout}"
        );
        assert_eq!(outcome.redacted, 1, "one substitution, counted host-side");
        assert!(!outcome.timed_out && !outcome.truncated);

        // A value outside its bound never reaches the cage at all.
        let refused = engine.run(
            "echo-secret",
            &params(&[("value", "DROP TABLE t")]),
            &BTreeMap::new(),
        );
        assert!(
            matches!(refused, Err(TaskError::Refused(_))),
            "an out-of-bound value must be refused: {refused:?}"
        );
        std::env::remove_var("SBX_SMOKE_TASK_TOKEN");
    }

    /// The task tool pool, end to end in a real cage: a tool realized in the pool exactly as mise
    /// lays one out is found by **name** (so the pool reached `PATH`), it is a `#!/bin/sh` script
    /// (so the cage kept the synthetic shell a shebang needs — the affordance a mise-installed tool
    /// almost always relies on), and the pool it came from is **read-only** inside the cage.
    ///
    /// A pool realized by hand rather than by a real `mise install`, on purpose: what needs proving
    /// here is sbx's wiring — the mount, its mode, its path, and the `PATH` prefix — and a real
    /// install would make this a network test of mise's backends instead.
    #[test]
    fn a_pool_tool_runs_by_name_and_its_pool_is_read_only() {
        let project = TmpDir::new();
        let pool_base = TmpDir::new();
        let pool = pool_base.join("task-mise");
        // The install record, so the pool reports the tool as realized...
        std::fs::create_dir_all(pool.join("installs/demo-tool/1.0")).unwrap();
        // The recorded spec `mise use -g` writes: a token counts as satisfied only when the
        // install and the record agree, since the record is what a shim resolves through.
        std::fs::create_dir_all(pool.join("config")).unwrap();
        std::fs::write(
            pool.join("config/config.toml"),
            "[tools]\ndemo-tool = \"latest\"\n",
        )
        .unwrap();
        // ...and the shim, which is what `PATH` actually resolves through. A plain script rather
        // than mise's real trampoline: the wiring under test is sbx's — the mount, its mode, its
        // path, the `PATH` prefix — and driving mise here would make this a network test of its
        // backends. It is a `#!/bin/sh` script, so it also proves the cage kept the synthetic shell
        // that a mise-installed tool's shebang almost always needs.
        let shims = pool.join("shims");
        std::fs::create_dir_all(&shims).unwrap();
        std::fs::write(
            shims.join("demo-tool"),
            "#!/bin/sh\necho \"pool-tool ran\"\n\
             if echo x > /opt/sbx/task-mise/probe 2>/dev/null; then echo POOL-WRITABLE; fi\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                shims.join("demo-tool"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }

        let spec = TaskSpec {
            name: "pool-tool".into(),
            description: None,
            cmd: vec!["demo-tool".into()],
            params: vec![],
            secrets: vec![],
            injections: vec![],
            env: BTreeMap::new(),
            env_allow: vec![],
            stdout: OutputDisposition::Show,
            stderr: OutputDisposition::Show,
            timeout: Duration::from_secs(30),
            max_output: 4096,
            network: vec![],
            nonce: false,
            packages: vec!["demo-tool".into()],
        };

        let Some((engine, _data)) = engine_with(vec![spec], project.path(), Some(&pool)) else {
            eprintln!("skipping task pool smoke: need bwrap, userns, and nix");
            return;
        };
        let outcome = engine
            .run("pool-tool", &BTreeMap::new(), &BTreeMap::new())
            .expect("the pool task runs");

        let stdout = outcome.stdout.unwrap_or_default();
        assert_eq!(
            outcome.exit, 0,
            "stdout: {stdout:?} stderr: {:?}",
            outcome.stderr
        );
        assert!(
            stdout.contains("pool-tool ran"),
            "the pool's tool must resolve by name on PATH: {stdout}"
        );
        assert!(
            !stdout.contains("POOL-WRITABLE"),
            "the pool must be read-only inside the cage: {stdout}"
        );
        assert!(
            !pool.join("probe").exists(),
            "nothing in the cage may write through to the pool on the host"
        );
    }

    #[test]
    fn the_timeout_kills_a_hanging_task_and_the_cap_truncates_a_loud_one() {
        let project = TmpDir::new();
        let shell = match crate::pathfind::find_on_path("bwrap")
            .and(crate::store::resolve_nix(None))
            .and_then(|nix| {
                let data = TmpDir::new();
                let layout = crate::store::Layout::under(data.path());
                let nixpkgs = crate::store::LockTarget::global(&layout, None)
                    .resolve(&nix, &layout)
                    .ok()?;
                super::super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &nixpkgs)
                    .ok()
                    .map(|u| u.shell_bin)
            }) {
            Some(shell) => shell,
            None => {
                eprintln!("skipping task ceiling smoke: need bwrap, userns, and nix");
                return;
            }
        };

        let mut hang = echo_task(&shell.to_string_lossy());
        hang.name = "hang".into();
        hang.cmd = vec![
            shell.to_string_lossy().into_owned(),
            "-c".into(),
            "sleep 30".into(),
        ];
        hang.params.clear();
        hang.secrets.clear();
        hang.timeout = Duration::from_millis(600);

        let mut loud = echo_task(&shell.to_string_lossy());
        loud.name = "loud".into();
        loud.cmd = vec![
            shell.to_string_lossy().into_owned(),
            "-c".into(),
            "yes abcdefghij | head -c 20000".into(),
        ];
        loud.params.clear();
        loud.secrets.clear();
        loud.max_output = 256;

        let Some((engine, _data)) = engine_for(vec![hang, loud], project.path()) else {
            eprintln!("skipping task ceiling smoke: prerequisites absent");
            return;
        };

        let killed = engine
            .run("hang", &BTreeMap::new(), &BTreeMap::new())
            .expect("the hanging task returns");
        assert!(killed.timed_out, "the timeout must fire");
        assert_ne!(killed.exit, 0, "a killed command does not report success");

        let cut = engine
            .run("loud", &BTreeMap::new(), &BTreeMap::new())
            .expect("the loud task returns");
        assert!(cut.truncated, "the output cap must report the truncation");
        assert!(
            cut.stdout.as_deref().map(str::len).unwrap_or(0) <= 256,
            "no more than the declared ceiling is kept"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Encoding, ParamBound, TaskParam, TaskSecret};

    fn task() -> TaskSpec {
        TaskSpec {
            name: "db-query".into(),
            description: None,
            cmd: vec!["psql".into(), "-c".into(), "{sql}".into()],
            params: vec![TaskParam {
                name: "sql".into(),
                bound: ParamBound::Pattern("^SELECT [a-z]+$".into()),
                default: None,
            }],
            secrets: vec![],
            injections: vec![],
            env: BTreeMap::new(),
            env_allow: vec!["PGCONNECT_TIMEOUT".into()],
            stdout: OutputDisposition::Show,
            stderr: OutputDisposition::Show,
            timeout: Duration::from_secs(5),
            max_output: 1024,
            network: vec![],
            nonce: false,
            packages: vec![],
        }
    }

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // A value fills the element that holds the placeholder and never becomes a second argument —
    // the property that keeps a caller from restructuring the command.
    #[test]
    fn substitution_stays_inside_one_argv_element() {
        let argv = substitute(&task().cmd, &values(&[("sql", "SELECT one two")])).unwrap();
        assert_eq!(
            argv,
            vec![
                OsString::from("psql"),
                OsString::from("-c"),
                OsString::from("SELECT one two")
            ],
            "a value with spaces stays one element"
        );
    }

    #[test]
    fn substitution_handles_several_placeholders_and_literal_braces() {
        let cmd = vec!["prog".to_string(), "{a}-{b}".to_string(), "{}".to_string()];
        let argv = substitute(&cmd, &values(&[("a", "1"), ("b", "2")])).unwrap();
        assert_eq!(argv[1], OsString::from("1-2"));
        assert_eq!(
            argv[2],
            OsString::from("{}"),
            "an empty brace pair is literal"
        );
    }

    // A caller's value is re-checked against the bound at invocation, not just at declaration.
    #[test]
    fn a_value_outside_its_bound_is_refused() {
        let e = resolve_params(&task(), &values(&[("sql", "DROP TABLE t")])).unwrap_err();
        assert!(e.contains("sql"), "{e}");
    }

    #[test]
    fn a_missing_required_parameter_is_refused_rather_than_emptied() {
        let e = resolve_params(&task(), &BTreeMap::new()).unwrap_err();
        assert!(e.contains("required"), "{e}");
    }

    #[test]
    fn an_undeclared_parameter_is_refused() {
        let e =
            resolve_params(&task(), &values(&[("sql", "SELECT one"), ("limit", "1")])).unwrap_err();
        assert!(e.contains("limit"), "{e}");
    }

    #[test]
    fn a_default_fills_in_for_an_absent_value() {
        let mut t = task();
        t.params[0].default = Some("SELECT one".into());
        let resolved = resolve_params(&t, &BTreeMap::new()).unwrap();
        assert_eq!(resolved.get("sql").map(String::as_str), Some("SELECT one"));
    }

    // The environment allowlist refuses rather than drops: a caller that believes it set a variable
    // must not be silently overruled.
    #[test]
    fn an_unlisted_environment_name_is_refused() {
        let e = caller_env(&task(), &values(&[("LD_PRELOAD", "/evil.so")])).unwrap_err();
        assert!(e.contains("LD_PRELOAD"), "{e}");
        let ok = caller_env(&task(), &values(&[("PGCONNECT_TIMEOUT", "5")])).unwrap();
        assert_eq!(ok, vec![("PGCONNECT_TIMEOUT".to_string(), "5".to_string())]);
    }

    // The mount derivation is the security core of the sibling cage: the skeleton is kept, `/nix`
    // is repointed at the immutable shared store, writable binds are demoted, and every channel the
    // agent cage carries is dropped.
    #[test]
    fn the_task_cage_keeps_the_skeleton_and_drops_every_channel() {
        let agent = vec![
            // the per-project store, read-WRITE in the agent's cage
            Mount::Bind {
                src: PathBuf::from("/data/projects/abc/store/nix"),
                dest: PathBuf::from("/nix"),
            },
            Mount::Symlink {
                target: PathBuf::from("/nix/store/abc-bash/bin/sh"),
                dest: PathBuf::from(super::super::binds::SANDBOX_SHELL),
            },
            Mount::RoBind {
                src: PathBuf::from("/data/projects/abc/etc/passwd"),
                dest: PathBuf::from("/etc/passwd"),
            },
            // a config bind, a GUI hole and a relay socket: all channels, none structural
            Mount::Bind {
                src: PathBuf::from("/home/u/secrets"),
                dest: PathBuf::from("/mnt/secrets"),
            },
            Mount::RoBind {
                src: PathBuf::from("/run/user/1000/wayland-0"),
                dest: PathBuf::from("/run/user/1000/wayland-0"),
            },
            Mount::Bind {
                src: PathBuf::from("/data/egress/cage-1"),
                dest: PathBuf::from("/run/sbx"),
            },
            Mount::DevBind {
                src: PathBuf::from("/dev/dri"),
                dest: PathBuf::from("/dev/dri"),
            },
            // The task plane's own two mounts. Both MUST be dropped: a task cage that carried the
            // socket could invoke tasks recursively, and one that carried sbx's binary would hand a
            // credential-bearing command the client to reach it with.
            Mount::Bind {
                src: PathBuf::from("/data/tasks/42/control.sock"),
                dest: PathBuf::from(super::super::task_control::CAGE_TASK_UDS),
            },
            Mount::RoBind {
                src: PathBuf::from("/usr/local/bin/sbx"),
                dest: PathBuf::from(super::super::task_control::TASK_SHIM_INCAGE),
            },
        ];
        let out = task_mounts(&agent, Path::new("/data/shared/store/nix"));
        assert!(
            !out.iter().any(|m| {
                let d = mount_dest(m);
                d == Path::new(super::super::task_control::CAGE_TASK_UDS)
                    || d == Path::new(super::super::task_control::TASK_SHIM_INCAGE)
            }),
            "the task socket and the task client must never reach a task cage: {out:?}"
        );

        assert_eq!(
            out,
            vec![
                Mount::RoBind {
                    src: PathBuf::from("/data/shared/store/nix"),
                    dest: PathBuf::from("/nix"),
                },
                Mount::Symlink {
                    target: PathBuf::from("/nix/store/abc-bash/bin/sh"),
                    dest: PathBuf::from(super::super::binds::SANDBOX_SHELL),
                },
                Mount::RoBind {
                    src: PathBuf::from("/data/projects/abc/etc/passwd"),
                    dest: PathBuf::from("/etc/passwd"),
                },
            ],
            "only the skeleton survives, and /nix comes from the shared store read-only"
        );
    }

    /// The allowlist is matched on *exact* destinations, so an entry that names no real mount keeps
    /// nothing while reading as though it did — `/bin` does not keep `/bin/sh`, `/etc/ssl` does not
    /// keep the CA bundle. Pin every entry against the set the cage assembler actually emits.
    #[test]
    fn every_kept_destination_is_one_the_cage_emits() {
        for dest in KEPT_DESTS {
            assert!(
                super::super::binds::STRUCTURAL_DESTS.contains(dest),
                "`{dest}` is not a destination the cage emits — it keeps nothing"
            );
        }
    }

    /// The hermetic userland a *foreign* binary needs: the nix-ld shim's mount and the two variables
    /// it reads. A mise-installed tool is typically foreign, so losing either half leaves a task
    /// cage that holds the program and cannot exec it.
    #[test]
    fn a_foreign_binarys_loader_survives_with_its_environment() {
        let agent = vec![
            Mount::RoBind {
                src: PathBuf::from("/nix/store/abc-nix-ld/lib/ld.so"),
                dest: PathBuf::from(super::super::binds::LOADER_DEST),
            },
            Mount::Symlink {
                target: PathBuf::from("/nix/store/abc-bash/bin/sh"),
                dest: PathBuf::from(super::super::binds::SANDBOX_SHELL),
            },
            Mount::Symlink {
                target: PathBuf::from("/nix/store/abc-coreutils/bin/env"),
                dest: PathBuf::from(super::super::binds::SANDBOX_ENV),
            },
        ];
        let kept: Vec<PathBuf> = task_mounts(&agent, Path::new("/shared/nix"))
            .iter()
            .map(|m| mount_dest(m).to_path_buf())
            .collect();
        assert_eq!(
            kept,
            vec![
                PathBuf::from(super::super::binds::LOADER_DEST),
                PathBuf::from(super::super::binds::SANDBOX_SHELL),
                PathBuf::from(super::super::binds::SANDBOX_ENV),
            ]
        );

        let env = task_env(&[
            (
                "NIX_LD".to_string(),
                "/nix/store/glibc/lib/ld.so".to_string(),
            ),
            (
                "NIX_LD_LIBRARY_PATH".to_string(),
                "/nix/store/glibc/lib".to_string(),
            ),
        ]);
        assert_eq!(env.len(), 2, "the nix-ld shim's environment must survive");
    }

    // A writable structural bind is demoted rather than dropped, so the userland stays complete
    // while nothing in a task cage is writable except its own tmpfs.
    #[test]
    fn a_writable_structural_bind_is_demoted_to_read_only() {
        let agent = vec![Mount::Bind {
            src: PathBuf::from("/host/etc/hosts"),
            dest: PathBuf::from("/etc/hosts"),
        }];
        let out = task_mounts(&agent, Path::new("/shared/nix"));
        assert_eq!(
            out,
            vec![Mount::RoBind {
                src: PathBuf::from("/host/etc/hosts"),
                dest: PathBuf::from("/etc/hosts"),
            }]
        );
    }

    // The environment is filtered the same way, and for the same reason.
    #[test]
    fn the_task_environment_keeps_only_the_userland_plumbing() {
        let agent = vec![
            ("PATH".to_string(), "/bin".to_string()),
            ("LOCALE_ARCHIVE".to_string(), "/nix/locales".to_string()),
            (
                "https_proxy".to_string(),
                "http://127.0.0.1:3128".to_string(),
            ),
            ("ANTHROPIC_API_KEY".to_string(), "sk-secret".to_string()),
            ("WAYLAND_DISPLAY".to_string(), "wayland-0".to_string()),
        ];
        let kept = task_env(&agent);
        assert_eq!(
            kept,
            vec![
                ("PATH".to_string(), "/bin".to_string()),
                ("LOCALE_ARCHIVE".to_string(), "/nix/locales".to_string()),
            ],
            "an agent's own credential, proxy pointer and display never reach a task"
        );
    }

    // The output cap keeps only the declared number of bytes but still drains the pipe, and says it
    // cut — a truncated result that looked complete would be worse than no result.
    #[test]
    fn the_capture_cap_truncates_and_reports() {
        let mut src = std::io::Cursor::new(b"0123456789".to_vec());
        let (kept, cut) = read_capped(&mut src, 4).unwrap();
        assert_eq!(kept, b"0123");
        assert!(cut);

        let mut fits = std::io::Cursor::new(b"ab".to_vec());
        let (kept, cut) = read_capped(&mut fits, 4).unwrap();
        assert_eq!(kept, b"ab");
        assert!(!cut);
    }

    /// A task that declares `network` must carry the egress forwarder into its cage. Its proxy
    /// serves a Unix socket while its proxy variables name a TCP port, so without the bridge the
    /// declaration reads as "this task may reach these hosts" and the cage reaches nothing.
    #[test]
    fn a_networked_task_carries_the_egress_forwarder_and_a_local_one_does_not() {
        let base = crate::testutil::TmpDir::new();
        let engine = engine_with_pool(&base.join("task-mise"), Vec::new());
        let bare = vec![
            OsString::from("curl"),
            OsString::from("https://example.com"),
        ];

        let mut local = task();
        local.network = Vec::new();
        assert_eq!(
            engine.cage_argv(bare.clone(), &local),
            bare,
            "a task with no egress must run exactly as declared — no shell it did not ask for"
        );

        let mut networked = task();
        networked.network = vec![crate::allowlist::classify("example.com").expect("a valid rule")];
        let wrapped = engine.cage_argv(bare.clone(), &networked);
        let script = wrapped
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            script.contains("TCP-LISTEN:") && script.contains("/tmp/sbx-egress.sock"),
            "the forwarder must bridge the cage port to the bound proxy socket: {script}"
        );
        assert!(
            wrapped.ends_with(&bare),
            "the declared command must still be what runs, positionally: {wrapped:?}"
        );
    }

    /// An engine wired to `pool`, with the given tasks. Built field-wise so a mount/PATH assertion
    /// needs neither nix nor a kernel.
    fn engine_with_pool(pool: &Path, tasks: Vec<TaskSpec>) -> TaskEngine {
        TaskEngine {
            bwrap: PathBuf::from("/usr/bin/bwrap"),
            forwarder: CageForwarder {
                socat: PathBuf::from("/nix/store/base/bin/socat"),
                shell: PathBuf::from("/nix/store/base/bin/bash"),
            },
            base_mounts: vec![Mount::RoBind {
                src: PathBuf::from("/shared/nix"),
                dest: PathBuf::from("/nix"),
            }],
            base_env: vec![("PATH".to_string(), "/nix/store/base/bin".to_string())],
            project: PathBuf::from("/project"),
            config_root: PathBuf::from("/project"),
            tasks,
            limits: super::super::cgroup::Limits::default(),
            slug: "test".to_string(),
            layout: crate::store::Layout::under(Path::new("/data")),
            ca_bundle: None,
            pool: Some((
                pool.to_path_buf(),
                PathBuf::from("/nix/store/mise/bin/mise"),
            )),
        }
    }

    /// A task that declares a tool gets the pool — read-only, at the path the install used — and
    /// that tool's directory at the *front* of its `PATH`. Read-only is the point: the pool is what
    /// makes a `mise:` tool's provenance trustworthy, and a writable one would give that back.
    #[test]
    fn a_task_declaring_a_tool_gets_the_pool_read_only_and_on_its_path() {
        let base = crate::testutil::TmpDir::new();
        let pool = base.join("task-mise");
        std::fs::create_dir_all(pool.join("installs/demo-tool/1.0/bin")).unwrap();
        std::fs::create_dir_all(pool.join("config")).unwrap();
        std::fs::write(
            pool.join("config/config.toml"),
            "[tools]\ndemo-tool = \"latest\"\n",
        )
        .unwrap();

        let mut task = task();
        task.packages = vec!["demo-tool".to_string()];
        let engine = engine_with_pool(&pool, vec![task.clone()]);

        let spec = engine
            .build_spec(
                vec![OsString::from("demo-tool")],
                &engine.base_env,
                &[],
                &task,
                0,
            )
            .unwrap();
        assert!(
            spec.mounts().contains(&Mount::RoBind {
                src: pool.clone(),
                dest: PathBuf::from(super::super::taskpool::POOL_INCAGE),
            }),
            "the pool must be bound READ-ONLY at the install path: {:?}",
            spec.mounts()
        );

        let mut env = engine.base_env.clone();
        prepend_path(&mut env, &engine.pool_bins(&task).unwrap());
        assert_eq!(
            env.iter()
                .find(|(k, _)| k == "PATH")
                .map(|(_, v)| v.as_str()),
            Some("/opt/sbx/task-mise/shims:/nix/store/base/bin"),
            "a declared tool wins over the base userland on a name collision"
        );
    }

    /// A task that declares nothing sees no pool at all — the mount is conditional on the
    /// declaration, so an unrelated task is not handed the other tasks' tools.
    #[test]
    fn a_task_declaring_no_tool_gets_no_pool_mount() {
        let base = crate::testutil::TmpDir::new();
        let pool = base.join("task-mise");
        std::fs::create_dir_all(pool.join("installs/demo-tool/1.0/bin")).unwrap();
        std::fs::create_dir_all(pool.join("config")).unwrap();
        std::fs::write(
            pool.join("config/config.toml"),
            "[tools]\ndemo-tool = \"latest\"\n",
        )
        .unwrap();

        let task = task();
        let engine = engine_with_pool(&pool, vec![task.clone()]);
        let spec = engine
            .build_spec(
                vec![OsString::from("psql")],
                &engine.base_env,
                &[],
                &task,
                0,
            )
            .unwrap();
        assert!(
            !spec
                .mounts()
                .iter()
                .any(|m| mount_dest(m) == Path::new(super::super::taskpool::POOL_INCAGE)),
            "a task with no declared tool must not see the pool"
        );
        assert!(engine.pool_bins(&task).is_none());
    }

    /// The union across tasks is what the pool must hold, deduplicated — one install for a tool two
    /// tasks share.
    #[test]
    fn the_pool_holds_the_union_of_every_tasks_tools() {
        let base = crate::testutil::TmpDir::new();
        let mut a = task();
        a.name = "a".into();
        a.packages = vec!["node@22".into(), "aqua:cli/gh".into()];
        let mut b = task();
        b.name = "b".into();
        b.packages = vec!["node@22".into(), "jq".into()];
        let engine = engine_with_pool(&base.join("task-mise"), vec![a, b]);
        assert_eq!(
            engine.declared_packages(),
            vec![
                "node@22".to_string(),
                "aqua:cli/gh".to_string(),
                "jq".to_string()
            ]
        );
    }

    /// A tool the pool does not hold is reported rather than turned into a dangling path entry: the
    /// command then fails with a plain "not found", which is what actually happened.
    #[test]
    fn a_tool_absent_from_the_pool_is_reported_not_papered_over() {
        let base = crate::testutil::TmpDir::new();
        let mut task = task();
        task.packages = vec!["absent-tool".to_string()];
        let engine = engine_with_pool(&base.join("task-mise"), vec![task.clone()]);
        assert_eq!(
            engine.missing_packages(&task),
            vec!["absent-tool".to_string()]
        );
        assert!(engine.pool_bins(&task).is_none());
    }

    // A credential's every spelling is a needle under the variable's own name, so a value that
    // reaches the output — plaintext or encoded — comes back as `${VAR}`.
    #[test]
    fn a_credentials_variants_are_all_named_after_the_variable() {
        let secret = TaskSecret {
            var: "PGPASSWORD".into(),
            sources: vec![],
            encode: Encoding::Base64,
            description: None,
        };
        let needles: Vec<SecretNeedle> = secret
            .encode
            .variants("hunter2-hunter2")
            .into_iter()
            .map(|b| SecretNeedle::named(&secret.var, b))
            .collect();
        let (out, hits) = redact_named(
            b"plain=hunter2-hunter2 b64=aHVudGVyMi1odW50ZXIy",
            &needles,
            &Placeholder::Plain,
        );
        assert_eq!(out, b"plain=${PGPASSWORD} b64=${PGPASSWORD}");
        assert_eq!(hits, 2);
    }
}
