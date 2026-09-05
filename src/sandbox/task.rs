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

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{OutputDisposition, TaskSpec};

use super::proxy::SecretNeedle;
use super::redact::{Placeholder, redact_named};
use super::spec::{Mount, NetPolicy, SandboxSpec};
use crate::sandbox::locks::locked;

/// Where a task's `$HOME` and scratch space live inside its cage: a fresh tmpfs, so nothing it
/// writes survives the invocation and nothing the agent wrote is visible to it.
const TASK_HOME: &str = "/tmp/task-home";

/// Where a task declaring `output` finds its writable directory, and the variable that names it. The
/// one path in the cage whose contents outlive the invocation.
///
/// A real directory, never a tmpfs: an artifact is the case where size is the point (a database
/// dump, an archive), and a tmpfs is RAM — it would put the whole file in memory and have the cage's
/// own cgroup kill it.
const TASK_OUT_INCAGE: &str = "/opt/sbx/out";
const TASK_OUT_ENV: &str = "SBX_TASK_OUT";

/// Where the same directories are readable from the **agent's** cage, and the directory under a
/// project's runtime tree they are bound from.
///
/// The agent's mount is decided when its cage is built, long before any invocation, and nothing can
/// be mounted into a live cage afterwards. So what is bound there is the **parent**: each task's
/// directory appears inside it as it is created, because a bind mount shows the tree it is bound to
/// rather than a copy of it.
pub(crate) const TASK_OUT_AGENT: &str = "/opt/sbx/task-out";
pub(crate) const TASK_OUT_TREE: &str = "task-out";

/// The **one** number that names an invocation, everywhere it is named: its host-side artifacts (its
/// proxy sockets, its exec supervisor, its systemd scope), its line in the session's log, the row
/// `sbx task status` shows while it runs, and the id `sbx task stop` takes. A session can serve two
/// invocations at once, and every name derived from the launcher pid alone would be the same name
/// twice. Monotonic per process, which is all it has to be: the pid already separates sessions.
///
/// It starts at **1** so that no invocation is ever id `0` — the log reserves that for an entry no
/// invocation stands behind (a request refused before it was admitted at all).
///
/// It reaches a socket path, which the kernel caps at `SUN_LEN` (108), so its width is worth
/// knowing rather than assuming: a session's call quota bounds how many are ever drawn, making the
/// suffix five bytes (`.t500`) at its widest. Measured against a deliberately long install path
/// (`/home/<32 chars>/.local/share/sbx`) with a seven-digit pid, the full control-socket path is 84
/// bytes — the suffix spends five of roughly thirty spare, so the width is not what would break
/// first even if a process somehow drew past the quota.
///
/// It opens with a **dot**, not a dash, and that is load-bearing rather than cosmetic: the runtime
/// sweep reads a launcher pid as the digits up to the first `.`, so `control-<pid>.t3.sock` is
/// collected with the session that made it while `control-<pid>-t3.sock` would be a name the sweep
/// cannot parse and therefore never removes. A per-invocation CA is ~460 KB; leaving those
/// unsweepable is how a data directory grows without bound.
static TASK_INVOCATION: AtomicU64 = AtomicU64::new(1);

/// Draw the next invocation id. Taken by the caller that admits the invocation, not by [`TaskEngine::run`]
/// itself, so that a request refused *after* admission still carries the id its refusal is recorded
/// under — there is one number per admitted invocation whether or not a command ever ran.
pub(crate) fn next_invocation() -> u64 {
    TASK_INVOCATION.fetch_add(1, Ordering::Relaxed)
}

/// How many detached invocations may be live at once.
///
/// A separate bound from the session's call quota, which counts admissions over the session's whole
/// life and so bounds nothing about how many run *together*. Detaching removes the caller's own wait
/// as a limit, and each live invocation holds a cage, a per-invocation proxy, an exec supervisor and
/// a systemd scope: without a cap, `--detach` in a loop is a way to stand up as many of those as the
/// quota allows, all at once.
pub(super) const MAX_DETACHED: usize = 4;

/// How many invocations may be live at once, detached or not.
///
/// The reason this exists is that "an attached invocation is bounded by its caller waiting for it"
/// counts callers, and the caller here is the *cage*: it reaches the plane over a socket it can open
/// as many times as the plane will serve, and each connection blocks on an invocation of its own.
/// So the wait bounds one invocation per connection and nothing at all per session, and what was
/// left holding the line was the connection ceiling — a number sized for what a *connection* costs,
/// standing in for a bound on what a *cage* costs.
///
/// Twice [`MAX_DETACHED`]: an invocation costs the same whether or not anyone is waiting for it, so
/// the number is of that order, and leaving room above the detached cap is what keeps a full
/// detached slate from also refusing the attached call that would inspect it. The trigger for
/// revisiting it is a workload legitimately refused, which `sbx task status` shows as the
/// invocations that were live at the time.
pub(super) const MAX_LIVE: usize = 2 * MAX_DETACHED;

/// How often the runner checks whether the command has exited, whether its timeout has passed, and
/// whether it has been asked to stop. Short enough that a fast task is not visibly delayed, long
/// enough not to spin.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// The exit code a stopped invocation reports. `128 + SIGKILL` is what a command killed mid-run
/// produces anyway; a stop that lands *before* the command starts reports the same, so one event has
/// one answer whichever side of the spawn it arrives on.
const STOPPED_EXIT: i32 = 128 + libc::SIGKILL;

/// How long [`TaskEngine::stop`] waits for a stop it requested to actually take effect.
///
/// Bounded because it cannot be unbounded honestly: a stop is a request the runner honors at its
/// next poll, and everything before the spawn — a credential resolving through `sops`, a proxy being
/// stood up — completes first. Long enough to cover the poll interval and a kill many times over, so
/// "still finishing" means something is genuinely holding it rather than that the wait was stingy.
const STOP_GRACE: Duration = Duration::from_secs(3);

/// The in-cage destinations a task cage keeps from the agent cage's mount set, on top of the
/// substrate that cage runs on ([`super::binds::substrate`], kept by rule rather than by entry:
/// a userland is not a destination an allowlist can name).
///
/// An **allowlist**, deliberately: a task needs the userland and the synthesized identity files,
/// and nothing else. Anything the agent's cage exposes that is not named here — a `[binds]`
/// path, a Wayland or PulseAudio socket, the D-Bus portal directory, a granted device, the egress
/// proxy socket — is dropped. A hole added to the agent cage later therefore does **not** silently
/// appear in task cages; it has to be named here on purpose.
///
/// Every entry must be a destination the agent cage actually emits, or it silently keeps nothing:
/// the entries are matched **exactly**, so `/bin` would not keep `/bin/sh` and `/etc/ssl` would not
/// keep the CA bundle. The names are taken from [`super::binds`]'s own constants rather than
/// retyped, and `every_kept_destination_is_one_the_cage_emits` fails on any entry the structural
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
    // The zone database and the link into it, so a task resolves the local zone exactly as the
    // session does. Both, never one: the link is what carries the zone *name*, and it is a dangling
    // pointer without the database it points into.
    super::binds::CAGE_ZONEINFO,
    super::binds::CAGE_LOCALTIME,
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
    "TZ",
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
    /// The structural mounts a task cage starts from — the substrate the launch declared (see
    /// [`super::binds::substrate`]) followed by the agent cage's set, filtered through
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
    /// Which tasks are mid-invocation and hold their output directory. A task's directory is one
    /// per *task*, not per invocation, so its path is predictable enough for a caller to know it
    /// before running anything — and two concurrent invocations of the same task would then write
    /// into one directory. The second is refused rather than allowed to interleave.
    output_held: Arc<Mutex<BTreeSet<String>>>,
    /// The invocations running right now, by id — what `sbx task status` reports and what
    /// `sbx task stop` acts on. Held by the engine rather than by the plane because only the engine
    /// knows when a command actually starts and ends; a registry kept beside it would be a second
    /// account of the same fact, and the two would drift.
    running: Arc<Mutex<BTreeMap<u64, Running>>>,
    /// The in-cage programs that give a networked task a route out. Not optional: any task may
    /// declare `network`, and one that does with no forwarder would find the proxy socket bound, the
    /// proxy variables set, and nothing listening on the port they name.
    forwarder: CageForwarder,
    /// Where a refusal inside a task invocation is announced, shared with the launch that built this
    /// engine so a task's refusals reach the same place the session's do. `None` on an inventory-only
    /// or test engine, which announces nothing; the launch attaches the real wiring with
    /// [`TaskEngine::with_notifier`].
    notify: Option<Arc<super::notify_sink::NotifyWiring>>,
    /// The session's `[fs]` masks and the decoys they mount, when the config declared any. Every
    /// task cage re-emits them over its own project bind, minus what that task's `unmask` lifts.
    fs_masks: Option<(super::fsmask::Expanded, super::fsmask::Decoys)>,
    /// The session's `[redact] min_len`: the shortest credential an invocation builds a needle for.
    /// Held by the engine rather than read per invocation so a task's output and the session's own
    /// egress are watched to the same depth — they are the two renderings of one floor.
    redact_min_len: usize,
    /// The session's standing brokers, for a task credential that resolves through a plugin whose
    /// manifest names one. Held so a `pass://` credential means the same thing in a task as it does
    /// in a wire injection: one resolver layer, one set of grants, no source that works in one place
    /// and fails in the other.
    brokers: Vec<super::broker::Reachable>,
    /// The session's egress event ring, shared with every per-invocation proxy this engine stands
    /// up, for the same reason the signer record below is: a proxy's own ring would be one nothing
    /// opens. Its control socket carries the instance in its name, and every reader globs those
    /// names for a bare pid. `None` on an inventory-only or test engine.
    egress_log: Option<Arc<super::control::LogRing>>,
    /// The session's signer record, shared with every per-invocation proxy this engine stands up.
    /// A task may declare `sign` in its own `[task.<name>.inject]`, and its proxy is gone when the
    /// invocation ends: without the session's ring, what its signer formed would be recorded into
    /// something nothing serves and nothing reads. `None` on an inventory-only or test engine.
    signer_log: Option<Arc<super::signer_control::SignerRing>>,
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
    /// How many secret values were substituted out of the streams the caller **receives**.
    ///
    /// A withheld stream contributes to [`redacted_withheld`](Self::redacted_withheld) instead. The
    /// split matters because this number goes back to the caller: a count over output that was never
    /// handed over is not the caller's to have, and it is a number the *command* chooses — printing
    /// the credential a chosen number of times makes the count a value it picked, which is a channel
    /// out of a cage whose streams were hidden precisely to close one.
    pub(crate) redacted: usize,
    /// The same count over the streams the declaration **withholds**. Recorded host-side, where the
    /// session's log answers "did the credential reach the output" whether or not the caller saw it;
    /// never written back to the caller.
    pub(crate) redacted_withheld: usize,
    /// Whether the timeout killed the command.
    pub(crate) timed_out: bool,
    /// Whether `sbx task stop` ended it. Distinct from `timed_out` although both end the command the
    /// same way: one is the declaration's own ceiling firing, the other is a person deciding, and a
    /// caller that cannot tell them apart cannot know whether to raise the ceiling or ask why.
    pub(crate) stopped: bool,
    /// How long the invocation took, in milliseconds.
    pub(crate) elapsed_ms: u64,
    /// This invocation's substitution nonce, when the section enabled it. Reported **out of band**
    /// (here, not in the text) on purpose: that is what makes a `${NAME@nonce}` in the output
    /// unforgeable for this invocation — the command could not have predicted it.
    pub(crate) nonce: Option<String>,
    /// Where the invocation's artifacts are, **as the agent's cage sees the path**, and how many
    /// bytes were left there. `None` when the task declares no `output`.
    ///
    /// The path is predictable — one directory per task — so a caller could know it without being
    /// told; reporting it anyway is what makes "the operation produced something" visible at the
    /// point of use rather than something to go and check.
    pub(crate) output: Option<(String, u64)>,
    /// The `execve`s `spawn` refused during this invocation, if any — each as the program that
    /// reached and the program it reached for.
    ///
    /// Reported for the same reason as `truncated`: the refusal is invisible in the result. The
    /// `execve` returns an error to a process that decides for itself whether to mention it, and
    /// several say nothing at all — leaving a caller an empty output and a success code with no
    /// account of either. A refusal a caller cannot see is one they would debug as a broken command.
    pub(crate) refused: Vec<super::proc_enforce::Refusal>,
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

/// The announcement one refused admission makes.
///
/// Split out because of what `name` is: the tail of a `RUN <name>` request line, chosen by the
/// cage and bounded by the crossing socket only at that plane's `MAX_PAYLOAD_BYTES` — a mebibyte.
/// A `Block`'s subject is not merely rendered and dropped: the notifier's coalescer keys its
/// repeat memory on it, one entry per distinct problem and up to `notify::SEEN_MAX` of them,
/// held for the session. So a cage asking over and over for tasks that do not exist could pin
/// roughly a gibibyte of supervisor memory in keys nothing evicts — the same shape the invocation
/// log ring was fixed for, one sink further along. The sink's own guard cannot close it: that one
/// shapes what is *shown*, and by then the key is already stored.
///
/// [`super::sanitize`] is the crate's single answer to a value the cage chose — control characters
/// (a newline that would forge a second line) to spaces, and the length capped. `detail` takes it
/// too, since `TaskError::Unknown`'s `Display` embeds the very same name.
fn refusal_block(name: &str, reason: &str, detail: &str) -> crate::notify::Block {
    crate::notify::Block {
        event: crate::notify::NotifyEvent::Task,
        subject: super::sanitize(name),
        reason: reason.to_string(),
        detail: super::sanitize(detail),
        // Nothing to suggest: a task is a declaration, and the answer to a refused one is to change
        // what is declared beside it — never a one-line command.
        fix: String::new(),
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
        redact_min_len: usize,
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
            output_held: Arc::new(Mutex::new(BTreeSet::new())),
            running: Arc::new(Mutex::new(BTreeMap::new())),
            notify: None,
            fs_masks: None,
            redact_min_len,
            brokers: Vec::new(),
            egress_log: None,
            signer_log: None,
        }
    }

    /// Attach the launch's refusal notifier, so a program an invocation's `spawn` policy stops is
    /// announced exactly like one the session's own exec policy stops.
    pub(crate) fn with_notifier(mut self, notify: Arc<super::notify_sink::NotifyWiring>) -> Self {
        self.notify = Some(notify);
        self
    }

    /// Record what this engine's per-invocation proxies **decide** into the session's own egress
    /// ring, so `sbx net logs` shows a task's requests beside the agent's.
    ///
    /// A per-invocation proxy is reached over a control socket whose name carries its instance, and
    /// the readers glob those names for a bare pid — so a ring of its own is one nothing opens, and
    /// every decision it made was invisible for the life of the session. See
    /// [`crate::sandbox::egress::Egress::event_log`]. Left unset (a test engine, or a launch with no
    /// proxy of its own) each invocation keeps a private ring, exactly as before.
    pub(crate) fn with_egress_log(mut self, log: Option<Arc<super::control::LogRing>>) -> Self {
        self.egress_log = log;
        self
    }

    /// Record what this engine's per-invocation proxies sign into the session's own feed, so
    /// `sbx logs --feed signer` shows a task's signatures beside the agent's. Left unset (a test
    /// engine, or a launch that declares no signer) nothing is recorded.
    pub(crate) fn with_signer_log(
        mut self,
        log: Option<Arc<super::signer_control::SignerRing>>,
    ) -> Self {
        self.signer_log = log;
        self
    }

    /// Carry the session's `[fs]` masks into every task cage this engine builds.
    ///
    /// A masked path is closed in the agent's cage and in each task's, and a task that needs one
    /// lifts it with its own `unmask` — that split is what lets a credential-bearing operation read
    /// a key the agent invoking it never can. Separate from [`TaskEngine::from_cage`] because a
    /// session with no `[fs]` policy has nothing to carry, and because the masks are **not**
    /// inherited through the base mounts: those are filtered to a fixed destination list that holds
    /// no project path (see `KEPT_DESTS`), and a task cage binds the project itself, so the masks
    /// have to be re-emitted over it.
    pub(crate) fn with_fs_masks(
        mut self,
        masks: super::fsmask::Expanded,
        decoys: super::fsmask::Decoys,
    ) -> Self {
        self.fs_masks = Some((masks, decoys));
        self
    }

    /// Point the engine at this project's task tool pool, filled by `mise_bin`. Separate from
    /// [`TaskEngine::from_cage`] because it is conditional: a session whose tasks declare no
    /// `packages` never materializes a pool, and never pays for one.
    pub(crate) fn with_pool(mut self, pool: PathBuf, mise_bin: PathBuf) -> Self {
        self.pool = Some((pool, mise_bin));
        self
    }

    /// Hand the engine the brokers the launch stood up, so a task credential resolving through a
    /// plugin that names one finds it. Separate from [`TaskEngine::from_cage`] for the reason the
    /// pool is: a session with no `[broker.*]` stands none up and passes none.
    pub(crate) fn with_brokers(mut self, brokers: Vec<super::broker::Reachable>) -> Self {
        self.brokers = brokers;
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
    ///
    /// `invocation` is drawn by the caller that admitted this run ([`next_invocation`]), not here:
    /// it is the id the refusal would be recorded under too, and a number the engine drew privately
    /// could not be one.
    pub(crate) fn run(
        &self,
        name: &str,
        params: &BTreeMap<String, String>,
        env: &BTreeMap<String, String>,
        invocation: u64,
    ) -> Result<TaskOutcome, TaskError> {
        let admitted = self.admit(name, params, env, invocation, false)?;
        self.run_admitted(name, admitted)
    }

    /// Decide everything that can be decided before the command starts, and take what an invocation
    /// must hold for its whole life: its place in the live registry and, when the task declares one,
    /// its output directory.
    ///
    /// Split out from [`Self::run_admitted`] because of `--detach`. A detached caller is told its
    /// invocation was admitted and then stops listening, so every refusal it could act on has to have
    /// happened by then — an unknown operation, a value outside its bound, an unlisted variable, and
    /// above all the output directory, which is one per *task* and therefore refuses a second
    /// concurrent invocation of the same one. Deciding that inside the detached thread would hand
    /// back an id for an invocation that died on a refusal its caller never saw.
    pub(crate) fn admit(
        &self,
        name: &str,
        params: &BTreeMap<String, String>,
        env: &BTreeMap<String, String>,
        invocation: u64,
        detached: bool,
    ) -> Result<Admission, TaskError> {
        let outcome = self.admit_inner(name, params, env, invocation, detached);
        // Announce a refused invocation from the one place every admission decision surfaces, rather
        // than at each `map_err` inside — there are seven, and a eighth added later would otherwise
        // be silent. Only a *refusal* is announced: an `Io` failure is sbx breaking, not sbx
        // refusing, and the caller already sees it.
        if let Some(notify) = &self.notify {
            let reason = match &outcome {
                Err(TaskError::Refused(_)) => Some("refused"),
                Err(TaskError::Unknown(_)) => Some("undeclared"),
                _ => None,
            };
            if let Some(reason) = reason {
                let detail = match &outcome {
                    Err(e) => e.to_string(),
                    Ok(_) => String::new(),
                };
                notify.notifier.block(refusal_block(name, reason, &detail));
            }
        }
        outcome
    }

    /// The admission decision itself. Split from [`Self::admit`] so the refusal announcement has one
    /// place to sit, whatever path inside produced it.
    fn admit_inner(
        &self,
        name: &str,
        params: &BTreeMap<String, String>,
        env: &BTreeMap<String, String>,
        invocation: u64,
        detached: bool,
    ) -> Result<Admission, TaskError> {
        let task = self
            .task(name)
            .ok_or_else(|| TaskError::Unknown(name.into()))?;
        // Live from here on: everything below can take real time — a credential resolves through a
        // subprocess, a proxy is stood up — and an invocation that cannot be seen during that is one
        // that cannot be stopped during it either.
        let live = self
            .enter(invocation, name, detached)
            .map_err(TaskError::Refused)?;
        let mut values = resolve_params(task, params).map_err(TaskError::Refused)?;
        let caller_env = caller_env(task, env).map_err(TaskError::Refused)?;

        // The writable directory, when the task asks for one. Claimed before the command is
        // assembled, because `{out}` substitutes to it — and the claim is what a concurrent
        // invocation of the same task is refused against.
        let output = match task.output {
            false => None,
            true => Some(self.claim_output(task).map_err(TaskError::Refused)?),
        };
        if output.is_some() {
            values.insert(
                crate::config::tasks::OUT_PLACEHOLDER.to_string(),
                TASK_OUT_INCAGE.to_string(),
            );
        }
        Ok(Admission {
            id: invocation,
            live: Some(live),
            values,
            caller_env,
            output,
        })
    }

    /// Run an invocation the engine has already admitted.
    pub(crate) fn run_admitted(
        &self,
        name: &str,
        admitted: Admission,
    ) -> Result<TaskOutcome, TaskError> {
        let Admission {
            id: invocation,
            live: _live,
            values,
            caller_env,
            output,
        } = admitted;
        let task = self
            .task(name)
            .ok_or_else(|| TaskError::Unknown(name.into()))?;
        let argv = substitute(&task.cmd, &values).map_err(TaskError::Refused)?;
        // Recorded here, where it is the task's own command: below it is wrapped for exec
        // confinement and for the egress forwarder, and neither is what a reader is asking about.
        self.note_argv(invocation, &argv);

        // Resolve the credentials for THIS invocation only, host-side. Nothing is cached: a
        // credential lives in this process for the duration of one command and its needles.
        let mut cage_env = self.base_env.clone();
        let mut needles = Vec::new();
        // Kept apart from the rest of the environment all the way to the cage: these values must not
        // reach bubblewrap's argument list, which is world-readable, so they travel on a descriptor
        // instead. Everything else about them is unchanged — same resolution, same encoding, same
        // needles for substituting them back out of the output.
        let mut secret_env = Vec::new();
        for secret in &task.secrets {
            let plaintext = resolve_secret(secret, &self.config_root, &self.bwrap, &self.brokers)
                .map_err(TaskError::Credential)?;
            needles.extend(credential_needles(secret, &plaintext, self.redact_min_len));
            secret_env.push((secret.var.clone(), secret.encode.render(&plaintext)));
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
        // The operation's own name, so a command that runs both by hand and as a declared operation
        // can tell which it is. What actually stops a tool from prompting is the closed stdin
        // `exec` gives it (`Stdio::null`): a prompt then reads EOF and the tool fails fast rather
        // than hanging until the timeout. This variable is a label, not the mechanism — nothing
        // reads it for interactivity, and the comment here used to claim it did.
        cage_env.push(("SBX_TASK".to_string(), name.to_string()));
        // The same directory by name, for a command that takes its destination from the environment
        // rather than from an argument.
        if output.is_some() {
            cage_env.push((TASK_OUT_ENV.to_string(), TASK_OUT_INCAGE.to_string()));
        }

        // Egress, when the task declares any: a proxy of its **own**, for this invocation only.
        //
        // Not the session's proxy, and not because that would be untidy: with no per-process identity
        // (same-uid), a shared proxy cannot tell a task's connection from the agent's, so registering
        // a task's credential in the session's injection table would let the agent trigger the
        // injection itself by aiming at that host. The socket is the only authority boundary
        // available, so a task gets its own — with its own rules and its own injections.
        let mut proxy_binds = Vec::new();
        let mut proxy_env = Vec::new();
        let mut tcp_plan = super::egress::TcpPlan::default();
        let mut argv = argv;

        // Exec confinement, when the task declares `spawn`: a supervisor of this invocation's own,
        // and the command wrapped in the shim **innermost** — before the egress wrap below, so the
        // filter covers the command and its descendants and not the forwarder the cage needs to
        // reach its proxy. Fail-closed: a supervisor that cannot be stood up refuses the invocation
        // rather than running the command unconfined.
        let mut proc_binds = Vec::new();
        let enforce = match &task.spawn {
            None => None,
            Some(declared) => {
                let policy = self
                    .spawn_policy(task, declared, &cage_env)
                    .map_err(|e| TaskError::Refused(format!("task `{name}`: {e}")))?;
                let shim = crate::store::ensure_proc_shim(&self.layout).map_err(TaskError::Io)?;
                let (guard, wiring) = super::proc_enforce::start_for_task(
                    self.layout.data_dir(),
                    &shim,
                    policy,
                    None,
                    invocation,
                    self.notify
                        .as_ref()
                        .map(|w| Arc::clone(&w.notifier))
                        .unwrap_or_else(|| Arc::new(super::notify_sink::Notifier::disabled())),
                )
                .map_err(TaskError::Io)?;
                argv = super::proc_enforce::wrap_command(argv, wiring.open_lens);
                proc_binds = wiring.binds;
                Some(guard)
            }
        };

        let _proxy = if task.network.is_empty() {
            None
        } else {
            let policy = crate::allowlist::EgressPolicy::new(task.network.clone(), Vec::new());
            let policy_for_cage = policy.clone();
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
                // A task's refusals reach the session's notifier, whose needle set this proxy's own
                // resolved credentials are added to.
                self.notify.as_deref(),
                self.redact_min_len,
                &self.brokers,
                self.egress_log.clone(),
                // The task's plane. It shares the session's ring for display, but its refusals are
                // this task's `network` list being enforced, not the agent's allowlist coming up
                // short, so `--net-learn` must not learn rules from them.
                super::control::Plane::Task,
                self.signer_log.clone(),
                // A task runs a command the configuration named, so a credential it declared but
                // cannot read is the launch's problem, not something to work around.
                super::egress::Unresolved::Abort,
            )
            .map_err(TaskError::Io)?;
            proxy_binds = wiring.binds;
            proxy_env = wiring.env;
            tcp_plan = super::egress::tcp_destinations(&policy_for_cage);
            for skipped in &tcp_plan.skipped {
                crate::diag::warn(&format!(
                    "task `{name}`: no in-cage listener for {skipped} — the rule still governs this \
                     task's proxy, but its command will have to tunnel itself"
                ));
            }
            // A task cage carries the same `no_proxy` as the session's, so an inspected rule naming
            // a loopback host is inert here for the same reason — and a task's command is fixed, so
            // its author cannot work around it from the outside.
            for rule in super::egress::unreachable_loopback_rules(&policy_for_cage) {
                crate::diag::warn(&format!(
                    "task `{name}`: `{rule}` allows a host this task's command reaches through no \
                     client: {exempt} are exempt from the cage's proxy (`no_proxy`), and only a \
                     `tcp://` rule gets an in-cage listener — declare `tcp://<host>:<port>` to \
                     reach the service on YOUR loopback",
                    exempt = super::egress::PROXY_EXEMPT_HOSTS.join(", ")
                ));
            }
            argv = self.cage_argv(argv, task, &tcp_plan.destinations);
            Some(guard)
        };
        cage_env.extend(proxy_env);
        proxy_binds.extend(proc_binds);

        let spec = self
            .build_spec(
                argv,
                &cage_env,
                task,
                &Invocation {
                    number: invocation,
                    proxy_binds: &proxy_binds,
                    tcp: &tcp_plan,
                    output: output.as_ref().map(|o| o.dir.as_path()),
                },
            )
            .map(|spec| spec.with_secret_env(secret_env))
            .map_err(|e| TaskError::Io(io::Error::other(e)))?;
        let started = Instant::now();
        // A failure message is substituted too: it can carry the command's own diagnostics, and
        // there is no reason for the one path that reports trouble to be the one that leaks.
        let placeholder = if task.nonce {
            Placeholder::Nonced(invocation_nonce())
        } else {
            Placeholder::Plain
        };
        // One byte less than the longest needle: enough that a credential lying across the output
        // ceiling is whole when the scan runs. See [`read_capped`].
        let scan_margin = needles
            .iter()
            .map(|n| n.as_bytes().len())
            .max()
            .unwrap_or(0)
            .saturating_sub(1);
        let raw = self
            .exec(&spec, task, invocation, scan_margin)
            .map_err(|e| {
                let (text, _) =
                    super::redact::redact_string(&e.to_string(), &needles, &placeholder);
                TaskError::Io(io::Error::other(text))
            })?;
        let elapsed_ms = started.elapsed().as_millis() as u64;

        // Substitution happens before anything is returned or logged, and on the raw bytes: the
        // output is arbitrary, and decoding first could split a value across a replacement
        // character and hide it from the scan.
        let (mut out_bytes, out_hits) = redact_named(&raw.stdout, &needles, &placeholder);
        let (mut err_bytes, err_hits) = redact_named(&raw.stderr, &needles, &placeholder);
        // The margin was the scanner's, not the caller's: cut it back off. Only on the truncated
        // path — an uncut stream held no margin bytes to begin with, and a redaction that grew the
        // text past the ceiling (a short secret, a long `${name}`) is not this ceiling's business.
        if raw.truncated {
            let cap = task.max_output as usize;
            out_bytes.truncate(cap);
            err_bytes.truncate(cap);
        }
        // Which side of the split each stream's count falls on is decided by whether that stream is
        // returned, one stream at a time: a declaration that shows stdout and hides stderr reports
        // what happened in the half the caller is holding, and no more.
        let split = |disposition: OutputDisposition, hits: usize| match disposition {
            OutputDisposition::Show => (hits, 0),
            OutputDisposition::Hide => (0, hits),
        };
        let (out_shown, out_withheld) = split(task.stdout, out_hits);
        let (err_shown, err_withheld) = split(task.stderr, err_hits);
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
            redacted: out_shown + err_shown,
            redacted_withheld: out_withheld + err_withheld,
            timed_out: raw.timed_out,
            stopped: raw.stopped,
            elapsed_ms,
            refused: Self::substituted_refusals(
                enforce.map(|e| e.refusals()).unwrap_or_default(),
                &needles,
                &placeholder,
            ),
            output: output.map(|o| {
                let size = o.size();
                (format!("{TASK_OUT_AGENT}/{}", task.name), size)
            }),
        })
    }

    /// Substitute credentials out of the paths an exec refusal names, exactly as the output is.
    ///
    /// These paths are a **third sink**. `stdout` and `stderr` are scanned because they leave; a
    /// refusal leaves too — straight to the caller — and it is the one text a caller receives that
    /// the command chose without writing a byte of output. The program a command reaches for is the
    /// command's own choice, so a command that spelled a credential into a program name would hand
    /// the caller that spelling verbatim.
    ///
    /// It cannot happen while every command is fixed and every parameter is bounded, which is the
    /// state of a declaration today. That is the wrong thing to rely on: the substituter's promise is
    /// about **spelling**, not about who composed the command, and a promise that holds only while a
    /// neighbouring check holds is one that breaks the day the neighbour moves.
    ///
    /// The hits are deliberately **not** added to the invocation's redaction count. That count is
    /// reported as values substituted out of the *output*, and a path is not output; the caller can
    /// see the substitution in the refusal line it is already reading, so a number would restate what
    /// it is looking at.
    fn substituted_refusals(
        refusals: Vec<super::proc_enforce::Refusal>,
        needles: &[super::proxy::SecretNeedle],
        placeholder: &Placeholder,
    ) -> Vec<super::proc_enforce::Refusal> {
        refusals
            .into_iter()
            .map(|r| super::proc_enforce::Refusal {
                caller: super::redact::redact_string(&r.caller, needles, placeholder).0,
                target: super::redact::redact_string(&r.target, needles, placeholder).0,
            })
            .collect()
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
    fn cage_argv(
        &self,
        argv: Vec<OsString>,
        task: &TaskSpec,
        tcp: &[super::egress::TcpDestination],
    ) -> Vec<OsString> {
        if task.network.is_empty() {
            return argv;
        }
        super::egress::wrap_command(&self.forwarder.socat, &self.forwarder.shell, argv, tcp)
    }

    /// Assemble the cage for one invocation: the structural skeleton, the project read-only, a fresh
    /// tmpfs home, an empty network namespace.
    fn build_spec(
        &self,
        argv: Vec<OsString>,
        env: &[(String, String)],
        task: &TaskSpec,
        inv: &Invocation<'_>,
    ) -> Result<SandboxSpec, String> {
        let Invocation {
            number: invocation,
            proxy_binds,
            tcp,
            output,
        } = *inv;
        let mut mounts = self.base_mounts.clone();
        // The task tool pool, **read-only** and at the same in-cage path the install cage used —
        // that agreement is what keeps the absolute paths mise baked into the pool valid. Bound only
        // when this task declares a tool, so a task that needs none sees no pool at all.
        if let Some((pool, _)) = &self.pool
            && !task.packages.is_empty()
            && pool.is_dir()
        {
            mounts.push(Mount::RoBind {
                src: pool.clone(),
                dest: PathBuf::from(super::taskpool::POOL_INCAGE),
            });
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
        // A task's `network` is its own, so its `/etc/hosts` must be too: the one inherited from the
        // agent cage maps the *agent's* destinations. Written per invocation and bound over the
        // inherited mount, so a task's command resolves the hosts this task declared and nothing
        // else. Swept with the invocation's other runtime files.
        if !tcp.destinations.is_empty() {
            let hosts = self
                .layout
                .data_dir()
                .join("egress")
                .join(format!("hosts-{}.t{invocation}", std::process::id()));
            let body = super::binds::hosts_contents(
                &super::naming::cage_hostname(&format!("{}-task{invocation}", self.slug)),
                &tcp.destinations,
            );
            std::fs::write(&hosts, body).map_err(|e| {
                format!(
                    "cannot write {}, the hosts file this task's cage resolves names through: {e}. \
                     The hosts its `network` declares would not resolve inside the cage, so the \
                     task is refused rather than run against the agent's own mapping.",
                    hosts.display()
                )
            })?;
            mounts.push(Mount::RoBind {
                src: hosts,
                dest: PathBuf::from("/etc/hosts"),
            });
        }
        // Likewise for a destination on a privileged port, which no cage can listen on: this task's
        // own ssh config, bound over whatever the agent cage carried, so `ssh`/`scp` in a declared
        // command reaches the destination *this task* declared through its own proxy — and nothing
        // else. Written per invocation and swept with the invocation's other runtime files.
        if let Some(body) =
            super::egress::ssh_config_contents(&self.forwarder.socat, &tcp.connect_only)
        {
            let ssh_config = self
                .layout
                .data_dir()
                .join("egress")
                .join(format!("sshcfg-{}.t{invocation}", std::process::id()));
            std::fs::write(&ssh_config, body).map_err(|e| {
                format!(
                    "cannot write {}, the ssh config this task's cage reaches a privileged port \
                     through: {e}. The command would dial a port nothing listens on, so the task \
                     is refused rather than run into a bare connection refused.",
                    ssh_config.display()
                )
            })?;
            mounts.push(Mount::RoBind {
                src: ssh_config,
                dest: PathBuf::from(super::binds::SSH_CONFIG_INCAGE),
            });
        }

        // The one writable path whose contents outlive the invocation, when the task declared
        // `output`. After the tmpfs pair, so `/tmp` cannot mount over it; a real directory under the
        // project's runtime tree, never a tmpfs, because an artifact's size is the whole point.
        if let Some(dir) = output {
            mounts.push(Mount::Bind {
                src: dir.to_path_buf(),
                dest: PathBuf::from(TASK_OUT_INCAGE),
            });
        }

        // The project, read-only: a task reads the repository it operates on, and a task that could
        // write it would be a way to edit the project through a credential-bearing command. Last,
        // so it survives wherever on the filesystem it sits.
        mounts.push(Mount::RoBind {
            src: self.project.clone(),
            dest: self.project.clone(),
        });

        // The session's `[fs]` masks, re-emitted over that bind — after it, or the project mount
        // would cover them. Default-closed: a task sees every masked path closed unless its own
        // `unmask` names it, so declaring a mask does not quietly open it to whatever operations
        // the session happens to offer. Only `deny` is carried; the project is already read-only
        // here, so a `readonly` entry would restate what this cage's shape says.
        if let Some((masks, decoys)) = &self.fs_masks {
            let (mask_mounts, unused) =
                super::fsmask::task_mounts(masks, decoys, &self.project, &task.unmask);
            for warning in unused {
                crate::diag::warn(&format!("task `{}`: {warning}", task.name));
            }
            mounts.extend(mask_mounts);
        }
        SandboxSpec::new(
            self.project.clone(),
            mounts,
            env.to_vec(),
            NetPolicy::Isolated,
            argv,
        )
        // The invocation number is part of the cage's name because it is part of its identity: it
        // is the one number naming this invocation everywhere else it is named, and a cage shown in
        // `systemctl --user` or `systemd-cgls` reads back to the invocation that stood it up.
        .map(|s| s.with_cage_slug(format!("{}-task{invocation}", self.slug)))
        .map_err(|e| format!("cannot build the task cage: {e:?}"))
    }

    /// Run the assembled cage, capturing both streams up to the task's ceiling and killing it at the
    /// timeout. Returns the raw (unsubstituted) bytes — substitution is the caller's next step, so
    /// there is exactly one place it can be forgotten.
    fn exec(
        &self,
        spec: &SandboxSpec,
        task: &TaskSpec,
        invocation: u64,
        scan_margin: usize,
    ) -> io::Result<RawOutput> {
        // The same assembly a launch makes, rather than a second spelling of it: a task cage never
        // carries a netns dummy, so the holder step the shared form adds is a no-op here — and stays
        // correct rather than silently absent if one ever does.
        let (prog, args, memfds) = super::launch::cage_command(&self.bwrap, spec, &self.limits)?;
        // A stop that arrived while the credentials were resolving is honored by not starting the
        // command at all — the earliest point at which it can be, and the only one where "stopped"
        // means nothing ran.
        if self.stop_requested(invocation) {
            return Ok(RawOutput {
                exit: STOPPED_EXIT,
                stdout: Vec::new(),
                stderr: Vec::new(),
                truncated: false,
                timed_out: false,
                stopped: true,
            });
        }
        let mut child = spawn_launcher(
            Command::new(prog)
                .args(args)
                // No stdin at all: a task is non-interactive, and an inherited stdin would be a
                // channel into a credential-bearing command.
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
            memfds,
        )?;
        self.note_pid(invocation, child.id());

        // Read both streams on their own threads so neither can block the other by filling its pipe
        // while the runner waits on the wrong one.
        let cap = task.max_output as usize;
        let mut out_pipe = child.stdout.take().expect("stdout piped");
        let mut err_pipe = child.stderr.take().expect("stderr piped");
        let out_reader = std::thread::spawn(move || read_capped(&mut out_pipe, cap, scan_margin));
        let err_reader = std::thread::spawn(move || read_capped(&mut err_pipe, cap, scan_margin));

        let deadline = Instant::now() + task.timeout;
        let mut timed_out = false;
        let mut stopped = false;
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
                // A stop uses the same lever as the timeout and stays a *distinct* answer: both end
                // the command, but one is the declaration's ceiling firing and the other is someone
                // deciding, and a caller that cannot tell them apart cannot know which to act on.
                None if self.stop_requested(invocation) => {
                    stopped = true;
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
            stopped,
        })
    }

    /// Whether invocation `id` has been asked to stop.
    fn stop_requested(&self, id: u64) -> bool {
        // A `false` from a poisoned lock would read as "no stop was asked for", which both callers
        // act on: one starts the command, the other keeps waiting on it. A stopped invocation would
        // run, and go on running.
        locked(&self.running).get(&id).is_some_and(|e| e.stop)
    }

    /// Record the cage's pid against the live invocation, so a reader can see which process a
    /// long-running operation is.
    fn note_pid(&self, id: u64, pid: u32) {
        let mut running = locked(&self.running);
        if let Some(entry) = running.get_mut(&id) {
            entry.pid = Some(pid);
        }
    }

    /// Record what this invocation actually runs, once its parameters are substituted in.
    fn note_argv(&self, id: u64, argv: &[OsString]) {
        let mut running = locked(&self.running);
        if let Some(entry) = running.get_mut(&id) {
            entry.argv = argv
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
        }
    }

    /// Everything known about invocation `id` while it runs: its live state, what it is running, and
    /// the declaration it runs under. Ordered, because it is read by a person rather than parsed.
    ///
    /// Environment values are **absent** by construction, not filtered: a task's credentials are
    /// resolved per invocation and never held anywhere this can reach. What a reader gets is the
    /// declaration and the command, which is the pair that answers "what is this doing".
    pub(crate) fn describe(&self, id: u64) -> Option<Vec<(String, String)>> {
        let (task, elapsed, argv, pid, stopping, detached) = {
            let running = locked(&self.running);
            let entry = running.get(&id)?;
            (
                entry.task.clone(),
                entry.started.elapsed().as_millis() as u64,
                entry.argv.clone(),
                entry.pid,
                entry.stop,
                entry.detached,
            )
        };
        let mut out = vec![
            ("id".into(), id.to_string()),
            ("operation".into(), task.clone()),
            (
                // A stop that has been asked for is the more urgent fact, so it wins the field; a
                // detached invocation that is stopping is a stopping one, and the listing agrees.
                "state".into(),
                match (stopping, detached) {
                    (true, _) => "stopping".into(),
                    (false, true) => "detached".to_string(),
                    (false, false) => "running".to_string(),
                },
            ),
            ("elapsed_ms".into(), elapsed.to_string()),
            ("pid".into(), pid.map(|p| p.to_string()).unwrap_or_default()),
            ("command".into(), shell_line(&argv)),
        ];
        let command = out.last().map(|(_, v)| v.clone()).unwrap_or_default();
        out.extend(self.task(&task).map(declared_fields).unwrap_or_default());
        // `declared` is the command as written, `command` is it with this invocation's parameters
        // substituted in. An operation with no parameters makes them the same string, and printing a
        // line that repeats the one above it is the same noise as a column that reads the same on
        // every row — so it is kept only when it differs, which is exactly when it is informative.
        out.retain(|(k, v)| k != "declared" || *v != command);
        Some(out)
    }

    /// What one declared operation says about itself — the declaration alone, with no identity of
    /// its own: it is appended to an invocation's fields, which already name it, and prefixed with
    /// the name when a reader asks about the operation rather than a run of it.
    pub(crate) fn describe_task(&self, name: &str) -> Option<Vec<(String, String)>> {
        Some(declared_fields(self.task(name)?))
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

    /// The host directory holding every output-declaring task's directory for this project.
    fn output_root(&self) -> io::Result<PathBuf> {
        output_root_for(&self.layout, &self.project)
    }

    /// Claim `task`'s output directory for one invocation: empty it, create it, and hold the name so
    /// a concurrent invocation of the same task is refused rather than writing into the same place.
    ///
    /// Emptying is what keeps a predictable path honest. The directory is one per task, so a caller
    /// knows where to look without being told — and would otherwise find the previous invocation's
    /// artifact sitting there, indistinguishable from the one it just asked for.
    fn claim_output(&self, task: &TaskSpec) -> Result<OutputClaim, String> {
        {
            let mut held = locked(&self.output_held);
            if !held.insert(task.name.clone()) {
                return Err(format!(
                    "another invocation of `{}` is still writing to its output directory — a task's \
                     directory is one per task, so two at once would interleave",
                    task.name
                ));
            }
        }
        let dir = match self.output_root() {
            Ok(root) => root.join(&task.name),
            Err(e) => {
                locked(&self.output_held).remove(&task.name);
                return Err(format!("no project tree for this task's output ({e})"));
            }
        };
        let prepare = || -> io::Result<()> {
            if dir.exists() {
                super::gc::force_remove_dir_all(&dir)?;
            }
            std::fs::create_dir_all(&dir)
        };
        if let Err(e) = prepare() {
            locked(&self.output_held).remove(&task.name);
            return Err(format!(
                "cannot prepare the output directory {}: {e}",
                dir.display()
            ));
        }
        Ok(OutputClaim {
            dir,
            task: task.name.clone(),
            held: self.output_held.clone(),
        })
    }

    /// Enter `id` in the live registry for the length of the invocation, refusing a detached one that
    /// would exceed [`MAX_DETACHED`].
    ///
    /// The count and the insertion happen under one lock, so two callers racing for the last slot
    /// cannot both take it. The cap is checked here rather than beside the call for that reason
    /// alone — a check outside would be a read of a number that can change before it is used.
    ///
    /// A poisoned registry refuses **both**, and the asymmetry it used to keep is gone with the
    /// reason for it: an attached invocation was admitted because its caller waiting for it was a
    /// limit no lock was needed to know, and [`MAX_LIVE`] is why that is no longer a limit. A cap
    /// that cannot be evaluated must not be assumed satisfied, and one that a caller could get
    /// around by arranging for the lock to be poisoned would not be a cap.
    fn enter(&self, id: u64, task: &str, detached: bool) -> Result<RunGuard, String> {
        match self.running.lock() {
            Ok(mut running) => {
                if running.len() >= MAX_LIVE {
                    return Err(format!(
                        "{} invocations are already running, which is the limit — each one holds a \
                         cage, a proxy and a scope of its own, so what bounds them is how many run \
                         together rather than the session's call quota. `sbx task status` shows \
                         them; `sbx task stop <id>` ends one",
                        running.len()
                    ));
                }
                let live = running.values().filter(|r| r.detached).count();
                if detached && live >= MAX_DETACHED {
                    return Err(format!(
                        "{live} detached invocations are already running, which is the limit — each \
                         one holds a cage, a proxy and a scope of its own, so they are capped \
                         separately from the session's call quota. `sbx task status` shows them; \
                         `sbx task stop <id>` ends one"
                    ));
                }
                running.insert(
                    id,
                    Running {
                        task: task.to_string(),
                        started: Instant::now(),
                        argv: Vec::new(),
                        pid: None,
                        stop: false,
                        detached,
                    },
                );
            }
            Err(_) => {
                return Err(
                    "the invocation registry is unavailable, so the limit on how many \
                            invocations run at once cannot be checked"
                        .to_string(),
                );
            }
        }
        Ok(RunGuard {
            id,
            registry: self.running.clone(),
        })
    }

    /// What is running right now, oldest first.
    pub(crate) fn running(&self) -> Vec<RunningView> {
        let running = locked(&self.running);
        running
            .iter()
            .map(|(id, r)| RunningView {
                id: *id,
                task: r.task.clone(),
                elapsed_ms: r.started.elapsed().as_millis() as u64,
                pid: r.pid,
                stopping: r.stop,
                detached: r.detached,
            })
            .collect()
    }

    /// Stop invocation `id`, and report what actually happened rather than what was asked for.
    ///
    /// Asking is instant; stopping is not. The runner honors the request at its next poll, and
    /// anything already under way before the command spawned — a credential resolving through a
    /// subprocess, a proxy being stood up — finishes first. So this sets the flag, waits a bounded
    /// [`STOP_GRACE`] for the invocation to actually leave the registry, and distinguishes the two
    /// outcomes. Reporting "stopped" for a request still in flight would be a claim about another
    /// process that this one cannot make.
    pub(crate) fn stop(&self, id: u64) -> StopOutcome {
        {
            // Recovers, where [`Self::enter`] refuses, and the two are not in tension. `enter` holds
            // a **cap**: one a caller could get around by arranging for the lock to be poisoned
            // would not be a cap, so doubt has to refuse. This holds no cap — it carries an order,
            // and the safe direction for an order to stop is that it arrives. Giving up here set no
            // flag at all and reported `NotRunning`, so the invocation the user stopped kept
            // running under an answer saying it was never there.
            let mut running = locked(&self.running);
            match running.get_mut(&id) {
                Some(entry) => entry.stop = true,
                None => return StopOutcome::NotRunning,
            }
        }
        let deadline = Instant::now() + STOP_GRACE;
        while Instant::now() < deadline {
            if !self.is_running(id) {
                return StopOutcome::Stopped;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        StopOutcome::Stopping
    }

    /// Whether invocation `id` is still in the registry — the one fact that tells a stop that
    /// *happened* from a stop that was merely requested.
    fn is_running(&self, id: u64) -> bool {
        // The fact a stop reports on. A `false` taken from a poisoned lock rather than from the
        // registry would report an invocation as stopped while it is still running.
        locked(&self.running).contains_key(&id)
    }

    /// Where an in-cage path lives on the host, read off the mounts this cage is built from. A path
    /// under no mount has no host counterpart — the cage is hermetic, so that is the normal answer
    /// for anything the declaration did not put there.
    ///
    /// The **longest** matching mount wins: a cage nests them (the tool pool sits under a directory
    /// the skeleton also maps), and the innermost is the one whose source the kernel will actually
    /// resolve through.
    fn host_path(&self, incage: &Path, task: &TaskSpec) -> Option<PathBuf> {
        let mut best: Option<(usize, PathBuf)> = None;
        let mut consider = |src: &Path, dest: &Path| {
            if let Ok(rest) = incage.strip_prefix(dest) {
                let depth = dest.components().count();
                if best.as_ref().is_none_or(|(d, _)| depth > *d) {
                    best = Some((depth, src.join(rest)));
                }
            }
        };
        for mount in &self.base_mounts {
            match mount {
                Mount::RoBind { src, dest } | Mount::Bind { src, dest } => consider(src, dest),
                _ => {}
            }
        }
        if let Some((pool, _)) = &self.pool
            && !task.packages.is_empty()
        {
            consider(pool, Path::new(super::taskpool::POOL_INCAGE));
        }
        // The project, read-only at the path it occupies on the host. Bound when the cage is built
        // rather than carried in the base list, and it has to be named here too: a command that is a
        // script in the repository is reachable only through this mapping, and without it the file
        // could not be read to see what runs it.
        consider(&self.project, &self.project);
        best.map(|(_, p)| p)
    }

    /// Resolve one declared `spawn` entry (or the command itself) to the rule that will match the
    /// `execve` the cage really issues.
    ///
    /// A bare name is looked up on the cage's own `PATH` and returned as the **absolute in-cage
    /// path**. That is the whole point of resolving: a basename rule would admit any file of that
    /// name, including one written into the invocation's own tmpfs, while a resolved path names the
    /// program in the read-only store and nothing else. An entry that already carries a `/` is a
    /// path or a path glob the author wrote deliberately, and is kept verbatim.
    ///
    /// Not finding a declared name refuses the launch: a rule that matches nothing would leave the
    /// program it names unrunnable, which is not what the declaration says.
    fn resolve_spawn_entry(
        &self,
        entry: &str,
        path_dirs: &[PathBuf],
        task: &TaskSpec,
    ) -> Result<String, String> {
        use std::os::unix::fs::PermissionsExt;
        if entry.contains('/') {
            return Ok(entry.to_string());
        }
        for dir in path_dirs {
            let incage = dir.join(entry);
            let Some(host) = self.host_path(&incage, task) else {
                continue;
            };
            let executable = std::fs::metadata(&host)
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false);
            if executable {
                return Ok(incage.to_string_lossy().into_owned());
            }
        }
        // A bare entry is a name, so a glob in one matches no file and would otherwise be reported
        // as simply absent — blaming the lookup for what is really the form.
        let hint = if entry.contains('*') || entry.contains('?') {
            " — a bare entry is a program name, not a pattern; a glob has to be written as a path \
             (`/nix/store/*/bin/tool`)"
        } else {
            " — a declared program must exist in the cage, or the rule naming it would match nothing"
        };
        Err(format!("`{entry}` is not on this task's path{hint}"))
    }

    /// Resolve a cage path's symlinks **in cage space**, down to the path the kernel will report as
    /// `/proc/<pid>/exe` for a process running it — which is how a caller is addressed.
    ///
    /// Cage space and not the host's, because the two disagree in both directions. A cage's `/bin/sh`
    /// is a symlink bubblewrap creates, so no host file answers for it; and a program built into a
    /// per-project store sits at a host path that is not the path the cage runs it by. So each link
    /// is read through whichever side knows it — the mount list for the names the cage synthesises,
    /// the host file for everything the cage merely maps — and its target is read as a cage path
    /// either way.
    ///
    /// Only the final component is followed: a directory in the middle could be a symlink too, but
    /// the paths here come from the cage's own `PATH` and its own mount list, which name directories
    /// as the cage creates them.
    fn canonical_incage(&self, incage: &str, task: &TaskSpec) -> String {
        // Enough hops for a name that goes through the FHS shim and then a multi-call binary; past
        // that a link is looping, and the unresolved path simply matches no caller — fail-closed.
        const MAX_HOPS: usize = 8;
        let mut cur = PathBuf::from(incage);
        for _ in 0..MAX_HOPS {
            let Some(target) = self.read_incage_link(&cur, task) else {
                break;
            };
            cur = if target.is_absolute() {
                target
            } else {
                match cur.parent() {
                    Some(parent) => lexical_join(parent, &target),
                    None => break,
                }
            };
        }
        cur.to_string_lossy().into_owned()
    }

    /// Read one cage path as a symlink, or `None` when it is not one.
    fn read_incage_link(&self, incage: &Path, task: &TaskSpec) -> Option<PathBuf> {
        let synthesised = self.base_mounts.iter().find_map(|mount| match mount {
            Mount::Symlink { target, dest } if dest == incage => Some(target.clone()),
            _ => None,
        });
        match synthesised {
            Some(target) => Some(target),
            None => std::fs::read_link(self.host_path(incage, task)?).ok(),
        }
    }

    /// Say so when a node names one of several programs that are the **same executable**, since its
    /// rule then governs all of them. A caller is addressed by the executable it is, and a
    /// multi-call binary — coreutils is one file behind a hundred names — cannot tell its own names
    /// apart from the outside.
    ///
    /// Only for a declared node: `cmd = ["/bin/sh", …]` reaches the same binary as `bash`, and
    /// warning about the commonest command there is, on every invocation, would teach a reader to
    /// stop reading. What bounds it either way is that only an **allowed** program can be running,
    /// so the over-grant never reaches past the programs the declaration already admits.
    fn warn_if_multicall(&self, program: &str, incage: &str, task: &TaskSpec) {
        let canonical = self.canonical_incage(incage, task);
        let real = Path::new(&canonical).file_name().unwrap_or_default();
        let named = Path::new(incage).file_name().unwrap_or_default();
        if real != named {
            crate::diag::warn(&format!(
                "task `{}`: `{program}` is one name of `{}`, a binary that answers to several — so \
                 what `{program}` may run, every program sharing that binary may run too",
                task.name,
                real.to_string_lossy()
            ));
        }
    }

    /// The program a cage path is **entered as**: itself for a binary, its interpreter for a script.
    ///
    /// A `#!` line is read by the kernel inside the `execve` that named the script — there is no
    /// second syscall — so nothing observes the script as a running program. Only the interpreter
    /// runs, and only the interpreter can be the caller of anything the script goes on to do.
    ///
    /// Read from the file rather than assumed, and followed through an interpreter that is itself a
    /// script, which the kernel does not do (Linux runs one `#!` hop) but a reader might write. The
    /// hop cap is what a loop meets; an unreadable file is left as itself, and the policy then simply
    /// governs a program that never appears — fail-closed.
    ///
    /// A **relative** spelling is resolved against the cage's working directory first, because what
    /// this returns is a caller key: the supervisor addresses a caller by `/proc/<pid>/exe`, which
    /// is absolute, always. A node declared as `[exec."./build.sh"]` was keyed by the string
    /// `./build.sh`, which no caller can equal, and an unmatched caller under a `CallerGraph` takes
    /// `unmatched()` — `Deny` for the `confine` mode a task runs in. The declaration read as a grant
    /// and behaved as a denial, and nothing said so. The working directory is the task's project
    /// directory (what the cage's `--chdir` is set to), which is what the kernel would resolve the
    /// name against; resolving it here is also what lets the file be read at all, since a relative
    /// cage path has no host counterpart.
    ///
    /// Only the **caller** side is resolved. A target rule is matched against the path the process
    /// asked for, which may itself be relative, so an entry of a `spawn` list stays as written.
    fn entered_as(&self, incage: &str, task: &TaskSpec) -> String {
        const MAX_HOPS: usize = 4;
        let mut cur = match incage.starts_with('/') {
            true => incage.to_string(),
            false => lexical_join(&self.project, Path::new(incage))
                .to_string_lossy()
                .into_owned(),
        };
        for _ in 0..MAX_HOPS {
            let Some(interpreter) = self.shebang_of(&cur, task) else {
                break;
            };
            cur = interpreter;
        }
        cur
    }

    /// The interpreter a cage path's `#!` line names, or `None` when the file is not a script.
    ///
    /// Only the first token after `#!` — Linux passes the rest as a single argument to the
    /// interpreter, so `#!/usr/bin/env bash` runs **`env`**, and it is `env` that goes on to run
    /// bash. Reporting `bash` here would name a program that is not what the process becomes.
    fn shebang_of(&self, incage: &str, task: &TaskSpec) -> Option<String> {
        use std::io::Read;
        // The kernel reads at most one BINPRM_BUF_SIZE page of `#!` line; far less is enough to
        // decide, and a bounded read keeps a named pipe or a huge binary from being pulled in.
        const PROBE: usize = 512;
        let host = self.host_path(Path::new(incage), task)?;
        let mut head = [0u8; PROBE];
        let read = std::fs::File::open(&host).ok()?.read(&mut head).ok()?;
        let line = head[..read].split(|b| *b == b'\n').next()?;
        let rest = line.strip_prefix(b"#!")?;
        let interpreter = std::str::from_utf8(rest).ok()?.split_whitespace().next()?;
        // A relative interpreter is resolved against the caller's working directory, which is not a
        // fact this policy has. Leaving it unresolved keeps the node honest rather than inventing a
        // path that would match nothing anyway.
        interpreter
            .starts_with('/')
            .then(|| interpreter.to_string())
    }

    /// The exec policy for one invocation: what each program may run, keyed by the program running
    /// it, with every name resolved to the absolute in-cage path it will run as.
    fn spawn_policy(
        &self,
        task: &TaskSpec,
        declared: &[String],
        cage_env: &[(String, String)],
    ) -> Result<crate::proc_policy::ProcPolicy, String> {
        use crate::proc_policy::{CallerGraph, ProcRule};
        let path_dirs: Vec<PathBuf> = cage_env
            .iter()
            .rev()
            .find(|(k, _)| k == "PATH")
            .map(|(_, v)| v.split(':').filter(|d| !d.is_empty()).map(PathBuf::from))
            .into_iter()
            .flatten()
            .collect();

        // The command's own node comes from the shim: the shim's exec of the command is the first
        // notified `execve`, and a policy that did not admit it would refuse the task outright.
        let command = self.resolve_spawn_entry(&task.cmd[0], &path_dirs, task)?;
        let mut callers: BTreeMap<String, Vec<ProcRule>> = BTreeMap::from([(
            super::proc_enforce::SHIM_CAGE_PATH.to_string(),
            vec![ProcRule::new(&command)],
        )]);

        // A target is matched against the path the process **asked** for, before symlinks — which is
        // what keeps `ls` meaning `ls`. Resolving targets the way callers are resolved would make
        // every coreutils name mean all of them, so the two sides are deliberately not symmetrical.
        let mut node = |program: &str, incage: &str, entries: Vec<String>| -> Result<(), String> {
            let key = self.canonical_incage(incage, task);
            if callers.contains_key(&key) {
                return Err(format!(
                    "`{program}` cannot have a node of its own: it is the same executable as \
                     another program already declared here, so nothing could tell the two apart \
                     when one of them runs something"
                ));
            }
            callers.insert(key, entries.iter().map(|e| ProcRule::new(e)).collect());
            Ok(())
        };

        let resolve_all = |entries: &[String]| -> Result<Vec<String>, String> {
            entries
                .iter()
                .map(|e| self.resolve_spawn_entry(e, &path_dirs, task))
                .collect()
        };
        // The command's node is keyed by what the command's process actually **is**, which for a
        // script is its interpreter: the kernel loads that interpreter inside the very `execve` that
        // started the script, so from its first instruction the process is `bash`, `python`, `env` —
        // never the file. Keyed by the file, the node would govern a caller that never exists, and
        // its whole list would sit there being read by nothing.
        let entered_as = self.entered_as(&command, task);
        node(&task.cmd[0], &entered_as, resolve_all(declared)?)?;
        for (program, entries) in &task.exec {
            let incage = self.resolve_spawn_entry(program, &path_dirs, task)?;
            self.warn_if_multicall(program, &incage, task);
            // Keyed by what the program is **entered as**, exactly like the command's node above
            // and for the reason stated there: a script's process is its interpreter from its first
            // instruction, so a node keyed by the script file governs a caller that never exists.
            // These nodes skipped that step, which made every `[exec."/opt/build.sh"]` a dead entry
            // — and dead in the direction that refuses, since an unmatched caller under a
            // `CallerGraph` takes `unmatched()`, which is `Deny` for the `confine` mode a task runs
            // in. The declaration read as a grant and behaved as a denial. `entered_as` also
            // resolves a relative spelling against the cage's working directory, for the same
            // reason and with the same consequence — see its own doc.
            //
            // `warn_if_multicall` stays on the declared program: its question is whether *that*
            // name is one of several for one binary, which is not a question about the interpreter.
            let entered = self.entered_as(&incage, task);
            node(program, &entered, resolve_all(entries)?)?;
        }
        Ok(crate::proc_policy::ProcPolicy::confined(CallerGraph {
            callers,
        }))
    }
}

/// Join a relative symlink target onto its directory, resolving `.` and `..` **lexically** — the
/// path is a cage path, so there is no filesystem here to ask.
fn lexical_join(base: &Path, target: &Path) -> PathBuf {
    let mut out = base.to_path_buf();
    for part in target.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
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

/// What one **invocation** contributes to its cage, beyond what the task's own declaration fixes.
/// Grouped rather than passed one by one: these four travel together, and a positional list of them
/// beside the task and its argv is where a caller silently swaps two.
struct Invocation<'a> {
    /// This invocation's number, worn by every host-side name it stands up.
    number: u64,
    /// The proxy socket and CA, when the task declared egress.
    proxy_binds: &'a [super::binds::ExtraBind],
    /// Where this task's declared `tcp://` destinations live inside its cage — the ones with a
    /// listener, and the ones only an explicit `CONNECT` reaches.
    tcp: &'a super::egress::TcpPlan,
    /// The writable output directory, when the task declared one.
    output: Option<&'a Path>,
}

/// Where a project's task output lives on the host: under the project's own runtime tree, so
/// `sbx projects rm` and the runtime sweep reclaim an artifact with the project it belongs to
/// instead of it needing a lifecycle of its own.
///
/// **One derivation, used twice** — by the engine that writes into it and by the launch that binds
/// it read-only into the agent's cage. Two would be two chances to disagree about which directory an
/// artifact is in, and the disagreement would show up as an empty directory rather than an error.
/// The id comes from the *canonical* path, like every other per-project tree.
pub(crate) fn output_root_for(
    layout: &crate::store::Layout,
    project: &Path,
) -> io::Result<PathBuf> {
    Ok(layout
        .data_dir()
        .join("projects")
        .join(super::binds::project_runtime_id(project)?)
        .join(TASK_OUT_TREE))
}

/// One invocation's hold on its task's output directory, released when the invocation ends —
/// including when it ends by panic or early return, which is why it is a guard and not a pair of
/// calls.
#[derive(Debug)]
struct OutputClaim {
    dir: PathBuf,
    task: String,
    held: Arc<Mutex<BTreeSet<String>>>,
}

impl OutputClaim {
    /// What the directory holds now, in bytes — reported so a caller learns an artifact was produced
    /// without having to go and look.
    fn size(&self) -> u64 {
        fn walk(dir: &Path) -> u64 {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return 0;
            };
            entries
                .flatten()
                .map(|e| match e.file_type() {
                    Ok(t) if t.is_dir() => walk(&e.path()),
                    Ok(t) if t.is_file() => e.metadata().map(|m| m.len()).unwrap_or(0),
                    _ => 0,
                })
                .sum()
        }
        walk(&self.dir)
    }
}

impl Drop for OutputClaim {
    fn drop(&mut self) {
        // The same lock `claim_output` takes through `locked`, released the same way: taking it
        // with recovery and releasing it without would strand the claim, and every later invocation
        // of this task would be refused for a conflict with an invocation that has already ended.
        locked(&self.held).remove(&self.task);
    }
}

/// One invocation while it is still running: what it is, when it started, and whether someone has
/// asked it to stop.
#[derive(Debug)]
struct Running {
    task: String,
    /// For the elapsed time, which is what a caller looking at a live invocation actually wants.
    started: Instant,
    /// The task's **own** command with this invocation's parameters substituted in — not the
    /// bubblewrap argv that wraps it. A credential never appears here: credentials reach a task
    /// through its environment, and what a parameter contributed is the caller's own value.
    argv: Vec<String>,
    /// The cage's pid once it exists — **display only**. Stopping goes through [`Running::stop`] and
    /// the runner's own `Child`, never a signal aimed at a pid read from here: a pid can be reaped
    /// and reused between the read and the signal, and the target of that race is another process
    /// entirely.
    pid: Option<u32>,
    /// Set by [`TaskEngine::stop`]; read by the runner on its next poll.
    stop: bool,
    /// Whether the caller that started this one is no longer waiting for it. Recorded because it is
    /// the only thing a reader cannot infer: a detached invocation looks exactly like an attached one
    /// while it runs, and it is the one whose result nobody is holding a terminal open for.
    detached: bool,
}

/// Render an argv as one readable line, quoting only what needs it — this is for a person to read,
/// not for a shell to run, so it stays close to what was written.
fn shell_line(argv: &[String]) -> String {
    argv.iter()
        .map(
            |arg| match arg.chars().any(|c| c.is_whitespace() || c == '\'') {
                false => arg.clone(),
                true => format!("'{}'", arg.replace('\'', "'\\''")),
            },
        )
        .collect::<Vec<_>>()
        .join(" ")
}

/// The declaration an invocation runs under, as ordered fields. Credential **names** only — a value
/// is resolved per invocation and never kept, and the name is what a substituted value is reported
/// as if it ever reaches the output.
fn declared_fields(task: &TaskSpec) -> Vec<(String, String)> {
    let list = |items: Vec<String>| items.join(", ");
    let mut out = vec![
        (
            "description".to_string(),
            task.description.clone().unwrap_or_default(),
        ),
        ("declared".to_string(), shell_line(&task.cmd)),
        // Beside the declaration it belongs to, and always shown here unlike the listing, which
        // drops the column when every row says the same: a reader asking about *one* operation is
        // often asking exactly this. It names where the block is and nothing more — a ceiling the
        // block does not set carries its own source, below.
        ("declared in".to_string(), task.origin.label()),
        (
            "parameters".to_string(),
            list(
                task.params
                    .iter()
                    .map(|p| match &p.default {
                        Some(d) => format!("{} (default {d})", p.name),
                        None => p.name.clone(),
                    })
                    .collect(),
            ),
        ),
        ("timeout_s".to_string(), task.timeout.as_secs().to_string()),
        // A ceiling the task did not set itself says which `[task.defaults]` it came from. Its own
        // key rather than text folded into the value, so the reader that formats the number does not
        // have to take it apart again; the `_from` suffix is what pairs the two.
        (
            "timeout_s_from".to_string(),
            task.timeout_from.label().unwrap_or_default(),
        ),
        ("max_output".to_string(), task.max_output.to_string()),
        (
            "max_output_from".to_string(),
            task.max_output_from.label().unwrap_or_default(),
        ),
        ("stdout".to_string(), task.stdout.as_str().to_string()),
        ("stderr".to_string(), task.stderr.as_str().to_string()),
        (
            "credentials".to_string(),
            list(
                task.secrets
                    .iter()
                    .map(|s| s.var.clone())
                    .chain(
                        task.injections
                            .iter()
                            .map(|i| format!("{} → {}", i.name, i.to)),
                    )
                    .collect(),
            ),
        ),
        (
            "network".to_string(),
            list(task.network.iter().map(|r| r.to_string()).collect()),
        ),
        (
            "output".to_string(),
            match task.output {
                true => format!("{TASK_OUT_AGENT}/{}", task.name),
                false => String::new(),
            },
        ),
        ("packages".to_string(), list(task.packages.clone())),
        (
            "spawn".to_string(),
            match &task.spawn {
                Some(names) => list(names.clone()),
                None => String::new(),
            },
        ),
        ("env_allow".to_string(), list(task.env_allow.clone())),
    ];
    // One row per program that has a node, keyed by the program so the rows read as the chain they
    // are — `spawn` says what the command may run, `git spawns` what git may run in turn. Placed
    // beside `spawn` rather than folded into it: a single cell holding a graph is a cell nobody
    // reads twice.
    if let Some(at) = out.iter().position(|(k, _)| k == "spawn") {
        let nodes = task
            .exec
            .iter()
            .map(|(program, entries)| (format!("{program} spawns"), list(entries.clone())));
        out.splice(at + 1..at + 1, nodes);
    }
    // An empty field is left out rather than shown as a blank: this is read as prose, and a page of
    // "network:" with nothing after it says less than its absence does.
    out.retain(|(_, v)| !v.is_empty());
    out
}

/// What a stop request actually achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopOutcome {
    /// The invocation ended. Nothing of it is still running.
    Stopped,
    /// The request was recorded and the invocation is still finishing — it was in a step that has to
    /// return before the runner can act (see [`TaskEngine::stop`]).
    Stopping,
    /// No invocation by that id is running.
    NotRunning,
}

/// One live invocation as a reader sees it. A snapshot, deliberately: the registry's lock is held
/// only long enough to copy, so listing what is running can never delay the thing being listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunningView {
    pub(crate) id: u64,
    pub(crate) task: String,
    pub(crate) elapsed_ms: u64,
    pub(crate) pid: Option<u32>,
    pub(crate) stopping: bool,
    pub(crate) detached: bool,
}

/// An invocation the engine has accepted but not yet run: the decisions a caller can act on, plus
/// the two things it holds for its whole life. Both are guards, so an admission that is dropped
/// without being run releases its registry entry and its output directory rather than stranding them.
///
/// It exists so that a **detached** caller can be answered before the command starts and still have
/// been told every refusal that concerns it. Passing it back to [`TaskEngine::run_admitted`] is what
/// makes the attached and detached paths one path: they differ in which thread runs the second half,
/// and in nothing else.
pub(crate) struct Admission {
    id: u64,
    /// An `Option` only so a caller can take it out with [`Admission::hold_registration`]; an
    /// admission that keeps it releases the entry when the run ends, which is what the attached
    /// path wants.
    live: Option<RunGuard>,
    /// The parameter values, checked against their declared bounds, with `{out}` already resolved.
    values: BTreeMap<String, String>,
    /// The caller-supplied variables, checked against `env_allow`.
    caller_env: Vec<(String, String)>,
    output: Option<OutputClaim>,
}

impl Admission {
    /// Take the registry entry out, so the caller decides when this invocation stops reading as
    /// running rather than having that decided by [`TaskEngine::run_admitted`] returning.
    ///
    /// The detached path needs it: the entry is what `RESULT <id>` consults to answer "still
    /// running", and the result it will answer with instead is stored two statements after the run
    /// returns. Released in between, the invocation reads as neither running nor holding a result,
    /// and the reader's remaining branches say "no invocation" or "its result is no longer held" —
    /// both false, and both terminal to a caller that asked once. Held until the result is stored,
    /// the worst answer in that window is "still running", which is the direction a caller retries
    /// on.
    ///
    /// Returns `None` on a second call: there is one entry, and the first caller has it.
    pub(crate) fn hold_registration(&mut self) -> Option<RunGuard> {
        self.live.take()
    }
}

/// One invocation's presence in the live registry, removed when it ends — by return, by error, or by
/// panic. A guard rather than a pair of calls for the same reason as [`OutputClaim`]: an entry left
/// behind would be an invocation `sbx task status` reports forever and `sbx task stop` can never
/// stop.
pub(crate) struct RunGuard {
    id: u64,
    registry: Arc<Mutex<BTreeMap<u64, Running>>>,
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        // Recovering here is what keeps the registry finite. A release that gave up on a poisoned
        // lock would leave this invocation in the map for the life of the session — read as running
        // long after it ended, and counted against [`MAX_LIVE`] by every admission after it.
        locked(&self.registry).remove(&self.id);
    }
}

/// The unsubstituted capture of one invocation, internal to the engine.
struct RawOutput {
    exit: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
    timed_out: bool,
    stopped: bool,
}

/// Spawn a cage launcher, then close this process's copies of the descriptors bwrap was told to
/// read.
///
/// [`super::argv::compose`] returns the compiled seccomp filters and the `--args` file as
/// anonymous in-memory files that are deliberately **not** close-on-exec ([`super::memfd`]), because
/// bwrap has to still be able to read them after the exec. A descriptor that survives one exec
/// survives every exec this process makes while it is open, and `Command::spawn` closes nothing in
/// the child that it was not told about — so every one of these that is still open when a *sibling*
/// cage is spawned is inherited by that sibling's command.
///
/// That is not a theoretical cost here: the `--args` file of a task invocation holds its
/// `--setenv <VAR> <plaintext>` credential pairs, [`MAX_LIVE`] invocations may run at once, and a
/// task cage runs a program from the project tree — a tree the agent's own cage may write. Holding
/// the descriptors for the run would therefore hand one invocation's resolved credential to any
/// other invocation started during it, walking around the pid namespace that keeps a task's
/// `/proc/<pid>/environ` out of the agent's reach.
///
/// `spawn` has already forked and exec'd by the time it returns, so the descriptors have done their
/// whole job and this is the earliest moment they can go. What remains is the fork window itself: a
/// sibling spawning between this `spawn` and this `drop` still inherits them. Closing that residual
/// means creating the file close-on-exec and clearing the flag only on the child's own copy, which
/// is a property of [`super::memfd`] rather than of any call site.
pub(super) fn spawn_launcher(
    command: &mut Command,
    memfds: Vec<std::fs::File>,
) -> io::Result<std::process::Child> {
    super::memfd::inherit_across_exec(command, &memfds);
    let child = command.spawn()?;
    drop(memfds);
    Ok(child)
}

/// Read a stream up to `cap` bytes, reporting whether it was cut. Reading continues past the cap
/// (draining the pipe) so the command is never blocked on a full pipe — only the *kept* bytes are
/// bounded.
///
/// `margin` extra bytes are kept **for the scanner, not for the caller**. The redaction that follows
/// searches for whole needles, so a credential lying across the cap used to be cut in half and its
/// surviving prefix matched nothing — the caller received it in the clear, from the one path whose
/// whole job is that it does not. A margin of one byte less than the longest needle guarantees that
/// any needle *starting* inside the cap is present whole when the scan runs; one starting at or past
/// the cap is entirely in the discarded tail and never reaches anyone. The caller cuts the redacted
/// result back to `cap`.
///
/// `cut` reports what the **caller** loses, so it is `total > cap` — the margin is not output.
fn read_capped(pipe: &mut impl Read, cap: usize, margin: usize) -> io::Result<(Vec<u8>, bool)> {
    let keep = cap.saturating_add(margin);
    let mut kept = Vec::new();
    let mut total = 0usize;
    let mut buf = [0u8; 8192];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total = total.saturating_add(n);
                if kept.len() < keep {
                    let take = (keep - kept.len()).min(n);
                    kept.extend_from_slice(&buf[..take]);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok((kept, total > cap))
}

/// Derive a task cage's mounts from the agent cage's: keep the substrate the launch declared, then
/// the structural skeleton (see [`KEPT_DESTS`]), repoint `/nix` at the shared store read-only, and
/// demote every kept read-write bind to read-only.
///
/// The substrate comes first and whole, because it is what everything else lands inside: see
/// [`super::binds::substrate`] for what it is and why an allowlist of destinations cannot express
/// it. `/tmp` is the one cover left behind, since [`TaskEngine::build_spec`] mounts a fresh one of
/// the invocation's own and two would be a mount a reader has to explain.
fn task_mounts(cage: &[Mount], shared_store_nix: &Path) -> Vec<Mount> {
    let mut out: Vec<Mount> = super::binds::substrate(cage)
        .into_iter()
        .filter(|m| mount_dest(m) != Path::new("/tmp"))
        .collect();
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
    /// [`Self::inventory_only`] with a launcher that exists, for the one test whose subject is the
    /// **return path** rather than the refusal.
    ///
    /// `inventory_only` points `bwrap` at `/nonexistent/bwrap`, which is right for every test that
    /// only needs a launch to fail. It is wrong for a test asserting on what the command wrote,
    /// because an exec failure is reported by *whoever spawned it*: under a scope wrapper
    /// `systemd-run` names the program it could not run, and with no delegation root
    /// ([`crate::sandbox::cgroup::limiter`] returning `None`) the launch is a bare
    /// `Command::spawn`, whose `ENOENT` names nothing at all. A test reading that wording measures
    /// the host's user manager instead of the stream it means to pin, and passes or fails by where
    /// it runs.
    pub(crate) fn inventory_with_launcher(
        tasks: Vec<crate::config::TaskSpec>,
        bwrap: PathBuf,
    ) -> Self {
        Self {
            bwrap,
            ..Self::inventory_only(tasks)
        }
    }

    /// An engine that knows an inventory but can launch nothing.
    ///
    /// It is enough to serve the listing verbs and to validate an invocation's parameters — so the
    /// wire protocol is exercisable end to end without provisioning a cage, which is what lets the
    /// in-cage client be tested against the real plane rather than a stand-in for it.
    pub(crate) fn inventory_only(tasks: Vec<crate::config::TaskSpec>) -> Self {
        Self {
            fs_masks: None,
            notify: None,
            brokers: Vec::new(),
            egress_log: None,
            signer_log: None,
            redact_min_len: crate::sandbox::redact::MIN_LEN_DEFAULT,
            bwrap: PathBuf::from("/nonexistent/bwrap"),
            forwarder: CageForwarder {
                socat: PathBuf::from("/nonexistent/socat"),
                shell: PathBuf::from("/nonexistent/bash"),
            },
            base_mounts: Vec::new(),
            base_env: Vec::new(),
            project: PathBuf::from("/nonexistent"),
            config_root: PathBuf::from("/nonexistent"),
            output_held: Arc::new(Mutex::new(BTreeSet::new())),
            running: Arc::new(Mutex::new(BTreeMap::new())),
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

    /// Give the engine a real data directory and project, so a test can exercise the output
    /// directory a task claims. It is the one part of an invocation that touches the filesystem
    /// before any cage exists, and therefore the one an inventory-only engine cannot reach.
    #[cfg(test)]
    pub(crate) fn with_tree(mut self, data_dir: &Path, project: PathBuf) -> Self {
        self.layout = crate::store::Layout::under(data_dir);
        self.project = project;
        self
    }
}

/// The needles one resolved task credential contributes: every spelling of it — the plaintext and
/// whatever encoding the declaration asks for — that clears the launch's redaction floor.
///
/// The floor is the launch's own ([`crate::sandbox::redact::MIN_LEN_DEFAULT`], moved by `[redact]
/// min_len`) — the same value a wire injection is held to — and it is here for the same two
/// reasons: a short value peppers the output with placeholders whose positions give it away, and it
/// matches text the command legitimately printed. A spelling below the floor is declined out loud:
/// the command still receives the credential, and output that carries one while looking substituted
/// is the trap this warning exists to prevent.
///
/// Applied per spelling, where a wire injection applies it to the credential as a whole. An
/// encoding can be longer than what it encodes, so a plaintext under the floor can still have a
/// spelling worth watching for, and here that spelling is kept.
pub(super) fn credential_needles(
    secret: &crate::config::TaskSecret,
    plaintext: &str,
    min_len: usize,
) -> Vec<SecretNeedle> {
    let mut needles = Vec::new();
    for bytes in secret.encode.variants(plaintext) {
        if bytes.len() < min_len {
            crate::diag::warn(&format!(
                "one spelling of the credential for `{}` is too short ({} bytes, under the \
                 {min_len}-byte `[redact] min_len` floor) to substitute out of this task's output \
                 safely; the command still receives it, and that spelling is not substituted if it \
                 reaches the output",
                secret.var,
                bytes.len()
            ));
            continue;
        }
        needles.push(SecretNeedle::named(&secret.var, bytes));
    }
    needles
}

/// Read one credential host-side, trying its sources in order. The first that yields a non-empty
/// value wins; a later one is a fallback. Reuses the session's resolver layer, so `env://`,
/// `file://`, `sops://` and every installed resolver plugin work in a task exactly as they do for a
/// wire injection — one source path, no second implementation.
fn resolve_secret(
    secret: &crate::config::TaskSecret,
    config_root: &Path,
    bwrap: &Path,
    brokers: &[super::broker::Reachable],
) -> Result<String, String> {
    super::egress::resolve_chain(&secret.sources, &secret.var, config_root, bwrap, brokers)
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
mod smoke_tests;

#[cfg(test)]
mod tests;
