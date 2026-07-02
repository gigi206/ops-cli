# `ops` (bwrap) — architecture skeleton

> Blueprint for the new `ops` (bubblewrap substrate + daemonless nix). Synthesizes
> the feasibility study ([`bwrap-spike-2026-06-14.md`](bwrap-spike-2026-06-14.md)) and the
> threat model + decisions
> ([`bwrap-threat-model-and-binds.md`](bwrap-threat-model-and-binds.md)) into
> Rust modules, CLI surface, and milestone ordering.

## 1. The pipeline (overview)

```
  config (global + project)
        │   ← trust gate (content hash, direnv model; untrusted ⇒ security fields ignored)
        ▼
  tool resolution  ── mise + nix (daemonless, sandbox=false, pinned nixpkgs)
        │
        ▼
  ┌──────────────────────────────────────────────┐
  │   SandboxSpec   (THE single audit point)       │   ← the policy engine (mode A/B) produces it
  └──────────────────────────────────────────────┘
        │
        ▼
  bwrap assembler  (binds + env + FHS + namespaces + network)  →  argv  (PURE function of the Spec)
        │
        ▼
  launch: exec bwrap, hand over the TTY
```

**Keystone: `SandboxSpec`.** A **declarative and pure** struct that describes
everything the sandbox exposes (binds, env, store, namespaces, holes, cmd). The
entire upstream **produces** it; the assembler **consumes** it. Security invariant:
**only the Spec constructor adds exposure; argv generation is a pure function of
the Spec.** ⇒ the security review has **a single surface** to audit.

## 2. Rust modules

| Module | Role | Reuses current code? |
|---|---|---|
| `cli/` | clap surface + dispatch | adapts `src/cli.rs` |
| `config/` | parse + global/project layering (symmetric schema), validation | **adapts** the existing layering machinery |
| `trust/` | trust gate: **hashing of security fields**, store of validated hashes, re-prompt on change (direnv); gating of security fields for an untrusted project | **extends** `src/trust.rs` |
| `store/` | provisions the **user-owned daemonless store** (relocated static nix) + the **shared flat store, ro at consumption / rw during provisioning** (overlay dropped), daemonless nix invocation (`NIX_REMOTE=`; provisioning builds with the build sandbox ON, outside the cage); **trust-gated provisioning** (untrusted ⇒ no input-addressed local builds) — §7.4 resolved | new |
| `provision/` | resolves declared tools/packages → store paths via **mise+nix**; mise-nix bridge; **nixpkgs pinning** for untrusted | **adapts** the mise-nix bridge (lua) |
| `sandbox/` | **the core** — assembles the `SandboxSpec` then the bwrap argv | new |
| ↳ `sandbox/spec.rs` | the `SandboxSpec` struct + its invariants | new |
| ↳ `sandbox/policy.rs` | mode A/B × trust → which holes are open (the matrix from §5 of the threat model) | new |
| ↳ `sandbox/binds.rs` | zones 0/1/2; TOCTOU canonicalization; **synthetic** `/etc/passwd`+`group`; FHS userland (loader+libs) | new |
| ↳ `sandbox/env.rs` | env zone: `--clearenv` + allowlist + secret injection (trusted config only) | new |
| ↳ `sandbox/net.rs` | network policy (share/unshare; future allowlist hook) | new |
| ↳ `sandbox/argv.rs` | final construction of the bwrap argv (pure) | new |
| ↳ `sandbox/launch.rs` | launch bwrap (see "As built" below — two models, by terminal policy) | adapts `src/run/` |
| `session/` | **session registry** (no daemon → on-disk registry): list of active sandboxes, "2nd terminal in the same env", **GC** of per-project `$HOME` + stale store generations/gcroots | new (replaces `status.rs`/`clean.rs`) |
| `app/` | app definitions (claude/gemini/…): which tool, **which secrets required** (declared trusted), which mode | **adapts** `src/app/` + `apps.toml` |
| `doctor/` | prerequisites (**userns**!), store health, nix version | **reorients** `src/doctor.rs` |
| `platform/ term/ util/ download/` | unchanged (download serves to fetch the static nix / assets) | keep |

**Disappearing**: `src/build.rs` (image build), `src/nerdctl.rs`, the OCI
runtime wrapping; `clean.rs` + `status.rs` → merged into the **`session/`** module
(GC of per-project `$HOME` + stale store generations + session listing).

> **As built — `launch.rs` has two models, not one (the "exec-replace" sketch was
> incomplete).** They are selected by `terminal: TerminalPolicy` (§3):
> - **`ops run` — exec-replace.** Non-interactive: ops execs bwrap and is
>   replaced by it; the command inherits the real stdio and its exit status
>   becomes ops's. Spec is `NewSession` (`--new-session`). Do not "simplify"
>   `shell` into this.
> - **`ops shell` — pty supervisor.** Interactive: ops stays alive, opens a pty,
>   launches bwrap with the *slave* as controlling terminal (`login_tty` → the
>   inner shell has job control), keeps the *master* (so the launching terminal
>   is unreachable), puts the real terminal in raw mode, and relays bytes both
>   ways. Spec is `PrivateTty` (omits `--new-session`; see §3). Empirically
>   required: `--new-session` `setsid`s without `TIOCSCTTY`, so it kills job
>   control even under a pty. Named gaps: terminal restore is RAII (covers
>   return/`?`/panic, **not** `SIGTERM`/`SIGHUP`); window size is set once
>   (dynamic `SIGWINCH` is a follow-up). Implemented in raw `libc`
>   (`openpty`/`login_tty`/`termios`/`poll`) — no new dependency.

> **As built — `session/` is the daemonless registry; `ops ls` lists it.**
> Shipped as a single file (`src/session.rs`) for now; it grows into the dir when
> GC lands. Each sandbox writes a record under `<data>/sessions/`. With no daemon,
> a record is a **liveness-validated hint** — never trusted to be removed:
> `Registry::list` re-checks each one and prunes the dead, so a crash/`SIGKILL`
> self-heals. Liveness is the `(pid, start_ticks)` pair (start time from
> `/proc/<pid>/stat`, which survives `execve`), defeating pid reuse;
> `kill(pid,0)` is only a pre-filter (`ESRCH`/`EPERM` ⇒ dead), the **start-time
> match is decisive**. Records are written atomically (temp-then-rename, dir
> `0700`) and the path field is hex-encoded so a non-UTF-8/newline path round
> trips. Both launch paths register: `ops run` (the Mode-B agent path) persists
> its record and is reclaimed by liveness pruning after it execs away; `ops shell`
> holds a `RecordGuard` that unlinks on exit. The record stores the **canonical**
> project root — the same identity `binds.rs` derives the per-project runtime id
> from — so the registry and the on-disk runtime never disagree (GC consumes this
> in M5). **"2nd terminal in the same env" needs no live-namespace join** (that
> would require a long-lived holder = a daemon): the per-project runtime is
> deterministic, so a second sandbox in the same project shares its persistent
> `$HOME` — multi-session is free. **Deferred to M5:** GC of per-project `$HOME` +
> stale store generations, and an `ops attach <id>` ergonomic.

> **As built — `doctor` decides the boundary by a real launch, not a stand-in.**
> The userns check is now a live `bwrap` smoke (`src/sandbox/smoke.rs`): it feeds
> the real `to_argv` to `bwrap` and reads `/proc/self/status` from inside. A
> launch reporting `CapEff=0` + `NoNewPrivs=1` proves the namespace is
> capability-bearing more conclusively than the `unshare` stand-in could —
> bubblewrap cannot nest its namespaces on a cap-stripped one. The stand-in
> (`probe_userns`) is **demoted, not deleted**: it stays the fast gate the launch
> path uses (no subprocess per `ops run`) and the failure classifier. On a failed
> smoke it attributes the cause — a capability-bearing namespace + a failed launch
> means the engine is at fault (surface `bwrap`'s stderr), not the boundary. The
> smoke binds host `/usr` (userland-independent hardening, so it neither needs nor
> touches nix or the store) and runs in a throwaway temp dir cleaned on drop, so
> `doctor` stays read-only on the host. The canonical minimal-hardened spec lives
> in `smoke.rs` and the test asserts hermeticity (host `$HOME` absent) on it.

> **As built — the trust gate ships recording-first (`trust/` before the loader).**
> `src/trust.rs` + `src/config/safety.rs` land the gate's *recording* side
> (`ops trust`/`untrust`/`trust --show`) ahead of any config parsing, because the
> trust marker hashes the **whole file** (the direnv model), so it needs no
> schema: a marker under `$XDG_STATE_HOME/ops/trusted/` holds a SHA-256 of the
> file's bytes, keyed by its canonical path, and any edit re-arms it
> (Trusted/Untrusted/Changed). Hashing a parsed "security-fields subset" was
> rejected — it would couple trust to the schema and force a canonical
> re-serialisation (a footgun); whole-file is the safe superset of "a
> security-relevant change re-prompts". The hash is cryptographic by necessity
> (the runtime-id `DefaultHasher` is forgeable, unfit for a trust boundary), which
> is why `sha2` is the rewrite's first non-`libc` dependency. The **safety gate**
> refuses a config that is not a plain, owner-owned, non-world-writable regular
> file and gates the **open descriptor** (`fstat`) whose bytes are then read and
> hashed, so the validated metadata and the consumed bytes are the same inode. The
> store dir's **absolute-path requirement** is a security control: a relative base
> resolves against the cwd, so a cloned repo could ship its own marker and
> pre-approve itself. The *consumption* side — the loader that parses, layers
> global/project, and **gates** an untrusted project's security fields (apply free
> fields, drop security fields, warn, never hard-fail) — is the next step; it owns
> the env reserved-key denylist and the structural-env/structural-mount precedence
> that make the deliverable's "*safely*" true.

> **As built — config layering + gating (`config/`), `ops config` shows the
> result.** The loader's policy core (`config::resolve`) is **pure** and
> matrix-tested: the global `ops.toml` is **trusted by location** (safety-gated,
> never marker-gated) and honored in full; the project `.ops.toml` is layered on
> top and **gated by its trust verdict**. `env` is a *free* field — applied from
> any project; `binds` is a *security* field — applied only from a **trusted**
> project, dropped (with an actionable, `Changed`≠`Untrusted` warning) otherwise.
> The env **denylist is untrusted-only**, *not* reserved-always: a reserved-always
> list would re-narrow the schema for trusted projects, which the symmetric-schema
> decision (threat-model §6/§10) forbids — a trusted config overriding `PATH`
> harms only its own sandbox (out of scope). Its contents mirror **glibc's
> `AT_SECURE` set** (`LD_*`, `GCONV_PATH`, `GLIBC_TUNABLES`, `LOCPATH`, `NLSPATH`,
> `RESOLV_HOST_CONF`, `HOSTALIASES`, `BASH_ENV`/`ENV`/`IFS`) plus the structural
> userland ops owns (`HOME`/`PATH`), because the threat it answers is the same one
> `AT_SECURE` answers: an untrusted project silently reconfiguring the execution
> environment of the user's *later* (Mode-A) sessions and trusted tools — not the
> Mode-B agent, which already runs arbitrary in-cage code. `load` is **infallible**
> — absent, unsafe, unparseable, or un-trust-checkable all degrade to a warning and
> a dropped layer (never a hard fail on an attacker-controlled file) — and the
> verdict is taken on the **exact bytes parsed**, so the trust decision and the
> applied content are one inode.
>
> The resolved config reaches the sandbox through `launch::build` (covering both
> `run` and `shell`). Env precedence: the structural `HOME`/`PATH`/`LD_LIBRARY_PATH`
> are emitted first and the config env is **upserted** over them, so a *trusted*
> override wins (an untrusted one has already lost its reserved keys). Bind
> resolution — absolute-only, canonicalized, missing dropped, de-duplicated by
> canonical path (last declaration wins) — lives in `config::load`, **not** the
> launch, so `ops config` advertises the *effective* binds and cannot drift from what
> the launch binds. A bind is **read-only by default**, or **read-write** with the
> table form `{ path = "...", mode = "rw" }` (mapped to bwrap's `--bind`); a
> read-write bind over one of ops's own control-plane roots (the data/engine, trust,
> or config directory) is forced read-only. Config binds are emitted **before** the
> structural mounts, so a colliding one is shadowed and can never displace `/nix`, the
> synthetic `/etc/passwd`/`group`, the loader, or the project — whatever its mode.
>
> **Known limitation (non-blocking, trusted-only): config binds interact with
> structural mounts by path *nesting*, and prepend resolves only *exact-dest*
> collisions.** A config bind that is a **descendant** of a structural dest (e.g. a
> bind under `/tmp`) is silently shadowed by the later tmpfs — fail-closed, but
> `ops config` may list it while the launch drops it. One that is an **ancestor**
> (e.g. binding `/etc`) leaves the synthetic identity overlaid on top yet exposes
> the rest of that directory (`/etc/shadow`) — trusted-only self-sabotage, which
> the threat model (§1) puts out of scope. Both are recorded, not gated; the
> eventual hardening is to warn when a config bind dest nests with a structural
> mount dest.

> **As built — the base userland moved into ops's own store (M3.1), on a rolling
> channel pinned as data-dir state.** `fhs::resolve_userland` no longer realises
> the base userland (glibc/gcc/bash/coreutils) from the host `/nix`; it
> **provisions it into ops's user-owned store** via `store::provision` (daemonless
> `nix --store … build --out-link <gcroot> --print-out-paths <pinned>#<attr>`,
> sandbox on), each output rooted under `<data>/gcroots/base/`, and binds *that*
> store read-only at `/nix`. The pinned reference is **not baked into the binary**:
> `store::nixpkgs_ref` resolves the rolling default channel (`nixos-unstable`)
> **once** via `nix flake metadata` and records the revision in
> `<data>/nixpkgs.lock`, read *before* nix is ever invoked. So the catalogue is a
> rolling-distro-style snapshot — fixed between explicit upgrades, **decoupled from
> ops binary updates** (an update cannot move tool versions; a nix-free test using
> a bogus nix path guards the early return). `--print-out-paths` reports the
> *logical* `/nix/store/…` path that resolves inside the sandbox; its host-side
> backing (a bind *source*) is the *physical* path under the store root, so
> `Userland` carries logical paths for `PATH`/loader/shell and physical paths for
> the store and loader binds (`store::physical_path`). `doctor`'s smoke is **not**
> migrated — it binds host `/usr` and is userland-independent, so it stays fast and
> store-free. Known consequence: a project's *first* launch must reach the binary
> cache to populate the store (the §7.4 "ops owns its store" tradeoff). The
> configurable channel override, the per-project lock, and `ops upgrade` are the
> rest of M3.2/M3.3 — see [[m3-provisioning-design]].
>
> **As built — declared `[packages]` reach the sandbox PATH (M3.2a), trusted-only
> for now.** A project (or the global config) names tools as
> `name = "<nixpkgs attr>"`. The layering in `config::resolve` stays **pure and
> drops nothing for trust**: it key-merges `packages` and stamps each
> `Package { name, attr, trusted }` with its source layer's trust (global is always
> trusted by location). The admission decision is **deferred downstream** to
> `sandbox::packages::admit`, the one place that can weigh a tool against the work
> it would build — so M3.2b's build-vs-fetch gate (which needs nix) changes a single
> predicate, not the pure layering. M3.2a admits **trusted-only** (the conservative
> slice, mirroring `binds`; M3.2b re-admits an untrusted tool that needs only a
> signed-cache *fetch*). `packages::provision` realises each admitted tool via
> `store::provision(…, marker = "bin")`, rooting it under
> `<data>/gcroots/projects/<id>/<name>` (the same per-project identity the runtime
> home uses, via `binds::project_runtime_id`, so M5 GC reclaims them together), and
> **prepends** the resulting `bin/` to the sandbox `PATH` ahead of the base userland
> (a declared tool wins a name collision; `/bin/sh` and the loader are wired by
> absolute path, so prepending never weakens them). A *withheld* (untrusted) tool
> only warns; an *admitted* tool that fails to realise is a **hard failure naming
> the attribute** — a declared tool is a stated requirement, unlike a best-effort
> bind. `nixpkgs_ref` is resolved **once** in `launch::prepare` (a new `Prepared`)
> and threaded to both the base userland and package provisioning, so the M3.2c
> channel override plumbs in one place. `ops config` shows the declared set with
> each tool's trust verdict **without realising anything** (network-free, so it
> cannot reflect M3.2b's build-vs-fetch outcome — an accepted relaxation of the
> binds anti-drift rule; provisioning stays out of `config::load`).
>
> **As built — a `nixpkgs` override pins the whole sandbox to one channel (M3.2c).**
> A **security** field `nixpkgs` (trusted-only, like `binds`) overrides the channel a
> launch resolves against: a branch/channel (`nixos-23.11`) or a 40-hex revision under
> `NixOS/nixpkgs` (charset-validated; arbitrary forks/flake-refs are a later additive
> feature). A per-project pin pins the **whole** sandbox — base userland **and**
> tools — from **one** effective channel (`project pin ?? global override ?? default`).
>
> The first cut pinned the **tools only**, leaving the base on the global channel, on
> the theory that each tool's closure is self-contained. It **crashed** for a
> cross-channel pin: `hello: … glibc-2.42 … undefined symbol __tunable_is_initialized,
> version GLIBC_PRIVATE`. The cause is the very `LD_LIBRARY_PATH` this module exports
> for *foreign* binaries — it points at the **base** glibc, and nixpkgs binaries use
> `DT_RUNPATH`, which the linker searches *after* `LD_LIBRARY_PATH`. So a tool pinned
> to a different glibc loads the base `libc.so.6` under its own (different) loader and
> skews on the `GLIBC_PRIVATE` ABI between ld.so and libc. The closure does not save
> it. One channel per launch keeps base == tools == `LD_LIBRARY_PATH` glibc, which is
> the only structurally-safe option short of a foreign-only library path that nix
> tools ignore (a nix-ld-style decouple; M1-level, deferred — the future path that
> would let base and tools diverge).
>
> So `launch::prepare` resolves **one** reference and feeds it to both
> `resolve_userland` and `packages::provision`. Base gcroots are keyed by revision
> (`<data>/gcroots/base/<rev>/`), so each channel roots its own base while same-pin
> projects share one copy; a pinned project downloads its own base closure (only
> pinned projects pay — the no-pin default still shares the global base). The lock is
> **source-aware** — two lines `<source>\n<rev>` — so changing the source re-resolves
> while an unchanged one stays fixed (a legacy single-line bare-rev lock reads as the
> default channel); without this the field would be inert against an existing lock. A
> global override uses the shared `<data>/nixpkgs.lock`; a trusted project pin uses a
> per-project `<data>/projects/<id>/nixpkgs.lock`, consulted **only** when a current
> pin is supplied, so a dropped or now-untrusted pin falls back to the global channel
> rather than reusing a stale per-project pin. `launch::prepare` loads the
> configuration once (infallible, network-free) before resolving, since the field
> chooses the channel; `ops config` shows the effective source (project pin / global /
> default) without resolving a revision.
>
> User-facing consequence of one-channel (the mirror of the bug above): a pin also
> sets the glibc that *foreign* binaries get — **pin an old channel, get an old
> glibc**, so a prebuilt/downloaded binary needing a newer glibc fails with a
> symbol-version error. Working as designed; the nix-ld decouple is the eventual fix.

> **As built — `ops upgrade` rolls the channel forward; `doctor`/`config` show the
> locked revision (M3.2d).** Versions never move on an ops binary update — only an
> explicit `ops upgrade [all|nix]` does (`all` covers every managed channel; today
> that is just nix). It is **context-aware**: it re-resolves the source the current
> directory tracks and rewrites **that** lock — a trusted project pin's per-project
> lock, otherwise the global one. This is the only way a project pinned to a *channel*
> (`nixos-23.11`) advances within it; global-only would freeze it forever. A project
> pinned to a *revision* refreshes to itself — a well-defined no-op (`is_pinned_revision`
> distinguishes it so the report says "nothing to roll", not "already latest"). An
> untrusted/changed pin is dropped upstream, so `upgrade` rolls the global channel and
> surfaces the config warning explaining why. It needs nix (to resolve) but **not** the
> sandbox boundary — it only rewrites a lock.
>
> The "which source, which lock" decision is extracted to **one** place,
> `sandbox::effective_lock_target(cwd, layout, cfg) -> store::LockTarget`, routed by all
> three consumers — the launch (`.resolve`, lock-reusing), `upgrade` (`.refresh`,
> force-re-resolve + report old→new), and `ops config` (`.locked_revision`, display) —
> so the lock `upgrade` writes is provably the lock a launch reads (no drift). `doctor`
> is host-level (no project context), so it reads the **global** lock straight from
> disk and shows its recorded `<source> @ <rev>` verbatim — accurate-to-disk, *not*
> config-aware: a global override set but not yet resolved still shows the prior source
> until the next launch/upgrade.
>
> Lock writes are **atomic** (temp + `rename`), prompted by the "what if two `ops
> upgrade` race?" question: a concurrent reader (another launch resolving, or a second
> upgrade) sees the old lock or the new one, never a half-written file; a failed
> resolution returns *before* the write, so it never truncates a known-good lock. Two
> upgrades racing settle on a last-writer-wins of two *valid* revisions (no `flock` —
> serialising would only avoid a redundant metadata fetch; the next upgrade reconciles).
>
> **As built — trust composes over the `.ops.toml` *and* a sibling mise file (M3.3a,
> the prerequisite for the mise front-end).** A project may declare tools in a mise
> file (`.mise.toml`/`mise.toml`), which is attacker-controlled and drives host-side
> resolution once provisioning lands — so the mise path is **trusted-only**, and trust
> must be the single authority over *both* declarative inputs. `ops trust` now hashes
> the `.ops.toml` **and** every sibling mise file together (an unambiguous filename-
> tagged, length-prefixed framing), so editing *either* re-arms the gate; the recorded
> hash stays byte-identical to the single-file hash when no mise file exists, so nothing
> already trusted churns. The verdict is computed on the same composed bytes in the
> loader (`config::read_project`) and in `ops trust --show` (`trust::state`), so the
> three never diverge. Every input is read through the same safety gate as the
> `.ops.toml`: a present-but-unsafe mise file is **unverifiable**, so it fails closed —
> `ops trust` refuses to record, and the loader/`--show` report `Untrusted` rather than
> trust a file they cannot read. `ops config` shows a `mise:` line — the discovered
> file(s) and whether they would be honored (`trusted` / `withheld: <reason>`) — without
> running mise, nix, or the network.
>
> Two decisions lock in here. (1) **Anchored on the `.ops.toml`**: a mise file is hashed
> and honored only beside one (the trust marker is keyed by the `.ops.toml` path); a
> mise file with no `.ops.toml` is not honored and `ops config` surfaces the no-op as a
> warning rather than leaving it silent. Project-root-anchored trust (for mise-only
> projects) is a later, additive option if the friction proves real. (2) **The set
> folded into the trust hash ≡ the set a later stage authorizes mise to read** (via
> `MISE_TRUSTED_CONFIG_PATHS`). This is the binding contract the mise-provisioning step
> must honor: mise's own discovery reaches beyond the project root
> (`.config/mise/config.toml`, env-specific `mise.<env>.toml`, parent-directory and
> user-global configs), so authorizing mise to use its default discovery — or trusting
> the whole project — would let a tool entry in an *unhashed* file reach resolution
> without re-arming trust. Provisioning must pass mise **exactly** the files
> `mise_files_for` hashed, and `MISE_CONFIG_NAMES` must grow only in lockstep with that
> authorized set. (As built — M3.3d.2a: that set now covers mise's full *same-directory*
> discovery — `mise.local.toml`, `.mise.toml`, `mise.toml`, `.tool-versions` — so a tool
> pinned in `.tool-versions` or overridden in `mise.local.toml` is hashed and honored;
> only the out-of-project reaches above stay excluded.)
>
> **As built — the mise engine is provisioned via nix and driven from ops's store
> (M3.3b, glibc-independent scaffolding for the mise front-end).** `sandbox::mise`
> realises the `mise` attribute into ops's own store (never the host's mise) and runs
> it from there. Running a relocated-store binary host-side needs care: a nix binary
> hard-codes its interpreter and library paths under `/nix/store/…`, which on the host
> live under ops's store root instead — so the driver runs mise inside a minimal
> bubblewrap that binds ops's store at `/nix`, the same mechanism the sandbox uses for
> its userland, applied to a tool ops runs itself. The mount set is empirical (a live
> `mise --version`): `/nix` read-only, `/proc`, `/dev`, a `/tmp` tmpfs, and one
> read-write bind — the private mise home.
>
> Two properties are born with the driver. (1) **mise tracks the global channel, not a
> project's pin.** It runs in its own relocated-store view, so the one-channel rule
> that forces a sandbox's base and tools onto a single glibc does not reach it (the
> engine is not loaded next to the project's foreign binaries). Keying mise to the
> global channel — `provision(nix, layout, nixpkgs)` takes the reference as a
> parameter, and the caller resolves the **global** `LockTarget`, never `prepare`'s
> effective (possibly project-pinned) reference — gives one shared engine per channel
> revision (`<data>/gcroots/mise/<rev>/`) rather than a fresh copy per distinctly-pinned
> project, and still hands a project pinned to an old channel a current engine to drive
> provisioning. (2) **It never mutates the host.** `HOME` and every `MISE_*_DIR` are
> redirected under ops's data directory (`<data>/mise/`, owner-only), the environment is
> `--clearenv`'d and rebuilt from only the keys mise needs, the network namespace is
> unshared and `MISE_OFFLINE=1` (provisioning the engine and running it offline needs no
> connectivity — a later, online step toggles this for nixhub), and the cwd is pinned to
> the private home (not the launching cwd, which does not exist inside the root, and
> which would otherwise feed mise's config discovery). The private home being the **only**
> writable mount is the structural no-host-write guarantee — asserted on the pure argv,
> proven live by a run that writes solely into ops's data directory. The provision +
> driver are reserved for the env/tool mapping that consumes them next, exercised live by
> the module's integration test.
>
> **As built — a trusted project's mise `[env]` maps into the sandbox (M3.3c, the first
> consumer that reads a project mise file).** `sandbox::mise::resolve_env` runs `mise env
> --json-extended` over the project's mise file(s) and folds the result into the sandbox
> environment (`[tasks]` and tool/`PATH` resolution stay out — the substrate/workflow
> line, and the glibc-gated `[tools]` step is later). The increment's whole point is that
> **mise sees exactly the authorized inputs**, on two fronts:
>
> - *The file set.* mise's own discovery reaches beyond the project root (a
>   `.config/mise/config.toml`, env-specific files, parent and user-global configs). So
>   the driver binds **only** `trust::mise_files_for` — each read-only under
>   `/project/<name>` — runs mise from there with `MISE_TRUSTED_CONFIG_PATHS` naming
>   exactly those, and exposes nothing else: the minimal root has no `/etc/mise`, no
>   parent dirs, no unhashed sibling. The **mount layout** is the containment, not a mise
>   flag.
> - *The bytes.* The files are materialized from the bytes trust validated at config load
>   (carried on `MiseConfig.files`, read once through the safety gate), into an owner-only
>   staging dir that sits **outside every writable mount** (a sibling of the project's
>   writable home, like the synthetic identity). So mise reads precisely the hashed
>   content and has no writable alias to rewrite it — closing the trust→read window the
>   same way the `.ops.toml` path already does.
>
> Extraction is by **provenance**: `--json-extended` tags each variable with the `source`
> file that set it, and the driver keeps a variable only when its source is one of the
> bound files. A variable mise merely echoes — notably `PATH` — carries no source and is
> dropped, so the sandbox's own `PATH` is never disturbed and a value pulled from an
> unhashed file (say a dotenv directive) could never ride along. The launch wires this
> trusted-only: it resolves the **global** channel for the engine (never `prepare`'s
> pinned reference), and a withheld (untrusted/changed) mise file only warns while a
> trusted `[env]` that fails to resolve is fatal — like a declared tool that cannot
> realise. Precedence is structural < passthrough < mise `[env]` < `.ops.toml [env]`.
> Proven live end-to-end: `ops run` exposes the var only once the project is trusted, and
> an unhashed sibling never contributes.

## 3. The central struct (sketch)

```rust
struct SandboxSpec {
    mode:       ActorMode,        // Interactive (A) | Agent (B, default)
    trust:      TrustTier,        // Untrusted (default) | Trusted
    workdir:    PathBuf,
    binds:      Vec<Bind>,        // { src, dest, Ro|Rw } — the only source of FS exposure
    store:      StoreLayout,      // shared flat store, ro at consumption
    env:        EnvPolicy,        // { clearenv: true, allowlist, injected_secrets }
    fhs:        FhsUserland,      // { loader, lib_paths } — 100% nix userland
    net:        NetPolicy,        // Shared{blocks} | Isolated | Allowlist(future)
    namespaces: NsPolicy,         // pid: REQUIRED, user, ipc, uts, mount…
    holes:      Holes,            // { gui: None|Wayland|X11, ssh_agent, container_socket }
    cmd:        Vec<String>,
}
```

Invariants checked at construction: `namespaces.pid == true`; no bind outside the
project-root/store/synthetic for `Untrusted`; `env.clearenv == true`;
`holes.container_socket == false` if `mode == Agent`.

> **As built (the sketch above is the target; this is the shipped subset).** The
> keystone landed as a minimal, fail-closed slice of the sketch. The shipped
> `SandboxSpec` is `{ workdir, mounts: Vec<Mount>, env: Vec<(String,String)>,
> net: NetPolicy, terminal: TerminalPolicy, cmd: Vec<OsString> }`, with two
> deliberate departures that *strengthen* the sketch — do not "reconcile" the
> code back toward the sketch:
>
> - **The pure-removal hardening is not a field.** The cleared environment, every
>   namespace (incl. pid), dropped capabilities (`--cap-drop ALL`) and
>   `--die-with-parent` are emitted **unconditionally** by `to_argv`, not carried
>   as toggleable `NsPolicy`/`clearenv` state. An unhardened sandbox is therefore
>   **unrepresentable**, not merely invariant-checked — the stronger fail-closed
>   stance. Verified live against real bwrap: the generated argv yields
>   `CapEff = CapBnd = 0`, `NoNewPrivs = 1`, host `$HOME` absent, environment
>   rebuilt from empty.
>   - **Exception — `--new-session` is conditional, by necessity.** It is
>     *session establishment*, not a pure removal, and it conflicts with an
>     interactive terminal: `--new-session` `setsid()`s without `TIOCSCTTY`, so
>     the sandbox gets **no controlling terminal and no job control even under a
>     pty** (proven empirically). So `terminal: TerminalPolicy` carries the
>     choice and `to_argv` emits `--new-session` only for `NewSession` (the
>     default, used by `ops run`). `PrivateTty` omits it because the pty
>     supervisor (`ops shell`) establishes the session itself and holds the pty
>     master; the *launching* terminal stays unreachable either way, so the
>     security intent is preserved by a different mechanism. `exec`-replace
>     refuses a `PrivateTty` spec (defense in depth — it has no pty to offer).
> - **`mounts` is the single FS-exposure field.** `store` and `fhs` are *not*
>   separate Spec fields; the constructor (M1.2) resolves them **into** `Mount`s,
>   so `to_argv` stays a dumb, pure serializer (the smallest possible argv audit
>   surface) and "the mounts are the only source of FS exposure" is literally
>   true.
>
> Deferred fields re-enter with their consumers: `mode`/`trust` and
> `holes`/secret-injection at config+trust (M2) and the policy engine (M4); `net`
> already carries `Shared | Isolated` (the egress allowlist is M6). One follow-up:
> `SandboxSpec` derives `Debug`, so once secrets are injected into `env` (M4) the
> `env` field must be redacted in that `Debug` impl.

## 4. CLI surface

| Command | Effect | Mode |
|---|---|---|
| `ops shell` | interactive dev shell in the project sandbox; `mise activate` (via `--rcfile`) puts the project's activated tools on PATH | A |
| `ops run -- <cmd>` | runs a command in the sandbox; the agent's activated mise tools are on PATH via the shims dir | A |
| `ops mise <args>` | runs mise in the open cage; the agent self-equips `nix:` tools into the project's store. `ops mise use [-g] nix:<pkg>` installs **and activates** (auto-on-PATH in later launches, no repo mutation with `-g`); a bare `ops mise install` installs only (reachable via `mise exec`) | B (default) |
| `ops app <name>` | launches a packaged app (claude/gemini/…); the mode is **declared by the app** | B (default) |
| `ops install <pkg>` | installs a tool for the project (ops-mediated provisioning into the shared store) | — |
| `ops trust` / `ops untrust` | manages trust (content hash, re-validation) | — |
| `ops config …` | views/edits the layered config | — |
| `ops test net <url>` | tests a URL against the resolved egress allowlist and names the rule that allows or denies it (no launch); `ops test <kind>` is the diagnostic family (filesystem/Landlock later) | — |
| `ops doctor` | checks prerequisites (**userns**), store health | — |
| `ops self-update` | updates the binary | — |

## 5. Milestone ordering (the DAG)

| M | Title | Content | Deliverable |
|---|---|---|---|
| **M0** | Prerequisites + store decision | `ops doctor`: **userns absent → hard-fail with remediation, NEVER a silent fallback** (proot = no security boundary); **store mechanism resolved & de-risked (§7.4): shared flat store, ro-consume / rw-provision, build-sandbox ON outside the cage ✓, concurrent provision-rw vs consume-ro ✓, gcroot+GC ✓, trust-gated provisioning (untrusted ⇒ no input-addressed local builds)** | productized doctor **+ store decision locked (§7.4)** |
| **M1** | Minimal sandbox | `SandboxSpec` + `binds.rs` (zones 0/1/2) + FHS userland + the **free bwrap hardening** (`--clearenv`, all namespaces, `no_new_privs`, `--cap-drop ALL`, `--new-session`, same-uid) + **`session/` (registry, 2nd terminal)**; `ops shell` isolates the host. Also: **`doctor`** — replace the userns *proxy* probe with a real bwrap smoke run through this argv builder. Seccomp + Landlock-FS land at M4 ([security-stack](bwrap-security-stack.md) §9) | usable shell, Mode A |
| **M2** | Config + trust | global/project layering; content-hash trust gate (direnv); gating of untrusted fields | `.ops.toml` drives the sandbox **safely** |
| **M3** | Tool provisioning | mise+nix bridge; declarative packages; **ops-mediated provisioning (store rw) via an inside→outside install channel** (the agent requests, ops provisions — `/nix` is ro at consumption, so the agent cannot `nix install` itself); pinned nixpkgs | reproducible tools |
| **M4** | Apps + **Mode B** | app definitions; policy engine (A/B × trust → holes); least-privilege secret injection; **the seccomp denylist (incl. `io_uring`/`AF_UNIX`) + Landlock-FS enforcement** ([security-stack](bwrap-security-stack.md) §3–4). ⚠️ **ships the flagship with the confidentiality hole OPEN until M6** (injected API key + open network = possible exfiltration, cf. threat-model §1) — mitigate by landing the **credential-injection proxy** (security-stack §6) here, so the agent never holds the key | **`ops app claude` = the differentiator** |
| **M5** | Parity holes + GC | GUI (Wayland); container socket **Mode A only**; ssh-agent; **GC of per-project `$HOME` + stale store generations** (`session/`) | opt-in conveniences + housekeeping |
| **M6** | **Network policy / allowlist** | netns layer + filtering (nono/greywall); metadata/localhost blocks → allowlist | **closes the confidentiality hole — LAST** |
| **M7** | Hardening (later) | subuid tier; Landlock file ACL; cgroups/DoS limits | opt-in tiers |

Rationale: **M1** quickly delivers something usable; **M4** delivers the
differentiator; **M6** closes confidentiality last (decision made).

## 6. Cross-cutting invariants
- **`SandboxSpec` = single audit surface**; argv = pure function of the Spec.
- **Default-deny** everywhere (FS, env, network later).
- **`--unshare-pid` always** (same-uid is only safe with it).
- **Untrusted config never touches the security fields.**
- **Store ro at consumption, rw only during ops-mediated provisioning** (no overlay); installs route through ops, never free agent writes to a ro `/nix`; per-project state = profile + a **plain** `$HOME` dir (cf. §7.4).

## 7. Design questions (item 4 resolved; 1–3 still open, to settle with the user)
1. **Config noun model.** [[noun-inheritance-model]] locks
   `image → container → app` — **obsolete** (no more image or container).
   Likely replacement: `profile`(userland/base tools) → `sandbox`(runtime:
   binds/env/net/mode) → `app`. To be redefined.
2. **CLI verb for agents.** `ops app <x>` with mode declared by the app
   (proposed) vs an explicit `ops agent <x>` that makes posture B visible.
3. **How ops embeds nix.** Static nix binary **embedded** in the ops asset,
   or **downloaded** at bootstrap (base closure from a binary cache /
   cachix)? Impacts the asset size and the first `ops doctor`.
4. **Store mechanism — RESOLVED: single shared flat store + trust-gated
   provisioning ("shared-only"). De-risk closed.**

   **Decision:** a **single shared flat store**, mounted **read-only at
   consumption** and **read-write only during ops-mediated provisioning**; the
   **overlay (base+upper) is dropped**. Per-project mutable state lives in the
   **profile (gcroot) + a per-project `$HOME`** — both **plain** writable dirs,
   never an overlay (an overlay would reintroduce the same-`upperdir`-twice
   breakage that got the overlay store rejected in the first place).

   **Proven live** (this kernel, host store mounted ro, nothing written to it):
   - a store binary + its closure execs through a ro `/nix` — consumption needs
     **no write** to the store;
   - a ro bind **defeats same-uid overwrite** (`EROFS` on both write and `chmod`,
     even as the owning uid) — the **consumption-side** poison vector is closed;
   - two concurrent ro-`/nix` sandboxes coexist — multi-session is free.

   **Why shared-flat over the alternatives** (the trilemma the overlay
   rejection left behind):

   | Mechanism | disk dedup | anti-poison isolation | multi-session |
   |---|---|---|---|
   | shared flat store (naive) | ✓ | ✗ | ✓ (nix db locks) |
   | per-project flat store | ✗ (574 MB × N) | ✓ | ✓ |
   | base+upper overlay | ✓ | ✓ | ✗ (same upperdir twice) |
   | **chosen: shared flat, ro-consume / rw-provision + trust-gate** | ✓ | **policy** | ✓ |

   The shared flat store closes **consumption-side** poison (the agent at
   runtime, via the ro bind). The **provisioning-side** residual — a locally
   built, **unsigned** path reused across projects — is closed by **policy**, not
   by a second store: with `require-sigs = true`, **cache-substituted paths are
   signature-verified → safe to share**; the only unsigned paths are **trusted**
   local builds (the user vouched for the project). For **`[packages]`** an
   **untrusted** `.ops.toml` provisions **nothing** (M3.2a): a tool's deliverable is
   its `bin` output, which is **input-addressed**, so the substitution-vs-FOD
   distinction is *moot* for a tool — it is either already in the signed cache (a
   pure substitution) or needs an input-addressed build. Letting an untrusted
   project pull *cache-resident* tools (a `nix build --dry-run` that admits when
   nothing builds locally) was weighed and **deferred**: it adds **no** security
   over `ops trust` (a signed tool is content-verified either way), so it is pure
   ergonomics and packages stay a **trust-gated** security field for now — reopened
   only if the friction proves real. The **substitution + hash-verified FOD**
   allowance is the eventual policy for a future **`sources`** field, where
   *fetching* (not a tool) is the point: a `fetchurl`/`fetchFromGitHub` FOD lands at
   a path bound to its declared `outputHash`, so its content cannot be poisoned;
   there, enforced by the same `nix build --dry-run` preflight, "substitutions only"
   *would* wrongly reject safe FOD fetches. Package / source selection is therefore
   a **trust-gated** security field. The per-project store for unsigned untrusted
   builds (the "hybrid") is **deferred** — it adds a second store root, GC across
   both, and loses dedup (574 MB × N); it can be added later without repainting
   the module if untrusted from-source ever becomes a requirement.

   **De-risk checklist — all green** (measured daemonless on a user-owned
   `mktemp` store; reproducible scripts + numbers in
   [`bwrap-store-derisk-2026-06-15.md`](bwrap-store-derisk-2026-06-15.md)):
   1. **(load-bearing) ✓** provisioning runs nix with the **build sandbox ON**
      (`sandbox = true`) *outside* the cap-dropped cage (caps available): a
      from-source build completes `rc=0`. That the sandbox actually *engaged* is
      shown by the isolation signature — an under-declared raw `derivation{}`
      first failed inside it with `ENOENT` (its builder's `ld-linux` unmounted,
      since the sandbox exposes only the declared closure); had the sandbox been
      silently off, that build would have *succeeded* via the real store. The
      spike's `sandbox = false` constraint is thus specific to the *inside* of
      the cage; provisioning runs outside it, so locally-built paths are built
      hermetically — this shrinks the residual from "real" to "narrow".
   2. **✓** provision-rw **concurrent** with a live consume-ro on the same store
      is safe: `nix store optimise` hardlinked 863 files *under* a sandbox
      actively exec'ing a store binary in a loop — zero exec failures, output
      intact, `nix store verify --all` clean (hardlink-via-rename preserves the
      open inode; `auto-optimise-store = true` is on in the host nix.conf).
   3. **Decided (not an experiment).** Logically established — only unsigned
      local builds are the residual — so the response is the trust-gate above:
      refuse untrusted local builds rather than route them to a per-project
      store.
   4. **✓** profile/gcroot handoff + GC: a gcrooted path survives `nix store gc`
      while an unrooted one is collected; one physical copy of a shared tool
      serves all projects (dedup); dropping a project's gcroots makes its
      **exclusive** paths collectable while **shared** ones survive — the store
      stays bounded and is cleanable **per project** (the `session/` GC model,
      M5, plus standard nix policy — `--delete-older-than`, max generations,
      GC-on-project-removal — for stale generations).

   **mise-nix bridge fit (M3).** The repo's bridge (`mise/lib/`) already *is*
   this model: it provisions via `nix build --no-link --print-out-paths`
   (`flake.lua`), registers a **gcroot per installed tool** (`install.lua`
   `register_gc_root`), and is built for **multiple workspaces sharing one store
   volume** with a **per-workspace profile gcroot** (`NOTICE`). Adapting it is M3
   work, not an M0 store change: (a) **relocate the gcroots** — they are
   hardcoded for the multi-user daemon store (`/nix/var/nix/gcroots/mise`,
   `…/per-user/<uid>/`); drive nix with `--store $OPS_STORE` + `NIX_REMOTE=` and
   reroot them under ops's store; (b) the bridge's `nix build` is where check 1
   and the refuse-untrusted-local-build policy apply; (c) the bridge's **non-nix
   backends** (`vsix`/`vscode`/`jetbrains`/`neovim`) fetch artifacts *outside* the
   store — in the bwrap model they are restricted or treated as in-sandbox
   installs, never host provisioning (settle at M3/M4).
