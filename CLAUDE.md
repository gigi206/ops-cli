# ops-cli — repo conventions (bwrap rewrite)

> ⚠️ You are on the **`bwrap`** branch: the clean rewrite of `ops` onto a
> **bubblewrap + daemonless nix** substrate. The old conventions (bash `ops.sh`
> release cutting, container image builds) **no longer apply** here.

## What `ops` is (this branch)

`ops` is a **sandbox launcher** (a static Rust binary) that runs tools — including
**encapsulated AI agents** — inside a bubblewrap sandbox where they can install a
project's full dependency set via **single-user daemonless nix** **without
mutating the host OS**. It is **not** an OCI container manager: no
docker/podman/nerdctl, no image build.

Reference class: nono.sh / greywall.io / landrun (sandboxes), **not**
flox/devbox/devenv (mere env managers that isolate nothing).

## Branch topology

| Branch | Contents |
|---|---|
| `main` | `v1.18.0` — bash/container era, frozen, pushed |
| `container` | snapshot of the **OCI** Rust v2 (reference / cherry-pick reusable modules: config, trust, mise-nix bridge) |
| **`bwrap`** | **working branch** — clean from `v1.18.0` + the rewrite |

## Design documents (read before coding)

1. [`docs/bwrap-spike-2026-06-14.md`](docs/bwrap-spike-2026-06-14.md) — feasibility, proven live.
2. [`docs/bwrap-threat-model-and-binds.md`](docs/bwrap-threat-model-and-binds.md) — threat model + bind layout + decisions.
3. [`docs/bwrap-architecture.md`](docs/bwrap-architecture.md) — Rust modules, CLI surface, milestones (M0→M7).
4. [`docs/bwrap-security-stack.md`](docs/bwrap-security-stack.md) — the enforcement building blocks (bwrap/seccomp/Landlock/cgroups) and when each lands.

## Security model (the essentials)

- **Two actor modes**: **A** = interactive shell (user, semi-trusted); **B** =
  autonomous agent (actions untrusted) → **B is the default**.
- **Hard requirement**: **capability-bearing unprivileged user namespaces**.
  Without them there is no security boundary → `ops doctor` **hard-fails**, never
  a silent fallback (proot = emulation = no boundary). Note: on restricted
  Ubuntu 24.04+, `unshare(CLONE_NEWUSER)` can succeed yet be stripped of
  capabilities — `doctor` checks for the capability-bearing case specifically.
- The sandbox runs **as the host uid** (same-uid) → **the bind layout IS the
  security control**; `read-only` protects integrity, not confidentiality (a
  secret must be **absent**, not mounted ro).
- **Enforcement building blocks** (the consensus of serious agent sandboxes;
  details in a dedicated doc): bwrap (all namespaces + `no_new_privs` + drop all
  capabilities + `--new-session`) · **seccomp** denylist · **Landlock** (FS) as
  defense-in-depth · **cgroups v2** limits (anti-DoS). Network (egress allowlist)
  is handled **last**.
- An **untrusted** project `.ops.toml` cannot touch security-relevant fields
  (binds/network/hooks/sources); the trust gate is the validation, bound to a
  **content hash** (direnv model).

## Build / verify

```bash
cargo build
cargo run -- doctor          # prerequisite preflight (userns, bwrap)
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

## Conventions

- **Never** a `Co-Authored-By:` line in git commits (user's global preference).
- **The project itself is in English** (code, comments, docs, CLI output).
- Code comments are **self-contained**: no references to a process ("Task N",
  "M1", "SEC-002"), to `ops.sh`/the container code, or "matches X". Reword to
  stand alone.
- **Always write the cleanest possible code**, following coding and security
  best practices: least privilege, fail-closed, validate inputs, no unsafe
  shortcuts. The security model above is the baseline, not the ceiling.
- **Every increment ships with tests** (unit + integration, green), is then
  **reviewed by the advisor**, and finally **validated with the user** before
  moving to the next — incremental, collaborative cadence, no barreling ahead.
- **Current status: M2 done; M3 in progress (M3.1 + M3.2a + M3.2c + M3.2d done;
  M3.2b SKIPPED; M3.3 in progress — M3.3a + M3.3b + M3.3c done; M3.3d in progress
  — M3.3d.1 (nix-ld) + M3.3d.2a (widen the honored mise files) done; M3.3d.2b
  (`[tools]` driver) in progress — the nixhub resolver + host-side provisioning of
  declared `nix:` tools landed (trusted-only); the per-project writable store layer
  shipped and is **WIRED — the cage's `/nix` is a read-write bind of the
  per-project store by default (the Mode-B posture inversion, 2b.3.2b.1)**;
  **nix now lives in the cage so the agent self-equips (2b.3.2b.2) — offline
  reuse from the seeded base proven and in-cage HTTPS to the default cache already
  works (M3.4 only makes its TLS hermetic)**; the **concurrency/flock settlement
  landed (2b.3.3) — no ops lock: atomic per-path placement + nix's own store lock
  carry concurrent same-project seeds, proven by a concurrent-seed smoke**; and
  **`ops mise` passthrough shipped (2b.4) — the agent self-equips a project's `nix:`
  tools live with `ops mise install nix:<pkg>` in the open cage (mise carried in every
  cage, the embedded `nix:` backend plugin registered per launch), proven e2e + a
  network smoke**; and **tool activation shipped (2b.5) — a tool the agent *activates*
  (`mise use [-g] nix:<pkg>`) is auto-on-PATH in later launches: the mise shims dir on
  PATH for `ops run` (mise's documented non-interactive mechanism) and `mise activate`
  via a synthetic `--rcfile` for `ops shell` (its interactive mechanism), proven e2e +
  pty + a network smoke**; and **the network increment (M6 / "network last") is under
  way: its safe first slice shipped — a trusted-only `network = "none"` posture (the
  `NetPolicy::Isolated` an empty netns) gated like `binds`/`nixpkgs`, plus a live
  P-vs-B spike that LOCKED the egress architecture on **Model B** (deny-by-construction,
  pending the user's confirmation)).**
  **M3.3d.2b — direction LOCKED with the user** (a long design discussion):
  project mise `[tools]` prefixed **`nix:`** (e.g. `nix:nodejs = "20"`) are the
  exact-pinned dev toolchain; ops resolves each to the nixpkgs revision that shipped
  it and realises it through its own store. The part after `nix:` **is** the nixhub
  package name (no `node→nodejs` table). The agent self-equips per project; the chosen
  enforcement model is the **open cage** (agent runs `mise install` live, with network
  — full now, per-project egress allowlist deferred à la nono.sh/greywall.io), with two
  non-negotiables: the **shared store stays immutable** (the agent writes a per-project
  layer, never raw rw on `/nix`) and **opening is never settable by an untrusted
  project**. This reverses M3.2a's trusted-only `[packages]` and reopens the M3.2b skip
  (the friction is now the central use case); the residual accepted is host-side nix
  eval + egress, not the binaries (pinned signed catalogue, and the agent already runs
  arbitrary code in-cage → more tools is not an escalation). Open-by-default inverts the
  documented "Mode B default, untrusted" — to record consciously when the cage opens.
  Ramp: **the nixhub resolver first** (this brick), then a per-project store layer, then
  opening the cage, then `ops mise` passthrough.
  **M3.3d.2b resolver** (`src/sandbox/nixhub.rs`): the de-risked new core — turning a
  project's `nix:` `[tools]` into pinned nixpkgs references, with **no new dependency**.
  Two pure halves plus one impure step: parse the `nix:` tools out of the authorized
  mise files (`[tools]` TOML — string/table/array version shapes — and `.tool-versions`
  lines; first declaration of a token wins across files; non-`nix:` and malformed tokens
  reported, never dropped), and select a release's pin from nixhub metadata (filter by
  the host `system`, then `latest`/`stable` newest, exact match, or newest extending the
  request at a `.`/`-` boundary so `20`→`20.x`). The one network step rides **nix's own
  fetcher** — `nix eval --impure --raw --expr 'builtins.readFile (builtins.fetchurl
  "…/v2/pkg?name=<pkg>")'` → `serde_json` → `(commit, attr, version)`; the package name
  is charset-validated so it can never escape the nix string, and the commit (40-hex) and
  attribute are validated before they reach a flake reference. **Wired** (`provision`
  in `nixhub.rs` + `launch::mise_tools` + `ops config`): a trusted project's declared
  `nix:` tools resolve and realise through the existing `[packages]` path
  (`store::provision`, per-project gcroots under `…/nix-tools/<pkg>`, bin dirs prepended
  ahead of `[packages]` so a pinned dev tool wins, hard-fail naming a tool that cannot
  be realised); a non-`nix:` backend or an untrusted project only warns. Resolution is
  cached in a per-project `tools.lock` (tab-framed `pkg/version/system/commit/attr/
  resolved`, atomic temp+rename, corrupt line self-heals) so nixhub is queried once, not
  per launch. Trusted-only for now — the open-cage relaxation (the agent self-provisions;
  the M3.2a/M3.2b reversal) is the deliberate next step. Proven live e2e (`ops run -- jq`
  from a trusted `nix:jq` project → `jq-1.8.1` from ops's store, lock written; untrusted →
  withheld) + **176 tests green**. **Advisor-reviewed** — it caught a real ordering bug
  the green suite structurally could not: nixhub lists releases **newest-first**, but
  `select_release` took `.last()` for `latest` (and the unit fixture was sorted ascending,
  encoding the same assumption), so `latest` silently picked the *oldest* build (an
  earlier e2e's `jq-1.6` was the tell). Fixed to `.first()` + forward scan, the fixture
  flipped to nixhub's real descending order so the test now fails on the bug, confirmed
  live (`latest` jq now resolves `1.8.1`). Also from the review: `ops config` lists
  ignored non-`nix:` tools (so a `node = "20"` absent from PATH is explained), and the
  lock's monotonic growth (no prune on tool removal) is noted for a later upgrade/GC.
  **M3.3d.2b.2/.3 — per-project writable store + THE FLIP** (`src/sandbox/projectstore.rs`
  + `binds::NixMount`): the substrate the open cage stands on. The model is **Option C**
  — each project gets its **own real nix store**, seeded from the immutable shared store
  (an overlay, Option A, was spiked, shipped as a mechanism, then **deleted** when the
  concurrency requirement — multiple cages of the same project installing at once — ruled
  it out: overlayfs forbids two live mounts sharing one upper/work, and the SQLite nix DB
  does not overlay-merge; see [[m3-2b2-store-layer-decision]]). The seed is
  **reflink-or-copy via `FICLONE`** (CoW where the FS supports it, full copy on ext4):
  each base path is a **physically independent inode**, so an in-cage same-uid write hits
  only the project's copy — a hard link would instead share the inode and let that write
  **poison the shared base for every tenant** (demonstrated live, the reason hardlink was
  rejected). The seed is **closure-scoped** (`nix-store -qR` over the declared roots → copy
  exactly that closure; the one closure list is the source of both the copy and the
  `nix-store --dump-db <closure> | --load-db` registration → a self-contained, `--verify`-able
  store) and **atomically placed** (copy into a unique temp sibling → `rename`, so a crash
  or a concurrent same-project seed never leaves a partial at a real store-path name).
  **WIRED and default-on (2b.3.2b.1, user-chosen over folding into the next step):** the
  cage's `/nix` is now a **read-write bind of the per-project store** instead of a
  read-only bind of the shared store — **the Mode-B posture inversion, by default**. The
  shared store is no longer in the cage; an agent that self-equips writes into the
  project's own store. This is **never a configurable field**, so an untrusted project
  cannot keep the shared store mounted or widen its access. The roots the seed copies are
  **surfaced explicitly** from the provisioners (`Provisioned { bins, roots, warnings }`
  from `packages`/`nixhub`; `Userland.base_roots` built from the same provisions as the
  loader/lib/bin sub-paths so none is forgotten; `launch::collect_roots` unions
  base ∪ `[packages]` ∪ `nix:` tools, unit-tested with teeth) — *not* reconstructed by
  stripping sub-paths, since an incomplete root set silently defeats reuse (the cage would
  re-fetch the missing closure and a "build succeeded" test would pass anyway). `build_spec`
  takes a `NixMount { src, writable }` (the old `Userland.store_dir` is gone); the nix-ld
  shim is kept bound read-only from the shared store at `/lib64` (one file, EROFS-safe —
  a read-only bind blocks the same-uid write); `nix-store` is now a hard launch prereq.
  **Write-isolation is proven live through the wired rw bind** (an in-cage
  `echo > /nix/POISON` lands in the project copy while the shared `nix/store` stays
  byte-identical), alongside: the base userland runs *entirely* from the seeded store
  (shared absent from `/nix`), every base root is present, `nix-store --verify` passes,
  and an unseeded shared package is *absent* (the completeness check has teeth). **Cost
  measured:** a project's first launch adds the base closure copy (~400 MB on ext4, ~free
  on a CoW FS); a warm launch is ≈0.33 s total, of which the seed (closure query + db
  top-up, copying nothing) is ≈0.05 s — soft, so default-on was accepted (a later
  optimisation: skip `load_db` when nothing was placed). **Three residuals consciously
  accepted:** the cost lands now while the agent-self-equip payoff is the next step;
  concurrent same-project seeding is now live in production (the M1.4 "2nd terminal"
  feature) but is only *proven* in the concurrency step; and a same-uid agent can overwrite
  a base path in *its own* seeded store (self-harm, the shared store untouched, single
  tenant). **184 tests green**, three consecutive full runs stable; fmt/clippy clean.
  *(A pre-existing tmpfs-inode flake was fixed earlier: `TmpDir` and `tests/run.rs` place
  throwaway stores on the repo disk under `target/test-tmp`, not the `/tmp` tmpfs whose
  fixed inode budget several concurrent nix smokes exhausted — which also matches
  production, where the store lives on disk.)*
  **M3.3d.2b.2.2 — nix in the cage (the open-cage payoff)** (`src/sandbox/fhs.rs` +
  the env denylist): the base userland now carries **nix itself**, so an agent in the
  open cage **self-equips** — it builds and installs a project's toolchain into the
  project's own writable store (the cage's rw `/nix`). `resolve_userland` provisions the
  `nix` attribute beside glibc/gcc/bash/coreutils/nix-ld; nix's root joins `base_roots`
  (so its closure is seeded) and its `bin` joins the base PATH (so the agent reaches it
  by name). **The config surface is empty — ops sets no `NIX_CONFIG`:** a live spike found
  nix's *compiled* defaults already work in-cage — `store = auto` resolves to the local
  `/nix` (the per-project store; `NIX_REMOTE` unset), a **fresh** derivation **builds
  offline** from the seeded base (substituters emptied), and — the surprise that retired
  the advisor's `sandbox=false`/`filter-syscalls=false` prior — **`sandbox = true` and
  `filter-syscalls = true` both succeed** because the cage permits nested namespaces and
  carries no syscall filter yet. **That "no config" result is load-bearing on "no seccomp
  yet"** (recorded in a code comment + memory): nix's build sandbox needs
  `unshare`/`clone(NEWUSER|NEWNS)`, `mount`, `pivot_root`, and `seccomp()` itself, so a
  later cage-level seccomp denylist must allowlist those — or force nix's
  `sandbox`/`filter-syscalls` off — or it silently breaks in-cage builds. Forward-looking
  safety: `NIX_CONFIG`/`NIX_USER_CONF_FILES`/`NIX_CONF_DIR` (the complete nix-config
  injection set, verified against nix's docs) join the **untrusted-only** env denylist —
  an untrusted project's `[env]` must not aim the user's later Mode-A nix at an attacker
  substituter with `require-sigs` off (in-cage it is no escalation, but the same Mode-A
  protection as `NIX_LD`/`LD_*`). **Proven live with teeth** (one smoke): nix is reached
  by name (so it is on the cage PATH), a novel derivation's output is **absent before /
  present after** an offline build (substituters empty, shared store not even bound → the
  success can only be a real local build from the seeded bash+coreutils), the build output
  lands in the **per-project** store, and the shared store stays byte-identical; the
  discriminant — a sibling derivation whose only input is a package realised into the
  shared store but **left out of the seed** — **fails offline**, so "present" means
  "seeded", not "anywhere in the shared store". **Scope (corrected by a live probe — the
  advisor caught an over-claim):** offline reuse from the seed is delivered *now*, and the
  network layer for fetching *new* tools **already works in-cage today** — `nix-prefetch-url`
  over HTTPS to `cache.nixos.org` succeeds with **no** `NIX_SSL_CERT_FILE` set, because the
  cage already `--ro-bind-try`s the host's `/etc/ssl` (nix's default certificate path) and
  `/etc/resolv.conf`. What **M3.4** actually adds is making that TLS **hermetic** — ops ships
  its own cacert so trust no longer depends on the host having a CA bundle at `/etc/ssl` —
  not "enabling" the network (binary substitution uses the same curl/TLS path, so it works on
  any host that has a CA bundle). The one genuinely-deferred piece is `experimental-features`
  for *flake-driven* mise (the `nix:` plugin path, 2b.3.4/2b.4), which the stable CLI this
  increment uses does not need. **Cost re-measured:** adding nix grows a project's first-launch seed by ≈69 MB / 57
  store paths on ext4 (the closure unique to nix — sqlite/boost/curl/libseccomp — over the
  base; ~free on a CoW FS) — the same "cost now, self-equip payoff" residual already
  accepted. **One residual newly named** (deferred, within the accepted self-harm class):
  an in-cage `nix-collect-garbage -d` could delete the seeded base paths mid-session (they
  carry no gcroot *in the project store*) — re-seed heals it next launch, the shared store
  is untouched, single-tenant self-harm; gcrooting the seed in the project store is the
  later mitigation. **185 tests green** (the teeth'd smoke is the net new one), three
  consecutive full runs stable; fmt/clippy clean; advisor-reviewed (the reconciliation
  above) + spike-validated live.
  **M3.3d.2b.3.3 — the concurrency/flock settlement** (`src/sandbox/projectstore.rs`):
  the verdict is **no lock of ops's own**. Two sandboxes of the same project can seed
  at once because the seed is already concurrency-safe by construction — proven, not
  reasoned: (a) each store path is placed by **atomic temp+rename**, so a lost rename
  race is simply a redundant copy discarded (the winner's identical, content-addressed
  path is already in place), and (b) concurrent `nix-store --load-db` merges serialise
  on the project database's own **SQLite locking** (the registration integrity the smoke
  proves). The broader case — a seed racing a live in-cage build, or two agents building
  into one project store — rests on nix's **concurrent store-access guarantee** (that
  database locking plus the per-store-path `.lock` files a build takes), nix's domain not
  ops's, **not exercised here** (the deferred line below); it is the reason Option C / a
  real per-project store was chosen over the overlay, which has no such guarantee. An ops
  flock would only serialise copies the atomic placement already makes safe, and could not
  cover the live builds anyway. The rename-race branch (`Err(_) if dest exists → discard +
  Ok`), previously test-unreached, is now exercised: the placement was **extracted to
  `place_atomically`** (a named unit with the race doc) so the lost-race branch (a
  pre-existing non-empty dir → ENOTEMPTY → Ok, winner kept, temp discarded) and the
  hard-failure branch (ENOENT, dest absent → propagate, temp discarded) are
  **deterministically** unit-tested. The headline is a **live concurrent-seed smoke**:
  4 threads seed the same project from the same roots into a **fresh** project store
  (so all race on first-creating the database — the sharp interleave), then the proof
  has **teeth on *registration*, not on-disk presence** — a bad concurrent `--load-db`
  merge manifests as a path copied but never *registered* (a dangling/missing ref),
  which `--verify` (it iterates only registered paths) and a file-existence check
  cannot see; so the test asserts the project DB's reference graph (`nix-store -qR`)
  **equals** the shared store's closure, then `--verify --check-contents` passes, no
  `.tmp-` leaked, and the shared store is byte-identical. **Cost named** (accepted perf
  residual, not a correctness gap): without serialising, N concurrent *cold* seeds each
  copy the closure before their rename, so the losers' copies are wasted I/O (bounded by
  the base closure, only on a project's first cold launches; a per-project seed lock is
  the future optimisation). **Scope stated, not narrowed (deferred line):** a seed racing
  a live build into the *same* store — and two agents building into one store, arguably the
  headline open-cage concurrency — rests on nix's concurrent store-access guarantee (DB
  locking + per-store-path `.lock` files), not separately exercised here; the one test that
  would *prove* it (two threads each `nix build` a distinct trivial derivation into one
  seeded project store, assert both succeed + `--verify`) is a deferrable follow-up, nix's
  domain rather than ops code. **188 tests green** (the two `place_atomically` unit tests + the concurrent-seed smoke
  are net new), three consecutive full runs stable; fmt/clippy clean; advisor-reviewed
  (it sharpened the smoke onto registration — the change that makes it prove its own
  claim).
  **M3.3d.2b.4 — `ops mise` passthrough (the open-cage self-equip, shipped)**
  (`build.rs` + `src/sandbox/miseplugin.rs` + `fhs.rs` + `binds.rs` + `launch.rs` +
  `main.rs` + `mise/lib/platform.lua`): the agent self-equips a project's `nix:`
  toolchain **from inside the cage** — `ops mise install nix:<pkg>` resolves the tool
  through nixhub and builds it into the project's **own** writable store, never the
  host. **De-risked by a live throwaway spike first** (the advisor's call — the load-
  bearing unknown was the lua plugin against the relocated store, not the CLI verb):
  the spike proved `mise install nix:jq` works in-cage and surfaced the exact
  ingredients, each found by a *failing* iteration, not by reasoning —
  [`docs/bwrap-mise-incage-derisk-2026-06-18.md`](docs/bwrap-mise-incage-derisk-2026-06-18.md).
  Those ingredients are the design: (1) **mise in every cage** — added to the base
  userland beside nix (user-chosen over on-demand, so an agent self-equips from any
  `ops run`/`ops shell`, not only `ops mise`); provisioned against the **project**
  channel (one-channel rule), seeded, on PATH. (2) **The `nix:` backend plugin is
  embedded in the binary** (`build.rs` walks `mise/` → a `(path, bytes)` table, no new
  dep), staged read-only content-keyed under `<data>/mise-plugin/<hash>/` (atomic
  temp+rename, like the store seed), bound at `/opt/ops/mise-nix-plugin`, and
  **registered per launch** by an *atomic* symlink (`symlink`+`rename`, concurrency-safe
  for the "second terminal" — the advisor caught a remove-then-create race in the first
  cut) at `$MISE_DATA_DIR/plugins/nix`. (3) **Structural cage env** (lowest precedence,
  set by the assembler so it is config-independent): `MISE_EXPERIMENTAL=1` (the `nix:`
  custom-backend gate), `MISE_YES=1` (non-interactive install never blocks),
  `MISE_DATA_DIR` under the writable home, and `NIX_CONFIG=extra-experimental-features
  = nix-command flakes` (the plugin's `nix build` is a flake ref; `extra-` is **additive**
  — it does not touch `sandbox`/`substituters`/`require-sigs`, so the offline base build
  and the "no-seccomp-yet" reasoning hold; this **supersedes** the earlier "ops sets no
  `NIX_CONFIG`" note). All three nix-config-injection keys are already on the
  untrusted-only denylist, so only a *trusted* project could override ops's value (self-
  harm). (4) **The vendored plugin's `which nix` → `command -v nix`** — the hermetic cage
  carries no `which` binary (it is a separate package, not coreutils); nix was on PATH
  the whole time, the probe was wrong. **Open by default** — `ops mise` works whether or
  not the project is trusted (the documented Mode-B self-equip inversion), unlike
  `ops run`'s host-side `nix:` provisioning which stays trusted-only. **Activation
  (the boundary 2b.4 deferred is now CLOSED — see 2b.5 below):** an `ops mise install`ed
  tool **persists** in the project store and `mise exec` resolves it; a tool the agent
  **activates** (`mise use`) is auto-on-PATH in later launches, while a bare `install`
  (not activated) stays reachable only via `mise exec`/`mise which`. **Two-path
  divergence (recorded):** `ops mise install`
  (in-cage lua plugin → `nixhub.lua`) and `ops run`'s host-side `nixhub.rs`→`tools.lock`
  are parallel resolution+realise paths sharing no state — a self-installed tool is not
  in `tools.lock`, not reproduced by a fresh `ops run`, outside `ops upgrade mise`.
  **Latent gap noted for M3.4:** the plugin shells `find` (findutils) on the
  `MiseEnv`/flake path (not the `nix:` install path used here) — the curated-base-
  packages concern. **Proven e2e through the real binary** (`ops mise install nix:jq` →
  `jq-1.8.1`, `ops mise ls`, `ops mise exec` all work; the "not activated" warning
  observed live) + a **network smoke** (`the_cage_self_equips_a_nix_tool_via_mise`:
  an **untrusted** project self-equips jq, the binary runs from the per-project store,
  and the **shared store stays byte-identical** — skip-not-fail when the cache is
  unreachable, the project's first network-dependent test). **193 tests green** (3
  miseplugin unit + the network smoke + the register-concurrency unit are net new),
  fmt/clippy clean; advisor-reviewed (it caught the register race and the NIX_CONFIG
  doc contradiction — both fixed).
  **M3.3d.2b.5 — tool activation (the persistence the user pulled forward)**
  (`src/sandbox/binds.rs` + `src/sandbox/launch.rs`): a tool the agent **activates**
  (`mise use [-g] nix:<pkg>`) is **auto-on-PATH** in a later, separate launch — without
  re-declaring it and without mutating the project's repo. The user's ask was *"je veux
  que ce que l'agent a fait soit persistent"*; the build already persisted (per-project
  store + mise data dir are durable, proven by a two-launch test), so the only gap was
  **activation** (auto-on-PATH), and that is what shipped. It uses **mise's two
  documented activation mechanisms — not a kludge** (verified against mise's docs +
  live): the **shims dir on PATH** (`$HOME/.local/share/mise/shims`) for `ops run`,
  mise's prescribed mechanism for a non-interactive context (it execs the command
  directly, no shell to hook); and **`mise activate`** for `ops shell`, its interactive
  mechanism — bash is started `--rcfile <synthetic rc>`, a static read-only rc bound at
  `/opt/ops/bashrc` that sources `~/.bashrc` (parity: plain bash already reads it) then
  `eval "$(mise activate bash)"`. PATH order is `declared tools > shims > base`; the two
  mechanisms coexist (no warning, activate puts the *real* bin ahead of the shim);
  `mise activate` leaves base tools (`ls`/`nix`) resolvable (it manages PATH, never
  resets it). Decision **(b)** with the user: activation is **local, no repo mutation** —
  the equip verb is `mise use -g` (writes `~/.config/mise/config.toml` under the
  persistent home, never the repo); **reproducible-in-git is the separate, deliberate
  path** (put `nix:` in the repo `mise.toml`, a future skill guides the agent). **The
  install-vs-use seam:** with shims on PATH, a bare `mise install` (no `use`) is *not* on
  PATH — it leaves a shim that errors `No version is set`, pointing the agent at
  `mise use` (mise's own install≠use split, surfaced not hidden). `mise_plugin_src` +
  `shell_rc_src` grouped into `SandboxPaths` (kept `assemble` ≤7 args). **195 tests
  green** (the rcfile-bound unit + the cross-launch activation network smoke are net
  new), fmt/clippy clean; advisor-reviewed (it had me verify the persist claim with a
  two-launch run, confirm base tools survive activate, and correct the stale records);
  proven live (fresh `ops run -- jq` via the shim, pty `ops shell` via activate's real
  bin).
  **M6.0 — the network slice + the P-vs-B architecture lock** (`src/config/` +
  `src/sandbox/launch.rs` + `ops config`): the network increment ("network last")
  opened with its **cheapest, decision-independent slice** — a trusted-only
  `network = "none"` posture — plus a live spike that **decided the egress
  architecture**. The slice: a `network` security field (`"none"` → an empty netns,
  `"shared"` → the host network, the default) gated **exactly like `binds`/`nixpkgs`**
  — honored from the global config (trusted by location) or a trusted project, dropped
  with a warning from an untrusted/changed one (proven both directions: an untrusted
  project can neither cut nor reopen the network). A config-local `NetworkPolicy` enum
  maps to the cage's `NetPolicy` in `launch::net_policy` (the two posture vocabularies
  kept separate — config is the user's, `NetPolicy` is the sandbox's and is where the
  allowlist will grow). **Zero new cage machinery**: `to_argv` already emits
  `--unshare-net` for `NetPolicy::Isolated`, and the live cage-isolation proof already
  exists — the spike's Q5(a) showed `bwrap --unshare-net` yields `lo`-only with curl
  failing, the live endpoint of the resolve→`net_policy`→argv chain. The `network` field
  rides the existing whole-file SHA-256 trust hash for free, so a trusted project cannot
  have its posture flipped post-`trust`. String-now/table-later is forward-compatible (a
  future untagged enum subsumes the bare string). Proven live (`ops config`: untrusted
  `network="none"` → `network: shared` + warning; after `ops trust` → `network: none`)
  + **204 tests green** (schema parse, 6 gating cases, the `net_policy` map, an `ops
  config` integration case), fmt/clippy clean, advisor-reviewed.
  **The P-vs-B spike** ([`docs/bwrap-net-spike-findings.md`](docs/bwrap-net-spike-findings.md),
  throwaway, host pasta — nothing installed): the two egress architectures are **Model P**
  (`--unshare-net` + pasta NAT uplink, then filter) vs **Model B** (empty netns, no uplink,
  the only egress a host-side allowlisting proxy reached over a bound socket — deny-by-
  construction). Evidence **locks B**: (1) **P-attach is impossible unprivileged** (bwrap
  makes its own userns where the host pasta has no `CAP_SYS_ADMIN` → `setns` refused), so P
  is reachable only via **P-inherit** (`pasta … -- bwrap --share-net`), pasta-as-outer-
  process, which is *invasive* — it mangles `ops run`'s exit-status propagation and the
  `ops shell` pty session leadership. (2) **P is fail-OPEN by default** — the cage reaches
  host loopback by two paths + would reach cloud metadata; closing it needs the exact
  non-obvious `--no-map-gw -T none -U none` (the intuitive `--no-splice` is a trap that
  leaves `127.0.0.1` open). (3) **B is fail-CLOSED by construction** — empty netns → no
  route/DNS/metadata/loopback for free, the single bound socket the only egress (proven
  from the *same* cage). (4) **both need the proxy anyway** (pasta can't filter by
  hostname), so P = B's work + pasta topology rework + fail-open; the 6.3 credential-
  injection proxy reuses the same host proxy. (5) curl **and** nix honor `http_proxy`/
  `https_proxy` (Q6), so the two tools that matter for self-equip are already proxy-aware.
  **B's true mechanism is NOT "just a bound UDS"**: it is the Codex pattern — an in-cage
  TCP→UDS forwarder (so tools use `http_proxy=127.0.0.1:PORT`) bridging over the bound
  socket to a host-side **CONNECT allowlisting proxy**. The spike validated the
  *primitives* (empty-netns denies all; a bound UDS bridges to a host proxy; curl/nix
  honor proxy env), **not** the integrated data path — so an **integrated-path micro-spike**
  (a real HTTPS fetch through forwarder→UDS→a real CONNECT proxy, **with teeth — a
  non-allowlisted host must be refused**) **gates the 6.2 build, not the decision**.
  **Security does not depend on the forwarder's integrity** (pure ergonomics — bypassing it
  just talks to the same allowlisting socket or loses egress, fail-closed either way; the
  boundary is empty-netns + the host proxy). **B CONFIRMED with the user (2026-06-18)**, with
  one added requirement: **the default posture must be overridable in the GLOBAL config** (the
  user's open-by-default escape hatch) — already supported, since the global `ops.toml` is
  trusted-by-location and honored in full, so a global `network = "shared"` overrides whatever
  ops's built-in default becomes; an untrusted project still cannot touch it. Open sub-decision
  deferred to 6.2: the built-in default *before* any global override once the allowlist exists
  (likely `"allowlist"` deny-by-default, `"shared"` the escape hatch). The **integrated-path
  micro-spike PASSED** (`docs/bwrap-net-spike-findings.md`, throwaway): the full chain — tool →
  in-cage `socat` TCP→UDS forwarder → bound UDS → a host CONNECT allowlisting proxy — works for
  **both curl and nix**, with **teeth** (an allowlisted host gets HTTP 200 / a real fetch; a
  non-allowlisted host is **actively refused 403 at the proxy**, proven for curl AND nix's 5
  retries; a direct no-proxy fetch fails — empty netns, no route, no DNS). DNS is **host-side**
  in the proxy (`CONNECT host:port` carries the hostname, the cage never resolves → DNS-exfil
  closed too). So the 6.2 build is de-risked. **Allowlist granularities + MITM (user, 2026-06-18):**
  the allowlist must support four granularities — an IP, an exact domain, a domain + its
  subdomains, and an **exact URL** (path-level). A CONNECT proxy only sees `host:port` for HTTPS
  (the path is in the TLS tunnel), so the first three (host-level) are free, but **exact-URL
  needs a TLS-terminating MITM** — ops generates a CA, injects it into the **cage's** trust
  store (never the host's), decrypts/inspects/re-encrypts. **The user chose MITM IN 6.2** (all
  four from the start), accepting that the proxy sees all plaintext (already so for 6.3) and
  cert-pinning tools break. **MITM non-negotiables** (else it *downgrades* security): the proxy
  MUST validate the *upstream* cert against the system CA bundle; the CA private key is
  per-session, owner-only, ideally ephemeral; ops's CA goes only into the cage trust store.
  **MITM micro-spike PASSED** (appended to the findings doc, throwaway): a ~200-line host MITM
  proxy (ephemeral CA via `cryptography`, TLS-terminating via `ssl`) proved (1) **nix fetches
  through the MITM** with ops's CA trusted (the load-bearing unknown — yes; nix's TLS is libcurl
  + the cert bundle, and `require-sigs`/NAR-hash verification is orthogonal to transport); (2)
  curl works (200); (3) **exact-URL/path filtering has teeth** — same allowed host, different
  path → 403 (the capability that justified MITM); (4) host-deny → 403; (5) **upstream-cert
  validation has teeth** — a self-signed upstream is refused with 502 (`UPSTREAM-CERT-REJECT`),
  so the MITM does not downgrade transport. (Bug the spike surfaced for the real matcher: URL
  reconstruction must include the **port**.)
  **6.2a — the allowlist schema + matcher + `ops test net` tester SHIPPED** (`src/allowlist.rs` +
  config + main, 249 tests, advisor-reviewed, live): the user chose a **single list classed by
  syntax**. `[network] mode = "allowlist"`, `allow = [...]`, **`deny = [...]`** — and **deny
  ALWAYS wins** (the user's case: "allow a domain but deny a precise URL or subdomain inside it"
  — e.g. `allow github.com` + `deny github.com/secret`, or `allow *.nixos.org` + `deny
  evil.nixos.org`). The `network` field is `string | table` (serde **untagged**,
  forward-compatible from the `"none"`/`"shared"` string form). The matcher (`Rule` +
  `EgressPolicy{allow,deny}`; `explain` → `Decision{DeniedBy|AllowedBy|DeniedDefault}` names the
  deciding rule, `permits` a bool view) classifies **five** kinds by syntax — IP (literal host),
  exact host (not subdomains), `*.domain` (apex + subdomains, suffix-spoof-safe), a
  **scheme-free `host[:ports]/path` URL** (**exact path by default, or a `/*`-suffixed subtree**;
  same port-set syntax as the host kinds), and **`re:<pattern>` regex** over the whole reconstructed URL
  `https://host[:port]path`. **Regex = the user chose Model 2** (full-URL `re:`) over Model 1
  (host-structured + path-regex): the structured kinds stay **exact/spoof-safe** (`api.github.com`
  never matches `api.github.com.evil.com` nor `myapi.github.com` — the user's explicit
  requirement, tested), while `re:` is unanchored so the author owns anchoring/escaping (an
  unanchored host-regex is the classic bypass). Engine = the **`regex` crate** (new dep,
  user-approved by choosing Model 2; linear-time / **ReDoS-immune** — a real security property in
  a filter). A bad regex → classify error (dropped+warned, fail-closed). **Path semantics
  (user-refined):** a `Url` is **exact by default** (`…/secret` matches `/secret` and its
  same-resource canonical variants `/secret?x`/`/secret/`/`%2f`/`/foo/../secret`, NOT `/secret/sub`)
  and a trailing **`/*`** matches the path and its whole subtree (`…/secret/*` covers `/secret/sub`,
  segment-aware so not `/secretarial`) — no regex needed; `re:` is for query-specific/arbitrary.
  **Port model (user-decided — the deferred "443/80 pinning" is now DECIDED):** each host kind
  (`Ip`/`Host`/`Subdomain`) carries a **port set** (`Ports::{Any, Ranges(Vec<(u16,u16)>)}`). A bare
  entry (`github.com`, `1.2.3.4`, `*.nixos.org`) defaults to the **web ports {80, 443}** — least
  privilege, so `allow github.com` can't be CONNECT-tunnelled to :22. A `:`-suffixed spec pins
  exactly those: a comma list of single ports and/or inclusive **`lo-hi` ranges** (`github.com:443`,
  `internal:8080,9000-9002`, sorted+de-duped), or **`:*`** for any port. A **path rule carries the
  same `Ports` set** (`github.com:443/secret`, `example.com:*/admin`; a bare `host/path` defaults to
  {80, 443}) — `Rule::Url` now holds `ports: Ports`, not a single `port: u16`. **IPv6 handled
  end-to-end:** bare
  (`::1`) at the default ports; **bracketed** with a port (`[::1]:443`, `[2001:db8::1]:*`,
  `[::1]:8080/admin`) so its own colons don't confuse the split — both the host kinds
  (`split_host_ports`) and the path-rule parser (`parse_path_rule`) parse it, and `Display` re-brackets it
  (round-trips, proven live through `ops test net`). **Advisor-caught (same class as the deny-evasion
  hole):** a `Url` host is matched as a **plain string**, but IPv6 has many spellings of one address
  (`::1` == `0:0:0:0:0:0:0:1`), so `deny https://[::1]/secret` was dodgeable by the long form (the
  `Ip` kind was safe — it compares `IpAddr`). FIXED — `canonical_host` normalizes an IP-literal host
  once, on **both** sides (`Request::new` and `parse_url_target`), so every spelling compares equal;
  the fix lands in `Request::new` exactly where the 6.2b proxy will build requests (free for it). The
  fixtures that missed it used the same spelling on both sides — the test now uses *different* ones
  (proven live: `[0:0:0:0:0:0:0:1]/secret` DENIED under `deny [::1]/secret`).
  **No host catch-all (`reject_catch_all`):** there is deliberately no "allow every host"
  entry — a bare `*` host in any scheme-free form (`*`, `*:*`, `*:80`, `*/path`, `*:*/admin`) is
  rejected (dropped+warned) with a message pointing at the posture switch `[network] mode =
  "shared"` rather than the generic "unrecognized entry"/"invalid port"; the bounded `*.domain`
  subdomain wildcard (host `*.domain`, not `*`) is unaffected. The check sits in `classify`
  (after `split_host_ports`) and in `parse_path_rule`; a *scheme*-prefixed `*` (`https://*`) is
  rejected one step earlier by the scheme guard (below). The only allowlist-mode escape hatch
  to all hosts stays `re:.*`; the real "open everything" is `mode = "shared"` (settable only in
  a trusted/global config).
  **Scheme removed from rules (`http`/`https` "serve no purpose" — the user's call):** a rule is a
  *pattern*, not a connection, so it carries **no scheme** — `http`/`https` only ever picked a
  default port the `:port` qualifier already expresses. So a URL rule is the scheme-free
  `host[:ports]/path` (a `/` is what makes it a path rule), parsed by **`parse_path_rule`** (the
  authority goes through the same `split_host_ports`, so paths get the full port grammar; the host
  must be concrete — a `*.domain`-with-path is rejected, use `re:`). An entry that still carries a
  scheme is **rejected** with a pointer to the scheme-free form (fail-closed, never a silent
  mis-parse of `https:` as a host). The distinction is **rule vs request**: a *request* names one
  concrete connection, so `ops test net <url>` and the future proxy keep the scheme (it sets the
  port) via the unchanged **`parse_url_target`** (the *request* parser, now its only caller — no
  longer the rule classifier); the `re:` reconstructed URL stays `https://…` (a stable canonical
  string for regexes, not a protocol claim). No security change — port+path are enforced
  identically; the scheme never enforced the wire protocol (a CONNECT proxy only sees `host:port`).
  Gated trusted-only
  like `binds`/`nixpkgs`; a malformed entry in either list is dropped+warned (fail-closed); `ops
  config` shows allow+deny. **`ops test net <url>`** reports ALLOWED/DENIED + the deciding rule
  (`parse_url_target` + `EgressPolicy::explain`), reflecting the trust gate, no launch/nix/network
  — which also exercises the matcher live through the real binary. **Interim until the proxy:
  `Allowlist` → `NetPolicy::Isolated` (fail-closed) + an honest launch warning.**
  **Advisor-caught deny-evasion hole — FIXED (Option A, user-chosen direction):** a literal-path
  `deny https://github.com/secret` was **dodgeable by the in-cage agent** (it controls the
  request) — `/secret?x=1`, `/secret/`, `/secret/sub`, `%2f`, `/foo/../secret` all sidestepped the
  exact-string deny while `allow github.com` let them through. (Asymmetry: a literal-path *allow*
  fails closed/safe, a literal-path *deny* fails **open** — a real hole, not a footgun; the earlier
  "every gap is a footgun" claim was wrong.) Fix: every request is **canonicalized once** (`Request`
  — percent-decode, resolve `.`/`..`, drop query) so all **same-resource** variants of `/secret`
  reduce to it and the exact deny catches them; a **different** sub-resource (`/secret/sub`) is a
  deliberate user choice — `deny /secret/*` (the user's `*` refinement) to include the subtree.
  Proven live: same-resource dodges DENIED, `/secret/sub` ALLOWED under `deny /secret` but DENIED
  under `deny /secret/*`, `/public` always ALLOWED. **Hard 6.2b invariant recorded:** the proxy
  must canonicalize the live request through the **same** `allowlist::Request::new`, or `ops test net`
  would mispredict — plan a test that drives a request *through the proxy* asserting its verdict ==
  `ops test net`'s. Minors (documented, not fixed — within Model 2's "you own the regex"): a regex
  `re:…:443/…` never fires (`Request.url` omits port 443); the regex path is decoded but **not**
  `.`/`..`-resolved, so a `re:` deny is dodgeable by `/foo/../secret` (a structured `Url` deny is
  not); `ops test net` always exits 0.
  **Before 6.2b: a code-level competitor comparison** (egress, then FS/seccomp/isolation; 6 research
  agents, all repos cloned) confirmed ops's netns→UDS→host-proxy is the **production consensus**
  (Codex CLI, Anthropic `sandbox-runtime` — which uses `socat`, our planned forwarder — nono,
  greywall) and that ops **leads** on path/URL/regex granularity + per-session cage-only CA. It
  surfaced the gaps now folded into the build (SSRF post-resolution IP guard, DNS-rebind recheck,
  per-request re-check, CONNECT==SNI==Host, fail-closed→502) and a concrete M4 seccomp/Landlock/
  cgroups roadmap (denylist not allowlist, the nix-in-cage allowlist carve-out, the broad CA env
  set). Recorded in memory (`network-egress-competitor-comparison`,
  `sandbox-isolation-competitor-comparison`); nono CVE-2026-47128 (no-ns → `systemd-run --user`
  escape) validates ops's all-namespaces + empty-netns.
  **6.2b — the host MITM allowlisting proxy MODULE done** (`src/sandbox/proxy.rs`, **222 tests**,
  advisor-reviewed plan AND implementation, deps user-approved): built **MITM-from-line-one** on a
  **musl-clean** stack — `rustls 0.23` (**`ring`** backend, no aws-lc/openssl), `rcgen 0.13`,
  `webpki-roots 1.0` (verified zero C deps) — its cert core de-risked by a throwaway Rust spike
  first. `Ca` (ephemeral, in-memory key, per-host leaf cache, cage-trust-only) + `CertResolver`
  (mints a leaf per SNI) + `upstream_config` (webpki-roots) + `ProxyCtx` (server cfg with **no h2
  ALPN** → HTTP/1.1) + `serve(UnixListener)` thread-per-conn + `handle_client`. Flow: CONNECT
  (byte-by-byte so the ClientHello survives) → 200 → MITM → one inner request (same BufReader keeps
  the body) → **CONNECT-host == SNI == decrypted Host** (anti domain-fronting) → `policy.explain`
  (**the same canonicalizer `ops test net` uses** = the recorded invariant) → host-side resolve →
  **SSRF guard** (private/loopback/CGNAT refused unless the deciding rule names the EXACT host —
  not a `*.domain`/regex/nix-cache match; metadata/link-local always refused; v4-mapped-v6
  unwrapped) → connect the **checked IP** (no re-resolve) + validate upstream (`complete_io`) →
  reserialize the head with forced **`Connection: close`** + forward + stream back + close (one
  request per tunnel → no path-skip). Fail-closed everywhere: forged/self-signed upstream → 502
  (never downgraded), IP-literal target → deny (no SNI), plain-HTTP absolute-form → reject,
  socket timeouts (slowloris), CL+TE / duplicate CL/Host → 400. **Built-in nix-cache allow-set**
  (`nix_cache_allow`: cache.nixos.org, *.nixos.org, github.com, api/codeload.github.com,
  *.githubusercontent.com, **search.devbox.sh** = the nixhub `NIXHUB_BASE`) unioned into allow
  **regardless of trust** so the untrusted self-equip survives (`union_with_nix_cache`); refined
  empirically + to be shown in `ops config` at wire time. 14 proxy tests (loopback rustls upstream,
  injectable resolver + upstream cfg): happy-path (proves byte-plumbing at both read boundaries),
  denied→403, path-deny-wins→403, forged→502, SNI≠host→421, SSRF private+metadata→403,
  verdict==tester, nix-cache union, **+2 advisor-regression tests** — a forced `Connection: close`
  (a capturing upstream caught a real 30s hang on verbatim forward to a keep-alive upstream) and a
  URL-in-query (caught `contains("://")`, fixed to `starts_with('/')`).
  **6.2c — the egress wiring done** (`src/sandbox/egress.rs` + `fhs.rs` + `binds.rs` + `launch.rs`
  + `config/mod.rs` + `main.rs`, **266 tests**, advisor-reviewed plan AND implementation): the
  Model-B path is wired into a launch under `[network] mode = "allowlist"`. **Forwarder pivot,
  advisor-driven:** NOT a self-exec'd `ops __incage` — the dev binary is **glibc-dynamic** (tests
  run `CARGO_BIN_EXE_ops`) and ops has never run in-cage, so binding a host-glibc ops into the
  hermetic cage is fragile (crashes wherever host glibc > base glibc; nix-ld redirects the loader,
  it does not backfill symbols). The forwarder is **`socat`, nix-provisioned** (ABI-matched to the
  cage glibc by construction) in the **base userland** (beside nix/mise, posture-independent base),
  invoked by absolute store path from a wrapper: `bash -c '<socat> TCP-LISTEN:18043,bind=127.0.0.1,
  fork,reuseaddr UNIX-CONNECT:<bound socket> </dev/null >/dev/null 2>&1 & exec "$@"' _ <cmd…>` —
  the command rides **`"$@"` positionally** (no shell injection, non-UTF-8 argv preserved; only
  ops-owned ASCII goes into the script string) and `exec` keeps it the cage's **PID 2 main
  process**, so `ops shell`'s pty job control is **unchanged**. **Lifecycle de-risked by a throwaway
  bwrap spike first** (the load-bearing claims only exist inside a real pid namespace): job control
  intact (`$-` has `m`, no warning), **no socat lingers** after `ops run -- true` (the default PID-1
  **reaper** tears the netns down — confirmed `--as-pid-1` is *absent* from `to_argv`), 0 zombies.
  **Host lifecycle:** `egress::start` binds a per-launch host UDS (`<data>/egress/proxy-<pid>.sock`,
  listen-before-serve so no first-request race), builds the ephemeral `Ca` + `ProxyCtx`, writes the
  CA **owner-only (0600) outside every rw mount**, spawns the `proxy::serve` thread, and returns the
  cage `Wiring` (binds + env) plus an RAII `Egress` guard (unlinks socket+CA on drop). `build` →
  `(SandboxSpec, Option<Egress>)`; **`ops run` + allowlist supervises** (`run_supervised` =
  `Command::status`, fork+wait+propagate) instead of exec-replacing, because the proxy thread must
  outlive the cage; `ops shell` already supervises (pty) and just holds the guard. `net_policy` maps
  allowlist → **empty netns** (`Isolated`) — the Model-B foundation; the bound UDS (a writable
  `ExtraBind` emitted **after** the tmpfs) is the only egress, the CA a read-only bind at
  `/opt/ops/egress-ca.pem`. **CA injected via the broad set** `CA_FILE_ENV_KEYS` (NIX_SSL_CERT_FILE,
  SSL_CERT_FILE, CURL_CA_BUNDLE, GIT_SSL_CAINFO, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS, PIP_CERT,
  npm_config_cafile — replace not append, since all cage egress is ops-minted under the empty netns);
  **the keys ops *sets* == the keys it protects** — `config::is_reserved_env_key` consumes that one
  const, so they can never drift, and adds the proxy-control keys (`http_proxy`/`https_proxy`/
  `all_proxy`/`no_proxy`, case-insensitive) to the untrusted denylist. **Two advisor fixes applied:**
  (1) ops sets **`no_proxy`/`NO_PROXY` = `localhost,127.0.0.1,::1`** structurally — else an agent's
  own in-cage loopback service would route through the proxy and be 403'd (IP-literal CONNECT reject);
  loopback is intra-cage under the empty netns, never egress, so exempting it weakens nothing; (2) the
  cage proxy port is **18043** (high/uncommon, below the ephemeral range), not 8080, to dodge an
  agent-vs-forwarder port clash. `ops config` shows the **built-in nix-cache allow-set** (so the
  always-on self-equip allowance is never silent). **Honest scope:** this is **wired + unit-tested**,
  NOT yet run integrated *through* ops — the lifecycle spike used host socat in a non-hermetic
  shared-net cage, and the unit tests exercise the pieces (`wrap_command`, `start`, `assemble` extra
  binds, the denylist, the config display); a real `ops run` under a trusted allowlist (proxy serving
  + nix-socat forwarder in the empty netns + exit propagation) is **6.2d**. proxy.rs lost its module
  `#![allow(dead_code)]` (now consumed).
  **6.2d — the egress e2e through ops, proven live AND committed** (`tests/run.rs::
  a_network_allowlist_filters_egress_through_the_proxy`): a **throwaway live smoke** ran the real
  `ops run` under a trusted `network = "allowlist"` first (the user's "smoke first, then formalize"
  call) — and it earned its keep by catching a flaw in the *test*, not the code: the denied probe used
  `https://example.com/` (trailing slash), which `nix-prefetch-url` rejects with "cannot figure out
  file name" **before any fetch** — a refusal for the wrong reason, no teeth. Fixed to a filename'd URL
  (`…/nix-cache-info`) so the proxy's **403** is what actually stops it. The committed test runs the
  real binary (so it exercises the full launch path — `egress::start` + `run_supervised`, which an
  in-crate `build_spec` test cannot), skip-not-fail when the host can't sandbox or the cache is
  unreachable, one project/data so the capability probe seeds the store once: trusted allowlist →
  **allowed** `nix-prefetch-url https://cache.nixos.org/nix-cache-info` returns the **known content
  hash** `15sqg1j6gq…` (proves the whole chain — forwarder bridged the empty netns, nix trusted the
  injected MITM CA, the proxy validated the upstream and relayed the bytes intact); **denied**
  `https://example.com/nix-cache-info` → stderr contains **`403`** (refused at the proxy, a real
  filename so the fetch is attempted); and `sh -c 'exit 7'` → **exit 7** (status propagation on the
  supervised path). Proven live (smoke: allowed 200 + hash, denied `HTTP error 403`, true→0/false→1)
  and green as a committed test (29.6s warm).
  **6.2e — explicit refusal reasons on the proxy (DONE)** (`src/sandbox/proxy.rs`): a
  user-driven slice so the agent can tell *why* a request failed — an explicit policy refusal
  vs a host that does not respond vs a name that does not resolve. Every refusal the proxy
  **itself** issues now carries an **`X-Ops-Egress-Reason`** header (a stable category token) plus
  a short `text/plain` body (the human detail) via a single chokepoint `write_refusal`
  (replacing the body-less `write_status`); a genuine upstream status (a real `404`) is still
  relayed verbatim with no such header. The categories: `denied-default` (no allow rule matched —
  the body echoes only the `host:port` the agent already sent), `denied-by-rule` (a deny rule
  matched — **categorical, the rule text is not disclosed**, so a *global*-config rule the agent
  cannot read in-cage never leaks; `ops test net` is the host-side tool for the deciding rule),
  `ssrf-blocked`, `ip-literal`, `host-mismatch` (421), `bad-request` (400), `method-not-allowed`
  (405), and three on the upstream side — `dns-failure`, `upstream-unreachable`, and
  `upstream-cert-rejected` (`connect_upstream` now returns a typed `UpstreamError` so a down host
  reads differently from a rejected cert; note the cert arm catches any `complete_io` failure, not
  *only* a bad cert — slightly broad, kept). The headline behavioural fix: a **DNS-resolution
  failure for an allowed host is now a clean 502** (`dns-failure`) instead of a **dropped
  connection** (the old `?` on `resolve` left the agent unable to tell a refusal from a transport
  glitch). **No security downgrade** — the category/body echo only what the agent sent or a fixed
  token, never the injected credential, a host-side secret, or a policy rule's text; the in-tunnel
  position means the cert/host-triple/SSRF checks all still gate before any reason is sent.
  **Honest scope** (recorded): the reason is **attached** to every deliberate refusal, but whether
  the agent **surfaces** it is tool-dependent — a raw-HTTP client or `curl -i` shows the header and
  body, while `nix` reports the status code; the coarse status *class* (explicit `403` vs `502`
  unreachable vs relayed `404`) is always available and is the distinction the reasons sharpen. The
  category table is documented in the `proxy.rs` module doc. **268 tests green** (5 existing proxy
  tests gained category assertions + 1 net-new `a_dns_failure_for_an_allowed_host_is_a_clean_502`;
  the 6.2d egress e2e re-ran live at 27.4s exercising the changed denied→403 path), fmt/clippy
  clean, advisor-reviewed (it caught that the prior full-suite "exit 0" was `tail`'s status with
  `tail -40` hiding `run.rs` — re-run with cargo's real exit + the e2e confirmed *ran* not
  *skipped*).
  **6.3a — http-header credential injection (DONE)** (`schema.rs` + `config/mod.rs` + `allowlist.rs`
  + `proxy.rs` + `egress.rs` + `main.rs`; full design `docs/bwrap-secrets-architecture.md`): a
  host-keyed `[secret."host"]` table (`kind="http-header"`, a `from` source, `header`,
  `type=bearer|basic|raw`, optional `prefix`) injects a host-scoped credential into an allowed
  request **host-side, after the verdict** — the plaintext is read in `egress::start` and **never
  enters the cage**, the injection fires only for the concrete destination host (the table key, and
  path), and **strip-and-replace**s any client-supplied copy so ops's value is the only one upstream.
  A security field, gated trusted/global; the host key is restricted to a concrete Ip/Host/Url (reject
  `*.`/`re:`); **CR/LF/NUL rejected** naming the source not the value; only under `mode="allowlist"`.
  **Residual:** an injection-target host that *reflects* the header returns it into the cage — bounding
  egress to the one destination host is the real control, the two tripwires below the backstops. Proven live + a
  committed no-leak e2e (`a_secret_is_resolved_host_side_and_never_enters_the_cage`).
  **6.3b — outbound secret redaction (the exfil tripwire, DONE)** (`config/mod.rs`
  `HeaderShape::needles` + `proxy.rs` `SecretNeedle`/`carries_secret`): the proxy scans each decrypted
  request **head** for any configured secret value and **REFUSES** the request (`outbound-secret`,
  403) — **block, never strip** — so a secret the agent *did* obtain cannot be re-sent verbatim to any
  allowed host. Scanned on the **pre-injection** client bytes (never self-trips on ops's own
  injection), before the verdict. **Head-only by design** (the body is streamed; clean block-not-strip
  would need a buffer cap → fail-closed breaks large uploads, fail-open beaten by padding).
  `REDACT_MIN_LEN=8` (a shorter secret is injected but not redacted, warned loudly).
  **6.3d — response-side redaction (the inbound reflection backstop, DONE)** (`proxy.rs`
  `pump_redacting`/`redact_in_place`): when the response comes from an **injection-target** host — the
  only place a configured secret can re-enter by reflection — the proxy **masks** every verbatim
  occurrence of the value out of the relayed response with an **equal-length run of `*`** (so
  `Content-Length`/chunked framing stay intact, `*` never introduces a CR/LF), streaming-safe via a
  `carry` of the last `max_needle_len-1` bytes (catches a match straddling reads). **Mask, not block**
  (vs 6.3b) because the response also carries legit content the agent needs. **Scoped to
  injection-target responses** (advisor) so the always-on nix-cache lane streams untouched and a
  coincidental match cannot corrupt unrelated traffic. Reuses 6.3b's needles — **zero config/egress
  change, `proxy.rs` only**. **Residual:** corruption-on-collision (masking mutates the stream),
  entropy + the min length mitigate, confined to the one injection-target host. **Honest scope:**
  6.3b + 6.3d bound the *naive verbatim* leak in both directions, but both are byte-exact backstops
  (base64/gzip/chunk-split evade) — the boundary stays empty-netns + the allowlist + the `to`
  bounding. **6.3c (body-borne *outbound*) is deliberately NOT built**: its precondition — the agent
  holding the verbatim value — exists only via a non-verbatim reflection that *also* defeats the byte
  filter, so it would guard an almost-empty set. **307 tests green**, fmt/clippy clean, advisor-reviewed
  plan AND impl (the response-side scoping is its load-bearing fix). **Next:** the secret **resolvers**
  (`sops://`) — the SOURCE layer, distinct from the broker; least-privilege/scoping at the source is
  the real lever against a reflecting host.
  **6.3 secret resolvers + resolver-plugin store (DONE)** (`src/config/` + `src/plugins.rs` +
  `src/stores.rs` + `src/plugin_store.rs` + `src/main.rs`; full design
  `docs/bwrap-secrets-architecture.md`): the SOURCE layer that 6.3a/6.3b left open, shipped as a
  resolver engine, a typed plugin registry, and a remote signed store — all under the graved
  invariant *ops never places a plaintext secret in the cage* (every resolution is **host-side**,
  before the cage). **The schema settled on the host-keyed form** `[secret."host"]` (an array
  `[[secret."host"]]` for several credentials to one host) with a shared `[secret.defaults]`
  (resolver `order` + per-resolver bindings + default `header`/`type`) — superseding the early
  `[[secret]]`/`from_env`/`from_file` sketch. A secret's source is either a verbose `from`
  (one `scheme://locator` ref or a fallback chain) or a terse `key` expanded through the default
  resolver order, optionally pinned `key@resolver`. **(a) Resolver engine** — `from` refs route
  through built-in `env://` and `file://` resolvers (read host-side, the value never bound into the
  cage) with a first-wins fallback chain; **the `sops://` built-in** (`sops://<file>[#<key>]`)
  proves the SOURCE layer is distinct from the http-header BROKER. **(b) Resolver-plugin registry**
  (`src/plugins.rs`) — a plugin declares a `scheme` in a `plugin.toml`; ops discovers + validates it
  and **runs it host-side under bwrap** (the resolver is in the TCB but still sandboxed), so a
  `scheme://locator` `from` ref routes to a third-party resolver without an in-tree engine
  dependency; `ops plugins list|info`, local `ops plugins install <dir>` / `rm <name>`, and an
  **embedded default store**. **(c) Remote signed store** (`src/stores.rs` + `src/plugin_store.rs`,
  the *3d* track) — `ops plugins store add/update/info/list/rm` fetches a git catalogue, verifies it
  with **Ed25519** (`ring`), enforces **anti-rollback** (a monotonic `rev`), caches it, and supports
  **trust-on-first-use** (`store add --trust` pins the key on first sight); `store install <store>
  <plugin>` pins each entry by a frozen **`dir_digest`** (`plugin_store::dir_digest`, the one
  wire-format) and re-verifies it through `verify_entry`; and **`store publish`** is the signer that
  *produces* a signed store — it walks a `plugins/` tree, pins each plugin by `dir_digest`, builds +
  signs a `catalogue.toml`, and writes the four store-root artifacts (the producing counterpart of
  the consuming `add`). The **signer reuses the one `dir_digest`** so signer and verifier cannot
  drift past both green suites; a committed clone e2e reads the published artifacts back through the
  full consumer chain. **Two pieces deferred to an operational step** (need a hosting URL + a
  long-term signing key, confirmed deferred 2026-06-20): the **default-store registration** (an
  embedded pubkey so the default store verifies against a baked key, never TOFU) and its routing
  guard. Honest residuals: (1) a resolver runs **host-side**, so a plugin manifest with
  `network = true` (to reach a Vault/KMS/1Password engine) shares the host network and is **not**
  behind the cage's egress allowlist — accepted because resolvers are in the TCB and an engine
  resolver needs real network; the lever is the trusted resolver set + scoping the secret at the
  source (a `network = false` resolver runs in an empty netns); (2) `publish` digests the
  **working tree**, so an untracked/gitignored file git won't deliver would make a later install
  mismatch — "commit exactly what you publish"; a `git ls-files`-scoped digest is the future
  hardening. Memory: [[secrets-architecture]]. Each sub-increment shipped green + advisor-reviewed
  (plan AND impl) + user-validated per the cadence; **474 tests green** (418 in-crate + 32 config +
  7 run.rs + 17 across the other suites), fmt/clippy clean. The shipping static musl binary links
  with the new C/asm deps via `mise exec -- cargo zigbuild` (zig cc); see `mise.toml`.
  **M3.3d.2a** (`src/trust.rs::MISE_CONFIG_NAMES`): the trust-hashed (and
  later-authorized) mise file set now covers mise's full *same-directory* discovery
  — `mise.local.toml`, `.mise.toml`, `mise.toml`, `.tool-versions` — up from the two
  canonical configs. So a tool pinned in `.tool-versions` or an override in
  `mise.local.toml` is folded into the trust hash (editing it re-arms the gate) and,
  through the existing `mise_files_for`-bound `resolve_env`, its `[env]` is honored.
  The **hashed-set ≡ authorized-set** invariant holds for free (both go through
  `mise_files_for`); the genuinely-wider reaches of mise discovery stay **out** by the
  same project-root anchoring — parent-directory configs, the user-global config,
  env-specific `mise.<env>.toml` — since admitting them would let a never-hashed file
  steer resolution. Pure cadrage, not new containment: the mount layout already binds
  exactly `mise_files_for`. The `resolve_env` integration test was reworked (the old
  unauthorized sibling `mise.local.toml` is now authorized → asserted *mapped*; a
  *parent-directory* `mise.toml` is the new genuinely-excluded case). **163 tests
  green**, fmt/clippy clean, proven live (`mise.local.toml` `[env]` mapped, parent
  config excluded).
  **M3.3d.1** (`src/sandbox/fhs.rs` + `binds.rs` + the env denylist): the base
  userland gains a **nix-ld shim** so the project's tools can run on a **different
  glibc than the base** — the enabler for mise's exact-patch `[tools]` (each tool
  pinned to its own nixpkgs revision is cross-channel by construction). The skew it
  cures was de-risked by a throwaway, mise-decoupled measurement: with the base
  glibc on `LD_LIBRARY_PATH` a cross-channel tool dies on a `GLIBC_PRIVATE` ABI
  mismatch (its own loader loads the base `libc.so.6`); drop it and the tool runs on
  its own glibc via RPATH; a **foreign** binary (which hard-codes `/lib64/ld-linux`
  and finds libc only through the loader) keeps working because nix-ld now sits at
  that path and re-execs the real base loader named in `NIX_LD`, with the base libs
  in `NIX_LD_LIBRARY_PATH` — *not* on the global `LD_LIBRARY_PATH`, which is dropped
  entirely. `resolve_userland` provisions the `nix-ld` attribute (selecting its
  `libexec/nix-ld` shim) beside glibc/gcc/bash/coreutils; `Userland` carries
  `interp_src` (the shim, bound at `/lib64/ld-linux-x86-64.so.2`), `base_loader`
  (the logical base loader → `NIX_LD`) and `foreign_lib_paths` (logical base libs →
  `NIX_LD_LIBRARY_PATH`). `NIX_LD`/`NIX_LD_LIBRARY_PATH` join the untrusted-only env
  denylist — the same loader-control (`AT_SECURE`) class as `LD_*`, which their
  `NIX_` prefix would otherwise slip past. A single integration smoke proves both
  ends live (a forged foreign binary served by the shim, and a cross-channel
  `nixos-23.11` tool running with no skew) — merged into one test so the heavy
  provisions run sequentially, which removed a cold-cache concurrency flake. Known
  residual: a foreign binary that itself execs a *cross-channel* nix child passes
  nix-ld's `LD_LIBRARY_PATH` down to it (still a strict subset of the prior skew,
  which forced the base glibc on **every** tool). nix-ld also lifts the M3.2c
  one-channel constraint for `[packages]`/`nixpkgs` pins as a side effect, though
  those stay channel-coarse by design (the OS-substrate layer). Proven live e2e +
  **162 tests green**.
  **M3.3c** (`src/sandbox/mise.rs::resolve_env` + launch wiring): a **trusted**
  project's mise `[env]` maps into the sandbox — the **first consumer that reads a
  project mise file** (`[tasks]` stays out = substrate/workflow line; `[tools]`
  exact-patch is the glibc-gated M3.3d). The increment's point is **mise sees exactly
  the authorized inputs**, on two fronts. (a) *File set*: mise's discovery is wider
  than ops's hash (`mise.local.toml`/`.tool-versions`/parent/global), so the driver
  binds **only** `trust::mise_files_for` (ro under `/project/<name>`), runs mise from
  there with `MISE_TRUSTED_CONFIG_PATHS` naming exactly those, exposes nothing else —
  the **mount layout IS the containment**, not a mise flag. (b) *Bytes*: the files are
  materialized from the bytes trust validated at load (carried on `MiseConfig.files`,
  read once through the safety gate — `read_project` now threads them out), into an
  owner-only staging dir **outside every writable mount** (sibling of the project home,
  like the synthetic `/etc`), so mise reads precisely the hashed content with no
  writable alias to rewrite it (closes the trust→read window, same as the `.ops.toml`
  path). Extraction is by **provenance**: `mise env --json-extended` tags each var with
  the `source` file; keep a var only when its source ∈ the bound set. A var mise merely
  **echoes (PATH) carries no source → dropped** (the sandbox PATH is never disturbed; a
  dotenv-pulled value from an unhashed file can't ride along). Decided empirically:
  `mise env` exits 0 even with uninstalled `[tools]` offline, so a mixed project is
  safe and **hard-fail-on-error** holds. Launch wires it trusted-only: resolves the
  **GLOBAL** channel for the engine (never `prep.nixpkgs`), withheld (untrusted/changed)
  only warns, a trusted `[env]` that fails to resolve is **fatal** (like a declared
  tool). Precedence **structural < passthrough < mise `[env]` < `.ops.toml [env]`**.
  Dep **serde_json** (user-approved; pairs with serde). `command` made private (took a
  private `ProjectBind`); provision/command `#[allow(dead_code)]` removed (now live).
  Proven live e2e (`ops run` exposes the var only once trusted; unhashed sibling never
  contributes) + **161 tests green**. **M3.3b**
  (`src/sandbox/mise.rs`): the **mise engine is provisioned via nix into ops's own
  store** (never the host's mise) and driven from there — the glibc-independent
  scaffolding the mise front-end builds on. Running a relocated-store binary needs a
  bind of ops's store at `/nix` inside a minimal bubblewrap (a nix binary hard-codes
  its interpreter under `/nix/store/…`, which lives under ops's store root on the
  host) — the same trick the sandbox uses for its userland, applied to a tool ops
  runs itself. The **mount set is empirical** (live `mise --version`): `/nix` ro,
  `/proc`, `/dev`, tmpfs `/tmp`, and one rw bind (the private mise home). Two
  properties **born with the driver**: (1) **mise tracks the GLOBAL channel, not a
  project pin** — it runs in its own relocated-store `/nix` view, so the one-channel
  glibc rule does not reach it; `provision(nix, layout, nixpkgs)` takes the ref as a
  param and the caller resolves the **global** `LockTarget` (never `prepare`'s
  effective/possibly-pinned ref — guard-noted on `Prepared.nixpkgs`), giving one
  shared engine per channel rev (`<data>/gcroots/mise/<rev>/`). (2) **never mutates
  the host** — `HOME` + every `MISE_*_DIR` redirected under `<data>/mise/`
  (owner-only), `--clearenv` + rebuilt env, network unshared + `MISE_OFFLINE=1`
  (offline now; online toggle for nixhub is later), cwd pinned to the private home
  (not the launching cwd — also keeps it out of mise's discovery). The private home
  is the **only writable mount** = the structural no-host-write guarantee (asserted
  on the pure argv; proven live writing solely into ops's data dir). Provision+driver
  shipped behind a surgical `#[allow(dead_code)]` (precedent: `NetPolicy::Isolated`),
  **now consumed by M3.3c** (allows removed). **M3.3a** (trust
  composition over `.ops.toml` + mise file — the prerequisite for the mise
  front-end, which is **trusted-only**): `ops trust` now hashes the `.ops.toml`
  **and every sibling mise file** (`.mise.toml`/`mise.toml`) together
  (filename-tagged, length-prefixed framing), so editing **either** re-arms the
  gate; the hash stays byte-identical to the single-file hash when no mise file
  exists (nothing already trusted churns). The verdict is computed on the same
  composed bytes in the loader and in `trust --show` (no divergence). Every input
  goes through the same safety gate — a present-but-unsafe mise file is
  unverifiable → **fail-closed** (`trust` refuses; loader/`--show` report
  Untrusted). `ops config` shows a `mise:` line (file(s) + trusted/withheld),
  network-free, **no mise run**. Two locked decisions: (1) **anchored on
  `.ops.toml`** — a mise file is hashed/honored only beside one (marker keyed by
  the `.ops.toml` path); an orphan mise file warns, not honored (project-root
  anchoring = later additive option). (2) **The hashed set ≡ the set later
  authorized to mise** (`MISE_TRUSTED_CONFIG_PATHS`) — the binding contract M3.3b
  must honor: mise's own discovery is wider (`.tool-versions`, `mise.local.toml`,
  `.config/mise/config.toml`, parent configs), so provisioning must pass mise
  **exactly** the `mise_files_for` set, never default discovery, or an unhashed
  file reaches resolution. **M3.3 itself = option-1 re-sequence** (decided with the
  user): mise's exact-patch via nixhub pins each tool to its **own** nixpkgs rev
  (`vsix.lua:34` `<repo>/<commit_hash>#<attr>`) → cross-channel → re-creates the
  M3.2c `GLIBC_PRIVATE` glibc skew. So the glibc-independent scaffolding (M3.3a
  trust; M3.3b mise-provisioned-via-nix; `[env]`; `ops upgrade mise`) ships first,
  and `[tools]` exact-patch provisioning is the **gated** last sub-increment where
  the glibc strategy (nix-ld vs empirical one-channel) is decided with measurements
  in hand. ops drives mise as a **subprocess** (the `mise/` tree is a vfox backend
  plugin); `mise` is **provisioned via nix**, not the host. 153 tests green. **M3.2d**
  (`ops upgrade [all|nix]` + channel
  visibility): versions move **only** on an explicit upgrade, never on an ops binary
  update. `upgrade` is **context-aware** — it re-resolves the source the cwd tracks and
  rewrites **that** lock (trusted project pin → per-project lock, else global); this is
  the only way a *channel* pin (`nixos-23.11`) advances within itself (global-only would
  freeze it). A *revision* pin refreshes to itself — a no-op the report names ("nothing
  to roll" vs "already latest", via `is_pinned_revision`). An untrusted/changed pin is
  dropped, so `upgrade` rolls the global channel and prints the config warning. Needs
  nix but **not** the sandbox boundary (only rewrites a lock). The "which source, which
  lock" decision is extracted to ONE place — `sandbox::effective_lock_target(cwd,
  layout, cfg) -> store::LockTarget` — routed by all three consumers: launch
  (`.resolve`, lock-reusing), upgrade (`.refresh`, force + report old→new), `ops config`
  (`.locked_revision`, display) — so the lock upgrade writes IS the lock a launch reads
  (no drift; replaced `global_ref`/`project_ref`). `doctor` is host-level → reads the
  **global** lock straight from disk and shows `<source> @ <rev>` verbatim
  (accurate-to-disk, NOT config-aware: a global override set-but-unresolved shows the
  prior source until the next launch/upgrade). Lock writes are **atomic** (temp +
  `rename`, prompted by the user's "two concurrent `ops upgrade`?" question): a reader
  sees old-or-new, never torn; a failed resolution returns before the write (never
  truncates a known-good lock); two upgrades race to a last-writer-wins of two valid
  revs (no flock — pure ergonomics). Proven live + 141 tests green (incl. pin-routing
  integration tests, network-free via a 40-hex revision pin). **M3.2c** (`nixpkgs`
  field + source-aware locks): a
  **security** field `nixpkgs` (trusted-only, like `binds`) overrides the channel the
  launch resolves against — a branch/channel (`nixos-23.11`) or 40-hex rev under
  `NixOS/nixpkgs` (forks/flake-refs deferred, charset-validated). **A per-project pin
  pins the WHOLE sandbox — base userland AND tools — from ONE effective channel**
  (`project pin ?? global override ?? default nixos-unstable`). This is the corrected
  design: a first attempt pinned tools-only (base stayed global) on the theory that
  each tool's closure is self-contained, but that **crashed** for a cross-channel pin
  (`hello: … glibc-2.42 … undefined symbol __tunable_is_initialized, GLIBC_PRIVATE`):
  the sandbox exports the base glibc on `LD_LIBRARY_PATH` for foreign binaries, and
  nixpkgs uses `RUNPATH` (searched *after* it), so a tool pinned to a different glibc
  loads the base `libc.so.6` under its own loader and skews. One channel per launch
  keeps base == tools == `LD_LIBRARY_PATH` glibc. So `launch::prepare` resolves ONE
  `nixpkgs` ref and feeds it to **both** `resolve_userland` and `packages::provision`;
  base gcroots are keyed by revision (`<data>/gcroots/base/<rev>/`) so each channel
  roots its own base (a pinned project downloads its own base closure — only pinned
  projects pay; the no-pin default still shares the global base). The lock is
  **source-aware** (2 lines `<source>\n<rev>`): a changed source re-resolves, an
  unchanged one stays fixed, a legacy bare-rev lock reads as the default channel. A
  global override → shared `<data>/nixpkgs.lock`; a trusted project pin → per-project
  `<data>/projects/<id>/nixpkgs.lock`, consulted **only** when a current pin exists
  (a dropped/now-untrusted pin falls back to global — no stale pin). `launch::prepare`
  loads the config once (infallible) before resolving; `ops config` shows the
  effective source (project pin / global / default), network-free. Proven live: a
  trusted `nixos-23.11` pin runs `hello` from 23.11 on a 23.11 base. Deeper smell
  noted (not now): the foreign-binary `LD_LIBRARY_PATH` is what forces one-channel;
  a nix-ld-style foreign-only library path (M1-level) would later let base and tools
  diverge safely. **M3.2b** (relax `[packages]` to untrusted projects via a
  build-vs-fetch dry-run) was **deliberately skipped**: `ops trust` already
  suffices for security, and for `[packages]` the relaxation adds **none** (a tool's
  `bin` output is input-addressed → it is either cache-substituted, safe to admit
  either way, or an input-addressed build that needs trust — the substitution/FOD
  distinction is moot for tools). So it is pure ergonomics; deferred (reopen if the
  friction proves real). The substitution+FOD-for-untrusted policy is the eventual
  model for a future **`sources`** field (where fetching is the point), not
  `[packages]`. **M3.2c** = `nixpkgs` override (trusted-only) + per-project lock.
  **M3.2a** (`src/sandbox/packages.rs` + config `[packages]`): a project declares
  tools as `name = "<nixpkgs attr>"`; the launcher provisions the **admitted** ones
  into ops's store (per-project gcroots under `<data>/gcroots/projects/<id>/`,
  reusing the runtime identity via `binds::project_runtime_id`) and **prepends**
  their `bin/` to the sandbox `PATH`. Layering is pure: `config::resolve` key-merges
  `packages` and stamps each with its source's trust, **dropping nothing** — the
  admission decision lives downstream in `packages::admit` (M3.2a = **trusted-only**,
  the deliberately conservative slice; M3.2b will re-admit an untrusted tool that
  needs only a signed-cache *fetch*, the build-vs-fetch gate). A withheld tool only
  warns; an **admitted** tool that fails to realise is a **hard fail naming the
  attribute** (a declared tool is a requirement, unlike a best-effort bind). Name +
  attr are charset-validated (the name is a gcroot filename). `nixpkgs_ref` is
  resolved **once** in `prepare` and threaded to both the base userland and package
  provisioning (so M3.2c's `nixpkgs` override plumbs in one place). `ops config`
  shows the declared set with each tool's trust verdict, **without** realising
  anything (network-free — it cannot reflect M3.2b's build-vs-fetch outcome, an
  accepted relaxation of the binds anti-drift rule). Proven live: untrusted ⇒ tool
  withheld (`ABSENT`); after `ops trust` ⇒ `ops run -- jq …` runs from ops's store.
  110 tests green. **M3.1**
  (`store.rs` + `sandbox/fhs.rs`): the base userland (glibc/gcc/bash/coreutils) is
  now **provisioned into ops's OWN store** (no longer the host `/nix`), bound
  read-only at `/nix`. `store::provision` runs daemonless nix (`--store`,
  `--out-link` gcroot under `<data>/gcroots/base/`) against a **pinned** nixpkgs;
  `nixpkgs_ref` resolves the rolling default channel (`nixos-unstable`) **once**
  and records the revision in `<data>/nixpkgs.lock` (read *before* nix is invoked,
  so an ops binary update never moves tool versions — the user's hard requirement,
  guarded by a nix-free test). `fhs.rs` splits **logical** in-sandbox paths from
  **physical** bind sources (`store::physical_path`). Proven live: `ops run -- id`
  → `uid=1000(sandbox)`, hermetic, from ops's store. **Two M3.1 notes:** a
  project's *first* run now needs the binary cache (ops populates its own store —
  the §7-q3 tradeoff, not a regression); and `doctor` is still blind to the
  channel rev (surface it when `ops upgrade` lands, M3.2). Full M3 design (rolling
  OS on a channel, two front-ends, trust lines, `ops upgrade [all|nix|mise]`):
  [[m3-provisioning-design]]. **M2 deliverable** remains **met** —
  a `.ops.toml` **drives the sandbox safely**: a *free* field (`env`) applies from
  any project, a *security* field (`binds`) only from a **trusted** one, proven
  end-to-end through a real launch (`ops run` with an untrusted config →
  `BIND=ABSENT`; after `ops trust` → `BIND=PRESENT`). The schema is deliberately
  **minimal and additive**: network / secrets / GUI / ssh-agent fields are
  **intentionally absent, not silently ungated** — each lands *with its consumer*
  (M3–M6), so the small surface is not a gap.
  **M2.1** (`src/trust.rs` + `src/config/safety.rs`): the **trust gate's recording
  side** — `ops trust`/`untrust`/`trust --show`. Content-bound trust on the
  **direnv model**: a marker under `$XDG_STATE_HOME/ops/trusted/` holds a
  **SHA-256 of the whole file** (not a parsed subset — keeps trust independent of
  the schema and any edit re-arms), keyed by the config's canonical path; states
  Trusted/Untrusted/Changed. The hash is **cryptographic by necessity** (the old
  `DefaultHasher` is forgeable); first non-`libc` dependency (`sha2`,
  user-approved — [[m2-dependency-policy]]). The **safety gate** refuses a config
  that is not a plain, owner-owned, non-world-writable regular file, gating the
  **open fd** (`fstat`) whose bytes are then read+hashed — so the validated
  metadata and the consumed bytes are one inode. The store dir's absolute-path
  requirement is a security control (a relative base would let a cloned repo
  pre-approve itself).
  **M2.2** (`src/config/schema.rs` + `mod.rs`; deps `toml`+`serde`): config
  parse + global/project layering + the **gating**, with `ops config` as the
  consumer. Pure `resolve` (matrix-tested): global is **trusted by location**
  (safety-gated, not marker-gated) and honored in full; the project is
  trust-gated. **Free** field `env` applies from any project; **security** field
  `binds` only from a *trusted* one (untrusted/changed ⇒ dropped + an actionable,
  Changed≠Untrusted warning). The env **denylist is untrusted-only** (a
  reserved-always list would violate the *decided* symmetric schema — a trusted
  config overriding `PATH` harms only itself, out of scope), scoped to glibc's
  **`AT_SECURE`** set + structural (`LD_*`, `GCONV_PATH`, `GLIBC_TUNABLES`,
  `LOCPATH`, `NLSPATH`, `RESOLV_HOST_CONF`, `HOSTALIASES`, `BASH_ENV`, `ENV`,
  `IFS`, `HOME`, `PATH`) — its job is protecting the user's later **Mode-A**
  sessions, not the already-in-cage agent. `load` is **infallible** (absent /
  unsafe / unparseable / no-store all degrade to a warning + dropped layer, never
  a hard fail); the project verdict is computed on the **exact parsed bytes**
  (closes the trust→parse TOCTOU). **M2.3** (`launch.rs` + `binds.rs`): the
  resolved config reaches the sandbox via `build()` (covers `run` **and**
  `shell`). Env ordering = structural first, then config **upserted** over it, so
  a *trusted* override wins (an untrusted one already lost its reserved keys). Bind
  resolution (absolute-only, canonicalized, missing-dropped) lives in
  `config::load`, **not** the launch — so `ops config` shows the *effective* binds,
  no preview-vs-reality drift. Config `ro_binds` are emitted **before** the
  structural mounts so a colliding one is shadowed (cannot displace `/nix`, the
  synthetic identity, the project). **Known limitation** (non-blocking,
  trusted-only): the prepend rule resolves only *exact-dest* collisions — a config
  bind that **nests** with a structural mount mis-resolves by path: a *descendant*
  (e.g. under `/tmp`) is silently shadowed by the later tmpfs (fail-closed —
  `ops config` may list it though the launch drops it); an *ancestor* (e.g. `/etc`)
  over-exposes the rest of that dir (self-sabotage, threat-model §1 out of scope).
  Eventual hardening: warn when a config bind dest nests with a structural mount
  dest. **M0 done** — `ops doctor` (the userns
  gate) + read-only store-health; store mechanism **resolved & de-risked**
  (single shared flat store, ro-consume / rw-provision, trust-gated
  provisioning — architecture §7.4,
  [`bwrap-store-derisk-2026-06-15.md`](docs/bwrap-store-derisk-2026-06-15.md)).
  **M1 so far** (`src/sandbox/`): the keystone `SandboxSpec` + pure `to_argv`
  (hardening is unconditional in argv → an unhardened sandbox is
  unrepresentable; architecture §3 "As built"), proven against real bwrap
  (`CapEff=CapBnd=0`, `NoNewPrivs=1`); the project constructor `binds.rs` (zones
  0/1/2, synthetic `/etc/passwd`+`group` **outside** every rw bind, TOCTOU
  canonicalisation) + the hermetic-FHS resolver `fhs.rs` (host `/nix` ro until
  provisioning lands), de-risked end-to-end. Both launch paths work and are
  proven through the CLI / a pty harness:
  - **`ops run`** (exec-replace, `NewSession`): `ops run -- id` →
    `uid=1000(sandbox)`, hermetic (no host `/usr`), host `$HOME` absent, exit
    status propagated.
  - **`ops shell`** (pty supervisor, `PrivateTty`): real interactive shell with
    **job control** (controlling terminal present, no "no job control" warning),
    hermetic, synthetic identity — the M1 headline. Empirically required to omit
    `--new-session` and own the session via a pty (see architecture §2/§3 "As
    built"); raw `libc`, no new dependency.
  - **M1.4 `session/` + `ops ps`** (`src/session.rs`): the **daemonless** on-disk
    registry. Each sandbox writes a record under `<data>/sessions/`; a record is a
    **liveness-validated hint**, never trusted to be cleaned up — `list()` prunes
    by liveness, so a crash/`SIGKILL` self-heals. Liveness = `(pid, start_ticks)`
    (process start time from `/proc/<pid>/stat`, survives `execve`) to defeat pid
    reuse; `kill(pid,0)` is only a pre-filter, the start-time match is decisive.
    Both paths register (`run` = the agent path, persists then liveness-pruned;
    `shell` = a `RecordGuard` that unlinks on exit). The record stores the
    **canonical** project path — the same identity `binds.rs` derives the runtime
    id from — so registry and runtime never disagree (GC consumes this in M5).
    "2nd terminal in the same env" works *today* because the per-project runtime
    is deterministic: a second sandbox in the same project shares its persistent
    `$HOME` (proven). No new dependency. **GC and `ops attach <id>` deferred (M5).**

  - **M1.5 `doctor` real bwrap smoke** (`src/sandbox/smoke.rs`): the security
    boundary is now decided by a **live launch**, not the `unshare` stand-in.
    `doctor` feeds the real `to_argv` to `bwrap` and reads `/proc/self/status`
    from inside; a launch with `CapEff=0` + `NoNewPrivs=1` proves the namespace is
    capability-bearing more conclusively than the stand-in could (bwrap cannot
    nest its namespaces on a cap-stripped one). `probe_userns` is **demoted, not
    deleted** — it stays the fast gate the launch path uses (no subprocess per
    `ops run`) and the red-path classifier: a capability-bearing namespace + a
    failed launch ⇒ the *engine* is at fault (surface `bwrap`'s stderr), not the
    boundary. The smoke binds host `/usr` (userland-independent hardening → no nix,
    no store touched; `doctor` stays read-only on the host) in a throwaway temp
    dir cleaned on drop. The canonical minimal-hardened spec lives in `smoke.rs`;
    its test asserts hermeticity (host `$HOME` absent). No new dependency.

  The M1.1/M1.2 scaffolding is load-bearing (the `#[allow(dead_code)]` are gone
  except the M3-reserved store primitives). **M1 is complete** — the minimal
  sandbox is end-to-end: `doctor` gate → `run`/`shell` launch → `ps` registry,
  all proven through the CLI. Next: **M2** (config + trust gate), per the
  milestone table.
