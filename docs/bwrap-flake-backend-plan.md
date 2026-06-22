# Plan — a `flake:` package backend (in-cage build)

> Status: PLAN (pre-impl). Triggered by the user's request for a `hermes` profile,
> which ships a `uv2nix` flake rather than a single binary. Cadence: plan → advisor
> → impl → user validation. The gating architecture decision is already taken
> (below); this plan works out the mechanism.

## Goal

Add a third package backend to `[packages]` — `flake:<ref>` — that provisions a
tool from **an arbitrary nix flake** (not just a nixpkgs attribute). This packages
any tool that distributes a flake (e.g. `NousResearch/hermes-agent`, a uv2nix Python
app exposing `packages.tui` / `packages.default`) **without** an in-cage installer
hook and **without** us authoring/maintaining a derivation.

Today `[packages]` has two backends:

| Backend | Locator | Where it builds | Trust |
|---|---|---|---|
| `nix:<attr>` | a **nixpkgs** attribute (resolved via nixhub) | **host-side** | trusted-only |
| `mise:<token>` | a mise token (`aqua:`/registry/…) | **in-cage** (`mise use -g`) | trusted-only |

`flake:` is the third. The locator is a full flake ref; the build is **in-cage**.

## The gating decision (taken with the user)

**A third-party, uncurated flake is built IN-CAGE, not host-side.** Rationale: a
flake's eval + build (and its transitive inputs, fetched over the network) are
exactly the kind of uncurated third-party code the cage exists to contain. Building
it host-side would import nixpkgs's *curated*-trust assumption into an uncurated
context — "I consent to run this tool in the cage" ≠ "I consent to execute this
flake's build-logic + its inputs on my host". So:

- `nix:` (curated nixpkgs) → **host-side** (unchanged).
- `flake:` (third-party) → **in-cage**, contained by the existing enforcement stack
  (seccomp mount/ns denylist + empty-netns + cgroups + per-project writable store;
  nix's own build sandbox is OFF in-cage per the seccomp posture, but the cage is the
  boundary).

This is **not new machinery**: the in-cage `nix build` of a flake ref is *already
shipped and proven* — the `ops mise install nix:<pkg>` path runs an in-cage `nix
build <nixpkgs>/<commit>#<attr>` (the embedded mise `nix:` plugin, with
`NIX_CONFIG=extra-experimental-features = nix-command flakes`). `flake:` generalizes
the **ref** from a nixpkgs attr to an arbitrary flake, built the same way in-cage.

## Mechanism

1. **`Backend::Flake(String)`** added to the `Backend` enum (beside `Nix`/`Mise`) in
   `src/config/mod.rs`. `locator()` returns the flake ref; `label()` returns `flake`.

2. **`parse_backend`**: a `flake:` prefix → `Backend::Flake(ref)`. The ref is
   **charset-validated** to a safe set that admits real flake refs —
   `github:owner/repo[/rev]#attr`, `git+https://…`, and the query forms
   `?ref=`/`?rev=`/`?dir=` (legitimate flake-ref syntax) — while **rejecting local
   sources** (`path:`, `git+file:`) and excluding shell metacharacters and
   whitespace. It is passed to nix **positionally** (never interpolated into a shell
   string), so validation is defense-in-depth, not the sole guard. `flake:` is a
   distinct prefix (clearer than overloading `nix:`; the double-scheme
   `flake:github:…` is cosmetically heavy but unambiguous).

3. **In-cage build wrap — `nix build --out-link`, NOT `nix profile install`**
   (advisor-corrected). The proven in-cage verb is **`nix build`** (the mise `nix:`
   plugin uses exactly it); `nix profile install` is a *different*, unproven verb
   (mutable profile manifest, generations, its own locking) and buys nothing
   `--out-link` doesn't. So each trusted `flake:` package builds to a per-package
   out-link under the persistent `$HOME`:

   ```
   <nix> build <ref> --out-link <home>/.local/state/ops/flake/<name>
   ```

   The out-link is a **gcroot** (protects the build from in-cage GC) and a symlink
   into `/nix` (= the per-project store in the cage). Refs + out-link paths + command
   are passed **positionally** (only the ops-owned absolute `nix` path + the integer
   count reach the wrap's script string → a ref from config cannot inject shell);
   out-link paths are derived host-side from the package name + the resolved home.

4. **PATH**: each `<out-link>/bin` is prepended to the cage PATH (the same pattern as
   the mise shims dir for `mise:` activation), so the installed tool is reachable by
   name in this and later launches. Order: declared/flake tools > mise shims > base.

5. **Composition / ordering** (advisor-caught class from multi-backend): the flake
   build wrap nests **inside** `egress::wrap_command` (socat forwarder up before the
   build fetches) and is **skipped under `network = "none"`** with a by-name warning
   (a flake build needs the network on a cold store).

6. **Warm/offline short-circuit — load-bearing** (advisor-corrected). The wrap runs
   on **every** launch; with a **floating** ref, a bare `nix build` re-evaluates and
   (past `tarball-ttl`) **re-fetches** the ref each time → a warm launch is *not* a
   cheap no-op, and worse, an **already-installed tool fails offline** (the re-eval of
   the floating ref needs the network even though the per-project store holds the
   binary). Fix: the wrap **short-circuits the `nix build` when the out-link is
   already realised in the current project store** — `[ -e <out-link>/bin ] || <nix>
   build …`. Because the out-link is a symlink into the cage's `/nix` (= the
   per-project store), this `[ -e ]` test naturally checks presence **in the current
   project's store**, not merely that the gcroot exists — which is exactly what point
   7 (the `home_scope = "global"` residual) requires. This short-circuit is what makes
   P1 (float) a genuine warm no-op + offline-warm; without it, P1 forces the network
   on every launch.

7. **`home_scope = "global"` × the per-project store** (advisor-named residual). The
   out-link/gcroot lives under `$HOME`; the store backing `/nix` is **per-project**.
   With the default `home_scope = "global"` the home (and thus the gcroot symlink) is
   shared across projects while each project's store is separate — the same shape as
   the already-documented `MISE_DATA_DIR` residual: in project B the shared gcroot
   points at a store path B's store may lack → **offline: hard fail; online: a silent
   rebuild**. The point-6 `[ -e <out-link>/bin ]` short-circuit handles it correctly
   (it dereferences into the *current* store, so a dangling cross-project symlink →
   rebuild, self-healing). For a fixed rev the output path is content-addressed and
   identical across projects (no thrash once each has built once); a floating ref can
   resolve different revs per project and re-point the shared symlink (bounded
   rebuild, self-heals). Named, in the already-accepted same-uid/per-project-store
   residual class; `home_scope = "project"` aligns gcroot and store.

## Pin / reproducibility — v1 floats, pin is a named follow-up

A bare `github:owner/repo#attr` floats on HEAD. Three options:

- **(P1) v1: no pin — float, warm-frozen per project.** The in-cage build resolves
  HEAD at first launch, then the per-project store keeps it (like `mise:@latest`).
  Simplest, **fully in-cage** (consistent with the gating decision — zero host-side
  third-party eval). **Depends on the point-6 short-circuit** to be a warm no-op +
  offline-warm (a bare float would re-fetch HEAD every launch). Residual: HEAD can
  drift between projects / first-launches.
- **(P2) host-side pin** via `nix flake metadata --json <ref>` → `.locked.rev` → a
  per-project lock; in-cage build of the pinned `…/<rev>#attr`. More reproducible,
  but `nix flake metadata` fetches + locks the third-party flake **host-side** (no
  output eval, no build — lighter than a build, but still a host-side third-party
  fetch, mildly against the in-cage purity the user chose).
- **(P3) in-cage pin** — resolve + lock inside the cage, write the lock back out.
  Most consistent, most complex (the lock is host state written from in-cage).

**Recommendation: ship P1 in v1** (simplest, fully consistent with the in-cage
decision), and name P2/P3 + an `ops upgrade` story as the reproducibility follow-up.
This keeps the increment scoped to "the backend works, in-cage, end-to-end".

## Network / allowlist — the real friction of in-cage build

An in-cage flake build fetches over the cage's egress. Under `network =
"allowlist"`, the build's fetch hosts must be allowlisted:

- The built-in nix-cache allow-set already covers `cache.nixos.org` / `*.nixos.org`
  / github / githubusercontent / codeload — so the flake itself + nixpkgs inputs +
  binary substitutions are covered.
- **uv2nix fetches Python wheels from `files.pythonhosted.org`** (and possibly
  `pypi.org`) — **NOT** in the built-in set. So a hermes profile must add the wheel
  host(s) to its `allow`. This is **profile-authoring** (tool-specific), documented
  in the profile + README — *not* a widening of the built-in allow-set.

This is the cost the user accepted in choosing in-cage (network at first launch +
allowlisting the build's fetch surface), in exchange for keeping third-party build
code off the host.

## Scope / non-goals

- **`flake:` is trusted-only**, gated exactly like `nix:`/`mise:` in `[packages]`,
  including the `protect_trusted` guard (a trusted app's `flake:` package survives an
  untrusted project's override attempt — the flagship "agent on untrusted code"
  property).
- **Auth is NOT solved here.** The flake backend packages the *binary*; it does
  nothing for credentials. `hermes`'s default is **Nous Portal OAuth** (the agy-class
  gap). **A hermes profile must be keyed on OpenAI** (`api.openai.com`,
  `Authorization: Bearer` → fits `[secret]`) to run **end-to-end** today. Stated
  plainly: *flake backend + a hermes profile keyed on OpenAI = hermes runs
  end-to-end; packaging was the only ops gap.*
- **agy is untouched** — it is already a clean prebuilt Go binary (packaging was
  never its blocker); its blocker is OAuth + an undocumented runtime host. Separate,
  heavier, deferred. We do **not** probe its host by launching it with the user's
  Google account.
- The flake's **`#desktop` GUI output** stays Wayland-blocked; `#tui` / `#default`
  are CLI and in scope.

## Tests

- **Unit** (`src/config/mod.rs`): `parse_backend` `flake:` case → `Backend::Flake`;
  ref charset validation (a metachar/whitespace ref dropped); `label()`/`locator()`.
- **Unit** (`launch.rs`): the in-cage flake wrap passes refs + command
  **positionally** (the multi-backend `wrap_*` test pattern); skipped under `network
  = "none"`.
- **Guard** (config): a trusted app's `flake:` package survives an untrusted
  project's override (mirror `an_untrusted_project_cannot_override_a_trusted_apps_package`).
- **e2e** (`tests/run.rs`), the load-bearing proof: a small flake-shipping tool built
  **in-cage** under a trusted `allowlist`, run by name, asserting it came from the
  per-project store + the shared store stays byte-identical (the multi-backend e2e
  pattern). **The committed e2e must exercise the friction the plan itself names**
  (advisor): a tiny flake that **fetches an input** from a host *outside* the built-in
  nix-cache allow-set, so the allowlist→fetch chain (the real cost of in-cage build)
  is what's under test — not a fully-offline trivial flake that proves only the easy
  case. Skip-not-fail when the cache/network is unreachable. The **full hermes uv2nix
  build (PyPI `files.pythonhosted.org`) is heavy** → a manual/heavier validation, NOT
  the committed e2e; the plan states plainly that the exact uv2nix/PyPI motivating
  case is not covered by CI (only the equivalent allowlist→fetch chain is).

## Sequencing

1. The `flake:` backend (`Backend::Flake`, `parse_backend`, in-cage wrap, PATH) +
   unit/guard tests + the tiny-flake e2e. Advisor (impl) → user validation.
2. The **hermes profile** keyed on OpenAI (`flake:github:NousResearch/hermes-agent#tui`,
   `allow` = `api.openai.com` + the uv2nix fetch hosts) — shipped only after (1) is
   green and a heavier hermes build is validated.
3. (Follow-up, named-not-built) the pin (P2/P3) + `ops upgrade` for `flake:`.

## Honest residuals

- **In-cage build = network at first launch per project** + the build's fetch hosts
  on the allowlist (the accepted trade-off).
- **v1 floats** (no pin) → HEAD drift until the pin follow-up lands.
- **The build runs with nix's own sandbox OFF** in-cage (the seccomp posture) — the
  cage (seccomp mount/ns + empty-netns + cgroups + per-project store) is the
  boundary, the same posture already accepted for the `mise:nix:` self-equip path.
