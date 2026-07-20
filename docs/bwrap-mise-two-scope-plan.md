# mise two-scope storage — implementation plan (2026-07-19)

Splitting mise's install/data storage into two scopes for a **global app**: an
**app-global** pool (shared across projects, holding the agent's own `mise:` tools) and
a **per-project** pool (aligned with the per-project `/nix` store, holding `nix:`-via-mise
self-equips and the project's local dev toolchain).

> **Status (2026-07-19): Increments 1 + 2 + 3 BUILT + GREEN — the feature is complete.** Inc 1 =
> layout + Runtime-aware `mise_env` + `nix:` plugin at both pools + Lane-1 app-global pin (folded per
> user + advisor — §6). keying RATIFIED app-keyed (§4.1) · spike PASSED (§5d). **Inc 2 = the headline
> two-project e2e `a_global_app_splits_mise_pools_across_two_projects`, RAN LIVE (44.9s) — the central
> fix proven end-to-end: app-global holds exactly rg (jq ABSENT), each of two per-project pools holds
> exactly jq (rg ABSENT), the (1, [1,1]) signature the old single-pool behaviour — (2, 0) — cannot
> produce.** **Inc 3 = housekeeping, all green (§6):** removal already-correct + pinned by regression
> tests (`projects rm` / `app rm --purge` reclaim the pool by nesting); `app show` now surfaces a
> global app's per-project pools (a `per-project self-equips` section + pool disk lines — the
> under-report the split introduced, fixed); a `mise:nix:` app-package detect-and-warn (points at the
> aligned `nix:<pkg>`); and **two behavioral e2es RAN LIVE** — Lane-2 lands per-project
> (`a_global_apps_project_mise_tool_lands_in_the_per_project_pool`, 24.6s) and `sbx upgrade mise` rolls
> a global app's tool app-global (`sbx_upgrade_mise_rolls_a_global_apps_app_global_tool`, 23.7s); docs
> updated (`apps/home.md` two-pool section, `cli/app.md`, `configuration/packages.md`,
> `concepts/directory-layout.md`). Pending: user validation.

---

## 1. The residual this targets

For a `Runtime::GlobalApp` (`sbx app <name>`, the default `home_scope = "global"`), the
home — and therefore mise's data dir — is **app-global**
(`<data>/apps/<name>/home/.local/share/mise`, `binds.rs:723-724` + `project_runtime`
`binds.rs:859`), while the store backing `/nix` is **per-project**
(`<data>/projects/<id>/store`). They are misaligned:

- An agent that `sbx mise use nix:<pkg>` in project A persists the *activation* in the
  app-global mise config, and mise records the *install* under the app-global
  `installs/`, but the tool's actual content is a `/nix/store/...` path built into
  **project A's** store only.
- In project B the app-global mise state says the tool is present, but B's `/nix` lacks
  the store path → **offline: a hard failure; online: a silent rebuild**.

`Runtime::ProjectDefault` (`sbx run`) and `Runtime::ProjectApp` already root the home
per-project (`binds.rs:856,861`), so their mise-data is already `/nix`-aligned. **This is a
`GlobalApp`-only change.**

## 2. Honest scope — what this does and does NOT fix

**Net-new value (narrow):**

- **(a) The real fix — `nix:`-via-mise self-equip alignment.** Moving the *ambient*
  `MISE_DATA_DIR` per-project makes project B correctly see the tool as "not installed"
  and rebuild into B's `/nix`, instead of trusting a stale app-global install record that
  points at A's store.
- **(b) Hygiene.** A project's local dev-tool installs stop piling into the app-global home.

**Explicitly NOT the value:**

- **Agent sharing across projects already works today.** For a GlobalApp, `mise use -g
  <agent>` already installs once under the app-global home and is reused in every project.
  The *only* reason this plan introduces `MISE_SHARED_INSTALL_DIRS` is to **preserve** that
  reuse after we move the primary data dir per-project — not to enable anything new.
- **The offline first-launch-per-project cost is inherent and stays.** A `nix:` self-equip
  still rebuilds into each new project's store the first time (online); we do not claim the
  residual disappears, only that the *stale-record / wrong-store* failure mode does.
- **Activation stays app-global** (§7.1): a `nix:` self-equip's activation record remains in
  the app-global config, so mise re-evaluates it per project (online) — correct for `nix:`,
  but not "fixed to zero work".

## 3. The enabling mise primitive (source-cited)

mise natively supports a **read-only multi-root install search**, so one invocation can see
two install pools:

- `MISE_DATA_DIR` — the single **primary** root; all *writes* (installs, `mise use`) go here
  (`src/env.rs:113-114`).
- `MISE_SHARED_INSTALL_DIRS` — colon-separated **read-only** fallback roots, searched only
  when the primary lacks the tool (`src/env.rs:145-179`, `find_in_shared_installs` fires only
  `if !primary_path.exists()`, `src/env.rs:222`).
- Config layers independently: project `mise.toml` (local) **beats** the app-global
  `config.toml` (`src/toolset/builder.rs:94-105`); local/global config dirs are separate env
  vars (`MISE_CONFIG_DIR`).
- No hidden coupling: the lockfile lives next to its config and records only
  versions+checksums, **no paths** (`src/lockfile.rs:65-77,1184`); install-state manifests
  record no absolute paths (`src/toolset/install_state.rs:40-56`). Same config across
  different data dirs works; same data dir across different configs works.

**Caveats from the same read:**

- Shims carry **no scope** — they re-resolve from the ambient `MISE_DATA_DIR` + config at
  exec (`src/shims.rs:101-149`). So "two shims dirs on PATH" is not itself a scoping
  mechanism; both shims must be on PATH so the shim *files* exist, but the scope is chosen by
  the ambient env.
- Only **installs** are multi-root. `MISE_PLUGINS_DIR` is single and follows the primary
  (`src/env.rs:130-131`) — the `nix:` vfox plugin must be registered under the primary
  (per-project). ops already registers it per launch (`binds.rs:1046`), so re-pointing the
  primary just moves that registration.
- **auto-install is ON by default** (`src/cli/exec.rs:140-156`) — a declared-but-missing
  tool is silently rebuilt into the primary. This is exactly the failure `SHARED_INSTALL_DIRS`
  must prevent for the shared agent (§5).

## 4. Design (GlobalApp only)

### 4.1 Physical layout

| Pool | Path | Holds | Scope |
|---|---|---|---|
| **app-global mise** | `<data>/apps/<name>/home/.local/share/mise` (**unchanged** — the home is already app-global) | the agent's `[packages] mise:` installs + shims + global `config.toml` | shared across projects |
| **per-project mise** (NEW) | `<data>/projects/<id>/mise` (project-keyed, sibling of `store/`) | `nix:`-via-mise self-equips + project `.mise.toml` installs + shims | per-project, `/nix`-aligned |

The per-project pool is a new writable bind into the cage (a fixed cage path, e.g.
`/opt/sbx/mise-project`, or a second path under the home tree that is itself the per-project
mount). The app-global pool stays the home's existing mise dir.

**Keying decision (RATIFIED by user, 2026-07-19): app-keyed / isolated —
`<data>/projects/<id>/apps/<name>/mise`** (per (project, app)). Each app's per-project mise
pool is private: a tool the agent self-equips in app A is **not** visible to app B or to
`sbx run` in the same project. This keeps ops's per-app isolation (Mode B, untrusted agent
actions) intact and does **not** extend the accepted "per-project `/nix` store shared across
apps" residual to mise install *records* (which were per-app before). It reuses the exact
`projects/<id>/apps/<name>/` base that `ProjectApp` already roots its home under, so it is
structurally clean. It does not regress the fix: app B still aligns with `/nix` — it re-resolves
a `nix:` tool, which is cheap because the project's shared `/nix` store already has the built
path (a store cache hit, no re-download). The rejected alternative was project-keyed
(`<data>/projects/<id>/mise`, one pool shared across apps): less disk + cross-app tool reuse,
but it widens the cross-app exposure to mise records — declined for the isolation cost.

### 4.2 Runtime env (the agent command)

For `GlobalApp` the ambient env becomes:

```
MISE_DATA_DIR            = <per-project>/mise            # primary; writes + nix:/project tools; /nix-aligned
MISE_SHARED_INSTALL_DIRS = <app-global>/installs         # agent tools, read-only fallback (preserves reuse)
MISE_CONFIG_DIR          = <app-global home>             # identity + global agent declarations (unchanged)
MISE_STATE_DIR/CACHE     = <app-global home>             # config-/registry-keyed, shareable (unchanged)
PATH  += <per-project>/mise/shims  AND  <app-global>/shims   # both shim dirs
```

`ProjectDefault` / `ProjectApp` keep today's single-pool wiring unchanged.

### 4.3 Two equip envs (the two lanes in `launch.rs:3599-3660`)

- **Lane 1 — app `[packages] mise:`** (`mise use -g`, `launch.rs:3651`): must run with
  `MISE_DATA_DIR = <app-global>` and `MISE_CONFIG_DIR = <app-global>` so the install lands in
  the app-global pool and the global `config.toml` records it. Set inline in the equip wrap
  (`wrap_mise_equip` builds a `bash -c` — prefix its `mise use -g` with the app-global
  `MISE_DATA_DIR`), so only this lane writes app-global.
- **Lane 2 — project `.mise.toml` non-`nix:` `[tools]`** (`mise install`, `launch.rs:3626`)
  and the **agent command itself**: run under the ambient per-project primary + shared
  fallback (§4.2). No change to lane 2's own logic beyond inheriting the ambient env.

## 5. Load-bearing spike — MUST pass live before any ops code

The spike must prove **both** halves — the *fix* (§2a) and the *preservation* (§3) — because
they exercise **different** mise mechanisms. A naive "the tool runs" check passes even on a
silent rebuild, so every claim below carries an assertion with teeth.

**Prerequisite verify — DONE (2026-07-19): PASS, no engine bump needed.** ops provisions a
**pinned** mise (`mise-engine.lock` → `nixos-unstable` @ `61b7c44…`, rolled only by `sbx upgrade
mise`), which materializes **mise 2026.7.5** (`…/store/nix/store/zip8s29…-mise-2026.7.5`). A
`strings` of that exact provisioned binary shows `MISE_SHARED_INSTALL_DIRS` in its env-var table,
so the pinned engine **has** the primitive — Increment 0.5 (engine bump) is **not** triggered.

Throwaway spike (host, nothing installed), on ops's provisioned mise:

### 5a. Preservation half — self-contained agent, no rebuild

1. Two data dirs: `PRIMARY=<tmp>/proj`, `SHARED=<tmp>/app`.
2. `MISE_DATA_DIR=$SHARED mise use -g aqua:BurntSushi/ripgrep` → assert `$SHARED/installs/…`
   populated + shim in `$SHARED/shims`.
3. Run the shim with ambient `MISE_DATA_DIR=$PRIMARY`,
   `MISE_SHARED_INSTALL_DIRS=$SHARED/installs`, `MISE_CONFIG_DIR=$SHARED`,
   `PATH=$PRIMARY/shims:$SHARED/shims:…`, `auto_install` at its default **ON** → assert the
   tool **runs** AND **`$PRIMARY/installs/` stays empty for it** (the no-rebuild teeth: proves
   the shared fallback is consulted *before* auto-install fires).
4. Install a *different* tool locally under `$PRIMARY` → assert it lands in `$PRIMARY/installs`,
   not `$SHARED`.

### 5b. Fix half — `nix:`-via-mise self-equip aligns per-project (THE fix, §2a)

This must reproduce §1's **cross-project, activation-driven** failure — not just "a `nix:`
build can target a per-project primary". §1 fails because `use` persists activation
**app-global** in project A, then project B trusts that record while B's `/nix` lacks the path.
The spike proves the split turns that stale-pointer failure into a clean rebuild-into-B.

5. Two primaries `$PROJ_A`, `$PROJ_B`, shared config `$SHARED`. Register ops's vfox **`nix:`
   plugin under each primary's `plugins/`** (production registers per-launch; `MISE_PLUGINS_DIR`
   follows the primary we are moving — the site is hardcoded to `home` today, `binds.rs:1046`,
   and moving it is on the critical path of the fix, not incidental).
6. `MISE_DATA_DIR=$PROJ_A MISE_CONFIG_DIR=$SHARED MISE_EXPERIMENTAL=1 <NIX_CONFIG> mise use
   nix:hello` → assert it **builds into `$PROJ_A`** AND the **activation record lands in
   `$SHARED`'s config** (app-global), with the plugin resolvable from its per-project location.
7. Then `MISE_DATA_DIR=$PROJ_B MISE_CONFIG_DIR=$SHARED` resolve/run `hello` → assert mise sees
   it **not-installed-in-B** and **rebuilds into `$PROJ_B`** (teeth: `$PROJ_B/installs` gets it;
   it does **not** resolve to A's store path). That is the residual, fixed, proven. Per §7.1 the
   activation stays app-global, so a per-project rebuild (online) is *expected*; the spike
   confirms that rebuild is **clean**, which is exactly what distinguishes the fix from today's
   stale-record failure.

### 5c. Scope note — RESOLVED (2026-07-19): interactive `mise activate` is not on the split path

The interactive `mise activate` path is **out of scope by construction**, not by assumption: the
split is **GlobalApp-only**, and a `sbx app run <name>` always runs its `cmd` through the **shims
path** (the exec launch, proven), never through the synthetic interactive rc that runs `mise
activate`. That rc belongs to the **no-command `sbx run` project shell** — which is `ProjectDefault`,
the single-pool runtime the split does not touch. So no global-app launch reaches `mise activate`,
and `MISE_SHARED_INSTALL_DIRS`/`activate` interaction never arises for the split. (If a future
interactive global-app shell is added, this line must be revisited.)

If 5a-step-3's no-rebuild assertion or 5b-step-6 fails, the design does not hold and the plan
stops here.

### 5d. RESULT — spike PASSED (2026-07-19)

Run against **ops's real provisioned mise 2026.7.5**, executed under a `bwrap` cage over ops's
own store (`~/.local/share/sbx/store`), throwaway. **8/8 assertions + the nix-plugin check
passed:**

- **5a preservation:** `aqua:BurntSushi/ripgrep` installed into `SHARED`; under
  `MISE_DATA_DIR=$PROJ_A` + `MISE_SHARED_INSTALL_DIRS=$SHARED/installs` +
  `MISE_CONFIG_DIR=$SHARED`, `rg --version` resolved (`ripgrep 14.1.1`) **and `$PROJ_A/installs`
  stayed empty** — the fallback is consulted before auto-install; no rebuild. (auto_install at
  default ON.)
- **5b cross-project activation:** `mise use -g aqua:sharkdp/fd` under
  `MISE_DATA_DIR=$PROJ_A MISE_CONFIG_DIR=$SHARED` wrote the activation to the app-global
  `SHARED/config.toml` and the install to `$PROJ_A/installs`; then under
  `MISE_DATA_DIR=$PROJ_B MISE_CONFIG_DIR=$SHARED` (no fallback to A), `fd` **ran and rebuilt into
  `$PROJ_B/installs`** (its own record, not a stale pointer to A) — §1's failure, fixed.
- **5b nix-specific (plugin location):** ops's embedded `nix:` plugin registered under a
  **per-project** primary's `plugins/` resolves (`mise plugins ls` → `nix`) **and is callable**
  (`mise ls-remote nix:hello` returned real versions from nixhub). The critical-path concern —
  `MISE_PLUGINS_DIR` following the moved primary — is proven.

**Not run standalone (deferred to the Increment-2 e2e):** a full `nix build` of a `nix:` tool
into a per-project store in the two-pool env — that is ops's already-shipped per-project-store +
nix-in-cage machinery, exercised end-to-end by the Increment-2 e2e through real ops. The mise
*mechanism* the fix depends on is proven live here; the nix: content-addressed per-project store
on top is pre-existing, proven ops behavior.

**Verdict: mechanism de-risked, design holds. Cleared to build Increment 1.**

## 6. Increments (each ships with tests, advisor-reviewed, user-validated)

- **Increment 0 — spike (§5).** Not committed; gates everything. Outcome recorded in a
  throwaway findings note. Includes the §5 prerequisite verify.
- **Increment 0.5 — engine bump (conditional).** Only if §5's prerequisite finds the pinned
  mise engine predates `MISE_SHARED_INSTALL_DIRS`: roll `mise-engine.lock` forward to an engine
  that has it. A hard prerequisite, not a footnote.
- **Increment 1 — per-project mise-data layout + Runtime-aware `mise_env` + Lane-1 pin (DONE
  2026-07-19).** Built and green. `ProjectRuntime` grew `mise_project_src: Option<PathBuf>`
  (`Some` app-keyed `projects/<id>/apps/<name>/mise` for `GlobalApp`, `None` otherwise);
  `build_spec` creates it owner-only and binds it writable at `MISE_PROJECT_INCAGE`
  (`/opt/sbx/mise-project`). `mise_env(per_project_primary: bool)` emits the split for a global
  app (`MISE_DATA_DIR` = per-project pool, `MISE_SHARED_INSTALL_DIRS` = app-global installs, both
  shims dirs on PATH); `ProjectDefault`/`ProjectApp` keep the single-pool wiring. The `nix:`
  plugin is registered under **both** primaries for a global app (per-project pool *and* the
  app-global home), since both are live mise primaries.
  **Lane-1 pin folded in (user decision + advisor, 2026-07-19):** shipping Increment 1 without
  it left a housekeeping read-path window — a global app's `mise:` tool would install into the
  per-project pool while `sbx app show`/`list`/`gc` read the app-global home, under-reporting the
  tool. So `wrap_mise_equip` gained a `mise_data_dir: Option<&str>` override, and `build()` pins
  Lane 1 (`mise use -g`) to the app-global home for a global app (`binds::mise_app_global_data_dir`),
  while Lane 2 + the agent command stay on the ambient per-project primary. No window remains.
  **Tests (all green):** unit — `mise_env` split on/off, `project_runtime` app-keyed layout, the
  single-pool negative, `assemble` binds the pool + both shims on PATH, `build_spec` registers the
  plugin under both pools, `wrap_mise_equip` pins the app-global data dir for the global lane; a
  `binds` **real-cage smoke** launching a global-app cage and asserting both shims dirs + the split
  env; and the **`a_fresh_mise_package_app_runs_under_its_own_allowlist` e2e gained discriminating
  teeth** — claude-code's Lane-1 install must land under the app-global home
  (`<data>/sbx/apps/cc/home/.local/share/mise/installs`), which fails if the pin does not take.
  fmt/clippy `-D warnings` clean, std-only (no new dep). 1201 fast-unit + the GlobalApp e2e green.
  **`sbx upgrade mise` regression closed (advisor-caught):** `upgrade_mise_packages` rolls a group by
  `build(runtime, [mise, "upgrade", tokens])`, so a global-app group would run `mise upgrade` under
  the ambient per-project primary — which does not hold the app tools (they are app-global) — and
  silently roll nothing. Fixed by a pure `mise_upgrade_cmd(runtime, …)` helper that pins the roll to
  the app-global pool for a global app (the same `MISE_DATA_DIR` prefix as Lane 1), leaving
  `ProjectDefault`/`ProjectApp` unwrapped; unit-tested (`mise_upgrade_cmd_pins_the_app_global_pool_only_for_a_global_app`),
  and the baseline (`ProjectDefault`) upgrade e2e re-ran green through the refactor. A full *global-app*
  upgrade e2e is folded into Inc 2/3 (the pin mechanism itself is live-proven by the fresh-mise e2e).
- **Increment 2 — the headline two-project e2e (DONE 2026-07-19, RAN LIVE 44.9s).** No new
  wiring — the end-to-end proof of Increment 1's plumbing.
  `tests/run.rs::a_global_app_splits_mise_pools_across_two_projects`: a GlobalApp whose `cmd`
  self-equips `nix:jq` in-cage (`mise use -g nix:jq && jq --version && rg --version`) and whose
  `[packages] mise:aqua:BurntSushi/ripgrep` is the app-global agent tool, launched in project A
  then project B under one shared data dir (so the app-global home is shared, the `/nix` store is
  per-project). **The discrimination rests on install *location counts*, not on inter-launch
  equality or a functional check** (advisor-caught: a refetch overwrites `installs/<tool>/<ver>`
  in place, so a set-unchanged assertion is blind to reuse; and under shared net a missing store
  path is substitutable, so "jq runs in B" only corroborates):
  - **app-global `installs/` = exactly 1 tool dir (`aqua-burnt-sushi-ripgrep`), jq ABSENT** — jq's
    absence from the shared app-global pool *is* the fix (were it shared there, B would resolve it
    from the app-global fallback → A's store path → absent in B's `/nix` → "active but absent");
  - **two per-project pools (`projects/<id>/apps/ag/mise/installs`), each exactly 1 tool dir
    (`nix-jq`), rg ABSENT** — two pools proves each project self-equipped jq into its own
    store-aligned pool; each holding a single tool (not two) proves rg was reused read-only via
    `MISE_SHARED_INSTALL_DIRS` and *not* copied per-project (property (a)).
  - Old single-pool behaviour would show (app-global 2, per-project pools 0); the split shows
    (1, [1,1]) — the counts alone discriminate, independent of the munged names.
  `installs/` also carries a top-level `.mise-installs.toml` bookkeeping file beside the tool dirs,
  so the count filters to directories (live-verified, not assumed). Test-only increment (no `src`
  change → the shipped binary is unchanged; the Increment-1 code it exercises is already in the
  release). The raw in-cage `mise use -g nix:jq` self-equip verb was exercised for the first time
  here (the `nix:` plugin at both pools + `MISE_EXPERIMENTAL`/`YES` resolved it; jq's per-project
  shim was on PATH in the same `sh -c`). Skip-not-fail without a sandbox or network.
- **Increment 3 — housekeeping (DONE 2026-07-19, all green).** Five slices, advisor-shaped
  (the review reframed "config shows the two pools" as the `app show` correctness fix, confirmed
  warn-only for `mise:nix:`, and had Lane-2's ambient routing code-confirmed before it was claimed):
  - **Removal was already correct — pinned, not re-coded.** The per-project pool
    (`projects/<id>/apps/<name>/mise`) nests under trees `sbx projects rm` (`reap_one` →
    `force_remove_dir_all(projects/<id>)`) and `sbx app rm --purge` (`purge_app_homes` →
    `force_remove_dir_all(projects/<id>/apps/<name>)`) already delete wholesale, so both reclaim it
    for free. Two regression tests pin it (`purge_app_homes_reclaims_a_global_apps_per_project_mise_pool`,
    `reap_one_reclaims_a_projects_per_project_mise_pool`) — their value is catching a future move of
    the pool out from under the deleted tree; `purge_app_homes`'s doc now names the sibling pool. The
    pool's `nix:` closures follow the existing "purged app's closures reclaimed by `sbx gc`" path (the
    in-pool out-links go with the pool → the auto-roots dangle → collectable).
  - **`app show` correctness fix (the real "shows the two pools").** The split moved a global app's
    `nix:` self-equips out of `app_home_dirs`'s view (the pools are `.../mise`, not `.../home`), so
    `app show <global-app>` under-reported. Fixed: `inspect::app_per_project_mise_pools` +
    `mise_installed_in` (a pool's `installs/` sits directly under it, not `.local/share/mise`);
    `build_app_show`/`render_app_show` add a `per-project self-equips` section + `project <id> (mise
    pool)` disk lines, pool bytes in the disk total, kept distinct from the app-global declared tools
    (package-matching stays home-only). Unit-tested (`app_per_project_mise_pools_reads_a_global_apps_pools_directly`,
    `app_show_surfaces_a_global_apps_per_project_mise_pools`). The `app list` mislabel (a mise-only
    per-project dir counted as a "home") is left as a minor label loosening, not a rabbit hole.
  - **`mise:nix:` detect-and-warn (§7.2), warn-only.** `warn_mise_nix_packages` flags an *app*
    `[packages] mise:nix:<pkg>` (its record pins app-global for a global app while the store path is
    per-project) and points at the aligned `nix:<pkg>`; trusted-only, apps-only (a baseline `mise:nix:`
    under `sbx run` is per-project-aligned, so it is not flagged — the existing baseline parse test
    stays green unchanged). No rerouting (routing would fight the Lane-1 pin). Unit-tested
    (`a_mise_nix_package_warns_to_use_the_plain_nix_backend`).
  - **The two behavioral verifications — RAN LIVE.** `a_global_apps_project_mise_tool_lands_in_the_per_project_pool`
    (24.6s): a global app's project `mise.toml` tool (Lane 2) auto-equips into the per-project pool,
    ABSENT from the app-global home (the Lane-2 landing check, moved from Inc 2 to keep Inc 2's clean
    (1, [1,1]) signature — Lane-2's ambient routing was code-confirmed at `launch.rs` `wrap_mise_equip(…,
    None, …)` before the test). `sbx_upgrade_mise_rolls_a_global_apps_app_global_tool` (23.7s): `sbx
    upgrade mise` rolls a global app's `[packages] mise:` tool in the APP-GLOBAL pool (the
    `mise_upgrade_cmd` pin), absent from any per-project pool.
  - **Docs (same increment, per sync-docs).** `apps/home.md` (the outdated "active but absent" caveat
    rewritten into a two-pool section describing the fix), `cli/app.md` (the `per-project self-equips`
    section), `configuration/packages.md` (`mise:nix:` → prefer `nix:`), `concepts/directory-layout.md`
    (the pool path). No help.rs change (no new command/flag). `profiles/README.md` needs none (no
    shipped profile uses `mise:nix:`).

> **Handoff (2026-07-19, complete):** all three increments are shipped and green. Inc 1 = the
> plumbing (app-global Lane-1 pin, per-project split, both shims on PATH, `nix:` plugin at both pools,
> the `upgrade` regression fix). Inc 2 = the central fix proven end-to-end (the (1, [1,1]) two-project
> signature). Inc 3 = housekeeping — removal pinned (already-correct), the `app show` under-report
> fixed, the `mise:nix:` warn, the two behavioral e2es (Lane-2-per-project, upgrade-global-app) RAN
> LIVE, docs updated. The one residual is inherent and documented (a `nix:` self-equip's activation
> stays app-global, so it re-evaluates/rebuilds per project on first launch — cheap on a store cache
> hit; the mitigation is `home_scope = "project"`). Nothing in this plan remains open.

## 7. Edge cases / caveats to resolve in the plan (not paper over)

1. **Activation scope stays app-global.** `MISE_CONFIG_DIR` remains the app-global home, so a
   `nix:` self-equip's activation is global and re-evaluated per project (online). This is
   correct for `nix:` (the content is per-project anyway) but must be stated — the plan does
   not eliminate the online re-evaluation, only the stale-record / wrong-store failure.
2. **`mise:nix:<pkg>` as an *app* package.** An app `[packages] mise:nix:<pkg>` install is a
   pointer into per-project `/nix`, so it **cannot** be shared via `SHARED_INSTALL_DIRS`. After
   Increment 1, Lane 1 (`mise use -g`) is pinned to the app-global home *and* the `nix:` plugin is
   registered there, so such a package does **not crash** — but its install record lands app-global
   while the built store path is per-project, the same record/content misalignment this plan fixes
   for self-equips. **No shipped profile uses `mise:nix:` in `[packages]`** (all are
   `mise:aqua/npm/github`), so this is theoretical; detect-and-warn (route it per-project) is
   deferred to Increment 3. `[packages] nix:`, `flake:`, `deb:`, `appimage:`, `tarball:` are
   unaffected — already per-project by construction.
3. **Surface: automatic, no new config field.** The split is an internal optimization for
   `GlobalApp` (strictly better behavior), so it needs no user-facing knob; `home_scope`
   stays as-is. (A `home_scope = "project"` app is already fully aligned and skips the split.)

## 8. Cost

Moderate, single-feature, no new dependency (100% native mise env). The real work is
Increment 1 (Runtime-aware `mise_env` + the new mount) and Increment 2 (the two equip envs +
both shims on PATH); Increment 3 is mechanical. ~1 focused feature across `binds.rs`,
`launch.rs`, the housekeeping paths, `ops config`, and docs, plus the headline two-project
e2e.

## 9. Go / no-go

The win is **narrow** (a `nix:`-via-mise self-equip alignment for global apps + install
hygiene) for a **moderate** change touching the mise env, a new per-project mount, the two
equip lanes, and housekeeping. It is strictly better behavior for `GlobalApp` and regresses
nothing (SHARED_INSTALL_DIRS preserves today's agent reuse), but it is not a large-value
feature. **Decision for the user:** build it now, defer it, or accept the current
`home_scope = "project"` as the manual mitigation for the alignment case.
