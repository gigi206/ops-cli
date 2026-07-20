# `flake:` host-side build — implementation plan (2026-07-19)

Make a `flake:` `[packages]` behave app-global like `nix:`: **built once** into the shared
store, **seeded** into each project, so a global app's flake package no longer rebuilds on
first launch per project. Distinct from — and posterior to — the (completed) mise two-scope split.

## Decision — Option A (user's call, 2026-07-19)

Build the flake **host-side into the shared store** (via `store::provision`), then seed
per-project — reusing the exact `nix:` path. Rejected: **B** (keep in-cage build + promote the
output to the shared store — ~4× the code + a lifecycle-timing problem, since the build is
mid-launch and a `--detach`/long agent cage would leave the 2nd project rebuilding until the
first session ends); **C** (a per-app store — unnecessary and it would break the per-project
isolation of a project's own tools).

## Security analysis (the load-bearing question, resolved)

- sbx's **host-side** nix build already runs with **`--option sandbox true`** (`store.rs:1043`
  in `provision`, `:1111` in `provision_expr`), so a flake's **builder** is sandboxed host-side —
  exactly like `nix:`/`deb:`. `store::provision(flake_ref, attr)` *is already a host-side flake
  build* (a `nix:` package is `nixpkgs#<attr>` down this path).
- A's only marginal risk over the `nix:` path already shipped: **(a) source curation** (an
  arbitrary third-party flake vs a curated nixpkgs attr) and **(b) the flake's eval runs
  host-side** (reading `flake.nix` + eval-time code, unsandboxed) — the same class as `nix:`
  evaluating a nixpkgs expression, and sbx **already** evaluates arbitrary flake refs host-side
  for pin resolution (`nix flake metadata` in `flake::upgrade`).
- `flake:` stays **trusted-only**; `is_valid_flake_ref` still rejects every local-source form (no
  host-path build). So the eval/build target is a trusted, remote, charset-validated ref.
- **Bonus:** a host-side build fetches its inputs over the **host network** (like `deb:`), so it
  removes the "a flake whose build self-fetches (bun) is blocked under the cage allowlist" wall
  (the kilocode case). The cage allowlist then governs only the app's **runtime** egress.

## The change — mirror `nix:`

- `packages::provision` builds each admitted `flake:` package host-side via
  `store::provision(nix, layout, gcroots/projects/<id>/<name>, <target>, …)` → its `bin/` joins
  `bins`, its store path joins `roots`; `seed_project_store` reflinks it per project (built once —
  the 2nd project's `nix build` is a content-addressed cache hit / gcroot-only).
- **Build target** = the pin honoured: the *locked* ref when `flake-packages.lock` pins it, else
  the declared ref. Split `ref#attr` with the existing `split_attr`; the no-`#attr` case builds
  the flake's default package (`nix build <ref>` — a `store::provision` variant that does not
  force `#attr`, or a `default` attr fallback — decided in the build).
- **Retire the in-cage machinery:** `wrap_flake_equip` + the `.failed`-marker/last-good-build
  logic, `FLAKE_ROOTS_REL`/`flake_roots_dir`/`flake_out_link*`, and the in-cage
  `/nix/var/nix/gcroots/sbx-flake-<name>` root. A `flake:` now writes
  `gcroots/projects/<id>/<name>` like `nix:`.
- **gc:** add `Backend::Flake` to `packages::project_gcroot_names` (it now writes the per-project
  data-dir out-link `nix:` uses); drop `gc::prune_flake_roots` (the in-cage-store root path it
  reclaimed no longer exists).
- **inspect (`app show`/`config show`):** `flake_built` (the home out-link reader) → the per-tree
  signal `nix_built_trees` already gives `nix:` (`built in N trees`).
- **`sbx upgrade flake`:** the pin resolution (`nix flake metadata` → rev) is unchanged; it now
  feeds the host-side build target instead of the in-cage one.

## Open design points (resolve during the build)

1. **Floating vs pinned host-side — RESOLVED (Slice 1).** A floating `flake:` (no lock) would, host-
   side, re-resolve its latest revision after nix's `tarball-ttl` (~1h) and silently roll — a naive
   unconditional `nix build` does **not** deliver the approved "frozen until upgrade". So
   `store::provision_flake` short-circuits on the build *target* via the same `<gcroot>.expr` stamp
   mechanism as `provision_expr` (proven for `deb:`): the built output is reused while the target
   string is unchanged, so a floating flake **freezes at its first build** until `sbx upgrade flake`
   pins it (the target becomes a locked ref → the stamp mismatches → a rebuild), and a pinned flake is
   a warm no-op until a roll changes its locked ref. Per-project (the stamp lives beside the
   per-project gcroot), consistent with the per-project lock model. The advisor caught that the first
   cut lacked this — the rev-pinned e2e was a pure eval-cache hit and proved nothing about floating.
2. **Lock scope.** The `flake-packages.lock` stays per-project (reproducibility per project);
   the build lands in the shared store keyed by the built path, so two projects pinning the same
   ref share the build. No change needed unless we want a global lock (probably not).
3. **`[flakes.<name>]` inline flakes.** `Backend::FlakeInline { content, attr }` is built in-cage
   too (staged flake dir). Does A cover it, or does the inline case stay in-cage? An inline flake
   is local content (not a remote ref) — host-side build of local content is the thing
   `is_valid_flake_ref` refuses for security. **Likely keep `FlakeInline` in-cage** (it is the
   user's own staged content, lower risk, and host-side would need staging the dir host-side).
   Decide explicitly — this may mean the in-cage machinery is *reduced*, not fully removed.

## Slices (each ships with tests, advisor-reviewed, user-validated)

- **0 — spike (DONE):** a host-side `nix build github:…#hello --store <shared> --option sandbox
  true` yields a `bin/` (live, `bin/hello` present). Gated the design.
- **1 — provision + display correctness (DONE, pending user validation).** `store::provision_flake`
  (raw target + `--no-write-lock-file` + the target-stamp short-circuit for the floating freeze);
  `packages::provision` builds a `flake:` host-side (pin → target, mirror `nix:`); the remote in-cage
  build retired from `launch.rs` (`wrap_flake_equip` now inline-only), dead `read_flake_lock`/
  `flake_out_link_for`/`flake_out_link_rev` removed. **gc keep-set correctness folded in** (a remote
  `flake:` now writes the bare-`<name>` data-dir gcroot, so `project_gcroot_names` includes it — else
  `sbx gc` would reclaim a declared flake's build). **Display correctness folded in** (advisor): the
  realized signal for a remote `flake:` moved from the home out-link (`flake_built`, now absent) to
  the per-tree gcroot (`nix_built_trees`) in `app show`, `sbx projects show`'s unbuilt report, and the
  `config show` `realised` label — `FlakeInline` keeps the home-out-link signal (which also fixed a
  pre-existing inline mislabel in the projects-show report). **Headline e2e RAN LIVE (36.4s):**
  `a_flake_package_builds_host_side_into_the_shared_store_and_a_fresh_project_reuses_it` — the flake
  output lands in the SHARED store (host-side, which the old in-cage build never touched) and a fresh
  second project reuses it. sandbox:: 510 green, fmt/clippy clean.
- **2 — roll re-point proof + gc cleanup (DONE, green, e2e live).** Retirement: `flake_root_names`
  (`launch.rs`) is now **inline-only** (`flake_inline_packages`), since a remote `flake:` builds
  host-side and no longer writes the in-cage `sbx-flake-<name>` root — that root is only ever
  registered by an inline `[flakes.<name>]` now. Docs swept for the shift: the `gc.rs` module doc +
  `prune_flake_roots` doc (only inline registers `sbx-flake-<name>`; a remote `flake:` carries a
  data-dir out-link pruned by `prune_project_package_roots`), and `packages::flake_packages`'s doc
  (kept — it is used by `flake.rs::declared` for `sbx upgrade flake`'s pin resolution, not the
  launcher). **Two Slice-1-latent broken e2es rewritten** for the host-side contract (they still
  encoded the retired in-cage `home/.local/state/sbx/flake/hello-<rev>` out-link and `sbx-flake-hello`
  root — they would *fail*, not skip; Slice 1's "green" ran one new test, not the affected suite):
  (a) `a_locked_flake_package_builds_the_pinned_ref_host_side` (the pin path host-side — `upgrade
  flake` pins, the launch builds the narHash'd locked ref host-side into the data-dir out-link);
  (b) `sbx_gc_keeps_a_current_flake_build_and_reclaims_a_rolled_away_one` — **the roll re-point proof**
  (advisor's flagged gap): phase 1 KEEP (a declared host-side flake build gets a seed root + survives
  `gc --prune`), phase 2 ROLL (change the ref to a genuinely-distinct target under the *same* package
  name, `#hello`→`#figlet`, relaunch → the `hello` out-link re-points; `gc --prune` → the OLD build is
  COLLECTED via `prune_superseded_roots` and the NEW one KEPT). Non-vacuous both ways: `hello` is
  proven present entering the second gc (it survived phase 1 while current), and `hello` stays a
  declared package name (now figlet), so the old build is reclaimed via superseded-root reconciliation
  on a *re-pointed* out-link — the flake-specific roll path, distinct from the removal path (unit-
  covered by `prune_project_package_roots_keeps_declared_and_multi_output_siblings`). A two-rev real
  `upgrade` e2e was rejected (non-deterministic tip / two nearby `#hello` revs are content-addressed to
  the same store path → "old collectable" goes vacuous). **Done-gate: the whole flake+gc e2e subset ran
  live** — 4 flake tests (109s: the two rewritten + the Slice-1 headline + the inline) + 4 gc-machinery
  tests (46.6s: `gc_prune_drops_a_superseded_seed_root`, `upgrade_hints`, `projects_rm_dead`,
  `app_rm_gc`) — plus unit 1218/0, fmt/clippy `-D warnings` clean.
  **Known coverage state (advisor, accepted — not a silent gap):** `prune_flake_roots` is now
  **inline-only** and has **no gc e2e** (rewriting the remote-flake gc test to host-side, correctly,
  removed its only end-to-end reach; the inline test does not run gc). It stays covered by unit tests —
  the prune logic (`prune_flake_roots_drops_only_removed_packages`) and the `flake_root_names` wiring
  (`flake_inline_packages_yields_only_trusted_inline_flakes`) — and the worst-case failure is an
  unnecessary rebuild after gc, never corruption. Not worth a 3rd heavy in-cage build.
- **3 — docs (DONE 2026-07-20).** `configuration/packages.md` (the backend table + the `flake:`
  section: host-side, host-network build, the bun/kilocode self-fetch wall gone; the inline `[flakes]`
  section reworded — inline is in-cage *unlike* a host-side `flake:`). `apps/home.md` — the caveat is
  retitled *"A caveat for inline `[flakes]`"*: a remote `flake:` **no longer** rebuilds per project
  (host-side, seeded like `nix:`), only an inline flake still does. `sbx app show` display fixed in
  `cli/app.md` (a remote `flake:` reads `built in N tree(s)` like `nix:`, not `pinned in N tree(s)
  (<hash>)` — verified against `main.rs::build_app_show`; also corrected the stale `nix:` label and the
  missing `tarball:` row). gc/upgrade docs de-"rev-keyed" (`housekeeping/gc.md`, `cli/gc.md`,
  `housekeeping/upgrade.md`): a `flake:` roll re-points the **name-keyed** out-link and the old build
  is reclaimed as a **superseded** build (like a `nix:` rebuild), not a "stale rev-keyed out-link";
  removed-`flake:` reclamation folded into the removed-package bullet. `cli/projects.md` notes a
  host-side `flake:` build appears under the `nix` store-roots group. **`config/schema.rs` doc-comments
  fixed too** (the config surface's canonical doc: `flake:` built host-side; inline `[flakes]` in-cage
  *unlike* a remote ref) — doc-only, byte-identical binary. `FlakeInline` decision settled: **kept
  in-cage** (local content). No `help.rs`/CLI-surface change (syntax unchanged). `concepts/directory-
  layout.md` and `concepts/provisioning.md` verified already-correct (per-project store seeded from
  shared; `flake-packages.lock` accurate) — no edit needed. cargo build + fmt clean.

**Increment COMPLETE** (Slices 0–3). The `flake:` `[packages]` backend now behaves app-global like
`nix:`: built once host-side into the shared store, seeded per project, rolled by `sbx upgrade flake`,
reclaimed by `sbx gc` — no per-project rebuild. Only an inline `[flakes.<name>]` stays in-cage.

## Cost

A focused refactor: the provision side is small (mirror `nix:`), the bulk is *retiring* the
in-cage machinery cleanly across `launch.rs`/`binds.rs`/`gc.rs`/`inspect.rs`/`flake.rs` and
adapting the consumers. No new dependency. The offline-rerun e2e is the load-bearing proof.
