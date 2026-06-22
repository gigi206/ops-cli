# Plan — `[packages]` backend prefix + fresh app profiles

Status: PLAN (pending advisor + user validation). Branch `bwrap`.

## Goal

Route every `[packages]` entry by a **mandatory backend prefix**, so an app/project
declares fresh upstream-direct tools via `mise:` alongside nixpkgs via `nix:`. Migrate the
three shipped profiles off stale/unfree nixpkgs onto fresh backends. Proven feasible live
2026-06-21: `aqua:anthropics/claude-code`=2.1.185 (unfree blocker gone), `aqua:openai/codex`
=0.141.0, registry `opencode`=1.17.9 — all fresh, hermetic, no node, in-cage.

## Decisions (locked with the user)

1. **Mandatory prefix, no bare.** Every `[packages]` value is `nix:<attr>` or `mise:<token>`.
   A bare or unknown-prefix value is **dropped + warned** with a precise message
   (`packages need a backend prefix: use nix:<attr> or mise:<token>`). Fail-closed — never a
   silent mis-route. (Breaking change to the current bare form; acceptable — `bwrap` is
   pre-release, `main` v1.18.0 frozen.)

2. **Two backends:**
   - `nix:<attr>` → ops **host-side** nixpkgs provisioning (existing `packages::provision`):
     built into the shared store, gcroot per-project, seeded → offline-reusable.
   - `mise:<token>` → **in-cage** mise, installed **globally** via `mise use -g` into the
     persistent home's global mise config: durable, always on PATH, **no repo mutation**.
     `<token>` is a full mise token (`aqua:openai/codex`, `opencode`, `npm:foo`,
     `nix:foo` for nixhub) passed to mise **verbatim** — NO special `mise:nix:` code path.

3. **`[packages]` is trusted-only for ALL backends** (`nix:` and `mise:`). An untrusted
   project's packages are dropped + warned at `admit`, regardless of backend. This closes
   the integrity hole (an untrusted project overriding a trusted app's `[packages]` entry to
   run attacker code under the app's posture/secrets/egress — the `cmd_trusted` hole via
   `[packages]`). Freshness is still met: profiles are **trusted-by-location**. Open
   self-equip stays in `.mise.toml [tools]`.

4. **Scope distinction (global vs local):**
   | Surface | Scope | Posture | Mechanism |
   |---|---|---|---|
   | `.ops.toml [packages] nix:` | global (shared store) | trusted-only | nix host-side |
   | `.ops.toml [packages] mise:` | global (`mise use -g`, home global config) | trusted-only | mise in-cage, global |
   | `.mise.toml [tools]` | local (project) | open | mise in-cage, local (unchanged) |

5. **App `[packages]` get PATH precedence** (narrowed from "strip `.mise.toml`", advisor).
   The app's own `[packages]` bins/shims sort **ahead** of any project `.mise.toml` shims, so
   the app's `cmd` always resolves to the **trusted** binary (the `cmd`-integrity property —
   what matters). The project's `.mise.toml` toolchain **stays available** in the app cage:
   `ops app` runs the agent *on the project's code* and often needs its toolchain
   (node/pnpm/…) to build/test it; stripping it is a real capability loss. Co-tenant risk is
   bounded by the existing Mode-B controls (secret never in the cage — proxy-injected
   host-side; egress = trusted-only allowlist), so the residual is within the accepted model.
   **Deferred to its own follow-up (user's call):** whether `ops app` should fully *strip* the
   project `.mise.toml` for maximum isolation — a usability↔isolation tradeoff decided on its
   own merits, not bundled into this increment.

6. **`ops config`** shows each package's backend + posture + (global-seeded vs
   global-fetched) so the per-entry semantics are never hidden.

7. **Roll-forward for floating `mise:` packages** (advisor). `mise:foo@latest` resolves once at
   install and is then frozen warm (a `latest` spec does not re-resolve once installed — the
   multi-backend finding). So a "fresh" `mise:` package would silently freeze at its
   first-install version unless something advances it. Intended mechanism: **`ops upgrade`
   re-resolves it** (runs `mise upgrade` / re-`mise use -g @latest` for the app's `mise:`
   packages), mirroring how `nix:` rolls via `ops upgrade nix`. Confirm the exact `mise`
   command that forces re-resolution; state it in the plan and the README so freshness is not
   a one-shot.

## Implementation sketch

- **Schema/parse** (`config/schema.rs`, `config/mod.rs`): `Package` gains a `Backend`
  discriminant (`Nix{attr}` | `Mise{token}`), parsed from the value prefix at resolve time.
  Bare/unknown prefix → drop + warn (the parsed `Package` carries the verdict). Charset
  validation: `nix:` attr as today; `mise:` token validated for safe positional passing.
- **Admission** (`packages.rs::admit`): posture unchanged (trusted-only) — now spans both
  backends. `Nix` admitted → host-side `provision`. `Mise` admitted → collected for the
  global in-cage equip.
- **Launch** (`launch.rs`): admitted `mise:` package tokens drive a **global-equip wrap**
  (`mise use -g "${tokens}"` — installs AND activates globally → on PATH), distinct from the
  existing **local** `.mise.toml` auto-equip (`mise install`). Tokens **positional** (reuse
  the multi-backend no-shell-injection wrap). Compose **inside** `egress::wrap_command`
  (socat up first). For `ops app`: pass only the app's `[packages] mise:` tokens; suppress
  the project's `.mise.toml` local auto-equip.
- **`ops config`** (`main.rs`): per-package backend + posture line.
- **Migration**: 3 profiles → prefixed fresh backends; existing `[packages]` tests/configs →
  prefixed; `ops search` declare-hints (`[packages] <pkg> = "nix:<attr>"`); docs
  (`profiles/README.md`, CLAUDE.md, memory).

## Profiles after migration

```toml
# claude-code.toml
[packages]
claude-code = "mise:aqua:anthropics/claude-code"   # 2.1.185, fresh, no unfree gate
# codex.toml
[packages]
codex = "mise:aqua:openai/codex"                   # 0.141.0
# opencode.toml
[packages]
opencode = "mise:opencode"                         # 1.17.9
```

## Tests

- **Schema** unit: `nix:`/`mise:` parse; bare → drop+warn; token round-trip.
- **Config** unit: admit trusted-only both backends; untrusted `mise:` dropped; app-overlay
  merge keeps the app's (trusted) package; the flagship untrusted-override refusal.
- **Launch** unit: `mise:` packages → global-equip wrap (`mise use -g`, tokens positional);
  `ops app` excludes the project `.mise.toml`; nix path unchanged.
- **e2e** (`tests/run.rs`): a trusted profile with `mise:aqua:anthropics/claude-code` →
  `ops app` → `claude --version` = 2.1.185, **fetched under the profile's own allowlist**
  (assert the nix-cache allow-set carries the github fetch; not wide-open), no node, unfree
  irrelevant. Skip-not-fail offline.
- **Migration**: the `shipped_profiles_import_and_resolve` test updated to the prefixed form.

## Risks / notes

- **`mise use -g` concurrency** (advisor — blocking to confirm before relying on it). It
  rewrites the home's global `config.toml` **every launch**, so two launches of the same app
  (the "2nd terminal") race that write — the same class fixed for plugin registration with an
  atomic symlink. Confirm `mise use -g` is concurrency-safe (atomic write / lock), or spike it,
  before building on it. Skip the equip when the version is already active to avoid needless
  rewrites.
- **Offline, stated accurately** (advisor). A `mise:` package fetches at install. For
  `home_scope = "global"` apps (the default) the global mise config is shared across projects
  **but the store is per-project**, so the per-launch equip re-installs into each new project's
  store: online everywhere, **offline fails on the first launch *per project*** (not merely
  "first launch ever"). It self-heals online — tolerable, but document it precisely; do not
  claim `mise:` is uniformly "durable, always-on".
- **`mise use -g` PATH precedence**: verify the global install persists in the home and the
  app's `cmd` resolves to it, **ahead of any project `.mise.toml` shim** (decision 5).
  Two-launch persistence check + a shadowing check (a project `.mise.toml` tool of the same
  name must not win over the app's `[packages]`).
- **The allowlist e2e is the load-bearing proof — it must RUN, not skip** (advisor).
  `aqua:anthropics/claude-code`=2.1.185 is proven under *shared* network, NOT yet under the
  profile's own `["api.anthropic.com"]` allowlist (the release-asset fetch rides
  `*.githubusercontent.com` in the built-in nix-cache allow-set — the new fact). The e2e must
  execute and assert the fetch succeeds under the profile's allowlist (apply the prior "exit 0
  was tail's status" lesson — confirm it ran, not skipped).
- **Export round-trip** (advisor): `serialize_app`/`parse_app` must round-trip a
  `mise:`-prefixed `[packages]` value, since the profiles now carry them — add to the
  round-trip test.
- **`/usr/bin/env` gap** is NOT needed here (aqua/registry standalone binaries avoid the npm
  shebang); it stays a separate future fix for npm-only tools.
