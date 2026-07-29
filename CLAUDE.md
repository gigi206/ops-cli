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
- **Current status — the bwrap rewrite is far along: M2 through the main M6 slices have shipped;
  the genuinely-remaining pieces are blocked on the user.** **Provisioning (M3) complete through
  M3.5** — the per-project writable store + the Mode-B `/nix` read-write inversion, nix-in-cage
  self-equip, `ops mise` passthrough + tool activation, `ops upgrade [nix|mise|flake]`, hermetic
  TLS + a curated base toolset, and `ops search`. **Enforcement (M4) complete** — seccomp denylist
  (Posture A, now trusted-relaxable via `[seccomp] allow`) + cgroup v2 resource limits + a trusted
  `[devices]` host-device grant into the cage's minimal `/dev` (Landlock-FS
  is a deferred defense-in-depth option, not a gap). **Housekeeping (M5) complete** — `ops gc [--all] [--prune]` (session + per-project +
  shared-store collection, including the stale rev-keyed flake out-link residual), `ops attach
  <id>`, `ops stop <id>… | --all`, and a `--detach` background-agent path; the **one open M5 parity
  hole is ssh-agent forwarding** (`$SSH_AUTH_SOCK`, a scoped trusted-only opt-in, deferred — the
  `container socket` row is N/A on this branch). **Network + secrets (M6) largely shipped** —
  Model-B egress (empty netns + an in-cage forwarder → a host MITM allowlisting proxy), host-side
  credential injection with outbound/inbound redaction, and the resolver / plugin / signed-store
  layer. **The `ops app` framework + 48 importable profiles and 26 bundles shipped** — named agent launchers with a
  per-app isolated `$HOME`, export/import, and `nix:` / `mise:` / `flake:` package backends. **The
  two genuinely-remaining pieces are blocked on the user:** the flagship live-auth e2e (a real API
  key, never the assistant's) and the signed-store *distribution* of profiles (a hosting URL + a
  long-term signing key). **Beyond the milestones, the shipping binary is now self-contained** — it
  embeds its own static `nix` (2.34.7) and `bwrap` (0.11.2) engines behind the `bundled-nix` /
  `bundled-bwrap` features, materialized under `<data>/engine/`, so a release no longer depends on
  host-installed engines; bwrap independence is *partial* (the host's path-profiled `/usr/bin/bwrap`
  is kept where `kernel.apparmor_restrict_unprivileged_userns` is set).**
- **The per-increment record is the git history, not this file.** Each change carries its
  reasoning in its own commit message, next to the diff that made it — read it with
  `git log -p`, search it with `git log -S '<term>'` or `git log --grep '<term>'`. Do not
  append an increment log here: this file is loaded in full at the start of every session,
  so anything added to it is paid for on every task whether it is relevant or not.
