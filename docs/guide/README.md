# ops — user guide

`ops` is a **sandbox launcher**: a single static Rust binary that runs tools —
including **encapsulated AI agents** — inside a [bubblewrap](https://github.com/containers/bubblewrap)
sandbox where they can install a project's full dependency set via single-user,
daemonless [Nix](https://nixos.org/) **without mutating the host OS**.

This guide is the complete, task-oriented documentation. It is split into small,
cross-linked pages so you can start anywhere and follow the links. For the design
rationale and threat analysis behind each subsystem, each section links out to the
[design documents](#design-documents).

> New to `ops`? Start with [What ops is](concepts/overview.md), then
> [Quick start](getting-started/quickstart.md).

---

## Getting started

- [Installation](getting-started/installation.md) — build the static binary, or a dev build.
- [Quick start](getting-started/quickstart.md) — your first sandboxed command in five minutes.
- [`ops doctor` and prerequisites](getting-started/doctor.md) — the runtime requirements and how to check them.

## Concepts

- [What ops is (and is not)](concepts/overview.md) — the reference class, the two actor modes.
- [Security model](concepts/security-model.md) — same-uid, confidentiality by absence, the bind layout.
- [The trust gate](concepts/trust.md) — the direnv content-hash model, free vs security fields.
- [Enforcement stack](concepts/enforcement.md) — bubblewrap, seccomp, cgroups, Landlock.
- [Provisioning model](concepts/provisioning.md) — the rolling nix channel, the per-project store, self-equip.
- [Directory layout](concepts/directory-layout.md) — where the config, data, and trust state live.

## Configuration (`.ops.toml`)

- [Configuration overview](configuration/README.md) — layering, the trust gate, free vs security fields.
- [`env`](configuration/env.md) — extra environment variables (a free field).
- [`binds`](configuration/binds.md) — extra host paths, read-only or read-write.
- [`packages`](configuration/packages.md) — tools by backend: `nix:` / `mise:` / `flake:`.
- [`[tools]` (mise)](configuration/tools.md) — a project's mise toolchain, auto-equipped in-cage.
- [`nixpkgs`](configuration/nixpkgs.md) — pin the channel or revision.
- [`[limits]`](configuration/limits.md) — cgroup resource limits.
- [`[seccomp]`](configuration/seccomp.md) — relax the mandatory syscall denylist (trusted-only).
- [`gui`](configuration/gui.md) — the Wayland display posture.
- [`network`](configuration/network.md) — the egress posture (links to [Networking](networking/README.md)).
- [`[secret]`](configuration/secret.md) — credential injection (links to [Secrets](secrets/README.md)).
- [`[app.<name>]`](configuration/apps.md) — named launch profiles (links to [Apps](apps/README.md)).
- [`[net.groups]`](configuration/net-groups.md) — reusable egress groups.
- [One-shot overrides](configuration/overrides.md) — `--config`/`--env`/`--net`/… and `OPS_*`.

## Command reference

- [Command index](cli/README.md) — every command at a glance.

| Command | Purpose |
|---|---|
| [`doctor`](cli/doctor.md) | verify the runtime prerequisites |
| [`run`](cli/run.md) | run a command in the sandbox |
| [`shell`](cli/shell.md) | an interactive sandboxed shell |
| [`app`](cli/app.md) | launch or manage named application profiles |
| [`mise`](cli/mise.md) | run the in-cage mise to self-equip a toolchain |
| [`search`](cli/search.md) | discover `nix:` tools via nixhub |
| [`test`](cli/test.md) | check whether an access would be allowed |
| [`net`](cli/net.md) | inspect and manage the egress policy |
| [`plugins`](cli/plugins.md) | manage resolver plugins and plugin stores |
| [`ls` / `attach` / `stop`](cli/ls.md) | the session registry |
| [`trust` / `untrust`](cli/trust.md) | vouch for a project config |
| [`config`](cli/config.md) | inspect and edit the configuration |
| [`upgrade`](cli/upgrade.md) | roll managed toolchains forward |
| [`gc`](cli/gc.md) | reclaim per-project store space |

## Apps and profiles

- [The app framework](apps/README.md) — named, reusable agent launchers.
- [Per-app isolated `$HOME`](apps/home.md) — persistent identity, `home_scope`.
- [Portable profiles](apps/profiles.md) — import, export, and the shipped starter profiles.
- [Profile catalog](apps/catalog.md) — the profiles shipped in this repository.

## Networking (egress)

- [Egress overview](networking/README.md) — the Model-B architecture (empty netns + host proxy).
- [Network modes](networking/modes.md) — `none` / `shared` / `deny` / `allow` / `ask`.
- [Rule grammar](networking/rules.md) — hosts, `*.domain`, URLs, `re:`, `tcp://`, ports, `{VERB}`.
- [Egress groups](networking/groups.md) — reusable `[net.groups]` referenced by `@name`.
- [Ask mode](networking/ask.md) — park-and-confirm requests with `ops net pending`.
- [Observability](networking/observability.md) — `ops net rules` / `stats` / `logs`, `ops test net`.

## Secrets

- [Secrets architecture](secrets/README.md) — the never-in-cage invariant, resolver × broker.
- [Resolvers](secrets/resolvers.md) — the source layer: `env://` / `file://` / `sops://`.
- [Injection](secrets/injection.md) — the http-header broker.
- [Redaction](secrets/redaction.md) — the outbound and inbound tripwires.
- [Resolver plugins and stores](secrets/plugins.md) — third-party resolvers, signed stores.

## Housekeeping

- [Sessions](housekeeping/sessions.md) — `ls`, `attach`, `stop`, and `--detach`.
- [Garbage collection](housekeeping/gc.md) — `ops gc`.
- [Upgrading toolchains](housekeeping/upgrade.md) — `ops upgrade` and the lock model.

## Reference

- [Environment variables](reference/environment-variables.md) — `OPS_*` and the cage environment.
- [Exit codes](reference/exit-codes.md) — what each exit status means.
- [Glossary](reference/glossary.md) — the terms this guide uses.

---

## Reading paths

- **"I want to run an agent on an untrusted project safely."**
  [Security model](concepts/security-model.md) → [Apps](apps/README.md) →
  [Network modes](networking/modes.md) → [Secrets](secrets/README.md).
- **"I want to give my project a reproducible toolchain."**
  [Provisioning](concepts/provisioning.md) → [`packages`](configuration/packages.md) /
  [`[tools]`](configuration/tools.md) → [`ops upgrade`](housekeeping/upgrade.md).
- **"I want to lock down what a tool can reach on the network."**
  [Network modes](networking/modes.md) → [Rule grammar](networking/rules.md) →
  [Ask mode](networking/ask.md) → [Observability](networking/observability.md).
- **"I just want the CLI."** [Command index](cli/README.md).

---

## Design documents

The guide is the *what* and *how*. The `docs/*.md` design documents are the *why* —
the feasibility spikes, the threat model, and the architecture decisions. They are
referenced from the relevant guide pages, and collected here:

- [`bwrap-architecture.md`](../bwrap-architecture.md) — Rust modules, CLI surface, milestones.
- [`bwrap-threat-model-and-binds.md`](../bwrap-threat-model-and-binds.md) — threat model and bind layout.
- [`bwrap-security-stack.md`](../bwrap-security-stack.md) — the enforcement building blocks.
- [`bwrap-secrets-architecture.md`](../bwrap-secrets-architecture.md) — the secret resolver/broker design.
- [`bwrap-net-spike-findings.md`](../bwrap-net-spike-findings.md) — the egress architecture decision.
- [`bwrap-spike-2026-06-14.md`](../bwrap-spike-2026-06-14.md) — the original feasibility spike.
- [`bwrap-store-derisk-2026-06-15.md`](../bwrap-store-derisk-2026-06-15.md) — the store mechanism.
- [`bwrap-seccomp-spike-2026-06-21.md`](../bwrap-seccomp-spike-2026-06-21.md) — the seccomp posture.
- [`bwrap-cgroups-spike-2026-06-21.md`](../bwrap-cgroups-spike-2026-06-21.md) — the cgroup limits.
- [`bwrap-gui-wayland-spike-2026-06-22.md`](../bwrap-gui-wayland-spike-2026-06-22.md) — the Wayland hole.
