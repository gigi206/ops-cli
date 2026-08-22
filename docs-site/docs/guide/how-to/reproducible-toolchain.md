---
sidebar_label: "Reproducible toolchain"
description: "Declare a project's tools with `packages` and mise, pin them, upgrade deliberately, and reclaim the space."
---

# Give a project a reproducible toolchain

The goal: every launch of this project gets the same tools at the same versions,
without touching the host OS, with upgrades done deliberately rather than by drift.

Prerequisites: `sbx` installed ([installation](../getting-started/installation)).

## 1. Declare the tools

`.sbx.toml` names tools; sbx resolves them per backend:

```toml
[packages]
jq       = "nix:jq"                        # host-side nix store, shared across projects
ripgrep  = "mise:aqua:BurntSushi/ripgrep"  # installed in-cage by mise
fzf      = "flake:github:nix-community/fzf" # a flake ref
```

Each backend differs in where it installs and what tracks upstream:
[`packages`](../configuration/packages) is the full reference.

## 2. Pin the base channel

The `nix:` backend builds against a nixpkgs revision recorded in a lock file: global
by default, one per app when a profile pins its own. Pin it explicitly when
reproducibility matters more than freshness:

```toml
[nixpkgs]
revision = "..."
```

What lives where: [Directory layout](../concepts/directory-layout); the field:
[`nixpkgs`](../configuration/nixpkgs).

## 3. Let the project's mise toolchain come along

A project that already carries a `.mise.toml` keeps working: `[tools]` equips that
toolchain inside the cage on demand:

```toml
[tools]
this-project-only = true
```

Reference: [`[tools]`](../configuration/tools); running mise explicitly:
[`sbx mise`](../cli/mise).

## 4. Upgrade deliberately

Nothing moves on its own: launches read the lock, never the channel head.

```sh
sbx upgrade nix              # roll the global base channel forward
sbx upgrade nix --app webui  # roll one app's pinned channel only
sbx upgrade mise             # advance the mise-installed tools
```

Each verb rewrites the corresponding lock and says so; the lock model and its
per-target rules: [Upgrading toolchains](../housekeeping/upgrade),
reference: [`sbx upgrade`](../cli/upgrade).

## 5. Reclaim superseded builds

Rolling leaves the previous builds in the store until you ask:

```sh
sbx gc            # reclaim what nothing references any more
sbx store         # see what sbx occupies before deciding
```

Reference: [`sbx gc`](../cli/gc), [`sbx store`](../cli/store).
