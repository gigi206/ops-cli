# Upgrading toolchains

`ops` treats the versions of your toolchain as **data-directory state**, not something
baked into the binary. Versions move **only** when you run `ops upgrade` — never on an
`ops` binary update. This is the "seeded not baked" contract.

See also: [`ops upgrade`](../cli/upgrade.md) · [Provisioning](../concepts/provisioning.md) · [`nixpkgs`](../configuration/nixpkgs.md) · [`packages`](../configuration/packages.md).

## Why versions do not move on a binary update

A project's base userland and tools are pinned by **locks** in the data directory (see
[Directory layout](../concepts/directory-layout.md)):

- `<data>/nixpkgs.lock` — the global base channel revision.
- `<data>/mise-engine.lock` — the mise engine revision (independent of the base).
- `<data>/projects/<id>/nixpkgs.lock` — a project's own channel pin.
- `<data>/projects/<id>/tools.lock` — resolved `nix:` mise tools.
- `<data>/projects/<id>/flake-packages.lock` — pinned `flake:` packages.
- `<data>/projects/<id>/deb-packages.lock` — pinned `deb:` packages (URL → content hash).

A launch reads these locks; it does not re-resolve. So updating the `ops` binary leaves
your versions exactly where they were. `ops upgrade` is the one place that rewrites a
lock.

## The upgrade targets

```sh
ops upgrade [all|nix|mise|flake|deb]
```

| Target | Rolls forward |
|---|---|
| `nix` | the nixpkgs channel — the base userland and native `nix:` packages |
| `mise` | the mise engine, the project's `nix:` tools, and `mise:` packages |
| `flake` | the project's and apps' `flake:` packages |
| `deb` | the project's and apps' `deb:` packages |
| `all` | all of the above (the default) |

The three are **decoupled**: `ops upgrade nix` leaves `mise-engine.lock` untouched, and
`ops upgrade mise` leaves `nixpkgs.lock` intact.

## Context-aware

`ops upgrade` re-resolves the source the **current directory** tracks and rewrites *that*
lock:

- In a project with a trusted [`nixpkgs`](../configuration/nixpkgs.md) pin, it rewrites
  the per-project lock — the only way a *channel* pin (`nixos-23.11`) advances within
  itself.
- Otherwise it rolls the global channel.

A *revision* pin refreshes to itself (a reported no-op). An untrusted/changed pin is
dropped, so `upgrade` rolls the global channel and prints the config warning.

## What each backend does on upgrade

- **`nix:`** — re-resolves the channel and rewrites the base lock (and floating `nix:`
  tool pins).
- **`mise:`** — runs an in-cage `mise upgrade` per home (the project baseline and each
  app's home), fetching the latest upstream version. The fetch rides the app's
  [egress allowlist](../networking/modes.md); `network = "none"` skips a home.
- **`flake:`** — re-pins each declared flake ref (`nix flake metadata`) and rewrites
  `flake-packages.lock`; a re-pin builds the newly-locked ref at the next launch.
- **`deb:`** — re-resolves each declared `.deb` URL to its current content hash
  (`nix store prefetch-file`, following a `…/releases/latest/…` redirect) and rewrites
  `deb-packages.lock`; a changed hash rebuilds host-side at the next launch.

## The fresh-release hold (`mise:` packages)

mise applies a built-in **`minimum_release_age`** (24 hours by default): it will not
install an upstream release until it has been public for a day, so a release that is
compromised or broken and then yanked within hours is never picked up. This is mise's own
supply-chain safety default — `ops` does not set it, and it is in none of your configs.

So `ops upgrade mise` can report a newer version yet leave the tool where it is:

```text
mise WARN  newer npm:cline release 3.0.38 … ignored by minimum_release_age (24h); latest eligible release is 3.0.37
mise All tools are up to date
```

This is not an error. The tool is up to date **relative to eligible (≥ 24 h old)
releases**, and a held version installs on the next `ops upgrade` once it crosses the
delay — the warning even prints the exact eligibility time.

### Installing the newest release immediately

A cage does **not** inherit your host environment, and `ops upgrade` takes no override
flags, so exporting `MISE_MINIMUM_RELEASE_AGE` on the host has no effect. The only channel
that reaches the in-cage mise is a trusted [`env`](../configuration/env.md) entry. Set it
in your **global** config (`ops/ops.toml`) to lift the hold for every app:

```toml
[env]
MISE_MINIMUM_RELEASE_AGE = "0"
```

The same entry can be written from the CLI (see [`ops config`](../cli/config.md)) — pass
the bare `0`, since an `env` value is always stored as a string:

```sh
ops config set --global env.MISE_MINIMUM_RELEASE_AGE 0   # every app
ops config set --local  env.MISE_MINIMUM_RELEASE_AGE 0   # this project only
```

Read it back with `ops config get --global env.MISE_MINIMUM_RELEASE_AGE`, or remove it
with `ops config unset --global env.MISE_MINIMUM_RELEASE_AGE`.

Use a shorter duration (`"6h"`, `"1h"`) to soften the delay rather than remove it; delete
the line to restore mise's default. The variable also applies to normal launches, but
there `mise use -g` is a warm no-op, so the effect is concentrated on `ops upgrade`.

> **Trade-off:** lifting the hold removes mise's supply-chain delay — a freshly published
> release is installed without the window that lets a bad one be caught first.

## Locks are written atomically

A lock is rewritten atomically (temp + rename), so a concurrent reader sees old-or-new,
never a torn file, and a failed resolution returns before the write rather than
truncating a known-good lock.

## Examples

```sh
ops upgrade              # roll everything the current context tracks
ops upgrade nix          # just the nixpkgs channel
ops upgrade mise         # the mise engine + this project's mise-managed tools
ops upgrade flake        # re-pin flake: packages
```

After a `flake:` upgrade, run [`ops gc`](gc.md) to reclaim the superseded rev-keyed
out-links.
