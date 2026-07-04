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

A launch reads these locks; it does not re-resolve. So updating the `ops` binary leaves
your versions exactly where they were. `ops upgrade` is the one place that rewrites a
lock.

## The upgrade targets

```sh
ops upgrade [all|nix|mise|flake]
```

| Target | Rolls forward |
|---|---|
| `nix` | the nixpkgs channel — the base userland and native `nix:` packages |
| `mise` | the mise engine, the project's `nix:` tools, and `mise:` packages |
| `flake` | the project's and apps' `flake:` packages |
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
