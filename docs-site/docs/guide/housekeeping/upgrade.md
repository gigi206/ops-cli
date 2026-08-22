---
description: "Why a binary update moves no version, what each backend does on `sbx upgrade`, and the lock model behind it."
---

# Upgrading toolchains

`sbx` treats the versions of your toolchain as **data-directory state**, not something
baked into the binary. Versions move **only** when you run `sbx upgrade`: never on an
`sbx` binary update. This is the "seeded not baked" contract.

See also: [`sbx upgrade`](../cli/upgrade) · [Provisioning](../concepts/provisioning) · [`nixpkgs`](../configuration/nixpkgs) · [`packages`](../configuration/packages).

## Why versions do not move on a binary update

A project's base userland and tools are pinned by **locks** in the data directory (see
[Directory layout](../concepts/directory-layout)):

- `<data>/nixpkgs.lock`: the global base channel revision.
- `<data>/mise-engine.lock`: the mise engine revision (independent of the base).
- `<data>/projects/<id>/nixpkgs.lock`: a project's own channel pin.
- `<data>/apps/<name>/nixpkgs.lock`: one app's own base channel revision.
- `<data>/projects/<id>/tools.lock`: resolved `nix:` mise tools.
- `<data>/projects/<id>/flake-packages.lock`: pinned `flake:` packages.
- `<data>/projects/<id>/deb-packages.lock`, pinned `deb:` packages (declared source → content hash, plus the resolved download URL for a `deb:resolve` package).
- `<data>/projects/<id>/appimage-packages.lock`, pinned `appimage:` packages (declared source → content hash, plus the resolved download URL for an `appimage:resolve` package).
- `<data>/projects/<id>/tarball-packages.lock`, pinned `tarball:` packages (declared source → content hash, plus the resolved download URL for a `tarball:resolve` package).
- `<data>/projects/<id>/binary-packages.lock`, pinned `binary:` packages (declared source → content hash, plus the resolved download URL for a `binary:resolve` package).

A launch reads these locks; it does not re-resolve. So updating the `sbx` binary leaves
your versions exactly where they were. `sbx upgrade` is the one place that rewrites a
lock.

## The upgrade targets

```sh
sbx upgrade [all|nix|mise|flake|deb|appimage|tarball|binary|provision]
```

| Target | Rolls forward |
|---|---|
| `nix` | the nixpkgs channel: the base userland and native `nix:` packages |
| `mise` | the mise engine, the project's `nix:` tools, `mise:` packages, and the declared operations' tool pool |
| `flake` | the project's and apps' `flake:` packages |
| `deb` | the project's and apps' `deb:` packages |
| `appimage` | the project's and apps' `appimage:` packages |
| `tarball` | the project's and apps' `tarball:` packages |
| `binary` | the project's and apps' `binary:` packages |
| `all` | every lock-rewriting target above (the default); `provision` is not part of it |
| `provision` | re-runs the apps' bundle install steps in-cage, one cage per app |

See [`sbx upgrade`](../cli/upgrade) for the flags (`-a <name>`, `--project <path>`) and
the per-target behavior.

The three are **decoupled**: `sbx upgrade nix` leaves `mise-engine.lock` untouched, and
`sbx upgrade mise` leaves `nixpkgs.lock` intact.

## Context-aware

`sbx upgrade` re-resolves the source the **current directory** tracks and rewrites *that*
lock:

- In a project with a trusted [`nixpkgs`](../configuration/nixpkgs) pin, it rewrites
  the per-project lock, the only way a *channel* pin (`nixos-23.11`) advances within
  itself.
- With `--app <name>` and no such pin, it rewrites that app's lock and nothing else.
- Otherwise it rolls the global channel, which no app follows.

A *revision* pin refreshes to itself (a reported no-op). An untrusted/changed pin is
dropped, so `upgrade` rolls the global channel and prints the config warning.

## What each backend does on upgrade

| Backend | On `sbx upgrade` | Lock file rewritten |
|---|---|---|
| `nix:` | re-resolves the channel (and floating `nix:` tool pins) | the base lock |
| `mise:` | runs an in-cage `mise upgrade` per home | none (versions live in the home) |
| `flake:` | re-pins each declared flake ref (`nix flake metadata`) | `flake-packages.lock` |
| `deb:` | re-resolves each source to its current `.deb` URL + content hash | `deb-packages.lock` |
| `appimage:` | the same, for a prebuilt `.AppImage` | `appimage-packages.lock` |
| `tarball:` | the same, for a prebuilt `.tar.gz` | `tarball-packages.lock` |
| `binary:` | the same, for a program downloaded as itself | `binary-packages.lock` |

Re-resolution follows a `…/releases/latest/…` redirect, and re-queries the release list or
the apt index for the `github:` / `apt:` locator forms (`nix store prefetch-file`). An
`appimage:github:` locator likewise re-reads the latest release asset.

For every backend but `mise:`, a changed hash **rebuilds host-side at the next launch**,
re-pointing the package's name-keyed out-link at the new build. Nothing is rebuilt during
`upgrade` itself.

### The newest eligible release, not the newest release

For `mise:` packages there is one more filter between "what upstream published" and "what the roll
pins". mise holds a release back until it has been public for a while, a supply chain protection
against an artefact replaced moments ago. sbx neither sets that delay nor overrides it, so a roll
advances a pin to the newest release that has cleared it. When a newer one exists but is still
inside the window, mise says so and the pin stays where it is:

```
newer npm:cline release 3.0.56 ignored by minimum_release_age; latest eligible release is 3.0.55
```

That is the roll working, not failing. It has one sharp edge: a vendor that publishes several times
a day never has an eligible release at all, so the package resolves to no version and can be neither
equipped nor rolled. The cure is per package and is declared where the package is, in
[`accepts_fresh_releases`](../configuration/packages#accepts_fresh_releases-when-the-vendor-publishes-faster-than-the-delay).

### `mise:` and the allowlist

The fetch rides the app's [egress allowlist](../networking/modes), so a home whose
profile sets `network = "none"` is skipped.

### The `resolve` forms

`deb:`, `appimage:`, `tarball:` and `binary:` each accept a `resolve` form, for a vendor that offers a
download API but no `latest`/apt/`github:` locator. On upgrade, `sbx` re-runs the package's
`[deb.<name>]` / `[appimage.<name>]` / `[tarball.<name>]` `resolve` command **in a hermetic
sandbox** to discover the current download URL, so those packages still roll forward. The
heavy artifact is re-fetched only when that URL actually changed.

A direct `tarball:<url>` (no `resolve`) re-resolves the same URL, so a version-stamped one is
effectively frozen: its path names the version.

## The fresh-release hold (`mise:` packages)

mise applies a built-in **`minimum_release_age`** (24 hours by default): it will not
install an upstream release until it has been public for a day, so a release that is
compromised or broken and then yanked within hours is never picked up. This is mise's own
supply-chain safety default: `sbx` does not set it, and it is in none of your configs.

So `sbx upgrade mise` can report a newer version yet leave the tool where it is:

```text
mise WARN  newer npm:cline release 3.0.38 … ignored by minimum_release_age (24h); latest eligible release is 3.0.37
mise All tools are up to date
```

This is not an error. The tool is up to date **relative to eligible (≥ 24 h old)
releases**, and a held version installs on the next `sbx upgrade` once it crosses the
delay: the warning even prints the exact eligibility time.

### Installing the newest release immediately

A cage does **not** inherit your host environment, and `sbx upgrade` takes no override
flags, so exporting `MISE_MINIMUM_RELEASE_AGE` on the host has no effect. The only channel
that reaches the in-cage mise is a trusted [`env`](../configuration/env) entry. Set it
in your **global** config (`sbx/sbx.toml`) to lift the hold for every app:

```toml
[env]
MISE_MINIMUM_RELEASE_AGE = "0"
```

The same entry can be written from the CLI (see [`sbx config`](../cli/config)): pass
the bare `0`, since an `env` value is always stored as a string:

```sh
sbx config set --global env.MISE_MINIMUM_RELEASE_AGE 0   # every app
sbx config set --local  env.MISE_MINIMUM_RELEASE_AGE 0   # this project only
```

Read it back with `sbx config get --global env.MISE_MINIMUM_RELEASE_AGE`, or remove it
with `sbx config unset --global env.MISE_MINIMUM_RELEASE_AGE`.

Use a shorter duration (`"6h"`, `"1h"`) to soften the delay rather than remove it; delete
the line to restore mise's default. The variable also applies to normal launches, but
there `mise use -g` is a warm no-op, so the effect is concentrated on `sbx upgrade`.

> **Trade-off:** lifting the hold removes mise's supply-chain delay: a freshly published
> release is installed without the window that lets a bad one be caught first.

## Locks are written atomically

A lock is rewritten atomically (temp + rename), so a concurrent reader sees old-or-new,
never a torn file, and a failed resolution returns before the write rather than
truncating a known-good lock.

## Examples

```sh
sbx upgrade              # roll everything the current context tracks
sbx upgrade nix          # just the nixpkgs channel
sbx upgrade mise         # the mise engine + this project's mise-managed tools
sbx upgrade flake        # re-pin flake: packages
```

After a `flake:` upgrade, run [`sbx gc`](gc) to reclaim the build the roll superseded
(the old build its name-keyed out-link no longer points at).

## Reclaiming superseded builds

A roll is what eventually supersedes a build (an old base revision, a rebuilt tool, a
rolled-forward app), and those accumulate in the project's store. `sbx upgrade` therefore
ends by reporting how many superseded builds the current project's store is holding, when
any are:

```
3 superseded build(s) in this project's store are reclaimable — run `sbx gc --prune`.
```

The check is a cheap filesystem read (no provisioning, no nix) and stays silent when there
is nothing to reclaim. It only reports: reclaiming is always the explicit, irreversible
[`sbx gc --prune`](gc).
