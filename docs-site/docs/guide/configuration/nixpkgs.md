---
sidebar_label: "nixpkgs"
description: "Pinning the nixpkgs channel or revision the base userland and tools resolve against."
---

# `nixpkgs`: pin the channel or revision

Override the nixpkgs reference the base userland and tools resolve against.

```toml
nixpkgs = "nixos-23.11"                                   # a branch/channel
# nixpkgs = "3e0ce8c5d4a1...40-hex-revision..."          # an exact revision
```

`nixpkgs` is a **security field**: honored from the global config or a trusted
project, ignored from an untrusted one: because the source of your toolchain is a
supply-chain-relevant choice.

See also: [Provisioning](../concepts/provisioning) · [`sbx upgrade`](../housekeeping/upgrade) · [`packages`](packages).

## What it accepts

- A **branch/channel** name: e.g. `nixos-23.11`, `nixos-unstable` (the default when
  unset).
- A **40-hex revision** under `NixOS/nixpkgs`: an exact, immutable pin.

The value is charset-validated before it reaches a flake reference. Forks and
arbitrary flake refs are not accepted.

## One channel pins the whole sandbox

A per-project `nixpkgs` pin pins **both** the base userland (glibc, gcc, bash,
coreutils, the curated base tools) **and** the `nix:` tools, from **one** effective
channel:

```
project pin  >  global override  >  default (nixos-unstable)
```

This is deliberate. The cage exports the base glibc on `LD_LIBRARY_PATH` for foreign
binaries, and nixpkgs uses `RUNPATH` (searched after it), so a tool pinned to a
*different* glibc than the base would load the base `libc.so.6` under its own loader
and crash with a `GLIBC_PRIVATE` mismatch. Keeping base and tools on one channel keeps
their glibc aligned.

(An exception: `nix:` tools declared in a [`[tools]`](tools) mise file each resolve
to their own revision and run via the [nix-ld shim](../concepts/provisioning), which
handles the skew. The coarse `nixpkgs` field stays channel-wide by design: it is the
OS-substrate layer.)

## Source-aware locks

The resolved revision is recorded in a lock so versions do not move on an `sbx` binary
update, only on an explicit [`sbx upgrade`](../housekeeping/upgrade):

- A **global** override records to the shared `<data>/nixpkgs.lock`.
- A trusted **project** pin records to a per-project
  `<data>/projects/<id>/nixpkgs.lock`.
- An **app** records to `<data>/apps/<name>/nixpkgs.lock`, so one app advances on its own
  and a global roll leaves it where it is. It applies when no project pin does: under a
  pin the app resolves against the project's lock like everything else in that launch,
  because an app launch also builds the project's declared packages. The lock is seeded
  from the global channel's the first time, so an app starts where the base already is.
  See [Rolling one app](../cli/upgrade#an-apps-base-channel).

  The lock is keyed by the app name, `home_scope` included: a `home_scope = "project"`
  app keeps a separate home per project but is still one app, and one app has one pin.
  So rolling it from one project moves it in every project that runs it, and each
  rebuilds at the new revision. Sharing the revision is also what makes the second
  project's launch a store hit rather than a second base userland. It is the same unit
  [`sbx app rm --purge`](../cli/app) uses, which removes the per-project trees along
  with the global one.

Changing the *source* (e.g. `nixos-23.11` → `nixos-24.05`) re-resolves; an unchanged
source stays fixed. A first launch of a pinned project downloads its own base closure
(only pinned projects pay this).

## `[mise] engine`: the engine's own source

The **mise engine** is the program that installs every `mise:` tool in every cage. Its
revision has always been pinned in a lock of its own, `<data>/mise-engine.lock`, separate
from the channel lock above, so `sbx upgrade mise` and `sbx upgrade nix` move different
things. What that lock tracked, until this field existed, was still the global `nixpkgs`
source: the two rolled apart but could not point apart.

`[mise] engine` is the other half of that separation.

```toml
[mise]
engine = "nixos-unstable"                        # a channel: tracked, rolled by `sbx upgrade mise`
# engine = "github:NixOS/nixpkgs/<40-hex rev>"   # a frozen nixpkgs, independent of the global pin
# engine = "github:jdx/mise/<40-hex rev>#default"  # any flake that builds a mise, upstream's own included
```

Unset, the engine follows the global `nixpkgs` source, which is what happens without the
table at all.

`[mise] engine` is a **security field, honored only from the global config**. Unlike
`nixpkgs`, a trusted project does not get one: the engine installs the tools of every app
in every project, so which build of it runs is infrastructure rather than a project's
business.

### What it accepts

- A **channel** (`nixos-unstable`): tracked through the engine's lock, and advanced by
  `sbx upgrade mise` like the global channel is by `sbx upgrade nix`.
- A **40-hex revision**, bare or spelled `github:NixOS/nixpkgs/<rev>`: a frozen nixpkgs
  pin that no upgrade rolls.
- A **flake reference**, `github:<owner>/<repo>/<rev>`, with an optional `#<attr>`. The
  attribute defaults to `mise`, which is what nixpkgs calls the package; mise's own flake
  calls it `default`, so that form writes it out.

The last two forms carry a revision because they *are* the pin. Nothing resolves them, so
`sbx upgrade mise` reports them frozen and the way to move one is to edit it here. A
branch or a tag is refused in that position on purpose: a name can be moved under you, and
this one names the program that installs every other program.

### Reaching past nixpkgs

The reason the flake form exists: nixpkgs packages mise on its own schedule, and that
schedule can fall behind upstream. Everything a `mise:` package installs is fetched
upstream-direct precisely so it does not wait on a packager (see
[`packages`](packages#mise-a-mise-backend)); the engine doing that fetching was the one
component still waiting. Pointing it at `github:jdx/mise/<rev>#default` builds upstream's
own derivation, from source, at a revision you chose.

What it costs, and it is not nothing: that flake carries its own inputs, so a second
nixpkgs enters your store, and mise is compiled rather than substituted from
`cache.nixos.org`. Staying on the nixpkgs attribute keeps the binary cache and the review
that comes with a distribution package. Reach for the flake form when nixpkgs is behind
something you need, not by default.

### Seeing and rolling it

`sbx config show` prints the engine beside the channel, with the origin of each.
`sbx upgrade mise` reports the engine on its own line: rolled forward for a channel,
unchanged for a revision, and frozen for a reference that carries its own.

## Rolling a channel forward

A **channel** pin (`nixos-23.11`) advances *within itself* only via `sbx upgrade` run
in that project, a global upgrade would not touch a project's own pin. A **revision**
pin refreshes to itself (a no-op). An app is the same shape one level down:
`sbx upgrade nix` does not move it, `sbx upgrade nix --app <name>` does. See
[Upgrading](../housekeeping/upgrade).

## Viewing the effective channel

```sh
sbx config show    # the effective source: project pin / global / default
sbx doctor         # the store's channel revision (accurate to disk)
```

## One-shot override

To resolve against a different channel or revision for a single launch without editing
the file, use `--nixpkgs` or `SBX_NIXPKGS`:

```sh
sbx run --nixpkgs nixos-23.11 -- ./build.sh
SBX_NIXPKGS=nixos-unstable sbx run
```

`--nixpkgs` takes a branch/channel name or a 40-hex revision (same as the field). The
command line beats the environment, and both beat the config file. See
[One-shot overrides](overrides).

## Examples

Three postures, and what each costs.

```toml
# unset: nixos-unstable, and the shared store's base closure is already there
```

```toml
# a channel, for a project that must not track unstable
nixpkgs = "nixos-23.11"
```

```toml
# an exact revision, for a build that must be byte-reproducible
nixpkgs = "3e0ce8c5d4a1f5f6b8a1a1a1a1a1a1a1a1a1a1a1"
```

A pinned project downloads **its own** base closure on first launch, since the shared
store's base is on the default channel. That is the whole cost, paid once, and only by
pinned projects.

Globally, for every project on the machine:

```sh
sbx config set --global nixpkgs nixos-23.11
sbx config show                       # which layer the effective value came from
sbx doctor                            # the revision actually realised on disk
```

For one launch, without touching either file:

```sh
sbx run --nixpkgs nixos-23.11 -- ./build.sh
SBX_NIXPKGS=nixos-unstable sbx run -- ./build.sh
```

And when you do want the channel to move, which is never automatic:

```sh
sbx upgrade nix                       # re-resolve this project's channel and rewrite its lock
sbx upgrade nix --project ~/src/other # …for another project, without cd-ing there
```

A revision pin refreshes to itself, so `upgrade` on it is a reported no-op rather than
an error.
