# `nixpkgs` — pin the channel or revision

Override the nixpkgs reference the base userland and tools resolve against.

```toml
nixpkgs = "nixos-23.11"                                   # a branch/channel
# nixpkgs = "3e0ce8c5d4a1...40-hex-revision..."          # an exact revision
```

`nixpkgs` is a **security field** — honored from the global config or a trusted
project, ignored from an untrusted one — because the source of your toolchain is a
supply-chain-relevant choice.

See also: [Provisioning](../concepts/provisioning.md) · [`sbx upgrade`](../housekeeping/upgrade.md) · [`packages`](packages.md).

## What it accepts

- A **branch/channel** name — e.g. `nixos-23.11`, `nixos-unstable` (the default when
  unset).
- A **40-hex revision** under `NixOS/nixpkgs` — an exact, immutable pin.

The value is charset-validated before it reaches a flake reference. Forks and
arbitrary flake refs are not accepted.

## One channel pins the whole sandbox

A per-project `nixpkgs` pin pins **both** the base userland (glibc, gcc, bash,
coreutils, the curated base tools) **and** the `nix:` tools, from **one** effective
channel:

```
project pin  ??  global override  ??  default (nixos-unstable)
```

This is deliberate. The cage exports the base glibc on `LD_LIBRARY_PATH` for foreign
binaries, and nixpkgs uses `RUNPATH` (searched after it), so a tool pinned to a
*different* glibc than the base would load the base `libc.so.6` under its own loader
and crash with a `GLIBC_PRIVATE` mismatch. Keeping base and tools on one channel keeps
their glibc aligned.

(An exception: `nix:` tools declared in a [`[tools]`](tools.md) mise file each resolve
to their own revision and run via the [nix-ld shim](../concepts/provisioning.md), which
handles the skew. The coarse `nixpkgs` field stays channel-wide by design — it is the
OS-substrate layer.)

## Source-aware locks

The resolved revision is recorded in a lock so versions do not move on an `sbx` binary
update — only on an explicit [`sbx upgrade`](../housekeeping/upgrade.md):

- A **global** override records to the shared `<data>/nixpkgs.lock`.
- A trusted **project** pin records to a per-project
  `<data>/projects/<id>/nixpkgs.lock`.

Changing the *source* (e.g. `nixos-23.11` → `nixos-24.05`) re-resolves; an unchanged
source stays fixed. A first launch of a pinned project downloads its own base closure
(only pinned projects pay this).

## Rolling a channel forward

A **channel** pin (`nixos-23.11`) advances *within itself* only via `sbx upgrade` run
in that project — a global upgrade would not touch a project's own pin. A **revision**
pin refreshes to itself (a no-op). See [Upgrading](../housekeeping/upgrade.md).

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
[One-shot overrides](overrides.md).
