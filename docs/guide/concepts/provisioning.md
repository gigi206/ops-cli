# Provisioning

`ops` runs tools inside a hermetic cage that has **no host `/usr`** and **no host
`/nix`**. Everything the cage needs — the base userland, the tools a project
declares, and the tools an agent installs for itself — is provisioned by
**daemonless [nix](https://nixos.org/)** into a store `ops` owns, and bound into the
cage. This page explains that store model and how it stays reproducible.

See also: [Directory layout](../concepts/directory-layout.md) · [`packages`](../configuration/packages.md) · [Upgrading](../housekeeping/upgrade.md).

## nix as a rolling OS on a channel

Think of the base userland as a **rolling distribution pinned as data**. `ops`
tracks the `nixos-unstable` channel by default, but the exact revision it uses is
**data-dir state**, recorded in `nixpkgs.lock`, not baked into the `ops` binary.

The consequence is the property the design calls **"seeded, not baked"**:

> Tool versions move **only** on an explicit `ops upgrade`. Updating the `ops`
> binary never changes what versions your projects get.

`ops upgrade [all|nix|mise|flake]` re-resolves the relevant channel and rewrites its
lock; a launch reads the lock that `upgrade` wrote. See
[Upgrading](../housekeeping/upgrade.md) and the [`ops upgrade` reference](../cli/upgrade.md).

## The shared store

`ops` drives nix **daemonlessly** — no host `/nix`, no `nix-daemon`, no multi-user
setup. It provisions the base userland (glibc, gcc, bash, coreutils, and more) into
its own user-owned store at `<data>/store/nix/store`, keeps each output alive with a
gcroot, and binds that store **read-only** into a cage as `/nix`.

Because provisioning runs *outside* the cage (where capabilities are available),
from-source builds run with nix's own build sandbox on; only *inside* the cage is
nix's sandbox forced off (see [Enforcement](enforcement.md)). A signed,
cache-substituted path is safe to share across projects; the only unsigned paths are
**trusted** local builds you have vouched for, which is why declared
[`packages`](../configuration/packages.md) are a trust-gated security field.

## The per-project writable store

A read-only shared store cannot host an agent that installs its own tools. So each
project also gets its **own real nix store** under `<data>/projects/<id>/`, and the
cage's `/nix` is a **read-write bind of that per-project store** — the Mode-B
inversion. This is **default-on and never a configurable field**: an untrusted
project cannot keep the shared store mounted or widen its access.

The per-project store is **seeded from the shared store** by reflink-or-copy
(`FICLONE`): copy-on-write where the filesystem supports it (near-free), a full copy
on ext4. Each seeded path is a **physically independent inode**. A hard link was
deliberately rejected — a same-uid write through a hard link would poison the shared
base for every other project — so the seed gives each project a private copy that an
in-cage write can only affect locally.

The net effect:

> An agent that self-equips writes **only** into its project's own store. The shared
> store stays immutable, and one project's installs never touch another's.

The per-project directory also holds that project's resolution locks —
`nixpkgs.lock` (a project channel pin), `tools.lock` (resolved `nix:` mise tools),
and `flake-packages.lock` (pinned `flake:` packages). See
[Directory layout](../concepts/directory-layout.md).

## nix and mise in the cage — the agent self-equips

The base userland carries **nix and [mise](https://mise.jdx.dev/) themselves**, so
an agent can equip a project's toolchain from inside the cage, building into the
project's own writable store rather than mutating the host:

```sh
ops mise install nix:jq                 # build jq into the project's store
ops mise use -g aqua:BurntSushi/ripgrep # install and activate a tool (on PATH next launch)
```

A tool installed with `mise use` is auto-on-PATH in later launches; a bare
`ops mise install` installs it but leaves it reachable only through `mise exec`. See
[`tools` configuration](../configuration/tools.md) and the
[`ops mise` reference](../cli/mise.md).

## Hermetic TLS

The cage has no host `/etc/ssl`, so `ops` provisions its **own** CA certificate
bundle (`cacert`) into the base userland and binds it read-only at **both**
conventional certificate paths — `ca-bundle.crt` (nix's libcurl default) and
`ca-certificates.crt` (the OpenSSL / reqwest spelling). Both are needed because the
two TLS clients in the cage disagree on where the bundle lives. In-cage TLS
therefore never depends on the host having a CA bundle.

## A curated base toolset

The base userland ships a small everyday CLI set — `curl`, `git`, `less`, `grep`,
`sed`, `awk`, `find`, `which` — provisioned into `ops`'s store and **sharing the
base glibc**. An agent gets the ordinary tools without declaring them (and the
in-cage mise plugin, which shells out to `find` / `which`, has them available).

## The nix-ld shim for cross-glibc tools

A tool pinned to a *different* nixpkgs channel than the base is built against a
different glibc. To keep it running, the base userland provides a **nix-ld shim** at
the standard loader path: a foreign binary that hard-codes `/lib64/ld-linux…`
resolves the shim, which re-execs the real base loader named in `NIX_LD`, with the
base libraries offered via `NIX_LD_LIBRARY_PATH` (never a global `LD_LIBRARY_PATH`).
This is what lets a cross-channel [`nixpkgs`](../configuration/nixpkgs.md) pin work
without an ABI skew.

## Engine independence (release option)

A release build can be made **self-contained**, embedding its own static engines so
it does not depend on host-installed ones. Behind the `bundled-nix` and
`bundled-bwrap` features, `ops` embeds a static `nix` (2.34.x) and `bwrap` (0.11.x),
materializes them under `<data>/engine/`, and drives its own store with no host nix.
The default build is unchanged and uses the host engines.

The two engines differ in how complete the independence is:

- **nix — total.** When the bundled engine is present, `ops` uses it in preference
  to a host nix.
- **bwrap — partial.** On a host where
  `kernel.apparmor_restrict_unprivileged_userns` is set, only a binary carrying an
  AppArmor profile that allows `userns` may create an unprivileged user namespace,
  and that profile is attached by path to the host's `/usr/bin/bwrap`. So on a
  restricted host `ops` keeps the host `/usr/bin/bwrap` (the only bwrap that can
  create the namespace); on an unrestricted host the bundled engine leads. This
  choice is non-regressive by construction.

`ops doctor` reports which engine it would use and why. See
[`ops doctor`](../getting-started/doctor.md).

## See also

- [Directory layout](../concepts/directory-layout.md) — where the stores and locks live
- [`packages` configuration](../configuration/packages.md) — declaring `nix:` / `mise:` / `flake:` tools
- [`nixpkgs` configuration](../configuration/nixpkgs.md) — pinning the channel
- [`tools` configuration](../configuration/tools.md) — mise `[tools]` and self-equip
- [Upgrading](../housekeeping/upgrade.md) — how versions actually move
- [`ops mise` reference](../cli/mise.md) · [`ops upgrade` reference](../cli/upgrade.md)
- [Enforcement stack](enforcement.md) — the always-on layers the cage runs behind
- Design docs: [store de-risk](../../bwrap-store-derisk-2026-06-15.md) · [architecture](../../bwrap-architecture.md)
