---
sidebar_label: "distro"
description: "Running the cage on a distribution's root filesystem instead of the hermetic nix userland."
---

# `distro`: run the cage on a distribution userland

Replace the cage's hermetic nix userland with a prebuilt distribution root filesystem.

```toml
distro = "oci:docker.io/library/debian:10"
```

Unset (the ordinary case) leaves the cage on the userland `sbx` provisions from its own
store, and nothing about it changes.

`distro` is a **security field**: honored from the global config or a trusted project,
ignored from an untrusted one, because the root filesystem supplies every program the cage
runs. That is the broadest supply-chain choice a configuration can express.

See also: [Provisioning](../concepts/provisioning) · [`packages`](packages) · [`nixpkgs`](nixpkgs) · [`sbx upgrade`](../housekeeping/upgrade).

## When you want one

The nix userland is hermetic and current, which is what most projects want. A distribution
userland answers a different need: building against **that distribution's own** compiler,
headers and libraries: an old glibc a production host still runs, a vendor SDK packaged
only for one distribution, a build whose output has to link against a release's ABI rather
than the newest one.

If what you need is a tool rather than a substrate, reach for [`packages`](packages)
instead: it costs nothing, it works on either userland, and it keeps the cage hermetic.

## What it accepts

An image locator carrying an **explicit prefix**, as every `[packages]` backend does:

```toml
distro = "oci:docker.io/library/debian:10"                 # a registry tag
distro = "oci:ghcr.io/owner/image@sha256:0123…"            # an exact image
distro = "oci:registry.example.com:8443/team/base:2024a"   # a private registry, with a port
```

The registry is written out. A bare `debian:10` is refused, because a reference with no
registry resolves against whatever default the client that reads it happens to carry, and
which host served your userland is not a detail to leave implicit. A reference is required
too: an image named with no tag and no digest floats, and this one names the ground every
process in the cage stands on.

The prefix is what keeps a second image source additive. A locator written today keeps
meaning exactly what it means now when another one is added beside it.

## What the image has to supply

An image is refused, by name, unless it carries all six of these:

| Path | Why the image has to have it |
|---|---|
| `/bin/sh` | the cage's default shell |
| `/bin/bash` | the interactive shell `sbx run` starts |
| `/usr/bin/env` | what a `#!/usr/bin/env` shebang resolves through |
| `/usr/bin/ldd` | read as a literal path by tools that ask which C library they are on |
| `/etc/localtime` | the cage's timezone |
| `/lib64/ld-linux-x86-64.so.2` | the ELF interpreter every dynamically linked program starts through |

These are the paths `sbx` stops providing once an image is in force, and it cannot provide
them anyway: each is a symlink or the loader, and both are created at a destination inside
the image's own read-only tree, which the kernel refuses. So a missing one would leave the
cage without it, and the failure would surface much later as an exec error naming a path
nobody declared. The launch stops instead, and names every path the image lacks.

The criterion is a glibc userland that ships `bash`: `debian:10-slim` satisfies it, and a
bare `alpine` does not, shipping neither `bash` nor a glibc loader. An image of your own
that adds what is missing is the answer there, and the refusal names exactly what to add.

## What `sbx` adds to the unpacked tree

The tree a cage runs on is the image's layers, applied in order, plus the **empty**
directories and files `sbx`'s own mounts need somewhere to land: `/nix`, `/etc/machine-id`,
`/etc/resolv.conf`, `/usr/bin/xdg-open`, `/etc/ssh/ssh_config` and a few more. A
distribution carries the paths it needs, which is not the same set, and a read-only root
cannot be given a mountpoint at launch.

Nothing is read from them: each is a name to mount over, and what the cage sees at every one
of those paths is the mount `sbx` puts there. A path the image already carries is left
exactly as the image left it, symlinks included.

## Where the project can live

`/home` and `/opt` are covered with a private tmpfs, which is where the cage's home and, for
most installations, the project at its real path both land. A project elsewhere is covered
the same way as long as the image leaves that directory empty (`/srv`, `/mnt`, `/media` in
a typical base image), and a top-level directory the image does not have at all is created
empty and covered.

What is refused, by name, is a mount whose destination sits inside a directory the
distribution populated: covering `/etc` to make room for a `[[binds]]` entry at
`/etc/myapp.conf` would empty the distribution's own `/etc`. Bind such a file somewhere the
image leaves free, or build an image that carries it.

## The userland is read-only

The root filesystem is mounted **read-only**. That is the shape, not a precaution:

- The provisioned tree is shared by content, so a cage that could write to it would alter
  what every other cage reads.
- It makes the substrate's rule hold in the filesystem rather than by convention: which
  userland you run on is chosen where the image is named, never from inside the cage.

So a package manager cannot install into the system tree. `apt-get install` and its
equivalents fail, and they fail loudly rather than appearing to succeed.

### Adding a package anyway

A project that needs one library or one set of headers does not need a new image. The
distribution's own tools fetch and unpack into the project, which is writable, with no
privilege and no `sbx` feature involved:

```sh
apt-get -o Dir::State::Lists=/tmp/apt/lists -o Dir::Cache=/tmp/apt/cache \
        download libjq-dev libjq1 libonig5
for deb in *.deb; do dpkg -x "$deb" ./prefix; done
export CPATH=$PWD/prefix/usr/include
export LD_LIBRARY_PATH=$PWD/prefix/usr/lib/x86_64-linux-gnu
```

Two of apt's directories are redirected because its defaults live under the read-only root.
What you get is an unpacked tree, not an installed package: no maintainer scripts run and
no package database records it, so this suits a library, its headers and a self-contained
program, and does not suit anything that needs post-install configuration. You also name the
dependencies yourself, since `download` fetches what you ask for and nothing else.

The archive host has to be reachable: egress is deny-by-default, so add it to the
[allowlist](../networking/rules) for the fetch to succeed.

Because it lands in the project, it survives across sessions and stays out of the shared
image, which is where a dependency belonging to one project should be.

## What `sbx` does not do

- **It does not build images.** It fetches a published one, verifies it against its digest,
  unpacks it, and mounts it. The reference class is the prebuilt `[packages]` backends
  (`deb:`, `tarball:`, `appimage:`), which consume artefacts rather than produce them.
- **It knows no package manager.** No name translation, no per-distribution catalogue. A
  package name in this world is the distribution's own name, the way a `nix:` name is a
  nixpkgs attribute.
- **It replaces the userland, not the kernel.** The cage is a set of namespaces on the host
  kernel, so a distribution userland gives you that distribution's programs and libraries,
  never its kernel behaviour.

The first of those is why any distribution works: nothing in `sbx` is specific to one.

## Living beside the nix tools

Declaring a userland does not take the [`packages`](packages) away. Tools provisioned from
nixpkgs carry their own interpreter and their own libraries, so they run beside the
distribution's without either loading the other's C library. A cage can hold a
distribution's compiler and `sbx`'s own `git`, `jq` and `rg` at once.

Where a name exists on both sides (`grep`, `sed`, `awk`, `find`), the distribution's wins.
That follows from what declaring a userland means: the distribution owns it, and `sbx` adds
what is missing rather than replacing what is there. It is also what a build expects, since
a release's own tools are part of what you came for.

The order on `PATH`, front to back, after the one-command `xdg-open` router that leads every
cage:

1. the tools your configuration declares, and the mise shims
2. `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin` (the image)
3. the nix base userland

So a project's own pin is never displaced by the image, the image beats the base, and both
are reachable. A fixed list rather than the image's declared `PATH`: it is what every
mainstream distribution uses, and a project that needs another one sets `PATH` through
[`env`](env), which wins over all of it.

## Settings a declared image takes over

[`timezone`](timezone) has no effect: the image supplies its own `/etc/localtime`, and `sbx`
stops emitting the link that setting writes. Declaring both is reported as a warning rather
than left to be discovered.

`NIX_LD` and `NIX_LD_LIBRARY_PATH` are not set either. They steer the `nix-ld` shim, which
is not mounted over an image's own loader: a foreign binary gets the distribution's loader
and the distribution's C library, which is the whole reason to declare one.

## Pinning and rolling forward

A tag is resolved once to the image's digest, and that digest is recorded in a lock. Later
launches reuse it: the launch path never queries a registry, and the same digest is what a
second machine gets from the same configuration. The digest is also checked against the bytes
the registry serves, so a pin proves what it names rather than trusting the registry's word.

[`sbx upgrade distro`](../cli/upgrade) is what moves it. A tag is re-resolved to whatever
the registry serves now, and the lock is rewritten when it differs, which is how a moving
tag like `latest` advances, and only then. A locator that already carries a digest refreshes
to itself and reports no change, exactly as a pinned revision does. Nothing is fetched by the
roll: the new root filesystem is unpacked at the next launch.

Which lock is rewritten follows the layer that named the image: a project that declares its
own gets a lock beside its other project state, and a global declaration is pinned once for
the host.

## What it costs

The unpacked tree lives in `sbx`'s store, keyed by the image's digest, so two projects on the
same image share one copy and the second pays nothing. A distribution image is larger than
the tools a hermetic cage carries, and that is the price of the userland.

## Viewing the effective value

```sh
sbx config show    # the locator in effect, and which layer named it
```

The line appears only when a layer named a userland, so a cage on the hermetic nix userland
reads as it always did.
