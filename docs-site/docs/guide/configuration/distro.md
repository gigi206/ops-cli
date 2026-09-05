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

The table form adds four keys: `image` for naming the image as a table value, `auth` for [a private registry](#a-private-registry), and
`from` plus `run` for [building your own userland](#building-your-own-userland).

The registry is written out. A bare `debian:10` is refused, because a reference with no
registry resolves against whatever default the client that reads it happens to carry, and
which host served your userland is not a detail to leave implicit. A reference is required
too: an image named with no tag and no digest floats, and this one names the ground every
process in the cage stands on.

The prefix is what keeps a second image source additive. A locator written today keeps
meaning exactly what it means now when another one is added beside it.

## Building your own userland

`image` takes a published image as it is. `from` plus `run` derives one from it:

```toml
[distro]
from = "oci:docker.io/library/debian:12-slim"
run  = [
  "printf 'APT::Sandbox::User \"root\";\\n' > /etc/apt/apt.conf.d/00-sbx-rootless",
  "apt-get update",
  "apt-get install -y --no-install-recommends build-essential",
]

[network]
mode  = "allow"
allow = ["http://deb.debian.org", "http://security.debian.org"]
```

The first line is Debian's, not `sbx`'s, and it is here because it is the one thing that is
not obvious. A build runs as uid 0 **inside its own user namespace**, which is what `dpkg`
checks for; exactly one uid can be mapped that way without a privileged helper, so it is 0
and nothing else. Debian's `apt` drops to the `_apt` user before fetching, that uid is not
mapped, and the fetch fails with `seteuid 42 failed`. Telling apt not to drop is the fix, and
it is a line you write because you know your distribution: `sbx` neither knows it nor
supplies it.

The allowlist entries name the **scheme** for the reason [the recipe
below](#adding-a-package-anyway) explains: Debian fetches over plain `http`, which the egress
proxy refuses unless the entry says so.

`sbx` understands **none** of those commands. Each is a line handed to the image's own
`/bin/sh`, so what a command means is what that distribution means by it: there is no
package-manager knowledge here and no name translation. That is the same property the
consuming path has, and it is why both work on a distribution nobody here has heard of.

`image` and `from` say different things about the same field, so declaring both is refused
by name rather than resolved by precedence. `run` beside `image` is refused too: it would
read as "and also run this every launch", which is neither what it does nor something `sbx`
offers. `from` with no `run` derives nothing, so it is simply taken as the image.

### It is built once, and rebuilt when it should be

The result is named by the base digest and the commands **together**. Editing a command
therefore builds a different userland rather than mutating this one, and so does a base that
moved. Two projects writing the same base and the same commands share one tree.

The build runs at the first launch that needs it, like every other provisioning here, and
each command is bounded: one that waits on a prompt nobody can answer is killed after ten
minutes rather than hanging the launch for ever.

[`sbx upgrade distro`](../cli/upgrade) re-resolves the base and says which of the two moved:

```
sbx upgrade — distribution image
  image: oci:docker.io/library/debian:12-slim  (project)
  rebuilt 4a1c9e2 → 88f0b31 (the base moved bb3dc79 → e5b6442) — built on the next launch.
```

### What the build sees

The tree, writable, and the minimum around it: a `/proc`, a `/dev`, a `/tmp`, the resolver
configuration and the certificate roots. Not `/nix`, not a home, and above all **not the
project**: a build is not a launch, and a command that could read the project could carry it
into an image other projects then share. No `[secret]` injection reaches it either.

What it does get is everything that confines a launch. The mandatory
[seccomp filter](../concepts/enforcement) is loaded here as it is everywhere, and the cage
runs inside the same [resource scope](limits) a session does. Both matter more here than on
the consuming path rather than less: what runs is the distribution's own package tooling,
mapped to uid 0 inside its namespace, on a root it may write.

The egress is the one the project declared, applied unchanged, on the rule the
[bundles' install step](bundles#the-install-step) already follows: a command that downloads
needs its host in the project's own [allowlist](../networking/rules), visible rather than
implied. Under an allowlist the build gets a proxy of its own, because the userland has to
exist before the launch's proxy does, and it runs on its own control plane so a build's
refusal can never widen the agent's allowlist through `--net-learn`. One consequence worth
knowing: a `tcp://` rule does not apply to a build, since those are served by an in-cage
forwarder this cage does not carry.

A failed command fails the launch and names itself. What it had already written is left in a
directory no launch will ever look up, so a build that stopped half way leaves nothing behind
that could be mistaken for a userland.

A reclaim never builds one. [`sbx gc`](../cli/gc) prepares the project in order to
re-root the tools it is about to collect, and that preparation stops short of the userland:
it fetches no image, unpacks no tree and runs no command. It has nothing to gain by doing so,
because what it keeps is decided by the locks on disk and the sessions that are live, and a
tree it created on the way would be one more thing to reason about rather than one less. A
project whose derived userland is not built yet still has none after a reclaim.

## A private registry

The table form adds a credential:

```toml
[distro]
image = "oci:registry.example.com/team/base:2024a"
auth  = "env://REGISTRY_TOKEN"
```

`image` is the same locator the string form takes; the two spellings mean the same thing, so
a configuration that never needs a credential keeps writing `distro = "..."`.

`auth` is a **reference to a secret**, never a secret: the same schemes
[`secret`](secret) accepts (`env://VAR`, `file:///abs/path`, `sops://file#key`, a resolver
plugin's own scheme), resolved by the same resolver. A password written in a config is a
password in the shell history, the backup and the diff.

It resolves to `<username>:<password>`, which is what a registry's token service exchanges
for a token. Three properties are worth stating, because they are what the code is shaped
around:

- **Host-side.** It is resolved before the cage exists and never bound into it. A credential
  the cage could read is a credential every program in the cage has.
- **On the token request only.** Once the registry has issued a token, that token is what
  every later request carries. The credential itself never reaches the registry's blob
  storage or its CDN.
- **Never through a redirect.** A blob hand-off names a URL nobody here reviewed, and a
  credential that followed one would be handed to whoever the registry named.

A registry that answers with a `Basic` challenge instead of pointing at a token service, as
a self-hosted one often does, gets the credential on the request itself. That is the only
other place it goes.

`sbx config show` names the *source* (`env REGISTRY_TOKEN`), never the value, so the output
stays something you can paste into a bug report.

One limit worth knowing: a resolver plugin that itself reaches a **broker** cannot serve
this. A launch starts its brokers well after the userland it is about to run on has to
exist, so there is nothing for such a plugin to reach, and it fails with its own message
rather than resolving to something unexpected.

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
mkdir -p /tmp/apt/lists/partial /tmp/apt/cache
apt-get -o Dir::State::Lists=/tmp/apt/lists -o Dir::Cache=/tmp/apt/cache update
apt-get -o Dir::State::Lists=/tmp/apt/lists -o Dir::Cache=/tmp/apt/cache \
        download libjq-dev libjq1 libonig5
for deb in *.deb; do dpkg -x "$deb" ./prefix; done
export CPATH=$PWD/prefix/usr/include
export LD_LIBRARY_PATH=$PWD/prefix/usr/lib/x86_64-linux-gnu
```

Two of apt's directories are redirected because its defaults live under the read-only root,
and the `partial` subdirectory is created because apt does not create it itself.

What you get is an unpacked tree, not an installed package: no maintainer scripts run and
no package database records it, so this suits a library, its headers and a self-contained
program, and does not suit anything that needs post-install configuration. You also name the
dependencies yourself, since `download` fetches what you ask for and nothing else.

The archive host has to be reachable, and **naming the host is not enough**. Debian's
`sources.list` fetches over plain `http://`, which the egress proxy refuses unless the
allowlist entry says so: apt reports `403 Forbidden [IP: 127.0.0.1]`, which is `sbx`
answering, not the archive. Name the scheme:

```toml
[network]
mode  = "allow"
allow = ["http://deb.debian.org", "http://security.debian.org"]
```

Apt is not less safe for it: it verifies the archive by GPG signature rather than by
transport, which is why Debian publishes over `http` in the first place.

A release that has left security support is on a different host. `debian:10` is archived, so
its entries are `http://archive.debian.org` and its `sources.list` needs rewriting to match;
a supported release needs neither.

Because it lands in the project, it survives across sessions and stays out of the shared
image, which is where a dependency belonging to one project should be.

## What `sbx` does not do

- **It does not produce images.** It fetches a published one, verifies it against its
  digest, unpacks it, and mounts it. A [derived userland](#building-your-own-userland) is a
  tree under `sbx`'s own data directory, named by what it was built from, that nothing but
  `sbx` reads and no other tool can consume; the base under it is always an image somebody
  else published. The reference class is the prebuilt `[packages]` backends (`deb:`,
  `tarball:`, `appimage:`), which consume artefacts rather than produce them.
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

## What it costs, and how to get it back

The unpacked tree lives under `sbx`'s data directory, beside the nix store rather than in
it: it holds no nix paths and nix knows nothing about it. It is keyed by the image's
digest, so two projects on the same image share one copy and the second pays nothing. A
distribution image is larger than the tools a hermetic cage carries, and that is the price
of the userland.

[`sbx store`](../cli/store) counts it with everything else, and
[`sbx gc --all --prune`](../cli/gc) frees the trees nothing names any more: an image you
tried once, or the one a roll moved past. Two things keep a tree, and they answer different
questions. A lock naming its digest keeps it, because that is what the next launch of that
project wants. A **running** session keeps it too, whatever the locks now say, because a
cage executes out of that tree: freeing it under one leaves it mounted on nothing, and its
own shell disappears mid-command. So a roll during a long session does not put that session
at risk, and the tree it left behind is freed by the first reclaim after it ends.

## Viewing the effective value

```sh
sbx config show    # the locator in effect, and which layer named it
```

The line appears only when a layer named a userland, so a cage on the hermetic nix userland
reads as it always did.
