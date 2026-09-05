---
sidebar_label: "Prerequisites"
description: "The kernel features and host tools a cage needs, and how `sbx doctor` checks them before the first launch."
---

# `sbx doctor` and prerequisites

```
sbx doctor
```

`doctor` verifies the load-bearing runtime requirements **before** anything can run,
and reports the store location and channel revision. A missing requirement is a
**hard failure with a remediation hint**: never a silent fallback to a weaker
engine, because a weaker engine would mean no security boundary. On a fresh install,
before the first launch, the store reports itself absent (created on first use) and the
channel unresolved (seeded on first launch): informational, not failures.

See also: [Installation](installation) · [Security model](../concepts/security-model) · [Enforcement stack](../concepts/enforcement).

## A passing host

```console
$ sbx doctor
sbx doctor — runtime preflight

  [ ok ] bubblewrap        /usr/bin/bwrap
         · host PATH
  [ ok ] sandbox           bubblewrap launched a hardened process
         · user namespaces: capability-bearing — proven by the launch
         · no_new_privs set, every capability dropped
         · host $HOME absent — the bind layout did not leak it
         · kernel.apparmor_restrict_unprivileged_userns = 0
         · kernel.unprivileged_userns_clone = 1
  [ ok ] resource limits   cage capped via a systemd scope (MemoryHigh=80%, MemoryMax=90%, TasksMax=16384)
  [ ok ] nix               /nix/var/nix/profiles/default/bin/nix
         · nix (Nix) 2.34.5
  [ ok ] git               /usr/bin/git
         · optional — needed only for `sbx plugins store`, not to run a sandbox
  [ ok ] store             ~/.local/share/sbx/store (present)
  [ ok ] channel           nixos-unstable @ 0954f7e (locked)
  [ ok ] storage           type: local (ext4) at ~/.local/share/sbx

sbx: prerequisites OK.
```

Every line is a check; the indented `·` lines are the evidence behind it. The
`sandbox` block is the one that matters most: it is not a probe of kernel flags but
the report of a real bubblewrap launch, which is why it can assert that the host
`$HOME` was absent from inside the cage.

On a host that has [adopted a volume](../cli/storage), the last two lines read
differently, and the store moves into it:

```console
  [ ok ] store             /run/media/you/sbx-storage/store (present)
  [ ok ] storage           type: volume (btrfs) at /run/media/you/sbx-storage
         · compression zstd; the data directory costs the host a single inode
```

## What it checks

- **Capability-bearing unprivileged user namespaces.** This is the security
  boundary everything else rests on. `sbx` decides this with a *live* bubblewrap
  launch that reads `/proc/self/status` from inside the cage: a launch with all
  capabilities dropped and `no_new_privs` set proves the namespace is
  capability-bearing more conclusively than a probe could.

  On a restricted Ubuntu 24.04+ host, `unshare(CLONE_NEWUSER)` can succeed yet be
  stripped of capabilities. `doctor` checks for the capability-bearing case
  specifically, so it will not pass a host where the namespace exists but is inert.

- **The bubblewrap engine.** The sandbox itself. `doctor` reports which `bwrap` it
  would use and why: the bundled static engine, or one found on `PATH`, with an
  AppArmor note where relevant (see [Provisioning](../concepts/provisioning)).

- **The nix binary.** Drives the user-owned store. Reported the same way (bundled or
  host).

- **Best-effort resource limiting.** Whether the cage can run inside a transient
  systemd user scope carrying cgroup v2 limits. This is *not* the boundary, so a
  host that cannot provide it gets a warning, not a failure: the launch still runs,
  just without the anti-DoS limits. See [Enforcement stack](../concepts/enforcement).

  Availability is decided by the user manager's delegation root, where a transient
  scope is actually registered, and not by where the calling process itself sits in
  the cgroup tree. The two differ more often than it looks: a login session is a
  sibling of that root, and a WSL2 distribution starts everything launched through
  `wsl.exe` outside the user slice altogether, yet a scope can still be created from
  either.

- **The store location and channel revision.** Where `sbx`'s user-owned store lives
  and which nixpkgs revision the base userland is pinned to.

- **The distribution image**, when the host-level lock pins one: the locator, its digest,
  and whether the tree is unpacked yet. The line is absent on a host that runs the hermetic
  nix userland, which is the ordinary case and not something missing. A project that
  declares its own image pins it in the project's own lock, which `doctor` does not read.

## Why it hard-fails

`sbx`'s entire security model depends on the unprivileged user namespace being
capability-bearing. There is no safe degraded mode: an emulation layer (such as
proot) provides isolation without a real boundary, which would be worse than an
honest failure because it *looks* sandboxed. So when the requirement is absent,
`doctor` fails and tells you how to fix it, and a launch refuses rather than running
unprotected.

## When user namespaces are unavailable

If `doctor` reports that user namespaces are missing or non-capability-bearing:

- On many distributions, unprivileged user namespaces are enabled by default. Some
  harden them off.
- On restricted Ubuntu 24.04+, an AppArmor policy
  (`kernel.apparmor_restrict_unprivileged_userns`) can grant the capability only to
  a binary carrying a matching profile. A release that pins the host's
  path-profiled `/usr/bin/bwrap` works there; a bwrap materialized elsewhere would
  match no profile. See [Provisioning](../concepts/provisioning) for how `sbx`
  chooses its bwrap engine on such a host.

The remediation hint `doctor` prints is specific to what it found.
