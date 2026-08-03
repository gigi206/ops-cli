# `sbx doctor` and prerequisites

```
sbx doctor
```

`doctor` verifies the load-bearing runtime requirements **before** anything can run,
and reports the store location and channel revision. A missing requirement is a
**hard failure with a remediation hint**: never a silent fallback to a weaker
engine, because a weaker engine would mean no security boundary.

See also: [Installation](installation) · [Security model](../concepts/security-model) · [Enforcement stack](../concepts/enforcement).

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

- **The store location and channel revision.** Where `sbx`'s user-owned store lives
  and which nixpkgs revision the base userland is pinned to.

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
