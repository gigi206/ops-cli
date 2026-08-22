---
sidebar_label: "binds"
description: "Extra host paths exposed inside the cage, read-only by default or read-write with the table form."
---

# `binds`: extra host paths

Extra host paths to expose inside the sandbox, **read-only by default**, or
read-write with the table form.

```toml
# a bare string is read-only
binds = ["/opt/data", "/etc/ssl/custom"]

# a table with mode = "rw" binds read-write (the cage writes through to the host)
binds = [
    "/opt/data",
    { path = "/work/scratch", mode = "rw" },
    { path = "/explicit/ro",  mode = "ro" },
]
```

`binds` is a **security field**: honored only from a trusted source. An untrusted
project gets no bind at all, so it can never obtain a writable one.

See also: [Security model](../concepts/security-model) · [The trust gate](../concepts/trust) · [`sbx config edit`](../cli/config).

## Read-only vs read-write, and same-uid

- A **read-only** bind exposes the path's *contents* to the cage.
- A **read-write** bind additionally lets the cage write through to the host path.

Remember the [same-uid model](../concepts/security-model): a read-only bind
protects **integrity**, not **confidentiality**: the process inside runs as your
uid, so it can *read* whatever is bound. To keep a secret out of the cage, do not
bind it at all; bind read-only only what the tool may read but must not modify.

## Path rules

- A bind path must be **absolute**. It is canonicalized (resolving symlinks) at
  resolution time, which **narrows** the time-of-check/time-of-use gap rather than
  closing it: the source is pinned to its real location, so a symlink swapped in later
  no longer redirects the bind, but a **parent directory** swapped between that
  resolution and the mount still races. Under the
  [same-uid model](../concepts/security-model) winning that race takes a host process
  already running as you, which has your rights anyway.
- A **missing** path is dropped with a warning rather than failing the launch (a
  best-effort bind), so a portable config referencing an optional path still works.
- A leading `~`, `$HOME`, or `$XDG_RUNTIME_DIR` is expanded from your environment, so
  a portable config need not hard-code an absolute home path. **Any other `$VAR` is
  refused**: no arbitrary environment interpolation.

## Editing binds

`binds` is an array of strings and tables, so it is edited with
[`sbx config edit`](../cli/config), not `sbx config set` (which handles single
scalar values):

```sh
sbx config edit          # add/remove bind entries
sbx config edit --trust  # and re-trust in one step
```

## Layering with the structural mounts

A config bind is emitted **before** `sbx`'s structural mounts (`/nix`, the synthetic
identity, the project), so a colliding entry is **shadowed**: a bind cannot displace
`/nix` or the synthetic `/etc`.

One known nuance: a config bind that **nests** with a structural mount (rather than
colliding exactly) is resolved by path and handled fail-closed, with a warning. A
*descendant* of a structural mount (e.g. a path under `/tmp`, which the cage covers
with a tmpfs) may be listed by `sbx config show` yet dropped by the launch; an
*ancestor* (e.g. `/etc`) would over-expose that directory. `sbx` warns when a config
bind's destination nests with a structural mount.

**The project is one of those mounts.** A bind at a path inside your project, or at the
project itself, is emitted before the project and then covered by it, so it does nothing
at all. `sbx` names it, because the failure is silent otherwise and because a bind of the
project itself reads as changing its mode when it does not: the project's own read-write
mount is what the cage ends up with. To narrow a path inside the project, use an
[`[fs] deny`](fs) mask, which is applied after the project rather than before it. A bind
that *contains* your project is the ordinary case and is not remarked on: the project
still lands correctly inside it.

## The control plane is protected

`sbx`'s own state, its data, trust, and config directories, all under your `$HOME`: is protected regardless of what a bind requests:

- A read-write bind aimed **at or inside** one of `sbx`'s directories is **forced
  read-only**, with a warning.
- A broad read-write bind that merely **contains** them (e.g. `mode = "rw"` on your
  whole `$HOME`) **stays read-write**, but each `sbx` root is **pinned read-only in
  place**, so the rest of the tree is writable while the agent still cannot alter
  what `sbx` runs or trusts.

This closes an escalation where a writable parent directory would let the agent
rename a control-plane directory out of the way and substitute a forged one. See
[Security model](../concepts/security-model#the-control-plane-is-pinned).

> Why the pin, and not just read-only? A read-only bind protects an **inode**, not a
> **path**. Without the pin, a writable parent would let `mv` swap the directory the
> path points at. The pin makes every path component a mountpoint, so a rename or
> rmdir of a control-plane root fails with `EBUSY`.

## Per-app binds

An `[app.<name>]` overlay can add its own `binds`, layered onto the baseline. Same
gating (security field), same rules. See [`[app.<name>]`](apps).

## One-shot override

To add a host bind for a single launch without editing the file, use `--bind`
(repeatable) or `SBX_BIND`:

```sh
sbx run --bind /opt/data -- ./tool          # read-only (the default)
sbx run --bind /work/scratch:rw -- ./tool   # read-write
SBX_BIND=/etc/ssl/custom:ro sbx run
```

The mode is the suffix after the **last** `:`, and only when it is exactly `ro` or
`rw`. A one-shot bind *adds* to whatever the config binds. The command line beats the
environment, and both beat the config file. See [One-shot overrides](overrides).
