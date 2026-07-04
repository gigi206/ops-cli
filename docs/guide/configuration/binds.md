# `binds` — extra host paths

Extra host paths to expose inside the sandbox — **read-only by default**, or
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

See also: [Security model](../concepts/security-model.md) · [The trust gate](../concepts/trust.md) · [`ops config edit`](../cli/config.md).

## Read-only vs read-write, and same-uid

- A **read-only** bind exposes the path's *contents* to the cage.
- A **read-write** bind additionally lets the cage write through to the host path.

Remember the [same-uid model](../concepts/security-model.md): a read-only bind
protects **integrity**, not **confidentiality** — the process inside runs as your
uid, so it can *read* whatever is bound. To keep a secret out of the cage, do not
bind it at all; bind read-only only what the tool may read but must not modify.

## Path rules

- A bind path must be **absolute**. It is canonicalized (resolving symlinks) at
  resolution time, closing a time-of-check/time-of-use gap.
- A **missing** path is dropped with a warning rather than failing the launch (a
  best-effort bind), so a portable config referencing an optional path still works.
- A leading `~`, `$HOME`, or `$XDG_RUNTIME_DIR` is expanded from your environment, so
  a portable config need not hard-code an absolute home path. **Any other `$VAR` is
  refused** — no arbitrary environment interpolation.

## Editing binds

`binds` is an array of strings and tables, so it is edited with
[`ops config edit`](../cli/config.md), not `ops config set` (which handles single
scalar values):

```sh
ops config edit          # add/remove bind entries
ops config edit --trust  # and re-trust in one step
```

## Layering with the structural mounts

A config bind is emitted **before** `ops`'s structural mounts (`/nix`, the synthetic
identity, the project), so a colliding entry is **shadowed** — a bind cannot displace
`/nix` or the synthetic `/etc`.

One known nuance: a config bind that **nests** with a structural mount (rather than
colliding exactly) is resolved by path and handled fail-closed, with a warning. A
*descendant* of a structural mount (e.g. a path under `/tmp`, which the cage covers
with a tmpfs) may be listed by `ops config show` yet dropped by the launch; an
*ancestor* (e.g. `/etc`) would over-expose that directory. `ops` warns when a config
bind's destination nests with a structural mount.

## The control plane is protected

`ops`'s own state — its data, trust, and config directories, all under your `$HOME` —
is protected regardless of what a bind requests:

- A read-write bind aimed **at or inside** one of `ops`'s directories is **forced
  read-only**, with a warning.
- A broad read-write bind that merely **contains** them (e.g. `mode = "rw"` on your
  whole `$HOME`) **stays read-write**, but each `ops` root is **pinned read-only in
  place** — so the rest of the tree is writable while the agent still cannot alter
  what `ops` runs or trusts.

This closes an escalation where a writable parent directory would let the agent
rename a control-plane directory out of the way and substitute a forged one. See
[Security model](../concepts/security-model.md#the-control-plane-is-pinned).

> Why the pin, and not just read-only? A read-only bind protects an **inode**, not a
> **path**. Without the pin, a writable parent would let `mv` swap the directory the
> path points at. The pin makes every path component a mountpoint, so a rename or
> rmdir of a control-plane root fails with `EBUSY`.

## Per-app binds

An `[app.<name>]` overlay can add its own `binds`, layered onto the baseline. Same
gating (security field), same rules. See [`[app.<name>]`](apps.md).
