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
project gets no bind at all, so it can never obtain a writable one. An unrecognized
`mode` falls closed to read-only with a warning (a `RW` suggests `rw`), and a table
without a `path` is skipped on its own with a warning: one bad entry never drops the
whole layer.

See also: [Security model](../concepts/security-model) · [The trust gate](../concepts/trust) · [`sbx config edit`](../cli/config).

## When you want one

A cage starts from almost nothing: the hermetic base, `/nix`, and the project bound at its real path. Sometimes the tool inside needs one more host path: a shared dataset under `/opt/data`, a host certificate bundle, a scratch directory it may write through. That is what `binds` is for: one extra host path, visible at the same path inside, read-only unless the table form says `rw`.

If what you need is to hide a project file from the agent instead (a `.env`, a key, a `secrets/` tree), that is [`[fs]`](fs), which subtracts from the project tree rather than adding a host path.

Security framing: under the same-uid model a read-only bind protects integrity only (the cage reads whatever is bound), so confidentiality is by absence and what must stay secret is simply not bound. That is why `binds` is trusted-only: each entry widens the boundary itself.

## Read-only vs read-write, and same-uid

- A **read-only** bind exposes the path's *contents* to the cage.
- A **read-write** bind additionally lets the cage write through to the host path.

Remember the [same-uid model](../concepts/security-model): a read-only bind
protects **integrity**, not **confidentiality**: the process inside runs as your
uid, so it can *read* whatever is bound. To keep a secret out of the cage, do not
bind it at all; bind read-only only what the tool may read but must not modify.

A read-only bind is named in the generated contract the cage reads at
`/opt/sbx/contract.md`, alongside the paths a [`[fs]`](fs) mask closes, under the
heading that lists what refuses a write. The two mechanisms differ on the host and not from
inside: either way the contents are the real ones and the write comes back refused, after the
work that produced the bytes. A writable bind is named nowhere, being no restriction to
announce.

Nor is a bind the cage never sees. One [inside the project](#layering-with-the-structural-mounts),
or under a structural mount such as `/tmp`, is covered by a mount emitted after it, so the cage
finds that mount at the path instead. Inside the project that means the project's own read-write
mount: listing the bind as read-only would tell a process that a path refuses a write when it
takes one.

A read-write bind is written the way the project is, so what your git reads there is held the
same way: the directory `core.hooksPath` names in the bind, a file git includes from it, a
submodule's repository in it, and, when the project is a linked worktree, the configuration and
hooks of its main repository and the repository's other work trees in it, are read-only in the
cage, and a symbolic link in the bind
on the way to one refuses the launch ([where the cage writes](fs#where-the-cage-writes)). The
directories between the bind and each of them can no longer be renamed or removed from the cage.
The rest of the bind stays writable: another repository in it is what the bind grants. A bind
that holds your global git configuration (a bind of your whole home, for one) holds none of
this, since the cage could name a program there that git runs anyway, and the launch warns.

## Path rules

- A bind path must be **absolute**. It is canonicalized (resolving symlinks) at
  resolution time, which pins the source to its real location, so a symlink swapped in
  later no longer redirects the bind. The launch then opens the source with every link on
  its path refused and hands bubblewrap that open descriptor (`--bind-fd`,
  `--ro-bind-fd`). A parent directory swapped for a link between the resolution and the
  launch, or a source removed in between, refuses the launch and names the bind. That gap
  is not only yours: another session's cage can write the parents of a source that lies in
  its own project, in one of its read-write binds or in its mise install pool. A bind
  inside your own project is out of its reach, since the project's mount covers that bind.
  bubblewrap looks the descriptor's path up once more as it mounts, and from 0.10.0 it
  then checks that what it mounted is that object, refusing the launch otherwise.
- The cage checks each bind it sees once more before it runs anything: a path that shows
  another object than the one the launch opened, or nothing, stops the cage with exit code
  `125` and names the bind, and your command does not start. A bind covered by a later
  mount, inside the project for one, is not checked, since what the cage finds there is
  that mount.
- A bubblewrap without `--bind-fd` (upstream releases before 0.10.0) is handed the path
  instead, and the launch warns: there a parent swapped between the resolution and the
  mount still races.
- Ubuntu 24.04's bubblewrap 0.9.0 has `--bind-fd` as a backport, without bubblewrap's own
  check. The descriptor still defeats a swap made before bubblewrap starts, since bubblewrap
  looks up where the open source is at that moment, and a swap made during its setup,
  between that look-up and the mount, is caught by the cage's check above. The check
  detects that swap rather than preventing it: the cage stops instead of running on it.
- A **missing** path is dropped with a warning rather than failing the launch (a
  best-effort bind), so a portable config referencing an optional path still works.
- A leading `~`, `$HOME`, or `$XDG_RUNTIME_DIR` is expanded from your environment, so
  a portable config need not hard-code an absolute home path. **Any other `$VAR` is
  refused**: no arbitrary environment interpolation. The expanded path is where the bind
  appears in the cage too: `~/.x` is your host `~/.x` at that same path, not a directory
  under the cage's `$HOME` (`/home/sandbox`), so a program that reads its settings from
  its home does not see it there.

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

A **read-only** ancestor can be impossible to establish at all. `sbx` mounts its own files
after the config binds, so each one under the bind must find room inside the bound host
directory: a path the host does not carry would have to be created, and a link `sbx` creates
(`/etc/localtime`, `/bin/sh`) can never be placed there. Such a bind is **dropped** with a
warning naming the path that blocks it, rather than failing the launch in `bwrap`. The two
common cases are `/etc`, which holds the `/etc/localtime` link, and `/etc/ssl` on a host
without `ca-bundle.crt` (Debian and Ubuntu); the cage's TLS never needs the latter, since `sbx`
binds its own CA bundle. Bind a narrower path instead, such as the directory holding your own
certificate. A declared [`distro`](distro) supplies some of those paths itself, so they no longer
block. A **read-write** bind is dropped for a link alone, which fails in any mode: a missing path
under it is created in the host directory where the host allows it.

The same holds for what `sbx` mounts under `/run` on some launches only: the audio socket, the
desktop portal, the GPU bridge. Whether one is there depends on the posture and on the hardware
found, so a read-only bind of `/run` itself is checked at the launch rather than when the
configuration is read: kept on a launch that mounts none of them, dropped with the same warning on
one that does.

**The project is one of those mounts.** A bind at a path inside your project, or at the
project itself, is emitted before the project and then covered by it, so it does nothing
at all. `sbx` names it, from a config file or a one-shot `--bind` alike, because the
failure is silent otherwise and because a bind of the project itself reads as changing its
mode when it does not: the project's own read-write mount is what the cage ends up with. To narrow a path inside the project, use an
[`[fs] deny`](fs) mask, which is applied after the project rather than before it. A bind
that *contains* your project is the ordinary case and is not remarked on: the project
still lands correctly inside it.

## The control plane is protected

`sbx`'s own state, its data, trust, and config directories, all under your `$HOME`: is protected regardless of what a bind requests:

- A read-write bind aimed **at or inside** one of `sbx`'s directories is **forced
  read-only**, with a warning.
- A broad read-write bind that merely **contains** them (e.g. `mode = "rw"` on your
  whole `$HOME`) **stays read-write**, but each `sbx` root is **pinned read-only in
  place and shown empty**, so the rest of the tree is writable while the agent still
  cannot alter what `sbx` runs or trusts, nor reach the control sockets and other
  projects' state those directories hold. A root that another bind, or the project,
  lies inside is shown with its contents instead, read-only, so what you asked for
  is still there.
- A **read-only** bind that contains them (e.g. your whole `$HOME`, read-only)
  shows each `sbx` root empty the same way, pinned alone: nothing under a
  read-only bind can be renamed.
- The **project itself** follows the same rule. The working directory you launch
  from is bound read-write without being declared anywhere, so running from one of
  `sbx`'s own directories is the same request as a read-write bind over it. It is
  mounted **read-only**, with a warning naming the directory. Launch from somewhere
  else if you need to write there.

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

That suffix belongs to the command line alone. In a file, a bare string is a path,
whole, so `binds = ["/work/scratch:rw"]` names a directory called `/work/scratch:rw`
and binds nothing. `sbx config add binds /work/scratch:rw` refuses for that reason and
names the table form to write instead.
