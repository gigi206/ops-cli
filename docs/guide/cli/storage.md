# `sbx storage`

```
sbx storage init    [--image <path>] [--size <n>] [--label <name>]
sbx storage migrate [--image <path>] [--force]
sbx storage use     [--image <path>] [--force]
sbx storage status  [--image <path>] [--json]
sbx storage up      [--image <path>]
sbx storage down    [--image <path>]
sbx storage unuse
```

Gives sbx a filesystem of its own for its data directory: a **sparse image file carrying a
compressed btrfs filesystem**, which grows as it is written and costs the host a **single
inode** no matter how many files it holds.

Optional. Without it sbx behaves exactly as it always has — see
[Directory layout](../concepts/directory-layout.md).

See also: [`sbx store`](store.md) · [`sbx gc`](gc.md) · [`SBX_DATA_DIR`](../reference/environment-variables.md#sbx_data_dir).

## Why

[`sbx store`](store.md) reports two numbers, and on a busy installation both get large:

```
sbx store — /home/you/.local/share/sbx (35.6 GiB, 595 678 inodes)
```

The inode count is the one that bites first. A filesystem can run out of inodes **while it
still has free space** — some fix their inode table when they are created and it cannot grow
— and a nix store is inode-heavy by nature. Check yours with `df -i`.

A volume addresses both at once:

- **Inodes** — the whole tree is one host file. 595 678 becomes 1.
- **Size** — the filesystem compresses. Real stores measure around **half** their apparent size.
- **Copies become shares** — sbx seeds each per-project store from the shared one. On an
  ordinary filesystem that is a physical copy; on this one the two share their blocks. A
  second project's 616 MiB store cost 81 MiB of real growth in testing.
- **It grows on demand** — the image declares a large size but occupies only what is written,
  so a fresh volume is a few megabytes.

## Where it works, and where it does not

The whole chain runs **without root**, for two reasons:

- `mkfs.btrfs --rootdir` builds the filesystem from a seed directory and gives its root that
  directory's ownership — so you own your own volume.
- `udisks` performs the loop attach and the mount over D-Bus, and its shipped policy grants
  both to a **locally active session** without authentication.

That second point is the boundary. In a **remote (SSH), headless, CI or inactive** session,
the same policy requires administrator authentication, so the mount cannot happen unattended.
This is why the feature is opt-in and never a prerequisite.

The one requirement is **`udisks2`**, and it is unavoidable: it is a system daemon, and the
privilege lives with it rather than with any binary sbx could ship.

`btrfs-progs` is **not** required. It is not installed on every distribution, so if the host
has no `mkfs.btrfs`, sbx provisions `btrfs-progs` into its own store and runs it sandboxed —
`init` says which it used. Using a volume needs no `btrfs` binary at all: compression rides an
extended attribute and space accounting an ioctl.

You do not have to find out the hard way. [`sbx doctor`](doctor.md) reports the storage line —
the filesystem the data directory sits on, and whether an encapsulated volume is available,
already redundant (the data is on a copy-on-write filesystem such as btrfs or ZFS), or blocked
(and why). And `up`/`use` **fail early with a single message** naming every missing
prerequisite, rather than surfacing the first obstacle deep in the mount.

## A one-time suggestion on first launch

On the **first interactive launch** (`sbx run`, `sbx app run …`) of an eligible host, sbx offers
to adopt a volume — **once**. It is shown only when connected to a **terminal**, so an agent, a
pipe or CI never meets it; sbx has no other blocking prompt, and the autonomous-agent path keeps
none. Whatever you answer, it is recorded and never shown again — [`sbx doctor`](doctor.md)
remains the standing reminder.

What it offers depends on what is already there:

- **A fresh install (empty data directory)** — a yes/no question. *Yes* creates and mounts a
  volume on the spot (instant, nothing to copy) and uses it from that launch on. *No* keeps the
  plain directory.
- **An existing data directory** — a single, non-blocking line pointing at `sbx storage migrate`,
  never an inline copy: migrating is slow and can fail its own checks, and it should not hijack
  the command you actually ran.

The offer appears only where a volume is genuinely worth it: a mountable host (btrfs, loop devices
and udisks2 present) with a **local active session**, whose data is **not already** on a
copy-on-write filesystem. Set [`SBX_DATA_DIR`](../reference/environment-variables.md#sbx_data_dir)
and it is skipped entirely — that is the invoker's explicit choice.

## Adopting a volume

You can also adopt one deliberately, at any time. Two commands, once:

```console
$ sbx storage init
creating /home/you/.local/share/sbx-storage.btrfs (200.0 GiB logical, sparse — it occupies only what is written)
  created — mount it with `sbx storage up`

$ sbx storage use
sbx now uses /run/media/you/sbx-storage
it is mounted automatically from now on — no environment variable needed.
```

`use` records the volume, and **from then on sbx mounts it whenever it needs it** — including
after a reboot. There is no variable to carry, nothing to add to a shell profile, and nothing
to run by hand.

Nothing changes until you run `use`, so upgrading sbx never alters an existing installation.

`sbx storage unuse` reverses it and goes back to the ordinary data directory, leaving the
volume and its contents untouched.

### `use` will not strand your data

Adopting a volume does not move what is already in the data directory — it hides it. So `use`
**refuses** when it finds a store, projects or app homes there:

```console
$ sbx storage use
sbx storage: /home/you/.local/share/sbx already holds store, projects, apps — adopting the
volume would leave that behind, not move it.
       Copy it into /run/media/you/sbx-storage while no sandbox is running, then re-run; or
       pass --force to adopt an empty volume anyway.
```

The image is created **beside** the data directory (`<xdg-data>/sbx-storage.btrfs`), never
inside it — the volume is what that directory becomes. `--image <path>` puts it elsewhere, on
another disk for instance.

## Mounting is automatic

`udisks` mounts under `/run`, which is cleared on reboot — so a volume is unmounted every time
you log in. sbx mounts it on demand, so this is invisible.

`sbx storage up` exists for the rare case where you want the mount without waiting for the
next command; it is idempotent. `sbx storage down` unmounts, but while the volume is adopted
the next sbx command simply mounts it again, and `down` says so.

**If an adopted volume cannot be mounted, sbx stops** rather than carrying on. This is
deliberate: the mount point exists only while mounted and lives on a tmpfs, so continuing
would provision gigabytes into RAM and report an empty store as the truth.

The mount point is read back from `udisks` rather than assumed — it varies by version
(`/run/media` or `/media`) and gains a suffix if the label collides — so always take it from
`use` or `status`.

## `status`

```console
$ sbx storage status
sbx storage — /home/you/.local/share/sbx-storage.btrfs
  type        volume (btrfs)
  state       mounted
  on host     957.0 MiB of 200.0 GiB logical
  device      /dev/loop7
  mounted at  /run/media/you/sbx-storage
  compression zstd
  inside      2.4 GiB used of 3.3 GiB the filesystem has claimed

  sbx is reading its data from this volume.
```

**type** says what the data directory is backed by right now: `volume (<fs>)` for an sbx-managed
encapsulated volume, or `local (<fs>)` when it sits directly on a host filesystem (the same line
[`sbx doctor`](doctor.md) leads with). **on host** is what the volume actually costs — compare it
with **inside**, which is what the filesystem holds, to see compression and block sharing at work.

`--json` emits the same data as a document.

## Releasing it

```console
$ sbx storage down
unmounted and detached
```

`down` **refuses while a sandbox is still running** from the volume, since its store lives
there. Stop them first with [`sbx session stop --all`](session.md). While the volume is
adopted, `down` is temporary — the next sbx command mounts it again. Use `sbx storage unuse`
to stop using it for good.

Freed space returns to the host **in the background** rather than the instant a file is
deleted, so the `on host` figure can lag a deletion by a moment — and after a large
[`sbx gc`](gc.md), by considerably more. It is not lost; it is being handed back.
