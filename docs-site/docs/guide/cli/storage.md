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

Optional. Without it sbx behaves exactly as it always has: see
[Directory layout](../concepts/directory-layout).

See also: [`sbx store`](store) · [`sbx gc`](gc) · [`SBX_DATA_DIR`](../reference/environment-variables#sbx_data_dir).

## Why

[`sbx store`](store) reports two numbers, and on a busy installation both get large:

```
sbx store — /home/you/.local/share/sbx (35.6 GiB, 595 678 inodes)
```

The inode count is the one that bites first. A filesystem can run out of inodes **while it
still has free space**, some fix their inode table when they are created and it cannot grow, and a nix store is inode-heavy by nature. Check yours with `df -i`.

A volume addresses both at once:

- **Inodes**: the whole tree is one host file. 595 678 becomes 1.
- **Size**: the filesystem compresses. Real stores measure around **half** their apparent size.
- **Copies become shares**: sbx seeds each per-project store from the shared one. On an
  ordinary filesystem that is a physical copy; on this one the two share their blocks. A
  second project's 616 MiB store cost 81 MiB of real growth in testing.
- **It grows on demand**, the image declares a large size but occupies only what is written,
  so a fresh volume is a few megabytes.

## Where it works, and where it does not

The whole chain runs **without root**, for two reasons:

- `mkfs.btrfs --rootdir` builds the filesystem from a seed directory and gives its root that
  directory's ownership: so you own your own volume.
- `udisks` performs the loop attach and the mount over D-Bus, and its shipped policy grants
  both to a **locally active session** without authentication.

That second point is the boundary. In a **remote (SSH), headless, CI or inactive** session,
the same policy requires administrator authentication, so the mount cannot happen unattended.
This is why the feature is opt-in and never a prerequisite.

The one requirement is **`udisks2`**, and it is unavoidable: it is a system daemon, and the
privilege lives with it rather than with any binary sbx could ship.

`btrfs-progs` is **not** required. It is not installed on every distribution, so if the host
has no `mkfs.btrfs`, sbx provisions `btrfs-progs` into its own store and runs it sandboxed, `init` says which it used. Using a volume needs no `btrfs` binary at all: compression rides an
extended attribute and space accounting an ioctl. Every file created on the volume inherits
that attribute, and nix normally strips extended attributes when it finalizes a store path, which would abort a build whose files are already read-only: so on a btrfs-backed store sbx
tells nix (host-side and in-cage alike) to leave `btrfs.compression` in place. The data was
already written compressed, so nothing is lost.

You do not have to find out the hard way. [`sbx doctor`](doctor) reports the storage line, the filesystem the data directory sits on, and whether an encapsulated volume is available,
already redundant (the data is on a copy-on-write filesystem such as btrfs or ZFS), or blocked
(and why). And `up`/`use` **fail early with a single message** naming every missing
prerequisite, rather than surfacing the first obstacle deep in the mount.

## A one-time suggestion on first launch

On the **first interactive launch** (`sbx run`, `sbx app run …`) of an eligible host, sbx offers
to adopt a volume, **once**. It is shown only when connected to a **terminal**, so an agent, a
pipe or CI never meets it; sbx has no other blocking prompt, and the autonomous-agent path keeps
none. Whatever you answer, it is recorded and never shown again: [`sbx doctor`](doctor)
remains the standing reminder.

What it offers depends on what is already there:

- **A fresh install (empty data directory)**: a yes/no question. *Yes* creates and mounts a
  volume on the spot (instant, nothing to copy) and uses it from that launch on. *No* keeps the
  plain directory.
- **An existing data directory**, a single, non-blocking line pointing at `sbx storage migrate`,
  never an inline copy: migrating is slow and can fail its own checks, and it should not hijack
  the command you actually ran.

The offer appears only where a volume is genuinely worth it: a mountable host (btrfs, loop devices
and udisks2 present), a **local active session**, and a filesystem that does not already give sbx
what a volume would. A volume brings two things: it **shares blocks** between files, so seeding a
per-project store from the shared one costs almost nothing, and it **compresses**: so the question
is whether either is missing:

| Data directory on | shares blocks | compresses | offered? |
|---|---|---|---|
| btrfs, ZFS, bcachefs | yes | yes | no, and nesting one copy-on-write filesystem in another only compounds fragmentation |
| XFS | yes (`reflink=1`) | no | yes, for the compression |
| ext2/3/4 | no | no | yes: and it relieves the fixed inode table too |
| tmpfs | n/a | n/a | no: nothing here survives a reboot |
| anything else | measured | unknown | only if it turns out not to share blocks |

For a filesystem sbx does not recognize there is no table to consult, so it **measures** block
sharing by attempting one in the data directory: and offers a volume only on a definite "cannot",
rather than guessing about compression. Set
[`SBX_DATA_DIR`](../reference/environment-variables#sbx_data_dir) and the offer is skipped
entirely: that is the invoker's explicit choice.

## Adopting a volume

You can also adopt one deliberately, at any time. Two commands, once:

```console
$ sbx storage init
creating /home/you/.local/share/sbx-storage.btrfs (200.0 GiB logical, sparse — it occupies only what is written)
  created — start using it with `sbx storage use`

$ sbx storage use
sbx now uses /run/media/you/sbx-storage
it is mounted automatically from now on — no environment variable needed.
```

`use` records the volume, and **from then on sbx mounts it whenever it needs it**: including
after a reboot. There is no variable to carry, nothing to add to a shell profile, and nothing
to run by hand.

Nothing changes until you run `use`, so upgrading sbx never alters an existing installation.

`sbx storage unuse` reverses it and goes back to the ordinary data directory, leaving the
volume and its contents untouched.

### `use` will not strand your data

Adopting a volume does not move what is already in the data directory: it hides it. So `use`
**refuses** when it finds a store, projects or app homes there:

```console
$ sbx storage use
sbx storage: /home/you/.local/share/sbx already holds store, projects, apps — adopting the
volume would leave that behind, not move it.
       Copy it into /run/media/you/sbx-storage while no sandbox is running, then re-run; or
       pass --force to adopt an empty volume anyway.
```

The image is created **beside** the data directory (`<xdg-data>/sbx-storage.btrfs`), never
inside it, the volume is what that directory becomes. `--image <path>` puts it elsewhere, on
another disk for instance.

## Choosing the size

`--size` is **optional**: `init` defaults to **200 GiB**. Whatever you pass, it is a *logical
ceiling, not a reservation*: the image is sparse, so it occupies only the bytes actually written.
A fresh 200 GiB volume is a few megabytes on the host and grows as the store does. Set it
generously and forget it: the number costs nothing until you fill it.

```console
$ sbx storage init --size 500G     # or 1T, or a plain byte count
```

You rarely need to change it afterwards, and that is fortunate, because **growing a volume in
place requires root**. Everything else sbx does is unprivileged, but a resize is the exception:
its two steps, telling the kernel the backing file has grown, and telling btrfs to use the new
room, are both privileged, and `udisks` grants neither unattended. A spike confirmed this on a
real volume: `losetup --set-capacity` and `btrfs filesystem resize` each returned *Operation not
permitted* for an ordinary user.

So the size is really settled **once, at `init`**: pick it high the first time. If you
genuinely must grow an existing volume and you have root (and the host carries `util-linux` and
`btrfs-progs`), [`status`](#status) names the device and the mount point, and the manual
procedure is:

```console
$ truncate -s 500G /home/you/.local/share/sbx-storage.btrfs   # unprivileged: enlarge the file
$ sudo losetup --set-capacity /dev/loop7                      # root: let the loop see the new size
$ sudo btrfs filesystem resize max /run/media/you/sbx-storage # root: grow the filesystem onto it
```

sbx supplies `btrfs-progs` for its own use but cannot supply the privilege, so this stays a
manual escape hatch it never runs for you. Not every host even carries `losetup` or a host
`btrfs` binary: one more reason to size the volume right at `init` instead.

## Mounting is automatic

`udisks` mounts under `/run`, which is cleared on reboot: so a volume is unmounted every time
you log in. sbx mounts it on demand, so this is invisible.

`sbx storage up` exists for the rare case where you want the mount without waiting for the
next command; it is idempotent. `sbx storage down` unmounts, but while the volume is adopted
the next sbx command simply mounts it again, and `down` says so.

**If an adopted volume cannot be mounted, sbx stops** rather than carrying on. This is
deliberate: the mount point exists only while mounted and lives on a tmpfs, so continuing
would provision gigabytes into RAM and report an empty store as the truth.

The mount point is read back from `udisks` rather than assumed: it varies by version
(`/run/media` or `/media`) and gains a suffix if the label collides: so always take it from
`use` or `status`.

## `status`

```console
$ sbx storage status
sbx storage — /home/you/.local/share/sbx-storage.btrfs
  type        volume (btrfs)
  state       mounted
  on host     3.1 GiB of 200.0 GiB logical
  device      /dev/loop7
  mounted at  /run/media/you/sbx-storage
  compression zstd
  inside      2.9 GiB used of 4.0 GiB the filesystem has claimed
  reclaimable 204.8 MiB the image carries beyond live data
              some of it queued for automatic return

  sbx is reading its data from this volume.
```

**type** says what the data directory is backed by right now: `volume (<fs>)` for an sbx-managed
encapsulated volume, or `local (<fs>)` when it sits directly on a host filesystem (the same line
[`sbx doctor`](doctor) leads with).

**on host** is what the volume costs, against the logical ceiling it was created with. **inside**
is the filesystem's own view: what its data occupies, and how much of the ceiling it has carved
into block groups to hold it. The two are counted **the same way, as blocks on the device**, so
the subtraction between them is the third line, and whenever there is something to reclaim you can
check it yourself.

That last point is worth spelling out, because btrfs itself counts differently. It writes every
metadata block twice, the `DUP` profile, its default on a single device, so a block that goes bad
is repaired from its twin instead of taking a part of the filesystem with it: and reports the pair
as one. `inside` counts them as they are written, which is why it can exceed what you think you
stored. A nix store's metadata runs on the order of 8% of its data, so expect that much overhead
and no surprise in it. **Compression is not visible here**: `used` is
already the compressed size. To see what compression and block sharing win you, compare `on host`
with the logical total [`sbx store`](store) reports.

**reclaimable** is what the image still carries beyond the data alive inside it: blocks written
once, since freed, and not yet handed back. That is the space a discard returns: see
[below](#releasing-it). Past a gigabyte, `status` also names the command that returns it.

The indented line appears when the kernel has discard work queued, which means the figure above
can fall without you doing anything. It carries **no number on purpose**: the kernel's queue counts
free space it *may* discard, including regions already punched out of the image, so it runs above
what the host would actually get back: on a volume where 800 MiB had just been deleted, the queue
read 1.1 GiB and 800 MiB came back. Only `reclaimable` tracks the return.

Right after a trim the line reads `reclaimable 0 B nothing the image can give back`. Do not expect
the two figures it comes from to meet exactly: they are independent counters, btrfs's own against
the host's accounting for the image file, and they cross by a few megabytes routinely. On an
ordinary host filesystem that crossing simply means zero.

Where the host filesystem itself compresses, the image genuinely holds more than it occupies, the
subtraction measures nothing, and the line is **absent** rather than shown as a confident zero.

`--json` emits the same data as a document.

## Releasing it

```console
$ sbx storage down
unmounted and detached
```

`down` **refuses while a sandbox is still running** from the volume, since its store lives
there. Stop them first with [`sbx session stop --all`](session). While the volume is
adopted, `down` is temporary, the next sbx command mounts it again. Use `sbx storage unuse`
to stop using it for good.

Freed space does not leave the image the instant a file is deleted, so the `on host` figure sits
above what the data now occupies, after a large [`sbx gc`](gc), well above. It is not lost, and
[**reclaimable**](#status) says exactly how much of it is in that state.

The volume mounts `discard=async` (btrfs's default), which favours write speed over prompt
reclaim: a delete returns its blocks through a **throttled background worker**, so the image runs
*above* the real used size for a few minutes rather than shrinking on the spot. That suits sbx's
workload, a nix build churns through many small writes, and `discard=sync` would make every commit
wait on the disk's TRIM. It cannot be changed here anyway: `udisks` fixes the mount options and sbx
holds no privilege.

**Part of it comes back on its own; the rest waits for you.** The worker only knows about space
freed while the filesystem is mounted this way: that is what the indented line under
`reclaimable` announces, and it needs no help. Do not expect it to trickle down, though: it
arrives in one step, whenever the worker gets to it. Measured on a fresh 800 MiB delete, the
figure did not move for a minute and a half and then dropped all at once.

Everything *else* in the `reclaimable` figure: space freed during an earlier mount, which no
queue survived, stays in the image indefinitely. That is the part watching `status` will not make
go away, and it is why the figure rarely sits at zero.

To return it: `sudo fstrim <mount-point>`. The `FITRIM` ioctl needs root, so sbx cannot do it for
you, which is also why `status` suggests it only once the figure passes a gigabyte, rather than
sending you to a root command for a few megabytes. Some distributions run a timer that sweeps every
mounted filesystem periodically (`systemctl status fstrim.timer` says whether yours does), which
makes this happen without asking.

Do not judge the result by what `fstrim -v` prints: it reports the range it walked as free,
including parts already punched out of the image, so its total over-states the gain. The honest
measure is `on host` before and after: or `du --block-size=1` on the image. A `sudo btrfs balance`
is a different matter again: it addresses the long-term fragmentation of partly-emptied chunks, not
ordinary deletes.
