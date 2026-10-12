---
description: "Give sbx's data directory a compressed, self-growing filesystem of its own."
---

# `sbx storage`

```
sbx storage init [--image <path>] [--size <n>] [--label <name>] [--metadata-dup]
sbx storage migrate [--image <path>] [--force]
sbx storage use [--image <path>] [--force]
sbx storage status [--image <path>] [--json]
sbx storage up [--image <path>]
sbx storage down [--image <path>]
sbx storage unuse
```

Gives sbx a filesystem of its own for its data directory: a **sparse image file carrying a
compressed btrfs filesystem**, which grows as it is written and costs the host a **single
inode** no matter how many files it holds. Each verb takes only the flags listed
above for it: a flag belonging to another verb is refused with a usage error rather than
accepted and ignored, so `sbx storage use --size 50G` says the size is not read there
instead of exiting 0 having thrown it away.

Adopted by default on a fresh install that can mount it (see
[Adopted on first launch](#adopted-on-first-launch)); everywhere else sbx keeps its data in a plain
directory: see [Directory layout](../concepts/directory-layout).

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
This is why a volume is never a prerequisite: sbx adopts one by itself only from a terminal on a
host that can mount it, and keeps a plain directory everywhere else.

The one requirement is **`udisks2`**, and it is unavoidable: it is a system daemon, and the
privilege lives with it rather than with any binary sbx could ship.

`btrfs-progs` is **not** required. It is not installed on every distribution, so if the host
has no `mkfs.btrfs`, sbx provisions `btrfs-progs` and runs it sandboxed, `init` says which it used.
The provisioned copy goes into a store set apart from sbx's own (`storage-tools` in the data
directory), which is removed once the volume is formatted: the data directory's store is never
touched, so the volume can be adopted straight after, and the nixpkgs source it is built from, a
few hundred megabytes, does not stay behind. The price is a fresh download each time a volume is
created. It is built from the channel the data directory's nixpkgs lock already records, which it
reads and never writes, so creating a volume never moves that channel: only
[`sbx upgrade nix`](upgrade) rolls it. Using a volume needs no `btrfs` binary at all: compression
rides an extended attribute and space accounting an ioctl. Every file created on the volume inherits
that attribute, and nix normally strips extended attributes when it finalizes a store path, which would abort a build whose files are already read-only: so on a btrfs-backed store sbx
tells nix (host-side and in-cage alike) to leave `btrfs.compression` in place. The data was
already written compressed, so nothing is lost.

You do not have to find out the hard way. [`sbx doctor`](doctor) reports the storage line, the filesystem the data directory sits on, and whether an encapsulated volume is available,
already redundant (the data is on a copy-on-write filesystem such as btrfs or ZFS), or blocked
(and why). And `up`/`use` **fail early with a single message** naming every missing
prerequisite, rather than surfacing the first obstacle deep in the mount.

## Adopted on first launch

On the **first interactive launch** (`sbx run`, `sbx app run …`) of an eligible host, a fresh
install adopts a volume **by default**, without asking, and keeps the plain directory only when the
volume cannot be set up. It happens **once**, recorded so it never runs again, not at all once
`init`, `use`, `unuse` or `migrate` has settled where the data lives, and only when connected to a
**terminal**: an agent, a pipe, CI, a cron job or a service unit never has its
storage decided for it, and the autonomous-agent path meets no prompt at all.
[`sbx doctor`](doctor) remains the standing reminder for a data directory that kept the plain
layout.

What happens depends on what is already there:

- **A fresh install (empty data directory)**: sbx creates and mounts a volume on the spot (there is
  nothing to copy) and uses it from that launch on. It says where the volume is mounted, that after
  a reboot your desktop session should be open before the first sbx command (see
  [Mounting is automatic](#mounting-is-automatic)), and that `sbx storage unuse` goes back to a
  plain directory, whose store is then downloaded again. When the volume cannot be set up, sbx says
  why, removes the image it had just created, and carries on with the plain directory. The
  directory is checked again right before the volume is recorded, so a launch from another terminal
  that filled it in the meantime makes sbx stop short of adopting.
- **An existing data directory**: a single, non-blocking line pointing at `sbx storage migrate`,
  never an inline copy: migrating is slow and can fail its own checks, and it should not hijack
  the command you actually ran.

A volume is adopted only where it is genuinely worth it: a mountable host (btrfs, loop devices
and udisks2 present), a **local session**, and a filesystem that does not already give sbx what a
volume would. A volume brings two things: it **shares blocks** between files, so seeding a
per-project store from the shared one costs almost nothing, and it **compresses**: so the question
is whether either is missing:

| Data directory on | shares blocks | compresses | adopted? |
|---|---|---|---|
| btrfs, ZFS, bcachefs | yes | yes | no, and nesting one copy-on-write filesystem in another only compounds fragmentation |
| XFS | yes (`reflink=1`) | no | yes, for the compression |
| ext2/3/4 | no | no | yes, and it relieves the fixed inode table too |
| tmpfs | n/a | n/a | no: nothing here survives a reboot |
| anything else | measured | unknown | only if it turns out not to share blocks |

For a filesystem sbx does not recognize there is no table to consult, so it **measures** block
sharing by attempting one in the data directory, and adopts a volume only on a definite "cannot",
rather than guessing about compression. Set
[`SBX_DATA_DIR`](../reference/environment-variables#sbx_data_dir) and this step is skipped
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
       `sbx storage migrate` copies it into the volume and switches over; or pass --force to
       adopt an empty volume anyway.
```

The check runs before the volume is mounted, so a refusal leaves nothing mounted behind it.
`use` also refuses while a sandbox is running from the data directory sbx follows now: once the
pointer names another one, [`sbx session ls`](session) and `sbx session stop` no longer see that
sandbox. `--force` does not waive this check, and neither does a session registry that cannot be
read, which counts as a refusal rather than as "nothing running".

It refuses for the same reason when sbx **already follows another volume**. The data directory
then holds only the pointer, so the check above finds nothing at risk; the store, projects and app
homes live in the adopted volume, and repointing hides them just as silently, with `unuse`
afterwards returning to the plain directory rather than to them:

```console
$ sbx storage use --image /mnt/other.btrfs
sbx storage: sbx already uses /run/media/you/sbx-storage.btrfs — adopting another volume would
leave its store, projects and app homes behind, not move them.
       `sbx storage unuse` first if you meant to switch, or pass --force.
```

The image is created **beside** the data directory (`<xdg-data>/sbx-storage.btrfs`), never
inside it, the volume is what that directory becomes. `--image <path>` puts it elsewhere, on
another disk for instance; it must be absolute, and is refused before anything mounts otherwise.
`init` formats the volume from an empty directory it creates beside the image under the same
name, `x.seed` for `x.btrfs`, and removes it afterwards. A directory already at that name is
refused rather than emptied or reused, since it may be yours; one a format that did not finish
left behind is yours to remove.

Adopting a volume records its path as one quoted line in `storage.toml`, which is read back
without unescaping. So the path may be anything absolute that carries no quote, no backslash and
no control character; spaces and accents are fine. A path that carries one is refused the moment
you pass it, with a message saying which character, rather than being written and read back later
as a different path, or not at all. Edited by hand, the line may end with a `#` comment; any other
text after the closing quote, a value that is not one double-quoted path, or a relative path, makes
every launch refuse until the line is fixed. A line removed, commented out or emptied names no volume at all:
sbx stops following it, as `sbx storage unuse` does, and moves nothing back.

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
room, are both privileged, and `udisks` grants neither unattended: on a real volume,
`losetup --set-capacity` and `btrfs filesystem resize` each return *Operation not permitted* for an
ordinary user.

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

## One copy of the metadata, or two

`init` writes the filesystem's metadata **once**, the `single` profile. `mkfs.btrfs` on its own
writes it twice on a single device, the `DUP` profile, so that a metadata block that goes bad is
repaired from its twin instead of taking part of the filesystem with it. sbx does not take that
default, for two reasons:

- **The two copies share every point of failure but one.** They land in the same image file, on the
  same disk; they guard against a single bad block, never against the disk. An SSD may even merge
  the two identical writes into one, which `mkfs.btrfs` itself names as the case where the second
  copy protects nothing.
- **They cost a metadata-sized share of the volume.** A nix store is inode-heavy, and its metadata
  runs on the order of 8% of its data.

`--metadata-dup` keeps the two copies, for whoever prefers the redundancy over the space:

```console
$ sbx storage init --metadata-dup
```

`init` always names the profile it uses on the `mkfs.btrfs` command line, so the result is the same
whichever `btrfs-progs` performs the format. The volume sbx creates by itself on
[first launch](#adopted-on-first-launch) takes the default, `single`.

Like the size, the profile is settled **at `init`**. Converting an existing volume is a
`btrfs balance`, which requires root, and which sbx never runs for you:

```console
$ sudo btrfs balance start -mconvert=single -sconvert=single -f /run/media/you/sbx-storage  # two copies to one
$ sudo btrfs balance start -mconvert=dup -sconvert=dup -f /run/media/you/sbx-storage        # one copy to two
```

`-f` is required to act on the system block group, and to reduce redundancy. Only the metadata is
rewritten, so the balance is short. `btrfs filesystem df` on the mount point shows the profile
before and after, and needs no privilege.

**The image grows before it shrinks.** The balance writes the metadata into fresh block groups and
frees the old ones inside the filesystem, but the blocks those occupied stay in the image file:
`inside` drops while `on host` rises. They are part of [**reclaimable**](#status) from then on, and
return the way any freed space does: see [Releasing it](#releasing-it).

## Mounting is automatic

`udisks` mounts under `/run`, which is cleared on reboot: so a volume is unmounted every time
you log in. sbx mounts it on demand, so this is invisible while your desktop session is open:
udisks then mounts without a password, whether the command runs in that session or in one of your
services. After a reboot, open it before the first sbx command; where udisks would need
administrator authentication instead, see [Where it works](#where-it-works-and-where-it-does-not).

`sbx storage up` exists for the rare case where you want the mount without waiting for the
next command; it is idempotent. `sbx storage down` unmounts, but while the volume is adopted
the next sbx command simply mounts it again, and `down` says so.

**If an adopted volume cannot be mounted, sbx stops** rather than carrying on. This is
deliberate: the mount point exists only while mounted and lives on a tmpfs, so continuing
would provision gigabytes into RAM and report an empty store as the truth. The refusal says how
out: [`sbx doctor`](doctor), or any launch, run from your desktop session mounts the volume, and
`sbx storage unuse` goes back to the plain directory, leaving the volume's data in it.

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
[`sbx doctor`](doctor) leads with). A filesystem that cannot be identified reads `unknown`.

`status`, `up` and `down` warn on stderr when the volume pointer (`storage.toml`) exists but cannot
be read, rather than reporting the volume as not adopted: every launch refuses on such a pointer,
so whether sbx follows the volume is then unknown.

**on host** is what the volume costs, against the logical ceiling it was created with. **inside**
is the filesystem's own view: what its data occupies, and how much of the ceiling it has carved
into block groups to hold it. The two are counted **the same way, as blocks on the device**, so
the subtraction between them is the third line, and whenever there is something to reclaim you can
check it yourself.

That last point is worth spelling out, because btrfs itself counts differently. A volume created
with [`--metadata-dup`](#one-copy-of-the-metadata-or-two) writes every metadata block twice, and
btrfs reports the pair as one. `inside` counts them as they are written, which is why on such a
volume it can exceed what you think you stored: a nix store's metadata runs on the order of 8% of
its data, so expect that much overhead and no surprise in it. A volume created without the flag
writes its metadata once, and the figure carries no such overhead. **Compression is not visible
here**: `used` is
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
there, and when the session registry cannot be read to tell. Stop them first with [`sbx session stop --all`](session). While the volume is
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
measure is `on host` before and after, or `du --block-size=1` on the image. A `sudo btrfs balance`
is a different matter again: it addresses the long-term fragmentation of partly-emptied chunks, not
ordinary deletes.

## Examples

The whole life cycle of a volume, in the order you meet the commands.

Starting fresh, with nothing yet in the data directory:

```sh
sbx storage init                  # create the image (200 GiB logical, sparse)
sbx storage init --size 500G      # …or a different ceiling; it costs nothing until filled
sbx storage init --image /mnt/ssd/sbx.btrfs   # …on another disk
sbx storage init --metadata-dup   # …keeping two copies of every metadata block
sbx storage use                   # adopt it; mounted automatically from now on
```

Starting with an installation that already has a store, projects, or app homes: `use`
refuses, and `migrate` is the command that moves them:

```sh
sbx session stop --all            # nothing may be running from the data directory
sbx storage migrate               # copy, verify, then switch over
```

`migrate` keeps the original authoritative for the whole copy and sets it aside under a
dated name rather than deleting it, so an interruption before the switch leaves the
installation exactly as it was. It asks again for running sandboxes once the copy is verified,
right before the switch, since one may have started during a long copy; if one has, nothing is
switched and the volume is cleared as after a failed copy. A volume whose free space cannot be
read is refused before the copy starts, rather than risking a copy that fails half-way. The
dated name is always a new directory: should it be taken, a `-1`, `-2`… suffix follows. Migrating into a volume that already holds a data
directory (`store`, `projects`, `apps`) is refused, unless `--force` overrides it.

Living with it:

```sh
sbx storage status                # where it stands, and what it costs the host
sbx storage status --json | jq '.host_bytes, .reclaimable_bytes, .state'
sbx store                         # what is inside it, subtree by subtree
sbx doctor                        # the `storage` line reports the posture
```

Releasing it, temporarily or for good:

```sh
sbx storage down                  # unmount now (refuses while a sandbox runs from it)
sbx storage up                    # mount it now, rather than at the next command
sbx storage unuse                 # go back to the ordinary data directory, volume untouched
```

`down` is temporary while the volume is adopted: the next sbx command mounts it again.
`unuse` is the deliberate reversal, and it deletes nothing.

For a one-off run somewhere else entirely, bypass the whole mechanism:

```sh
SBX_DATA_DIR=/tmp/sbx-scratch sbx run -- ./build.sh
```

That also skips the first-launch adoption: an explicit
[`SBX_DATA_DIR`](../reference/environment-variables#sbx_data_dir) is the invoker's own
choice about where data lives.
