---
description: "Report what sbx occupies on disk, per project and in the shared store."
---

# `sbx store`

```
sbx store [--shared] [--json]
```

Reports what sbx occupies **on disk**: every top-level subtree of its data directory, largest
first, each with its size and its **inode count**, plus the shared nix store's own shape.

[`sbx app list`](app) accounts for the app homes and [`sbx projects list`](projects) for the
per-project runtime trees. This covers *everything*: including the **shared nix store**, routinely
the largest tree, which [`sbx gc`](gc) describes only in terms of what is *reclaimable*, never
what is actually there.

Read-only: a filesystem walk. No nix, no network, no sandbox, and nothing is reclaimed.

See also: [`sbx gc`](gc) · [`sbx projects`](projects) · [`sbx app`](app) · [Directory layout](../concepts/directory-layout).

## Output

```
sbx store — /home/you/.local/share/sbx (34.4 GiB, 589 948 inodes)
  apps/              13.1 GiB  201 874 inodes  global app homes (one per app, shared across projects)
  projects/          10.7 GiB  156 824 inodes  per-project runtime trees (store, home, locks)
  store/             10.6 GiB  230 342 inodes  shared daemonless nix store (the `nix --store` target)
  engine/            38.8 MiB        6 inodes  embedded nix + bwrap engines sbx materializes
  …

  shared store: 5 310 realised path(s), 167 256 file(s) deduplicated into `.links`
```

The trailing line describes the shared store in its own terms: how many store paths are realised,
and how many files nix has deduplicated into its `.links` pool (identical content sharing a single
inode). When the store directory or the pool cannot be read, the line says so instead of counting
nothing, and `--json` carries that count as `null`.

Before anything is provisioned the data directory may not exist yet, and the report says
`(nothing provisioned yet)`. A data directory that exists but cannot be listed is an error
(exit `1`), never an empty report.

An entry that is a symbolic link, such as a store moved to another disk and linked back, is shown
with a trailing `@` and what it points at. It is sized as the link: its target is not followed, so
nothing under it is counted. `--json` carries the target as `link_target`.

When sbx's data lives in a [storage volume](storage), a line under the header reports what the
volume's **image really costs the host**: its actual on-disk size, after btrfs compression and
block sharing:

```
sbx store — /run/media/you/sbx-storage (2.1 GiB, 129 889 inodes)
  btrfs volume — 1.4 GiB on host (/home/you/.local/share/sbx-storage.btrfs)
  …
```

The header size stays *apparent* (what the tree occupies uncompressed, each hardlink counted once);
the `btrfs volume` line is the *real* figure: the same `on host` number
[`sbx storage status`](storage) reports.

`--json` emits the same data as a document, with the raw `bytes` and `inodes` alongside the
rendered size, and `unreadable`, the number of entries that could not be read; on a volume it
carries a `volume` object (`image`, `host_bytes`, `host_size`).

## What each subtree holds alone: `--shared`

The plain report counts blocks, which cannot tell a block a tree owns from one it shares (see
[below](#how-the-sizes-are-counted)). `--shared` asks the filesystem instead: it opens every file
and reads its extents with `FIEMAP`, the ioctl `btrfs filesystem du` uses, which needs no
privilege. On a storage volume holding a project store seeded from the shared one:

```
sbx store — /run/media/you/sbx-storage (103.1 GiB, 2 085 890 inodes)
  btrfs volume — 46.0 GiB on host (/home/you/.local/share/sbx-storage.btrfs)
  apps/              55.9 GiB  1 053 917 inodes   48.0 GiB exclusive  global app homes (one per app, shared across projects)
  projects/          24.1 GiB    318 903 inodes    1.5 GiB exclusive  per-project runtime trees (store, home, locks)
  store/             23.1 GiB    711 592 inodes  448.8 MiB exclusive  shared daemonless nix store (the `nix --store` target)
  …

  extents, read from the filesystem:
   99.6 GiB  file data, every reference counted
  −27.6 GiB  shared between files, counted once
   71.9 GiB  distinct file data, before compression
  −28.4 GiB  compression and allocation: the difference to what is stored
   43.5 GiB  data on disk
   +2.6 GiB  metadata on disk, inline file contents included
```

**`exclusive`** is the file data no other subtree references: what removing that subtree alone
frees inside the filesystem. Here the project store and the shared store report 23 GiB each, and
together hold under 2 GiB of their own: the rest is one copy, referenced from both.

The **breakdown** walks from what the files reference to what the filesystem stores:

- **file data, every reference counted** is `btrfs filesystem du`'s total: a block shared by two
  files counts twice.
- **shared between files** is what counting each extent once saves, and **distinct file data** what
  is left. These figures are **before compression**: a file's extents report their logical length,
  never their compressed size.
- On a [storage volume](storage), the breakdown goes on to what the filesystem stores, from its
  own accounting: **data** and **metadata** on disk. The step between distinct and stored data is
  a **difference**, not a compression ratio: it also holds allocation effects, such as an extent
  that stays whole on disk after a file stopped referencing part of it. Off a volume these lines
  are left out, because the filesystem's accounting then covers whatever else it holds.

Small files whose contents the filesystem keeps inline, in its metadata, are counted apart, as a
number of files and their size: they occupy metadata, not data.

Three limits, stated rather than hidden:

- **Exclusive is before compression**, and is space freed *inside* the filesystem. On a volume the
  host gets it back only once that space is discarded: see [Releasing it](storage#releasing-it).
- **References from outside the data directory are invisible.** An extent shared with a file the
  walk never visits counts as the subtree's own. A storage volume holds nothing else, so this
  concerns a data directory on a filesystem shared with other data.
- **It costs a query per file.** On a volume of two million inodes it took about 35 seconds with a
  warm cache, against a few for the plain report. An entry that cannot be read is counted under
  the breakdown, since its bytes are missing from every figure.

With `--json`, each subtree carries `exclusive_bytes` and the document an `extents` object:
`referenced_bytes`, `distinct_bytes`, `inline_files`, `inline_bytes`, `unreadable`, and on a volume
`data_on_disk_bytes` and `metadata_on_disk_bytes`.

## Examples

```sh
sbx store                        # every subtree, largest first
sbx store --json                 # the same, machine-readable
sbx store --json | jq -r '.size, .inodes'                       # the totals alone
sbx store --json | jq -r '.subtrees[] | "\(.size)\t\(.label)"'  # a two-column report
sbx store --json | jq '.volume'  # the real host cost, on a storage volume (null otherwise)
sbx store --shared               # …and what each subtree holds alone
sbx store --shared --json | jq -r '.subtrees[] | "\(.exclusive_bytes)\t\(.label)"'
```

Two questions this answers that no other verb does:

```sh
# Is the inode count a problem on this filesystem?
sbx store --json | jq .inodes ; df -i "$(sbx path --json | jq -r .bases[0].root)"

# How much of the total is the shared store, before deciding to gc?
sbx store --json | jq -r '.subtrees[] | select(.label=="store/") | .size'
sbx gc --all                     # …then see what of it is actually reclaimable
```

`sbx store` reports what **is** on disk; [`sbx gc`](gc) reports what is
**reclaimable**. They are different numbers, which is why `gc` defaults to a dry run:
it tells you how much of the size reported here a sweep would actually return.

## Why inodes are reported

A filesystem can run out of **inodes while it still has free space**, and a nix store is
inode-heavy: many small files.

Some filesystems fix the size of their inode table when they are created; it cannot grow, and once
it is exhausted, writes fail with `ENOSPC` even with gigabytes free. Others allocate inodes on
demand and have no such limit. Check yours with `df -i`.

If the count here is a large share of what `df -i` reports for the filesystem, the levers are
[`sbx gc --all --prune`](gc), [`sbx projects rm <id>`](projects), `sbx app rm <name> --purge`, or a data directory on a filesystem that allocates inodes on demand.

## How the sizes are counted

Two properties always hold, because they decide whether the numbers agree with other tools:

- **Allocated blocks, not apparent size**: a sparse file counts what it occupies. Same as `du`.
- **A hardlinked file counts once**, however many names point at it. This is essential here: a nix
  store deduplicates identical files into `.links`, so counting each name would roughly *double*
  the reported size of any store.

An entry the walk cannot read, such as a directory whose mode refuses you or a tree nested deeper
than a path can name, is counted rather than skipped in silence. Its bytes are missing from every
size, so a line under the rows says how many such entries there are:

```
  1 entry could not be read; its bytes are missing from these figures.
```

Whether a size is **exact or an upper bound** then depends on the filesystem, and the last line of
the report says which case yours is:

- Where the filesystem does **not** share storage between files, each file's blocks are its own and
  the sizes are **exact**.
- Where it **does** (copy-on-write), a per-project store reports its full size even though it was
  seeded by a clone that shares most of its storage with the store it came from, and the real
  footprint is smaller still where the filesystem compresses. A block count sees neither saving
  (`du` has the same blind spot), so the sizes are honest **upper bounds**: the true on-disk total
  is smaller, and can be well below what the report shows. [`--shared`](#what-each-subtree-holds-alone---shared)
  reads the sharing itself.
- Where the sharing probe itself fails, the report says so: every size may then be an upper
  bound, claimed as neither exact nor CoW-measured.

On a [storage volume](storage) the report closes that gap with a real number: the `btrfs volume`
line shows the image's actual host footprint, so you see both the apparent tree size and what it
truly costs, the compression and block sharing an upper bound can only allude to.
