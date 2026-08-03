# `sbx store`

```
sbx store [--json]
```

Reports what sbx occupies **on disk**: every top-level subtree of its data directory, largest
first, each with its size and its **inode count**, plus the shared nix store's own shape.

[`sbx app list`](app.md) accounts for the app homes and [`sbx projects list`](projects.md) for the
per-project runtime trees. This covers *everything*: including the **shared nix store**, routinely
the largest tree, which [`sbx gc`](gc.md) describes only in terms of what is *reclaimable*, never
what is actually there.

Read-only and free: a filesystem walk. No nix, no network, no sandbox, and nothing is reclaimed.

See also: [`sbx gc`](gc.md) · [`sbx projects`](projects.md) · [`sbx app`](app.md) · [Directory layout](../concepts/directory-layout.md).

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
inode).

When sbx's data lives in a [storage volume](storage.md), a line under the header reports what the
volume's **image really costs the host**: its actual on-disk size, after btrfs compression and
block sharing:

```
sbx store — /run/media/you/sbx-storage (2.1 GiB, 129 889 inodes)
  btrfs volume — 1.4 GiB on host (/home/you/.local/share/sbx-storage.btrfs)
  …
```

The header size stays *apparent* (what the tree occupies uncompressed, each hardlink counted once);
the `btrfs volume` line is the *real* figure: the same `on host` number
[`sbx storage status`](storage.md) reports.

`--json` emits the same data as a document, with the raw `bytes` and `inodes` alongside the
rendered size; on a volume it carries a `volume` object (`image`, `host_bytes`, `host_size`).

## Why inodes are reported

A filesystem can run out of **inodes while it still has free space**, and a nix store is
inode-heavy: many small files.

Some filesystems fix the size of their inode table when they are created; it cannot grow, and once
it is exhausted, writes fail with `ENOSPC` even with gigabytes free. Others allocate inodes on
demand and have no such limit. Check yours with `df -i`.

If the count here is a large share of what `df -i` reports for the filesystem, the levers are
[`sbx gc --all --prune`](gc.md), [`sbx projects rm <id>`](projects.md), `sbx app rm <name> --purge`, or a data directory on a filesystem that allocates inodes on demand.

## How the sizes are counted

Two properties always hold, because they decide whether the numbers agree with other tools:

- **Allocated blocks, not apparent size**: a sparse file counts what it occupies. Same as `du`.
- **A hardlinked file counts once**, however many names point at it. This is essential here: a nix
  store deduplicates identical files into `.links`, so counting each name would roughly *double*
  the reported size of any store.

Whether a size is **exact or an upper bound** then depends on the filesystem, and the last line of
the report says which case yours is:

- Where the filesystem does **not** share storage between files, each file's blocks are its own and
  the sizes are **exact**.
- Where it **does** (copy-on-write), a per-project store reports its full size even though it was
  seeded by a clone that shares most of its storage with the store it came from: and the real
  footprint is smaller still where the filesystem compresses. No per-file measurement can see
  either saving (`du` has the same blind spot), so the sizes are honest **upper bounds**: the true
  on-disk total is smaller, and can be well below what the report shows.

On a [storage volume](storage.md) the report closes that gap with a real number: the `btrfs volume`
line shows the image's actual host footprint, so you see both the apparent tree size and what it
truly costs, the compression and block sharing an upper bound can only allude to.
