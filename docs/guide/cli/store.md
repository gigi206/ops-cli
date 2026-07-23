# `sbx store`

```
sbx store [--json]
```

Reports what sbx occupies **on disk**: every top-level subtree of its data directory, largest
first, each with its size and its **inode count**, plus the shared nix store's own shape.

[`sbx app list`](app.md) accounts for the app homes and [`sbx projects list`](projects.md) for the
per-project runtime trees. This covers *everything* — including the **shared nix store**, routinely
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

`--json` emits the same data as a document, with the raw `bytes` and `inodes` alongside the
rendered size.

## Why inodes are reported

A filesystem can run out of **inodes while it still has free space**, and a nix store is
inode-heavy — many small files.

- **ext4** fixes the size of its inode table when the filesystem is created. It cannot grow. Once
  exhausted, writes fail with `ENOSPC` even with gigabytes free. Check yours with `df -i`.
- **btrfs** and **XFS** allocate inodes on demand and have no such limit.

If the count here is a large share of what `df -i` reports for the filesystem, the levers are
[`sbx gc --all --prune`](gc.md), [`sbx projects rm <id>`](projects.md), `sbx app rm <name> --purge`
— or moving the data directory to btrfs/XFS.

## How the sizes are counted

Two properties worth knowing, because they decide whether the numbers agree with other tools:

- **Allocated blocks, not apparent size** — a sparse file counts what it occupies. Same as `du`.
- **A hardlinked file counts once**, however many names point at it. This is essential here: a nix
  store deduplicates identical files into `.links`, so counting each name would roughly *double*
  the reported size of any store.

One deliberate blind spot: **extents shared by reflink are not detected.** On a copy-on-write
filesystem (btrfs, XFS) a per-project store shares nearly every extent with the shared store it was
seeded from, yet still reports its full size, because no cheap system call exposes extent sharing
(`du` has the same gap). On such a filesystem the total is an **upper bound** and can exceed what
`df` reports as used — the per-project trees are far cheaper than they look.
