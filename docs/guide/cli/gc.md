# `sbx gc`

```
sbx gc [--all] [--prune] [--optimise]
```

Reclaim `sbx`'s nix store space. By default it sweeps the **current project's**
store. Reclamation is irreversible, so the destructive form is opt-in — without
`--prune` it is a **dry run** that touches nothing.

| Option | Meaning |
|---|---|
| `--all` | also collect the **shared** store across every project (orphaned closures), and sweep the runtime files of launches that are gone |
| `--prune` | actually reclaim (default is a dry run) |
| `--optimise` | **deduplicate** the store afterwards: replace identical files by hardlinks to one copy |

Removing whole per-project runtime **trees** (a project whose directory is gone, or a
markerless legacy tree) is a separate command — [`sbx projects rm`](projects.md).

See also: [`sbx store`](store.md) · [`sbx projects`](projects.md) · [Garbage collection](../housekeeping/gc.md) · [Directory layout](../concepts/directory-layout.md) · [Provisioning](../concepts/provisioning.md).

## Behavior

- Without flags: a **dry run** listing what the current project's store would reclaim
  (including builds a `flake:`/`nix:` roll or a removed package superseded).
- `--prune`: performs the reclamation.
- `--optimise`: deduplicates rather than collects — see [Deduplication](#deduplication) below.
- `--all`: also collects the shared store — the closures no live project or locked
  channel revision still roots — under an exclusive lock, and sweeps the **per-launch
  runtime files** of launches that are gone (see below).

## Runtime files

A launch stands up per-launch plumbing under the data directory: the egress MITM CA and
its proxy/control sockets, the inbound forwarder's and the in-cage portal's runtime
directories, the process-observation sockets, the declared-operations plane's socket
directory. Each is unlinked when the launch exits
cleanly — but a cage normally ends on a **signal** (Ctrl-C, `sbx session stop`, a
detached session killed later), and the cleanup does not run then.

So every launch first sweeps whatever its predecessors left, identifying a leftover by
its launcher pid: an entry whose pid is gone is removed, one whose pid is still live is
never touched. `sbx gc --all` runs the same sweep, for a data directory nothing launches
from any more.

**Per-session egress statistics are folded, never swept.** They outlive their session by
design — they are the data [`sbx net stats`](net.md) aggregates — so removing them would
throw away counters you still want. But one file per session, kept forever, is a directory
that only grows, and nothing ever reads a *single* session's numbers: every consumer sums
them.

So the finished ones are added together into one file per project (and app), and the
originals go. The totals are identical before and after; what changes is how many files
hold them. A running session's file is left alone, since it is still being written.
`sbx net stats --reset` remains the way to actually discard counters.

## Examples

```sh
sbx gc                    # dry run: what this project would reclaim
sbx gc --prune            # reclaim this project's store
sbx gc --all --prune      # also collect the shared store
```

To reclaim a removed project tree's store closures, run `sbx gc --all --prune` after
`sbx projects rm`, or do both at once with `sbx projects rm <id> --gc`.

See [Garbage collection](../housekeeping/gc.md) for the details.

## Deduplication

`--optimise` reclaims a different kind of waste: **duplication**, not garbage.

A per-project store is *seeded* from the shared store by **copy** (or reflink, where the
filesystem supports it) — never by hardlink, because a same-uid write inside the cage would
otherwise reach through the link and corrupt the shared copy. So every seeded file arrives
as its own inode, and identical content is held several times over. The shared store
deduplicates as it is built; a seeded store does not.

```sh
sbx gc --optimise             # deduplicate this project's store
sbx gc --all --prune --optimise   # collect everything, then deduplicate both stores
```

It reports what it reclaimed, in **bytes and inodes**:

```
sbx gc: this project's store — deduplicated: freed 21.7 MiB across 2002 inode(s).
```

Running it again is a no-op (`already deduplicated, nothing to reclaim`).

### Why it is safe

Deduplicating **within one store** is sound where linking *across* stores is not: nix keeps
its `.links` pool under the store root it is given, so files can only ever be linked to
others in the **same** store. A cage that writes to one of them is writing into its own
store — something it is already free to do; no other project's store, and not the shared
store, can be reached through such a link. Files that are writable are skipped by nix as
"suspicious", so anything deliberately mutable stays separate.

### Notes

- Unlike a collection, this **deletes nothing**, so it applies immediately rather than
  defaulting to a dry run — asking for it is the consent.
- Run it **after** a `--prune` so nothing about to be collected is deduplicated first;
  passing both flags does this in the right order.
- Scope follows `sbx gc`: this project's store, plus the shared store under `--all`.
- What the stores occupy before and after is [`sbx store`](store.md).
