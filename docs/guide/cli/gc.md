# `ops gc`

```
ops gc [--all] [--prune]
```

Reclaim `ops`'s nix store space. By default it sweeps the **current project's**
store. Reclamation is irreversible, so the destructive form is opt-in — without
`--prune` it is a **dry run** that touches nothing.

| Option | Meaning |
|---|---|
| `--all` | also collect the **shared** store across every project (orphaned closures) |
| `--prune` | actually reclaim (default is a dry run) |

Removing whole per-project runtime **trees** (a project whose directory is gone, or a
markerless legacy tree) is a separate command — [`ops projects rm`](projects.md).

See also: [`ops projects`](projects.md) · [Garbage collection](../housekeeping/gc.md) · [Directory layout](../concepts/directory-layout.md) · [Provisioning](../concepts/provisioning.md).

## Behavior

- Without flags: a **dry run** listing what the current project's store would reclaim
  (including stale rev-keyed `flake:` out-links left by an upgrade).
- `--prune`: performs the reclamation.
- `--all`: also collects the shared store — the closures no live project or locked
  channel revision still roots — under an exclusive lock.

## Examples

```sh
ops gc                    # dry run: what this project would reclaim
ops gc --prune            # reclaim this project's store
ops gc --all --prune      # also collect the shared store
```

To reclaim a removed project tree's store closures, run `ops gc --all --prune` after
`ops projects rm`, or do both at once with `ops projects rm <id> --gc`.

See [Garbage collection](../housekeeping/gc.md) for the details.
