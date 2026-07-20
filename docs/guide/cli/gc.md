# `sbx gc`

```
sbx gc [--all] [--prune]
```

Reclaim `sbx`'s nix store space. By default it sweeps the **current project's**
store. Reclamation is irreversible, so the destructive form is opt-in — without
`--prune` it is a **dry run** that touches nothing.

| Option | Meaning |
|---|---|
| `--all` | also collect the **shared** store across every project (orphaned closures) |
| `--prune` | actually reclaim (default is a dry run) |

Removing whole per-project runtime **trees** (a project whose directory is gone, or a
markerless legacy tree) is a separate command — [`sbx projects rm`](projects.md).

See also: [`sbx projects`](projects.md) · [Garbage collection](../housekeeping/gc.md) · [Directory layout](../concepts/directory-layout.md) · [Provisioning](../concepts/provisioning.md).

## Behavior

- Without flags: a **dry run** listing what the current project's store would reclaim
  (including builds a `flake:`/`nix:` roll or a removed package superseded).
- `--prune`: performs the reclamation.
- `--all`: also collects the shared store — the closures no live project or locked
  channel revision still roots — under an exclusive lock.

## Examples

```sh
sbx gc                    # dry run: what this project would reclaim
sbx gc --prune            # reclaim this project's store
sbx gc --all --prune      # also collect the shared store
```

To reclaim a removed project tree's store closures, run `sbx gc --all --prune` after
`sbx projects rm`, or do both at once with `sbx projects rm <id> --gc`.

See [Garbage collection](../housekeeping/gc.md) for the details.
