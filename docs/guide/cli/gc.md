# `ops gc`

```
ops gc [--all] [--prune]
```

Reclaim `ops`'s per-project store space. By default it sweeps the **current project's**
store. Reclamation is irreversible, so the destructive form is opt-in — without
`--prune` it is a **dry run** that touches nothing.

| Option | Meaning |
|---|---|
| `--all` | also reap whole runtime trees whose project directory is gone |
| `--prune` | actually reclaim (default is a dry run) |

See also: [Garbage collection](../housekeeping/gc.md) · [Directory layout](../concepts/directory-layout.md) · [Provisioning](../concepts/provisioning.md).

## Behavior

- Without flags: a **dry run** listing what the current project's store would reclaim
  (including stale rev-keyed `flake:` out-links left by an upgrade).
- `--prune`: performs the reclamation.
- `--all`: extends the sweep to whole per-project runtime trees whose project directory
  no longer exists, and runs a shared-store collection under an exclusive lock.

## Examples

```sh
ops gc                    # dry run: what this project would reclaim
ops gc --prune            # reclaim this project's store
ops gc --all --prune      # also reap dead project trees + collect the shared store
```

See [Garbage collection](../housekeeping/gc.md) for the details.
