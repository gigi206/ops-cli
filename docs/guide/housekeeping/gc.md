# Garbage collection

`sbx` provisions a per-project nix store and, over time, leaves reclaimable residue —
superseded closures and stale rev-keyed `flake:` out-links. `sbx gc` reclaims the nix
store; whole per-project runtime **trees** (for projects that no longer exist) are removed
by [`sbx projects rm`](../cli/projects.md).

See also: [`sbx gc`](../cli/gc.md) · [`sbx projects`](../cli/projects.md) · [Provisioning](../concepts/provisioning.md) · [Directory layout](../concepts/directory-layout.md).

## Dry run by default

Reclamation is **irreversible**, so `sbx gc` is a **dry run by default** — it lists what
*would* be reclaimed and touches nothing. Pass `--prune` to actually reclaim:

```sh
sbx gc                    # dry run: what this project's store would reclaim
sbx gc --prune            # reclaim this project's store
```

## Scope

| Invocation | What it sweeps |
|---|---|
| `sbx gc` | the **current project's** store (dry run) |
| `sbx gc --prune` | the current project's store (reclaim) |
| `sbx gc --all` | also the **shared** store's orphaned closures (dry run) |
| `sbx gc --all --prune` | the above, collected under an exclusive lock |

- The per-project sweep reclaims a project's own store residue, including the **stale
  rev-keyed `flake:` out-links** an [`sbx upgrade flake`](upgrade.md) leaves behind
  (each roll `A → B` leaves the old `<name>-A` out-link and its closure).
- `--all` collects the shared nix store — the closures no live project or locked channel
  revision still roots — under an exclusive lock so a concurrent launch cannot race it.
- Removing a whole per-project runtime **tree** is [`sbx projects rm`](../cli/projects.md);
  its store closures are then reclaimed by `sbx gc --all --prune` (or in one step,
  `sbx projects rm <id> --gc`).

## Examples

```sh
sbx gc                    # see what's reclaimable in this project
sbx gc --prune            # free this project's residue
sbx gc --all --prune      # + collect the shared store
```

Re-seeding heals what a sweep removes: a launch re-seeds the project store from the
shared store, so `gc` is safe to run — the cost is a re-fetch/re-seed on the next launch,
not lost work.
