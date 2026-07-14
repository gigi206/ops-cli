# `ops projects`

```
ops projects [list] [--json]
ops projects rm <id>... [--dead] [--markerless] [--dry-run] [--yes] [--gc] [--force]
```

List and remove the **per-project runtime trees** — the directories under
`<data>/projects/<id>` that hold each project's writable nix store, isolated home, and
locks. `ops projects` (or `ops projects list`) shows them; `ops projects rm` removes them.

Removing a tree is host-side only (no sandbox, no nix). Its nix store closures are left for
[`ops gc`](gc.md) to reclaim — or add `--gc` to do both at once.

See also: [`ops gc`](gc.md) · [`ops path`](path.md) · [Garbage collection](../housekeeping/gc.md) · [Directory layout](../concepts/directory-layout.md).

## `list`

The default. Lists every runtime tree with its id, state, on-disk size, last-used date, and
recorded project path — richer than [`ops path`](path.md)'s `projects/` section, which omits
the size. The tree of the directory you are in is marked `*`.

Each tree's **state**:

| State | Meaning |
|---|---|
| `live` | a running session holds it |
| `idle` | its project directory still exists, just not active |
| `dead` | the project directory is gone — removable with `rm --dead` |
| `markerless` | a legacy tree pre-dating marker recording (its project path is unknown) |

`--json` emits the trees as a JSON array for scripting.

## `rm`

| Option | Meaning |
|---|---|
| `<id>...` | remove one or more named trees (the id `ops projects` lists) |
| `--dead` | sweep every tree whose project directory is gone |
| `--markerless` | also sweep markerless legacy trees (no deadness proof) |
| `--dry-run`, `-n` | preview a targeted removal instead of removing |
| `--yes`, `-y` | apply a `--dead` / `--markerless` sweep (they preview by default) |
| `--gc` | after a real removal, collect the shared store's now-orphaned closures |
| `--force`, `-f` | allow removing the current project's own tree |

A named `rm <id>` removes **immediately** — you named it, so it is not an accident; pass
`--dry-run` to preview first. The bulk selectors `--dead` and `--markerless` **preview by
default** and require `--yes` to apply, since they act on more than one tree at once.

Two trees are always protected:

- a tree a **live session** holds is refused — stop it with [`ops stop`](stop.md) first;
- the **current project's** own tree is refused without `--force`.

## Examples

```sh
ops projects                         # list every runtime tree with its state and size
ops projects --json                  # the same, as JSON

ops projects rm 1a2b3c4d5e6f7a8b     # remove one named tree now
ops projects rm 1a2b… --dry-run      # preview it first

ops projects rm --dead --yes         # reap every tree whose project is gone
ops projects rm --dead --yes --gc    # + collect the freed shared-store closures
```

Re-seeding heals a removed tree: the next launch in that project re-seeds its store from the
shared store, so the only cost is a re-fetch/re-seed, not lost work.
