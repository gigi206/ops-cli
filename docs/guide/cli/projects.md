# `sbx projects`

```
sbx projects list [--json]
sbx projects show <id> [--json]
sbx projects rm <id>... [--dead] [--markerless] [--dry-run] [--yes] [--gc] [--force]
```

List, inspect, and remove the **per-project runtime trees** — the directories under
`<data>/projects/<id>` that hold each project's writable nix store, isolated home, and
locks. `sbx projects list` shows them; `sbx projects show` details one; `sbx projects rm`
removes them. Bare `sbx projects` prints this page.

Removing a tree is host-side only (no sandbox, no nix). Its nix store closures are left for
[`sbx gc`](gc.md) to reclaim — or add `--gc` to do both at once.

See also: [`sbx gc`](gc.md) · [`sbx path`](path.md) · [Garbage collection](../housekeeping/gc.md) · [Directory layout](../concepts/directory-layout.md).

## `list`

Lists every runtime tree with its id, state, on-disk size, last-used date, and
recorded project path — richer than [`sbx path`](path.md)'s `projects/` section, which omits
the size. The tree of the directory you are in is marked `*`.

Each tree's **state**:

| State | Meaning |
|---|---|
| `live` | a running session holds it |
| `idle` | its project directory still exists, just not active |
| `dead` | the project directory is gone — removable with `rm --dead` |
| `markerless` | a legacy tree pre-dating marker recording (its project path is unknown) |

`--json` emits the trees as a JSON array for scripting.

## `show`

`sbx projects show <id>` reports one tree's **realized-on-disk** detail:

- its **state** and **size**, broken down `store` / `home` / `other`;
- the **nixpkgs** channel or per-project pin it resolves against;
- the **store roots** built in its store, grouped by backend (`nix`, `deb`, `appimage`) —
  the store is **shared** by the project and every app launched in it, so the roots include
  app packages;
- the **mise tools** in the project's own home;
- when the project directory still exists, the project's declared packages/tools that are
  **not built yet** — an untrusted declaration is flagged `withheld` (a launch would not
  provision it), distinct from a trusted one simply not equipped yet. A dead tree shows
  realized state only.

Read-only (no sandbox, no nix, no network). `--json` emits the same model. For an app rather
than a tree, see [`sbx app show`](app.md).

## `rm`

| Option | Meaning |
|---|---|
| `<id>...` | remove one or more named trees (the id `sbx projects list` shows) |
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

- a tree a **live session** holds is refused — stop it with [`sbx session stop`](session.md#stop) first;
- the **current project's** own tree is refused without `--force`.

## Examples

```sh
sbx projects list                    # list every runtime tree with its state and size
sbx projects list --json             # the same, as JSON
sbx projects show 1a2b3c4d5e6f7a8b   # one tree's realized detail (store roots, tools, size)

sbx projects rm 1a2b3c4d5e6f7a8b     # remove one named tree now
sbx projects rm 1a2b… --dry-run      # preview it first

sbx projects rm --dead --yes         # reap every tree whose project is gone
sbx projects rm --dead --yes --gc    # + collect the freed shared-store closures
```

Re-seeding heals a removed tree: the next launch in that project re-seeds its store from the
shared store, so the only cost is a re-fetch/re-seed, not lost work.
