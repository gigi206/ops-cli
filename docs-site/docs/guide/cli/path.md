# `sbx path`

```
sbx path [--json]
```

Prints where sbx keeps its state on this machine: the three `<xdg>/sbx` roots it
owns, the **data root** (per-project trees, app homes, the shared nix store, the
embedded engines), the **config root** (the profiles directory and its siblings),
and the **state root** (the trust markers).

Read-only and free: a path listing. No nix, no network, no sandbox.

`--json` prints the same view as JSON.

See also: [`sbx store`](store) · [`sbx projects`](projects) · [`sbx storage`](storage) · [Directory layout](../concepts/directory-layout).

## What it prints

```console
$ sbx path
sbx on-disk locations (grouped by XDG base)

data:    ~/.local/share/sbx  (present)  $SBX_DATA_DIR, else $XDG_DATA_HOME/sbx (else ~/.local/share/sbx)
  store/        ~/.local/share/sbx/store  (present)  shared daemonless nix store (the `nix --store` target)
  engine/       ~/.local/share/sbx/engine  (present)  embedded engines and the exec shim sbx materializes
  plugins/      ~/.local/share/sbx/plugins  (present)  installed resolver plugins (one directory each)
  sessions/     ~/.local/share/sbx/sessions  (present)  session registry read by `sbx session ls`
  logs/         ~/.local/share/sbx/logs  (present)  detached sessions' output, read by `sbx session logs`
  projects/     ~/.local/share/sbx/projects  (present)  per-project runtime trees (store, home, locks)
    fedf617023b39e1b  …/projects/fedf617023b39e1b  (idle)  2026-08-02  ~/src/demo-app  *
    a09391eaba715387  …/projects/a09391eaba715387  (dead)  2026-07-28  ~/src/gone
  apps/         ~/.local/share/sbx/apps  (present)  global app homes (one per app, shared across projects)
    claude-code       ~/.local/share/sbx/apps/claude-code
```

Each `projects/` row carries a liveness state and the last-used date. The `*` marks
the tree for the current directory, `dead` means the project directory itself is
gone (sweepable with [`sbx projects rm --dead`](projects)). An `(absent)` on an
entry simply means nothing has needed it yet. Two more bases follow the `data` one:
`config:` (the profiles directory and its siblings) and `state:` (the trust
markers).

## Examples

```sh
sbx path                                   # every root, with its liveness annotations
sbx path --json | jq -r '.bases[0].root'   # the data root, for a script
sbx path --json | jq '.bases[] | select(.label=="state")'   # where the trust markers live
cd "$(sbx path --json | jq -r '.bases[0].entries[] | select(.label=="store/") | .path')"
```

`sbx path` answers "where does sbx put things", including before the directory
exists. For where a *config file* is read from, in resolution order, use
[`sbx config path`](config#sbx-config-path) instead; for the size of what is in
those trees, [`sbx store`](store) and [`sbx projects list`](projects).
