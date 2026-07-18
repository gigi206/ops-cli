# Per-app isolated `$HOME`

Each `sbx app run <name>` gets a **dedicated, persistent, isolated `$HOME`**, so the app's
config, login state, and history never bleed into your project shell or another app.
The `home_scope` field chooses whether that home is also per-project.

See also: [The app framework](README.md) · [`[app.<name>]`](../configuration/apps.md) · [Directory layout](../concepts/directory-layout.md).

## Always isolated

An app's home is **always** per-app and isolated from the project's default shell home.
An agent that logs in, writes a config, or accumulates history does so in its own home
— an `sbx run` in the same project sees none of it, and neither does another app. This
persistence is what lets an agent keep an identity across launches.

## `home_scope` — global vs per-project

```toml
[app.review]
cmd        = "claude"
home_scope = "global"     # the default
```

| Scope | Home location | Meaning |
|---|---|---|
| `"global"` (default) | `<data>/apps/<name>/home` | one home per app, **shared across every project** — the agent keeps a single identity wherever it runs |
| `"project"` | `<data>/projects/<id>/apps/<name>/home` | a home per `(project, app)` — isolates what the agent writes in one project from another |

Choose `"global"` when the agent has one identity you reuse everywhere (a single login,
one set of preferences). Choose `"project"` when you want what the agent writes in one
project kept apart from another.

## `home_scope` is integrity-gated

`home_scope` is an integrity field. An untrusted project may set the scope of *its own*
app but **may not flip a trusted app from `"project"` to `"global"`** — that would route
an untrusted run into the home a trusted run shares (a contamination vector). The safe
direction (`"global"` → `"project"`, more isolation) is allowed. See
[`[app.<name>]` gating](../configuration/apps.md#layering-and-gating).

## What is per-app vs per-project

Only the **home** (and its sibling synthetic `/etc`) becomes app-scoped. The
per-project **store** (`/nix`), the nixpkgs/tools locks, and the mise-config staging
stay **project-scoped** (shared across an app and the project shell). So per-app *home*
isolation is not per-app *store* isolation — a consciously accepted, same-uid,
self-harm-class residual.

### A caveat for global-scope apps

Because `MISE_DATA_DIR` lives under `$HOME`, a `"global"`-scope app's mise **activation
state** is shared across projects, while the store backing `/nix` is per-project. So a
global app that `mise use`s a `nix:` tool in project A persists the *activation*
globally but builds the tool into project A's store only — in project B mise believes
the tool active while B's store lacks it (offline: a hard failure; online: a silent
rebuild). The credentials/login/identity you chose `"global"` *for* persist correctly;
only tool self-equip is the caveat. The mitigation is `home_scope = "project"` (mise
data and store both per-project, aligned).

### A caveat for `flake:` packages in global-scope apps

The same misalignment hits an in-cage-built package. A `flake:` package (and an inline
`[flakes.<name>]`) builds in the cage, and its output lands in the **launching project's**
per-project store — only a symlink to it is kept in the home. So a `"global"`-scope app
launched from a **new** project finds that warm symlink pointing at a store path absent
from the new project's `/nix`, and **rebuilds** on first launch there (minutes; a hard
failure if offline). This is unlike a `nix:` package, which builds into the **shared**
store and is re-seeded into each project offline — so a `nix:` tool never rebuilds in a
fresh project. The mitigation is again `home_scope = "project"`: the home and the
per-project store are then aligned, so a flake built in a project stays reachable there.

## Inspecting a running app

```sh
sbx attach <id>     # join the running app's cage and open a shell inside it
```

`sbx session attach` enters the live cage (its processes, its real `/tmp`, its network, and the
app's isolated home as the agent currently sees it) — not a fresh cage. See
[`sbx session attach`](../cli/session.md#attach) and [Sessions](../housekeeping/sessions.md).

## Removing an app's home

The home persists until you remove it. `sbx app rm <name> --purge` deletes the app's
home(s) — the global one and any per-project ones — freeing the tools its `mise:`
backends installed, its config, and its login state. `sbx app list` shows which apps
have an installed home, with size. Any `nix:`/`flake:` closures in the shared per-project
store are reclaimed by [`sbx gc --prune`](../cli/gc.md) — or add `--gc` to the purge to
sweep the current project's store in one command. See
[`sbx app`](../cli/app.md#removing-an-app).
