# Per-app isolated `$HOME`

Each `sbx app run <name>` gets a **dedicated, persistent, isolated `$HOME`**, so the app's
config, login state, and history never bleed into your project shell or another app.
The `home_scope` field chooses whether that home is also per-project.

See also: [The app framework](../apps/) · [`[app.<name>]`](../configuration/apps) · [Directory layout](../concepts/directory-layout).

## Always isolated

An app's home is **always** per-app and isolated from the project's default shell home.
An agent that logs in, writes a config, or accumulates history does so in its own home, an `sbx run` in the same project sees none of it, and neither does another app. This
persistence is what lets an agent keep an identity across launches.

## `home_scope`: global vs per-project

```toml
[app.review]
cmd        = "claude"
home_scope = "global"     # the default
```

| Scope | Home location | Meaning |
|---|---|---|
| `"global"` (default) | `<data>/apps/<name>/home` | one home per app, **shared across every project**: the agent keeps a single identity wherever it runs |
| `"project"` | `<data>/projects/<id>/apps/<name>/home` | a home per `(project, app)`, isolates what the agent writes in one project from another |

Choose `"global"` when the agent has one identity you reuse everywhere (a single login,
one set of preferences). Choose `"project"` when you want what the agent writes in one
project kept apart from another.

## `home_scope` is integrity-gated

`home_scope` is an integrity field. An untrusted project may set the scope of *its own*
app but **may not flip a trusted app from `"project"` to `"global"`**: that would route
an untrusted run into the home a trusted run shares (a contamination vector). The safe
direction (`"global"` → `"project"`, more isolation) is allowed. See
[`[app.<name>]` gating](../configuration/apps#layering-and-gating).

## What is per-app vs per-project

Only the **home** (and its sibling synthetic `/etc`) becomes app-scoped. The
per-project **store** (`/nix`), the nixpkgs/tools locks, and the mise-config staging
stay **project-scoped** (shared across an app and the project shell). So per-app *home*
isolation is not per-app *store* isolation: a consciously accepted, same-uid,
self-harm-class residual.

### Two mise pools keep a global app's self-equips aligned

A `"global"`-scope app keeps **one** home: its identity, login, and mise **activation
state**, shared across every project, while the store backing `/nix` is per-project. To
keep a `nix:`-via-mise self-equip aligned with that per-project store, sbx splits a global
app's mise install storage into two pools:

| Pool | Location | Holds | Scope |
|---|---|---|---|
| **app-global** | `<data>/apps/<name>/home/.local/share/mise` | the app's own `[packages] mise:` tools | shared across projects |
| **per-project** | `<data>/projects/<id>/apps/<name>/mise` | the agent's `nix:`-via-mise self-equips and the project's `mise.toml` tools | per-project, `/nix`-aligned |

So when a global app runs `mise use nix:<tool>` in project A, the install lands in A's
per-project pool (aligned with A's `/nix`). In project B, mise correctly sees it as
not-installed and rebuilds into B's store: a **clean per-project rebuild**, not a stale
app-global record pointing at A's store (the "active but absent" failure this split
removes). The app's own `[packages] mise:` tools stay in the shared app-global pool
(installed once, reused everywhere). [`sbx app show <name>`](../cli/app#inspecting-an-app)
surfaces both, the app-global tools under `disk`, the per-project self-equips under
`per-project self-equips`.

This is **automatic**, no config field, and it applies only to a `"global"`-scope app (a
`"project"`-scope app already roots its mise data under its per-project home). One residual
is inherent: the activation record stays app-global, so a `nix:` self-equip is re-evaluated
per project and rebuilds on first launch there: cheap when the project's shared `/nix`
already holds the built path (a store cache hit), a real rebuild only when it does not (and
a hard failure offline on that first launch). The credentials/login/identity you chose
`"global"` *for* persist correctly. `home_scope = "project"` avoids even the re-evaluation
by aligning the home with the per-project store from the start.

> **Avoid `mise:nix:<pkg>` in an app's `[packages]`.** Routing a `nix:` package through the
> mise backend pins its install record in the app-global pool while its `/nix` store path is
> per-project, the very misalignment above. Declare it as plain [`nix:<pkg>`](../configuration/packages)
> instead: a `nix:` package is host-provisioned and seeded into each project's store, aligned
> by construction. sbx warns when a global app declares `mise:nix:`.

### A caveat for inline `[flakes]` in global-scope apps

A remote `flake:` package **no longer** has this problem: it builds **host-side** into the
shared store and is re-seeded into each project offline, exactly like a `nix:` tool: so a
`"global"`-scope app's `flake:` package never rebuilds in a fresh project.

An inline [`[flakes.<name>]`](../configuration/packages#flakes-an-inline-nix-flake) still
builds **in the cage** (it is local content, which cannot be built host-side), and its output
lands in the **launching project's** per-project store: only a symlink to it is kept in the
home. So a `"global"`-scope app carrying an inline flake, launched from a **new** project, finds
that warm symlink pointing at a store path absent from the new project's `/nix`, and **rebuilds**
on first launch there (a hard failure if offline). The mitigation is again `home_scope =
"project"`, which aligns the home with the per-project store; or, when the tool is available as
a remote flake, prefer a `flake:<ref>` (host-side, seeded like `nix:`).

## Inspecting a running app

```sh
sbx attach <id>     # join the running app's cage and open a shell inside it
```

`sbx session attach` enters the live cage (its processes, its real `/tmp`, its network, and the
app's isolated home as the agent currently sees it): not a fresh cage. See
[`sbx session attach`](../cli/session#attach) and [Sessions](../concepts/sessions).

## Removing an app's home

The home persists until you remove it. `sbx app rm <name> --purge` deletes the app's
home(s), the global one and any per-project ones, freeing the tools its `mise:`
backends installed, its config, and its login state. `sbx app list` shows which apps
have an installed home, with size. Any `nix:`/`flake:` closures in the shared per-project
store are reclaimed by [`sbx gc --prune`](../cli/gc), or add `--gc` to the purge to
sweep the current project's store in one command. See
[`sbx app`](../cli/app#removing-an-app).
