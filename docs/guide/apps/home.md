# Per-app isolated `$HOME`

Each `ops app <name>` gets a **dedicated, persistent, isolated `$HOME`**, so the app's
config, login state, and history never bleed into your project shell or another app.
The `home_scope` field chooses whether that home is also per-project.

See also: [The app framework](README.md) · [`[app.<name>]`](../configuration/apps.md) · [Directory layout](../concepts/directory-layout.md).

## Always isolated

An app's home is **always** per-app and isolated from the project's default shell home.
An agent that logs in, writes a config, or accumulates history does so in its own home
— an `ops run` in the same project sees none of it, and neither does another app. This
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

## Reproducing an app's environment

```sh
ops attach <id>     # open a shell in a running app session's isolated home
```

See [`ops attach`](../cli/attach.md) and [Sessions](../housekeeping/sessions.md).
