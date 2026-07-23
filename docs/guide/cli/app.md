# `sbx app`

```
sbx app run <name> [--detach] [--observe] [override flags] [-- <args>...]
sbx app import <file> [--as <name>] [--force]
sbx app export <name> [--out <file>]
sbx app rm <name> [--purge] [--gc]
sbx app list
sbx app show <name> [--json]
sbx app prune <name> [--yes]
```

`sbx app run <name>` launches a named application profile — a project `[app.<name>]`
overlay, or an imported `apps/<name>.toml` profile — inside the project sandbox, each
with its own persistent isolated home.

See also: [The app framework](../apps/README.md) · [`[app.<name>]`](../configuration/apps.md) · [Portable profiles](../apps/profiles.md) · [Profile catalog](../apps/catalog.md).

## Launching an app

| Option | Meaning |
|---|---|
| `--detach` | launch in the background as a session [`sbx session`](session.md) can see |
| `--observe` | record what the app does — its processes ([`sbx proc logs`](proc.md#logs), also streamed inline to stderr on a non-interactive foreground run) and its file writes ([`sbx fs logs`](fs.md#logs)); works for interactive and detached launches too — see [`sbx run`](run.md#observing-a-run-observe) |
| `--config` / `--env` / `--net` / `--gui` / `--nixpkgs` / `--bind` / `--limit` / `--package` | one-shot [overrides](../configuration/overrides.md), applied **after** the app's overlay (the final word) |
| `-- <args>...` | appended to the app's declared command |

Arguments after a `--` are appended to the app's `cmd`, so you can pass a flag to the
launched program without editing the profile — e.g. `sbx app run claude-code -- -c` runs
the profile's `claude` with `-c`. They are ordinary launch-time arguments; the app's
posture (network, binds, secrets, home) is fixed by the profile.

A one-shot override is applied after the app's overlay, so it is the final word — e.g.
`sbx app run claude-code --net none` cuts the app's network for one run. Note: overriding
an app's network drops its read-by-default verb filter (an override posture is
all-verbs); scope it with `{GET,HEAD}` rules in a `--config` `[network]` if you need to
keep it.

## Managing profiles

| Subcommand | Purpose |
|---|---|
| `import <file> [--as <name>] [--force]` | place a portable profile (trusted by location); the granted posture is printed |
| `export <name> [--out <file>]` | write a named app out as a portable profile (stdout by default) |
| `rm <name>` | remove an **imported** profile (a project `[app.<name>]` lives in that project's `.sbx.toml`) |
| `rm <name> --purge` | also remove the app's isolated **home(s)** — the tools its `mise:` backends installed, its config, and its login state |
| `rm <name> --purge --gc` | after the purge, sweep the **current project's** nix store too (one command; requires `--purge`) |
| `list` | list the imported profiles **and** the apps with an installed home (with disk size) |

`run`/`import`/`export`/`rm`/`list`/`show`/`prune` are subcommands. Launching always goes
through `run`, so an app is never confused with a subcommand and **may be named like one**
(reached as `sbx app run <name>`). `import` is a deliberate consent act — an agent in the
cage cannot run it, and the profile stays inert until `sbx app run <name>`. See
[Portable profiles](../apps/profiles.md).

### Listing apps

`sbx app list` (alias `sbx app ls`) shows one row per app with its `HOME` column: the total
size a `--purge` would reclaim, and where that state lives.

| Reads | Means |
|---|---|
| `global` | the app's single shared home `<data>/apps/<name>/home` — a `home_scope = "global"` app (the default) |
| `N project home(s)` | one isolated home per project — a [`home_scope = "project"`](../apps/home.md) app |
| `N project mise pool(s)` | not a home: a per-project [mise pool](../apps/home.md#two-mise-pools-keep-a-global-apps-self-equips-aligned) a **global** app self-equipped a tool into |

So `global + 1 project mise pool` is one home plus a pool — not two homes.

Every launch creates the pool directory, so an app that has merely *run* in a project has an
**empty** pool there; an empty pool is **not listed** (it would report per-project state the
app does not have). Only a pool holding an installed tool counts. Its size is included in the
row's total either way, since `--purge` removes it. `sbx app show <name>` breaks the sizes
down per home and per pool, empty ones included.

### Removing an app

`rm <name>` deletes only the imported profile. To also reclaim what a launch left on
disk, add `--purge`: it removes the app's [isolated home(s)](../apps/home.md) — the
global one and any per-project ones — which hold the tools installed by the app's
`mise:` backends, its config, and its login/session state, freed immediately. A running
session of the app is a hard stop (stop it first with [`sbx session stop`](session.md#stop)).

`--purge` on its own does **not** touch the shared per-project nix store, which backs
every app in a project. Add **`--gc`** (which requires `--purge`) to sweep the **current
project's** store in the same command — equivalent to running [`sbx gc --prune`](gc.md)
there — reclaiming the app's now-unreferenced `nix:`/`flake:` closures. For a global app
used in several projects, run the sweep in each of them (one command covers the current
project only). Use `sbx app list` to see which apps have an installed home to purge.

## Inspecting an app

`sbx app show <name>` reports one app's **realized-on-disk** detail — the counterpart to
[`sbx config show --app <name>`](config.md), which shows what the app *declares*. It lists
the profile source, the app's isolated home(s) with on-disk size (and the mise-tools share
broken out), and each declared package annotated with whether it is **actually installed**:

| Package | Installed reads |
|---|---|
| `mise:` | `installed <version>` (read from the app's home) or `not installed` |
| `deb:` / `appimage:` / `tarball:` | `pinned in N tree(s) (<hash>)` — the build lives in the [per-project store](../concepts/directory-layout.md); see [`sbx projects show`](projects.md) — or `not built` |
| `nix:` / `flake:` | `built in N tree(s)` — built host-side into the shared store, seeded per project; or `not built` |

A package a launch would not provision because an untrusted layer declared it reads
`withheld` (distinct from `not installed`, so it is not mistaken for a failed provision).

If the home holds mise tools that **no declared package accounts for** — a leftover from a
removed profile, or a dependency a `mise:` backend pulled in — they are listed under
`installed (undeclared)`, named by their real backend token (its provider, e.g.
`pipx:hermes-agent`, recovered from mise's metadata rather than the munged directory name), so
the report shows everything that is actually installed, not only what the profile names.

For a `"global"`-scope app, the report also surfaces its **per-project mise pools** — where
the agent's `nix:`-via-mise self-equips and the project's own `mise.toml` tools install,
aligned with each project's `/nix` store (see
[Two mise pools](../apps/home.md#two-mise-pools-keep-a-global-apps-self-equips-aligned)). Each
pool appears in the `disk` breakdown as `project <id> (mise pool)`, and its tools are listed
per project under `per-project self-equips` — kept distinct from the app-global declared tools,
since they are transient per-project state, re-resolved when a project's store lacks them.

Read-only: no trust gate, no launch, no network. `--json` emits the same model for scripting.

## Pruning undeclared tools

`sbx app prune <name>` removes the `installed (undeclared)` mise tools `show` surfaces — a
tool from a former profile, or one added by hand — from every home the app has. Each is
deleted from the home's `mise/installs/` and dropped from that home's `mise/config.toml`
`[tools]` so a later launch does not re-equip it. It **previews by default** (listing what
would go, with sizes) and applies only with `--yes`. The app's declared tools, its
login/session state, and any `nix:`/`deb:`/`flake:` build are left untouched — to remove the
whole home instead, use [`sbx app rm --purge`](#removing-an-app).

## Examples

```sh
sbx app import profiles/claude-code.toml
sbx app run claude-code                # launch with its own isolated home
sbx app run claude-code -- -c          # resume the previous session
sbx app run claude-code --net none     # one run with no network
sbx app list                           # imported profiles + installed homes
sbx app show claude-code               # what this app has actually installed on disk
sbx app prune hermes                    # preview undeclared mise tools in hermes' home
sbx app prune hermes --yes              # …and remove them
sbx app export claude-code > my-claude.toml
sbx app rm claude-code --purge         # remove the profile, home, and tools
sbx app rm claude-code --purge --gc    # …and sweep this project's nix store too
```
