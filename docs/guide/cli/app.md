# `sbx app`

```
sbx app <name> [--detach] [override flags] [-- <args>...]
sbx app import <file> [--as <name>] [--force]
sbx app export <name> [--out <file>]
sbx app rm <name> [--purge] [--gc]
sbx app list
sbx app show <name> [--json]
```

`sbx app <name>` launches a named application profile — a project `[app.<name>]`
overlay, or an imported `apps/<name>.toml` profile — inside the project sandbox, each
with its own persistent isolated home.

See also: [The app framework](../apps/README.md) · [`[app.<name>]`](../configuration/apps.md) · [Portable profiles](../apps/profiles.md) · [Profile catalog](../apps/catalog.md).

## Launching an app

| Option | Meaning |
|---|---|
| `--detach` | launch in the background as a session [`sbx session`](session.md) can see |
| `--config` / `--env` / `--net` / `--gui` / `--nixpkgs` / `--bind` / `--limit` / `--package` | one-shot [overrides](../configuration/overrides.md), applied **after** the app's overlay (the final word) |
| `-- <args>...` | appended to the app's declared command |

Arguments after a `--` are appended to the app's `cmd`, so you can pass a flag to the
launched program without editing the profile — e.g. `sbx app claude-code -- -c` runs
the profile's `claude` with `-c`. They are ordinary launch-time arguments; the app's
posture (network, binds, secrets, home) is fixed by the profile.

A one-shot override is applied after the app's overlay, so it is the final word — e.g.
`sbx app claude-code --net none` cuts the app's network for one run. Note: overriding
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

`import`/`export`/`rm`/`list` are reserved verbs and cannot be app names. `import` is a
deliberate consent act — an agent in the cage cannot run it, and the profile stays
inert until `sbx app <name>`. See [Portable profiles](../apps/profiles.md).

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
| `deb:` / `appimage:` / `flake:` | `pinned in N tree(s) (<hash>)` — the build lives in the [per-project store](../concepts/directory-layout.md); see [`sbx projects show`](projects.md) — or `not built` |
| `nix:` | `built per-project` |

A package a launch would not provision because an untrusted layer declared it reads
`withheld` (distinct from `not installed`, so it is not mistaken for a failed provision).

If the home holds mise tools that **no declared package accounts for** — a leftover from a
removed profile, or a dependency a `mise:` backend pulled in — they are listed under
`installed (undeclared)`, so the report shows everything that is actually installed, not only
what the profile names.

Read-only: no trust gate, no launch, no network. `--json` emits the same model for scripting.

## Examples

```sh
sbx app import profiles/claude-code.toml
sbx app claude-code                    # launch with its own isolated home
sbx app claude-code -- -c              # resume the previous session
sbx app claude-code --net none         # one run with no network
sbx app list                           # imported profiles + installed homes
sbx app show claude-code               # what this app has actually installed on disk
sbx app export claude-code > my-claude.toml
sbx app rm claude-code --purge         # remove the profile, home, and tools
sbx app rm claude-code --purge --gc    # …and sweep this project's nix store too
```
