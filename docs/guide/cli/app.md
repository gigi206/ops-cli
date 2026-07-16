# `ops app`

```
ops app <name> [--detach] [override flags] [-- <args>...]
ops app import <file> [--as <name>] [--force]
ops app export <name> [--out <file>]
ops app rm <name> [--purge] [--gc]
ops app list
```

`ops app <name>` launches a named application profile — a project `[app.<name>]`
overlay, or an imported `apps/<name>.toml` profile — inside the project sandbox, each
with its own persistent isolated home.

See also: [The app framework](../apps/README.md) · [`[app.<name>]`](../configuration/apps.md) · [Portable profiles](../apps/profiles.md) · [Profile catalog](../apps/catalog.md).

## Launching an app

| Option | Meaning |
|---|---|
| `--detach` | launch in the background as a session [`ops session`](session.md) can see |
| `--config` / `--env` / `--net` / `--gui` / `--nixpkgs` / `--bind` / `--limit` / `--package` | one-shot [overrides](../configuration/overrides.md), applied **after** the app's overlay (the final word) |
| `-- <args>...` | appended to the app's declared command |

Arguments after a `--` are appended to the app's `cmd`, so you can pass a flag to the
launched program without editing the profile — e.g. `ops app claude-code -- -c` runs
the profile's `claude` with `-c`. They are ordinary launch-time arguments; the app's
posture (network, binds, secrets, home) is fixed by the profile.

A one-shot override is applied after the app's overlay, so it is the final word — e.g.
`ops app claude-code --net none` cuts the app's network for one run. Note: overriding
an app's network drops its read-by-default verb filter (an override posture is
all-verbs); scope it with `{GET,HEAD}` rules in a `--config` `[network]` if you need to
keep it.

## Managing profiles

| Subcommand | Purpose |
|---|---|
| `import <file> [--as <name>] [--force]` | place a portable profile (trusted by location); the granted posture is printed |
| `export <name> [--out <file>]` | write a named app out as a portable profile (stdout by default) |
| `rm <name>` | remove an **imported** profile (a project `[app.<name>]` lives in that project's `.ops.toml`) |
| `rm <name> --purge` | also remove the app's isolated **home(s)** — the tools its `mise:` backends installed, its config, and its login state |
| `rm <name> --purge --gc` | after the purge, sweep the **current project's** nix store too (one command; requires `--purge`) |
| `list` | list the imported profiles **and** the apps with an installed home (with disk size) |

`import`/`export`/`rm`/`list` are reserved verbs and cannot be app names. `import` is a
deliberate consent act — an agent in the cage cannot run it, and the profile stays
inert until `ops app <name>`. See [Portable profiles](../apps/profiles.md).

### Removing an app

`rm <name>` deletes only the imported profile. To also reclaim what a launch left on
disk, add `--purge`: it removes the app's [isolated home(s)](../apps/home.md) — the
global one and any per-project ones — which hold the tools installed by the app's
`mise:` backends, its config, and its login/session state, freed immediately. A running
session of the app is a hard stop (stop it first with [`ops session stop`](session.md#stop)).

`--purge` on its own does **not** touch the shared per-project nix store, which backs
every app in a project. Add **`--gc`** (which requires `--purge`) to sweep the **current
project's** store in the same command — equivalent to running [`ops gc --prune`](gc.md)
there — reclaiming the app's now-unreferenced `nix:`/`flake:` closures. For a global app
used in several projects, run the sweep in each of them (one command covers the current
project only). Use `ops app list` to see which apps have an installed home to purge.

## Examples

```sh
ops app import profiles/claude-code.toml
ops app claude-code                    # launch with its own isolated home
ops app claude-code -- -c              # resume the previous session
ops app claude-code --net none         # one run with no network
ops app list                           # imported profiles + installed homes
ops app export claude-code > my-claude.toml
ops app rm claude-code --purge         # remove the profile, home, and tools
ops app rm claude-code --purge --gc    # …and sweep this project's nix store too
```
