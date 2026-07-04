# `ops app`

```
ops app <name> [--detach] [override flags] [-- <args>...]
ops app import <file> [--as <name>] [--force]
ops app export <name> [--out <file>]
ops app rm <name>
ops app list
```

`ops app <name>` launches a named application profile — a project `[app.<name>]`
overlay, or an imported `apps/<name>.toml` profile — inside the project sandbox, each
with its own persistent isolated home.

See also: [The app framework](../apps/README.md) · [`[app.<name>]`](../configuration/apps.md) · [Portable profiles](../apps/profiles.md) · [Profile catalog](../apps/catalog.md).

## Launching an app

| Option | Meaning |
|---|---|
| `--detach` | launch in the background as a session [`ops ls`](ls.md)/[`attach`](attach.md)/[`stop`](stop.md) can see |
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
| `list` | list the imported profiles |

`import`/`export`/`rm`/`list` are reserved verbs and cannot be app names. `import` is a
deliberate consent act — an agent in the cage cannot run it, and the profile stays
inert until `ops app <name>`. See [Portable profiles](../apps/profiles.md).

## Examples

```sh
ops app import profiles/claude-code.toml
ops app claude-code                    # launch with its own isolated home
ops app claude-code -- -c              # resume the previous session
ops app claude-code --net none         # one run with no network
ops app list
ops app export claude-code > my-claude.toml
```
