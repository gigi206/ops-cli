# `ops config`

```
ops config <subcommand>
```

Inspect or edit the configuration for the current project.

See also: [Configuration overview](../configuration/README.md) · [The trust gate](../concepts/trust.md) · [Directory layout](../concepts/directory-layout.md).

## Subcommands

| Subcommand | Purpose |
|---|---|
| [`show`](#ops-config-show) | the resolved, trust-gated configuration a launch would use |
| [`get`](#get-set-unset) | read a value from a single layer file |
| [`set`](#get-set-unset) | set a scalar value in a layer file (comments preserved) |
| [`unset`](#get-set-unset) | remove a key from a layer file |
| [`path`](#ops-config-path) | the config files in resolution order, or one scope's path |
| [`edit`](#ops-config-edit) | open a config file in your editor |

## `ops config show`

```
ops config show [--json] [--details] [-a|--app <name>] [-g|--global|-l|--local|-d|--default]
```

Prints the resolved configuration — the layered global and project environment, binds,
packages, tools, network, GUI, secrets, and app profiles, after the trust gate has
dropped anything an untrusted project may not set. Each value is tagged with where it
came from — `(default)`, `(global)`, or `(project)` — colored by level. Warnings
explain what was dropped and why. No launch, no nix, no network.

| Option | Meaning |
|---|---|
| `--json` | the resolved model as JSON (warnings included) |
| `--details` | expand each app overlay (env, binds, packages, allowlist rules, credentials) |
| `-a, --app <name>` | one app's **effective** config, each field tagged `inherited` or `app:global`/`app:project` |
| `-g, --global` | only what the global config (and imported profiles) contributes |
| `-l, --local` | only what the project `.ops.toml` contributes |
| `-d, --default` | the built-in defaults alone |

The single-source flags are mutually exclusive and do not combine with `--app`. Note
`-d` is `--default`, so `--details` has no short form.

## get, set, unset

```
ops config get   <key> [-l|-g|-c <file>] [-a|--app <name>]
ops config set   <key> <value> [-l|-g|-c <file>] [-a|--app <name>] [--trust]
ops config unset <key> [-l|-g|-c <file>] [-a|--app <name>] [--trust]
```

Read/write a single **scalar** value at a dotted key (e.g. `env.FOO`, `network`,
`nixpkgs`) in one layer file, preserving comments and formatting. Array and table
fields (`binds`, an allowlist, secrets, apps) are edited with
[`edit`](#ops-config-edit).

| Scope | Meaning |
|---|---|
| `-l, --local` | the project `.ops.toml` (the default) |
| `-g, --global` | the global `ops.toml` |
| `-c <file>` | an explicit config file |
| `-a, --app <name>` | address the key under that app (`app.<name>.<key>` inline, or `-g` its profile) |

Writing a trusted project file re-arms its [trust gate](../concepts/trust.md); pass
`--trust` to re-trust in one step. The global config and app profiles are trusted by
location, so a write there needs no trust; a free `env` value needs no trust.

## `ops config path`

```
ops config path [-l|-g|-c <file>]
```

With no scope flag, lists every config layer in resolution order (global then project)
and whether each exists. With a scope flag, prints just that file's path (for scripting
and for locating the global config).

## `ops config edit`

```
ops config edit [-l|-g|-c <file>] [--trust]
```

Opens the target file in `$VISUAL` / `$EDITOR` (falling back to `vi`) — the way to edit
fields `set` does not handle as a single value: [`binds`](../configuration/binds.md),
an [allowlist](../configuration/network.md), [secrets](../configuration/secret.md), or
[app](../configuration/apps.md) tables. An edit that changes a trusted file re-arms its
trust gate; `--trust` re-trusts as the editor closes.

## Examples

```sh
ops config show
ops config show --app claude-code
ops config show --json
ops config set nixpkgs nixos-23.11 --trust
ops config get env.RUST_LOG
ops config edit --trust
ops config path
```
