# `sbx config`

```
sbx config <subcommand>
```

Inspect or edit the configuration for the current project.

See also: [Configuration overview](../configuration/) · [The trust gate](../concepts/trust) · [Directory layout](../concepts/directory-layout).

## Subcommands

| Subcommand | Purpose |
|---|---|
| [`show`](#sbx-config-show) | the resolved, trust-gated configuration a launch would use |
| [`get`](#get-set-unset) | read a value from a single layer file |
| [`set`](#get-set-unset) | set a scalar value in a layer file (comments preserved) |
| [`unset`](#get-set-unset) | remove a key from a layer file |
| [`path`](#sbx-config-path) | the config files in resolution order, or one scope's path |
| [`edit`](#sbx-config-edit) | open a config file in your editor |

## `sbx config show`

```
sbx config show [--json] [--details] [-a|--app <name>] [-g|--global|-l|--local|-d|--default]
```

Prints the resolved configuration: the layered global and project environment, binds,
packages, tools, network, GUI, secrets, and app profiles, after the trust gate has
dropped anything an untrusted project may not set. Each value is tagged with where it
came from, `(default)`, `(global)`, or `(project)`, colored by level. Warnings
explain what was dropped and why. No launch, no nix, no network.

| Option | Meaning |
|---|---|
| `--json` | the resolved model as JSON (warnings included) |
| `--details` | expand each app overlay (env, binds, packages, allowlist rules, credentials) |
| `-a, --app <name>` | one app's **effective** config, each field tagged `inherited` or `app:global`/`app:project` |
| `-g, --global` | only what the global config (and imported profiles) contributes |
| `-l, --local` | only what the project `.sbx.toml` contributes |
| `-d, --default` | the built-in defaults alone |

The single-source flags are mutually exclusive and do not combine with `--app`. Note
`-d` is `--default`, so `--details` has no short form.

## get, set, unset

```
sbx config get   <key> [-l|-g|-c <file>] [-a|--app <name>]
sbx config set   <key> <value> [-l|-g|-c <file>] [-a|--app <name>] [--trust]
sbx config unset <key> [-l|-g|-c <file>] [-a|--app <name>] [--trust]
```

Read/write a single **scalar** value at a dotted key (e.g. `env.FOO`, `network`,
`nixpkgs`) in one layer file, preserving comments and formatting. Array and table
fields (`binds`, an allowlist, secrets, apps) are edited with
[`edit`](#sbx-config-edit).

| Scope | Meaning |
|---|---|
| `-l, --local` | the project `.sbx.toml` (the default) |
| `-g, --global` | the global `sbx.toml` |
| `-c <file>` | an explicit config file |
| `-a, --app <name>` | address the key under that app (`app.<name>.<key>` inline, or `-g` its profile) |

Writing a trusted project file re-arms its [trust gate](../concepts/trust); pass
`--trust` to re-trust in one step. The global config and app profiles are trusted by
location, so a write there needs no trust; a free `env` value needs no trust.

## `sbx config path`

```
sbx config path [-l|-g|-c <file>]
```

With no scope flag, lists every config layer in resolution order (global then project)
and whether each exists. With a scope flag, prints just that file's path (for scripting
and for locating the global config).

## `sbx config edit`

```
sbx config edit [-l|-g|-c <file>] [--trust]
```

Opens the target file in `$VISUAL` / `$EDITOR` (falling back to `vi`): the way to edit
fields `set` does not handle as a single value: [`binds`](../configuration/binds),
an [allowlist](../configuration/network), [secrets](../configuration/secret), or
[app](../configuration/apps) tables.

A `binds` entry is an absolute host path, bound read-only by default; write it as a
table `{ path = "/abs/path", mode = "rw" }` to bind it read-write (the cage writes
through to the host path). A leading `~`, `$HOME`, or `$XDG_RUNTIME_DIR` is expanded
from your environment, so a portable config need not hard-code an absolute home path;
any other `$VAR` is refused. `binds` is a security field, honored only from a trusted
source. sbx's own state (its data, trust, and config directories) is protected either
way: a read-write bind aimed at or inside one of them is forced read-only with a
warning, while a broad read-write bind that merely contains them (e.g. `mode = "rw"`
on your whole home) stays read-write with those directories pinned read-only in place
— the rest of the tree is writable, but the agent still cannot alter what sbx runs or
trusts.

An edit that changes a trusted file re-arms its trust gate; `--trust` re-trusts as
the editor closes.

## Examples

```sh
sbx config show
sbx config show --app claude-code
sbx config show --json
sbx config set nixpkgs nixos-23.11 --trust
sbx config get env.RUST_LOG
sbx config edit --trust
sbx config path
```
