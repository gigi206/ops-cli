# Command reference

Every `sbx` command, at a glance. Run `sbx help <command>` (or `sbx <command> --help`)
for the built-in page; `sbx help <command> <subcommand>` for a subcommand.

See also: [Configuration overview](../configuration/) · [Exit codes](../reference/exit-codes) · [Environment variables](../reference/environment-variables).

## Launching

| Command | Purpose |
|---|---|
| [`sbx run`](run) | run a command inside the project sandbox, or open its shell |
| [`sbx app`](app) | launch (`sbx app run <name>`) or manage named application profiles |
| [`sbx mise`](mise) | run the in-cage mise to self-equip a toolchain |

## Configuration and discovery

| Command | Purpose |
|---|---|
| [`sbx config`](config) | inspect and edit the configuration |
| [`sbx search`](search) | discover `nix:` tools via nixhub |
| [`sbx test`](test) | check whether an access would be allowed |
| [`sbx bundle`](bundle) | list, export and import reusable [tool bundles](../configuration/bundles) |
| [`sbx trust`](trust) / [`sbx untrust`](untrust) | vouch for / revoke a project config |

## Networking

| Command | Purpose |
|---|---|
| [`sbx net`](net) | inspect the egress policy, its rules, and parked `ask` requests |
| [`sbx test net`](test) | test one URL against the resolved policy |

## Secrets and plugins

| Command | Purpose |
|---|---|
| [`sbx secret`](secret) | the credential inventory this configuration declares |
| [`sbx plugins`](plugins) | manage resolver plugins and signed plugin stores |

## Sessions and lifecycle

| Command | Purpose |
|---|---|
| [`sbx session`](session) | list, attach to, and stop the live sandbox sessions |
| [`sbx proc`](proc) | observe a running session's process tree |
| [`sbx fs`](fs) | observe the files a running session writes in its project |
| [`sbx ssh-agent`](ssh-agent) | what a running session asked your ssh keys to sign |
| [`sbx task`](task) | list and invoke a session's [declared operations](../tasks/) |
| [`sbx projects`](projects) | list and remove per-project runtime trees |
| [`sbx path`](path) | where the config, data, and state roots live |
| [`sbx storage`](storage) | manage a compressed, self-growing volume for the data directory |
| [`sbx store`](store) | report what sbx occupies on disk, subtree by subtree |
| [`sbx gc`](gc) | reclaim nix store space |
| [`sbx upgrade`](upgrade) | roll managed toolchains forward |

## Preflight

| Command | Purpose |
|---|---|
| [`sbx doctor`](doctor) | verify the runtime prerequisites |
| [`sbx version`](version) | print the version of this sbx build |

## Shell integration

| Command | Purpose |
|---|---|
| [`sbx completion`](completion) | print the bash or zsh completion script |

## Help

- `sbx help` / `sbx --help`: the top-level command list.
- `sbx help <command> [subcommand...]`: the page for a command path.
- `sbx <command> --help`: the same page.
- `sbx version` / `sbx --version` / `sbx -V`: the version of this build, one line on stdout.
- A `--` ends `sbx`'s own flags, so `sbx app run <name> -- --help` passes `--help` to the
  launched command.
