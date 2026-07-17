# Command reference

Every `sbx` command, at a glance. Run `sbx help <command>` (or `sbx <command> --help`)
for the built-in page; `sbx help <command> <subcommand>` for a subcommand.

See also: [Configuration overview](../configuration/README.md) · [Exit codes](../reference/exit-codes.md) · [Environment variables](../reference/environment-variables.md).

## Launching

| Command | Purpose |
|---|---|
| [`sbx run`](run.md) | run a command inside the project sandbox |
| [`sbx shell`](shell.md) | open an interactive sandboxed shell |
| [`sbx app`](app.md) | launch (`sbx app run <name>`) or manage named application profiles |
| [`sbx mise`](mise.md) | run the in-cage mise to self-equip a toolchain |

## Configuration and discovery

| Command | Purpose |
|---|---|
| [`sbx config`](config.md) | inspect and edit the configuration |
| [`sbx search`](search.md) | discover `nix:` tools via nixhub |
| [`sbx test`](test.md) | check whether an access would be allowed |
| [`sbx trust`](trust.md) / [`sbx untrust`](untrust.md) | vouch for / revoke a project config |

## Networking

| Command | Purpose |
|---|---|
| [`sbx net`](net.md) | inspect the egress policy, its rules, and parked `ask` requests |
| [`sbx test net`](test.md) | test one URL against the resolved policy |

## Secrets and plugins

| Command | Purpose |
|---|---|
| [`sbx plugins`](plugins.md) | manage resolver plugins and signed plugin stores |

## Sessions and housekeeping

| Command | Purpose |
|---|---|
| [`sbx session`](session.md) | list, attach to, and stop the live sandbox sessions |
| [`sbx proc`](proc.md) | observe a running session's process tree |
| [`sbx projects`](projects.md) | list and remove per-project runtime trees |
| [`sbx gc`](gc.md) | reclaim nix store space |
| [`sbx upgrade`](upgrade.md) | roll managed toolchains forward |

## Preflight

| Command | Purpose |
|---|---|
| [`sbx doctor`](doctor.md) | verify the runtime prerequisites |

## Help

- `sbx help` / `sbx --help` — the top-level command list.
- `sbx help <command> [subcommand...]` — the page for a command path.
- `sbx <command> --help` — the same page.
- A `--` ends `sbx`'s own flags, so `sbx app run <name> -- --help` passes `--help` to the
  launched command.
