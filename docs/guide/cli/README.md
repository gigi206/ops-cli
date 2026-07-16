# Command reference

Every `ops` command, at a glance. Run `ops help <command>` (or `ops <command> --help`)
for the built-in page; `ops help <command> <subcommand>` for a subcommand.

See also: [Configuration overview](../configuration/README.md) · [Exit codes](../reference/exit-codes.md) · [Environment variables](../reference/environment-variables.md).

## Launching

| Command | Purpose |
|---|---|
| [`ops run`](run.md) | run a command inside the project sandbox |
| [`ops shell`](shell.md) | open an interactive sandboxed shell |
| [`ops app <name>`](app.md) | launch or manage named application profiles |
| [`ops mise`](mise.md) | run the in-cage mise to self-equip a toolchain |

## Configuration and discovery

| Command | Purpose |
|---|---|
| [`ops config`](config.md) | inspect and edit the configuration |
| [`ops search`](search.md) | discover `nix:` tools via nixhub |
| [`ops test`](test.md) | check whether an access would be allowed |
| [`ops trust`](trust.md) / [`ops untrust`](untrust.md) | vouch for / revoke a project config |

## Networking

| Command | Purpose |
|---|---|
| [`ops net`](net.md) | inspect the egress policy, its rules, and parked `ask` requests |
| [`ops test net`](test.md) | test one URL against the resolved policy |

## Secrets and plugins

| Command | Purpose |
|---|---|
| [`ops plugins`](plugins.md) | manage resolver plugins and signed plugin stores |

## Sessions and housekeeping

| Command | Purpose |
|---|---|
| [`ops session`](session.md) | list, attach to, and stop the live sandbox sessions |
| [`ops projects`](projects.md) | list and remove per-project runtime trees |
| [`ops gc`](gc.md) | reclaim nix store space |
| [`ops upgrade`](upgrade.md) | roll managed toolchains forward |

## Preflight

| Command | Purpose |
|---|---|
| [`ops doctor`](doctor.md) | verify the runtime prerequisites |

## Help

- `ops help` / `ops --help` — the top-level command list.
- `ops help <command> [subcommand...]` — the page for a command path.
- `ops <command> --help` — the same page.
- A `--` ends `ops`'s own flags, so `ops app <name> -- --help` passes `--help` to the
  launched command.
