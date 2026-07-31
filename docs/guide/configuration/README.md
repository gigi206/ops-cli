# Configuration overview

A project is configured by an optional `.sbx.toml` in its root. There is also a
**global** config at [`~/.config/sbx/sbx.toml`](../concepts/directory-layout.md). Both
use the **same schema** — the difference is only how they are trusted.

See also: [The trust gate](../concepts/trust.md) · [Directory layout](../concepts/directory-layout.md) · [One-shot overrides](overrides.md).

## Layering

A launch resolves the configuration by overlaying, low to high:

```
built-in defaults  <  global sbx.toml  <  project .sbx.toml
```

Plus, for [`sbx app run <name>`](../apps/README.md), the app's own overlay on top, and
then a [one-shot override](overrides.md) as the final word. Use
[`sbx config show`](../cli/config.md) to see the resolved result, with each value
tagged by the layer it came from.

## Free fields vs security fields

The schema is split by the [trust gate](../concepts/trust.md), not by two schemas:

- **Free field** — [`env`](env.md) — applies from any project (minus a reserved-key
  denylist).
- **Security fields** — everything else — apply only from a **trusted** source (the
  global config, an app profile, or a project you have run [`sbx trust`](../cli/trust.md)
  on).

The global config and imported app profiles are **trusted by location**; a project
`.sbx.toml` is **trusted by content**.

## The fields

| Field | Kind | Page |
|---|---|---|
| `env` | free | [env](env.md) |
| `binds` | security | [binds](binds.md) |
| `packages` | security | [packages](packages.md) |
| `[flakes.<name>]` | security | [packages](packages.md#flakes--an-inline-nix-flake) |
| `nixpkgs` | security | [nixpkgs](nixpkgs.md) |
| `[limits]` | security | [limits](limits.md) |
| `[seccomp]` | security | [seccomp](seccomp.md) |
| `[devices]` | security | [devices](devices.md) |
| `[ssh_agent]` | security | [ssh-agent](ssh-agent.md) |
| `gui` | security | [gui](gui.md) |
| `gpu` | security | [gpu](gpu.md) |
| `audio` | security | [audio](audio.md) |
| `dbus` | security | [dbus](dbus.md) |
| `network` | security | [network](network.md) |
| `[secret]` | security | [secret](secret.md) |
| `[task.<name>]` | security | [task](task.md) |
| `[app.<name>]` | security overlay | [apps](apps.md) |
| `[net.groups]` | security (global-only) | [net-groups](net-groups.md) |
| `[bundle.<name>]` | security (global-only) | [bundles](bundles.md) |
| `use` | security | [bundles](bundles.md) |

A project's mise files (`[tools]`, `.tool-versions`) are a related input — see
[`[tools]`](tools.md).

## Forward compatibility

The schema is **additive**: every field is optional, and unknown fields are ignored.
A config written for a newer `sbx` still loads on an older one — a new field is
skipped rather than failing the parse. A malformed TOML file (or one that fails the
[safety gate](../concepts/trust.md#the-safety-gate)) is dropped with a warning, never
a hard failure that wedges a launch.

## A worked example

```toml
# extra environment (free — applies even untrusted)
[env]
RUST_LOG = "info"

# tools from nixpkgs (security — needs trust)
[packages]
jq   = "nix:jq"
node = "nix:nodejs_20"

# egress: deny-by-default, only these hosts reach (security)
[network]
mode  = "deny"
allow = ["api.github.com", "*.nixos.org"]

# a named agent launcher (security overlay)
[app.review]
cmd     = "claude"
network = { mode = "deny", allow = ["api.anthropic.com"] }
```

```sh
sbx trust                 # bless the security fields
sbx config show           # verify the resolved result
sbx run -- jq --version   # jq is on PATH
sbx app run review        # launch the agent with its own posture
```

## Editing the config

- [`sbx config show`](../cli/config.md) — the resolved, trust-gated view.
- [`sbx config set`/`unset`/`get`](../cli/config.md) — a single scalar key.
- [`sbx config edit`](../cli/config.md) — open the file for array/table fields.
- [`sbx config path`](../cli/config.md) — where the files are.

Editing a trusted project file re-arms its [trust gate](../concepts/trust.md); pass
`--trust` to re-trust in one step.
