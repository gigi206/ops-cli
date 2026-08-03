# Configuration overview

A project is configured by an optional `.sbx.toml` in its root. There is also a
**global** config at [`~/.config/sbx/sbx.toml`](../concepts/directory-layout). Both
use the **same schema**: the difference is only how they are trusted.

See also: [The trust gate](../concepts/trust) · [Directory layout](../concepts/directory-layout) · [One-shot overrides](overrides).

## Layering

A launch resolves the configuration by overlaying, low to high:

```
built-in defaults  <  global sbx.toml  <  project .sbx.toml
```

Plus, for [`sbx app run <name>`](../apps/), the app's own overlay on top, and
then a [one-shot override](overrides) as the final word. Use
[`sbx config show`](../cli/config) to see the resolved result, with each value
tagged by the layer it came from.

## Free fields vs security fields

The schema is split by the [trust gate](../concepts/trust), not by two schemas:

- **Free field**, [`env`](env), applies from any project (minus a reserved-key
  denylist).
- **Security fields**, everything else, apply only from a **trusted** source (the
  global config, an app profile, or a project you have run [`sbx trust`](../cli/trust)
  on).

The global config and imported app profiles are **trusted by location**; a project
`.sbx.toml` is **trusted by content**.

## The fields

| Field | Kind | Page |
|---|---|---|
| `env` | free | [env](env) |
| `binds` | security | [binds](binds) |
| `packages` | security | [packages](packages) |
| `[flakes.<name>]` | security | [packages](packages#flakes-an-inline-nix-flake) |
| `[tarball.<name>]`, `[deb.<name>]`, `[appimage.<name>]` (auto-upgrade resolvers) | security | [packages](packages#tarball-a-prebuilt-application-tarball) |
| `nixpkgs` | security | [nixpkgs](nixpkgs) |
| `[limits]` | security | [limits](limits) |
| `[seccomp]` | security | [seccomp](seccomp) |
| `[devices]` | security | [devices](devices) |
| `[ssh_agent]` | security | [ssh-agent](ssh-agent) |
| `gui` | security | [gui](gui) |
| `gpu` | security | [gpu](gpu) |
| `audio` | security | [audio](audio) |
| `dbus` | security | [dbus](dbus) |
| `network` | security | [network](network) |
| `[proc]` | security | [proc](proc) |
| `forward` | security | [forward](../networking/forward) |
| `[notify]` | security | [notify](notify) |
| `[secret]` | security | [secret](secret) |
| `[task.<name>]` | security | [task](task) |
| `[app.<name>]` | security overlay | [apps](apps) |
| `[net.groups]` | security (global-only) | [net-groups](net-groups) |
| `[bundle.<name>]` | security (global-only) | [bundles](bundles) |
| `use` | security | [bundles](bundles) |

A project's mise files (`[tools]`, `.tool-versions`) are a related input: see
[`[tools]`](tools).

## Forward compatibility

The schema is **additive**: every field is optional, and unknown fields are ignored.
A config written for a newer `sbx` still loads on an older one: a new field is
skipped rather than failing the parse. A malformed TOML file (or one that fails the
[safety gate](../concepts/trust#the-safety-gate)) is dropped with a warning, never
a hard failure that wedges a launch.

## A worked example

```toml
# extra environment (free: applies even untrusted)
[env]
RUST_LOG = "info"

# tools from nixpkgs (security: needs trust)
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

- [`sbx config show`](../cli/config): the resolved, trust-gated view.
- [`sbx config set`/`unset`/`get`](../cli/config): a single scalar key.
- [`sbx config edit`](../cli/config): open the file for array/table fields.
- [`sbx config path`](../cli/config): where the files are.

Editing a trusted project file re-arms its [trust gate](../concepts/trust); pass
`--trust` to re-trust in one step.
