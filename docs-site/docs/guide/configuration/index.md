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

## Global defaults: what applies everywhere

The **global** config (`~/.config/sbx/sbx.toml`) is the one place to declare
something **once** and have it apply to every launch: every project, and every
app (an app resolves `global → project → app`, inheriting the layers below it).
So "make tool X available everywhere" is a [`[packages]`](packages) declaration
in the global config:

```toml
# ~/.config/sbx/sbx.toml: applies to every project and every app
[packages]
ast-grep = "nix:ast-grep"
```

```sh
sbx run -- ast-grep --version  # any project
sbx app run review             # any app: ast-grep is on PATH there too
sbx config show -g             # what the global layer contributes
sbx config show -a review      # ast-grep tagged "inherited" in the app's effective config
```

One table composes differently, and it is worth knowing before relying on a global
setting: a [`[network]`](network#what-a-table-does-not-inherit) table declared in a lower
layer **replaces** the one above it rather than adding to it. A global `capture` or
`ca_roots` therefore stops applying to a project that declares its own table, which
[`sbx net allow --local`](../cli/net) does for you. Only the mode is inherited, and sbx
names on stderr whatever stopped applying.

By contrast, a project's mise files ([`[tools]`](tools)) are **project-local by
design**: declare a tool there and it equips that project only. The usual split
is a global `[packages]` for tools you want everywhere, plus the project's mise
file for its own toolchain. Note that the global config is **trusted by
location**, so its `[packages]` apply regardless of any project's trust state.

## Free fields vs security fields

The schema is split by the [trust gate](../concepts/trust), not by two schemas:

- **Free fields**, [`env`](env) (minus a reserved-key denylist) and
  [`timezone`](timezone), apply from any project. Neither reads anything from the host:
  they say what the cage's own environment and clock look like.
- **Security fields**, almost everything else, apply only from a **trusted** source (the
  global config, an app profile, or a project you have run [`sbx trust`](../cli/trust)
  on).
- **[`[fs]`](fs)** sits outside the split, and it is the only field that does. Every other
  table can grant something, which is what the gate is there to decide; `[fs]` can only
  close a path of the project it is declared in, so it applies from any source. Dropping it
  from an untrusted project would leave open exactly the file that project asked to close.

The global config and imported app profiles are **trusted by location**; a project
`.sbx.toml` is **trusted by content**.

## The fields

| Field | Kind | Page |
|---|---|---|
| `env` | free | [env](env) |
| `timezone` | free | [timezone](timezone) |
| `binds` | security | [binds](binds) |
| `packages` | security | [packages](packages) |
| `[flakes.<name>]` | security | [packages](packages#flakes-an-inline-nix-flake) |
| `[tarball.<name>]`, `[deb.<name>]`, `[appimage.<name>]` (auto-upgrade resolvers) | security | [packages](packages#tarball-a-prebuilt-application-tarball) |
| `nixpkgs` | security | [nixpkgs](nixpkgs) |
| `[limits]` | security | [limits](limits) |
| `[seccomp]` | security | [seccomp](seccomp) |
| `[devices]` | security | [devices](devices) |
| `[fs]` | ungated (only closes) | [fs](fs) |
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
| `[redact]` | security | [redaction](../secrets/redaction#the-length-floor) |
| `[task.<name>]` | security | [task](task), and [Declared operations](../tasks/) |
| `[app.<name>]` | security overlay | [apps](apps) |
| `[plugin.<name>]` | security | [resolver plugins](../secrets/plugins#configuring-a-plugin-from-your-own-config) |
| `[network.groups]` | security (global-only) | [Egress groups](../networking/groups) |
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
