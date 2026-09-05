---
sidebar_label: "[app.<name>]"
description: "A named, reusable launcher: a command plus the overlay it runs under."
---

# `[app.<name>]`: named launch profiles

A `[app.<name>]` table declares a named, reusable launcher: a command plus a
security/tooling overlay over the sandbox baseline. `sbx app run <name>` launches it. This
page documents the **config shape**; for the framework (isolated homes, profiles,
credential injection) see the [Apps](../apps/) section.

`[app.<name>]` fields are gated exactly like the baseline: the security ones honored
only from a trusted source.

See also: [The app framework](../apps/) · [Per-app home](../apps/home) · [Portable profiles](../apps/profiles) · [`sbx app`](../cli/app).

## Why name an app

The same agent command tends to be relaunched across projects with the same packages, network allowlist, credential injection, and an isolated `$HOME` that keeps one agent's state away from another's and from your shell. Copying that overlay into every project's `.sbx.toml` drifts: one copy misses a host the others added and the failure looks like a sandbox bug. An `[app.<name>]` table declares it once, and `sbx app run <name>` launches the command under it, on any project.

## Two ways to declare an app

- **Inline** in a project `.sbx.toml` (or the global `sbx.toml`) as `[app.<name>]`.
- **As a profile file** under [`~/.config/sbx/apps/<name>.toml`](../concepts/directory-layout),
  a standalone top-level app definition (its fields directly, no `[app.<name>]`
  wrapper), the filename being the app name. Imported with
  [`sbx app import`](../cli/app). A global app lives **only** as a profile file, not
  inline in the global `sbx.toml`.

## The fields

```toml
[app.review]
cmd        = "claude"                 # or an argv: ["claude", "--flag"]
home_scope = "global"                 # "global" (default) or "project"
gui        = "none"

[app.review.env]
SOME_FLAG = "1"

[app.review.packages]
claude = "mise:aqua:anthropics/claude-code"

[app.review.network]
mode  = "deny"
allow = ["api.anthropic.com"]

[app.review.secret."api.anthropic.com"]
from   = "env://ANTHROPIC_API_KEY"
header = "x-api-key"
type   = "raw"

[app.review.limits]
tasks_max = 4096
```

| Field | Kind | Notes |
|---|---|---|
| `cmd` | integrity-gated | a bare string (one-element argv, never whitespace-split) or an argv array |
| `use` | security | tool [bundles](bundles) folded into this app, in the order written (a later one wins on a key, the app always wins); must sit above the first `[table]` header |
| `env` | free | overlaid on the baseline `env`, app wins on collision |
| `binds` | security | added to the baseline binds |
| `packages` | security | overrides a baseline tool of the same name |
| `flakes`, `tarball`, `deb`, `appimage`, `binary` | security | the resolver tables pairing with this app's packages, `[app.<name>.flakes.<tool>]` etc. (see [packages](packages)) |
| `accepts_fresh_releases` | security | package names exempted from the new-release cooling-off period, unioned onto the baseline's |
| `allow_insecure_http` | security | plaintext-fetch posture for this app, overriding the baseline when set |
| `network` | security | overrides the baseline posture when set |
| `proc` | security | overrides the baseline exec posture when set (see [proc](proc)) |
| `notify` | security | overrides the baseline refusal-notification policy when set (see [notify](notify)) |
| `gui` | security | overrides the baseline when set |
| `gpu`, `audio`, `dbus` | security | override the baseline when set (see [gpu](gpu), [audio](audio), [dbus](dbus)) |
| `forward` | security | host loopback forwards folded onto the baseline's **by cage port**: an app adds a forward, or moves one to another host port, but never closes one (see [forward](../networking/forward)) |
| `secret` | security | credentials for this app's egress |
| `open` | security | URI handlers for this app, overriding the baseline's on the same scheme |
| `service` | security | auxiliary processes for this app, overriding the baseline's under the same name |
| `task` | security | this app's declared operations, `[app.<name>.task.<task>]`, unioned onto the baseline's (see [task](task)) |
| `limits` | security | per-field override of the baseline cgroup limits |
| `seccomp`, `devices`, `ssh_agent` | security | unioned onto the baseline's, which is how a deploy key is granted to *one* agent rather than every cage (see [seccomp](seccomp), [devices](devices), [ssh-agent](ssh-agent)) |
| `fs` | ungated | project paths this app closes, **unioned** onto the baseline's: an app closes more for its own cage and can never reopen what the project closed (see [fs](fs)) |
| `home_scope` | integrity-gated | `"global"` (default) or `"project"`: see [Per-app home](../apps/home); an unrecognized value is warned about and ignored, keeping `global` |

### A key an app does not have

An app profile is a **subset** of this schema, not all of it: baseline fields like
[`timezone`](timezone), `nixpkgs`, `distro`, `mise`, `plugin`, `broker`, `bundle`, `redact`
and `[network] groups` belong to the config that holds the app,
not to the app. Writing one under `[app.<name>]`, or at the top level of a profile file, parses and does nothing.
sbx names the key at launch instead of dropping it in silence, and says that such a field is
declared at the top level of `sbx.toml` or `.sbx.toml`. The same report catches a plain misspelling.

The report names the **file** the key is in, which is the one to open: `apps/<name>.toml` for a
global app, `.sbx.toml [app.<name>]` for a project one. The two differ because only a project app is
a table; a profile file holds one app and puts its fields at the top level.

One mistake it cannot catch, and it is the more likely of the two: a scalar written *below* a
`[table]` header is folded into that table by TOML itself, so it never reaches sbx as an app key at
all. Appending `timezone = "Europe/Paris"` to the end of a profile is exactly that. Keep scalars
above the first table.

:::note Where an app's `nixpkgs` value comes from

"Not a key an app has" says where you may *write* it. It does not say the app inherits the
value from the config it was declared in. The launch reads the channel **source** from the
directory it is launched in: a trusted `nixpkgs` pin in that project wins, otherwise the
global config's channel, otherwise the default. For an app declared in a project's own
`.sbx.toml` those are the same config. For a **global** app they are not, so the same profile
launched from two projects can read two different sources.

The **revision** is separate, and it is the app's own: each app has its own nixpkgs lock, so
`sbx upgrade nix` rolls the project and leaves the app where it is, and
[`sbx upgrade nix --app <name>`](../cli/upgrade#an-apps-base-channel) is what moves it. A
trusted project pin still outranks that lock, because an app launch also builds the project's
declared packages and they have to come from the pinned revision.

What remains is that one shared home can be built under two different projects' pins. If that
matters for an app, give it [`home_scope = "project"`](../apps/home): one home per project means
one config decides for that home, and the two can never cross.

:::

### The `cmd` field and trailing arguments

`cmd` is either a bare string (a one-element argv, never whitespace-split) or an argv
array. `sbx app run <name> -- <args>` appends those arguments to it, so a plain argv
receives them directly and the program reads its own flags.

A shell-wrapped command needs one more thing from you. `["bash", "-c", "<script>"]` binds
the element right after the script to `$0`, not to `$1`, so sbx inserts the app's name
there before appending: your first argument arrives as `$1`. What sbx cannot do is decide
where the script sends them, so the script has to expand `"$@"` itself, on the command it
finally runs:

```toml
[app.demo]
# Receives `sbx app run demo -- --flag value`.
cmd = ["bash", "-c", "export PATH=\"$HOME/.local/bin:$PATH\"\nexec demo \"$@\""]

# Accepts those arguments and drops them: no `"$@"` anywhere in the script.
# cmd = ["bash", "-c", "exec demo --headless"]
```

A profile that declares its own element after the script keeps it: sbx adds nothing, and
that element stays the script's `$0`. Use a shell only when the command derives a value,
tests a path or writes a file; when it does not, a plain argv is one process fewer and
needs no `"$@"` at all.

## Layering and gating

An app resolves `global → project → app`, each field overriding per layer, and each
security field gated by the trust of the layer that supplied it. Then
`merge_app` folds the app onto the resolved baseline. The one-shot
[override](overrides) applies *after* the app, as the final word.

The **flagship property**: a **globally-declared app keeps its posture even under an
untrusted project**: which is the whole point of running an agent *on* untrusted
code. Two integrity gates enforce it:

- **`cmd`**, an untrusted project may define *its own* app but **cannot override the
  `cmd` of a trusted/global app** (else it would launch attacker code under that app's
  posture). An untrusted override is dropped with a warning.
- **`home_scope`**, an untrusted project may set the scope of *its own* app but may
  not flip a trusted app from `"project"` to `"global"` (which would route an untrusted
  run into the home a trusted run shares). The safe direction (`"global"` → `"project"`,
  more isolation) is allowed.

`packages` is similarly protected: an untrusted project cannot override (or DoS) a
trusted app's package.

## Every app is Mode B

An app is the locked-down [agent posture](../concepts/#the-two-actor-modes):
its egress allowlist defaults to read-only verbs (see
[`default_methods`](network#default_methods-apps)), its home is isolated, and its
credentials are injected host-side. There is no per-app "interactive mode" field.

## Name validation

An app name is 1–64 characters of `[A-Za-z0-9._-]`, and not `.`/`..`: because the
name keys an on-disk home directory and profile file, an unsafe name is dropped
(fail-closed). The verbs `import`/`export`/`rm`/`list` are reserved and cannot be app
names.

## Viewing an app

```sh
sbx config show                 # a compact per-app roster
sbx config show --details       # each app's env, binds, packages, rules, credentials
sbx config show --app review    # each field tagged default, inherited, or set by the app
sbx config show --app review --details  # plus every posture no layer set (folded by default)
```

## Examples by posture

**A terminal agent, reaching one API.** The common case: an isolated home, a
read-by-default allowlist, and a credential the cage never holds.

```toml
[app.review]
cmd = "claude"

[app.review.packages]
claude = "mise:aqua:anthropics/claude-code"

[app.review.network]
mode  = "deny"
allow = ["api.anthropic.com"]

[app.review.secret."api.anthropic.com"]
from   = "env://ANTHROPIC_API_KEY"
header = "x-api-key"
type   = "raw"
```

**An agent that must write somewhere, and push.** Egress needs the verbs spelled out
(the app default is read-only), the ssh grant is unioned onto the baseline so it
belongs to this one app, and the limits keep a runaway build off the host.

```toml
[app.builder]
cmd        = ["claude", "--dangerously-skip-permissions"]
home_scope = "project"          # one home per project, not one shared home

[app.builder.network]
mode  = "deny"
allow = ["api.anthropic.com", "{*} https://api.github.com", "tcp://github.com:22"]

[app.builder.ssh_agent]
allow   = ["deploy@example"]
confirm = true

[app.builder.limits]
memory_max = "8G"
tasks_max  = 4096
```

**A desktop application.** The display, GPU and portal holes are each trusted-only and
each off unless named.

```toml
[app.editor]
cmd   = "some-editor"
gui   = "wayland"
gpu   = true
dbus  = true

[app.editor.packages]
some-editor = "appimage:https://example.invalid/editor-1.2.3.AppImage"
```

**An agent under observation, with the operations it may invoke.** The task is the
credential-bearing half; the agent holds only the right to ask for it.

```toml
[app.reviewer]
cmd  = "claude"
proc = "enforce"

[app.reviewer.task.fmt-check]
cmd   = ["cargo", "fmt", "--check"]
spawn = []
```

**Reusing a shared piece instead of rewriting it.** `use` folds a bundle's packages,
env, egress and credentials in; it must sit above the first `[table]` header.

```toml
[app.my-agent]
cmd = "claude"
use = ["claude-code"]
```

Then, whichever shape it is, the same three questions before launching it:

```sh
sbx config show --app my-agent   # its effective config, each field tagged
sbx net rules -a my-agent        # the egress it would actually get
sbx secret list -a my-agent      # the credentials it would carry
sbx app run my-agent
```
