# `[app.<name>]`: named launch profiles

A `[app.<name>]` table declares a named, reusable launcher: a command plus a
security/tooling overlay over the sandbox baseline. `sbx app run <name>` launches it. This
page documents the **config shape**; for the framework (isolated homes, profiles,
credential injection) see the [Apps](../apps/) section.

`[app.<name>]` fields are gated exactly like the baseline: the security ones honored
only from a trusted source.

See also: [The app framework](../apps/) · [Per-app home](../apps/home) · [Portable profiles](../apps/profiles) · [`sbx app`](../cli/app).

## Two ways to declare an app

- **Inline** in a project `.sbx.toml` (or the global `sbx.toml`) as `[app.<name>]`.
- **As a profile file** under [`~/.config/sbx/apps/<name>.toml`](../concepts/directory-layout)
 , a standalone top-level app definition (its fields directly, no `[app.<name>]`
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
| `flakes`, `tarball`, `deb`, `appimage` | security | the resolver tables pairing with this app's packages, `[app.<name>.flakes.<tool>]` etc. (see [packages](packages)) |
| `network` | security | overrides the baseline posture when set |
| `proc` | security | overrides the baseline exec posture when set (see [proc](proc)) |
| `notify` | security | overrides the baseline refusal-notification policy when set (see [notify](notify)) |
| `gui` | security | overrides the baseline when set |
| `gpu`, `audio`, `dbus` | security | override the baseline when set (see [gpu](gpu), [audio](audio), [dbus](dbus)) |
| `forward` | security | host loopback ports **unioned** onto the baseline's (see [forward](../networking/forward)) |
| `secret` | security | credentials for this app's egress |
| `task` | security | this app's declared operations, `[app.<name>.task.<task>]`, unioned onto the baseline's (see [task](task)) |
| `limits` | security | per-field override of the baseline cgroup limits |
| `seccomp`, `devices`, `ssh_agent` | security | unioned onto the baseline's, which is how a deploy key is granted to *one* agent rather than every cage (see [seccomp](seccomp), [devices](devices), [ssh-agent](ssh-agent)) |
| `fs` | ungated | project paths this app closes, **unioned** onto the baseline's: an app closes more for its own cage and can never reopen what the project closed (see [fs](fs)) |
| `home_scope` | integrity-gated | `"global"` (default) or `"project"`: see [Per-app home](../apps/home) |

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

An app is the locked-down [agent posture](../concepts/overview#the-two-actor-modes):
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
sbx config show --app review    # one app's effective config, each field tagged inherited or set
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
