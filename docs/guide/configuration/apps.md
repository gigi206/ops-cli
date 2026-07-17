# `[app.<name>]` — named launch profiles

A `[app.<name>]` table declares a named, reusable launcher — a command plus a
security/tooling overlay over the sandbox baseline. `sbx app <name>` launches it. This
page documents the **config shape**; for the framework (isolated homes, profiles,
credential injection) see the [Apps](../apps/README.md) section.

`[app.<name>]` fields are gated exactly like the baseline: the security ones honored
only from a trusted source.

See also: [The app framework](../apps/README.md) · [Per-app home](../apps/home.md) · [Portable profiles](../apps/profiles.md) · [`sbx app`](../cli/app.md).

## Two ways to declare an app

- **Inline** in a project `.sbx.toml` (or the global `sbx.toml`) as `[app.<name>]`.
- **As a profile file** under [`~/.config/sbx/apps/<name>.toml`](../concepts/directory-layout.md)
  — a standalone top-level app definition (its fields directly, no `[app.<name>]`
  wrapper), the filename being the app name. Imported with
  [`sbx app import`](../cli/app.md). A global app lives **only** as a profile file, not
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
| `env` | free | overlaid on the baseline `env`, app wins on collision |
| `binds` | security | added to the baseline binds |
| `packages` | security | overrides a baseline tool of the same name |
| `network` | security | overrides the baseline posture when set |
| `gui` | security | overrides the baseline when set |
| `secret` | security | credentials for this app's egress |
| `limits` | security | per-field override of the baseline cgroup limits |
| `home_scope` | integrity-gated | `"global"` (default) or `"project"` — see [Per-app home](../apps/home.md) |

## Layering and gating

An app resolves `global → project → app`, each field overriding per layer, and each
security field gated by the trust of the layer that supplied it. Then
`merge_app` folds the app onto the resolved baseline. The one-shot
[override](overrides.md) applies *after* the app, as the final word.

The **flagship property**: a **globally-declared app keeps its posture even under an
untrusted project** — which is the whole point of running an agent *on* untrusted
code. Two integrity gates enforce it:

- **`cmd`** — an untrusted project may define *its own* app but **cannot override the
  `cmd` of a trusted/global app** (else it would launch attacker code under that app's
  posture). An untrusted override is dropped with a warning.
- **`home_scope`** — an untrusted project may set the scope of *its own* app but may
  not flip a trusted app from `"project"` to `"global"` (which would route an untrusted
  run into the home a trusted run shares). The safe direction (`"global"` → `"project"`,
  more isolation) is allowed.

`packages` is similarly protected: an untrusted project cannot override (or DoS) a
trusted app's package.

## Every app is Mode B

An app is the locked-down [agent posture](../concepts/overview.md#the-two-actor-modes):
its egress allowlist defaults to read-only verbs (see
[`default_methods`](network.md#default_methods-apps)), its home is isolated, and its
credentials are injected host-side. There is no per-app "interactive mode" field.

## Name validation

An app name is 1–64 characters of `[A-Za-z0-9._-]`, and not `.`/`..` — because the
name keys an on-disk home directory and profile file, an unsafe name is dropped
(fail-closed). The verbs `import`/`export`/`rm`/`list` are reserved and cannot be app
names.

## Viewing an app

```sh
sbx config show                 # a compact per-app roster
sbx config show --details       # each app's env, binds, packages, rules, credentials
sbx config show --app review    # one app's effective config, each field tagged inherited or set
```
