---
description: "Importing, exporting and sharing an app as a standalone file, and the starter profiles sbx ships."
---

# Portable profiles

An app **profile** is a standalone, portable file that defines one app. `sbx` ships
**no built-in apps**, every profile is a separate artifact you import deliberately, so
importing is a conscious trust act.

See also: [The app framework](../apps/) · [Profile catalog](catalog) · [`sbx app`](../cli/app) · [`[app.<name>]`](../configuration/apps).

## The profile file shape

A profile is a TOML file shaped as a **top-level app**: the app's fields directly, with
**no `[app.<name>]` wrapper**, and its **filename is the app name**:

```toml
# my-agent.toml  →  the app is named "my-agent"
cmd = "my-agent"
home_scope = "global"

[packages]
my-agent = "mise:npm:my-agent"

[network]
mode  = "deny"
allow = ["{*} https://api.openrouter.ai"]

[secret."api.openrouter.ai"]
from   = "env://OPENROUTER_API_KEY"
header = "Authorization"
type   = "bearer"
```

Imported profiles live under
[`~/.config/sbx/apps/<name>.toml`](../concepts/directory-layout) and are **trusted by
location**, honored even when the project you launch in is untrusted (the point: run an
agent *on* untrusted code, safely).

## Import

```sh
sbx app import <file> [--as <name>] [--force]
```

- The **deliberate command is the consent**: an agent in the cage cannot run it, and
  the profile stays **inert until `sbx app run <name>`** launches it.
- The **granted posture is printed** (command, home scope, packages, binds, network, each
  credential by destination + source, never a plaintext value, and every grant that widens
  what the cage reaches of the host: `devices`, `seccomp allow`,
  [`ssh_agent`](../configuration/ssh-agent), the one that asks your own agent to sign,
  `allow_insecure_http`, `gpu`, `audio`, `dbus`, `forward`, and the profile's own
  `[task]`/`[service]` entries). Any other section the file declares is **named** on a
  closing `also declares:` line, so a profile never arrives carrying something the report
  did not mention.
- The file must have a `cmd` (an empty parse is the tell-tale of a wrongly
  `[app.<name>]`-wrapped file, refused with a hint).
- `--as` renames the imported app (default: the file's stem); `--force` overwrites an
  existing profile. Without it the existing file is refused, not replaced. A forced import
  names the settings the incoming file no longer sets, and keeps what it replaced beside
  the profile as `<name>.toml.replaced`, so a rule or credential added by hand on this
  machine can be read back and re-applied. That copy is not a profile (only `*.toml` is
  read as one) and is removed with the app.
- The bytes are copied verbatim (comments preserved).
- **What the profile is short of is named.** A profile that references a
  [bundle](../configuration/bundles) in `use`, or an
  [egress group](../networking/) as `@<name>`, resolves both against the global config; an
  undeclared one is reported here, with the sibling file to import when one can be found.
  All 74 shipped profiles name a bundle, so a starter profile takes two imports. Either
  order works: nothing resolves until `sbx app run <name>`. With `--with-deps` the import
  follows those references instead of naming them, which merges into your global config and
  is therefore opt-in.

## Export

```sh
sbx app export <name> [--out <file>]
```

Writes a named app out as a portable profile: to **stdout** by default (composable and
clobber-safe), or `--out <file>`. An imported profile is emitted **verbatim**; an inline
`[app.<name>]` is serialized to a minimal profile, **as authored** (security fields and
all, import is the trust act, not export). The exported file re-imports identically.

```sh
sbx app export claude-code > my-claude.toml
```

## Manage

```sh
sbx app list          # the imported profiles, by name
sbx app rm <name>...  # remove imported profiles (not an inline [app.<name>])
```

`sbx app rm` manages only **imported** profiles (files in the profiles directory). A
project `[app.<name>]` overlay lives in that project's `.sbx.toml` and is edited there.
Several names may be given in one call, each removed on its own (see
[Removing an app](../cli/app#removing-an-app)).
For the full resolved app set (inline, project, and profile apps with their gating), use
[`sbx config show`](../cli/config).

## The trust act

Importing is where trust happens, not export: a profile is exported *as authored*,
security fields and all, regardless of trust, because the person importing it is the one
who decides to trust it. Since an imported profile is trusted by location, it keeps its
posture even under an untrusted project (the [flagship property](../apps/#the-flagship-property)).

## Reproducibility

The repository's [`examples/app/`](catalog) directory holds importable starter profiles
for popular coding agents. Each declares its tool with a
[backend-prefixed `[packages]`](../configuration/packages) value, so it provisions
fresh. See the [Profile catalog](catalog).
