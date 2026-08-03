# `[bundle.<name>]`: reusable tool bundles

A bundle is **everything one tool needs to be installed and to reach its own
services**, declared once in the **global** config and folded into any app that names
it in `use`.

```toml
# ~/.config/sbx/sbx.toml
[bundle.claude-code]
packages = { claude-code = "mise:aqua:anthropics/claude-code" }
env      = { CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1" }
allow    = [
  "{*,WS} https://api.anthropic.com",
  "{*} https://platform.claude.com",
  "{GET} https://storage.googleapis.com:443/claude-code-dist-.../*",
]
```

```toml
# an app profile names it, and states nothing about that tool itself
cmd = "orchestrate"
use = ["claude-code"]

[network]
mode  = "deny"
allow = ["{*} https://orchestrator.example.com"]
```

See also: [Apps](apps) · [`[packages]`](packages) · [`[net.groups]`](net-groups) · [`sbx bundle`](../cli/bundle).

## What it is for

Some apps drive **other agents' CLIs**: an orchestrator that spawns `claude`,
`codex` or `opencode` as a subprocess. Each such app needs that tool's package, its
environment, its egress hosts and its credential, all of which the tool's *own*
profile already states. Copied by hand, the two drift: the copy misses a host the
original added, and the sub-agent fails at runtime in a way that looks like a sandbox
bug.

A bundle is the one declaration both read. `[net.groups]` already does this for
egress entries, which are list items a `@<name>` reference can expand into;
`packages` and `env` are **maps**, with no slot for such a reference: so a bundle is
the map-side companion, and it carries the egress along.

## What a bundle may carry: and what it may not

| Carries | Deliberately not |
| --- | --- |
| `packages` | `cmd` |
| `env` | `binds`, `forward`, `devices`, `seccomp`, `limits` |
| `allow`, `deny`, `mute` | `network` mode, `gui`, `gpu`, `audio`, `dbus`, `proc`, `home_scope` |
| `secret` | another bundle (`use`) |
| `task` (declared operations, `[bundle.<name>.task.<task>]`) | |
| `flakes`, `tarball`, `deb`, `appimage` (the resolver tables that pair with a package) | |

The line is the design, not a shortlist. A bundle describes **a tool**; it says
nothing about **the shape of the cage**. So using one can add a tool, its
environment, its egress and its credential: it can never widen what the cage exposes
of your host, and it can never silently switch on a microphone or a display because
the tool it packages can use one. There is no `cmd` because an app's command is its
identity: inheriting one would be an integrity hijack.

`task` folds like the rest: a tool that ships a brokered operation (a fixed command
run with a credential the caller never holds, see [`[task.<name>]`](task)) carries
it into any app that names the bundle, exactly as its packages and credentials do.
Each folded operation is stamped with the bundle it came from, so the origin reads
`bundle:<name>` in the `DECLARED IN` column of [`sbx task list`](../cli/task) (and
in [`sbx task show`](../cli/task)): the fold makes the entry look like the app's
own, and the bundle is where a reader would go to change it.

A bundle cannot name another bundle. There is no `use` field on a bundle, so nesting, and with it any cycle: is impossible by construction, exactly as a `[net.groups]`
entry may not be a `@other` reference. A bundle's `allow`/`deny`/`mute` entries **may**
be `@group` references: those are reference sites like an app's own lists, and the
bundle is folded in before classification, so group expansion still runs once.

## Precedence

Bundles apply **in the order written**, and the app always wins:

```toml
use = ["a", "b"]        # b overrides a on a key both declare
[packages]
shared-lib = "nix:ripgrep"   # and this overrides whatever either bundle said
```

Egress entries **union** rather than override: a duplicate is not repeated. So a
profile can adopt a bundle wholesale and still pin one of its packages.

## Global-only, and `use` is a security field

Bundles are honored **only from the global config** (trusted by its location), like
`[net.groups]`. A project's `[bundle]` is ignored with a warning.

`use` is a **security field**. A bundle carries egress rules and credentials, so an
untrusted project naming one would be choosing which trusted reach to graft onto an
app it controls. An untrusted layer's `use` is therefore dropped with a per-app note,
exactly like `network`:

```
note: .sbx.toml [app.sneaky]: ignoring `use` of bundle(s) `claude-code` (untrusted — run `sbx trust`)
```

Run [`sbx trust`](../cli/trust) to apply it. A profile under `~/.config/sbx/apps/`
is trusted by location, so its `use` always applies.

## An app with no `[network]` table

A bundle's egress entries are unioned into the app's **own** `[network]` table. An app
that declares none has them **dropped, with a warning**: add a table to apply them:

```toml
[network]
mode = "deny"
```

This looks over-cautious and is not. A `[network]` table with no `mode` inherits the
parent posture, but *only a filtering one*: under a `shared` (or `allow`, or absent)
baseline it falls back to `deny`. Synthesizing a table for you would therefore turn a
wide-open app into a default-deny allowlist behind your back. A bundle must never move
a posture in either direction, so the gap is the safe answer.

Under an app that declared `network = "shared"` or `"none"` the entries are simply
redundant, that posture is already wider, or admits nothing at all, so they are
dropped silently. Nothing was lost.

## The shipped bundles

The repository ships one bundle per agent CLI under
[`examples/bundle/`](https://github.com/gigi206/ops-cli/tree/ops-v2/examples/bundle/), each derived from the agent profile of
the same name in [`examples/app/`](https://github.com/gigi206/ops-cli/tree/ops-v2/examples/app/): a test pins the two
together, so they cannot drift apart:

```sh
sbx bundle import examples/bundle/opencode.toml
```

The 26 shipped bundles, and what each carries:

| Bundle | Packages | Also carries |
|---|---|---|
| `agy` | 1 (`mise:`) | 8 egress rules |
| `auggie` | 2 (`mise:`, `nix:`) | 3 egress rules, 1 env var |
| `claude-code` | 1 (`mise:`) | 6 egress rules, 3 env vars |
| `cline` | 3 (`mise:`, `nix:`) | 5 egress rules |
| `codebuddy` | 2 (`mise:`, `nix:`) | 3 egress rules, 2 env vars |
| `codex` | 1 (`mise:`) | 6 egress rules |
| `copilot` | 1 (`mise:`) | 5 egress rules |
| `dirac` | 3 (`mise:`, `nix:`) | 1 egress rule |
| `droid` | 2 (`mise:`, `nix:`) | 6 egress rules |
| `freebuff` | 2 (`mise:`, `nix:`) | 6 egress rules |
| `goose` | 1 (`mise:`) | 1 egress rule, 2 env vars |
| `grok` | 1 (`mise:`) | 2 egress rules, 1 env var |
| `hermes` | 2 (`flake:`, `nix:`) | 10 egress rules, 1 env var |
| `kilocode` | 1 (`mise:`) | 3 egress rules |
| `kimi` | 2 (`mise:`, `nix:`) | 6 egress rules |
| `nova` | 2 (`mise:`, `nix:`) | 3 egress rules |
| `openclaw` | 2 (`mise:`, `nix:`) | 2 egress rules, 1 env var |
| `opencode` | 1 (`mise:`) | 3 egress rules |
| `openfox` | 2 (`mise:`, `nix:`) | none |
| `pi` | 1 (`mise:`) | 1 egress rule |
| `qoder` | 3 (`mise:`, `nix:`) | 4 egress rules |
| `qwen-code` | 2 (`mise:`, `nix:`) | 2 egress rules |
| `sigit` | 2 (`mise:`, `nix:`) | 3 egress rules |
| `snow` | 2 (`mise:`, `nix:`) | 1 egress rule |
| `stakpak` | 1 (`mise:`) | 1 egress rule |
| `vtcode` | 3 (`mise:`, `nix:`) | none |

None of them carries a `cmd` or a posture (`network` mode, `gui`, `gpu`, …): a bundle states
what a tool *needs*, and the consuming app keeps its own command and its own posture. See
[What a bundle may carry](#what-a-bundle-may-carry-and-what-it-may-not).

The three orchestrator profiles (`aionui`, `t3code`, `open-design`) name one with
`use` instead of copying its requirements. They are therefore the only shipped
profiles that are **not** one-step imports; every standalone agent profile still is.

## Managing bundles

```sh
sbx bundle                        # list every bundle and what it contributes
sbx bundle claude-code            # show one in full
sbx bundle export > bundles.toml  # write a portable fragment
sbx bundle import bundles.toml    # merge one into the global config
```

An imported bundle is **inert** until an app names it in `use`. See
[`sbx bundle`](../cli/bundle) for the full command surface.

## Portability

A bundle lives in the global config, so a profile that names one is **not
self-contained**: sharing that profile means sharing the bundle too
(`sbx bundle export` / `sbx bundle import`), the same two-step
[`sbx net groups`](../cli/net) uses. A profile that states everything itself stays
one portable file, the trade is fewer copies against fewer moving parts, and it is
yours to make per profile.
