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

See also: [Apps](apps) · [`[packages]`](packages) · [`[net.groups]`](../networking/groups) · [`sbx bundle`](../cli/bundle).

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

## What a bundle may carry, and what it may not

| Carries | Deliberately not |
| --- | --- |
| `packages` | `cmd` |
| `env` | `binds`, `forward`, `devices`, `seccomp`, `limits` |
| `allow`, `deny`, `mute` | `network` mode, `gui`, `gpu`, `audio`, `dbus`, `proc`, `home_scope` |
| `secret` | another bundle (`use`) |
| `task` (declared operations, `[bundle.<name>.task.<task>]`) | |
| `flakes`, `tarball`, `deb`, `appimage` (the resolver tables that pair with a package) | |
| `provision` (the one-time step that finishes an install) | |

The line is the design, not a shortlist. A bundle describes **a tool**; it says
nothing about **the shape of the cage**. So using one can add a tool, its
environment, its egress and its credential: it can never widen what the cage exposes
of your host, and it can never silently switch on a microphone or a display because
the tool it packages can use one. There is no `cmd` because an app's command is its
identity: inheriting one would be an integrity hijack.

`provision` is the one thing a bundle carries that is a **command**, and it is not an
exception to that rule: it is the step that finishes installing the tool, it runs
before the app's own command, and it can never replace it. It exists because a bundle
could describe what a tool needs but not the act of installing it when that act is a
command, which left a consuming app with a package it cannot start and an install step
to hand-copy. Declared as an argv, like `cmd`:

```toml
[bundle.demo]
packages  = { demo = "mise:npm:demo" }
provision = ["bash", "-c", "npm rebuild demo-addon"]
```

What using it grants is stated where the decision is made: `sbx bundle` counts it in
the summary and prints the command verbatim when a bundle is named,
`sbx bundle import` says an install step arrived alongside the egress and credential
counts, and [`sbx config show --app <name>`](../cli/config) renders it beside that
app's command, naming the bundle it came from. A command that will run in your cage is
not something to discover at the next launch.

Steps are **carried, not merged**: two bundles each finish their own tool, so both run,
in the order the app named them in `use`. A bundle named by two layers contributes
once. And like everything else a bundle brings, a step arrives only from a trusted
layer: an untrusted project's `use` is dropped whole, with the same per-app note it
already gets.

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

The repository ships one bundle per tool — a CLI, a desktop build, a web UI's engine — under
`examples/bundle/`, each the single source of truth for what that agent needs: the namesake profile in
`examples/app/` names it with `use` and no longer restates the requirements; a test pins the two
together, so they cannot drift apart:

```sh
sbx bundle import examples/bundle/opencode.toml
```

A bundle may itself reference shared egress groups with `@name` (its header then says
`REQUIRES egress groups — import them once`): import those too, from
`examples/net-groups/`,
with `sbx net groups import`.

The 62 shipped bundles, and what each carries:

| Bundle | Packages | Also carries | Requires groups |
|---|---|---|---|
| `agy` | 1 (`mise:`) | 9 egress entries | none |
| `aider` | 3 (`mise:`, `nix:`) | 2 egress entries | `pypi` |
| `amp` | 2 (`mise:`, `nix:`) | 4 egress entries, 1 env var | `npm-audit`, `npm-registry` |
| `ante` | 1 (`mise:`) | 4 egress entries | none |
| `antigravity` | 2 (`nix:`, `tarball:`) | 27 egress entries, a `tarball:` resolver | `chromium-background` |
| `auggie` | 2 (`mise:`, `nix:`) | 6 egress entries, 1 env var | `npm-audit`, `npm-registry` |
| `autohand` | 2 (`mise:`, `nix:`) | 4 egress entries | `github-install`, `npm-registry` |
| `claude-code` | 1 (`mise:`) | 6 egress entries, 3 env vars | none |
| `claude-desktop` | 2 (`deb:`, `nix:`) | 23 egress entries, 3 env vars | `chromium-background`, `google-signin-incage` |
| `cline` | 3 (`mise:`, `nix:`) | 7 egress entries | `models-catalog`, `npm-audit`, `npm-registry` |
| `codebuddy` | 2 (`mise:`, `nix:`) | 4 egress entries, 2 env vars | `npm-audit`, `npm-registry` |
| `codex` | 1 (`mise:`) | 6 egress entries | none |
| `command-code` | 2 (`mise:`, `nix:`) | 12 egress entries | `github-install`, `npm-registry` |
| `copilot` | 1 (`mise:`) | 6 egress entries | none |
| `cortex` | 2 (`mise:`, `nix:`) | 6 egress entries | none |
| `crush` | 1 (`mise:`) | 4 egress entries, 2 env vars | `github-install` |
| `cursor` | 2 (`deb:`, `nix:`) | 31 egress entries, 1 env var, a `deb:` resolver | `chromium-background` |
| `cursor-agent` | 2 (`nix:`) | 5 egress entries, 1 env var | none |
| `deepagents-code` | 3 (`mise:`, `nix:`) | 1 egress entry | `pypi` |
| `deepseek-harness` | 5 (`mise:`, `nix:`) | 3 egress entries | `npm-audit`, `npm-registry` |
| `devin` | 1 (`tarball:`) | 4 egress entries, a `tarball:` resolver | none |
| `dirac` | 3 (`mise:`, `nix:`) | 5 egress entries | `npm-audit`, `npm-registry` |
| `droid` | 2 (`mise:`, `nix:`) | 9 egress entries | `npm-audit`, `npm-registry` |
| `freebuff` | 2 (`mise:`, `nix:`) | 8 egress entries | `npm-audit`, `npm-registry` |
| `freebuff-desktop` | 2 (`appimage:`, `nix:`) | 26 egress entries, an `appimage:` resolver | `chromium-background`, `github`, `github-api`, `npm-runtime` |
| `goose` | 1 (`mise:`) | 1 egress entry, 2 env vars | none |
| `goose-desktop` | 1 (`deb:`) | 2 env vars | none |
| `grok` | 1 (`mise:`) | 3 egress entries, 1 env var | none |
| `hermes` | 2 (`flake:`, `nix:`) | 10 egress entries, 1 env var | `models-catalog`, `npm-audit`, `npm-registry` |
| `hermes-desktop` | 4 (`flake:`, `mise:`, `nix:`) | 21 egress entries, 1 env var | `chromium-background`, `google-signin-incage`, `models-catalog`, `npm-audit`, `npm-registry` |
| `jcode` | 1 (`mise:`) | 1 egress entry, 2 env vars | none |
| `junie` | 2 (`mise:`, `nix:`) | 7 egress entries | `npm-audit`, `npm-registry` |
| `kilocode` | 1 (`mise:`) | 4 egress entries | `models-catalog` |
| `kimi` | 2 (`mise:`, `nix:`) | 7 egress entries | `models-catalog`, `npm-registry` |
| `kiro` | 2 (`nix:`) | 34 egress entries | `chromium-background`, `google-signin-incage` |
| `kiro-desktop` | 2 (`nix:`, `tarball:`) | 36 egress entries, 1 env var, a `tarball:` resolver | `chromium-background` |
| `mimo` | 2 (`mise:`, `nix:`) | 6 egress entries | `models-catalog`, `npm-registry` |
| `muse` | 1 (`nix:`) | 4 egress entries, 1 env var | none |
| `nanobot` | 3 (`mise:`, `nix:`) | 1 egress entry | `pypi` |
| `nova` | 2 (`mise:`, `nix:`) | 5 egress entries | `npm-audit`, `npm-registry` |
| `odysseus` | 6 (`nix:`) | 6 egress entries, 3 env vars | `npm-audit`, `npm-registry`, `pypi` |
| `omp` | 1 (`mise:`) | 1 egress entry | none |
| `openclaude` | 2 (`mise:`, `nix:`) | 1 egress entry | `npm-registry` |
| `openclaw` | 2 (`mise:`, `nix:`) | 3 egress entries, 1 env var | `npm-audit`, `npm-registry` |
| `opencode` | 1 (`mise:`) | 3 egress entries | `models-catalog`, `npm-registry` |
| `opencode-desktop` | 1 (`deb:`) | 4 egress entries | `models-catalog`, `npm-runtime` |
| `openfox` | 2 (`mise:`, `nix:`) | none | none |
| `pi` | 1 (`mise:`) | 1 egress entry | none |
| `pool` | 1 (`tarball:`) | 1 egress entry, a `tarball:` resolver | none |
| `prime-agent` | 5 (`nix:`) | 4 egress entries, 1 env var | `npm-registry`, `pypi` |
| `qoder` | 3 (`mise:`, `nix:`) | 6 egress entries | `npm-audit`, `npm-registry` |
| `qwen-code` | 2 (`mise:`, `nix:`) | 3 egress entries | `npm-registry` |
| `reasonix` | 2 (`mise:`, `nix:`) | 4 egress entries | `npm-audit`, `npm-registry` |
| `reasonix-desktop` | 1 (`deb:`) | 2 egress entries, 4 env vars, a `deb:` resolver | none |
| `rovo` | 1 (`nix:`) | 12 egress entries | none |
| `sigit` | 2 (`mise:`, `nix:`) | 5 egress entries | `npm-audit`, `npm-registry` |
| `snow` | 2 (`mise:`, `nix:`) | 2 egress entries | `npm-audit`, `npm-registry` |
| `stakpak` | 1 (`mise:`) | 4 egress entries | none |
| `trae` | 2 (`nix:`) | 2 egress entries | `github`, `pypi` |
| `vibe` | 4 (`mise:`, `nix:`) | 12 egress entries | `chromium-background`, `pypi` |
| `vtcode` | 3 (`mise:`, `nix:`) | none | none |
| `warp` | 1 (`tarball:`) | 6 egress entries, a `tarball:` resolver | none |

None of them carries a `cmd` or a posture (`network` mode, `gui`, `gpu`, …): a bundle states
what a tool *needs*, and the consuming app keeps its own command and its own posture. See
[What a bundle may carry](#what-a-bundle-may-carry-and-what-it-may-not).

Every shipped profile now names a bundle with `use`: 62 of the 69 name their own, and the
other 7 consume **another** agent's, because nothing would ever compose them in turn —
`t3code` names `claude-code`; `aionui`, `opencode-web`, `open-design` and `orca-desktop`
name `opencode`; `hermes-web` and `hermes-webui` name `hermes`. No shipped profile is a
one-step import any more: importing one alone leaves its bundle (and any group that
bundle REQUIRES) undeclared, and the launch warns.

Five of those bundles carry the **fetch tooling** rather than the agent: `cursor-agent`, `muse`,
`odysseus`, `prime-agent` and `trae` install through their profile's own `cmd` — a vendor bootstrap
whose artifact no backend fits, or a source checkout — which a bundle cannot carry.
Their headers say so: naming one equips a cage that can reach the agent's service but has
no agent in it until the consuming app reproduces that install step.

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
