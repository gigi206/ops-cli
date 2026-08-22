---
sidebar_label: "Overview"
description: "An app is a named, reusable agent launcher: a command plus the security and tooling overlay it runs under."
---

# The app framework

An **app** is a named, reusable agent launcher: the flagship surface of `sbx`. It
bundles a command with a security and tooling overlay so you can run an autonomous
agent *on* untrusted code, safely and repeatably.

```sh
sbx bundle import examples/bundle/claude-code.toml  # what the agent requires
sbx app import    examples/app/claude-code.toml     # a deliberate trust act
sbx app run claude-code                             # launch it, sandboxed
```

A shipped profile names a [bundle](../configuration/bundles) in `use`, so it takes two
imports: the bundle carries what the agent **requires** and follows upstream, the profile
carries what **you** configure. Either order works. Import only the profile and the app
launches without the tool and egress it named, which is why `sbx app import` names the
file you are still missing, and why `--with-deps` will fetch it for you from the file
beside the profile.

See also: [`[app.<name>]` config](../configuration/apps) · [Per-app home](home) · [Portable profiles](profiles) · [Profile catalog](catalog) · [Bundles](../configuration/bundles) · [`sbx app`](../cli/app).

## The two-layer model

An app is an **overlay** over the sandbox baseline:

```
sandbox baseline  +  [app.<name>] overlay  →  what `sbx app run <name>` launches
```

The baseline is your project's resolved config (global + project). The overlay adds the
app's `cmd`, `env`, `packages`, `binds`, `network`, `gui`, `secret`, and `limits`. Each
overlay field is [gated by trust](../concepts/trust) exactly like the baseline, then
merged onto it. A one-shot [override](../configuration/overrides) applies *after* the
overlay, as the final word.

## Every app is Mode B

An app is the locked-down [agent posture](../concepts/#the-two-actor-modes):

- Its own **persistent isolated `$HOME`**: the agent's config, login state, and
  history never bleed into your project shell or another app. See [Per-app home](home).
- **Read-by-default egress**: an app's allow rules default to `{GET,HEAD}`, so an
  agent reads but does not write unless a rule opts a host out. See
  [`default_methods`](../configuration/network#default_methods-apps).
- **Host-side credential injection**: the API key is read on the host and injected on
  the wire by the [egress proxy](../secrets/injection); it never enters the cage.

## The flagship property

A **globally-declared app keeps its posture even under an untrusted project.** That is
the whole point: you can point an agent at a repository you do not trust, and the
agent's command, network allowlist, and credentials are fixed by *your* profile, not
by the project.

Two integrity gates enforce it: an untrusted project cannot override a trusted app's
[`cmd`](../configuration/apps#layering-and-gating) (which would run attacker code
under the app's posture), nor flip a trusted app's [`home_scope`](home) from
`"project"` to `"global"` (which would route an untrusted run into a shared home). Its
`packages` are protected the same way.

## Declaring an app

- **Inline**, a `[app.<name>]` table in a project `.sbx.toml` (or the global
  `sbx.toml`, though a *global* app is best kept as a profile file). See
  [`[app.<name>]`](../configuration/apps).
- **A profile file**: a standalone `apps/<name>.toml`, imported with
  [`sbx app import`](../cli/app). This is the portable form. See
  [Portable profiles](profiles).

## Where to go next

- [Per-app isolated `$HOME`](home): persistence and the `home_scope` choice.
- [Portable profiles](profiles): import, export, and the trust act.
- [Profile catalog](catalog): the agent profiles shipped in this repository.
- [Secrets](../secrets/): how a credential is injected without entering the cage.
