---
description: "Roll managed toolchains forward by re-resolving and rewriting their locks."
---

# `sbx upgrade`

```
sbx upgrade [all|nix|mise|flake|deb|appimage|tarball|binary|provision] [-a <name>] [--project <path>]
```

Roll managed channels forward by re-resolving and rewriting their locks, so versions
advance **only here**, never on an `sbx` binary update.

| Target | Rolls |
|---|---|
| `all` | every channel, and the bundles' install steps under their own guards (the default) |
| `nix` | the nixpkgs channel (base userland + native `nix:` packages) |
| `mise` | the mise engine, the project's `nix:` tools, `mise:` packages, and the [task tool pool](../tasks/execution#the-task-tool-pool) |
| `flake` | the project's and apps' `flake:` packages |
| `deb` | the project's and apps' `deb:` packages |
| `appimage` | the project's and apps' `appimage:` packages |
| `tarball` | the project's and apps' `tarball:` packages |
| `binary` | the project's and apps' `binary:` packages |
| `provision` | re-run the apps' [bundle install steps](../configuration/bundles#the-install-step) in-cage, regardless of their guards |

| Flag | Effect |
|---|---|
| `-a, --app <name>` | narrow `nix`, `mise` or `provision` to one app |
| `--project <path>` | roll another project instead of the current directory |

This page is organised by **channel**, which is the right shape when you know which one
you want. To advance a single app without working that out first, use
[`sbx app upgrade <name>`](app#advancing-an-app): it reads what the app declares, rolls
the two channels whose unit of work is that app's own cage, and names the project-wide
ones rather than rolling them.

See also: [Upgrading toolchains](../housekeeping/upgrade) · [Provisioning](../concepts/provisioning) · [`nixpkgs`](../configuration/nixpkgs) · [`packages`](../configuration/packages).

## Behavior

`sbx upgrade` is **context-aware**: it re-resolves the source the target directory
tracks and rewrites *that* lock (a trusted project pin → the per-project lock, else the
global one). This is the only way a *channel* pin (`nixos-23.11`) advances within
itself. Lock writes are atomic (a reader sees old-or-new, never torn).

- `sbx upgrade nix` rolls the base channel, leaving the mise engine lock untouched.
- `sbx upgrade mise` rolls the mise engine + the project's `nix:` tools + `mise:`
  packages (an in-cage `mise upgrade` per home) + the declared operations' tool pool
  (host-side, under a `task pool` line), leaving `nixpkgs.lock` intact.
- `sbx upgrade flake` re-pins the project's and apps' `flake:` packages.
- `sbx upgrade provision` re-runs the bundle install steps, one cage per app, with
  `SBX_UPGRADE=1` so each step installs whatever its guard would have said. `all` runs
  the same steps without it, leaving each guard to decide, so an agent whose guard
  compares the upstream release advances there and one whose guard cannot tell does not.

### After a roll that moved the store

Three targets resolve to nix store paths, so rolling one **repoints them**: `nix` rolls
the channel, `flake` builds through `nix build`, and `mise` re-resolves the project's
`nix:` tools. An app home built against the old paths can be left holding a reference to
one that is gone: a virtualenv is the clear case, since its `bin/python` is a symlink
into the store. When such a roll replaces a revision that was locked before, the run
closes by naming the apps whose [install
steps](../configuration/bundles#the-install-step) build against those paths:

```
sbx upgrade — nix channel
  channel: nixos-unstable  (default)
  rolled forward 1111111 → 0e251e2 — the new base and tools download on the next launch.
  the store paths moved: the install steps of odysseus build against them, so an app home
  may now hold a reference to a path that is gone. Each repairs itself at its next launch
  — or now, with `sbx upgrade provision`.
```

It is a pointer, not a failure: each home repairs itself the next time the app launches,
provided the step's guard [tests what has to work rather than what has to
exist](../configuration/bundles#rolling-an-install-step-forward). Running `sbx upgrade
provision` only brings that repair forward, which is worth doing when you would rather
find a broken build now than at the next launch.

The other targets stay silent here, and on their mechanism rather than by omission:
`deb`, `appimage`, `tarball` and `binary` place their own content-hashed artifacts, so
none of them moves a path a home points into. Under `mise` it is the project's `nix:`
tools that qualify the target, and only those: the engine runs host-side out of its own
private home, and `mise:` packages are downloads inside each app's home, so neither can
leave a home pointing into the store. `all` says the same thing in its own words, naming
the channel it does not roll.

A roll that fails with `403 rate limit exceeded` and `github auth: no` is not a
misconfiguration: mise's `aqua:` backend reads the GitHub API, whose anonymous ceiling is
60 requests an hour per IP, and a cage inherits no token from your shell by design. See
[authenticating the GitHub API](../configuration/secret#worked-example-authenticating-the-github-api).

### Rolling one app

`-a, --app <name>` narrows a roll to a single app:

```
sbx upgrade provision --app trae
sbx upgrade mise --app openfox
sbx upgrade nix --app openfox
```

It applies to the two **in-cage** rolls, `provision` and `mise`, whose unit of work is
already one app's own cage; and to `nix`, because an app resolves the base channel
against a lock of its own. The remaining targets rewrite a project-wide lock host-side,
where there is no per-app unit to select, so naming an app there is a usage error rather
than a flag that quietly rolls the whole project.

Under `--app`, `mise` rolls that app's `mise:` packages and nothing else: not the engine,
not the project's `nix:` tools, not the project baseline. All three are project-wide, and
rolling them would make a per-app flag do project-wide work.

### An app's base channel

An app does not follow the global nixpkgs channel. Its base userland and its `nix:`
packages resolve against a lock of the app's own, so:

- `sbx upgrade nix` rolls the channel for the project and leaves every app where it is.
- `sbx upgrade nix --app <name>` rolls that one app, and nothing else.

The first time an app runs, its lock is seeded from the global channel's, so an app that
existed before this and an app created today both start where the base already is.
Nothing moves it afterwards but a roll naming it.

`sbx upgrade nix --app <name>` is refused in a project that **pins** `nixpkgs`. A pin
outranks an app's own lock, because an app launch also builds the project's declared
packages and those must come from the pinned revision. There is no app-only revision to
roll there, and rolling the pin under a per-app flag would be project-wide work. Run
`sbx upgrade nix` to roll the pin for the whole project, or launch the app from a
directory that does not pin.

`sbx config show --app <name>` prints the revision that app is on, which is how you see
whether it has drifted from the project's.

An app name that selects no work is refused, with which of the three ways it selected
none: no app carries that name, the app declares no command so it never launches, or it
rides a `[packages]` backend and `sbx upgrade all` is what advances it. A clean roll of
nothing would read as success.

### Targeting another project

By default a roll acts on the project in the current directory. `--project <path>` runs
the whole command against another project instead: identical to `cd <path> && sbx
upgrade`, with the same trust gate, pin, and per-project locks. The path must be an
existing directory. This matters for the per-project backends (`flake:`, `deb:`,
`appimage:`, `tarball:`, the `nix:` tools, and the in-cage `mise:` roll): an app's pins
and equipped tools live in the store and lock of the project it is launched from, so
rolling that project is how they advance. The host-global parts (the nixpkgs channel
when no project pin, and the mise engine) roll the same regardless.

## Examples

```sh
sbx upgrade                        # roll everything, current directory
sbx upgrade nix                    # just the nixpkgs channel
sbx upgrade mise                   # the mise engine + tools/packages
sbx upgrade --project ~/work/api   # roll everything for another project
sbx upgrade deb --project ~/work/api   # just its deb: packages
```

See [Upgrading toolchains](../housekeeping/upgrade) for the lock model and the
"seeded not baked" contract.
