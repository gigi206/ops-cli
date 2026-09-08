---
description: "List, export, import and remove the reusable tool bundles an app names with `use`."
---

# `sbx bundle`

```
sbx bundle [<name>...] [--json]
sbx bundle export [<name>...] [-o|--out <file>] [--out-dir <dir>]
sbx bundle import <file> [--as <name>] [-f|--force]
sbx bundle rm <name>...
```

The reusable-tool-bundle surface. Host-side: no launch, no nix, and read-only except
`import`.

A bundle is everything one tool needs to be installed and to reach its own
services: its `packages`, the `env` it reads, its `allow`/`deny`/`mute` egress rules and
its `[secret]` credential. An app names one with `use = ["<name>"]`. Bundles are
**global-only**, so these commands have no scope flag: they always read the global
config.

See also: [Tool bundles](../configuration/bundles) · [Apps](../configuration/apps) · [`sbx net groups`](net#sbx-net-groups).

## Subcommands

| Subcommand | Purpose |
|---|---|
| [(none)](#sbx-bundle-1) | list every bundle, or show named ones in full |
| [`export`](#sbx-bundle-export) | write bundles out as portable files |
| [`import`](#sbx-bundle-import) | file a bundle under `bundles/<name>.toml` |
| [`rm`](#sbx-bundle-rm) | delete `bundles/<name>.toml` |

## `sbx bundle`

```sh
sbx bundle                 # every bundle, with what it contributes
sbx bundle claude-code     # one bundle, in full
sbx bundle --json
```

With no name, one line per bundle summarising what using it would pull in: packages,
environment entries, egress rules, credentials: so the listing answers "how much does
this bring?" without printing everything.

With names, each bundle's contents print in full: its packages, the **keys** of its
environment, each egress rule, and each credential's destination host.

Environment **values** are not printed here: the listing answers "what does using this
bring in?", not "what is in it". That is not redaction: `sbx bundle export` writes the
values in full, because the export is the portable artifact. A bundle holds no plaintext
credential in any case, a `[secret]` names a *source* (`env://`, `sops://`), and the
real value is read on the host at launch and never enters the cage.

A name that matches no bundle is an error naming what *is* declared, never a blank
success. `export` and `import` are reserved subcommand verbs, so a bundle named
`export` is listable and usable in a `use` list but not resolvable by bare name here.

## `sbx bundle export`

```sh
sbx bundle export claude-code            # one bundle, to stdout
sbx bundle export claude-code -o cc.toml # to a file
sbx bundle export --out-dir ./bundles    # every bundle, one file each
```

Writes each bundle in the portable form `import` reads: its fields at the top level,
its name carried by the file. Stdout is the default for a single bundle: composable and
clobber-safe. A file holds one bundle, so exporting several needs `--out-dir <dir>`.
Source comments are not carried (a bundle is data). The inverse of `import`.

## `sbx bundle import`

```sh
sbx bundle import claude-code.toml
sbx bundle import frag.toml --as claude-code
sbx bundle import claude-code.toml --force
```

Copies the file into `bundles/<name>.toml`, where the loader reads it. The name comes
from the file: its own stem, or `--as <name>`. The bytes are copied verbatim, so the
author's comments survive. Bundles are global-only, and that directory is trusted by its
location: the deliberate command **is** the consent (an agent inside the cage cannot run
it), so there is no prompt.

A name that already exists is refused unless `--force`, and nothing is written when it
is. An app *profile* handed here is refused too: a bundle carries no `cmd`, so the wrong
file is named rather than filed as a toolless bundle.

A forced overwrite is the one import that can lose work, since a declared bundle may carry
an entry added by hand on this machine. So it keeps the file it replaced beside it as
`<name>.toml.replaced`, and names both sides of the change: what the incoming bundle no
longer declares, and what it declares on top (a widening is as worth reading as a loss).

```
sbx: warning: replaced bundle `demo`, which declared 1 line the new one does not:
     `allow = ["{GET} https://example.com", "{GET} https://local.example.org"]`, and
     declares 1 line the previous one did not: `allow = ["{GET} https://example.com"]`
     — the previous fragment is kept at ~/.config/sbx/bundles/demo.toml.replaced, so a
     per-machine entry can be read back and re-imported
```

Putting the entry back is `sbx bundle import --force ~/.config/sbx/bundles/demo.toml.replaced`.
A re-import that changes nothing keeps no copy and reports no loss.

Because an import is the one moment you consciously take in another author's data, a
bundle that would grant **egress, a credential or an install step** is named right after
the import:

```
imported 1 bundle(s) into ~/.config/sbx/sbx.toml — added claude-code
sbx: warning: an app that names these gains their egress, credentials and install steps:
     claude-code (6 egress rule(s), 1 credential(s)) — inspect with `sbx bundle <name>`
```

Inspect it before an app uses it. An imported bundle is **inert** until an app names it
in `use`.

An app *profile* is a different artifact: import that with
[`sbx app import`](app); the error message says so if you mix them up.

## `sbx bundle rm`

```
sbx bundle rm <name>...
```

Delete `bundles/<name>.toml`, the removal half of the cycle `import` opens. A bundle is one entry
in one file named by that file, so removing the bundle is removing the file, and nothing is left
behind to reclaim.

```sh
sbx bundle rm demo
sbx bundle rm demo other      # several at once
```

There is no `--purge`/`--gc` pair here, unlike [`sbx app rm`](app#sbx-app-rm), and the difference
is structural. An app owns runtime state: a home, and the tools its backends installed into it. A
bundle owns none: it is a declaration that contributes packages, environment and rules to the apps
that name it. Whatever those apps provisioned belongs to **them**, and is reclaimed with
[`sbx app rm --purge`](app#sbx-app-rm) or [`sbx gc`](gc).

An app profile that still names the bundle in `use` is **reported, not refused**. The config left
behind is valid, and a launch already warns about a `use` naming a bundle that is not declared;
saying it at the moment of removal says it while the decision can still be changed:

```
removed bundle 'demo'
sbx: warning: app profile(s) still name `demo` in `use`: claude-code
```

Only the global app profiles are searched. A project's own `[app.<name>] use` is not, since there
is no register of every project on the machine.

## Examples

The full round trip: inspect what a bundle would bring in, use it from an app, then
move it to another machine.

```sh
sbx bundle                             # what is declared, and how much each brings
sbx bundle claude-code                 # one in full: packages, env keys, egress, credentials
sbx bundle --json | jq -r '.bundles[].name'
```

A bundle is inert until an app names it, and the naming is what grants its egress and
credentials:

```toml
# ~/.config/sbx/sbx.toml
[app.my-agent]
cmd = ["claude"]
use = ["claude-code"]                  # folds in its packages, env, egress rules, secret
```

```sh
sbx net rules -a my-agent              # the egress the bundle contributed, now effective
sbx secret list -a my-agent            # …and the credentials it carries
sbx app run my-agent
```

Moving it:

```sh
sbx bundle export claude-code --out claude-code.toml   # on the source machine
sbx bundle import claude-code.toml                     # on the target
sbx bundle import claude-code.toml --force             # …overwriting an existing name
sbx bundle claude-code                                 # inspect before an app uses it
```

An import that would grant egress or a credential says so in its output; that warning
is the moment to run `sbx bundle <name>` before wiring it into an app.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | the write failed, there was nothing to export, or `rm` found no such bundle |
| 2 | usage error, an unknown bundle name, an invalid name, or a file that is not a bundle |
