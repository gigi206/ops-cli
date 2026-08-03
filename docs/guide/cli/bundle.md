# `sbx bundle`

```
sbx bundle [<name>...] [--json]
sbx bundle export [<name>...] [-o|--out <file>]
sbx bundle import <file> [-f|--force]
```

The reusable-tool-bundle surface. Host-side: no launch, no nix, and read-only except
`import`.

A `[bundle.<name>]` is everything one tool needs to be installed and to reach its own
services: its `packages`, the `env` it reads, its `allow`/`deny`/`mute` egress rules and
its `[secret]` credential. An app names one with `use = ["<name>"]`. Bundles are
**global-only**, so these commands have no scope flag: they always read the global
config.

See also: [`[bundle.<name>]` configuration](../configuration/bundles.md) · [Apps](../configuration/apps.md) · [`sbx net groups`](net.md#sbx-net-groups).

## Subcommands

| Subcommand | Purpose |
|---|---|
| [(none)](#sbx-bundle) | list every bundle, or show named ones in full |
| [`export`](#sbx-bundle-export) | write bundles as a portable TOML fragment |
| [`import`](#sbx-bundle-import) | merge a fragment into the global config |

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
sbx bundle export > bundles.toml       # every bundle, to stdout
sbx bundle export claude-code codex    # only the named ones
sbx bundle export --out bundles.toml
```

Writes a portable `[bundle.<name>]` TOML fragment. Stdout is the default: composable
and clobber-safe. Source comments are not carried (a bundle is data). The inverse of
`import`.

## `sbx bundle import`

```sh
sbx bundle import bundles.toml
sbx bundle import bundles.toml --force
```

Merges the fragment's bundles into the global config, preserving every existing bundle
and comment. Bundles are global-only, so the target is always the global config, which
is trusted by its location: the deliberate command **is** the consent (an agent inside
the cage cannot run it), so there is no prompt.

A name that already exists is refused unless `--force`, and the merge is
**all-or-nothing**: a refused import writes nothing.

Because an import is the one moment you consciously take in another author's data, a
bundle that would grant **egress or a credential** is named right after the import:

```
imported 1 bundle(s) into ~/.config/sbx/sbx.toml — added claude-code
sbx: warning: an app that names these gains their egress and credentials:
     claude-code (6 egress rule(s), 1 credential(s)) — inspect with `sbx bundle <name>`
```

Inspect it before an app uses it. An imported bundle is **inert** until an app names it
in `use`.

An app *profile* is a different artifact: import that with
[`sbx app import`](app.md); the error message says so if you mix them up.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | the write failed, or there was nothing to export |
| 2 | usage error, an unknown bundle name, an invalid name in a fragment, or a file that is not a bundle fragment |
