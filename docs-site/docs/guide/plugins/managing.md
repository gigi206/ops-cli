---
description: "Installing, the registry's trust-by-location, drift detection, scheme conflicts, and a plugin's own tests."
---

# Managing plugins

Every verb below is host-level and deliberate: it reads the owner-only data directory,
not a project's config, and an agent inside a cage can run none of it.

## The verbs

```
sbx plugins list              # built-in schemes + every installed plugin
                              #   (scheme, name, version, network grant, runnable?, origin)
sbx plugins info <scheme|name>  # a plugin's manifest, sandbox grant, and origin
                              #   (a resolver by its scheme, a broker by its name;
                              #    a built-in scheme is reported as such)
sbx plugins install <name|dir>  # install a bundled plugin by name, or copy a local ./dir
sbx plugins rm <name>...      # remove installed plugins (several names in one call)
sbx plugins verify [name]     # re-hash installed plugins against the digest recorded at install
sbx plugins upgrade [name] [--dry-run]   # replace with what the store lists now (digest-decided)
```

Installing is **a deliberate user act**: an agent inside the cage cannot run it.
The staged copy is validated exactly as the launcher will validate it and
refused, fail-closed, on any flaw. `sbx plugins` is host-level: it reads the data
directory, not a project's config.

## Where a plugin came from

A manifest is byte-identical whatever the source, so the install records the
plugin's **origin** and every listing reports it:

```
installed resolver plugins:
  kp://  kp  v1.0.0  no-network
    Resolve a secret from a local database
    from: store 'mine' (https://example.invalid/plugins.git)
```

The origin is either a local directory (by path) or a named store (with its URL, so
the answer survives `store rm`). A plugin installed before origins were recorded, or placed by hand: reads as **unknown**; reinstalling it records the source.

The record lives in `<data>/plugins/.origins/<name>.toml`, **outside** the
plugin's own directory: a store pins a plugin by a hash over its whole tree, so a
file added inside would put every installed plugin permanently out of agreement
with what was signed. It is display-only provenance and never a trust input, what makes an installed plugin trusted is the owner-only data directory it sits
in.

## The registry is trusted by location, and fail-closed

Plugins live under the owner-only (`0700`) data directory, which a project (which
writes only the project directory) cannot plant into: so the registry is
**trusted by location**. Loading a plugin *neither runs nor provisions* anything;
before it execs a resolver, the runner re-checks the executable is a regular file
owned by you and not writable by group or other (stricter than the config-file
safety gate, because this is code about to run in the TCB).

Loading is **infallible and fail-closed**. A malformed manifest, an unsupported
type or a reserved or ill-formed scheme produces a warning and skips that plugin, never a failed launch, and never a silently-honored bad plugin. **Two plugins
claiming one scheme** drops *both* (never an arbitrary winner) and is reported
rather than merely warned about: see below. A project's `.sbx.toml` may only
*reference* a scheme, and only if the project is trusted (an untrusted project's
whole `[secret]` section is dropped before any scheme is looked up).

## A plugin edited after it was installed

Every install records the **digest of the tree it placed** (in
`<data>/plugins/.origins/<name>.toml`, alongside the origin). Three paths compare
against it:

```
sbx plugins verify [name]     # re-hash one plugin, or every one; non-zero if a tree changed
sbx plugins list              # a changed plugin is marked [modified since install]
sbx plugins info <scheme>     # an `integrity:` line, in all four states
```

The digest covers exactly what git records: the set of regular files, their
paths, the executable bit, and their bytes: so it catches an edited resolver
script **and** an edited `plugin.toml`. The manifest is the sharper of the two:
it carries the `[sandbox]` grant, so editing it in place widens what the plugin
may reach, and the registry would otherwise honor that without a word.

Four states, deliberately distinct:

| State | What it means |
|---|---|
| `unchanged since install` | the tree hashes to what was recorded |
| `MODIFIED since install` | it does not: reinstall to restore a known tree |
| `no digest recorded` | installed before sbx recorded digests, or **placed by hand**, nothing was attested, which is not the same as "unchanged" |
| `cannot be hashed` | a symlink or unreadable file appeared in the tree, which is itself a change |

`verify` exits non-zero only for the two that say something is wrong. An
unattested plugin is reported plainly and does not fail the command: the fix is
different (reinstall, which records a digest).

> **This is drift detection, not a security control.** The record lives in the
> **same owner-only directory** as the plugin, so anything able to rewrite the
> plugin can rewrite the record. It is worthless against an adversary and never
> claimed otherwise; what it catches is the accident: a plugin edited in place
> to debug it and forgotten, a careless third-party process. For that reason it
> is a verb you run and a marker you read, **never** a gate on the launch path:
> hashing every plugin at every launch would buy no safety and cost real time.

The actual boundary is elsewhere, and it is the bind layout: `<data>/plugins` is
`0700` and is **never mounted into the cage**, so the in-cage agent (the adversary of
the threat model) cannot reach a plugin at all. While a resolver
runs, its own directory is bound **read-only** at its real path, so it cannot
rewrite itself.

## A scheme belongs to one plugin

Every install path refuses a scheme another installed plugin claims, and refuses
one that is *already* contested, so an install can never add to the mess:

```
sbx: cannot install plugin: scheme `vault://` is claimed by more than one
installed plugin (`vault-a`, `vault-b`) — they are all disabled; remove all but
one with `sbx plugins rm <name>` first
```

So the only route to a conflict is placing a plugin directory under
`<data>/plugins/` **by hand**. When that happens the scheme resolves to *nothing*
and **every** claimant is disabled: never an arbitrary winner, and never a
silent one. It is shown, not just warned about:

```
$ sbx plugins list
built-in schemes (always resolve, never a plugin): env, file, sops
installed resolver plugins: (none resolving — see the scheme conflicts below)
scheme conflicts (every claimant below is disabled):
  vault://  claimed by 2 plugins
    vault-a  from: local directory /home/u/src/vault-a
    vault-b  from: unknown (installed before sbx recorded plugin origins, or placed by hand)
(a scheme must be unique: remove all but one with sbx plugins rm <name>)

$ sbx plugins info vault
… the same block, for that scheme only …
sbx: the scheme 'vault' is claimed by 2 installed plugins and resolves to nothing
until exactly one remains
```

`info` exits non-zero: the scheme is unusable, and a secret referencing it fails
the config with `unknown secret resolver scheme`. Removing all but one claimant
(`sbx plugins rm <name>`: the **directory** name, which is what the conflict
lists) restores it immediately.

## Installing from a signed store

The other way a plugin arrives is a **signed store**: a git repository whose catalogue
is verified against a pinned Ed25519 key, with anti-rollback on the revision. Everything
in this section still applies to a plugin that came from one, since a store install
re-validates the manifest exactly as a local install does; what a store adds is where
the tree came from and how its authenticity is established. See
[Signed plugin stores](stores).

## Running a plugin's tests

A plugin may ship its own behaviour tests, as an executable `tests/run` inside its
directory. They are covered by the hash a store pins the plugin with, so they arrive
with it and are checked with it: what you run is the copy you installed, not a
checkout you would have to trust separately.

```sh
"$(sbx plugins info <name> | sed -n 's/^  exec: *//p' | xargs dirname)/tests/run"
```

sbx neither runs them nor requires them, and a plugin without a `tests/` directory
installs and resolves exactly the same. What they are worth is evidence: a resolver
decides whether a missing credential is *absent* (your chain falls through to a
weaker source) or *failed* (the launch aborts), and getting that line wrong is
silent. A suite that pins it lets you check the distinction rather than read the
code for it.

Expect a suite to exit **77** when a tool it needs is not installed, rather than
reporting a pass it never ran, and expect it to leave the plugin's own directory
untouched: a file written there would put the tree out of agreement with what was
signed, and `sbx plugins list` would report the plugin as MODIFIED.

If you write a plugin, keep its tests inside its directory for the same reason, and
do not rebuild sbx's sandbox in them. A hand-written cage is a second copy of what
sbx builds, and it stops testing what ships as soon as the two drift. Stand in for
the service a resolver talks to, not for the tool it runs.

## See also

- [`sbx plugins`](../cli/plugins): every flag of the verbs above.
- [Signed plugin stores](stores): where `sbx plugins store install` installs from.
