# Resolver plugins

The secret-source space is open-ended: any well-known secret-manager backend,
a cloud KMS, a third-party vault app, a
keyring, so `sbx` keeps the **resolver** (SOURCE) layer *pluggable*. A resolver
plugin adds a new `scheme://` that a secret's `from` reference can route to. The
**broker** (SINK) layer, which terminates TLS and injects on the wire, stays
first-party: a broker bug is a boundary breach, so it is never a plugin.

A resolver plugin still obeys the invariant: it runs **host-side, sandboxed under
bubblewrap, never in the cage**, and returns the plaintext to `sbx`'s host
process, which hands it to the broker. Because a resolver sees plaintext, it is
in the trusted computing base: which is exactly why installing one, or trusting
a store to install from, is a deliberate act.

## What a resolver plugin is

A plugin is a directory containing a `plugin.toml` manifest and an executable.
Run with a `scheme://locator` reference as its single argument, the executable
prints the secret's plaintext to stdout. `sbx` discovers installed plugins under
its owner-only data directory (`<data>/plugins/<name>/`) and builds a
`scheme → plugin` map the secret validator consults.

### The `plugin.toml` manifest

```toml
name        = "vault"          # optional; defaults to the directory name
type        = "resolver"       # required; only "resolver" is supported today
scheme      = "vault"          # the scheme:// this plugin claims; unique in the registry
exec        = "bin/resolve"    # directory-relative, traversal-free path to the executable
version     = "1.2.0"          # optional, display-only
description = "Generic KV-store resolver"   # optional, display-only

[sandbox]                      # the least-privilege grant the runner gives the plugin
programs    = ["vault"]            # host programs to locate on sbx's PATH and bind into the cage
allow_paths = ["~/.vault-token"]   # extra host paths bound read-only (data, not binaries)
allow_env   = ["VAULT_ADDR"]       # host env vars passed into the otherwise-cleared environment
network     = false                # true = reach the network; false = empty network namespace
```

- `type` must be `"resolver"`: the type is an explicit, extensible discriminator
  so a future plugin type can be added without breaking the registry.
- `scheme` cannot be a built-in (`env`, `file`, `sops`): the built-in always
  wins, and a plugin claiming one is dropped.
- `exec` is resolved against the plugin directory and must be traversal-free.
- `version`/`description` are display-only: `sbx` never compares or acts on the
  version.
- `[sandbox]` declares only the resolver-specific extra; the runner supplies the
  structural environment (a minimal `PATH`, a read-only host userland, `HOME`,
  and, under `network`, DNS/TLS files) on top of it.
- `programs` names the host tools the plugin runs, **by name, never by path**.
  For each one sbx searches its own `PATH` (the one your shell gives it), so a
  tool you can run is a tool the plugin can run, whatever installed it: a
  package manager, Homebrew, a nix profile, `~/.local/bin`. The binary is bound
  read-only under `/run/sbx-programs/`, which leads the cage's `PATH`, so the
  script simply calls it by name.
  - Where a tool lives is a property of the machine, not of the plugin. Listing
    install locations in `allow_paths` was at once too wide (a nix profile's
    binaries are symlinks into the store, so the whole store had to be bound to
    reach one of them) and too narrow (no list covers every package manager).
  - The binary is `execve`d inside the resolver's cage, on the plaintext path,
    so it is held to the check sbx applies to its own engines: a regular file,
    owned by you or by root, not world-writable. Every match on `PATH` is
    scanned, so a world-writable early entry is skipped with a warning rather
    than shadowing a legitimate one further down.
  - A declared program that resolves to nothing **fails the launch**, naming it.
    `sbx plugins info <name>` shows where each one resolves right now, so the
    answer comes before the first secret rather than during it.
- `allow_paths` is for the plugin's **data**: a token file, a database, a
  socket. `HOME` in the cage is a private tmpfs, so a tool that derives a
  location from it (a password store, a GnuPG keyring and its agent socket, a
  token file) looks where nothing exists: bind the host path and point the tool
  at it. Naming `PATH` in `allow_env` has no effect; the structural value wins.
- `allow_env` is how a resolver receives *its own* credential (`VAULT_TOKEN`, an
  age identity), so the value never travels where another user could read it:
  see [the cage's environment is not readable by other
  users](../concepts/security-model#the-cages-environment-is-not-readable-by-other-users).

### The execution contract

The runner passes the **full reference** as the executable's single argument
(`argv[1]`, e.g. `vault://secret/data/ci#token`) and reads the outcome from the
exit status and the output streams:

| Outcome | Exit | stdout | Effect |
| --- | --- | --- | --- |
| resolved | `0` | the plaintext | the secret is used (one trailing line ending is stripped) |
| absent | `0` | empty | a clean fall-through to the next source in the `from` chain |
| failed | non-zero | ignored | a hard, fail-closed error: the launch aborts, and the next source is **not** tried |

`stdin` is closed, so a resolver can never prompt for anything: everything it
needs must come from its `[sandbox]` grant.

**stderr is the diagnostic channel, and must never carry the value.** It is
folded into the error of a failed run, and relayed as an `sbx: warning:` line
when a run resolves *nothing*: so a plugin can explain a misspelled locator or
an empty field without turning a fall-through into a hard failure. A run that
returns a value stays silent, so a plugin that logs to stderr cannot echo a
plaintext back at you. What is relayed is first reduced to a single bounded line
with control characters removed, since a plugin's own text must not be able to
drive your terminal.

### The registry is trusted by location, and fail-closed

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

### A plugin edited after it was installed

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

### A scheme belongs to one plugin

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

## The reference plugins

Ready-made resolvers are published in the signed
[sbx-plugins](https://github.com/sbx-labs/sbx-plugins) store, not carried in this
repository. A plugin is trusted by *location*, so none is installed by default:
it only counts once it sits in `<data>/plugins/<name>/`.

```sh
sbx plugins store install sbx-plugins pass    # then: from = "pass://github/token"
sbx plugins store install sbx-plugins vault   # then: from = "vault://secret/myapp#password"
```

| Plugin | Reference form | Resolves to | Sandbox grant |
|---|---|---|---|
| `pass` | `pass://<path>[#<field>]` | the **first line** of `~/.password-store/<path>.gpg` (the password by convention), or a named `key: value` field below it | `programs = ["pass"]`; `allow_paths` on the store, `~/.gnupg` and the gpg-agent socket; **no network** |
| `vault` | `vault://<mount>/<path>[?version=<n>]#<field>` | one field of a HashiCorp Vault KV secret, optionally at a past version | `programs = ["vault"]`; `allow_env` for `VAULT_ADDR`/`VAULT_TOKEN`/`VAULT_NAMESPACE`; `allow_paths` on `~/.vault-token`; `network = true` |
| `openbao` | `openbao://<mount>/<path>[?version=<n>]#<field>` | the same, against an OpenBao server (`bao`) | `programs = ["bao"]`; the `BAO_*` equivalents; `network = true` |
| `infisical` | `infisical://<project>/<env>[/<folder>][?<opts>]#<secret>` | one secret of an Infisical project | `programs = ["infisical"]`; `allow_env` for the `INFISICAL_*` credentials; `network = true` |
| `keepassxc` | `keepassxc://<database>/<entry>[#<attribute>]` | one attribute of an entry in a `.kdbx` on disk, unlocked by a key file or password file beside it | `programs = ["keepassxc-cli"]`; `allow_paths` on the vault directories; **no network** |
| `keepassxc-browser` | `keepassxc-browser://<url>[#<login>]` | a credential out of the database KeePassXC currently holds **unlocked**, over its browser-integration socket | `allow_paths` on that socket and the association; **no network** |

Each is also a worked example of the manifest and the execution contract above:
read its `plugin.toml`, its `resolve` script and its README when writing your own.
They show what the structural cage forces on a resolver (declaring the host tools
it runs, and restoring the host `HOME` a tool derives its paths from), and each
reports a reference it does not hold as a clean absent, so any of them is safe to
place ahead of another source in a `from` chain.

Two conventions are worth copying. A reference is read as a URI, so the container
is the authority, the item is the path, options are the query and the selector is
the fragment. And where a `#` could belong to either side, the split follows the
side the source constrains: `sops://` and `vault://` split at the **last** `#`
because a path may hold one, while `infisical://` splits at the **first**, since
an Infisical secret name may hold a `#` and the project, environment and folder
before it cannot.

If a launch refuses because a declared program is not on `PATH`, the tool the
plugin runs is not installed, or not where the shell that starts sbx looks for
it. `sbx plugins info <name>` resolves each declared program the way a launch
would and shows the answer.

## Managing plugins

```
sbx plugins list              # built-in schemes + every installed plugin
                              #   (scheme, name, version, network grant, runnable?, origin)
sbx plugins info <scheme>     # a plugin's manifest, sandbox grant, and origin
                              #   (a built-in scheme is reported as such)
sbx plugins install <name|dir>  # install a bundled plugin by name, or copy a local ./dir
sbx plugins rm <name>...      # remove installed plugins (several names in one call)
sbx plugins verify [name]     # re-hash installed plugins against the digest recorded at install
sbx plugins upgrade [name] [--dry-run]   # replace with what the store lists now (digest-decided)
```

Installing is **a deliberate user act**: an agent inside the cage cannot run it.
The staged copy is validated exactly as the launcher will validate it and
refused, fail-closed, on any flaw. `sbx plugins` is host-level: it reads the data
directory, not a project's config.

### Where a plugin came from

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

## Installing from a signed store

The other way a plugin arrives is a **signed store**: a git repository whose catalogue
is verified against a pinned Ed25519 key, with anti-rollback on the revision. Everything
on this page still applies to a plugin that came from one, since a store install
re-validates the manifest exactly as a local install does; what a store adds is where
the tree came from and how its authenticity is established. See
[Signed plugin stores](stores).

## An honest residual: a networked resolver reaches the host network

- **A `network = true` resolver reaches the host network, not the cage's
  allowlist.** A resolver runs host-side (outside the agent's cage), so a manifest
  that declares `network = true`, to reach a remote secret-manager / KMS / third-party-vault engine, shares
  the **host** network and is **not** behind the cage's egress allowlist. This is
  accepted because resolvers are in the TCB (first-party, or trust-installed and
  signed from a store) and an engine resolver needs real network to do its job.
  The lever is keeping the resolver *set* trusted and scoping the secret at the
  source, not bounding the resolver's own egress. A `network = false` resolver
  runs in an empty network namespace and has no such reach.

## See also

- [Resolvers](resolvers): the built-in `env://`/`file://`/`sops://`
  schemes a plugin extends.
- [Secrets architecture](../secrets/): the never-in-cage invariant and why brokers stay
  first-party while resolvers are pluggable.
- [Signed plugin stores](stores): distributing and installing plugins from a
  verified remote.
- [`sbx plugins`](../cli/plugins): the `sbx plugins` command reference.
- [Security model](../concepts/security-model) /
  [The trust gate](../concepts/trust): the TCB and trust gates a plugin
  rests on.
  plugin model, the typed registry, and the store design.
