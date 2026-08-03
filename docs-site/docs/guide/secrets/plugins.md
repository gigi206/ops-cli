# Resolver plugins and signed stores

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
scheme      = "vault"          # the scheme:// this plugin claims — unique in the registry
exec        = "bin/resolve"    # directory-relative, traversal-free path to the executable
version     = "1.2.0"          # optional, display-only
description = "Generic KV-store resolver"   # optional, display-only

[sandbox]                      # the least-privilege grant the runner gives the plugin
allow_paths = ["~/.vault-token"]   # extra host paths bound read-only
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
`0700` and is **never mounted into the cage**, so the in-cage agent: the
adversary of the threat model: cannot reach a plugin at all. While a resolver
runs, its own directory is bound **read-only** at its real path, so it cannot
rewrite itself.

### A scheme belongs to one plugin

Every install path refuses a scheme another installed plugin claims: and refuses
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

## The two reference plugins

The repository ships two working resolver plugins under
[`plugins/`](https://github.com/gigi206/ops-cli/tree/ops-v2/plugins/). They are not installed
by default — a plugin is trusted by *location*, so it only counts once it sits in
`<data>/plugins/<name>/`:

```sh
sbx plugins install plugins/pass    # then: from = "pass://github/token"
sbx plugins install plugins/vault   # then: from = "vault://secret/myapp#password"
```

| Plugin | Reference form | Resolves to | Sandbox grant |
|---|---|---|---|
| `pass` | `pass://<path>` | the **first line** of `~/.password-store/<path>.gpg` (the password by convention) | `allow_paths` on the store, `~/.gnupg` and the gpg-agent socket; **no network** |
| `vault` | `vault://<path>#<field>` | one field of a HashiCorp Vault KV secret | `allow_env` for `VAULT_ADDR`/`VAULT_TOKEN`/`VAULT_NAMESPACE`; `network = true` |

Both are also worked examples of the manifest and the execution contract above: read
their `plugin.toml` and `resolve` script when writing your own.

## Managing plugins

```
sbx plugins list              # built-in schemes + every installed plugin
                              #   (scheme, name, version, network grant, runnable?, origin)
sbx plugins info <scheme>     # a plugin's manifest, sandbox grant, and origin
                              #   (a built-in scheme is reported as such)
sbx plugins install <name|dir>  # install a bundled plugin by name, or copy a local ./dir
sbx plugins rm <name>         # remove an installed plugin
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

## Signed plugin stores

A **remote plugin store** is a git repository of resolver plugins that `sbx`
fetches on your behalf. Because you do not inspect what is fetched, authenticity
cannot come from the transport: git moves bytes and checks their *integrity*,
never their *origin*. It comes from a signature.

**The trust chain**, every link fail-closed:

1. The store's root carries a signed `catalogue.toml` (plus a detached
   `catalogue.toml.sig`) and the plugin directories it pins.
2. The store's configured **Ed25519 public key** verifies the catalogue
   signature.
3. The catalogue pins each plugin by a **`dir_digest`** (a `sha256` over the
   plugin's directory contents): the content hash the fetched directory must
   reproduce.
4. At install, the plugin's own `plugin.toml` is re-validated **exactly** as a
   locally installed one.

The fetch is **clone-always into private staging, then an atomic swap**: a store
is cloned fresh, verified, and the whole staged tree is `rename`d into place in
one step, no in-place `git pull`, so no merge/dirty-tree/partial-write state. A
failed or unverifiable fetch leaves any prior cache untouched. The verified cache
lives under the owner-only `<data>/stores/<name>/`. An accepted catalogue
revision is recorded, and a re-fetch **refuses a rollback**: a store cannot be
downgraded to an older, superseded catalogue (anti-rollback).

### Managing stores

```
sbx plugins store list [--installed]  # every configured store, plugins included
                                      #   --installed keeps only what is already in place
sbx plugins store add --name <n> --url <git-url> (--key <hex|@file> | --trust)
sbx plugins store update [name]       # re-fetch one or all; re-verify + anti-rollback + atomic swap
sbx plugins store install <store> <plugin>   # install a plugin the store lists (verifies its hash)
sbx plugins store verify <name> --key <hex|@file>   # confirm its key against one obtained elsewhere
sbx plugins store rekey <name> (--key <hex|@file> | --trust) [--yes]   # the store rotated its key
sbx plugins store info <name>         # origin URL, pinned key, accepted rev, listed plugins
sbx plugins store rm <name>           # remove a configured store
sbx plugins store publish <dir> --key <key-file> [--rev <n>]   # the signer (operator tool)
```

**Both listings expand to the plugins themselves**, installed *and* not, and
mark each entry:

| Marker | What it means |
|---|---|
| *(none)* | offered: neither its name nor its scheme is taken, so it installs |
| `[installed]` | in place, and it came from **this** store |
| `[update available: vX → vY]` | the catalogue pins a different tree, and the versions order that way |
| `[installed vX, the store lists a different build …]` | a different tree the versions cannot separate: a republish, or an unorderable pair |
| `[ahead of the store: …]` | you hold a newer version than the store lists (it rolled back) |
| `[name taken by …]` | another plugin holds the name (another store, or a local install) |
| `[scheme x:// taken by …]` | the name is free, but an installed plugin already claims that scheme |
| `[scheme x:// in conflict between …]` | several installed plugins claim it: nothing resolves it, and an install is refused all the same |
| `[installed, disabled: scheme x:// in conflict]` | in place from this store, but contesting a scheme: it resolves nothing |

`[name taken by …]` and `[scheme x:// taken by …]` are the **two stores, one
plugin name** case. The install namespace is flat: only one plugin can hold a
name, and only one can claim a scheme. So the second store's entry is *not*
installed, it is blocked, and the listing names what blocks it, as does the
refusal if you try:

```
sbx: cannot install plugin: a plugin named `kp` is already installed
(from store 'mine') — remove it first with `sbx plugins rm kp`
```

### When the store lists something else

**The digest decides, not the version string.** A catalogue pins the `sha256` of
the tree it offers, and an install records the digest of the tree it placed: so
"do I have what this store lists?" is answered exactly, by comparing two hashes
that are both already on disk. Version numbers only *phrase* the difference.

That matters for the case a version comparison cannot see at all: a **republish
under an unchanged version**. Comparing `v1.0.0` with `v1.0.0` says "up to
date"; comparing digests says the truth.

```
[installed]                                                  the tree the store lists
[update available: v1.0.0 → v1.1.0]                          a different tree, versions ordered
[installed v1.0.0, the store lists a different build of v1.0.0]   republished, same version
[ahead of the store: installed v1.1.0, listed v1.0.0]        the store rolled back
[installed v2026-08-01, the store lists v2026-08-02]         versions that cannot be ordered
```

Versions are ordered only when both are plainly ordered: dot-separated numbers
with an optional `-pre` suffix. A date, a git describe, a letter: `sbx` says the
two *differ* rather than inventing a direction. Guessing here would produce the
one wrong answer that matters: telling you that you are current when you are
not.

Upgrading is its own verb:

```
sbx plugins store update mine     # refresh the catalogue first — comparisons read the cache
sbx plugins upgrade --dry-run     # what would change
sbx plugins upgrade [name]        # every store-installed plugin, or one
```

`upgrade` runs **every gate an install runs**: the checkout must be a real
directory, its content must reproduce the signed `sha256`, and its manifest must
agree with the catalogue's advertised name and scheme: then stages the new tree
and swaps it in. **The installed plugin is kept until that succeeds**, so an
upgrade that cannot complete leaves what you had. Doing it by hand with
`sbx plugins rm` followed by a fresh install deletes first: if the install then
fails, you are left with nothing.

Every comparison reads the **cached** catalogue, so it is only as fresh as your
last `sbx plugins store update`: which is why the output says so rather than
implying a currency nothing checked.

**Adding a store requires a key.** Exactly one of `--key` or `--trust` is
required, a store with no verifying key would be unsigned, and is refused
fail-closed:

- `--key <hex|@file>` **pins a public key you obtained out of band**: the strong
  form.
- `--trust` accepts the key the store ships **on first use** (trust-on-first-use)
 , weaker; `sbx` prints the pinned key so you can compare it afterward against a
  source the store does not control.

Run `store add` with **neither** flag and sbx fetches the store into a throwaway
staging clone, shows you the key it ships, and stops without configuring
anything, so the decision is made with the key in view rather than after
pinning it:

```
this store needs a trust anchor — it ships this key:

    9cda8348d36ae7533dd58831c2574d51b19291a8af81ecc5e20c9d61a5a715ff

  a key the store ships confirms nothing: whoever controls the URL controls the key
  and the signature over the catalogue alike. Accepting it only detects a LATER key change.

  if you verified this key out of band, pin it:
    sbx plugins store add --name <n> --url <git-url> --key 9cda8348…

  to accept it unverified on first use (weaker):
    sbx plugins store add --name <n> --url <git-url> --trust
```

A store whose key was accepted rather than supplied is flagged in `store list` as
`[key not confirmed elsewhere]`, with the command that closes it on the line below;
`store info` spells the same thing out under `trust:`. What is missing is a **second source** for the key,
not verification as such: the catalogue's signature *is* checked against that key
on every fetch. But the store shipped both the key and the signature over the
catalogue, so that check cannot establish whose key it is. Once pinned, a later key
change is refused either way.

When you do obtain the key from a source the store does not control, record it:

```
sbx plugins store verify sbx-plugins --key <the key you obtained>
```

A match ends the caution; a mismatch is refused and changes nothing (the store is
not the one that key belongs to). It changes **no enforcement**: the pinned key is
untouched, so it is bookkeeping that makes the display match what you know. Without
it the caution would stand forever, and a warning that can never be resolved is one
you stop reading.

### When a store changes its signing key

`update` refuses, a pinned key is the whole point, and says so precisely, naming
both keys:

```
sbx: cannot update store 'mine': the catalogue is no longer signed by the key pinned
for this store — the key this store ships has CHANGED
  pinned: d9d8e152…
  now:    8b5c482b…
  an announced rotation is legitimate; an unannounced one is what a takeover looks
  like. Confirm the new key from a source this store does not control, then:
    sbx plugins store rekey mine --key <the new key you obtained>
```

`rekey` is the deliberate way through, and it is loud: it prints a security alert
naming both keys and what the exchange means, then asks a terminal to confirm.
Without a terminal it refuses unless `--yes` says an operator meant it, so nothing
rotates a signing identity unattended. The new key must actually sign the fetched
catalogue, the **rollback floor is carried over** (a new key does not reopen a
superseded catalogue), and `--trust`: re-accepting whatever the store now ships, leaves it flagged as unconfirmed, exactly like a first-use acceptance.

Rotating is not the same as `store rm` + `store add`: that path also ends with a new
key pinned, but silently, which is why `rekey` exists.

**`store install`** uses only the cached, verified catalogue: it re-verifies the
plugin's pinned hash and places it exactly as a local install would: no network.

**`store publish`** is the **operator/signer** counterpart of `add`, never
reachable from a cage. It walks a directory of plugins, pins each by its
`dir_digest`, and builds and signs `catalogue.toml` with `--rev` (monotonic, so
consumers refuse a rollback). The **signing key is the store's secret and never
leaves the operator's host**; the public key it prints is what consumers pin with
`add --key`.

## Two honest residuals

- **A `network = true` resolver reaches the host network, not the cage's
  allowlist.** A resolver runs host-side (outside the agent's cage), so a manifest
  that declares `network = true`, to reach a remote secret-manager / KMS / third-party-vault engine, shares
  the **host** network and is **not** behind the cage's egress allowlist. This is
  accepted because resolvers are in the TCB (first-party, or trust-installed and
  signed from a store) and an engine resolver needs real network to do its job.
  The lever is keeping the resolver *set* trusted and scoping the secret at the
  source, not bounding the resolver's own egress. A `network = false` resolver
  runs in an empty network namespace and has no such reach.

- **The default-store *registration* is deferred.** An embedded public key for a
  hosted default store (so it verifies against a baked-in key, never TOFU) needs a
  hosting URL and a long-term signing key, and is an operational step still to
  come. Until then, a store you add today uses **trust-on-first-use** (`--trust`)
  or an **out-of-band pinned key** (`--key`).

## See also

- [resolvers.md](resolvers): the built-in `env://`/`file://`/`sops://`
  schemes a plugin extends.
- [README.md](/): the never-in-cage invariant and why brokers stay
  first-party while resolvers are pluggable.
- [../cli/plugins.md](../cli/plugins): the `sbx plugins` command reference.
- [../concepts/security-model.md](../concepts/security-model) /
  [../concepts/trust.md](../concepts/trust): the TCB and trust gates a plugin
  and a store rest on.
- [https://github.com/gigi206/ops-cli/blob/ops-v2/docs/bwrap-secrets-architecture.md](https://github.com/gigi206/ops-cli/blob/ops-v2/docs/bwrap-secrets-architecture): the
  plugin model, the typed registry, and the store design.
