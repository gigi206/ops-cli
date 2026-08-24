---
description: "A git repository of plugins verified against a pinned Ed25519 key, with anti-rollback on the revision."
---

# Signed plugin stores

This page covers configuring a store, installing from it, and what happens when it
changes; for the plugins themselves, and for installing one from a local directory, see
[Managing plugins](managing).

See also: [Plugins](./) · [`sbx plugins store`](../cli/plugins#stores) ·
[The resolver type](resolvers) · [The trust gate](../concepts/trust).

A **remote plugin store** is a git repository of plugins that `sbx` fetches on your
behalf. One store serves **every kind** ([resolvers](resolvers),
[brokers](broker) and [signers](signer)), under one key
and one catalogue: the store is not what fences a broker, since installing one grants
nothing until a global [`[broker.<name>] socket`](../configuration/broker) binds it to a
host resource. A second store would ask you to pin a second key where nothing is decided. Because you do not inspect what is fetched, authenticity
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

## Managing stores

```
sbx plugins store list [<name>] [--installed]  # configured stores, plugins included
                                      #   <name> restricts it to one store
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

## When the store lists something else

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
sbx plugins store update mine     # refresh the catalogue first: comparisons read the cache
sbx plugins upgrade --dry-run     # what would change
sbx plugins upgrade [name]        # every store-installed plugin, or one
```

`upgrade` syncs each plugin to what its store **lists**, which is not always forward: a
store that rolled back lists an older build, and the plugin follows it. That move is
reported as `downgraded` rather than `upgraded`, with the versions it moved between, so a
walk back to an earlier version is visible in the output instead of reading like progress.

`upgrade` runs **every gate an install runs**: the checkout must be a real
directory, its content must reproduce the signed `sha256`, and its manifest must
agree with the catalogue's advertised name, **kind** and scheme: then stages the new tree
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
- `--trust` accepts the key the store ships **on first use** (trust-on-first-use),
  weaker; `sbx` prints the pinned key so you can compare it afterward against a
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

## When a store changes its signing key

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

## An honest residual: the default store is not registered yet

An embedded public key for a hosted default store (so it verifies against a baked-in
key, never TOFU) needs a hosting URL and a long-term signing key, and is an operational
step still to come. Until then, a store you add today uses **trust-on-first-use**
(`--trust`) or an **out-of-band pinned key** (`--key`).

## See also

- [Plugins](./): what a store distributes, and the manifest each
  plugin carries.
- [`sbx plugins`](../cli/plugins): the command reference, including every `store`
  subcommand.
- [Security model](../concepts/security-model) /
  [The trust gate](../concepts/trust): the TCB and trust gates a store rests on.
  plugin model, the typed registry, and the store design.
