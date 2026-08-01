# Resolver plugins and signed stores

The secret-source space is open-ended — Vault, a cloud KMS, 1Password, a
keyring — so `sbx` keeps the **resolver** (SOURCE) layer *pluggable*. A resolver
plugin adds a new `scheme://` that a secret's `from` reference can route to. The
**broker** (SINK) layer, which terminates TLS and injects on the wire, stays
first-party — a broker bug is a boundary breach, so it is never a plugin.

A resolver plugin still obeys the invariant: it runs **host-side, sandboxed under
bubblewrap, never in the cage**, and returns the plaintext to `sbx`'s host
process, which hands it to the broker. Because a resolver sees plaintext, it is
in the trusted computing base — which is exactly why installing one, or trusting
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
description = "HashiCorp Vault resolver"   # optional, display-only

[sandbox]                      # the least-privilege grant the runner gives the plugin
allow_paths = ["~/.vault-token"]   # extra host paths bound read-only
allow_env   = ["VAULT_ADDR"]       # host env vars passed into the otherwise-cleared environment
network     = false                # true = reach the network; false = empty network namespace
```

- `type` must be `"resolver"` — the type is an explicit, extensible discriminator
  so a future plugin type can be added without breaking the registry.
- `scheme` cannot be a built-in (`env`, `file`, `sops`) — the built-in always
  wins, and a plugin claiming one is dropped.
- `exec` is resolved against the plugin directory and must be traversal-free.
- `version`/`description` are display-only — `sbx` never compares or acts on the
  version.
- `[sandbox]` declares only the resolver-specific extra; the runner supplies the
  structural environment (a minimal `PATH`, a read-only host userland, `HOME`,
  and — under `network` — DNS/TLS files) on top of it.
- `allow_env` is how a resolver receives *its own* credential (`VAULT_TOKEN`, an
  age identity), so the value never travels where another user could read it:
  see [the cage's environment is not readable by other
  users](../concepts/security-model.md#the-cages-environment-is-not-readable-by-other-users).

### The execution contract

The runner passes the **full reference** as the executable's single argument
(`argv[1]` — e.g. `vault://secret/data/ci#token`) and reads the outcome from the
exit status and the output streams:

| Outcome | Exit | stdout | Effect |
| --- | --- | --- | --- |
| resolved | `0` | the plaintext | the secret is used (one trailing line ending is stripped) |
| absent | `0` | empty | a clean fall-through to the next source in the `from` chain |
| failed | non-zero | ignored | a hard, fail-closed error — the launch aborts, and the next source is **not** tried |

`stdin` is closed, so a resolver can never prompt for anything: everything it
needs must come from its `[sandbox]` grant.

**stderr is the diagnostic channel, and must never carry the value.** It is
folded into the error of a failed run, and relayed as an `sbx: warning:` line
when a run resolves *nothing* — so a plugin can explain a misspelled locator or
an empty field without turning a fall-through into a hard failure. A run that
returns a value stays silent, so a plugin that logs to stderr cannot echo a
plaintext back at you. What is relayed is first reduced to a single bounded line
with control characters removed, since a plugin's own text must not be able to
drive your terminal.

### The registry is trusted by location, and fail-closed

Plugins live under the owner-only (`0700`) data directory, which a project (which
writes only the project directory) cannot plant into — so the registry is
**trusted by location**. Loading a plugin *neither runs nor provisions* anything;
before it execs a resolver, the runner re-checks the executable is a regular file
owned by you and not writable by group or other (stricter than the config-file
safety gate, because this is code about to run in the TCB).

Loading is **infallible and fail-closed**. A malformed manifest, an unsupported
type, a reserved or ill-formed scheme, or **two plugins claiming one scheme**
(both are dropped — the scheme is ambiguous, never an arbitrary winner) produces
a warning and skips the offending plugin — never a failed launch, and never a
silently-honored bad plugin. A project's `.sbx.toml` may only *reference* a
scheme, and only if the project is trusted (an untrusted project's whole
`[secret]` section is dropped before any scheme is looked up).

## Managing plugins

```
sbx plugins list              # built-in schemes + every installed plugin
                              #   (scheme, name, version, network grant, runnable?)
sbx plugins info <scheme>     # a plugin's manifest and sandbox grant
                              #   (a built-in scheme is reported as such)
sbx plugins install <name|dir>  # install a bundled plugin by name, or copy a local ./dir
sbx plugins rm <name>         # remove an installed plugin
```

Installing is **a deliberate user act** — an agent inside the cage cannot run it.
The staged copy is validated exactly as the launcher will validate it and
refused, fail-closed, on any flaw. `sbx plugins` is host-level: it reads the data
directory, not a project's config.

## Signed plugin stores

A **remote plugin store** is a git repository of resolver plugins that `sbx`
fetches on your behalf. Because you do not inspect what is fetched, authenticity
cannot come from the transport — git moves bytes and checks their *integrity*,
never their *origin*. It comes from a signature.

**The trust chain**, every link fail-closed:

1. The store's root carries a signed `catalogue.toml` (plus a detached
   `catalogue.toml.sig`) and the plugin directories it pins.
2. The store's configured **Ed25519 public key** verifies the catalogue
   signature.
3. The catalogue pins each plugin by a **`dir_digest`** (a `sha256` over the
   plugin's directory contents) — the content hash the fetched directory must
   reproduce.
4. At install, the plugin's own `plugin.toml` is re-validated **exactly** as a
   locally installed one.

The fetch is **clone-always into private staging, then an atomic swap**: a store
is cloned fresh, verified, and the whole staged tree is `rename`d into place in
one step — no in-place `git pull`, so no merge/dirty-tree/partial-write state. A
failed or unverifiable fetch leaves any prior cache untouched. The verified cache
lives under the owner-only `<data>/stores/<name>/`. An accepted catalogue
revision is recorded, and a re-fetch **refuses a rollback** — a store cannot be
downgraded to an older, superseded catalogue (anti-rollback).

### Managing stores

```
sbx plugins store list                # the built-in store + configured stores (rev, plugin count)
sbx plugins store add --name <n> --url <git-url> (--key <hex|@file> | --trust)
sbx plugins store update [name]       # re-fetch one or all; re-verify + anti-rollback + atomic swap
sbx plugins store install <store> <plugin>   # install a plugin the store lists (verifies its hash)
sbx plugins store info <name>         # origin URL, pinned key, accepted rev, listed plugins
sbx plugins store rm <name>           # remove a configured store
sbx plugins store publish <dir> --key <key-file> [--rev <n>]   # the signer (operator tool)
```

**Adding a store requires a key.** Exactly one of `--key` or `--trust` is
required — a store with no verifying key would be unsigned, and is refused
fail-closed:

- `--key <hex|@file>` **pins a public key you obtained out of band** — the strong
  form.
- `--trust` accepts the key the store ships **on first use** (trust-on-first-use)
  — weaker; `sbx` prints the pinned key's fingerprint so you can verify it out of
  band afterward.

**`store install`** uses only the cached, verified catalogue: it re-verifies the
plugin's pinned hash and places it exactly as a local install would — no network.

**`store publish`** is the **operator/signer** counterpart of `add`, never
reachable from a cage. It walks a directory of plugins, pins each by its
`dir_digest`, and builds and signs `catalogue.toml` with `--rev` (monotonic, so
consumers refuse a rollback). The **signing key is the store's secret and never
leaves the operator's host**; the public key it prints is what consumers pin with
`add --key`.

## Two honest residuals

- **A `network = true` resolver reaches the host network, not the cage's
  allowlist.** A resolver runs host-side (outside the agent's cage), so a manifest
  that declares `network = true` — to reach a Vault/KMS/1Password engine — shares
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

- [resolvers.md](resolvers.md) — the built-in `env://`/`file://`/`sops://`
  schemes a plugin extends.
- [README.md](README.md) — the never-in-cage invariant and why brokers stay
  first-party while resolvers are pluggable.
- [../cli/plugins.md](../cli/plugins.md) — the `sbx plugins` command reference.
- [../concepts/security-model.md](../concepts/security-model.md) /
  [../concepts/trust.md](../concepts/trust.md) — the TCB and trust gates a plugin
  and a store rest on.
- [../../bwrap-secrets-architecture.md](../../bwrap-secrets-architecture.md) — the
  plugin model, the typed registry, and the store design.
