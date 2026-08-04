# Resolvers: the SOURCE layer

A **resolver** answers one question: *where does this secret's plaintext come
from?* It turns a reference, `scheme://locator`, into the credential's bytes,
**on the host, before the cage starts**. The resolved value is handed to the
[broker](injection), which injects it on the wire; it is never written into a
cage file, a cage environment variable, or a cage bind.

This page covers the three built-in resolver schemes and the two ways to name a
source: the verbose `from` ref and the terse `key` form expanded through
`[secret.defaults]`. Additional schemes come from [resolver
plugins](plugins).

## Built-in schemes

`sbx` implements three resolvers itself. A plugin can never claim these names: the built-in always wins.

### `env://`: a host environment variable

```toml
[secret."api.github.com"]
from   = "env://GITHUB_TOKEN"
header = "Authorization"
type   = "bearer"
```

`env://VAR` reads the named variable **from `sbx`'s host process environment** at
launch. The value is read host-side and never exported into the cage: the cage's
environment is built separately and does not inherit it. Use this for a token
your shell or CI runner already holds.

### `file://`: a host file

```toml
[secret."registry.example.com"]
from   = "file:///run/secrets/registry-token"
header = "Authorization"
type   = "bearer"
```

`file:///absolute/path` reads the file's contents **host-side** at launch. The
path is **never bound into the cage**: only the resolved value reaches the
broker, on the host. This matters: the cage cannot read the file, so even a
compromised agent cannot exfiltrate it directly; it can only ask the proxy to use
the resulting capability toward the one allowed host.

### `sops://`: a SOPS-encrypted store

```toml
[secret."api.github.com"]
from   = "sops://secrets.enc.yaml#github.token"
header = "Authorization"
type   = "bearer"
```

`sops://<file>#<key>` decrypts an encrypted file host-side and extracts one key.
The decryption uses the host-side age/KMS key material: which stays on the host,
outside the cage. This is the clean demonstration that the SOURCE layer is
distinct from the SINK: the same first-party HTTP-header broker consumes a value
that a completely different mechanism produced. The encrypted file the agent
*could* read (if it were bound, which it is not) would be useless ciphertext
anyway, because no decryption key is in the cage.

## Two ways to name a source

Every secret entry names its source in exactly one of two ways: `from` or
`key`: never both.

### Verbose: `from`

`from` is a full `scheme://locator` reference:

```toml
[secret."api.github.com"]
from   = "sops://secrets.enc.yaml#github.token"
header = "Authorization"
type   = "bearer"
```

### Terse: `key` + `[secret.defaults]`

When several secrets share a resolver setup, declare it once under
`[secret.defaults]` and let each entry name only its `key`:

```toml
[secret.defaults]
order  = ["env", "sops"]           # try env first, then sops
header = "Authorization"           # default header for every entry
type   = "bearer"                  # default type for every entry
[secret.defaults.sops]
file   = "secrets/prod.yaml"       # where a terse sops key reads from
[secret.defaults.env]
case   = "upper"                   # transform the key into a variable name
[secret.defaults.file]
dir    = "/run/secrets"            # base dir a terse file key reads from

# a terse entry names only its key
[secret."api.npmjs.org"]
key    = "npm_token"
```

A terse `key` is expanded through the resolver **order**, and each resolver's
per-scheme binding says how the bare key becomes a locator:

| Resolver | Binding | A terse key `k` expands to |
|---|---|---|
| `env` | `[secret.defaults.env] case = "upper" \| "lower" \| "asis"` | `env://<case(k)>` |
| `sops` | `[secret.defaults.sops] file = "…"` | `sops://<file>#k` |
| `file` | `[secret.defaults.file] dir = "…"` | `file://<dir>/k` |

`case` defaults to `"asis"` (the key is used unchanged): set `"upper"` or
`"lower"` to normalize it into a conventional variable name.

The `header`/`type` defaults under `[secret.defaults]` apply to **every** entry,
verbose or terse, a `from` entry that omits `header` inherits the default just
as a `key` entry does. Only the resolver order and per-scheme bindings are
terse-only. A per-entry `header`/`type` always overrides the default.

## Fallback chains

Two forms let a resolution try several sources in order and take the first that
succeeds: a fallback chain, not a merge.

**Explicit chain**: an array `from`:

```toml
[secret."api.github.com"]
from   = ["env://GH_TOKEN", "sops://secrets.enc.yaml#github.token"]
header = "Authorization"
type   = "bearer"
```

`sbx` tries `env://GH_TOKEN`; if that variable is unset it falls back to the SOPS
key. The first ref that resolves at launch wins; the rest are fallbacks. This is
how a developer's local `env://` overrides a shared `sops://` default without
editing the file.

**Terse chain**: the default `order`: a bare `key` walks the `order` list
(`["env", "sops"]` above) using each resolver's binding, first-that-resolves
wins.

**Pin one resolver**: append `@resolver` to a terse key to bypass the order:

```toml
[secret."api.npmjs.org"]
key    = "npm_token@sops"          # ignore `order`, use sops only
```

You can pin a shorter chain too: `key@resolver,resolver` restricts the fallback
to exactly those resolvers, in that order.

## Everything is host-side

Whichever scheme and form you use, the resolution runs in `sbx`'s host process
before the cage exists. The plaintext lives briefly in host memory, is consumed
by the broker, and is discarded. It is never an argument to a cage process, never
a cage file, never a cage variable. A resolver *plugin* also runs host-side (in
the trusted computing base, sandboxed under bubblewrap): see
[Resolver plugins](plugins).

## See also

- [Secrets architecture](../secrets/): the never-in-cage invariant and the resolver × broker
  split.
- [Injection](injection): the broker that consumes the resolved value.
- [Resolver plugins](plugins): additional resolver schemes from installed plugins.
- [Signed plugin stores](stores): where those plugins can come from.
- [`[secret]`](../configuration/secret): the full `[secret]`
  config reference.
