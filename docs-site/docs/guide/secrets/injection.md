# Injection: the HTTP-header broker

A **broker** is the SINK half of a secret: it consumes the resolved plaintext
host-side and puts only a *capability* in front of the cage. Today `sbx` ships
one broker, `http-header`, which injects a credential into the matching outbound
HTTPS request **on the wire**, inside the MITM egress proxy. The agent makes a
plain request with no token anywhere; the proxy adds the header before forwarding.
The plaintext never enters the sandbox.

## Where injection happens (and when it does nothing)

Injection is performed by the filtering egress proxy. That proxy only runs under
a **filtering network posture**, so header injection is effective **only** when
the cage's network is `deny`, `allow`, or `ask`. Under `shared` or `none` there
is no proxy on the wire and a `[secret]` **injects nothing**: `sbx` warns rather
than silently sending an unauthenticated request. The destination host must also
be reachable under the policy (in the `allow` list, or not denied); a request to
a host the policy blocks is refused *before* injection. See
[../networking/modes.md](../networking/modes) and
[../configuration/network.md](../configuration/network).

## The `[secret]` table, keyed by destination host

`[secret]` is a TOML **table keyed by the destination host**, so a credential's
target reads at a glance:

```toml
[secret."api.github.com"]
from   = "sops://secrets.enc.yaml#github.token"   # SOURCE (see resolvers.md)
kind   = "http-header"                             # SINK (the broker)
header = "Authorization"
type   = "bearer"
```

The host key is the section name. It must be a **concrete host**: an IP, an
exact host, or a host-plus-path: because a credential is bound to one
destination; wildcard (`*.domain`) and regex (`re:`) forms are rejected as
injection targets. Injection matches the verified CONNECT host and the same
canonical request the egress verdict used, so path-scoping composes with the
allowlist.

`[secret]` is a **security field**: honored from the global config or a trusted
project, dropped from an untrusted one. It is a *table*, never an array (the one
reserved key, `defaults`, holds the resolver settings: so a host cannot be named
`defaults`). See [README.md](/) and
[../concepts/security-model.md](../concepts/security-model).

## Per-secret fields

| Field | Meaning |
|---|---|
| `kind` | The broker kind. Optional; defaults to `"http-header"`, the only kind today. |
| `key` **or** `from` | The SOURCE, exactly one. Terse `key` (expanded through `[secret.defaults]`) or a verbose `from` ref/chain. See [resolvers.md](resolvers). |
| `header` | The header name to set, e.g. `Authorization`. |
| `type` | How to shape the value: `bearer`, `basic`, or `raw`. |
| `prefix` | Optional override of the type's default prefix. |

### `header` and `type` are required: never silently defaulted

A secret must name a `header` and a `type`, either on the entry itself or via
`[secret.defaults]`. A secret that supplies **neither** is an **explicit error**,
not a silent fallback: an unnamed header or an unnamed transform would inject the
wrong thing quietly, and `sbx` refuses that. A per-entry value always overrides
the default.

### The `type` transforms

| `type` | Header value | Notes |
|---|---|---|
| `bearer` | `Authorization: Bearer <secret>` | Sugar for `raw` + `prefix = "Bearer "`. |
| `basic` | `Authorization: Basic <base64(user:pass)>` | The resolved value holds the `user:pass` pair; **`sbx` base64-encodes it**: the agent never pre-encodes. |
| `raw` | `<header>: <secret>` | No prefix by default. |

An optional `prefix` makes non-Bearer schemes expressible. For example, GitHub's
legacy `token ` scheme:

```toml
[secret."api.github.com"]
from   = "env://GH_TOKEN"
header = "Authorization"
type   = "raw"
prefix = "token "        # → Authorization: token <tok>
```

## Several credentials to one host

To send different headers to the same host, use an **array of tables**
(`[[secret."host"]]`):

```toml
[[secret."api.example.com"]]
from   = "env://EXAMPLE_TOKEN"
header = "Authorization"
type   = "bearer"

[[secret."api.example.com"]]
from   = "env://EXAMPLE_TENANT"
header = "X-Tenant-Id"
type   = "raw"
```

Each entry is keyed by `(host, header)` for deduplication, so give each a
distinct header. (Two entries that both fall back to the same default `header`
would collapse to the last, with a warning.)

## Strip-and-replace: `sbx`'s value is authoritative

Injection **strips any client-supplied copy of the header and replaces it** with
`sbx`'s value, matched case-insensitively across all spellings. An agent that
tries to set its own `Authorization` header cannot smuggle a value past the
broker or observe interference: the proxy always presents `sbx`'s credential,
and only that, to the upstream. Injection is re-matched per request, so it tracks
the live, canonicalized destination rather than a once-computed guess.

## Worked example

The declaration above (`sops://` source, `bearer` header) plays out like this:

1. **Declare** it in a trusted project under a filtering network posture.
2. **Launch (host-side, before the cage):** `sbx` calls the SOPS resolver: it
   uses the host-side age/KMS key to decrypt `secrets.enc.yaml` and returns
   `github.token`'s plaintext. `sbx` configures the proxy: *for `api.github.com`,
   set `Authorization: Bearer <token>`.* The token is in `sbx`'s host process: not the cage env, not a cage file.
3. **Agent runs:** `curl https://api.github.com/user` (no token anywhere) →
   in-cage forwarder → host MITM proxy → the header is injected → forwarded → the
   `200` is relayed back. The agent never saw the token; the `secrets.enc.yaml`
   it could read (if it were bound) is useless ciphertext with no key in the
   cage.
4. **Teardown:** `sbx` discards the plaintext; the proxy, CA, and socket are torn
   down with the cage.

The "consumption" is the HTTPS call the agent was going to make anyway: `sbx`
brokers the credential onto the wire. No MCP, no agent cooperation.

## Honest residual: a reflecting upstream

"The agent never sees the secret" over-claims for one case: an
**injection-target host that reflects the header back**, or an allowed
multi-tenant host the agent can write to. The structural guarantee is that the
agent cannot exfiltrate the credential to an *arbitrary* host (concrete-host
scope + empty netns + tight egress), not that it can never observe it against a
cooperating destination. The inbound tripwire in [redaction.md](redaction)
masks the naive verbatim reflection; the real lever remains least privilege at
the source and a tight allowlist.

## See also

- [resolvers.md](resolvers): the SOURCE that produces the value injected
  here.
- [redaction.md](redaction): the outbound/inbound tripwires around this
  broker.
- [README.md](/): the never-in-cage invariant and the two-layer model.
- [../networking/modes.md](../networking/modes) /
  [../configuration/network.md](../configuration/network): the filtering
  posture that makes injection live.
- [../configuration/secret.md](../configuration/secret): the full config
  reference.
- [https://github.com/gigi206/ops-cli/blob/ops-v2/docs/bwrap-secrets-architecture.md](https://github.com/gigi206/ops-cli/blob/ops-v2/docs/bwrap-secrets-architecture): the broker design and the exposure lattice.
