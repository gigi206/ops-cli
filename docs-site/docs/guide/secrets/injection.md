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
[Network modes](../networking/modes) and
[`[network]`](../configuration/network).

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
`defaults`). See [Secrets architecture](../secrets/) and
[Security model](../concepts/security-model).

## Per-secret fields

| Field | Meaning |
|---|---|
| `kind` | The broker kind. Optional; defaults to `"http-header"`, the only kind today. |
| `key` **or** `from` | The SOURCE, exactly one. Terse `key` (expanded through `[secret.defaults]`) or a verbose `from` ref/chain. See [Resolvers](resolvers). |
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

## When the upstream refuses the credential

A credential can stop being accepted while the cage is still running: an access
token expires, a secret is rotated, a session is revoked elsewhere. When an
injection target answers **`401`**, `sbx` re-runs the resolver for that
declaration and injects the newly resolved value from then on.

The trigger is the refusal, not a declared expiry. An expiry is a claim about a
clock this process does not own, and it says nothing about a token revoked early;
a `401` is the destination itself stating that the value it was given is no
longer good.

**The refused request is lost.** Its response head reaches the cage before `sbx`
reads the status, so what a refresh buys is the *next* request. In practice the
agent retries and continues, but the first call after a credential goes stale
does fail, and that is worth knowing before you read it as a bug.

Three bounds keep a hopeless credential from spinning, since a resolver run can
mean launching a sandboxed plugin:

- a refusal within a short window of the last attempt is ignored;
- a resolver that **errors** stops the mechanism for the session, since a broken
  source is not a stale one and retrying only repeats the failure;
- a resolver that returns **the same value** stops it too: the upstream just
  refused that value, so re-sending it would only be refused again.

A `401` from a host carrying no injection is never a signal. Otherwise any
allowed destination, including one the agent chose, could drive the resolver.

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
cooperating destination. The inbound tripwire in [Redaction](redaction)
masks the naive verbatim reflection; the real lever remains least privilege at
the source and a tight allowlist.

## See also

- [Resolvers](resolvers): the SOURCE that produces the value injected
  here.
- [Redaction](redaction): the outbound/inbound tripwires around this
  broker.
- [Secrets architecture](../secrets/): the never-in-cage invariant and the two-layer model.
- [Network modes](../networking/modes) /
  [`[network]`](../configuration/network): the filtering
  posture that makes injection live.
- [`[secret]`](../configuration/secret): the full config
  reference.
