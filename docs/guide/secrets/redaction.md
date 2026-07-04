# Redaction — the secret tripwires

The never-in-cage invariant keeps a secret's plaintext on the host. But a secret
`ops` injects on the wire could, in principle, leak back the other way — an agent
that somehow *already* holds a token could try to re-send it, or a cooperating
allowed upstream could reflect an injected header into its response body. `ops`
adds two byte-exact tripwires, one per direction, as **backstops**. Be clear on
what they are and are not: they catch the naive verbatim leak; they are **not the
boundary**.

## Outbound: block a request that carries a secret

When a request leaves the cage, the proxy scans the **decrypted request head**
for any configured secret value. If a secret appears verbatim, the proxy
**refuses the whole request** — it blocks, it does not strip:

- category **`outbound-secret`**, HTTP **`403`**;
- scanned on the **pre-injection** client bytes, so `ops`'s own injection never
  trips its own scanner;
- checked **before** the egress verdict.

Blocking (rather than stripping) is deliberate: a request that is trying to carry
a secret out is not a request to quietly clean up and forward. The agent gets a
clear `403` refusal.

### The 8-byte floor

The scan has a minimum length: **`REDACT_MIN_LEN = 8`**. A secret shorter than 8
bytes is still injected, but it is **not** added to the outbound scan set, and
`ops` **warns loudly**. A very short value produces too many false-positive
matches against ordinary request bytes to scan safely. The lesson is practical:
use secrets of reasonable length (real tokens already are).

### Head-only, by design

Only the request **head** is scanned. The body is streamed, and a clean
block-not-strip on the body would need to buffer it — a cap that either
fails-closed on large uploads or is beaten by padding. Scanning the head covers
where a leaked credential naturally lands (a header, a query string); the body is
left to the structural boundary below.

## Inbound: mask a secret a target reflects back

The one place a configured secret can legitimately re-enter the cage is a
response **from an injection-target host** — a cooperating or misconfigured
upstream that echoes the header `ops` injected. For those responses only, the
proxy **masks** every verbatim occurrence of the secret value as it streams the
response back, replacing it with an **equal-length run of `*`**:

- **mask, not block** — unlike the outbound case, the response also carries
  legitimate content the agent needs, so `ops` masks the secret in place rather
  than dropping the whole response;
- **equal-length** — the `*` run is the same byte length as the secret, so
  `Content-Length`/chunked framing stays intact and `*` never introduces a
  `CR`/`LF`;
- **streaming-safe** — the proxy carries the trailing bytes of each chunk so a
  value straddling two reads is still caught.

### Scoped to injection-target responses only

Inbound masking runs **only** on responses from a host `ops` injects a secret
into — the only place a configured secret can reflect. The always-on nix-cache
lane and every non-target response stream through untouched, so a coincidental
byte match in unrelated traffic cannot corrupt it. The trade-off: masking mutates
the stream, so a coincidental collision *within* a target host's response would
be masked too — entropy and the 8-byte floor make that vanishingly unlikely, and
it is confined to the one host.

## Honest scope: these are backstops, not the boundary

Both tripwires are **byte-exact**. They catch a secret sent or reflected
*verbatim*. They do **not** catch a secret that is re-encoded first — base64,
gzip, chunk-splitting, or any transform defeats a byte-exact scan. `ops` does not
pretend otherwise.

The actual guarantee is structural, and it is the trio you should rely on:

1. **Empty netns** — the cage has no route of its own; its only egress is the
   host proxy.
2. **The egress allowlist** — the cage can only reach the hosts the policy
   permits. See [../networking/modes.md](../networking/modes.md).
3. **Host/`to` bounding** — a credential is injected only toward its one concrete
   destination host, never anywhere else.

The tripwires reduce the *naive verbatim* leak in both directions; the three
structural controls are what make exfiltration to an *arbitrary* host impossible.
And the source-side lever still dominates: a tightly scoped secret is worth less
if it does leak. See the resolver guidance in [resolvers.md](resolvers.md).

## See also

- [injection.md](injection.md) — the broker whose injected header these tripwires
  guard, and the reflecting-upstream residual.
- [README.md](README.md) — the never-in-cage invariant and least-privilege at the
  source.
- [../networking/modes.md](../networking/modes.md) — the empty-netns + allowlist
  boundary the tripwires sit behind.
- [../../bwrap-secrets-architecture.md](../../bwrap-secrets-architecture.md) — the
  design's honest residuals (reflecting upstream, encoding-evasion, masking's
  limits).
