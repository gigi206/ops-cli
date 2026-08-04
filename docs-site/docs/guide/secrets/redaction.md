# Redaction: the secret tripwires

The never-in-cage invariant keeps a secret's plaintext on the host. But a secret
`sbx` injects on the wire could, in principle, leak back the other way: an agent
that somehow *already* holds a token could try to re-send it, or a cooperating
allowed upstream could reflect an injected header into its response body. `sbx`
adds two byte-exact tripwires, one per direction, as **backstops**. Be clear on
what they are and are not: they catch the naive verbatim leak; they are **not the
boundary**.

## Outbound: block a request that carries a secret

When a request leaves the cage, the proxy scans the **decrypted request head**
for any configured secret value. If a secret appears verbatim, the proxy
**refuses the whole request**: it blocks, it does not strip:

- category **`outbound-secret`**, HTTP **`403`**;
- scanned on the **pre-injection** client bytes, so `sbx`'s own injection never
  trips its own scanner;
- checked **before** the egress verdict.

Blocking (rather than stripping) is deliberate: a request that is trying to carry
a secret out is not a request to quietly clean up and forward. The agent gets a
clear `403` refusal.

### The 8-byte floor

The scan has a minimum length: **`REDACT_MIN_LEN = 8`**. A secret shorter than 8
bytes is still injected, but it is **not** added to the outbound scan set, and
`sbx` **warns loudly**. A very short value produces too many false-positive
matches against ordinary request bytes to scan safely. The lesson is practical:
use secrets of reasonable length (real tokens already are).

### Head-only, by design

Only the request **head** is scanned. The body is streamed, and a clean
block-not-strip on the body would need to buffer it: a cap that either
fails-closed on large uploads or is beaten by padding. Scanning the head covers
where a leaked credential naturally lands (a header, a query string); the body is
left to the structural boundary below.

## Inbound: mask a secret a target reflects back

The one place a configured secret can legitimately re-enter the cage is a
response **from an injection-target host**: a cooperating or misconfigured
upstream that echoes the header `sbx` injected. For those responses only, the
proxy **masks** every verbatim occurrence of the secret value as it streams the
response back, replacing it with an **equal-length run of `*`**:

- **mask, not block**: unlike the outbound case, the response also carries
  legitimate content the agent needs, so `sbx` masks the secret in place rather
  than dropping the whole response;
- **equal-length**: the `*` run is the same byte length as the secret, so
  `Content-Length`/chunked framing stays intact and `*` never introduces a
  `CR`/`LF`;
- **streaming-safe**: the proxy carries the trailing bytes of each chunk so a
  value straddling two reads is still caught.

### Scoped to injection-target responses only

Inbound masking runs **only** on responses from a host `sbx` injects a secret
into, the only place a configured secret can reflect. The always-on nix-cache
lane and every non-target response stream through untouched, so a coincidental
byte match in unrelated traffic cannot corrupt it. The trade-off: masking mutates
the stream, so a coincidental collision *within* a target host's response would
be masked too, entropy and the 8-byte floor make that vanishingly unlikely, and
it is confined to the one host.

## The traffic capture is masked unconditionally

[`[network] capture`](../networking/observability#seeing-the-traffic-network-capture)
retains what an inspected exchange carried, so `sbx net logs --with-body` can show it.
That is a third place a secret could surface, and it is masked on a **stricter** rule
than the inbound case above:

- **Every capture, from every host.** Unlike inbound masking (scoped to
  injection-target responses, because it mutates a stream the cage will read), a capture
  is not a stream anyone consumes: masking it costs nothing and is applied to all of it.
- **Masked on the way in, at a single door.** The bytes are masked *before* they are
  stored, so the ring never holds a credential, and no reader can forget to mask.
- **Over whole buffers.** The masking sees a finished part rather than each socket read,
  so a value straddling two reads is one contiguous run by then and is masked exactly.

A credential **sbx injects** never enters a capture at all: the head recorded is the
client's own as it stood before the injection, and the injected headers appear by **name**
only (`authorization: <injected by sbx>`).

A WebSocket's messages are **decompressed before they are masked** when the peers
negotiated `permessage-deflate`, so a secret inside a compressed message is masked out of
the capture like any other. That is narrower than it sounds: it holds for the capture,
because the capture holds decoded plaintext. On the wire, a compressed payload is not a
verbatim needle, so the encoding residual below still applies there.

### A WebSocket: masked in the capture, not on the wire

A capture covers a WebSocket's messages too, and they are masked at the same door as
everything else. Be precise about what that does and does not mean: the **relay** does not
mask frames. Once a tunnel is open the framed bytes are relayed verbatim, so a secret a peer
reflects inside a frame **reaches the cage as it was sent** — inbound masking, above, covers
HTTP responses, not frames. What is masked is the copy `sbx net logs` shows you. Masking the
wire would mean rewriting the relayed stream (decode, mask, re-frame, re-mask) on the one
path that has to stay a byte-exact pipe.

## The third tripwire: a WebSocket is watched, not filtered

The two tripwires above act on what they find: one refuses, the other masks. On an open
WebSocket neither is possible, so sbx does the one honest thing left and **reports**. Whenever
a secret is configured, the frames crossing a tunnel are decoded and scanned, and a
configured value seen crossing is named on that tunnel's log line:

```
      ! secret `openai-key` crossed this websocket (upstream → cage); it was NOT blocked or masked
```

The wording is the point. **The frame reached its destination.** This is an alarm, not a
control: it tells you a credential is somewhere it should not be, while the tunnel is still
open, so you can act. Treating it as protection would be exactly the mistake the line is
worded to prevent.

- Both directions: `cage → upstream` (the agent sent it out) and `upstream → cage` (the far
  side sent it back).
- The credential's **name**, never its value.
- **Once per credential per direction** — a repeat carries no new information.
- It runs **whether or not the launch captures**: an enforcement path must not depend on a
  debugging setting. It sees the payloads decoded, so a masked frame and a
  `permessage-deflate` message are scanned as the text they carry.
- Byte-exact and per message, with the same honest scope as the rest of this page: a
  re-encoded value, or one split across two separate messages, is not caught.

See [Observability](../networking/observability#a-secret-crossing-a-websocket) for the
`--json` shape. And as everywhere on this page, the structural controls below are what
actually bound the damage.

## Seeing a tripwire fire

Both directions are observable from the host, with the ordinary egress surfaces.

An outbound block is a **security block**, not a policy refusal, so it appears under
the `blocked` column rather than `deny`:

```sh
sbx net logs --verdict blocked -f          # as it happens, on a running session
sbx net stats                              # after the fact, per host
sbx net stats --json | jq -r '.stats[] | select(.blocked>0) | "\(.blocked)\t\(.host)"'
```

That distinction is the point of the column: a `deny` is the allowlist working as
configured, while a `blocked` means a guard stopped something the policy would
otherwise have let through. In the cage, the same event is a plain `403`:

```console
$ curl -sS -o /dev/null -w '%{http_code}\n' https://api.example.com/v1/echo \
    -H "X-Copy: $SOME_TOKEN"
403
```

A short secret disables the outbound half at launch, loudly, rather than silently
scanning nothing:

```
sbx: warning: the secret for `Authorization` is too short (6 bytes) to redact from outbound
     requests safely; outbound leak-blocking is disabled for it (the injection still applies)
```

Inbound masking is visible in the response itself: an upstream that echoes the header
back returns an equal-length run of `*`, so the framing is intact and only the value
is gone.

```console
$ curl -sS https://api.example.com/v1/whoami
{"seen_authorization":"Bearer ****************************************"}
```

And in a [capture](../networking/observability#seeing-the-traffic-network-capture), an
sbx-injected credential is named rather than valued, because the recorded head is the
client's own, taken before injection:

```sh
sbx net logs --with-headers --host api.example.com
#   > authorization: <injected by sbx>
```

## Honest scope: these are backstops, not the boundary

Both tripwires are **byte-exact**. They catch a secret sent or reflected
*verbatim*. They do **not** catch a secret that is re-encoded first: base64,
gzip, chunk-splitting, or any transform defeats a byte-exact scan. `sbx` does not
pretend otherwise.

The actual guarantee is structural, and it is the trio you should rely on:

1. **Empty netns**: the cage has no route of its own; its only egress is the
   host proxy.
2. **The egress allowlist**: the cage can only reach the hosts the policy
   permits. See [Network modes](../networking/modes).
3. **Host/`to` bounding**: a credential is injected only toward its one concrete
   destination host, never anywhere else.

The tripwires reduce the *naive verbatim* leak in both directions; the three
structural controls are what make exfiltration to an *arbitrary* host impossible.
And the source-side lever still dominates: a tightly scoped secret is worth less
if it does leak. See the resolver guidance in [Resolvers](resolvers).

## See also

- [Injection](injection): the broker whose injected header these tripwires
  guard, and the reflecting-upstream residual.
- [Secrets architecture](../secrets/): the never-in-cage invariant and least-privilege at the
  source.
- [Network modes](../networking/modes): the empty-netns + allowlist
  boundary the tripwires sit behind.
- [`bwrap-secrets-architecture.md`](https://github.com/gigi206/ops-cli/blob/ops-v2/docs/bwrap-secrets-architecture.md): the
  design's honest residuals (reflecting upstream, encoding-evasion, masking's
  limits).
