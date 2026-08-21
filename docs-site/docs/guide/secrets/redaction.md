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

### The length floor

The scan has a minimum length, **8 bytes by default**. A secret shorter than the
floor is still injected, but it is **not** added to the outbound scan set, and
`sbx` **warns loudly**. A very short value produces too many false-positive
matches against ordinary request bytes to scan safely. The lesson is practical:
use secrets of reasonable length (real tokens already are).

The floor is one setting for the whole launch, in the `[redact]` table:

```toml
[redact]
min_len = 4
```

Lower it when a legitimate credential is short and you accept the noise; raise it
to scan only for values long enough to be unmistakable. The value must be at
least `1`, since a zero-length needle matches at every offset and so names
nothing.

One floor governs every place a credential is watched for, so moving it moves
them together:

- the outbound refusal and the inbound mask described on this page;
- the `${NAME}` substitution over [a task's output](../tasks/output);
- a credential the cage obtained by its own sign-in, which `sbx` remembers so the
  tripwires cover it too. That one is held to the stricter of the configured
  floor and its own built-in minimum, since it was inferred rather than declared
  by a person.

What each place decides for itself is how the floor is applied to a credential
with more than one spelling. A wire injection is judged as a whole, on the
plaintext, so a short secret is left unscanned along with its encoded form; a
task credential is judged per spelling, so a `base64` encoding that clears the
floor is still substituted out of the output even when its plaintext does not.

`[redact]` is a security field: it is honored from the global config or a trusted
project, and dropped from an untrusted one. Raising the floor is how a project
would stop `sbx` watching for the very credentials it injects on that project's
behalf. `sbx config` shows the floor whenever a layer moved it, with the layer it
came from.

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
- **head and body**: an echo or debug endpoint reflects the credential in a
  header of its own (`X-Echo-Authorization`, a `Set-Cookie`) as readily as in a
  body, so both are masked;
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
reflects inside a frame **reaches the cage as it was sent**: inbound masking, above, covers
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
- **Once per credential per direction**: a repeat carries no new information.
- It runs **whether or not the launch captures**: an enforcement path must not depend on a
  debugging setting. It sees the payloads decoded, so a masked frame and a
  `permessage-deflate` message are scanned as the text they carry.
- Byte-exact and per message, with the same honest scope as the rest of this page: a
  re-encoded value, or one split across two separate messages, is not caught.

See [Egress observability](../networking/observability#a-secret-crossing-a-websocket) for the
`--json` shape. And as everywhere on this page, the structural controls below are what
actually bound the damage.

## Credentials the cage obtained for itself

Everything above describes a **declared** secret. An agent that signs in by itself,
through OAuth or SSO, ends up holding a token nobody declared, and the tripwires
would have nothing to match it against.

So the proxy remembers it. When an allowed request carries an authentication header
(`Authorization`, `x-api-key`, and a short list of siblings), the token it holds is
kept as a needle, along with the host it was going to, and from then on it is treated
like a declared secret's value: refused if the cage sends it to any **other** host,
masked if a response reflects it, hidden from the capture.

Its own host is the exception, and it has to be. A session token exists to be sent
back to the service that issued it, on every request after the sign-in; refusing it
there would turn a successful login into an application that stops working at its
second authenticated request. What the tripwire stops is the case it exists for, which
is the cage carrying a credential it holds for one service to a different one. A
declared secret keeps no such exemption: the cage is never given its value, so that
value appearing in a request is a leak wherever the request is going.

This is worth being explicit about, because it means `sbx` retains a value you never
gave it. It only ever holds it in memory, never writes it and never logs it, and the
proxy already *saw* it in any case, being the thing that terminates the cage's TLS.
The choice is only whether it remembers what it has seen, and remembering is what
lets it protect the credential at all.

Every inspected plane observes, and they are named here by what selects one rather than
by the shape of the request, because two of them share that shape:

| Plane | Selected by |
|---|---|
| tunneled | a `CONNECT`, the ordinary `https_proxy` route |
| inspected TLS | an absolute-form `https://` request, a client treating the proxy as a forward proxy |
| inspected cleartext | an absolute-form `http://` request, permitted only by an explicit [`http://` rule](../networking/rules) |
| HTTP/2 | a negotiated h2 connection, gRPC included |

The scan set is shared, so a token learned on any of them is covered on all of them; a
plane that watched and never learned would be a gap in each. The cleartext plane observes
although it never *injects*, and the two do not follow from one another: it injects
nothing because a bearer must not travel in the clear, while what it observes is what
refuses that same value on a TLS plane, toward a host it was never acquired on.

Five bounds keep this narrow:

- only a request that reached the wire is observed, so an agent cannot seed the scan
  set by aiming at hosts it knows are refused. The bound is the **last** refusal, not
  the first: a request the policy allowed and the SSRF guard then blocked teaches
  nothing either;
- the tripwire is scoped to **other** destinations, so an app re-sending its own
  session token to its own service is not refused for holding it;
- observation happens **after** the outbound scan, so the request that teaches a
  value is never refused by that value;
- a short value is ignored, on a stricter floor than for a declared secret, since
  one that occurs by chance would refuse ordinary requests;
- the number kept is capped, because every needle is scanned against every request
  head and every response chunk.

Once remembered, a value stays remembered for the life of the session. That matters
because a declared credential can be **re-resolved** mid-session, when the destination
answers `401` and says the value it was given is no longer accepted. A re-resolution
speaks for every declaration and replaces what they produced; it speaks for nothing the
cage obtained on its own, so what was learned is carried across rather than discarded
with the value it had nothing to do with.

It changes what is *scanned*, never what is *sent*: observing never creates an
injection, so it cannot alter what the cage authenticates as.

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
  design's honest residuals (reflecting upstream, encoding-evasion, masking's
  limits).
