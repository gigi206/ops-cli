---
description: "Forming a credential that depends on the request being made, bounded to the one host its declaration names."
---

# The signer type


A resolver answers *where a value comes from*. A broker answers *how the cage uses a
host resource without holding it*. A **signer** answers the question neither can:
*what does authenticating this request look like?*

[Credential injection](../secrets/injection) already puts a credential on an outbound request:
a header name, and a value formed once at launch from the resolved plaintext. That
covers every auth point whose value is a constant, such as a bearer token, a Basic
pair or an API key. It cannot cover one whose value depends on the request itself:
a signature over the method, the path and the query, a per-request nonce, a
challenge answered in kind. `type = "signer"` is the third plugin type, for exactly
those.

```toml
name = "example-signer"
type = "signer"                       # no `scheme`: a signer claims no ref namespace
exec = "bin/sign"

[signer]
sets_headers = ["Authorization", "X-Example-Date"]   # every header it may put on a request
sees_headers = ["Content-Type"]                      # beyond the method, host and target
reads_secret = false                                 # true = handed the plaintext, not a marker
body_digest = "sha256"                               # optional: be told a digest of the body
```

What bounds a signer is not a new argument, it is an inherited one:

- **The window is one host.** A signer is named by a `[[secret]]`, and a declaration's
  destination is its section key: a single concrete host (a `*.` wildcard or a `re:`
  regex is refused at validation). So a signer is shown the requests of exactly the host its own
  declaration names, which is the host that already receives that credential on
  every request. No spelling of a manifest widens that: the destination comes from
  the config, never from the plugin.
- **The plugin is a pure filter**, on the same terms as a broker: no listening
  socket, no network descriptor, no host resource. It speaks to `sbx` alone, over
  stdin and stdout, from a host-side cage with an empty network namespace.

Together those are the ceiling: **a signer plugin can never see or place more than
the `[[secret]]` naming it already puts on the wire.** It is meant to place it far
better, bound to one request instead of replayable on any.

The rules a signer manifest is held to, each refused at load rather than at launch:

- **`network` and `state` are refused**, for the reason a broker's are. A signer is
  shown a credential's requests and, where it reads one, the credential itself.
- **`sets_headers` is required and non-empty.** A signer that sets nothing
  authenticates nothing, and the list is what makes the manifest a review surface:
  reading it tells you every header this plugin can write.
- **Some headers no manifest may declare.** `Host` chooses where the credential
  lands; `Content-Length`, `Transfer-Encoding` and `Trailer` choose where `sbx`
  thinks the request ends; `Connection`, `Upgrade`, `TE`, `Expect` and the
  `Proxy-*` family belong to the hop rather than to the request. Where a request
  goes, where it ends and what the connection becomes are sbx's, never a plugin's.
  The refusal is case-insensitive, since a header name is.
- **`sees_headers` is empty by default.** A request carries whatever the cage put on
  it, including credentials an app obtained by its own sign-in, which belong to no
  declaration. A plugin that must see one says which.
- **`reads_secret` is the step down, and it is labelled.** Off, the plugin is handed
  a marker standing in for the credential rather than the credential: it can place a
  secret it can never read, which is enough for one that is *carried*. It is not
  enough for one that is *computed*, since an HMAC over the canonical request is a
  function of the key. On, the plugin gets the key material, and it says so in the
  manifest that was reviewed rather than in the config of the machine that runs it.
- **`body_digest` is absent by default**, and names an algorithm rather than being a
  flag: `"sha256"` is the one sbx computes, and a manifest naming another is refused
  rather than quietly handed the one it does. What declaring it changes is described
  [below](#what-a-signer-is-told-about-the-body).

:::note What a signer plugin does not reach
A signer is given no `scheme`, so nothing a secret's `from` names routes to it, and
it may not declare `brokers` of its own: a broker fences a cage's access to a host
resource, and a signer has no cage and reaches no resource.
:::

The rest of `[sandbox]` applies exactly as it does to a resolver: `programs`,
`allow_paths`, `mask_paths`, `allow_env` and `allow_env_paths` bind the same way, and
`sbx plugins info <name>` shows them on a signer's page with each declared program
resolved against this host's `PATH`. `aws-sigv4` declares `programs = ["python3"]`, so
that line is where a missing interpreter is visible before a request is ever signed.

A declaration reaches it with [`sign`](../configuration/secret#sign-a-credential-computed-from-the-request):

```toml
[secret."s3.eu-west-1.amazonaws.com"]
from = "env://AWS_SECRET_ACCESS_KEY"
sign = "aws-sigv4"
```

The plugin is started once for the launch and asked once per request. It is told the
destination the config named, the method, the target and the headers it declared in
`sees_headers`, and it answers with headers. **Any failure refuses the request** with a
`403` and the reason `signer-refused`: a request that could not be signed is never sent
unsigned.

The plugin's own reason travels in that `403`, so the caller learns what to change, and it
is **scrubbed of every declared credential on the way**. That body is the one refusal sbx
writes that repeats a third party's words rather than its own, and it is answered into the
sandbox, which is the one reader that must never see a key.

## What a signer is told about the body

A signer is shown a request's head. The body is a different matter, and the reason is
structural rather than a policy: the proxy streams a `Content-Length` body straight
through to the upstream and de-chunks a `chunked` one only on its way out, so on both
framings the bytes are past sbx by the moment a signature has to be formed. A scheme
whose signature covers the payload would have nothing to sign over.

`body_digest = "sha256"` changes that, for the requests of the declaration naming this
plugin and no others. sbx holds the whole body before it asks, digests it, and states
the result in the question:

```json
{"seq": 1, "method": "POST", "host": "dynamodb.eu-west-1.amazonaws.com",
 "target": "/", "headers": {},
 "body": {"held": true, "bytes": 42, "sha256": "9f86d0…"}}
```

The digest is stated under the name of the algorithm that produced it, so a plugin reads
it under the spelling its own manifest asked for. A plugin that declared no `body_digest`
is shown no `body` key at all: asking for one changes nothing about what any other signer
is shown.

It does not widen what the plugin sees. A digest is a fact *about* the body, and the bytes
themselves never leave sbx.

**Where sbx cannot hold the body it says so**, rather than leaving the absence to be
inferred from a missing field:

```json
{"seq": 1, "method": "POST", "host": "…", "target": "/", "headers": {},
 "body": {"held": false, "why": "this request's body arrives as HTTP/2 DATA frames, …"}}
```

That is one plane, HTTP/2, for one reason: an HTTP/2 request half may legitimately never
end (a bidirectional streaming RPC), so a digest over it is not a cost sbx declines to
pay, it is a fact that does not exist at the moment the request must be signed. A stream
that ended with its headers carries no body, and the digest of nothing is stated as held
like any other. A scheme that requires the payload covered can refuse on `held: false`
instead of signing as though the request had none.

Two consequences worth knowing before you meet them:

- A body larger than the buffer sbx holds is **refused**, and which refusal depends on
  how the client framed it. A `Content-Length` above the ceiling is read off the head,
  so it is refused with `413` and the reason `signer-body-too-large` before the client
  is invited to send: an oversized upload is answered rather than received. A `chunked`
  body declares no length, so it is discovered at the ceiling while being read, and gets
  the `400 bad-request:chunked` that an over-cap chunked body already got before any
  signer was involved.
- Below that ceiling, a client's `Expect: 100-continue` is answered before the body is
  read, so the body arrives before the *plugin* can refuse the request. A signer refusal
  then follows an interim `100`, which is what HTTP allows and what the de-chunking path
  already did.

What the tripwires watch also changes, and deliberately: for a signed credential the
[needle](../secrets/redaction) is the **key**, not the signature. A signature is derived,
request-bound and single-use, while the key is the thing that must never leave the cage
verbatim.

Where a signer is visible: every request it forms a credential for, and every one it
would not, is one line of the **`signer` feed** in [`sbx logs`](../cli/logs#the-two-plugin-feeds).
A `sign` line names the signer, the request, and the header names it put on it; the
values are never shown. A refusal appears there too, and again in
[`sbx net logs`](../cli/net) with the verdict `blocked` and the reason
`signer-refused`, counted under `BLOCKED` in `sbx net stats`.

An answer may carry a `label`, the plugin's own account of what it formed (the region
and service a signature was scoped to, the identity it signed as). It is appended after
what sbx observed, never before, and the whole line is scrubbed of every credential the
launch declared: a plugin that echoed the key it was handed writes `${name}` into the
record, not the key.

## The published signer

One plugin in the store is not a resolver at all. Where [every resolver](resolvers)
answers *where a value comes from*, `aws-sigv4` answers what no resolved value
can: what authenticating **this** request looks like. It is reached with
[`sign`](../configuration/secret#sign-a-credential-computed-from-the-request)
rather than by a scheme, and the type it belongs to is
described on this page.

| Plugin | Named by | Forms | Sandbox grant |
|---|---|---|---|
| `aws-sigv4` | `sign = "aws-sigv4"` | an AWS Signature Version 4 signature over each request: `Authorization`, `X-Amz-Date`, `X-Amz-Content-Sha256`, and `X-Amz-Security-Token` for a temporary credential | `programs = ["python3"]`; `allow_env` for `AWS_ACCESS_KEY_ID`, `AWS_SESSION_TOKEN` and the region and service overrides; **no network**, no state, no broker |

```toml
[secret."my-bucket.s3.eu-west-3.amazonaws.com"]
from = "pass://aws/prod#secret_access_key"
sign = "aws-sigv4"
```

The secret access key stays host-side; the sandbox holds nothing reusable, and
each request leaves it unsigned and reaches AWS signed. Because the headers sbx
places are strip-and-replaced, an `aws` CLI or a boto3 running in the sandbox can
carry placeholder credentials: whatever it signed with is dropped, and the
plugin's signature is the only one the destination sees.

Bodies work, and the manifest is what makes them: `aws-sigv4` declares
[`body_digest = "sha256"`](#what-a-signer-is-told-about-the-body), so sbx holds a
request body before asking and states its digest in the question. That digest is
of exactly the bytes AWS will receive, so it supersedes one the client claimed,
while an `x-amz-content-sha256` carrying a literal AWS token rather than a digest
is honoured verbatim, since it chooses what the signature covers.

One shape is still **refused** rather than signed over a digest that does not
exist: a body to a non-S3 service over **HTTP/2**, where sbx states the body as
unheld, from a client that computed no digest of its own. The refusal repeats the
reason sbx gave.

If a launch refuses because a declared program is not on `PATH`, the tool the
plugin runs is not installed, or not where the shell that starts sbx looks for
it. `sbx plugins info <name>` resolves each declared program the way a launch
would and shows the answer.

## See also

- [`sign`](../configuration/secret#sign-a-credential-computed-from-the-request): the
  declaration that reaches a signer.
- [Injection](../secrets/injection): the constant-value case a signer exists to go
  beyond.
