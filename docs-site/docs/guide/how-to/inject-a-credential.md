---
sidebar_label: "Inject a credential"
description: "A `[secret]` block from nothing to a verified injection: the source, the destination, the posture, and what then watches the value."
---

# Give an agent a credential it can use but never read

An agent that calls an authenticated API needs the call to carry a token. Handing it
the token puts a permanent, portable secret inside a cage you do not trust. The
alternative sbx offers is to keep the plaintext host-side and have the egress proxy put
it on the wire: the agent makes the request it was going to make, and the header is
added in front of it.

This recipe takes one host from nothing to a verified injection. The reference for
every field it uses is [`[secret]`](../configuration/secret); the model behind it is
[Secrets](../secrets/).

## 1. Put the value somewhere the host can read it

The declaration names a **source**, never a literal. The simplest is an environment
variable of the shell that launches sbx:

```sh
export GITHUB_TOKEN=ghp_…
```

A file, a SOPS-encrypted store or a password manager work the same way, and are
generally better than a shell that keeps the value exported all day: see
[Resolvers](../secrets/resolvers) for `file://` and `sops://`, and
[The resolver type](../plugins/resolvers) for the published `pass://`, `vault://` and
`bitwarden://` plugins.

## 2. Declare the destination, in a trusted config

`[secret]` is keyed by the host that receives the credential, and it is a security
field: put it in the global config, or in a project you will trust in step 4.

```toml
[secret."api.github.com"]
from   = "env://GITHUB_TOKEN"
header = "Authorization"
type   = "bearer"
```

Repeating `header`/`type` for every entry gets old: [`[secret.defaults]`](../configuration/secret#secretdefaults)
carries the pair once, and each entry keeps only its host and its source.

## 3. Give the cage a filtering posture that reaches the host

**Injection is done by the proxy, so a posture with no proxy injects nothing.** The
cage must be under `deny`, `allow` or `ask`, and its allowlist must reach the host the
block names:

```toml
[network]
mode  = "deny"
allow = ["api.github.com"]
```

Under `none` there is no network at all; under `shared` there is no proxy to inject
with. See [Network modes](../networking/modes).

## 4. Trust it, and check the inventory

```sh
sbx trust                 # both tables above are security fields
sbx secret list           # the declarations, by host — names and sources, never values
```

[`sbx secret list`](../cli/secret) is the inventory: it answers *which credential would
be injected where*, from the resolved config, without launching anything.

## 5. Verify with the request itself

```sh
sbx run -- curl -sS https://api.github.com/rate_limit
```

`"limit": 5000` is the authenticated ceiling; `60` is the anonymous one, and means the
header did not arrive. When it does not, the two usual causes are the posture from step
3 and a path rule that does not match: a rule matches a path exactly, so an entry keyed
on a base path needs a trailing `/*` to cover what lives below it.

The other side of the check is the log, which names an injected credential without ever
printing it:

```sh
sbx net logs --host api.github.com     # from another terminal, while the session runs
```

## 6. What now watches that value

Declaring a secret arms the [tripwires](../secrets/redaction): the plaintext is refused
if the cage tries to send it anywhere it was not declared for, and masked if it comes
back in a response. That is a property of *declaring* it, not of using it, and it is
the reason a declared credential is safer than one the app signs in for itself.

## Where to go next

- [Per-provider recipes](../secrets/providers/): the same six steps, already written
  for around forty services.
- [`sign`](../plugins/signer): when the credential is not a constant but a signature
  over each request.
- [OAuth sessions](../secrets/oauth): when the app has its own sign-in and you want the
  token out of the cage anyway.
