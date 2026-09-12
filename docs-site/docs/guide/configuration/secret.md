---
sidebar_label: "[secret]"
description: "Credentials the egress proxy injects into matching outbound requests, keyed by destination host."
---

# `[secret]`: credential injection

Credentials the [egress proxy](../networking/architecture) injects into matching
outbound requests, keyed by destination host. This page documents the **config
shape**; for the architecture (the never-in-cage invariant, resolvers, redaction) see
the [Secrets](../secrets/) section.

`[secret]` is a **security field**: honored from the global config or a trusted
project, ignored from an untrusted one, and **effective only under a filtering
network posture** (`deny`/`allow`/`ask`), because the filtering proxy is what performs
the injection.

See also: [Secrets architecture](../secrets/) · [Resolvers](../secrets/resolvers) · [Injection](../secrets/injection) · [`network`](network).

## The invariant

`sbx` **never places a plaintext secret in the cage**. The value is read **host-side**
and injected into the matching outbound request on the wire; the plaintext never
enters the sandbox. So a credential belongs in `[secret]`, **not** in
[`env`](env) (which is visible inside the cage).

## Keyed by host

`secret` is a TOML *table* keyed by destination host, not an array: the host is the
section, so a credential's destination reads at a glance:

```toml
# one credential for a host
[secret."api.github.com"]
from   = "env://GITHUB_TOKEN"
header = "Authorization"
type   = "bearer"

# several credentials to one host (an array of tables)
[[secret."registry.example.com"]]
key = "reg_a"
header = "X-A"
type = "raw"
[[secret."registry.example.com"]]
key = "reg_b"
header = "X-B"
type = "raw"
```

The destination is written **only** as the section key: there is no `to =` field. sbx does
call it `to` where it has to name it, in a validation refusal (`` `to` must be a concrete
host ``) and in the `sbx config show --json` view, so the two spellings meet the same thing.

## A secret entry's fields

| Field | Meaning |
|---|---|
| `name` | a logical name for the inventory, defaulting to the section key (the destination host): `1-64` characters of letters, digits, `_`, `-`, `.`; empty means omit it |
| `description` | one line saying what the credential is for, printed beside the name; control characters become spaces and it is capped at 200 characters, never refused |
| `kind` | the broker kind; defaults to the only kind today, `"http-header"` |
| `key` | a **terse** source name, expanded through `[secret.defaults]` (optionally pinned `key@resolver`) |
| `from` | an **explicit** source: one `scheme://locator` ref, or an array = a fallback chain |
| `header` | the header name to set (e.g. `Authorization`, `x-api-key`) |
| `type` | how to shape the value: `bearer`, `basic`, or `raw` |
| `prefix` | override the type's default prefix (`Bearer ` / `Basic ` / empty) |
| `sign` | a [signer plugin](../plugins/signer) that forms the credential **per request** |
| `optional` | whether a launch may proceed when this credential does not resolve, its destination denied for the run; default `false`, which refuses the launch |

A secret must have **exactly one** of `key` or `from`. It must have a `header` and a
`type`, either on itself or from `[secret.defaults]`: a secret that names neither is
an **explicit error**, never a silent (and likely wrong) default. The `header` must be
non-empty and carry no control character, space or `:`; the `prefix` no control character;
a `type` outside `bearer` / `basic` / `raw` is an error. The destination is always one
concrete inspected-TLS host: no `{verb}` prefix, no `tcp://` or `http://` scheme, no
`*.domain` wildcard, no `re:` regex.

A **port** may be a wildcard where a host may not. `api.example.com` sends the credential to
`443`, `api.example.com:8443` to that port alone, and `api.example.com:*` to every port of that
one host. What differs is what the wildcard ranges over: `*.domain` ranges across *hosts*, so a
host you do not control could ask for the credential, while `:*` stays on the single host you
named, whose ports are one machine under one administration. The egress allowlist still decides
which of those ports the cage may reach at all, so one you never allowed never sees the header.

### `optional`: what an unresolvable credential costs

A credential is read host-side at launch, and a source can be missing: an unset variable,
a vault that is locked, an OAuth session that expired. By default the launch is **refused**,
before anything is stood up, because the configuration said the cage needs that credential
to do its work.

```toml
[secret."api.example.com"]
from     = "vault://kv/app#token"
header   = "Authorization"
type     = "bearer"
optional = true
```

With `optional = true` the launch proceeds and **that destination alone is denied** for the
run. It is not a permission to send the request without the header: the header is the reason
the configuration reaches that host at all, so a run that could not form it does not reach it.
Every other credential still resolves, and every other destination still works.

The case it exists for is a credential the session must be able to **renew**. When the thing
that re-issues the token lives inside the cage, a login for instance, refusing the launch over
the expired token also refuses the only way to replace it. Marking the declaration breaks that
deadlock without widening what may leave.

Two things are unaffected. A batch roll (`sbx upgrade`) already denies rather than refuses,
for every declaration, because it runs one captured command per app and a credential that
command never sends must not decide whether the app is upgraded. And a credential denied at
launch stays denied for that run: re-seeding its source mid-session does not re-open the
destination, which takes a relaunch.

### `sign`: a credential computed from the request

`header`, `type` and `prefix` form the value **once**, at launch, from the resolved
plaintext. That covers every auth point whose value is a constant: a bearer token, a
Basic pair, an API key. It cannot cover one whose value depends on the request itself,
such as a signature over the method, the path and the query.

`sign` names an installed [signer plugin](../plugins/signer) instead,
and the plugin is asked once per request:

```toml
[secret."s3.eu-west-1.amazonaws.com"]
from = "env://AWS_SECRET_ACCESS_KEY"
sign = "aws-sigv4"
```

`sign` is **mutually exclusive** with `header`, `type` and `prefix`: which headers the
request carries and how they are formed is the plugin's own manifest to say, so a
declaration stating both would state two answers to one question. The source
(`key`/`from`) still applies: it is the credential the plugin signs with, resolved
host-side exactly as any other.

Three properties hold whatever the plugin does:

- **It sees only this host.** A declaration's destination is its section key, one
  concrete host, so the plugin is shown the requests of exactly the host its own
  declaration names, which is the host that already receives that credential.
- **It sets only the headers its manifest declared.** A header outside `sets_headers`
  refuses the whole answer, and a value carrying a newline is refused too: the request
  head is sbx's to frame.
- **A request that could not be signed is not sent.** Any failure, including a plugin
  that says it cannot sign, refuses the request with a `403` and the reason
  `signer-refused`. It is never sent unsigned, which would reach the destination as an
  anonymous request and come back an authentication error for an unrelated reason.

`name` and `description` are what [`sbx secret list`](../cli/secret) prints, and the name matters
for more than tidiness: it is what a substituted value is reported as (`${NAME}`) if a credential ever
reaches a [task's](task) output. Two credentials sharing a name are both kept but warned about: a
reader could not tell which one was withheld. Keep a name non-sensitive: it is a label, and it is
shown to the caller. Its character set is narrow (letters, digits, `_`, `-`, `.`) precisely because it
is rendered into output.

For a credential a *declared operation* reads from its environment, see
[`[task.<name>.secret]`](../tasks/credentials): there the key **is** the variable, so the reported name
is the variable's own.

## `[secret.defaults]`

A reserved `defaults` table holds the resolver order and per-resolver bindings the
terse `key` form expands through, plus a default `header`/`type` any entry may omit:

```toml
[secret.defaults]
order  = ["env", "sops"]   # try env:// first, then sops://
header = "Authorization"
type   = "bearer"
[secret.defaults.sops]
file = "secrets/prod.yaml"
[secret.defaults.env]
case = "upper"             # a terse key `k` → env var UPPER(k)
[secret.defaults.file]
dir  = "/run/secrets"

[secret."api.github.com"]
key = "github_token"       # → env://GITHUB_TOKEN, else sops://secrets/prod.yaml#github_token
```

Because `defaults` is reserved, a host cannot be named `defaults`.

A [resolver plugin](../plugins/) is bound the same way, under `resolver`, keyed by the
**scheme** it claims rather than by its name (the two differ for a plugin whose name says what it
is while its scheme says what it addresses):

```toml
[secret.defaults]
order  = ["vault-demo"]
header = "Authorization"
type   = "bearer"
[secret.defaults.resolver.vault-demo]
locator = "agents/{key}"   # a terse key `k` → vault-demo://agents/k

[secret."api.example.com"]
key = "api-example"        # → vault-demo://agents/api-example
```

`locator` takes one placeholder, `{key}`. Unset, or with no table at all, the key is the whole
locator (`vault-demo://k`), which is what a vault addressed by host or by entry name already
wants. A template that never writes `{key}` is refused, since every terse key would then resolve
the same secret.

## The source: `key` vs `from`

- **`from`** is explicit: one resolver ref (`from = "env://VAR"`) or a fallback chain
  (`from = ["env://VAR", "sops://f#k"]`, tried in order, first to resolve wins).
- **`key`** is terse, a bare key expanded through the `[secret.defaults] order` and
  per-resolver bindings, optionally pinned to a resolver with `key@resolver`.

Built-in resolvers are `env://`, `file://`, `sops://`; more come from
[resolver plugins](../plugins/). See [Resolvers](../secrets/resolvers).

## Worked example: authenticating the GitHub API

The one most installations end up needing. mise's `aqua:` backend reads the GitHub API to
resolve a tool's release, and **anonymously that is 60 requests an hour per IP**: which a
couple of [`sbx upgrade mise`](../cli/upgrade) runs across several apps exhausts. The
symptom is a roll that fails mid-way:

```
mise ERROR Failed to install aqua:owner/tool@latest: HTTP status client error
           (403 rate limit exceeded) for url (https://api.github.com/…)
       github auth: no
       github rate limit: 0/60 (core)
```

`github auth: no` is not a misconfiguration: a cage inherits **three** variables from the
host (`TERM`, `LANG`, `LC_ALL`) and nothing else, so a `GITHUB_TOKEN` set in your shell is
correctly invisible inside it. The fix is not to let it in, but to inject it on the wire:

```toml
[secret."api.github.com"]
from   = "env://GITHUB_TOKEN"
header = "Authorization"
type   = "bearer"
```

`env://` is read **host-side**, from sbx's own environment: where your token already is.
The authenticated ceiling is 5000/hour, and it is a *separate* counter from the anonymous
one, so this takes effect immediately rather than at the next hourly reset. Verify it from
inside a cage:

```sh
$ sbx run -- curl -sS https://api.github.com/rate_limit
{"resources":{"core":{"limit":5000,"used":0,"remaining":5000, …
```

`"limit": 5000` means the header arrived; `60` means it did not: check that the cage is
under a filtering `network` posture (the proxy is what injects) and that its allowlist
reaches `api.github.com`.

**Scope it deliberately.** Declared globally, every cage whose allowlist reaches that host
has its requests authenticated *as you*. It still never sees the token, but it acts with
your identity on that API within whatever its allowlist permits. Put the block in a single
app profile (below) to narrow that to one tool.

## Per-app secrets

An `[app.<name>.secret]` section declares credentials for that app, gated and
effective the same way. Since an app's home is isolated and its egress bounded, a
credential is injected on the wire to the allowlisted host and never persists in the
cage. An app that opens a filtering posture over a non-filtering baseline still inherits
the baseline's declared credentials (re-judged under its own posture): the effective set
is re-derived from what was declared, not from what the baseline posture cleared. See
[`[app.<name>]`](apps) and [the app framework](../apps/).

## Viewing

```sh
sbx config show           # "secrets: N injected host-side" (the value is never shown)
sbx config show --details # each credential by destination host, source, and whether it is optional
sbx test net <url>        # notes a declared injection for that host (by header/source)
```
