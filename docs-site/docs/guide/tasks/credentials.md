---
description: "`secret` and `encode`: giving an operation a credential its caller never sees."
---

# Task credentials

A [declared operation](./) exists to run a command with a credential its caller never
holds. Two forms: the value reaches the task cage's environment, or it never enters any
cage at all.

See also: [Declared operations](./) · [Parameters](parameters) · [Output](output) ·
[`[secret]`](../configuration/secret) · [Secrets](../secrets/).

## In the command's environment

The key **is** the environment variable, so the name a substituted value is reported under is the
name the declaration already gives it:

```toml
[task.db-query.secret]
# terse: a resolver ref, or a bare key expanded through `[secret.defaults]`
PGPASSWORD = "sops://secrets.enc.yaml#db.password"

# table: adds an encoding and a description
[task.api-call.secret]
API_TOKEN = { from = "env://UPSTREAM_TOKEN", encode = "base64", description = "upstream API token" }
```

`encode` is `raw` (default), `base64`, `url`, or `json-string`. The set is closed on purpose: each
encoding registers the form it produces with the substituter, so a value can never reach the output
in a spelling sbx does not recognise.

Sources are the ones the rest of the product speaks: `env://`, `file://`, `sops://file#key`, and any
installed resolver plugin's scheme. They are resolved **per invocation**, never held for the session.

## Wire-injected credentials (the strongest form)

When the operation is an HTTP call, the credential need not enter the task cage at all: this task's
own proxy injects it on the wire, and the command runs knowing nothing:

```toml
[task.gh-issue]
cmd     = ["curl", "-sS", "https://api.github.com/repos/{repo}/issues"]
params  = { repo = "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$" }
network = ["api.github.com"]

[task.gh-issue.inject."api.github.com"]
from   = "sops://secrets.enc.yaml#github.token"
header = "Authorization"
type   = "bearer"
```

An `inject` entry requires `network` reaching that host: the injection happens in the task's proxy,
which only exists when the task has egress, so the pair is refused rather than silently doing
nothing.

**Each invocation gets its own proxy**, never the session's. That is a requirement, not tidiness:
with no per-process identity (the cage runs same-uid), a shared proxy could not tell a task's
connection from the agent's, so a task credential registered in the session's injection table would
be reachable by the agent simply requesting that host.
