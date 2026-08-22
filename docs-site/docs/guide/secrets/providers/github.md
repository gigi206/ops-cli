---
title: "`github`: the GitHub API"
sidebar_label: "github"
description: "The credential sbx most often needs is a GitHub token: the GitHub API ratelimits anonymous clients to 60 requests an hour per IP, which a few import or upgrade rolls exhausts (403 rate limit exceeded, github rate limit: 0/60)."
sidebar_position: 13
---

# `github`: the GitHub API

The credential sbx most often needs is a GitHub token: the GitHub API
ratelimits anonymous clients to 60 requests an hour per IP, which a few import
or upgrade rolls exhausts (`403 rate limit exceeded`, `github rate limit:
0/60`). The fix is not to hand the token to the tool but to have the egress
proxy inject it on the wire: how injection works, when it injects, and how to
scope it are in [Secrets](../); this page only adds what is
specific to GitHub.

```toml
[secret."api.github.com"]
from   = "env://GITHUB_TOKEN"
header = "Authorization"
type   = "bearer"
```

Set the token in your shell, exactly as the `from` names it:

```sh
export GITHUB_TOKEN=ghp_…
```

## Specifics

- **Host:** `api.github.com`: both classic PATs (`ghp_…`) and fine-grained
  tokens are accepted as `Bearer` values.
- **Gateway:** the `defaults` table in your config can carry the
  `header = "Authorization"` / `type = "bearer"` pair once, and the entry
  keeps only its host and source.
- **Scope:** declared globally, this block authenticates every cage whose
  allowlist reaches `api.github.com`: including the mise `aqua:` / `github`
  backends that resolve tool releases against this API.

## Verifying

```sh
sbx run -- curl -sS https://api.github.com/rate_limit
```

`"limit": 5000` (the authenticated ceiling, a separate counter from the
anonymous 60/hour) means the header arrived; `60` means it did not; the cage
must be under a filtering network posture and its allowlist must reach
`api.github.com` (see [Secrets](../)).

---

*This page is generated from `examples/secrets/github/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
