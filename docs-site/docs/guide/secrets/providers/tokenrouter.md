---
title: "`tokenrouter` — TokenRouter"
sidebar_label: "tokenrouter"
description: "the aggregator that re-exposes its model catalogue behind OpenAI-, Anthropic-, and Gemini-compatible endpoints."
sidebar_position: 37
---

# `tokenrouter` — TokenRouter

the aggregator that re-exposes its model catalogue behind OpenAI-, Anthropic-, and Gemini-compatible endpoints. The mechanics, posture, and scoping are in [the shared page](../); this page only adds what is specific to TokenRouter.

```toml
[secret."api.tokenrouter.com/v1/*"]
from   = "env://TOKENROUTER_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export TOKENROUTER_API_KEY=…
```

## Specifics

- **Host:** `api.tokenrouter.com`, path `/v1`; the base URL the service documents is `https://api.tokenrouter.com/v1`. Model IDs use the `provider/model` scheme (`qwen/qwen3.8-max-free`, …).
- **Variable:** `TOKENROUTER_API_KEY` — sbx's name, not the service's. TokenRouter documents the base URL a client points at and calls the credential "your TokenRouter API key" without naming an environment variable, so this page follows the `<PROVIDER>_API_KEY` convention the rest of the catalogue uses. The `from` is the only place the name is read; rename it on both sides if your shell already holds the key elsewhere.
- **What the block replaces.** The getting-started snippet the service publishes is the stock OpenAI client with the base URL swapped and the key passed inline as a literal — the credential living in source the agent can read. Under this block the snippet runs unchanged with no *real* key in it: sbx's header is authoritative, so whatever the client sends is stripped and replaced, and the `api_key` argument only has to be non-empty for the client to accept it.
- **Trailing `/*` is load-bearing** (same rule as the openrouter page): the real requests live below the base path, and a path rule matches exactly by default — without `/*` the block never matches anything.
- **One block covers every API shape.** The OpenAI-compatible route (`/v1/chat/completions`) and the Anthropic-compatible one (`/v1/messages`) both sit under `/v1` and both accept the credential in `Authorization`, so the single subtree rule authenticates all of them. The service also reads a key from `x-api-key`; `Authorization` is the one to declare, because `type = "bearer"` shapes exactly that header and one credential per destination is enough.
- **A near-homonym exists.** The `tokenrouter` package on PyPI is *not* this service: it defaults to `api.tokenrouter.io/v1`, another host under another domain. This page is `tokenrouter.com` only, and a rule naming one host never reaches the other — so keep the section name literal and take the base URL from the reference below rather than from a same-named SDK.
- **Reference:** [https://www.tokenrouter.com/docs/](https://www.tokenrouter.com/docs/)

## Verifying

```sh
sbx run -- curl -sS https://api.tokenrouter.com/v1/models
```

This listing reads the credential — a syntactically valid but wrong `Bearer` answers `401 Invalid token` on it — so unlike the Kilo gateway's public listing, a `200` here does prove the header arrived. On a failure, read the **body** and not only the status: TokenRouter answers `401` for three different situations and only the first is an injection problem.

| Body | Meaning |
|---|---|
| `Token not provided` | nothing was injected — check the filtering posture and that the allowlist reaches the host (see the shared page) |
| `Invalid token` | the header arrived and the value was rejected — the injection works, the key does not |
| a quota message quoting the key masked (`sk-…***…`) | the header arrived and the key was recognised down to its account — the injection works, the account has no budget left |

The quota refusal precedes model routing, so it answers the same way for a free model as for a paid one. A credential-less `GET /v1/models` answers `400` rather than `401`, which is one more way to read "nothing was injected".

---

*This page is generated from `examples/secrets/tokenrouter/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
