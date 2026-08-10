# `mistral` — Mistral AI

Mistral's hosted API (api.mistral.ai, their `@ai-sdk/mistral` base). The
mechanics, posture, and scoping are in [the shared page](../README.md); this
page only adds what is specific to Mistral.

```toml
[secret."api.mistral.ai/v1/*"]
from   = "env://MISTRAL_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export MISTRAL_API_KEY=…
```

## Specifics

- **Host:** `api.mistral.ai`, OpenAI-style `/v1` layout (`/v1/chat/completions`,
  `/v1/models`, …). The `v1/*` subtree covers the API and nothing else.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real
  requests live one segment below `/v1`, and a path rule matches exactly by
  default — without `/*` the block never matches anything.
- **Variable:** `MISTRAL_API_KEY`, Mistral's own binding (the one opencode and
  the docs both use). Mistral also offers an account login — the injected path
  is for the API **key**, not the OAuth account.

## Verifying

```sh
sbx run -- curl -sS https://api.mistral.ai/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did
not — check the filtering posture and that the allowlist reaches the host (see
the shared page).