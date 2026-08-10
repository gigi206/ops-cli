# `ollama` — Ollama (cloud)

Ollama's hosted cloud API. The mechanics, posture, and scoping are in [the shared page](../README.md); this page only adds what is specific to Ollama.

```toml
[secret."ollama.com/v1/*"]
from   = "env://OLLAMA_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export OLLAMA_API_KEY=…
```

## Specifics

- **Host:** `ollama.com`, OpenAI-compatible layer at `/v1` (the native API lives at `/api` — same key, same header, add the block if the cage reaches it).
- **Variable:** `OLLAMA_API_KEY` — the env var the official docs and SDKs use (`Authorization: Bearer $OLLAMA_API_KEY`).
- **Local runtime:** the in-cage daemon (`localhost:11434`) needs **no** credential — the cloud model list it may proxy is covered by this host's block instead.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): without it the block never matches beneath the base path.
- **Reference:** <https://docs.ollama.com/cloud> · <https://ollama.com/settings/keys>

## Verifying

```sh
sbx run -- curl -sS https://ollama.com/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did not — check the filtering posture and that the allowlist reaches the host (see the shared page).