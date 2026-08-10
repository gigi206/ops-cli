# `meta-ai` — Meta (Model API) API)

Meta's paid developer API for its flagship models (Muse Spark) — distinct from
the Llama API page (`llama/`), which is a different surface and a different
key. The mechanics, posture, and scoping are in [the shared
page](../README.md); this page only adds what is specific to Meta.

```toml
[secret."api.meta.ai/v1/*"]
from   = "env://MODEL_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export MODEL_API_KEY=…
```

## Specifics

- **Host:** `api.meta.ai`, OpenAI-compatible surface at `/v1` (chat
  completions, Responses, `/models`).
- **Variable:** `MODEL_API_KEY` — the env var the official SDKs read by
  default (`Authorization: Bearer $MODEL_API_KEY`; key format `LLM|…`). Not
  `META_MODEL_API_KEY`, despite what aggregator catalogs call it.
- **Trade-off:** several of Meta's own SDKs *don't* auto-read `MODEL_API_KEY`
  (only OpenAI SDK compatibility layer) — the proxy injects on the wire
  regardless of what the client sends, so the constraint above is not a
  blocker: any client that lets you set a *base URL* only works with this
  block.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): without
  it the block never matches beneath the base path.
- **Reference:** <https://dev.meta.ai/>

## Verifying

```sh
sbx run -- curl -sS https://api.meta.ai/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did
not — check the filtering posture and that the allowlist reaches the host (see
the shared page).