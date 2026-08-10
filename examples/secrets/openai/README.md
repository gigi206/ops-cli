# `openai` — OpenAI

OpenAI's chat API. The mechanics, posture, and scoping are in [the shared page](../README.md); this page only adds what is specific to OpenAI.

```toml
[secret."api.openai.com/v1/*"]
from   = "env://OPENAI_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export OPENAI_API_KEY=…
```

## Specifics

- **Host:** `api.openai.com`, path `/v1`; the binding opencode ships is `https://api.openai.com/v1`.
- **Variable:** `OPENAI_API_KEY` — the env var both the SDK and the docs use.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default — without `/*` the block never matches anything.
- **Reference:** <https://platform.openai.com/docs/models>

## Verifying

```sh
sbx run -- curl -sS https://api.openai.com/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did not — check the filtering posture and that the allowlist reaches the host (see the shared page).
