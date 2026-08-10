# `alibaba` — Alibaba (Qwen)

Alibaba's DashScope platform. The mechanics, posture, and scoping are in [the shared page](../README.md); this page only adds what is specific to Alibaba.

```toml
[secret."dashscope-intl.aliyuncs.com/compatible-mode/v1/*"]
from   = "env://DASHSCOPE_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export DASHSCOPE_API_KEY=…
```

## Specifics

- **Host:** `dashscope-intl.aliyuncs.com`, path `/compatible-mode/v1` (the OpenAI-compatible surface; the platform's own schema lives at `/api/v1` — same host, same key, add the block if the cage reaches it).
- **Variable:** `DASHSCOPE_API_KEY` — the API key from your Alibaba Cloud account.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default — without `/*` the block never matches anything.

## Verifying

```sh
sbx run -- curl -sS https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did not — check the filtering posture and that the allowlist reaches the host (see the shared page).