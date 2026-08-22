---
title: "`llama` — Meta (Llama API)"
sidebar_label: "llama"
description: "Meta's hosted Llama API."
sidebar_position: 21
---

# `llama` — Meta (Llama API)

Meta's hosted Llama API. The mechanics, posture, and scoping are in [the shared page](../); this page only adds what is specific to Meta.

```toml
[secret."api.llama.com/compat/v1/*"]
from   = "env://LLAMA_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export LLAMA_API_KEY=…
```

## Specifics

- **Host:** `api.llama.com`, path `/compat/v1` (the OpenAI-compatible surface).
- **Variable:** `LLAMA_API_KEY` — the API key issued when you set up a Llama API account.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default — without `/compat/v1/*` the block never matches any request.
- **Reference:** [https://ai.meta.com/llama/api](https://ai.meta.com/llama/api)

## Verifying

```sh
sbx run -- curl -sS https://api.llama.com/compat/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did not — check the filtering posture and that the allowlist reaches the host (see the shared page).

---

*This page is generated from `examples/secrets/llama/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
