---
title: "`minimax`: MiniMax"
sidebar_label: "minimax"
description: "MiniMax's hosted API."
sidebar_position: 24
---

# `minimax`: MiniMax

MiniMax's hosted API. The mechanics, posture, and scoping are in [Secrets](../); this page only adds what is specific to MiniMax.

```toml
[secret."api.minimax.io/v1/*"]
from   = "env://MINIMAX_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export MINIMAX_API_KEY=…
```

## Specifics

- **Host:** `api.minimax.io`, paths `/v1` (OpenAI-compatible) and `/anthropic/v1` (Anthropic-compatible): one key, one header, both.
- **Variable:** `MINIMAX_API_KEY`, the API key from Account Management > API Keys.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default; without `/*` the block never matches anything.
- **Reference:** [https://platform.minimax.io/docs/api-reference](https://platform.minimax.io/docs/api-reference)

## Verifying

```sh
sbx run -- curl -sS https://api.minimax.io/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did not: check the filtering posture and that the allowlist reaches the host (see [Secrets](../)).

---

*This page is generated from `examples/secrets/minimax/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
