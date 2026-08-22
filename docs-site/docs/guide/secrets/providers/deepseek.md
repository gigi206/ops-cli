---
title: "`deepseek` — DeepSeek"
sidebar_label: "deepseek"
description: "DeepSeek's chat API (DeepSeek-V/R models)."
sidebar_position: 10
---

# `deepseek` — DeepSeek

DeepSeek's chat API (DeepSeek-V/R models). The mechanics, posture, and scoping are in [the shared page](../); this page only adds what is specific to DeepSeek.

```toml
[secret."api.deepseek.com/*"]
from   = "env://DEEPSEEK_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export DEEPSEEK_API_KEY=…
```

## Specifics

- **Host:** `api.deepseek.com`; the binding opencode ships is `https://api.deepseek.com`.
- **Variable:** `DEEPSEEK_API_KEY` — the env var both the SDK and the docs use.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default — without `/*` the block never matches anything.
- **Reference:** [https://api-docs.deepseek.com/quick_start/pricing](https://api-docs.deepseek.com/quick_start/pricing)

## Verifying

```sh
sbx run -- curl -sS https://api.deepseek.com/models
```

A `200` with the model listing means the header arrived; a `401` means it did not — check the filtering posture and that the allowlist reaches the host (see the shared page).

---

*This page is generated from `examples/secrets/deepseek/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
