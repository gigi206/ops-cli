---
title: "`togetherai`: Together AI"
sidebar_label: "togetherai"
description: "Together AI's hosted models."
sidebar_position: 36
---

# `togetherai`: Together AI

Together AI's hosted models. The mechanics, posture, and scoping are in [Secrets](../); this page only adds what is specific to Together AI.

```toml
[secret."api.together.xyz/v1/*"]
from   = "env://TOGETHER_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export TOGETHER_API_KEY=…
```

## Specifics

- **Host:** `api.together.xyz`, path `/v1`; the binding opencode ships is `https://api.together.xyz/v1`.
- **Variable:** `TOGETHER_API_KEY`, the env var both the SDK and the docs use.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default; without `/*` the block never matches anything.
- The binding opencode ships uses `api.together.xyz` (the `together.ai` alias serves the same API).
- **Reference:** [https://docs.together.ai/docs/serverless-models](https://docs.together.ai/docs/serverless-models)

## Verifying

```sh
sbx run -- curl -sS https://api.together.xyz/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did not: check the filtering posture and that the allowlist reaches the host (see [Secrets](../)).

---

*This page is generated from `examples/secrets/togetherai/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
