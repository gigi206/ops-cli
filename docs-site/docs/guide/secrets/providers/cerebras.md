---
title: "`cerebras`: Cerebras"
sidebar_label: "cerebras"
description: "Cerebras' hosted API (Wafer-Scale inference)."
sidebar_position: 6
---

# `cerebras`: Cerebras

Cerebras' hosted API (Wafer-Scale inference). The mechanics, posture, and scoping are in [the shared page](../); this page only adds what is specific to Cerebras.

```toml
[secret."api.cerebras.ai/v1/*"]
from   = "env://CEREBRAS_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export CEREBRAS_API_KEY=…
```

## Specifics

- **Host:** `api.cerebras.ai`, path `/v1`; the binding opencode ships is `https://api.cerebras.ai/v1`.
- **Variable:** `CEREBRAS_API_KEY`, the env var both the SDK and the docs use.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default, without `/*` the block never matches anything.
- **Reference:** [https://inference-docs.cerebras.ai/models/overview](https://inference-docs.cerebras.ai/models/overview)

## Verifying

```sh
sbx run -- curl -sS https://api.cerebras.ai/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did not: check the filtering posture and that the allowlist reaches the host (see the shared page).

---

*This page is generated from `examples/secrets/cerebras/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
