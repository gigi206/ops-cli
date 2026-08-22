---
title: "`fireworks-ai`: Fireworks AI"
sidebar_label: "fireworks-ai"
description: "Fireworks AI's serverless models."
sidebar_position: 11
---

# `fireworks-ai`: Fireworks AI

Fireworks AI's serverless models. The mechanics, posture, and scoping are in [the shared page](../); this page only adds what is specific to Fireworks AI.

```toml
[secret."api.fireworks.ai/inference/v1/*"]
from   = "env://FIREWORKS_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export FIREWORKS_API_KEY=…
```

## Specifics

- **Host:** `api.fireworks.ai`, path `/inference/v1`; the binding opencode ships is `https://api.fireworks.ai/inference/v1/`.
- **Variable:** `FIREWORKS_API_KEY`, the env var both the SDK and the docs use.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default, without `/*` the block never matches anything.
- **Reference:** [https://fireworks.ai/docs/](https://fireworks.ai/docs/)

## Verifying

```sh
sbx run -- curl -sS https://api.fireworks.ai/inference/v1//models
```

A `200` with the model listing means the header arrived; a `401` means it did not: check the filtering posture and that the allowlist reaches the host (see the shared page).

---

*This page is generated from `examples/secrets/fireworks-ai/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
