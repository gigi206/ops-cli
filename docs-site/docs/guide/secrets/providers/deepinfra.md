---
title: "`deepinfra`: Deep Infra"
sidebar_label: "deepinfra"
description: "DeepInfra's serverless models."
sidebar_position: 9
---

# `deepinfra`: Deep Infra

DeepInfra's serverless models. The mechanics, posture, and scoping are in [the shared page](../); this page only adds what is specific to Deep Infra.

```toml
[secret."api.deepinfra.com/v1/*"]
from   = "env://DEEPINFRA_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export DEEPINFRA_API_KEY=…
```

## Specifics

- **Host:** `api.deepinfra.com`, path `/v1`; the binding opencode ships is `https://api.deepinfra.com/v1`.
- **Variable:** `DEEPINFRA_API_KEY`, the env var both the SDK and the docs use.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default, without `/*` the block never matches anything.
- **Reference:** [https://deepinfra.com/models](https://deepinfra.com/models)

## Verifying

```sh
sbx run -- curl -sS https://api.deepinfra.com/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did not: check the filtering posture and that the allowlist reaches the host (see the shared page).

---

*This page is generated from `examples/secrets/deepinfra/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
