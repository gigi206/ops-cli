---
title: "`cohere`: Cohere"
sidebar_label: "cohere"
description: "Cohere's hosted API (Command models)."
sidebar_position: 8
---

# `cohere`: Cohere

Cohere's hosted API (Command models). The mechanics, posture, and scoping are in [the shared page](../); this page only adds what is specific to Cohere.

```toml
[secret."api.cohere.com/v2/*"]
from   = "env://COHERE_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export COHERE_API_KEY=…
```

## Specifics

- **Host:** `api.cohere.com`, path `/v2`; the binding opencode ships is `https://api.cohere.com/v2`.
- **Variable:** `COHERE_API_KEY`, the env var both the SDK and the docs use.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default, without `/*` the block never matches anything.
- **Reference:** [https://docs.cohere.com/docs/models](https://docs.cohere.com/docs/models)

## Verifying

```sh
sbx run -- curl -sS https://api.cohere.com/v2/models
```

A `200` with the model listing means the header arrived; a `401` means it did not: check the filtering posture and that the allowlist reaches the host (see the shared page).

---

*This page is generated from `examples/secrets/cohere/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
