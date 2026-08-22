---
title: "`moonshot`: Moonshot AI"
sidebar_label: "moonshot"
description: "Moonshot AI's Kimi API."
sidebar_position: 26
---

# `moonshot`: Moonshot AI

Moonshot AI's Kimi API. The mechanics, posture, and scoping are in [Secrets](../); this page only adds what is specific to Moonshot AI.

```toml
[secret."api.moonshot.ai/v1/*"]
from   = "env://MOONSHOT_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export MOONSHOT_API_KEY=…
```

## Specifics

- **Host:** `api.moonshot.ai`, path `/v1`; the binding opencode ships is `https://api.moonshot.ai/v1`.
- **Variable:** `MOONSHOT_API_KEY`, the env var both the SDK and the docs use.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default; without `/*` the block never matches anything.

## Verifying

```sh
sbx run -- curl -sS https://api.moonshot.ai/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did not: check the filtering posture and that the allowlist reaches the host (see [Secrets](../)).

---

*This page is generated from `examples/secrets/moonshot/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
