---
title: "`openrouter`: OpenRouter"
sidebar_label: "openrouter"
description: "the multi-provider router that fronts every major model."
sidebar_position: 31
---

# `openrouter`: OpenRouter

the multi-provider router that fronts every major model. The mechanics, posture, and scoping are in [the shared page](../); this page only adds what is specific to OpenRouter.

```toml
[secret."openrouter.ai/api/v1/*"]
from   = "env://OPENROUTER_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export OPENROUTER_API_KEY=…
```

## Specifics

- **Host:** `openrouter.ai`, path `/api/v1`; the binding opencode ships is `https://openrouter.ai/api/v1`.
- **Variable:** `OPENROUTER_API_KEY`, the env var both the SDK and the docs use.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default, without `/*` the block never matches anything.
- OpenRouter asks clients to send `HTTP-Referer` and `X-Title` for attribution; those are application-level headers, not credentials: they belong in the agent's config, not in `[secret]`.
- **Reference:** [https://openrouter.ai/models](https://openrouter.ai/models)

## Verifying

```sh
sbx run -- curl -sS https://openrouter.ai/api/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did not: check the filtering posture and that the allowlist reaches the host (see the shared page).

---

*This page is generated from `examples/secrets/openrouter/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
