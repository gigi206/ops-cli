---
title: "`anthropic` — Anthropic"
sidebar_label: "anthropic"
description: "Anthropic's Claude API."
sidebar_position: 3
---

# `anthropic` — Anthropic

Anthropic's Claude API. The mechanics, posture, and scoping are in [the shared page](../); this page only adds what is specific to Anthropic.

```toml
[secret."api.anthropic.com/v1/*"]
from   = "env://ANTHROPIC_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export ANTHROPIC_API_KEY=…
```

## Specifics

- **Host:** `api.anthropic.com`, path `/v1`; the binding opencode ships is `https://api.anthropic.com/v1`.
- **Variable:** `ANTHROPIC_API_KEY` — the env var both the SDK and the docs use.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default — without `/*` the block never matches anything.
- **Reference:** [https://docs.anthropic.com/en/docs/about-claude/models](https://docs.anthropic.com/en/docs/about-claude/models)

## Verifying

```sh
sbx run -- curl -sS https://api.anthropic.com/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did not — check the filtering posture and that the allowlist reaches the host (see the shared page).

---

*This page is generated from `examples/secrets/anthropic/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
