---
title: "`groq` — Groq"
sidebar_label: "groq"
description: "Groq's low-latency hosted API."
sidebar_position: 16
---

# `groq` — Groq

Groq's low-latency hosted API. The mechanics, posture, and scoping are in [the shared page](../); this page only adds what is specific to Groq.

```toml
[secret."api.groq.com/openai/v1/*"]
from   = "env://GROQ_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export GROQ_API_KEY=…
```

## Specifics

- **Host:** `api.groq.com`, path `/openai/v1`; the binding opencode ships is `https://api.groq.com/openai/v1`.
- **Variable:** `GROQ_API_KEY` — the env var both the SDK and the docs use.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default — without `/*` the block never matches anything.
- **Reference:** [https://console.groq.com/docs/models](https://console.groq.com/docs/models)

## Verifying

```sh
sbx run -- curl -sS https://api.groq.com/openai/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did not — check the filtering posture and that the allowlist reaches the host (see the shared page).

---

*This page is generated from `examples/secrets/groq/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
