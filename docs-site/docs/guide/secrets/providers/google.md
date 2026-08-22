---
title: "`google` — Google"
sidebar_label: "google"
description: "Google's Gemini API (generative language)."
sidebar_position: 15
---

# `google` — Google

Google's Gemini API (generative language). The mechanics, posture, and scoping are in [the shared page](../); this page only adds what is specific to Google.

```toml
[secret."generativelanguage.googleapis.com/v1beta/*"]
from   = "env://GEMINI_API_KEY"
header = "x-goog-api-key"
type   = "raw"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export GEMINI_API_KEY=…
```

## Specifics

- **Host:** `generativelanguage.googleapis.com`, path `/v1beta`; the binding opencode ships is `https://generativelanguage.googleapis.com/v1beta`.
- **Variable:** `GEMINI_API_KEY` — the env var both the SDK and the docs use.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default — without `/*` the block never matches anything.
- The SDK accepts `GOOGLE_API_KEY`, `GOOGLE_GENERATIVE_AI_API_KEY` or `GEMINI_API_KEY`; this page pins `GEMINI_API_KEY`. The key rides the SDK's own `x-goog-api-key` header, so this is a `raw` secret, not a bearer.
- **Reference:** [https://ai.google.dev/gemini-api/docs/models](https://ai.google.dev/gemini-api/docs/models)

## Verifying

```sh
sbx run -- curl -sS https://generativelanguage.googleapis.com/v1beta/models
```

A `200` with the model listing means the header arrived; a `401` means it did not — check the filtering posture and that the allowlist reaches the host (see the shared page).

---

*This page is generated from `examples/secrets/google/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
