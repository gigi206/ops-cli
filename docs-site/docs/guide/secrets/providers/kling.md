---
title: "`kling` — Kling AI (video)"
sidebar_label: "kling"
description: "Kuaishou's video-generation API."
sidebar_position: 20
---

# `kling` — Kling AI (video)

Kuaishou's video-generation API. The shared mechanics, posture, and scoping are
in [the shared page](../); this page only adds what is specific to
Kling.

```toml
[secret."api-singapore.klingai.com/*"]
from   = "env://KLINGAI_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export KLINGAI_API_KEY=…
```

## Specifics

- **Host:** `api-singapore.klingai.com` — the API-key default region prefix
  (Kuaishou serves regional prefixes per account; pick the one your console
  shows and make it the block's host).
- **Variable:** `KLINGAI_API_KEY` — the single-key scheme, which Kuaishou now
  recommends; the legacy scheme (`KLINGAI_ACCESS_KEY`/`KLINGAI_SECRET_KEY`)
  mints a short-lived JWT **per request** — that is Bedrock-style, not
  injectable, and the reasons to prefer the single key.
- **Trailing `/*` is load-bearing** (same rule as theopencode page): without
  it the block never matches beneath the base path.
- **Reference:** [https://kling.ai/document-api/](https://kling.ai/document-api/)

## Verifying

```sh
sbx run -- curl -sS -X POST https://api-singapore.klingai.com/api/v1/videos/text2video \
  -H 'Content-Type: application/json' \
  -d '{"model_name":"kling-v1","prompt":"a red cube","duration":"5s"}'
```

A non-`401` (generation accepted, or a quota/validation error — the key
flowed) proves the header arrived; a `401` means it did not — check the
filtering posture and the allowlist (see the shared page).

---

*This page is generated from `examples/secrets/kling/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
