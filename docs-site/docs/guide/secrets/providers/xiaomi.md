---
title: "`xiaomi` — Xiaomi (MiMo)"
sidebar_label: "xiaomi"
description: "Xiaomi's model API, OpenAI-compatible."
sidebar_position: 40
---

# `xiaomi` — Xiaomi (MiMo)

Xiaomi's model API, OpenAI-compatible. The shared mechanics, posture, and
scoping are in [the shared page](../); this page only adds what is
specific to Xiaomi.

```toml
[secret."api.xiaomimimo.com/v1/*"]
from   = "env://MIMO_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export MIMO_API_KEY=…
```

## Specifics

- **Host:** `api.xiaomimimo.com`, OpenAI-compatible layer at `/v1` (a
  `/anthropic` variant exists on the same host).
- **Variable:** `MIMO_API_KEY` — the env var the official docs and SDKs use.
  Two credential flavours exist, refuse to mix them: pay-as-you-go `sk-…`
  (`api.xiaomimimo.com`) and Token Plan `tp-…`
  (`token-plan-cn.xiaomimimo.com`, per-plan host — second block if needed).
- **Either header:** the official API accepts both `api-key: $MIMO_API_KEY`
  and `Authorization: Bearer $MIMO_API_KEY` — this page pins the standard
  `bearer`/`Authorization` shape, which the proxy prefers.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): without
  it the block never matches beneath the base path.
- **Reference:** [https://mimo.mi.com/docs/en-US/api/chat/openai-api](https://mimo.mi.com/docs/en-US/api/chat/openai-api)

## Verifying

```sh
sbx run -- curl -sS https://api.xiaomimimo.com/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did
not — check the filtering posture and that the allowlist reaches the host (see
the shared page).

---

*This page is generated from `examples/secrets/xiaomi/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
