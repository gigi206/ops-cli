---
title: "`tencent`: Tencent (TokenHub Coding Plan)"
sidebar_label: "tencent"
description: "Tencent Cloud's agent-facing LLM surface (Hunyuan-la family, multi-provider merging)."
sidebar_position: 35
---

# `tencent`: Tencent (TokenHub Coding Plan)

Tencent Cloud's agent-facing LLM surface (Hunyuan-la family, multi-provider
merging). The shared mechanics, posture, and scoping are in [the shared
page](../); this page only adds what is specific to Tencent.

```toml
[secret."api.lkeap.cloud.tencent.com/coding/v3/*"]
from   = "env://TENCENT_CODING_PLAN_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export TENCENT_CODING_PLAN_API_KEY=…
```

## Specifics

- **Host:** `api.lkeap.cloud.tencent.com`, OpenAI-compatible coding surface at
  `/coding/v3` (a `/coding/anthropic` equivalent exists for Anthropic-format
  clients, same host).
- **Variable:** `TENCENT_CODING_PLAN_API_KEY`, the Coding Plan **dedicated**
  key, prefix `sk-sp-…`, minted on the Coding Plan page. Do **not** mix it
  with the pay-as-you-go `sk-…` MaaS key `/tele…` on the same host: Tencent
  refuses the cross-use.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): without
  it the block never matches beneath the base path.
- **Reference:** [https://cloud.tencent.com/document/product/1823/130092](https://cloud.tencent.com/document/product/1823/130092)

## Verifying

```sh
sbx run -- curl -sS https://api.lkeap.cloud.tencent.com/coding/v3/models
```

A `200` with the model listing means the header arrived; a `401` means it did
not: check the filtering posture and that the allowlist reaches the host (see
the shared page).

---

*This page is generated from `examples/secrets/tencent/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
