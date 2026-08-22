---
title: "`alibaba-cn` — Alibaba (Qwen, China)"
sidebar_label: "alibaba-cn"
description: "Qwen's China-hosted surface — same provider family as alibaba/, but the domestic endpoint (dashscope.aliyuncs.com, mainland)."
sidebar_position: 2
---

# `alibaba-cn` — Alibaba (Qwen, China)

Qwen's China-hosted surface — same provider family as `alibaba/`, but the
**domestic** endpoint (`dashscope.aliyuncs.com`, mainland). The shared
mechanics, posture, and scoping are in [the shared page](../).

```toml
[secret."dashscope.aliyuncs.com/compatible-mode/v1/*"]
from   = "env://DASHSCOPE_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export DASHSCOPE_API_KEY=…
```

## Specifics

- **Host:** `dashscope.aliyuncs.com`, OpenAI-compatible layer at
  `/compatible-mode/v1` — the international twin `dashscope-intl.aliyuncs.com`
  is covered by the `alibaba/` page; **the key is the same**, only the
  destination differs (pick the block the reachable host needs).
- **Variable:** `DASHSCOPE_API_KEY` — the env var the official
  DashScope Key from the console, same key both sides (intl/CN).
- **Trailing `/*` is load-bearing** (same rule as the opencode page): without
  it the block never matches beneath the base path.
- **Reference:** [https://help.aliyun.com/zh/model-studio/](https://help.aliyun.com/zh/model-studio/) (DashScope)

## Verifying

```sh
sbx run -- curl -sS https://dashscope.aliyuncs.com/compatible-mode/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did
not — check the filtering posture and that the allowlist reaches the host (see
the shared page).

---

*This page is generated from `examples/secrets/alibaba-cn/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
