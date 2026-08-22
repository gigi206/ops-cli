---
title: "`bytedance`: ByteDance (Volcengine Ark / Doubao)"
sidebar_label: "bytedance"
description: "ByteDance's model platform (Volcano Engine Ark), serving the Doubao family and third-party models."
sidebar_position: 5
---

# `bytedance`: ByteDance (Volcengine Ark / Doubao)

ByteDance's model platform (Volcano Engine Ark), serving the Doubao family and
third-party models. The shared mechanics, posture, and scoping are in [the
shared page](../); this page only adds what is specific to ByteDance.

```toml
[secret."ark.cn-beijing.volces.com/api/v3/*"]
from   = "env://ARK_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export ARK_API_KEY=…
```

## Specifics

- **Host:** `ark.cn-beijing.volces.com`, OpenAI-compatible layer at
  `/api/v3`, the Ark console's API-key page is where the key comes from
  (shown once at creation). A `/api/coding` variant serves the coding Plan
  (`docker` tooling) on the same host.
- **Variable:** `ARK_API_KEY`, the env var the official SDK/guides use
  (`Authorization: Bearer $ARK_API_KEY`).
- **Regions:** the Ark key and model provisioning are per-platform and
  per-region; the international counterpart (BytePlus ModelArk) lives at
  `ark.ap-southeast.bytepluses.com`, a separate host, add its own block if
  the cage reaches it.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): without
  it the block never matches beneath the base path.
- **Reference:** [https://www.volcengine.com/docs/82379](https://www.volcengine.com/docs/82379) (Ark / Doubao)

## Verifying

```sh
sbx run -- curl -sS https://ark.cn-beijing.volces.com/api/v3/models
```

A `200` with the model listing means the header arrived; a `401` means it did
not: check the filtering posture and that the allowlist reaches the host (see
the shared page).

---

*This page is generated from `examples/secrets/bytedance/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
