# `zai` — Z.AI (GLM, ex-Zhipu)

Z.AI's hosted GLM models: an OpenAI-compatible API (`api.z.ai`), one key for
both plans. The mechanics, posture, and scoping are in [the shared
page](../README.md); this page only adds what is specific to Z.AI.

```toml
# Z.AI — the standard plan.
[secret."api.z.ai/api/paas/v4/*"]
from   = "env://ZHIPU_API_KEY"
header = "Authorization"
type   = "bearer"
```

```toml
# Z.AI Coding Plan — same host, same key, one route apart.
[secret."api.z.ai/api/coding/paas/v4/*"]
from   = "env://ZHIPU_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export ZHIPU_API_KEY=…
```

## Specifics

- **Host:** `api.z.ai` (Zhipu AI is the company behind the GLM models; this
  binding is opencode's own, read from its provider table). The host also
  answers on `open.bigmodel.cn` (the CN edition) with the same variable.
- **Variable:** `ZHIPU_API_KEY` — the name is the company's historical one,
  not a typo; both routes read it.
- **One key, two plans.** `api/paas/v4` is the standard API,
  `api/coding/paas/v4` the Coding Plan; both take the same `Authorization:
  Bearer` key, so the two blocks differ only in the path.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real
  requests are `/api/paas/v4/chat/completions` and the like, and a path rule
  matches exactly by default — without `/*` the block never matches anything.

If you only use one plan, drop the other block.

## Verifying

```sh
sbx run -- curl -sS https://api.z.ai/api/paas/v4/models
```

A `200` with the model listing means the header arrived; a `401` means it did
not — check the filtering posture and that the allowlist reaches the host (see
the shared page).