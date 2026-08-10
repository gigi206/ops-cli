# `zhipuai` — ZhipuAI (GLM)

ZhipuAI's big-model platform. The mechanics, posture, and scoping are in [the shared page](../README.md); this page only adds what is specific to ZhipuAI.

```toml
[secret."open.bigmodel.cn/api/paas/v4/*"]
from   = "env://ZHIPU_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export ZHIPU_API_KEY=…
```

## Specifics

- **Host:** `open.bigmodel.cn`, path `/api/paas/v4` (Chinese mainland platform). The international GLM API is `api.z.ai` — see the [Z.AI page](../zai/), same `ZHIPU_API_KEY` works for both.
- **Variable:** `ZHIPU_API_KEY` — the API key shown in the platform console.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default — without `/*` the block never matches anything.
- **Reference:** <https://open.bigmodel.cn/dev/howuse/glm-4>

## Verifying

```sh
sbx run -- curl -sS https://open.bigmodel.cn/api/paas/v4/models
```

A `200` with the model listing means the header arrived; a `401` means it did not — check the filtering posture and that the allowlist reaches the host (see the shared page).