---
title: "`stepfun-ai`: StepFun (Global)"
sidebar_label: "stepfun-ai"
description: "StepFun's hosted API (Step models)."
sidebar_position: 34
---

# `stepfun-ai`: StepFun (Global)

StepFun's hosted API (Step models). The mechanics, posture, and scoping are in [Secrets](../); this page only adds what is specific to StepFun (Global).

```toml
[secret."api.stepfun.ai/v1/*"]
from   = "env://STEPFUN_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export STEPFUN_API_KEY=…
```

## Specifics

- **Host:** `api.stepfun.ai`, path `/v1`; the binding opencode ships is `https://api.stepfun.ai/v1`.
- **Variable:** `STEPFUN_API_KEY`, the env var both the SDK and the docs use.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default; without `/*` the block never matches anything.
- **Reference:** [https://platform.stepfun.ai/docs/en/overview/concept](https://platform.stepfun.ai/docs/en/overview/concept)

## Verifying

```sh
sbx run -- curl -sS https://api.stepfun.ai/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did not: check the filtering posture and that the allowlist reaches the host (see [Secrets](../)).

---

*This page is generated from `examples/secrets/stepfun-ai/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
