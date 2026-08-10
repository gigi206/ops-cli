# `baseten` — Baseten

Baseten's model inference API. The mechanics, posture, and scoping are in [the shared page](../README.md); this page only adds what is specific to Baseten.

```toml
[secret."inference.baseten.co/v1/*"]
from   = "env://BASETEN_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export BASETEN_API_KEY=…
```

## Specifics

- **Host:** `inference.baseten.co`, path `/v1`; the binding opencode ships is `https://inference.baseten.co/v1`.
- **Variable:** `BASETEN_API_KEY` — the env var both the SDK and the docs use.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): the real requests live below the base path, and a path rule matches exactly by default — without `/*` the block never matches anything.
- **Reference:** <https://docs.baseten.co/inference/model-apis/overview>

## Verifying

```sh
sbx run -- curl -sS https://inference.baseten.co/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did not — check the filtering posture and that the allowlist reaches the host (see the shared page).
