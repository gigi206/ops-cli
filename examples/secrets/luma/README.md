# `luma` — Luma (Dream Machine)

Luma's image/video generation API (Dream Machine). The shared mechanics,
posture, and scoping are in [the shared page](../README.md); this page only
adds what is specific to Luma.

```toml
[secret."api.lumalabs.ai/*"]
from   = "env://LUMA_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export LUMA_API_KEY=…
```

## Specifics

- **Host:** `api.lumalabs.ai`, `dream-machine` surface at
  `/dream-machine/v1/…` (`/generations`, keyed by a generation ID — submit
  first, then poll the status).
- **Variable:** `LUMA_API_KEY` — the key mints from the Dream Machine API
  page (`lumalabs.ai/dream-machine/api/keys`, format `luma-…`) and travels as
  `Authorization: Bearer`. Newer Luma Platforms use a different portal and
  base — if yours is a platform key, point this host/block at it instead.
- **Verify note:** a `GET …/dream-machine/v1/generations` without the header
  returns `401` — with it, `200` and the (possibly empty) history: a cheap,
  side-effect-free check.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): without
  it the block never matches beneath the base path.
- **Reference:** <https://docs.lumalabs.ai/docs/api>

## Verifying

```sh
sbx run -- curl -sS https://api.lumalabs.ai/dream-machine/v1/generations
```

A `200` means the header arrived (possibly empty history); a `401` means it
did not — check the filtering posture and that the allowlist reaches the host
(see the shared page).