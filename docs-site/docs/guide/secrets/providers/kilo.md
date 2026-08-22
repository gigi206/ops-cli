---
title: "`kilo` — Kilo (AI Gateway)"
sidebar_label: "kilo"
description: "Kilo Code's aggregator gateway — hundreds of models behind one OpenAI-compatible endpoint."
sidebar_position: 18
---

# `kilo` — Kilo (AI Gateway)

Kilo Code's aggregator gateway — hundreds of models behind one OpenAI-compatible
endpoint. The shared mechanics, posture, and scoping are in [the shared
page](../); this page only adds what is specific to Kilo.

```toml
[secret."api.kilo.ai/api/gateway/*"]
from   = "env://KILO_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export KILO_API_KEY=…
```

## Specifics

- **Host:** `api.kilo.ai`, gateway at `/api/gateway` (OpenAI-compatible) —
  model IDs use the `provider/model` scheme (`anthropic/claude-sonnet-4.6`,
  `openai/gpt-5.4`, `deepseek/deepseek-v3.2`, …).
- **Variable:** `KILO_API_KEY` — the bearer key from the Kilo dashboard (keys
  are JWTs bound to your account).
- **BYOK caveat:** the gateway can route *your own* provider keys (encrypted
  at rest, on Kilo's side). Whatever routing you configure, the wire-authent
  the gateway itself is always `Authorization: Bearer $KILO_API_KEY` — the
  upstream provider keys never pass through the cage.
- **Model listing note:** `GET /api/gateway/models` is **public** (no auth) —
  it is friendly for discovery but proves nothing about the header; only a
  `POST /api/gateway/chat/completions` exercises the credential.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): without
  it the block never matches beneath the base path.
- **Reference:** [https://kilo.ai/docs/gateway](https://kilo.ai/docs/gateway)

## Verifying

```sh
sbx run -- curl -sS -X POST https://api.kilo.ai/api/gateway/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"openai/gpt-5.4-mini","messages":[{"role":"user","content":"hi"}]}'
```

A `200` (or `402`/`429` — the key **flowed**, just not enough credits) means
the header arrived; a `401` means it did not — check the filtering posture and
that the allowlist reaches the host (see the shared page).

---

*This page is generated from `examples/secrets/kilo/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
