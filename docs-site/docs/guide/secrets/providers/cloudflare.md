---
title: "`cloudflare` — Cloudflare (Workers AI)"
sidebar_label: "cloudflare"
description: "Cloudflare's model inference on the edge (Workers AI @cf/ models and third-party models routed through AI Gateway)."
sidebar_position: 7
---

# `cloudflare` — Cloudflare (Workers AI)

Cloudflare's model inference on the edge (Workers AI `@cf/*` models and
third-party models routed through AI Gateway). The mechanics, posture, and
scoping are in [the shared page](../); this page only adds what is
specific to Cloudflare.

```toml
[secret."api.cloudflare.com/client/v4/accounts/*/ai/v1/*"]
from   = "env://CLOUDFLARE_API_TOKEN"
header = "Authorization"
type   = "bearer"
```

Set the token in your shell, exactly as the `from` names it:

```sh
export CLOUDFLARE_API_TOKEN=…
```

## Specifics

- **Host:** `api.cloudflare.com`, OpenAI-compatible surface at
  `/client/v4/accounts/{account_id}/ai/v1` — the **account ID lives in the
  URL**, so the destination wildcard pins it to the path the client uses, not
  to the credential.
- **Variable:** `CLOUDFLARE_API_TOKEN` — an API token (never your Global API
  key) with **Account › Workers AI › Read** permission; a token holding only
  AI Gateway permission is refused (`401`, error `10000`).
- **Routing:** the outer `*` absorbs the account ID segment; requests to
  `gateway.ai.cloudflare.com` (provider-native endpoints) are a different host
  — separate block, and there the credential travels as `cf-aig-authorization`
  (`header = "cf-aig-authorization"`, `type = "bearer"`) rather than
  `Authorization`.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): without
  it the block never matches beneath the base path.
- **Reference:** [https://developers.cloudflare.com/workers-ai/configuration/open-ai-compatibility/](https://developers.cloudflare.com/workers-ai/configuration/open-ai-compatibility/)

## Verifying

```sh
sbx run -- curl -sS https://api.cloudflare.com/client/v4/accounts/YOUR_ACCOUNT_ID/ai/v1/models
```

A `200` with the model listing means the header arrived; a `401` (error
`10000`) means it did not — check the filtering posture and that the
allowlist reaches the host (see the shared page).

---

*This page is generated from `examples/secrets/cloudflare/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
