---
title: "`ovhcloud`: OVHcloud (AI Endpoints)"
sidebar_label: "ovhcloud"
description: "OVHcloud's hosted model API (European, sovereign cloud)."
sidebar_position: 32
---

# `ovhcloud`: OVHcloud (AI Endpoints)

OVHcloud's hosted model API (European, sovereign cloud). The shared mechanics,
posture, and scoping are in [Secrets](../); this page only
adds what is specific to OVHcloud.

```toml
[secret."oai.endpoints.kepler.ai.cloud.ovh.net/v1/*"]
from   = "env://OVHCLOUD_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export OVHCLOUD_API_KEY=…
```

## Specifics

- **Host:** `oai.endpoints.kepler.ai.cloud.ovh.net`, OpenAI-compatible layer at
  `/v1` (chat completions, embeddings, …).
- **Variable:** `OVHCLOUD_API_KEY`, API key created in the Public Cloud panel
  (AI Endpoints → API keys), the env var the official integration guides read.
- **Anonymous mode:** OVH serves requests without a key too (rate-limited).
  You only *need* a `[secret]` block once you own a key: without one, no
  header is injected and requests go out as guest. Whatever you choose, keep
  the two out of sync: this block exists for the authenticated mode.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): without
  it the block never matches beneath the base path.
- **Reference:** [https://docs.ovhcloud.com/en/guides/public-cloud/ai-machine-learning/ai-endpoints/](https://docs.ovhcloud.com/en/guides/public-cloud/ai-machine-learning/ai-endpoints/)

## Verifying

```sh
sbx run -- curl -sS https://oai.endpoints.kepler.ai.cloud.ovh.net/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did
not: check the filtering posture and that the allowlist reaches the host (see [Secrets](../)).

---

*This page is generated from `examples/secrets/ovhcloud/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
