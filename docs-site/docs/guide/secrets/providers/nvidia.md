---
title: "`nvidia` — NVIDIA NIM (build.nvidia.com)"
sidebar_label: "nvidia"
description: "NVIDIA's hosted AI models (the NIM API behind build.nvidia.com): an OpenAI-compatible endpoint, one key for the whole catalogue."
sidebar_position: 27
---

# `nvidia` — NVIDIA NIM (build.nvidia.com)

NVIDIA's hosted AI models (the NIM API behind build.nvidia.com): an
OpenAI-compatible endpoint, one key for the whole catalogue. The injection
mechanics, posture, and scoping are in [the shared page](../); this
page only adds what is specific to NVIDIA.

```toml
[secret."integrate.api.nvidia.com"]
from   = "env://NVIDIA_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export NVIDIA_API_KEY=nvapi-…
```

## Specifics

- **Host:** `integrate.api.nvidia.com` (path `/v1`). All NIM models are served
  from this one host, so a single block covers the whole catalogue.
- **Variable:** `NVIDIA_API_KEY` — the binding opencode and the NVIDIA docs
  both use; a key minted on build.nvidia.com (`nvapi-…`).
- **Tracking headers:** NVIDIA asks clients to send `HTTP-Referer` and
  `X-Title` for attribution; these are application-level headers, not
  credentials — they belong in the agent's config, not in `[secret]`.

## Verifying

```sh
sbx run -- curl -sS https://integrate.api.nvidia.com/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did
not — check the filtering posture and that the allowlist reaches the host (see
the shared page).

---

*This page is generated from `examples/secrets/nvidia/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
