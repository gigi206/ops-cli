---
title: "`huggingface` — Hugging Face (Inference Providers)"
sidebar_label: "huggingface"
description: "Hugging Face's router for the whole open-model catalog."
sidebar_position: 17
---

# `huggingface` — Hugging Face (Inference Providers)

Hugging Face's router for the whole open-model catalog. The mechanics, posture,
and scoping are in [the shared page](../); this page only adds what is
specific to Hugging Face.

```toml
[secret."router.huggingface.co/v1/*"]
from   = "env://HF_TOKEN"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export HF_TOKEN=…
```

## Specifics

- **Host:** `router.huggingface.co`, OpenAI-compatible layer at `/v1` — the
  server picks the fastest provider for the model you name (a token
  fine-grained to *Inference Providers* permission; account-scoped works too,
  but prefers least privilege).
- **Variable:** `HF_TOKEN` — the env var the official docs and SDKs use
  (`Authorization: Bearer $HF_TOKEN`).
- **Scope of `/v1`:** chat completions (and the Responses API) only; embeddings
  and other tasks stay on the per-provider endpoints — the full
  `https://huggingface.co/api/**` surface and the classic
  `api-inference.huggingface.co` are separate hosts, add blocks only if the
  cage needs them.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): without
  it the block never matches beneath the base path.
- **Reference:** [https://huggingface.co/docs/inference-providers](https://huggingface.co/docs/inference-providers) ·
  [https://huggingface.co/settings/tokens](https://huggingface.co/settings/tokens)

## Verifying

```sh
sbx run -- curl -sS https://router.huggingface.co/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did
not — check the filtering posture and that the allowlist reaches the host (see
the shared page).

---

*This page is generated from `examples/secrets/huggingface/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
