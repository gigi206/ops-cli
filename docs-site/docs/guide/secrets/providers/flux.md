---
title: "`flux`: Black Forest Labs (Flux)"
sidebar_label: "flux"
description: "Black Forest Labs' image-generation API (the Flux family)."
sidebar_position: 12
---

# `flux`: Black Forest Labs (Flux)

Black Forest Labs' image-generation API (the Flux family). The shared
mechanics, posture, and scoping are in [Secrets](../); this
page only adds what is specific to BFL: **including a non-`Authorization`
header, which is the one real twist here**.

```toml
[secret."api.bfl.ai/*"]
from   = "env://BFL_API_KEY"
header = "x-key"
type   = "raw"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export BFL_API_KEY=…
```

## Specifics

- **Host:** `api.bfl.ai`: the global endpoint (regional variants
  `api.eu.bfl.ai` / `api.us.bfl.ai`, same header, separate blocks). Generation
  is async: submit `POST /v1/flux-2-…`, then poll the **`polling_url`** given
  in the response; the same `x-key` applies there.
- **Header is `x-key`, not `Authorization`:** the official API takes the key
  in the `x-key` request header, so this page uses `header = "x-key"` with
  `type = "raw"` (no `Bearer` prefix is applied). This is the provider-making
  case for non-standard headers: everything else (`from`, fail-closed,
  host-scoping) behaves the same.
- **Variable:** `BFL_API_KEY`, the env var the official SDK and guide use.
- **Reference:** [https://docs.bfl.ai/](https://docs.bfl.ai/)

## Verifying

```sh
sbx run -- curl -sS -X POST https://api.bfl.ai/v1/flux-2-pro \
  -H 'Content-Type: application/json' \
  -d '{"prompt":"a red cube","width":256,"height":256}'
```

A `200` (or `402`/`429`: the key flowed, quota just not available) means the
`x-key` reached the wire; a `401` means it did not: check the filtering
posture and that the allowlist reaches the host (see [Secrets](../)).

---

*This page is generated from `examples/secrets/flux/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
