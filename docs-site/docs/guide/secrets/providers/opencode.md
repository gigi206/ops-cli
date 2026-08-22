---
title: "`opencode` — the OpenCode Zen and OpenCode Go gateways"
sidebar_label: "opencode"
description: "OpenCode's own pay-per-use gateways: one API key for both, giving access to the coding-optimized models on opencode's infrastructure."
sidebar_position: 30
---

# `opencode` — the OpenCode Zen and OpenCode Go gateways

OpenCode's own pay-per-use gateways: one API key for both, giving access to the
coding-optimized models on opencode's infrastructure. Both are OpenAI-compatible
endpoints that expect `Authorization: Bearer <key>` — the injection mechanics,
posture, and scoping are in [the shared page](../); this page only adds
what is specific to OpenCode.

```toml
# OpenCode Zen — the trailing `/*` is load-bearing: the API's real requests
# are `/zen/v1/…` (e.g. `/zen/v1/chat/completions`) and a path rule matches
# exactly by default, so without `/*` the block never matches anything.
[secret."opencode.ai/zen/v1/*"]
from   = "env://OPENCODE_API_KEY"
header = "Authorization"
type   = "bearer"
```

```toml
# OpenCode Go — same subtree rule, on the Go route.
[secret."opencode.ai/zen/go/v1/*"]
from   = "env://OPENCODE_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export OPENCODE_API_KEY=oc_…
```

## Specifics

- **Two gateways, one key.** Zen (`opencode.ai/zen/v1`) and Go
  (`opencode.ai/zen/go/v1`) both bind `OPENCODE_API_KEY` — the variable is
  opencode's own, not an sbx choice, so a single `export` authenticates both.
- **Path-scoped on purpose.** The blocks target the gateway **paths**, not the
  bare host: the key is injected only into requests to `/zen/v1/*` and
  `/zen/go/v1/*`, never into opencode's other hosts (`opencode.ai` docs/install,
  `models.opencode.ai`, …). Keep the trailing `/*`: a path rule matches its
  path **exactly**, so `…/zen/go/v1` would never match the real requests
  (`/zen/go/v1/chat/completions`, …). The egress allowlist should carry the
  same two subtree rules (plus whatever else the tool needs), so injection and
  permit scopes agree.
- **The key never enters the cage**, as with GitHub: the agent issues a plain
  request, the proxy adds the header on the wire.

## Verifying

```sh
sbx run -- curl -sS https://opencode.ai/zen/v1/models
```

A `200` with the model listing means the header arrived; a `401` means it did
not — check the filtering posture and that the allowlist carries the path (see
the shared page). The `models` listing is the standard OpenAI-compatible
endpoint the gateway exposes.

---

*This page is generated from `examples/secrets/opencode/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
