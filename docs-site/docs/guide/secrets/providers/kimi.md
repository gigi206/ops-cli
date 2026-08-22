---
title: "`kimi`: Kimi (Code)"
sidebar_label: "kimi"
description: "Kimi's coding lane, dedicated to agentic tooling."
sidebar_position: 19
---

# `kimi`: Kimi (Code)

Kimi's coding lane, dedicated to agentic tooling. The mechanics, posture, and
scoping are in [Secrets](../); this page only adds what is
specific to Kimi.

```toml
[secret."api.kimi.com/coding/v1/*"]
from   = "env://KIMI_API_KEY"
header = "Authorization"
type   = "bearer"
```

Set the key in your shell, exactly as the `from` names it:

```sh
export KIMI_API_KEY=…
```

## Specifics

- **Host:** `api.kimi.com`, coding gateway at `/coding/v1`: model
  `kimi-for-coding` (`-highspeed` variant available).
- **Variable:** `KIMI_API_KEY`, the env var the coding integrations use
  (`Authorization: Bearer $KIMI_API_KEY`).
- **Access:** an active Kimi membership with *Kimi Code* benefits enabled; the
  key is minted in the Kimi console (`kimi.com/code/console`). The gateway
  refuses keys from non-approved platforms: the header injection in no way
  bypasses that gate.
- **Trailing `/*` is load-bearing** (same rule as the opencode page): without
  it the block never matches beneath the base path.
- **Reference:** [https://kimi.com/help/coding/third-party-agents](https://kimi.com/help/coding/third-party-agents)

## Verifying

```sh
sbx run -- curl -sS https://api.kimi.com/coding/v1/models
```

A `200` with the model list* means the header arrived; a `401` means it did
not: check the filtering posture and that the allowlist reaches the host (see [Secrets](../)).

---

*This page is generated from `examples/secrets/kimi/README.md`. Edit it there:
the file beside the configuration it describes is the copy people import.*
