---
description: "Revoke a config's trust, so its security fields stop applying until it is trusted again."
---

# `sbx untrust`

```
sbx untrust [path]
```

Revoke a config's trust, so its security-relevant fields stop applying until it is
trusted again.

| Operand | Meaning |
|---|---|
| `[path]` | the config to act on (default `./.sbx.toml`) |

See also: [`sbx trust`](trust) · [The trust gate](../concepts/trust).

## Example

```sh
sbx untrust               # revoke ./.sbx.toml
sbx untrust path/to/.sbx.toml
```

After `untrust`, the project's [security fields](../concepts/trust#free-fields-vs-security-fields)
(binds, network, secrets, packages, …) are dropped from a launch; the free `env` field
still applies. Re-approve with [`sbx trust`](trust).
