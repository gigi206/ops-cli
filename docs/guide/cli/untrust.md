# `ops untrust`

```
ops untrust [path]
```

Revoke a config's trust, so its security-relevant fields stop applying until it is
trusted again.

| Operand | Meaning |
|---|---|
| `[path]` | the config to act on (default `./.ops.toml`) |

See also: [`ops trust`](trust.md) · [The trust gate](../concepts/trust.md).

## Example

```sh
ops untrust               # revoke ./.ops.toml
ops untrust path/to/.ops.toml
```

After `untrust`, the project's [security fields](../concepts/trust.md#free-fields-vs-security-fields)
(binds, network, secrets, packages, …) are dropped from a launch; the free `env` field
still applies. Re-approve with [`ops trust`](trust.md).
