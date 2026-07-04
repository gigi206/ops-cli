# `ops trust`

```
ops trust [path]
ops trust --show [path]
```

Vouch for a project config's current contents, so its security-relevant fields are
honored until the file changes again. Trust is bound to the file's contents, so any
edit re-arms the gate.

| Option | Meaning |
|---|---|
| `[path]` | the config to act on (default `./.ops.toml`) |
| `--show` | report the trust state without changing it |

See also: [The trust gate](../concepts/trust.md) · [`ops untrust`](untrust.md) · [Configuration overview](../configuration/README.md).

## Behavior

`ops trust` records a **SHA-256 of the whole file** (plus any sibling mise files),
keyed by the config's canonical path. A launch then compares the hash of the exact
bytes it parses:

- **Trusted** — the hash matches; security fields apply.
- **Changed** — a record exists but the bytes differ; security fields are dropped
  (distinct from untrusted).
- **Untrusted** — no record; security fields are dropped.

The global config and app profiles are **trusted by location** — they need no `ops
trust`. Only a project `.ops.toml` uses content trust. See
[The trust gate](../concepts/trust.md).

## Examples

```sh
ops trust                 # trust ./.ops.toml
ops trust --show          # report the state
ops trust path/to/.ops.toml
```

After editing a trusted file, run `ops trust` again — or use `ops config set/edit
--trust` to re-trust in one step. Revoke with [`ops untrust`](untrust.md).
