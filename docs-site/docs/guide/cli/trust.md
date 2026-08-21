# `sbx trust`

```
sbx trust [path]
sbx trust --show [path]
```

Vouch for a project config's current contents, so its security-relevant fields are
honored until the file changes again. Trust is bound to the file's contents, so any
edit re-arms the gate.

| Option | Meaning |
|---|---|
| `[path]` | the config to act on (default `./.sbx.toml`) |
| `--show` | report the trust state without changing it |

See also: [The trust gate](../concepts/trust) · [`sbx untrust`](untrust) · [Configuration overview](../configuration/).

## Behavior

`sbx trust` records a **SHA-256 of the whole file** (plus any sibling mise files),
keyed by the config's canonical path. A launch then compares the hash of the exact
bytes it parses:

- **Trusted**: the hash matches; security fields apply.
- **Changed**, a record exists but the bytes differ; security fields are dropped
  (distinct from untrusted).
- **Untrusted**: no record; security fields are dropped.

The global config and app profiles are **trusted by location**: they need no `sbx
trust`. Only a project `.sbx.toml` uses content trust. One exception: [`[fs]`](../configuration/fs)
is the one table this does not govern, since it can only close project paths off inside
the cage, so it applies whether or not the file is trusted. See
[The trust gate](../concepts/trust).

## Examples

```sh
sbx trust                 # trust ./.sbx.toml
sbx trust --show          # report the state
sbx trust path/to/.sbx.toml
```

After editing a trusted file, run `sbx trust` again, or use `sbx config set/edit
--trust` to re-trust in one step. Revoke with [`sbx untrust`](untrust).
