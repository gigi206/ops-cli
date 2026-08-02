# `pass://` — the pass(1) password store

Reads a secret from a local [pass](https://www.passwordstore.org/) store and prints its
**first line**, which is the password by convention.

```
pass://<path>
```

| Reference | Resolves to |
|---|---|
| `pass://github/token` | the first line of `~/.password-store/github/token.gpg` |
| `pass://work/db/prod` | the first line of `~/.password-store/work/db/prod.gpg` |

Used in a project's `.sbx.toml`:

```toml
[secret.GITHUB_TOKEN]
from = "pass://github/token"
```

## Installing

```
sbx plugins install ./plugins/pass
```

Or from a signed store that publishes it — see [the plugins
README](../README.md) for both paths and what each guarantees.

## What it needs on the host

`pass` and `gpg` must be on sbx's `PATH`, and a **gpg-agent must already be running** with the
store's key available. The resolver cannot prompt for anything: sbx closes its stdin, so a key
that would need a passphrase typed in resolves to a hard failure, not a prompt.

The grant in `plugin.toml` is read-only and minimal:

| Granted | Why |
|---|---|
| `~/.password-store` | the encrypted store itself |
| `~/.gnupg` | the public keyring and trustdb |
| `$XDG_RUNTIME_DIR/gnupg` | the live gpg-agent socket |
| `GNUPGHOME`, `XDG_RUNTIME_DIR` | passed through only when set, so gpg finds a non-default store and its agent |
| no network | the store is local; the resolver runs in an empty network namespace |

Binding the agent socket read-only is enough because the **agent** holds the secret keys and
performs the decryption — the client only writes to the socket. Each `allow_paths` entry is bound
only if it exists, so a host with no agent socket yet still installs; the resolver then fails
closed if it genuinely needed it.

## Behaviour

| Situation | Exit | stdout |
|---|---|---|
| the entry is found | `0` | the first line |
| the ref is not `pass://…`, or its path is empty | non-zero | — (the reason goes to stderr) |
| `pass show` fails (no such entry, locked key, no agent) | non-zero | — |

A non-zero exit is a **hard** failure: sbx names the resolver, folds in its stderr, and never
falls through to a weaker source in a `from = [...]` chain. This plugin never reports a clean
"absent" (exit 0 with empty stdout), so a missing entry is an error rather than a fall-through.
