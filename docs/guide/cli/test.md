# `sbx test`

```
sbx test net [--app <name>] [-X|--method <verb>] <url|tcp://host:port>
```

A diagnostic surface that reports whether an access would be allowed, and why. No
launch, no nix, no network — it reports a verdict against the resolved policy.

See also: [`sbx net`](net.md) · [Network modes](../networking/modes.md) · [Rule grammar](../networking/rules.md) · [Observability](../networking/observability.md).

## `sbx test net`

Reports **ALLOWED / DENIED / WOULD ASK** and the rule that decides it, against the
effective [egress policy](../networking/modes.md) a launch would serve. The built-in
self-equip allow-set is included, and a declared [credential injection](../secrets/injection.md)
is noted (by header and source, never the value, and not resolved). Reflects the
[trust gate](../concepts/trust.md) — an untrusted project's policy is dropped.

| Option | Meaning |
|---|---|
| `<url>` | the URL (or a bare host, completed to `https`) to test |
| `tcp://host:port` | test a raw L4 splice instead — reports **SPLICED / NOT SPLICED** |
| `-a, --app <name>` | test against that app's effective policy (baseline + overlay) |
| `-X, --method <verb>` | the HTTP method to test (default `GET`); a `{GET}` rule only matches that verb (ignored for `tcp://`) |

## Examples

```sh
sbx test net https://api.github.com
sbx test net api.github.com --method POST
sbx test net --app claude-code https://api.anthropic.com/v1/messages
sbx test net tcp://db.internal:5432
```

`sbx test net` tests **one URL**; to list the effective rules, use
[`sbx net rules`](net.md).
