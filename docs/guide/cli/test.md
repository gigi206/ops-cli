# `ops test`

```
ops test net [--app <name>] [-X|--method <verb>] <url|tcp://host:port>
```

A diagnostic surface that reports whether an access would be allowed, and why. No
launch, no nix, no network — it reports a verdict against the resolved policy.

See also: [`ops net`](net.md) · [Network modes](../networking/modes.md) · [Rule grammar](../networking/rules.md) · [Observability](../networking/observability.md).

## `ops test net`

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
ops test net https://api.github.com
ops test net api.github.com --method POST
ops test net --app claude-code https://api.anthropic.com/v1/messages
ops test net tcp://db.internal:5432
```

`ops test net` tests **one URL**; to list the effective rules, use
[`ops net rules`](net.md).
