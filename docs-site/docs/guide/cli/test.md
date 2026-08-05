# `sbx test`

```
sbx test net [--app <name>] [-X|--method <verb>] <url|tcp://host:port>
```

A diagnostic surface that reports whether an access would be allowed, and why. No
launch, no nix, no network: it reports a verdict against the resolved policy.

See also: [`sbx net`](net) · [Network modes](../networking/modes) · [Rule grammar](../networking/rules) · [Observability](../networking/observability).

## `sbx test net`

Reports **ALLOWED / DENIED / WOULD ASK** and the rule that decides it, against the
effective [egress policy](../networking/modes) a launch would serve. The built-in
self-equip allow-set is included, and a declared [credential injection](../secrets/injection)
is noted (by header and source, never the value, and not resolved). Reflects the
[trust gate](../concepts/trust): an untrusted project's policy is dropped.

| Option | Meaning |
|---|---|
| `<url>` | the URL (or a bare host, completed to `https`) to test |
| `tcp://host:port` | test a raw L4 splice instead: reports **SPLICED / NOT SPLICED** |
| `-a, --app <name>` | test against that app's effective policy (baseline + overlay) |
| `-X, --method <verb>` | the HTTP method to test (default `GET`); a `{GET}` rule only matches that verb (ignored for `tcp://`) |

## Private and internal addresses

A permitted request meets one more check on the wire: the proxy resolves the host and
runs its [SSRF guard](../networking/architecture#the-ssrf-guard) on the address, which
admits a private or loopback one only when the deciding rule names **that exact host**.
`sbx test net` replays that guard, so a target it reports as allowed is one the proxy
would really connect to:

```
$ sbx test net https://127.0.0.1/
network: deny (allowlist — only listed and built-in hosts reach)
DENIED   https://127.0.0.1/
  the policy allows it (allow rule: re:.*), but the proxy refuses the address at connect time: a private or loopback address is reachable only when the deciding rule names that exact host
```

Naming the host exactly (`allow = ["192.168.1.10"]`, `allow = ["db.internal"]`) is the
deliberate act the guard admits, and the verdict is then a plain ALLOWED.

The guard needs an address, and this command resolves nothing (no network). So on an
**IP literal** the verdict is exact, while on a **name** under a rule that does not
name it exactly (a `re:` regex, a `*.domain`, an allow-by-default posture) it can only
state the condition:

```
  note: if this name resolves to a private or loopback address, the proxy refuses it at connect time (no rule names this exact host)
```

A link-local address (the cloud metadata one among them), a multicast, or the
unspecified address is refused however the policy is written, exact rule included.

## Examples

```sh
sbx test net https://api.github.com
sbx test net api.github.com --method POST
sbx test net --app claude-code https://api.anthropic.com/v1/messages
sbx test net tcp://db.internal:5432
sbx test net https://127.0.0.1/          # the address guard, replayed
```

`sbx test net` tests **one URL**; to list the effective rules, use
[`sbx net rules`](net).
