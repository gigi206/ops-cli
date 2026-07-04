# `ops net`

```
ops net <subcommand> [args...]
```

The egress-policy surface. Host-side — no launch, no nix. (Distinct from
[`ops test net <url>`](test.md), which tests one URL against the policy.)

See also: [Networking overview](../networking/README.md) · [Rule grammar](../networking/rules.md) · [Ask mode](../networking/ask.md) · [Observability](../networking/observability.md) · [Egress groups](../networking/groups.md).

## Subcommands

| Subcommand | Purpose |
|---|---|
| [`rules`](#ops-net-rules) | list the effective allow/deny rules by source |
| [`groups`](#ops-net-groups) | list reusable `[net.groups]`, or resolve one |
| [`allow`](#ops-net-allow-and-deny) / [`deny`](#ops-net-allow-and-deny) | persist a rule to config |
| [`pending`](#ops-net-pending) | list and answer `ask`-mode parked requests |
| [`stats`](#ops-net-stats) | per-host allow/deny/blocked decision counters |
| [`logs`](#ops-net-logs) | the live, per-request egress log of a running session |

## `ops net rules`

```
ops net rules [-a|--app <name>] [-s|--source config|builtin|manual] [-f|--filter <substr>] [-e|--expand] [--json]
```

Lists the allow/deny rules of the effective filtering posture, each tagged `config` or
`built-in`, reflecting the trust gate. An inspected L7 rule shows `https://`, a raw L4
rule shows `tcp://`; a `[net.groups]` group shows as one `@<name>` row (`--expand`
unfolds it). `--app <name>` shows what `ops app <name>` would launch with. `--source
manual` queries live `ask`-session rules remembered from `--session` answers. Under
`shared`/`none` there are no rules. See [Observability](../networking/observability.md).

## `ops net groups`

```
ops net groups [<name>…] [--json]
ops net groups export [<name>…] [-o|--out <file>]
ops net groups import <file> [-f|--force]
```

A `[net.groups]` group is a named set of egress entries declared once in the global
config and referenced by `@<name>`. `ops net groups` lists them; `ops net groups
<name>` resolves one; `export`/`import` move them between machines. Global-only (no
scope flag). See [Egress groups](../networking/groups.md).

## ops net allow and deny

```
ops net allow <rule> [-l|--local|-g|--global] [-a|--app <name>]
ops net deny  <rule> [-l|--local|-g|--global] [-a|--app <name>]
```

Validates the rule, then persists it to a config file. `allow` on a fresh config
**bootstraps a deny-by-default allowlist**; `deny` needs an existing filtering posture
(it will not open one). Writing the project config re-trusts it; the global config and
`-a <name>` app profile are trusted by location. See the [rule grammar](../networking/rules.md).

## `ops net pending`

```
ops net pending [-a <app>] [--json]
ops net pending allow|deny <id>|--all [-a <app>] [--session] [--save [-l|-g]]
ops net pending watch [-i <secs>] [-a <app>]
```

Under `[network] mode = "ask"`, a request no rule decides parks until answered. With no
verb, lists what is parked (id `<pid>.<seq>`; identical retries collapse to `×N`).
`allow <id>`/`deny <id>` answer a whole destination; `--all` drains; `--session`
remembers for the live session; `--save` persists a rule; `watch` redraws live. See
[Ask mode](../networking/ask.md).

## `ops net stats`

```
ops net stats [-a|--app <name>] [--reset] [--json]
```

Per destination host, how many requests this project's launches **allowed**, **denied**
(by a rule or an `ask` decision), or had **blocked** by a security guard (SSRF, an
outbound-secret tripwire, a host mismatch). Persist after the session (owner-only);
recording is on by default (a trusted `[network] stats = false` disables it). See
[Observability](../networking/observability.md).

## `ops net logs`

```
ops net logs [-a <app>] [--host <h>] [--verdict allow|deny|blocked|error] [-n <N>]
             [--with-query] [--with-status] [-f|--follow] [-i <secs>] [--json]
```

A chronological, per-request record of every egress decision a **running** session's
proxy made. **Live-only** — the log lives in the running session's memory and is
**never written to disk**; once the session exits, nothing remains. Verdicts are a
superset of `stats`, adding `error` (allowed but did not complete). `--follow` tails
it. See [Observability](../networking/observability.md).
