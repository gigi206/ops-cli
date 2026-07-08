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
| [`mute`](#ops-net-mute-and-unmute) / [`unmute`](#ops-net-mute-and-unmute) | add / remove a log-suppression (`dontaudit`) rule |
| [`pending`](#ops-net-pending) | list and answer `ask`-mode parked requests |
| [`stats`](#ops-net-stats) | per-host allow/deny/blocked decision counters |
| [`logs`](#ops-net-logs) | the live, per-request egress log of a running session |

## `ops net rules`

```
ops net rules [-a|--app <name>] [-s|--source config|builtin|session] [-f|--filter <substr>] [-e|--expand] [--json]
```

Lists the allow/deny rules of the effective filtering posture, each tagged `config` or
`built-in`, reflecting the trust gate. An inspected L7 rule shows `https://`, a raw L4
rule shows `tcp://`; a `[net.groups]` group shows as one `@<name>` row (`--expand`
unfolds it). `--app <name>` shows what `ops app <name>` would launch with. `--source
session` queries live `ask`-session rules remembered from `--session` answers (`manual`
is accepted as an alias). Under
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
ops net allow <rule> [-l|--local|-g|--global] [-a|--app <name>] [--session [--all]]
ops net deny  <rule> [-l|--local|-g|--global] [-a|--app <name>] [--session [--all]]
```

Validates the rule, then persists it to a config file. `allow` on a fresh config
**bootstraps a deny-by-default allowlist**; `deny` needs an existing filtering posture
(it will not open one). Writing the project config re-trusts it; the global config and
`-a <name>` app profile are trusted by location. See the [rule grammar](../networking/rules.md).

`--session` instead loads the rule into the **live overlay** of the running session(s),
which the proxy folds into its effective policy — so it takes effect **immediately**, on an
allowlist or denylist session as well as [`ask`](../networking/ask.md): a `--session allow`
opens an otherwise-denied host, a `--session deny` cuts an allowed one (deny wins). It is the
proactive sibling of [`ops net pending allow <id> --session`](../networking/ask.md), which
decides a request that already parked. It writes no file (so it never re-trusts the project)
and dies with the session. By default it scopes to the current project's session(s); `-a
<app>` narrows to one app, `--all` widens to every reachable session. The config-scope flags
(`-l`/`-g`/`-c`) do not apply with `--session`; only a filtering posture runs the proxy, so a
`shared`/`none` session has nothing to load into.

```sh
ops net allow api.example.com --session          # for this project's live ask session(s)
ops net allow api.example.com --session -a bot   # only app `bot`'s session(s)
ops net deny  ads.example.com --session --all    # every reachable session, this run only
```

## ops net mute and unmute

```
ops net mute   <rule> [-l|--local|-g|--global] [-a|--app <name>] [--session [--all]]
ops net unmute <rule> [-l|--local|-g|--global] [-a|--app <name>]
```

`mute` adds a [`[network] mute`](../networking/observability.md#muting-noisy-refusals--network-mute-selinux-dontaudit)
rule (SELinux `dontaudit`): a **denied** request matching it is still refused and still
counted in [`stats`](#ops-net-stats), but its line is kept out of the default
[`ops net log`](#ops-net-logs) (see it with `--all`). It is a log filter, never a verdict —
it cannot open egress. `unmute` removes such a rule (idempotent — removing an absent rule is a
reported no-op). Same scope vocabulary as `allow`/`deny`: a config write needs an existing
filtering posture (nothing to suppress under `shared`/`none`) and re-trusts the project
config; the global config and `-a <name>` app profile are trusted by location.

`--session` instead loads the mute into a **running** session's live overlay — it takes
effect immediately and dies with the session, exactly like `ops net allow|deny --session`
(scope with `-a <app>`/`--all`). A live mute is not un-loaded by `unmute` (a log filter has no
counter-verdict); it ends with the session.

```sh
ops net mute   play.googleapis.com -a agy             # persist to the profile
ops net unmute play.googleapis.com -a agy             # undo it
ops net mute   play.googleapis.com --session -a agy   # quiet a running agy session now
```

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
             [--all] [--with-query] [--with-status] [-f|--follow] [-i <secs>] [--json]
```

A chronological, per-request record of every egress decision a **running** session's
proxy made. **Live-only** — the log lives in the running session's memory and is
**never written to disk**; once the session exits, nothing remains. Verdicts are a
superset of `stats`, adding `error` (allowed but did not complete). `--follow` tails
it. `--all` also shows refusals a [`[network] mute`](../networking/observability.md#muting-noisy-refusals--network-mute-selinux-dontaudit)
rule suppressed (tagged `muted`; still counted in `stats`). See
[Observability](../networking/observability.md).
