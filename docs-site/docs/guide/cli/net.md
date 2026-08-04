# `sbx net`

```
sbx net <subcommand> [args...]
```

The egress-policy surface. Host-side: no launch, no nix. (Distinct from
[`sbx test net <url>`](test), which tests one URL against the policy.)

See also: [The four lenses](../concepts/observability#the-four-lenses) · [Networking overview](../networking/) · [Rule grammar](../networking/rules) · [Ask mode](../networking/ask) · [Observability](../networking/observability) · [Egress groups](../networking/groups).

## Subcommands

| Subcommand | Purpose |
|---|---|
| [`rules`](#sbx-net-rules) | list the effective allow/deny rules by source |
| [`groups`](#sbx-net-groups) | list reusable `[net.groups]`, or resolve one |
| [`allow`](#sbx-net-allow-and-deny) / [`deny`](#sbx-net-allow-and-deny) | persist a rule to config |
| [`mute`](#sbx-net-mute-and-unmute) / [`unmute`](#sbx-net-mute-and-unmute) | add / remove a log-suppression (`dontaudit`) rule |
| [`pending`](#sbx-net-pending) | list and answer `ask`-mode parked requests |
| [`stats`](#sbx-net-stats) | per-host allow/deny/blocked decision counters |
| [`logs`](#sbx-net-logs) | the live, per-request egress log of a running session |
| [`live`](#sbx-net-live) | a live view of the egress tunnels currently open (a `top` for connections) |

## `sbx net rules`

```
sbx net rules [-a|--app <name>] [-s|--source config|builtin|session] [-f|--filter <substr>] [-e|--expand] [--json]
```

Lists the allow/deny rules of the effective filtering posture, each tagged `config` or
`built-in`, reflecting the trust gate. An inspected L7 rule shows `https://`, a raw L4
rule shows `tcp://`; a `[net.groups]` group shows as one `@<name>` row (`--expand`
unfolds it). `--app <name>` shows what `sbx app run <name>` would launch with. `--source
session` queries live `ask`-session rules remembered from `--session` answers (`manual`
is accepted as an alias). Under
`shared`/`none` there are no rules. See [Observability](../networking/observability).

## `sbx net groups`

```
sbx net groups [<name>…] [--json]
sbx net groups export [<name>…] [-o|--out <file>]
sbx net groups import <file> [-f|--force]
```

A `[net.groups]` group is a named set of egress entries declared once in the global
config and referenced by `@<name>`. `sbx net groups` lists them; `sbx net groups
<name>` resolves one; `export`/`import` move them between machines. Global-only (no
scope flag). See [Egress groups](../networking/groups).

## sbx net allow and deny

```
sbx net allow <rule> [-l|--local|-g|--global] [-a|--app <name>] [--session [--all]]
sbx net deny  <rule> [-l|--local|-g|--global] [-a|--app <name>] [--session [--all]]
```

Validates the rule, then persists it to a config file. `allow` on a fresh config
**bootstraps a deny-by-default allowlist**; `deny` needs an existing filtering posture
(it will not open one). Writing the project config re-trusts it; the global config and
`-a <name>` app profile are trusted by location. See the [rule grammar](../networking/rules).

`--session` instead loads the rule into the **live overlay** of the running session(s),
which the proxy folds into its effective policy: so it takes effect **immediately**, on an
allowlist or denylist session as well as [`ask`](../networking/ask): a `--session allow`
opens an otherwise-denied host, a `--session deny` cuts an allowed one (deny wins). It is the
proactive sibling of [`sbx net pending allow <id> --session`](../networking/ask), which
decides a request that already parked. It writes no file (so it never re-trusts the project)
and dies with the session. By default it scopes to the current project's session(s); `-a
<app>` narrows to one app, `--all` widens to every reachable session. The config-scope flags
(`-l`/`-g`/`-c`) do not apply with `--session`; only a filtering posture runs the proxy, so a
`shared`/`none` session has nothing to load into.

```sh
sbx net allow api.example.com --session          # for this project's live ask session(s)
sbx net allow api.example.com --session -a bot   # only app `bot`'s session(s)
sbx net deny  ads.example.com --session --all    # every reachable session, this run only
```

## sbx net mute and unmute

```
sbx net mute   <rule> [-l|--local|-g|--global] [-a|--app <name>] [--session [--all]]
sbx net unmute <rule> [-l|--local|-g|--global] [-a|--app <name>]
```

`mute` adds a [`[network] mute`](../networking/observability#muting-noisy-refusals-network-mute-selinux-dontaudit)
rule (SELinux `dontaudit`): a **denied** request matching it is still refused and still
counted in [`stats`](#sbx-net-stats), but its line is kept out of the default
[`sbx net log`](#sbx-net-logs) (see it with `--all`). It is a log filter, never a verdict, it cannot open egress. `unmute` removes such a rule (idempotent: removing an absent rule is a
reported no-op). Same scope vocabulary as `allow`/`deny`: a config write needs an existing
filtering posture (nothing to suppress under `shared`/`none`) and re-trusts the project
config; the global config and `-a <name>` app profile are trusted by location.

`--session` instead loads the mute into a **running** session's live overlay: it takes
effect immediately and dies with the session, exactly like `sbx net allow|deny --session`
(scope with `-a <app>`/`--all`). A live mute is not un-loaded by `unmute` (a log filter has no
counter-verdict); it ends with the session.

```sh
sbx net mute   play.googleapis.com -a agy             # persist to the profile
sbx net unmute play.googleapis.com -a agy             # undo it
sbx net mute   play.googleapis.com --session -a agy   # quiet a running agy session now
```

## `sbx net pending`

```
sbx net pending [-a <app>] [--json]
sbx net pending allow|deny <id>|--all [-a <app>] [--session] [--save [-l|-g]]
sbx net pending watch [-i <secs>] [-a <app>]
```

Under `[network] mode = "ask"`, a request no rule decides parks until answered. With no
verb, lists what is parked (id `<pid>.<seq>`; identical retries collapse to `×N`).
`allow <id>`/`deny <id>` answer a whole destination; `--all` drains; `--session`
remembers for the live session; `--save` persists a rule; `watch` redraws live. See
[Ask mode](../networking/ask).

## `sbx net stats`

```
sbx net stats [-a|--app <name>] [--reset] [--json]
```

Per destination host, how many requests this project's launches **allowed**, **denied**
(by a rule or an `ask` decision), or had **blocked** by a security guard (SSRF, an
outbound-secret tripwire, a host mismatch). Persist after the session (owner-only);
recording is on by default (a trusted `[network] stats = false` disables it). See
[Observability](../networking/observability).

## `sbx net logs`

```
sbx net logs [-a <app>] [--host <h>] [--verdict allow|deny|blocked|error] [-n <N>]
             [--all] [--with-query] [--with-status] [--with-headers] [--with-body]
             [-f|--follow] [-i <secs>] [--json]
```

A chronological, per-request record of every egress decision a **running** session's
proxy made. **Live-only**: the log lives in the running session's memory and is
**never written to disk**; once the session exits, nothing remains. Verdicts are a
superset of `stats`, adding `error` (allowed but did not complete). `--follow` tails
it. `--all` also shows refusals a [`[network] mute`](../networking/observability#muting-noisy-refusals-network-mute-selinux-dontaudit)
rule suppressed (tagged `muted`; still counted in `stats`).

`--with-headers` / `--with-body` show what actually crossed (request and response
heads, then the leading bytes of each body), for a session launched with
[`[network] capture`](../networking/observability#seeing-the-traffic-network-capture)
on. Secrets are masked and an sbx-injected credential is named, never valued. See
[Observability](../networking/observability).

A `!` line under an event reports a configured secret **seen crossing that exchange's
WebSocket**, by name and direction. It needs no flag, and it is a report rather than a
verdict: an open tunnel is relayed byte-exact, so nothing was blocked or masked. See
[Redaction](../secrets/redaction#the-third-tripwire-a-websocket-is-watched-not-filtered).

## `sbx net live`

```
sbx net live [-a|--app <name>] [-i|--interval <secs>] [--json]
```

A live view of the egress tunnels **currently open**: one line per flow: destination
`host:port`, the transport (`https` inspected TLS, `http` inspected cleartext, `tcp` raw L4
splice), how long it has been open, and the bytes each way (`↑` client→upstream, `↓`
upstream→client): grouped by session and redrawn in place like `top`. This is the *open
connections*, distinct from [`logs`](#sbx-net-logs) (the *history of decided requests*).

Because the proxy closes each inspected request after one response, short API calls flash by
in under a second; the durable rows are raw `tcp://` tunnels (SSH, a database wire),
WebSockets, and large L7 transfers in progress. Byte counts are application bytes on an
inspected `https`/`http` flow, encrypted bytes on a raw `tcp` splice. The redraw needs a
terminal; `--json` emits one snapshot object per tick (NDJSON) for a pipe. Only a filtering
posture (`deny`/`allow`/`ask`) runs a proxy, so only those sessions have flows. See
[Observability](../networking/observability).

## Examples

### Build an allowlist from nothing

`allow` on a config with no filtering posture bootstraps a deny-by-default
allowlist, so the first rule is also what turns filtering on:

```sh
sbx net allow api.example.com          # deny-by-default from here on
sbx net allow '*.example.com'          # a subdomain wildcard
sbx net allow '{GET,HEAD} https://docs.example.com'   # read-only, verb-scoped
sbx net allow tcp://db.example.com:5432               # a raw L4 tunnel, not inspected
sbx net rules                          # what the launch would actually enforce
sbx test net https://api.example.com/v1/users         # try one URL against it
```

Scope the write where the rule belongs:

```sh
sbx net allow api.example.com            # the project .sbx.toml (default), re-trusting it
sbx net allow api.example.com -g         # the global config, for every project
sbx net allow api.example.com -a codex   # only app `codex`'s profile
```

### Inspect the effective policy

```sh
sbx net rules                          # by source, groups shown as one @<name> row
sbx net rules --expand                 # …with every group unfolded to its hosts
sbx net rules --filter github          # only rules mentioning github (implies --expand)
sbx net rules --source builtin         # just the always-allowed self-equip set
sbx net rules --source session         # what was loaded live, with --session
sbx net rules -a codex                 # what `sbx app run codex` would launch with
sbx net rules --json | jq -r '.rules[] | "\(.source)\t\(.kind)\t\(.rule)"'
```

`rules` is the answer to "did my rule survive the trust gate": an untrusted project's
rules are dropped, and they are simply absent from this listing.

### Watch a running session

```sh
sbx net live                           # open tunnels, redrawn like `top`
sbx net logs -f                        # every decision as it is made
sbx net logs --verdict deny -n 20      # the last 20 refusals
sbx net logs --host api.example.com --with-status
sbx net logs --all                     # …including what a `mute` rule suppressed
sbx net logs --with-headers --with-body   # what actually crossed (needs [network] capture)
```

`logs` is live-only and never written to disk: once the session exits, nothing
remains. `stats` is the durable counterpart:

```sh
sbx net stats                          # per-host allow / deny / blocked, after the fact
sbx net stats -a codex                 # one app's sessions
sbx net stats --json | jq -r '.stats[] | select(.blocked>0) | .host'   # what a guard stopped
sbx net stats --reset                  # clear the recorded counters
```

A `blocked` count is not a policy refusal but a security guard firing (SSRF, an
outbound-secret tripwire, a domain-fronting host mismatch), so it is the column worth
looking at first.

### Answer an `ask` session

```sh
sbx net pending                        # what is parked, by id <pid>.<seq>
sbx net pending watch                  # …redrawn live, in a second terminal
sbx net pending allow 1234.1           # let this destination through, this session
sbx net pending allow 1234.1 --save    # …and persist the rule to the project config
sbx net pending deny --all             # drain everything with a refusal
```

### Decide a host without waiting for it to park

```sh
sbx net allow api.example.com --session         # this project's live session(s), immediately
sbx net deny  ads.example.com --session --all   # every reachable session, this run only
```

A `--session` rule writes no file, so it never re-trusts the project, and it dies with
the session. It works on an allowlist or denylist session too, not only `ask`.

### Quiet a noisy refusal

```sh
sbx net mute play.googleapis.com -a agy           # persist it to the app profile
sbx net mute play.googleapis.com --session -a agy # quiet a running session now
sbx net logs --all                                # the muted lines are still there, tagged
sbx net unmute play.googleapis.com -a agy         # undo the persisted rule
```

A mute is a log filter, never a verdict: the request stays refused and still counts in
`stats`.

### Share a set of hosts across apps

```sh
sbx net groups                         # every group and its entry count
sbx net groups ci                      # what @ci expands to
sbx net allow @ci -a codex             # reference it from an app
sbx net groups export ci -o ci.toml    # move it to another machine
sbx net groups import ci.toml          # …merge it into the global config there
```

Groups are global-only, which is why this verb has no scope flag.
