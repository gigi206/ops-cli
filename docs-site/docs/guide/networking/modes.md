# Network modes

The `network` field chooses the sandbox's egress posture. There are five values:
two that run **no proxy** (`none`, `shared`) and three **filtering** postures that
run the [Model-B egress proxy](architecture) and honor the
[rule grammar](rules): `deny`, `allow`, and `ask`.

```toml
# the two simple postures
network = "none"     # empty network namespace: nothing reaches out
network = "shared"   # the host network, unfiltered

# the three filtering postures (string form: no carve-outs yet)
network = "deny"     # allowlist: only what you allow reaches (the default)
network = "allow"    # denylist: every public host reaches except what you deny
network = "ask"      # park-and-confirm: undecided hosts block for your answer
```

A filtering posture usually needs carve-out lists, so it is more often written as
the **table form**:

```toml
[network]
mode  = "deny"
allow = ["api.anthropic.com", "*.nixos.org"]
deny  = ["telemetry.example.com"]
```

The string and table forms are the same field: a bare string is just a table with
no `allow`/`deny` lists. See [rules](rules) for what goes in the lists.

---

## `none`

An empty network namespace: the cage has loopback and nothing else: no route, no
DNS, no way out. A direct connection fails immediately (`Could not resolve host` /
`Could not connect`). Use it for fully offline work, or to be certain a tool cannot
phone home.

Because there is no proxy, there are no rules, no [stats](observability), and no
[live log](observability#sbx-net-logs). Note that a project's *first* provision
of a tool needs the network: an offline `none` cage can only run what is already
in the per-project store.

## `shared`

The host network, unfiltered: the cage shares your network namespace and reaches
whatever your host can. It is the right posture for your own interactive shell
(`sbx run`) and for trusted work where filtering would only get in the way. There is
no proxy, so no rules, stats, or log apply. It is also the only posture that reaches
your **host loopback** (a local database, a model server, a dev server) and your
**LAN**, which no filtering posture ever exposes.

`shared` is the documented **escape hatch** from the filtering default: set
`network = "shared"` in your global config to make open networking the baseline for
every project. An untrusted project still cannot reach this posture (see [the security
gate](#security-gated)). For how it compares with the two filtering ways to let
everything through, see [Opening the network wide](#opening-the-network-wide).

## `deny`

**Deny-by-default, an allowlist.** Only the hosts your `allow` list names can be
reached; everything else is refused (HTTP 403 at the proxy). This is the posture
for running an agent you do not fully trust: give it exactly the provider host and
whatever else it legitimately needs, and nothing else leaves.

```toml
[network]
mode  = "deny"
allow = ["api.anthropic.com"]
```

Under `deny`, the [built-in self-equip set](#the-built-in-self-equip-set) is
unioned in so the project can still provision from the nix cache and GitHub: you
do not have to list those yourself. A `deny` entry can carve a hole back out of any
allow (including a built-in one): `deny` always wins.

### `deny` is the default

With no `network` anywhere, this is the posture you get, carrying no rules of its own.
A cage nobody configured therefore reaches the built-in self-equip set and nothing
else. Two consequences are worth stating outright:

- **An untrusted project lands here.** Its own `network` is dropped whichever way it
  points (see [the security gate](#security-gated)), so this default is what a
  repository sbx knows nothing about actually runs under. It reaches neither your host
  loopback nor your LAN.
- **A tool you never named will not fetch.** A `mise:` package whose backend downloads
  from a host outside the self-equip set (npm, PyPI, crates.io) cannot install until
  you allow that host. The refusal names it and prints the `sbx net allow` line that
  admits it, and [`--net-learn`](../cli/app#learning-an-apps-egress---net-learn) writes
  those rules for you. The launch itself is not blocked: the tool is simply absent.

Set `network = "shared"` in your global config if you would rather have the open host
network as your baseline.

## `allow`

**Allow-by-default, a denylist.** Every public host reaches *except* the ones your
`deny` list names. This is the broad-access posture with targeted blocks: useful
when a tool needs general internet but a specific host (a telemetry endpoint, a
known-bad domain) must be blocked.

```toml
[network]
mode = "allow"
deny = ["telemetry.example.com", "*.doubleclick.net"]
```

Under `allow`, the `allow` list has almost no remaining effect (every public host
is already permitted); its one job is the [SSRF exception](architecture#the-ssrf-guard), a private or internal address is refused unless an allow rule names that exact
host. In other words, `allow` opens the *public* internet, not your internal
network.

## `ask`

**Park-and-confirm.** An `allow` entry auto-passes and a `deny` entry auto-fails
(exactly as under the other modes), but anything *undecided* **parks**: the request
blocks inside the cage while you answer it from another terminal with
[`sbx net pending`](ask). You allow or deny it live, optionally remembering the
answer for the session or persisting a rule. This is the discovery posture: run an
agent and watch, in real time, what it tries to reach, deciding as you go.

```toml
[network]
mode  = "ask"
allow = ["api.anthropic.com"]   # never asked: always allowed
deny  = ["telemetry.example.com"] # never asked: always denied
# everything else parks until you answer
```

Two table fields tune `ask` (both inert outside `ask` mode):

- `ask_timeout`, a duration like `"90s"` or `"5m"` that bounds how long a parked
  request waits before it times out to a deny. Absent means wait indefinitely.
- `ask_notice`, `true` by default; a stderr alert is printed when a request parks.
  Set `false` to silence the inline alert (the request still parks; answer it with
  `sbx net pending`).

The full workflow is on the [ask mode](ask) page.

---

## Opening the network wide

Three spellings are used to "let everything through", and they are **not**
equivalent. Only `shared` removes the proxy; the other two keep every byte flowing
through it and merely widen what the policy permits. (A fourth spelling, `allow =
["*"]`, does not exist: it is [rejected](rules#no-catch-all) in favour of these, which
say in the posture what they do.)

```bash
sbx run --net shared -- ./x.sh                   # no proxy at all: the host's network
sbx run --net 'allow=re:.*' -- ./x.sh            # deny mode, one catch-all rule
sbx run --config 'network = "allow"' -- ./x.sh   # allow-by-default, an empty denylist
```

|  | `--net shared` | `--net 'allow=re:.*'` | `--config 'network = "allow"'` |
|---|---|---|---|
| the proxy | **none**: no `http_proxy` in the cage | MITM proxy | MITM proxy |
| the network namespace | the host's own | empty | empty |
| public `https://`, any port | direct | allowed | allowed |
| cleartext `http://` | works | **refused (403)** | **refused (403)** |
| raw `tcp://` (ssh, a database) | works | never spliced | never spliced |
| host loopback and LAN | **reachable** | out of reach | out of reach |
| DNS and any other non-HTTP traffic | direct, like on the host | nothing leaves the namespace | nothing leaves the namespace |
| `[secret]` header injection | **dropped, with a warning** | injected | injected |
| `sbx net rules` / `logs` / `stats` / `capture` | nothing to show | full | full |
| [`--net-learn`](../cli/app#learning-an-apps-egress---net-learn) | refused (needs a filtering posture) | accepted, learns nothing | accepted, learns nothing |

`--net-learn` turns each refusal into a rule, so under a posture where nothing is
refused it has nothing to write: learn an app's egress under its **own** posture, not
under one of these.

### Why only `shared` is a real bypass

`shared` puts the cage in **your** network namespace, so there is nothing to filter
with: no proxy is started, no `http_proxy`/`https_proxy` is set, and a tool connects
out exactly as it would on the host. That includes your **host loopback** (a database
on `127.0.0.1`, a local model server, a dev server) and your **LAN**, which no
filtering posture ever exposes.

Three consequences are worth knowing before reaching for it:

- **Credential injection stops.** `[secret]` HTTP headers are injected *by the proxy*,
  so with no proxy there is nowhere to inject them. They are dropped with a loud
  warning rather than silently ignored (see [`[secret]`](../configuration/secret)).
- **Nothing is observable.** No rules, and no [decision log, stats, or
  capture](observability): the traffic never passes through sbx.
- **`forward` becomes a no-op** (noticed at launch): the cage's loopback already *is*
  the host's, so there is nothing to bridge.

### What the two filtering spellings still refuse

A catch-all rule and an allow-by-default posture only move the *verdict*; the
proxy's structural guards are untouched, so three refusals survive both:

- **Cleartext is opt-in.** `http://` needs an explicit `http://host` allow rule; the
  default action is never consulted for it, and a regex never opens it. A plain
  `http://` request answers `403` under either spelling.
- **Raw TCP is opt-in.** A `tcp://` splice happens only when an explicit
  `tcp://host:port` allow rule matches. Everything else takes the inspected HTTPS
  path, which a non-HTTP protocol cannot satisfy, so ssh and a database client stay
  blocked. See [rules](rules).
- **Private addresses stay out of reach.** The [SSRF guard](architecture#the-ssrf-guard)
  admits a private or loopback address only when the *deciding rule names that exact
  host*: a regex never does, and an allow-by-default verdict has no deciding rule at
  all. Under a filtering posture the cage cannot even route to them (its namespace is
  empty), and the host-side proxy answers `403` at CONNECT time.
  [`sbx test net`](../cli/test#private-and-internal-addresses) replays that guard: it
  reports the refusal outright for an IP literal, and, since it resolves nothing, notes
  the condition for a name no rule covers exactly.

To reach one internal host on purpose, name it exactly (`allow = ["db.internal"]`,
`allow = ["tcp://db.internal:5432"]`), which is the deliberate act the guard is
waiting for.

### Which of the two filtering forms to prefer

`network = "allow"` is the readable one: it is a posture, it reads as "everything
except my `deny` list", and a `deny` entry keeps working on top of it. The catch-all
`re:.*` is a `deny` posture wearing a disguise; prefer it only when you want each
allowed request to carry a *visible deciding rule* in [`sbx net logs`](observability)
rather than an `allowed-by-default` verdict.

Two practical notes on the catch-all form:

- `--net allow=…` splits its value on **commas**, so a regex containing one (a
  `{n,m}` quantifier, an alternation list) must go through
  `--config '[network] allow = ["re:…"]'` instead. You do not have to remember it:
  a value whose split would break a `re:` pattern is refused whole, naming the cure.
  A comma-free regex (`--net 'allow=re:.*'`) and a list mixing hosts with an intact
  pattern (`--net 'allow=github.com,re:^https://api\.'`) are unaffected.
- In an **app profile**, a bare `allow = ["re:.*"]` inherits the app
  [read-by-default posture](#default_methods-apps-only) and resolves to
  `{GET,HEAD} re:.*`, so a POST is still refused. Write `allow = ["{*} re:.*"]` (or
  `default_methods = ["*"]`) to mean every verb. A `--net` override on the command
  line is not affected: an override posture is Mode A and carries all verbs.

### It is still trust-gated

All three are `network` values, so the [security gate](#security-gated) applies: an
untrusted project cannot reach any of them from its `.sbx.toml`. A one-shot `--net` /
`--config` on the command line is trusted by invocation, which is what makes it the
practical escape hatch when a filtering posture blocks a legitimate tool.

---

## The built-in self-equip set

Under any filtering posture, one set of read-only (`{GET,HEAD}`) hosts is always
allowed so a project can provision its toolchain even when untrusted:

- `cache.nixos.org`: the nix binary cache (substitution)
- `*.nixos.org`: channels, releases, tarballs
- `github.com`, `api.github.com`, `codeload.github.com`: nixpkgs GitHub sources
- `*.githubusercontent.com`: raw content and release assets
- `search.devbox.sh`: the Nixhub metadata endpoint the nix resolver queries (overridable via the per-toolkit resolver plugin)
- `mise-versions.jdx.dev`: mise's version index

These are the *version-resolution and nix-source* hosts both self-equip front-ends
(in-cage nix and the `mise:` backends) need. The per-tool *artifact* hosts (npm, a
release host) are **not** in this set: a profile that fetches from them must list
them explicitly. The whole set is shown in `sbx config` (and in
[`sbx net rules --source builtin`](observability)), so it is never a silent
allowance, and a `deny` rule can carve any of it back out.

---

## Mode inheritance

A `[network]` **table may omit `mode`** to inherit it from the parent config layer
while keeping its own `allow`/`deny` rules. This lets a project add rules without
restating the posture, and lets an app narrow the baseline's rule set:

```toml
# global sbx.toml
[network]
mode  = "deny"
allow = ["*.nixos.org"]

# project .sbx.toml: no `mode`, inherits "deny", adds a host
[network]
allow = ["api.anthropic.com"]
```

Inheritance is deliberately **fail-safe**: only a *filtering* mode is inherited. If
the parent posture is `allow` (a denylist), `shared`, `none`, or absent, a
mode-less table falls back to the safe **`deny`** rather than inheriting an open
posture. So a mode-less table can never silently widen the network: a `mode`
typo lands here too (the table parses mode-less and resolves to `deny`/`ask`, never
`shared`). Inheritance follows the layer chain: an app takes the baseline's mode, a
project takes the global's.

The `ask_notice` and `stats` fields inherit the same way: a layer that does not
mention them leaves the inherited value unchanged.

---

## default_methods (apps only)

An app launched in **Mode B** (the locked-down agent posture: every `sbx app` is
Mode B) reads by default: its unscoped allow rules default to `["GET", "HEAD"]`, so
an agent can read from an allowed host but cannot POST/PUT/DELETE unless a rule
opts the host out with a `{VERB}` or `{*}` [method prefix](rules#method-scoping).

`default_methods` overrides that per-app default:

```toml
[app.writer.network]
mode = "deny"
allow = ["api.example.com"]
default_methods = ["GET", "POST"]   # this app may also POST to unscoped hosts
# default_methods = ["*"]           # all verbs (opt the whole app back to Mode A behavior)
```

This field is **ignored on the baseline** `[network]`: `sbx run`
(Mode A) stay all-verbs. It only changes an app's unscoped (`{...}`-less) allow
rules; an explicit `{VERB}` or `{*}` on a rule always keeps its own verbs. See the
[rule grammar](rules#method-scoping) for how a per-rule prefix interacts with
this app default.

---

## Security-gated

`network` is a **security field**. Narrowing or widening the network is a
confidentiality choice an untrusted project may not make, so the posture (and its
rules, groups, `ask_timeout`, `stats`, and `default_methods`) is honored **only**
from:

- the **global** config (trusted by its location), or
- a **trusted** project `.sbx.toml` (blessed with [`sbx trust`](../concepts/trust)).

An untrusted (or edited-since-trusted) project's `network` is **dropped with a
warning**, and the cage falls back to the built-in default. This holds both
directions: an untrusted project can neither *cut* the network (to hide what it
does) nor *reopen* one that a trusted layer restricted. A globally-declared app
keeps its posture even under an untrusted project: which is the whole point of
running an agent *on* untrusted code.

To change the posture for a single launch without editing (and re-trusting) a file,
use the [`--net` one-shot override](../configuration/overrides), which is trusted
by invocation.

---

## See also

- [Rule grammar](rules): what goes in the `allow`/`deny` lists.
- [Ask mode](ask): the `ask` posture's workflow.
- [Egress groups](groups): reuse a set of hosts across apps.
- [Observability](observability): inspect the effective mode and rules.
- [`network` configuration reference](../configuration/network)
- [The trust gate](../concepts/trust): what "trusted" means and how to grant it.
- [Apps](../apps/): Mode B and `default_methods` in context.
