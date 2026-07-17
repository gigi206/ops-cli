# Network modes

The `network` field chooses the sandbox's egress posture. There are five values:
two that run **no proxy** (`none`, `shared`) and three **filtering** postures that
run the [Model-B egress proxy](architecture.md) and honor the
[rule grammar](rules.md): `deny`, `allow`, and `ask`.

```toml
# the two simple postures
network = "none"     # empty network namespace — nothing reaches out
network = "shared"   # the host network, unfiltered (the default)

# the three filtering postures (string form: no carve-outs yet)
network = "deny"     # allowlist: only what you allow reaches
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

The string and table forms are the same field — a bare string is just a table with
no `allow`/`deny` lists. See [rules](rules.md) for what goes in the lists.

---

## `none`

An empty network namespace: the cage has loopback and nothing else — no route, no
DNS, no way out. A direct connection fails immediately (`Could not resolve host` /
`Could not connect`). Use it for fully offline work, or to be certain a tool cannot
phone home.

Because there is no proxy, there are no rules, no [stats](observability.md), and no
[live log](observability.md#sbx-net-logs). Note that a project's *first* provision
of a tool needs the network — an offline `none` cage can only run what is already
in the per-project store.

## `shared`

The host network, unfiltered — the cage shares your network namespace and reaches
whatever your host can. This is the **default** when `network` is unset. It is the
right posture for your own interactive shell (`sbx shell`) and for trusted work
where filtering would only get in the way. There is no proxy, so no rules, stats,
or log apply.

`shared` is also the documented **escape hatch**: set `network = "shared"` in your
global config to make open networking the default for every project, overriding
whatever `sbx`'s built-in default becomes. An untrusted project still cannot reach
this posture (see [the security gate](#security-gated)).

## `deny`

**Deny-by-default — an allowlist.** Only the hosts your `allow` list names can be
reached; everything else is refused (HTTP 403 at the proxy). This is the posture
for running an agent you do not fully trust: give it exactly the provider host and
whatever else it legitimately needs, and nothing else leaves.

```toml
[network]
mode  = "deny"
allow = ["api.anthropic.com"]
```

Under `deny`, the [built-in self-equip set](#the-built-in-self-equip-set) is
unioned in so the project can still provision from the nix cache and GitHub — you
do not have to list those yourself. A `deny` entry can carve a hole back out of any
allow (including a built-in one): `deny` always wins.

## `allow`

**Allow-by-default — a denylist.** Every public host reaches *except* the ones your
`deny` list names. This is the broad-access posture with targeted blocks — useful
when a tool needs general internet but a specific host (a telemetry endpoint, a
known-bad domain) must be blocked.

```toml
[network]
mode = "allow"
deny = ["telemetry.example.com", "*.doubleclick.net"]
```

Under `allow`, the `allow` list has almost no remaining effect (every public host
is already permitted); its one job is the [SSRF exception](architecture.md#the-ssrf-guard)
— a private or internal address is refused unless an allow rule names that exact
host. In other words, `allow` opens the *public* internet, not your internal
network.

## `ask`

**Park-and-confirm.** An `allow` entry auto-passes and a `deny` entry auto-fails
(exactly as under the other modes), but anything *undecided* **parks**: the request
blocks inside the cage while you answer it from another terminal with
[`sbx net pending`](ask.md). You allow or deny it live, optionally remembering the
answer for the session or persisting a rule. This is the discovery posture — run an
agent and watch, in real time, what it tries to reach, deciding as you go.

```toml
[network]
mode  = "ask"
allow = ["api.anthropic.com"]   # never asked — always allowed
deny  = ["telemetry.example.com"] # never asked — always denied
# everything else parks until you answer
```

Two table fields tune `ask` (both inert outside `ask` mode):

- `ask_timeout` — a duration like `"90s"` or `"5m"` that bounds how long a parked
  request waits before it times out to a deny. Absent means wait indefinitely.
- `ask_notice` — `true` by default; a stderr alert is printed when a request parks.
  Set `false` to silence the inline alert (the request still parks; answer it with
  `sbx net pending`).

The full workflow is on the [ask mode](ask.md) page.

---

## The built-in self-equip set

Under any filtering posture, one set of read-only (`{GET,HEAD}`) hosts is always
allowed so a project can provision its toolchain even when untrusted:

- `cache.nixos.org` — the nix binary cache (substitution)
- `*.nixos.org` — channels, releases, tarballs
- `github.com`, `api.github.com`, `codeload.github.com` — nixpkgs GitHub sources
- `*.githubusercontent.com` — raw content and release assets
- `search.devbox.sh` — the nixhub metadata endpoint the nix resolver queries
- `mise-versions.jdx.dev` — mise's version index

These are the *version-resolution and nix-source* hosts both self-equip front-ends
(in-cage nix and the `mise:` backends) need. The per-tool *artifact* hosts (npm, a
release host) are **not** in this set — a profile that fetches from them must list
them explicitly. The whole set is shown in `sbx config` (and in
[`sbx net rules --source builtin`](observability.md)), so it is never a silent
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

# project .sbx.toml — no `mode`, inherits "deny", adds a host
[network]
allow = ["api.anthropic.com"]
```

Inheritance is deliberately **fail-safe**: only a *filtering* mode is inherited. If
the parent posture is `allow` (a denylist), `shared`, `none`, or absent, a
mode-less table falls back to the safe **`deny`** rather than inheriting an open
posture. So a mode-less table can never silently widen the network — a `mode`
typo lands here too (the table parses mode-less and resolves to `deny`/`ask`, never
`shared`). Inheritance follows the layer chain: an app takes the baseline's mode, a
project takes the global's.

The `ask_notice` and `stats` fields inherit the same way — a layer that does not
mention them leaves the inherited value unchanged.

---

## default_methods (apps only)

An app launched in **Mode B** (the locked-down agent posture — every `sbx app` is
Mode B) reads by default: its unscoped allow rules default to `["GET", "HEAD"]`, so
an agent can read from an allowed host but cannot POST/PUT/DELETE unless a rule
opts the host out with a `{VERB}` or `{*}` [method prefix](rules.md#method-scoping).

`default_methods` overrides that per-app default:

```toml
[app.writer.network]
mode = "deny"
allow = ["api.example.com"]
default_methods = ["GET", "POST"]   # this app may also POST to unscoped hosts
# default_methods = ["*"]           # all verbs (opt the whole app back to Mode A behavior)
```

This field is **ignored on the baseline** `[network]` — `sbx run` and `sbx shell`
(Mode A) stay all-verbs. It only changes an app's unscoped (`{...}`-less) allow
rules; an explicit `{VERB}` or `{*}` on a rule always keeps its own verbs. See the
[rule grammar](rules.md#method-scoping) for how a per-rule prefix interacts with
this app default.

---

## Security-gated

`network` is a **security field**. Narrowing or widening the network is a
confidentiality choice an untrusted project may not make, so the posture — and its
rules, groups, `ask_timeout`, `stats`, and `default_methods` — is honored **only**
from:

- the **global** config (trusted by its location), or
- a **trusted** project `.sbx.toml` (blessed with [`sbx trust`](../concepts/trust.md)).

An untrusted (or edited-since-trusted) project's `network` is **dropped with a
warning**, and the cage falls back to the built-in default. This holds both
directions: an untrusted project can neither *cut* the network (to hide what it
does) nor *reopen* one that a trusted layer restricted. A globally-declared app
keeps its posture even under an untrusted project — which is the whole point of
running an agent *on* untrusted code.

To change the posture for a single launch without editing (and re-trusting) a file,
use the [`--net` one-shot override](../configuration/overrides.md), which is trusted
by invocation.

---

## See also

- [Rule grammar](rules.md) — what goes in the `allow`/`deny` lists.
- [Ask mode](ask.md) — the `ask` posture's workflow.
- [Egress groups](groups.md) — reuse a set of hosts across apps.
- [Observability](observability.md) — inspect the effective mode and rules.
- [`network` configuration reference](../configuration/network.md)
- [The trust gate](../concepts/trust.md) — what "trusted" means and how to grant it.
- [Apps](../apps/README.md) — Mode B and `default_methods` in context.
