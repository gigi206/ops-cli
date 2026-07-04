# Networking (egress)

`ops` controls what the sandbox can reach on the network. This is the
*confidentiality-and-integrity* half of running an untrusted agent: the cage
already cannot read your host filesystem (secrets are absent, not merely
read-only), and the egress control decides which hosts — and, for HTTP, which
paths and methods — an in-cage tool may talk to.

The default posture is **`shared`** (the host network, unfiltered). Everything on
this page is about the *filtering* postures you opt into for an agent you do not
fully trust: `deny` (an allowlist), `allow` (a denylist), and `ask`
(park-and-confirm). All of them are built on one architecture — **Model B** — and
all of them are [security-gated](modes.md#security-gated): the network posture is
honored only from the global config or a **trusted** project, never from an
untrusted one.

---

## The five modes at a glance

| Mode | What reaches the cage | Filtering proxy? | Typical use |
|---|---|---|---|
| [`none`](modes.md#none) | nothing — an empty network namespace | no | fully offline work; a tool that must not phone home |
| [`shared`](modes.md#shared) | the whole host network, unfiltered (the default) | no | trusted, interactive work; your own shell |
| [`deny`](modes.md#deny) | only the hosts you allow (an **allowlist**) | yes | the agent default — reach a provider and the nix cache, nothing else |
| [`allow`](modes.md#allow) | every public host except the ones you deny (a **denylist**) | yes | broad access with a few carve-outs blocked |
| [`ask`](modes.md#ask) | allow/deny listed hosts decide immediately; anything else **parks** for your live decision | yes | discovering what an agent needs; interactive triage |

`deny`, `allow`, and `ask` are the three **filtering** postures — each runs the
egress proxy and honors the [rule grammar](rules.md). `none` and `shared` run no
proxy (there is nothing to filter), so they have no rules, no
[stats](observability.md), and no [live log](observability.md#ops-net-logs).

Under a filtering posture, one **always-allowed self-equip set** is unioned into
your rules regardless of trust so a project can still provision its toolchain (the
nix binary cache, the nixpkgs GitHub sources, and the nixhub/mise version
indexes). It is shown in `ops config`, so it is never a silent allowance, and a
`deny` rule can still carve it back out. See [modes](modes.md#the-built-in-self-equip-set).

---

## Model B in one paragraph

A filtering cage runs in an **empty network namespace** — no interfaces but
loopback, no route, no DNS. Nothing leaves it by construction; a misconfiguration
fails *closed*. The one and only path out is a **Unix-domain socket** bound into
the cage, onto which an in-cage `socat` forwarder relays `127.0.0.1:18043` (the
proxy the tools point at) as a TCP→UDS bridge. On the host side of that socket sits
an **`ops`-owned MITM CONNECT proxy** that terminates TLS with a per-session,
cage-only CA, checks each request against your resolved policy (host, port, path,
method, regex), resolves DNS **host-side** (so the cage never sees a name to
exfiltrate through), validates the upstream certificate against the system trust
store, and only then relays the bytes. Deny-by-construction, filtered by an
allowlist you author. The full evidence and the rejected alternative (Model P,
pasta NAT) are in [architecture](architecture.md) and the
[spike findings](../../bwrap-net-spike-findings.md).

---

## The pages

- **[Network modes](modes.md)** — `none` / `shared` / `deny` / `allow` / `ask` in
  depth, the config forms, mode inheritance, and the security gate.
- **[Rule grammar](rules.md)** — the full syntax of an allow/deny entry: hosts,
  `*.domain`, exact URLs, IP literals, `re:` regexes, ports, `{VERB}` method
  scoping, and the raw `tcp://` L4 splice. Deny always wins. The reference page.
- **[Egress groups](groups.md)** — `[net.groups]`: declare a set of hosts once,
  reference it from any allow/deny list with `@name`.
- **[Ask mode](ask.md)** — the park-and-confirm workflow end to end, with
  `ops net pending` and `ops net pending watch`.
- **[Observability](observability.md)** — inspect and audit egress with
  `ops net rules`, `ops net stats`, `ops net logs`, and `ops test net`.
- **[Architecture](architecture.md)** — how Model B works under the hood, and why
  it was chosen over the alternatives.

Credential injection into an allowed request (and the secret-redaction tripwires
that ride the same proxy) are a separate subsystem — see
[Secrets](../secrets/README.md).

---

## See also

- [`network` configuration reference](../configuration/network.md) — the field itself.
- [`[net.groups]` configuration reference](../configuration/net-groups.md) — the group table.
- [Secrets](../secrets/README.md) — credential injection over the egress proxy.
- [Security model](../concepts/security-model.md) — why the bind layout, not the
  network alone, is the boundary.
- [`ops net` CLI reference](../cli/net.md) · [`ops test` CLI reference](../cli/test.md)
- Design: [egress spike findings](../../bwrap-net-spike-findings.md) ·
  [threat model and binds](../../bwrap-threat-model-and-binds.md)
