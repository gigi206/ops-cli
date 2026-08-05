# Networking (egress)

`sbx` controls what the sandbox can reach on the network. This is the
*confidentiality-and-integrity* half of running an untrusted agent: the cage
already cannot read your host filesystem (secrets are absent, not merely
read-only), and the egress control decides which hosts (and, for HTTP, which
paths and methods) an in-cage tool may talk to. A **gRPC** service (HTTP/2) is
supported too: list its host under [`http2`](../configuration/network#http2-and-grpc)
and each RPC is inspected and filtered by `:path` (`/package.Service/Method`) like any HTTP request.

The default posture is **`deny`** (an allowlist carrying no rules of its own, so a
cage nobody configured reaches only the [self-equip set](modes#the-built-in-self-equip-set)).
This page is about the three *filtering* postures: `deny` (an allowlist), `allow`
(a denylist), and `ask` (park-and-confirm). All of them are built on one
architecture, **Model B**, and all of them are
[security-gated](modes#security-gated): the network posture is honored only from
the global config or a **trusted** project, never from an untrusted one. That gate
is why the default matters as much as it does, since an untrusted project's own
posture is dropped and this is what it runs under. To make the open host network
your baseline instead, set [`network = "shared"`](modes#shared) in your global config.

---

## The five modes at a glance

| Mode | What reaches the cage | Filtering proxy? | Typical use |
|---|---|---|---|
| [`none`](modes#none) | nothing, an empty network namespace | no | fully offline work; a tool that must not phone home |
| [`shared`](modes#shared) | the whole host network, unfiltered | no | trusted, interactive work; your own shell |
| [`deny`](modes#deny) | only the hosts you allow (an **allowlist**) | yes | **the default**: reach a provider and the nix cache, nothing else |
| [`allow`](modes#allow) | every public host except the ones you deny (a **denylist**) | yes | broad access with a few carve-outs blocked |
| [`ask`](modes#ask) | allow/deny listed hosts decide immediately; anything else **parks** for your live decision | yes | discovering what an agent needs; interactive triage |

`deny`, `allow`, and `ask` are the three **filtering** postures: each runs the
egress proxy and honors the [rule grammar](rules). `none` and `shared` run no
proxy (there is nothing to filter), so they have no rules, no
[stats](observability), no [live log](observability#sbx-net-logs), and no
[live flow view](observability#sbx-net-live).

Under a filtering posture, one **always-allowed self-equip set** is unioned into
your rules regardless of trust so a project can still provision its toolchain (the
nix binary cache, the nixpkgs GitHub sources, and the nixhub/mise version
indexes). It is shown in `sbx config`, so it is never a silent allowance, and a
`deny` rule can still carve it back out. See [modes](modes#the-built-in-self-equip-set).

---

## Model B in one paragraph

A filtering cage runs in an **empty network namespace**: no interfaces but
loopback, no route, no DNS. Nothing leaves it by construction; a misconfiguration
fails *closed*. The one and only path out is a **Unix-domain socket** bound into
the cage, onto which an in-cage `socat` forwarder relays `127.0.0.1:18043` (the
proxy the tools point at) as a TCP→UDS bridge. On the host side of that socket sits
an **`sbx`-owned MITM CONNECT proxy** that terminates TLS with a per-session,
cage-only CA, checks each request against your resolved policy (host, port, path,
method, regex), resolves DNS **host-side** (so the cage never sees a name to
exfiltrate through), validates the upstream certificate against the system trust
store, and only then relays the bytes. Deny-by-construction, filtered by an
allowlist you author. The full evidence and the rejected alternative (Model P,
pasta NAT) are in [architecture](architecture) (the section above).

---

## The pages

- **[Network modes](modes)**: `none` / `shared` / `deny` / `allow` / `ask` in
  depth, the config forms, mode inheritance, and the security gate.
- **[Rule grammar](rules)**: the full syntax of an allow/deny entry: hosts,
  `*.domain`, exact URLs, IP literals, `re:` regexes, ports, `{VERB}` method
  scoping, and the raw `tcp://` L4 splice. Deny always wins. The reference page.
- **[Egress groups](groups)**: `[net.groups]`: declare a set of hosts once,
  reference it from any allow/deny list with `@name`.
- **[Ask mode](ask)**: the park-and-confirm workflow end to end, with
  `sbx net pending` and `sbx net pending watch`.
- **[Observability](observability)**: inspect and audit egress with
  `sbx net rules`, `sbx net stats`, `sbx net logs`, `sbx net live`, and
  `sbx test net`.
- **[Architecture](architecture)**: how Model B works under the hood, and why
  it was chosen over the alternatives.
- **[Inbound forwarding (`forward`)](forward)**: the reverse direction: forward a host
  loopback port *into* the cage so an OAuth `localhost:<port>` callback or a cage-run dev
  server is reachable from the host. Loopback-only, trusted-only, orthogonal to egress.

Credential injection into an allowed request (and the secret-redaction tripwires
that ride the same proxy) are a separate subsystem: see
[Secrets](../secrets/).

---

## See also

- [`network` configuration reference](../configuration/network): the field itself.
- [Secrets](../secrets/): credential injection over the egress proxy.
- [Security model](../concepts/security-model): why the bind layout, not the
  network alone, is the boundary.
- [`sbx net` CLI reference](../cli/net) · [`sbx test` CLI reference](../cli/test)
