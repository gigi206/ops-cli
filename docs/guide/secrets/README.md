# Secrets

`sbx` lets an agent *authenticate* to a host without ever handing it the
credential. A GitHub token, an API key, a registry password: the plaintext is
read **on the host**, injected into the matching outbound request **on the
wire**, and torn down when the cage exits. The agent makes the HTTPS call it was
going to make anyway; `sbx` brokers the credential onto it. The secret's bytes
never enter the sandbox.

## The invariant: no plaintext secret in the cage

> **`sbx` never places a plaintext secret inside the cage.** Every resolution is
> host-side, before the cage starts. The agent receives a *capability*
> (authenticate to an allowed host), never the secret's bytes.

This is a hard line, on the same footing as the capability-bearing-userns
requirement and the immutable shared store. It is what makes the secret *absent
by construction* rather than merely present-but-discouraged:

- A **capability** is scoped and ephemeral: usable only while the cage runs, and
  only toward the hosts the [egress allowlist](../networking/modes.md) permits.
- A **secret** is permanent and portable: exfiltrate it once, reuse it forever,
  anywhere.

Holding a capability is not holding the secret. `sbx` blocks
**extraction/portability**, not in-session use (granting the use is the whole
point). The irreducible lever is therefore **least privilege at the source**: a
fine-scoped token or a read-only account is only as dangerous as its own
permissions. Scope the secret tightly where it lives.

## Two host-side layers: resolver × broker

A secret declaration composes two orthogonal halves, and **both run host-side**:

| Layer | Role | Question it answers | Documented in |
|---|---|---|---|
| **Resolver** (SOURCE) | fetch the plaintext | *where does the value come from?* | [resolvers.md](resolvers.md) |
| **Broker** (SINK) | expose only a capability to the cage | *how does the agent use it without seeing it?* | [injection.md](injection.md) |

The resolver fetches the plaintext into `sbx`'s own host process (from an
environment variable, a file, a SOPS-encrypted store, or a resolver plugin). The
broker, today, HTTP-header injection, consumes that plaintext host-side and
puts only a capability in front of the cage. The plaintext is used and discarded
on the host; only ciphertext (if any) and capabilities ever cross into the cage.

```mermaid
flowchart LR
    subgraph host_side["**<span style=\"color:#1b5e20\">host side</span>**"]
        direction LR
        R["**<b>resolver.fetch(ref)</b>**<br/><i>env · file · sops · plugin</i>"]
        B["**<b>broker</b>**<br/><i>in sbx mem</i><br/><i>↳ header inject</i>"]
        R -- "<b>plaintext</b>" --> B
    end

    subgraph cage_side["**<span style=\"color:#bf360c\">cage · empty netns</span>**"]
        direction LR
        T["**<b>agent's tool</b>**<br/><i>curl · git · …</i>"]
    end

    B -- "<b>capability</b>" --> T

    classDef hs fill:#e8f5e9,stroke:#2e7d32,stroke-width:1.5px,color:#1b5e20
    classDef cs fill:#fff3e0,stroke:#e65100,stroke-width:1.5px,color:#bf360c
    class R,B hs
    class T cs
```

The two layers compose freely: any source with any broker. Resolvers are the
open-ended, pluggable half (see [plugins.md](plugins.md)); the broker touches the
security boundary, so it stays first-party.

## Injection is effective only under a filtering network

Header injection happens **inside the MITM egress proxy**, and that proxy only
exists under a filtering network posture. A `[secret]` declaration therefore does
nothing unless the cage's network is one of:

- `deny`: filtered egress, deny-by-default (an allowlist);
- `allow`: filtered egress, allow-by-default (a denylist);
- `ask`: filtered egress, park-and-confirm.

Under `network = "shared"` (the open host network) or `network = "none"` (an
empty, uplink-less namespace) there is no proxy on the wire, so a `[secret]`
**injects nothing**. `sbx` warns loudly rather than silently sending an
unauthenticated request: an agent that got a `401` should never have to guess
that the cause was a missing filtering posture. Likewise, a secret's destination
host must itself be reachable under the policy (present in the `allow` list, or
not denied), or the request is refused *before* injection.

See [../networking/modes.md](../networking/modes.md) and
[../configuration/network.md](../configuration/network.md) for the posture that
makes secrets live.

## `[secret]` is a security field

The `[secret]` section is a **security field**: it is honored from the global
config or a **trusted** project, and dropped from an untrusted one: the same
gate that governs `binds`, `network`, and `nixpkgs`. An untrusted project can
declare a `[secret]` section all it likes; the whole section is discarded before
any resolver scheme is even looked up. See
[../concepts/security-model.md](../concepts/security-model.md) and
[../concepts/trust.md](../concepts/trust.md).

The section is a TOML **table keyed by destination host** (not an array), with a
reserved `defaults` sub-table. The full schema: the terse `key` form, the
verbose `from` refs, `header`/`type`/`prefix`: is documented in
[injection.md](injection.md) and [resolvers.md](resolvers.md), and mirrored in
[../configuration/secret.md](../configuration/secret.md).

## Backstops, and their honest limits

Two byte-exact tripwires guard the naive verbatim leak in each direction: the
proxy refuses an outbound request that carries a configured secret value, and
masks a secret that a cooperating upstream reflects back. They are **backstops,
not the boundary**: any encoding (base64, gzip) evades a byte-exact scan. The
real guarantee is structural: empty netns, the egress allowlist, and the fact
that a credential is bound to *one* destination host. See
[redaction.md](redaction.md) for both tripwires and their scope.

## Where to go next

- [resolvers.md](resolvers.md): the SOURCE layer: `env://`, `file://`,
  `sops://`, terse keys, and fallback chains.
- [injection.md](injection.md): the HTTP-header broker: how a credential lands
  on the wire.
- [redaction.md](redaction.md): the outbound and inbound secret tripwires.
- [plugins.md](plugins.md): resolver plugins and signed plugin stores.

## See also

- [../configuration/secret.md](../configuration/secret.md): the `[secret]`
  config reference.
- [../configuration/network.md](../configuration/network.md) and
  [../networking/modes.md](../networking/modes.md): the filtering posture that
  makes injection effective.
- [../concepts/security-model.md](../concepts/security-model.md): where the
  never-in-cage invariant sits among `sbx`'s hard lines.
- [../concepts/trust.md](../concepts/trust.md): the trust gate that admits a
  project's `[secret]` section.
- [https://github.com/gigi206/ops-cli/blob/ops-v2/docs/bwrap-secrets-architecture.md](https://github.com/gigi206/ops-cli/blob/ops-v2/docs/bwrap-secrets-architecture.md), the authoritative design (resolver × broker, the exposure lattice, residuals).
