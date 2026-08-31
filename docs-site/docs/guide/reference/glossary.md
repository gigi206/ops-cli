---
description: "The terms this guide uses in a specific sense: cage, posture, broker, resolver, the trust gate."
---

# Glossary

The terms this guide uses.

See also: [What sbx is](../concepts/) · [Security model](../concepts/security-model).

**Bind**, a host path exposed inside the cage, read-only by default. The set of binds
*is* the security control. See [`binds`](../configuration/binds).

**Broker**, the **sink** half of a secret: what puts a credential on an outbound request
without the cage ever holding it. The first-party broker is HTTP-header injection in the
egress proxy; a [`[broker.<name>]`](../configuration/broker) plugin is the second kind, standing
in front of a host socket. Distinct from the [resolver](../secrets/resolvers), which is the
source half. See [Injection](../secrets/injection).

**bubblewrap (`bwrap`)**: the unprivileged sandboxing engine `sbx` launches the cage
with (all namespaces, `no_new_privs`, all capabilities dropped). See
[Enforcement](../concepts/enforcement).

**Bundle**, everything one tool needs to be installed and to reach its own services,
declared once in the global config and folded into any app that names it in `use`. See
[`[bundle.<name>]`](../configuration/bundles).

**Cage**, the sandbox instance a launch creates: a bubblewrap namespace with a hermetic
FHS, a synthetic identity, and the enforcement stack.

**Confidentiality by absence**: the principle that a secret is protected by being
**absent** from the cage, not merely read-only: a consequence of the same-uid
model. See [Security model](../concepts/security-model).

**Control plane**, `sbx`'s own state (its config, data, and trust directories). Pinned
read-only even inside a broad read-write bind. See [Security model](../concepts/security-model#the-control-plane-is-pinned).

**Declared operation**, a fixed command `sbx` runs on a caller's behalf, in an ephemeral
sibling cage, with a credential the caller never holds. Declared in a
[`[task.<name>]`](../configuration/task) table. See [Declared operations](../tasks/).

**Egress**, outbound network traffic. Filtered by the [network posture](../networking/modes).

**Egress group**, a named set of egress entries, declared once in the global config and
referenced from any allow/deny list with `@name`. See [Egress groups](../networking/groups).

**Free field**, a config field applied even from an untrusted project: [`env`](../configuration/env)
and [`timezone`](../configuration/timezone), the two that read nothing from the host. The opposite
of a security field. See [The trust gate](../concepts/trust).

**Hermetic FHS**, the minimal, self-contained filesystem the cage presents (`/bin/sh`,
`/usr/bin/env`, `/nix`, a synthetic `/etc`), with no host `/usr` or ambient libraries.

**Lens**, one of the four read-only views on a live session: what it ran, what it wrote,
where it went, and what it asked your keys to sign. Each is read over a socket the cage
never sees, and only the exec lens has an enforcing sibling. See
[Observability](../concepts/observability).

**Mode A / Mode B**: the two actor modes. Mode A is an interactive user shell
([`sbx run`](../cli/run)); Mode B is an autonomous agent
([`sbx app`](../cli/app)) and is the default posture. See [Overview](../concepts/#the-two-actor-modes).

**Model B**, the egress architecture: an empty network namespace whose only exit is an
in-cage forwarder bridging to a host-side allowlisting proxy. See
[Networking architecture](../networking/architecture).

**nixhub**, the index `sbx` queries to resolve a `nix:` tool to a pinned nixpkgs
revision. See [`sbx search`](../cli/search).

**Per-project store**, each project's own writable nix store, seeded from the shared
store, so an agent that self-equips writes only there. See [Provisioning](../concepts/provisioning).

**Posture**, the named state a subsystem runs a cage under, chosen from a closed set: the
[network](../networking/modes) posture, the [display](../configuration/gui) posture, the
[exec](../configuration/proc) posture, the [notification](../configuration/notify) mode. A
posture is a security field, so which one applies is what the [trust gate](../concepts/trust)
decides.

**Profile**, a portable, standalone file defining one [app](../apps/). Imported
deliberately. See [Portable profiles](../apps/profiles).

**Resolver**: the **source** layer of a secret (`env://`, `file://`, `sops://`, or a
plugin scheme). Distinct from the [broker](../secrets/injection) (the sink). See
[Resolvers](../secrets/resolvers).

**Same-uid**, the cage runs as *your* user id, not a separate identity, so a bound
file is readable, and the bind layout is the boundary. See
[Security model](../concepts/security-model).

**Security field**, a config field honored only from a trusted source (binds, network,
secrets, packages, nixpkgs, gui, limits, apps, net groups). See
[The trust gate](../concepts/trust).

**Self-equip**, an agent installing its own toolchain from inside the cage, into the
per-project store. See [`sbx mise`](../cli/mise).

**Signer**, a plugin that forms a credential **per request**, for an auth scheme whose value
depends on the request itself (a signature over the method, path and query). Named by
[`sign`](../configuration/secret#sign-a-credential-computed-from-the-request) on a secret. See
[The signer type](../plugins/signer).

**Synthetic identity**, the `sandbox` user (and synthetic `/etc/passwd`) the cage
presents, generated outside every writable mount. The uid and gid are the host's own
(the same-uid model); only the name and the account set are synthetic.

**Trust gate**, the mechanism binding a project config's security fields to a content
hash, on the direnv model. See [The trust gate](../concepts/trust).

**Trusted by location / by content**: the global config and app profiles are trusted
because you placed them (location); a project `.sbx.toml` is trusted by
[`sbx trust`](../cli/trust) recording its content hash.
