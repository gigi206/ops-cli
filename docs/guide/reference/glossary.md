# Glossary

The terms this guide uses.

See also: [What sbx is](../concepts/overview.md) · [Security model](../concepts/security-model.md).

**Bind** — a host path exposed inside the cage, read-only by default. The set of binds
*is* the security control. See [`binds`](../configuration/binds.md).

**bubblewrap (`bwrap`)** — the unprivileged sandboxing engine `sbx` launches the cage
with (all namespaces, `no_new_privs`, all capabilities dropped). See
[Enforcement](../concepts/enforcement.md).

**Cage** — the sandbox instance a launch creates: a bubblewrap namespace with a hermetic
FHS, a synthetic identity, and the enforcement stack.

**Confidentiality by absence** — the principle that a secret is protected by being
**absent** from the cage, not merely read-only — a consequence of the
[same-uid](#same-uid) model. See [Security model](../concepts/security-model.md).

**Control plane** — `sbx`'s own state (its config, data, and trust directories). Pinned
read-only even inside a broad read-write bind. See [Security model](../concepts/security-model.md#the-control-plane-is-pinned).

**Egress** — outbound network traffic. Filtered by the [network posture](../networking/modes.md).

**Free field** — a config field applied even from an untrusted project (only `env`). The
opposite of a [security field](#security-field). See [The trust gate](../concepts/trust.md).

**Hermetic FHS** — the minimal, self-contained filesystem the cage presents (`/bin/sh`,
`/usr/bin/env`, `/nix`, a synthetic `/etc`), with no host `/usr` or ambient libraries.

**Mode A / Mode B** — the two actor modes. Mode A is an interactive user shell
([`sbx run`](../cli/run.md)); Mode B is an autonomous agent
([`sbx app`](../cli/app.md)) and is the default posture. See [Overview](../concepts/overview.md#the-two-actor-modes).

**Model B** — the egress architecture: an empty network namespace whose only exit is an
in-cage forwarder bridging to a host-side allowlisting proxy. See
[Networking architecture](../networking/architecture.md).

**nixhub** — the index `sbx` queries to resolve a `nix:` tool to a pinned nixpkgs
revision. See [`sbx search`](../cli/search.md).

**Per-project store** — each project's own writable nix store, seeded from the shared
store, so an agent that self-equips writes only there. See [Provisioning](../concepts/provisioning.md).

**Profile** — a portable, standalone file defining one [app](../apps/README.md). Imported
deliberately. See [Portable profiles](../apps/profiles.md).

**Resolver** — the **source** layer of a secret (`env://`, `file://`, `sops://`, or a
plugin scheme). Distinct from the [broker](../secrets/injection.md) (the sink). See
[Resolvers](../secrets/resolvers.md).

<a id="same-uid"></a>**Same-uid** — the cage runs as *your* user id, not a separate
identity — so a bound file is readable, and the bind layout is the boundary. See
[Security model](../concepts/security-model.md).

<a id="security-field"></a>**Security field** — a config field honored only from a
trusted source (binds, network, secrets, packages, nixpkgs, gui, limits, apps, net
groups). See [The trust gate](../concepts/trust.md).

**Self-equip** — an agent installing its own toolchain from inside the cage, into the
per-project store. See [`sbx mise`](../cli/mise.md).

**Synthetic identity** — the `uid=1000(sandbox)` user (and synthetic `/etc/passwd`) the
cage presents, generated outside every writable mount.

**Trust gate** — the mechanism binding a project config's [security fields](#security-field)
to a content hash, on the direnv model. See [The trust gate](../concepts/trust.md).

**Trusted by location / by content** — the global config and app profiles are trusted
because you placed them (location); a project `.sbx.toml` is trusted by
[`sbx trust`](../cli/trust.md) recording its content hash.
