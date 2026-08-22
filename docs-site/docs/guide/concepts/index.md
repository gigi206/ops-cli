---
sidebar_label: "What sbx is"
description: "What sbx is, the reference class it belongs to, and the two actor modes it runs in."
---

# What sbx is (and is not)

`sbx` is a **sandbox launcher**: a single static Rust binary that runs tools, including **encapsulated AI agents**, inside a [bubblewrap](https://github.com/containers/bubblewrap)
sandbox where they can install a project's full dependency set via single-user,
daemonless [Nix](https://nixos.org/) **without mutating the host OS**.

See also: [Security model](security-model) · [Provisioning](provisioning) · [Quick start](../getting-started/quickstart).

## The problem it solves

Running an autonomous coding agent on a project means letting untrusted code install
dependencies and execute. `sbx` gives that agent a real boundary: it runs as your
user, but the **bind layout is the security control**: the host filesystem and your
secrets are absent from the cage unless explicitly and trustedly granted. The agent
self-equips a per-project Nix store it cannot use to escape, behind an always-on
[seccomp filter](enforcement) and best-effort resource limits; egress is a
[deny-by-default allowlist](../networking/modes) carrying no rules of its own, so only the
hosts you name, and the built-in self-equip set, are reachable at all.

## What it is not

`sbx` is **not** a container manager. There is no OCI runtime wrapping, no
image to build, no registry.

The reference class is **sandboxes**: tools whose job is isolation under
capability-bearing namespaces, **not** environment managers that assemble a
toolchain but isolate nothing. `sbx` does both: it provisions a project's
toolchain *and* confines it.

| | `sbx` | container manager | env manager |
|---|---|---|---|
| Isolates the host | yes (bind layout + namespaces) | yes (image + namespaces) | no |
| Builds an image | no | yes | no |
| Runs as your uid | yes (same-uid) | usually root-in-container | n/a |
| Provisions a toolchain | yes (nix + mise) | at build time | yes |
| Root/daemon required | no | usually | no |

What it does not *do*, as opposed to what it is not, is gathered in [Decisions and
limits](decisions): the layers that are depth rather than boundary, the holes a field opens
when you ask for one, and why the shape is one process rather than a daemon.

## The two actor modes

`sbx` distinguishes two ways a sandbox is used, and the *default* is the locked-down
one:

- **Mode A: interactive shell** (`sbx run`): a semi-trusted user at a
  keyboard. Network egress rules stay all-verbs; the human is the trust anchor.
- **Mode B, autonomous agent** (`sbx app run <name>`): actions are untrusted. **This is
  the default posture.** An app's egress allowlist defaults to read-only verbs
  (`GET`/`HEAD`) unless a rule opts a host out, credentials are injected host-side
  and never enter the cage, and the app gets its own isolated home.

The whole design is oriented around Mode B: safely running an agent *on* untrusted
code. See [the app framework](../apps/).

## The essentials

- The default posture is the **locked-down agent**, not the interactive shell.
- **Capability-bearing unprivileged user namespaces are a hard requirement**: no
  boundary, no launch (see [`sbx doctor`](../getting-started/doctor)).
- The cage runs **as your uid** (same-uid), so a secret is protected by being
  **absent**, not merely read-only.
- An untrusted project's `.sbx.toml` **cannot** touch security-relevant fields; the
  [trust gate](trust) binds approval to the file's content hash.

## The rest of this section

Each page below argues one subject and states its own limits; what cuts across all of
them is gathered in [Decisions and limits](decisions).

- [Architecture](architecture): the boundary, the launch pipeline from a command to a
  cage, the control planes, and where each decision is made.
- [Security model](security-model): same-uid confinement, confidentiality by absence,
  the bind layout, and where the protection stops.
- [Decisions and limits](decisions): what sbx does not do, and what would reopen each
  structural choice.
- [The trust gate](trust): the content-hash model, and free fields versus security
  fields.
- [Enforcement stack](enforcement): bubblewrap, seccomp, cgroups and the egress
  firewall, and which one refuses what.
- [Observability](observability): the process and filesystem lenses on a running cage,
  and what they cannot see.
- [Provisioning](provisioning): the rolling nix channel, the per-project store, and
  self-equipping.
- [Directory layout](directory-layout): where the config, data, state and trust records
  live.
