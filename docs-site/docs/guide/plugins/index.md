---
sidebar_label: "Overview"
description: "The three kinds of plugin sbx takes, what they share, and the boundary none of them crosses."
---

# Plugins

`sbx` takes **three kinds of plugin**, and this section is all three. A
[resolver](resolvers) adds a `scheme://` that a secret's `from`
can route to. A [broker](broker) stands in front of a host socket the
sandbox must use without ever holding. A [signer](signer) forms a
credential that depends on the request being made. Resolvers came first and are
the bulk of what follows, so the pages below are written about them unless they
say otherwise; each of the other two kinds has its own page, stating what its contract
adds and what it refuses. What all three genuinely share is everything around the
plugin rather than inside it: how it is installed and trusted, the sandbox it runs
in, the manifest's `[sandbox]` grant, and the store it can come from.

Where the three stop is [collected at the end of this page](#what-no-plugin-can-do), with the
reason for each boundary and what would justify moving it.

The secret-source space is open-ended: any well-known secret-manager backend,
a cloud KMS, a third-party vault app, a
keyring, so `sbx` keeps the **resolver** (SOURCE) layer *pluggable*. A resolver
plugin adds a new `scheme://` that a secret's `from` reference can route to. The
**broker** (SINK) layer of a secret, which terminates TLS and injects on the wire,
stays first-party: a bug where a request is decrypted and decided is a boundary
breach, so that one is never a plugin. A broker that terminates nothing, and
stands in front of a host socket instead, is a second plugin type under a contract
that leaves `sbx` holding the socket.

A resolver plugin still obeys the invariant: it runs **host-side, sandboxed under
bubblewrap, never in the cage**, and returns the plaintext to `sbx`'s host
process, which hands it to the broker. Because a resolver sees plaintext, it is
in the trusted computing base: which is exactly why installing one, or trusting
a store to install from, is a deliberate act.

## The pages

- [The resolver type](resolvers): what a resolver is, the execution contract every
  plugin answers under, and the ready-made resolvers published in the store.
- [The `plugin.toml` manifest](manifest): the field reference all three types share,
  and the `[sandbox]` grant that bounds each one.
- [`[plugin.<name>]`](configuring): what *this machine* supplies to an installed
  plugin, and where to get a tool it does not have.
- [The broker type](broker): standing in front of a host socket the cage must use
  without ever holding it.
- [The signer type](signer): forming a credential that depends on the request being
  made.
- [Managing plugins](managing): installing, the registry's trust-by-location, drift
  detection, scheme conflicts, and a plugin's own tests.
- [Signed plugin stores](stores): distributing and installing from a verified remote.

## What no plugin can do

Three kinds exist and the set is closed. Each is admissible **because of what it cannot do**, so
the boundary is part of the design rather than a list of things not yet built. What follows says
where the boundary is, why it is there, and what would justify moving it. A limit with no stated
trigger is one nobody should move on a hunch.

- **There is no fourth kind.** A resolver, a broker and a signer each refuse specific grants in
  their own words, and those refusals are what make the type safe to install. A general "plugin"
  holding the union of the three grants would have no such argument to make. What would justify a
  fourth: a contract statable as narrowly as these three, with its own refusals, rather than one
  described as a resolver that also does something else.

- **No plugin rules on decrypted HTTP in general.** sbx decrypts at the egress proxy, so the
  attachment point exists, and a general layer-7 decider was considered. What shipped instead is
  the signer, named by a `[secret]` and bounded to the one concrete host that declaration names.
  Two reasons the general form did not follow. HTTP is not framed, it is *parsed*, so the closed
  framing set below does not apply and what a plugin would see is a request sbx already took apart.
  And the bound would have to be invented: a signer inherits its host bound from the declaration
  that reaches it, while a general decider would need one written from scratch. What would justify
  it: a protocol under TLS needing a credential injected that cannot be expressed as a signer on a
  concrete host.

- **A broker's framing is one of three** (`length-u32-be`, `line`, `pgwire`). A framing is how sbx
  knows where one message ends, which makes it sbx's to implement rather than a plugin's to
  describe: a plugin handed an uncut stream would *be* the broker instead of ruling on it. One
  protocol is known not to fit, the KeePassXC browser integration, whose JSON is unframed and whose
  payloads are encrypted, so a plugin could only rule on the envelope. What would justify a fourth
  framing: a **second** protocol that fits none of the three. One does not justify a mechanism.

- **A resolver cannot ask you anything on the terminal.** Its standard input is closed, because a
  resolver that read or blocked on sbx's own input would hang the launch, and anything it printed
  would compete with what the cage is writing. A plugin that needs a human brings its own window or
  talks to something already holding one, which is what the `keepassxc-browser://` resolver does.

- **A plugin's own settings are environment variables.** `[plugin.<name>] env` supplies values for
  the names a manifest declares in `allow_env`, and a name the manifest does not declare is refused
  rather than passed. A typed settings table would carry the same values under a second set of
  rules. What would justify one: a setting that cannot be a string, or one whose validation belongs
  to sbx because getting it wrong is a security matter rather than a failure the plugin reports.

- **Nothing outside this page is pluggable.** Package backends, the store layer, the seccomp
  policy, app profiles and redaction are all first-party. Each decides what a sandbox may do, so a
  plugin there would be pluggable *policy*, and the argument that admits a resolver, that it holds
  a value and reaches nothing else, does not transfer to something that decides the reaching.

## An honest residual: a networked resolver reaches the host network

- **A `network = true` resolver reaches the host network, not the cage's
  allowlist.** A resolver runs host-side (outside the agent's cage), so a manifest
  that declares `network = true`, to reach a remote secret-manager / KMS / third-party-vault engine, shares
  the **host** network and is **not** behind the cage's egress allowlist. This is
  accepted because resolvers are in the TCB (first-party, or trust-installed and
  signed from a store) and an engine resolver needs real network to do its job.
  The lever is keeping the resolver *set* trusted and scoping the secret at the
  source, not bounding the resolver's own egress. A `network = false` resolver
  runs in an empty network namespace and has no such reach.

## See also

- [Resolvers](../secrets/resolvers): the built-in `env://`/`file://`/`sops://` schemes a
  plugin extends.
- [Secrets architecture](../secrets/): the never-in-cage invariant, and why brokers stay
  first-party while resolvers are pluggable.
- [`sbx plugins`](../cli/plugins): the command reference.
- [Security model](../concepts/security-model) / [The trust gate](../concepts/trust):
  the TCB and the trust gates a plugin rests on.
