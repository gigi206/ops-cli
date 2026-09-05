---
description: "What sbx deliberately does not do, and what would reopen each structural choice."
---

# Decisions and limits

This page carries the two questions the rest of the guide answers only per subject: what
`sbx` does **not** do, and **why** it has the shape it has. Both were written where they
belonged, one page at a time, which serves a reader who already knows which page to open
and nobody else.

It is two halves, and they are read by different people. [What sbx does not
do](#what-sbx-does-not-do) is for someone deciding whether this tool covers their risk.
The one-page map for that same reader is [Threat model](threat-model): each threat beside
the control that answers it and what remains.
[Why it is shaped this way](#why-it-is-shaped-this-way) is for someone wondering why it
looks like this rather than like a daemon, a container runtime, or a plugin host. Neither
half repeats the pages it points at.

## What sbx does not do

### One boundary, and everything else is depth

The boundary is the **bind layout under a user namespace**: a secret is protected by being
[absent](security-model#same-uid-confidentiality-by-absence), not by being read-only. Every
other mechanism is depth, and each says so on its own page rather than being quietly
promoted:

- the [seccomp denylist](../configuration/seccomp#why-it-stays-surface-reduction-not-a-boundary)
  removes kernel attack surface; it is not what keeps the agent in;
- [cgroup v2 limits](enforcement#best-effort-never-the-boundary) are hardening against
  runaway resource use, applied where the host supports them and skipped where it does not;
- [`[fs] deny`](../configuration/fs#what-it-does-not-cover) reduces exposure of paths inside
  the cage, resolves at launch, and does not see a file created afterwards;
- [ask mode](../networking/rules#it-is-a-guardrail-not-a-boundary) is a prompt, not a
  control: what enforces egress is the allowlist behind it;
- a task's [output redaction](../tasks/output) and [parameter
  handling](../tasks/parameters) are accident containment, catching a credential echoed by
  mistake rather than one a program set out to exfiltrate.

Reading any of those as the boundary is the one misreading that changes a decision, which
is why each page states it in its own words.

### The likeliest way out is not an escape

The agent holds the project read-write by construction, so the realistic path out of the
cage is that it **writes something you run later on the host**: a `postinstall` script, a
`Makefile` recipe, a git hook, a CI workflow. That is not a hole in the cage; it is the
boundary being crossed afterwards, by you. The full carrier table, what `sbx fs logs`
narrows and what it deliberately does not show, and the one carrier `[fs] readonly` closes,
are in [Where the protection stops](security-model#where-the-protection-stops). It is the
most important limit on this page and it is not summarised here, because a summary is
exactly what a reader would act on instead of the table.

### The holes are opened on request, and each one is a hole

A cage nobody configured exposes no display, no device, no bus and no host network. The
fields that open those are named for what they are, and the cost is written beside each:

- [`gui = "wayland"`](../configuration/gui) binds the compositor socket, and the isolation
  that follows is the **compositor's**, not sbx's: see the [compositor
  caveats](../configuration/gui#compositor-caveats) before assuming a wlroots session
  isolates input and screen capture the way GNOME's does. X11 is never offered, and
  [enforcement](enforcement#gui-exposure-is-wayland-only) says why.
- [`audio = true`](../configuration/audio) opens the audio bus, which carries the
  microphone and the monitor sources, not only playback.
- [`dbus = true`](../configuration/dbus) gives the cage a private bus and portal; the host
  session bus and the login keyring stay out.
- [`gpu = true`](../configuration/gpu) and [`[devices]`](../configuration/devices) expose
  hardware nodes, whose drivers are kernel surface the seccomp filter does not cover.
- `network = "shared"` removes egress filtering entirely, which is the point of it.

### What the egress proxy cannot tell you

The proxy decides per request and reports what it decided. It does not report what happened
*inside* an allowed connection: an allowed host is allowed, and what a program does there is
not observable from the boundary. What a capture holds, and the two shapes it cannot
reassemble, are in [What a capture does not cover](../networking/observability#what-a-capture-does-not-cover).
A [broker](../configuration/broker#what-this-does-and-does-not-cover) draws its own line the
same way.

### What is not the product

The class question, why this is a sandbox and not a container manager or an environment
manager, is answered with a comparison table in [What it is
not](./#what-it-is-not). Three more, which that table does not cover:

- **Not multi-user.** The store is single-user and daemonless, and the cage runs as your
  uid. Nothing here isolates one human from another on a shared machine.
- **Not a supply-chain verifier.** Provisioning pins and verifies **what** it fetched, by
  hash and by lock; it makes no statement about whether the pinned thing is trustworthy.
  The [trust gate](trust) governs who may declare a dependency, not what the dependency
  does.
- **Not a service manager.** Nothing runs when you are not running it: see [one process, no
  daemon](#one-process-no-daemon) below for what that costs.

## Why it is shaped this way

Each decision below is stated the way the code states its refusals: what was chosen, what
it buys, what it costs, and **what would reopen it**. The last part is the one that matters
later, because a decision without a trigger cannot be revisited except by argument.

### One process, no daemon

`sbx` is one process per invocation. The supervisor, the egress proxy and the control planes
all live in the process you launched, and they end when it does.

**What it buys** is the property the whole [architecture](architecture) rests on: the cage
cannot reach what judges it, because what judges it is not a service with an address, a
socket in a shared namespace or a state directory another cage can write. There is nothing
persistent to compromise between one launch and the next.

**What it costs** is paid on every launch, and it is not small: configuration, trust and
secrets are resolved again each time, nothing is cached across invocations, and a detached
session keeps a supervisor alive because the proxy and the planes have nowhere else to live.
A daemon would buy cached resolution, one proxy shared by several cages, and a supervisor
that outlives its caller.

**What would reopen it**: a measured launch cost that resolution dominates, or a use for
several concurrent cages sharing one egress policy. Both would have to be weighed against
turning "the cage cannot reach its judge" from a property of the process layout into a claim
about a service's access control, which is a much weaker thing to have to defend.

### bubblewrap as the cage engine

The namespaces, the mounts and the hardening are driven through `bwrap` rather than by
calling the kernel directly, even though `sbx` does call it directly elsewhere (an isolated
network namespace is set up by hand, and attaching to a session enters five namespaces by
hand).

**What it buys** is not the syscalls, which are the easy part. It is the **ordering**: the
sequence of mounts, the propagation flags, `pivot_root`, dying with the parent, and the
long adversarial exposure that a widely deployed setuid-capable sandbox has had on exactly
that code.

**What it costs** is an external component carrying part of the boundary, which is why a
release can [embed its own](../getting-started/installation#self-contained-engines-optional),
and an argv-shaped interface, which is why the cage's environment is passed
[off the argument list](enforcement#the-environment-is-loaded-off-the-argument-list) instead
of through it.

**What would reopen it**: an enumeration of the awkward cases `bwrap` handles that `sbx`
would have to reimplement. A short list makes internalising arguable; a long one closes the
question.

### Nix as the provisioning base

Tools are provisioned from nixpkgs into a per-project store, with `mise` beside it for
language runtimes and four prebuilt backends for what neither can deliver.

**What it buys** is confirmed by the shipped catalogue rather than asserted: the great
majority of declared tools resolve through nix or mise, so the base is the common path and
the prebuilt backends are the exception they were added as.

**What it costs** is the store: it has to be created, garbage collected, measured and
sometimes moved to another filesystem, and that machinery is a large part of the binary,
serving every package including those that never touch the store.

**What would reopen it**: not the ratio, which is settled, but the direction of growth.
Every capability nix lacked so far produced another backend **inside** the binary rather
than an extension outside it, which is the pattern the next section is about.

**What `distro` did to that trigger.** It grew inside the binary too, and it is not a
backend: a registry client, an HTTPS client, a gzip reader, tar unpacking with the path
checks an archive from a stranger needs, and a runner for the commands that derive a
userland. None of it is a way to name a tool; all of it replaces the substrate a cage runs
on. So the trigger as written does not fire, because nothing was added to the package
vocabulary, while the thing the trigger exists to notice happened anyway. What it costs is
a second provisioning road, with its own locks, its own reclaim rules and its own failure
modes, maintained beside the first for as long as both exist.

### Decrypting as the egress default

A filtering posture terminates TLS at a host-side proxy with a per-session CA. The
alternative already exists in the product: a `tcp://` rule is authenticated straight through
to the real server at layer 4, filtered by host and never decrypted, and the cage's trust
bundle carries the normal roots beside the session CA so that path validates correctly.
The rule's scheme is what selects the layer.

**What decryption buys** is everything a host name cannot express: filtering by path and
method, [credential injection](../configuration/secret) the cage never sees, response
masking, request signing, and WebSocket and HTTP/2 handling.

**What it costs** is the largest subsystem in the binary, and a CA the cage must trust,
which for a browser or an Electron app means seeding it into that program's own store.

**Where the measurement landed**, because this one was open: the shipped profiles were
classified by whether their policy actually uses a decryption-only capability. The great
majority do, so the default is where it belongs. What they use it for is the surprise:
almost all of them are filtering by **method**, a minority scope a path, and **none of them
injects a credential**, which is the capability the design is most often justified by. The
counts and the classification rule are in the commit that measured them, deliberately not
here, where they would go stale.

**What would reopen it**: not the default, which the measurement settles, but the
presentation. A policy that only needs host filtering pays for the rest today without being
told there is a choice, and `tcp://` reads as a layer-4 special case rather than as the mode
without inspection.

### One binary, and where extension lives

`sbx` ships as a single static binary, which is what makes the trusted computing base
something you can point at.

**What it costs** is the pull of that shape on everything else: a new capability is cheapest
to add **inside**, so that is where each one has gone. Meanwhile the extension model that
already works, [plugins](../plugins/), is a separate process with its own cage, a
signed manifest and a verified store, and it has never been used outside secrets, although
the four prebuilt package backends do the same three things as each other and already share
a common trait.

**Where the examination landed**, because the trigger has since been pulled: the simplest
prebuilt backend was examined as a plugin, and the backend split in half. Its delegable half
was already delegated: a `<backend>:resolve` package runs an arbitrary command in a cage,
honoured only from a trusted layer, and the URL that command prints is re-validated against
the same rule a declared locator meets. Nothing about that half needs a plugin type it does
not already have. The other half is a nix template the backend keeps, and it cannot leave the
host process: evaluation is pure and happens in-process, and a fetch driven from an
expression would run outside the proxy the launch is enforcing. So the answer is no, and the
core does not shrink here.

**What would reopen it**: a backend whose resolution step needs something a caged command
cannot do. That is a different trigger from the one above, and pulling it would be an
argument about the cage rather than about the plugin manifest.

### Declarative TOML, and what a field cannot say

Configuration is TOML: flat, diffable, and layered global-under-project with the security
fields gated by [trust](trust).

**What it cannot express** is that one field depends on another. Those rules exist all the
same, as validations that run at launch: a credential is inert unless the posture filters, a
host carrying both a layer-4 and a layer-7 rule has the second one ignored, an undefined
group reference is dropped. Each is reported as a warning to someone who has already written
the file.

**Where the sort landed**, because this one was open too: the inter-field rules were divided
into the ones a stricter type could make unrepresentable and the ones that are genuinely
semantic. A minority fall in the first group, where an exclusive variant would say what two
orthogonal fields say today. The majority decide a field from another field that a
*different layer* supplied, global under project under app under a one-shot override, and the
type of one document cannot express a rule about a value that document does not contain. So
the schema is not under-typed, and the warnings at launch are where those rules belong: they
are the first moment every layer is present.

**What would reopen it**: a rule of the first kind that bites often enough to be worth a
variant of its own. The sort says which those are; nothing says one is expensive yet.

## See also

- [Architecture](architecture): the process layout, and what is never mounted.
- [Security model](security-model): same-uid, the bind zones, and where the protection
  stops.
- [Enforcement stack](enforcement): what is always on, and what is best effort.
