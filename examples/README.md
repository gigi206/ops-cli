# Importable examples

One kind of artifact per directory, each named after the command that imports it:

| Directory | Artifact | Import with |
| --- | --- | --- |
| [`app/`](app/) | a launch profile for one app | `sbx app import` |
| [`bundle/`](bundle/) | a reusable tool bundle an app names in `use` | `sbx bundle import` |
| [`net-groups/`](net-groups/) | a shared egress group an app's `allow` references with `@<name>` | `sbx net groups import` |
| [`secrets/`](secrets/) | a documented `[secret]` block, one provider per subdirectory | copy into `sbx.toml` (or an app profile) |

**For the list of shipped profiles**, see the [profile catalog](../docs-site/docs/guide/apps/catalog.md):
it names every profile with its tool and its provider, grouped by how you interact with it. This
page covers how the artifacts are built and how they fit together; each profile's own header covers
its specifics.

## How the pieces compose

A profile is a standalone TOML file shaped as a top-level app: a `cmd`, plus the posture (network
mode, `gui`/`gpu`/`audio`/`dbus`, binds, limits) and the credential choices that are *that app's*.
What the underlying agent needs in order to be installed and to reach its own services lives in a
**bundle**, which the profile names in `use`. Host sets shared across unrelated agents live in an
**egress group**, referenced from either side with `@<name>`.

```
app profile  ──use──▶  bundle  ──@name──▶  egress group
(cmd, posture,         (packages,          (a flat list of
 credentials)           env, hosts)         allow/mute/deny entries)
```

Profiles are therefore **not self-contained, on purpose**: `sbx app import` alone is not enough.
Import the bundle too, and any group the header lists under `REQUIRES`; every header says which.
The reason is the failure this layout removes: a hand-copied set of an agent's requirements falls
behind the agent silently, and the launch that breaks says nothing about why.

**Order does not matter.** Each import writes its own file and resolves nothing: a profile is inert
until `sbx app run <name>`, so the references are looked up then, not at import. What order does
change is only what you are told — import the profile first and it names the bundle file you still
need; import the bundle first and it names any group *it* references. Skipping one is what breaks:
the app launches without the tool and egress it named.

`sbx app import <profile> --with-deps` does all of them at once, taking each from the file beside it
here. It merges into your global config rather than only writing a profile sbx owns, which is why it
is a flag: an unresolvable reference makes it refuse and write nothing at all.

All 73 shipped profiles name a bundle, so this is the shape everywhere. The seven that name
**another** agent's bundle rather than their own are the orchestrators listed below.

## App profiles (`app/`)

sbx ships **no built-in apps**. Each profile here is a separate, portable artifact you import
deliberately:

```sh
sbx bundle import examples/bundle/claude-code.toml   # the agent's requirements
sbx app import    examples/app/claude-code.toml      # a conscious trust act
sbx app run       claude-code                        # launch it, sandboxed
```

Imported profiles live under `$XDG_CONFIG_HOME/sbx/apps/` and are **trusted by location**: honored
even when the project you launch in is untrusted. That is the point, since the job is to run an
agent *on* untrusted code. Manage them with `sbx app list` / `sbx app rm <name>`, and re-export one
with `sbx app export <name>`.

Each app gets its own persistent, isolated `$HOME` (config, login, history), shared across projects
by default (`home_scope`).

### Two credential postures

Most profiles are **BYOK**: your provider key is read on the host and injected by the egress proxy,
never entering the cage. The others log in to a service **account**, and that token persists in the
app's isolated `$HOME`, so it does live in the cage, though never in your project shell. Both stay
bounded by the egress allowlist.

A vendor account is not automatically the second kind. Where the account's token *is* a header
value, it takes the injected path exactly like a BYOK key and the secret still never enters the
cage. The distinction that matters is not "account or key" but **is there a header for the broker
to strip and replace**: an OAuth flow or a query-parameter key offers none.

A profile that runs its model in-cage has no credential at all: no key to inject, no account to log
into, and nothing to leak.

## Tool bundles (`bundle/`)

```sh
sbx bundle import examples/bundle/opencode.toml   # then: use = ["opencode"] in an app
sbx bundle                                        # what is declared, and what each brings
```

One bundle per shipped tool — a CLI, a desktop build, a web UI's engine: its package, the
environment it reads, and the hosts it must reach, and **nothing about the shape of the cage** (no `cmd`, no `binds`, no `gui`/`gpu`/`audio`/`dbus`, no
network mode). Each is derived from the agent profile of the same name in [`app/`](app/), and a
test pins the two together so they cannot drift apart: the namesake profile must name its bundle in
`use`, and must not restate any package, environment variable or egress rule the bundle already
provides. See [`[bundle.<name>]`](../docs-site/docs/guide/configuration/bundles.md).

The bundle's egress entries land in the consuming app's own `[network]` table. An app that declares
no such table gets a warning rather than an invented one, because inventing one would move its
posture.

**A bundle publishes what another profile can consume**, and that is the rule. Every shipped tool
now has one — 66 bundles for 73 profiles — with a single exception: a profile that consumes another
agent's engine publishes nothing of its own. `t3code` names `claude-code`; `aionui`,
`opencode-web`, `open-design` and `orca-desktop` name `opencode`; `hermes-web` and `hermes-webui`
name `hermes`. Nothing would ever compose one of *those*, so a bundle for them would be an artifact
with no consumer and a second file to keep in step. The two roles are exclusive by construction:
the test above requires a namesake profile to name its own bundle **and only it**, so a profile
cannot both publish and consume. If an app ever needs both, that assertion is the one line to
change.

**When the install is a command, the bundle carries it too.** Some tools are not finished by
unpacking a package: a vendor postinstall mise's `--ignore-scripts` skips (`junie`), a native addon
with no prebuilt binary for this platform (`deepseek-harness`, `openfox`), a source checkout that
has to be cloned and built (`odysseus`, `trae`). Those bundles declare that one-time step as
[`provision`](../docs-site/docs/guide/configuration/bundles.md), and sbx runs it in the consuming
app's own cage, before that app's command and never in its place. So the bundle is complete: name
it and you get the agent, not a package that cannot start.

A step runs on every launch and guards itself — sbx does not remember that one succeeded, because
what proves an install finished is a path only the step knows. That is also what makes it
self-healing: delete what it produced and the next launch puts it back.

Four profiles left this shape entirely once their artifact was measured rather than assumed:
`devin` and `warp` moved to `tarball:resolve`, `pool` too, and `rovo` to the nixpkgs attribute that
now exists. Three keep a `cmd` that installs, because no backend fits their artifact and the step
is not a one-time install but the launch itself: `cursor-agent` (a JavaScript tree with no binary
to wrap), `muse` (a bare binary rather than an archive) and `prime-agent` (a packed npm tarball).
Their headers say which, measured rather than assumed.

A related discriminator is worth keeping in mind: "is a postinstall skipped" is not the question —
**can the tool still find what that postinstall would have placed** is. An agent that looks its
helper binary up on `PATH` first is cured by declaring that helper as a `nix:` package and needs no
wrapper at all.

## Egress groups (`net-groups/`)

```sh
sbx net groups import examples/net-groups/npm-registry.toml   # then: allow = ["@npm-registry"]
sbx net groups                                                # what each expands to
```

Egress-only sharing, kept separate from bundles because a group is a *flat list of entries*, not a
tool: it carries no package, no environment, no credential. It exists for host sets shared verbatim
across several profiles and not tied to one agent. An app's, **or a bundle's**, `allow`/`mute`/`deny`
references one with `@<name>`, and the entries expand at resolution (see `[network.groups]` in the
configuration guide).

Because a group expands into the list that references it, a group is **slot-pure**: an allow group
and a mute group cannot be one fragment. That is why the npm install lane and the npm audit mute
ship as two fragments rather than one.

The shipped groups cover the install lanes shared by the npm- and GitHub-backed agents, the GitHub
runtime lanes (same hosts as the install lane, different verbs, hence separate fragments), the
Python install lane, the npm runtime lane for agents that fetch packages while running, the model
catalogue, the optional OpenRouter provider, and the Google and GitHub identity-provider lanes.

The Google sign-in comes as **two** fragments, because the posture decides the reach.
`google-oauth` serves an agent that prints a URL you open in your HOST browser: the `.com` sign-in
host and the token endpoints, nothing more. `google-signin-incage` serves the consent rendered
INSIDE the cage, which needs three things the first does not — the country domain the `/SetSID`
cookie step redirects to (an anchored regex, so a look-alike is refused), the consent page's fonts
and static assets, and the JS client it loads. Three bundles converged on that exact set, entry for
entry, so it is described once; the other in-cage sign-in profiles keep their own list because
theirs genuinely differ (wildcard asset hosts, an extra favicon service, a missing `apis.google.com`),
and harmonizing them would change what each cage can reach.

One of them is a **mute** group rather than an allow group: `chromium-background`, the background
services a Chromium engine reaches on its own whatever it is embedded in. Every profile that ships a
browser engine references it, so that lane is described once instead of once per app, which is
exactly the drift this directory exists to prevent.

A bundle that references groups says so in its header under `REQUIRES`, because the bundle alone is
then not enough: import it *and* its groups. A reference to a fragment that does not exist is
fail-closed, and a test pins every reference in this directory against the fragments that ship.

## Secrets (`secrets/`)

One subdirectory per provider, each a documented `[secret]` block you copy into your `sbx.toml` or
an app profile. See [`secrets/README.md`](secrets/README.md).

## Credentials: the key never enters the cage

The real API key is read **on the host** and injected into the matching outbound request by the
egress proxy. It never enters the sandbox. Provide it on the host:

```sh
export ANTHROPIC_API_KEY=sk-ant-…      # for claude-code / opencode
export OPENAI_API_KEY=sk-…             # for codex
```

…or point the profile's `from = "env://…"` at a resolver (`sops://`, `file://`). The in-cage
placeholder in `[env]` lets the CLI start and issue its request; the proxy strips the placeholder
and substitutes the real key on the wire. Egress is an **allowlist** (deny by construction), so
even with the key in flight the agent can only reach the provider you listed.

### The GitHub API, the one you hit while importing these

Several profiles install their tool through mise's `aqua:` backend, which reads the GitHub API to
resolve a release. Anonymous use is rate-limited per IP, and importing a handful of profiles, or one
`sbx upgrade mise` across them, exhausts it: the install then fails with `403 rate limit exceeded`
and `github auth: no`. A cage inherits no token from your shell by design, so the fix has the same
shape as every credential here:

```toml
[secret."api.github.com"]
from   = "env://GITHUB_TOKEN"
header = "Authorization"
type   = "bearer"
```

Global (in `sbx.toml`) authenticates every cage that can reach that host, as you; in one app profile
it stays that app's. The full reasoning and the scope trade-off are in
[the worked example](../docs-site/docs/guide/configuration/secret.md#worked-example-authenticating-the-github-api).

## Read by default: declare the write hosts

An **app is read-by-default**: every Mode-B agent's allow rules default to `{GET,HEAD}`, so a host
the agent only reads needs no annotation, while a host it **writes** to (an API it POSTs completions
to, an account it logs into, a package registry it installs from) must be opened to all verbs with a
`{*}` prefix, e.g. `"{*} https://api.anthropic.com"`. Pure download and catalogue hosts stay
`{GET,HEAD}`, which is why the shipped profiles prefix their API and install hosts with `{*}` and
their read-only hosts with `{GET,HEAD}`. A WebSocket needs its own explicit `WS` opt-in that a plain
`{*}` does not cover, because a WebSocket is an unredactable bidirectional channel.

To change an app's default for *unscoped* rules, set `[network] default_methods` in the profile
(`["GET", "HEAD"]` is the built-in; `["*"]` opts the app out, back to all verbs; or a custom set).
A method filter bounds the upstream's verb semantics, **not** raw exfiltration: a `GET` URL still
carries data out, and the host allowlist is the egress boundary.

The bare interactive `sbx run` (Mode A) is unaffected; it stays all-verbs.

## How a tool is packaged

Each profile declares its tool with a **backend-prefixed** `[packages]` value, in its bundle where
it has one.

The `mise:` prefix means the tool is equipped **in-cage from upstream directly** (mise's
`aqua`/`github`/registry backends pull the real release binary, its `pipx` backend a PyPI wheel via
uv), so the version is the latest upstream rather than whatever nixpkgs has packaged. This sidesteps
both the nixpkgs lag and, for some tools, the nixpkgs **unfree** gate that a standalone vendor
binary does not carry.

A nixpkgs attribute is available as `nix:<attr>`, provisioned host-side, seeded, and offline
reusable. Use it for stable substrate tools where freshness does not matter, and for the helper
binaries an agent expects to find on `PATH`.

**`flake:<ref>`** packages a tool that ships only as a nix flake: no single release binary and no
nixpkgs attribute. sbx builds a remote `flake:` ref **host-side** into its shared store, like
`nix:`, and seeds it per project, so one build serves every project. Because that build runs
host-side it uses the **host** network: its fetch hosts do not need to be in `allow`, which governs
only what the running tool may reach. That also removes an old wall, since a build step fetching
with its own client rather than through nix's fetcher no longer has to honour the cage proxy and its
CA. A floating ref freezes at its first build until `sbx upgrade flake` re-resolves and pins it.

When the flake is one you author yourself, write the whole `flake.nix` **inline** in a
`[flakes.<name>]` table instead of hosting a separate repo. Unlike a remote ref, an inline flake
builds **in-cage** (its source is local content), so that first build does run under the cage's
egress posture; the out-link is keyed by the source's content hash, so editing the flake rebuilds.
See [inline flakes](../docs-site/docs/guide/configuration/packages.md). An inline flake floats, so
pin its inputs inside the `flake.nix`.

**`deb:<url>`**, **`appimage:<url>`** and **`tarball:<url>`** package a GUI or desktop app
distributed only as a prebuilt artifact. sbx fetches it, resolves it to a content hash pinned in a
per-project lock, and builds a generated derivation that unpacks it and `autoPatchelfHook`s the
binaries against a curated library set, **host-side** like `nix:`, which is safe because unpacking a
prebuilt artifact runs no build script. An AppImage is extracted at build time rather than
self-mounted, since the runtime FUSE mount is seccomp-blocked. Where the strict `deb:` autoPatchelf
refuses an app's optional native libraries, the lenient `tarball:` backend ignores them.

The locator can track upstream automatically: `deb:github:<owner>/<repo>` picks the repo's newest
release asset for this architecture, `deb:apt:<Packages-index-url>` the index's highest version, and
`tarball:resolve` runs a sandboxed resolve command against the vendor's version API. Prefer those,
or a version-stamped URL, over a moving `…/releases/latest/download/…` alias: a pin is a content
hash, so a *moving* URL breaks the next launch with a hash mismatch the moment upstream releases,
whereas an immutable asset keeps the pinned build working until you upgrade.

**npm and node CLIs** declare a node runtime (`nix:nodejs`) plus the tool via mise's npm backend
(`mise:npm:<pkg>`). The cage synthesises `/usr/bin/env`, so a `#!/usr/bin/env node` shebang
resolves, which a hermetic cage otherwise could not. These differ in whether node is needed at
**runtime** or only to install: a package that delivers a self-contained native binary through
optional dependencies needs node only for the install, while a pure-node CLI needs it to run.

**Offline trade-off:** a `mise:` tool fetches at first launch, which is the price of upstream
freshness, so a profile's *first* launch in a given project needs the network; a `nix:` tool is
seeded and reusable offline. With the default `home_scope = "global"` the install is shared across
projects, but the per-project store means the fetch re-runs the first time you launch the app in
each new project.

**Distribution hosts and the allowlist:** a `mise:` fetch must reach the tool's distribution host,
so the bundle or profile lists it. GitHub-distributed tools ride the built-in read-only allow-set
(github.com and githubusercontent), so they need no entry. A tool shipped from a cloud storage
bucket gets that one bucket path-scoped, not the whole storage host.

## How a profile upgrades: three classes

A tool declared through a `[packages]` backend is rolled by `sbx upgrade <backend>` (`nix` / `mise`
/ `flake` / `deb` / `appimage` / `tarball`), which re-resolves the source and rewrites the lock;
`sbx upgrade` with no argument rolls them all. A `mise:` tool is equipped at the latest upstream
version on the **first launch in a project** and then pinned to it: until you upgrade, a long-lived
project store keeps that version. That is the contract, not a gap. Versions move only on an explicit
upgrade, never on an sbx binary update.

A few profiles install their tool from inside the cage instead, because upstream ships no artifact
any backend can consume: a vendor `curl … | sh` bootstrap, or a source checkout. Those have no lock
to roll, so each exposes an explicit, one-launch refresh through a one-shot env override:

| Profile | Refresh |
| ------- | ------- |
| `cursor-agent` | `sbx app run cursor-agent --env CURSOR_AGENT_SBX_UPDATE=1` |
| `muse` | `sbx app run muse --env MUSE_SBX_UPDATE=1` |
| `odysseus` | `sbx app run odysseus --env ODYSSEUS_SBX_UPDATE=1` |
| `open-design` | `sbx app run open-design --env OPEN_DESIGN_SBX_UPDATE=1` |
| `prime-agent` | `sbx app run prime-agent --env PRIME_AGENT_SBX_UPDATE=1` |
| `trae` | `sbx app run trae --env TRAE_SBX_UPDATE=1` |

`devin`, `pool`, `rovo` and `warp` used to be in that table and are not any more: their artifact
turned out to fit a backend, so `sbx upgrade` rolls them like every other package.

`--env` is authoritative and read on the host, so these keep the same contract as `sbx upgrade`:
**the version moves only when you ask**, never on a launch and never on an sbx binary update.

The third class is narrower: a tool with a built-in updater that the profile deliberately allows, so
the tool can also advance itself from inside the cage. Most profiles do the opposite and leave the
vendor's auto-updater denied, because a binary it downloads itself is not patched for the cage the
way a backend-provisioned one is. Either way the profile's header says which it is.

## Adjusting the allowlist

If a tool's request is refused, the proxy reports the host it blocked: add it to `allow`, and note
that a write verb may need a `{*}` or `{POST}` prefix since an app is read-by-default. Check a URL's
verdict ahead of time with `sbx test net <url>` (or `--method POST`).

A `mute` entry is the SELinux `dontaudit` analogue: it keeps a **denied** request's line out of the
default log without changing the verdict and without hiding the count. The host stays denied, `sbx
net stats` still tallies it, and `sbx net log --all` still shows it. Use it for the background
telemetry a packaged app emits on every launch, not for anything whose refusal you would want to
see.

## Not here yet, and why

A profile needs three things: a **runnable agent** (a CLI or TUI, or a GUI app packaged through one
of the prebuilt-artifact backends, not an editor extension), a way to **package it in the hermetic
cage**, and a **header-injectable credential**, meaning an API key supplied via an env var against
an OpenAI-compatible or Anthropic endpoint. OpenRouter is the universal one: a single key, many
models, `Authorization: Bearer`. An OAuth or account login, or a query-parameter key, offers no
header for sbx's `[secret]` broker to strip and replace.

Each candidate below was researched against primary sources. Nothing here is guessed, so each waits
on a real fact or on a named feature:

- **Not a runnable agent.** Some entries in an agent catalogue are a *component*, and a component is
  useless in a cage without the thing it plugs into. A language and runtime *for building* agents
  needs a program you have written before it is an agent at all; an ACP bridge is inert without the
  primary CLI it adapts; and a bridge onto a model provider is a provider the existing profiles
  already reach by BYOK, not a new agent. None of these is refused on quality: each simply is not
  the kind of thing `sbx app run <name>` can launch.

- **Provenance not established.** The rule for `[packages]` is that a binary comes from **official
  upstream**. A package declaring no repository, no homepage and no author, whose namesake GitHub
  repo names neither the package nor a site, ties nothing to a vendor, and an unscoped npm name is
  claimable by anyone. A release-only repository with no README, no license and no published
  credential mechanism gives a profile nothing to stand on. Both would ship the day upstream
  publishes the missing link.

- **OAuth-only credential.** An agent that authenticates with a provider sign-in rather than a
  header key ships as an **account** profile when its token persists in the isolated home, and not
  at all when it requires a **system keyring** the hermetic cage does not provide. Each such
  profile's header states which case it is and what remains open.

- **A native GUI toolkit the curated library set does not cover.** The prebuilt-artifact backends
  patch an app against a curated set that covers base glibc, Wayland, and the Chromium and Electron
  runtimes. A native GTK or WebKitGTK app needs libraries outside it, and the `deb:` build fails
  when they are missing. Such a profile needs the extra libraries named in its backend table, which
  its header does where it ships; where that has not been worked out, the app waits on it rather
  than on anything about the app itself.

For any other CLI agent: give the package (a `mise:`, `nix:` or `flake:` backend), the launch
command, the runtime API hosts, and the credential mechanism (an injectable **header** key, not
OAuth), and a profile can be added.
