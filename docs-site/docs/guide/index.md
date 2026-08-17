# sbx: user guide

`sbx` is a **sandbox launcher**: a single static Rust binary that runs tools, including **encapsulated AI agents**, inside a [bubblewrap](https://github.com/containers/bubblewrap)
sandbox where they can install a project's full dependency set via single-user,
daemonless [Nix](https://nixos.org/) **without mutating the host OS**.

This guide is the complete, task-oriented documentation. It is split into small,
cross-linked pages so you can start anywhere and follow the links. Each subsystem's page
carries its own rationale and its own limits; what cuts across all of them is gathered in
[Decisions and limits](concepts/decisions).

> New to `sbx`? Start with [What sbx is](concepts/overview), then
> [Quick start](getting-started/quickstart).

---

## Getting started

- [Installation](getting-started/installation): build the static binary, or a dev build.
- [Quick start](getting-started/quickstart): your first sandboxed command in five minutes.
- [`sbx doctor` and prerequisites](getting-started/doctor): the runtime requirements and how to check them.
- [Troubleshooting](getting-started/troubleshooting): the symptoms you may hit first, and the page that owns each fix.

## Concepts

- [What sbx is (and is not)](concepts/overview): the reference class, the two actor modes.
- [Architecture](concepts/architecture): the map: the boundary, the launch pipeline, the control planes, the plugin chain.
- [Security model](concepts/security-model): same-uid, confidentiality by absence, the bind layout.
- [Decisions and limits](concepts/decisions): what sbx does not do, and what would reopen each structural choice.
- [The trust gate](concepts/trust): the direnv content-hash model, free vs security fields.
- [Enforcement stack](concepts/enforcement): bubblewrap, seccomp, cgroups, and the egress firewall.
- [Observability](concepts/observability): the process and filesystem lenses on a running cage.
- [Provisioning model](concepts/provisioning): the rolling nix channel, the per-project store, self-equip.
- [Directory layout](concepts/directory-layout): where the config, data, and trust state live.

## Configuration (`.sbx.toml`)

- [Configuration overview](configuration/): layering, the trust gate, free vs security fields.
- [`env`](configuration/env): extra environment variables (a free field).
- [`binds`](configuration/binds): extra host paths, read-only or read-write.
- [`packages`](configuration/packages): tools by backend: `nix:` / `mise:` / `flake:`.
- [`[tools]` (mise)](configuration/tools): a project's mise toolchain, auto-equipped in-cage.
- [`nixpkgs`](configuration/nixpkgs): pin the channel or revision.
- [`[limits]`](configuration/limits): cgroup resource limits.
- [`[seccomp]`](configuration/seccomp): relax the mandatory syscall denylist (trusted-only).
- [`[devices]`](configuration/devices): expose host device nodes into the cage (trusted-only).
- [`[ssh_agent]`](configuration/ssh-agent): sign with a named key the cage never holds (trusted-only).
- [`gui`](configuration/gui): the Wayland display posture.
- [`gpu`](configuration/gpu): hardware-accelerated GPU rendering (mesa: Intel/AMD/nouveau).
- [`audio`](configuration/audio): microphone and playback via PulseAudio.
- [`dbus`](configuration/dbus): a private in-cage desktop portal (file chooser + theme + notifications).
- [`network`](configuration/network): the egress posture (links to [Networking](networking/)).
- [`[proc]`](configuration/proc): observe or block what the agent execs (trusted-only).
- [`[notify]`](configuration/notify): be told when something was blocked (trusted-only).
- [`[secret]`](configuration/secret): credential injection (links to [Secrets](secrets/)).
- [`[task.<name>]`](configuration/task): the field reference for a declared operation,
  trusted-only (links to [Declared operations](tasks/)).
- [`[app.<name>]`](configuration/apps): named launch profiles (links to [Apps](apps/)).
- [`[network.groups]`](networking/groups): reusable egress groups.
- [`[bundle.<name>]`](configuration/bundles): reusable tool bundles an app names with `use`.
- [One-shot overrides](configuration/overrides): `--config`/`--env`/`--net`/… and `SBX_*`.

## Command reference

- [Command index](cli/): every command at a glance.

| Command | Purpose |
|---|---|
| [`doctor`](cli/doctor) | verify the runtime prerequisites |
| [`run`](cli/run) | run a command in the sandbox, or open its shell |
| [`app`](cli/app) | launch or manage named application profiles |
| [`mise`](cli/mise) | run the in-cage mise to self-equip a toolchain |
| [`search`](cli/search) | discover `nix:` tools via nixhub |
| [`test`](cli/test) | check whether an access would be allowed |
| [`bundle`](cli/bundle) | list, export and import reusable tool bundles |
| [`net`](cli/net) | inspect and manage the egress policy |
| [`proc`](cli/proc) | observe a running sandbox's process tree |
| [`fs`](cli/fs) | observe the files a running sandbox writes |
| [`ssh-agent`](cli/ssh-agent) | what a running sandbox asked your ssh keys to sign |
| [`task`](cli/task) | list and invoke a session's declared operations |
| [`secret`](cli/secret) | the credential inventory, by name |
| [`plugins`](cli/plugins) | manage resolver plugins and plugin stores |
| [`projects`](cli/projects) | list and remove the per-project runtime trees |
| [`session`](cli/session) | list, attach to, and stop the live sessions |
| [`trust` / `untrust`](cli/trust) | vouch for a project config |
| [`config`](cli/config) | inspect and edit the configuration |
| [`upgrade`](cli/upgrade) | roll managed toolchains forward |
| [`gc`](cli/gc) | reclaim per-project store space |
| [`storage`](cli/storage) | manage a compressed, self-growing volume for the data directory |
| [`store`](cli/store) | report what sbx occupies on disk |
| [`path`](cli/path) | where the config, data, and state roots live |

## Apps and profiles

- [The app framework](apps/): named, reusable agent launchers.
- [Per-app isolated `$HOME`](apps/home): persistent identity, `home_scope`.
- [Portable profiles](apps/profiles): import, export, and the shipped starter profiles.
- [Profile catalog](apps/catalog): the profiles shipped in this repository.

## Networking (egress)

- [Egress overview](networking/): the Model-B architecture (empty netns + host proxy).
- [Architecture: Model B](networking/architecture): how a filtering posture works under the hood.
- [Network modes](networking/modes): `none` / `shared` / `deny` / `allow` / `ask`.
- [Rule grammar](networking/rules): hosts, `*.domain`, URLs, `re:`, `tcp://`, ports, `{VERB}`.
- [Egress groups](networking/groups): reusable `[network.groups]` referenced by `@name`.
- [Ask mode](networking/ask): park-and-confirm requests with `sbx net pending`.
- [Inbound forwarding](networking/forward): `forward`, host loopback ports into the cage.
- [Observability](networking/observability): `sbx net rules` / `stats` / `logs` / `live`, `sbx test net`.

## Declared operations

- [Declared operations](tasks/): a fixed command run with a credential the caller never holds.
- [Parameters](tasks/parameters): `params`, the bounds that hold a caller, and `env_allow`.
- [Credentials](tasks/credentials): `secret`, `encode`, and wire-injected credentials.
- [What a task may run](tasks/execution): `spawn`, `[exec.<program>]`, and the task tool pool.
- [What a task returns](tasks/output): substitution, and the `output` directory.
- [Reaching a non-HTTP service](tasks/network): `tcp://` rules, in-cage listeners, ssh.

## Secrets

- [Secrets architecture](secrets/): the never-in-cage invariant, resolver × broker.
- [Resolvers](secrets/resolvers): the source layer: `env://` / `file://` / `sops://`.
- [Injection](secrets/injection): the http-header broker.
- [Redaction](secrets/redaction): the outbound and inbound tripwires.
- [Plugins](secrets/plugins): third-party resolvers, brokers and signers.
- [Signed plugin stores](secrets/stores): distributing and installing them from a verified remote.

## Housekeeping

- [Sessions](concepts/sessions): `ls`, `attach`, `stop`, and `--detach`.
- [Garbage collection](concepts/gc): `sbx gc`.
- [Upgrading toolchains](concepts/upgrade): `sbx upgrade` and the lock model.

## Reference

- [Environment variables](reference/environment-variables): `SBX_*` and the cage environment.
- [Exit codes](reference/exit-codes): what each exit status means.
- [Glossary](reference/glossary): the terms this guide uses.

---

## Reading paths

- **"I want to run an agent on an untrusted project safely."**
  [Security model](concepts/security-model) → [Apps](apps/) →
  [Network modes](networking/modes) → [Secrets](secrets/).
- **"I want to give my project a reproducible toolchain."**
  [Provisioning](concepts/provisioning) → [`packages`](configuration/packages) /
  [`[tools]`](configuration/tools) → [`sbx upgrade`](concepts/upgrade).
- **"I want to lock down what a tool can reach on the network."**
  [Network modes](networking/modes) → [Rule grammar](networking/rules) →
  [Ask mode](networking/ask) → [Observability](networking/observability).
- **"I just want the CLI."** [Command index](cli/).

---

## The why

The guide is mostly the *what* and *how*, and each page argues its own subject. Two pages
carry the *why* across subjects: [Decisions and limits](concepts/decisions), which states
what `sbx` does not do and what would reopen each structural choice, and [Security
model](concepts/security-model), which holds the threat analysis and names where the
protection stops.

There is no separate design-document directory. The four that once sat under `docs/` were
folded into these pages when the site was built, and the pages are now the only copy.
