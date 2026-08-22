---
description: "Launch, import, export and inspect the named application profiles."
---

# `sbx app`

```
sbx app run <name> [--detach] [--observe] [--net-learn[=level] [--global|--local] [--dry-run]] [override flags] [-- <args>...]
sbx app upgrade <name>
sbx app import <file> [--as <name>] [--force] [--with-deps]
sbx app export <name> [--out <file>]
sbx app rm <name>... [--purge] [--gc]
sbx app list
sbx app show <name> [--json]
sbx app prune <name> [--yes]
```

`sbx app run <name>` launches a named application profile: a project `[app.<name>]`
overlay, or an imported `apps/<name>.toml` profile: inside the project sandbox, each
with its own persistent isolated home.

See also: [The app framework](../apps/) · [`[app.<name>]`](../configuration/apps) · [Portable profiles](../apps/profiles) · [Profile catalog](../apps/catalog).

## Launching an app

| Option | Meaning |
|---|---|
| `--detach` | launch in the background as a session [`sbx session`](session) can see |
| `--observe` | record what the app does, its processes ([`sbx proc logs`](proc#logs), also streamed inline to stderr on a non-interactive foreground run under a non-enforcing `[proc]` mode) and its file writes ([`sbx fs logs`](fs#logs)); works for interactive and detached launches too, see [`sbx run`](run#observing-a-run---observe) |
| `--net-learn[=domain\|path\|exact]` | run under the app's real posture, then add the egress rules it was refused for lack of one to the app's profile (default level `domain`); see [Learning an app's egress](#learning-an-apps-egress---net-learn) |
| `-g, --global` / `-l, --local` | with `--net-learn`: write the learned rules to the global app profile / the project config (default local) |
| `--dry-run` | with `--net-learn`: print the rules that would be added without writing them |
| `--config` / `--env` / `--net` / `--gui` / `--proc` / `--notify` / `--nixpkgs` / `--bind` / `--forward` / `--limit` / `--package` / `--seccomp` / `--device` / `--gpu` / `--audio` / `--dbus` | typed one-shot [overrides](../configuration/overrides), applied **after** the app's overlay (the final word) |
| `-- <args>...` | appended to the app's declared command |

Arguments after a `--` are appended to the app's `cmd`, so you can pass a flag to the
launched program without editing the profile: e.g. `sbx app run claude-code -- -c` runs
the profile's `claude` with `-c`. They are ordinary launch-time arguments; the app's
posture (network, binds, secrets, home) is fixed by the profile.

When the profile's `cmd` is a shell script (`["bash", "-c", "..."]`), sbx inserts the
app's name as the script's `$0` before appending, so your first argument arrives as `$1`
instead of being absorbed as the shell's own name. The script still has to expand `"$@"`
for the arguments to reach the program it runs: see
[`cmd`](../configuration/apps#the-cmd-field-and-trailing-arguments).

A one-shot override is applied after the app's overlay, so it is the final word: e.g.
`sbx app run claude-code --net none` cuts the app's network for one run. Note: overriding
an app's network drops its read-by-default verb filter (an override posture is
all-verbs); scope it with `{GET,HEAD}` rules in a `--config` `[network]` if you need to
keep it.

### Learning an app's egress (`--net-learn`)

`--net-learn` discovers an app's egress needs: it runs the app under its own (unchanged)
posture (nothing is opened, so a request the allowlist refuses stays refused), and turns
each such refusal into the allow rule that would have admitted it, writing them to the
app's profile (or, with `--dry-run`, only printing them). It needs a filtering posture
(`mode` `allow`/`deny`/`ask`); a `shared`/`none` app logs no egress to learn from. Only a
plain "not allowed yet" refusal is learned: a deliberate `deny` rule and a security
block (SSRF, host-mismatch, an outbound secret) are never turned into a rule. Run it
again after adding rules to catch a host only reachable once an earlier one is allowed.

The level sets how wide each rule is:

| Level | Rule written |
|---|---|
| `domain` (default) | the whole host, e.g. `{*} https://host` |
| `path` | its first path section, e.g. `{*} https://host/v1/*` |
| `exact` | the one endpoint, e.g. `{POST} https://host/v1/chat` |

The rules land in the project config by default (`--local`), or in the app's global
profile with `-g`, which, for an app defined only inline in a project `sbx.toml`, writes
a partial `apps/<name>.toml` the inline table then shadows on load; prefer `-g` for an
app that is already an imported profile. It is foreground-only (not with `--detach`).

## Advancing an app

`sbx app upgrade <name>` moves one app forward without making you work out which
channel it rides first. sbx reads what the app declares and dispatches on that.

Two kinds of work exist, and the verb treats them differently because they differ in
scope, not in importance.

| What the app declares | What `sbx app upgrade` does |
|---|---|
| `mise:` packages | rolls them, in the app's own cage |
| a bundle [install step](../configuration/bundles#the-install-step) | re-runs it, in the app's own cage |
| `flake:` / `deb:` / `appimage:` / `tarball:` / `binary:` packages | names the channel that rolls them, and rolls none |
| `nix:` packages | names the channel too: they ride the app's own nixpkgs lock, which only [`sbx upgrade nix --app <name>`](upgrade#an-apps-base-channel) advances |
| an inline [`[flakes.<name>]`](../configuration/packages#flakes-an-inline-nix-flake) | names it as floating: no channel advances it |

The first two are rolled here because their unit of work is already one app's cage. The
rest are named rather than rolled. A `flake:` / `deb:` / `appimage:` / `tarball:` /
`binary:` package is pinned in a lock that belongs to the **project**, so rolling one
from a per-app verb would advance every app that rides it, under a command that reads as
though it touched only this one. A `nix:` package has the opposite shape: it resolves
against the **app's own** nixpkgs lock, and advancing that lock re-resolves the channel
and rebuilds the base userland, a download this verb does not take on unasked. Either way
the roll belongs to the channel command:

```
  `deb:`, `nix:` packages advance with the project, not with one app: `sbx upgrade deb`, `sbx upgrade nix`.
```

That is the honest limit of the verb: what it removes is the question "which channel?",
not the scope of the locks behind each answer. See [`sbx upgrade`](upgrade) for the
channels themselves, and [an app's base channel](upgrade#an-apps-base-channel) for the
per-app roll.

An inline flake is named apart because it has no channel at all. It pins its inputs
inside its own `flake.nix` source and rebuilds when that source changes, and
`sbx upgrade flake` deliberately skips it.

A package a layer you have not trusted declared is counted rather than dropped, so an
untrusted project never reads as "nothing advances this app":

```
  2 package(s) withheld (untrusted) — not equipped, so not rolled; run `sbx trust`.
```

### The install step runs here

`sbx upgrade all` leaves the bundle install steps alone and says so, because it is
unscoped: its steps would launch one cage per app across the whole project and re-run a
clone, a build or a vendor script in each. Naming one app removes that reason. The cost
is one cage, for the app you asked about, so `sbx app upgrade <name>` runs the step
without a further flag.

That matters for the apps a bundle **installs** rather than pins: they ride no
`[packages]` backend, so re-running the install is the only thing that advances them.
Gating it would make the verb fail exactly the apps it exists for.

Because nothing gates it, the cost is named **before** the cage is built rather than
reported after it:

```
  the install step below re-runs in junie's own cage, which downloads again — `sbx upgrade mise --app junie` rolls only the packages.
```

That second clause appears only for an app that has packages to roll. `sbx upgrade mise
--app <name>` refuses an app that declares none, so an app the install step is the whole
of is not sent to it.

## Managing profiles

| Subcommand | Purpose |
|---|---|
| `import <file> [--as <name>] [--force] [--with-deps]` | place a portable profile (trusted by location); the granted posture is printed |
| `export <name> [--out <file>]` | write a named app out as a portable profile (stdout by default) |
| `rm <name>` | remove an **imported** profile (a project `[app.<name>]` lives in that project's `.sbx.toml`) |
| `rm <name> --purge` | also remove the app's isolated **home(s)**, the tools its `mise:` backends installed, its config, and its login state |
| `rm <name> --purge --gc` | after the purge, sweep the **current project's** nix store too (one command; requires `--purge`) |
| `list` | list the imported profiles **and** the apps with an installed home (with disk size) |

`export`/`import`/`list`/`prune`/`rm`/`run`/`show`/`upgrade` are the subcommands. Launching
always goes through `run`, so an app is never confused with a subcommand and **may be named
like one** (reached as `sbx app run <name>`). `import` is a deliberate consent act: an agent in the
cage cannot run it, and the profile stays inert until `sbx app run <name>`. See
[Portable profiles](../apps/profiles).

### What the import says you are still missing

A profile is not always self-contained, and what it can be short of is not only a tool. Both
kinds of reference resolve against the global config, and both are reported at import, when
you are holding the file and can act on it:

- a **bundle** it names in `use`, which carries the packages, environment, egress and
  credential of the tool it wraps. See [Bundles](../configuration/bundles).
- an **egress group** it references as `@<name>`, a reusable lane of allowlist entries.
  Undefined, its entries are dropped and the app reaches less than it names.

```
sbx: warning: 'claude-code' names a bundle not declared here: claude-code — import it too
  (`sbx bundle import examples/bundle/claude-code.toml`, or re-run with --with-deps), or the
  app launches without the tool and egress it names
```

The remedy **names the file** when one can be found: the shipped catalogue lays `app/`,
`bundle/` and `net-groups/` out as siblings, so the reference resolves to a path you can
retype. It is named only when that file really declares what is missing, so following the
suggestion always changes something; otherwise the message falls back to `<file>`. Order
does not matter, and a profile never fires until `sbx app run <name>`.

A group referenced by a **bundle** rather than by the profile is reported by
`sbx bundle import` instead: a profile resolves nothing from disk, so it cannot see into the
bundle its `use` names.

### Importing what it references, in one gesture

`--with-deps` follows those references instead of naming them, taking each from the file
beside the profile in the same catalogue:

```
$ sbx app import examples/app/aider.toml --with-deps
imported app profile 'aider' -> ~/.config/sbx/apps/aider.toml
  ...
imported 1 bundle(s) into ~/.config/sbx/sbx.toml — added aider
imported 1 egress group(s) into ~/.config/sbx/sbx.toml — added pypi
```

It is a flag rather than the default because of **where it writes**. Importing a profile
places a file at a path sbx owns; a bundle and a group are merged into `sbx.toml`, the config
you maintain by hand. Following a reference therefore gives one command a second write target
inside your own file, chosen by the contents of a profile. That is an admission, so it is
asked for explicitly.

What it will and will not do:

- **Only the referenced names** are merged, never the rest of a fragment that happens to
  declare more.
- **Nothing already declared is replaced.** Only references nothing defines are written.
- **A group a bundle reaches** is followed too, which is where most of them live. A group
  reached through a bundle that is *already* declared is out of scope: that bundle arrived
  through `sbx bundle import`, which named the gap at the time.
- **All or nothing.** If any reference has no file behind it, the command refuses and writes
  nothing at all, profile included. Outside a catalogue layout there is nothing to follow, so
  drop the flag and the plain import will name what to fetch.
- The **grant** a bundle carries is announced exactly as `sbx bundle import` announces it.
  This is the one import where you did not name the bundle yourself, so it is the one where
  an unexpected credential or egress rule matters most.

Importing over a profile that already exists needs `--force`; without it the existing file
is refused, not replaced. A forced import is the one import that can lose work, since the
profile on disk may carry a rule, a credential or a package added by hand on this machine.
So it names the settings the incoming file no longer sets, and keeps the bytes it replaced
beside the profile as `<name>.toml.replaced`, to read a per-machine setting back from. That
copy is not itself a profile (only `*.toml` files are read as profiles) and goes away with
`sbx app rm <name>`. A re-import of an identical file keeps no copy and reports no loss.

### Listing apps

`sbx app list` (alias `sbx app ls`) shows one row per app with its `HOME` column: the total
size a `--purge` would reclaim, and where that state lives.

| Reads | Means |
|---|---|
| `global` | the app's single shared home `<data>/apps/<name>/home`: a `home_scope = "global"` app (the default) |
| `N project home(s)` | one isolated home per project: a [`home_scope = "project"`](../apps/home) app |
| `N project mise pool(s)` | not a home: a per-project [mise pool](../apps/home#two-mise-pools-keep-a-global-apps-self-equips-aligned) a **global** app self-equipped a tool into |

So `global + 1 project mise pool` is one home plus a pool: not two homes.

Every launch creates the pool directory, so an app that has merely *run* in a project has an
**empty** pool there; an empty pool is **not listed** (it would report per-project state the
app does not have). Only a pool holding an installed tool counts. Its size is included in the
row's total either way, since `--purge` removes it. `sbx app show <name>` breaks the sizes
down per home and per pool, empty ones included.

### Removing an app

`rm <name>` deletes only the imported profile. To also reclaim what a launch left on
disk, add `--purge`: it removes the app's [isolated home(s)](../apps/home): the
global one and any per-project ones: which hold the tools installed by the app's
`mise:` backends, its config, and its login/session state, freed immediately. A running
session of the app is a hard stop (stop it first with [`sbx session stop`](session#stop)).

`--purge` on its own does **not** touch the shared per-project nix store, which backs
every app in a project. Add **`--gc`** (which requires `--purge`) to sweep the **current
project's** store in the same command: equivalent to running [`sbx gc --prune`](gc)
there, reclaiming the app's now-unreferenced `nix:`/`flake:` closures. For a global app
used in several projects, run the sweep in each of them (one command covers the current
project only). Use `sbx app list` to see which apps have an installed home to purge.

Several names may be given in one call, like [`sbx projects rm`](projects). Each app is
removed on its own: a name that fails (no profile to remove, a live session holding its
home) leaves the others removed and only makes the exit code non-zero, while an invalid
name is rejected before anything is removed at all. A name repeated in one call counts
once, and the `--gc` sweep runs once for the whole call, since the store it collects is
shared by every app in the project.

## Inspecting an app

`sbx app show <name>` reports one app's **realized-on-disk** detail: the counterpart to
[`sbx config show --app <name>`](config), which shows what the app *declares*. It lists
the profile source, the app's isolated home(s) with on-disk size (and the mise-tools share
broken out), and each declared package annotated with whether it is **actually installed**:

| Package | Installed reads |
|---|---|
| `mise:` | `installed <version>` (read from the app's home) or `not installed` |
| `deb:` / `appimage:` / `tarball:` | `pinned in N tree(s) (<hash>)`, the build lives in the [per-project store](../concepts/directory-layout); see [`sbx projects show`](projects), or `not built` |
| `nix:` / `flake:` | `built in N tree(s)`, built host-side into the shared store, seeded per project; or `not built` |

A package a launch would not provision because an untrusted layer declared it reads
`withheld` (distinct from `not installed`, so it is not mistaken for a failed provision).

If the home holds mise tools that **no declared package accounts for**: a leftover from a
removed profile, or a dependency a `mise:` backend pulled in: they are listed under
`installed (undeclared)`, named by their real backend token (its provider, e.g.
`pipx:hermes-agent`, recovered from mise's metadata rather than the munged directory name), so
the report shows everything that is actually installed, not only what the profile names.

For a `"global"`-scope app, the report also surfaces its **per-project mise pools**: where
the agent's `nix:`-via-mise self-equips and the project's own `mise.toml` tools install,
aligned with each project's `/nix` store (see
[Two mise pools](../apps/home#two-mise-pools-keep-a-global-apps-self-equips-aligned)). Each
pool appears in the `disk` breakdown as `project <id> (mise pool)`, and its tools are listed
per project under `per-project self-equips`: kept distinct from the app-global declared tools,
since they are transient per-project state, re-resolved when a project's store lacks them.

Read-only: no trust gate, no launch, no network. `--json` emits the same model for scripting.

## Pruning undeclared tools

`sbx app prune <name>` removes the `installed (undeclared)` mise tools `show` surfaces: a
tool from a former profile, or one added by hand: from every home the app has. Each is
deleted from the home's `mise/installs/` and dropped from that home's `mise/config.toml`
`[tools]` so a later launch does not re-equip it. It **previews by default** (listing what
would go, with sizes) and applies only with `--yes`. The app's declared tools, its
login/session state, and any `nix:`/`deb:`/`flake:` build are left untouched: to remove the
whole home instead, use [`sbx app rm --purge`](#removing-an-app).

## Examples

```sh
sbx bundle import examples/bundle/claude-code.toml   # what the agent requires
sbx app import examples/app/claude-code.toml
sbx app run claude-code                # launch with its own isolated home
sbx app run claude-code -- -c          # resume the previous session
sbx app run claude-code --net none     # one run with no network
sbx app run claude-code --net-learn    # learn the egress rules it actually needs
sbx app run claude-code --net-learn=exact --dry-run   # preview its exact endpoints
sbx app list                           # imported profiles + installed homes
sbx app show claude-code               # what this app has actually installed on disk
sbx app prune hermes                    # preview undeclared mise tools in hermes' home
sbx app prune hermes --yes              # …and remove them
sbx app export claude-code > my-claude.toml
sbx app rm claude-code --purge         # remove the profile, home, and tools
sbx app rm claude-code --purge --gc    # …and sweep this project's nix store too
sbx app rm claude-code hermes --purge  # several apps in one call, each on its own
```
