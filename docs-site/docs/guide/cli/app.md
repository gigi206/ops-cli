---
description: "Launch, import, export and inspect the named application profiles."
---

# `sbx app`

```
sbx app run <name> [--detach] [--observe] [--net-learn[=level]] [--proc-learn[=level]] [[-g|--global|-l|--local] [--dry-run]] [override flags] [-- <args>...]
sbx app upgrade <name>
sbx app import <file> [--as <new-name>] [--force] [--with-deps]
sbx app export <name> [--out <file>]
sbx app rm <name>... [--purge] [--gc]
sbx app list
sbx app show <name> [--json]
sbx app prune <name>|--all [--stale] [--drop <entry>]... [--reset] [-y|--yes]
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
| `--proc-learn[=name\|path]` | run under the app's real posture, then add the programs it ran to the app's `[proc] allow` list and set `mode = "ask"` (default level `name`); see [Learning what an app runs](#learning-what-an-app-runs---proc-learn) |
| `-g, --global` / `-l, --local` | with `--net-learn`/`--proc-learn`: write the learned rules to the global app profile / the project config (default local); refused without a learning flag |
| `--dry-run` | with `--net-learn`/`--proc-learn`: print the rules that would be added without writing them; refused without a learning flag |
| `--config` / `--env` / `--net` / `--gui` / `--proc` / `--notify` / `--nixpkgs` / `--bind` / `--forward` / `--limit` / `--package` / `--seccomp` / `--device` / `--fs` / `--gpu` / `--audio` / `--dbus` | typed one-shot [overrides](../configuration/overrides), applied **after** the app's overlay (the final word); value-taking flags also accept `--flag=value` |
| `-- <args>...` | appended to the app's declared command |

`--detach`, `--observe` and `--dry-run` take no value: `--detach=x` is refused (usage, exit 2).

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

Only the app's **own** egress is learned. A [declared task](../configuration/task) runs
behind a proxy of its own enforcing the task's `network` list, and what that list turns
down is the task's to declare, not the app's to discover, so those refusals are skipped
and counted in the run's notes rather than opened in the app's profile. A destination the
posture would have [asked](../networking/modes) a person about is skipped for the same
reason: the answer is theirs to give.

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

### Learning what an app runs (`--proc-learn`)

`--proc-learn` is the exec half of the same idea, and it reads the opposite half of a
run. Egress learning reads what was **refused**: a denied connection leaves the program
running, so one pass collects every host it wanted. A denied `execve` usually ends the
run, so learning what to allow from refusals would learn exactly one program. This
learns from what the app **ran**.

To see every exec, the run stands up the seccomp user-notification supervisor under a
denylist with nothing on it: every `execve` is notified and every one is allowed, so the
app behaves exactly as it would have. The cheap `/proc` poll behind
[`--observe`](run#observing-a-run---observe) cannot serve here. It samples, so a command
shorter than a tick is missed, and an allowlist learned from a sample parks the agent on
the first program the sample did not see.

What counts as a program the app ran is what the policy was **asked about**, which is
more than the command lines show. A `#!` script is decided against both itself and the
interpreter its first line names, and a program started through an explicitly invoked
dynamic loader is decided against what the loader would load, so running `./build.sh`
learns `build.sh` and the `sh` that runs it. Both are rules the cage needs under `ask`;
a list holding only the script would park on its interpreter.

The level sets how wide each rule is:

| Level | Rule written |
|---|---|
| `name` (default) | the program's basename, e.g. `git` |
| `path` | the whole in-cage path, e.g. `/nix/store/<hash>-git-2.51.0/bin/git` |

`name` is the default because an in-cage program does not live at a stable path. A nix
closure spells `git` as `/nix/store/<hash>-git-2.51.0/bin/git`, and that hash changes at
the next [`sbx upgrade`](upgrade), so a rule written against the path stops naming the
program the day its channel rolls. The price is stated plainly: a name rule admits that
basename wherever it is found. `path` is the strict reading, for a cage whose programs
sit where they will stay; it goes stale visibly (the exec waits for a decision) rather
than widening quietly.

**The write sets the posture.** An `allow` list does nothing under any mode but `ask`,
which is why [`sbx proc allow`](proc#allow--deny) refuses to write one elsewhere, so a learning
write sets `[proc] mode = "ask"` together with the rules and says so. That is the strict
direction: under `enforce` anything not denied runs, under `ask` anything not allowed
waits for [`sbx proc allow`/`deny`](proc#pending). A `deny` list already in the file is
left exactly as its author wrote it, and a program a `deny` rule names is never turned
into an allow: the rule would be inert beside it, and writing one would read as undoing
a refusal that was meant.

Every posture is learnable except `ask` itself, which is refused: under `ask` an
unmatched exec is already put to a person, and a run cannot pre-answer a question that
is theirs. Under `off` or `observe` the app's config declares no exec policy, and the
run supplies the empty denylist itself.

```bash
sbx app run claude-code --proc-learn --dry-run   # what would be allowed, nothing written
sbx app run claude-code --proc-learn             # write the list, and move to `ask`
```

Both learning flags compose. `sbx app run <name> --net-learn --proc-learn` learns an
app's egress and its programs in one launch, writing both to the same profile.

## Advancing an app

`sbx app upgrade <name>` moves one app forward without making you work out which
channel it rides first. sbx reads what the app declares and rolls all of it. It is the
same roll as [`sbx upgrade --app <name>`](upgrade#rolling-one-app), under its own name.

| What the app declares | What `sbx app upgrade` does |
|---|---|
| `mise:` packages | rolls them, in the app's own cage |
| a bundle [install step](../configuration/bundles#the-install-step) | re-runs it, in the app's own cage, forced |
| `flake:` / `deb:` / `appimage:` / `tarball:` / `binary:` packages | re-resolves the app's own, and rewrites only their entries in the project lock |
| `nix:` packages | rolls them against the [app's own nixpkgs lock](upgrade#an-apps-base-channel) |
| an inline [`[flakes.<name>]`](../configuration/packages#flakes-an-inline-nix-flake) | nothing: it pins its inputs in its own source, so no channel advances it |

What the roll does **not** touch is everything that belongs to the project rather than to
this app: the mise engine, the project's `nix:` tools, the
[task tool pool](../tasks/execution#the-task-tool-pool), the project baseline's packages,
and the [`distro`](../configuration/distro) image, which no app can declare.

It also **prunes nothing**. Dropping a lock entry that no layer declares any more is a
statement about the project, and a roll narrowed to one app never makes one, so another
app's pin is never touched.

This is newer than the verb. `sbx app upgrade` used to roll the two channels whose unit
of work was already the app's cage and merely **name** the rest, because a `deb:` or
`appimage:` package is pinned in a lock that belongs to the project. What removed the
limit was giving the roll a selector: it now resolves only what the named app declares
and leaves the lock's other entries alone.

A package a layer you have not trusted declared is counted rather than dropped, so an
untrusted project never reads as "nothing advances this app":

```
  2 package(s) withheld (untrusted) — not equipped, so not rolled; run `sbx trust`.
```

### The install step runs here

An unscoped `sbx upgrade` leaves each install step's own guard in charge, because its
steps would launch one cage per app across the whole project and re-run a clone, a build
or a vendor script in each. Naming one app removes that reason: a user who typed the name
is asking for that app to be re-installed, not polled. So naming one app **forces** the
step, whichever spelling you use, and the cost is one cage, for the app you asked about.

That matters for the apps a bundle **installs** rather than pins: they ride no
`[packages]` backend, so re-running the install is the only thing that advances them.
Gating it would make the verb fail exactly the apps it exists for.

Because nothing gates it, the cost is named **before** the cage is built rather than
reported after it:

```
  the install step below re-runs in junie's own cage regardless of its guard, which downloads again — `sbx upgrade mise --app junie` rolls only the packages.
```

That second clause appears only for an app that has packages to roll. `sbx upgrade mise
--app <name>` refuses an app that declares none, so an app the install step is the whole
of is not sent to it.

## Managing profiles

| Subcommand | Purpose |
|---|---|
| `import <file> [--as <new-name>] [--force] [--with-deps]` | place a portable profile (trusted by location); the granted posture is printed |
| `export <name> [--out <file>]` | write a named app out as a portable profile (stdout by default) |
| `rm <name>...` | remove an **imported** profile (a project `[app.<name>]` lives in that project's `.sbx.toml`) |
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

`sbx app list` (alias `sbx app ls`) shows one row per app with its `HOME` column: the size of
the state a `--purge` would remove, and where that state lives. `--json` emits the same rows as a
document, with the sizes in **bytes** rather than `12.4 MiB`: the human column is a rendering of
that number, and a consumer compares and sums it.

:::warning The sizes are of the data, not of the space returned
Every size sbx prints for a home, a tree or a prune is the size of the **data** it holds. The disk can get back less, for
two reasons that stack: a volume with compression enabled stored those bytes smaller, so
removing a gigabyte of data frees less than a gigabyte of blocks; and a block shared with
another tree survives until the last reference to it goes. Only the filesystem knows either
number, so read it from [`sbx storage status`](storage), which reports what the volume holds
and, on an image, how much is waiting on a discard to return to the host.
:::

The same applies to [`sbx app show`](#inspecting-an-app), [`sbx app prune`](#pruning-undeclared-tools)
and [`sbx projects`](projects).

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

`rm <name>` deletes only the imported profile. Without `--purge` a missing profile is
an error (a project `[app.<name>]` overlay lives in that project's `.sbx.toml`: edit it
there); with `--purge` it is tolerated, since homes may remain after the profile is gone.
To also reclaim what a launch left on
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

`--purge` also leaves your project tree alone. An app that keys state by the directory it
runs in wrote that state at the project root, in your tree, and taking it out is yours to
do: see [what an app writes in the
project](../concepts/decisions#what-an-app-writes-in-the-project-stays-where-the-app-puts-it).

Several names may be given in one call, like [`sbx projects rm`](projects). Each app is
removed on its own: a name that fails (no profile to remove, a live session holding its
home) leaves the others removed and only makes the exit code non-zero, while an invalid
name is rejected before anything is removed at all. A name repeated in one call counts
once, and the `--gc` sweep runs once for the whole call, since the store it collects is
shared by every app in the project.

## Inspecting an app

`sbx app show <name>` reports one app's **realized-on-disk** detail: the counterpart to
[`sbx config show --app <name>`](config), which shows what the app *declares*. It lists
the profile source, the app's isolated home(s) with on-disk size and what each one is made
of, and each declared package annotated with whether it is **actually installed**:

| Package | Installed reads |
|---|---|
| `mise:` | `installed <version>` (read from the app's home) or `not installed` |
| `deb:` / `appimage:` / `tarball:` | `pinned in N tree(s) (<hash>)`, the build lives in the [per-project store](../concepts/directory-layout); see [`sbx projects show`](projects), or `not built` |
| `nix:` / `flake:` | `built in N tree(s)`, built host-side into the shared store, seeded per project; or `not built` |

### What a home is made of

Under each home, `show` lists what it holds, largest first, read from the disk. It names no
directory and knows no tool: the places a program keeps disposable data are open-ended, and a
view that recognised them would be a list to keep current and would still be wrong about the
next one.

Where a single entry holds nearly all of its level, the level below it is listed too, indented
under the line it explains. Half the homes on a working machine have that shape, and a line
reading `.local  5.2 GiB  99%` says nothing a total does not.

```
    global · 5.2 GiB
      .local                                5.2 GiB  99%
        .local/share                        5.2 GiB  99%
          .local/share/open-design          3.1 GiB  60%
          .local/share/pnpm                 1.9 GiB  35%
```

Nothing here says which entries are disposable, because nothing can: an app's own data and a
package manager's downloads sit side by side under one parent, and their names do not tell them
apart. Reading them is the reader's, and so is deciding.

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
would go, with sizes) and applies only with `-y` / `--yes`. The app's declared tools, its
login/session state, and any `nix:`/`deb:`/`flake:` build are left untouched: to remove the
whole home instead, use [`sbx app rm --purge`](#removing-an-app).

`--yes` (`-y`) is **refused while a session of that app is running**: the tools are in the home
that session is using, so deleting them takes an interpreter or a `PATH` entry out from
under a command in flight, and what the agent then reports looks nothing like what
happened. Stop it with `sbx session stop` and retry. The preview deletes nothing, so
it stays available either way.

The same refusal covers the case where sbx cannot tell: if the session registry itself
cannot be read, `--yes` refuses and says so rather than treating an unreadable registry
as an empty one. Under `--all` that refuses the whole sweep, since naming the apps to skip
needs the answer the registry could not give. The preview never asks the registry, so it
keeps working.

### Taking a named entry

`--drop <entry>` removes one entry of each home, named relative to the home exactly as
[`show`](#what-a-home-is-made-of) lists it. The flag repeats.

```sh
sbx app prune hermes-desktop --drop .rustup --drop .npm
```

Nothing about the name is interpreted, and that is the design rather than a gap: what a
directory holds is yours to judge, because an app's own data and a package manager's
downloads sit side by side and their names do not tell them apart. sbx lists what is there
and removes what you name.

A name that resolves outside the home is skipped rather than followed, including one whose
parent turned out to be a symlink. A name that is not there reports nothing. It previews by
default, like every other form of `prune`.

### Resetting an app

`--reset` takes everything: every home, its configuration and its login state included, and
the per-project [mise pools](../concepts/directory-layout) a global app self-equipped into.

```sh
sbx app prune hermes-desktop --reset          # what would go
sbx app prune hermes-desktop --reset --yes    # take it
```

What survives is what the app **declares**, so the next launch builds the home again from
the profile: tools reinstall, and you sign in again. That is the difference from
[`rm --purge`](#removing-an-app), which takes the declaration too and leaves nothing to
launch.

It acts on one named app rather than under `--all`, and it stands instead of the other
flags rather than beside them. A live session of the app refuses the **applying** run, the
way it refuses any applying prune; the preview stays available, since it deletes nothing.

### Sweeping every app

`--all` sweeps every app that has an installed home instead of one named. It widens the
scope the way [`sbx gc --all`](gc) does, though the two widen different things. Naming an
app **and** `--all` is refused, since neither would clearly govern. `--drop` composes with
it, so one entry can be taken from every app at once.

:::tip Start with the preview
`sbx app prune --all --drop .npm` lists what every app holds under that name, with sizes,
and removes nothing. That is the number to look at before deciding, and
[`sbx app list`](#listing-apps) shows what each app holds in total.
:::

The sizes it prints carry the same caveat as everywhere else: see
[what a size means](#listing-apps).

### Dropping stale versions

`--stale` drops, from each of the app's pools, an installed **version** that no activation asks
for. This is a different question from an undeclared tool: the tool can be declared and current
while an older version of it sits in a per-project pool that nothing reaches. That happens
because a global app's install pool is scoped per project (see
[Two mise pools](../apps/home#two-mise-pools-keep-a-global-apps-self-equips-aligned)), so a
version equipped there stays behind when the app's own record moves on.

Two files are read to decide: the app's activation record, which is app-global and lives in its
home, and the project's mise file, where a `mise use` without `-g` writes. An alias such as
`latest` or `2` is resolved **against the pool**, by following the link mise wrote beside the
version, rather than compared as text: a pool whose `latest` points at the version an activation
names is asking for it.

A third source joins them for a per-project pool: the activation record of every other app that
has a pool in the same project. Where the project sets
[`apps_share_install_pools`](../configuration/packages#apps_share_install_pools-when-two-apps-in-one-project-equip-the-same-tool),
a version this app equipped and no longer asks for may be the one a neighbour found here and
therefore never installed itself, and a sweep reading this app's records alone would take it out
from under a neighbour. Those records are read whether or not the project shares its pools: with
sharing off they name versions no launch resolves from this pool, so reading them can only keep a
version, never remove one. A project that does not share therefore sees `--stale` free the same
disk or a little less, never more.

What it deliberately leaves alone: a tool no activation mentions at all (that may mean the file
asking for it was not among those read, and a tool the app does not declare is what plain
`prune` is for), and a pool whose project directory is gone (its tree is removed whole by
[`sbx projects rm --dead`](projects#rm)).

Under `--all`, an app whose session is running is **skipped and named** rather than refusing
the whole sweep, so one live agent does not hold up the rest; the sweep then exits non-zero
so a script notices that not everything was covered.

## Examples

```sh
sbx bundle import examples/bundle/claude-code.toml   # what the agent requires
sbx app import examples/app/claude-code.toml
sbx app run claude-code                # launch with its own isolated home
sbx app run claude-code -- -c          # resume the previous session
sbx app run claude-code --net none     # one run with no network
sbx app run claude-code --net-learn    # learn the egress rules it actually needs
sbx app run claude-code --net-learn=exact --dry-run   # preview its exact endpoints
sbx app run claude-code --proc-learn   # learn the programs it runs, and move to `ask`
sbx app list                           # imported profiles + installed homes
sbx app show claude-code               # what this app has actually installed on disk
sbx app prune hermes                    # preview undeclared mise tools in hermes' home
sbx app prune hermes --yes              # …and remove them
sbx app prune hermes --stale            # …and versions nothing asks for any more
sbx app prune hermes --drop .rustup     # take one entry `sbx app show` listed
sbx app prune hermes --reset --yes      # empty its home entirely, keeping the profile
sbx app prune --all --drop .npm         # what every app holds under that name
sbx app export claude-code > my-claude.toml
sbx app rm claude-code --purge         # remove the profile, home, and tools
sbx app rm claude-code --purge --gc    # …and sweep this project's nix store too
sbx app rm claude-code hermes --purge  # several apps in one call, each on its own
```
