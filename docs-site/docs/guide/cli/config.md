---
description: "Inspect and edit the configuration for the current project, with each value tagged by the layer it came from."
---

# `sbx config`

```
sbx config <subcommand>
```

Inspect or edit the configuration for the current project.

See also: [Configuration overview](../configuration/) · [The trust gate](../concepts/trust) · [Directory layout](../concepts/directory-layout).

## Subcommands

| Subcommand | Purpose |
|---|---|
| [`show`](#sbx-config-show) | the resolved, trust-gated configuration a launch would use |
| [`get`](#get-set-add-rm-unset) | read a value from a single layer file |
| [`set`](#get-set-add-rm-unset) | set a value, or a whole list, in a layer file (comments preserved) |
| [`add`](#get-set-add-rm-unset) | add one entry to a list field |
| [`rm`](#get-set-add-rm-unset) | remove one entry from a list field |
| [`unset`](#get-set-add-rm-unset) | remove a key from a layer file |
| [`path`](#sbx-config-path) | the config files in resolution order, or one scope's path |
| [`edit`](#sbx-config-edit) | open a config file in your editor |

## `sbx config show`

```
sbx config show [--json] [--details] [-a|--app <name>] [-g|--global|-l|--local|-d|--default]
```

Prints the resolved configuration: the layered global and project environment, binds,
packages, tools, network, GUI, secrets, the closed and read-only project paths, the
declared operations, and app profiles, after the trust gate has dropped anything an
untrusted project may not set. Each value is tagged with where it
came from, `(default)`, `(global)`, or `(project)`, colored by level. Warnings
explain what was dropped and why. No launch, no nix, no network.

The declared operations are the **static** view of `[task.<name>]`, and the one place to
confirm a block survived validation without launching anything:

```
  tasks (declared operations a cage may run):
    build  Build the project  (project)
    fmt    (project)
```

Name, description, and the layer that declared it (`project`, `global`, `app:<name>`, or
`bundle:<name>` for a bundle folded into an app). The command is not shown: an operation is a fixed
command plus a credential the caller never holds, and [`sbx task show`](task) is where that
whole contract is read. `[task]` is trust-gated, so an untrusted project shows none.
[`sbx task ls`](task) answers a different question, about a session that is running now.

| Option | Meaning |
|---|---|
| `--json` | the resolved model as JSON (warnings included) |
| `--details` | expand what each app overlay's entries *are* (env values, package backend lines, credential shapes), plus the postures left at their default and the allowlist machinery |
| `-a, --app <name>` | one app's **effective** config, each field tagged `default`, `inherited`, or `app:global`/`app:project` |
| `-g, --global` | only what the global config (and imported profiles) contributes |
| `-l, --local` | only what the project `.sbx.toml` contributes |
| `-d, --default` | the built-in defaults alone |

The single-source flags are mutually exclusive and do not combine with `--app`. Note
`-d` is `--default`, so `--details` has no short form.

### What `--app` shows, and what it leaves out

The per-app view answers one question: what would this app launch with, and who decided.
So each field carries one of three tags. `app:global` / `app:project` means the app
declaration set it. `inherited` means a config layer set it and the app takes that value.
`default` means no layer set it at all: the value is sbx's own.

A field tagged `default` is not printed. It would say the same thing for every app on the
machine, and there are ten of them, which is enough to bury the few fields that tell this
app from the next one. They are named together on a single line instead:

```
  at their default: proc, gui, gpu, audio, dbus, limits, forward, seccomp, devices — see --details
```

Nothing is dropped without being listed, and `--details` prints every one of them back in
place. The line disappears when there is nothing to fold, so an app that configures its
whole posture reads exactly as before.

What the app *adds* is named rather than counted, for the same reason: `1 own` is true of
half the catalogue and says nothing about this app.

```
  env:     ANTHROPIC_MODEL  · inherits 2 baseline
  binds:   /srv/workspace (rw)
  packages: chromium (nix), cursor (deb)
  nixpkgs: nixos-unstable @ 0e251e2  (default)
  secrets: (none)
```

The tail counts what comes from the baseline, because those entries are one hop away in
`sbx config show`; it disappears when there are none. `--details` expands each entry to
what it *is*: an env value, a package's full backend line, a credential's shape and
sources.

The `nixpkgs` line sits beside the packages because it is what they resolve against: the
channel your `nix:` packages and the cage's base userland are built from. It is the one
field of this view that the **directory** decides rather than the app. A launch reads the
channel from the working directory, so the same app run from a project carrying a trusted
`nixpkgs` pin builds against that pin, and run from anywhere else builds against the
global channel. That is why the origin tag matters here as much as the value: `project
pin`, `global` or `default` tells you which of the two you are looking at.

```
$ cd ~/work/pinned-project && sbx config show --app cursor | grep nixpkgs
  nixpkgs: nixos-24.11  (project pin)

$ cd ~ && sbx config show --app cursor | grep nixpkgs
  nixpkgs: nixos-unstable @ 0e251e2  (default)
```

The app is the same in both, and so is its home. Only the directory changed.

The allow and deny rules are listed too, one per line, since a rule is a whole clause
(verbs, scheme, host pattern) and nineteen of them joined on one line would be
unreadable. What stays behind `--details` is the machinery that decides nothing about
reachability: muted hosts (they only silence an already-permitted request in the log),
HTTP/2 designations (a transport choice), and the always-allowed built-in set (identical
for every app). The compact view counts those instead.

## get, set, add, rm, unset

```
sbx config get   <key> [-l|-g|-c <file>] [-a|--app <name>]
sbx config set   <key> <value> [-l|-g|-c <file>] [-a|--app <name>] [--trust]
sbx config add   <key> <entry> [-l|-g|-c <file>] [-a|--app <name>] [--trust]
sbx config rm    <key> <entry> [-l|-g|-c <file>] [-a|--app <name>] [--trust]
sbx config unset <key> [-l|-g|-c <file>] [-a|--app <name>] [--trust]
```

These edit **one layer file**, preserving its other keys, its comments and its
formatting. `get` reads the raw declared value in that file (an unset key exits 1);
for the effective value
across layers, use [`show`](#sbx-config-show).

| Verb | What it edits |
|---|---|
| `set` | one value, or a whole list when the value is written as a TOML array |
| `add` | one entry of a list, leaving the other entries alone |
| `rm` | one entry of a list |
| `unset` | the key itself, list or not |

```sh
sbx config set gpu true                        # boolean, written as one
sbx config set limits.tasks_max 4096           # integer
sbx config set fs.deny '[".env", "secrets/"]'  # the whole list
sbx config add fs.deny .env                    # one entry, rest untouched
sbx config rm  fs.deny .env
```

The difference is what survives. On a file that already reads `fs.deny = [".env"]`:

```sh
sbx config set  fs.deny '["secrets/"]'   # → fs.deny = ["secrets/"]          ".env" is gone
sbx config add  fs.deny .env             # → fs.deny = ["secrets/", ".env"]  both kept
sbx config set  fs.deny .env             # → refused: a single value for a list
sbx config add  fs.deny .env             # → already there: no change, no trust lost
```

`set` is a statement: "this is the whole value now". `add` is a suggestion:
"one more entry", and it never touches the rest.

`set` writes the value in the type the schema expects: `true`/`false` become booleans
and a bare number an integer, so `set network.stats false` writes a real boolean rather
than a string that would make the loader drop the whole layer. Handing a list a single
value is refused instead of dropping its other entries, and the error names the three
ways to say what you meant.

`add` and `rm` are the safe half: they never restate a list, so nothing is lost by
omission. Adding an entry already present, or removing one that is not there, changes
nothing and says so. That matters beyond tidiness: an unchanged file keeps its trust
marker, so repeating a command cannot disarm a trusted config's security fields.
Removing the last entry leaves `deny = []` rather than deleting the key, because "nothing
is closed here" and "this layer says nothing" are different claims. Use `unset` for the
second.

### Which key takes which verb

Every field of the schema, and the verb that edits it. `<name>` is yours to choose.

**Single values, edited with `set`:**

| Key | Value |
|---|---|
| `nixpkgs` | a channel or revision |
| `network` | a posture: `none`, `shared`, `deny`, `allow`, `ask` |
| `network.mode` | the same postures, in the table form |
| `network.stats`, `network.pool`, `network.ask_notice` | booleans |
| `network.capture` | `off`, `headers`, `bodies` |
| `network.capture_max_kb`, `network.dns_cache_ttl` | numbers |
| `network.ask_timeout` | a duration, e.g. `30s` |
| `proc`, `proc.mode` | `off`, `observe`, `enforce`, `ask` |
| `notify`, `notify.mode` | `off`, `once`, `always` |
| `notify.repeat_after` | a duration |
| `gui` | `none`, `offscreen`, `wayland` |
| `gpu`, `audio`, `dbus` | booleans |
| `limits.memory_high`, `limits.memory_max`, `limits.tasks_max` | a size, a percentage, or a count |
| `ssh_agent.confirm` | a boolean |
| `env.<KEY>` | one cage environment variable |
| `packages.<name>` | one `<backend>:<locator>`, e.g. `nix:hello` |
| `app.<name>.home_scope` | `project` or `global` |
| `task.<name>.description`, `.timeout`, `.max_output`, `.stdout`, `.stderr` | one value each |

**Lists, edited with `add` / `rm` (or `set` with a TOML array):**

| Key | Entries |
|---|---|
| `fs.deny`, `fs.readonly` | project paths to close or protect |
| `seccomp.allow` | syscall tokens re-permitted for the cage |
| `devices.allow` | host device paths, e.g. `/dev/kvm` |
| `ssh_agent.allow` | agent key names the cage may sign with |
| `forward` | host loopback ports |
| `binds` | host paths; `add` writes the read-only form, and a read-write one goes through `set binds '[{ path = "/opt/data", mode = "rw" }]'` |
| `network.groups.<name>` | egress entries of a reusable group |
| `network.http2`, `network.default_methods` | hosts, HTTP verbs |
| `app.<name>.use` | bundle names the app folds in |
| `task.<name>.cmd`, `.unmask`, `.env_allow`, `.network`, `.packages`, `.spawn` | the operation's own lists (`allow` and `deny` are [not task controls](../configuration/task) and a declaration carrying either is refused) |
| `bundle.<name>.allow`, `.deny`, `.mute` | the bundle's egress entries |

**Lists with a posture, added through their own verb:**

| Key | Add with | Remove with |
|---|---|---|
| `network.allow`, `network.deny` | [`sbx net allow` / `deny`](net) | [`sbx net unallow` / `undeny`](net) or `sbx config rm` |
| `network.mute` | [`sbx net mute`](net) | [`sbx net unmute`](net) or `sbx config rm` |
| `proc.allow`, `proc.deny` | [`sbx proc allow` / `deny`](proc) | [`sbx proc unallow` / `undeny`](proc) or `sbx config rm` |

`[network]` and `[proc]` gate their rules behind a posture, and those verbs carry the
matrix: they bootstrap the restrictive posture when there is none, refuse a rule that
would sit inert under the current mode, and never flip a deliberate `shared` or `none`.
`sbx config add` would write a rule that looks set and decides nothing, so it refuses and
names the verb. Removal is not redirected: taking a rule out cannot leave an inert one.
`sbx config rm` is the generic removal route; the dedicated verbs
([`sbx net unallow` / `undeny`](net), [`sbx proc unallow` / `undeny`](proc)) do the same
through the posture-aware surface.

**Records, one field at a time with `set`:** a table's own keys are reachable through the
dotted path, so nothing needs an editor just for being nested. A key that itself contains a
dot (every secret, since it is keyed by host) is **quoted**:

```sh
sbx config set 'secret."api.example.com".from' 'env://API_KEY'
sbx config set 'secret."api.example.com".header' Authorization
sbx config set 'task.build.params.file' '^[a-z]+\.enc$'
sbx config set 'task.build.inject.TOKEN.from' 'env://API_KEY'
```

[`edit`](#sbx-config-edit) is for what a command line handles badly rather than for what
it cannot reach: a multi-line inline flake (`flakes.<name>`), or a record you would rather
read whole than assemble field by field.

| Scope | Meaning |
|---|---|
| `-l, --local` | the project `.sbx.toml` (the default) |
| `-g, --global` | the global `sbx.toml` |
| `-c, --config <file>` | an explicit config file |
| `-a, --app <name>` | address the key under that app (`app.<name>.<key>` inline, or `-g` its profile) |

Writing a trusted project file re-arms its [trust gate](../concepts/trust); pass
`--trust` to re-trust in one step. A command that changes nothing writes nothing, and so
re-arms nothing: setting a key to the value it already holds, adding an entry a list
already carries, removing one it does not, or unsetting a key that was never set all
report `no change` and leave the file (and its trust) exactly as it was. The global config and app profiles are trusted by
location, so a write there needs no trust; a free `env` or `timezone` value needs none either.

`--trust` blesses the **whole current file**, which is why these four verbs refuse it on
a file that was never trusted, or that changed since you trusted it. Blessing it would
activate every security field in the file, including ones you have not read: a
`[network] mode = "shared"` you never saw takes the cage out of its own network
namespace, and with it the allowlist, the filtering proxy, and the egress log. The rule
the writing verbs share is that sbx blesses the delta it wrote, never bytes you have not
approved. The refusal lands before the write, so the file is left alone, and it names the
two ways through: review it and run `sbx trust`, or use `sbx config edit --trust`, where
the editor shows you the file first.

A file you trusted and then hand-edited is refused for the same reason, and says so in its
own words rather than claiming it is untrusted: the edit is exactly what `--trust` would
bless unread. The scope decides this, not the verb, so a `-c <file>` target is admitted the
same way; the exempt ones are those with no marker at all, the global config and the app
profiles. A file that does not exist yet is written and trusted, since sbx's own write is
then the whole content.

Without `--trust` nothing changes: the write goes through, and a security key is reported
as applying only once the file is trusted.

A write that would leave the layer unparseable is refused and the file is left
byte-for-byte alone. This is fail-closed on purpose: a committed invalid layer is dropped
**whole** at load, taking every security field with it.

## `sbx config path`

```
sbx config path [-l|-g|-c <file>]
```

With no scope flag, lists every config layer in resolution order (global then project)
and whether each exists. With a scope flag, prints just that file's path (for scripting
and for locating the global config).

## `sbx config edit`

```
sbx config edit [-l|-g|-c <file>] [--trust]
```

Opens the target file in `$VISUAL` / `$EDITOR` (falling back to `vi`): the way to edit
fields `set` does not handle as a single value: [`binds`](../configuration/binds),
an [allowlist](../configuration/network), [secrets](../configuration/secret), or
[app](../configuration/apps) tables.

A `binds` entry is an absolute host path, bound read-only by default; write it as a
table `{ path = "/abs/path", mode = "rw" }` to bind it read-write (the cage writes
through to the host path). A leading `~`, `$HOME`, or `$XDG_RUNTIME_DIR` is expanded
from your environment, so a portable config need not hard-code an absolute home path;
any other `$VAR` is refused. `binds` is a security field, honored only from a trusted
source. sbx's own state (its data, trust, and config directories) is protected either
way: a read-write bind aimed at or inside one of them is forced read-only with a
warning, while a broad read-write bind that merely contains them (e.g. `mode = "rw"`
on your whole home) stays read-write with those directories pinned read-only in place
and the rest of the tree is writable, but the agent still cannot alter what sbx runs or
trusts.

An edit that changes a trusted file re-arms its trust gate; `--trust` re-trusts as
the editor closes. That is about a gated file. The global config is trusted by
location, exactly as it is for the writing verbs above: it carries no marker, so
there is none to re-arm and none to write, and `--trust` there answers that it is not
needed rather than storing something nothing reads back.

This is also the one verb whose `--trust` blesses a file that was never trusted, where
`set`, `add`, `rm` and `unset` refuse. The difference is what you saw: the editor put the
file in front of you, so what is blessed is what you read. It is the way through the
other four verbs point at.

Two limits worth knowing. Your editor runs on the host with your own privileges and the
environment you invoked `sbx` with: it is not sandboxed, and this verb is not a
confinement boundary. And the file is edited in place, so sbx neither stages a copy nor
replaces it atomically; an editor killed mid-write can leave a truncated file, which the
loader drops whole with a warning and which no longer matches its trust marker, so its
security fields stay inert until you review and trust it again.

## Examples

```sh
sbx config show
sbx config show --app claude-code
sbx config show --json
sbx config set nixpkgs nixos-23.11 --trust
sbx config set fs.deny '[".env", "secrets/"]' --trust
sbx config add fs.deny .env --trust
sbx config rm fs.deny .env --trust
sbx config get env.RUST_LOG
sbx config edit --trust
sbx config path
```
