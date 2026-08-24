---
description: "Print the shell completion script for a shell, on stdout."
---

# `sbx completion`

```
sbx completion <bash|zsh>
```

Print the shell completion script for a shell, on stdout. The shell is **required**, and
one that is not supported is refused by name rather than guessed at, so you never end up
with a script that loads quietly and completes nothing.

| Argument | Meaning |
|---|---|
| `bash` | the bash completion script |
| `zsh` | the zsh completion script |

See also: [Command reference](../cli/) · [`sbx run`](run) · [Installation](../getting-started/installation).

## Install it

### bash

```sh
# just this shell
source <(sbx completion bash)

# permanently
mkdir -p ~/.local/share/bash-completion/completions
sbx completion bash > ~/.local/share/bash-completion/completions/sbx
```

The permanent form relies on the `bash-completion` package being installed and loaded
from your `~/.bashrc` (most distributions do this by default). Without it, put the
`source <(sbx completion bash)` line in `~/.bashrc` instead.

### zsh

```sh
# just this shell
source <(sbx completion zsh)

# permanently, into a directory on your $fpath
sbx completion zsh > "${fpath[1]}/_sbx"
```

zsh needs its completion system initialised before either form works. If it is not
already, add this to `~/.zshrc` **above** the line that loads the script:

```sh
autoload -U compinit && compinit
```

After installing the permanent form, start a new shell (or delete `~/.zcompdump` and run
`compinit` again) so zsh picks the new file up.

:::note
The generated script calls `sbx` by name, so the binary has to be on your `PATH`. That is
the same condition under which completion is useful at all, but it is worth knowing if you
keep several builds around: completion answers for whichever `sbx` your `PATH` resolves.
:::

## What completes

| Where | What you get |
|---|---|
| `sbx <TAB>` | every top-level command |
| `sbx app <TAB>` | that command's subcommands, at any depth |
| `sbx plugins store <TAB>` | three levels deep, same as the help tree |
| `sbx run --<TAB>` | that command's options |
| `sbx help <TAB>` | the command tree again, so `sbx help plugins store <TAB>` works |
| `sbx app run <TAB>` | the values that position takes, see below |
| `sbx run -- ls <TAB>` | nothing of sbx's: the shell completes the launched command's line |

Under zsh each candidate carries its one-line description, the same summary the help page
shows.

### Values

Where the help table says a word is a **value** rather than a command, the oracle completes
the value. Two kinds:

- **Read from this machine**, fresh on every request: the live sessions' ids, the configured
  stores and their catalogue plugins, the installed resolver plugins, the app profiles, the
  per-project trees, and the table names and `[task.<name>]` sections of the config files in
  front of you.
- **Spelled out by the grammar itself**: a `bash` or `zsh` for this page, an upgrade target,
  a `--net` posture, a `--gui` or `--notify` mode, a `--verdict`.

A **removal verb completes what it can remove**. `sbx net unallow <TAB>` offers the allow
rules already written, `undeny` the deny rules, `unmute` the mute rules, and
`sbx proc unallow`/`undeny` their `[proc]` twins. `--app <name>` moves the offer to that
app's own profile, the file the removal would edit. The add verbs deliberately offer none
of them: `sbx net allow` takes precisely a rule that is *not* in the list yet.

Only a value sbx cannot enumerate is left to the shell: a filesystem path, and the command
line past a `--`. There the oracle answers with a reserved marker instead of a candidate,
and the script turns it into the shell's own file completion, so a name holding a space
stays one candidate.

A few positions complete nothing on purpose, because the set they name is not one this
machine holds: a number, free text being composed, a URL or flake ref, an HTTP method, a
seccomp token. That list is pinned by a test, so a value position added later is either
completed or declared, never silently empty.

:::note
Value completion reads the registries the listing verbs read: the session registry, the
store checkouts, the profile directory, the two config files. These are small, local, and
read-only, and no value position reaches for the network or the nix store. A page whose
registry cannot be read simply offers nothing there.
:::

**Nothing of sbx's is offered past a `--`.** Everything after the separator belongs to the
launched command, so `sbx run -- ls <TAB>` completes files, not sbx's verbs.

## How it works

The generated script holds **no copy of the command tree**. It collects the words typed so
far and asks the binary, through a hidden `__complete` verb, which candidates fit:

```
$ sbx __complete -- plugins store publ
publish	sign a directory of plugins into a store
```

One name, a tab, one description, per line. The binary answers from the very same table
that renders `sbx help`, which has two consequences worth relying on:

- **Completion cannot drift from the CLI.** A verb added to the help tree completes the day
  it lands; there is no second list to keep in step, and no generated file to refresh.
- **A stale script is not a thing.** Upgrading sbx upgrades what it completes, without
  regenerating anything. The script only ever needs rewriting if its own protocol changes.

The oracle writes nothing to stderr, and it never writes anything anywhere: it reads
registries, and answers. Both are deliberate. The script is `eval`'d at shell startup and
runs on every completion request, so a stray diagnostic would land in the middle of your
prompt, and a completion that changed state would make pressing Tab a thing you had to
think about.

A [storage volume](storage) is read the same way: the oracle follows the pointer only as
far as reading it, so a volume that is already mounted completes normally and one that is
not simply completes nothing. Pressing Tab is not what attaches a loop device and mounts a
filesystem; a command you typed is.

A command path answers from the help table alone and reads nothing. A value position reads
the registry behind it, and does so fresh rather than from a cache, so a session you just
started completes without a stale list to refresh. Where a registry is another process
rather than a file, the oracle gives it a short budget and drops it from the menu if it
does not answer inside it: a menu one item short beats a prompt that stalls.

## Adding a shell

Only bash and zsh are supported today. Because all of the logic lives in the binary, a
third shell is a small adapter (collect the words, call `sbx __complete --`, render the
lines) rather than a second transcription of the command tree; `src/cli/completion.rs`
holds both existing ones side by side.

There is no `sh` script, and there cannot be one: POSIX `sh` (dash, ash) has no
programmable completion mechanism. `complete` is a bash builtin, so "sh completion" in
practice means the bash script above.
