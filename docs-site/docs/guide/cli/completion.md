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
| anything else | left to the shell's own file completion |

Under zsh each candidate carries its one-line description, the same summary the help page
shows.

**Values are not completed.** An app name, a session id, a config key or a path falls
through to the shell's file completion. Completing them would mean reading the project
config, scanning the session registry or touching the store on every keypress, and a
completion has to be instant; the binary's own listing verbs ([`sbx app list`](app),
[`sbx session ls`](session)) stay the way to see them.

**Nothing is offered past a `--`.** Everything after the separator belongs to the launched
command, so `sbx run -- ls <TAB>` completes files, not sbx's verbs.

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

The oracle writes nothing to stderr and touches no configuration, store or session state.
Both are deliberate: the script is `eval`'d at shell startup and runs on every completion
request, so a stray diagnostic would land in the middle of your prompt, and a disk read
would show up as lag on every keypress.

## Adding a shell

Only bash and zsh are supported today. Because all of the logic lives in the binary, a
third shell is a small adapter (collect the words, call `sbx __complete --`, render the
lines) rather than a second transcription of the command tree; `src/cli/completion.rs`
holds both existing ones side by side.

There is no `sh` script, and there cannot be one: POSIX `sh` (dash, ash) has no
programmable completion mechanism. `complete` is a bash builtin, so "sh completion" in
practice means the bash script above.
