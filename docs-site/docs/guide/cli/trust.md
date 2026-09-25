---
description: "Vouch for a project config's current contents, so its security fields are honored until the file changes."
---

# `sbx trust`

```
sbx trust [--yes] [path]
sbx trust --show [path]
```

Vouch for a project config's current contents, so its security-relevant fields are
honored until the file changes again. Trust is bound to the file's contents, so any
edit re-arms the gate.

| Option | Meaning |
|---|---|
| `[path]` | the config to act on (default `./.sbx.toml`) |
| `--show` | report the trust state without changing it (accepted before or after `[path]`) |
| `--yes` | record without asking; required when there is no terminal to confirm at |

See also: [The trust gate](../concepts/trust) · [`sbx untrust`](untrust) · [Configuration overview](../configuration/).

## Behavior

`sbx trust` records a **SHA-256 of the whole file** (plus any sibling mise files, and
every [sops file it names in the project](../concepts/trust#sops-files-the-config-names)),
keyed by the config's canonical path. A launch then compares the hash of the exact
bytes it parses:

- **Trusted**: the hash matches; security fields apply.
- **Changed**, a record exists but the bytes differ; security fields are dropped
  (distinct from untrusted).
- **Untrusted**: no record; security fields are dropped.

Before recording, `sbx trust` prints what the trust grants: the lines of the config,
of its mise files and of its sops files (shown as `sops:<path>`) that changed since they were last approved, as a diff, or every line
when nothing was approved before. It then asks for confirmation on a terminal. Without a
terminal it refuses unless `--yes` is given, so a script that trusts a config has to say
so. A config that already matches its approval is recorded without a question, since it
grants nothing new. The bytes recorded are the ones shown: a change written to the file
while the prompt waits is not covered by the trust.

The review matters because the project tree is writable from inside the cage. A
re-approval prompted by a change you did not make is exactly the moment to read the
diff: a launch names each bind it drops from a changed file, and `sbx trust` shows the
line that added it.

For the same reason, the review never lets a line act on your terminal. A control
character (an escape sequence, a carriage return) is printed as an escape such as `\x1b`
or `\x0d`, and so is a character that reorders the text around it, such as `\u{202e}`.
You see that the character is there rather than what it would do to the lines you read.
A tab is left as it is.

The global config and app profiles are **trusted by location**: they need no `sbx
trust`, and asking for one says so and records nothing, since no reader looks for a
marker on either. Only a project `.sbx.toml` uses content trust. One exception: [`[fs]`](../configuration/fs)
is the one table this does not govern, since it can only close project paths off inside
the cage, so it applies whether or not the file is trusted. Its two keys that widen
instead, `scan_max_kb` and `git_writable`, are gated like any security field. See
[The trust gate](../concepts/trust).

## Examples

```sh
sbx trust                 # review and trust ./.sbx.toml
sbx trust --yes           # the same, without the prompt (scripts, CI)
sbx trust --show          # report the state
sbx trust path/to/.sbx.toml
```

After editing a trusted file, run `sbx trust` again, or use `sbx config set/edit
--trust` to re-trust in one step. Revoke with [`sbx untrust`](untrust).
