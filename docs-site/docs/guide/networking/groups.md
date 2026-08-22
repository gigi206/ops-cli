---
sidebar_label: "Egress groups"
description: "Named sets of egress entries, declared once in the global config and referenced from any list with `@name`."
---

# Egress groups (`[network.groups]`)

A `[network.groups]` group is a **named set of egress entries**, declared once and
referenced from any [`allow`/`deny` list](rules) with `@name`. Instead of
copying the same hosts into every app profile, you declare them in one place and
share them:

```toml
# global sbx.toml
[network.groups]
ci-hosts   = ["github.com", "api.github.com", "codeload.github.com"]
anthropic  = ["api.anthropic.com"]
telemetry  = ["*.doubleclick.net", "telemetry.example.com"]
```

Then reference a group by `@name` in a `[network]` list:

```toml
[app.claude-code.network]
mode  = "deny"
allow = ["@anthropic", "@ci-hosts"]   # expands to the four hosts above
deny  = ["@telemetry"]
```

At resolution each `@name` expands to the group's classified entries. A group entry
is **any egress rule** the `allow`/`deny` lists accept: an IP, host, `*.domain`,
exact URL, `re:` regex, or `tcp://` L4 target, with an optional `{VERB}` method
prefix. (See the [rule grammar](rules).)

---

## Groups live under the posture, and commit it to its table form

A group is a **vocabulary**: it says what a name stands for, and grants nothing on its
own. It sits under the same `[network]` as the posture that references it, so one
namespace answers "where may this cage go" and there is no second place to look.

That nesting has one consequence worth knowing before you write the file. TOML cannot
extend a string with a sub-table, so a config that declares groups writes its posture in
the [table form](../configuration/network#the-two-forms):

```toml
# global sbx.toml
[network]
mode = "deny"

[network.groups]
ci-hosts = ["github.com", "api.github.com"]
```

Writing `network = "deny"` above a `[network.groups]` table is not valid TOML, and a
config file that does not parse is **ignored in full**, with a warning naming the line.
Every other layer, a project config, an app profile, a `--config` blob, is free to keep
the bare-string form: only the file that defines groups has to spell out its posture.

---

## Global-only

Groups are a security-relevant input, they expand into egress rules, so they are
honored **only from the top-level `[network]` of the global config** (trusted by its
location). A project's `[network.groups]` is **ignored** with a warning; a project may
*reference* a global group with `@name`, but it cannot *define* one. This is why the
[`sbx net groups`](observability) command has no scope flag: it always reads the
global config.

The same holds for every other layer that has a `[network]` of its own. An
`[app.<name>.network]` and a `--config` blob are postures, not vocabularies: a `groups`
table written in either is ignored with a warning naming it, and the layer references a
global group with `@name` instead.

---

## Undefined and nested references fail loudly

An `@name` reference to a group that does not exist is **dropped with a loud
warning**. The direction of the failure depends on the list:

- In an **`allow`** list, dropping the reference means those hosts are **not
  allowed**: the safe (fail-closed) direction.
- In a **`deny`** list, dropping the reference means a carve-out is **lost**: the
  host is no longer blocked. This is the one case where a typo fails open *in
  intent*, which is exactly why the warning is loud and un-ignorable: an undefined
  reference must never pass unnoticed.

Always check `sbx config` (or [`sbx net rules`](observability)) after editing
groups so an undefined reference is caught before a launch.

A group is a **flat list**: a group entry may **not** itself be a `@other`
reference. A nested reference is rejected with a warning (the offending entry is
dropped). This makes an unbounded or cyclic expansion impossible by construction.

---

## Inspecting groups

```bash
sbx net groups                 # list every group and its entry count
sbx net groups anthropic       # resolve one group to its authored entries
sbx net groups anthropic --json
```

`sbx net groups` reads the global config only. A malformed or nested entry in a
group is flagged. To see a group *expanded inline* within an effective policy, use
[`sbx net rules --expand`](observability): a rule that came from a group shows
its `@name` origin.

---

## Moving groups between machines

Export and import let you share a curated group set:

```bash
sbx net groups export > groups.toml        # every group, as a [network.groups] fragment
sbx net groups export ci-hosts anthropic   # only these groups
sbx net groups export -o groups.toml       # to a file
```

`export` emits a portable `[network.groups]` TOML fragment (a group is data, so source
comments are not carried).

```bash
sbx net groups import groups.toml          # merge into the global config
sbx net groups import groups.toml --force  # overwrite a name that already exists
```

`import` merges the fragment's groups into the global config, preserving every
existing group and its comments. The global config is trusted by location, so the
deliberate command *is* the consent, an agent inside a cage cannot run it, and
there is no interactive prompt. A name that already exists is **refused** unless
`--force`, and the merge is all-or-nothing. A group carrying an entry that will not
resolve (malformed or nested) is flagged after the import; inspect it with
`sbx net groups <name>`.

A forced overwrite is the one import that can lose work, since a declared group may carry
an entry added by hand on this machine, and a group is policy: dropping an entry narrows
what an app may reach, adding one widens it. So it names what the incoming fragment no
longer declares, and keeps the group it replaced beside the config as
`<name>.group.replaced`. That copy is the same portable form `sbx net groups export`
writes, so putting the entry back is `sbx net groups import --force` on it. A group lives
in a key of the shared config rather than a file of its own, which is why the copy exists:
there is no per-group file to keep. A re-import that declares exactly what is already there
keeps no copy and reports no loss.

Imported groups are **inert** until a `[network]` `allow`/`deny` list references them
with `@name`.

---

## Adding a reference from the CLI

You do not have to edit a file to reference a group:

```bash
sbx net allow @ci-hosts               # add "@ci-hosts" to the project allow list
sbx net allow @anthropic -a claude    # under an app's [app.claude.network]
sbx net deny  @telemetry -g           # to the global config's deny list
```

`sbx net allow`/`deny` validate the reference name and write it like any other rule.
See [Egress observability](observability#persisting-rules) for the write scopes.

---

## See also

- [Rule grammar](rules): what a group entry may contain, and how `@name` is
  parsed within a list.
- [Network modes](modes): where the referencing `allow`/`deny` lists live.
- [Egress observability](observability): `sbx net groups`, `sbx net rules --expand`.
- [`sbx net` CLI reference](../cli/net)
