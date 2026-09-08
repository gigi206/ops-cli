---
sidebar_label: "Egress groups"
description: "Named sets of egress entries, one file per group, referenced from any list with `@name`."
---

# Egress groups

A group is a **named set of egress entries**, declared once and referenced from any
[`allow`/`deny` list](rules) with `@name`. Instead of copying the same hosts into every
app profile, you declare them in one place and share them.

Each group is a file under `net-groups/`, beside the global config, and **the file name
is the group name**:

```toml
# ~/.config/sbx/net-groups/ci-hosts.toml
entries = ["github.com", "api.github.com", "codeload.github.com"]
```

```toml
# ~/.config/sbx/net-groups/anthropic.toml
entries = ["api.anthropic.com"]
```

```toml
# ~/.config/sbx/net-groups/telemetry.toml
entries = ["*.doubleclick.net", "telemetry.example.com"]
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

## One group, one file

A group is a **vocabulary**: it says what a name stands for, and grants nothing on its
own. It lives in its own file, so there is one place to look for what `@name` means, and
the name lives in exactly one place: the file name. The entries go under `entries`,
because TOML has no top-level array; nothing else belongs in the file, and a key sbx does
not know there is refused rather than filed as an empty group.

That is also why your posture stays where it is. A group used to be a sub-table of
`[network]`, which forced any config defining one into the table form of the posture;
now `network = "deny"` and a directory of groups coexist, in every layer.

An inline `[network.groups]` in `sbx.toml` is **ignored**, with a warning naming each
group it carries, so two declaration sites for one name cannot disagree.

---

## Global-only

Groups are a security-relevant input, they expand into egress rules, so they are
honored **only from the `net-groups/` directory beside the global config** (trusted by
its location). A project's `[network.groups]` is **ignored** with a warning; a project may
*reference* a group with `@name`, but it cannot *define* one. This is why the
[`sbx net groups`](../cli/net#sbx-net-groups) command has no scope flag: it always reads
that directory.

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
sbx net groups export ci-hosts > ci-hosts.toml   # one group, to stdout
sbx net groups export ci-hosts -o ci-hosts.toml  # to a file
sbx net groups export --out-dir ./groups         # every group, one file each
```

`export` emits each group in the portable form `import` reads: its entries under
`entries`, its name carried by the file (a group is data, so source comments are not
carried). A file holds one group, which is why several need `--out-dir`.

```bash
sbx net groups import ci-hosts.toml            # file it under net-groups/ci-hosts.toml
sbx net groups import frag.toml --as ci-hosts  # …under a name of your choosing
sbx net groups import ci-hosts.toml --force    # overwrite a name that already exists
```

`import` copies the file into `net-groups/<name>.toml`, where the loader reads it. The
name comes from the file: its own stem, or `--as`. That directory is trusted by location,
so the deliberate command *is* the consent, an agent inside a cage cannot run it, and
there is no interactive prompt. A name that already exists is **refused** unless
`--force`. A group carrying an entry that will not resolve (malformed or nested) is
flagged after the import; inspect it with `sbx net groups <name>`.

A forced overwrite is the one import that can lose work, since a declared group may carry
an entry added by hand on this machine, and a group is policy: dropping an entry narrows
what an app may reach, adding one widens it. So it keeps the file it replaced beside it as
`<name>.toml.replaced`, and names both what the incoming group no longer declares and what
it declares on top. Re-import that copy to put the previous group back. A re-import that
changes nothing keeps no copy and reports no loss.

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
- [`sbx net`](../cli/net#sbx-net-groups): the `groups` verb, its `export`/`import` and its flags.
- [Egress observability](observability): `sbx net rules --expand`, which shows a rule's `@name` origin.
- [`sbx net` CLI reference](../cli/net)
