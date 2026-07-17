# Egress groups (`[net.groups]`)

A `[net.groups]` group is a **named set of egress entries**, declared once and
referenced from any [`allow`/`deny` list](rules.md) with `@name`. Instead of
copying the same hosts into every app profile, you declare them in one place and
share them:

```toml
# global sbx.toml
[net.groups]
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
is **any egress rule** the `allow`/`deny` lists accept — an IP, host, `*.domain`,
exact URL, `re:` regex, or `tcp://` L4 target, with an optional `{VERB}` method
prefix. (See the [rule grammar](rules.md).)

---

## Global-only

Groups are a security-relevant input — they expand into egress rules — so they are
honored **only from the global config** (trusted by its location). A project's
`[net.groups]` is **ignored** with a warning; a project may *reference* a
global group with `@name`, but it cannot *define* one. This is why the
[`sbx net groups`](observability.md) command has no scope flag: it always reads the
global config.

---

## Undefined and nested references fail loudly

An `@name` reference to a group that does not exist is **dropped with a loud
warning**. The direction of the failure depends on the list:

- In an **`allow`** list, dropping the reference means those hosts are **not
  allowed** — the safe (fail-closed) direction.
- In a **`deny`** list, dropping the reference means a carve-out is **lost** — the
  host is no longer blocked. This is the one case where a typo fails open *in
  intent*, which is exactly why the warning is loud and un-ignorable: an undefined
  reference must never pass unnoticed.

Always check `sbx config` (or [`sbx net rules`](observability.md)) after editing
groups so an undefined reference is caught before a launch.

A group is a **flat list** — a group entry may **not** itself be a `@other`
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
[`sbx net rules --expand`](observability.md) — a rule that came from a group shows
its `@name` origin.

---

## Moving groups between machines

Export and import let you share a curated group set:

```bash
sbx net groups export > groups.toml        # every group, as a [net.groups] fragment
sbx net groups export ci-hosts anthropic   # only these groups
sbx net groups export -o groups.toml       # to a file
```

`export` emits a portable `[net.groups]` TOML fragment (a group is data, so source
comments are not carried).

```bash
sbx net groups import groups.toml          # merge into the global config
sbx net groups import groups.toml --force  # overwrite a name that already exists
```

`import` merges the fragment's groups into the global config, preserving every
existing group and its comments. The global config is trusted by location, so the
deliberate command *is* the consent — an agent inside a cage cannot run it — and
there is no interactive prompt. A name that already exists is **refused** unless
`--force`, and the merge is all-or-nothing. A group carrying an entry that will not
resolve (malformed or nested) is flagged after the import; inspect it with
`sbx net groups <name>`.

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
See [Observability](observability.md#persisting-rules) for the write scopes.

---

## See also

- [Rule grammar](rules.md) — what a group entry may contain, and how `@name` is
  parsed within a list.
- [Network modes](modes.md) — where the referencing `allow`/`deny` lists live.
- [Observability](observability.md) — `sbx net groups`, `sbx net rules --expand`.
- [`[net.groups]` configuration reference](../configuration/net-groups.md)
- [`sbx net` CLI reference](../cli/net.md)
