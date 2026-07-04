# `[net.groups]` — reusable egress groups

A `[net.groups]` group is a named set of egress entries declared once in the **global**
config and referenced from a `[network]` allow/deny list with `@<name>`, so a set of
hosts is shared across apps instead of rewritten per profile.

```toml
# ~/.config/ops/ops.toml
[net.groups]
ci-hosts   = ["api.github.com", "codeload.github.com", "*.githubusercontent.com"]
ai-vendors = ["api.anthropic.com", "api.openai.com"]
```

```toml
# a project or app references the group by @name
[network]
mode  = "deny"
allow = ["@ci-hosts", "registry.npmjs.org"]
```

See also: [Network modes](../networking/modes.md) · [Rule grammar](../networking/rules.md) · [Egress groups (networking)](../networking/groups.md) · [`ops net groups`](../cli/net.md).

## Global-only

Groups are a security-relevant input — they expand to egress rules — so they are
honored **only from the global config** (trusted by location). A project's
`[net.groups]` is ignored. This is why the group commands have no scope flag: they
always read the global config.

## Group entries

A group entry is **any egress rule string** the `allow`/`deny` lists accept — an IP,
a host, `*.domain`, an exact URL, a `re:` regex, or a `tcp://` L4 target, with an
optional `{VERB,…}` method prefix. See the [rule grammar](../networking/rules.md).

A `[network]` list references a group by `@<name>`; the reference expands to the
group's entries at launch.

## Undefined references fail closed

An `@<name>` that names no defined group is a **fail-closed** error — the rule does
not silently become "allow nothing" or "allow everything"; the reference is refused. A
group entry that will not resolve (malformed or nested) is flagged.

## Managing groups

```sh
ops net groups                 # list every group and its entry count
ops net groups ci-hosts        # resolve one group to its entries
ops net allow @ci-hosts        # add a reference to a config's allow list
ops net rules --expand         # show effective rules with groups unfolded
```

Groups move between machines as a portable `[net.groups]` fragment:

```sh
ops net groups export > groups.toml           # or export named groups
ops net groups import groups.toml             # merge into the global config
ops net groups import groups.toml --force      # overwrite same-named groups
```

`import` merges into the global config (trusted by location), preserving existing
groups and comments; a name clash is refused unless `--force`. Imported groups are
inert until referenced by a `[network]` list. See
[`ops net groups`](../cli/net.md) and [Egress groups](../networking/groups.md).
