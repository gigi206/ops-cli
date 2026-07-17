# `sbx search`

```
sbx search <query>
```

Discover the `nix:` tools a project can declare, via [nixhub](https://www.nixhub.io/).
Host-side and read-only — it resolves nothing into the sandbox and needs no trust.

See also: [`packages`](../configuration/packages.md) · [`[tools]`](../configuration/tools.md) · [Provisioning](../concepts/provisioning.md).

## Two behaviors

- A **fuzzy** query lists matches (`name — summary`), capped at 25.
- A query that **names a package exactly** (case-insensitive) leads with that package's
  versions for your system and the lines to declare it in
  [`[tools]`](../configuration/tools.md) or [`[packages]`](../configuration/packages.md),
  with a `related:` footer.

## Examples

```sh
sbx search ripgrep      # exact: versions + declaration lines
sbx search ripgr        # fuzzy: a capped list of matches
sbx search jq
```

The `[tools]`/`[packages]` lines it prints use the `nix:` backend; for the `mise:` and
`flake:` backends see [`packages`](../configuration/packages.md).
