---
sidebar_label: "Recommended tools"
description: "The tools worth putting in an agent cage, which tier to declare each in, and how to pin their versions."
---

# Choose the tools an agent cage needs

The base userland already carries a small, everyday toolset (`curl`, `git`,
`less`, `grep`, `rg`, `sed`, `awk`, `find`, `fd`, `jq`, `yq`, `which`),
provisioned into every cage, so the never-worth-declaring tools are already there,
search and structured-data querying included (see
[Provisioning](../concepts/provisioning#a-curated-base-toolset)). What remains
worth declaring is what the base deliberately leaves out: anything tied to a
language or to a particular harness. This page is that add-on set, what each tool
gives an agent, and where to declare it.

See also: [`packages`](../configuration/packages) · [`tools`](../configuration/tools) · [Provisioning](../concepts/provisioning) · [`sbx search`](../cli/search) · the [profile catalog](../apps/catalog).

## The recommended set

| Tool | What it gives an agent | Declare it |
|---|---|---|
| `python` | a scripting runtime for one-off transforms, data munging and glue; the base many agent kernels are built on | `python = "nix:python312"` |
| `ast-grep` | structural (AST-based) code search, lint and rewrite across many languages: finds symbols and patterns that text search misses, immune to formatting noise | `ast-grep = "nix:ast-grep"` |

Both are exactly what the base excludes. `python` is a language runtime, and
`ast-grep` carries a grammar per language it understands, so its size follows the
languages rather than the task. A cage that never runs either should not pay for
them, which is why they are declared rather than provisioned everywhere.

Search and structured data are not on this list: `rg`, `fd` and `yq` are in
the base userland, alongside `grep`, `find` and `jq`. A profile that declares
`nix:ripgrep` or `nix:fd` still works and is occasionally kept for
self-documentation, but it adds nothing to `PATH`.

A copy-paste `[packages]` block:

```toml
# ~/.config/sbx/sbx.toml: every project and every agent launch
[packages]
python    = "nix:python312"
ast-grep  = "nix:ast-grep"
```

## LSP servers: only when the harness drives them

An LSP server (`rust-analyzer`, `pyright`, `gopls`,
`typescript-language-server`, …) is an ordinary process to `sbx`: it is
provisioned like any other `nix:` package, and the cage needs no special
handling for it. Whether installing one is worth it is a property of the agent
harness, not of the sandbox: the only question is whether the harness actually
invokes the server (an LSP client of its own, a tool that shells out to the
binary, a language-analysis plugin) or leaves it untouched. Equip one when your
harness documents support for it, not speculatively: a server nothing invokes is
store space and nothing else.

```toml
[packages]
rust-analyzer = "nix:rust-analyzer"            # Rust
pyright       = "nix:pyright"                  # Python
gopls         = "nix:gopls"                    # Go
ts-ls         = "nix:typescript-language-server"  # TypeScript / JavaScript
```

## Where to declare: the three tiers

The same tools are declared in three different places depending on scope,
and the tiers compose (global → project → app, the app winning):

- **Global** (`~/.config/sbx/sbx.toml`): applies to every project and every
  agent launch, trusted by location. This is where the recommended set belongs:
  it is the "always available" answer.
- **An app profile** (`[packages]` in an imported profile): a per-agent
  toolset, for the harness that needs it.
- **A project's mise files** (`[tools]` in `.mise.toml`): project-local
  toolchain, the open self-equip path, auto-installed at launch. There is no
  trust gate on declaring it: the `nix:` prefix keeps it trusted-only, the
  non-`nix:` backends are open.

```toml
# .mise.toml: this project only, auto-equipped at launch
[tools]
"nix:python"   = "3.12"
"nix:ast-grep" = "latest"
```

The same tool can also be equipped live from inside the cage, into the project's
own store:

```sh
sbx mise install nix:ast-grep   # build ast-grep into this project's store
sbx mise use -g nix:ast-grep    # activate it: on PATH from the next launch
```

## Choosing versions

`nix:` tracks the pinned nixpkgs channel and is durable and offline-reusable
(seeded into each project's store). `sbx search` shows the attribute and its
versions, and prints the exact declaration lines:

```sh
sbx search ast-grep    # versions + [tools] / [packages] declaration lines
```

Versions move only on [`sbx upgrade nix`](../housekeeping/upgrade): the base
userland, the channel pin and these packages advance together. Prefer `nix:` for
the recommended set because presence must not depend on the cage's
[`network`](../configuration/network) posture: a `mise:` tool is fetched upstream-direct at
launch, so under `network = "none"` it is absent, while a seeded `nix:` tool is
there regardless. See the [`packages`](../configuration/packages) backend table for the full
trade-off.

## Already in the base, and why this list stops here

The base toolset is deliberately small and transverse (see
[Provisioning](../concepts/provisioning#a-curated-base-toolset)): re-declaring a
base tool (`git = "nix:git"`) is harmless and occasionally done in profiles for
self-documentation, but it buys nothing on `PATH`: the base `git` is already
there. Everything else is either language-specific or harness-dependent, and
belongs in the tiers above rather than the base: runtimes such as `nodejs` and
`uv` when your harness needs them, and LSP servers when it drives them. The two
tools above are the line where the base stops and an agent starts to benefit.

## Where to go next

- [Give a project a reproducible toolchain](reproducible-toolchain): pinning what you
  declared here, and rolling it forward deliberately.
- [`packages`](../configuration/packages): the backend prefixes, and what attests each
  provisioned artefact.
- [`[bundle.<name>]`](../configuration/bundles): declaring a tool's requirements once and
  naming them from every profile that needs them.

