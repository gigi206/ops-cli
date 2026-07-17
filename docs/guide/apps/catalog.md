# Profile catalog

The repository's [`profiles/`](../../../profiles/) directory ships importable starter
profiles for popular coding agents. `sbx` ships **no built-in apps** — you import each
deliberately:

```sh
sbx app import profiles/claude-code.toml
sbx app claude-code
```

See also: [Portable profiles](profiles.md) · [The app framework](README.md) · [Secrets](../secrets/README.md) · the repository [`profiles/README.md`](../../../profiles/README.md).

## The shipped profiles

| Profile | Tool (fresh, upstream) | Provider / egress |
|---|---|---|
| `claude-code` | `mise:aqua:anthropics/claude-code` | `api.anthropic.com` (BYOK) |
| `codex` | `mise:aqua:openai/codex` | `api.openai.com` (BYOK) |
| `opencode` | `mise:opencode` | provider-dependent (BYOK) |
| `pi` | `mise:aqua:earendil-works/pi` | provider-dependent (BYOK) |
| `hermes` | `flake:github:NousResearch/hermes-agent#default` | `openrouter.ai` (BYOK) |
| `kilocode` | `mise:github:Kilo-Org/kilocode` | provider-dependent (BYOK) |
| `freebuff` | `mise:npm:freebuff` (+ `nix:nodejs`) | `www.codebuff.com` (account) |
| `cline` | `mise:npm:cline` (+ `nix:nodejs`) | `openrouter.ai` (BYOK) |
| `droid` | `mise:npm:droid` (+ `nix:nodejs`) | `*.factory.ai` (account) |

Each gets its own persistent, isolated [`$HOME`](home.md), shared across projects by
default (`home_scope = "global"`).

## Two credential postures

- **BYOK** (most profiles) — your provider key is read on the host and injected by the
  proxy, **never entering the cage**. Provide it on the host:

  ```sh
  export ANTHROPIC_API_KEY=sk-ant-…      # claude-code / opencode
  export OPENAI_API_KEY=sk-…             # codex
  export OPENROUTER_API_KEY=sk-or-…      # hermes / cline (OpenRouter is the universal one)
  ```

  …or point the profile's `from = "env://…"` at a [resolver](../secrets/resolvers.md)
  (`sops://`, `file://`). The in-cage placeholder in `[env]` lets the CLI start; the
  proxy strips it and substitutes the real key on the wire. See
  [Injection](../secrets/injection.md).

- **Account** (`freebuff`, `droid`) — the tool logs in to a service account and the
  token persists in the app's **isolated** `$HOME` (so it lives in the — isolated —
  cage, never in the project shell).

Both stay bounded by the [egress allowlist](../networking/modes.md).

## Read by default — declare the write hosts

An app is [read-by-default](../configuration/network.md#default_methods-apps): every
Mode-B agent's allow rules default to `{GET,HEAD}`. A host the agent **writes** to (an
API it POSTs completions to, an account it logs into, a registry it installs from) must
be opened to all verbs with a `{*}` prefix — e.g. `"{*} https://api.anthropic.com"` —
while pure download/catalog hosts stay `"{GET,HEAD} …"` (least privilege). This is why
the shipped profiles prefix their API/install hosts with `{*}`.

## Freshness and the offline trade-off

The `mise:` prefix means a tool is equipped **in-cage from upstream directly**, so it is
the **latest upstream** version — not whatever nixpkgs packaged. A `mise:` (or `flake:`)
tool **fetches at first launch**, so a profile's *first* launch in a given project needs
the network; a `nix:` tool is seeded and reusable offline. Advancing an already-installed
`mise:`/`flake:` version via `sbx upgrade` is supported — see
[Upgrading](../housekeeping/upgrade.md).

## Adjusting the allowlist

If a tool's request is refused, the proxy reports the host it blocked — add it to the
profile's `allow` (a write verb may need a `{*}`/`{POST}` prefix). Check a URL's verdict
ahead of time:

```sh
sbx test net https://api.example.com --method POST
```

## Status and honest scope

The profiles **import and resolve** cleanly (covered by a test), and each tool is
**provisioned fresh and runs** under its own allowlist. The one remaining *live*
end-to-end is the **credential step** — for BYOK profiles, the CLI authenticating
through the proxy-injected key; for account profiles, completing the login inside the
cage. See the repository [`profiles/README.md`](../../../profiles/README.md) for the
per-tool status and the "not here yet — and why" triage (OAuth-only tools, GUI/desktop
agents blocked on the Wayland passthrough, etc.).
