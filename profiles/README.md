# App profiles

Importable launch profiles for `ops app`. ops ships **no built-in apps** — each
profile here is a separate, portable artifact you import deliberately:

```sh
ops app import profiles/claude-code.toml   # a conscious trust act
ops app claude-code                        # launch it, sandboxed
```

A profile is a standalone TOML file shaped as a top-level app (`cmd` plus the
tools, network posture, and credentials it needs). Imported profiles live under
`$XDG_CONFIG_HOME/ops/apps/` and are trusted by location — honored even when the
project you launch in is untrusted (the point: run an agent *on* untrusted code,
safely). Manage them with `ops app list` / `ops app rm <name>`, and re-export one
with `ops app export <name>`.

## What's here

| Profile           | Tool            | Provider / egress       |
| ----------------- | --------------- | ----------------------- |
| `claude-code`     | `claude-code`   | `api.anthropic.com`     |
| `codex`           | `codex`         | `api.openai.com`        |
| `opencode`        | `opencode`      | provider-dependent      |

Each gets its own persistent, isolated `$HOME` (config, login, history), shared
across projects by default (`home_scope`).

## Credentials — the key never enters the cage

The real API key is read **on the host** and injected into the matching outbound
request by the egress proxy; it never enters the sandbox. Provide it on the host:

```sh
export ANTHROPIC_API_KEY=sk-ant-…      # for claude-code / opencode
export OPENAI_API_KEY=sk-…             # for codex
```

…or point the profile's `from = "env://…"` at a resolver (`sops://`, `file://`).
The in-cage placeholder in `[env]` lets the CLI start and issue its request; the
proxy strips the placeholder and substitutes the real key on the wire. Egress is
an **allowlist** (deny-by-construction), so even with the key in flight the agent
can only reach the provider you listed.

> **Status:** the profiles import and resolve cleanly (covered by a test). The
> *live* end-to-end — the CLI authenticating through the proxy-injected key — is
> the flagship validation still to be proven with a real key (does the tool accept
> the placeholder and let the proxy fill in the real key?). Treat these as correct
> artifacts pending that proof.

## Tool freshness

A profile declares its tool via `[packages]` (a nixpkgs attribute), so the version
tracks your **base nix channel**; roll it forward with `ops upgrade nix`. For these
agents nixpkgs is current, so that is fresh enough. Per-tool floating versions
(nixhub `nix:<tool> = "latest"`) and non-nix mise backends (`aqua:`/`github:`/`npm:`
for immediate-upstream freshness) are a planned increment — non-nix tools fetch
from upstream at install (gated by the egress allowlist) and so trade away offline
launch.

## Adjusting the allowlist

If a tool's request is refused, the proxy reports the host it blocked — add it to
`allow`. You can check a URL's verdict ahead of time with `ops test net <url>`.

## Not here yet

- **GUI / desktop agents** (opencode desktop, antigravity, hermes desktop): these
  need the Wayland passthrough, which is not built yet.
- **Other CLI agents** (pi, agy, hermes, …): tell us the package, launch command,
  API host(s), and credential mechanism and a profile can be added — nothing here
  is guessed.
