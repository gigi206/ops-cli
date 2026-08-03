# Profile catalog

The repository's [`examples/app/`](https://github.com/gigi206/ops-cli/tree/ops-v2/examples/app/) directory ships **48 importable
starter profiles**. `sbx` ships **no built-in apps**: you import each deliberately:

```sh
sbx app import examples/app/claude-code.toml
sbx app run claude-code
```

See also: [Portable profiles](profiles) · [The app framework](/) · [Secrets](../secrets/) · the repository [`examples/README.md`](https://github.com/gigi206/ops-cli/blob/ops-v2/examples/).

The tables below list every shipped profile, grouped by **how you interact with it**: a
terminal agent, a desktop window, or a UI served in your host browser. The per-profile
packaging notes and the "not here yet, and why" triage live in
[`examples/README.md`](https://github.com/gigi206/ops-cli/blob/ops-v2/examples/).

## Terminal agents (31)

The common case: a CLI or TUI that runs in the terminal you launched it from.

| Profile | Tool (fresh, upstream) | Provider / egress |
|---|---|---|
| `agy` | `mise:aqua:google-antigravity/antigravity-cli` | `accounts.google.com` (Google account) |
| `amp` | `nix:nodejs` (+ `mise:npm:@ampcode/cli`) | `ampcode.com` (account / `AMP_API_KEY`) |
| `auggie` | `nix:nodejs` (+ `mise:npm:@augmentcode/auggie`) | `*.api.augmentcode.com` (`AUGMENT_API_TOKEN`) |
| `claude-code` | `mise:aqua:anthropics/claude-code` | `api.anthropic.com` (BYOK) |
| `cline` | `nix:nodejs` (+ `mise:npm:cline`, `nix:hostname`) | `openrouter.ai` (BYOK) |
| `codebuddy` | `nix:nodejs` (+ `mise:npm:@tencent-ai/codebuddy-code`) | `*.codebuddy.ai` (account) |
| `codex` | `mise:aqua:openai/codex` | `api.openai.com` (BYOK) |
| `copilot` | `mise:aqua:github/copilot-cli` | `*.githubcopilot.com` (GitHub account / `GH_TOKEN`) |
| `cortex` | `mise:github:CortexLM/cortex-code` (+ `nix:alsa-lib`) | `api.cortex.foundation` (`CORTEX_API_KEY`) or BYOK |
| `cursor-agent` | `nix:gnutar` (+ `nix:gzip`) | `*.cursor.sh` (Cursor account / `CURSOR_API_KEY`) |
| `dirac` | `nix:nodejs` (+ `mise:npm:dirac-cli`, `nix:ripgrep`) | provider-dependent (BYOK, no vendor account) |
| `droid` | `nix:nodejs` (+ `mise:npm:droid`) | `*.factory.ai` (account) |
| `freebuff` | `nix:nodejs` (+ `mise:npm:freebuff`) | `www.codebuff.com` (account) |
| `goose` | `mise:aqua:block/goose` | provider-dependent (BYOK) |
| `grok` | `mise:aqua:x.ai/cli/grok` | `api.x.ai` (BYOK) or an xAI account |
| `hermes` | `flake:github:NousResearch/hermes-agent#default` (+ `nix:nodejs`, `nix:chromium`, …) | `openrouter.ai` (BYOK) |
| `junie` | `nix:nodejs` (+ `mise:npm:@jetbrains/junie`) | `api.jetbrains.ai` (JetBrains account / `JUNIE_API_KEY` / BYOK) |
| `kilocode` | `mise:github:Kilo-Org/kilocode` | provider-dependent (BYOK) |
| `kimi` | `nix:nodejs` (+ `mise:npm:@moonshot-ai/kimi-code`) | `api.kimi.com` (`KIMI_API_KEY` / Moonshot account) |
| `nova` | `nix:nodejs` (+ `mise:npm:@compass-ai/nova`) | `api.compassap.ai` (`COMPASS_API_KEY`) or BYOK |
| `openclaw` | `nix:nodejs` (+ `mise:npm:openclaw`) | `api.openai.com` (BYOK) |
| `opencode` | `mise:opencode` | provider-dependent (BYOK) |
| `openfox` | `nix:nodejs` (+ `mise:npm:openfox`) | **none**: a local LLM you point it at |
| `pi` | `mise:aqua:earendil-works/pi` | provider-dependent (BYOK) |
| `pool` | `nix:gnutar` (+ `nix:gzip`) | `*.poolside.ai` (Poolside account) |
| `qoder` | `nix:nodejs` (+ `mise:npm:@qoder-ai/qodercli`, `nix:ripgrep`) | `*.qoder.sh` (Qoder account / `QODER_PERSONAL_ACCESS_TOKEN`) |
| `qwen-code` | `nix:nodejs` (+ `mise:npm:@qwen-code/qwen-code`) | `dashscope.aliyuncs.com` (`DASHSCOPE_API_KEY`) |
| `sigit` | `nix:nodejs` (+ `mise:npm:@smbcloud/sigit`) | **none**: the model runs in-cage |
| `snow` | `nix:nodejs` (+ `mise:npm:snow-ai`) | provider-dependent (BYOK) |
| `stakpak` | `mise:github:stakpak/agent` | `apiv2.stakpak.dev` (`STAKPAK_API_KEY`) or BYOK: a DevOps agent |
| `vtcode` | `mise:github:vinhnx/VTCode` (+ `nix:ripgrep`, `nix:ast-grep`) | provider-dependent (BYOK, default OpenRouter) |

## Desktop applications (12)

Electron/GUI agents. Each needs a [Wayland display](../configuration/gui)
(`gui = "wayland"`), and most also enable [`gpu`](../configuration/gpu) and the in-cage
[desktop portal](../configuration/dbus) (`dbus = true`). Where the tool's sign-in opens
an external browser, the profile wires an in-cage Chromium as the `xdg-open` handler so the
whole login closes inside the cage.

| Profile | Tool (fresh, upstream) | Provider / egress |
|---|---|---|
| `aionui` | `deb:github:iOfficeAI/AionUi` (+ `nix:chromium`) | multi-provider (BYOK) |
| `antigravity` | `tarball:resolve` (+ `nix:chromium`) | `cloudcode-pa.googleapis.com` (Google account) |
| `claude-desktop` | `deb:apt:downloads.claude.ai/…` (+ `nix:chromium`) | `api.anthropic.com` / `claude.ai` (Anthropic account) |
| `cursor` | `deb:resolve` (+ `nix:chromium`) | `*.cursor.com` (Cursor account) |
| `freebuff-desktop` | `appimage:resolve` (+ `nix:chromium`) | `www.codebuff.com` (account) |
| `goose-desktop` | `deb:github:aaif-goose/goose` | provider-dependent (BYOK) |
| `hermes-desktop` | `flake:github:NousResearch/hermes-agent#desktop` (+ `nix:chromium`, `nix:nodejs`, …) | `openrouter.ai` (BYOK) |
| `kiro` | `nix:kiro-cli` (+ `nix:chromium`) | `*.kiro.dev` (AWS/Kiro account) |
| `kiro-desktop` | `tarball:resolve` (+ `nix:chromium`) | `app.kiro.dev` (AWS/Kiro account) |
| `opencode-desktop` | `deb:github:anomalyco/opencode` | provider-dependent (BYOK) |
| `t3code` | `appimage:github:pingdotgg/t3code` (+ `nix:chromium`) | provider-dependent (BYOK) |
| `vibe` | `mise:pipx:mistral-vibe` (+ `nix:uv`, `nix:python312`, …) | `*.mistral.ai` (`MISTRAL_API_KEY`) |

## Browser-served UIs (5)

The app serves a UI inside the cage; the profile [forwards](../networking/forward) its
port to your host loopback, and you open it in your own browser.

| Profile | Tool (fresh, upstream) | Provider / egress |
|---|---|---|
| `hermes-web` | `flake:github:NousResearch/hermes-agent#default` (+ `nix:nodejs`, `nix:chromium`, …) | `openrouter.ai` (BYOK) |
| `hermes-webui` | `flake:github:nesquena/hermes-webui#default` (+ `flake:github:NousResearch/hermes-agent#default`, `nix:nodejs`, …) | `openrouter.ai` (BYOK) |
| `odysseus` | `nix:git` (+ `nix:python312`, `nix:uv`, …) | multi-provider (BYOK), self-hosted workspace |
| `open-design` | `nix:nodejs_24` (+ `nix:git`, `nix:python3`, …) | none directly: renders through the `opencode` bundle |
| `opencode-web` | `mise:opencode` | provider-dependent (BYOK) |

Each profile gets its own persistent, isolated [`$HOME`](home), shared across projects by
default (`home_scope = "global"`).

## Bundles: the shared pieces

Beyond the app profiles, [`examples/bundle/`](https://github.com/gigi206/ops-cli/tree/ops-v2/examples/bundle/)
ships **26 reusable tool bundles**: a named set of packages and egress rules that several
profiles pull in with `use = [...]` instead of restating it. See
[Bundles](../configuration/bundles) and [`sbx bundle`](../cli/bundle).

## Two credential postures

- **BYOK** (most profiles): your provider key is read on the host and injected by the
  proxy, **never entering the cage**. Provide it on the host:

  ```sh
  export ANTHROPIC_API_KEY=sk-ant-…      # claude-code / opencode
  export OPENAI_API_KEY=sk-…             # codex
  export OPENROUTER_API_KEY=sk-or-…      # hermes / cline (OpenRouter is the universal one)
  ```

  …or point the profile's `from = "env://…"` at a [resolver](../secrets/resolvers)
  (`sops://`, `file://`). The in-cage placeholder in `[env]` lets the CLI start; the
  proxy strips it and substitutes the real key on the wire. See
  [Injection](../secrets/injection).

- **Account** (`freebuff`, `droid`, `copilot`, `codebuddy`, `amp`, `junie`, and most of the
  desktop profiles): the tool logs in to a service account and the token persists in the
  app's **isolated** `$HOME`, inside the cage, never in the project shell. An account whose
  token *is* a header value takes the injected path instead, so the secret still never enters
  the cage: `stakpak` (a Stakpak API key), `qoder` (a personal access token), `nova` (a
  Compass key).

There is also a third case: **no credential at all**. `sigit` runs the model in-cage (a GGUF
fetched from Hugging Face on first launch) and `openfox` talks to a local LLM you point it
at, so there is nothing to inject and nothing to log into.

Both stay bounded by the [egress allowlist](../networking/modes).

## Read by default: declare the write hosts

An app is [read-by-default](../configuration/network#default_methods-apps): every
Mode-B agent's allow rules default to `{GET,HEAD}`. A host the agent **writes** to (an
API it POSTs completions to, an account it logs into, a registry it installs from) must
be opened to all verbs with a `{*}` prefix: e.g. `"{*} https://api.anthropic.com"`, while pure download/catalog hosts stay `"{GET,HEAD} …"` (least privilege). This is why
the shipped profiles prefix their API/install hosts with `{*}`.

## Freshness and the offline trade-off

The `mise:` prefix means a tool is equipped **in-cage from upstream directly**, so it is
the **latest upstream** version: not whatever nixpkgs packaged. A `mise:` (or `flake:`)
tool **fetches at first launch**, so a profile's *first* launch in a given project needs
the network; a `nix:` tool is seeded and reusable offline. The `deb:`, `appimage:` and
`tarball:` backends fetch a published upstream artifact the same way; see
[Packages](../configuration/packages). Advancing an already-installed version via
`sbx upgrade` is supported: see [Upgrading](../housekeeping/upgrade).

## Adjusting the allowlist

If a tool's request is refused, the proxy reports the host it blocked: add it to the
profile's `allow` (a write verb may need a `{*}`/`{POST}` prefix). Check a URL's verdict
ahead of time:

```sh
sbx test net https://api.example.com --method POST
```

To discover a profile's real needs rather than guessing them, run it once under
[`--net-learn`](../cli/app#learning-an-apps-egress---net-learn), which turns each refusal
into the rule that would have admitted it:

```sh
sbx app run claude-code --net-learn --dry-run    # preview the rules, write nothing
```

## Status and honest scope

The profiles **import and resolve** cleanly (covered by a test), and each tool is
**provisioned fresh and runs** under its own allowlist. The one remaining *live*
end-to-end is the **credential step**: for BYOK profiles, the CLI authenticating
through the proxy-injected key; for account profiles, completing the login inside the
cage. See the repository [`examples/README.md`](https://github.com/gigi206/ops-cli/blob/ops-v2/examples/) for the
per-tool status and the "not here yet, and why" triage (tools that are not a runnable
agent, or whose provenance is not established).
