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

| Profile           | Tool (fresh, upstream)               | Provider / egress       |
| ----------------- | ------------------------------------ | ----------------------- |
| `claude-code`     | `mise:aqua:anthropics/claude-code`   | `api.anthropic.com`     |
| `codex`           | `mise:aqua:openai/codex`             | `api.openai.com`        |
| `opencode`        | `mise:opencode`                      | provider-dependent      |
| `pi`              | `mise:aqua:earendil-works/pi`        | provider-dependent      |
| `hermes`          | `flake:github:NousResearch/hermes-agent#default` | `openrouter.ai` (BYOK)  |
| `kilocode`        | `mise:github:Kilo-Org/kilocode`                  | provider-dependent      |
| `freebuff`        | `mise:npm:freebuff` (+ `nix:nodejs`)             | `www.codebuff.com` (account) |
| `cline`           | `mise:npm:cline` (+ `nix:nodejs`)                | `openrouter.ai` (BYOK)  |
| `droid`           | `mise:npm:droid` (+ `nix:nodejs`)                | `*.factory.ai` (account) |

Each gets its own persistent, isolated `$HOME` (config, login, history), shared
across projects by default (`home_scope`).

> **Two credential postures.** Most profiles are **BYOK** — your provider key is read
> on the host and injected by the proxy, never entering the cage (see below).
> `freebuff` is the other kind: it logs in to a service **account** and the token
> persists in the app's isolated `$HOME` (so it *does* live in the — isolated — cage,
> never in the project shell). Both stay bounded by the egress allowlist.

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

> **Status:** the profiles import and resolve cleanly (covered by a test), and the
> tool is **provisioned fresh and runs** under the profile's own allowlist — proven
> live for `claude-code` (2.1.185, equipped via `mise use -g` and run through the
> empty-netns MITM), `kilocode` (7.3.50, equipped via the mise `github` backend and run
> in-cage — `kilo --version`), and `freebuff` (0.0.112, equipped via mise's **npm** backend
> over a `nix:nodejs` runtime — the npm launcher and its 46 MB binary both fetched through the
> empty-netns MITM allowlist, then `freebuff --version`), and `cline` (3.0.29) and `droid`
> (0.153.1) (both equipped via mise's **npm** backend over a `nix:nodejs` runtime — their
> native platform binaries resolved through the empty-netns MITM allowlist, then `--version`).
> The one remaining *live* end-to-end is
> the credential step: for the BYOK profiles, the CLI **authenticating** through the
> proxy-injected key (does the tool accept the placeholder and let the proxy fill in the real
> key?); for `freebuff`, completing its account **login** once inside the cage (the token then
> persists in the isolated home). Both are the flagship validation, still to be proven with a
> real key/account.
>
> The **flake-backed** profile `hermes` carries an extra first-launch step — the in-cage
> `nix build` that compiles it (uv2nix Python + its bundled node front-ends) — and that build
> is **proven to run live in-cage** under the profile's own allowlist (`hermes` lands on PATH;
> only the live-auth above is still pending). The `flake:` backend itself is also proven on a
> reference flake.

## Tool freshness

Each profile declares its tool with a **backend-prefixed** `[packages]` value:

| Profile       | Declaration                                  | Source                         |
| ------------- | -------------------------------------------- | ------------------------------ |
| `claude-code` | `mise:aqua:anthropics/claude-code`           | Anthropic's standalone release |
| `codex`       | `mise:aqua:openai/codex`                      | OpenAI's GitHub release        |
| `opencode`    | `mise:opencode`                              | opencode's standalone release  |
| `pi`          | `mise:aqua:earendil-works/pi`                | Earendil's GitHub release      |
| `hermes`      | `flake:github:NousResearch/hermes-agent#default` | NousResearch flake (uv2nix Python) |
| `kilocode`    | `mise:github:Kilo-Org/kilocode`                  | Kilo Code's GitHub release binary  |
| `freebuff`    | `mise:npm:freebuff` (+ `nix:nodejs`)             | npm launcher → www.codebuff.com binary |
| `cline`       | `mise:npm:cline` (+ `nix:nodejs`)                | npm package → native platform binary |
| `droid`       | `mise:npm:droid` (+ `nix:nodejs`)                | npm package → native platform binary |

The `mise:` prefix means the tool is equipped **in-cage** from **upstream directly**
(mise's `aqua`/`github`/registry backends pull the real release binary), so the version is the
**latest upstream** — not whatever nixpkgs has packaged. This sidesteps both the nixpkgs
lag and, for `claude-code`, the nixpkgs **unfree** gate (the standalone binary carries no
such restriction). The tool is equipped at the latest upstream version on the **first
launch in a project**; advancing an already-installed `mise:` version is **not yet
automated** by `ops upgrade` (a roll-forward for `[packages] mise:` is a planned increment)
— so a long-lived project store keeps its first-installed version until then.

A nixpkgs attribute is still available as `nix:<attr>` (provisioned host-side, seeded,
offline-reusable) — use it for stable substrate tools where freshness does not matter.

A third backend, **`flake:<ref>`**, packages a tool that ships **only as a nix flake** — no
single release binary and no nixpkgs attribute (e.g. a uv2nix Python agent like `hermes`). ops
builds the flake **in-cage** with `nix build` into the project's own store; the first launch
builds it (network + minutes — the build's own fetch hosts must be in `allow`, e.g.
`files.pythonhosted.org`/`pypi.org` and `registry.npmjs.org` for `hermes`), and later launches
reuse the warm build **offline**. Like `mise:`, the flake reference **floats** at HEAD for now —
a `flake:` pin and an `ops upgrade` roll-forward are planned, not yet built. Note a flake build
runs under the cage's egress posture: a build step that fetches with its **own** client (e.g.
`bun install`) rather than through nix's fetcher may not honour the proxy / MITM CA under an
allowlist (for such a tool, prefer its release-binary `mise:` backend — that is exactly how
`kilocode` is equipped here, after its `flake:` source build hit this very wall).

**npm/node CLIs** are also supported: declare a `node` runtime (`nix:nodejs`) and the
tool via mise's npm backend (`mise:npm:<pkg>`). The cage synthesises `/usr/bin/env`, so
a tool's `#!/usr/bin/env node` shebang resolves (a hermetic cage has no host `/usr`).
`freebuff`, `cline`, and `droid` ship this way. They differ in how the binary arrives:
`freebuff`'s npm package is a thin launcher that downloads the real binary at first run into
the app's isolated home, while `cline` and `droid` deliver a self-contained native platform
binary through the npm package's optional dependencies (resolved at install, no separate
first-run download). Like `mise:`, an npm CLI fetches at first launch (the node runtime and
the package), so the first launch in a project needs the network.

**Offline trade-off:** a `mise:` tool **fetches at first launch** (the price of upstream
freshness), so a profile's *first* launch in a given project needs the network; a `nix:`
tool is seeded and reusable offline. With the default `home_scope = "global"` the tool's
install is shared across projects, but the per-project store means the fetch re-runs the
first time you launch the app **in each new project** — online everywhere, the first launch
per project not offline.

**Distribution hosts and the allowlist:** a `mise:` fetch must reach the tool's
distribution host, so the profile's `[network] allow` lists it. GitHub-distributed tools
(`codex`, `opencode`, `kilocode`) ride the built-in nix-cache allow-set (github / githubusercontent);
`claude-code` ships from a Google Cloud Storage bucket, so its profile path-scopes that one
bucket (not all of GCS). If a future release moves hosts, the proxy reports the refused host
— add it to `allow` (check ahead with `ops test net <url>`).

## Read by default — declare the write hosts

An **app is read-by-default**: every Mode-B agent's allow rules default to `{GET,HEAD}`, so a
host the agent only reads needs no annotation, while a host it **writes** to (an API it POSTs
completions to, an account it logs into, a package registry it installs from) must be opened to
all verbs with a `{*}` prefix — e.g. `"{*} https://api.anthropic.com"`. Pure download/catalog
hosts stay `"{GET,HEAD} https://models.dev"` (least privilege). This is why the shipped profiles
prefix their API/install hosts with `{*}` and their catalog hosts with `{GET,HEAD}`. (The bare
interactive `ops run`/`ops shell` — Mode A — is unaffected; it stays all-verbs.)

To change an app's default for *unscoped* rules, set `[network] default_methods` in the profile
(`["GET", "HEAD"]` is the built-in; `["*"]` opts the app out, back to all verbs; or a custom set
like `["GET", "POST"]`). A method filter bounds the upstream's verb semantics, **not** raw
exfiltration — a `GET` URL still carries data out; the host allowlist is the egress boundary.

## Adjusting the allowlist

If a tool's request is refused, the proxy reports the host it blocked — add it to
`allow` (and a write verb may need a `{*}`/`{POST}` prefix — an app is read-by-default). You can
check a URL's verdict ahead of time with `ops test net <url>` (or `--method POST`).

## Not here yet — and why

A profile needs three things: a **standalone CLI/TUI** (not a GUI app, not an editor
extension), a way to **package it in the hermetic cage**, and a **header-injectable BYOK
credential** — an API key supplied via an env var against an OpenAI-compatible or Anthropic
endpoint (**OpenRouter** is the universal one: one key, hundreds of models, `Authorization:
Bearer`). An OAuth/account login or a query-param key has no header for ops's `[secret]`
broker to strip-and-replace. The tools below were each researched against primary sources; we
do not guess the values, so each waits on a real fact or on a named feature:

- **OAuth-only credential** — **`agy`** (Antigravity CLI, Google) authenticates with **Google
  Sign-In / an OAuth token in the keyring** and exposes no env-var/API-key path. A header broker
  has nothing to inject, and the `freebuff`-style account-login posture does not fit either — it
  needs a browser/keyring, not a token file written under the isolated home. What would unblock
  it is an **interactive device-code login** (prints a URL + code you approve in your own
  browser; the token persists in the app's isolated `$HOME`, no in-cage browser) **plus**
  observing the tool's runtime API host before writing `allow`.

- **GUI / desktop agents — blocked on the Wayland passthrough** — **opencode desktop** and
  **t3 code** (`pingdotgg/t3code`, a web+Electron control plane that drives *other* agents,
  not a CLI), plus Antigravity *IDE* and hermes desktop. These are Electron/desktop apps that
  need a graphical display, which the headless cage does not bind yet. Their headless siblings
  are the path: the `opencode` **CLI** is already profiled; t3 code's targets are the CLIs it
  wraps (`codex`/`claude`/`opencode`), already here.

- **`aionui`** is the closest GUI candidate — it is an Electron app **but ships a genuine
  headless `--webui` HTTP-server mode** and is OpenRouter-keyable. It waits on two things:
  packaging an **Electron/AppImage app inside the hermetic cage** (unproven, heavy) and
  confirming it reads its key from an **env var** rather than only its GUI config (so the
  host-side injection has a request to act on). Filed as *deferred*, not refused.

For any other CLI agent: give the package (a `mise:`/`nix:`/`flake:` backend), the launch
command, the runtime API host(s), and the credential mechanism (an injectable **header** key,
not OAuth) and a profile can be added — nothing here is guessed.
