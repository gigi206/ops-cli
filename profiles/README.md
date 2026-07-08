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
| `opencode-web`    | `mise:opencode` (`opencode web` + `forward`) | provider-dependent |
| `opencode-desktop`| `flake:github:tomsch/opencode-desktop-nix#opencode-desktop` (Electron GUI, `gui = "wayland"`) | provider-dependent |
| `pi`              | `mise:aqua:earendil-works/pi`        | provider-dependent      |
| `hermes`          | `mise:pipx:hermes-agent` (+ `nix:uv`, `nix:python312`) | `openrouter.ai` (BYOK)  |
| `kilocode`        | `mise:github:Kilo-Org/kilocode`                  | provider-dependent      |
| `freebuff`        | `mise:npm:freebuff` (+ `nix:nodejs`)             | `www.codebuff.com` (account) |
| `cline`           | `mise:npm:cline` (+ `nix:nodejs`)                | `openrouter.ai` (BYOK)  |
| `droid`           | `mise:npm:droid` (+ `nix:nodejs`)                | `*.factory.ai` (account) |
| `agy`             | `mise:aqua:google-antigravity/antigravity-cli`  | `accounts.google.com` (Google OAuth) |

Each gets its own persistent, isolated `$HOME` (config, login, history), shared
across projects by default (`home_scope`).

> **Two credential postures.** Most profiles are **BYOK** — your provider key is read
> on the host and injected by the proxy, never entering the cage (see below).
> `freebuff` and `agy` are the other kind: they log in to a service **account** (a
> Codebuff account; a Google account, respectively) and the token persists in the app's
> isolated `$HOME` (so it *does* live in the — isolated — cage, never in the project
> shell). Both stay bounded by the egress allowlist. `agy` carries an extra unproven
> risk — it may want a **system keyring** the hermetic cage does not provide (see its
> profile header and the status note below).

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
> native platform binaries resolved through the empty-netns MITM allowlist, then `--version`),
> and `agy` (1.0.16, equipped via mise's **aqua** backend — the upstream GitHub release binary
> resolved through the empty-netns MITM allowlist, then `agy --version` and `agy --help`, which
> confirmed its headless `-p`/`--print` mode).
> The one remaining *live* end-to-end is
> the credential step: for the BYOK profiles, the CLI **authenticating** through the
> proxy-injected key (does the tool accept the placeholder and let the proxy fill in the real
> key?); for `freebuff`, completing its account **login** once inside the cage (the token then
> persists in the isolated home). Both are the flagship validation, still to be proven with a
> real key/account.
>
> `agy` is a special case of the account posture. Bringing it up surfaced a real **cage gap**,
> now fixed: `agy` starts an internal language server that binds `localhost`, and a hermetic cage
> had no `/etc/hosts`, so resolving the *name* `localhost` fell through to DNS the empty netns
> cannot answer — `agy` exited immediately (`CLI failed to start … lookup localhost … connection
> refused`). ops now synthesises an `/etc/hosts` mapping `localhost` (and the cage hostname) to
> loopback, so `agy` gets past language-server startup and reaches its **Google Sign-In** step —
> proven live (the process now blocks awaiting login instead of quitting). Two items remain,
> both needing a real Google account: whether the OAuth credential **persists** in the cage
> (Antigravity is documented to use the **system keyring** the hermetic cage lacks — it may or may
> not fall back to a token file under the isolated home), and the runtime **model-traffic host**
> (not captured without auth; the profile leaves a commented `*.googleapis.com` to narrow via
> `ops net logs -a agy`).
>
> `hermes` installs its published PyPI wheel with **uv** (mise's `pipx` backend over a `nix:uv`
> installer and `nix:python312`) — proven live in-cage under the profile's own allowlist
> (`hermes --version` → v0.18.0, ~60 wheels resolved in seconds; only the live-auth above is
> still pending). The `flake:` backend itself is proven separately on a reference flake.
>
> `opencode-web` and `opencode-desktop` are the two **graphical** ways to run opencode under ops,
> both proven live. `opencode-web` runs opencode's `web` server headless in the cage and exposes it
> to your host browser with `forward` (an inbound loopback hole) — proven end-to-end: opencode
> equipped via mise under the allowlist, `opencode web` serving on the cage's `127.0.0.1:4096`, and
> `curl http://127.0.0.1:4096/` from the host returning the UI (HTTP 200). No Electron, no in-cage
> build — the lightest graphical path.
>
> `opencode-desktop` is the native Electron app, packaged from the prebuilt `.deb` (the community
> `tomsch/opencode-desktop-nix` flake) so no bun/source build is needed, and displayed through
> `gui = "wayland"`. Proven live **under the allowlist**: version 1.17.15 built in-cage
> (`.deb` fetched from GitHub, autoPatchelf'd), the Electron window mapped and rendered on the
> Wayland compositor, and its HTTPS ran through the egress MITM because ops seeds its per-session
> CA into the cage's NSS database automatically for a `gui = "wayland"` cage under a filtering
> posture (Electron ignores the CA-file env vars other tools honour). `ops net logs` showed the
> model catalogue / gateway / plugin fetches allowed and the Sentry telemetry denied — egress
> filtered as intended. The remaining flagship step, as for every profile, is the live
> credential/auth with your own provider key.

## Tool freshness

Each profile declares its tool with a **backend-prefixed** `[packages]` value:

| Profile       | Declaration                                  | Source                         |
| ------------- | -------------------------------------------- | ------------------------------ |
| `claude-code` | `mise:aqua:anthropics/claude-code`           | Anthropic's standalone release |
| `codex`       | `mise:aqua:openai/codex`                      | OpenAI's GitHub release        |
| `opencode`    | `mise:opencode`                              | opencode's standalone release  |
| `opencode-web`| `mise:opencode`                              | opencode's standalone release (`opencode web`) |
| `opencode-desktop` | `flake:github:tomsch/opencode-desktop-nix#opencode-desktop` | opencode's prebuilt `.deb` (Electron), autoPatchelf'd in-cage |
| `pi`          | `mise:aqua:earendil-works/pi`                | Earendil's GitHub release      |
| `hermes`      | `mise:pipx:hermes-agent` (+ `nix:uv`, `nix:python312`) | NousResearch PyPI wheel (via uv) |
| `kilocode`    | `mise:github:Kilo-Org/kilocode`                  | Kilo Code's GitHub release binary  |
| `freebuff`    | `mise:npm:freebuff` (+ `nix:nodejs`)             | npm launcher → www.codebuff.com binary |
| `cline`       | `mise:npm:cline` (+ `nix:nodejs`)                | npm package → native platform binary |
| `droid`       | `mise:npm:droid` (+ `nix:nodejs`)                | npm package → native platform binary |
| `agy`         | `mise:aqua:google-antigravity/antigravity-cli`  | Antigravity's GitHub release binary (native) |

The `mise:` prefix means the tool is equipped **in-cage** from **upstream directly**
(mise's `aqua`/`github`/registry backends pull the real release binary, its `pipx` backend a
PyPI wheel via uv), so the version is the
**latest upstream** — not whatever nixpkgs has packaged. This sidesteps both the nixpkgs
lag and, for `claude-code`, the nixpkgs **unfree** gate (the standalone binary carries no
such restriction). The tool is equipped at the latest upstream version on the **first
launch in a project**; advancing an already-installed `mise:` version is **not yet
automated** by `ops upgrade` (a roll-forward for `[packages] mise:` is a planned increment)
— so a long-lived project store keeps its first-installed version until then.

A nixpkgs attribute is still available as `nix:<attr>` (provisioned host-side, seeded,
offline-reusable) — use it for stable substrate tools where freshness does not matter.

A third backend, **`flake:<ref>`**, packages a tool that ships **only as a nix flake** — no
single release binary and no nixpkgs attribute (e.g. a uv2nix Python agent). ops
builds the flake **in-cage** with `nix build` into the project's own store; the first launch
builds it (network + minutes — the build's own fetch hosts must be in `allow`), and later launches
reuse the warm build **offline**. Like `mise:`, the flake reference **floats** for now —
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

A profile needs three things: a **runnable agent** — a CLI/TUI, or a GUI/Electron app packaged
as described in the GUI bullet below (not an editor extension) — a way to **package it in the
hermetic cage**, and a **header-injectable BYOK credential** — an API key supplied via an env var against an OpenAI-compatible or Anthropic
endpoint (**OpenRouter** is the universal one: one key, hundreds of models, `Authorization:
Bearer`). An OAuth/account login or a query-param key has no header for ops's `[secret]`
broker to strip-and-replace. The tools below were each researched against primary sources; we
do not guess the values, so each waits on a real fact or on a named feature:

- **OAuth-only credential** — **`agy`** (Antigravity CLI, Google) authenticates with **Google
  Sign-In**, not a header-injectable key, so it ships as an **account** profile (above), not a
  BYOK one. It equips and runs headless (proven), and its Sign-In prints an authorization URL
  you complete in your own browser — no in-cage browser needed. The open caveat is credential
  persistence: Antigravity may want a **system keyring** the hermetic cage lacks (see the profile
  header + the status note). Its runtime model host is also not yet captured.

- **GUI / desktop (Electron) agents** — no longer blocked in general: `opencode-desktop` (above)
  is a working Electron profile, and it maps out the recipe for the next one. Three pieces make an
  Electron desktop app work in the cage: (1) **package it from its prebuilt `.deb`** with a flake
  that `autoPatchelfHook`s it (fetch via nix from GitHub — avoids the from-source `bun install`
  wall); (2) **`gui = "wayland"`** plus the Chromium flags (`--no-sandbox --ozone-platform=wayland
  --disable-gpu --use-system-ca`); (3) nothing extra for CA trust — ops **seeds its MITM CA into
  the cage's NSS db automatically** for a gui cage under a filtering posture (Chromium ignores the
  CA-file env vars other tools honour). Still
  waiting, each on a real fact: **t3 code** (`pingdotgg/t3code`, a web+Electron control plane that
  drives *other* agents — its targets `codex`/`claude`/`opencode` are already profiled as CLIs), the
  Antigravity *IDE* (distinct from the `agy` CLI, profiled above), and hermes desktop — each needs a
  prebuilt-`.deb`/flake package and a groundable credential, or is better served by its headless
  sibling (the `opencode`/`hermes` CLIs are profiled).

- **`aionui`** is the closest GUI candidate — it is an Electron app **but ships a genuine
  headless `--webui` HTTP-server mode** and is OpenRouter-keyable. It waits on two things:
  packaging an **Electron/AppImage app inside the hermetic cage** (unproven, heavy) and
  confirming it reads its key from an **env var** rather than only its GUI config (so the
  host-side injection has a request to act on). Filed as *deferred*, not refused.

For any other CLI agent: give the package (a `mise:`/`nix:`/`flake:` backend), the launch
command, the runtime API host(s), and the credential mechanism (an injectable **header** key,
not OAuth) and a profile can be added — nothing here is guessed.
