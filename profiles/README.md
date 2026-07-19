# App profiles

Importable launch profiles for `sbx app`. sbx ships **no built-in apps** — each
profile here is a separate, portable artifact you import deliberately:

```sh
sbx app import profiles/claude-code.toml   # a conscious trust act
sbx app claude-code                        # launch it, sandboxed
```

A profile is a standalone TOML file shaped as a top-level app (`cmd` plus the
tools, network posture, and credentials it needs). Imported profiles live under
`$XDG_CONFIG_HOME/sbx/apps/` and are trusted by location — honored even when the
project you launch in is untrusted (the point: run an agent *on* untrusted code,
safely). Manage them with `sbx app list` / `sbx app rm <name>`, and re-export one
with `sbx app export <name>`.

## What's here

| Profile           | Tool (fresh, upstream)               | Provider / egress       |
| ----------------- | ------------------------------------ | ----------------------- |
| `claude-code`     | `mise:aqua:anthropics/claude-code`   | `api.anthropic.com`     |
| `codex`           | `mise:aqua:openai/codex`             | `api.openai.com`        |
| `opencode`        | `mise:opencode`                      | provider-dependent      |
| `opencode-web`    | `mise:opencode` (`opencode web` + `forward`) | provider-dependent |
| `opencode-desktop`| `deb:` prebuilt `.deb` (Electron GUI, `gui = "wayland"`) | provider-dependent |
| `claude-desktop`  | `deb:` prebuilt `.deb` (Electron GUI, `gui = "wayland"`) | `api.anthropic.com` / `claude.ai` (account) |
| `pi`              | `mise:aqua:earendil-works/pi`        | provider-dependent      |
| `hermes`          | `flake:…/hermes-agent#default` (built in-cage) | `openrouter.ai` (BYOK) / Nous account |
| `vibe`            | `mise:pipx:mistral-vibe` (+ `nix:uv`, `nix:python312`, `nix:chromium`, `gui = "wayland"`) | `console.mistral.ai` (Mistral account SSO, in-cage browser) / `api.mistral.ai` (BYOK) |
| `kilocode`        | `mise:github:Kilo-Org/kilocode`                  | provider-dependent      |
| `freebuff`        | `mise:npm:freebuff` (+ `nix:nodejs`)             | `www.codebuff.com` (account) |
| `cline`           | `mise:npm:cline` (+ `nix:nodejs`)                | `openrouter.ai` (BYOK)  |
| `droid`           | `mise:npm:droid` (+ `nix:nodejs`)                | `*.factory.ai` (account) |
| `agy`             | `mise:aqua:google-antigravity/antigravity-cli`  | `accounts.google.com` (Google OAuth) |
| `antigravity-ide` | `tarball:resolve` prebuilt `.tar.gz` (Electron GUI IDE / VS Code fork, `gui`/`gpu`/`dbus`, auto-upgraded) | `cloudcode-pa.googleapis.com` (Google OAuth, in-cage browser) |
| `auggie`          | `mise:npm:@augmentcode/auggie` (+ `nix:nodejs`) | `*.api.augmentcode.com` (Augment account) |
| `cursor-agent`    | bootstrap `curl cursor.com/install` (CLI tarball — no clean backend; **not** the npm `cursor-agent`) | `*.cursor.sh` (Cursor account) |
| `cursor`          | `deb:` prebuilt `.deb` (Electron GUI editor, `gui`/`gpu`/`dbus`) | `*.cursor.sh` (Cursor account) |
| `t3code`          | `appimage:` prebuilt `.AppImage` (Electron GUI, `gui`/`gpu`/`dbus`) — a control plane driving other agents | **`network = "shared"`** (see note ‡) |
| `openfox`         | `mise:npm:openfox` (+ `nix:nodejs`) — a local-LLM web coding agent (browser UI) | **`network = "shared"`** (host-local LLM, see note ‡) |
| `goose`           | `mise:aqua:block/goose` (Rust release binary, no runtime deps) | provider-dependent (BYOK: OpenRouter / Anthropic / OpenAI — examples in profile) |
| `goose-desktop`   | `deb:` prebuilt `.deb` (Electron GUI, `gui`/`gpu`/`dbus`) — the same agent with a desktop UI | provider-dependent (GUI login or BYOK — examples in profile) |

Each gets its own persistent, isolated `$HOME` (config, login, history), shared
across projects by default (`home_scope`).

> **Two credential postures.** Most profiles are **BYOK** — your provider key is read
> on the host and injected by the proxy, never entering the cage (see below).
> `freebuff`, `agy`, `droid`, `auggie`, and `claude-desktop` are the other kind: they log in
> to a service **account** (a Codebuff account; a Google account; a Factory account; an Augment
> account; an Anthropic/claude.ai account or SSO, respectively) and the token persists in the
> app's isolated `$HOME` (so it *does* live in the — isolated — cage, never in the project
> shell). All stay bounded by the egress allowlist. `agy` and `claude-desktop` carry an extra
> unproven risk — they may want a **system keyring** the hermetic cage does not provide (see each
> profile header and the status note below). `auggie` has a cleaner headless path: pass a
> host-minted session token for one launch with `--env AUGMENT_SESSION_AUTH=…` (never baked into
> the profile), sidestepping the in-cage OAuth loopback-callback that the empty netns would break.

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
> refused`). sbx now synthesises an `/etc/hosts` mapping `localhost` (and the cage hostname) to
> loopback, so `agy` gets past language-server startup and reaches its **Google Sign-In** step —
> proven live (the process now blocks awaiting login instead of quitting). Two items remain,
> both needing a real Google account: whether the OAuth credential **persists** in the cage
> (Antigravity is documented to use the **system keyring** the hermetic cage lacks — it may or may
> not fall back to a token file under the isolated home), and the runtime **model-traffic host**
> (not captured without auth; the profile leaves a commented `*.googleapis.com` to narrow via
> `sbx net logs -a agy`).
>
> `cursor-agent` (Cursor's headless terminal agent — **not** the Cursor desktop editor, which is a
> separate GUI increment) is the one profile packaged by a **bootstrap download** rather than a clean
> backend: Cursor ships the CLI only as a versioned tarball from `downloads.cursor.com` (no nixpkgs
> attr, no GitHub release, and the npm `cursor-agent` is an unrelated third-party package), so the
> `cmd` runs Cursor's own `curl cursor.com/install | bash` **inside the cage** on first launch (the
> installer needs `tar`+`gzip`, provisioned as `nix:` packages; the un-patchelf'd binary runs under
> the cage's `nix-ld` shim). It is an **account** profile — a Cursor account API key (from
> cursor.com/dashboard/api), injected per launch with `sbx app cursor-agent --env CURSOR_API_KEY=…`
> (never baked in), or the interactive `cursor-agent login`. Egress is a least-privilege allowlist
> on `*.cursor.sh` (Cursor's own recommended wildcard). **Its unverified set is unusually large** —
> import + resolve are covered by the shipped-profiles test, but the packaging (bootstrap + nix-ld
> binary), the proxy-honoring, the transport through sbx's MITM, and the auth are **all** still to be
> proven with a real Cursor account. On transport: the profile designates Cursor's HTTP/2-only
> indexing host `repo42.cursor.sh` in `[network] http2` (so the proxy speaks h2/gRPC to it rather than
> failing it), and the dual-stack agent hosts fall back to HTTP/1.1 SSE — but this rides sbx's own
> brand-new h2/gRPC MITM, itself unproven for Cursor, and Cursor recommends against SSL inspection on
> its domains, so it is a live-pending claim, not a proven one. If the agent misbehaves under the
> allowlist, the profile header documents the `network = "shared"` fallback (like `t3code`) and the
> exact failure signatures to read from `sbx net logs -a cursor-agent`.
>
> `cursor` (the Cursor desktop **editor** — the GUI sibling of `cursor-agent`) is an Electron
> profile in the `opencode-desktop` / `claude-desktop` mould: packaged from Cursor's prebuilt `.deb`
> via the `deb:` backend (autoPatchelf'd host-side), displayed with `gui = "wayland"` + `gpu` +
> `dbus`, egress on `*.cursor.sh`. Two caveats specific to it: the `.deb` URL is **version-pinned**
> (Cursor has no `…/latest/…` URL or apt index — bump it from the download API, see the profile
> header), and the **account login** is the open question — the editor signs in through a web flow +
> a `cursor://` deep-link that does not complete in the cage out of the box (the header documents a
> one-time `--net shared` login and the heavier in-cage-browser recipe, but Cursor's exact flow is
> not fabricated here). Like every desktop profile it imports + resolves (test-covered); the
> autoPatchelf of a large VS Code-fork app, the display bring-up, the filtered model traffic, and the
> login are all still to be proven live.
>
> `auggie` (Augment Code's CLI, `@augmentcode/auggie`) is an **account** profile like the above:
> it routes model traffic through Augment's per-user tenant backend (`<tenant>.api.augmentcode.com`,
> covered by the `*.api.augmentcode.com` subdomain wildcard) and authenticates to your Augment
> account, so there is no header-injectable BYOK key. It **imports and resolves** cleanly (allowlist
> verified; the tenant wildcard and the `{GET}`-only npm registry confirmed with `sbx test net`), but
> — like every profile — the **live equip/run and auth** are still to be proven with a real account.
> The recommended credential path is headless: on the host `auggie login` then `auggie token print`,
> and inject the session JSON for one caged launch with
> `sbx app auggie --env AUGMENT_SESSION_AUTH="$(auggie token print)"`. Auggie is a **pure-node** CLI
> (unlike the native-binary `cline`/`droid`), so it needs the `nix:nodejs` runtime at run time, not
> only to install.
>
> The three `hermes` profiles (`hermes` CLI, `hermes-web`, `hermes-desktop`) build the tool from its
> **nix flake** — `flake:github:NousResearch/hermes-agent#default` for the CLI and web dashboard,
> `#desktop` for the Electron app — so `sbx upgrade flake` rolls them. The flake output bundles the
> Python agent (uv2nix), the node TUI/web front-ends, and every extra in one self-wiring package
> (it sets `HERMES_NODE`/`HERMES_TUI_DIR`/`HERMES_WEB_DIST`, and `#desktop` wires the Python backend
> via `HERMES_DESKTOP_HERMES`). Cost: a multi-minute, ~2 GiB in-cage `nix build` on the first launch
> (its PyPI + npm source fetches ride each profile's allowlist), warm and offline after. **These
> flake migrations are live-pending** — the config resolves (covered by the shipped-profiles test),
> but the heavy in-cage build + a real dashboard/desktop run are the standing live validation.
>
> `opencode-web` and `opencode-desktop` are the two **graphical** ways to run opencode under sbx,
> both proven live. `opencode-web` runs opencode's `web` server headless in the cage and exposes it
> to your host browser with `forward` (an inbound loopback hole) — proven end-to-end: opencode
> equipped via mise under the allowlist, `opencode web` serving on the cage's `127.0.0.1:4096`, and
> `curl http://127.0.0.1:4096/` from the host returning the UI (HTTP 200). No Electron, no in-cage
> build — the lightest graphical path.
>
> `opencode-desktop` is the native Electron app, packaged from opencode's prebuilt `.deb` via sbx's
> **`deb:` backend** (no third-party flake, no bun/source build) and displayed through
> `gui = "wayland"`. Proven live **under the allowlist**: version 1.17.15 provisioned host-side
> (the `.deb` fetched from GitHub, resolved to a pinned hash, and autoPatchelf'd), the Electron
> window mapped and rendered on the Wayland compositor, and its HTTPS ran through the egress MITM
> because sbx seeds its per-session CA into the cage's NSS database automatically for a
> `gui = "wayland"` cage under a filtering posture (Electron ignores the CA-file env vars other
> tools honour). `sbx net logs` showed the model catalogue / gateway / plugin fetches allowed and
> the Sentry telemetry denied — egress filtered as intended. `sbx upgrade deb` rolls it forward
> (re-resolving the `…/releases/latest/…` URL). The remaining flagship step, as for every profile,
> is the live credential/auth with your own provider key.

## Tool freshness

Each profile declares its tool with a **backend-prefixed** `[packages]` value:

| Profile       | Declaration                                  | Source                         |
| ------------- | -------------------------------------------- | ------------------------------ |
| `claude-code` | `mise:aqua:anthropics/claude-code`           | Anthropic's standalone release |
| `codex`       | `mise:aqua:openai/codex`                      | OpenAI's GitHub release        |
| `opencode`    | `mise:opencode`                              | opencode's standalone release  |
| `opencode-web`| `mise:opencode`                              | opencode's standalone release (`opencode web`) |
| `opencode-desktop` | `deb:…/releases/latest/download/opencode-desktop-linux-amd64.deb` | opencode's prebuilt `.deb` (Electron), autoPatchelf'd host-side |
| `claude-desktop` | `deb:apt:…/apt/stable/dists/stable/main/binary-amd64/Packages` | Anthropic's official prebuilt `.deb` (Electron), autoPatchelf'd host-side — tracks the apt index's newest version (`sbx upgrade deb`) |
| `pi`          | `mise:aqua:earendil-works/pi`                | Earendil's GitHub release      |
| `hermes`      | `flake:github:NousResearch/hermes-agent#default` | NousResearch flake (uv2nix + node front-ends), built in-cage |
| `vibe`        | `mise:pipx:mistral-vibe` (+ `nix:uv`, `nix:python312`) | Mistral PyPI wheel (via uv) |
| `kilocode`    | `mise:github:Kilo-Org/kilocode`                  | Kilo Code's GitHub release binary  |
| `freebuff`    | `mise:npm:freebuff` (+ `nix:nodejs`)             | npm launcher → www.codebuff.com binary |
| `cline`       | `mise:npm:cline` (+ `nix:nodejs`)                | npm package → native platform binary |
| `droid`       | `mise:npm:droid` (+ `nix:nodejs`)                | npm package → native platform binary |
| `agy`         | `mise:aqua:google-antigravity/antigravity-cli`  | Antigravity's GitHub release binary (native) |
| `antigravity-ide` | `tarball:resolve` (+ `[tarball.antigravity-ide]`) | Google's official IDE `.tar.gz` from `edgedl.me.gvt1.com` (Electron / VS Code fork), autoPatchelf'd host-side — auto-upgraded via a sandboxed resolve command over Google's version API (`sbx upgrade tarball`) |
| `auggie`      | `mise:npm:@augmentcode/auggie` (+ `nix:nodejs`) | Augment Code npm package (pure-node CLI, node at runtime) |
| `cursor-agent`| bootstrap installer (`curl cursor.com/install`)  | Cursor's own tarball (`downloads.cursor.com`), no npm/nixpkgs/GitHub package |
| `cursor`      | `deb:…/cursor_<ver>_amd64.deb` (version-pinned)  | Cursor's prebuilt `.deb` (Electron), autoPatchelf'd host-side |
| `openfox`     | `mise:npm:openfox` (+ `nix:nodejs`) | OpenFox npm package (pure-node web agent, node at runtime) |
| `goose`       | `mise:aqua:block/goose`                | Block's GitHub release binary (Rust, self-contained, GitHub artifact attestations verified via Sigstore) |
| `goose-desktop` | `deb:…/releases/download/v1.43.0/goose_1.43.0_amd64.deb` | Block's prebuilt `.deb` (Electron + embedded Rust CLI), autoPatchelf'd host-side — hand-pinned (versioned filename, no `latest` alias) |

The `mise:` prefix means the tool is equipped **in-cage** from **upstream directly**
(mise's `aqua`/`github`/registry backends pull the real release binary, its `pipx` backend a
PyPI wheel via uv), so the version is the
**latest upstream** — not whatever nixpkgs has packaged. This sidesteps both the nixpkgs
lag and, for `claude-code`, the nixpkgs **unfree** gate (the standalone binary carries no
such restriction). The tool is equipped at the latest upstream version on the **first
launch in a project**; advancing an already-installed `mise:` version is **not yet
automated** by `sbx upgrade` (a roll-forward for `[packages] mise:` is a planned increment)
— so a long-lived project store keeps its first-installed version until then.

A nixpkgs attribute is still available as `nix:<attr>` (provisioned host-side, seeded,
offline-reusable) — use it for stable substrate tools where freshness does not matter.

A third backend, **`flake:<ref>`**, packages a tool that ships **only as a nix flake** — no
single release binary and no nixpkgs attribute (e.g. a uv2nix Python agent). sbx
builds the flake **in-cage** with `nix build` into the project's own store; the first launch
builds it (network + minutes — the build's own fetch hosts must be in `allow`), and later launches
reuse the warm build **offline**. Like `mise:`, the flake reference **floats** for now —
a `flake:` pin and an `sbx upgrade` roll-forward are planned, not yet built. Note a flake build
runs under the cage's egress posture: a build step that fetches with its **own** client (e.g.
`bun install`) rather than through nix's fetcher may not honour the proxy / MITM CA under an
allowlist (for such a tool, prefer its release-binary `mise:` backend — that is exactly how
`kilocode` is equipped here, after its `flake:` source build hit this very wall).

When the flake is one you author yourself, write the whole `flake.nix` **inline** in a
`[flakes.<name>]` table instead of hosting a separate repo — same in-cage build and read-only
staging as `flake:`, but the out-link is keyed by the source's content hash, so editing the flake
in the profile rebuilds. See [inline flakes](../docs/guide/configuration/packages.md). An inline
flake floats, so pin its inputs inside the `flake.nix`.

A fourth backend, **`deb:<url>`**, packages a GUI/desktop app distributed **only as a prebuilt
`.deb`** (no release binary, no nixpkgs attribute, and — for opencode-desktop — an official flake
whose from-source build is broken). sbx fetches the `.deb`, resolves it to a content hash (pinned
in a per-project `deb-packages.lock`), and builds a generated derivation that `dpkg-deb -x`-unpacks
it and `autoPatchelfHook`s the Electron binaries against a curated library set — **host-side**
(like `nix:`, seeded and offline-reusable), because a `.deb` runs no build script so evaluating it
host-side is safe. A `…/releases/latest/download/…` URL tracks upstream and `sbx upgrade deb`
re-resolves it forward. `opencode-desktop` ships this way. (Its build needs your host network at
first launch, not the cage allowlist; only the app's *runtime* egress is filtered.)

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
— add it to `allow` (check ahead with `sbx test net <url>`).

## Read by default — declare the write hosts

An **app is read-by-default**: every Mode-B agent's allow rules default to `{GET,HEAD}`, so a
host the agent only reads needs no annotation, while a host it **writes** to (an API it POSTs
completions to, an account it logs into, a package registry it installs from) must be opened to
all verbs with a `{*}` prefix — e.g. `"{*} https://api.anthropic.com"`. Pure download/catalog
hosts stay `"{GET,HEAD} https://models.dev"` (least privilege). This is why the shipped profiles
prefix their API/install hosts with `{*}` and their catalog hosts with `{GET,HEAD}`. (The bare
interactive `sbx run` — Mode A — is unaffected; it stays all-verbs.)

To change an app's default for *unscoped* rules, set `[network] default_methods` in the profile
(`["GET", "HEAD"]` is the built-in; `["*"]` opts the app out, back to all verbs; or a custom set
like `["GET", "POST"]`). A method filter bounds the upstream's verb semantics, **not** raw
exfiltration — a `GET` URL still carries data out; the host allowlist is the egress boundary.

## Adjusting the allowlist

If a tool's request is refused, the proxy reports the host it blocked — add it to
`allow` (and a write verb may need a `{*}`/`{POST}` prefix — an app is read-by-default). You can
check a URL's verdict ahead of time with `sbx test net <url>` (or `--method POST`).

## Not here yet — and why

A profile needs three things: a **runnable agent** — a CLI/TUI, or a GUI/Electron app packaged
as described in the GUI bullet below (not an editor extension) — a way to **package it in the
hermetic cage**, and a **header-injectable BYOK credential** — an API key supplied via an env var against an OpenAI-compatible or Anthropic
endpoint (**OpenRouter** is the universal one: one key, hundreds of models, `Authorization:
Bearer`). An OAuth/account login or a query-param key has no header for sbx's `[secret]`
broker to strip-and-replace. The tools below were each researched against primary sources; we
do not guess the values, so each waits on a real fact or on a named feature:

- **OAuth-only credential** — **`agy`** (Antigravity CLI, Google) authenticates with **Google
  Sign-In**, not a header-injectable key, so it ships as an **account** profile (above), not a
  BYOK one. It equips and runs headless (proven), and its Sign-In prints an authorization URL
  you complete in your own browser — no in-cage browser needed. The open caveat is credential
  persistence: Antigravity may want a **system keyring** the hermetic cage lacks (see the profile
  header + the status note). Its runtime model host is also not yet captured.

- **GUI / desktop (Electron) agents** — no longer blocked in general: `opencode-desktop`,
  `claude-desktop`, and `t3code` (above) are working Electron profiles, and they map out the recipe
  for the next one. Three pieces make an Electron desktop app work in the cage: (1) **package it from
  its prebuilt binary** — the `deb:<url>` / `deb:github:<owner>/<repo>` backend for a `.deb`, or the
  `appimage:<url>` / `appimage:github:<owner>/<repo>` backend for an `.AppImage` (sbx fetches, hashes,
  and `autoPatchelfHook`s it host-side — avoids the from-source `bun install` wall and any third-party
  flake; an AppImage is extracted at build time, never self-mounted, since the runtime FUSE mount is
  seccomp-blocked); (2) **`gui = "wayland"`** (usually with `gpu = true` and `dbus = true`) plus the
  Chromium flags (`--no-sandbox --ozone-platform=wayland --use-system-ca`); (3) nothing extra for CA
  trust — sbx **seeds its MITM CA into the cage's NSS db automatically** for a gui cage under a
  filtering posture (Chromium ignores the CA-file env vars other tools honour). **`t3code`** — a
  control plane driving *other* agents (`codex`/`claude`/`opencode`, already profiled as CLIs) — is
  the AppImage-backend flagship: it packages, imports, resolves, renders + logs in, and its build seam
  is proven through `sbx run` (the launcher lands on the cage PATH). **‡ It is one of two shipped
  profiles that ship `network = "shared"` and cannot filter egress** (the other, `openfox`, does so for
  an unrelated reason — to reach a LLM on the host's `localhost`, which the empty netns cannot; see its
  header) — t3code's model traffic is made by a SEPARATE,
  proxy-blind Node backend (`ELECTRON_RUN_AS_NODE`, Effect's undici with its own Agent) that no
  profile-level mechanism can route through the egress proxy: proxychains' `LD_PRELOAD` breaks
  Chromium's renderer (spiked 1-vs-0 rendered docs), Electron strips `NODE_OPTIONS` so a preload never
  reaches the backend, and a transparent redirect is an sbx-sized feature (a Chromium-safe LD_PRELOAD
  connect-shim, or a cap-free loopback-DNS + SNI-relay interceptor), not a profile knob. So t3code keeps
  bwrap + seccomp + the isolated home + the minimal `/dev`, but reaches the host network unfiltered —
  the honest posture for an Electron app whose backend is proxy-blind. The Antigravity *IDE* (distinct
  from the `agy` CLI, profiled above) now **ships** as `antigravity-ide` — packaged from Google's
  official `.tar.gz` via the `tarball:resolve` backend (auto-upgraded through a sandboxed resolve command),
  with the `gui`/`gpu`/`dbus` holes and the Google Sign-In in-cage-browser flow; its real build + login
  is the pending live-gate like every GUI profile. Still waiting on a real fact: hermes desktop — it
  needs a prebuilt package and a groundable credential, or is better served by its headless sibling
  (the `hermes` CLI is profiled).

- **`aionui`** is the closest GUI candidate — it is an Electron app **but ships a genuine
  headless `--webui` HTTP-server mode** and is OpenRouter-keyable. It waits on two things:
  packaging an **Electron/AppImage app inside the hermetic cage** (unproven, heavy) and
  confirming it reads its key from an **env var** rather than only its GUI config (so the
  host-side injection has a request to act on). Filed as *deferred*, not refused.

For any other CLI agent: give the package (a `mise:`/`nix:`/`flake:` backend), the launch
command, the runtime API host(s), and the credential mechanism (an injectable **header** key,
not OAuth) and a profile can be added — nothing here is guessed.
