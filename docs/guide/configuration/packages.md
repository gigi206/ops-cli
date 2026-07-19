# `packages` — tools by backend

Tools to provision into the sandbox, declared as `name = "<backend>:<locator>"`.

```toml
[packages]
jq       = "nix:jq"
ripgrep  = "mise:aqua:BurntSushi/ripgrep"
myagent  = "flake:github:owner/repo#default"
```

The **name** is a free label — the merge key across layers and the on-disk root name.
The **value carries a mandatory backend prefix**. `packages` is a **security field**:
honored only from a trusted source (all three backends).

See also: [Provisioning](../concepts/provisioning.md) · [`[tools]` (mise)](tools.md) · [`sbx search`](../cli/search.md) · [`sbx upgrade`](../housekeeping/upgrade.md).

## The mandatory backend prefix

There is **no bare form**. A value with no recognized prefix is **dropped with a
warning** naming the fix — this is fail-closed, so a typo never silently mis-routes to
nix.

| Prefix | Where it is built | Freshness | Offline |
|---|---|---|---|
| `nix:<attribute>` | host-side, into the shared store | tracks the nixpkgs channel | yes (seeded, durable) |
| `mise:<token>` | in-cage, via `mise use -g` | upstream-direct, fetched at launch | first launch needs network |
| `flake:<ref>` | in-cage, via `nix build` | floats, or pinned by `sbx upgrade flake` | after a warm build |
| `deb:<url>` · `deb:github:…` · `deb:apt:…` · `deb:resolve` (+ `[deb.<name>]`) | host-side, from a prebuilt `.deb` | pin-on-first-use, rolled by `sbx upgrade deb` (the `resolve` form auto-discovers the newest version) | yes (seeded, durable) |
| `appimage:<url>` | host-side, from a prebuilt `.AppImage` | pin-on-first-use, rolled by `sbx upgrade appimage` | yes (seeded, durable) |
| `tarball:<url>` · `tarball:resolve` (+ `[tarball.<name>]`) | host-side, from a prebuilt `.tar.gz` | pin-on-first-use, rolled by `sbx upgrade tarball` (the `resolve` form auto-discovers the newest version) | yes (seeded, durable) |

### `nix:` — a nixpkgs attribute

```toml
[packages]
node = "nix:nodejs_20"
jq   = "nix:jq"
```

Provisioned **host-side** from the pinned nixpkgs channel into `sbx`'s store, its
`bin/` prepended to the cage `PATH`. Durable and offline-reusable (seeded into the
per-project store). Use [`sbx search <query>`](../cli/search.md) to find attribute
names. Advances with [`sbx upgrade nix`](../housekeeping/upgrade.md).

`mise:nix:<pkg>` routes to mise's nixhub resolver — a way to get a nix package with
mise's own version selection, not a third nix path.

### `mise:` — a mise backend

```toml
[packages]
codex = "mise:aqua:openai/codex"
tool  = "mise:npm:some-cli"
```

Equipped **in-cage** with `mise use -g <token>` at launch, fetched upstream-direct
(so it is fresher than nixpkgs but the first launch needs network). Any mise backend
works: `aqua:`, `github:`, `npm:`, `cargo:`, a plain registry token, etc. Advances
with [`sbx upgrade mise`](../housekeeping/upgrade.md).

Note: an `npm:` tool needs `/usr/bin/env` (the cage provides a synthetic one) and, if
it is pure JS, a node runtime — declare `nodejs = "nix:nodejs"` alongside it.

### `flake:` — a nix flake output

```toml
[packages]
agent = "flake:github:owner/repo#default"
```

Built **in-cage** with `nix build <ref>` into the project's own store, the out-link's
`bin/` prepended to `PATH`. A warm/offline second launch short-circuits. The flake ref
must carry an explicit scheme — **every local-source form is rejected**
(`path:`/`git+file:`, a leading `/`·`.`·`~`, the bare indirect `nixpkgs`) so a config
cannot aim the in-cage build at a host path. The first launch needs network **and**
the build's own fetch hosts in the [egress allowlist](../networking/rules.md). A flake
build step that fetches with its own HTTP client (e.g. `bun install`) rather than
nix's fetcher is blocked under a filtering posture — prefer a release binary via
`mise:github:` for such tools. Pins advance with
[`sbx upgrade flake`](../housekeeping/upgrade.md).

## `[flakes]` — an inline nix flake

When a tool ships **only** as a flake you author yourself — or you want to package a
one-off build without hosting a separate repo — write the whole `flake.nix` **inline** in a
`[flakes.<name>]` table instead of referencing an external `flake:<ref>`:

```toml
[flakes.mytool]
attr = "default"          # optional, the output to build (defaults to "default")
flake = '''
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }: {
    packages.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.hello;
  };
}
'''
```

sbx stages the source to a directory, binds it **read-only** into the cage, and builds
`path:<dir>#<attr>` **in-cage** — exactly the same containment as a `flake:` package, applied to
arbitrary inline build source. The out-link's `bin/` is prepended to `PATH`, and the out-link is
keyed by the source's **content hash**, so **editing the flake in the config rebuilds** at the next
launch while an unchanged flake reuses the warm build. It is folded into the same tool set as
`[packages]` (the name is the merge key), so a name declared in both `[packages]` and `[flakes]` is
a mistake — sbx warns and the inline flake wins.

A dedicated section (not a `[packages]` value) because a full `flake.nix` is a bulky multiline
string, and TOML forbids adding scalar keys to `[packages]` once one of its subtables is opened.

An inline flake **floats**: it has no persisted lock and no `sbx upgrade` path, so **pin the inputs
inside the `flake.nix`** (e.g. `nixpkgs.url = "github:NixOS/nixpkgs/<rev>"`) for a reproducible
build. Like `flake:`, the first build needs network **and** the build's own fetch hosts in the
[egress allowlist](../networking/rules.md). A security field, honored only from a trusted source.

### `deb:` — a prebuilt Debian package

```toml
[packages]
opencode-desktop = "deb:https://github.com/owner/repo/releases/latest/download/app-linux-amd64.deb"
```

For a GUI/desktop app distributed **only as a `.deb`** (no release binary, no nixpkgs
attribute, no buildable flake). sbx resolves the source to a concrete `.deb`, resolves that to a
content hash (pinned in a per-project `deb-packages.lock`), and builds a generated derivation that
`dpkg-deb -x`-unpacks the `.deb` and `autoPatchelfHook`s its Electron/Chromium binaries against a
curated library set — **host-side** (like `nix:`, seeded and offline-reusable), because a `.deb`
runs no build script so evaluating it host-side is safe. The build uses the **host** network (not
the cage allowlist), and `sbx upgrade deb` re-resolves each source forward.

Three source forms:

| Form | Tracks |
| --- | --- |
| `deb:<https url ending in .deb>` | a fixed `.deb`. A `…/releases/latest/download/…` URL rolls forward via its redirect; a version-stamped URL does not. |
| `deb:github:<owner>/<repo>` | the repo's newest GitHub release — sbx selects its linux `.deb` asset (so a version-embedding asset name still rolls). |
| `deb:apt:<https Packages-index url>` | an apt repository's newest `.deb` — sbx reads the uncompressed `Packages` index, picks the highest version, and derives its `.deb` URL. For a vendor pool with **no `latest` alias** (e.g. `claude-desktop`). |
| `deb:resolve` (+ `[deb.<name>]`) | a `resolve` **command** you supply that prints the newest `.deb` URL — for a vendor with a download **API** but no `latest`/apt form (e.g. `cursor`). See below. |

For `deb:github:` and `deb:apt:` the URL sbx derives from the remote index/release is
**re-validated** by the same `https://`-and-`.deb` charset check a hand-written `deb:` URL passes,
so a compromised index cannot inject a URL. `deb:apt:` reads the **uncompressed** `Packages` only,
does **no** `InRelease`/GPG signature check, and expects a **single-application** repo — the same
TLS-plus-unpack trust level as a direct `deb:` URL, not a general Debian mirror; its version order
is plain dotted-decimal (a non-numeric version is refused rather than mis-ordered).

Pairs with [`gui = "wayland"`](gui.md) for the display; sbx seeds its MITM CA into the cage's NSS
store so the Chromium app trusts a filtering posture's proxy.

**Auto-upgrade — `deb:resolve`.** When a vendor ships a version-stamped `.deb` URL with no
`…/latest/…` alias and no apt index (so `deb:<url>` would freeze and neither `deb:github:` nor
`deb:apt:` applies), pair a `deb:resolve` sentinel with a `[deb.<name>]` table carrying a `resolve`
**command** that prints the current `.deb` URL — sbx runs it on the first launch and on `sbx upgrade
deb` to roll forward. This is the exact `deb:` twin of [`tarball:resolve`](#tarball--a-prebuilt-application-tarball):

```toml
[packages]
cursor = "deb:resolve"

[deb.cursor]
# A command (argv) that prints the current `.deb` URL to stdout, and nothing else. Here: query the
# vendor download API and extract its `debUrl` field.
resolve = ["sh", "-c", "curl -fsSL 'https://www.cursor.com/api/download?platform=linux-x64&releaseTrack=stable' | sed -n 's/.*\"debUrl\":\"\\([^\"]*\\)\".*/\\1/p'"]
```

The `[packages]` entry stays the canonical tool list (the `deb:resolve` sentinel is the opt-in); the
`[deb.<name>]` table — keyed by the same package name — carries the command. sbx runs it **in a
hermetic sandbox** (its own base tools — `curl`/`coreutils`/`grep`/`sed`/`awk` — plus the app's own
`nix:` `[packages]`; the host network for the API, sbx's own CA bundle for TLS), captures the URL it
prints, **re-validates** it (`https://`, ending `.deb`, injection-free) before any fetch, and pins it
+ its content hash in `deb-packages.lock`. A warm launch reuses the pin offline and does **not** run
the command; `sbx upgrade deb` re-runs it and re-fetches the `.deb` only when the URL actually
changed. Because the command is arbitrary code it is honored **only from a trusted source** and
**never runs for an untrusted layer**.

### `appimage:` — a prebuilt AppImage

```toml
[packages]
t3code = "appimage:github:pingdotgg/t3code"
```

The sibling of `deb:`, for a GUI/desktop app distributed **only as an `.AppImage`**. sbx resolves
the URL to a content hash (pinned in a per-project `appimage-packages.lock`) and builds a generated
derivation that **extracts the AppImage's squashfs at build time** and `autoPatchelfHook`s its
Electron/Chromium binaries against the same curated library set — **host-side**, seeded and
offline-reusable. The AppImage is **never self-mounted at runtime**: `appimage-run`/`wrapType2`/the
raw AppImage all rely on a runtime FUSE/namespace mount that the cage's seccomp denylist blocks, so
build-time extraction is the only mechanism that runs in-cage. Two forms: a direct `https://` URL
ending in `.AppImage`, or `appimage:github:<owner>/<repo>` — which tracks the newest release's
linux `.AppImage` asset (so a version-embedding asset name still rolls forward). `sbx upgrade
appimage` re-resolves it. Pairs with [`gui = "wayland"`](gui.md), [`gpu = true`](gpu.md), and
[`dbus = true`](dbus.md) exactly like a `.deb` desktop app.

### `tarball:` — a prebuilt application tarball

```toml
[packages]
demo-app = "tarball:https://host/path/App.tar.gz"
```

The sibling of `deb:`/`appimage:`, for a GUI/desktop app distributed **only as a plain `.tar.gz`**
(no `.deb`, no `.AppImage`, no nixpkgs attribute, no official flake). sbx resolves the URL to a
content hash (pinned in a per-project `tarball-packages.lock`) and
builds a generated derivation that **`tar -xz`-extracts it at build time** and `autoPatchelfHook`s
its Electron/Chromium binaries against the same curated library set — **host-side**, seeded and
offline-reusable. Pairs with [`gui = "wayland"`](gui.md), [`gpu = true`](gpu.md), and
[`dbus = true`](dbus.md) exactly like a `.deb` desktop app.

Two forms:

- **Direct** — `tarball:https://host/path/App.tar.gz`, a URL ending in `.tar.gz` or `.tgz`. A
  version-stamped vendor URL does not roll forward on its own (the version is in the path); `sbx
  upgrade tarball` only re-resolves the same URL.
- **Auto-upgrade** — `tarball:resolve`, paired with a `[tarball.<name>]` table carrying a `resolve`
  **command** that prints the newest release's download URL, so `sbx upgrade tarball` can roll the app
  forward automatically (the direct form's version-stamped URL cannot). Use this when there is no
  stable "latest" download alias:

  ```toml
  [packages]
  demo-app = "tarball:resolve"

  [tarball.demo-app]
  # A command (argv) that prints the newest `.tar.gz` download URL to stdout, and nothing else.
  resolve = ["sh", "-c", "curl -fsS https://updates.example.com/releases | grep -oE 'https://[^\"]+\\.tar\\.gz' | head -1"]
  ```

  The `[packages]` entry stays the canonical tool list (the `tarball:resolve` sentinel is the opt-in);
  the `[tarball.<name>]` table — keyed by the same package name — carries the resolver command. On the
  first launch (and on `sbx upgrade tarball`) sbx runs that command **in a hermetic sandbox**, captures
  the URL it prints, validates it, and pins it + its content hash; a warm launch reuses the pin offline
  and does **not** run the command. An upgrade re-runs the command and re-fetches the tarball only when
  the URL actually changed — a no-op upgrade never re-downloads a large asset.

  The command works with **any** vendor's version-discovery shape (JSON, XML, a text file, a redirect —
  whatever your command can parse). It runs with sbx's own base tools on `PATH` (`curl`, `coreutils`,
  `grep`, `sed`, `awk` — never the host's, so a command is portable by construction) plus the app's own
  `nix:` `[packages]`, so if you need e.g. `jq`, declare `jq = "nix:jq"` and it is on the resolver's
  `PATH`. Because the command is arbitrary code it is honored **only from a trusted source** and **never
  runs for an untrusted layer**; it is sandboxed (no host filesystem, no secrets) and the URL it prints
  is re-validated (`https://`, ending `.tar.gz`/`.tgz`, injection-free) before any fetch. Its network is
  the **host network, not the app's `[network]` allowlist** — the same as the host-side tarball fetch
  the resolved URL then feeds; the allowlist governs the app's *runtime* egress, not this provisioning
  step.

## Why the tool sources are trusted-only

Loosening `packages` (or the inline `[flakes]`) to an untrusted project would let it override
a trusted app's tool and run attacker code under that app's posture — the same class of hole as
overriding a trusted app's command. So all six `[packages]` backends **and** inline `[flakes]`
are gated. A trusted app's tool **survives an untrusted project's override attempt** (the flagship
"agent on untrusted code" property). The open self-equip path stays [`sbx mise`](../cli/mise.md)
and a project's [`[tools]`](tools.md).

## `[packages]` vs `[tools]`

- `[packages]` is a **global, durable declaration** (`mise use -g`, `nix:` into the
  store, `flake:` build); `[flakes]` is its inline-source sibling. Both are trusted-only.
- [`[tools]`](tools.md) (a project mise file) is the **local, project-scoped**
  self-equip path (`mise install`), auto-equipped at launch under an open posture.

## Viewing the resolved set

```sh
sbx config show          # each package with its backend and gating
sbx config show --json   # machine-readable
```

## One-shot override

To add a package for a single launch without editing the file, use `--package
<name>=<backend:locator>` (repeatable) or `SBX_PACKAGE_<name>`:

```sh
sbx run --package jq=nix:jq -- ./tool
SBX_PACKAGE_ripgrep=mise:aqua:BurntSushi/ripgrep sbx run
```

The value carries the same mandatory backend prefix as the field
(`nix:`/`mise:`/`flake:`/`deb:`/`appimage:`). A one-shot package *adds* to whatever the config declares.
The command line beats the environment, and both beat the config file. See
[One-shot overrides](overrides.md).
