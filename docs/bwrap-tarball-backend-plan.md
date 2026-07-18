# `tarball:` package backend + the Antigravity IDE v2 profile — design plan

> Status: **PLAN, awaiting user validation.** No code written yet. This document is the
> deliverable of the "plan-first" decision. Two user constraints are load-bearing and drive
> the whole design: **(1) the binary source must be OFFICIAL** (Google's own CDN — a
> third-party community flake is banned as a source, inspiration for technique only, see the
> memory `profile-official-sources-only`); **(2) `sbx upgrade` must work** (roll forward to
> the newest official version automatically).

## 1. Why a new backend is unavoidable

The user wants the **Antigravity IDE v2** desktop app (Google's agentic IDE, a VS Code /
Windsurf fork — an Electron desktop app), *not* the older 1.x.

Grounded facts (verified against Google's own endpoints, July 2026):

- The official **v2** IDE for Linux ships **only as a `.tar.gz` tarball** from Google's Edge
  download CDN. There is **no** official v2 `.deb`, no official v2 AppImage, no nixpkgs attr
  reachable under sbx's unfree-gated `nix:` path.
  - x86_64: `https://edgedl.me.gvt1.com/edgedl/release2/j0qc3/antigravity/stable/2.1.1-6123990880747520/linux-x64/Antigravity%20IDE.tar.gz`
  - host `edgedl.me.gvt1.com` = Google's official Edge download infrastructure (`gvt1.com`,
    the same CDN Chrome ships from).
- The official **v1** IDE is in Google's apt repo (`us-central1-apt.pkg.dev/projects/
  antigravity-auto-updater-dev`, package `antigravity`, `Maintainer: Google, LLC`, an Electron
  editor — confirmed by its GTK/NSS/gbm dependency set + 690 MiB install size) but is **frozen
  at 1.23.2**. Rejected by the user (wants v2).

sbx's existing backends are `nix:` / `mise:` / `flake:` / `deb:` / `deb:apt:` / `appimage:`.
**None consumes a `.tar.gz`.** And there is no shortcut:

- A `cmd` that extracts the tarball in-cage **fails**: the Electron binaries need
  `autoPatchelfHook` against the nix closure to run in the hermetic cage (no host `/usr`,
  wrong loader/glibc). That autoPatchelf is exactly what `deb:`/`appimage:` do and a raw
  extract cannot.
- `nix:google-antigravity-ide` does **not** satisfy "official only": nixpkgs lags the tarball,
  and — the strong reason — a **nixpkgs derivation is itself a third-party repackaging**
  (community-authored derivation over the same gvt1 fetch), so it fails the user's rule for the
  *same* reason the community flake does. (The unfree gate is only a secondary obstacle.)
  `mise:http` can extract but not autoPatchelf → the Electron binaries won't run in the cage.
  Google publishes no official flake.

**Conclusion: add a 6th `[packages]` backend, `tarball:`**, that fetches the official
Google tarball, resolves+pins a hash, extracts (`tar xzf`), autoPatchelfs the Electron
binaries, and wraps the launcher — reusing the `deb:`/`appimage:`/`prebuilt.rs` machinery.
sbx is the trusted packager; the *artifact* stays official.

## 2. The upgrade mechanism (the hard requirement)

The download URL is **version-stamped** (`.../stable/2.1.1-6123990880747520/...`), so there is
**no stable "latest" alias** to re-resolve — a bare direct URL would be frozen. The official
upgrade path is a Google **auto-updater manifest API**, verified live:

```
GET https://antigravity-ide-auto-updater-974169037036.us-central1.run.app/releases
→ [{"version":"2.1.1","execution_id":"6123990880747520"},
   {"version":"2.0.4","execution_id":"6381998290370560"}, ...]   # newest at index [0]
```

The download URL is then **templated** from `[0]`:

```
https://edgedl.me.gvt1.com/edgedl/release2/j0qc3/antigravity/stable/{version}-{execution_id}/linux-x64/Antigravity%20IDE.tar.gz
```

This is structurally the **`deb:apt:` pattern**: query an official index → pick newest → pin
per project → `sbx upgrade` re-reads and rolls forward. So the backend gets **two forms**:

### Form 1 — direct (no version discovery)
```
tarball:<https-url>
```
Pin URL+hash. `sbx upgrade tarball` re-prefetches the same URL. For a version-stamped URL this
is effectively frozen (honest: only rolls if the URL is itself a "latest" alias). **Not used by
the Antigravity profile** — kept because it is the trivial base case and mirrors bare `deb:<url>`.

### Form 2 — manifest (auto-upgrade) — **used by the profile, satisfies the requirement**
```
tarball:manifest:<api-url>#<url-template>
```
- **Resolve**: `GET <api-url>` (host-side), parse a top-level JSON **array**, take element
  **`[0]`** (newest), substitute each `{key}` placeholder in `<url-template>` with `[0].key`,
  prefetch the constructed URL → SRI hash, pin `(constructed-url, hash, version-tag)`.
- **Upgrade** (`sbx upgrade tarball`): re-`GET` the API, recompute `[0]`'s version-tag; if it
  differs from the lock, re-pin (rebuild at the next launch — the lock rewrite IS the roll,
  exactly like `deb:apt:`).
- The Antigravity profile value:
  ```
  antigravity-ide = "tarball:manifest:https://antigravity-ide-auto-updater-974169037036.us-central1.run.app/releases#https://edgedl.me.gvt1.com/edgedl/release2/j0qc3/antigravity/stable/{version}-{execution_id}/linux-x64/Antigravity%20IDE.tar.gz"
  ```

**Why the template lives in the profile (data), not the backend (code):** the API→URL mapping
is app-specific; keeping it in the profile keeps the backend generic (any auto-updater with a
JSON-array manifest + a templated download URL works), exactly as `deb:apt:<index-url>` keeps
the app-specific index URL in the profile.

> **OPEN DESIGN QUESTION (for the human reviewer — not settled).** Form 2 introduces a generic
> placeholder-substitution mini-language (`{version}`/`{execution_id}` → JSON `[0].key`) for
> **exactly one** consumer today. That is speculative generality of the kind the project usually
> cuts. Three candidate shapes, pick one:
> - **(a) the generic `#template` string** (above) — most reuse, most machinery;
> - **(b) an app-specific manifest resolver keyed by a token** (e.g. `tarball:antigravity-ide`)
>   — the API+template hardcoded in the backend; smallest surface, but the first app-specific
>   backend in sbx (a design break);
> - **(c) a `[tarball.<name>]` config table** carrying `manifest`/`template`/`binary` — explicit,
>   but breaks the uniform `name = "backend:locator"` string model.
> My lean is (a) for parity with `deb:apt:`, but this is the one part of the plan I'd want you to
> rule on before I build increment 2.

**Separator:** `#` splits api-url from template (neither URL carries a fragment; the template's
only literal space is already `%20`-encoded).

### Upgrade security (load-bearing — the API response is the only untrusted input)
The api-url + template come from a **trusted** profile (`[packages]` is trusted-only; an
untrusted project cannot set them). The only untrusted data is the **API response**, so the
resolver must fail-closed on a hostile/compromised manifest:
- Each substituted `{key}` value must match a strict charset `[A-Za-z0-9._-]+` (no `/`, no
  `..`, no space, no control) — so it cannot alter the URL's host/path structure.
- The final constructed URL must pass `is_valid_tarball_url` (https, injection-free charset).
- The template's literal prefix fixes the host (`edgedl.me.gvt1.com`); placeholders only fill
  the version segment. A manifest that tries to redirect the host cannot (the host is literal).
- JSON-shape assumption (top-level array, newest at `[0]`, string fields) documented; a
  differently-shaped manifest simply does not match this form (fail-closed, warned).

### Runtime self-update note
The IDE (like the CLI) has an in-app updater that hits the same `run.app` + gvt1 CDN. In-cage,
a self-downloaded binary is **not** autoPatchelf'd → cannot run, so the in-app updater is inert
(same caveat as the CLI's background updater). **`sbx upgrade tarball` is the real upgrade
path** — a clean story: sbx owns the version. The updater's hosts can be muted (or allowed
harmlessly); the pinned build is what actually runs.

## 3. The derivation (extract → autoPatchelf → wrap), host-side

Mirrors `deb.rs::derivation_expr`, swapping only the extract step:

- **Fetch** `src = fetchurl { url; sha256 = <pinned SRI>; }` (nix's fetcher, host network).
- **Extract** `tar xzf "$src"` (vs deb's `dpkg-deb -x`, appimage's `unsquashfs`) into `$out`.
  The IDE tarball extracts to a VS Code-fork layout: the launcher `antigravity-ide` beside
  `resources/` (launcher name grounded from the official layout).
- **autoPatchelfHook** against `prebuilt::ELECTRON_LIBS` (the curated set already used by
  `deb:`/`appimage:`). Compare against the official dependency set (§ below) and add any
  missing lib (candidates seen in the official closure: `libsecret`, `vulkan-loader`,
  `libxkbfile`, `gsettings-desktop-schemas`) to `ELECTRON_LIBS` **once** — benefiting every
  Electron backend. `autoPatchelfIgnoreMissingDeps = [ "libc.musl-x86_64.so.1" ]` as in deb.
- **Setuid strip on `chrome-sandbox`** (reuse deb's non-`--preserve-permissions` `tar` copy):
  an unprivileged nix builder cannot set the setuid bit, and `--no-sandbox` in the profile
  means chrome-sandbox is never used (bwrap + seccomp + empty netns IS the boundary).
- **Wrap** the launcher. **CONFIRMED by the spike (§ Increment 0): the tarball is asar-LESS**
  — top-level dir `Antigravity IDE/` (note the space), launcher `Antigravity IDE/antigravity-ide`,
  and `resources/app/` unpacked (16028 files), **no `resources/app.asar`**. So
  `prebuilt::ELECTRON_WRAP` (which finds `*/resources/app.asar`) would **not** locate it as-is
  → the backend must generalize the wrap to also match an unpacked `resources/app/` (or wrap the
  known launcher directly). Small, shared, benefits deb too. The launcher `antigravity-ide` is
  the anchor.
- Built **host-side** (a tarball runs no maintainer script → safe to evaluate host-side, like
  `deb:`/`appimage:`), seeded into the store, offline-reusable after first launch.

## 4. Shared-machinery refactor (DRY)

`deb.rs`, `appimage.rs`, and the new `tarball.rs` differ only in the **extract** step; the
**autoPatchelf + setuid-strip + wrap** tail is identical. Extract that tail into `prebuilt.rs`
as a helper (`electron_install_and_wrap(extract_cmd, name, ...) -> String` producing the shared
derivation body), and have all three backends call it with their own extract command
(`dpkg-deb -x` / `unsquashfs` / `tar xzf`). Behaviour-preserving for deb/appimage (guarded by
their existing tests). Keeps the tarball backend small (~200–300 lines: parse, resolve/manifest,
lock, provision, upgrade — the derivation body is shared).

## 5. Config + CLI wiring

- `config/mod.rs`: `Backend::Tarball(String)` variant; `parse_backend` recognizes `tarball:`
  and, within it, the `manifest:` sub-form (split on `#`); `is_valid_tarball_url` (https +
  injection-free) and template validation (placeholder charset, `#` present for manifest form).
  Trusted-only like every backend; `protect_trusted` covers it for free (a trusted app's tarball
  package survives an untrusted project's override — the flagship property).
- `backend_label` → `"tarball"`; `backend_locator` → the value; `ops config show` renders
  `name -> tarball:<...>  (host-side, durable | in-cage …)` and, for the manifest form, the
  pinned version-tag from the lock (`@ <version> (pinned)`), like the flake/deb rev display.
- Per-project **`tarball-packages.lock`** (sibling of `deb-packages.lock`), keyed by the
  declared value, storing `(resolved-url, hash, version-tag)`. Atomic temp+rename, self-healing
  read, `0700` dir — same as deb.
- `launch.rs::build`: provision alongside the `deb:`/`appimage:` provisions (bins → PATH, roots
  → seed), and `equip_for_gc` seeds the roots so `sbx gc` keeps the built output.
- `main.rs::upgrade_cmd`: add `"tarball"` to the `("all"|"nix"|"mise"|"flake"|"deb"|"appimage")`
  set; `upgrade_tarball_packages` (+ folded into `all`), `tarball_upgrade_summary` — mirroring
  `upgrade_deb_packages`. `sbx upgrade [all|tarball]`.
- `help.rs` + `docs/guide/**`: document the new backend + the `tarball` upgrade word (per the
  "sync user docs with CLI" rule).

## 6. The profile — `profiles/antigravity-ide.toml`

Modeled on `claude-desktop.toml` (Electron `.deb` + Google OAuth in-cage browser) and
`t3code.toml` (GUI holes), grounded on the CLI profile's Google allowlist:

- `cmd`: a bash wrapper installing an in-cage `xdg-open` that routes `http(s)` → an in-cage
  Chromium (Google consent) and the OAuth callback → the IDE — the claude-desktop pattern
  (Google Sign-In needs a browser; the flake confirms the IDE wraps one). `--no-sandbox
  --ozone-platform=wayland --disable-dev-shm-usage --password-store=basic`. **Live-gate:** the
  exact IDE Sign-In callback scheme/flow is unverified — determined on the first real login.
- `[packages]`:
  - `antigravity-ide = "tarball:manifest:<run.app>/releases#<gvt1 template>"` (Form 2, §2).
  - `chromium = "nix:chromium"` (in-cage OAuth browser, like claude-desktop/t3code; HEAVY,
    droppable if a non-browser login path exists).
- Holes: `gui = "wayland"`, `gpu = true`, `dbus = true` (file picker + theme + notifications).
  `audio = true` only if voice is a feature (conservative: omit until confirmed; add if needed).
- `[network] mode = "deny"`, allowlist seeded from the CLI profile + claude-desktop's Google
  set: `cloudcode-pa.googleapis.com` (+ `daily-`) model backend, the Google OAuth set
  (`accounts.google.*` bounded regex, `oauth2.googleapis.com`, `www.googleapis.com/oauth2/*`,
  gstatic/googleapis fonts, `lh3.googleusercontent.com`), `antigravity.google`, the IDE
  auto-updater `run.app` + `edgedl.me.gvt1.com` (in-app updater probes — harmless, or muted),
  the VS Code-fork marketplace/extension host **if** used (live-caught). `mute` telemetry
  (`play.googleapis.com`, `antigravity-unleash.goog`, the Playwright mirrors — from the CLI
  profile) + Google component CDNs (from claude-desktop's mute set).
- **No `[secret]`** — Google OAuth / account, not a header-injectable key (same posture as the
  CLI + claude-desktop). Login persists in the isolated home; keyring caveat noted (file
  fallback via `--password-store=basic`).
- Note: the **build** fetches the tarball over the **host network** (host-side, not the cage
  allowlist), so `edgedl.me.gvt1.com` is only needed in the allowlist for the (inert) runtime
  self-update, not for provisioning.

## 7. Tests

- **Unit** (`config`): `parse_backend` accepts `tarball:<url>` and `tarball:manifest:<api>#<tpl>`,
  rejects a missing scheme / bad charset / a manifest form with no `#` / a template with a
  placeholder that would inject (`{x}` → a value containing `/` or `..` → rejected). Trusted-only
  gating + the `protect_trusted` flagship (trusted app's tarball survives untrusted override).
  `ops config show` renders the backend + pinned version.
- **Unit** (`tarball.rs`/`prebuilt.rs`): the shared derivation body contains `tar`, the setuid-safe
  extract, the autoPatchelf hook, and wraps the launcher; the manifest resolver picks `[0]` and
  substitutes placeholders (with a hostile-value rejection case); lock round-trip + self-heal;
  `tarball_upgrade_summary`; the refactor keeps deb/appimage derivations byte-compatible (their
  existing tests stay green).
- **e2e** (`tests/run.rs`, skip-not-fail): a small-tarball provision proof — resolve a tiny public
  `.tar.gz` via the manifest form, build the derivation host-side, and assert the wrapped binary
  runs from the store (a non-Electron trivial tarball for the mechanism; the real Antigravity
  build is a live-gate given its size, like the claude-desktop `deb:` build).
- **Upgrade e2e**: pin an older version-tag in the lock, run `upgrade_tarball_packages` against
  a stubbed/real manifest, assert the lock rolls to `[0]` and re-pins (the requirement).

## 8. Honest scope / pending-live gates (same class as every GUI profile)

- The **real Antigravity IDE build + launch + Google login** with the user's account is the
  flagship live validation (heavy build ~150–200 MiB tarball + Electron closure; not a per-run
  committed e2e, like claude-desktop).
- The **asar-vs-unpacked launcher layout** is a build-time verification (may need a one-line
  `ELECTRON_WRAP` generalization).
- The **exact OAuth callback flow** for the IDE (deep-link scheme, single-instance handoff) is
  determined on the first login and the allowlist refined from `sbx net logs`.
- **Keyring persistence** across relaunch (file fallback) — confirm with the user's account.

## 9. Increment order (proposed cadence)

**Increment 0 — the runnability spike (GATES everything; do this before writing any backend
code).** The kill-question is *not* the backend plumbing — it is **whether an autoPatchelf
`no-fhs` Antigravity IDE actually launches in the hermetic cage**. The warning sign: the
community flake **defaults to `buildFHSEnv` (`useFHS ? true`)** and treats no-fhs as the
fallback — authors reach for FHS precisely when plain autoPatchelf leaves dlopen gaps a VS Code
fork needs, and an FHS `/usr` papers over exactly those. But sbx **must** use no-fhs (FHS's
runtime nested bwrap is seccomp-blocked). So if no-fhs is insufficient, the whole backend is
wasted — or forces a heavy `[seccomp] allow` mount/unshare relaxation (a very different, much
weaker security posture for the profile). The spike (throwaway, one tarball, one derivation, one
launch) answers it cheaply and surfaces the exact missing-lib set for `ELECTRON_LIBS`:
- Fetch the real official tarball, autoPatchelf against `prebuilt::ELECTRON_LIBS` + the flake's
  `dlopenLibs` (`libglvnd`/`vulkan-loader`/`systemdLibs`/`libnotify`/`libsecret`), wrap the
  `antigravity-ide` launcher, and try to **map a window in a real cage** under `gui="wayland"`
  + `gpu=true` + `dbus=true`.
- Permitted here: build the community flake's `-no-fhs` output **purely as a runnability oracle**
  (not shipped, not the source — same "inspire yourself" latitude), to cross-check the missing-lib
  set and confirm no-fhs can launch at all.
- **Exit criteria:** the window maps (backend is worth building; record the final lib set) — or
  it does not without FHS/seccomp-relaxation (STOP, re-decide the whole approach with the user
  before writing code).

> **RESULT — spike DONE, PASSED (2026-07-17).** A hand-written no-fhs derivation (own
> `mkDerivation` over the OFFICIAL gvt1 tarball, `sha256 = 1gbq10li8hiqwn2s0115wan0a2b0s64aj7wgzl1x0s1ssgvynb2v`,
> no unfree, no google-chrome, no FHS) built against nixos-unstable and **ran**:
> - autoPatchelf patched the **entire core IDE** cleanly; the core launcher `ldd` has zero
>   `not found`. The **only** unresolved deps were `libwebkit2gtk-4.1.so.0` + `libsoup-3.0.so.0`,
>   wanted **solely** by the *optional* bundled `microsoft-authentication` extension's
>   `libmsalruntime.so` (we use Google auth). → real backend: add `webkitgtk_4_1` + `libsoup_3`
>   to `ELECTRON_LIBS` to make MS-login work, **or** ignore them (the extension stays inert).
> - Launched under Wayland (software render, `--disable-gpu`, throwaway HOME): the **full Electron
>   tree came up and stayed alive** — zygotes, gpu-process (SwiftShader), NetworkService,
>   renderer (vscode-webview UI), NodeService extension hosts, and **the native Antigravity
>   `language_server_linux_x64` running** (→ `https://cloudcode-pa.googleapis.com`). No crash, no
>   missing-symbol death. The lone log line was the benign SwiftShader-fallback notice (an
>   artifact of `--disable-gpu`; sbx's `gpu=true` hole gives real GL, already proven for
>   claude-desktop).
> - **Verdict:** no-fhs autoPatchelf is sufficient — the flake's `buildFHSEnv` default was
>   convenience, not necessity. The backend is worth building.
> - **Recorded lib set** (worked): `ELECTRON_LIBS`-equivalent + `stdenv.cc.cc.lib alsa-lib
>   at-spi2-core atk cairo cups dbus expat glib gtk3 libdrm libgbm libglvnd libxkbcommon nspr nss
>   pango xorg.{libX11,libXScrnSaver,libXcomposite,libXcursor,libXdamage,libXext,libXfixes,libXi,
>   libXrandr,libXrender,libXtst,libxcb,libxshmfence,libxkbfile} zlib vulkan-loader systemd
>   libnotify libsecret gsettings-desktop-schemas fontconfig freetype`; dlopen prefix (LD_LIBRARY_PATH):
>   `libglvnd vulkan-loader systemd libnotify libsecret libgbm`.

1. `tarball:` backend core (parse + resolve + Form-1 direct + lock + derivation + provision) +
   the `prebuilt.rs` DRY refactor — tests green, advisor review.

> **RESULT — increment 1 DONE (2026-07-17).** New `src/sandbox/tarball.rs` (direct-URL form,
> mirroring `deb.rs`, `tar -xz` unpack) + full wiring: `Backend::Tarball` + `is_valid_tarball_url`
> (`config/mod.rs`), `tarball_packages` trusted-only filter (`packages.rs`), host-side provision at
> both launch sites + gc keep-set (`launch.rs`), config-view rendering + pin display (`view.rs`),
> `sbx upgrade tarball` dispatch + `tarball_upgrade_summary` (`main.rs`), module re-exports
> (`sandbox/mod.rs`), and help + `docs/guide` sync. **No `prebuilt.rs` refactor needed** — the
> shared `ELECTRON_WRAP` already matches the asar-less `resources/app/` layout (Cursor/VS Code
> forks), so it wraps `antigravity-ide` unchanged. **One deliberate divergence from `deb:`:** the
> tarball derivation uses `autoPatchelfIgnoreMissingDeps = true` (not deb's `[ "libc.musl…" ]` list)
> — a raw vendor tarball commonly bundles OPTIONAL native modules (the Antigravity IDE's
> `microsoft-authentication` extension wants webkit2gtk/libsoup) whose libs are irrelevant to a run
> that does not use them; the CORE binaries are still fully patched. **Tests:** 5 net-new
> (`derivation_expr` string, lock round-trip, `parse_backend`/`is_valid_tarball_url` accept/reject,
> `tarball_packages` trusted-only, `tarball_upgrade_summary` outcomes) — unit **1140/0**, config
> **98/0**, help **13/0**. **Real-build validation (not just string tests):** the EXACT derivation
> the backend generates was `nix build`-ed against the official Antigravity IDE 2.1.1 tarball → it
> builds, `ELECTRON_WRAP` finds the asar-less launcher, `= true` absorbs the MS-auth webkit/soup, and
> the wrapped `bin/antigravity-ide` **runs the full app** (Electron tree + native language server up,
> no crash). fmt clean; the tarball-touched files are clippy-clean (the crate's `clippy -D warnings`
> is currently blocked only by unrelated concurrent WIP in `fs_watch.rs`/`observe_feed.rs`).
2. Form-2 manifest resolve + `sbx upgrade tarball` — tests green (the upgrade requirement),
   advisor review. **Blocked on the §2 open design question being ruled on.**
3. `profiles/antigravity-ide.toml` + docs — import/resolve test green; live validation with the
   user's Google account.

Each increment: unit + integration green, `cargo fmt --check && cargo clippy -D warnings`,
advisor review, user validation before the next — per the project cadence.
