# Hermes browser toolset in the cage — spike findings (2026-07-25)

Why the caged `hermes` exposes fewer tools than a standard install, and exactly what a cage
needs before the browser toolset comes back. Everything below was measured live against the
hermes-agent 0.19.0 build sbx ships (`flake:github:NousResearch/hermes-agent#default`), not
inferred from documentation.

## 1. What is actually missing, and why

Hermes builds its tool schema from `toolsets._HERMES_CORE_TOOLS`, filtered per tool by a
`check_fn` (`tools/registry.py::get_definitions`). A tool whose check fails is not "broken" —
it is **absent from the schema**, so the model never sees it.

Probing the registry inside a cage (sbx store bound at `/nix`, fresh `$HOME`) gives:

| | tools |
|---|---|
| **available** (16) | `clarify` `delegate_task` `execute_code` `memory` `patch` `process` `read_file` `search_files` `session_search` `skill_manage` `skill_view` `skills_list` `terminal` `text_to_speech` `todo` `write_file` |
| **missing** (38) | the 12 `browser_*`, `web_search` `web_extract` `image_generate` `vision_analyze` `cronjob` `computer_use`, the 4 `ha_*`, the 11 `kanban_*`, and the 4 desktop-pane tools |

Attribution — only one group is a genuine cage gap:

- **`browser_*` (12 tools) — the cage gap.** `check_browser_requirements()` needs the
  `agent-browser` CLI on PATH **and** a Chromium build on disk. The flake's `#default` output
  ships neither (`ls <hermes-agent-env>/bin` has no `agent-browser`; the wrapper's PATH adds
  nodejs/ripgrep/git/openssh/ffmpeg/tirith/wl-clipboard/xclip only). A standard install gets
  them from the installer's `npm install -g agent-browser && agent-browser install`. The app
  home was checked for residue — nothing: it never was there.
- **`vision_analyze`, `cronjob` — not cage gaps.** `check_vision_requirements()` needs a
  resolvable provider client (an authenticated session has one); `check_cronjob_requirements()`
  needs `HERMES_INTERACTIVE`, which the interactive CLI sets. Both were false in the probe only
  because it ran unauthenticated and non-interactive.
- **`web_search` / `web_extract` / `image_generate` — key-gated, absent upstream too.**
  `check_web_api_key()` / `check_image_generation_requirements()` need a provider key. A
  standard install without one does not have them either.
- **`ha_*`, `kanban_*`, `computer_use`, desktop panes — gated by design** (HASS token, kanban
  worker mode, macOS, `HERMES_DESKTOP`).

## 2. The working recipe (proven live, real navigation)

```toml
[packages]
chromium      = "nix:chromium"          # _chromium_installed() finds it on PATH
nodejs        = "nix:nodejs"            # required: mise's npm backend needs node in the cage
agent-browser = "mise:npm:agent-browser"

[env]
AGENT_BROWSER_ARGS = "--no-sandbox,--disable-dev-shm-usage"
```

No `cmd` wrapper is needed: agent-browser locates Chromium on PATH by itself (verified both
without the variable and with a bare `AGENT_BROWSER_EXECUTABLE_PATH=chromium`), so the profiles stay
declarative. The variable remains the escape hatch for pointing it at a different browser.

Verified in a real `sbx run` under an empty-netns MITM allowlist:
`agent-browser open https://example.com` → `✓ Example Domain`, and `agent-browser snapshot`
returns a real accessibility tree. Reproduced 5/5 in one cage.

Notes on the mechanics, each checked rather than assumed:

- **`--no-sandbox` reaches Chromium through `AGENT_BROWSER_ARGS`** — no PATH shim needed. It is
  mandatory: M4.1 seccomp blocks `clone(CLONE_NEWUSER)`, so Chromium's own SUID/userns sandbox
  aborts the process (`setuid_sandbox_host.cc:166`). The nixpkgs chromium wrapper does **not**
  honor `CHROMIUM_FLAGS`, so that route does not exist.
- **`agent-browser doctor`'s "Launch test" fails even when the browser works** — that test does
  not apply `AGENT_BROWSER_ARGS`. Its failure is not a signal.
- **mise's `--ignore-scripts` is harmless here, and in fact desirable.** agent-browser ships
  prebuilt Rust binaries in the tarball; its JS shim re-`chmod`s them when postinstall did not
  run (an explicit upstream provision for exactly this case). Skipping postinstall also skips
  Playwright's browser download, which we do not want — nix supplies Chromium.
- Egress at launch needs `registry.npmjs.org` for the mise install.

## 3. The blocker (resolved): two things the cage only got under `gui = "wayland"`

The recipe above works **only** in a cage that also has fonts and sbx's MITM CA. Both were tied to
the GUI hole, and a headless browser needs neither a compositor nor a window:

1. **fontconfig + a font** — provisioned by `sandbox/fonts.rs`, then gated on `gui = "wayland"`.
   Without it Chromium starts and can even report a TLS error, but **dies as soon as it renders
   a real page** under agent-browser's CDP session (`✗ CDP response channel closed`).
   A font package has no `bin/`, so a profile cannot supply one through `[packages]`.
2. **the egress MITM CA in the NSS db** — imported by `sandbox/catrust.rs`, then gated on
   `gui = "wayland"` **and** a filtering allowlist. Chromium ignores the `CA_FILE_ENV_KEYS` sbx
   sets and reads `~/.pki/nssdb`; without the import every page is
   `net::ERR_CERT_AUTHORITY_INVALID`.

Isolation (each cell measured, same project, one variable at a time):

| gui | CA in NSS db | fonts | `agent-browser open` |
|---|---|---|---|
| wayland | yes (catrust) | yes (font hole) | **✓ 5/5** |
| none | yes (profile certutil) | no | ✗ 5/5 `CDP response channel closed` |
| none | no | no | ✗ `ERR_CERT_AUTHORITY_INVALID` (browser alive) |
| none | yes (profile certutil) | yes (host fonts bound + generated `fonts.conf`) | **✓ 3/3** |

The last row is the proof that **neither the compositor socket nor the GUI hole itself is
needed** — only its two by-products. A misleading intermediate result is worth recording: the
agent-browser daemon is started by the first invocation in a cage and reused by later ones, so
one bad first launch makes every subsequent attempt in that cage fail identically. Two runs were
mis-read as flaky before that was understood.

Cost, measured in the store: `nss-3.112.5-tools` 46 MB, DejaVu negligible,
`chromium-unwrapped-150` 620 MB (closure larger), `nodejs` ~10 MB.

## 4. Consequence — the `offscreen` posture

Shipping `gui = "wayland"` on the CLI/web hermes profiles to obtain fonts + CA would grant a
compositor socket to agents that never draw a window — under wlroots/sway/hyprland that is
screencopy and input injection (threat model §5a). `hermes-web` / `hermes-webui` serve their UI
to the **host** browser, so a display grant there is indefensible.

The two by-products are not privilege grants (fonts are read-only data; the CA is trust the cage
already extends to the proxy through every `CA_FILE_ENV_KEYS` variable), so the fix is core-side:
`gui` grew a third posture, **`offscreen`**, between `none` and `wayland`. It provisions the fonts,
imports the CA under a filtering posture, and gives the netns its black-hole `dummy0` interface (so
the engine reports itself online) — and binds no compositor socket, no GUI data, no portal. One
predicate, `GuiPolicy::renders()`, drives all three prerequisites so they cannot drift apart as the
postures grow; the display-bearing pieces stay matched on `Wayland` alone.

Live proof of the shipped posture, in a real `sbx run` with `gui = "offscreen"` and nothing else
(no compositor, no hand-rolled `certutil`, no host font bind): `FONTCONFIG_FILE=/opt/sbx/fonts.conf`,
`agent-browser open https://example.com` → `✓ Example Domain`, `snapshot` → a real accessibility tree.

And the acceptance that matters — the same cage with the hermes flake package added, probing Hermes'
own registry: `check_browser_requirements: True`, **9 `browser_*` tools back in the schema**
(`back` `click` `console` `get_images` `navigate` `press` `scroll` `snapshot` `type`), total
available 16 → 25. `browser_vision` needs a browser **and** a resolvable vision provider
(`check_browser_vision_requirements`), so it returns with an authenticated session, exactly like
`vision_analyze`; `browser_cdp` / `browser_dialog` carry their own separate gates.

`hermes-desktop` (already `gui = "wayland"`, which carries everything `offscreen` does) needed only
the section-2 packages.

## 5. Not in scope

`web_search` / `web_extract` / `image_generate` are provider-key gated and absent on a standard
install without keys. They need a `[secret]` block, not a cage change.
