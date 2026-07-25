# ops-cli — repo conventions (bwrap rewrite)

> ⚠️ You are on the **`bwrap`** branch: the clean rewrite of `ops` onto a
> **bubblewrap + daemonless nix** substrate. The old conventions (bash `ops.sh`
> release cutting, container image builds) **no longer apply** here.

## What `ops` is (this branch)

`ops` is a **sandbox launcher** (a static Rust binary) that runs tools — including
**encapsulated AI agents** — inside a bubblewrap sandbox where they can install a
project's full dependency set via **single-user daemonless nix** **without
mutating the host OS**. It is **not** an OCI container manager: no
docker/podman/nerdctl, no image build.

Reference class: nono.sh / greywall.io / landrun (sandboxes), **not**
flox/devbox/devenv (mere env managers that isolate nothing).

## Branch topology

| Branch | Contents |
|---|---|
| `main` | `v1.18.0` — bash/container era, frozen, pushed |
| `container` | snapshot of the **OCI** Rust v2 (reference / cherry-pick reusable modules: config, trust, mise-nix bridge) |
| **`bwrap`** | **working branch** — clean from `v1.18.0` + the rewrite |

## Design documents (read before coding)

1. [`docs/bwrap-spike-2026-06-14.md`](docs/bwrap-spike-2026-06-14.md) — feasibility, proven live.
2. [`docs/bwrap-threat-model-and-binds.md`](docs/bwrap-threat-model-and-binds.md) — threat model + bind layout + decisions.
3. [`docs/bwrap-architecture.md`](docs/bwrap-architecture.md) — Rust modules, CLI surface, milestones (M0→M7).
4. [`docs/bwrap-security-stack.md`](docs/bwrap-security-stack.md) — the enforcement building blocks (bwrap/seccomp/Landlock/cgroups) and when each lands.

## Security model (the essentials)

- **Two actor modes**: **A** = interactive shell (user, semi-trusted); **B** =
  autonomous agent (actions untrusted) → **B is the default**.
- **Hard requirement**: **capability-bearing unprivileged user namespaces**.
  Without them there is no security boundary → `ops doctor` **hard-fails**, never
  a silent fallback (proot = emulation = no boundary). Note: on restricted
  Ubuntu 24.04+, `unshare(CLONE_NEWUSER)` can succeed yet be stripped of
  capabilities — `doctor` checks for the capability-bearing case specifically.
- The sandbox runs **as the host uid** (same-uid) → **the bind layout IS the
  security control**; `read-only` protects integrity, not confidentiality (a
  secret must be **absent**, not mounted ro).
- **Enforcement building blocks** (the consensus of serious agent sandboxes;
  details in a dedicated doc): bwrap (all namespaces + `no_new_privs` + drop all
  capabilities + `--new-session`) · **seccomp** denylist · **Landlock** (FS) as
  defense-in-depth · **cgroups v2** limits (anti-DoS). Network (egress allowlist)
  is handled **last**.
- An **untrusted** project `.ops.toml` cannot touch security-relevant fields
  (binds/network/hooks/sources); the trust gate is the validation, bound to a
  **content hash** (direnv model).

## Build / verify

```bash
cargo build
cargo run -- doctor          # prerequisite preflight (userns, bwrap)
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

## Conventions

- **Never** a `Co-Authored-By:` line in git commits (user's global preference).
- **The project itself is in English** (code, comments, docs, CLI output).
- Code comments are **self-contained**: no references to a process ("Task N",
  "M1", "SEC-002"), to `ops.sh`/the container code, or "matches X". Reword to
  stand alone.
- **Always write the cleanest possible code**, following coding and security
  best practices: least privilege, fail-closed, validate inputs, no unsafe
  shortcuts. The security model above is the baseline, not the ceiling.
- **Every increment ships with tests** (unit + integration, green), is then
  **reviewed by the advisor**, and finally **validated with the user** before
  moving to the next — incremental, collaborative cadence, no barreling ahead.
- **Current status — the bwrap rewrite is far along: M2 through the main M6 slices have shipped;
  the genuinely-remaining pieces are blocked on the user.** **Provisioning (M3) complete through
  M3.5** — the per-project writable store + the Mode-B `/nix` read-write inversion, nix-in-cage
  self-equip, `ops mise` passthrough + tool activation, `ops upgrade [nix|mise|flake]`, hermetic
  TLS + a curated base toolset, and `ops search`. **Enforcement (M4) complete** — seccomp denylist
  (Posture A, now trusted-relaxable via `[seccomp] allow`) + cgroup v2 resource limits + a trusted
  `[devices]` host-device grant into the cage's minimal `/dev` (Landlock-FS
  is a deferred defense-in-depth option, not a gap). **Housekeeping (M5) complete** — `ops gc [--all] [--prune]` (session + per-project +
  shared-store collection, including the stale rev-keyed flake out-link residual), `ops attach
  <id>`, `ops stop <id>… | --all`, and a `--detach` background-agent path; the **one open M5 parity
  hole is ssh-agent forwarding** (`$SSH_AUTH_SOCK`, a scoped trusted-only opt-in, deferred — the
  `container socket` row is N/A on this branch). **Network + secrets (M6) largely shipped** —
  Model-B egress (empty netns + an in-cage forwarder → a host MITM allowlisting proxy), host-side
  credential injection with outbound/inbound redaction, and the resolver / plugin / signed-store
  layer. **The `ops app` framework + 9 importable profiles shipped** — named agent launchers with a
  per-app isolated `$HOME`, export/import, and `nix:` / `mise:` / `flake:` package backends. **The
  two genuinely-remaining pieces are blocked on the user:** the flagship live-auth e2e (a real API
  key, never the assistant's) and the signed-store *distribution* of profiles (a hosting URL + a
  long-term signing key). **Beyond the milestones, the shipping binary is now self-contained** — it
  embeds its own static `nix` (2.34.7) and `bwrap` (0.11.2) engines behind the `bundled-nix` /
  `bundled-bwrap` features, materialized under `<data>/engine/`, so a release no longer depends on
  host-installed engines; bwrap independence is *partial* (the host's path-profiled `/usr/bin/bwrap`
  is kept where `kernel.apparmor_restrict_unprivileged_userns` is set — see the entry below). The
  per-increment history below is the append-only record, kept as-is.**
  **The host light/dark theme is read over the bus, not by running a store binary (DONE 2026-07-25)**
  (`src/sandbox/theme_relay.rs` + `portal.rs` + `launch.rs`): the user reported that
  `hermes-desktop` **does not follow the host light/dark theme**. Traced, not guessed: the at-launch
  seed obtained the host preference by executing the **provisioned `dbus-send`** host-side, and that
  binary **can never run on the host** — its ELF interpreter is `/nix/store/…glibc-2.42-67/…
  ld-linux-x86-64.so.2`, a path that exists **only in sbx's relocated store** (measured live:
  `ls` sees the file, exec fails "no such file or directory", the interpreter `ABSENT on host`,
  `present in sbx store`). So the read failed on **every** host, `color_scheme` was always `None`,
  **no seed was emitted**, and the cage's GSettings keyfile was never written — verified absent both
  in the app home and through the running cage's mount ns. The app therefore opened in its default
  (light) theme whatever the desktop was set to. **The live relay was NOT the bug** — it only mirrors
  *changes*, so it never supplied the initial value; proven working in both directions during the
  diagnosis, with the user watching: host portal emits `SettingChanged appearance color-scheme
  <uint32 0>` → sbx rewrites the keyfile to `default`/`Adwaita` (17:08:55), then `<uint32 1>` →
  `prefer-dark`/`Adwaita-dark` (17:09:45), and the **user confirmed the window went dark**. **Fix:**
  the initial `Read` now rides the **zbus client already in the tree** — `theme_relay` held a proxy
  onto exactly this portal interface for the signal, so the read is placed **beside it**, and the
  value seeded once at launch and the values mirrored afterwards are the same setting read the same
  way (they cannot drift). Bounded by a **2 s timeout** (an unresponsive portal costs a pause, never
  a stalled launch); every failure still degrades to the default theme. This **removes the last
  host-side execution of a store binary** (`physical_path`'s other uses are bind *sources*, checked)
  and the `dbus_send` field with it (no other consumer). **Proven live end-to-end on a fresh cage:**
  at launch, untouched, the keyfile carries `color-scheme='prefer-dark'` / `gtk-theme='Adwaita-dark'`
  — the host's exact state; before, no keyfile at all. **Test placed in-crate on purpose:** only
  there can it ask the **bus daemon** who owns the portal name and so separate "this host has no
  portal" (skip) from "the read is broken" (fail); confirmed non-skipping here by temporarily
  pinning it to the host's real `prefer-dark`. **Honest asymmetry:** unlike the font fix there is no
  before/after test run (the signature changed, so the new test cannot compile against the old code)
  — the *cause* is proven by the absent interpreter, the *fix* by the seed landing. 1315 unit +
  gui/dbus e2e green, fmt/clippy `-D warnings` clean, **no new dep** (zbus/async-io already present).
  **Instrument caution earned the hard way:** the first diagnosis pass reported a `gsettings`-vs-portal
  disagreement that did not exist — the linuxbrew `gsettings` cannot load the dconf backend and was
  returning *schema defaults*. Verify the instrument before trusting a mismatch it reports. See
  [[dbus-hole]], [[gui-offscreen-posture]].
  **Adwaita Sans provisioned by the GUI hole (DONE 2026-07-25)** (`src/sandbox/fonts.rs` +
  `docs/bwrap-threat-model-and-binds.md` + `tests/run.rs`): a GTK4/libadwaita or Electron app styled
  for a modern GNOME desktop asks for **`Adwaita Sans` by name**, and fontconfig **cannot alias its
  way to a face that is absent** — hermes-desktop logged `Could not find any font: Adwaita Sans,
  sans` every launch and rendered in a substitute. A font package carries **no `bin/`**, so it cannot
  ride `[packages]` (which selects a bin-bearing output — the failure is a hard error, recorded in
  the 2026-06-22 GUI spike) and a **profile has no way to supply one**; the hole is where it belongs.
  Measured before adding, against the pinned rev: **7.3 MiB, 1 store path, no dependencies**
  (vs DejaVu 9.1 MiB and the emoji face 11 MiB), layout `share/fonts` — the marker the hole already
  uses, so it is one `GUI_FONTS` line. **Deliberately left out of the generic-family aliases**
  (the user's call): provisioning it lets an app that *names* it get it, while a page that asked for
  nothing in particular keeps rendering in the neutral face — restyling every cage is the user's
  business, not the sandbox's. Reaches **both** rendering postures (`wayland` and `offscreen`).
  **Cost:** every GUI cage pays the 7 MiB, including those that never request it; the per-profile
  alternative (a trusted-only `[fonts]` config field) was weighed and **deferred** as a full
  increment (schema + gating + merge_app + view + override + docs + tests). See
  [[gui-offscreen-posture]].
  **The font layer was silently unwired for `gui = "wayland"` — a regression the offscreen increment
  introduced, plus the blunt assertion that hid it (DONE 2026-07-25)** (`src/sandbox/launch.rs` +
  `tests/run.rs`): the user reported hermes-desktop **rendering wrongly**; its log ended in
  `Fontconfig error: Cannot load default config file` and a **FATAL**
  `SkFontMgr_FontConfigInterface … Not implemented` — a Chromium renderer dying because it found
  **zero fonts**. Diagnosed on the **running cage**, not by reading code: its bwrap argv carried the
  `--ro-bind …/fonts.conf /opt/sbx/fonts.conf` but **no `--setenv FONTCONFIG_FILE`** among its 40
  keys. Root cause: splitting the font block **out** of the Wayland block (so `offscreen` would get
  it) moved it **above** `gui_env = env;` — an **assignment**, not an `extend` — so the display
  wiring **overwrote** the entry the font block had just pushed. The bind survived (it goes to
  `gui_binds`), the variable naming it did not: a configuration mounted but never named. One-line
  fix (`gui_env.extend(env)`), and the four sibling sites were already `extend`. **The fix landed
  inside commit `7fa7b05`** (the user committed while it was being edited), so `git log` does not
  show it as a separate change. **The second, larger finding — the test that should have caught it
  passed:** `a_gui_wayland_launch_provisions_fonts_the_cage_can_find` asserted the substring
  `dejavu-fonts`, which **`dejavu-fonts-minimal` satisfies** — the font path compiled into nixpkgs'
  fontconfig (`--with-default-fonts`), which `fc-list` reports **even in a cage whose generated
  configuration never takes effect**. So all three font assertions (wayland, offscreen, compose)
  passed in a cage with **no working fontconfig at all**. Re-keyed on **`noto-fonts-color-emoji`**
  (nothing but the hole supplies an emoji face) plus, on the wayland site, an assertion on
  **`FONTCONFIG_FILE` itself** — a bind alone cannot tell a named configuration from an unnamed one.
  **Proven in both directions:** with the overwrite restored the wayland e2e fails
  (`FONTCONFIG_FILE=[]`, only `dejavu-fonts-minimal` listed); it passes once merged. **Standing
  lesson, three occurrences in one session** (the `dejavu-fonts` substring, a replacement assertion
  that matched the `fc-list` listing instead of the `fc-match` answer, and a `gsettings` that read
  schema defaults): *verify that the assertion and the instrument measure what they claim*. A sweep
  of `tests/run.rs` for assertions matching a **superstring** of what they pin is tracked separately.
  See [[gui-offscreen-posture]].
  **`gui = "offscreen"` — a third posture, so a headless browser works without a display (DONE
  2026-07-25)** (`src/config/{types,mod,schema,view,overrides}.rs` + `src/cli/config.rs` +
  `src/sandbox/launch.rs` + `src/help.rs` + `docs/guide/configuration/{gui,overrides}.md` +
  `docs/guide/reference/environment-variables.md` + `profiles/{hermes,hermes-web,hermes-webui,
  hermes-desktop}.toml` + `profiles/README.md` + `tests/run.rs`; findings
  `docs/bwrap-hermes-browser-toolset-spike-2026-07-25.md`): the user reported that the caged
  `hermes` offers **far fewer tools than a standard install**. Traced to Hermes' own gating, not to
  a sandbox failure: it builds its tool schema from `toolsets._HERMES_CORE_TOOLS` filtered per tool
  by a `check_fn`, and a failing check **removes the tool from the schema silently** — the model
  simply never sees it. Measured in a real cage: **16 of 54 tools exposed**, and exactly one group
  is a genuine cage gap — the **12 `browser_*` tools**, gated on the `agent-browser` CLI being on
  PATH **and** a Chromium build on disk, neither of which the flake's `#default` output ships (a
  standard install gets them from the installer's `npm install -g agent-browser && agent-browser
  install`; the app home was checked for residue — it never was there). Explicitly **not** cage
  gaps, so not "fixed": `vision_analyze`/`browser_vision` need a resolvable vision provider and
  `cronjob` needs `HERMES_INTERACTIVE` (both true in a real authenticated interactive session);
  `web_search`/`web_extract`/`image_generate` are provider-key gated and absent on the user's
  standard install too; `ha_*`/`kanban_*`/`computer_use`/the desktop panes are gated by design.
  **The blocker was ours, though:** a browser engine needs two things the hermetic cage lacks, and
  both were tied to `gui = "wayland"` — **fonts** (without them Chromium starts, can even report a
  TLS error, but **dies the moment it renders a real page**) and **the egress MITM CA in the cage's
  NSS db** (Chromium ignores the `CA_FILE_ENV_KEYS` sbx sets and reads its own store → every page
  `ERR_CERT_AUTHORITY_INVALID`). Shipping `gui = "wayland"` on the CLI/web profiles to get them
  would hand a **compositor socket** (screencopy + input injection on wlroots/sway/hyprland,
  threat-model §5a) to agents that never draw a window — indefensible for `hermes-web`/`hermes-webui`,
  which serve their UI to the HOST browser. So `GuiPolicy` grew a third posture **`Offscreen`**,
  ordered by exposure **`none` < `offscreen` < `wayland`**, and one predicate **`GuiPolicy::renders()`**
  (`Offscreen | Wayland`) now drives the three in-cage rendering prerequisites — the font layer
  (provision **and** the `FONTCONFIG_FILE` bind, which lived **nested inside the Wayland block** and
  had to be split out — the bug the first live run caught), the catrust CA import (still ∧ a
  filtering allowlist), and the netns `dummy0` online signal — while everything that exposes the
  host stays matched on `Wayland` alone (compositor socket, guidata/GTK, dbus portal, the pty
  double-Ctrl+C force-quit for a window that ignores SIGINT). `offscreen` grants **no host access at
  all** but rides the same trusted-only gate, so the postures stay one ordered field; `validate_gui`
  still fail-closes an unknown string, and a one-shot `--gui`/`SBX_GUI` typo stays fatal
  (verified live: exit refuses with `expected "none", "offscreen" or "wayland"`).
  **Naming was the user's call** (they pushed back on the first proposal): a dedicated
  `browser = true` field would duplicate the whole gating/merge/override/provenance machinery and
  misreads as "sbx installs a browser"; `"headless"` was rejected as ambiguous with `"none"`.
  **Profiles (all four, default-on — the user's call over a commented opt-in):** `nix:chromium` +
  `mise:npm:agent-browser` + `nix:nodejs` (mise's npm backend needs a node in the cage — the flake's
  own bundled node is only on the `hermes` wrapper's PATH) + `AGENT_BROWSER_ARGS =
  "--no-sandbox,--disable-dev-shm-usage"` (**mandatory**: M4.1 seccomp blocks `clone(CLONE_NEWUSER)`,
  so Chromium's SUID/userns sandbox aborts the process — acceptable because bwrap + seccomp + the
  empty netns IS the boundary; the nixpkgs chromium wrapper does **not** honor `CHROMIUM_FLAGS`, so
  that route does not exist) + `{GET} registry.npmjs.org` with the audit POST muted; `gui =
  "offscreen"` on the three headless ones, `hermes-desktop` already carrying it via `wayland`.
  **No `cmd` wrapper**: agent-browser locates Chromium on PATH by itself (verified both bare and via
  `AGENT_BROWSER_EXECUTABLE_PATH=chromium`), so the profiles stay declarative. mise's
  `--ignore-scripts` is not merely harmless but **wanted** — agent-browser ships prebuilt Rust
  binaries whose JS shim self-`chmod`s them, and skipping postinstall skips the Playwright browser
  download nixpkgs' Chromium replaces. **Everything was measured, not assumed** (spike-first): the
  registry probe in a cage, `ls <hermes-agent-env>/bin` for the missing CLI, an A/B/C/D matrix over
  {gui, CA, fonts} that isolated the two by-products, and the recipe proven live end-to-end.
  **Live-proven:** with `gui = "offscreen"` alone (no compositor, no hand-rolled certutil, no host
  font bind) a real `sbx run` gives `FONTCONFIG_FILE=/opt/sbx/fonts.conf`, `agent-browser open
  https://example.com` → `✓ Example Domain` and `snapshot` → a real accessibility tree, through the
  empty-netns MITM allowlist; and the same cage with the hermes flake added reports
  `check_browser_requirements: True` with **9 `browser_*` tools back in the schema** (16 → 25 total).
  **Tests:** 2 net-new unit (`the_offscreen_gui_posture_resolves_and_is_gated_like_wayland`,
  `only_the_drawing_gui_postures_render`) + 1 net-new run.rs e2e
  (`an_offscreen_gui_posture_provisions_fonts_without_exposing_a_display` — teeth on **both** halves
  in one launch: the DejaVu store path from `fc-list` plus the bound `/opt/sbx/fonts.conf`, and the
  host compositor socket **absent** from the cage, so a refactor that re-couples the display to
  `renders()` fails here; the first cut asserted `WAYLAND_DISPLAY=[]`, which the advisor caught as
  toothless — the cage's env passthrough is `TERM`/`LANG` only, so it holds under `none` too).
  **1315 unit + config/help integration green**, fmt/clippy `-D warnings` clean, musl static build
  verified, **std-only** (no new dep). **Honest scope — the standing live gate:** `sbx app run
  hermes` with the user's own provider credentials, checking `/tools` in a real session and driving
  one `browser_navigate`, is NOT done (it needs their auth); what is proven is the registry gate
  flipping and the browser stack working end-to-end in the cage. `browser_vision` stays absent until
  a vision provider resolves (`check_browser_vision_requirements` = browser ∧ vision), exactly like
  `vision_analyze` — auth-gated, not broken. **Cost, measured:** chromium-unwrapped 620 MB unpacked
  (larger closure), nss-tools 46 MB, nodejs ~10 MB — paid per project store on the first launch.
  **Deliberate residual:** the agent browses **only** the profile's allowlist, so a real site's
  subresources are refused unless opened with `sbx net allow -a <app> <url>`; browsing is not opened
  wholesale. See [[gui-offscreen-posture]], [[hermes-browser-toolset]], [[gui-netns-dummy-online]].
  **Supervised-session teardown — sweep the cage's scope cgroup, not just the ppid subtree (DONE
  2026-07-17)** (`src/session.rs`): `sbx session stop` (and every teardown) could leave a supervised
  cage's process running — an orphaned agent/`sleep` — surfacing as an **intermittent** failure of
  `stop_tears_down_a_supervised_app_session` under heavy parallel load (and, live, as accumulated
  orphaned `sbx-*.scope` units). **Root cause, traced live not assumed:** a supervised/detached cage
  runs inside a transient systemd resource-limit scope (`sbx-<slug>-<pid>.scope`), and the stop tore
  it down by SIGTERM/SIGKILL-ing `descendants(session_pid)` — the **ppid subtree** of the launcher.
  But the scope can reparent the cage off the launcher's subtree (onto the systemd **user manager**),
  so `descendants` intermittently returns a set that misses the cage and the cage outlives the
  launcher's signal. Proven by instrumenting `Session::stop`: on a passing run `descendants(pid)` and
  the scope's `cgroup.procs` both listed the full cage (`[…,bwrap,sleep,socat]`), confirming the scope
  unit-name embeds the **launcher pid = the session pid**; and a teardown driven by the scope
  **cgroup alone** tore the cage down reliably in a controlled repro (`cage sleep gone`), so the
  cgroup membership is the stable identity the racy ppid link is not. **Fix:** `Session::stop` now
  **unions** `descendants(pid)` with the members of the cage's scope cgroup — the scope found by the
  unit-name suffix `-<pid>.scope` under `/sys/fs/cgroup/user.slice`, its `cgroup.procs` read to
  `(pid, start_ticks)` — so the sweep reaches every cage process regardless of reparenting.
  **Degrades cleanly:** a launch with no scope (no usable systemd user manager, the best-effort M4.2
  path) yields no scope members and the ppid subtree covers it exactly as before. **Not a regression
  from the run/shell merge or the app-run verb** — a pre-existing latent race in the teardown that the
  `--no-fail-fast` load surfaced; it affects any supervised session (an `ops run`/`ops app` under a
  filtering network, or a `--detach`). Also fixes the sibling `detach_runs_an_agent…stop_ends_it` flake
  (same `Session::stop`). **Verified:** with `/tmp`'s tmpfs inode budget freed (my own repro store
  seeds had exhausted it, which is what made the e2e *skip* — the store belongs on disk, [[nix-store-inode-budget]]),
  the real `stop_tears_down_a_supervised_app_session` runs fully (≈29.5s, not skipped) and passes
  **3/3**; the cgroup-only teardown proven live; `is_cage_scope` unit test pins the pid-boundary match;
  fmt/clippy `-D warnings` clean, std-only (no new dep). **Honest scope:** the *failure* under the fix
  was not re-reproduced at low load (the race needs the heavy parallel contention), but the cgroup set
  is authoritative by construction (systemd guarantees the scope holds exactly the cage) and the
  cgroup-only sweep was shown to tear the cage down. See [[m5-gc]], [[m4-cgroup-resource-limits]],
  [[cage-naming]].
  **`sbx run`/`sbx shell` merged — one docker-style verb (BREAKING, DONE 2026-07-17)**
  (`src/sandbox/{launch,mod}.rs` + `src/{main,help}.rs` + `src/session.rs` + comment sweeps across
  `config/{mod,schema}.rs` + `sandbox/{binds,egress,forward,spec,attach}.rs` + `docs/guide/**` (incl.
  `cli/shell.md` DELETED, folded into `cli/run.md`) + `README.md` + `profiles/README.md` +
  `tests/{help,shell}.rs`): `sbx shell` is **removed** and folded into `sbx run` (one verb, like
  `docker run`). **Dispatch** (`sandbox::run`): `interactive = !detach && isatty(0)`. With **no
  command** → the project shell: a tty opens the interactive pty shell (the old `sbx shell` body —
  bash `--rcfile` synthetic rc, `mise activate`, the `(sbx-<slug>)` prompt, job control, via
  `launch_interactive_shell`), a pipe runs a non-interactive `[shell_bin]` reading stdin (via the exec
  `launch`, tools through the shims on PATH), and `--detach` with no command is **refused** (a detached
  shell has no terminal). With a **command** → the launch mode follows stdin: a tty runs it under the
  pty supervisor (`launch_pty_supervised`, job control + resize — *new* vs the old `sbx run`, and
  exactly what `app_run`/`session attach` already did), a non-tty/`--detach` keeps the exec-replace /
  supervised path (`launch`, inherited stdio, exit status propagated — the old `sbx run`, unchanged).
  **No new low-level code** — the dispatch reuses proven machinery; the security posture is identical
  either way (`Runtime::ProjectDefault`, same resolved config, same network/seccomp/cgroup gating);
  only the exec-vs-pty *mechanism* differs. `Kind::Shell` is kept (labels the no-command session in
  `sbx session ls`). **The breaking change was the user's explicit call** ("run de préférence comme
  docker"): `run`/`shell` were only ever exec-vs-pty siblings on the same posture, so a single verb
  that dispatches on stdin is the cleaner surface. **Purged in the same commit (the user's standing
  no-migration-messages rule):** `help::subcommand_hint` (its 9 old-spelling→namespace mappings
  ls/attach/stop/import/export/publish/add/update/store) **and** the `sbx app <name>` verbless
  suggestion arm — a removed/renamed verb now yields a **plain** "unknown command" + the generic
  `sbx --help` pointer, never a "did you mean" nudge (`sbx shell`/`sbx ls` → unknown command; a bare
  `sbx app` still names the launch verb as *usage*, not migration — `to launch an app, use sbx app
  run <name>`, kept at the user's direction). Every code/doc reference to `sbx shell` was reworded so
  nothing dangles at a removed verb. **Help:** the `["shell"]` page is gone; `["run"]` documents the
  no-command shell + the stdin-follows launch mode. **Tests:** the pty integration test was rebranded
  from `sbx shell` to a no-command `sbx run`
  (`an_interactive_run_with_no_command_gives_the_sandbox_a_controlling_terminal`); the help guard's
  `TOP_LEVEL`/`PATHS` dropped `shell`; the subcommand-hint tests collapsed into one asserting *no*
  hint. **Verified:** exit-3 propagation on the exec path and a piped `echo … | sbx run` both proven
  live; **unit 1106/0** and every integration suite green for this change — config 98/0, help 13/0,
  net 56/0, app 10/0, attach 2/0, sessions 2/0, proc 6/0, projects 19/0, doctor 6/0, trust 6/0,
  upgrade 3/0, color 4/0, path 4/0, and the **pty suite 2/0** — plus the one test that encoded the
  old no-command contract flipped to the new one (`run_without_a_command_is_a_usage_error` →
  `run_detach_without_a_command_is_a_usage_error`, since a no-command `sbx run` now opens a shell,
  not a usage error). fmt/clippy `-D warnings` clean. **Full-suite honesty:** the `cargo test
  --no-fail-fast` failures were pre-existing and unrelated to this merge — the `detach_runs_an_agent…`
  / `run.rs::sbx_net_logs_*` timing/contention flakes, and `stop_tears_down_a_supervised_app_session`.
  The last was first mis-attributed here as a deterministic WIP regression; a live investigation showed
  it is an **intermittent teardown race** (the ppid-subtree teardown can miss a cage the systemd scope
  reparents off the launcher), pre-existing and independent of both this merge and the app-run verb,
  surfaced only under the heavy parallel load — and it is now **fixed in a follow-up increment** (see
  the entry above: teardown via the cage's scope cgroup). This diff itself provably does not touch the
  app-supervised launch or the stop path (`git diff HEAD -- launch.rs` is confined to `run()`, the
  `shell()` removal, and comment rewords). This increment also **removed the `sbx app <name>` migration
  hint** the entry below added (superseding its "migration hint" description). See [[run-shell-merged]],
  [[no-migration-messages]], [[session-namespace]], [[app-interactive-pty]].
  **`sbx app run <name>` — the launch verb is now mandatory (BREAKING, DONE 2026-07-17)**
  (`src/main.rs` `app_cmd`/`app_run`/`parse_app_launch` + `src/config/mod.rs` + `src/help.rs`
  + `docs/guide/**` (18 files) + `tests/{config,help,run,attach,shell,detach,stop}.rs`): launching a
  named app now requires the explicit `run` verb — `sbx app run <name>` — mirroring the other
  `sbx app` subcommands (`import`/`export`/`rm`/`list`/`show`/`prune`), which each already carried a
  verb. The **verbless `sbx app <name>` form is removed**: `app_cmd`'s catch-all no longer routes a
  bare token to a launch; a former-launch token (`sbx app claude`) now gets the **generic "needs a
  subcommand" usage + the app overview page** (no migration hint — the once-present
  `to launch an app, use sbx app run …` suggestion was removed in the run/shell-merge increment, per
  the user's no-migration-messages rule). The launch body moved into a new `app_run(&args[1..])` (strips
  the `run` token, then the unchanged pure `parse_app_launch` reads the name/`--detach`/`--net-learn`
  /overrides/`-- passthrough`); its usage messages now point at the `["app","run"]` synopsis. **The
  breaking change was the user's explicit call** (over a docker-style `run`-plus-shortcut option) —
  chosen precisely because requiring `run` **frees the app namespace**: the first `sbx app` token is
  always a subcommand, so an app name can never collide with one → `RESERVED_APP_VERBS` /
  `is_reserved_app_verb` **deleted** (the 8 `main.rs` + 2 `config/mod.rs` call sites keep only the
  `is_valid_app_name` anti-traversal check — the load-bearing security control), and an app may now be
  named `run`/`show`/`import`/etc., reached as `sbx app run <name>`. This also fixes a latent
  inconsistency (`prune` was dispatched but absent from the old reserved set) and is future-proof (a
  future `sbx app <newverb>` can never shadow an app's launch). **Help** split: `["app"]` slimmed to an
  overview + a new `["app","run"]` page carrying all launch options/details (`resolve_path` handles
  `sbx app run <name> --help` for free once the page exists; `-- --help` still passes through). **Docs:**
  a `docs/guide/**` sweep converted every launch-form `sbx app <name>` to `sbx app run <name>`,
  leaving management usages untouched. **Tests:** three tests that asserted the old reserved-verb
  rejection were **flipped to assert the opposite** (a verb-named app is now a usable name) rather than
  deleted — `config` `a_subcommand_verb_is_a_usable_app_name`, `reading_profiles_keys_each_app_by_its_file_stem`
  (an `import.toml` profile now resolves; an unsafe-name profile with a space still drops), `main.rs`
  `resolve_key_target_routes_by_scope_and_app`, and the `config` integration
  `sbx_app_import_refuses_a_wrapped_profile_and_an_invalid_name` (renamed; `--as rm` now succeeds); plus
  a **teeth test** `run.rs::app_run_treats_a_subcommand_verb_as_an_app_name` (`sbx app run list` reaches
  the launch path treating `list` as an app name, while bare `sbx app list` still runs the subcommand).
  **Shipped alongside the WIP `sbx app prune` / `sbx proc ls`** (all committed together in `0ca8e25`; the
  test flips + a follow-up regression fix were a later pass). **Verify caught a real miss:** the first
  test-invocation survey truncated (`head -40`), so `tests/stop.rs`'s `&["app", app, "--detach"]` (the
  app name a **loop variable**, not a string literal) was not converted → it hit the new migration-hint
  path and failed; an exhaustive re-sweep (variable forms included) + running the actual modified e2e
  suites caught and fixed it. Verified: fmt/clippy `-D warnings` clean; **UNIT 1106 + config 98 + help
  14 + app 10 + attach 2 + shell 2 + stop 6 (after the fix) + a `run.rs` teeth test** green; the two
  `run.rs` `sbx_net_logs_*` failures were **contention flakes** (empty egress log under the full-suite
  parallel load — green 2/0 in isolation; they launch via `sbx run`, not `sbx app`). **Honest residual:**
  the `detach_runs_an_agent_then_stop_ends_it` e2e fails on a **pre-existing 10s-teardown timing flake**
  (the failing assertion varies between runs — the supervised path at :288 vs the exec path at :334 —
  non-deterministic; all launch asserts pass; `session stop`/teardown is untouched by this change, and
  `stop_tears_down_a_supervised_app_session` passes), unrelated to `app run`. See [[ops-app-framework]],
  [[global-apps-are-profile-files]], [[app-rm-purge]].
  **`audio = true` — microphone + playback in the cage via PulseAudio (DONE 2026-07-13)**
  (`src/sandbox/audio.rs` [new] + `mod.rs` + `config/{schema,mod,view,overrides}.rs` + `src/{main,help}.rs`
  + `sandbox/launch.rs` + `profiles/claude-desktop.toml` + `docs/guide/configuration/{audio,README}.md`
  + `docs/guide/README.md` + `tests/{config,run}.rs`): a **trusted-only security field `audio = true`**
  (a boolean, mirroring `gpu` **exactly** across schema/resolve/gating/merge_app/view/`--audio`+`OPS_AUDIO`
  /`equip_for_gc`/the flagship) that opens **microphone + playback** for a graphical app. Born from the
  user reporting the mic didn't work in `claude-desktop` under `dbus = "incage"`. **Root cause (verified,
  not assumed):** a hermetic cage has no audio-server socket and no PulseAudio client library, so
  Chromium/Electron (which uses the **PulseAudio** backend for capture) has nothing to connect to; the
  mic does **not** go through a desktop portal (portals are screen-capture/camera only — getUserMedia
  audio talks to PulseAudio directly), so the in-cage GTK portal is irrelevant to it. **The hole supplies
  two pieces, both proven live via a one-shot override BEFORE any code** (spike-first, advisor-required):
  (1) **`libpulse.so.0`** — `deb.rs`'s `ELECTRON_LIBS` carries `alsa-lib` but **not** `libpulseaudio`, so
  the autoPatchelf'd app lacks libpulse and Chromium's `dlopen("libpulse.so.0")` fails; ops provisions
  `libpulseaudio` (marker `lib/libpulse.so.0`, gcroot `gcroots/audio/<rev>`, ~113 MB closure) via
  `store::provision` (**not** the `[packages]` path — that requires a `bin/`, which libpulseaudio lacks;
  `store::provision` like mesa has no such requirement) and puts its `lib` dir on **`LD_LIBRARY_PATH`**
  (unlike mesa's dedicated driver-path vars, libpulse has no indirection var, so LD_LIBRARY_PATH is the
  only mechanism — the way nixpkgs Electron wrappers do it). (2) **the host PulseAudio socket** — bind
  `$XDG_RUNTIME_DIR/pulse/native` (a PipeWire host exposes it via `pipewire-pulse`) **read-only** at the
  fixed cage path **`/run/ops-pulse`** (parity with `/run/ops-portal`/`/run/ops-dbus`), named through
  **`PULSE_SERVER=unix:/run/ops-pulse`** (same-uid → a ro bind still permits `connect()`, like Wayland).
  **Wiring nuance (advisor-driven):** the socket bind + `PULSE_SERVER` are wired whenever the host socket
  exists, **decoupled** from the libpulse provision succeeding (mirrors gpu granting `/dev/dri` even if
  mesa fails) → gives the run.rs e2e network-independent teeth; `audio::env(Option<&Path>)` returns
  PULSE_SERVER always + LD_LIBRARY_PATH when the lib was provisioned (best-effort, else the app finds no
  libpulse and simply has no audio). **deb-wrapper interaction (verified, load-bearing):** the `deb.rs`
  derivation wraps the launcher with `makeWrapper --prefix LD_LIBRARY_PATH` (**prepend, not `--set`**), so
  it prepends the app's buildInputs and **keeps** ops's inherited value → libpulse (present nowhere else)
  is found appended after buildInputs, no shadowing; a `--set` would have clobbered it and forced injection
  into the derivation instead. **Security:** the PulseAudio bus is **not** per-client isolated — a client
  captures the mic **and** every `.monitor` source (records all host audio output), so `audio` is
  trusted-only; `PULSE_SERVER` is a data path (like `WAYLAND_DISPLAY`/`DBUS_SESSION_BUS_ADDRESS`) → no
  untrusted-`[env]` denylist entry (self-DoS only), and `LD_LIBRARY_PATH` is already reserved
  (`is_reserved_env_key` matches `LD_*`). **Scope v1 = PulseAudio** (covers mic + playback); the
  PipeWire-native `pipewire-0` socket is deferred. **Live-proven end-to-end:** the real mic in
  `claude-desktop` records (user confirmed "le micro fonctionne") via the one-shot override with the full
  stack on (gui + gpu + dbus=incage); then codified, and `profiles/claude-desktop.toml` migrated to
  `audio = true`. **Tests:** 3 audio.rs unit (`host_socket`, `env`, `asound_conf`) + 2 config integration
  (untrusted-drop, the flagship untrusted-override) + 1 run.rs e2e
  `a_trusted_audio_posture_binds_the_pulseaudio_socket_into_the_cage`
  (**ran live**: socket + `PULSE_SERVER` firm network-independent teeth; **v2 update** captures a real
  32044-byte `arecord -D default` through the shim end-to-end — see below; skips without a host pulse
  socket / sandbox). fmt/clippy `-D warnings` clean, **std-only** (`audio.rs` reuses `store::provision`).
  See [[audio-hole]], [[gpu-hole]], [[dbus-hole]], [[electron-gui-profiles]].
  **`audio = true` — v2: the ALSA→PulseAudio shim, for CLI voice tools (DONE 2026-07-13)** (`src/sandbox/
  audio.rs` + `launch.rs` + `profiles/{codex,hermes,claude-code}.toml` + `docs/guide/configuration/audio.md`
  + `tests/run.rs`): the user asked *which profiles need audio*, and a source-verified research pass found
  it is **not only the GUI apps** — the terminal CLIs **claude-code** (`/voice`), **codex**
  (voice_transcription, `cpal`), and **hermes** (voice mode Ctrl+B, `sounddevice`) all have in-process voice
  input. **The load-bearing finding (golden-rule catch):** those CLI tools capture through the **ALSA API**
  (`cpal`/PortAudio/`arecord`), which does **not** honor `PULSE_SERVER`, so the v1 hole (pulse socket +
  libpulse) is **insufficient** for them — migrating their profiles to a bare `audio = true` would have been
  a false fix. v2 adds the standard **ALSA→PulseAudio compatibility shim**: ops also provisions `alsa-lib`
  (marker `lib/libasound.so.2`) + `alsa-plugins` (marker `lib/alsa-lib/libasound_module_pcm_pulse.so`),
  stages a fixed `asound.conf` (`pcm.!default`/`ctl.!default` → `type pulse`) bound ro at `/etc/asound.conf`,
  and sets `ALSA_CONFIG_DIR` (alsa-lib's `share/alsa`, holding the base `alsa.conf` that loads the plugins)
  + `ALSA_PLUGIN_DIR` + libasound on `LD_LIBRARY_PATH` — so an ALSA `default` capture/playback routes to the
  same bound pulse socket. **(ALSA is not deprecated** — it is the kernel sound layer every server runs on,
  and the alsa-plugins pulse bridge is the standard way an ALSA app reaches PipeWire/pulse.) **`AudioLayer`
  grew** from a single `root`/`lib_dir` to `roots: Vec` + `lib_dirs: Vec` + `alsa_config_dir` +
  `alsa_plugin_dir` + `asound_conf`; `env(Option<&AudioLayer>)` emits the ALSA vars alongside PULSE_SERVER +
  LD_LIBRARY_PATH; the launch binds the asound.conf when the userspace provisioned. **De-risked spike-first**
  (advisor discipline): a throwaway bwrap proved `arecord -D default` captures a real 32044-byte WAV through
  the shim in an **empty-netns** cage with only the pulse socket exposed; then the run.rs e2e was extended to
  provision `nix:alsa-utils` and do the same **through the real `ops run`** — `CAPTURED-32044` (**ran live
  29.39s**), the full ops-wired shim proven end-to-end (not just the mechanism). **Migrated** codex/hermes/
  claude-code to `audio = true` (each with an honest comment on its capture path; claude-code's `/voice`
  additionally needs a Claude.ai account, noted). **Not migrated:** the playback-only tools
  (opencode/droid/kilocode — notification sounds, lower value) and the no-audio ones (cline/pi/agy/freebuff,
  opencode-web = host-browser audio; `hermes-web` = the dashboard served headless in-cage + `forward`ed to
  the HOST browser, so its UI/mic are host-side → no cage hole). Same security/gating/flagship as v1;
  `ASOUND_CONF`/`ALSA_*` are data paths (self-DoS only, no denylist), `LD_LIBRARY_PATH` already reserved.
  **Advisor-reviewed (v2): the one fix — the Electron path is DECOUPLED from the ALSA shim.** `provision`
  was all-or-nothing, so an `alsa-plugins` fetch failure would have returned `Err` → `env(None)` → no
  libpulse on `LD_LIBRARY_PATH` → **claude-desktop's mic broken even though libpulse was available** (a
  regression of the proven flagship path). Fixed: `libpulseaudio` is the **core** (`?`), the ALSA shim
  (`alsa-lib` + `alsa-plugins` + `asound.conf`) is a **best-effort add-on** on `AudioLayer.alsa:
  Option<AlsaShim>` — a shim-provision failure warns and yields `alsa: None`, and `env`/the launch still
  put libpulse on the loader path (Electron keeps audio; only the ALSA CLI path is lost). Unit-guarded
  (`a_layer_without_the_alsa_shim_still_gives_a_native_pulseaudio_app_its_library`). The CLI mic profiles
  stay `audio = true` **default-on** (user's call over commented-opt-in). ~1009 unit + 99 config + the
  e2e (re-ran `CAPTURED-32044` after the refactor) green, fmt/clippy `-D warnings` clean. **Open ship-gate
  (honest):** claude-desktop's mic on the *shipped* `libpulseaudio` path (vs the `pulseaudio`-full
  override it was first proven with) and each CLI tool's real voice mode are the pending live-user gates.
  See [[audio-hole]].
  **catrust CA-purge — the NSS db no longer accumulates per-session CAs (DONE 2026-07-10)**
  (`src/sandbox/catrust.rs` + `tests/run.rs`): a real bug surfaced live while validating the in-cage
  portal — `ops app claude-desktop` failed every HTTPS with `ERR_CERT_AUTHORITY_INVALID`, and a full
  variable-by-variable isolation (fresh home vs the user's polluted home; chromium-150 vs the app's
  Electron-148; `ops run` vs `ops app`; all three `dbus` postures) proved it was **orthogonal to the
  portal** and preexisting. Root cause: the egress MITM CA has a **fixed subject DN** (`CN=ops egress
  proxy CA`, `proxy.rs`) but a fresh key each session, and catrust added one per launch under a
  **content-keyed nickname with NO delete** — the earlier design deemed the accumulation "harmless"
  (it is not). After N launches (the user's app home had **30**), N same-subject CAs collide on the
  NSS issuer lookup and Chromium picks a stale one whose key does not match the current cert →
  `ERR_CERT_AUTHORITY_INVALID`. **Fix:** `catrust::wrap` now **purges every `ops-mitm*` entry**
  (`certutil -L | grep -oE 'ops-mitm[0-9a-f-]*'` → `-D -n` each) **before re-adding the current CA
  under a fixed nickname** `ops-mitm`, so the persistent home's db holds exactly one. This is a
  delete-then-add, consciously **superseding** the content-keyed-nickname scheme (the accumulation
  bug beats the race it dodged). **Residual (documented honestly, not "harmless"):** a concurrent
  SECOND launch of the same app can delete the still-running first instance's CA from the shared db;
  that instance keeps failing HTTPS until its next restart — rare, since these are single-instance
  GUI apps. **Payoff: the first launch self-purges, so nobody needs a manual reset** — every GUI app
  under the allowlist (opencode-desktop too) is fixed automatically. **Live-proven on the shipped
  shell:** the user's real 30-CA broken db → one `ops app claude-desktop --dbus=incage` launch →
  **db purged to 1 CA, `net_error -202` gone, the app connects** (assets + login page load). **Tests:**
  the catrust unit test now pins the purge loop + fixed nickname (was pinning the keyed nickname +
  asserting NO `-D`), and a new run.rs e2e `catrust_purges_stale_cas_so_the_nss_db_never_accumulates`
  (**ran live 58.6s**) does **two sequential `ops app` launches** sharing the persistent home and
  asserts the `ops-mitm` count stays **1, not 2** (2 is exactly the pre-fix accumulation) — teeth on
  the actual property, not a string shape. The false "harmless" claim in the deb: entry below is
  corrected in place. 993 unit + run e2e green, fmt/clippy clean, std-only. See [[dbus-hole]],
  [[electron-gui-profiles]].
  **`dbus = "incage"` — a private in-cage desktop portal (picker + theme-at-launch), increment A
  (DONE 2026-07-10)** (`src/sandbox/portal.rs` [new] + `mod.rs` + `config/{schema,mod,view,
  overrides}.rs` + `src/main.rs` + `sandbox/launch.rs` + `docs/guide/configuration/dbus.md` +
  `tests/{config,run}.rs`; design + spike `docs/bwrap-incage-portal-plan.md`): a **third `dbus`
  posture** solving why a Chromium/Electron app's **file chooser fails** under `dbus = true`. Root
  cause (traced to the Chromium 148/Electron 42.5.1 sources shipped in claude-desktop 1.18286.2):
  `SelectFileDialogLinuxPortal` probes `Properties.Get(FileChooser, version)` on a **process-wide
  singleton** (`dbus_xdg::PortalRegistrar`), our filter **allows** that read (the theme needs it —
  `xdg-dbus-proxy` filters by destination/interface/method, **never by argument**, so the theme's
  version read and the FileChooser version read are the *same* message), so Chromium sees the host
  portal's real version (≥3), commits to the portal path, and `OpenFile` is refused by the filter →
  `CancelOpen` (the GTK fallback fires only at version <3; the M145 refactor removed the
  `--xdg-portal-required-version` escape hatch, electron#50057). **`dbus = "incage"` gives the cage
  its OWN portal:** a **private** `dbus-daemon` runs *inside* the cage carrying ops-provisioned
  `xdg-desktop-portal` + the **reference GTK backend** (`xdg-desktop-portal-gtk`), so the app probes
  *that* portal (real version 4, live-proven) and the file chooser it opens is **rendered in-cage**
  by the GTK backend — a dialog that by construction lists only the cage FS (the backend runs in the
  cage's mount ns; live `ls /` = `bin dev etc home lib64 nix opt proc run tmp usr`). **NOT GNOME-tied:**
  `xdg-desktop-portal-gtk` is the freedesktop *reference* backend (the universal fallback for
  sway/XFCE/MATE), depending only on the GTK lib the Electron app already carries; the host desktop
  never participates (works under GNOME/KDE/wlroots alike). **Config: `dbus` grew from `Option<bool>`
  to 3 postures** (`DbusPolicy{Off,HostFiltered,InCagePortal}` mirroring `GuiPolicy`; a `RawDbus`
  untagged `bool | string` keeps `dbus = true/false` and adds `"incage"`; `validate_dbus`
  fail-closes an unknown string to the default with a warning, like `validate_gui`); threaded through
  every site (schema/resolve global+project gating/merge_app/apply_override/resolve_app/view/`--dbus
  =incage` override, an unknown override value fatal→exit 2 like `gui`). **launch (`portal.rs` +
  `build`):** under `gui = "wayland"` **AND** `dbus = "incage"` — provision the 3 packages (gcroot
  `gui/<rev>`, seeded, `equip_for_gc` too), read the host theme **host-side** best-effort (the
  provisioned `dbus-send` run against the real bus → `org.freedesktop.appearance color-scheme`), and
  wrap the command **outermost** (after catrust) so a `bash -c` preamble writes the generated
  `session.conf` + `portals.conf` (`default=gtk` — the load-bearing key, NOT `XDG_CURRENT_DESKTOP`),
  seeds the GLib keyfile from the host scheme (and, under a dark host, exports `GTK_THEME=Adwaita:dark`
  so the portal's GTK3 file-dialog backend — which does not follow the `color-scheme` gsetting for its
  own theme — renders the picker dark to match the app, not light against a dark app), and starts
  `dbus-daemon --config-file … --fork` (which
  **blocks until the socket is ready** — no race, no sleep). Env: `DBUS_SESSION_BUS_ADDRESS` at the
  cage-tmpfs socket, `GSETTINGS_BACKEND=keyfile` (no dconf), `XDG_DESKTOP_PORTAL_DIR` (the GTK
  backend's `gtk.portal`), `XDG_CONFIG_DIRS` (the generated `portals.conf`) — all data paths, no
  denylist entry (self-DoS only, like `WAYLAND_DISPLAY`). **Needs `gui = "wayland"`** (the GTK backend
  renders through the compositor) and — unlike the host-filtered bus — is **network-independent** (the
  private bus touches no host socket; works even under `network = "shared"`). Best-effort throughout
  (provision fail → no portal; theme read fail → default theme; never a wider fallback). **The command
  wrap `super::egress::wrap_background` is reused** (positional `"$@"`, zero shell injection; the
  config heredocs use a quoted delimiter so the already-substituted ops-controlled content is verbatim).
  **Live-proven end-to-end through the REAL ops cage** (before any code, a throwaway spike proved
  dbus-daemon + D-Bus activation + FileChooser version 4 + the theme seed + a real `OpenFile` rendering
  an in-cage dialog + clean PID-ns teardown; and after wiring, `ops run` under a trusted
  `gui="wayland"` + `dbus="incage"` + `network="none"` project: `FileChooser version = (<uint32 4>,)`
  and `Settings.Read appearance color-scheme = (<<uint32 1>>,)` [prefer-dark, seeded] on the private
  bus, keyring `ServiceUnknown`). **The advisor caught the load-bearing scope question** (spike proved
  only the *probe*, not the *picker*): a follow-up spike proved **`dbus = false` + the (uncommitted)
  `gschemas.rs` already gives a working in-cage GTK file chooser** (schema `org.gtk.Settings.FileChooser`
  present; a zenity dialog mapped in-cage with no bus), so the picker alone is a two-line fix and the
  in-cage portal's marginal value is **theme-at-launch** (increment A) + **live theme + notifications**
  (increment B). **User chose A+B together** (nothing regresses vs `dbus = true`), cadence A-first;
  **claude-desktop stays on `dbus = true` until B** (migrating to increment-A-only would drop its
  notifications). **Increment B (next, NOT built):** reintroduce the filtered host bus (the existing
  `dbus.rs`, bound at a side path) + an in-cage keyfile updater fed by the host `SettingChanged` (live
  theme) + an `org.freedesktop.Notifications` relay on the private bus (notifications — likely a `zbus`
  dependency to validate), then migrate the profiles. **Tests:** 5 portal.rs unit (`session_conf`
  servicedirs + cage-socket-only, `env`, `wrap_command` positional shape + theme seed + no-theme,
  `parse_color_scheme`) + 1 override unit (`--dbus=incage` applies, typo fatal) + 3 config integration
  (untrusted-drop→trust for incage, flagship untrusted-override, unknown-posture fail-closed) + 1
  run.rs e2e `a_trusted_incage_dbus_stands_up_an_in_cage_portal` (**ran live 33.6s**, not skipped:
  FileChooser version served on the private bus under `network="none"` + keyring absent; skips without
  Wayland/cache). 993 unit + 97 config + run e2e green, fmt/clippy `-D warnings` clean, **std-only** (no
  new dep — `portal.rs` reuses `store::provision`/`egress::wrap_background`). **Honest scope:** the real
  claude-desktop end-to-end (login + a click on "browse folder") is the pending live-user validation, as
  for every GUI increment. *(The once-recorded caveat "the host-side theme read needs a host `/nix`
  with compatible paths" is **superseded and was wrong in both directions** — it was never a
  host-without-`/nix` problem but a read that could not run **anywhere**, and it no longer applies at
  all: the read now goes over the session bus. See the theme-read entry at the top.)* See
  [[dbus-hole]], [[gpu-hole]], [[electron-gui-profiles]].
  **`dbus = true` — a filtered D-Bus session bus in the cage (DONE 2026-07-09)**
  (`src/sandbox/dbus.rs` [new] + `mod.rs` + `config/{schema,mod,view}.rs` + `src/{main}.rs` +
  `sandbox/launch.rs` + `profiles/opencode-desktop.toml` + `docs/guide/configuration/{dbus,README}.md`
  + `docs/guide/README.md` + `tests/{config,run}.rs`): a **trusted-only security field `dbus = true`**
  (a boolean, mirroring `gpu`) that opens a **filtered** D-Bus session bus so a graphical app can
  **follow the host light/dark theme** (the desktop `appearance` portal) and **raise notifications**.
  Born from the `opencode-desktop` follow-up (the GTK theme hack the user rejected in favour of "propre
  et sécurisé avec dbus"). Exposing the **raw** session bus is unsafe — it carries the login **keyring**
  (`org.freedesktop.secrets` = every saved password) + every desktop portal — so ops runs
  **`xdg-dbus-proxy`** (Flatpak's mechanism, provisioned via nix like the fonts/mesa, gcroot
  `gcroots/gui/<rev>/xdg-dbus-proxy`) **host-side** as a **default-deny** filtering proxy, inside its
  OWN minimal bwrap (built from the audited `to_argv` — all-ns, cap-drop, `--die-with-parent`; binds
  ops's shared store ro at `/nix` so the store binary's interpreter resolves, the host bus socket ro, a
  writable `<data>/dbus` output dir; **isolated netns** — D-Bus is AF_UNIX). Only the **filtered
  socket** is bound into the agent cage at `/run/ops-dbus/bus` + `DBUS_SESSION_BUS_ADDRESS`. **The
  curated filter** (`filter_args()`): `--filter` (deny-all) then `--call=…portal.Desktop=…Settings.Read`
  + `.ReadAll` + `--broadcast=…Settings.SettingChanged` (theme, LIVE-following) + `--call=…portal.Desktop=
  org.freedesktop.DBus.Properties.Get`/`.GetAll` (read-only interface `version` metadata a portal client
  probes — **live-caught: without it Chromium/Electron hits `Properties.Get … AccessDenied` on the portal
  and the theme does not apply**; `gdbus Settings.Read` alone does NOT prove the app's theme follows —
  launch the real Electron app) + `--talk=…Notifications` — **method-scoping the portal via `--call` is
  load-bearing** (opens ONLY the Settings + read-only Properties reads, so FileChooser/Screenshot/ScreenCast
  on the SAME bus name stay refused; a whole-name `--talk` would open them all). A `DbusProxy` guard (`LaunchGuard.dbus`) kills+unlinks on Drop and **forces the supervised
  path** (the proxy must outlive the cage, never exec-replace). **Best-effort:** no host bus / provision
  fail / proxy dies → warn + run WITHOUT a bus (the raw bus is never a fallback = fail-closed; a
  `try_wait` liveness check after the socket appears catches a create-then-die). **Config side mirrors
  `gpu` exactly** (`RawConfig`/`RawApp` `dbus: Option<bool>`; `Resolved`/`ResolvedApp` `dbus` +
  `dbus_origin`; trusted/global-only gating in `resolve`/`resolve_app` with the untrusted-drop warning;
  `merge_app` replace; the flagship — a global app's dbus survives an untrusted project's override;
  `apply_override` direct-apply like `gpu`; `ops config show` a `dbus: filtered (theme + notifications)`
  line, provenance-tagged, `--app` effective + `--json`). The typed `--dbus` one-shot flag **shipped**
  alongside `--gpu` (see the entry below). **Env:** `DBUS_SESSION_BUS_ADDRESS` is NOT denylisted (unlike the mesa
  driver-path vars, which load code) — it is a data path like `WAYLAND_DISPLAY` (an untrusted `[env]`
  only mispoints the cage's own client → self-DoS). **Live-proven end-to-end through the REAL ops cage:**
  `ops run -- gdbus … Settings.Read appearance color-scheme` → `(<<uint32 1>>,)` = prefer-dark; keyring →
  `ServiceUnknown` (denied); FileChooser → `AccessDenied`. **AND the real `ops app opencode-desktop`
  launch: the Electron window renders in DARK (user-confirmed "oui noire"), the portal `AccessDenied` gone
  after the `Properties.Get` grant.** `opencode-desktop.toml` gained `dbus = true`. **Residual log noise
  (benign, not fixed):** the app probes the SYSTEM bus (`/run/dbus/system_bus_socket`), which ops does not
  expose (privileged — correct); and a `GLib-GIO-CRITICAL g_settings_schema_source_lookup` warning is
  SEPARATE (absent GSettings schemas — the theme comes via the portal, not GSettings; a glib-schema
  provisioning slice would silence it).
  **Advisor-reviewed (code + security), findings addressed.** Security review found **one real
  ship-blocker — SEC-001:** `dbus` and `network` are independent, so `dbus = true` + `network = "shared"`
  is reachable, and under `shared` the cage shares the host netns where **abstract** Unix sockets
  (`unix:abstract=…`, legacy sessions) are netns-scoped not filesystem-scoped — a hostile agent could
  read `/proc/net/unix`, find the raw bus's abstract address, and connect AROUND the proxy to the
  keyring. Fixed: the launch wires the proxy **only under an isolated netns** (`dbus_filter_enforceable(net)
  = !matches!(net, Shared)`, unit-pinned); under `shared` it warns + does NOT wire (a bypassable filter =
  false confidence; the exact residual Flatpak severs with `--unshare-net`). Every other posture
  (`none`/`deny`/`allow`/`ask`) → empty netns → airtight; the e2e uses `network = "none"` (default is
  `shared`, now skipped), opencode-desktop uses `deny` → safe. Live-proven both directions (theme under
  `none`; warn + BUS-ABSENT under `shared`). Code review **APPROVE** (folded: the `try_wait` liveness
  check; the guard-match comment now names dbus). **Accepted (documented, not fixed):** notification
  spoofing within the allowed Notifications name; `Settings.Read` not argument-scoped to `appearance`
  (the portal surfaces only appearance keys); a `SIGKILL` leaves a stale `<data>/dbus/*.sock` (0700,
  dead — housekeeping, same as egress). **Tests:** 3 dbus.rs unit (`filter_args` allow+deny sets,
  `parse_unix_path`, `proxy_spec` shape) + `dbus_filter_enforceable` (SEC-001) + 2 config gating
  (untrusted-drop + flagship) + merge_app precedence + view `--json` + 1 run.rs e2e
  `a_trusted_dbus_posture_binds_a_filtered_bus_into_the_cage` (firm netns-independent gating teeth;
  firm BUS-PRESENT+ADDR-SET when the proxy comes up, best-effort otherwise, skips with no host bus). 976
  unit + 94 config green, fmt/clippy `-D warnings` clean, **std-only** (no new dep — reuses
  `store::provision`/`to_argv`). **Scope:** fixed curated allowlist (a custom `[dbus]` table is a
  forward-compatible follow-up — `dbus` could become `bool | table`); tray icon (StatusNotifier) not in
  the set; the GSettings-schema warning is separate/cosmetic (the theme comes via the portal, not
  GSettings). **Roadmap:** NVIDIA GPU (opt-in slice), then a custom `[dbus]` interface allowlist.
  **`gpu = true` — hardware-accelerated GPU rendering in the cage (DONE 2026-07-09)**
  (`src/sandbox/gpu.rs` [new] + `mod.rs` + `config/{schema,mod,view}.rs` + `src/{main}.rs` +
  `sandbox/launch.rs` + `profiles/opencode-desktop.toml` + `docs/guide/configuration/{gpu,README}.md`
  + `docs/guide/README.md` + `tests/{config,run}.rs`): a **trusted-only security field `gpu = true`**
  (a boolean, mirroring `gui`) that opens hardware-accelerated GPU rendering. Born from live-debugging
  why **`opencode-desktop`'s Electron window never mapped**: on Wayland a Chromium/Electron app with no
  working GL **never maps a window** (its GPU process crashes `Exiting GPU process due to errors`, the
  surface gets no buffer). The hermetic cage lacks **three** things the driver needs, found in cascade
  (each fix revealed the next, live): (1) **`/dev/dri`** (else `drmGetDevices2() has not found any
  devices`); (2) **`/sys`** — the cage has NONE by design, but mesa/`drmGetDevices2` read `/sys/dev/char`
  + `/sys/class/drm` + each node's device dir to enumerate; (3) the **mesa DRI driver** (else
  `MESA-LOADER: failed to open …/gbm/dri_gbm.so` — nixpkgs mesa hardcodes `/run/opengl-driver/lib`,
  absent off NixOS). **`gpu.rs` supplies all three, all best-effort** (a missing piece degrades to
  software rendering, never fails the launch): **mesa provisioned into ops's store** (like the fonts,
  gcroot `gcroots/gpu/<rev>/mesa`) with `LIBGL_DRIVERS_PATH`/`GBM_BACKENDS_PATH`/
  `__EGL_VENDOR_LIBRARY_DIRS` pointed at its closure — **hermetic + drift-proof** (same pinned nixpkgs
  as the app → same mesa hash → no ABI skew with the app's own libgbm/libEGL, no host driver path);
  the **render node** `/dev/dri` granted through the existing `[devices]` dev-bind mechanism (appended
  to the devices vec in `build`); and the **`/sys` DRM subtree read-only, scoped LEAST-PRIVILEGE**
  (user's call over wholesale `/sys:ro`, proven equivalent for GL init) — `drm_sys_paths()` returns
  `/sys/dev/char` + `/sys/class/drm` + `canonicalize(<node>/device)` for each `card<N>`/`renderD<N>`
  (connectors `card1-DP-1` filtered by the pure `is_drm_node`). **Config side mirrors `gui` exactly**
  (`RawConfig`/`RawApp` `gpu: Option<bool>`; `Resolved`/`ResolvedApp` `gpu: bool` + `gpu_origin`;
  trusted/global-only gating in `resolve`/`resolve_app` with the same untrusted-drop warning;
  `merge_app` replace; the flagship — a global app's GPU posture survives an untrusted project's
  override; `ops config show` a `gpu: enabled` line, provenance-tagged, `--app` effective + `--json`).
  The one-shot `--config` blob override carries `gpu` (`apply_override` applies it directly — a bool
  needs no validation); the **typed `--gpu`/`--dbus` flags shipped 2026-07-09** — optional-value
  booleans (`--gpu` = true, `--gpu=true|false`, never a space-separated value so they cannot swallow an
  app name), each with an `OPS_GPU`/`OPS_DBUS` env twin, routed through a dedicated `take_flag_bool`
  in `main.rs` (not `take_flag_value`) and a shared `parse_bool` in `overrides.rs` (a value other than
  true/false is a fail-closed usage error); `--gpu=false` disables a profile's `gpu = true` for one
  launch. Consumed in `launch.rs::build` (env + `/sys` ExtraBinds +
  the `/dev/dri` device) **and** `equip_for_gc` (so `ops gc` keeps the mesa closure). **Scope
  (honest): mesa GPUs (Intel/AMD/nouveau)** — the **NVIDIA proprietary stack is OUT** (userspace
  version-locked to the host `nvidia.ko`, cannot be provisioned hermetically; a separate deferred
  slice needing a host-lib bind + PRIME offload). On the user's Optimus laptop (Intel iris + NVIDIA
  RTX 3050) it renders on the Intel iGPU — the correct GPU for a desktop app. **De-risked live before
  coding** (the scoped `/sys` subset proven == full `/sys:ro` for EGL init; the full recipe proven via
  one-shot `--bind`/`--env` overrides). **Live-proven end-to-end:** `ops app opencode-desktop` NU
  (profile `gui = "wayland"` + `gpu = true`, `--disable-gpu` dropped) renders the Electron window with
  GPU, **zero GL errors**, mesa provisioned automatically by the hole; `opencode-desktop.toml` migrated
  off the manual `[devices]`+`--disable-gpu` stopgap. **Design answers recorded (user asked):** (a)
  exposing **dbus wholesale is UNSAFE** — the session bus carries `gnome-keyring`/`org.freedesktop.secrets`
  (the whole login keyring) + portals, the system bus privileged services; the only safe path is a
  **filtered `xdg-dbus-proxy`** (interface allowlist — a deferred slice). (b) **`/proc`** is already in
  the cage (namespaced, safe); never expose the **host** `/proc` (leaks other processes' `environ` =
  secrets). (c) exposing **`/sys`** for a capability = a scoped ro subset tied to the grant, trusted-only,
  never all of `/sys`. **972 unit (+2 gpu.rs: `driver_env`, `is_drm_node`) + 92 config (+2: gpu gating
  + the flagship) green** + **1 run.rs e2e** `a_trusted_gpu_posture_grants_the_render_node_and_sys_to_the_cage`
  (firm network-independent teeth: `/dev/dri` + `/sys/class/drm` ABSENT untrusted, PRESENT trusted; the
  mesa env reported best-effort), fmt/clippy `-D warnings` clean, **std-only** (`gpu.rs` reuses
  `store::provision`). **Advisor-reviewed (code + security), findings addressed.** Security: design
  sound (gating/flagship/`/sys` ro/`/dev/dri` grant correct, within the accepted `[devices]` class, no
  boundary breach) with **one real fix — SEC-001:** the mesa driver-path env vars are **code-load
  paths** (mesa `dlopen`s a `.so` from them), unlike the data-only `FONTCONFIG_FILE`, so an untrusted
  `[env]` could have re-pointed a *trusted* GPU app's mesa at an attacker `.so` in the project tree
  (in-cage code-exec, confined but a vector a trusted app should not inherit) → the three vars
  (`LIBGL_DRIVERS_PATH`/`GBM_BACKENDS_PATH`/`__EGL_VENDOR_LIBRARY_DIRS`) are now on the untrusted-only
  env denylist (`is_reserved_env_key`, beside `LD_*`/`NIX_LD`), with a unit test; ops still sets them
  and a trusted config still may. Code review **APPROVE**; its minors folded in: the `/dev/dri` grant
  is **deduped** against a trusted `[devices]` entry; the launch comment softened (the `/sys` binds are
  firm `--ro-bind` checked at enumeration, same shape as the Wayland socket — not "never fails"); a
  direct `merge_app` gpu-precedence assertion added; a `/sys/dev/char` char-device-name-leak note added
  to `drm_sys_paths`. **Accepted (documented, not changed):** `/dev/dri` grants the whole dir incl.
  the KMS `card0` node (parity with a `[devices] allow = ["/dev/dri"]`; its dangerous ioctls need
  DRM-master held by the host compositor); the device+`/sys` are granted even when mesa provisioning
  fails (keeps the e2e's firm teeth network-independent — surface without a driver, not a fail-open).
  **Roadmap:** NVIDIA (opt-in slice, host-lib bind + PRIME), then a filtered dbus proxy.
  **`deb:` package backend — a prebuilt `.deb` provisioned host-side (DONE 2026-07-09)**
  (`src/sandbox/deb.rs` [new] + `mod.rs` + `config/{mod,view}.rs` + `packages.rs` + `launch.rs` +
  `main.rs` + `help.rs` + `profiles/opencode-desktop.toml` + `profiles/README.md` + `docs/guide/
  {configuration/packages,cli/upgrade,housekeeping/upgrade}.md`): a **fourth `[packages]` backend**,
  `deb:<url>`, so opencode-desktop stops depending on the third-party `tomsch/opencode-desktop-nix`
  flake (a single-maintainer repo, deemed unreliable by the user). A GUI/desktop app shipped **only
  as a `.deb`** (no release binary, no nixpkgs attr, an official flake whose from-source `bun` build
  is broken) is now packaged by ops directly: `Backend::Deb(url)` (`parse_backend`, `is_valid_deb_url`
  — `https://` + ends `.deb` + injection-free charset); `packages::deb_packages` (trusted-only, like
  every backend). `deb.rs` resolves the URL to an SRI hash via **`nix store prefetch-file`** (which
  follows a `…/releases/latest/download/…` redirect), pins it in a per-project **`deb-packages.lock`**
  (pin-on-first-use — reused offline after, `ops upgrade deb` re-resolves forward), and builds a
  **generated derivation** (`derivation_expr`, a `@…@`-placeholder template to keep nix `${…}`/`{…}`
  out of Rust's formatter) that `dpkg-deb -x`-unpacks the `.deb` and `autoPatchelfHook`s the Electron
  binaries against a curated `ELECTRON_LIBS` set, then wraps the launcher (found generically by its
  `resources/app.asar` signature) as `bin/<name>`. **Built HOST-SIDE** via `store::provision_expr`
  (against ops's pinned nixpkgs) — like `nix:`, seeded + offline-reusable — **not** in-cage like
  `flake:`, the justification being a `.deb` runs **no build script** (`dontBuild`), so evaluating it
  host-side is safe (unlike an arbitrary flake's eval); the build uses the **host** network, so the
  cage allowlist governs only the app's *runtime* egress. Wired in `build()` beside the `nix:`
  provision (bins → PATH, roots → the seed); `ops upgrade deb` (dispatch + `upgrade_deb_packages` +
  `deb_upgrade_summary`, mirroring flake) folded into `all`. **De-risked by a throwaway host `nix-build`
  spike first** (our own derivation, buildInputs grounded on tomsch's working set) — autoPatchelf `0
  unsatisfied`, binary + ldd clean. **Proven live under the allowlist:** `opencode-desktop` migrated
  to `deb:https://github.com/anomalyco/opencode/releases/latest/download/opencode-desktop-linux-amd64.deb`,
  host-side resolve+build → Electron 1.17.15 renders on Wayland (via the catrust CA→NSS seed), updater
  `checking → up-to-date` through the MITM, egress filtered (models.dev/opencode.ai/npmjs allowed,
  Sentry muted); `deb-packages.lock` written (pin-on-first-use), `ops upgrade deb` → `unchanged`.
  **Advisor-reviewed (code + security), findings addressed.** Security: **✅ no exploitable
  vulnerability** — every interpolated value (`url`/`name`/`hash`/`nixpkgs`/`system`) is
  charset-validated so it cannot inject nix or shell; `deb:` is trusted-only and the flagship
  override-protection holds; host-side build is safe (`dpkg-deb -x` runs no maintainer script,
  `dontBuild`, and nix's own build sandbox contains it); the CA→NSS import adds only the same
  server-auth CA the env vars already trust, into the cage's isolated home NSS db. Code review
  drove the fixes: unit tests for `declared_urls`/`all_declared_urls`/`withheld`/`deb_upgrade_summary`/
  `short_hash` (the untested mirror logic); a **deterministic** launcher pick (`sort | head`); a
  **layout-general** install (extract into a subdir, `cp -r extracted/. $out` — any prefix, no nix
  build-metadata leak); `write_pins` dir at `0o700` (matching flake); and — the security review's
  one real wrinkle — catrust's NSS nickname was keyed by the CA content (`ops-mitm-<sha256>`) with
  no delete-then-add, so concurrent same-app launches coexist. **[REVISED 2026-07-10 — the claim
  that "the accumulated dead ephemeral-CA entries are harmless" was WRONG and is fixed: every
  per-session CA shares a fixed subject DN, so N accumulated entries collide on NSS issuer lookup and
  Chromium rejects the current MITM cert (`ERR_CERT_AUTHORITY_INVALID`) after enough launches. See
  the catrust CA-purge entry at the top.]** And **`ops config show` now displays a deb's pinned short
  hash** (`@ …
  (pinned)`, keyed by URL in the same merged pin map that serves flake revs — disjoint key spaces).
  **970 unit (+5 over the pre-review 965) + 90 config green**, fmt/clippy `-D warnings` clean,
  std-only (reuses `store::provision_expr`/`nix_command` + serde_json).
  **Honest scope:** the install phase targets the **Electron layout** (locates the app by
  `resources/app.asar` + wraps its launcher) — the deb-desktop class every current target belongs
  to; a non-Electron `.deb` **fail-closes with a clear error** (a `.desktop`-`Exec` entry-point + a
  per-profile lib set would generalize it — deferred, YAGNI). **The review's `upgrade` double-collection
  is now optimized** (both backends together, for parity): `declared_urls`+`all_declared_urls` (and the
  flake twins) collapsed into a single `declared(cfg) -> Declared { trusted, all }` that walks the apps
  **once** and materializes each `merge_app` overlay a single time, feeding both the trusted roll set and
  the trust-agnostic prune universe — so `ops upgrade` no longer merges every app twice. The
  `latest`-URL TOFU/race (upstream moving between a stale lock and a genuinely-fresh rebuild — further
  mitigated now that `equip_for_gc` seeds the deb roots, so gc keeps the built output) fails closed →
  `ops upgrade deb`.
  **GUI CA trust — ops seeds the egress MITM CA into the cage's NSS db for Chromium/Electron apps
  (DONE 2026-07-08)** (`src/sandbox/catrust.rs` [new] + `mod.rs` + `egress.rs` [`CAGE_CA` →
  `pub(crate)`] + `launch.rs`): the ops-core generalization of the per-profile CA→NSS shim
  `opencode-desktop` shipped with. Chromium/Electron **ignores ops's CA-file env vars**
  (`SSL_CERT_FILE`/`NODE_EXTRA_CA_CERTS`) and verifies against its **own NSS db** (`~/.pki/nssdb`),
  so under the allowlist MITM a graphical app rejects ops's per-session CA
  (`ERR_CERT_AUTHORITY_INVALID`) and its UI cannot load. When a cage is BOTH `gui = "wayland"` AND a
  filtering `Allowlist`, ops now provisions `certutil` (`nss.tools`, part of the GUI hole like the
  fonts — **gated so only GUI+filtering cages pay the closure**, seeded into the project store) and
  wraps the command (outermost, after the egress wrap) to import the bound CA
  (`egress::CAGE_CA` = `/opt/ops/egress-ca.pem`) into the cage's NSS db before the app runs. **No new
  trust:** the cage already trusts the MITM CA via the env vars; this extends the *same* trust to the
  store Chromium reads. `catrust::wrap` rides the command **positionally** (`exec "$@"`, no config
  interpolation; only the ops-controlled certutil store path + fixed CA path are interpolated).
  **Live-caught bug (why live-verify matters):** `certutil -N` on an *existing* db — the persistent
  per-app home reuses `~/.pki/nssdb` across launches — prompts for confirmation on stdin and HUNG the
  tty-less launch; fixed by guarding `-N` on `cert9.db` absence AND redirecting every certutil step
  from `/dev/null` (delete-then-add of a fixed `ops-mitm` nickname handles the per-session CA
  rotation). **Proven live:** with the *clean* `opencode-desktop` profile (its per-profile `certutil`
  wrapper + `nss` package removed — ops does it now, cmd back to the bare Electron invocation +
  `--use-system-ca`), 1.17.15 renders under the allowlist, updater `checking → up-to-date` through the
  MITM, egress filtered (Sentry denied). **961 unit (+1 `catrust::wrap`) + 90 config green**,
  fmt/clippy `-D warnings` clean, std-only (reuses `store::provision`). **Residual:** the app still
  passes `--use-system-ca` (its own Chromium flag to consult the system/NSS store — ops cannot add app
  argv); a **dbus session bus** for GUI apps is still absent (no notifications/tray/system-keyring —
  benign for editing/chat; a keyring login falls back to a file in the isolated home).
  **opencode GUI profiles — `opencode-web` + `opencode-desktop` (DONE 2026-07-08)**
  (`profiles/opencode-web.toml` [new] + `profiles/opencode-desktop.toml` [new] + `profiles/
  README.md`; no ops code change): two graphical ways to run opencode under ops, both live-proven.
  **`opencode-web`** runs opencode's `web` server headless in the cage and reaches the host browser
  via the inbound **`forward = [4096]`** hole (a TOP-LEVEL field): `mise:opencode` (no build),
  `opencode web --port 4096` on the cage loopback, host `curl http://127.0.0.1:4096/` → HTTP 200
  (proven) — the lightest graphical path, no Electron, no in-cage build. **`opencode-desktop`** is
  the native **Electron** app (1.17.15). The desktop ships only as `.deb`/`.rpm`; opencode's OWN
  flake `#opencode-desktop` builds it from source with **bun** and its prebuild script requires
  `bun ^1.3.14` > the nixpkgs max (1.3.13) → `nix build` fails at prebuild (the same wall that kept
  `kilocode` off its flake — proven live, incl. that `max-jobs=1` clears the earlier `/homeless-shelter`
  parallel-build collision under ops's forced `sandbox = false`, and that a `--net shared` build then
  fails on the bun-version check not the network). Fixed by packaging from the **prebuilt `.deb`** via
  the community flake `flake:github:tomsch/opencode-desktop-nix#opencode-desktop` (autoPatchelf,
  github-fetched, **no bun / no source build**) + `gui = "wayland"` + Electron flags (`--no-sandbox
  --ozone-platform=wayland --disable-gpu --disable-dev-shm-usage`). **Load-bearing runtime finding:
  Electron/Chromium ignores ops's CA-file env vars** (`SSL_CERT_FILE`/`NODE_EXTRA_CA_CERTS`) **and
  trusts its own NSS db** (`~/.pki/nssdb`), so under the allowlist MITM every HTTPS fails
  `ERR_CERT_AUTHORITY_INVALID` and the UI cannot load (proven: updater `checking → error` under
  allowlist, `→ up-to-date` under `shared`). The `cmd` is a `bash` wrapper that `certutil`-imports
  ops's per-session CA into the NSS db (+ `--use-system-ca`), with `nss = "nix:nss.tools"` supplying
  certutil. **Proven live under the allowlist:** 1.17.15 built in-cage from the `.deb`, the Electron
  window rendered on the Wayland compositor, and `ops net logs` showed models.dev / opencode.ai /
  registry.npmjs.org (the `@opencode-ai/plugin` runtime fetch) allowed and Sentry telemetry denied —
  `[network] mute = ["*.sentry.io"]` keeps that refusal out of the default log. **Gotcha recorded:** a
  floating `flake:` package's out-link is keyed by package NAME, so switching the flake ref for the
  same name reuses the stale build — remove the out-link (or `ops upgrade flake`, which pins a
  rev-keyed out-link) to rebuild. **Upgrade:** `ops upgrade flake` rolls the app's flake package
  (bounded by what tomsch's flake pins); a floating package is sticky to its first warm build until
  then. **Follow-up now DONE (see the entry above):** the CA→NSS seeding was generalized into
  ops-core (`catrust`), so `opencode-desktop`'s per-profile `certutil` wrapper was removed; a dbus
  session bus for GUI apps remains absent (no desktop notifications/tray/keyring, benign for
  editing/chat). `the_shipped_profiles_import_and_resolve` now covers 12 profiles.
  **`[network] mute` — SELinux-`dontaudit` egress-log suppression (DONE 2026-07-08)**
  (`src/allowlist.rs` + `config/{schema,mod,view,manage}.rs` + `sandbox/{control,proxy,egress,
  netlearn}.rs` + `{main,help}.rs` + `docs/guide/networking/{observability,rules}.md` +
  `configuration/network.md` + `cli/net.md` + `profiles/agy.toml` + `tests/{config,net}.rs`):
  bringing up the **Antigravity CLI (`agy`)** surfaced the recurring pain that a busy agent hammers
  hosts a user has **deliberately left denied** (telemetry, feature flags, an optional Playwright
  CDN), and those refusals drown the *actionable* denials in `ops net log`. A **`mute` list** (the
  analogue of SELinux `dontaudit`) suppresses a **denied** request's log line **without changing the
  verdict** — the request is still refused and still counted in `ops net stats`, only its line drops
  out of the default log (`ops net log --all` shows it, tagged `muted`). The single load-bearing
  invariant: **`mute` is a log filter, never a verdict** — consulted only at logging time
  (`EgressPolicy::muted`, `Layer::L7`, same canonicalized request + method-set semantics as
  `explain`), so a mute can *never* open egress. Shipped in **three increments + a residual pass**,
  all green (960 unit + 56 net + 90 config + 14 help, fmt/clippy clean, live-smoked). **Increment 1
  — declarative:** `NetworkTable.mute` (`#[serde(default)]`), classified via the same
  `classify_entries` as allow/deny (grammar + `@group` expansion), gated **trusted/global-only** for
  free (it rides the whole-`[network]` trust gate — an untrusted project cannot blind the user).
  `EgressPolicy` gains `mute: Vec<Rule>` + `with_mute` + `muted()`; the proxy's single decision
  chokepoint `outcome()` routes a mute-matched **deny** to the log's **separate** ring
  (`LogInner.muted`, own cap) so a chatty muted host can never evict a real event, and the event
  carries a `muted` flag on the wire (`muted=1`) that `ops net log --all` folds back in. Rendered
  (dim `muted` tag) + `--json` `"muted"`, surfaced in `ops net rules` (`NetRuleKind::Mute`) and
  `ops config show` (`NetworkView::Allowlist.mute`). **A real bug the proxy test caught:**
  `union_with_builtin` **and** `effective_policy` rebuilt the policy from allow/deny and **dropped the
  mute set** — fixed (both carry it), else config mutes would be silently ignored. **Increment 2 —
  config verbs:** `ops net mute <rule>` / `ops net unmute <rule>` (all scopes `--local`/`--global`/
  `-a <app>`, trust-gate + re-trust, idempotent), `EgressList::Mute` + `manage::remove_egress_rule`
  (new — the inverse of `add_egress_rule`) + `MuteNeedsPosture` (a mute with no filtering posture is
  inert → refused, not written). **Increment 3 — live `--session`:** `ops net mute … --session
  [-a] [--all]` loads into a running session's overlay (a **dedicated** `ManualInner.mute` +
  `remember_mute` + a `REMEMBER MUTE` control verb + `inject_mute` — deliberately **not** a
  `Verdict::Mute`, which would pollute the park-answer paths); `effective_policy` folds config-mutes
  ∪ session-mutes and `outcome` consults the **effective** policy, so a session mute suppresses
  exactly like a config one. `unmute` stays config-only by construction (a log filter has no
  counter-verdict — a live mute ends with the session, parity with allow/deny having no live-forget).
  **Residual pass:** a live mute now lists in `ops net rules --source session` (a 3-state
  `ManualKind` allow/deny/**mute** replacing the binary `is_allow`; `RULES` emits `manual mute`,
  `query_manual` parses it, `net_rules_manual` maps it), and `unmute` of the last entry drops the
  key (no `mute = []` residue, table + inline forms). **Profile:** `profiles/agy.toml` carries a
  `mute` block (`play.googleapis.com` telemetry, `antigravity-unleash.goog` feature flags, the three
  `playwright*.azureedge.net` driver mirrors) so `ops net log -a agy` reads clean by default.
  **Tests (net-new):** allowlist `muted`/method-scope (2), config classify+group (1), proxy
  config-mute + session-mute routing (2), control `REMEMBER MUTE`/`RULES` + wire round-trip, manage
  add/remove round-trip + posture-guard (2), config-integration gating+visibility (1), net-integration
  mute/unmute round-trip + `--session` no-op + posture/refusal (2). **std-only, no new dep.** The
  `--session` overlay path reuses the proactive `ops net allow|deny --session` machinery.
  **Synthetic `/etc/hosts` — `localhost` resolves in the cage (DONE 2026-07-08)** (`src/sandbox/
  binds.rs` + `tests/run.rs` + `profiles/agy.toml` [new] + `profiles/README.md`): bringing up the
  **Antigravity CLI (`agy`)** profile surfaced a real cage gap. `agy` starts an internal language
  server that binds `localhost`; the hermetic cage carried **no `/etc/hosts`**, so resolving the
  *name* `localhost` fell through the file lookup to DNS — which the Model-B empty netns has no
  resolver for (`resolv.conf` points at the unreachable `127.0.0.53` stub) — and `agy` exited
  immediately (`CLI failed to start … lookup localhost … connection refused`). The loopback
  *interface* was already up (the egress `socat` forwarder binds `127.0.0.1`); only the *name*
  failed. **This falsifies the premise recorded in the cage-naming entry below** that `/etc/hosts`
  was safe to drop because "the tools that warn `unable to resolve host` aren't in the cage" — `agy`
  does not warn, it **hard-fails**. Fix: a **synthetic `/etc/hosts`** (`hosts_contents`) mapping
  `localhost` **and** the cage's own `ops-<slug>` hostname to loopback (v4 + v6), materialized via
  `write_atomic` beside the synthetic identity (outside every writable mount, so the agent cannot
  rewrite its own name resolution) and bound **read-only** at `/etc/hosts` in `assemble` — the same
  pattern as `/etc/passwd`/`group`. **Security-neutral:** it is *synthetic* (never a bind of the
  host's `/etc/hosts`, which would leak the user's other host entries), contains only loopback
  mappings, and adds no network reach — the loopback interface was already up; only name resolution
  is added. Broadly useful beyond `agy` — any tool that binds or reaches an internal `localhost`
  server (an in-process language server, a dev server, a local MCP) needed it. The hostname line
  reuses `naming::cage_hostname(&slug)`, the exact value the argv passes to `--hostname`, so the two
  cannot drift; `build_spec` computes the slug once, before materializing hosts and again at
  `with_cage_slug`. `/etc/hosts` added to `STRUCTURAL_DESTS` (the bind-nesting guard). **Tests:**
  2 unit (`hosts_contents` maps localhost + hostname to loopback only; `assemble` emits the ro
  `/etc/hosts` bind) → 36 `binds` tests green incl. the real-cage smokes; **1 run.rs e2e**
  `the_cage_resolves_localhost_via_a_synthetic_hosts_file` (**ran live 24.7s**, not skipped): under
  a trusted `network = "none"` (empty netns — the exact failing condition, where only `/etc/hosts`
  can answer) `curl -v http://localhost:1` resolves to `127.0.0.1` (a connection error, nothing
  listening) and never reports "could not resolve host". fmt/clippy `-D warnings` clean, **std-only**
  (no new dep). **Live-proven for `agy`:** with the fix its language server starts (the `lookup
  localhost` error is gone from its `cli.log`) and the process reaches the Google Sign-In step
  (blocks awaiting login) instead of quitting immediately. **The `agy` profile** (account/OAuth
  class, `mise:aqua:google-antigravity/antigravity-cli`, no `[secret]` — Google does not support a
  BYOK header key for the CLI) equips fresh (1.0.16) and runs headless (`--version`/`--help`
  confirmed the `-p`/`--print` mode); the remaining pending items (the OAuth **keyring**-vs-file
  persistence, and the runtime **model host**) need a real Google account — the standard live-auth
  step deferred for every profile.
  **One-shot `--seccomp` / `--device` flags — closing the two fail-closed override residuals (DONE
  2026-07-07)** (`src/config/overrides.rs` + `config/mod.rs` + `src/{main,help}.rs` + `docs/guide/
  configuration/{seccomp,devices,overrides}.md` + `tests/{config,run}.rs`): the two typed one-shot
  overrides named-but-deferred by the `[seccomp] allow` and `[devices]` increments. Until now
  `apply_override` **ignored** an override's `[seccomp]`/`[devices]` (`seccomp: _, devices: _`) — the
  fail-closed direction. Now `--seccomp <token[,token…]>` (repeatable, `OPS_SECCOMP` comma-list) and
  `--device <path>` (repeatable, `OPS_DEVICE` single, one path per flag — **not** comma-split, mirroring
  `OPS_BIND`) relax the mandatory syscall denylist / grant a host device for a **single launch**. **The
  security basis is parity with the trusted config, NOT the `--net`/`--bind` axis** (the advisor's
  load-bearing catch — an earlier "no wider than `--net shared`/`--bind :rw`" framing was a **category
  error**: `--net`/`--bind` widen host reach, but `--seccomp` re-permits a syscall whose *only*
  containment was the filter → widens the in-cage **kernel attack surface**). The sound justification,
  now in all four doc/comment sites: a config file gates `[seccomp]`/`[devices]` **trusted-only**, and
  the override is **trusted by invocation** — the invoker strictly outranks any config layer, so it may
  declare exactly the relaxation/grant a *trusted config already can*. Both are **additive collections**
  (union, fail-closed: a bad token/path is warned+skipped by the same `apply_seccomp`/`apply_devices`/
  `union_devices`/`SeccompPolicy::union` helpers the config path uses, stamped `Provenance::Override`,
  never fatal — `validate_override` unchanged, only scalar postures are fatal-up-front). **Fold bug
  fixed en passant:** `overlay_into` did **not** copy `seccomp`/`devices`, so even a `--config` blob's
  `[seccomp]` was silently dropped before apply — a new generic `union_allow_opt` unions both across the
  four tiers (regression-guarded). `scan_ambient` reads `OPS_SECCOMP`/`OPS_DEVICE`; both are
  **security-field env-source-noticed** (anti stale `OPS_SECCOMP` — carries more weight than `OPS_NET`
  given the kernel-surface axis). `main.rs` two dispatch arms; `ops config show` reflects the ambient
  `OPS_*` tagged `(override)` (live-verified). **Tests: net-new 8 unit** (collect/merge/notice/apply
  incl. union-onto-trusted-baseline, malformed-fail-closed, and the **blob-survives-the-fold** regression
  guard), **1 config integration** (`config show` reflects `OPS_SECCOMP`/`OPS_DEVICE` tagged override),
  **1 run.rs e2e** `a_typed_one_shot_security_override_reaches_the_cage` (**ran live ~22s**): `--device`
  = measurable teeth (device ABSENT without the flag, PRESENT with it, **no `ops trust`** → trusted-by-
  invocation + the flag→collect→apply_override→build_spec→`--dev-bind-try` thread); `--seccomp ptrace`
  rides the same launch = **threading coverage** for the seccomp arm (an override-sourced `SeccompPolicy`
  through the real `build_spec`→`with_seccomp`→`memfds`→`--add-seccomp-fd` path — a union/apply bug
  corrupting the policy would fail here). **Honest scope (advisor-noted):** the seccomp arm is *threading*,
  not kernel *enforcement* — no base tool triggers a denied syscall distinguishably, so enforcement teeth
  stay in `seccomp.rs` real-cage tests on a byte-identical policy. 951→ green unit + 89 config + the e2e,
  fmt/clippy `-D warnings` clean, **std-only** (no new dep). Advisor-reviewed (**APPROVE** — the two
  non-blocking asks both applied: the parity-not-blast-radius correction, and the seccomp-arm threading
  coverage folded into the e2e). **Residual:** none material — the override path now covers every
  security field.
  **`[devices]` — a trusted grant of host device nodes into the cage (DONE 2026-07-07)**
  (`src/config/{schema,mod,view}.rs` + `src/sandbox/{spec,argv,binds,launch}.rs` + `src/{main,help}.rs`
  + `docs/guide/configuration/devices.md` [new] + `docs/guide/{README,configuration/README,concepts/
  enforcement}.md` + `tests/{config,run}.rs`): the cage's `/dev` is a **minimal, hostless** tree
  (null/zero/urandom/tty/full/ptmx/pts/shm/std\* — verified live against bwrap's `--dev`), so a tool
  needing the GPU (`/dev/dri`), a VPN tunnel (`/dev/net/tun`), KVM (`/dev/kvm`), or FUSE (`/dev/fuse`)
  could not reach one. A new **`[devices] allow = ["/dev/…"]`** field lets a **trusted** config
  (global or a trusted project) bind a host device node over the minimal `/dev`. **Modelled on
  `[seccomp]`/`forward`** — a set that **unions** across layers with a single `Provenance` origin,
  gated **trusted/global-only** (a device widens the kernel attack surface, so an untrusted project's
  `[devices]` is **dropped + warned**; the flagship holds — a global app's grant survives an untrusted
  project's widening, its own integration test). **Sandbox side = modelled on `binds`** (devices are
  filesystem exposure = mounts): a new `Mount::DevBind{src,dest}` → bwrap **`--dev-bind-try`** (a
  `-try` so a device absent on this host is **skipped, not fatal** — a portable GPU/kvm profile still
  launches everywhere; the missing-device firm-bind bricks, verified live). Emitted in `assemble`
  **after** the structural `Mount::Dev` (so the real device layers *over* the hostless `/dev` rather
  than being shadowed — the mount-order is load-bearing and unit-tested), src==dest (bound at its own
  `/dev/*` path). **Validation is purely lexical** (`validate_device_path`: absolute, strictly under
  `/dev/`, no `..` component, refuses the bare `/dev`/`/dev/`) so `resolve` stays **pure** (no I/O,
  mirrors `apply_seccomp`); a malformed entry is dropped + warned (fail-closed), the rest kept. **No
  stderr caution** (unlike seccomp's per-dangerous-token cautions) — a device grant is uniform and
  `warnings` print on *every* launch, so the risk is surfaced in `ops config show` + the docs, not as
  per-launch noise. **Config** (`config/`): `RawDevices{allow: Vec<String>}` on `RawConfig`+`RawApp`;
  `Resolved`/`ResolvedApp` gain `devices: Vec<PathBuf>` + `devices_origin`; `apply_devices` +
  `union_devices` (mirror `apply_seccomp`/`union_forward`); global+project gating in `resolve`,
  global+project app gating in `resolve_app`, `merge_app` does `union_devices(&mut self.devices,
  app.devices)` (so an `ops app` launch's grant = baseline ∪ app). Threaded via `Overlay`-sibling
  param: `build_spec` gains `devices: &[PathBuf]` (`&prep.cfg.devices` post-`merge_app`, like the
  seccomp policy), `assemble` emits the `DevBind` mounts (`#[allow(clippy::too_many_arguments)]`, same
  as `build_spec`). A one-shot override **does not grant** a device (`apply_override` ignores
  `[devices]` — the fail-closed direction, like `[seccomp]`). **`ops config show`** renders a
  `devices:` line (baseline, provenance-tagged) + the per-app compact roster + the `--app` effective
  (union) view with `inherited`/`app:*` provenance; `--json` carries the sorted path array. **Tests:**
  net-new **9 unit** (`validate_device_path` accept/reject incl. `..`-escape + bare-`/dev` + non-`/dev`;
  resolve default-empty / trusted-union / untrusted-drop-flagship / malformed-drop; `merge_app` union;
  app-level flagship + trusted-app; argv `DevBind`→`--dev-bind-try`; binds `assemble` emits DevBind
  after `--dev` with src==dest), **4 config integration** (untrusted-dropped-then-trusting-applies;
  malformed-dropped; the flagship untrusted-widen via `--app`; `--json`), **1 run.rs e2e**
  (`a_trusted_devices_grant_binds_a_host_device_into_the_cage` — **ran live 21s**, real teeth: the
  device is **ABSENT** in the untrusted probe's minimal `/dev` and **PRESENT** only after trust, so it
  appears *solely* because of the grant; picks the first of `/dev/net/tun|fuse|kvm|dri` present on the
  host, skips if none). fmt/clippy `-D warnings` clean, **std-only** (no new dep). **Honest scope:** a
  grant binds the device *node*; actual *use* is still governed by the device's file perms + the host
  uid (same-uid) — visibility, not new privilege. Some devices need more than the node — **`/dev/fuse`
  also needs `[seccomp] allow = ["mount"]`** (the mandatory denylist refuses `mount`), **`/dev/net/tun`
  is most useful under `network = "shared"`** — both documented. Re-exposing a device is
  surface-reduction undone, not a boundary breach (cap-drop + single-uid userns unchanged). Docs: new
  `configuration/devices.md` (grammar, when-you-need-it table, the fuse/tun interactions, why
  trusted-only, per-app) + index links + an `enforcement.md` minimal-`/dev` note. **Deferred:** a
  one-shot `--device` flag (the override path ignores `[devices]`, fail-closed); devices outside
  `/dev/` (lexically refused).
  **`[seccomp] allow` — a trusted relaxation of the mandatory syscall denylist (DONE 2026-07-07)**
  (`src/sandbox/seccomp.rs` + `spec.rs` + `binds.rs` + `launch.rs` + `smoke.rs` + `config/{schema,mod,
  view}.rs` + `main.rs` + `help.rs` + `docs/guide/configuration/seccomp.md` [new] + `tests/{config,
  run}.rs`): the M4.1 denylist was **unconditional** — no tool needing a denied syscall (`gdb`/`strace`
  → `ptrace`, `perf` → `perf_event_open`, CRIU → `userfaultfd`, nested containers → `unshare`/`mount`)
  could run in a cage, even in a fully-trusted project. A new **`[seccomp] allow = [...]`** field lets a
  **trusted** config (global or a trusted project) re-permit specific denied syscalls. **Grammar is
  uniform (the user's explicit call, over an initial refuse-the-dangerous design):** a **bare syscall
  name lifts the whole syscall** (`ptrace`, `unshare`, `mount`), and `clone`/`ioctl` — the only two
  *argument-filtered* denylist entries — additionally accept a **`:selector`** (`clone:newns`,
  `ioctl:tioclinux`) that lifts one sub-rule and leaves its siblings denied. **No refusals** — every
  token that reopens a real escape surface is applied but flagged with a graduated **`Caution`**
  (`clone`/`clone:newuser`/`clone3` → userns creation; `ioctl`/`ioctl:tiocsti`/`ioctl:tioclinux` →
  terminal injection; `umount2` → a mount teardown that can defeat a control-plane pin). Each string
  is also **comma-splittable** (`"ptrace,unshare"` ≡ two entries), and an unknown/malformed token is
  **dropped + warned** (fail-closed — loosens nothing). **`allow = []` ≡ the current mandatory
  denylist, byte-identical** (the field can only subtract). **Engine** (`seccomp.rs`): the denied set
  is refactored to **single-source `(name, number)` tables** (`eperm_unconditional_named`/`enosys_named`
  → both the compiled filter *and* the allow-token lookup, so the allowable set cannot drift from the
  denied set); a `SeccompPolicy { whole, clone_flags, ioctl_reqs }` (default empty) drives
  `eperm_rules(&policy)`/`enosys_rules(&policy)` (skip a lifted whole syscall; keep only the
  non-lifted clone flags / ioctl requests; drop the clone/ioctl entry entirely when every sub-rule is
  lifted); `resolve_allow(token) -> Result<(Allow, Option<Caution>), String>` is the parser
  (bare=whole, `:selector`=subset, `:selector` on a non-filtered syscall rejected); `programs(&policy)`
  **skips an emptied filter** (seccompiler rejects an empty rule set) so a fully-relaxed filter is
  omitted rather than a panic; `tokens()` reverse-maps for display (same tables → shown ≡ enforced).
  **Threading:** the policy rides on `SandboxSpec.seccomp` (default empty, `with_seccomp` builder),
  set in `binds::build_spec` from `prep.cfg.seccomp` (post-`merge_app`, so an app's union is in effect
  for `ops app`, like limits), consumed by `seccomp_argv`/`supervise`/`smoke` via
  `memfds(&spec.seccomp)`. **Config** (`config/`): `RawSeccomp{allow}` on `RawConfig`+`RawApp`;
  `Resolved`/`ResolvedApp` gain `seccomp: SeccompPolicy` + `seccomp_origin`; modelled on **`forward`**
  (a set that **unions**, single origin) not `limits` (per-field) — gated trusted/global-only in
  `resolve`/`resolve_app` (untrusted layer's `[seccomp]` dropped + warned), `merge_app` does
  `self.seccomp.union(&app.seccomp)`. **The flagship holds** (a global app's relaxation survives an
  untrusted project's widening, because the untrusted contribution is dropped before the union — its
  own integration test). A one-shot **override does not relax** the denylist (`apply_override`
  ignores an override's `[seccomp]` — the fail-closed direction; the deferred residual). **`ops config
  show`** renders a `seccomp allow:` line (baseline, provenance-tagged) + the per-app compact roster +
  the `--app` effective (union) view with `inherited`/`app:*` provenance; `--json` carries the token
  array. **Tests:** net-new **15 unit** (`seccomp.rs`: token parse incl. rejections, surgical
  filtering [bare `clone`/`ioctl` drop the whole entry without touching the sibling arg-filtered
  syscall; `clone:newns` leaves one clone rule], `tokens()` round-trip, union, and **two dedicated
  real-cage teeth via a shared `run_probe` helper** — `a_bare_seccomp_allow_lifts_a_whole_syscall_in_a_real_cage`
  (`allow=["ptrace"]` → live `ptrace(TRACEME)`→0 [lifted], `keyctl`→EPERM [surgical]) and
  `a_seccomp_selector_lifts_only_the_named_sub_rule_in_a_real_cage` (`allow=["ioctl:tioclinux"]` →
  `ioctl(TIOCLINUX)`→non-EPERM [selector lifted] while `ioctl(TIOCSTI)`→EPERM [sibling still denied]),
  **both ran not skipped**; plus the unchanged default-denylist real-cage test. Note: a bare `clone`
  / `clone:xxx` lift is proven at parse + filter-construction level but **not** kernel-probed —
  clone(NEWUSER) *succeeds* and forks a child [messy probe], clone(NEWNS) is CAP_SYS_ADMIN-gated
  [EPERM indistinguishable from seccomp] — so the selector *mechanism*'s kernel teeth ride on the
  identical arg-filter codegen exercised by `ioctl:tioclinux`), **4 config integration** (untrusted-dropped/trusted-applies + canonical tokens +
  comma-split; caution + unknown-dropped; the flagship untrusted-widen; `--json`), **1 run.rs e2e**
  (`a_trusted_seccomp_relaxation_launches_a_working_cage` — the config→spec→`memfds(&policy)`→bwrap
  thread a `build_spec` unit test cannot reach; **ran live 21s**). **933→ green unit + 4 config + the
  e2e**, fmt/clippy `-D warnings` clean, **std-only** (no new dep — reuses `seccompiler`).
  **Honest scope:** kernel *enforcement* teeth live in `seccomp.rs`'s real-cage tests (no base-tool
  triggers a denied syscall distinguishably, so the run.rs e2e proves *threading + non-regression*,
  not enforcement — named). Re-permitting mount/ns is **surface-reduction undone, not a boundary
  breach** (cap-drop + single-uid userns still neuter a nested userns) and does **not** re-enable
  nix's inner sandbox. Docs: new `configuration/seccomp.md` (grammar, cautions, per-app, why-not-a-
  boundary) + `configuration/README.md` + top guide index + a relaxation note in
  `concepts/enforcement.md`. **Deferred:** a typed one-shot `--seccomp` flag (the override path
  currently ignores `[seccomp]`, fail-closed).
  **Cage naming — one `ops-<slug>` name across the scope, hostname, and `ops ls` (DONE 2026-07-05)**
  (`src/sandbox/naming.rs` [new] + `cgroup.rs` + `argv.rs` + `binds.rs` + `spec.rs` + `mod.rs` +
  `src/main.rs`): a cage had three opaque/undifferentiated names — the systemd scope was
  `run-p<pid>-i<pid>.scope`, the in-cage hostname was a fixed `sandbox` for **every** cage, and
  `ops ls` showed only `[run]`/`app:<name>`. They now all read **one** readable name, `ops-<slug>`,
  derived once from the launch's **own** identity (the app name for `ops app <name>`, else the
  project's directory name — never an untrusted field, so naming grants no new host influence;
  security-neutral, since the project is already bind-mounted at its real path in-cage). A new pure
  `naming` module owns the shared derivation: `cage_slug` sanitizes to the charset common to a
  systemd unit name **and** a DNS hostname label (lowercase `[a-z0-9-]`, common accented Latin
  transliterated — `café`→`cafe`, `Zürich`→`zurich` — every other non-alnum→`-`, collapse/trim,
  bounded to 50, empty→`cage`); `cage_hostname`/`scope_unit`/`cage_name` compose the three faces. The slug is carried on `SandboxSpec.cage_slug` (default `cage`, builder `with_cage_slug`),
  computed once in `binds::build_spec`. **Face 1 — systemd scope** (`cgroup::wrap`/`scope_wrapper`):
  `--unit=ops-<slug>-<pid>.scope`, so `systemctl --user`/`ps`/`systemd-cgls` read it. Uniqueness is
  **load-bearing** — `systemd-run` fails a launch on a live unit-name collision, so `--collect` (frees
  a finished name) + the launcher pid (two cages of one project share a slug) is required; the one
  multi-cage-per-process path (`ops upgrade`) is sequential. Probed live that `--unit=X.scope` yields
  exactly `X.scope`. **Face 2 — hostname** (`argv.rs`): `--hostname ops-<slug>` (was the fixed
  `sandbox`); still never reveals the *host's* hostname (the unshared UTS ns's point); affects
  `$HOSTNAME`/`uname -n`. **Face 3 — shell prompt** (`binds.rs` `SHELL_RC_CONTENTS`): a
  `PS1='(\h) \w\$ '` set **before** the home's `.bashrc` source (an overridable default), so `\h`
  resolves to the `ops-<slug>` hostname and `ops shell` reads `(ops-<slug>) <cwd>$` instead of the
  bare `bash-<v>$`. **Face 4 — `ops ls` NAME column** (`main.rs::list_sessions`): computed **at render
  time** via `sandbox::cage_name(s.app(), &s.project)` from the session record, so it **cannot drift**
  from the scope/hostname (the single-slug design's whole point). **Golden-rule live verifications that
  shaped the design:** the `hostname` *command* is not in the cage (base toolset), and the prompt did
  **not** show the hostname (the synthetic bashrc set no `PS1` → bash's compiled `bash-<v>$` default) —
  so a hostname change alone doesn't touch the prompt (the PS1 was added deliberately, user-chosen via
  AskUserQuestion); and `/etc/hosts` was **dropped** as a non-problem (nothing binds it, `sandbox`/
  `localhost` already don't resolve with zero complaints, and the tools that warn `unable to resolve
  host` — `sudo`/`getent`/`hostname` — aren't in the cage, so it would only widen the mount surface).
  All three faces **live-proven to show the same name** for one cage (`ops-lsname` scope+hostname+ls;
  `ops-hostv2` env/uname; `(ops-ptyprompt) …$` real pty prompt). Increment-1 non-regression closed per
  the advisor: exec path (live `ops run`) + pty path (`shell.rs` 2/2) + limits still land with `--unit`
  present (`run.rs` cgroup e2e). **867 unit** (net-new: 9 naming + 2 argv hostname + 1 cgroup `--unit`
  [ran with teeth on this host] + 1 binds PS1-order) green, fmt/clippy `-D warnings` clean, **std-only**
  (no new dep). Shipped incrementally (scope → hostname+prompt → ls), advisor-reviewed (direction + the
  incr-1 gap-close + the verify-first discipline on the two hostname premises).
  **Proactive `ops net allow|deny <rule> --session` + the effective-policy pivot (DONE 2026-07-05)**
  (`src/sandbox/{control.rs,proxy.rs,egress.rs}` + `src/{main,help}.rs` + `docs/guide/networking/
  {ask,rules}.md` + `cli/net.md` + `tests/net.rs`): a `--session` egress rule can now be **loaded into
  a running session's live overlay** proactively — `ops net allow http://host --session [-a <app>]
  [--all]` — the forward sibling of `ops net pending allow <id> --session` (which decides a request that
  *already* parked). The load-bearing fix is a **design pivot**: the manual overlay is **folded into the
  proxy's effective policy per request** (`proxy::effective_policy` = config `allow/deny` ∪ overlay
  `allow/deny`, carrying `default_action`/`ask_timeout`/`ask_notice`, borrowing `ctx.policy` when the
  overlay is empty), consulted at **all three enforcement sites** (`explain` CONNECT · `explain_clear`
  `http://` cleartext · `l4_decision` `tcp://` splice) — so a `--session` rule takes effect in **every**
  filtering posture (allowlist `deny`, denylist `allow`, and `ask`), not only `ask`. This closes the real
  gap the user hit: their agents run **allowlist**, where the old ask-only overlay did nothing. Precedence
  is **deny-wins, free from `explain`**: a `--session deny` cuts a config-allowed host, while a config
  **explicit** deny stays authoritative over a `--session allow` (a live allow only opens a *default*-
  denied host — the exact `http://google.fr`-not-in-allowlist case). SSRF is auto-correct: the deciding
  rule is the actually-matched effective rule, so a broad `--session allow *.dom` does **not** unlock a
  private IP (wildcard ≠ exact host) while an exact host:port does (the deliberate "approve an internal
  target"). The pivot **removes** the old separate-overlay path (`ManualVerdict`/`ManualRules::decide`
  gone; `remember`/`remember_rule`/`snapshot`/`is_empty` stay as storage). Control gains a `REMEMBER
  ALLOW|DENY <rule>` verb (rule verbatim via `splitn`, re-`classify`d server-side; `CMD_MAX`→8K) + client
  `inject_rule`; `--session` writes **no config** (so no re-trust — the reason it is overlay-only, never
  additive to a config write) and is scoped current-project / `-a <app>` / `--all` (mirrors `pending
  --all`). `egress.rs` now wires the overlay for **every** filtering posture (`with_control` unconditional;
  `notices` stays inert off-`ask` — it is read only in the park closure). **`ops net rules --source session
  -a <app>`** now filters the live listing to that app's sessions (was refused — closing the load-vs-list
  asymmetry). **Reason-shift to know:** a remembered/`--session` **deny** now surfaces `denied-by-rule`
  (a deny rule in the effective policy), not `asked-denied`; `asked-denied` is kept for the ask
  park-**timeout** path. **LIVE-PROVEN (the definitive proof, the user's exact scenario):** a running
  allowlist cage looping `curl http://example.com` flipped **403 → 200** the instant `ops net allow
  http://example.com --session` was injected — no relaunch, no config write — and the same on a real `ops
  app` session with `-a`. ~860 unit + config 80 + **net 54** + help 14 + the 3 egress launch e2e green,
  fmt/clippy `-D warnings` clean, **std-only** (reuses `Cow`/`RwLock`). Advisor-reviewed (plan AND impl —
  the impl review's five gotchas all closed: `Methods::Unspecified` admits every verb so an unscoped
  overlay allow opens GET **and** POST; `effective_policy` carries the ask fields; the park path + its
  exact-host deciding rule preserved; all three sites **and** the splice SSRF threaded; the reason-shift
  with the two tests updated).
  **Egress `http://` scheme — inspected cleartext (DONE 2026-07-04)** (`src/allowlist.rs` +
  `src/sandbox/proxy.rs` + `config/mod.rs` + `main.rs` + `help.rs` + `tests/run.rs` +
  `docs/guide/networking/rules.md` + `configuration/network.md`): the egress grammar closed its one
  inconsistency — **every posture was expressible except plaintext HTTP**. A tool doing `curl
  http://host` in the cage got `405 only CONNECT supported`, with **no rule that could ever permit
  it** (the proxy rejected the absolute-form before any policy lookup, and `split_scheme` rejected an
  `http://` rule). Now an **`http://host` rule** selects a third enforcement path, `Layer::L7Clear`
  (**inspected cleartext**): the *same* HTTP policy as the MITM default — host/port/path/method
  matching, the anti-fronting `Host` check, the outbound-secret tripwire, the SSRF guard — on a
  **plaintext** connection (no TLS to terminate, so no leaf minted, no upstream cert validated). It is
  the plaintext sibling of the `tcp://` splice and shares its two invariants: **strictly opt-in** (only
  an explicit `http://` allow opens it; the default action is **never** consulted — a `deny`/`allow`/
  `ask` posture never silently opens plaintext, and under `ask` an unmatched cleartext request
  **denies rather than parks**, since a live prompt cannot convey "unencrypted"), and **deny wins
  layer-agnostically** (any deny matched by kind suppresses it — a bare `deny evil.com:80` and an
  `http://` deny both block; a wrong-port deny does not, same consequence the splice documents). Its
  one loss versus the default is transport confidentiality **and** credential injection — a header
  secret is **never** sent in the clear, so [`handle_cleartext`] skips `matching_injections` wholesale
  (not merely trusting the validator), and the secret-target validator now rejects an `http://` `to`
  alongside `tcp://`. **Grammar** (`allowlist.rs`): `Layer` gained the third variant + `default_port()`
  (443 TLS / 80 cleartext) + `inspected()` (L7|L7Clear); the scheme's default port threads through
  `classify → classify_kind → split_host_ports`/`parse_path_rule` via a new `default_port` param (`Ports::single(p)`, the single choke point — not post-processing, which can't tell an explicit `:443`
  from the default); `render` omits each scheme's default (`:80`/`:443`) so `http://host` round-trips
  compact. **New `explain_clear`/`method_denied_clear`** decide the cleartext verdict (the L7 `explain`
  stays MITM-only), and — **the advisor-caught bug the green suite would have hidden** —
  `apply_default_methods` now rewrites **both** inspected layers (`inspected()`), else an app's
  `http://` allow silently escaped the read-by-default `{GET,HEAD}` posture to all-verbs.
  `l4_l7_conflicts` likewise treats a cleartext rule as inspected for the splice-shadow warning.
  **Proxy** (`proxy.rs`): the `method != "CONNECT"` branch routes a well-formed `http://` absolute-form
  to a new `handle_cleartext` (a focused sibling of `splice_l4`, **not** a generic refactor of the MITM
  tail — the advisor's call, keeping regression risk off the encrypted path), reusing the pure helpers
  (`carries_secret`, `ip_permitted`, `reserialize_request`→origin-form, `pump_to_eof`, `write_refusal`,
  ctx logging); it forwards in **origin-form** with the client's `Host` and forced `Connection: close`,
  and streams the one response back (a cleartext host is never an injection target, so no reflection to
  mask). **`ops test net http://…`** and its built-in/injection-note tags route through the *same*
  `explain_clear` (no drift from the wire; no injection note ever shown for a cleartext request), and
  `ops net rules`/help render the third scheme. **The load-bearing proof is a live e2e**
  (`a_cleartext_http_rule_forwards_plaintext_egress_through_the_proxy`, **ran 22s**): a trusted
  `allow = ["http://cache.nixos.org"]` project runs an in-cage `curl -i http://cache.nixos.org/…`
  through the empty-netns forwarder → the cleartext handler → real plaintext egress (no `denied-*`),
  while `http://example.com` (no rule) is refused **`403 denied-default` at the proxy** whose body
  names `ops net allow http://example.com` — exercising the `method != CONNECT` absolute-form entry a
  proxy unit test cannot reach. **855+ tests green** (net-new: 6 `allowlist` unit incl. the opt-in +
  layer-agnostic-deny + method-scope + `apply_default_methods`-rewrites-cleartext + the round-trip;
  3 `proxy` unit incl. the origin-form forward proof + opt-in + deny-wins; the config secret-target
  cleartext rejection; the repurposed 405 test for a bare origin-form; the live e2e), fmt/clippy `-D
  warnings` clean, **std-only** (no new dep — reuses the existing rustls/socket machinery),
  live-verified (`ops net rules` renders `http://` compact; `test net http://` ALLOWED only via an
  `http://` rule, a bare/`https` rule does **not** open the clear, deny wins). Advisor-reviewed (plan
  AND impl). **Honest scope:** cleartext is bytes-on-the-wire unencrypted by nature — the doc steers
  to `https://` wherever the host offers it; the boundary (empty netns + allowlist + the one host on
  its one port) is unchanged.
  **One-shot config override — increment 2: typed security flags (DONE 2026-07-04)**
  (`src/config/overrides.rs` + `config/mod.rs` + `config/view.rs` + `main.rs` + `help.rs` +
  `tests/{run,config}.rs`): the ergonomic half of the one-shot override — a **typed flag per field**,
  each with an `OPS_*` environment equivalent, so a launch can change a single security field without
  writing TOML. `--net <none|shared|ask|allow=h1,h2|deny=h1,h2>` (the `allow=`/`deny=` DSL builds a
  default-deny **allowlist** / default-allow **denylist** — the common one-shot egress shapes; a bare
  `allow`/`deny` is **refused as ambiguous**, since it reads like the list forms but means the opposite
  wide-open posture — advisor's call), `--gui <none|wayland>`, `--nixpkgs <ref>`,
  `--bind <path[:ro|:rw]>` (the mode is the suffix after the **last** `:`, and only when exactly
  `ro`/`rw`, so `/my:dir` is not mis-parsed), `--limit <key>=<value>` (key ∈
  `memory_high`/`memory_max`/`tasks_max`; the value parses to a `RawLimit` number-or-text so the
  downstream systemd-grammar **and** bare-byte-floor guards still fire), `--package
  <name>=<backend:locator>`. Env forms: scalar `OPS_NET`/`OPS_GUI`/`OPS_NIXPKGS` + single `OPS_BIND` +
  per-key `OPS_LIMIT_<key>`/`OPS_PACKAGE_<name>` (mirroring `OPS_ENV_<KEY>`). **Precedence is now four
  tiers** — `OPS_CONFIG < OPS_* typed < --config < --* typed` — the CLI still beats the environment and
  a typed flag beats the blob. **The merge is one uniform rule across all four tiers** (advisor's #1):
  a **scalar** (`nixpkgs`/`network`/`gui`) is *replaced* by the highest tier that sets it; a
  **collection** (`env`/`packages`/`binds`/`limits`) is *unioned*, the higher tier winning per
  key/entry — so `--bind` adds to whatever the blobs bound and `--limit tasks_max=…` tunes one limit
  without dropping a blob's `memory_max`. `merge_raw` became `overlay_into` (the single merge), which
  **also fixed a latent increment-1 bug the rewrite surfaced**: `merge_raw` had dropped `limits`
  entirely, so a second `--config` blob's `[limits]` silently vanished (a repeated-blob-unions-limits
  guard now pins it). **The impl seam is clean:** a typed flag only builds the same `RawConfig` fields
  a blob does, so `apply_override`/`validate_override` need **zero** change — the set-but-invalid *value*
  fail-closed (a `--gui bogus`, a `--net nonee` → exit 2, no launch) is the increment-1 machinery
  unchanged; `collect` adds only *structural* hard errors (a `--limit` with no `=`, a `--bind` with an
  empty path, a bad `--net` keyword, an unknown limit key). `collect`'s signature became
  `collect(&CliOverrides)`; `main.rs` grew one `take_override_flag` that dispatches all eight flags,
  shared by `run`/`shell`/`parse_app_launch`. **`ops config show` reflects the ambient `OPS_*` typed
  vars** through the same `collect(&CliOverrides::default())` it already used, so it never lies about a
  launch in this environment. **Residual (unchanged from increment 1, now documented in `ops help
  app`):** overriding an app's `network` drops the app's read-by-default `default_methods` → all-verbs
  (an override posture is Mode-A-like; `{VERB}` prefixes in a `--config` `[network]` restrict it — the
  user's "no preference" call). Non-blocking wrinkle: `--net allow=host` renders as `network: deny
  (override)` in `config show` (the raw mode name of a default-deny allowlist, consistent with a
  `[network] mode = "deny"` — the `allow …` entries disambiguate). **Full `cargo test` green** (unit
  835 + config 80 + **run 39** [net-new `a_typed_one_shot_limit_flag_lands_in_the_cage_scope` — a
  trusted-by-invocation `--limit tasks_max=8192` measured as the cage's host-visible `pids.max`, teeth
  on the flag→collect→`cgroup::wrap`→scope thread; the three increment-1 override e2es re-ran and
  **passed**, confirming the merge rewrite did not regress the collect path] + the rest; net-new: ~13
  `overrides` unit incl. the four-tier layering, the `allow=`/`deny=` DSL, the last-colon bind parse,
  the union-across-tiers + same-path-replace, the repeated-limits-union guard, and the ambient
  structural-error case; a `config show` ambient-typed-override integration case; the `parse_app_launch`
  typed-flag parse). fmt/clippy `-D warnings` clean, **std-only** (no new dep). Advisor-reviewed (plan
  AND impl — the plan review set the uniform-merge rule and the `--net` DSL/bare-refusal and the
  last-colon `--bind` and the `RawLimit`-preserving `--limit`; the impl review confirmed the two-level
  fold keeps the env-source notice computable and required the fmt gate + the increment-1-e2e
  non-regression confirmation). Live-verified (six fail-closed paths → exit 2 with exact messages; the
  `allow=` DSL + `OPS_PACKAGE_`/`OPS_BIND` ambient scan through the real binary). **This is a single
  commit** (the pty-deadline bump already shipped separately with increment 1).
  **One-shot config override — increment 1: the `--config`/`--env` + `OPS_*` overlay (DONE
  2026-07-04)** (`src/config/overrides.rs` [new] + `config/mod.rs` + `config/schema.rs` +
  `config/view.rs` + `sandbox/launch.rs` + `main.rs` + `help.rs` + `tests/{run,config}.rs`): a
  one-shot override so **any** config field can be changed for a single launch without editing a
  file. Carried by `--config <toml|@file>` (repeatable) + `OPS_CONFIG` — a full `RawConfig` overlay
  (covers every field by construction) — and `--env KEY=VALUE` (repeatable) + `OPS_ENV_<KEY>` for one
  cage variable (the per-key shape confirmed with the user over `OPS_ENV="K=V …"`). It is the
  **authoritative final word** — it beats a trusted project config **and** a named app's overlay —
  because it comes from the invoker, whose authority over the host process's argv/env no lower-trust
  context can reach (**verified**: cage passthrough is `TERM`/`LANG` only, no self-exec, `--detach`
  forks not re-execs). So it is **trusted by invocation**, distinct from the direnv content-trust of a
  project config (it touches no trust marker). **Precedence**, low→high:
  `OPS_CONFIG < OPS_ENV_<KEY> < --config < --env` (the CLI always beats the environment; within a
  source the typed flag beats the blob). `overrides::collect` merges the inputs into one overlay
  (fail-closed on a parse error), and application is split by the launch flow's channel/rest seam:
  `apply_override_channel` (nixpkgs) runs in `prepare_with` **before** the lock is chosen; a pure
  `validate_override` runs there too, **before** the expensive provisioning; and `apply_override` (the
  real apply) runs at each verb's final point — after `prepare` for `run`/`shell`, **after
  `merge_app`** for `app`, so it beats the app. **Fail-closed is the load-bearing property (an
  advisor review caught it half-done):** a malformed TOML was already a hard error, but a *set-but-
  invalid VALUE* (a `network="nonee"` typo) MUST be too — silently keeping the baseline could leave a
  *wider* posture than the mistyped intent (the exact fail-open the feature must not have), so a
  set-but-invalid scalar security field (`network`/`gui`/`[limits]`/`nixpkgs`) is a **hard error, exit
  2, aborting ~10 ms before any provisioning**; the additive fields (`env`/`binds`/`packages`) instead
  fail *closed* by dropping a bad entry (a missing bind/tool is less capability, never a wider
  posture), so they warn and skip. **Two fail-open bugs the golden-rule live verification caught:**
  the invalid-value fall-through above, and `fold_launch_fields` having dropped `limits` from the
  merge entirely (fixed + a `every_launch_field_survives_the_merge` regression guard). **Env footgun
  (user chose "all fields, if secure"):** the environment can set security fields, but each security
  field sourced from the env prints a stderr notice (anti stale-`OPS_NETWORK=shared`); the CLI is
  silent (explicit per-invocation). **`ops config show`** reflects an ambient override (`OPS_*`) in the
  full view and tags values `(override)` (a new `Provenance::Override`, warn hue), so it never lies
  about what a launch would do; a set-but-invalid ambient override surfaces as an error note (baseline
  stands). Three `Clone` derives on `NetworkField`/`NetworkTable`/`RawLimits` enable the borrowing
  early-validate. **Residuals (documented):** `[net.groups]`/`[app.*]` in an override are
  ignored+noticed (not launch concepts); an override `[network]` has no `@group` vocabulary (fails
  closed); on `run`/`shell` an override that *opens* the network does not resurrect a baseline secret
  the baseline posture cleared (fail-closed, marginal); overriding an app's `network` drops the app's
  read-by-default `default_methods` → all-verbs (like a Mode-A baseline; `{VERB}` prefixes are the
  opt-in to restrict — user: no preference, kept as-is); `config show --app`/attach/`ops test net`
  don't preview the override yet. **Increment 2 (next):** ergonomic typed security flags
  `--net/--gui/--bind/--nixpkgs/--limit/--package` + their `OPS_*` equivalents, layered per the same
  precedence. **Full `cargo test` green under load** (unit 821 + config 79 + run 38 + the rest;
  net-new: ~14 `overrides` unit incl. the merge-survival guard, 9 `apply_override`/validate unit incl.
  the flagship override-beats-app and invalid-value-hard-error, a `config show` `(override)`-tag
  integration case, and run.rs e2e — env reaches the cage + CLI-beats-env, malformed AND invalid-value
  → exit 2, and **override beats an app overlay through the real dispatch** [the after-`merge_app`
  ordering, which ran a real cage]). fmt/clippy `-D warnings` clean, **std-only** for the config side
  (no new dep). Advisor-reviewed (plan AND impl AND the fail-closed fix — the review caught the
  invalid-value hole, blessed the validate-against-baseline correctness, and required the app-
  precedence e2e + the `config show` tag guard). *(The pre-existing `tests/shell.rs` pty-resize flake
  this increment's heavier run.rs tipped over its 45 s deadline is fixed in a separate commit —
  deadline raised to 180 s.)*
  **Engine independence — the binary ships its own nix + bwrap (DONE 2026-06-25)** (`build.rs` +
  `Cargo.toml` + `mise.toml` + `src/store.rs` + `src/sandbox/launch.rs` + `src/main.rs`): the two
  host couplings that contradicted the self-contained-binary promise — host nix and host
  `/usr/bin/bwrap` — are closed by **embedding both static engines** behind opt-in features.
  **nix first** (`bundled-nix`): a static musl `nix` 2.34.7 (~39 MB, **multi-call** — one binary
  dispatches `nix`/`nix-store` off argv0) is `include_bytes!`'d into ops and materialized,
  content-keyed + atomic (temp+rename, 0755), into `<data>/engine/{nix,nix-store}` with a `.sha256`
  marker; `store::resolve_nix` resolves **override `OPS_NIX_BIN` → owned `<data>/engine/nix` → host
  PATH**, the owned tier consulted **feature-independently** (resolution only *finds* what
  materialization placed — so any binary picks up an engine a prior bundled run left on disk), so a
  release drives its own daemonless store with no host nix. **Then bwrap** (`bundled-bwrap`, the
  2026-06-25 increment): same shape — a static musl `bwrap` 0.11.2 (~0.2 MB) embedded, materialized
  into `<data>/engine/bwrap` with a **distinct `.bwrap.sha256`** marker (it shares `<data>/engine/`
  with nix; markers never clobber), resolved by `store::resolve_bwrap`. **bwrap independence is
  *partial*, not total like nix's** — the defining nuance: on a host with
  `kernel.apparmor_restrict_unprivileged_userns` set, the kernel grants unprivileged
  user-namespace creation **only** to a binary carrying an AppArmor profile that allows `userns`,
  and the shipped profile attaches that grant **by path** to `/usr/bin/bwrap`; a bwrap materialized
  elsewhere matches no profile and cannot create a namespace, and a user-level tool cannot ship its
  own profile without root. So the seam chooses **by host** (`pick_bwrap`, pure, the AppArmor branch
  unit-tested since a host without the restriction cannot flip the sysctl live): `OPS_BWRAP_BIN`
  override always wins; **unrestricted** → the bundled engine leads (host PATH the fallback);
  **restricted** → the host engine leads (the same bwrap ops uses today) — **non-regressive by
  construction**. The pin is a **robustness win ≥ the independence**: ops couples tightly to bwrap
  flags (`--add-seccomp-fd` / `--unshare-cgroup` / `--new-session`), so owning the version removes
  the "host bwrap too old / missing flag" failure mode. `build.rs` carries a generalized **`ENGINES`
  table** driving one `emit_bundled_engine` for both engines, each pinned by its own
  build-time-verified sha256 (a drift fails the build, loudly); `mise run build-bundled` (needs host
  nix) realises both `pkgsStatic` attrs from the pinned nixpkgs rev and builds `--features
  bundled-nix,bundled-bwrap`; `doctor` reports which engine it would use and why (`· bundled engine`
  / `· host PATH` + an AppArmor note). **The default-feature build is behaviorally unchanged** (host
  engines), so CI stays embed-free. Verified: **564 tests** + fmt/clippy clean (default features);
  feature-on `lint-bundled` / `build-bundled` clean (**44.0 MB** musl static, both engines
  embedded); **live empty-PATH** (no host nix, no host bwrap, overrides unset) `ops doctor`
  materializes both engines (distinct markers coexist) and launches a real hardened process, and a
  **cold `ops run -- id`** provisions the base via the embedded nix (downloaded from
  cache.nixos.org) and launches the hermetic cage via the embedded bwrap → `uid=1000(sandbox)`, exit
  0 — real work, not `--version`, for both engines. **CI blind spot** (inherent to the feature gate):
  CI exercises the *default* build (host engines), never the embedded versions, so **a pin bump is
  not caught by CI** — after bumping either engine, re-run the live cold proof on the shipping musl
  binary. **Residuals (deferred, named):** the LGPL NOTICE owed before distribution now covers
  **bwrap too** (nix + bubblewrap are both LGPL); the pins are **x86_64-only** (a 2nd arch needs its
  own `OPS_BUNDLED_*` + sha per `TARGET`); embedded-bwrap *on* restricted hosts is reachable only via
  a one-time `sudo`-installed AppArmor profile for the materialized path (a packaging option,
  explicitly outside the no-privilege runtime promise); and on unrestricted hosts the shipped binary
  now uses its **own** bwrap by default (surfaced by the `· bundled engine` doctor line,
  escape-hatched by `OPS_BWRAP_BIN`) — a release-note line for power users with a customized host
  bwrap. Advisor-reviewed (plan AND impl).
  **Engine resolution integrity gate (DONE 2026-06-25)** (`src/store.rs`): a follow-up hardening
  of the engine seam above — before any resolved `nix`/`bwrap` binary is `execve`d it passes an
  **ownership/permission gate** (`engine_verdict` + a 3-state `engine_probe`), mirroring the
  config-file `safety` gate with one deliberate difference: an engine may be owned by **root**
  (the host `/usr/bin/bwrap` is `root:root`, an override may be a system binary), so uid 0 is
  accepted alongside our euid; a non-regular or world-writable file is refused, group-writable
  tolerated (the `0700` engine dir is the real boundary). The probe is **3-state**
  (`Absent`/`Untrusted`/`Trusted`) so the cases cannot collapse: a present-but-untrusted
  **override is refused outright** (`None`, never silently replaced by a lower tier — a deliberate
  choice failing closed), while a lower **owned/`PATH` tier that is untrusted is skipped with a
  by-name warning** in favour of the next. Wired into `pick_engine_bin` **and** `pick_bwrap` (the
  resolution path common to feature-on **and** feature-off), closing the soft spot that the
  feature-off binary `execve`d `<data>/engine/<bin>` with **zero** checks. **Honest scope:**
  defense-in-depth, **not** a boundary — a same-uid attacker who can write the engine already owns
  the account and could replace `ops` itself; the real end-to-end integrity stays the deferred
  **signature of the released `ops` binary**. **Static check** (`stat` then `execve`), not
  TOCTOU-proof (would need `O_PATH`+`fexecve`, out of proportion for this tier). **Two named
  residuals:** the `PATH` tier probes only `find_on_path`'s **first match**, so it refuses a
  world-writable first match but does **not** scan past it — not a full `PATH`-poisoning defense
  (skip-and-continue deferred); and under `bundled-*`, `ensure_owned_*`'s marker fast-path does
  **not** re-lay-down a tampered-but-right-version engine — it is refused and falls through to
  host, silently demoting a self-contained binary to host-dependence until the next version bump
  (safe, same-uid class, documented). **Proven live with teeth** (`chmod o+w <data>/engine/bwrap`
  → `ops: ignoring untrusted engine binary …: world-writable` + fall-through to `/usr/bin/bwrap`;
  restored → `· bundled engine`, no warning) + unit tests (`engine_verdict` us/root/refusals;
  `pick_*` override-untrusted→refuse, owned-untrusted→fall-through, PATH-untrusted→none) + **the
  full launch-path e2e re-ran green through the new probe** (`tests/run.rs` 26/0, `tests/shell.rs`
  1/0 — fresh data dirs hit the host-`PATH` tier through `engine_probe` end-to-end, the path
  live-doctor skipped). **565 `--bins` + 27 e2e green**, fmt/clippy clean, musl static verified
  (std-only, no new dep — reuses `libc`), advisor-reviewed (plan AND impl — it caught the missing
  integration run, now green, and the PATH-first-match overclaim + the bundled-skip residual, both
  folded in).
  **Configurable resource limits — `[limits]` override (DONE 2026-06-25)** (`src/config/schema.rs`
  + `config/mod.rs` + `sandbox/cgroup.rs` + `sandbox/mod.rs` + `sandbox/launch.rs` + `main.rs` +
  `config/view.rs` + `tests/run.rs`): the M4.2 cgroup limits (`MemoryHigh=80%`/`MemoryMax=90%`/
  `TasksMax=16384`) were hardcoded constants; they are now **overridable from a `[limits]` config
  table**, declarable in the **global config OR a project** `.ops.toml`. A new `RawLimits`
  (`memory_high`/`memory_max`/`tasks_max`, each an untagged `RawLimit` number-or-string so a natural
  `tasks_max = 8192` AND a `memory_max = "80%"` both parse without a type-mismatch dropping the whole
  config) resolves into a `cgroup::Limits` (three `Option<String>` overrides over the constants),
  threaded into `cgroup::wrap`/`profile`/`probe` at all three launch sites. **Gated trusted/global-
  only like `network`/`gui`** — loosening a limit (a higher `tasks_max`, an unbounded ceiling)
  reduces the anti-DoS control, so an **untrusted project's `[limits]` is dropped + warned**; the
  three sub-fields **layer per field** (the `env` model, not wholesale: a global `tasks_max` + a
  project `memory_max` compose, neither silently reverting to a constant). **Validation is
  load-bearing** (advisor's #1): a launch execs `systemd-run`, which exits non-zero **before bwrap**
  on a rejected `-p` value → a bad config value would **brick *every* launch of the project**. So
  `is_valid_memory_value`/`is_valid_tasks_value` mirror systemd's grammar **exactly**, and the
  grammar was **verified empirically against a live `systemd-run`** (not guessed): memory =
  `infinity` | `N%` bounded **(0,100]** | a decimal byte size + an **uppercase** `K/M/G/T/P/E`
  suffix (NO `B`, no `i`, no lowercase — the initial `B`-suffix guess was a bug live-probing caught);
  tasks = `infinity` | a positive integer (`0` rejected). **A config-time invalid value is dropped +
  warned by field name**, falling back to the default, never reaching `systemd-run`. The committed
  **live grammar test** (`every_accepted_value_is_one_systemd_run_accepts`, skip-not-fail) drives a
  real throwaway scope per accepted form — and **earned its keep**: it caught that **`TasksMax=100%`
  is rejected by systemd** (an asymmetric exclusive percent bound vs memory's inclusive `100%`), so
  tasks-percent was **deliberately dropped** (esoteric `% of pid_max`, surprising boundary — a task
  cap is a count or `infinity`). `doctor` reflects the **global** `[limits]` (they apply to every
  launch; its live probe validates them), `ops config` shows a `limits:` line **only when a field is
  overridden** (uncluttered for the default profile, marking each custom field). `cgroup` module
  raised to `pub(crate)` so `config`/`main` name `cgroup::Limits`. **579 tests green** (**577
  `--bins`** incl. the live grammar test + schema parse + validator unit + profile-override +
  config gating/merge matrix + the byte-floor guard + the `ops config` render test; **2 net-new
  limits e2e** in `tests/run.rs` — the
  default cap unchanged AND the **headline `a_trusted_limits_override_lands_in_the_cage_scope`**: a
  trusted `tasks_max = 4096` → `ops run` → the cage's host-visible `pids.max` **measured 4096**, not
  the default 16384, end-to-end through resolve → `cgroup::wrap` → the systemd scope — teeth: a
  default leak panics, no scope skips), fmt/clippy clean, **std-only (no new dep)**, advisor-reviewed
  (plan AND impl — the plan review made the grammar empirically-verified-and-tested the gate, which
  is what caught the `B`-suffix and `TasksMax=100%` drifts; the impl review caught that my last
  fmt/clippy predated the `run.rs` e2e (re-run clean) and flagged the `memory_max = 90` footgun
  below). **Footgun guarded (advisor #2, user chose to add):** a memory value is *bytes* when bare,
  so `memory_max = 90` means 90 **bytes** — a percentage written without its `%` — which is below
  the kernel floor and would brick **every** launch of the project. `is_bare_byte_count_below_floor`
  (config-time, < 1 MiB) drops a bare small memory integer with a `did you mean "90%"?` hint,
  falling back to the default — converting the most-likely brick into a warning. **Narrower residual
  (accepted, documented not guarded):** a unit-suffixed-but-too-small memory value (`"2K"`) or
  `memory_high` ≥ `memory_max` is still a syntactically-valid value systemd rejects — the
  already-accepted **self-sabotage-of-a-trusted-field** class (like a bad `nixpkgs`/`cmd`).
  **Scope: baseline-only** (global + project); per-`app` limits shipped as the **next increment
  (below)** — an app without its own `[limits]` still inherits the baseline via `merge_app`. **579
  tests green (577 `--bins` + the full 27 `run.rs` e2e re-run, incl. the headline override e2e).**
  **Per-app `[limits]` overlay (DONE 2026-06-25)** (`src/config/schema.rs` + `config/mod.rs` +
  `config/view.rs` + `main.rs` + `tests/run.rs`): the named-future extension delivered — a
  `[app.<name>.limits]` table (or a `[limits]` table in an imported profile) overrides the baseline
  cgroup limits **for that app's launches**, gated and layered exactly like the per-app
  `network`/`gui`. `RawApp` gains `limits: Option<RawLimits>` (reusing the baseline shape, so the
  number-or-string `RawLimit` forms and the systemd-grammar validation apply unchanged);
  `ResolvedApp.limits: cgroup::Limits` carries the app's **own** per-field overrides (all-`None` =
  inherits the baseline whole). **Gating mirrors `network`/`gui`, NOT the `cmd`/`packages`
  integrity-gate** (the advisor's call, airtight by construction): an untrusted project has no
  legitimate need to set a limit on its own app — the safe default is inherit-baseline, which still
  bounds it, and the only dangerous direction is loosening — so an untrusted layer's app `[limits]`
  is **dropped whole** in `resolve_app` *before* any overlay. The flagship therefore holds by
  construction: a globally-declared app's tight `tasks_max` cannot be loosened by an untrusted
  project (the untrusted contribution is gone before `overlay_limits` runs). Layering is the `env`
  model via one DRY helper **`overlay_limits(&mut base, over)`** (a `Some` field replaces, a `None`
  keeps base), shared by **three** call sites — the baseline project-over-global merge (refactored
  from its inline three-`if` block, behaviour-preserving), the app's global→project resolution, and
  `merge_app`'s overlay onto the baseline — so the per-field semantics cannot drift between them. The
  launch path needs **zero new wiring**: `ops app` already does `prep.cfg.merge_app(app)` *before*
  `launch` reads `prep.cfg.limits` for `cgroup::wrap`, so the merged limits flow to the scope for
  free. `ops config` shows a per-app `limits:` line listing **only the fields the app tunes** (an
  `Option<AppLimitsView>`, `None` when it tunes nothing) — *not* the effective-or-default the
  baseline `limits:` line shows, since an app inherits the baseline's *resolved* value (possibly
  itself an override) for an unset field, so a default would misreport what the app changes. **doctor
  stays baseline-only by design** (host-level, no app context). The `[limits]` table round-trips
  through `serialize_app`/`parse_app` (extended the existing multi-table round-trip test, which
  catches a scalar-before-table ordering bug a limits-only test would miss; the minimal-app test
  asserts an unset `limits` is omitted). **583 tests green** (**580 `--bins`** — net +3: per-field
  overlay-precedence merge_app test, two app gating tests [trusted per-field override; the flagship
  untrusted-drop both directions], the `ops config` per-app render test, plus the extended schema
  round-trip + view JSON-contract assertions; **3 `run.rs` cgroup e2e** incl. the net-new
  **`a_trusted_app_limits_override_lands_in_the_cage_scope`**: a trusted `[app.cap.limits] tasks_max
  = 2048` → `ops app cap` → host `pids.max` **measured 2048**, closing the one seam a `merge_app`
  unit test cannot — that the real dispatch merges the overlay *before* consuming limits; teeth = a
  default-16384 leak panics, no scope skips). fmt/clippy clean, **std-only (no new dep)**,
  advisor-reviewed (plan AND impl — the plan review made the app e2e mandatory over a merge_app unit
  test alone, confirmed the gating-by-construction flagship, and chose the app-own-overrides view
  shape; the impl review confirmed the gating is airtight and the e2e has teeth on both new seams).
  **Named residual (unchanged):** a unit-suffixed-but-too-small value (`"2K"`) or `memory_high` ≥
  `memory_max` stays the self-sabotage-of-a-trusted-field class; the app path reuses the identical
  `validate_limits`, so its config-time drops behave exactly as the baseline's.
  **`config show` value provenance — baseline (DONE 2026-06-25)** (`src/config/mod.rs` +
  `config/view.rs` + `main.rs`): `ops config show` now tags **every baseline value** with where it
  came from — `(default)` (ops built-in), `(global)`, `(project)` — **colored by level** (default
  gray, global cyan, project green), so a value's origin reads at a glance (the user's ask: "on ne
  voit pas d'où vient la valeur"). `Layer{Global,Project}` was **migrated to one
  `Provenance{Default,Global,Project}`** enum (the single origin type, no drift); `env`/`binds`
  already carried per-entry origin, now extended to the **scalar postures** (`network`/`gui` →
  `Resolved.network_origin`/`gui_origin`) and **per-field `limits`** (`LimitsOrigin`, set by
  `mark_limit_origins` once per layer in declaration order). **The load-bearing property:** origin is
  recorded at **every** assignment **including a value a layer sets to the built-in default** — so
  `network: shared (global)` is distinguishable from `shared (default)` (the most useful case: open
  because chosen, or because unset?). This hinges on `validate_network`/`validate_gui` returning
  `Some(Shared)`/`Some(None)` for an explicit `"shared"`/`"none"`, which they do; pinned by a
  discriminating unit test on `resolve` (explicit-default-valued `network`/`gui`/`tasks_max = 16384`
  → origin `Global`, not `Default`; a field no layer set → `Default`). View: `ProvenanceView`
  mirror + `network_origin`/`gui_origin` on `ConfigView` + `LimitView.origin` (replaced the
  `overridden` bool). Render: `provenance_tag` (end-of-line) + `provenance_parts` (the **one**
  level→hue mapping, so the inline per-field `limits` cells cannot drift); the `nixpkgs:`/`engine:`
  channel lines were **folded into the same per-level coloring** (was bold) via a renderer-side
  `channel_origin_kind` string-match of the closed `store::Origin::label()` set — **kept a renderer
  mapping (no `ChannelView` field / ~15 fixture edits) but the string coupling is pinned** by a seam
  test routing the real `Origin::Default/Global/ProjectPin.label()` through it (a rename in `store.rs`
  fails loudly instead of silently degrading to gray). **Scope: baseline only** — the `Inherited`
  provenance + per-app `config show --app <name>` effective-with-inheritance view is the **next
  increment** (apps), deliberately deferred so `Inherited` is added when it is first constructed (not
  dead code). **584 `--bins` + 56 config green** (net-new: the discriminating `resolve` origin test,
  a project-path origin test, the network/gui render-tag test, the channel-origin seam test; the
  colored render test re-pinned env/bind tags to green/cyan and the channel origin to green), fmt +
  clippy clean, **std-only (no new dep)**, live-verified (`network: allowlist (global)`,
  `limits … TasksMax=4096 (global)`), advisor-reviewed (plan AND impl — the impl review added the
  explicit-default discriminating test and the channel-seam test, and confirmed keeping the renderer
  mapping over a `ChannelView` field).
  **`config show --app <name>` value provenance — apps (DONE 2026-06-25)** (`src/config/mod.rs` +
  `config/view.rs` + `main.rs` + `tests/config.rs`): the second provenance increment — a dedicated
  per-app view answering "what does this app *actually* launch with, and which of it did the app
  change?", which the compact baseline `apps:` section (overlay-own only) cannot. `ops config show
  --app <name>` renders the app's **effective** configuration (baseline folded with the overlay)
  field by field, each scalar tagged `app:global`/`app:project` (the app declaration set it) or
  **`inherited`** (it took the baseline's value) — so the inheritance the user said the feature
  needed ("sinon ça ne veut pas dire grand chose") is finally visible (`gui: none (inherited)`,
  `MemoryHigh=70% (inherited)` from the baseline, `TasksMax=2048 (app:global)` set by the app). Same
  per-level coloring as the baseline (cyan/green/dim), with an **app-context label vocabulary**
  (`app_provenance_parts`: `Global`→`app:global`, `Project`→`app:project`) over the same hues.
  **`Inherited` lives only on the view-side `ProvenanceView`, never `Provenance`** (the resolution
  never inherits — inheritance is *derived at view time* from the absence of an overlay value, the
  advisor's call). `resolve_app` records per-field app-layer origin (`cmd_origin`/`network_origin`/
  `gui_origin`/`limits_origin`/`home_scope_origin` on `ResolvedApp`, set at each assignment in the
  global-then-project blocks); `app_detail_view` computes effective value + provenance, falling back
  to the baseline (passed in — the one new plumb) for an unset scalar. **Collections
  (env/binds/packages/secrets) are NOT re-listed** — they show the overlay's *own* additions + a
  count of inherited baseline entries (a same-key/-name overlay entry shadows its baseline twin in
  the `env`/`packages` count), so `--app` never becomes a baseline echo; `--details` expands the
  allowlist rules and the own-entry lists. `--json` emits the serializable `AppDetailView`.
  **The increment's core guard (advisor-required):** `app_detail_view` *mirrors* `merge_app`'s
  precedence (it needs the per-field "did the app set this" the merge discards) rather than calling
  it, so a unit test pins the two together — `baseline.clone().merge_app(app)` ’s effective
  network/gui/limits must equal the detail view's — and a `merge_app` drift fails loudly instead of
  silently making `--app` misreport what the app launches. **587 `--bins`** (net +3: `resolve_app`
  per-field origin recording, the `render_app_detail` output, the merge_app-agreement guard) **+ 57
  config** (the `config show --app` e2e: app:global vs inherited end-to-end, the unknown-app error,
  and `--json` carrying the provenance), full suite green incl. **run.rs 28 (launch non-regression —
  `resolve_app` is on the `ops app` launch path)**, fmt + clippy clean, **std-only (no new dep)**,
  live-verified, advisor-reviewed (plan AND impl — the impl review required the merge_app-agreement
  guard and the `--json` coverage, both added). **The once-named secret-posture residual is now
  fixed (see the increment-3 entry below):** the detail view applies `enforce_secret_posture`, so an
  app that inherits baseline secrets while narrowing its network reports the zero the launch injects.
  **Scope: the provenance axis (baseline + apps) is complete;** increment 3 (write-side `--app` sugar
  and `show --global/--local/--default` single-source views) **also shipped — see the next entry.**
  **`config` family — increment 3: source views + write-side `--app` + the secret-posture fix
  (DONE 2026-06-26)** (`src/config/mod.rs` + `config/view.rs` + `src/main.rs` + `src/help.rs` +
  `tests/config.rs`): the user pulled the deferred increment 3 forward, plus closing the
  apps-provenance secret residual. **Three slices, one cohesive commit.** **(a) the secret-posture
  fix** (`view.rs::app_detail_view` AND `app_view`): both per-app credential views now **mirror
  `merge_app`'s `enforce_secret_posture`** — the detail view builds the effective `baseline ++ app`
  set and runs the *same* host-private check (reachable as `super::enforce_secret_posture`, a child
  seeing the parent-private fn), so when the app's **effective** network is not an allowlist it
  reports **zero** credentials (own *and* inherited) and carries the launch's exact drop note,
  instead of over-reporting a credential `ops app <name>` silently drops. **The advisor's impl-review
  consistency check caught that this would otherwise diverge from the sibling compact `apps:`
  roster** (`app_view`, the full `config show`), which showed the declared-own count unconditionally
  — so an app with its *own* `[secret]` + `network = "none"` read `1 injected host-side` in the
  compact line while `--app` correctly said 0; `app_view` was therefore *also* made posture-aware
  (it takes the app's **effective** network — its own, else the baseline's — and emits no credential
  when that is not an allowlist), so **all three secret views now agree** (the baseline `secrets:`
  section was already posture-checked at `resolve`). Pinned by **extending the
  merge_app-agreement guard** (a baseline secret the app's narrowed network drops → `detail.secrets +
  secrets_inherited == merged.secrets.len() == 0`) **and** two `config show` integration cases (a
  `--app` `wide`/`narrow` pair — inherit-and-keep vs narrow-and-drop; and a compact-roster
  `wired`/`solo` pair where exactly one of two own-secret apps claims an injection). **(b) single-source views** `ops config show --global|--local|--default`
  (`config/mod.rs` `Source` enum + `load_scoped`; `view.rs` `build_scoped`): each shows what **one
  layer contributes over the built-in defaults**, so the provenance tags read as that layer's own
  additions (`--global` = global config + imported profiles, project ignored; `--local` = project
  only; `--default` = the built-ins alone). **The advisor's #1 (highest) risk handled:** `load` is on
  the **launch path** (`launch.rs` calls `config::load`), so `load` is kept a **thin
  `load_scoped(cwd, Source::All)` wrapper** with a **minimal diff** (only the global+profiles and
  project *reads* are gated behind `Source`; plugins, mise, bind-canonicalization, and warning
  assembly stay byte-identical) — and the **launch non-regression is verified by run.rs (28) +
  shell.rs (1)**, not config tests alone. The flags are **mutually exclusive** (a second, different
  source flag errors, not last-wins) and **`--app` ⊥ any source flag** (a per-app view is inherently
  over the full baseline) — one parser in `config_show`'s own loop (the write-verb `--global/--local`
  stay in `split_scope`; `--default` is show-only, kept out of `split_scope` so a write verb rejects
  it). **(c) write-side `--app <name>`** (`main.rs`): `set`/`unset`/`get --app <name> <key>` rewrites
  the key to `app.<name>.<key>` (sugar over the dotted key, which already worked). Parsed once in
  `split_scope` (now returning a `ScopeArgs` struct); `app_prefixed_key` validates the name
  (`is_valid_app_name` **and** no `.` — the key splitter is naive, so a dotted name is unaddressable
  this way and the error points at `ops config edit`); **`path`/`edit` reject `--app`** (they take no
  key) via `reject_app`. **Help** (`help.rs`): the `show` synopsis/options/prose document `--app` +
  the three source flags (and that `--global` surfaces imported profiles — deliberate, advisor-noted);
  `get`/`set`/`unset` gain `--app`. **589 `--bins`** (+2 unit: `app_prefixed_key` simple-vs-dotted,
  `set_show_source` conflict) **+ 63 config** (+6 integration: source-view restriction, the `--app`
  secret drop, the compact-roster posture-awareness, the conflict matrix, the `--app` write
  round-trip, the name-validation + path/edit rejection)
  **+ run.rs 28 + shell.rs 1 (launch non-regression — the load refactor)**, fmt/clippy clean,
  **std-only (no new dep)**, live-verified (all three source views, the conflict errors, the `--app`
  round-trip, and the secret drop with its note), advisor-reviewed (plan AND impl — the plan review
  caught that `load` is launch-path and set the minimal-diff + run.rs-verification discipline, the
  flag-matrix single-source-of-truth, and the dotted-name→`edit` escape hatch). The **config-family
  provenance + source-vocabulary work is now complete**; nothing in this axis remains deferred.
  **M3.4 done — hermetic TLS + a curated base
  toolset: ops provisions its own `cacert` into the base userland and binds the bundle
  at BOTH cert paths (`ca-bundle.crt` for nix/libcurl, `ca-certificates.crt` for mise's
  reqwest), so in-cage TLS no longer depends on the host's `/etc/ssl`; and the base
  carries a small curated CLI set (`curl git less grep sed awk find which`) sharing the
  base glibc, so an agent gets the everyday tools without declaring them.** **M3.5 done —
  `ops search <query>`: a host-side, read-only, no-trust-gate tool-discovery front-end over
  nixhub (the heavy `nix search` dropped after a probe found nixhub's fuzzy endpoint covers it);
  a fuzzy query lists matches, an exact name leads with that package's versions + the
  `nix:`/`[packages]` declaration lines; rides the shared nix fetcher (no new dep), free query
  percent-encoded safe-by-construction, version-fetch failure is best-effort (keeps the list).**
  **M4.1 done —
  the first in-cage enforcement layer: a two-filter `seccompiler` cBPF **seccomp denylist
  (Posture A)** handed to bwrap via `--add-seccomp-fd`, blocking the historically-abused
  syscall set AND the mount/ns family (so the userns→mount→overlayfs/`pivot_root` LPE
  surface is unreachable), reconciled with nix by forcing `sandbox = false` +
  `filter-syscalls = false`. Spike-decided A-vs-B, advisor-reviewed, 494 tests green.**
  **M4.2 done — the anti-DoS layer: the cage runs inside a transient systemd user scope
  (`systemd-run --user --scope`) carrying cgroup v2 limits (`MemoryHigh=80%`, `MemoryMax=90%`,
  `TasksMax=16384`) — chosen over Landlock-FS (whose confidentiality job the hermetic FHS already
  does) to close the unaddressed resource-exhaustion gap. systemd-run exec-chains (non-invasive,
  pty job control survives); best-effort/graceful-degradation (no cgroups/systemd → no limits,
  never a hard-fail); one `limiter()` decision shared by launch + doctor; wired at all three launch
  sites + a doctor line. 500 tests green. The M4 enforcement stack is complete (seccomp + cgroups);
  Landlock-FS is a deferred defense-in-depth option, not a gap.**
  **`ops app` framework — Step 1 (DONE)** (`src/config/schema.rs` + `config/mod.rs` +
  `sandbox/launch.rs` + `mod.rs` + `main.rs`): the flagship surface — a **named, reusable
  agent launcher** — landed as its framework slice. A `[app.<name>]` table (declarable in
  the **global OR project** config) carries a `cmd` (argv; a bare string is a one-element
  argv, **never whitespace-split** → zero quoting surface) plus a security/free overlay
  (`env`/`binds`/`packages`/`network`/`secret`). **Two-layer noun** (sandbox baseline +
  named app overlay; the reusable *preset* noun is deferred, YAGNI/additive). **Layering =
  global → project → app, override per field, each security field gated by the trust of the
  layer that supplied it** (`resolve_app`/`resolve_apps` mirror the baseline gating: a
  global app is **trusted-by-location**, a project app rides its own verdict). `merge_app`
  is then a **pure merge** over the resolved baseline (env upsert, packages override-by-name,
  binds/secrets unioned, network override-if-set) followed by a **re-check of the
  secret↔posture invariant** (`enforce_secret_posture`) — an app may add secrets or flip the
  posture, so the check runs post-merge. **Flagship property:** a **globally-declared app
  keeps its posture even under an untrusted project** — the whole point is to run an agent
  *on* untrusted code safely. The verb is **`ops app <name>`** (umbrella name, future-proof
  for TUI and GUI agents alike); `ops config` lists each app (cmd, packages, network, secret
  count, per-app gating notes). **Advisor-caught integrity fix:** `cmd` is **integrity-gated**
  — an untrusted project may define *its own* app but **cannot override the `cmd` of a
  trusted/global app** (else `ops app claude` would launch attacker code under the app's
  posture); a `cmd_trusted` flag drops+warns the untrusted override. **Every app is Mode B**
  (the locked-down agent posture) — the `mode` field is **deliberately deferred** (additive,
  default-agent, for when a concrete interactive Mode-A tool appears); GUI is a separate
  *hole* axis (Wayland), not a mode. **519 tests green** (1 schema parse + 7 config unit
  [layering/gating/merge/cmd-integrity] + 1 `ops config` integration + 1 **real-sandbox e2e**
  that ran: a `[app.probe]` runs under the synthetic identity, a free-env overlay reaches the
  cage, an unknown app exits 2), fmt/clippy clean, **musl static build verified**,
  advisor-reviewed (plan AND impl). **Honest scope — this is the *framework*; deferred to
  later steps:** the **persistent isolated creds dir** (Step 2), the **flagship `ops app
  claude` e2e** (key injection via the proxy + an Anthropic allowlist; the credential hole is
  *bounded to the allowlist*, not closed — Step 3), and the **GUI/Wayland hole** for
  opencode/hermes desktop (Step 4).
  **`ops app` framework — Step 2: per-app persistent isolated `$HOME` (DONE)**
  (`src/config/schema.rs` + `config/mod.rs` + `sandbox/binds.rs` + `launch.rs` + `main.rs`):
  the **creds dir** — each `ops app <name>` gets a **dedicated, persistent, isolated `$HOME`**
  so the app's config, login state, and history never bleed into the project shell or another
  app (the threat-model row "a dedicated, persistent, isolated creds dir, mounted for that tool
  alone"; the security-stack "each app … its own `$HOME`"). The home is **always** per-app and
  isolated from the project's default shell home; a new per-app **`home_scope`** chooses whether
  it is *also* per-project: **`"global"` (the default, user's call) — one home per app shared
  across every project** (`<data>/apps/<name>/home`), so an agent keeps a single identity
  everywhere; **`"project"` (opt-in)** — a home per `(project, app)`
  (`<data>/projects/<id>/apps/<name>/home`), isolating what the agent writes in one project from
  another. A `binds::Runtime` (`ProjectDefault | GlobalApp(name) | ProjectApp(name)`) is threaded
  `build → build_spec → project_runtime`; `ops run`/`ops shell` keep `ProjectDefault` (the
  project's shared home, unchanged). The synthetic `/etc` stays a **sibling** of the home for
  every scope, so the read-only-identity integrity invariant holds without special-casing.
  **`home_scope` is integrity-gated exactly like `cmd`** (`home_scope_trusted`): an untrusted
  project may set the scope of *its own* app but **may not flip a trusted app `"project"` →
  `"global"`** — that would route the untrusted run into the home a trusted run shares (the
  contamination vector); the safe direction (`"global"` → `"project"`, more isolation) is
  allowed. **App-name validation** (`is_valid_app_name`: 1–64 of `[A-Za-z0-9._-]`, not `.`/`..`)
  drops an unsafe name with a warning at resolve time — the name now keys an **on-disk** home
  directory, so a traversal/odd-charset name must never reach the launcher (fail-closed). The
  per-project **store (`/nix`, rw), the nixpkgs/tools locks, and the mise-config staging stay
  project-scoped (shared across apps)** — only the home + its sibling `/etc` become app-scoped; a
  consciously-accepted **cross-app integrity residual** (app A's self-equip writes are visible to
  app B in the same project) within the already-documented same-uid self-harm class — per-app
  *home* isolation is **not** per-app *store* isolation. **Residual specific to the global scope
  (advisor-caught, documented not fixed):** `MISE_DATA_DIR` lives under `$HOME`, so a
  `"global"`-scope app's mise activation state (`mise use`'s `config.toml` + shims) is **shared
  across projects**, while the store backing `/nix` is **per-project** (`seed_project_store` keys
  on the cwd). So an agent in a global app that `mise use`s a `nix:` tool in project A persists
  the *activation* globally but builds the tool's store path into project A's store only — in
  project B mise believes the tool active while B's store lacks it (**offline: a hard failure;
  online: a silent rebuild**). This is *new in Step 2* (before, an app used the per-project home,
  so mise-data and store were aligned). It dents the self-equip persistence promise specifically
  for global apps; the **already-present mitigation is `home_scope = "project"`** (mise-data and
  store both per-project, aligned), and the only clean fix for the global case is splitting the
  home (creds/config global, mise-data per-project) — **named, not built**. The creds/login/
  identity the user chose global *for* persist correctly; only tool self-equip is the caveat.
  Reasoned from the path layout, not separately e2e-proven (a discriminating test needs two full
  project provisions). `ops config` shows each app's
  `home: global (shared across projects)` / `home: per-project`. **The residual the user accepted
  by choosing the global default:** an agent run on an untrusted project writes into the same
  global home a trusted project's run uses (`"project"` is the per-app mitigation knob); with
  Step-3's proxy-injected key the credential is **not** in the home, so the re-login cost of
  `"project"` mostly does not apply. **525 tests green** (schema parse extended + 4 config unit
  [default/set, integrity-gate widening refused, unknown value defaults global, unsafe name
  dropped] + 1 binds unit [each scope a distinct home, a global app project-independent, a
  per-project app nests under the project] + the `ops config` integration extended + a
  **real-sandbox e2e that ran** —
  `an_app_home_persists_across_launches_and_is_isolated_from_the_project_shell`: two `ops app`
  launches count 1→2 = persistence, an `ops run` sees no `COUNT` = isolation from the project
  shell), fmt/clippy clean, **musl static build verified**, advisor-reviewed (plan — it caught
  that the keying default was the user's call, not mine, and had me re-read the secrets doc to
  confirm the creds-dir IS the mounted `$HOME` — AND impl). **Also fixed a pre-existing test
  flake** (own concern, not Step 2): the egress proxy binds a Unix socket under the test data
  dir (`…/ops/egress/proxy-<pid>.sock`), and `sun_path` caps the whole path at 108 bytes; a
  7-digit pid plus the long `run.rs` temp prefix tipped two secret e2e tests over `SUN_LEN`, so
  the temp-dir prefix was shortened. **No built-in apps + export/import (user, 2026-06-20):** ops
  ships **zero** apps — every profile is a separate, portable artifact authored independently and
  **imported** (a conscious trust act; may reuse the signed-store machinery). The ramp is now
  3) flagship `ops app claude` e2e, 4) **export/import of app profiles**, 5) the GUI/Wayland hole.
  **`ops app` export/import — sub-slice 1: import (DONE)** (`src/config/schema.rs` +
  `config/mod.rs` + `src/main.rs`): the portable-profile **import** half — an app profile is a
  **standalone TOML file shaped as a top-level `RawApp`** (the app's fields directly, *no*
  `[app.<name>]` wrapper), whose **filename is the app name** (chosen with the user over the inline
  wrapper: `--as` becomes a trivial different-filename, the import path needs **zero serialization**
  — a verbatim copy preserving comments — and a file is structurally one app). Profiles live under
  **`<config>/ops/apps/<name>.toml`**, a sibling of `ops.toml`, **trusted by location** through the
  same `safety` gate. (Note: an `apps` directory under the *config* root holds profiles, while one
  under the *data* root holds each app's home — two distinct trees.) **Wiring** (`load`): the
  profiles dir is read and its apps folded into `global_apps` **before** `resolve` —
  `resolve_app`/`resolve_apps` are **unchanged**, so a profile gets the global layer's
  trust-by-location, the per-field gating, the `cmd`/`home_scope` integrity gates, and the
  project-overlay layering for free (the **flagship property holds for profiles**: a profile's
  `cmd` and network survive an untrusted project's override attempt — directly tested). The read is
  **infallible** like the rest of `load` (unsafe/unparseable/unsafely-named profile → warn+skip,
  deterministic order); on a name collision an **inline `[app.<name>]` in `ops.toml` wins** with a
  loud warning. The four `ops app` management verbs **`import`/`export`/`rm`/`list` are reserved** —
  dispatched as subcommands **and** rejected as app names (`is_reserved_app_verb`, checked in
  `resolve_apps` and at import), so an app named `import` can never shadow the subcommand
  (advisor-caught dispatch hole, fixed at the source). **`ops app import <file> [--as <name>]
  [--force]`**: safety-gate the source → parse as `RawApp` → **require a `cmd`** (a profile with no
  command is unlaunchable, and an empty parse is the tell-tale of a wrongly-`[app.<name>]`-wrapped
  file, refused with a hint) → validate the name (charset/length, not `.`/`..`, not a reserved verb
  — anti-traversal, since the name keys an on-disk file) → write **owner-only, atomically**
  (temp + rename, like every other on-disk placement; a `--force` overwrite keeps the old profile
  until the new one lands). **The deliberate command IS the consent** (parity with `plugins install
  <dir>` — an agent in the cage cannot run it, and the profile stays **inert until `ops app
  <name>`**), so there is no interactive prompt, but the **granted posture is printed** (command,
  home scope, packages, binds, network, and each credential by **destination + source locator** —
  never a plaintext value, which a profile does not carry; a note flags secrets declared without an
  allowlist, which would not inject). `ops app rm`/`list` manage imported profiles only (an inline
  app lives in `ops.toml`, edited there). **`export` is a reserved stub** — deferred to sub-slice 2
  with a `toml::to_string(&RawApp)` round-trip spike first (serializing `#[serde(flatten)]` +
  untagged enums is a known-fragile `toml` corner; the import path deliberately needs none). **538
  tests green** (7 unit: top-level + wrapped parse, reserved-verb-as-name, profile-keying,
  absent-dir, inline-shadow, validate/summarize + 5 config integration: trusted-by-location,
  the flagship untrusted-override, import/rename/rm, wrapped+reserved refusal, absent-rm + 1 run.rs
  e2e: import→launch under the synthetic identity), fmt/clippy clean, **musl static build
  verified**, advisor-reviewed (plan AND impl — it caught the dispatch hole pre-impl and, post-impl,
  had me re-run the full suite on the atomic-write code, add the flagship untrusted-override test,
  and flag the secret-without-allowlist over-claim, all folded in). **Honest scope:** this is the
  **import** half; **export** (sub-slice 2) and the signed-store *distribution* of profiles (needs a
  hosting URL + long-term key, like the default-store registration) are deferred. The ramp's item 4
  is now: export (next), then signed distribution; items 3 (flagship `claude` e2e) and 5 (GUI) stand.
  **`ops app` export/import — sub-slice 2: export (DONE)** (`src/config/schema.rs` +
  `config/mod.rs` + `src/main.rs`): `ops app export <name> [--out <file>]` — the inverse of import,
  writing a portable profile out. **De-risked by a spike first** (advisor's call): `toml::to_string`
  of a `RawApp` is the known-fragile `toml` corner (`#[serde(flatten)]` secret hosts + untagged
  `cmd`/`network`/`from` enums), so a throwaway round-trip test proved it **lossless** — including a
  `[secret.defaults]` table beside an array-of-tables host (`[[secret."h"]]`) — **before** committing
  to the serialize path. The app types gained `Serialize`; `skip_serializing_if` on the empty-able
  `env`/`binds`/`packages` (and `secret.defaults.order`) keeps the output **minimal** (TOML already
  omits a `None` option), so a one-line app exports as one line. `serialize_app` is the inverse of
  `parse_app` (a permanent round-trip test, plus a bare-string-`cmd` round-trip — `RawCmd::Line` is
  not silently promoted to a one-element array). **Two sources, by origin:** an **imported profile**
  (`<config>/ops/apps/<name>.toml`) is emitted **verbatim** (comments + formatting preserved);
  otherwise an app declared **inline** — project `.ops.toml` preferred over global `ops.toml` — has
  its `RawApp` serialized. The app is exported **as authored, security fields and all, regardless of
  trust** (import is the trust act, not export). **Output = stdout by default** (user's call —
  composable + clobber-safe, `ops app export claude > claude.toml`), `--out <file>` writes directly
  (a user-chosen leaf path → plain `std::fs::write`/`>` semantics, *not* the atomic store-placement
  the managed import does — a deliberate role distinction). **Precedence is the inverse of load's
  collision rule** (export prefers the profile; a launch prefers the inline) — they only diverge when
  one name is both, a state the load-time collision warning already pushes the user to resolve
  (documented on `export_profile`). **The export→import portability loop is proven** (an inline
  untrusted-project app → `--out` file → re-import → resolves as a trusted-by-location app). **541
  tests green** (2 net-new schema unit: the round-trip + the skip-empty/bare-cmd; 1 net-new config
  integration: verbatim-profile + serialized-inline + the round-trip loop + unknown→error), fmt/clippy
  clean, **musl static build verified**, advisor-reviewed (plan AND impl — the spike was its call; it
  flagged the export-vs-load precedence divergence, now documented). Export/import is **complete**;
  the **signed-store distribution** of profiles stays deferred. **Starter app profiles — first three
  SHIPPED (user, 2026-06-21)** (`profiles/{claude-code,codex,opencode}.toml` + `profiles/README.md` +
  a `the_shipped_profiles_import_and_resolve` test): importable `profiles/*.toml` artifacts in the repo
  (NOT built-in — imported deliberately). Each = `cmd` + `[packages]` (the tool from nixpkgs) +
  `[network] allowlist` (the provider host) + `[secret]` (the API key injected **host-side** by the
  egress proxy, never in the cage; an in-cage placeholder lets the CLI start, the proxy strips +
  substitutes the real key on the wire). **Grounded, not guessed:** packages confirmed via `ops search`
  (claude-code 2.1.177, codex 0.139.0, opencode 1.17.4); API hosts/headers are established facts
  (Anthropic `x-api-key`; OpenAI `Authorization: Bearer`); opencode ships as a multi-provider template
  (Anthropic default, allowlist adjustable — the proxy's 6.2e reasons report a refused host). **Honest
  scope:** the profiles **import + resolve** (the test proves it, verified live — `ops config` shows
  `network: allowlist` + `secrets: 1 injected host-side`), but the **live auth e2e** (the CLI
  authenticating through the proxy-injected key — does the tool accept the placeholder?) is the
  **flagship validation, item 3**, pending a real key (the user's; never used by the assistant).
  Freshness: `[packages]` tracks the **base nix channel** (rolled by `ops upgrade nix`; the app overlay
  has no per-tool nixhub-floating — that, and non-nix mise backends, are the **multi-backend
  increment** below). **Deferred / blocked:** the **GUI/Wayland hole** (item 5) gates the *desktop*
  variants (opencode desktop, **antigravity** = Google's agentic IDE, hermes desktop); **pi/agy/hermes**
  await disambiguation (package, argv, API host, credential mechanism — no fabrication); a
  query-param key (Gemini `?key=`) or OAuth/device-flow does **not** fit the header-injection
  `[secret]` model.
  **mise multi-backend — DONE (2026-06-21)** (`src/sandbox/nixhub.rs` + `launch.rs` + `fhs.rs` +
  `binds.rs` + `main.rs`; spike `docs/bwrap-mise-multibackend-derisk-2026-06-21.md`): ops now honors
  **mise's full backend set** (`aqua:`/`github:`/`npm:`/`cargo:`/… and plain registry tools), not just
  the custom `nix:` plugin, for upstream-fresh versions — a project's non-`nix:` `[tools]` are
  **auto-equipped in-cage at launch** so `ops run`/`shell`/`app` start with them on PATH, no manual
  `ops mise install`. **De-risked by a throwaway spike first** (the advisor's call — the load-bearing
  unknown was the shim→PATH chain, not the CLI): a config-declared `aqua:BurntSushi/ripgrep` installs
  in-cage and `command -v rg` → the **shims dir** (the config *sets* the version → the shim resolves,
  unlike a bare ad-hoc install's `No version set`); warm `mise install` = "all installed", **zero
  network** (`latest` does not re-resolve once installed); the persisted shim resolves even without a
  re-install. **The increment, three parts:** (1) **`DeclaredTools` split** (`parse_nix_tools`) —
  `nix` (host-provisioned) / `non_nix` (`MiseTool{token,version}`, auto-equipped) / `malformed` (a
  bad `nix:` token); `provision` now warns only `malformed` (a non-nix backend is **not** a problem,
  it is handled in-cage), and `ops config`/`ops upgrade` reworded to match (`(equipped in-cage via
  mise)` / `Ignored{mise_managed}`). (2) **Auto-install at launch** (`build()` + `wrap_autoequip` +
  `auto_equip_tokens` + `Userland.mise_bin`) — when non-`nix:` tools are declared, the command is
  wrapped `bash -c '<mise> install "${@:1:N}" 1>&2; shift N; exec "$@"'` with the **tokens + command
  positional** (only the absolute mise path + the integer count reach the script → a token from an
  untrusted config **cannot inject shell**), and `MISE_TRUSTED_CONFIG_PATHS = cwd` is set so the
  in-cage mise trusts the project config. **Open by design** (user's call, 2026-06-21) — runs whether
  or not the project is trusted (the agent self-equip path, like `ops mise`); the real gate is that
  `network = "allowlist"` is trusted/global-only, so an untrusted project may *declare* `aqua:evil/x`
  but cannot *open* the egress to fetch it. **Composition** (advisor-caught ordering): the autoequip
  wrap nests **inside** `egress::wrap_command`, so under an allowlist socat is up before the install
  fetches. (3) **`network = "none"`** + a non-nix tool is an inherent conflict → **skip the install +
  loud by-name warning** (best-effort, not the `nix:` hard-fail; a persisted tool still resolves via
  its shim). **The advisor's discriminating case PROVEN live + committed:** a non-`nix:` tool
  downloads via mise's **own reqwest** (not nix's libcurl), which reads the certificate *file* not the
  env — so whether it trusts the proxy's per-session **MITM** CA on a *direct* download was untested
  by the `nix:jq` allowlist smoke (whose heavy fetch is libcurl's). A throwaway probe + committed e2e
  (`the_cage_auto_equips_a_non_nix_tool_under_a_network_allowlist`) settled it green: a trusted
  `allowlist` runs `ops run -- rg --version` → `ripgrep 15.1.0` through the empty-netns MITM, so mise's
  reqwest **does** trust the MITM CA. **Residual:** a non-nix tool **kills offline first-launch**
  (fetches upstream at install) — the price of freshness vs the nix seed's offline reuse;
  `MISE_TRUSTED_CONFIG_PATHS` now also reaches a manual `ops mise` in such a project (a conscious,
  open-posture-consistent widening). **Honest scope (the advisor's #1):** this auto-equips a **project's
  mise `[tools]`** — it does **not** make the shipped app *profiles* fresher (they declare their tool
  via `[packages]`/nixpkgs, and the app overlay has no mise-`[tools]` field); fresh *profiles* is a
  separate slice (the app overlay gains a tools field, or `[packages]` learns non-nix backends).
  **546 tests green** (2 net-new run.rs e2e — shared/open + allowlist/MITM, both ran live; +
  `wrap_autoequip` + `auto_equip_tokens` unit tests + the `DeclaredTools`/`provision`/`upgrade`
  reworks), fmt/clippy clean, **musl static build verified** (no new dep — std-only), advisor-reviewed
  (plan AND impl — it caught the allowlist+MITM blind spot the shared-net e2e could not see, now the
  committed headline proof).
  **`[packages]` backend prefix + fresh app profiles — DONE (2026-06-21)** (`src/config/schema.rs`
  + `config/mod.rs` + `src/sandbox/packages.rs` + `launch.rs` + `main.rs` + `search.rs` +
  `profiles/*.toml`; plan `docs/bwrap-packages-backend-prefix-plan.md`): the slice that makes the
  shipped profiles **fresh** (measured before: nixpkgs lagged — claude-code 2.1.170 vs upstream
  2.1.185, and was additionally **unfree** in nixpkgs). Every `[packages]` value now carries a
  **mandatory backend prefix** — `nix:<attr>` (host-side nixpkgs, durable/seeded/offline) or
  `mise:<token>` (in-cage, equipped **globally** via `mise use -g`, fetched at launch from
  upstream-direct). **No bare form** — a value with no recognized prefix is dropped + warned naming
  the fix (fail-closed, never a silent nix mis-route; a breaking change, fine pre-release).
  `Package` gained a `Backend{Nix(attr)|Mise(token)}`; `parse_backend` routes by prefix (and
  `mise:nix:<pkg>` reaches mise's nixhub verbatim — no third nix path). **Both backends trusted-only
  in `[packages]`** (the advisor-caught integrity fix: per-entry "open mise:" would let an untrusted
  project override a trusted app's package and run attacker code under its posture — the `cmd_trusted`
  hole via packages; closed by keeping `[packages]` uniformly gated, freshness still met because
  profiles are **trusted-by-location**). The **open self-equip stays in `.mise.toml [tools]`** (local,
  `mise install`); `[packages] mise:` is the **global** (`mise use -g`) durable declaration — the
  user's global-vs-local distinction. `packages::mise_packages` collects the admitted (trusted)
  `mise:` tokens; `provision` host-realises only the `Nix` ones; `launch::build` wraps the command
  with `mise use -g <tokens>` (a generalized `wrap_mise_equip(verb, …)`, tokens **positional** →
  no shell injection), nested inside the egress wrap (socat first) and skipped under `network = "none"`.
  `ops config` shows each package's `name -> backend:locator (host-side, durable | in-cage via mise,
  fetched at launch)`; `ops search`'s `[packages]` hint now emits `nix:<attr>`. **Decision on the
  app↔`.mise.toml` interaction (B, with the user):** `ops app` keeps honoring the project's local
  `.mise.toml` (the agent keeps the project toolchain — `ops app` runs *on* the project's code);
  the residual (a malicious project `.mise.toml` could shadow a `mise:` app cmd, since mise resolves
  **local > global**) is **bounded by Mode-B** — the secret is never in the cage and egress is the
  trusted-only allowlist, and in-cage untrusted code can already trigger the same key-injection for
  the allowlisted host, so it adds no new capability (the "strip the project `.mise.toml` for max
  isolation" hardening is a deferred follow-up, the user's call). **The 3 profiles migrated** to the
  fresh backends — `mise:aqua:anthropics/claude-code` (2.1.185, **unfree blocker gone** — it is a
  standalone release binary, not nixpkgs), `mise:aqua:openai/codex` (0.141.0), `mise:opencode`
  (1.17.9). **Allowlist finding (live):** a `mise:` fetch must reach the tool's **distribution host**
  — codex/opencode ride github via the built-in nix-cache allow-set (verified live), but **claude-code
  ships from a Google Cloud Storage bucket**, so its profile **path-scopes that one bucket**
  (`storage.googleapis.com/claude-code-dist-…/*`, least-privilege, not all of GCS). **De-risked by
  spikes first** (advisor's call): `mise use -g` for `aqua:` persists + lands on PATH at the next
  launch, and **two concurrent `mise use -g` writes both land** (mise's config write is
  concurrency-safe — the "2nd terminal" race the advisor flagged is a non-issue). **The trusted-app
  package survives an untrusted override** (the `cmd_trusted` guard mirrored onto packages,
  `apply_packages(protect_trusted)`): an untrusted project may add its own app's packages but may not
  override one a trusted layer supplied — so a malicious project can neither hijack nor *DoS* a global
  app's tool (the flagship "agent on untrusted code" property, now holding for packages too). **551
  tests green** (net-new: `parse_backend`/Backend unit + `mise_packages` filter + `wrap_mise_equip`
  global-verb unit + the trusted-app-package-override guard test + the load-bearing run.rs e2e
  **`a_fresh_mise_package_app_runs_under_its_own_allowlist`** — claude 2.1.185 equipped via `mise use
  -g` at an `ops app` launch and run through the empty-netns MITM under the profile's own allowlist; it
  **ran**, and caught the GCS-host fact the github assumption missed), fmt/clippy clean, **musl static
  build verified** (std-only, no new dep), advisor-reviewed (plan AND impl — the impl review caught the
  integrity hole that made `[packages]` trusted-only, walked back its own #5 nudge to PATH-precedence,
  required the e2e run under the profile's *own* allowlist not shared net, then on the final pass caught
  a **false `ops upgrade` roll-forward promise in the shipped profile/README docs** — corrected to state
  the accurate behavior, fresh-at-first-launch-then-pinned — and the missing trusted-app-package guard
  test, both folded in).
  **Honest scope:** the tool is provisioned **fresh and runs**; the **live auth e2e** (the CLI
  authenticating through the proxy-injected key) stays the flagship validation pending the user's real
  key. The roll-forward of a floating `mise:` package (`@latest` freezes warm) via `ops upgrade` and a
  `/usr/bin/env` shim for npm-only tools (the hermetic cage lacks it, so `npm:` JS tooling is blocked;
  `aqua:`/registry standalone binaries sidestep it) are **named, not built**. See
  [[ubi-backend-deprecated]], [[ops-app-framework]], [[ops-mise-passthrough]].
  **`[packages]` `flake:` backend — DONE (2026-06-22)** (`src/config/mod.rs` +
  `src/sandbox/packages.rs` + `binds.rs` + `fhs.rs` + `launch.rs` + `main.rs`; plan
  `docs/bwrap-flake-backend-plan.md`): a **third `[packages]` backend**, `flake:<ref>`, for a tool
  that ships **only as a nix flake** (no single release binary, no nixpkgs attribute — e.g. a
  uv2nix-packaged Python agent). Built **in-cage** (the user's call over host-side, so an uncurated
  third-party flake's eval+build are contained by the cage): `nix build <ref> --out-link
  <home>/.local/state/ops/flake/<name>` realises the flake output into the **project's own**
  writable store, the out-link's `bin/` prepended to PATH; a warm/offline **short-circuit**
  (`[ -e "$out/bin" ] || nix build …`) makes a second launch a no-op and lets it run with the
  network cut. `Backend::Flake(String)`; `parse_backend` routes the prefix;
  **`is_valid_flake_ref` rejects every local-source form** (`path:`/`git+file:`/a `/`·`.`·`~`
  lead, and the bare registry-indirect `nixpkgs` — an explicit scheme is **required**) so a
  config-supplied ref can never aim the in-cage build at a host path, charset-validated.
  **Trusted-only** like the other two backends, and the `protect_trusted` package guard is
  backend-agnostic, so a trusted app's flake package **survives an untrusted project's override**
  (the flagship property holds for flakes too). `wrap_flake_equip` passes each `(ref, out-link)`
  pair **and** the command **positionally** through a `bash -c` script (zero shell-injection),
  nested **inside** the egress wrap (socat up first) and **skipped under `network = "none"`** with a
  by-name warning. `ops config` shows `flake:<ref>  (in-cage via nix build, fetched at launch)`.
  **555 tests green** (net-new: `parse_backend`/`is_valid_flake_ref` unit with **7 refused
  local/indirect cases**, the `flake_packages` trusted-only filter, the `wrap_flake_equip`
  positional/short-circuit unit, and the load-bearing run.rs e2e
  **`a_flake_package_app_builds_in_cage_then_reruns_offline_from_the_warm_out_link`** — phase 1
  builds `flake:github:NixOS/nixpkgs/<rev>#hello` in-cage under its own `allow = ["cache.nixos.org"]`
  and runs `Hello, world!`; phase 2 rewrites the config to `network = "none"`, re-trusts,
  re-launches, and `hello` **still runs** from the warm out-link — a re-fetch being impossible is
  what proves the short-circuit), fmt/clippy clean, **musl static build verified** (std-only, no new
  dep), advisor-reviewed (plan AND impl — the impl pass caught that `is_valid_flake_ref` admitted
  bare local path-refs and that the warm/offline property was only *structurally* proven; both fixed
  — the local-ref rejection and the 2-phase offline e2e). **Honest scope:** an in-cage flake build
  needs **network at first launch** AND the build's own fetch hosts in the allowlist — the
  `nixpkgs#hello` e2e rides the built-in nix-cache allow-set, but a **uv2nix flake fetches PyPI
  wheels from `files.pythonhosted.org`**, which a real profile's allowlist must add (not exercised by
  the e2e). **v1 floats** (no pin); a `flake:` pin (`nix flake metadata` → a lock) + `ops upgrade`
  for flakes is **named, not built**. The backend packages a tool; it does **not** solve a tool's
  **auth** (a flake-packaged agent still needs a header-injectable credential to be profile-able).
  Also this thread, **starter profiles + a live flake-build validation (2026-06-22):** `profiles/pi.toml`
  (`pi`, multi-provider/Anthropic-default, `mise:aqua:earendil-works/pi`) and **`profiles/hermes.toml`**
  (`hermes`, `flake:github:NousResearch/hermes-agent#default`, keyed OpenRouter) ship and import+resolve
  (`the_shipped_profiles_import_and_resolve`). **hermes's in-cage flake build was PROVEN live** — the
  headline proof that `flake:` equips a flake-only tool: `hermes` lands on PATH after a real in-cage
  `nix build` under its own allowlist (~7.5 min). The build corrected a grounding error — `#default`
  **bundles the node `tui`/`web` front-ends**, so it fetches npm too (not "pure Python"); the profile's
  allowlist gained `registry.npmjs.org` (PyPI `files.pythonhosted.org`/`pypi.org` + npm; runtime
  `openrouter.ai` + `hermes-agent.nousresearch.com`). **A `kilocode` profile was authored then DROPPED
  by the same live build** — two independent blockers, neither a profile typo: (1) the upstream kilocode
  flake is **broken** (build script needs `bun@^1.3.14`, its pinned nixpkgs gives `1.3.11` — fails even
  under `network="shared"`); (2) its `node_modules` step uses **`bun install`**, whose own HTTP client
  does **not** honour ops's egress proxy / MITM CA under an `allowlist` (every dep `failed to resolve`
  though `registry.npmjs.org` was allowed), unlike hermes's `buildNpmPackage` which fetches **through
  nix's fetcher** and works. **`kilocode` was then SHIPPED via a different backend** —
  `mise:github:Kilo-Org/kilocode`, its prebuilt release binary (`kilo-linux-x64.tar.gz`,
  GitHub-attestation + SLSA verified by mise, self-contained), which sidesteps both blockers;
  proven live in-cage (`kilo --version` → 7.3.50). The lesson: for a flake whose build *self-fetches*
  (bun) and so hits the proxy wall — or is broken upstream — prefer the upstream **release binary via
  `mise:github:`**. **Open `flake:` limitation recorded:** a flake build step that fetches with
  its **own** client (bun) rather than nix's fetcher is blocked under the Model-B allowlist — fix = teach
  such builders to honour the proxy or route them through nix's fetcher. Live-auth (the proxy-injected
  key) stays the flagship pending-real-key step for every profile. Triage of the rest (cline/droid →
  `/usr/bin/env` shim; agy/freebuff → OAuth not header; opencode-desktop/t3 → Wayland; aionui →
  Electron-in-cage deferred) in `profiles/README.md`. See [[ubi-backend-deprecated]], [[ops-app-framework]].
  **`/usr/bin/env` FHS facade + the first npm/node CLI profile (freebuff) — DONE (2026-06-22)**
  (`src/sandbox/binds.rs` + `fhs.rs` + `launch.rs` + `tests/run.rs` + `profiles/freebuff.toml`):
  the design answer to *"is nix even the right approach?"* (the user's question, after the
  `/usr/bin/env` friction): **yes — keep nix, complete the FHS-interop facade.** The cage already
  synthesises the only two FHS paths nix's own ecosystem standardises — `/bin/sh` and, now,
  **`/usr/bin/env`** — so an interpreted upstream tool's `#!/usr/bin/env <interp>` shebang resolves
  (a hermetic cage has no host `/usr`). This is **nix convention, not a workaround**; the *retreat*
  would be a full `buildFHSEnv` ambient `/usr` (rejected — the minimal explicit bind set IS the
  confidentiality-by-absence edge). Mechanism: a `Userland.env_bin` (logical `/nix/store/.../bin/env`,
  coreutils) + one `Mount::Symlink` for `/usr/bin/env` in `assemble`, mirroring `/bin/sh` exactly;
  bwrap auto-creates the `/usr/bin` parent, so `/usr` stays the **minimal synthetic tree** (only
  `bin/env`, never the host's). **Advisor-caught (the same class I hit by luck):** the change adds
  `/usr` to *every* cage, so the two tests encoding the old "no `/usr`" invariant
  (`binds.rs`'s hermetic smoke AND `run.rs::run_executes_commands_in_a_hermetic_sandbox`) both went
  red — found via `grep -rn "/usr"` + running the *other* cage-launching paths (pty `shell.rs`,
  doctor `smoke.rs`), now reworked to assert `/usr` is minimal (`USR=bin,`, `/usr/lib` absent) rather
  than absent. `smoke.rs`/`resolver.rs`/`seccomp.rs` build their **own** specs (host `/usr` bound,
  not via `assemble`) → untouched. **Proven live + committed e2e**
  (`a_usr_bin_env_shebang_resolves_in_the_cage`): a `#!/usr/bin/env node` script (with `nix:nodejs`)
  executed *by its own path* → `ENV-SHEBANG-OK v24.15.0` (teeth: a bare `node <script>` would prove
  node, not the shebang path). **This unblocks the `npm:` backend** (the documented gap is closed),
  shipped as **`profiles/freebuff.toml`** — the **first npm/node-runtime CLI profile**: `cmd =
  "freebuff"`, `[packages] nodejs = "nix:nodejs"` + `freebuff = "mise:npm:freebuff"`,
  `[network] allow = ["registry.npmjs.org", "codebuff.com", "www.codebuff.com"]`. **A different
  credential posture (user-accepted, not header-BYOK):** freebuff's npm package is a thin launcher
  that downloads the real ~124 MB binary into the app's **isolated `$HOME`** (`~/.config/manicode/`),
  and authenticates to a **Codebuff account** (model traffic proxied server-side) — so there is **no
  `[secret]`**; the login token persists in the isolated home (in the — isolated — cage, never the
  project shell). **Smoke-first, grounded not guessed** (advisor's discipline — `ENV-SHEBANG-OK`
  proves the shebang resolves, NOT that a real CLI runs): equipped + ran the **real** freebuff binary
  end-to-end through the **empty-netns MITM allowlist** — `mise use -g npm:freebuff` installed via
  the proxy (mise's npm backend honours the MITM CA — the discriminating case), the 46 MB tar
  downloaded through it, `freebuff --version` → **0.0.112**; the allowlist hosts were grounded by
  *reading the launcher source* (download URL `codebuff.com/api/releases/download/...` → 301 →
  `www.codebuff.com`, no further CDN; PostHog telemetry off by default) and confirmed by the proxy's
  refusals. The **`ops app freebuff` path** (import → isolated global home → equip → download) was
  also proven (the 124 MB binary landed in `<data>/apps/freebuff/home/.config/manicode/`).
  `the_shipped_profiles_import_and_resolve` now covers **7** profiles. fmt/clippy clean. **Pending
  (the flagship, like every profile):** the live **login** once inside the cage (whether it completes
  headlessly — URL-paste vs a browser — is unverified; the user's account). `cline` + `droid` (the
  next non-desktop CLIs this facade unblocked) **then SHIPPED** — see the next block. See
  [[ops-app-framework]], [[ubi-backend-deprecated]].
  **`cline` + `droid` profiles — DONE (2026-06-22)** (`profiles/{cline,droid}.toml`; the
  data-driven `the_shipped_profiles_import_and_resolve` now covers **9** profiles): the two npm/node
  CLIs the `/usr/bin/env` facade unblocked, both equipped `nix:nodejs` + `mise:npm:<tool>`.
  **Grounded from primary sources first** (two parallel research agents, every value URL-cited or
  flagged unconfirmed — no guessing): `cline` (`cline/cline`, npm `cline`, a **native platform binary
  via optional-deps** — not a bun self-fetcher, so no proxy-wall risk) is a **clean header-BYOK**
  profile keyed to **OpenRouter** (`OPENROUTER_API_KEY` → `Authorization: Bearer`, injected host-side
  on the wire to `openrouter.ai`, placeholder in `[env]` — the hermes pattern), allow
  `registry.npmjs.org`/`openrouter.ai`/`api.cline.bot`/`data.cline.bot`. `droid` (Factory, npm
  `droid`, also a native optional-dep binary) is **account-class (freebuff-style), NOT clean
  header-BYOK**: it authenticates to a **Factory account** (`FACTORY_API_KEY`, `fk-…`, required for
  headless `droid exec`), and per-provider BYOK lives in `~/.factory/settings.json` (`${VAR}` refs),
  **not** a top-level env var — and Factory's auth **header is not a published, groundable detail**,
  so ops does **not** MITM-inject it; the credential persists in the isolated `~/.factory/` (interactive
  login). A **headless `FACTORY_API_KEY` has no clean ops env-injection path** (the env passthrough
  carries only TERM/LANG, and the `[secret]` broker injects an HTTP header on the wire, not an env var,
  and the profile `[env]` is highest-precedence so a `= ""` placeholder would set *empty* in the cage,
  not pass the host value), so the profile ships **no `[env]`** — freebuff parity; a literal `[env]`
  key is the user's own call (advisor-caught: the first cut shipped a false "ops passes it through"
  claim). allow `registry.npmjs.org`/`app.factory.ai`/`api.factory.ai`. **Both PROVEN live through the empty-netns MITM allowlist**
  (smoke-first): `mise:npm:cline` → `cline --version` → **3.0.29** and `mise:npm:droid` → `droid
  --version` → **0.153.1**, their native optional-dep binaries resolved **through the proxy** (the
  discriminating npm-optional-dep-over-MITM case, the class freebuff settled — passed). **Two live
  observations** (non-blocking): mise skips the npm `postinstall` (`--ignore-scripts=true`) for both
  yet `--version` works (the native bin resolves without it); and `cline` prints a benign `hostname:
  command not found` (absent from the hermetic cage), exit 0 regardless. `ops config` shows `cline`
  with `secrets: 1 injected host-side` and `droid` with none — the posture split, visible. fmt/clippy
  clean. **Pending (the flagship, every profile):** the live credential step — `cline` authenticating
  through the proxy-injected OpenRouter key, `droid`'s Factory account login — the user's key/account,
  never the assistant's. **Next non-desktop CLIs:** the BYOK/account CLI space this facade reaches is
  largely covered; what remains is the **GUI/Wayland** desktop class (the user's deferred track). See
  [[ops-app-framework]], [[ubi-backend-deprecated]].
  **GUI/Wayland — Slice A: the `gui = "wayland"` security field (DONE 2026-06-22)** (`src/config/
  schema.rs` + `config/mod.rs` + `sandbox/launch.rs` + `main.rs` + `tests/run.rs`; spike
  `docs/bwrap-gui-wayland-spike-2026-06-22.md`, threat-model §5a): the desktop-app track opened with
  its **primitive** — a `gui` field that is the **exact mirror of `network`**, a security posture
  gated **trusted/global-only**. `"none"` (default) | `"wayland"` (X11 never offered — the spike's
  protocol enumeration showed Wayland-under-Mutter advertises none of screencopy/virtual-keyboard/
  data-control, the basis for "Wayland never X11"). `GuiPolicy` (config-side enum, `validate_gui`),
  `Resolved.gui`/`ResolvedApp.gui`, `merge_app` precedence, gated in `resolve`/`resolve_app` exactly
  like `network` (an untrusted project can **neither open nor close/override** a display — baseline
  AND app-level, the flagship property both directions unit-tested, incl. `a_global_apps_gui_survives_
  an_untrusted_projects_override_attempt`). **The cage hole** (`launch::resolve_wayland_hole` + the
  `build` gui block): a **read-only bind of the socket FILE** (`$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`,
  never `$XDG_RUNTIME_DIR` itself — it holds dbus/pulse/agents), same-uid so ro `connect()` works;
  env `WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR`; **best-effort** (socket absent → warn + run without =
  fail-closed-by-not-binding); `/dev/dri`/dbus/pulse/X11 **not** exposed (each a separate later
  opt-in hole). Chromium/Electron flags (`--no-sandbox --ozone-platform=wayland --disable-gpu
  --disable-dev-shm-usage`) are **app argv** (profile `cmd`), not hole state — the spike proved a
  real Chromium renderer **survives the M4.1 seccomp cage** (its own SUID/userns/ptrace sandbox is
  blocked → `--no-sandbox` mandatory and acceptable: bwrap+seccomp+empty-netns **is** the boundary)
  and a top-level window **maps** on Mutter. `ops config` shows `gui: wayland (exposure depends on
  your compositor)`. **566 tests green** (schema parse + 6 config gating/flagship + a launch unit
  **with teeth** [the hole binds the socket *file*, asserts `!= the runtime dir`, `file_name ==
  wayland-0`] + the **live e2e** `a_gui_wayland_launch_connects_to_the_host_compositor` — under
  `network = "none"` a trusted `gui = "wayland"` project runs `wayland-info` → exit 0 + `wl_compositor`;
  the netns is empty so a successful connect can **only** be the bound socket), fmt/clippy clean,
  **musl static verified**, advisor-reviewed (plan AND impl). **Honest scope — this is the primitive,
  not yet a usable GUI app** (two deliberate incompletes, same class, no regression — posed only under
  `gui = "wayland"`): (1) **gui + `network = "allowlist"` is untested** — the real desktop-agent target
  (GUI **+** filtered egress, both stacking `ExtraBind`s); the code is trivially correct (disjoint
  dests, local IPC in the empty netns) but **unproven** → Slice C. (2) **`XDG_RUNTIME_DIR` points at a
  read-only dir** (bwrap auto-creates `/run/user/<uid>` on the ro rootfs to host the socket bind), so a
  toolkit wanting to write `$XDG_RUNTIME_DIR/<app>` fails — same class as fonts. **Residuals**
  (threat-model §5a): clipboard (`wl_data_device`, focus-bounded), **compositor-dependent** isolation
  (Mutter safe; wlroots/sway/hyprland *would* expose screencopy + input-injection to ordinary clients),
  and **fonts** (the cage renders boxes without them) → **Slice B (next): font + fontconfig provisioning
  by the hole** (the spike's §4 — a font package has no `bin/` so it **cannot** ride `[packages]`; the
  hole provisions fontconfig + a base font like the base userland, and generates a `fonts.conf` via
  `FONTCONFIG_FILE`). Slice C = a real desktop agent profile (a concrete Electron target + packaging +
  credential, and the gui+allowlist proof). See [[ops-app-framework]].
  **GUI/Wayland — Slice B (fonts) + Slice C1 (composition) DONE; track ACTED CLOSED (2026-06-22)**
  (`src/sandbox/fonts.rs` + `mod.rs` + `launch.rs` + `tests/run.rs`; threat-model §5a). **Slice B —
  font/fontconfig provisioning by the hole:** a fontless cage renders boxes, and a font package has no
  `bin/` so it **cannot** ride `[packages]` — the hole provisions it directly (like the base userland).
  `fonts::provision` realises DejaVu into ops's store (gcroot **keyed by revision** `<data>/gcroots/gui/
  <rev>/`, marker = a **directory** `share/fonts`, not a bin); its roots join `collect_roots`/
  `seed_project_store` so the cage reads them through `/nix`. `fonts_conf` generates a **self-contained**
  fontconfig XML (a `<dir>` per font dir, `<cachedir>` on the cage tmpfs `/tmp/.ops-fontconfig`, 3
  generic-family aliases → DejaVu; every interpolated value ops-controlled → no XML escaping), staged
  **content-keyed + atomic** (`stage`, mirrors `miseplugin`), bound ro at `/opt/ops/fonts.conf` and named
  via `FONTCONFIG_FILE`. **Best-effort** like the socket (provision/stage failure → warn, run without).
  **Parity with Slice A:** `FONTCONFIG_FILE` is fixed by ops; an untrusted `[env]` override only
  re-points the agent's own in-cage fontconfig (self-sabotage, not an escape) → no denylist entry.
  **Scope boundary:** the hole supplies the font *files* + the *configuration*; the fontconfig
  **library** is the app's own (a nix-packaged app's closure; the e2e brings it via `[packages]
  fontconfig`). e2e `a_gui_wayland_launch_provisions_fonts_the_cage_can_find` (ran live): under
  `network = "none"`, `fc-list` lists the **DejaVu store path** — a hermetic cage has no `/etc/fonts`, so
  the store path appears only because the hole seeded the fonts **and** the generated config's `<dir>`
  names them. **Slice C1 — the gui + `network = "allowlist"` composition proof** (the residual Slice A
  named): proven to need **no new production code** — `gui_binds`/`gui_env` and `egress_binds`/`egress_env`
  are disjoint and coexist as wired (the Wayland UDS connects inside the empty netns the allowlist imposes,
  local IPC needing no route). e2e `a_gui_wayland_launch_composes_with_a_network_allowlist` (ran live): a
  **single** `ops run` under both holes emits four co-located markers — `wayland-info` → `wl_compositor`,
  `fc-list` → DejaVu, allowed host → known hash, **denied host → `403`** (under `shared` it would be a
  404, so the 403 proves the allowlist enforces *and* catches a silent trust fallback). **The compose
  tooth = the denied-403 AND the wl_compositor enumeration in the *same* run** (split, they would only
  re-prove Slice A + 6.2d). **Honest scope:** proven = **coexistence** (disjoint binds/env, UDS in the
  empty netns, filtered egress + fonts with the display open); **not** proven = a real desktop **app**, the
  **writable `XDG_RUNTIME_DIR`**, and **compositor-independence** (this is Mutter).
  **Real rendering — PROVEN LIVE 2026-06-22** (the advisor-named gap, the user's "rendu réel" before
  compacting): the fonts don't just list, they **rasterize**. A headless **Chromium** (the desktop-agent
  class engine — the spike proved it runs in the cage with `--no-sandbox`) renders a black `Hello` on
  white to a `--screenshot`, measured by ImageMagick (`%[fx:minima]`/`standard_deviation`): under
  `gui = "wayland"` the hole's DejaVu is present → darkest pixel **0**, std **0.091** (glyphs drawn);
  the **control** `gui = "none"` (no font) renders the *same* page **perfectly blank** → darkest pixel
  **1**, std **0**. The only delta is the font hole → the hole's fonts are what produce rendered text
  (the spike's HarfBuzz `glyph_count: 0` failure, closed). **Heavy live proof, NOT a committed e2e** —
  Chromium re-provisions on every fresh-TmpDir suite run (minutes), so a per-run test is impractical,
  exactly like the in-cage flake build; documented as proven-live. The per-run fonts guard stays the
  Slice B `fc-list` e2e. (The `fc-list`-in-the-render-smoke red herring: it showed `0` only because the
  smoke's `[packages]` omitted `fontconfig`, so `fc-list` wasn't on PATH — Chromium reads
  `FONTCONFIG_FILE` via its own libfontconfig, which the rendering asymmetry confirms.)
  **570 tests green** (1 net-new composition e2e over Slice B; *one config network test degraded to
  skip-not-fail this run* — a transient nix `git-2.42.2` substitution hiccup, not a failure), fmt/clippy
  clean, **musl inherited** (C1 = test + doc, zero production-code change → the Slice-B musl verification
  stands), advisor-reviewed (plan AND impl — Slice B impl review caught the egress-flake-fix-as-separate-
  commit discipline; C1 impl review confirmed both markers catch a trust fallback). **Slice B also fixed a
  pre-existing test flake** (own concern, **a separate commit when committing**): `egress.rs`'s
  `run_sops_passes_…` test wrote a fake `sops` then exec'd it, racing other threads' forks → intermittent
  **ETXTBSY**; a bounded retry scoped to the spawn-error class (a real decrypt/extract error still fails).
  **Slice C2 — a real desktop agent profile — CONSCIOUSLY DEFERRED (user, 2026-06-22):** the triage is
  decisive — opencode-desktop/t3/hermes-desktop have their **CLI twins already shipped** (same agent
  function, no GUI), `agy` is **OAuth-blocked** (a credential problem, not a display one), and **only
  `aionui` *needs* the GUI hole** (Electron/AppImage-in-cage, heavy/unproven). So the user **acted the
  GUI/Wayland track closed here** — primitive + fonts + composition delivered as infra; heavy desktop
  packaging deferred until a concrete need (grounded-not-guessed). See [[ops-app-framework]].
  **`[packages]` freshness roll-forward (mise: + flake:) — DONE (2026-06-22)**
  (`src/sandbox/flake.rs` [new] + `launch.rs` + `binds.rs` + `config/mod.rs` + `mod.rs` + `main.rs`
  + `tests/{run,upgrade}.rs`): `ops upgrade` now advances the two non-nix `[packages]` backends,
  which both **froze at their first-launch version** (the "named, not built" gap from the
  backend-prefix slice). **(1) `mise:` (8 of 9 profiles — the value centre, advisor-reframed from
  difficulty to value)** — spike (mise's own help) settled it: `mise use -g <bare token>` writes
  `latest` (fuzzy; ops sets no `MISE_PIN`), so the config IS mise's lock and **no ops-side lock is
  needed**; the *freeze* is the installed version, so a roll **must run `mise upgrade`** (it fetches,
  unlike the pure host-side lock rewrites). `ops upgrade mise` runs `mise upgrade` **in-cage**, **per
  home** — the project baseline (default home) and **each app** (its own home, by `home_scope`),
  generic over `mise_package_groups` (no app special-cased), reusing `wrap_mise_equip(verb="upgrade")`
  through `build()` + a fork-and-wait `run_status` (extracted from `run_supervised`, since N groups
  run sequentially). The fetch rides the app's egress allowlist; trusted-only (an untrusted project's
  `mise:` is **withheld and named**, not silent — advisor parity); `network = "none"` skips a group;
  **best-effort** when the host can't sandbox. **Semantic recorded + tested:** a baseline `mise:` tool
  is equipped in *every* app home too (an app's cage equips baseline + overlay), so it rolls in N+1
  homes (profiles put `mise:` in app overlays, so baseline is usually empty). **Advisor-caught
  regression fixed:** groups are computed from the already-loaded config **before** any `prepare()`,
  so `ops upgrade nix`/`all` keeps its cheap, sandbox-free path (a first cut paid a full `prepare()`
  — and crashed with a userns error — even with no `mise:` package). **(2) `flake:` (hermes + future)**
  — a **per-project `flake-packages.lock`** (NOT `flake.lock` — collision with nix's own), keyed by
  the *declared* ref: `nix flake metadata <base> --json` (spiked: `.revision` + `.url`; `.url`'s
  `?narHash=…` plus an appended `#<attr>` evals fine) yields `(rev, locked_ref)`; `ops upgrade flake`
  rewrites the lock (pin/roll/prune, best-effort per ref, atomic temp+rename, self-healing reads). A
  launch **consults the lock**: a pinned package builds the **locked immutable ref** into an out-link
  **keyed by the rev** (`flake_out_link_rev`, `<name>-<rev>`), so a re-pin — a rev-keyed path that
  does not yet exist — **rebuilds at the next launch with no home enumerated** (the host-side lock
  rewrite is the whole roll); an unpinned package floats (v1 unchanged; the lock read is skipped when
  there is no flake package). Generic over `declared_refs` (baseline + all apps, deduped,
  trusted-only). `ops upgrade [all|nix|mise|flake]`. `Resolved`/`ResolvedApp` gained `Clone` (no
  cascade — contained types are already `Clone`) for the per-group/per-ref merges.
  **Advisor-reviewed (plan AND impl)** — slice 1: caught the `prepare()` regression + the untrusted
  "no packages" lie (both fixed); slice 2: caught that **no test executed the *locked* launch path**
  (the `Some(pin)` branch + the narHash ref built in-cage through the allowlist — my own
  "build-succeeded-anyway" trap), closed by the committed e2e
  `a_locked_flake_package_builds_the_pinned_ref_into_a_rev_keyed_out_link` (**ran live, 56s**: pin →
  in-cage narHash build through the empty-netns MITM → `Hello, world!` in `hello-<rev>`, not the
  floating `hello`). **Proven live + committed e2es:** `ops_upgrade_mise_rolls_a_mise_package_in_cage`
  (the upgrade cage equips the `rg` shim into the project home — teeth: probe runs an *empty* project,
  so only the upgrade could place it), `upgrade_flake_pins_and_locks_a_declared_flake_package` (pin +
  lock + idempotent "unchanged"), the locked-flake e2e above; + units (mise grouping; flake
  `declared_refs`/`split_attr`/`is_rev`/lock round-trip+self-heal; both report summaries; the
  rev-keyed out-link distinctness = the advisor's load-bearing property b). Full regression green
  (unit ~500 + config 40 + upgrade 3 + run.rs 25 + shell 1), fmt/clippy clean, musl inherited
  (std-only; no new dep). **Named residuals (advisor, deferred):** stale rev-keyed out-links
  accumulate (each roll A→B leaves `<name>-A` + its closure) → **M5-GC class** (re-seed/GC heals,
  same-tenant disk only). *(The once-named "`ops config` does not show a flake's pinned rev" residual
  has since shipped — `package_line` renders `@ <short-rev> (…, pinned)` / `(…, floating)`, read
  network-free from the per-project lock.)* The two slices share the `Clone` derive + the upgrade
  dispatch + re-exports
  + test helpers, so they shipped as **one cohesive commit** (the message delineates both). See
  [[ops-mise-passthrough]], [[ubi-backend-deprecated]], [[ops-app-framework]].
  **M3.3d.2b — direction LOCKED with the user** (a long design discussion):
  project mise `[tools]` prefixed **`nix:`** (e.g. `nix:nodejs = "20"`) are the
  exact-pinned dev toolchain; ops resolves each to the nixpkgs revision that shipped
  it and realises it through its own store. The part after `nix:` **is** the nixhub
  package name (no `node→nodejs` table). The agent self-equips per project; the chosen
  enforcement model is the **open cage** (agent runs `mise install` live, with network
  — full now, per-project egress allowlist deferred à la nono.sh/greywall.io), with two
  non-negotiables: the **shared store stays immutable** (the agent writes a per-project
  layer, never raw rw on `/nix`) and **opening is never settable by an untrusted
  project**. This reverses M3.2a's trusted-only `[packages]` and reopens the M3.2b skip
  (the friction is now the central use case); the residual accepted is host-side nix
  eval + egress, not the binaries (pinned signed catalogue, and the agent already runs
  arbitrary code in-cage → more tools is not an escalation). Open-by-default inverts the
  documented "Mode B default, untrusted" — to record consciously when the cage opens.
  Ramp: **the nixhub resolver first** (this brick), then a per-project store layer, then
  opening the cage, then `ops mise` passthrough.
  **M3.3d.2b resolver** (`src/sandbox/nixhub.rs`): the de-risked new core — turning a
  project's `nix:` `[tools]` into pinned nixpkgs references, with **no new dependency**.
  Two pure halves plus one impure step: parse the `nix:` tools out of the authorized
  mise files (`[tools]` TOML — string/table/array version shapes — and `.tool-versions`
  lines; first declaration of a token wins across files; non-`nix:` and malformed tokens
  reported, never dropped), and select a release's pin from nixhub metadata (filter by
  the host `system`, then `latest`/`stable` newest, exact match, or newest extending the
  request at a `.`/`-` boundary so `20`→`20.x`). The one network step rides **nix's own
  fetcher** — `nix eval --impure --raw --expr 'builtins.readFile (builtins.fetchurl
  "…/v2/pkg?name=<pkg>")'` → `serde_json` → `(commit, attr, version)`; the package name
  is charset-validated so it can never escape the nix string, and the commit (40-hex) and
  attribute are validated before they reach a flake reference. **Wired** (`provision`
  in `nixhub.rs` + `launch::mise_tools` + `ops config`): a trusted project's declared
  `nix:` tools resolve and realise through the existing `[packages]` path
  (`store::provision`, per-project gcroots under `…/nix-tools/<pkg>`, bin dirs prepended
  ahead of `[packages]` so a pinned dev tool wins, hard-fail naming a tool that cannot
  be realised); a non-`nix:` backend or an untrusted project only warns. Resolution is
  cached in a per-project `tools.lock` (tab-framed `pkg/version/system/commit/attr/
  resolved`, atomic temp+rename, corrupt line self-heals) so nixhub is queried once, not
  per launch. Trusted-only for now — the open-cage relaxation (the agent self-provisions;
  the M3.2a/M3.2b reversal) is the deliberate next step. Proven live e2e (`ops run -- jq`
  from a trusted `nix:jq` project → `jq-1.8.1` from ops's store, lock written; untrusted →
  withheld) + **176 tests green**. **Advisor-reviewed** — it caught a real ordering bug
  the green suite structurally could not: nixhub lists releases **newest-first**, but
  `select_release` took `.last()` for `latest` (and the unit fixture was sorted ascending,
  encoding the same assumption), so `latest` silently picked the *oldest* build (an
  earlier e2e's `jq-1.6` was the tell). Fixed to `.first()` + forward scan, the fixture
  flipped to nixhub's real descending order so the test now fails on the bug, confirmed
  live (`latest` jq now resolves `1.8.1`). Also from the review: `ops config` lists
  ignored non-`nix:` tools (so a `node = "20"` absent from PATH is explained), and the
  lock's monotonic growth (no prune on tool removal) is noted for a later upgrade/GC.
  **M3.3d.2b.2/.3 — per-project writable store + THE FLIP** (`src/sandbox/projectstore.rs`
  + `binds::NixMount`): the substrate the open cage stands on. The model is **Option C**
  — each project gets its **own real nix store**, seeded from the immutable shared store
  (an overlay, Option A, was spiked, shipped as a mechanism, then **deleted** when the
  concurrency requirement — multiple cages of the same project installing at once — ruled
  it out: overlayfs forbids two live mounts sharing one upper/work, and the SQLite nix DB
  does not overlay-merge; see [[m3-2b2-store-layer-decision]]). The seed is
  **reflink-or-copy via `FICLONE`** (CoW where the FS supports it, full copy on ext4):
  each base path is a **physically independent inode**, so an in-cage same-uid write hits
  only the project's copy — a hard link would instead share the inode and let that write
  **poison the shared base for every tenant** (demonstrated live, the reason hardlink was
  rejected). The seed is **closure-scoped** (`nix-store -qR` over the declared roots → copy
  exactly that closure; the one closure list is the source of both the copy and the
  `nix-store --dump-db <closure> | --load-db` registration → a self-contained, `--verify`-able
  store) and **atomically placed** (copy into a unique temp sibling → `rename`, so a crash
  or a concurrent same-project seed never leaves a partial at a real store-path name).
  **WIRED and default-on (2b.3.2b.1, user-chosen over folding into the next step):** the
  cage's `/nix` is now a **read-write bind of the per-project store** instead of a
  read-only bind of the shared store — **the Mode-B posture inversion, by default**. The
  shared store is no longer in the cage; an agent that self-equips writes into the
  project's own store. This is **never a configurable field**, so an untrusted project
  cannot keep the shared store mounted or widen its access. The roots the seed copies are
  **surfaced explicitly** from the provisioners (`Provisioned { bins, roots, warnings }`
  from `packages`/`nixhub`; `Userland.base_roots` built from the same provisions as the
  loader/lib/bin sub-paths so none is forgotten; `launch::collect_roots` unions
  base ∪ `[packages]` ∪ `nix:` tools, unit-tested with teeth) — *not* reconstructed by
  stripping sub-paths, since an incomplete root set silently defeats reuse (the cage would
  re-fetch the missing closure and a "build succeeded" test would pass anyway). `build_spec`
  takes a `NixMount { src, writable }` (the old `Userland.store_dir` is gone); the nix-ld
  shim is kept bound read-only from the shared store at `/lib64` (one file, EROFS-safe —
  a read-only bind blocks the same-uid write); `nix-store` is now a hard launch prereq.
  **Write-isolation is proven live through the wired rw bind** (an in-cage
  `echo > /nix/POISON` lands in the project copy while the shared `nix/store` stays
  byte-identical), alongside: the base userland runs *entirely* from the seeded store
  (shared absent from `/nix`), every base root is present, `nix-store --verify` passes,
  and an unseeded shared package is *absent* (the completeness check has teeth). **Cost
  measured:** a project's first launch adds the base closure copy (~400 MB on ext4, ~free
  on a CoW FS); a warm launch is ≈0.33 s total, of which the seed (closure query + db
  top-up, copying nothing) is ≈0.05 s — soft, so default-on was accepted (a later
  optimisation: skip `load_db` when nothing was placed). **Three residuals consciously
  accepted:** the cost lands now while the agent-self-equip payoff is the next step;
  concurrent same-project seeding is now live in production (the M1.4 "2nd terminal"
  feature) but is only *proven* in the concurrency step; and a same-uid agent can overwrite
  a base path in *its own* seeded store (self-harm, the shared store untouched, single
  tenant). **184 tests green**, three consecutive full runs stable; fmt/clippy clean.
  *(A pre-existing tmpfs-inode flake was fixed earlier: `TmpDir` and `tests/run.rs` place
  throwaway stores on the repo disk under `target/test-tmp`, not the `/tmp` tmpfs whose
  fixed inode budget several concurrent nix smokes exhausted — which also matches
  production, where the store lives on disk.)*
  **M3.3d.2b.2.2 — nix in the cage (the open-cage payoff)** (`src/sandbox/fhs.rs` +
  the env denylist): the base userland now carries **nix itself**, so an agent in the
  open cage **self-equips** — it builds and installs a project's toolchain into the
  project's own writable store (the cage's rw `/nix`). `resolve_userland` provisions the
  `nix` attribute beside glibc/gcc/bash/coreutils/nix-ld; nix's root joins `base_roots`
  (so its closure is seeded) and its `bin` joins the base PATH (so the agent reaches it
  by name). **The config surface is empty — ops sets no `NIX_CONFIG`:** a live spike found
  nix's *compiled* defaults already work in-cage — `store = auto` resolves to the local
  `/nix` (the per-project store; `NIX_REMOTE` unset), a **fresh** derivation **builds
  offline** from the seeded base (substituters emptied), and — the surprise that retired
  the advisor's `sandbox=false`/`filter-syscalls=false` prior — **`sandbox = true` and
  `filter-syscalls = true` both succeed** because the cage permits nested namespaces and
  carries no syscall filter yet. **That "no config" result is load-bearing on "no seccomp
  yet"** (recorded in a code comment + memory): nix's build sandbox needs
  `unshare`/`clone(NEWUSER|NEWNS)`, `mount`, `pivot_root`, and `seccomp()` itself, so a
  later cage-level seccomp denylist must allowlist those — or force nix's
  `sandbox`/`filter-syscalls` off — or it silently breaks in-cage builds. Forward-looking
  safety: `NIX_CONFIG`/`NIX_USER_CONF_FILES`/`NIX_CONF_DIR` (the complete nix-config
  injection set, verified against nix's docs) join the **untrusted-only** env denylist —
  an untrusted project's `[env]` must not aim the user's later Mode-A nix at an attacker
  substituter with `require-sigs` off (in-cage it is no escalation, but the same Mode-A
  protection as `NIX_LD`/`LD_*`). **Proven live with teeth** (one smoke): nix is reached
  by name (so it is on the cage PATH), a novel derivation's output is **absent before /
  present after** an offline build (substituters empty, shared store not even bound → the
  success can only be a real local build from the seeded bash+coreutils), the build output
  lands in the **per-project** store, and the shared store stays byte-identical; the
  discriminant — a sibling derivation whose only input is a package realised into the
  shared store but **left out of the seed** — **fails offline**, so "present" means
  "seeded", not "anywhere in the shared store". **Scope (corrected by a live probe — the
  advisor caught an over-claim):** offline reuse from the seed is delivered *now*, and the
  network layer for fetching *new* tools **already works in-cage today** — `nix-prefetch-url`
  over HTTPS to `cache.nixos.org` succeeds with **no** `NIX_SSL_CERT_FILE` set, because the
  cage already `--ro-bind-try`s the host's `/etc/ssl` (nix's default certificate path) and
  `/etc/resolv.conf`. What **M3.4** actually adds is making that TLS **hermetic** — ops ships
  its own cacert so trust no longer depends on the host having a CA bundle at `/etc/ssl` —
  not "enabling" the network (binary substitution uses the same curl/TLS path, so it works on
  any host that has a CA bundle). The one genuinely-deferred piece is `experimental-features`
  for *flake-driven* mise (the `nix:` plugin path, 2b.3.4/2b.4), which the stable CLI this
  increment uses does not need. **Cost re-measured:** adding nix grows a project's first-launch seed by ≈69 MB / 57
  store paths on ext4 (the closure unique to nix — sqlite/boost/curl/libseccomp — over the
  base; ~free on a CoW FS) — the same "cost now, self-equip payoff" residual already
  accepted. **One residual newly named** (deferred, within the accepted self-harm class):
  an in-cage `nix-collect-garbage -d` could delete the seeded base paths mid-session (they
  carry no gcroot *in the project store*) — re-seed heals it next launch, the shared store
  is untouched, single-tenant self-harm; gcrooting the seed in the project store is the
  later mitigation. **185 tests green** (the teeth'd smoke is the net new one), three
  consecutive full runs stable; fmt/clippy clean; advisor-reviewed (the reconciliation
  above) + spike-validated live.
  **M3.3d.2b.3.3 — the concurrency/flock settlement** (`src/sandbox/projectstore.rs`):
  the verdict is **no lock of ops's own**. Two sandboxes of the same project can seed
  at once because the seed is already concurrency-safe by construction — proven, not
  reasoned: (a) each store path is placed by **atomic temp+rename**, so a lost rename
  race is simply a redundant copy discarded (the winner's identical, content-addressed
  path is already in place), and (b) concurrent `nix-store --load-db` merges serialise
  on the project database's own **SQLite locking** (the registration integrity the smoke
  proves). The broader case — a seed racing a live in-cage build, or two agents building
  into one project store — rests on nix's **concurrent store-access guarantee** (that
  database locking plus the per-store-path `.lock` files a build takes), nix's domain not
  ops's, **not exercised here** (the deferred line below); it is the reason Option C / a
  real per-project store was chosen over the overlay, which has no such guarantee. An ops
  flock would only serialise copies the atomic placement already makes safe, and could not
  cover the live builds anyway. The rename-race branch (`Err(_) if dest exists → discard +
  Ok`), previously test-unreached, is now exercised: the placement was **extracted to
  `place_atomically`** (a named unit with the race doc) so the lost-race branch (a
  pre-existing non-empty dir → ENOTEMPTY → Ok, winner kept, temp discarded) and the
  hard-failure branch (ENOENT, dest absent → propagate, temp discarded) are
  **deterministically** unit-tested. The headline is a **live concurrent-seed smoke**:
  4 threads seed the same project from the same roots into a **fresh** project store
  (so all race on first-creating the database — the sharp interleave), then the proof
  has **teeth on *registration*, not on-disk presence** — a bad concurrent `--load-db`
  merge manifests as a path copied but never *registered* (a dangling/missing ref),
  which `--verify` (it iterates only registered paths) and a file-existence check
  cannot see; so the test asserts the project DB's reference graph (`nix-store -qR`)
  **equals** the shared store's closure, then `--verify --check-contents` passes, no
  `.tmp-` leaked, and the shared store is byte-identical. **Cost named** (accepted perf
  residual, not a correctness gap): without serialising, N concurrent *cold* seeds each
  copy the closure before their rename, so the losers' copies are wasted I/O (bounded by
  the base closure, only on a project's first cold launches; a per-project seed lock is
  the future optimisation). **Scope stated, not narrowed (deferred line):** a seed racing
  a live build into the *same* store — and two agents building into one store, arguably the
  headline open-cage concurrency — rests on nix's concurrent store-access guarantee (DB
  locking + per-store-path `.lock` files), not separately exercised here; the one test that
  would *prove* it (two threads each `nix build` a distinct trivial derivation into one
  seeded project store, assert both succeed + `--verify`) is a deferrable follow-up, nix's
  domain rather than ops code. **188 tests green** (the two `place_atomically` unit tests + the concurrent-seed smoke
  are net new), three consecutive full runs stable; fmt/clippy clean; advisor-reviewed
  (it sharpened the smoke onto registration — the change that makes it prove its own
  claim).
  **M3.3d.2b.4 — `ops mise` passthrough (the open-cage self-equip, shipped)**
  (`build.rs` + `src/sandbox/miseplugin.rs` + `fhs.rs` + `binds.rs` + `launch.rs` +
  `main.rs` + `mise/lib/platform.lua`): the agent self-equips a project's `nix:`
  toolchain **from inside the cage** — `ops mise install nix:<pkg>` resolves the tool
  through nixhub and builds it into the project's **own** writable store, never the
  host. **De-risked by a live throwaway spike first** (the advisor's call — the load-
  bearing unknown was the lua plugin against the relocated store, not the CLI verb):
  the spike proved `mise install nix:jq` works in-cage and surfaced the exact
  ingredients, each found by a *failing* iteration, not by reasoning —
  [`docs/bwrap-mise-incage-derisk-2026-06-18.md`](docs/bwrap-mise-incage-derisk-2026-06-18.md).
  Those ingredients are the design: (1) **mise in every cage** — added to the base
  userland beside nix (user-chosen over on-demand, so an agent self-equips from any
  `ops run`/`ops shell`, not only `ops mise`); provisioned against the **project**
  channel (one-channel rule), seeded, on PATH. (2) **The `nix:` backend plugin is
  embedded in the binary** (`build.rs` walks `mise/` → a `(path, bytes)` table, no new
  dep), staged read-only content-keyed under `<data>/mise-plugin/<hash>/` (atomic
  temp+rename, like the store seed), bound at `/opt/ops/mise-nix-plugin`, and
  **registered per launch** by an *atomic* symlink (`symlink`+`rename`, concurrency-safe
  for the "second terminal" — the advisor caught a remove-then-create race in the first
  cut) at `$MISE_DATA_DIR/plugins/nix`. (3) **Structural cage env** (lowest precedence,
  set by the assembler so it is config-independent): `MISE_EXPERIMENTAL=1` (the `nix:`
  custom-backend gate), `MISE_YES=1` (non-interactive install never blocks),
  `MISE_DATA_DIR` under the writable home, and `NIX_CONFIG=extra-experimental-features
  = nix-command flakes` (the plugin's `nix build` is a flake ref; `extra-` is **additive**
  — it does not touch `sandbox`/`substituters`/`require-sigs`, so the offline base build
  and the "no-seccomp-yet" reasoning hold; this **supersedes** the earlier "ops sets no
  `NIX_CONFIG`" note). All three nix-config-injection keys are already on the
  untrusted-only denylist, so only a *trusted* project could override ops's value (self-
  harm). (4) **The vendored plugin's `which nix` → `command -v nix`** — the hermetic cage
  carries no `which` binary (it is a separate package, not coreutils); nix was on PATH
  the whole time, the probe was wrong. **Open by default** — `ops mise` works whether or
  not the project is trusted (the documented Mode-B self-equip inversion), unlike
  `ops run`'s host-side `nix:` provisioning which stays trusted-only. **Activation
  (the boundary 2b.4 deferred is now CLOSED — see 2b.5 below):** an `ops mise install`ed
  tool **persists** in the project store and `mise exec` resolves it; a tool the agent
  **activates** (`mise use`) is auto-on-PATH in later launches, while a bare `install`
  (not activated) stays reachable only via `mise exec`/`mise which`. **Two-path
  divergence (recorded):** `ops mise install`
  (in-cage lua plugin → `nixhub.lua`) and `ops run`'s host-side `nixhub.rs`→`tools.lock`
  are parallel resolution+realise paths sharing no state — a self-installed tool is not
  in `tools.lock`, not reproduced by a fresh `ops run`, outside `ops upgrade mise`.
  **Latent gap CLOSED by M3.4:** the plugin shells `find` (findutils) on the
  `MiseEnv`/flake path (not the `nix:` install path used here) — the curated-base-
  packages concern, now resolved (`findutils`/`which` ship in the base toolset).
  **Proven e2e through the real binary** (`ops mise install nix:jq` →
  `jq-1.8.1`, `ops mise ls`, `ops mise exec` all work; the "not activated" warning
  observed live) + a **network smoke** (`the_cage_self_equips_a_nix_tool_via_mise`:
  an **untrusted** project self-equips jq, the binary runs from the per-project store,
  and the **shared store stays byte-identical** — skip-not-fail when the cache is
  unreachable, the project's first network-dependent test). **193 tests green** (3
  miseplugin unit + the network smoke + the register-concurrency unit are net new),
  fmt/clippy clean; advisor-reviewed (it caught the register race and the NIX_CONFIG
  doc contradiction — both fixed).
  **M3.3d.2b.5 — tool activation (the persistence the user pulled forward)**
  (`src/sandbox/binds.rs` + `src/sandbox/launch.rs`): a tool the agent **activates**
  (`mise use [-g] nix:<pkg>`) is **auto-on-PATH** in a later, separate launch — without
  re-declaring it and without mutating the project's repo. The user's ask was *"je veux
  que ce que l'agent a fait soit persistent"*; the build already persisted (per-project
  store + mise data dir are durable, proven by a two-launch test), so the only gap was
  **activation** (auto-on-PATH), and that is what shipped. It uses **mise's two
  documented activation mechanisms — not a kludge** (verified against mise's docs +
  live): the **shims dir on PATH** (`$HOME/.local/share/mise/shims`) for `ops run`,
  mise's prescribed mechanism for a non-interactive context (it execs the command
  directly, no shell to hook); and **`mise activate`** for `ops shell`, its interactive
  mechanism — bash is started `--rcfile <synthetic rc>`, a static read-only rc bound at
  `/opt/ops/bashrc` that sources `~/.bashrc` (parity: plain bash already reads it) then
  `eval "$(mise activate bash)"`. PATH order is `declared tools > shims > base`; the two
  mechanisms coexist (no warning, activate puts the *real* bin ahead of the shim);
  `mise activate` leaves base tools (`ls`/`nix`) resolvable (it manages PATH, never
  resets it). Decision **(b)** with the user: activation is **local, no repo mutation** —
  the equip verb is `mise use -g` (writes `~/.config/mise/config.toml` under the
  persistent home, never the repo); **reproducible-in-git is the separate, deliberate
  path** (put `nix:` in the repo `mise.toml`, a future skill guides the agent). **The
  install-vs-use seam:** with shims on PATH, a bare `mise install` (no `use`) is *not* on
  PATH — it leaves a shim that errors `No version is set`, pointing the agent at
  `mise use` (mise's own install≠use split, surfaced not hidden). `mise_plugin_src` +
  `shell_rc_src` grouped into `SandboxPaths` (kept `assemble` ≤7 args). **195 tests
  green** (the rcfile-bound unit + the cross-launch activation network smoke are net
  new), fmt/clippy clean; advisor-reviewed (it had me verify the persist claim with a
  two-launch run, confirm base tools survive activate, and correct the stale records);
  proven live (fresh `ops run -- jq` via the shim, pty `ops shell` via activate's real
  bin).
  **M3.3d.3 — `ops upgrade mise` (the explicit roll-forward for mise, DONE)**
  (`src/sandbox/nixhub.rs` + `mise.rs` + `fhs.rs` + `launch.rs` + `store.rs` + `main.rs`):
  the deliberate way a project's mise toolchain advances — versions still never move on an
  ops binary update (the seeded-not-baked contract), only on an explicit `ops upgrade`. Two
  halves. **(a) tools.lock roll + prune (3d.3a)** — `nixhub::upgrade_tools` re-resolves each
  **floating** `nix:` pin (`latest`/`stable`/a prefix like `20`) against nixhub → its newest
  commit and rewrites the per-project `tools.lock`; a tool whose request is an **exact**
  version is left untouched (already pinned). It also **prunes** lock entries whose tool has
  left the config (closing the monotonic-growth residual noted at 2b.1-wire — a
  removed-then-readded tool no longer reuses a stale pin). Trust-gated like the launch path;
  an untrusted project rolls nothing. **(b) a dedicated engine lock (3d.3b)** — the mise
  **engine** now tracks its own `<data>/mise-engine.lock`, independent of the base channel
  (`nixpkgs.lock`), so `ops upgrade mise` advances the engine **without** bumping the base
  (glibc/gcc/`[packages]`) of non-pinned projects, and `ops upgrade nix` no longer touches the
  engine. Running the in-cage mise on a revision ≠ base is safe because the cage exposes **no
  global `LD_LIBRARY_PATH`** — the engine resolves its own glibc by RUNPATH, exactly like a
  cross-channel `nix:` tool (the nix-ld property). Both engine consumers — the in-cage mise
  seeded into the per-project store, and the host-side `[env]` mise — ride the **one** engine
  lock via `mise::provision_engine` (gcroot keyed by the engine rev; callers derive `bin`).
  `store::resolve_engine_ref` is the **migration-safe** resolver (an advisor-caught blocker):
  reuse the engine lock if present (no nix); else **seed it from `nixpkgs.lock`** when the
  source matches (no nix — so an established install with a base lock but no engine lock never
  re-resolves at the network on its first post-update launch, never carries two glibcs, and
  works offline); else resolve fresh. `ops config` gains an `engine: <source> @ <rev>
  (<origin>)` line beside `nixpkgs:`; `ops upgrade [all|nix|mise]` — `mise` rolls engine +
  tools, `nix` rolls the base channel, `all` rolls all three, each reported by the
  parameterized `channel_upgrade_summary`. **480 tests green** (engine-lock construction + 2
  nix-free migration discriminants + a deterministic "two commands, two locks" decoupling test
  are net new over 3d.3a's roll/prune tests), fmt/clippy clean, advisor-reviewed (plan AND
  impl — it caught the migration blocker, fixed by `resolve_engine_ref` + the discriminant
  test). Proven live (engine `rolled forward … → 567a49d`; decoupling both directions —
  `upgrade mise` leaves `nixpkgs.lock` intact, `upgrade nix` leaves `mise-engine.lock`
  byte-identical; `ops config` showing the two locks at distinct revs). **Honest scope:** a
  real `ops run` with `engine_ref ≠ base` was not re-run live (a 2nd full base provision is
  minutes) — covered structurally by the nix-ld smoke + the migration unit test.
  **M3.4 — hermetic TLS + a curated base toolset (DONE)** (`src/sandbox/fhs.rs` +
  `binds.rs` + `launch.rs`): two slices, shipped together. **(a) hermetic TLS** — the base
  userland now provisions its **own `cacert`** (nss-cacert) beside glibc/bash/nix/mise, and
  the cage binds ops's bundle **read-only at BOTH conventional paths** instead of
  `--ro-bind-try`-ing the host's `/etc/ssl`: `/etc/ssl/certs/ca-bundle.crt` (nix's libcurl
  default) **and** `/etc/ssl/certs/ca-certificates.crt` (the Debian/OpenSSL spelling). Both
  paths are needed because the two TLS clients in the cage disagree — **nix** (libcurl) reads
  `ca-bundle.crt` *and* honors the `*_CA_*` env, but **mise** (reqwest) reads the **file**
  `ca-certificates.crt` and does **not** honor `SSL_CERT_FILE`; nss-cacert ships only
  `ca-bundle.crt`, so ops binds its one bundle at both names (the regression that proved this:
  a dir-bind exposing only `ca-bundle.crt` let nix fetch but broke every mise smoke — caught
  live, fixed to two file-binds). `cacert_env()` also exports ops's bundle under the broad
  `CA_FILE_ENV_KEYS` set (the same const the egress MITM uses) so env-reading clients agree
  with the file. **Precedence is explicit** — `extra_cage_env` layers `structural <
  passthrough < cacert < mise < egress < cfg.env`, so under `network = "allowlist"` the
  egress MITM CA (injected via the same keys, replace-not-append) **wins** over the structural
  cacert (a launch-path unit test `egress_ca_overrides_the_structural_cacert` pins this);
  with `network = "shared"`/`"none"` the cacert is the cage's trust root and the host's CA
  bundle is **no longer in the cage at all** (`the_cage_trusts_ops_own_ca_bundle_not_the_host`).
  **(b) curated base tools** — the base carries a small everyday CLI set (`BASE_TOOLS`:
  `curl git less gnugrep gnused gawk findutils which`) provisioned into ops's store, bins
  prepended to the base PATH, **sharing the base glibc** (the one-channel rule — these are the
  OS-substrate layer, not cross-channel dev tools). This closes the earlier latent gap (the
  mise `nix:` plugin shells `find`/`which`, absent from a bare hermetic cage). **`xdg-utils`
  was considered and dropped** (user call) — measured at **+76 MB / 42 store paths** of
  dbus/glib/systemd-libs/X11 (a GUI stack) dragged into every project's seed for no headless
  benefit; the curated-set doc records "declare it per project if ever needed". `git`'s
  closure (≈353 MB, perl) dominates the set; the other seven are negligible. **Proven live +
  committed e2e:** `a_shared_network_launch_trusts_ops_own_cacert` (a real
  `nix-prefetch-url` over the cage's hermetic TLS, with **causation teeth** —
  `NIX_SSL_CERT_FILE=/dev/null SSL_CERT_FILE=/dev/null` makes the same fetch fail, so success
  means the bound bundle, not a leaked host one); `the_curated_base_tools_run_in_the_cage` (one
  launch runs each curated tool by name); and `the_cage_self_equips_via_mise_under_a_network_
  allowlist` (a **trusted allowlist** project runs `ops mise install nix:jq` end-to-end —
  the load-bearing proof that mise's reqwest trusts the MITM CA through the `ca-certificates.crt`
  file-bind, which an advisor flagged as a likely blind spot and the live run **disproved**).
  The seed-witness smoke's "unseeded" probe moved `jq`→`hello` (xdg-utils' closure contains
  `jq`, which would have made the witness legitimately present). **486 tests green** (3 net-new
  run.rs e2e + new unit tests in fhs/binds/launch), **4 consecutive green full runs**
  (fmt/clippy clean), advisor-reviewed (plan AND impl). The threat-model bind-layout doc row
  was split: `/etc/ssl/certs` is now **ops's own cacert (ro)**, distinct from the host's
  best-effort `/etc/resolv.conf`.
  **M3.5 — `ops search` (tool discovery, DONE)** (`src/sandbox/search.rs` + `nixhub.rs` +
  `mod.rs` + `main.rs`): a host-side, **read-only**, **no-trust-gate** discovery front-end
  (the posture of a plain `nix search`) that turns "what `nix:` tool do I declare?" into one
  command. **Spike-decided away from `nix search`:** probes found nixhub exposes a fuzzy
  endpoint (`search.devbox.sh/v2/search?q=`, `{results:[{name,summary}]}`), so the whole
  increment is nixhub-based — lighter and reusing the resolver's machinery — and the heavy
  `nix search` (full nixpkgs eval, tens of seconds cold) was **dropped as unnecessary**.
  **Two behaviours over one verb** (the user's "floue + versions" scope): a fuzzy query lists
  matches (`name — summary`, capped at 25, name column capped so one long `python312Packages.…`
  cannot blow out alignment); when the query **names a package exactly** (case-insensitive), the
  report **leads** with that package's versions for the host system + the lines to declare it
  (`[tools] "nix:<pkg>" = "<latest>"` / `[packages] <pkg> = "<attr>"`) and a compact `related:`
  footer. **No new dependency:** the one network step rides the **shared** nix fetcher — the old
  private `fetch_metadata` was generalised to `fetch_url_json` (the `builtins.fetchurl { url;
  name; }` form, an explicit store-path name so a query-string URL with percent-encoding's `%`
  fetches cleanly — the bare-string form errors on `%`), reused by both search and the resolver;
  `platform_for` exposed so the version shape is read in one place. **Free-form query made safe by
  construction:** percent-encoded to the RFC-3986 unreserved set before it reaches the URL, so it
  carries no `"`/`$`/`\`/space/control to escape the nix string literal (the resolver's
  validated-pkg interpolation trick does not apply to a free query — the advisor's point). **Three
  exact-hit states, not two** (advisor-caught best-effort bug): the version GET is *enrichment*
  over a search that already succeeded, so its failure is `Exact::Unavailable` → render the list +
  a "could not fetch versions" note, **never** discard the list (the naive `?` did) and **never**
  the absurd "name a package exactly" nudge after the user already named one (the `Err(_)=>None`
  trap); the no-host-build case is the third state. **509 tests green** (9 net-new search unit +
  the failure-state render branch + a live skip-not-fail integration that *ran*), fmt/clippy clean,
  musl static build verified, advisor-reviewed (plan AND impl). Proven live: `ops search jq`
  (versions-first + declare hints), `ops search ripgr` (capped fuzzy list + exact-name nudge).
  **M6.0 — the network slice + the P-vs-B architecture lock** (`src/config/` +
  `src/sandbox/launch.rs` + `ops config`): the network increment ("network last")
  opened with its **cheapest, decision-independent slice** — a trusted-only
  `network = "none"` posture — plus a live spike that **decided the egress
  architecture**. The slice: a `network` security field (`"none"` → an empty netns,
  `"shared"` → the host network, the default) gated **exactly like `binds`/`nixpkgs`**
  — honored from the global config (trusted by location) or a trusted project, dropped
  with a warning from an untrusted/changed one (proven both directions: an untrusted
  project can neither cut nor reopen the network). A config-local `NetworkPolicy` enum
  maps to the cage's `NetPolicy` in `launch::net_policy` (the two posture vocabularies
  kept separate — config is the user's, `NetPolicy` is the sandbox's and is where the
  allowlist will grow). **Zero new cage machinery**: `to_argv` already emits
  `--unshare-net` for `NetPolicy::Isolated`, and the live cage-isolation proof already
  exists — the spike's Q5(a) showed `bwrap --unshare-net` yields `lo`-only with curl
  failing, the live endpoint of the resolve→`net_policy`→argv chain. The `network` field
  rides the existing whole-file SHA-256 trust hash for free, so a trusted project cannot
  have its posture flipped post-`trust`. String-now/table-later is forward-compatible (a
  future untagged enum subsumes the bare string). Proven live (`ops config`: untrusted
  `network="none"` → `network: shared` + warning; after `ops trust` → `network: none`)
  + **204 tests green** (schema parse, 6 gating cases, the `net_policy` map, an `ops
  config` integration case), fmt/clippy clean, advisor-reviewed.
  **The P-vs-B spike** ([`docs/bwrap-net-spike-findings.md`](docs/bwrap-net-spike-findings.md),
  throwaway, host pasta — nothing installed): the two egress architectures are **Model P**
  (`--unshare-net` + pasta NAT uplink, then filter) vs **Model B** (empty netns, no uplink,
  the only egress a host-side allowlisting proxy reached over a bound socket — deny-by-
  construction). Evidence **locks B**: (1) **P-attach is impossible unprivileged** (bwrap
  makes its own userns where the host pasta has no `CAP_SYS_ADMIN` → `setns` refused), so P
  is reachable only via **P-inherit** (`pasta … -- bwrap --share-net`), pasta-as-outer-
  process, which is *invasive* — it mangles `ops run`'s exit-status propagation and the
  `ops shell` pty session leadership. (2) **P is fail-OPEN by default** — the cage reaches
  host loopback by two paths + would reach cloud metadata; closing it needs the exact
  non-obvious `--no-map-gw -T none -U none` (the intuitive `--no-splice` is a trap that
  leaves `127.0.0.1` open). (3) **B is fail-CLOSED by construction** — empty netns → no
  route/DNS/metadata/loopback for free, the single bound socket the only egress (proven
  from the *same* cage). (4) **both need the proxy anyway** (pasta can't filter by
  hostname), so P = B's work + pasta topology rework + fail-open; the 6.3 credential-
  injection proxy reuses the same host proxy. (5) curl **and** nix honor `http_proxy`/
  `https_proxy` (Q6), so the two tools that matter for self-equip are already proxy-aware.
  **B's true mechanism is NOT "just a bound UDS"**: it is the Codex pattern — an in-cage
  TCP→UDS forwarder (so tools use `http_proxy=127.0.0.1:PORT`) bridging over the bound
  socket to a host-side **CONNECT allowlisting proxy**. The spike validated the
  *primitives* (empty-netns denies all; a bound UDS bridges to a host proxy; curl/nix
  honor proxy env), **not** the integrated data path — so an **integrated-path micro-spike**
  (a real HTTPS fetch through forwarder→UDS→a real CONNECT proxy, **with teeth — a
  non-allowlisted host must be refused**) **gates the 6.2 build, not the decision**.
  **Security does not depend on the forwarder's integrity** (pure ergonomics — bypassing it
  just talks to the same allowlisting socket or loses egress, fail-closed either way; the
  boundary is empty-netns + the host proxy). **B CONFIRMED with the user (2026-06-18)**, with
  one added requirement: **the default posture must be overridable in the GLOBAL config** (the
  user's open-by-default escape hatch) — already supported, since the global `ops.toml` is
  trusted-by-location and honored in full, so a global `network = "shared"` overrides whatever
  ops's built-in default becomes; an untrusted project still cannot touch it. Open sub-decision
  deferred to 6.2: the built-in default *before* any global override once the allowlist exists
  (likely `"allowlist"` deny-by-default, `"shared"` the escape hatch). The **integrated-path
  micro-spike PASSED** (`docs/bwrap-net-spike-findings.md`, throwaway): the full chain — tool →
  in-cage `socat` TCP→UDS forwarder → bound UDS → a host CONNECT allowlisting proxy — works for
  **both curl and nix**, with **teeth** (an allowlisted host gets HTTP 200 / a real fetch; a
  non-allowlisted host is **actively refused 403 at the proxy**, proven for curl AND nix's 5
  retries; a direct no-proxy fetch fails — empty netns, no route, no DNS). DNS is **host-side**
  in the proxy (`CONNECT host:port` carries the hostname, the cage never resolves → DNS-exfil
  closed too). So the 6.2 build is de-risked. **Allowlist granularities + MITM (user, 2026-06-18):**
  the allowlist must support four granularities — an IP, an exact domain, a domain + its
  subdomains, and an **exact URL** (path-level). A CONNECT proxy only sees `host:port` for HTTPS
  (the path is in the TLS tunnel), so the first three (host-level) are free, but **exact-URL
  needs a TLS-terminating MITM** — ops generates a CA, injects it into the **cage's** trust
  store (never the host's), decrypts/inspects/re-encrypts. **The user chose MITM IN 6.2** (all
  four from the start), accepting that the proxy sees all plaintext (already so for 6.3) and
  cert-pinning tools break. **MITM non-negotiables** (else it *downgrades* security): the proxy
  MUST validate the *upstream* cert against the system CA bundle; the CA private key is
  per-session, owner-only, ideally ephemeral; ops's CA goes only into the cage trust store.
  **MITM micro-spike PASSED** (appended to the findings doc, throwaway): a ~200-line host MITM
  proxy (ephemeral CA via `cryptography`, TLS-terminating via `ssl`) proved (1) **nix fetches
  through the MITM** with ops's CA trusted (the load-bearing unknown — yes; nix's TLS is libcurl
  + the cert bundle, and `require-sigs`/NAR-hash verification is orthogonal to transport); (2)
  curl works (200); (3) **exact-URL/path filtering has teeth** — same allowed host, different
  path → 403 (the capability that justified MITM); (4) host-deny → 403; (5) **upstream-cert
  validation has teeth** — a self-signed upstream is refused with 502 (`UPSTREAM-CERT-REJECT`),
  so the MITM does not downgrade transport. (Bug the spike surfaced for the real matcher: URL
  reconstruction must include the **port**.)
  **6.2a — the allowlist schema + matcher + `ops test net` tester SHIPPED** (`src/allowlist.rs` +
  config + main, 249 tests, advisor-reviewed, live): the user chose a **single list classed by
  syntax**. `[network] mode = "allowlist"`, `allow = [...]`, **`deny = [...]`** — and **deny
  ALWAYS wins** (the user's case: "allow a domain but deny a precise URL or subdomain inside it"
  — e.g. `allow github.com` + `deny github.com/secret`, or `allow *.nixos.org` + `deny
  evil.nixos.org`). The `network` field is `string | table` (serde **untagged**,
  forward-compatible from the `"none"`/`"shared"` string form). The matcher (`Rule` +
  `EgressPolicy{allow,deny}`; `explain` → `Decision{DeniedBy|AllowedBy|DeniedDefault}` names the
  deciding rule, `permits` a bool view) classifies **five** kinds by syntax — IP (literal host),
  exact host (not subdomains), `*.domain` (apex + subdomains, suffix-spoof-safe), a
  **scheme-free `host[:ports]/path` URL** (**exact path by default, or a `/*`-suffixed subtree**;
  same port-set syntax as the host kinds), and **`re:<pattern>` regex** over the whole reconstructed URL
  `https://host[:port]path`. **Regex = the user chose Model 2** (full-URL `re:`) over Model 1
  (host-structured + path-regex): the structured kinds stay **exact/spoof-safe** (`api.github.com`
  never matches `api.github.com.evil.com` nor `myapi.github.com` — the user's explicit
  requirement, tested), while `re:` is unanchored so the author owns anchoring/escaping (an
  unanchored host-regex is the classic bypass). Engine = the **`regex` crate** (new dep,
  user-approved by choosing Model 2; linear-time / **ReDoS-immune** — a real security property in
  a filter). A bad regex → classify error (dropped+warned, fail-closed). **Path semantics
  (user-refined):** a `Url` is **exact by default** (`…/secret` matches `/secret` and its
  same-resource canonical variants `/secret?x`/`/secret/`/`%2f`/`/foo/../secret`, NOT `/secret/sub`)
  and a trailing **`/*`** matches the path and its whole subtree (`…/secret/*` covers `/secret/sub`,
  segment-aware so not `/secretarial`) — no regex needed; `re:` is for query-specific/arbitrary.
  **Port model (user-decided — the deferred "443/80 pinning" is now DECIDED):** each host kind
  (`Ip`/`Host`/`Subdomain`) carries a **port set** (`Ports::{Any, Ranges(Vec<(u16,u16)>)}`). A bare
  entry (`github.com`, `1.2.3.4`, `*.nixos.org`) defaults to the **web ports {80, 443}** — least
  privilege, so `allow github.com` can't be CONNECT-tunnelled to :22. A `:`-suffixed spec pins
  exactly those: a comma list of single ports and/or inclusive **`lo-hi` ranges** (`github.com:443`,
  `internal:8080,9000-9002`, sorted+de-duped), or **`:*`** for any port. A **path rule carries the
  same `Ports` set** (`github.com:443/secret`, `example.com:*/admin`; a bare `host/path` defaults to
  {80, 443}) — `Rule::Url` now holds `ports: Ports`, not a single `port: u16`. **IPv6 handled
  end-to-end:** bare
  (`::1`) at the default ports; **bracketed** with a port (`[::1]:443`, `[2001:db8::1]:*`,
  `[::1]:8080/admin`) so its own colons don't confuse the split — both the host kinds
  (`split_host_ports`) and the path-rule parser (`parse_path_rule`) parse it, and `Display` re-brackets it
  (round-trips, proven live through `ops test net`). **Advisor-caught (same class as the deny-evasion
  hole):** a `Url` host is matched as a **plain string**, but IPv6 has many spellings of one address
  (`::1` == `0:0:0:0:0:0:0:1`), so `deny https://[::1]/secret` was dodgeable by the long form (the
  `Ip` kind was safe — it compares `IpAddr`). FIXED — `canonical_host` normalizes an IP-literal host
  once, on **both** sides (`Request::new` and `parse_url_target`), so every spelling compares equal;
  the fix lands in `Request::new` exactly where the 6.2b proxy will build requests (free for it). The
  fixtures that missed it used the same spelling on both sides — the test now uses *different* ones
  (proven live: `[0:0:0:0:0:0:0:1]/secret` DENIED under `deny [::1]/secret`).
  **No host catch-all (`reject_catch_all`):** there is deliberately no "allow every host"
  entry — a bare `*` host in any scheme-free form (`*`, `*:*`, `*:80`, `*/path`, `*:*/admin`) is
  rejected (dropped+warned) with a message pointing at the posture switch `[network] mode =
  "shared"` rather than the generic "unrecognized entry"/"invalid port"; the bounded `*.domain`
  subdomain wildcard (host `*.domain`, not `*`) is unaffected. The check sits in `classify`
  (after `split_host_ports`) and in `parse_path_rule`; a *scheme*-prefixed `*` (`https://*`) is
  rejected one step earlier by the scheme guard (below). The only allowlist-mode escape hatch
  to all hosts stays `re:.*`; the real "open everything" is `mode = "shared"` (settable only in
  a trusted/global config).
  **Scheme removed from rules (`http`/`https` "serve no purpose" — the user's call):** a rule is a
  *pattern*, not a connection, so it carries **no scheme** — `http`/`https` only ever picked a
  default port the `:port` qualifier already expresses. So a URL rule is the scheme-free
  `host[:ports]/path` (a `/` is what makes it a path rule), parsed by **`parse_path_rule`** (the
  authority goes through the same `split_host_ports`, so paths get the full port grammar; the host
  must be concrete — a `*.domain`-with-path is rejected, use `re:`). An entry that still carries a
  scheme is **rejected** with a pointer to the scheme-free form (fail-closed, never a silent
  mis-parse of `https:` as a host). The distinction is **rule vs request**: a *request* names one
  concrete connection, so `ops test net <url>` and the future proxy keep the scheme (it sets the
  port) via the unchanged **`parse_url_target`** (the *request* parser, now its only caller — no
  longer the rule classifier); the `re:` reconstructed URL stays `https://…` (a stable canonical
  string for regexes, not a protocol claim). No security change — port+path are enforced
  identically; the scheme never enforced the wire protocol (a CONNECT proxy only sees `host:port`).
  Gated trusted-only
  like `binds`/`nixpkgs`; a malformed entry in either list is dropped+warned (fail-closed); `ops
  config` shows allow+deny. **`ops test net <url>`** reports ALLOWED/DENIED + the deciding rule
  (`parse_url_target` + `EgressPolicy::explain`), reflecting the trust gate, no launch/nix/network
  — which also exercises the matcher live through the real binary. **Interim until the proxy:
  `Allowlist` → `NetPolicy::Isolated` (fail-closed) + an honest launch warning.**
  **Advisor-caught deny-evasion hole — FIXED (Option A, user-chosen direction):** a literal-path
  `deny https://github.com/secret` was **dodgeable by the in-cage agent** (it controls the
  request) — `/secret?x=1`, `/secret/`, `/secret/sub`, `%2f`, `/foo/../secret` all sidestepped the
  exact-string deny while `allow github.com` let them through. (Asymmetry: a literal-path *allow*
  fails closed/safe, a literal-path *deny* fails **open** — a real hole, not a footgun; the earlier
  "every gap is a footgun" claim was wrong.) Fix: every request is **canonicalized once** (`Request`
  — percent-decode, resolve `.`/`..`, drop query) so all **same-resource** variants of `/secret`
  reduce to it and the exact deny catches them; a **different** sub-resource (`/secret/sub`) is a
  deliberate user choice — `deny /secret/*` (the user's `*` refinement) to include the subtree.
  Proven live: same-resource dodges DENIED, `/secret/sub` ALLOWED under `deny /secret` but DENIED
  under `deny /secret/*`, `/public` always ALLOWED. **Hard 6.2b invariant recorded:** the proxy
  must canonicalize the live request through the **same** `allowlist::Request::new`, or `ops test net`
  would mispredict — plan a test that drives a request *through the proxy* asserting its verdict ==
  `ops test net`'s. Minors (documented, not fixed — within Model 2's "you own the regex"): a regex
  `re:…:443/…` never fires (`Request.url` omits port 443); the regex path is decoded but **not**
  `.`/`..`-resolved, so a `re:` deny is dodgeable by `/foo/../secret` (a structured `Url` deny is
  not); `ops test net` always exits 0.
  **Before 6.2b: a code-level competitor comparison** (egress, then FS/seccomp/isolation; 6 research
  agents, all repos cloned) confirmed ops's netns→UDS→host-proxy is the **production consensus**
  (Codex CLI, Anthropic `sandbox-runtime` — which uses `socat`, our planned forwarder — nono,
  greywall) and that ops **leads** on path/URL/regex granularity + per-session cage-only CA. It
  surfaced the gaps now folded into the build (SSRF post-resolution IP guard, DNS-rebind recheck,
  per-request re-check, CONNECT==SNI==Host, fail-closed→502) and a concrete M4 seccomp/Landlock/
  cgroups roadmap (denylist not allowlist, the nix-in-cage allowlist carve-out, the broad CA env
  set). Recorded in memory (`network-egress-competitor-comparison`,
  `sandbox-isolation-competitor-comparison`); nono CVE-2026-47128 (no-ns → `systemd-run --user`
  escape) validates ops's all-namespaces + empty-netns.
  **6.2b — the host MITM allowlisting proxy MODULE done** (`src/sandbox/proxy.rs`, **222 tests**,
  advisor-reviewed plan AND implementation, deps user-approved): built **MITM-from-line-one** on a
  **musl-clean** stack — `rustls 0.23` (**`ring`** backend, no aws-lc/openssl), `rcgen 0.13`,
  `webpki-roots 1.0` (verified zero C deps) — its cert core de-risked by a throwaway Rust spike
  first. `Ca` (ephemeral, in-memory key, per-host leaf cache, cage-trust-only) + `CertResolver`
  (mints a leaf per SNI) + `upstream_config` (webpki-roots) + `ProxyCtx` (server cfg with **no h2
  ALPN** → HTTP/1.1) + `serve(UnixListener)` thread-per-conn + `handle_client`. Flow: CONNECT
  (byte-by-byte so the ClientHello survives) → 200 → MITM → one inner request (same BufReader keeps
  the body) → **CONNECT-host == SNI == decrypted Host** (anti domain-fronting) → `policy.explain`
  (**the same canonicalizer `ops test net` uses** = the recorded invariant) → host-side resolve →
  **SSRF guard** (private/loopback/CGNAT refused unless the deciding rule names the EXACT host —
  not a `*.domain`/regex/nix-cache match; metadata/link-local always refused; v4-mapped-v6
  unwrapped) → connect the **checked IP** (no re-resolve) + validate upstream (`complete_io`) →
  reserialize the head with forced **`Connection: close`** + forward + stream back + close (one
  request per tunnel → no path-skip). Fail-closed everywhere: forged/self-signed upstream → 502
  (never downgraded), IP-literal target → deny (no SNI), plain-HTTP absolute-form → reject,
  socket timeouts (slowloris), CL+TE / duplicate CL/Host → 400. **Built-in nix-cache allow-set**
  (`nix_cache_allow`: cache.nixos.org, *.nixos.org, github.com, api/codeload.github.com,
  *.githubusercontent.com, **search.devbox.sh** = the nixhub `NIXHUB_BASE`) unioned into allow
  **regardless of trust** so the untrusted self-equip survives (`union_with_nix_cache`); refined
  empirically + to be shown in `ops config` at wire time. 14 proxy tests (loopback rustls upstream,
  injectable resolver + upstream cfg): happy-path (proves byte-plumbing at both read boundaries),
  denied→403, path-deny-wins→403, forged→502, SNI≠host→421, SSRF private+metadata→403,
  verdict==tester, nix-cache union, **+2 advisor-regression tests** — a forced `Connection: close`
  (a capturing upstream caught a real 30s hang on verbatim forward to a keep-alive upstream) and a
  URL-in-query (caught `contains("://")`, fixed to `starts_with('/')`).
  **6.2c — the egress wiring done** (`src/sandbox/egress.rs` + `fhs.rs` + `binds.rs` + `launch.rs`
  + `config/mod.rs` + `main.rs`, **266 tests**, advisor-reviewed plan AND implementation): the
  Model-B path is wired into a launch under `[network] mode = "allowlist"`. **Forwarder pivot,
  advisor-driven:** NOT a self-exec'd `ops __incage` — the dev binary is **glibc-dynamic** (tests
  run `CARGO_BIN_EXE_ops`) and ops has never run in-cage, so binding a host-glibc ops into the
  hermetic cage is fragile (crashes wherever host glibc > base glibc; nix-ld redirects the loader,
  it does not backfill symbols). The forwarder is **`socat`, nix-provisioned** (ABI-matched to the
  cage glibc by construction) in the **base userland** (beside nix/mise, posture-independent base),
  invoked by absolute store path from a wrapper: `bash -c '<socat> TCP-LISTEN:18043,bind=127.0.0.1,
  fork,reuseaddr UNIX-CONNECT:<bound socket> </dev/null >/dev/null 2>&1 & exec "$@"' _ <cmd…>` —
  the command rides **`"$@"` positionally** (no shell injection, non-UTF-8 argv preserved; only
  ops-owned ASCII goes into the script string) and `exec` keeps it the cage's **PID 2 main
  process**, so `ops shell`'s pty job control is **unchanged**. **Lifecycle de-risked by a throwaway
  bwrap spike first** (the load-bearing claims only exist inside a real pid namespace): job control
  intact (`$-` has `m`, no warning), **no socat lingers** after `ops run -- true` (the default PID-1
  **reaper** tears the netns down — confirmed `--as-pid-1` is *absent* from `to_argv`), 0 zombies.
  **Host lifecycle:** `egress::start` binds a per-launch host UDS (`<data>/egress/proxy-<pid>.sock`,
  listen-before-serve so no first-request race), builds the ephemeral `Ca` + `ProxyCtx`, writes the
  CA **owner-only (0600) outside every rw mount**, spawns the `proxy::serve` thread, and returns the
  cage `Wiring` (binds + env) plus an RAII `Egress` guard (unlinks socket+CA on drop). `build` →
  `(SandboxSpec, Option<Egress>)`; **`ops run` + allowlist supervises** (`run_supervised` =
  `Command::status`, fork+wait+propagate) instead of exec-replacing, because the proxy thread must
  outlive the cage; `ops shell` already supervises (pty) and just holds the guard. `net_policy` maps
  allowlist → **empty netns** (`Isolated`) — the Model-B foundation; the bound UDS (a writable
  `ExtraBind` emitted **after** the tmpfs) is the only egress, the CA a read-only bind at
  `/opt/ops/egress-ca.pem`. **CA injected via the broad set** `CA_FILE_ENV_KEYS` (NIX_SSL_CERT_FILE,
  SSL_CERT_FILE, CURL_CA_BUNDLE, GIT_SSL_CAINFO, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS, PIP_CERT,
  npm_config_cafile — replace not append, since all cage egress is ops-minted under the empty netns);
  **the keys ops *sets* == the keys it protects** — `config::is_reserved_env_key` consumes that one
  const, so they can never drift, and adds the proxy-control keys (`http_proxy`/`https_proxy`/
  `all_proxy`/`no_proxy`, case-insensitive) to the untrusted denylist. **Two advisor fixes applied:**
  (1) ops sets **`no_proxy`/`NO_PROXY` = `localhost,127.0.0.1,::1`** structurally — else an agent's
  own in-cage loopback service would route through the proxy and be 403'd (IP-literal CONNECT reject);
  loopback is intra-cage under the empty netns, never egress, so exempting it weakens nothing; (2) the
  cage proxy port is **18043** (high/uncommon, below the ephemeral range), not 8080, to dodge an
  agent-vs-forwarder port clash. `ops config` shows the **built-in nix-cache allow-set** (so the
  always-on self-equip allowance is never silent). **Honest scope:** this is **wired + unit-tested**,
  NOT yet run integrated *through* ops — the lifecycle spike used host socat in a non-hermetic
  shared-net cage, and the unit tests exercise the pieces (`wrap_command`, `start`, `assemble` extra
  binds, the denylist, the config display); a real `ops run` under a trusted allowlist (proxy serving
  + nix-socat forwarder in the empty netns + exit propagation) is **6.2d**. proxy.rs lost its module
  `#![allow(dead_code)]` (now consumed).
  **6.2d — the egress e2e through ops, proven live AND committed** (`tests/run.rs::
  a_network_allowlist_filters_egress_through_the_proxy`): a **throwaway live smoke** ran the real
  `ops run` under a trusted `network = "allowlist"` first (the user's "smoke first, then formalize"
  call) — and it earned its keep by catching a flaw in the *test*, not the code: the denied probe used
  `https://example.com/` (trailing slash), which `nix-prefetch-url` rejects with "cannot figure out
  file name" **before any fetch** — a refusal for the wrong reason, no teeth. Fixed to a filename'd URL
  (`…/nix-cache-info`) so the proxy's **403** is what actually stops it. The committed test runs the
  real binary (so it exercises the full launch path — `egress::start` + `run_supervised`, which an
  in-crate `build_spec` test cannot), skip-not-fail when the host can't sandbox or the cache is
  unreachable, one project/data so the capability probe seeds the store once: trusted allowlist →
  **allowed** `nix-prefetch-url https://cache.nixos.org/nix-cache-info` returns the **known content
  hash** `15sqg1j6gq…` (proves the whole chain — forwarder bridged the empty netns, nix trusted the
  injected MITM CA, the proxy validated the upstream and relayed the bytes intact); **denied**
  `https://example.com/nix-cache-info` → stderr contains **`403`** (refused at the proxy, a real
  filename so the fetch is attempted); and `sh -c 'exit 7'` → **exit 7** (status propagation on the
  supervised path). Proven live (smoke: allowed 200 + hash, denied `HTTP error 403`, true→0/false→1)
  and green as a committed test (29.6s warm).
  **6.2e — explicit refusal reasons on the proxy (DONE)** (`src/sandbox/proxy.rs`): a
  user-driven slice so the agent can tell *why* a request failed — an explicit policy refusal
  vs a host that does not respond vs a name that does not resolve. Every refusal the proxy
  **itself** issues now carries an **`X-Ops-Egress-Reason`** header (a stable category token) plus
  a short `text/plain` body (the human detail) via a single chokepoint `write_refusal`
  (replacing the body-less `write_status`); a genuine upstream status (a real `404`) is still
  relayed verbatim with no such header. The categories: `denied-default` (no allow rule matched —
  the body echoes only the `host:port` the agent already sent), `denied-by-rule` (a deny rule
  matched — **categorical, the rule text is not disclosed**, so a *global*-config rule the agent
  cannot read in-cage never leaks; `ops test net` is the host-side tool for the deciding rule),
  `ssrf-blocked`, `ip-literal`, `host-mismatch` (421), `bad-request` (400), `method-not-allowed`
  (405), and three on the upstream side — `dns-failure`, `upstream-unreachable`, and
  `upstream-cert-rejected` (`connect_upstream` now returns a typed `UpstreamError` so a down host
  reads differently from a rejected cert; note the cert arm catches any `complete_io` failure, not
  *only* a bad cert — slightly broad, kept). The headline behavioural fix: a **DNS-resolution
  failure for an allowed host is now a clean 502** (`dns-failure`) instead of a **dropped
  connection** (the old `?` on `resolve` left the agent unable to tell a refusal from a transport
  glitch). **No security downgrade** — the category/body echo only what the agent sent or a fixed
  token, never the injected credential, a host-side secret, or a policy rule's text; the in-tunnel
  position means the cert/host-triple/SSRF checks all still gate before any reason is sent.
  **Honest scope** (recorded): the reason is **attached** to every deliberate refusal, but whether
  the agent **surfaces** it is tool-dependent — a raw-HTTP client or `curl -i` shows the header and
  body, while `nix` reports the status code; the coarse status *class* (explicit `403` vs `502`
  unreachable vs relayed `404`) is always available and is the distinction the reasons sharpen. The
  category table is documented in the `proxy.rs` module doc. **268 tests green** (5 existing proxy
  tests gained category assertions + 1 net-new `a_dns_failure_for_an_allowed_host_is_a_clean_502`;
  the 6.2d egress e2e re-ran live at 27.4s exercising the changed denied→403 path), fmt/clippy
  clean, advisor-reviewed (it caught that the prior full-suite "exit 0" was `tail`'s status with
  `tail -40` hiding `run.rs` — re-run with cargo's real exit + the e2e confirmed *ran* not
  *skipped*).
  **6.3a — http-header credential injection (DONE)** (`schema.rs` + `config/mod.rs` + `allowlist.rs`
  + `proxy.rs` + `egress.rs` + `main.rs`; full design `docs/bwrap-secrets-architecture.md`): a
  host-keyed `[secret."host"]` table (`kind="http-header"`, a `from` source, `header`,
  `type=bearer|basic|raw`, optional `prefix`) injects a host-scoped credential into an allowed
  request **host-side, after the verdict** — the plaintext is read in `egress::start` and **never
  enters the cage**, the injection fires only for the concrete destination host (the table key, and
  path), and **strip-and-replace**s any client-supplied copy so ops's value is the only one upstream.
  A security field, gated trusted/global; the host key is restricted to a concrete Ip/Host/Url (reject
  `*.`/`re:`); **CR/LF/NUL rejected** naming the source not the value; only under `mode="allowlist"`.
  **Residual:** an injection-target host that *reflects* the header returns it into the cage — bounding
  egress to the one destination host is the real control, the two tripwires below the backstops. Proven live + a
  committed no-leak e2e (`a_secret_is_resolved_host_side_and_never_enters_the_cage`).
  **6.3b — outbound secret redaction (the exfil tripwire, DONE)** (`config/mod.rs`
  `HeaderShape::needles` + `proxy.rs` `SecretNeedle`/`carries_secret`): the proxy scans each decrypted
  request **head** for any configured secret value and **REFUSES** the request (`outbound-secret`,
  403) — **block, never strip** — so a secret the agent *did* obtain cannot be re-sent verbatim to any
  allowed host. Scanned on the **pre-injection** client bytes (never self-trips on ops's own
  injection), before the verdict. **Head-only by design** (the body is streamed; clean block-not-strip
  would need a buffer cap → fail-closed breaks large uploads, fail-open beaten by padding).
  `REDACT_MIN_LEN=8` (a shorter secret is injected but not redacted, warned loudly).
  **6.3d — response-side redaction (the inbound reflection backstop, DONE)** (`proxy.rs`
  `pump_redacting`/`redact_in_place`): when the response comes from an **injection-target** host — the
  only place a configured secret can re-enter by reflection — the proxy **masks** every verbatim
  occurrence of the value out of the relayed response with an **equal-length run of `*`** (so
  `Content-Length`/chunked framing stay intact, `*` never introduces a CR/LF), streaming-safe via a
  `carry` of the last `max_needle_len-1` bytes (catches a match straddling reads). **Mask, not block**
  (vs 6.3b) because the response also carries legit content the agent needs. **Scoped to
  injection-target responses** (advisor) so the always-on nix-cache lane streams untouched and a
  coincidental match cannot corrupt unrelated traffic. Reuses 6.3b's needles — **zero config/egress
  change, `proxy.rs` only**. **Residual:** corruption-on-collision (masking mutates the stream),
  entropy + the min length mitigate, confined to the one injection-target host. **Honest scope:**
  6.3b + 6.3d bound the *naive verbatim* leak in both directions, but both are byte-exact backstops
  (base64/gzip/chunk-split evade) — the boundary stays empty-netns + the allowlist + the `to`
  bounding. **6.3c (body-borne *outbound*) is deliberately NOT built**: its precondition — the agent
  holding the verbatim value — exists only via a non-verbatim reflection that *also* defeats the byte
  filter, so it would guard an almost-empty set. **307 tests green**, fmt/clippy clean, advisor-reviewed
  plan AND impl (the response-side scoping is its load-bearing fix). **Next:** the secret **resolvers**
  (`sops://`) — the SOURCE layer, distinct from the broker; least-privilege/scoping at the source is
  the real lever against a reflecting host.
  **6.3 secret resolvers + resolver-plugin store (DONE)** (`src/config/` + `src/plugins.rs` +
  `src/stores.rs` + `src/plugin_store.rs` + `src/main.rs`; full design
  `docs/bwrap-secrets-architecture.md`): the SOURCE layer that 6.3a/6.3b left open, shipped as a
  resolver engine, a typed plugin registry, and a remote signed store — all under the graved
  invariant *ops never places a plaintext secret in the cage* (every resolution is **host-side**,
  before the cage). **The schema settled on the host-keyed form** `[secret."host"]` (an array
  `[[secret."host"]]` for several credentials to one host) with a shared `[secret.defaults]`
  (resolver `order` + per-resolver bindings + default `header`/`type`) — superseding the early
  `[[secret]]`/`from_env`/`from_file` sketch. A secret's source is either a verbose `from`
  (one `scheme://locator` ref or a fallback chain) or a terse `key` expanded through the default
  resolver order, optionally pinned `key@resolver`. **(a) Resolver engine** — `from` refs route
  through built-in `env://` and `file://` resolvers (read host-side, the value never bound into the
  cage) with a first-wins fallback chain; **the `sops://` built-in** (`sops://<file>[#<key>]`)
  proves the SOURCE layer is distinct from the http-header BROKER. **(b) Resolver-plugin registry**
  (`src/plugins.rs`) — a plugin declares a `scheme` in a `plugin.toml`; ops discovers + validates it
  and **runs it host-side under bwrap** (the resolver is in the TCB but still sandboxed), so a
  `scheme://locator` `from` ref routes to a third-party resolver without an in-tree engine
  dependency; `ops plugins list|info`, local `ops plugins install <dir>` / `rm <name>`, and an
  **embedded default store**. **(c) Remote signed store** (`src/stores.rs` + `src/plugin_store.rs`,
  the *3d* track) — `ops plugins store add/update/info/list/rm` fetches a git catalogue, verifies it
  with **Ed25519** (`ring`), enforces **anti-rollback** (a monotonic `rev`), caches it, and supports
  **trust-on-first-use** (`store add --trust` pins the key on first sight); `store install <store>
  <plugin>` pins each entry by a frozen **`dir_digest`** (`plugin_store::dir_digest`, the one
  wire-format) and re-verifies it through `verify_entry`; and **`store publish`** is the signer that
  *produces* a signed store — it walks a `plugins/` tree, pins each plugin by `dir_digest`, builds +
  signs a `catalogue.toml`, and writes the four store-root artifacts (the producing counterpart of
  the consuming `add`). The **signer reuses the one `dir_digest`** so signer and verifier cannot
  drift past both green suites; a committed clone e2e reads the published artifacts back through the
  full consumer chain. **Two pieces deferred to an operational step** (need a hosting URL + a
  long-term signing key, confirmed deferred 2026-06-20): the **default-store registration** (an
  embedded pubkey so the default store verifies against a baked key, never TOFU) and its routing
  guard. Honest residuals: (1) a resolver runs **host-side**, so a plugin manifest with
  `network = true` (to reach a Vault/KMS/1Password engine) shares the host network and is **not**
  behind the cage's egress allowlist — accepted because resolvers are in the TCB and an engine
  resolver needs real network; the lever is the trusted resolver set + scoping the secret at the
  source (a `network = false` resolver runs in an empty netns); (2) `publish` digests the
  **working tree**, so an untracked/gitignored file git won't deliver would make a later install
  mismatch — "commit exactly what you publish"; a `git ls-files`-scoped digest is the future
  hardening. Memory: [[secrets-architecture]]. Each sub-increment shipped green + advisor-reviewed
  (plan AND impl) + user-validated per the cadence; **474 tests green** (418 in-crate + 32 config +
  7 run.rs + 17 across the other suites), fmt/clippy clean. The shipping static musl binary links
  with the new C/asm deps via `mise exec -- cargo zigbuild` (zig cc); see `mise.toml`.
  **M4.1 — seccomp denylist, Posture A (DONE)** (`src/sandbox/seccomp.rs` + `mod.rs` + `binds.rs`
  + `fhs.rs` + `launch.rs` + `smoke.rs`; spike `docs/bwrap-seccomp-spike-2026-06-21.md`): the first
  enforcement layer **inside** the bwrap namespace cage — a syscall denylist that removes the
  userns→mount→overlayfs/`pivot_root` kernel-LPE surface and the historically-abused syscall set,
  delivered as **two `seccompiler`-compiled cBPF filters** (a new musl-clean pure-Rust dep, no
  libseccomp) handed to bwrap via `--add-seccomp-fd` over **non-CLOEXEC `memfd`s** (inherited
  across `exec`, kept alive until bwrap reads them). Two filters because one `seccompiler` program
  carries one match-action: an **EPERM** set (ptrace/process_vm_*, kernel modules, kexec/reboot,
  `bpf`, `perf_event_open`, `io_uring_*`, `userfaultfd`, keyring, swap/acct/syslog,
  sethostname/setdomainname, personality, x86_64 `ioperm`/`iopl`, the **mount/ns family**
  `unshare`/`setns`/`mount`/`umount2`/`pivot_root`/`chroot`, `clone` **arg-filtered** on
  `CLONE_NEWUSER`/`CLONE_NEWNS`, `ioctl` arg-filtered on `TIOCSTI`/`TIOCLINUX`) **plus** an
  **ENOSYS** set (`clone3` + the new mount API `open_tree`/`move_mount`/`fsopen`/`fsconfig`/
  `fsmount`/`fspick`/`mount_setattr`). `clone3 → ENOSYS` is **mandatory** — it both blocks the
  arg-filter bypass and lets glibc fall back to `clone` (glibc only retries on ENOSYS, so EPERM
  would break **all** process creation); proven live (`fork`/8 threads/`subprocess` survive, a real
  nix builder forks 50×). The two disjoint denylists both load; `ERRNO` outranks `ALLOW` so each
  denied syscall gets its own filter's action. **Carve-outs kept allowed:** `AF_UNIX`,
  `socketpair`, `recvfrom` (the Model-B egress `socat` forwarder + toolchain plumbing).
  **Posture A vs B settled by the spike's evidence** (not a predetermined pick): the *conflict-free
  core* ships in both; the contested delta is the mount/ns family. **A blocks it** and ops forces
  nix `sandbox = false` + `filter-syscalls = false` via the structural `NIX_CONFIG` (already on the
  untrusted-only denylist) — the userns→mount→overlayfs/`pivot_root` paths become **unreachable**
  in the cage (real reduction of the most common Linux LPE class); the cost is nix builds lose
  their *inner* sandbox, accepted inside the Mode-B threat model (the agent already runs arbitrary
  code in-cage; the per-project store is the boundary). The **discriminating fact** the spike
  surfaced: `--cap-drop ALL` + bwrap's single-uid userns already **neuter** a nested userns
  (`unshare(CLONE_NEWUSER)` succeeds but `write /proc/self/uid_map` → EPERM, the single-uid map
  cannot map root), so blocking mount/ns is surface-reduction, **not** the sole escape-block. There
  is **no clean third option in M4.1** — seccomp is process-wide + inherited, so one filter cannot
  allow `unshare` for nix yet deny it for the agent; the selective path is the nested-ns
  re-isolation helper, deferred to M5 and itself gated by that uid_map limit. **`NIX_CONFIG`
  reconciliation** updated (`binds.rs::mise_env`): the additive `extra-experimental-features`
  line now also carries `sandbox = false` + `filter-syscalls = false`, **superseding** the
  earlier "ops sets no NIX_CONFIG / sandbox=true works in-cage" note — that held only while the
  cage carried *no* syscall filter, exactly the load-bearing dependency recorded at 2b.3.2b.2.
  **Wired at all four launch sites** (`exec`, `run_supervised`, `supervise`/pty, and the `doctor`
  smoke) via `seccomp::memfds()` + `seccomp::argv_prefix()`, so `doctor` now proves the full
  launch path *with* the filter (fail-closed on a host without `CONFIG_SECCOMP` — intended for a
  mandatory control). `to_argv` stays pure; arch-gated to x86_64/aarch64 (`compile_error!`
  otherwise). **494 tests green** (8 net-new seccomp unit + a real-bwrap **teeth test** —
  python3 probe in the live cage asserting keyctl/clone3/unshare/`clone(CLONE_NEWUSER)`/
  `ioctl(TIOCSTI)` are refused with the right errno while `fork`/`AF_UNIX` succeed and a benign
  `ioctl(TIOCGWINSZ)` returns ENOTTY — the arg-filter is selective, not a blanket block),
  fmt/clippy clean, **musl static build verified** (zigbuild + seccompiler). Non-regression
  proof: the `the_cage_self_equips_via_mise_under_a_network_allowlist` smoke **executed** (a real
  in-cage `nix build` under both filters + `sandbox = false`) and the egress e2e passed (AF_UNIX
  forwarder in the empty netns). Advisor-reviewed (plan AND impl — it caught that the committed
  teeth test exercised only the *unconditional* rules, not the arg-filtered `clone`/`ioctl`
  firing, a distinct escape path; folded the firing probes into the committed test). Memory:
  [[m4-seccomp-denylist]].
  **M4.2 — cgroup v2 resource limits, anti-DoS (DONE)** (`src/sandbox/cgroup.rs` + `mod.rs` +
  `launch.rs` + `main.rs` + `tests/run.rs`/`tests/shell.rs`; spike
  `docs/bwrap-cgroups-spike-2026-06-21.md`): the M4 enforcement stack's anti-DoS layer — nothing
  in the namespace/seccomp/egress stack bounds *resource consumption*, so an in-cage agent can
  fork-bomb, exhaust memory, or peg the CPU (a runaway build or deliberate). **cgroups was chosen
  over Landlock-FS for M4.2 with the user**: Landlock's confidentiality job is **already done by
  the hermetic FHS** (a secret is *absent* from the cage, not merely read-only-bound — Landlock
  would re-police paths that simply are not mounted), whereas resource exhaustion is a live,
  unaddressed gap; Landlock-FS stays a *defense-in-depth* option for a later milestone, not a M4.2
  need. **Mechanism: a transient systemd user scope** (`systemd-run --user --scope -q --collect
  -p <prop> -- <bwrap…>`) carrying the limits, **not** a hand-rolled cgroup — under cgroup v2 an
  ad-hoc cgroup under systemd's `app.slice` is unsanctioned and GC-able, while `systemd-run` asks
  the user manager for a proper scope it owns/tracks/auto-removes. **The spike's load-bearing
  measurement** (a real pty): `systemd-run` **exec-chains** (registers the scope, moves itself in,
  `execve`s → parent of the cage is the original process, no lingering `systemd-run`), so **pty
  job control survives** (`JOBCTRL_ON`, no "no job control" warning) — it behaves as a plain argv
  prefix, the same non-invasive shape the seccomp prefix has. **Profile:** `MemoryHigh=80%`
  (reclaim/throttle threshold — a heavy build slows, survives), `MemoryMax=90%` (hard **per-cage**
  OOM ceiling), `TasksMax=16384` (the unambiguous host-wide anti-DoS win — any finite bound defeats
  a fork-bomb, while the cap sits far above any real `make -j`; maps to cgroup `pids.max` — the
  property is `TasksMax`, **not** `PidsMax`, which systemd rejects). No `CPUQuota` (the scheduler is
  already fair; a hard quota would only slow legitimate builds). The memory ceiling is honestly
  **per-cage, not host-global** — N concurrent cages each capped relative to total RAM can sum past
  it; the task cap is the clean host-wide guarantee. **Best-effort / graceful degradation — never
  the boundary** (resource limits are hardening; the namespace+seccomp+egress layer is the control
  and *that* hard-fails): where there is no cgroup v2, no reachable systemd user session, no
  `systemd-run`, or no delegated controller, the cage launches **without** limits rather than
  failing — the launch must never regress where it previously worked. **The `-p` list is built from
  the *delegated* controllers** (`/proc/self/cgroup` → the session's `user@<uid>.service` →
  `cgroup.controllers`), so an undelegated property is dropped rather than risking a `systemd-run`
  rejection. **One single decision** — `cgroup::limiter()` — is consulted by **both** the launch
  path (`wrap`) and the `doctor` probe (`probe`), so `doctor` can never report a posture a launch
  would not take (the `effective_lock_target` pattern). **The launch must require a *reachable* user
  manager, not merely `XDG_RUNTIME_DIR` set** (advisor-caught blocking regression): a detached/
  cron/post-logout context can inherit the env var while the session bus is gone, which would
  hard-fail the launch; `limiter()` requires `$XDG_RUNTIME_DIR/bus` to **exist** (residual: a stale
  socket from a crashed manager, rare, then the failure names `systemd-run`). **Wired at all three
  launch sites** via `cgroup::wrap(bwrap, argv)` (pure `compose` splices bwrap after the scope
  prefix, or returns it unchanged when degraded): `exec` (exec-replace — the cage pid *becomes*
  systemd-run→bwrap, so host `/proc/<pid>/cgroup` reads the scope), `run_supervised` (the egress
  allowlist path — the scope coexists with the proxy thread + supervised wait + exit propagation),
  and `supervise`/pty (the shell — `execv` with the launcher as `argv[0]`). `doctor` gains a
  `[ ok ] resource limits` line (or `[warn]` + the degradation note, **never** a remediation entry,
  since it is not the boundary). The cage uses `--unshare-cgroup` and does not mount
  `/sys/fs/cgroup`, so limits are **not visible from inside** — verification is **host-side** via
  `/proc/<pid>/cgroup`. **500 tests green** (5 net-new `cgroup` unit — incl. a **landing test** that
  launches a real scope and reads back `pids.max==16384` + `memory.high < memory.max` from the
  cgroup files, skip-not-fail; the degraded `compose(None,…)` branch tested host-independently — and
  a net-new `tests/run.rs::the_cage_runs_under_a_resource_limit_scope` e2e that drives a real
  `ops run -- sleep` and asserts `pids.max==16384` host-side through `/proc/<pid>/cgroup`,
  skip-not-fail), fmt/clippy clean, **musl static build verified** (cgroup.rs is std-only, no new
  dep). Non-regression proof: the egress e2e **executed** (the wrapped `run_supervised` path — scope
  + proxy thread + exit propagation coexist) and the pty `shell.rs` test **executed** (`CTTY=OK`
  proves job control survives the wrapped supervisor→scope→bwrap→shell chain). Advisor-reviewed
  (plan AND impl — it caught the `XDG_RUNTIME_DIR`-only regression, an untested degraded branch, an
  over-claimed memory comment, and a doctor↔launch precondition drift now closed by the shared
  `limiter()`). Memory: [[m4-cgroup-resource-limits]]. **The M4 enforcement stack is complete —
  seccomp denylist (M4.1) + cgroup v2 limits (M4.2); Landlock-FS is a deferred defense-in-depth
  option, not a gap.**
  **M3.3d.2a** (`src/trust.rs::MISE_CONFIG_NAMES`): the trust-hashed (and
  later-authorized) mise file set now covers mise's full *same-directory* discovery
  — `mise.local.toml`, `.mise.toml`, `mise.toml`, `.tool-versions` — up from the two
  canonical configs. So a tool pinned in `.tool-versions` or an override in
  `mise.local.toml` is folded into the trust hash (editing it re-arms the gate) and,
  through the existing `mise_files_for`-bound `resolve_env`, its `[env]` is honored.
  The **hashed-set ≡ authorized-set** invariant holds for free (both go through
  `mise_files_for`); the genuinely-wider reaches of mise discovery stay **out** by the
  same project-root anchoring — parent-directory configs, the user-global config,
  env-specific `mise.<env>.toml` — since admitting them would let a never-hashed file
  steer resolution. Pure cadrage, not new containment: the mount layout already binds
  exactly `mise_files_for`. The `resolve_env` integration test was reworked (the old
  unauthorized sibling `mise.local.toml` is now authorized → asserted *mapped*; a
  *parent-directory* `mise.toml` is the new genuinely-excluded case). **163 tests
  green**, fmt/clippy clean, proven live (`mise.local.toml` `[env]` mapped, parent
  config excluded).
  **M3.3d.1** (`src/sandbox/fhs.rs` + `binds.rs` + the env denylist): the base
  userland gains a **nix-ld shim** so the project's tools can run on a **different
  glibc than the base** — the enabler for mise's exact-patch `[tools]` (each tool
  pinned to its own nixpkgs revision is cross-channel by construction). The skew it
  cures was de-risked by a throwaway, mise-decoupled measurement: with the base
  glibc on `LD_LIBRARY_PATH` a cross-channel tool dies on a `GLIBC_PRIVATE` ABI
  mismatch (its own loader loads the base `libc.so.6`); drop it and the tool runs on
  its own glibc via RPATH; a **foreign** binary (which hard-codes `/lib64/ld-linux`
  and finds libc only through the loader) keeps working because nix-ld now sits at
  that path and re-execs the real base loader named in `NIX_LD`, with the base libs
  in `NIX_LD_LIBRARY_PATH` — *not* on the global `LD_LIBRARY_PATH`, which is dropped
  entirely. `resolve_userland` provisions the `nix-ld` attribute (selecting its
  `libexec/nix-ld` shim) beside glibc/gcc/bash/coreutils; `Userland` carries
  `interp_src` (the shim, bound at `/lib64/ld-linux-x86-64.so.2`), `base_loader`
  (the logical base loader → `NIX_LD`) and `foreign_lib_paths` (logical base libs →
  `NIX_LD_LIBRARY_PATH`). `NIX_LD`/`NIX_LD_LIBRARY_PATH` join the untrusted-only env
  denylist — the same loader-control (`AT_SECURE`) class as `LD_*`, which their
  `NIX_` prefix would otherwise slip past. A single integration smoke proves both
  ends live (a forged foreign binary served by the shim, and a cross-channel
  `nixos-23.11` tool running with no skew) — merged into one test so the heavy
  provisions run sequentially, which removed a cold-cache concurrency flake. Known
  residual: a foreign binary that itself execs a *cross-channel* nix child passes
  nix-ld's `LD_LIBRARY_PATH` down to it (still a strict subset of the prior skew,
  which forced the base glibc on **every** tool). nix-ld also lifts the M3.2c
  one-channel constraint for `[packages]`/`nixpkgs` pins as a side effect, though
  those stay channel-coarse by design (the OS-substrate layer). Proven live e2e +
  **162 tests green**.
  **M3.3c** (`src/sandbox/mise.rs::resolve_env` + launch wiring): a **trusted**
  project's mise `[env]` maps into the sandbox — the **first consumer that reads a
  project mise file** (`[tasks]` stays out = substrate/workflow line; `[tools]`
  exact-patch is the glibc-gated M3.3d). The increment's point is **mise sees exactly
  the authorized inputs**, on two fronts. (a) *File set*: mise's discovery is wider
  than ops's hash (`mise.local.toml`/`.tool-versions`/parent/global), so the driver
  binds **only** `trust::mise_files_for` (ro under `/project/<name>`), runs mise from
  there with `MISE_TRUSTED_CONFIG_PATHS` naming exactly those, exposes nothing else —
  the **mount layout IS the containment**, not a mise flag. (b) *Bytes*: the files are
  materialized from the bytes trust validated at load (carried on `MiseConfig.files`,
  read once through the safety gate — `read_project` now threads them out), into an
  owner-only staging dir **outside every writable mount** (sibling of the project home,
  like the synthetic `/etc`), so mise reads precisely the hashed content with no
  writable alias to rewrite it (closes the trust→read window, same as the `.ops.toml`
  path). Extraction is by **provenance**: `mise env --json-extended` tags each var with
  the `source` file; keep a var only when its source ∈ the bound set. A var mise merely
  **echoes (PATH) carries no source → dropped** (the sandbox PATH is never disturbed; a
  dotenv-pulled value from an unhashed file can't ride along). Decided empirically:
  `mise env` exits 0 even with uninstalled `[tools]` offline, so a mixed project is
  safe and **hard-fail-on-error** holds. Launch wires it trusted-only: resolves the
  **GLOBAL** channel for the engine (never `prep.nixpkgs`), withheld (untrusted/changed)
  only warns, a trusted `[env]` that fails to resolve is **fatal** (like a declared
  tool). Precedence **structural < passthrough < mise `[env]` < `.ops.toml [env]`**.
  Dep **serde_json** (user-approved; pairs with serde). `command` made private (took a
  private `ProjectBind`); provision/command `#[allow(dead_code)]` removed (now live).
  Proven live e2e (`ops run` exposes the var only once trusted; unhashed sibling never
  contributes) + **161 tests green**. **M3.3b**
  (`src/sandbox/mise.rs`): the **mise engine is provisioned via nix into ops's own
  store** (never the host's mise) and driven from there — the glibc-independent
  scaffolding the mise front-end builds on. Running a relocated-store binary needs a
  bind of ops's store at `/nix` inside a minimal bubblewrap (a nix binary hard-codes
  its interpreter under `/nix/store/…`, which lives under ops's store root on the
  host) — the same trick the sandbox uses for its userland, applied to a tool ops
  runs itself. The **mount set is empirical** (live `mise --version`): `/nix` ro,
  `/proc`, `/dev`, tmpfs `/tmp`, and one rw bind (the private mise home). Two
  properties **born with the driver**: (1) **mise tracks the GLOBAL channel, not a
  project pin** — it runs in its own relocated-store `/nix` view, so the one-channel
  glibc rule does not reach it; `provision(nix, layout, nixpkgs)` takes the ref as a
  param and the caller resolves the **global** `LockTarget` (never `prepare`'s
  effective/possibly-pinned ref — guard-noted on `Prepared.nixpkgs`), giving one
  shared engine per channel rev (`<data>/gcroots/mise/<rev>/`). (2) **never mutates
  the host** — `HOME` + every `MISE_*_DIR` redirected under `<data>/mise/`
  (owner-only), `--clearenv` + rebuilt env, network unshared + `MISE_OFFLINE=1`
  (offline now; online toggle for nixhub is later), cwd pinned to the private home
  (not the launching cwd — also keeps it out of mise's discovery). The private home
  is the **only writable mount** = the structural no-host-write guarantee (asserted
  on the pure argv; proven live writing solely into ops's data dir). Provision+driver
  shipped behind a surgical `#[allow(dead_code)]` (precedent: `NetPolicy::Isolated`),
  **now consumed by M3.3c** (allows removed). **M3.3a** (trust
  composition over `.ops.toml` + mise file — the prerequisite for the mise
  front-end, which is **trusted-only**): `ops trust` now hashes the `.ops.toml`
  **and every sibling mise file** (`.mise.toml`/`mise.toml`) together
  (filename-tagged, length-prefixed framing), so editing **either** re-arms the
  gate; the hash stays byte-identical to the single-file hash when no mise file
  exists (nothing already trusted churns). The verdict is computed on the same
  composed bytes in the loader and in `trust --show` (no divergence). Every input
  goes through the same safety gate — a present-but-unsafe mise file is
  unverifiable → **fail-closed** (`trust` refuses; loader/`--show` report
  Untrusted). `ops config` shows a `mise:` line (file(s) + trusted/withheld),
  network-free, **no mise run**. Two locked decisions: (1) **anchored on
  `.ops.toml`** — a mise file is hashed/honored only beside one (marker keyed by
  the `.ops.toml` path); an orphan mise file warns, not honored (project-root
  anchoring = later additive option). (2) **The hashed set ≡ the set later
  authorized to mise** (`MISE_TRUSTED_CONFIG_PATHS`) — the binding contract M3.3b
  must honor: mise's own discovery is wider (`.tool-versions`, `mise.local.toml`,
  `.config/mise/config.toml`, parent configs), so provisioning must pass mise
  **exactly** the `mise_files_for` set, never default discovery, or an unhashed
  file reaches resolution. **M3.3 itself = option-1 re-sequence** (decided with the
  user): mise's exact-patch via nixhub pins each tool to its **own** nixpkgs rev
  (`vsix.lua:34` `<repo>/<commit_hash>#<attr>`) → cross-channel → re-creates the
  M3.2c `GLIBC_PRIVATE` glibc skew. So the glibc-independent scaffolding (M3.3a
  trust; M3.3b mise-provisioned-via-nix; `[env]`; `ops upgrade mise`) ships first,
  and `[tools]` exact-patch provisioning is the **gated** last sub-increment where
  the glibc strategy (nix-ld vs empirical one-channel) is decided with measurements
  in hand. ops drives mise as a **subprocess** (the `mise/` tree is a vfox backend
  plugin); `mise` is **provisioned via nix**, not the host. 153 tests green. **M3.2d**
  (`ops upgrade [all|nix]` + channel
  visibility): versions move **only** on an explicit upgrade, never on an ops binary
  update. `upgrade` is **context-aware** — it re-resolves the source the cwd tracks and
  rewrites **that** lock (trusted project pin → per-project lock, else global); this is
  the only way a *channel* pin (`nixos-23.11`) advances within itself (global-only would
  freeze it). A *revision* pin refreshes to itself — a no-op the report names ("nothing
  to roll" vs "already latest", via `is_pinned_revision`). An untrusted/changed pin is
  dropped, so `upgrade` rolls the global channel and prints the config warning. Needs
  nix but **not** the sandbox boundary (only rewrites a lock). The "which source, which
  lock" decision is extracted to ONE place — `sandbox::effective_lock_target(cwd,
  layout, cfg) -> store::LockTarget` — routed by all three consumers: launch
  (`.resolve`, lock-reusing), upgrade (`.refresh`, force + report old→new), `ops config`
  (`.locked_revision`, display) — so the lock upgrade writes IS the lock a launch reads
  (no drift; replaced `global_ref`/`project_ref`). `doctor` is host-level → reads the
  **global** lock straight from disk and shows `<source> @ <rev>` verbatim
  (accurate-to-disk, NOT config-aware: a global override set-but-unresolved shows the
  prior source until the next launch/upgrade). Lock writes are **atomic** (temp +
  `rename`, prompted by the user's "two concurrent `ops upgrade`?" question): a reader
  sees old-or-new, never torn; a failed resolution returns before the write (never
  truncates a known-good lock); two upgrades race to a last-writer-wins of two valid
  revs (no flock — pure ergonomics). Proven live + 141 tests green (incl. pin-routing
  integration tests, network-free via a 40-hex revision pin). **M3.2c** (`nixpkgs`
  field + source-aware locks): a
  **security** field `nixpkgs` (trusted-only, like `binds`) overrides the channel the
  launch resolves against — a branch/channel (`nixos-23.11`) or 40-hex rev under
  `NixOS/nixpkgs` (forks/flake-refs deferred, charset-validated). **A per-project pin
  pins the WHOLE sandbox — base userland AND tools — from ONE effective channel**
  (`project pin ?? global override ?? default nixos-unstable`). This is the corrected
  design: a first attempt pinned tools-only (base stayed global) on the theory that
  each tool's closure is self-contained, but that **crashed** for a cross-channel pin
  (`hello: … glibc-2.42 … undefined symbol __tunable_is_initialized, GLIBC_PRIVATE`):
  the sandbox exports the base glibc on `LD_LIBRARY_PATH` for foreign binaries, and
  nixpkgs uses `RUNPATH` (searched *after* it), so a tool pinned to a different glibc
  loads the base `libc.so.6` under its own loader and skews. One channel per launch
  keeps base == tools == `LD_LIBRARY_PATH` glibc. So `launch::prepare` resolves ONE
  `nixpkgs` ref and feeds it to **both** `resolve_userland` and `packages::provision`;
  base gcroots are keyed by revision (`<data>/gcroots/base/<rev>/`) so each channel
  roots its own base (a pinned project downloads its own base closure — only pinned
  projects pay; the no-pin default still shares the global base). The lock is
  **source-aware** (2 lines `<source>\n<rev>`): a changed source re-resolves, an
  unchanged one stays fixed, a legacy bare-rev lock reads as the default channel. A
  global override → shared `<data>/nixpkgs.lock`; a trusted project pin → per-project
  `<data>/projects/<id>/nixpkgs.lock`, consulted **only** when a current pin exists
  (a dropped/now-untrusted pin falls back to global — no stale pin). `launch::prepare`
  loads the config once (infallible) before resolving; `ops config` shows the
  effective source (project pin / global / default), network-free. Proven live: a
  trusted `nixos-23.11` pin runs `hello` from 23.11 on a 23.11 base. Deeper smell
  noted (not now): the foreign-binary `LD_LIBRARY_PATH` is what forces one-channel;
  a nix-ld-style foreign-only library path (M1-level) would later let base and tools
  diverge safely. **M3.2b** (relax `[packages]` to untrusted projects via a
  build-vs-fetch dry-run) was **deliberately skipped**: `ops trust` already
  suffices for security, and for `[packages]` the relaxation adds **none** (a tool's
  `bin` output is input-addressed → it is either cache-substituted, safe to admit
  either way, or an input-addressed build that needs trust — the substitution/FOD
  distinction is moot for tools). So it is pure ergonomics; deferred (reopen if the
  friction proves real). The substitution+FOD-for-untrusted policy is the eventual
  model for a future **`sources`** field (where fetching is the point), not
  `[packages]`. **M3.2c** = `nixpkgs` override (trusted-only) + per-project lock.
  **M3.2a** (`src/sandbox/packages.rs` + config `[packages]`): a project declares
  tools as `name = "<nixpkgs attr>"`; the launcher provisions the **admitted** ones
  into ops's store (per-project gcroots under `<data>/gcroots/projects/<id>/`,
  reusing the runtime identity via `binds::project_runtime_id`) and **prepends**
  their `bin/` to the sandbox `PATH`. Layering is pure: `config::resolve` key-merges
  `packages` and stamps each with its source's trust, **dropping nothing** — the
  admission decision lives downstream in `packages::admit` (M3.2a = **trusted-only**,
  the deliberately conservative slice; M3.2b will re-admit an untrusted tool that
  needs only a signed-cache *fetch*, the build-vs-fetch gate). A withheld tool only
  warns; an **admitted** tool that fails to realise is a **hard fail naming the
  attribute** (a declared tool is a requirement, unlike a best-effort bind). Name +
  attr are charset-validated (the name is a gcroot filename). `nixpkgs_ref` is
  resolved **once** in `prepare` and threaded to both the base userland and package
  provisioning (so M3.2c's `nixpkgs` override plumbs in one place). `ops config`
  shows the declared set with each tool's trust verdict, **without** realising
  anything (network-free — it cannot reflect M3.2b's build-vs-fetch outcome, an
  accepted relaxation of the binds anti-drift rule). Proven live: untrusted ⇒ tool
  withheld (`ABSENT`); after `ops trust` ⇒ `ops run -- jq …` runs from ops's store.
  110 tests green. **M3.1**
  (`store.rs` + `sandbox/fhs.rs`): the base userland (glibc/gcc/bash/coreutils) is
  now **provisioned into ops's OWN store** (no longer the host `/nix`), bound
  read-only at `/nix`. `store::provision` runs daemonless nix (`--store`,
  `--out-link` gcroot under `<data>/gcroots/base/`) against a **pinned** nixpkgs;
  `nixpkgs_ref` resolves the rolling default channel (`nixos-unstable`) **once**
  and records the revision in `<data>/nixpkgs.lock` (read *before* nix is invoked,
  so an ops binary update never moves tool versions — the user's hard requirement,
  guarded by a nix-free test). `fhs.rs` splits **logical** in-sandbox paths from
  **physical** bind sources (`store::physical_path`). Proven live: `ops run -- id`
  → `uid=1000(sandbox)`, hermetic, from ops's store. **Two M3.1 notes:** a
  project's *first* run now needs the binary cache (ops populates its own store —
  the §7-q3 tradeoff, not a regression); and `doctor` is still blind to the
  channel rev (surface it when `ops upgrade` lands, M3.2). Full M3 design (rolling
  OS on a channel, two front-ends, trust lines, `ops upgrade [all|nix|mise]`):
  [[m3-provisioning-design]]. **M2 deliverable** remains **met** —
  a `.ops.toml` **drives the sandbox safely**: a *free* field (`env`) applies from
  any project, a *security* field (`binds`) only from a **trusted** one, proven
  end-to-end through a real launch (`ops run` with an untrusted config →
  `BIND=ABSENT`; after `ops trust` → `BIND=PRESENT`). The schema is deliberately
  **minimal and additive**: network / secrets / GUI / ssh-agent fields are
  **intentionally absent, not silently ungated** — each lands *with its consumer*
  (M3–M6), so the small surface is not a gap.
  **M2.1** (`src/trust.rs` + `src/config/safety.rs`): the **trust gate's recording
  side** — `ops trust`/`untrust`/`trust --show`. Content-bound trust on the
  **direnv model**: a marker under `$XDG_STATE_HOME/ops/trusted/` holds a
  **SHA-256 of the whole file** (not a parsed subset — keeps trust independent of
  the schema and any edit re-arms), keyed by the config's canonical path; states
  Trusted/Untrusted/Changed. The hash is **cryptographic by necessity** (the old
  `DefaultHasher` is forgeable); first non-`libc` dependency (`sha2`,
  user-approved — [[m2-dependency-policy]]). The **safety gate** refuses a config
  that is not a plain, owner-owned, non-world-writable regular file, gating the
  **open fd** (`fstat`) whose bytes are then read+hashed — so the validated
  metadata and the consumed bytes are one inode. The store dir's absolute-path
  requirement is a security control (a relative base would let a cloned repo
  pre-approve itself).
  **M2.2** (`src/config/schema.rs` + `mod.rs`; deps `toml`+`serde`): config
  parse + global/project layering + the **gating**, with `ops config` as the
  consumer. Pure `resolve` (matrix-tested): global is **trusted by location**
  (safety-gated, not marker-gated) and honored in full; the project is
  trust-gated. **Free** field `env` applies from any project; **security** field
  `binds` only from a *trusted* one (untrusted/changed ⇒ dropped + an actionable,
  Changed≠Untrusted warning). The env **denylist is untrusted-only** (a
  reserved-always list would violate the *decided* symmetric schema — a trusted
  config overriding `PATH` harms only itself, out of scope), scoped to glibc's
  **`AT_SECURE`** set + structural (`LD_*`, `GCONV_PATH`, `GLIBC_TUNABLES`,
  `LOCPATH`, `NLSPATH`, `RESOLV_HOST_CONF`, `HOSTALIASES`, `BASH_ENV`, `ENV`,
  `IFS`, `HOME`, `PATH`) — its job is protecting the user's later **Mode-A**
  sessions, not the already-in-cage agent. `load` is **infallible** (absent /
  unsafe / unparseable / no-store all degrade to a warning + dropped layer, never
  a hard fail); the project verdict is computed on the **exact parsed bytes**
  (closes the trust→parse TOCTOU). **M2.3** (`launch.rs` + `binds.rs`): the
  resolved config reaches the sandbox via `build()` (covers `run` **and**
  `shell`). Env ordering = structural first, then config **upserted** over it, so
  a *trusted* override wins (an untrusted one already lost its reserved keys). Bind
  resolution (absolute-only, canonicalized, missing-dropped) lives in
  `config::load`, **not** the launch — so `ops config` shows the *effective* binds,
  no preview-vs-reality drift. Config `ro_binds` are emitted **before** the
  structural mounts so a colliding one is shadowed (cannot displace `/nix`, the
  synthetic identity, the project). **Known limitation** (non-blocking,
  trusted-only): the prepend rule resolves only *exact-dest* collisions — a config
  bind that **nests** with a structural mount mis-resolves by path: a *descendant*
  (e.g. under `/tmp`) is silently shadowed by the later tmpfs (fail-closed —
  `ops config` may list it though the launch drops it); an *ancestor* (e.g. `/etc`)
  over-exposes the rest of that dir (self-sabotage, threat-model §1 out of scope).
  Eventual hardening: warn when a config bind dest nests with a structural mount
  dest. **M0 done** — `ops doctor` (the userns
  gate) + read-only store-health; store mechanism **resolved & de-risked**
  (single shared flat store, ro-consume / rw-provision, trust-gated
  provisioning — architecture §7.4,
  [`bwrap-store-derisk-2026-06-15.md`](docs/bwrap-store-derisk-2026-06-15.md)).
  **M1 so far** (`src/sandbox/`): the keystone `SandboxSpec` + pure `to_argv`
  (hardening is unconditional in argv → an unhardened sandbox is
  unrepresentable; architecture §3 "As built"), proven against real bwrap
  (`CapEff=CapBnd=0`, `NoNewPrivs=1`); the project constructor `binds.rs` (zones
  0/1/2, synthetic `/etc/passwd`+`group` **outside** every rw bind, TOCTOU
  canonicalisation) + the hermetic-FHS resolver `fhs.rs` (host `/nix` ro until
  provisioning lands), de-risked end-to-end. Both launch paths work and are
  proven through the CLI / a pty harness:
  - **`ops run`** (exec-replace, `NewSession`): `ops run -- id` →
    `uid=1000(sandbox)`, hermetic (no host `/usr`), host `$HOME` absent, exit
    status propagated.
  - **`ops shell`** (pty supervisor, `PrivateTty`): real interactive shell with
    **job control** (controlling terminal present, no "no job control" warning),
    hermetic, synthetic identity — the M1 headline. Empirically required to omit
    `--new-session` and own the session via a pty (see architecture §2/§3 "As
    built"); raw `libc`, no new dependency.
  - **M1.4 `session/` + `ops ls`** (`src/session.rs`): the **daemonless** on-disk
    registry. Each sandbox writes a record under `<data>/sessions/`; a record is a
    **liveness-validated hint**, never trusted to be cleaned up — `list()` prunes
    by liveness, so a crash/`SIGKILL` self-heals. Liveness = `(pid, start_ticks)`
    (process start time from `/proc/<pid>/stat`, survives `execve`) to defeat pid
    reuse; `kill(pid,0)` is only a pre-filter, the start-time match is decisive.
    Both paths register (`run` = the agent path, persists then liveness-pruned;
    `shell` = a `RecordGuard` that unlinks on exit). The record stores the
    **canonical** project path — the same identity `binds.rs` derives the runtime
    id from — so registry and runtime never disagree (GC consumes this in M5).
    "2nd terminal in the same env" works *today* because the per-project runtime
    is deterministic: a second sandbox in the same project shares its persistent
    `$HOME` (proven). No new dependency. **GC and `ops attach <id>` deferred (M5).**

  - **M1.5 `doctor` real bwrap smoke** (`src/sandbox/smoke.rs`): the security
    boundary is now decided by a **live launch**, not the `unshare` stand-in.
    `doctor` feeds the real `to_argv` to `bwrap` and reads `/proc/self/status`
    from inside; a launch with `CapEff=0` + `NoNewPrivs=1` proves the namespace is
    capability-bearing more conclusively than the stand-in could (bwrap cannot
    nest its namespaces on a cap-stripped one). `probe_userns` is **demoted, not
    deleted** — it stays the fast gate the launch path uses (no subprocess per
    `ops run`) and the red-path classifier: a capability-bearing namespace + a
    failed launch ⇒ the *engine* is at fault (surface `bwrap`'s stderr), not the
    boundary. The smoke binds host `/usr` (userland-independent hardening → no nix,
    no store touched; `doctor` stays read-only on the host) in a throwaway temp
    dir cleaned on drop. The canonical minimal-hardened spec lives in `smoke.rs`;
    its test asserts hermeticity (host `$HOME` absent). No new dependency.

  The M1.1/M1.2 scaffolding is load-bearing (the `#[allow(dead_code)]` are gone
  except the M3-reserved store primitives). **M1 is complete** — the minimal
  sandbox is end-to-end: `doctor` gate → `run`/`shell` launch → `ls` registry,
  all proven through the CLI. Next: **M2** (config + trust gate), per the
  milestone table.
