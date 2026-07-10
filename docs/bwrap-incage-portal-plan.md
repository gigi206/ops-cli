# In-cage desktop portal — design (increment A)

Status: PROPOSED 2026-07-09 — awaiting user validation; a throwaway spike (§6) gates the build.

## 0. Scope-deciding finding (2026-07-10) — the trivial fix already works

Before building the in-cage portal, a follow-up spike proved that **`dbus = false` + the
uncommitted `gschemas.rs` already gives a working in-cage file chooser**:

- The GTK file-chooser schema `org.gtk.Settings.FileChooser` is present in the cage under
  `gui = "wayland"` (ops points `XDG_DATA_DIRS` at the provisioned schemas). `gsettings get
  org.gtk.Settings.FileChooser sort-directories-first` → `false` (not "No such schema").
- With **no session bus** (`DBUS_SESSION_BUS_ADDRESS` empty), a real GTK file-chooser (zenity,
  the same GTK stack Chromium's `SelectFileDialogImplGtk` fallback uses) **mapped a dialog
  window in the cage** and stayed open (`GtkDialog mapped …`, killed at the 3s timeout, exit 124)
  — no FATAL "No GSettings schemas" abort. Only a benign `dconf-WARNING` (no machine-id).

This matches the traced Chromium 148 logic: with no bus, `RequestXdgDesktopPortal` fails →
`OnPortalAvailable(version=0)` → `version < kXdgPortalRequiredVersion` → `CreateSelectFileDialog`
(the in-process GTK dialog), rendered in the cage, seeing only the cage FS.

**Consequence for scope.** The user's actual complaint (the picker) is fixed by a two-line
change — `dbus = false` on the profile + committing `gschemas.rs` — at ~zero cost. The in-cage
portal below buys, over that trivial fix, **only theme-at-launch** (increment A) and, with
increment B, notifications + live theme. And moving claude-desktop from its current `dbus = true`
to increment-A-only would *regress* notifications and live theme (both in B) to gain the picker.
So the build below is worth it only if theme/notifications with the picker are wanted; that is a
user decision, put back to them with the cost named. The design (§1+) stands as the route to
picker + theme + notifications together, if chosen.

## 1. Problem

A Chromium/Electron GUI app in the cage cannot open a file/folder chooser under `dbus = true`,
and the failure is structural, not a bug in the filter:

- When the app opens a dialog, `SelectFileDialogLinuxPortal` asks a **process-wide singleton**
  (`dbus_xdg::PortalRegistrar`, `components/dbus/xdg/portal.cc`) whether the desktop portal is
  available. The singleton's only probe is
  `Properties.Get("org.freedesktop.portal.FileChooser", "version")` on
  `org.freedesktop.portal.Desktop`.
- Our filtered bus **allows** `Properties.Get` (the theme needs it — live-caught when the dbus
  hole shipped), so the probe returns the host portal's real version (≥ 3) → Chromium commits to
  the portal path → `OpenFile` is refused by the filter (`AccessDenied`, deliberate) →
  `CancelOpen()`. The GTK fallback only exists when the probed version is `< 3`
  (`ui/shell_dialogs/select_file_dialog_linux_portal.cc`, `kXdgPortalRequiredVersion`); a failed
  portal *call* never falls back.
- The theme (`DarkModeManagerLinux`, `chrome/browser/ui/views/dark_mode_manager_linux.cc`) uses
  the **same singleton and the same probe** (it bails out only on `version == 0`). And
  `xdg-dbus-proxy` filters by message destination/path/interface/method — never by *argument* —
  so the FileChooser version read and the theme's availability read are literally the same D-Bus
  message. The filter cannot admit one and refuse the other.
- The app-side escape hatch is gone: Chromium's M145 refactor removed the
  `--xdg-portal-required-version` switch with no replacement (electron/electron#50057, verified
  against the 148.0.7778.271 sources — the version shipped in claude-desktop 1.18286.2 /
  Electron 42.5.1).

So under `dbus = true` the choice today is binary: theme + notifications with **no** file
chooser, or (`dbus = false`) a GTK in-cage chooser with **no** theme/notifications. Exposing the
host FileChooser portal is rejected on principle (its dialog is a host-privileged file manager
the caged app could summon; see the `filter_args` comment in `src/sandbox/dbus.rs`) and would be
functionally wrong anyway (the returned host paths do not exist in the cage).

## 2. Decision and drivers

**Give the cage its own desktop portal.** A private D-Bus session bus runs *inside* the cage,
carrying a real `xdg-desktop-portal` with the reference GTK backend (`xdg-desktop-portal-gtk`).
Chromium probes it, gets a real version, and the file chooser it opens is rendered **in-cage**
by the backend — a dialog that by construction sees only the cage's filesystem (the app's
isolated home, the project, the `binds` mounts). The Flatpak model, with the cage as the world.

Drivers (user-set):

- **No host-FS exposure, ever** — the picker must show the cage's view, nothing else.
- **Not tied to GNOME** — neither on the host nor in the cage. `xdg-desktop-portal-gtk` is the
  freedesktop *reference* backend (the universal fallback used by sway/XFCE/MATE); its only
  dependency is the GTK3 library, which the cage already carries for the Electron app itself.
  `gsettings-desktop-schemas` is GLib data (names happen to start `org.gnome.`), not a GNOME
  desktop dependency. The host desktop never participates: the cage supplies everything.
- **The host bus policy does not change by one byte** — the existing `xdg-dbus-proxy` filter
  stays exactly as is.

## 3. Design

### 3.1 Config surface

`dbus` grows a third posture (untagged `bool | string`, the `network` string-or-table pattern):

| value      | meaning                                                                    |
|------------|----------------------------------------------------------------------------|
| `false`    | no bus (default, unchanged)                                                |
| `true`     | the filtered **host** bus (unchanged: theme live + notifications, no picker)|
| `"incage"` | a private in-cage bus with ops's own portal (picker + theme seeded at launch)|

Resolved as `DbusPolicy { Off, HostFiltered, InCagePortal }`. Everything else mirrors the
existing field: trusted/global-only gating, `merge_app` replace, the flagship property, `ops
config show` line, `--dbus`/`OPS_DBUS` accepting `incage` alongside `true|false` (the value
grammar stays fail-closed). `profiles/claude-desktop.toml` migrates to `dbus = "incage"`.

### 3.2 Provisioning (pattern: fonts/mesa/gschemas)

Three packages from the pinned nixpkgs into ops's store, gcroots under `gcroots/gui/<rev>/`,
roots joining the project-store seed (and `equip_for_gc`):

- `dbus` — `bin/dbus-daemon` (and `bin/dbus-send`, used by the theme seed);
- `xdg-desktop-portal` — `libexec/xdg-desktop-portal`, its D-Bus `.service` files;
- `xdg-desktop-portal-gtk` — `libexec/xdg-desktop-portal-gtk`, its `.service`, its
  `share/xdg-desktop-portal/portals/gtk.portal`.

The existing GUI-hole provisions are prerequisites and already shipped: fonts (`fonts.rs`),
GSettings schemas (`gschemas.rs` — the GTK dialog *and* the GTK backend need them), Wayland
socket, and (unchanged) the host-side filtered proxy for the side channel below.

### 3.3 Launch wiring (under `gui = "wayland"` + `dbus = "incage"`)

Generated, content-keyed, read-only staged files (pattern: `fonts_conf`/`miseplugin::stage`):

- **`/opt/ops/dbus-session.conf`** — a minimal session-bus config: `unix:path=` listen address
  on the cage tmpfs (e.g. `/tmp/.ops-bus/bus`), `<servicedir>` entries pointing at the two
  portal packages' `share/dbus-1/services`, default-allow policy (every peer on this bus is
  already inside the cage's single trust domain).
- **`portals.conf`** (`[preferred] default=gtk`) — exposed via `XDG_CONFIG_DIRS` (a small ro
  ops dir), so no home mutation.
- **`XDG_DESKTOP_PORTAL_DIR`** — a staged dir carrying `gtk.portal` (the mechanism NixOS itself
  uses to point the portal front-end at its backends).

A positional `bash -c` wrapper (pattern: the egress `socat` wrap — only ops-owned strings enter
the script, the command rides `"$@"`), composed outermost so the bus exists before the app:

1. start `dbus-daemon --config-file=/opt/ops/dbus-session.conf` in the background;
2. export `DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/.ops-bus/bus`;
3. seed the theme (§3.4), best-effort;
4. `exec "$@"`.

`xdg-desktop-portal` and the GTK backend are **not** started manually: D-Bus *activation*
(the `<servicedir>` entries) launches them on the app's first probe — no readiness dance, no
lingering processes when nothing asks. Everything dies with the cage (PID-ns reaper, the socat
lifecycle already proved this shape).

Structural env: `GSETTINGS_BACKEND=keyfile` (GLib's built-in file backend — no dconf daemon in
the cage; both the app's GTK and the portal backend then read the seeded keyfile).

### 3.4 Theme seed (launch-time, not live)

The **host-side filtered proxy stays**, but its socket is bound at a side path
(`/run/ops-dbus/host-bus`) and **not** exported as `DBUS_SESSION_BUS_ADDRESS`. The wrapper does
one read over it at boot — `dbus-send --bus=unix:path=/run/ops-dbus/host-bus …
org.freedesktop.portal.Settings.Read org.freedesktop.appearance color-scheme` (already allowed
by the unchanged filter) — and writes the GLib keyfile
(`$HOME/.config/glib-2.0/settings/keyfile`):

```ini
[org/gnome/desktop/interface]
color-scheme='prefer-dark'   # (or 'default' when the host answers light)
```

`xdg-desktop-portal-gtk`'s Settings backend derives `org.freedesktop.appearance color-scheme`
from that gsetting, so the app's portal-side theme probe answers with the host's value as of
launch. Live following and notifications return in increment B (the bridge). The SEC-001 gating
(`dbus_filter_enforceable`) applies to the side channel exactly as today: under
`network = "shared"` the host-bus is not wired (warn; theme seed skipped) — but the in-cage
portal itself still works, since it touches no host socket.

### 3.5 Failure posture

Best-effort at every seam, warn + degrade, never a wider fallback: provisioning fails → no
private bus (the app runs as under `dbus = false` today); the host-bus side channel fails → no
theme seed (portal + picker unaffected); the seed read fails → default (light) theme. The raw
host bus is never a fallback.

## 4. Security analysis

- **No new host exposure.** The cage's outward channels are unchanged: the Wayland socket, the
  egress socket, and the *same* filtered host-bus socket (same default-deny filter, now at a
  side path). The private bus, the portal, and the dialog are all cage-internal; the dialog
  process (`xdg-desktop-portal-gtk`) runs in the cage's mount ns and can only ever list what the
  cage already exposes to the app.
- **The private bus is allow-all internally** — acceptable by construction: every peer is the
  same uid inside the same cage (one trust domain); a "dangerous" in-cage portal interface
  (e.g. Screenshot) has no host channel to leak through and at worst observes the cage itself.
  The Documents portal needs FUSE (`mount` is seccomp-denied) — expected to fail closed and be
  absent; the spike confirms the front-end tolerates that.
- **Supply chain** — same class as fonts/mesa: pinned-nixpkgs packages seeded into the project
  store.
- **Untrusted-config posture** — `dbus` remains trusted/global-only; nothing here is reachable
  from an untrusted project.

## 5. Cost

First-launch closure grows by dbus + xdg-desktop-portal(+gtk); GTK3 itself is already in every
Electron app's closure. To be measured in the spike; expected O(100 MB) shared per channel rev,
the usual seed economics.

## 6. Spike — DONE 2026-07-10 (throwaway, gated the build)

Ran live via one-shot overrides on a scratch project, no ops code. Results:

1. **✅ Closures build in-cage** — `dbus`, `xdg-desktop-portal`, `xdg-desktop-portal-gtk` (+
   `glib.bin` for `dbus-send`/gsettings) substitute from the pinned nixpkgs through the built-in
   nix-cache allow-set (`ops run` cold, then reused).
2. **✅ Private bus + activation** — `dbus-daemon --config-file=<generated>` starts in-cage, its
   socket appears, and D-Bus *activation* (the `<servicedir>` entries) launches
   `xdg-desktop-portal` + the GTK backend on the first probe. No manual start, no readiness dance.
3. **✅ FileChooser `version` = 4 (≥ 3) on the private bus** — the load-bearing result: Chromium
   will get a real version and render its picker in-cage instead of hitting `AccessDenied`. The
   unlock key is **`portals.conf` with `default=gtk`** (a "last-resort" fallback the front-end
   honours), NOT `XDG_CURRENT_DESKTOP`.
4. **✅ Theme seed works** — read the host color-scheme over the *existing* filtered host bus
   (`Settings.Read appearance color-scheme` → `uint32 1`), write the GLib keyfile
   (`color-scheme='prefer-dark'`), and with `GSETTINGS_BACKEND=keyfile` the private bus's
   `Settings.Read appearance color-scheme` returns `uint32 1` — the seeded value, end to end.
5. **✅ Isolation holds** — on the private bus `org.freedesktop.secrets` (keyring) and
   `org.freedesktop.Notifications` are both `ServiceUnknown` (keyring never present; notifications
   absent in increment A, as designed).
6. **✅ Front-end tolerates the Documents/FUSE failure** — `mount` is seccomp-denied so the
   document portal cannot mount (`fuse: device not found`), and the front-end logs a warning and
   carries on; the Desktop portal activates and FileChooser works regardless.
7. **✅ Clean teardown** — no `dbus-daemon`/portal process survives the cage (the PID-ns reaper).
8. **Cost measured** — ~983 MiB closure for the GTK backend, shared per channel rev (gcroot
   `gui/<rev>`, like mesa/fonts). Much of it is gstreamer+pipewire pulled for ScreenCast/Screenshot,
   which we do not use → a package `override` dropping those is the obvious size optimisation
   (residual, not blocking).

### Design refinements the spike settled

- **The GTK backend needs the live Wayland display** — without `gui = "wayland"` it dies on
  `cannot open display` and the FileChooser interface never appears. So `dbus = "incage"` is only
  meaningful under `gui = "wayland"`, and the committed run.rs e2e must skip when there is no
  Wayland socket (same condition as every GUI e2e).
- **The portal carries its own `gsettings-desktop-schemas`** (via its nix wrapper's
  `XDG_DATA_DIRS`), so it is self-sufficient for schemas; only the *app* needs the existing
  `gschemas.rs`. The generated bus config points servicedirs at the two portal packages; no
  extra schema wiring for the portal side.

### Picker via the in-cage portal — PROVEN 2026-07-10 (spike4)

Driving `org.freedesktop.portal.FileChooser.OpenFile` on the **private bus** returned a Request
handle (`(objectpath '/org/freedesktop/portal/desktop/request/1_0/t',)`, rc=0) and the gtk
backend was invoked to render the dialog. `ls /` in the same cage listed exactly
`bin dev etc home lib64 nix opt proc run tmp usr` — the cage FS, never the host — which is all a
real picker rendered by that in-cage backend can show. Benign warnings only (`Unhandled parent
window type`, because the gdbus caller passed an empty parent; the real app passes its Wayland
handle via `ExportWindowHandle`).

### OpenFile on the SHIPPED bus policy — PROVEN 2026-07-10 (advisor follow-up)

The advisor noted spike4 used `eavesdrop="true"` while `portal.rs::session_conf` ships
`own`/`send_destination`/`receive_sender`, so `OpenFile` was re-driven on the shipped path (a real
`ops run` under the trusted incage project → `gdbus … FileChooser.OpenFile`): rc=0, Request handle
`/org/freedesktop/portal/desktop/request/1_0/t`, the GTK backend rendered the dialog. The shipped
policy does not break the picker.

### Not separately proven (heavyweight live, deferred — the pending user validation)

- The real claude-desktop end to end via `ops app claude-desktop --dbus=incage` (login + a click on
  "browse folder"): the Response **signal** delivery back to the client after a selection, and — with
  no document portal (FUSE absent) — that the portal returns the **direct path** for a non-Flatpak app
  (expected to work since the app shares the cage mount ns; `receive_sender="*"` admits the signal).

## 10. Scope decision (2026-07-10)

User chose **A + B together** (in-cage portal + the bridge): picker **and** live theme **and**
notifications, so nothing regresses versus today's `dbus = true`. Cadence stays incremental per
the repo convention — **A first** (portal: picker + theme-at-launch, shipped, tested, advisor-
reviewed, user-validated), **then B** (live theme + notifications). A is designed B-compatible:
A seeds the theme by reading it host-side at launch (no host-bus bind), and B adds the filtered
host-bus (the existing `dbus.rs`) plus the relays — an in-cage keyfile updater fed by the host
`SettingChanged` (live theme) and an `org.freedesktop.Notifications` relay on the private bus
(notifications). The B relay likely needs a real D-Bus impl (validate the `zbus` dependency then).

## 7. Tests (with the build)

- Unit: generated bus config (listen path, both servicedirs, no host path), portals.conf,
  keyfile writer (uint32 → `'prefer-dark'`/`'default'`), `dbus-send` reply parse, wrapper
  positional shape (no config interpolation), config gating/merge/flag/view for the new variant.
- Config integration: untrusted-drop + flagship for `"incage"`, `--json`.
- run.rs e2e: a trusted `dbus = "incage"` cage probes FileChooser `version` ≥ 3 **on the private
  bus** via `dbus-send`, and the keyring name is absent on it (skip condition per spike §3).
- Live (not committed): the real claude-desktop picker — the heavyweight Electron proof, like
  every GUI increment.

## 8. Increment B (sketch, out of scope here)

A small in-cage bridge giving back what `dbus = true` has today, on top of `"incage"`: own
`org.freedesktop.Notifications` on the private bus and relay to the filtered host bus; a
`org.freedesktop.impl.portal.Settings` backend relaying `Read`/`ReadAll`/`SettingChanged` from
the host portal (live theme). Needs a real D-Bus implementation (likely the `zbus` crate — a
dependency decision to validate) or an equivalent; the host filter still bounds everything it
can reach. Until then, `"incage"` trades notifications + live theme for the picker; profiles
choose per app.

## 9. Open decisions for review

- Field shape: third value on `dbus` (proposed) vs a separate field.
- Wrapper-managed `dbus-daemon` vs ops-supervised host-side spawn — proposed in-cage
  wrapper-managed (dies with the cage for free; no new guard).
- Whether `opencode-desktop` migrates in the same increment or stays on `true` until B.
