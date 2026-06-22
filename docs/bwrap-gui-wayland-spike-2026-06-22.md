# GUI / Wayland hole — feasibility spike (2026-06-22)

Throwaway spike. Nothing was installed on the host; everything ran through the
real `ops run` cage (so the M4.1 seccomp filters and the hermetic FHS were
active — a hand-rolled `bwrap` without `--add-seccomp-fd` would have given a
false green).

## Question

The deferred GUI track wants to launch **desktop agent variants** (opencode
desktop, antigravity, hermes desktop, t3). These are **Electron/Chromium** apps.
The load-bearing unknown is *not* the Wayland socket — it is whether a
**Chromium renderer survives the cage's seccomp denylist at all**: Chromium
sandboxes its own renderer by creating a nested user namespace
(`clone(CLONE_NEWUSER)`/`clone3`/`unshare`), and M4.1 blocks exactly those. A
`wayland-info`/`foot` probe would pass green while hiding that collision.

So the spike targets a **real Chromium under the real cage**, in two halves:
the renderer-vs-seccomp question first, then the Wayland socket hole.

Host: GNOME/Mutter Wayland (`wayland-0`), the favourable compositor case.

## Findings

### 1. The renderer runs — but only with `--no-sandbox`

`ops run -- chromium --headless=new --no-sandbox --disable-gpu
--disable-dev-shm-usage --dump-dom about:blank` →
**exit 0**, DOM rendered (`<html><head></head><body></body></html>`). The
renderer initialised and ran to completion inside the seccomp cage.

Teeth — the **same command without `--no-sandbox`** → **exit 134 (SIGABRT)**, no
DOM:

```
FATAL:setuid_sandbox_host.cc:166] The SUID sandbox helper binary was found, but
is not configured correctly. Rather than run without sandboxing I'm aborting now.
You need to make sure that …__chromium-suid-sandbox is owned by root and has mode 4755.
ERROR:scoped_ptrace_attach.cc:27] ptrace: Operation not permitted (1)
```

Chromium's own sandbox cannot run in the cage (the SUID helper can't be
setuid-root under a nix store + `no_new_privs`; the user-namespace path is
blocked by seccomp; `ptrace` is denied by the denylist — all three confirm the
cage is doing its job). **`--no-sandbox` is therefore mandatory, and acceptable:
bwrap + seccomp + the empty netns *is* the boundary; Chromium's internal sandbox
is redundant defence-in-depth we are replacing, not removing.**

### 2. The Wayland socket hole works

Binding the compositor socket read-only (`binds = ["/run/user/1000/wayland-0"]`)
plus `WAYLAND_DISPLAY` / `XDG_RUNTIME_DIR` in the env was enough:
`ops run -- wayland-info` → **exit 0**, 41 interfaces enumerated. A read-only
bind is sufficient because the cage runs **same-uid**, so `connect()` to the
socket succeeds. No new machinery was needed to *prove* the hole — the existing
`binds` field carried it.

### 3. A real top-level window maps on the compositor

`WAYLAND_DEBUG=1 chromium --ozone-platform=wayland --no-sandbox --disable-gpu
--disable-dev-shm-usage about:blank` (headful, ~12 s, then killed; exit 124 =
stayed alive) produced, in the protocol trace:

```
-> wl_display#1.get_registry(new id wl_registry#2)        # connected
-> xdg_surface#49.get_toplevel(new id xdg_toplevel#50)    # a window
-> xdg_toplevel#50.set_app_id("chromium-browser")
-> xdg_toplevel#50.set_title("about:blank – Chromium")    # page loaded, title updated
```

No FATAL. The only errors are **dbus** (`/run/dbus/system_bus_socket` absent) —
dbus is a *separate* hole we deliberately do not open; Chromium degrades
gracefully and the window still maps. So the full composition — Electron
renderer **+** a mapped Wayland window — works from inside the hermetic cage.

### 4. Fonts: needed for text, and they cannot come from `[packages]`

Without fonts the renderer floods `HarfBuzz error … font: '', glyph_count: 0`
(harmless for `about:blank`, broken for any real text UI) — the hermetic cage
carries no fonts. Adding `fonts = "nix:dejavu_fonts"` to `[packages]` **hard-failed
the launch**:

```
ops: cannot provision package `fonts` (dejavu_fonts): no provisioned output of
dejavu_fonts contains bin
```

A font package has no `bin/`, and `[packages]` requires one. **Implication: the
`gui` hole must provision fonts + fontconfig itself** (like the base userland /
`base_roots`), not via the user-facing `[packages]` field — and generate a
`fonts.conf` (`FONTCONFIG_FILE`) pointing at the provisioned font store paths,
since fontconfig has no `/etc/fonts` in the cage.

### 5. GPU and /dev/shm

Software GL (`--disable-gpu`) renders fine, so **`/dev/dri` need not be exposed**
(least privilege — no GPU device hole in v1). Chromium uses `/dev/shm`; the cage
has none of useful size, so **`--disable-dev-shm-usage`** routes shared memory to
temp files. `wayland-info` logs a benign `drmGetDeviceFromDevId failed` (it
probes DRM for dmabuf and falls back) — expected with no `/dev/dri`.

## The recipe (what a `gui = "wayland"` hole must carry)

- **Mount:** read-only bind of `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY` at the same
  path (same-uid → ro is enough).
- **Env:** `WAYLAND_DISPLAY`, `XDG_RUNTIME_DIR` (and, for Chromium-class apps,
  the caller passes `--ozone-platform=wayland --no-sandbox --disable-gpu
  --disable-dev-shm-usage`; these are *app argv*, not hole state — they live in
  the profile's `cmd`).
- **Provisioned by the hole:** fontconfig + a base font package, plus a generated
  `fonts.conf` via `FONTCONFIG_FILE`. (Closure cost lands like the base userland.)
- **Not exposed:** `/dev/dri` (software GL), dbus, pipewire/pulse (audio),
  X11/`DISPLAY`. Each is a separate, later, opt-in hole.

## Security analysis (the protocol enumeration)

On GNOME/Mutter, `wayland-info` advertised **none** of the dangerous protocols:
no `wlr_screencopy` (screenshot), no `virtual_keyboard`/`input_method`
(keystroke injection), no `zwlr_data_control` (clipboard snooping), no
`foreign_toplevel` (see/drive other windows), no `security_context`. This is the
concrete basis for the threat model's "Wayland, never X11": an ordinary client
under Mutter cannot watch or drive the other windows, unlike an X client.

Residuals to **document, not assume away**:

- **Clipboard** — `wl_data_device_manager` (and primary selection) *are*
  advertised. A **focused** GUI agent can read and set your clipboard. Bounded to
  focus, but a real cross-app channel (the ssh-agent-class minor residual).
- **`zwp_keyboard_shortcuts_inhibit`** — a focused client can suppress *its own*
  shortcut interception. Not a cross-window leak.
- **Compositor-dependent** — this enumeration is Mutter's. A shipped
  `gui = "wayland"` profile run on **wlroots** (sway/hyprland) *would* get
  `wlr_screencopy` + virtual-keyboard/pointer exposed to ordinary clients. The
  "Wayland is isolated" property is **host-compositor-dependent**; the
  threat-model row must state it as a residual, and `ops doctor`/`ops config`
  should ideally warn when the GUI hole is open.

## Verdict

Electron-in-cage is **feasible**, the recipe is pinned, and the Wayland hole is a
clean read-only socket bind + two env vars + a host-provisioned font/fontconfig
layer. The next slice is the `gui` security field (mirror of `network`:
`GuiField`/`GuiPolicy`, trusted-only, settable in the global config, merged per
app), whose hole carries items §6 above. Launching an actual desktop *agent*
profile (a specific Electron target, its packaging + credential mechanism) is the
slice after that.
