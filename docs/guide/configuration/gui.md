# `gui` — the display posture

The sandbox's GUI posture: whether a graphical app inside the cage can reach a
display.

```toml
gui = "none"      # the default — no display access
# gui = "wayland" # bind the host's Wayland compositor socket read-only
```

`gui` is a **security field** — honored from the global config or a trusted project,
ignored from an untrusted one — because exposing a compositor socket is a
confidentiality and integrity choice (clipboard access, and on some compositors screen
capture or input injection).

See also: [Security model](../concepts/security-model.md) · [`[app.<name>]`](apps.md) · design doc [`bwrap-gui-wayland-spike-2026-06-22.md`](../../bwrap-gui-wayland-spike-2026-06-22.md).

## `none` (default)

No display access. The cage cannot connect to any compositor. This is the right
posture for a headless agent or a CLI tool.

## `wayland`

`sbx` binds the host's Wayland compositor socket **read-only** into the cage (the
socket *file*, `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY` — never `$XDG_RUNTIME_DIR` itself,
which holds other agents' sockets), sets `WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR`, and
provisions fonts + a fontconfig so text renders. A graphical app can then map a window
on the host compositor.

The GUI hole composes with a [network allowlist](../networking/modes.md) — a desktop
agent can have a display *and* filtered egress at once.

### Why Wayland only, never X11

X11 is deliberately never offered. An X client can snoop on and drive every other
window (keylogging, screen capture, synthetic input), which Wayland's per-client
isolation prevents on a well-behaved compositor.

### App argv, not GUI state

A Chromium/Electron app needs its own flags (`--no-sandbox --ozone-platform=wayland
--disable-gpu --disable-dev-shm-usage`) to run under the cage — `--no-sandbox` is
mandatory and acceptable because bubblewrap + seccomp + the empty netns *is* the
boundary. These are the app's command arguments (in a profile's `cmd`), not part of the
`gui` posture.

## Best-effort

If `gui = "wayland"` but no compositor socket is present, the cage runs **without** the
display (fail-closed by not binding), with a warning.

## Compositor caveats

Isolation is compositor-dependent. Mutter (GNOME) is safe. Some compositors
(wlroots-based: sway, hyprland) expose screencopy and input-injection protocols to
ordinary clients, which would let a cage snoop or inject. Clipboard access
(`wl_data_device`) is focus-bounded but present. Know your compositor before exposing
it to an untrusted agent.

## Per-app GUI

An `[app.<name>]` overlay can set its own `gui`, overriding the baseline. Same gating.
See [`[app.<name>]`](apps.md).

```toml
[app.desktop]
cmd = "some-electron-app"
gui = "wayland"
```

## One-shot override

To set the display posture for a single launch without editing the file, use `--gui`
or `SBX_GUI`:

```sh
sbx run --gui wayland -- some-electron-app
SBX_GUI=none sbx shell
```

`--gui` takes `none | wayland`. The command line beats the environment, and both beat
the config file. See [One-shot overrides](overrides.md).
