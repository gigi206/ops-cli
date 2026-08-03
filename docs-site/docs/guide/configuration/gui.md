# `gui`: the display posture

The sandbox's GUI posture: what a cage that draws is given. The three postures are
ordered by host exposure: `none` < `offscreen` < `wayland`.

```toml
gui = "none"        # the default — no display access
# gui = "offscreen" # fonts + the proxy CA for a headless browser; no display
# gui = "wayland"   # all of the above, plus the host's compositor socket (read-only)
```

`gui` is a **security field**: honored from the global config or a trusted project,
ignored from an untrusted one: because exposing a compositor socket is a
confidentiality and integrity choice (clipboard access, and on some compositors screen
capture or input injection). `offscreen` grants no host access at all, but rides the same
gate so the postures stay one ordered field.

See also: [Security model](../concepts/security-model) · [`[app.<name>]`](apps).

## `none` (default)

No display access. The cage cannot connect to any compositor. This is the right
posture for a headless agent or a CLI tool.

## `offscreen`

For a cage that runs a **browser engine but never maps a window**: a headless Chromium
driving page automation, as an agent's browser toolset does. It exposes **nothing** of the
host; it provisions, inside the cage, the two things such an engine cannot work without:

- **fonts + a fontconfig**, without which the engine starts but dies the moment it renders
  a real page;
- under a [filtering egress posture](../networking/modes), the **egress proxy's CA
  imported into the cage's NSS database**, Chromium ignores the CA-file environment
  variables `sbx` sets and reads its own store, so without this every page fails with
  `ERR_CERT_AUTHORITY_INVALID`.

It also gives the cage's network namespace a black-hole `dummy0` interface, so the engine
reports itself online (Chromium decides `navigator.onLine` from a non-loopback interface
being present, not from real reachability). No egress is opened: the dummy has no route,
and all traffic still goes through the proxy on loopback.

Use it for a terminal agent whose tools browse the web. It is strictly less exposure than
`wayland` for the same capability, so prefer it whenever nothing needs a real window.

```toml
gui = "offscreen"

[packages]
chromium = "nix:chromium"
```

## `wayland`

`sbx` binds the host's Wayland compositor socket **read-only** into the cage (the
socket *file*, `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`: never `$XDG_RUNTIME_DIR` itself,
which holds other agents' sockets), sets `WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR`, and
provisions fonts + a fontconfig so text renders. A graphical app can then map a window
on the host compositor.

The GUI hole composes with a [network allowlist](../networking/modes): a desktop
agent can have a display *and* filtered egress at once.

### Why Wayland only, never X11

X11 is deliberately never offered. An X client can snoop on and drive every other
window (keylogging, screen capture, synthetic input), which Wayland's per-client
isolation prevents on a well-behaved compositor.

### App argv, not GUI state

A Chromium/Electron app needs its own flags (`--no-sandbox --ozone-platform=wayland
--disable-gpu --disable-dev-shm-usage`) to run under the cage: `--no-sandbox` is
mandatory and acceptable because bubblewrap + seccomp + the empty netns *is* the
boundary. These are the app's command arguments (in a profile's `cmd`), not part of the
`gui` posture.

## Best-effort

If `gui = "wayland"` but no compositor socket is present, the cage runs **without** the
display (fail-closed by not binding), with a warning. The same holds for the rendering
prerequisites under either posture: a font set or a `certutil` that cannot be provisioned
warns and the app runs without them, rather than failing the launch.

## Compositor caveats

Isolation is compositor-dependent. Mutter (GNOME) is safe. Some compositors
(wlroots-based: sway, hyprland) expose screencopy and input-injection protocols to
ordinary clients, which would let a cage snoop or inject. Clipboard access
(`wl_data_device`) is focus-bounded but present. Know your compositor before exposing
it to an untrusted agent.

## Per-app GUI

An `[app.<name>]` overlay can set its own `gui`, overriding the baseline. Same gating.
See [`[app.<name>]`](apps).

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
SBX_GUI=none sbx run
```

`--gui` takes `none | offscreen | wayland`. The command line beats the environment, and both beat
the config file. See [One-shot overrides](overrides).
