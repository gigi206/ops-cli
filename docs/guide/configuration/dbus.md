# `dbus`: a private desktop portal for the cage

A hermetic cage carries no D-Bus session bus, so a graphical app cannot open a **file chooser**
through the desktop portal, **follow the host's light/dark theme** (the `appearance` portal), or
**raise desktop notifications**. Exposing the *host* session bus would be unsafe: it carries the
login keyring (`org.freedesktop.secrets`, every saved password) and every desktop portal. Instead,
`dbus = true` gives the cage its **own private desktop portal**, entirely in-cage:

```toml
gui = "wayland"
dbus = true    # a private in-cage desktop portal (default: false = no bus)
```

| `dbus`  | what the cage gets                                                                    |
|---------|---------------------------------------------------------------------------------------|
| `false` | no session bus (the default)                                                          |
| `true`  | a **private in-cage** portal, an in-cage **file chooser**, host light/dark **theme** (at launch and live), and desktop **notifications** relayed to the host |

`dbus` is a **security field**, honored from the global config or a trusted project, ignored from
an untrusted one, because a session bus sits next to the keyring and the portals.

See also: [`gui`](gui.md) · [`gpu`](gpu.md) · [Enforcement stack](../concepts/enforcement.md) · [The trust gate](../concepts/trust.md) · [`[app.<name>]`](apps.md).

## What `dbus = true` provides

A recent Chromium/Electron app opens its file chooser through the desktop portal
(`org.freedesktop.portal.FileChooser`). If that portal were the **host's**, its dialog would be a
host-privileged file manager the cage must not be able to summon: so sbx does not expose the host
bus at all. Instead it stands up a **private** D-Bus session bus **inside** the cage carrying
sbx-provisioned `xdg-desktop-portal` with the reference **GTK backend** (`xdg-desktop-portal-gtk`).
The app probes *that* portal and gets three things:

- **File chooser**: the dialog is **rendered in-cage** by the GTK backend, so by construction it can
  list only the cage's own filesystem (the app's isolated `$HOME`, the project, the
  [`binds`](binds.md) mounts), because the backend runs in the cage's mount namespace. It is the
  Flatpak model with the cage as the world, and it is **not tied to GNOME**: `xdg-desktop-portal-gtk`
  is the freedesktop *reference* backend (the universal fallback used by sway/XFCE/MATE), depending
  only on the GTK library the Electron app already carries.
- **Theme**, the host light/dark preference is read host-side and seeded into the cage so both the
  app window **and the file chooser** open in the right theme, and a host-side relay mirrors later
  host theme switches into the cage, so both surfaces **follow the theme live** (the file dialog
  re-themes even while it is open).
- **Notifications**, a host-side relay bridges `org.freedesktop.Notifications` on the private bus to
  the host notifications daemon, so the app's desktop notifications work end to end (including
  click-to-focus and dismiss).

The keyring (`org.freedesktop.secrets`) is **never** exposed: the private bus carries only sbx's own
portal and relays, and touches no host socket.

This posture:

- **requires `gui = "wayland"`**, the GTK backend renders through the compositor, so without a
  display it cannot start and the file chooser never appears;
- is **unaffected by the network posture**: the private bus is internal, so it works even under
  `network = "shared"`;
- is **best-effort**, if the portal stack cannot be provisioned, the app runs without an in-cage
  portal (its file chooser falls back to its own dialog); if the host theme cannot be read, the app
  opens in its default theme; if there is no host notifications daemon, notifications are simply
  absent. None of these fail the launch.

The in-cage front-end activates every portal backend interface in-cage (Screenshot, ScreenCast, …),
not only the file chooser. This adds **no** reach beyond what the display hole already grants: those
backends are confined to the cage's namespaces (PipeWire unconnected), and the only host resource in
the cage is the Wayland socket `gui = "wayland"` bound. So the compositor-dependent isolation caveat
for that socket (Mutter safe; wlroots exposes screen-capture/input-injection: see [`gui`](gui.md))
governs these interfaces too.

## Most useful with a display

`dbus = true` needs `gui = "wayland"` (its GTK backend renders on the compositor), and its point is a
graphical app's file chooser, theme, and notifications, so it is normally paired with
[`gpu = true`](gpu.md) as well.

## Why it is trusted-only

A session bus is where the login keyring and the desktop portals live. Standing one up for in-cage
code is a choice only a trusted operator makes, so an untrusted project's `dbus` posture is dropped,
and a globally-declared app keeps its `dbus` posture even under an untrusted project (an agent runs
*on* untrusted code without that code opening, or closing, the app's portal).

## Per-app posture

An `[app.<name>]` `dbus = true`/`false` (or `dbus` in an imported profile) sets the posture **for
that app's launches**, overriding the baseline and gated the same way. An untrusted project's app
`dbus` is dropped.

```toml
[app.desktop]
dbus = true
```

## One-shot override

To set the D-Bus posture for a single launch without editing the file, use `--dbus` or `SBX_DBUS`:

```sh
sbx app run opencode-desktop --dbus=false   # no portal for this launch
sbx run --dbus -- some-gtk-app          # bare --dbus means true (the in-cage portal)
```

Bare `--dbus` means `true`; the inline forms are `--dbus=true` and `--dbus=false` (it never takes a
space-separated value). Like the config field it is trusted by invocation, and a non-boolean value
(`--dbus=incage`) is a fail-closed usage error. The command line beats the environment, and both beat
the config file. See [One-shot overrides](overrides.md).

## Viewing the effective posture

```sh
sbx config show                # a `dbus:` line only when it is enabled
sbx config show --app desktop  # an app's effective posture, tagged inherited or set
```

## Scope

The portal ships the file chooser, theme, and notifications; a **tray icon** (StatusNotifier) is
deliberately not provided. The **system keyring** is never exposed, so a keyring-backed login inside
the cage falls back to a file in the app's isolated `$HOME`.
