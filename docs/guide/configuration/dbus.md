# `dbus` — a D-Bus session bus for the cage

A hermetic cage carries no D-Bus session bus, so a graphical app cannot **follow the host's
light/dark theme** (the desktop `appearance` portal), **raise desktop notifications**, or open a
**file chooser** through the desktop portal. Exposing the *raw* session bus would be unsafe — it
carries the login keyring (`org.freedesktop.secrets`, every saved password) and every desktop
portal. The `dbus` field lets a **trusted** config choose one of three postures:

```toml
gui = "wayland"
dbus = true        # a filtered view of the HOST bus: theme + notifications
# dbus = "incage"  # a PRIVATE in-cage portal: an in-cage file chooser + theme-at-launch
# dbus = false     # no bus (the default)
```

| `dbus`     | what the cage gets                                                     |
|------------|-----------------------------------------------------------------------|
| `false`    | no session bus (default)                                               |
| `true`     | a **filtered host** bus — the app follows the host theme (live) and raises notifications |
| `"incage"` | a **private in-cage** portal — the app's **file chooser renders in-cage** (seeing only the cage filesystem) and the host theme is seeded at launch |

`dbus` is a **security field** — honored from the global config or a trusted project, ignored
from an untrusted one — because any session bus sits next to the keyring and the portals.

See also: [`gui`](gui.md) · [`gpu`](gpu.md) · [Enforcement stack](../concepts/enforcement.md) · [The trust gate](../concepts/trust.md) · [`[app.<name>]`](apps.md).

## What `dbus = true` provides

ops runs `xdg-dbus-proxy` (the mechanism Flatpak uses) **host-side**, as a **default-deny**
filtering proxy, and binds **only** its filtered socket into the cage (with
`DBUS_SESSION_BUS_ADDRESS` pointed at it). The curated allowlist is exactly:

- **`org.freedesktop.portal.Desktop`, scoped by method to the `Settings` interface**
  (`Read`/`ReadAll` plus the `SettingChanged` broadcast) — so the app can read and
  **live-follow** the `appearance` color-scheme (light/dark) — plus the standard read-only
  `Properties.Get`/`GetAll`, which a portal client (Chromium/Electron) probes to read an
  interface's `version` before using it (read-only metadata, no setting value or capability);
- **`org.freedesktop.Notifications`** — desktop notifications.

Everything else is refused, and an unlisted name is not even visible to the cage:

- the **keyring / secrets** service (`org.freedesktop.secrets`);
- the **file-chooser, screenshot, and screencast** interfaces of the portal (the same bus
  name, but those methods are outside the `Settings`-only scope);
- every **other client** on the bus.

`dbus = true` is **best-effort**: with no host session bus, or if `xdg-dbus-proxy` cannot be
provisioned (no network on a first launch), the app runs **without** a bus (no theme
following or notifications) rather than failing the launch — and the raw bus is never exposed,
which is the fail-closed direction.

## What `dbus = "incage"` provides

A recent Chromium/Electron app opens its file chooser through the desktop portal
(`org.freedesktop.portal.FileChooser`). Under `dbus = true` that portal is the **host's**, whose
dialog is a host-privileged file manager the cage must not be able to summon — so ops refuses the
file-chooser interface, and the app's "browse for a folder" fails (once a portal advertises a
new-enough version, Chromium no longer falls back to its own in-process dialog).

`dbus = "incage"` gives the cage its **own** portal instead. A **private** D-Bus session bus runs
**inside** the cage carrying ops-provisioned `xdg-desktop-portal` with the reference **GTK backend**
(`xdg-desktop-portal-gtk`). The app probes *that* portal, gets a real version, and the file chooser
it opens is **rendered in-cage** by the GTK backend — a dialog that by construction can list only
the cage's own filesystem (the app's isolated `$HOME`, the project, the [`binds`](binds.md) mounts),
because the backend runs in the cage's mount namespace. It is the Flatpak model with the cage as the
world, and it is **not tied to GNOME**: `xdg-desktop-portal-gtk` is the freedesktop *reference*
backend (the universal fallback used by sway/XFCE/MATE), depending only on the GTK library the
Electron app already carries.

The host **light/dark theme** is read host-side at launch and seeded into the cage, so the window
opens in the right theme. This posture:

- **needs `gui = "wayland"`** — the GTK backend renders through the compositor, so without a display
  it cannot start and the file chooser never appears;
- is **unaffected by the network posture** — the private bus is internal and touches no host socket,
  so unlike `dbus = true` it works even under `network = "shared"`;
- is **best-effort** — if the portal stack cannot be provisioned, the app runs without an in-cage
  portal (its file chooser falls back to its own dialog); if the host theme cannot be read, the app
  opens in its default theme.

> **This increment ships the picker + theme-at-launch.** **Live** theme following and desktop
> **notifications** (what `dbus = true` gives) are a planned follow-up on this posture. Until then,
> pick `dbus = true` if live theme + notifications matter more than the in-cage file chooser.

The in-cage front-end activates every portal backend interface in-cage (Screenshot, ScreenCast, …),
not only the file chooser. This adds **no** reach beyond what the display hole already grants — those
backends are confined to the cage's namespaces (PipeWire unconnected), and the only host resource in
the cage is the Wayland socket `gui = "wayland"` bound. So the compositor-dependent isolation caveat
for that socket (Mutter safe; wlroots exposes screen-capture/input-injection — see [`gui`](gui.md))
governs these interfaces too.

## Requires an isolated network namespace

> This section is about `dbus = true` (the filtered **host** bus). `dbus = "incage"` is a private
> in-cage bus and is **not** affected — it works under every network posture.


The filter is only a boundary when the cage has an **isolated** network namespace — every posture
except `network = "shared"` (`"none"`, `"deny"`, `"allow"`, `"ask"`). Under `network = "shared"`
the cage shares the host's network namespace, where the host session bus is reachable **directly**:
abstract-namespace Unix sockets (`unix:abstract=…`, which some D-Bus sessions open) are
namespace-scoped, not filesystem-scoped, so in-cage code could connect around the proxy to the raw
bus. So under `network = "shared"`, `dbus = true` is **not wired** (it would be false confidence) and
a launch warning says so. Pair `dbus` with `none`/`deny`/`allow`/`ask` for a filtered bus — the
shipped desktop profiles use `network = "deny"`, which is safe.

## Most useful with a display

`dbus = true` is independent of `gui`, but its point is a graphical app's theme and
notifications, so it is normally paired with `gui = "wayland"` (and usually
[`gpu = true`](gpu.md)).

## Why it is trusted-only

The session bus is where the login keyring and the desktop portals live. Handing even a
filtered slice of it to in-cage code is a choice only a trusted operator makes, so an
untrusted project's `dbus` posture is dropped, and a globally-declared app keeps its `dbus`
posture even under an untrusted project (an agent runs *on* untrusted code without that code
opening — or closing — the app's bus access).

## Per-app posture

An `[app.<name>]` `dbus = true`/`false`/`"incage"` (or `dbus` in an imported profile) sets the
posture **for that app's launches**, overriding the baseline and gated the same way. An untrusted
project's app `dbus` is dropped.

```toml
[app.desktop]
dbus = "incage"
```

## One-shot override

To set the D-Bus posture for a single launch without editing the file, use `--dbus` or `OPS_DBUS`:

```sh
ops app opencode-desktop --dbus=false    # no bus for this launch
ops run --dbus -- some-gtk-app           # bare --dbus means true (filtered host bus)
ops app my-desktop --dbus=incage         # the in-cage portal for this launch
```

Bare `--dbus` means `true`; the inline forms are `--dbus=true`, `--dbus=false`, and `--dbus=incage`
(it never takes a space-separated value). Like the config field it is trusted by invocation, and a
typo'd value (`--dbus=incagee`) is a fail-closed usage error. The command line beats the environment,
and both beat the config file. See [One-shot overrides](overrides.md).

## Viewing the effective posture

```sh
ops config show                # a `dbus:` line only when it is enabled
ops config show --app desktop  # an app's effective posture, tagged inherited or set
```

## Scope

The filter is a fixed, curated allowlist (theme + notifications); a custom interface allowlist
is not configurable. A **tray icon** (StatusNotifier) is deliberately not in the set. The
**system keyring** is never exposed, so a keyring-backed login inside the cage falls back to a
file in the app's isolated `$HOME`.
