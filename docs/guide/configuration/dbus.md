# `dbus` — a filtered D-Bus session bus

A hermetic cage carries no D-Bus session bus, so a graphical app cannot **follow the host's
light/dark theme** (the desktop `appearance` portal) or **raise desktop notifications**.
Exposing the *raw* session bus would be unsafe — it carries the login keyring
(`org.freedesktop.secrets`, every saved password) and every desktop portal (file chooser,
screenshot, screencast). `dbus = true` lets a **trusted** config open a **filtered** view of
the session bus instead.

```toml
gui = "wayland"
dbus = true
```

`dbus` is a **security field** — honored from the global config or a trusted project, ignored
from an untrusted one — because even a filtered slice of the session bus sits next to the
keyring and the portals. It defaults to `false` (no bus at all).

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

## Requires an isolated network namespace

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

An `[app.<name>]` `dbus = true`/`false` (or `dbus` in an imported profile) sets the posture
**for that app's launches**, overriding the baseline and gated the same way. An untrusted
project's app `dbus` is dropped.

```toml
[app.desktop]
dbus = true
```

## One-shot override

To set the D-Bus posture for a single launch without editing the file, use `--dbus` or `OPS_DBUS`:

```sh
ops app opencode-desktop --dbus=false   # no filtered bus for this launch
ops run --dbus -- some-gtk-app          # bare --dbus means true
```

`--dbus` is a boolean: bare `--dbus` means `true`, or write `--dbus=true` / `--dbus=false` (it never
takes a space-separated value). Like the config field it is trusted by invocation. The command line
beats the environment, and both beat the config file. See [One-shot overrides](overrides.md).

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
