# `gpu` — hardware-accelerated GPU rendering

A hermetic cage carries no GPU driver, no `/sys` (which the driver reads to enumerate a
device), and no render node — so a graphical app falls back to a software GL path that, on
Wayland, often fails to produce a buffer and **no window ever maps**. `gpu = true` lets a
**trusted** config open hardware-accelerated rendering.

```toml
gui = "wayland"
gpu = true
```

`gpu` is a **security field** — honored from the global config or a trusted project, ignored
from an untrusted one — because a render node and the `/sys` device tree widen the kernel
attack surface (a GPU-driver bug becomes reachable from inside the cage). It defaults to
`false` (no GPU access).

See also: [`gui`](gui.md) · [`[devices]`](devices.md) · [Enforcement stack](../concepts/enforcement.md) · [The trust gate](../concepts/trust.md) · [`[app.<name>]`](apps.md).

## What `gpu = true` provides

Three pieces, together, all supplied automatically — no paths to write:

1. **mesa's DRI drivers**, provisioned into ops's own store and pointed at through
   `LIBGL_DRIVERS_PATH`/`GBM_BACKENDS_PATH`/`__EGL_VENDOR_LIBRARY_DIRS`. The driver path
   never depends on the host and does not drift across `ops upgrade` (the same pinned
   nixpkgs as the app → the same mesa, no ABI skew with the app's own libgbm/libEGL).
2. **The render node(s)** under `/dev/dri`, granted through the same device-bind mechanism
   as [`[devices]`](devices.md).
3. **The minimal `/sys` DRM subtree** the driver reads to enumerate the device
   (`/sys/dev/char`, `/sys/class/drm`, and the GPU's own device directories), read-only and
   scoped to those paths — never all of `/sys`.

Each piece is **best-effort**: if mesa cannot be provisioned (no network on a first launch),
or a render node is absent, the app still runs and falls back to software rendering rather
than failing the launch.

## Scope: mesa GPUs

This covers **mesa-supported GPUs — Intel, AMD, and nouveau**. The **NVIDIA proprietary**
stack is a separate mechanism (its userspace is version-locked to the host kernel module, so
it cannot be provisioned hermetically like mesa) and is not this hole. On an NVIDIA-only
machine `gpu = true` provisions mesa but finds no mesa-drivable device, and rendering falls
back to software (it still works, just slower).

## Most useful with a display

`gpu = true` is independent of `gui`, but its point is a rendered window, so it is normally
paired with `gui = "wayland"`. For a Chromium/Electron desktop app that means dropping
`--disable-gpu` from the app's `cmd` (that flag forces the software path). A GPU-less
compute use (no display) is possible but not the primary case.

## Why it is trusted-only

A render node and the sysfs device tree are a kernel attack surface — GPU drivers are a
classic local-privilege-escalation vector, and exposing the device makes that driver
reachable from in-cage code. That is a choice only a trusted operator makes, so an untrusted
project's `gpu` posture is dropped, and a globally-declared app keeps its GPU posture even
under an untrusted project (an agent runs *on* untrusted code without that code opening —
or closing — the app's GPU access).

## Per-app posture

An `[app.<name>]` `gpu = true`/`false` (or `gpu` in an imported profile) sets the posture
**for that app's launches**, overriding the baseline and gated the same way. An untrusted
project's app `gpu` is dropped.

```toml
[app.desktop]
gpu = true
```

## One-shot override

To set the GPU posture for a single launch without editing the file, use `--gpu` or `OPS_GPU`:

```sh
ops app opencode-desktop --gpu=false   # disable the profile's gpu for this launch
ops run --gpu -- some-gl-app           # bare --gpu means true
```

`--gpu` is a boolean: bare `--gpu` means `true`, or write `--gpu=true` / `--gpu=false` (it never
takes a space-separated value, so it cannot swallow a following app name). Like the config field it
is trusted by invocation. The command line beats the environment, and both beat the config file. See
[One-shot overrides](overrides.md).

## Viewing the effective posture

```sh
ops config show               # a `gpu:` line only when it is enabled
ops config show --app desktop  # an app's effective posture, tagged inherited or set
```

## Access, not new privilege

`gpu = true` binds the render node and the driver's sysfs; whether a process may *use* the
GPU is still governed by the device's own file permissions and the host uid the cage runs as
(same-uid) — exactly as on the host (on most desktops your login session already has an ACL
granting access to the render node). `ops` grants visibility, not new privilege.
