---
sidebar_label: "gpu"
description: "Hardware-accelerated rendering inside the cage, on Intel, AMD, nouveau, and NVIDIA."
---

# `gpu`: hardware-accelerated GPU rendering

A hermetic cage carries no GPU driver, no `/sys` (which the driver reads to enumerate a
device), and no render node, so a graphical app falls back to a software GL path that, on
Wayland, often fails to produce a buffer and **no window ever maps**. `gpu = true` lets a
**trusted** config open hardware-accelerated rendering.

```toml
gui = "wayland"
gpu = true
```

`gpu` is a **security field**, honored from the global config or a trusted project, ignored
from an untrusted one, because a render node and the `/sys` device tree widen the kernel
attack surface (a GPU-driver bug becomes reachable from inside the cage). It defaults to
`false` (no GPU access).

See also: [`gui`](gui) · [`[devices]`](devices) · [Enforcement stack](../concepts/enforcement) · [The trust gate](../concepts/trust) · [`[app.<name>]`](apps).

## What `gpu = true` provides

Three pieces, together, all supplied automatically: no paths to write. A fourth set joins
them on a host with an NVIDIA driver, described under [the NVIDIA bridge](#scope-mesa-gpus-and-the-nvidia-bridge).

1. **mesa's DRI drivers**, provisioned into sbx's own store and pointed at through
   `LIBGL_DRIVERS_PATH`/`GBM_BACKENDS_PATH`/`__EGL_VENDOR_LIBRARY_DIRS`, and its Vulkan
   driver manifests through `VK_DRIVER_FILES`. The driver path never depends on the host and
   does not drift across `sbx upgrade` (the same pinned nixpkgs as the app → the same mesa,
   no ABI skew with the app's own libgbm/libEGL). The Vulkan entry is not optional polish:
   the loader looks in host directories a hermetic cage does not have, so without it a
   Vulkan client finds no device at all, not even a software one.
2. **The render node(s)** under `/dev/dri`, granted through the same device-bind mechanism
   as [`[devices]`](devices).
3. **The minimal `/sys` DRM subtree** the driver reads to enumerate the device
   (`/sys/dev/char`, `/sys/class/drm`, and the GPU's own device directories), read-only and
   scoped to those paths: never all of `/sys`.

Each piece is **best-effort**: if mesa cannot be provisioned (no network on a first launch),
or a render node is absent, the app still runs and falls back to software rendering rather
than failing the launch.

## Scope: mesa GPUs, and the NVIDIA bridge

The three pieces above cover **mesa-supported GPUs, Intel, AMD, and nouveau**, whose
userspace sbx provisions itself from its own pinned nixpkgs.

The **NVIDIA proprietary** stack cannot be provisioned that way: its userspace is
version-locked to the host's kernel module, so it has to come from the host. Under the same
`gpu = true`, sbx bridges it when the host has one, adding three more pieces:

4. **The driver's libraries**, bound read-only file by file under `/run/sbx-nvidia/lib` and
   placed on the loader path. Each real file is bound under the name the loader asks for
   (its soname), because a host symlink bound onto itself resolves to its versioned target
   and the soname would disappear from the cage.
5. **Its driver manifests**: the GLVND vendor declaration (`10_nvidia.json`), NVIDIA's EGL
   external platform declarations, and its Vulkan ICD (`nvidia_icd.json`), named through
   `__EGL_VENDOR_LIBRARY_DIRS`, `__EGL_EXTERNAL_PLATFORM_CONFIG_DIRS` and `VK_DRIVER_FILES`.
   Each of those is a union with mesa's, never a replacement: the cage carries both vendors
   and each platform gets the one that drives it.
6. **The driver's character devices** (`/dev/nvidiactl`, `/dev/nvidia<N>`, `/dev/nvidia-uvm`,
   `/dev/nvidia-uvm-tools`, `/dev/nvidia-modeset`), granted through the same device-bind
   mechanism as the render nodes and enumerated rather than assumed, so a second card comes
   along. Never a DRM `card*` primary node, for the reason the render nodes are granted alone.

### Prerequisites

The host must carry the NVIDIA **graphics** userspace, not only the compute one. On
Debian and Ubuntu that is `libnvidia-gl-<branch>` alongside `libnvidia-compute-<branch>`; a
compute-only install ships `libcuda.so.1` but no `libEGL_nvidia.so.0`, no GLVND vendor
declaration and no Vulkan ICD. On such a host nothing renders on the card, in a cage or out
of one, and sbx builds no bridge: `gpu = true` provisions mesa and behaves exactly as before.

That userspace must match the loaded kernel module. When the two disagree sbx names the
mismatch, because the natural failure is silent: the vendor never registers, and EGL reports
an empty extension string with no error at all.

### Vulkan

`gpu = true` gives a cage a working Vulkan loader with mesa's drivers behind it and, where the
host has an NVIDIA driver, that driver's ICD beside them. Both halves are needed for a cage to
see any device at all: the loader searches host directories a hermetic cage does not have, so
without `VK_DRIVER_FILES` it enumerates nothing, not even a software device.

The NVIDIA half carries one more piece, and it is the reason a bare cage could not use it:
NVIDIA's vendor library links **GLVND's** `libEGL.so.1`, which it resolves through the ordinary
loader search. A library bound under `/run/sbx-nvidia` inherits neither the app's `RUNPATH` nor
an `ldconfig` cache, and a cage carrying no graphical package has no `libEGL.so.1` of its own,
so the driver used to answer `NULL` for `vkCreateInstance` without ever touching the card or
naming a reason. sbx therefore provisions GLVND beside mesa, from the same pinned nixpkgs, and
puts it on the cage's loader path.

### Limitation: a windowed app on a hybrid machine

The bridge serves **compute** (CUDA) and **offscreen** rendering. On a hybrid machine (an
integrated GPU plus an NVIDIA card, the usual laptop arrangement) a **windowed** client still
renders on the integrated GPU, inside the cage exactly as it does outside one: the compositor
holds that device, and the only known way around it runs GLX under X11 with PRIME offload.

sbx [never offers X11](gui#why-wayland-only-never-x11), by the same isolation decision that
governs the display posture: an X client can snoop and drive every other window in the
session. The bridge does not touch that refusal, so that way around stays out of reach, on
purpose. On a host whose NVIDIA card is the only one, the compositor itself runs on it and
the question does not arise.

## Most useful with a display

`gpu = true` is independent of `gui`, but its point is a rendered window, so it is normally
paired with `gui = "wayland"`. For a Chromium/Electron desktop app that means dropping
`--disable-gpu` from the app's `cmd` (that flag forces the software path). A compute use
with no display at all is equally supported: `gpu = true` with `gui = "none"` still grants the
devices and the driver libraries, which is what a CUDA workload in a cage needs.

## Why it is trusted-only

A render node and the sysfs device tree are a kernel attack surface, GPU drivers are a
classic local-privilege-escalation vector, and exposing the device makes that driver
reachable from in-cage code. That is a choice only a trusted operator makes, so an untrusted
project's `gpu` posture is dropped, and a globally-declared app keeps its GPU posture even
under an untrusted project (an agent runs *on* untrusted code without that code opening,
or closing, the app's GPU access).

## Per-app posture

An `[app.<name>]` `gpu = true`/`false` (or `gpu` in an imported profile) sets the posture
**for that app's launches**, overriding the baseline and gated the same way. An untrusted
project's app `gpu` is dropped.

```toml
[app.desktop]
gpu = true
```

## One-shot override

To set the GPU posture for a single launch without editing the file, use `--gpu` or `SBX_GPU`:

```sh
sbx app run opencode-desktop --gpu=false   # disable the profile's gpu for this launch
sbx run --gpu -- some-gl-app           # bare --gpu means true
```

`--gpu` is a boolean: bare `--gpu` means `true`, or write `--gpu=true` / `--gpu=false` (it never
takes a space-separated value, so it cannot swallow a following app name). Like the config field it
is trusted by invocation. The command line beats the environment, and both beat the config file. See
[One-shot overrides](overrides).

## Viewing the effective posture

```sh
sbx config show               # a `gpu:` line only when it is enabled
sbx config show --app desktop            # tagged default, inherited or set by the app
sbx config show --app desktop --details  # plus the postures no layer set (folded by default)
```

## Access, not new privilege

`gpu = true` binds the render node and the driver's sysfs; whether a process may *use* the
GPU is still governed by the device's own file permissions and the host uid the cage runs as
(same-uid): exactly as on the host (on most desktops your login session already has an ACL
granting access to the render node). `sbx` grants visibility, not new privilege.
