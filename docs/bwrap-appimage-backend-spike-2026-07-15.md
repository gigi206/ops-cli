# `appimage:` backend — de-risk spike (2026-07-15)

Throwaway spike proving an `.AppImage` desktop app can be packaged for the cage before writing the
`appimage:` backend. Target: **t3 code** (`pingdotgg/t3code`), an Electron control-plane distributed
for Linux **only as an `.AppImage`** (no `.deb`, no nixpkgs attr, no buildable flake — verified: the
`v0.0.28` release ships `T3-Code-0.0.28-x86_64.AppImage` + `latest-linux.yml`, nothing else).

## The load-bearing question

Can a generated nix derivation turn the AppImage into a runnable, autoPatchelf'd `bin/t3code` that
**runs inside the seccomp cage** — i.e. without any runtime FUSE/namespace mount?

## Findings (built + run against the pinned nixpkgs `18b9261…`)

1. **Runtime AppImage execution is a hard block in-cage.** `appimage-run`, `appimageTools.wrapType2`,
   and the raw `.AppImage` all self-mount the embedded squashfs via FUSE (a mount/user-namespace op).
   The cage's seccomp denylist EPERMs `mount`/`unshare`/`pivot_root` and arg-filters
   `clone(NEWNS|NEWUSER)`. So the only mechanism that runs is **build-time extraction** — the exact
   shape the `deb:` backend already uses (unpack + autoPatchelf + wrap a plain ELF, no runtime ns op).

2. **`appimageTools.extractType2` extracts the squashfs at build time** (via `unsquashfs`, no FUSE).
   In this pinned rev its signature is `{ pname, version, src }` — **not** `{ name, src }` (version
   sensitivity; the first attempt with `name` failed with `called without required argument 'version'`).

3. **The layout matches the `.deb` install phase with one tweak.** The extracted squashfs-root carries
   `resources/app.asar` (so the generic `find … -path '*/resources/*'` → `dirname(dirname)` locates the
   app dir), but it **also** carries an `AppRun` launcher script that sorts *before* the real `t3code`
   binary. The shared Electron install phase therefore excludes `AppRun` (harmless for a `.deb`, which
   has none) so the real binary is wrapped, not the AppRun host-FHS shim.

4. **autoPatchelf is clean on the main binary; only bundled legacy shims miss deps.** `ldd` on the
   patched `t3code` ELF is clean against `ELECTRON_LIBS`. Five deps could not be satisfied — all wanted
   by the AppImage's own bundled `usr/lib/libappindicator.so.1` / `libindicator.so.7` / `libgconf-2.so.4`
   (old GTK2-era `libdbusmenu-*`, `libgtk-x11-2.0`, `libdbus-glib`). The main Electron binary does not
   need them and a hermetic cage has no system tray, so they are added to `autoPatchelfIgnoreMissingDeps`
   rather than dragging GTK2 into the closure.

5. **The wrapped binary RUNS** (the spike's real teeth). `result/bin/t3code` launches the actual
   Electron runtime — `runtime logging configured`, `app ready`, `bootstrap start`, `selected backend
   port via sequential scan` — and fails **only** on `MESA-LOADER /run/opengl-driver/lib` (the GPU path
   that `gpu = true` supplies in-cage). Death on display/GPU, **not** on a missing library → the
   packaging is sound; the window-map is the live-user gate, as for every GUI profile.

6. **LD_LIBRARY_PATH**: the AppImage's Chromium sibling `.so`s (`libEGL.so`, `libffmpeg.so`, …) sit
   loose in the bundle root, so the wrapper prepends `$out` to `LD_LIBRARY_PATH` (unlike a `.deb`, whose
   binary finds its siblings via RUNPATH).

## Decision

Ship an `appimage:` backend as a near-clone of `deb:` (shared `prebuilt.rs`: `ELECTRON_LIBS`, the
launcher-locating install phase, `is_sri`/`prefetch_hash`, arch tokens). The only appimage-specific
delta is the prefix, the `.AppImage` matcher/validator, the lock filename, the `extractType2` unpack,
and the extended ignore-list. Then a `profiles/t3code.toml` modelled on `aionui.toml`.
