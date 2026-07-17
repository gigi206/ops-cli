//! GPU acceleration for the Wayland GUI hole (mesa: Intel / AMD / nouveau).
//!
//! A hermetic cage carries no GPU userspace driver, no `/sys` (which mesa reads to
//! enumerate a DRM device), and no render node — so a graphical app falls back to a
//! software GL path that, on Wayland, often fails to produce a buffer and the window
//! never maps. When `gpu = true` a trusted config opens hardware-accelerated rendering
//! by supplying the three pieces the driver needs:
//!
//! 1. mesa's DRI drivers, provisioned into sbx's own store and pointed at through
//!    `LIBGL_DRIVERS_PATH`/`GBM_BACKENDS_PATH`/`__EGL_VENDOR_LIBRARY_DIRS` — so the
//!    driver path never depends on the host (`/run/opengl-driver` on NixOS, absent
//!    elsewhere) and does not drift across `sbx upgrade` (same pinned nixpkgs as the
//!    app → same mesa, no ABI skew with the app's own libgbm/libEGL);
//! 2. the render node(s) under `/dev/dri`, granted through the device-bind mechanism;
//! 3. the minimal `/sys` DRM subtree the driver reads to enumerate the device,
//!    read-only and scoped to the GPU device directories (not all of `/sys`).
//!
//! Scope: mesa-supported GPUs (Intel/AMD/nouveau). The NVIDIA proprietary stack is a
//! separate mechanism — its userspace is version-locked to the host kernel module, so
//! it cannot be provisioned hermetically like mesa — and is not this hole.

use crate::store::{self, Layout};
use std::io;
use std::path::{Path, PathBuf};

/// The mesa package the GPU hole provisions: `(nixpkgs attribute, a directory the output
/// must contain, gcroot name)`. `lib/dri` holds the gallium DRI drivers (`iris`, `radeonsi`,
/// `nouveau`, `swrast`, …); the same output also carries `lib/gbm` (the gbm backend the
/// error path complains about) and the GLVND EGL vendor JSON. Keyed on `lib/dri`, the
/// directory `LIBGL_DRIVERS_PATH` points at.
const MESA: (&str, &str, &str) = ("mesa", "lib/dri", "mesa");

/// The device directory the render nodes live under. The whole directory is granted (its
/// `card*` and `renderD*` nodes) via the device-bind mechanism: a Wayland client renders
/// offscreen on a render node and hands the buffer to the compositor.
pub(crate) const DRI_DIR: &str = "/dev/dri";

/// The provisioned GPU userspace: the mesa store root to seed into the project store (so the
/// cage reads the drivers through `/nix`) and the env pointing the cage's libgbm/libEGL at them.
pub(crate) struct GpuLayer {
    /// The mesa store root, to seed into the project store like the fonts and base userland.
    pub(crate) root: PathBuf,
    /// Env pairs pointing the cage's libgbm/libEGL at mesa's own drivers (hermetic, no host path).
    pub(crate) env: Vec<(String, String)>,
}

/// Provision mesa into sbx's store against the pinned `nixpkgs` and derive the driver-path env.
/// The gcroot is keyed by revision (`<data>/gcroots/gpu/<rev>/mesa`), shared across every project
/// on the same channel — like the fonts and the base userland — rather than copied per project.
pub(crate) fn provision(nix: &Path, layout: &Layout, nixpkgs: &str) -> io::Result<GpuLayer> {
    let (attr, marker, name) = MESA;
    let root_dir = layout
        .data_dir()
        .join("gcroots")
        .join("gpu")
        .join(store::revision_of(nixpkgs));
    let root = store::provision(nix, layout, &root_dir.join(name), nixpkgs, attr, marker)?;
    let env = driver_env(&root);
    Ok(GpuLayer { root, env })
}

/// The env that points the cage's libgbm/libEGL at mesa's own drivers in the seeded store, so
/// rendering needs no host driver path. Pure over the store root, so it is unit-tested.
pub(crate) fn driver_env(mesa_root: &Path) -> Vec<(String, String)> {
    [
        ("LIBGL_DRIVERS_PATH", mesa_root.join("lib/dri")),
        ("GBM_BACKENDS_PATH", mesa_root.join("lib/gbm")),
        (
            "__EGL_VENDOR_LIBRARY_DIRS",
            mesa_root.join("share/glvnd/egl_vendor.d"),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.display().to_string()))
    .collect()
}

/// The minimal `/sys` DRM subtree mesa/libdrm read to enumerate a device, discovered from the
/// host's DRM nodes at launch. `drmGetDevices2()` walks `/sys/dev/char` and each node's sysfs
/// device directory (the PCI/platform device carrying `vendor`/`device`/`uevent` and the `drm/`
/// subtree) for the driver to match; without them EGL init fails and a Wayland window never maps.
///
/// Read-only and least-privilege: only the two small symlink index directories plus the resolved
/// GPU device directories, never all of `/sys`. Best-effort — a path absent on this host is
/// simply not returned (a cage that then finds no usable GPU falls back to software, as before).
pub(crate) fn drm_sys_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut push_unique = |p: PathBuf| {
        if !paths.contains(&p) {
            paths.push(p);
        }
    };

    // The two small symlink directories the driver indexes DRM nodes through. The symlinks point
    // into `/sys/devices/…`; only the device directories bound below make the GPU ones resolve — the
    // non-GPU symlink targets dangle in the cage. `/sys/dev/char` does expose the *names* (major:minor)
    // of every host char device (a hardware-fingerprint leak, but no device contents, since only the
    // GPU device directories are bound); `drmGetDevices2()` walks it, so the whole small dir is bound.
    for fixed in ["/sys/dev/char", "/sys/class/drm"] {
        let p = PathBuf::from(fixed);
        if p.exists() {
            push_unique(p);
        }
    }

    // The real device directory behind each DRM node: `/sys/class/drm/<node>/device` is a symlink
    // to the PCI/platform device directory (which contains the driver attributes and the `drm/`
    // subtree). Canonicalized so the relative symlinks in the two index directories resolve inside
    // the cage. Connector nodes (`card1-DP-1`, …) are skipped — they resolve to a subpath of a
    // device already covered.
    if let Ok(entries) = std::fs::read_dir("/sys/class/drm") {
        for node in entries.flatten() {
            if !is_drm_node(&node.file_name().to_string_lossy()) {
                continue;
            }
            if let Ok(dev) = std::fs::canonicalize(node.path().join("device")) {
                push_unique(dev);
            }
        }
    }
    paths
}

/// Whether a `/sys/class/drm` entry is a primary DRM node (`card<N>` or `renderD<N>`), as opposed
/// to a connector (`card1-DP-1`, `card1-eDP-1`) whose device resolves to a covered subpath. Pure.
fn is_drm_node(name: &str) -> bool {
    for prefix in ["renderD", "card"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit());
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_env_points_at_mesas_own_driver_directories() {
        let root = PathBuf::from("/nix/store/abc-mesa-26.1.4");
        let env = driver_env(&root);
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(
            get("LIBGL_DRIVERS_PATH").as_deref(),
            Some("/nix/store/abc-mesa-26.1.4/lib/dri")
        );
        assert_eq!(
            get("GBM_BACKENDS_PATH").as_deref(),
            Some("/nix/store/abc-mesa-26.1.4/lib/gbm")
        );
        assert_eq!(
            get("__EGL_VENDOR_LIBRARY_DIRS").as_deref(),
            Some("/nix/store/abc-mesa-26.1.4/share/glvnd/egl_vendor.d")
        );
    }

    #[test]
    fn is_drm_node_accepts_primary_nodes_and_rejects_connectors() {
        assert!(is_drm_node("card0"));
        assert!(is_drm_node("card1"));
        assert!(is_drm_node("renderD128"));
        assert!(is_drm_node("renderD129"));
        // connectors resolve to a subpath of a covered device — excluded so we bind the device once
        assert!(!is_drm_node("card1-DP-1"));
        assert!(!is_drm_node("card1-eDP-1"));
        // neither a card nor a render node
        assert!(!is_drm_node("card"));
        assert!(!is_drm_node("renderD"));
        assert!(!is_drm_node("version"));
        assert!(!is_drm_node("cardX"));
    }
}
