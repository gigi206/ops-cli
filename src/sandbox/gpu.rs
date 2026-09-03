//! GPU acceleration for the Wayland GUI hole (mesa: Intel / AMD / nouveau).
//!
//! A hermetic cage carries no GPU userspace driver, no `/sys` (which mesa reads to
//! enumerate a DRM device), and no render node — so a graphical app falls back to a
//! software GL path that, on Wayland, often fails to produce a buffer and the window
//! never maps. When `gpu = true` a trusted config opens hardware-accelerated rendering
//! by supplying the pieces the driver needs:
//!
//! 1. mesa's DRI drivers, provisioned into sbx's own store and pointed at through
//!    `LIBGL_DRIVERS_PATH`/`GBM_BACKENDS_PATH`/`__EGL_VENDOR_LIBRARY_DIRS` — so the
//!    driver path never depends on the host (`/run/opengl-driver` on NixOS, absent
//!    elsewhere) and does not drift across `sbx upgrade` (same pinned nixpkgs as the
//!    app → same mesa, no ABI skew with the app's own libgbm/libEGL);
//! 2. the render node(s) under `/dev/dri` — the `renderD*` nodes alone, never the `card*`
//!    primary nodes beside them — granted through the device-bind mechanism;
//! 3. the minimal `/sys` DRM subtree the driver reads to enumerate the device,
//!    read-only and scoped to the GPU device directories (not all of `/sys`);
//! 4. under WSL only, the bridge libraries the `d3d12` driver reaches the GPU through
//!    ([`wsl_bridge`]) — Windows provides those, not nixpkgs, so a hermetic cage would
//!    otherwise hold the render node and render in software regardless.
//!
//! 5. where the host carries an NVIDIA driver, that driver's own userspace
//!    ([`nvidia_bridge`]): its libraries, its GLVND vendor declaration, its EGL external
//!    platforms and its character devices. Version-locked to the host's kernel module, so
//!    unlike mesa it cannot be provisioned hermetically and has to come from the host.
//!
//! Scope of that last piece is compute and offscreen rendering. On a hybrid host a windowed
//! client still renders on the integrated GPU, inside a cage exactly as outside one, because
//! the compositor holds that device; the one way around it is GLX under X11, which the
//! display posture never offers and this module does not reopen.

use crate::store::{self, Layout};
use std::io;
use std::path::{Path, PathBuf};

/// The mesa package the GPU hole provisions: `(nixpkgs attribute, a directory the output
/// must contain, gcroot name)`. `lib/dri` is the DRI driver directory `LIBGL_DRIVERS_PATH`
/// points at — on mesa 26.x it holds the `dri_gbm.so` loader with the per-hardware drivers
/// (`iris`, `radeonsi`, `nouveau`, `swrast`, …) merged into a single `libgallium-*.so` (older
/// mesa shipped a separate `<driver>_dri.so` per GPU). Pointing at the directory, not a driver
/// filename, is robust to either layout. The same output also carries `lib/gbm` (the gbm backend
/// the error path complains about) and the GLVND EGL vendor JSON. Keyed on `lib/dri`.
const MESA: (&str, &str, &str) = ("mesa", "lib/dri", "mesa");

/// The GLVND dispatch, provisioned beside mesa when this host has an NVIDIA driver to bridge.
///
/// NVIDIA's vendor library links `libEGL.so.1` — GLVND's dispatch, not mesa's `libEGL_mesa.so.0` —
/// and resolves it through the ordinary loader search. A hermetic cage has no `ldconfig` cache and
/// a library bound at [`CAGE_NVIDIA`] does not inherit the app's `RUNPATH`, so unless the app's own
/// closure happens to carry GLVND there is nothing to find: measured, a cage with no graphical
/// package has no `libEGL.so.1` at all, and NVIDIA's Vulkan driver then answers `NULL` for
/// `vkCreateInstance` without touching the card or naming a reason. Provisioned from the same
/// pinned nixpkgs as mesa, for the same reason mesa is: no ABI skew with the app's own dispatch.
const GLVND: (&str, &str, &str) = ("libglvnd", "lib/libEGL.so.1", "libglvnd");

/// The device directory the DRM nodes live under. Not itself the grant: [`render_nodes`] enumerates
/// the `renderD*` entries in it, and those are what `gpu = true` binds.
pub(crate) const DRI_DIR: &str = "/dev/dri";

/// The DRM **render** nodes this host offers, as paths to bind into the cage under `gpu = true`.
///
/// Render nodes exist precisely so GPU access can be handed out without the primary node: a
/// `renderD*` node offers rendering, buffer allocation and compute, and offers neither modesetting
/// nor the GEM flink namespace. That is the whole of what a Wayland client needs — it renders
/// offscreen and hands the buffer to the compositor — so it is the whole of what is granted.
///
/// Binding the containing directory instead would carry the `card*` primary nodes in with them, and
/// a primary node with no DRM master (a second GPU on a hybrid-graphics host, say) makes its first
/// opener the master: modesetting on a display the user is looking at, and an authenticated handle
/// on that device's flink namespace. Neither is offscreen rendering, and `gpu = true` says it grants
/// the render nodes. A `card*` node reaches a cage only when a trusted config names it under
/// `[devices]`, where the grant is written down.
///
/// Best-effort, like [`drm_sys_paths`]: a host with no readable `/dev/dri` yields nothing and the
/// cage falls back to software rendering, as it did before any of this existed.
pub(crate) fn render_nodes() -> Vec<PathBuf> {
    render_nodes_in(Path::new(DRI_DIR))
}

/// [`render_nodes`] over a named directory, so the enumeration is testable without the host's own
/// devices deciding the answer.
fn render_nodes_in(dri_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dri_dir) else {
        return Vec::new();
    };
    let mut nodes: Vec<PathBuf> = entries
        .flatten()
        .filter(|node| is_render_node(&node.file_name().to_string_lossy()))
        .map(|node| node.path())
        .collect();
    // `read_dir` returns whatever order the filesystem holds; the bind list a launch emits should
    // not depend on it.
    nodes.sort();
    nodes
}

/// The provisioned GPU userspace: the mesa store root to seed into the project store (so the
/// cage reads the drivers through `/nix`) and the env pointing the cage's libgbm/libEGL at them.
pub(crate) struct GpuLayer {
    /// The mesa store root, to seed into the project store like the fonts and base userland.
    pub(crate) root: PathBuf,
    /// The GLVND store root, present only where the NVIDIA bridge needs it (see [`GLVND`]).
    pub(crate) glvnd: Option<PathBuf>,
    /// Env pairs pointing the cage's libgbm/libEGL at mesa's own drivers (hermetic, no host path).
    pub(crate) env: Vec<(String, String)>,
}

/// Provision mesa into sbx's store against the pinned `nixpkgs` and derive the driver-path env,
/// plus GLVND when `nvidia` names a bridge to serve (see [`GLVND`]). The bridge is passed in rather
/// than resolved here because it walks the host's driver directories, and its other two readers —
/// the binds and the device grant — need the same answer this one does.
///
/// The gcroot is keyed by revision (`<data>/gcroots/gpu/<rev>/mesa`), shared across every project
/// on the same channel — like the fonts and the base userland — rather than copied per project.
pub(crate) fn provision(
    nix: &Path,
    layout: &Layout,
    nixpkgs: &str,
    nvidia: Option<&NvidiaBridge>,
) -> io::Result<GpuLayer> {
    let (attr, marker, name) = MESA;
    let root_dir = layout
        .data_dir()
        .join("gcroots")
        .join("gpu")
        .join(store::revision_of(nixpkgs));
    let root = store::provision(nix, layout, &root_dir.join(name), nixpkgs, attr, marker)?;
    let env = driver_env(&root);
    // Only where there is an NVIDIA driver to bridge: on every other host mesa's own dispatch comes
    // from the app, and provisioning a second one would be a download for no gain.
    let glvnd = match nvidia {
        Some(_) => {
            let (attr, marker, name) = GLVND;
            Some(store::provision(
                nix,
                layout,
                &root_dir.join(name),
                nixpkgs,
                attr,
                marker,
            )?)
        }
        None => None,
    };
    Ok(GpuLayer { root, glvnd, env })
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
        // The Vulkan loader searches `/usr/share/vulkan/icd.d`, `/etc/vulkan/icd.d` and
        // `$XDG_DATA_DIRS/vulkan/icd.d`. A hermetic cage has none of those carrying a driver
        // manifest, so without this the loader enumerates zero devices and Vulkan is not merely
        // unaccelerated, it is absent. Points at mesa's own manifests in the seeded store, the
        // same way the three above point at its DRI drivers.
        ("VK_DRIVER_FILES", mesa_root.join("share/vulkan/icd.d")),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.display().to_string()))
    .collect()
}

/// The directory a WSL distribution keeps the GPU bridge libraries in. Not itself the grant:
/// [`wsl_bridge_in`] answers whether it holds them.
pub(crate) const WSL_LIB_DIR: &str = "/usr/lib/wsl/lib";

/// The library the check keys on. mesa's d3d12 path reaches the GPU through DXCore, and this is the
/// loader stub it goes through, so a directory without it is not the bridge whatever else it holds.
const WSL_BRIDGE_LIB: &str = "libdxcore.so";

/// The WSL GPU bridge directory to bind, when this host has one.
///
/// mesa's `d3d12` driver reaches the GPU through `libdxcore.so`/`libd3d12core.so`, which Windows
/// provides here rather than nixpkgs. A hermetic cage carries neither, so it falls back to
/// software rendering.
///
/// Measured, because the bind alone is not the grant: with the directory bound and nothing else,
/// the cage's loader still answers `cannot open shared object file` for all three, since a
/// subdirectory of `/usr/lib` is not a default search path. The caller therefore puts it on the
/// loader path as well, and that pair is what makes the libraries resolvable.
///
/// It grants libraries and not a device. The WSL this was measured on publishes no DRM node at
/// all — no `/dev/dri`, only the `dxgkrnl` character device `/dev/dxg` — so [`render_nodes`] finds
/// nothing there and a `--gpu` cage reaches it without any device node. Binding `/dev/dxg` was
/// measured too and moved no renderer, because that host answers `swrast` outside any cage as
/// well; the grant would buy nothing. Whether another WSL publishes a `renderD*` is untested.
///
/// `None` on any host without it, which is every host that is not WSL — the GPU hole is then
/// exactly what it was.
pub(crate) fn wsl_bridge() -> Option<PathBuf> {
    wsl_bridge_in(Path::new("/"))
}

/// [`wsl_bridge`] under a named root, so both answers are testable without the host's own `/usr`.
pub(crate) fn wsl_bridge_in(root: &Path) -> Option<PathBuf> {
    let dir = root.join(WSL_LIB_DIR.trim_start_matches('/'));
    dir.join(WSL_BRIDGE_LIB).exists().then_some(dir)
}

/// The fixed cage path the host's NVIDIA driver userspace is bound under (parity with the other
/// fixed cage paths, `/run/sbx-pulse` and friends). Three children: `lib` for the driver
/// libraries, `egl_vendor.d` for the GLVND vendor declaration, `egl_external_platform.d` for the
/// platform declarations NVIDIA's Wayland and GBM support are declared through.
pub(crate) const CAGE_NVIDIA: &str = "/run/sbx-nvidia";

/// The library the NVIDIA bridge keys on: the GLVND EGL vendor. A host without it has no NVIDIA
/// graphics userspace at all — a compute-only install (`libnvidia-compute-*` with no
/// `libnvidia-gl-*`) is exactly that, and nothing on such a host can render on the card, cage or
/// no cage. The bridge is then `None` and the GPU hole is what it was.
const NVIDIA_VENDOR_LIB: &str = "libEGL_nvidia.so.0";

/// Where distributions keep the driver's userspace, probed in order. The first directory holding
/// [`NVIDIA_VENDOR_LIB`] wins; sbx is a static binary and does not shell out to `ldconfig` to ask.
const NVIDIA_LIB_DIRS: [&str; 4] = [
    "usr/lib/x86_64-linux-gnu",
    "usr/lib64",
    "usr/lib",
    "run/opengl-driver/lib",
];

/// The host's NVIDIA userspace, resolved into what a cage needs: files to bind, and nodes to grant.
///
/// Every path pair is `(host source, cage destination)`. The destination matters as much as the
/// source: the loader asks for a *soname* (`libEGL_nvidia.so.0`), which on the host is a symlink
/// to a versioned file. Binding such a path with source and destination equal resolves it to the
/// versioned name and the soname disappears from the cage — measured, and its failure mode is
/// silent: the vendor never registers and EGL reports an empty extension string with no error at
/// all. So each real file is bound *under the name the loader asks for*.
pub(crate) struct NvidiaBridge {
    /// The driver libraries, each real file destined for the name it is known by.
    pub(crate) libs: Vec<(PathBuf, PathBuf)>,
    /// The GLVND vendor declaration, named through `__EGL_VENDOR_LIBRARY_FILENAMES`.
    pub(crate) vendor_json: Option<(PathBuf, PathBuf)>,
    /// The external EGL platform declarations (Wayland, GBM); without them NVIDIA's vendor does
    /// not expose `EGL_EXT_platform_wayland`.
    pub(crate) platforms: Vec<(PathBuf, PathBuf)>,
    /// The Vulkan driver manifest, so a Vulkan client sees the card and not only mesa's devices.
    pub(crate) icd: Option<(PathBuf, PathBuf)>,
    /// The character devices the driver reaches the card through. Never a DRM `card*` node: the
    /// reason [`render_nodes`] gives holds here too.
    pub(crate) devices: Vec<PathBuf>,
    /// The driver version, read off the versioned file the vendor soname resolves to, so a skew
    /// against the loaded kernel module can be named rather than left to fail silently.
    pub(crate) version: Option<String>,
}

/// The NVIDIA bridge for this host, or `None` where there is no NVIDIA graphics userspace.
pub(crate) fn nvidia_bridge() -> Option<NvidiaBridge> {
    nvidia_bridge_in(Path::new("/"))
}

/// [`nvidia_bridge`] under a named root, so the whole resolution is testable against a fixture
/// tree rather than the host's own `/usr` and `/dev`.
pub(crate) fn nvidia_bridge_in(root: &Path) -> Option<NvidiaBridge> {
    let dir = NVIDIA_LIB_DIRS
        .iter()
        .map(|d| root.join(d))
        .find(|d| d.join(NVIDIA_VENDOR_LIB).exists())?;
    let cage_lib = PathBuf::from(CAGE_NVIDIA).join("lib");

    let mut libs: Vec<(PathBuf, PathBuf)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !is_nvidia_driver_lib(name) {
                continue;
            }
            // The *resolved* file as the source, so a soname entry carries the real library and
            // not a link that would dangle once the cage no longer holds its target.
            if let Ok(src) = std::fs::canonicalize(entry.path()) {
                libs.push((src, cage_lib.join(name)));
            }
        }
    }
    libs.sort();
    if libs.is_empty() {
        return None;
    }

    let vendor = root.join("usr/share/glvnd/egl_vendor.d/10_nvidia.json");
    let vendor_json = vendor.exists().then(|| {
        (
            vendor,
            PathBuf::from(CAGE_NVIDIA).join("egl_vendor.d/10_nvidia.json"),
        )
    });

    let platform_dir = root.join("usr/share/egl/egl_external_platform.d");
    let cage_platforms = PathBuf::from(CAGE_NVIDIA).join("egl_external_platform.d");
    let mut platforms: Vec<(PathBuf, PathBuf)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&platform_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            // Only NVIDIA's own declarations: the directory is shared, and another vendor's
            // platform has no business entering a cage on the GPU flag's account.
            if name.contains("nvidia") && name.ends_with(".json") {
                platforms.push((entry.path(), cage_platforms.join(name)));
            }
        }
    }
    platforms.sort();

    let version = libs
        .iter()
        .find(|(_, dest)| dest.file_name().is_some_and(|n| n == NVIDIA_VENDOR_LIB))
        .and_then(|(src, _)| src.file_name()?.to_str()?.rsplit_once(".so."))
        .map(|(_, v)| v.to_string());

    let icd_src = root.join("usr/share/vulkan/icd.d/nvidia_icd.json");
    let icd = icd_src.exists().then(|| {
        (
            icd_src,
            PathBuf::from(CAGE_NVIDIA).join("vulkan/icd.d/nvidia_icd.json"),
        )
    });

    Some(NvidiaBridge {
        libs,
        vendor_json,
        platforms,
        icd,
        devices: nvidia_nodes_in(root),
        version,
    })
}

/// The NVIDIA character devices under a named root: the control and memory nodes plus every
/// numbered card, enumerated rather than assumed — a second card is `nvidia1`, and a host with the
/// libraries but no card at all yields the control nodes only.
fn nvidia_nodes_in(root: &Path) -> Vec<PathBuf> {
    let dev = root.join("dev");
    let mut nodes: Vec<PathBuf> = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dev) else {
        return nodes;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let wanted = matches!(
            name,
            "nvidiactl" | "nvidia-uvm" | "nvidia-uvm-tools" | "nvidia-modeset"
        ) || numbered_node(name, "nvidia");
        if wanted {
            nodes.push(entry.path());
        }
    }
    nodes.sort();
    nodes
}

/// Whether a file in the host's driver directory belongs to the NVIDIA driver's userspace. Pure.
fn is_nvidia_driver_lib(name: &str) -> bool {
    // The container toolkit installs `libnvidia-container*` in the same directory. It is not part
    // of the driver's userspace, versions on its own schedule, and a cage has no use for it.
    if name.starts_with("libnvidia-container") {
        return false;
    }
    [
        "libnvidia-",
        "libEGL_nvidia",
        "libGLX_nvidia",
        "libGLESv1_CM_nvidia",
        "libGLESv2_nvidia",
        "libcuda",
        "libnvcuvid",
        "libnvoptix",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

/// The driver version the loaded kernel module reports, from the text of
/// `/proc/driver/nvidia/version`. That file is prose, not a bare version — its first line reads
/// `NVRM version: NVIDIA UNIX x86_64 Kernel Module  580.173.02  <date>` — so the version is the
/// token after `Kernel Module`. Pure, because the format is the fragile part. `None` when the line
/// does not have that shape, which is the same answer as "cannot tell", never a false mismatch.
pub(crate) fn kernel_module_version(text: &str) -> Option<String> {
    let (_, rest) = text.split_once("Kernel Module")?;
    rest.split_whitespace().next().map(str::to_string)
}

/// What a cage needs wired for the NVIDIA bridge: the files to bind, and the environment that makes
/// them findable.
pub(crate) struct NvidiaWiring {
    /// `(host source, cage destination)` pairs. All are bound read-only by the caller.
    pub(crate) binds: Vec<(PathBuf, PathBuf)>,
    /// Environment pairs to add. `LD_LIBRARY_PATH` appears more than once on purpose: it names a
    /// list, and the caller folds repeats into their union rather than letting the last writer win.
    pub(crate) env: Vec<(String, String)>,
}

/// Compose the NVIDIA bridge's binds and environment. Pure over its inputs, so the composition is
/// unit-tested — which is where it needed to be, because the two defects this wiring has had were
/// both here and neither was in a resolver: a vendor list built so that mesa's own declaration
/// dropped out (taking the Wayland and GBM platforms with it), and a missing GLVND dispatch that
/// left the driver refusing an instance without a word.
///
/// `mesa_env` is the layer's own env, read for the settings this one *joins* rather than replaces:
/// both `__EGL_VENDOR_LIBRARY_DIRS` and `VK_DRIVER_FILES` name lists, and the answer is the union
/// with NVIDIA's entry first. Read from there rather than recomputed because those values are the
/// paths *as the cage sees them*, and the store sits elsewhere on the host.
///
/// `kernel_version` is what the loaded module reports (see [`kernel_module_version`]), passed in so
/// the skew check is testable; `None` means "cannot tell", which never warns.
pub(crate) fn nvidia_wiring(
    bridge: &NvidiaBridge,
    mesa_env: &[(String, String)],
    glvnd: Option<&Path>,
    kernel_version: Option<&str>,
    warnings: &mut Vec<String>,
) -> NvidiaWiring {
    let cage = PathBuf::from(CAGE_NVIDIA);
    let mut binds: Vec<(PathBuf, PathBuf)> = bridge.libs.clone();
    let mut env: Vec<(String, String)> = vec![(
        "LD_LIBRARY_PATH".to_string(),
        cage.join("lib").display().to_string(),
    )];

    // The GLVND dispatch the vendor library links, which nothing else puts within its reach.
    if let Some(glvnd) = glvnd {
        env.push((
            "LD_LIBRARY_PATH".to_string(),
            glvnd.join("lib").display().to_string(),
        ));
    }

    let mesa_value = |key: &str| {
        mesa_env
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };
    let joined = |first: String, mesa: Option<String>| match mesa {
        Some(mesa) => format!("{first}:{mesa}"),
        None => first,
    };

    match &bridge.vendor_json {
        Some((src, dest)) => {
            binds.push((src.clone(), dest.clone()));
            env.push((
                "__EGL_VENDOR_LIBRARY_DIRS".to_string(),
                joined(
                    cage.join("egl_vendor.d").display().to_string(),
                    mesa_value("__EGL_VENDOR_LIBRARY_DIRS"),
                ),
            ));
        }
        None => warnings.push(
            "`gpu = true`: the NVIDIA driver libraries are here but their GLVND declaration \
             (`10_nvidia.json`) is not — the cage renders on mesa"
                .to_string(),
        ),
    }

    if bridge.platforms.is_empty() {
        warnings.push(
            "`gpu = true`: no NVIDIA EGL external-platform declaration was found under \
             `/usr/share/egl/egl_external_platform.d` — the cage's NVIDIA vendor will not offer \
             the Wayland platform"
                .to_string(),
        );
    } else {
        binds.extend(bridge.platforms.iter().cloned());
        env.push((
            "__EGL_EXTERNAL_PLATFORM_CONFIG_DIRS".to_string(),
            cage.join("egl_external_platform.d").display().to_string(),
        ));
    }

    if let Some((src, dest)) = &bridge.icd {
        binds.push((src.clone(), dest.clone()));
        env.push((
            "VK_DRIVER_FILES".to_string(),
            joined(dest.display().to_string(), mesa_value("VK_DRIVER_FILES")),
        ));
    }

    // A userspace that does not match the loaded kernel module fails the same silent way a missing
    // soname does. Name it rather than leaving the reader to derive it from a blank.
    if let (Some(user), Some(kernel)) = (bridge.version.as_deref(), kernel_version)
        && user != kernel
    {
        warnings.push(format!(
            "`gpu = true`: the NVIDIA userspace on this host is {user} but the loaded kernel \
             module is {kernel} — the cage will find no NVIDIA device"
        ));
    }

    NvidiaWiring { binds, env }
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

/// Whether a `/sys/class/drm` entry is a DRM node (`card<N>` or `renderD<N>`), as opposed to a
/// connector (`card1-DP-1`, `card1-eDP-1`) whose device resolves to a covered subpath. Pure.
fn is_drm_node(name: &str) -> bool {
    is_render_node(name) || numbered_node(name, "card")
}

/// Whether a device name is a DRM **render** node (`renderD<N>`) — the half of the DRM node space
/// [`render_nodes`] grants, as against the `card<N>` primary nodes it does not. Pure.
fn is_render_node(name: &str) -> bool {
    numbered_node(name, "renderD")
}

/// Whether `name` is `<prefix>` followed by at least one digit and nothing else. Written once
/// because the two node kinds are spelled the same way and a second copy could drift from it.
fn numbered_node(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
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
            get("VK_DRIVER_FILES").as_deref(),
            Some("/nix/store/abc-mesa-26.1.4/share/vulkan/icd.d"),
            "the Vulkan loader searches host directories a hermetic cage does not have, so \
             without this it enumerates no device at all"
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

    /// The WSL bridge is discovered by what it holds, and its absence leaves the hole untouched.
    ///
    /// The second and third arms are the ones that matter: every host that is not WSL takes them,
    /// and a GPU hole that started binding a directory there would be granting on a guess. The
    /// empty-directory arm is not hypothetical either — a distribution can carry `/usr/lib/wsl`
    /// without the bridge, and a directory is not a driver.
    #[test]
    fn the_wsl_bridge_is_found_by_its_library_and_not_by_its_path() {
        let root = crate::testutil::TmpDir::new();
        let dir = root.join("usr/lib/wsl/lib");

        assert_eq!(
            wsl_bridge_in(root.path()),
            None,
            "no such directory: an ordinary Linux host grants nothing here"
        );

        std::fs::create_dir_all(&dir).expect("stage the bridge directory");
        assert_eq!(
            wsl_bridge_in(root.path()),
            None,
            "the directory alone is not the bridge"
        );

        std::fs::write(dir.join("libdxcore.so"), b"").expect("stage the loader stub");
        assert_eq!(
            wsl_bridge_in(root.path()),
            Some(dir),
            "the library is what makes it the bridge"
        );
    }

    /// `gpu = true` grants the render nodes and only the render nodes.
    ///
    /// The grant used to be `/dev/dri` itself, which is a `--dev-bind` of the whole directory: the
    /// `card*` primary nodes came in with the `renderD*` ones the driver actually needs. That is the
    /// split render nodes exist to make — a primary node carries modesetting and the GEM flink
    /// namespace, and an unprivileged opener of one that has no DRM master becomes its master — so
    /// handing over the directory gives that up for a use case (a Wayland client rendering offscreen
    /// and handing the buffer to the compositor) that never touches a `card*` node. Both the module
    /// header and the shipped guide say "the render node(s)"; this is what makes that true.
    #[test]
    fn the_nvidia_bridge_binds_each_real_file_under_the_name_the_loader_asks_for() {
        let root = crate::testutil::TmpDir::new();
        let dir = root.join("usr/lib/x86_64-linux-gnu");

        assert!(
            nvidia_bridge_in(root.path()).is_none(),
            "a host with no NVIDIA graphics userspace has no bridge — a compute-only install is \
             exactly that"
        );

        std::fs::create_dir_all(&dir).expect("stage the driver directory");
        std::fs::write(dir.join("libEGL_nvidia.so.580.173.02"), b"").expect("stage the vendor");
        std::os::unix::fs::symlink(
            "libEGL_nvidia.so.580.173.02",
            dir.join("libEGL_nvidia.so.0"),
        )
        .expect("stage the soname");
        std::fs::write(dir.join("libnvidia-container.so.1.20.0"), b"").expect("stage the toolkit");

        let bridge = nvidia_bridge_in(root.path()).expect("the vendor library makes it a bridge");

        let soname = bridge
            .libs
            .iter()
            .find(|(_, dest)| dest.ends_with("libEGL_nvidia.so.0"))
            .expect("the soname is carried into the cage");
        assert_eq!(
            soname.0,
            std::fs::canonicalize(dir.join("libEGL_nvidia.so.0")).expect("resolve the soname"),
            "the source is the real file, so the cage entry does not dangle"
        );
        assert_eq!(
            soname.1,
            PathBuf::from("/run/sbx-nvidia/lib/libEGL_nvidia.so.0"),
            "and its destination keeps the name the loader asks for — a source bound onto itself \
             would resolve to the versioned name and the soname would vanish"
        );
        assert_eq!(
            bridge.version.as_deref(),
            Some("580.173.02"),
            "the version is read off the file the soname resolves to"
        );
        assert!(
            !bridge
                .libs
                .iter()
                .any(|(_, dest)| dest.to_string_lossy().contains("libnvidia-container")),
            "the container toolkit sits in the same directory and is not the driver's userspace"
        );
        assert!(
            bridge.icd.is_none() && bridge.vendor_json.is_none(),
            "the libraries alone declare nothing: a host without the manifests offers no vendor \
             and no Vulkan driver, and the bridge says so rather than inventing them"
        );

        let icd = root.join("usr/share/vulkan/icd.d");
        std::fs::create_dir_all(&icd).expect("stage the Vulkan manifest directory");
        std::fs::write(icd.join("nvidia_icd.json"), b"{}").expect("stage the manifest");
        assert_eq!(
            nvidia_bridge_in(root.path())
                .expect("still a bridge")
                .icd
                .map(|(_, dest)| dest),
            Some(PathBuf::from(
                "/run/sbx-nvidia/vulkan/icd.d/nvidia_icd.json"
            )),
            "and it is carried once it is there, so a Vulkan client sees the card beside mesa"
        );
    }

    #[test]
    fn the_nvidia_grant_enumerates_its_nodes_and_never_a_drm_primary_node() {
        let root = crate::testutil::TmpDir::new();
        let dev = root.join("dev");
        std::fs::create_dir_all(&dev).expect("stage the device directory");
        for node in [
            "nvidiactl",
            "nvidia0",
            "nvidia1",
            "nvidia-uvm",
            "nvidia-modeset",
            "nvidia-caps",
            "card0",
        ] {
            std::fs::write(dev.join(node), b"").expect("stage a node");
        }

        let nodes: Vec<String> = nvidia_nodes_in(root.path())
            .iter()
            .filter_map(|p| p.file_name()?.to_str().map(str::to_string))
            .collect();

        assert_eq!(
            nodes,
            [
                "nvidia-modeset",
                "nvidia-uvm",
                "nvidia0",
                "nvidia1",
                "nvidiactl"
            ],
            "every numbered card is enumerated rather than assumed, the control nodes come along, \
             and neither a DRM primary node nor the `nvidia-caps` directory does"
        );
    }

    /// A bridge with one library and every declaration present, for the composition tests below.
    fn a_bridge() -> NvidiaBridge {
        let cage = PathBuf::from(CAGE_NVIDIA);
        NvidiaBridge {
            libs: vec![(
                PathBuf::from("/usr/lib/x86_64-linux-gnu/libEGL_nvidia.so.580.173.02"),
                cage.join("lib/libEGL_nvidia.so.0"),
            )],
            vendor_json: Some((
                PathBuf::from("/usr/share/glvnd/egl_vendor.d/10_nvidia.json"),
                cage.join("egl_vendor.d/10_nvidia.json"),
            )),
            platforms: vec![(
                PathBuf::from("/usr/share/egl/egl_external_platform.d/10_nvidia_wayland.json"),
                cage.join("egl_external_platform.d/10_nvidia_wayland.json"),
            )],
            icd: Some((
                PathBuf::from("/usr/share/vulkan/icd.d/nvidia_icd.json"),
                cage.join("vulkan/icd.d/nvidia_icd.json"),
            )),
            devices: vec![PathBuf::from("/dev/nvidiactl")],
            version: Some("580.173.02".into()),
        }
    }

    #[test]
    fn the_nvidia_wiring_joins_mesas_lists_and_never_stands_in_for_them() {
        let mesa = driver_env(Path::new("/nix/store/abc-mesa"));
        let mut warnings = Vec::new();
        let wiring = nvidia_wiring(
            &a_bridge(),
            &mesa,
            Some(Path::new("/nix/store/abc-libglvnd")),
            Some("580.173.02"),
            &mut warnings,
        );
        let all = |key: &str| -> Vec<String> {
            wiring
                .env
                .iter()
                .filter(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .collect()
        };

        // The defect this pins: a first cut named vendor *files* built from a host path that did
        // not exist in the cage, so mesa's declaration dropped out and the Wayland and GBM
        // platforms went with it. Both directories, NVIDIA first, is the measured answer.
        assert_eq!(
            all("__EGL_VENDOR_LIBRARY_DIRS"),
            ["/run/sbx-nvidia/egl_vendor.d:/nix/store/abc-mesa/share/glvnd/egl_vendor.d"],
            "the vendor directories are a union with mesa's, not a replacement of it"
        );
        assert_eq!(
            all("VK_DRIVER_FILES"),
            ["/run/sbx-nvidia/vulkan/icd.d/nvidia_icd.json:/nix/store/abc-mesa/share/vulkan/icd.d"],
            "and so are the Vulkan manifests: NVIDIA's file ahead of the directory holding mesa's"
        );

        // The second defect: without GLVND on the loader path the vendor library cannot resolve
        // `libEGL.so.1`, and the driver refuses an instance without a word. Both directories are
        // emitted; the caller folds repeats of this key into their union.
        assert_eq!(
            all("LD_LIBRARY_PATH"),
            ["/run/sbx-nvidia/lib", "/nix/store/abc-libglvnd/lib"],
            "the bridge's own directory and the GLVND dispatch both reach the loader path"
        );
        assert_eq!(
            all("__EGL_EXTERNAL_PLATFORM_CONFIG_DIRS"),
            ["/run/sbx-nvidia/egl_external_platform.d"],
            "without which NVIDIA's vendor offers no Wayland platform"
        );
        assert!(warnings.is_empty(), "a complete bridge warns about nothing");

        let dests: Vec<String> = wiring
            .binds
            .iter()
            .map(|(_, dest)| dest.display().to_string())
            .collect();
        assert_eq!(
            dests,
            [
                "/run/sbx-nvidia/lib/libEGL_nvidia.so.0",
                "/run/sbx-nvidia/egl_vendor.d/10_nvidia.json",
                "/run/sbx-nvidia/egl_external_platform.d/10_nvidia_wayland.json",
                "/run/sbx-nvidia/vulkan/icd.d/nvidia_icd.json",
            ],
            "every declaration is carried, each under the name its reader asks for"
        );
    }

    #[test]
    fn a_missing_piece_is_named_and_leaves_the_layer_below_alone() {
        let mesa = driver_env(Path::new("/nix/store/abc-mesa"));
        let mut bridge = a_bridge();
        bridge.vendor_json = None;
        bridge.platforms.clear();
        let mut warnings = Vec::new();
        let wiring = nvidia_wiring(&bridge, &mesa, None, Some("580.173.02"), &mut warnings);

        assert!(
            !wiring
                .env
                .iter()
                .any(|(k, _)| k == "__EGL_VENDOR_LIBRARY_DIRS"
                    || k == "__EGL_EXTERNAL_PLATFORM_CONFIG_DIRS"),
            "a declaration that is not there is not announced: mesa's own value stands"
        );
        assert_eq!(warnings.len(), 2, "and each absence is named: {warnings:?}");
        assert!(
            warnings.iter().any(|w| w.contains("10_nvidia.json"))
                && warnings.iter().any(|w| w.contains("Wayland platform")),
            "by what is missing and what it costs: {warnings:?}"
        );
    }

    #[test]
    fn a_userspace_that_disagrees_with_the_kernel_module_is_named() {
        let mut warnings = Vec::new();
        nvidia_wiring(&a_bridge(), &[], None, Some("575.64.03"), &mut warnings);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("580.173.02") && w.contains("575.64.03")),
            "the skew names both sides, because its natural failure is silent: {warnings:?}"
        );

        let mut quiet = Vec::new();
        nvidia_wiring(&a_bridge(), &[], None, None, &mut quiet);
        assert!(
            quiet.is_empty(),
            "and `cannot tell` is not a mismatch: {quiet:?}"
        );
    }

    #[test]
    fn the_kernel_module_version_is_read_from_the_prose_line_it_sits_in() {
        assert_eq!(
            kernel_module_version(
                "NVRM version: NVIDIA UNIX x86_64 Kernel Module  580.173.02  Tue Jun 23 08:38:17 \
                 UTC 2026\nGCC version:\n"
            )
            .as_deref(),
            Some("580.173.02"),
            "the file is prose, not a bare version: the number is the token after `Kernel Module`"
        );
        assert_eq!(
            kernel_module_version("something else entirely"),
            None,
            "a line of another shape answers `cannot tell`, never a false mismatch"
        );
    }

    #[test]
    fn the_gpu_grant_enumerates_render_nodes_and_never_the_primary_nodes() {
        let dri = crate::testutil::TmpDir::new();
        for node in [
            "renderD129",
            "card0",
            "renderD128",
            "card1",
            "by-path",
            "renderD",
            "cardX",
        ] {
            std::fs::write(dri.join(node), b"").expect("stage a device node");
        }

        assert_eq!(
            render_nodes_in(dri.path()),
            vec![dri.join("renderD128"), dri.join("renderD129")],
            "only the numbered render nodes are granted, in a fixed order"
        );

        // A host with no `/dev/dri` at all grants nothing, and the cage renders in software.
        assert!(render_nodes_in(&dri.join("absent")).is_empty());
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

        // The render half of the same space, which is what the device grant is drawn from.
        assert!(is_render_node("renderD128"));
        assert!(
            !is_render_node("card0"),
            "a primary node is not a render node"
        );
        assert!(!is_render_node("renderD"));
        assert!(!is_render_node("card1-DP-1"));
    }
}
