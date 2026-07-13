//! Audio (microphone + playback) for an app in the cage, via PulseAudio.
//!
//! A hermetic cage carries no audio: no audio-server socket and no client libraries, so an app
//! cannot open a capture or playback stream — its microphone and sound are silently unavailable.
//! When `audio = true` a trusted config opens audio, covering both kinds of Linux audio client:
//!
//! 1. **A native PulseAudio client** (Chromium/Electron): ops provisions the PulseAudio client
//!    library (`libpulse.so.0`, absent from an autoPatchelf'd app's closure, which carries only
//!    ALSA) and puts it on the app's loader path (`LD_LIBRARY_PATH`); the client connects to the
//!    bound socket named by `PULSE_SERVER`.
//! 2. **An ALSA client** (a CLI tool using `cpal`/PortAudio/`arecord`, e.g. a terminal agent's voice
//!    mode): these speak the ALSA API (`libasound`) and do **not** honor `PULSE_SERVER`, so ops adds
//!    the standard ALSA→PulseAudio compatibility shim — `alsa-plugins` (the `pcm_pulse`/`ctl_pulse`
//!    plugins) plus an `asound.conf` routing the default PCM/CTL to `pulse` — so an ALSA `default`
//!    capture/playback is transparently routed to the same PulseAudio socket. `libasound` itself is
//!    provisioned too (on `LD_LIBRARY_PATH`) for a CLI binary that does not carry its own.
//!
//! The host PulseAudio socket (`$XDG_RUNTIME_DIR/pulse/native`, which a PipeWire host exposes via
//! `pipewire-pulse`) is bound **read-only** into the cage at a fixed path and named through
//! `PULSE_SERVER`. Same-uid, so a read-only bind still permits `connect()` (like the Wayland socket).
//!
//! Capability: the PulseAudio bus is **not** per-client isolated — a connected client can capture the
//! microphone AND every `.monitor` source (record whatever is playing on the host), not only the
//! microphone. That is why `audio = true` is trusted-only, like `gpu`/`dbus`.
//!
//! Unlike `dbus = true`, there is **no network-posture caveat** (no SEC-001 analog): audio has no
//! filtering proxy to bypass — the whole bus is the documented grant — and the socket is bound
//! directly by path (filesystem-scoped), so `network = "shared"` exposes nothing beyond what
//! `audio = true` already grants (unlike an abstract-namespace D-Bus socket reachable around a proxy
//! in the shared netns). Audio is therefore wired the same in every network posture.
//!
//! Best-effort throughout: a failed provision, or the absence of a host socket, degrades to a cage
//! without audio (a warning), never a failed launch. The socket bind + `PULSE_SERVER` are firm
//! (independent of provisioning); the client libraries and the ALSA shim are best-effort.

use crate::store::{self, Layout};
use std::io;
use std::path::{Path, PathBuf};

/// The PulseAudio client library: `(nixpkgs attribute, a file the output must contain, gcroot name)`.
/// `lib/libpulse.so.0` is the client library a native PulseAudio client (Chromium) `dlopen`s.
const LIBPULSE: (&str, &str, &str) = ("libpulseaudio", "lib/libpulse.so.0", "libpulseaudio");
/// The ALSA client library, so a CLI binary that does not carry its own `libasound.so.2` finds one
/// (and its `share/alsa/alsa.conf`, the base config that loads the plugins).
const ALSA_LIB: (&str, &str, &str) = ("alsa-lib", "lib/libasound.so.2", "alsa-lib");
/// The ALSA→PulseAudio compatibility plugins: `libasound_module_pcm_pulse.so` (and the ctl twin) let
/// an ALSA `default` device route to a PulseAudio server. This is the standard, maintained bridge —
/// the same mechanism a desktop uses to let ALSA apps reach PipeWire's `pipewire-pulse`.
const ALSA_PLUGINS: (&str, &str, &str) = (
    "alsa-plugins",
    "lib/alsa-lib/libasound_module_pcm_pulse.so",
    "alsa-plugins",
);

/// The fixed cage path the host PulseAudio socket is bound at (parity with the portal and dbus
/// sockets under `/run/ops-*`), named through `PULSE_SERVER` — so audio does not depend on the
/// Wayland hole's `XDG_RUNTIME_DIR`, and a project `[env]` re-pointing `PULSE_SERVER` only self-DoSes.
pub(crate) const CAGE_SOCK: &str = "/run/ops-pulse";
/// The in-cage path the generated `asound.conf` is bound at. The base `alsa.conf` (from `alsa-lib`,
/// located via `ALSA_CONFIG_DIR`) includes this file, so its `default`→`pulse` routing takes effect.
pub(crate) const ASOUND_CONF_INCAGE: &str = "/etc/asound.conf";

/// The ALSA configuration routing the default PCM and control to PulseAudio. Fixed and ops-controlled
/// (no interpolation), so it is safe to bind verbatim.
const ASOUND_CONF: &str = "pcm.!default {\n    type pulse\n}\nctl.!default {\n    type pulse\n}\n";

/// The ALSA→PulseAudio compatibility shim (`alsa-plugins` + `asound.conf`), for ALSA clients. This is
/// a **best-effort add-on** over the core native-PulseAudio layer: it can fail to provision (e.g.
/// `alsa-plugins` not in the cache) without sinking audio for a native-PulseAudio app (Electron).
pub(crate) struct AlsaShim {
    /// `alsa-lib`'s `share/alsa` directory (holds `alsa.conf`), for `ALSA_CONFIG_DIR`.
    pub(crate) config_dir: PathBuf,
    /// `alsa-plugins`' plugin directory, for `ALSA_PLUGIN_DIR` (where `libasound` loads the pulse
    /// plugin from).
    pub(crate) plugin_dir: PathBuf,
    /// The staged `asound.conf`, to bind read-only at [`ASOUND_CONF_INCAGE`].
    pub(crate) asound_conf: PathBuf,
}

/// The provisioned audio userspace: the store roots to seed into the project store (so the cage reads
/// the libraries through `/nix`), the library directories for `LD_LIBRARY_PATH`, and — when it
/// provisioned — the ALSA→PulseAudio shim.
pub(crate) struct AudioLayer {
    /// The store roots to seed like mesa and the fonts: libpulseaudio always, plus the ALSA userspace
    /// (alsa-lib + alsa-plugins) when the shim provisioned.
    pub(crate) roots: Vec<PathBuf>,
    /// The library directories to add to `LD_LIBRARY_PATH`: libpulse always, plus libasound when the
    /// shim provisioned.
    pub(crate) lib_dirs: Vec<PathBuf>,
    /// The ALSA→PulseAudio shim, present only when it provisioned. `None` still leaves a working
    /// native-PulseAudio layer (Electron) — the ALSA add-on is decoupled from the core.
    pub(crate) alsa: Option<AlsaShim>,
}

/// Provision the audio userspace into ops's store against the pinned `nixpkgs`. The gcroots are keyed
/// by revision (`<data>/gcroots/audio/<rev>/…`), shared across every project on the same channel —
/// like mesa and the fonts.
///
/// The native-PulseAudio client library (`libpulseaudio`) is the **core**: if it fails, there is no
/// audio (`Err`) and the caller degrades to a cage without audio. The **ALSA→pulse shim**
/// (`alsa-lib`, `alsa-plugins`, and the `asound.conf`) is a **best-effort add-on**: a failure to
/// provision it warns and returns a layer with `alsa: None`, so a native-PulseAudio app (Electron,
/// the proven flagship path) still gets audio even though the ALSA CLI path would not. This
/// decoupling keeps the new ALSA dependency from being able to break the pre-existing Electron path.
pub(crate) fn provision(nix: &Path, layout: &Layout, nixpkgs: &str) -> io::Result<AudioLayer> {
    let base = layout
        .data_dir()
        .join("gcroots")
        .join("audio")
        .join(store::revision_of(nixpkgs));
    let provision_one = |attr_marker_name: (&str, &str, &str)| {
        let (attr, marker, name) = attr_marker_name;
        store::provision(nix, layout, &base.join(name), nixpkgs, attr, marker)
    };
    // Core — a failure here means no audio at all.
    let pulse_root = provision_one(LIBPULSE)?;
    let mut roots = vec![pulse_root.clone()];
    let mut lib_dirs = vec![pulse_root.join("lib")];

    // Best-effort ALSA→pulse shim — a failure leaves the native-PulseAudio layer intact.
    let alsa = match provision_alsa_shim(&provision_one, layout.data_dir()) {
        Ok((alsa_lib_root, plugins_root, asound_conf)) => {
            let shim = AlsaShim {
                config_dir: alsa_lib_root.join("share/alsa"),
                plugin_dir: plugins_root.join("lib/alsa-lib"),
                asound_conf,
            };
            lib_dirs.push(alsa_lib_root.join("lib"));
            roots.push(alsa_lib_root);
            roots.push(plugins_root);
            Some(shim)
        }
        Err(e) => {
            crate::diag::warn(&format!(
                "`audio = true`: the ALSA→PulseAudio shim could not be provisioned ({e}) — a \
                 native-PulseAudio app (Electron) still has audio, but an ALSA-based CLI voice tool \
                 will not capture"
            ));
            None
        }
    };
    Ok(AudioLayer {
        roots,
        lib_dirs,
        alsa,
    })
}

/// Provision the ALSA shim's two store paths and stage the `asound.conf`. Returned as raw paths so
/// [`provision`] can add them to the seed roots; any failure propagates and the caller degrades to a
/// layer without the shim.
fn provision_alsa_shim(
    provision_one: &impl Fn((&str, &str, &str)) -> io::Result<PathBuf>,
    data_dir: &Path,
) -> io::Result<(PathBuf, PathBuf, PathBuf)> {
    let alsa_lib_root = provision_one(ALSA_LIB)?;
    let plugins_root = provision_one(ALSA_PLUGINS)?;
    let asound_conf = stage_asound_conf(data_dir)?;
    Ok((alsa_lib_root, plugins_root, asound_conf))
}

/// Stage the fixed `asound.conf` under the data dir, written atomically (temp + `rename`). The
/// content is constant, so a present file is already correct (idempotent); a concurrent launch that
/// lost the rename race just reuses the identical winner.
fn stage_asound_conf(data_dir: &Path) -> io::Result<PathBuf> {
    let base = data_dir.join("audio");
    std::fs::create_dir_all(&base)?;
    let file = base.join("asound.conf");
    if file.is_file() {
        return Ok(file);
    }
    let tmp = base.join(format!(".tmp-{}", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, ASOUND_CONF) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    match std::fs::rename(&tmp, &file) {
        Ok(()) => Ok(file),
        Err(_) if file.is_file() => {
            let _ = std::fs::remove_file(&tmp);
            Ok(file)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// The host PulseAudio socket to bind, derived from the host `$XDG_RUNTIME_DIR`. A PipeWire host
/// exposes it through `pipewire-pulse`; a native PulseAudio host creates the same path. Pure over the
/// runtime dir so it is unit-tested. Returns `None` when `$XDG_RUNTIME_DIR` is unset or empty (the
/// socket cannot be located) — the caller then degrades to a cage without audio.
pub(crate) fn host_socket(runtime_dir: Option<&str>) -> Option<PathBuf> {
    let dir = runtime_dir.filter(|d| !d.is_empty())?;
    Some(PathBuf::from(dir).join("pulse/native"))
}

/// The audio env: always point clients at the bound socket (`PULSE_SERVER`); and, when the userspace
/// was provisioned, add the client libraries to the loader path (`LD_LIBRARY_PATH`) and point ALSA at
/// its base config (`ALSA_CONFIG_DIR`) and the pulse plugin (`ALSA_PLUGIN_DIR`). Pure over the layer
/// so it is unit-tested. `PULSE_SERVER` is firm (it goes with the socket bind), the rest best-effort
/// — `None` (a failed provision) means the app finds no client library and simply has no audio, not a
/// launch failure, exactly like GPU degrading to software rendering.
///
/// `LD_LIBRARY_PATH` is a shared, composable variable (unlike mesa's dedicated driver-path vars): the
/// cage sets no baseline value, so this is the sole setter, and the app's own libraries still win — a
/// nix binary resolves them by RUNPATH first, and the `deb:` launcher's own `makeWrapper --prefix
/// LD_LIBRARY_PATH` prepends the app's closure ahead of these directories, so the client libraries
/// (present nowhere else) are found without shadowing anything. It is reserved against an untrusted
/// `[env]` (a code-load path, denylisted alongside `LD_*`); the `ALSA_*` keys are data paths (a
/// project re-pointing them only self-DoSes its own cage's audio); a trusted config overriding any of
/// them only breaks its own cage's audio.
pub(crate) fn env(layer: Option<&AudioLayer>) -> Vec<(String, String)> {
    let mut env = vec![("PULSE_SERVER".to_string(), format!("unix:{CAGE_SOCK}"))];
    if let Some(l) = layer {
        let ld = l
            .lib_dirs
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(":");
        env.push(("LD_LIBRARY_PATH".to_string(), ld));
        // The ALSA vars only when the shim provisioned — a native-PulseAudio app (Electron) needs
        // none of them, so its audio does not depend on the shim.
        if let Some(alsa) = &l.alsa {
            env.push((
                "ALSA_CONFIG_DIR".to_string(),
                alsa.config_dir.display().to_string(),
            ));
            env.push((
                "ALSA_PLUGIN_DIR".to_string(),
                alsa.plugin_dir.display().to_string(),
            ));
        }
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_layer() -> AudioLayer {
        AudioLayer {
            roots: vec![
                PathBuf::from("/nix/store/aaa-libpulseaudio-17.0"),
                PathBuf::from("/nix/store/bbb-alsa-lib-1.2.16"),
                PathBuf::from("/nix/store/ccc-alsa-plugins-1.2.12"),
            ],
            lib_dirs: vec![
                PathBuf::from("/nix/store/aaa-libpulseaudio-17.0/lib"),
                PathBuf::from("/nix/store/bbb-alsa-lib-1.2.16/lib"),
            ],
            alsa: Some(AlsaShim {
                config_dir: PathBuf::from("/nix/store/bbb-alsa-lib-1.2.16/share/alsa"),
                plugin_dir: PathBuf::from("/nix/store/ccc-alsa-plugins-1.2.12/lib/alsa-lib"),
                asound_conf: PathBuf::from("/data/audio/asound.conf"),
            }),
        }
    }

    #[test]
    fn host_socket_locates_pulse_native_under_the_runtime_dir() {
        assert_eq!(
            host_socket(Some("/run/user/1000")),
            Some(PathBuf::from("/run/user/1000/pulse/native"))
        );
        // An unset or empty runtime dir cannot locate the socket → no audio (best-effort).
        assert_eq!(host_socket(None), None);
        assert_eq!(host_socket(Some("")), None);
    }

    #[test]
    fn env_points_at_the_socket_the_libraries_and_the_alsa_shim() {
        let get = |e: &[(String, String)], k: &str| {
            e.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
        };
        let layer = sample_layer();
        let full = env(Some(&layer));
        // The client connects to the fixed cage socket path, not the host's XDG_RUNTIME_DIR.
        assert_eq!(
            get(&full, "PULSE_SERVER").as_deref(),
            Some("unix:/run/ops-pulse")
        );
        // Both client libraries (native libpulse + ALSA libasound) are on the loader path.
        assert_eq!(
            get(&full, "LD_LIBRARY_PATH").as_deref(),
            Some("/nix/store/aaa-libpulseaudio-17.0/lib:/nix/store/bbb-alsa-lib-1.2.16/lib")
        );
        // ALSA finds its base config and the pulse plugin.
        assert_eq!(
            get(&full, "ALSA_CONFIG_DIR").as_deref(),
            Some("/nix/store/bbb-alsa-lib-1.2.16/share/alsa")
        );
        assert_eq!(
            get(&full, "ALSA_PLUGIN_DIR").as_deref(),
            Some("/nix/store/ccc-alsa-plugins-1.2.12/lib/alsa-lib")
        );
        // Without a provisioned userspace (best-effort failure), only PULSE_SERVER is set — the socket
        // is still bound, but the app finds no client library and simply has no audio.
        let bare = env(None);
        assert_eq!(
            get(&bare, "PULSE_SERVER").as_deref(),
            Some("unix:/run/ops-pulse")
        );
        assert_eq!(get(&bare, "LD_LIBRARY_PATH"), None);
        assert_eq!(get(&bare, "ALSA_PLUGIN_DIR"), None);
    }

    #[test]
    fn a_layer_without_the_alsa_shim_still_gives_a_native_pulseaudio_app_its_library() {
        // The decoupling guard: if only libpulse provisioned (the ALSA shim failed), a native
        // PulseAudio app (Electron — the proven flagship path) must still get libpulse on the loader
        // path. The new ALSA dependency must not be able to break the pre-existing Electron path.
        let get = |e: &[(String, String)], k: &str| {
            e.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
        };
        let pulse_only = AudioLayer {
            roots: vec![PathBuf::from("/nix/store/aaa-libpulseaudio-17.0")],
            lib_dirs: vec![PathBuf::from("/nix/store/aaa-libpulseaudio-17.0/lib")],
            alsa: None,
        };
        let e = env(Some(&pulse_only));
        assert_eq!(
            get(&e, "LD_LIBRARY_PATH").as_deref(),
            Some("/nix/store/aaa-libpulseaudio-17.0/lib"),
            "libpulse must be on the loader path even without the ALSA shim"
        );
        // No ALSA vars without the shim (an ALSA CLI tool would have no audio, but Electron does).
        assert_eq!(get(&e, "ALSA_CONFIG_DIR"), None);
        assert_eq!(get(&e, "ALSA_PLUGIN_DIR"), None);
    }

    #[test]
    fn asound_conf_routes_the_default_device_to_pulse() {
        // The load-bearing content: the default PCM and control both route to the pulse type, so an
        // ALSA client opening `default` reaches the PulseAudio socket.
        assert!(ASOUND_CONF.contains("pcm.!default"));
        assert!(ASOUND_CONF.contains("ctl.!default"));
        assert!(ASOUND_CONF.contains("type pulse"));
    }
}
