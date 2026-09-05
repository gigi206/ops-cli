//! Audio (microphone + playback) for an app in the cage, via PulseAudio.
//!
//! A hermetic cage carries no audio: no audio-server socket and no client libraries, so an app
//! cannot open a capture or playback stream — its microphone and sound are silently unavailable.
//! When `audio = true` a trusted config opens audio, covering the kinds of Linux audio client:
//!
//! 1. **A native PulseAudio client** (Chromium/Electron): sbx provisions the PulseAudio client
//!    library (`libpulse.so.0`, absent from an autoPatchelf'd app's closure, which carries only
//!    ALSA) and puts it on the app's loader path (`LD_LIBRARY_PATH`); the client connects to the
//!    bound socket named by `PULSE_SERVER`.
//! 2. **An ALSA client** (a CLI tool using `cpal`/`arecord`, e.g. a terminal agent's voice mode):
//!    these speak the ALSA API (`libasound`) and do **not** honor `PULSE_SERVER`, so sbx adds the
//!    standard ALSA→PulseAudio compatibility shim — `alsa-plugins` (the `pcm_pulse`/`ctl_pulse`
//!    plugins) plus an `asound.conf` routing the default PCM/CTL to `pulse` — so an ALSA `default`
//!    capture/playback is transparently routed to the same PulseAudio socket. `libasound` itself is
//!    provisioned too (on `LD_LIBRARY_PATH`) for a CLI binary that does not carry its own.
//! 3. **A PortAudio client** (e.g. a Python tool such as `sounddevice`): PortAudio speaks ALSA under
//!    the hood, so it rides the shim from (2) — but the tool must first `dlopen`
//!    `libportaudio.so.2`, which the cage lacks, so sbx provisions `portaudio` onto
//!    `LD_LIBRARY_PATH`.
//!
//! Delivery is **runtime-agnostic**: putting the client libraries (libpulse, libasound, portaudio) on
//! `LD_LIBRARY_PATH` is all a C/C++/Rust/Node tool needs — they load a native library the normal way
//! (`dlopen` a soname, or RUNPATH), which honors `LD_LIBRARY_PATH`. That path is proven for C
//! (`arecord`), C++ (Electron/libpulse), and Rust (`cpal`/libasound). **Python is the one exception**:
//! `ctypes.util.find_library(name)` does NOT consult `LD_LIBRARY_PATH` — on Linux it shells out to
//! `ldconfig`/`gcc`/`ld`, none of which a hermetic cage carries, so it always returns `None` and
//! `sounddevice` cannot locate PortAudio. So sbx additionally stages a `sitecustomize.py` (on
//! `PYTHONPATH`) that makes `find_library` fall back to scanning `LD_LIBRARY_PATH`. This is **not**
//! Python favoritism — it is a targeted patch for a Python-specific discovery defect; it is inert for
//! any non-Python runtime (`PYTHONPATH` is a no-op for them), generic across ctypes consumers, and
//! staged only under `audio = true`.
//!
//! The host PulseAudio socket (`$XDG_RUNTIME_DIR/pulse/native`, which a PipeWire host exposes via
//! `pipewire-pulse`) is bound **read-only** into the cage at a fixed path and named through
//! `PULSE_SERVER`. Same-uid, so a read-only bind still permits `connect()` (like the Wayland socket).
//!
//! Capability: the PulseAudio bus is **not** per-client isolated — a connected client can capture the
//! microphone AND every `.monitor` source (record whatever is playing on the host), not only the
//! microphone. That is why `audio = true` is trusted-only, like `gpu`/`dbus`.
//!
//! Unlike `dbus = true`, there is **no network-posture caveat**: audio has no
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
/// PortAudio, which a Python audio tool such as `sounddevice` `dlopen`s (`lib/libportaudio.so.2`).
/// PortAudio speaks ALSA, so it rides the ALSA→PulseAudio shim; provisioned only alongside it.
const PORTAUDIO: (&str, &str, &str) = ("portaudio", "lib/libportaudio.so.2", "portaudio");

/// The fixed cage path the `find_library` shim directory is bound at, placed on `PYTHONPATH` so its
/// `sitecustomize.py` runs at interpreter startup (parity with the other fixed cage paths).
pub(crate) const PYSHIM_INCAGE: &str = "/opt/sbx/audio-pyshim";

/// A `sitecustomize.py` for the Python voice stack, patching two ecosystem quirks a hermetic MITM
/// cage exposes. **(1)** `ctypes.util.find_library` falls back to scanning `LD_LIBRARY_PATH` for a
/// matching `lib<name>.so*`: a hermetic cage has no `ldconfig`/`gcc`/`ld`, so the stock `find_library`
/// (which shells out to one of those) always returns `None` — breaking any package that loads a native
/// library by name, notably `sounddevice`, which resolves PortAudio via `find_library('portaudio')`.
/// Its full path is then `dlopen`ed directly. **(2)** `certifi.where()` returns `SSL_CERT_FILE` when
/// set: a certifi-pinned TLS client (edge-tts's read-aloud) verifies against certifi's Mozilla bundle
/// and ignores `SSL_CERT_FILE`, so under the egress allowlist it rejects sbx's per-session MITM CA;
/// this makes it trust the same CA sbx already exports to every other client. Both patches are
/// additive/conditional (find_library only extends the stock lookup; certifi only when SSL_CERT_FILE
/// is set) and generic (any ctypes / any certifi consumer benefits). Fixed and sbx-controlled (no
/// interpolation), so it is safe to stage verbatim.
///
/// A `sitecustomize` on `PYTHONPATH` shadows one an app might ship (Python imports only the first on
/// `sys.path`). This is an accepted, documented trade-off: it is staged only under the opt-in,
/// trusted `audio = true`, and shipping a `sitecustomize.py` inside an installed package is rare; the
/// alternative (a language-agnostic `/sbin/ldconfig` + generated `ld.so.cache`) costs more moving
/// parts for a case this narrow.
const SITECUSTOMIZE: &str = include_str!("audio_sitecustomize.py");

/// The fixed cage path the host PulseAudio socket is bound at (parity with the portal and dbus
/// sockets under `/run/sbx-*`), named through `PULSE_SERVER` — so audio does not depend on the
/// Wayland hole's `XDG_RUNTIME_DIR`, and a project `[env]` re-pointing `PULSE_SERVER` only self-DoSes.
pub(crate) const CAGE_SOCK: &str = "/run/sbx-pulse";
/// The in-cage path the generated `asound.conf` is bound at. The base `alsa.conf` (from `alsa-lib`,
/// located via `ALSA_CONFIG_DIR`) includes this file, so its `default`→`pulse` routing takes effect.
pub(crate) const ASOUND_CONF_INCAGE: &str = "/etc/asound.conf";

/// The ALSA configuration routing the default PCM and control to PulseAudio. Fixed and sbx-controlled
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
    /// The staged `find_library` shim directory (holding `sitecustomize.py`), present only when
    /// PortAudio provisioned. Bound read-only at [`PYSHIM_INCAGE`] and placed on `PYTHONPATH`, it
    /// lets a Python PortAudio tool (`sounddevice`) locate `libportaudio.so.2` on `LD_LIBRARY_PATH`.
    /// `None` leaves ALSA-direct capture (arecord/cpal) working — PortAudio support rides the shim
    /// but is decoupled from it.
    pub(crate) pyshim: Option<PathBuf>,
}

/// Provision the audio userspace into sbx's store against the pinned `nixpkgs`. The gcroots are keyed
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
    let mut pyshim = None;
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
            // PortAudio (sounddevice) support builds on the ALSA backend just wired: provision
            // `libportaudio` and stage the `find_library` shim. Best-effort within the shim — a
            // failure leaves ALSA-direct capture (arecord/cpal) working; only a Python PortAudio tool
            // loses audio, so it must not sink the ALSA layer.
            match provision_portaudio(&provision_one, layout.data_dir()) {
                Ok((pa_root, shim_dir)) => {
                    lib_dirs.push(pa_root.join("lib"));
                    roots.push(pa_root);
                    pyshim = Some(shim_dir);
                }
                Err(e) => crate::diag::warn(&format!(
                    "`audio = true`: PortAudio support could not be provisioned ({e}) — ALSA-direct \
                     capture still works, but a Python PortAudio tool (e.g. `sounddevice`) will not"
                )),
            }
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
        pyshim,
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

/// Provision PortAudio and stage the `find_library` shim, so a Python PortAudio tool (`sounddevice`)
/// can locate and `dlopen` `libportaudio.so.2`. Returned as `(portaudio root, shim dir)` so
/// [`provision`] can seed the root and carry the shim dir (bound at [`PYSHIM_INCAGE`]). Best-effort:
/// any failure propagates and the caller keeps the ALSA-direct layer.
fn provision_portaudio(
    provision_one: &impl Fn((&str, &str, &str)) -> io::Result<PathBuf>,
    data_dir: &Path,
) -> io::Result<(PathBuf, PathBuf)> {
    let pa_root = provision_one(PORTAUDIO)?;
    let pyshim_dir = stage_pyshim(data_dir)?;
    Ok((pa_root, pyshim_dir))
}

/// Stage the fixed `asound.conf` under the data dir. The content is constant, so a present file is
/// already correct (idempotent).
fn stage_asound_conf(data_dir: &Path) -> io::Result<PathBuf> {
    stage_atomically(&data_dir.join("audio"), "asound.conf", ASOUND_CONF)
}

/// Stage the `find_library` shim (`sitecustomize.py`) in its own directory under the data dir, and
/// return that **directory** (to bind at [`PYSHIM_INCAGE`] and put on `PYTHONPATH`). A dedicated dir
/// so `PYTHONPATH` exposes only this one file, not the whole `audio/` staging area.
fn stage_pyshim(data_dir: &Path) -> io::Result<PathBuf> {
    let dir = data_dir.join("audio").join("pyshim");
    stage_atomically(&dir, "sitecustomize.py", SITECUSTOMIZE)?;
    Ok(dir)
}

/// Atomically stage `content` at `dir/name` (temp + `rename`), creating `dir`. Re-stages whenever the
/// on-disk bytes differ from `content` — the content is fixed within one sbx build but CHANGES across
/// releases (a new binary ships an updated shim/config), so a skip-if-present would pin a stale file
/// forever. An atomic `rename` replaces in place; a concurrent launch writing the identical bytes is
/// harmless (last writer wins with the same content). Returns the staged file path.
fn stage_atomically(dir: &Path, name: &str, content: &str) -> io::Result<PathBuf> {
    let file = dir.join(name);
    super::atomicfile::write_atomic_if_changed(&file, content.as_bytes())?;
    Ok(file)
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
pub(crate) fn env(layer: Option<&AudioLayer>, base_lib_dirs: &[PathBuf]) -> Vec<(String, String)> {
    let mut env = vec![("PULSE_SERVER".to_string(), format!("unix:{CAGE_SOCK}"))];
    if let Some(l) = layer {
        // LD_LIBRARY_PATH = the provisioned audio client libraries, then the base C++/glibc runtime
        // (`base_lib_dirs`, the same directories as `NIX_LD_LIBRARY_PATH`). A voice speech-to-text
        // engine's native library — faster-whisper's ctranslate2, or onnxruntime, both foreign
        // manylinux `.so`s — is `dlopen`ed by the tool's own interpreter, and `dlopen` honors
        // `LD_LIBRARY_PATH` but NOT `NIX_LD_LIBRARY_PATH` (which only nix-ld consults, and only for a
        // foreign *executable* it launches). Without the base runtime here the load fails with
        // `libstdc++.so.6: cannot open shared object file`. This is language-agnostic — any voice
        // library linked against the C++ runtime needs it, whatever wrapper (Python/Rust/Node) drives
        // it. Appended (not prepended), so the app's own closure and the audio libraries stay ahead.
        let ld = l
            .lib_dirs
            .iter()
            .chain(base_lib_dirs)
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
        // The `find_library` shim only when PortAudio provisioned: put its bound cage directory on
        // `PYTHONPATH` so the staged `sitecustomize.py` runs and `find_library('portaudio')` resolves
        // the provisioned `libportaudio.so.2` from `LD_LIBRARY_PATH`.
        //
        // `PYTHONPATH` *is* a reserved key against an untrusted `[env]`
        // ([`crate::config::is_reserved_env_key`]), which this line is unaffected by: what is pushed
        // here is sbx's own environment for the cage, not a config layer's, and the denylist governs
        // only what an untrusted layer may set. The reasoning that once left it off that list —
        // that re-pointing it self-DoSes the cage's own Python audio — held for this shim and not
        // for the mechanism: a `sitecustomize.py` on `PYTHONPATH` runs before the first line of
        // *any* Python the cage starts, which is the same hole `PYTHONSTARTUP` beside it is
        // reserved for. `config/tasks.rs` had refused it on those terms all along.
        if l.pyshim.is_some() {
            env.push(("PYTHONPATH".to_string(), PYSHIM_INCAGE.to_string()));
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
                PathBuf::from("/nix/store/ddd-portaudio-19"),
            ],
            lib_dirs: vec![
                PathBuf::from("/nix/store/aaa-libpulseaudio-17.0/lib"),
                PathBuf::from("/nix/store/bbb-alsa-lib-1.2.16/lib"),
                PathBuf::from("/nix/store/ddd-portaudio-19/lib"),
            ],
            alsa: Some(AlsaShim {
                config_dir: PathBuf::from("/nix/store/bbb-alsa-lib-1.2.16/share/alsa"),
                plugin_dir: PathBuf::from("/nix/store/ccc-alsa-plugins-1.2.12/lib/alsa-lib"),
                asound_conf: PathBuf::from("/data/audio/asound.conf"),
            }),
            pyshim: Some(PathBuf::from("/data/audio/pyshim")),
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
        let base = [
            PathBuf::from("/nix/store/eee-glibc-2.42/lib"),
            PathBuf::from("/nix/store/fff-gcc-15.2.0-lib/lib"),
        ];
        let layer = sample_layer();
        let full = env(Some(&layer), &base);
        // The client connects to the fixed cage socket path, not the host's XDG_RUNTIME_DIR.
        assert_eq!(
            get(&full, "PULSE_SERVER").as_deref(),
            Some("unix:/run/sbx-pulse")
        );
        // All three client libraries (native libpulse + ALSA libasound + PortAudio) are on the loader
        // path — the last so `sounddevice`'s `find_library` shim can resolve `libportaudio.so.2` — then
        // the base C++/glibc runtime, so a voice STT engine's `dlopen`ed native library finds
        // `libstdc++.so.6` (it is not on NIX_LD_LIBRARY_PATH, which `dlopen` ignores).
        assert_eq!(
            get(&full, "LD_LIBRARY_PATH").as_deref(),
            Some(
                "/nix/store/aaa-libpulseaudio-17.0/lib:/nix/store/bbb-alsa-lib-1.2.16/lib:\
                 /nix/store/ddd-portaudio-19/lib:/nix/store/eee-glibc-2.42/lib:\
                 /nix/store/fff-gcc-15.2.0-lib/lib"
            )
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
        // The `find_library` shim is on PYTHONPATH (the fixed cage path, not the host staging dir).
        assert_eq!(get(&full, "PYTHONPATH").as_deref(), Some(PYSHIM_INCAGE));
        // Without a provisioned userspace (best-effort failure), only PULSE_SERVER is set — the socket
        // is still bound, but the app finds no client library and simply has no audio. The base
        // runtime is not added either (there is no audio library for it to support).
        let bare = env(None, &base);
        assert_eq!(
            get(&bare, "PULSE_SERVER").as_deref(),
            Some("unix:/run/sbx-pulse")
        );
        assert_eq!(get(&bare, "LD_LIBRARY_PATH"), None);
        assert_eq!(get(&bare, "ALSA_PLUGIN_DIR"), None);
        assert_eq!(get(&bare, "PYTHONPATH"), None);
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
            pyshim: None,
        };
        let base = [PathBuf::from("/nix/store/fff-gcc-15.2.0-lib/lib")];
        let e = env(Some(&pulse_only), &base);
        assert_eq!(
            get(&e, "LD_LIBRARY_PATH").as_deref(),
            Some("/nix/store/aaa-libpulseaudio-17.0/lib:/nix/store/fff-gcc-15.2.0-lib/lib"),
            "libpulse must be on the loader path even without the ALSA shim, followed by the base C++ runtime"
        );
        // No ALSA vars and no PYTHONPATH without the shim (an ALSA/PortAudio CLI tool would have no
        // audio, but Electron does).
        assert_eq!(get(&e, "ALSA_CONFIG_DIR"), None);
        assert_eq!(get(&e, "ALSA_PLUGIN_DIR"), None);
        assert_eq!(get(&e, "PYTHONPATH"), None);
    }

    #[test]
    fn asound_conf_routes_the_default_device_to_pulse() {
        // The load-bearing content: the default PCM and control both route to the pulse type, so an
        // ALSA client opening `default` reaches the PulseAudio socket.
        assert!(ASOUND_CONF.contains("pcm.!default"));
        assert!(ASOUND_CONF.contains("ctl.!default"));
        assert!(ASOUND_CONF.contains("type pulse"));
    }

    #[test]
    fn sitecustomize_patches_find_library_to_scan_ld_library_path() {
        // The load-bearing pieces: it wraps `ctypes.util.find_library`, only extends it (calls the
        // original first), and scans `LD_LIBRARY_PATH` for the library, so PortAudio is found in a
        // toolchain-less cage. It is valid, executable Python (parsed by an interpreter at startup).
        assert!(SITECUSTOMIZE.contains("import ctypes.util"));
        assert!(SITECUSTOMIZE.contains("_sbx_orig_find_library = ctypes.util.find_library"));
        assert!(SITECUSTOMIZE.contains("os.environ.get(\"LD_LIBRARY_PATH\""));
        assert!(SITECUSTOMIZE.contains("ctypes.util.find_library = _sbx_find_library"));
        // Part 2: certifi.where() is redirected to SSL_CERT_FILE (sbx's MITM CA), conditionally — so a
        // certifi-pinned voice TTS client (edge-tts) trusts the same CA as every other client under the
        // allowlist, and is untouched when SSL_CERT_FILE is unset (no MITM).
        assert!(SITECUSTOMIZE.contains("os.environ.get(\"SSL_CERT_FILE\")"));
        assert!(SITECUSTOMIZE.contains("certifi.where = lambda: _sbx_ca"));
    }

    #[test]
    fn stage_atomically_rewrites_a_stale_file_when_the_content_changes() {
        // A new sbx release ships an updated shim; the staged file must be replaced, not kept stale.
        // (This is the bug that left the pre-certifi sitecustomize on disk after an upgrade.)
        let dir = crate::testutil::TmpDir::new();
        let d = dir.path().join("audio");

        let p = stage_atomically(&d, "shim.py", "v1").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "v1");

        // Changed content → the same path is overwritten with the new bytes.
        let p2 = stage_atomically(&d, "shim.py", "v2").unwrap();
        assert_eq!(p2, p);
        assert_eq!(std::fs::read_to_string(&p2).unwrap(), "v2");

        // Unchanged content → idempotent no-op (still correct on disk).
        stage_atomically(&d, "shim.py", "v2").unwrap();
        assert_eq!(std::fs::read_to_string(&p2).unwrap(), "v2");
    }
}
