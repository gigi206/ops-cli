//! Where sbx's data directory is, and how a logical store path maps onto it.
//!
//! Pure derivation, plus the guards that decide whether a directory may host the store at all.
//! Two of those guards are the reason this is a module and not a `join`: a data directory is
//! trusted by *location*, so a relative override is refused rather than resolved against whatever
//! directory sbx was launched from; and every unix socket sbx binds lives under this directory, so
//! a path too long to leave room for the widest socket name is refused here — at the moment the
//! directory is chosen — instead of failing later at `bind`, saying "socket" for a mistake about a
//! directory.
//!
//! The leaf of `store`: nothing here reaches into the other children, and all three of them read
//! it.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

/// On-disk layout of the user-owned store, rooted at sbx's private data
/// directory. Pure path derivation — holds no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Layout {
    data_dir: PathBuf,
}

impl Layout {
    /// Resolve the layout from the environment, highest precedence first:
    /// `$SBX_DATA_DIR` names the data directory outright, else `$XDG_DATA_HOME/sbx`,
    /// else `$HOME/.local/share/sbx`. `None` when nothing yields a usable base.
    ///
    /// A relative `$SBX_DATA_DIR` is **refused**, not ignored: it would otherwise
    /// resolve against whatever directory sbx happens to be launched from, letting a
    /// checked-out repository decide where the store lives — and a store is trusted by
    /// location. Falling back silently would put the data somewhere the user did not
    /// ask for, so the refusal yields `None` and is reported on stderr. Every command
    /// that needs the data directory then stops; the one that merely inventories on-disk
    /// locations reports the base as unresolved rather than inventing one. An overlong
    /// `$SBX_DATA_DIR` is refused the same way — see [`check_data_dir_override`].
    pub(crate) fn from_env() -> Option<Self> {
        let over = std::env::var_os("SBX_DATA_DIR");
        let data_dir = data_dir_from(
            over.as_deref(),
            std::env::var_os("XDG_DATA_HOME").as_deref(),
            std::env::var_os("HOME").as_deref(),
        );
        if data_dir.is_none() {
            // The decision came from `data_dir_from`; the wording comes from the same
            // check it consulted, so the two cannot describe different refusals. The gate
            // comes last on purpose: it latches, so it must be reached only once the
            // refusal is about to be spoken.
            if let Some(over) = over.as_deref().filter(|o| !o.is_empty())
                && let Err(why) = check_data_dir_override(over)
                && refusal_unspoken()
            {
                crate::diag::error(&format!("sbx: {why}"));
            }
        }
        let mut data_dir = data_dir?;

        // An explicit override is the invoker's word and settles it. Otherwise a pointer in
        // the default directory says the data has moved into a volume, and sbx follows it —
        // mounting it if need be, so no shell has to remember to.
        if over.as_deref().is_none_or(|o| o.is_empty()) {
            match follow_volume(&data_dir) {
                None => {}
                Some(Ok(mounted)) => data_dir = mounted,
                Some(Err(why)) => {
                    // Fail closed. The mount point exists only while mounted, and it lives
                    // under `/run` — a tmpfs. Carrying on with the unmounted path would
                    // provision gigabytes into RAM and present an empty store as the truth.
                    // Both lines are inside the gate: they are one diagnostic, and speaking
                    // the refusal without the consequence would stop mid-sentence.
                    if refusal_unspoken() {
                        crate::diag::error(&format!(
                            "sbx: sbx's data is in a volume that could not be mounted: {why}"
                        ));
                        crate::diag::error(
                            "sbx: refusing to continue rather than use an empty data directory",
                        );
                    }
                    return None;
                }
            }
        }

        // Guard the directory sbx will actually use — after a volume pointer may have swapped
        // it for a short mount point. A derived `$HOME`/`$XDG_DATA_HOME` too long for the
        // sockets sbx binds under it would otherwise fail deep at launch, talking about a socket
        // rather than the directory; refuse here, with the remedy, at the moment it is resolved.
        // `sbx storage` anchors to `default_data_dir`, not this path, so a volume can still be
        // adopted to fix it.
        if let Err(why) = check_resolved_data_dir(&data_dir) {
            if refusal_unspoken() {
                crate::diag::error(&format!("sbx: {why}"));
            }
            return None;
        }
        Some(Self { data_dir })
    }

    /// [`Layout::from_env`] for a caller that must **not act**: the same resolution, except that a
    /// volume pointer is followed only when the volume is already mounted.
    ///
    /// The completion oracle is that caller. It runs on a keystroke, and `from_env` mounts, so
    /// `sbx net pending <TAB>` attached a loop device and mounted a filesystem — work measured in
    /// seconds, and on a udisks setup a password prompt — because the shell asked what the
    /// candidates were. A volume that is not mounted completes nothing here, which is the right
    /// answer for a keystroke that must not be the thing that mounts it.
    ///
    /// The refusals stay silent too: a completion oracle writing to stderr would print into the
    /// user's half-typed command line.
    pub(crate) fn from_env_without_mounting() -> Option<Self> {
        let over = std::env::var_os("SBX_DATA_DIR");
        let mut data_dir = data_dir_from(
            over.as_deref(),
            std::env::var_os("XDG_DATA_HOME").as_deref(),
            std::env::var_os("HOME").as_deref(),
        )?;
        if over.as_deref().is_none_or(|o| o.is_empty())
            && let Some(mounted) = mounted_volume(&data_dir)
        {
            data_dir = mounted;
        }
        check_resolved_data_dir(&data_dir).ok()?;
        Some(Self { data_dir })
    }

    /// The data directory sbx would use with no volume in play — the plain XDG computation.
    ///
    /// This is where the volume's image and pointer live, so it must stay reachable even once
    /// a pointer has redirected everything else.
    pub(crate) fn default_data_dir() -> Option<PathBuf> {
        data_dir_from(
            None,
            std::env::var_os("XDG_DATA_HOME").as_deref(),
            std::env::var_os("HOME").as_deref(),
        )
    }

    /// Pure constructor: the layout rooted at a given data directory. Split out
    /// so the derived paths are testable without touching the environment.
    #[cfg(test)]
    pub(crate) fn under(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
        }
    }

    /// The argument passed to `nix --store`: the directory that *contains* the
    /// `nix/` tree. A daemonless build into it yields `<store_dir>/nix/store`,
    /// owned by the invoking user.
    pub(crate) fn store_dir(&self) -> PathBuf {
        self.data_dir.join("store")
    }

    /// The root of sbx's private data directory — the parent of the store and of
    /// the per-project sandbox runtime trees.
    pub(crate) fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Where sbx places a nix engine it owns — the store-driving `nix`/`nix-store`
    /// binary, as opposed to the host's. Distinct from the in-cage nix an agent
    /// self-equips with: this one runs on the host to provision the store. The
    /// engine resolver consults it ahead of the host `PATH`.
    pub(crate) fn engine_dir(&self) -> PathBuf {
        self.data_dir.join("engine")
    }

    /// Where installed resolver plugins live, one directory per plugin. Trusted by
    /// location: a project cannot write here, so a plugin's presence is the user's act.
    pub(crate) fn plugins_dir(&self) -> PathBuf {
        self.data_dir.join("plugins")
    }

    /// Where configured remote plugin stores are cached, one directory per store. Like
    /// the plugins tree, trusted by location (owner-only), so the verified catalogue and
    /// fetched artifacts cannot be tampered with by a project.
    pub(crate) fn stores_dir(&self) -> PathBuf {
        self.data_dir.join("stores")
    }

    /// Where the signing key of an apt repository is pinned once sbx has verified an `InRelease`
    /// against it, one armored key per repository. Trusted by location like the plugins and stores
    /// trees: a project cannot write here, so what is pinned is what sbx itself verified. The pin is
    /// deliberately **not** per project — a repository's signing key is a property of that
    /// repository, so a key that changes under one project is caught in every other.
    pub(crate) fn apt_keys_dir(&self) -> PathBuf {
        self.data_dir.join("apt-keys")
    }

    /// The cache directory of one named remote store: `<stores>/<name>/`, holding its
    /// `store.toml` (url + public key), `checkout/` (the verified git clone), and
    /// `catalogue.lock` (the catalogue revision last accepted).
    pub(crate) fn store_path(&self, name: &str) -> PathBuf {
        self.stores_dir().join(name)
    }

    /// Where sbx writes the mark it signs its own desktop notifications with, in the fill that
    /// suits a `dark` desktop or the one that suits a light one.
    ///
    /// A notification daemon runs in its own process and opens the icon file itself, so the mark
    /// has to exist on disk somewhere it can reach — a static binary carrying the image in its
    /// `.rodata` has nothing to hand it otherwise. Here rather than in an XDG icon theme because
    /// this is a directory sbx already owns: no install step to run, and owner-only, so what a
    /// daemon renders as "sbx" cannot be replaced by a project.
    ///
    /// Two files rather than one rewritten in place, so switching desktop theme changes only which
    /// path is sent — nothing is rewritten under a daemon that may be reading it.
    pub(crate) fn icon_path(&self, dark: bool) -> PathBuf {
        self.data_dir
            .join(if dark { "sbx-dark.png" } else { "sbx.png" })
    }
}

/// Follow a volume pointer in `default_dir`, mounting the volume if it is not already.
///
/// `None` when there is no pointer — the ordinary case, and the one that must stay free.
///
/// Resolved once per process: the answer cannot change under us, and a single launch asks for
/// the layout dozens of times. Only the mount is memoised, so nothing is cached before a
/// pointer is found.
fn follow_volume(default_dir: &Path) -> Option<Result<PathBuf, String>> {
    static RESOLVED: std::sync::OnceLock<Option<Result<PathBuf, String>>> =
        std::sync::OnceLock::new();
    RESOLVED
        .get_or_init(|| {
            let image = crate::storage::read_pointer(default_dir)?;
            Some(crate::storage::ensure_mounted(&image))
        })
        .clone()
}

/// Follow a volume pointer **only as far as reading it**: the mount point when the volume is
/// already mounted, and nothing at all when it is not.
///
/// For a caller that must not act. [`follow_volume`] mounts, which is right for a command the user
/// typed and wrong for the completion oracle: that runs on a keystroke, so `sbx net pending <TAB>`
/// attached a loop device and mounted a filesystem — work measured in seconds, and on a udisks
/// setup a password prompt — because the shell asked what the candidates were. Reading the mount
/// table changes nothing, and a volume that is not mounted simply completes nothing, which is the
/// right answer for a keystroke that must not be the thing that mounts it.
fn mounted_volume(default_dir: &Path) -> Option<PathBuf> {
    let image = crate::storage::read_pointer(default_dir)?;
    match crate::storage::state(&image) {
        Ok(crate::storage::State::Mounted { mount_point, .. }) => Some(mount_point),
        _ => None,
    }
}

/// True the first time it is called in a process, false ever after — the gate the data-directory
/// refusals speak through.
///
/// [`Layout::from_env`] is consulted by every layer that needs the store, dozens of times in a
/// single command, and each consultation re-derives the same refusal from the same environment.
/// Printed per consultation, one fact about the environment becomes a wall of identical lines —
/// nine of them for `sbx config show` — and a reader counts failures instead of reading one.
///
/// A gate around the *block* rather than a wrapper around each print, because the volume refusal
/// is two lines: a per-line gate would speak the first and swallow the second, leaving a
/// diagnostic that stops mid-sentence.
///
/// One gate for the whole family rather than one per message, because at most one refusal can be
/// true in a process. The environment decides, it is read afresh on every call, and the only code
/// that rewrites it mid-process (`cli::storage`, after adopting a volume) points it at a mount
/// point under `/run` — short by construction, and the very remedy the refusal names, so the
/// second reading cannot refuse. **Trigger:** a second path that changes `$SBX_DATA_DIR`,
/// `$XDG_DATA_HOME` or `$HOME` mid-process to something that can *also* be refused would go
/// unspoken here; key the gate by message text then.
fn refusal_unspoken() -> bool {
    use std::sync::atomic::{AtomicBool, Ordering};
    static SPOKEN: AtomicBool = AtomicBool::new(false);
    !SPOKEN.swap(true, Ordering::Relaxed)
}

/// Whether `$SBX_DATA_DIR` is what selected the data directory. Surfaced by `doctor` so a
/// shell that carries the override is distinguishable from one that does not — otherwise a
/// store that looks unexpectedly empty has no visible explanation.
pub(crate) fn data_dir_overridden() -> bool {
    std::env::var_os("SBX_DATA_DIR")
        .filter(|v| !v.is_empty())
        .is_some_and(|v| check_data_dir_override(&v).is_ok())
}

/// The longest path a Unix-domain socket can carry, minus its terminator: `sun_path` is a
/// fixed 108-byte field and the kernel needs the trailing NUL.
const SUN_PATH_MAX: usize = 107;

/// The longest socket name any feature appends to the data directory. Every feature that binds
/// an `AF_UNIX` socket under the data directory contributes one; the widest is what the cap must
/// reserve for. With a 7-digit pid and a 5-digit port:
///   `/egress/proxy-<pid>.sock`         (26)  egress proxy, bound into the cage
///   `/egress/control-<pid>.sock`       (28)  egress live control
///   `/fs/control-<pid>.sock`           (24)  filesystem-observation control
///   `/broker/<pid>/<name>.sock`        (33)  a broker plugin's host socket, one per declared
///                                            `[broker.<name>]`, in a per-launch subdir — the only
///                                            family whose width depends on a user-chosen name,
///                                            which is why that name is capped
///                                            ([`BROKER_NAME_MAX`])
///   `/forward/fwd-<pid>/p-<port>.sock` (33)  port forwarding — a per-launch subdir holding one
///                                            socket per forwarded port
/// A new feature whose host socket path is wider than this must widen the sample below, or a
/// data directory the cap accepts would still overrun `sun_path` at that feature's first launch.
const LONGEST_SOCKET_SUFFIX: usize = "/forward/fwd-1234567/p-65535.sock".len();

/// The most a broker name may measure, so `<data>/broker/<pid>/<name>.sock` stays inside
/// [`LONGEST_SOCKET_SUFFIX`] and the data-directory cap keeps the promise it makes.
///
/// Derived rather than written down: every other socket family is fixed-width, so this one is the
/// only place a user's choice can push a bind past `sun_path`. Without it,
/// [`check_data_dir_override`] tells the user a directory fits "because sbx binds sockets under
/// it", and a launch declaring a long-named broker then fails on `UnixListener::bind` with a
/// message about a socket rather than about the directory — the exact outcome that check exists to
/// prevent, on a directory it approved.
pub(crate) const BROKER_NAME_MAX: usize =
    LONGEST_SOCKET_SUFFIX - "/broker/".len() - 7 - "/".len() - ".sock".len();

/// The most a data directory may measure and still host those sockets.
const DATA_DIR_MAX: usize = SUN_PATH_MAX - LONGEST_SOCKET_SUFFIX;

/// Validate an explicit `$SBX_DATA_DIR`, returning the directory or why it was refused.
///
/// One function so the decision and the diagnostic can never disagree.
///
/// The length bound is not cosmetic. Egress filtering, the D-Bus filter, port forwarding and
/// exec enforcement each bind an `AF_UNIX` socket *under* the data directory, and a socket
/// path that overruns `sun_path` fails at launch — well after the choice was made, with a
/// message about a socket rather than about the directory. Refusing here turns a puzzling
/// runtime failure into an answerable one, at the moment the path is chosen.
fn check_data_dir_override(value: &OsStr) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!(
            "SBX_DATA_DIR must be an absolute path (got {})",
            path.display()
        ));
    }
    let len = value.as_encoded_bytes().len();
    if len > DATA_DIR_MAX {
        return Err(format!(
            "SBX_DATA_DIR is {len} bytes; at most {DATA_DIR_MAX} fit, because sbx binds \
             sockets under it and a Unix socket path cannot exceed {SUN_PATH_MAX} bytes \
             (got {})",
            path.display()
        ));
    }
    Ok(path)
}

/// Refuse a *resolved* data directory whose path is too long to host sbx's sockets.
///
/// [`check_data_dir_override`] guards only an explicit `$SBX_DATA_DIR`; a directory sbx
/// *derives* — `$XDG_DATA_HOME/sbx` or `$HOME/.local/share/sbx` — is not handed in and so
/// escapes it, yet overruns `sun_path` just the same when `$HOME` is long. This runs on the
/// **final** directory, after a volume pointer has had its say, so an adopted volume — whose
/// mount point under `/run` is short — passes silently even when the plain derived path would
/// not. That is deliberate: adopting a volume is one of the two remedies, and it must not be
/// refused as a side effect of the very problem it solves. An override that reached here already
/// passed the stricter check above, so it too passes without a second, differently-worded refusal.
fn check_resolved_data_dir(dir: &Path) -> Result<(), String> {
    let len = dir.as_os_str().as_encoded_bytes().len();
    if len > DATA_DIR_MAX {
        return Err(format!(
            "sbx's data directory is {len} bytes ({}); at most {DATA_DIR_MAX} fit, because sbx \
             binds sockets under it and a Unix socket path cannot exceed {SUN_PATH_MAX} bytes. \
             Set SBX_DATA_DIR to a shorter path, or adopt a storage volume — its mount point is short.",
            dir.display()
        ));
    }
    Ok(())
}

/// Pure core of [`Layout::from_env`]: an absolute `SBX_DATA_DIR` wins outright, else
/// prefer an absolute `XDG_DATA_HOME`, else fall back to `HOME/.local/share`.
///
/// The two overrides differ in kind, so they differ in treatment. `XDG_DATA_HOME` is a
/// *base* shared with every other application, so `sbx` is appended and a relative value
/// is ignored, as the base-directory specification requires. `SBX_DATA_DIR` names sbx's
/// own directory, so it is used verbatim — and a relative value yields `None` rather than
/// falling through, because quietly using a different directory than the one asked for
/// would strand the user's projects and apps somewhere they never look. An unset *or
/// empty* value is simply absent, so clearing the variable restores the default.
fn data_dir_from(
    sbx: Option<&OsStr>,
    xdg: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Option<PathBuf> {
    if let Some(sbx) = sbx.filter(|s| !s.is_empty()) {
        return check_data_dir_override(sbx).ok();
    }
    if let Some(xdg) = xdg {
        let p = PathBuf::from(xdg);
        if p.is_absolute() {
            return Some(p.join("sbx"));
        }
    }
    Some(PathBuf::from(home?).join(".local/share/sbx"))
}

/// Create the store's directory skeleton if absent and tighten its permissions
/// to owner-only. Idempotent, and fail-closed: a directory that already existed
/// with looser permissions is tightened, never left group/world-accessible.
///
/// Never touches the host `/nix`. Called lazily, the first time a sandbox
/// consumes the store or sbx provisions into it.
pub(crate) fn ensure(layout: &Layout) -> io::Result<()> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    for dir in [layout.data_dir.clone(), layout.store_dir()] {
        // Create owner-only from the start, so a loose umask never leaves a
        // world-readable window between creation and tightening...
        DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
        // ...and tighten a directory that already existed with looser bits.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// The host-side path backing a logical store path. `nix build --print-out-paths`
/// reports the *logical* path (`/nix/store/<hash>-<name>`), which is what resolves
/// *inside* the sandbox (where the store is bound at `/nix`); on the host the same
/// content lives under the store root, so a bind *source* must use this physical
/// path. Inside-sandbox uses (`PATH`, the loader) keep the logical path.
///
/// **The result is always under the store root**, and this is the one place that says so. A plain
/// `join` does not constrain anything: a `logical` carrying `..` produced a path outside the store,
/// and the callers are where that would have mattered — of thirteen in production, five read the
/// path and **eight are bind sources**. Rather than thirteen checks that could each be forgotten,
/// the walk resolves the path itself: `.` is dropped, `..` steps back through what has been built,
/// and a `..` at the top is dropped rather than followed, because the store root *is* the root
/// here. So a benign `a/../b` still means `b`, and an escape means nothing at all.
pub(crate) fn physical_path(layout: &Layout, logical: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = layout.store_dir();
    // How many components deep below the root we are, which is what makes the clamp cheap: a `..`
    // with nothing above it has nowhere to go, and comparing paths would answer the same question
    // more slowly and with more ways to be wrong.
    let mut depth = 0usize;
    for part in logical.components() {
        match part {
            Component::Normal(p) => {
                out.push(p);
                depth += 1;
            }
            Component::ParentDir if depth > 0 => {
                out.pop();
                depth -= 1;
            }
            // A leading `/`, a `.`, a `..` at the top, a Windows prefix: nothing to add and nowhere
            // to go back to.
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;
    use std::os::unix::fs::PermissionsExt;

    /// The completion oracle runs on a keystroke, so it resolves the layout without acting. The
    /// ordinary resolution follows a volume pointer by **mounting** the volume: completing an
    /// argument attached a loop device and mounted a filesystem, which on a udisks setup is a
    /// password prompt for pressing TAB.
    ///
    /// A pointer at an image that is not mounted (here, one that does not exist at all) leaves the
    /// default directory in place and touches nothing.
    #[test]
    fn resolving_without_mounting_follows_a_pointer_no_further_than_reading_it() {
        use crate::testutil::{EnvVar, env_lock};
        let _lock = env_lock();
        let home = TmpDir::new();
        let data = home.path().join("sbx");
        std::fs::create_dir_all(&data).unwrap();
        // A pointer at an image nothing has attached — following it would have to mount.
        let image = home.path().join("volume.btrfs");
        std::fs::write(
            data.join(crate::storage::POINTER),
            format!("image = \"{}\"\n", image.display()),
        )
        .unwrap();

        let _over = EnvVar::unset("SBX_DATA_DIR");
        let _xdg = EnvVar::set("XDG_DATA_HOME", home.path());
        let layout = Layout::from_env_without_mounting().expect("the default directory resolves");
        assert_eq!(
            layout.data_dir(),
            data,
            "an unmounted volume leaves the default directory in place"
        );
        assert!(
            !image.exists(),
            "and nothing was created on the way: the pointer was read, not followed"
        );
    }

    #[test]
    fn layout_derives_store_paths_from_data_dir() {
        let layout = Layout::under(Path::new("/data/sbx"));
        assert_eq!(layout.data_dir.as_path(), Path::new("/data/sbx"));
        assert_eq!(layout.store_dir(), Path::new("/data/sbx/store"));
    }

    #[test]
    fn the_two_notification_marks_are_separate_files() {
        // A notification daemon opens these by path, in another process, so the names are part of
        // what sbx puts on a user's disk rather than an internal detail. Pinned literally: deriving
        // one from the other is how the two fills end up being the same file.
        let layout = Layout::under(Path::new("/data/sbx"));
        assert_eq!(layout.icon_path(false), Path::new("/data/sbx/sbx.png"));
        assert_eq!(layout.icon_path(true), Path::new("/data/sbx/sbx-dark.png"));
    }

    #[test]
    fn data_dir_prefers_absolute_xdg_else_falls_back_to_home() {
        assert_eq!(
            data_dir_from(None, Some(OsStr::new("/xdg")), Some(OsStr::new("/home/u"))),
            Some(PathBuf::from("/xdg/sbx"))
        );
        // a relative XDG_DATA_HOME is ignored; HOME is used instead
        assert_eq!(
            data_dir_from(
                None,
                Some(OsStr::new("rel/xdg")),
                Some(OsStr::new("/home/u"))
            ),
            Some(PathBuf::from("/home/u/.local/share/sbx"))
        );
        assert_eq!(
            data_dir_from(None, None, Some(OsStr::new("/home/u"))),
            Some(PathBuf::from("/home/u/.local/share/sbx"))
        );
        assert_eq!(data_dir_from(None, None, None), None);
    }

    #[test]
    fn an_absolute_data_dir_override_wins_verbatim_and_a_relative_one_is_refused() {
        // It outranks both lower sources, and names the directory itself: no `sbx`
        // is appended, unlike the shared XDG base.
        let over = data_dir_from(
            Some(OsStr::new("/vol/data")),
            Some(OsStr::new("/xdg")),
            Some(OsStr::new("/home/u")),
        );
        assert_eq!(over, Some(PathBuf::from("/vol/data")));
        assert_ne!(over, Some(PathBuf::from("/vol/data/sbx")));

        // A relative override is refused outright — crucially it does NOT fall
        // through to a lower source, which would silently use another directory.
        assert_eq!(
            data_dir_from(
                Some(OsStr::new("rel/data")),
                Some(OsStr::new("/xdg")),
                Some(OsStr::new("/home/u"))
            ),
            None
        );

        // Empty reads as absent, so clearing the variable restores the default.
        assert_eq!(
            data_dir_from(
                Some(OsStr::new("")),
                Some(OsStr::new("/xdg")),
                Some(OsStr::new("/home/u"))
            ),
            Some(PathBuf::from("/xdg/sbx"))
        );
    }

    /// The constant is only worth what the real path builders measure against it. The existing
    /// cap tests restate `LONGEST_SOCKET_SUFFIX` and so would pass unchanged if a feature started
    /// binding a wider path — which is how the broker family, the one whose width a user chooses,
    /// went unaccounted for: a data directory `check_data_dir_override` approved would then fail at
    /// `bind` with `sun_path`, saying "socket" for a mistake about a directory.
    #[test]
    fn every_socket_family_fits_the_budget_the_data_dir_cap_reserves() {
        // A data directory exactly at the cap, and the widest pid the kernel hands out.
        let data = PathBuf::from(format!("/{}", "d".repeat(DATA_DIR_MAX - 1)));
        assert_eq!(data.as_os_str().len(), DATA_DIR_MAX);
        let pid = 4_194_304u32; // kernel.pid_max's documented ceiling: 7 digits
        assert_eq!(pid.to_string().len(), 7);

        // The broker family, built by the function a launch actually calls, with the longest name
        // the config layer now admits.
        let name = "b".repeat(crate::store::BROKER_NAME_MAX);
        let broker = data
            .join("broker")
            .join(pid.to_string())
            .join(format!("{name}.sock"));
        assert!(
            broker.as_os_str().len() <= SUN_PATH_MAX,
            "a broker socket at the cap overruns sun_path: {} > {SUN_PATH_MAX} ({})",
            broker.as_os_str().len(),
            broker.display()
        );

        // One character more does not fit, so the cap is the real boundary rather than slack.
        let over = data
            .join("broker")
            .join(pid.to_string())
            .join(format!("{name}b.sock"));
        assert!(
            over.as_os_str().len() > SUN_PATH_MAX,
            "the name cap is looser than sun_path requires"
        );

        // The forward family, the other per-launch subdir, against its widest port.
        let forward = data
            .join("forward")
            .join(format!("fwd-{pid}"))
            .join("p-65535.sock");
        assert!(
            forward.as_os_str().len() <= SUN_PATH_MAX,
            "a forward socket at the cap overruns sun_path: {}",
            forward.as_os_str().len()
        );
    }

    #[test]
    fn a_data_dir_override_too_long_to_host_a_unix_socket_is_refused() {
        // The bound is what is left of `sun_path` once the widest socket name sbx
        // appends is accounted for, so a directory at the limit still works...
        let at_limit = format!("/{}", "d".repeat(DATA_DIR_MAX - 1));
        assert_eq!(at_limit.len(), DATA_DIR_MAX);
        assert!(check_data_dir_override(OsStr::new(&at_limit)).is_ok());

        // ...and one byte more does not. Teeth: the longest socket path that
        // directory would have to carry must actually overrun the kernel's field.
        let over = format!("/{}", "d".repeat(DATA_DIR_MAX));
        assert_eq!(over.len(), DATA_DIR_MAX + 1);
        assert!(over.len() + LONGEST_SOCKET_SUFFIX > SUN_PATH_MAX);
        let why = check_data_dir_override(OsStr::new(&over)).unwrap_err();
        assert!(why.contains("at most"), "{why}");

        // And it is refused, not silently swapped for a lower source.
        assert_eq!(
            data_dir_from(
                Some(OsStr::new(&over)),
                Some(OsStr::new("/xdg")),
                Some(OsStr::new("/home/u"))
            ),
            None
        );
    }

    #[test]
    fn a_derived_data_dir_too_long_for_a_socket_is_caught_but_still_adoptable() {
        // A directory at the limit passes; one byte more overruns the widest socket path.
        let at_limit = PathBuf::from(format!("/{}", "d".repeat(DATA_DIR_MAX - 1)));
        assert_eq!(at_limit.as_os_str().len(), DATA_DIR_MAX);
        assert!(check_resolved_data_dir(&at_limit).is_ok());

        let over = PathBuf::from(format!("/{}", "d".repeat(DATA_DIR_MAX)));
        assert_eq!(over.as_os_str().len(), DATA_DIR_MAX + 1);
        assert!(over.as_os_str().len() + LONGEST_SOCKET_SUFFIX > SUN_PATH_MAX);
        let why = check_resolved_data_dir(&over).unwrap_err();
        assert!(why.contains("at most"), "{why}");
        assert!(why.contains("SBX_DATA_DIR"), "names the remedy: {why}");

        // The derivation itself does NOT drop a long `$HOME` — `data_dir_from` still returns it,
        // so `sbx storage` (which anchors to that path, not the guarded resolution) can create
        // the image and adopt a volume whose short mount point then passes the guard.
        let long_home = "/".to_string() + &"h".repeat(DATA_DIR_MAX);
        let derived = data_dir_from(None, None, Some(OsStr::new(&long_home)))
            .expect("a long derived home still resolves to a path storage can adopt from");
        assert!(check_resolved_data_dir(&derived).is_err());
    }

    #[test]
    fn ensure_creates_dirs_owner_only_and_is_idempotent() {
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));

        ensure(&layout).unwrap();
        for dir in [layout.data_dir.clone(), layout.store_dir()] {
            assert!(dir.is_dir(), "{} should exist", dir.display());
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} should be owner-only", dir.display());
        }
        // idempotent: a second call succeeds and leaves perms owner-only
        ensure(&layout).unwrap();
        let mode = std::fs::metadata(layout.store_dir())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn ensure_tightens_a_preexisting_loose_store_root() {
        let base = TmpDir::new();
        let data = base.join("sbx");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o777)).unwrap();

        ensure(&Layout::under(&data)).unwrap();
        let mode = std::fs::metadata(&data).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "loose perms must be tightened");
    }

    #[test]
    fn physical_path_maps_a_logical_store_path_under_the_store_root() {
        let layout = Layout::under(Path::new("/data/sbx"));
        assert_eq!(
            physical_path(&layout, Path::new("/nix/store/abc-hello")),
            PathBuf::from("/data/sbx/store/nix/store/abc-hello")
        );
        assert_eq!(
            physical_path(&layout, Path::new("/nix")),
            PathBuf::from("/data/sbx/store/nix")
        );
    }

    /// Whatever the logical path says, the physical one is under the store root.
    ///
    /// Eight of this function's callers are bind sources, so a result outside the store is a mount
    /// of something the store never held. A `..` that stays inside keeps its meaning; one that
    /// would step above the root is dropped, because the store root is the root on this side.
    #[test]
    fn physical_path_cannot_be_walked_out_of_the_store() {
        let layout = Layout::under(Path::new("/data/sbx"));
        let root = layout.store_dir();
        for (logical, want) in [
            // An escape, in the two shapes a store path could carry one.
            ("/../../etc/passwd", "/data/sbx/store/etc/passwd"),
            (
                "/nix/store/../../../etc/passwd",
                "/data/sbx/store/etc/passwd",
            ),
            // A `..` that stays inside still means what it says.
            ("/nix/store/x/../y", "/data/sbx/store/nix/store/y"),
            // The no-op components.
            ("/nix/./store/abc", "/data/sbx/store/nix/store/abc"),
            ("..", "/data/sbx/store"),
            ("/", "/data/sbx/store"),
        ] {
            let got = physical_path(&layout, Path::new(logical));
            assert_eq!(got, PathBuf::from(want), "{logical}");
            assert!(got.starts_with(&root), "{logical} left the store: {got:?}");
        }
    }
}
