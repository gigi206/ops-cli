//! The in-cage live-theme relay (`dbus = true`).
//!
//! The in-cage portal ([`super::portal`]) seeds the host light/dark theme into the cage **once** at
//! launch (so the app opens in the right scheme), but does not follow a host theme switch made
//! afterwards. This relay closes that gap. It runs **host-side** (sbx's own trusted infrastructure,
//! like the notifications relay and the egress proxy), connects to the real host session bus,
//! subscribes to the desktop portal's `org.freedesktop.portal.Settings.SettingChanged` signal for
//! the `org.freedesktop.appearance` `color-scheme` key, and on each change **rewrites the in-cage
//! GSettings keyfile** through the home bind. The keyfile carries both surface keys
//! ([`super::portal::keyfile_body`]):
//! `color-scheme`, which the in-cage portal re-emits so the Chromium/Electron **app** follows the new
//! scheme live; and `gtk-theme`, which GTK3 watches through the same keyfile backend so the **file
//! dialog** rendered by `xdg-desktop-portal-gtk` re-themes itself live.
//!
//! It adds no capability: the values written are only a light/dark preference and its matching GTK
//! theme name, into the app's own isolated home; the relay reads one host setting and touches no
//! other bus service. Best-effort
//! throughout — no host session bus, no host portal, or a home that cannot be written simply leaves
//! the app on its at-launch theme (the seed), never blocking the launch.
//!
//! Lifecycle mirrors [`super::notify_relay`]: [`ThemeRelay::start`] spawns a dedicated thread driving
//! the async work with `async_io::block_on` (no tokio); the guard's `Drop` closes a shutdown channel
//! and joins the thread.

use crate::diag;
use futures_util::{FutureExt, StreamExt};
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use zbus::proxy;
use zbus::zvariant::Value;

/// Client proxy onto the **host** desktop portal's Settings interface, for the appearance
/// `color-scheme` `SettingChanged` signal.
#[proxy(
    interface = "org.freedesktop.portal.Settings",
    default_service = "org.freedesktop.portal.Desktop",
    default_path = "/org/freedesktop/portal/desktop"
)]
pub(crate) trait HostSettings {
    /// The current value of one setting. Used for the at-launch read; the signal below carries
    /// every later change.
    fn read(&self, namespace: &str, key: &str) -> zbus::Result<zbus::zvariant::OwnedValue>;

    #[zbus(signal)]
    fn setting_changed(
        &self,
        namespace: String,
        key: String,
        value: zbus::zvariant::OwnedValue,
    ) -> zbus::Result<()>;
}

/// How long the at-launch read waits on the host portal before giving up. It runs on the launch
/// path, so an unresponsive portal must cost a bounded pause and not the D-Bus default (tens of
/// seconds) — the price of giving up is the app opening in its default theme, not a failed launch.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Read the host's current light/dark preference, for seeding the cage's theme at launch. Returns
/// the GSettings keyfile value (`prefer-dark`/`prefer-light`/`default`), or `None` when there is no
/// session bus, no desktop portal, or the reply carries no `uint32` — in which case the app opens
/// in its default theme.
///
/// Deliberately the same D-Bus client, proxy and value unwrapping the relay uses for the change
/// signal: the value read once at launch and the values mirrored afterwards must be the same
/// setting read the same way, or the app would open on one interpretation and switch to another.
pub(crate) fn read_host_color_scheme() -> Option<String> {
    let from_portal = async_io::block_on(async {
        futures_util::select! {
            scheme = current_color_scheme().fuse() => scheme,
            // `Timer` is both a `Future` and a `Stream`, so name the trait rather than let
            // `.fuse()` resolve to the stream one.
            _ = FutureExt::fuse(async_io::Timer::after(READ_TIMEOUT)) => None,
        }
    });
    if from_portal.is_some() {
        return from_portal;
    }
    // No portal answered. Under WSL that is the normal case rather than a failure — the desktop
    // whose preference this is runs on the Windows side, which answers through a registry value
    // instead of a bus name — so the same question is asked there. Everywhere else this is where
    // the read gives up, exactly as before: the branch is gated on the kernel being a WSL one, so a
    // Linux host with no portal reaches no process spawn it did not reach yesterday.
    windows_fallback(host_is_wsl(), read_windows_color_scheme)
}

/// The fallback itself, with its gate and its reader passed in so both halves are testable: the
/// point of the gate is a spawn that does **not** happen off WSL, and an absence is only provable
/// against a reader that would have recorded being called.
fn windows_fallback(is_wsl: bool, read: impl FnOnce() -> Option<String>) -> Option<String> {
    if !is_wsl {
        return None;
    }
    read()
}

/// Ask Windows for its apps light/dark preference, through the interop `reg.exe`. Best-effort and
/// bounded: a launch must not hang on it, and the price of giving up is the cage opening in its
/// default theme.
///
/// Bounded the way the install step is, by polling for exit against a deadline and killing what
/// outlives it, because an interop call crosses into another operating system and there is nothing
/// on this side that promises it returns. The budget is the portal read's, so a host that answers
/// through neither channel costs one launch the same wait twice rather than an unbounded one.
///
/// This serves the launch seed alone. The relay that mirrors a **later** switch stays on the bus
/// signal it subscribes to, and WSL offers no such signal: following live here would mean polling
/// Windows, which is an interop round-trip per poll for a value that changes twice a day. A cage
/// therefore opens in the desktop's theme and keeps it for the session.
fn read_windows_color_scheme() -> Option<String> {
    let mut child = std::process::Command::new("reg.exe")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            "/v",
            "AppsUseLightTheme",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + READ_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(_) => return None,
        }
    }
    let out = child.wait_with_output().ok()?;
    windows_scheme_name(&String::from_utf8_lossy(out.stdout.as_slice())).map(str::to_string)
}

/// Whether this kernel is a WSL one, from what `/proc/sys/kernel/osrelease` holds. Pure.
///
/// Microsoft's own marker: a WSL2 kernel names itself `…-microsoft-standard-WSL2`. Read as a
/// substring rather than a suffix because the release carries a version prefix that changes, and
/// case-insensitively because the spelling has changed across WSL generations.
pub(crate) fn is_wsl_release(osrelease: &str) -> bool {
    osrelease.to_ascii_lowercase().contains("microsoft")
}

/// Whether the kernel this launch runs on is a WSL one, read from `/proc/sys/kernel/osrelease`.
/// A file that cannot be read answers `false`, which keeps the fallback shut on a host whose
/// `/proc` is not the one this expects rather than opening it on a guess.
fn host_is_wsl() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .is_ok_and(|release| is_wsl_release(&release))
}

/// The keyfile value a Windows `AppsUseLightTheme` word means, from the line `reg.exe` prints for
/// it. Pure, and the one place the two scales are reconciled.
///
/// They are inverted, which is the whole reason this is a named function with a test of its own:
/// the registry answers *are apps using the light theme*, so `1` is light, while the freedesktop
/// portal answers *which scheme is preferred*, where `1` is [`super::portal::color_scheme_name`]'s
/// `prefer-dark`. Mapping one number onto the other would open every cage in the opposite theme.
/// A missing or unparseable value is `None`: the launch then seeds nothing, which is what it did
/// before this fallback existed.
pub(crate) fn windows_scheme_name(reg_output: &str) -> Option<&'static str> {
    let value = reg_output
        .lines()
        .find(|l| l.contains("AppsUseLightTheme"))?
        .split_whitespace()
        .next_back()?;
    let light = u32::from_str_radix(value.strip_prefix("0x")?, 16).ok()?;
    Some(if light == 0 {
        "prefer-dark"
    } else {
        "prefer-light"
    })
}

/// The read itself: connect to the host session bus, ask its portal for the appearance
/// `color-scheme`, and map the `uint32` to its keyfile value. Every failure is `None` (best-effort).
async fn current_color_scheme() -> Option<String> {
    let conn = zbus::Connection::session().await.ok()?;
    color_scheme_over(&conn).await
}

/// The same read over a connection the caller **already holds**, binding a proxy for the one read.
///
/// For the callers that ask once. A caller that asks repeatedly should bind with
/// [`bind_host_settings`] and keep the proxy: binding is not free next to the read it serves, so
/// re-binding per read is the one shape to avoid.
pub(crate) async fn color_scheme_over(conn: &zbus::Connection) -> Option<String> {
    color_scheme_of(&bind_host_settings(conn).await?).await
}

/// Bind the portal's Settings interface on an existing connection, to be held by a caller that
/// reads the preference more than once — the notification sink asks on every announcement, so that
/// it always signs itself in the theme the desktop is wearing *now* rather than the one it wore
/// when the launch started.
pub(crate) async fn bind_host_settings(
    conn: &zbus::Connection,
) -> Option<HostSettingsProxy<'static>> {
    HostSettingsProxy::new(conn).await.ok()
}

/// The read itself, over an already-bound proxy. Every failure is `None` (best-effort): no portal,
/// no such setting, or a reply carrying something other than the `uint32` the spec defines.
///
/// This is the single place the appearance setting is turned into a value, so the read at launch
/// and the reads during a session cannot end up interpreting it two different ways.
pub(crate) async fn color_scheme_of(settings: &HostSettingsProxy<'_>) -> Option<String> {
    let value = settings
        .read("org.freedesktop.appearance", "color-scheme")
        .await
        .ok()?;
    extract_u32(&value).map(|n| super::portal::color_scheme_name(n).to_string())
}

/// A running theme relay: the shutdown channel signalling its thread to stop, and the thread handle.
/// Dropping it closes the channel (breaking the relay's loop) and joins the thread.
pub(crate) struct ThemeRelay {
    shutdown: async_channel::Sender<()>,
    handle: Option<JoinHandle<()>>,
}

impl ThemeRelay {
    /// Spawn the relay thread. `home` is the **host** path of the project home bound into the cage;
    /// the keyfile it writes is `<home>/<KEYFILE_REL>`, which the cage reads through that bind.
    ///
    /// The home rather than the joined keyfile path, because the split is what [`write_keyfile`]
    /// rests on: everything below `home` is cage-writable and is walked with symlinks refused, and a
    /// caller that handed over an already-joined path would leave nothing to say where the trusted
    /// prefix ends. Infallible — any failure inside the thread warns and leaves the app on its
    /// at-launch theme (best-effort).
    pub(crate) fn start(home: PathBuf) -> ThemeRelay {
        let (shutdown, rx) = async_channel::bounded::<()>(1);
        let handle = std::thread::Builder::new()
            .name("sbx-theme-relay".to_string())
            .spawn(move || {
                if let Err(e) = async_io::block_on(run(home, rx)) {
                    // A connection error is almost always the session ending (the host bus went away)
                    // — a benign teardown race, not worth alarming the user. Only a genuinely
                    // unexpected failure warns.
                    let msg = e.to_string();
                    if !msg.contains("Connection refused")
                        && !msg.contains("Broken pipe")
                        && !msg.contains("reset by peer")
                    {
                        diag::warn(&format!(
                            "`dbus = true`: the live-theme relay stopped ({e}) — the app keeps its \
                             at-launch theme"
                        ));
                    }
                }
            })
            .ok();
        ThemeRelay { shutdown, handle }
    }
}

impl Drop for ThemeRelay {
    fn drop(&mut self) {
        self.shutdown.close();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// The relay body: connect to the host session bus, subscribe to the appearance color-scheme signal,
/// and mirror each change into the in-cage keyfile until shutdown.
async fn run(
    home: PathBuf,
    shutdown: async_channel::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Host session bus (ambient $DBUS_SESSION_BUS_ADDRESS) and a proxy onto its desktop portal.
    let host_conn = zbus::Connection::session().await?;
    let settings = HostSettingsProxy::new(&host_conn).await?;
    let mut changes = settings.receive_setting_changed().await?;
    loop {
        futures_util::select! {
            _ = shutdown.recv().fuse() => break,
            sig = changes.next().fuse() => match sig {
                Some(sig) => {
                    if let Ok(args) = sig.args()
                        && args.namespace == "org.freedesktop.appearance"
                        && args.key == "color-scheme"
                        && let Some(n) = extract_u32(&args.value)
                    {
                        write_keyfile(&home, super::portal::color_scheme_name(n));
                    }
                }
                None => break,
            },
        }
    }
    Ok(())
}

/// Unwrap the `color-scheme` value to its `uint32`, tolerating a nested variant (`v(v(u))`). Pure.
fn extract_u32(value: &Value) -> Option<u32> {
    match value {
        Value::U32(n) => Some(*n),
        Value::Value(inner) => extract_u32(inner),
        _ => None,
    }
}

/// The temp sibling the rewrite lands on before it is renamed into place. Fixed rather than unique:
/// one relay per launch owns this directory chain, and [`write_keyfile`] refuses to reuse an entry
/// that is already there, so a name the cage can predict buys it nothing.
const TMP_NAME: &str = "keyfile.sbx-tmp";

/// Rewrite the in-cage keyfile atomically (temp + rename) with `scheme`'s GSettings body. Atomic so
/// the cage never reads a half-written file; the in-cage GSettings keyfile backend watches the parent
/// directory, so the rename fires its reload. Best-effort — any I/O error is swallowed, leaving the
/// previous theme in place.
///
/// **Every component below `home` is resolved with symlinks refused, and this is the security
/// property of the function rather than a hardening detail.** This write runs host-side, on sbx's own
/// thread and with the user's full privileges, into `<home>/.config/glib-2.0/settings/` — a directory
/// the cage holds **read-write** (`binds::assemble` binds `home_src` at `SANDBOX_HOME`, and the
/// in-cage portal itself does `mkdir -p`/`cat >` there). A path-based write would therefore resolve
/// through whatever the cage last put at each of those four components: `create_dir_all` is satisfied
/// by a symlink to a directory, and `fs::write` follows a symlink at the leaf and truncates its
/// target. That is an arbitrary-file-truncation primitive handed out of the sandbox, against the
/// module header's claim that the relay "adds no capability".
///
/// So the walk starts at `home` — the bind's mount point, which the cage cannot replace — and takes
/// one component at a time through `openat`, each with `O_NOFOLLOW`, ending at a descriptor for the
/// real `settings/` directory. The temp file is created `O_CREAT|O_EXCL|O_NOFOLLOW` relative to that
/// descriptor, so an entry the cage pre-planted is refused rather than followed, and the rename is a
/// `renameat` within the same descriptor. A cage that plants a symlink now costs itself its own live
/// theme updates and nothing else.
fn write_keyfile(home: &Path, scheme: &str) {
    let _ = write_keyfile_confined(home, scheme);
}

/// The fallible body of [`write_keyfile`], split out so every step's error can propagate with `?`
/// while the caller stays best-effort.
fn write_keyfile_confined(home: &Path, scheme: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let (dirs, leaf) = super::portal::KEYFILE_REL
        .rsplit_once('/')
        .expect("KEYFILE_REL names a file inside a directory");

    // The anchor: the project home itself. It is sbx's own directory (created `0700` under the data
    // dir) and it is the cage's mount point, so it is the one component in this path the cage cannot
    // have swapped.
    let mut dir = std::fs::File::open(home).map(OwnedFd::from)?;
    for comp in dirs.split('/') {
        let c = std::ffi::CString::new(comp).map_err(std::io::Error::other)?;
        // Create it if it is missing; an existing entry is fine here, and the `O_NOFOLLOW` open
        // below is what decides whether it is a directory or a link the cage left.
        // SAFETY: `dir` is a live descriptor and `c` is a NUL-terminated name valid for the call.
        unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o700) };
        // SAFETY: same, and the returned descriptor is taken ownership of immediately below.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, owned descriptor this thread just opened.
        dir = unsafe { OwnedFd::from_raw_fd(fd) };
    }

    let tmp = std::ffi::CString::new(TMP_NAME).map_err(std::io::Error::other)?;
    // A leftover temp from a killed run would fail the `O_EXCL` below forever, so clear it first.
    // `unlinkat` removes the entry itself and never follows it, so this cannot reach out of the
    // directory even when what sits there is a symlink the cage planted.
    // SAFETY: `dir` is a live directory descriptor and `tmp` is a valid NUL-terminated name.
    unsafe { libc::unlinkat(dir.as_raw_fd(), tmp.as_ptr(), 0) };
    // SAFETY: same; the descriptor is owned immediately below.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            tmp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, owned descriptor this thread just opened.
    let mut f = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let write = f
        .write_all(super::portal::keyfile_body(scheme).as_bytes())
        .and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = write {
        // SAFETY: `dir` is live and `tmp` is a valid name; the half-written temp is removed.
        unsafe { libc::unlinkat(dir.as_raw_fd(), tmp.as_ptr(), 0) };
        return Err(e);
    }

    let dest = std::ffi::CString::new(leaf).map_err(std::io::Error::other)?;
    // SAFETY: both names are valid and `dir` is a live directory descriptor for both ends.
    let renamed = unsafe {
        libc::renameat(
            dir.as_raw_fd(),
            tmp.as_ptr(),
            dir.as_raw_fd(),
            dest.as_ptr(),
        )
    };
    if renamed < 0 {
        let e = std::io::Error::last_os_error();
        // SAFETY: as above.
        unsafe { libc::unlinkat(dir.as_raw_fd(), tmp.as_ptr(), 0) };
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether this host runs a desktop portal, decided *without* the code under test: ask the bus
    /// daemon who owns the portal's name. So a host with no portal skips, while a host that has one
    /// must produce a scheme — the two cases cannot be confused, which is the whole point (a read
    /// that silently answers `None` everywhere would otherwise look like "no portal here").
    fn host_portal_present() -> bool {
        async_io::block_on(async {
            let Ok(conn) = zbus::Connection::session().await else {
                return false;
            };
            let Ok(dbus) = zbus::fdo::DBusProxy::new(&conn).await else {
                return false;
            };
            matches!(
                dbus.name_has_owner("org.freedesktop.portal.Desktop".try_into().unwrap())
                    .await,
                Ok(true)
            )
        })
    }

    #[test]
    fn the_at_launch_read_returns_the_hosts_scheme_when_a_portal_is_present() {
        // The value seeded into the cage at launch, so the app opens in the host's light/dark
        // scheme instead of its default. Reading it must not depend on executing anything from
        // sbx's store: those binaries name an interpreter under a `/nix` the host need not have, so
        // a read that shells out to one fails on an ordinary host and every launch silently loses
        // the theme.
        if !host_portal_present() {
            skip_incapable!("skipping host theme read: no desktop portal on the session bus");
            return;
        }
        let scheme = read_host_color_scheme();
        assert!(
            matches!(
                scheme.as_deref(),
                Some("prefer-dark" | "prefer-light" | "default")
            ),
            "a host with a desktop portal must yield a scheme, got {scheme:?}"
        );
    }

    #[test]
    fn extract_u32_reads_a_bare_or_nested_variant() {
        assert_eq!(extract_u32(&Value::U32(1)), Some(1));
        // The appearance value can arrive wrapped in an extra variant (`v(v(u))`).
        let nested = Value::Value(Box::new(Value::U32(2)));
        assert_eq!(extract_u32(&nested), Some(2));
        // A non-uint value yields nothing rather than a bogus scheme.
        assert_eq!(extract_u32(&Value::Bool(true)), None);
    }

    #[test]
    fn write_keyfile_writes_the_scheme_body_atomically_and_creates_the_dir() {
        let tmp = crate::testutil::TmpDir::new();
        let home = tmp.path().to_path_buf();
        let keyfile = home.join(super::super::portal::KEYFILE_REL);

        // First write creates the nested parent dirs and the file.
        write_keyfile(&home, super::super::portal::color_scheme_name(1));
        assert_eq!(
            std::fs::read_to_string(&keyfile).unwrap(),
            super::super::portal::keyfile_body("prefer-dark")
        );

        // A second write replaces the content and leaves no temp file behind.
        write_keyfile(&home, super::super::portal::color_scheme_name(2));
        assert_eq!(
            std::fs::read_to_string(&keyfile).unwrap(),
            super::super::portal::keyfile_body("prefer-light")
        );
        assert!(!keyfile.parent().unwrap().join(TMP_NAME).exists());
    }

    /// The relay writes host-side, with the user's privileges, into a directory the cage holds
    /// read-write. So the only thing standing between a cage-planted symlink and an arbitrary host
    /// file being truncated is that this walk refuses to follow one — at the leaf and at every
    /// directory above it. Both are pinned here, against a real file outside the home that must come
    /// back untouched.
    #[test]
    fn a_symlink_planted_under_the_home_is_refused_and_never_written_through() {
        let tmp = crate::testutil::TmpDir::new();
        let home = tmp.path().join("home");
        let outside = tmp.path().join("outside.txt");
        let untouched = "the cage must not be able to truncate this\n";

        let settings = home.join(".config/glib-2.0/settings");

        // 1. A link at the temp name, pointing at a host file. The old path-based `fs::write` opened
        //    it `O_CREAT|O_TRUNC` and followed it, which truncated the target. The temp name is one
        //    this function owns, so the link is *unlinked* rather than followed — which is also how
        //    a temp left behind by a killed run is recovered — and the write then goes on normally.
        std::fs::write(&outside, untouched).unwrap();
        std::fs::create_dir_all(&settings).unwrap();
        std::os::unix::fs::symlink(&outside, settings.join(TMP_NAME)).unwrap();

        write_keyfile(&home, super::super::portal::color_scheme_name(1));

        assert_eq!(
            std::fs::read_to_string(&outside).unwrap(),
            untouched,
            "a link at the temp name was followed out of the home and its target truncated"
        );
        assert_eq!(
            std::fs::read_to_string(home.join(super::super::portal::KEYFILE_REL)).unwrap(),
            super::super::portal::keyfile_body("prefer-dark"),
            "clearing a stale temp must leave the ordinary write working"
        );

        // 2. A link standing in for one of the directories on the way down, pointing at a host
        //    *directory*. This is the shape `create_dir_all` used to accept — it stats through the
        //    link, finds a directory, and reports the parents as made — after which every write
        //    below landed in the host directory. Each component is checked separately, because one
        //    `O_NOFOLLOW` missing from the walk is the whole hole.
        let elsewhere = tmp.path().join("elsewhere");
        for (case, plant) in [
            ("the leaf directory", settings.clone()),
            ("a middle directory", home.join(".config/glib-2.0")),
            ("the first directory", home.join(".config")),
        ] {
            let _ = std::fs::remove_dir_all(&home);
            let _ = std::fs::remove_dir_all(&elsewhere);
            std::fs::create_dir_all(&elsewhere).unwrap();
            std::fs::create_dir_all(plant.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&elsewhere, &plant).unwrap();

            write_keyfile(&home, super::super::portal::color_scheme_name(1));

            assert_eq!(
                std::fs::read_dir(&elsewhere).unwrap().count(),
                0,
                "{case}: the walk went through the link and wrote outside the home"
            );
            assert_eq!(
                std::fs::read_link(&plant).unwrap(),
                elsewhere,
                "{case}: a refused directory link must be left alone, not replaced"
            );
        }
    }

    /// The gate is the whole safety property of the WSL fallback: a host that is not WSL must not
    /// reach the reader at all. Asserted as an absence — the reader records being called, and the
    /// non-WSL arm proves it was not — because "returns None" is satisfied just as well by a reader
    /// that ran, spawned a process that does not exist there, and failed.
    #[test]
    fn only_a_wsl_host_reaches_the_windows_read() {
        let called = std::cell::Cell::new(false);
        let reader = || {
            called.set(true);
            Some("prefer-dark".to_string())
        };
        assert_eq!(super::windows_fallback(false, reader), None);
        assert!(!called.get(), "a host that is not WSL must spawn nothing");

        let called = std::cell::Cell::new(false);
        let reader = || {
            called.set(true);
            Some("prefer-dark".to_string())
        };
        assert_eq!(
            super::windows_fallback(true, reader),
            Some("prefer-dark".to_string())
        );
        assert!(called.get(), "a WSL host asks Windows");
    }

    /// The marker Microsoft writes, and the shapes that are not it.
    #[test]
    fn a_wsl_kernel_is_told_from_an_ordinary_one() {
        assert!(super::is_wsl_release("6.18.33.2-microsoft-standard-WSL2"));
        assert!(super::is_wsl_release("5.15.0-MICROSOFT-standard"));
        assert!(!super::is_wsl_release("6.11.0-19-generic"));
        assert!(!super::is_wsl_release("6.6.87.1-lts"));
    }

    /// The two scales are inverted, so this asserts the NAME rather than the number: reading the
    /// registry's `1` as the portal's `1` would open every cage in the opposite theme, and no
    /// numeric assertion would catch it.
    #[test]
    fn the_registry_word_maps_to_the_opposite_numbered_scheme() {
        let line = |v| format!("\n    AppsUseLightTheme    REG_DWORD    {v}\n");
        assert_eq!(
            super::windows_scheme_name(&line("0x1")),
            Some("prefer-light"),
            "apps use the light theme, which the portal numbers 2"
        );
        assert_eq!(
            super::windows_scheme_name(&line("0x0")),
            Some("prefer-dark"),
            "apps do not use the light theme, which the portal numbers 1"
        );
        // And the same value as the portal's own mapping would name it, so the two cannot drift.
        assert_eq!(
            super::windows_scheme_name(&line("0x0")),
            Some(crate::sandbox::portal::color_scheme_name(1))
        );
        assert_eq!(
            super::windows_scheme_name(&line("0x1")),
            Some(crate::sandbox::portal::color_scheme_name(2))
        );
        assert_eq!(super::windows_scheme_name("nothing here"), None);
        assert_eq!(
            super::windows_scheme_name("    AppsUseLightTheme    REG_DWORD    zzz"),
            None
        );
    }
}
