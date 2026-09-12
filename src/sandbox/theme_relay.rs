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
//! **Under WSL the source is not a bus.** The desktop whose preference this mirrors runs on the
//! Windows side, which owns no portal and emits no signal a Linux subscriber can hear. It does
//! notify, though: `RegNotifyChangeKeyValue` blocks until the theme value is written and returns
//! within milliseconds of it, so the relay follows Windows through one long-lived interop process
//! whose output it reads ([`WATCH_SCRIPT`]) rather than by asking again on a timer. Which source a
//! launch follows is decided the way the seed decides it ([`read_host_color_scheme`]): the portal
//! when it answers, Windows when it does not and the kernel is a WSL one.
//!
//! Lifecycle mirrors [`super::notify_relay`]: [`ThemeRelay::start`] spawns a dedicated thread driving
//! the async work with `async_io::block_on` (no tokio); the guard's `Drop` closes a shutdown channel
//! and joins the thread. The WSL body waits on a pipe instead of that channel, so `Drop` also ends
//! the watcher process, which is what closes the pipe. That watcher is started only after
//! [`WATCH_START_DELAY`], because starting it competes with the launch it runs alongside, and a
//! cage can end before the delay elapses: [`WatchSlot`] is what carries the stop across that
//! window, so the process is killed whichever of the two arrives first.

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
    if let Some(from_portal) = portal_color_scheme() {
        return Some(from_portal);
    }
    // No portal answered. Under WSL that is the normal case rather than a failure — the desktop
    // whose preference this is runs on the Windows side, which answers through a registry value
    // instead of a bus name — so the same question is asked there. Everywhere else this is where
    // the read gives up, exactly as before: the branch is gated on the kernel being a WSL one, so a
    // Linux host with no portal reaches no process spawn it did not reach yesterday.
    windows_fallback(host_is_wsl(), read_windows_color_scheme)
}

/// The bounded portal read on its own, because the relay must ask the **same** question the seed
/// asked before choosing what to follow.
///
/// A launch that seeded from the portal has a portal to subscribe to; one that seeded from Windows
/// does not, and following the other source would correct the cage to a value read a second way.
/// Sharing the read is what keeps the seed and the relay on one interpretation.
fn portal_color_scheme() -> Option<String> {
    async_io::block_on(async {
        futures_util::select! {
            scheme = current_color_scheme().fuse() => scheme,
            // `Timer` is both a `Future` and a `Stream`, so name the trait rather than let
            // `.fuse()` resolve to the stream one.
            _ = FutureExt::fuse(async_io::Timer::after(READ_TIMEOUT)) => None,
        }
    })
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
/// This serves the launch seed alone: one question, one answer. A **later** switch is followed by
/// the relay, which under WSL watches the same value through [`WATCH_SCRIPT`] instead of asking
/// again — Windows notifies on a write to the key, so following it costs one long-lived process
/// and no repeated round-trip.
fn read_windows_color_scheme() -> Option<String> {
    // Interop is still a program looked up on `PATH`, so it goes through the search that reads
    // absolute entries only — an empty element resolves from the current directory, which here is
    // the project tree the cage writes — and that weighs each match's owner and mode. `None` leaves
    // the cage on the default theme, this function's existing answer for a host with no registry.
    let reg = crate::store::find_trusted_on_path("reg.exe")?;
    let mut child = std::process::Command::new(reg)
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

// The predicate moved to `super::wsl`, which three subjects now share. Re-exported here because
// `notify_sink` still names it through this module; point that call site at `wsl::host_is_wsl` and
// this line goes away.
pub(crate) use super::wsl::host_is_wsl;

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

/// How long the relay waits before starting the Windows-side watcher, on WSL only.
///
/// Starting it costs the launch it runs alongside, and the cost is not the spawn: a `spawn` of a
/// Windows program returns in tens of milliseconds, but the program it starts then runs on the
/// Windows side of the same machine. A `powershell.exe` that prints nothing takes about two
/// seconds of wall time for no measurable CPU on the Linux side, because the work is a .NET
/// startup happening beyond that boundary, and under WSL that boundary is inside the same host.
/// Measured on a two-CPU virtual machine, a cage launch with `dbus = true` went from about 2.5
/// seconds to about 4.5 when the watcher started with it, and stripping the interop entries out
/// of `PATH` restored it exactly.
///
/// The wait is the remedy because the watcher's work is **independent of the launch**. It only
/// has to be running soon, not now: what it exists to catch is a theme switch made while an app
/// is open, and a switch inside the first seconds of a cage's life is not worth charging every
/// launch for. The value clears a `gui` + `dbus` launch on the machine it was sized against
/// (setup measured at 2.5 to 4 seconds there) with room to spare; re-measure before changing it,
/// and re-measure the launch itself, since that is what it is sized against.
///
/// It is not a configuration field: a value nobody can size without the measurement above is
/// surface without a user.
const WATCH_START_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

/// The Windows-side watcher the relay runs under WSL: block until the theme value is written, print
/// what it became, repeat. Handed to `powershell.exe` as a single `-Command` argument, the way the
/// toast sink hands it one, so no shell parses it on the way.
///
/// `RegNotifyChangeKeyValue` with `fAsynchronous = false` **blocks** its caller until the key is
/// written. That is what makes this a notification and not a poll: between two switches the process
/// waits in the kernel and costs nothing, and it returns within milliseconds of the write. It is
/// the only Win32 call here, reached through `Add-Type` because PowerShell binds no wrapper for it.
///
/// Each change is printed in the shape `reg.exe query` prints, so a watcher line and a seed read go
/// through [`windows_scheme_name`] — the one place the inverted scales are reconciled. Printing any
/// other shape would put that mapping in two places, which is how a cage ends up opening in one
/// theme and being corrected into the opposite one.
const WATCH_SCRIPT: &str = r#"$sig = @'
[DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern int RegOpenKeyExW(IntPtr hKey, string subKey, int opts, int sam, out IntPtr res);
[DllImport("advapi32.dll", SetLastError=true)]
public static extern int RegNotifyChangeKeyValue(IntPtr hKey, bool subtree, int filter, IntPtr hEvent, bool async);
'@
$api = Add-Type -MemberDefinition $sig -Name SbxRegWatch -Namespace Sbx -PassThru
$key = 'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
$h = [IntPtr]::Zero
if ($api::RegOpenKeyExW([IntPtr]::new(-2147483647), $key, 0, 0x10, [ref]$h) -ne 0) { exit 1 }
while ($true) {
  if ($api::RegNotifyChangeKeyValue($h, $false, 0x4, [IntPtr]::Zero, $false) -ne 0) { exit 1 }
  $v = (Get-ItemProperty -Path ('HKCU:\' + $key) -Name AppsUseLightTheme -EA SilentlyContinue).AppsUseLightTheme
  if ($null -ne $v) {
    [Console]::Out.WriteLine('    AppsUseLightTheme    REG_DWORD    0x' + ('{0:x}' -f [int]$v))
    [Console]::Out.Flush()
  }
}"#;

/// Whether this relay follows Windows rather than a host bus, from the two facts that decide it.
///
/// Pure, and named for the reason [`windows_fallback`] is: what matters is the process that does
/// **not** start off WSL, and an absence is only provable against a decision that can be asked
/// without a bus or a registry to stand up first.
fn relay_follows_windows(portal_answered: bool, is_wsl: bool) -> bool {
    !portal_answered && is_wsl
}

/// Whether a watcher that has just started may be published into the shared slot, or must be
/// killed on the spot.
///
/// Pure and named for the reason [`relay_follows_windows`] is: the case worth asserting is the one
/// that is hard to reach on purpose — the relay ended while the thread was waiting out its delay,
/// so the process it then starts belongs to a cage that is gone. A thread that published it anyway
/// would go on to read a pipe nothing will close, and the `join` in [`ThemeRelay::drop`] would wait
/// on that read for as long as the process lived.
fn may_publish(stopping: bool) -> bool {
    !stopping
}

/// Start the Windows-side watcher, or `None` on a host with no interop to start it with.
///
/// Same `PATH` posture as [`read_windows_color_scheme`]: interop is a program lookup like any
/// other, so it takes the search that refuses a relative entry and weighs each match's owner and
/// mode, rather than running whatever `powershell.exe` the `PATH` happens to reach first.
fn spawn_windows_watcher() -> Option<std::process::Child> {
    let powershell = crate::store::find_trusted_on_path("powershell.exe")?;
    std::process::Command::new(powershell)
        .args(["-NoProfile", "-Command", WATCH_SCRIPT])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()
}

/// Mirror each watcher line into the in-cage keyfile, until the watcher's output ends.
///
/// Blocking rather than async, and deliberately: this loop's only wait is the pipe, and what ends
/// it is [`ThemeRelay::drop`] killing the watcher — which closes the pipe and ends the read. A
/// shutdown channel to select against would duplicate a stop the kill already performs.
///
/// A line that does not parse is skipped rather than ending the loop: the watcher prints one shape,
/// but a PowerShell that wrote anything else to its output would otherwise cost the rest of the
/// session's changes over a line that costs nothing to ignore.
fn run_windows_watch(home: &Path, stdout: std::process::ChildStdout) {
    use std::io::BufRead;
    for line in std::io::BufReader::new(stdout)
        .lines()
        .map_while(Result::ok)
    {
        if let Some(scheme) = windows_scheme_name(&line) {
            write_keyfile(home, scheme);
        }
    }
}

/// The relay thread's body: follow the source the seed followed.
///
/// Split from [`ThemeRelay::start`] so the thread closure stays one call, and because the two
/// sources fail differently — a bus that goes away is a teardown race worth swallowing, while a
/// watcher that will not start is a capability this launch loses and says so once.
fn run_relay(
    home: PathBuf,
    shutdown: async_channel::Receiver<()>,
    watcher: &std::sync::Mutex<WatchSlot>,
) {
    if !relay_follows_windows(portal_color_scheme().is_some(), host_is_wsl()) {
        if let Err(e) = async_io::block_on(run_portal(home, shutdown)) {
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
        return;
    }
    // The wait is on the shutdown channel rather than the clock, because a cage can end before it
    // elapses: a short command finishes in milliseconds, `Drop` runs while this thread is still
    // waiting, and a sleep would wake to start a watcher for a cage that no longer exists. Waiting
    // on the channel makes an early end of the launch the other way out of the delay. A closed
    // channel returns immediately, which is that same case seen one moment later.
    let ended = async_io::block_on(async {
        futures_util::select! {
            _ = shutdown.recv().fuse() => true,
            _ = FutureExt::fuse(async_io::Timer::after(WATCH_START_DELAY)) => false,
        }
    });
    if ended {
        return;
    }
    let Some(mut child) = spawn_windows_watcher() else {
        diag::warn(
            "`dbus = true`: no interop to watch the Windows theme with — the app keeps its \
             at-launch theme",
        );
        return;
    };
    // Take the pipe before the process is handed over: the reader holds one end while `Drop` holds
    // the process, and those are the two halves of the same stop.
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return;
    };
    // Publishing the child and reading `stopping` under one lock is what closes the window between
    // them. `Drop` can still arrive between the wait above and this line; it then leaves `stopping`
    // set and finds no child to kill, so the child born a moment later is killed here instead. The
    // reverse order has `Drop` kill it. Without the flag this thread would go on to read a pipe
    // nothing will ever close, and the `join` in `Drop` would wait on it forever.
    match watcher.lock() {
        Ok(mut slot) if may_publish(slot.stopping) => slot.child = Some(child),
        _ => {
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
    }
    run_windows_watch(&home, stdout);
}

/// What [`ThemeRelay`] and its thread share about the Windows-side watcher: the process once it
/// exists, and whether the relay has been told to stop.
///
/// Both under one lock, because the two facts are only useful together. The watcher is started
/// after a delay, so there is a window in which the relay has ended and the process it would own
/// does not exist yet; a slot holding only the process cannot express that, and the thread would
/// start a watcher for a cage that is gone and then block reading it forever.
#[derive(Default)]
struct WatchSlot {
    /// Set by [`ThemeRelay::drop`]. A thread that finds it set kills whatever it just started
    /// instead of publishing it.
    stopping: bool,
    /// The watcher, once started and published. `None` before that, and on a host that follows the
    /// bus instead.
    child: Option<std::process::Child>,
}

/// A running theme relay: the shutdown channel signalling its thread to stop, and the thread handle.
/// Dropping it closes the channel (breaking the relay's loop) and joins the thread.
pub(crate) struct ThemeRelay {
    shutdown: async_channel::Sender<()>,
    handle: Option<JoinHandle<()>>,
    /// The Windows-side watcher, on a launch that follows Windows rather than a bus. Held because
    /// its reader waits on a pipe that no channel reaches: ending the process is what closes the
    /// pipe, so `Drop` needs the process itself. Untouched on every other host.
    watcher: std::sync::Arc<std::sync::Mutex<WatchSlot>>,
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
        let watcher = std::sync::Arc::new(std::sync::Mutex::new(WatchSlot::default()));
        let theirs = std::sync::Arc::clone(&watcher);
        let handle = std::thread::Builder::new()
            .name("sbx-theme-relay".to_string())
            .spawn(move || run_relay(home, rx, &theirs))
            .ok();
        ThemeRelay {
            shutdown,
            handle,
            watcher,
        }
    }
}

impl Drop for ThemeRelay {
    fn drop(&mut self) {
        self.shutdown.close();
        // The two bodies wait on different things, so both are ended here: the bus loop selects on
        // the channel above, while the WSL loop is blocked reading the watcher's pipe and only
        // the watcher's death closes it. Killing first, then joining, is what keeps the join from
        // waiting on a read that nothing would ever end.
        if let Ok(mut slot) = self.watcher.lock() {
            // The flag first, and it matters even when there is a child to kill: the thread may be
            // between its wait and publishing one, and this is what tells it not to.
            slot.stopping = true;
            if let Some(child) = slot.child.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// The bus body: connect to the host session bus, subscribe to the appearance color-scheme signal,
/// and mirror each change into the in-cage keyfile until shutdown. The source every host but WSL
/// follows, and WSL too when a portal answers there.
async fn run_portal(
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

    /// The gate decides whether an interop process starts, so it is asserted on all four
    /// combinations rather than the one that happens to hold here: the case that matters is the
    /// process that must NOT start off WSL, and that is only provable by naming it.
    #[test]
    fn only_a_wsl_host_whose_portal_stayed_silent_follows_windows() {
        assert!(
            super::relay_follows_windows(false, true),
            "a WSL host with no portal has Windows as its only source"
        );
        assert!(
            !super::relay_follows_windows(true, true),
            "a WSL host whose portal answered is followed on the bus, so the seed and the relay \
             read the same source"
        );
        assert!(
            !super::relay_follows_windows(false, false),
            "a Linux host with no portal starts no interop process — there is none to start"
        );
        assert!(!super::relay_follows_windows(true, false));
    }

    /// The watcher and the launch seed feed the SAME parser, which is the one place the inverted
    /// scales are reconciled. This pins that contract from both ends: the shape the script prints,
    /// and the parser reading it. Changing the script's output format fails here rather than in a
    /// cage that silently stops following the theme.
    #[test]
    fn the_watcher_prints_the_shape_the_seed_parser_reads() {
        assert!(
            super::WATCH_SCRIPT.contains("'    AppsUseLightTheme    REG_DWORD    0x'"),
            "the watcher must print a `reg.exe query` line, not a shape of its own"
        );
        assert_eq!(
            super::windows_scheme_name("    AppsUseLightTheme    REG_DWORD    0x0"),
            Some("prefer-dark"),
            "a single watcher line parses like the multi-line read it imitates"
        );
        assert_eq!(
            super::windows_scheme_name("    AppsUseLightTheme    REG_DWORD    0x1"),
            Some("prefer-light")
        );
    }

    /// `RegNotifyChangeKeyValue`'s last argument is what separates a notification from a poll: with
    /// `fAsynchronous` true the call returns at once and the loop would spin. It is asserted here
    /// because the difference is invisible in a review of the script's shape.
    #[test]
    fn the_watcher_blocks_rather_than_spinning() {
        assert!(
            super::WATCH_SCRIPT.contains("$false, 0x4, [IntPtr]::Zero, $false"),
            "the notify call must be synchronous (fAsynchronous = $false) and filtered on \
             REG_NOTIFY_CHANGE_LAST_SET"
        );
    }

    /// The window the delay opens: a cage can end before the watcher is started, and then the
    /// process must not be adopted. Both orders are asserted because only one of them is the one
    /// that used to hang, and a test that covered the easy order would have passed on the defect.
    #[test]
    fn a_relay_that_ended_first_refuses_the_watcher_started_after_it() {
        let slot = std::sync::Mutex::new(super::WatchSlot::default());

        // The ordinary order: the thread publishes, and `Drop` later finds the process to kill.
        {
            let guard = slot.lock().unwrap();
            assert!(
                super::may_publish(guard.stopping),
                "a live relay adopts the watcher it started"
            );
        }

        // The order that hung: `Drop` ran during the delay, found no child, and set the flag. The
        // thread wakes afterwards and must kill what it started rather than read it forever.
        slot.lock().unwrap().stopping = true;
        let guard = slot.lock().unwrap();
        assert!(
            !super::may_publish(guard.stopping),
            "a relay that already ended must not adopt a watcher started after it"
        );
        assert!(
            guard.child.is_none(),
            "and `Drop` had nothing to kill, which is exactly why the flag has to carry the stop"
        );
    }
}
