//! The network-namespace holder: gives an isolated cage a black-hole `dummy0` interface so an
//! in-cage graphical app reports itself *online*.
//!
//! ## Why
//!
//! Under a filtering network posture the cage runs in an empty network namespace (loopback only) —
//! its sole egress is the forwarder-to-proxy path on `127.0.0.1`. But Chromium/Electron decide
//! `navigator.onLine` from the *presence of a non-loopback interface*, not from actual reachability:
//! a loopback-only namespace reads as "no network", so a graphical agent panel freezes on
//! "No internet — wait for reconnection" even though egress works perfectly through the proxy.
//! Adding one dummy interface (a kernel black hole: no peer, no route, drops everything) flips
//! `navigator.onLine` to true without opening any egress — a direct connect still has no route and
//! fails closed, and all real traffic still goes through the proxy on loopback.
//!
//! ## How
//!
//! bwrap can only *create* an empty namespace (`--unshare-net`); it cannot join a pre-configured
//! one, and the cage is cap-dropped so it could never add an interface itself. So a tiny holder
//! runs first, as its own `__netns-holder` subcommand (host-side, never in the cage):
//!
//! 1. `unshare(CLONE_NEWUSER)` and map our uid/gid to root inside it — now we hold `CAP_NET_ADMIN`.
//! 2. `unshare(CLONE_NEWNET)` — a fresh network namespace owned by that user namespace.
//! 3. bring up `lo` and add `dummy0` (best-effort — any failure degrades to a loopback-only
//!    namespace, i.e. exactly what `--unshare-net` would have produced).
//! 4. `execve` the real command (`bwrap …`). Namespaces survive `execve`; bwrap then makes its own
//!    *nested* user namespace (same-uid, via `--uid`/`--gid`) and inherits this network namespace,
//!    dummy included. The cage stays cap-dropped, non-root, and same-uid at the host level.

use super::spec::NetnsDummy;
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The dummy interface's address. A private, non-routable /24 that installs only a connected route
/// for its own subnet (no default route), so it can never become an egress path — a cage connect to
/// any real host still finds no route and fails closed, exactly as in a loopback-only namespace.
const DUMMY_ADDR: &str = "10.11.12.13/24";

/// Wrap a bwrap invocation so it runs behind the netns holder, when `dummy` is set. Returns the
/// program to spawn and its argument list; with `None` it is the unchanged `(bwrap, argv)`, so the
/// ordinary launch path is byte-for-byte identical. The result is what the cgroup scope wrapper
/// then splices, giving `systemd-run --scope -- <sbx> __netns-holder <bwrap> <argv…>`.
pub(crate) fn holder_wrap(
    bwrap: &Path,
    bwrap_argv: Vec<OsString>,
    dummy: Option<&NetnsDummy>,
) -> (PathBuf, Vec<OsString>) {
    match dummy {
        None => (bwrap.to_path_buf(), bwrap_argv),
        Some(nd) => {
            let mut argv = Vec::with_capacity(bwrap_argv.len() + 2);
            argv.push(OsString::from("__netns-holder"));
            argv.push(bwrap.as_os_str().to_owned());
            argv.extend(bwrap_argv);
            (nd.holder_exe.clone(), argv)
        }
    }
}

/// The `__netns-holder` subcommand body. `argv` is `[bwrap, bwrap-args…]`. Sets up the user and
/// network namespaces, adds the dummy interface, then `execve`s the command. Never returns: it
/// either becomes the command or exits non-zero with a diagnostic.
pub(crate) fn run_holder(argv: &[OsString]) -> ! {
    if argv.is_empty() {
        die("__netns-holder: no command to exec");
    }

    // Capture the host credentials before entering the user namespace (afterwards we are the
    // namespace's overflow uid until the map is written).
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // A new user namespace, then map our real uid/gid to root inside it — the single-uid self-map
    // an unprivileged process is allowed to write. This gives us CAP_NET_ADMIN over the network
    // namespace created next. `setgroups` must be denied before `gid_map` (a kernel requirement for
    // an unprivileged user namespace).
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        die(&format!(
            "__netns-holder: unshare(CLONE_NEWUSER): {}",
            std::io::Error::last_os_error()
        ));
    }
    let _ = std::fs::write("/proc/self/setgroups", "deny");
    if let Err(e) = std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")) {
        die(&format!("__netns-holder: write uid_map: {e}"));
    }
    if let Err(e) = std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")) {
        die(&format!("__netns-holder: write gid_map: {e}"));
    }

    // A fresh, empty network namespace owned by that user namespace.
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
        die(&format!(
            "__netns-holder: unshare(CLONE_NEWNET): {}",
            std::io::Error::last_os_error()
        ));
    }

    // Best-effort: loopback up + the black-hole dummy. A failure here (e.g. the `dummy` kernel
    // module is unavailable) leaves a loopback-only namespace — the cage still launches, just
    // without the online signal — so it is never fatal.
    configure_dummy();

    // Become the command. `execve` preserves both namespaces; bwrap makes its own nested user
    // namespace and inherits this network namespace, dummy included.
    let prog = to_cstring(&argv[0]);
    let cargs: Vec<CString> = argv.iter().map(to_cstring).collect();
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    unsafe {
        libc::execv(prog.as_ptr(), ptrs.as_ptr());
    }
    die(&format!(
        "__netns-holder: execv {:?}: {}",
        argv[0],
        std::io::Error::last_os_error()
    ));
}

/// Bring up loopback and add the black-hole `dummy0` interface. Best-effort throughout.
// TODO(hardening): replace the `ip` invocations with direct rtnetlink so the holder does not depend
// on a host `ip` binary (sbx is otherwise self-contained). The mechanism is identical either way.
fn configure_dummy() {
    let Some(ip) = find_ip() else {
        return;
    };
    let run = |args: &[&str]| {
        let _ = Command::new(&ip).args(args).status();
    };
    run(&["link", "set", "lo", "up"]);
    run(&["link", "add", "dummy0", "type", "dummy"]);
    run(&["addr", "add", DUMMY_ADDR, "dev", "dummy0"]);
    run(&["link", "set", "dummy0", "up"]);
}

/// Locate the host `ip` tool. It lives in `sbin` on most systems, which a user PATH often omits, so
/// the usual absolute locations are tried before falling back to a PATH search.
fn find_ip() -> Option<PathBuf> {
    for cand in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        let p = Path::new(cand);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    crate::pathfind::find_on_path("ip")
}

fn to_cstring(s: &OsString) -> CString {
    CString::new(s.as_bytes()).unwrap_or_else(|_| {
        die(&format!(
            "__netns-holder: argument contains a NUL byte: {s:?}"
        ))
    })
}

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(127);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holder_wrap_is_a_byte_for_byte_passthrough_without_a_dummy() {
        let argv = vec![OsString::from("--unshare-net"), OsString::from("--")];
        let (prog, out) = holder_wrap(Path::new("/usr/bin/bwrap"), argv.clone(), None);
        assert_eq!(prog, PathBuf::from("/usr/bin/bwrap"));
        assert_eq!(out, argv);
    }

    #[test]
    fn holder_wrap_prepends_the_subcommand_and_the_bwrap_path() {
        let nd = NetnsDummy {
            uid: 1000,
            gid: 1000,
            holder_exe: PathBuf::from("/opt/sbx"),
        };
        let (prog, out) = holder_wrap(
            Path::new("/usr/bin/bwrap"),
            vec![OsString::from("--cap-drop"), OsString::from("ALL")],
            Some(&nd),
        );
        // The program becomes sbx itself, invoked as `__netns-holder <bwrap> <args…>`.
        assert_eq!(prog, PathBuf::from("/opt/sbx"));
        assert_eq!(
            out,
            vec![
                OsString::from("__netns-holder"),
                OsString::from("/usr/bin/bwrap"),
                OsString::from("--cap-drop"),
                OsString::from("ALL"),
            ]
        );
    }
}
