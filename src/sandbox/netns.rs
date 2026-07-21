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
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The dummy interface's address (octets + prefix length). A private, non-routable /24: assigning it
/// installs only a connected route for its own subnet (no default route), so it can never become an
/// egress path — a cage connect to any real host still finds no route and fails closed, exactly as in
/// a loopback-only namespace.
const DUMMY_OCTETS: [u8; 4] = [10, 11, 12, 13];
const DUMMY_PREFIX: u8 = 24;

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

// Netlink protocol constants (stable Linux UAPI from <linux/netlink.h>, <linux/rtnetlink.h>,
// <linux/if_link.h>, <linux/if_addr.h>). Defined here rather than pulled from `libc`: the wire
// numbers are a frozen kernel ABI, and the attribute-type constants in particular are not uniformly
// exposed across `libc` versions, so a local, self-documenting block is the more auditable choice.
const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_ACK: u16 = 0x004;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLMSG_ERROR: u16 = 0x2;
const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1; // nested inside IFLA_LINKINFO
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

/// The fixed byte length of a `nlmsghdr` (u32 len, u16 type, u16 flags, u32 seq, u32 pid).
const NLMSG_HDR_LEN: usize = 16;
/// The fixed byte length of an `rtattr` header (u16 len, u16 type).
const RTA_HDR_LEN: usize = 4;

/// Bring up loopback and add the black-hole `dummy0` interface, speaking `NETLINK_ROUTE` directly so
/// the holder depends on no host `ip` binary (sbx is otherwise self-contained). Best-effort
/// throughout: the holder runs in the fresh user+net namespace where it holds `CAP_NET_ADMIN`, and
/// any single failure (no netlink socket, the `dummy` kernel module absent) simply leaves a
/// loopback-only namespace — exactly what `--unshare-net` alone would have produced.
fn configure_dummy() {
    let fd = match nl_open() {
        Ok(fd) => fd,
        Err(_) => return,
    };
    // Four independent operations, each ignored on failure (mirrors the degrade-per-step behaviour of
    // the equivalent `ip` commands: lo up, create dummy0, give it the address, dummy0 up).
    if let Some(lo) = if_index("lo") {
        let _ = set_link_up(fd, lo);
    }
    let _ = create_dummy(fd);
    if let Some(idx) = if_index("dummy0") {
        let _ = add_dummy_addr(fd, idx);
        let _ = set_link_up(fd, idx);
    }
    unsafe { libc::close(fd) };
}

/// Open a `NETLINK_ROUTE` socket. `SOCK_CLOEXEC` so it can never leak across the `execve` into bwrap
/// (it is also closed explicitly once configuration is done).
fn nl_open() -> io::Result<libc::c_int> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// The kernel index of an interface by name, or `None` if it does not exist in this namespace.
fn if_index(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (idx != 0).then_some(idx)
}

/// Set an interface's `IFF_UP` flag (an `RTM_NEWLINK` that modifies, not creates — no `NLM_F_CREATE`).
fn set_link_up(fd: libc::c_int, index: u32) -> io::Result<()> {
    let up = libc::IFF_UP as u32;
    nl_request(fd, RTM_NEWLINK, 0, &ifinfomsg(index, up, up))
}

/// Create the `dummy0` interface (`RTM_NEWLINK` with the `dummy` link kind).
fn create_dummy(fd: libc::c_int) -> io::Result<()> {
    nl_request(
        fd,
        RTM_NEWLINK,
        NLM_F_CREATE | NLM_F_EXCL,
        &create_dummy_body(),
    )
}

/// Assign the black-hole address to `dummy0` (`RTM_NEWADDR`). The prefix installs only the connected
/// /24 route; no default route is added, so this never becomes an egress path.
fn add_dummy_addr(fd: libc::c_int, index: u32) -> io::Result<()> {
    nl_request(
        fd,
        RTM_NEWADDR,
        NLM_F_CREATE | NLM_F_EXCL,
        &addr_body(index),
    )
}

// ---- pure wire-format builders (unit-tested) -------------------------------------------------

/// A 16-byte `ifinfomsg` body: family `AF_UNSPEC`, the given interface index, and a flags/change pair
/// (`change` is the mask of which flag bits `flags` applies).
fn ifinfomsg(index: u32, flags: u32, change: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(NLMSG_HDR_LEN);
    b.push(libc::AF_UNSPEC as u8); // ifi_family
    b.push(0); // padding
    b.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
    b.extend_from_slice(&(index as i32).to_ne_bytes()); // ifi_index
    b.extend_from_slice(&flags.to_ne_bytes()); // ifi_flags
    b.extend_from_slice(&change.to_ne_bytes()); // ifi_change
    b
}

/// The `RTM_NEWLINK` body that creates `dummy0`: an `ifinfomsg` (index 0 = kernel-assigned, no flags)
/// followed by `IFLA_IFNAME` and an `IFLA_LINKINFO` nesting `IFLA_INFO_KIND = "dummy"`.
fn create_dummy_body() -> Vec<u8> {
    let mut body = ifinfomsg(0, 0, 0);
    push_attr(&mut body, IFLA_IFNAME, b"dummy0\0");
    let mut linkinfo = Vec::new();
    push_attr(&mut linkinfo, IFLA_INFO_KIND, b"dummy\0");
    push_attr(&mut body, IFLA_LINKINFO, &linkinfo);
    body
}

/// The `RTM_NEWADDR` body: an 8-byte `ifaddrmsg` (AF_INET, the /24 prefix, the interface index)
/// followed by `IFA_LOCAL` and `IFA_ADDRESS`, both the dummy octets.
fn addr_body(index: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(8);
    body.push(libc::AF_INET as u8); // ifa_family
    body.push(DUMMY_PREFIX); // ifa_prefixlen
    body.push(0); // ifa_flags
    body.push(0); // ifa_scope (RT_SCOPE_UNIVERSE)
    body.extend_from_slice(&index.to_ne_bytes()); // ifa_index
    push_attr(&mut body, IFA_LOCAL, &DUMMY_OCTETS);
    push_attr(&mut body, IFA_ADDRESS, &DUMMY_OCTETS);
    body
}

/// Append one `rtattr` TLV — a 4-byte header (`rta_len`, `rta_type`) then the payload — padded to the
/// 4-byte netlink alignment. `rta_len` records the unpadded length, per the ABI.
fn push_attr(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let len = RTA_HDR_LEN + payload.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes()); // rta_len
    buf.extend_from_slice(&ty.to_ne_bytes()); // rta_type
    buf.extend_from_slice(payload);
    buf.resize(buf.len() + (align4(len) - len), 0); // pad to 4-byte alignment
}

/// Round a length up to the 4-byte netlink alignment.
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

// ---- socket exchange -------------------------------------------------------------------------

/// Send one request (a `nlmsghdr` framing `body`) with `NLM_F_ACK` and read the kernel's ACK. The
/// exchange is strictly serialized (send then recv before the next send), so a fixed sequence number
/// is unambiguous. A negative error in the `NLMSG_ERROR` reply becomes an `Err`.
fn nl_request(fd: libc::c_int, msg_type: u16, extra_flags: u16, body: &[u8]) -> io::Result<()> {
    let len = NLMSG_HDR_LEN + body.len();
    let mut buf = Vec::with_capacity(len);
    buf.extend_from_slice(&(len as u32).to_ne_bytes()); // nlmsg_len
    buf.extend_from_slice(&msg_type.to_ne_bytes()); // nlmsg_type
    buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK | extra_flags).to_ne_bytes()); // nlmsg_flags
    buf.extend_from_slice(&1u32.to_ne_bytes()); // nlmsg_seq
    buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid (kernel fills its own)
    buf.extend_from_slice(body);

    let sent = unsafe { libc::send(fd, buf.as_ptr().cast(), buf.len(), 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    read_ack(fd)
}

/// Read a kernel reply and interpret an `NLMSG_ERROR` payload: `error == 0` is the success ACK, a
/// negative value is `-errno`.
fn read_ack(fd: libc::c_int) -> io::Result<()> {
    let mut rbuf = [0u8; 1024];
    let n = unsafe { libc::recv(fd, rbuf.as_mut_ptr().cast(), rbuf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = n as usize;
    // An NLMSG_ERROR payload is the 16-byte header, then an i32 error, then the offending header.
    if n < NLMSG_HDR_LEN + 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short netlink reply",
        ));
    }
    let msg_type = u16::from_ne_bytes([rbuf[4], rbuf[5]]);
    if msg_type == NLMSG_ERROR {
        let err = i32::from_ne_bytes([rbuf[16], rbuf[17], rbuf[18], rbuf[19]]);
        if err != 0 {
            return Err(io::Error::from_raw_os_error(-err));
        }
    }
    Ok(())
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

    /// Whether `needle` appears as a contiguous run in `haystack`.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn align4_rounds_up_to_four() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(6), 8);
    }

    #[test]
    fn push_attr_frames_a_tlv_padded_to_four() {
        let mut buf = Vec::new();
        push_attr(&mut buf, IFLA_INFO_KIND, b"dummy\0"); // 6-byte payload
                                                         // rta_len = 4 + 6 = 10, padded to 12 bytes on the wire.
        assert_eq!(buf.len(), 12);
        assert_eq!(u16::from_ne_bytes([buf[0], buf[1]]), 10); // rta_len excludes padding
        assert_eq!(u16::from_ne_bytes([buf[2], buf[3]]), IFLA_INFO_KIND);
        assert_eq!(&buf[4..10], b"dummy\0");
        assert_eq!(&buf[10..12], &[0, 0]); // padding
    }

    #[test]
    fn ifinfomsg_is_sixteen_bytes_with_the_index_and_flags() {
        let up = libc::IFF_UP as u32;
        let b = ifinfomsg(7, up, up);
        assert_eq!(b.len(), NLMSG_HDR_LEN);
        assert_eq!(b[0], libc::AF_UNSPEC as u8); // ifi_family
        assert_eq!(i32::from_ne_bytes([b[4], b[5], b[6], b[7]]), 7); // ifi_index
        assert_eq!(u32::from_ne_bytes([b[8], b[9], b[10], b[11]]), up); // ifi_flags
        assert_eq!(u32::from_ne_bytes([b[12], b[13], b[14], b[15]]), up); // ifi_change
    }

    #[test]
    fn create_dummy_body_names_the_interface_and_the_dummy_kind() {
        let body = create_dummy_body();
        // Starts with a 16-byte ifinfomsg whose index is 0 (kernel-assigned).
        assert_eq!(i32::from_ne_bytes([body[4], body[5], body[6], body[7]]), 0);
        // 4-byte aligned overall, and carries both the requested name and link kind.
        assert_eq!(align4(body.len()), body.len());
        assert!(contains(&body, b"dummy0\0"));
        assert!(contains(&body, b"dummy\0"));
    }

    #[test]
    fn addr_body_carries_af_inet_the_prefix_and_the_octets() {
        let body = addr_body(9);
        assert_eq!(body[0], libc::AF_INET as u8); // ifa_family
        assert_eq!(body[1], DUMMY_PREFIX); // ifa_prefixlen
        assert_eq!(u32::from_ne_bytes([body[4], body[5], body[6], body[7]]), 9); // ifa_index
        assert!(contains(&body, &DUMMY_OCTETS));
    }

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
