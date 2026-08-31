//! The bytes of the synthetic files the cage is handed read-only, and the two helpers that stage
//! them.
//!
//! Each producer is a pure function of the launch's own inputs, so what the cage reads as its
//! identity, its hosts table and its machine id is decided here and nowhere else: no host file is
//! copied through, and beyond the uid and gid the same-uid model reflects deliberately, no host
//! account, name or address appears in what they return. Staging is kept beside the bytes because
//! the parent's integrity note constrains both halves together: these files are bound read-only, a
//! read-only bind freezes the mountpoint rather than the inode, and only writing them outside every
//! read-write bind — through a rename, never in place — keeps a running cage from observing a
//! partial rewrite of its own `/etc`.

use super::{SANDBOX_HOME, SANDBOX_SHELL};
use std::io;
use std::path::{Path, PathBuf};

/// The synthetic sandbox identity. Same uid/gid as the host (the same-uid model),
/// but a synthetic name and no other host accounts — uid resolution works
/// without leaking `/etc/passwd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) user: String,
}

/// The synthetic interactive-shell rc: set a default prompt that names the cage, show the
/// egress contract once (to stderr, so a captured stdout stays clean), source the home's own
/// `.bashrc` if the agent has written one, then activate mise so its activated tools manage
/// PATH/env. Static (no per-project data, so the same bytes back every cage), bound read-only
/// from outside every writable mount, so the agent cannot rewrite what its own shell sources.
///
/// The prompt uses `\h`, which resolves to the cage's `sbx-<slug>` hostname, so an interactive `sbx run`
/// reads `(sbx-<slug>) <cwd>$` instead of the bare `bash-<v>$` default — set *before* the
/// `.bashrc` source so a home's own `PS1` still wins. The contract `cat` is guarded on the
/// variable being set and readable, so it is a no-op where the handle is absent.
pub(super) const SHELL_RC_CONTENTS: &str = "\
PS1='(\\h) \\w\\$ '\n\
[ -r \"$SBX_EGRESS_CONTRACT\" ] && cat \"$SBX_EGRESS_CONTRACT\" >&2\n\
[ -r \"$HOME/.bashrc\" ] && . \"$HOME/.bashrc\"\n\
command -v mise >/dev/null 2>&1 && eval \"$(mise activate bash)\"\n";

/// The synthetic `/etc/passwd`: the sandbox user (same uid/gid as the host) plus
/// `nobody`. No other host account appears.
pub(super) fn passwd_contents(id: &Identity, home: &str, shell: &str) -> String {
    format!(
        "{user}:x:{uid}:{gid}:{user}:{home}:{shell}\n\
         nobody:x:65534:65534:nobody:/:/sbin/nologin\n",
        user = id.user,
        uid = id.uid,
        gid = id.gid,
    )
}

/// The synthetic `/etc/group`: the sandbox group plus `nogroup`.
pub(super) fn group_contents(id: &Identity) -> String {
    format!(
        "{user}:x:{gid}:\nnogroup:x:65534:\n",
        user = id.user,
        gid = id.gid,
    )
}

/// The synthetic `/etc/hosts`: `localhost` (and the cage's own `sbx-<slug>` hostname) mapped to
/// loopback, so a name lookup of either resolves via the file without reaching DNS — which the
/// cage's empty netns has no resolver for. Only loopback mappings appear; no host entry is
/// leaked. The hostname is placed on the `localhost` lines so a tool that resolves its own
/// hostname (`gethostname` → `getaddrinfo`) also gets a loopback answer instead of a DNS failure.
///
/// Each `tcp://` destination is added on its own loopback address, where the cage's forwarder
/// listens for it. That is what lets a declaration name the real host (`psql -h db.internal`) and
/// have it work: the name resolves inside the cage to somewhere the cage can actually reach, while
/// the request that leaves still carries the name, so the egress policy matches on what the author
/// wrote. These are still loopback addresses — nothing here reveals where the destination really is.
pub(crate) fn hosts_contents(
    hostname: &str,
    tcp: &[crate::sandbox::egress::TcpDestination],
) -> String {
    let mut out = format!(
        "127.0.0.1\tlocalhost {hostname}\n\
         ::1\tlocalhost ip6-localhost ip6-loopback {hostname}\n"
    );
    // `map_name` is already false for a destination this file maps itself; the hostname check is the
    // belt to that suspenders, since a second line for a name written above would never be read.
    for dest in tcp
        .iter()
        .filter(|d| d.map_name && d.host != hostname && d.host != "localhost")
    {
        out.push_str(&format!("{}\t{}\n", dest.cage_addr, dest.host));
    }
    out
}

/// A synthetic `/etc/machine-id` (systemd format: 32 lowercase hex digits, newline-terminated),
/// deterministically derived from the cage's own home path so it is **stable across launches of the
/// same app-home and unique per home** — never the host's real machine-id (which the hermetic cage
/// does not carry, and which would leak a host identifier). A hermetic cage otherwise has no
/// `/etc/machine-id`, `/var/lib/dbus/machine-id`, or MAC, so a desktop app that fingerprints the
/// machine (some editors read `cat /var/lib/dbus/machine-id /etc/machine-id || hostname` to build
/// a device id) falls back to hashing an empty string — producing the *same* id in every such cage,
/// which the app's server-side anti-abus then reads as one machine running countless accounts. A
/// per-home synthetic id gives each app a distinct, persistent machine identity instead. The input is
/// domain-separated so the raw home path is not recoverable from the id.
pub(super) fn machine_id_contents(home_src: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"sbx-cage-machine-id\0");
    h.update(home_src.as_os_str().as_encoded_bytes());
    let digest = h.finalize();
    let mut id = String::with_capacity(33);
    for byte in &digest[..16] {
        id.push_str(&format!("{byte:02x}"));
    }
    id.push('\n');
    id
}

/// The host identity to reflect into the sandbox (same-uid model). Reads ambient
/// process state, so it is kept out of the pure assembly.
pub(super) fn current_identity() -> Identity {
    // SAFETY: `getuid`/`getgid` always succeed and only read the caller's ids.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    Identity {
        uid,
        gid,
        user: "sandbox".to_string(),
    }
}

/// Materialise the synthetic `passwd`/`group` into `etc_dir` (created owner-only)
/// and return their paths, ready to bind read-only. The shell field matches the
/// in-sandbox `/bin/sh`, and `$HOME` matches the writable home bind.
///
/// Written through [`crate::sandbox::atomicfile::write_atomic`], like every other file staged in
/// this directory and for the same reason: concurrent cages of one project share it, and these
/// two are bound read-only into each of them, so an in-place rewrite could show a running cage a
/// truncated `passwd` — every `getpwuid` in it failing for as long as the window lasts.
pub(super) fn materialize_etc(etc_dir: &Path, id: &Identity) -> io::Result<(PathBuf, PathBuf)> {
    use std::fs::{DirBuilder, Permissions};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(etc_dir)?;
    std::fs::set_permissions(etc_dir, Permissions::from_mode(0o700))?;

    let passwd = etc_dir.join("passwd");
    let group = etc_dir.join("group");
    crate::sandbox::atomicfile::write_atomic(
        &passwd,
        passwd_contents(id, SANDBOX_HOME, SANDBOX_SHELL).as_bytes(),
    )?;
    crate::sandbox::atomicfile::write_atomic(&group, group_contents(id).as_bytes())?;
    Ok((passwd, group))
}
