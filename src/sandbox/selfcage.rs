//! sbx's own binary, run in a cage of its own: how the supervisor starts the helpers that read what
//! a cage or a registry sends, the egress proxy ([`super::proxy::child`]), the transparent-capture
//! tap ([`super::nettap`]) and the unpack of an image's layer ([`super::distro::unpack`]).
//!
//! Each helper is the running build, bound at [`BINARY`] through a descriptor opened on it (or
//! copied in when its file has gone since), over the host's userland read-only for a binary that
//! loads libraries, and nothing else of the host but what its caller adds. The cage carries the
//! hardening every cage gets ([`super::argv::compose`]): every namespace but the network one the
//! caller names, no capability, a cleared environment, the syscall denylist.
//!
//! ## What stays in the supervisor
//!
//! A helper is worth what it takes away from a flaw in the code it runs, and there are two things
//! it can take. One is the supervisor's own reach, the user's uid outside any cage, should a flaw
//! hand over execution. The other is an effect a flaw could redirect without that: an unpack writes
//! at paths an archive's members name, which is why [`super::distro::unpack`] runs caged.
//!
//! The documents sbx fetches through nix, a release's asset list or a package index's answer,
//! offer neither. Nix has already fetched and handled them host-side, outside any cage, with its
//! own TLS and HTTP stack, so the supervisor's reach is exposed to those bytes either way, and the
//! parse has no effect beyond the value it returns. Those parses stay in the supervisor until nix's
//! host-side fetches run in a cage themselves.
//!
//! The registry client ([`super::distro::registry`]) offers the first and not the second: no
//! uncaged reader precedes it, but where it writes is settled before the bytes arrive, since a
//! layer lands under the name its validated digest spells and is kept only once its bytes hash to
//! that digest. It stays in the supervisor as well. Only the global configuration or a project the
//! trust gate admits declares the image it fetches, and a manifest pinned by digest is hashed
//! before it is parsed. A helper would need a syscall list that admits sockets, the `distro`
//! credential inside its cage, and every layer passed back through the supervisor to be hashed,
//! for a gain confined to one path while nix's fetches stay uncaged beside it.

use super::spec::{Mount, NetPolicy, SandboxSpec};
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// Where the binary is inside a helper's cage.
pub(crate) const BINARY: &str = "/sbx";

/// The build that is running, whatever has become of its file since, and whether that file has been
/// deleted: a helper started from a binary replaced mid-session would speak another build's
/// messages.
pub(crate) fn running() -> io::Result<(File, bool)> {
    let binary = File::open("/proc/self/exe")?;
    let gone = deleted(&binary);
    Ok((binary, gone))
}

/// The cage `who` runs in: the host's userland read-only, the binary open as `binary` at
/// [`BINARY`], bound where it is or `copy`'d when its file is gone, then `extra`, under the network
/// posture `net`, running [`BINARY`] with `args`.
pub(crate) fn spec(
    who: &str,
    binary: RawFd,
    copy: bool,
    extra: Vec<Mount>,
    net: NetPolicy,
    args: Vec<OsString>,
) -> io::Result<SandboxSpec> {
    let ro = |p: &str| Mount::RoBind {
        src: p.into(),
        dest: p.into(),
    };
    let symlink = |target: &str, dest: &str| Mount::Symlink {
        target: target.into(),
        dest: dest.into(),
    };
    let mut mounts = vec![
        ro("/usr"),
        symlink("usr/lib", "/lib"),
        symlink("usr/lib64", "/lib64"),
        Mount::RoBindTry {
            src: "/etc/ld.so.cache".into(),
            dest: "/etc/ld.so.cache".into(),
        },
        if copy {
            Mount::Copy {
                fd: binary,
                dest: BINARY.into(),
            }
        } else {
            // Through the descriptor's own link, which names the file it was opened on even after
            // a rename.
            Mount::RoBind {
                src: format!("/proc/self/fd/{binary}").into(),
                dest: BINARY.into(),
            }
        },
    ];
    mounts.extend(extra);
    let mut cmd = vec![OsString::from(BINARY)];
    cmd.extend(args);
    SandboxSpec::new("/".into(), mounts, Vec::new(), net, cmd)
        .map_err(|e| io::Error::other(format!("cannot build {who}'s cage: {e:?}")))
}

/// bwrap starting `spec`, and the descriptors it reads: the spec's own, then `binary`, the file the
/// spec binds at [`BINARY`].
pub(crate) fn command(
    bwrap: &Path,
    spec: &SandboxSpec,
    binary: File,
) -> io::Result<(Command, Vec<File>)> {
    let (argv, mut files) = super::argv::compose(spec)?;
    files.push(binary);
    let mut command = Command::new(bwrap);
    command.args(argv).stdin(Stdio::null());
    Ok((command, files))
}

/// Whether the file `open` was opened on has been deleted since, as its `/proc` link says.
fn deleted(open: &File) -> bool {
    std::fs::read_link(format!("/proc/self/fd/{}", open.as_raw_fd()))
        .is_ok_and(|target| target.as_os_str().as_bytes().ends_with(b" (deleted)"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    /// A file deleted after it was opened reads as such through its descriptor; one still there
    /// does not.
    #[test]
    fn a_binary_deleted_since_it_was_opened_is_seen_as_gone() {
        let dir = TmpDir::new();
        let path = dir.join("sbx");
        std::fs::write(&path, b"x").unwrap();
        let open = File::open(&path).unwrap();
        assert!(!deleted(&open));
        std::fs::rename(&path, dir.join("moved")).unwrap();
        assert!(
            !deleted(&open),
            "a rename leaves the file where the descriptor finds it"
        );
        std::fs::remove_file(dir.join("moved")).unwrap();
        assert!(deleted(&open));
    }
}
