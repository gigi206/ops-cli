//! Config-file safety gate.
//!
//! Before any config file's bytes are acted on, it is refused unless it is a
//! plain regular file, owned by us, and not world-writable. The decision is a
//! pure `fstat` on the already-open descriptor — so the metadata that is checked
//! and the bytes that are read belong to the same inode, closing the rename
//! window a separate path-based check would reopen.

use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Pure safety decision for a config file's owner uid and mode.
///
/// Split out from the I/O so the owner-mismatch branch (`file_uid != euid`) is
/// unit-testable without a foreign-owned file (which would otherwise need root).
///
/// Refuses a non-regular file, one not owned by us, or a world-writable one;
/// group-writable (`0o020`) is tolerated — only the other-write bit (`0o002`) is
/// checked. `mode` is the full `st_mode` (type bits included), so the
/// regular-file test reads its `S_IFMT` field.
fn verdict(file_uid: u32, mode: u32, euid: u32) -> io::Result<()> {
    // A non-regular file (FIFO, socket, device, directory) must never be loaded: a device could
    // feed back attacker-controlled bytes, a FIFO would stall a reader. The owner/mode checks alone
    // do not catch it. (The descriptor is opened `O_NONBLOCK` so a writer-less FIFO reaches this
    // refusal instead of hanging the open — see `read_safe_bytes`.)
    if mode & libc::S_IFMT != libc::S_IFREG {
        return Err(refuse("not a regular file"));
    }
    if file_uid != euid {
        return Err(refuse(&format!("owned by uid {file_uid}, expected {euid}")));
    }
    if mode & 0o002 != 0 {
        return Err(refuse("world-writable"));
    }
    Ok(())
}

/// The most a config file may be before it is refused unread.
///
/// The gate's own checks are on the inode, not the size, so without this a repository could ship a
/// multi-gibibyte `.sbx.toml` — one long comment line compresses to little in a pack, so the clone
/// stays cheap — and every sbx invocation in that directory would read it whole into host memory
/// before the parser ever saw a key. `sbx run`, `sbx config show`, a shell-prompt integration and
/// `sbx trust` all take this path. The ceiling is three orders of magnitude above the largest
/// profile this repository ships (~21 KiB), so it bounds the attack without bounding any use.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// A refusal carries `PermissionDenied`, the closest kind to "this file is not
/// trustworthy to load".
fn refuse(why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("refusing to load config: {why}"),
    )
}

/// Apply the owner/mode verdict to an already-open file (its `fstat`), so the
/// safety decision covers the same inode whose bytes a caller reads through that
/// descriptor. `path` is used only to name the file in an error.
pub(crate) fn check_safe_file(f: &std::fs::File, path: &Path) -> io::Result<()> {
    let m = f.metadata()?;
    // The owner check uses the EFFECTIVE uid (`geteuid`), the identity whose
    // files we are willing to act on; a pure syscall, musl-safe.
    let euid = unsafe { libc::geteuid() };
    verdict(m.uid(), m.mode(), euid).map_err(|e| with_path(e, path))
}

/// Open `path`, gate the OPEN descriptor with [`check_safe_file`], and read its
/// raw bytes from that same descriptor.
///
/// One open serves the `fstat` and the read, so the validated metadata and the
/// consumed bytes cannot belong to two different files (the trust hash and the
/// later parse act on exactly these bytes).
///
/// **Every error returned names the file**, so a caller renders it under an action and does not
/// prefix the path a second time: `ignoring {e}`, `cannot trust {e}`, `cannot read {e}`. The gate
/// names the file, the caller names the action. It has to be this way round because the gate is the
/// only layer that knows *which* file failed when a caller reads several under one verb: a trust
/// verdict covers a sibling mise file, and "refusing to load config" about the wrong one of the two
/// is worse than unhelpful. A caller that also renders errors of its own (a parse failure, a store
/// write) names the path in those, since nothing else will.
pub(crate) fn read_safe_bytes(path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    // Open non-blocking: a writer-less FIFO would otherwise hang this `O_RDONLY` open indefinitely,
    // before the verdict below could refuse it as a non-regular file. For a regular file
    // `O_NONBLOCK` is a no-op on reads, so the bytes read are unaffected.
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| with_path(e, path))?;
    check_safe_file(&f, path)?;
    // Read one byte past the ceiling so "exactly at the ceiling" and "over it" are distinguishable,
    // the way `read_line_bounded` distinguishes them in the proxy's framing reader.
    let mut out = Vec::new();
    f.by_ref()
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|e| with_path(e, path))?;
    if out.len() as u64 > MAX_CONFIG_BYTES {
        return Err(with_path(
            refuse(&format!("larger than {MAX_CONFIG_BYTES} bytes")),
            path,
        ));
    }
    Ok(out)
}

/// Prefix an error with the file path, so a failure that aborts a command names
/// which file failed rather than emitting a bare, unactionable I/O error.
fn with_path(e: io::Error, path: &Path) -> io::Error {
    io::Error::new(e.kind(), format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;
    use std::os::unix::fs::PermissionsExt;

    /// A regular file's `st_mode`: the permission bits OR'd with the `S_IFREG`
    /// type bits, so `verdict`'s regular-file gate sees a real file.
    fn reg(perm: u32) -> u32 {
        perm | libc::S_IFREG
    }

    #[test]
    fn read_safe_bytes_refuses_a_fifo_without_hanging() {
        // A writer-less FIFO must be refused as a non-regular file, not hang the open — the whole
        // point of the non-blocking open. (Were the open blocking, this test would deadlock.)
        use std::ffi::CString;
        let tmp = TmpDir::new();
        let p = tmp.join("cfg");
        let c = CString::new(p.to_str().unwrap()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(c.as_ptr(), 0o600) },
            0,
            "mkfifo({p:?}) failed"
        );
        let err = read_safe_bytes(&p).expect_err("a FIFO must be refused, not read");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("not a regular file"));
    }

    #[test]
    fn verdict_accepts_an_owned_non_world_writable_regular_file() {
        assert!(verdict(1000, reg(0o644), 1000).is_ok());
        // group-writable is tolerated
        assert!(verdict(1000, reg(0o664), 1000).is_ok());
    }

    #[test]
    fn verdict_refuses_a_foreign_owner() {
        let err = verdict(1234, reg(0o600), 1000).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("owned by uid 1234"));
    }

    #[test]
    fn verdict_refuses_a_world_writable_file() {
        let err = verdict(1000, reg(0o666), 1000).unwrap_err();
        assert!(err.to_string().contains("world-writable"));
    }

    #[test]
    fn verdict_refuses_a_non_regular_file() {
        // a directory's mode: no S_IFREG bits
        let err = verdict(1000, libc::S_IFDIR | 0o755, 1000).unwrap_err();
        assert!(err.to_string().contains("not a regular file"));
    }

    #[test]
    fn read_safe_bytes_reads_an_owned_file_and_names_a_missing_one() {
        let dir = TmpDir::new();
        let ok = dir.join("ok.toml");
        std::fs::write(&ok, b"hello").unwrap();
        assert_eq!(read_safe_bytes(&ok).unwrap(), b"hello");

        let err = read_safe_bytes(&dir.join("absent.toml")).unwrap_err();
        assert!(
            err.to_string().contains("absent.toml"),
            "a missing file must name the path; got: {err}"
        );
    }

    /// A config larger than the ceiling is refused unread rather than pulled into host memory.
    ///
    /// The gate's other checks are on the inode and say nothing about size, so a repository could
    /// ship a `.sbx.toml` of arbitrary length — cheap to clone, one long comment line — and every
    /// sbx invocation in that directory read it whole before the parser saw a key. The file at
    /// exactly the ceiling is loaded, so the refusal cannot be satisfied by refusing everything.
    #[test]
    fn read_safe_bytes_refuses_a_config_over_the_ceiling_and_loads_one_at_it() {
        let dir = TmpDir::new();
        let at = dir.join("at.toml");
        std::fs::write(&at, vec![b'#'; MAX_CONFIG_BYTES as usize]).unwrap();
        assert_eq!(
            read_safe_bytes(&at).unwrap().len(),
            MAX_CONFIG_BYTES as usize,
            "a file exactly at the ceiling is still loaded whole"
        );

        let over = dir.join("over.toml");
        std::fs::write(&over, vec![b'#'; MAX_CONFIG_BYTES as usize + 1]).unwrap();
        // Matched rather than `unwrap_err`, which would print the whole mebibyte on failure.
        let err = match read_safe_bytes(&over) {
            Ok(loaded) => panic!(
                "a config over the ceiling was read whole: {} bytes",
                loaded.len()
            ),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("larger than") && err.to_string().contains("over.toml"),
            "the refusal names the ceiling and the file: {err}"
        );
    }

    #[test]
    fn read_safe_bytes_refuses_a_world_writable_file() {
        let dir = TmpDir::new();
        let f = dir.join("loose.toml");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = read_safe_bytes(&f).unwrap_err();
        assert!(err.to_string().contains("world-writable"));
    }
}
