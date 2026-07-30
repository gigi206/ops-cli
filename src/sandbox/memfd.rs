//! Hand bytes to bubblewrap through a descriptor instead of through its argument list.
//!
//! A process's argument list is **world-readable** (`/proc/<pid>/cmdline` is mode `444`) while its
//! environment is not (`/proc/<pid>/environ` is `400`). So anything sensitive that reaches bwrap as
//! an argument is readable by every uid on the machine for as long as the cage runs — measured, not
//! assumed. An anonymous in-memory file has neither a name on any filesystem nor a place in the
//! argument list: only its descriptor number appears there.
//!
//! bwrap reads two kinds of input this way — a compiled seccomp filter
//! (`--add-seccomp-fd`) and a further slice of its own arguments (`--args`) — and both want the same
//! thing from this side: a descriptor that survives the `exec`, positioned at offset zero.

use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::io::FromRawFd;

/// Write `bytes` into an anonymous in-memory file, rewound and ready for bwrap to read.
///
/// The descriptor is deliberately **not** close-on-exec, so it survives the exec into bwrap; the
/// caller must keep the returned `File` alive until bwrap has read it. No seal is applied or needed
/// — the file is written, rewound, and read once.
pub(super) fn write(name: &CStr, bytes: &[u8]) -> io::Result<File> {
    // SAFETY: the name is a valid NUL-terminated C string and `flags = 0` yields a descriptor
    // without O_CLOEXEC, so it survives the exec into bwrap.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned an owned descriptor we wrap exactly once.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    /// What bwrap will find: the bytes, from the start, on a descriptor that is not close-on-exec.
    #[test]
    fn the_bytes_are_readable_from_the_start_and_survive_an_exec() {
        let mut file = super::write(c"sbx-test", b"--setenv\0NAME\0value\0").expect("memfd");
        let mut read = Vec::new();
        file.read_to_end(&mut read).expect("read");
        assert_eq!(read, b"--setenv\0NAME\0value\0");

        // SAFETY: querying the descriptor flags of a descriptor we own.
        let flags =
            unsafe { libc::fcntl(std::os::unix::io::AsRawFd::as_raw_fd(&file), libc::F_GETFD) };
        assert_eq!(
            flags & libc::FD_CLOEXEC,
            0,
            "a close-on-exec descriptor would be gone by the time bwrap looked for it"
        );
    }
}
