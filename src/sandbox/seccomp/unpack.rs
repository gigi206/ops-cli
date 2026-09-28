//! A layer's unpack's own seccomp filter: a list of what it may call, where every cage gets a list
//! of what it may not.
//!
//! The unpack ([`crate::sandbox::distro::unpack`]) parses a layer a registry served, gzip and tar,
//! and writes what the layer declares into the tree being assembled. What it asks of the kernel is
//! narrow: it reads the layer on its standard input, makes, links, looks at, sets the mode of,
//! lists and removes entries of that tree, and writes one line, an answer or a refusal. So this
//! filter names those calls and answers every other one with `EPERM`: no socket, no program run, no
//! process started, no memory mapped executable. The cage the unpack runs in holds no network and
//! no writable path but the tree; the filter takes away the calls that would reach past it, should
//! a flaw in the parsing hand someone its execution.
//!
//! The unpack installs it itself ([`confine`]), before it reads the layer ([`allowlist`] says what
//! every such list starts from). The list was read from a trace of the unpack over layers that take
//! every path of its applier (gzip and plain tar, files, directories, symlinks, hard links, a
//! whiteout, an opaque marker, a directory replaced by a file and a file by a directory, a whole
//! distribution's userland, and each refusal) under both C libraries sbx is built with.
//!
//! `fcntl` is allowed only to duplicate a descriptor, mark it close-on-exec or read its flags.
//!
//! The unpack is one thread, and ends by ending its process: nothing on the list ends a thread.
//!
//! On x86_64 its C libraries make some of those calls under their older names (`open`, `stat`,
//! `lstat`, `mkdir`, `chmod`, `symlink`, `unlink`), which aarch64 does not have; there they make
//! the `*at` calls the list names on every architecture. The aarch64 build was not traced.

use super::{Rules, allowlist};
use std::io;

/// The calls the unpack's own work makes, allowed with any argument.
fn work() -> Vec<i64> {
    let calls = vec![
        // The layer on standard input; the answer or the refusal on the other two.
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        // The tree: entries made, linked, looked at, given a mode, listed and removed.
        libc::SYS_openat,
        libc::SYS_mkdirat,
        libc::SYS_symlinkat,
        libc::SYS_linkat,
        libc::SYS_fchmodat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_fstat,
        libc::SYS_getdents64,
        libc::SYS_unlinkat,
        // Memory.
        libc::SYS_brk,
        libc::SYS_munmap,
        // The end: the signal stack taken down, then the process.
        libc::SYS_sigaltstack,
        libc::SYS_exit_group,
    ];
    // The older spellings, which x86_64 still has and its C libraries still make. The rebinding
    // carries the same `cfg` as the extension it serves.
    #[cfg(target_arch = "x86_64")]
    let calls = {
        let mut calls = calls;
        calls.extend_from_slice(&[
            libc::SYS_open,
            libc::SYS_stat,
            libc::SYS_lstat,
            libc::SYS_mkdir,
            libc::SYS_chmod,
            libc::SYS_symlink,
            libc::SYS_unlink,
        ]);
        calls
    };
    calls
}

/// What the unpack may call: every call named here, under its conditions when it has some.
fn allowed() -> Rules {
    let mut m = allowlist::starting_from(work());
    m.insert(
        libc::SYS_fcntl,
        [libc::F_DUPFD_CLOEXEC, libc::F_SETFD, libc::F_GETFL]
            .into_iter()
            .map(|cmd| allowlist::arg_is(1, cmd as u64))
            .collect(),
    );
    m
}

/// Put the calling thread, and every thread it starts from now on, under the unpack's filters: the
/// unpack calls this first thing, before it reads the layer.
pub(crate) fn confine() -> io::Result<()> {
    allowlist::confine(allowed())
}

#[cfg(test)]
mod tests {
    use super::super::allowlist::probe::{Outcome, call, opening};
    use super::*;
    use crate::sandbox::deadline::Deadlined;
    use crate::testutil::TmpDir;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::panic::AssertUnwindSafe;
    use std::path::Path;
    use std::time::{Duration, Instant};

    /// The outcome of a filesystem operation, as a probe reports it.
    fn done(r: io::Result<impl Sized>) -> Outcome {
        r.map(|_| 0).map_err(|e| e.raw_os_error().unwrap_or(-1))
    }

    /// How long the probe's process has to give its report before it is killed and the test fails.
    const REPORT_WITHIN: Duration = Duration::from_secs(30);

    /// Every probe, made in a process of its own under the unpack's filters, the filesystem ones
    /// under `dir`.
    ///
    /// A process, as the unpack is, rather than a thread of this one. The filters refuse `futex`,
    /// which a thread sharing locks with others needs: a lock such a thread releases while another
    /// waits on it is never handed over, the waiter never being woken. The allocator's locks are
    /// shared by every thread of a test process, so one thread confined here could stop all of it.
    ///
    /// The child is a copy of this thread alone. It allocates (the filters are compiled in it, and
    /// the probes go through the standard library, whose calls are what the list was read from),
    /// which the C library keeps safe in the child of a threaded process by resetting its
    /// allocator's locks at `fork`. It writes what it found, one `name=outcome` line each, and
    /// ends. A child that has not given its report within [`REPORT_WITHIN`] is killed, and the
    /// test fails rather than waits.
    fn under_the_filters(dir: &Path) -> BTreeMap<String, Outcome> {
        let (mut results, report) = UnixStream::pair().unwrap();
        // SAFETY: the child runs `probes` and leaves by `_exit`, never back into the harness it
        // was copied from.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
        if pid == 0 {
            drop(results);
            // Written as the unpack writes its answer, by `write`: a socket's own `send` is not on
            // the list.
            let mut report = std::fs::File::from(std::os::fd::OwnedFd::from(report));
            let text = std::panic::catch_unwind(AssertUnwindSafe(|| probes(dir, &report)));
            let code = match text.map(|text| report.write_all(text.as_bytes())) {
                Ok(Ok(())) => 0,
                Ok(Err(_)) => 2,
                Err(_) => 3,
            };
            // SAFETY: `_exit` ends the child without running anything of the process it copied.
            unsafe { libc::_exit(code) };
        }
        drop(report);
        results.set_read_timeout(Some(REPORT_WITHIN)).unwrap();
        let mut text = String::new();
        let read =
            Deadlined::new(&mut results, Instant::now() + REPORT_WITHIN).read_to_string(&mut text);
        if read.is_err() {
            // SAFETY: `pid` is a child of this process, not yet reaped.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        let mut status = 0;
        // SAFETY: `pid` is a child of this process that has exited or is about to.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        if let Err(e) = read {
            panic!("no report from the probe under the unpack's filters: {e}");
        }
        // Exit 2: the report could not be written; 3: the probes panicked.
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "the probe's process ended with wait status {status:#x}: {text}"
        );
        let mut outcomes = BTreeMap::new();
        for line in text.lines() {
            let (name, said) = line.split_once('=').unwrap();
            let outcome = match said {
                "ok" => Ok(0),
                errno => Err(errno.parse().unwrap()),
            };
            outcomes.insert(name.to_string(), outcome);
        }
        outcomes
    }

    /// What [`under_the_filters`]'s child does: confine itself, make every probe, and say what each
    /// answered, the calls that need a descriptor making them on `report`.
    fn probes(dir: &Path, report: &std::fs::File) -> String {
        let mut out: Vec<(&str, Outcome)> = Vec::new();
        out.push(("confine", done(confine())));
        let path = c"/dev/null".as_ptr() as libc::c_long;

        // Refused.
        out.push((
            "socket unix",
            opening(
                libc::SYS_socket,
                &[libc::AF_UNIX as _, libc::SOCK_STREAM as _],
            ),
        ));
        out.push((
            "socket inet",
            opening(
                libc::SYS_socket,
                &[libc::AF_INET as _, libc::SOCK_STREAM as _],
            ),
        ));
        let nowhere = c"/nonexistent/sbx-probe".as_ptr() as libc::c_long;
        let empty: [*const libc::c_char; 1] = [std::ptr::null()];
        let empty = empty.as_ptr() as libc::c_long;
        out.push(("execve", call(libc::SYS_execve, &[nowhere, empty, empty])));
        // A process `clone` let through runs on here as a copy of this thread, and leaves at
        // once.
        let process = call(libc::SYS_clone, &[libc::SIGCHLD as _, 0, 0, 0, 0]);
        if process == Ok(0) {
            // SAFETY: `_exit` ends the copy without running anything of the process it copied.
            unsafe { libc::_exit(0) };
        }
        out.push(("clone process", process));
        let fd = report.as_raw_fd() as libc::c_long;
        out.push((
            "ioctl TCGETS",
            call(libc::SYS_ioctl, &[fd, libc::TCGETS as _, 0]),
        ));
        out.push((
            "fcntl F_SETFL",
            call(libc::SYS_fcntl, &[fd, libc::F_SETFL as _, 0]),
        ));
        let (prot_rx, anon) = (
            (libc::PROT_READ | libc::PROT_EXEC) as libc::c_long,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as libc::c_long,
        );
        out.push((
            "mmap PROT_EXEC",
            call(libc::SYS_mmap, &[0, 4096, prot_rx, anon, -1, 0]),
        ));
        // SAFETY: `getpid` reads nothing and cannot fail.
        let me = unsafe { libc::getpid() } as libc::c_long;
        out.push(("kill", call(libc::SYS_kill, &[me, 0])));
        out.push((
            "renameat2",
            call(
                libc::SYS_renameat2,
                &[libc::AT_FDCWD as _, path, libc::AT_FDCWD as _, path, 0],
            ),
        ));

        // Answered `ENOSYS`.
        out.push(("clone3", call(libc::SYS_clone3, &[0, 0])));

        // Allowed: what an unpack does to its tree.
        let at = |name: &str| dir.join(name);
        out.push(("create_dir", done(std::fs::create_dir(at("d")))));
        out.push(("write", done(std::fs::write(at("d/f"), b"x"))));
        out.push(("symlink", done(std::os::unix::fs::symlink("d/f", at("l")))));
        out.push(("hard_link", done(std::fs::hard_link(at("d/f"), at("h")))));
        out.push((
            "set_permissions",
            done(std::fs::set_permissions(
                at("d/f"),
                std::os::unix::fs::PermissionsExt::from_mode(0o600),
            )),
        ));
        out.push(("symlink_metadata", done(std::fs::symlink_metadata(at("l")))));
        out.push((
            "read_dir",
            done(std::fs::read_dir(at("d")).map(|d| d.count())),
        ));
        out.push(("remove_file", done(std::fs::remove_file(at("h")))));
        out.push(("remove_dir_all", done(std::fs::remove_dir_all(at("d")))));
        out.push((
            "fcntl F_DUPFD_CLOEXEC",
            opening(libc::SYS_fcntl, &[fd, libc::F_DUPFD_CLOEXEC as _, 0]),
        ));

        let mut text = String::new();
        for (name, outcome) in out {
            let said = match outcome {
                Ok(_) => "ok".to_string(),
                Err(errno) => errno.to_string(),
            };
            text.push_str(&format!("{name}={said}\n"));
        }
        text
    }

    /// The unpack's filters, in a process of their own: the calls that would reach past its cage
    /// are refused, `clone3` is answered `ENOSYS`, and what an unpack does to its tree still works.
    #[test]
    fn the_unpacks_filters_refuse_what_its_work_does_not_make() {
        let tmp = TmpDir::new();
        let outcomes = under_the_filters(tmp.path());
        let got = |name: &str| {
            *outcomes
                .get(name)
                .unwrap_or_else(|| panic!("no probe {name}: {outcomes:?}"))
        };
        assert_eq!(got("confine"), Ok(0), "the filters install");
        for name in [
            "socket unix",
            "socket inet",
            "execve",
            "clone process",
            "ioctl TCGETS",
            "fcntl F_SETFL",
            "mmap PROT_EXEC",
            "kill",
            "renameat2",
        ] {
            assert_eq!(got(name), Err(libc::EPERM), "{name} is refused");
        }
        assert_eq!(
            got("clone3"),
            Err(libc::ENOSYS),
            "clone3 is answered ENOSYS"
        );
        for name in [
            "create_dir",
            "write",
            "symlink",
            "hard_link",
            "set_permissions",
            "symlink_metadata",
            "read_dir",
            "remove_file",
            "remove_dir_all",
            "fcntl F_DUPFD_CLOEXEC",
        ] {
            assert_eq!(got(name), Ok(0), "{name} is allowed");
        }
    }
}
