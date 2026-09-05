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
use std::process::Command;

/// Write `bytes` into an anonymous in-memory file, rewound and ready for bwrap to read.
///
/// The descriptor is **close-on-exec**, and stays so in this process. bwrap receives it through
/// [`inherit_across_exec`], which clears the flag on the child's own copy between the fork and the
/// exec, so exactly one exec inherits it.
///
/// Creating it inheritable instead is what a single reader of this function would expect, and it is
/// the thing that cannot be done: a descriptor without the flag is handed to **every** process this
/// one spawns while it is open, not only to the bwrap it was made for. One process stands up several
/// cages at once — a task engine runs up to `MAX_LIVE` invocations concurrently — and an `--args`
/// file holds that invocation's resolved credentials. So one invocation's secret was readable from
/// a sibling cage's `/proc/<pid>/fd`, walking around the pid namespace that keeps a task's
/// environment out of reach.
///
/// The caller must keep the returned `File` alive until bwrap has read it. No seal is applied or
/// needed — the file is written, rewound, and read once.
pub(super) fn write(name: &CStr, bytes: &[u8]) -> io::Result<File> {
    // SAFETY: the name is a valid NUL-terminated C string. `MFD_CLOEXEC` keeps the descriptor out
    // of every exec but the one `inherit_across_exec` prepares.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned an owned descriptor we wrap exactly once.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// Let the exec `command` performs inherit `files`, and only that one.
///
/// Registered as a `pre_exec` closure, which `std` runs in the child between the fork and the
/// `execvp` — on `Command::spawn` and on `CommandExt::exec` alike, since both reach the same
/// `do_exec`. The parent's copies keep the flag, so a cage standing up while this one spawns
/// inherits nothing.
///
/// The caller must hold `files` alive across the spawn: this records descriptor **numbers**, and a
/// file dropped before the fork would leave the child clearing the flag on whatever took its place.
pub(crate) fn inherit_across_exec(command: &mut Command, files: &[File]) {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::process::CommandExt as _;

    let fds: Vec<libc::c_int> = files.iter().map(|f| f.as_raw_fd()).collect();
    // SAFETY: the closure runs in the child between fork and exec, where only async-signal-safe
    // calls are allowed. It calls `fcntl` and, on failure, `Error::last_os_error`, which reads
    // `errno` and allocates nothing.
    unsafe {
        command.pre_exec(move || match clear_cloexec(&fds) {
            true => Ok(()),
            false => Err(io::Error::last_os_error()),
        });
    }
}

/// Clear `FD_CLOEXEC` on each of `fds`, reporting whether all of them took it.
///
/// Answers with a `bool` rather than a `Result` because both callers are on the child side of a
/// fork: the `pre_exec` closure above, and the hand-written fork in [`super::launch`]'s pty
/// supervisor, which may call nothing that allocates. `fcntl` is async-signal-safe.
pub(super) fn clear_cloexec(fds: &[libc::c_int]) -> bool {
    // SAFETY: `fcntl` with `F_SETFD` on descriptors the caller owns; the child holds the same
    // numbers the parent did.
    fds.iter()
        .all(|&fd| unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } >= 0)
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::process::Command;

    /// Every file that stages one of these descriptors also prepares the exec that must inherit it.
    ///
    /// Anchored on the **staging**, not on any one launch helper. The first form of this guard asked
    /// which files call `cage_command`, and that was the wrong question by exactly the margin that
    /// matters: two harnesses stage their own descriptors and spawn bwrap directly, so they were
    /// invisible to it and broke on the change this guard exists to protect. What decides is who
    /// creates a descriptor, since that is who owes the child a way to keep it.
    ///
    /// The list of staging entry points is this guard's upkeep, and it has been short twice: keyed
    /// on the shared launch command alone it missed two harnesses that stage their own descriptors
    /// and spawn bubblewrap directly, and without the plugin path's own composition it missed every
    /// plugin cage. Both times a suite that launches real cages found what reading did not. A new
    /// way to stage a descriptor belongs in that list the day it is written.
    ///
    /// A scan of the source rather than a call graph, for the reason this crate's other
    /// source-scanning guards exist: the failure is an **absence**, and nothing in the type system
    /// makes a new spawn path ask for this. Its shape is quiet, too — bwrap reads these descriptors
    /// by number off its own argument list, so a path that forgets the preparation hands it a
    /// number that closed at the exec, and the cage refuses with `Bad file descriptor`, naming
    /// neither this nor the filter it could not read.
    #[test]
    fn every_file_that_stages_a_descriptor_prepares_its_exec() {
        /// A call to one of the staging entry points, not a mention inside a longer name.
        fn calls_it(text: &str) -> bool {
            [
                "cage_command(",
                "memfd::write(",
                "memfds(",
                "argv::compose(",
            ]
            .iter()
            .any(|needle| crate::testutil::calls_function(text, needle))
        }

        let files = crate::testutil::crate_sources();

        let mut callers = 0usize;
        let mut offenders = Vec::new();
        for path in &files {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            if !calls_it(&text) {
                continue;
            }
            callers += 1;
            // `spawn_launcher` counts: it is the one launch helper that prepares on its caller's
            // behalf, so a file handing it a command has already answered for its descriptors.
            let prepares = ["inherit_across_exec", "clear_cloexec", "spawn_launcher("]
                .iter()
                .any(|needle| text.contains(needle));
            if !prepares {
                offenders.push(path.display().to_string());
            }
        }
        assert!(
            offenders.is_empty(),
            "these stage a descriptor for bwrap and never prepare the exec that must inherit it, \
             so bwrap is handed a number that closed at the exec: {offenders:?}"
        );
        // The scan itself has to keep finding something: a rename that made `calls_it` match
        // nothing would leave this test green while guarding nothing at all.
        assert!(
            callers >= 4,
            "the scan found {callers} files staging a descriptor, so it is no longer looking at \
             the thing it guards"
        );
    }

    /// What bwrap will find: the bytes, from the start.
    #[test]
    fn the_bytes_are_readable_from_the_start() {
        let mut file = super::write(c"sbx-test", b"--setenv\0NAME\0value\0").expect("memfd");
        let mut read = Vec::new();
        file.read_to_end(&mut read).expect("read");
        assert_eq!(read, b"--setenv\0NAME\0value\0");
    }

    /// The descriptor this process holds is close-on-exec, so a cage standing up while another
    /// spawns inherits nothing of its `--args` file.
    ///
    /// This is the half that is about *other* processes, and it is the half a flag read can answer.
    /// The half about bwrap is below, where the descriptor has to arrive despite this.
    #[test]
    fn the_parents_own_copy_is_close_on_exec() {
        let file = super::write(c"sbx-test", b"secret").expect("memfd");
        // SAFETY: querying the descriptor flags of a descriptor we own.
        let flags =
            unsafe { libc::fcntl(std::os::unix::io::AsRawFd::as_raw_fd(&file), libc::F_GETFD) };
        assert_ne!(
            flags & libc::FD_CLOEXEC,
            0,
            "an inheritable descriptor reaches every process spawned while it is open, not only \
             the bwrap it was made for"
        );
    }

    /// And the child of a prepared spawn reads it anyway — the whole point, and the thing a flag
    /// read cannot answer.
    ///
    /// Asked of a real exec rather than of the flag, because what has to hold is that bwrap finds
    /// the descriptor its own argument list names by number. The control arm is the same spawn
    /// without the preparation, which must find nothing: without it this test would pass on a build
    /// that never clears the flag *and* on one that never sets it.
    #[test]
    fn a_prepared_spawn_hands_the_descriptor_to_its_child_and_a_bare_one_does_not() {
        use std::os::unix::io::AsRawFd;

        let file = super::write(c"sbx-test", b"the-bytes").expect("memfd");
        let fd = file.as_raw_fd();
        let read_it = format!("cat /proc/self/fd/{fd}");

        let mut prepared = Command::new("/bin/sh");
        prepared.arg("-c").arg(&read_it);
        super::inherit_across_exec(&mut prepared, std::slice::from_ref(&file));
        let out = prepared.output().expect("the prepared child runs");
        assert_eq!(
            out.stdout, b"the-bytes",
            "bwrap reads this descriptor by number; the child must find it"
        );

        let bare = Command::new("/bin/sh")
            .arg("-c")
            .arg(&read_it)
            .output()
            .expect("the bare child runs");
        assert!(
            bare.stdout.is_empty(),
            "an unprepared spawn must inherit nothing: {:?}",
            String::from_utf8_lossy(&bare.stdout)
        );
    }
}
