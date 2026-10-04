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

/// Write `bytes` into an anonymous in-memory file, rewound, to be handed to another process over a
/// socket rather than to an exec.
///
/// The same file as [`write()`], under a name of its own because the guard over [`write()`] admits
/// only the composition of a cage among its callers, and a file handed over a socket has no exec to
/// prepare: the receiver gets its own copy with the message that carries it. It stays
/// close-on-exec here, and the caller drops it once it is sent, since it may hold a credential set.
/// No seal: the receiver trusts the writer and copies the file once.
pub(super) fn handed(name: &CStr, bytes: &[u8]) -> io::Result<std::os::fd::OwnedFd> {
    write(name, bytes).map(Into::into)
}

/// Let the exec `command` performs inherit `files`, and only that one.
///
/// Registered as a `pre_exec` closure, which `std` runs in the child between the fork and the
/// `execvp` — on `Command::spawn` and on `CommandExt::exec` alike, since both reach the same
/// `do_exec`. The parent's copies keep the flag, so a cage standing up while this one spawns
/// inherits nothing.
///
/// `files` are **taken**: the closure owns them, so they stay open exactly as long as `command`
/// does. The child clears the flag by descriptor number, and a file dropped before the fork would
/// leave it clearing the flag on whatever took that number; owned by the command, none can be, and
/// `std` never drops the closure in the child, which either execs or exits. Dropping `command` once
/// it has spawned is what closes this process's copies.
pub(crate) fn inherit_across_exec(command: &mut Command, files: Vec<File>) {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::process::CommandExt as _;

    let fds: Vec<libc::c_int> = files.iter().map(|f| f.as_raw_fd()).collect();
    // SAFETY: the closure runs in the child between fork and exec, where only async-signal-safe
    // calls are allowed. It calls `fcntl` and, on failure, `Error::last_os_error`, which reads
    // `errno` and allocates nothing. Naming `files` only moves them into the closure.
    unsafe {
        command.pre_exec(move || {
            let _owned = &files;
            match clear_cloexec(&fds) {
                true => Ok(()),
                false => Err(io::Error::last_os_error()),
            }
        });
    }
}

/// Let the exec `command` performs inherit `files` and nothing else of what this process holds.
///
/// [`inherit_across_exec`] is enough where the spawning process opened nothing it did not mean to
/// hand on. One that holds descriptors another exec of its own needs, without the flag, would pass
/// them to this one too: every descriptor past the standard three is marked close-on-exec in the
/// child first, then the flag is cleared on `files`. Registered before, so it runs before. The
/// parent's copies are its own, and keep what they had. `files` are taken, as there.
pub(crate) fn inherit_only(command: &mut Command, files: Vec<File>) {
    use std::os::unix::process::CommandExt as _;
    // SAFETY: the closure runs in the child between fork and exec, where only async-signal-safe
    // calls are allowed. `close_range`, `getrlimit` and `fcntl` are system calls that take no lock
    // and allocate nothing.
    unsafe {
        command.pre_exec(|| {
            mark_close_on_exec_past_the_standard_three();
            Ok(())
        });
    }
    inherit_across_exec(command, files);
}

/// Mark every descriptor past the standard three close-on-exec, in one call where the kernel has
/// it (5.11), and one at a time below the descriptor limit where it does not. Called between a fork
/// and an exec, so it reads no directory and allocates nothing: a number that is not open answers
/// `EBADF`.
fn mark_close_on_exec_past_the_standard_three() {
    // SAFETY: `close_range` takes no pointer.
    let marked = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if marked == 0 {
        return;
    }
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `getrlimit` writes the one `rlimit` it is handed.
    let top = match unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } {
        0 => limit.rlim_cur.min(1 << 20),
        _ => 1 << 20,
    };
    for fd in 3..top as libc::c_int {
        // SAFETY: `fcntl` with `F_SETFD` on a number this child holds, or `EBADF`.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
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

/// Give the program about to be exec'd the signal state a program starts from: `SIGPIPE` back at
/// its default, and nothing blocked.
///
/// Both cross an `exec`. The Rust runtime ignores `SIGPIPE` in every sbx process, and a raw `fork`
/// copies the calling thread's mask. `Command` resets both in its child, and the three execs sbx
/// writes by hand did not: the pty supervisor's child, the netns holder becoming bubblewrap, and
/// the attached command. bubblewrap and `systemd-run --scope` pass both on as they find them, so a
/// cage started through any of the three ran with `SIGPIPE` ignored, which a
/// program cannot take back once it starts (POSIX lets an inherited ignore stand), and `yes | head
/// -1` answered `EPIPE` in a loop where it would have died. Called on the child side of a fork:
/// `signal`, `sigemptyset` and `sigprocmask` are async-signal-safe. Best effort, since a failure
/// leaves the state as it was, which is no worse than before.
pub(crate) fn default_signals_across_exec() {
    // SAFETY: `signal` with `SIG_DFL` installs no handler; the set is a local, emptied before
    // `sigprocmask` reads it.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        let mut none: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut none);
        libc::sigprocmask(libc::SIG_SETMASK, &none, std::ptr::null_mut());
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::process::Command;

    /// Each exec sbx writes by hand calls [`super::default_signals_across_exec`] first. The three
    /// sites are pinned against their source: an exec that skipped it fails nothing else, since the
    /// cage still starts, with `SIGPIPE` ignored.
    #[test]
    fn every_hand_written_exec_resets_the_signal_state() {
        for (file, source) in [
            ("launch/cage.rs", include_str!("launch/cage.rs")),
            ("netns.rs", include_str!("netns.rs")),
            ("attach.rs", include_str!("attach.rs")),
        ] {
            assert!(
                crate::testutil::production_half(source).contains("default_signals_across_exec();"),
                "`{file}` execs by hand and must reset the signal state first"
            );
        }
    }

    /// A program exec'd by hand starts from the default signal state: `SIGPIPE` no longer ignored,
    /// nothing blocked. The child starts from what sbx has, which the Rust runtime set and a
    /// forking thread may add to, and answers by its exit code which part did not reset.
    #[test]
    fn a_hand_written_exec_hands_on_the_default_signal_state() {
        // SAFETY: the child runs `signal`, the `sigset_t` calls, `sigprocmask`, `sigaction` and
        // `_exit`, all async-signal-safe, on locals.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            unsafe {
                libc::signal(libc::SIGPIPE, libc::SIG_IGN);
                let mut term: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut term);
                libc::sigaddset(&mut term, libc::SIGTERM);
                libc::sigprocmask(libc::SIG_BLOCK, &term, std::ptr::null_mut());

                super::default_signals_across_exec();

                let mut pipe: libc::sigaction = std::mem::zeroed();
                libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut pipe);
                let mut blocked: libc::sigset_t = std::mem::zeroed();
                libc::sigprocmask(libc::SIG_BLOCK, std::ptr::null(), &mut blocked);
                let code = i32::from(pipe.sa_sigaction != libc::SIG_DFL)
                    | (i32::from(libc::sigismember(&blocked, libc::SIGTERM) == 1) << 1);
                libc::_exit(code);
            }
        }
        let mut status = 0;
        // SAFETY: the child forked above, reaped once.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "the child did not exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "1: SIGPIPE still ignored, 2: SIGTERM still blocked, 3: both"
        );
    }

    /// Only the composition stages a descriptor for bwrap: every file [`super::write`] makes for
    /// an exec is made by [`crate::sandbox::argv::compose`]'s own steps, the environment's in
    /// `argv.rs` and the filters' in `seccomp.rs`, or by
    /// [`crate::sandbox::argv::CageCommand::stage`] for what a wrapper is handed, and leaves inside
    /// a [`crate::sandbox::argv::CageCommand`], whose only ways out hand it to the exec.
    ///
    /// This asked the other question before: whether every file that stages one also prepares the
    /// exec that inherits it. That needed a list of the ways to stage one, and the list was short
    /// twice, once missing two harnesses that spawned bubblewrap directly and once every plugin
    /// cage; both times a suite that launches real cages found what reading did not. The type now
    /// answers that question for every caller of `compose`, at compile time. What it cannot see is
    /// a descriptor made outside it: [`super::write`] and the filters' own entry points are visible
    /// to the whole of `sandbox`, and a file made there and handed to a `Command` by hand is the
    /// mistake the type exists to rule out, back by another door.
    ///
    /// Read on each file's production half, since a test that makes one to probe with starts
    /// nothing a binary ships. The limit, since a text scan has one: a caller that imports
    /// `write` under its bare name, or the module under another, is not seen.
    #[test]
    fn only_the_composition_stages_a_descriptor_for_bwrap() {
        const STAGES: &[&str] = &["src/sandbox/argv.rs", "src/sandbox/seccomp.rs"];
        let stages_one = |text: &str| {
            ["memfd::write(", "seccomp::memfds(", "ownership_noop_memfd("]
                .iter()
                .any(|needle| crate::testutil::calls_function(text, needle))
        };
        let root = format!("{}/", env!("CARGO_MANIFEST_DIR"));
        let declared_test_only = crate::testutil::test_only_sources();
        let mut staging: Vec<String> = crate::testutil::crate_sources()
            .into_iter()
            .filter(|file| {
                !crate::testutil::is_test_only_source(file) && !declared_test_only.contains(file)
            })
            .filter(|file| {
                let text = std::fs::read_to_string(file).unwrap_or_default();
                stages_one(crate::testutil::production_half(&text))
            })
            .map(|file| file.display().to_string().replacen(&root, "", 1))
            .collect();
        staging.sort();
        assert_eq!(
            staging, STAGES,
            "a descriptor for bwrap is made outside `compose`, where nothing hands it to the exec \
             that must inherit it; build the command with `argv::compose` instead"
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
        super::inherit_across_exec(&mut prepared, vec![file]);
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

    /// The files a command is prepared with are the command's: open for as long as it is, and
    /// closed with it. That is what lets no caller drop one before the spawn, and what closes this
    /// process's copies once the command that spawned is gone.
    #[test]
    fn a_prepared_command_holds_its_files_open_until_it_is_dropped() {
        use std::os::unix::fs::MetadataExt;
        // Asked by identity rather than by number: a number freed by a close is reused at once,
        // and other tests open descriptors on other threads.
        let open = |dev: u64, ino: u64| {
            std::fs::read_dir("/proc/self/fd")
                .expect("/proc/self/fd")
                .flatten()
                .any(|entry| {
                    std::fs::metadata(entry.path()).is_ok_and(|m| m.dev() == dev && m.ino() == ino)
                })
        };
        let file = super::write(c"sbx-test", b"held").expect("memfd");
        let meta = file.metadata().expect("the anonymous file's identity");
        let (dev, ino) = (meta.dev(), meta.ino());

        let mut command = Command::new("/bin/true");
        super::inherit_across_exec(&mut command, vec![file]);
        assert!(open(dev, ino), "the command holds the file it was handed");
        drop(command);
        assert!(!open(dev, ino), "and closes it when it goes");
    }

    /// A spawn prepared with `inherit_only` hands on the files it names and nothing else the
    /// spawning process holds without the flag, which `inherit_across_exec` alone lets through:
    /// the tap is started from a process holding the cage's descriptors for another exec.
    #[test]
    fn a_spawn_prepared_with_inherit_only_hands_on_its_files_and_no_other() {
        use std::os::unix::io::AsRawFd;

        use std::os::unix::process::CommandExt as _;
        const HELD: libc::c_int = 50;

        let stray = super::write(c"sbx-stray", b"stray").expect("memfd");
        let raw = stray.as_raw_fd();
        // Held for another exec, the way a holder keeps the cage's descriptors: a copy without the
        // flag, made in the child alone so no other test's spawn inherits it, and made first.
        let hold = |command: &mut Command| {
            // SAFETY: `dup2` is async-signal-safe, and `raw` is open for the whole spawn.
            unsafe {
                command.pre_exec(move || match libc::dup2(raw, HELD) {
                    HELD => Ok(()),
                    _ => Err(std::io::Error::last_os_error()),
                });
            }
        };
        // One handed file per command, since each command takes the one it hands on.
        let handed = || super::write(c"sbx-handed", b"handed").expect("memfd");
        let read_both = |handed: &std::fs::File| {
            format!(
                "cat /proc/self/fd/{}; cat /proc/self/fd/{HELD}",
                handed.as_raw_fd()
            )
        };

        let handed_across = handed();
        let mut across = Command::new("/bin/sh");
        across.arg("-c").arg(read_both(&handed_across));
        hold(&mut across);
        super::inherit_across_exec(&mut across, vec![handed_across]);
        let out = across.output().expect("the child runs");
        assert_eq!(
            out.stdout, b"handedstray",
            "the control: the stray one crosses"
        );

        let handed_only = handed();
        let mut only = Command::new("/bin/sh");
        only.arg("-c").arg(read_both(&handed_only));
        hold(&mut only);
        super::inherit_only(&mut only, vec![handed_only]);
        let out = only.output().expect("the child runs");
        assert_eq!(out.stdout, b"handed");
    }
}
