use super::*;

#[test]
fn each_open_form_is_read_from_its_own_registers() {
    // Distinctive values so a wrong register is visible rather than plausible.
    let args: [u64; 6] = [11, 22, 33, 44, 55, 66];

    #[cfg(target_arch = "x86_64")]
    assert_eq!(
        open_args(libc::SYS_open as libc::c_int, &args),
        Some((libc::AT_FDCWD, 11)),
        "`open(path, …)` carries no descriptor: the path is the first argument, and the form is              implicitly relative to the working directory"
    );
    assert_eq!(
        open_args(libc::SYS_openat as libc::c_int, &args),
        Some((11, 22)),
        "`openat(dirfd, path, …)` leads with the descriptor, so the path is the second argument"
    );
    assert_eq!(
        open_args(libc::SYS_openat2 as libc::c_int, &args),
        Some((11, 22)),
        "`openat2` agrees with `openat` on the first two arguments"
    );
}

#[test]
fn a_syscall_that_is_not_an_open_is_left_to_the_exec_path() {
    let args: [u64; 6] = [11, 22, 33, 44, 55, 66];
    assert_eq!(
        open_args(libc::SYS_execve as libc::c_int, &args),
        None,
        "the same receive loop carries `execve`, which must fall through to the exec policy              rather than be read as a path to scan"
    );
    assert_eq!(open_args(libc::SYS_read as libc::c_int, &args), None);
}

#[test]
fn ending_supervision_denies_what_is_still_parked_before_closing_their_descriptor() {
    // A parked entry holds the descriptor it will be answered through, and the receive loop can
    // return with entries still registered — on stop, or when the cage's filter goes away with
    // a decision outstanding. Closing first left those entries pointing at a number the process
    // may since have reissued, and left a target parked at teardown with no verdict from sbx at
    // all. Draining first is the fail-closed order.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a live two-element array, which is what `pipe` fills.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "the pipe opens");
    let (read_end, write_end) = (fds[0], fds[1]);

    let pending = PendingExec::new();
    pending.park(read_end, 1, 4242, "/bin/ls");
    pending.park(read_end, 2, 4243, "/bin/cat");
    assert_eq!(pending.list().len(), 2, "both parks are registered");

    // Answering a pipe is not answering a seccomp listener: `notif_id_valid` refuses it, so no
    // response is written. What is under test is the registry being emptied, and the descriptor
    // being closed only after it is.
    close_supervision(read_end, &pending);
    assert!(
        pending.list().is_empty(),
        "nothing may outlive the descriptor it answers through: {:?}",
        pending.list()
    );

    // SAFETY: both are this test's own descriptors. The first close proves `close_supervision`
    // already closed the read end; the second releases the write end.
    assert_eq!(
        unsafe { libc::close(read_end) },
        -1,
        "the descriptor was closed by the teardown"
    );
    unsafe { libc::close(write_end) };
}

/// The parked registry is the third producer on the line-based control wire that
/// `ExecRing::push_verdict` guards, and it was the one written apart. `dispatch_enforced` renders
/// a park as `pending id=… pid=… path={path}` and the client reads the reply with `.lines()`,
/// stopping at the first bare `ok` — so a newline in a target the cage named would end the row
/// and let what follows read as another park that never happened, or hide a real one behind it.
#[test]
fn a_parked_path_carries_no_byte_that_could_forge_a_row_on_the_wire() {
    let pending = PendingExec::new();
    // A path may legally carry a newline on Linux, and this one is read out of the cage's own
    // memory — so this is a name a hostile cage can simply give itself.
    let forged = "/tmp/a\npending id=99 pid=1 waiting=0 path=/bin/ls\nok";
    // A real descriptor, because a park now takes a `dup` of the one it is answered through and
    // an entry it cannot duplicate is refused rather than registered. Nothing is ever answered
    // here: the registry is under its cap, so `park` only inserts.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a live two-element array, which is what `pipe` fills.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "the pipe opens");
    let (read_end, write_end) = (fds[0], fds[1]);
    pending.park(read_end, 1, 4242, forged);

    let listed = pending.list();
    assert_eq!(listed.len(), 1, "the park is registered");
    let path = &listed[0].2;
    assert!(
        !path.chars().any(char::is_control),
        "a parked path reached the wire with a control byte: {path:?}"
    );
    assert_eq!(
        path, "/tmp/a pending id=99 pid=1 waiting=0 path=/bin/ls ok",
        "replaced rather than dropped, so what the cage asked to run is still legible"
    );

    // SAFETY: both are this test's own descriptors, each closed exactly once; the entry's own
    // dup is closed when the registry drops with this scope.
    unsafe {
        libc::close(read_end);
        libc::close(write_end);
    }
}

#[test]
fn each_exec_form_is_read_from_its_own_registers() {
    // The shim notifies on both forms, and they disagree on argument order. Reading `execveat`'s
    // first register as a path address makes every `execveat` unnameable, and an unnameable
    // target takes the mode's unmatched default — `Allow` under the shipped denylist. So this is
    // the mapping a `deny` rests on, not a detail of it.
    let args: [u64; 6] = [11, 22, 33, 44, 55, 66];
    assert_eq!(
        exec_args(libc::SYS_execve as libc::c_int, &args),
        Some((libc::AT_FDCWD, 11)),
        "`execve(path, …)` carries no descriptor: the path is the first argument"
    );
    assert_eq!(
        exec_args(libc::SYS_execveat as libc::c_int, &args),
        Some((11, 22)),
        "`execveat(dirfd, path, …)` leads with the descriptor, so the path is the second \
         argument — reading the first would hand the policy a file descriptor as an address"
    );
}

#[test]
fn a_syscall_that_is_neither_an_open_nor_an_exec_is_decided_by_neither() {
    // The two mappings partition the five numbers the shim's filter notifies on, and agree that
    // anything else belongs to neither: the receive loop refuses such a notification instead of
    // judging it as an exec against a register that means something else.
    let args: [u64; 6] = [11, 22, 33, 44, 55, 66];
    for nr in [libc::SYS_read, libc::SYS_write, libc::SYS_ioctl] {
        assert_eq!(open_args(nr as libc::c_int, &args), None, "syscall {nr}");
        assert_eq!(exec_args(nr as libc::c_int, &args), None, "syscall {nr}");
    }
    // And the two families do not overlap: an open is never read as an exec, nor the reverse.
    assert_eq!(exec_args(libc::SYS_openat as libc::c_int, &args), None);
    assert_eq!(open_args(libc::SYS_execveat as libc::c_int, &args), None);
}

#[test]
fn an_absolute_path_is_read_through_the_targets_own_root() {
    assert_eq!(
        open_target_path(42, libc::AT_FDCWD, "/etc/passwd"),
        PathBuf::from("/proc/42/root/etc/passwd"),
        "an absolute cage path must be resolved in the cage's mount namespace, never against \
         the supervisor's own root"
    );
}

#[test]
fn a_relative_path_follows_the_descriptor_it_was_opened_against() {
    assert_eq!(
        open_target_path(42, libc::AT_FDCWD, "secrets/prod.key"),
        PathBuf::from("/proc/42/cwd/secrets/prod.key")
    );
    assert_eq!(
        open_target_path(42, 7, "prod.key"),
        PathBuf::from("/proc/42/fd/7/prod.key"),
        "a path opened against a directory fd is resolved through that fd, not the cwd"
    );
}

// The lint fires on the very call this test exists to pin: the point is to demonstrate that
// `join` discards the prefix, which is why `open_target_path` concatenates instead.
#[allow(clippy::join_absolute_paths)]
#[test]
fn an_absolute_path_never_takes_over_the_prefix() {
    // The trap this guards: `PathBuf::join` with an absolute argument discards everything to its
    // left, which would hand the supervisor its *own* /etc/shadow instead of the cage's.
    let joined = PathBuf::from("/proc/42/root").join("/etc/shadow");
    assert_eq!(
        joined,
        PathBuf::from("/etc/shadow"),
        "join really does drop the prefix — which is why the absolute arm concatenates"
    );
    assert_eq!(
        open_target_path(42, libc::AT_FDCWD, "/etc/shadow"),
        PathBuf::from("/proc/42/root/etc/shadow")
    );
}
