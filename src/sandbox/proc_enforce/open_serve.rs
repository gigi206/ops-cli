//! Answer an open the lens permitted — from the supervisor's own descriptor rather than by
//! letting the syscall re-resolve the path.
//!
//! This is the half that makes an allow sound, and it is mechanism rather than policy: it decides
//! nothing about content, only how a verdict already formed is delivered to the cage.

use std::io;
use std::time::Duration;

use super::cagepath::{caller_umask, open_target_path};
use super::notify::{notif_id_valid, notif_of, respond_errno, respond_with_fd};
use super::open_lens::{OpenLens, errno_describes_the_file, vouched_probe};
use super::target::{open_flags, open_mode, open_resolve};

/// Serve one allowed open from the descriptor the supervisor already holds, rather than letting the
/// syscall run again.
///
/// This is the whole point of the lens being sound on an *allow*. The verdict was formed against the
/// inode behind `probe`; reopening through `/proc/self/fd/<probe>` reaches that same inode without
/// walking a path, so the descriptor the cage receives is definitionally the one that was examined.
/// A `CONTINUE` answer would instead re-run the syscall from its arguments, and a sibling thread is
/// free to have rewritten them meanwhile.
///
/// Serving carries no authority the cage did not have: the probe was taken through
/// `/proc/<pid>/root` and then vouched for by [`vouched_probe`], so it sits on the cage's own
/// mounts, and a read-only bind refuses a write reopen with `EROFS` exactly as it would have refused
/// the cage. The prefix alone does not carry that far — a symlink target beginning with `/` restarts
/// the walk at this process's root — which is what the vouching is for.
///
/// Returns `false` when the call cannot be served this way, leaving the caller to answer `CONTINUE`
/// — which is the pre-existing behaviour, and with it the pre-existing race.
pub(super) fn serve_open(
    notif_fd: libc::c_int,
    req: &libc::seccomp_notif,
    dirfd: libc::c_int,
    path: &str,
    probe: Option<std::fs::File>,
) -> bool {
    let Some(probe) = probe else { return false };
    let Some(flags) = open_flags(
        req.pid,
        req.data.nr,
        &req.data.args,
        notif_of(notif_fd, req.id),
    ) else {
        return false;
    };
    let flags = flags as libc::c_int;
    // `O_TMPFILE` names a directory and asks for a new unnamed inode under it. There is no existing
    // file to serve, and the probe is not it.
    if flags & libc::O_TMPFILE == libc::O_TMPFILE {
        return false;
    }
    // An `openat2` may ask for a stricter walk than the one this supervisor performed: the probe
    // follows symlinks on purpose (a scan that stopped at a link would be walked around with one
    // `ln -s`), so serving from it would hand a caller that asked for `RESOLVE_NO_SYMLINKS` the
    // descriptor its own restriction was meant to refuse. The verdict is unaffected — the lens
    // judged the resolved target either way, and this is only reached for an open it permitted —
    // but a program inside the cage that hardened its own path walk must not have that hardening
    // quietly removed by being supervised. So the call is declined here and answered `CONTINUE`,
    // which runs the real `openat2` with the real `resolve` semantics; it joins the other flags
    // that cannot be carried onto a descriptor.
    //
    // What that costs, stated because the caller chooses it rather than merely encountering it: any
    // non-zero `resolve` word takes this branch, so a program in the cage that sets a bit costing it
    // nothing -- `RESOLVE_NO_MAGICLINKS` on a program that opens no magic link -- routes every one
    // of its opens back to `CONTINUE`, and with them back to the re-resolution that serving exists
    // to remove. The verdict still holds: a denied path is denied here, and only a permitted one
    // reaches this line. What is reachable is the window after an allow, where the path the lens
    // judged is walked a second time by the kernel and a sibling thread may have moved it.
    //
    // Left as it is, with the two alternatives named because neither is free. Refusing instead of
    // continuing would deny the hardened program the call it was entitled to, punishing the defence
    // this branch exists to preserve. Serving it properly means re-taking the probe with the
    // caller's own `resolve` word -- an `openat2` anchored by `RESOLVE_IN_ROOT` on a dirfd for
    // `/proc/<pid>/root`, which would also subsume what [`vouched_probe`] checks by hand -- and that
    // is a rewrite of the probe on the enforcement path, verifiable only where a cage can actually
    // run. The trigger to do it is a launch that needs `openat2` opens served rather than continued,
    // measured on a host that can run the cage: until then this is a window the supervisor narrows
    // for `open`/`openat` and does not narrow for a caller that asks the kernel for a stricter walk.
    match open_resolve(
        req.pid,
        req.data.nr,
        &req.data.args,
        notif_of(notif_fd, req.id),
    ) {
        Some(0) => {}
        _ => return false,
    }
    // The file exists — holding a descriptor on it is the proof — so `O_CREAT|O_EXCL` is precisely
    // the case the caller asked to be told about, and the errno it expects is the sound answer.
    if flags & libc::O_CREAT != 0 && flags & libc::O_EXCL != 0 {
        respond_errno(notif_fd, req.id, libc::EEXIST);
        return true;
    }
    // `O_NOFOLLOW` asks to fail when the final component is a symlink. The probe followed links on
    // purpose (a scan that stopped at the link would be walked around with one `ln -s`), and
    // `/proc/self/fd/<n>` is itself a link, so the flag cannot ride into the reopen. It is decided
    // here instead, against the same path, and answered the way the kernel would have.
    //
    // The final component's **type** is what settles it, asked with `lstat`. Asking instead whether
    // an `O_PATH | O_NOFOLLOW` open fails answers nothing: `open(2)` is explicit that the pair
    // *succeeds* on a symlink and hands back a descriptor referring to the link itself, so the one
    // case this guard exists to catch took the success path and the cage was served the probe —
    // which names the link's target. A program that opened its own log with `O_NOFOLLOW`, the
    // standard defence against having a file swapped for a link, had that defence removed by being
    // supervised. It is the same rule the `openat2` `resolve` check above states: a program that
    // hardened its own path walk must not have the hardening quietly dropped.
    //
    // Re-walking the path is a second resolution, and the cage may have moved it since. The two
    // outcomes of losing that race are a spurious `ELOOP` and serving the inode that was scanned —
    // never an open the lens did not examine, which is the property being defended.
    if flags & libc::O_NOFOLLOW != 0 {
        // Except with `O_PATH`, where the pair is not a refusal at all: the kernel answers it with a
        // descriptor for the link itself, which is neither `ELOOP` nor the inode the probe holds. It
        // joins the flags that cannot be carried onto a descriptor, and the real call runs.
        if flags & libc::O_PATH != 0 {
            return false;
        }
        let target = open_target_path(req.pid, dirfd, path);
        match std::fs::symlink_metadata(&target) {
            Ok(meta) if meta.file_type().is_symlink() => {
                respond_errno(notif_fd, req.id, libc::ELOOP);
                return true;
            }
            Ok(_) => {}
            // The path no longer resolves from here, which is the race above rather than a link.
            // Answered `ELOOP` all the same: the cage asked for the stricter walk, and the stricter
            // of the two answers is the one that cannot serve an inode this call did not establish.
            Err(_) => {
                respond_errno(notif_fd, req.id, libc::ELOOP);
                return true;
            }
        }
    }
    // `O_CREAT` on a file that exists is a no-op, and `O_NOFOLLOW` has just been answered. Our own
    // descriptor is always close-on-exec; what the *cage's* copy carries is set on the response.
    let reopen = (flags & !libc::O_CREAT & !libc::O_NOFOLLOW) | libc::O_CLOEXEC;
    let cloexec = flags & libc::O_CLOEXEC != 0;

    use std::os::unix::fs::FileTypeExt;
    let kind = probe.metadata().map(|m| m.file_type());
    let Ok(kind) = kind else { return false };

    // A socket inode cannot be opened at all: measured, `open` on one returns `ENXIO` whatever the
    // access mode. Answering it here is both the truthful reply and one less door, since no reopen
    // has to be attempted to know it.
    if kind.is_socket() {
        respond_errno(notif_fd, req.id, libc::ENXIO);
        return true;
    }

    // A FIFO is the one type whose open blocks by design, and the direction decides how. Measured
    // on a pipe with no peer at all, which is what the first reading of it got wrong: a probe left
    // waiting in one direction counts as a peer for the other, and made the write side look
    // instantaneous.
    //
    // - `O_RDWR` never blocks, so it is served here like any other.
    // - `O_WRONLY` blocks for a reader, and `O_NONBLOCK` reports `ENXIO` until one arrives — so a
    //   retry loop is *faithful* (the caller does wait for a reader) and bounded (it gives up when
    //   the notification stops being valid, which is when the target is gone).
    // - `O_RDONLY` blocks for a writer, and `O_NONBLOCK` succeeds immediately without one — so a
    //   retry loop would drift, letting the caller past and turning its first `read` into an EOF
    //   where the open should still have been waiting. Only a blocking open is faithful there.
    if kind.is_fifo() && flags & libc::O_ACCMODE != libc::O_RDWR {
        return park_open(notif_fd, req.id, probe, reopen, cloexec);
    }

    // A character or block device may wait on the hardware behind it (a serial line waiting for
    // carrier). `O_NONBLOCK` is the standard way to open one without hanging on that, and clearing
    // it afterwards restores what the caller asked for on the description it receives.
    let nonblock_dance =
        (kind.is_char_device() || kind.is_block_device()) && flags & libc::O_NONBLOCK == 0;
    let attempt = if nonblock_dance {
        reopen | libc::O_NONBLOCK
    } else {
        reopen
    };
    let served = reopen_probe(&probe, attempt);
    if served < 0 {
        // Whose failure is it? An errno about the *file* is one the cage would have met itself,
        // reopening the same inode on the same mounts under the same identity, so it is the answer
        // and the path is not walked again. An errno about the *opener* — this process out of
        // descriptors, the machine out of memory — says nothing about the cage, and inventing it
        // would fail an open that had every right to succeed. Only those fall back, and with them
        // the race, for a window the cage cannot arrange from inside.
        let e = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno_describes_the_file(e) {
            respond_errno(notif_fd, req.id, e);
            return true;
        }
        return false;
    }
    if nonblock_dance {
        // SAFETY: served is this call's live descriptor; F_SETFL only alters its status flags.
        unsafe {
            let cur = libc::fcntl(served, libc::F_GETFL);
            if cur >= 0 {
                libc::fcntl(served, libc::F_SETFL, cur & !libc::O_NONBLOCK);
            }
        }
    }
    let ok = respond_with_fd(notif_fd, req.id, served, cloexec);
    // SAFETY: served is a fresh owned descriptor; the kernel copied it into the target if it took
    // it at all, and either way this side is done with it.
    unsafe { libc::close(served) };
    ok
}

/// What came of trying to make the file an open named and the probe could not find.
pub(super) enum Creation {
    /// The file was made and its descriptor handed over; the notification is answered.
    Served,
    /// The name is there after all — put there by someone else while this was being decided — so
    /// the ordinary decision applies to it.
    Exists,
    /// The file was made, could not be handed over, and has been taken away again, leaving the
    /// name as the open found it. Nothing was answered, and the real syscall has to run.
    Unmade,
    /// Nothing was made, and nothing was answered.
    Declined,
}

/// Make, on the cage's behalf, the file its open named and the supervisor's probe could not find.
///
/// The probe that examines a path opens it `O_PATH`, which creates nothing — so a name that is not
/// there yet makes it fail, and the `ENOENT` it met is not the answer to an open carrying `O_CREAT`.
/// Measured against a control arm, that left a cage under `[fs] scan` unable to write a single new
/// file, which is most of what a build does.
///
/// Answering `CONTINUE` would be worse than the failure it fixes. Naming a file that is not there is
/// something a cage can do whenever it likes, so that answer would be a trigger in its hands — and
/// behind the answer sits the re-resolution a re-pointed path walks through.
///
/// So the file is made here, inside a directory this supervisor has vouched for by the same walk a
/// read goes through, and the descriptor is handed over. `O_EXCL` is added whether or not the cage
/// asked for it: it is what makes the served descriptor certainly empty, and an empty file certainly
/// carries no content a scan has not examined. Its `EEXIST` says the name appeared while this was
/// being decided, and such a file belongs to the ordinary decision rather than to this path.
///
/// A name that is a dangling symlink also answers `EEXIST`, so it takes the ordinary decision too
/// and is reported absent. The cage's own open would have created the link's target instead; making
/// it here would mean resolving that target on the cage's behalf, which is the walk this module
/// declines to make on anything it has not vouched for.
pub(super) fn serve_creation(
    notif_fd: libc::c_int,
    req: &libc::seccomp_notif,
    lens: &OpenLens,
    dirfd: libc::c_int,
    path: &str,
) -> Creation {
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let (Some(flags), Some(mode)) = (
        open_flags(
            req.pid,
            req.data.nr,
            &req.data.args,
            notif_of(notif_fd, req.id),
        ),
        open_mode(
            req.pid,
            req.data.nr,
            &req.data.args,
            notif_of(notif_fd, req.id),
        ),
    ) else {
        return Creation::Declined;
    };
    let flags = flags as libc::c_int;
    if flags & libc::O_CREAT == 0 {
        return Creation::Declined;
    }
    // The directory that will hold the name, and the name itself. The separator stays with the
    // directory so that `/x` asks for `/` rather than for the empty string.
    let (dir, base) = match path.rfind('/') {
        Some(cut) => (&path[..=cut], &path[cut + 1..]),
        None => (".", path),
    };
    if base.is_empty() || base == "." || base == ".." {
        return Creation::Declined;
    }
    let target = open_target_path(req.pid, dirfd, dir);
    let Ok(cdir) = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()) else {
        return Creation::Declined;
    };
    // SAFETY: cdir is a live NUL-terminated path for the duration of the call.
    let parent = unsafe {
        libc::open(
            cdir.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if parent < 0 {
        return Creation::Declined;
    }
    // SAFETY: parent is a fresh owned descriptor; the File takes sole ownership and closes it.
    let parent = unsafe { std::fs::File::from_raw_fd(parent) };
    // The same vouching a read gets: a directory reached through a walk that left the cage's mounts
    // is not one to create in, whatever it holds.
    // Never `own`: a file is created in a directory a mount vouches for, and no anonymous inode is
    // a directory to create in.
    let Ok(parent) = vouched_probe(lens, req.pid, parent, false) else {
        return Creation::Declined;
    };
    let Ok(cbase) = std::ffi::CString::new(base) else {
        return Creation::Declined;
    };
    // The kernel subtracts the *creating* process's umask from the mode, and the creating process
    // here is the supervisor rather than the cage. The two part company the moment the cage sets its
    // own — which is what a script writing a key does — so the caller's is applied here instead.
    // Measured under `[fs] scan` before this: a cage asking for `0600` under `umask 077` received
    // `0664`, group-readable and group-writable.
    let Some(umask) = caller_umask(req.pid) else {
        return Creation::Declined;
    };
    let wanted = mode as libc::c_uint & !umask;
    // `O_PATH` is dropped because this descriptor is the one the cage receives and has to be usable;
    // ours is always close-on-exec, and what the cage's copy carries is set on the response.
    let asked = (flags & !libc::O_PATH) | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC;
    // SAFETY: parent is a live directory descriptor and cbase a live NUL-terminated name.
    let made = unsafe { libc::openat(parent.as_raw_fd(), cbase.as_ptr(), asked, wanted) };
    if made < 0 {
        let e = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return if e == libc::EEXIST {
            Creation::Exists
        } else {
            Creation::Declined
        };
    }
    // The supervisor's own umask was subtracted by the kernel a moment ago, so the file may have
    // landed narrower than the cage asked. `fchmod` is not umask-governed and settles it exactly.
    // Widening rather than narrowing, and only after `O_EXCL` proved the file is this call's, so the
    // window before it is the narrower mode and never a wider one.
    // SAFETY: made is this call's live descriptor, and fchmod only alters its mode bits.
    unsafe { libc::fchmod(made, wanted as libc::mode_t) };
    let ok = respond_with_fd(notif_fd, req.id, made, flags & libc::O_CLOEXEC != 0);
    // SAFETY: made is a fresh owned descriptor; the kernel copied it into the target if it took it
    // at all, and either way this side is done with it.
    unsafe { libc::close(made) };
    if ok {
        return Creation::Served;
    }
    // The file was made but could not be handed over — the kernel has no `ADDFD_SEND`, or this one
    // notification could not take it. Leaving it there and falling into the ordinary decision was
    // the shape this had, and it answered `EEXIST` to an `O_CREAT|O_EXCL` open: the second pass
    // finds a file that is there, and `serve_open` reports the exclusivity failure the caller asked
    // to be told about — for a file the supervisor itself had just created a line earlier. The cage
    // is then told a name it holds exclusively is taken, which is the one answer it acts on.
    //
    // So the creation is undone and the syscall left to run for real. `O_EXCL` proved the file was
    // this call's when it was made, and it has been open and empty ever since.
    // SAFETY: parent is a live directory descriptor and cbase a live NUL-terminated name.
    unsafe { libc::unlinkat(parent.as_raw_fd(), cbase.as_ptr(), 0) };
    Creation::Unmade
}

/// Reopen the inode behind `probe` with `flags`, without walking a path.
///
/// `/proc/self/fd/<n>` names the descriptor's inode, not the name it was reached by, so this reaches
/// exactly what was examined however the cage has since rearranged its tree. Returns a raw
/// descriptor, or a negative value with `errno` set.
fn reopen_probe(probe: &std::fs::File, flags: libc::c_int) -> libc::c_int {
    use std::os::unix::io::AsRawFd;
    let by_fd = format!("/proc/self/fd/{}", probe.as_raw_fd());
    let Ok(c) = std::ffi::CString::new(by_fd) else {
        return -1;
    };
    // SAFETY: c is a live NUL-terminated path for the duration of the call.
    unsafe { libc::open(c.as_ptr(), flags) }
}

/// How many notified opens may be waiting on a blocking reopen at once.
///
/// The same shape as the `ask` registry's cap and for the same reason: a cage that can create pipes
/// can create them faster than anyone drains them, and a registry that grows with what the cage asks
/// for is a registry the cage sizes.
const PARKED_OPEN_CAP: usize = 64;

/// Opens currently parked on a thread of their own.
static PARKED_OPENS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How often a write-direction FIFO open asks again while it waits for a reader.
const FIFO_RETRY: Duration = Duration::from_millis(10);

/// Serve an open whose reopen may block, on a thread of its own.
///
/// The thread that decides is the one every other open in the cage is queued behind, so it must
/// never be the thread that waits. Answering from elsewhere is not new here: the `ask` registry
/// already has the control plane answer parked `execve`s while the receive loop keeps draining, and
/// the kernel serialises the ioctls that do it.
///
/// Over the cap the answer is `EACCES`, never `CONTINUE`. Falling back to `CONTINUE` under pressure
/// would hand the cage the door back by the simple act of asking for too much at once, which is a
/// door that opens *wider* the harder it is pushed.
///
/// The notification descriptor is duplicated for the thread rather than shared. A parked open can
/// outlive the supervisor's own descriptor, and answering through a number that has since been
/// closed and handed to something else would send an ioctl to whatever now holds it.
pub(super) fn park_open(
    notif_fd: libc::c_int,
    id: u64,
    probe: std::fs::File,
    reopen: libc::c_int,
    cloexec: bool,
) -> bool {
    use std::sync::atomic::Ordering;
    if PARKED_OPENS.fetch_add(1, Ordering::SeqCst) >= PARKED_OPEN_CAP {
        PARKED_OPENS.fetch_sub(1, Ordering::SeqCst);
        respond_errno(notif_fd, id, libc::EACCES);
        return true;
    }
    // SAFETY: notif_fd is the supervisor's live notification descriptor; the copy is owned by the
    // thread below, which closes it.
    let own_fd = unsafe { libc::dup(notif_fd) };
    if own_fd < 0 {
        PARKED_OPENS.fetch_sub(1, Ordering::SeqCst);
        return false;
    }
    let write_side = reopen & libc::O_ACCMODE == libc::O_WRONLY;
    std::thread::spawn(move || {
        let served = if write_side {
            // Faithful *and* bounded: `ENXIO` means no reader yet, and the wait ends either when one
            // arrives or when the notification stops being valid, which is when the caller is gone.
            loop {
                let fd = reopen_probe(&probe, reopen | libc::O_NONBLOCK);
                if fd >= 0 {
                    // SAFETY: fd is this thread's live descriptor; F_SETFL only alters status flags.
                    unsafe {
                        let cur = libc::fcntl(fd, libc::F_GETFL);
                        if cur >= 0 {
                            libc::fcntl(fd, libc::F_SETFL, cur & !libc::O_NONBLOCK);
                        }
                    }
                    break fd;
                }
                if io::Error::last_os_error().raw_os_error() != Some(libc::ENXIO)
                    || !notif_id_valid(own_fd, id)
                {
                    break -1;
                }
                std::thread::sleep(FIFO_RETRY);
            }
        } else {
            // The read direction has no faithful poll, so this blocks exactly as the cage would
            // have. It ends when a writer arrives; a pipe no writer ever joins holds this thread for
            // as long as the supervisor lives, which is the price of not lying to the caller about
            // whether its open completed.
            reopen_probe(&probe, reopen)
        };
        if served >= 0 {
            respond_with_fd(own_fd, id, served, cloexec);
            // SAFETY: served is this thread's owned descriptor, closed exactly once.
            unsafe { libc::close(served) };
        } else {
            respond_errno(own_fd, id, libc::EACCES);
        }
        // SAFETY: own_fd is this thread's duplicate, closed exactly once.
        unsafe { libc::close(own_fd) };
        PARKED_OPENS.fetch_sub(1, Ordering::SeqCst);
    });
    true
}
