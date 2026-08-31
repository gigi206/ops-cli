use super::*;
use crate::proc_policy::ProcMode;
use crate::testutil::TmpDir;

#[test]
fn ioctl_codes_match_the_kernel_abi() {
    // Computed once against the struct sizes; pin the well-known x86_64/aarch64 values so a wrong
    // direction/size bit is caught here, not at runtime.
    // seccomp_notif = 80 bytes, seccomp_notif_resp = 24 bytes.
    assert_eq!(std::mem::size_of::<libc::seccomp_notif>(), 80);
    assert_eq!(std::mem::size_of::<libc::seccomp_notif_resp>(), 24);
    // _IOWR('!', 0, seccomp_notif) = 0xC0502100; _IOWR('!', 1, resp) = 0xC0182101;
    // _IOW('!', 2, u64) = 0x40082102.
    assert_eq!(notif_recv_code(), 0xC050_2100);
    assert_eq!(notif_send_code(), 0xC018_2101);
    assert_eq!(notif_id_valid_code(), 0x4008_2102);
}

/// Run `payload` under a supervisor whose content lens carries `patterns`, draining every
/// notification until the payload exits.
///
/// Unlike the exec harness, the notification count cannot be fixed in advance: the open lens
/// also traps the loader's own opens, whose number belongs to the host's libc rather than to
/// this test. So the loop drains until the child is gone.
fn run_with_open_lens(
    payload: &[&str],
    patterns: &[&str],
    root: &std::path::Path,
) -> (Option<i32>, String) {
    let dir = TmpDir::new();
    let shim = materialized_shim(&dir);
    let sock_path = dir.join("notif.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind the handoff socket");

    let mut cmd = std::process::Command::new(&shim);
    cmd.arg(&sock_path)
        .arg(OPEN_LENS_FLAG)
        .arg("--")
        .args(payload)
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut child = spawn_shim(&mut cmd);

    let (sock, _) = listener.accept().expect("the shim never connected");
    let notif = recv_fd(&sock).expect("receive the listener fd");

    let owned: Vec<String> = patterns.iter().map(|p| (*p).to_string()).collect();
    let lens = OpenLens::new(
        crate::open_policy::OpenPolicy::compile(&owned, crate::open_policy::MAX_SCAN_DEFAULT)
            .expect("the test patterns compile")
            .expect("a non-empty list yields a policy"),
        // The caller's fixture directory is the "project" here: everything else the payload
        // opens — its loader, its libc — is out of scope exactly as the store is in a real
        // launch. Canonicalised because the bound is applied to a resolved path.
        std::fs::canonicalize(root).expect("canonical fixture root"),
    );
    // Nothing is denied by exec policy here: the lens is what the test is about.
    let policy = ProcPolicy::new(ProcMode::Enforce, &[], &[]);
    let overlay = ProcOverlay::new();
    let ring = Arc::new(ExecRing::new(64));
    let pending = Arc::new(PendingExec::new());

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        if let Some(st) = child.try_wait().expect("poll the payload") {
            break Some(st);
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            break None;
        }
        if !poll_readable(notif, 50) {
            continue;
        }
        let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::ioctl(notif, notif_recv_code() as libc::Ioctl, &mut req) };
        if rc >= 0 {
            handle_notif(
                notif,
                &req,
                &Deciding {
                    policy: &policy,
                    overlay: &overlay,
                    ring: &ring,
                    pending: &pending,
                    notifier: &crate::sandbox::notify_sink::Notifier::disabled(),
                    open: Some(&lens),
                    undecidable: &Undecidable::default(),
                },
            );
        }
    };
    // SAFETY: notif is this test's owned descriptor, closed exactly once.
    unsafe { libc::close(notif) };
    let out = child
        .wait_with_output()
        .expect("collect the payload output");
    let code = status.and_then(|s| s.code());
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (code, text)
}

#[test]
fn an_allowed_open_hands_the_cage_the_inode_that_was_scanned() {
    // The property this defends is what makes an *allow* mean anything. The supervisor forms its
    // verdict against an inode, and the cage must receive a descriptor for that inode — not for
    // whatever the path it wrote names once the answer is given.
    //
    // The adversary here is a symlink flipped under the cage's feet, which races the same window
    // a sibling thread rewriting the path argument would: the supervisor scans what the link
    // pointed at, and the answer decides whether the kernel gets to walk the link a second time.
    // Answering `CONTINUE` lets it, and the secret crosses; serving the scanned descriptor does
    // not, and there is no second walk to redirect.
    use std::sync::atomic::{AtomicBool, Ordering};
    const SECRET: &str = "sk-ABC123DEF456GHI789";
    const ROUNDS: usize = 400;

    let dir = TmpDir::new();
    let secret = dir.join("secret.txt");
    std::fs::write(&secret, format!("API key: {SECRET}\n")).expect("write the secret fixture");
    let door = dir.join("door");
    std::os::unix::fs::symlink(&secret, &door).expect("plant the door");

    let stop = Arc::new(AtomicBool::new(false));
    let flipper = {
        let (stop, dir_path, door, secret) = (
            Arc::clone(&stop),
            dir.join(".").to_path_buf(),
            door.clone(),
            secret.clone(),
        );
        std::thread::spawn(move || {
            let mut n = 0usize;
            while !stop.load(Ordering::Relaxed) {
                // A fresh inode for the clean side every flip, so its verdict is never answered
                // from the cache: a cached answer skips the read, and the read is the widest
                // part of the window this test has to be able to lose. Kept small, because the
                // flip rate matters more here than the length of any one scan.
                let clean = dir_path.join(format!("clean-{}.txt", n % 64));
                n += 1;
                if std::fs::write(&clean, vec![b'.'; 4096]).is_err() {
                    return;
                }
                for target in [clean.as_path(), secret.as_path()] {
                    let tmp = dir_path.join("door.tmp");
                    let _ = std::fs::remove_file(&tmp);
                    if std::os::unix::fs::symlink(target, &tmp).is_ok() {
                        let _ = std::fs::rename(&tmp, &door);
                    }
                }
            }
        })
    };

    let script = format!(
        "i=0; while [ $i -lt {ROUNDS} ]; do /bin/cat {} 2>/dev/null; i=$((i+1)); done",
        door.to_str().expect("utf-8 fixture path")
    );
    let (_, out) = run_with_open_lens(
        &["/bin/sh", "-c", &script],
        &[r"sk-[A-Za-z0-9]{12,}"],
        &dir.join("."),
    );
    stop.store(true, Ordering::Relaxed);
    flipper.join().expect("the flipper thread");

    assert!(
        !out.contains(SECRET),
        "the cage received a descriptor for a file the supervisor never scanned: the verdict was \
         formed against one inode and the open landed on another"
    );
}

#[test]
fn a_non_regular_first_target_no_longer_lets_the_swap_through() {
    // The door increment one left open, and the cheapest one to walk: the supervisor decides on
    // the path it read, so the cage picks what that path names *first*. Naming something the
    // supervisor could not serve from a descriptor sent the answer back to `CONTINUE`, and the
    // kernel then walked the path again onto whatever the cage had swapped in.
    //
    // A unix socket is the sharpest form of it. Its open fails whatever happens, so nothing here
    // depends on timing or on a peer: the only question is *which* file the failure is about.
    // Answered from the descriptor, it is the socket, every time. Answered with `CONTINUE`, it
    // is whatever the link points at by then, and that is a regular file holding a secret.
    use std::sync::atomic::{AtomicBool, Ordering};
    const SECRET: &str = "sk-ABC123DEF456GHI789";
    const ROUNDS: usize = 400;

    let dir = TmpDir::new();
    let secret = dir.join("secret.txt");
    std::fs::write(&secret, format!("API key: {SECRET}\n")).expect("write the secret fixture");
    let sock_path = dir.join("stand-in.sock");
    let _sock = UnixListener::bind(&sock_path).expect("bind the stand-in socket");
    let door = dir.join("door");
    std::os::unix::fs::symlink(&secret, &door).expect("plant the door");

    let stop = Arc::new(AtomicBool::new(false));
    let flipper = {
        let (stop, dir_path, door, secret, sock_path) = (
            Arc::clone(&stop),
            dir.join(".").to_path_buf(),
            door.clone(),
            secret.clone(),
            sock_path.clone(),
        );
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                for target in [sock_path.as_path(), secret.as_path()] {
                    let tmp = dir_path.join("door.tmp");
                    let _ = std::fs::remove_file(&tmp);
                    if std::os::unix::fs::symlink(target, &tmp).is_ok() {
                        let _ = std::fs::rename(&tmp, &door);
                    }
                }
            }
        })
    };

    let script = format!(
        "i=0; while [ $i -lt {ROUNDS} ]; do /bin/cat {} 2>/dev/null; i=$((i+1)); done",
        door.to_str().expect("utf-8 fixture path")
    );
    let (_, out) = run_with_open_lens(
        &["/bin/sh", "-c", &script],
        &[r"sk-[A-Za-z0-9]{12,}"],
        &dir.join("."),
    );
    stop.store(true, Ordering::Relaxed);
    flipper.join().expect("the flipper thread");

    assert!(
        !out.contains(SECRET),
        "naming a socket first sent the answer back to a path walk, and the walk landed on the \
         secret: a target the supervisor cannot read is still a target it must answer for"
    );
}

#[test]
fn an_absent_first_target_is_answered_rather_than_walked_again() {
    // The cheapest door of the three, because it needs no special file at all: point the name at
    // nothing while the answer is being formed, and a `CONTINUE` would send the kernel back down
    // the path once the secret is behind it.
    //
    // Both halves matter. The secret must not cross, and a missing file must still read as
    // missing: answering with the probe's own errno is only sound if it is the errno the cage
    // would have met.
    use std::sync::atomic::{AtomicBool, Ordering};
    const SECRET: &str = "sk-ABC123DEF456GHI789";
    const ROUNDS: usize = 400;

    let dir = TmpDir::new();
    let secret = dir.join("secret.txt");
    std::fs::write(&secret, format!("API key: {SECRET}\n")).expect("write the secret fixture");
    let nowhere = dir.join("nowhere.txt");
    let door = dir.join("door");
    std::os::unix::fs::symlink(&secret, &door).expect("plant the door");

    let stop = Arc::new(AtomicBool::new(false));
    let flipper = {
        let (stop, dir_path, door, secret, nowhere) = (
            Arc::clone(&stop),
            dir.join(".").to_path_buf(),
            door.clone(),
            secret.clone(),
            nowhere.clone(),
        );
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                for target in [nowhere.as_path(), secret.as_path()] {
                    let tmp = dir_path.join("door.tmp");
                    let _ = std::fs::remove_file(&tmp);
                    if std::os::unix::fs::symlink(target, &tmp).is_ok() {
                        let _ = std::fs::rename(&tmp, &door);
                    }
                }
            }
        })
    };

    let script = format!(
        "i=0; while [ $i -lt {ROUNDS} ]; do /bin/cat {} 2>&1; i=$((i+1)); done",
        door.to_str().expect("utf-8 fixture path")
    );
    let (_, out) = run_with_open_lens(
        &["/bin/sh", "-c", &script],
        &[r"sk-[A-Za-z0-9]{12,}"],
        &dir.join("."),
    );
    stop.store(true, Ordering::Relaxed);
    flipper.join().expect("the flipper thread");

    assert!(
        !out.contains(SECRET),
        "naming something absent sent the answer back to a path walk, and the walk landed on \
         the secret once it was put there"
    );
    assert!(
        out.contains("No such file"),
        "a path that is not there must still read as not there, or the errno being replied with \
         is not the one the cage would have met: {out}"
    );
}

#[test]
fn a_device_and_a_fifo_are_served_without_changing_what_the_cage_gets() {
    // The arms that carry the most machinery are also the ones that would break quietly: a cage
    // opens `/dev/null` constantly, and a FIFO read is served from a thread of its own. What is
    // asserted here is that neither behaves differently for being served.
    //
    // The `O_NONBLOCK` a character device is opened with is the supervisor's own doing, to avoid
    // hanging on hardware that waits; leaving it set on what the cage receives would turn a
    // blocking read into a spurious `EAGAIN` in the caller's hands.
    let dir = TmpDir::new();
    let pipe = dir.join("pipe");
    let c = std::ffi::CString::new(pipe.as_os_str().as_encoded_bytes()).expect("fixture path");
    // SAFETY: c is a live NUL-terminated path for the duration of the call.
    assert_eq!(
        unsafe { libc::mkfifo(c.as_ptr(), 0o600) },
        0,
        "make the fixture pipe"
    );

    // A writer for the whole run, so the read side completes rather than waiting for one, and a
    // bounded read so the payload ends rather than following the pipe forever.
    //
    // The wait for a reader is bounded the same way the supervisor bounds its own
    // write-direction open: `O_NONBLOCK` reports `ENXIO` until one arrives, so this asks again
    // rather than blocking in `open`. A blocking open here would be unbounded, and the `join`
    // below would then hold the whole test binary — not just this test — on any run where the
    // payload fails before it reaches the read side. That is a failure reported as a hang
    // rather than by name, and the deadline that would eventually catch it belongs to whatever
    // runs the suite.
    let writer = {
        let pipe = pipe.clone();
        std::thread::spawn(move || {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            let mut w = loop {
                match std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&pipe)
                {
                    Ok(w) => break w,
                    Err(_) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            };
            // The flag was for the open alone: the writes below are the ordinary blocking ones
            // the reader is meant to meet.
            use std::os::unix::io::AsRawFd;
            // SAFETY: w is this thread's live descriptor; F_SETFL only alters status flags.
            unsafe {
                let cur = libc::fcntl(w.as_raw_fd(), libc::F_GETFL);
                if cur >= 0 {
                    libc::fcntl(w.as_raw_fd(), libc::F_SETFL, cur & !libc::O_NONBLOCK);
                }
            }
            for _ in 0..200 {
                if w.write_all(b"pipebyte").is_err() {
                    return;
                }
            }
        })
    };

    // The two output files exist before the payload runs. Creating one from inside would be a
    // different subject: the supervisor examines a path with a probe that does not create, so a
    // name that is not there yet is a question it cannot answer on the open's behalf.
    //
    // Each `dd` is given an `of=`, and what it wrote is read back from there. Without one, `dd`
    // examines its output by opening `/dev/stdout` — a link into `/proc/self/fd`, which names
    // whichever process resolves it. That would make the arm depend on what the suite's own
    // output happens to be rather than on the property asserted here; `/dev/stdout` across the
    // cage boundary is a subject of its own, and belongs to a test that has a boundary to cross.
    for name in ["device.bin", "fifo.bin"] {
        std::fs::write(dir.join(name), b"").expect("place the output fixture");
    }
    let script = format!(
        "/bin/cat /dev/null; \
         /bin/dd if=/dev/urandom bs=4 count=1 of={1} 2>/dev/null; /bin/wc -c < {1}; \
         /bin/dd if={0} bs=8 count=1 of={2} 2>/dev/null; /bin/cat {2}",
        pipe.to_str().expect("utf-8 fixture path"),
        dir.join("device.bin").to_str().expect("utf-8 fixture path"),
        dir.join("fifo.bin").to_str().expect("utf-8 fixture path"),
    );
    let (code, out) = run_with_open_lens(
        &["/bin/sh", "-c", &script],
        &[r"sk-[A-Za-z0-9]{12,}"],
        &dir.join("."),
    );
    let _ = writer.join();

    assert_eq!(code, Some(0), "the payload must run to the end: {out}");
    // The whole output, not a substring of it: a lone `4` is a digit half the diagnostics in
    // this file could produce, and an assertion a failure can still satisfy proves nothing.
    assert_eq!(
        out.trim_end(),
        "4\npipebyte",
        "a device must still deliver its four bytes and a pipe what its writer sent"
    );
}

#[test]
fn self_and_thread_self_are_rewritten_to_the_caller_and_nothing_else_is() {
    // With this process as its own caller the two namespaces coincide, so what is pinned here is
    // the rewriting itself: which prefixes it claims, which it leaves alone, and that the two
    // forms differ — `self` names the group, `thread-self` the thread inside it.
    let me = std::process::id();
    let (tgid, tid) = caller_ids_in_cage(me).expect("this process has its own ids");
    assert_eq!(
        caller_proc_path(me, "/proc/self/maps").as_deref(),
        Some(format!("/proc/{tgid}/maps").as_str()),
        "`self` names the caller's thread group"
    );
    assert_eq!(
        caller_proc_path(me, "/proc/thread-self/status").as_deref(),
        Some(format!("/proc/{tgid}/task/{tid}/status").as_str()),
        "`thread-self` names the thread inside that group"
    );
    assert_eq!(
        caller_proc_path(me, "/proc/self").as_deref(),
        Some(format!("/proc/{tgid}").as_str()),
        "the directory itself is named too, not only what is under it"
    );
    // The prefix has to end where the component does, or a neighbouring name is captured with
    // it and the caller's own entry is served for a file that was never theirs.
    for untouched in [
        "/proc/selfish/maps",
        "/proc/thread-selfish",
        "/proc/1/maps",
        "/etc/passwd",
    ] {
        assert_eq!(
            caller_proc_path(me, untouched),
            None,
            "`{untouched}` does not name the caller"
        );
    }
    // A caller whose ids cannot be read leaves the path as it was, rather than being rewritten
    // against a number guessed for it.
    assert_eq!(caller_proc_path(u32::MAX, "/proc/self/maps"), None);
}

#[test]
fn a_link_is_spliced_where_it_sits_and_not_only_at_the_end() {
    // `/dev/fd/1` is not a link; `/dev/fd` is. A chase that only read the last component would
    // leave that one to the kernel, which resolves what it points at against this process — the
    // very resolution being avoided.
    let me = std::process::id();
    let at = libc::AT_FDCWD;
    assert_eq!(
        splice_first_link(me, at, "/dev/fd/1").as_deref(),
        Some("/proc/self/fd/1"),
        "the link is the directory, and what follows it rides along"
    );
    assert_eq!(
        splice_first_link(me, at, "/dev/stdout").as_deref(),
        Some("/proc/self/fd/1"),
        "a link that is the whole path is spliced too"
    );

    let dir = TmpDir::new();
    std::fs::write(dir.join("plain.txt"), b"x").expect("write the fixture");
    assert_eq!(
        splice_first_link(me, at, dir.join("plain.txt").to_str().expect("utf-8")),
        None,
        "a path with no link on it has nothing to splice"
    );
    // A relative target names something the ordinary walk already reaches, and following it here
    // would make this a resolution of its own.
    std::os::unix::fs::symlink("plain.txt", dir.join("near")).expect("plant the near link");
    assert_eq!(
        splice_first_link(me, at, dir.join("near").to_str().expect("utf-8")),
        None,
        "a relative target is left to the ordinary walk"
    );
}

#[test]
fn the_dev_links_arrive_at_the_callers_own_entry() {
    // What the chase exists for: none of these names says `self`, so the rewriting that handles
    // the spelled-out form cannot see them, and every one of them ends at `/proc/self/fd`.
    let me = std::process::id();
    let at = libc::AT_FDCWD;
    for (named, wanted) in [
        ("/dev/stdout", "/proc/self/fd/1"),
        ("/dev/stderr", "/proc/self/fd/2"),
        ("/dev/stdin", "/proc/self/fd/0"),
        ("/dev/fd/1", "/proc/self/fd/1"),
    ] {
        assert_eq!(
            proc_self_behind_a_link(me, at, named).as_deref(),
            Some(wanted),
            "`{named}` names the caller's own descriptor"
        );
    }
    assert_eq!(
        proc_self_behind_a_link(me, at, "/dev/null"),
        None,
        "a device that is not a link to `self` is left where it is"
    );
}

#[test]
fn the_umask_line_is_read_as_the_octal_it_is_written_in() {
    // `status` writes the mask in octal without a prefix, so reading it as decimal turns `0022`
    // into eighteen — a mask that clears bits nobody asked to clear, silently.
    assert_eq!(umask_of("Name:\tsh\nUmask:\t0022\nTgid:\t1\n"), Some(0o022));
    assert_eq!(umask_of("Umask:\t0077\n"), Some(0o077));
    assert_eq!(umask_of("Umask:\t0000\n"), Some(0));
    assert_eq!(
        umask_of("Name:\tsh\nTgid:\t1\n"),
        None,
        "a file without the line answers nothing rather than a mask of zero, which would be the \
         most permissive answer there is"
    );
}

#[test]
fn a_made_file_lands_with_the_masks_the_cage_asked_for() {
    // The file is made by the supervisor, so the kernel subtracts the *supervisor's* umask — and
    // the two part company the moment the cage sets its own, which is what a script writing a key
    // does. Both directions are pinned: a mask stricter than this process's has to be honoured,
    // and a mask looser than it must not be quietly narrowed by ours.
    use std::os::unix::fs::PermissionsExt;
    let dir = TmpDir::new();
    let (tight, wide) = (dir.join("tight.txt"), dir.join("wide.txt"));
    let script = format!(
        "umask 077; echo k > {}; umask 000; echo w > {}; echo done",
        tight.to_str().expect("utf-8 fixture path"),
        wide.to_str().expect("utf-8 fixture path"),
    );
    let (_, out) = run_with_open_lens(
        &["/bin/sh", "-c", &script],
        &[r"sk-[A-Za-z0-9]{12,}"],
        &dir.join("."),
    );
    assert!(
        out.contains("done"),
        "the payload must reach its last line: {out}"
    );
    let mode = |at: &std::path::Path| {
        std::fs::metadata(at)
            .unwrap_or_else(|e| panic!("the file must exist: {e}: {out}"))
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(
        mode(&tight),
        0o600,
        "a mask the cage tightened has to reach the file, or a key it meant to keep to itself \
         arrives readable: {out}"
    );
    assert_eq!(
        mode(&wide),
        0o666,
        "and a mask the cage widened must not be narrowed by this process's own, which the \
         kernel would otherwise subtract on top: {out}"
    );
}

#[test]
fn the_innermost_number_is_the_one_the_cage_uses() {
    // A cage's `status` names its tasks once per namespace it is in, outermost first. Reading
    // the first would name the task the way the *host* does, which is a number the cage's own
    // `/proc` has never heard of — so the last field is the one, and a file with a single field
    // has to keep working because that is what an uncaged process shows.
    assert_eq!(
        innermost_ids("Name:\tsh\nNStgid:\t2559290\t1\nNSpid:\t2559290\t1\n"),
        Some((1, 1)),
        "two namespaces: the cage's own numbers come last"
    );
    assert_eq!(
        innermost_ids("NStgid:\t4242\t17\t3\nNSpid:\t4242\t17\t5\n"),
        Some((3, 5)),
        "nested deeper, the innermost is still the last"
    );
    assert_eq!(
        innermost_ids("NStgid:\t4242\nNSpid:\t4242\n"),
        Some((4242, 4242)),
        "one namespace names the task once"
    );
    assert_eq!(
        innermost_ids("Name:\tsh\nNSpid:\t7\n"),
        None,
        "a file missing either line answers nothing rather than half"
    );
}

#[test]
fn each_open_form_keeps_its_mode_where_its_own_abi_puts_it() {
    // The mirror of the flags test, for the argument a creating open carries. Reading the wrong
    // register would make a file land with permissions the cage never asked for.
    let mut args = [0u64; 6];
    args[2] = 0o600;
    args[3] = 0o640;
    assert_eq!(
        open_mode(
            std::process::id(),
            libc::SYS_open as libc::c_int,
            &args,
            None
        ),
        Some(0o600),
        "`open` keeps its mode in the third argument"
    );
    assert_eq!(
        open_mode(
            std::process::id(),
            libc::SYS_openat as libc::c_int,
            &args,
            None
        ),
        Some(0o640),
        "`openat` leads with the descriptor, so its mode sits one along"
    );
    assert_eq!(
        open_mode(
            std::process::id(),
            libc::SYS_read as libc::c_int,
            &args,
            None
        ),
        None,
        "a syscall that is not an open has no mode to read"
    );
    // `openat2` carries the mode in the struct, and a `size` short of the whole struct describes
    // a call the kernel refuses with `EINVAL` before it reads a word of it.
    let how: [u64; 3] = [libc::O_CREAT as u64, 0o600, 0];
    let mut args2 = [0u64; 6];
    args2[2] = how.as_ptr() as u64;
    args2[3] = 8;
    assert_eq!(
        open_mode(
            std::process::id(),
            libc::SYS_openat2 as libc::c_int,
            &args2,
            None
        ),
        None,
        "a `size` the kernel refuses carries no mode, whatever sits at that address"
    );
    args2[3] = 16;
    assert_eq!(
        open_mode(
            std::process::id(),
            libc::SYS_openat2 as libc::c_int,
            &args2,
            None
        ),
        None,
        "and a struct that reaches the mode word but stops before the end of the version the \
         kernel accepts is refused just the same"
    );
    args2[3] = std::mem::size_of_val(&how) as u64;
    assert_eq!(
        open_mode(
            std::process::id(),
            libc::SYS_openat2 as libc::c_int,
            &args2,
            None
        ),
        Some(0o600),
        "the mode is the second field of `struct open_how`"
    );
}

/// The control buffer a descriptor handoff uses is handed back by `CMSG_FIRSTHDR` as a
/// `*mut cmsghdr`, so every field access through it is only defined if the storage is aligned
/// for one. It was a `[u8; 32]`, which is byte-aligned: aligned in practice on the targets sbx
/// builds for, and "in practice" is not what the rule says.
#[test]
fn the_handoff_control_buffer_is_aligned_for_the_header_it_is_read_as() {
    use std::mem::{align_of, size_of};
    assert!(
        align_of::<CmsgBuf>() >= align_of::<libc::cmsghdr>(),
        "a cmsg header is read out of this buffer: {} < {}",
        align_of::<CmsgBuf>(),
        align_of::<libc::cmsghdr>()
    );
    // And it still holds one header plus one descriptor, which is what it is sized for.
    // SAFETY: `CMSG_SPACE` reads nothing; it computes a size from a size.
    let needed = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize;
    assert!(
        size_of::<CmsgBuf>() >= needed,
        "{} < {needed}",
        size_of::<CmsgBuf>()
    );
}

/// An `openat2` may ask the kernel for a stricter path walk than the supervisor performed. The
/// probe follows symlinks by design, so a descriptor served from it is the result of the looser
/// walk: a caller that asked for `RESOLVE_NO_SYMLINKS` would be handed exactly what its own
/// restriction existed to refuse. Reading the third word of `struct open_how` is what lets
/// `serve_open` decline those and leave them to the kernel.
#[test]
fn each_open_form_states_the_path_walk_it_asked_for() {
    let mut args = [0u64; 6];
    assert_eq!(
        open_resolve(
            std::process::id(),
            libc::SYS_open as libc::c_int,
            &args,
            None
        ),
        Some(0),
        "`open` has no `resolve` word, so it restricts nothing"
    );
    assert_eq!(
        open_resolve(
            std::process::id(),
            libc::SYS_openat as libc::c_int,
            &args,
            None
        ),
        Some(0),
        "nor does `openat`"
    );
    assert_eq!(
        open_resolve(
            std::process::id(),
            libc::SYS_read as libc::c_int,
            &args,
            None
        ),
        None,
        "a syscall that is not an open asks for no walk at all"
    );
    let how: [u64; 3] = [libc::O_RDONLY as u64, 0, libc::RESOLVE_NO_SYMLINKS];
    args[2] = how.as_ptr() as u64;
    args[3] = std::mem::size_of_val(&how) as u64;
    assert_eq!(
        open_resolve(
            std::process::id(),
            libc::SYS_openat2 as libc::c_int,
            &args,
            None
        ),
        Some(libc::RESOLVE_NO_SYMLINKS),
        "the restriction is the third field of `struct open_how`"
    );
    // A `size` short of the third word was read here as a call asking for no restriction, on
    // the reasoning that the kernel reads a missing tail as zero. It does not: `openat2`
    // refuses any `size` below the first version of the struct, so such a call never runs — and
    // a supervisor that answered it with a served descriptor answered for the kernel.
    for short in [0, 8, 16, OPEN_HOW_VER0 - 1] {
        args[3] = short;
        assert_eq!(
            open_resolve(
                std::process::id(),
                libc::SYS_openat2 as libc::c_int,
                &args,
                None
            ),
            None,
            "a `size` of {short} is refused by the kernel, so there is no walk to establish"
        );
    }
}

/// The reader is only half of it: `serve_open` has to act on what it says. A restricted
/// `openat2` must be declined *before* any answer is formed, so the kernel performs the walk the
/// caller asked for; an unrestricted one must be served exactly as before.
///
/// The control is a socket inode, whose answer (`ENXIO`) is formed from the probe's type alone
/// and needs no live notification descriptor — so the only difference between the two arms is
/// the `resolve` word, which is the point.
#[test]
fn a_restricted_openat2_is_left_to_the_kernel_to_walk() {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = TmpDir::new();
    let sock_path = dir.join("probe.sock");
    let _listener = UnixListener::bind(&sock_path).expect("bind the probe socket");

    let serve = |resolve: u64| {
        // `O_PATH` is the only way to hold a descriptor on a socket inode, and it is how the
        // lens holds every probe.
        let probe = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(&sock_path)
            .expect("hold the socket inode");
        let how: [u64; 3] = [libc::O_RDONLY as u64, 0, resolve];
        let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        req.pid = std::process::id();
        req.data.nr = libc::SYS_openat2 as libc::c_int;
        req.data.args[2] = how.as_ptr() as u64;
        req.data.args[3] = std::mem::size_of_val(&how) as u64;
        // No notification descriptor: the arm under test forms its answer without one, and the
        // arm being excluded would need one.
        serve_open(-1, &req, libc::AT_FDCWD, "probe.sock", Some(probe))
    };

    assert!(
        serve(0),
        "an `openat2` asking for no restriction is served the way every other open is"
    );
    assert!(
        !serve(libc::RESOLVE_NO_SYMLINKS),
        "a caller that asked the kernel not to follow symlinks must not be handed the result of              a walk that did"
    );
    assert!(
        !serve(libc::RESOLVE_BENEATH),
        "the same holds for every other restriction this supervisor cannot reproduce"
    );
}

/// And an `openat2` whose `size` is below the struct's first version is left to the kernel too.
///
/// Such a call is refused with `EINVAL` before the path is looked at, so there is nothing to
/// serve it from and nothing the served descriptor could be the answer to. It used to be served
/// anyway: the `resolve` reader answered `Some(0)` for a short `size` — "the kernel reads the
/// missing tail as zero" — which is true of a struct the caller is *older* than and not of one
/// shorter than any version there has ever been. The cage received a descriptor for a syscall
/// that never ran.
///
/// The same socket-inode probe as above, whose answer is formed from the type alone and needs no
/// live notification descriptor — so the only difference between the arms is `size`.
#[test]
fn a_short_openat2_is_left_to_the_kernel_to_refuse() {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = TmpDir::new();
    let sock_path = dir.join("probe.sock");
    let _listener = UnixListener::bind(&sock_path).expect("bind the probe socket");

    let serve = |size: u64| {
        let probe = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(&sock_path)
            .expect("hold the socket inode");
        let how: [u64; 3] = [libc::O_RDONLY as u64, 0, 0];
        let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        req.pid = std::process::id();
        req.data.nr = libc::SYS_openat2 as libc::c_int;
        req.data.args[2] = how.as_ptr() as u64;
        req.data.args[3] = size;
        serve_open(-1, &req, libc::AT_FDCWD, "probe.sock", Some(probe))
    };

    assert!(
        serve(OPEN_HOW_VER0),
        "the shortest `size` the kernel accepts is still served the way every other open is"
    );
    for short in [0, 8, 16, OPEN_HOW_VER0 - 1] {
        assert!(
            !serve(short),
            "a `size` of {short} is refused by the kernel with `EINVAL`, so this supervisor \
             must not answer it with a descriptor of its own"
        );
    }
}

/// An `O_NOFOLLOW` open whose final component *is* a symlink is answered `ELOOP` here, because
/// this supervisor answers the flag itself and has to answer it the way the kernel would.
///
/// The guard used to ask whether an `O_PATH | O_NOFOLLOW` open **failed**, which is the one
/// question that cannot decide this: `open(2)` gives that pair a descriptor referring to the
/// symlink rather than an error, so the branch was dead for exactly the case it was written for
/// and the open fell through to be served from the probe — which was taken *without*
/// `O_NOFOLLOW` on purpose and names the link's target. A program in the cage that opened its
/// own file with `O_NOFOLLOW`, the standard defence against having it swapped for a link, had
/// that defence removed by being supervised.
///
/// The kernel semantics are asserted here too rather than trusted, because the whole defect was
/// a belief about them.
#[test]
fn an_open_that_asked_not_to_follow_a_link_is_refused_when_the_final_component_is_one() {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = TmpDir::new();
    let real = dir.join("real.txt");
    std::fs::write(&real, b"the file the cage meant to open\n").expect("write the fixture");
    let link = dir.join("link.txt");
    std::os::unix::fs::symlink(&real, &link).expect("plant the link");

    let c = std::ffi::CString::new(link.as_os_str().as_encoded_bytes()).expect("link path");
    // SAFETY: c is a live NUL-terminated path for the duration of the call.
    let on_the_link = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    assert!(
        on_the_link >= 0,
        "`O_PATH|O_NOFOLLOW` succeeds on a symlink — which is why a failed open can never be \
         the test for one"
    );
    // SAFETY: on_the_link is this test's own descriptor, closed exactly once.
    unsafe { libc::close(on_the_link) };

    let serve = |target: &Path| {
        // The probe the lens holds: opened without `O_NOFOLLOW`, so on the link it names the
        // file behind it. That is the descriptor that must not be handed over.
        let probe = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(target)
            .expect("hold the probe");
        let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        req.pid = std::process::id();
        req.data.nr = libc::SYS_openat as libc::c_int;
        req.data.args[2] = (libc::O_RDONLY | libc::O_NOFOLLOW) as u64;
        // An absolute path, resolved through this process's own `/proc/<pid>/root` exactly as a
        // cage's is resolved through the target's. No notification descriptor: the refusal
        // under test is formed without one, and the arm that is not refused needs one.
        serve_open(
            -1,
            &req,
            libc::AT_FDCWD,
            target.to_str().expect("utf-8 fixture path"),
            Some(probe),
        )
    };

    assert!(
        serve(&link),
        "an `O_NOFOLLOW` open of a symlink must be answered here — with the `ELOOP` the kernel \
         would have given — rather than served from a probe that followed the link"
    );
    assert!(
        !serve(&real),
        "and a final component that is not a link is not refused: no answer is formed here, so \
         the open goes on to be served like any other"
    );
}

#[test]
fn a_name_that_is_not_there_yet_is_made_rather_than_reported_absent() {
    // The probe that examines a path creates nothing, so a creating open finds its name absent
    // and would be told so. Both halves are asserted: the file has to appear with the bytes the
    // cage wrote, and a file that already carries a secret must still be refused — a lens that
    // answered every creating open by making the file would satisfy the first alone.
    let dir = TmpDir::new();
    let secret = dir.join("carries.txt");
    std::fs::write(&secret, b"API key: sk-ABC123DEF456GHI789\n").expect("write the fixture");

    let made = dir.join("made.txt");
    let script = format!(
        // The refused read is not last: its own failure is the point, and the exit code
        // asserted below is about the payload reaching its end rather than about that read.
        "echo neuf > {0}; echo made=$?; cat {0}; cat {1} 2>&1; echo fin",
        made.to_str().expect("utf-8 fixture path"),
        secret.to_str().expect("utf-8 fixture path"),
    );
    let (code, out) = run_with_open_lens(
        &["/bin/sh", "-c", &script],
        &[r"sk-[A-Za-z0-9]{12,}"],
        &dir.join("."),
    );
    assert_eq!(code, Some(0), "the payload must run to the end: {out}");
    assert!(
        out.contains("fin"),
        "the payload must reach its last line: {out}"
    );
    assert!(
        out.contains("made=0") && out.contains("neuf"),
        "the file must be created and carry what was written to it: {out}"
    );
    assert_eq!(
        std::fs::read_to_string(&made).expect("the file exists on this side too"),
        "neuf\n",
        "the file the cage was served has to be the one that appeared on disk"
    );
    assert!(
        !out.contains("sk-ABC123DEF456GHI789"),
        "a file that already carries a secret is still refused: {out}"
    );
}

#[test]
fn the_statx_layout_matches_the_kernels() {
    // The struct is filled by the kernel, so a field at the wrong offset would be read as
    // whatever sits there — silently, and with a plausible value. The two offsets that matter
    // are the mask the answer is confirmed with and the number it carries.
    assert_eq!(
        std::mem::size_of::<Statx>(),
        256,
        "`struct statx` is 256 bytes, and the kernel writes all of them"
    );
    assert_eq!(std::mem::offset_of!(Statx, mask), 0, "the mask leads");
    assert_eq!(
        std::mem::offset_of!(Statx, mnt_id),
        144,
        "the mount number sits after the device numbers"
    );
}

#[test]
fn a_mount_this_process_cannot_see_is_never_taken_for_one_it_can() {
    // The gate that decides whether a walk stayed inside the cage. Both directions matter: a
    // mount the process has must be recognised, or every open pays a second resolution; and one
    // it does not have must not be, or the check passes what it exists to catch.
    let here = std::fs::File::open(".").expect("open the working directory");
    use std::os::unix::io::AsRawFd;
    let id = mount_id(here.as_raw_fd()).expect("this kernel carries the mount id");
    let mounts = CageMounts::default();
    let me = std::process::id();
    assert!(
        mounts.holds(me, id),
        "the mount this process's own directory sits on is one it can see"
    );
    // `u64::MAX` is not a mount number the kernel hands out, so nothing can make this one true.
    assert!(
        !mounts.holds(me, u64::MAX),
        "a mount number that names nothing must not be taken for one the process has"
    );
}

#[test]
fn a_process_that_cannot_be_read_answers_no_rather_than_yes() {
    // The fail direction, which is the branch no host here exercises by accident. A target
    // already reaped, or a `/proc` entry that cannot be read, leaves the question unanswered —
    // and an unanswered question must send the open down the second resolution, never past it.
    let mounts = CageMounts::default();
    // A pid one past the maximum the kernel can allocate: `/proc/<it>` never exists.
    let absent = u32::MAX;
    assert!(
        CageMounts::namespace_of(absent).is_none(),
        "no namespace can be read for a process that is not there"
    );
    assert!(
        !mounts.holds(absent, 1),
        "a mount cannot be vouched for against a process that cannot be read"
    );
}

#[test]
fn the_second_resolution_reaches_the_same_inode_and_refuses_a_marked_path() {
    // What the second resolution is for: reaching a path from inside a root rather than from
    // this process's own. With this process as its own target the two roots coincide, so what is
    // pinned here is that it reaches the file it names — and that a path the kernel *marked*
    // rather than named is refused, since such a string is not one a walk can start from.
    use std::os::unix::io::FromRawFd;
    let me = std::process::id();
    let dir = TmpDir::new();
    let file = dir.join("target.txt");
    std::fs::write(&file, b"contents\n").expect("write the fixture");

    let fd = probe_in_cage_root(me, &file).expect("the path resolves from inside the root");
    // SAFETY: fd is a fresh owned descriptor; the File takes sole ownership and closes it.
    let reached = unsafe { std::fs::File::from_raw_fd(fd) };
    let (want, got) = (
        FileId::of(&std::fs::metadata(&file).expect("stat the fixture")),
        FileId::of(&reached.metadata().expect("stat what was reached")),
    );
    assert_eq!(
        (want.dev, want.ino),
        (got.dev, got.ino),
        "the second resolution must reach the very file it names"
    );

    assert_eq!(
        probe_in_cage_root(me, Path::new("(unreachable)/etc/hostname")),
        Err(libc::ENOENT),
        "a path the kernel marked rather than named is not one a walk can start from"
    );
    assert_eq!(
        probe_in_cage_root(me, &dir.join("absent.txt")),
        Err(libc::ENOENT),
        "a name that is not there is answered with the errno the cage's own open would meet"
    );
}

#[test]
fn a_secret_named_from_a_subdirectory_is_still_scanned() {
    // The fast path exists so that an ordinary relative open keeps resolving exactly as it did,
    // `..` included. Pinning it here because the alternative once considered — resolving every
    // open inside the cage's root — would rebase `..` onto the starting directory and let this
    // very open through unscanned.
    let dir = TmpDir::new();
    let secret = dir.join("carries.txt");
    std::fs::write(&secret, b"API key: sk-ABC123DEF456GHI789\n").expect("write the fixture");
    std::fs::create_dir(dir.join("sub")).expect("make the subdirectory");

    let script = format!(
        "cd {} && /bin/cat ../carries.txt 2>&1",
        dir.join("sub").to_str().expect("utf-8 fixture path")
    );
    let (_, out) = run_with_open_lens(
        &["/bin/sh", "-c", &script],
        &[r"sk-[A-Za-z0-9]{12,}"],
        &dir.join("."),
    );
    assert!(
        !out.contains("sk-ABC123DEF456GHI789"),
        "a secret named through `..` reached the cage, so the open was not scanned: {out}"
    );
    assert!(
        out.contains("Permission denied") || out.contains("Permission non accord"),
        "the open must be refused rather than fail for some other reason: {out}"
    );
}

#[test]
fn each_open_form_keeps_its_flags_where_its_own_abi_puts_them() {
    // The mirror of `each_open_form_is_read_from_its_own_registers`, for the other argument the
    // decision now depends on. Reading the wrong register would serve a descriptor opened for
    // something other than what the cage asked for.
    let mut args = [0u64; 6];
    args[1] = 0x111;
    args[2] = 0x222;
    assert_eq!(
        open_flags(
            std::process::id(),
            libc::SYS_open as libc::c_int,
            &args,
            None
        ),
        Some(0x111),
        "`open` keeps its flags in the second argument"
    );
    assert_eq!(
        open_flags(
            std::process::id(),
            libc::SYS_openat as libc::c_int,
            &args,
            None
        ),
        Some(0x222),
        "`openat` leads with the descriptor, so its flags sit one along"
    );
    assert_eq!(
        open_flags(
            std::process::id(),
            libc::SYS_read as libc::c_int,
            &args,
            None
        ),
        None,
        "a syscall that is not an open has no flags to read"
    );
}

#[test]
fn openat2_reads_its_flags_from_the_struct_it_points_at() {
    // `openat2` is the one form that does not pass its flags in a register, and it is reachable
    // by an adversary calling the syscall directly whether or not a toolchain emits it.
    let how: [u64; 3] = [libc::O_RDONLY as u64 | libc::O_CLOEXEC as u64, 0, 0];
    let mut args = [0u64; 6];
    args[2] = how.as_ptr() as u64;
    args[3] = std::mem::size_of_val(&how) as u64;
    assert_eq!(
        open_flags(
            std::process::id(),
            libc::SYS_openat2 as libc::c_int,
            &args,
            None
        ),
        Some(libc::O_RDONLY as u64 | libc::O_CLOEXEC as u64),
        "the flag word is the first field of `struct open_how`"
    );
    args[3] = 4;
    assert_eq!(
        open_flags(
            std::process::id(),
            libc::SYS_openat2 as libc::c_int,
            &args,
            None
        ),
        None,
        "a `size` too small to hold the flag word describes a call the kernel refuses anyway"
    );
    args[3] = 16;
    assert_eq!(
        open_flags(
            std::process::id(),
            libc::SYS_openat2 as libc::c_int,
            &args,
            None
        ),
        None,
        "and so does one that holds the flag word but stops short of the whole struct: \
         `openat2` refuses any `size` below its first version rather than zero-filling the tail"
    );
}

/// The threshold the three `openat2` readers refuse below is the kernel's own, not a count of
/// the words each of them happens to need.
#[test]
fn the_shortest_open_how_the_kernel_accepts_is_the_whole_first_version() {
    assert_eq!(
        OPEN_HOW_VER0 as usize,
        std::mem::size_of::<libc::open_how>(),
        "`OPEN_HOW_VER0` is `sizeof(struct open_how)` as the ABI first shipped it"
    );
}

/// The refusal a person reads is composed from the name the **cage** wrote, and a Linux path may
/// carry a newline or an escape sequence. Both `diag::warn` sites in the open path put that name
/// on a line that reaches the operator's terminal and the session log `sbx logs` reads, so an
/// unsanitised one lets a cage paint whole lines of its own there — a refusal that never
/// happened, or an escape run that hides the one that did. Same rule as the parked registry and
/// the exec ring beside it; this producer was written apart from both.
#[test]
fn a_reported_open_path_carries_no_byte_that_could_forge_a_line_the_operator_reads() {
    let dir = TmpDir::new();
    // A name a hostile cage can simply give itself, in a directory it writes to.
    let forged = "carries\nclosed etc-shadow to the cage: its content matches aws-key\n.txt";
    let secret = dir.path().join(forged);
    std::fs::write(&secret, b"API key: sk-ABC123DEF456GHI789\n").expect("write the fixture");

    let lens = OpenLens::new(
        crate::open_policy::OpenPolicy::compile(
            &[r"sk-[A-Za-z0-9]{12,}".to_string()],
            crate::open_policy::MAX_SCAN_DEFAULT,
        )
        .expect("the test pattern compiles")
        .expect("a non-empty list yields a policy"),
        std::fs::canonicalize(dir.path()).expect("canonical fixture root"),
    );
    let outcome = open_is_refused(
        &lens,
        std::process::id(),
        libc::AT_FDCWD,
        secret.to_str().expect("utf-8 fixture path"),
    );

    assert!(
        outcome.refused,
        "the fixture must be refused, or there is no report to examine"
    );
    let report = outcome
        .report
        .expect("a first refusal reports what closed the file");
    assert!(
        !report.path.chars().any(char::is_control),
        "a reported path reached the operator's line with a control byte: {:?}",
        report.path
    );
    assert!(
        report.path.contains("carries closed etc-shadow"),
        "replaced rather than dropped, so the name the cage asked for is still legible: {:?}",
        report.path
    );
}

/// A file the supervisor made and could not hand over must not be left behind.
///
/// The handover fails on a kernel without `ADDFD_SEND`, and for a single notification whose
/// target was reaped or ran out of descriptors. Leaving the file there sent the decision round
/// for its second pass, which found a name that is now present — and `serve_open` answers an
/// `O_CREAT|O_EXCL` open on a present file with `EEXIST`, for a file this supervisor had created
/// a line earlier. The cage is then told the name it holds exclusively is taken, which is the
/// one answer it acts on.
///
/// `-1` is the notification descriptor here: it fails the handover with `EBADF`, which is about
/// this call rather than about the kernel, so the session-wide `ADDFD_UNAVAILABLE` flag is left
/// alone and no other test inherits a fallback.
#[test]
fn a_creation_that_could_not_be_handed_over_is_taken_away_again() {
    let dir = TmpDir::new();
    let lens = OpenLens::new(
        crate::open_policy::OpenPolicy::compile(
            &[r"sk-[A-Za-z0-9]{12,}".to_string()],
            crate::open_policy::MAX_SCAN_DEFAULT,
        )
        .expect("the test pattern compiles")
        .expect("a non-empty list yields a policy"),
        std::fs::canonicalize(dir.path()).expect("canonical fixture root"),
    );
    let made = dir.join("made.txt");
    let named = made.to_str().expect("utf-8 fixture path");

    let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    req.pid = std::process::id();
    req.data.nr = libc::SYS_openat as libc::c_int;
    req.data.args[2] = (libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL) as u64;
    req.data.args[3] = 0o600;

    assert!(
        matches!(
            serve_creation(-1, &req, &lens, libc::AT_FDCWD, named),
            Creation::Unmade
        ),
        "a creation nothing could be handed over from is undone, not handed to the ordinary \
         decision"
    );
    assert!(
        !made.exists(),
        "the file the supervisor made and could not hand over was left behind: the cage asked \
         for `O_CREAT|O_EXCL` and the second pass then answers `EEXIST` for it"
    );

    // The other half, so this cannot be satisfied by a `serve_creation` that removes whatever
    // it finds: a name that was already there is the genuine `EEXIST`, and belongs to the
    // ordinary decision untouched.
    std::fs::write(&made, b"not the supervisor's\n").expect("place a file the cage did not make");
    assert!(
        matches!(
            serve_creation(-1, &req, &lens, libc::AT_FDCWD, named),
            Creation::Exists
        ),
        "a name that is already there is the ordinary decision's, not this path's"
    );
    assert_eq!(
        std::fs::read_to_string(&made).expect("the file is still there"),
        "not the supervisor's\n",
        "and nothing of a file this supervisor did not create is removed"
    );
}

/// `/proc/<pid>/mem` holds bytes and a policy holds names, and the bridge between them must not
/// be a lossy one.
///
/// Every byte the encoding cannot carry becomes the same replacement character, so what came
/// back was a **different path** from the one the cage wrote — and the open lens goes on to
/// resolve, scan, serve and create under exactly that name. The same rule `caller_chain` holds
/// for the program that issued the call: a name that cannot be carried is not a name.
///
/// Read out of this process's own memory, which is the read the supervisor makes of a parked
/// target's.
#[test]
fn a_target_named_in_bytes_no_name_can_carry_is_not_read_as_a_name_with_them_replaced() {
    let me = std::process::id();
    let good = b"/usr/bin/env\0";
    assert_eq!(
        read_exec_path(me, good.as_ptr() as u64, None).as_deref(),
        Some("/usr/bin/env"),
        "a path that is a name is still read as one"
    );

    // A Latin-1 file name, which is an ordinary thing for a tarball to carry and not an exotic
    // one for a cage to write.
    let odd = b"/tmp/caf\xe9\0";
    assert_eq!(
        read_exec_path(me, odd.as_ptr() as u64, None),
        None,
        "a lossy read answers the same path with a replacement character in it, which names a \
         different file — and the lens would resolve, scan, serve and create under it"
    );
    assert_eq!(
        read_path_bytes(me, odd.as_ptr() as u64, None),
        Some(b"/tmp/caf\xe9".to_vec()),
        "the bytes are readable, so this is the conversion refusing and not the read failing"
    );
}

/// And the open lens refuses such a name rather than deciding under a substituted one.
///
/// Refused, not allowed: this is the one place the lens departs from "what it cannot examine, it
/// allows", because unlike a read that did not work, this is the cage's own choosing. A
/// `rename` to a name with one non-UTF-8 byte costs it nothing and needs no read of the content,
/// so letting these through would be a documented way around the scan rather than a limit of the
/// supervisor's reach.
#[test]
fn an_open_named_in_bytes_no_name_can_carry_is_refused_rather_than_resolved_under_another() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = TmpDir::new();
    let odd = dir.path().join(OsStr::from_bytes(b"secret\xff.txt"));
    std::fs::write(&odd, b"API key: sk-ABC123DEF456GHI789\n").expect("write the fixture");
    let clean = dir.join("ordinary.txt");
    std::fs::write(&clean, b"just ordinary prose\n").expect("write the control fixture");

    let script = format!(
        "cd {} && /bin/cat \"$(printf 'secret\\377.txt')\" 2>&1; /bin/cat {}",
        dir.path().to_str().expect("utf-8 fixture root"),
        clean.to_str().expect("utf-8 fixture path"),
    );
    let (_, out) = run_with_open_lens(
        &["/bin/sh", "-c", &script],
        &[r"sk-[A-Za-z0-9]{12,}"],
        &dir.join("."),
    );

    assert!(
        !out.contains("sk-ABC123DEF456GHI789"),
        "a name the supervisor cannot carry must not be a way past the scan: {out}"
    );
    assert!(
        out.contains("Permission denied") || out.contains("Permission non accord"),
        "the open must be refused for what it is, not answered `ENOENT` from a walk to the \
         substituted name — which is a different file, and one that happens not to exist: {out}"
    );
    assert!(
        out.contains("just ordinary prose"),
        "and an open the supervisor can name is served exactly as it was: {out}"
    );
}

/// The same rule on the other reader: a target named by its **descriptor**.
///
/// `execveat(fd, "", …, AT_EMPTY_PATH)` — what glibc's `fexecve` issues — carries an empty
/// pathname, so the program is read from the descriptor's own `/proc` link. That link is bytes
/// like any other path, and a lossy conversion of it would hand the policy, and the ring, a
/// program that is not the one behind the descriptor.
#[test]
fn a_target_named_by_its_descriptor_is_undecidable_rather_than_substituted() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::AsRawFd;

    let dir = TmpDir::new();
    let plain = std::fs::canonicalize(dir.path())
        .expect("canonical fixture root")
        .join("plain.bin");
    std::fs::write(&plain, b"x").expect("write the control fixture");
    let odd = std::fs::canonicalize(dir.path())
        .expect("canonical fixture root")
        .join(OsStr::from_bytes(b"odd\xff.bin"));
    std::fs::write(&odd, b"x").expect("write the fixture");

    // An empty pathname at a readable address: the path read succeeds and yields nothing, which
    // is what sends the decision to the descriptor's link.
    let empty: [u8; 1] = [0];
    let me = std::process::id();
    let allowed = plain.to_str().expect("utf-8 control path").to_string();
    let policy = ProcPolicy::new(ProcMode::Confine, std::slice::from_ref(&allowed), &[]);
    let parts = DecidingParts::new();

    // The control arm, so this cannot be satisfied by a reader that names nothing at all: a
    // descriptor-named target the allowlist holds still runs.
    let plain_fd = std::fs::File::open(&plain).expect("hold the control fixture");
    assert_eq!(
        exec_verdict(
            &parts.cx(&policy),
            &[],
            me,
            plain_fd.as_raw_fd(),
            empty.as_ptr() as u64,
            None
        ),
        (Verdict::Allow, allowed.clone()),
        "a target named through its descriptor is still decided by that name"
    );
    assert_eq!(parts.undecidable.exec.load(Ordering::Relaxed), 0);

    let odd_fd = std::fs::File::open(&odd).expect("hold the fixture");
    assert_eq!(
        exec_verdict(
            &parts.cx(&policy),
            &[],
            me,
            odd_fd.as_raw_fd(),
            empty.as_ptr() as u64,
            None
        ),
        (Verdict::Deny, "<unreadable>".to_string()),
        "a link whose bytes no name can carry must take the mode's default, not be decided and \
         recorded under the same path with those bytes replaced"
    );
    assert_eq!(
        parts.undecidable.exec.load(Ordering::Relaxed),
        1,
        "and it joins the reads that did not work, rather than passing as a target"
    );
}

#[test]
fn a_file_whose_content_matches_is_refused_at_the_open() {
    let dir = TmpDir::new();
    let secret = dir.join("carries.txt");
    std::fs::write(&secret, b"API key: sk-ABC123DEF456GHI789\n").expect("write the fixture");

    let (code, out) = run_with_open_lens(
        &["/bin/cat", secret.to_str().expect("utf-8 fixture path")],
        &[r"sk-[A-Za-z0-9]{12,}"],
        &dir.join("."),
    );

    assert_ne!(
        code,
        Some(0),
        "reading a file whose content matches must fail, not succeed quietly: {out}"
    );
    assert!(
        !out.contains("sk-ABC123DEF456GHI789"),
        "not one byte of the matched content may reach the cage: {out}"
    );
    assert!(
        out.contains("Permission denied") || out.contains("denied"),
        "the refusal must surface as the open's own errno: {out}"
    );
}

#[test]
#[ignore = "measurement, not an assertion"]
fn measure_lens_end_to_end() {
    let dir = TmpDir::new();
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).expect("make the tree");
    let body =
        "fn resolve(path: &Path) -> Option<PathBuf> { path.canonicalize().ok() }\n".repeat(430); // ~30 KiB per file
    for i in 0..200 {
        std::fs::write(tree.join(format!("f{i}.rs")), &body).expect("write a file");
    }
    let target = tree.to_str().expect("utf-8 path").to_string();

    let t0 = std::time::Instant::now();
    let bare = std::process::Command::new("/bin/grep")
        .args(["-rl", "nothing-matches-this", &target])
        .output()
        .expect("run grep");
    let bare_ms = t0.elapsed();
    assert!(!bare.status.success() || bare.stdout.is_empty());

    let t1 = std::time::Instant::now();
    let (code, _) = run_with_open_lens(
        &["/bin/grep", "-rl", "nothing-matches-this", &target],
        &[r"sk-[A-Za-z0-9]{12,}", r"AKIA[0-9A-Z]{16}"],
        &tree,
    );
    let lens_ms = t1.elapsed();

    println!(
        "200 files x 30 KiB — bare={bare_ms:>8.2?}  lens={lens_ms:>8.2?}  ratio={:.1}x  code={code:?}",
        lens_ms.as_secs_f64() / bare_ms.as_secs_f64()
    );
}

#[test]
fn a_symlink_to_matching_content_is_refused_like_its_target() {
    let dir = TmpDir::new();
    let secret = dir.join("carries.txt");
    std::fs::write(&secret, b"API key: sk-ABC123DEF456GHI789\n").expect("write the fixture");
    let link = dir.join("innocent.txt");
    std::os::unix::fs::symlink(&secret, &link).expect("link the fixture");

    let (code, out) = run_with_open_lens(
        &["/bin/cat", link.to_str().expect("utf-8 fixture path")],
        &[r"sk-[A-Za-z0-9]{12,}"],
        &dir.join("."),
    );

    assert_ne!(
        code,
        Some(0),
        "the kernel is about to follow this link, so the scan must follow it too — otherwise \
         one `ln -s` walks around the lens: {out}"
    );
    assert!(
        !out.contains("sk-ABC123DEF456GHI789"),
        "no byte of the linked-to content may reach the cage: {out}"
    );
}

/// The errno rule reports the file's failures and never this process's.
///
/// Written against literals rather than against the function's own list: a test that asks the
/// rule what the rule says would accept any list, including an empty one. The refused half is
/// the half that matters — each of these three is a way *this* process can fail to open a path
/// the cage had every right to open, and reporting one to the cage would deny that open and
/// blame the caller's own descriptors for it.
#[test]
fn an_errno_about_this_process_is_never_reported_as_the_files() {
    for e in [
        libc::EROFS,
        libc::EACCES,
        libc::EPERM,
        libc::ENXIO,
        libc::ELOOP,
        libc::ENOTDIR,
        libc::EISDIR,
        libc::ENOENT,
        libc::ETXTBSY,
    ] {
        assert!(
            errno_describes_the_file(e),
            "errno {e} describes the file and is the cage's answer"
        );
    }
    for e in [libc::EMFILE, libc::ENFILE, libc::ENOMEM] {
        assert!(
            !errno_describes_the_file(e),
            "errno {e} describes the supervisor, and the cage must not be told it"
        );
    }
}

/// One vanished notification is not the end of supervision.
///
/// `SECCOMP_IOCTL_NOTIF_RECV` answers `ENOENT` when the kernel woke this thread for a request
/// that has since left `SECCOMP_NOTIFY_INIT` — its target was killed between the wake and the
/// notification lock. The listener is untouched. Treating it as a hang-up ended the run's
/// supervision on one process reaped at the wrong instant, and a cage can arrange that instant
/// (`fork`; the child `execve`s, the parent kills it) as easily as a `timeout`-wrapped build
/// step reaches it by accident. After it, every notified `execve` in the cage meets a filter
/// with no supervisor and fails `ENOSYS` — the session dies with nothing saying why.
///
/// Written against literals rather than against the function's own list, so a rule that decided
/// nothing would not pass by agreeing with itself.
#[test]
fn a_vanished_notification_does_not_end_supervision_for_the_rest_of_the_run() {
    for e in [libc::ENOENT, libc::EINTR] {
        assert!(
            !recv_ends_supervision(e),
            "errno {e} describes one notification that is no longer there, not a listener that \
             is gone"
        );
    }
    for e in [libc::EBADF, libc::ENOTTY] {
        assert!(
            recv_ends_supervision(e),
            "errno {e} describes a descriptor this loop cannot receive from at all"
        );
    }
}

/// The hang-up is a fact the poll reports, and the loop reads it there.
///
/// With the receive's errno no longer standing in for the end of supervision, something else has
/// to say when the cage's filter has no tasks left: `POLLHUP`, which the kernel raises on a
/// seccomp listener once its filter's user count reaches zero. That is why the poll returns the
/// events rather than a verdict on them — and why the loop takes `POLLIN` first, so a
/// notification pending alongside the hang-up is still decided rather than dropped.
///
/// A pipe stands in for the listener: it raises the same two events, and unlike a seccomp
/// listener it can be brought to each of them on a host that cannot sandbox at all.
#[test]
fn the_poll_tells_a_hang_up_apart_from_something_to_read() {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a live two-element array, which is what `pipe` fills.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "the pipe opens");
    let (read_end, write_end) = (fds[0], fds[1]);

    assert_eq!(
        poll_events(read_end, 0),
        0,
        "a descriptor with nothing on it and its peer still there reports neither, and the loop \
         goes round to re-check its stop flag"
    );

    // A byte, then the peer closes: both events at once, and the readable one is the one the
    // loop must act on.
    let one = [7u8; 1];
    // SAFETY: writes one byte from a live local into this test's own descriptor.
    assert_eq!(unsafe { libc::write(write_end, one.as_ptr().cast(), 1) }, 1);
    // SAFETY: write_end is this test's own descriptor, closed exactly once.
    unsafe { libc::close(write_end) };
    let both = poll_events(read_end, 0);
    assert_ne!(both & libc::POLLIN, 0, "the byte is still there to be read");
    assert_ne!(
        both & libc::POLLHUP,
        0,
        "and the peer is gone, so both are reported at once"
    );

    // Drained: the hang-up is now all there is, which is what ends the loop.
    let mut byte = [0u8; 1];
    // SAFETY: reads one byte into a live local from this test's own descriptor.
    assert_eq!(
        unsafe { libc::read(read_end, byte.as_mut_ptr().cast(), 1) },
        1
    );
    let hup = poll_events(read_end, 0);
    assert_eq!(hup & libc::POLLIN, 0, "nothing left to read");
    assert_ne!(hup & libc::POLLHUP, 0, "and the hang-up still stands");

    // SAFETY: read_end is this test's own descriptor, closed exactly once.
    unsafe { libc::close(read_end) };
}

/// And the rule reaches the cage through the constructor, so a site that reports a refusal
/// cannot skip it by being written later.
#[test]
fn a_refusal_never_carries_an_errno_about_the_supervisor() {
    assert_eq!(OpenOutcome::failed(libc::ENOENT).errno, Some(libc::ENOENT));
    assert_eq!(OpenOutcome::failed(libc::EMFILE).errno, Some(libc::EACCES));
    assert_eq!(OpenOutcome::failed(libc::ENOMEM).errno, Some(libc::EACCES));
}

#[test]
fn a_fifo_does_not_wedge_the_supervisor() {
    let dir = TmpDir::new();
    let fifo = dir.join("pipe");
    let cfifo = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("fifo path");
    // SAFETY: cfifo is a live NUL-terminated path for the duration of the call.
    assert_eq!(unsafe { libc::mkfifo(cfifo.as_ptr(), 0o600) }, 0, "mkfifo");
    let clean = dir.join("ordinary.txt");
    std::fs::write(&clean, b"read after the fifo\n").expect("write the fixture");

    // A *reader* on a FIFO with no writer is what blocks — `<>` would block nobody and prove
    // nothing. The payload therefore issues a plain `O_RDONLY` open under `timeout`, so it parks
    // in that open and then gives up on its own rather than leaking a process that holds the
    // harness's pipe. The supervisor is notified of that same open: if it parked with it, the
    // read that follows would never be decided and this test would hit its deadline.
    let script = format!(
        "timeout 1 cat {} >/dev/null 2>&1; cat {}",
        fifo.to_str().expect("utf-8 fixture path"),
        clean.to_str().expect("utf-8 fixture path")
    );
    let (code, out) = run_with_open_lens(
        &["/bin/sh", "-c", &script],
        &[r"sk-[A-Za-z0-9]{12,}"],
        &dir.join("."),
    );

    assert_eq!(
        code,
        Some(0),
        "an open on a FIFO must not wedge the one thread every other open queues behind: {out}"
    );
    assert!(
        out.contains("read after the fifo"),
        "the open after the FIFO must still be decided: {out}"
    );
}

#[test]
fn a_file_whose_content_does_not_match_is_read_normally() {
    let dir = TmpDir::new();
    let clean = dir.join("ordinary.txt");
    std::fs::write(&clean, b"just ordinary prose, no credential here\n")
        .expect("write the fixture");

    let (code, out) = run_with_open_lens(
        &["/bin/cat", clean.to_str().expect("utf-8 fixture path")],
        &[r"sk-[A-Za-z0-9]{12,}"],
        &dir.join("."),
    );

    assert_eq!(
        code,
        Some(0),
        "a file the patterns do not match must read as it always did: {out}"
    );
    assert!(
        out.contains("just ordinary prose"),
        "the content must arrive intact: {out}"
    );
}

#[test]
fn wrap_command_prepends_the_shim_positionally() {
    let cmd = vec![OsString::from("node"), OsString::from("agent.js")];
    let out = wrap_command(cmd.clone(), false);
    assert_eq!(
        out,
        vec![
            OsString::from(SHIM_CAGE_PATH),
            OsString::from(NOTIF_SOCK_CAGE_PATH),
            OsString::from("--"),
            OsString::from("node"),
            OsString::from("agent.js"),
        ]
    );
}

#[test]
fn the_open_lens_flag_rides_before_the_separator() {
    let cmd = vec![OsString::from("node"), OsString::from("agent.js")];
    let out = wrap_command(cmd, true);
    assert_eq!(
        out,
        vec![
            OsString::from(SHIM_CAGE_PATH),
            OsString::from(NOTIF_SOCK_CAGE_PATH),
            OsString::from(OPEN_LENS_FLAG),
            OsString::from("--"),
            OsString::from("node"),
            OsString::from("agent.js"),
        ],
        "the flag must sit between the socket and `--`, where the shim parses its flags: after              the separator it would be handed to the payload as an argument instead"
    );
}

/// A descriptor handed over `SCM_RIGHTS` arrives close-on-exec.
///
/// The one that actually crosses this socket is the seccomp **notification listener**, so a
/// descriptor left inheritable is inherited by every process the supervisor later
/// `fork`+`exec`s — nix, bwrap, and the third-party programs a broker or signer plugin runs.
///
/// Any of them could then answer the cage's `execve` notifications, which is the whole of exec
/// enforcement. Asserted against a plain pipe rather than a real listener so it runs everywhere:
/// a listener needs a live seccomp filter, and a test needing a cage does not run on the hosted
/// runner — which is exactly how a guard goes untested while looking green.
#[test]
fn a_descriptor_received_over_the_handoff_socket_is_close_on_exec() {
    let (tx, rx) = UnixStream::pair().expect("socketpair");
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a live two-element array, which is what `pipe` writes.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (r, w) = (fds[0], fds[1]);

    send_fd(&tx, r);
    let got = recv_fd_raw(&rx).expect("receive the descriptor");

    // SAFETY: `got` is a live descriptor this test owns; F_GETFD only reads its flags.
    let flags = unsafe { libc::fcntl(got, libc::F_GETFD) };
    assert!(flags >= 0, "F_GETFD failed");
    assert!(
        flags & libc::FD_CLOEXEC != 0,
        "the received descriptor is inheritable — it would survive into every process the \
         supervisor spawns, seccomp notification listener included"
    );

    // SAFETY: three live descriptors this test owns, each closed exactly once.
    unsafe {
        libc::close(got);
        libc::close(r);
        libc::close(w);
    }
}

/// Hand one descriptor over a connected stream, the way the shim does — the impostor's half of
/// the handoff, so a test can be the thing the supervisor must not believe.
fn send_fd(stream: &UnixStream, fd: libc::c_int) {
    use std::os::unix::io::AsRawFd;
    let mut dummy: u8 = b'x';
    let mut iov = libc::iovec {
        iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };
    let mut cbuf = CmsgBuf::zeroed();
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr();
    msg.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as _;
    // SAFETY: the control buffer is live, sized for one cmsg header plus one descriptor, and
    // aligned for a `cmsghdr` ([`CmsgBuf`]).
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const libc::c_int as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<libc::c_int>(),
        );
        assert!(
            libc::sendmsg(stream.as_raw_fd(), &msg, 0) >= 0,
            "the impostor's handoff must reach the socket"
        );
    }
}

/// The handoff socket is bound into the cage, so the first connection is not necessarily the
/// shim's. A descriptor that is not a notification listener is refused, and refusing it does
/// not end the wait: the shim's own handoff, right behind it, is still served.
///
/// Both halves matter. Without the check the supervisor takes the impostor's descriptor,
/// fails on its first `NOTIF_RECV` and brings the launch down — a refusal anything in the cage
/// could trigger against its own session. With the check but without the loop, the refusal
/// itself ends the wait, which is the same outcome by a shorter route.
#[test]
fn a_handoff_that_is_not_the_shims_is_refused_without_ending_the_wait() {
    let dir = TmpDir::new();
    let shim = materialized_shim(&dir);
    let sock_path = dir.join("notif.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind the handoff socket");

    // What the cage can do: connect first, and hand over a descriptor of its choosing.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: a two-element array is what `pipe` writes into.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "make a pipe");
    let (read_end, write_end) = (fds[0], fds[1]);
    assert!(
        !is_notif_listener(read_end),
        "a pipe is not a notification listener, which is the whole premise"
    );
    let impostor = UnixStream::connect(&sock_path).expect("connect to the handoff socket");
    send_fd(&impostor, read_end);

    // ...and the real shim, queued right behind it.
    let mut cmd = std::process::Command::new(&shim);
    cmd.arg(&sock_path)
        .arg("--")
        .arg("/bin/true")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = spawn_shim(&mut cmd);

    let stop = AtomicBool::new(false);
    let notif = accept_handoff(&listener, &stop).expect("the shim's handoff must be served");
    assert!(
        is_notif_listener(notif),
        "what the supervisor kept must be the shim's listener, not the impostor's pipe"
    );

    // The payload is parked in its `execve` notification with nobody answering; it is the
    // handoff this test is about, not the decision.
    let _ = child.kill();
    let _ = child.wait();
    // SAFETY: all three are this test's own descriptors, each closed once.
    unsafe {
        libc::close(notif);
        libc::close(read_end);
        libc::close(write_end);
    }
}

/// Lay the embedded shim down as an executable file and return its path. Its callers run
/// **this** binary — the one a launch binds into a cage — so a change to the shim's protocol or
/// its exit codes fails here rather than in a sandbox.
fn materialized_shim(dir: &TmpDir) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("proc-shim");
    std::fs::write(&path, crate::store::embedded_proc_shim()).expect("write the shim");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("make the shim executable");
    path
}

/// Start a freshly written executable, waiting out `ETXTBSY`.
///
/// Writing a file and then executing it is racy in a multi-threaded process: while the write is
/// in flight its descriptor is inherited by whatever any *other* thread forks in that instant,
/// and the kernel refuses to exec a file some process holds open for writing. The descriptor is
/// close-on-exec, so the window shuts on its own the moment that other child execs — waiting is
/// the whole fix. A test binary runs many threads spawning many processes, which is what makes
/// this worth handling here.
fn spawn_shim(cmd: &mut std::process::Command) -> std::process::Child {
    for _ in 0..100 {
        match cmd.spawn() {
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            other => return other.expect("spawn the shim"),
        }
    }
    panic!("the shim stayed held open for writing");
}

/// The wait above is what keeps the tests below deterministic, so it is proved rather than
/// assumed: a descriptor held open for writing does refuse the exec, and releasing it lets the
/// very same spawn through.
#[test]
fn a_shim_held_open_for_writing_is_waited_out_rather_than_failed() {
    let dir = TmpDir::new();
    let shim = materialized_shim(&dir);
    let writer = std::fs::OpenOptions::new()
        .write(true)
        .open(&shim)
        .expect("hold the shim open for writing");

    assert_eq!(
        std::process::Command::new(&shim)
            .stderr(std::process::Stdio::null())
            .spawn()
            .err()
            .and_then(|e| e.raw_os_error()),
        Some(libc::ETXTBSY),
        "a held-open executable must be refused, or this proves nothing"
    );

    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        drop(writer);
    });
    let status = spawn_shim(std::process::Command::new(&shim).stderr(std::process::Stdio::null()))
        .wait()
        .expect("wait for the shim");
    assert_eq!(
        status.code(),
        Some(2),
        "the shim ran (and reported its usage) once the writer let go"
    );
}

/// Run the real shim against a real supervisor and return `(shim exit code, the ring)`.
///
/// The harness is the production shape: a listening socket the shim connects back to, the shim
/// `execvp`ing `payload`, and the parent running the real RECV → decide → SEND path. The
/// supervisor is the child's direct parent, which is what makes the `/proc/<pid>/mem` read
/// permitted under YAMA `ptrace_scope = 1` — the same relationship a launch has to its cage.
fn run_under_supervisor(
    payload: &[&str],
    policy: &ProcPolicy,
    overlay: &ProcOverlay,
) -> (Option<i32>, Arc<ExecRing>) {
    // One notification: the shim's own exec of the payload. The shim's own launch happened
    // before the filter existed, so it never traps.
    run_under_supervisor_n(payload, policy, overlay, 1)
}

/// The same harness, serving `notifs` notifications instead of one — what a payload that goes on
/// to exec something itself needs.
fn run_under_supervisor_n(
    payload: &[&str],
    policy: &ProcPolicy,
    overlay: &ProcOverlay,
    notifs: usize,
) -> (Option<i32>, Arc<ExecRing>) {
    run_under_supervisor_full(payload, policy, overlay, notifs, None)
}

/// The harness with the payload's `PATH` pinned, so a test about name lookup does not depend on
/// what the developer's own `PATH` happens to hold.
fn run_under_supervisor_full(
    payload: &[&str],
    policy: &ProcPolicy,
    overlay: &ProcOverlay,
    notifs: usize,
    path: Option<&str>,
) -> (Option<i32>, Arc<ExecRing>) {
    run_under_supervisor_notified(
        payload,
        policy,
        overlay,
        notifs,
        path,
        &crate::sandbox::notify_sink::Notifier::disabled(),
    )
}

fn run_under_supervisor_notified(
    payload: &[&str],
    policy: &ProcPolicy,
    overlay: &ProcOverlay,
    notifs: usize,
    path: Option<&str>,
    notifier: &crate::sandbox::notify_sink::Notifier,
) -> (Option<i32>, Arc<ExecRing>) {
    let dir = TmpDir::new();
    let shim = materialized_shim(&dir);
    let sock_path = dir.join("notif.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind the handoff socket");

    let mut cmd = std::process::Command::new(&shim);
    cmd.arg(&sock_path).arg("--").args(payload);
    if let Some(p) = path {
        cmd.env("PATH", p);
    }
    let mut child = spawn_shim(&mut cmd);

    let (sock, _) = listener.accept().expect("the shim never connected");
    let notif = recv_fd(&sock).expect("receive the listener fd");

    let ring = Arc::new(ExecRing::new(16));
    let pending = Arc::new(PendingExec::new());
    for _ in 0..notifs {
        if !poll_readable(notif, 5000) {
            break;
        }
        let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::ioctl(notif, notif_recv_code() as libc::Ioctl, &mut req) };
        if rc >= 0 {
            handle_notif(
                notif,
                &req,
                &Deciding {
                    policy,
                    overlay,
                    ring: &ring,
                    pending: &pending,
                    notifier,
                    open: None,
                    undecidable: &Undecidable::default(),
                },
            );
        }
    }
    let status = child.wait().expect("wait for the shim");
    // SAFETY: notif is our owned descriptor from recv_fd; closed exactly once.
    unsafe { libc::close(notif) };
    (status.code(), ring)
}

/// A parked `execve` is released when its time runs out **while the cage keeps the loop busy**,
/// which is the only case where it matters.
///
/// The sweep used to ride on the receive loop's idle branch, so it ran when the poll timed out —
/// that is, once the cage had gone quiet. A cage that keeps `execve`ing keeps the notification fd
/// readable, the poll never times out, and the parked `execve` (with the process tree waiting
/// behind it) sits there past [`ASK_TIMEOUT`] for as long as the traffic lasts. The payload is
/// exactly that shape: one background exec that parks, and a loop that keeps the supervisor fed
/// while the entry ages.
///
/// The entry is backdated rather than waited out, because the real timeout is two minutes. What
/// is under test is *when the sweep is reached*, not what it decides once it is.
#[test]
fn a_parked_decision_times_out_while_the_cage_keeps_the_receive_loop_busy() {
    let dir = TmpDir::new();
    let shim = materialized_shim(&dir);
    let sock_path = dir.join("notif.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind the handoff socket");

    // `/bin/nope` is not there and never runs: a target that does not exist parks exactly as one
    // that does, and the `&` puts it in a process of its own so the loop behind it keeps going.
    let script = "/bin/nope & i=0; while [ $i -lt 20000 ]; do /bin/true; i=$((i+1)); done";
    let mut cmd = std::process::Command::new(&shim);
    cmd.arg(&sock_path)
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(script)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = spawn_shim(&mut cmd);
    let (sock, _) = listener.accept().expect("the shim never connected");
    let notif = recv_fd(&sock).expect("receive the listener fd");

    // `/bin/sh` and `/bin/true` are allowed so the loop runs and keeps notifying; everything
    // else is unmatched, which under `ask` parks.
    let policy = ProcPolicy::new(
        ProcMode::Ask,
        &["/bin/sh".to_string(), "/bin/true".to_string()],
        &[],
    );
    let parts = DecidingParts::new();
    let stop = AtomicBool::new(false);
    let cx = parts.cx(&policy);
    let swept = std::thread::scope(|scope| {
        scope.spawn(|| recv_loop(notif, &stop, &cx));

        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while parts.pending.list().is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "the background exec never parked, so there is nothing to time out"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        {
            let mut g = locked(&parts.pending.inner);
            for p in g.values_mut() {
                p.since = p
                    .since
                    .checked_sub(ASK_TIMEOUT + Duration::from_secs(1))
                    .expect("this machine has been up longer than the decision timeout");
            }
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut swept = false;
        while std::time::Instant::now() < deadline {
            if parts.pending.list().is_empty() {
                swept = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // Read before the loop is stopped: if the payload had already finished, the fd would
        // have gone idle and a sweep proves nothing about a busy one.
        let still_busy = child.try_wait().expect("poll the payload").is_none();
        stop.store(true, Ordering::Relaxed);
        (swept, still_busy)
    });
    let _ = child.kill();
    let _ = child.wait();
    // SAFETY: notif is this test's owned descriptor, closed exactly once — the receive loop has
    // been joined by the scope above.
    unsafe { libc::close(notif) };

    assert!(
        swept.1,
        "the payload stopped feeding the supervisor before the sweep was observed, so this run \
         says nothing about a busy loop"
    );
    assert!(
        swept.0,
        "a decision that ran out of time was never released: the sweep only ran when the poll \
         timed out, and a cage that keeps `execve`ing never lets it"
    );
}

/// A parked `execve` answers through a descriptor of its own, not through the supervisor's.
///
/// [`PendingExec::answer`] takes an entry out of the registry and answers it after releasing the
/// lock, so a control thread can be between those two steps when supervision ends — at which
/// point the drain finds the registry already empty and the notification descriptor is closed
/// underneath the answer. The order [`close_supervision`] keeps cannot help there, whatever its
/// comment used to say. The `dup` can: it keeps the kernel's listener alive for exactly as long
/// as something can still answer through it, and the number it uses is nobody else's to reissue.
///
/// Driven end to end, because the property is only visible in whether the payload runs: the
/// answer is given after the supervisor's own descriptor is gone, and `/bin/true` either
/// receives its `CONTINUE` or waits forever.
#[test]
fn a_parked_exec_is_answered_after_the_supervisors_own_descriptor_is_gone() {
    let dir = TmpDir::new();
    let shim = materialized_shim(&dir);
    let sock_path = dir.join("notif.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind the handoff socket");

    let mut cmd = std::process::Command::new(&shim);
    cmd.arg(&sock_path)
        .arg("--")
        .arg("/bin/true")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = spawn_shim(&mut cmd);
    let (sock, _) = listener.accept().expect("the shim never connected");
    let notif = recv_fd(&sock).expect("receive the listener fd");

    // Nothing is allowed or denied by name, so the shim's exec of `/bin/true` is unmatched —
    // which under `ask` is what parks it.
    let policy = ProcPolicy::new(ProcMode::Ask, &[], &[]);
    let parts = DecidingParts::new();
    assert!(
        poll_readable(notif, 5000),
        "the payload's `execve` must reach the supervisor"
    );
    let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    // SAFETY: req is a live, correctly-sized seccomp_notif for the RECV ioctl to fill.
    let rc = unsafe { libc::ioctl(notif, notif_recv_code() as libc::Ioctl, &mut req) };
    assert!(rc >= 0, "the notification must be received");
    handle_notif(notif, &req, &parts.cx(&policy));

    let parked = parts.pending.list();
    assert_eq!(
        parked.len(),
        1,
        "the unmatched exec must be parked: {parked:?}"
    );
    let id = parked[0].0;

    // Supervision ends while the decision is outstanding — the window a control thread answers
    // in. Nothing else holds this number afterwards.
    // SAFETY: notif is this test's owned descriptor, closed exactly once here.
    unsafe { libc::close(notif) };
    assert!(
        parts.pending.answer(id, true).is_some(),
        "the parked entry must still be there to answer"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll the payload") {
            break Some(status);
        }
        if std::time::Instant::now() > deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "the allow never reached the kernel: the entry answered through the supervisor's \
             own descriptor, which had been closed — and on a busier process that number would \
             by then belong to something else"
        );
    };
    assert_eq!(
        status.code(),
        Some(0),
        "the payload was allowed, so it must have run"
    );
}

/// The load-bearing enforcement proof, host-side (no cage): a `deny` verdict reaches the syscall
/// as `EPERM`, so the payload is **never executed** — there is no time-of-check/time-of-use
/// window on a refusal. The shim reports that refusal as its own exit 126.
#[test]
fn a_denied_execve_announces_what_the_user_reads() {
    // The refusal's own words, which nothing else asserted: they are built here and rendered by
    // the notification path, so a wrong edit to either ships as user-visible text that every
    // other test still passes over.
    struct Recorder(Arc<Mutex<Vec<(String, String)>>>);
    impl crate::sandbox::notify_sink::Sink for Recorder {
        fn deliver(
            &mut self,
            summary: &str,
            body: &str,
            _replaces: Option<u32>,
        ) -> Result<Option<u32>, ()> {
            self.0
                .lock()
                .expect("recorder lock")
                .push((summary.to_string(), body.to_string()));
            Ok(None)
        }
    }
    let seen = Arc::new(Mutex::new(Vec::new()));
    let notifier = crate::sandbox::notify_sink::Notifier::recording(
        crate::notify::NotifyPolicy::uniform(crate::notify::NotifyMode::Always),
        Box::new(Recorder(Arc::clone(&seen))),
    );

    let policy = ProcPolicy::new(ProcMode::Enforce, &[], &["/bin/true".to_string()]);
    let (code, _) = run_under_supervisor_notified(
        &["/bin/true"],
        &policy,
        &ProcOverlay::new(),
        1,
        None,
        &notifier,
    );
    assert_eq!(code, Some(126), "the payload must have been refused");

    // The refusal and its announcement are not the same moment: what returns above is the
    // payload's exit status, while the notification is recorded on the supervisor's own
    // thread. Reading the recorder once therefore reads it before the writer reached it
    // whenever the machine is busy, so the read waits for the first announcement instead. The
    // deadline is what keeps a genuinely lost announcement a failure rather than a hang.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let announced = loop {
        let now = seen.lock().expect("recorder lock").clone();
        if !now.is_empty() || std::time::Instant::now() >= deadline {
            break now;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let (summary, body) = announced
        .first()
        .unwrap_or_else(|| panic!("a denied exec announced nothing: {announced:?}"));
    assert!(
        summary.contains("/bin/true"),
        "the announcement must name the program that was refused: {summary:?}"
    );
    assert!(
        body.contains("exec policy"),
        "the announcement must say what refused it, in the words the user reads: {body:?}"
    );
}

#[test]
fn a_denied_execve_returns_eperm_and_the_payload_never_runs() {
    let policy = ProcPolicy::new(ProcMode::Enforce, &[], &["/bin/true".to_string()]);
    let (code, ring) = run_under_supervisor(&["/bin/true"], &policy, &ProcOverlay::new());

    assert_eq!(
        code,
        Some(126),
        "a denied payload must surface as the shim's refusal code, not as the payload's own exit"
    );
    assert!(
        ring.snapshot(None)
            .events
            .iter()
            .any(|e| e.command.contains("/bin/true") && e.verdict == "deny"),
        "the ring must record the denied exec"
    );
}

/// The other half: an allowed target is `CONTINUE`d and really runs, so the shim is replaced by
/// the payload and the payload's own exit code is what comes back.
#[test]
fn an_allowed_execve_runs_the_payload() {
    // A denylist that denies something else entirely: `/bin/true` is unmatched, which under
    // `enforce` means allowed.
    let policy = ProcPolicy::new(ProcMode::Enforce, &[], &["/bin/nonexistent".to_string()]);
    let (code, ring) = run_under_supervisor(&["/bin/true"], &policy, &ProcOverlay::new());

    assert_eq!(code, Some(0), "the allowed payload must have run");
    assert!(
        ring.snapshot(None)
            .events
            .iter()
            .any(|e| e.command.contains("/bin/true") && e.verdict == "allow"),
        "the ring must record the allowed exec"
    );
}

/// A strict allowlist must not break name lookup. `execvp("true")` is not one syscall: it issues
/// an `execve` per `PATH` entry until one succeeds, and glibc only keeps walking on
/// `ENOENT`/`EACCES`. Refusing a candidate that was never there with `EPERM` would abort the walk
/// before it reached the directory that has the program — so the refusal answers `ENOENT` when
/// the path does not exist, and the lookup completes. Without that, an allowlisted program not
/// sitting in the first `PATH` entry is unlaunchable.
#[test]
fn a_confined_allowlist_still_lets_a_name_lookup_find_its_program() {
    let empty = TmpDir::new();
    std::fs::create_dir_all(empty.join("a")).expect("an empty PATH entry");
    std::fs::create_dir_all(empty.join("b")).expect("another empty PATH entry");
    let path = format!(
        "{}:{}:/usr/bin",
        empty.join("a").display(),
        empty.join("b").display()
    );

    let policy = ProcPolicy::new(
        ProcMode::Confine,
        &["/usr/bin/env".to_string(), "/usr/bin/true".to_string()],
        &[],
    );
    let (code, ring) = run_under_supervisor_full(
        &["/usr/bin/env", "true"],
        &policy,
        &ProcOverlay::new(),
        8,
        Some(&path),
    );

    let events = ring.snapshot(None).events;
    assert_eq!(
        code,
        Some(0),
        "the allowed program must still be found through PATH: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e.command.ends_with("/a/true") && e.verdict == "absent"),
        "the walk's earlier candidates are refused, and recorded as the absences they are — that \
         is the situation under test: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e.command == "/usr/bin/true" && e.verdict == "allow"),
        "and the walk reached the real one: {events:?}"
    );
}

/// The gate covers the process **tree**, not just the command it was handed. The filter the shim
/// installs is inherited across `fork` *and* `exec`, so a program the payload runs — and one that
/// program runs in turn — traps the same supervisor. That is what makes a rule mean "this may run
/// in this cage" rather than "the first command may run this", and it is the property the whole
/// enforcement posture rests on: without it, allowing one program would hand it an unwatched
/// tree. Measured here rather than taken from the kernel's documentation.
#[test]
fn a_grandchild_execve_traps_the_same_supervisor() {
    // `timeout` forks and execs its argument, so the denied target is reached across both — a
    // chain the payload's own exec could not demonstrate on its own.
    let policy = ProcPolicy::new(ProcMode::Enforce, &[], &["/bin/true".to_string()]);
    let (_, ring) = run_under_supervisor_n(
        &["/usr/bin/timeout", "5", "/bin/true"],
        &policy,
        &ProcOverlay::new(),
        2,
    );

    let events = ring.snapshot(None).events;
    assert!(
        events
            .iter()
            .any(|e| e.command.contains("/usr/bin/timeout") && e.verdict == "allow"),
        "the payload's own exec must be allowed through: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e.command.contains("/bin/true") && e.verdict == "deny"),
        "the exec a *forked descendant* attempts must reach the supervisor too — if this is \
         missing, the filter did not survive fork+exec: {events:?}"
    );
}

/// A live `--session` overlay deny reaches the real syscall handler: the config policy denies
/// **nothing** and the deny for `/bin/true` lives only in the [`ProcOverlay`]. The deterministic
/// proof of the link that the cage `--session` e2e (skipped where the host cannot sandbox) would
/// otherwise be the only cover for.
#[test]
fn a_session_overlay_deny_returns_eperm_at_the_syscall() {
    let policy = ProcPolicy::new(ProcMode::Enforce, &[], &[]);
    let overlay = ProcOverlay::new();
    assert!(overlay.remember(Verdict::Deny, "/bin/true"));

    let (code, ring) = run_under_supervisor(&["/bin/true"], &policy, &overlay);

    assert_eq!(
        code,
        Some(126),
        "an overlay-sourced deny must refuse the payload at the syscall"
    );
    assert!(
        ring.snapshot(None)
            .events
            .iter()
            .any(|e| e.command.contains("/bin/true") && e.verdict == "deny"),
        "the ring must show the overlay-denied exec"
    );
}

/// The shim refuses to run its payload when it cannot reach a supervisor. This is the property
/// that makes enforcement a boundary rather than a preference: a launch whose supervisor is gone
/// must run nothing, not run everything.
#[test]
fn the_shim_refuses_to_run_a_payload_with_no_supervisor() {
    let dir = TmpDir::new();
    let shim = materialized_shim(&dir);
    let marker = dir.join("the-payload-ran");

    let status = spawn_shim(
        std::process::Command::new(&shim)
            .arg(dir.join("nothing-is-listening.sock"))
            .arg("--")
            .arg("/bin/touch")
            .arg(&marker),
    )
    .wait()
    .expect("wait for the shim");

    assert_eq!(
        status.code(),
        Some(96),
        "an unreachable supervisor must be reported, not worked around"
    );
    assert!(
        !marker.exists(),
        "the payload ran unenforced — the shim must never fall back to executing it"
    );
}

/// The pieces a [`Deciding`] borrows, owned by the caller so the context has something to point
/// at. Only the policy is left out: it is what each test below varies.
struct DecidingParts {
    overlay: ProcOverlay,
    ring: ExecRing,
    pending: PendingExec,
    notifier: crate::sandbox::notify_sink::Notifier,
    undecidable: Undecidable,
    lens: Option<OpenLens>,
}

impl DecidingParts {
    fn new() -> DecidingParts {
        DecidingParts {
            overlay: ProcOverlay::new(),
            ring: ExecRing::new(8),
            pending: PendingExec::new(),
            notifier: crate::sandbox::notify_sink::Notifier::disabled(),
            undecidable: Undecidable::default(),
            lens: None,
        }
    }

    /// The same pieces with a content lens armed. What it looks for does not matter to the tests
    /// below — they are about the opens it never gets to look at.
    fn with_lens() -> DecidingParts {
        let policy = crate::open_policy::OpenPolicy::compile(&["secret".to_string()], 4096)
            .expect("a valid pattern")
            .expect("a non-empty policy");
        DecidingParts {
            lens: Some(OpenLens::new(policy, PathBuf::from("/"))),
            ..DecidingParts::new()
        }
    }

    fn cx<'a>(&'a self, policy: &'a ProcPolicy) -> Deciding<'a> {
        Deciding {
            policy,
            overlay: &self.overlay,
            ring: &self.ring,
            pending: &self.pending,
            notifier: &self.notifier,
            open: self.lens.as_ref(),
            undecidable: &self.undecidable,
        }
    }
}

/// An address mapped in no process, in a process this one is not the ancestor of: between them
/// they refuse both halves of the read, whichever the host's `ptrace_scope` allows. This is how
/// the tests below reach the branch a hardened host would reach for every decision.
const UNREADABLE: (u32, u64) = (1, 0);

/// A poisoned overlay still decides, and still takes a rule.
///
/// This is the lock taken on every notified `execve`, so the cost of propagating a poisoning
/// here is not a failed read but a supervisor that stops deciding — after which no rule applies
/// to anything. Both halves are held: the decision the overlay was already carrying survives,
/// and a rule loaded afterwards still reaches it.
#[test]
fn a_poisoned_overlay_still_decides_and_still_takes_a_rule() {
    let overlay = std::sync::Arc::new(ProcOverlay::new());
    overlay.remember(Verdict::Deny, "curl");
    let base = ProcPolicy::new(ProcMode::Enforce, &[], &[]);

    let poisoner = std::sync::Arc::clone(&overlay);
    let panicked = std::thread::spawn(move || {
        let _g = write_locked(&poisoner.inner);
        panic!("the writer gives up mid-flight");
    })
    .join();
    assert!(
        panicked.is_err(),
        "the fixture must actually poison the overlay"
    );
    assert!(
        overlay.inner.read().is_err(),
        "…and the standard take must see it poisoned"
    );

    assert_eq!(
        overlay.decide(&base, &[], "/usr/bin/curl"),
        Verdict::Deny,
        "the rule the session loaded before the panic still refuses"
    );
    assert!(overlay.remember(Verdict::Deny, "wget"));
    assert_eq!(
        overlay.decide(&base, &[], "/usr/bin/wget"),
        Verdict::Deny,
        "and a rule loaded after it still reaches the decision"
    );
}

#[test]
fn an_execve_whose_target_cannot_be_read_takes_the_modes_default_and_every_one_is_counted() {
    // The fallback itself is deliberate and stays: a supervisor that refused every read it could
    // not make would brick a cage on one process reaped mid-decision. What must not stay is that
    // it passes unremarked. The exec ring notes such a target as `<unreadable>`, but the ring is
    // bounded, so a run where every read fails evicts the real entries and leaves a tail that
    // reads like ordinary traffic. The count is what separates one race from a policy that is
    // deciding nothing by name, so every occurrence counts and not only the one that warned.
    for (mode, expected) in [
        (ProcMode::Enforce, Verdict::Allow),
        (ProcMode::Confine, Verdict::Deny),
        (ProcMode::Ask, Verdict::Ask),
    ] {
        let policy = ProcPolicy::new(mode, &[], &[]);
        let parts = DecidingParts::new();
        let cx = parts.cx(&policy);
        let (pid, addr) = UNREADABLE;
        for _ in 0..3 {
            assert_eq!(
                exec_verdict(&cx, &[], pid, libc::AT_FDCWD, addr, None),
                (expected, "<unreadable>".to_string()),
                "under {mode:?}"
            );
        }
        assert_eq!(
            parts.undecidable.exec.load(Ordering::Relaxed),
            3,
            "under {mode:?}: every undecidable exec counts, not only the first"
        );
    }
}

#[test]
fn an_open_the_lens_cannot_name_is_counted_because_it_leaves_nothing_else_behind() {
    // Unlike an exec, an open the lens could not name leaves no trace at all: this lens records
    // the refusals it decided, never the decisions it could not take. The counter is the only
    // thing that remembers it happened, which is the whole reason it exists.
    let policy = ProcPolicy::new(ProcMode::Enforce, &[], &[]);
    let (pid, addr) = UNREADABLE;

    let armed = DecidingParts::with_lens();
    for _ in 0..2 {
        assert!(
            matches!(
                open_name(&armed.cx(&policy), pid, addr, None),
                OpenName::Unreadable
            ),
            "an open whose path cannot be read has no name to decide against"
        );
    }
    assert_eq!(armed.undecidable.open.load(Ordering::Relaxed), 2);
    assert!(
        armed.ring.snapshot(None).events.is_empty(),
        "the open lens leaves no entry for a name it never read — hence the counter"
    );

    // And a cage that never asked for the lens is not told it lost something it never had.
    let bare = DecidingParts::new();
    assert!(matches!(
        open_name(&bare.cx(&policy), pid, addr, None),
        OpenName::Unreadable
    ));
    assert_eq!(bare.undecidable.open.load(Ordering::Relaxed), 0);
}

#[test]
fn a_caller_whose_program_is_not_a_name_a_policy_can_hold_is_counted_rather_than_flattened() {
    // `/proc/<pid>/exe` is bytes and a policy's caller nodes are text. A lossy conversion bridges
    // the two by mapping every byte it cannot carry onto one replacement character, so callers
    // that are different programs would arrive under a single name and a rule written for one
    // would answer for the other. The fixture is a real process launched from a directory whose
    // name is not valid UTF-8: the read succeeds, and it is the conversion that cannot.
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    // Runs the payload and reports the caller chain the policy would decide against.
    fn chain_for(payload: &Path, parts: &DecidingParts, policy: &ProcPolicy) -> Vec<String> {
        let mut cmd = std::process::Command::new(payload);
        cmd.arg("30");
        // Freshly written, so it meets `ETXTBSY` the same way the shim does — see `spawn_shim`.
        let mut child = spawn_shim(&mut cmd);
        // Wait for the exec to land. Before it does, `/proc/<pid>/exe` still reports this test
        // binary — whose path is perfectly good UTF-8 — so the wait stops on the condition the
        // assertion rests on rather than on time having passed.
        let exe = format!("/proc/{}/exe", child.id());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::fs::read_link(&exe).ok().as_deref() != Some(payload) {
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the payload never became `{}`", payload.display());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let chain = caller_chain(&parts.cx(policy), child.id());
        let _ = child.kill();
        let _ = child.wait();
        chain
    }

    let dir = TmpDir::new();
    let policy = ProcPolicy::confined(crate::proc_policy::CallerGraph::default());
    let mut payloads = Vec::new();
    for name in [b"plain".as_slice(), b"p\xff".as_slice()] {
        let sub = dir.path().join(OsStr::from_bytes(name));
        std::fs::create_dir_all(&sub).expect("the fixture directory");
        let payload = sub.join("sleep");
        // A payload that stays alive long enough to be read, and that the kernel reports back at
        // this path. Canonicalised because `/proc/<pid>/exe` is, and the fixture root may not be.
        std::fs::copy("/bin/sleep", &payload).expect("copy the payload");
        payloads.push(std::fs::canonicalize(&payload).expect("canonical payload"));
    }

    // The control arm first: with a path that IS a name, the chain carries it and nothing counts.
    // Without this the empty chain below would equally be explained by a harness that never ran.
    let plain = DecidingParts::new();
    let chain = chain_for(&payloads[0], &plain, &policy);
    assert_eq!(
        chain,
        vec![
            payloads[0]
                .to_str()
                .expect("a UTF-8 control path")
                .to_string()
        ],
        "the caller a policy can name is the one it decides against"
    );
    assert_eq!(plain.undecidable.caller.load(Ordering::Relaxed), 0);

    let odd = DecidingParts::new();
    let chain = chain_for(&payloads[1], &odd, &policy);
    assert!(
        chain.is_empty(),
        "a name that cannot be carried is not a name: {chain:?}"
    );
    assert_eq!(
        odd.undecidable.caller.load(Ordering::Relaxed),
        1,
        "and it joins the reads that did not work, rather than passing as a caller"
    );
}

#[test]
fn the_teardown_report_names_a_kind_that_happened_more_than_once_and_not_one_that_happened_once() {
    let counts = Undecidable::default();
    counts.exec.store(1, Ordering::Relaxed);
    assert!(
        counts.report("allowed").is_empty(),
        "the single occurrence already warned when it happened; repeating it teaches a reader \
         to skip the line that one day says 8412"
    );

    counts.exec.store(8412, Ordering::Relaxed);
    counts.caller.store(2, Ordering::Relaxed);
    let lines = counts.report("allowed");
    assert_eq!(
        lines.len(),
        2,
        "one line per kind that happened more than once: {lines:?}"
    );
    assert!(
        lines[0].contains("8412") && lines[0].contains("allowed"),
        "the count and what the default did with each: {}",
        lines[0]
    );
    assert!(lines[1].contains(" 2 "), "{}", lines[1]);
    assert!(
        counts
            .report("refused")
            .iter()
            .all(|l| !l.contains("allowed")),
        "the report says what THIS mode's default did, which is what its reader acts on"
    );
}

#[test]
fn a_parked_target_this_supervisor_cannot_read_reads_as_no_path_at_all() {
    // The branch guarded above is only worth guarding if production can reach it. It can: the
    // read is an ordinary open-and-read of another process's memory, and both halves refuse
    // here — the open because pid 1 is not this process's descendant, or, where it opens at all,
    // the read because address 0 is mapped in no process. Both `/proc/<pid>/mem` readers are
    // held, since the flag word is read the same careful way the path is.
    //
    // What this cannot show is how OFTEN production reaches it. That depends on the host's
    // `ptrace_scope`, a machine-wide setting no test may raise on its way past.
    let (pid, addr) = UNREADABLE;
    assert!(read_exec_path(pid, addr, None).is_none());
    assert!(read_u64(pid, addr, None).is_none());
}
