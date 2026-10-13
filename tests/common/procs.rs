//! The host processes an end-to-end launch leaves running, found and ended by fingerprint.
//!
//! A detached or supervised session outlives the command that started it, so a test cannot reap it
//! as a child: it looks for what the cage runs on the host instead, which still sees an in-cage
//! process from outside the cage's pid namespace. Each such test gives its agent the argv
//! `sleep <secs>` with an unusual `secs`, unique across the suites cargo runs side by side.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::process::{Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

/// The pids of this user's processes whose argv is exactly `sleep <secs>`.
///
/// Matched argument by argument against `/proc/<pid>/cmdline` split on its NULs, never as a
/// substring of the whole line: a fingerprint is a bare number, and a substring test against every
/// command line on the machine matches a port, a pid, a hash prefix or a timestamp that happens to
/// contain its digits. Only a process whose real uid is this test's counts: a cage runs as its
/// launcher's user on the host, and nothing another user runs is a test's to count or to kill.
///
/// Panics when `/proc` cannot be listed, since every answer would then be "none", which reads as an
/// agent that never started or as a teardown that worked.
pub fn pids_sleeping_for(secs: &str) -> Vec<i32> {
    scan(secs).unwrap_or_else(|e| panic!("listing /proc: {e}"))
}

/// Whether any process [`pids_sleeping_for`] names is alive: an in-cage agent seen from outside the
/// cage's pid namespace.
pub fn any_sleeping_for(secs: &str) -> bool {
    !pids_sleeping_for(secs).is_empty()
}

/// SIGKILL every process [`pids_sleeping_for`] names, and no other.
///
/// Each one is pinned by a pidfd before its argv is read a second time, and the signal goes through
/// that pidfd. A pid recycled between the listing and the signal then names a process whose argv
/// does not match, and nothing is signalled; one recycled after the pin leaves the pidfd naming the
/// process that exited, which the kernel refuses to signal. Never panics: this runs in a teardown,
/// and a teardown runs while a failed assertion unwinds, when a second panic aborts the test binary.
pub fn kill_sleeping_for(secs: &str) {
    for pid in scan(secs).unwrap_or_default() {
        // SAFETY: `pidfd_open` only reads `pid`; it returns a new descriptor, or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            continue;
        }
        // SAFETY: the descriptor was just opened here and is owned once, through this.
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
        if !is_ours_sleeping_for(pid, secs) {
            continue;
        }
        // SAFETY: `pidfd_send_signal` with a null `siginfo` sends the signal as `kill` would, to
        // the process the pidfd pins. A refusal means that process has exited.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
    }
}

/// Kills, on drop, every process left running under the fingerprints it holds: the backstop for an
/// assertion that panics before the stop under test runs. A detached daemon is reparented to init
/// and cannot be reaped by the test, so only a sweep by fingerprint reaches it.
pub struct FingerprintCleanup(pub Vec<&'static str>);

impl Drop for FingerprintCleanup {
    fn drop(&mut self) {
        for fp in &self.0 {
            kill_sleeping_for(fp);
        }
    }
}

/// Every pid under `/proc` that [`is_ours_sleeping_for`] accepts.
fn scan(secs: &str) -> std::io::Result<Vec<i32>> {
    let mut pids = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let Some(pid) = entry?.file_name().to_str().and_then(|s| s.parse().ok()) else {
            continue;
        };
        if is_ours_sleeping_for(pid, secs) {
            pids.push(pid);
        }
    }
    Ok(pids)
}

/// Whether `pid` runs as this user with the argv `sleep <secs>`. A process that has exited, or
/// whose files cannot be read, is not one.
fn is_ours_sleeping_for(pid: i32, secs: &str) -> bool {
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let mut argv = cmdline.split(|b| *b == 0).filter(|a| !a.is_empty());
    let (Some(program), Some(arg), None) = (argv.next(), argv.next(), argv.next()) else {
        return false;
    };
    // SAFETY: `getuid` reads this process's credentials and cannot fail.
    let me = unsafe { libc::getuid() };
    arg == secs.as_bytes()
        && program.rsplit(|b| *b == b'/').next() == Some(b"sleep".as_slice())
        && real_uid(pid) == Some(me)
}

/// The real uid `pid` runs as, the first figure of its status file's `Uid:` line.
fn real_uid(pid: i32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Poll `cond` until it is `true` or the deadline passes; returns the final value.
pub fn wait_until(deadline: Instant, mut cond: impl FnMut() -> bool) -> bool {
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    cond()
}

/// Whether a per-session egress socket exists under `<data>/sbx/egress/`: present only when the
/// allowlist (supervised) launch path ran, so it confirms a fixture took that path. An absent
/// directory is no socket; any other failure to read it panics with its cause, rather than
/// reporting the launch as having taken the other path.
pub fn egress_socket_exists(data: &Path) -> bool {
    let dir = data.join("sbx").join("egress");
    let mut entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
        Err(e) => panic!("reading {}: {e}", dir.display()),
    };
    entries.any(|entry| {
        entry
            .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
            .path()
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("sock"))
    })
}

/// Run `cmd` until it ends or `limit` passes, killing it in the second case; `Some` with its status
/// when it ended in time. Its output is discarded, and nothing here panics: a teardown runs this
/// while a failed assertion unwinds, when a second panic aborts the test binary, and a command that
/// never returned would hold the whole suite.
pub fn finish_within(cmd: &mut Command, limit: Duration) -> Option<ExitStatus> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// Run `cmd` to its end with both streams captured, killing it once `limit` passes: `Some` with
/// what it printed when it ended in time, `None` when it had to be killed.
///
/// For a command that ends on its own and could, through a regression, wait for good — a verb
/// that misreads its arguments as a request to watch — so that the caller fails naming it rather
/// than holding the suite until its job times out. Each stream is read on a thread of its own and
/// handed over by channel, and waited for only briefly once the command has ended: something it
/// started can hold a pipe open after it, and a join would wait on that instead.
pub fn output_within(cmd: &mut Command, limit: Duration) -> Option<Output> {
    use std::io::Read as _;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawning {cmd:?}: {e}"));
    let drain = |mut pipe: Box<dyn std::io::Read + Send>| {
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            let _ = sent.send(bytes);
        });
        received
    };
    let stdout = drain(Box::new(child.stdout.take().expect("stdout is piped")));
    let stderr = drain(Box::new(child.stderr.take().expect("stderr is piped")));
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let grace = Duration::from_secs(5);
    Some(Output {
        status,
        stdout: stdout.recv_timeout(grace).unwrap_or_default(),
        stderr: stderr.recv_timeout(grace).unwrap_or_default(),
    })
}

/// The detached session's id, out of the line `sbx` prints as it detaches
/// (`...detached session <pid>...`).
pub fn parse_detach_pid(stderr: &[u8]) -> Option<u32> {
    let text = String::from_utf8_lossy(stderr);
    let after = text.split("detached session ").nth(1)?;
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Whether one of `listing`'s rows carries `pid` as a column of its own. A substring test would
/// find pid 12 in a listing of pid 123, and read a session as listed, or as still listed, when it
/// is not.
pub fn lists_pid(listing: &str, pid: u32) -> bool {
    let pid = pid.to_string();
    listing
        .lines()
        .any(|row| row.split_whitespace().any(|column| column == pid))
}
