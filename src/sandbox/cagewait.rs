//! Waiting for a cage to finish, under a ceiling it cannot outlive.
//!
//! The runners that wait on a bubblewrap child — the pool's install, a distribution build, a
//! captured launch, the smoke probe — each give their run a budget of their own and poll at a
//! cadence of their own. What happens when the budget runs out is one rule, stated here once.
//!
//! That rule is to kill the cage's `bwrap`. It is the pid-namespace init for everything inside, so
//! killing it tears the cage down with it and nothing the run started outlives the ceiling. A
//! caller that signalled only the process it spawned would leave the descendants behind.
//!
//! The budget and the cadence stay the caller's. A download, a build, a launch and a probe are not
//! the same wait, and folding them onto one pair of constants would be a change of behaviour
//! wearing a refactor's clothes.
//!
//! What a runner keeps of a cage's output is read here too, while the wait runs and under a cap of
//! the caller's ([`drain_capped`]), since a cage blocked on a pipe nobody reads would otherwise meet
//! the ceiling for a reason that is not its own.
//!
//! The task engine keeps a loop of its own, and that is not an oversight: a task can also be
//! stopped by hand, and that answer stays distinct from the ceiling firing — one is the
//! declaration's limit, the other is someone deciding, and a caller that cannot tell them apart
//! cannot know which to act on.

use std::io;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

/// Whether the status a killed child carried out is the one this module's `SIGKILL` produced.
///
/// The question the caller really asks is "did the ceiling end this run", and the kill alone does
/// not answer it: `try_wait` saying "still running" and the kill landing are two moments, and a run
/// that finished in between carries out its **own** status while the kill reaches a process that is
/// already a zombie. Reporting the ceiling there annexed "the run passed its ceiling and was
/// killed" to output the run had produced on its own, and turned a task's `timed_out` into a claim
/// about a command that had exited 0.
///
/// The status is the discriminant because only a `SIGKILL` can have come from here — the ceiling
/// path and the stop path both use it, and a process that exits normally or dies on any other
/// signal did neither. What this cannot separate is a `SIGKILL` from elsewhere arriving in that
/// same window: an out-of-memory kill at the instant of the ceiling reads as the ceiling. That is
/// a narrower wrong answer than the one it replaces, and the run is over either way.
pub(in crate::sandbox) fn ended_on_our_kill(status: ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt as _;
    status.signal() == Some(libc::SIGKILL)
}

/// Wait for `child` to exit, killing it once `deadline` has passed, polling every `poll`.
///
/// An error from the wait itself is handed back as it is, the child neither killed nor reaped:
/// `waitpid` fails on a child of this process only when the kernel reaps it unasked, under an
/// ignored `SIGCHLD`, and sbx takes the default disposition back before it starts anything
/// (`restore_child_reaping` in `main`).
///
/// Answers the exit status and whether the ceiling is what ended the run. That second half is not
/// readable from the first alone — a cage killed here exits on a signal, which is exactly what a
/// cage signalled for any other reason reports too — so it is read through [`ended_on_our_kill`],
/// which says why the distinction cannot be drawn from the fact that a kill was *issued*.
pub(in crate::sandbox) fn wait_capped(
    child: &mut Child,
    deadline: Instant,
    poll: Duration,
) -> io::Result<(ExitStatus, bool)> {
    loop {
        match child.try_wait()? {
            Some(status) => return Ok((status, false)),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let status = child.wait()?;
                return Ok((status, ended_on_our_kill(status)));
            }
            None => nap(poll, deadline),
        }
    }
}

/// Sleep one `poll`, or what is left until `deadline` when that is shorter.
///
/// A poll longer than what is left would let a run outlive its ceiling by the difference, so the
/// waits that poll a cage against a deadline sleep through this: [`wait_capped`], and the task
/// engine's own loop, which also answers a stop.
pub(in crate::sandbox) fn nap(poll: Duration, deadline: Instant) {
    std::thread::sleep(poll.min(deadline.saturating_duration_since(Instant::now())));
}

/// Read `pipe` to EOF keeping at most `cap` bytes, reporting whether anything was dropped.
///
/// Reading continues past the cap so the writer is never blocked on a full pipe — a cage held there
/// would never exit, which is the hang the cap exists to prevent. Only the kept bytes are bounded.
/// The runners that keep what a cage prints read it through this, a thread per stream, while
/// [`wait_capped`] waits: read only after the wait, output past what a pipe holds would leave the
/// cage blocked writing until the ceiling killed it. The task engine's own reader has the same shape
/// plus a margin for its redaction scanner, which these readers have no use for: nothing they keep
/// is scanned for credentials.
pub(in crate::sandbox) fn drain_capped(pipe: &mut impl io::Read, cap: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut cut = false;
    let mut buf = [0u8; 8192];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if kept.len() < cap {
                    let take = (cap - kept.len()).min(n);
                    kept.extend_from_slice(&buf[..take]);
                    cut |= take < n;
                } else {
                    cut = true;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // A read error leaves what was already kept: the caller's report is better off with a
            // partial capture than with none.
            Err(_) => break,
        }
    }
    (kept, cut)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};

    /// A run that ends on its own carries out its own status, and says the ceiling was not reached.
    #[test]
    fn a_run_that_ends_on_its_own_is_not_reported_as_capped() {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("exit 7")
            .stdin(Stdio::null())
            .spawn()
            .expect("a shell can be spawned");
        let (status, capped) = wait_capped(
            &mut child,
            Instant::now() + Duration::from_secs(30),
            Duration::from_millis(5),
        )
        .expect("the child can be waited for");
        assert_eq!(
            status.code(),
            Some(7),
            "the run's own status is carried out"
        );
        assert!(
            !capped,
            "a run that ended on its own did not meet its ceiling"
        );
    }

    /// Only this module's own `SIGKILL` reads as the ceiling.
    ///
    /// The window it guards cannot be produced on demand — it is the gap between a poll that saw
    /// the child alive and a signal that arrives after it has exited — so the predicate is asked
    /// directly, against the statuses a `wait` can carry out. Without it the ceiling was reported
    /// from the fact that a kill had been *issued*, which is true on every one of these.
    #[test]
    fn a_status_the_ceiling_did_not_produce_is_not_the_ceiling() {
        let exited = |code: i32| ExitStatus::from_raw(code << 8);
        let signalled = |sig: i32| ExitStatus::from_raw(sig);

        assert!(
            !ended_on_our_kill(exited(0)),
            "a run that exited 0 ended itself"
        );
        assert!(
            !ended_on_our_kill(exited(7)),
            "a run that exited 7 ended itself"
        );
        assert!(
            !ended_on_our_kill(signalled(libc::SIGTERM)),
            "this module only ever sends SIGKILL, so a SIGTERM came from somewhere else"
        );
        assert!(
            ended_on_our_kill(signalled(libc::SIGKILL)),
            "the signal the ceiling sends has to read as the ceiling"
        );
    }

    /// A run still going at its ceiling is killed rather than waited out, and the answer says so.
    #[test]
    fn a_run_still_going_at_its_ceiling_is_killed_and_named() {
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .spawn()
            .expect("sleep can be spawned");
        let (status, capped) = wait_capped(
            &mut child,
            Instant::now() + Duration::from_millis(50),
            Duration::from_millis(5),
        )
        .expect("the child can be waited for");
        assert!(capped, "a run alive at its ceiling is reported as capped");
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "the ceiling kills the run rather than waiting it out"
        );
    }

    /// The ceiling is met where it falls, not at the next poll past it: a cadence longer than what
    /// is left of the budget is cut to it.
    #[test]
    fn a_poll_longer_than_the_budget_does_not_carry_the_run_past_it() {
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .spawn()
            .expect("sleep can be spawned");
        let start = Instant::now();
        let (_, capped) = wait_capped(
            &mut child,
            start + Duration::from_millis(100),
            Duration::from_secs(10),
        )
        .expect("the child can be waited for");
        assert!(capped, "a run alive at its ceiling is reported as capped");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the run was killed {:?} after it started, past its 100 ms ceiling by most of a poll",
            start.elapsed()
        );
    }
}
