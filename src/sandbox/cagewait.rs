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
            None => std::thread::sleep(poll),
        }
    }
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
}
