//! Who is on the other end of a host-side control socket.
//!
//! The control sockets — each lens's, the egress plane's, the task log's — answer the host-side
//! `sbx` CLI and nothing else. Some of their verbs release a parked `execve`, answer a parked egress
//! request, remember a rule or stop an invocation, and a cage reaching them would be deciding its
//! own asks. They are never bound into a cage, and the launcher pins sbx's directories from an
//! empty decoy, but neither holds when a bind or the launch directory shows a data dir with its
//! contents (see [`super::lens`]): a read-only mount does not refuse `connect(2)`. This is the check
//! behind them. Every cage runs in a PID namespace of its own, unshared unconditionally by
//! [`super::argv::to_argv`], so a connection from a process outside this process's own PID
//! namespace is refused.
//!
//! The rule is relative, on purpose. A nested sbx, whose supervisor and CLI both run in an outer
//! cage, shares that cage's namespace and keeps working, as does every test that connects from the
//! process that serves. What it refuses besides a cage is a client in an ancestor or a sibling
//! namespace, such as a CLI on the host driving a supervisor that runs inside a container. What it
//! does not refuse is any other process of the same user in the same namespace, which the same-uid
//! model leaves outside sbx's boundary.
//!
//! The comparison is between depths in the PID namespace tree, both read from the `NSpid:` line of
//! a pidfd's fdinfo under the same `/proc`. That line lists the process's number in each namespace
//! from the one `/proc` belongs to down to the process's own, and shows `0` for a process outside
//! the first, so a visible peer with as many entries as this process lives in this process's
//! namespace whenever `/proc` is this process's own. With a `/proc` mounted from an ancestor, an
//! equal depth also admits a sibling namespace's process; a cage is still refused, since its
//! namespace is a child of this one's and so always one level deeper. Reading the depth needs no
//! ptrace access to the peer, which `/proc/<pid>/ns/pid` would, and never looks a process up by a
//! number another process may since have taken.
//!
//! The peer is named by a pidfd. `SO_PEERPIDFD` (Linux 6.5) pins the very process that connected.
//! An older kernel answers `ENOPROTOOPT`, and the pidfd is then opened on the pid `SO_PEERCRED`
//! reports, which was captured at `connect(2)`: if the peer exits before the open and its number
//! goes to another process, the check reads that process instead. That window can only admit
//! wrongly, and only a process of this namespace. A kernel older than 5.5 prints no `NSpid:` in a
//! pidfd's fdinfo, and there every connection is refused.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

/// What the check made of one connection.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The peer runs in this process's PID namespace.
    Admit,
    /// The peer runs in another PID namespace: a cage's, or one beside or above this one.
    Outside,
    /// The peer had exited before it could be named.
    Gone,
    /// Which PID namespace the peer runs in could not be read, for the reason given.
    Unnamed(String),
}

/// A process's place in the PID namespace tree, as the `NSpid:` line of its fdinfo gives it.
#[derive(Debug, PartialEq, Eq)]
enum Depth {
    /// Visible, with this many entries: one per namespace from the one `/proc` belongs to down to
    /// the process's own.
    At(usize),
    /// The process has exited (`-1`).
    Exited,
    /// The process runs outside the namespace `/proc` belongs to (`0`).
    Outside,
    /// No `NSpid:` line, or one that does not read as a list of numbers.
    Unnamed,
}

/// The peer check of one accept loop, holding what it has already said.
///
/// A refused connection is closed unanswered and recorded nowhere, as one past a connection ceiling
/// is. Each kind of refusal is announced once per socket: a cage decides how often it connects, and
/// a warning per connection would let it write to the user's terminal at a rate of its choosing.
pub(super) struct PeerGate {
    who: &'static str,
    said_outside: bool,
    said_unnamed: bool,
}

impl PeerGate {
    pub(super) fn new(who: &'static str) -> Self {
        Self {
            who,
            said_outside: false,
            said_unnamed: false,
        }
    }

    /// Whether `stream`'s peer runs in this process's PID namespace. Anything short of knowing that
    /// it does refuses the connection.
    pub(super) fn admits(&mut self, stream: &UnixStream) -> bool {
        match verdict(stream, true) {
            Verdict::Admit => true,
            Verdict::Gone => false,
            Verdict::Outside => {
                if !std::mem::replace(&mut self.said_outside, true) {
                    crate::diag::warn(&format!(
                        "{}: refused a connection from outside this session's PID namespace, as \
                         one from a cage would be; any further ones are refused silently",
                        self.who
                    ));
                }
                false
            }
            Verdict::Unnamed(why) => {
                if !std::mem::replace(&mut self.said_unnamed, true) {
                    crate::diag::warn(&format!(
                        "{}: refused a connection whose PID namespace could not be read ({why}); \
                         any further ones are refused silently",
                        self.who
                    ));
                }
                false
            }
        }
    }
}

/// Name the peer of `stream` and compare its depth with this process's own, both read the same way
/// from the same `/proc`. `peer_pidfd` is false only in the test that runs the pre-6.5 path.
fn verdict(stream: &UnixStream, peer_pidfd: bool) -> Verdict {
    let own = match crate::session::open_pidfd(std::process::id()) {
        // SAFETY: `pidfd_open` returned a new descriptor that nothing else owns.
        Ok(fd) => depth(&fdinfo(&unsafe { OwnedFd::from_raw_fd(fd) })),
        Err(errno) => {
            return Verdict::Unnamed(format!(
                "pidfd_open: {}",
                io::Error::from_raw_os_error(errno)
            ));
        }
    };
    let peer = match pin_peer(stream, peer_pidfd) {
        Ok(fd) => depth(&fdinfo(&fd)),
        Err(verdict) => return verdict,
    };
    decide(&own, &peer)
}

/// The pure core of [`verdict`]: admit a visible peer at this process's own depth, and nothing else.
fn decide(own: &Depth, peer: &Depth) -> Verdict {
    match (own, peer) {
        (Depth::At(own), Depth::At(peer)) if own == peer => Verdict::Admit,
        (Depth::At(_), Depth::At(_) | Depth::Outside) => Verdict::Outside,
        (Depth::At(_), Depth::Exited) => Verdict::Gone,
        _ => Verdict::Unnamed(
            "no `NSpid:` line in a pidfd's fdinfo, which Linux prints from 5.5 on".to_string(),
        ),
    }
}

/// A pidfd for the process at the other end of `stream`.
///
/// Only `ENOPROTOOPT`, a kernel that does not know `SO_PEERPIDFD`, falls back to `SO_PEERCRED` and
/// `pidfd_open`. Any other refusal of the option refuses the peer: falling back then would reopen,
/// on a kernel that had closed it, the window in which the pid names another process.
fn pin_peer(stream: &UnixStream, peer_pidfd: bool) -> Result<OwnedFd, Verdict> {
    let socket = stream.as_raw_fd();
    if peer_pidfd {
        let mut pidfd: libc::c_int = -1;
        let mut len = size_of_val(&pidfd) as libc::socklen_t;
        // SAFETY: `SO_PEERPIDFD` writes one `c_int` into what is passed, with its size, and installs
        // the descriptor it names only on success.
        let read = unsafe {
            libc::getsockopt(
                socket,
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                std::ptr::from_mut(&mut pidfd).cast(),
                &mut len,
            )
        };
        if read == 0 {
            // SAFETY: the kernel installed a new descriptor that nothing else owns.
            return Ok(unsafe { OwnedFd::from_raw_fd(pidfd) });
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENOPROTOOPT) => {}
            Some(libc::ESRCH | libc::ENODATA) => return Err(Verdict::Gone),
            _ => return Err(Verdict::Unnamed(format!("SO_PEERPIDFD: {err}"))),
        }
    }
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = size_of_val(&cred) as libc::socklen_t;
    // SAFETY: `SO_PEERCRED` writes one `ucred` into what is passed, with its size.
    let read = unsafe {
        libc::getsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut cred).cast(),
            &mut len,
        )
    };
    if read != 0 {
        return Err(Verdict::Unnamed(format!(
            "SO_PEERCRED: {}",
            io::Error::last_os_error()
        )));
    }
    // The pid as numbered in this process's namespace, and `0` when the peer has no number there:
    // it runs outside it.
    let pid = match u32::try_from(cred.pid) {
        Ok(0) | Err(_) => return Err(Verdict::Outside),
        Ok(pid) => pid,
    };
    match crate::session::open_pidfd(pid) {
        // SAFETY: `pidfd_open` returned a new descriptor that nothing else owns.
        Ok(fd) => Ok(unsafe { OwnedFd::from_raw_fd(fd) }),
        Err(libc::ESRCH) => Err(Verdict::Gone),
        Err(errno) => Err(Verdict::Unnamed(format!(
            "pidfd_open: {}",
            io::Error::from_raw_os_error(errno)
        ))),
    }
}

/// The fdinfo text of a pidfd, empty when it cannot be read (which [`depth`] reads as unnamed).
fn fdinfo(pidfd: &OwnedFd) -> String {
    std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd())).unwrap_or_default()
}

/// The [`Depth`] an fdinfo's `NSpid:` line gives.
fn depth(fdinfo: &str) -> Depth {
    let Some(line) = fdinfo.lines().find_map(|l| l.strip_prefix("NSpid:")) else {
        return Depth::Unnamed;
    };
    let ids: Result<Vec<i64>, _> = line.split_whitespace().map(str::parse).collect();
    match ids.as_deref() {
        Ok([-1]) => Depth::Exited,
        Ok([0]) => Depth::Outside,
        Ok(ids) if !ids.is_empty() && ids.iter().all(|&id| id > 0) => Depth::At(ids.len()),
        _ => Depth::Unnamed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fdinfo of a pidfd as the kernel prints it, around the line under test.
    fn fdinfo_with(nspid: &str) -> String {
        format!("pos:\t0\nflags:\t02000002\nmnt_id:\t15\nino:\t1234\nPid:\t42\n{nspid}\n")
    }

    #[test]
    fn the_nspid_line_gives_the_depth_or_says_why_it_cannot() {
        assert_eq!(depth(&fdinfo_with("NSpid:\t42")), Depth::At(1));
        assert_eq!(depth(&fdinfo_with("NSpid:\t4242\t7\t1")), Depth::At(3));
        assert_eq!(depth(&fdinfo_with("NSpid:\t-1")), Depth::Exited);
        assert_eq!(depth(&fdinfo_with("NSpid:\t0")), Depth::Outside);
        // A kernel before 5.5 prints no such line in a pidfd's fdinfo.
        assert_eq!(depth("pos:\t0\nflags:\t02000002\n"), Depth::Unnamed);
        assert_eq!(depth(""), Depth::Unnamed);
        assert_eq!(depth(&fdinfo_with("NSpid:")), Depth::Unnamed);
        assert_eq!(depth(&fdinfo_with("NSpid:\t42\tx")), Depth::Unnamed);
        assert_eq!(depth(&fdinfo_with("NSpid:\t42\t0")), Depth::Unnamed);
    }

    /// The cage case is the second row: a peer one level below this process, as every process of a
    /// cage this process started is.
    #[test]
    fn only_a_visible_peer_at_this_processs_own_depth_is_admitted() {
        assert_eq!(decide(&Depth::At(1), &Depth::At(1)), Verdict::Admit);
        assert_eq!(decide(&Depth::At(1), &Depth::At(2)), Verdict::Outside);
        assert_eq!(decide(&Depth::At(2), &Depth::At(1)), Verdict::Outside);
        assert_eq!(decide(&Depth::At(1), &Depth::Outside), Verdict::Outside);
        assert_eq!(decide(&Depth::At(1), &Depth::Exited), Verdict::Gone);
        assert!(matches!(
            decide(&Depth::At(1), &Depth::Unnamed),
            Verdict::Unnamed(_)
        ));
        assert!(matches!(
            decide(&Depth::Unnamed, &Depth::At(1)),
            Verdict::Unnamed(_)
        ));
    }

    /// The real path, on a socket pair whose both ends are this process: admitted through
    /// `SO_PEERPIDFD`, and through the `SO_PEERCRED` and `pidfd_open` path an older kernel takes.
    #[test]
    fn a_peer_in_this_processs_pid_namespace_is_admitted_by_either_path() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        assert_eq!(verdict(&ours, true), Verdict::Admit);
        assert_eq!(verdict(&ours, false), Verdict::Admit);
        assert!(PeerGate::new("test").admits(&ours));
    }

    /// Each accept loop that serves a control socket asks the gate before it takes a slot, or,
    /// where it takes none, before it serves the connection, so a refused connection never holds
    /// one. The capture tap's report channel is the one egress plane that passes no gate: a socket
    /// pair has no peer but the one handed its other end.
    #[test]
    fn every_control_accept_loop_asks_the_gate_before_it_takes_a_slot() {
        let loops = [
            (
                "lens.rs",
                crate::testutil::production_half(include_str!("lens.rs")),
                "if !gate.admits(&stream)",
                "cap.take()",
            ),
            (
                "control/mod.rs",
                crate::testutil::production_half(include_str!("control/mod.rs")),
                "&& !gate.admits(&stream)",
                "super::conncap::spawn_conn(who",
            ),
            (
                "task_control.rs",
                crate::testutil::production_half(include_str!("task_control.rs")),
                "if !gate.admits(&stream)",
                "for stream in log_listener.incoming()",
            ),
        ];
        for (file, source, check, anchor) in loops {
            let check_at = source
                .find(check)
                .unwrap_or_else(|| panic!("{file}: the accept loop no longer asks the gate"));
            let anchor_at = source
                .find(anchor)
                .unwrap_or_else(|| panic!("{file}: `{anchor}` moved"));
            if file == "task_control.rs" {
                let slot_at = anchor_at
                    + source[anchor_at..]
                        .find("cap.take()")
                        .expect("task_control.rs: the log loop takes a slot");
                assert!(
                    anchor_at < check_at && check_at < slot_at,
                    "{file}: the log socket's loop must ask the gate before it takes a slot"
                );
            } else {
                assert!(
                    check_at < anchor_at,
                    "{file}: the gate must be asked before a slot is taken or the connection served"
                );
            }
        }
        let control = crate::testutil::production_half(include_str!("control/mod.rs"));
        assert!(
            control.contains("Some(super::peer::PeerGate::new(\"egress control\"))"),
            "the egress control socket passes the gate"
        );
    }
}
