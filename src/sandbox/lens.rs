//! The substrate every observation lens stands on: a bounded, in-RAM ring of stamped events, read
//! out-of-band over a per-session Unix socket.
//!
//! Three lenses are built from it — the files the cage writes ([`super::fs_control`]), the processes
//! it execs ([`super::proc_control`]), and the decisions its ssh-agent broker made
//! ([`super::sshagent_control`]). They stay deliberately independent of one another at runtime: each
//! owns its own ring and its own socket, so a failure to stand one up never takes another down. What
//! they share is *shape*, and the shape lives here.
//!
//! The egress control plane ([`super::control`]) is not one of them, and folding it in here would be
//! the wrong trade: its ring keeps a separate muted ring, a second monotonic cursor for retroactive
//! amendments, captured traffic and secret sightings. That is a superset, and the three lenses that
//! never need any of it would carry the weight.
//!
//! Security is the same for all three, and it is the reason the ring is RAM and the socket is not in
//! the cage. The socket is bound under the `0700` data dir and is **never** bound into the cage: in
//! Mode B the in-cage agent is the adversary, so it must not reach the record of what it did. A ring
//! is never written to disk and never crosses the boundary; it is the supervisor's owner-only memory
//! for the session's lifetime, and it dies with it.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// One event a lens records. The ring stamps the sequence number, so an event only has to hand it
/// back: that is what a `--follow` cursor is compared against, and what an eviction gap is measured
/// in.
pub(crate) trait Event: Clone {
    fn seq(&self) -> u64;
}

/// The result of a `LOG` query: the events past the caller's cursor, how many fell off the ring
/// before that cursor (surfaced, not silently dropped — a bursty agent between `--follow` polls),
/// and the newest sequence number (the cursor to pass next time, even when `events` is empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Snapshot<E> {
    pub(crate) events: Vec<E>,
    pub(crate) dropped: u64,
    pub(crate) head: u64,
}

/// A bounded ring of recent events, newest appended, oldest evicted past `cap`. Shared (via `Arc`)
/// between whatever produces the events — a watcher thread, a supervisor, a broker's per-connection
/// threads — and the control serve thread that [`snapshot`](Ring::snapshot)s them for a reader.
/// Sequence numbers start at 1 and never repeat within a session, so a `--follow` cursor of 0 means
/// "from the beginning" and can never collide with a real event.
pub(crate) struct Ring<E> {
    inner: Mutex<Inner<E>>,
    cap: usize,
}

struct Inner<E> {
    next_seq: u64,
    events: VecDeque<E>,
}

impl<E: Event> Ring<E> {
    pub(crate) fn new(cap: usize) -> Self {
        Ring {
            inner: Mutex::new(Inner {
                next_seq: 1,
                events: VecDeque::new(),
            }),
            cap: cap.max(1),
        }
    }

    /// Append one event, assigning the next sequence number and evicting the oldest if the ring is
    /// full. `make` builds the event from the two things the ring stamps: its sequence number and
    /// the wall-clock capture time in epoch milliseconds. Returns the assigned sequence number.
    ///
    /// `make` runs **while the ring is locked**, so it must do nothing but build the event. Anything
    /// that reaches outside — announcing a refusal on the desktop, say — belongs to the caller
    /// around this call, never inside it: a lens whose notification blocked would hold the lock the
    /// reader needs to answer `sbx … logs`.
    pub(crate) fn push_with(&self, make: impl FnOnce(u64, u128) -> E) -> u64 {
        // Stamped before the lock, so a contended ring times events by when they happened rather
        // than by when they got their turn.
        let at_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut g = self.inner.lock().unwrap();
        let seq = g.next_seq;
        g.next_seq += 1;
        g.events.push_back(make(seq, at_epoch_ms));
        while g.events.len() > self.cap {
            g.events.pop_front();
        }
        seq
    }

    /// The events past `after`, plus the eviction gap and the newest sequence. `after = None` is a
    /// tail read (the whole retained window; never reports a gap — a first read has nothing to
    /// miss); `after = Some(cursor)` is a follow read (events with `seq > cursor`, reporting how
    /// many between the cursor and the retained window were evicted unseen).
    pub(crate) fn snapshot(&self, after: Option<u64>) -> Snapshot<E> {
        let g = self.inner.lock().unwrap();
        let head = g.next_seq - 1;
        let cursor = after.unwrap_or(0);
        let events: Vec<E> = g
            .events
            .iter()
            .filter(|e| e.seq() > cursor)
            .cloned()
            .collect();
        let dropped = match (after, g.events.front()) {
            (Some(a), Some(oldest)) if oldest.seq() > a + 1 => oldest.seq() - a - 1,
            _ => 0,
        };
        Snapshot {
            events,
            dropped,
            head,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The least an event can be: a sequence number and nothing else. The ring's contract is about
    /// sequencing and eviction, so a lens's own fields would only be noise here — each lens tests
    /// that its `push` maps its arguments onto its own event.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestEvent {
        seq: u64,
        at_epoch_ms: u128,
    }

    impl Event for TestEvent {
        fn seq(&self) -> u64 {
            self.seq
        }
    }

    fn push(ring: &Ring<TestEvent>) -> u64 {
        ring.push_with(|seq, at_epoch_ms| TestEvent { seq, at_epoch_ms })
    }

    #[test]
    fn push_assigns_monotonic_seqs_and_stamps_a_capture_time() {
        let ring = Ring::new(10);
        assert_eq!(push(&ring), 1);
        assert_eq!(push(&ring), 2);
        let snap = ring.snapshot(None);
        assert_eq!(snap.head, 2);
        assert_eq!(snap.dropped, 0);
        assert_eq!(
            snap.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [1, 2]
        );
        // The stamp is the ring's, not the caller's — an event carries a real wall-clock time.
        assert!(snap.events[0].at_epoch_ms > 0);
    }

    #[test]
    fn snapshot_after_returns_only_newer_events() {
        let ring = Ring::new(10);
        for _ in 0..5 {
            push(&ring);
        }
        let snap = ring.snapshot(Some(3));
        assert_eq!(
            snap.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [4, 5]
        );
        assert_eq!(snap.head, 5);
        assert_eq!(snap.dropped, 0);
    }

    #[test]
    fn a_follow_cursor_behind_the_evicted_window_reports_the_gap() {
        // cap 3: after pushing 6, the ring holds seq 4..=6; a follow reader at cursor 1 missed 2 and 3.
        let ring = Ring::new(3);
        for _ in 0..6 {
            push(&ring);
        }
        let snap = ring.snapshot(Some(1));
        assert_eq!(
            snap.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [4, 5, 6]
        );
        assert_eq!(
            snap.dropped, 2,
            "seq 2 and 3 fell off before the cursor caught up"
        );
        assert_eq!(snap.head, 6);

        // A tail read over the same evicted ring never claims a gap: a first read has nothing to
        // have missed, however much fell off before it.
        let tail = ring.snapshot(None);
        assert_eq!(tail.dropped, 0);
        assert_eq!(tail.events.len(), 3);
    }

    /// A ring with no room would evict the event it was just handed, so `snapshot` could never
    /// return anything and every reader would see an empty feed. One is the floor.
    #[test]
    fn a_zero_cap_ring_still_retains_one_event() {
        let ring = Ring::new(0);
        push(&ring);
        assert_eq!(ring.snapshot(None).events.len(), 1);
    }
}
