//! The proxy's side of `sbx net live`: the tunnels it has open, and the bytes each has carried.
//!
//! The relays count into per-flow atomics on the hot path and never take a lock to do it. What the
//! supervisor's view needs of those counts is how they stand, not every increment, so one thread per
//! proxy reads them on a fixed tick ([`TICK`]) and reports the flows that moved, with **absolute**
//! totals; an opening and a closing are reported as they happen ([`super::events`]). The view trails
//! the relay by at most one tick, and a total applied late or twice is still the right total.

use super::events::{Emitter, ProxyEvent};
use crate::sandbox::control::Proto;
use crate::sandbox::locks::locked;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

/// How often the counts of the open flows are reported. A tunnel moving data would otherwise report
/// once per relayed block, several hundred times per megabyte, for a view a person reads.
const TICK: Duration = Duration::from_millis(100);

/// The flows one proxy has open, and what it last reported of each.
pub(super) struct LiveFlows {
    events: Emitter,
    inner: Mutex<Inner>,
}

/// What [`LiveFlows`] guards: the numbering of its flows, and the ones open.
struct Inner {
    /// The number the next flow is given; the supervisor's view is keyed by it.
    next_id: u64,
    open: BTreeMap<u64, Tracked>,
}

/// One open flow's counters, shared with the relay, and the totals last reported for it.
struct Tracked {
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    reported: (u64, u64),
}

impl LiveFlows {
    /// Track the flows of the proxy reporting through `events`, and report their counts every
    /// [`TICK`] for as long as the returned table is held. The reporting thread holds the table
    /// only while it reports, so it ends, and lets go of `events`, once the proxy has.
    pub(super) fn start(events: Emitter) -> Arc<Self> {
        let flows = Arc::new(LiveFlows {
            events,
            inner: Mutex::new(Inner {
                next_id: 1,
                open: BTreeMap::new(),
            }),
        });
        let table: Weak<LiveFlows> = Arc::downgrade(&flows);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(TICK);
                let Some(flows) = table.upgrade() else {
                    return;
                };
                flows.report();
            }
        });
        flows
    }

    /// Open a flow for a permitted tunnel, returning the guard that closes it when dropped. The
    /// opening is reported before the flow can be counted, so no count reaches the supervisor for a
    /// flow it has not been told of.
    pub(super) fn open(self: &Arc<Self>, host: &str, port: u16, proto: Proto) -> FlowGuard {
        let id = {
            let mut inner = locked(&self.inner);
            let id = inner.next_id;
            inner.next_id += 1;
            id
        };
        self.events.send(ProxyEvent::FlowOpened {
            id,
            host: host.to_string(),
            port,
            proto,
        });
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        locked(&self.inner).open.insert(
            id,
            Tracked {
                up: Arc::clone(&up),
                down: Arc::clone(&down),
                reported: (0, 0),
            },
        );
        FlowGuard {
            flows: Some(Arc::clone(self)),
            id,
            up,
            down,
        }
    }

    /// Report the totals of every open flow that moved since it was last reported. Sent outside the
    /// lock, so a full queue slows this thread without holding up a relay opening or closing a flow.
    pub(super) fn report(&self) {
        let moved: Vec<(u64, u64, u64)> = {
            let mut inner = locked(&self.inner);
            inner
                .open
                .iter_mut()
                .filter_map(|(&id, flow)| {
                    let now = (
                        flow.up.load(Ordering::Relaxed),
                        flow.down.load(Ordering::Relaxed),
                    );
                    (now != flow.reported).then(|| {
                        flow.reported = now;
                        (id, now.0, now.1)
                    })
                })
                .collect()
        };
        if !moved.is_empty() {
            self.events.send(ProxyEvent::FlowCounts(moved));
        }
    }

    /// Forget the flow `id` and report it closed. A count for it that a concurrent report had
    /// already taken may reach the supervisor after the closing; it names a flow no longer listed
    /// and changes nothing.
    fn close(&self, id: u64) {
        locked(&self.inner).open.remove(&id);
        self.events.send(ProxyEvent::FlowClosed { id });
    }
}

/// RAII handle for one open flow: it is opened by [`LiveFlows::open`] and closed when this guard
/// drops (the tunnel closed). It always carries the two byte counters the relay increments — `up`
/// (client→upstream) and `down` (upstream→client) — so the counting wrappers can bump them without a
/// lock. A **detached** guard ([`detached`](Self::detached)) carries live counters but belongs to no
/// table, so the relay counts unconditionally without a branch and a proxy that keeps no live view
/// (tests) still works.
pub(crate) struct FlowGuard {
    flows: Option<Arc<LiveFlows>>,
    id: u64,
    pub(crate) up: Arc<AtomicU64>,
    pub(crate) down: Arc<AtomicU64>,
}

impl FlowGuard {
    /// A guard not tied to any table — it carries counters (so the relay's counting wrappers work
    /// uniformly) but opens and closes nothing. Used when the launch keeps no live view (tests).
    pub(crate) fn detached() -> Self {
        FlowGuard {
            flows: None,
            id: 0,
            up: Arc::new(AtomicU64::new(0)),
            down: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        // The flow leaves the live view the moment its tunnel closes; a detached guard has nothing
        // to close. `locked` cannot panic, so this is safe to run while a thread is unwinding.
        if let Some(flows) = &self.flows {
            flows.close(self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::control::FlowRegistry;
    use crate::sandbox::proxy::events;

    fn live(registry: &Arc<FlowRegistry>) -> (Arc<LiveFlows>, Emitter) {
        let emitter = events::spawn(events::Sinks {
            flows: Some(Arc::clone(registry)),
            ..events::Sinks::default()
        })
        .unwrap();
        (LiveFlows::start(emitter.clone()), emitter)
    }

    /// A flow is listed from its opening, carries the totals its relay counted once they are
    /// reported, and leaves the view when its guard drops.
    #[test]
    fn a_flow_is_listed_counted_and_removed_through_the_reports() {
        let registry = Arc::new(FlowRegistry::new());
        let (flows, emitter) = live(&registry);
        let g1 = flows.open("api.test", 443, Proto::Https);
        let g2 = flows.open("db.test", 5432, Proto::Tcp);
        emitter.flush();
        let snap = registry.snapshot();
        assert_eq!(snap.len(), 2, "two open tunnels are visible");
        assert_eq!(
            (snap[0].host.as_str(), snap[0].port, snap[0].proto),
            ("api.test", 443, Proto::Https),
            "oldest-open first"
        );
        assert_eq!((snap[0].up, snap[0].down), (0, 0), "counters start at zero");
        assert_eq!(snap[1].proto, Proto::Tcp);

        g1.up.fetch_add(1024, Ordering::Relaxed);
        g1.down.fetch_add(2048, Ordering::Relaxed);
        flows.report();
        emitter.flush();
        assert_eq!(
            (registry.snapshot()[0].up, registry.snapshot()[0].down),
            (1024, 2048)
        );

        drop(g1);
        emitter.flush();
        let snap = registry.snapshot();
        assert_eq!(snap.len(), 1, "a closed tunnel drops off the view");
        assert_eq!(snap[0].host, "db.test");
        drop(g2);
        emitter.flush();
        assert!(registry.snapshot().is_empty());
    }

    /// The counts reach the view on the tick alone, with nobody asking: the relay never reports.
    #[test]
    fn the_tick_reports_what_the_relay_counted() {
        let registry = Arc::new(FlowRegistry::new());
        let (flows, emitter) = live(&registry);
        let g = flows.open("api.test", 443, Proto::Https);
        g.down.fetch_add(4096, Ordering::Relaxed);
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            emitter.flush();
            if registry.snapshot().first().map(|f| f.down) == Some(4096) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the tick never reported the count: {:?}",
                registry.snapshot()
            );
            std::thread::sleep(TICK / 2);
        }
    }

    /// A flow that did not move since its last report is not reported again: an idle tunnel costs
    /// the queue nothing on the tick. Built without the reporting thread, so only this test reports.
    #[test]
    fn a_flow_that_did_not_move_is_not_reported_again() {
        let flows = Arc::new(LiveFlows {
            events: events::spawn(events::Sinks::default()).unwrap(),
            inner: Mutex::new(Inner {
                next_id: 1,
                open: BTreeMap::new(),
            }),
        });
        let unreported = |flows: &LiveFlows| {
            locked(&flows.inner)
                .open
                .values()
                .filter(|f| {
                    (f.up.load(Ordering::Relaxed), f.down.load(Ordering::Relaxed)) != f.reported
                })
                .count()
        };
        let g = flows.open("api.test", 443, Proto::Https);
        g.up.fetch_add(1, Ordering::Relaxed);
        assert_eq!(unreported(&flows), 1);
        flows.report();
        assert_eq!(unreported(&flows), 0, "reported, and nothing moved since");
    }

    /// The reporting thread lets go of the reporter once the proxy has let go of the table, so the
    /// applying side can end.
    #[test]
    fn the_tick_ends_once_the_table_is_dropped() {
        let (emitter, applier) = events::spawn_joinable(events::Sinks {
            flows: Some(Arc::new(FlowRegistry::new())),
            ..events::Sinks::default()
        });
        let flows = LiveFlows::start(emitter);
        drop(flows);
        applier.join().unwrap();
    }

    #[test]
    fn a_detached_guard_counts_but_opens_nothing() {
        let g = FlowGuard::detached();
        g.up.fetch_add(10, Ordering::Relaxed);
        assert_eq!(g.up.load(Ordering::Relaxed), 10);
        drop(g);
    }
}
