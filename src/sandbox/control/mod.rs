//! The `ask`-posture control plane: the pending-decision queue plus the per-session Unix control
//! socket a host-side `sbx net pending` reaches to list and answer parked egress requests.
//!
//! Under `[network] mode = "ask"`, the proxy parks a request that no rule decides and blocks until
//! a human answers it (allow/deny) or the configured timeout elapses (deny — fail-closed). The
//! answer arrives out-of-band: a launch binds a control socket at
//! `<data>/egress/control-<pid>.sock` (under the `0700` data dir, owner-only) and serves it on a
//! thread alongside the proxy; a separate `sbx net pending allow|deny` process connects to it.
//!
//! Security: the control socket is **never** bound into the cage — only the proxy socket and the CA
//! cross in (see [`super::egress`]). In Mode B the in-cage agent is the adversary, so letting it
//! reach this socket would let it answer its own asks, defeating the whole posture. Where a bind
//! shows the data dir to the cage anyway, the same holds here as for the lenses ([`super::lens`]):
//! [`serve`] closes a connection from outside the supervisor's PID namespace before reading it.
//! Answering is inherently a trusted host-side act.
//!
//! Discovery is a glob of the egress directory; the socket filename carries the session pid, which
//! is also the `<pid>.<seq>` id prefix the park notice prints (the supervisor prints it, from the
//! form the queue stores) and the CLI parses to address one session. The wire protocol is
//! line-based and minimal (one command per connection): `LIST` returns the pending rows,
//! `ALLOW <seq>` / `DENY <seq>` answer one destination (every identical retry of it, since a tool
//! re-parks one URL many times), naming the host so a `--save` can persist it; `RULES` lists the
//! session's live manual `--session` rules; and `ALLOW *` / `DENY *` drain every parked request at
//! once (one `answered host=…` line each, then `ok` — an older server that predates this replies
//! `err …`, which the CLI reports as unsupported).

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::allowlist::Rule;
use crate::sandbox::locks::{locked, read_locked, write_locked};

mod capture;
mod client;
// The traffic capture and the host-side reader/querier are re-exported so callers keep reaching
// them as `control::…`.
pub(crate) use capture::*;
pub(crate) use client::*;
// Exercised by a server-side round-trip unit test (the server formats, the client parses).
#[cfg(test)]
use client::parse_flow_line;

/// A human's answer to a parked request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum Verdict {
    Allow,
    Deny,
}

/// One request parked awaiting a decision: what it is, when it started waiting, and the channel the
/// control side sends the verdict on to wake the thread waiting for it.
///
/// `host` and `path` are held in their sanitised form — see [`PendingState::enqueue`], which is
/// where they are filtered. Everything that reads this queue reports it to an operator, so the
/// stored form is the reportable one and no reader has to remember to filter.
struct Entry {
    host: String,
    port: u16,
    path: String,
    since: Instant,
    answer: mpsc::Sender<Verdict>,
}

/// A snapshot row of one pending request, for listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingRow {
    pub(crate) seq: u64,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) path: String,
    pub(crate) waiting_secs: u64,
}

/// A request the queue let in: its id and the forms it is listed under, which are what a notice
/// announcing it may print, and where its answer arrives ([`PendingState::wait`]).
pub(crate) struct Parked {
    pub(crate) seq: u64,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) path: String,
    answer: mpsc::Receiver<Verdict>,
}

/// The most `ask`-posture requests parked at once. A new one beyond this is denied immediately
/// (fail-closed) rather than enqueued, and each one parked holds a supervisor thread waiting for
/// its answer ([`crate::sandbox::proxy::link`]), so an in-cage agent cannot pin unbounded host
/// threads by opening connections that all park — the default ask wait being indefinite. Far above
/// any realistic interactive backlog.
pub(crate) const ASK_PENDING_CAP: usize = 256;

/// The shared, lock-guarded queue of parked requests. A request the proxy parks is
/// [`enqueue`](PendingState::enqueue)d by the supervisor's end of the proxy's link
/// ([`crate::sandbox::proxy::link`]), which [`wait`](PendingState::wait)s for its answer; the
/// control socket [`list`](PendingState::list)s and [`answer_like`](PendingState::answer_like)s it.
/// One per proxy, shared (via `Arc`) between that link and the control serve thread.
#[derive(Default)]
pub(crate) struct PendingState {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// A monotonic per-session counter — an id is never reused within a session, so a stale answer
    /// for a since-removed request can never hit a different one.
    next_seq: u64,
    entries: BTreeMap<u64, Entry>,
}

impl PendingState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Let a request into the queue, or `None` when `cap` requests are already parked: the caller
    /// then denies it without waiting on anything. The returned [`Parked`] is how the caller waits
    /// for its answer ([`Self::wait`]), and names the request in the forms the queue lists it under.
    ///
    /// `host` and `path` are chosen by the cage and stored filtered ([`super::sanitize`]), the one
    /// door into a queue every reader of which reports it to an operator. The verdict is unaffected:
    /// it is reached on the values the proxy holds.
    ///
    /// Flood guard: the `cap` keeps an in-cage agent from pinning unbounded host threads by opening
    /// connections that all park, the default `ask` wait being indefinite. It is checked under the
    /// same lock that inserts, so no burst gets past it.
    ///
    /// Residual (a departed-client ghost): the wait is on the answer, not on socket I/O, so a cage
    /// tool that hits its *own* client-side timeout and disconnects mid-park is not noticed — the
    /// entry then sits in the queue (listed, and counting against `cap`) until answered or the
    /// `ask_timeout` elapses. Reaping a departed client denies nothing live, so it is compatible with
    /// the indefinite default; a future increment can poll the socket for a half-close while parked.
    pub(crate) fn enqueue(&self, host: &str, port: u16, path: &str, cap: usize) -> Option<Parked> {
        let mut inner = locked(&self.inner);
        if inner.entries.len() >= cap {
            return None;
        }
        inner.next_seq += 1;
        let seq = inner.next_seq;
        let (tx, rx) = mpsc::channel();
        // The two free-form values are sanitised **here**, on the way in, for the reason
        // [`LogRing::push`] states at length for the log ring: this is the one door every ask
        // enters by, and the alternative is a duty spread over every reader of the queue. Both
        // are chosen by the cage — a `Host` header, an SNI or a CONNECT authority, and the
        // target of the request being asked about — so they may carry any byte, including an
        // ESC, which paints over the operator's terminal when `sbx net pending` prints the row
        // while they are deciding whether to open egress. The supervisor lets a host in only as a
        // name or an address (`serve_park`), so of the two it is the path that can still carry
        // one; the host is filtered here all the same, so that this door holds whoever calls it.
        //
        // This is not the verdict's view of either: the decision is reached on the raw values
        // the proxy still holds, and only what is *reported* passes through here. What the
        // answer reply names, and what `--session` then remembers, is the stored form — so the
        // rule the operator approves is the one they read. A host that needed filtering
        // therefore yields a session rule matching nothing, and the next identical request is
        // asked again rather than granted against a name the operator never saw.
        //
        // The stored form is also what [`PendingState::answer_like`] groups a destination by,
        // and that is a real widening to state: two requests whose raw host or path differ only
        // in control or reordering characters, or past this filter's 512-character cap, collapse
        // into one `×2` row that a single answer frees. They are one row precisely because they
        // are one row *to the operator*: nothing on screen could tell them apart, so grouping on
        // the raw values would show one line and mean two. Keeping both forms is the alternative,
        // and it puts the unfiltered values back in a struct every reader of this queue reports
        // from, which is the arrangement this door exists to remove.
        let (host, path) = (super::sanitize(host), super::sanitize(path));
        inner.entries.insert(
            seq,
            Entry {
                host: host.clone(),
                port,
                path: path.clone(),
                since: Instant::now(),
                answer: tx,
            },
        );
        Some(Parked {
            seq,
            host,
            port,
            path,
            answer: rx,
        })
    }

    /// Wait for the answer to a request [`Self::enqueue`] let in, or until `timeout` elapses
    /// (`None` waits indefinitely). A timeout, or an answer that can no longer come, is a deny —
    /// fail-closed.
    pub(crate) fn wait(&self, parked: Parked, timeout: Option<Duration>) -> Verdict {
        let verdict = match timeout {
            Some(t) => parked.answer.recv_timeout(t).unwrap_or(Verdict::Deny),
            None => parked.answer.recv().unwrap_or(Verdict::Deny),
        };
        // On a real answer the control side already removed the entry; on a timeout it is still
        // present.
        self.forget(parked.seq);
        verdict
    }

    /// Take request `seq` out of the queue without answering it. Idempotent: an answered request
    /// is already gone.
    pub(crate) fn forget(&self, seq: u64) {
        locked(&self.inner).entries.remove(&seq);
    }

    /// Take a request [`Self::enqueue`] let in back out of the queue when nobody will wait for its
    /// answer, and return the answer it was given before it left, or a deny. Out of the queue
    /// first: after that, the only answer that can still come is one already on its way, which is
    /// waited for, so an operator told the request was allowed is not contradicted.
    pub(crate) fn withdraw(&self, parked: Parked) -> Verdict {
        self.forget(parked.seq);
        parked.answer.recv().unwrap_or(Verdict::Deny)
    }

    /// [`Self::enqueue`] then [`Self::wait`], denying at once past `cap`: a request parked as the
    /// queue's own tests park one. `on_enqueue` runs with the id before the wait.
    #[cfg(test)]
    pub(crate) fn park(
        &self,
        host: &str,
        port: u16,
        path: &str,
        timeout: Option<Duration>,
        cap: usize,
        on_enqueue: impl FnOnce(u64),
    ) -> Verdict {
        let Some(parked) = self.enqueue(host, port, path, cap) else {
            return Verdict::Deny;
        };
        on_enqueue(parked.seq);
        self.wait(parked, timeout)
    }

    /// The currently-parked requests, oldest id first (the `BTreeMap` orders by sequence).
    pub(crate) fn list(&self) -> Vec<PendingRow> {
        let inner = locked(&self.inner);
        inner
            .entries
            .iter()
            .map(|(&seq, e)| PendingRow {
                seq,
                host: e.host.clone(),
                port: e.port,
                path: e.path.clone(),
                waiting_secs: e.since.elapsed().as_secs(),
            })
            .collect()
    }

    /// Answer every parked request sharing the named request's destination — its `(host, port, path)`
    /// — with `verdict`, waking each thread waiting for one, and return `(host, port, count)` where
    /// `count` is how many were answered (the host for a `--save`, the port for a `--session` remember
    /// of the exact request). `None` if `seq` is not parked (already answered, or timed out). A send
    /// failure (a thread that just timed out on its own) is ignored — that entry is gone either way.
    ///
    /// This is the destination-grained answer the grouped listing addresses: a tool that retries one
    /// URL re-parks it many times, and they are a single decision, so `allow <id>`/`deny <id>` on the
    /// representative id decides the whole group at once. A *different* destination stays parked — this
    /// is not the blanket [`answer_all_after`](PendingState::answer_all_after) drain.
    pub(crate) fn answer_like(&self, seq: u64, verdict: Verdict) -> Option<(String, u16, usize)> {
        let mut inner = locked(&self.inner);
        let (host, port, path) = {
            let e = inner.entries.get(&seq)?;
            (e.host.clone(), e.port, e.path.clone())
        };
        // The seqs of every parked request to the same destination (collected first — the map cannot
        // be mutated while it is borrowed for the scan).
        let matching: Vec<u64> = inner
            .entries
            .iter()
            .filter(|(_, e)| e.host == host && e.port == port && e.path == path)
            .map(|(&s, _)| s)
            .collect();
        let count = matching.len();
        for s in matching {
            if let Some(entry) = inner.entries.remove(&s) {
                let _ = entry.answer.send(verdict);
            }
        }
        Some((host, port, count))
    }

    /// [`answer_like`](Self::answer_like), with `first` run on the destination **before** any request
    /// is woken. A `--session` answer remembers the destination there, so the retry of a request it
    /// frees is decided by the rule instead of parking again. When `first` fails, nothing is answered
    /// and its error is returned.
    ///
    /// `first` runs with the queue unlocked. Remembering waits for the proxy to confirm the rule, and
    /// the proxy must be able to park a request meanwhile: a queue held across that wait would stall
    /// every request deciding to park behind an answer waiting on the proxy. The request may time
    /// out, or be answered by someone else, in between: what `first` did then stands, and the
    /// answer names the destination with a count of 0, which a caller tells apart from a request
    /// that was not parked at all (`None`, `first` not run).
    pub(crate) fn answer_like_after(
        &self,
        seq: u64,
        verdict: Verdict,
        first: impl FnOnce(&str, u16) -> io::Result<()>,
    ) -> io::Result<Option<(String, u16, usize)>> {
        let Some((host, port)) = locked(&self.inner)
            .entries
            .get(&seq)
            .map(|e| (e.host.clone(), e.port))
        else {
            return Ok(None);
        };
        first(&host, port)?;
        Ok(Some(
            self.answer_like(seq, verdict).unwrap_or((host, port, 0)),
        ))
    }

    /// [`answer_all_after`](Self::answer_all_after) with nothing to do first: how the requests of a
    /// proxy that is gone are let go, and what the tests of the queue itself call.
    pub(crate) fn answer_all(&self, verdict: Verdict) -> Vec<(String, u16)> {
        self.answer_all_after(verdict, |_, _| Ok(()))
            .unwrap_or_default()
    }

    /// Answer every request parked when this is called with `verdict`, wake each thread waiting for
    /// one, and return the `(host, port)` of each, oldest id first (the `BTreeMap` orders by
    /// sequence). A point-in-time drain: a request that parks after the call began is not affected,
    /// save for the one below, and one that timed out meanwhile is not reported.
    ///
    /// `first` is run on every parked destination before any request is woken, with the queue
    /// unlocked, for the reasons [`answer_like_after`](Self::answer_like_after) gives. When `first`
    /// fails, nothing is answered. A request that parked while `first` ran is answered when its
    /// destination is one `first` ran on, as the answer by id answers it: the rule remembered there
    /// decides its retry as it does the others'. Any other stays parked, so none is freed without
    /// the rule that was to decide its retry.
    pub(crate) fn answer_all_after(
        &self,
        verdict: Verdict,
        mut first: impl FnMut(&str, u16) -> io::Result<()>,
    ) -> io::Result<Vec<(String, u16)>> {
        let seen: Vec<(u64, String, u16)> = locked(&self.inner)
            .entries
            .iter()
            .map(|(&seq, e)| (seq, e.host.clone(), e.port))
            .collect();
        let mut remembered: Vec<(&str, u16)> = Vec::new();
        for (_, host, port) in &seen {
            if !remembered.contains(&(host.as_str(), *port)) {
                first(host, *port)?;
                remembered.push((host, *port));
            }
        }
        let answered: Vec<Entry> = {
            let mut inner = locked(&self.inner);
            let taken: Vec<u64> = inner
                .entries
                .iter()
                .filter(|&(seq, e)| {
                    seen.iter().any(|(s, _, _)| s == seq)
                        || remembered.contains(&(e.host.as_str(), e.port))
                })
                .map(|(&seq, _)| seq)
                .collect();
            taken
                .iter()
                .filter_map(|seq| inner.entries.remove(seq))
                .collect()
        };
        // The lock is released before the sends, so a woken `park` thread's idempotent
        // self-`remove` does not contend (its entry is already gone).
        Ok(answered
            .into_iter()
            .map(|e| {
                let _ = e.answer.send(verdict);
                (e.host, e.port)
            })
            .collect())
    }
}

/// The live, per-session manual egress rules a user adds at runtime — either by answering an `ask`
/// with `--session` (an exact `host:port` for the answered request) or by loading a rule ahead of
/// time with `sbx net allow|deny <rule> --session` (any egress rule). A runtime overlay distinct
/// from the (immutable) config policy. The proxy folds these rules into the effective policy it
/// evaluates per request — so an overlay allow/deny is enforced through the same
/// allow/deny/path/method/deny-wins machinery as a config rule, in every filtering posture
/// (allowlist, denylist, and `ask`), not only when a request would otherwise park.
///
/// This is the supervisor's copy, the one `RULES` lists. The proxy decides with its own, which every
/// change is pushed to whole and **confirmed** before the change returns
/// ([`crate::sandbox::proxy::link`]): the command that loaded a rule answers once the rule decides
/// the next request, and says so when the proxy did not confirm it. Until [`attach`](Self::attach)
/// names a proxy there is nobody to confirm, and a change is in force as soon as it is made.
///
/// Its lock recovers from a poisoning panic ([`crate::sandbox::locks`]) on the argument
/// [`super::proc_enforce::ProcOverlay`] gives rather than the module's, because it is the same
/// shape: **live policy**, not a record kept for a reader, so it owes that argument here. The lists
/// cannot be left incomplete by an unwind — every mutation is a `contains` followed by a `push`,
/// neither of which can unwind, so a poisoned overlay holds exactly what a completed
/// [`remember_rule`](Self::remember_rule) put there. And the alternative is worse in the direction
/// that matters: propagating the panic would make every later `--session` command fail while the
/// rest of the plane keeps running.
#[derive(Default)]
pub(crate) struct ManualRules {
    inner: RwLock<ManualInner>,
    /// The proxy these rules are pushed to, once attached. Held across a push, so two changes reach
    /// the proxy in the order they were made.
    proxy: Mutex<Option<crate::sandbox::proxy::link::Supervisor>>,
}

#[derive(Default)]
struct ManualInner {
    allow: Vec<Rule>,
    deny: Vec<Rule>,
    /// Live `--session` mute (`dontaudit`) rules — a denied request matching one has its log line
    /// suppressed for this session, never its verdict. Folded into the effective policy's mute set
    /// alongside the config mutes; carried separately from allow/deny because it is a log filter,
    /// not a verdict rule.
    mute: Vec<Rule>,
    /// Counts the changes, so the proxy installs the newest overlay it was sent and the supervisor
    /// knows which one it confirmed.
    version: u64,
}

impl ManualRules {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Push these rules to `proxy` from now on, starting with the ones already held, and wait until
    /// it confirms them.
    pub(crate) fn attach(&self, proxy: crate::sandbox::proxy::link::Supervisor) -> io::Result<()> {
        let mut held = locked(&self.proxy);
        *held = Some(proxy);
        self.confirm(held.as_ref())
    }

    /// Remember an answered `host:port` as a manual allow or deny, so re-running that exact request
    /// is decided without re-asking. Deduped — re-answering the same `host:port` does not stack.
    pub(crate) fn remember(&self, verdict: Verdict, host: &str, port: u16) -> io::Result<()> {
        self.remember_rule(verdict, crate::allowlist::host_port_rule(host, port))
    }

    /// Add an arbitrary egress `rule` to the overlay as a manual allow or deny — the proactive
    /// `sbx net allow|deny <rule> --session` path. Deduped, so re-loading the same rule does not
    /// stack. A deny takes precedence over an allow at decision time (deny wins in the policy).
    ///
    /// An error when the proxy did not confirm the overlay holding it: the rule is kept here, and
    /// the next change, or the same one again, pushes it once more.
    pub(crate) fn remember_rule(&self, verdict: Verdict, rule: Rule) -> io::Result<()> {
        self.change(|inner| {
            let list = match verdict {
                Verdict::Allow => &mut inner.allow,
                Verdict::Deny => &mut inner.deny,
            };
            if list.contains(&rule) {
                return false;
            }
            list.push(rule);
            true
        })
    }

    /// Add an egress `rule` to the live **mute** overlay — the `sbx net mute <rule> --session` path.
    /// A `dontaudit` log filter: a denied request matching it is still refused (and still counted),
    /// only its log line is suppressed for this session. Deduped, so re-loading does not stack. Kept
    /// off [`Verdict`] deliberately — a mute is not a park answer, so it never touches the
    /// allow/deny/ask verdict paths. Fails as [`Self::remember_rule`] does.
    pub(crate) fn remember_mute(&self, rule: Rule) -> io::Result<()> {
        self.change(|inner| {
            if inner.mute.contains(&rule) {
                return false;
            }
            inner.mute.push(rule);
            true
        })
    }

    /// Apply `edit`, which reports whether it changed anything, and bring the proxy up to date.
    fn change(&self, edit: impl FnOnce(&mut ManualInner) -> bool) -> io::Result<()> {
        let held = locked(&self.proxy);
        {
            let mut inner = write_locked(&self.inner);
            if edit(&mut inner) {
                inner.version += 1;
            }
        }
        self.confirm(held.as_ref())
    }

    /// Push the overlay unless the proxy has already confirmed it. Checked on every change, the ones
    /// that change nothing included: loading a rule again after the proxy failed to confirm it must
    /// push it again, not report the rule it still cannot vouch for.
    fn confirm(&self, proxy: Option<&crate::sandbox::proxy::link::Supervisor>) -> io::Result<()> {
        let Some(proxy) = proxy else {
            return Ok(());
        };
        let (version, overlay) = {
            let inner = read_locked(&self.inner);
            (
                inner.version,
                crate::sandbox::proxy::link::Overlay {
                    allow: inner.allow.clone(),
                    deny: inner.deny.clone(),
                    mute: inner.mute.clone(),
                },
            )
        };
        if proxy.installed() >= version {
            return Ok(());
        }
        proxy.push(version, overlay)
    }

    /// Whether no rule is held. The proxy asks its own overlay ([`crate::sandbox::proxy::link`]);
    /// this copy is asked only by the tests of what it holds.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        let inner = read_locked(&self.inner);
        inner.allow.is_empty() && inner.deny.is_empty() && inner.mute.is_empty()
    }

    /// A snapshot of the manual verdict rules `(allow, deny)` — cloned out so the read lock is not
    /// held across listing or I/O.
    pub(crate) fn snapshot(&self) -> (Vec<Rule>, Vec<Rule>) {
        let inner = read_locked(&self.inner);
        (inner.allow.clone(), inner.deny.clone())
    }

    /// A snapshot of the manual **mute** rules — cloned out like [`Self::snapshot`].
    pub(crate) fn mute_snapshot(&self) -> Vec<Rule> {
        read_locked(&self.inner).mute.clone()
    }
}

// ── The live egress event log ─────────────────────────────────────────────────────────────────
//
// A bounded, in-memory ring of the decisions the proxy makes, read live by `sbx net log` over the
// same per-session control socket. It is **never written to disk and never crosses into the cage**:
// it lives in the launch process's owner-only RAM for the session's lifetime and dies with it, at
// the same trust level as the injected secret the proxy already holds. The proxy redacts a request's
// query against the configured secret needles *before* pushing, so even in RAM the ring never holds a
// raw configured secret; the default `sbx net log` display drops the query entirely.

/// The default number of recent egress events a session retains for the live log.
pub(crate) const LOG_RING_CAP: usize = 1000;

/// The most secret sightings one event keeps ([`LogRing::secret_seen`]). A proxy reports each
/// credential once per direction, and the names it reports are the launch's declared secrets and
/// the few header names an app's own sign-in is learned under, so this covers both directions of
/// sixteen names. The names are the proxy's to report, and nothing else bounds how many distinct
/// ones it sends: past this, a sighting changes nothing. A full ring then holds at most this many
/// names of [`SANITIZED_CHARS`](crate::sandbox::observe_feed::SANITIZED_CHARS) characters per
/// event, about 64 MiB across [`LOG_RING_CAP`] events, and each sighting's search and amendment
/// stay short under the lock every proxy of the session and every `sbx net logs` reader share.
const SIGHTINGS_MAX: usize = 32;

/// The most `--follow` readers one ring keeps track of for [`LogRing::linger`]. Past it, the reader
/// heard from longest ago is forgotten.
const FOLLOWERS_MAX: usize = 16;

/// How long after its announced interval a `--follow` reader's next read may come and still be
/// waited for. A follow reads every session in turn once its interval has passed, so its read of
/// any one session lands a little after it.
const FOLLOW_SLACK: Duration = Duration::from_millis(500);

/// The longest a session that ends waits for its `--follow` readers ([`LogRing::linger`]).
pub(crate) const LINGER_MAX: Duration = Duration::from_secs(2);

/// The verdict class of a logged egress decision. A superset of the `sbx net stats` taxonomy
/// (allow/deny/blocked): the log is a diagnostic record, not a counter, so it also carries `error` —
/// a request the policy permitted but that could not complete (DNS failed, the host was unreachable,
/// its certificate was rejected). Keeping `error` distinct from `blocked` (a *refusal*) is the point:
/// "allowed but it failed" reads differently from "we said no", which is the question the log exists
/// to answer. It also carries `resolved`, which is outside that taxonomy for a second reason: a name
/// the capture tap answered is not a decision, so it belongs in none of the three columns
/// `sbx net stats` adds up, and those stay the proxy's alone.
///
/// The durable register does carry one fact about a resolution all the same — how many there were
/// (`resolutions` in [`super::egress_stats::Tally`]) — because this ring is bounded and a name is
/// the one thing a cage can push through it without the proxy deciding anything. A flood of names
/// can therefore carry a decision off the end of the live log; the count is what is left to say it
/// happened. It is a number, never a list: naming them is this log's job, for as long as it holds
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum LogVerdict {
    /// The request was permitted and egressed.
    Allow,
    /// The request was refused by *policy*: a matching deny rule, a method scope, or an `ask`
    /// decision/timeout. (Security-guard and malformed/IP-literal refusals are recorded as
    /// [`Blocked`](Self::Blocked), not here.)
    Deny,
    /// A security guard or protocol check refused the request (SSRF, host/SNI mismatch, an
    /// outbound-secret leak, the splice cap, an IP-literal target, a malformed/smuggling request),
    /// or the transparent-capture tap refused a connection to an address it handed out no name for
    /// (`dns-bypassed`) — the one refusal here the proxy does not make, because that connection
    /// never reaches it.
    Blocked,
    /// The request was allowed but did not complete: the name did not resolve, the host was
    /// unreachable, or its certificate was rejected. Not a refusal — a downstream failure.
    Error,
    /// A **name the cage asked for**, recorded by the transparent-capture tap when it answered the
    /// query. Deliberately not [`Allow`](Self::Allow): the tap answers every name without consulting
    /// the allowlist, because the policy decision belongs to the connection that may follow. Reading
    /// this as a permission would be wrong in exactly the case that matters — a name resolved and
    /// never dialed, which is what enumeration and DNS-shaped exfiltration look like, and which no
    /// other record in this system can see.
    Resolved,
}

impl LogVerdict {
    /// The stable wire/display token for this verdict.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            LogVerdict::Allow => "allow",
            LogVerdict::Deny => "deny",
            LogVerdict::Blocked => "blocked",
            LogVerdict::Error => "error",
            LogVerdict::Resolved => "resolved",
        }
    }

    /// Whether this verdict's reason merely restates the verdict, and so is dropped from a rendered
    /// line: `allow` has nothing to explain, and `resolved`'s reason is its own token spelled twice.
    /// Every other verdict's reason is the value of the line, because `deny` alone does not say what
    /// to change.
    ///
    /// Shared because two views render the same event: `sbx net logs` and the unified `sbx logs`
    /// feed. They disagreed once, and the disagreement showed as `resolved  example.com:53
    /// (resolved)` in one of them.
    pub(crate) fn reason_restates_verdict(self) -> bool {
        matches!(self, LogVerdict::Allow | LogVerdict::Resolved)
    }

    /// Parse a verdict token back, or `None` if it is not one of them.
    ///
    /// The inverse of [`Self::as_str`], and the two are a pair a test proves total: this side has a
    /// `_` arm, so the compiler cannot catch a variant added to the other alone, and a verdict that
    /// fails to parse here is an event **silently dropped** on the reader's side of the wire.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(LogVerdict::Allow),
            "deny" => Some(LogVerdict::Deny),
            "blocked" => Some(LogVerdict::Blocked),
            "error" => Some(LogVerdict::Error),
            "resolved" => Some(LogVerdict::Resolved),
            _ => None,
        }
    }

    /// Every verdict. The fixed array length is the mechanism that keeps it whole: a new variant
    /// that is not added here does not type-check, and the exhaustive match the tests hold it
    /// against catches one added here that the enum does not carry.
    pub(crate) const ALL: [Self; 5] = [
        LogVerdict::Allow,
        LogVerdict::Deny,
        LogVerdict::Blocked,
        LogVerdict::Error,
        LogVerdict::Resolved,
    ];

    /// Every verdict's token, for the surfaces that must *offer* the set rather than parse one of
    /// it: the `--verdict` completion, and the message a rejected value gets. Spelled through
    /// [`Self::as_str`] so the vocabulary has a single definition — `resolved` was accepted by
    /// [`Self::parse`] while six separate surfaces still said the set was `allow|deny|blocked|
    /// error`, which made a working filter undiscoverable.
    pub(crate) const TOKENS: [&'static str; Self::ALL.len()] = [
        LogVerdict::Allow.as_str(),
        LogVerdict::Deny.as_str(),
        LogVerdict::Blocked.as_str(),
        LogVerdict::Error.as_str(),
        LogVerdict::Resolved.as_str(),
    ];

    /// Exhaustive by construction: adding a variant breaks this match, which is what makes
    /// [`Self::ALL`] trustworthy.
    #[cfg(test)]
    fn assert_all_listed(self) {
        let listed = match self {
            LogVerdict::Allow
            | LogVerdict::Deny
            | LogVerdict::Blocked
            | LogVerdict::Error
            | LogVerdict::Resolved => true,
        };
        assert!(
            listed && Self::ALL.contains(&self),
            "{self:?} is not in ALL"
        );
    }
}

/// Which proxy decided a logged request — the *whose policy* axis, distinct from the transport.
///
/// A session runs more than one proxy: the launch's own, enforcing the project's allowlist for the
/// agent, and one per invocation of a declared task ([`crate::sandbox::task`]), enforcing that
/// task's much narrower `network` list. The per-invocation proxies append to the session's ring
/// rather than opening one nothing would read (see [`crate::sandbox::egress::Egress::event_log`]),
/// so the ring is a merge of planes that do not share a policy.
///
/// That is harmless for a reader that renders the ring and wrong for one that writes policy from
/// it: a task's refusal says what the *task* was not granted, and turning it into a rule would
/// widen the **agent's** allowlist for a destination the operator was never asked about. So every
/// event names the plane that produced it, and [`crate::sandbox::netlearn`] learns only from
/// [`Agent`](Self::Agent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plane {
    /// The session's own proxy: the agent's plane, under the project/app allowlist.
    Agent,
    /// A declared task's per-invocation proxy, under that task's own `network` list.
    Task,
    /// A `[distro] run` build's proxy, under the launch's own allowlist. Distinct from
    /// [`Agent`](Self::Agent) for the reason this enum exists: a build runs commands the project
    /// wrote, and letting its refusals widen the agent's allowlist would answer a question about
    /// the agent that nobody asked about the agent.
    Build,
    /// The plane is not known. The control wire does not carry it, so an event decoded on the
    /// client side reads as this — a fail-closed value, since nothing that writes policy may treat
    /// an unattributed refusal as the agent's.
    Unknown,
}

/// The transport the proxy used for a decided request — the *how*, distinct from the port. The three
/// enforcement paths map one-to-one: an inspected TLS tunnel (a MITM'd `CONNECT`, including a
/// WebSocket over TLS) is [`Https`](Self::Https); an inspected cleartext `http://` absolute-form is
/// [`Http`](Self::Http); a raw `tcp://` L4 splice is [`Tcp`](Self::Tcp). [`Other`](Self::Other) is
/// the honest fallback for a request refused before its transport was known (a malformed `CONNECT`
/// line, a non-routable non-`CONNECT` request). Shown as a column in `sbx net logs` because the port
/// alone is ambiguous — a `tcp://` splice can ride 443, and an inspected host can ride any port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum Proto {
    /// Inspected over TLS (a MITM'd `CONNECT`) — the default `https://` path, WebSockets included.
    Https,
    /// Inspected in the clear (an `http://` absolute-form request).
    Http,
    /// A raw L4 splice selected by a `tcp://` rule — bytes forwarded uninspected.
    Tcp,
    /// The transport was not yet known when the request was refused (a malformed `CONNECT`, a
    /// non-routable request). Rendered as `-`.
    Other,
    /// A name resolution answered by the transparent-capture tap. Not a transport the proxy used:
    /// it is the *question* a client asked before choosing one, and it is recorded because the tap
    /// is the only place in the system that sees it.
    Dns,
}

impl Proto {
    /// The stable wire/display token.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Proto::Https => "https",
            Proto::Http => "http",
            Proto::Tcp => "tcp",
            Proto::Other => "-",
            Proto::Dns => "dns",
        }
    }

    /// Parse a proto token back, defaulting to [`Other`](Self::Other) for an absent or unknown token
    /// (an older persisted log line carries no `proto=`, so it reads as `-` rather than failing).
    ///
    /// That default is also what makes this side unable to fail loudly, so the same round-trip guard
    /// [`LogVerdict::parse`] carries applies here: a transport missing an arm reads as `-` forever.
    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "https" => Proto::Https,
            "http" => Proto::Http,
            "tcp" => Proto::Tcp,
            "dns" => Proto::Dns,
            _ => Proto::Other,
        }
    }

    /// Every transport, for the round-trip guard. See [`LogVerdict::ALL`].
    #[cfg(test)]
    const ALL: [Self; 5] = [
        Proto::Https,
        Proto::Http,
        Proto::Tcp,
        Proto::Other,
        Proto::Dns,
    ];

    /// Exhaustive by construction; see [`LogVerdict::assert_all_listed`].
    #[cfg(test)]
    fn assert_all_listed(self) {
        let listed = match self {
            Proto::Https | Proto::Http | Proto::Tcp | Proto::Other | Proto::Dns => true,
        };
        assert!(
            listed && Self::ALL.contains(&self),
            "{self:?} is not in ALL"
        );
    }
}

/// The HTTP protocol version an **inspected** request used — a second axis beside [`Proto`] (which
/// names the transport *security*: TLS-inspected / cleartext / raw splice). Kept separate so the
/// display can carry both without conflating them: an inspected TLS request reads `https/h1` or
/// `https/h2`, never a bare `h2` that would drop the "it was TLS" signal. Only a completed inspected
/// request has a version; a refusal (no HTTP exchange) or a raw `tcp://` splice (no HTTP at all) is
/// [`Unknown`](Self::Unknown), rendered without a suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum HttpVer {
    /// HTTP/1.1 — the default MITM path, and the only version cleartext (`http://`) ever uses.
    H1,
    /// HTTP/2 — a `[network] http2`-designated host, MITM'd with ALPN `h2` (for gRPC).
    H2,
    /// Not known: a refusal before any HTTP exchange, a raw `tcp://` splice, or an older persisted
    /// log line that predates this field. Rendered without a version suffix.
    Unknown,
}

impl HttpVer {
    /// The wire token, or `""` when unknown (the field is then omitted from the line entirely).
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            HttpVer::H1 => "h1",
            HttpVer::H2 => "h2",
            HttpVer::Unknown => "",
        }
    }

    /// The display suffix appended to the proto token (`https` → `https/h1`); empty when unknown, so
    /// a refusal or a raw splice keeps its bare `https`/`tcp`/`-`.
    pub(crate) fn suffix(self) -> &'static str {
        match self {
            HttpVer::H1 => "/h1",
            HttpVer::H2 => "/h2",
            HttpVer::Unknown => "",
        }
    }

    /// Parse a version token back, defaulting to [`Unknown`](Self::Unknown) for an absent or unknown
    /// token (an older persisted line carries no `ver=`).
    fn parse(s: &str) -> Self {
        match s {
            "h1" => HttpVer::H1,
            "h2" => HttpVer::H2,
            _ => HttpVer::Unknown,
        }
    }
}

/// The RPC framing of an inspected request, recognized from its `Content-Type`. **Ground truth from
/// the header, never inferred from the path** — a request whose content-type does not name an RPC
/// framing is [`None`](Self::None) even if its path looks like `/pkg.Service/Method`. Consequence
/// worth knowing: **Connect *unary*** rides bare `application/proto`/`application/json` (byte-for-byte
/// indistinguishable from a plain protobuf POST), so it reads as `None`; only gRPC, gRPC-web, and
/// Connect *streaming* (`application/connect+…`) carry a self-identifying content-type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum RpcKind {
    /// `application/grpc[+…]` — native gRPC (HTTP/2 framed).
    Grpc,
    /// `application/grpc-web[+…]` — gRPC-web (rides HTTP/1.1 or HTTP/2).
    GrpcWeb,
    /// `application/connect+…` — the Connect protocol's streaming framing.
    Connect,
    /// No RPC content-type recognized (a plain request, or Connect unary's ambiguous `application/proto`).
    None,
}

impl RpcKind {
    /// Classify from a request `Content-Type` value (case-insensitive; grpc-web is tested before grpc
    /// since it shares the `application/grpc` prefix).
    pub(crate) fn from_content_type(ct: &str) -> Self {
        let ct = ct.trim().to_ascii_lowercase();
        if ct.starts_with("application/grpc-web") {
            RpcKind::GrpcWeb
        } else if ct.starts_with("application/grpc") {
            RpcKind::Grpc
        } else if ct.starts_with("application/connect+") {
            RpcKind::Connect
        } else {
            RpcKind::None
        }
    }

    /// The wire/display token, or `""` when not an RPC framing (the field is then omitted).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RpcKind::Grpc => "grpc",
            RpcKind::GrpcWeb => "grpc-web",
            RpcKind::Connect => "connect",
            RpcKind::None => "",
        }
    }

    /// Parse an `l7` token back, defaulting to [`None`](Self::None) for an absent or unknown token.
    fn parse(s: &str) -> Self {
        match s {
            "grpc" => RpcKind::Grpc,
            "grpc-web" => RpcKind::GrpcWeb,
            "connect" => RpcKind::Connect,
            _ => RpcKind::None,
        }
    }
}

/// One decided egress request captured for the live view: when, where, how, and why. `method`/`path`
/// are present only for the inspected L7 path (an early-CONNECT block or a raw `tcp://` splice has no
/// HTTP head to read). The `path` is stored **already query-redacted** by the proxy, so the ring is
/// safe to hold in RAM; the `reason` is a stable category token (or `allowed`), never a rule's text
/// or a secret name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogEvent {
    pub(crate) seq: u64,
    /// Wall-clock capture time in epoch milliseconds — a clean stamp for `--json`; the human view
    /// renders it as a local `hh:mm:ss` time.
    pub(crate) at_epoch_ms: u128,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) method: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) verdict: LogVerdict,
    pub(crate) reason: String,
    /// The transport the proxy used (or would have): `https` (inspected TLS), `http` (inspected
    /// cleartext), `tcp` (raw L4 splice), or `-` when unknown at refusal time. Shown as a column
    /// because the port alone does not name the protocol (a `tcp://` splice can ride 443).
    pub(crate) proto: Proto,
    /// The HTTP version of an inspected request (`h1`/`h2`), or `Unknown` for a refusal / raw splice
    /// / older line. A second axis beside `proto`: rendered as a suffix (`https/h2`) so the transport
    /// security (`https` vs cleartext `http`) is never lost. Set only at the inspected-forward sites.
    pub(crate) http_ver: HttpVer,
    /// The RPC framing recognized from the request `Content-Type` (`grpc`/`grpc-web`/`connect`), or
    /// `None`. Ground truth from the header — never inferred from the path — so Connect *unary*
    /// (bare `application/proto`) reads as `None`. Set only at the inspected-forward sites.
    pub(crate) rpc: RpcKind,
    /// Whether this refusal was suppressed from the default `sbx net log` view by a `mute`
    /// (SELinux `dontaudit`) rule. A muted event is still counted in `sbx net stats` and lives in a
    /// **separate** ring (so a muted flood never evicts a real event); it appears only under
    /// `sbx net log --all`, tagged. Only ever `true` for a `deny` (mute suppresses refusals, never
    /// an allow, a security-guard `blocked`, or a downstream `error`).
    pub(crate) muted: bool,
    /// The upstream HTTP status code (200/404/…), for a **completed L7** request only — filled in by
    /// [`LogRing::set_status`] once the response head returns, after the event was pushed at the
    /// decision point. `None` for an L4 (`tcp://`) splice (no HTTP response to parse), a refusal, an
    /// `error` (no response), or a request whose response has not yet arrived.
    pub(crate) status: Option<u16>,
    /// The amendment sequence at which this event was last completed, or `None` while nothing has
    /// amended it. It is a SECOND monotonic cursor (distinct from `seq`): a `--follow` reader that
    /// already passed this event's `seq` uses it to pick the event up again once its status (and,
    /// when captured, its traffic) arrives, so `--with-status` is not blank in follow mode.
    ///
    /// Server-side only — never sent over the wire (the reader tracks the ring's amend cursor from
    /// the `amended=` reply line).
    pub(crate) amend_seq: Option<u64>,
    /// Whether a traffic capture is still being filled in for this exchange. While it is, an
    /// arriving status fills the field but does **not** amend: the capture is what completes the
    /// record, so the event is re-emitted exactly once, carrying everything. Server-side only.
    pub(crate) awaiting_capture: bool,
    /// Which proxy pushed this event ([`Plane`]) — the session's own or a declared task's
    /// per-invocation one, both of which append here.
    ///
    /// Server-side only — never sent over the wire, so a client-decoded event carries
    /// [`Plane::Unknown`]. The one consumer that needs it, `--net-learn`, snapshots the ring
    /// in-process while the launch still holds it.
    pub(crate) plane: Plane,
    /// Configured secrets seen crossing this exchange's WebSocket tunnel, if any. Empty for
    /// everything else: the two HTTP tripwires act on the exchange itself (a `403` outbound, a
    /// masked response inbound), while an open tunnel is relayed byte-exact, so the sighting IS the
    /// outcome there. Each credential appears at most once per direction — a value that keeps
    /// crossing says nothing new after the first time — and the event keeps at most
    /// [`SIGHTINGS_MAX`] of them.
    pub(crate) secrets_seen: Vec<SecretSighting>,
}

/// Which way a configured secret was seen crossing an open WebSocket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum SecretWay {
    /// Cage → upstream: the agent sent it out.
    Out,
    /// Upstream → cage: the far side sent it back.
    Back,
}

impl SecretWay {
    /// The stable wire/display token for this direction.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SecretWay::Out => "out",
            SecretWay::Back => "back",
        }
    }

    /// Parse the wire token back, for the reading client.
    pub(crate) fn parse(token: &str) -> Option<Self> {
        match token {
            "out" => Some(SecretWay::Out),
            "back" => Some(SecretWay::Back),
            _ => None,
        }
    }
}

/// One configured credential seen crossing a tunnel, and which way it went.
///
/// The `name` is the credential's **logical name** — the label the configuration gave it, never its
/// value. That is the whole point of naming needles: an alarm has to say *which* secret without
/// becoming a second place the secret can be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecretSighting {
    pub(crate) name: String,
    pub(crate) way: SecretWay,
}

/// The result of a `LOG` query: the events past the caller's cursor, how many fell off the ring
/// before that cursor (surfaced, not silently dropped — a bursty agent between `--follow` polls),
/// the newest sequence number (the seq cursor to pass next time, even when `events` is empty), and
/// the newest amendment sequence (the amend cursor to pass next time, for retroactive status).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogSnapshot {
    pub(crate) events: Vec<LogEvent>,
    pub(crate) dropped: u64,
    pub(crate) head: u64,
    pub(crate) amend_head: u64,
    /// The captured traffic for those of `events` that have a capture retained — empty unless the
    /// reader asked for it (`--with-headers`/`--with-body`) and the launch captures at all.
    pub(crate) captures: Vec<Capture>,
    /// How many captures this session has evicted to stay inside its byte budget, so a reader can be
    /// told its view is partial rather than inferring completeness from a missing body.
    pub(crate) capture_evicted: u64,
}

/// A bounded ring of recent egress decisions, newest appended, oldest evicted past `cap`. Shared
/// (via `Arc`) between the side that applies what each proxy reports (which
/// [`push`](LogRing::push)es, see [`crate::sandbox::proxy::events`]) and the control serve thread
/// (which [`snapshot`](LogRing::snapshot)s for `sbx net log`). Sequence numbers start at 1 and
/// never repeat within a session, so a `--follow` cursor of 0 means "from the beginning" and can
/// never collide with a real event.
pub(crate) struct LogRing {
    inner: Mutex<LogInner>,
    cap: usize,
    /// Where every decision is also written, when the launch asked for a session record. `None` is
    /// the default and the shape this ring always had. See [`LogRing::with_record`].
    record: Option<super::lens::Recorder>,
    /// The `--follow` readers of this ring, each as its last read left it
    /// ([`LogRing::followed`]), for [`LogRing::linger`] to wait on.
    followers: Mutex<Vec<FollowRead>>,
    /// Signalled on every follow read, so a [`LogRing::linger`] ends at the read it waits for.
    follow_read: Condvar,
}

/// One `--follow` reader of a [`LogRing`], as its last read left it.
struct FollowRead {
    /// The reader, by the process id it announced.
    reader: u32,
    /// When it last read.
    at: Instant,
    /// How often it reads, as it announced.
    interval: Duration,
    /// The newest event sequence that read covered.
    head: u64,
    /// The newest amendment sequence that read covered, for a reader that asks for amendments.
    amend: Option<u64>,
}

// The same choice [`crate::sandbox::signer_control::SignerRing`] makes, for the same reason: a
// `Debug` that dumped a session's whole egress record would be noise wherever a holder of this ring
// renders itself, and the events carry cage-chosen text. The count is what a reader of such a line
// wants. Taken without the lock, so rendering a holder can never wait on a serve thread.
impl std::fmt::Debug for LogRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LogRing(cap {})", self.cap)
    }
}

struct LogInner {
    next_seq: u64,
    /// How many events the cap has evicted from each ring, and for each the newest seq that
    /// eviction took. [`LogRing::snapshot`] needs all four to report an eviction gap: the two rings
    /// share `next_seq`, so the distance between a reader's cursor and the oldest retained event
    /// counts seqs that muted refusals took and that `events` never held, while `evicted_high`
    /// alone says whether what `events` lost is past that cursor at all.
    evicted: u64,
    evicted_high: u64,
    muted_evicted: u64,
    muted_evicted_high: u64,
    /// The next amendment sequence [`LogRing::set_status`] will stamp — a second monotonic counter,
    /// bumped only when a status is filled in, so a follow reader can pick up retroactive statuses.
    next_amend: u64,
    events: VecDeque<LogEvent>,
    /// Muted refusals, kept out of the default view. A **separate** ring with the same cap so a
    /// chatty muted host can never evict a real event from `events`; merged in (by `seq`) only when
    /// a reader passes `include_muted` (`sbx net log --all`). Shares `next_seq` with `events`, so the
    /// two interleave in one monotonic order.
    muted: VecDeque<LogEvent>,
}

impl LogRing {
    pub(crate) fn new(cap: usize) -> Self {
        LogRing {
            inner: Mutex::new(LogInner {
                next_seq: 1,
                evicted: 0,
                evicted_high: 0,
                muted_evicted: 0,
                muted_evicted_high: 0,
                next_amend: 1,
                events: VecDeque::new(),
                muted: VecDeque::new(),
            }),
            cap: cap.max(1),
            record: None,
            followers: Mutex::new(Vec::new()),
            follow_read: Condvar::new(),
        }
    }

    /// How many events each of the two rings holds before it evicts its oldest.
    pub(crate) fn cap(&self) -> usize {
        self.cap
    }

    /// Attach this session's record, so the decisions also reach a file that outlives the session.
    ///
    /// Attached where the ring is **created**, never where one is passed in: a task's per-invocation
    /// proxy is handed the session's ring (see [`super::egress::Egress::event_log`]), and attaching
    /// there would open a second record at the same path and truncate the first.
    pub(crate) fn with_record(mut self, record: Option<super::lens::Recorder>) -> Self {
        self.record = record;
        self
    }

    /// Append one decision, assigning it the next sequence number and evicting the oldest if the ring
    /// is full. Called with the path already query-redacted by the proxy. Returns the assigned
    /// sequence number, so a later [`set_status`](LogRing::set_status) can amend this same event once
    /// its upstream response returns.
    ///
    /// `plane` names the proxy the decision is from, because a ring is shared by proxies enforcing
    /// different policies — see [`Plane`]. It is a property of that proxy, not of a request: the
    /// side applying one proxy's reports passes the same value for every event.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn push(
        &self,
        muted: bool,
        host: &str,
        port: u16,
        method: Option<&str>,
        path: Option<&str>,
        verdict: LogVerdict,
        reason: &str,
        proto: Proto,
        http_ver: HttpVer,
        rpc: RpcKind,
        plane: Plane,
    ) -> u64 {
        let at_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut guard = locked(&self.inner);
        let g = &mut *guard;
        let seq = g.next_seq;
        g.next_seq += 1;
        // The three free-form values are sanitised **here**, on the way in, for the reason
        // [`super::proc_control::ExecRing::push_verdict`] states for the exec ring: this is the one
        // door every log event enters by, and the alternative is a duty spread over the ~30 call
        // sites that push one. All three are chosen by the cage — a `Host` header, an SNI, a CONNECT
        // authority, and the raw method and target of a request line, which the two fail-closed
        // refusals in `handle_client` log *before* `head_carries_control_byte` has run at all. So
        // they may carry any byte that is not a line break: an ESC, which paints over the operator's
        // terminal when `sbx net logs` prints the row (`\x1b[1A\x1b[2K` erases the line above, so a
        // cage can overwrite its own earlier `blocked` rows with forged `allow` ones), and a NUL or a
        // CR, which on the line-based control wire would end the event and let what follows read as
        // a second one. `super::egress_stats::Tally::bump` already does exactly this for the host it
        // counts, from the same values; the log — the audit surface — was the sink that skipped it.
        //
        // This is not the decision's view of any of them: every verdict is reached on the raw value,
        // and only what is *reported* passes through here. Sanitising is idempotent, and it runs
        // after the caller's secret redaction so a masked query stays masked.
        //
        // What it does **not** close is the wire line's own tokenisation: it maps a control byte to a
        // space, and a space is what the reader splits `key=value` tokens on. That is a second
        // property, settled a second time, where the line is built — see `head_field`.
        let event = LogEvent {
            seq,
            at_epoch_ms,
            host: super::sanitize(host),
            port,
            method: method.map(super::sanitize),
            path: path.map(super::sanitize),
            verdict,
            // A constant when the proxy is honest, but it arrives from the proxy's process, which
            // is held to what it reports ([`crate::sandbox::proxy::events`]) like the three above.
            reason: super::sanitize(reason),
            proto,
            http_ver,
            rpc,
            plane,
            muted,
            status: None,
            amend_seq: None,
            awaiting_capture: false,
            secrets_seen: Vec::new(),
        };
        // A muted refusal goes to its own ring so it can never evict a real event from `events`;
        // both rings share `self.cap` and the monotonic `seq`.
        let ring = if muted { &mut g.muted } else { &mut g.events };
        // Cloned only when there is a record to write, and only for an event the record keeps. A
        // muted refusal is not one: `mute` is `dontaudit`, and on disk a muted flood does not evict
        // real events the way the separate ring stops it doing in memory — it fills the file's cap
        // and truncates the tail, which is the real events at the end of the session. The counters
        // `sbx net stats` keeps for it are unaffected, which is the contract `mute` already had.
        let recorded = self
            .record
            .as_ref()
            .filter(|_| !muted)
            .map(|_| event.clone());
        ring.push_back(event);
        // Counted as they go, per ring: what a reader lost is the events the cap took out of
        // `events`, and a seq missing from it is as often a muted refusal that was never there.
        // Each ring also keeps the newest seq its cap took, which is what places an eviction
        // relative to a follower's cursor.
        let mut taken = 0u64;
        let mut highest = None;
        while ring.len() > self.cap {
            highest = ring.pop_front().map(|e| e.seq);
            taken += 1;
        }
        if muted {
            g.muted_evicted += taken;
            if let Some(seq) = highest {
                g.muted_evicted_high = seq;
            }
        } else {
            g.evicted += taken;
            if let Some(seq) = highest {
                g.evicted_high = seq;
            }
        }
        drop(guard);
        if let (Some(record), Some(event)) = (&self.record, recorded) {
            record.record(&format_event_line(&event));
        }
        seq
    }

    /// Amend an already-pushed event with the upstream HTTP status code its response returned. A no-op
    /// if the event has already been evicted from the ring (a very bursty session between the push and
    /// the response), so a late status never resurrects an evicted event. Events are appended in
    /// sequence order, so a reverse scan finds the target quickly (the amend usually lands on the
    /// newest events).
    pub(crate) fn set_status(&self, seq: u64, status: u16) {
        let recorded = {
            let mut guard = locked(&self.inner);
            let g = &mut *guard;
            let Some(ev) = g.events.iter_mut().rev().find(|e| e.seq == seq) else {
                return;
            };
            ev.status = Some(status);
            if ev.awaiting_capture {
                // A capture is still being filled in for this exchange. Amending now would re-emit
                // the event with a status but no traffic, and again once the capture lands — so hold
                // the amendment for `capture_settled`, which fires exactly once. The record waits
                // with it, so a file never carries the same status twice.
                return;
            }
            // Stamp the amendment cursor so a follow reader that already passed this event's `seq`
            // re-reads it once (with its status now filled) on its next poll.
            ev.amend_seq = Some(g.next_amend);
            g.next_amend += 1;
            self.record.as_ref().map(|_| format_amend_line(seq, status))
        };
        self.write_record(recorded);
    }

    /// Append one already-formatted line to the session record, outside the ring's lock. `None` is
    /// the ordinary case of a launch that keeps no record.
    fn write_record(&self, line: Option<String>) {
        if let (Some(record), Some(line)) = (&self.record, line) {
            record.record(&line);
        }
    }

    /// Mark the event `seq` as having a traffic capture on the way, so an arriving status waits for
    /// [`capture_settled`](LogRing::capture_settled) instead of amending on its own. Called right
    /// after the event is pushed, only when the launch captures.
    pub(crate) fn expect_capture(&self, seq: u64) {
        let mut g = locked(&self.inner);
        if let Some(ev) = g.events.iter_mut().rev().find(|e| e.seq == seq) {
            ev.awaiting_capture = true;
        }
    }

    /// Release the amendment held back for a pending capture. `filed` says whether a capture was
    /// actually stored; with none, the event is amended only if a status is waiting to be shown (so
    /// an exchange with nothing new is not re-emitted at all).
    pub(crate) fn capture_settled(&self, seq: u64, filed: bool) {
        let recorded = {
            let mut guard = locked(&self.inner);
            let g = &mut *guard;
            let Some(ev) = g.events.iter_mut().rev().find(|e| e.seq == seq) else {
                return;
            };
            ev.awaiting_capture = false;
            if !filed && ev.status.is_none() {
                return;
            }
            ev.amend_seq = Some(g.next_amend);
            g.next_amend += 1;
            // The status this release was holding, if one arrived while the capture filled. A
            // capture that settled with no status has nothing the file can carry: the traffic is in
            // its own store, and the record is a line per decision.
            let status = ev.status;
            self.record
                .as_ref()
                .zip(status)
                .map(|(_, status)| format_amend_line(seq, status))
        };
        self.write_record(recorded);
    }

    /// Amend the event `seq` again because its capture grew after it was first settled — the one case
    /// where an exchange is worth re-emitting twice.
    ///
    /// A WebSocket is that case and the only one: its handshake settles at the `101` (so the tunnel's
    /// opening is visible while it is open), and the frames that cross afterwards are a second thing
    /// to show. Every other exchange settles once and is never re-emitted again.
    pub(crate) fn capture_grew(&self, seq: u64) {
        let mut guard = locked(&self.inner);
        let g = &mut *guard;
        if let Some(ev) = g.events.iter_mut().rev().find(|e| e.seq == seq) {
            ev.amend_seq = Some(g.next_amend);
            g.next_amend += 1;
        }
    }

    /// Note that a configured secret was seen crossing the tunnel of event `seq`, and amend the
    /// event so a `--follow` reader is told **while the tunnel is still open**.
    ///
    /// The amendment is unconditional, including while a capture is still filling: an alarm the user
    /// only learns about once the tunnel closes — which for a WebSocket may be hours — is not an
    /// alarm. That is why it does not take the `awaiting_capture` path a status takes. What bounds
    /// the re-emissions instead is the caller: a credential is reported once per direction, so a
    /// tunnel adds at most two amendments per configured secret over its whole life.
    ///
    /// A repeat of an already-recorded (name, direction) is dropped rather than amending again, so a
    /// second caller cannot turn the alarm into a stream, and so is any sighting past
    /// [`SIGHTINGS_MAX`] on one event, since distinct names are the proxy's to invent.
    pub(crate) fn secret_seen(&self, seq: u64, name: &str, way: SecretWay) {
        // The proxy reports the name, and is held to what it reports like every logged field.
        let name = super::sanitize(name);
        let name = name.as_str();
        let mut guard = locked(&self.inner);
        let g = &mut *guard;
        if let Some(ev) = g.events.iter_mut().rev().find(|e| e.seq == seq) {
            if ev.secrets_seen.len() >= SIGHTINGS_MAX
                || ev
                    .secrets_seen
                    .iter()
                    .any(|s| s.name == name && s.way == way)
            {
                return;
            }
            let seen = SecretSighting {
                name: name.to_string(),
                way,
            };
            let recorded = self
                .record
                .as_ref()
                .map(|_| format_sighting_line(seq, &seen));
            ev.secrets_seen.push(seen);
            ev.amend_seq = Some(g.next_amend);
            g.next_amend += 1;
            drop(guard);
            self.write_record(recorded);
        }
    }

    /// The events past `after`, plus the eviction gap and the newest sequences. `after = None` is a
    /// tail read (the whole retained window; never reports a gap — a first read has nothing to miss);
    /// `after = Some(cursor)` is a follow read (events with `seq > cursor`, reporting how many between
    /// the cursor and the retained window were evicted unseen).
    ///
    /// `after_amend = Some(a)` additionally RE-EMITS an already-seen event (`seq <= after`) whose
    /// status was filled in since amendment cursor `a` — so a `--follow --with-status` reader sees a
    /// status that arrives after it passed the event's `seq`. A brand-new event (`seq > after`) is
    /// already included, so it is not re-emitted (no duplicate). `after_amend = None` (a tail read, or
    /// an old reader that does not track the amend cursor) does no retroactive re-emission.
    pub(crate) fn snapshot(
        &self,
        after: Option<u64>,
        after_amend: Option<u64>,
        include_muted: bool,
    ) -> LogSnapshot {
        let g = locked(&self.inner);
        let head = g.next_seq - 1;
        let amend_head = g.next_amend - 1;
        let cursor = after.unwrap_or(0);
        let mut events: Vec<LogEvent> = g
            .events
            .iter()
            .filter(|e| e.seq > cursor)
            .cloned()
            .collect();
        // `--all` folds the separate muted ring into the view, re-sorted into one `seq` order. The
        // default view omits it entirely (muted refusals are suppressed). `dropped`/amend stay keyed
        // on the main ring — a muted eviction never reports a gap (it is suppressed by design).
        if include_muted {
            events.extend(g.muted.iter().filter(|e| e.seq > cursor).cloned());
            events.sort_by_key(|e| e.seq);
        }
        if let Some(a) = after_amend {
            for e in g.events.iter() {
                if e.seq <= cursor && e.amend_seq.is_some_and(|s| s > a) {
                    events.push(e.clone());
                }
            }
        }
        // What the reader lost, counted from the evictions `events` actually made rather than from
        // the distance between the cursor and the oldest retained event: the muted ring takes seqs
        // out of the same counter without ever entering `events`, so that distance reports a gap
        // for a session that only refused muted requests and evicted nothing.
        //
        // *Whether* anything was lost is settled by `evicted_high`, the newest seq the cap took out
        // of `events`. Evictions take the oldest first, so the events gone from `events` are its
        // pushes up to and including that seq, and one of them is past the cursor exactly when
        // `evicted_high > cursor` — a test the muted ring cannot disturb, whatever it evicted.
        //
        // *How many* is counted from the evictions beyond the main-ring events the reader was
        // already given — hence the subtraction. That count of events comes from the seq space:
        // seqs start at 1, so the seqs up to and including the cursor are exactly that many pushes,
        // of which the ones muted refusals took are not the main ring's. Retained muted pushes are
        // counted directly and evicted ones from the counter, which is exact as long as the cursor
        // is at or past the newest muted eviction. Past that the muted ring has overflowed too, its
        // pre-cursor pushes are no longer separable from the main ring's, and the count falls short
        // — but never below the one event `evicted_high` has already proved lost, because a
        // reported gap is what a reader acts on and a silent loss is what it cannot.
        let dropped = match after {
            Some(a) if g.evicted_high > a => {
                let muted_seen = g.muted.iter().filter(|e| e.seq <= a).count() as u64
                    + if g.muted_evicted_high <= a {
                        g.muted_evicted
                    } else {
                        0
                    };
                let main_seen = a.saturating_sub(muted_seen);
                g.evicted.saturating_sub(main_seen).max(1)
            }
            _ => 0,
        };
        LogSnapshot {
            events,
            dropped,
            head,
            amend_head,
            // The captures are attached by whoever serves this snapshot (the control dispatch reads
            // them from the separate capture ring, and only when the reader asked for them).
            captures: Vec::new(),
            capture_evicted: 0,
        }
    }

    /// Note a `--follow` read: `reader` announced itself with the `interval` it polls at, and was
    /// handed `snapshot`. `amendments` says whether the read asked for amendments, so that a status
    /// or a capture the reader never shows is no reason to wait for it.
    pub(crate) fn followed(
        &self,
        reader: u32,
        interval: Duration,
        snapshot: &LogSnapshot,
        amendments: bool,
    ) {
        let read = FollowRead {
            reader,
            at: Instant::now(),
            interval,
            head: snapshot.head,
            amend: amendments.then_some(snapshot.amend_head),
        };
        let mut followers = locked(&self.followers);
        match followers.iter_mut().find(|f| f.reader == reader) {
            Some(known) => *known = read,
            None => {
                if followers.len() >= FOLLOWERS_MAX
                    && let Some(oldest) = (0..followers.len()).min_by_key(|&i| followers[i].at)
                {
                    followers.swap_remove(oldest);
                }
                followers.push(read);
            }
        }
        drop(followers);
        self.follow_read.notify_all();
    }

    /// Wait until every `--follow` reader of this ring has read it since its last change, for at
    /// most `max`.
    ///
    /// A session calls this as it ends, once the last of what its proxy reported is in the ring
    /// and before its control socket goes. A follow reads on an interval, so what arrived after
    /// its last read (the status and the traffic of an exchange that ended with the session)
    /// would otherwise go with the socket, unread. The wait is for the follow's next read, and it
    /// ends at that read.
    ///
    /// Only a reader that is still polling is waited for: one whose next read is overdue by more
    /// than [`FOLLOW_SLACK`] has stopped, and one whose next read falls past `max` is not waited
    /// for at all. A session no follow has read, or whose follows have read everything, does not
    /// wait.
    pub(crate) fn linger(&self, max: Duration) {
        let end = Instant::now() + max;
        let (head, amend_head) = {
            let g = locked(&self.inner);
            (g.next_seq - 1, g.next_amend - 1)
        };
        let mut followers = locked(&self.followers);
        loop {
            let now = Instant::now();
            let due = followers
                .iter()
                .filter(|f| f.head < head || f.amend.is_some_and(|a| a < amend_head))
                .map(|f| f.at + f.interval + FOLLOW_SLACK)
                .filter(|&due| due > now && due <= end)
                .max();
            let Some(due) = due else { return };
            followers = self
                .follow_read
                .wait_timeout(followers, due - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

// ── The live active-flow registry ─────────────────────────────────────────────────────────────
//
// The set of egress tunnels currently OPEN through the proxy, read live by `sbx net live` over the
// same per-session control socket. Unlike the event log (a *history* of decisions), this is volatile
// state: a flow appears when its tunnel is established and vanishes when it closes. It is never
// persisted and never crosses into the cage — it lives in the launch process's owner-only RAM for the
// session's lifetime, at the same trust level as the log.
//
// The registry is written by the side that applies what the proxy reports
// ([`crate::sandbox::proxy::events`]): a flow's opening and closing as they happen, and its two byte
// totals (`up` = client→upstream, `down` = upstream→client) on the proxy's reporting tick. The
// counting itself stays in the proxy, on lock-free counters the relay bumps per read/write
// ([`crate::sandbox::proxy::flows::FlowGuard`]), so the hot relay path never touches this lock.

/// One open tunnel captured for `sbx net live`: where it goes, how it is carried, when it opened, and
/// how much has flowed each way so far. `up`/`down` are byte totals — application-plaintext bytes on
/// an inspected L7/cleartext path, raw ciphertext bytes on a `tcp://` L4 splice (the proxy sees only
/// the encrypted stream there).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FlowSnapshot {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) proto: Proto,
    /// When the tunnel was established, epoch milliseconds. The CLI renders the age (now − start).
    pub(crate) start_epoch_ms: u128,
    pub(crate) up: u64,
    pub(crate) down: u64,
}

/// The most flows the registry lists at once. A proxy has no more tunnels open than its connection
/// cap and each connection's streams allow, so this is reached only by a proxy reporting flows it
/// does not have; past it an opening is not listed, and the view stays bounded. What each listing
/// keeps is bounded on arrival too: a host longer than the 253 bytes of a name is no flow the proxy
/// opened ([`crate::sandbox::proxy::events`]), so the listed hosts take under 16 MiB together.
const MAX_OPEN_FLOWS: usize = 65_536;

/// The set of currently-open egress tunnels, keyed by the number the proxy gave each. Shared (via
/// `Arc`) between the side applying the proxy's reports and the control serve thread (which
/// [`snapshot`](FlowRegistry::snapshot)s for `sbx net live`). One registry serves one proxy, and that
/// proxy numbers its flows in the order it opens them, so the snapshot order is stable
/// (oldest-open first).
pub(crate) struct FlowRegistry {
    inner: Mutex<BTreeMap<u64, FlowSnapshot>>,
}

impl FlowRegistry {
    pub(crate) fn new() -> Self {
        FlowRegistry {
            inner: Mutex::new(BTreeMap::new()),
        }
    }

    /// List the tunnel the proxy opened as `id`, with zeroed totals and the current time as its
    /// start. An `id` already listed, or one past [`MAX_OPEN_FLOWS`], changes nothing.
    pub(crate) fn open(&self, id: u64, host: &str, port: u16, proto: Proto) {
        let start_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut flows = locked(&self.inner);
        if flows.len() >= MAX_OPEN_FLOWS || flows.contains_key(&id) {
            return;
        }
        flows.insert(
            id,
            FlowSnapshot {
                host: host.to_string(),
                port,
                proto,
                start_epoch_ms,
                up: 0,
                down: 0,
            },
        );
    }

    /// Set the totals of the tunnel `id` to what the proxy last counted. Absolute rather than added,
    /// so a report applied late or twice still shows the right figure. A tunnel no longer listed is
    /// left closed.
    pub(crate) fn count(&self, id: u64, up: u64, down: u64) {
        if let Some(flow) = locked(&self.inner).get_mut(&id) {
            flow.up = up;
            flow.down = down;
        }
    }

    /// Remove the tunnel `id` from the live view: it has closed. Recovering rather than skipping the
    /// removal on a poisoned lock is what keeps the registry a view of what is *open*: a skipped
    /// removal would leave a closed tunnel listed by `sbx net live` for the rest of the session.
    pub(crate) fn close(&self, id: u64) {
        locked(&self.inner).remove(&id);
    }

    /// A snapshot of every currently-open flow, oldest-open first. A total climbing between two
    /// snapshots is a transfer in progress.
    pub(crate) fn snapshot(&self) -> Vec<FlowSnapshot> {
        locked(&self.inner).values().cloned().collect()
    }
}

/// Everything a control command is served against, shared in from the proxy that holds them.
///
/// One value rather than a parameter each, because they travel as a set: `serve` shares the whole
/// set with every connection's thread, and the dispatcher reaches for a different member per verb.
/// The `Option` is the plane a launch may not have configured.
///
/// The durable counters are not here: the only verb that writes them is the tap's `RESOLVED`,
/// which [`serve_reports`] serves on a socket of its own.
pub(crate) struct Planes {
    /// The `ask` queue a decision is parked in.
    pub(crate) state: Arc<PendingState>,
    /// The live rule overlay `REMEMBER` writes to.
    pub(crate) manual: Arc<ManualRules>,
    /// The bounded event ring `sbx net logs` reads.
    pub(crate) log: Arc<LogRing>,
    /// The open-tunnel registry `sbx net live` reads.
    pub(crate) flows: Arc<FlowRegistry>,
    /// The head/body ring, when `[network] capture` asked for one.
    pub(crate) capture: Option<Arc<CaptureRing>>,
}

/// Serve the control socket: one short-lived thread per connection, each handling exactly one
/// command. A per-connection error is that connection's problem, never the server's. The pending
/// queue, the manual-rule overlay, and the event log are shared in (the same ones the proxy holds).
pub(crate) fn serve(
    listener: UnixListener,
    planes: Planes,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> io::Result<()> {
    let gate = Some(super::peer::PeerGate::new("egress control"));
    accept_each(listener, &stop, "egress control", None, gate, move |cmd| {
        Some(dispatch(
            cmd,
            &planes.state,
            &planes.manual,
            &planes.log,
            &planes.flows,
            planes.capture.as_deref(),
        ))
    });
    Ok(())
}

/// The most report connections served at once. The transparent-capture tap reports from a single
/// thread, one connection at a time, so a handful covers a slow control plane; the ceiling is for a
/// peer that opens more.
const REPORT_CONNS: usize = 8;

/// Serve the transparent-capture tap's report socket: the same one-command connections as
/// [`serve`], answered by [`report`] alone.
///
/// The tap parses bytes the cage writes, so it is the one peer of the control plane that runs next
/// to the workload. It was handed the owner's socket, whose other verbs answer parked requests and
/// remember rules, so a flaw in the tap would have been a way to decide egress. This server is
/// handed the event ring and the durable counters and nothing else: the owner's verbs are not
/// refused here, they are out of its reach.
///
/// For the same reason this socket passes no [`super::peer::PeerGate`]: its peer runs in a cage of
/// its own, in a PID namespace beside the agent's, and nothing the kernel says about a peer tells
/// the two apart. What does is `token`, drawn for this launch and handed to the tap alone
/// ([`super::nettap::ReportToken`]): a complete line that does not open with it is closed
/// unanswered before [`report`] reads it, and one cut at the read bound is refused before it is
/// dispatched at all, so a cage that can see this socket adds nothing to the record or the
/// counters. It can still hold the socket's connections open until each one's read times out,
/// and the tap's reports are dropped while it does.
pub(crate) fn serve_reports(
    listener: UnixListener,
    token: super::nettap::ReportToken,
    log: Arc<LogRing>,
    stats: Option<Arc<super::egress_stats::EgressStats>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> io::Result<()> {
    let cap = super::conncap::ConnCap::new(REPORT_CONNS);
    accept_each(
        listener,
        &stop,
        "egress reports",
        Some(cap),
        None,
        move |line| Some(report(token.admits(line)?, &log, stats.as_deref())),
    );
    Ok(())
}

/// The accept loop of both of this module's sockets: each connection on a thread of its own,
/// answered by `dispatch`, until `stop` is set. With a `cap`, a connection past the ceiling is
/// closed unanswered; with a `gate`, so is one whose peer runs outside this process's PID
/// namespace, before it takes a slot. A command `dispatch` answers with `None` is closed
/// unanswered as well.
fn accept_each<F>(
    listener: UnixListener,
    stop: &std::sync::atomic::AtomicBool,
    who: &'static str,
    cap: Option<super::conncap::ConnCap>,
    mut gate: Option<super::peer::PeerGate>,
    dispatch: F,
) where
    F: Fn(&str) -> Option<String> + Send + Sync + 'static,
{
    let dispatch = Arc::new(dispatch);
    for stream in listener.incoming() {
        // See [`super::proxy::serve`]: the owner sets this and pokes the socket to unpark `accept`.
        if stop.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                // The same defence the proxy's accept loop in this very process already carries,
                // and for the same reason: a transient `accept(2)` error (host fd exhaustion, a
                // connection aborted between the SYN and the accept) is not this server's death.
                //
                // `?` here ended the `for` loop, and this function is the body of a detached thread
                // — so returning dropped the `UnixListener` and closed the listening fd for the rest
                // of the launch. Every `sbx net` verb then failed for a session that was otherwise
                // running fine, while the socket file stayed on disk (only `Egress::drop` unlinks
                // it) and `session_pids` kept reporting the pid, so nothing said the control plane
                // was gone. The doc of [`serve`] already stated the rule this broke: "A
                // per-connection error is that connection's problem, never the server's."
                crate::diag::error(&format!("sbx: {who}: accept error: {e}"));
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
        };
        if let Some(gate) = gate.as_mut()
            && !gate.admits(&stream)
        {
            continue;
        }
        let slot = match &cap {
            Some(cap) => match cap.take() {
                Some(slot) => Some(slot),
                None => continue,
            },
            None => None,
        };
        let dispatch = Arc::clone(&dispatch);
        super::conncap::spawn_conn(who, move || {
            let _slot = slot;
            let _ = handle(stream, dispatch.as_ref());
        });
    }
}

/// The largest control command accepted. Most commands are short (`ALLOW <seq>`), but `REMEMBER
/// ALLOW|DENY <rule>` carries a full egress rule (a long regex or URL rule), so the bound matches the
/// reply bound rather than the terse-command size — still bounded so a confused or hostile peer
/// cannot make us buffer unboundedly. The peer is the owner-only, host-side control client.
const CMD_MAX: u64 = 8 * 1024;

/// The reply to a `--session` rule the proxy did not confirm it holds: the rule is kept by the
/// session and pushed again with the next change, but nothing vouches that it decides requests yet,
/// so the command that asked for it reports that instead of the rule. An answer that was to remember
/// its destination answers nothing.
pub(crate) const UNCONFIRMED: &str = "err unconfirmed";

/// The largest control *reply* accepted. A reply carries the destination the agent reached
/// (`ok host=<h> …`), which for a URL rule is far longer than a terse command: a bound sized for
/// `ALLOW <seq>` would truncate the host and, with `--save`, persist a wrong (agent-influenceable)
/// rule. Still bounded (a URL is not unbounded) so a hostile peer cannot make the reader buffer
/// forever.
///
/// Equal to [`CMD_MAX`], and that is the direction the equality was reached from: this bound was
/// sized for a URL first, and the command bound was then raised to match it because `REMEMBER
/// ALLOW|DENY <rule>` carries the same shape of value. Two names for one size, kept apart because
/// they answer two questions and either could move alone.
const REPLY_MAX: u64 = 8 * 1024;

/// Handle one control connection: read a single command line, dispatch it, write the response, and
/// close; a command `dispatch` gives no response is closed with nothing written. The bound read and
/// the timeout hold against a stuck or malformed caller on either socket.
fn handle(stream: UnixStream, dispatch: &dyn Fn(&str) -> Option<String>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new((&stream).take(CMD_MAX));
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    // A command that filled the bound with no terminating newline was truncated, and dispatching a
    // truncated command is dispatching a *different* one: `REMEMBER ALLOW <rule>` cut short is
    // another rule, which the `session` token then loads into the live overlay. Refused rather than
    // parsed — the rule the reply reader already applies on the other half of this exchange
    // ([`client`]), where a partial host would be persisted by `--save`.
    let response = match n as u64 >= CMD_MAX && !line.ends_with('\n') {
        true => "err bad-request\n".to_string(),
        false => match dispatch(line.trim()) {
            Some(response) => response,
            None => return Ok(()),
        },
    };
    (&stream).write_all(response.as_bytes())?;
    (&stream).flush()
}

/// Map a control command to its response. `LIST` returns one `pending …` line per parked request
/// then `ok`; `ALLOW <seq>`/`DENY <seq>` answer every parked request to that request's destination
/// (its `host:port/path` — identical retries are one decision; a trailing `session` token also
/// remembers it as a manual rule), replying `ok host=<host> count=<n>` or `err not-found`;
/// `ALLOW *`/`DENY *` drain *every* parked request, replying one `answered host=<host>` line each
/// then `ok` (the `session` token remembers each); `REMEMBER ALLOW|DENY|MUTE <rule>` loads a
/// proactive `--session` rule into the overlay (`ok`, or `err bad-request` for an
/// unclassifiable/absent rule), which the proxy folds into its effective policy. Every verb that
/// remembers a rule replies [`UNCONFIRMED`] instead when the proxy did not confirm it holds it, and
/// an answer that was to remember then answers nothing; one whose request timed out while its rule
/// was being confirmed keeps the rule and replies `ok host=<host> count=0`. `RULES` returns the
/// session's manual rules (`manual allow|deny <rule>` lines) then `ok`. `LOG` returns the recent
/// egress events (a `dropped=` line when a `--follow` cursor fell behind the ring, a `head=`
/// cursor, then one `event …` line each) then `ok`; `LOG after=<seq>` returns only events past that
/// cursor, and a `follow=<pid>:<ms>` token names a `--follow` reader and its poll interval
/// ([`LogRing::followed`]). `path` is emitted last on a `pending`/`event` line so a query
/// string's `=` cannot be mistaken for a field separator (the reader splits each token on its
/// first `=`).
///
/// The transparent-capture tap's reports are not verbs of this socket: they arrive on the tap's own
/// ([`report`]), and here they are a bad request like any other unknown word.
fn dispatch(
    cmd: &str,
    state: &PendingState,
    manual: &ManualRules,
    log: &LogRing,
    flows: &FlowRegistry,
    capture: Option<&CaptureRing>,
) -> String {
    let mut parts = cmd.split_whitespace();
    match parts.next() {
        Some("LIST") => {
            let mut out = String::new();
            for row in state.list() {
                // The two cage-chosen fields get the same treatment as the event line's, and for
                // the same two reasons: [`PendingState::park`] has already stripped the control
                // characters that would end the line, and [`head_field`]/[`trailing_field`] stop
                // whitespace from splitting off a token that either restates a field of this row or
                // — carrying no `=` — makes the reader drop the request altogether, leaving the cage
                // parked with no id to answer it by. `path` is last, so its value is everything past
                // the first `=` and a query string's own `=` round-trips.
                out.push_str(&format!(
                    "pending seq={} inc={} port={} waiting={} host={} path={}\n",
                    row.seq,
                    incarnation_field(),
                    row.port,
                    row.waiting_secs,
                    head_field(&row.host),
                    trailing_field(&row.path)
                ));
            }
            out.push_str("ok\n");
            out
        }
        Some(verb @ ("ALLOW" | "DENY")) => {
            let verdict = if verb == "ALLOW" {
                Verdict::Allow
            } else {
                Verdict::Deny
            };
            // The target is a seq, or `*` for every parked request (a bulk drain). A trailing
            // `session` token (after either) also remembers each decision as a live manual rule.
            let Some(target) = parts.next() else {
                return "err bad-request\n".to_string();
            };
            // What follows the target is a set of tokens rather than a position: `session` has been
            // one from the start, `inc=` was added beside it, and an unknown one is ignored so a
            // client newer than this server is answered rather than refused.
            let mut remember = false;
            let mut claimed: Option<&str> = None;
            for token in parts {
                match token {
                    "session" => remember = true,
                    _ => {
                        if let Some(ticks) = token.strip_prefix("inc=") {
                            claimed = Some(ticks);
                        }
                    }
                }
            }
            if let Some(claimed) = claimed
                && !is_our_incarnation(claimed)
            {
                // The id was minted by another incarnation of this pid — this session inherited the
                // number from a predecessor, and the request the operator means is gone with it.
                // Answered as a request this session does not have, which is exactly what it is.
                return "err not-found\n".to_string();
            }
            // With `session`, the destination is remembered before the request is freed, so its
            // retry is decided by the rule rather than parked again, and a rule the proxy did not
            // confirm answers nothing: the operator is told, and nothing is half done.
            let first = |host: &str, port: u16| match remember {
                true => manual.remember(verdict, host, port),
                false => Ok(()),
            };
            if target == "*" {
                // Drain framing mirrors `LIST`: one `answered host=…` line per request, then `ok`.
                // An empty queue is a clean `ok` (nothing to answer is not an error).
                let Ok(answered) = state.answer_all_after(verdict, first) else {
                    return format!("{UNCONFIRMED}\n");
                };
                let mut out = String::new();
                for (host, _) in answered {
                    out.push_str(&format!("answered host={}\n", head_field(&host)));
                }
                out.push_str("ok\n");
                return out;
            }
            let Some(seq) = target.parse::<u64>().ok() else {
                return "err bad-request\n".to_string();
            };
            match state.answer_like_after(seq, verdict, first) {
                // A count of 0 is a request gone while `first` ran: with `session` its rule is in
                // force and the reply says so, without it nothing was done.
                //
                // `host` is not the last token here — `count` follows it — so whitespace in it would
                // shift what the reader reads as the count.
                Ok(Some((host, _, count))) if count > 0 || remember => {
                    format!("ok host={} count={count}\n", head_field(&host))
                }
                Ok(_) => "err not-found\n".to_string(),
                Err(_) => format!("{UNCONFIRMED}\n"),
            }
        }
        Some("REMEMBER") => {
            // `REMEMBER ALLOW|DENY <rule>` loads a proactive `--session` rule. The rule is the
            // remainder of the line taken **verbatim** (not whitespace-split): an egress rule can be a
            // `re:` regex carrying spaces. Re-validated here through the same classifier the config
            // resolver uses, so a malformed rule the CLI somehow let through cannot enter the overlay.
            let body = cmd["REMEMBER".len()..].trim_start();
            // `MUTE` is a log-suppression rule, not a verdict, so it routes to the mute overlay
            // rather than [`ManualRules::remember_rule`]; `ALLOW`/`DENY` stay verdict rules.
            enum Kind {
                Verdict(Verdict),
                Mute,
            }
            let (kind, rule_text) = if let Some(r) = body.strip_prefix("ALLOW ") {
                (Kind::Verdict(Verdict::Allow), r.trim())
            } else if let Some(r) = body.strip_prefix("DENY ") {
                (Kind::Verdict(Verdict::Deny), r.trim())
            } else if let Some(r) = body.strip_prefix("MUTE ") {
                (Kind::Mute, r.trim())
            } else {
                return "err bad-request\n".to_string();
            };
            let Ok(rule) = crate::allowlist::classify(rule_text) else {
                return "err bad-request\n".to_string();
            };
            let loaded = match kind {
                Kind::Verdict(v) => manual.remember_rule(v, rule),
                Kind::Mute => manual.remember_mute(rule),
            };
            match loaded {
                Ok(()) => "ok\n".to_string(),
                Err(_) => format!("{UNCONFIRMED}\n"),
            }
        }
        Some("RULES") => {
            let (allow, deny) = manual.snapshot();
            let mut out = String::new();
            // The rule text is emitted after the `manual allow `/`manual deny `/`manual mute ` prefix;
            // the reader takes the whole remainder, so a rule carrying whitespace (a `re:` regex)
            // round-trips.
            for rule in allow {
                out.push_str(&format!("manual allow {rule}\n"));
            }
            for rule in deny {
                out.push_str(&format!("manual deny {rule}\n"));
            }
            for rule in manual.mute_snapshot() {
                out.push_str(&format!("manual mute {rule}\n"));
            }
            out.push_str("ok\n");
            out
        }
        Some("LOG") => {
            // An optional `after=<seq>` makes this a follow read (events past the cursor, with the
            // eviction gap reported); absent, it is a tail read of the whole retained window. An
            // optional `amended=<seq>` opts into retroactive status re-emission (a `--with-status`
            // follow); an old reader that omits it gets today's behavior (no re-emission).
            let mut after = None;
            let mut after_amend = None;
            let mut include_muted = false;
            let mut want_capture = false;
            let mut follow = None;
            for token in parts {
                if let Some(v) = token.strip_prefix("after=") {
                    after = v.parse().ok();
                } else if let Some(v) = token.strip_prefix("amended=") {
                    after_amend = v.parse().ok();
                } else if let Some(v) = token.strip_prefix("follow=") {
                    // `sbx net logs --follow` — the reader's process id and poll interval in
                    // milliseconds, so the session can wait for its next read as it ends.
                    follow = v.split_once(':').and_then(|(reader, ms)| {
                        Some((reader.parse::<u32>().ok()?, ms.parse::<u64>().ok()?))
                    });
                } else if token == "all" {
                    // `sbx net log --all` — fold the muted (`dontaudit`) ring into the view.
                    include_muted = true;
                } else if token == "capture" {
                    // `sbx net log --with-headers/--with-body` — attach the captured traffic. Sent
                    // only when asked, so an ordinary listing never carries request/response bytes.
                    want_capture = true;
                }
            }
            let snapshot = log.snapshot(after, after_amend, include_muted);
            if let Some((reader, ms)) = follow {
                let interval = Duration::from_millis(ms);
                log.followed(reader, interval, &snapshot, after_amend.is_some());
            }
            let mut out = String::new();
            if snapshot.dropped > 0 {
                out.push_str(&format!("dropped={}\n", snapshot.dropped));
            }
            out.push_str(&format!("head={}\n", snapshot.head));
            out.push_str(&format!("amended={}\n", snapshot.amend_head));
            // Each event's capture (when one is retained) follows its own `event` line, so a reader
            // attaches it without a second lookup and an older reader ignores the unknown lines.
            let captures = match (want_capture, capture) {
                (true, Some(ring)) => {
                    let seqs: Vec<u64> = snapshot.events.iter().map(|e| e.seq).collect();
                    let (found, evicted) = ring.get(&seqs);
                    if evicted > 0 {
                        out.push_str(&format!("capture-evicted={evicted}\n"));
                    }
                    found
                }
                _ => Vec::new(),
            };
            for ev in &snapshot.events {
                out.push_str(&format_event_line(ev));
                // A sighting is not gated on `--with-headers`/`--with-body` the way a capture is: a
                // capture is a debugging convenience the reader opts into, while a secret crossing a
                // tunnel is a fact about the session that has to reach a plain `sbx net logs`.
                out.push_str(&format_sighting_lines(ev));
                if let Some(cap) = captures.iter().find(|c| c.seq == ev.seq) {
                    out.push_str(&format_capture_lines(cap));
                }
            }
            out.push_str("ok\n");
            out
        }
        Some("FLOWS") => {
            // The tunnels open right now (one `flow …` line each, then `ok`). `host` is emitted last
            // so the reader can split every other field on its first `=`, and is made token-safe by
            // `format_flow_line` — the cage names it.
            let mut out = String::new();
            for f in flows.snapshot() {
                out.push_str(&format_flow_line(&f));
            }
            out.push_str("ok\n");
            out
        }
        _ => "err bad-request\n".to_string(),
    }
}

/// Map one of the transparent-capture tap's reports to its response, on the socket
/// [`serve_reports`] serves, which has already taken the launch's token off the front of the line.
/// `RESOLVED <host>` records a name the cage asked for, and
/// `BYPASSED <addr> <port>` a connection it made to an address no name was handed out for; both
/// answer `ok`. Any other verb, the owner's included, is `err bad-request`.
///
/// They are the only verbs whose argument originates in the cage's own traffic, which is why each
/// is held to a type or a restricted alphabet before it becomes a record.
fn report(cmd: &str, log: &LogRing, stats: Option<&super::egress_stats::EgressStats>) -> String {
    let mut parts = cmd.split_whitespace();
    match parts.next() {
        // One line per name, not per query: the tap sends this when it first hands a name an
        // address, so a build resolving one host a thousand times leaves one entry, and what the
        // record answers is "which names did this cage ask for" rather than "how often".
        Some("RESOLVED") => {
            let Some(host) = parts.next() else {
                return "err bad-request\n".to_string();
            };
            // The host is cage-chosen text. It arrives already restricted to name bytes by the
            // tap's own parser, and `push` sanitises every free-form value again on the way in —
            // the second layer being the one that holds if this verb ever gains another caller.
            log.push(
                false,
                host,
                53,
                None,
                None,
                LogVerdict::Resolved,
                "resolved",
                Proto::Dns,
                HttpVer::Unknown,
                RpcKind::None,
                Plane::Agent,
            );
            // Counted as well as logged. The ring above is bounded, so a cage that asks for enough
            // names carries its own earlier entries off the end of it; this is the one number that
            // survives that, and it is why the durable register hears from the tap at all.
            if let Some(stats) = stats {
                stats.record_resolution();
            }
            "ok\n".to_string()
        }
        Some("BYPASSED") => {
            // Machine-checked rather than merely sanitised: this verb carries an address the tap
            // read off a socket, so anything that does not parse as one is a bad request instead of
            // a log line. The refusal is the tap's own — the connection never reached the proxy, so
            // without this the one thing transparent capture makes visible would be visible only in
            // the session's stderr.
            let Some(addr) = parts
                .next()
                .and_then(|a| a.parse::<std::net::Ipv4Addr>().ok())
            else {
                return "err bad-request\n".to_string();
            };
            let Some(port) = parts.next().and_then(|p| p.parse::<u16>().ok()) else {
                return "err bad-request\n".to_string();
            };
            log.push(
                false,
                &addr.to_string(),
                port,
                None,
                None,
                LogVerdict::Blocked,
                // Not the proxy's `ip-literal`, which has a different remedy: that one is admitted
                // by a rule naming the address, and this one cannot be — the tap has no name to
                // decide with. A reader who sees this must make the client resolve the name.
                "dns-bypassed",
                Proto::Tcp,
                HttpVer::Unknown,
                RpcKind::None,
                Plane::Agent,
            );
            "ok\n".to_string()
        }
        _ => "err bad-request\n".to_string(),
    }
}

/// Format one open flow as a control-wire line, `host` last (the reader splits each token on its
/// first `=`). A flow has no method/path — it is a live tunnel, not a decided request.
///
/// The host is the authority of a permitted request, so it is cage-chosen text like the event line's
/// and gets the same two treatments: [`super::sanitize`] against a control byte that would end the
/// line, and [`head_field`] against whitespace that would split the token or an `=` that would name
/// a field of its own. Unlike the event log, the registry stores what it was given, so both are
/// applied here — the flow view is volatile and nothing else reads the stored form.
fn format_flow_line(f: &FlowSnapshot) -> String {
    format!(
        "flow proto={} port={} start={} up={} down={} host={}\n",
        f.proto.as_str(),
        f.port,
        f.start_epoch_ms,
        f.up,
        f.down,
        head_field(&super::sanitize(&f.host)),
    )
}

/// Format one capture as its control-wire lines — one per non-empty part, each following the
/// `event` line it belongs to. The bytes travel base64-encoded (`b64=` last, since its padding is
/// the one `=` a value can end with) because a captured body is arbitrary binary and the wire is
/// line-based. `trunc=1` marks a part cut at its cap.
fn format_capture_lines(cap: &Capture) -> String {
    let mut out = String::new();
    for (part, bytes) in cap.parts() {
        out.push_str(&format!(
            "cap seq={} part={} trunc={} b64={}\n",
            cap.seq,
            part.as_str(),
            u8::from(bytes.truncated),
            base64_encode(&bytes.bytes),
        ));
    }
    out
}

/// Format an event's secret sightings, one `seen` line each, or nothing when it has none.
///
/// `name` is emitted **last** and read as the rest of the line rather than as a whitespace token: a
/// credential's logical name comes from a configuration key, which — unlike a host or a request
/// target — may legitimately contain a space.
fn format_sighting_lines(ev: &LogEvent) -> String {
    let mut out = String::new();
    for seen in &ev.secrets_seen {
        out.push_str(&format_sighting_line(ev.seq, seen));
    }
    out
}

/// One sighting as its wire line. Split out of [`format_sighting_lines`] because the session record
/// writes a sighting the moment it is noticed, one line, where the wire re-emits an event's whole
/// set — and the two must produce the same bytes or a record would not read back as a reply does.
fn format_sighting_line(seq: u64, seen: &SecretSighting) -> String {
    format!(
        "seen seq={} way={} name={}\n",
        seq,
        seen.way.as_str(),
        seen.name,
    )
}

/// One `amend` line: the upstream status of an event already written.
///
/// The file is append-only, so an event completed after it was recorded cannot have its line
/// rewritten. It gets a second line instead, which the reader applies onto the event it names. The
/// capture is not carried: it lives in its own store and stays there.
fn format_amend_line(seq: u64, status: u16) -> String {
    format!("{}seq={seq} status={status}\n", super::lens::RECORD_AMEND)
}

/// This process's incarnation — its start-time ticks — read once.
///
/// The same number [`crate::session::current_start_ticks`] gives the persisted stats file, and for
/// the same reason: a pid is not an identity. A process cannot change its own start time, so this
/// is read once and kept; a host whose `/proc` does not answer leaves it `None`, and the two
/// functions below then behave as this plane did before the field existed.
pub(in crate::sandbox) fn incarnation() -> Option<u64> {
    static TICKS: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *TICKS.get_or_init(crate::session::current_start_ticks)
}

/// The incarnation as it goes on the wire: the ticks, or `-` when this host does not offer them.
///
/// A dash rather than an omitted token, so every `pending` line has the same shape; the reader
/// parses it as a number and simply finds none, which is the same answer it gets from a session
/// too old to send the field at all.
fn incarnation_field() -> String {
    incarnation().map_or_else(|| "-".to_string(), |ticks| ticks.to_string())
}

/// Whether `claimed` names this incarnation.
///
/// A host that cannot read its own start time answers `true` to anything: refusing every tagged id
/// there would make the plane unanswerable on a host where nothing is wrong except that `/proc`
/// is not readable. That leaves such a host exactly where it was before the tag existed, which is
/// the fallback this whole field is a strict improvement on.
fn is_our_incarnation(claimed: &str) -> bool {
    match incarnation() {
        Some(ticks) => claimed.parse::<u64>() == Ok(ticks),
        None => true,
    }
}

/// Make `value` safe to occupy one whitespace-split `key=value` token of a control-wire line.
///
/// [`super::sanitize`] is not that, and cannot be: it maps every control character to a **space**,
/// which is the separator the reader splits on, and it leaves `=` alone. The reader takes a line as
/// `split_whitespace()` then `split_once('=')` per token, so a value carrying a space splits into a
/// token of its own — and that token either rewrites a field the event already stated (a later
/// `verdict=allow` wins over the real one) or, carrying no `=` at all, makes the parse fail and
/// *erase the whole event*. A cage chooses the host, the method and the request target of a logged
/// request, so it chooses whether its own row survives.
///
/// Whitespace is not only the control characters `sanitize` produces: `split_whitespace` splits on
/// Unicode White_Space, and U+00A0 or U+2000‥200A reach here untouched because they are not control
/// characters. This asks `char::is_whitespace`, which is the same set the reader splits on.
///
/// The same two characters [`super::proc_control`]'s `head_token` and [`super::task_control`]'s
/// `head_field` replace, for the same reason and at the same price: a legitimate value carrying a
/// space renders with an underscore, which is a value this line could not have carried either way.
fn head_field(value: &str) -> String {
    value
        .chars()
        .map(|c| match c.is_whitespace() || c == '=' {
            true => '_',
            false => c,
        })
        .collect()
}

/// [`head_field`] for the **last** token on a line, whose value the reader takes as everything past
/// its first `=`. An `=` is therefore free there and must stay: a request target's query string is
/// the one logged value that legitimately carries one, and rewriting it would change what the row
/// says the cage asked for. Whitespace still has to go — it would end the token early whatever its
/// position.
fn trailing_field(value: &str) -> String {
    value
        .chars()
        .map(|c| match c.is_whitespace() {
            true => '_',
            false => c,
        })
        .collect()
}

/// Format one event as a control-wire line. Fields are `key=value` tokens split on their first `=`;
/// `method`/`path` are omitted when absent, and `path` is emitted **last** so a query string's `=`
/// round-trips (it is the only field that can carry one).
///
/// The three cage-chosen fields, and the reason the proxy reports, go through
/// [`head_field`]/[`trailing_field`] on the way out. They
/// reach the ring already stripped of control characters ([`LogRing::push`]), which is what stops
/// them forging a *second line*; this is what stops them forging, or deleting, a *token* of their
/// own line. Both are needed, and neither substitutes for the other.
fn format_event_line(ev: &LogEvent) -> String {
    let mut line = format!(
        "event seq={} at={} port={} verdict={} proto={} reason={}",
        ev.seq,
        ev.at_epoch_ms,
        ev.port,
        ev.verdict.as_str(),
        ev.proto.as_str(),
        head_field(&ev.reason),
    );
    if let Some(status) = ev.status {
        line.push_str(&format!(" status={status}"));
    }
    // Emitted only for a muted event (so a default-view line is byte-unchanged); a reader that
    // requested `--all` uses it to tag the suppressed refusal.
    if ev.muted {
        line.push_str(" muted=1");
    }
    // Emitted only when known/non-default so an older reader ignores the unknown key and an older
    // persisted line (without them) parses back to `Unknown`/`None` — a forward/backward-compatible
    // extension of the line format.
    if ev.http_ver != HttpVer::Unknown {
        line.push_str(&format!(" ver={}", ev.http_ver.as_wire()));
    }
    if ev.rpc != RpcKind::None {
        line.push_str(&format!(" l7={}", ev.rpc.as_str()));
    }
    if let Some(method) = &ev.method {
        line.push_str(&format!(" method={}", head_field(method)));
    }
    line.push_str(&format!(" host={}", head_field(&ev.host)));
    if let Some(path) = &ev.path {
        line.push_str(&format!(" path={}", trailing_field(path)));
    }
    line.push('\n');
    line
}

#[cfg(test)]
mod tests {
    /// `as_str` and `parse` are a pair, and only one of them is checked by the compiler: `parse`
    /// matches on `&str` with a fallback, so a variant added to `as_str` alone compiles and then
    /// **silently drops the event** on the reader's side of the control wire. That is not a
    /// hypothetical: `resolved` and `dns` were added to `as_str` first, and the resolutions the tap
    /// reported never reached `sbx net logs` until this guard was written.
    #[test]
    fn every_verdict_and_transport_survives_the_control_wire() {
        for v in LogVerdict::ALL {
            v.assert_all_listed();
            assert_eq!(
                LogVerdict::parse(v.as_str()),
                Some(v),
                "the verdict `{}` does not survive the wire",
                v.as_str()
            );
        }
        for p in Proto::ALL {
            p.assert_all_listed();
            // `Other` is the token an absent/unknown transport reads as, so it is the one variant
            // whose round trip is a fixed point rather than a name.
            if p != Proto::Other {
                assert_eq!(
                    Proto::parse(p.as_str()),
                    p,
                    "the transport `{}` does not survive the wire",
                    p.as_str()
                );
            }
        }
        assert_eq!(Proto::parse("-"), Proto::Other);
        assert_eq!(Proto::parse("something else"), Proto::Other);
    }

    use super::*;
    use std::thread;

    #[test]
    fn park_returns_the_answered_verdict() {
        let state = Arc::new(PendingState::new());
        let s = state.clone();
        // Park in a thread; the main thread answers it.
        let handle =
            thread::spawn(move || s.park("api.example.com", 443, "/v1/x", None, 256, |_| {}));
        // Wait for the request to appear, then allow it.
        let seq = wait_for_one(&state);
        assert_eq!(
            state.answer_like(seq, Verdict::Allow),
            Some(("api.example.com".to_string(), 443, 1))
        );
        assert_eq!(handle.join().unwrap(), Verdict::Allow);
        // The queue is drained.
        assert!(state.list().is_empty());
    }

    #[test]
    fn park_returns_deny_when_denied() {
        let state = Arc::new(PendingState::new());
        let s = state.clone();
        let handle = thread::spawn(move || s.park("evil.test", 443, "/", None, 256, |_| {}));
        let seq = wait_for_one(&state);
        assert_eq!(
            state.answer_like(seq, Verdict::Deny),
            Some(("evil.test".to_string(), 443, 1))
        );
        assert_eq!(handle.join().unwrap(), Verdict::Deny);
    }

    #[test]
    fn park_times_out_to_deny() {
        let state = PendingState::new();
        // A tiny timeout with no answer → deny, and the entry is cleaned up.
        let verdict = state.park(
            "slow.test",
            443,
            "/",
            Some(Duration::from_millis(30)),
            256,
            |_| {},
        );
        assert_eq!(verdict, Verdict::Deny);
        assert!(state.list().is_empty(), "a timed-out entry is removed");
    }

    /// A request taken back out of the queue keeps the answer an operator gave it before it left,
    /// by id or by the drain, and is denied when none was given: what a request whose waiting
    /// thread could not be started is decided with.
    #[test]
    fn a_withdrawn_request_keeps_the_answer_it_was_given() {
        let state = PendingState::new();
        let parked = state.enqueue("api.test", 443, "/", 4).unwrap();
        state.answer_like(parked.seq, Verdict::Allow);
        assert_eq!(state.withdraw(parked), Verdict::Allow);
        let parked = state.enqueue("api.test", 443, "/", 4).unwrap();
        state.answer_all(Verdict::Allow);
        assert_eq!(state.withdraw(parked), Verdict::Allow);
        let parked = state.enqueue("api.test", 443, "/", 4).unwrap();
        assert_eq!(state.withdraw(parked), Verdict::Deny);
        assert!(state.list().is_empty());
    }

    #[test]
    fn the_flood_cap_denies_without_enqueuing() {
        let state = Arc::new(PendingState::new());
        // Fill the queue to a cap of 1 with one indefinitely-parked request.
        let s = state.clone();
        let parked = thread::spawn(move || s.park("first.test", 443, "/", None, 1, |_| {}));
        wait_for_one(&state);
        // A second park at cap 1 is denied immediately, never enqueued.
        let verdict = state.park("second.test", 443, "/", None, 1, |_| {});
        assert_eq!(verdict, Verdict::Deny);
        assert_eq!(
            state.list().len(),
            1,
            "the flooding request was not enqueued"
        );
        // Release the first so the thread joins.
        let seq = state.list()[0].seq;
        state.answer_like(seq, Verdict::Allow);
        assert_eq!(parked.join().unwrap(), Verdict::Allow);
    }

    #[test]
    fn answer_an_unknown_seq_is_none() {
        let state = PendingState::new();
        assert_eq!(state.answer_like(999, Verdict::Allow), None);
    }

    #[test]
    fn answer_like_wakes_the_whole_destination_and_leaves_others_parked() {
        let state = Arc::new(PendingState::new());
        // Two identical retries of one URL (same host:port/path) plus a different destination,
        // parked one at a time so the seqs are 1, 2, 3 in this order.
        let a1 = park_next(&state, "dl.test", 443, 0);
        let a2 = park_next(&state, "dl.test", 443, 1);
        let other = park_next(&state, "logs.test", 443, 2);

        // Answering the representative (seq 1) wakes BOTH dl.test retries and reports the count.
        assert_eq!(
            state.answer_like(1, Verdict::Allow),
            Some(("dl.test".to_string(), 443, 2))
        );
        assert_eq!(a1.join().unwrap(), Verdict::Allow);
        assert_eq!(a2.join().unwrap(), Verdict::Allow);

        // The different destination stays parked — this is destination-grained, not the `--all` drain.
        let still = state.list();
        assert_eq!(
            still.len(),
            1,
            "the other destination is untouched: {still:?}"
        );
        assert_eq!(still[0].host, "logs.test");

        state.answer_like(still[0].seq, Verdict::Deny);
        assert_eq!(other.join().unwrap(), Verdict::Deny);
    }

    #[test]
    fn manual_rules_store_remembered_and_proactive_rules_deduped() {
        // The overlay is a rule store; the proxy folds `snapshot()` into its effective policy, so the
        // *decision* semantics (deny-wins, allow-opens, SSRF breadth) are proven there. Here we pin
        // only the store contract: an ask answer records an exact host:port, a `--session` load
        // records an arbitrary rule, each in the right list, deduped, and `is_empty` tracks it.
        let m = ManualRules::new();
        assert!(m.is_empty());

        // An ask answer records the exact host:port on the right list.
        m.remember(Verdict::Allow, "api.test", 8080).unwrap();
        assert!(!m.is_empty());
        assert_eq!(
            m.snapshot().0,
            vec![crate::allowlist::host_port_rule("api.test", 8080)]
        );

        // A proactive `--session` load records an arbitrary (wildcard) rule.
        let wildcard = crate::allowlist::classify("*.internal.test").unwrap();
        m.remember_rule(Verdict::Allow, wildcard.clone()).unwrap();
        let (allow, deny) = m.snapshot();
        assert!(allow.contains(&wildcard) && deny.is_empty());

        // A deny goes on the deny list.
        m.remember_rule(
            Verdict::Deny,
            crate::allowlist::classify("bad.internal.test").unwrap(),
        )
        .unwrap();
        assert_eq!(m.snapshot().1.len(), 1);

        // Dedup: re-loading the same rule does not stack.
        m.remember(Verdict::Allow, "api.test", 8080).unwrap();
        m.remember_rule(Verdict::Allow, wildcard).unwrap();
        assert_eq!(
            m.snapshot().0.len(),
            2,
            "a re-loaded rule is not duplicated"
        );
    }

    /// A `--session` answer puts its rule in force in the proxy before it frees the request, so the
    /// request's retry is decided by the rule rather than parked again — one answer, one decision,
    /// for a tool that retries at once. Both the answer by id and the drain.
    ///
    /// The proxy is held from installing the rule while the answer waits on it, so the request
    /// still being parked at that point is checked exactly, not raced: its rule is in the
    /// supervisor's copy, and the answer cannot have gone past the confirmation.
    #[test]
    fn a_session_answer_is_in_force_before_the_request_it_frees() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let (link, supervisor) = crate::sandbox::proxy::link::pair();
        manual.attach(supervisor).unwrap();
        let link = Arc::new(link);
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let flows = Arc::new(FlowRegistry::new());
        for (port, target) in [(8080u16, None), (8081, Some("*"))] {
            let (s, l) = (state.clone(), link.clone());
            let parked = thread::spawn(move || {
                let verdict = s.park("api.test", port, "/", None, 256, |_| {});
                (verdict, l.overlay().allow.clone())
            });
            let seq = wait_for_one(&state);
            let target = target.map_or_else(|| seq.to_string(), str::to_string);
            let stall = link.stall_installs();
            let answer = {
                let (state, manual) = (state.clone(), manual.clone());
                let (log, flows) = (log.clone(), flows.clone());
                thread::spawn(move || {
                    let cmd = format!("ALLOW {target} session");
                    dispatch(&cmd, &state, &manual, &log, &flows, None)
                })
            };
            let rule = crate::allowlist::host_port_rule("api.test", port);
            let deadline = Instant::now() + Duration::from_secs(30);
            while !manual.snapshot().0.contains(&rule) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
            let still_parked = state.list().len();
            drop(stall);
            let reply = answer.join().unwrap();
            state.answer_all(Verdict::Deny);
            assert_eq!(
                still_parked, 1,
                "the request was freed before its rule was confirmed"
            );
            assert!(
                reply.ends_with("ok\n") || reply.starts_with("ok "),
                "{reply}"
            );
            let (verdict, in_force) = parked.join().unwrap();
            assert_eq!(verdict, Verdict::Allow);
            assert!(
                in_force.contains(&crate::allowlist::host_port_rule("api.test", port)),
                "the freed request found its rule already in force: {in_force:?}"
            );
        }
    }

    /// A `--session` answer waiting for the proxy to confirm its rule does not hold the queue: a
    /// request parking meanwhile is queued at once, and the answer is confirmed once the proxy
    /// installs the rule. A request that parked meanwhile for the destination being remembered is
    /// freed with the others, one for another destination stays parked. Both the answer by id and
    /// the drain.
    #[test]
    fn a_request_parks_while_a_session_answer_waits_for_its_confirmation() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let (link, supervisor) = crate::sandbox::proxy::link::pair();
        manual.attach(supervisor).unwrap();
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let flows = Arc::new(FlowRegistry::new());
        let park = |port: u16| {
            let s = state.clone();
            thread::spawn(move || s.park("api.test", port, "/", None, 256, |_| {}))
        };
        for (port, other, target, freed) in [
            (8080u16, 9080u16, None, "ok host=api.test count=2\n"),
            (
                8081,
                9081,
                Some("*"),
                "answered host=api.test\nanswered host=api.test\nok\n",
            ),
        ] {
            let first = park(port);
            let seq = wait_for_one(&state);
            let stall = link.stall_installs();
            let target = target.map_or_else(|| seq.to_string(), str::to_string);
            let answer = {
                let (state, manual) = (state.clone(), manual.clone());
                let (log, flows) = (log.clone(), flows.clone());
                thread::spawn(move || {
                    let cmd = format!("ALLOW {target} session");
                    dispatch(&cmd, &state, &manual, &log, &flows, None)
                })
            };
            // The answer is waiting for its confirmation once its rule is in the supervisor's copy.
            let rule = crate::allowlist::host_port_rule("api.test", port);
            let deadline = Instant::now() + Duration::from_secs(30);
            while !manual.snapshot().0.contains(&rule) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
            let (same, elsewhere) = (park(port), park(other));
            // Nothing here is asserted on a duration: a queue held across the confirmation takes
            // these two only once the answer has given up, and the answer then reports its rule
            // unconfirmed.
            while state.list().len() < 3 && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
            drop(stall);
            let reply = answer.join().unwrap();
            let left: Vec<u16> = state.list().iter().map(|row| row.port).collect();
            state.answer_all(Verdict::Deny);
            let verdicts = [first, same, elsewhere].map(|h| h.join().unwrap());
            assert_eq!(reply, freed);
            assert_eq!(left, [other], "only the other destination is still parked");
            assert_eq!(verdicts, [Verdict::Allow, Verdict::Allow, Verdict::Deny]);
        }
    }

    /// The same, with the requests parked the way the proxy parks them: up its link, whose reader
    /// on the supervisor's side is also the one that takes in the confirmation the answer waits
    /// for. A request arriving meanwhile is queued at once, not once the answer has given up: the
    /// reader queues a park without waiting on it, and the queue is not held across the
    /// confirmation.
    #[test]
    fn a_request_parked_through_the_link_is_queued_while_a_session_answer_waits() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let (link, supervisor) = crate::sandbox::proxy::link::joined(
            crate::sandbox::proxy::link::default_judge(),
            Some(crate::sandbox::proxy::link::Parks {
                pending: state.clone(),
                cap: ASK_PENDING_CAP,
                timeout: None,
                notices: false,
            }),
            None,
        );
        manual.attach(supervisor).unwrap();
        let link = Arc::new(link);
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let flows = Arc::new(FlowRegistry::new());
        let park = |host: &'static str| {
            let link = link.clone();
            thread::spawn(move || link.park(host, 443, "/"))
        };
        let first = park("api.test");
        let seq = wait_for_one(&state);
        let stall = link.stall_installs();
        let answer = {
            let (state, manual) = (state.clone(), manual.clone());
            let (log, flows) = (log.clone(), flows.clone());
            thread::spawn(move || {
                let cmd = format!("ALLOW {seq} session");
                dispatch(&cmd, &state, &manual, &log, &flows, None)
            })
        };
        let rule = crate::allowlist::host_port_rule("api.test", 443);
        let deadline = Instant::now() + Duration::from_secs(30);
        while !manual.snapshot().0.contains(&rule) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        let elsewhere = park("other.test");
        // Nothing here is asserted on a duration: held behind the confirmation, the request is
        // listed only once the answer has given up.
        let listed = || state.list().iter().any(|row| row.host == "other.test");
        while !listed() && !answer.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        let queued_while_waiting = listed() && !answer.is_finished();
        drop(stall);
        let reply = answer.join().unwrap();
        // Every request is let go however the answer went, so a defect fails the test rather than
        // hanging it.
        while !(first.is_finished() && elsewhere.is_finished()) && Instant::now() < deadline {
            state.answer_all(Verdict::Deny);
            thread::sleep(Duration::from_millis(1));
        }
        let verdicts = [first, elsewhere].map(|h| h.join().unwrap());
        assert!(
            queued_while_waiting,
            "a request parked through the link is queued while the answer waits"
        );
        assert_eq!(reply, "ok host=api.test count=1\n");
        assert_eq!(verdicts, [Verdict::Allow, Verdict::Deny]);
    }

    /// A `--session` answer whose request is gone while its rule is being confirmed (here answered
    /// by another command; a timeout takes the same path) keeps the rule, and says so: `ok` with a
    /// count of 0, not the `err not-found` of a request that was never parked, which would tell the
    /// operator nothing was done.
    #[test]
    fn a_session_answer_whose_request_is_gone_meanwhile_keeps_its_rule() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let (link, supervisor) = crate::sandbox::proxy::link::pair();
        manual.attach(supervisor).unwrap();
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let flows = Arc::new(FlowRegistry::new());
        let s = state.clone();
        let parked = thread::spawn(move || s.park("api.test", 8080, "/", None, 256, |_| {}));
        let seq = wait_for_one(&state);
        let stall = link.stall_installs();
        let answer = {
            let (state, manual) = (state.clone(), manual.clone());
            let (log, flows) = (log.clone(), flows.clone());
            thread::spawn(move || {
                let cmd = format!("ALLOW {seq} session");
                dispatch(&cmd, &state, &manual, &log, &flows, None)
            })
        };
        let rule = crate::allowlist::host_port_rule("api.test", 8080);
        let deadline = Instant::now() + Duration::from_secs(30);
        while !manual.snapshot().0.contains(&rule) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        let other = dispatch(&format!("DENY {seq}"), &state, &manual, &log, &flows, None);
        drop(stall);
        let reply = answer.join().unwrap();
        state.answer_all(Verdict::Deny);
        assert_eq!(parked.join().unwrap(), Verdict::Deny);
        assert_eq!(other, "ok host=api.test count=1\n");
        assert_eq!(reply, "ok host=api.test count=0\n");
        assert!(
            link.overlay().allow.contains(&rule),
            "the rule stays in force"
        );
    }

    #[test]
    fn dispatch_remembers_only_on_the_session_token() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = LogRing::new(LOG_RING_CAP);
        let flows = FlowRegistry::new();

        // A bare ALLOW answers but does not remember.
        let s = state.clone();
        let parked = thread::spawn(move || s.park("api.test", 8080, "/", None, 256, |_| {}));
        let seq = wait_for_one(&state);
        assert_eq!(
            dispatch(&format!("ALLOW {seq}"), &state, &manual, &log, &flows, None),
            "ok host=api.test count=1\n"
        );
        assert_eq!(parked.join().unwrap(), Verdict::Allow);
        assert!(
            manual.snapshot().0.is_empty(),
            "a bare ALLOW must not remember"
        );

        // `ALLOW <seq> session` answers AND remembers the exact host:port.
        let s = state.clone();
        let parked = thread::spawn(move || s.park("api.test", 8080, "/", None, 256, |_| {}));
        let seq = wait_for_one(&state);
        let _ = dispatch(
            &format!("ALLOW {seq} session"),
            &state,
            &manual,
            &log,
            &flows,
            None,
        );
        parked.join().unwrap();
        assert_eq!(manual.snapshot().0.len(), 1, "`… session` must remember");
        // And `RULES` reports the remembered rule with its exact port.
        assert!(
            dispatch("RULES", &state, &manual, &log, &flows, None)
                .contains("manual allow https://api.test:8080"),
            "RULES must list the remembered host:port"
        );
    }

    /// The tap's bypass report becomes a row in the record the reader actually consults.
    ///
    /// This refusal is the tap's alone: the connection is closed before the proxy is dialed, so no
    /// other part of the system can write it. Without this verb the one thing transparent capture
    /// newly makes visible — a client that reached an address without ever asking for a name —
    /// would appear only in the session's stderr, which is not where a refusal is looked for.
    #[test]
    fn report_bypassed_records_the_address_no_name_was_handed_out_for() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = LogRing::new(LOG_RING_CAP);
        let flows = FlowRegistry::new();

        assert_eq!(report("BYPASSED 198.18.0.7 443", &log, None), "ok\n");

        let out = dispatch("LOG", &state, &manual, &log, &flows, None);
        let line = out
            .lines()
            .find(|l| l.starts_with("event "))
            .unwrap_or_else(|| panic!("the report left no event: {out}"));
        let fields: BTreeMap<&str, &str> = line
            .split_whitespace()
            .skip(1)
            .filter_map(|t| t.split_once('='))
            .collect();
        assert_eq!(fields.get("host"), Some(&"198.18.0.7"), "{line}");
        assert_eq!(fields.get("port"), Some(&"443"), "{line}");
        assert_eq!(fields.get("verdict"), Some(&"blocked"), "{line}");
        // Not the proxy's `ip-literal`: that refusal is lifted by a rule naming the address, and
        // this one cannot be, so the reader is owed a different word for a different remedy.
        assert_eq!(fields.get("reason"), Some(&"dns-bypassed"), "{line}");
        assert_eq!(fields.get("proto"), Some(&"tcp"), "{line}");
    }

    /// The live log this `RESOLVED` lands in is bounded, so a cage that asks for enough names
    /// carries its own earlier entries off the end of it. The durable count is what survives that,
    /// which is why the verb reaches the stats register at all — and why it must keep working when
    /// there is no register to reach (stats are a configurable field, and a launch without one is
    /// not a launch that stops answering the tap).
    #[test]
    fn a_reported_resolution_reaches_the_durable_count_and_is_a_no_op_without_one() {
        use crate::sandbox::egress_stats::EgressStats;
        use crate::testutil::TmpDir;
        let log = LogRing::new(LOG_RING_CAP);

        // No register: the verb still answers, and nothing panics on the way.
        assert_eq!(report("RESOLVED unregistered.test", &log, None), "ok\n");

        let dir = TmpDir::new();
        let path = dir.path().join("stats-1-11");
        let stats = EgressStats::new(path.clone(), "/home/u/proj".into(), None);
        for host in ["a.test", "b.test"] {
            assert_eq!(
                report(&format!("RESOLVED {host}"), &log, Some(&stats)),
                "ok\n"
            );
        }
        stats.flush_final();

        let body = std::fs::read_to_string(&path).expect("the register was written");
        assert!(
            body.contains("resolutions=2"),
            "both resolutions counted: {body:?}"
        );
        // Counted, never listed: naming them is the live log's job, for as long as it holds them.
        assert!(
            !body.contains("a.test"),
            "no row for a resolved name: {body:?}"
        );
    }

    /// Held to a type, not merely sanitised. The two tap verbs are the only ones whose argument
    /// comes from the cage's own traffic, and this one names an address — so anything that is not
    /// one is a bad request and leaves no row, rather than becoming a record of something the tap
    /// never saw.
    #[test]
    fn report_bypassed_refuses_anything_that_is_not_an_address() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = LogRing::new(LOG_RING_CAP);
        let flows = FlowRegistry::new();

        for bad in [
            "BYPASSED",
            "BYPASSED 198.18.0.7",
            "BYPASSED example.com 443",
            "BYPASSED 198.18.0.7 https",
            "BYPASSED 198.18.0.7 70000",
            "BYPASSED 198.18.0.7.9 443",
            // IPv6 has no place here: the tap hands out v4 fake addresses and reads a v4 original
            // destination, so a v6 report is not something it could have produced.
            "BYPASSED ::1 443",
        ] {
            assert_eq!(
                report(bad, &log, None),
                "err bad-request\n",
                "`{bad}` must be refused"
            );
        }
        assert!(
            !dispatch("LOG", &state, &manual, &log, &flows, None).contains("event "),
            "a refused report must leave no row"
        );
    }

    /// The owner's verbs, each in a form the owner's socket would carry out.
    const OWNER_VERBS: [&str; 11] = [
        "LIST",
        "ALLOW 1",
        "ALLOW 1 session",
        "DENY 1",
        "ALLOW *",
        "DENY *",
        "REMEMBER ALLOW https://api.test",
        "REMEMBER DENY https://api.test",
        "REMEMBER MUTE https://api.test",
        "RULES",
        "LOG",
    ];

    /// The tap's socket answers its two reports and nothing else. The tap parses what the cage
    /// writes, so a verb that answers a parked request or remembers a rule must not be reachable
    /// from it, however the command is spelled.
    #[test]
    fn the_report_socket_answers_no_owner_verb() {
        let log = LogRing::new(LOG_RING_CAP);
        for verb in OWNER_VERBS.iter().chain(&["FLOWS", ""]) {
            assert_eq!(
                report(verb, &log, None),
                "err bad-request\n",
                "`{verb}` must not be answered on the tap's socket"
            );
        }
        assert!(
            log.snapshot(None, None, true).events.is_empty(),
            "a refusal leaves no row"
        );
    }

    /// The report socket closes a line that does not open with the launch's token before
    /// [`report`] reads it: no answer, so nothing reached the verb that writes the record and the
    /// counters, and no row. The line that opens with it is answered and recorded.
    #[test]
    fn the_report_socket_takes_a_report_only_with_the_launchs_token() {
        use std::io::{Read, Write};
        let dir = crate::testutil::TmpDir::new();
        let path = dir.join("report.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        let token = crate::sandbox::nettap::ReportToken::draw().expect("a token");
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let (token, log, stop) = (token.clone(), log.clone(), stop.clone());
            thread::spawn(move || serve_reports(listener, token, log, None, stop));
        }
        let ask = |line: &str| {
            let mut sock = UnixStream::connect(&path).expect("connect");
            sock.write_all(format!("{line}\n").as_bytes())
                .expect("write");
            let mut reply = String::new();
            sock.read_to_string(&mut reply).expect("read");
            reply
        };
        let other = crate::sandbox::nettap::ReportToken::draw().expect("another token");
        for forged in [
            "RESOLVED forged.test".to_string(),
            "BYPASSED 198.18.0.7 443".to_string(),
            format!("{} RESOLVED forged.test", other.as_str()),
            token.as_str().to_string(),
        ] {
            assert_eq!(ask(&forged), "", "`{forged}` was answered");
        }
        assert!(
            log.snapshot(None, None, true).events.is_empty(),
            "a report without the token left a row"
        );
        assert_eq!(
            ask(&format!("{} RESOLVED real.test", token.as_str())),
            "ok\n"
        );
        assert!(
            log.snapshot(None, None, true)
                .events
                .iter()
                .any(|e| e.host == "real.test"),
            "the tap's report reaches the record"
        );
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = UnixStream::connect(&path);
    }

    /// And the owner's socket takes no report: each socket has one peer and that peer's verbs.
    #[test]
    fn the_owner_socket_takes_no_tap_report() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = LogRing::new(LOG_RING_CAP);
        let flows = FlowRegistry::new();
        for verb in ["RESOLVED api.test", "BYPASSED 198.18.0.7 443"] {
            assert_eq!(
                dispatch(verb, &state, &manual, &log, &flows, None),
                "err bad-request\n",
                "`{verb}` belongs to the tap's socket"
            );
        }
        assert!(
            !dispatch("LOG", &state, &manual, &log, &flows, None).contains("event "),
            "a refused report must leave no row"
        );
    }

    #[test]
    fn dispatch_remember_loads_a_rule_into_the_overlay() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = LogRing::new(LOG_RING_CAP);
        let flows = FlowRegistry::new();

        // `REMEMBER ALLOW <rule>` loads an arbitrary (here wildcard) rule into the overlay and
        // `RULES` reports it — the proactive `--session` path. It is accepted in any posture (the
        // proxy folds the overlay into its effective policy for every filtering posture).
        assert_eq!(
            dispatch(
                "REMEMBER ALLOW *.foo.test",
                &state,
                &manual,
                &log,
                &flows,
                None
            ),
            "ok\n"
        );
        assert!(
            dispatch("RULES", &state, &manual, &log, &flows, None)
                .contains("manual allow https://*.foo.test"),
            "REMEMBER must load the rule"
        );

        // A malformed rule (a `*` catch-all) and a missing kind/rule are `err bad-request`.
        assert_eq!(
            dispatch("REMEMBER ALLOW *", &state, &manual, &log, &flows, None),
            "err bad-request\n"
        );
        assert_eq!(
            dispatch("REMEMBER ALLOW", &state, &manual, &log, &flows, None),
            "err bad-request\n"
        );

        // `REMEMBER MUTE <rule>` loads into the dedicated mute overlay (a log filter, not a verdict),
        // so it lands in `mute_snapshot`, never the allow/deny verdict lists.
        assert_eq!(
            dispatch(
                "REMEMBER MUTE play.googleapis.com",
                &state,
                &manual,
                &log,
                &flows,
                None
            ),
            "ok\n"
        );
        let (allow, deny) = manual.snapshot();
        assert!(
            allow
                .iter()
                .all(|r| r.to_string() != "https://play.googleapis.com")
                && deny.is_empty(),
            "a MUTE must not enter the verdict lists"
        );
        assert_eq!(
            manual.mute_snapshot().len(),
            1,
            "a MUTE lands in the mute overlay"
        );
        assert!(
            !manual.is_empty(),
            "a loaded mute makes the overlay non-empty"
        );
        // …and `RULES` reports it as a `manual mute` line, so `sbx net rules --source session` lists
        // a live mute (distinct from the allow/deny lines).
        assert!(
            dispatch("RULES", &state, &manual, &log, &flows, None)
                .contains("manual mute https://play.googleapis.com"),
            "RULES must list a live mute"
        );
    }

    #[test]
    fn flow_registry_opens_counts_and_closes() {
        let reg = FlowRegistry::new();
        assert!(reg.snapshot().is_empty(), "a fresh registry has no flows");

        reg.open(1, "api.test", 443, Proto::Https);
        reg.open(2, "db.test", 5432, Proto::Tcp);
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 2, "two open tunnels are visible");
        // Oldest-open first (ascending id).
        assert_eq!(snap[0].host, "api.test");
        assert_eq!(snap[0].port, 443);
        assert_eq!(snap[0].proto, Proto::Https);
        assert_eq!((snap[0].up, snap[0].down), (0, 0), "counters start at zero");
        assert_eq!(snap[1].host, "db.test");
        assert_eq!(snap[1].proto, Proto::Tcp);

        // Totals are absolute: a repeated or late report sets the same figure again.
        reg.count(1, 1024, 2048);
        reg.count(1, 1024, 2048);
        let snap = reg.snapshot();
        assert_eq!((snap[0].up, snap[0].down), (1024, 2048));

        reg.close(1);
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 1, "a closed tunnel drops off the view");
        assert_eq!(snap[0].host, "db.test");
        reg.close(2);
        assert!(
            reg.snapshot().is_empty(),
            "no flow remains once every tunnel closed"
        );
    }

    /// What reaches the registry is the proxy's account, so it is bounded on arrival: an opening
    /// under a number already listed does not reset that flow, a count or a closing for a number
    /// never opened changes nothing, and a count after a closing does not bring the flow back.
    #[test]
    fn flow_registry_ignores_what_names_no_open_flow() {
        let reg = FlowRegistry::new();
        reg.open(1, "api.test", 443, Proto::Https);
        reg.count(1, 10, 20);
        reg.open(1, "other.test", 80, Proto::Http);
        reg.count(9, 1, 1);
        reg.close(9);
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(
            (snap[0].host.as_str(), snap[0].up, snap[0].down),
            ("api.test", 10, 20)
        );
        reg.close(1);
        reg.count(1, 30, 40);
        assert!(reg.snapshot().is_empty(), "a closed flow stays closed");
    }

    /// A panic in one unrelated handler must not take the whole control plane with it.
    ///
    /// Every lock here guards something a reader depends on — the decision ring `sbx net log` reads,
    /// the queue a parked request is answered through, the live `--session` overlay every request is
    /// decided against, the registry `sbx net live` lists — and `std`'s default is to answer `Err`
    /// from every later take once a holder has panicked. Taking that as a panic of its own is how one
    /// fault in a single proxy connection becomes a session whose log stops recording, whose parked
    /// requests can no longer be answered and whose closed tunnels never leave the live view. See
    /// [`crate::sandbox::locks`] for why these are the recovering class and what makes it sound.
    ///
    /// The plane's fifth lock-holder, the traffic capture's ring, is the same class and is covered
    /// beside its own definition in `control/capture.rs`, whose fields are private to that module.
    #[test]
    fn a_poisoned_control_plane_lock_keeps_serving_rather_than_panicking_again() {
        // Poison a lock the only way it can be poisoned: panic on another thread while a guard on it
        // is still held, so the unwind marks it. The assertion is the fixture's own — a body that
        // released the guard before panicking would poison nothing and prove nothing.
        fn poisoning(hold_and_panic: impl FnOnce() + Send + 'static) {
            let panicked = std::thread::spawn(hold_and_panic).join();
            assert!(
                panicked.is_err(),
                "the fixture must actually poison the lock"
            );
        }

        // The event ring: the row pushed after the poisoning is still recorded, and still readable.
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        push_event(&log, "before.test", LogVerdict::Allow, "allowed");
        let poisoner = Arc::clone(&log);
        poisoning(move || {
            let _held = locked(&poisoner.inner);
            panic!("an unrelated holder gives up mid-flight");
        });
        push_event(&log, "after.test", LogVerdict::Deny, "denied-default");
        let hosts: Vec<String> = log
            .snapshot(None, None, false)
            .events
            .iter()
            .map(|e| e.host.clone())
            .collect();
        assert_eq!(hosts, vec!["before.test", "after.test"]);

        // The pending queue: still listable and still answerable, which is what a parked proxy
        // thread is waiting on.
        let pending = Arc::new(PendingState::new());
        let poisoner = Arc::clone(&pending);
        poisoning(move || {
            let _held = locked(&poisoner.inner);
            panic!("an unrelated holder gives up mid-flight");
        });
        assert!(pending.list().is_empty());
        assert!(pending.answer_all(Verdict::Deny).is_empty());

        // The live overlay: a rule loaded after the poisoning is still folded into the policy.
        let manual = Arc::new(ManualRules::new());
        let poisoner = Arc::clone(&manual);
        poisoning(move || {
            let _held = write_locked(&poisoner.inner);
            panic!("an unrelated holder gives up mid-flight");
        });
        manual.remember(Verdict::Allow, "api.test", 443).unwrap();
        assert!(!manual.is_empty());
        assert_eq!(manual.snapshot().0.len(), 1);

        // The flow registry: a tunnel opened after the poisoning appears, and closing it removes it
        // — the half that skipped the removal instead of recovering, which would have left a closed
        // tunnel listed for the rest of the session.
        let flows = Arc::new(FlowRegistry::new());
        let poisoner = Arc::clone(&flows);
        poisoning(move || {
            let _held = locked(&poisoner.inner);
            panic!("an unrelated holder gives up mid-flight");
        });
        flows.open(1, "api.test", 8443, Proto::Https);
        assert_eq!(flows.snapshot().len(), 1);
        flows.close(1);
        assert!(
            flows.snapshot().is_empty(),
            "a closed tunnel must leave the live view even after a poisoning"
        );
    }

    #[test]
    fn flows_verb_lists_open_tunnels_and_round_trips() {
        // `FLOWS` returns one `flow …` line per open tunnel then `ok`, and the client parser reads each
        // back — the server format and the client parser agree (not just by inspection).
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = LogRing::new(LOG_RING_CAP);
        let flows = Arc::new(FlowRegistry::new());

        flows.open(1, "api.test", 8443, Proto::Https);
        flows.count(1, 100, 200);

        let resp = dispatch("FLOWS", &state, &manual, &log, &flows, None);
        assert!(resp.ends_with("ok\n"), "the reply ends with ok: {resp:?}");
        let parsed: Vec<FlowSnapshot> = resp.lines().filter_map(parse_flow_line).collect();
        assert_eq!(parsed.len(), 1, "one open flow is listed");
        let f = &parsed[0];
        assert_eq!(f.host, "api.test");
        assert_eq!(f.port, 8443);
        assert_eq!(f.proto, Proto::Https);
        assert_eq!((f.up, f.down), (100, 200));

        // An empty registry lists no flow, just `ok`.
        flows.close(1);
        assert_eq!(
            dispatch("FLOWS", &state, &manual, &log, &flows, None),
            "ok\n"
        );
    }

    /// A command that fills the bound without a terminator was truncated, and a truncated command
    /// is a different command.
    ///
    /// `REMEMBER ALLOW <rule>` cut short is another rule, and this form loads straight into the
    /// live overlay the proxy folds into its policy. The reply half of the same exchange already
    /// refuses a line that filled its bound with no newline, for the mirror-image reason: a partial
    /// host that `--save` would persist. The command half read it as complete and dispatched it.
    #[test]
    fn a_command_that_fills_the_bound_without_a_newline_is_refused() {
        use crate::testutil::TmpDir;
        use std::io::{Read, Write};
        let data = TmpDir::new();
        std::fs::create_dir_all(control_dir(data.path())).unwrap();
        let pid = 24681u32;
        let sock = control_socket(data.path(), pid);
        let listener = UnixListener::bind(&sock).unwrap();
        let manual = Arc::new(ManualRules::new());
        let served_manual = manual.clone();
        thread::spawn(move || {
            let _ = serve(
                listener,
                Planes {
                    state: Arc::new(PendingState::new()),
                    manual: served_manual,
                    log: Arc::new(LogRing::new(LOG_RING_CAP)),
                    flows: Arc::new(FlowRegistry::new()),
                    capture: None,
                },
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
            );
        });

        let mut cmd = b"REMEMBER ALLOW allowed.test/".to_vec();
        cmd.resize(CMD_MAX as usize, b'a');
        let stream = UnixStream::connect(&sock).unwrap();
        (&stream).write_all(&cmd).unwrap();
        (&stream).flush().unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = String::new();
        (&stream).read_to_string(&mut reply).unwrap();

        assert_eq!(reply, "err bad-request\n");
        let (allow, deny) = manual.snapshot();
        assert!(
            allow.is_empty() && deny.is_empty(),
            "and the truncation never reached the overlay: {allow:?} {deny:?}"
        );
    }

    #[test]
    fn inject_rule_round_trips_over_the_control_socket() {
        // The proactive-`--session` integration seam: `inject_rule` (client) against a real `serve`
        // (server) over a bound socket, so the `REMEMBER` wire format is exercised end to end.
        use crate::testutil::TmpDir;
        let data = TmpDir::new();
        std::fs::create_dir_all(control_dir(data.path())).unwrap();
        let pid = 24680u32;
        let sock = control_socket(data.path(), pid);
        let listener = UnixListener::bind(&sock).unwrap();
        let pending = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let served_manual = manual.clone();
        let flows = Arc::new(FlowRegistry::new());
        thread::spawn(move || {
            let _ = serve(
                listener,
                Planes {
                    state: pending,
                    manual: served_manual,
                    log,
                    flows,
                    capture: None,
                },
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
            );
        });

        // A loaded rule reports `Loaded` and lands in the overlay the proxy folds into its policy.
        assert!(matches!(
            inject_rule(data.path(), pid, Verdict::Allow, "*.svc.test").unwrap(),
            InjectOutcome::Loaded
        ));
        let (allow, _) = manual.snapshot();
        assert_eq!(
            allow,
            vec![crate::allowlist::classify("*.svc.test").unwrap()]
        );
    }

    /// A `--session` rule the proxy did not confirm is reported as such by every verb that loads
    /// one, over the real socket, and an answer that was to remember its destination answers
    /// nothing: the request stays parked, for an answer that can be confirmed.
    #[test]
    fn a_session_rule_the_proxy_did_not_confirm_is_reported_and_answers_nothing() {
        use crate::testutil::TmpDir;
        let data = TmpDir::new();
        std::fs::create_dir_all(control_dir(data.path())).unwrap();
        let pid = 24681u32;
        let listener = UnixListener::bind(control_socket(data.path(), pid)).unwrap();
        let pending = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        // A proxy that is gone: nothing will confirm what is pushed to it. Attaching pushes
        // nothing, since no rule is held yet.
        let (link, supervisor) = crate::sandbox::proxy::link::pair();
        drop(link);
        manual.attach(supervisor).unwrap();
        {
            let (pending, manual) = (pending.clone(), manual.clone());
            thread::spawn(move || {
                let _ = serve(
                    listener,
                    Planes {
                        state: pending,
                        manual,
                        log: Arc::new(LogRing::new(LOG_RING_CAP)),
                        flows: Arc::new(FlowRegistry::new()),
                        capture: None,
                    },
                    Arc::new(std::sync::atomic::AtomicBool::new(false)),
                );
            });
        }
        assert!(matches!(
            inject_rule(data.path(), pid, Verdict::Deny, "evil.test").unwrap(),
            InjectOutcome::Unconfirmed
        ));
        assert!(matches!(
            inject_mute(data.path(), pid, "noise.test").unwrap(),
            InjectOutcome::Unconfirmed
        ));

        let s = pending.clone();
        let parked = thread::spawn(move || s.park("api.test", 443, "/x", None, 256, |_| {}));
        let seq = wait_for_one(&pending);
        assert!(matches!(
            answer_request(data.path(), pid, seq, None, Verdict::Allow, true).unwrap(),
            AnswerOutcome::Unconfirmed
        ));
        assert!(matches!(
            drain_session(data.path(), pid, Verdict::Allow, true).unwrap(),
            DrainOutcome::Unconfirmed
        ));
        assert_eq!(pending.list().len(), 1, "nothing was answered");
        // Without `session` there is nothing to confirm, and the answer goes through.
        assert!(matches!(
            answer_request(data.path(), pid, seq, None, Verdict::Allow, false).unwrap(),
            AnswerOutcome::Answered { .. }
        ));
        assert_eq!(parked.join().unwrap(), Verdict::Allow);
    }

    /// A rule the proxy did not confirm is kept, and reaches the next proxy attached: an unconfirmed
    /// push loses nothing.
    #[test]
    fn a_rule_left_unconfirmed_reaches_the_next_proxy_attached() {
        let manual = ManualRules::new();
        let (gone, supervisor) = crate::sandbox::proxy::link::pair();
        drop(gone);
        manual.attach(supervisor).unwrap();
        let rule = crate::allowlist::classify("evil.test").unwrap();
        assert!(manual.remember_rule(Verdict::Deny, rule.clone()).is_err());
        assert_eq!(manual.snapshot().1, vec![rule.clone()], "kept all the same");

        let (link, supervisor) = crate::sandbox::proxy::link::pair();
        manual.attach(supervisor).unwrap();
        assert_eq!(link.overlay().deny, vec![rule]);
    }

    #[test]
    fn the_control_socket_round_trips_answer_and_rules() {
        // The integration seam: drive the client functions (`answer_request`, `query_manual`)
        // against a real `serve` over a bound socket, so the server's wire format and the client's
        // parser are exercised *together* — not just agreeing by inspection.
        use crate::testutil::TmpDir;
        let data = TmpDir::new();
        std::fs::create_dir_all(control_dir(data.path())).unwrap();
        let pid = 12345u32; // a stand-in session pid; the socket path is keyed by it
        let socket = control_socket(data.path(), pid);

        let pending = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let flows = Arc::new(FlowRegistry::new());
        let listener = UnixListener::bind(&socket).unwrap();
        {
            let pending = pending.clone();
            let manual = manual.clone();
            let log = log.clone();
            let flows = flows.clone();
            thread::spawn(move || {
                let _ = serve(
                    listener,
                    Planes {
                        state: pending,
                        manual,
                        log,
                        flows,
                        capture: None,
                    },
                    Arc::new(std::sync::atomic::AtomicBool::new(false)),
                );
            });
        }

        // Park one request (a non-standard port — the granularity that must survive the round-trip).
        let p = pending.clone();
        let parked = thread::spawn(move || p.park("api.test", 8080, "/x", None, 256, |_| {}));
        let seq = wait_for_one(&pending);

        // Answer it ALLOW with `--session` (remember) over the real socket.
        match answer_request(data.path(), pid, seq, incarnation(), Verdict::Allow, true).unwrap() {
            AnswerOutcome::Answered { host, count } => {
                assert_eq!(host, "api.test");
                assert_eq!(count, 1);
            }
            AnswerOutcome::NotFound | AnswerOutcome::Unconfirmed => {
                panic!("the live request must be answered")
            }
        }
        assert_eq!(parked.join().unwrap(), Verdict::Allow);

        // The remembered rule round-trips back through RULES with its exact host:port.
        let rules = query_manual(data.path(), pid).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].kind, ManualKind::Allow);
        assert_eq!(rules[0].rule, "https://api.test:8080");

        // The consumed seq is now gone — a second answer is NotFound (not a phantom success).
        match answer_request(data.path(), pid, seq, incarnation(), Verdict::Allow, false).unwrap() {
            AnswerOutcome::NotFound => {}
            AnswerOutcome::Answered { .. } | AnswerOutcome::Unconfirmed => {
                panic!("an already-answered seq must be NotFound")
            }
        }
    }

    /// An id from another incarnation of this pid is refused over the real socket, and what it
    /// named stays parked.
    ///
    /// The whole chain rather than the dispatch alone: the tag is put on by [`format_id`], read
    /// back by [`parse_id`], carried by [`answer_request`] and decided by the server. A link that
    /// dropped it — an `Option` flattened on the way through — would leave every other test here
    /// green, because each of them passes the tag this session actually has.
    #[test]
    fn an_id_from_another_incarnation_does_not_answer_this_session() {
        use crate::testutil::TmpDir;
        let data = TmpDir::new();
        std::fs::create_dir_all(control_dir(data.path())).unwrap();
        // A stand-in session pid, as in the round-trip test above: the socket path is keyed by it,
        // and what this test is about is the tag the id carries beside it.
        let pid = 12345u32;
        let socket = control_socket(data.path(), pid);

        let pending = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let flows = Arc::new(FlowRegistry::new());
        let listener = UnixListener::bind(&socket).unwrap();
        {
            let pending = pending.clone();
            let manual = manual.clone();
            let log = log.clone();
            let flows = flows.clone();
            thread::spawn(move || {
                let _ = serve(
                    listener,
                    Planes {
                        state: pending,
                        manual,
                        log,
                        flows,
                        capture: None,
                    },
                    Arc::new(std::sync::atomic::AtomicBool::new(false)),
                );
            });
        }

        let p = pending.clone();
        let parked = thread::spawn(move || p.park("api.test", 443, "/x", None, 256, |_| {}));
        let seq = wait_for_one(&pending);

        // The id as an operator would hold it, from a session that no longer exists.
        let ours = incarnation().expect("this host reports its own start time");
        let stale = format_id(pid, seq, Some(ours.wrapping_add(1)));
        let (parsed_pid, parsed_seq, parsed_inc) = parse_id(&stale).expect("a tagged id parses");
        assert_eq!((parsed_pid, parsed_seq), (pid, seq));

        match answer_request(
            data.path(),
            parsed_pid,
            parsed_seq,
            parsed_inc,
            Verdict::Allow,
            false,
        )
        .unwrap()
        {
            AnswerOutcome::NotFound => {}
            AnswerOutcome::Answered { .. } | AnswerOutcome::Unconfirmed => {
                panic!("an id minted by another incarnation must not answer this queue")
            }
        }
        assert_eq!(
            pending.list().len(),
            1,
            "the request it named is still parked"
        );

        // And this session's own id still answers it, so the guard refuses the stale tag rather
        // than the socket.
        match answer_request(data.path(), pid, seq, incarnation(), Verdict::Allow, false).unwrap() {
            AnswerOutcome::Answered { host, .. } => assert_eq!(host, "api.test"),
            AnswerOutcome::NotFound | AnswerOutcome::Unconfirmed => {
                panic!("the live id must still be answered")
            }
        }
        assert_eq!(parked.join().unwrap(), Verdict::Allow);
    }

    #[test]
    fn on_enqueue_sees_the_assigned_id() {
        let state = Arc::new(PendingState::new());
        let s = state.clone();
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            s.park(
                "h.test",
                443,
                "/",
                Some(Duration::from_millis(50)),
                256,
                |seq| {
                    tx.send(seq).unwrap();
                },
            )
        });
        // The id handed to on_enqueue is the one the queue assigned.
        let seq = rx.recv().unwrap();
        assert_eq!(seq, 1, "the first parked request gets seq 1");
        let _ = handle.join();
    }

    #[test]
    fn parse_id_and_format_id_round_trip() {
        assert_eq!(format_id(12345, 7, None), "12345.7");
        assert_eq!(parse_id("12345.7"), Some((12345, 7, None)));
        assert_eq!(parse_id("nope"), None);
        assert_eq!(parse_id("12345"), None);
        assert_eq!(parse_id("12345.x"), None);

        // Tagged with the incarnation its session minted it in, and back.
        assert_eq!(format_id(12345, 7, Some(9_657_137)), "12345.7@9657137");
        assert_eq!(
            parse_id("12345.7@9657137"),
            Some((12345, 7, Some(9_657_137)))
        );
        // A tag that is not a number is not a tag, and the id is refused rather than read as the
        // untagged form — accepting it would hand the answer to whatever the pid is now.
        assert_eq!(parse_id("12345.7@"), None);
        assert_eq!(parse_id("12345.7@x"), None);
    }

    /// A verdict carrying another incarnation's tag is refused, and the request stays parked.
    ///
    /// The window this closes: the id routes on the pid alone (`control-<pid>.sock`) and the
    /// sequence restarts at zero in every session, so a session given a dead one's pid was handed
    /// its predecessor's ids and answered them against its own queue. What the operator meant is
    /// gone with the session that parked it; `not-found` is what actually happened.
    #[test]
    fn a_verdict_tagged_for_another_incarnation_is_refused() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = Arc::new(LogRing::new(8));
        let flows = Arc::new(FlowRegistry::new());
        let s = state.clone();
        let parked = thread::spawn(move || s.park("api.test", 443, "/x", None, 256, |_| {}));
        let seq = wait_for_one(&state);

        let ours = incarnation().expect("this host reports its own start time");
        let theirs = ours.wrapping_add(1);
        assert_eq!(
            dispatch(
                &format!("ALLOW {seq} inc={theirs}"),
                &state,
                &manual,
                &log,
                &flows,
                None
            ),
            "err not-found\n",
            "a tag that is not this session's must not answer its queue"
        );

        // Untagged, as an older `sbx` sends it: answered, which is the behaviour this field is a
        // strict addition to rather than a replacement of.
        let reply = dispatch(&format!("ALLOW {seq}"), &state, &manual, &log, &flows, None);
        assert!(reply.starts_with("ok host=api.test"), "{reply}");
        assert_eq!(parked.join().unwrap(), Verdict::Allow);
    }

    /// Block briefly until exactly one request is parked, returning its seq — so a test can answer a
    /// request a sibling thread just parked without racing the enqueue.
    fn wait_for_one(state: &PendingState) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let rows = state.list();
            if let Some(row) = rows.first() {
                return row.seq;
            }
            assert!(Instant::now() < deadline, "no request was parked");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Block until at least `n` requests are parked (used by the bulk-drain tests).
    fn wait_for_n(state: &PendingState, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while state.list().len() < n {
            assert!(Instant::now() < deadline, "fewer than {n} requests parked");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Spawn one parked request and block until it is enqueued (its seq assigned). Parking one at a
    /// time makes the per-host seq order deterministic — each `park` grabs the lock and increments
    /// the counter before the next is spawned — so a test can assert the oldest-first drain order.
    fn park_next(
        state: &Arc<PendingState>,
        host: &'static str,
        port: u16,
        already: usize,
    ) -> thread::JoinHandle<Verdict> {
        let s = state.clone();
        let handle = thread::spawn(move || s.park(host, port, "/", None, 256, |_| {}));
        wait_for_n(state, already + 1);
        handle
    }

    /// A parked request holds no byte the cage could paint the operator's terminal with.
    ///
    /// `host` and `path` are the cage's to choose — a `Host` header, an SNI, a CONNECT authority,
    /// and the target of the request being asked about — and `sbx net pending` prints both while the
    /// operator is deciding whether to open egress. An ESC run there erases the lines above it, so a
    /// listing can be made to show a destination other than the one the id answers. This is the same
    /// door, and the same treatment, as `LogRing::push`.
    #[test]
    fn a_parked_request_carries_no_byte_the_cage_could_paint_with() {
        let state = Arc::new(PendingState::new());
        let s = state.clone();
        let parked = thread::spawn(move || {
            s.park(
                "api.example.com\x1b[2Kgithub.com",
                443,
                "/v1/x\x1b[31mRED\x1b[0m",
                None,
                256,
                |_| {},
            )
        });
        wait_for_one(&state);
        let rows = state.list();
        let row = rows.first().expect("the parked row");
        for (field, value) in [("host", &row.host), ("path", &row.path)] {
            assert!(
                !value.chars().any(char::is_control),
                "{field} kept a control byte: {value:?}"
            );
        }
        // Replaced rather than dropped, so what the cage asked for stays legible in the listing.
        assert_eq!(row.host, "api.example.com [2Kgithub.com");
        assert_eq!(row.path, "/v1/x [31mRED [0m");
        // The answer reply names the stored host, so what the operator approves is what they read.
        let (host, _, _) = state
            .answer_like(row.seq, Verdict::Allow)
            .expect("answered");
        assert_eq!(host, "api.example.com [2Kgithub.com");
        assert_eq!(parked.join().unwrap(), Verdict::Allow);
    }

    /// Sanitising the queue closes the *line*; this closes the line's own **tokens**.
    ///
    /// `parse_pending_line` takes a row as `split_whitespace()` then `split_once('=')` per token,
    /// and a token carrying no `=` makes the whole parse fail — which drops the request from
    /// `sbx net pending` entirely, leaving no id to answer it with while the cage stays parked.
    /// `sanitize` maps a control byte to exactly that separator, and Unicode whitespace such as
    /// U+00A0 is not a control character and reaches the line untouched, so the two treatments are
    /// both needed here for the reason `format_event_line` states for the log plane.
    #[test]
    fn a_cage_chosen_field_cannot_split_or_rewrite_a_token_of_its_own_pending_line() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = LogRing::new(LOG_RING_CAP);
        let flows = FlowRegistry::new();
        let s = state.clone();
        let parked = thread::spawn(move || {
            s.park(
                // U+00A0: whitespace to the reader, not a control character, so `sanitize` keeps it.
                "h.test\u{a0}port=1",
                443,
                // A query string's `=` must survive; the whitespace around it must not.
                "/x?a=1\u{a0}waiting=9",
                None,
                256,
                |_| {},
            )
        });
        wait_for_one(&state);
        let response = dispatch("LIST", &state, &manual, &log, &flows, None);
        let line = response.lines().next().expect("the pending line");

        // The reader's own contract, applied here so the assertion is the parse and not a guess at
        // it: every token past the marker splits on an `=`, and the last write of a key wins.
        let mut tokens = line.split_whitespace();
        assert_eq!(
            tokens.next(),
            Some("pending"),
            "the line opens with its marker"
        );
        let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
        for token in tokens {
            let (key, value) = token.split_once('=').unwrap_or_else(|| {
                panic!("`{token}` carries no `=`, which erases the request: {line}")
            });
            fields.insert(key, value);
        }
        assert_eq!(fields.get("port"), Some(&"443"), "{line}");
        // `waiting` is read from the clock, so its value is not the assertion — that the cage's own
        // `waiting=9` did not become the one the reader keeps is.
        assert_ne!(
            fields.get("waiting"),
            Some(&"9"),
            "a cage-chosen value must not restate a field of the row carrying it: {line}"
        );
        assert_eq!(fields.get("host"), Some(&"h.test_port_1"), "{line}");
        // The path is the line's last token, so its value is everything past the first `=` — the one
        // place a query string's `=` survives, and it has to, or the row would misreport the target.
        assert_eq!(fields.get("path"), Some(&"/x?a=1_waiting=9"), "{line}");

        let _ = state.answer_all(Verdict::Deny);
        let _ = parked.join();
    }

    #[test]
    fn answer_all_drains_every_parked_request_oldest_first() {
        let state = Arc::new(PendingState::new());
        // Park three requests one at a time, so their seqs are 1,2,3 in this order.
        let parked: Vec<_> = ["a.test", "b.test", "c.test"]
            .iter()
            .enumerate()
            .map(|(i, host)| park_next(&state, host, 443, i))
            .collect();

        // One drain answers all three, oldest id first (so the parking order is preserved).
        let answered = state.answer_all(Verdict::Allow);
        assert_eq!(
            answered,
            vec![
                ("a.test".to_string(), 443),
                ("b.test".to_string(), 443),
                ("c.test".to_string(), 443),
            ]
        );
        for p in parked {
            assert_eq!(p.join().unwrap(), Verdict::Allow);
        }
        assert!(state.list().is_empty(), "the queue is fully drained");
        // A second drain on the empty queue answers nothing (clean, not an error).
        assert!(state.answer_all(Verdict::Deny).is_empty());
    }

    #[test]
    fn dispatch_star_drains_all_and_remembers_only_with_session() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = LogRing::new(LOG_RING_CAP);
        let flows = FlowRegistry::new();

        // A bare `DENY *` drains every request but remembers nothing. Parked one at a time so the
        // response lines come back in a deterministic oldest-first order.
        let _ = park_next(&state, "x.test", 8080, 0);
        let _ = park_next(&state, "y.test", 8080, 1);
        let response = dispatch("DENY *", &state, &manual, &log, &flows, None);
        assert_eq!(response, "answered host=x.test\nanswered host=y.test\nok\n");
        assert!(
            manual.snapshot().1.is_empty(),
            "a bare `DENY *` must not remember"
        );

        // `ALLOW * session` drains and remembers each host:port as a manual rule.
        let _ = park_next(&state, "p.test", 8080, 0);
        let _ = park_next(&state, "q.test", 8080, 1);
        let _ = dispatch("ALLOW * session", &state, &manual, &log, &flows, None);
        let (allow, _) = manual.snapshot();
        assert_eq!(allow.len(), 2, "`* session` remembers each answered host");

        // An empty queue replies a clean `ok` with no `answered` lines.
        assert_eq!(
            dispatch("ALLOW *", &state, &manual, &log, &flows, None),
            "ok\n"
        );
    }

    #[test]
    fn drain_session_round_trips_over_the_socket() {
        // The integration seam for the bulk drain: the client `drain_session` against a real `serve`.
        use crate::testutil::TmpDir;
        let data = TmpDir::new();
        std::fs::create_dir_all(control_dir(data.path())).unwrap();
        let pid = 22222u32;
        let socket = control_socket(data.path(), pid);

        let pending = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let flows = Arc::new(FlowRegistry::new());
        let listener = UnixListener::bind(&socket).unwrap();
        {
            let pending = pending.clone();
            let manual = manual.clone();
            let log = log.clone();
            let flows = flows.clone();
            thread::spawn(move || {
                let _ = serve(
                    listener,
                    Planes {
                        state: pending,
                        manual,
                        log,
                        flows,
                        capture: None,
                    },
                    Arc::new(std::sync::atomic::AtomicBool::new(false)),
                );
            });
        }

        // Parked one at a time so the drained order is deterministic (seqs 1 then 2).
        let parked = vec![
            park_next(&pending, "one.test", 8080, 0),
            park_next(&pending, "two.test", 8080, 1),
        ];

        // Drain ALLOW with `--session` (remember) over the real socket.
        match drain_session(data.path(), pid, Verdict::Allow, true).unwrap() {
            DrainOutcome::Drained(hosts) => {
                assert_eq!(hosts, vec!["one.test".to_string(), "two.test".to_string()])
            }
            DrainOutcome::Unsupported | DrainOutcome::Unconfirmed => {
                panic!("a current server must drain, not report unsupported")
            }
        }
        for p in parked {
            assert_eq!(p.join().unwrap(), Verdict::Allow);
        }
        // Each answered host:port round-trips back as a remembered manual rule.
        let rules = query_manual(data.path(), pid).unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|r| r.kind == ManualKind::Allow));

        // A drain on the now-empty queue is a clean *empty* Drained — distinct from Unsupported.
        match drain_session(data.path(), pid, Verdict::Allow, false).unwrap() {
            DrainOutcome::Drained(hosts) => assert!(hosts.is_empty()),
            DrainOutcome::Unsupported | DrainOutcome::Unconfirmed => {
                panic!("an empty healthy queue is Drained, not Unsupported")
            }
        }
    }

    #[test]
    fn drain_session_reports_unsupported_when_the_server_does_not_know_the_command() {
        // An older control server (one predating `--all`) replies `err bad-request` to a bulk drain.
        // `drain_session` must report that as `Unsupported`, NOT silently swallow it as an empty drain
        // — the difference between "nothing parked" and "this session is too old to drain in bulk".
        use crate::testutil::TmpDir;
        use std::io::{BufRead, BufReader, Write};
        let data = TmpDir::new();
        std::fs::create_dir_all(control_dir(data.path())).unwrap();
        let pid = 24242u32;
        let socket = control_socket(data.path(), pid);
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut cmd = String::new();
            BufReader::new(&stream).read_line(&mut cmd).unwrap();
            assert!(cmd.starts_with("ALLOW *"));
            (&stream).write_all(b"err bad-request\n").unwrap();
        });
        let outcome = drain_session(data.path(), pid, Verdict::Allow, false).unwrap();
        server.join().unwrap();
        assert!(
            matches!(outcome, DrainOutcome::Unsupported),
            "an `err` reply must surface as Unsupported"
        );
    }

    // ── The live egress event log ──────────────────────────────────────────────────────────────

    fn push_event(ring: &LogRing, host: &str, verdict: LogVerdict, reason: &str) {
        ring.push(
            false,
            host,
            443,
            Some("GET"),
            Some("/x"),
            verdict,
            reason,
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
            Plane::Agent,
        );
    }

    #[test]
    fn log_ring_assigns_monotonic_seqs_and_evicts_oldest_past_cap() {
        let ring = LogRing::new(3);
        for i in 0..5 {
            push_event(&ring, &format!("h{i}.test"), LogVerdict::Allow, "allowed");
        }
        let snap = ring.snapshot(None, None, false);
        // Cap is 3, so only the newest three survive; seqs are 1..=5 and never repeat.
        assert_eq!(snap.events.len(), 3);
        assert_eq!(snap.head, 5, "head is the newest seq assigned");
        let seqs: Vec<u64> = snap.events.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![3, 4, 5], "the oldest two were evicted");
        assert_eq!(snap.events[0].host, "h2.test");
        assert_eq!(snap.dropped, 0, "a tail read never reports a gap");
    }

    /// Every free-form field of a log event is chosen by the cage, and the two fail-closed refusals
    /// in the proxy's `handle_client` push the raw method and target *before* the control-byte check
    /// has run. So an ESC reaching the ring is an ESC `sbx net logs` prints straight at the
    /// operator's terminal — `\x1b[1A\x1b[2K` erases the row above, which is how a cage would paint
    /// over its own refusals — and a CR or NUL is a forged second row on the line-based control
    /// wire. The door is here, not at the ~30 call sites; this is what says so.
    #[test]
    fn a_log_event_carries_no_byte_the_cage_could_frame_or_paint_with() {
        let ring = LogRing::new(LOG_RING_CAP);
        ring.push(
            false,
            "\x1b[1A\x1b[2Kevil.test",
            443,
            Some("GET\r\nX: forged"),
            Some("/a\npending id=1"),
            LogVerdict::Blocked,
            "method-not-allowed",
            Proto::Other,
            HttpVer::Unknown,
            RpcKind::None,
            Plane::Agent,
        );
        let snap = ring.snapshot(None, None, false);
        let e = &snap.events[0];
        for (field, value) in [
            ("host", &e.host),
            ("method", e.method.as_ref().expect("method")),
            ("path", e.path.as_ref().expect("path")),
        ] {
            assert!(
                !value.chars().any(char::is_control),
                "{field} kept a control byte: {value:?}"
            );
        }
        // Replaced rather than dropped, so what the cage asked for is still legible in the row.
        assert_eq!(e.host, " [1A [2Kevil.test");
        assert_eq!(e.method.as_deref(), Some("GET  X: forged"));
        assert_eq!(e.path.as_deref(), Some("/a pending id=1"));
    }

    /// Sanitising the ring closes the *line*; this closes the line's own **tokens**.
    ///
    /// The reader takes an event line as `split_whitespace()` then `split_once('=')` per token, so a
    /// space inside a cage-chosen value either erases the whole event (a token with no `=` fails the
    /// parse) or rewrites a field the event already stated (a later `verdict=` wins). Both are
    /// reachable: `sanitize` maps a control byte — an HTAB, which the tunnelled-request guard
    /// deliberately admits as an ordinary request-target byte — to exactly that space, and Unicode
    /// whitespace such as U+00A0 is not a control character and reaches the line untouched. The
    /// stake is an allowed, credential-bearing request that leaves no row in `sbx net log` while
    /// `sbx net stats` still counts it, so the two disagree and the log reads as the broken one.
    #[test]
    fn a_cage_chosen_field_cannot_split_or_rewrite_a_token_of_its_own_event_line() {
        let ring = LogRing::new(LOG_RING_CAP);
        ring.push(
            false,
            // U+00A0: whitespace to the reader, not a control character, so `sanitize` keeps it.
            "h.test\u{a0}port=1",
            443,
            // An HTAB, which `sanitize` turns into the reader's own separator.
            Some("GET\tX"),
            // A query string's `=` must survive; the space before it must not.
            Some("/x?a=1\u{a0}verdict=allow"),
            LogVerdict::Blocked,
            "method-not-allowed",
            Proto::Other,
            HttpVer::Unknown,
            RpcKind::None,
            Plane::Agent,
        );
        let snap = ring.snapshot(None, None, false);
        let line = format_event_line(&snap.events[0]);
        let line = line.trim_end();

        // The reader's own contract, applied here so the assertion is the parse and not a guess at
        // it: every token past the marker splits on an `=`, and the last write of a key wins.
        let mut tokens = line.split_whitespace();
        assert_eq!(
            tokens.next(),
            Some("event"),
            "the line opens with its marker"
        );
        let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
        for token in tokens {
            let (key, value) = token.split_once('=').unwrap_or_else(|| {
                panic!("`{token}` carries no `=`, which erases the event: {line}")
            });
            fields.insert(key, value);
        }
        assert_eq!(
            fields.get("verdict"),
            Some(&"blocked"),
            "a cage-chosen value must not restate a field of the row recording it: {line}"
        );
        assert_eq!(fields.get("port"), Some(&"443"), "{line}");
        assert_eq!(fields.get("method"), Some(&"GET_X"), "{line}");
        assert_eq!(fields.get("host"), Some(&"h.test_port_1"), "{line}");
        // The path is the line's last token, so its value is everything past the first `=` — the one
        // place a query string's `=` survives, and it has to, or the row would misreport the request.
        assert_eq!(fields.get("path"), Some(&"/x?a=1_verdict=allow"), "{line}");
    }

    /// The reason a decision is logged with, and the name of a credential seen crossing a tunnel,
    /// reach the ring from the proxy as well ([`crate::sandbox::proxy::events`]), and the proxy is
    /// the process an attacker may hold once it runs apart. So the door holds them to what it holds
    /// the host, method and path to, and the event line keeps the reason to one token of its own: a
    /// reason carrying a line break or a space cannot paint the operator's terminal, write a second
    /// row, or restate a field of its own.
    #[test]
    fn a_reason_or_a_sighting_the_proxy_reports_cannot_frame_or_paint_a_row() {
        let ring = LogRing::new(LOG_RING_CAP);
        let seq = ring.push(
            false,
            "h.test",
            443,
            None,
            None,
            LogVerdict::Blocked,
            "denied\x1b[2K\nevent seq=9 verdict=allowed host=forged.test",
            Proto::Other,
            HttpVer::Unknown,
            RpcKind::None,
            Plane::Agent,
        );
        ring.secret_seen(
            seq,
            "TOKEN\x1b[1A\nseen seq=9 way=out name=FORGED",
            SecretWay::Out,
        );
        let snap = ring.snapshot(None, None, false);
        let e = &snap.events[0];
        assert!(
            !e.reason.chars().any(char::is_control),
            "the reason kept a control byte: {:?}",
            e.reason
        );
        let name = &e.secrets_seen[0].name;
        assert!(
            !name.chars().any(char::is_control),
            "the sighting kept a control byte: {name:?}"
        );
        let line = format_event_line(e);
        let line = line.trim_end();
        assert!(!line.contains('\n'), "one row: {line:?}");
        let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
        for token in line.split_whitespace().skip(1) {
            let (key, value) = token.split_once('=').unwrap_or_else(|| {
                panic!("`{token}` carries no `=`, which erases the event: {line}")
            });
            fields.insert(key, value);
        }
        assert_eq!(fields.get("verdict"), Some(&"blocked"), "{line}");
        assert_eq!(fields.get("host"), Some(&"h.test"), "{line}");
        let seen = format_sighting_line(seq, &e.secrets_seen[0]);
        assert_eq!(seen.matches('\n').count(), 1, "one sighting row: {seen:?}");
    }

    /// The flow line carries the same hazard as the event line and gets the same treatment: `sbx net
    /// live` lists the authority of a permitted tunnel, which the cage named. A host holding a space
    /// would split into a token of its own and drop the whole flow from the view, and one holding a
    /// control byte would end the line early.
    #[test]
    fn a_flow_line_host_cannot_split_or_end_the_line_it_is_written_on() {
        let flow = FlowSnapshot {
            host: "api.test\u{a0}port=1\x1b[2K".to_string(),
            port: 8443,
            proto: Proto::Https,
            start_epoch_ms: 1_700_000_000_000,
            up: 1,
            down: 2,
        };
        let line = format_flow_line(&flow);
        assert!(
            line.ends_with('\n') && line.matches('\n').count() == 1,
            "a flow is exactly one line: {line:?}"
        );
        let parsed = parse_flow_line(line.trim_end()).expect("the reader parses its own line");
        assert_eq!(
            parsed.port, 8443,
            "the port must not be rewritten: {line:?}"
        );
        assert_eq!(parsed.host, "api.test_port_1_[2K");
    }

    #[test]
    fn log_ring_tail_returns_the_whole_window_with_no_gap() {
        let ring = LogRing::new(LOG_RING_CAP);
        push_event(&ring, "a.test", LogVerdict::Allow, "allowed");
        push_event(&ring, "b.test", LogVerdict::Deny, "denied-default");
        let snap = ring.snapshot(None, None, false);
        assert_eq!(snap.events.len(), 2);
        assert_eq!(snap.dropped, 0);
        assert_eq!(snap.head, 2);
        assert_eq!(snap.events[1].verdict, LogVerdict::Deny);
        assert_eq!(snap.events[1].reason, "denied-default");
    }

    /// A muted refusal takes a seq from the counter both rings share while living in the muted ring
    /// alone, so the distance between a follower's cursor and the oldest retained event is not the
    /// number of events it lost. A session that refuses muted requests and evicts nothing has no gap
    /// to report, and one that also overflows reports only what `events` actually lost.
    #[test]
    fn log_ring_follow_does_not_count_seqs_muted_refusals_took_as_a_gap() {
        let ring = LogRing::new(8);
        let mute = |host: &str| {
            ring.push(
                true,
                host,
                443,
                None,
                None,
                LogVerdict::Deny,
                "muted",
                Proto::Https,
                HttpVer::Unknown,
                RpcKind::None,
                Plane::Agent,
            );
        };
        // Seqs 1-3 go to the muted ring; the main ring is still empty, so a tail read seeds the
        // follower's cursor from the head alone.
        for i in 0..3 {
            mute(&format!("muted{i}.test"));
        }
        let tail = ring.snapshot(None, None, false);
        assert!(tail.events.is_empty());
        assert_eq!(tail.head, 3);
        // Two more muted refusals, then one real decision: the main ring's oldest is seq 6, two
        // seqs past the cursor, and both of those went to muted refusals this reader never had.
        mute("muted3.test");
        mute("muted4.test");
        push_event(&ring, "real.test", LogVerdict::Allow, "allowed");
        let snap = ring.snapshot(Some(tail.head), None, false);
        assert_eq!(snap.events.len(), 1, "the one real decision");
        assert_eq!(
            snap.dropped, 0,
            "nothing was evicted, so there is no gap to report"
        );

        // With the main ring over its cap the gap is what `events` lost, not what the seq space
        // suggests: at cap 2, three real decisions (seqs 4-6) evict the first of them and no more,
        // while the muted ring has overflowed on its own account.
        let ring = LogRing::new(2);
        let mute = |host: &str| {
            ring.push(
                true,
                host,
                443,
                None,
                None,
                LogVerdict::Deny,
                "muted",
                Proto::Https,
                HttpVer::Unknown,
                RpcKind::None,
                Plane::Agent,
            );
        };
        for i in 0..3 {
            mute(&format!("muted{i}.test"));
        }
        let cursor = ring.snapshot(None, None, false).head;
        for i in 0..3 {
            push_event(
                &ring,
                &format!("real{i}.test"),
                LogVerdict::Allow,
                "allowed",
            );
        }
        let snap = ring.snapshot(Some(cursor), None, false);
        assert_eq!(
            snap.events.iter().map(|e| e.seq).collect::<Vec<u64>>(),
            vec![5, 6]
        );
        assert_eq!(snap.dropped, 1, "the one real event the cap evicted");
    }

    /// The counterpart: a muted flood that overflows the muted ring *past* the follower's cursor
    /// leaves the seq space unable to say how many of the pre-cursor pushes were the main ring's,
    /// but a real decision the cap took after that cursor is still a decision the reader lost. The
    /// gap is reported, never rounded away to "nothing happened".
    #[test]
    fn log_ring_follow_reports_a_gap_when_the_muted_ring_overflowed_past_the_cursor() {
        let ring = LogRing::new(2);
        let mute = |host: &str| {
            ring.push(
                true,
                host,
                443,
                None,
                None,
                LogVerdict::Deny,
                "muted",
                Proto::Https,
                HttpVer::Unknown,
                RpcKind::None,
                Plane::Agent,
            );
        };
        // Seqs 1-3 are muted refusals; the follower seeds its cursor from the head of a tail read.
        for i in 0..3 {
            mute(&format!("muted{i}.test"));
        }
        let cursor = ring.snapshot(None, None, false).head;
        assert_eq!(cursor, 3);
        // Seqs 4-6 are more muted refusals: the muted ring now evicts seqs past the cursor too.
        for i in 3..6 {
            mute(&format!("muted{i}.test"));
        }
        // Seqs 7-9 are real decisions, and the cap takes seq 7 out of the main ring unseen.
        for i in 0..3 {
            push_event(
                &ring,
                &format!("real{i}.test"),
                LogVerdict::Allow,
                "allowed",
            );
        }
        let snap = ring.snapshot(Some(cursor), None, false);
        assert_eq!(
            snap.events.iter().map(|e| e.seq).collect::<Vec<u64>>(),
            vec![8, 9]
        );
        assert_eq!(
            snap.dropped, 1,
            "seq 7 was evicted before this follower ever saw it"
        );
        // A follower past every eviction has lost nothing, muted flood or not.
        let caught_up = ring.snapshot(Some(snap.head), None, false);
        assert!(caught_up.events.is_empty());
        assert_eq!(caught_up.dropped, 0);
    }

    #[test]
    fn log_ring_follow_reports_the_eviction_gap_and_advances() {
        let ring = LogRing::new(2);
        // Push 4 events; the ring keeps only seqs 3 and 4.
        for i in 0..4 {
            push_event(&ring, &format!("h{i}.test"), LogVerdict::Allow, "allowed");
        }
        // A follower whose cursor is 1 missed seq 2 (evicted, never seen): report the gap.
        let snap = ring.snapshot(Some(1), None, false);
        let seqs: Vec<u64> = snap.events.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![3, 4]);
        assert_eq!(snap.dropped, 1, "seq 2 fell off the ring between polls");
        // A follower already at the head sees nothing new and no gap.
        let caught_up = ring.snapshot(Some(snap.head), None, false);
        assert!(caught_up.events.is_empty());
        assert_eq!(caught_up.dropped, 0);
        assert_eq!(caught_up.head, 4);
    }

    #[test]
    fn set_status_amends_a_live_event_and_is_a_noop_once_evicted() {
        let ring = LogRing::new(2);
        let s1 = ring.push(
            false,
            "a.test",
            443,
            Some("GET"),
            Some("/1"),
            LogVerdict::Allow,
            "allowed",
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
            Plane::Agent,
        );
        let s2 = ring.push(
            false,
            "b.test",
            443,
            Some("GET"),
            Some("/2"),
            LogVerdict::Allow,
            "allowed",
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
            Plane::Agent,
        );
        // A status amends the matching still-resident event, and only it.
        ring.set_status(s2, 404);
        let snap = ring.snapshot(None, None, false);
        assert_eq!(
            snap.events[0].status, None,
            "the untouched event keeps None"
        );
        assert_eq!(
            snap.events[1].status,
            Some(404),
            "the amended event carries its code"
        );

        // Evict s1 and s2 (push two more, cap is 2), then a late status for s1 is a silent no-op —
        // an evicted event is never resurrected.
        ring.push(
            false,
            "c.test",
            443,
            Some("GET"),
            Some("/3"),
            LogVerdict::Allow,
            "allowed",
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
            Plane::Agent,
        );
        ring.push(
            false,
            "d.test",
            443,
            Some("GET"),
            Some("/4"),
            LogVerdict::Allow,
            "allowed",
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
            Plane::Agent,
        );
        ring.set_status(s1, 500);
        let after = ring.snapshot(None, None, false);
        assert!(
            after.events.iter().all(|e| e.seq != s1),
            "s1 is gone from the ring"
        );
        assert!(
            after.events.iter().all(|e| e.status.is_none()),
            "a late status for an evicted event resurrects nothing"
        );
    }

    #[test]
    fn a_follow_reader_gets_a_status_amended_after_it_passed_the_event() {
        let ring = LogRing::new(8);
        let s1 = ring.push(
            false,
            "a.test",
            443,
            Some("GET"),
            Some("/1"),
            LogVerdict::Allow,
            "allowed",
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
            Plane::Agent,
        );
        // A follow reader catches up: it has seen seq s1, with no amendment yet.
        let seen = ring.snapshot(Some(s1), Some(0), false);
        assert!(seen.events.is_empty(), "nothing new past the head");
        let (seq_cursor, amend_cursor) = (seen.head, seen.amend_head);

        // The response returns later and the status is filled in — after the reader passed s1.
        ring.set_status(s1, 200);

        // The next follow poll RE-EMITS the already-seen event, now carrying its status.
        let after = ring.snapshot(Some(seq_cursor), Some(amend_cursor), false);
        assert_eq!(after.events.len(), 1, "the amended event resurfaces");
        assert_eq!(after.events[0].seq, s1);
        assert_eq!(after.events[0].status, Some(200));

        // A reader that does NOT track the amend cursor gets today's behavior: no re-emission.
        let no_amend = ring.snapshot(Some(seq_cursor), None, false);
        assert!(
            no_amend.events.is_empty(),
            "without the amend cursor there is no retroactive status"
        );

        // Once the reader advances its amend cursor, the amendment is not shown a second time.
        let caught_up = ring.snapshot(Some(after.head), Some(after.amend_head), false);
        assert!(
            caught_up.events.is_empty(),
            "an amendment resurfaces exactly once"
        );
    }

    /// A session that ends waits for a `--follow` reader that has not read its last change, and the
    /// wait ends at that reader's next read, not when a timer runs out.
    #[test]
    fn linger_ends_at_the_read_of_a_follower_behind_the_ring() {
        let ring = Arc::new(LogRing::new(LOG_RING_CAP));
        let interval = Duration::from_millis(900);
        let first = ring.snapshot(None, None, false);
        ring.followed(7, interval, &first, false);
        push_event(&ring, "last.test", LogVerdict::Allow, "allowed");
        let cursor = first.head;
        // Taken before the reader starts its sleep, so the read cannot land sooner than 100 ms
        // after it, however late this thread is scheduled once the reader is spawned.
        let begun = Instant::now();
        let reader = {
            let ring = Arc::clone(&ring);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(100));
                let next = ring.snapshot(Some(cursor), None, false);
                ring.followed(7, interval, &next, false);
                next.events.len()
            })
        };
        ring.linger(LINGER_MAX);
        let took = begun.elapsed();
        assert_eq!(
            reader.join().unwrap(),
            1,
            "the read the session waited for carries its last event"
        );
        assert!(
            took >= Duration::from_millis(100) && took < interval,
            "the wait ends at the read: {took:?}"
        );
    }

    /// A follower that shows amendments is waited for when only an amendment arrived after its last
    /// read, and a follower that does not read again is waited for until its read was due, and no
    /// longer.
    #[test]
    fn linger_waits_for_an_amendment_the_follower_shows_until_its_read_was_due() {
        let ring = LogRing::new(LOG_RING_CAP);
        push_event(&ring, "a.test", LogVerdict::Allow, "allowed");
        let snap = ring.snapshot(None, None, false);
        let interval = Duration::from_millis(100);
        ring.followed(1, interval, &snap, true);
        ring.set_status(snap.head, 200);
        let begun = Instant::now();
        ring.linger(LINGER_MAX);
        let took = begun.elapsed();
        assert!(
            took + Duration::from_millis(50) >= interval + FOLLOW_SLACK && took < LINGER_MAX,
            "the wait runs to the read that was due: {took:?}"
        );
    }

    /// A session does not wait when no follower has anything left to read: with no follower, with
    /// one that has read everything, for an amendment a follower does not show, for one whose next
    /// read falls past the bound, and for one that has stopped reading.
    #[test]
    fn linger_does_not_wait_when_no_follower_has_anything_left_to_read() {
        let quick = |ring: &LogRing| {
            let begun = Instant::now();
            ring.linger(LINGER_MAX);
            begun.elapsed() < Duration::from_millis(50)
        };

        let ring = LogRing::new(LOG_RING_CAP);
        push_event(&ring, "a.test", LogVerdict::Allow, "allowed");
        assert!(quick(&ring), "no follower");
        let snap = ring.snapshot(None, None, false);
        ring.followed(1, Duration::from_secs(1), &snap, true);
        assert!(quick(&ring), "a follower that has read everything");

        let ring = LogRing::new(LOG_RING_CAP);
        push_event(&ring, "a.test", LogVerdict::Allow, "allowed");
        let snap = ring.snapshot(None, None, false);
        ring.followed(1, Duration::from_secs(1), &snap, false);
        ring.set_status(snap.head, 200);
        assert!(quick(&ring), "a status the follower does not show");

        let ring = LogRing::new(LOG_RING_CAP);
        let snap = ring.snapshot(None, None, false);
        ring.followed(1, LINGER_MAX * 2, &snap, false);
        push_event(&ring, "a.test", LogVerdict::Allow, "allowed");
        assert!(quick(&ring), "a follower whose next read is past the bound");

        let ring = LogRing::new(LOG_RING_CAP);
        let snap = ring.snapshot(None, None, false);
        ring.followed(1, Duration::from_millis(1), &snap, false);
        thread::sleep(FOLLOW_SLACK + Duration::from_millis(50));
        push_event(&ring, "a.test", LogVerdict::Allow, "allowed");
        assert!(quick(&ring), "a follower whose read is overdue has stopped");
    }

    /// A ring keeps one entry per follower and a bounded number of them: past the bound, the
    /// follower heard from longest ago is the one forgotten.
    #[test]
    fn a_ring_keeps_one_entry_per_follower_and_a_bounded_number() {
        let ring = LogRing::new(LOG_RING_CAP);
        let snap = ring.snapshot(None, None, false);
        let readers = FOLLOWERS_MAX as u32 + 3;
        for reader in 0..readers {
            ring.followed(reader, Duration::from_secs(1), &snap, false);
            thread::sleep(Duration::from_millis(1));
        }
        ring.followed(readers - 1, Duration::from_secs(1), &snap, false);
        let followers = locked(&ring.followers);
        assert_eq!(followers.len(), FOLLOWERS_MAX);
        assert_eq!(
            followers.iter().filter(|f| f.reader == readers - 1).count(),
            1,
            "a follower that reads again is the same entry"
        );
        assert!(
            (0..3).all(|gone| followers.iter().all(|f| f.reader != gone)),
            "the followers heard from longest ago are the ones forgotten"
        );
    }

    /// `LOG … follow=<pid>:<ms>` names a follow reader, and the session records the reader, its
    /// interval, how far the read went, and whether it asked for amendments. A malformed token
    /// names nobody.
    #[test]
    fn a_log_read_that_names_a_follower_is_recorded() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = LogRing::new(LOG_RING_CAP);
        let flows = FlowRegistry::new();
        push_event(&log, "a.test", LogVerdict::Allow, "allowed");
        log.set_status(1, 200);

        for bad in [
            "follow=",
            "follow=12",
            "follow=x:1000",
            "follow=12:y",
            "follow=-1:1000",
        ] {
            dispatch(&format!("LOG {bad}"), &state, &manual, &log, &flows, None);
        }
        assert!(
            locked(&log.followers).is_empty(),
            "a malformed token names nobody"
        );

        let out = dispatch(
            "LOG after=0 amended=0 follow=4242:1000",
            &state,
            &manual,
            &log,
            &flows,
            None,
        );
        assert!(out.contains("event seq=1"), "{out}");
        dispatch("LOG follow=77:250", &state, &manual, &log, &flows, None);
        let followers = locked(&log.followers);
        let shown = |reader: u32| {
            followers
                .iter()
                .find(|f| f.reader == reader)
                .map(|f| (f.interval, f.head, f.amend))
        };
        assert_eq!(shown(4242), Some((Duration::from_secs(1), 1, Some(1))));
        assert_eq!(shown(77), Some((Duration::from_millis(250), 1, None)));
    }

    #[test]
    fn rpc_kind_classifies_by_content_type_family_never_the_path() {
        use RpcKind::*;
        // gRPC-web is matched before gRPC (it shares the `application/grpc` prefix).
        assert_eq!(RpcKind::from_content_type("application/grpc"), Grpc);
        assert_eq!(RpcKind::from_content_type("application/grpc+proto"), Grpc);
        assert_eq!(RpcKind::from_content_type("APPLICATION/GRPC"), Grpc);
        assert_eq!(RpcKind::from_content_type("application/grpc-web"), GrpcWeb);
        assert_eq!(
            RpcKind::from_content_type("application/grpc-web+proto"),
            GrpcWeb
        );
        assert_eq!(
            RpcKind::from_content_type("application/connect+proto"),
            Connect
        );
        assert_eq!(
            RpcKind::from_content_type("application/connect+json"),
            Connect
        );
        // Connect *unary* and a plain protobuf/JSON POST are byte-identical on the wire, so they are
        // deliberately NOT tagged — the classifier never guesses from the path.
        assert_eq!(RpcKind::from_content_type("application/proto"), None);
        assert_eq!(RpcKind::from_content_type("application/json"), None);
        assert_eq!(RpcKind::from_content_type("text/plain"), None);
        assert_eq!(RpcKind::from_content_type(""), None);
    }

    #[test]
    fn read_log_round_trips_over_the_socket() {
        // The integration seam: the client `read_log`/`log_all` against a real `serve` over a bound
        // socket, so the server's wire format and the client's parser are exercised together.
        use crate::testutil::TmpDir;
        let data = TmpDir::new();
        std::fs::create_dir_all(control_dir(data.path())).unwrap();
        let pid = 33333u32;
        let socket = control_socket(data.path(), pid);

        let pending = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        log.push(
            false,
            "a.test",
            443,
            Some("GET"),
            Some("/one"),
            LogVerdict::Allow,
            "allowed",
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
            Plane::Agent,
        );
        log.push(
            false,
            "b.test",
            443,
            Some("POST"),
            Some("/two?t=1"),
            LogVerdict::Deny,
            "denied-by-rule",
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
            Plane::Agent,
        );

        let flows = Arc::new(FlowRegistry::new());
        let listener = UnixListener::bind(&socket).unwrap();
        {
            let pending = pending.clone();
            let manual = manual.clone();
            let log = log.clone();
            let flows = flows.clone();
            thread::spawn(move || {
                let _ = serve(
                    listener,
                    Planes {
                        state: pending,
                        manual,
                        log,
                        flows,
                        capture: None,
                    },
                    Arc::new(std::sync::atomic::AtomicBool::new(false)),
                );
            });
        }

        // A tail read over the socket returns both events, newest last, with the fields intact.
        let snap = read_log(&socket, None, None, false, false, None).unwrap();
        assert_eq!(snap.events.len(), 2);
        assert_eq!(snap.head, 2);
        assert_eq!(snap.events[0].host, "a.test");
        assert_eq!(snap.events[0].verdict, LogVerdict::Allow);
        assert_eq!(snap.events[1].host, "b.test");
        assert_eq!(snap.events[1].reason, "denied-by-rule");
        assert_eq!(snap.events[1].path.as_deref(), Some("/two?t=1"));

        // A follow read past the first event returns only the second, no gap.
        let after = read_log(&socket, Some(1), None, false, false, None).unwrap();
        assert_eq!(after.events.len(), 1);
        assert_eq!(after.events[0].seq, 2);
        assert_eq!(after.dropped, 0);

        // Discovery: `log_all` globs the egress dir and finds this session by its socket pid.
        let sessions = log_all(data.path(), false, false, None).read;
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].pid, pid);
        assert_eq!(sessions[0].snapshot.events.len(), 2);
    }
    /// The egress plane is the one feed that revises what it already said: a status arrives after
    /// the decision was recorded, and an append-only file cannot rewrite the line it landed on. It
    /// gets a second line, and the reader replays it onto the event it names.
    #[test]
    fn a_status_that_arrives_later_is_a_second_line_the_reader_applies() {
        let dir = crate::testutil::TmpDir::new();
        let path = dir.path().join("record-1-2.log");
        let record = crate::sandbox::lens::Recorder::create(
            &path,
            "/p",
            None,
            std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
        )
        .unwrap();
        let ring = LogRing::new(8).with_record(Some(record));
        let seq = ring.push(
            false,
            "a.test",
            443,
            Some("GET"),
            Some("/one"),
            LogVerdict::Allow,
            "allowed",
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
            Plane::Agent,
        );
        ring.set_status(seq, 204);

        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines[0], "project=/p");
        assert!(lines[1].starts_with("event seq=1 "), "{}", lines[1]);
        assert_eq!(lines[2], "amend seq=1 status=204");

        let back = super::read_record(&path).unwrap();
        assert_eq!(back.events.len(), 1, "the amendment is not a second event");
        assert_eq!(back.events[0].status, Some(204));
        assert_eq!(back.events[0].host, "a.test");
    }

    /// `mute` is `dontaudit`. In memory a muted flood is kept off the real ring so it cannot evict
    /// anything; on disk it would evict nothing and **fill** instead, truncating the tail of the
    /// session. The counters `sbx net stats` keeps for it are untouched, which is the contract mute
    /// already had.
    #[test]
    fn a_muted_refusal_is_counted_but_never_recorded() {
        let dir = crate::testutil::TmpDir::new();
        let path = dir.path().join("record-1-2.log");
        let record = crate::sandbox::lens::Recorder::create(
            &path,
            "/p",
            None,
            std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
        )
        .unwrap();
        let ring = LogRing::new(8).with_record(Some(record));
        ring.push(
            true,
            "noisy.test",
            443,
            None,
            None,
            LogVerdict::Deny,
            "no-rule",
            Proto::Https,
            HttpVer::Unknown,
            RpcKind::None,
            Plane::Agent,
        );
        ring.push(
            false,
            "real.test",
            443,
            None,
            None,
            LogVerdict::Deny,
            "no-rule",
            Proto::Https,
            HttpVer::Unknown,
            RpcKind::None,
            Plane::Agent,
        );

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(!body.contains("noisy.test"), "{body}");
        assert!(body.contains("real.test"), "{body}");
        // Both are still in the rings the live view reads, the muted one in its own.
        assert_eq!(
            super::LogRing::snapshot(&ring, None, None, true)
                .events
                .len(),
            2
        );
    }

    /// A credential seen crossing an open tunnel is the single most audit-worthy thing this plane
    /// reports, and it arrives long after the event was written. It is recorded the moment it is
    /// noticed, as the same `seen` line the wire carries.
    #[test]
    fn a_secret_sighting_reaches_the_record_as_its_own_line() {
        let dir = crate::testutil::TmpDir::new();
        let path = dir.path().join("record-1-2.log");
        let record = crate::sandbox::lens::Recorder::create(
            &path,
            "/p",
            None,
            std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
        )
        .unwrap();
        let ring = LogRing::new(8).with_record(Some(record));
        let seq = ring.push(
            false,
            "ws.test",
            443,
            None,
            None,
            LogVerdict::Allow,
            "allowed",
            Proto::Https,
            HttpVer::Unknown,
            RpcKind::None,
            Plane::Agent,
        );
        ring.secret_seen(seq, "API_TOKEN", SecretWay::Out);
        // Reported once per direction: a second sighting of the same pair adds no line.
        ring.secret_seen(seq, "API_TOKEN", SecretWay::Out);

        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            body.lines().filter(|l| l.starts_with("seen ")).count(),
            1,
            "{body}"
        );
        let back = super::read_record(&path).unwrap();
        assert_eq!(back.events[0].secrets_seen.len(), 1);
        assert_eq!(back.events[0].secrets_seen[0].name, "API_TOKEN");
    }

    /// The names a sighting carries are the proxy's to report, so an event keeps at most
    /// [`SIGHTINGS_MAX`] of them: one more neither lists a name, nor amends the event for a
    /// `--follow` reader, nor writes a line to the record.
    #[test]
    fn an_event_keeps_a_bounded_number_of_secret_sightings() {
        let dir = crate::testutil::TmpDir::new();
        let path = dir.path().join("record-1-2.log");
        let record = crate::sandbox::lens::Recorder::create(
            &path,
            "/p",
            None,
            std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
        )
        .unwrap();
        let ring = LogRing::new(8).with_record(Some(record));
        let seq = ring.push(
            false,
            "ws.test",
            443,
            None,
            None,
            LogVerdict::Allow,
            "allowed",
            Proto::Https,
            HttpVer::Unknown,
            RpcKind::None,
            Plane::Agent,
        );
        for n in 0..SIGHTINGS_MAX + 8 {
            ring.secret_seen(seq, &format!("NAME_{n}"), SecretWay::Out);
        }

        let snap = ring.snapshot(None, None, false);
        let names: Vec<&str> = snap.events[0]
            .secrets_seen
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        let kept: Vec<String> = (0..SIGHTINGS_MAX).map(|n| format!("NAME_{n}")).collect();
        assert_eq!(names, kept);
        assert_eq!(snap.amend_head, 32);
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            body.lines().filter(|l| l.starts_with("seen ")).count(),
            32,
            "{body}"
        );
    }
}
