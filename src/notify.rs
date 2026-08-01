//! The block-notification policy: which refusals sbx says out loud to the person running it, and how
//! often it repeats itself.
//!
//! A refusal is structurally invisible. The cage's own boundary is enforced by the kernel — an absent
//! bind answers `ENOENT`, a read-only one `EROFS`, the mandatory seccomp filter an errno — and none of
//! that reaches the host: no call is made, no event is raised, there is nothing to observe. What *is*
//! observable is the set of refusals **sbx itself decides**, host-side: an egress request the policy
//! turned down, an `execve` the exec supervisor stopped, a signature the ssh-agent broker withheld, a
//! task refused at admission, a security field dropped because its source is not trusted. Each of those
//! already passes through sbx's own code, so announcing it costs nothing — and each is otherwise seen
//! only by the agent (in a `403` body it may well swallow) or by a log nobody thinks to read.
//!
//! This module is the pure half: the policy resolved from `[notify]`, the identity a repeat is measured
//! against, and the decision to speak or stay quiet. It performs no I/O — the desktop/stderr sink is
//! built on top — so the semantics that decide whether a security-relevant refusal is heard are
//! unit-tested without a notification daemon.
//!
//! ## Modes
//!
//! Per event, one of [`NotifyMode`]: `off` (silent), `once` (the first of each distinct problem, then
//! quiet), `always` (every occurrence). `always` is the default, and is affordable because a repeat
//! **revises** the notification already on screen rather than adding one — so the difference from
//! `once` is that a problem still happening keeps saying so, not that the desktop fills up. `once`
//! is there for the reader who wants each problem stated exactly once and never again.
//!
//! ## What "the same problem" means
//!
//! Identity is `(event, subject, reason)` — see [`Block::key`]. The reason is part of it deliberately:
//! `api.example.com:443` refused by an explicit deny rule and the same host refused because nothing
//! allowed it are two different problems with two different fixes, and folding them together would hide
//! the second behind the first. Identity is held in RAM for the session and never persisted: a refusal
//! silenced yesterday must not stay silent today, when it may mean something new.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A refusal sbx can announce. One variant per **config section that governs the refusal**, so the
/// name in `[notify.events]` is also the name of the setting to go and change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum NotifyEvent {
    /// An egress request the network policy turned down — governed by `[network]`.
    Network,
    /// An `execve` the exec supervisor stopped — governed by `[proc]`.
    Proc,
    /// A signature the ssh-agent broker withheld — governed by `[ssh_agent]`.
    SshAgent,
    /// A task invocation refused at admission — governed by `[task]`.
    Task,
    /// A security field dropped because the config declaring it is not trusted — governed by the trust
    /// gate. Distinct from the others: nothing was blocked at runtime, a *declaration* was, and the
    /// symptom shows up later as a cage that is not shaped the way its config reads.
    Trust,
}

impl NotifyEvent {
    /// Every event, in declaration order — the iteration order of `sbx config show` and the order a
    /// bare `events` list is folded in.
    pub(crate) const ALL: [NotifyEvent; 5] = [
        NotifyEvent::Network,
        NotifyEvent::Proc,
        NotifyEvent::SshAgent,
        NotifyEvent::Task,
        NotifyEvent::Trust,
    ];

    /// Parse an event name as written in `[notify.events]`. `None` for anything unrecognized, so the
    /// caller names the key rather than passing over it — a misspelled event would otherwise silently
    /// mean "never notified", which is exactly the failure this feature exists to prevent.
    pub(crate) fn parse(s: &str) -> Option<NotifyEvent> {
        match s {
            "network" => Some(NotifyEvent::Network),
            "proc" => Some(NotifyEvent::Proc),
            "ssh_agent" => Some(NotifyEvent::SshAgent),
            "task" => Some(NotifyEvent::Task),
            "trust" => Some(NotifyEvent::Trust),
            _ => None,
        }
    }

    /// The canonical name, identical to the config section it names.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            NotifyEvent::Network => "network",
            NotifyEvent::Proc => "proc",
            NotifyEvent::SshAgent => "ssh_agent",
            NotifyEvent::Task => "task",
            NotifyEvent::Trust => "trust",
        }
    }

    /// The one-line headline for this event, the notification's summary.
    fn headline(self) -> &'static str {
        match self {
            NotifyEvent::Network => "sbx blocked a network request",
            NotifyEvent::Proc => "sbx blocked a program from running",
            NotifyEvent::SshAgent => "sbx withheld an ssh key",
            NotifyEvent::Task => "sbx refused a task",
            NotifyEvent::Trust => "sbx dropped a setting from an untrusted config",
        }
    }

    /// The slot this event occupies in a [`NotifyPolicy`]'s mode table.
    fn index(self) -> usize {
        match self {
            NotifyEvent::Network => 0,
            NotifyEvent::Proc => 1,
            NotifyEvent::SshAgent => 2,
            NotifyEvent::Task => 3,
            NotifyEvent::Trust => 4,
        }
    }
}

/// How often one event is announced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum NotifyMode {
    /// Never announced. The refusal still happens and is still recorded (`sbx net logs`, `sbx proc
    /// logs`) — only the notification is withheld.
    Off,
    /// The first occurrence of each distinct problem, then silence for that problem.
    Once,
    /// Every occurrence — the default. A repeat does not stack a second toast: it updates the one
    /// already on screen through `replaces_id` (see [`Coalescer::decide`]), so what `always` costs
    /// over `once` is an accurate count rather than a pile to dismiss. An agent retrying a blocked
    /// host in a loop therefore leaves one notification, not two hundred.
    #[default]
    Always,
}

impl NotifyMode {
    /// Parse a `[notify]` mode. `None` for an unknown value, so the caller warns and keeps the mode it
    /// already had — a typo must never silently switch notifications off.
    pub(crate) fn parse(s: &str) -> Option<NotifyMode> {
        match s {
            "off" => Some(NotifyMode::Off),
            "once" => Some(NotifyMode::Once),
            "always" => Some(NotifyMode::Always),
            _ => None,
        }
    }

    /// The canonical string, for `sbx config show` and the one-shot override display.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            NotifyMode::Off => "off",
            NotifyMode::Once => "once",
            NotifyMode::Always => "always",
        }
    }
}

/// The resolved notification policy: one mode per event.
///
/// A whole-policy mode (`notify = "off"`) and a per-event one (`[notify.events] network = "always"`)
/// are the same shape here — the former sets every slot, the latter one — so nothing downstream has to
/// know which spelling produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NotifyPolicy {
    modes: [NotifyMode; NotifyEvent::ALL.len()],
    /// How long a problem stays quiet after being announced, under `always`. `None` announces every
    /// occurrence.
    ///
    /// This is what makes `always` liveable on a session that lasts hours. A repeat revises the
    /// notification already on screen, so a burst costs nothing — but an agent that keeps retrying
    /// for an hour keeps putting that notification back in front of its reader, and *that* is the
    /// spam. A period turns "every occurrence" into "at most once per period, per problem", which
    /// still says a problem is ongoing without saying it every few seconds.
    repeat_after: Option<Duration>,
}

impl Default for NotifyPolicy {
    fn default() -> Self {
        NotifyPolicy::uniform(NotifyMode::default())
    }
}

impl NotifyPolicy {
    /// One mode for every event.
    pub(crate) fn uniform(mode: NotifyMode) -> NotifyPolicy {
        NotifyPolicy {
            modes: [mode; NotifyEvent::ALL.len()],
            repeat_after: None,
        }
    }

    /// This policy with a quiet period between repeats of one problem.
    pub(crate) fn with_repeat_after(mut self, period: Option<Duration>) -> NotifyPolicy {
        self.repeat_after = period;
        self
    }

    /// The quiet period between repeats, when one is set.
    pub(crate) fn repeat_after(self) -> Option<Duration> {
        self.repeat_after
    }

    /// This policy with one event's mode replaced — the per-event override, applied over a resolved
    /// baseline so `[notify.events]` narrows or widens exactly what it names and leaves the rest alone.
    pub(crate) fn with_event(mut self, event: NotifyEvent, mode: NotifyMode) -> NotifyPolicy {
        self.modes[event.index()] = mode;
        self
    }

    /// The mode governing one event.
    pub(crate) fn mode_for(self, event: NotifyEvent) -> NotifyMode {
        self.modes[event.index()]
    }

    /// Whether any event is announced at all. The launch consults this before standing up the sink —
    /// an all-`off` policy opens no bus connection and spawns no thread.
    pub(crate) fn any_enabled(self) -> bool {
        NotifyEvent::ALL
            .iter()
            .any(|e| self.mode_for(*e) != NotifyMode::Off)
    }
}

/// One refusal to announce.
///
/// `subject` and `reason` are what identity is measured on, so both must be **stable** across repeats
/// of the same problem: the host and port rather than the full URL (which carries a per-request path),
/// the exec target rather than the pid that reached for it. `detail` and `fix` are free text for the
/// human and play no part in identity.
///
/// Every field can carry text the agent chose (a host it asked for, a path it ran), and a notification
/// body may be journaled by the desktop daemon — so a block is redacted at the sink, before it leaves
/// the process, exactly like every other outward-facing sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Block {
    /// Which lens refused.
    pub(crate) event: NotifyEvent,
    /// What was refused, in its most stable form: `api.example.com:443`, `/usr/bin/curl`, a task name.
    pub(crate) subject: String,
    /// The stable category, as the corresponding log records it: `denied-by-rule`, `denied-default`,
    /// `denied-method`, `outbound-secret`…
    pub(crate) reason: String,
    /// One human sentence explaining the refusal, or empty.
    pub(crate) detail: String,
    /// The command that would allow it, or empty. Offered only where allowing is a sound suggestion —
    /// never for a refusal that fired on a security ground (a leaked credential, an SSRF target).
    pub(crate) fix: String,
}

impl Block {
    /// The identity a repeat is measured against: the event, the subject, and the reason. Two refusals
    /// share a key exactly when they are the same problem with the same fix.
    ///
    /// The subject is length-prefixed rather than merely separator-joined. A subject is agent-chosen
    /// text (a host it asked for, a path it ran) and no byte can be assumed absent from it, so a plain
    /// join would let one triple produce another's key — and a forged collision does not just mislabel,
    /// it makes `once` swallow the refusal it collided with.
    pub(crate) fn key(&self) -> String {
        format!(
            "{}\u{1f}{}:{}\u{1f}{}",
            self.event.as_str(),
            self.subject.len(),
            self.subject,
            self.reason
        )
    }

    /// The notification's `(summary, body)`. Pure, so both forms are pinned by tests without a
    /// notification daemon; the sink adds nothing to what this returns beyond redaction.
    ///
    /// `context` names the session this refusal came from (see [`Origin::label`]) and rides the
    /// **summary**, not the body: with two or three sandboxes running at once, "which one was that?"
    /// is the first question a toast has to answer, and the summary is the part that is read first
    /// and never truncated. Empty for a launch that has no session to name, and then the summary is
    /// the headline alone.
    pub(crate) fn render(&self, context: &str) -> (String, String) {
        let mut summary = self.event.headline().to_string();
        if !context.is_empty() {
            summary.push_str(" · ");
            summary.push_str(context);
        }
        let mut body = self.subject.clone();
        if !self.detail.is_empty() {
            body.push_str(" — ");
            body.push_str(&self.detail);
        }
        if !self.fix.is_empty() {
            // A visible separator rather than a newline: a notification daemon is free to flatten
            // `\n` into a space (GNOME Shell does), and the sentence then runs into the suggestion —
            // "…allows this host allow it: sbx net allow …". A mid-dot survives either rendering.
            body.push_str(" · allow it: ");
            body.push_str(&self.fix);
        }
        (summary, body)
    }
}

/// Which sandbox a refusal came from: the app (when the launch is one), the project, and the pid.
///
/// All three, because each answers a different question and none answers the others. The **app** is
/// what a person recognises ("that was my coding agent"), but several projects can run the same app.
/// The **project** disambiguates those, and is the only name a bare `sbx run` has. The **pid** is the
/// one part that is unique while the session lives — it is what `sbx session ls` lists and what `sbx
/// attach`/`sbx stop` take — so it turns a toast into something actionable rather than merely
/// informative.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Origin {
    /// The `sbx app <name>` this launch runs, or empty for a bare `sbx run`.
    pub(crate) app: String,
    /// The project's directory name — not its full path, which no toast is wide enough to carry.
    /// `sbx session ls` is where the full path lives.
    pub(crate) project: String,
    /// The launching sbx process. Zero means "not a session" and is left out.
    pub(crate) pid: u32,
}

impl Origin {
    /// The one-line label a notification carries: `app@project[pid]`, dropping whichever part is
    /// absent — `project[pid]` for a bare run, and empty when there is nothing to name at all.
    pub(crate) fn label(&self) -> String {
        let mut out = String::new();
        if !self.app.is_empty() {
            out.push_str(&self.app);
            if !self.project.is_empty() {
                out.push('@');
            }
        }
        out.push_str(&self.project);
        if self.pid != 0 {
            out.push_str(&format!("[{}]", self.pid));
        }
        out
    }
}

/// What the sink should do with a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Speak {
    /// Say nothing: the mode is `off`, or `once` already said this one.
    Stay,
    /// Announce it. `replaces` carries the id the daemon returned for the previous notification of this
    /// same problem, when there was one — passed as `replaces_id` so a repeat **updates the toast in
    /// place** instead of stacking another one. That is what makes `always` survivable against an agent
    /// that retries in a loop, without an arbitrary per-session cap.
    Say { replaces: Option<u32> },
}

/// The per-session repeat memory: which problems have been announced, and under which notification id.
///
/// In RAM, for the session's lifetime, and deliberately never persisted — a problem silenced by
/// yesterday's run must be heard again today, because the same refusal in a new context is new
/// information.
#[derive(Debug, Default)]
pub(crate) struct Coalescer {
    /// Key → what is known about that problem's last announcement.
    seen: HashMap<String, Announced>,
}

/// What a problem's last announcement left behind.
#[derive(Debug, Clone, Copy)]
struct Announced {
    /// The id the daemon returned, so a repeat revises that notification rather than adding one.
    /// `None` until a daemon returns one — which it may never do: a stderr fallback has no ids.
    id: Option<u32>,
    /// When it was announced, for the `repeat_after` quiet period. `None` when the announcement was
    /// only *decided* and delivery has not been dated (never, in practice — `decide` dates it).
    at: Option<Instant>,
}

impl Coalescer {
    /// Decide whether to announce `block` under `policy`, and against which prior notification.
    ///
    /// Records the key as seen, so a `once` event announces exactly one of each distinct problem. Pure
    /// apart from that memory — no I/O, no clock — so the whole repeat semantics is unit-testable.
    /// `now` is passed in rather than read here, so the quiet period is tested by advancing a clock
    /// instead of by waiting.
    pub(crate) fn decide(&mut self, policy: NotifyPolicy, block: &Block, now: Instant) -> Speak {
        let mode = policy.mode_for(block.event);
        if mode == NotifyMode::Off {
            return Speak::Stay;
        }
        let key = block.key();
        match self.seen.get_mut(&key) {
            // Seen before: quiet under `once`; under `always` an update of the same toast, unless a
            // quiet period is set and has not elapsed.
            Some(prior) => {
                if mode == NotifyMode::Once {
                    return Speak::Stay;
                }
                if let (Some(period), Some(last)) = (policy.repeat_after(), prior.at) {
                    if now.duration_since(last) < period {
                        return Speak::Stay;
                    }
                }
                prior.at = Some(now);
                Speak::Say { replaces: prior.id }
            }
            None => {
                self.seen.insert(
                    key,
                    Announced {
                        id: None,
                        at: Some(now),
                    },
                );
                Speak::Say { replaces: None }
            }
        }
    }

    /// Record the id the daemon returned for `block`'s notification, so the next repeat of that problem
    /// replaces this toast rather than adding one. A no-op for a sink with no ids (stderr).
    pub(crate) fn record_id(&mut self, block: &Block, id: u32) {
        let entry = self
            .seen
            .entry(block.key())
            .or_insert(Announced { id: None, at: None });
        entry.id = Some(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block for `event` about `subject`, refused for `reason`.
    fn block(event: NotifyEvent, subject: &str, reason: &str) -> Block {
        Block {
            event,
            subject: subject.to_string(),
            reason: reason.to_string(),
            detail: String::new(),
            fix: String::new(),
        }
    }

    #[test]
    fn every_event_name_round_trips_and_is_its_config_section() {
        for e in NotifyEvent::ALL {
            assert_eq!(NotifyEvent::parse(e.as_str()), Some(e));
        }
        // The names are the config sections that govern each refusal — the property that makes an
        // event name tell its reader where to go and change it.
        assert_eq!(
            NotifyEvent::ALL.map(|e| e.as_str()),
            ["network", "proc", "ssh_agent", "task", "trust"]
        );
        assert_eq!(NotifyEvent::parse("egress"), None, "no second vocabulary");
        assert_eq!(
            NotifyEvent::parse("ssh-agent"),
            None,
            "the section is `ssh_agent`"
        );
    }

    #[test]
    fn every_mode_round_trips_and_an_unknown_one_is_rejected() {
        for m in [NotifyMode::Off, NotifyMode::Once, NotifyMode::Always] {
            assert_eq!(NotifyMode::parse(m.as_str()), Some(m));
        }
        assert_eq!(NotifyMode::parse("one"), None);
        assert_eq!(NotifyMode::parse("true"), None);
    }

    #[test]
    fn each_event_occupies_its_own_slot() {
        // A duplicated `index()` would make two events share a mode — one would silently follow the
        // other's setting.
        let mut policy = NotifyPolicy::uniform(NotifyMode::Off);
        for e in NotifyEvent::ALL {
            policy = policy.with_event(e, NotifyMode::Always);
        }
        for e in NotifyEvent::ALL {
            assert_eq!(policy.mode_for(e), NotifyMode::Always);
        }
        let one =
            NotifyPolicy::uniform(NotifyMode::Off).with_event(NotifyEvent::Proc, NotifyMode::Once);
        assert_eq!(one.mode_for(NotifyEvent::Proc), NotifyMode::Once);
        for e in NotifyEvent::ALL.iter().filter(|e| **e != NotifyEvent::Proc) {
            assert_eq!(one.mode_for(*e), NotifyMode::Off, "{e:?} must be untouched");
        }
    }

    #[test]
    fn the_default_policy_announces_every_occurrence() {
        let policy = NotifyPolicy::default();
        for e in NotifyEvent::ALL {
            assert_eq!(policy.mode_for(e), NotifyMode::Always);
        }
        assert!(policy.any_enabled());
        assert!(!NotifyPolicy::uniform(NotifyMode::Off).any_enabled());
    }

    #[test]
    fn once_says_a_problem_a_single_time() {
        let policy = NotifyPolicy::uniform(NotifyMode::Once);
        let mut c = Coalescer::default();
        let b = block(
            NotifyEvent::Network,
            "api.example.com:443",
            "denied-default",
        );
        assert_eq!(
            c.decide(policy, &b, Instant::now()),
            Speak::Say { replaces: None }
        );
        assert_eq!(c.decide(policy, &b, Instant::now()), Speak::Stay);
        assert_eq!(c.decide(policy, &b, Instant::now()), Speak::Stay);
    }

    #[test]
    fn a_new_reason_for_the_same_subject_is_a_new_problem() {
        // The whole point of folding the reason into identity: a host refused by an explicit rule and
        // the same host refused because nothing allowed it have different fixes, so hiding the second
        // behind the first would send its reader to the wrong place.
        let policy = NotifyPolicy::uniform(NotifyMode::Once);
        let mut c = Coalescer::default();
        let host = "api.example.com:443";
        assert_eq!(
            c.decide(
                policy,
                &block(NotifyEvent::Network, host, "denied-default"),
                Instant::now()
            ),
            Speak::Say { replaces: None }
        );
        assert_eq!(
            c.decide(
                policy,
                &block(NotifyEvent::Network, host, "denied-by-rule"),
                Instant::now()
            ),
            Speak::Say { replaces: None }
        );
        // …and the same subject under a different lens is different again.
        assert_eq!(
            c.decide(
                policy,
                &block(NotifyEvent::Proc, host, "denied-default"),
                Instant::now()
            ),
            Speak::Say { replaces: None }
        );
    }

    #[test]
    fn always_updates_one_notification_rather_than_stacking() {
        let policy = NotifyPolicy::uniform(NotifyMode::Always);
        let mut c = Coalescer::default();
        let b = block(
            NotifyEvent::Network,
            "api.example.com:443",
            "denied-default",
        );
        assert_eq!(
            c.decide(policy, &b, Instant::now()),
            Speak::Say { replaces: None }
        );
        // Without an id from the daemon there is nothing to replace, but it still speaks.
        assert_eq!(
            c.decide(policy, &b, Instant::now()),
            Speak::Say { replaces: None }
        );
        c.record_id(&b, 42);
        assert_eq!(
            c.decide(policy, &b, Instant::now()),
            Speak::Say { replaces: Some(42) }
        );
        // A *different* problem is its own notification, never a replacement of this one.
        assert_eq!(
            c.decide(
                policy,
                &block(
                    NotifyEvent::Network,
                    "other.example.com:443",
                    "denied-default"
                ),
                Instant::now()
            ),
            Speak::Say { replaces: None }
        );
    }

    #[test]
    fn a_quiet_period_spaces_out_repeats_of_one_problem() {
        // `always` revises the notification already on screen, so a burst is free — but an agent
        // retrying for an hour keeps putting it back in front of its reader, and that is the spam a
        // period is for. Driven by advancing a clock, never by waiting.
        let policy = NotifyPolicy::uniform(NotifyMode::Always)
            .with_repeat_after(Some(Duration::from_secs(300)));
        let mut c = Coalescer::default();
        let b = block(
            NotifyEvent::Network,
            "api.example.com:443",
            "denied-default",
        );
        let t0 = Instant::now();

        assert_eq!(c.decide(policy, &b, t0), Speak::Say { replaces: None });
        // Inside the period: the refusal still happens and is still logged, it is simply not
        // announced again.
        assert_eq!(
            c.decide(policy, &b, t0 + Duration::from_secs(1)),
            Speak::Stay
        );
        assert_eq!(
            c.decide(policy, &b, t0 + Duration::from_secs(299)),
            Speak::Stay
        );
        // Past it: said again, because it is still happening.
        assert_eq!(
            c.decide(policy, &b, t0 + Duration::from_secs(301)),
            Speak::Say { replaces: None }
        );
        // …and the clock restarts from that announcement, not from the first one.
        assert_eq!(
            c.decide(policy, &b, t0 + Duration::from_secs(400)),
            Speak::Stay
        );

        // A *different* problem is never held back by another's period.
        assert_eq!(
            c.decide(
                policy,
                &block(
                    NotifyEvent::Network,
                    "other.example.com:443",
                    "denied-default"
                ),
                t0 + Duration::from_secs(2)
            ),
            Speak::Say { replaces: None }
        );
    }

    #[test]
    fn a_quiet_period_does_not_resurrect_once() {
        // `once` says a problem a single time whatever the period says — the period spaces repeats
        // out, it does not create them.
        let policy =
            NotifyPolicy::uniform(NotifyMode::Once).with_repeat_after(Some(Duration::from_secs(1)));
        let mut c = Coalescer::default();
        let b = block(
            NotifyEvent::Network,
            "api.example.com:443",
            "denied-default",
        );
        let t0 = Instant::now();
        assert_eq!(c.decide(policy, &b, t0), Speak::Say { replaces: None });
        assert_eq!(
            c.decide(policy, &b, t0 + Duration::from_secs(3600)),
            Speak::Stay
        );
    }

    #[test]
    fn off_stays_quiet_even_for_a_first_occurrence() {
        let policy = NotifyPolicy::uniform(NotifyMode::Always)
            .with_event(NotifyEvent::Task, NotifyMode::Off);
        let mut c = Coalescer::default();
        assert_eq!(
            c.decide(
                policy,
                &block(NotifyEvent::Task, "deploy", "refused"),
                Instant::now()
            ),
            Speak::Stay
        );
        assert_eq!(
            c.decide(
                policy,
                &block(
                    NotifyEvent::Network,
                    "api.example.com:443",
                    "denied-default"
                ),
                Instant::now()
            ),
            Speak::Say { replaces: None }
        );
    }

    #[test]
    fn an_origin_names_the_app_the_project_and_the_pid() {
        // A bare `sbx run`: the project and the pid, which is the pair that identifies a session in
        // `sbx session ls`.
        let bare = Origin {
            app: String::new(),
            project: "ops-cli".into(),
            pid: 4242,
        };
        assert_eq!(bare.label(), "ops-cli[4242]");

        // An app launch adds which app it was — several projects can run the same one, so the
        // project stays.
        let app = Origin {
            app: "kiro".into(),
            project: "ops-cli".into(),
            pid: 4242,
        };
        assert_eq!(app.label(), "kiro@ops-cli[4242]");

        // Whatever is absent is left out rather than rendered as an empty slot.
        assert_eq!(
            Origin {
                app: String::new(),
                project: String::new(),
                pid: 7,
            }
            .label(),
            "[7]"
        );
        assert_eq!(Origin::default().label(), "");
    }

    #[test]
    fn the_summary_names_the_session_a_refusal_came_from() {
        // Which sandbox it was rides the summary, not the body: with two or three running at once
        // that is the first question, and the summary is what a toast shows first and never cuts.
        let b = block(
            NotifyEvent::Network,
            "api.example.com:443",
            "denied-default",
        );
        let (summary, body) = b.render("kiro@ops-cli[4242]");
        assert_eq!(
            summary,
            "sbx blocked a network request · kiro@ops-cli[4242]"
        );
        assert_eq!(
            body, "api.example.com:443",
            "the body is unchanged by context"
        );

        // With nothing to name, the summary is the headline alone — never a trailing separator.
        assert_eq!(b.render("").0, "sbx blocked a network request");
    }

    #[test]
    fn a_rendered_block_leads_with_the_subject_and_carries_its_fix() {
        let b = Block {
            event: NotifyEvent::Network,
            subject: "api.example.com:443".to_string(),
            reason: "denied-default".to_string(),
            detail: "no rule in the network policy allows this host".to_string(),
            fix: "sbx net allow api.example.com".to_string(),
        };
        let (summary, body) = b.render("");
        assert_eq!(summary, "sbx blocked a network request");
        assert_eq!(
            body,
            "api.example.com:443 — no rule in the network policy allows this host \
             · allow it: sbx net allow api.example.com"
        );
        // No newline anywhere: a daemon that flattens one would run the sentence into the
        // suggestion, which is how "…allows this host allow it: …" reads on a real desktop.
        assert!(
            !body.contains('\n'),
            "the body must not rely on a newline: {body:?}"
        );

        // A refusal with no sound fix to offer says only what happened.
        let bare = block(NotifyEvent::Proc, "/usr/bin/curl", "denied-by-rule");
        assert_eq!(bare.render("").1, "/usr/bin/curl");
    }

    #[test]
    fn identity_cannot_be_forged_by_a_subject_carrying_the_separator() {
        // The key joins three fields; a subject that itself contained the separator could otherwise
        // collide with a different (event, subject, reason) triple and silence it.
        let a = block(NotifyEvent::Network, "a", "b\u{1f}c");
        let b = block(NotifyEvent::Network, "a\u{1f}b", "c");
        assert_ne!(a.key(), b.key(), "distinct triples must not share a key");
    }
}
