//! The host-side credential the proxy injects into an allowed request, and the outbound-leak
//! needle it refuses to let leave the cage verbatim. Both hold a secret's value, so both carry a
//! redacted `Debug` — the value must never reach a log or a panic message.

use std::fmt;

use crate::allowlist::Rule;

/// A resolved credential the proxy injects into requests matching its host/path rule. The
/// value is the **fully-formed header value** — the plaintext was read host-side and shaped
/// before this was built, so the proxy never touches the source. Injection happens only
/// after a request is ALLOWED, and only when `rule` matches the verified CONNECT host and the
/// decrypted path, so the secret reaches exactly one known destination.
#[derive(Clone)]
pub(crate) struct HeaderInjection {
    /// The concrete host/path the secret is scoped to (an `Ip`/`Host`/`Url` rule).
    pub(crate) rule: Rule,
    /// The header name to set.
    pub(crate) header: String,
    /// The fully-formed header value (`prefix` + plaintext, or `Basic <base64>`).
    pub(crate) value: String,
}

// A manual `Debug` that redacts the value — the formed header carries the secret, so it must
// never reach a log or a panic message.
impl fmt::Debug for HeaderInjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderInjection")
            .field("rule", &self.rule)
            .field("header", &self.header)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// A configured secret's value the proxy refuses to let leave the cage verbatim in an outbound
/// request head — the egress leak tripwire. Held as raw bytes so the byte-substring scan matches
/// whatever spelling reaches the wire (the plaintext, or its base64 form for Basic). Its `Debug`
/// is redacted so the value can never reach a log or a panic message.
///
/// It also carries the credential's **logical name**, which the wire path ignores (it substitutes
/// length-preserving `*`) and a text sink uses to render `${name}` — one needle set, two
/// renderings. The name is a label, never secret, so `Debug` shows it: it is what makes a redacted
/// `Debug` line diagnosable.
#[derive(Clone)]
pub(crate) struct SecretNeedle {
    name: String,
    bytes: Vec<u8>,
    /// The substring searcher for `bytes`, built once with the needle rather than per scan.
    ///
    /// It is here rather than at the call sites because the scan is not a one-off: a response body
    /// from an injection-target host is scanned chunk by chunk for as long as it streams, so a
    /// searcher rebuilt per chunk would pay its setup on every read. Measured on this machine, the
    /// searcher moves ~56 GiB/s against ~470 MiB/s for a naive substring walk — two orders of
    /// magnitude, which is the difference between the scan being invisible next to the relay's own
    /// copy and being the thing that caps its throughput.
    finder: memchr::memmem::Finder<'static>,
}

impl SecretNeedle {
    /// A needle whose name is the credential's logical name.
    pub(crate) fn named(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        let finder = memchr::memmem::Finder::new(&bytes).into_owned();
        Self {
            name: name.into(),
            bytes,
            finder,
        }
    }

    /// The needle bytes — used by the scan, and by the egress tests to confirm a needle was
    /// derived. Deliberately a named method, never `Debug`, so it is only ever read explicitly.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The offset of this needle's first occurrence in `haystack` at or after `from`, if any.
    pub(crate) fn find_in(&self, haystack: &[u8], from: usize) -> Option<usize> {
        if self.bytes.is_empty() || from > haystack.len() {
            return None;
        }
        self.finder.find(&haystack[from..]).map(|at| from + at)
    }

    /// The credential's logical name, for the `${name}` rendering on a text sink.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Debug for SecretNeedle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecretNeedle({}, <redacted {} bytes>)",
            self.name,
            self.bytes.len()
        )
    }
}

/// One resolved credential state: the header injections the proxy applies, and the needles its
/// tripwires scan for. They are one type rather than two fields because they are two renderings of
/// the *same* resolved plaintexts — a needle set that does not match the values being injected is
/// worse than none, since the stale value stays tripwired while the live one crosses unwatched.
/// Holding them together makes that pairing structural instead of a rule someone must remember.
pub(crate) struct CredentialSet {
    pub(crate) injections: Vec<HeaderInjection>,
    pub(crate) needles: Vec<SecretNeedle>,
}

/// The live credential state, shared by every consumer that scans or injects: the HTTP/1.1 path, the
/// HTTP/2 path, and the capture ring's masking. A credential can be re-resolved mid-session (an
/// access token the upstream has expired), so this is read through a snapshot rather than borrowed.
///
/// Copy-on-write rather than a plain `RwLock<CredentialSet>`: the read side is the proxy's hottest
/// loop — every request head, every response chunk — and a reader that had to clone the needles
/// would pay for their bytes on each pass, while one holding a guard across a streaming body would
/// block the refresh for as long as the body runs. Swapping an `Arc` costs a refcount either way,
/// and a reader keeps a coherent set for the whole exchange even if a refresh lands mid-flight.
pub(crate) struct Credentials {
    current: std::sync::RwLock<std::sync::Arc<CredentialSet>>,
}

impl Credentials {
    /// The state as first resolved, host-side, before the cage started.
    pub(crate) fn new(injections: Vec<HeaderInjection>, needles: Vec<SecretNeedle>) -> Self {
        Self {
            current: std::sync::RwLock::new(std::sync::Arc::new(CredentialSet {
                injections,
                needles,
            })),
        }
    }

    /// The set to use for one exchange. Take it once and keep it: re-reading mid-exchange could
    /// inject one credential and scan for another.
    ///
    /// A poisoned lock falls back to an empty set rather than panicking, which fails *closed* for
    /// injection (no credential is applied) and open for redaction (nothing is scanned) — the same
    /// asymmetry the tripwires already carry, and unreachable in practice since no code panics
    /// while holding this lock.
    pub(crate) fn snapshot(&self) -> std::sync::Arc<CredentialSet> {
        match self.current.read() {
            Ok(set) => set.clone(),
            Err(_) => std::sync::Arc::new(CredentialSet {
                injections: Vec::new(),
                needles: Vec::new(),
            }),
        }
    }

    /// Install a newly resolved state. Exchanges already in flight keep the snapshot they took, so
    /// a refresh never changes what a running request injects halfway through.
    pub(crate) fn replace(&self, set: CredentialSet) {
        if let Ok(mut current) = self.current.write() {
            *current = std::sync::Arc::new(set);
        }
    }
}

/// How a credential is re-resolved, host-side, when the upstream says the one being injected is no
/// longer good. A closure rather than a call into the resolver because *what* a credential resolves
/// from belongs to the launch (sources, project root, the `bwrap` to sandbox a plugin with) and
/// *when* to ask again belongs to the proxy — this is the seam between the two.
pub(crate) type Refresher =
    Box<dyn Fn() -> std::io::Result<(Vec<HeaderInjection>, Vec<SecretNeedle>)> + Send + Sync>;

/// The minimum wall-clock gap between two refresh attempts. A refresh is a resolver run, which for a
/// plugin source is a bwrap spawn plus whatever the plugin itself does, so an upstream answering
/// `401` to every request must not turn each one into that. The gap is what makes a broken
/// credential cost a bounded trickle instead of a storm.
const MIN_REFRESH_GAP: std::time::Duration = std::time::Duration::from_secs(30);

/// Re-resolution of the injected credentials, triggered by the upstream refusing the current one.
///
/// The trigger is a `401` rather than a declared expiry: an expiry is a claim about a clock this
/// process does not own, while a `401` is the destination itself saying the credential is no longer
/// accepted. It also covers the cases an expiry cannot — a revoked token, a rotated secret, a
/// session invalidated elsewhere.
///
/// Three bounds keep a hopeless credential from spinning: no attempt within [`MIN_REFRESH_GAP`] of
/// the last, a hard stop once an attempt fails outright (the source is broken, not stale), and a
/// hard stop when a successful re-resolution returns *the same value* — the upstream refused that
/// value, so re-sending it would only refuse again.
pub(crate) struct CredentialRefresh {
    refresher: Refresher,
    credentials: std::sync::Arc<Credentials>,
    state: std::sync::Mutex<RefreshState>,
}

#[derive(Default)]
struct RefreshState {
    last_attempt: Option<std::time::Instant>,
    stopped: bool,
}

impl CredentialRefresh {
    pub(crate) fn new(credentials: std::sync::Arc<Credentials>, refresher: Refresher) -> Self {
        Self {
            refresher,
            credentials,
            state: std::sync::Mutex::new(RefreshState::default()),
        }
    }

    /// Re-resolve after an upstream refusal, and report whether the credential state actually
    /// changed. `false` covers every no-op: too soon, already given up, the source failed, or the
    /// value came back identical.
    ///
    /// The caller has already established that the refusing host carries an injection, so this does
    /// not re-check it: an unrelated `401` from some other allowed host must never spend a resolver
    /// run.
    pub(crate) fn on_refusal(&self) -> bool {
        {
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(_) => return false,
            };
            if state.stopped {
                return false;
            }
            if let Some(last) = state.last_attempt
                && last.elapsed() < MIN_REFRESH_GAP
            {
                return false;
            }
            state.last_attempt = Some(std::time::Instant::now());
        }

        let (injections, needles) = match (self.refresher)() {
            Ok(resolved) => resolved,
            // A source that errors is broken rather than stale; retrying on a timer would only
            // repeat it. Stop, and let the launch's own error path be what the user sees.
            Err(_) => {
                if let Ok(mut state) = self.state.lock() {
                    state.stopped = true;
                }
                return false;
            }
        };

        let current = self.credentials.snapshot();
        if same_values(&current.injections, &injections) {
            if let Ok(mut state) = self.state.lock() {
                state.stopped = true;
            }
            return false;
        }
        self.credentials.replace(CredentialSet {
            injections,
            needles,
        });
        true
    }
}

/// Whether two injection sets carry the same values for the same headers — the test for "the source
/// gave us back what the upstream just refused". Compared in full rather than by length so a set
/// that changed shape counts as new.
fn same_values(a: &[HeaderInjection], b: &[HeaderInjection]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x.header == y.header && x.value == y.value)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    // The formed header value carries the plaintext secret, so its `Debug` must never leak it — the
    // redacted `Debug` is the guard that keeps a secret out of a log line or a panic message.
    #[test]
    fn header_injection_debug_redacts_the_value() {
        let injection = HeaderInjection {
            rule: crate::allowlist::classify("api.example.com").unwrap(),
            header: "x-api-key".to_string(),
            value: "SECRET-TOKEN-abc123".to_string(),
        };
        let shown = format!("{injection:?}");
        assert!(
            !shown.contains("SECRET-TOKEN-abc123"),
            "the secret value must never appear in Debug output: {shown}"
        );
        assert!(
            shown.contains("<redacted>"),
            "the value must render as <redacted>: {shown}"
        );
        // the non-secret fields stay visible, so the Debug is still useful for diagnosis.
        assert!(
            shown.contains("x-api-key"),
            "the header name is kept: {shown}"
        );
    }

    // An exchange decides once which credentials it is working with. A refresh landing mid-flight
    // must not make a request inject one value while its tripwire scans for another: the snapshot a
    // reader already took stays whole, and only the next reader sees the new state.
    #[test]
    fn a_snapshot_survives_a_replacement_and_the_next_reader_sees_the_new_state() {
        let creds = Credentials::new(
            vec![HeaderInjection {
                rule: crate::allowlist::classify("api.example.com").unwrap(),
                header: "authorization".to_string(),
                value: "Bearer first".to_string(),
            }],
            vec![SecretNeedle::named("tok", b"first".to_vec())],
        );

        let held = creds.snapshot();
        creds.replace(CredentialSet {
            injections: vec![HeaderInjection {
                rule: crate::allowlist::classify("api.example.com").unwrap(),
                header: "authorization".to_string(),
                value: "Bearer second".to_string(),
            }],
            needles: vec![SecretNeedle::named("tok", b"second".to_vec())],
        });

        assert_eq!(
            held.injections[0].value, "Bearer first",
            "an exchange in flight keeps the state it started with"
        );
        assert_eq!(
            held.needles[0].as_bytes(),
            b"first",
            "and its needle matches that same state, never the newer one"
        );

        let fresh = creds.snapshot();
        assert_eq!(fresh.injections[0].value, "Bearer second");
        assert_eq!(fresh.needles[0].as_bytes(), b"second");
    }

    fn injection(value: &str) -> HeaderInjection {
        HeaderInjection {
            rule: crate::allowlist::classify("api.example.com").unwrap(),
            header: "authorization".to_string(),
            value: value.to_string(),
        }
    }

    /// A refresh replaces both halves at once, and the value the proxy will inject next is the new
    /// one. This is the whole point of the mechanism: an upstream that refused the old credential
    /// gets the re-resolved one on the following request.
    #[test]
    fn a_refusal_re_resolves_and_the_next_snapshot_carries_the_new_value() {
        let creds = Arc::new(Credentials::new(
            vec![injection("Bearer old")],
            vec![SecretNeedle::named("tok", b"old".to_vec())],
        ));
        let refresh = CredentialRefresh::new(
            creds.clone(),
            Box::new(|| {
                Ok((
                    vec![injection("Bearer new")],
                    vec![SecretNeedle::named("tok", b"new".to_vec())],
                ))
            }),
        );

        assert!(refresh.on_refusal(), "a first refusal re-resolves");
        let set = creds.snapshot();
        assert_eq!(set.injections[0].value, "Bearer new");
        assert_eq!(
            set.needles[0].as_bytes(),
            b"new",
            "the needle moved with the value it protects"
        );
    }

    /// An upstream answering `401` to every request must not turn each one into a resolver run. The
    /// second refusal inside the gap is a no-op, and the source is not consulted again.
    #[test]
    fn a_second_refusal_inside_the_gap_does_not_consult_the_source() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        let creds = Arc::new(Credentials::new(vec![injection("Bearer old")], Vec::new()));
        let refresh = CredentialRefresh::new(
            creds.clone(),
            Box::new(move || {
                let n = seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok((vec![injection(&format!("Bearer v{n}"))], Vec::new()))
            }),
        );

        assert!(refresh.on_refusal());
        assert!(!refresh.on_refusal(), "the second is inside the gap");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the source is consulted once, not per refusal"
        );
    }

    /// Re-resolving to the value the upstream just refused proves the source has nothing newer.
    /// Retrying on a timer would refuse again forever, so the mechanism gives up for good.
    #[test]
    fn an_unchanged_value_stops_the_mechanism_for_good() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        let creds = Arc::new(Credentials::new(vec![injection("Bearer same")], Vec::new()));
        let refresh = CredentialRefresh::new(
            creds,
            Box::new(move || {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok((vec![injection("Bearer same")], Vec::new()))
            }),
        );

        assert!(!refresh.on_refusal(), "an identical value is not a refresh");
        assert!(!refresh.on_refusal(), "and it does not try again");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A source that errors is broken rather than stale. Stop, rather than repeat the failure on a
    /// timer for the rest of the session.
    #[test]
    fn a_failing_source_stops_the_mechanism_for_good() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        let creds = Arc::new(Credentials::new(vec![injection("Bearer old")], Vec::new()));
        let refresh = CredentialRefresh::new(
            creds.clone(),
            Box::new(move || {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err(std::io::Error::other("the vault is unreachable"))
            }),
        );

        assert!(!refresh.on_refusal());
        assert!(!refresh.on_refusal());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            creds.snapshot().injections[0].value,
            "Bearer old",
            "a failed refresh leaves the current credential in place"
        );
    }

    // The needle holds a secret to scan the wire for; its `Debug` reports only the byte length, never
    // the value, and `as_bytes` returns the raw bytes the outbound scan matches against.
    #[test]
    fn secret_needle_debug_redacts_the_value_but_reports_its_length() {
        let secret = b"SECRET-TOKEN-abc123";
        let needle = SecretNeedle::named("test-secret", secret.to_vec());
        assert_eq!(needle.as_bytes(), secret);
        let shown = format!("{needle:?}");
        assert!(
            !shown.contains("SECRET-TOKEN"),
            "the secret must never appear in Debug output: {shown}"
        );
        assert!(
            shown.contains(&format!("{} bytes", secret.len())),
            "the redacted Debug reports the byte length: {shown}"
        );
    }
}
