//! The host-side credential the proxy injects into an allowed request, and the outbound-leak
//! needle it refuses to let leave the cage verbatim. Both hold a secret's value, so both carry a
//! redacted `Debug` — the value must never reach a log or a panic message.

use std::fmt;

use crate::allowlist::Rule;

/// A resolved credential the proxy injects into requests matching its host/path rule. Injection
/// happens only after a request is ALLOWED, and only when `rule` matches the verified CONNECT host
/// and the decrypted path, so the credential reaches exactly one known destination.
#[derive(Clone)]
pub(crate) struct HeaderInjection {
    /// The concrete host/path the secret is scoped to (an `Ip`/`Host`/`Url` rule).
    pub(crate) rule: Rule,
    /// How the headers it puts on a request come to be.
    pub(crate) form: Form,
}

/// The two ways a credential becomes headers on a request.
///
/// They are one type rather than two injection kinds because everything else about them is the
/// same: both are scoped to one rule, both are selected by the same match, both partition the
/// upstream pool, and both must be named to [`Credentials::observe_head`] so the header they
/// replace is not remembered as the cage's own. What differs is *when* the value exists.
#[derive(Clone)]
pub(crate) enum Form {
    /// One header, formed once host-side from the resolved plaintext, before any request existed.
    /// Every auth point whose value is a constant.
    Fixed { header: String, value: String },
    /// Headers computed per request by a signer plugin. The auth points a fixed value cannot
    /// express: a signature over the request, a per-request nonce, a challenge answered in kind.
    Signed(Signed),
}

/// A signer plugin bound to one credential declaration, and the material it was started with.
#[derive(Clone)]
pub(crate) struct Signed {
    /// The plugin's name, for the record and for a refusal that has to say who refused.
    pub(crate) name: String,
    /// The headers the plugin's manifest declared it may set. Known without asking it, which is
    /// what keeps the *selection* of injections pure: which headers a request will carry is
    /// answerable before any plugin runs, and only their values are not.
    pub(crate) sets: Vec<String>,
    /// The request headers the plugin is shown, beyond the method, host, port and target.
    pub(crate) sees: Vec<String>,
    /// The credential resolved at launch, held for one purpose: it is this injection's
    /// **resolve-time material**, which is what a re-resolution has to differ in for a refresh to
    /// mean anything. The plugin received it (or a marker for it) at its handshake; nothing here
    /// puts it on a wire.
    pub(crate) key: String,
    /// The marker standing in for the credential, when the plugin was not given the value itself.
    /// sbx substitutes it into the plugin's own headers on their way to the wire, so the plugin can
    /// place a credential it never learns.
    pub(crate) marker: Option<std::sync::Arc<super::super::broker::SecretMarker>>,
    /// The running plugin, serialized: it is one process answering one question at a time, and a
    /// launch may have many requests in flight.
    pub(crate) process: std::sync::Arc<std::sync::Mutex<dyn crate::sandbox::signer::Signing>>,
    /// The digest this plugin's manifest asked for over the request body, if any. Read *before* the
    /// plugin runs, because it decides whether the caller holds the body at all — which is a choice
    /// about how the request is forwarded, not about how it is signed.
    pub(crate) body_digest: Option<crate::plugins::signer::BodyDigest>,
}

impl HeaderInjection {
    /// One header, formed once host-side from the resolved plaintext.
    pub(crate) fn fixed(rule: Rule, header: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            rule,
            form: Form::Fixed {
                header: header.into(),
                value: value.into(),
            },
        }
    }

    /// The formed value of a fixed injection, for the tests that assert what reaches the wire.
    ///
    /// A signed injection has no such value, and this panics rather than returning an empty one: a
    /// test asserting on a value that does not exist would pass while checking nothing.
    #[cfg(test)]
    pub(crate) fn value(&self) -> &str {
        match &self.form {
            Form::Fixed { value, .. } => value,
            Form::Signed(signed) => {
                panic!(
                    "`{}` signs per request: there is no formed value",
                    signed.name
                )
            }
        }
    }

    /// Whether a `401` from this credential's destination is worth re-resolving on.
    ///
    /// A fixed value can go stale: the upstream refusing it is the destination saying so, and a
    /// fresh resolution may carry a new one. A signed one cannot. There is no token to refresh —
    /// the value is computed per request — so a re-resolution would hand the same key to a newly
    /// spawned plugin cage, once per refusal, for the life of the session.
    pub(crate) fn refreshable(&self) -> bool {
        matches!(self.form, Form::Fixed { .. })
    }

    /// The header names this injection **may** put on a request, answerable without running
    /// anything: the declaration's own, which for a signer is its manifest's `sets_headers`.
    ///
    /// May, not will. A signer decides per request, so what it actually set is read off the formed
    /// pairs instead ([`super::injected_names`]) wherever the difference matters — skipping a
    /// header nothing replaced would leave a credential the cage sent for itself unlearned. This
    /// answers the question that is about the declaration alone: whether two resolutions describe
    /// the same set of headers ([`same_values`]).
    pub(crate) fn header_names(&self) -> Vec<&str> {
        match &self.form {
            Form::Fixed { header, .. } => vec![header.as_str()],
            Form::Signed(signed) => signed.sets.iter().map(String::as_str).collect(),
        }
    }

    /// What a re-resolution has to differ in for a refresh to be worth installing.
    ///
    /// For a fixed injection this is the formed value, which is what the upstream refused. For a
    /// signed one it is the **key**, not the signature: a signature is a function of the request,
    /// so comparing two of them would compare two different requests and always differ — the
    /// refresh's "the source gave back what was just refused" stop would never fire again, and a
    /// host answering `401` forever would spend a resolver run every thirty seconds for the life
    /// of the session.
    fn material(&self) -> &str {
        match &self.form {
            Form::Fixed { value, .. } => value,
            Form::Signed(signed) => &signed.key,
        }
    }
}

// A manual `Debug` that redacts the value — the formed header carries the secret, so it must
// never reach a log or a panic message.
impl fmt::Debug for HeaderInjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("HeaderInjection");
        s.field("rule", &self.rule);
        match &self.form {
            Form::Fixed { header, .. } => s.field("header", header).field("value", &"<redacted>"),
            Form::Signed(signed) => s
                .field("signer", &signed.name)
                .field("sets", &signed.sets)
                .field("key", &"<redacted>"),
        };
        s.finish()
    }
}

/// How a caller offers this request's headers to a signer, without any of them having to agree on
/// a representation. The two HTTP/1.1 paths hold a `Vec<(String, String)>` and the HTTP/2 path an
/// `http::HeaderMap`; a signer is shown a named subset of either.
pub(crate) trait HeaderLookup {
    /// The value of a header by case-insensitive name, if the request carries one.
    fn get(&self, name: &str) -> Option<&str>;

    /// Every value carried under this name, in arrival order.
    ///
    /// The two readings answer different questions, and a request that carries the same header
    /// twice is where they part. A signer is shown one value, because it signs the request the
    /// upstream will read and a duplicated credential header is not a shape a signature has an
    /// answer for. [`Credentials::observe_head`] takes them all: what it is asked is whether the
    /// cage sent a credential, and a client library that adds a default `Authorization` beside an
    /// explicit one sent two. Keeping only the first leaves the other unmasked in a capture and in
    /// `sbx net logs --with-headers`, which is the exposure observing exists to close.
    fn for_each(&self, name: &str, f: &mut dyn FnMut(&str));
}

impl HeaderLookup for Vec<(String, String)> {
    fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn for_each(&self, name: &str, f: &mut dyn FnMut(&str)) {
        for (_, value) in self.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)) {
            f(value);
        }
    }
}

/// One request, in the terms an injection needs to form its headers. Only a signed injection reads
/// any of it; a fixed one was formed before the request existed.
pub(crate) struct RequestFacts<'a> {
    pub(crate) method: &'a str,
    pub(crate) host: &'a str,
    pub(crate) port: u16,
    /// The request target as it goes on the wire: the path with its query.
    pub(crate) target: &'a str,
    pub(crate) headers: &'a dyn HeaderLookup,
    /// What the caller established about the request body, where a matched signer asked for it (see
    /// [`CredentialSet::wants_body_digest`]). `None` where nothing asked — and a signer that did ask
    /// then refuses the request rather than signing it as though the body were empty.
    pub(crate) body: Option<&'a crate::sandbox::signer::BodyFacts>,
}

/// Why a request could not be given its credential. Carried rather than logged here, so the caller
/// records the refusal on the same chokepoint every other refusal passes through.
pub(crate) struct SignRefusal {
    /// The plugin that could not sign, named because a refusal that does not say who refused
    /// leaves the user auditing every declaration.
    pub(crate) signer: String,
    pub(crate) why: String,
}

/// The `(header, value)` pairs a request's matched injections put on it.
///
/// Fixed injections contribute what they were formed with. A signed one asks its plugin, once per
/// request, and **any failure refuses the request**: a request that could not be signed is never
/// sent unsigned, since it would arrive at the destination as an anonymous one and come back an
/// authentication error for a reason that has nothing to do with the credential.
///
/// `log` is the session's signer feed, where each answer and each refusal is recorded. It is passed
/// in rather than held on the injection because a credential refresh rebuilds every signed injection
/// from scratch (see [`super::CredentialRefresh`]): a ring carried on one would have to survive that
/// rebuild, and the feed would go quiet after the first refresh with every unit test still green.
/// `None` where no feed was stood up (the tests, and any launch that declares no signer).
///
/// One session's proxies share that feed — the agent's, and one per invocation of a declared
/// operation — but each records against **its own** needles, which are the ones in `creds` here.
/// That is the correct set and not an approximation: a plugin is told one credential, its own
/// declaration's, resolved by this very proxy, so the only value it could echo back is one these
/// needles cover. The exception is a credential under the launch's redaction floor, which has no
/// needle anywhere — the launch says so when it resolves it, and this record is no different from
/// the wire in that respect.
pub(crate) fn pairs_for(
    creds: &CredentialSet,
    ids: &[usize],
    req: &RequestFacts<'_>,
    log: Option<&crate::sandbox::signer_control::SignerRing>,
) -> Result<Vec<(String, String)>, SignRefusal> {
    use crate::sandbox::signer_control::SignerKind;

    let mut out = Vec::with_capacity(ids.len());
    for &i in ids {
        match &creds.injections[i].form {
            Form::Fixed { header, value } => out.push((header.clone(), value.clone())),
            Form::Signed(signed) => {
                let headers = signed
                    .sees
                    .iter()
                    .filter_map(|name| req.headers.get(name).map(|v| (name.clone(), v.to_string())))
                    .collect();
                // A plugin that asked for a body digest is never signed *around*: where the caller
                // established nothing, the request is refused rather than put to the plugin without
                // the fact its scheme was written to cover.
                let body = match signed.body_digest {
                    None => None,
                    Some(_) => match req.body {
                        Some(facts) => Some(facts),
                        None => {
                            return Err(SignRefusal {
                                signer: signed.name.clone(),
                                why: "sbx established nothing about this request's body, which \
                                      this plugin's manifest asks to be told"
                                    .to_string(),
                            });
                        }
                    },
                };
                let ask = crate::sandbox::signer::SignRequest {
                    method: req.method,
                    host: req.host,
                    port: req.port,
                    target: req.target,
                    headers,
                    body,
                };
                // A poisoned lock is a panic in another thread's `sign`, which is not a state to
                // sign in: refuse like any other failure rather than reach past it.
                let signed_headers = match signed.process.lock() {
                    Ok(mut process) => process.sign(&ask),
                    Err(_) => Err("the signer plugin is in an unusable state".to_string()),
                };
                // What sbx observed of this request, which leads every line on the feed. The values
                // are never in it — the header *names* are what a reader needs, and they are the
                // manifest's own.
                //
                // Built on demand rather than up front: both readers are inside an `if let
                // Some(log)`, so with no feed attached this allocated a string per request the
                // signer saw — refused ones included — and dropped each unread. A signer runs on
                // the request path, which is where that is worth not doing.
                let asked = || format!("{} {}{}", req.method, req.host, req.target);
                match signed_headers {
                    // The marker is substituted here and nowhere else: on the plugin's own bytes,
                    // on their way out, after they were bounded to the headers its manifest
                    // declared. A plugin that placed the marker gets the credential on the wire; it
                    // never learns what it was.
                    Ok(sig) => {
                        if let Some(log) = log {
                            let names: Vec<&str> =
                                sig.headers.iter().map(|(n, _)| n.as_str()).collect();
                            log.push(
                                SignerKind::Sign,
                                &signed.name,
                                &format!("{} set {}", asked(), names.join(", ")),
                                sig.label.as_deref(),
                                &creds.needles,
                            );
                        }
                        out.extend(sig.headers.into_iter().map(
                            |(name, value)| match &signed.marker {
                                Some(marker) => (name, marker.substitute_str(&value)),
                                None => (name, value),
                            },
                        ))
                    }
                    Err(why) => {
                        if let Some(log) = log {
                            log.push(
                                SignerKind::Refuse,
                                &signed.name,
                                &asked(),
                                Some(&why),
                                &creds.needles,
                            );
                        }
                        return Err(SignRefusal {
                            signer: signed.name.clone(),
                            why,
                        });
                    }
                }
            }
        }
    }
    Ok(out)
}

/// The form a learned needle's destination is recorded and compared under. It is the allowlist's
/// own [`canonical_host`](crate::allowlist::canonical_host) — the same normalization the verdict
/// applies to the host it just authorized — so the two sides cannot drift into disagreeing about
/// what one host is. Every caller passes a host that is already free of its port (the planes carry
/// host and port separately), and canonicalization settles case, a trailing dot, and an IP literal.
fn host_key(host: &str) -> String {
    crate::allowlist::canonical_host(host)
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
    /// The Knuth-Morris-Pratt failure table for `bytes`: `fail[i]` is the length of the longest
    /// proper prefix of `bytes[..=i]` that is also a suffix of it.
    ///
    /// It answers one question, [`Self::prefix_suffix_len`], and it is built with the needle for
    /// the same reason the searcher is: that question is asked once per read for as long as a
    /// response streams. Answering it by testing each candidate length in turn is quadratic in the
    /// needle, and the needle's *value* is chosen by the cage — an `Authorization` of 16 KiB of one
    /// repeated byte made the decision cost 1.4 ms per 64 KiB read against 22 us for the masking
    /// beside it, on a host thread outside the cage's own limits. With this table the walk is linear
    /// in the needle and there is no shape of value that is worse than another.
    fail: Vec<u32>,
    /// Whether this needle was **learned from traffic** rather than derived from a declaration.
    ///
    /// It decides what survives a re-resolution. A declared needle is replaced by the re-resolved
    /// value of the same declaration; an observed one has no declaration behind it, so nothing
    /// replaces it and dropping it is simply losing it — see [`Credentials::replace`].
    observed: bool,
    /// For a **learned** needle, the hosts it may travel to — its own service, lowercased and
    /// without a port. `None` for a declared one.
    ///
    /// The outbound tripwire skips a learned needle on a request bound for one of these, and only
    /// there. What the tripwire exists to stop is the cage taking a credential it acquired for one
    /// service and re-sending it to ANOTHER; scanning it on the way back to its own service refuses
    /// the app's own authenticated traffic instead, so an app that signs itself in cuts its own
    /// session off at the second request.
    ///
    /// It is a set rather than the one host sbx saw, because a service is not one host: an app that
    /// signs in on one name and calls its API on another would otherwise refuse its own traffic on
    /// the second name for the reason above. Which names belong together is not inferable — the
    /// registrable domains of a real pair differ — so it comes from the `[network]
    /// shared_credential` group containing the host it was learned on, and is that host alone when
    /// no group names it. A declared needle keeps `None` and is therefore scanned everywhere, which
    /// stays correct: the cage never holds a declared value in the first place, so its appearance
    /// anywhere — destination included — is a leak.
    dest: Option<Vec<String>>,
}

impl SecretNeedle {
    /// A needle whose name is the credential's logical name — for a value a declaration produced.
    pub(crate) fn named(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        let finder = memchr::memmem::Finder::new(&bytes).into_owned();
        let fail = failure_table(&bytes);
        Self {
            name: name.into(),
            bytes,
            finder,
            fail,
            observed: false,
            dest: None,
        }
    }

    /// A needle for a credential sbx **saw** rather than issued: an app's own sign-in, remembered by
    /// [`Credentials::observe`] so the tripwires cover it too. `service` is the host it was
    /// travelling to together with any the launch declared to share its credential, which
    /// [`Self::scanned_for`] then exempts — see the field's own note.
    fn learned(name: impl Into<String>, bytes: Vec<u8>, service: Vec<String>) -> Self {
        Self {
            observed: true,
            dest: Some(service),
            ..Self::named(name, bytes)
        }
    }

    /// The length of the longest suffix of `window` that is a **proper prefix** of this needle.
    ///
    /// What a streaming scan must hold back, and no more: a tail that spells the beginning of this
    /// needle may turn out to be it once the next read arrives, while a tail that spells no
    /// beginning cannot become one however the stream continues. Ordinary traffic ends in neither,
    /// so the usual answer is zero.
    ///
    /// Only the last `len - 1` bytes are walked, because the answer cannot be longer than that and a
    /// suffix of the window that short is a suffix of them too. Walking exactly that many is also
    /// what makes the result a *proper* prefix without testing for it: each byte advances the match
    /// by at most one from a start of zero, so `len - 1` bytes cannot reach `len`, and no full match
    /// is there to fall back from.
    pub(crate) fn prefix_suffix_len(&self, window: &[u8]) -> usize {
        let p = &self.bytes;
        if p.len() < 2 {
            // A single byte has no proper prefix, so nothing about it can straddle a read.
            return 0;
        }
        let from = window.len().saturating_sub(p.len() - 1);
        let mut matched = 0usize;
        for &b in &window[from..] {
            while matched > 0 && p[matched] != b {
                matched = self.fail[matched - 1] as usize;
            }
            if p[matched] == b {
                matched += 1;
            }
        }
        matched
    }

    /// Whether this needle was learned from traffic rather than declared.
    pub(crate) fn is_observed(&self) -> bool {
        self.observed
    }

    /// Whether the outbound tripwire scans for this needle on a request bound for `host`.
    ///
    /// True for every declared needle, and for a learned one everywhere except the hosts of the
    /// service it was learned on. The comparison is on the same normalized form both sides record
    /// ([`host_key`]), because an exemption that fails to match is invisible: the request is refused
    /// and the reason looks like the credential really did go somewhere it should not.
    pub(crate) fn scanned_for(&self, host: &str) -> bool {
        match &self.dest {
            None => true,
            Some(service) => {
                let host = host_key(host);
                !service
                    .iter()
                    .any(|entry| crate::allowlist::shared_credential_covers(entry, &host))
            }
        }
    }

    /// Whether the **operator's own record** of an exchange with `host` masks this needle: the
    /// traffic capture `sbx net logs` prints, and the request path that enters the event ring and
    /// the pending queue.
    ///
    /// A declared needle is masked everywhere. Its value was issued host-side and the cage never
    /// holds it, so wherever it appears it is a value the operator asked sbx to keep out of sight.
    ///
    /// A learned one is masked on the service it was learned on and nowhere else, which is
    /// [`Self::scanned_for`] read the other way round. The two questions have the same answer for
    /// the same reason: on its own service the value is the app's credential doing its job, so it
    /// is neither scanned as a leak nor printed in the record; anywhere else it is a leak, so it
    /// **is** scanned and it must stay legible in the record, which is where a reader goes to see
    /// where it went.
    ///
    /// The asymmetry matters because a learned needle's bytes are the cage's to choose. It sends a
    /// value in an auth header and the proxy remembers it, so masking learned needles across the
    /// whole record would hand a cage a small budget of arbitrary strings it could make disappear
    /// from what the operator reads, with the seeding request looking exactly like an
    /// authenticated one. Bounded to its own service, that budget buys the cage nothing it did not
    /// already have: bytes it sent to the host it sent them to.
    pub(crate) fn masks_record_for(&self, host: &str) -> bool {
        !self.observed || !self.scanned_for(host)
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

impl CredentialSet {
    /// The digest a matched signer asks to be told over this request's body, if one does.
    ///
    /// Answered from the manifests alone, before any plugin runs, because the answer decides how the
    /// request is *forwarded*: a body sbx must digest is one it holds rather than streams, and that
    /// choice is made before the head goes out. There is one body, and it is held and digested once
    /// however many matched injections ask about it.
    pub(crate) fn wants_body_digest(
        &self,
        ids: &[usize],
    ) -> Option<crate::plugins::signer::BodyDigest> {
        ids.iter().find_map(|&i| match &self.injections[i].form {
            Form::Signed(signed) => signed.body_digest,
            Form::Fixed { .. } => None,
        })
    }

    /// Whether a response from `host` is scanned for a reflected credential before it is relayed
    /// into the cage.
    ///
    /// A configured secret can only re-enter the cage by being *reflected* by a host an injection
    /// targets (an echo or debug endpoint, or one that stores the credential and later returns it),
    /// so the mask is scoped to exactly those hosts. Every other response — notably the large
    /// built-in downloads — is relayed untouched, which is what keeps the scan off the traffic that
    /// could never carry a reflection back.
    ///
    /// The empty-needle short-circuit is load-bearing rather than tidy: it is what keeps a launch
    /// with no secrets from paying for the injection walk on every response it relays.
    ///
    /// Every inspected plane asks this one question of one function, because the answer decides
    /// whether a secret crosses back into the cage: widening it (a `Subdomain` rule, which
    /// [`names_exact_host`](super::names_exact_host) answers `false` for today) must widen it for
    /// HTTP/1.1 and HTTP/2 together, and a plane left behind is a plane relaying the value in clear.
    pub(crate) fn masks_reflection_for(&self, host: &str) -> bool {
        !self.needles.is_empty()
            && self
                .injections
                .iter()
                .any(|inj| super::names_exact_host(host, Some(&inj.rule)))
    }
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
    /// The launch's `[redact] min_len`. Held because [`Credentials::observe`] builds needles of its
    /// own after the launch resolved its declared ones, and a needle it adds must clear the same
    /// floor as those — see [`OBSERVE_MIN_LEN`].
    min_len: usize,
    /// The launch's `[network] shared_credential` groups, canonicalized by the config layer (which
    /// is where a `*.domain` entry keeps its prefix and its domain is normalized). Read once per
    /// learned
    /// needle, to give it the whole service rather than the single host sbx happened to see the
    /// credential going to. Held here rather than consulted per request because
    /// [`SecretNeedle::scanned_for`] runs against every request head: resolving the group at learn
    /// time keeps that a membership test with no reachback.
    shared_credential: Vec<Vec<String>>,
}

impl Credentials {
    /// The state as first resolved, host-side, before the cage started.
    pub(crate) fn new(
        injections: Vec<HeaderInjection>,
        needles: Vec<SecretNeedle>,
        min_len: usize,
        shared_credential: Vec<Vec<String>>,
    ) -> Self {
        Self {
            current: std::sync::RwLock::new(std::sync::Arc::new(CredentialSet {
                injections,
                needles,
            })),
            min_len,
            shared_credential,
        }
    }

    /// The hosts a credential learned on `dest` may travel to: the declared group containing it, or
    /// `dest` alone when no group names it — which is the behaviour that predates the field.
    fn service_of(&self, dest: &str) -> Vec<String> {
        let host = host_key(dest);
        match self.shared_credential.iter().find(|group| {
            group
                .iter()
                .any(|entry| crate::allowlist::shared_credential_covers(entry, &host))
        }) {
            Some(group) => group.clone(),
            None => vec![host],
        }
    }

    /// The floor this state was built with, so a caller that rebuilds one side of it (the test-only
    /// half-replacements) carries the same floor rather than silently reverting to the built-in one.
    #[cfg(test)]
    pub(crate) fn min_len(&self) -> usize {
        self.min_len
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
        let Ok(mut current) = self.current.write() else {
            return;
        };
        // What the re-resolution produced is the whole of the *declared* state, and replaces it.
        // What it cannot speak for is what was **learned**: an app's own credential belongs to no
        // declaration, so a re-resolution has nothing to offer in its place and taking the answer
        // wholesale would simply drop it — leaving the value the cage actually authenticates with
        // un-tripwired on the way out, unmasked on the way back, and unmasked in the capture. It is
        // carried across, minus anything the new declared set already covers.
        let mut needles = set.needles;
        let learned: Vec<SecretNeedle> = current
            .needles
            .iter()
            .filter(|n| n.is_observed())
            .filter(|n| !needles.iter().any(|kept| kept.as_bytes() == n.as_bytes()))
            .cloned()
            .collect();
        needles.extend(learned);
        *current = std::sync::Arc::new(CredentialSet {
            injections: set.injections,
            needles,
        });
    }

    /// Remember a credential the cage sent for itself, so the tripwires cover it too. Reports
    /// whether it was newly kept.
    ///
    /// A credential an app obtained by its own sign-in is invisible to everything here: it belongs
    /// to no declaration, so nothing refuses it on the way out and nothing masks it on the way
    /// back. sbx already *sees* it — it terminates the TLS — so the only question is whether it
    /// retains it. Retaining it costs a value held in host memory, never written; not retaining it
    /// leaves the credential with no protection at all.
    ///
    /// What it does **not** buy is a value hidden from the operator. A learned needle is masked out
    /// of the traffic capture and the logged path for the service it was learned on and nowhere
    /// else ([`SecretNeedle::masks_record_for`]), because the bytes here are the cage's to choose:
    /// a learned needle that masked the whole record would let a cage decide what
    /// `sbx net logs --with-headers` can still show.
    ///
    /// This is a net over the cage's traffic, not a boundary, and it is a net the cage feeds. It
    /// cannot tell a credential an app signed in for from a value sent to occupy a slot, since both
    /// are just header values on allowed requests. What the cap and its eviction settle is which
    /// eight are held; nothing here can settle whether they are the eight that matter.
    ///
    /// Only the injections are authoritative for what gets *sent*: this never adds an injection, so
    /// observing can change what is scanned but never what the cage authenticates as.
    pub(crate) fn observe(&self, header: &str, value: &str, dest: &str) -> bool {
        let credential = credential_in(value);
        // The higher of the two floors. `OBSERVE_MIN_LEN` is not itself configurable: it states a
        // *relation* — an inferred credential is held to a stricter floor than a declared one — and
        // that relation is what breaks the moment a launch raises `[redact] min_len` above it. Take
        // the maximum and it holds at every setting.
        if credential.len() < OBSERVE_MIN_LEN.max(self.min_len) {
            return false;
        }
        let bytes = credential.as_bytes();
        // Only the duplicate check refuses. The cap is enforced by eviction below, over the
        // **learned** needles alone, which is what [`OBSERVE_MAX`] bounds: what a cage rotating
        // through values can add, never a declared needle. Counting the whole set turned the
        // ceiling into a switch — `HeaderShape::needles` emits *two* needles for a `basic`-shaped
        // secret, so four declared credentials filled it and this function then learned nothing for
        // the rest of the launch, silently leaving every cage-acquired token outside the redaction
        // and the outbound tripwire.
        {
            let current = self.snapshot();
            if current.needles.iter().any(|n| n.as_bytes() == bytes) {
                return false;
            }
        }
        let Ok(mut current) = self.current.write() else {
            return false;
        };
        // Re-checked under the write lock: two threads can reach the check above with the same new
        // credential, and a duplicate needle would scan the same bytes twice for the same result.
        if current.needles.iter().any(|n| n.as_bytes() == bytes) {
            return false;
        }
        let mut needles = current.needles.clone();
        // Room is made rather than the new value refused, and the two are not the same policy on an
        // adversary that fills this set for free. What goes out is the least recently learned, and
        // only ever a learned one: a declared needle is not what `OBSERVE_MAX` bounds.
        while needles.iter().filter(|n| n.is_observed()).count() >= OBSERVE_MAX {
            let Some(oldest) = needles.iter().position(|n| n.is_observed()) else {
                break;
            };
            needles.remove(oldest);
        }
        needles.push(SecretNeedle::learned(
            format!("observed:{header}"),
            bytes.to_vec(),
            self.service_of(dest),
        ));
        *current = std::sync::Arc::new(CredentialSet {
            injections: current.injections.clone(),
            needles,
        });
        true
    }

    /// Remember every credential a request head carries, given the head's headers and the names of
    /// the headers this request will have **replaced** by injection.
    ///
    /// The caller must have established that the request was **allowed**: observing a refused one
    /// would let an agent seed the scan set by aiming at hosts it knows are denied.
    ///
    /// A header being injected is skipped, and that exclusion is load-bearing rather than an
    /// optimisation. The value the client put there is stripped and never reaches the wire, so
    /// there is nothing to tripwire — while remembering it would tripwire *the client's own
    /// placeholder*, and the next request carrying that same placeholder would be refused as an
    /// outbound leak. That is the exact shape of the intended setup, where an application holds a
    /// worthless value and sbx substitutes the real one on every request: observing the placeholder
    /// would break the design it exists to protect.
    ///
    /// The exclusion therefore has to answer "is this header being replaced?" with the SAME equality
    /// the replacement uses — [`super::header_name_eq`], which folds `_` onto `-` as well as case.
    /// Matching on case alone here left a gap between the two: an injection declared `X_Api_Key`
    /// still stripped a client's `X-Api-Key` (the strip folds), while this filter did not recognise
    /// the pair, so the placeholder it stripped was learned as a needle and the next request
    /// carrying it was refused as an outbound leak.
    ///
    /// Reads through a [`HeaderLookup`] so every plane can call it with what it already holds: the
    /// HTTP/1.1 planes' parsed pairs, and the HTTP/2 plane's decoded header map. The alternative was
    /// a signature only one plane could satisfy, which is how this ended up running on one plane out
    /// of three in the first place.
    pub(crate) fn observe_head(
        &self,
        headers: &dyn HeaderLookup,
        injected: &[&str],
        dest: &str,
    ) -> usize {
        let mut kept = 0;
        for name in OBSERVED_AUTH_HEADERS
            .iter()
            .filter(|name| !injected.iter().any(|inj| super::header_name_eq(name, inj)))
        {
            headers.for_each(name, &mut |value| {
                if self.observe(name, value, dest) {
                    kept += 1;
                }
            });
        }
        kept
    }
}

/// The Knuth-Morris-Pratt failure table for `pattern` — see [`SecretNeedle::fail`].
fn failure_table(pattern: &[u8]) -> Vec<u32> {
    let mut fail = vec![0u32; pattern.len()];
    let mut matched = 0usize;
    for i in 1..pattern.len() {
        while matched > 0 && pattern[matched] != pattern[i] {
            matched = fail[matched - 1] as usize;
        }
        if pattern[matched] == pattern[i] {
            matched += 1;
        }
        fail[i] = matched as u32;
    }
    fail
}

/// The request headers whose value is a credential worth remembering when the cage sends one of its
/// own. Deliberately a short, explicit list rather than a heuristic: a guess that swept in a
/// correlation id or a trace token would tripwire ordinary traffic and mask ordinary responses.
const OBSERVED_AUTH_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-goog-api-key",
];

/// The shortest observed value kept. Higher than the built-in floor for a *declared* secret, because
/// that one was named by a human who accepted the consequence, while this one is inferred: a short
/// value is far likelier to occur by chance in unrelated traffic, and a false needle blocks requests
/// and mutates responses.
///
/// It is a floor of its own rather than a configurable setting, and what it states is a *relation*:
/// an inferred credential is held at least as strictly as a declared one. A launch that raises
/// `[redact] min_len` past this value therefore raises this one with it — see
/// [`Credentials::observe`], which takes the higher of the two.
const OBSERVE_MIN_LEN: usize = 16;

/// The most observed credentials kept. A cage rotating through many values must not grow the scan
/// set without bound, since every needle is scanned against every request head and every response
/// chunk from an injection target.
///
/// Reaching it evicts the least recently learned rather than refusing the new value, and the
/// difference is the whole of what this ceiling is worth against a cage that fills it deliberately.
/// Refusing meant eight requests to an allowed host settled the set for the rest of the launch, and
/// every credential the app obtained afterwards stayed outside the outbound tripwire and the
/// response mask. Under recency the same manoeuvre costs eight further values for every value it
/// wants uncovered, and covers nothing in the window between a credential being seen and those
/// eight arriving. It also fits the ordinary case it was written for, an app whose token rotates:
/// the current values are the ones held.
const OBSERVE_MAX: usize = 8;

/// The credential inside an auth header value: the token, with a `Bearer`/`Basic`/`Token` scheme
/// prefix removed however the client cased it. The bare token is what matters, since that is the
/// spelling that would appear if it leaked somewhere other than this header.
fn credential_in(value: &str) -> &str {
    let value = value.trim();
    // Case-insensitively, because RFC 9110 makes the auth scheme case-insensitive and clients do use
    // the other spellings (`BEARER`, `bEaReR` from a hand-rolled header). Listing a couple of casings
    // and comparing exactly missed those, and the needle then held the scheme word too: the outbound
    // tripwire only refused the token when it left inside a header spelled exactly that way, and the
    // response masking never matched the bare token at all — which is the spelling that matters,
    // since that is how the credential appears when it leaks somewhere other than this header.
    // `get(..)` rather than an index: the value is attacker-shaped, and a byte offset that lands
    // inside a multi-byte character (`abcdef\u{e9}`) panics a slice while it merely yields `None`
    // here. A panic on this path is a killed proxy thread, not a refused request.
    for scheme in ["bearer ", "basic ", "token "] {
        if let Some(prefix) = value.get(..scheme.len())
            && prefix.eq_ignore_ascii_case(scheme)
        {
            return value[scheme.len()..].trim();
        }
    }
    value
}

/// How a credential is re-resolved, host-side, when the upstream says the one being injected is no
/// longer good. A closure rather than a call into the resolver because *what* a credential resolves
/// from belongs to the launch (sources, project root, the `bwrap` to sandbox a plugin with) and
/// *when* to ask again belongs to the proxy — this is the seam between the two.
///
/// It is handed the state it is replacing, because part of that state is *running*: a signed
/// injection holds a plugin process, started once at launch and told its credential at a handshake.
/// A re-resolution that could not see it would have to start a new one for every declared signer on
/// every refresh — a sandbox spawn per `401`, for credentials a `401` says nothing about (see
/// [`HeaderInjection::refreshable`]). What the launch does with it is reuse the process where the
/// credential behind it came back unchanged.
pub(crate) type Refresher = Box<
    dyn Fn(&[HeaderInjection]) -> std::io::Result<(Vec<HeaderInjection>, Vec<SecretNeedle>)>
        + Send
        + Sync,
>;

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

        // Taken before the re-resolution, and handed to it: it is both what the answer is compared
        // against and what the answer may reuse.
        let current = self.credentials.snapshot();
        let (injections, needles) = match (self.refresher)(&current.injections) {
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

/// Whether two injection sets carry the same **resolve-time material** for the same headers — the
/// test for "the source gave us back what the upstream just refused". Compared in full rather than
/// by length so a set that changed shape counts as new.
///
/// Deliberately not a comparison of what goes on the wire: a signed injection's wire value is a
/// function of the request, so two of them differ for reasons that have nothing to do with the
/// credential. See [`HeaderInjection::material`].
fn same_values(a: &[HeaderInjection], b: &[HeaderInjection]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x.header_names() == y.header_names() && x.material() == y.material())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::sandbox::redact::MIN_LEN_DEFAULT;

    /// A credential state on the built-in redaction floor — what a launch that configures none runs
    /// with. The tests that care about the floor itself call [`Credentials::new`] directly.
    fn default_creds(injections: Vec<HeaderInjection>, needles: Vec<SecretNeedle>) -> Credentials {
        Credentials::new(injections, needles, MIN_LEN_DEFAULT, Vec::new())
    }

    /// A credential sbx **learned** survives a re-resolution; a declared one is replaced by it.
    ///
    /// The two are not symmetric, and the asymmetry is the whole point. A re-resolution answers for
    /// every declaration, so taking its needles wholesale is right for those. It answers for nothing
    /// an app obtained by its own sign-in, which sbx keeps only because it saw it — so taking the
    /// answer wholesale dropped it, and with it every protection that value had: the outbound
    /// tripwire stopped refusing it on the way out, the response masking stopped masking it on the
    /// way back, and the capture stopped masking it at filing. One `401` from any host carrying a
    /// refreshable declared credential was enough to trigger it.
    ///
    /// Residual, stated rather than fixed: the *previous* declared value is gone the moment the new
    /// one lands, so an exchange still in flight that is filed after a re-resolution has its
    /// reflected copy of the old value masked against the new needles. Keeping a generation of
    /// superseded values alive to close that would mean masking values that are no longer
    /// credentials, and holding them for a window nothing can pick correctly.
    #[test]
    fn a_learned_credential_survives_a_re_resolution_and_a_declared_one_is_replaced() {
        let creds = default_creds(
            Vec::new(),
            vec![SecretNeedle::named(
                "declared",
                b"declared-value-v1".to_vec(),
            )],
        );
        assert!(
            creds.observe(
                "authorization",
                "Bearer app-own-token-abcdefgh",
                "host.test"
            ),
            "the app's own credential is remembered"
        );

        // What the launch's refresher produces on a `401`: every declaration re-resolved, and
        // nothing else — it knows nothing of what was learned from traffic.
        creds.replace(CredentialSet {
            injections: Vec::new(),
            needles: vec![SecretNeedle::named(
                "declared",
                b"declared-value-v2".to_vec(),
            )],
        });

        let values: Vec<Vec<u8>> = creds
            .snapshot()
            .needles
            .iter()
            .map(|n| n.as_bytes().to_vec())
            .collect();
        assert!(
            values.contains(&b"app-own-token-abcdefgh".to_vec()),
            "the learned credential still has a needle: {:?}",
            values
                .iter()
                .map(|v| String::from_utf8_lossy(v))
                .collect::<Vec<_>>()
        );
        assert!(
            values.contains(&b"declared-value-v2".to_vec()),
            "the re-resolved declared value is in force"
        );
        assert!(
            !values.contains(&b"declared-value-v1".to_vec()),
            "and it replaced the value it re-resolved, rather than piling up beside it"
        );
        assert_eq!(values.len(), 2);

        // A second re-resolution does not duplicate what it carried across.
        creds.replace(CredentialSet {
            injections: Vec::new(),
            needles: vec![SecretNeedle::named(
                "declared",
                b"declared-value-v3".to_vec(),
            )],
        });
        assert_eq!(creds.snapshot().needles.len(), 2, "carried once, not twice");

        // ...and a re-resolution that happens to produce the same bytes as a learned needle keeps
        // one of them, not two scanning for the same value.
        creds.replace(CredentialSet {
            injections: Vec::new(),
            needles: vec![SecretNeedle::named(
                "declared",
                b"app-own-token-abcdefgh".to_vec(),
            )],
        });
        assert_eq!(creds.snapshot().needles.len(), 1);
    }

    // The formed header value carries the plaintext secret, so its `Debug` must never leak it — the
    // redacted `Debug` is the guard that keeps a secret out of a log line or a panic message.
    #[test]
    fn header_injection_debug_redacts_the_value() {
        let injection = HeaderInjection::fixed(
            crate::allowlist::classify("api.example.com").unwrap(),
            "x-api-key".to_string(),
            "SECRET-TOKEN-abc123".to_string(),
        );
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
        let creds = default_creds(
            vec![HeaderInjection::fixed(
                crate::allowlist::classify("api.example.com").unwrap(),
                "authorization".to_string(),
                "Bearer first".to_string(),
            )],
            vec![SecretNeedle::named("tok", b"first".to_vec())],
        );

        let held = creds.snapshot();
        creds.replace(CredentialSet {
            injections: vec![HeaderInjection::fixed(
                crate::allowlist::classify("api.example.com").unwrap(),
                "authorization".to_string(),
                "Bearer second".to_string(),
            )],
            needles: vec![SecretNeedle::named("tok", b"second".to_vec())],
        });

        assert_eq!(
            held.injections[0].value(),
            "Bearer first",
            "an exchange in flight keeps the state it started with"
        );
        assert_eq!(
            held.needles[0].as_bytes(),
            b"first",
            "and its needle matches that same state, never the newer one"
        );

        let fresh = creds.snapshot();
        assert_eq!(fresh.injections[0].value(), "Bearer second");
        assert_eq!(fresh.needles[0].as_bytes(), b"second");
    }

    fn injection(value: &str) -> HeaderInjection {
        HeaderInjection::fixed(
            crate::allowlist::classify("api.example.com").unwrap(),
            "authorization".to_string(),
            value.to_string(),
        )
    }

    /// A refresh replaces both halves at once, and the value the proxy will inject next is the new
    /// one. This is the whole point of the mechanism: an upstream that refused the old credential
    /// gets the re-resolved one on the following request.
    #[test]
    fn a_refusal_re_resolves_and_the_next_snapshot_carries_the_new_value() {
        let creds = Arc::new(default_creds(
            vec![injection("Bearer old")],
            vec![SecretNeedle::named("tok", b"old".to_vec())],
        ));
        let refresh = CredentialRefresh::new(
            creds.clone(),
            Box::new(|_| {
                Ok((
                    vec![injection("Bearer new")],
                    vec![SecretNeedle::named("tok", b"new".to_vec())],
                ))
            }),
        );

        assert!(refresh.on_refusal(), "a first refusal re-resolves");
        let set = creds.snapshot();
        assert_eq!(set.injections[0].value(), "Bearer new");
        assert_eq!(
            set.needles[0].as_bytes(),
            b"new",
            "the needle moved with the value it protects"
        );
    }

    /// The re-resolution is handed the state it replaces, which is what lets the launch keep the
    /// part of it that is *running*: a signed injection holds a plugin process, and re-resolving
    /// blind would start a new one for every declared signer on every refresh — a sandbox spawn per
    /// `401`, for credentials a `401` says nothing about.
    #[test]
    fn the_re_resolution_is_shown_the_state_it_replaces() {
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = seen.clone();
        let creds = Arc::new(default_creds(vec![injection("Bearer old")], Vec::new()));
        let refresh = CredentialRefresh::new(
            creds,
            Box::new(move |standing| {
                recorded
                    .lock()
                    .unwrap()
                    .extend(standing.iter().map(|i| i.value().to_string()));
                Ok((vec![injection("Bearer new")], Vec::new()))
            }),
        );

        assert!(refresh.on_refusal());
        assert_eq!(
            *seen.lock().unwrap(),
            vec!["Bearer old".to_string()],
            "the credential being replaced, as it stands at the moment of the refusal"
        );
    }

    /// An upstream answering `401` to every request must not turn each one into a resolver run. The
    /// second refusal inside the gap is a no-op, and the source is not consulted again.
    #[test]
    fn a_second_refusal_inside_the_gap_does_not_consult_the_source() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        let creds = Arc::new(default_creds(vec![injection("Bearer old")], Vec::new()));
        let refresh = CredentialRefresh::new(
            creds.clone(),
            Box::new(move |_| {
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
        let creds = Arc::new(default_creds(vec![injection("Bearer same")], Vec::new()));
        let refresh = CredentialRefresh::new(
            creds,
            Box::new(move |_| {
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
        let creds = Arc::new(default_creds(vec![injection("Bearer old")], Vec::new()));
        let refresh = CredentialRefresh::new(
            creds.clone(),
            Box::new(move |_| {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err(std::io::Error::other("the vault is unreachable"))
            }),
        );

        assert!(!refresh.on_refusal());
        assert!(!refresh.on_refusal());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            creds.snapshot().injections[0].value(),
            "Bearer old",
            "a failed refresh leaves the current credential in place"
        );
    }

    /// What is kept is the token, not the header value: a leaked credential shows up as the bare
    /// token, so that is the spelling the tripwires have to match.
    #[test]
    fn an_observed_credential_is_kept_without_its_scheme_prefix() {
        let creds = default_creds(Vec::new(), Vec::new());
        assert!(creds.observe("authorization", "Bearer tok-0123456789abcdef", "host.test"));
        let set = creds.snapshot();
        assert_eq!(set.needles.len(), 1);
        assert_eq!(set.needles[0].as_bytes(), b"tok-0123456789abcdef");
        assert!(
            set.injections.is_empty(),
            "observing must never change what the cage authenticates as"
        );
    }

    /// A short value occurs by chance in unrelated traffic, and a false needle refuses requests and
    /// mutates responses. The floor is higher than for a declared secret, which a human accepted.
    #[test]
    fn a_short_observed_value_is_not_kept() {
        let creds = default_creds(Vec::new(), Vec::new());
        assert!(!creds.observe("authorization", "Bearer short", "host.test"));
        assert!(creds.snapshot().needles.is_empty());
    }

    /// A service is not one host. A credential learned on one host of a declared group travels to
    /// the others without tripping the wire, and still trips it everywhere else — the third host is
    /// what makes this a test of the scope rather than of the tripwire being off.
    #[test]
    fn a_learned_credential_travels_across_its_declared_service_and_no_further() {
        let creds = Credentials::new(
            Vec::new(),
            Vec::new(),
            MIN_LEN_DEFAULT,
            vec![vec![
                "api.example.test".to_string(),
                "app.example.test".to_string(),
            ]],
        );
        assert!(creds.observe(
            "authorization",
            "Bearer tok-0123456789abcdef",
            "api.example.test"
        ));
        let set = creds.snapshot();
        let needle = set.needles.first().expect("the credential was learned");
        assert!(
            !needle.scanned_for("api.example.test"),
            "the host it was acquired on is exempt, as it was before the field existed"
        );
        assert!(
            !needle.scanned_for("app.example.test"),
            "the other host of the declared service is exempt too — this is the whole field"
        );
        assert!(
            needle.scanned_for("elsewhere.test"),
            "a host outside the group is still scanned: the guard is scoped, not disabled"
        );
    }

    /// A `*.domain` entry covers the apex and every subdomain, and nothing that merely ends in the
    /// same letters — the separator rule an `allow` list's wildcard obeys, asked here through the
    /// same function so it cannot be right in one place and wrong in the other.
    #[test]
    fn a_wildcard_group_covers_the_service_and_stops_at_its_boundary() {
        let creds = Credentials::new(
            Vec::new(),
            Vec::new(),
            MIN_LEN_DEFAULT,
            vec![vec![
                "*.example.test".to_string(),
                "example.test".to_string(),
            ]],
        );
        assert!(creds.observe(
            "authorization",
            "Bearer tok-0123456789abcdef",
            "api.example.test"
        ));
        let set = creds.snapshot();
        let needle = set.needles.first().expect("the credential was learned");
        assert!(
            !needle.scanned_for("api.example.test"),
            "the acquiring host"
        );
        assert!(!needle.scanned_for("app.example.test"), "another subdomain");
        assert!(!needle.scanned_for("example.test"), "the apex");
        assert!(
            needle.scanned_for("example.test.evil.test"),
            "a domain that merely carries the name is outside the group"
        );
        assert!(
            needle.scanned_for("notexample.test"),
            "the separating dot is required, so a bare suffix does not match"
        );
        assert!(needle.scanned_for("elsewhere.test"), "an unrelated host");
    }

    /// With no group naming its host, a learned credential keeps the exemption it had before the
    /// field existed — one host, and one only.
    #[test]
    fn an_undeclared_host_keeps_the_single_host_exemption() {
        let creds = Credentials::new(
            Vec::new(),
            Vec::new(),
            MIN_LEN_DEFAULT,
            vec![vec![
                "api.other.test".to_string(),
                "app.other.test".to_string(),
            ]],
        );
        assert!(creds.observe(
            "authorization",
            "Bearer tok-0123456789abcdef",
            "api.example.test"
        ));
        let set = creds.snapshot();
        let needle = set.needles.first().expect("the credential was learned");
        assert!(!needle.scanned_for("api.example.test"));
        assert!(
            needle.scanned_for("app.other.test"),
            "a group that does not name the acquiring host grants it nothing"
        );
    }

    /// The group and the request's host are compared in one spelling, because an exemption that
    /// fails to match is invisible: the request is refused and the reason names a leak. The two
    /// sides are normalized in different places — the entries by the config layer, which is where a
    /// group is read, and the request's host here — so this covers the half this type owns: an
    /// oddly-spelled destination still meets a canonical group.
    #[test]
    fn a_request_host_is_canonicalized_before_it_meets_its_group() {
        let creds = Credentials::new(
            Vec::new(),
            Vec::new(),
            MIN_LEN_DEFAULT,
            vec![vec![
                "api.example.test".to_string(),
                "app.example.test".to_string(),
            ]],
        );
        assert!(creds.observe(
            "authorization",
            "Bearer tok-0123456789abcdef",
            "API.Example.Test"
        ));
        let set = creds.snapshot();
        let needle = set.needles.first().expect("the credential was learned");
        assert!(
            !needle.scanned_for("APP.EXAMPLE.TEST."),
            "upper case and a trailing root dot still name the group's host"
        );
        assert!(needle.scanned_for("elsewhere.test"));
    }

    /// Lowering the declared floor must not lower this one: an observed credential was inferred
    /// rather than named by a human, so it stays on the stricter of the two.
    #[test]
    fn a_lowered_declared_floor_does_not_lower_the_observed_one() {
        let creds = Credentials::new(Vec::new(), Vec::new(), 4, Vec::new());
        // 12 bytes: over the launch's floor, under the inferred one.
        assert!(!creds.observe("authorization", "Bearer tok-01234567", "host.test"));
        assert!(creds.snapshot().needles.is_empty());
    }

    /// Raising it past the inferred floor does raise this one: a launch that says a credential is
    /// only worth scanning for above 24 bytes means it for the ones it did not declare too.
    #[test]
    fn a_raised_declared_floor_raises_the_observed_one() {
        let creds = Credentials::new(Vec::new(), Vec::new(), 24, Vec::new());
        // 20 bytes: over the inferred floor, under the launch's.
        assert!(!creds.observe("authorization", "Bearer tok-0123456789abcdef", "host.test"));
        assert!(creds.snapshot().needles.is_empty());
        // 26 bytes clears both.
        assert!(creds.observe(
            "authorization",
            "Bearer tok-0123456789abcdefghijkl",
            "host.test"
        ));
        assert_eq!(creds.snapshot().needles.len(), 1);
    }

    /// Every needle is scanned against every request head and every response chunk, so the same
    /// credential seen on a thousand requests must cost one needle, not a thousand.
    #[test]
    fn the_same_credential_is_kept_once_and_the_set_is_capped() {
        let creds = default_creds(Vec::new(), Vec::new());
        assert!(creds.observe("authorization", "Bearer tok-0123456789abcdef", "host.test"));
        assert!(!creds.observe("authorization", "Bearer tok-0123456789abcdef", "host.test"));
        assert_eq!(creds.snapshot().needles.len(), 1);

        for i in 0..20 {
            creds.observe(
                "authorization",
                &format!("Bearer tok-{i:0>20}"),
                "host.test",
            );
        }
        assert_eq!(
            creds.snapshot().needles.len(),
            OBSERVE_MAX,
            "the scan set is bounded whatever the cage rotates through"
        );
    }

    /// Which eight the cap keeps is the cage's choice either way, so it must be the eight most
    /// recent rather than the eight that arrived first.
    ///
    /// The values that fill this set are chosen by the cage: it sends an auth header and the proxy
    /// remembers it. First-come admission therefore let eight requests to an allowed host settle
    /// the set for the whole launch, and a credential the app really signed in for afterwards was
    /// refused entry, so nothing tripwired it on the way out and nothing masked it on the way back.
    /// Recency cannot be gamed the same way: covering a value that has been seen costs the cage
    /// eight further values, every time, and the value is covered from the moment it is seen.
    #[test]
    fn a_credential_seen_after_the_cap_is_full_still_joins_the_scan_set() {
        let creds = default_creds(Vec::new(), Vec::new());
        for i in 0..OBSERVE_MAX {
            assert!(
                creds.observe(
                    "authorization",
                    &format!("Bearer seed-{i:0>20}"),
                    "host.test"
                ),
                "the seeding values are the premise of this test"
            );
        }
        assert_eq!(creds.snapshot().needles.len(), OBSERVE_MAX);

        const LATE: &str = "app-signed-in-0123456789";
        assert!(
            creds.observe("authorization", &format!("Bearer {LATE}"), "host.test"),
            "a credential the app obtains after the cap is full must still be kept"
        );
        let set = creds.snapshot();
        assert_eq!(
            set.needles.len(),
            OBSERVE_MAX,
            "and the set stays bounded: the oldest went out to make room"
        );
        assert!(
            set.needles.iter().any(|n| n.as_bytes() == LATE.as_bytes()),
            "the value the tripwires must cover is the one in the set"
        );
        assert!(
            !set.needles
                .iter()
                .any(|n| n.as_bytes() == b"seed-00000000000000000000"),
            "and the one that made room is the first the cage seeded"
        );
    }

    /// `OBSERVE_MAX` is documented as "The most **observed** credentials kept" — it bounds what a
    /// cage rotating through values can add to a set that is scanned against every request head and
    /// every response chunk. The check counted the whole needle set instead, declared needles
    /// included, which turned a ceiling into a switch: `HeaderShape::needles` emits *two* needles
    /// for a `basic`-shaped secret, so four declared credentials filled it and nothing was ever
    /// learned again — every token the cage obtained by its own sign-in stayed outside the
    /// redaction and the outbound tripwire, silently, on exactly the launches that declare the most.
    #[test]
    fn a_launch_full_of_declared_needles_still_observes_what_the_cage_obtains() {
        let declared: Vec<SecretNeedle> = (0..OBSERVE_MAX)
            .map(|i| {
                SecretNeedle::named(
                    format!("declared-{i}"),
                    format!("declared-value-{i:0>20}").into_bytes(),
                )
            })
            .collect();
        let creds = default_creds(Vec::new(), declared);
        assert_eq!(creds.snapshot().needles.len(), OBSERVE_MAX);

        assert!(
            creds.observe("authorization", "Bearer tok-0123456789abcdef", "host.test"),
            "a declared set at the cap must not stop the cage's own credential being learned"
        );

        // And the cap still binds the population it is about.
        for i in 0..OBSERVE_MAX + 5 {
            creds.observe(
                "authorization",
                &format!("Bearer tok-{i:0>20}"),
                "host.test",
            );
        }
        let set = creds.snapshot();
        let learned = set.needles.iter().filter(|n| n.is_observed()).count();
        assert_eq!(learned, OBSERVE_MAX, "the learned population is bounded");
        assert_eq!(
            set.needles.len(),
            OBSERVE_MAX * 2,
            "and the declared ones were never evicted to make room"
        );
    }

    /// The header list is explicit on purpose: sweeping in a correlation id would tripwire ordinary
    /// traffic and mask ordinary responses.
    #[test]
    fn only_the_named_auth_headers_are_observed() {
        let creds = default_creds(Vec::new(), Vec::new());
        let kept = creds.observe_head(
            &vec![
                ("X-Request-Id".into(), "req-0123456789abcdef".into()),
                (
                    "User-Agent".into(),
                    "some-agent/1.0-with-a-long-name".into(),
                ),
                ("Authorization".into(), "Bearer tok-0123456789abcdef".into()),
            ],
            &[],
            "host.test",
        );
        assert_eq!(kept, 1, "only the auth header counts");
        let set = creds.snapshot();
        assert_eq!(set.needles.len(), 1);
        assert_eq!(set.needles[0].as_bytes(), b"tok-0123456789abcdef");
    }

    /// A request that carries the same credential header twice is observed twice. A client library
    /// that adds a default `Authorization` beside an explicit one sends two, and the one kept is
    /// not necessarily the one that authenticates: the other would stay unmasked in a capture and
    /// in `sbx net logs --with-headers`.
    ///
    /// Teeth: reading the first value alone keeps one needle, and the assertion on the second fails.
    #[test]
    fn every_occurrence_of_a_credential_header_is_observed() {
        let creds = default_creds(Vec::new(), Vec::new());
        let kept = creds.observe_head(
            &vec![
                ("Authorization".into(), "Bearer tok-first-0123456789".into()),
                (
                    "authorization".into(),
                    "Bearer tok-second-0123456789".into(),
                ),
            ],
            &[],
            "host.test",
        );
        assert_eq!(kept, 2, "both values are credentials the cage sent");
        let set = creds.snapshot();
        let needles: Vec<&[u8]> = set.needles.iter().map(|n| n.as_bytes()).collect();
        assert!(
            needles.contains(&b"tok-first-0123456789".as_slice()),
            "the first is kept: {needles:?}"
        );
        assert!(
            needles.contains(&b"tok-second-0123456789".as_slice()),
            "and so is the second: {needles:?}"
        );
    }

    /// The interaction that matters most, because it breaks the very setup observing exists to
    /// protect. When sbx injects a header, the client's own value is stripped and never reaches the
    /// wire — and in the intended arrangement that value is a *placeholder* the application carries
    /// on every request. Remembering it would make the next request an outbound leak of a worthless
    /// string, refusing traffic sbx itself arranged. Found by running a real agent, not by reading.
    #[test]
    fn a_header_that_will_be_injected_is_never_observed() {
        let creds = default_creds(Vec::new(), Vec::new());
        let kept = creds.observe_head(
            &vec![(
                "Authorization".into(),
                "Bearer sbx-placeholder-not-a-real-credential".into(),
            )],
            &["authorization"],
            "host.test",
        );
        assert_eq!(
            kept, 0,
            "an injected header's client value is not a credential"
        );
        assert!(
            creds.snapshot().needles.is_empty(),
            "and nothing is tripwired, so the next request carrying it still passes"
        );
    }

    /// The same exclusion, reached through the spelling that used to slip past it. The strip on the
    /// injection path compares header names with [`super::header_name_eq`], which folds `_` onto `-`;
    /// this filter compared case only. So an injection declared `X_Api_Key` stripped the client's
    /// `X-Api-Key` and this filter did not recognise the two as the same header — the placeholder was
    /// learned, and the very next request carrying it was refused as an outbound leak.
    ///
    /// Teeth: with the filter back on `eq_ignore_ascii_case`, `kept` is 2 and the placeholder has a
    /// needle. The `Authorization` in the same head is the other half of the assertion — it is not
    /// being injected, so it must still be observed, and a filter that simply dropped everything
    /// could not pass.
    #[test]
    fn an_injected_header_is_excluded_under_every_spelling_the_strip_folds() {
        let creds = default_creds(Vec::new(), Vec::new());
        let kept = creds.observe_head(
            &vec![
                (
                    "X-Api-Key".into(),
                    "sbx-placeholder-not-a-real-credential".into(),
                ),
                ("Authorization".into(), "Bearer tok-0123456789abcdef".into()),
            ],
            // The declaration's own spelling, which the strip folds onto the client's.
            &["X_Api_Key"],
            "host.test",
        );
        assert_eq!(kept, 1, "only the header sbx does not replace is observed");
        let set = creds.snapshot();
        let needles: Vec<Vec<u8>> = set.needles.iter().map(|n| n.as_bytes().to_vec()).collect();
        assert!(
            !needles
                .iter()
                .any(|n| n == b"sbx-placeholder-not-a-real-credential"),
            "the stripped placeholder must not be tripwired: {needles:?}"
        );
        assert_eq!(
            needles,
            vec![b"tok-0123456789abcdef".to_vec()],
            "and the header that does reach the wire is still remembered"
        );
    }

    /// The auth scheme is case-insensitive (RFC 9110), so the needle must be the bare token whichever
    /// way the client spelled it. Comparing a hand-written list of casings exactly left `BEARER
    /// <token>` unstripped, and the needle then carried the scheme word: the outbound tripwire only
    /// refused the token inside a header spelled that same way, and the response masking never
    /// matched the bare token — the one spelling that matters, because it is how the credential looks
    /// when it leaks somewhere other than this header.
    ///
    /// Teeth: with the case-sensitive prefix list, the first assertion reports the needle as
    /// `BEARER tok-…` instead of the token.
    #[test]
    fn a_scheme_prefix_is_stripped_however_the_client_cased_it() {
        for value in [
            "BEARER tok-0123456789abcdef",
            "bEaReR tok-0123456789abcdef",
            "Bearer tok-0123456789abcdef",
        ] {
            assert_eq!(
                credential_in(value),
                "tok-0123456789abcdef",
                "`{value}` carries the bare token"
            );
        }
        assert_eq!(
            credential_in("BASIC dXNlcjpwYXNzd29yZA=="),
            "dXNlcjpwYXNzd29yZA==",
        );
        assert_eq!(
            credential_in("TOKEN tok-0123456789abcdef"),
            "tok-0123456789abcdef"
        );

        // And the widening stops at a scheme: a value that merely starts with those letters is a
        // credential in its own right and must be kept whole, or the needle would be a suffix of the
        // secret and the masking would leave the first bytes of it on the wire.
        assert_eq!(
            credential_in("bearerish-0123456789abcdef"),
            "bearerish-0123456789abcdef"
        );
        assert_eq!(
            credential_in("opaque-token-0123456789"),
            "opaque-token-0123456789"
        );
        // A non-ASCII value whose seventh byte falls inside a character: `None` from `get`, never a
        // panicked proxy thread.
        assert_eq!(credential_in("abcdef\u{e9}ghij"), "abcdef\u{e9}ghij");
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

    /// A signer scripted to answer, so the injection path is exercised without a sandbox.
    struct FakeSigner(Result<crate::sandbox::signer::Signature, String>);

    impl crate::sandbox::signer::Signing for FakeSigner {
        fn sign(
            &mut self,
            _req: &crate::sandbox::signer::SignRequest<'_>,
        ) -> Result<crate::sandbox::signer::Signature, String> {
            self.0.clone()
        }
    }

    fn signed_injection(
        answer: Result<Vec<(&str, &str)>, &str>,
        marker: Option<std::sync::Arc<crate::sandbox::broker::SecretMarker>>,
    ) -> HeaderInjection {
        let answer = match answer {
            Ok(headers) => Ok(crate::sandbox::signer::Signature {
                headers: headers
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                label: Some("us-east-1 s3".to_string()),
            }),
            Err(why) => Err(why.to_string()),
        };
        HeaderInjection {
            rule: crate::allowlist::classify("api.example.com").unwrap(),
            form: Form::Signed(Signed {
                name: "demo-signer".to_string(),
                sets: vec!["Authorization".to_string(), "X-Demo-Date".to_string()],
                sees: vec!["Content-Type".to_string()],
                key: "the-key".to_string(),
                marker,
                process: std::sync::Arc::new(std::sync::Mutex::new(FakeSigner(answer))),
                body_digest: None,
            }),
        }
    }

    fn facts<'a>(headers: &'a Vec<(String, String)>) -> RequestFacts<'a> {
        RequestFacts {
            method: "GET",
            host: "api.example.com",
            port: 443,
            target: "/v1/thing",
            headers,
            body: None,
        }
    }

    /// The whole point of the type: a signed injection's headers are formed from the request, at
    /// the moment the request exists, and go on the wire like any other injection.
    #[test]
    fn a_signed_injection_puts_the_plugins_headers_on_the_request() {
        let creds = CredentialSet {
            injections: vec![signed_injection(
                Ok(vec![
                    ("Authorization", "SIG abc"),
                    ("X-Demo-Date", "20260813"),
                ]),
                None,
            )],
            needles: Vec::new(),
        };
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        let pairs =
            pairs_for(&creds, &[0], &facts(&headers), None).unwrap_or_else(|e| panic!("{}", e.why));
        assert_eq!(
            pairs,
            vec![
                ("Authorization".to_string(), "SIG abc".to_string()),
                ("X-Demo-Date".to_string(), "20260813".to_string()),
            ]
        );
    }

    /// What a signer *may* set and what it *did* set are two different lists, and the skip list
    /// `observe_head` is given has to be the second.
    ///
    /// A manifest's `sets_headers` is a ceiling: the plugin decides per request. When it declines
    /// one, the client's own copy of that header is what goes on the wire — nothing replaced it —
    /// so a credential the cage sent for itself there is one to remember. Skipping by the
    /// declaration left it unlearned: unmasked in `sbx net logs`, and outside the outbound tripwire
    /// afterwards, on every plane. The same list is what `reserialize_request` strips by, so the
    /// two answer with one voice.
    ///
    /// `Authorization` is the header under test because it is one this scan looks at at all: the
    /// difference is only ever visible on a header a signer's manifest declares *and* the observer
    /// watches.
    #[test]
    fn a_header_the_signer_declined_to_set_is_still_observed() {
        // The manifest declares two; this plugin sets the other one.
        let creds = CredentialSet {
            injections: vec![signed_injection(
                Ok(vec![("X-Demo-Date", "20260813")]),
                None,
            )],
            needles: Vec::new(),
        };
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        let pairs =
            pairs_for(&creds, &[0], &facts(&headers), None).unwrap_or_else(|e| panic!("{}", e.why));

        let declared = creds.injections[0].header_names();
        assert_eq!(
            declared,
            vec!["Authorization", "X-Demo-Date"],
            "the declaration names both, which is the ceiling and not the answer"
        );
        let actually_set = crate::sandbox::proxy::injected_names(&pairs);
        assert_eq!(
            actually_set,
            vec!["X-Demo-Date"],
            "what went on the wire is the other one"
        );

        // The request carries a credential in the header the signer declined, so nothing replaced
        // it and it reached the upstream as the cage wrote it.
        let sent = vec![(
            "Authorization".to_string(),
            "Bearer cage-token-0123456789".to_string(),
        )];

        let by_declaration = default_creds(Vec::new(), Vec::new());
        assert_eq!(
            by_declaration.observe_head(&sent, &declared, "api.example.com"),
            0,
            "the ceiling skips a header nothing replaced"
        );

        let by_answer = default_creds(Vec::new(), Vec::new());
        assert_eq!(
            by_answer.observe_head(&sent, &actually_set, "api.example.com"),
            1,
            "the header the signer left alone carries a credential the cage sent for itself"
        );
        let set = by_answer.snapshot();
        assert_eq!(set.needles.len(), 1);
        assert_eq!(set.needles[0].as_bytes(), b"cage-token-0123456789");
    }

    /// A signer records what it was asked, so a test can assert on the question rather than only on
    /// the answer.
    struct RecordingSigner(std::sync::Arc<std::sync::Mutex<Option<String>>>);

    impl crate::sandbox::signer::Signing for RecordingSigner {
        fn sign(
            &mut self,
            req: &crate::sandbox::signer::SignRequest<'_>,
        ) -> Result<crate::sandbox::signer::Signature, String> {
            use crate::sandbox::signer::BodyFacts;
            *self.0.lock().expect("lock") = Some(match req.body {
                None => "no body stated".to_string(),
                Some(BodyFacts::Held {
                    bytes,
                    algorithm,
                    digest,
                }) => format!("held {bytes} bytes, {algorithm} {digest}"),
                Some(BodyFacts::Unheld { why }) => format!("unheld: {why}"),
            });
            Ok(crate::sandbox::signer::Signature {
                headers: vec![("Authorization".to_string(), "SIG abc".to_string())],
                label: None,
            })
        }
    }

    fn digesting_injection(
        seen: &std::sync::Arc<std::sync::Mutex<Option<String>>>,
    ) -> HeaderInjection {
        HeaderInjection {
            rule: crate::allowlist::classify("api.example.com").unwrap(),
            form: Form::Signed(Signed {
                name: "demo-signer".to_string(),
                sets: vec!["Authorization".to_string()],
                sees: Vec::new(),
                key: "the-key".to_string(),
                marker: None,
                process: std::sync::Arc::new(std::sync::Mutex::new(RecordingSigner(seen.clone()))),
                body_digest: Some(crate::plugins::signer::BodyDigest::Sha256),
            }),
        }
    }

    /// Which injections a request receives is answerable from the manifests alone — the caller has
    /// to know whether to hold the body *before* any plugin runs, because holding it is a decision
    /// about how the request is forwarded.
    #[test]
    fn the_digest_a_matched_signer_asks_for_is_known_before_the_plugin_runs() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let creds = CredentialSet {
            injections: vec![
                signed_injection(Ok(vec![("Authorization", "SIG abc")]), None),
                digesting_injection(&seen),
            ],
            needles: Vec::new(),
        };
        assert_eq!(
            creds.wants_body_digest(&[0]),
            None,
            "a signer that asked for no digest leaves the body streaming"
        );
        assert_eq!(
            creds.wants_body_digest(&[0, 1]),
            Some(crate::plugins::signer::BodyDigest::Sha256),
            "one matched injection asking is enough to hold the body"
        );
    }

    /// The facts the caller established reach the plugin that asked for them.
    #[test]
    fn a_signer_that_asked_for_a_digest_is_told_it() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let creds = CredentialSet {
            injections: vec![digesting_injection(&seen)],
            needles: Vec::new(),
        };
        let headers = Vec::new();
        let body = crate::sandbox::signer::BodyFacts::held(
            b"hello",
            crate::plugins::signer::BodyDigest::Sha256,
        );
        let mut req = facts(&headers);
        req.body = Some(&body);
        pairs_for(&creds, &[0], &req, None).unwrap_or_else(|e| panic!("{}", e.why));
        let asked = seen
            .lock()
            .expect("lock")
            .clone()
            .expect("the plugin was asked");
        assert!(
            asked.contains("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
            "the SHA-256 of `hello` reaches the plugin: {asked}"
        );
    }

    /// Fail-closed, and the one refusal that catches a caller which forgot to establish the body: a
    /// plugin whose scheme covers the payload must never be asked as though the request had none.
    #[test]
    fn a_signer_that_asked_for_a_digest_is_never_signed_around() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let creds = CredentialSet {
            injections: vec![digesting_injection(&seen)],
            needles: Vec::new(),
        };
        let headers = Vec::new();
        let refusal = match pairs_for(&creds, &[0], &facts(&headers), None) {
            Err(refusal) => refusal,
            Ok(pairs) => panic!("a body the caller did not establish refuses, got {pairs:?}"),
        };
        assert_eq!(refusal.signer, "demo-signer");
        assert!(refusal.why.contains("body"), "{}", refusal.why);
        assert!(
            seen.lock().expect("lock").is_none(),
            "the plugin is never asked at all"
        );
    }

    /// Fail-closed. A request that could not be signed is not sent unsigned: it would arrive
    /// anonymous and come back an authentication error for a reason unrelated to the credential.
    #[test]
    fn a_signer_that_cannot_answer_refuses_the_request() {
        let creds = CredentialSet {
            injections: vec![signed_injection(
                Err("no credentials for that region"),
                None,
            )],
            needles: Vec::new(),
        };
        let headers = Vec::new();
        let refusal = match pairs_for(&creds, &[0], &facts(&headers), None) {
            Err(refusal) => refusal,
            Ok(pairs) => panic!("a plugin that cannot sign refuses the request, got {pairs:?}"),
        };
        assert_eq!(refusal.signer, "demo-signer");
        assert!(refusal.why.contains("no credentials"), "{}", refusal.why);
    }

    /// The structural posture: the plugin places a marker, sbx substitutes the value on the way
    /// out, and the plugin never learns what it placed.
    #[test]
    fn a_marker_the_plugin_placed_becomes_the_credential_on_the_wire() {
        let marker = std::sync::Arc::new(
            crate::sandbox::broker::SecretMarker::new("s3cr3t-value-here", 8).expect("marker"),
        );
        let token = marker.token();
        let creds = CredentialSet {
            injections: vec![signed_injection(
                Ok(vec![("Authorization", &format!("Custom {token}"))]),
                Some(marker),
            )],
            needles: Vec::new(),
        };
        let headers = Vec::new();
        let pairs =
            pairs_for(&creds, &[0], &facts(&headers), None).unwrap_or_else(|e| panic!("{}", e.why));
        assert_eq!(
            pairs,
            vec![(
                "Authorization".to_string(),
                "Custom s3cr3t-value-here".to_string()
            )],
            "the marker is replaced by the value, on the plugin's own bytes"
        );
    }

    /// What the signer feed is for: a request's credential is formed by a plugin, and neither the
    /// egress log nor the launch note can say which declaration formed it or what it put on. Both
    /// outcomes are recorded — an answer and a refusal — because a feed that only showed failures
    /// would leave "it worked" indistinguishable from "nothing ran".
    #[test]
    fn every_signature_and_every_refusal_reaches_the_feed() {
        use crate::sandbox::signer_control::{SIGNER_RING_CAP, SignerKind, SignerRing};

        let ring = SignerRing::new(SIGNER_RING_CAP);
        let signs = CredentialSet {
            injections: vec![signed_injection(
                Ok(vec![("Authorization", "SIG abc")]),
                None,
            )],
            needles: Vec::new(),
        };
        let headers = Vec::new();
        pairs_for(&signs, &[0], &facts(&headers), Some(&ring))
            .unwrap_or_else(|e| panic!("{}", e.why));

        let refuses = CredentialSet {
            injections: vec![signed_injection(
                Err("no credentials for that region"),
                None,
            )],
            needles: Vec::new(),
        };
        assert!(
            pairs_for(&refuses, &[0], &facts(&headers), Some(&ring)).is_err(),
            "the scripted refusal refuses"
        );

        let events = ring.snapshot(None).events;
        assert_eq!(events.len(), 2, "{events:?}");

        assert_eq!(events[0].kind, SignerKind::Sign);
        assert!(
            events[0].detail.contains("demo-signer")
                && events[0].detail.contains("GET api.example.com/v1/thing")
                && events[0].detail.contains("set Authorization"),
            "who formed it, for what request, and which headers it put on: {:?}",
            events[0]
        );
        assert!(
            events[0].detail.contains("us-east-1 s3"),
            "and the plugin's own account of it: {:?}",
            events[0]
        );
        assert!(
            !events[0].detail.contains("SIG abc"),
            "never the value it formed: {:?}",
            events[0]
        );

        assert_eq!(events[1].kind, SignerKind::Refuse);
        assert!(
            events[1].detail.contains("no credentials for that region"),
            "a refusal carries the plugin's reason: {:?}",
            events[1]
        );
    }

    /// The refresher's circuit breaker, on the arm that would otherwise lose it: a signed
    /// injection's wire value differs per request, so the comparison has to be over the key.
    #[test]
    fn a_re_resolution_that_returns_the_same_key_stops_the_refresh() {
        let same = || {
            vec![signed_injection(
                Ok(vec![("Authorization", "SIG whatever")]),
                None,
            )]
        };
        assert!(
            same_values(&same(), &same()),
            "two runs with one key are the same credential, whatever they would sign"
        );
        let mut other = signed_injection(Ok(vec![("Authorization", "SIG whatever")]), None);
        if let Form::Signed(signed) = &mut other.form {
            signed.key = "a-rotated-key".to_string();
        }
        assert!(
            !same_values(&same(), &[other]),
            "a rotated key is a new credential"
        );
    }
}
