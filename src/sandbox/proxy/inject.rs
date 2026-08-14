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

    /// The header names this injection puts on a request, answerable without running anything.
    ///
    /// This is what a caller needs before the value exists: which headers to skip when remembering
    /// the cage's own credentials, and whether this request carries a credential at all.
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
}

impl HeaderLookup for Vec<(String, String)> {
    fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
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
                let asked = format!("{} {}{}", req.method, req.host, req.target);
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
                                &format!("{asked} set {}", names.join(", ")),
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
                                &asked,
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
    /// Whether this needle was **learned from traffic** rather than derived from a declaration.
    ///
    /// It decides what survives a re-resolution. A declared needle is replaced by the re-resolved
    /// value of the same declaration; an observed one has no declaration behind it, so nothing
    /// replaces it and dropping it is simply losing it — see [`Credentials::replace`].
    observed: bool,
}

impl SecretNeedle {
    /// A needle whose name is the credential's logical name — for a value a declaration produced.
    pub(crate) fn named(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        let finder = memchr::memmem::Finder::new(&bytes).into_owned();
        Self {
            name: name.into(),
            bytes,
            finder,
            observed: false,
        }
    }

    /// A needle for a credential sbx **saw** rather than issued: an app's own sign-in, remembered by
    /// [`Credentials::observe`] so the tripwires cover it too.
    fn learned(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            observed: true,
            ..Self::named(name, bytes)
        }
    }

    /// Whether this needle was learned from traffic rather than declared.
    fn is_observed(&self) -> bool {
        self.observed
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
}

impl Credentials {
    /// The state as first resolved, host-side, before the cage started.
    pub(crate) fn new(
        injections: Vec<HeaderInjection>,
        needles: Vec<SecretNeedle>,
        min_len: usize,
    ) -> Self {
        Self {
            current: std::sync::RwLock::new(std::sync::Arc::new(CredentialSet {
                injections,
                needles,
            })),
            min_len,
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
    /// to no declaration, so nothing refuses it on the way out, masks it on the way back, or hides
    /// it from `sbx net logs`. sbx already *sees* it — it terminates the TLS — so the only question
    /// is whether it retains it. Retaining it costs a value held in host memory, never written and
    /// never logged; not retaining it leaves the credential with no protection at all.
    ///
    /// Only the injections are authoritative for what gets *sent*: this never adds an injection, so
    /// observing can change what is scanned but never what the cage authenticates as.
    pub(crate) fn observe(&self, header: &str, value: &str) -> bool {
        let credential = credential_in(value);
        // The higher of the two floors. `OBSERVE_MIN_LEN` is not itself configurable: it states a
        // *relation* — an inferred credential is held to a stricter floor than a declared one — and
        // that relation is what breaks the moment a launch raises `[redact] min_len` above it. Take
        // the maximum and it holds at every setting.
        if credential.len() < OBSERVE_MIN_LEN.max(self.min_len) {
            return false;
        }
        let bytes = credential.as_bytes();
        {
            let current = self.snapshot();
            if current.needles.len() >= OBSERVE_MAX
                || current.needles.iter().any(|n| n.as_bytes() == bytes)
            {
                return false;
            }
        }
        let Ok(mut current) = self.current.write() else {
            return false;
        };
        // Re-checked under the write lock: two threads can reach the check above with the same new
        // credential, and a duplicate needle would scan the same bytes twice for the same result.
        if current.needles.len() >= OBSERVE_MAX
            || current.needles.iter().any(|n| n.as_bytes() == bytes)
        {
            return false;
        }
        let mut needles = current.needles.clone();
        needles.push(SecretNeedle::learned(
            format!("observed:{header}"),
            bytes.to_vec(),
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
    /// Reads through a [`HeaderLookup`] so every plane can call it with what it already holds: the
    /// HTTP/1.1 planes' parsed pairs, and the HTTP/2 plane's decoded header map. The alternative was
    /// a signature only one plane could satisfy, which is how this ended up running on one plane out
    /// of three in the first place.
    pub(crate) fn observe_head(&self, headers: &dyn HeaderLookup, injected: &[&str]) -> usize {
        OBSERVED_AUTH_HEADERS
            .iter()
            .filter(|name| !injected.iter().any(|inj| name.eq_ignore_ascii_case(inj)))
            .filter_map(|name| headers.get(name).map(|value| (*name, value)))
            .filter(|(name, value)| self.observe(name, value))
            .count()
    }
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
const OBSERVE_MAX: usize = 8;

/// The credential inside an auth header value: the token, with a `Bearer`/`Basic`/`Token` scheme
/// prefix removed. The bare token is what matters, since that is the spelling that would appear if
/// it leaked somewhere other than this header.
fn credential_in(value: &str) -> &str {
    let value = value.trim();
    for scheme in ["Bearer ", "bearer ", "Basic ", "basic ", "Token ", "token "] {
        if let Some(rest) = value.strip_prefix(scheme) {
            return rest.trim();
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
        Credentials::new(injections, needles, MIN_LEN_DEFAULT)
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
            creds.observe("authorization", "Bearer app-own-token-abcdefgh"),
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
        assert!(creds.observe("authorization", "Bearer tok-0123456789abcdef"));
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
        assert!(!creds.observe("authorization", "Bearer short"));
        assert!(creds.snapshot().needles.is_empty());
    }

    /// Lowering the declared floor must not lower this one: an observed credential was inferred
    /// rather than named by a human, so it stays on the stricter of the two.
    #[test]
    fn a_lowered_declared_floor_does_not_lower_the_observed_one() {
        let creds = Credentials::new(Vec::new(), Vec::new(), 4);
        // 12 bytes: over the launch's floor, under the inferred one.
        assert!(!creds.observe("authorization", "Bearer tok-01234567"));
        assert!(creds.snapshot().needles.is_empty());
    }

    /// Raising it past the inferred floor does raise this one: a launch that says a credential is
    /// only worth scanning for above 24 bytes means it for the ones it did not declare too.
    #[test]
    fn a_raised_declared_floor_raises_the_observed_one() {
        let creds = Credentials::new(Vec::new(), Vec::new(), 24);
        // 20 bytes: over the inferred floor, under the launch's.
        assert!(!creds.observe("authorization", "Bearer tok-0123456789abcdef"));
        assert!(creds.snapshot().needles.is_empty());
        // 26 bytes clears both.
        assert!(creds.observe("authorization", "Bearer tok-0123456789abcdefghijkl"));
        assert_eq!(creds.snapshot().needles.len(), 1);
    }

    /// Every needle is scanned against every request head and every response chunk, so the same
    /// credential seen on a thousand requests must cost one needle, not a thousand.
    #[test]
    fn the_same_credential_is_kept_once_and_the_set_is_capped() {
        let creds = default_creds(Vec::new(), Vec::new());
        assert!(creds.observe("authorization", "Bearer tok-0123456789abcdef"));
        assert!(!creds.observe("authorization", "Bearer tok-0123456789abcdef"));
        assert_eq!(creds.snapshot().needles.len(), 1);

        for i in 0..20 {
            creds.observe("authorization", &format!("Bearer tok-{i:0>20}"));
        }
        assert_eq!(
            creds.snapshot().needles.len(),
            OBSERVE_MAX,
            "the scan set is bounded whatever the cage rotates through"
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
        );
        assert_eq!(kept, 1, "only the auth header counts");
        let set = creds.snapshot();
        assert_eq!(set.needles.len(), 1);
        assert_eq!(set.needles[0].as_bytes(), b"tok-0123456789abcdef");
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
