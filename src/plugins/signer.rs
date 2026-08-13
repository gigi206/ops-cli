//! The signer plugin type: a third-party value-former at an HTTP request's auth point.
//!
//! A resolver plugin answers *where a value comes from*; a broker plugin answers *how the cage uses
//! a host resource without holding it*. A signer answers the question neither can: **what does
//! authenticating THIS request look like?**
//!
//! sbx already injects a credential into outbound requests — a header name and a value formed once,
//! host-side, from the resolved plaintext ([`crate::config::HeaderShape`]). That covers every
//! protocol whose auth point is a constant: a bearer token, a Basic pair, an API key. It cannot
//! cover an auth point whose value depends on the request itself — a signature over the method, the
//! path and the query, a per-request nonce, a challenge answered in kind. Those protocols are not
//! exotic; they are what most cloud APIs authenticate with, and none of them can be expressed by a
//! value that was formed before the request existed.
//!
//! **The window is one host, and it is inherited rather than invented.** A signer is named by a
//! `[[secret]]` declaration, whose `to` is a single concrete destination — a `*.` wildcard or a
//! `re:` regex is refused at validation. So a signer is shown the requests of exactly the host its
//! declaration names, which is the host that already receives that credential on every request. It
//! is never shown another host's traffic, and there is no spelling of a manifest that widens that:
//! the destination comes from the config, never from here.
//!
//! **The plugin is a pure filter**, on the terms [`super::broker`] set: no listening socket, no
//! network descriptor, no host resource. It speaks to sbx alone, over stdin/stdout, from a
//! host-side cage with an empty network namespace. What it returns is a set of headers, bounded by
//! what its own manifest declared ([`SignerSpec::sets_headers`]) and refused outright where a
//! header would move the request rather than authenticate it.
//!
//! Those two together are the ceiling: **a signer plugin can never see or place more than the
//! `[[secret]]` declaration naming it already puts on the wire.** It is meant to place it far
//! better — bound to one request instead of replayable on any.

use serde::Deserialize;
use std::path::PathBuf;

/// The most headers a manifest may declare on either list.
///
/// A bound rather than a judgement about protocols: an auth scheme is a handful of headers, and a
/// manifest asking for dozens has stopped describing an auth point. It bounds what one declaration
/// can hold the way [`super::broker::MAX_FRAME_CEILING`] bounds what one frame can read.
pub(crate) const MAX_HEADERS: usize = 32;

/// Headers a signer may never set, whatever its manifest declares. Three families, and the reason
/// differs by family — which is why they are one list with one refusal rather than a rule of thumb:
///
/// - **Where the request goes.** `Host` selects the origin a multi-tenant upstream serves. sbx
///   opened the connection to an address the SSRF guard checked, against a certificate validated
///   for the host the *config* named; a plugin rewriting `Host` would land the credential on a
///   different origin behind the same address, and would let two logical destinations share one
///   pooled connection. The destination is the config's to name.
/// - **Where the request ends.** `Content-Length`, `Transfer-Encoding` and `Trailer` are what sbx
///   re-serializes the head with and streams the body by. A plugin rewriting one desynchronizes
///   sbx's framing from the upstream's — request smuggling, with sbx as the confused party.
/// - **What the connection becomes.** `Connection`, `Upgrade`, `TE` and `Expect` are hop-by-hop.
///   `Upgrade` in particular would turn an inspected request into an opaque tunnel, which is the
///   exact combination the proxy already refuses for a credential-bearing WebSocket: past the
///   handshake nothing can be redacted.
///
/// Compared lowercase, because a header name is case-insensitive and a denial that `Host` passes
/// but `host` does not would be no denial at all.
const NEVER_SET: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "trailer",
    "connection",
    "upgrade",
    "te",
    "expect",
];

/// The prefix of the headers that belong to a proxy hop rather than to the request. sbx *is* the
/// hop: `proxy-authorization` and `proxy-connection` address the layer doing the injecting, so a
/// plugin setting one is speaking to sbx's own transport instead of authenticating to the
/// destination.
const NEVER_SET_PREFIX: &str = "proxy-";

/// The `[signer]` table of a validated manifest: what sbx must know to call a plugin at a request's
/// auth point without understanding the scheme being signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignerSpec {
    /// The headers this plugin may set on a request it signs. Required and non-empty: a signer that
    /// sets nothing authenticates nothing.
    ///
    /// The bound is enforced on the plugin's *answer*, not merely documented by it — a header the
    /// manifest did not declare is refused whatever the plugin returns. That is what makes the
    /// manifest a review surface: reading it tells you every header this plugin can write, and
    /// [`NEVER_SET`] tells you the ones no manifest can declare.
    pub(crate) sets_headers: Vec<String>,
    /// The request headers this plugin is shown, beyond the method, the host and the target, which
    /// it always sees (a signature over a request that cannot see the request is not a signature).
    ///
    /// Empty by default, and deliberately so: a request carries whatever the cage put on it,
    /// including credentials an app obtained by its own sign-in, which belong to no declaration
    /// here. Showing a third-party plugin every header would widen its window past the credential
    /// it was named to form. A plugin that must see one says which.
    pub(crate) sees_headers: Vec<String>,
    /// Whether the plugin is handed the credential's **plaintext**, rather than a marker standing
    /// in for it.
    ///
    /// Off is the structural posture, and the one to reach for: the plugin places a per-connection
    /// marker where the credential belongs, and sbx substitutes the real value into the header on
    /// its way to the wire — the plugin can place a secret it can never read. That is enough for
    /// any scheme whose credential is *carried*.
    ///
    /// It is not enough for one whose credential is *computed*: an HMAC over the canonical request
    /// is a function of the key, so a signer that derives one needs the key material, exactly as a
    /// resolver holds a plaintext it read. On, that is what it gets — a labelled step down, taken
    /// by declaring it in the manifest that was reviewed rather than in the config of the machine
    /// that runs it.
    pub(crate) reads_secret: bool,
}

/// A validated signer plugin: `exec` is run host-side and, on stdin/stdout, is asked what
/// authenticating one request looks like. Carries no secret and is safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignerPlugin {
    /// The plugin's name, which is also the key it is registered and configured under.
    pub(crate) name: String,
    /// The plugin's own directory, bound read-only into the runner's cage so the executable (and
    /// any sibling helper it ships) is reachable at its real path.
    pub(crate) dir: PathBuf,
    /// Absolute path to the executable: the plugin directory joined with the manifest's
    /// (directory-relative, traversal-free) `exec`.
    pub(crate) exec: PathBuf,
    /// The least-privilege grant the runner gives the plugin, minus the grants this type refuses
    /// outright (see [`check_sandbox`]).
    pub(crate) sandbox: super::SandboxGrant,
    /// What sbx must know about the auth point.
    pub(crate) signer: SignerSpec,
    /// The manifest's declared version, if any. Display-only.
    pub(crate) version: Option<String>,
    /// The manifest's one-line description, if any. Display-only.
    pub(crate) description: Option<String>,
    /// What the *host* supplies to this plugin, from a `[plugin.<name>]` table in the global or a
    /// trusted project config. Empty unless one is declared.
    pub(crate) host: super::HostConfig,
}

impl SignerPlugin {
    /// The plugin's on-disk identity: its directory name, which is the token `sbx plugins rm`
    /// takes and the key its origin record is filed under.
    pub(crate) fn dir_name(&self) -> &str {
        super::dir_name_of(&self.dir, &self.name)
    }

    /// Whether the executable would be accepted by the runner: a regular file owned by us and not
    /// writable by group or other. The very check the runner enforces, so `sbx plugins` can
    /// surface a gap the runner would refuse on.
    pub(crate) fn check_exec(&self) -> Result<(), String> {
        super::check_exec_at(&self.exec)
    }
}

/// The raw `[signer]` table, before validation. Every field is optional so a missing one yields a
/// precise "missing X" error rather than a generic parse failure, and unknown fields are refused
/// for the reason the rest of the manifest refuses them: a key nothing reads would leave an author
/// believing they had declared something they had not.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawSigner {
    #[serde(default)]
    sets_headers: Vec<String>,
    #[serde(default)]
    sees_headers: Vec<String>,
    #[serde(default)]
    reads_secret: bool,
}

/// Validate a manifest's `[signer]` table.
pub(super) fn validate(raw: RawSigner, name: &str) -> Result<SignerSpec, String> {
    if raw.sets_headers.is_empty() {
        return Err(format!(
            "missing `sets_headers` — a signer is asked what authenticating a request looks like, \
             so `{name}` must name at least one header it may set"
        ));
    }
    let sets_headers = check_header_list(raw.sets_headers, "sets_headers")?;
    for header in &sets_headers {
        let lowered = header.to_ascii_lowercase();
        if NEVER_SET.contains(&lowered.as_str()) || lowered.starts_with(NEVER_SET_PREFIX) {
            return Err(format!(
                "`sets_headers` names `{header}`, which moves or reframes the request rather than \
                 authenticating it — where a request goes, where it ends and what the connection \
                 becomes are sbx's, never a plugin's"
            ));
        }
    }
    let sees_headers = check_header_list(raw.sees_headers, "sees_headers")?;

    Ok(SignerSpec {
        sets_headers,
        sees_headers,
        reads_secret: raw.reads_secret,
    })
}

/// Validate one header list: every entry a well-formed field name, no entry twice, and no more
/// than [`MAX_HEADERS`] of them. Shared by both lists because both are read as header names, and a
/// rule that held on one but not the other would be a rule nobody could state.
fn check_header_list(headers: Vec<String>, field: &str) -> Result<Vec<String>, String> {
    if headers.len() > MAX_HEADERS {
        return Err(format!(
            "`{field}` names {} headers, above the {MAX_HEADERS} a signer may declare",
            headers.len()
        ));
    }
    for (i, header) in headers.iter().enumerate() {
        if !is_header_name(header) {
            return Err(format!(
                "`{field}` has `{header}`, which is not a header field name"
            ));
        }
        // Case-insensitively, because that is how the header is matched on the wire: two spellings
        // of one name are two declarations of one grant that a later edit can make disagree.
        if headers[..i]
            .iter()
            .any(|prev| prev.eq_ignore_ascii_case(header))
        {
            return Err(format!(
                "`{field}` names `{header}` twice — one header, one declaration"
            ));
        }
    }
    Ok(headers)
}

/// Whether `name` is a header field name: a non-empty HTTP token (RFC 9110 §5.6.2). Checked rather
/// than assumed because a name with a colon, a space or a control byte would not be a header at all
/// — it would be a way to write a second line into the request head.
fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// The grants this type refuses whatever a manifest declares, checked against the already-parsed
/// `[sandbox]` table so the refusal names the field rather than the consequence.
///
/// Spelled out rather than shared with [`super::broker::check_sandbox`], which refuses the same
/// three fields: what a refusal has to carry is the *argument*, and the argument differs for every
/// one of them. A shared function would keep the three `if`s and lose the three reasons.
pub(super) fn check_sandbox(grant: &super::SandboxGrant) -> Result<(), String> {
    if grant.network {
        return Err(
            "a signer plugin may not declare `network` — it is shown a credential's requests and, \
             where it reads one, the credential itself, so network reach here is an exfiltration \
             path for the very secret it is forming"
                .to_string(),
        );
    }
    if grant.state {
        return Err(
            "a signer plugin may not declare `state` — a signature is derived per request and \
             kept by nobody, and a writable directory would be somewhere a credential could come \
             to rest"
                .to_string(),
        );
    }
    if !grant.brokers.is_empty() {
        return Err(
            "a signer plugin may not declare `brokers` — a broker fences a cage's access to a host \
             resource, and a signer has no cage and reaches no resource: sbx hands it a request \
             and takes back headers"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw() -> RawSigner {
        RawSigner {
            sets_headers: vec!["Authorization".to_string()],
            sees_headers: Vec::new(),
            reads_secret: false,
        }
    }

    #[test]
    fn a_well_formed_signer_table_validates() {
        let spec = validate(raw(), "fake").expect("valid");
        assert_eq!(spec.sets_headers, vec!["Authorization".to_string()]);
        assert!(spec.sees_headers.is_empty());
        assert!(
            !spec.reads_secret,
            "the plaintext is the wider grant, so it must be off by default"
        );
    }

    #[test]
    fn a_signer_that_sets_nothing_is_refused() {
        let err = validate(
            RawSigner {
                sets_headers: Vec::new(),
                ..raw()
            },
            "fake",
        )
        .expect_err("a signer that writes no header authenticates nothing");
        assert!(err.contains("sets_headers"), "{err}");
    }

    /// The load-bearing refusal of this type. A signer forms a credential; a signer that could set
    /// `Host` would choose where the credential lands, and one that could set `Content-Length`
    /// would choose where sbx thinks the request ends.
    #[test]
    fn the_headers_that_move_or_reframe_a_request_are_refused() {
        for header in [
            "Host",
            "Content-Length",
            "Transfer-Encoding",
            "Trailer",
            "Connection",
            "Upgrade",
            "TE",
            "Expect",
            "Proxy-Authorization",
        ] {
            let err = validate(
                RawSigner {
                    sets_headers: vec![header.to_string()],
                    ..raw()
                },
                "fake",
            )
            .expect_err("a header that moves or reframes the request is not a signer's to set");
            assert!(err.contains(header), "the refusal must name it: {err}");
        }
    }

    /// A header is case-insensitive on the wire, so a denial one spelling passes is no denial.
    #[test]
    fn the_refused_headers_are_refused_in_any_spelling() {
        for header in ["host", "hOsT", "CONTENT-LENGTH", "proxy-connection"] {
            let err = validate(
                RawSigner {
                    sets_headers: vec![header.to_string()],
                    ..raw()
                },
                "fake",
            )
            .expect_err("case is not a way past the list");
            assert!(err.contains(header), "{err}");
        }
    }

    #[test]
    fn a_name_that_is_not_a_header_is_refused() {
        for bad in ["Authorization: x", "two words", "x\ny", "", "a:b"] {
            let err = validate(
                RawSigner {
                    sets_headers: vec![bad.to_string()],
                    ..raw()
                },
                "fake",
            )
            .expect_err("a header name is a token, and a name that is not one writes a new line");
            assert!(err.contains("header field name"), "{err}");
        }
    }

    #[test]
    fn one_header_declared_twice_is_refused_however_it_is_spelled() {
        let err = validate(
            RawSigner {
                sets_headers: vec!["Authorization".to_string(), "authorization".to_string()],
                ..raw()
            },
            "fake",
        )
        .expect_err("two spellings of one name are two declarations of one grant");
        assert!(err.contains("twice"), "{err}");

        let err = validate(
            RawSigner {
                sees_headers: vec!["X-Amz-Date".to_string(), "X-Amz-Date".to_string()],
                ..raw()
            },
            "fake",
        )
        .expect_err("the rule holds on both lists");
        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn a_manifest_may_not_declare_more_headers_than_the_ceiling() {
        let many: Vec<String> = (0..=MAX_HEADERS).map(|i| format!("X-H{i}")).collect();
        let err = validate(
            RawSigner {
                sets_headers: many,
                ..raw()
            },
            "fake",
        )
        .expect_err("a manifest asking for dozens has stopped describing an auth point");
        assert!(err.contains("above the"), "{err}");
    }

    /// A signer sees the request it signs. Nothing it declares may reach the host's network, hold
    /// anything across runs, or be fenced behind a broker.
    #[test]
    fn the_grants_a_signer_never_gets_are_refused_by_name() {
        let refused = [
            (
                super::super::SandboxGrant {
                    network: true,
                    ..Default::default()
                },
                "network",
            ),
            (
                super::super::SandboxGrant {
                    state: true,
                    ..Default::default()
                },
                "state",
            ),
            (
                super::super::SandboxGrant {
                    brokers: vec!["gpg-agent".to_string()],
                    ..Default::default()
                },
                "brokers",
            ),
        ];
        for (grant, field) in refused {
            let err = check_sandbox(&grant).expect_err("refused");
            assert!(err.contains(field), "{err}");
        }
        check_sandbox(&super::super::SandboxGrant::default()).expect("a plain grant is admissible");
    }
}
