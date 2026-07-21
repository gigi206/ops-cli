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
pub(crate) struct SecretNeedle(Vec<u8>);

impl SecretNeedle {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The needle bytes — used by the scan, and by the egress tests to confirm a needle was
    /// derived. Deliberately a named method, never `Debug`, so it is only ever read explicitly.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretNeedle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretNeedle(<redacted {} bytes>)", self.0.len())
    }
}
