//! The egress policy as bytes: the form it crosses a process boundary in.
//!
//! The proxy is to run in a process of its own, holding nothing it does not need, and the policy is
//! one of the things it is handed at start. That hand-over is a serialization, and a serialization
//! can drop a field in silence — `Rule`'s own equality ignores two of them, `group` and `builtin`,
//! the second of which the SSRF guard reads. So the proxy already receives its policy through this
//! form today, decoded from the bytes [`EgressPolicy::encode`] produced, rather than as the value
//! the launch built: a field this form loses is lost on every launch, where the suites that drive
//! real cages see it, instead of on the day the proxy moves.
//!
//! JSON through `serde_json`, already a dependency. A `re:` rule crosses as its pattern and is
//! compiled again on arrival by the same call the grammar makes; a pattern that no longer compiles
//! is an error, never a rule dropped.

use super::{EgressPolicy, IpAddr, Ports, Regex, RuleKind};
use serde::{Deserialize, Serialize};
use std::io;

/// [`RuleKind`] as it crosses: the same variants, with a `re:` rule carried by its pattern alone,
/// since a compiled regex is not data.
#[derive(Clone, Serialize, Deserialize)]
pub(super) enum RuleKindWire {
    Ip(IpAddr, Ports),
    Host(String, Ports),
    Subdomain(String, Ports),
    Url {
        host: String,
        ports: Ports,
        path: String,
        subtree: bool,
    },
    Regex {
        pattern: String,
    },
}

impl From<RuleKind> for RuleKindWire {
    fn from(kind: RuleKind) -> Self {
        match kind {
            RuleKind::Ip(ip, ports) => RuleKindWire::Ip(ip, ports),
            RuleKind::Host(host, ports) => RuleKindWire::Host(host, ports),
            RuleKind::Subdomain(domain, ports) => RuleKindWire::Subdomain(domain, ports),
            RuleKind::Url {
                host,
                ports,
                path,
                subtree,
            } => RuleKindWire::Url {
                host,
                ports,
                path,
                subtree,
            },
            RuleKind::Regex { pattern, .. } => RuleKindWire::Regex { pattern },
        }
    }
}

impl TryFrom<RuleKindWire> for RuleKind {
    type Error = String;

    fn try_from(wire: RuleKindWire) -> Result<Self, Self::Error> {
        Ok(match wire {
            RuleKindWire::Ip(ip, ports) => RuleKind::Ip(ip, ports),
            RuleKindWire::Host(host, ports) => RuleKind::Host(host, ports),
            RuleKindWire::Subdomain(domain, ports) => RuleKind::Subdomain(domain, ports),
            RuleKindWire::Url {
                host,
                ports,
                path,
                subtree,
            } => RuleKind::Url {
                host,
                ports,
                path,
                subtree,
            },
            // The grammar's own call, so a pattern means on arrival what it meant when parsed.
            RuleKindWire::Regex { pattern } => {
                let re =
                    Regex::new(&pattern).map_err(|e| format!("invalid regex `{pattern}`: {e}"))?;
                RuleKind::Regex { pattern, re }
            }
        })
    }
}

impl EgressPolicy {
    /// This policy as the bytes the proxy is handed.
    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| io::Error::other(format!("egress policy: {e}")))
    }

    /// The policy [`EgressPolicy::encode`] wrote. A malformed document, or a `re:` pattern that no
    /// longer compiles, is an error: a proxy started on part of its policy enforces a different one.
    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("egress policy: {e}")))
    }
}
