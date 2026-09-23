//! A credential state as it crosses from the launch to the egress proxy.
//!
//! The proxy is to run in a process of its own, and its credentials are handed to it at start and
//! again at every re-resolution. Like its policy ([`crate::allowlist::EgressPolicy::encode`]), it
//! already receives them through this form today, decoded from the bytes the launch encoded: a
//! field the form drops is dropped on every launch and every refresh, where the suites see it,
//! rather than on the day the proxy moves.
//!
//! Two things do not cross as bytes. A needle's searcher and failure table are rebuilt on arrival
//! from its value, the way a `re:` rule's automaton is. And a signer's running plugin is not data:
//! it crosses beside the bytes, in [`Transfer`]'s list of signers, which the bytes name by position
//! and a process boundary turns into the descriptors of the plugins' sockets.
//!
//! The bytes hold every secret the state does, in the clear, since they are what the proxy
//! injects. They live no longer than the decoding that consumes them, and a malformed document is
//! reported by its position alone: the parser's own message may quote the value it stopped on.

use super::{CredentialSet, Credentials, Form, HeaderInjection, SecretNeedle, Signed};
use crate::allowlist::Rule;
use crate::plugins::signer::BodyDigest;
use crate::sandbox::broker::SecretMarker;
use crate::sandbox::signer::Signing;
use serde::{Deserialize, Serialize};
use std::io;
use std::sync::{Arc, Mutex};

/// A signer's running plugin, as an injection holds it.
type SignerProcess = Arc<Mutex<dyn Signing>>;

/// A credential state in the form it is handed over: the document, and the running signers it
/// names by position.
pub(crate) struct Transfer {
    bytes: Vec<u8>,
    signers: Vec<SignerProcess>,
}

impl CredentialSet {
    /// This set as it is handed to the proxy.
    pub(crate) fn encode(&self) -> io::Result<Transfer> {
        let mut signers = Vec::new();
        let wire = SetWire::from_set(self, &mut signers);
        Ok(Transfer {
            bytes: to_bytes(&wire)?,
            signers,
        })
    }

    /// The set [`CredentialSet::encode`] handed over. A malformed document, or one naming a signer
    /// that was not handed over with it, is an error: a proxy given part of a set injects a
    /// different one.
    pub(crate) fn decode(transfer: Transfer) -> io::Result<Self> {
        let wire: SetWire = from_bytes(&transfer.bytes)?;
        wire.into_set(&transfer.signers)
    }
}

impl Credentials {
    /// The state as the proxy is handed it at start: the live set, and the floor and the shared
    /// groups a needle it learns later is built with.
    ///
    /// What the state accumulates while it runs does not cross, because a state handed over at
    /// start has accumulated nothing: its generation is the first, and its masking history is its
    /// live set, which [`Credentials::new`] seeds it with on arrival.
    pub(crate) fn encode(&self) -> io::Result<Transfer> {
        let mut signers = Vec::new();
        let wire = CredentialsWire {
            set: SetWire::from_set(&self.snapshot(), &mut signers),
            min_len: self.min_len,
            shared_credential: self.shared_credential.clone(),
        };
        Ok(Transfer {
            bytes: to_bytes(&wire)?,
            signers,
        })
    }

    /// The state [`Credentials::encode`] handed over, under the same rule as
    /// [`CredentialSet::decode`].
    pub(crate) fn decode(transfer: Transfer) -> io::Result<Self> {
        let wire: CredentialsWire = from_bytes(&transfer.bytes)?;
        let CredentialSet {
            injections,
            needles,
        } = wire.set.into_set(&transfer.signers)?;
        Ok(Credentials::new(
            injections,
            needles,
            wire.min_len,
            wire.shared_credential,
        ))
    }
}

#[derive(Serialize, Deserialize)]
struct CredentialsWire {
    set: SetWire,
    min_len: usize,
    shared_credential: Vec<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
struct SetWire {
    injections: Vec<InjectionWire>,
    needles: Vec<NeedleWire>,
}

#[derive(Serialize, Deserialize)]
struct InjectionWire {
    rule: Rule,
    form: FormWire,
}

/// [`Form`] as it crosses: a signer's process is carried by its position in [`Transfer`]'s list.
#[derive(Serialize, Deserialize)]
enum FormWire {
    Fixed {
        header: String,
        value: String,
    },
    Signed {
        name: String,
        sets: Vec<String>,
        sees: Vec<String>,
        key: String,
        marker: Option<MarkerWire>,
        process: usize,
        body_digest: Option<DigestWire>,
    },
}

#[derive(Serialize, Deserialize)]
struct MarkerWire {
    marker: Vec<u8>,
    secret: Vec<u8>,
    watch: bool,
}

/// [`BodyDigest`] as it crosses. A mirror rather than a derive on the type itself, which a
/// manifest spells in its own words: a derived reader would accept this form there too.
#[derive(Serialize, Deserialize)]
enum DigestWire {
    Sha256,
}

/// A needle as it crosses: its value and what it is scoped to. The searcher and the failure table
/// are rebuilt from the value on arrival.
#[derive(Serialize, Deserialize)]
struct NeedleWire {
    name: String,
    bytes: Vec<u8>,
    observed: bool,
    dest: Option<Vec<String>>,
}

impl SetWire {
    // Every conversion below takes its source apart field by field, with no `..`: a field added to
    // one of these types then fails to compile here instead of failing to cross.
    fn from_set(set: &CredentialSet, signers: &mut Vec<SignerProcess>) -> Self {
        let CredentialSet {
            injections,
            needles,
        } = set;
        SetWire {
            injections: injections
                .iter()
                .map(|injection| InjectionWire::from_injection(injection, signers))
                .collect(),
            needles: needles.iter().map(NeedleWire::from_needle).collect(),
        }
    }

    fn into_set(self, signers: &[SignerProcess]) -> io::Result<CredentialSet> {
        let SetWire {
            injections,
            needles,
        } = self;
        Ok(CredentialSet {
            injections: injections
                .into_iter()
                .map(|injection| injection.into_injection(signers))
                .collect::<io::Result<_>>()?,
            needles: needles.into_iter().map(NeedleWire::into_needle).collect(),
        })
    }
}

impl InjectionWire {
    fn from_injection(injection: &HeaderInjection, signers: &mut Vec<SignerProcess>) -> Self {
        let HeaderInjection { rule, form } = injection;
        let form = match form {
            Form::Fixed { header, value } => FormWire::Fixed {
                header: header.clone(),
                value: value.clone(),
            },
            Form::Signed(Signed {
                name,
                sets,
                sees,
                key,
                marker,
                process,
                body_digest,
            }) => {
                // One entry per process, so two injections served by one plugin are served by one
                // on arrival too.
                let process = match signers.iter().position(|held| Arc::ptr_eq(held, process)) {
                    Some(at) => at,
                    None => {
                        signers.push(Arc::clone(process));
                        signers.len() - 1
                    }
                };
                FormWire::Signed {
                    name: name.clone(),
                    sets: sets.clone(),
                    sees: sees.clone(),
                    key: key.clone(),
                    marker: marker.as_deref().map(|marker| {
                        let (marker, secret, watch) = marker.parts();
                        MarkerWire {
                            marker: marker.to_vec(),
                            secret: secret.to_vec(),
                            watch,
                        }
                    }),
                    process,
                    body_digest: body_digest.map(|digest| match digest {
                        BodyDigest::Sha256 => DigestWire::Sha256,
                    }),
                }
            }
        };
        InjectionWire {
            rule: rule.clone(),
            form,
        }
    }

    fn into_injection(self, signers: &[SignerProcess]) -> io::Result<HeaderInjection> {
        let InjectionWire { rule, form } = self;
        let form = match form {
            FormWire::Fixed { header, value } => Form::Fixed { header, value },
            FormWire::Signed {
                name,
                sets,
                sees,
                key,
                marker,
                process,
                body_digest,
            } => {
                let Some(process) = signers.get(process) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "credentials: signer `{name}` names process {process}, and {} were \
                             handed over",
                            signers.len()
                        ),
                    ));
                };
                Form::Signed(Signed {
                    name,
                    sets,
                    sees,
                    key,
                    marker: marker.map(
                        |MarkerWire {
                             marker,
                             secret,
                             watch,
                         }| {
                            Arc::new(SecretMarker::from_parts(marker, secret, watch))
                        },
                    ),
                    process: Arc::clone(process),
                    body_digest: body_digest.map(|digest| match digest {
                        DigestWire::Sha256 => BodyDigest::Sha256,
                    }),
                })
            }
        };
        Ok(HeaderInjection { rule, form })
    }
}

impl NeedleWire {
    fn from_needle(needle: &SecretNeedle) -> Self {
        let SecretNeedle {
            name,
            bytes,
            finder: _,
            fail: _,
            observed,
            dest,
        } = needle;
        NeedleWire {
            name: name.clone(),
            bytes: bytes.clone(),
            observed: *observed,
            dest: dest.clone(),
        }
    }

    fn into_needle(self) -> SecretNeedle {
        let NeedleWire {
            name,
            bytes,
            observed,
            dest,
        } = self;
        SecretNeedle {
            observed,
            dest,
            ..SecretNeedle::named(name, bytes)
        }
    }
}

fn to_bytes(wire: &impl Serialize) -> io::Result<Vec<u8>> {
    serde_json::to_vec(wire).map_err(|e| io::Error::other(format!("credentials: {}", position(&e))))
}

fn from_bytes<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> io::Result<T> {
    serde_json::from_slice(bytes).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("credentials: {}", position(&e)),
        )
    })
}

/// Where a document went wrong, without what it held there.
fn position(e: &serde_json::Error) -> String {
    format!(
        "malformed ({:?}) at line {} column {}",
        e.classify(),
        e.line(),
        e.column()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::signer::{SignRequest, Signature};

    struct Inert;

    impl Signing for Inert {
        fn sign(&mut self, _req: &SignRequest<'_>) -> Result<Signature, String> {
            Err("a stand-in".to_string())
        }
    }

    fn signed(
        host: &str,
        process: &SignerProcess,
        marker: Option<SecretMarker>,
    ) -> HeaderInjection {
        HeaderInjection {
            rule: crate::allowlist::classify(host).unwrap(),
            form: Form::Signed(Signed {
                name: "demo-sigv4".to_string(),
                sets: vec!["Authorization".to_string(), "X-Amz-Date".to_string()],
                sees: vec!["X-Amz-Content-Sha256".to_string()],
                key: "the-signing-key".to_string(),
                marker: marker.map(Arc::new),
                process: Arc::clone(process),
                body_digest: Some(BodyDigest::Sha256),
            }),
        }
    }

    /// A set in which every field of every type holds a value other than its default.
    fn full_set(process: &SignerProcess) -> CredentialSet {
        let mut rule = crate::allowlist::classify("{GET,POST} api.fixed.test/v1").unwrap();
        rule.group = Some("apis".to_string());
        rule.builtin = true;
        CredentialSet {
            injections: vec![
                HeaderInjection {
                    rule,
                    form: Form::Fixed {
                        header: "X-Api-Key".to_string(),
                        value: "fixed-secret-value".to_string(),
                    },
                },
                signed(
                    "signed.test",
                    process,
                    Some(SecretMarker::from_parts(
                        b"SBX-SECRET-00".to_vec(),
                        b"marker-secret".to_vec(),
                        true,
                    )),
                ),
                // A second declaration served by the same running plugin.
                signed("other.test", process, None),
            ],
            needles: vec![
                SecretNeedle::named("declared", b"fixed-secret-value".to_vec()),
                SecretNeedle::learned(
                    "observed:authorization",
                    b"an-app-own-token-value".to_vec(),
                    vec!["login.test".to_string(), "api.test".to_string()],
                ),
            ],
        }
    }

    fn same_injection(a: &HeaderInjection, b: &HeaderInjection) {
        let HeaderInjection { rule, form } = a;
        assert_eq!(rule, &b.rule);
        assert_eq!(rule.group, b.rule.group, "`==` ignores the group");
        assert_eq!(rule.builtin, b.rule.builtin, "`==` ignores `builtin`");
        match (form, &b.form) {
            (
                Form::Fixed { header, value },
                Form::Fixed {
                    header: h2,
                    value: v2,
                },
            ) => assert_eq!((header, value), (h2, v2)),
            (
                Form::Signed(Signed {
                    name,
                    sets,
                    sees,
                    key,
                    marker,
                    process,
                    body_digest,
                }),
                Form::Signed(other),
            ) => {
                assert_eq!(
                    (name, sets, sees, key, body_digest),
                    (
                        &other.name,
                        &other.sets,
                        &other.sees,
                        &other.key,
                        &other.body_digest
                    )
                );
                assert_eq!(
                    marker.as_deref().map(SecretMarker::parts),
                    other.marker.as_deref().map(SecretMarker::parts)
                );
                assert!(
                    Arc::ptr_eq(process, &other.process),
                    "the running plugin, not another one"
                );
            }
            _ => panic!("the form changed kind in crossing"),
        }
    }

    fn same_needle(a: &SecretNeedle, b: &SecretNeedle) {
        let SecretNeedle {
            name,
            bytes,
            finder,
            fail,
            observed,
            dest,
        } = a;
        assert_eq!(
            (name, bytes, observed, dest),
            (&b.name, &b.bytes, &b.observed, &b.dest)
        );
        assert_eq!(fail, &b.fail, "the failure table is rebuilt from the value");
        assert_eq!(finder.needle(), b.finder.needle(), "and so is the searcher");
    }

    fn same_set(a: &CredentialSet, b: &CredentialSet) {
        let CredentialSet {
            injections,
            needles,
        } = a;
        assert_eq!(injections.len(), b.injections.len());
        for (x, y) in injections.iter().zip(&b.injections) {
            same_injection(x, y);
        }
        assert_eq!(needles.len(), b.needles.len());
        for (x, y) in needles.iter().zip(&b.needles) {
            same_needle(x, y);
        }
    }

    #[test]
    fn every_field_of_a_set_survives_the_crossing() {
        let process: SignerProcess = Arc::new(Mutex::new(Inert));
        let set = full_set(&process);
        let transfer = set.encode().unwrap();
        assert_eq!(
            transfer.signers.len(),
            1,
            "one plugin serving two declarations crosses once"
        );
        let first = transfer.bytes.clone();
        let back = CredentialSet::decode(transfer).unwrap();
        same_set(&set, &back);
        assert_eq!(
            back.encode().unwrap().bytes,
            first,
            "and it encodes to the same document again"
        );
    }

    #[test]
    fn a_state_crosses_with_its_floor_and_its_groups_and_starts_afresh() {
        let process: SignerProcess = Arc::new(Mutex::new(Inert));
        let set = full_set(&process);
        let shared = vec![vec!["login.test".to_string(), "*.api.test".to_string()]];
        let state = Credentials::new(set.injections, set.needles, 24, shared.clone());
        let back = Credentials::decode(state.encode().unwrap()).unwrap();
        same_set(&state.snapshot(), &back.snapshot());
        assert_eq!(back.min_len, 24);
        assert_eq!(back.shared_credential, shared);
        assert_eq!(back.generation(), 0);
        let masking = back.masking_needles();
        assert_eq!(masking.len(), back.snapshot().needles.len());
        for (x, y) in masking.iter().zip(&back.snapshot().needles) {
            same_needle(x, y);
        }
    }

    #[test]
    fn a_document_naming_a_signer_not_handed_over_is_refused() {
        let process: SignerProcess = Arc::new(Mutex::new(Inert));
        let transfer = full_set(&process).encode().unwrap();
        let without = Transfer {
            bytes: transfer.bytes,
            signers: Vec::new(),
        };
        let e = CredentialSet::decode(without).err().expect("refused");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    /// A malformed document is reported by where it broke, never by what it held there: the bytes
    /// are credentials, and the parser's own message quotes the value it stopped on.
    #[test]
    fn a_malformed_document_is_refused_without_quoting_it() {
        let process: SignerProcess = Arc::new(Mutex::new(Inert));
        let mut transfer = full_set(&process).encode().unwrap();
        let text = String::from_utf8(transfer.bytes).unwrap();
        // A secret where a number is expected: the parser's message would name it.
        transfer.bytes = text
            .replacen("\"watch\":true", "\"watch\":\"marker-secret\"", 1)
            .into_bytes();
        let e = CredentialSet::decode(transfer).err().expect("refused");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(
            !e.to_string().contains("marker-secret"),
            "the error quotes the document: {e}"
        );
    }
}
