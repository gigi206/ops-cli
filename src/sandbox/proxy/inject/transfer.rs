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
//! the supervisor keeps the plugin, and what crosses beside the bytes is a descriptor of the
//! conversation with it, one per plugin, which the bytes name by position ([`Transfer`]). The copy
//! that crosses is therefore always the supervisor's ([`Signer::Running`]), and the copy that
//! arrives always the proxy's ([`Signer::Asking`]).
//!
//! The bytes hold every secret the state does, in the clear, since they are what the proxy
//! injects. They live no longer than the decoding that consumes them, and a malformed document is
//! reported by its position alone: the parser's own message may quote the value it stopped on.

use super::{CredentialSet, Credentials, Form, HeaderInjection, SecretNeedle, Signed, Signer};
use crate::allowlist::Rule;
use crate::plugins::signer::BodyDigest;
use crate::sandbox::broker::SecretMarker;
use crate::sandbox::signer::{SignerChannel, SignerProcess};
use serde::{Deserialize, Serialize};
use std::io;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};

/// A credential state in the form it is handed over: the document, and a descriptor of each
/// running signer's conversation, in the order the document names them.
pub(crate) struct Transfer {
    bytes: Vec<u8>,
    signers: Vec<OwnedFd>,
}

impl CredentialSet {
    /// This set as it is handed to the proxy. Only the supervisor's copy crosses: a set holding a
    /// conversation rather than a plugin is refused.
    pub(crate) fn encode(&self) -> io::Result<Transfer> {
        let mut signers = Handed::default();
        let wire = SetWire::from_set(self, &mut signers)?;
        Ok(Transfer {
            bytes: to_bytes(&wire)?,
            signers: signers.fds,
        })
    }

    /// The set [`CredentialSet::encode`] handed over. A malformed document, or one whose signers do
    /// not match the descriptors handed over with it, is an error: a proxy given part of a set
    /// injects a different one.
    pub(crate) fn decode(transfer: Transfer) -> io::Result<Self> {
        let wire: SetWire = from_bytes(&transfer.bytes)?;
        wire.into_set(transfer.signers, None)
    }

    /// [`CredentialSet::decode`] for a set that replaces `current`: a plugin `current` already
    /// talks to keeps its conversation, and the descriptor handed over for it again is closed.
    ///
    /// Two conversations over one plugin's socket would each read the other's answers, so a plugin a
    /// re-resolution kept must be asked through the channel that was already asking it.
    pub(crate) fn decode_over(transfer: Transfer, current: &CredentialSet) -> io::Result<Self> {
        let wire: SetWire = from_bytes(&transfer.bytes)?;
        wire.into_set(transfer.signers, Some(current))
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
        let mut signers = Handed::default();
        let wire = CredentialsWire {
            set: SetWire::from_set(&self.snapshot(), &mut signers)?,
            min_len: self.min_len,
            shared_credential: self.shared_credential.clone(),
        };
        Ok(Transfer {
            bytes: to_bytes(&wire)?,
            signers: signers.fds,
        })
    }

    /// The state [`Credentials::encode`] handed over, under the same rule as
    /// [`CredentialSet::decode`].
    pub(crate) fn decode(transfer: Transfer) -> io::Result<Self> {
        let wire: CredentialsWire = from_bytes(&transfer.bytes)?;
        let CredentialSet {
            injections,
            needles,
        } = wire.set.into_set(transfer.signers, None)?;
        Ok(Credentials::new(
            injections,
            needles,
            wire.min_len,
            wire.shared_credential,
        ))
    }
}

/// The running signers an encoding has met so far: each plugin once, with the descriptor it crosses
/// as.
#[derive(Default)]
struct Handed {
    plugins: Vec<Arc<SignerProcess>>,
    wire: Vec<SignerWire>,
    fds: Vec<OwnedFd>,
}

impl Handed {
    /// The position `signer` crosses at, handing its plugin over the first time it is met.
    fn position(&mut self, signer: &Signer) -> io::Result<usize> {
        let Signer::Running(plugin) = signer else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "credentials: only the supervisor's copy is handed over, and this one holds a \
                 conversation with a signer rather than the signer",
            ));
        };
        // One entry per plugin, so two injections served by one plugin are served by one on
        // arrival too.
        if let Some(at) = self
            .plugins
            .iter()
            .position(|held| Arc::ptr_eq(held, plugin))
        {
            return Ok(at);
        }
        self.fds.push(plugin.handoff()?);
        self.wire.push(SignerWire {
            id: plugin.id(),
            sets: plugin.sets().to_vec(),
        });
        self.plugins.push(Arc::clone(plugin));
        Ok(self.plugins.len() - 1)
    }
}

/// [`Credentials`] as it crosses: its live set, and what a needle it learns later is built with.
#[derive(Serialize, Deserialize)]
struct CredentialsWire {
    set: SetWire,
    min_len: usize,
    shared_credential: Vec<Vec<String>>,
}

/// [`CredentialSet`] as it crosses, with the running signers its injections name by position.
#[derive(Serialize, Deserialize)]
struct SetWire {
    injections: Vec<InjectionWire>,
    needles: Vec<NeedleWire>,
    signers: Vec<SignerWire>,
}

/// A running signer as it crosses: which plugin it is, and the headers its manifest declared, which
/// bound every answer the proxy takes from it. The conversation itself is the descriptor at the
/// same position.
#[derive(Serialize, Deserialize)]
struct SignerWire {
    id: u64,
    sets: Vec<String>,
}

/// [`HeaderInjection`] as it crosses.
#[derive(Serialize, Deserialize)]
struct InjectionWire {
    rule: Rule,
    form: FormWire,
}

/// [`Form`] as it crosses: a signer is carried by its position in [`SetWire::signers`].
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
        signer: usize,
        body_digest: Option<DigestWire>,
    },
}

/// A signer's [`SecretMarker`] as it crosses: its three fields.
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
    fn from_set(set: &CredentialSet, signers: &mut Handed) -> io::Result<Self> {
        let CredentialSet {
            injections,
            needles,
        } = set;
        let injections = injections
            .iter()
            .map(|injection| InjectionWire::from_injection(injection, signers))
            .collect::<io::Result<_>>()?;
        Ok(SetWire {
            injections,
            needles: needles.iter().map(NeedleWire::from_needle).collect(),
            signers: std::mem::take(&mut signers.wire),
        })
    }

    fn into_set(
        self,
        fds: Vec<OwnedFd>,
        current: Option<&CredentialSet>,
    ) -> io::Result<CredentialSet> {
        let SetWire {
            injections,
            needles,
            signers,
        } = self;
        if fds.len() != signers.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "credentials: the document names {} signers, and {} were handed over",
                    signers.len(),
                    fds.len()
                ),
            ));
        }
        let signers: Vec<Signer> = signers
            .into_iter()
            .zip(fds)
            .map(|(SignerWire { id, sets }, fd)| {
                current
                    .and_then(|set| asking(set, id))
                    .unwrap_or_else(|| Signer::Asking {
                        id,
                        channel: Arc::new(Mutex::new(SignerChannel::new(fd, sets))),
                    })
            })
            .collect();
        Ok(CredentialSet {
            injections: injections
                .into_iter()
                .map(|injection| injection.into_injection(&signers))
                .collect::<io::Result<_>>()?,
            needles: needles.into_iter().map(NeedleWire::into_needle).collect(),
        })
    }
}

/// The conversation `set` holds with plugin `id`, if it holds one.
fn asking(set: &CredentialSet, id: u64) -> Option<Signer> {
    set.injections
        .iter()
        .find_map(|injection| match &injection.form {
            Form::Signed(Signed {
                signer: signer @ Signer::Asking { id: held, .. },
                ..
            }) if *held == id => Some(signer.clone()),
            _ => None,
        })
}

impl InjectionWire {
    fn from_injection(injection: &HeaderInjection, signers: &mut Handed) -> io::Result<Self> {
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
                signer,
                body_digest,
            }) => FormWire::Signed {
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
                signer: signers.position(signer)?,
                body_digest: body_digest.map(|digest| match digest {
                    BodyDigest::Sha256 => DigestWire::Sha256,
                }),
            },
        };
        Ok(InjectionWire {
            rule: rule.clone(),
            form,
        })
    }

    fn into_injection(self, signers: &[Signer]) -> io::Result<HeaderInjection> {
        let InjectionWire { rule, form } = self;
        let form = match form {
            FormWire::Fixed { header, value } => Form::Fixed { header, value },
            FormWire::Signed {
                name,
                sets,
                sees,
                key,
                marker,
                signer,
                body_digest,
            } => {
                let Some(signer) = signers.get(signer) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "credentials: signer `{name}` names plugin {signer}, and {} were \
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
                    signer: signer.clone(),
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

/// The document `wire` is written as.
fn to_bytes(wire: &impl Serialize) -> io::Result<Vec<u8>> {
    serde_json::to_vec(wire).map_err(|e| io::Error::other(format!("credentials: {}", position(&e))))
}

/// The value a document holds, a malformed one reported by its position alone.
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
    use crate::sandbox::signer::{SignRequest, Signing};
    use std::io::{BufRead, Write};

    fn signed(
        host: &str,
        process: &Arc<SignerProcess>,
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
                signer: Signer::Running(Arc::clone(process)),
                body_digest: Some(BodyDigest::Sha256),
            }),
        }
    }

    /// A running signer with no plugin behind it, and the plugin's end of its conversation.
    fn stand_in() -> (Arc<SignerProcess>, std::os::unix::net::UnixStream) {
        let (process, plugin) = SignerProcess::stand_in(&["Authorization", "X-Amz-Date"]);
        (Arc::new(process), plugin)
    }

    /// A set in which every field of every type holds a value other than its default.
    fn full_set(process: &Arc<SignerProcess>) -> CredentialSet {
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

    /// The conversation the injection at `at` holds, which only the proxy's copy has.
    fn channel_at(set: &CredentialSet, at: usize) -> (u64, Arc<Mutex<dyn Signing>>) {
        match &set.injections[at].form {
            Form::Signed(Signed {
                signer: Signer::Asking { id, channel },
                ..
            }) => (*id, Arc::clone(channel)),
            _ => panic!("injection {at} holds no conversation"),
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
                    signer,
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
                match (signer, &other.signer) {
                    (Signer::Running(plugin), Signer::Asking { id, .. }) => {
                        assert_eq!(*id, plugin.id(), "a conversation with the plugin it was");
                    }
                    _ => panic!("the supervisor's plugin arrives as the proxy's conversation"),
                }
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

    /// Every field crosses. The proxy's copy cannot be encoded again (it holds conversations), so
    /// what arrives is compared field by field with what left, the signer by the plugin it names.
    #[test]
    fn every_field_of_a_set_survives_the_crossing() {
        let (process, _plugin) = stand_in();
        let set = full_set(&process);
        let transfer = set.encode().unwrap();
        assert_eq!(
            transfer.signers.len(),
            1,
            "one plugin serving two declarations crosses once"
        );
        let back = CredentialSet::decode(transfer).unwrap();
        same_set(&set, &back);
        assert!(
            Arc::ptr_eq(&channel_at(&back, 1).1, &channel_at(&back, 2).1),
            "and is one conversation on arrival"
        );
    }

    #[test]
    fn a_state_crosses_with_its_floor_and_its_groups_and_starts_afresh() {
        let (process, _plugin) = stand_in();
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
        let (process, _plugin) = stand_in();
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
        let (process, _plugin) = stand_in();
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

    /// The proxy's copy is never handed over: it holds conversations, and a conversation is not a
    /// plugin the proxy can give away.
    #[test]
    fn the_proxys_copy_is_not_handed_over() {
        let (process, _plugin) = stand_in();
        let back = CredentialSet::decode(full_set(&process).encode().unwrap()).unwrap();
        let e = back.encode().err().expect("refused");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    /// What arrives is a conversation with the plugin the supervisor started: a question asked
    /// through it reaches that plugin, and its answer comes back as the request's signature.
    #[test]
    fn a_signer_crosses_as_a_conversation_with_the_plugin_it_names() {
        let (process, plugin) = stand_in();
        let back = CredentialSet::decode(full_set(&process).encode().unwrap()).unwrap();
        // The plugin: one question, one answer to it.
        let answering = std::thread::spawn(move || {
            let mut questions = std::io::BufReader::new(plugin.try_clone().unwrap());
            let mut line = String::new();
            questions.read_line(&mut line).unwrap();
            let asked: serde_json::Value = serde_json::from_str(&line).unwrap();
            let answer = serde_json::json!({
                "seq": asked["seq"],
                "headers": {"Authorization": format!("SIGNED {}", asked["target"].as_str().unwrap())},
            });
            let mut plugin = plugin;
            writeln!(plugin, "{answer}").unwrap();
        });
        let (_, channel) = channel_at(&back, 1);
        let signature = channel
            .lock()
            .unwrap()
            .sign(&SignRequest {
                method: "GET",
                host: "signed.test",
                port: 443,
                target: "/v1/thing",
                headers: Vec::new(),
                body: None,
            })
            .expect("signed through the descriptor handed over");
        answering.join().unwrap();
        assert_eq!(
            signature.headers,
            vec![("Authorization".to_string(), "SIGNED /v1/thing".to_string())]
        );
    }

    /// A re-resolution hands the proxy its set again, the kept plugins with it. A plugin it already
    /// talks to keeps its conversation: two over one socket would each read the other's answers. A
    /// plugin it has not met gets a conversation of its own.
    #[test]
    fn a_plugin_a_re_resolution_kept_keeps_its_conversation() {
        let (kept, _kept_plugin) = stand_in();
        let proxys = CredentialSet::decode(full_set(&kept).encode().unwrap()).unwrap();
        let (fresh, _fresh_plugin) = stand_in();
        let mut again = full_set(&kept);
        again.injections.push(signed("new.test", &fresh, None));
        let back = CredentialSet::decode_over(again.encode().unwrap(), &proxys).unwrap();
        assert!(
            Arc::ptr_eq(&channel_at(&proxys, 1).1, &channel_at(&back, 1).1),
            "the kept plugin is asked through the channel already asking it"
        );
        let (id, channel) = channel_at(&back, 3);
        assert_eq!(id, fresh.id());
        assert!(
            !Arc::ptr_eq(&channel_at(&proxys, 1).1, &channel),
            "a new plugin is not asked through another plugin's channel"
        );
    }
}
