//! The broker plugin type: a third-party filter in front of a host resource.
//!
//! A resolver plugin answers *where a value comes from*; a broker plugin answers *how the cage
//! uses a host resource without holding it*. The first-party ssh-agent broker
//! ([`crate::sandbox::sshagent`]) is the shape: a socket of sbx's own in front of the host agent,
//! speaking the protocol on both sides and refusing what the grant does not name. That shape has
//! to be re-cut by hand for every protocol, and most protocols will never justify first-party
//! code — which is what this type exists to fix.
//!
//! **The plugin is a pure filter.** It gets no listening socket, no network descriptor, and no
//! access to the host resource. It speaks to sbx alone, over stdin/stdout, from a host-side cage
//! with an empty network namespace. sbx keeps the cage-facing listener, the connection to the host
//! resource, the framing, the decision record, and the timeouts; the plugin sees bytes and answers
//! verdicts.
//!
//! That division is what bounds the damage a bad plugin can do: **a broker plugin can never grant
//! more than binding the host socket into the cage would have granted**. It cannot do worse than
//! the hole it replaces, and it is meant to do far better.
//!
//! Two grants a resolver may hold are refused here, and both refusals are about that bound:
//!
//! - `network` — a resolver reaches the network because a remote vault is where the secret *is*;
//!   a broker has nothing to reach, since sbx opens the connection for it. Host network reach on
//!   the component brokering a credential is an exfiltration path for that exact credential.
//! - `state` — everything else a plugin gets is read-only, and a broker has no rotating token to
//!   persist. A writable directory here would be surface without a use.
//!
//! The remaining grants (`programs`, `allow_paths`, `mask_paths`, `allow_env`, `allow_env_paths`)
//! are kept, and for the reason a resolver has them: a plugin is a *program*, and a program needs
//! its interpreter and the read-only data that interpreter loads. None of them widens what the
//! plugin can reach on the wire, which is the axis this type is fenced on.
//!
//! The manifest also cannot name **where** the cage-facing socket lands, for the reason
//! [`SandboxGrant::state`](super::SandboxGrant::state) is a boolean and never a path: sbx picks
//! the location, so a manifest can neither collide with another plugin's socket nor place one
//! over a path the cage needs. What a manifest declares is the *variables* that must point at it,
//! and those pass two barriers: the reserved-key one an untrusted project's `[env]` meets (a
//! plugin that could set `LD_PRELOAD` or `PATH` would be running code in the cage rather than
//! brokering), and [`SBX_OWNED_CAGE_ENV`] (a plugin that took the name sbx uses for a broker of
//! its own would answer that protocol in place of the broker actually granted).

use serde::Deserialize;
use std::path::PathBuf;

/// The largest frame sbx will read on either side of any broker, whatever a manifest asks for.
///
/// A property of *this channel*, not of any one protocol: the cage is on one end of it, so the
/// length prefix is attacker-controlled, and a bound a manifest declares for itself is a bound the
/// declaring side does not enforce. Without a ceiling above every declared `max_frame`, a manifest
/// could turn a length prefix into an allocation of its choosing.
pub(crate) const MAX_FRAME_CEILING: usize = 256 * 1024;

/// How long sbx waits on the host resource for one exchange when a manifest names nothing. The
/// socket is whatever the machine offers, so a hang there must not become a hang in the cage.
pub(crate) const DEFAULT_HOST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// The longest a manifest may ask sbx to wait on a host resource. Ten minutes: past it, whatever is
/// on the other side is wedged rather than thinking, and no pinentry prompt a person answers takes
/// that long. It bounds what a manifest can hold — a thread, a plugin process and two connections —
/// the way [`MAX_FRAME_CEILING`] bounds what one can read.
pub(crate) const MAX_HOST_DEADLINE_SECS: i64 = 600;

/// Cage variables sbx sets itself, to point a client at a channel it stands up. A broker
/// plugin's `cage_env` may not claim one: it would put its own socket where another broker's
/// belongs, and the client would never know it was talking to something else.
///
/// Each entry is taken from where sbx sets it, so the two cannot drift apart silently.
const SBX_OWNED_CAGE_ENV: &[&str] = &[crate::sandbox::sshagent::AUTH_SOCK_ENV];

/// How a stream of bytes is cut into the messages a plugin decides one at a time.
///
/// A closed set, implemented in Rust on sbx's side of the channel. The framing is the one part of
/// a protocol sbx must understand to keep the boundary: a plugin that received an uncut stream
/// would *be* the broker, holding the whole conversation instead of ruling on its messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framing {
    /// A four-byte big-endian length, then that many bytes of body. The length counts the body
    /// alone, and the body is what the plugin is shown: whatever type or tag byte the protocol
    /// puts first is *inside* it, because that is the byte a decision usually turns on.
    ///
    /// This is the ssh-agent framing, and it is far from unique to it.
    LengthU32Be,
    /// One message per line, terminated by a newline the frame does not include. The framing of
    /// Assuan (gpg-agent and its siblings) and of many text protocols.
    ///
    /// `max_frame` bounds the line, and an over-long one is an **error, not a truncation**: the
    /// same posture the length prefix takes, for the same reason — half a message put on a wire is
    /// worse than none.
    Line,
    /// PostgreSQL's frontend/backend framing, and the shape of several protocols built the same
    /// way: a one-byte message type, then a four-byte big-endian length **that counts itself**,
    /// then the body.
    ///
    /// With one exception that no formula covers: the connection's **first** message from the
    /// client (the startup packet) carries **no type byte** — it is length-then-body alone. So the
    /// reader is stateful, and the state is per direction: the first frame read from the cage has
    /// no type, every later one does, and everything from the server has one from the start.
    ///
    /// A frame is handed to the plugin **whole**, type byte included where there is one, and put
    /// back on the wire exactly as it came. sbx reads the length to know where a message ends; it
    /// reads nothing else.
    PgWire,
}

impl Framing {
    /// The manifest token for this framing, for diagnostics and `sbx plugins info`.
    pub(crate) fn token(self) -> &'static str {
        match self {
            Framing::LengthU32Be => "length-u32-be",
            Framing::Line => "line",
            Framing::PgWire => "pgwire",
        }
    }

    /// Parse a manifest's `framing`, naming the alternatives when it is not one of them.
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "length-u32-be" => Ok(Framing::LengthU32Be),
            "line" => Ok(Framing::Line),
            "pgwire" => Ok(Framing::PgWire),
            other => Err(format!(
                "unsupported `framing` `{other}` (supported: `length-u32-be`, `line`, `pgwire`)"
            )),
        }
    }
}

/// The `[broker]` table of a validated manifest: what sbx must know about a protocol to stand
/// between the cage and the host resource without understanding what the messages mean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrokerSpec {
    /// The cage environment variables that must point at the broker's socket **file**.
    pub(crate) cage_env: Vec<String>,
    /// The cage environment variables that must point at the **directory** holding it.
    ///
    /// Some clients take a directory and derive the file name themselves: libpq reads `PGHOST` and
    /// looks for `.s.PGSQL.<port>` inside it. Without this a broker could serve PostgreSQL only if
    /// the user linked the socket into a directory by hand, which is the difference between a
    /// mechanism that works and one that works for whoever knows the trick.
    pub(crate) cage_env_dir: Vec<String>,
    /// The socket's file name inside the directory sbx chose, for a client that expects a
    /// particular one. Defaults to `<plugin>.sock`.
    ///
    /// A **name, never a path**: the directory stays sbx's to choose, which is what keeps a
    /// manifest from placing a socket over something the cage needs, and keeps two brokers from
    /// colliding. The same rule `programs` entries are held to, for the same reason.
    pub(crate) socket_name: String,
    /// Whether this protocol's clients find the socket by a **fixed path** they compute
    /// themselves, rather than by reading a variable.
    ///
    /// Still not a path in the manifest: it says how the protocol locates a socket, and the path
    /// itself comes from the config that named the host resource. Where this is set, the fenced
    /// socket is bound at the host socket's own address, so a client that would have found the raw
    /// resource finds the fence instead and needs no telling.
    ///
    /// Measured on GnuPG, whose clients derive `/run/user/<uid>/gnupg/S.gpg-agent` from the uid and
    /// the home directory: `GPG_AGENT_INFO` has named nothing since GnuPG 2.1, so a broker that
    /// could only be pointed at by a variable could not fence an agent at all.
    ///
    /// Only a Unix target has an address to stand at, so this and a `tcp://` socket are refused
    /// together rather than one silently ignoring the other.
    pub(crate) at_host_path: bool,
    /// How the byte stream is cut into messages.
    pub(crate) framing: Framing,
    /// The largest frame this protocol admits, capped at [`MAX_FRAME_CEILING`]. Required, never
    /// defaulted: a plugin author knows their protocol's bound, and a default here would be a
    /// number sbx invented and the manifest appeared to have chosen.
    pub(crate) max_frame: usize,
    /// The protocol's refusal frame, if it has one that does not depend on the request refused.
    ///
    /// Optional, and deliberately so. It exists for the case the ssh-agent broker demonstrates,
    /// where every refusal is the same constant byte and none carries a field taken from the
    /// request. A protocol whose refusal must echo a sequence number or a request id has no such
    /// constant, and declares none: a live plugin refuses with its own bytes, and a dead one is
    /// refused by closing the connection.
    ///
    /// Closing is the refusal that always works, because it needs no knowledge of the protocol.
    /// This field only buys the client a clean protocol-level refusal instead of a cut socket.
    pub(crate) deny_frame: Option<Vec<u8>>,
    /// Whether this broker is handed a **marker** to stand in for a secret it never sees.
    ///
    /// A broker holds no secret — that is what bounds it to the hole it replaces. This grant does
    /// not change that: what the plugin receives is a random per-connection marker, and sbx
    /// substitutes the real value into the plugin's own bytes on their way to the host resource.
    /// The plugin can place the secret; it can never read it.
    ///
    /// Declared here, and not only in the config, for the reason every grant is: which plugin may
    /// be handed one is a property of the code that was installed and reviewed, not of the machine
    /// that configures it. Without it a plugin gets no marker and any substitution is refused.
    pub(crate) uses_secret: bool,
    /// Whether the host resource speaks first: it sends a frame on connection, before the cage has
    /// asked anything.
    ///
    /// Measured on gpg-agent, which greets every connection with `OK Pleased to meet you`. Without
    /// this, sbx would leave that frame in the buffer and read it as the answer to the cage's first
    /// message — and every message of the connection after that would be answered by the reply to
    /// the one before. Off by default, because the protocol sbx already brokers (ssh-agent) has no
    /// greeting and a wrong `true` would make sbx wait for a frame that never comes.
    pub(crate) host_greets: bool,
    /// How long sbx waits on the host resource for one exchange, when the protocol's own answer can
    /// legitimately take longer than a machine's.
    ///
    /// A deadline exists so a wedged resource cannot wedge the cage: it holds a thread, a plugin
    /// process and two connections while it waits. The default suits a protocol that answers as
    /// fast as the machine can. It does not suit one that stops to **ask a person** — a gpg-agent
    /// opening a pinentry for a passphrase answers when the human does, and 30 seconds is a typing
    /// speed rather than a fault.
    ///
    /// So the manifest raises it, bounded by [`MAX_HOST_DEADLINE_SECS`], and the number is a
    /// property of the protocol rather than of the machine: what waits is sbx, and how long a
    /// resource may take is the one thing only the protocol knows.
    pub(crate) host_deadline: std::time::Duration,
    /// Whether the plugin also rules on the frames coming *back* from the host resource.
    ///
    /// Off unless asked for: it is the wider grant of the two, and a broker that only needs to
    /// bound what the cage may *ask* should not be shown what the host answers. On, it is what
    /// lets a reply be rebuilt rather than filtered in place — the property that keeps a withheld
    /// identity from being spelled toward the cage at all.
    pub(crate) inspect_replies: bool,
}

/// A validated broker plugin: `exec` is run once per cage connection and, on stdin/stdout, rules
/// on the frames crossing between the cage and the host resource. Carries no secret and is safe
/// to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrokerPlugin {
    /// The plugin's name, which is also the key it is registered and configured under.
    pub(crate) name: String,
    /// The plugin's own directory, bound read-only into the runner's cage so the executable (and
    /// any sibling helper it ships) is reachable at its real path.
    pub(crate) dir: PathBuf,
    /// Absolute path to the executable: the plugin directory joined with the manifest's
    /// (directory-relative, traversal-free) `exec`.
    pub(crate) exec: PathBuf,
    /// The least-privilege grant the runner gives the plugin, minus the two grants this type
    /// refuses outright (see the module documentation).
    pub(crate) sandbox: super::SandboxGrant,
    /// What sbx must know about the protocol.
    pub(crate) broker: BrokerSpec,
    /// The manifest's declared version, if any. Display-only.
    pub(crate) version: Option<String>,
    /// The manifest's one-line description, if any. Display-only.
    pub(crate) description: Option<String>,
    /// What the *host* supplies to this plugin, from a `[plugin.<name>]` table in the global or a
    /// trusted project config. Empty unless one is declared.
    pub(crate) host: super::HostConfig,
}

impl BrokerPlugin {
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

/// The raw `[broker]` table, before validation. Every field is optional so a missing one yields a
/// precise "missing X" error rather than a generic parse failure, and unknown fields are refused
/// for the reason the rest of the manifest refuses them: a key nothing reads would leave an
/// author believing they had declared something they had not.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawBroker {
    host_deadline: Option<i64>,
    #[serde(default)]
    cage_env: Vec<String>,
    #[serde(default)]
    cage_env_dir: Vec<String>,
    socket_name: Option<String>,
    framing: Option<String>,
    max_frame: Option<i64>,
    deny_frame: Option<Vec<i64>>,
    #[serde(default)]
    uses_secret: bool,
    #[serde(default)]
    host_greets: bool,
    #[serde(default)]
    inspect_replies: bool,
    #[serde(default)]
    at_host_path: bool,
}

/// Validate a manifest's `[broker]` table. `is_reserved` is the cage's reserved-environment-key
/// predicate, injected so this stays testable without the config layer and so there is exactly
/// one list of reserved keys in the tree.
pub(super) fn validate(
    raw: RawBroker,
    name: &str,
    is_valid_env_key: impl Fn(&str) -> bool,
    is_reserved: impl Fn(&str) -> bool,
) -> Result<BrokerSpec, String> {
    // Something has to point the cage at the socket. A variable is the general answer; a protocol
    // whose clients compute the path themselves says so instead, and is pointed at by the address
    // the socket stands at. One of the two, never neither: a broker nothing can find is a fence in
    // front of a door nobody walks through.
    if raw.cage_env.is_empty() && raw.cage_env_dir.is_empty() && !raw.at_host_path {
        return Err(
            "missing `cage_env` — sbx picks where the broker's socket lands, so a broker must \
             name at least one cage variable to point at it (`cage_env` for the socket itself, \
             `cage_env_dir` for the directory holding it), or declare `at_host_path` if its \
             clients compute the path themselves"
                .to_string(),
        );
    }
    let socket_name = match raw.socket_name {
        None => format!("{name}.sock"),
        Some(named) => {
            // A name, never a path: a separator or a `.`/`..` component would let a manifest place
            // its socket somewhere sbx did not choose.
            if named.is_empty()
                || named.contains('/')
                || named == "."
                || named == ".."
                || named.contains('\0')
            {
                return Err(format!(
                    "`socket_name` is `{named}`, which is not a plain file name — the directory is \
                     sbx's to choose"
                ));
            }
            named
        }
    };
    let all_env: Vec<&String> = raw.cage_env.iter().chain(raw.cage_env_dir.iter()).collect();
    for (i, key) in all_env.iter().enumerate() {
        if !is_valid_env_key(key) {
            return Err(format!("`cage_env` has an invalid variable name `{key}`"));
        }
        // The same barrier an untrusted project's `[env]` meets. A broker plugin is installed
        // deliberately and is in the trusted computing base, but the variables it sets land in the
        // *agent's* cage, and these particular names load code rather than carry data: a socket
        // path in `LD_PRELOAD` or `PATH` is not a broker declaring its endpoint.
        if is_reserved(key) {
            return Err(format!(
                "`cage_env` names the reserved variable `{key}` — a broker points a client at its \
                 socket, and these names load code in the cage rather than carry a path"
            ));
        }
        // A second, narrower barrier, and not the same one. The reserved set above is about names
        // that *load code*; this is about names sbx already uses to point the cage at a channel of
        // its own. Claiming one does not run anything — it **substitutes** one broker for another,
        // which is why an untrusted `[env]` may set `SSH_AUTH_SOCK` (self-DoS at worst, the socket
        // being sbx's to bind) while a manifest may not: a broker that took that name would be
        // answering the ssh-agent protocol in place of the broker that was actually granted.
        if SBX_OWNED_CAGE_ENV.contains(&key.as_str()) {
            return Err(format!(
                "`cage_env` names `{key}`, which sbx sets itself to point the cage at another \
                 broker — a plugin cannot stand in for one the config granted"
            ));
        }
        if all_env[..i].contains(key) {
            return Err(format!(
                "`cage_env` names `{key}` twice — one variable, one declaration"
            ));
        }
    }

    let framing = Framing::parse(raw.framing.as_deref().ok_or("missing `framing`")?)?;

    let max_frame = raw.max_frame.ok_or(
        "missing `max_frame` — the largest frame this protocol admits, which bounds what sbx \
         reads from the cage",
    )?;
    if max_frame <= 0 {
        return Err(format!(
            "`max_frame` must be a positive number of bytes, not {max_frame}"
        ));
    }
    let max_frame = max_frame as usize;
    if max_frame > MAX_FRAME_CEILING {
        return Err(format!(
            "`max_frame` is {max_frame}, above the {MAX_FRAME_CEILING}-byte ceiling sbx reads \
             on a broker channel"
        ));
    }

    let deny_frame = match raw.deny_frame {
        None => None,
        Some(bytes) => {
            if bytes.is_empty() {
                return Err(
                    "`deny_frame` is empty — omit it entirely for a protocol with no \
                     request-independent refusal, and sbx refuses by closing the connection"
                        .to_string(),
                );
            }
            if bytes.len() > max_frame {
                return Err(format!(
                    "`deny_frame` is {} bytes, above this broker's own `max_frame` of {max_frame}",
                    bytes.len()
                ));
            }
            let mut frame = Vec::with_capacity(bytes.len());
            for b in bytes {
                let byte = u8::try_from(b).map_err(|_| {
                    format!("`deny_frame` has the value {b}, which is not a byte (0-255)")
                })?;
                frame.push(byte);
            }
            Some(frame)
        }
    };

    // Seconds, because that is the unit a protocol's own patience is described in. Defaulted rather
    // than required, unlike `max_frame`: every protocol has a frame ceiling worth stating, while
    // only one that waits on a person has a reason to move this.
    let host_deadline = match raw.host_deadline {
        None => DEFAULT_HOST_DEADLINE,
        Some(secs) if secs <= 0 => {
            return Err(format!(
                "`host_deadline` must be a positive number of seconds, not {secs}"
            ));
        }
        Some(secs) if secs > MAX_HOST_DEADLINE_SECS => {
            return Err(format!(
                "`host_deadline` is {secs} seconds, above the {MAX_HOST_DEADLINE_SECS}-second \
                 ceiling sbx waits on a host resource — past it a wedged resource would hold a \
                 thread and two connections for longer than any prompt takes to answer"
            ));
        }
        Some(secs) => std::time::Duration::from_secs(secs as u64),
    };

    // A greeting is a frame the plugin has to be able to rule on: it reaches the cage, and on a
    // multi-message protocol nothing else can say where it ends. Refused rather than quietly
    // forwarded, so a manifest cannot arrange for one frame to bypass the broker entirely.
    if raw.host_greets && !raw.inspect_replies {
        return Err(
            "`host_greets` needs `inspect_replies` — the greeting is a frame from the host, and \
             without the grant to rule on replies the broker would pass it to the cage unseen"
                .to_string(),
        );
    }

    Ok(BrokerSpec {
        cage_env: raw.cage_env,
        cage_env_dir: raw.cage_env_dir,
        socket_name,
        framing,
        max_frame,
        deny_frame,
        uses_secret: raw.uses_secret,
        host_deadline,
        host_greets: raw.host_greets,
        inspect_replies: raw.inspect_replies,
        at_host_path: raw.at_host_path,
    })
}

/// The grants this type refuses whatever a manifest declares, checked against the already-parsed
/// `[sandbox]` table so the refusal names the field rather than the consequence.
pub(super) fn check_sandbox(grant: &super::SandboxGrant) -> Result<(), String> {
    if grant.network {
        return Err(
            "a broker plugin may not declare `network` — sbx opens the connection to the host \
             resource for it, so network reach here is an exfiltration path for the very \
             credential the broker is fencing"
                .to_string(),
        );
    }
    if grant.state {
        return Err(
            "a broker plugin may not declare `state` — a broker holds nothing across runs, and a \
             writable directory would be surface without a use"
                .to_string(),
        );
    }
    if !grant.brokers.is_empty() {
        return Err(
            "a broker plugin may not declare `brokers` — a broker fenced by another broker is a \
             chain, and what the outer one admits would depend on a plugin rather than on the \
             config that bound it"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stand-ins for the config layer's two predicates, so this module's validation is testable
    /// on its own. The real ones are injected by the caller.
    fn valid_key(key: &str) -> bool {
        !key.is_empty()
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !key.starts_with(|c: char| c.is_ascii_digit())
    }
    fn reserved(key: &str) -> bool {
        key.starts_with("LD_") || matches!(key, "PATH" | "HOME")
    }

    fn raw() -> RawBroker {
        RawBroker {
            host_deadline: None,
            cage_env: vec!["GPG_AGENT_SOCK".to_string()],
            cage_env_dir: Vec::new(),
            socket_name: None,
            framing: Some("length-u32-be".to_string()),
            max_frame: Some(4096),
            deny_frame: Some(vec![5]),
            uses_secret: false,
            host_greets: false,
            inspect_replies: true,
            at_host_path: false,
        }
    }

    #[test]
    fn a_well_formed_broker_table_validates() {
        let spec = validate(raw(), "fake", valid_key, reserved).expect("valid");
        assert_eq!(spec.cage_env, vec!["GPG_AGENT_SOCK".to_string()]);
        assert_eq!(spec.framing, Framing::LengthU32Be);
        assert_eq!(spec.max_frame, 4096);
        assert_eq!(spec.deny_frame, Some(vec![5]));
        assert!(spec.inspect_replies);
    }

    #[test]
    fn replies_are_not_inspected_unless_asked_for() {
        let spec = validate(
            RawBroker {
                inspect_replies: false,
                ..raw()
            },
            "fake",
            valid_key,
            reserved,
        )
        .expect("valid");
        assert!(
            !spec.inspect_replies,
            "the wider grant must be off by default"
        );
    }

    /// A greeting reaches the cage like any other frame from the host, so a broker that declares
    /// one must be able to rule on it. Otherwise a manifest would arrange for exactly one frame to
    /// bypass the broker.
    #[test]
    fn a_greeting_cannot_be_declared_without_the_grant_to_rule_on_replies() {
        let err = validate(
            RawBroker {
                host_greets: true,
                inspect_replies: false,
                ..raw()
            },
            "fake",
            valid_key,
            reserved,
        )
        .expect_err("a greeting nothing may rule on is refused");
        assert!(err.contains("inspect_replies"), "{err}");

        let spec = validate(
            RawBroker {
                host_greets: true,
                inspect_replies: true,
                ..raw()
            },
            "fake",
            valid_key,
            reserved,
        )
        .expect("with the grant it is admissible");
        assert!(spec.host_greets);
    }

    #[test]
    fn a_broker_that_names_no_cage_variable_is_refused() {
        let err = validate(
            RawBroker {
                cage_env: Vec::new(),
                ..raw()
            },
            "fake",
            valid_key,
            reserved,
        )
        .expect_err("a socket nothing can find is not a broker");
        assert!(err.contains("cage_env"), "{err}");
    }

    /// A client that derives the socket's file name (libpq reads `PGHOST` as a directory and looks
    /// for `.s.PGSQL.<port>` inside) needs the manifest to name the file. The directory stays
    /// sbx's, which is the part that matters.
    #[test]
    fn a_manifest_may_name_the_socket_file_but_never_its_directory() {
        let spec = validate(
            RawBroker {
                cage_env: Vec::new(),
                cage_env_dir: vec!["PGHOST".to_string()],
                socket_name: Some(".s.PGSQL.5432".to_string()),
                ..raw()
            },
            "postgres",
            valid_key,
            reserved,
        )
        .expect("a file name is admissible");
        assert_eq!(spec.socket_name, ".s.PGSQL.5432");
        assert_eq!(spec.cage_env_dir, vec!["PGHOST".to_string()]);

        // Anything with a path in it is refused: the directory is not the manifest's to pick.
        for bad in ["/etc/passwd", "../escape", "sub/dir.sock", "..", ""] {
            validate(
                RawBroker {
                    socket_name: Some(bad.to_string()),
                    ..raw()
                },
                "postgres",
                valid_key,
                reserved,
            )
            .expect_err(&format!("`{bad}` is not a plain file name"));
        }
    }

    /// Naming neither form of variable leaves a socket nothing in the cage can find.
    #[test]
    fn a_broker_must_name_a_variable_of_one_form_or_the_other() {
        let err = validate(
            RawBroker {
                cage_env: Vec::new(),
                cage_env_dir: Vec::new(),
                ..raw()
            },
            "fake",
            valid_key,
            reserved,
        )
        .expect_err("neither form named");
        assert!(err.contains("cage_env"), "{err}");
    }

    /// The other substitution: taking the name sbx uses for a broker it stood up itself would put
    /// this plugin's socket where the agent's belongs, and the client would never know.
    #[test]
    fn a_broker_may_not_claim_a_variable_sbx_sets_for_another_broker() {
        let err = validate(
            RawBroker {
                cage_env: vec![crate::sandbox::sshagent::AUTH_SOCK_ENV.to_string()],
                ..raw()
            },
            "fake",
            valid_key,
            reserved,
        )
        .expect_err("a name sbx owns must be refused");
        assert!(err.contains("sbx sets itself"), "{err}");
    }

    /// The escalation this barrier exists for: these names load code in the agent's cage.
    #[test]
    fn a_broker_may_not_point_a_reserved_variable_at_its_socket() {
        for key in ["LD_PRELOAD", "PATH"] {
            let err = validate(
                RawBroker {
                    cage_env: vec![key.to_string()],
                    ..raw()
                },
                "fake",
                valid_key,
                reserved,
            )
            .expect_err("a reserved key must be refused");
            assert!(err.contains(key), "{err}");
        }
    }

    #[test]
    fn one_variable_is_declared_once() {
        let err = validate(
            RawBroker {
                cage_env: vec!["GPG_AGENT_SOCK".to_string(), "GPG_AGENT_SOCK".to_string()],
                ..raw()
            },
            "fake",
            valid_key,
            reserved,
        )
        .expect_err("a doubled declaration is refused");
        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn an_unknown_framing_names_what_is_supported() {
        let err = validate(
            RawBroker {
                framing: Some("netstring".to_string()),
                ..raw()
            },
            "fake",
            valid_key,
            reserved,
        )
        .expect_err("an unimplemented framing must be refused");
        assert!(err.contains("length-u32-be"), "{err}");
    }

    #[test]
    fn framing_and_max_frame_are_required() {
        let err = validate(
            RawBroker {
                framing: None,
                ..raw()
            },
            "fake",
            valid_key,
            reserved,
        )
        .expect_err("missing framing");
        assert!(err.contains("framing"), "{err}");
        let err = validate(
            RawBroker {
                max_frame: None,
                ..raw()
            },
            "fake",
            valid_key,
            reserved,
        )
        .expect_err("missing max_frame");
        assert!(err.contains("max_frame"), "{err}");
    }

    /// The length prefix is written by the cage, so a manifest cannot raise the ceiling sbx reads.
    #[test]
    fn max_frame_cannot_exceed_the_ceiling() {
        let err = validate(
            RawBroker {
                max_frame: Some(MAX_FRAME_CEILING as i64 + 1),
                ..raw()
            },
            "fake",
            valid_key,
            reserved,
        )
        .expect_err("above the ceiling");
        assert!(err.contains("ceiling"), "{err}");
        let spec = validate(
            RawBroker {
                max_frame: Some(MAX_FRAME_CEILING as i64),
                ..raw()
            },
            "fake",
            valid_key,
            reserved,
        )
        .expect("the ceiling itself is admissible");
        assert_eq!(spec.max_frame, MAX_FRAME_CEILING);
    }

    #[test]
    fn max_frame_must_be_positive() {
        for value in [0, -1] {
            let err = validate(
                RawBroker {
                    max_frame: Some(value),
                    ..raw()
                },
                "fake",
                valid_key,
                reserved,
            )
            .expect_err("a non-positive bound is not a bound");
            assert!(err.contains("positive"), "{err}");
        }
    }

    #[test]
    fn a_deny_frame_holds_bytes_and_fits_the_protocol() {
        let err = validate(
            RawBroker {
                deny_frame: Some(vec![256]),
                ..raw()
            },
            "fake",
            valid_key,
            reserved,
        )
        .expect_err("256 is not a byte");
        assert!(err.contains("0-255"), "{err}");

        let err = validate(
            RawBroker {
                max_frame: Some(2),
                deny_frame: Some(vec![1, 2, 3]),
                ..raw()
            },
            "fake",
            valid_key,
            reserved,
        )
        .expect_err("a refusal larger than the protocol admits");
        assert!(err.contains("max_frame"), "{err}");
    }

    /// Absent is the documented answer for a protocol with no request-independent refusal;
    /// present-but-empty says the same thing while looking like a declaration.
    #[test]
    fn an_empty_deny_frame_is_refused_rather_than_read_as_absent() {
        let err = validate(
            RawBroker {
                deny_frame: Some(Vec::new()),
                ..raw()
            },
            "fake",
            valid_key,
            reserved,
        )
        .expect_err("empty is not absent");
        assert!(err.contains("omit it"), "{err}");

        let spec = validate(
            RawBroker {
                deny_frame: None,
                ..raw()
            },
            "fake",
            valid_key,
            reserved,
        )
        .expect("a protocol may have no constant refusal");
        assert_eq!(spec.deny_frame, None);
    }

    #[test]
    fn the_grants_a_broker_never_gets_are_refused_by_name() {
        let mut grant = super::super::SandboxGrant {
            programs: Vec::new(),
            allow_paths: Vec::new(),
            mask_paths: Vec::new(),
            allow_env: Vec::new(),
            allow_env_paths: Vec::new(),
            network: true,
            state: false,
            brokers: Vec::new(),
        };
        let err = check_sandbox(&grant).expect_err("network is refused");
        assert!(err.contains("network"), "{err}");

        grant.network = false;
        grant.state = true;
        let err = check_sandbox(&grant).expect_err("state is refused");
        assert!(err.contains("state"), "{err}");

        grant.state = false;
        grant.brokers = vec!["gpg-agent".to_string()];
        let err = check_sandbox(&grant).expect_err("a broker behind a broker is refused");
        assert!(err.contains("brokers"), "{err}");

        grant.brokers.clear();
        check_sandbox(&grant).expect("none of the three grants declared");
    }

    /// A protocol that stops to ask a person answers when the human does, so the manifest may raise
    /// what sbx waits — bounded, since what waits is a thread and two connections of sbx's.
    #[test]
    fn a_protocol_that_waits_on_a_human_may_raise_the_host_deadline() {
        let spec = validate(
            RawBroker {
                host_deadline: Some(300),
                ..raw()
            },
            "gpg-agent",
            valid_key,
            reserved,
        )
        .expect("five minutes is under the ceiling");
        assert_eq!(spec.host_deadline, std::time::Duration::from_secs(300));

        // The default is what a protocol answering at machine speed gets.
        assert_eq!(
            validate(raw(), "fake", valid_key, reserved)
                .expect("valid")
                .host_deadline,
            DEFAULT_HOST_DEADLINE
        );

        for bad in [0, -1, MAX_HOST_DEADLINE_SECS + 1] {
            let err = validate(
                RawBroker {
                    host_deadline: Some(bad),
                    ..raw()
                },
                "fake",
                valid_key,
                reserved,
            )
            .expect_err("outside the bounds");
            assert!(err.contains("host_deadline"), "{bad}: {err}");
        }
    }

    /// A protocol whose clients compute the socket path is pointed at by the address the socket
    /// stands at, so it names no variable — and must not be refused for naming none.
    #[test]
    fn a_broker_whose_clients_compute_the_path_needs_no_variable() {
        let spec = validate(
            RawBroker {
                cage_env: Vec::new(),
                cage_env_dir: Vec::new(),
                at_host_path: true,
                ..raw()
            },
            "gpg-agent",
            valid_key,
            reserved,
        )
        .expect("the host path is what points at it");
        assert!(spec.at_host_path);
        assert!(spec.cage_env.is_empty());
    }
}
