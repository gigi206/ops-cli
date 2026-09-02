//! The in-cage contract: a human- and agent-readable description of what the sandbox
//! permits, generated from the resolved config and bound read-only into the cage at
//! [`EGRESS_CONTRACT_INCAGE`].
//!
//! It is purely informational — it enforces nothing (the empty network namespace plus
//! the host filtering proxy are the boundary). Its job is to let a process inside the
//! cage understand *why* a direct connection or a `ping` fails and *which* hosts it can
//! actually reach, without running the host-side `sbx net` tools (which it cannot, from
//! inside the cage). The companion `SBX_SANDBOX=1` / `SBX_EGRESS_CONTRACT` environment
//! variables (set by the assembler) are the discovery handle: a tool reads the file the
//! second variable points at.
//!
//! # What may be written here, and what may not
//!
//! One rule decides it: **state what the cage could discover by trying, withhold what it
//! could not.** An allow rule is discoverable in one request (200 or 403), so listing it
//! costs nothing and spares an honest process a great deal of futile behaviour — an agent
//! that concludes "no network" from a failed `ping` starts rewriting `resolv.conf` and
//! disabling TLS verification, which is indistinguishable from an attack and drowns the
//! real signals. A **deny** rule is not discoverable: enumerating it would mean
//! enumerating the internet, so the specifics stay out.
//!
//! The declared operations sit at the far end of that scale — they are not merely
//! discoverable, they are already **served on request** over the task socket
//! (`sbx task list`). Restating them here adds no disclosure at all; it only puts them
//! where a process already looks, because a capability that cannot be found is worth the
//! same as one that was never granted.

use crate::config::{NetworkPolicy, ParamBound, TaskSpec};

/// Where the generated contract is bound read-only inside the cage. Also the value of
/// the `SBX_EGRESS_CONTRACT` environment variable, so a tool need not hard-code the path.
///
/// Under `/opt/sbx`, beside the mise plugin and the shell rc, colliding with no
/// structural mount.
pub(crate) const EGRESS_CONTRACT_INCAGE: &str = "/opt/sbx/egress-contract.md";

/// Render the egress contract for a resolved network posture. Pure: the text derives only
/// from the policy.
///
/// For an allowlist, the reachable-destination list mirrors the **wire** policy — the built-in
/// self-equip allow set is unioned in exactly as the proxy does, so the contract lists
/// what is actually reachable, not only what the config spelled out. Only **allow** rules
/// are listed: a process legitimately learns which hosts it can reach (it would discover
/// them by connecting anyway), but the specifics of deny rules are **not** disclosed — a
/// global deny the agent cannot read must not leak through the contract. That an unnamed deny rule
/// may still refuse a *listed* host is stated outright ([`DENY_CAVEAT`]): it discloses nothing, and
/// without it the listing reads as a promise the policy does not make.
pub(crate) fn egress_contract(policy: &NetworkPolicy) -> String {
    match policy {
        NetworkPolicy::Isolated => ISOLATED.to_string(),
        NetworkPolicy::Shared => SHARED.to_string(),
        NetworkPolicy::Allowlist(policy) => allowlist_contract(policy),
    }
}

/// The whole contract the cage is given: the egress posture, then the declared operations when the
/// session offers any.
///
/// One file rather than two, and the one a process already knows to read (`$SBX_EGRESS_CONTRACT`).
/// A second file would reintroduce the very problem this section exists to solve — something the
/// cage can only use if it already knows to look for it.
pub(crate) fn cage_contract(policy: &NetworkPolicy, tasks: &[TaskSpec]) -> String {
    format!("{}{}", egress_contract(policy), operations_section(tasks))
}

/// The contract for a filtered-egress (allowlist) posture: the isolation note, then the reachable
/// destinations **grouped by the plane that reaches them**, then a closing line whose wording
/// follows the default action, and the caveat every listing carries ([`DENY_CAVEAT`]).
///
/// The grouping is not cosmetic. A rule's scheme names its enforcement layer
/// ([`crate::allowlist::Layer`]), and the three layers are reached by different means: an inspected
/// `https://` host answers the `curl` recipe in [`ISOLATION_NOTE`], an `http://` host answers it
/// only without TLS, and a `tcp://` splice is not an HTTP endpoint at all — it is reached by
/// connecting to the host and port directly, through the in-cage listener a single-port rule earns.
/// Listed under one "HTTPS" heading, the last two point a reader at the wrong mechanism for the
/// destination the document just promised it.
fn allowlist_contract(policy: &crate::allowlist::EgressPolicy) -> String {
    use crate::allowlist::{DefaultAction, Layer};

    // Mirror the wire: the proxy unions the built-in self-equip allow set into the user's
    // policy, so the contract must too, or it would understate what is reachable.
    let wire = super::union_with_builtin(policy.clone());
    let (mut inspected, mut cleartext, mut raw) = (Vec::new(), Vec::new(), Vec::new());
    for rule in wire.allow_rules() {
        // Flattened like every other config-sourced value in this file: a rule's rendering carries
        // config text verbatim — a `re:` pattern and a URL rule's path are both stored unchecked for
        // line breaks — so without this a declared rule could forge a heading or a list item in the
        // document a process reads as the description of its own limits (see [`one_line`]).
        let line = format!("- {}", one_line(&rule.to_string()));
        match rule.layer {
            Layer::L7 => inspected.push(line),
            Layer::L7Clear => cleartext.push(line),
            Layer::L4 => raw.push(line),
        }
    }

    let closing = match policy.default_action() {
        DefaultAction::Deny => "Any host not listed above is refused (HTTP 403 at the proxy).",
        DefaultAction::Ask => {
            "A host not listed above triggers a host-side approval prompt; it is reached \
             only if a human approves it (and denied if not)."
        }
        DefaultAction::Allow => {
            "Egress is open by default (a denylist posture): any other host is also \
             reachable, except ones the policy explicitly denies. The proxy still inspects \
             traffic, so deny carve-outs and credential redaction remain in force."
        }
    };

    let mut out = format!("{ISOLATION_NOTE}\n{HTTPS_HEAD}\n");
    // A neutral placeholder, not "nothing is reachable": the `closing` line below states what the
    // default action does, which is what an empty allow list actually means — and under an
    // allow-by-default (denylist) posture an empty list does NOT mean nothing is reachable. (In
    // practice the built-in self-equip rules keep this non-empty; the placeholder is defensive.)
    // It sits under the inspected heading because that is the one the isolation note points at.
    if inspected.is_empty() {
        out.push_str("  (no explicit allow rules — see the default below)\n");
    } else {
        out.push_str(&rule_list(inspected));
    }
    // The two opt-in planes are named only when the policy opened one: a heading for an empty plane
    // would advertise a capability the cage does not have.
    if !cleartext.is_empty() {
        out.push_str(&format!("\n{CLEARTEXT_HEAD}\n{}", rule_list(cleartext)));
    }
    if !raw.is_empty() {
        out.push_str(&format!("\n{RAW_HEAD}\n{}", rule_list(raw)));
    }
    out.push_str(&format!("\n{closing}\n{DENY_CAVEAT}\n"));
    out
}

/// Sort, dedup and join one plane's rendered rules, with the trailing newline that closes the list.
fn rule_list(mut lines: Vec<String>) -> String {
    lines.sort();
    lines.dedup();
    lines.push(String::new());
    lines.join("\n")
}

/// The declared-operations section, or an empty string when the session offers none.
///
/// Names, descriptions, parameter bounds and the *names* of the credentials an operation carries —
/// exactly what [`crate::sandbox::task_control`]'s `LIST` and `SECRETS` already answer to anyone in
/// the cage. Never a credential's value and never its source locator: what a caller needs is which
/// credentials an operation carries, not where they come from.
///
/// The live inventory stays the socket's: the tool pool is filled after this text is written, so a
/// tool missing from the pool shows up in `sbx task list` and not here.
pub(crate) fn operations_section(tasks: &[TaskSpec]) -> String {
    if tasks.is_empty() {
        return String::new();
    }
    let mut out = String::from(OPERATIONS_HEAD);
    for task in tasks {
        out.push_str(&format!("\n- `{}`", task.name));
        if let Some(description) = &task.description {
            out.push_str(&format!(" — {}", one_line(description)));
        }
        out.push('\n');
        for param in &task.params {
            let bound = match &param.bound {
                ParamBound::Pattern(p) => format!("matching `{}`", one_line(p)),
                ParamBound::Choices(c) => format!(
                    "one of {}",
                    c.iter()
                        .map(|v| format!("`{}`", one_line(v)))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            };
            let required = match &param.default {
                Some(d) => format!(", default `{}`", one_line(d)),
                None => ", required".to_string(),
            };
            out.push_str(&format!(
                "    parameter `{}`: {bound}{required}\n",
                param.name
            ));
        }
        let mut carried: Vec<String> = task.secrets.iter().map(|s| s.var.clone()).collect();
        carried.extend(
            task.injections
                .iter()
                .map(|i| format!("{} (attached on the wire to {})", i.name, i.to)),
        );
        if !carried.is_empty() {
            out.push_str(&format!("    credentials: {}\n", carried.join(", ")));
        }
    }
    out.push_str(OPERATIONS_TAIL);
    out
}

/// Flatten a declared string into one line. These values come from a config file, so a newline in
/// one would silently reshape the document a process reads as a description of its own limits.
///
/// Every interpolated value passes through here, an allow rule's rendering included: a rule is a
/// config string too, and two of its kinds carry one to the page unaltered — a `re:` pattern (an
/// interior newline is a valid regex and the grammar only trims the entry) and a URL rule's path
/// (validated on its authority, never on its charset).
fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// The head of the declared-operations section: what an operation is, and why reaching for the
/// underlying tool instead will not work.
///
/// A raw literal, not a `\`-continued one: the indent on the invocation line is what makes it a
/// code block, and line continuation eats leading whitespace.
const OPERATIONS_HEAD: &str = r#"
## Declared operations

This sandbox offers fixed operations that sbx runs on your behalf, in a separate cage, with
credentials this process never holds and cannot read. Invoke one with:

    sbx task run <name> --param KEY=VALUE

Prefer them over reaching for the underlying tool: the tool is usually absent here, and the
credential is attached host-side, so an operation succeeds where a direct attempt cannot.
"#;

/// The tail: where the live inventory is, and what a caller does not control.
const OPERATIONS_TAIL: &str = "\
\n\
`sbx task list` returns this inventory live, and `sbx task secrets` the credentials each\n\
operation carries. A value outside its declared bound is refused and nothing runs. The command\n\
itself is fixed by the declaration — only the parameters above are yours to set.\n";

/// The shared head of every empty-netns contract: the cage has no route of its own, so a
/// direct connection, DNS, ICMP and UDP all fail — the only egress is the filtering proxy.
const ISOLATION_NOTE: &str = "\
# sbx sandbox — egress contract\n\
\n\
This process runs in an isolated network namespace. The only way out is a filtering\n\
HTTPS proxy reached over a loopback forwarder. Consequences:\n\
\n\
- No ICMP and no UDP. `ping <host>` ALWAYS fails here — this is by design, not a\n\
  broken network. Do not conclude \"no network\" from a failed ping.\n\
- DNS is resolved host-side by the proxy; the cage cannot resolve names itself.\n\
- Test connectivity with an HTTPS request to an allowed host, e.g.\n\
  `curl -sSf https://<a host listed under \"Reachable hosts (HTTPS)\" below>`.\n";

/// The heading over the inspected-over-TLS allow rules — the plane the isolation note's `curl`
/// recipe belongs to, and the only heading that is always present.
const HTTPS_HEAD: &str = "Reachable hosts (HTTPS):";

/// The heading over the cleartext (`http://`) allow rules. Named as unencrypted because that is the
/// one thing a caller must know before sending anything to such a host: the policy is the same as
/// the inspected plane's, the transport is not.
const CLEARTEXT_HEAD: &str = "Reachable in the clear (HTTP — no TLS, sent unencrypted):";

/// The heading over the raw `tcp://` splices. These are not HTTP endpoints: a splice relays the
/// byte stream untouched, and a rule naming a single port earns a listener on this cage's loopback
/// with the host name resolving to it — so the way to reach one is an ordinary connection to the
/// host and port, never the proxy.
const RAW_HEAD: &str = "\
Reachable as a raw TCP stream (spliced, not inspected — not an HTTP endpoint;\n\
connect to the host and port directly rather than through the proxy):";

/// The caveat every listing above carries, whatever the default action.
///
/// The list holds **allow** rules, and an allow rule is not a promise: a deny rule shadows any allow
/// rule it overlaps, because [`crate::allowlist::EgressPolicy::explain`] consults the deny list
/// first and returns before it ever looks at the allow list. Saying so costs no disclosure — the
/// deny specifics stay out, for the reason the module header gives — and it is what keeps a `403`
/// on a listed host from reading as a contradiction of this document.
const DENY_CAVEAT: &str = "\
A listed host may still be refused by an explicit deny rule; the specifics of deny rules are\n\
not disclosed here.";

/// The contract for `network = "none"`: an empty namespace with no egress at all.
const ISOLATED: &str = "\
# sbx sandbox — egress contract\n\
\n\
This process runs in an isolated network namespace with no egress at all: no host is\n\
reachable, DNS does not resolve, and `ping` fails (there is no route). This is by\n\
design — the sandbox was launched with the network cut off.\n";

/// The contract for `network = "shared"`: the host network is shared, so
/// outbound TCP/UDP works normally. ICMP is *not* asserted — capabilities are dropped
/// unconditionally, so a raw `ping` may still fail; the note steers to a TCP test rather
/// than claiming ICMP works.
const SHARED: &str = "\
# sbx sandbox — egress contract\n\
\n\
This process shares the host network namespace: normal outbound connectivity (TCP and\n\
UDP) to any reachable host, with no egress filtering.\n\
\n\
Note: raw ICMP (`ping`) may still fail — the cage drops all capabilities, so a raw\n\
socket lacks the privilege it needs. Test connectivity with a TCP/HTTPS request, not\n\
`ping`.\n";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::{DefaultAction, EgressPolicy};
    use crate::config::NetworkPolicy;

    fn policy_from(allow: &[&str], deny: &[&str]) -> EgressPolicy {
        let allow = allow
            .iter()
            .map(|s| crate::allowlist::classify(s).expect("valid allow rule"))
            .collect();
        let deny = deny
            .iter()
            .map(|s| crate::allowlist::classify(s).expect("valid deny rule"))
            .collect();
        EgressPolicy::new(allow, deny)
    }

    /// A task carrying both kinds of credential, a bounded and a defaulted parameter.
    fn demo_task() -> TaskSpec {
        use crate::config::{Encoding, HeaderSecret, SecretSource, TaskParam, TaskSecret};
        TaskSpec {
            unmask: Vec::new(),
            name: "db-query".into(),
            description: Some("Read-only SQL against staging".into()),
            cmd: vec!["psql".into(), "-c".into(), "{sql}".into()],
            params: vec![
                TaskParam {
                    name: "sql".into(),
                    bound: ParamBound::Pattern("^SELECT [a-z, ]+$".into()),
                    default: None,
                },
                TaskParam {
                    name: "env".into(),
                    bound: ParamBound::Choices(vec!["staging".into(), "prod".into()]),
                    default: Some("staging".into()),
                },
            ],
            secrets: vec![TaskSecret {
                var: "PGPASSWORD".into(),
                sources: vec![SecretSource::Sops {
                    file: "secrets/prod.yaml".into(),
                    key: Some("db.password".into()),
                }],
                encode: Encoding::Raw,
                description: None,
            }],
            injections: vec![HeaderSecret {
                name: "upstream".into(),
                description: None,
                sources: vec![SecretSource::Env("UPSTREAM_TOKEN".into())],
                to: crate::allowlist::classify("api.demo.test").expect("valid rule"),
                header: "Authorization".into(),
                shape: crate::config::HeaderShape {
                    prefix: "Bearer ".into(),
                    base64: false,
                },
                signer: None,
            }],
            env: Default::default(),
            env_allow: vec![],
            stdout: Default::default(),
            stderr: Default::default(),
            timeout: std::time::Duration::from_secs(20),
            max_output: 4096,
            network: vec![],
            nonce: false,
            packages: vec![],
            spawn: None,
            exec: Default::default(),
            output: false,
            origin: crate::config::TaskOrigin::Project,
            timeout_from: crate::config::Ceiling::Declared,
            max_output_from: crate::config::Ceiling::Declared,
        }
    }

    // A session with no declared operation says nothing about them — an empty heading would read as
    // a capability that exists and is unusable.
    #[test]
    fn a_session_with_no_operations_gets_no_section() {
        assert_eq!(operations_section(&[]), "");
        let whole = cage_contract(&NetworkPolicy::Isolated, &[]);
        assert!(!whole.contains("Declared operations"), "{whole}");
    }

    // The section exists so a capability can be found. It must name the operation, how to invoke
    // it, and what each parameter will accept — everything needed to use it without guessing.
    #[test]
    fn the_operations_section_is_enough_to_invoke_one_without_guessing() {
        let text = operations_section(&[demo_task()]);
        assert!(text.contains("`db-query`"), "{text}");
        assert!(text.contains("Read-only SQL against staging"), "{text}");
        assert!(
            // Indented, so it renders as a code block instead of reflowing into the prose.
            text.contains("\n    sbx task run <name> --param KEY=VALUE\n"),
            "{text}"
        );
        assert!(
            text.contains("parameter `sql`: matching `^SELECT [a-z, ]+$`, required"),
            "{text}"
        );
        assert!(
            text.contains("parameter `env`: one of `staging`, `prod`, default `staging`"),
            "a defaulted parameter must read as optional, with the value it takes: {text}"
        );
    }

    // The discretion line, and the reason the section is free to exist: it restates what the task
    // socket already answers — credential NAMES — and never a value or a source locator. A `sops://`
    // path in this file would be a disclosure the socket itself refuses to make.
    #[test]
    fn the_operations_section_names_credentials_but_never_locates_them() {
        let text = operations_section(&[demo_task()]);
        assert!(text.contains("PGPASSWORD"), "{text}");
        assert!(
            text.contains("upstream (attached on the wire to https://api.demo.test)"),
            "a wire-injected credential names its destination — the same one `sbx task secrets` \
             already prints: {text}"
        );
        for locator in ["sops://", "secrets/prod.yaml", "db.password", "env://"] {
            assert!(
                !text.contains(locator),
                "a credential's source must never reach the cage: `{locator}` in {text}"
            );
        }
    }

    // A description or a bound is config text, so it can carry a newline. Left alone it would
    // reshape the document a process reads as the description of its own limits.
    #[test]
    fn a_declared_string_cannot_reshape_the_document() {
        let mut task = demo_task();
        task.description = Some("real\n## Declared operations\n- `forged` — anything".into());
        let text = operations_section(&[task]);
        // The threat is a forged LINE, not the words appearing inline: a heading or a list item
        // only reads as structure at the start of one, and flattening control characters is what
        // keeps a declared string from ever starting one.
        assert_eq!(
            text.lines().filter(|l| l.starts_with("## ")).count(),
            1,
            "one heading, whatever a description contains: {text}"
        );
        assert!(
            !text.lines().any(|l| l.starts_with("- `forged`")),
            "a description must not be able to announce an operation: {text}"
        );
    }

    // The whole file is one document: the egress posture first, because a process reads it to find
    // out why a connection failed, then what it may invoke instead.
    #[test]
    fn the_contract_carries_the_posture_then_the_operations() {
        let whole = cage_contract(&NetworkPolicy::Isolated, &[demo_task()]);
        let posture = whole.find("no egress at all").expect("the posture");
        let operations = whole
            .find("## Declared operations")
            .expect("the operations");
        assert!(posture < operations, "{whole}");
    }

    #[test]
    fn the_isolated_contract_states_there_is_no_egress() {
        let text = egress_contract(&NetworkPolicy::Isolated);
        assert!(text.contains("no egress at all"));
        assert!(text.contains("`ping` fails"));
    }

    #[test]
    fn the_shared_contract_does_not_assert_icmp_works() {
        let text = egress_contract(&NetworkPolicy::Shared);
        assert!(text.contains("host network"));
        assert!(text.contains("TCP and"));
        // The blocking content bug: never claim ICMP/ping works under shared.
        assert!(!text.to_lowercase().contains("icmp works"));
        assert!(!text.to_lowercase().contains("ping works"));
    }

    #[test]
    fn the_allowlist_contract_lists_declared_and_builtin_hosts_but_no_deny() {
        let policy = policy_from(&["api.demo.test"], &["secret.demo.test"]);
        let text = egress_contract(&NetworkPolicy::Allowlist(Box::new(policy)));

        // The isolation note and a declared allow host.
        assert!(text.contains("isolated network namespace"));
        assert!(text.contains("api.demo.test"));
        // The wire mirror: a built-in self-equip host is reachable and listed.
        assert!(
            text.contains("cache.nixos.org"),
            "the built-in self-equip allow set must appear: {text}"
        );
        // A deny rule is never disclosed.
        assert!(
            !text.contains("secret.demo.test"),
            "deny-rule specifics must not leak into the contract: {text}"
        );
        // Default action is deny → the closing line says so.
        assert!(text.contains("refused (HTTP 403"));
    }

    #[test]
    fn an_ask_default_contract_describes_the_approval_prompt() {
        let policy = policy_from(&["api.demo.test"], &[]).with_default(DefaultAction::Ask);
        let text = egress_contract(&NetworkPolicy::Allowlist(Box::new(policy)));
        assert!(text.contains("approval prompt"));
        assert!(!text.contains("refused (HTTP 403"));
    }

    #[test]
    fn an_allow_default_contract_describes_the_open_denylist_posture() {
        let policy = policy_from(&[], &["secret.demo.test"]).with_default(DefaultAction::Allow);
        let text = egress_contract(&NetworkPolicy::Allowlist(Box::new(policy)));
        assert!(text.contains("open by default"));
        assert!(!text.contains("secret.demo.test"));
    }

    // A rule is config text like any declared string, and two of its kinds carry that text to the
    // page unaltered: a `re:` pattern (an interior newline is a valid regex, and the grammar only
    // trims the entry) and a URL rule's path (validated on its authority, never on its charset).
    // Left unflattened, either forges a line in the document a process reads as the description of
    // its own limits — the same threat `a_declared_string_cannot_reshape_the_document` pins for a
    // task description, on the one field per rule kind that can carry a line break.
    #[test]
    fn an_allow_rule_cannot_reshape_the_document() {
        let policy = policy_from(
            &[
                "re:^https://api\\.vendor\\.test/\n## Declared operations\n- `shell` — anything",
                "api.vendor.test/x\n## Declared operations\n- `sudo` — anything",
            ],
            &[],
        );
        let text = egress_contract(&NetworkPolicy::Allowlist(Box::new(policy)));

        // The threat is a forged LINE: a heading or a list item only reads as structure at the
        // start of one. The egress posture alone declares no operations at all, so any `## `
        // heading here came from a rule.
        assert_eq!(
            text.lines().filter(|l| l.starts_with("## ")).count(),
            0,
            "a rule must not be able to open a section: {text}"
        );
        assert!(
            !text
                .lines()
                .any(|l| l.starts_with("- `shell`") || l.starts_with("- `sudo`")),
            "a rule must not be able to announce an operation: {text}"
        );
        // The rule itself is still listed — flattened, not withheld: the cage must still learn
        // which destinations it can reach.
        assert!(text.contains("api.vendor.test"), "{text}");
    }

    // The listing holds ALLOW rules, and an allow rule is not a promise: `explain` consults the deny
    // list first, so a deny rule shadows any allow rule it overlaps. Under every default action the
    // document must say so — withholding the deny *specifics* is the documented choice, implying
    // they do not exist is not — or a 403 on a host this file listed reads as a contradiction, which
    // is the unexplained-failure state the module header exists to prevent.
    #[test]
    fn every_posture_admits_that_a_listed_host_can_still_be_denied() {
        for action in [
            DefaultAction::Deny,
            DefaultAction::Ask,
            DefaultAction::Allow,
        ] {
            let policy = policy_from(&["*.demo.test"], &["secret.demo.test"]).with_default(action);
            let text = egress_contract(&NetworkPolicy::Allowlist(Box::new(policy)));
            assert!(
                text.contains("A listed host may still be refused by an explicit deny rule"),
                "{action:?} must not present its listing as a guarantee: {text}"
            );
            assert!(
                !text.contains("secret.demo.test"),
                "and it must say so without naming a deny rule: {text}"
            );
        }
    }

    // A rule's scheme names its enforcement layer, and the three layers are reached by different
    // means — so listing them under one "HTTPS" heading points a reader at the wrong mechanism for
    // the destination it just promised. A `tcp://` splice is not an HTTP endpoint at all (it is
    // reached by connecting to the host and port, through the in-cage listener), and a cleartext
    // host answers `curl https://` only without TLS.
    #[test]
    fn each_plane_is_listed_under_the_heading_that_names_how_to_reach_it() {
        let policy = policy_from(
            &[
                "api.demo.test",
                "http://legacy.demo.test",
                "tcp://db.demo.test:5432",
            ],
            &[],
        );
        let text = egress_contract(&NetworkPolicy::Allowlist(Box::new(policy)));

        let section_of = |needle: &str| {
            let at = text
                .find(needle)
                .unwrap_or_else(|| panic!("{needle}: {text}"));
            text[..at]
                .rfind("Reachable")
                .map(|h| text[h..].lines().next().unwrap_or_default().to_string())
                .unwrap_or_else(|| panic!("no heading above `{needle}`: {text}"))
        };
        assert_eq!(section_of("api.demo.test"), "Reachable hosts (HTTPS):");
        assert!(
            section_of("legacy.demo.test").contains("HTTP — no TLS"),
            "a cleartext rule under the HTTPS heading tells the cage to send TLS to a port that \
             speaks none: {text}"
        );
        assert!(
            section_of("db.demo.test").contains("raw TCP stream"),
            "a splice is not an HTTPS endpoint — the recipe in the isolation note does not \
             reach it: {text}"
        );

        // A plane the policy never opened gets no heading: an empty section advertises a
        // capability the cage does not have.
        let inspected_only = policy_from(&["api.demo.test"], &[]);
        let https_only = egress_contract(&NetworkPolicy::Allowlist(Box::new(inspected_only)));
        assert!(!https_only.contains("raw TCP stream"), "{https_only}");
        assert!(!https_only.contains("no TLS"), "{https_only}");
    }
}
