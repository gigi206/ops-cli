//! The in-cage egress contract: a human- and agent-readable description of what the
//! sandbox's network posture permits, generated from the resolved policy and bound
//! read-only into the cage at [`EGRESS_CONTRACT_INCAGE`].
//!
//! It is purely informational — it enforces nothing (the empty network namespace plus
//! the host filtering proxy are the boundary). Its job is to let a process inside the
//! cage understand *why* a direct connection or a `ping` fails and *which* hosts it can
//! actually reach, without running the host-side `ops net` tools (which it cannot, from
//! inside the cage). The companion `OPS_SANDBOX=1` / `OPS_EGRESS_CONTRACT` environment
//! variables (set by the assembler) are the discovery handle: a tool reads the file the
//! second variable points at.

use crate::config::NetworkPolicy;

/// Where the generated contract is bound read-only inside the cage. Also the value of
/// the `OPS_EGRESS_CONTRACT` environment variable, so a tool need not hard-code the path.
/// Under `/opt/ops`, beside the mise plugin and the shell rc, colliding with no
/// structural mount.
pub(crate) const EGRESS_CONTRACT_INCAGE: &str = "/opt/ops/egress-contract.md";

/// Render the egress contract for a resolved network posture. Pure: the text derives only
/// from the policy.
///
/// For an allowlist, the reachable-host list mirrors the **wire** policy — the built-in
/// self-equip allow set is unioned in exactly as the proxy does, so the contract lists
/// what is actually reachable, not only what the config spelled out. Only **allow** rules
/// are listed: a process legitimately learns which hosts it can reach (it would discover
/// them by connecting anyway), but the specifics of deny rules are **not** disclosed — a
/// global deny the agent cannot read must not leak through the contract.
pub(crate) fn egress_contract(policy: &NetworkPolicy) -> String {
    match policy {
        NetworkPolicy::Isolated => ISOLATED.to_string(),
        NetworkPolicy::Shared => SHARED.to_string(),
        NetworkPolicy::Allowlist(policy) => allowlist_contract(policy),
    }
}

/// The contract for a filtered-egress (allowlist) posture: the isolation note, then the
/// reachable hosts, then a closing line whose wording follows the default action.
fn allowlist_contract(policy: &crate::allowlist::EgressPolicy) -> String {
    use crate::allowlist::DefaultAction;

    // Mirror the wire: the proxy unions the built-in self-equip allow set into the user's
    // policy, so the contract must too, or it would understate what is reachable.
    let wire = super::union_with_builtin(policy.clone());
    let mut hosts: Vec<String> = wire
        .allow_rules()
        .iter()
        .map(|rule| format!("- {rule}"))
        .collect();
    hosts.sort();
    hosts.dedup();
    let hosts = if hosts.is_empty() {
        "  (no allow rules — nothing is reachable by default)".to_string()
    } else {
        hosts.join("\n")
    };

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

    format!("{ISOLATION_NOTE}\nReachable hosts (HTTPS):\n{hosts}\n\n{closing}\n")
}

/// The shared head of every empty-netns contract: the cage has no route of its own, so a
/// direct connection, DNS, ICMP and UDP all fail — the only egress is the filtering proxy.
const ISOLATION_NOTE: &str = "\
# ops sandbox — egress contract\n\
\n\
This process runs in an isolated network namespace. The only way out is a filtering\n\
HTTPS proxy reached over a loopback forwarder. Consequences:\n\
\n\
- No ICMP and no UDP. `ping <host>` ALWAYS fails here — this is by design, not a\n\
  broken network. Do not conclude \"no network\" from a failed ping.\n\
- DNS is resolved host-side by the proxy; the cage cannot resolve names itself.\n\
- Test connectivity with an HTTPS request to an allowed host, e.g.\n\
  `curl -sSf https://<one of the hosts below>`.\n";

/// The contract for `network = "none"`: an empty namespace with no egress at all.
const ISOLATED: &str = "\
# ops sandbox — egress contract\n\
\n\
This process runs in an isolated network namespace with no egress at all: no host is\n\
reachable, DNS does not resolve, and `ping` fails (there is no route). This is by\n\
design — the sandbox was launched with the network cut off.\n";

/// The contract for `network = "shared"` (the default): the host network is shared, so
/// outbound TCP/UDP works normally. ICMP is *not* asserted — capabilities are dropped
/// unconditionally, so a raw `ping` may still fail; the note steers to a TCP test rather
/// than claiming ICMP works.
const SHARED: &str = "\
# ops sandbox — egress contract\n\
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
        let text = egress_contract(&NetworkPolicy::Allowlist(policy));

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
        let text = egress_contract(&NetworkPolicy::Allowlist(policy));
        assert!(text.contains("approval prompt"));
        assert!(!text.contains("refused (HTTP 403"));
    }

    #[test]
    fn an_allow_default_contract_describes_the_open_denylist_posture() {
        let policy = policy_from(&[], &["secret.demo.test"]).with_default(DefaultAction::Allow);
        let text = egress_contract(&NetworkPolicy::Allowlist(policy));
        assert!(text.contains("open by default"));
        assert!(!text.contains("secret.demo.test"));
    }
}
