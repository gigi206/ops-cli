//! `sbx test <kind> <target>`: probe whether an access would be allowed and explain why — a
//! diagnostic surface (currently `net <url>`, testing a URL against the egress policy a launch
//! serves). No launch, no nix, no network. The app-overlay fold and the `net_mode_word` keyword it
//! shares with `sbx net`/`sbx config` stay at the crate root, referenced via crate::.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::process::ExitCode;

use crate::fold_app_overlay;
use crate::{allowlist, config, diag, help, sandbox, style};

/// `sbx test <kind> <target>`: probe whether an access would be allowed and explain why —
/// a diagnostic surface meant to grow with sbx's access controls (currently the network
/// egress allowlist). No launch, no nix, no network.
pub(crate) fn test_cmd(args: Vec<OsString>) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("net") => net_test(&args[1..]),
        // Unknown or no kind: name the mistake (if any), then print the full page so its
        // Subcommands list guides, like bare `sbx net`/`sbx config`.
        other => {
            if let Some(tok) = other {
                diag::error(&format!("sbx: test: unknown kind {tok:?}"));
            }
            eprint!("{}", help::page_usage(&["test"]).unwrap_or_default());
            ExitCode::from(2)
        }
    }
}

/// `sbx test net [--app <name>] <url>`: test a URL against the egress policy a launch serves and
/// report the rule that decides it. A diagnostic for the egress allowlist — it reflects the trust
/// gate (an untrusted project's policy is dropped, so the *effective* posture is shown), folds in a
/// named app's overlay when `--app` is given, includes the built-in allow-set the proxy
/// always unions, and notes a credential the proxy would inject (by header and source, never its
/// value). A bare host with no scheme is completed to `https://`. No launch, no nix, no network.
/// Exit status is informational only (success), since "the URL would be denied" is a valid answer.
fn net_test(args: &[OsString]) -> ExitCode {
    // An optional `--app/-a <name>`, an optional `--method/-X <verb>` (the HTTP method to test,
    // default GET), and the positional target (a URL or a bare host), in any order.
    let mut app: Option<String> = None;
    let mut method: String = "GET".to_string();
    let mut target: Option<&str> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--app") | Some("-a") => {
                let Some(name) = it.next().and_then(|n| n.to_str()) else {
                    diag::error("sbx: test net: `--app` needs an app name");
                    return ExitCode::from(2);
                };
                app = Some(name.to_string());
            }
            Some("--method") | Some("-X") => {
                let Some(m) = it.next().and_then(|n| n.to_str()) else {
                    diag::error("sbx: test net: `--method` needs an HTTP verb (e.g. GET, POST)");
                    return ExitCode::from(2);
                };
                method = m.to_ascii_uppercase();
            }
            Some(s) if target.is_none() => target = Some(s),
            Some(s) => {
                diag::error(&format!("sbx: test net: unexpected argument `{s}`"));
                return ExitCode::from(2);
            }
            None => {
                diag::error("sbx: test net: an argument is not valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    let Some(target) = target else {
        diag::error(&format!("sbx: usage: {}", help::synopsis("test")));
        return ExitCode::from(2);
    };

    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the current directory: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let mut resolved = config::load(&cwd);
    for w in &resolved.warnings {
        diag::warn(w);
    }
    // Fold a named app's overlay onto the baseline so the URL is tested against the *effective*
    // policy `sbx app <name>` would launch with (its own posture, allow/deny rules, credentials),
    // not the bare baseline.
    if let Some(name) = &app
        && let Err(e) = fold_app_overlay(&mut resolved, name)
    {
        diag::error(&format!("sbx: test net: {e}"));
        return ExitCode::from(2);
    }

    // A bare host (no scheme) is completed to https — the common case for a quick check.
    let url = if target.contains("://") {
        target.to_string()
    } else {
        format!("https://{target}")
    };

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, r) = (pal.head, pal.reset);
    // Names which posture is in view: the baseline, or one app's effective overlay.
    let scope = match &app {
        Some(name) => format!(" (app {name})"),
        None => String::new(),
    };
    match &resolved.network {
        config::NetworkPolicy::Shared => {
            println!(
                "{h}network{scope}:{r} shared (host network) — every URL is reachable; no allowlist to test"
            );
            ExitCode::SUCCESS
        }
        config::NetworkPolicy::Isolated => {
            println!("{h}network{scope}:{r} none (isolated) — no URL is reachable");
            ExitCode::SUCCESS
        }
        config::NetworkPolicy::Allowlist(policy) => {
            // Build the *effective* policy a launch serves: the user rules plus the built-in
            // allow-set the proxy always unions — the single source of truth, so the verdict here
            // matches the wire (e.g. a cache host reads as allowed, not deny-default).
            let effective = sandbox::union_with_builtin(policy.clone());
            // A one-line header so an ALLOWED/DENIED verdict on an arbitrary URL is
            // self-explanatory — it names the default the policy applies to an unmatched request.
            let mode = match effective.default_action() {
                allowlist::DefaultAction::Deny => {
                    "deny (allowlist — only listed and built-in hosts reach)"
                }
                allowlist::DefaultAction::Allow => {
                    "allow (denylist — every public host reaches except the deny rules)"
                }
                allowlist::DefaultAction::Ask => {
                    "ask (an unmatched host parks for a live `sbx net pending` decision)"
                }
            };
            println!("{h}network{scope}:{r} {mode}");
            // A `tcp://` target is a raw-splice question, decided on host:port alone through the same
            // `l4_decision` the proxy uses (so the tester cannot drift from the wire). The L7 default
            // action above does not apply to it — a raw splice is strictly opt-in via a `tcp://` rule.
            if target.starts_with("tcp://") {
                let (host, port) = match allowlist::parse_tcp_target(target) {
                    Ok(t) => t,
                    Err(e) => {
                        diag::error(&format!("sbx: {e}"));
                        return ExitCode::from(2);
                    }
                };
                let l4 = effective.l4_decision(&host, port);
                // A spliced connection meets the same post-resolution address guard as an inspected
                // one, so replay it on an IP literal (no resolution needed) rather than report a
                // splice the proxy would refuse. A `tcp://` rule always names its host exactly, so
                // the private-address exception applies here; only a never-reachable address (a
                // link-local, the cloud metadata one, multicast) is refused.
                if let allowlist::L4Decision::Splice(rule) = &l4
                    && let Some(refusal) = literal_addr_refusal(&host, Some(rule))
                {
                    print!(
                        "{}",
                        render_addr_refusal(
                            target,
                            &format!("a tcp:// rule allows the splice ({rule})"),
                            &refusal,
                            &pal
                        )
                    );
                    return ExitCode::SUCCESS;
                }
                print!("{}", render_l4_decision(target, &l4, &pal));
                return ExitCode::SUCCESS;
            }
            let (host, port, path) = match allowlist::parse_url_target(&url) {
                Ok(t) => t,
                Err(e) => {
                    diag::error(&format!("sbx: {e}"));
                    return ExitCode::from(2);
                }
            };
            // An `http://` URL is a cleartext (L7Clear) question, decided through the same
            // `explain_clear` the proxy's absolute-form handler uses (so the tester cannot drift from
            // the wire). Cleartext is strictly opt-in: only an explicit `http://` allow permits it —
            // the L7 default action above does not open it, so a bare host stays HTTPS-only here too.
            let clear = url.starts_with("http://");
            let decision = if clear {
                effective.explain_clear(&host, port, &path, &method)
            } else {
                effective.explain(&host, port, &path, &method)
            };
            // Tag a request allowed *only* by the built-in set (not the user's own
            // rules), so "why does this pass — I never allowed it?" is answerable. The union adds
            // only allow rules, so an effective `AllowedBy` the user policy does not also allow can
            // only be the built-in set. Discriminate on the user verdict's own variant (definitely
            // "the user allowed it") rather than a separate predicate. The `clear` question is
            // decided through the same `explain_clear`, so the tag matches the wire (the built-in set
            // is all `https://` hosts, so a cleartext allow is always the user's own).
            let user_decision = if clear {
                policy.explain_clear(&host, port, &path, &method)
            } else {
                policy.explain(&host, port, &path, &method)
            };
            let user_allowed = matches!(
                user_decision,
                allowlist::Decision::AllowedBy(_) | allowlist::Decision::AllowedDefault
            );
            let builtin = matches!(decision, allowlist::Decision::AllowedBy(_)) && !user_allowed;
            // The policy verdict is only half of what the wire does: the proxy resolves the host and
            // runs the address guard before connecting. Replay that guard here so the tester does not
            // promise a pass the proxy refuses. On an **IP literal** the answer is exact and needs no
            // resolution, so it replaces the verdict; on a **name** the tester resolves nothing (no
            // network), so it can only note the condition, and only when the deciding rule does not
            // name the host exactly (the one shape the guard admits for a private address).
            let deciding = match &decision {
                allowlist::Decision::AllowedBy(rule) => Some(*rule),
                _ => None,
            };
            let allowed = matches!(
                decision,
                allowlist::Decision::AllowedBy(_) | allowlist::Decision::AllowedDefault
            );
            if allowed && let Some(refusal) = literal_addr_refusal(&host, deciding) {
                let by = match deciding {
                    Some(rule) => format!("the policy allows it (allow rule: {rule})"),
                    None => "the policy allows it (allow-by-default)".to_string(),
                };
                print!("{}", render_addr_refusal(&url, &by, &refusal, &pal));
                return ExitCode::SUCCESS;
            }
            print!("{}", render_net_decision(&url, &decision, builtin, &pal));
            if allowed
                && host.parse::<std::net::IpAddr>().is_err()
                && !sandbox::names_exact_host(&host, deciding)
            {
                print!("{}", render_private_name_note(&pal));
            }
            // The policy permitting an inspected request is not the same as the cage being able to
            // make it: a loopback host is exempt from the cage's proxy and gets no in-cage listener,
            // so nothing inside takes this rule. Said here because this command is what an author
            // checks before concluding the host's loopback is unreachable.
            if allowed && sandbox::egress::proxy_exempt(&host) {
                print!("{}", render_loopback_note(&host, port, &pal));
            }
            // On an allowed request, surface any credential the proxy would inject for this exact
            // destination — by header and source locator only, never the value, and with no I/O. A
            // **cleartext** (`http://`) request never receives an injection (a bearer is not sent in
            // the clear — the proxy skips injection wholesale), so no note is shown for it.
            if !clear
                && matches!(
                    decision,
                    allowlist::Decision::AllowedBy(_) | allowlist::Decision::AllowedDefault
                )
            {
                for secret in &resolved.secrets {
                    if allowlist::rule_matches(&secret.to, &host, port, &path) {
                        print!("{}", render_injection_note(secret, &pal));
                    }
                }
            }
            ExitCode::SUCCESS
        }
    }
}

/// Render an egress allowlist decision — a pure presenter (so its colored layout is asserted in a
/// test): the verdict (`ALLOWED` green / `DENIED` red), the URL and the deciding rule as
/// identifiers (cyan, matching how `sbx config` renders allow/deny rules), and the reason as
/// de-emphasized prose. Every span is empty under a non-terminal, so a capture is plain text.
fn render_net_decision(
    url: &str,
    decision: &allowlist::Decision,
    builtin: bool,
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (n, ok, err, dim, r) = (pal.name, pal.ok, pal.err, pal.dim, pal.reset);
    let mut o = String::new();
    match decision {
        allowlist::Decision::AllowedBy(rule) => {
            let _ = writeln!(o, "{ok}ALLOWED{r}  {n}{url}{r}");
            // Name the source when the allow came from the built-in self-equip set rather than a
            // user rule, so a pass the config did not declare is explained, not surprising.
            if builtin {
                let _ = writeln!(o, "  {dim}by allow rule (built-in):{r} {n}{rule}{r}");
            } else {
                let _ = writeln!(o, "  {dim}by allow rule:{r} {n}{rule}{r}");
            }
            // Testing one URL against a catch-all proves nothing about *this* URL: the rule admits
            // every host, so the pass would look identical for a destination the author never meant
            // to open. Say it here, where a reader is asking exactly "why did this pass".
            if rule.opens_every_host() {
                let _ = writeln!(
                    o,
                    "  {dim}note: that rule matches every host — this URL is not what makes it \
                     pass{r}"
                );
            }
        }
        allowlist::Decision::DeniedBy(rule) => {
            let _ = writeln!(o, "{err}DENIED{r}   {n}{url}{r}");
            let _ = writeln!(o, "  {dim}by deny rule (deny wins):{r} {n}{rule}{r}");
        }
        allowlist::Decision::DeniedDefault => {
            let _ = writeln!(o, "{err}DENIED{r}   {n}{url}{r}");
            let _ = writeln!(o, "  {dim}no allow rule matches (deny-by-default){r}");
        }
        allowlist::Decision::AllowedDefault => {
            let _ = writeln!(o, "{ok}ALLOWED{r}  {n}{url}{r}");
            let _ = writeln!(o, "  {dim}no deny rule matches (allow-by-default){r}");
        }
        allowlist::Decision::Ask => {
            // No static verdict: at launch this request would park for a live decision. Use the
            // dim hue (neither pass nor fail) so a tester reading the column is not misled.
            let _ = writeln!(o, "{dim}WOULD ASK{r} {n}{url}{r}");
            let _ = writeln!(
                o,
                "  {}",
                style::dim_prose(
                    "no rule matches (ask-by-default — it would park for `sbx net pending`)",
                    pal
                )
            );
        }
    }
    o
}

/// Render an L4 (`tcp://`) raw-splice decision for `sbx test net tcp://host:port` — a pure presenter
/// (its color is asserted in a test). A raw splice is strictly opt-in, so the verdict is binary:
/// SPLICED (a `tcp://` allow rule covers this host:port and no host-level deny suppresses it — the
/// proxy tunnels it uninspected) or NOT SPLICED (the connection would instead take the inspected L7
/// path, which a non-HTTP protocol cannot satisfy). Every span is empty under a non-terminal, so a
/// capture is plain text.
fn render_l4_decision(target: &str, l4: &allowlist::L4Decision, pal: &style::Palette) -> String {
    use std::fmt::Write as _;
    let (n, ok, err, dim, r) = (pal.name, pal.ok, pal.err, pal.dim, pal.reset);
    let mut o = String::new();
    match l4 {
        allowlist::L4Decision::Splice(rule) => {
            let _ = writeln!(
                o,
                "{ok}SPLICED{r}  {n}{target}{r} {dim}(raw L4 — uninspected){r}"
            );
            let _ = writeln!(o, "  {dim}by allow rule:{r} {n}{rule}{r}");
        }
        allowlist::L4Decision::Suppressed(rule) => {
            let _ = writeln!(o, "{err}NOT SPLICED{r} {n}{target}{r}");
            let _ = writeln!(
                o,
                "  {dim}a deny rule suppressed the raw splice (deny wins): the connection takes the \
                 inspected L7 path, where it is denied (or, for a non-TLS protocol, the handshake \
                 fails closed). To allow raw access, drop or narrow the deny.{r}"
            );
            let _ = writeln!(o, "  {dim}by deny rule:{r} {n}{rule}{r}");
        }
        allowlist::L4Decision::NoMatch => {
            let _ = writeln!(o, "{err}NOT SPLICED{r} {n}{target}{r}");
            let _ = writeln!(
                o,
                "  {}",
                style::dim_prose(
                    "no tcp:// rule covers this host:port — a raw tunnel needs an explicit \
                     `tcp://host:port` allow (a bare/https:// rule is inspected L7, which a \
                     non-HTTP protocol cannot satisfy)",
                    pal
                )
            );
        }
    }
    o
}

/// The post-resolution address guard's verdict for a target whose host is an **IP literal**, or
/// `None` when the host is a name (nothing to classify without resolving it, which this command
/// never does) or the address is reachable. Delegates to the same `ip_refusal` the proxy's connect
/// paths use, so the tester cannot drift from the wire.
fn literal_addr_refusal(
    host: &str,
    deciding: Option<&allowlist::Rule>,
) -> Option<sandbox::AddrRefusal> {
    let ip = host.parse::<std::net::IpAddr>().ok()?;
    sandbox::ip_refusal(ip, host, deciding)
}

/// Render a target the policy permits but the proxy's address guard refuses before connecting — a
/// pure presenter (its color is asserted in a test). The verdict line is the *wire's* answer
/// (DENIED), and the reason carries both halves: which rule permitted it, and why the address is
/// refused anyway. Every span is empty under a non-terminal, so a capture is plain text.
fn render_addr_refusal(
    target: &str,
    permitted_by: &str,
    refusal: &sandbox::AddrRefusal,
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (n, err, r) = (pal.name, pal.err, pal.reset);
    let why = match refusal {
        sandbox::AddrRefusal::PrivateWithoutExactHost => {
            "a private or loopback address is reachable only when the deciding rule names that \
             exact host"
        }
        sandbox::AddrRefusal::NeverReachable => {
            "a link-local (the cloud metadata address among them), multicast or unspecified \
             address is never reachable, however the policy is written"
        }
    };
    let mut o = String::new();
    let _ = writeln!(o, "{err}DENIED{r}   {n}{target}{r}");
    let _ = writeln!(
        o,
        "  {}",
        style::dim_prose(
            &format!("{permitted_by}, but the proxy refuses the address at connect time: {why}"),
            pal
        )
    );
    o
}

/// Render the dim "this name may resolve to an address the guard refuses" note — the honest answer
/// for a **name** under a rule that does not name it exactly, since resolving it is the one thing
/// this command will not do. A pure presenter (its color is asserted in a test).
fn render_private_name_note(pal: &style::Palette) -> String {
    format!(
        "  {}\n",
        style::dim_prose(
            "note: if this name resolves to a private or loopback address, the proxy refuses it at \
             connect time (no rule names this exact host)",
            pal
        )
    )
}

/// Render the dim "the policy allows it, the cage cannot take it" note for an inspected request to a
/// loopback host — the one shape where an `ALLOWED` verdict is true of the proxy and false of every
/// client inside the cage. Names the way through (a `tcp://` rule, which does get a listener) rather
/// than only the obstacle. A pure presenter (its color is asserted in a test); every span is empty
/// under a non-terminal, so a capture is plain text.
fn render_loopback_note(host: &str, port: u16, pal: &style::Palette) -> String {
    format!(
        "  {}\n",
        style::dim_prose(
            &format!(
                "note: the proxy would allow this, but nothing in the cage asks it — {host} is \
                 exempt from the cage's proxy (`no_proxy`) and an inspected rule gets no in-cage \
                 listener; declare `tcp://{host}:{port}` to reach the service on your own loopback"
            ),
            pal
        )
    )
}

/// Render the dim "+ a credential would be injected" note for a secret whose destination matches
/// the tested request — by header name and source locator only (never the plaintext, and with no
/// I/O), mirroring how `sbx config` describes a credential. A pure presenter (its color is asserted
/// in a test); every span is empty under a non-terminal, so a capture is plain text.
fn render_injection_note(secret: &config::HeaderSecret, pal: &style::Palette) -> String {
    let (dim, n, r) = (pal.dim, pal.name, pal.reset);
    format!(
        "  {dim}+ a credential would be injected:{r} {n}{}{r} {dim}(from {}){r}\n",
        secret.headers().join(", "),
        secret.describe_sources()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_decision_is_plain_text_when_uncolored() {
        // The OFF path the integration capture relies on: empty spans, byte-identical plain text.
        let p = style::Palette::plain();
        let allowed = render_net_decision(
            "https://x/y",
            &allowlist::Decision::DeniedDefault,
            false,
            &p,
        );
        assert_eq!(
            allowed,
            "DENIED   https://x/y\n  no allow rule matches (deny-by-default)\n"
        );
    }

    #[test]
    fn an_allow_by_catch_all_says_the_url_is_not_what_made_it_pass() {
        // Testing a URL against `re:.*` reads as a green light for *that* URL; it is a green light
        // for every URL. The tester says so, or it quietly certifies a destination nobody vetted.
        let p = style::Palette::plain();
        let wide = allowlist::classify("re:.*").unwrap();
        let out = render_net_decision(
            "https://anything.example.test/x",
            &allowlist::Decision::AllowedBy(&wide),
            false,
            &p,
        );
        assert!(
            out.contains("matches every host"),
            "a catch-all pass must be qualified:\n{out}"
        );

        // A rule that names its host carries no such note — it passed *because of* this URL.
        let exact = allowlist::classify("github.com").unwrap();
        let out = render_net_decision(
            "https://github.com/x",
            &allowlist::Decision::AllowedBy(&exact),
            false,
            &p,
        );
        assert!(
            !out.contains("matches every host"),
            "an exact-host pass must stay unqualified:\n{out}"
        );
    }

    #[test]
    fn net_decision_colors_the_verdict_and_resets() {
        // The ON path: DENIED is wrapped in the error span and closed with a reset, the URL in
        // the name span — a mis-mapped verdict or a dropped reset would only ever show here.
        let p = style::Palette::colored();
        let denied = render_net_decision(
            "https://x/y",
            &allowlist::Decision::DeniedDefault,
            false,
            &p,
        );
        assert!(
            denied.contains(&format!("{}DENIED{}", p.err, p.reset)),
            "DENIED must be wrapped in the error span and reset:\n{denied}"
        );
        assert!(
            denied.contains(&format!("{}https://x/y{}", p.name, p.reset)),
            "the URL must be wrapped in the name span:\n{denied}"
        );
    }

    #[test]
    fn literal_addr_refusal_replays_the_proxy_guard_only_on_an_ip_literal() {
        // The tester resolves nothing, so a name is never classified (no verdict to give), while an
        // IP literal is classified exactly as the proxy's connect paths do.
        let catch_all = allowlist::classify("re:.*").unwrap();
        assert!(
            literal_addr_refusal("intranet.example.com", Some(&catch_all)).is_none(),
            "a name must stay unclassified: resolving it is what this command does not do"
        );
        // A private address under a rule that does not name the host exactly: refused, as the wire
        // refuses it (a 403 at CONNECT).
        assert!(matches!(
            literal_addr_refusal("192.168.1.10", Some(&catch_all)),
            Some(sandbox::AddrRefusal::PrivateWithoutExactHost)
        ));
        // The same address named exactly is the deliberate internal target the guard admits.
        let exact = allowlist::classify("192.168.1.10").unwrap();
        assert!(literal_addr_refusal("192.168.1.10", Some(&exact)).is_none());
        // The cloud metadata address is refused however the policy is written, exact rule included.
        let meta = allowlist::classify("169.254.169.254").unwrap();
        assert!(matches!(
            literal_addr_refusal("169.254.169.254", Some(&meta)),
            Some(sandbox::AddrRefusal::NeverReachable)
        ));
        // An allow-by-default verdict has no deciding rule, so the exception never applies.
        assert!(matches!(
            literal_addr_refusal("127.0.0.1", None),
            Some(sandbox::AddrRefusal::PrivateWithoutExactHost)
        ));
        // A public address is the ordinary pass: no refusal to report.
        assert!(literal_addr_refusal("93.184.216.34", Some(&catch_all)).is_none());
    }

    #[test]
    fn addr_refusal_reads_as_the_wire_verdict_with_both_halves_of_the_reason() {
        // The verdict line is what the launch would do (DENIED), and the reason names the rule that
        // permitted it *and* the guard that refuses it — a bare ALLOWED here would mispredict.
        let p = style::Palette::plain();
        let out = render_addr_refusal(
            "https://127.0.0.1/",
            "the policy allows it (allow rule: re:.*)",
            &sandbox::AddrRefusal::PrivateWithoutExactHost,
            &p,
        );
        assert_eq!(
            out,
            "DENIED   https://127.0.0.1/\n  the policy allows it (allow rule: re:.*), but the \
             proxy refuses the address at connect time: a private or loopback address is reachable \
             only when the deciding rule names that exact host\n"
        );
        let colored = render_addr_refusal(
            "https://127.0.0.1/",
            "the policy allows it (allow-by-default)",
            &sandbox::AddrRefusal::NeverReachable,
            &style::Palette::colored(),
        );
        let c = style::Palette::colored();
        assert!(
            colored.contains(&format!("{}DENIED{}", c.err, c.reset)),
            "the refusal must wear the error span, like every other DENIED:\n{colored}"
        );
        assert!(
            colored.contains("never reachable"),
            "the never-reachable class must say so:\n{colored}"
        );
    }

    #[test]
    fn private_name_note_states_the_condition_it_cannot_resolve() {
        // For a name the honest answer is conditional: the note must say what would refuse it and
        // why the tester cannot tell, without claiming a verdict.
        let p = style::Palette::plain();
        let note = render_private_name_note(&p);
        assert_eq!(
            note,
            "  note: if this name resolves to a private or loopback address, the proxy refuses it \
             at connect time (no rule names this exact host)\n"
        );
    }

    #[test]
    fn loopback_note_names_the_tcp_rule_that_would_actually_carry_the_request() {
        // An ALLOWED verdict on a loopback host is true of the proxy and false of every client in
        // the cage. The note has to carry both halves — why nothing takes it, and the one rule shape
        // that does — because this command is where an author checks before giving up on the
        // filtered posture entirely.
        let p = style::Palette::plain();
        let note = render_loopback_note("localhost", 11434, &p);
        assert_eq!(
            note,
            "  note: the proxy would allow this, but nothing in the cage asks it — localhost is \
             exempt from the cage's proxy (`no_proxy`) and an inspected rule gets no in-cage \
             listener; declare `tcp://localhost:11434` to reach the service on your own loopback\n"
        );
    }

    #[test]
    fn net_decision_tags_a_built_in_allow_only_when_asked() {
        // The built-in flag controls one phrase on the ALLOWED rule line, in both directions, so a
        // user-rule pass and a built-in-only pass read differently.
        let p = style::Palette::plain();
        let rule = allowlist::classify("cache.nixos.org").unwrap();
        let d = allowlist::Decision::AllowedBy(&rule);
        let tagged = render_net_decision("https://cache.nixos.org/x", &d, true, &p);
        assert!(
            tagged.contains("ALLOWED") && tagged.contains("(built-in)"),
            "a built-in allow must be named:\n{tagged}"
        );
        let plain = render_net_decision("https://cache.nixos.org/x", &d, false, &p);
        assert!(
            plain.contains("ALLOWED") && !plain.contains("built-in"),
            "a user-rule allow must not claim the built-in source:\n{plain}"
        );
    }
}
