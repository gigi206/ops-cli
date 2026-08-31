//! `sbx net rules` and the rule writers — everything that reads or writes one egress rule.
//!
//! The effective-policy listing and its manual-source variant, the config writers behind
//! `allow`/`unallow`/`deny`/`undeny`/`mute`/`unmute` with the trust gate they pass through, the
//! live-overlay injection a `--session` write performs, and the two rule presenters.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::{
    ALL_NEEDS_SESSION, SESSION_IGNORES_FILE_SCOPE, config_cwd, egress_dir_or_fail,
    fold_app_overlay, in_scope, net_mode_word, pending_session_context, persist_egress_rule,
    removal_takes_no_session_flags, report_rule_write, session_pids_for_app, session_scope_pids,
    split_one_rule, split_session_flags,
};
use crate::{allowlist, config, diag, help, sandbox, style};

use super::write_session_header;

/// `sbx net rules [--source config|builtin|session] [--filter <substr>] [--json]`: list the effective
/// egress rules, each tagged by source, optionally filtered. Reflects the trust gate (an untrusted
/// project's rules are dropped), and does no launch / nix / network — the read-only posture of
/// `sbx config show` and `sbx test net`.
pub(super) fn net_rules(args: &[OsString]) -> ExitCode {
    use config::view::RuleSourceView;
    let mut source: Option<RuleSourceView> = None;
    let mut filter: Option<String> = None;
    let mut app: Option<String> = None;
    let mut json = false;
    let mut expand = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--json") => json = true,
            Some("--expand") | Some("-e") => expand = true,
            Some("--app") | Some("-a") => {
                let Some(v) = it.next().and_then(|a| a.to_str()) else {
                    diag::error("sbx: net rules: `--app` needs an app name");
                    return ExitCode::from(2);
                };
                app = Some(v.to_string());
            }
            Some("--source") | Some("-s") => {
                let Some(v) = it.next().and_then(|a| a.to_str()) else {
                    diag::error("sbx: `--source` needs a value (config, builtin, session)");
                    return ExitCode::from(2);
                };
                source = Some(match v {
                    "config" => RuleSourceView::Config,
                    "builtin" => RuleSourceView::Builtin,
                    // `session` is the live `--session`-answered overlay; `manual` is kept as an
                    // accepted alias for the same source.
                    "session" | "manual" => RuleSourceView::Manual,
                    other => {
                        diag::error(&format!(
                            "sbx: unknown rule source '{other}' (known: config, builtin, session)"
                        ));
                        return ExitCode::from(2);
                    }
                });
            }
            Some("--filter") | Some("-f") => {
                let Some(v) = it.next().and_then(|a| a.to_str()) else {
                    diag::error("sbx: `--filter` needs a substring");
                    return ExitCode::from(2);
                };
                filter = Some(v.to_lowercase());
            }
            _ => {
                diag::error(&format!(
                    "sbx: usage: {}",
                    help::synopsis_of(&["net", "rules"])
                ));
                return ExitCode::from(2);
            }
        }
    }

    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    // `--source session` is live runtime state, not config: query the running sessions for the rules
    // loaded into their live overlay, rather than reading the static config policy. Scoped to this
    // project by default, or — with `-a <app>` — to that app's session(s), mirroring how
    // `sbx net allow --session -a <app>` scopes the load (`--app` here filters *which sessions* to
    // query, it does not fold a config overlay the way it does for the config/builtin sources).
    if source == Some(RuleSourceView::Manual) {
        return net_rules_manual(&cwd, app.as_deref(), filter.as_deref(), json);
    }

    let mut resolved = config::load(&cwd);
    for w in &resolved.warnings {
        diag::warn(w);
    }
    // Fold a named app's overlay so the rules listed are the *effective* set `sbx app <name>` would
    // launch with (its own posture, allow/deny, credentials), not the bare baseline — the same path
    // `sbx test net --app` uses, so the two read the same policy.
    if let Some(name) = &app
        && let Err(e) = fold_app_overlay(&mut resolved, name)
    {
        diag::error(&format!("sbx: net rules: {e}"));
        return ExitCode::from(2);
    }

    // A `--filter` is a search for a host, so it forces expansion: otherwise the substring would run
    // against a collapsed `@<group>` row and a host *inside* a group would be reported absent though
    // it is allowed — a filter must never hide a matching rule. (`sbx test net <url>` is the
    // authoritative "does this resolve" check regardless.)
    let expand = expand || filter.is_some();

    // The effective posture decides the mode word and whether there are rules at all. The built-in
    // built-in set is unioned by the proxy, which runs only under a filtering posture, so it is
    // absent (with every other rule) under `shared`/`none`.
    let (mode, all_rules) = match &resolved.network {
        config::NetworkPolicy::Shared => ("shared", Vec::new()),
        config::NetworkPolicy::Isolated => ("none", Vec::new()),
        config::NetworkPolicy::Allowlist(policy) => (
            net_mode_word(policy.default_action().into()),
            config::view::net_rules_view(policy, expand),
        ),
    };

    // Apply the source and substring filters (the substring is matched case-insensitively against
    // the rule text). `total` is the unfiltered count, so an empty result reads as "nothing matched
    // your filter" rather than "no rules at all".
    let total = all_rules.len();
    let shown: Vec<&config::view::NetRuleView> = all_rules
        .iter()
        .filter(|r| source.is_none_or(|s| r.source == s))
        .filter(|r| {
            filter
                .as_ref()
                .is_none_or(|f| r.rule.to_lowercase().contains(f))
        })
        .collect();

    if json {
        let value = serde_json::json!({
            "mode": mode,
            "rules": shown.iter().map(|r| (*r).clone()).collect::<Vec<_>>(),
        });
        println!("{value}");
        return ExitCode::SUCCESS;
    }

    // Name the posture in view: the baseline, or one app's effective overlay (matching the label
    // `sbx test net --app` prints, so the two commands read the same).
    let scope = app
        .as_ref()
        .map(|n| format!(" (app {n})"))
        .unwrap_or_default();
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_net_rules(mode, &scope, &shown, total, &pal));
    ExitCode::SUCCESS
}

/// `sbx net rules --source session`: the live overlay rules this project's running sessions carry —
/// loaded with `sbx net allow|deny --session` or remembered from a `sbx net pending … --session`
/// answer. These live in the sessions' memory (not config) and are gone when the sessions end. The
/// proxy folds them into its effective policy, so they apply in any filtering posture, not only
/// `ask`. Cross-references the registry to find the sessions for this project (by the
/// canonical project root the registry keys on), queries each one's control socket, and lists the
/// merged, deduped rules. No config read, no launch, no nix.
fn net_rules_manual(cwd: &Path, app: Option<&str>, filter: Option<&str>, json: bool) -> ExitCode {
    use config::view::{NetRuleKind, NetRuleView, RuleSourceView};
    let data_dir = match egress_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };
    // Which sessions to query: `-a <app>` selects that app's session(s) (from the registry, across
    // projects — an app's live rules are the same wherever it runs); otherwise this project's
    // sessions, keyed by the canonical project root (the registry stores canonical paths; fall back
    // to the cwd as-is if it cannot be canonicalized).
    let (pids, scope): (Vec<u32>, String) = match app {
        Some(name) => (
            session_pids_for_app(&data_dir, name).into_iter().collect(),
            format!(" (app: {name})"),
        ),
        None => {
            let project = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
            (
                pending_session_context(&data_dir)
                    .into_iter()
                    .filter(|(_, proj, _)| *proj == project)
                    .map(|(pid, _, _)| pid)
                    .collect(),
                String::new(),
            )
        }
    };

    // Merge + dedup the manual rules across this project's sessions.
    let mut rules: Vec<NetRuleView> = Vec::new();
    for pid in pids {
        let Ok(rows) = sandbox::control::query_manual(&data_dir, pid) else {
            continue; // the session ended between the registry read and the query
        };
        for row in rows {
            // A live rule crosses the control socket as text, so its reach is re-derived here
            // through the same classifier that admitted it. An unclassifiable row cannot be in the
            // overlay (the loader validates first), so the fallback is unreachable in practice and
            // errs toward the unlabelled, never toward a false "opens every host".
            let catch_all = crate::allowlist::classify(&row.rule)
                .map(|r| r.opens_every_host())
                .unwrap_or(false);
            let view = NetRuleView {
                kind: match row.kind {
                    sandbox::control::ManualKind::Allow => NetRuleKind::Allow,
                    sandbox::control::ManualKind::Deny => NetRuleKind::Deny,
                    sandbox::control::ManualKind::Mute => NetRuleKind::Mute,
                },
                source: RuleSourceView::Manual,
                rule: row.rule,
                group: None,
                catch_all,
            };
            if !rules
                .iter()
                .any(|r| r.kind == view.kind && r.rule == view.rule)
            {
                rules.push(view);
            }
        }
    }

    let total = rules.len();
    let shown: Vec<&NetRuleView> = rules
        .iter()
        .filter(|r| filter.is_none_or(|f| r.rule.to_lowercase().contains(f)))
        .collect();

    if json {
        let value = serde_json::json!({
            "mode": "session",
            "rules": shown.iter().map(|r| (*r).clone()).collect::<Vec<_>>(),
        });
        println!("{value}");
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!(
        "{}",
        render_net_rules("session", &scope, &shown, total, &pal)
    );
    ExitCode::SUCCESS
}

/// Render the egress rule listing — a pure presenter (so its colored layout is asserted in a test):
/// a header naming the effective mode, then one line per shown rule (`allow`/`deny` keyword, the
/// rule as a cyan identifier matching `sbx config`, the source dim). `shared`/`none` carry no rules
/// and say so; an empty result distinguishes "no rules declared" from "nothing matched the filter".
fn render_net_rules(
    mode: &str,
    scope: &str,
    shown: &[&config::view::NetRuleView],
    total: usize,
    pal: &style::Palette,
) -> String {
    use config::view::{NetRuleKind, RuleSourceView};
    use std::fmt::Write as _;
    let (h, n, ok, err, dim, r) = (pal.head, pal.name, pal.ok, pal.err, pal.dim, pal.reset);
    let mut o = String::new();

    match mode {
        "shared" => {
            let _ = writeln!(
                o,
                "{h}network{scope}:{r} shared {dim}— no egress rules (host network, no proxy){r}"
            );
            return o;
        }
        "none" => {
            let _ = writeln!(
                o,
                "{h}network{scope}:{r} none {dim}— no egress rules (no network){r}"
            );
            return o;
        }
        // A filtering posture: name it and frame what the rules mean.
        "allow" => {
            let _ = writeln!(
                o,
                "{h}network{scope}:{r} allow {dim}— denylist: every public host reaches except the deny rules{r}"
            );
        }
        "ask" => {
            let _ = writeln!(
                o,
                "{h}network{scope}:{r} ask {}",
                style::dim_prose(
                    "— an unmatched host parks for a live `sbx net pending` decision; \
                     allow rules auto-pass, deny rules auto-fail",
                    pal
                )
            );
        }
        // The live session-rule listing (`--source session`): runtime rules from `--session`
        // answers, not config — framed as such so they are not mistaken for the static policy.
        "session" => {
            // `scope` is ` (app: <name>)` when `-a` narrowed the query, else empty (this project).
            let where_ = if scope.is_empty() {
                "this project's running sessions".to_string()
            } else {
                format!("that app's running sessions{scope}")
            };
            let _ = writeln!(
                o,
                "{h}session egress rules{r} {}",
                style::dim_prose(
                    &format!(
                        "— live, loaded with `sbx net allow|deny --session` \
                         (or a `sbx net pending … --session` answer) into {where_} (gone when they end)"
                    ),
                    pal
                )
            );
        }
        _ => {
            let _ = writeln!(
                o,
                "{h}network{scope}:{r} deny {dim}— allowlist: only the listed and built-in hosts reach{r}"
            );
        }
    }

    if shown.is_empty() {
        let note = if total == 0 {
            "(no rules declared)"
        } else {
            "(no rules match the filter)"
        };
        let _ = writeln!(o, "  {dim}{note}{r}");
        return o;
    }

    for rule in shown {
        let source = match rule.source {
            RuleSourceView::Config => "config",
            RuleSourceView::Builtin => "builtin",
            RuleSourceView::Manual => "session",
        };
        // A group-expanded rule notes its origin `@<group>` beside the source — but only in the
        // expanded view: a collapsed row's text is already `@<group>`, so the annotation would just
        // repeat it.
        let tag = match &rule.group {
            Some(g) if rule.rule != format!("@{g}") => format!("{source}, @{g}"),
            _ => source.to_string(),
        };
        // A catch-all regex is the one rule whose text does not show its reach — `re:.*`, a bare
        // `re:`, `re:^https://` all read as "a pattern" and mean "every host". The grammar refuses a
        // bare `*` so that a policy reads as what it does; saying so here keeps that promise for the
        // spelling it does accept. Verdict-neutral: the rule is listed exactly as declared.
        let tag = if rule.catch_all {
            format!("{tag}, matches every host")
        } else {
            tag
        };
        match rule.kind {
            NetRuleKind::Allow => {
                let _ = writeln!(o, "  {ok}allow{r} {n}{}{r}  {dim}({tag}){r}", rule.rule);
            }
            NetRuleKind::Deny => {
                let _ = writeln!(o, "  {err}deny{r}  {n}{}{r}  {dim}({tag}){r}", rule.rule);
            }
            // A `mute` (`dontaudit`) rule suppresses the log line of a request that is *denied*
            // anyway — dim, so it never reads as a third verdict beside allow/deny.
            NetRuleKind::Mute => {
                let _ = writeln!(o, "  {dim}mute{r}  {n}{}{r}  {dim}({tag}){r}", rule.rule);
            }
        }
    }
    o
}

/// `sbx net allow|deny <rule> [--local|--global|-c <file>] [--app <name>]`: persist an egress rule
/// to a config file. The rule is validated up front (fail-closed), then `manage::add_egress_rule`
/// places it per the posture matrix. A write to the project `.sbx.toml` is trust-gated: it must be
/// absent or already trusted (else refuse — never bless an unreviewed file by appending), and is
/// re-trusted after the write so the rule takes effect. The global config is trusted by location
/// (no gate). `--app <name>` targets the app's own `[app.<name>.network]`.
pub(super) fn net_add_rule(list: config::manage::EgressList, args: &[OsString]) -> ExitCode {
    use config::manage;
    // The list is also the rule's classification slot: a refused `*` catch-all then names the escape
    // hatch this verb's author was reaching for, rather than one shared pointer that fits only
    // `allow` (and tells a `deny` author to open the network — the exact opposite of the intent).
    let slot = match list {
        manage::EgressList::Allow => allowlist::Slot::Allow,
        manage::EgressList::Deny => allowlist::Slot::Deny,
        manage::EgressList::Mute => allowlist::Slot::Mute,
    };
    let verb = slot.label();

    let (session, all, rest) = split_session_flags(args);
    let (parsed, rule) = match split_one_rule("net", verb, &rest) {
        Ok(v) => v,
        Err(code) => return code,
    };
    // Validate the rule before touching any file or session (fail-closed). A `@<name>` group reference
    // is an alias for a `[network.groups]` group, expanded at load time — not itself a classifiable rule —
    // so it is validated as a group name rather than through `classify` (which would reject the `@`).
    // An undefined reference is not a write-time error (the group may be defined later); it warns
    // loudly on the next load. Any other entry is classified: a `*` catch-all, a scheme, or an
    // uncompilable regex is refused, the same classification the config resolver applies.
    let is_group = rule.trim().starts_with('@');
    if is_group {
        let group = rule.trim().strip_prefix('@').unwrap_or_default();
        if !config::is_valid_group_name(group) {
            diag::error(&format!(
                "sbx: invalid group reference {rule:?}: a group name must be 1–64 of [A-Za-z0-9._-]"
            ));
            return ExitCode::from(2);
        }
    } else if let Err(e) = allowlist::classify_in(&rule, slot) {
        diag::error(&format!("sbx: invalid rule {rule:?}: {e}"));
        return ExitCode::from(2);
    }

    if session {
        // `--session` writes no config file, so the file-scope flags do not apply — point at the
        // session-scope flags instead of silently ignoring a `--global` the user expected to matter.
        if parsed.scope_explicit {
            diag::error(SESSION_IGNORES_FILE_SCOPE);
            return ExitCode::from(2);
        }
        // A `@group` is expanded from the config at launch; the live overlay has no group vocabulary,
        // so it cannot carry one. Point at the two ways to use a group.
        if is_group {
            diag::error(
                "sbx: --session cannot load a @group (a group is expanded from the config at launch) \
                 — pass the concrete rules, or add the group to the config without --session",
            );
            return ExitCode::from(2);
        }
        let cwd = match config_cwd() {
            Ok(d) => d,
            Err(code) => return code,
        };
        return net_inject_session(list, &rule, all, parsed.app.as_deref(), &cwd);
    }

    // `--all` is a session-scope widener, meaningless for a config write (which targets one file).
    if all {
        diag::error(ALL_NEEDS_SESSION);
        return ExitCode::from(2);
    }

    // `sbx net allow|deny` resolves a `--local` scope against the cwd, as one expects of a command
    // run in a project.
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    report_rule_write(persist_egress_rule(
        list,
        &rule,
        &parsed.scope,
        parsed.app.as_deref(),
        &cwd,
    ))
}

/// `sbx net unallow|undeny|unmute <rule> [--local|--global|-c <file>] [-a <app>]`: remove one egress
/// rule from a config file — the inverse of `sbx net allow|deny|mute`, so a rule is undone with the
/// vocabulary it was written in. Idempotent (removing a rule that is not there is a reported no-op,
/// not an error); a project `.sbx.toml` write is trust-gated and re-trusted exactly like the add
/// path. There is no `--session` form on any of the three: the live overlay only takes rules
/// (`inject_rule` has no retraction), so an overlay rule dies with the session rather than being
/// un-loaded, and a session-scope flag is refused rather than silently ignored.
///
/// The posture is deliberately left alone. `sbx net allow` sets one because a rule without it
/// decides nothing; taking the rule back out cannot leave that inert state behind, so removing the
/// last `allow` leaves the closed posture in place — an empty allowlist under `deny`, which is
/// stricter than what was there before, never looser.
pub(super) fn net_remove_rule(list: config::manage::EgressList, args: &[OsString]) -> ExitCode {
    let (verb, _) = removal_words(list);
    if args
        .iter()
        .any(|a| matches!(a.to_str(), Some("--session") | Some("--all")))
    {
        diag::error(&removal_takes_no_session_flags("net", verb));
        return ExitCode::from(2);
    }
    let (parsed, rule) = match split_one_rule("net", verb, args) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    report_rule_write(persist_egress_removal(
        list,
        &rule,
        &parsed.scope,
        parsed.app.as_deref(),
        &cwd,
    ))
}

/// `sbx net allow|deny <rule> --session [-a <app>] [--all]`: load a rule into the **live overlay** of
/// the running session(s) instead of a config file — the proactive sibling of `sbx net pending
/// allow|deny <id> --session`, which remembers a decision for a request that already parked. It writes
/// no file (so it never re-trusts a project the way a config write does) and the rule dies with the
/// session. Scope: by default the **current project's** sessions; `-a <app>` narrows to that app's;
/// `--all` widens to every reachable session. The proxy folds the overlay into its effective policy
/// in every filtering posture (allowlist, denylist, `ask`), so a loaded rule decides immediately
/// wherever it lands; a session running an sbx whose control server predates `REMEMBER` refuses the
/// load and is named in the report rather than silently skipped.
fn net_inject_session(
    list: config::manage::EgressList,
    rule: &str,
    all: bool,
    app: Option<&str>,
    cwd: &Path,
) -> ExitCode {
    use config::manage::EgressList;
    // `allow`/`deny` load a verdict rule; `mute` loads a log-suppression rule (a different overlay
    // and control verb), so the injection call is dispatched per-list in the loop below.
    let verb = match list {
        EgressList::Allow => "allow",
        EgressList::Deny => "deny",
        EgressList::Mute => "mute",
    };
    let data_dir = match egress_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let (project_pids, app_pids) = match session_scope_pids(&data_dir, all, app, cwd) {
        Ok(filters) => filters,
        Err(code) => return code,
    };

    let context = pending_session_context(&data_dir);
    let mut loaded: Vec<u32> = Vec::new();
    let mut refused: Vec<u32> = Vec::new();
    for pid in sandbox::control::session_pids(&data_dir) {
        if !in_scope(pid, &project_pids, &app_pids) {
            continue;
        }
        // A mute loads through the dedicated mute overlay (`REMEMBER MUTE`); allow/deny load a
        // verdict rule (`REMEMBER ALLOW|DENY`).
        let injected = match list {
            EgressList::Mute => sandbox::control::inject_mute(&data_dir, pid, rule),
            EgressList::Allow => sandbox::control::inject_rule(
                &data_dir,
                pid,
                sandbox::control::Verdict::Allow,
                rule,
            ),
            EgressList::Deny => {
                sandbox::control::inject_rule(&data_dir, pid, sandbox::control::Verdict::Deny, rule)
            }
        };
        match injected {
            Ok(sandbox::control::InjectOutcome::Loaded) => loaded.push(pid),
            Ok(sandbox::control::InjectOutcome::Refused) => refused.push(pid),
            // A dead/stale socket (the session went away) — skip it.
            Err(_) => {}
        }
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!(
        "{}",
        render_inject(verb, rule, all, app, &loaded, &refused, &context, &pal)
    );
    ExitCode::SUCCESS
}

/// Render a `--session` rule load: which live sessions took the rule (with their agent/project
/// context, so a cross-agent reach is visible) and which an older server refused. When no session in
/// scope took it, it says so and points at the config write as the persistent alternative. A pure
/// presenter — its palette comes from the caller.
#[allow(clippy::too_many_arguments)]
fn render_inject(
    verb: &str,
    rule: &str,
    all: bool,
    app: Option<&str>,
    loaded: &[u32],
    refused: &[u32],
    context: &[(u32, PathBuf, String)],
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (h, dim, warn, r) = (pal.head, pal.dim, pal.warn, pal.reset);
    let mut o = String::new();
    if !loaded.is_empty() {
        let _ = writeln!(
            o,
            "{}",
            style::paint_spans(
                &format!(
                    "{h}loaded {verb} rule `{rule}` into {} live session(s):{r}",
                    loaded.len()
                ),
                pal.name,
                pal.head,
                pal
            )
        );
        for pid in loaded {
            write_session_header(&mut o, *pid, context, pal);
        }
        // The rule is live-only, never written to config — so plain `sbx net rules` (the config
        // policy) will not show it. Point at where it *is* visible.
        let _ = writeln!(
            o,
            "  {}",
            style::dim_prose(
                "see it with `sbx net rules --source session` (it is not in the config)",
                pal
            )
        );
    }
    if !refused.is_empty() {
        let pids = refused
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            o,
            "{warn}session(s) {pids} refused the rule (an older sbx without --session rule \
             support).{r}"
        );
    }
    // Nothing took the rule: no session with egress filtering is running in scope. Point at the
    // persistent path (which pre-decides the host for the next launch), carrying the `--app <name>`
    // scope when one was given so the hint is copy-pasteable.
    if loaded.is_empty() {
        if refused.is_empty() {
            let scope = match (app, all) {
                (Some(a), _) => format!("app `{a}`"),
                (None, true) => "any session".to_string(),
                (None, false) => "this project".to_string(),
            };
            let _ = writeln!(
                o,
                "{dim}no reachable session with egress filtering for {scope} — nothing to load the \
                 rule into.{r}"
            );
        }
        let app_flag = app.map(|a| format!(" --app {a}")).unwrap_or_default();
        let _ = writeln!(
            o,
            "  {dim}to pre-decide it for the next launch, persist it: sbx net {verb} \
             {rule}{app_flag}{r}"
        );
    }
    o
}

/// The removal verb and the rule noun for one egress list: `sbx net unallow` takes an `allow` rule
/// back out, `undeny` a `deny`, `unmute` a `mute`. One spelling for all of it, so the usage errors,
/// the help lookup and the confirmation sentence cannot drift from the verb the user actually typed.
///
/// Its `[proc]` twin is `cli::proc::removal_words`, deliberately a separate function: the two match
/// over unrelated enums, and a trait to share five lines would cost more than it saves.
fn removal_words(list: config::manage::EgressList) -> (&'static str, &'static str) {
    match list {
        config::manage::EgressList::Allow => ("unallow", "allow"),
        config::manage::EgressList::Deny => ("undeny", "deny"),
        config::manage::EgressList::Mute => ("unmute", "mute"),
    }
}

/// Remove an egress `rule` from the scoped config file — the removal sibling of
/// [`persist_egress_rule`], behind `sbx net unallow|undeny|unmute`. A rule that is not present is a
/// reported no-op (no write, no re-trust). Same scope vocabulary, trust-gate, and error codes as the
/// add path: a `-c <file>` scope or an untrusted project config is code `2`; a trust-store/write/
/// re-trust failure is code `1`.
fn persist_egress_removal(
    list: config::manage::EgressList,
    rule: &str,
    scope: &config::manage::Scope,
    app: Option<&str>,
    base: &Path,
) -> Result<String, (u8, String)> {
    // A project `.sbx.toml` edit is trust-gated and re-trusted, exactly like the add path — removing
    // a rule still rewrites the file, so it must not silently bless an untrusted one.
    crate::persist_removal(
        "net",
        removal_words(list),
        rule,
        scope,
        app,
        base,
        |path, app_key| config::manage::remove_egress_rule(path, app_key, list, rule),
    )
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_rules_render_tags_each_rule_by_source_and_kind() {
        use config::view::{NetRuleKind, NetRuleView, RuleSourceView};
        let p = style::Palette::plain();
        let mk = |kind, source, rule: &str| NetRuleView {
            kind,
            source,
            rule: rule.into(),
            group: None,
            catch_all: false,
        };
        let rules = [
            mk(NetRuleKind::Allow, RuleSourceView::Config, "github.com"),
            mk(NetRuleKind::Deny, RuleSourceView::Config, "evil.com"),
            mk(
                NetRuleKind::Allow,
                RuleSourceView::Builtin,
                "cache.nixos.org",
            ),
            // A live `--session`-answered rule is tagged `session`, not `manual`.
            mk(NetRuleKind::Deny, RuleSourceView::Manual, "adhoc.test"),
        ];
        let refs: Vec<&NetRuleView> = rules.iter().collect();

        // deny mode: header frames it as an allowlist; each rule carries its kind + source.
        let out = render_net_rules("deny", "", &refs, refs.len(), &p);
        assert!(out.contains("network: deny"), "{out}");
        assert!(out.contains("allow github.com  (config)"), "{out}");
        assert!(out.contains("deny  evil.com  (config)"), "{out}");
        assert!(out.contains("allow cache.nixos.org  (builtin)"), "{out}");
        assert!(out.contains("deny  adhoc.test  (session)"), "{out}");

        // Colored: `allow` carries the green span, `deny` the red one.
        let c = render_net_rules("deny", "", &refs, refs.len(), &style::Palette::colored());
        assert!(c.contains("\x1b[32mallow\x1b[0m"), "allow is green: {c:?}");
        assert!(c.contains("\x1b[1;31mdeny\x1b[0m"), "deny is red: {c:?}");

        // allow mode frames it as a denylist.
        assert!(render_net_rules("allow", "", &refs, refs.len(), &p).contains("network: allow"));

        // A `--app` scope labels the header exactly as `sbx test net --app` does, on every posture.
        assert!(
            render_net_rules("deny", " (app demo)", &refs, refs.len(), &p)
                .contains("network (app demo): deny"),
            "the app scope must label the header"
        );
        assert!(
            render_net_rules("shared", " (app demo)", &[], 0, &p).contains("network (app demo):"),
            "the app scope must label a non-filtering posture too"
        );

        // shared/none carry no rules, with an explanatory one-liner (no rule list).
        assert!(render_net_rules("shared", "", &[], 0, &p).contains("no egress rules"));
        assert!(render_net_rules("none", "", &[], 0, &p).contains("no egress rules"));

        // An empty result distinguishes "nothing declared" from "the filter matched nothing".
        assert!(render_net_rules("deny", "", &[], 0, &p).contains("no rules declared"));
        assert!(render_net_rules("deny", "", &[], 3, &p).contains("no rules match the filter"));
    }

    #[test]
    fn render_net_rules_annotates_only_an_expanded_group_rule() {
        use config::view::{NetRuleKind, NetRuleView, RuleSourceView};
        let p = style::Palette::plain();

        // A collapsed group row — the rule text is already `@mcp`, so the origin note would just
        // repeat it and is omitted.
        let collapsed = NetRuleView {
            kind: NetRuleKind::Allow,
            source: RuleSourceView::Config,
            rule: "@mcp".into(),
            group: Some("mcp".into()),
            catch_all: false,
        };
        let out = render_net_rules("deny", "", &[&collapsed], 1, &p);
        assert!(out.contains("allow @mcp  (config)"), "{out}");
        assert!(
            !out.contains("@mcp, @mcp"),
            "no redundant annotation:\n{out}"
        );

        // A catch-all regex — listed exactly as declared (the tag never changes a verdict), with
        // its reach spelled out beside the source, since `re:.*` does not read as "every host".
        let wide = NetRuleView {
            kind: NetRuleKind::Allow,
            source: RuleSourceView::Config,
            rule: "re:.*".into(),
            group: None,
            catch_all: true,
        };
        let out = render_net_rules("deny", "", &[&wide], 1, &p);
        assert!(
            out.contains("allow re:.*  (config, matches every host)"),
            "a catch-all must carry its reach in the listing:\n{out}"
        );

        // An expanded group row — the rule is the host, so the source tag notes its `@mcp` origin.
        let expanded = NetRuleView {
            kind: NetRuleKind::Allow,
            source: RuleSourceView::Config,
            rule: "{*} https://a.example.com".into(),
            group: Some("mcp".into()),
            catch_all: false,
        };
        let out = render_net_rules("deny", "", &[&expanded], 1, &p);
        assert!(
            out.contains("(config, @mcp)"),
            "an expanded group rule must note its origin:\n{out}"
        );
    }
}
