//! `sbx net` — inspect and manage the per-project egress allowlist and the live
//! network control plane.
//!
//! This file is the verb tree itself: the three dispatchers behind `net`, `net pending` and
//! `net groups`, and the session header line every listing that spans sessions shares. Each verb
//! family is a child module, and none of them calls another — the dispatch below and that one
//! shared writer are the only edges between them:
//!
//! * [`mod@pending`] — the `ask`-posture control plane: what is parked, watching it, answering
//!   one request or draining a session, and saving the rule an answer implies.
//! * [`mod@live`] — the egress tunnels open right now, refreshed in place.
//! * [`mod@logs`] — the decisions already recorded, their filters, the `--follow` stream and the
//!   captured traffic.
//! * [`mod@stats`] — the per-host allow/deny/blocked counters a launch wrote.
//! * [`mod@rules`] — every read and every write of an egress rule, config and live overlay alike.
//! * [`mod@groups`] — the reusable egress groups: list, export, import.
//!
//! Cross-cutting domain and plumbing helpers — session record readers (`session_pids_*`,
//! `pending_session_context`), the shared egress writers (`persist_egress_rule`, `persist_removal`,
//! `egress_write_target`), the local-save trust gate (`precheck_local_save`), and formatting shared
//! with other families (`format_log_time`, `net_mode_word`, `short_rev`) — stay at the crate root
//! and are reached from the children via `crate::`.

mod groups;
mod live;
mod logs;
mod pending;
mod rules;
mod stats;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::{config, diag, help, sandbox, style};

use groups::{net_groups_export, net_groups_import, net_groups_list};
use live::net_live;
use logs::net_logs;
use pending::{net_pending_answer, net_pending_list, net_pending_watch};
use rules::{net_add_rule, net_remove_rule, net_rules};
use stats::net_stats;

/// `sbx net <subcommand>`: the interactive-egress namespace. `rules` lists the effective egress
/// rules (optionally for one app), `allow`/`deny` persist a rule to a config file, `pending`
/// drives the live `ask`-posture control plane, and `stats` reports the per-host allow/deny/blocked
/// decision counters a launch recorded. Distinct from `sbx test net <url>` (the URL matcher): `net`
/// is the listing/management surface.
pub(crate) fn net_cmd(args: Vec<OsString>) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("rules") => net_rules(&args[1..]),
        Some("groups") => net_groups(&args[1..]),
        // Each rule list is added to and taken back out with one vocabulary, so undoing a rule never
        // means dropping to the schema key it was written under. The removal verbs are config-only:
        // an `--session` overlay rule cannot be un-loaded (the control plane injects, it does not
        // retract), so it dies with the session instead.
        Some("allow") => net_add_rule(config::manage::EgressList::Allow, &args[1..]),
        Some("unallow") => net_remove_rule(config::manage::EgressList::Allow, &args[1..]),
        Some("deny") => net_add_rule(config::manage::EgressList::Deny, &args[1..]),
        Some("undeny") => net_remove_rule(config::manage::EgressList::Deny, &args[1..]),
        // `mute` adds a `dontaudit` log-suppression rule; `unmute` removes one. Both take the
        // same scopes as allow/deny, and `mute --session` loads the mute into the live overlay on
        // the same terms as `allow`/`deny` above.
        Some("mute") => net_add_rule(config::manage::EgressList::Mute, &args[1..]),
        Some("unmute") => net_remove_rule(config::manage::EgressList::Mute, &args[1..]),
        Some("pending") => net_pending(&args[1..]),
        Some("stats") => net_stats(&args[1..]),
        // `log` is an accepted alias for `logs` so a typo does not error.
        Some("logs") | Some("log") => net_logs(&args[1..]),
        // `live` is the real-time view of the tunnels *currently open*, distinct from the decided
        // requests `logs` records.
        Some("live") => net_live(&args[1..]),
        // Unknown or no subcommand: name the mistake (if any), then print the full page — its
        // Subcommands list reveals rules/allow/deny/pending/… instead of a bare one-line synopsis,
        // the way `sbx config` and bare `sbx` guide.
        other => {
            if let Some(tok) = other {
                diag::error(&format!("sbx: net: unknown subcommand {tok:?}"));
            }
            eprint!("{}", help::page_usage(&["net"]).unwrap_or_default());
            ExitCode::from(2)
        }
    }
}

/// `sbx net pending` family — the live control plane for the `ask` egress posture (see
/// [`sandbox::control`]). With no verb it lists the requests parked across every reachable ask-mode
/// session; `allow <id>`/`deny <id>` answer one (`<id>` = `<pid>.<seq>` from the listing or the
/// launch's notice), optionally persisting a matching rule with `--save` + a scope. The control
/// sockets live under `<data>/egress`, never inside any cage.
fn net_pending(args: &[OsString]) -> ExitCode {
    use sandbox::control::Verdict;
    match args.first().and_then(|a| a.to_str()) {
        Some("allow") => net_pending_answer(Verdict::Allow, &args[1..]),
        Some("deny") => net_pending_answer(Verdict::Deny, &args[1..]),
        Some("watch") => net_pending_watch(&args[1..]),
        // No verb (or `--json`): list the pending requests.
        _ => net_pending_list(args),
    }
}

/// `sbx net groups` — the reusable-egress-group surface. `export`/`import` move groups between
/// configs (they are reserved subcommand verbs, so a group named `export`/`import` is listable and
/// referenceable as `@export` but not resolvable by bare name — use the listing); anything else is
/// the list/resolve reader ([`net_groups_list`]).
fn net_groups(args: &[OsString]) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("export") => net_groups_export(&args[1..]),
        Some("import") => net_groups_import(&args[1..]),
        _ => net_groups_list(args),
    }
}

/// One session's header line: `session <pid> [<agent>] <project>`, or `session <pid>
/// (unregistered)` when the registry does not know it.
///
/// Every `sbx net` listing that spans sessions prints this line, and it must read the same in all
/// of them — it is what tells the user which agent a flow, a parked request or a grant belongs to,
/// which is the literal reason the control plane is multi-session. Written once so the six listings
/// cannot come to disagree about the shape of the identifier they share.
fn write_session_header_line(
    o: &mut String,
    pid: u32,
    ctx: Option<(&str, &str)>,
    pal: &style::Palette,
) {
    use std::fmt::Write as _;
    let (dim, r) = (pal.dim, pal.reset);
    match ctx {
        Some((label, project)) => {
            let _ = writeln!(o, "  {dim}session {pid} [{label}] {project}{r}");
        }
        None => {
            let _ = writeln!(o, "  {dim}session {pid} (unregistered){r}");
        }
    }
}

/// [`write_session_header_line`] for a caller holding the registry snapshot rather than an
/// already-resolved entry: the pid is looked up in `context`, and an absent one reads as
/// unregistered.
fn write_session_header(
    o: &mut String,
    pid: u32,
    context: &[(u32, PathBuf, String)],
    pal: &style::Palette,
) {
    let found = context.iter().find(|(p, _, _)| *p == pid);
    let project = found.map(|(_, project, _)| project.display().to_string());
    write_session_header_line(
        o,
        pid,
        match (&found, &project) {
            (Some((_, _, label)), Some(project)) => Some((label.as_str(), project.as_str())),
            _ => None,
        },
        pal,
    );
}
