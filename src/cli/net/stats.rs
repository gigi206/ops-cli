//! `sbx net stats` — the per-host allow/deny/blocked counters a launch recorded.
//!
//! Reads back the tallies each session wrote under `<data>/egress`, folds the long tail of
//! destinations into a single row so the busiest hosts stay legible, renders the table, and
//! clears the counters under `--reset`. The one `net` subsystem that opens no control socket.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::process::ExitCode;

use crate::{config_cwd, egress_dir_or_fail};
use crate::{diag, help, sandbox, style};

/// `sbx net stats [--app <name>] [--reset] [--json]`: report the per-host egress decision counters a
/// project's launches recorded — how often each destination was allowed, denied by a rule, or
/// stopped by a security guard (SSRF, an outbound-secret tripwire, a domain-fronting mismatch).
/// Read-only and host-side: it aggregates the session files under `<data>/egress`, with no launch,
/// nix, or network. `--reset` clears this project's recorded files instead.
pub(super) fn net_stats(args: &[OsString]) -> ExitCode {
    let mut app: Option<String> = None;
    let mut reset = false;
    let mut json = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--json") => json = true,
            Some("--reset") => reset = true,
            Some("--app") | Some("-a") => {
                let Some(v) = it.next().and_then(|a| a.to_str()) else {
                    diag::error("sbx: net stats: `--app` needs an app name");
                    return ExitCode::from(2);
                };
                app = Some(v.to_string());
            }
            _ => {
                diag::error(&format!(
                    "sbx: usage: {}",
                    help::synopsis_of(&["net", "stats"])
                ));
                return ExitCode::from(2);
            }
        }
    }
    // `--reset` reports how many files it cleared; pairing it with `--json` is meaningless — flag it
    // rather than silently pick one.
    if reset && json {
        diag::error("sbx: net stats: `--reset` does not combine with `--json`");
        return ExitCode::from(2);
    }

    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    // The canonical project identity is exactly what `egress::start` writes into each session file's
    // `project=` header, so a read here matches what a launch recorded — no canonicalization drift.
    let project = match sandbox::project_identity(&cwd) {
        Ok((_, canon)) => canon.display().to_string(),
        Err(e) => {
            diag::error(&format!("sbx: cannot resolve the project directory: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let egress_dir = match egress_dir_or_fail() {
        Ok(d) => d.join("egress"),
        Err(code) => return code,
    };

    if reset {
        let n = sandbox::egress_stats::reset(&egress_dir, &project, app.as_deref());
        let scope = app
            .as_ref()
            .map(|a| format!(" for app {a}"))
            .unwrap_or_default();
        println!("reset {n} egress stat file(s){scope}");
        return ExitCode::SUCCESS;
    }

    let tally = sandbox::egress_stats::aggregate(&egress_dir, &project, app.as_deref());
    if json {
        let rows: Vec<_> = tally
            .hosts
            .iter()
            .map(|(host, c)| {
                serde_json::json!({
                    "host": host,
                    "allow": c.allow,
                    "deny": c.deny,
                    "blocked": c.blocked,
                })
            })
            .collect();
        // Present only when something was folded, so a reader that never meets the cap sees the
        // shape it always saw. Its counts are in no row above, so a consumer summing the rows must
        // add this to get the total the proxy decided.
        let overflow = (tally.overflow.total() > 0).then(|| {
            serde_json::json!({
                "allow": tally.overflow.allow,
                "deny": tally.overflow.deny,
                "blocked": tally.overflow.blocked,
            })
        });
        println!(
            "{}",
            serde_json::json!({
                "project": project,
                "app": app,
                "stats": rows,
                "overflow": overflow,
            })
        );
        return ExitCode::SUCCESS;
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_stats(&project, app.as_deref(), &tally, &pal));
    ExitCode::SUCCESS
}

/// The host-column label for the destinations folded past the per-session cap in `sbx net stats`.
/// Named once because it is both printed in that column and counted into the column's width: a
/// label wider than the width it is padded to would shift its own counts out from under the
/// headers they belong to.
const FOLD_LABEL: &str = "(other hosts)";

/// Render the per-host egress stats table — a pure presenter (its colored layout is asserted in a
/// test): a project/app header, then one row per destination with its allow/deny/blocked counts,
/// busiest first (ties broken by host for stable output). An empty result says nothing has been
/// recorded yet and when recording happens.
fn render_stats(
    project: &str,
    app: Option<&str>,
    tally: &sandbox::egress_stats::Tally,
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let mut o = String::new();
    let scope = app.map(|a| format!(" · app {a}")).unwrap_or_default();
    let _ = writeln!(o, "{h}egress stats{r} {dim}({project}{scope}){r}");
    if tally.is_empty() {
        let _ = writeln!(
            o,
            "  {dim}nothing recorded yet \
             (stats accrue while a filtering posture — allowlist/ask — runs){r}"
        );
        return o;
    }
    // Busiest host first; ties by host name so the order is stable run to run.
    let mut rows: Vec<(&String, &sandbox::egress_stats::Counts)> = tally.hosts.iter().collect();
    rows.sort_by(|(ha, a), (hb, b)| b.total().cmp(&a.total()).then(ha.cmp(hb)));
    // The folded-destinations row below prints its label in the host column, so that label is part
    // of the column's width: padded to a narrower one it would overflow and push its own counts
    // right of the ALLOW/DENY/BLOCKED headers they belong to, the one row whose numbers a reader
    // would then misread.
    let folded = &tally.overflow;
    let fold_w = if folded.total() > 0 {
        FOLD_LABEL.len()
    } else {
        0
    };
    let host_w = rows
        .iter()
        .map(|(host, _)| host.len())
        .max()
        .unwrap_or(0)
        .max(4)
        .max(fold_w);
    let _ = writeln!(
        o,
        "  {dim}{:<host_w$}  {:>6}  {:>6}  {:>7}{r}",
        "HOST", "ALLOW", "DENY", "BLOCKED"
    );
    for (host, c) in rows {
        let _ = writeln!(
            o,
            "  {n}{:<host_w$}{r}  {:>6}  {:>6}  {:>7}",
            host, c.allow, c.deny, c.blocked
        );
    }
    // The destinations past the per-session cap, as one row. Shown only when something was folded,
    // and named rather than left out: a total that silently omitted them would be the one number
    // here nobody could reconcile.
    if folded.total() > 0 {
        let _ = writeln!(
            o,
            "  {dim}{:<host_w$}{r}  {:>6}  {:>6}  {:>7}",
            FOLD_LABEL, folded.allow, folded.deny, folded.blocked
        );
    }
    o
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_stats_tabulates_hosts_busiest_first() {
        use sandbox::egress_stats::Counts;
        let p = style::Palette::plain();

        // Empty → the project header plus the "nothing recorded yet" line.
        let empty = sandbox::egress_stats::Tally::default();
        let out = render_stats("/home/u/proj", None, &empty, &p);
        assert!(
            out.contains("/home/u/proj") && out.contains("nothing recorded yet"),
            "{out}"
        );

        let mut counts = std::collections::BTreeMap::new();
        counts.insert(
            "quiet.test".to_string(),
            Counts {
                allow: 1,
                deny: 0,
                blocked: 0,
            },
        );
        counts.insert(
            "busy.test".to_string(),
            Counts {
                allow: 40,
                deny: 2,
                blocked: 1,
            },
        );
        let tally = sandbox::egress_stats::Tally {
            hosts: counts,
            ..Default::default()
        };
        let out = render_stats("/home/u/proj", Some("demo"), &tally, &p);
        assert!(
            !out.contains("(other hosts)"),
            "no fold row when nothing was folded: {out}"
        );
        // The app scope is shown in the header, and the columns are present.
        assert!(out.contains("app demo"), "{out}");
        assert!(
            out.contains("HOST")
                && out.contains("ALLOW")
                && out.contains("DENY")
                && out.contains("BLOCKED"),
            "{out}"
        );
        // Busiest host first: busy.test (total 43) precedes quiet.test (total 1).
        let busy = out.find("busy.test").unwrap();
        let quiet = out.find("quiet.test").unwrap();
        assert!(busy < quiet, "busiest host must sort first:\n{out}");
    }

    /// The destinations past the per-session cap get one row of their own, named rather than left
    /// out: a listing whose numbers did not add up to what the proxy decided would be the one figure
    /// here nobody could reconcile.
    #[test]
    fn render_stats_shows_the_folded_destinations_as_their_own_row() {
        use sandbox::egress_stats::{Counts, Tally};
        let p = style::Palette::plain();
        let tally = Tally {
            hosts: [(
                "busy.test".to_string(),
                Counts {
                    allow: 40,
                    deny: 0,
                    blocked: 0,
                },
            )]
            .into_iter()
            .collect(),
            overflow: Counts {
                allow: 0,
                deny: 44,
                blocked: 2,
            },
        };
        let out = render_stats("/home/u/proj", None, &tally, &p);
        let folded = out
            .lines()
            .find(|l| l.contains("(other hosts)"))
            .unwrap_or_else(|| panic!("no fold row:\n{out}"));
        assert!(folded.contains("44") && folded.contains("2"), "{folded:?}");

        // ...and a tally holding *only* folded counts is a listing, not "nothing recorded yet".
        let only_folded = Tally {
            overflow: Counts {
                allow: 0,
                deny: 7,
                blocked: 0,
            },
            ..Default::default()
        };
        let out = render_stats("/home/u/proj", None, &only_folded, &p);
        assert!(!out.contains("nothing recorded yet"), "{out}");
        assert!(out.contains("(other hosts)"), "{out}");
    }

    /// The fold row prints its label in the host column, so the label is part of that column's
    /// width. Sized from the recorded hosts alone, a project whose destinations are all short pads
    /// the wider label into a narrower field, and the one row whose counts nobody can cross-check
    /// against a host name is also the one row that sits out from under its headers.
    #[test]
    fn the_folded_row_stays_under_its_headers_when_every_recorded_host_is_short() {
        use sandbox::egress_stats::{Counts, Tally};
        let p = style::Palette::plain();
        let tally = Tally {
            // Shorter than `(other hosts)`, which is the whole point of the case.
            hosts: [(
                "pypi.org".to_string(),
                Counts {
                    allow: 12,
                    deny: 0,
                    blocked: 0,
                },
            )]
            .into_iter()
            .collect(),
            overflow: Counts {
                allow: 0,
                deny: 44,
                blocked: 2,
            },
        };
        let out = render_stats("/home/u/proj", None, &tally, &p);
        let row = |needle: &str| -> String {
            out.lines()
                .find(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("no {needle} row:\n{out}"))
                .to_string()
        };
        let header = row("HOST");
        let host = row("pypi.org");
        let folded = row("(other hosts)");

        // A plain palette emits no escapes and every numeric column has a fixed width, so the rows
        // line up exactly when they are the same length — no trailing space can hide a shift.
        assert_eq!(host.len(), header.len(), "host row vs header:\n{out}");
        assert_eq!(folded.len(), header.len(), "fold row vs header:\n{out}");
        // And the fold row's counts sit in the columns they are counts of: a right-aligned field
        // ends where its right-aligned header does.
        assert_eq!(
            folded.find("44").map(|i| i + 2),
            header.find("DENY").map(|i| i + 4),
            "the folded deny count must end in the DENY column:\n{out}"
        );
    }
}
