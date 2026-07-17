//! `sbx search <query>` — discovering the `nix:` tools (and `[packages]` attributes)
//! a project can declare, by querying nixhub.
//!
//! Host-side and read-only: it resolves nothing into the sandbox, mutates no store,
//! and needs no trust gate — it is a discovery front-end, the same posture as a plain
//! `nix search`. The one network step rides nix's own fetcher (the shared
//! [`super::nixhub::fetch_url_json`]), so no HTTP-client dependency is added.
//!
//! Two behaviours over one verb. A fuzzy query lists the matching packages (name +
//! one-line summary). When the query *is* a package name (an exact match among the
//! results), the package's available versions are listed beneath, so the discovery of
//! "which package" and "which version to pin" happen in one command. The search query
//! is free-form, so — unlike the resolver's validated package name — it is
//! **percent-encoded** before it reaches the request URL: every byte outside the
//! unreserved set becomes `%XX`, so the value carries no quote, `$`, backslash, or
//! space that could escape the nix string literal or break the URL. Pure parsing and
//! rendering are split from the single impure fetch so the policy is testable offline.

use crate::store::Layout;
use crate::style::Palette;
use std::io;
use std::path::Path;

/// How many of a package's releases to list (newest first); nixhub returns the full
/// history, but the most recent handful is what a declaration realistically pins.
const MAX_VERSIONS: usize = 12;

/// How many fuzzy matches to list before summarising the rest as a count — nixhub caps a
/// search at 50, and a wall of near-duplicates (every `emacsNNPackages.*` variant) buries
/// the useful hits.
const MAX_MATCHES: usize = 25;

/// Cap on the name column's alignment width, so one long attribute path
/// (`python312Packages.…`) does not push every summary off to the right.
const NAME_COL: usize = 28;

/// How many sibling hits to name in the `related:` footer of an exact-match report.
const RELATED: usize = 8;

/// A fuzzy-search hit: a package name and its one-line summary.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Match {
    name: String,
    summary: String,
}

/// One release of an exact-match package, as a pin candidate: the version and the
/// nixpkgs commit/attribute that shipped it for the host system.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VersionRow {
    version: String,
    commit: String,
    attr: String,
}

/// The outcome of resolving the versions of a query that named a package exactly. The
/// version fetch is *enrichment* over a search that already succeeded, so its failure is
/// a distinct state — never one that discards the fuzzy list the user can still use.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Exact {
    /// The package's releases (newest first), filtered to the host system; empty when it
    /// ships no build for this host.
    Resolved {
        pkg: String,
        summary: String,
        versions: Vec<VersionRow>,
    },
    /// The exact name was found, but fetching its versions failed (a transient nixhub
    /// blip, or a name the metadata fetch rejects). The list still renders.
    Unavailable { pkg: String },
}

/// Run a search: fetch the fuzzy matches, and when the query names a package exactly,
/// its versions too, then render the report. The only impure steps are the two GETs,
/// both through the shared nix fetcher.
pub(crate) fn run(
    nix: &Path,
    layout: &Layout,
    query: &str,
    system: &str,
    pal: &Palette,
) -> io::Result<String> {
    let url = format!(
        "{}{}",
        super::nixhub::NIXHUB_SEARCH_BASE,
        percent_encode(query)
    );
    // The search GET is the report: if it fails there is nothing to show, so propagate.
    let json = super::nixhub::fetch_url_json(nix, layout, &url, false)?;
    let matches = parse_matches(&json);

    // An exact (case-insensitive) hit means the user named a package, not just a
    // fragment — fetch its versions so the pin is one step away, using the result's own
    // name (nixhub's canonical spelling). This second GET is best-effort: a failure
    // degrades to the list plus a note, it never discards the search that succeeded.
    let exact = matches
        .iter()
        .find(|m| m.name.eq_ignore_ascii_case(query))
        .map(
            |m| match super::nixhub::fetch_metadata(nix, layout, &m.name, false) {
                Ok(meta) => Exact::Resolved {
                    pkg: m.name.clone(),
                    summary: m.summary.clone(),
                    versions: parse_versions(&meta, system),
                },
                Err(_) => Exact::Unavailable {
                    pkg: m.name.clone(),
                },
            },
        );

    Ok(render(query, &matches, exact.as_ref(), system, pal))
}

/// Percent-encode a free-form query for a URL query value: keep the RFC 3986 unreserved
/// set verbatim, encode every other byte as `%XX` (uppercase). This both makes the value
/// URL-safe and guarantees it carries no character (`"`, `$`, `\`, space, control) that
/// could escape the nix string literal the URL is interpolated into. Shared with the
/// resolver, whose package names may carry a `+` a raw query would decode as a space.
pub(crate) fn percent_encode(query: &str) -> String {
    let mut out = String::with_capacity(query.len());
    for &b in query.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Extract the `(name, summary)` hits from a nixhub `v2/search` response. A result with
/// no name is skipped; a missing summary renders empty. Pure, so it is tested against
/// captured JSON.
fn parse_matches(json: &serde_json::Value) -> Vec<Match> {
    let Some(results) = json.get("results").and_then(|r| r.as_array()) else {
        return Vec::new();
    };
    results
        .iter()
        .filter_map(|r| {
            let name = r.get("name")?.as_str()?.to_string();
            let summary = r
                .get("summary")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            Some(Match { name, summary })
        })
        .collect()
}

/// Build the version list for an exact-match package from its nixhub metadata, newest
/// first, keeping only releases that ship a build for `system` (so a pin the host could
/// not realise is never suggested). Reuses the resolver's platform accessor so the JSON
/// shape is read in exactly one place.
fn parse_versions(metadata: &serde_json::Value, system: &str) -> Vec<VersionRow> {
    let Some(releases) = metadata.get("releases").and_then(|r| r.as_array()) else {
        return Vec::new();
    };
    releases
        .iter()
        .filter_map(|release| {
            let version = release.get("version")?.as_str()?.to_string();
            let platform = super::nixhub::platform_for(release, system)?;
            let commit = platform.get("commit_hash")?.as_str()?.to_string();
            let attr = platform.get("attribute_path")?.as_str()?.to_string();
            Some(VersionRow {
                version,
                commit,
                attr,
            })
        })
        .collect()
}

/// Render the report. When the query names a package exactly, lead with that package's
/// versions and the lines to declare it (what the user came for), then a compact footer
/// of the sibling hits; otherwise list the fuzzy matches and nudge toward an exact name.
/// Pure, so the exact layout is asserted in a test.
fn render(
    query: &str,
    matches: &[Match],
    exact: Option<&Exact>,
    system: &str,
    pal: &Palette,
) -> String {
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let mut out = String::new();
    if matches.is_empty() {
        out.push_str(&format!(
            "{h}sbx search{r} \"{query}\" — no packages found on nixhub\n"
        ));
        return out;
    }

    match exact {
        Some(Exact::Resolved {
            pkg,
            summary,
            versions,
        }) if !versions.is_empty() => {
            if summary.is_empty() {
                out.push_str(&format!("{h}sbx search{r} \"{query}\" — `{n}{pkg}{r}`\n\n"));
            } else {
                out.push_str(&format!(
                    "{h}sbx search{r} \"{query}\" — `{n}{pkg}{r}`: {summary}\n\n"
                ));
            }
            out.push_str(&format!("{h}versions for {system} (newest first):{r}\n"));
            for row in versions.iter().take(MAX_VERSIONS) {
                let short = row.commit.get(..7).unwrap_or(row.commit.as_str());
                out.push_str(&format!("  {n}{:<12}{r} {dim}{short}{r}\n", row.version));
            }
            if versions.len() > MAX_VERSIONS {
                out.push_str(&format!(
                    "  … and {} older\n",
                    versions.len() - MAX_VERSIONS
                ));
            }
            // The attribute is usually the package name but not always, so quote the real
            // one from the newest release for the `[packages]` form.
            let (latest, attr) = (&versions[0].version, &versions[0].attr);
            out.push_str(&format!("\n{h}declare it:{r}\n"));
            out.push_str(&format!(
                "  [tools]     \"{n}nix:{pkg}{r}\" = \"{n}{latest}{r}\"   (or \"latest\")\n"
            ));
            out.push_str(&format!(
                "  [packages]  {n}{pkg}{r} = \"{n}nix:{attr}{r}\"\n"
            ));
            push_related(&mut out, pkg, matches, pal);
        }
        // The query named a real package, but it ships no build for this host.
        Some(Exact::Resolved { pkg, .. }) => {
            push_match_table(&mut out, query, matches, pal);
            out.push_str(&format!(
                "\n`{n}{pkg}{r}` has no release built for {system}.\n"
            ));
        }
        // The exact name was found, but its version fetch failed — the list still stands,
        // so show it and say why the version block is missing (never the "name a package
        // exactly" nudge: the user already named one).
        Some(Exact::Unavailable { pkg }) => {
            push_match_table(&mut out, query, matches, pal);
            out.push_str(&format!(
                "\ncould not fetch versions for `{n}{pkg}{r}` — try `sbx search {pkg}` again.\n"
            ));
        }
        None => {
            push_match_table(&mut out, query, matches, pal);
            out.push_str(&format!(
                "\nname a package exactly to see its versions, e.g. `sbx search {}`\n",
                matches[0].name
            ));
        }
    }
    out
}

/// The fuzzy matches as an aligned `name  summary` table, capped so a large result set
/// stays scannable and one long attribute path does not blow out the column.
fn push_match_table(out: &mut String, query: &str, matches: &[Match], pal: &Palette) {
    let (h, n, r) = (pal.head, pal.name, pal.reset);
    out.push_str(&format!(
        "{h}sbx search{r} \"{query}\" — {} match{} on nixhub\n\n",
        matches.len(),
        if matches.len() == 1 { "" } else { "es" }
    ));
    let shown = matches.len().min(MAX_MATCHES);
    let width = matches[..shown]
        .iter()
        .map(|m| m.name.len())
        .max()
        .unwrap_or(0)
        .min(NAME_COL);
    for m in &matches[..shown] {
        if m.summary.is_empty() {
            out.push_str(&format!("  {n}{}{r}\n", m.name));
        } else {
            out.push_str(&format!("  {n}{:<width$}{r}  {}\n", m.name, m.summary));
        }
    }
    if matches.len() > shown {
        out.push_str(&format!("  … and {} more\n", matches.len() - shown));
    }
}

/// The sibling hits (every match but the exact one), names only, on one footer line.
fn push_related(out: &mut String, pkg: &str, matches: &[Match], pal: &Palette) {
    let (h, n, r) = (pal.head, pal.name, pal.reset);
    let related: Vec<&str> = matches
        .iter()
        .map(|m| m.name.as_str())
        .filter(|name| *name != pkg)
        .collect();
    if related.is_empty() {
        return;
    }
    let shown = related.len().min(RELATED);
    let names = related[..shown]
        .iter()
        .map(|name| format!("{n}{name}{r}"))
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!("\n{h}related:{r} {names}"));
    if related.len() > shown {
        out.push_str(&format!(", … ({} more)", related.len() - shown));
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encoding_keeps_unreserved_and_escapes_everything_else() {
        // unreserved bytes pass through; a shell/nix-significant set is all escaped
        assert_eq!(percent_encode("ripgrep"), "ripgrep");
        assert_eq!(percent_encode("c-._~9"), "c-._~9");
        assert_eq!(percent_encode("json processor"), "json%20processor");
        // the characters that could break the nix string literal or the URL
        assert_eq!(percent_encode("a\"b$c\\d"), "a%22b%24c%5Cd");
        assert_eq!(percent_encode("x/y?z=1&q"), "x%2Fy%3Fz%3D1%26q");
        // a newline cannot survive into the expression
        assert_eq!(percent_encode("a\nb"), "a%0Ab");
        // multi-byte UTF-8 is encoded byte-by-byte
        assert_eq!(percent_encode("é"), "%C3%A9");
    }

    fn search_json() -> serde_json::Value {
        serde_json::json!({
            "query": "jq",
            "total_results": 3,
            "results": [
                { "name": "jq", "summary": "Lightweight and flexible command-line JSON processor" },
                { "name": "jq-lsp", "summary": "jq language server" },
                { "name": "gojq", "summary": "Pure Go implementation of jq" }
            ]
        })
    }

    #[test]
    fn parses_search_hits_and_tolerates_a_missing_summary() {
        let json = serde_json::json!({
            "results": [
                { "name": "a", "summary": "first" },
                { "name": "b" },                 // no summary -> empty
                { "summary": "no name dropped" } // no name -> skipped
            ]
        });
        let got = parse_matches(&json);
        assert_eq!(
            got,
            vec![
                Match {
                    name: "a".into(),
                    summary: "first".into()
                },
                Match {
                    name: "b".into(),
                    summary: "".into()
                },
            ]
        );
    }

    /// Versions come from the resolver's metadata shape, filtered to the host system and
    /// kept newest-first.
    fn metadata() -> serde_json::Value {
        serde_json::json!({
            "name": "jq",
            "releases": [
                { "version": "1.8.1", "platforms": [
                    { "system": "x86_64-linux", "commit_hash": "a".repeat(40), "attribute_path": "jq" }
                ]},
                { "version": "1.7.1", "platforms": [
                    { "system": "aarch64-darwin", "commit_hash": "b".repeat(40), "attribute_path": "jq" }
                ]},
                { "version": "1.6", "platforms": [
                    { "system": "x86_64-linux", "commit_hash": "c".repeat(40), "attribute_path": "jq" }
                ]}
            ]
        })
    }

    #[test]
    fn version_list_keeps_only_host_system_releases_newest_first() {
        let rows = parse_versions(&metadata(), "x86_64-linux");
        // the darwin-only 1.7.1 is filtered out; order is preserved (newest first)
        assert_eq!(
            rows.iter().map(|r| r.version.as_str()).collect::<Vec<_>>(),
            ["1.8.1", "1.6"]
        );
        assert_eq!(rows[0].commit, "a".repeat(40));
        assert_eq!(rows[0].attr, "jq");
    }

    #[test]
    fn render_lists_matches_and_points_at_an_exact_name_when_none_matches() {
        let matches = parse_matches(&search_json());
        let out = render("js", &matches, None, "x86_64-linux", &Palette::plain());
        assert!(out.contains("3 matches on nixhub"));
        assert!(out.contains("jq-lsp") && out.contains("jq language server"));
        // no exact hit -> it nudges toward a concrete name, shows no versions block
        assert!(out.contains("name a package exactly"));
        assert!(!out.contains("declare it:"));
    }

    #[test]
    fn render_shows_versions_and_declaration_lines_on_an_exact_hit() {
        let matches = parse_matches(&search_json());
        let versions = parse_versions(&metadata(), "x86_64-linux");
        let exact = Exact::Resolved {
            pkg: "jq".to_string(),
            summary: "JSON processor".to_string(),
            versions,
        };
        let out = render(
            "jq",
            &matches,
            Some(&exact),
            "x86_64-linux",
            &Palette::plain(),
        );
        // leads with the exact package's versions and short commit
        assert!(out.contains("`jq`: JSON processor"));
        assert!(out.contains("versions for x86_64-linux"));
        assert!(out.contains("1.8.1") && out.contains("aaaaaaa"));
        // both declaration forms, pinned to the newest version / its attribute (the
        // `[packages]` form now carries the mandatory `nix:` backend prefix)
        assert!(out.contains("\"nix:jq\" = \"1.8.1\""));
        assert!(out.contains("jq = \"nix:jq\""));
        // the sibling hits follow as a compact footer, the exact one excluded
        assert!(out.contains("related: ") && out.contains("jq-lsp"));
        assert!(
            !out.contains("\n  jq  "),
            "the exact pkg should not be in a table row"
        );
    }

    #[test]
    fn render_reports_an_exact_hit_unbuildable_on_this_system() {
        let matches = parse_matches(&search_json());
        let exact = Exact::Resolved {
            pkg: "jq".to_string(),
            summary: "summary".to_string(),
            versions: Vec::new(),
        };
        let out = render(
            "jq",
            &matches,
            Some(&exact),
            "riscv64-linux",
            &Palette::plain(),
        );
        assert!(out.contains("no release built for riscv64-linux"));
        assert!(!out.contains("declare it:"));
    }

    #[test]
    fn a_version_fetch_failure_keeps_the_list_and_avoids_the_exact_name_nudge() {
        // The user named `jq` exactly, but the version fetch failed. The fuzzy list must
        // still render, with a note — never the "name a package exactly" nudge (it would
        // be absurd: they already did) and never the no-host-build message.
        let matches = parse_matches(&search_json());
        let exact = Exact::Unavailable {
            pkg: "jq".to_string(),
        };
        let out = render(
            "jq",
            &matches,
            Some(&exact),
            "x86_64-linux",
            &Palette::plain(),
        );
        assert!(out.contains("3 matches on nixhub") && out.contains("jq-lsp"));
        assert!(out.contains("could not fetch versions for `jq`"));
        assert!(!out.contains("name a package exactly"));
        assert!(!out.contains("has no release built"));
        assert!(!out.contains("declare it:"));
    }

    #[test]
    fn render_handles_no_results() {
        let out = render(
            "zzzznotarealpkg",
            &[],
            None,
            "x86_64-linux",
            &Palette::plain(),
        );
        assert!(out.contains("no packages found"));
    }

    #[test]
    fn a_colored_render_wraps_the_package_name_and_resets() {
        // The ON path the plain-output tests cannot see: the package name is wrapped in the
        // name span and the styling is closed with a reset (catches a wrong span or a missing
        // reset that would only ever manifest on a terminal).
        let matches = parse_matches(&search_json());
        let versions = parse_versions(&metadata(), "x86_64-linux");
        let exact = Exact::Resolved {
            pkg: "jq".to_string(),
            summary: "JSON processor".to_string(),
            versions,
        };
        let pal = Palette::colored();
        let out = render("jq", &matches, Some(&exact), "x86_64-linux", &pal);
        assert!(
            out.contains(&format!("{}jq{}", pal.name, pal.reset)),
            "the package name must be wrapped in the name span and reset:\n{out}"
        );
        assert!(out.contains(pal.head), "the headers must be styled:\n{out}");
    }
}

/// Searching the real nixhub needs the network and a real nix, so this is an
/// integration check: it skips where nix is absent or nixhub is unreachable, and
/// otherwise proves the GET + parse + render path yields a usable report for a known
/// package — including its version block, since `jq` is an exact hit.
#[cfg(test)]
mod search_tests {
    use super::*;
    use crate::store;
    use crate::testutil::TmpDir;

    #[test]
    fn searches_a_known_package_and_surfaces_its_versions() {
        let Some(nix) = store::resolve_nix(None) else {
            eprintln!("skipping nixhub search: no nix on PATH");
            return;
        };
        let data = TmpDir::new();
        let layout = Layout::under(data.path());

        let out = match run(
            &nix,
            &layout,
            "jq",
            &super::super::nixhub::current_system(),
            &Palette::plain(),
        ) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("skipping nixhub search: {e}");
                return;
            }
        };
        // jq is both a fuzzy hit and an exact name, so the report carries the match
        // table and the version/declaration block.
        assert!(out.contains("jq"), "no jq match in:\n{out}");
        assert!(
            out.contains("declare it:") && out.contains("\"nix:jq\""),
            "no declaration hint in:\n{out}"
        );
    }
}
