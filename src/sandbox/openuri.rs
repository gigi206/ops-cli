//! What a URI opens with inside the cage: the router script the cage reaches as `xdg-open`, and
//! the two XDG files the in-cage portal reads to reach the same router.
//!
//! A hermetic cage has no browser and no desktop, so a link has nowhere to go unless the config
//! says where. Two different callers ask, and they ask differently:
//!
//!   * a command-line tool runs `xdg-open <uri>` and resolves it on `PATH`;
//!   * a GTK or Electron application calls `org.freedesktop.portal.OpenURI`, and the portal
//!     resolves a *desktop entry* through the mime database, then runs its `Exec=`.
//!
//! Both must end at the same handler, or a link behaves differently depending on which library the
//! tool that opened it happens to use. So this module emits one router and points both routes at
//! it: `PATH` reaches it directly, and the desktop entry's `Exec=` names it by absolute path.
//!
//! **Neither route may be re-pointed from inside the cage.** The router is bound read-only in a
//! directory that leads `PATH` (see [`super::binds`]), and the portal's inputs are bound read-only
//! at the locations the XDG lookup prefers: `$XDG_DATA_HOME` and `$XDG_CONFIG_HOME` are unset in the
//! cage, so their defaults under `$HOME` outrank everything else and a copy placed elsewhere would
//! be shadowed by one written there.
//!
//! What that prevents is narrow and worth stating plainly: the cage is one trust domain, so this is
//! not a privilege boundary, but a substituted handler lets whatever runs in the cage answer a
//! sign-in click the *user* made with a page of its own.
//!
//! The desktop entry is frozen as a whole *directory* rather than as one file, and that part is not
//! about substitution at all — see [`APPLICATIONS_REL`] for the portal behaviour that forces it.

use crate::config::{OpenHandler, OpenMode};
use std::collections::BTreeMap;

/// The desktop entry's basename. Fixed rather than derived from the app name: it is the value
/// `mimeapps.list` refers to, and both are generated together.
pub(crate) const DESKTOP_FILE: &str = "sbx-open-uri.desktop";

/// The desktop-entry **directory** bound into the cage, relative to `$HOME`. `$XDG_DATA_HOME` is
/// unset in the cage, so the XDG default applies and this is the highest-priority location.
///
/// The whole directory rather than the one file, for a functional reason measured on the in-cage
/// portal rather than a security one: `OpenURI` opens nothing at all when **two** entries claim the
/// same scheme, even with the mime defaults naming ours and even with the caller passing
/// `ask = false`. One claimant is answered directly; two are not answered at all. A second claimant
/// is not an attack but the steady state, since an application registers a handler for its own
/// scheme when it installs itself, so leaving the directory open would make the portal route dead
/// exactly on the applications this table exists to serve.
///
/// Bound only when `[open]` declares something. A cage that routes nothing has no reason to be
/// handed a frozen directory it never asked for, and an application that registers its own entry
/// there keeps working as before.
///
/// Freezing this one directory is sufficient only because it is the sole `applications` directory
/// the portal can reach: the cage's `XDG_DATA_DIRS` carries a single entry, sbx's own GUI data,
/// which holds schemas and themes and no desktop entries, and a packaged application's `share` is
/// prefixed onto the *application's* environment by its launcher wrapper, never onto the portal's.
/// **That is the condition to re-check before putting anything else on the cage-wide
/// `XDG_DATA_DIRS`**: a second directory carrying an `applications/` would restore the two-claimant
/// state, and the portal would go quiet again with no error anywhere to explain it.
pub(crate) const APPLICATIONS_REL: &str = ".local/share/applications";

/// Where the mime defaults are bound, relative to the cage's `$HOME`. `$XDG_CONFIG_HOME` is unset
/// too, so this is likewise the location the lookup prefers.
pub(crate) const MIMEAPPS_REL: &str = ".config/mimeapps.list";

/// The `mimeinfo.cache` index the portal reads to find which entries claim a scheme.
///
/// Generated rather than left to `update-desktop-database`, because the directory it would write it
/// into is read-only. It is a plain INI index of the same information the entry already carries, so
/// producing it here costs nothing and removes a tool from the path.
pub(crate) fn mimeinfo_cache(handlers: &BTreeMap<String, OpenHandler>) -> String {
    let mut out = String::from("[MIME Cache]\n");
    for scheme in handlers.keys() {
        out.push_str(&format!("x-scheme-handler/{scheme}={DESKTOP_FILE};\n"));
    }
    out
}

/// The router's behaviour when no declared scheme matches: name the URI on stderr and succeed.
///
/// Succeeding is deliberate. A tool that auto-opens a verification URL treats a failing open as a
/// failed flow and gives up, when in fact the person can still follow the link — so the router
/// reports and returns 0, leaving the decision with them.
const FALLBACK: &str = "echo \"sbx: open on the host:\" \"$@\" >&2\nexit 0\n";

/// Where a `detach` handler's output is parked, as the router writes it: in the cage's `$HOME`, so
/// it lands in the app's isolated home and can be read host-side afterwards. The `${HOME:-/tmp}`
/// guard is not decoration — a redirect to an unset variable's path fails, and the failure would
/// take the handler down with it, turning a diagnostic convenience into a broken sign-in.
const LOG: &str = "${HOME:-/tmp}/.sbx-open.log";

/// The router script for a set of handlers, or the bare fallback when none is declared.
///
/// Emitted as POSIX `sh` (the cage synthesises `/bin/sh`) with one `case` arm per scheme. Scheme
/// matching is case-insensitive, as URI schemes are, using bracket classes rather than a `tr`
/// pipeline so the script stays free of any tool the cage might not carry.
pub(crate) fn router(handlers: &BTreeMap<String, OpenHandler>) -> String {
    let mut out = String::from(
        "#!/bin/sh\n\
         # Generated by sbx for this launch and bound read-only. Edit `[open]` in the config, not\n\
         # this file: it is regenerated every launch and the cage cannot write it.\n",
    );
    if !handlers.is_empty() {
        out.push_str("case \"$1\" in\n");
        for (scheme, handler) in handlers {
            out.push_str(&format!("  {}://*)\n", case_insensitive(scheme)));
            let cmd = shell_argv(&handler.argv);
            match handler.mode {
                OpenMode::Exec => out.push_str(&format!("    exec {cmd} \"$@\" ;;\n")),
                // Detached in a subshell so no job-control notice reaches the caller's terminal,
                // with stdin closed so the handler cannot hold a pipe a waiting caller reads.
                //
                // Output is parked in the isolated home rather than discarded. It cannot stay on
                // the caller's terminal (a browser started this way outlives the call and would
                // scribble over whatever runs next), but discarding it would take away the only
                // account of a sign-in that opened a window and then went nowhere — which is the
                // failure this mode exists for, and the hardest one to diagnose blind. Appended,
                // never rotated: delete the file if it grows.
                OpenMode::Detach => out.push_str(&format!(
                    "    ( {cmd} \"$@\" >>\"{LOG}\" 2>&1 </dev/null & ) ; exit 0 ;;\n"
                )),
            }
        }
        out.push_str("esac\n");
    }
    out.push_str(FALLBACK);
    out
}

/// The desktop entry the in-cage portal resolves a URI through.
///
/// `Exec=` names the router by absolute path rather than by the name `PATH` would resolve. Both end
/// at the same file, but only the absolute form is independent of the environment the portal
/// happens to launch the handler with — and the portal's `Exec=` is the one place a handler is run
/// by something other than the cage's own shell.
pub(crate) fn desktop_entry(handlers: &BTreeMap<String, OpenHandler>, router_path: &str) -> String {
    let mut mime = String::new();
    for scheme in handlers.keys() {
        mime.push_str(&format!("x-scheme-handler/{scheme};"));
    }
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=sbx URL handler\n\
         Exec={router_path} %u\n\
         MimeType={mime}\n\
         NoDisplay=true\n\
         Terminal=false\n"
    )
}

/// The mime defaults naming [`DESKTOP_FILE`] for every declared scheme.
///
/// This is the load-bearing half of the portal route: the desktop database may hold any number of
/// entries claiming a scheme (an application installed in the cage registers its own), and this
/// file is what decides which one is used. Frozen, it makes every other entry inert.
pub(crate) fn mimeapps(handlers: &BTreeMap<String, OpenHandler>) -> String {
    let mut out = String::from("[Default Applications]\n");
    for scheme in handlers.keys() {
        out.push_str(&format!("x-scheme-handler/{scheme}={DESKTOP_FILE}\n"));
    }
    out
}

/// A `case` pattern matching `scheme` regardless of case: each letter becomes a two-element bracket
/// class, everything else (digits, `+`, `-`, `.`) stands for itself. The scheme grammar is validated
/// upstream, so nothing here can be glob-significant.
fn case_insensitive(scheme: &str) -> String {
    scheme
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                format!("[{}{}]", c.to_ascii_uppercase(), c.to_ascii_lowercase())
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// An argv as a single-quoted shell command. Single quotes suppress every expansion the shell would
/// otherwise perform, and an embedded quote is closed, escaped and reopened — the standard form, and
/// the reason a handler's arguments can be taken verbatim from config without a grammar of their own.
fn shell_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|a| format!("'{}'", a.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler(argv: &[&str], mode: OpenMode) -> OpenHandler {
        OpenHandler {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            mode,
        }
    }

    fn table(entries: &[(&str, OpenHandler)]) -> BTreeMap<String, OpenHandler> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn an_undeclared_router_is_the_printing_stub() {
        // The behaviour a cage has without `[open]`, and the behaviour of any scheme no arm
        // matches: name the URI and exit 0, so a device-auth flow continues instead of aborting.
        let out = router(&BTreeMap::new());
        assert!(out.starts_with("#!/bin/sh\n"), "a POSIX sh script: {out}");
        assert!(!out.contains("case "), "no arms without handlers: {out}");
        assert!(out.contains("exit 0"), "the fallback succeeds: {out}");
        assert!(
            out.contains("\"$@\""),
            "it names the URI it did not open: {out}"
        );
    }

    #[test]
    fn an_exec_handler_replaces_the_router_and_a_detach_handler_returns_at_once() {
        // The distinction is why `mode` exists: a caller that waits on `xdg-open` must get its
        // process back for a sign-in to complete, and a caller handing a deep link to a running app
        // must not.
        let out = router(&table(&[
            (
                "https",
                handler(&["chromium", "--no-sandbox"], OpenMode::Exec),
            ),
            (
                "cursor",
                handler(&["cursor", "--open-url"], OpenMode::Detach),
            ),
        ]));
        assert!(
            out.contains("exec 'chromium' '--no-sandbox' \"$@\" ;;"),
            "exec mode execs: {out}"
        );
        assert!(
            out.contains(
                "( 'cursor' '--open-url' \"$@\" >>\"${HOME:-/tmp}/.sbx-open.log\" 2>&1 </dev/null & ) ; exit 0"
            ),
            "detach mode backgrounds, parks its output, and returns: {out}"
        );
    }

    #[test]
    fn a_scheme_matches_whatever_case_the_caller_used() {
        // URI schemes are case-insensitive, and a provider's redirect is not obliged to use the
        // spelling the config did. Bracket classes rather than `tr`: the cage need carry no tool.
        let out = router(&table(&[("cursor", handler(&["cursor"], OpenMode::Exec))]));
        assert!(
            out.contains("[Cc][Uu][Rr][Ss][Oo][Rr]://*)"),
            "each letter matches either case: {out}"
        );
    }

    #[test]
    fn an_argument_carrying_a_quote_cannot_break_out_of_its_word() {
        // A handler's arguments come from config, and a config is written by hand: the escaping has
        // to hold for a value nobody vetted character by character, not only for well-formed flags.
        let out = router(&table(&[(
            "https",
            handler(&["browser", "--title=it's; rm -rf /"], OpenMode::Exec),
        )]));
        assert!(
            out.contains(r#"'--title=it'\''s; rm -rf /'"#),
            "the quote is closed, escaped and reopened: {out}"
        );
        assert!(
            !out.contains("; rm -rf / '"),
            "the semicolon never leaves the quoted word: {out}"
        );
    }

    #[test]
    fn the_desktop_entry_names_the_router_by_absolute_path() {
        // The portal launches `Exec=` itself, with an environment sbx does not compose — so the
        // handler must not depend on `PATH` resolving to the frozen router.
        let out = desktop_entry(
            &table(&[
                ("cursor", handler(&["cursor"], OpenMode::Exec)),
                ("https", handler(&["chromium"], OpenMode::Exec)),
            ]),
            "/opt/sbx/open/xdg-open",
        );
        assert!(
            out.contains("Exec=/opt/sbx/open/xdg-open %u\n"),
            "absolute path, one URI: {out}"
        );
        assert!(
            out.contains("MimeType=x-scheme-handler/cursor;x-scheme-handler/https;\n"),
            "every declared scheme is claimed: {out}"
        );
    }

    #[test]
    fn the_generated_index_claims_each_scheme_for_the_generated_entry_alone() {
        // The index the portal consults for a scheme's claimants. It has to be generated because
        // the directory holding it is read-only in the cage, and it has to name only our entry:
        // the portal answers a scheme with one claimant and answers nothing at all with two.
        let out = mimeinfo_cache(&table(&[
            ("cursor", handler(&["cursor"], OpenMode::Exec)),
            ("https", handler(&["chromium"], OpenMode::Exec)),
        ]));
        assert_eq!(
            out,
            "[MIME Cache]\n\
             x-scheme-handler/cursor=sbx-open-uri.desktop;\n\
             x-scheme-handler/https=sbx-open-uri.desktop;\n"
        );
    }

    #[test]
    fn the_mime_defaults_name_the_generated_entry_for_every_scheme() {
        // This file, not the desktop database, decides which entry wins — so an application that
        // registers itself for its own scheme inside the cage does not take the route over.
        let out = mimeapps(&table(&[
            ("cursor", handler(&["cursor"], OpenMode::Exec)),
            ("https", handler(&["chromium"], OpenMode::Exec)),
        ]));
        assert_eq!(
            out,
            "[Default Applications]\n\
             x-scheme-handler/cursor=sbx-open-uri.desktop\n\
             x-scheme-handler/https=sbx-open-uri.desktop\n"
        );
    }
}
