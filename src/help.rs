//! `ops --help` / `ops help <command> [subcommand...]` — the usage surface.
//!
//! One table of [`Page`]s is the single source of truth: every top-level command
//! *and* every subcommand has a page carrying its argument grammar (`synopsis`),
//! one-line summary, option list, and prose. The top-level listing, each page, and
//! the handlers' own argument-error paths (which print [`synopsis`]) all render from
//! it, so help text and error text cannot drift.
//!
//! Help is dispatched centrally: [`maybe_help`] resolves the deepest command path a
//! `--help`/`-h` flag asks about, so `ops plugins store add --help` shows that exact
//! page. Subcommand listings are sorted alphabetically; the top-level command list
//! keeps its logical (loose-to-specific) order.
//!
//! Option descriptions duplicate knowledge that also lives in each handler's argument
//! parser — a deliberate, documented maintenance seam (options change rarely, and the
//! table and the parsers all live next to each other in `main.rs`). The guard test
//! enforces the one invariant the structure is exposed to: every dispatched command
//! and verb resolves to a page.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::process::ExitCode;

/// One option or operand line: the flag/operand token and its one-line description.
type Opt = (&'static str, &'static str);

/// A help page for a command path. A length-1 path is a top-level command; a longer
/// path is a subcommand (e.g. `["plugins", "store", "add"]`). `details` is prose only —
/// it never repeats the synopsis or the option/subcommand lists the page renders above it.
struct Page {
    path: &'static [&'static str],
    synopsis: &'static str,
    summary: &'static str,
    options: &'static [Opt],
    details: &'static str,
}

/// Every command and subcommand. Top-level entries are in logical order (the order the
/// command list shows); subcommands may be in any order — the renderer sorts them.
const PAGES: &[Page] = &[
    // ---- top-level commands -------------------------------------------------------
    Page {
        path: &["doctor"],
        synopsis: "ops doctor",
        summary: "verify the runtime prerequisites before anything can run",
        options: &[],
        details: "Checks the load-bearing requirements: capability-bearing unprivileged user\n\
            namespaces (the security boundary everything rests on), the bubblewrap engine,\n\
            and the nix binary that drives the user-owned store. A missing requirement is a\n\
            hard failure with a remediation hint — never a silent fallback to a weaker\n\
            engine. Also reports best-effort resource limiting and the store location and\n\
            channel revision.",
    },
    Page {
        path: &["shell"],
        synopsis: "ops shell",
        summary: "open an interactive sandboxed shell in the current project",
        options: &[],
        details:
            "Launches an interactive shell inside the project sandbox, with job control and a\n\
            synthetic identity. The project's trusted config drives the environment; the\n\
            host home and the rest of the host filesystem are absent (confidentiality by\n\
            absence).",
    },
    Page {
        path: &["run"],
        synopsis: "ops run [--detach] [--] <command> [args...]",
        summary: "run a command inside the project sandbox",
        options: &[
            (
                "--detach",
                "run in the background as a session `ops ls`/`attach`/`stop` can see",
            ),
            ("--", "end ops's own flags; everything after runs literally"),
        ],
        details:
            "Runs <command> inside the project sandbox and propagates its exit status. A `--`\n\
            separates ops's flags from the command's, so `ops run -- --detach` runs the\n\
            literal `--detach`.",
    },
    Page {
        path: &["mise"],
        synopsis: "ops mise <args...>",
        summary: "run the in-cage mise to self-equip a project's toolchain",
        options: &[],
        details:
            "Passes its arguments through to the mise that runs inside the cage, so an agent\n\
            can self-equip a project's tools into the project's own store, e.g.\n\
            `ops mise install nix:jq` or `ops mise use -g aqua:BurntSushi/ripgrep`.\n\
            For mise's own help, run `ops mise help`.",
    },
    Page {
        path: &["app"],
        synopsis: "ops app <name> [--detach]",
        summary: "launch or manage named application profiles",
        options: &[(
            "--detach",
            "launch the app in the background as a session `ops ls`/`attach`/`stop` can see",
        )],
        details:
            "`ops app <name>` launches a named application profile (an [app.<name>] table from\n\
            the global or project config, or an imported <name>.toml) inside the project\n\
            sandbox, each with its own persistent isolated home.",
    },
    Page {
        path: &["search"],
        synopsis: "ops search <query>",
        summary: "discover the nix: tools a project can declare, via nixhub",
        options: &[],
        details: "Queries nixhub for tools to declare. A fuzzy query lists matches; a query that\n\
            names a package exactly leads with that package's versions and the lines to\n\
            declare it in `[tools]` or `[packages]`. Host-side and read-only — it resolves\n\
            nothing into the sandbox and needs no trust.",
    },
    Page {
        path: &["test"],
        synopsis: "ops test <subcommand> <target>",
        summary: "check whether an access would be allowed, and why",
        options: &[],
        details:
            "A diagnostic surface meant to grow with ops's access controls. No launch, no nix,\n\
            no network — it reports a verdict against the resolved policy.",
    },
    Page {
        path: &["plugins"],
        synopsis: "ops plugins <subcommand> [args...]",
        summary: "inspect and manage resolver plugins and plugin stores",
        options: &[],
        details:
            "Host-level — reads the data directory, not a project's config. A resolver plugin\n\
            declares a `scheme://` ops can route a secret `from` reference to.",
    },
    Page {
        path: &["ls"],
        synopsis: "ops ls",
        summary: "list the live sandbox sessions",
        options: &[],
        details:
            "Lists the live sandbox sessions from the on-disk registry (daemonless). Reading\n\
            the registry re-validates and prunes dead records, so the list is always\n\
            current. An app session shows its app name, so you can tell which sessions are\n\
            agents.",
    },
    Page {
        path: &["attach"],
        synopsis: "ops attach <id>",
        summary: "open a shell in a running session's environment",
        options: &[("<id>", "the PID `ops ls` shows for the session")],
        details:
            "Opens a shell in a running session's environment. For an app session, that is the\n\
            app's isolated environment.",
    },
    Page {
        path: &["stop"],
        synopsis: "ops stop <id>...|--all [--delay <secs>]",
        summary: "stop running sessions",
        options: &[
            (
                "<id>...",
                "the PIDs `ops ls` shows for the sessions to stop",
            ),
            (
                "--all",
                "stop every live session (mutually exclusive with explicit ids)",
            ),
            (
                "--delay <secs>",
                "seconds to wait after SIGTERM before SIGKILL (default 10; 0 = at once)",
            ),
        ],
        details:
            "Sends SIGTERM, then SIGKILL after the grace delay. Either ids or --all is required,\n\
            not both. --all targets every session, interactive shells included.",
    },
    Page {
        path: &["trust"],
        synopsis: "ops trust [path] | ops trust --show [path]",
        summary: "vouch for a project config's current contents",
        options: &[
            ("[path]", "the config to act on (default ./.ops.toml)"),
            ("--show", "report the trust state without changing it"),
        ],
        details: "Vouches for a config's current contents, so its security-relevant fields are\n\
            honored until the file changes again. Trust is bound to the file's contents, so\n\
            any edit re-arms the gate.",
    },
    Page {
        path: &["untrust"],
        synopsis: "ops untrust [path]",
        summary: "revoke a project config's trust",
        options: &[("[path]", "the config to act on (default ./.ops.toml)")],
        details:
            "Revokes a config's trust, so its security-relevant fields stop applying until it\n\
            is trusted again.",
    },
    Page {
        path: &["config"],
        synopsis: "ops config",
        summary: "show the resolved configuration for the current project",
        options: &[],
        details:
            "Shows the resolved configuration for the current project — the layered global and\n\
            project environment, binds, packages, tools, network, GUI, secrets, and app\n\
            profiles, after the trust gate has dropped anything an untrusted project may not\n\
            set. Warnings explain what was dropped and why. No launch, no nix, no network.",
    },
    Page {
        path: &["upgrade"],
        synopsis: "ops upgrade [all|nix|mise|flake]",
        summary: "roll managed channels forward (versions move only here)",
        options: &[
            ("all", "roll every managed channel (the default)"),
            (
                "nix",
                "the nixpkgs channel (base userland + native nix: packages)",
            ),
            (
                "mise",
                "the mise engine, the project's nix: tools, and mise: packages",
            ),
            ("flake", "the project's and apps' flake: packages"),
        ],
        details: "Rolls managed channels forward by re-resolving and rewriting their locks, so\n\
            versions advance only here, never on an ops binary update.",
    },
    Page {
        path: &["gc"],
        synopsis: "ops gc [--all] [--prune]",
        summary: "reclaim ops's per-project store space",
        options: &[
            (
                "--all",
                "also reap whole runtime trees whose project directory is gone",
            ),
            (
                "--prune",
                "actually reclaim (default is a dry run that touches nothing)",
            ),
        ],
        details:
            "By default it sweeps the current project's store. Reclamation is irreversible, so\n\
            the destructive form is opt-in.",
    },
    // ---- app subcommands ----------------------------------------------------------
    Page {
        path: &["app", "import"],
        synopsis: "ops app import <file> [--as <name>] [--force]",
        summary: "place a portable app profile (trusted by location)",
        options: &[
            (
                "<file>",
                "the portable profile (a top-level TOML app definition) to import",
            ),
            (
                "--as <name>",
                "name the imported app (default: the source file's stem)",
            ),
            ("--force", "overwrite an existing profile of the same name"),
        ],
        details:
            "The deliberate command IS the consent — an agent in the cage cannot run it, and the\n\
            profile stays inert until `ops app <name>` launches it. The granted posture is\n\
            printed so the act is informed. The bytes are copied verbatim.",
    },
    Page {
        path: &["app", "export"],
        synopsis: "ops app export <name> [--out <file>]",
        summary: "write a named app out as a portable profile",
        options: &[
            ("<name>", "the app to export"),
            (
                "--out <file>",
                "write to a file (default: stdout, composable and clobber-safe)",
            ),
        ],
        details:
            "An imported profile is emitted verbatim; an inline app is serialized to a minimal\n\
            profile, as authored (security fields and all — import is the trust act, not\n\
            export). The exported file re-imports identically.",
    },
    Page {
        path: &["app", "rm"],
        synopsis: "ops app rm <name>",
        summary: "remove an imported profile",
        options: &[("<name>", "the imported profile to remove")],
        details: "Removes only an imported profile (a file in the profiles directory). An inline\n\
            [app.<name>] lives in ops.toml and is yours to edit there.",
    },
    Page {
        path: &["app", "list"],
        synopsis: "ops app list",
        summary: "list the imported profiles",
        options: &[],
        details:
            "The imported profiles `import`/`rm` manage, by name. The full resolved app set —\n\
            inline, project, and profile apps with their gating — is `ops config`.",
    },
    // ---- test subcommands ---------------------------------------------------------
    Page {
        path: &["test", "net"],
        synopsis: "ops test net <url>",
        summary: "test a URL against the resolved network policy",
        options: &[("<url>", "the URL to test")],
        details: "Reports ALLOWED/DENIED and the rule that decides it, reflecting the trust gate\n\
            (an untrusted project's policy is dropped). No launch, no nix, no network.",
    },
    // ---- plugins subcommands ------------------------------------------------------
    Page {
        path: &["plugins", "list"],
        synopsis: "ops plugins list",
        summary: "list installed resolver plugins and built-in schemes",
        options: &[],
        details: "Shows the reserved built-in schemes and every installed resolver plugin — its\n\
            scheme, name, version, network grant, and whether it is runnable.",
    },
    Page {
        path: &["plugins", "info"],
        synopsis: "ops plugins info <scheme>",
        summary: "show a plugin's manifest and sandbox grant",
        options: &[("<scheme>", "the resolver scheme to detail")],
        details:
            "A built-in scheme is reported as such; an unknown scheme is a non-zero miss, with\n\
            the load warnings re-emitted (so a dropped plugin explains itself).",
    },
    Page {
        path: &["plugins", "install"],
        synopsis: "ops plugins install <name|dir>",
        summary: "install a built-in or local resolver plugin",
        options: &[
            (
                "<name>",
                "a built-in store plugin name (bundled in the binary)",
            ),
            (
                "<dir>",
                "a local plugin directory (./dir, /abs/dir) to copy",
            ),
        ],
        details: "A deliberate user act (an agent in the cage cannot run it). The staged copy is\n\
            validated exactly as the launcher will and refused, fail-closed, on any flaw.",
    },
    Page {
        path: &["plugins", "rm"],
        synopsis: "ops plugins rm <name>",
        summary: "remove an installed resolver plugin",
        options: &[(
            "<name>",
            "the installed plugin to remove (the token `list` shows)",
        )],
        details: "",
    },
    Page {
        path: &["plugins", "store"],
        synopsis: "ops plugins store <subcommand> [args...]",
        summary: "manage signed plugin stores",
        options: &[],
        details:
            "A remote signed store is a git repository whose catalogue is verified against a\n\
            pinned public key, with anti-rollback on the revision.",
    },
    // ---- plugins store subcommands ------------------------------------------------
    Page {
        path: &["plugins", "store", "list"],
        synopsis: "ops plugins store list",
        summary: "list the built-in store and configured remote stores",
        options: &[],
        details: "The resolver plugins bundled in the binary, then every configured remote store\n\
            with its accepted revision and plugin count. No fetch, no network.",
    },
    Page {
        path: &["plugins", "store", "add"],
        synopsis: "ops plugins store add --name <n> --url <git-url> (--key <hex|@file> | --trust)",
        summary: "configure and fetch a remote signed store",
        options: &[
            ("--name <n>", "a local name for the store"),
            ("--url <git-url>", "the store's git repository"),
            (
                "--key <hex|@file>",
                "pin a public key obtained out of band (the strong form)",
            ),
            (
                "--trust",
                "accept the key the store ships on first use (weaker — trust-on-first-use)",
            ),
        ],
        details:
            "Exactly one of --key or --trust is required: a store with no verifying key would\n\
            be unsigned, refused fail-closed. With --trust the pinned key's fingerprint is\n\
            printed for out-of-band verification.",
    },
    Page {
        path: &["plugins", "store", "publish"],
        synopsis: "ops plugins store publish <dir> --key <key-file> [--rev <n>]",
        summary: "sign a directory of plugins into a store",
        options: &[
            ("<dir>", "a directory of resolver plugins to sign"),
            (
                "--key <key-file>",
                "the signing key (reused if it exists, else generated owner-only)",
            ),
            (
                "--rev <n>",
                "the catalogue revision (monotonic; consumers refuse a rollback)",
            ),
        ],
        details:
            "The producing counterpart of `store add` — an operator tool, never reachable from\n\
            a cage. The signing key is the store's secret and never leaves the operator's\n\
            host; the public key it prints is what consumers pin.",
    },
    Page {
        path: &["plugins", "store", "update"],
        synopsis: "ops plugins store update [name]",
        summary: "re-fetch one or all configured stores",
        options: &[(
            "[name]",
            "a configured store to update (default: every one)",
        )],
        details:
            "Each re-fetch re-verifies the catalogue against the store's pinned key and refuses\n\
            a revision that would roll back, replacing the cache atomically.",
    },
    Page {
        path: &["plugins", "store", "install"],
        synopsis: "ops plugins store install <store> <plugin>",
        summary: "install a plugin a configured store lists",
        options: &[
            ("<store>", "the configured store"),
            ("<plugin>", "the plugin it lists, by name"),
        ],
        details: "The cached, verified catalogue pins the plugin's content by hash; the install\n\
            verifies that hash and places it exactly as a local install would. No network.",
    },
    Page {
        path: &["plugins", "store", "info"],
        synopsis: "ops plugins store info <name>",
        summary: "detail a configured remote store",
        options: &[("<name>", "the configured store to detail")],
        details:
            "Its origin URL, the pinned public key, the accepted revision, and each plugin it\n\
            lists. Reads only the owner-only cache: no fetch, no network.",
    },
    Page {
        path: &["plugins", "store", "rm"],
        synopsis: "ops plugins store rm <name>",
        summary: "remove a configured remote store",
        options: &[("<name>", "the configured store to remove")],
        details: "",
    },
];

/// ANSI styling for one output stream. Empty strings when color is off, so the render
/// code is unconditional and a non-terminal (a pipe, a captured test) is plain text.
struct Palette {
    /// Command and subcommand names.
    name: &'static str,
    /// Option and operand flags.
    flag: &'static str,
    /// Section headers (`Usage:`, `Options:`, …).
    head: &'static str,
    reset: &'static str,
}

impl Palette {
    /// The active ANSI styling — command/subcommand names in bold cyan, option flags in bold
    /// green, section headers in bold.
    fn colored() -> Self {
        Palette {
            name: "\x1b[1;36m",
            flag: "\x1b[1;32m",
            head: "\x1b[1m",
            reset: "\x1b[0m",
        }
    }

    /// No styling — every span is empty, so the render code is unconditional and the output is
    /// plain text (a pipe, a captured test, `NO_COLOR`, a `dumb` terminal).
    fn plain() -> Self {
        Palette {
            name: "",
            flag: "",
            head: "",
            reset: "",
        }
    }

    /// Decide color for a stream — the conventional auto-detection: colored only when the stream
    /// is a terminal, `NO_COLOR` is unset, and the terminal is not `dumb`.
    fn for_stream(is_tty: bool) -> Self {
        let on = is_tty
            && std::env::var_os("NO_COLOR").is_none()
            && std::env::var_os("TERM").is_none_or(|t| t != "dumb");
        if on {
            Self::colored()
        } else {
            Self::plain()
        }
    }
}

/// Find the page for an exact command path.
fn find(path: &[&str]) -> Option<&'static Page> {
    PAGES.iter().find(|p| p.path == path)
}

/// The pages exactly one level below `path`, sorted alphabetically by their last token —
/// the subcommand listing under a command's page.
fn children(path: &[&str]) -> Vec<&'static Page> {
    let mut kids: Vec<&Page> = PAGES
        .iter()
        .filter(|p| p.path.len() == path.len() + 1 && p.path.starts_with(path))
        .collect();
    kids.sort_by_key(|p| *p.path.last().unwrap());
    kids
}

/// The argument grammar for a command path, e.g. `synopsis_of(&["app","import"])`. Handlers
/// print this on an argument error so the grammar lives in exactly one place. An unknown
/// path (only an internal caller can pass one) yields a generic fallback.
pub fn synopsis_of(path: &[&str]) -> &'static str {
    find(path).map_or("ops <command>", |p| p.synopsis)
}

/// The argument grammar for a top-level command, e.g. `synopsis("stop")`.
pub fn synopsis(name: &str) -> &'static str {
    synopsis_of(&[name])
}

/// Whether `name` is a dispatched top-level command. Used to keep the help-flag
/// interception from swallowing an unknown command (which has its own diagnosis).
pub fn is_command(name: &str) -> bool {
    find(&[name]).is_some()
}

/// For an unknown top-level command that is really a subcommand verb, the full path to
/// suggest. Only verbs with a *single* parent are listed — an ambiguous verb (`rm`,
/// `list`, `info`, `install` each belong to more than one parent) would misdirect, so it
/// falls through to the generic `ops --help` pointer instead.
pub fn subcommand_hint(name: &str) -> Option<&'static str> {
    Some(match name {
        "import" => "ops app import",
        "export" => "ops app export",
        "net" => "ops test net",
        "publish" => "ops plugins store publish",
        "add" => "ops plugins store add",
        "update" => "ops plugins store update",
        "store" => "ops plugins store",
        _ => return None,
    })
}

/// One aligned `  flag    description` line, the flag painted in `color`.
fn item(out: &mut String, color: &str, reset: &str, key: &str, width: usize, desc: &str) {
    if desc.is_empty() {
        out.push_str(&format!("  {color}{key}{reset}\n"));
    } else {
        out.push_str(&format!("  {color}{key:<width$}{reset}  {desc}\n"));
    }
}

/// Render the top-level command list — the body of `ops --help` and the no-command usage.
/// Top-level commands keep their table (logical) order.
fn top_level(pal: &Palette) -> String {
    let mut out = String::from("ops — a sandbox launcher (bubblewrap + daemonless nix)\n\n");
    out.push_str(&format!(
        "{}Usage:{}\n  ops <command> [arguments]\n\n",
        pal.head, pal.reset
    ));
    out.push_str(&format!("{}Commands:{}\n", pal.head, pal.reset));
    let tops: Vec<&Page> = PAGES.iter().filter(|p| p.path.len() == 1).collect();
    let width = tops.iter().map(|p| p.path[0].len()).max().unwrap_or(0);
    for p in tops {
        item(&mut out, pal.name, pal.reset, p.path[0], width, p.summary);
    }
    out.push_str("\nRun `ops help <command>` (or `ops <command> --help`) for usage and details.\n");
    out
}

/// Render one page: header, usage, options, subcommands (alphabetical), then prose.
fn render(page: &Page, pal: &Palette) -> String {
    let joined = page.path.join(" ");
    let mut out = format!(
        "{}ops {}{} — {}\n\n",
        pal.name, joined, pal.reset, page.summary
    );
    out.push_str(&format!(
        "{}Usage:{}\n  {}\n",
        pal.head, pal.reset, page.synopsis
    ));

    if !page.options.is_empty() {
        out.push_str(&format!("\n{}Options:{}\n", pal.head, pal.reset));
        let width = page.options.iter().map(|(f, _)| f.len()).max().unwrap_or(0);
        for (flag, desc) in page.options {
            item(&mut out, pal.flag, pal.reset, flag, width, desc);
        }
    }

    let kids = children(page.path);
    if !kids.is_empty() {
        out.push_str(&format!("\n{}Subcommands:{}\n", pal.head, pal.reset));
        let width = kids
            .iter()
            .map(|k| k.path.last().unwrap().len())
            .max()
            .unwrap_or(0);
        for k in &kids {
            item(
                &mut out,
                pal.name,
                pal.reset,
                k.path.last().unwrap(),
                width,
                k.summary,
            );
        }
        out.push_str(&format!(
            "\nRun `ops help {joined} <subcommand>` for a subcommand's options.\n"
        ));
    }

    if !page.details.is_empty() {
        out.push_str(&format!("\n{}\n", page.details));
    }
    out
}

/// Print one command path's page to stdout. A path that is not a known page is a usage
/// error pointing back at the top-level help.
pub fn show(path: &[&str]) -> ExitCode {
    match find(path) {
        Some(page) => {
            let pal = Palette::for_stream(std::io::stdout().is_terminal());
            print!("{}", render(page, &pal));
            ExitCode::SUCCESS
        }
        None => {
            eprintln!(
                "ops: no help for `ops {}` — run `ops --help` for the list of commands.",
                path.join(" ")
            );
            ExitCode::from(2)
        }
    }
}

/// The deepest command path a help request is about: the command, then each following
/// non-flag token that extends it to a known subcommand. `ops plugins store add --help`
/// resolves to `["plugins","store","add"]`; `ops stop --all --help` to `["stop"]`.
fn resolve_path<'a>(cmd: &'a str, rest: &'a [OsString]) -> Vec<&'a str> {
    let mut path = vec![cmd];
    for arg in rest {
        let Some(tok) = arg.to_str() else { break };
        if tok.starts_with('-') {
            break;
        }
        let mut candidate = path.clone();
        candidate.push(tok);
        if find(&candidate).is_some() {
            path.push(tok);
        } else {
            break;
        }
    }
    path
}

/// If the arguments carry a `--help`/`-h` flag, show the page for the deepest command path
/// they name and return its exit code; otherwise `None`, so the command runs normally. The
/// caller restricts this to known commands (an unknown command keeps its own diagnosis) and
/// excludes `run`/`mise`, which handle a leading help flag themselves.
pub fn maybe_help(cmd: &str, rest: &[OsString]) -> Option<ExitCode> {
    let asks_help = rest
        .iter()
        .any(|a| matches!(a.to_str(), Some("--help" | "-h")));
    asks_help.then(|| show(&resolve_path(cmd, rest)))
}

/// `ops help [command [subcommand...]]` / `ops --help` / `ops -h`: the top-level list, or
/// the page for the full command path given after the verb.
pub fn dispatch(args: Vec<OsString>) -> ExitCode {
    let path: Vec<&str> = args
        .iter()
        .map_while(|a| a.to_str())
        .take_while(|t| !t.starts_with('-'))
        .collect();
    if path.is_empty() {
        let pal = Palette::for_stream(std::io::stdout().is_terminal());
        print!("{}", top_level(&pal));
        ExitCode::SUCCESS
    } else {
        show(&path)
    }
}

/// Render the top-level list to a string for the no-command usage error (the caller writes
/// it to stderr and exits non-zero). Color is decided for stderr.
pub fn top_level_usage() -> String {
    top_level(&Palette::for_stream(std::io::stderr().is_terminal()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Count the ANSI styling in a rendered string and assert it is balanced: every color span
    /// is closed by a reset (opens == resets), at least one span exists, and the output never
    /// ends mid-span. A captured test stream is never a TTY, so this is the only place the
    /// *colored* branch — the feature the user asked for — is actually exercised.
    fn assert_balanced(s: &str) {
        assert!(s.contains("\x1b["), "expected color");
        let escapes = s.matches("\x1b[").count();
        let resets = s.matches("\x1b[0m").count();
        // Every escape is either an opening color or a reset, and the two must match.
        assert_eq!(
            escapes,
            2 * resets,
            "unbalanced spans: {escapes} escapes vs {resets} resets"
        );
        assert!(
            !s.trim_end().ends_with("\x1b["),
            "output must not end mid-span"
        );
    }

    #[test]
    fn colored_render_balances_every_span() {
        // A page with a header, options, and a subcommand list exercises all three colors.
        let page = find(&["app"]).expect("app page");
        assert_balanced(&render(page, &Palette::colored()));
        assert_balanced(&top_level(&Palette::colored()));
    }

    #[test]
    fn plain_render_emits_no_escapes() {
        let page = find(&["app"]).expect("app page");
        assert!(!render(page, &Palette::plain()).contains('\x1b'));
        assert!(!top_level(&Palette::plain()).contains('\x1b'));
    }

    #[test]
    fn every_page_renders_balanced_in_color() {
        // Guard the whole table, not just one page: a future page that forgets a reset is caught.
        for page in PAGES {
            assert_balanced(&render(page, &Palette::colored()));
        }
    }
}
