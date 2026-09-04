use super::render::{paint_inline_code, paint_synopsis};
use super::*;

/// Count the ANSI styling in a rendered string and assert it is balanced: every color span
/// is closed by a reset (opens == resets), at least one span exists, and the output never
/// ends mid-span. A captured test stream is never a TTY, so this is the only place the
/// *colored* branch is actually exercised.
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

/// A folded option group changes where a row is PRINTED and nothing else.
///
/// The two halves are what make the fold safe. The rendered page must show the heading and must not
/// give a folded target a line of its own, or the fold did not happen; and `options_of` must still
/// answer every one of them, because that table is what completion walks — a target that stops
/// completing is a capability quietly removed, which is the opposite of what folding is for.
#[test]
fn a_folded_option_group_moves_the_row_without_removing_it() {
    let page = find(&["upgrade"]).expect("upgrade page");
    let rendered = render(page, &Palette::plain());
    let folded = [
        "nix", "mise", "flake", "deb", "appimage", "tarball", "binary",
    ];

    assert!(
        rendered.contains("narrow to one channel:"),
        "the heading must be rendered:\n{rendered}"
    );
    for name in folded {
        assert!(
            !rendered
                .lines()
                .any(|l| l.trim_start().starts_with(&format!("{name} "))),
            "`{name}` must not keep an option line of its own:\n{rendered}"
        );
    }
    // The group sits between the operands and the flags, which is where every folded row belongs:
    // they are operands themselves.
    let heading = rendered.find("narrow to one channel:").expect("heading");
    let flag = rendered.find("-a, --app").expect("a flag row");
    assert!(heading < flag, "the group precedes the flags:\n{rendered}");

    let offered: Vec<&str> = crate::help::options_of(&["upgrade"])
        .iter()
        .map(|(f, _)| *f)
        .collect();
    for name in folded {
        assert!(
            offered.contains(&name),
            "`{name}` must still be offered to completion: {offered:?}"
        );
    }
}

#[test]
fn plain_render_emits_no_escapes() {
    let page = find(&["app"]).expect("app page");
    assert!(!render(page, &Palette::plain()).contains('\x1b'));
    assert!(!top_level(&Palette::plain()).contains('\x1b'));
}

#[test]
fn maybe_help_stops_at_a_double_dash() {
    use std::ffi::OsString;
    let v = |xs: &[&str]| -> Vec<OsString> { xs.iter().map(OsString::from).collect() };

    // A leading help flag — or one after a subcommand, or after a non-`--` flag — is sbx's.
    assert!(maybe_help("app", &v(&["--help"])).is_some());
    assert!(maybe_help("app", &v(&["-h"])).is_some());
    assert!(maybe_help("app", &v(&["import", "--help"])).is_some());
    assert!(maybe_help("app", &v(&["run", "--help"])).is_some());
    assert!(maybe_help("stop", &v(&["--all", "--help"])).is_some());

    // A help flag *after* a `--` belongs to the launched command — `sbx app run <name> -- --help`
    // passes `--help` through, so sbx does not intercept it.
    assert!(maybe_help("app", &v(&["run", "demo-app", "--", "--help"])).is_none());
    assert!(maybe_help("app", &v(&["run", "demo-app", "--", "-h"])).is_none());
    // No help flag at all runs the command.
    assert!(maybe_help("app", &v(&["run", "demo-app", "--", "-c"])).is_none());
    assert!(maybe_help("app", &v(&["run", "demo-app"])).is_none());
}

#[test]
fn every_page_renders_balanced_in_color() {
    // Guard the whole table, not just one page: a future page that forgets a reset is caught.
    for page in PAGES {
        assert_balanced(&render(page, &Palette::colored()));
    }
}

#[test]
fn paint_synopsis_wraps_only_metavariables() {
    let pal = Palette::colored();
    let painted = paint_synopsis("sbx session stop <id>...|--all [--delay <secs>]", &pal);
    // Each `<…>` span (angle brackets included) is wrapped; literals stay untouched.
    assert!(painted.contains("\x1b[1m<id>\x1b[0m"));
    assert!(painted.contains("\x1b[1m<secs>\x1b[0m"));
    assert!(painted.contains("--all"));
    assert!(!painted.contains("\x1b[1m--all")); // a literal flag is never painted as a metavar

    // A plain palette returns the input byte-for-byte.
    assert_eq!(
        paint_synopsis("sbx session stop <id>...|--all", &Palette::plain()),
        "sbx session stop <id>...|--all"
    );

    // An unterminated `<` is emitted verbatim — never a dangling open span.
    let weird = paint_synopsis("sbx x <unterminated", &pal);
    assert!(weird.ends_with("<unterminated"));
    assert!(!weird.trim_end().ends_with("\x1b["));
}

#[test]
fn paint_inline_code_strips_backticks_and_wraps_the_content() {
    let pal = Palette::colored();
    let painted = paint_inline_code("run `sbx help run` for the `--config` reference", &pal);
    // Backticks are dropped; the inner token is wrapped in the code style + reset.
    assert!(painted.contains("\x1b[36msbx help run\x1b[0m"));
    assert!(painted.contains("\x1b[36m--config\x1b[0m"));
    assert!(
        !painted.contains('`'),
        "backticks must be dropped when styled"
    );

    // A metavariable inside a code span stays literal text (only the whole span is styled).
    let meta = paint_inline_code("Run `sbx help <command>` for details", &pal);
    assert!(meta.contains("\x1b[36msbx help <command>\x1b[0m"));

    // Color off: the string is returned byte-for-byte, backticks kept.
    assert_eq!(
        paint_inline_code("run `sbx help run`", &Palette::plain()),
        "run `sbx help run`"
    );

    // A lone backtick is emitted verbatim — never a dangling open span.
    let weird = paint_inline_code("an `unterminated span", &pal);
    assert!(weird.ends_with("`unterminated span"));
    assert!(!weird.trim_end().ends_with("\x1b["));
}

/// Whether `text` names `phrase` as a whole command rather than as the head of a longer one:
/// `sbx task log` must not be considered advertised by a `sbx task logs` sitting in the prose.
fn names_command(text: &str, phrase: &str) -> bool {
    text.match_indices(phrase).any(|(at, _)| {
        text[at + phrase.len()..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric() && c != '-' && c != '_')
    })
}

/// The inline-code spans of one page: its summary, its option rows and their descriptions,
/// and its details prose. A command is quoted in a span wherever a page names one, so the
/// span is the unit a claim about a command is made in. Read the way [`paint_inline_code`]
/// reads them — the odd halves of a split on the backtick.
fn code_spans_of(page: &Page) -> Vec<&'static str> {
    let mut texts: Vec<&'static str> = vec![page.summary, page.details];
    for &(row, desc) in page.options {
        texts.push(row);
        texts.push(desc);
    }
    texts
        .into_iter()
        .flat_map(|text| text.split('`').skip(1).step_by(2))
        .collect()
}

/// Whether a quoted word is shaped like a command name. The table writes them lowercase, so
/// a flag, a metavariable, a dotted key or an example value is not one and is left alone.
fn is_command_word(tok: &str) -> bool {
    tok.starts_with(|c: char| c.is_ascii_lowercase())
        && tok.chars().all(|c| c.is_ascii_lowercase() || c == '-')
}

/// No page sends a reader to a command the binary does not have.
///
/// A page is where a refusal's remediation is written, so a command named here is read at the
/// moment something already failed — and both ways it goes stale are silent. A verb that never
/// existed — a bare `stop`, where the verb is `sbx session stop` — is one. A namespace named
/// without the subcommand it requires is the other: `sbx app <name>` is not a launch, because
/// an app name is never a subcommand — an app may itself be named `run`, and is launched as
/// `sbx app run <name>` either way.
///
/// Both halves are read out of the table rather than from a list kept here. The head of a
/// quoted `sbx …` names a top-level command; and where that command's own page carries no
/// options — the namespaces, whose whole grammar is their subcommands — the word after it names
/// one of them.
#[test]
fn no_page_names_a_command_the_binary_does_not_have() {
    let mut broken: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for page in PAGES {
        let named = |what: String| format!("sbx {}: {what}", page.path.join(" "));
        for span in code_spans_of(page) {
            let mut words = span.split_whitespace();
            if words.next() != Some("sbx") {
                continue;
            }
            let Some(head) = words.next().filter(|w| is_command_word(w)) else {
                continue;
            };
            // `help` is a real verb, and the one with no page of its own.
            if head == "help" {
                continue;
            }
            checked += 1;
            let head = canonical(&[], head);
            let Some(owner) = find(&[head]) else {
                broken.push(named(format!("`{span}` names no command `{head}`")));
                continue;
            };
            // A namespace takes a subcommand and nothing else: its page documents no option
            // or operand of its own, and every word it accepts has a page one level down.
            if !owner.options.is_empty() || children(&[head]).is_empty() {
                continue;
            }
            let Some(next) = words
                .next()
                .filter(|w| is_command_word(w) || w.starts_with(['<', '[']))
            else {
                continue;
            };
            if find(&[head, canonical(&[head], next)]).is_none() {
                broken.push(named(format!(
                    "`{span}` names no `{head}` subcommand `{next}`"
                )));
            }
        }
    }
    assert!(
        broken.is_empty(),
        "these pages quote a command the dispatcher would refuse:\n{}",
        broken.join("\n")
    );
    // A sweep that read no span at all would pass while guarding nothing.
    assert!(checked > 150, "only {checked} quoted commands swept");
}

/// One Rust source with the line breaks a quoted span may wrap across closed up: leading
/// whitespace, a comment's `///`/`//!`/`//` continuation marker, and a string literal's trailing
/// `\` (with the `\n` a page's prose puts before it) are dropped, and the lines are joined by a
/// single space.
///
/// A quoted command is written the way prose is written, so it wraps like prose: the same span
/// crosses a line break in a doc comment and in a diagnostic alike. Splitting such a file line by
/// line would cut the span in two and sweep neither half, which is silence reported as a pass.
fn unwrapped_source(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, raw) in text.lines().enumerate() {
        let mut line = raw.trim_start();
        for marker in ["///", "//!", "//"] {
            if let Some(rest) = line.strip_prefix(marker) {
                line = rest.trim_start();
                break;
            }
        }
        let line = line.trim_end();
        let line = line.strip_suffix('\\').unwrap_or(line);
        let line = line.strip_suffix("\\n").unwrap_or(line);
        if i > 0 {
            out.push(' ');
        }
        out.push_str(line);
    }
    out
}

/// No source sends a reader to a command the binary does not have, either.
///
/// [`no_page_names_a_command_the_binary_does_not_have`] guards the help table, which is where a
/// remedy is *documented*. The same remedy is also *printed* — by the refusal itself, and by the
/// hint under it — and explained in the comments beside the code that prints it, and none of those
/// are pages. That is how `sbx app prune` came to refuse a live session and send the user to a
/// top-level `stop` verb long after its own page had been corrected to `sbx session stop`: the page
/// sweep read the fixed half and had nothing to say about the other one.
///
/// The unit is the same inline-code span, taken here from every `.rs` file in the crate, so a
/// diagnostic, a doc comment and an ordinary comment are all held to it — a comment naming a verb
/// is what the next reader of that code repeats into a message.
///
/// Only the *top-level* verb is checked. The page sweep's second half — a namespace named without
/// the subcommand it requires — is deliberately not applied to the sources yet: the comments write
/// `sbx app <name>` throughout as shorthand for a launch, where the verb is `sbx app run <name>`.
/// That shorthand is wrong in the same way and correcting it is worth doing, but it is a change to
/// those comments; asserting it here first would leave a permanently red test, which guards
/// nothing.
#[test]
fn no_source_names_a_command_the_binary_does_not_have() {
    let mut broken: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for path in crate::testutil::crate_sources() {
        let text = unwrapped_source(&std::fs::read_to_string(&path).expect("a crate source"));
        let shown = path.display().to_string();
        for span in text.split('`').skip(1).step_by(2) {
            let mut words = span.split_whitespace();
            if words.next() != Some("sbx") {
                continue;
            }
            let Some(head) = words.next().filter(|w| is_command_word(w)) else {
                continue;
            };
            // `help` is a real verb, and the one with no page of its own.
            if head == "help" {
                continue;
            }
            checked += 1;
            let head = canonical(&[], head);
            if find(&[head]).is_none() {
                broken.push(format!("{shown}: `{span}` names no command `{head}`"));
            }
        }
    }
    assert!(
        broken.is_empty(),
        "these sources quote a command the dispatcher would refuse:\n{}",
        broken.join("\n")
    );
    // A sweep that read no span at all would pass while guarding nothing.
    assert!(checked > 150, "only {checked} quoted commands swept");
}

/// The `config add` page redirects a rule *write* to the verb that owns it, and the same
/// paragraph tells the reader how a rule comes back out. The second half is a claim about the
/// table's own removal verbs, and it went stale the day they were added: the page said
/// `sbx config rm` was the only way out, while `sbx net unallow|undeny|unmute` and `sbx proc
/// unallow|undeny` each had a page, each was dispatched, and the `config rm` page said so.
///
/// Asserted against the removal verbs the table declares rather than a list kept here, so a
/// verb added tomorrow is one this paragraph has to account for.
#[test]
fn the_config_add_page_accounts_for_every_rule_removal_verb() {
    let page = find(&["config", "add"]).expect("the `config add` page");
    let mut unnamed: Vec<String> = Vec::new();
    let mut removals = 0usize;
    for namespace in ["net", "proc"] {
        for (verb, _) in subcommands_of(&[namespace]) {
            if !verb.starts_with("un") {
                continue;
            }
            removals += 1;
            if !page.details.contains(verb) {
                unnamed.push(format!("sbx {namespace} {verb}"));
            }
        }
    }
    assert!(
        unnamed.is_empty(),
        "the `config add` page describes removal without naming these verbs, which take a \
         rule back out in the vocabulary it was written in: {unnamed:?}"
    );
    assert!(removals >= 5, "only {removals} removal verbs found");
}

#[test]
fn the_alias_table_is_well_formed() {
    for &(parent, alias, name) in ALIASES {
        assert!(
            is_command_path(parent),
            "the path {alias:?} is read under, {parent:?}, is not a command"
        );
        let mut spelled = parent.to_vec();
        spelled.push(alias);
        assert!(
            find(&spelled).is_none(),
            "{spelled:?} has a page of its own — an alias must not shadow a command"
        );
        assert_ne!(alias, name, "{spelled:?} cannot stand for itself");
        assert_eq!(
            canonical(parent, name),
            name,
            "{spelled:?} stands for {name:?}, which is itself an alias — aliases must not chain"
        );
        assert_eq!(
            ALIASES
                .iter()
                .filter(|(p, a, _)| *p == parent && *a == alias)
                .count(),
            1,
            "{spelled:?} is declared more than once"
        );
    }
}

#[test]
fn every_alias_is_advertised_on_the_page_that_owns_it() {
    // An accepted spelling nobody documents is left to be discovered by trial, and — worse —
    // reads as if the surface it belongs to were the one exception. This caught exactly that:
    // `plugins` accepted only `list`, while `secret` and `task` accepted `ls` without ever
    // mentioning it. The page that owns the canonical name carries the mention; a verb with no
    // page of its own (`sbx projects rm`) is documented on its parent's page, so that is where
    // its alias is looked for too.
    for &(parent, alias, name) in ALIASES {
        let mut canonical_path = parent.to_vec();
        canonical_path.push(name);
        let page = find(&canonical_path)
            .or_else(|| find(parent))
            .unwrap_or_else(|| panic!("{canonical_path:?} has no page and no parent page"));
        let mut prose = format!("{}\n{}\n{}", page.synopsis, page.summary, page.details);
        for (flag, desc) in page.options {
            prose.push_str(&format!("\n{flag}\n{desc}"));
        }
        let spelled = format!(
            "sbx {}",
            parent
                .iter()
                .copied()
                .chain([alias])
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert!(
            names_command(&prose, &spelled),
            "{:?}: the page must advertise `{spelled}`",
            page.path
        );
    }
}

#[test]
fn an_alias_resolves_to_the_page_of_the_name_it_stands_for() {
    fn v(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }
    assert_eq!(resolve_path("plugins", &v(&["ls"])), ["plugins", "list"]);
    assert_eq!(
        resolve_path("plugins", &v(&["store", "ls"])),
        ["plugins", "store", "list"]
    );
    assert_eq!(resolve_path("sessions", &v(&[])), ["session"]);
    // An alias below an alias: each level is folded before the next is looked up, so the
    // subcommand is read under `session` rather than under the `sessions` the user typed.
    assert_eq!(resolve_path("sessions", &v(&["list"])), ["session", "ls"]);
    assert_eq!(resolve_path("tasks", &v(&["log"])), ["task", "logs"]);
    // A canonical name is untouched, and an unknown token still stops the descent at the
    // deepest page that exists.
    assert_eq!(
        resolve_path("plugins", &v(&["store", "add"])),
        ["plugins", "store", "add"]
    );
    assert_eq!(resolve_path("plugins", &v(&["bogus"])), ["plugins"]);
    // A top-level alias is a command, so the help flag is intercepted before dispatch.
    assert!(is_command("sessions"));
    assert!(!is_command("bogus"));
}

/// The subcommand spellings one match arm accepts: the string literals left of its `=>`,
/// flags dropped. `Some("list") | Some("ls") =>` and `Some("list" | "ls") =>` both yield
/// `["list", "ls"]`; an arm that accepts one name yields one, and carries no alias.
fn arm_names(line: &str) -> Vec<&str> {
    let Some((head, _)) = line.split_once("=>") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut rest = head;
    while let Some(open) = rest.find('"') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('"') else { break };
        names.push(&after[..close]);
        rest = &after[close + 1..];
    }
    names.retain(|n| !n.starts_with('-'));
    names
}

/// Where every dispatcher lives and what it dispatches below: the source path relative to
/// `src/cli`, the function, and the command path its match arms are subcommands of. One file may
/// hold two (`plugins`, and the `store` namespace under it). A dispatcher missing from this list
/// is not silently unchecked — an alias arm found outside every listed function fails the scan.
///
/// The path is relative rather than a bare file name because a verb family split into `<verb>.rs`
/// beside a `<verb>/` puts more than one `logs.rs` under `src/cli`, and a bare name would key both
/// of them onto the same row.
const DISPATCHERS: &[(&str, &str, &[&str])] = &[
    ("mod.rs", "dispatch", &[]),
    ("app.rs", "app_cmd", &["app"]),
    ("fs.rs", "fs_cmd", &["fs"]),
    ("net.rs", "net_cmd", &["net"]),
    ("plugins.rs", "plugins_cmd", &["plugins"]),
    ("plugins.rs", "plugins_store", &["plugins", "store"]),
    ("proc.rs", "proc_cmd", &["proc"]),
    ("projects.rs", "projects_cmd", &["projects"]),
    ("secret.rs", "secret_cmd", &["secret"]),
    ("session.rs", "session_cmd", &["session"]),
    ("sshagent.rs", "ssh_agent_cmd", &["ssh-agent"]),
    ("task.rs", "task_cmd", &["task"]),
];

/// The half-open line range a top-level `fn` occupies in `text`: its signature through the
/// closing brace in column 0.
///
/// A range must end at that brace, not run to the end of the file: an unterminated one would
/// swallow the arms of every function below it, which turns a real mismatch into a pass.
fn body_lines(text: &str, func: &str) -> std::ops::Range<usize> {
    let lines: Vec<&str> = text.lines().collect();
    let signature = format!("fn {func}(");
    let start = lines
        .iter()
        .position(|l| {
            l.starts_with(&signature) || l.starts_with(&format!("pub(crate) {signature}"))
        })
        .unwrap_or_else(|| panic!("no `fn {func}` in the dispatcher sources"));
    let end = lines[start..]
        .iter()
        .position(|l| *l == "}")
        .map(|at| start + at)
        .unwrap_or_else(|| panic!("`fn {func}` has no closing brace in column 0"));
    start..end
}

/// Every pair of spellings the dispatchers accept for one verb, read out of their sources:
/// `(parent path, first spelling, second spelling, where it was read)`.
///
/// Two shapes carry a subcommand alias. A namespace dispatcher matches an `Option<&str>`, so
/// its arms are recognized by the `Some(` before the `=>` — which also keeps the scan off the
/// arms that map an *option value* (`--source session|manual`). The top-level dispatcher
/// matches a plain `&str`, so its arms are read without that marker, from its function alone.
///
/// A text scan is a net, not a proof: an alias spelled some third way would slip past it. It
/// holds the shapes the code actually uses, and fails the moment one of them grows a spelling
/// the table does not know.
fn dispatched_alias_pairs() -> Vec<(&'static [&'static str], String, String, String)> {
    let cli = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli");

    let mut pairs = Vec::new();
    for source in crate::testutil::cli_sources() {
        let file = source
            .strip_prefix(&cli)
            .unwrap_or(&source)
            .to_string_lossy()
            .into_owned();
        let text = std::fs::read_to_string(&source).expect("a dispatcher source is readable");
        let dispatchers: Vec<(&[&str], std::ops::Range<usize>)> = DISPATCHERS
            .iter()
            .filter(|(f, _, _)| *f == file)
            .map(|(_, func, parent)| (*parent, body_lines(&text, func)))
            .collect();
        // Two dispatchers in one file must not overlap: a range that reached into the next
        // function would read its arms under the wrong parent, and a mismatch would pass.
        for (i, (parent, body)) in dispatchers.iter().enumerate() {
            for (other, next) in &dispatchers[i + 1..] {
                assert!(
                    body.end <= next.start || next.end <= body.start,
                    "in {file}, the bodies read for {parent:?} and {other:?} overlap"
                );
            }
        }

        for (i, line) in text.lines().enumerate() {
            let within = dispatchers.iter().find(|(_, body)| body.contains(&i));
            // Outside a known dispatcher only the `Some(...)` shape is read, so an arm that
            // maps an option value to a variant is not mistaken for a subcommand alias.
            let marked = line
                .split_once("=>")
                .is_some_and(|(head, _)| head.contains("Some("));
            if within.is_none() && !marked {
                continue;
            }
            let names = arm_names(line);
            let Some(first) = names.first() else { continue };
            let parent = match within {
                Some((parent, _)) => *parent,
                None => {
                    assert!(
                        names.len() < 2,
                        "src/cli/{file}:{} dispatches {names:?} from outside every function \
                         DISPATCHERS lists — add it, so its aliases are checked too",
                        i + 1
                    );
                    continue;
                }
            };
            for other in names.iter().skip(1) {
                pairs.push((
                    parent,
                    (*first).to_string(),
                    (*other).to_string(),
                    format!("src/cli/{file}:{}", i + 1),
                ));
            }
        }
    }
    pairs
}

#[test]
fn every_dispatched_alias_is_declared_in_the_table() {
    // The dispatchers own what they accept; this table owns what help, completion and the
    // option lists resolve. A spelling in one and not the other is a verb that runs but whose
    // `--help` lands on its parent's page — the bug this table was written for. Both
    // directions are checked: an undeclared alias resolves to nothing, and a declared one no
    // dispatcher accepts documents a verb that refuses to run.
    let pairs = dispatched_alias_pairs();
    assert!(
        pairs.len() >= 19,
        "the scan found only {} alias arms — its shapes no longer match the dispatchers",
        pairs.len()
    );
    for (parent, a, b, at) in &pairs {
        let declared = ALIASES.iter().any(|(p, alias, name)| {
            p == parent && ((alias == a && name == b) || (alias == b && name == a))
        });
        assert!(
            declared,
            "{at} accepts both {a:?} and {b:?} under {parent:?}, which ALIASES does not declare"
        );
    }
    for &(parent, alias, name) in ALIASES {
        assert!(
            pairs.iter().any(|(p, a, b, _)| *p == parent
                && ((a == alias && b == name) || (a == name && b == alias))),
            "no dispatcher accepts {alias:?} for {name:?} under {parent:?}"
        );
    }
}

#[test]
fn top_level_commands_are_listed_alphabetically() {
    // Parse the rendered command column and assert its order — the user-visible property.
    let plain = top_level(&Palette::plain());
    let block = plain
        .split_once("Commands:\n")
        .and_then(|(_, rest)| rest.split_once("\n\nRun "))
        .map(|(cmds, _)| cmds)
        .expect("command block");
    let listed: Vec<&str> = block
        .lines()
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    let mut sorted = listed.clone();
    sorted.sort_unstable();
    assert_eq!(
        listed, sorted,
        "top-level commands must render alphabetically"
    );
    // Every command is present (nothing dropped), and the declaration order was reordered.
    assert_eq!(
        listed.len(),
        PAGES.iter().filter(|p| p.path.len() == 1).count()
    );
}
