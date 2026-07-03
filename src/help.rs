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

use crate::style::Palette;

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
            "`ops app <name>` launches a named application profile (a project [app.<name>] overlay,\n\
            or an imported apps/<name>.toml profile — a global app lives as a profile file, not\n\
            inline in ops.toml) inside the project sandbox, each with its own persistent isolated\n\
            home.",
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
        path: &["net"],
        synopsis: "ops net <subcommand> [args...]",
        summary: "inspect the egress policy, its rules, and parked `ask` requests",
        options: &[],
        details:
            "The egress-policy surface. `rules` lists the effective allow/deny rules by source;\n\
            `groups` lists the reusable `[net.groups]` egress groups (referenced by `@<name>`) and\n\
            resolves one to its entries; `allow`/`deny <rule>` persist a rule to config; `pending`\n\
            lists and answers requests parked by the `ask` posture; `stats` reports the per-host\n\
            allow/deny/blocked decision counters launches recorded; `logs` is the live, per-request\n\
            egress log of a running session. Host-side — no launch, no nix. (Distinct from `ops test\n\
            net <url>`, which tests one URL against the policy.)",
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
        synopsis: "ops config <subcommand>",
        summary: "inspect and edit the project configuration",
        options: &[],
        details:
            "Inspect or edit the configuration for the current project. `ops config show` prints\n\
            the resolved, trust-gated view a launch would use (add --json for the machine-readable\n\
            model); get/set/unset read and edit a single raw layer file; path prints which file a\n\
            scope targets; and edit opens it in your editor.\n\
            \n\
            Run `ops config show` for the resolved configuration, or one of the subcommands below.",
    },
    Page {
        path: &["config", "get"],
        synopsis: "ops config get <key> [-l|--local|-g|--global|-c <file>] [-a|--app <name>]",
        summary: "read a value from a single config file",
        options: &[
            ("<key>", "a dotted key, e.g. env.FOO or nixpkgs"),
            ("-l, --local", "the project .ops.toml (the default)"),
            ("-g, --global", "the global ops.toml"),
            ("-c <file>", "an explicit config file"),
            (
                "-a, --app <name>",
                "address the key under that app's table (app.<name>.<key>)",
            ),
        ],
        details:
            "Prints the value declared at a dotted key in one layer file. This is the raw declared\n\
            value in that file — for the effective resolved value across layers, use `ops config\n\
            show` (or `ops config show --json`). An unset key exits 1; an array or table value is\n\
            edited with `ops config edit`, not read as a single value.\n\
            \n\
            --app <name> rewrites the key under that app's table, so `get --app demo cmd` reads\n\
            app.demo.cmd — sugar for the dotted key. An app name containing a `.` is edited with\n\
            `ops config edit` instead.",
    },
    Page {
        path: &["config", "set"],
        synopsis: "ops config set <key> <value> [-l|--local|-g|--global|-c <file>] [-a|--app <name>] [--trust]",
        summary: "set a value in a config file (comments preserved)",
        options: &[
            ("<key>", "a dotted key, e.g. env.FOO or network"),
            ("<value>", "the string value to set"),
            ("-l, --local", "the project .ops.toml (the default)"),
            ("-g, --global", "the global ops.toml"),
            ("-c <file>", "an explicit config file"),
            (
                "-a, --app <name>",
                "address the key under that app's table (app.<name>.<key>)",
            ),
            (
                "--trust",
                "re-trust the file after writing (applies its security fields at once)",
            ),
        ],
        details:
            "Writes a string value at a dotted key, preserving the file's other keys, comments,\n\
            and formatting. Creates the file and intermediate tables as needed.\n\
            \n\
            --app <name> rewrites the key under that app's table, so `set --app demo network\n\
            shared` writes app.demo.network — sugar for the dotted key. An app name containing a\n\
            `.` is edited with `ops config edit` instead.\n\
            \n\
            The trust gate hashes the whole file, so any edit re-arms it: after writing a file\n\
            you had trusted, its security fields stop applying until you run `ops trust`. Pass\n\
            --trust to re-trust in one step (this blesses the whole current file). A free env\n\
            value needs no trust. Array and table fields (binds, an allowlist, secrets, apps) are\n\
            edited with `ops config edit`.",
    },
    Page {
        path: &["config", "unset"],
        synopsis: "ops config unset <key> [-l|--local|-g|--global|-c <file>] [-a|--app <name>] [--trust]",
        summary: "remove a key from a config file",
        options: &[
            ("<key>", "a dotted key to remove, e.g. env.FOO"),
            ("-l, --local", "the project .ops.toml (the default)"),
            ("-g, --global", "the global ops.toml"),
            ("-c <file>", "an explicit config file"),
            (
                "-a, --app <name>",
                "address the key under that app's table (app.<name>.<key>)",
            ),
            ("--trust", "re-trust the file after writing"),
        ],
        details:
            "Removes a dotted key from one layer file. Removing a key that is not set changes\n\
            nothing (and so never re-arms trust). A removal that does change a trusted file\n\
            re-arms its trust gate, the same as `set`.\n\
            \n\
            --app <name> rewrites the key under that app's table, so `unset --app demo network`\n\
            removes app.demo.network. An app name containing a `.` is edited with `ops config\n\
            edit` instead.",
    },
    Page {
        path: &["config", "path"],
        synopsis: "ops config path [-l|--local|-g|--global|-c <file>]",
        summary: "show the config files in resolution order, or one scope's path",
        options: &[
            ("(no flag)", "list every config layer in resolution order, marking which exist"),
            ("-l, --local", "print only the project .ops.toml path"),
            ("-g, --global", "print only the global ops.toml path"),
            ("-c <file>", "print only this explicit config file path"),
        ],
        details:
            "With no scope flag, lists the config files a launch resolves — the global ops.toml\n\
            (the base) then the project .ops.toml (which overlays it) — and whether each exists,\n\
            so it is clear where ops looks even before any file is created. With a scope flag,\n\
            prints just that file's path (the one get/set/unset/edit would touch) — for scripting\n\
            and for locating the global config. For resolved values, see `ops config show`.",
    },
    Page {
        path: &["config", "edit"],
        synopsis: "ops config edit [-l|--local|-g|--global|-c <file>] [--trust]",
        summary: "open a config file in your editor",
        options: &[
            ("-l, --local", "the project .ops.toml (the default)"),
            ("-g, --global", "the global ops.toml"),
            ("-c <file>", "an explicit config file"),
            ("--trust", "re-trust the file after editing"),
        ],
        details:
            "Opens the target file in $VISUAL or $EDITOR (falling back to vi) — the way to edit\n\
            fields `set` does not handle as a single value, such as binds, an allowlist, secrets,\n\
            or app tables. A `binds` entry is an absolute host path, bound read-only by default;\n\
            write it as a table `{ path = \"/abs/path\", mode = \"rw\" }` to bind it read-write\n\
            (the cage writes through to the host path). `binds` is a security field, honored only\n\
            from a trusted source. A read-write bind covering ops's own state (its data, trust, or\n\
            config directory — e.g. a broad `mode = \"rw\"` bind of your home) is forced read-only\n\
            with a warning, so the agent cannot alter what ops runs or trusts; bind the narrower\n\
            path you actually need read-write instead.\n\
            An edit that changes a file you had trusted re-arms its trust gate, so it warns to\n\
            re-run `ops trust`; pass --trust to re-trust as the editor closes.",
    },
    Page {
        path: &["config", "show"],
        synopsis: "ops config show [--json] [--details] [-a|--app <name>] [-g|--global|-l|--local|-d|--default]",
        summary: "show the resolved configuration for the current project",
        options: &[
            (
                "--json",
                "print the resolved configuration as JSON (for scripts and tooling)",
            ),
            (
                "--details",
                "expand each app overlay's compact summary (env, binds, packages, allowlist rules, and injected credentials)",
            ),
            (
                "-a, --app <name>",
                "show one app's effective configuration, each field tagged inherited or set by the app",
            ),
            (
                "-g, --global",
                "show only what the global config (and imported profiles) contributes",
            ),
            ("-l, --local", "show only what the project .ops.toml contributes"),
            ("-d, --default", "show the built-in defaults alone (no config)"),
        ],
        details:
            "Shows the resolved configuration for the current project — the layered global and\n\
            project environment, binds, packages, tools, network, GUI, secrets, and app\n\
            profiles, after the trust gate has dropped anything an untrusted project may not\n\
            set. Each value is tagged with where it came from — (default), (global), or\n\
            (project), colored by level. Warnings explain what was dropped and why. No launch,\n\
            no nix, no network.\n\
            \n\
            A single-source flag restricts the view to one layer (over the built-in defaults),\n\
            so the provenance tags read as that layer's own additions: --global shows what the\n\
            global config plus any imported app profiles set (the project is ignored), --local\n\
            what the project .ops.toml sets (the global config and profiles ignored), and\n\
            --default the built-in defaults alone. The flags are mutually exclusive; with none,\n\
            the full layered configuration is shown. Each has a short form — -g, -l, -d, and -a\n\
            for --app; note -d is --default, so --details has no short form.\n\
            \n\
            With --app <name>, the view is one app's effective configuration — the baseline\n\
            folded with the app's overlay — each field tagged (inherited) when it takes the\n\
            baseline's value, or (app:global)/(app:project) when the app set it. (It does not\n\
            combine with a single-source flag.)\n\
            \n\
            An app profile is otherwise shown as a compact summary (one line per field); with\n\
            --details its env is expanded to each KEY=value, its binds to each path, its packages\n\
            to each full backend line (a withheld one marked, the same line the baseline packages\n\
            section renders), its allowlist to the individual allow/deny rules plus the\n\
            always-allowed built-in hosts, and its injected credentials to each by destination and\n\
            source — so what `ops app <name>` adds, can reach, and injects is visible at a glance.\n\
            An env value is the in-cage placeholder, a free field; the credential value is never\n\
            shown — ops reads it host-side at launch.\n\
            \n\
            With --json, the same resolved model is printed as a JSON document (warnings\n\
            included as a field) — the machine-readable form the human output renders, already\n\
            carrying every app's env, binds, packages, rules, and injected credentials in full.",
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
        details: "Removes only an imported profile (a file in the profiles directory). A project\n\
            [app.<name>] overlay lives in that project's .ops.toml and is yours to edit there.",
    },
    Page {
        path: &["app", "list"],
        synopsis: "ops app list",
        summary: "list the imported profiles",
        options: &[],
        details:
            "The imported profiles `import`/`rm` manage, by name. The full resolved app set —\n\
            inline, project, and profile apps with their gating — is `ops config show`.",
    },
    // ---- test subcommands ---------------------------------------------------------
    Page {
        path: &["test", "net"],
        synopsis: "ops test net [--app <name>] [-X|--method <verb>] <url|tcp://host:port>",
        summary: "test a URL (or a tcp:// target) against the resolved network policy",
        options: &[
            ("<url>", "the URL (or a bare host, completed to https) to test; `tcp://host:port` tests a raw L4 splice instead"),
            (
                "-a, --app <name>",
                "test against that app's effective policy (baseline + overlay), not the baseline",
            ),
            (
                "-X, --method <verb>",
                "the HTTP method to test (default GET); a method-scoped rule like `{GET} host` only matches that verb (ignored for a tcp:// target — a raw stream has no method)",
            ),
        ],
        details:
            "Reports ALLOWED/DENIED/WOULD ASK and the rule that decides it, against the effective\n\
            egress policy a launch serves: the built-in self-equip allow-set is included, and a\n\
            declared credential injection is noted (by header and source, never the value, and not\n\
            resolved). A `tcp://host:port` target instead reports SPLICED/NOT SPLICED — whether a\n\
            `tcp://` rule would tunnel it raw (uninspected) or it would take the inspected L7 path.\n\
            Reflects the trust gate (an untrusted project's policy is dropped). No nix.",
    },
    // ---- net subcommands ----------------------------------------------------------
    Page {
        path: &["net", "rules"],
        synopsis: "ops net rules [-a|--app <name>] [-s|--source config|builtin|manual] [-f|--filter <substr>] [-e|--expand] [--json]",
        summary: "list the effective egress rules by source",
        options: &[
            (
                "-a, --app <name>",
                "list the effective rules for that app (its `[app.<name>.network]` folded onto the baseline), not the baseline's",
            ),
            (
                "-s, --source <src>",
                "show only one source: config (the .ops.toml/global rules), builtin (the always-allowed self-equip set), or manual (live `--session` rules)",
            ),
            (
                "-f, --filter <substr>",
                "show only rules whose text contains <substr> (case-insensitive); implies --expand, so a host inside a group still matches",
            ),
            (
                "-e, --expand",
                "expand each `[net.groups]` group to its hosts (each tagged `@<group>`); by default a group shows as one `@<name>` row",
            ),
            ("--json", "emit the mode and rules as JSON"),
        ],
        details:
            "Lists the allow/deny rules of the effective filtering posture, each tagged config or\n\
            built-in, reflecting the trust gate (an untrusted project's rules are dropped). Every\n\
            rule names its layer: an inspected L7 rule shows `https://` (a bare host is https on 443),\n\
            a raw L4 rule shows `tcp://`; a `re:` regex shows neither (its pattern carries its own).\n\
            A rule that came from a `[net.groups]` group shows as a single `@<name>` reference;\n\
            `--expand` unfolds it to its hosts, each noting its `@<group>` origin (resolve one\n\
            directly with `ops net groups <name>`). Under `shared`/`none` there are no rules. `--app\n\
            <name>` shows what `ops app <name>` would launch with — the same effective policy `ops\n\
            test net --app` tests a URL against. `--source manual` instead queries this project's live\n\
            ask sessions for the rules they remembered from `--session` answers (it does not combine\n\
            with `--app`). No launch, no nix.",
    },
    Page {
        path: &["net", "groups"],
        synopsis: "ops net groups [<name>…] [--json] | ops net groups export|import …",
        summary: "list reusable egress groups, or resolve one to its entries",
        options: &[
            (
                "<name>…",
                "resolve the named group(s) to their authored entries (with no name, list every group and its entry count)",
            ),
            ("--json", "emit the groups and their entries as JSON"),
        ],
        details:
            "A `[net.groups]` group is a named set of egress entries declared once in the global\n\
            config and referenced from a `[network]` allow/deny list with `@<name>`, so a set of hosts\n\
            is shared across apps instead of rewritten per profile. Groups are global-only, so this\n\
            command has no scope flag — it always reads the global config. `ops net groups` lists the\n\
            groups; `ops net groups <name>` shows what `@<name>` expands to; `export`/`import` move\n\
            groups between machines. A malformed or nested entry is flagged. Add a reference with\n\
            `ops net allow @<name>`. Read-only (except `import`), no launch.",
    },
    Page {
        path: &["net", "groups", "export"],
        synopsis: "ops net groups export [<name>…] [-o|--out <file>]",
        summary: "write egress groups as a portable [net.groups] fragment",
        options: &[
            ("<name>…", "export only the named group(s) (default: every group)"),
            ("-o, --out <file>", "write to <file> instead of stdout"),
        ],
        details:
            "Emits the reusable egress groups as a portable `[net.groups]` TOML fragment — to stdout\n\
            by default (`ops net groups export > groups.toml`), or to `--out <file>`. The inverse of\n\
            `import`. Source comments are not carried (a group is data). Read-only, no launch.",
    },
    Page {
        path: &["net", "groups", "import"],
        synopsis: "ops net groups import <file> [-f|--force]",
        summary: "merge a [net.groups] fragment into the global config",
        options: &[
            ("<file>", "a `[net.groups]` fragment (e.g. from `ops net groups export`)"),
            ("-f, --force", "overwrite a group whose name already exists (default: refuse)"),
        ],
        details:
            "Merges the fragment's groups into the global config, preserving every existing group and\n\
            comment (`toml_edit`). Groups are global-only, so the target is always the global config,\n\
            which is trusted by location — the deliberate command is the consent (an agent in the cage\n\
            cannot run it), so there is no prompt. A name that already exists is refused unless\n\
            `--force`; the merge is all-or-nothing. A group carrying an entry that will not resolve (a\n\
            malformed or nested one) is flagged after the import — inspect it with `ops net groups\n\
            <name>`. Imported groups are inert until referenced by a `[network]` allow/deny with\n\
            `@<name>`.",
    },
    Page {
        path: &["net", "allow"],
        synopsis: "ops net allow <rule> [-l|--local|-g|--global] [-a|--app <name>]",
        summary: "persist an allow rule to a config file",
        options: &[
            ("<rule>", "an egress rule. A bare host (or `https://host`) is inspected L7 on port 443; add `:port`/`:*`/`:a,b` to widen. Forms: a host, `*.domain`, `host/path`, IP, or `re:<regex>`, optionally prefixed `{GET,POST}` to scope it to those HTTP verbs. `tcp://host:port` is a raw (uninspected) L4 tunnel — it must name a port; `tcp://host:*` opens every port and protocol. `@<group>` references a reusable `[net.groups]` group (defined in the global config), expanded to its entries at launch"),
            ("-l, --local", "write the project .ops.toml (the default)"),
            ("-g, --global", "write the global ops.toml"),
            ("-a, --app <name>", "write the rule under that app's `[app.<name>.network]`"),
        ],
        details:
            "Validates the rule, then adds it. With no filtering posture yet, `allow` bootstraps a\n\
            deny-by-default allowlist. Writing the project config re-trusts it (it must be absent or\n\
            already trusted first); the global config is trusted by location.",
    },
    Page {
        path: &["net", "deny"],
        synopsis: "ops net deny <rule> [-l|--local|-g|--global] [-a|--app <name>]",
        summary: "persist a deny rule to a config file",
        options: &[
            ("<rule>", "an egress rule. A bare host (or `https://host`) is inspected L7 on port 443; add `:port`/`:*`/`:a,b` to widen. Forms: a host, `*.domain`, `host/path`, IP, or `re:<regex>`, optionally prefixed `{GET,POST}` to scope it to those HTTP verbs. `tcp://host:port` is a raw (uninspected) L4 tunnel — it must name a port; `tcp://host:*` opens every port and protocol. `@<group>` references a reusable `[net.groups]` group (defined in the global config), expanded to its entries at launch"),
            ("-l, --local", "write the project .ops.toml (the default)"),
            ("-g, --global", "write the global ops.toml"),
            ("-a, --app <name>", "write the rule under that app's `[app.<name>.network]`"),
        ],
        details:
            "Validates the rule, then adds it (deny always wins over allow). A deny needs an existing\n\
            filtering posture — it will not open one — so set the posture first on a fresh config.\n\
            Writing the project config re-trusts it; the global config is trusted by location.",
    },
    Page {
        path: &["net", "pending"],
        synopsis:
            "ops net pending [-a <app>] [--json] | ops net pending allow|deny <id>|--all [-a <app>] [--save ...] | ops net pending watch [-i <secs>]",
        summary: "list and answer egress requests parked by the `ask` posture",
        options: &[
            ("-a, --app <name>", "limit the listing / `--all` drain to one app's session(s)"),
            ("--json", "list the pending requests as JSON"),
        ],
        details:
            "Under `[network] mode = \"ask\"` a request no rule decides parks until answered. With no\n\
            verb, lists what is parked across every live ask-mode session, each with a `<pid>.<seq>`\n\
            id; identical retries of one URL collapse to a single `×N` line. `allow <id>`/`deny <id>`\n\
            answer that whole destination (every identical retry at once); `allow|deny --all` drain\n\
            every parked request; `watch` redraws the listing live. `--app <name>` scopes the\n\
            listing or the `--all` drain to one app's session(s). No launch, no nix, no network.",
    },
    Page {
        path: &["net", "pending", "watch"],
        synopsis: "ops net pending watch [-i|--interval <secs>] [-a|--app <name>]",
        summary: "redraw the parked-request listing live until interrupted",
        options: &[
            ("-i, --interval <secs>", "seconds between refreshes (default 2)"),
            ("-a, --app <name>", "limit the listing to one app's session(s)"),
        ],
        details:
            "Polls the same live control sockets as `ops net pending` and redraws the listing in\n\
            place every few seconds (top-style — the terminal scrollback is preserved), so a parked\n\
            request appears as soon as an agent triggers it. Answer it from another shell with\n\
            `ops net pending allow|deny <id>`; the watch picks up the change on the next refresh.\n\
            Ctrl-C quits. Needs a terminal — for a pipe or a script use the one-shot listing (`--json`).\n\
            No launch, no nix, no network.",
    },
    Page {
        path: &["net", "pending", "allow"],
        synopsis: "ops net pending allow <id> [-a <app>] [--session] [--save [-l|-g]] | ops net pending allow --all [-a <app>] [--session] [--save [-l|-g]]",
        summary: "allow a parked egress request (optionally remembering or saving a rule)",
        options: &[
            ("<id>", "the `<pid>.<seq>` id from `ops net pending` or the launch notice"),
            ("--all", "allow every parked request at once (every session, or with `-a <app>` only that app's)"),
            ("--session", "also remember the host:port for this live session, so it is not re-asked"),
            ("--save", "also persist an allow rule per answered host (scope below; by id or in bulk with --all)"),
            ("-l, --local", "with --save: write the project .ops.toml (the default; with --all, drains only this project)"),
            ("-g, --global", "with --save: write the global ops.toml"),
            ("-a, --app <name>", "scope to an app: with `<id>` assert the id is that app's session; with `--all` limit the drain to it; with `--save` write under its `[app.<name>.network]`"),
        ],
        details:
            "Unblocks the parked request — and every identical retry of the same URL — letting it\n\
            proceed. `--session` remembers the exact host:port for the running session (it is not\n\
            re-asked); `--save` persists an allow rule so the host is pre-decided next launch. The\n\
            unblock sticks even if a save fails. The two combine; the id addresses one live session's\n\
            destination.\n\
            \n\
            `--all` instead drains every request parked across every reachable session at once — or,\n\
            with `-a <app>`, only that app's session(s). A point-in-time bulk allow (one parked after\n\
            the drain still waits), reported per session so a cross-agent grant is visible. It composes\n\
            with `--session`, and with `--save`: `--all --save` (default `--local`) drains only the\n\
            *current project's* sessions and saves each host to the project config — never machine-wide,\n\
            so one project's requests can never land in another's config; `--all --save --global` drains\n\
            across sessions and saves to the global config. A `--local` save pre-flights the trust gate\n\
            before the (irreversible) drain.",
    },
    Page {
        path: &["net", "pending", "deny"],
        synopsis: "ops net pending deny <id> [-a <app>] [--session] [--save [-l|-g]] | ops net pending deny --all [-a <app>] [--session] [--save [-l|-g]]",
        summary: "deny a parked egress request (optionally remembering or saving a rule)",
        options: &[
            ("<id>", "the `<pid>.<seq>` id from `ops net pending` or the launch notice"),
            ("--all", "deny every parked request at once (every session, or with `-a <app>` only that app's)"),
            ("--session", "also remember the host:port as denied for this live session, so it is not re-asked"),
            ("--save", "also persist a deny rule per answered host (scope below; by id or in bulk with --all)"),
            ("-l, --local", "with --save: write the project .ops.toml (the default; with --all, drains only this project)"),
            ("-g, --global", "with --save: write the global ops.toml"),
            ("-a, --app <name>", "scope to an app: with `<id>` assert the id is that app's session; with `--all` limit the drain to it; with `--save` write under its `[app.<name>.network]`"),
        ],
        details:
            "Refuses the parked request — and every identical retry of the same URL — (the proxy\n\
            returns a 403 to the cage). `--session` remembers the host:port as denied for the running\n\
            session (it is not re-asked); `--save` persists a deny rule so the host is auto-denied\n\
            next launch. The answer sticks even if a save fails.\n\
            \n\
            `--all` instead drains every request parked across every reachable session at once — or,\n\
            with `-a <app>`, only that app's session(s). A point-in-time bulk deny (one parked after\n\
            the drain still waits), reported per session. It composes with `--session`, and with\n\
            `--save`: `--all --save` (default `--local`) drains only the *current project's* sessions\n\
            and saves each host to the project config; `--all --save --global` drains across sessions\n\
            and saves to the global config. A `--local` save pre-flights the trust gate before the\n\
            (irreversible) drain.",
    },
    Page {
        path: &["net", "stats"],
        synopsis: "ops net stats [-a|--app <name>] [--reset] [--json]",
        summary: "per-host egress decision counters (allow / deny / blocked)",
        options: &[
            ("-a, --app <name>", "scope to the sessions of that app, not the whole project"),
            ("--reset", "clear this project's recorded stat files instead of showing them (ended sessions; a live session's counters reappear on its next request)"),
            ("--json", "emit the counters as JSON"),
        ],
        details:
            "Reports, per destination host, how many requests this project's launches allowed,\n\
            denied by a rule (or an `ask` decision), or had blocked by a security guard — SSRF, an\n\
            outbound-secret tripwire, or a domain-fronting host mismatch. Each request is counted\n\
            once. Counters accrue while a filtering posture (allowlist / ask) runs and persist after\n\
            the session; they are owner-only under the data dir. Transport/protocol failures (DNS, an\n\
            unreachable upstream, a malformed request) are not a policy verdict and are not counted.\n\
            Recording is on by default; a trusted `[network] stats = false` turns it off. Host-side\n\
            and read-only — no launch, no nix, no network.",
    },
    Page {
        path: &["net", "logs"],
        synopsis: "ops net logs [-a|--app <name>] [--host <h>] [--verdict allow|deny|blocked|error] \
                   [-n <N>] [--with-query] [--with-status] [-f|--follow] [-i|--interval <secs>] [--json]",
        summary: "the live, per-request egress log of a running session",
        options: &[
            ("-a, --app <name>", "scope to the sessions of that app, not the whole project"),
            ("--host <h>", "only events whose destination host is exactly <h>"),
            ("--verdict <v>", "only events with this verdict: allow, deny, blocked, or error"),
            ("-n <N>", "show only the most recent N events (per session)"),
            ("--with-query", "keep the URL query in the shown path (dropped by default; already \
                              secret-redacted)"),
            ("--with-status", "show the upstream HTTP status (200/404/…) — completed L7 requests \
                               only; `-` for an L4 splice, a refusal, or an error"),
            ("-f, --follow", "after the initial listing, keep appending new events (a `tail -f`) \
                              until Ctrl-C"),
            ("-i, --interval <secs>", "the `--follow` poll interval in seconds (default 1)"),
            ("--json", "emit the events as JSON (one object per line under `--follow`)"),
        ],
        details:
            "A chronological, per-request record of every egress decision the proxy made this\n\
            session — the session id (the PID `ops ls` shows), the local `hh:mm:ss` time, host:port,\n\
            method, path, verdict, and the reason category. It is read from the same control sockets\n\
            `ops net pending` uses, and `log` is an accepted alias.\n\
            \n\
            LIVE-ONLY: the log lives in the running session's memory and is NEVER written to disk;\n\
            once the session exits, nothing remains. It shows a session while it runs (watch it\n\
            from another terminal), not after. Only a filtering posture (`allowlist`/`ask`) has a\n\
            proxy, so only those sessions have a log.\n\
            \n\
            Verdicts are a superset of `ops net stats`: allow, deny, blocked (a security/protocol\n\
            guard), and `error` — a request that was allowed but did not complete (DNS failure, an\n\
            unreachable host, a rejected certificate). `error` is diagnostic and is NOT one of the\n\
            stats counters, so the log's lines do not reconcile with `ops net stats` totals.\n\
            \n\
            `--with-status` adds the upstream HTTP status (200/404/5xx) the server answered — for a\n\
            completed L7 (inspected `https://`) request only; an L4 (`tcp://`) splice, a refusal, or\n\
            an error shows `-` (no HTTP response to read). This is the server's answer to a delivered\n\
            request, distinct from the egress verdict: an allowed request can still get a 404. Under\n\
            `--follow --with-status`, an event whose response has not yet returned first appears with\n\
            no status, then reappears once — carrying its status — when the response lands (a live\n\
            `tail` cannot un-print a line, so the status arrives as a follow-up); the one-shot\n\
            listing shows each event's status directly.\n\
            \n\
            The URL query is dropped from the shown path by default (a token can ride in a query);\n\
            `--with-query` keeps it — already redacted, since the proxy masks configured secret\n\
            values before an event enters the log.\n\
            \n\
            `--follow` prints the current listing, then appends new events as they happen (a\n\
            `tail -f`) until Ctrl-C, polling every `--interval` seconds (default 1). If the ring\n\
            overflowed between polls the dropped count is announced, never silently skipped; a\n\
            session that ends is noted. The append shape is pipe-friendly, and `--json` streams one\n\
            event object per line. Host-side and read-only — no launch, no nix, no network.",
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

/// Render a command's page to a string for a no-subcommand usage error — the caller writes it to
/// stderr and exits non-zero, the way bare `ops` writes [`top_level_usage`]. The page lists the
/// command's subcommands, so `ops config` reveals `show`/`get`/… instead of silently acting. An
/// unknown path (only an internal caller can pass one) yields `None`. Color is decided for stderr.
pub fn page_usage(path: &[&str]) -> Option<String> {
    find(path).map(|page| render(page, &Palette::for_stream(std::io::stderr().is_terminal())))
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
