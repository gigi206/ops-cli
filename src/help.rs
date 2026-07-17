//! `sbx --help` / `sbx help <command> [subcommand...]` — the usage surface.
//!
//! One table of [`Page`]s is the single source of truth: every top-level command
//! *and* every subcommand has a page carrying its argument grammar (`synopsis`),
//! one-line summary, option list, and prose. The top-level listing, each page, and
//! the handlers' own argument-error paths (which print [`synopsis`]) all render from
//! it, so help text and error text cannot drift.
//!
//! Help is dispatched centrally: [`maybe_help`] resolves the deepest command path a
//! `--help`/`-h` flag asks about, so `sbx plugins store add --help` shows that exact
//! page. The top-level command list and each subcommand listing are both sorted
//! alphabetically.
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

/// Every command and subcommand. Entries may be declared in any order — the renderer sorts
/// both the top-level command list and each subcommand listing alphabetically.
const PAGES: &[Page] = &[
    // ---- top-level commands -------------------------------------------------------
    Page {
        path: &["doctor"],
        synopsis: "sbx doctor",
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
        synopsis: "sbx shell [override flags]",
        summary: "open an interactive sandboxed shell in the current project",
        options: &[
            (
                "--config <toml|@file>",
                "one-shot config override for this launch: inline TOML (or @file) shaped like an \
                 sbx.toml; repeatable, later wins",
            ),
            (
                "--env / --net / --gui / --nixpkgs / --bind / --forward / --limit / --package / \
                 --seccomp / --device / --gpu / --audio / --dbus",
                "typed one-shot overrides for a single field each; see `sbx help run`",
            ),
        ],
        details:
            "Launches an interactive shell inside the project sandbox, with job control and a\n\
            synthetic identity. The project's trusted config drives the environment; the\n\
            host home and the rest of the host filesystem are absent (confidentiality by\n\
            absence).\n\n\
            A one-shot override (`--config` or the typed flags, and their `SBX_*` environment\n\
            equivalents) is the final word for this launch — see `sbx help run` for the rules.",
    },
    Page {
        path: &["run"],
        synopsis: "sbx run [--detach] [override flags] [--] <command> [args...]",
        summary: "run a command inside the project sandbox",
        options: &[
            (
                "--detach",
                "run in the background as a session `sbx session ls` can see",
            ),
            (
                "--config <toml|@file>",
                "one-shot config override: inline TOML (or @file) shaped like an sbx.toml, setting \
                 any field; repeatable, later wins",
            ),
            (
                "--env KEY=VALUE",
                "one-shot override of a single cage environment variable; repeatable",
            ),
            (
                "--net <posture>",
                "one-shot network posture: none | shared | ask | allow=h1,h2 | deny=h1,h2",
            ),
            ("--gui <none|wayland>", "one-shot display posture"),
            ("--nixpkgs <ref>", "one-shot nixpkgs channel or revision"),
            (
                "--bind <path[:ro|:rw]>",
                "one-shot host bind (read-only by default); repeatable",
            ),
            (
                "--forward <port[,port…]>",
                "one-shot host loopback forward port(s) into the cage (e.g. 1455 for an OAuth \
                 callback, or 1455,8080); repeatable, unions with the config",
            ),
            (
                "--limit <key>=<value>",
                "one-shot cgroup limit: memory_high | memory_max | tasks_max; repeatable",
            ),
            (
                "--package <name>=<backend:locator>",
                "one-shot package (e.g. hello=nix:hello); repeatable",
            ),
            (
                "--seccomp <token[,token…]>",
                "one-shot relaxation of the syscall denylist (e.g. ptrace, clone:newuser); repeatable",
            ),
            (
                "--device <path>",
                "one-shot host device grant, one path per flag (e.g. /dev/kvm); repeatable",
            ),
            (
                "--gpu[=true|false]",
                "one-shot GPU posture (bare --gpu means true); --gpu=false disables it",
            ),
            (
                "--audio[=true|false]",
                "one-shot audio posture (bare --audio means true); --audio=false disables it",
            ),
            (
                "--dbus[=true|false]",
                "one-shot in-cage desktop portal (bare --dbus means true)",
            ),
            ("--", "end sbx's own flags; everything after runs literally"),
        ],
        details:
            "Runs <command> inside the project sandbox and propagates its exit status. A `--`\n\
            separates sbx's flags from the command's, so `sbx run -- --detach` runs the\n\
            literal `--detach`.\n\n\
            One-shot overrides let you change any configuration field for a single launch without\n\
            editing a file. The whole-schema `--config` takes inline TOML (or `@<file>`) shaped\n\
            exactly like an `sbx.toml`, so it can set any field; the typed flags\n\
            `--env`/`--net`/`--gui`/`--nixpkgs`/`--bind`/`--forward`/`--limit`/`--package`/`--seccomp`/\n\
            `--device`/`--gpu`/`--audio`/`--dbus` are ergonomic shorthands for one field each. The\n\
            booleans `--gpu`/`--audio`/`--dbus` are optional-value (bare means `true`, or\n\
            `=true`/`=false`); the rest take a\n\
            value. Every flag has an environment\n\
            equivalent — `SBX_CONFIG`, `SBX_ENV_<KEY>`, `SBX_NET`, `SBX_GUI`, `SBX_NIXPKGS`, `SBX_BIND`,\n\
            `SBX_FORWARD`, `SBX_LIMIT_<key>`, `SBX_PACKAGE_<name>`, `SBX_SECCOMP`, `SBX_DEVICE`,\n\
            `SBX_GPU`, `SBX_AUDIO`, `SBX_DBUS`.\n\
            Precedence, lowest to highest:\n\
            `SBX_CONFIG < SBX_* typed < --config < --* typed` — the command line always beats the\n\
            environment, and a typed flag beats the blob. Scalars\n\
            (`net`/`gui`/`nixpkgs`/`gpu`/`audio`/`dbus`)\n\
            replace;\n\
            collections (`env`/`bind`/`forward`/`limit`/`package`/`seccomp`/`device`) union. An override\n\
            is the final word: it beats a trusted project config and an app's own posture — including\n\
            `--seccomp`/`--device`, which relax the denylist and grant a device a config file gates\n\
            trusted-only (the invoker outranks any config layer, so it may set exactly what a trusted\n\
            config already can — note `--seccomp` widens the in-cage kernel attack surface, so an\n\
            ambient `SBX_SECCOMP` is worth checking). A malformed override is a hard error (it never\n\
            silently launches a different posture); a security field set from the environment prints a\n\
            notice.",
    },
    Page {
        path: &["mise"],
        synopsis: "sbx mise <args...>",
        summary: "run the in-cage mise to self-equip a project's toolchain",
        options: &[],
        details:
            "Passes its arguments through to the mise that runs inside the cage, so an agent\n\
            can self-equip a project's tools into the project's own store, e.g.\n\
            `sbx mise install nix:jq` or `sbx mise use -g aqua:BurntSushi/ripgrep`.\n\
            For mise's own help, run `sbx mise help`.",
    },
    Page {
        path: &["app"],
        synopsis: "sbx app <name> [--detach] [--net-learn[=level] [-g|--local] [--dry-run]] \
                   [override flags] [-- <args>...]",
        summary: "launch or manage named application profiles",
        options: &[
            (
                "--detach",
                "launch the app in the background as a session `sbx session ls` can see",
            ),
            (
                "--net-learn[=domain|path|exact]",
                "run under the app's real posture, then add the egress rules it was refused for \
                 lack of one to the app's profile (default level `domain`)",
            ),
            (
                "-g, --global / -l, --local",
                "with --net-learn, write the learned rules to the global app profile / the project \
                 config (default local)",
            ),
            (
                "--dry-run",
                "with --net-learn, print the rules that would be added without writing them",
            ),
            (
                "--config <toml|@file>",
                "one-shot config override for this launch, beating the app's own posture; \
                 repeatable (see `sbx help run`)",
            ),
            (
                "--env / --net / --gui / --nixpkgs / --bind / --forward / --limit / --package / \
                 --seccomp / --device / --gpu / --audio / --dbus",
                "typed one-shot overrides for a single field each, beating the app's posture; \
                 see `sbx help run`",
            ),
        ],
        details:
            "`sbx app <name>` launches a named application profile (a project [app.<name>] overlay,\n\
            or an imported apps/<name>.toml profile — a global app lives as a profile file, not\n\
            inline in sbx.toml) inside the project sandbox, each with its own persistent isolated\n\
            home.\n\n\
            Arguments after a `--` are appended to the app's declared command, so you can pass a\n\
            flag to the launched program without editing the profile — e.g. `sbx app claude-code\n\
            -- -c` runs the profile's `claude` command with `-c` (resume the previous session).\n\
            They are ordinary launch-time arguments; the app's posture (network, binds, secrets,\n\
            home) is fixed by the profile and unchanged.\n\n\
            A one-shot override (`--config` or a typed flag, and their `SBX_*` environment\n\
            equivalents) is applied *after* the app's overlay, so it is the final word — e.g.\n\
            `sbx app claude-code --net none` cuts the app's network for one run. Note that\n\
            overriding an app's network drops its read-by-default verb filter (an override posture is\n\
            all-verbs, like a Mode-A launch); scope it with `{GET,HEAD}` rules in a `--config`\n\
            `[network]` if you need to keep it. See `sbx help run` for the full precedence rules.\n\n\
            `--net-learn` discovers an app's egress needs: it runs the app under its own (unchanged)\n\
            posture — nothing is opened, so a request the allowlist refuses stays refused — and turns\n\
            each such refusal into the allow rule that would have admitted it, writing them to the\n\
            app's profile (or, with `--dry-run`, only printing them). It needs a filtering posture\n\
            (mode allow/deny/ask); a `shared`/`none` app logs no egress to learn from. Only a\n\
            plain \"not allowed yet\" refusal is learned — a deliberate `deny` rule and a security\n\
            block (SSRF, host-mismatch, an outbound secret) are never turned into a rule. Run it\n\
            again after adding rules to catch a host only reachable once an earlier one is allowed.\n\
            The level sets how wide each rule is: `domain` opens the whole host (`{*} https://host`),\n\
            `path` its first path section (`{*} https://host/v1/*`), `exact` the one endpoint\n\
            (`{POST} https://host/v1/chat`). It is foreground-only (not with `--detach`).\n\n\
            The rules land in the project config by default (`--local`), or in the app's global\n\
            profile with `-g` — which, for an app defined only inline in a project sbx.toml, writes a\n\
            partial apps/<name>.toml the inline table then shadows on load; prefer `-g` for an app\n\
            that is already an imported profile.",
    },
    Page {
        path: &["search"],
        synopsis: "sbx search <query>",
        summary: "discover the nix: tools a project can declare, via nixhub",
        options: &[],
        details: "Queries nixhub for tools to declare. A fuzzy query lists matches; a query that\n\
            names a package exactly leads with that package's versions and the lines to\n\
            declare it in `[tools]` or `[packages]`. Host-side and read-only — it resolves\n\
            nothing into the sandbox and needs no trust.",
    },
    Page {
        path: &["test"],
        synopsis: "sbx test <subcommand> <target>",
        summary: "check whether an access would be allowed, and why",
        options: &[],
        details:
            "A diagnostic surface meant to grow with sbx's access controls. No launch, no nix,\n\
            no network — it reports a verdict against the resolved policy.",
    },
    Page {
        path: &["net"],
        synopsis: "sbx net <subcommand> [args...]",
        summary: "inspect the egress policy, its rules, and parked `ask` requests",
        options: &[],
        details:
            "The egress-policy surface. `rules` lists the effective allow/deny rules by source;\n\
            `groups` lists the reusable `[net.groups]` egress groups (referenced by `@<name>`) and\n\
            resolves one to its entries; `allow`/`deny <rule>` persist a rule to config, and\n\
            `mute`/`unmute <rule>` add/remove a log-suppression (`dontaudit`) rule; `pending`\n\
            lists and answers requests parked by the `ask` posture; `stats` reports the per-host\n\
            allow/deny/blocked decision counters launches recorded; `logs` is the live, per-request\n\
            egress log of a running session; and `live` is a `top`-style view of the egress tunnels\n\
            currently open. Host-side — no launch, no nix. (Distinct from `sbx test net <url>`, which\n\
            tests one URL against the policy.)",
    },
    Page {
        path: &["plugins"],
        synopsis: "sbx plugins <subcommand> [args...]",
        summary: "inspect and manage resolver plugins and plugin stores",
        options: &[],
        details:
            "Host-level — reads the data directory, not a project's config. A resolver plugin\n\
            declares a `scheme://` sbx can route a secret `from` reference to.",
    },
    Page {
        path: &["session"],
        synopsis: "sbx session <subcommand> [args...]",
        summary: "inspect and control the live sandbox sessions",
        options: &[],
        details:
            "A session is a live sandbox cage. `sbx session ls` lists them, `sbx session attach`\n\
            runs a shell or a command inside one, and `sbx session stop` ends them. Host-side —\n\
            reads the on-disk session registry (daemonless), launches nothing. `sbx sessions` is\n\
            an alias.\n\
            \n\
            Run one of the subcommands below.",
    },
    Page {
        path: &["session", "ls"],
        synopsis: "sbx session ls",
        summary: "list the live sandbox sessions",
        options: &[],
        details:
            "Lists the live sandbox sessions from the on-disk registry (daemonless). Reading\n\
            the registry re-validates and prunes dead records, so the list is always\n\
            current. An app session shows its app name, so you can tell which sessions are\n\
            agents.",
    },
    Page {
        path: &["session", "attach"],
        synopsis: "sbx session attach <id> [-- command [args...]]",
        summary: "run a shell or a command inside a running session's live cage",
        options: &[
            ("<id>", "the PID `sbx session ls` shows for the session"),
            (
                "-- command [args...]",
                "run this command in the cage instead of an interactive shell",
            ),
        ],
        details:
            "Joins the running cage the way `docker exec` does — the agent's live processes, its\n\
            real /tmp, and its network. With no command it opens an interactive shell (needs a\n\
            terminal); with `-- command` it runs that command: through a pty when stdin is a\n\
            terminal (interactive, job control), through inherited stdio when it is a pipe or\n\
            script (clean bytes, so it composes with pipes and redirection). The command's exit\n\
            status becomes sbx's. Either way it re-applies the cage's confinement — the same\n\
            seccomp denylist, no_new_privs, and dropped capabilities — so it is never a wider\n\
            hole than the agent. Provisions nothing and reads no config; needs a live session\n\
            (run `sbx session ls`). A bare shell keeps running until you type `exit`; the agent\n\
            keeps running either way.",
    },
    Page {
        path: &["session", "stop"],
        synopsis: "sbx session stop <id>...|--all [--delay <secs>]",
        summary: "stop running sessions",
        options: &[
            (
                "<id>...",
                "the PIDs `sbx session ls` shows for the sessions to stop",
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
        synopsis: "sbx trust [path] | sbx trust --show [path]",
        summary: "vouch for a project config's current contents",
        options: &[
            ("[path]", "the config to act on (default ./.sbx.toml)"),
            ("--show", "report the trust state without changing it"),
        ],
        details: "Vouches for a config's current contents, so its security-relevant fields are\n\
            honored until the file changes again. Trust is bound to the file's contents, so\n\
            any edit re-arms the gate.",
    },
    Page {
        path: &["untrust"],
        synopsis: "sbx untrust [path]",
        summary: "revoke a project config's trust",
        options: &[("[path]", "the config to act on (default ./.sbx.toml)")],
        details:
            "Revokes a config's trust, so its security-relevant fields stop applying until it\n\
            is trusted again.",
    },
    Page {
        path: &["config"],
        synopsis: "sbx config <subcommand>",
        summary: "inspect and edit the project configuration",
        options: &[],
        details:
            "Inspect or edit the configuration for the current project. `sbx config show` prints\n\
            the resolved, trust-gated view a launch would use (add --json for the machine-readable\n\
            model); get/set/unset read and edit a single raw layer file; path prints which file a\n\
            scope targets; and edit opens it in your editor.\n\
            \n\
            Run `sbx config show` for the resolved configuration, or one of the subcommands below.",
    },
    Page {
        path: &["config", "get"],
        synopsis: "sbx config get <key> [-l|--local|-g|--global|-c <file>] [-a|--app <name>]",
        summary: "read a value from a single config file",
        options: &[
            ("<key>", "a dotted key, e.g. env.FOO or nixpkgs"),
            ("-l, --local", "the project .sbx.toml (the default)"),
            ("-g, --global", "the global sbx.toml"),
            ("-c <file>", "an explicit config file"),
            (
                "-a, --app <name>",
                "address the key under that app (app.<name>.<key> inline, or -g reads its profile)",
            ),
        ],
        details:
            "Prints the value declared at a dotted key in one layer file. This is the raw declared\n\
            value in that file — for the effective resolved value across layers, use `sbx config\n\
            show` (or `sbx config show --json`). An unset key exits 1; an array or table value is\n\
            edited with `sbx config edit`, not read as a single value.\n\
            \n\
            --app <name> addresses an app's config: inline (a project .sbx.toml) it reads\n\
            app.<name>.<key>; with -g it reads the top-level key from the app's profile file\n\
            (apps/<name>.toml). An app name containing a `.` is edited with `sbx config edit`\n\
            instead.",
    },
    Page {
        path: &["config", "set"],
        synopsis: "sbx config set <key> <value> [-l|--local|-g|--global|-c <file>] [-a|--app <name>] [--trust]",
        summary: "set a value in a config file (comments preserved)",
        options: &[
            ("<key>", "a dotted key, e.g. env.FOO or network"),
            ("<value>", "the string value to set"),
            ("-l, --local", "the project .sbx.toml (the default)"),
            ("-g, --global", "the global sbx.toml"),
            ("-c <file>", "an explicit config file"),
            (
                "-a, --app <name>",
                "address the key under that app (app.<name>.<key> inline, or -g writes its profile)",
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
            --app <name> addresses an app's config: inline (a project .sbx.toml) it writes\n\
            app.<name>.<key>; with -g it writes the top-level key into the app's profile file\n\
            (apps/<name>.toml, created if absent). So `set network ask --app demo -g` sets a\n\
            global app's posture, and `set network.mode ask --app demo -g` tunes its table. An\n\
            app name containing a `.` is edited with `sbx config edit` instead.\n\
            \n\
            The trust gate hashes the whole file, so any edit re-arms it: after writing a project\n\
            file you had trusted, its security fields stop applying until you run `sbx trust`. Pass\n\
            --trust to re-trust in one step (this blesses the whole current file). The global config\n\
            and app profiles are trusted by location, so a write to either needs no trust. A free\n\
            env value needs no trust. Array and table fields (binds, an allowlist, secrets, apps)\n\
            are edited with `sbx config edit`.",
    },
    Page {
        path: &["config", "unset"],
        synopsis: "sbx config unset <key> [-l|--local|-g|--global|-c <file>] [-a|--app <name>] [--trust]",
        summary: "remove a key from a config file",
        options: &[
            ("<key>", "a dotted key to remove, e.g. env.FOO"),
            ("-l, --local", "the project .sbx.toml (the default)"),
            ("-g, --global", "the global sbx.toml"),
            ("-c <file>", "an explicit config file"),
            (
                "-a, --app <name>",
                "address the key under that app (app.<name>.<key> inline, or -g edits its profile)",
            ),
            ("--trust", "re-trust the file after writing"),
        ],
        details:
            "Removes a dotted key from one layer file. Removing a key that is not set changes\n\
            nothing (and so never re-arms trust). A removal that does change a trusted project\n\
            file re-arms its trust gate, the same as `set` (the global config and app profiles\n\
            are trusted by location, so a removal there needs no re-trust).\n\
            \n\
            --app <name> addresses an app's config: inline (a project .sbx.toml) it removes\n\
            app.<name>.<key>; with -g it removes the top-level key from the app's profile file\n\
            (apps/<name>.toml). So `unset network.mode --app demo -g` drops a global app's mode,\n\
            leaving a table that inherits it from the parent layer. An app name containing a `.`\n\
            is edited with `sbx config edit` instead.",
    },
    Page {
        path: &["config", "path"],
        synopsis: "sbx config path [-l|--local|-g|--global|-c <file>]",
        summary: "show the config files in resolution order, or one scope's path",
        options: &[
            ("(no flag)", "list every config layer in resolution order, marking which exist"),
            ("-l, --local", "print only the project .sbx.toml path"),
            ("-g, --global", "print only the global sbx.toml path"),
            ("-c <file>", "print only this explicit config file path"),
        ],
        details:
            "With no scope flag, lists the config files a launch resolves — the global sbx.toml\n\
            (the base) then the project .sbx.toml (which overlays it) — and whether each exists,\n\
            so it is clear where sbx looks even before any file is created. With a scope flag,\n\
            prints just that file's path (the one get/set/unset/edit would touch) — for scripting\n\
            and for locating the global config. For resolved values, see `sbx config show`.",
    },
    Page {
        path: &["config", "edit"],
        synopsis: "sbx config edit [-l|--local|-g|--global|-c <file>] [--trust]",
        summary: "open a config file in your editor",
        options: &[
            ("-l, --local", "the project .sbx.toml (the default)"),
            ("-g, --global", "the global sbx.toml"),
            ("-c <file>", "an explicit config file"),
            ("--trust", "re-trust the file after editing"),
        ],
        details:
            "Opens the target file in $VISUAL or $EDITOR (falling back to vi) — the way to edit\n\
            fields `set` does not handle as a single value, such as binds, an allowlist, secrets,\n\
            or app tables. A `binds` entry is an absolute host path, bound read-only by default;\n\
            write it as a table `{ path = \"/abs/path\", mode = \"rw\" }` to bind it read-write\n\
            (the cage writes through to the host path). A leading `~`, `$HOME`, or\n\
            `$XDG_RUNTIME_DIR` is expanded from your environment, so a portable config need not\n\
            hard-code an absolute home path; any other `$VAR` is refused. `binds` is a security\n\
            field, honored only\n\
            from a trusted source. sbx's own state (its data, trust, and config directories) is\n\
            protected either way: a read-write bind aimed at or inside one of them is forced\n\
            read-only with a warning, while a broad read-write bind that merely contains them (e.g.\n\
            `mode = \"rw\"` on your whole home) stays read-write with those directories pinned\n\
            read-only in place — so the rest of the tree is writable but the agent still cannot\n\
            alter what sbx runs or trusts.\n\
            An edit that changes a file you had trusted re-arms its trust gate, so it warns to\n\
            re-run `sbx trust`; pass --trust to re-trust as the editor closes.",
    },
    Page {
        path: &["config", "show"],
        synopsis: "sbx config show [--json] [--details] [-a|--app <name>] [-g|--global|-l|--local|-d|--default]",
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
            ("-l, --local", "show only what the project .sbx.toml contributes"),
            ("-d, --default", "show the built-in defaults alone (no config)"),
        ],
        details:
            "Shows the resolved configuration for the current project — the layered global and\n\
            project environment, binds, packages, tools, network, GUI, secrets, resource\n\
            limits, the seccomp relaxation, the host device grant, and app profiles, after the\n\
            trust gate has dropped\n\
            anything an untrusted project may not set. Each value is tagged with where it came\n\
            from — (default), (global), or\n\
            (project), colored by level. Warnings explain what was dropped and why. No launch,\n\
            no nix, no network.\n\
            \n\
            A single-source flag restricts the view to one layer (over the built-in defaults),\n\
            so the provenance tags read as that layer's own additions: --global shows what the\n\
            global config plus any imported app profiles set (the project is ignored), --local\n\
            what the project .sbx.toml sets (the global config and profiles ignored), and\n\
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
            source — so what `sbx app <name>` adds, can reach, and injects is visible at a glance.\n\
            An env value is the in-cage placeholder, a free field; the credential value is never\n\
            shown — sbx reads it host-side at launch.\n\
            \n\
            With --json, the same resolved model is printed as a JSON document (warnings\n\
            included as a field) — the machine-readable form the human output renders, already\n\
            carrying every app's env, binds, packages, rules, and injected credentials in full.",
    },
    Page {
        path: &["upgrade"],
        synopsis: "sbx upgrade [all|nix|mise|flake|deb|appimage]",
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
            ("deb", "the project's and apps' deb: packages"),
            ("appimage", "the project's and apps' appimage: packages"),
        ],
        details: "Rolls managed channels forward by re-resolving and rewriting their locks, so\n\
            versions advance only here, never on an sbx binary update.",
    },
    Page {
        path: &["gc"],
        synopsis: "sbx gc [--all] [--prune]",
        summary: "reclaim sbx's nix store space",
        options: &[
            (
                "--all",
                "also collect the shared store across every project (orphaned closures)",
            ),
            (
                "--prune",
                "actually reclaim (default is a dry run that touches nothing)",
            ),
        ],
        details:
            "By default it sweeps the current project's store. Reclamation is irreversible, so\n\
            the destructive form is opt-in.\n\
            \n\
            `--all` additionally collects the shared store — the closures no live project or\n\
            locked channel revision still roots — under an exclusive lock.\n\
            \n\
            Removing whole per-project runtime *trees* (a project whose directory is gone, or a\n\
            markerless legacy tree) is `sbx projects rm` — see `sbx help projects`. After a tree\n\
            is removed, its store closures are reclaimed by `sbx gc --all --prune`, or in one step\n\
            with `sbx projects rm <id> --gc`.",
    },
    Page {
        path: &["projects"],
        synopsis: "sbx projects list [--json]\n       \
                   sbx projects rm <id>... [--dead] [--markerless] [-n] [-y] [--gc] [-f]",
        summary: "list and remove per-project runtime trees",
        options: &[
            (
                "list",
                "list every runtime tree with its state, size, and last-used date",
            ),
            ("--json", "with list, emit the trees as a JSON document"),
            (
                "rm <id>...",
                "remove one or more named trees; the id is what `sbx projects list` shows. Immediate —\n\
                 naming it is consent. A live-held tree is refused (run `sbx session stop` first); the\n\
                 current project is refused without --force.",
            ),
            (
                "--dead",
                "with rm, sweep every tree whose project directory is gone (dry run unless --yes)",
            ),
            (
                "--markerless",
                "with rm, also sweep markerless legacy trees, no deadness proof (needs --yes)",
            ),
            ("-n, --dry-run", "preview a targeted rm instead of removing"),
            (
                "-y, --yes",
                "apply a --dead / --markerless sweep (they preview by default)",
            ),
            (
                "--gc",
                "after a real removal, collect the shared store's now-orphaned closures",
            ),
            ("-f, --force", "allow removing the current project's own tree"),
        ],
        details:
            "The per-project runtime trees live under `<data>/projects/<id>` and hold each\n\
            project's writable store, isolated home, and locks. `sbx projects list` lists them\n\
            (richer than `sbx path`'s projects section — it adds each tree's on-disk size); `sbx\n\
            projects rm` removes them.\n\
            \n\
            A named `rm <id>` removes immediately (you named it, so it is not an accident); pass\n\
            `--dry-run` to preview first. The bulk selectors `--dead` and `--markerless` preview\n\
            by default and require `--yes` to apply, since they act on more than one tree. A tree\n\
            a live session holds is always refused — stop it with `sbx session stop` first — and the\n\
            current project is refused without `--force`.\n\
            \n\
            Removing a tree is host-side only and leaves its store closures for `sbx gc` to\n\
            reclaim; `--gc` runs that shared-store collection in the same command.",
    },
    Page {
        path: &["path"],
        synopsis: "sbx path [--json]",
        summary: "show every directory sbx uses on disk, grouped by XDG base",
        options: &[
            ("--json", "emit the layout as a JSON document for scripting"),
        ],
        details:
            "Lists the on-disk locations sbx owns — the data, config, and state trees — and\n\
            marks which exist, so it is clear where sbx puts things even before any file is\n\
            created. Under `projects/` it enumerates each project's runtime tree and annotates it\n\
            with a liveness state — `live` (a running session holds it), `idle` (the project\n\
            directory still exists, just not active), `dead` (the project is gone — removable\n\
            by `sbx projects rm --dead`), or `markerless` (a legacy tree pre-dating marker\n\
            recording) — plus the last-used date, and (via `sbx projects list`) its size. Under `apps/`\n\
            it lists each global app home, and under the config\n\
            `apps/` each imported profile. Read-only: no trust gate, no network. For the config\n\
            files in resolution order, see `sbx config path`.",
    },
    // ---- app subcommands ----------------------------------------------------------
    Page {
        path: &["app", "import"],
        synopsis: "sbx app import <file> [--as <name>] [--force]",
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
            profile stays inert until `sbx app <name>` launches it. The granted posture is\n\
            printed so the act is informed. The bytes are copied verbatim.",
    },
    Page {
        path: &["app", "export"],
        synopsis: "sbx app export <name> [--out <file>]",
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
        synopsis: "sbx app rm <name> [--purge] [--gc]",
        summary: "remove an imported profile (and, with --purge, the app's home + tools)",
        options: &[
            ("<name>", "the app to remove"),
            (
                "--purge",
                "also remove the app's isolated home(s): its mise tools, config, and login state",
            ),
            (
                "--gc",
                "after --purge, sweep the current project's nix store (requires --purge)",
            ),
        ],
        details: "Without --purge, removes only an imported profile (a file in the profiles\n\
            directory); a project [app.<name>] overlay lives in that project's .sbx.toml and is\n\
            yours to edit there. With --purge it also removes the app's per-app home(s) — the\n\
            global one and any per-project ones — which hold the tools its mise: backends\n\
            installed, its config, and its login state; those are freed immediately. A missing\n\
            profile is tolerated under --purge (the homes may still exist). The shared per-project\n\
            nix store is not touched by --purge alone: add --gc to sweep the current project's\n\
            store in the same command (equivalent to `sbx gc --prune` there), or run that yourself\n\
            in each project the app used to reclaim its nix:/flake: closures. A purge refuses while\n\
            a session of the app is still running.",
    },
    Page {
        path: &["app", "list"],
        synopsis: "sbx app list  (alias: sbx app ls)",
        summary: "list apps with their profile and installed home",
        options: &[],
        details:
            "One row per app: whether it has an imported profile (the `import`/`rm` artifact) and\n\
            whether it has an installed home on disk (its mise tools + login state, with disk size)\n\
            — which `sbx app rm <name> --purge` removes. An app can have a profile with no home yet\n\
            (never launched), or a home with no profile (launched from an inline/project app, or a\n\
            profile since removed). `sbx app ls` is the same command. The full resolved app set —\n\
            inline, project, and profile apps with their gating — is `sbx config show`.",
    },
    // ---- test subcommands ---------------------------------------------------------
    Page {
        path: &["test", "net"],
        synopsis: "sbx test net [--app <name>] [-X|--method <verb>] <url|tcp://host:port>",
        summary: "test a URL (or an http:///tcp:// target) against the resolved network policy",
        options: &[
            ("<url>", "the URL (or a bare host, completed to https) to test. `http://host` tests the inspected-cleartext path (opt-in — only an `http://` rule opens it); `tcp://host:port` tests a raw L4 splice instead"),
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
        synopsis: "sbx net rules [-a|--app <name>] [-s|--source config|builtin|session] [-f|--filter <substr>] [-e|--expand] [--json]",
        summary: "list the effective egress rules by source",
        options: &[
            (
                "-a, --app <name>",
                "list the effective rules for that app (its `[app.<name>.network]` folded onto the baseline), not the baseline's",
            ),
            (
                "-s, --source <src>",
                "show only one source: config (the .sbx.toml/global rules), builtin (the always-allowed self-equip set), or session (live `--session` rules; `manual` is accepted as an alias)",
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
            rule names its layer: an inspected-over-TLS rule shows `https://` (a bare host is https on\n\
            443), an inspected-cleartext rule shows `http://` (default port 80), a raw L4 rule shows\n\
            `tcp://`; a `re:` regex shows neither (its pattern carries its own).\n\
            A rule that came from a `[net.groups]` group shows as a single `@<name>` reference;\n\
            `--expand` unfolds it to its hosts, each noting its `@<group>` origin (resolve one\n\
            directly with `sbx net groups <name>`). Under `shared`/`none` there are no rules. `--app\n\
            <name>` shows what `sbx app <name>` would launch with — the same effective policy `sbx\n\
            test net --app` tests a URL against. `--source session` instead queries the live sessions\n\
            for the rules loaded into their overlay with `sbx net allow|deny --session` (or a `net\n\
            pending … --session` answer) — this project's sessions by default, or `-a <app>`'s\n\
            session(s). No launch, no nix.",
    },
    Page {
        path: &["net", "groups"],
        synopsis: "sbx net groups [<name>…] [--json] | sbx net groups export|import …",
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
            command has no scope flag — it always reads the global config. `sbx net groups` lists the\n\
            groups; `sbx net groups <name>` shows what `@<name>` expands to; `export`/`import` move\n\
            groups between machines. A malformed or nested entry is flagged. Add a reference with\n\
            `sbx net allow @<name>`. Read-only (except `import`), no launch.",
    },
    Page {
        path: &["net", "groups", "export"],
        synopsis: "sbx net groups export [<name>…] [-o|--out <file>]",
        summary: "write egress groups as a portable [net.groups] fragment",
        options: &[
            ("<name>…", "export only the named group(s) (default: every group)"),
            ("-o, --out <file>", "write to <file> instead of stdout"),
        ],
        details:
            "Emits the reusable egress groups as a portable `[net.groups]` TOML fragment — to stdout\n\
            by default (`sbx net groups export > groups.toml`), or to `--out <file>`. The inverse of\n\
            `import`. Source comments are not carried (a group is data). Read-only, no launch.",
    },
    Page {
        path: &["net", "groups", "import"],
        synopsis: "sbx net groups import <file> [-f|--force]",
        summary: "merge a [net.groups] fragment into the global config",
        options: &[
            ("<file>", "a `[net.groups]` fragment (e.g. from `sbx net groups export`)"),
            ("-f, --force", "overwrite a group whose name already exists (default: refuse)"),
        ],
        details:
            "Merges the fragment's groups into the global config, preserving every existing group and\n\
            comment (`toml_edit`). Groups are global-only, so the target is always the global config,\n\
            which is trusted by location — the deliberate command is the consent (an agent in the cage\n\
            cannot run it), so there is no prompt. A name that already exists is refused unless\n\
            `--force`; the merge is all-or-nothing. A group carrying an entry that will not resolve (a\n\
            malformed or nested one) is flagged after the import — inspect it with `sbx net groups\n\
            <name>`. Imported groups are inert until referenced by a `[network]` allow/deny with\n\
            `@<name>`.",
    },
    Page {
        path: &["net", "allow"],
        synopsis: "sbx net allow <rule> [-l|--local|-g|--global] [-a|--app <name>] [--session [--all]]",
        summary: "persist an allow rule to a config file (or load it live with --session)",
        options: &[
            ("<rule>", "an egress rule. A bare host (or `https://host`) is inspected over TLS on port 443; add `:port`/`:*`/`:a,b` to widen. Forms: a host, `*.domain`, `host/path`, IP, or `re:<regex>`, optionally prefixed `{GET,POST}` to scope it to those HTTP verbs. `http://host` is an inspected *cleartext* rule (plaintext, default port 80) — the same HTTP policy without TLS; opt-in, so it never carries a credential. `tcp://host:port` is a raw (uninspected) L4 tunnel — it must name a port; `tcp://host:*` opens every port and protocol. `@<group>` references a reusable `[net.groups]` group (defined in the global config), expanded to its entries at launch"),
            ("-l, --local", "write the project .sbx.toml (the default)"),
            ("-g, --global", "write the global sbx.toml"),
            ("-a, --app <name>", "write the rule under that app's `[app.<name>.network]`; with `--session`, scope the live load to that app's session(s)"),
            ("--session", "load the rule into the live overlay of the running session(s) instead of a config file (writes nothing, no re-trust); the proxy folds it into its effective policy, so it takes effect immediately on any filtering-posture session (allowlist, denylist, ask). It dies with the session. Scopes to the current project by default"),
            ("--all", "with `--session`, widen the live load to every reachable session (all projects), not just the current one"),
        ],
        details:
            "Validates the rule, then adds it. With no filtering posture yet, `allow` bootstraps a\n\
            deny-by-default allowlist. Writing the project config re-trusts it (it must be absent or\n\
            already trusted first); the global config is trusted by location.\n\
            \n\
            `--session` instead loads the rule into the **live overlay** of the running session(s), which\n\
            the proxy folds into its effective policy — so it takes effect immediately, on an allowlist\n\
            or denylist session as well as `ask` (a `--session allow` opens an otherwise-denied host, a\n\
            `--session deny` cuts an allowed one; deny wins). It is the proactive sibling of `sbx net\n\
            pending allow <id> --session`, which decides a request that already parked. It writes no\n\
            file — so, unlike a config write, it never re-trusts the project — and dies with the session.\n\
            The config-scope flags (`-l`/`-g`/`-c`) do not apply with `--session`; scope the sessions\n\
            with `-a <app>`/`--all`. Only a filtering posture runs the proxy, so a `shared`/`none`\n\
            session has nothing to load into.",
    },
    Page {
        path: &["net", "deny"],
        synopsis: "sbx net deny <rule> [-l|--local|-g|--global] [-a|--app <name>] [--session [--all]]",
        summary: "persist a deny rule to a config file (or load it live with --session)",
        options: &[
            ("<rule>", "an egress rule. A bare host (or `https://host`) is inspected over TLS on port 443; add `:port`/`:*`/`:a,b` to widen. Forms: a host, `*.domain`, `host/path`, IP, or `re:<regex>`, optionally prefixed `{GET,POST}` to scope it to those HTTP verbs. `http://host` is an inspected *cleartext* rule (plaintext, default port 80) — the same HTTP policy without TLS; opt-in, so it never carries a credential. `tcp://host:port` is a raw (uninspected) L4 tunnel — it must name a port; `tcp://host:*` opens every port and protocol. `@<group>` references a reusable `[net.groups]` group (defined in the global config), expanded to its entries at launch"),
            ("-l, --local", "write the project .sbx.toml (the default)"),
            ("-g, --global", "write the global sbx.toml"),
            ("-a, --app <name>", "write the rule under that app's `[app.<name>.network]`; with `--session`, scope the live load to that app's session(s)"),
            ("--session", "load the rule into the live overlay of the running session(s) instead of a config file (writes nothing, no re-trust); the proxy folds it into its effective policy, so it takes effect immediately on any filtering-posture session (allowlist, denylist, ask). It dies with the session. Scopes to the current project by default"),
            ("--all", "with `--session`, widen the live load to every reachable session (all projects), not just the current one"),
        ],
        details:
            "Validates the rule, then adds it (deny always wins over allow). A deny needs an existing\n\
            filtering posture — it will not open one — so set the posture first on a fresh config.\n\
            Writing the project config re-trusts it; the global config is trusted by location.\n\
            \n\
            `--session` instead loads the rule into the **live overlay** of the running session(s), which\n\
            the proxy folds into its effective policy — so a `--session deny` cuts a host immediately on\n\
            an allowlist or denylist session as well as `ask` (deny wins over any allow). It writes no\n\
            file and dies with the session. The config-scope flags (`-l`/`-g`/`-c`) do not apply with\n\
            `--session`; scope the sessions with `-a <app>`/`--all`.",
    },
    Page {
        path: &["net", "mute"],
        synopsis: "sbx net mute <rule> [-l|--local|-g|--global] [-a|--app <name>] [--session [--all]]",
        summary: "suppress a denied request's log line without changing the verdict (SELinux `dontaudit`)",
        options: &[
            ("<rule>", "an egress rule, the same grammar as `allow`/`deny` (a host, `*.domain`, `host/path`, IP, `re:<regex>`, an optional `{GET,POST}` verb prefix, or `@<group>`). It matches a *denied* request whose log line should be kept out of the default `sbx net log`"),
            ("-l, --local", "write the project .sbx.toml (the default)"),
            ("-g, --global", "write the global sbx.toml"),
            ("-a, --app <name>", "write the rule under that app's `[app.<name>.network]` (e.g. an imported profile); with `--session`, scope the live load to that app's session(s)"),
            ("--session", "load the mute into the live overlay of the running session(s) instead of a config file (writes nothing, no re-trust); it takes effect immediately and dies with the session. Scopes to the current project by default"),
            ("--all", "with `--session`, widen the live load to every reachable session (all projects)"),
        ],
        details:
            "Adds a `mute` (`dontaudit`) rule: a request matching it is still **denied** and still\n\
            **counted** in `sbx net stats` — only its line is kept out of the default `sbx net log`\n\
            (see it with `sbx net log --all`). It is a log filter, never a verdict: it cannot open\n\
            egress. Use it to quiet the refusals you have deliberately left denied (telemetry, feature\n\
            flags, an optional CDN) so the actionable ones stand out.\n\
            \n\
            A config write needs an existing filtering posture (there is nothing to suppress under\n\
            `shared`/`none`), so set one first on a fresh config; it re-trusts the project config (it\n\
            must be absent or already trusted first), while the global config and app profiles are\n\
            trusted by location. Remove a rule with `sbx net unmute`.\n\
            \n\
            `--session` instead loads the mute into the **live overlay** of the running session(s),\n\
            which the proxy folds into its effective policy — so it quiets the log immediately, on\n\
            any filtering-posture session. It writes no file (no re-trust) and dies with the session;\n\
            scope it with `-a <app>`/`--all`. A live mute is not un-loaded by `unmute` (it is a\n\
            log filter with no counter-verdict) — it simply ends with the session.",
    },
    Page {
        path: &["net", "unmute"],
        synopsis: "sbx net unmute <rule> [-l|--local|-g|--global] [-a|--app <name>]",
        summary: "remove a mute rule from a config file (the inverse of `sbx net mute`)",
        options: &[
            ("<rule>", "the mute rule to remove — an exact-string match of what was muted"),
            ("-l, --local", "edit the project .sbx.toml (the default)"),
            ("-g, --global", "edit the global sbx.toml"),
            ("-a, --app <name>", "edit that app's `[app.<name>.network]`"),
        ],
        details:
            "Removes a `mute` rule added by `sbx net mute`. Idempotent: unmuting a rule that is not\n\
            present is a reported no-op, not an error. Editing the project config re-trusts it (only\n\
            when something actually changed); the global config and app profiles are trusted by\n\
            location.",
    },
    Page {
        path: &["net", "pending"],
        synopsis:
            "sbx net pending [-a <app>] [--json] | sbx net pending allow|deny <id>|--all [-a <app>] [--save ...] | sbx net pending watch [-i <secs>]",
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
        synopsis: "sbx net pending watch [-i|--interval <secs>] [-a|--app <name>]",
        summary: "redraw the parked-request listing live until interrupted",
        options: &[
            ("-i, --interval <secs>", "seconds between refreshes (default 2)"),
            ("-a, --app <name>", "limit the listing to one app's session(s)"),
        ],
        details:
            "Polls the same live control sockets as `sbx net pending` and redraws the listing in\n\
            place every few seconds (top-style — the terminal scrollback is preserved), so a parked\n\
            request appears as soon as an agent triggers it. Answer it from another shell with\n\
            `sbx net pending allow|deny <id>`; the watch picks up the change on the next refresh.\n\
            Ctrl-C quits. Needs a terminal — for a pipe or a script use the one-shot listing (`--json`).\n\
            No launch, no nix, no network.",
    },
    Page {
        path: &["net", "pending", "allow"],
        synopsis: "sbx net pending allow <id> [-a <app>] [--session] [--save [-l|-g]] | sbx net pending allow --all [-a <app>] [--session] [--save [-l|-g]]",
        summary: "allow a parked egress request (optionally remembering or saving a rule)",
        options: &[
            ("<id>", "the `<pid>.<seq>` id from `sbx net pending` or the launch notice"),
            ("--all", "allow every parked request at once (every session, or with `-a <app>` only that app's)"),
            ("--session", "also remember the host:port for this live session, so it is not re-asked"),
            ("--save", "also persist an allow rule per answered host (scope below; by id or in bulk with --all)"),
            ("-l, --local", "with --save: write the project .sbx.toml (the default; with --all, drains only this project)"),
            ("-g, --global", "with --save: write the global sbx.toml"),
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
        synopsis: "sbx net pending deny <id> [-a <app>] [--session] [--save [-l|-g]] | sbx net pending deny --all [-a <app>] [--session] [--save [-l|-g]]",
        summary: "deny a parked egress request (optionally remembering or saving a rule)",
        options: &[
            ("<id>", "the `<pid>.<seq>` id from `sbx net pending` or the launch notice"),
            ("--all", "deny every parked request at once (every session, or with `-a <app>` only that app's)"),
            ("--session", "also remember the host:port as denied for this live session, so it is not re-asked"),
            ("--save", "also persist a deny rule per answered host (scope below; by id or in bulk with --all)"),
            ("-l, --local", "with --save: write the project .sbx.toml (the default; with --all, drains only this project)"),
            ("-g, --global", "with --save: write the global sbx.toml"),
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
        synopsis: "sbx net stats [-a|--app <name>] [--reset] [--json]",
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
            once. Counters accrue while a filtering posture (deny / allow / ask) runs and persist after\n\
            the session; they are owner-only under the data dir. Transport/protocol failures (DNS, an\n\
            unreachable upstream, a malformed request) are not a policy verdict and are not counted.\n\
            Recording is on by default; a trusted `[network] stats = false` turns it off. Host-side\n\
            and read-only — no launch, no nix, no network.",
    },
    Page {
        path: &["net", "logs"],
        synopsis: "sbx net logs [-a|--app <name>] [--host <h>] [--verdict allow|deny|blocked|error] \
                   [-n <N>] [--all] [--with-query] [--with-status] [-f|--follow] [-i|--interval <secs>] [--json]",
        summary: "the live, per-request egress log of a running session",
        options: &[
            ("-a, --app <name>", "scope to the sessions of that app, not the whole project"),
            ("--host <h>", "only events whose destination host is exactly <h>"),
            ("--verdict <v>", "only events with this verdict: allow, deny, blocked, or error"),
            ("-n <N>", "show only the most recent N events (per session)"),
            ("--all", "also show refusals a `[network] mute` rule suppressed (tagged `muted`); the \
                       default view omits them (they stay counted in `sbx net stats`)"),
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
            session — the session id (the PID `sbx session ls` shows), the local `hh:mm:ss` time, host:port,\n\
            method, path, verdict, and the reason category. It is read from the same control sockets\n\
            `sbx net pending` uses, and `log` is an accepted alias.\n\
            \n\
            LIVE-ONLY: the log lives in the running session's memory and is NEVER written to disk;\n\
            once the session exits, nothing remains. It shows a session while it runs (watch it\n\
            from another terminal), not after. Only a filtering posture (`deny`/`allow`/`ask`) has a\n\
            proxy, so only those sessions have a log.\n\
            \n\
            Verdicts are a superset of `sbx net stats`: allow, deny, blocked (a security/protocol\n\
            guard), and `error` — a request that was allowed but did not complete (DNS failure, an\n\
            unreachable host, a rejected certificate). `error` is diagnostic and is NOT one of the\n\
            stats counters, so the log's lines do not reconcile with `sbx net stats` totals.\n\
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
            A WebSocket is flagged `ws` on its line (it opens with a `101` status, which only an\n\
            upgrade produces) — shown even without `--with-status`, since a long-lived bidirectional\n\
            tunnel reads differently from a one-shot request.\n\
            \n\
            MUTE (SELinux `dontaudit`): a `[network] mute` rule suppresses a *denied* request's line\n\
            from this view — never its verdict (the request is still refused) and never its count\n\
            (`sbx net stats` still records it). Muted refusals live in a separate ring, so a chatty\n\
            muted host (telemetry, feature flags) can never evict a real event; `--all` folds them\n\
            back in, each tagged `muted`. Use it to keep the log focused on the refusals worth acting\n\
            on while still being able to see everything on demand.\n\
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
    Page {
        path: &["net", "live"],
        synopsis: "sbx net live [-a|--app <name>] [-i|--interval <secs>] [--json]",
        summary: "a live view of the egress tunnels currently open (a `top` for connections)",
        options: &[
            ("-a, --app <name>", "scope to the sessions of that app, not the whole project"),
            ("-i, --interval <secs>", "the redraw interval in seconds (default 1)"),
            ("--json", "emit one snapshot object per tick (NDJSON) instead of the redraw; works in a \
                        pipe and needs no terminal"),
        ],
        details:
            "Shows the egress tunnels open RIGHT NOW — one line per flow: destination host:port, the\n\
            transport (`https` inspected TLS, `http` inspected cleartext, `tcp` raw L4 splice), how\n\
            long it has been open, and the bytes transferred each way (`↑` client→upstream,\n\
            `↓` upstream→client). Rows are grouped by session (the PID `sbx session ls` shows) so several\n\
            agents are told apart. Redrawn in place on the interval until Ctrl-C, like `top`.\n\
            \n\
            This is the OPEN CONNECTIONS, distinct from `sbx net logs` (the history of decided\n\
            requests). Because the proxy closes each inspected request after one response, short API\n\
            calls flash by in well under a second; the durable rows are raw `tcp://` tunnels (SSH, a\n\
            database wire), WebSockets, and large L7 transfers in progress (a download, a streamed\n\
            completion). If nothing durable is open, the view is legitimately empty.\n\
            \n\
            Byte semantics: on an inspected `https`/`http` flow the counters are application bytes\n\
            (the proxy sees the plaintext); on a raw `tcp` splice they are the encrypted bytes on the\n\
            wire (the tunnel is opaque). Only a filtering posture (`deny`/`allow`/`ask`) runs a proxy,\n\
            so only those sessions have flows.\n\
            \n\
            The redraw needs a terminal; use `--json` to script it (one snapshot object per tick,\n\
            each flow carrying its session, destination, transport, age, and byte totals). Read live\n\
            from the same control sockets `sbx net logs` uses — host-side, no launch, no nix, no\n\
            network.",
    },
    // ---- plugins subcommands ------------------------------------------------------
    Page {
        path: &["plugins", "list"],
        synopsis: "sbx plugins list",
        summary: "list installed resolver plugins and built-in schemes",
        options: &[],
        details: "Shows the reserved built-in schemes and every installed resolver plugin — its\n\
            scheme, name, version, network grant, and whether it is runnable.",
    },
    Page {
        path: &["plugins", "info"],
        synopsis: "sbx plugins info <scheme>",
        summary: "show a plugin's manifest and sandbox grant",
        options: &[("<scheme>", "the resolver scheme to detail")],
        details:
            "A built-in scheme is reported as such; an unknown scheme is a non-zero miss, with\n\
            the load warnings re-emitted (so a dropped plugin explains itself).",
    },
    Page {
        path: &["plugins", "install"],
        synopsis: "sbx plugins install <name|dir>",
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
        synopsis: "sbx plugins rm <name>",
        summary: "remove an installed resolver plugin",
        options: &[(
            "<name>",
            "the installed plugin to remove (the token `list` shows)",
        )],
        details: "",
    },
    Page {
        path: &["plugins", "store"],
        synopsis: "sbx plugins store <subcommand> [args...]",
        summary: "manage signed plugin stores",
        options: &[],
        details:
            "A remote signed store is a git repository whose catalogue is verified against a\n\
            pinned public key, with anti-rollback on the revision.",
    },
    // ---- plugins store subcommands ------------------------------------------------
    Page {
        path: &["plugins", "store", "list"],
        synopsis: "sbx plugins store list",
        summary: "list the built-in store and configured remote stores",
        options: &[],
        details: "The resolver plugins bundled in the binary, then every configured remote store\n\
            with its accepted revision and plugin count. No fetch, no network.",
    },
    Page {
        path: &["plugins", "store", "add"],
        synopsis: "sbx plugins store add --name <n> --url <git-url> (--key <hex|@file> | --trust)",
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
        synopsis: "sbx plugins store publish <dir> --key <key-file> [--rev <n>]",
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
        synopsis: "sbx plugins store update [name]",
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
        synopsis: "sbx plugins store install <store> <plugin>",
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
        synopsis: "sbx plugins store info <name>",
        summary: "detail a configured remote store",
        options: &[("<name>", "the configured store to detail")],
        details:
            "Its origin URL, the pinned public key, the accepted revision, and each plugin it\n\
            lists. Reads only the owner-only cache: no fetch, no network.",
    },
    Page {
        path: &["plugins", "store", "rm"],
        synopsis: "sbx plugins store rm <name>",
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
    find(path).map_or("sbx <command>", |p| p.synopsis)
}

/// The argument grammar for a top-level command, e.g. `synopsis("shell")`.
pub fn synopsis(name: &str) -> &'static str {
    synopsis_of(&[name])
}

/// Whether `name` is a dispatched top-level command. Used to keep the help-flag
/// interception from swallowing an unknown command (which has its own diagnosis).
pub fn is_command(name: &str) -> bool {
    find(&[name]).is_some()
}

/// For an unknown top-level command that is really a subcommand verb, the full path to
/// suggest. Verbs with a *single* parent are listed; a genuinely ambiguous verb (`rm`,
/// `list`, `info`, `install` each belong to more than one parent) would misdirect, so it
/// falls through to the generic `sbx --help` pointer instead. `ls` is a deliberate
/// exception: it is an alias of both `session` and `projects`, but `sbx ls` historically
/// meant the session list, so pointing its old spelling at `sbx session ls` is the least
/// surprising migration aid.
pub fn subcommand_hint(name: &str) -> Option<&'static str> {
    Some(match name {
        // The session verbs used to be top-level; point their old spellings at the namespace.
        "ls" => "sbx session ls",
        "attach" => "sbx session attach",
        "stop" => "sbx session stop",
        "import" => "sbx app import",
        "export" => "sbx app export",
        "publish" => "sbx plugins store publish",
        "add" => "sbx plugins store add",
        "update" => "sbx plugins store update",
        "store" => "sbx plugins store",
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

/// Paint the `<metavar>` placeholders in a usage synopsis, leaving the literal command words,
/// flags, and `[...]`/`|` punctuation untouched. Each `<...>` span (its angle brackets included)
/// is wrapped in the palette's placeholder style; with color off every span is empty, so the
/// string is returned byte-for-byte. An unterminated `<` is emitted verbatim (never a dangling
/// open span), so malformed input can only under-style, never corrupt the output.
fn paint_synopsis(syn: &str, pal: &Palette) -> String {
    let mut out = String::with_capacity(syn.len());
    let mut rest = syn;
    while let Some(start) = rest.find('<') {
        out.push_str(&rest[..start]);
        match rest[start..].find('>') {
            Some(end) => {
                out.push_str(pal.arg);
                out.push_str(&rest[start..start + end + 1]); // the whole `<…>`
                out.push_str(pal.reset);
                rest = &rest[start + end + 1..];
            }
            None => {
                out.push_str(&rest[start..]); // no closing `>`: emit the remainder as-is
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Paint the backtick-quoted inline-code spans in prose (summaries, option descriptions, the
/// `details` body, the reminder lines). Each `` `…` `` span has its backticks dropped and its
/// content wrapped in the palette's code style. With color off the style span is empty, so the
/// backticks are *kept* and the string is returned byte-for-byte — the delimiters stay useful in
/// piped/plain output, and the non-terminal-is-plain invariant holds. An unterminated backtick is
/// emitted verbatim (never a dangling open span), so malformed input can only under-style.
fn paint_inline_code(text: &str, pal: &Palette) -> String {
    if pal.code.is_empty() {
        return text.to_string(); // color off: keep the backticks, unchanged
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('`') {
        out.push_str(&rest[..start]);
        match rest[start + 1..].find('`') {
            Some(end) => {
                out.push_str(pal.code);
                out.push_str(&rest[start + 1..start + 1 + end]); // inner text, backticks dropped
                out.push_str(pal.reset);
                rest = &rest[start + 1 + end + 1..];
            }
            None => {
                out.push_str(&rest[start..]); // lone backtick: emit the remainder as-is
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Render the top-level command list — the body of `sbx --help` and the no-command usage.
/// Top-level commands are sorted alphabetically, like each subcommand listing.
fn top_level(pal: &Palette) -> String {
    let mut out = String::from("sbx — a sandbox launcher (bubblewrap + daemonless nix)\n\n");
    out.push_str(&format!(
        "{}Usage:{}\n  {}\n\n",
        pal.head,
        pal.reset,
        paint_synopsis("sbx <command> [arguments]", pal)
    ));
    out.push_str(&format!("{}Commands:{}\n", pal.head, pal.reset));
    let mut tops: Vec<&Page> = PAGES.iter().filter(|p| p.path.len() == 1).collect();
    tops.sort_by_key(|p| p.path[0]);
    let width = tops.iter().map(|p| p.path[0].len()).max().unwrap_or(0);
    for p in tops {
        item(
            &mut out,
            pal.name,
            pal.reset,
            p.path[0],
            width,
            &paint_inline_code(p.summary, pal),
        );
    }
    out.push_str(&paint_inline_code(
        "\nRun `sbx help <command>` (or `sbx <command> --help`) for usage and details.\n",
        pal,
    ));
    out
}

/// Render one page: header, usage, options, subcommands (alphabetical), then prose.
fn render(page: &Page, pal: &Palette) -> String {
    let joined = page.path.join(" ");
    let mut out = format!(
        "{}sbx {}{} — {}\n\n",
        pal.name,
        joined,
        pal.reset,
        paint_inline_code(page.summary, pal)
    );
    out.push_str(&format!(
        "{}Usage:{}\n  {}\n",
        pal.head,
        pal.reset,
        paint_synopsis(page.synopsis, pal)
    ));

    if !page.options.is_empty() {
        out.push_str(&format!("\n{}Options:{}\n", pal.head, pal.reset));
        let width = page.options.iter().map(|(f, _)| f.len()).max().unwrap_or(0);
        for (flag, desc) in page.options {
            item(
                &mut out,
                pal.flag,
                pal.reset,
                flag,
                width,
                &paint_inline_code(desc, pal),
            );
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
                &paint_inline_code(k.summary, pal),
            );
        }
        out.push_str(&paint_inline_code(
            &format!("\nRun `sbx help {joined} <subcommand>` for a subcommand's options.\n"),
            pal,
        ));
    }

    if !page.details.is_empty() {
        out.push_str(&format!("\n{}\n", paint_inline_code(page.details, pal)));
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
                "sbx: no help for `sbx {}` — run `sbx --help` for the list of commands.",
                path.join(" ")
            );
            ExitCode::from(2)
        }
    }
}

/// The deepest command path a help request is about: the command, then each following
/// non-flag token that extends it to a known subcommand. `sbx plugins store add --help`
/// resolves to `["plugins","store","add"]`; `sbx session stop --all --help` to `["session","stop"]`.
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
///
/// A `--` ends sbx's own options: anything after it belongs to a launched command (e.g.
/// `sbx app <name> -- --help` passes `--help` through to that command), so the help scan stops
/// at the first `--` — the same rule the `run` arm applies to its command.
pub fn maybe_help(cmd: &str, rest: &[OsString]) -> Option<ExitCode> {
    let asks_help = rest
        .iter()
        .take_while(|a| a.to_str() != Some("--"))
        .any(|a| matches!(a.to_str(), Some("--help" | "-h")));
    asks_help.then(|| show(&resolve_path(cmd, rest)))
}

/// `sbx help [command [subcommand...]]` / `sbx --help` / `sbx -h`: the top-level list, or
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
/// stderr and exits non-zero, the way bare `sbx` writes [`top_level_usage`]. The page lists the
/// command's subcommands, so `sbx config` reveals `show`/`get`/… instead of silently acting. An
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
    fn maybe_help_stops_at_a_double_dash() {
        use std::ffi::OsString;
        let v = |xs: &[&str]| -> Vec<OsString> { xs.iter().map(OsString::from).collect() };

        // A leading help flag — or one after a subcommand, or after a non-`--` flag — is sbx's.
        assert!(maybe_help("app", &v(&["--help"])).is_some());
        assert!(maybe_help("app", &v(&["-h"])).is_some());
        assert!(maybe_help("app", &v(&["import", "--help"])).is_some());
        assert!(maybe_help("stop", &v(&["--all", "--help"])).is_some());

        // A help flag *after* a `--` belongs to the launched command — `sbx app <name> -- --help`
        // passes `--help` through, so sbx does not intercept it.
        assert!(maybe_help("app", &v(&["claude", "--", "--help"])).is_none());
        assert!(maybe_help("app", &v(&["claude", "--", "-h"])).is_none());
        // No help flag at all runs the command.
        assert!(maybe_help("app", &v(&["claude", "--", "-c"])).is_none());
        assert!(maybe_help("app", &v(&["claude"])).is_none());
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
}
