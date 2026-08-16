//! `sbx config` — inspect and edit the resolved configuration.
//!
//! Handlers for `config show/get/set/unset/path/edit` and the whole config-view
//! rendering layer: `render_config`, the per-field provenance tags, and the
//! `config show --app` effective-view renderer (`render_app_detail`). Cross-cutting
//! plumbing that other command families also use — `split_scope`/`ScopeArgs`,
//! `config_cwd`, the transactional confirmation renderers, and `short_rev` — stays at
//! the crate root and is reached from here via `crate::`.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::cli::confirm::{
    render_config_unchanged, render_config_write, render_list_edit, render_list_unchanged,
    render_trusted_whole_file,
};
use crate::{ScopeArgs, config_cwd, net_mode_word, short_rev, split_scope};
use crate::{config, diag, help, style, trust};

/// `sbx config [--json]` and the management verbs `get`/`set`/`unset`/`path`. With no verb it
/// shows the resolved configuration for the current project — the layered global + project
/// environment and host binds (each read-only or read-write), after the trust gate has dropped
/// anything an untrusted project may not set. The human form renders a colored document with
/// warnings on stderr;
/// `--json` prints the same resolved model as a JSON document. The verbs read and edit a single
/// raw layer file (the project `.sbx.toml`, the global config, or an explicit path).
pub(crate) fn config_cmd(args: Vec<OsString>) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("show") => config_show(&args[1..]),
        Some("get") => config_get(&args[1..]),
        Some("set") => config_set(&args[1..]),
        Some("add") => config_list_edit(&args[1..], ListEdit::Add),
        Some("rm") => config_list_edit(&args[1..], ListEdit::Remove),
        Some("unset") => config_unset(&args[1..]),
        Some("path") => config_path_cmd(&args[1..]),
        Some("edit") => config_edit(&args[1..]),
        // No subcommand — or an unknown one. Print the config page (which lists the subcommands)
        // to stderr and exit non-zero, so `sbx config` reveals `show`/`get`/… instead of silently
        // doing one of them. Mirrors the no-command usage of bare `sbx`.
        other => {
            match other {
                // The old `sbx config --json` muscle memory: the resolved view (and its --json) is
                // now `show`, so point straight at it. Other flags belong to a specific subcommand
                // (get/set/… take -c/--local/--trust), so name no verb and let the page below guide.
                Some("--json") => {
                    diag::error("sbx: config: --json is now `sbx config show --json`")
                }
                Some(tok) if tok.starts_with('-') => diag::error(&format!(
                    "sbx: config: {tok:?} is an option of a subcommand — pick one from the list below"
                )),
                Some(tok) => diag::error(&format!("sbx: config: unknown subcommand {tok:?}")),
                None => {}
            }
            eprint!("{}", help::page_usage(&["config"]).unwrap_or_default());
            ExitCode::from(2)
        }
    }
}

/// `sbx config show [--json]`: show the resolved configuration for the current project — the
/// layered, trust-gated view a launch would use. The human render is colored when stdout is a
/// terminal; `--json` emits the whole resolved model for tooling.
/// Record a chosen single-source `config show` view flag (`--global`/`--local`/`--default`),
/// rejecting a second, conflicting one — two different sources is a user error, not last-wins. The
/// same flag repeated is harmless. On conflict, prints the usage and returns the usage exit code.
fn set_show_source(
    current: &mut Option<(&'static str, config::Source)>,
    flag: &'static str,
    source: config::Source,
) -> Result<(), ExitCode> {
    match current {
        Some((prev, _)) if *prev == flag => Ok(()),
        Some((prev, _)) => {
            diag::error(&format!(
                "sbx: config show: `{flag}` conflicts with `{prev}` (choose one source)"
            ));
            diag::error(&format!(
                "sbx: usage: {}",
                help::synopsis_of(&["config", "show"])
            ));
            Err(ExitCode::from(2))
        }
        None => {
            *current = Some((flag, source));
            Ok(())
        }
    }
}

fn config_show(args: &[OsString]) -> ExitCode {
    let mut json = false;
    let mut details = false;
    let mut app: Option<String> = None;
    let mut source: Option<(&'static str, config::Source)> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--json") => json = true,
            Some("--details") => details = true,
            Some("--app") | Some("-a") => match it.next() {
                Some(name) => app = Some(name.to_string_lossy().into_owned()),
                None => {
                    diag::error("sbx: config show: `--app` needs an app name");
                    diag::error(&format!(
                        "sbx: usage: {}",
                        help::synopsis_of(&["config", "show"])
                    ));
                    return ExitCode::from(2);
                }
            },
            Some("--global") | Some("-g") => {
                if let Err(code) = set_show_source(&mut source, "--global", config::Source::Global)
                {
                    return code;
                }
            }
            Some("--local") | Some("-l") => {
                if let Err(code) = set_show_source(&mut source, "--local", config::Source::Local) {
                    return code;
                }
            }
            Some("--default") | Some("-d") => {
                if let Err(code) =
                    set_show_source(&mut source, "--default", config::Source::Default)
                {
                    return code;
                }
            }
            _ => {
                diag::error(&format!(
                    "sbx: config show: unexpected argument {:?}",
                    arg.to_string_lossy()
                ));
                diag::error(&format!(
                    "sbx: usage: {}",
                    help::synopsis_of(&["config", "show"])
                ));
                return ExitCode::from(2);
            }
        }
    }

    // A per-app view is inherently the app's effective configuration over the *full* baseline, so a
    // single-source restriction is meaningless there — reject the combination rather than silently
    // ignoring one flag.
    if app.is_some()
        && let Some((flag, _)) = source
    {
        diag::error(&format!(
            "sbx: config show: `--app` does not combine with `{flag}`"
        ));
        diag::error(&format!(
            "sbx: usage: {}",
            help::synopsis_of(&["config", "show"])
        ));
        return ExitCode::from(2);
    }

    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the current directory: {e}"));
            return ExitCode::FAILURE;
        }
    };

    // `--app <name>` focuses on one app's *effective* configuration with provenance, instead of the
    // whole resolved baseline.
    if let Some(name) = app {
        return config_show_app(&cwd, &name, json, details);
    }

    // A source flag restricts the view to that one layer (over the built-in defaults); with none,
    // the full layered configuration is shown.
    let view = match source {
        Some((_, src)) => config::view::build_scoped(&cwd, src),
        None => config::view::build(&cwd),
    };

    if json {
        // The whole resolved model, warnings and all, as one JSON document — already exhaustive
        // (every app's rules in full), so `--details` is moot here whatever order the flags came.
        // Nothing goes to stderr — stdout stays pure JSON, the contract a consuming tool relies on.
        match serde_json::to_string_pretty(&view) {
            Ok(doc) => println!("{doc}"),
            Err(e) => {
                diag::error(&format!("sbx: cannot serialize the configuration: {e}"));
                return ExitCode::FAILURE;
            }
        }
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_config(&view, &pal, details));
    // Warnings go to stderr, out of band from the resolved view, so the body stays a clean
    // capturable document and a warning never pollutes a piped human render.
    for w in &view.warnings {
        diag::warn(w);
    }
    ExitCode::SUCCESS
}

/// Render one app's effective configuration with provenance — the `config show --app <name>` path.
/// Errors (listing the declared apps) when no such app exists.
fn config_show_app(cwd: &Path, name: &str, json: bool, details: bool) -> ExitCode {
    let Some(view) = config::view::build_app_detail(cwd, name) else {
        diag::error(&format!("sbx: config show: no app named {name:?}"));
        let declared: Vec<String> = config::view::build(cwd)
            .apps
            .into_iter()
            .map(|a| a.name)
            .collect();
        if declared.is_empty() {
            diag::error("sbx: no apps are declared for this directory");
        } else {
            diag::error(&format!("sbx: declared apps: {}", declared.join(", ")));
        }
        return ExitCode::FAILURE;
    };

    if json {
        match serde_json::to_string_pretty(&view) {
            Ok(doc) => println!("{doc}"),
            Err(e) => {
                diag::error(&format!("sbx: cannot serialize the app configuration: {e}"));
                return ExitCode::FAILURE;
            }
        }
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_app_detail(&view, &pal, details));
    ExitCode::SUCCESS
}

/// Render the resolved configuration for display — a pure presenter over [`config::view`]. It
/// adds only color and layout, so the management core stays presentation-agnostic and a future
/// front-end can render the same model differently. Every color span is empty under a
/// non-terminal, so captured output is byte-for-byte the plain text the integration tests pin.
/// The ` (default)` / ` (global)` / ` (project)` / ` (inherited)` provenance tag a line carries,
/// hued by level so a configured source stands out (global cyan, project green) while a built-in
/// default or an inherited baseline value stays dim. The *label text* is always emitted — color is
/// additive and (like every span) vanishes under a non-terminal — so captured output keeps the
/// bare `(global)` the integration tests pin.
fn provenance_tag(origin: config::view::ProvenanceView, pal: &style::Palette) -> String {
    let (label, span) = provenance_parts(origin, pal);
    format!("  {span}({label}){r}", r = pal.reset)
}

/// The label and color span for a provenance level — the one place the level→hue mapping lives, so
/// the end-of-line [`provenance_tag`] and any inline use (the per-field `limits` cells) cannot
/// drift. A configured source is hued (global cyan, project green); a default or inherited value
/// stays dim.
fn provenance_parts(
    origin: config::view::ProvenanceView,
    pal: &style::Palette,
) -> (&'static str, &'static str) {
    use config::view::ProvenanceView;
    match origin {
        ProvenanceView::Default => ("default", pal.dim),
        ProvenanceView::Global => ("global", pal.name),
        ProvenanceView::Project => ("project", pal.ok),
        ProvenanceView::Inherited => ("inherited", pal.dim),
        // A one-shot override is the final word for this invocation — flagged in warn hue so it
        // stands out from the persisted config layers.
        ProvenanceView::Override => ("override", pal.warn),
    }
}

/// The provenance tag for a field in the per-app detail view, hued by the same level scale but
/// labelled in the app's vocabulary: a value the app declaration set reads `app:global`/`app:project`
/// (not the baseline `global`/`project`), one it left to the baseline reads `inherited`.
fn app_provenance_tag(origin: config::view::ProvenanceView, pal: &style::Palette) -> String {
    let (label, span) = app_provenance_parts(origin, pal);
    format!("  {span}({label}){r}", r = pal.reset)
}

/// The label and color span for a provenance level in the per-app view — the one place the app
/// vocabulary lives (so the inline `limits` cells and the end-of-line tag cannot drift). Same hues
/// as [`provenance_parts`]: a configured source is cyan/green, a default or inherited value dim.
fn app_provenance_parts(
    origin: config::view::ProvenanceView,
    pal: &style::Palette,
) -> (&'static str, &'static str) {
    use config::view::ProvenanceView;
    match origin {
        ProvenanceView::Default => ("default", pal.dim),
        ProvenanceView::Global => ("app:global", pal.name),
        ProvenanceView::Project => ("app:project", pal.ok),
        ProvenanceView::Inherited => ("inherited", pal.dim),
        ProvenanceView::Override => ("override", pal.warn),
    }
}

/// The provenance tag for an optional origin — a per-entry value (an `env` variable, a bind) whose
/// declaring layer may not be recorded (an app overlay's binds carry none). Empty when unknown.
fn opt_provenance_tag(
    origin: Option<config::view::ProvenanceView>,
    pal: &style::Palette,
) -> String {
    origin.map_or_else(String::new, |o| provenance_tag(o, pal))
}

/// The mode marker appended after a bind path: a warning-hued ` (rw)` for a read-write bind
/// (the more-privileged, exceptional case worth flagging), nothing for the read-only default.
fn bind_mode_tag(writable: bool, pal: &style::Palette) -> String {
    if writable {
        format!(" {}(rw){}", pal.warn, pal.reset)
    } else {
        String::new()
    }
}

/// The two `[network]` settings that decide how a permitted request is carried rather than whether
/// it is carried: connection reuse and the resolver cache.
///
/// They earn their line for a sharper reason than the other transport settings do. The whole table
/// is trusted/global-only, and neither is observable from inside the cage: a client cannot see that
/// its connection was reused, nor how old the address it reached was. `sbx config` is where a
/// project learns that a trusted layer set them.
///
/// The baseline view names only what a layer moved off its default, in the same spirit as the
/// capture line — never a silent property of a launch, never noise for the common posture.
/// `--details` names the **effective** posture instead, defaults included, because the baseline's
/// silence is ambiguous to a reader who does not already know the product defaults: nothing printed
/// means "reuse is on and the cache is the built-in one", which is exactly what someone asking for
/// details wants spelled out. Only the resolver cache can say *which* of the two it is, because the
/// view keeps its unset state (`None`) while `pool` arrives already collapsed to a `bool`.
/// The transport settings of a filtering launch: how a permitted request is *carried*, none of them
/// a verdict. Grouped rather than passed one by one because they are reported together and grow
/// together.
struct NetTransport {
    pool: bool,
    ca_roots: bool,
    dns_cache_ttl: Option<u64>,
    idle_timeout: Option<u64>,
    max_connections: Option<usize>,
    body_max_mb: Option<u64>,
}

fn write_net_transport(o: &mut String, t: NetTransport, details: bool, pal: &style::Palette) {
    use std::fmt::Write as _;
    let NetTransport {
        pool,
        ca_roots,
        dns_cache_ttl,
        idle_timeout,
        max_connections,
        body_max_mb,
    } = t;
    let mut line = |s: &str| {
        let _ = writeln!(o, "    {}", style::dim_prose(s, pal));
    };
    if !pool {
        line(
            "connection reuse: off (every request opens and validates its own upstream connection)",
        );
    } else if details {
        line(
            "connection reuse: on (a request may ride an upstream connection an earlier one left behind)",
        );
    }
    // The minimal anchor is the state worth naming unasked: it is what a tool that refuses a
    // one-certificate trust store trips over, and its own error blames the bundle.
    if !ca_roots {
        line(
            "cage ca: session CA only (no public roots; a tool that checks the store's shape may refuse it)",
        );
    } else if details {
        line("cage ca: session CA + public roots (an ordinary, full trust store)");
    }
    match dns_cache_ttl {
        Some(0) => line("dns cache: off (every request re-resolves)"),
        Some(secs) => line(&format!(
            "dns cache: {secs}s (a resolved address stands for that long)"
        )),
        None if details => line(&format!(
            "dns cache: {}s (built-in default; a resolved address stands for that long)",
            crate::allowlist::DEFAULT_DNS_CACHE_TTL.as_secs()
        )),
        None => {}
    }
    // Only meaningful where something is kept: `pool = false` holds nothing to age out, and the
    // line above already said so.
    if pool {
        match idle_timeout {
            Some(secs) => line(&format!(
                "idle timeout: {secs}s (a connection with nothing to carry is closed after that)"
            )),
            None if details => line(&format!(
                "idle timeout: {}s (built-in default; a connection with nothing to carry is \
                 closed after that)",
                crate::allowlist::DEFAULT_IDLE_TIMEOUT.as_secs()
            )),
            None => {}
        }
    }
    match max_connections {
        Some(max) => line(&format!(
            "max connections: {max} (one beyond it is refused `connection-cap`, not queued)"
        )),
        None if details => line(&format!(
            "max connections: {} (built-in default; one beyond it is refused `connection-cap`, \
             not queued)",
            crate::allowlist::DEFAULT_MAX_CONNECTIONS
        )),
        None => {}
    }
    match body_max_mb {
        Some(mb) => line(&format!(
            "body ceiling: {mb} MiB (the most of one request body held; a larger streamed upload \
             is refused)"
        )),
        None if details => line(&format!(
            "body ceiling: {} MiB (built-in default; the most of one request body held; a larger \
             streamed upload is refused)",
            crate::allowlist::DEFAULT_BODY_MAX / (1024 * 1024)
        )),
        None => {}
    }
}

/// The layered environment, after the trust gate. Shown even when empty: a reader looking for a
/// variable they set needs to see that nothing carries it.
fn env_section(env: &[config::view::EnvVar], pal: &style::Palette) -> String {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let mut o = String::new();
    if env.is_empty() {
        let _ = writeln!(o, "  {h}env:{r}   {dim}(none){r}");
    } else {
        let _ = writeln!(o, "  {h}env:{r}");
        for e in env {
            let _ = writeln!(
                o,
                "    {n}{}{r}={}{}",
                e.key,
                e.value,
                opt_provenance_tag(e.layer, pal)
            );
        }
    }
    o
}

/// The host paths bound into the cage, read-only or read-write, after the trust gate.
fn binds_section(binds: &[config::view::BindView], pal: &style::Palette) -> String {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let mut o = String::new();
    if binds.is_empty() {
        let _ = writeln!(o, "  {h}binds:{r} {dim}(none){r}");
    } else {
        let _ = writeln!(o, "  {h}binds:{r}");
        for b in binds {
            let _ = writeln!(
                o,
                "    {n}{}{r}{}{}",
                b.path,
                bind_mode_tag(b.writable, pal),
                opt_provenance_tag(b.layer, pal)
            );
        }
    }
    o
}

/// What a URI opens with, by scheme. Listed rather than counted, and shown even when empty: the
/// empty state is the informative one here, since a cage with no handler opens nothing and a reader
/// chasing a sign-in that goes nowhere is looking for exactly this line.
fn open_section(open: &[config::view::OpenView], pal: &style::Palette) -> String {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let mut o = String::new();
    if open.is_empty() {
        let _ = writeln!(
            o,
            "  {h}open:{r} {dim}(none — a URI is printed, not opened){r}"
        );
    } else {
        let _ = writeln!(o, "  {h}open:{r}");
        for e in open {
            let _ = writeln!(
                o,
                "    {n}{}://{r} {} {dim}({}){r}",
                e.scheme, e.cmd, e.mode
            );
        }
    }
    o
}

/// The auxiliary processes the cage starts before its command. Listed, never counted, and only when
/// there are any: this section exists so a second process running beside the app is a line someone
/// can read rather than a `nohup` buried in a shell script.
fn service_section(service: &[config::view::ServiceView], pal: &style::Palette) -> Option<String> {
    use std::fmt::Write as _;
    if service.is_empty() {
        return None;
    }
    let (h, r) = (pal.head, pal.reset);
    let mut o = String::new();
    let _ = writeln!(o, "  {h}service:{r}");
    for s in service {
        let _ = writeln!(o, "{}", service_line(s, pal, "    "));
    }
    Some(o)
}

/// Declared tools, each with its backend and trust verdict — the launcher's decision, shown without
/// realising anything (no nix, no network).
fn packages_section(packages: &[config::view::PackageView], pal: &style::Palette) -> String {
    use std::fmt::Write as _;
    let (h, dim, r) = (pal.head, pal.dim, pal.reset);
    let mut o = String::new();
    if packages.is_empty() {
        let _ = writeln!(o, "  {h}packages:{r} {dim}(none){r}");
    } else {
        let _ = writeln!(o, "  {h}packages:{r}");
        for p in packages {
            let _ = writeln!(o, "{}", package_line(p, pal, "    "));
        }
    }
    o
}

/// The project's mise file and whether it would be honored — a tool source gated like `packages`,
/// reported as presence + verdict (no mise run). Trusted is green (it applies); withheld is yellow.
fn mise_section(mise: Option<&config::view::MiseView>, pal: &style::Palette) -> String {
    use std::fmt::Write as _;
    let (h, n, ok, warn, dim, r) = (pal.head, pal.name, pal.ok, pal.warn, pal.dim, pal.reset);
    let mut o = String::new();
    match mise {
        None => {
            let _ = writeln!(o, "  {h}mise:{r}  {dim}(none){r}");
        }
        Some(m) if m.trusted => {
            let _ = writeln!(o, "  {h}mise:{r}  {n}{}{r} {ok}(trusted){r}", m.name);
        }
        Some(m) => {
            let _ = writeln!(
                o,
                "  {h}mise:{r}  {n}{}{r} {warn}(withheld: {}){r}",
                m.name,
                m.withheld_reason.as_deref().unwrap_or_default()
            );
        }
    }
    o
}

/// The tools that mise file declares — parsed only. `nix:` tools carry the file's trust; a
/// non-`nix:` tool is equipped in-cage (so honored regardless of trust) unless `network = "none"`
/// prevents the fetch; a malformed `nix:` token is shown so it is not silently absent.
fn tools_section(tools: &config::view::ToolsView, pal: &style::Palette) -> Option<String> {
    use std::fmt::Write as _;
    if tools.is_empty() {
        return None;
    }
    let (h, n, warn, dim, r) = (pal.head, pal.name, pal.warn, pal.dim, pal.reset);
    let mut o = String::new();
    let _ = writeln!(o, "  {h}tools:{r}");
    for t in &tools.nix {
        match &t.withheld_reason {
            Some(reason) => {
                let _ = writeln!(
                    o,
                    "    {n}nix:{}{r} = {}  {warn}(withheld: {reason}){r}",
                    t.pkg, t.version
                );
            }
            None => {
                let _ = writeln!(o, "    {n}nix:{}{r} = {}", t.pkg, t.version);
            }
        }
    }
    for t in &tools.non_nix {
        if t.equipped {
            let _ = writeln!(
                o,
                "    {n}{}{r} = {}  {dim}(equipped in-cage via mise){r}",
                t.token, t.version
            );
        } else {
            let _ = writeln!(
                o,
                "    {n}{}{r} = {}  {}",
                t.token,
                t.version,
                style::paint_spans(
                    &format!("{warn}(needs network — not equipped under `network = \"none\"`){r}"),
                    pal.code,
                    pal.warn,
                    pal
                )
            );
        }
    }
    for token in &tools.malformed {
        let _ = writeln!(o, "    {token}  {warn}(ignored: malformed nix: token){r}");
    }
    Some(o)
}

/// The nixpkgs source the tools resolve against and its locked revision, then the mise engine's own
/// channel — shown so the engine's decoupling from the base channel is visible. Routed through the
/// launch's own channel decision; an unlocked source omits the revision.
fn channels_section(view: &config::view::ConfigView, pal: &style::Palette) -> String {
    use std::fmt::Write as _;
    let (h, r) = (pal.head, pal.reset);
    let mut o = String::new();
    let _ = writeln!(o, "  {h}nixpkgs:{r} {}", channel_text(&view.nixpkgs, pal));
    let _ = writeln!(o, "  {h}engine:{r} {}", channel_text(&view.engine, pal));
    o
}

/// The process/exec posture — shown only when the lens is on, so an unenforced config stays
/// uncluttered. `--details` lists the allow/deny exec-target rules.
fn proc_section(
    view: &config::view::ConfigView,
    pal: &style::Palette,
    details: bool,
) -> Option<String> {
    use std::fmt::Write as _;
    if view.proc.mode == "off" {
        return None;
    }
    let (h, dim, r) = (pal.head, pal.dim, pal.reset);
    let mut o = String::new();
    let p = &view.proc;
    let _ = writeln!(
        o,
        "  {h}proc:{r} {} {dim}({} allow, {} deny){r}{}",
        p.mode,
        p.allow.len(),
        p.deny.len(),
        provenance_tag(view.proc_origin, pal)
    );
    if details {
        for rule in &p.allow {
            let _ = writeln!(o, "      {dim}allow{r} {rule}");
        }
        for rule in &p.deny {
            let _ = writeln!(o, "      {dim}deny{r}  {rule}");
        }
    }
    Some(o)
}

/// The refusal notifications. Summarised as one mode when every event shares it (the common case,
/// including the default), and spelled out per event only when they differ — a row that reads
/// `notify: once` says everything there is to say, while five identical lines would be noise. `off`
/// for everything is shown too, unlike the postures below: silence is exactly the state a reader
/// wondering "why was I not told" needs to see.
fn notify_section(view: &config::view::ConfigView, pal: &style::Palette) -> String {
    use std::fmt::Write as _;
    let (h, dim, r) = (pal.head, pal.dim, pal.reset);
    let mut o = String::new();
    let n = &view.notify;
    let uniform = n
        .events
        .first()
        .filter(|(_, first)| n.events.iter().all(|(_, m)| m == first))
        .map(|(_, m)| m.clone());
    let every = if n.repeat_after.is_empty() {
        String::new()
    } else {
        format!(" {dim}(a repeat waits {}){r}", n.repeat_after)
    };
    match uniform {
        Some(mode) => {
            let _ = writeln!(
                o,
                "  {h}notify:{r} {mode}{every}{}",
                provenance_tag(view.notify_origin, pal)
            );
        }
        None => {
            let _ = writeln!(
                o,
                "  {h}notify:{r} {dim}per event{r}{every}{}",
                provenance_tag(view.notify_origin, pal)
            );
            for (event, mode) in &n.events {
                let _ = writeln!(o, "      {dim}{event}{r} {mode}");
            }
        }
    }
    o
}

/// The desktop holes, each shown only when opened so a config that opened none stays uncluttered:
/// GUI (with the compositor caveat on `wayland`, and what `offscreen` supplies since it exposes
/// nothing), GPU, audio, and the in-cage D-Bus portal.
fn desktop_sections(view: &config::view::ConfigView, pal: &style::Palette) -> Option<String> {
    use config::view::GuiView;
    use std::fmt::Write as _;
    let (h, dim, r) = (pal.head, pal.dim, pal.reset);
    let mut o = String::new();
    match view.gui {
        GuiView::Wayland => {
            let _ = writeln!(
                o,
                "  {h}gui:{r} wayland {dim}(exposure depends on your compositor){r}{}",
                provenance_tag(view.gui_origin, pal)
            );
        }
        GuiView::Offscreen => {
            let _ = writeln!(
                o,
                "  {h}gui:{r} offscreen {dim}(fonts + proxy CA, no display){r}{}",
                provenance_tag(view.gui_origin, pal)
            );
        }
        GuiView::None => {}
    }
    if view.gpu {
        let _ = writeln!(
            o,
            "  {h}gpu:{r} enabled {dim}(mesa: Intel/AMD/nouveau){r}{}",
            provenance_tag(view.gpu_origin, pal)
        );
    }
    if view.audio {
        let _ = writeln!(
            o,
            "  {h}audio:{r} enabled {dim}(microphone + playback via PulseAudio){r}{}",
            provenance_tag(view.audio_origin, pal)
        );
    }
    if view.dbus {
        let _ = writeln!(
            o,
            "  {h}dbus:{r} in-cage portal {dim}(file chooser + theme + notifications){r}{}",
            provenance_tag(view.dbus_origin, pal)
        );
    }
    (!o.is_empty()).then_some(o)
}

/// Inbound loopback forward ports — shown only when a layer declared any. Each port is bound on the
/// host's `127.0.0.1` and bridged into the cage at the same port (an OAuth `localhost:<port>`
/// callback, or a cage-run dev server).
fn forward_section(view: &config::view::ConfigView, pal: &style::Palette) -> Option<String> {
    use std::fmt::Write as _;
    if view.forward.is_empty() {
        return None;
    }
    let (h, dim, r) = (pal.head, pal.dim, pal.reset);
    let mut o = String::new();
    let ports = view
        .forward
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(
        o,
        "  {h}forward:{r} {ports} {dim}(host loopback → cage loopback){r}{}",
        provenance_tag(view.forward_origin, pal)
    );
    Some(o)
}

/// Resource limits — shown only when a config `[limits]` override customizes one, so a
/// default-profile config stays uncluttered (the effective defaults are in `sbx doctor`). When
/// shown, each of the three fields carries its own provenance: the overridden ones name their
/// layer, the untouched ones read `(default)`, so the line tells exactly which limits were tuned.
fn limits_section(view: &config::view::ConfigView, pal: &style::Palette) -> Option<String> {
    use config::view::LimitView;
    use std::fmt::Write as _;
    let (h, r) = (pal.head, pal.reset);
    let l = &view.limits;
    let overridden = |v: &LimitView| v.origin != config::view::ProvenanceView::Default;
    if !(overridden(&l.memory_high) || overridden(&l.memory_max) || overridden(&l.tasks_max)) {
        return None;
    }
    let cell = |name: &str, v: &LimitView| {
        let (label, span) = provenance_parts(v.origin, pal);
        format!("{name}={} {span}({label}){r}", v.value)
    };
    let mut o = String::new();
    let _ = writeln!(
        o,
        "  {h}limits:{r} {}, {}, {}",
        cell("MemoryHigh", &l.memory_high),
        cell("MemoryMax", &l.memory_max),
        cell("TasksMax", &l.tasks_max),
    );
    Some(o)
}

/// The grants that widen the cage beyond its defaults, each shown only when a trusted layer made
/// it: a seccomp denylist relaxation, a host device node, the `[fs]` masks, and the ssh-agent keys.
/// The entries read as written, since that is what a reader edits; what each covers is settled at
/// launch and reported there.
fn grants_section(view: &config::view::ConfigView, pal: &style::Palette) -> Option<String> {
    use std::fmt::Write as _;
    let (h, dim, r) = (pal.head, pal.dim, pal.reset);
    let mut o = String::new();
    if !view.seccomp.is_empty() {
        let _ = writeln!(
            o,
            "  {h}seccomp allow:{r} {} {dim}(syscalls re-permitted in the cage){r}{}",
            view.seccomp.join(", "),
            provenance_tag(view.seccomp_origin, pal)
        );
    }
    if !view.devices.is_empty() {
        let _ = writeln!(
            o,
            "  {h}devices:{r} {} {dim}(host device nodes exposed in the cage){r}{}",
            view.devices.join(", "),
            provenance_tag(view.devices_origin, pal)
        );
    }
    if !view.fs_deny.is_empty() {
        let _ = writeln!(
            o,
            "  {h}fs deny:{r} {} {dim}(closed to the cage; the name stays visible){r}{}",
            view.fs_deny.join(", "),
            provenance_tag(view.fs_origin, pal)
        );
    }
    if !view.fs_readonly.is_empty() {
        let _ = writeln!(
            o,
            "  {h}fs readonly:{r} {} {dim}(readable in the cage, not writable){r}{}",
            view.fs_readonly.join(", "),
            provenance_tag(view.fs_origin, pal)
        );
    }
    if !view.ssh_agent.is_empty() {
        let _ = writeln!(
            o,
            "  {h}ssh-agent:{r} {} {dim}({}){r}{}",
            view.ssh_agent.join(", "),
            if view.ssh_agent_confirm {
                "keys the cage may sign with, each signature confirmed on your desktop"
            } else {
                "keys the cage may sign with"
            },
            provenance_tag(view.ssh_agent_origin, pal)
        );
    }
    (!o.is_empty()).then_some(o)
}

/// Broker plugins — shown only when one is bound. The **socket** leads each line: it is the whole of
/// what is exposed, and a reader auditing a broker is auditing that path. The policy follows, and
/// its provenance tag is the policy's — the socket is always the global config's, which is what
/// makes the tag readable rather than ambiguous.
fn brokers_section(brokers: &[config::view::BrokerView], pal: &style::Palette) -> Option<String> {
    use std::fmt::Write as _;
    if brokers.is_empty() {
        return None;
    }
    let (h, dim, r) = (pal.head, pal.dim, pal.reset);
    let mut o = String::new();
    for b in brokers {
        let _ = writeln!(
            o,
            "  {h}broker:{r} {} {dim}→{r} {} {dim}({}){r}{}",
            b.socket,
            b.name,
            if b.allow.is_empty() {
                "brokered by this plugin, no policy entries".to_string()
            } else {
                format!("brokered by this plugin: {}", b.allow.join(", "))
            },
            provenance_tag(b.origin, pal)
        );
        // The credential, by locator. On its own line rather than folded into the one above: a
        // broker that authenticates on the cage's behalf is the thing an audit stops at.
        if !b.secret.is_empty() {
            let _ = writeln!(
                o,
                "    {dim}places the credential from:{r} {}",
                b.secret.join(", ")
            );
        }
    }
    Some(o)
}

/// The network posture — a security field. `shared` keeps the host network; `none` cuts it off; a
/// filtering posture (`deny`/`allow`/`ask`) routes egress through the proxy — `deny` permits only
/// what is listed (deny wins over allow), plus the always-allowed built-in set so the self-equip
/// allowance is never silent.
///
/// The largest section by far, and the one whose sub-lines carry the most: the tuning knobs under
/// `--details`, the rule lists, the mute and http2 sets, and the egress-stats toggle, which is
/// meaningful only here because the proxy runs only under a filtering posture.
fn network_section(view: &config::view::ConfigView, pal: &style::Palette, details: bool) -> String {
    use config::view::{NetDefaultView, NetworkView};
    use std::fmt::Write as _;
    let (h, n, warn, dim, r) = (pal.head, pal.name, pal.warn, pal.dim, pal.reset);
    let mut o = String::new();
    let net_tag = provenance_tag(view.network_origin, pal);
    match &view.network {
        NetworkView::Shared => {
            let _ = writeln!(o, "  {h}network:{r} shared {dim}(host network){r}{net_tag}");
        }
        NetworkView::Isolated => {
            let _ = writeln!(
                o,
                "  {h}network:{r} none {dim}(isolated — no network){r}{net_tag}"
            );
        }
        NetworkView::Allowlist {
            default_action,
            ask_timeout,
            ask_notice,
            allow,
            deny,
            mute,
            http2,
            capture,
            capture_max_kb,
            pool,
            ca_roots,
            dns_cache_ttl,
            idle_timeout,
            max_connections,
            body_max_mb,
            builtin,
        } => {
            let _ = writeln!(
                o,
                "  {h}network:{r} {}{net_tag}",
                net_mode_word(*default_action)
            );
            if let Some(t) = ask_timeout {
                let shown = if t == "none" {
                    "none (wait indefinitely until answered)".to_string()
                } else {
                    t.clone()
                };
                let _ = writeln!(o, "    {dim}ask timeout: {shown}{r}");
            }
            if matches!(ask_notice, Some(false)) {
                let _ = writeln!(
                    o,
                    "    {}",
                    style::dim_prose(
                        "ask notice: off (parked requests are silent — answer via \
                         `sbx net pending`)",
                        pal
                    )
                );
            }
            // A traffic capture retains the plaintext of every inspected exchange, so it is always
            // stated — never a silent property of a launch.
            if capture != "off" {
                let cap = match capture_max_kb {
                    Some(kb) => format!("capture: {capture} (up to {kb} KiB per body)"),
                    None => format!("capture: {capture}"),
                };
                let _ = writeln!(
                    o,
                    "    {}",
                    style::dim_prose(
                        &format!("{cap} — read it with `sbx net logs --with-body`"),
                        pal
                    )
                );
            }
            write_net_transport(
                &mut o,
                NetTransport {
                    pool: *pool,
                    ca_roots: *ca_roots,
                    dns_cache_ttl: *dns_cache_ttl,
                    idle_timeout: *idle_timeout,
                    max_connections: *max_connections,
                    body_max_mb: *body_max_mb,
                },
                details,
                pal,
            );
            match default_action {
                // Allowlist: only the listed (and built-in) hosts reach; everything else is denied.
                NetDefaultView::Deny => {
                    if allow.is_empty() {
                        let _ = writeln!(
                            o,
                            "    {dim}allow: (none declared beyond the built-in set){r}"
                        );
                    } else {
                        for rule in allow {
                            let _ = writeln!(o, "    allow {n}{rule}{r}");
                        }
                    }
                    // Deny wins over allow, so the keyword takes the caution hue.
                    for rule in deny {
                        let _ = writeln!(o, "    {warn}deny{r}  {n}{rule}{r}");
                    }
                    let _ = writeln!(
                        o,
                        "    {dim}built-in (always allowed, so self-equip works):{r}"
                    );
                    for host in builtin {
                        let _ = writeln!(o, "      allow {n}{host}{r}");
                    }
                    let _ = writeln!(o, "    {dim}(deny wins; an unlisted host is denied){r}");
                }
                // Denylist: every public host reaches except the deny carve-outs; the proxy stays
                // active. The allow rules only relax the SSRF private-host guard here (every public
                // host is already permitted), and the built-in set is moot, so neither is led with.
                NetDefaultView::Allow => {
                    let _ = writeln!(o, "    {dim}every public host is reachable except:{r}");
                    if deny.is_empty() {
                        let _ = writeln!(o, "    {dim}deny: (none declared){r}");
                    } else {
                        for rule in deny {
                            let _ = writeln!(o, "    {warn}deny{r}  {n}{rule}{r}");
                        }
                    }
                    if !allow.is_empty() {
                        let _ = writeln!(o, "    {dim}allow (private-host exceptions only):{r}");
                        for rule in allow {
                            let _ = writeln!(o, "      allow {n}{rule}{r}");
                        }
                    }
                }
                // Ask: an unlisted host parks for a live decision; allow rules still auto-pass and
                // deny rules still auto-fail, so list those (and the built-in set) as pre-decided.
                NetDefaultView::Ask => {
                    let _ = writeln!(
                        o,
                        "    {}",
                        style::dim_prose(
                            "an unlisted host parks for a live `sbx net pending` decision; \
                             these are pre-decided:",
                            pal
                        )
                    );
                    if !allow.is_empty() {
                        let _ = writeln!(o, "    {dim}auto-allow:{r}");
                        for rule in allow {
                            let _ = writeln!(o, "      allow {n}{rule}{r}");
                        }
                    }
                    for rule in deny {
                        let _ = writeln!(o, "    {warn}deny{r}  {n}{rule}{r}");
                    }
                    let _ = writeln!(
                        o,
                        "    {dim}built-in (always allowed, so self-equip works):{r}"
                    );
                    for host in builtin {
                        let _ = writeln!(o, "      allow {n}{host}{r}");
                    }
                }
            }
            // Mute (`dontaudit`) rules apply under every filtering posture — they suppress a denied
            // request's log line (never a verdict), so they are surfaced here (dimmed) whenever any
            // are declared, so the suppression is never silent.
            if !mute.is_empty() {
                let _ = writeln!(
                    o,
                    "    {}",
                    style::dim_prose(
                        "mute (refusals kept out of `sbx net log`; see `--all`):",
                        pal
                    )
                );
                for rule in mute {
                    let _ = writeln!(o, "      {dim}mute{r}  {n}{rule}{r}");
                }
            }
            // http2 hosts: spoken to as HTTP/2 (gRPC) instead of HTTP/1.1. A transport choice —
            // orthogonal to the verdict (the host is still allow-gated and every stream inspected) —
            // so surfaced under the filtering posture whenever any is declared.
            if !http2.is_empty() {
                let _ = writeln!(
                    o,
                    "    {dim}http2 (gRPC over HTTP/2; still allow-gated and inspected):{r}"
                );
                for host in http2 {
                    let _ = writeln!(o, "      http2 {n}{host}{r}");
                }
            }
            // The egress-stats toggle is meaningful only under a filtering posture (the proxy runs
            // only then), so it rides the network section. Shown both ways — an audit knob is worth
            // surfacing — naming the reader command when on.
            let _ = writeln!(
                o,
                "    {dim}stats: {}{r}",
                if view.egress_stats {
                    "recording (sbx net stats)"
                } else {
                    "off"
                }
            );
        }
    }

    o
}

/// Credentials the egress proxy injects — by destination and source locator, never the value.
fn secrets_section(secrets: &[config::view::SecretView], pal: &style::Palette) -> Option<String> {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    if secrets.is_empty() {
        return None;
    }
    let mut o = String::new();
    let _ = writeln!(
        o,
        "  {h}secrets (injected host-side by the egress proxy):{r}"
    );
    for s in secrets {
        let _ = writeln!(
            o,
            "    {n}{}{r} -> {n}{}{r}  {dim}({}, from {}){r}",
            s.header, s.to, s.shape, s.sources
        );
    }
    Some(o)
}

/// The redaction floor, shown only when a layer moved it. It governs credentials the secrets
/// section may not list — a task's, and one the cage obtained for itself — so it gets its own line
/// rather than a note under the secrets above; at the built-in floor there is nothing to report.
fn redact_section(view: &config::view::ConfigView, pal: &style::Palette) -> Option<String> {
    use std::fmt::Write as _;
    let (h, n, r) = (pal.head, pal.name, pal.reset);
    if view.redact_min_len_origin == config::view::ProvenanceView::Default {
        return None;
    }
    let mut o = String::new();
    let _ = writeln!(
        o,
        "  {h}redact:{r} a secret under {n}{}{r} bytes is not scanned for{}",
        view.redact_min_len,
        provenance_tag(view.redact_min_len_origin, pal)
    );
    Some(o)
}

/// What the host answers to a resolver plugin. Values are shown: a `[plugin.<name>]` table carries
/// configuration, never a credential — a secret is declared in `[secret]`, which
/// [`secrets_section`] prints by locator and never by value.
fn plugins_section(plugins: &[config::view::PluginView], pal: &style::Palette) -> Option<String> {
    use std::fmt::Write as _;
    let (h, n, r) = (pal.head, pal.name, pal.reset);
    if plugins.is_empty() {
        return None;
    }
    let mut o = String::new();
    let _ = writeln!(
        o,
        "  {h}plugins (what this host supplies to a resolver):{r}"
    );
    for p in plugins {
        // Two different kinds of answer, kept on their own lines: `env` configures a tool the
        // machine already has, `programs` says where to get one it has not. Running them
        // together would read as one list whose entries mean different things.
        if !p.env.is_empty() {
            let _ = writeln!(o, "    {n}{}{r}  env: {}", p.name, p.env.join(", "));
        }
        if !p.programs.is_empty() {
            let _ = writeln!(
                o,
                "    {n}{}{r}  programs: {} (a fallback; PATH wins)",
                p.name,
                p.programs.join(", ")
            );
        }
    }
    Some(o)
}

/// Declared operations, the static counterpart to `sbx task ls` (which reads a running session).
/// Name, what it says it does, and which layer declared it — not the command, which is the whole
/// contract `sbx task show` prints. Without this there was no way to confirm a `[task]` block
/// survived validation short of launching a session and asking it.
fn tasks_section(tasks: &[config::view::TaskView], pal: &style::Palette) -> Option<String> {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    if tasks.is_empty() {
        return None;
    }
    let mut o = String::new();
    let _ = writeln!(o, "  {h}tasks (declared operations a cage may run):{r}");
    let width = tasks.iter().map(|t| t.name.len()).max().unwrap_or(0);
    for t in tasks {
        let described = match &t.description {
            Some(d) => format!("  {d}"),
            None => String::new(),
        };
        let _ = writeln!(
            o,
            "    {n}{:<width$}{r}{described}  {dim}({}){r}",
            t.name,
            t.origin,
            width = width
        );
    }
    Some(o)
}

/// Named application profiles, each a gated overlay over the baseline: the command it runs, what
/// its overlay adds, and its own dropped-field notes (so `sbx app <name>` holds no surprises).
/// Security fields appear only when their source was trusted, exactly as at launch.
fn apps_section(
    apps: &[config::view::AppView],
    pal: &style::Palette,
    details: bool,
) -> Option<String> {
    use config::view::{AppNetworkView, GuiView};
    use std::fmt::Write as _;
    let (h, n, warn, dim, r) = (pal.head, pal.name, pal.warn, pal.dim, pal.reset);
    if apps.is_empty() {
        return None;
    }
    let mut o = String::new();
    let _ = writeln!(o, "  {h}apps:{r}");
    for app in apps {
        match &app.cmd {
            Some(cmd) => {
                let _ = writeln!(o, "    {n}{}{r}: {cmd}", app.name);
            }
            // No layer declared a command — the app cannot launch, so flag it.
            None => {
                let _ = writeln!(o, "    {n}{}{r}: {warn}(no command){r}", app.name);
            }
        }
        let _ = writeln!(o, "      {dim}home:{r} {}", app.home_scope);
        // The environment this overlay adds over the baseline — a count by default, each
        // `KEY=value` under `--details`, mirroring the baseline `env` section. A free field; the
        // value shown is the one that enters the cage (a placeholder for a credential profile),
        // never the injected secret, which sbx reads host-side and never prints.
        if !app.env.is_empty() {
            if details {
                let _ = writeln!(o, "      {dim}env:{r}");
                for e in &app.env {
                    let _ = writeln!(o, "        {n}{}{r}={}", e.key, e.value);
                }
            } else {
                let _ = writeln!(o, "      {dim}env:{r} {} set", app.env.len());
            }
        }
        // The host binds this overlay adds — a security field, so what host paths
        // `sbx app <name>` exposes (and whether read-write) is visible here, the same as the
        // baseline `binds` section. A count by default, each canonical path under `--details`.
        if !app.binds.is_empty() {
            if details {
                let _ = writeln!(o, "      {dim}binds:{r}");
                for b in &app.binds {
                    let _ = writeln!(
                        o,
                        "        {n}{}{r}{}",
                        b.path,
                        bind_mode_tag(b.writable, pal)
                    );
                }
            } else {
                let _ = writeln!(o, "      {dim}binds:{r} {}", app.binds.len());
            }
        }
        // The URI handlers this overlay adds, its bundles' folded in. Listed by default, not
        // counted: a handler is what a sign-in link reaches, which is precisely what
        // distinguishes this app from every other one.
        if !app.open.is_empty() {
            let _ = writeln!(o, "      {dim}open:{r}");
            for e in &app.open {
                let _ = writeln!(
                    o,
                    "        {n}{}://{r} {} {dim}({}){r}",
                    e.scheme, e.cmd, e.mode
                );
            }
        }
        // The auxiliary processes this overlay adds, its bundles' folded in. Listed for the
        // reason the field exists: what else this app starts is part of what it is.
        if !app.service.is_empty() {
            let _ = writeln!(o, "      {dim}service:{r}");
            for s in &app.service {
                let _ = writeln!(o, "{}", service_line(s, pal, "        "));
            }
        }
        // The packages this overlay declares. Compact by default — names with ` @ <rev>` for a
        // pinned `flake:` one and ` (withheld)` for one the trust gate would withhold at launch,
        // so an untrusted app package reads as withheld here without `--details`. `--details`
        // expands to one full line per package (backend, locator, realisation), the same line
        // the baseline `packages` section renders, so the two never drift.
        if !app.packages.is_empty() {
            if details {
                let _ = writeln!(o, "      {dim}packages:{r}");
                for p in &app.packages {
                    let _ = writeln!(o, "{}", package_line(p, pal, "        "));
                }
            } else {
                let pkgs = app
                    .packages
                    .iter()
                    .map(|p| {
                        // A withheld package stands as its name plus the marker — neither its
                        // pin nor its realisation, since it is not built; the same short-circuit
                        // the full `--details` line takes, so the two paths agree.
                        if p.withheld_reason.is_some() {
                            return format!("{} {warn}(withheld){r}", p.name);
                        }
                        match &p.pinned_rev {
                            Some(rev) => format!("{} @ {}", p.name, short_rev(rev)),
                            None => p.name.clone(),
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = writeln!(o, "      {dim}packages:{r} {pkgs}");
            }
        }
        // An overlay is a compact summary by default — one line per field; an allowlist shows
        // just its rule counts. `--details` expands that to the individual allow/deny rules
        // and the always-allowed built-in hosts, so what `sbx app <name>` can reach is visible
        // here (the baseline `network` section shows the built-in set only when the *baseline*
        // is an allowlist, which a profile's app-overlay allowlist is not).
        if let Some(net) = &app.network {
            match net {
                AppNetworkView::Shared => {
                    let _ = writeln!(o, "      {dim}network:{r} shared {dim}(host network){r}");
                }
                AppNetworkView::Isolated => {
                    let _ = writeln!(
                        o,
                        "      {dim}network:{r} none {dim}(isolated — no network){r}"
                    );
                }
                AppNetworkView::Allowlist {
                    default_action,
                    ask_timeout,
                    ask_notice,
                    allow,
                    deny,
                    builtin,
                } if details => {
                    let _ = writeln!(
                        o,
                        "      {dim}network:{r} {}",
                        net_mode_word(*default_action)
                    );
                    if let Some(t) = ask_timeout {
                        let _ = writeln!(o, "        {dim}ask timeout: {t}{r}");
                    }
                    if matches!(ask_notice, Some(false)) {
                        let _ = writeln!(o, "        {dim}ask notice: off{r}");
                    }
                    for rule in allow {
                        let _ = writeln!(o, "        allow {n}{rule}{r}");
                    }
                    for rule in deny {
                        let _ = writeln!(o, "        {warn}deny{r}  {n}{rule}{r}");
                    }
                    let _ = writeln!(
                        o,
                        "        {dim}built-in (always allowed, so self-equip works):{r}"
                    );
                    for host in builtin {
                        let _ = writeln!(o, "          allow {n}{host}{r}");
                    }
                    let _ = writeln!(o, "        {dim}(deny wins over allow){r}");
                }
                AppNetworkView::Allowlist {
                    default_action,
                    allow,
                    deny,
                    ..
                } => {
                    let _ = writeln!(
                        o,
                        "      {dim}network:{r} {} {dim}({} allow, {} deny){r}",
                        net_mode_word(*default_action),
                        allow.len(),
                        deny.len()
                    );
                }
            }
        }
        // The GUI posture the overlay sets, matched like the baseline `gui` line: `wayland`
        // carries the same compositor-exposure caveat, so an app that opens a display explains
        // it the same way; an explicit `none` (the app closing a display the baseline may open)
        // stays a bare word — there is nothing to caveat.
        match &app.gui {
            Some(GuiView::Wayland) => {
                let _ = writeln!(
                    o,
                    "      {dim}gui:{r} wayland {dim}(exposure depends on your compositor){r}"
                );
            }
            Some(GuiView::Offscreen) => {
                let _ = writeln!(
                    o,
                    "      {dim}gui:{r} offscreen {dim}(fonts + proxy CA, no display){r}"
                );
            }
            Some(GuiView::None) => {
                let _ = writeln!(o, "      {dim}gui:{r} none");
            }
            None => {}
        }
        // The GPU posture the overlay sets (`Some(true)`/`Some(false)`); `None` inherits.
        match app.gpu {
            Some(true) => {
                let _ = writeln!(o, "      {dim}gpu:{r} enabled {dim}(mesa){r}");
            }
            Some(false) => {
                let _ = writeln!(o, "      {dim}gpu:{r} disabled");
            }
            None => {}
        }
        // The audio posture the overlay sets (`Some(true)`/`Some(false)`); `None` inherits.
        match app.audio {
            Some(true) => {
                let _ = writeln!(
                    o,
                    "      {dim}audio:{r} enabled {dim}(microphone + playback){r}"
                );
            }
            Some(false) => {
                let _ = writeln!(o, "      {dim}audio:{r} disabled");
            }
            None => {}
        }
        // The D-Bus posture the overlay sets; `None` inherits.
        match app.dbus {
            Some(true) => {
                let _ = writeln!(
                    o,
                    "      {dim}dbus:{r} in-cage portal {dim}(file chooser + theme + notifications){r}"
                );
            }
            Some(false) => {
                let _ = writeln!(o, "      {dim}dbus:{r} disabled");
            }
            None => {}
        }
        // The cgroup limits this overlay overrides — only the fields it tunes, since an app
        // does not carry the full effective set (an unset field inherits the baseline, shown in
        // `sbx doctor`). Mirrors the baseline `limits:` line but lists the app's own overrides.
        if let Some(limits) = &app.limits {
            let mut parts: Vec<String> = Vec::new();
            if let Some(v) = &limits.memory_high {
                parts.push(format!("MemoryHigh={v}"));
            }
            if let Some(v) = &limits.memory_max {
                parts.push(format!("MemoryMax={v}"));
            }
            if let Some(v) = &limits.tasks_max {
                parts.push(format!("TasksMax={v}"));
            }
            let _ = writeln!(o, "      {dim}limits:{r} {}", parts.join(", "));
        }
        // The host loopback ports this overlay adds (its own, not the baseline-merged set). A
        // compact list under the app's roster entry; the effective set is in `config show --app`.
        if !app.forward.is_empty() {
            let ports = app
                .forward
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(o, "      {dim}forward:{r} {ports} (host loopback → cage)");
        }
        // The seccomp relaxation this overlay adds (its own allow tokens, not the merged set).
        if !app.seccomp.is_empty() {
            let _ = writeln!(o, "      {dim}seccomp allow:{r} {}", app.seccomp.join(", "));
        }
        // The host device grant this overlay adds (its own `/dev/` paths, not the merged set).
        if !app.devices.is_empty() {
            let _ = writeln!(o, "      {dim}devices:{r} {}", app.devices.join(", "));
        }
        if !app.fs_deny.is_empty() {
            let _ = writeln!(o, "      {dim}fs deny:{r} {}", app.fs_deny.join(", "));
        }
        if !app.fs_readonly.is_empty() {
            let _ = writeln!(
                o,
                "      {dim}fs readonly:{r} {}",
                app.fs_readonly.join(", ")
            );
        }
        // The ssh-agent keys this overlay grants (its own entries, not the merged set) — the
        // whole point of the per-app field is that one app may sign where another may not, so a
        // listing that folded it into the baseline would hide exactly what it is for.
        if !app.ssh_agent.is_empty() {
            let _ = writeln!(o, "      {dim}ssh-agent:{r} {}", app.ssh_agent.join(", "));
        }
        // The credentials this overlay injects (its own `[secret]` sections, gated; the merge
        // unions them with the baseline only for the launch) — a count by default, expanded
        // under `--details` to each by destination and source, the same metadata the baseline
        // section shows. Never the value; sbx reads that host-side.
        if !app.secrets.is_empty() {
            if details {
                let _ = writeln!(o, "      {dim}secrets (injected host-side):{r}");
                for s in &app.secrets {
                    let _ = writeln!(
                        o,
                        "        {n}{}{r} -> {n}{}{r}  {dim}({}, from {}){r}",
                        s.header, s.to, s.shape, s.sources
                    );
                }
            } else {
                let _ = writeln!(
                    o,
                    "      {dim}secrets:{r} {} injected host-side",
                    app.secrets.len()
                );
            }
        }
        for note in &app.notes {
            let _ = writeln!(o, "      {warn}note: {note}{r}");
        }
    }
    Some(o)
}

fn render_config(view: &config::view::ConfigView, pal: &style::Palette, details: bool) -> String {
    use std::fmt::Write as _;
    let (h, n, r) = (pal.head, pal.name, pal.reset);
    let mut o = String::new();

    // The hue carries the layering story the model already holds: a section header is bold, an
    // identifier (a key, a path, a rule, a channel) rides the name span, a value the trust gate
    // *withheld* is yellow while an admitted one's detail is dimmed, and every value's provenance
    // tag is hued by level — a built-in default gray, a global source cyan, a project source green
    // — so where a value came from reads at a glance. None of this is new data; it is the gating
    // outcome and the per-value origin made visible. Every span is empty under a non-terminal, so
    // captured output stays byte-for-byte the plain text the integration tests pin.
    let _ = writeln!(o, "{h}sbx config{r} — resolved for {n}{}{r}", view.cwd);

    // Each section renders on its own and is appended in order. The order is load-bearing (it is
    // the reading order of a resolved config), so it lives here as a sequence of calls rather than
    // inside the sections themselves.
    o.push_str(&env_section(&view.env, pal));
    o.push_str(&binds_section(&view.binds, pal));
    o.push_str(&open_section(&view.open, pal));
    if let Some(s) = service_section(&view.service, pal) {
        o.push_str(&s);
    }
    o.push_str(&packages_section(&view.packages, pal));
    o.push_str(&mise_section(view.mise.as_ref(), pal));
    if let Some(s) = tools_section(&view.tools, pal) {
        o.push_str(&s);
    }
    o.push_str(&channels_section(view, pal));

    o.push_str(&network_section(view, pal, details));

    for section in [
        proc_section(view, pal, details),
        Some(notify_section(view, pal)),
        desktop_sections(view, pal),
        forward_section(view, pal),
        limits_section(view, pal),
        grants_section(view, pal),
        brokers_section(&view.brokers, pal),
        secrets_section(&view.secrets, pal),
        redact_section(view, pal),
        plugins_section(&view.plugins, pal),
        tasks_section(&view.tasks, pal),
        apps_section(&view.apps, pal, details),
    ]
    .into_iter()
    .flatten()
    {
        o.push_str(&section);
    }

    o
}

/// Whether a posture line belongs in the default per-app view, recording the ones it does not.
///
/// A posture nobody configured — not the app, not the baseline — says only that sbx has a default,
/// which is the same answer for every app on the machine. Ten of them crowded out the handful of
/// fields that actually distinguish one app from another, so they are folded unless `--details`
/// asks for the full picture. `folded` collects their names in the order they would have appeared,
/// and the caller prints them on one line: what is hidden is still named, and the flag that shows
/// it is named beside it.
///
/// The judgement is `at_default`, not the provenance itself, so `limits` — three cells with three
/// origins — folds on the same rule as the scalars: only when no cell was set by anyone.
fn posture_shown(
    details: bool,
    at_default: bool,
    name: &'static str,
    folded: &mut Vec<&'static str>,
) -> bool {
    if details || !at_default {
        return true;
    }
    folded.push(name);
    false
}

/// Render one app's *effective* configuration with per-field provenance — the `config show --app
/// <name>` view. Every scalar shows the value the app would launch with, tagged `app:global`/
/// `app:project` (the app set it), `inherited` (it took a value the baseline configured) or
/// `default` (nobody configured it); collections show the overlay's own additions and a count of
/// the baseline entries they inherit, with the entry lists and the allowlist rules expanded under
/// `--details`. A posture left entirely at its default is folded out of the default view and named
/// on the summary line instead ([`posture_shown`]). Color and layout only over
/// [`config::view::AppDetailView`]; every span empties under a non-terminal.
fn render_app_detail(
    view: &config::view::AppDetailView,
    pal: &style::Palette,
    details: bool,
) -> String {
    use config::view::{GuiView, LimitView, NetworkView, ProvenanceView};
    use std::fmt::Write as _;
    let (h, n, warn, dim, r) = (pal.head, pal.name, pal.warn, pal.dim, pal.reset);
    let mut o = String::new();
    // The postures nobody configured, in the order they would have been printed. Filled as the
    // fields below are skipped, and spelled out once after them.
    let mut folded: Vec<&'static str> = Vec::new();
    let untouched = |origin: ProvenanceView| origin == ProvenanceView::Default;

    let _ = writeln!(
        o,
        "{h}sbx config{r} — app {n}{}{r} resolved for {n}{}{r}",
        view.name, view.cwd
    );

    // The command — never inherited (the baseline carries none of its own).
    match &view.cmd {
        Some(cmd) => {
            let _ = writeln!(
                o,
                "  {h}cmd:{r}     {cmd}{}",
                app_provenance_tag(view.cmd_origin, pal)
            );
        }
        None => {
            let _ = writeln!(o, "  {h}cmd:{r}     {warn}(no command){r}");
        }
    }
    // Ahead of the posture, beside the command: an install step runs in this cage before `cmd`, so
    // it belongs where a reader looks for what this app executes, not among the fields that shape
    // it.
    for step in &view.provisions {
        let _ = writeln!(
            o,
            "  {h}install:{r} {}  {dim}(from bundle {}, runs once before cmd){r}",
            step.cmd, step.bundle
        );
    }
    let _ = writeln!(
        o,
        "  {h}home:{r}    {}{}",
        view.home_scope,
        app_provenance_tag(view.home_scope_origin, pal)
    );

    // The effective network posture + provenance; the allowlist's rules expand under `--details`.
    let net_tag = app_provenance_tag(view.network_origin, pal);
    match &view.network {
        NetworkView::Shared => {
            let _ = writeln!(o, "  {h}network:{r} shared {dim}(host network){r}{net_tag}");
        }
        NetworkView::Isolated => {
            let _ = writeln!(
                o,
                "  {h}network:{r} none {dim}(isolated — no network){r}{net_tag}"
            );
        }
        NetworkView::Allowlist {
            default_action,
            ask_timeout,
            ask_notice,
            allow,
            deny,
            mute,
            http2,
            capture,
            capture_max_kb,
            pool,
            ca_roots,
            dns_cache_ttl,
            idle_timeout,
            max_connections,
            body_max_mb,
            builtin,
        } => {
            let _ = writeln!(
                o,
                "  {h}network:{r} {}{net_tag}",
                net_mode_word(*default_action)
            );
            if let Some(t) = ask_timeout {
                let _ = writeln!(o, "    {dim}ask timeout: {t}{r}");
            }
            if matches!(ask_notice, Some(false)) {
                let _ = writeln!(
                    o,
                    "    {}",
                    style::dim_prose(
                        "ask notice: off (parked requests are silent — answer via \
                         `sbx net pending`)",
                        pal
                    )
                );
            }
            // A traffic capture retains the plaintext of every inspected exchange, so it is always
            // stated — never a silent property of a launch.
            if capture != "off" {
                let cap = match capture_max_kb {
                    Some(kb) => format!("capture: {capture} (up to {kb} KiB per body)"),
                    None => format!("capture: {capture}"),
                };
                let _ = writeln!(
                    o,
                    "    {}",
                    style::dim_prose(
                        &format!("{cap} — read it with `sbx net logs --with-body`"),
                        pal
                    )
                );
            }
            write_net_transport(
                &mut o,
                NetTransport {
                    pool: *pool,
                    ca_roots: *ca_roots,
                    dns_cache_ttl: *dns_cache_ttl,
                    idle_timeout: *idle_timeout,
                    max_connections: *max_connections,
                    body_max_mb: *body_max_mb,
                },
                details,
                pal,
            );
            // The policy itself is listed either way: which hosts this app may reach is the
            // answer someone opens this view to find, and a count sends them to a second command
            // to read it. A rule is a whole clause (verbs, scheme, host pattern), so one per line
            // rather than joined — nineteen of them on one line would be unreadable.
            for rule in allow {
                let _ = writeln!(o, "    allow {n}{rule}{r}");
            }
            for rule in deny {
                let _ = writeln!(o, "    {warn}deny{r}  {n}{rule}{r}");
            }
            if details {
                for rule in mute {
                    let _ = writeln!(o, "    {dim}mute{r}  {n}{rule}{r}");
                }
                for host in http2 {
                    let _ = writeln!(o, "    {dim}http2{r} {n}{host}{r}");
                }
                let _ = writeln!(
                    o,
                    "    {dim}built-in (always allowed, so self-equip works):{r}"
                );
                for host in builtin {
                    let _ = writeln!(o, "      allow {n}{host}{r}");
                }
                let _ = writeln!(o, "    {dim}(deny wins over allow){r}");
            } else {
                // What stays behind the flag decides nothing about reachability: `mute` only
                // silences an already-permitted request in the log, `http2` picks a transport, and
                // the built-in set is the same for every app. Counted, not listed — and only when
                // non-zero, so an app that uses neither reads as if the line were not there.
                let mut extra = String::new();
                if !mute.is_empty() {
                    extra.push_str(&format!("{} mute", mute.len()));
                }
                if !http2.is_empty() {
                    if !extra.is_empty() {
                        extra.push_str(", ");
                    }
                    extra.push_str(&format!("{} http2", http2.len()));
                }
                if !extra.is_empty() {
                    let _ = writeln!(o, "    {dim}({extra} — see --details){r}");
                }
            }
        }
    }

    // The effective process/exec posture — shown whenever somebody set it, `off` included, so the
    // inherited story is visible.
    if posture_shown(details, untouched(view.proc_origin), "proc", &mut folded) {
        let proc_tag = app_provenance_tag(view.proc_origin, pal);
        let _ = writeln!(
            o,
            "  {h}proc:{r}    {} {dim}({} allow, {} deny){r}{proc_tag}",
            view.proc.mode,
            view.proc.allow.len(),
            view.proc.deny.len()
        );
    }

    // The effective refusal notifications — shown whenever somebody set them, even when every event
    // agrees, and spelled out per event only when they differ.
    if posture_shown(
        details,
        untouched(view.notify_origin),
        "notify",
        &mut folded,
    ) {
        let notify_tag = app_provenance_tag(view.notify_origin, pal);
        let uniform = view
            .notify
            .events
            .first()
            .filter(|(_, first)| view.notify.events.iter().all(|(_, m)| m == first))
            .map(|(_, m)| m.clone());
        match uniform {
            Some(mode) => {
                let _ = writeln!(o, "  {h}notify:{r}  {mode}{notify_tag}");
            }
            None => {
                let _ = writeln!(o, "  {h}notify:{r}  {dim}per event{r}{notify_tag}");
                for (event, mode) in &view.notify.events {
                    let _ = writeln!(o, "      {dim}{event}{r} {mode}");
                }
            }
        }
    }

    // The effective GUI posture — shown whenever somebody set it, `none` included.
    if posture_shown(details, untouched(view.gui_origin), "gui", &mut folded) {
        let gui_tag = app_provenance_tag(view.gui_origin, pal);
        match view.gui {
            GuiView::Wayland => {
                let _ = writeln!(
                    o,
                    "  {h}gui:{r}     wayland {dim}(exposure depends on your compositor){r}{gui_tag}"
                );
            }
            GuiView::Offscreen => {
                let _ = writeln!(
                    o,
                    "  {h}gui:{r}     offscreen {dim}(fonts + proxy CA, no display){r}{gui_tag}"
                );
            }
            GuiView::None => {
                let _ = writeln!(o, "  {h}gui:{r}     none{gui_tag}");
            }
        }
    }

    // The effective GPU posture — shown either way whenever somebody set it.
    if posture_shown(details, untouched(view.gpu_origin), "gpu", &mut folded) {
        let gpu_tag = app_provenance_tag(view.gpu_origin, pal);
        let _ = writeln!(
            o,
            "  {h}gpu:{r}     {}{gpu_tag}",
            if view.gpu { "enabled" } else { "disabled" }
        );
    }

    // The effective audio posture — shown either way whenever somebody set it.
    if posture_shown(details, untouched(view.audio_origin), "audio", &mut folded) {
        let audio_tag = app_provenance_tag(view.audio_origin, pal);
        let _ = writeln!(
            o,
            "  {h}audio:{r}   {}{audio_tag}",
            if view.audio { "enabled" } else { "disabled" }
        );
    }

    // The effective D-Bus posture — shown either way whenever somebody set it.
    if posture_shown(details, untouched(view.dbus_origin), "dbus", &mut folded) {
        let dbus_tag = app_provenance_tag(view.dbus_origin, pal);
        let dbus_label = if view.dbus {
            "in-cage portal"
        } else {
            "disabled"
        };
        let _ = writeln!(o, "  {h}dbus:{r}    {dbus_label}{dbus_tag}");
    }

    // The effective cgroup limits — every field its provenance (inherited from the baseline, or the
    // app layer that tuned it).
    let cell = |label_name: &str, v: &LimitView| {
        let (label, span) = app_provenance_parts(v.origin, pal);
        format!("{label_name}={} {span}({label}){r}", v.value)
    };
    let l = &view.limits;
    // One line, three origins: it folds only when no cell was set by anyone. A single tuned cell
    // keeps the whole line, since the other two are the context that tuning is read against.
    let limits_untouched = untouched(l.memory_high.origin)
        && untouched(l.memory_max.origin)
        && untouched(l.tasks_max.origin);
    if posture_shown(details, limits_untouched, "limits", &mut folded) {
        let _ = writeln!(
            o,
            "  {h}limits:{r}  {}, {}, {}",
            cell("MemoryHigh", &l.memory_high),
            cell("MemoryMax", &l.memory_max),
            cell("TasksMax", &l.tasks_max),
        );
    }

    // Effective inbound loopback forward ports — the app's own ∪ the baseline's. Shown even when
    // empty so the inherited story is visible (a non-empty baseline set shows as `inherited`).
    if posture_shown(
        details,
        untouched(view.forward_origin),
        "forward",
        &mut folded,
    ) {
        let forward_tag = app_provenance_tag(view.forward_origin, pal);
        if view.forward.is_empty() {
            let _ = writeln!(o, "  {h}forward:{r} (none){forward_tag}");
        } else {
            let ports = view
                .forward
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                o,
                "  {h}forward:{r} {ports} {dim}(host loopback → cage loopback){r}{forward_tag}"
            );
        }
    }

    // Effective seccomp relaxation — the app's own ∪ the baseline's. Shown even when empty so the
    // inherited story is visible (a relaxation the app takes from the baseline reads as `inherited`).
    if posture_shown(
        details,
        untouched(view.seccomp_origin),
        "seccomp",
        &mut folded,
    ) {
        let seccomp_tag = app_provenance_tag(view.seccomp_origin, pal);
        if view.seccomp.is_empty() {
            let _ = writeln!(o, "  {h}seccomp:{r} (mandatory denylist){seccomp_tag}");
        } else {
            let _ = writeln!(
                o,
                "  {h}seccomp:{r} allow {} {dim}(syscalls re-permitted){r}{seccomp_tag}",
                view.seccomp.join(", ")
            );
        }
    }

    // Effective host device grant — the app's own ∪ the baseline's. Shown even when empty so the
    // inherited story is visible (a device the app takes from the baseline reads as `inherited`).
    if posture_shown(
        details,
        untouched(view.devices_origin),
        "devices",
        &mut folded,
    ) {
        let devices_tag = app_provenance_tag(view.devices_origin, pal);
        if view.devices.is_empty() {
            let _ = writeln!(o, "  {h}devices:{r} (none — minimal /dev){devices_tag}");
        } else {
            let _ = writeln!(
                o,
                "  {h}devices:{r} {} {dim}(host device nodes exposed){r}{devices_tag}",
                view.devices.join(", ")
            );
        }
    }

    // What the fold cost, on one line: every hidden posture named, and the flag that brings them
    // back. Nothing disappears without saying so — a reader must never have to guess whether a
    // field is absent because it is unset or because the view chose not to show it.
    if !folded.is_empty() {
        let _ = writeln!(
            o,
            "  {dim}at their default: {} — see --details{r}",
            folded.join(", ")
        );
    }

    // The effective mask set — the app's own ∪ the baseline's. Shown only when something is
    // closed: "none" would say nothing a reader does not already assume.
    let fs_tag = app_provenance_tag(view.fs_origin, pal);
    if !view.fs_deny.is_empty() {
        let _ = writeln!(
            o,
            "  {h}fs deny:{r} {} {dim}(closed to the cage){r}{fs_tag}",
            view.fs_deny.join(", ")
        );
    }
    if !view.fs_readonly.is_empty() {
        let _ = writeln!(
            o,
            "  {h}fs readonly:{r} {} {dim}(readable, not writable){r}{fs_tag}",
            view.fs_readonly.join(", ")
        );
    }

    // The effective ssh-agent grant — the app's own keys unioned with the baseline's, tagged with
    // where they came from. Shown only when something is granted: "none" would say nothing the
    // baseline view does not already say.
    if !view.ssh_agent.is_empty() {
        let _ = writeln!(
            o,
            "  {h}ssh-agent:{r} {} {dim}({}){r}{}",
            view.ssh_agent.join(", "),
            if view.ssh_agent_confirm {
                "keys the cage may sign with, each signature confirmed on your desktop"
            } else {
                "keys the cage may sign with"
            },
            app_provenance_tag(view.ssh_agent_origin, pal)
        );
    }

    // Collections: what the overlay adds, by name, then how many baseline entries it inherits.
    // Names rather than counts, because the names are what distinguishes this app — `1 own` is
    // true of half the catalogue. What each entry *is* (a value, a backend line, a credential's
    // shape and sources) still expands under `--details`; the inherited baseline entries are not
    // re-listed there either, being one hop away in `sbx config show`.
    let _ = writeln!(
        o,
        "  {h}env:{r}     {}",
        collection_list(
            &view
                .env
                .iter()
                .map(|e| format!("{n}{}{r}", e.key))
                .collect::<Vec<_>>(),
            view.env_inherited,
            pal
        )
    );
    if details {
        for e in &view.env {
            let _ = writeln!(o, "    {n}{}{r}={}", e.key, e.value);
        }
    }
    let _ = writeln!(
        o,
        "  {h}binds:{r}   {}",
        collection_list(
            &view
                .binds
                .iter()
                .map(|b| format!("{n}{}{r}{}", b.path, bind_mode_tag(b.writable, pal)))
                .collect::<Vec<_>>(),
            view.binds_inherited,
            pal
        )
    );
    let _ = writeln!(
        o,
        "  {h}packages:{r} {}",
        collection_list(
            &view
                .packages
                .iter()
                .map(|p| package_name_tag(p, pal))
                .collect::<Vec<_>>(),
            view.packages_inherited,
            pal
        )
    );
    if details {
        for p in &view.packages {
            let _ = writeln!(o, "{}", package_line(p, pal, "    "));
        }
    }
    // What a link opens with, effective. Listed in full rather than summarised as a count: this is
    // the answer someone opens this view to find when a sign-in goes nowhere, and it is short.
    if view.open.is_empty() {
        let _ = writeln!(
            o,
            "  {h}open:{r} {dim}(none — a URI is printed, not opened){r}"
        );
    } else {
        let _ = writeln!(o, "  {h}open:{r}");
        for e in &view.open {
            let _ = writeln!(
                o,
                "    {n}{}://{r} {} {dim}({}){r}",
                e.scheme, e.cmd, e.mode
            );
        }
    }

    // The auxiliary processes the cage starts before its command. Listed, never counted, and only
    // when there are any: this section exists so a second process running beside the app is a line
    // someone can read rather than a `nohup` buried in a shell script.
    if !view.service.is_empty() {
        let _ = writeln!(o, "  {h}service:{r}");
        for s in &view.service {
            let _ = writeln!(o, "{}", service_line(s, pal, "    "));
        }
    }
    let _ = writeln!(
        o,
        "  {h}secrets:{r} {}",
        collection_list(
            &view
                .secrets
                .iter()
                .map(|s| format!("{n}{}{r} -> {n}{}{r}", s.header, s.to))
                .collect::<Vec<_>>(),
            view.secrets_inherited,
            pal
        )
    );
    if details {
        for s in &view.secrets {
            let _ = writeln!(
                o,
                "    {n}{}{r} -> {n}{}{r}  {dim}({}, from {}){r}",
                s.header, s.to, s.shape, s.sources
            );
        }
    }

    for note in &view.notes {
        let _ = writeln!(o, "  {warn}note: {note}{r}");
    }
    o
}

/// One per-app collection line: the overlay's own entries, then what it inherits.
///
/// `own` arrives already rendered (each entry carries its own spans), because what identifies an
/// entry differs per collection — a variable's name, a bind's path and mode, a package's name and
/// backend. Measured before choosing to join them on one line: across every shipped bundle and
/// profile the widest of these is six packages and four variables, so they fit. The allowlist,
/// whose rules run to seventy characters each, is listed one per line instead.
///
/// The inherited tail is dim (those entries live in the baseline `sbx config show`) and is dropped
/// when there are none: `· inherits 0 baseline` is a sentence about nothing.
fn collection_list(own: &[String], inherited: usize, pal: &style::Palette) -> String {
    let (dim, r) = (pal.dim, pal.reset);
    let head = if own.is_empty() {
        format!("{dim}(none){r}")
    } else {
        own.join(", ")
    };
    if inherited == 0 {
        head
    } else {
        format!("{head}  {dim}· inherits {inherited} baseline{r}")
    }
}

/// A package's compact identity for the collection line: its name, its backend, and — in the
/// caution hue — whether it was withheld. The backend is there because it decides *how* the app
/// gets the thing (host store, in-cage fetch, downloaded artifact); the withheld marker is there
/// because a package that will not be installed must never read like one that will.
fn package_name_tag(p: &config::view::PackageView, pal: &style::Palette) -> String {
    let (n, warn, dim, r) = (pal.name, pal.warn, pal.dim, pal.reset);
    match p.withheld_reason {
        Some(_) => format!("{n}{}{r} {warn}({}, withheld){r}", p.name, p.backend),
        None => format!("{n}{}{r} {dim}({}){r}", p.name, p.backend),
    }
}

/// One `service:` line: the name, the command it runs, and the two qualifiers that change whether
/// and when it runs. Shared by the baseline section (four spaces) and an app overlay's expansion
/// (eight), so the two render identically and cannot drift.
///
/// The readiness gate is shown because its absence is the interesting half: a service with no gate
/// means the app starts without waiting for it, which is what someone debugging a race needs to
/// read. The enable condition is shown because it is the switch — the way to turn this off for one
/// launch without editing anything.
fn service_line(s: &config::view::ServiceView, pal: &style::Palette, indent: &str) -> String {
    let (n, dim, r) = (pal.name, pal.dim, pal.reset);
    let mut line = format!("{indent}{n}{}{r} {}", s.name, s.cmd);
    if let Some(ready) = &s.ready {
        line.push_str(&format!(
            " {dim}(waits for :{} up to {}s){r}",
            ready.tcp, ready.timeout_secs
        ));
    }
    if let Some(cond) = &s.enable {
        line.push_str(&format!(" {dim}[only when {cond}]{r}"));
    }
    line
}

/// One package's detail line, indented by `indent`: `<name> -> <backend>:<locator>  (<detail>)`,
/// with the trust verdict and any `flake:` pin folded in. A withheld package takes the caution hue
/// and carries its reason; an admitted `flake:` package shows its pinned revision and `pinned`, or
/// `floating` when unpinned; every other backend shows its plain realisation. Shared by the
/// baseline `packages` section (indented four spaces) and an app overlay's `--details` expansion
/// (eight), so the two render identically and cannot drift. The identifier rides the name span, a
/// secondary detail is dimmed, a withheld reason is yellow — every span empty under a non-terminal.
fn package_line(p: &config::view::PackageView, pal: &style::Palette, indent: &str) -> String {
    let (n, warn, dim, r) = (pal.name, pal.warn, pal.dim, pal.reset);
    match &p.withheld_reason {
        Some(reason) => format!(
            "{indent}{n}{}{r} -> {}:{}  {warn}(withheld: {reason}){r}",
            p.name, p.backend, p.locator
        ),
        None => match &p.pinned_rev {
            Some(rev) => format!(
                "{indent}{n}{}{r} -> {}:{}  {dim}@ {} ({}, pinned){r}",
                p.name,
                p.backend,
                p.locator,
                short_rev(rev),
                p.realised
            ),
            None if p.backend == "flake" => format!(
                "{indent}{n}{}{r} -> {}:{}  {dim}({}, floating){r}",
                p.name, p.backend, p.locator, p.realised
            ),
            None => format!(
                "{indent}{n}{}{r} -> {}:{}  {dim}({}){r}",
                p.name, p.backend, p.locator, p.realised
            ),
        },
    }
}

/// One channel line's text (without the colored label): `<source> @ <short-rev>  (<origin>)`, or
/// `<source>  (<origin>)` when no revision has been locked. The source rides the name span (it is
/// the channel identifier), the shortened revision is dimmed (secondary detail), and the origin —
/// the per-channel provenance — is hued by level like every other provenance tag (default gray,
/// global cyan, project green), so a channel reads consistently with its neighbors while keeping
/// its richer wording (`project pin`). The revision is shortened here, a presentation choice; the
/// view model carries the full revision.
fn channel_text(c: &config::view::ChannelView, pal: &style::Palette) -> String {
    let (n, dim, r) = (pal.name, pal.dim, pal.reset);
    let (_, span) = provenance_parts(channel_origin_kind(&c.origin), pal);
    match &c.locked_rev {
        Some(rev) => format!(
            "{n}{}{r} @ {dim}{}{r}  ({span}{}{r})",
            c.source,
            short_rev(rev),
            c.origin
        ),
        None => format!("{n}{}{r}  ({span}{}{r})", c.source, c.origin),
    }
}

/// Map a channel's origin *label* to its provenance level for coloring. The channel view carries
/// its origin as the richer display string `store::Origin::label` emits (`default`/`global`/`project
/// pin`), a closed, stable set; this colors it on the same gray/cyan/green scale as the other
/// provenance tags. The coupling to those exact labels is pinned by a test that routes the real
/// `Origin::label()` strings through here, so a rename fails loudly rather than silently degrading a
/// channel's origin to the dim default — which is also the safe fallback for any unrecognized label.
fn channel_origin_kind(label: &str) -> config::view::ProvenanceView {
    use config::view::ProvenanceView;
    match label {
        "global" => ProvenanceView::Global,
        "project pin" => ProvenanceView::Project,
        _ => ProvenanceView::Default,
    }
}

/// Rewrite a dotted `key` to address it under app `name`'s table — the `--app <name>` sugar, so
/// `set --app demo network shared` writes `app.demo.network`. The name keys a single TOML table
/// segment, and the segment splitter does not handle quoting, so a name with a `.` (which is a
/// valid app name otherwise) cannot be addressed this way — it is edited directly with `sbx config
/// edit`. A name that no app could ever carry is rejected outright.
fn app_prefixed_key(name: &str, key: &str) -> Result<String, String> {
    if name.contains('.') {
        return Err(format!(
            "an app name containing `.` (`{name}`) cannot be addressed with `--app`; \
             edit it directly with `sbx config edit`"
        ));
    }
    if !config::is_valid_app_name(name) {
        return Err(format!("invalid app name `{name}`: 1–64 of [A-Za-z0-9._-]"));
    }
    Ok(format!("app.{name}.{key}"))
}

/// Print the usage synopsis for a `config` verb and return the usage exit code.
fn config_usage(verb: &str) -> ExitCode {
    diag::error(&format!(
        "sbx: usage: {}",
        help::synopsis_of(&["config", verb])
    ));
    ExitCode::from(2)
}

/// `sbx config get <key>`: print the value declared at a dotted key in the target layer file
/// (`--local` by default). This reads the *raw declared* value in that one file; for the
/// *effective resolved* value across layers, use `sbx config show` / `sbx config show --json`. An
/// unset key OR a read/parse error both exit 1 (each prints a distinct stderr line saying which); a
/// usage problem exits 2.
fn config_get(args: &[OsString]) -> ExitCode {
    let ScopeArgs {
        positionals,
        scope,
        app,
        ..
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            diag::error(&format!("sbx: config get: {e}"));
            return config_usage("get");
        }
    };
    if positionals.len() != 1 {
        return config_usage("get");
    }
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let (path, key, _gated) =
        match resolve_key_target("get", &scope, app.as_deref(), &positionals[0], &cwd) {
            Ok(t) => t,
            Err(code) => return code,
        };
    match config::manage::get(&path, &key) {
        Ok(Some(v)) => {
            println!("{v}");
            ExitCode::SUCCESS
        }
        Ok(None) => {
            diag::error(&format!(
                "sbx: config: `{}` is not set in {}",
                key,
                path.display()
            ));
            ExitCode::from(1)
        }
        Err(e) => {
            diag::error(&format!("sbx: config: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// Reject `--app` on a verb that takes no key (`path` prints a file path; `edit` opens the whole
/// file) — there is nothing for the app rewrite to apply to. Returns the usage exit code when an
/// `--app` was passed, else `None`.
fn reject_app(verb: &str, app: &Option<String>) -> Option<ExitCode> {
    if app.is_some() {
        diag::error(&format!(
            "sbx: config {verb}: `--app` does not apply to `{verb}` (it takes no key)"
        ));
        Some(config_usage(verb))
    } else {
        None
    }
}

/// Whether a write to this scope passes a trust gate at all.
///
/// The global config is trusted **by location**: the loader consults no marker for it, so one written
/// there is never read back. Everything else a write can target (a project `.sbx.toml`, an explicit
/// `-c` file) is hashed and gated.
///
/// One definition, shared by the key-writing verbs and by `edit`, because a second one is exactly how
/// `edit` came to write a marker nothing reads and report a gate that does not exist.
fn scope_is_gated(scope: &config::manage::Scope) -> bool {
    !matches!(scope, config::manage::Scope::Global)
}

/// Read the trust verdict for a write, **before** the write happens, and refuse the one write that
/// would bless bytes the user has never approved.
///
/// Two answers in one pass, because both come from the same read and both must precede the edit:
///
/// - The returned `was_trusted` is what [`report_write_trust`] needs to say whether this edit
///   re-armed a gate. It has to be read first: the write changes the file, and so its verdict.
/// - `--trust` on a file that exists and is not trusted is **refused** (exit 2), because the flag
///   blesses the whole current file — every security field in it, including the ones the user has
///   not read. It is the same admission [`crate::local_save_permitted`] applies to `sbx net allow
///   --local`, and calling that function is the point: one definition of when sbx may bless.
///
/// The refusal lands before the edit deliberately. Writing and *then* declining to bless would leave
/// a modified, untrusted file — worse than either outcome, since the user must now review bytes sbx
/// changed under them.
///
/// Scope decides the gate, not the verb: a `-c <file>` target carries a trust marker like any
/// project config, so it is admitted the same way. Only the global config and the app profiles are
/// exempt, and they are exempt because they are trusted by *location* — there is no marker to bless.
fn admit_config_write(
    verb: &str,
    path: &Path,
    gated: bool,
    trust_flag: bool,
    store_dir: Option<&Path>,
) -> Result<bool, ExitCode> {
    if !gated {
        return Ok(false);
    }
    // No store means no marker can be read and none can be written: `--trust` cannot bless anything,
    // which `report_write_trust` says in its own words. Nothing to admit.
    let Some(dir) = store_dir else {
        return Ok(false);
    };
    let state = trust::state(dir, path);
    if trust_flag && !crate::local_save_permitted(path.exists(), state) {
        // The two refused states read very differently to whoever hit them. "Never trusted" is a
        // file you have not vetted; "changed since" is one you *did* vet, whose current bytes are
        // not the ones you approved — and being told it "is not trusted" there invites the honest
        // objection that you trusted it yourself. Name the edit instead.
        let why = if state == trust::TrustState::Changed {
            "changed since you trusted it"
        } else {
            "is not trusted"
        };
        diag::error(&format!(
            "sbx: config {verb}: {} {why} — `--trust` blesses the whole file, \
             including what you have not read",
            path.display()
        ));
        diag::hint(&format!(
            "       review it and run `sbx trust {}`, then retry — or use `sbx config edit --trust`, \
             which opens the file first",
            path.display()
        ));
        return Err(ExitCode::from(2));
    }
    Ok(state == trust::TrustState::Trusted)
}

/// Resolve the file a key-taking verb (`get`/`set`/`unset`) targets and the dotted key within it,
/// applying the `--app <name>` routing and reporting whether the target is trust-gated.
///
/// The routing mirrors `sbx net … -a <name>`: a **global** app lives in its own profile file
/// `apps/<name>.toml` with **top-level** keys, so the key is used as-is; an app declared **inline**
/// (a project `.sbx.toml` or a `-c` file) is addressed under its `app.<name>.` table. The name
/// asymmetry is deliberate, not a bug: a `.`-containing app name is addressable at `-g` (it keys the
/// profile *filename*) but rejected inline (the dotted-key splitter does not handle a quoted segment).
///
/// The returned `gated` flag drives the trust note: the global config and the app profiles under
/// `apps/` are trusted **by location**, so a write to either is never gated (and never re-arms a trust
/// marker); a project (or explicit `-c`) file is. Any resolution error is already reported to stderr,
/// so the caller just returns the carried exit code.
fn resolve_key_target(
    verb: &str,
    scope: &config::manage::Scope,
    app: Option<&str>,
    raw_key: &str,
    cwd: &Path,
) -> Result<(PathBuf, String, bool), ExitCode> {
    use config::manage::{self, Scope};
    let gated = scope_is_gated(scope);
    let scope_path = |scope: &Scope| {
        manage::scope_path(scope, cwd).map_err(|e| {
            diag::error(&format!("sbx: config: {e}"));
            ExitCode::FAILURE
        })
    };
    match (app, scope) {
        (None, _) => Ok((scope_path(scope)?, raw_key.to_string(), gated)),
        (Some(name), Scope::Global) => {
            // A global app is its own profile file with top-level keys. The name keys that
            // filename, so validate it (anti-traversal) the way `sbx net … -a <name> -g` does.
            if !config::is_valid_app_name(name) {
                diag::error(&format!("sbx: config {verb}: invalid app name `{name}`"));
                return Err(config_usage(verb));
            }
            let path = manage::scope_app_path(scope, cwd, name).map_err(|e| {
                diag::error(&format!("sbx: config: {e}"));
                ExitCode::FAILURE
            })?;
            Ok((path, raw_key.to_string(), false))
        }
        (Some(name), _) => {
            // An inline app (project `.sbx.toml` or a `-c` file) is addressed under `app.<name>.`.
            let key = app_prefixed_key(name, raw_key).map_err(|e| {
                diag::error(&format!("sbx: config {verb}: {e}"));
                config_usage(verb)
            })?;
            Ok((scope_path(scope)?, key, gated))
        }
    }
}

/// `sbx config set <key> <value>`: write a string value at a dotted key in the target layer file
/// (`--local` by default), preserving the rest of the file's comments and formatting. Because the
/// trust gate hashes the whole file, any edit re-arms it — so a write to a trusted file warns that
/// its security fields will not apply until `sbx trust`, and `--trust` re-trusts in one step.
fn config_set(args: &[OsString]) -> ExitCode {
    let ScopeArgs {
        positionals,
        scope,
        trust,
        app,
        ..
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            diag::error(&format!("sbx: config set: {e}"));
            return config_usage("set");
        }
    };
    if positionals.len() != 2 {
        return config_usage("set");
    }
    let val = &positionals[1];
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let (path, key, gated) =
        match resolve_key_target("set", &scope, app.as_deref(), &positionals[0], &cwd) {
            Ok(t) => t,
            Err(code) => return code,
        };
    let store_dir = trust::default_store_dir();
    let was_trusted = match admit_config_write("set", &path, gated, trust, store_dir.as_deref()) {
        Ok(t) => t,
        Err(code) => return code,
    };

    match config::manage::set(&path, &key, val) {
        Ok(created) => {
            let verb = if created { "set" } else { "updated" };
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_config_write(verb, &key, &path, &pal));
            report_write_trust(&path, &key, was_trusted, trust, store_dir.as_deref(), gated);
            ExitCode::SUCCESS
        }
        Err(e) => {
            diag::error(&format!("sbx: config: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// Which end of a list `config add`/`config rm` works on. The two verbs differ only in the call and
/// the words they print, so they share one implementation — the scope parsing, the trust capture,
/// and the no-op reporting are the parts that must not drift between them.
#[derive(Clone, Copy)]
enum ListEdit {
    Add,
    Remove,
}

/// `sbx config add <key> <entry>` / `sbx config rm <key> <entry>`: edit ONE entry of a list field,
/// leaving the rest of the list (and the file's comments) alone. This is the ergonomic half of
/// `set`, which replaces a whole list: adding a mask or a host is the common act, and doing it by
/// rewriting the entire array invites dropping an entry by mistake.
///
/// An entry already present (or already absent, for `rm`) leaves the file untouched and says so.
/// That is a security property, not a nicety: an unchanged file keeps its trust marker, so repeating
/// a command cannot disarm a trusted config's security fields behind the user's back.
fn config_list_edit(args: &[OsString], op: ListEdit) -> ExitCode {
    let verb = match op {
        ListEdit::Add => "add",
        ListEdit::Remove => "rm",
    };
    let ScopeArgs {
        positionals,
        scope,
        trust,
        app,
        ..
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            diag::error(&format!("sbx: config {verb}: {e}"));
            return config_usage(verb);
        }
    };
    if positionals.len() != 2 {
        return config_usage(verb);
    }
    let entry = &positionals[1];
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let (path, key, gated) =
        match resolve_key_target(verb, &scope, app.as_deref(), &positionals[0], &cwd) {
            Ok(t) => t,
            Err(code) => return code,
        };
    let store_dir = trust::default_store_dir();
    let was_trusted = match admit_config_write(verb, &path, gated, trust, store_dir.as_deref()) {
        Ok(t) => t,
        Err(code) => return code,
    };

    let outcome = match op {
        ListEdit::Add => config::manage::add(&path, &key, entry),
        ListEdit::Remove => config::manage::remove(&path, &key, entry),
    };
    match outcome {
        Ok(true) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            let (done, preposition) = match op {
                ListEdit::Add => ("added", "to"),
                ListEdit::Remove => ("removed", "from"),
            };
            println!(
                "{}",
                render_list_edit(done, preposition, entry, &key, &path, &pal)
            );
            report_write_trust(&path, &key, was_trusted, trust, store_dir.as_deref(), gated);
            ExitCode::SUCCESS
        }
        Ok(false) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            let why = match op {
                ListEdit::Add => "is already in",
                ListEdit::Remove => "is not in",
            };
            println!("{}", render_list_unchanged(entry, why, &key, &path, &pal));
            ExitCode::SUCCESS
        }
        Err(e) => {
            diag::error(&format!("sbx: config: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// `sbx config unset <key>`: remove a dotted key from the target layer file. Removing a key that
/// was not set is a no-op (exit 0) that changes nothing — so it never re-arms trust. A removal
/// that does change a trusted file re-arms it, with the same warning as `set`.
fn config_unset(args: &[OsString]) -> ExitCode {
    let ScopeArgs {
        positionals,
        scope,
        trust,
        app,
        ..
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            diag::error(&format!("sbx: config unset: {e}"));
            return config_usage("unset");
        }
    };
    if positionals.len() != 1 {
        return config_usage("unset");
    }
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let (path, key, gated) =
        match resolve_key_target("unset", &scope, app.as_deref(), &positionals[0], &cwd) {
            Ok(t) => t,
            Err(code) => return code,
        };
    let store_dir = trust::default_store_dir();
    let was_trusted = match admit_config_write("unset", &path, gated, trust, store_dir.as_deref()) {
        Ok(t) => t,
        Err(code) => return code,
    };

    match config::manage::unset(&path, &key) {
        Ok(true) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_config_write("unset", &key, &path, &pal));
            report_write_trust(&path, &key, was_trusted, trust, store_dir.as_deref(), gated);
            ExitCode::SUCCESS
        }
        Ok(false) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_config_unchanged(&key, &path, &pal));
            ExitCode::SUCCESS
        }
        Err(e) => {
            diag::error(&format!("sbx: config: {e}"));
            ExitCode::FAILURE
        }
    }
}

fn config_path_cmd(args: &[OsString]) -> ExitCode {
    let ScopeArgs {
        positionals,
        scope,
        scope_explicit,
        app,
        ..
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            diag::error(&format!("sbx: config path: {e}"));
            return config_usage("path");
        }
    };
    if let Some(code) = reject_app("path", &app) {
        return code;
    }
    if !positionals.is_empty() {
        return config_usage("path");
    }
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };

    if !scope_explicit {
        // The useful default: the resolution overview. A successful listing even when nothing
        // exists yet — that is the common first-run state, not an error.
        let layers = config::manage::resolution_layers(&cwd);
        let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
        print!("{}", render_resolution_layers(&layers, &pal));
        return ExitCode::SUCCESS;
    }

    match config::manage::scope_path(&scope, &cwd) {
        Ok(p) => {
            println!("{}", p.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            diag::error(&format!("sbx: config: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// Render the config-file resolution overview: each layer in order (global base, project overlay)
/// with its path and whether the file is present. Returned as a string so a test can assert it
/// without a terminal. The label column is padded as plain text before color is applied, so the
/// path column stays aligned regardless of styling.
fn render_resolution_layers(layers: &[config::manage::Layer], pal: &style::Palette) -> String {
    use std::fmt::Write as _;
    let (h, nm, ok, dim, r) = (pal.head, pal.name, pal.ok, pal.dim, pal.reset);
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{h}config files in resolution order{r} \
         {dim}(global is the base; the project overlays it){r}"
    );
    for layer in layers {
        let label = format!("{:<8}", layer.label);
        match &layer.path {
            Some(p) => {
                let (state, hue) = if p.try_exists().unwrap_or(false) {
                    ("present", ok)
                } else {
                    ("absent", dim)
                };
                let _ = writeln!(o, "  {nm}{label}{r}{}  {hue}({state}){r}", p.display());
            }
            None => {
                let _ = writeln!(o, "  {nm}{label}{r}{dim}(no config directory){r}");
            }
        }
    }
    let _ = writeln!(
        o,
        "{}",
        style::dim_prose("for the resolved values, see `sbx config show`.", pal)
    );
    o
}

/// `sbx config edit`: open the target layer file in `$VISUAL`/`$EDITOR` (falling back to `vi`).
/// The escape hatch for what `set` does not handle — arrays, secrets, and app tables. Runs through
/// a shell so an editor carrying arguments (e.g. `code --wait`) works, with the path passed as a
/// positional so it needs no quoting. Because the trust gate hashes the whole file, an edit that
/// changes a trusted file re-arms it — detected after the editor exits (the verdict becomes
/// Changed) and warned, or applied at once with `--trust`.
///
/// All of that is about a **gated** target. The global config is trusted by location, so it has no
/// marker to re-arm and none to write: `--trust` there is answered with the note the key-writing
/// verbs give, and nothing is stored. See [`scope_is_gated`].
fn config_edit(args: &[OsString]) -> ExitCode {
    let ScopeArgs {
        positionals,
        scope,
        trust: trust_flag,
        app,
        ..
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            diag::error(&format!("sbx: config edit: {e}"));
            return config_usage("edit");
        }
    };
    if let Some(code) = reject_app("edit", &app) {
        return code;
    }
    if !positionals.is_empty() {
        return config_usage("edit");
    }
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let path = match config::manage::scope_path(&scope, &cwd) {
        Ok(p) => p,
        Err(e) => {
            diag::error(&format!("sbx: config: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // Make sure the parent directory exists so the editor can save a new file (the global config
    // directory may not exist yet).
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        diag::error(&format!(
            "sbx: config: cannot create {}: {e}",
            parent.display()
        ));
        return ExitCode::FAILURE;
    }

    // Whether this target passes a trust gate at all. A non-gated one (the global config) carries no
    // marker: writing one would leave a file nothing ever reads, and reporting one would announce a
    // gate that does not exist. Both are settled before the editor runs, so the answer cannot depend
    // on what was saved.
    //
    // This verb deliberately skips [`admit_config_write`]: `--trust` here blesses a file the editor
    // just showed, which is the one case where blessing bytes sbx did not author is what the user
    // asked for. It is the escape hatch the other four verbs point at when they refuse.
    let gated = scope_is_gated(&scope);
    let store_dir = trust::default_store_dir();
    let was_trusted = gated
        && store_dir
            .as_deref()
            .is_some_and(|d| trust::state(d, &path) == trust::TrustState::Trusted);

    let editor_os = std::env::var_os("VISUAL")
        .or_else(|| std::env::var_os("EDITOR"))
        .unwrap_or_else(|| OsString::from("vi"));
    let editor = editor_os.to_string_lossy();
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} \"$@\""))
        .arg("sh")
        .arg(&path)
        .status();
    match status {
        // The editor ran (whatever its exit) — the file is now whatever the user saved.
        Ok(_) => {}
        Err(e) => {
            diag::error(&format!(
                "sbx: config: could not launch the editor `{editor}`: {e}"
            ));
            return ExitCode::FAILURE;
        }
    }

    if !gated {
        // Say so only when `--trust` was asked for: the flag is what carries the mistaken belief,
        // and an unasked-for note on every global edit would be noise. The same sentence the
        // key-writing verbs use, since it is the same fact.
        if trust_flag {
            diag::note(&format!(
                "{} is trusted by location; `--trust` is not needed",
                path.display()
            ));
        }
    } else if trust_flag {
        match store_dir.as_deref() {
            Some(dir) => match trust::trust(dir, &path) {
                Ok(()) => {
                    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
                    println!("{}", render_trusted_whole_file(&path, &pal));
                }
                Err(e) => diag::warn(&format!("could not trust {}: {e}", path.display())),
            },
            None => diag::warn("no trust store available; cannot --trust"),
        }
    } else if was_trusted {
        // Only warn if the edit actually changed the file (the verdict is now Changed).
        let now = store_dir.as_deref().map(|d| trust::state(d, &path));
        if now == Some(trust::TrustState::Changed) {
            diag::warn(&format!(
                "your edit re-armed the trust gate for {}",
                path.display()
            ));
            diag::hint(&format!(
                "       run `sbx trust {}` to re-apply its security fields",
                path.display()
            ));
        }
    }
    ExitCode::SUCCESS
}

/// Report the trust consequence of a write, the load-bearing UX of `set`/`unset`: the whole-file
/// trust hash means any edit re-arms the gate. `--trust` re-trusts in one step (blessing the whole
/// current file); otherwise a write to a previously-trusted file warns that its security fields
/// will not apply until `sbx trust`, and a write of a security field to an untrusted file notes it
/// needs trust to take effect. A free `env` write to an untrusted file needs neither.
fn report_write_trust(
    path: &Path,
    key: &str,
    was_trusted: bool,
    trust_flag: bool,
    store_dir: Option<&Path>,
    gated: bool,
) {
    // The global config and the app profiles under `apps/` are trusted **by location** — they carry
    // no per-file trust marker, so a write never re-arms a gate and needs no `sbx trust`. Reporting
    // one would be a false positive (the field applies as soon as the file is read), so say nothing —
    // beyond noting that an explicit `--trust` is unnecessary here.
    if !gated {
        if trust_flag {
            diag::note(&format!(
                "{} is trusted by location; `--trust` is not needed",
                path.display()
            ));
        }
        return;
    }
    if trust_flag {
        match store_dir {
            Some(dir) => match trust::trust(dir, path) {
                Ok(()) => {
                    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
                    println!("{}", render_trusted_whole_file(path, &pal));
                }
                Err(e) => diag::warn(&format!("could not trust {}: {e}", path.display())),
            },
            None => diag::warn("no trust store available; cannot --trust"),
        }
        return;
    }
    if was_trusted {
        diag::warn(&format!(
            "this edit re-armed the trust gate for {}",
            path.display()
        ));
        diag::hint(&format!(
            "       its security fields will not apply until you run `sbx trust {}`",
            path.display()
        ));
    } else if is_security_key(key) {
        diag::note(&format!(
            "`{key}` is a security field; it applies only once {} is trusted (`sbx trust`)",
            path.display()
        ));
    }
}

/// Whether a dotted config key names a security-relevant field. The only field applied without
/// trust (minus the untrusted-env denylist) is the free `env` table — both the baseline `env.*`
/// and an app's `app.<name>.env.*`; everything else is gated, so setting one on an untrusted file
/// is worth a note.
fn is_security_key(key: &str) -> bool {
    let segs: Vec<&str> = key.split('.').collect();
    !matches!(segs.as_slice(), ["env", ..] | ["app", _, "env", ..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store;

    #[test]
    fn is_security_key_treats_only_the_env_table_as_free() {
        // the free `env` table — baseline and per-app — is not gated
        assert!(!is_security_key("env.FOO"));
        assert!(!is_security_key("env"));
        assert!(!is_security_key("app.demo-app.env.FOO"));
        // everything else is a security field, including an app's own security overlay
        assert!(is_security_key("binds"));
        assert!(is_security_key("network"));
        assert!(is_security_key("app.demo-app.network"));
        assert!(is_security_key("app.demo-app.cmd"));
        // a bare app table (no field) is gated too
        assert!(is_security_key("app.demo-app"));
    }

    #[test]
    fn resolution_layers_render_marks_presence_and_stays_plain_uncolored() {
        use config::manage::Layer;
        let tmp = crate::testutil::TmpDir::new();
        let present = tmp.path().join("here.toml");
        std::fs::write(&present, "x = 1\n").unwrap();
        let absent = tmp.path().join("gone.toml");
        let layers = vec![
            Layer {
                label: "global",
                path: Some(absent.clone()),
            },
            Layer {
                label: "project",
                path: Some(present.clone()),
            },
        ];
        let plain = render_resolution_layers(&layers, &style::Palette::plain());
        assert!(plain.contains("resolution order"), "header:\n{plain}");
        assert!(
            plain.contains(&format!("{}  (absent)", absent.display())),
            "an absent layer must be marked absent:\n{plain}"
        );
        assert!(
            plain.contains(&format!("{}  (present)", present.display())),
            "a present layer must be marked present:\n{plain}"
        );
        // The colored path wraps the marker in its hue and resets it — pad-then-color keeps the
        // path column aligned, which only ever shows here.
        let c = style::Palette::colored();
        let colored = render_resolution_layers(&layers, &c);
        assert!(
            colored.contains(&format!("{}(present){}", c.ok, c.reset)),
            "a present marker must be wrapped in the ok span and reset:\n{colored}"
        );
    }

    #[test]
    fn resolution_layers_render_handles_a_missing_config_directory() {
        // The global layer can have no path (no $XDG_CONFIG_HOME/$HOME) — it must not error the
        // listing, just say so.
        use config::manage::Layer;
        let layers = vec![Layer {
            label: "global",
            path: None,
        }];
        let plain = render_resolution_layers(&layers, &style::Palette::plain());
        assert!(
            plain.contains("global") && plain.contains("(no config directory)"),
            "a pathless global layer must read as no config directory:\n{plain}"
        );
    }

    #[test]
    fn resolve_key_target_routes_by_scope_and_app() {
        // The routing behind `config get/set/unset`. Env-independent arms are asserted here; the
        // `--app <name> --global` profile arm resolves the config home, so it is covered by the
        // `config show --app` / profile integration tests instead (same convention as
        // `egress_write_target` above).
        use config::manage::Scope;
        let cwd = std::path::Path::new("/some/cwd");
        let proj = cwd.join(config::PROJECT_CONFIG);

        // No app: the raw key, the scope's file, and gated for a project write.
        let (path, key, gated) =
            resolve_key_target("set", &Scope::Local, None, "network", cwd).unwrap();
        assert_eq!((path, key.as_str(), gated), (proj.clone(), "network", true));

        // An inline app (project scope) addresses `app.<name>.<key>` and stays gated.
        let (path, key, gated) =
            resolve_key_target("set", &Scope::Local, Some("demo"), "network", cwd).unwrap();
        assert_eq!(
            (path, key.as_str(), gated),
            (proj, "app.demo.network", true)
        );

        // A `-c` file with an app: the file itself, the prefixed key, still gated (not trusted by
        // location).
        let explicit = std::path::PathBuf::from("/etc/sbx.toml");
        let (path, key, gated) = resolve_key_target(
            "set",
            &Scope::File(explicit.clone()),
            Some("demo"),
            "cmd",
            cwd,
        )
        .unwrap();
        assert_eq!(
            (path, key.as_str(), gated),
            (explicit, "app.demo.cmd", true)
        );

        // An app name with a `.` cannot be addressed inline (the dotted-key splitter is naive).
        assert!(
            resolve_key_target("set", &Scope::Local, Some("a.b"), "network", cwd).is_err(),
            "a dotted app name is rejected inline"
        );

        // An invalid charset can never key a profile filename (validated before the config home is
        // even resolved, so this arm stays env-independent). A name that merely coincides with a
        // subcommand verb (`import`, `show`, …) is valid — launching goes through `sbx app run` —
        // so that arm resolves the config home and is covered by the profile integration tests.
        assert!(
            resolve_key_target("set", &Scope::Global, Some("bad/name"), "network", cwd).is_err(),
            "an invalid app name cannot name a global-app profile"
        );
    }

    /// A representative resolved view: an untrusted project that withholds a `nix:` package and its
    /// mise file, a project-pinned base channel (with a locked revision) beside the default engine,
    /// and an allowlist carrying a deny rule. Built by hand so the render tests need no I/O.
    fn sample_config_view() -> config::view::ConfigView {
        use config::view::*;
        ConfigView {
            open: vec![],
            service: vec![],
            plugins: vec![],
            fs_deny: Vec::new(),
            tasks: Vec::new(),
            fs_origin: Default::default(),
            fs_readonly: Vec::new(),
            notify: Default::default(),
            notify_origin: Default::default(),
            ssh_agent_confirm: false,
            cwd: "/proj".into(),
            env: vec![EnvVar {
                key: "EDITOR".into(),
                value: "vim".into(),
                layer: Some(ProvenanceView::Project),
            }],
            binds: vec![BindView {
                path: "/data".into(),
                writable: false,
                layer: Some(ProvenanceView::Global),
            }],
            packages: vec![PackageView {
                name: "jq".into(),
                backend: "nix".into(),
                locator: "jq".into(),
                realised: "host-side, durable".into(),
                trusted: false,
                withheld_reason: Some("the project is untrusted".into()),
                pinned_rev: None,
            }],
            mise: Some(MiseView {
                name: ".mise.toml".into(),
                trusted: false,
                withheld_reason: Some("the project is untrusted".into()),
            }),
            tools: ToolsView::default(),
            nixpkgs: ChannelView {
                source: "nixos-23.11".into(),
                origin: "project pin".into(),
                locked_rev: Some("9ae611a455b90cf061d8f332b977e387bda8e1ca".into()),
            },
            engine: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            network: NetworkView::Allowlist {
                default_action: config::view::NetDefaultView::Deny,
                ask_timeout: None,
                ask_notice: None,
                allow: vec!["github.com".into()],
                deny: vec!["evil.com".into()],
                mute: vec![],
                http2: vec![],
                capture: "off".to_string(),
                capture_max_kb: None,
                pool: true,
                ca_roots: true,
                dns_cache_ttl: None,
                idle_timeout: None,
                max_connections: None,
                body_max_mb: None,
                builtin: vec!["cache.nixos.org".into()],
            },
            network_origin: ProvenanceView::Project,
            egress_stats: true,
            redact_min_len: crate::sandbox::redact::MIN_LEN_DEFAULT,
            redact_min_len_origin: Default::default(),
            proc: Default::default(),
            proc_origin: Default::default(),
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Default,
            audio_origin: ProvenanceView::Default,
            dbus_origin: ProvenanceView::Default,
            forward: vec![],
            forward_origin: ProvenanceView::Default,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Default,
            devices: vec![],
            devices_origin: ProvenanceView::Default,
            ssh_agent: vec![],
            brokers: Vec::new(),
            ssh_agent_origin: Default::default(),
            limits: Default::default(),
            secrets: vec![],
            apps: vec![],
            warnings: vec![],
        }
    }

    /// A section renders on its own, which is the point of splitting the renderer up: before, the
    /// only way to ask "what does `limits` print when nothing overrode it?" was to build a whole
    /// view, render all fifty sections, and search the result.
    ///
    /// `limits` is the case worth pinning because **both** of its answers are meaningful: silence
    /// when every field is a built-in default (a config that tuned nothing must not grow a line
    /// saying so), and one line naming each field's own layer when any was overridden. A `contains`
    /// check on the whole render can see the second; only calling the section can see the first.
    #[test]
    fn the_limits_section_is_silent_until_a_layer_overrides_one() {
        use config::view::{LimitView, LimitsView, ProvenanceView};
        let plain = style::Palette::plain();
        let mut view = sample_config_view();

        view.limits = LimitsView {
            memory_high: LimitView {
                value: "80%".into(),
                origin: ProvenanceView::Default,
            },
            memory_max: LimitView {
                value: "90%".into(),
                origin: ProvenanceView::Default,
            },
            tasks_max: LimitView {
                value: "16384".into(),
                origin: ProvenanceView::Default,
            },
        };
        assert_eq!(
            limits_section(&view, &plain),
            None,
            "a config that tuned no limit must print no limits line"
        );

        view.limits.tasks_max = LimitView {
            value: "4096".into(),
            origin: ProvenanceView::Project,
        };
        let shown = limits_section(&view, &plain).expect("an overridden limit is shown");
        assert_eq!(
            shown,
            "  limits: MemoryHigh=80% (default), MemoryMax=90% (default), TasksMax=4096 (project)\n",
            "each field carries its own provenance, so the line says which one was tuned"
        );
    }

    /// The collection sections state their emptiness the same way, and nothing else checks it: the
    /// render assertions pin the absence of a `limits` and a `redact` line, but a `secrets`,
    /// `plugins`, `tasks` or `apps` header that started appearing on a config declaring none would
    /// pass every one of them. Calling the four with empty inputs is the only place that says a
    /// config which declared nothing announces nothing.
    ///
    /// `secrets` then carries the second half, compared whole rather than by fragment, because what
    /// it must print is exactly a locator: header, destination, shape and source name, and no value.
    #[test]
    fn a_collection_section_stays_silent_on_an_empty_collection() {
        let plain = style::Palette::plain();
        assert_eq!(secrets_section(&[], &plain), None, "no secret, no header");
        assert_eq!(plugins_section(&[], &plain), None, "no plugin, no header");
        assert_eq!(tasks_section(&[], &plain), None, "no task, no header");
        assert_eq!(
            apps_section(&[], &plain, true),
            None,
            "no app profile, no roster"
        );

        let secrets = vec![config::view::SecretView {
            header: "Authorization".into(),
            to: "https://api.example.com".into(),
            shape: "bearer".into(),
            sources: "env EXAMPLE_TOKEN".into(),
        }];
        assert_eq!(
            secrets_section(&secrets, &plain).expect("a declared secret is listed"),
            "  secrets (injected host-side by the egress proxy):\n    \
             Authorization -> https://api.example.com  (bearer, from env EXAMPLE_TOKEN)\n",
            "a credential is shown by destination and locator, never by value"
        );
    }

    #[test]
    fn config_render_is_plain_text_when_uncolored() {
        // The OFF path the `sbx config show` integration assertions stand on: empty spans, so the
        // wording and spacing are exactly today's — a withheld note, a channel line (with and
        // without a locked revision), and a deny rule.
        let out = render_config(&sample_config_view(), &style::Palette::plain(), false);
        assert!(
            out.contains("    jq -> nix:jq  (withheld: the project is untrusted)"),
            "{out}"
        );
        assert!(
            out.contains("  mise:  .mise.toml (withheld: the project is untrusted)"),
            "{out}"
        );
        assert!(
            out.contains("  nixpkgs: nixos-23.11 @ 9ae611a  (project pin)"),
            "{out}"
        );
        assert!(out.contains("  engine: nixos-unstable  (default)"), "{out}");
        assert!(out.contains("    deny  evil.com"), "{out}");
        // The free-field provenance tag is plain parenthesized text on its line.
        assert!(out.contains("    EDITOR=vim  (project)"), "{out}");
        assert!(out.contains("    /data  (global)"), "{out}");
        // A read-only bind carries no mode marker.
        assert!(
            !out.contains("/data (rw)"),
            "a read-only bind must not be marked:\n{out}"
        );
    }

    #[test]
    fn config_render_marks_a_writable_bind() {
        // The `(rw)` marker: a writable bind is flagged so a host write-through hole is
        // visible in `sbx config show`; the marker precedes the provenance tag. A read-only bind
        // (the default, covered above) carries none.
        let mut view = sample_config_view();
        view.binds = vec![config::view::BindView {
            path: "/data".into(),
            writable: true,
            layer: Some(config::view::ProvenanceView::Global),
        }];
        let out = render_config(&view, &style::Palette::plain(), false);
        assert!(
            out.contains("    /data (rw)  (global)"),
            "a writable bind must be marked (rw) before its provenance tag:\n{out}"
        );
    }

    /// A broker is a host resource put in front of a cage, so the view leads with the **socket**:
    /// that path is the whole of what is exposed, and it is what a reader auditing the config is
    /// checking. The provenance tag is the policy's, since the socket is always the global
    /// config's.
    #[test]
    fn config_render_leads_a_broker_with_the_host_resource_it_exposes() {
        let mut view = sample_config_view();
        view.brokers = vec![config::view::BrokerView {
            name: "gpg-agent".into(),
            socket: "/run/user/1000/gnupg/S.gpg-agent".into(),
            allow: vec!["sign".into()],
            secret: Vec::new(),
            origin: config::view::ProvenanceView::Project,
        }];
        let out = render_config(&view, &style::Palette::plain(), false);
        let line = out
            .lines()
            .find(|l| l.contains("broker:"))
            .expect("the broker is shown");
        let socket_at = line
            .find("/run/user/1000/gnupg/S.gpg-agent")
            .expect("the socket is shown");
        let arrow_at = line
            .find('→')
            .expect("the socket is followed by the plugin it feeds");
        assert!(
            socket_at < arrow_at,
            "the socket leads, the plugin follows: {line}"
        );
        assert!(line.contains("sign"), "the policy is shown: {line}");
        assert!(line.contains("(project)"), "the policy's layer: {line}");
    }

    /// A config with no broker says nothing about brokers — the common case stays uncluttered.
    #[test]
    fn config_render_says_nothing_when_no_broker_is_bound() {
        let out = render_config(&sample_config_view(), &style::Palette::plain(), false);
        assert!(!out.contains("broker:"), "{out}");
    }

    #[test]
    fn config_render_colors_the_gating_outcome_and_the_channel_provenance() {
        // The ON path: a withheld value takes the warn hue (the trust gate dropped it), a channel's
        // provenance origin is hued by level (a project pin green) and its source rides the name
        // span, its short revision is dim, and the deny keyword is warn — the inheritance/gating
        // story a swapped hue would hide.
        let p = style::Palette::colored();
        let out = render_config(&sample_config_view(), &p, false);
        assert!(
            out.contains(&format!(
                "{}(withheld: the project is untrusted){}",
                p.warn, p.reset
            )),
            "a withheld package must take the warn hue:\n{out}"
        );
        assert!(
            out.contains(&format!("{}nixos-23.11{}", p.name, p.reset)),
            "a channel source must ride the name span:\n{out}"
        );
        assert!(
            out.contains(&format!("({}project pin{})", p.ok, p.reset)),
            "a channel origin must be hued by provenance level — a project pin is green:\n{out}"
        );
        assert!(
            out.contains(&format!("{}9ae611a{}", p.dim, p.reset)),
            "a locked revision must be dimmed:\n{out}"
        );
        assert!(
            out.contains(&format!("{}deny{}", p.warn, p.reset)),
            "the deny keyword must take the caution hue:\n{out}"
        );
        // The provenance tag is hued by level: a project source is green, a global source is cyan
        // (a default/inherited one stays dim). The env value here is project-supplied, the bind
        // global-supplied, so the two tags carry their respective hues.
        assert!(
            out.contains(&format!("{}(project){}", p.ok, p.reset)),
            "a project provenance tag must take the green hue:\n{out}"
        );
        assert!(
            out.contains(&format!("{}(global){}", p.name, p.reset)),
            "a global provenance tag must take the cyan hue:\n{out}"
        );
    }

    #[test]
    fn channel_origin_kind_tracks_the_real_store_origin_labels() {
        // `channel_origin_kind` colors by matching the channel's origin *label* — a string coupling
        // to `store::Origin::label()`. Route the REAL labels through it so a rename in store.rs
        // fails here loudly, instead of silently degrading that channel's origin to the dim default.
        use config::view::ProvenanceView;
        assert_eq!(
            channel_origin_kind(store::Origin::Default.label()),
            ProvenanceView::Default
        );
        assert_eq!(
            channel_origin_kind(store::Origin::Global.label()),
            ProvenanceView::Global
        );
        assert_eq!(
            channel_origin_kind(store::Origin::ProjectPin.label()),
            ProvenanceView::Project
        );
    }

    #[test]
    fn declared_operations_render_with_their_origin_and_no_command() {
        // The static view of `[task]`, and the reason it exists: `sbx task ls` reads a *running*
        // session, so a declared operation had no surface at all until a cage was launched. What it
        // must NOT print is the command — an operation is a fixed program plus a credential the
        // caller never holds, and putting that argv in the layered config view invites reading it as
        // something the user may edit here.
        use config::view::TaskView;
        let plain = style::Palette::plain();
        let mut view = sample_config_view();
        view.tasks = vec![
            TaskView {
                name: "build".into(),
                description: Some("Build the project".into()),
                origin: "project".into(),
            },
            TaskView {
                name: "deploy".into(),
                description: None,
                origin: "app:demo".into(),
            },
        ];
        let out = render_config(&view, &plain, false);
        assert!(
            out.contains("tasks (declared operations a cage may run):"),
            "the section is titled:\n{out}"
        );
        assert!(
            out.contains("build") && out.contains("Build the project") && out.contains("(project)"),
            "name, description and origin:\n{out}"
        );
        // An operation with no description still lists, with its origin — absent is not empty.
        assert!(
            out.contains("deploy") && out.contains("(app:demo)"),
            "a description-less operation still shows:\n{out}"
        );

        // No operations, no section: an empty heading would read like something was dropped.
        let mut none = sample_config_view();
        none.tasks = Vec::new();
        assert!(
            !render_config(&none, &plain, false).contains("tasks ("),
            "no section when nothing is declared"
        );
    }

    #[test]
    fn config_render_tags_the_network_and_gui_posture_with_their_origin() {
        use config::view::{GuiView, ProvenanceView};
        let plain = style::Palette::plain();

        // The headline of the provenance work: the always-shown `network` line names where its
        // posture came from. The sample's allowlist is project-supplied, so it reads `(project)`.
        let out = render_config(&sample_config_view(), &plain, false);
        assert!(
            out.contains("network: deny  (project)"),
            "the network posture must carry its project origin:\n{out}"
        );

        // A posture no config set reads `(default)` — the distinction the user could not see
        // before (is the network open because I chose it, or because nothing set it?).
        let mut view = sample_config_view();
        view.network = config::view::NetworkView::Shared;
        view.network_origin = ProvenanceView::Default;
        let out = render_config(&view, &plain, false);
        assert!(
            out.contains("network: shared (host network)  (default)"),
            "an unset network posture must read default:\n{out}"
        );

        // The GUI line, shown only when opened, names its origin too.
        view.gui = GuiView::Wayland;
        view.gui_origin = ProvenanceView::Global;
        let out = render_config(&view, &plain, false);
        assert!(
            out.contains("gui: wayland (exposure depends on your compositor)  (global)"),
            "the gui posture must carry its global origin:\n{out}"
        );
    }

    /// `pool`, `ca_roots` and `dns_cache_ttl` decide how a permitted request is carried, and a
    /// trusted layer can set any of them for a project that has no reason to look: no client sees
    /// whether its connection was reused or how old the address it reached was, and a trust store is
    /// read without being examined until the day a tool refuses its shape. So each is shown when a
    /// layer moved it off the product default, and stays out of the way when nothing did.
    #[test]
    fn config_render_shows_the_network_transport_settings_only_when_a_layer_set_them() {
        use config::view::NetworkView;
        let plain = style::Palette::plain();

        let out = render_config(&sample_config_view(), &plain, false);
        assert!(
            !out.contains("connection reuse")
                && !out.contains("dns cache")
                && !out.contains("cage ca"),
            "none earns a line at its default:\n{out}"
        );

        let mut view = sample_config_view();
        if let NetworkView::Allowlist {
            pool,
            ca_roots,
            dns_cache_ttl,
            ..
        } = &mut view.network
        {
            *pool = false;
            *ca_roots = false;
            *dns_cache_ttl = Some(30);
        }
        let out = render_config(&view, &plain, false);
        assert!(
            out.contains("connection reuse: off"),
            "a launch that gave up reuse must say so:\n{out}"
        );
        assert!(
            out.contains("cage ca: session CA only"),
            "a launch that dropped the public roots must say so:\n{out}"
        );
        assert!(
            out.contains("dns cache: 30s"),
            "a layer-set resolver cache must name its duration:\n{out}"
        );

        // Zero is a decision, not an absent value: it turns the cache off. A render that showed it
        // as `0s` would read as "cached for no time", which is the same thing said worse.
        if let NetworkView::Allowlist { dns_cache_ttl, .. } = &mut view.network {
            *dns_cache_ttl = Some(0);
        }
        let out = render_config(&view, &plain, false);
        assert!(
            out.contains("dns cache: off (every request re-resolves)"),
            "a disabled resolver cache must read as disabled:\n{out}"
        );
    }

    /// The baseline view's silence means "both are at their default", which only helps a reader who
    /// already knows what the defaults are. `--details` reports the effective posture instead, so
    /// the resolver cache a launch actually gets is a number on the screen rather than product
    /// knowledge the reader is assumed to have.
    #[test]
    fn config_render_details_names_the_transport_defaults_it_otherwise_leaves_silent() {
        use config::view::NetworkView;
        let plain = style::Palette::plain();

        let out = render_config(&sample_config_view(), &plain, true);
        assert!(
            out.contains("connection reuse: on"),
            "the reuse default must be named under --details:\n{out}"
        );
        for expected in [
            format!(
                "dns cache: {}s (built-in default;",
                crate::allowlist::DEFAULT_DNS_CACHE_TTL.as_secs()
            ),
            format!(
                "idle timeout: {}s (built-in default;",
                crate::allowlist::DEFAULT_IDLE_TIMEOUT.as_secs()
            ),
            format!(
                "max connections: {} (built-in default;",
                crate::allowlist::DEFAULT_MAX_CONNECTIONS
            ),
            format!(
                "body ceiling: {} MiB (built-in default;",
                crate::allowlist::DEFAULT_BODY_MAX / (1024 * 1024)
            ),
        ] {
            assert!(
                out.contains(&expected),
                "each built-in must be named, and marked as the built-in — missing \
                 `{expected}`:\n{out}"
            );
        }

        // A layer-set value keeps its own wording: it is not a default and must not read as one,
        // even where the number happens to match.
        let mut view = sample_config_view();
        if let NetworkView::Allowlist {
            dns_cache_ttl,
            idle_timeout,
            max_connections,
            body_max_mb,
            ..
        } = &mut view.network
        {
            *dns_cache_ttl = Some(crate::allowlist::DEFAULT_DNS_CACHE_TTL.as_secs());
            *idle_timeout = Some(crate::allowlist::DEFAULT_IDLE_TIMEOUT.as_secs());
            *max_connections = Some(crate::allowlist::DEFAULT_MAX_CONNECTIONS);
            *body_max_mb = Some(crate::allowlist::DEFAULT_BODY_MAX / (1024 * 1024));
        }
        let out = render_config(&view, &plain, true);
        assert!(
            !out.contains("built-in default"),
            "a value a layer set must not be reported as the built-in:\n{out}"
        );
        for expected in [
            format!(
                "dns cache: {}s (a resolved address",
                crate::allowlist::DEFAULT_DNS_CACHE_TTL.as_secs()
            ),
            format!(
                "idle timeout: {}s (a connection with nothing",
                crate::allowlist::DEFAULT_IDLE_TIMEOUT.as_secs()
            ),
            format!(
                "max connections: {} (one beyond it",
                crate::allowlist::DEFAULT_MAX_CONNECTIONS
            ),
            format!(
                "body ceiling: {} MiB (the most of one",
                crate::allowlist::DEFAULT_BODY_MAX / (1024 * 1024)
            ),
        ] {
            assert!(
                out.contains(&expected),
                "a layer-set value must still name itself — missing `{expected}`:\n{out}"
            );
        }
    }

    #[test]
    fn render_app_detail_shows_effective_values_tagged_inherited_or_app_set() {
        use config::view::*;
        let p = style::Palette::plain();
        let view = AppDetailView {
            open: vec![],
            service: vec![],
            provisions: Vec::new(),
            fs_deny: Vec::new(),
            fs_origin: Default::default(),
            fs_readonly: Vec::new(),
            notify: Default::default(),
            notify_origin: Default::default(),
            ssh_agent_confirm: false,
            name: "demo".into(),
            cwd: "/proj".into(),
            cmd: Some("demo-agent".into()),
            cmd_origin: ProvenanceView::Global,
            home_scope: "global (shared across projects)".into(),
            home_scope_origin: ProvenanceView::Default,
            network: NetworkView::Allowlist {
                default_action: config::view::NetDefaultView::Deny,
                ask_timeout: None,
                ask_notice: None,
                allow: vec!["api.example.com".into()],
                deny: vec![],
                mute: vec![],
                http2: vec![],
                capture: "off".to_string(),
                capture_max_kb: None,
                pool: true,
                ca_roots: true,
                dns_cache_ttl: None,
                idle_timeout: None,
                max_connections: None,
                body_max_mb: None,
                builtin: vec!["cache.nixos.org".into()],
            },
            network_origin: ProvenanceView::Global,
            proc: ProcView::default(),
            proc_origin: ProvenanceView::Inherited,
            gui: GuiView::None,
            gui_origin: ProvenanceView::Inherited,
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Inherited,
            audio_origin: ProvenanceView::Inherited,
            dbus_origin: ProvenanceView::Inherited,
            forward: vec![],
            forward_origin: ProvenanceView::Inherited,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Inherited,
            devices: vec![],
            devices_origin: ProvenanceView::Inherited,
            ssh_agent: vec![],
            ssh_agent_origin: Default::default(),
            limits: LimitsView {
                memory_high: LimitView {
                    value: "70%".into(),
                    origin: ProvenanceView::Inherited,
                },
                memory_max: LimitView {
                    value: "90%".into(),
                    origin: ProvenanceView::Inherited,
                },
                tasks_max: LimitView {
                    value: "2048".into(),
                    origin: ProvenanceView::Project,
                },
            },
            env: vec![AppEnvVar {
                key: "DEMO_TOKEN".into(),
                value: "placeholder".into(),
            }],
            env_inherited: 2,
            binds: vec![],
            binds_inherited: 0,
            packages: vec![],
            packages_inherited: 0,
            secrets: vec![],
            secrets_inherited: 0,
            notes: vec![],
        };

        // Compact: each scalar carries its effective value + app-context provenance — the headline
        // being that an unset field reads `inherited` (its effective value comes from the baseline).
        let out = render_app_detail(&view, &p, false);
        assert!(out.contains("cmd:     demo-agent  (app:global)"), "{out}");
        assert!(out.contains("gui:     none  (inherited)"), "{out}");
        assert!(out.contains("network: deny  (app:global)"), "{out}");
        // The policy is listed in the compact view, not counted: which hosts the app may reach is
        // what this view is opened for.
        assert!(out.contains("    allow api.example.com"), "{out}");
        // Per-field limits: two inherited from the baseline, the task cap set by the app.
        assert!(out.contains("MemoryHigh=70% (inherited)"), "{out}");
        assert!(out.contains("TasksMax=2048 (app:project)"), "{out}");
        // Collections name the overlay's own entries and count what they inherit.
        assert!(out.contains("DEMO_TOKEN  · inherits 2 baseline"), "{out}");
        assert!(!out.contains(" own  ·"), "{out}");

        // Details add what the compact view keeps back: each variable's value, and the built-in
        // set every app shares.
        let detailed = render_app_detail(&view, &p, true);
        assert!(detailed.contains("    allow api.example.com"), "{detailed}");
        assert!(detailed.contains("built-in (always allowed"), "{detailed}");
        assert!(
            detailed.contains("    DEMO_TOKEN=placeholder"),
            "{detailed}"
        );
    }

    #[test]
    fn app_prefixed_key_rewrites_a_simple_name_and_rejects_a_dotted_one() {
        // The `--app` sugar puts the key under the app's table; a dotted leaf key composes.
        assert_eq!(
            app_prefixed_key("demo", "network").unwrap(),
            "app.demo.network"
        );
        assert_eq!(
            app_prefixed_key("demo", "env.FOO").unwrap(),
            "app.demo.env.FOO"
        );
        // A name with a `.` is not one TOML segment under the naive key splitter — point at `edit`.
        let err = app_prefixed_key("my.app", "cmd").unwrap_err();
        assert!(err.contains("sbx config edit"), "{err}");
        // A name no app could ever carry is rejected outright.
        assert!(app_prefixed_key("bad name", "cmd").is_err());
    }

    #[test]
    fn set_show_source_rejects_a_conflicting_second_flag() {
        let mut src: Option<(&'static str, config::Source)> = None;
        assert!(set_show_source(&mut src, "--global", config::Source::Global).is_ok());
        // The same flag repeated is harmless (no conflict).
        assert!(set_show_source(&mut src, "--global", config::Source::Global).is_ok());
        // A different source flag is a conflict, not last-wins.
        assert!(set_show_source(&mut src, "--local", config::Source::Local).is_err());
    }

    #[test]
    fn config_render_shows_limits_only_when_overridden() {
        let p = style::Palette::colored();
        // A default-profile config prints no `limits:` line — the section surfaces a custom cap,
        // not the documented defaults (which `sbx doctor` shows).
        let out = render_config(&sample_config_view(), &p, false);
        assert!(
            !out.contains("limits:"),
            "a default profile must not print a limits line:\n{out}"
        );

        // An override of the ceiling and task cap prints the line, tagging each field with its
        // provenance: the overridden ones name their layer (`global`/`project`), the untouched
        // throttle reads `(default)` and keeps its default value.
        use config::view::ProvenanceView;
        let mut view = sample_config_view();
        view.limits = config::view::LimitsView {
            memory_high: config::view::LimitView {
                value: "80%".into(),
                origin: ProvenanceView::Default,
            },
            memory_max: config::view::LimitView {
                value: "8G".into(),
                origin: ProvenanceView::Global,
            },
            tasks_max: config::view::LimitView {
                value: "4096".into(),
                origin: ProvenanceView::Project,
            },
        };
        let out = render_config(&view, &p, false);
        assert!(
            out.contains("limits:"),
            "an override prints the line:\n{out}"
        );
        assert!(
            out.contains("MemoryMax=8G"),
            "the overridden ceiling shows:\n{out}"
        );
        assert!(
            out.contains("TasksMax=4096"),
            "the overridden task cap shows:\n{out}"
        );
        // Each field names its source, hued by level: the global-set ceiling (cyan), the
        // project-set task cap (green), and the untouched throttle's default (dim).
        assert!(
            out.contains(&format!("MemoryMax=8G {}(global){}", p.name, p.reset)),
            "the overridden ceiling is tagged global (cyan):\n{out}"
        );
        assert!(
            out.contains(&format!("TasksMax=4096 {}(project){}", p.ok, p.reset)),
            "the overridden task cap is tagged project (green):\n{out}"
        );
        assert!(
            out.contains(&format!("MemoryHigh=80% {}(default){}", p.dim, p.reset)),
            "the untouched throttle shows its default value, tagged default (dim):\n{out}"
        );
    }

    #[test]
    fn config_render_shows_the_redaction_floor_only_when_a_layer_moved_it() {
        let p = style::Palette::colored();
        // At the built-in floor there is nothing to report: the line would say what every launch
        // already does, and this section exists to surface what someone changed.
        let out = render_config(&sample_config_view(), &p, false);
        assert!(
            !out.contains("redact:"),
            "the default floor prints no line:\n{out}"
        );

        let mut view = sample_config_view();
        view.redact_min_len = 4;
        view.redact_min_len_origin = config::view::ProvenanceView::Project;
        let out = render_config(&view, &p, false);
        assert!(
            out.contains(&format!(
                "a secret under {}4{} bytes is not scanned for  {}(project){}",
                p.name, p.reset, p.ok, p.reset
            )),
            "the moved floor names the length and the layer it came from:\n{out}"
        );
    }

    #[test]
    fn config_render_shows_an_app_limits_override() {
        use config::view::*;
        let p = style::Palette::plain();
        let app = |name: &str, limits: Option<AppLimitsView>| AppView {
            open: vec![],
            service: vec![],
            provisions: Vec::new(),
            fs_deny: Vec::new(),
            fs_readonly: Vec::new(),
            ssh_agent: Vec::new(),
            name: name.into(),
            cmd: Some(name.into()),
            home_scope: "global (shared across projects)".into(),
            env: vec![],
            binds: vec![],
            packages: vec![],
            network: None,
            gui: None,
            gpu: None,
            audio: None,
            dbus: None,
            forward: vec![],
            seccomp: vec![],
            devices: vec![],
            limits,
            secrets: vec![],
            notes: vec![],
        };
        let mut view = sample_config_view();
        view.apps = vec![
            app(
                "capped",
                Some(AppLimitsView {
                    memory_high: None,
                    memory_max: None,
                    tasks_max: Some("4096".into()),
                }),
            ),
            app("plain", None),
        ];
        let out = render_config(&view, &p, false);
        // The tuning app prints only the field it set — its task cap.
        assert!(out.contains("      limits: TasksMax=4096"), "{out}");
        // A field the app left unset is absent (it inherits the baseline, not shown per-app); the
        // baseline itself is default here, so it prints no limits line either.
        assert!(
            !out.contains("MemoryHigh"),
            "an unset app field is not rendered:\n{out}"
        );
        // Exactly one app limits line: the app that tunes nothing prints none.
        assert_eq!(
            out.matches("      limits:").count(),
            1,
            "only the tuning app shows a limits line:\n{out}"
        );
    }

    #[test]
    fn config_render_shows_flake_pins_and_floating_state() {
        // A pinned `flake:` package shows its short revision and `pinned`; an unpinned one shows
        // `floating`, so the absence of a rev reads as a state, not a gap. The same pin appears
        // compactly in an app's package list — the motivating case (a flake package in an app
        // overlay, not the baseline).
        use config::view::*;
        let rev = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
        let view = ConfigView {
            open: vec![],
            service: vec![],
            plugins: vec![],
            fs_deny: Vec::new(),
            tasks: Vec::new(),
            fs_origin: Default::default(),
            fs_readonly: Vec::new(),
            notify: Default::default(),
            notify_origin: Default::default(),
            ssh_agent_confirm: false,
            cwd: "/proj".into(),
            env: vec![],
            binds: vec![],
            packages: vec![
                PackageView {
                    name: "pinned-tool".into(),
                    backend: "flake".into(),
                    locator: "github:example/pinned-tool#default".into(),
                    realised: "in-cage via nix build, fetched at launch".into(),
                    trusted: true,
                    withheld_reason: None,
                    pinned_rev: Some(rev.into()),
                },
                PackageView {
                    name: "floating-tool".into(),
                    backend: "flake".into(),
                    locator: "github:example/floating-tool".into(),
                    realised: "in-cage via nix build, fetched at launch".into(),
                    trusted: true,
                    withheld_reason: None,
                    pinned_rev: None,
                },
            ],
            mise: None,
            tools: ToolsView::default(),
            nixpkgs: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            engine: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            network: NetworkView::Shared,
            network_origin: ProvenanceView::Default,
            egress_stats: true,
            redact_min_len: crate::sandbox::redact::MIN_LEN_DEFAULT,
            redact_min_len_origin: Default::default(),
            proc: Default::default(),
            proc_origin: Default::default(),
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Default,
            audio_origin: ProvenanceView::Default,
            dbus_origin: ProvenanceView::Default,
            forward: vec![],
            forward_origin: ProvenanceView::Default,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Default,
            devices: vec![],
            devices_origin: ProvenanceView::Default,
            ssh_agent: vec![],
            brokers: Vec::new(),
            ssh_agent_origin: Default::default(),
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
                open: vec![],
                service: vec![],
                provisions: Vec::new(),
                fs_deny: Vec::new(),
                fs_readonly: Vec::new(),
                ssh_agent: Vec::new(),
                name: "demo-app".into(),
                cmd: Some("demo-app".into()),
                home_scope: "global (shared across projects)".into(),
                env: vec![],
                binds: vec![],
                packages: vec![PackageView {
                    name: "pinned-tool".into(),
                    backend: "flake".into(),
                    locator: "github:example/pinned-tool#default".into(),
                    realised: "in-cage via nix build, fetched at launch".into(),
                    trusted: true,
                    withheld_reason: None,
                    pinned_rev: Some(rev.into()),
                }],
                network: None,
                gui: None,
                gpu: None,
                audio: None,
                dbus: None,
                forward: vec![],
                seccomp: vec![],
                devices: vec![],
                limits: None,
                secrets: vec![],
                notes: vec![],
            }],
            warnings: vec![],
        };
        let out = render_config(&view, &style::Palette::plain(), false);
        assert!(
            out.contains(
                "    pinned-tool -> flake:github:example/pinned-tool#default  \
                 @ a1b2c3d (in-cage via nix build, fetched at launch, pinned)"
            ),
            "a pinned flake package must show its short rev and `pinned`:\n{out}"
        );
        assert!(
            out.contains(
                "    floating-tool -> flake:github:example/floating-tool  \
                 (in-cage via nix build, fetched at launch, floating)"
            ),
            "an unpinned flake package must read as `floating`:\n{out}"
        );
        assert!(
            out.contains("      packages: pinned-tool @ a1b2c3d"),
            "an app's pinned flake package must show its rev compactly:\n{out}"
        );
    }

    #[test]
    fn config_render_shows_an_app_allowlist_compactly_then_expands_under_details() {
        // An app overlay's allowlist is a one-line count by default and expands to its rules under
        // `--details`. The expansion includes the built-in set, which the baseline
        // `network` section does not show here (the baseline is `shared`), so this is the only place
        // a profile's app-overlay allowlist surfaces what `sbx app <name>` can actually reach.
        use config::view::*;
        let view = ConfigView {
            open: vec![],
            service: vec![],
            plugins: vec![],
            fs_deny: Vec::new(),
            tasks: Vec::new(),
            fs_origin: Default::default(),
            fs_readonly: Vec::new(),
            notify: Default::default(),
            notify_origin: Default::default(),
            ssh_agent_confirm: false,
            cwd: "/proj".into(),
            env: vec![],
            binds: vec![],
            packages: vec![],
            mise: None,
            tools: ToolsView::default(),
            nixpkgs: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            engine: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            network: NetworkView::Shared,
            network_origin: ProvenanceView::Default,
            egress_stats: true,
            redact_min_len: crate::sandbox::redact::MIN_LEN_DEFAULT,
            redact_min_len_origin: Default::default(),
            proc: Default::default(),
            proc_origin: Default::default(),
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Default,
            audio_origin: ProvenanceView::Default,
            dbus_origin: ProvenanceView::Default,
            forward: vec![],
            forward_origin: ProvenanceView::Default,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Default,
            devices: vec![],
            devices_origin: ProvenanceView::Default,
            ssh_agent: vec![],
            brokers: Vec::new(),
            ssh_agent_origin: Default::default(),
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
                open: vec![],
                service: vec![],
                provisions: Vec::new(),
                fs_deny: Vec::new(),
                fs_readonly: Vec::new(),
                ssh_agent: Vec::new(),
                name: "demo-app".into(),
                cmd: Some("demo-app".into()),
                home_scope: "global (shared across projects)".into(),
                env: vec![],
                binds: vec![],
                packages: vec![],
                network: Some(AppNetworkView::Allowlist {
                    default_action: config::view::NetDefaultView::Deny,
                    ask_timeout: None,
                    ask_notice: None,
                    allow: vec!["api.example.com".into(), "github.com".into()],
                    deny: vec!["github.com/secret".into()],
                    builtin: vec!["cache.nixos.org".into()],
                }),
                gui: None,
                gpu: None,
                audio: None,
                dbus: None,
                forward: vec![],
                seccomp: vec![],
                devices: vec![],
                limits: None,
                secrets: vec![],
                notes: vec![],
            }],
            warnings: vec![],
        };

        // Default: a compact count, both numbers present even at zero deny, no expanded rule.
        let compact = render_config(&view, &style::Palette::plain(), false);
        assert!(
            compact.contains("      network: deny (2 allow, 1 deny)"),
            "the default app allowlist must read as compact counts:\n{compact}"
        );
        assert!(
            !compact.contains("allow api.example.com"),
            "the default must not expand the rules:\n{compact}"
        );

        // --details: the individual rules and the always-allowed built-in set.
        let expanded = render_config(&view, &style::Palette::plain(), true);
        assert!(
            expanded.contains("        allow api.example.com")
                && expanded.contains("        allow github.com"),
            "--details must list the allow rules:\n{expanded}"
        );
        assert!(
            expanded.contains("        deny  github.com/secret"),
            "--details must list the deny rules:\n{expanded}"
        );
        assert!(
            expanded.contains("built-in (always allowed, so self-equip works):")
                && expanded.contains("          allow cache.nixos.org"),
            "--details must surface the always-allowed built-in set:\n{expanded}"
        );
        // The overlay's allowlist closes with the same `deny wins over allow` reminder the baseline
        // `network` section shows — security-field parity between the overlay and the baseline.
        assert!(
            expanded.contains("        (deny wins over allow)"),
            "--details must explain that deny wins, as the baseline allowlist does:\n{expanded}"
        );
    }

    #[test]
    fn config_render_app_overlay_postures_carry_the_baseline_parentheticals() {
        // An app overlay's simple postures read with the same parentheticals the baseline sections
        // carry, so `sbx app <name>` explains them identically: `network: shared` notes the host
        // network, `network: none` notes the isolation, and a `wayland` gui carries the
        // compositor-exposure caveat. None of these is an expandable list, so they render the same
        // with or without `--details` — the default render is enough to pin them.
        use config::view::*;
        let app = |name: &str, network: Option<AppNetworkView>, gui: Option<GuiView>| AppView {
            open: vec![],
            service: vec![],
            provisions: Vec::new(),
            fs_deny: Vec::new(),
            fs_readonly: Vec::new(),
            ssh_agent: Vec::new(),
            name: name.into(),
            cmd: Some(name.into()),
            home_scope: "global (shared across projects)".into(),
            env: vec![],
            binds: vec![],
            packages: vec![],
            network,
            gui,
            gpu: None,
            audio: None,
            dbus: None,
            forward: vec![],
            seccomp: vec![],
            devices: vec![],
            limits: None,
            secrets: vec![],
            notes: vec![],
        };
        let view = ConfigView {
            open: vec![],
            service: vec![],
            plugins: vec![],
            fs_deny: Vec::new(),
            tasks: Vec::new(),
            fs_origin: Default::default(),
            fs_readonly: Vec::new(),
            notify: Default::default(),
            notify_origin: Default::default(),
            ssh_agent_confirm: false,
            cwd: "/proj".into(),
            env: vec![],
            binds: vec![],
            packages: vec![],
            mise: None,
            tools: ToolsView::default(),
            nixpkgs: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            engine: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            network: NetworkView::Shared,
            network_origin: ProvenanceView::Default,
            egress_stats: true,
            redact_min_len: crate::sandbox::redact::MIN_LEN_DEFAULT,
            redact_min_len_origin: Default::default(),
            proc: Default::default(),
            proc_origin: Default::default(),
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Default,
            audio_origin: ProvenanceView::Default,
            dbus_origin: ProvenanceView::Default,
            forward: vec![],
            forward_origin: ProvenanceView::Default,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Default,
            devices: vec![],
            devices_origin: ProvenanceView::Default,
            ssh_agent: vec![],
            brokers: Vec::new(),
            ssh_agent_origin: Default::default(),
            limits: Default::default(),
            secrets: vec![],
            apps: vec![
                app("shared-app", Some(AppNetworkView::Shared), None),
                app("none-app", Some(AppNetworkView::Isolated), None),
                app("gui-app", None, Some(GuiView::Wayland)),
            ],
            warnings: vec![],
        };

        let out = render_config(&view, &style::Palette::plain(), false);
        // Each app line is six-space-indented, so these substrings match the overlay, not the
        // two-space baseline `network: shared (host network)` line.
        assert!(
            out.contains("      network: shared (host network)"),
            "an app's shared network must carry the baseline parenthetical:\n{out}"
        );
        assert!(
            out.contains("      network: none (isolated — no network)"),
            "an app's none network must carry the baseline parenthetical:\n{out}"
        );
        assert!(
            out.contains("      gui: wayland (exposure depends on your compositor)"),
            "an app's wayland gui must carry the baseline compositor caveat:\n{out}"
        );
    }

    #[test]
    fn config_render_shows_app_secrets_compactly_then_expands_under_details() {
        // An app overlay's injected credentials are a one-line count by default and expand to each
        // by destination and source under `--details` — the same metadata the baseline section
        // shows. The shipped profiles put their secret in the overlay, so this is the only place a
        // profile's credential surfaces in `sbx config` (the baseline `secrets` section is empty).
        use config::view::*;
        let view = ConfigView {
            open: vec![],
            service: vec![],
            plugins: vec![],
            fs_deny: Vec::new(),
            tasks: Vec::new(),
            fs_origin: Default::default(),
            fs_readonly: Vec::new(),
            notify: Default::default(),
            notify_origin: Default::default(),
            ssh_agent_confirm: false,
            cwd: "/proj".into(),
            env: vec![],
            binds: vec![],
            packages: vec![],
            mise: None,
            tools: ToolsView::default(),
            nixpkgs: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            engine: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            network: NetworkView::Shared,
            network_origin: ProvenanceView::Default,
            egress_stats: true,
            redact_min_len: crate::sandbox::redact::MIN_LEN_DEFAULT,
            redact_min_len_origin: Default::default(),
            proc: Default::default(),
            proc_origin: Default::default(),
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Default,
            audio_origin: ProvenanceView::Default,
            dbus_origin: ProvenanceView::Default,
            forward: vec![],
            forward_origin: ProvenanceView::Default,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Default,
            devices: vec![],
            devices_origin: ProvenanceView::Default,
            ssh_agent: vec![],
            brokers: Vec::new(),
            ssh_agent_origin: Default::default(),
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
                open: vec![],
                service: vec![],
                provisions: Vec::new(),
                fs_deny: Vec::new(),
                fs_readonly: Vec::new(),
                ssh_agent: Vec::new(),
                name: "demo-app".into(),
                cmd: Some("demo-app".into()),
                home_scope: "global (shared across projects)".into(),
                env: vec![],
                binds: vec![],
                packages: vec![],
                network: None,
                gui: None,
                gpu: None,
                audio: None,
                dbus: None,
                forward: vec![],
                seccomp: vec![],
                devices: vec![],
                limits: None,
                secrets: vec![
                    SecretView {
                        header: "x-api-key".into(),
                        to: "api.example.com".into(),
                        shape: "raw".into(),
                        sources: "env DEMO_API_KEY".into(),
                    },
                    SecretView {
                        header: "authorization".into(),
                        to: "api2.example.com".into(),
                        shape: "bearer".into(),
                        sources: "env DEMO_TOKEN".into(),
                    },
                ],
                notes: vec![],
            }],
            warnings: vec![],
        };

        // Default: a compact count, no destination or source expanded.
        let compact = render_config(&view, &style::Palette::plain(), false);
        assert!(
            compact.contains("      secrets: 2 injected host-side"),
            "the default app secrets line must read as a compact count:\n{compact}"
        );
        assert!(
            !compact.contains("api.example.com"),
            "the default must not expand the destinations:\n{compact}"
        );

        // --details: each credential by destination and source — never the value.
        let expanded = render_config(&view, &style::Palette::plain(), true);
        assert!(
            expanded.contains("      secrets (injected host-side):"),
            "--details must head the expanded secrets block:\n{expanded}"
        );
        assert!(
            expanded.contains("        x-api-key -> api.example.com  (raw, from env DEMO_API_KEY)")
                && expanded.contains(
                    "        authorization -> api2.example.com  (bearer, from env DEMO_TOKEN)"
                ),
            "--details must list each credential by destination and source:\n{expanded}"
        );
    }

    #[test]
    fn config_render_shows_app_env_and_binds_compactly_then_expands_under_details() {
        // An app overlay's env and binds are one-line counts by default and expand under
        // `--details` — env to each `KEY=value` (the value is the in-cage placeholder, a free
        // field, never an injected secret) and binds to each path. This is the only place a
        // profile's overlay env/binds surface, mirroring the baseline `env`/`binds` sections.
        use config::view::*;
        let view = ConfigView {
            open: vec![],
            service: vec![],
            plugins: vec![],
            fs_deny: Vec::new(),
            tasks: Vec::new(),
            fs_origin: Default::default(),
            fs_readonly: Vec::new(),
            notify: Default::default(),
            notify_origin: Default::default(),
            ssh_agent_confirm: false,
            cwd: "/proj".into(),
            env: vec![],
            binds: vec![],
            packages: vec![],
            mise: None,
            tools: ToolsView::default(),
            nixpkgs: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            engine: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            network: NetworkView::Shared,
            network_origin: ProvenanceView::Default,
            egress_stats: true,
            redact_min_len: crate::sandbox::redact::MIN_LEN_DEFAULT,
            redact_min_len_origin: Default::default(),
            proc: Default::default(),
            proc_origin: Default::default(),
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Default,
            audio_origin: ProvenanceView::Default,
            dbus_origin: ProvenanceView::Default,
            forward: vec![],
            forward_origin: ProvenanceView::Default,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Default,
            devices: vec![],
            devices_origin: ProvenanceView::Default,
            ssh_agent: vec![],
            brokers: Vec::new(),
            ssh_agent_origin: Default::default(),
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
                open: vec![],
                service: vec![],
                provisions: Vec::new(),
                fs_deny: Vec::new(),
                fs_readonly: Vec::new(),
                ssh_agent: Vec::new(),
                name: "demo-app".into(),
                cmd: Some("demo-app".into()),
                home_scope: "global (shared across projects)".into(),
                env: vec![
                    AppEnvVar {
                        key: "DEMO_API_KEY".into(),
                        value: "placeholder".into(),
                    },
                    AppEnvVar {
                        key: "EDITOR".into(),
                        value: "vim".into(),
                    },
                ],
                binds: vec![BindView {
                    path: "/data/cache".into(),
                    writable: false,
                    layer: None,
                }],
                packages: vec![],
                network: None,
                gui: None,
                gpu: None,
                audio: None,
                dbus: None,
                forward: vec![],
                seccomp: vec![],
                devices: vec![],
                limits: None,
                secrets: vec![],
                notes: vec![],
            }],
            warnings: vec![],
        };

        // Default: compact counts, no values or paths expanded.
        let compact = render_config(&view, &style::Palette::plain(), false);
        assert!(
            compact.contains("      env: 2 set") && compact.contains("      binds: 1"),
            "the default must show compact env and bind counts:\n{compact}"
        );
        assert!(
            !compact.contains("DEMO_API_KEY=placeholder") && !compact.contains("/data/cache"),
            "the default must not expand the env values or bind paths:\n{compact}"
        );

        // --details: each env entry by `KEY=value` and each bind path.
        let expanded = render_config(&view, &style::Palette::plain(), true);
        assert!(
            expanded.contains("        DEMO_API_KEY=placeholder")
                && expanded.contains("        EDITOR=vim"),
            "--details must list each env entry as KEY=value:\n{expanded}"
        );
        assert!(
            expanded.contains("      binds:") && expanded.contains("        /data/cache"),
            "--details must list each bind path:\n{expanded}"
        );
    }

    #[test]
    fn config_render_shows_app_packages_compactly_then_expands_under_details() {
        // An app overlay's packages are a compact name list by default — a withheld one marked
        // `(withheld)` and a pinned `flake:` one carrying ` @ <rev>`, so the trust verdict (which
        // governs whether the package is admitted at launch) and the pin are visible without
        // `--details`. `--details` expands to the full per-package line — the same one the baseline
        // `packages` section renders, just indented under the app — so the backend is visible there.
        use config::view::*;
        let rev = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
        let view = ConfigView {
            open: vec![],
            service: vec![],
            plugins: vec![],
            fs_deny: Vec::new(),
            tasks: Vec::new(),
            fs_origin: Default::default(),
            fs_readonly: Vec::new(),
            notify: Default::default(),
            notify_origin: Default::default(),
            ssh_agent_confirm: false,
            cwd: "/proj".into(),
            env: vec![],
            binds: vec![],
            packages: vec![],
            mise: None,
            tools: ToolsView::default(),
            nixpkgs: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            engine: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            network: NetworkView::Shared,
            network_origin: ProvenanceView::Default,
            egress_stats: true,
            redact_min_len: crate::sandbox::redact::MIN_LEN_DEFAULT,
            redact_min_len_origin: Default::default(),
            proc: Default::default(),
            proc_origin: Default::default(),
            gui: GuiView::None,
            gui_origin: ProvenanceView::Default,
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Default,
            audio_origin: ProvenanceView::Default,
            dbus_origin: ProvenanceView::Default,
            forward: vec![],
            forward_origin: ProvenanceView::Default,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Default,
            devices: vec![],
            devices_origin: ProvenanceView::Default,
            ssh_agent: vec![],
            brokers: Vec::new(),
            ssh_agent_origin: Default::default(),
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
                open: vec![],
                service: vec![],
                provisions: Vec::new(),
                fs_deny: Vec::new(),
                fs_readonly: Vec::new(),
                ssh_agent: Vec::new(),
                name: "demo-app".into(),
                cmd: Some("demo-app".into()),
                home_scope: "global (shared across projects)".into(),
                env: vec![],
                binds: vec![],
                packages: vec![
                    PackageView {
                        name: "admitted-tool".into(),
                        backend: "nix".into(),
                        locator: "ripgrep".into(),
                        realised: "host-side, durable".into(),
                        trusted: true,
                        withheld_reason: None,
                        pinned_rev: None,
                    },
                    PackageView {
                        name: "withheld-tool".into(),
                        backend: "nix".into(),
                        locator: "foo".into(),
                        realised: "host-side, durable".into(),
                        trusted: false,
                        withheld_reason: Some("the project is untrusted".into()),
                        pinned_rev: None,
                    },
                    PackageView {
                        name: "pinned-tool".into(),
                        backend: "flake".into(),
                        locator: "github:example/pinned-tool#default".into(),
                        realised: "in-cage via nix build, fetched at launch".into(),
                        trusted: true,
                        withheld_reason: None,
                        pinned_rev: Some(rev.into()),
                    },
                ],
                network: None,
                gui: None,
                gpu: None,
                audio: None,
                dbus: None,
                forward: vec![],
                seccomp: vec![],
                devices: vec![],
                limits: None,
                secrets: vec![],
                notes: vec![],
            }],
            warnings: vec![],
        };

        // Default: one compact line — the withheld marker and the flake pin inline, no full lines.
        let compact = render_config(&view, &style::Palette::plain(), false);
        assert!(
            compact.contains(
                "      packages: admitted-tool, withheld-tool (withheld), pinned-tool @ a1b2c3d"
            ),
            "the default must show a compact name list with the withheld marker and the pin:\n{compact}"
        );
        assert!(
            !compact.contains("-> nix:ripgrep"),
            "the default must not expand to the full package line:\n{compact}"
        );

        // --details: each package on its own full line, mirroring the baseline section — a withheld
        // one carries its reason, the flake one its pin, every other its realisation.
        let expanded = render_config(&view, &style::Palette::plain(), true);
        assert!(
            expanded.contains("        admitted-tool -> nix:ripgrep  (host-side, durable)"),
            "--details must expand an admitted package to its full backend line:\n{expanded}"
        );
        assert!(
            expanded
                .contains("        withheld-tool -> nix:foo  (withheld: the project is untrusted)"),
            "--details must show a withheld package's reason:\n{expanded}"
        );
        assert!(
            expanded.contains(
                "        pinned-tool -> flake:github:example/pinned-tool#default  \
                 @ a1b2c3d (in-cage via nix build, fetched at launch, pinned)"
            ),
            "--details must show a pinned flake package's rev:\n{expanded}"
        );
    }
}
