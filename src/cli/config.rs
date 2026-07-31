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
    render_config_unchanged, render_config_write, render_trusted_whole_file,
};
use crate::{config, diag, help, style, trust};
use crate::{config_cwd, net_mode_word, short_rev, split_scope, ScopeArgs};

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
    if app.is_some() {
        if let Some((flag, _)) = source {
            diag::error(&format!(
                "sbx: config show: `--app` does not combine with `{flag}`"
            ));
            diag::error(&format!(
                "sbx: usage: {}",
                help::synopsis_of(&["config", "show"])
            ));
            return ExitCode::from(2);
        }
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

fn render_config(view: &config::view::ConfigView, pal: &style::Palette, details: bool) -> String {
    use config::view::{AppNetworkView, GuiView, LimitView, NetDefaultView, NetworkView};
    use std::fmt::Write as _;
    let (h, n, ok, warn, dim, r) = (pal.head, pal.name, pal.ok, pal.warn, pal.dim, pal.reset);
    let mut o = String::new();

    // The hue carries the layering story the model already holds: a section header is bold, an
    // identifier (a key, a path, a rule, a channel) rides the name span, a value the trust gate
    // *withheld* is yellow while an admitted one's detail is dimmed, and every value's provenance
    // tag is hued by level — a built-in default gray, a global source cyan, a project source green
    // — so where a value came from reads at a glance. None of this is new data; it is the gating
    // outcome and the per-value origin made visible. Every span is empty under a non-terminal, so
    // captured output stays byte-for-byte the plain text the integration tests pin.
    let _ = writeln!(o, "{h}sbx config{r} — resolved for {n}{}{r}", view.cwd);

    // The layered environment and host binds (read-only or read-write), after the trust gate.
    if view.env.is_empty() {
        let _ = writeln!(o, "  {h}env:{r}   {dim}(none){r}");
    } else {
        let _ = writeln!(o, "  {h}env:{r}");
        for e in &view.env {
            let _ = writeln!(
                o,
                "    {n}{}{r}={}{}",
                e.key,
                e.value,
                opt_provenance_tag(e.layer, pal)
            );
        }
    }
    if view.binds.is_empty() {
        let _ = writeln!(o, "  {h}binds:{r} {dim}(none){r}");
    } else {
        let _ = writeln!(o, "  {h}binds:{r}");
        for b in &view.binds {
            let _ = writeln!(
                o,
                "    {n}{}{r}{}{}",
                b.path,
                bind_mode_tag(b.writable, pal),
                opt_provenance_tag(b.layer, pal)
            );
        }
    }

    // Declared tools, each with its backend and trust verdict — the launcher's decision, shown
    // without realising anything (no nix, no network). A withheld package's reason is yellow (the
    // trust gate dropped it); an admitted one's realisation detail is dimmed.
    if view.packages.is_empty() {
        let _ = writeln!(o, "  {h}packages:{r} {dim}(none){r}");
    } else {
        let _ = writeln!(o, "  {h}packages:{r}");
        for p in &view.packages {
            let _ = writeln!(o, "{}", package_line(p, pal, "    "));
        }
    }

    // The project's mise file and whether it would be honored — a tool source gated like
    // `packages`, reported as presence + verdict (no mise run). Trusted is green (it applies);
    // withheld is yellow.
    match &view.mise {
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

    // The tools that file declares — parsed only. `nix:` tools carry the file's trust; a
    // non-`nix:` tool is equipped in-cage (so honored regardless of trust) unless `network =
    // "none"` prevents the fetch; a malformed `nix:` token is shown so it is not silently absent.
    if !view.tools.is_empty() {
        let _ = writeln!(o, "  {h}tools:{r}");
        for t in &view.tools.nix {
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
        for t in &view.tools.non_nix {
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
                        &format!(
                            "{warn}(needs network — not equipped under `network = \"none\"`){r}"
                        ),
                        pal.code,
                        pal.warn,
                        pal
                    )
                );
            }
        }
        for token in &view.tools.malformed {
            let _ = writeln!(o, "    {token}  {warn}(ignored: malformed nix: token){r}");
        }
    }

    // The nixpkgs source the tools resolve against and its locked revision, then the mise
    // engine's own channel — shown so the engine's decoupling from the base channel is visible.
    // Routed through the launch's own channel decision; an unlocked source omits the revision.
    let _ = writeln!(o, "  {h}nixpkgs:{r} {}", channel_text(&view.nixpkgs, pal));
    let _ = writeln!(o, "  {h}engine:{r} {}", channel_text(&view.engine, pal));

    // The network posture — a security field. `shared` keeps the host network; `none` cuts it
    // off; a filtering posture (`deny`/`allow`/`ask`) routes egress through the proxy — `deny`
    // permits only what is listed (deny wins over allow), plus the always-allowed built-in set so
    // the self-equip allowance is never silent.
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

    // The process/exec posture — shown only when the lens is on, so an unenforced config stays
    // uncluttered. `--details` lists the allow/deny exec-target rules.
    if view.proc.mode != "off" {
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
    }

    // The GUI posture — shown only when opened, so a non-GUI config stays uncluttered. `wayland`
    // carries the compositor caveat; `offscreen` names what it supplies, since it exposes nothing.
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

    // The GPU posture — shown only when opened, so a non-GPU config stays uncluttered.
    if view.gpu {
        let _ = writeln!(
            o,
            "  {h}gpu:{r} enabled {dim}(mesa: Intel/AMD/nouveau){r}{}",
            provenance_tag(view.gpu_origin, pal)
        );
    }
    // The audio posture — shown only when opened, same as GPU.
    if view.audio {
        let _ = writeln!(
            o,
            "  {h}audio:{r} enabled {dim}(microphone + playback via PulseAudio){r}{}",
            provenance_tag(view.audio_origin, pal)
        );
    }
    // The D-Bus posture — the in-cage desktop portal; shown only when opened, same as GPU.
    if view.dbus {
        let _ = writeln!(
            o,
            "  {h}dbus:{r} in-cage portal {dim}(file chooser + theme + notifications){r}{}",
            provenance_tag(view.dbus_origin, pal)
        );
    }

    // Inbound loopback forward ports — shown only when a layer declared any, so a default-profile
    // config stays uncluttered. Each port is bound on the host's `127.0.0.1` and bridged into the
    // cage at the same port (an OAuth `localhost:<port>` callback, or a cage-run dev server).
    if !view.forward.is_empty() {
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
    }

    // Resource limits — shown only when a config `[limits]` override customizes one, so a
    // default-profile config stays uncluttered (the effective defaults are in `sbx doctor`). When
    // shown, each of the three fields carries its own provenance: the overridden ones name their
    // layer, the untouched ones read `(default)`, so the line tells exactly which limits were tuned.
    let l = &view.limits;
    let overridden = |v: &LimitView| v.origin != config::view::ProvenanceView::Default;
    if overridden(&l.memory_high) || overridden(&l.memory_max) || overridden(&l.tasks_max) {
        let cell = |name: &str, v: &LimitView| {
            let (label, span) = provenance_parts(v.origin, pal);
            format!("{name}={} {span}({label}){r}", v.value)
        };
        let _ = writeln!(
            o,
            "  {h}limits:{r} {}, {}, {}",
            cell("MemoryHigh", &l.memory_high),
            cell("MemoryMax", &l.memory_max),
            cell("TasksMax", &l.tasks_max),
        );
    }

    // Seccomp denylist relaxation — shown only when a trusted `[seccomp] allow` re-permits a
    // syscall, so the default (full mandatory denylist) stays uncluttered. The tokens read as the
    // canonical `allow` entries; the provenance names which layer relaxed the denylist.
    if !view.seccomp.is_empty() {
        let _ = writeln!(
            o,
            "  {h}seccomp allow:{r} {} {dim}(syscalls re-permitted in the cage){r}{}",
            view.seccomp.join(", "),
            provenance_tag(view.seccomp_origin, pal)
        );
    }

    // Host device grant — shown only when a trusted `[devices] allow` exposes a device, so the
    // default (minimal, hostless `/dev`) stays uncluttered. The paths read as the `allow` entries;
    // the provenance names which layer granted them.
    if !view.devices.is_empty() {
        let _ = writeln!(
            o,
            "  {h}devices:{r} {} {dim}(host device nodes exposed in the cage){r}{}",
            view.devices.join(", "),
            provenance_tag(view.devices_origin, pal)
        );
    }

    // ssh-agent grant — shown only when a trusted `[ssh_agent] allow` names a key, so the default
    // (no agent in the cage at all) stays uncluttered. The entries read as written; which of them
    // the host agent actually holds is settled at launch, and reported there.
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

    // Credentials the egress proxy injects — by destination and source locator, never the value.
    if !view.secrets.is_empty() {
        let _ = writeln!(
            o,
            "  {h}secrets (injected host-side by the egress proxy):{r}"
        );
        for s in &view.secrets {
            let _ = writeln!(
                o,
                "    {n}{}{r} -> {n}{}{r}  {dim}({}, from {}){r}",
                s.header, s.to, s.shape, s.sources
            );
        }
    }

    // Named application profiles, each a gated overlay over the baseline: the command it runs,
    // what its overlay adds, and its own dropped-field notes (so `sbx app <name>` holds no
    // surprises). Security fields appear only when their source was trusted, exactly as at launch.
    if !view.apps.is_empty() {
        let _ = writeln!(o, "  {h}apps:{r}");
        for app in &view.apps {
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
    }

    o
}

/// Render one app's *effective* configuration with per-field provenance — the `config show --app
/// <name>` view. Every scalar shows the value the app would launch with, tagged `app:global`/
/// `app:project` (the app set it) or `inherited` (it took the baseline's); collections show the
/// overlay's own additions and a count of the baseline entries they inherit, with the entry lists
/// and the allowlist rules expanded under `--details`. Color and layout only over
/// [`config::view::AppDetailView`]; every span empties under a non-terminal.
fn render_app_detail(
    view: &config::view::AppDetailView,
    pal: &style::Palette,
    details: bool,
) -> String {
    use config::view::{GuiView, LimitView, NetworkView};
    use std::fmt::Write as _;
    let (h, n, warn, dim, r) = (pal.head, pal.name, pal.warn, pal.dim, pal.reset);
    let mut o = String::new();

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
            if details {
                for rule in allow {
                    let _ = writeln!(o, "    allow {n}{rule}{r}");
                }
                for rule in deny {
                    let _ = writeln!(o, "    {warn}deny{r}  {n}{rule}{r}");
                }
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
                // The mute / http2 counts ride the summary only when non-zero, so an app that uses
                // neither reads exactly as before.
                let mut extra = String::new();
                if !mute.is_empty() {
                    extra.push_str(&format!(", {} mute", mute.len()));
                }
                if !http2.is_empty() {
                    extra.push_str(&format!(", {} http2", http2.len()));
                }
                let _ = writeln!(
                    o,
                    "    {dim}({} allow, {} deny{extra} — see --details){r}",
                    allow.len(),
                    deny.len()
                );
            }
        }
    }

    // The effective process/exec posture — shown even when `off`, so the inherited story is visible.
    let proc_tag = app_provenance_tag(view.proc_origin, pal);
    let _ = writeln!(
        o,
        "  {h}proc:{r}    {} {dim}({} allow, {} deny){r}{proc_tag}",
        view.proc.mode,
        view.proc.allow.len(),
        view.proc.deny.len()
    );

    // The effective GUI posture — shown even when `none`, so the inherited story is visible.
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

    // The effective GPU posture — shown either way, so the inherited story is visible.
    let gpu_tag = app_provenance_tag(view.gpu_origin, pal);
    let _ = writeln!(
        o,
        "  {h}gpu:{r}     {}{gpu_tag}",
        if view.gpu { "enabled" } else { "disabled" }
    );

    // The effective audio posture — shown either way, so the inherited story is visible.
    let audio_tag = app_provenance_tag(view.audio_origin, pal);
    let _ = writeln!(
        o,
        "  {h}audio:{r}   {}{audio_tag}",
        if view.audio { "enabled" } else { "disabled" }
    );

    // The effective D-Bus posture — shown either way, so the inherited story is visible.
    let dbus_tag = app_provenance_tag(view.dbus_origin, pal);
    let dbus_label = if view.dbus {
        "in-cage portal"
    } else {
        "disabled"
    };
    let _ = writeln!(o, "  {h}dbus:{r}    {dbus_label}{dbus_tag}");

    // The effective cgroup limits — every field its provenance (inherited from the baseline, or the
    // app layer that tuned it).
    let cell = |label_name: &str, v: &LimitView| {
        let (label, span) = app_provenance_parts(v.origin, pal);
        format!("{label_name}={} {span}({label}){r}", v.value)
    };
    let l = &view.limits;
    let _ = writeln!(
        o,
        "  {h}limits:{r}  {}, {}, {}",
        cell("MemoryHigh", &l.memory_high),
        cell("MemoryMax", &l.memory_max),
        cell("TasksMax", &l.tasks_max),
    );

    // Effective inbound loopback forward ports — the app's own ∪ the baseline's. Shown even when
    // empty so the inherited story is visible (a non-empty baseline set shows as `inherited`).
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

    // Effective seccomp relaxation — the app's own ∪ the baseline's. Shown even when empty so the
    // inherited story is visible (a relaxation the app takes from the baseline reads as `inherited`).
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

    // Effective host device grant — the app's own ∪ the baseline's. Shown even when empty so the
    // inherited story is visible (a device the app takes from the baseline reads as `inherited`).
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

    // Collections: the overlay's own additions and how many baseline entries it inherits. The own
    // entry lists expand under `--details`; the inherited baseline entries are not re-listed (they
    // are one hop away in `sbx config show`).
    let _ = writeln!(
        o,
        "  {h}env:{r}     {}",
        collection_summary(view.env.len(), view.env_inherited, pal)
    );
    if details {
        for e in &view.env {
            let _ = writeln!(o, "    {n}{}{r}={}", e.key, e.value);
        }
    }
    let _ = writeln!(
        o,
        "  {h}binds:{r}   {}",
        collection_summary(view.binds.len(), view.binds_inherited, pal)
    );
    if details {
        for b in &view.binds {
            let _ = writeln!(o, "    {n}{}{r}{}", b.path, bind_mode_tag(b.writable, pal));
        }
    }
    let _ = writeln!(
        o,
        "  {h}packages:{r} {}",
        collection_summary(view.packages.len(), view.packages_inherited, pal)
    );
    if details {
        for p in &view.packages {
            let _ = writeln!(o, "{}", package_line(p, pal, "    "));
        }
    }
    let _ = writeln!(
        o,
        "  {h}secrets:{r} {}",
        collection_summary(view.secrets.len(), view.secrets_inherited, pal)
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

/// The compact summary for a per-app collection: `<own> own · inherits <n> baseline`. The own count
/// rides the name span (the app's own contribution), the inherited count is dim (it lives in the
/// baseline `sbx config show`).
fn collection_summary(own: usize, inherited: usize, pal: &style::Palette) -> String {
    let (n, dim, r) = (pal.name, pal.dim, pal.reset);
    format!("{n}{own}{r} own  {dim}· inherits {inherited} baseline{r}")
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
    let gated = !matches!(scope, Scope::Global);
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
    // Capture the trust state before the write — the write itself changes the file and so its
    // verdict, so "was it trusted" must be read first. A non-gated target (the global config or an
    // app profile, both trusted by location) carries no marker, so the read is skipped.
    let store_dir = trust::default_store_dir();
    let was_trusted = gated
        && store_dir
            .as_deref()
            .is_some_and(|d| trust::state(d, &path) == trust::TrustState::Trusted);

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
    let was_trusted = gated
        && store_dir
            .as_deref()
            .is_some_and(|d| trust::state(d, &path) == trust::TrustState::Trusted);

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
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            diag::error(&format!(
                "sbx: config: cannot create {}: {e}",
                parent.display()
            ));
            return ExitCode::FAILURE;
        }
    }

    let store_dir = trust::default_store_dir();
    let was_trusted = store_dir
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

    if trust_flag {
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
                builtin: vec!["cache.nixos.org".into()],
            },
            network_origin: ProvenanceView::Project,
            egress_stats: true,
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
            ssh_agent_origin: Default::default(),
            limits: Default::default(),
            secrets: vec![],
            apps: vec![],
            warnings: vec![],
        }
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

    #[test]
    fn render_app_detail_shows_effective_values_tagged_inherited_or_app_set() {
        use config::view::*;
        let p = style::Palette::plain();
        let view = AppDetailView {
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
        assert!(out.contains("(1 allow, 0 deny — see --details)"), "{out}");
        // Per-field limits: two inherited from the baseline, the task cap set by the app.
        assert!(out.contains("MemoryHigh=70% (inherited)"), "{out}");
        assert!(out.contains("TasksMax=2048 (app:project)"), "{out}");
        // Collections summarize the overlay's own count and the inherited baseline count.
        assert!(out.contains("1 own  · inherits 2 baseline"), "{out}");

        // Details expand the allowlist rules and the overlay's own env entries.
        let detailed = render_app_detail(&view, &p, true);
        assert!(detailed.contains("    allow api.example.com"), "{detailed}");
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
    fn config_render_shows_an_app_limits_override() {
        use config::view::*;
        let p = style::Palette::plain();
        let app = |name: &str, limits: Option<AppLimitsView>| AppView {
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
            ssh_agent_origin: Default::default(),
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
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
            ssh_agent_origin: Default::default(),
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
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
            ssh_agent_origin: Default::default(),
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
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
            ssh_agent_origin: Default::default(),
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
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
            ssh_agent_origin: Default::default(),
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
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
