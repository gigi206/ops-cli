//! The baseline `sbx config show` document.
//!
//! One renderer per section, then [`render_config`], whose body is the ordered sequence of section
//! calls and whose order is load-bearing. Pure: no process, no filesystem, no diagnostics — a
//! resolved view in, a string out — so a section can be asserted on its own without a launch.

use crate::{config, style};
use crate::{net_mode_word, short_rev};

use super::format::{
    bind_mode_tag, channel_text, opt_provenance_tag, package_line, provenance_parts,
    provenance_tag, service_line, write_net_posture_head, write_notify,
};

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
    let mut o = String::new();
    write_notify(
        &mut o,
        &view.notify,
        " ",
        &provenance_tag(view.notify_origin, pal),
        pal,
    );
    o
}

/// The cage's clock, rendered only when a layer actually named a zone. Every cage has one, so
/// printing it unconditionally would put a line reading `timezone: UTC` on every `sbx config show`
/// that says nothing — the same reason `gui: none` is not printed. What is worth reading is that
/// *this* configuration moved the clock somewhere, and from which layer.
fn timezone_section(view: &config::view::ConfigView, pal: &style::Palette) -> Option<String> {
    use config::view::ProvenanceView;
    if view.timezone_origin == ProvenanceView::Default {
        return None;
    }
    let (h, r) = (pal.head, pal.reset);
    Some(format!(
        "  {h}timezone:{r} {}{}\n",
        view.timezone,
        provenance_tag(view.timezone_origin, pal)
    ))
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
    // Only when it is on. Off is the default and says nothing; on is a posture the reader has to
    // be able to see without opening three files, since it is what stands between a package source
    // and anyone on the network path.
    if view.allow_insecure_http {
        let _ = writeln!(
            o,
            "  {h}allow_insecure_http:{r} enabled {dim}(package sources may be fetched over \
             plaintext http){r}{}",
            provenance_tag(view.allow_insecure_http_origin, pal)
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
        .map(ToString::to_string)
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
    if !view.fs_scan.is_empty() {
        // The ceiling rides the same line: a refusal rests on how far the scan read, so a reader
        // asking which shapes are closed is asking that at the same time.
        let ceiling = match view.fs_scan_max_kb {
            Some(kb) => format!("first {kb} KiB of each file"),
            None => "built-in ceiling".to_string(),
        };
        let _ = writeln!(
            o,
            "  {h}fs scan:{r} {} {dim}(content closed at every open; {ceiling}){r}{}",
            view.fs_scan.join(", "),
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
    let (n, warn, dim, r) = (pal.name, pal.warn, pal.dim, pal.reset);
    let mut o = String::new();
    let net_tag = provenance_tag(view.network_origin, pal);
    write_net_posture_head(&mut o, &view.network, &net_tag, details, pal);
    if let NetworkView::Allowlist {
        default_action,
        allow,
        deny,
        mute,
        http2,
        builtin,
        ..
    } = &view.network
    {
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
///
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
        // Beside the command, for the reason the per-app view puts it there: an install step is a
        // command that runs inside this cage before `cmd`, so it belongs where a reader looks for
        // what this app executes. `AppView` has carried it all along and this section never read
        // it, so the aggregate listing showed an app's shape with the commands left out.
        if !app.provisions.is_empty() {
            if details {
                let _ = writeln!(o, "      {dim}install:{r}");
                for step in &app.provisions {
                    let _ = writeln!(
                        o,
                        "        {n}{}{r}  {dim}(from bundle {}){r}",
                        step.cmd, step.bundle
                    );
                }
            } else {
                let _ = writeln!(
                    o,
                    "      {dim}install:{r} {} step(s) run before cmd",
                    app.provisions.len()
                );
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
        // The plaintext-fetch posture the overlay sets; `None` inherits the baseline's.
        match app.allow_insecure_http {
            Some(true) => {
                let _ = writeln!(o, "      {dim}allow_insecure_http:{r} enabled");
            }
            Some(false) => {
                let _ = writeln!(o, "      {dim}allow_insecure_http:{r} disabled");
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
                .map(ToString::to_string)
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
        if !app.fs_scan.is_empty() {
            let _ = writeln!(o, "      {dim}fs scan:{r} {}", app.fs_scan.join(", "));
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

/// Render the resolved configuration for display — a pure presenter over [`config::view`]. It
/// adds only color and layout, so the management core stays presentation-agnostic and a future
/// front-end can render the same model differently. Every color span is empty under a
/// non-terminal, so captured output is byte-for-byte the plain text the integration tests pin.
pub(super) fn render_config(
    view: &config::view::ConfigView,
    pal: &style::Palette,
    details: bool,
) -> String {
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
        timezone_section(view, pal),
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

#[cfg(test)]
mod tests {
    use super::super::app_detail;
    use super::*;

    /// One declared app at an inert default, named `name` and running a command of the same name —
    /// the counterpart of `blank_config_view` for the nested app view, so an app a test builds
    /// carries only the fields that test is about.
    fn blank_app_view(name: &str) -> config::view::AppView {
        use config::view::*;
        AppView {
            open: vec![],
            service: vec![],
            provisions: Vec::new(),
            fs_deny: Vec::new(),
            fs_readonly: Vec::new(),
            fs_scan: Vec::new(),
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
            allow_insecure_http: None,
            audio: None,
            dbus: None,
            forward: vec![],
            seccomp: vec![],
            devices: vec![],
            limits: None,
            secrets: vec![],
            notes: vec![],
        }
    }

    /// Every field of a resolved view at an inert default: the shape a render test that cares about
    /// one section starts from, so a field added to `ConfigView` lands in one place here rather than
    /// in every literal. `sample_config_view` and the section tests set only what they are about,
    /// and struct-update syntax still fails to compile on a new field — in exactly one spot.
    fn blank_config_view() -> config::view::ConfigView {
        use config::view::*;
        ConfigView {
            timezone: "UTC".to_string(),
            timezone_origin: Default::default(),
            open: vec![],
            service: vec![],
            plugins: vec![],
            fs_deny: Vec::new(),
            tasks: Vec::new(),
            fs_origin: Default::default(),
            fs_readonly: Vec::new(),
            fs_scan: Vec::new(),
            fs_scan_max_kb: None,
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
            allow_insecure_http: false,
            audio: false,
            dbus: false,
            gpu_origin: ProvenanceView::Default,
            allow_insecure_http_origin: ProvenanceView::Default,
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

    /// A representative resolved view: an untrusted project that withholds a `nix:` package and its
    /// mise file, a project-pinned base channel (with a locked revision) beside the default engine,
    /// and an allowlist carrying a deny rule. Built by hand so the render tests need no I/O.
    fn sample_config_view() -> config::view::ConfigView {
        use config::view::*;
        ConfigView {
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
            nixpkgs: ChannelView {
                source: "nixos-23.11".into(),
                origin: "project pin".into(),
                locked_rev: Some("9ae611a455b90cf061d8f332b977e387bda8e1ca".into()),
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
                websocket_secret: "warn".to_string(),
                pool: true,
                ca_roots: true,
                dns_cache_ttl: None,
                idle_timeout: None,
                max_connections: None,
                body_max_mb: None,
                builtin: vec!["cache.nixos.org".into()],
            },
            network_origin: ProvenanceView::Project,
            ..blank_config_view()
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
    fn the_timezone_line_is_silent_until_a_layer_names_a_zone() {
        use config::view::ProvenanceView;
        let plain = style::Palette::plain();
        let mut view = sample_config_view();

        // The default cage runs on UTC, and saying so on every `sbx config show` would be a line
        // that never varies. What the view reports is that a layer *moved* the clock.
        view.timezone = "UTC".into();
        view.timezone_origin = ProvenanceView::Default;
        assert_eq!(timezone_section(&view, &plain), None);

        view.timezone = "Europe/Paris".into();
        view.timezone_origin = ProvenanceView::Global;
        assert_eq!(
            timezone_section(&view, &plain).expect("a named zone is shown"),
            "  timezone: Europe/Paris  (global)\n"
        );
    }

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

    /// An install step is a command that runs inside the app's cage before its `cmd`, which is what
    /// `AppView::provisions` says it is carried for: "someone reading an app's resolved shape is
    /// entitled to see it here". The aggregate listing never read the field, so it showed an app's
    /// shape with the commands left out — visible only under `sbx config show --app <name>`.
    #[test]
    fn the_apps_section_names_the_install_steps_that_run_before_cmd() {
        use config::view::*;
        let p = style::Palette::plain();
        let app = AppView {
            provisions: vec![AppProvisionView {
                bundle: "demo-agent".into(),
                cmd: "npm install -g demo".into(),
            }],
            ..blank_app_view("demo-app")
        };
        let listed = apps_section(std::slice::from_ref(&app), &p, false).expect("one app");
        assert!(
            listed.contains("install: 1 step(s) run before cmd"),
            "the count belongs beside the command:\n{listed}"
        );
        let detailed = apps_section(std::slice::from_ref(&app), &p, true).expect("one app");
        assert!(
            detailed.contains("npm install -g demo") && detailed.contains("from bundle demo-agent"),
            "and `--details` names the command and where it came from:\n{detailed}"
        );

        // An app with no steps says nothing: the line is about what will run, not about a field.
        let mut quiet = app;
        quiet.provisions = Vec::new();
        let out = apps_section(std::slice::from_ref(&quiet), &p, true).expect("one app");
        assert!(
            !out.contains("install:"),
            "nothing to run, nothing to say:\n{out}"
        );
    }

    #[test]
    fn config_render_shows_an_app_limits_override() {
        use config::view::*;
        let p = style::Palette::plain();
        let app = |name: &str, limits: Option<AppLimitsView>| AppView {
            limits,
            ..blank_app_view(name)
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
            apps: vec![AppView {
                packages: vec![PackageView {
                    name: "pinned-tool".into(),
                    backend: "flake".into(),
                    locator: "github:example/pinned-tool#default".into(),
                    realised: "in-cage via nix build, fetched at launch".into(),
                    trusted: true,
                    withheld_reason: None,
                    pinned_rev: Some(rev.into()),
                }],
                ..blank_app_view("demo-app")
            }],
            ..blank_config_view()
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
            apps: vec![AppView {
                network: Some(AppNetworkView::Allowlist {
                    default_action: config::view::NetDefaultView::Deny,
                    ask_timeout: None,
                    ask_notice: None,
                    allow: vec!["api.example.com".into(), "github.com".into()],
                    deny: vec!["github.com/secret".into()],
                    builtin: vec!["cache.nixos.org".into()],
                }),
                ..blank_app_view("demo-app")
            }],
            ..blank_config_view()
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
            network,
            gui,
            ..blank_app_view(name)
        };
        let view = ConfigView {
            apps: vec![
                app("shared-app", Some(AppNetworkView::Shared), None),
                app("none-app", Some(AppNetworkView::Isolated), None),
                app("gui-app", None, Some(GuiView::Wayland)),
            ],
            ..blank_config_view()
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
            apps: vec![AppView {
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
                ..blank_app_view("demo-app")
            }],
            ..blank_config_view()
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
            apps: vec![AppView {
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
                ..blank_app_view("demo-app")
            }],
            ..blank_config_view()
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
            apps: vec![AppView {
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
                ..blank_app_view("demo-app")
            }],
            ..blank_config_view()
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

    #[test]
    fn the_per_app_notify_row_names_the_repeat_window_like_the_baseline_row() {
        // A notify policy carries a quiet period between repeats of one problem. The baseline view
        // has always named it; the per-app view reproduced the mode logic without it, so an app
        // announcing one refusal per window read exactly like an app announcing every occurrence,
        // and a reader asking "why was I told about this only once" found nothing to explain it.
        // Both rows now render through one writer, so they cannot state the field differently.
        let p = style::Palette::plain();
        let notify = || config::view::NotifyView {
            events: vec![
                ("egress".to_string(), "always".to_string()),
                ("exec".to_string(), "always".to_string()),
            ],
            repeat_after: "300s".to_string(),
        };

        let mut view = app_detail::sample_app_detail_view();
        view.notify = notify();
        view.notify_origin = config::view::ProvenanceView::Inherited;
        let out = app_detail::render_app_detail(&view, &p, false);
        assert!(
            out.contains("notify:  always (a repeat waits 300s)  (inherited)"),
            "the per-app notify row must name the repeat window:\n{out}"
        );

        // The same fact on the baseline view, whose rendering this one now shares.
        let mut base = sample_config_view();
        base.notify = notify();
        base.notify_origin = config::view::ProvenanceView::Project;
        let baseline = render_config(&base, &p, false);
        assert!(
            baseline.contains("notify: always (a repeat waits 300s)  (project)"),
            "the baseline notify row must name the repeat window:\n{baseline}"
        );
    }
}
