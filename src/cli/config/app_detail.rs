//! The `sbx config show --app <name>` document.
//!
//! One app's *effective* configuration with per-field provenance: the value it would launch with,
//! whether the overlay set it or it came from the baseline, what its collections add on top of
//! what they inherit, and the fold that keeps a posture nobody configured out of the default view.
//! Pure over the app detail view, like the baseline renderer beside it.

use crate::config;
use crate::style;

use super::format::{
    app_provenance_parts, app_provenance_tag, bind_mode_tag, channel_text, package_line,
    service_line, write_net_posture_head, write_notify,
};

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

/// Whether nobody configured a field — the judgement [`posture_shown`] folds on, and the one
/// question the posture helpers below ask of a provenance.
fn at_default(origin: config::view::ProvenanceView) -> bool {
    origin == config::view::ProvenanceView::Default
}

/// The document's title line and what this app runs: the command, the install steps its
/// bundles put before it, and where its persistent home is keyed.
fn app_detail_head(o: &mut String, view: &config::view::AppDetailView, pal: &style::Palette) {
    use std::fmt::Write as _;
    let (h, n, warn, dim, r) = (pal.head, pal.name, pal.warn, pal.dim, pal.reset);
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
}

/// The effective network posture and, when it filters, the policy under it: the rules this app
/// may reach by, the credential groups they may carry, and what `--details` adds to them.
fn app_detail_network(
    o: &mut String,
    view: &config::view::AppDetailView,
    pal: &style::Palette,
    details: bool,
) {
    use config::view::NetworkView;
    use std::fmt::Write as _;
    let (n, warn, dim, r) = (pal.name, pal.warn, pal.dim, pal.reset);
    // The effective network posture + provenance; the allowlist's rules expand under `--details`.
    let net_tag = app_provenance_tag(view.network_origin, pal);
    write_net_posture_head(o, &view.network, &net_tag, details, pal);
    if let NetworkView::Allowlist {
        allow,
        deny,
        mute,
        http2,
        shared_credential,
        builtin,
        ..
    } = &view.network
    {
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
        // The host groups a credential the cage signed in for may travel across. Ahead of
        // `--details`, unlike `mute` and `http2`: those decide nothing about what leaves the cage,
        // while a group widens the outbound tripwire — and an app takes it from a bundle rather
        // than writing it, so this view is where its reader meets it at all.
        for group in shared_credential {
            let _ = writeln!(
                o,
                "    {dim}shared_credential{r} {n}{}{r}",
                group.join(", ")
            );
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

/// The scalar postures, each shown or folded on its own provenance: process/exec, refusal
/// notifications, display, GPU, plaintext fetches, audio and D-Bus.
fn app_detail_postures(
    o: &mut String,
    view: &config::view::AppDetailView,
    pal: &style::Palette,
    details: bool,
    folded: &mut Vec<&'static str>,
) {
    use config::view::GuiView;
    use std::fmt::Write as _;
    let (h, dim, r) = (pal.head, pal.dim, pal.reset);
    // The effective process/exec posture — shown whenever somebody set it, `off` included, so the
    // inherited story is visible.
    if posture_shown(details, at_default(view.proc_origin), "proc", folded) {
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
    if posture_shown(details, at_default(view.notify_origin), "notify", folded) {
        let notify_tag = app_provenance_tag(view.notify_origin, pal);
        write_notify(o, &view.notify, "  ", &notify_tag, pal);
    }

    // The effective GUI posture — shown whenever somebody set it, `none` included.
    if posture_shown(details, at_default(view.gui_origin), "gui", folded) {
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
    if posture_shown(details, at_default(view.gpu_origin), "gpu", folded) {
        let gpu_tag = app_provenance_tag(view.gpu_origin, pal);
        let _ = writeln!(
            o,
            "  {h}gpu:{r}     {}{gpu_tag}",
            if view.gpu { "enabled" } else { "disabled" }
        );
    }

    // The effective plaintext-fetch posture — shown either way whenever somebody set it, like the
    // postures around it: an app that turned it *off* against an open baseline is as worth seeing as
    // one that turned it on.
    if posture_shown(
        details,
        at_default(view.allow_insecure_http_origin),
        "allow_insecure_http",
        folded,
    ) {
        let tag = app_provenance_tag(view.allow_insecure_http_origin, pal);
        let _ = writeln!(
            o,
            "  {h}allow_insecure_http:{r} {}{tag}",
            if view.allow_insecure_http {
                "enabled"
            } else {
                "disabled"
            }
        );
    }

    // The effective audio posture — shown either way whenever somebody set it.
    if posture_shown(details, at_default(view.audio_origin), "audio", folded) {
        let audio_tag = app_provenance_tag(view.audio_origin, pal);
        let _ = writeln!(
            o,
            "  {h}audio:{r}   {}{audio_tag}",
            if view.audio { "enabled" } else { "disabled" }
        );
    }

    // The effective D-Bus posture — shown either way whenever somebody set it.
    if posture_shown(details, at_default(view.dbus_origin), "dbus", folded) {
        let dbus_tag = app_provenance_tag(view.dbus_origin, pal);
        let dbus_label = if view.dbus {
            "in-cage portal"
        } else {
            "disabled"
        };
        let _ = writeln!(o, "  {h}dbus:{r}    {dbus_label}{dbus_tag}");
    }
}

/// The effective cgroup limits: one line, three cells, each carrying the layer that set it.
fn app_detail_limits(
    o: &mut String,
    view: &config::view::AppDetailView,
    pal: &style::Palette,
    details: bool,
    folded: &mut Vec<&'static str>,
) {
    use config::view::LimitView;
    use std::fmt::Write as _;
    let (h, r) = (pal.head, pal.reset);
    // The effective cgroup limits — every field its provenance (inherited from the baseline, or the
    // app layer that tuned it).
    let cell = |label_name: &str, v: &LimitView| {
        let (label, span) = app_provenance_parts(v.origin, pal);
        format!("{label_name}={} {span}({label}){r}", v.value)
    };
    let l = &view.limits;
    // One line, three origins: it folds only when no cell was set by anyone. A single tuned cell
    // keeps the whole line, since the other two are the context that tuning is read against.
    let limits_untouched = at_default(l.memory_high.origin)
        && at_default(l.memory_max.origin)
        && at_default(l.tasks_max.origin);
    if posture_shown(details, limits_untouched, "limits", folded) {
        let _ = writeln!(
            o,
            "  {h}limits:{r}  {}, {}, {}",
            cell("MemoryHigh", &l.memory_high),
            cell("MemoryMax", &l.memory_max),
            cell("TasksMax", &l.tasks_max),
        );
    }
}

/// The three grants an app takes as a union with the baseline's: the inbound loopback
/// forwards, the seccomp relaxation, and the host device nodes.
fn app_detail_grants(
    o: &mut String,
    view: &config::view::AppDetailView,
    pal: &style::Palette,
    details: bool,
    folded: &mut Vec<&'static str>,
) {
    use std::fmt::Write as _;
    let (h, dim, r) = (pal.head, pal.dim, pal.reset);
    // Effective inbound loopback forward ports — the app's own ∪ the baseline's. Shown even when
    // empty so the inherited story is visible (a non-empty baseline set shows as `inherited`).
    if posture_shown(details, at_default(view.forward_origin), "forward", folded) {
        let forward_tag = app_provenance_tag(view.forward_origin, pal);
        if view.forward.is_empty() {
            let _ = writeln!(o, "  {h}forward:{r} (none){forward_tag}");
        } else {
            let ports = view
                .forward
                .iter()
                .map(ToString::to_string)
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
    if posture_shown(details, at_default(view.seccomp_origin), "seccomp", folded) {
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
    if posture_shown(details, at_default(view.devices_origin), "devices", folded) {
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
}

/// What the fold cost, on one line: every posture the view hid, and the flag that brings it back.
fn app_detail_folded(o: &mut String, folded: &[&'static str], pal: &style::Palette) {
    use std::fmt::Write as _;
    let (dim, r) = (pal.dim, pal.reset);
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
}

/// The effective filesystem masks: what is closed to the cage outright, what is closed at the
/// content level, and what it may read but not write.
fn app_detail_fs(o: &mut String, view: &config::view::AppDetailView, pal: &style::Palette) {
    use std::fmt::Write as _;
    let (h, dim, r) = (pal.head, pal.dim, pal.reset);
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
    if !view.fs_scan.is_empty() {
        let ceiling = match view.fs_scan_max_kb {
            Some(kb) => format!("first {kb} KiB of each file"),
            None => "built-in ceiling".to_string(),
        };
        let _ = writeln!(
            o,
            "  {h}fs scan:{r} {} {dim}(content closed at every open; {ceiling}){r}{fs_tag}",
            view.fs_scan.join(", ")
        );
    }
    if !view.fs_readonly.is_empty() {
        let _ = writeln!(
            o,
            "  {h}fs readonly:{r} {} {dim}(readable, not writable){r}{fs_tag}",
            view.fs_readonly.join(", ")
        );
    }
}

/// The effective ssh-agent grant: the keys the cage may sign with, and whether each signature
/// is confirmed on the host desktop first.
fn app_detail_ssh_agent(o: &mut String, view: &config::view::AppDetailView, pal: &style::Palette) {
    use std::fmt::Write as _;
    let (h, dim, r) = (pal.head, pal.dim, pal.reset);
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
}

/// The three collections an overlay adds to and the channel they resolve against: the
/// environment, the host binds, the packages, and the nixpkgs the last of those are built from.
fn app_detail_collections(
    o: &mut String,
    view: &config::view::AppDetailView,
    pal: &style::Palette,
    details: bool,
) {
    use std::fmt::Write as _;
    let (h, n, r) = (pal.head, pal.name, pal.reset);
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
    // The channel those packages — and the cage's base userland — are built from. Beside them
    // rather than among the postures, because it is what they resolve against, and it is the one
    // field of this view that the *directory* decides rather than the app: the same app launched
    // from a project with a trusted pin builds against that pin. Rendered by the baseline view's
    // own `channel_text`, so a channel reads identically wherever it appears.
    let _ = writeln!(o, "  {h}nixpkgs:{r} {}", channel_text(&view.nixpkgs, pal));
}

/// The effective URI handler table: what a link the cage opens is handed to.
fn app_detail_open(o: &mut String, view: &config::view::AppDetailView, pal: &style::Palette) {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
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
}

/// The effective auxiliary services: what else the cage starts beside the app's own command.
fn app_detail_service(o: &mut String, view: &config::view::AppDetailView, pal: &style::Palette) {
    use std::fmt::Write as _;
    let (h, r) = (pal.head, pal.reset);
    // The auxiliary processes the cage starts before its command. Listed, never counted, and only
    // when there are any: this section exists so a second process running beside the app is a line
    // someone can read rather than a `nohup` buried in a shell script.
    if !view.service.is_empty() {
        let _ = writeln!(o, "  {h}service:{r}");
        for s in &view.service {
            let _ = writeln!(o, "{}", service_line(s, pal, "    "));
        }
    }
}

/// The credentials this app injects, by destination and — under `--details` — by shape and
/// source. Never a value: sbx reads those host-side and prints none of them.
fn app_detail_secrets(
    o: &mut String,
    view: &config::view::AppDetailView,
    pal: &style::Palette,
    details: bool,
) {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
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
}

/// What this app's resolution dropped or ignored, one note per line.
fn app_detail_notes(o: &mut String, view: &config::view::AppDetailView, pal: &style::Palette) {
    use std::fmt::Write as _;
    let (warn, r) = (pal.warn, pal.reset);
    for note in &view.notes {
        let _ = writeln!(o, "  {warn}note: {note}{r}");
    }
}

/// Render one app's *effective* configuration with per-field provenance — the `config show --app
/// <name>` view. Every scalar shows the value the app would launch with, tagged `app:global`/
/// `app:project` (the app set it), `inherited` (it took a value the baseline configured) or
/// `default` (nobody configured it); collections show the overlay's own additions and a count of
/// the baseline entries they inherit, with the entry lists and the allowlist rules expanded under
/// `--details`. A posture left entirely at its default is folded out of the default view and named
/// on the summary line instead ([`posture_shown`]). Color and layout only over
/// [`config::view::AppDetailView`]; every span empties under a non-terminal.
///
/// The document is one block per section, each written by a helper below and called in reading
/// order from here, so this body is the table of contents of what `config show --app` prints.
pub(super) fn render_app_detail(
    view: &config::view::AppDetailView,
    pal: &style::Palette,
    details: bool,
) -> String {
    let mut o = String::new();
    // The postures nobody configured, in the order they would have been printed. Filled as the
    // helpers below skip them, and spelled out once after them by `app_detail_folded`.
    let mut folded: Vec<&'static str> = Vec::new();

    // One helper per block of the document, called in the order they are read. The order is
    // load-bearing (it is the reading order of an app's resolved configuration), so it lives here
    // as a sequence of calls rather than inside the blocks themselves.
    app_detail_head(&mut o, view, pal);
    app_detail_network(&mut o, view, pal, details);
    app_detail_postures(&mut o, view, pal, details, &mut folded);
    app_detail_limits(&mut o, view, pal, details, &mut folded);
    app_detail_grants(&mut o, view, pal, details, &mut folded);
    app_detail_folded(&mut o, &folded, pal);
    app_detail_fs(&mut o, view, pal);
    app_detail_ssh_agent(&mut o, view, pal);
    app_detail_collections(&mut o, view, pal, details);
    app_detail_open(&mut o, view, pal);
    app_detail_service(&mut o, view, pal);
    app_detail_secrets(&mut o, view, pal, details);
    app_detail_notes(&mut o, view, pal);
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

/// A representative per-app effective view: an app that sets its command and its allowlist,
/// inherits most postures from the baseline, and resolves against a project-pinned channel.
///
/// Built by hand so the render tests need no I/O, and shared so a test that varies one field
/// does not restate the other forty.
#[cfg(test)]
pub(super) fn sample_app_detail_view() -> config::view::AppDetailView {
    use config::view::*;
    AppDetailView {
        open: vec![],
        service: vec![],
        provisions: Vec::new(),
        fs_deny: Vec::new(),
        fs_origin: Default::default(),
        fs_readonly: Vec::new(),
        fs_scan: Vec::new(),
        fs_scan_max_kb: None,
        notify: Default::default(),
        notify_origin: Default::default(),
        ssh_agent_confirm: false,
        name: "demo".into(),
        cwd: "/proj".into(),
        nixpkgs: ChannelView {
            source: "nixos-23.11".into(),
            origin: "project pin".into(),
            locked_rev: Some("9ae611a0f2b1c3d4".into()),
        },
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
            shared_credential: vec![],
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
        network_origin: ProvenanceView::Global,
        proc: ProcView::default(),
        proc_origin: ProvenanceView::Inherited,
        gui: GuiView::None,
        gui_origin: ProvenanceView::Inherited,
        gpu: false,
        allow_insecure_http: false,
        audio: false,
        dbus: false,
        gpu_origin: ProvenanceView::Inherited,
        allow_insecure_http_origin: ProvenanceView::Default,
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
    }
}

/// A per-app view with every posture left at its default — the fixture that reaches the *folded*
/// half of [`posture_shown`], which the mixed [`sample_app_detail_view`] cannot: there four
/// postures carry a baseline value and stay on screen.
///
/// It carries, around that fold, the shapes the mixed fixture leaves unrendered: an app no layer
/// gave a command, a network posture that filters nothing, an offscreen display, a scan set under
/// the built-in ceiling, an ssh-agent grant that confirms nothing, a channel with no locked
/// revision, and a collection that is empty and still inherits.
#[cfg(test)]
fn all_defaults_app_detail_view() -> config::view::AppDetailView {
    use config::view::*;
    AppDetailView {
        name: "quiet".into(),
        cwd: "/proj".into(),
        cmd: None,
        cmd_origin: ProvenanceView::Default,
        provisions: Vec::new(),
        home_scope: "global (shared across projects)".into(),
        home_scope_origin: ProvenanceView::Default,
        nixpkgs: ChannelView {
            source: "nixos-unstable".into(),
            origin: "default".into(),
            locked_rev: None,
        },
        network: NetworkView::Shared,
        network_origin: ProvenanceView::Default,
        proc: ProcView::default(),
        proc_origin: ProvenanceView::Default,
        notify: Default::default(),
        notify_origin: ProvenanceView::Default,
        gui: GuiView::Offscreen,
        gui_origin: ProvenanceView::Default,
        gpu: false,
        gpu_origin: ProvenanceView::Default,
        allow_insecure_http: false,
        allow_insecure_http_origin: ProvenanceView::Default,
        audio: false,
        audio_origin: ProvenanceView::Default,
        dbus: false,
        dbus_origin: ProvenanceView::Default,
        forward: vec![],
        forward_origin: ProvenanceView::Default,
        seccomp: vec![],
        seccomp_origin: ProvenanceView::Default,
        devices: vec![],
        devices_origin: ProvenanceView::Default,
        fs_deny: Vec::new(),
        fs_readonly: Vec::new(),
        fs_scan: vec!["/home/demo/.ssh".into()],
        fs_scan_max_kb: None,
        fs_origin: ProvenanceView::Default,
        ssh_agent: vec!["id_ed25519".into()],
        ssh_agent_confirm: false,
        ssh_agent_origin: ProvenanceView::Default,
        limits: LimitsView {
            memory_high: LimitView {
                value: "70%".into(),
                origin: ProvenanceView::Default,
            },
            memory_max: LimitView {
                value: "90%".into(),
                origin: ProvenanceView::Default,
            },
            tasks_max: LimitView {
                value: "4096".into(),
                origin: ProvenanceView::Default,
            },
        },
        env: vec![],
        env_inherited: 0,
        binds: vec![],
        binds_inherited: 0,
        packages: vec![],
        packages_inherited: 2,
        secrets: vec![],
        secrets_inherited: 0,
        open: vec![],
        service: vec![],
        notes: vec![],
    }
}

/// A per-app view with every field an app can carry set to something — the fixture that reaches the
/// branches a posture only takes when somebody configured it.
///
/// Against the two fixtures beside it, this one is what renders the `install:` rows, a deny rule
/// beside an allow, the counted `mute`/`http2` tail the compact view prints instead of listing
/// them, a wayland display, every posture in its enabled spelling, a forward that remaps its port,
/// the three mask sets, a confirmed ssh-agent grant, a withheld package, the handler and service
/// tables, injected credentials, and the dropped-field notes. Its fold is empty, so the summary
/// line the other two print is absent here — the other half of that branch.
#[cfg(test)]
fn filled_app_detail_view() -> config::view::AppDetailView {
    use config::view::*;
    AppDetailView {
        name: "loaded".into(),
        cwd: "/proj".into(),
        cmd: Some("loaded-agent --serve".into()),
        cmd_origin: ProvenanceView::Project,
        provisions: vec![
            AppProvisionView {
                bundle: "demo-bundle".into(),
                cmd: "npm ci".into(),
            },
            AppProvisionView {
                bundle: "demo-tools".into(),
                cmd: "demo-tool setup".into(),
            },
        ],
        home_scope: "project (one home per directory)".into(),
        home_scope_origin: ProvenanceView::Global,
        nixpkgs: ChannelView {
            source: "nixos-23.11".into(),
            origin: "global".into(),
            locked_rev: Some("1f2e3d4c5b6a7988".into()),
        },
        network: NetworkView::Allowlist {
            default_action: NetDefaultView::Ask,
            ask_timeout: Some("none".into()),
            ask_notice: Some(false),
            allow: vec!["api.example.com".into(), "registry.example.org".into()],
            deny: vec!["telemetry.example.net".into()],
            mute: vec!["logs.example.com".into(), "beacon.example.com".into()],
            shared_credential: vec![vec!["example.com".into(), "api.example.com".into()]],
            http2: vec!["grpc.example.com".into()],
            capture: "bodies".to_string(),
            capture_max_kb: Some(64),
            websocket_secret: "block".to_string(),
            pool: true,
            ca_roots: false,
            dns_cache_ttl: Some(30),
            idle_timeout: Some(90),
            max_connections: Some(64),
            body_max_mb: Some(8),
            builtin: vec!["cache.nixos.org".into(), "channels.nixos.org".into()],
        },
        network_origin: ProvenanceView::Project,
        proc: ProcView {
            mode: "enforce".into(),
            allow: vec!["git".into(), "npm".into()],
            deny: vec!["curl".into()],
        },
        proc_origin: ProvenanceView::Project,
        notify: NotifyView {
            events: vec![
                ("net-refusal".into(), "once".into()),
                ("fs-refusal".into(), "off".into()),
            ],
            repeat_after: "300s".into(),
        },
        notify_origin: ProvenanceView::Global,
        gui: GuiView::Wayland,
        gui_origin: ProvenanceView::Global,
        gpu: true,
        gpu_origin: ProvenanceView::Project,
        allow_insecure_http: true,
        allow_insecure_http_origin: ProvenanceView::Global,
        audio: true,
        audio_origin: ProvenanceView::Project,
        dbus: true,
        dbus_origin: ProvenanceView::Global,
        forward: vec![
            config::ForwardPort::same(8080),
            config::ForwardPort {
                host: 3000,
                cage: 3001,
            },
        ],
        forward_origin: ProvenanceView::Project,
        seccomp: vec!["userfaultfd".into(), "perf_event_open".into()],
        seccomp_origin: ProvenanceView::Global,
        devices: vec!["/dev/kvm".into(), "/dev/net/tun".into()],
        devices_origin: ProvenanceView::Project,
        fs_deny: vec!["/home/demo/.gnupg".into(), "/home/demo/.aws".into()],
        fs_readonly: vec!["/home/demo/src".into()],
        fs_scan: vec!["/home/demo/.config".into(), "/home/demo/.local".into()],
        fs_scan_max_kb: Some(128),
        fs_origin: ProvenanceView::Global,
        ssh_agent: vec!["id_ed25519".into(), "id_rsa".into()],
        ssh_agent_confirm: true,
        ssh_agent_origin: ProvenanceView::Project,
        limits: LimitsView {
            memory_high: LimitView {
                value: "4G".into(),
                origin: ProvenanceView::Global,
            },
            memory_max: LimitView {
                value: "8G".into(),
                origin: ProvenanceView::Project,
            },
            tasks_max: LimitView {
                value: "512".into(),
                origin: ProvenanceView::Override,
            },
        },
        env: vec![
            AppEnvVar {
                key: "DEMO_TOKEN".into(),
                value: "placeholder".into(),
            },
            AppEnvVar {
                key: "DEMO_REGION".into(),
                value: "eu-west".into(),
            },
        ],
        env_inherited: 0,
        binds: vec![
            BindView {
                path: "/data".into(),
                writable: false,
                layer: None,
            },
            BindView {
                path: "/scratch".into(),
                writable: true,
                layer: None,
            },
        ],
        binds_inherited: 3,
        packages: vec![
            PackageView {
                name: "jq".into(),
                backend: "nix".into(),
                locator: "jq".into(),
                realised: "host-side, durable".into(),
                trusted: true,
                withheld_reason: None,
                pinned_rev: None,
            },
            PackageView {
                name: "demo-tool".into(),
                backend: "flake".into(),
                locator: "github:example/demo-tool".into(),
                realised: "host-side, durable".into(),
                trusted: false,
                withheld_reason: Some("the project is untrusted".into()),
                pinned_rev: Some("abcdef0123456789".into()),
            },
        ],
        packages_inherited: 1,
        secrets: vec![
            SecretView {
                header: "Authorization".into(),
                to: "api.example.com".into(),
                shape: "bearer".into(),
                sources: "env:DEMO_TOKEN".into(),
            },
            SecretView {
                header: "X-Api-Key".into(),
                to: "registry.example.org".into(),
                shape: "raw".into(),
                sources: "file:~/.demo/key".into(),
            },
        ],
        secrets_inherited: 1,
        open: vec![
            OpenView {
                scheme: "https".into(),
                cmd: "demo-browser".into(),
                mode: "detach".into(),
            },
            OpenView {
                scheme: "demo".into(),
                cmd: "demo-agent open".into(),
                mode: "exec".into(),
            },
        ],
        service: vec![
            ServiceView {
                name: "api".into(),
                cmd: "demo-api --port 9119".into(),
                enable: Some("DEMO_API is set".into()),
                ready: Some(ServiceReadyView {
                    tcp: 9119,
                    timeout_secs: 20,
                }),
            },
            ServiceView {
                name: "watcher".into(),
                cmd: "demo-watch".into(),
                enable: None,
                ready: None,
            },
        ],
        notes: vec![
            "the project is untrusted, so its `binds` were dropped".into(),
            "`caps` is not a field sbx accepts".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::super::format::assert_snapshot;
    use super::*;

    /// Each fixture with the four documents it must render: plain and colored, each compact and
    /// under `--details`, in that order.
    ///
    /// Held as `include_str!` so a snapshot file that goes missing fails the build rather than the
    /// run, and so the text compared against is the file on disk rather than a literal an edit
    /// could quietly bring into line with a regression.
    fn fixtures() -> Vec<(&'static str, config::view::AppDetailView, [&'static str; 4])> {
        vec![
            (
                "sample",
                sample_app_detail_view(),
                [
                    include_str!("snapshots/app_detail.sample.plain.txt"),
                    include_str!("snapshots/app_detail.sample.plain.details.txt"),
                    include_str!("snapshots/app_detail.sample.colored.txt"),
                    include_str!("snapshots/app_detail.sample.colored.details.txt"),
                ],
            ),
            (
                "defaults",
                all_defaults_app_detail_view(),
                [
                    include_str!("snapshots/app_detail.defaults.plain.txt"),
                    include_str!("snapshots/app_detail.defaults.plain.details.txt"),
                    include_str!("snapshots/app_detail.defaults.colored.txt"),
                    include_str!("snapshots/app_detail.defaults.colored.details.txt"),
                ],
            ),
            (
                "filled",
                filled_app_detail_view(),
                [
                    include_str!("snapshots/app_detail.filled.plain.txt"),
                    include_str!("snapshots/app_detail.filled.plain.details.txt"),
                    include_str!("snapshots/app_detail.filled.colored.txt"),
                    include_str!("snapshots/app_detail.filled.colored.details.txt"),
                ],
            ),
        ]
    }

    /// The whole document, byte for byte, for every fixture under both palettes and both settings
    /// of `--details`.
    ///
    /// The substring assertions beside this one each pin a line; none of them pins the *document*,
    /// so a section that moved, one that stopped rendering, or a line that changed hue passes all
    /// of them. The colored palette is rendered as well as the plain one for the last of those:
    /// under `Palette::plain` every span is the empty string, so a line whose color changed renders
    /// identically and a snapshot taken there could not see it.
    #[test]
    fn render_app_detail_renders_each_fixture_byte_for_byte() {
        for (stem, view, expected) in fixtures() {
            for (p, (paint, pal)) in [
                ("plain", style::Palette::plain()),
                ("colored", style::Palette::colored()),
            ]
            .into_iter()
            .enumerate()
            {
                for (d, details) in [false, true].into_iter().enumerate() {
                    let suffix = if details { ".details" } else { "" };
                    assert_snapshot(
                        &format!("app_detail.{stem}.{paint}{suffix}"),
                        expected[p * 2 + d],
                        &render_app_detail(&view, &pal, details),
                    );
                }
            }
        }
    }

    /// A `shared_credential` group is shown here, and without `--details`: it widens the outbound
    /// tripwire — the hosts a credential the cage signed in for may travel to — and an app takes it
    /// from a bundle rather than writing it, so a reader auditing the launch meets it nowhere else.
    #[test]
    fn render_app_detail_shows_a_shared_credential_group_without_details() {
        let p = style::Palette::plain();
        let mut view = sample_app_detail_view();
        if let config::view::NetworkView::Allowlist {
            shared_credential, ..
        } = &mut view.network
        {
            shared_credential.push(vec!["claude.ai".into(), "api.anthropic.com".into()]);
        }
        let out = render_app_detail(&view, &p, false);
        assert!(
            out.contains("shared_credential claude.ai, api.anthropic.com"),
            "{out}"
        );
    }

    #[test]
    fn render_app_detail_shows_effective_values_tagged_inherited_or_app_set() {
        let p = style::Palette::plain();
        let view = sample_app_detail_view();

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
        // The channel the packages and the base userland resolve against, in the default view (not
        // behind `--details`): it is what they are built from, and no other line of this view names
        // it. The whole line is pinned, origin included — the origin is the half that says the
        // directory decided this, and a channel shown without it would read as a property of the
        // app.
        assert!(
            out.contains("  nixpkgs: nixos-23.11 @ 9ae611a  (project pin)"),
            "the app view must name the channel it resolves against:\n{out}"
        );

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
}
