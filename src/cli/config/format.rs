//! The line-level formatters both `config show` documents share.
//!
//! The provenance vocabulary lives here — the one level to hue mapping behind every ` (global)` /
//! ` (project)` tag, in the baseline spelling and in the per-app one — together with the entry
//! lines a service, a package or a channel renders as. The network-posture preamble and the
//! `notify:` row are here for the same reason: the baseline view and the per-app view state the
//! same posture over the same data and differ only in the listing that follows it, so keeping the
//! shared half in one place is what stops the two from drifting, which they had already done.

use crate::{config, style};
use crate::{net_mode_word, short_rev};

/// The ` (default)` / ` (global)` / ` (project)` / ` (inherited)` provenance tag a line carries,
/// hued by level so a configured source stands out (global cyan, project green) while a built-in
/// default or an inherited baseline value stays dim. The *label text* is always emitted — color is
/// additive and (like every span) vanishes under a non-terminal — so captured output keeps the
/// bare `(global)` the integration tests pin.
pub(super) fn provenance_tag(origin: config::view::ProvenanceView, pal: &style::Palette) -> String {
    let (label, span) = provenance_parts(origin, pal);
    format!("  {span}({label}){r}", r = pal.reset)
}

/// The label and color span for a provenance level — the one place the level→hue mapping lives, so
/// the end-of-line [`provenance_tag`] and any inline use (the per-field `limits` cells) cannot
/// drift. A configured source is hued (global cyan, project green); a default or inherited value
/// stays dim.
pub(super) fn provenance_parts(
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
pub(super) fn app_provenance_tag(
    origin: config::view::ProvenanceView,
    pal: &style::Palette,
) -> String {
    let (label, span) = app_provenance_parts(origin, pal);
    format!("  {span}({label}){r}", r = pal.reset)
}

/// The label and color span for a provenance level in the per-app view — the one place the app
/// vocabulary lives (so the inline `limits` cells and the end-of-line tag cannot drift). Same hues
/// as [`provenance_parts`]: a configured source is cyan/green, a default or inherited value dim.
pub(super) fn app_provenance_parts(
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
pub(super) fn opt_provenance_tag(
    origin: Option<config::view::ProvenanceView>,
    pal: &style::Palette,
) -> String {
    origin.map_or_else(String::new, |o| provenance_tag(o, pal))
}

/// The mode marker appended after a bind path: a warning-hued ` (rw)` for a read-write bind
/// (the more-privileged, exceptional case worth flagging), nothing for the read-only default.
pub(super) fn bind_mode_tag(writable: bool, pal: &style::Palette) -> String {
    if writable {
        format!(" {}(rw){}", pal.warn, pal.reset)
    } else {
        String::new()
    }
}

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
///
/// `--details` names the **effective** posture instead, defaults included, because the baseline's
/// silence is ambiguous to a reader who does not already know the product defaults: nothing printed
/// means "reuse is on and the cache is the built-in one", which is exactly what someone asking for
/// details wants spelled out. Only the resolver cache can say *which* of the two it is, because the
/// view keeps its unset state (`None`) while `pool` arrives already collapsed to a `bool`.
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

/// Write the `notify:` row into `o`: the uniform mode (or the per-event breakdown when the events
/// disagree), followed by the repeat window whenever one is configured.
///
/// Written once because `sbx config show` and the per-app view state the same posture over the same
/// data and differ only in column spacing and in how they spell provenance. Keeping it in one place
/// is what stops them from drifting: they already had, on the repeat window, which this view named
/// and the app view dropped — so a reader of one app's configuration could not see that a repeated
/// refusal waits out a quiet period before it is reported again.
///
/// `pad` is the caller's spacing after the label and `tag` its rendered provenance, because the two
/// views align their columns differently and tag them from different vocabularies
/// ([`provenance_tag`] vs [`app_provenance_tag`]).
pub(super) fn write_notify(
    o: &mut String,
    n: &config::view::NotifyView,
    pad: &str,
    tag: &str,
    pal: &style::Palette,
) {
    use std::fmt::Write as _;
    let (h, dim, r) = (pal.head, pal.dim, pal.reset);
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
            let _ = writeln!(o, "  {h}notify:{r}{pad}{mode}{every}{tag}");
        }
        None => {
            let _ = writeln!(o, "  {h}notify:{r}{pad}{dim}per event{r}{every}{tag}");
            for (event, mode) in &n.events {
                let _ = writeln!(o, "      {dim}{event}{r} {mode}");
            }
        }
    }
}

/// The `network:` line and the posture preamble that precedes any rule listing: the mode word and
/// its provenance tag, the ask-timeout and ask-notice lines, the capture and websocket-secret
/// statements, and the transport block.
///
/// Written once because both views state the same posture and only their *rule listing* differs —
/// `sbx config show` groups rules by default action, the per-app view lists them flat. Keeping the
/// preamble in one place is what stops the two from drifting: they already had, on `ask timeout:
/// none`, where this view explained the value and the app view printed it bare.
///
/// `net_tag` is the caller's, because the provenance tag is rendered differently in the two views
/// (`provenance_tag` vs `app_provenance_tag`).
pub(super) fn write_net_posture_head(
    o: &mut String,
    network: &config::view::NetworkView,
    net_tag: &str,
    details: bool,
    pal: &style::Palette,
) {
    use config::view::NetworkView;
    use std::fmt::Write as _;
    let (h, dim, r) = (pal.head, pal.dim, pal.reset);
    match network {
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
            capture,
            capture_max_kb,
            websocket_secret,
            pool,
            ca_roots,
            dns_cache_ttl,
            idle_timeout,
            max_connections,
            body_max_mb,
            ..
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
            // Stated for the same reason, and only when it is not the default: a tunnel closed on a
            // sighting looks from inside the cage exactly like one its peer closed.
            if websocket_secret != "warn" {
                let _ = writeln!(
                    o,
                    "    {}",
                    style::dim_prose(
                        "websocket secret: block (a tunnel carrying one out is closed)",
                        pal
                    )
                );
            }
            write_net_transport(
                o,
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
        }
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
pub(super) fn service_line(
    s: &config::view::ServiceView,
    pal: &style::Palette,
    indent: &str,
) -> String {
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
pub(super) fn package_line(
    p: &config::view::PackageView,
    pal: &style::Palette,
    indent: &str,
) -> String {
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
pub(super) fn channel_text(c: &config::view::ChannelView, pal: &style::Palette) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store;

    #[test]
    fn channel_origin_kind_tracks_the_real_store_origin_labels() {
        // `channel_origin_kind` colors by matching the channel's origin *label* — a string coupling
        // to `store::Origin::label()`. Route the REAL labels through it so a rename in
        // store/channel.rs fails here loudly, instead of silently degrading that channel's origin
        // to the dim default.
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
}
