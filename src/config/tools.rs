//! The declared-tool pipeline: turn `[packages]`, `[flakes]`, `[tarball]`, `[deb]`, `[appimage]`
//! and `[binary]` into the resolved package set, and decide what a package value may contain.
//!
//! The fold and the locator grammar stay in one module deliberately. Every validator here exists
//! for a caller in the fold above it — the character set one backend admits is only legible beside
//! the command line the value ends up in — and the two halves cross-reference each other in a dozen
//! places, so separating them would leave each half arguing about the other from a distance.
//!
//! The grammar is the whole barrier on the fetching backends: a locator is interpolated into a
//! generated derivation or into a fetch, so a value admitted here is one sbx will act on. Each
//! validator therefore refuses by default and admits a named character set, and every URL derived
//! from a locator is re-validated through the same predicate rather than trusted for its source.

use super::*;

/// Warn about any `mise:nix:<pkg>` package. Routing `nix:` content through the mise backend pins the
/// install record app-global (Lane-1 `mise use -g`, so a global app's declared `mise:` tool installs
/// once and is shared) while the built store path is per-project — so the record and content misalign
/// across projects, the same failure the per-project mise split fixes for `nix:`-via-mise self-equips.
/// The fix is a plain `nix:<pkg>`, which is host-provisioned and seeded into each project's store,
/// per-project-aligned by construction — so this warns rather than rerouting. Trusted-only: a withheld
/// package never equips, so it stays silent. `source` prefixes the message (e.g. `` `app <name> ` ``).
pub(super) fn warn_mise_nix_packages(
    source: &str,
    packages: &[Package],
    warnings: &mut Vec<String>,
) {
    for pkg in packages {
        if pkg.state != TrustState::Trusted {
            continue;
        }
        if let Backend::Mise(token) = &pkg.backend
            && let Some(attr) = token.strip_prefix("nix:")
        {
            warnings.push(format!(
                    "{source}package `{}` uses `mise:nix:{attr}`: for a global app its install record \
                     is pinned app-global while its `/nix` store path is per-project, so it misaligns \
                     across projects — declare it as `nix:{attr}` (host-provisioned, \
                     per-project-aligned) instead",
                    pkg.name
                ));
        }
    }
}

/// Fold a layer's packages into `out`, validating the label and parsing the value's
/// mandatory backend prefix, stamping each with whether its source layer is trusted. A
/// later layer overrides an earlier one at the same name, so a project can pin a tool
/// the global set named. Nothing is dropped for trust here — that belongs to the
/// launcher; this is a pure merge. A malformed label, or a value with no `nix:`/`mise:`
/// prefix, *is* dropped (with a warning): it could never realise, and a label names an
/// on-disk path — fail-closed, never a silent mis-route.
pub(super) fn apply_packages(
    out: &mut Vec<Package>,
    warnings: &mut Vec<String>,
    source: &str,
    packages: BTreeMap<String, String>,
    state: TrustState,
    protect_trusted: bool,
    allow_insecure_http: bool,
) {
    for (name, value) in packages {
        if !is_valid_package_name(&name) {
            warnings.push(format!(
                "{source}: ignoring malformed package name `{name}`"
            ));
            continue;
        }
        // When `protect_trusted` is set (an untrusted project layering over a trusted app),
        // a package a trusted layer already supplied may not be overridden — the integrity-of-
        // intent guard `cmd` has, applied to the tool: else an untrusted project could swap a
        // trusted app's `demo-tool` for its own attribute and either run attacker code (closed
        // separately by `[packages]` being trusted-only) or simply deny the app its tool. A new
        // name may still be added.
        if protect_trusted
            && out
                .iter()
                .any(|p| p.name == name && p.state == TrustState::Trusted)
        {
            refuse_untrusted(
                warnings,
                source,
                &format!("package `{name}` override of a trusted app"),
                state,
            );
            continue;
        }
        let backend = match parse_backend(&value, allow_insecure_http) {
            Ok(b) => b,
            Err(reason) => {
                warnings.push(format!("{source}: ignoring package `{name}`: {reason}"));
                continue;
            }
        };
        upsert_package(out, name, backend, state, Vec::new());
    }
}

/// Absorb one layer's `accepts_fresh_releases` into the accumulating list, trusted-only.
///
/// Separate from [`apply_tools`] rather than a thirteenth parameter on it: that function turns declared
/// locators into [`Package`]s, and this list names packages instead of declaring them. Gated the way
/// every security field is, because lifting a freshness delay is a supply-chain decision and an
/// untrusted layer may not make it for the layers above.
///
/// Deduplicated on the way in, so an app and the bundle it consumes may name the same package
/// without the value reaching mise twice.
pub(super) fn apply_fresh_releases(
    into: &mut Vec<String>,
    warnings: &mut Vec<String>,
    source: &str,
    names: Vec<String>,
    state: TrustState,
) {
    if names.is_empty() {
        return;
    }
    if state != TrustState::Trusted {
        refuse_untrusted(warnings, source, "`accepts_fresh_releases`", state);
        return;
    }
    for name in names {
        if !into.contains(&name) {
            into.push(name);
        }
    }
}

/// Fold a layer's `[packages]` and `[flakes]` into `out` as one tool set, upserting by name.
///
/// Packages are applied first, then inline flakes, so a name declared in both — a config mistake —
/// resolves to the `[flakes]` inline source, and the collision is warned rather than silently
/// last-winning. `state`/`protect_trusted` gate both exactly like [`apply_packages`], so an
/// untrusted project's inline flake is stamped untrusted (withheld at launch) and cannot override
/// a trusted app's tool. The collision check is per-layer, so a *legitimate* cross-layer override
/// (a project flake replacing a global package of the same name) does not trip it — the two sit in
/// different `apply_tools` calls.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_tools(
    out: &mut Vec<Package>,
    warnings: &mut Vec<String>,
    source: &str,
    mut packages: BTreeMap<String, String>,
    flakes: BTreeMap<String, RawInlineFlake>,
    tarball: BTreeMap<String, RawResolve>,
    deb: BTreeMap<String, RawResolve>,
    appimage: BTreeMap<String, RawResolve>,
    binary: BTreeMap<String, RawResolve>,
    state: TrustState,
    protect_trusted: bool,
    allow_insecure_http: bool,
) {
    // A `<name> = "tarball:resolve"` / `"deb:resolve"` / `"appimage:resolve"` entry is a sentinel, not
    // a real backend locator: pull each out of the ordinary packages before `apply_packages` (which
    // would reject the bare prefix) and hand the names to `apply_resolvers`, which binds each to its
    // `[tarball.<name>]` / `[deb.<name>]` / `[appimage.<name>]` table.
    let collect_sentinel =
        |packages: &BTreeMap<String, String>, sentinel: &str| -> BTreeSet<String> {
            packages
                .iter()
                .filter(|(_, v)| v.as_str() == sentinel)
                .map(|(k, _)| k.clone())
                .collect()
        };
    // One row per prebuilt backend, rather than each of the steps below fanned out four times: a
    // fifth backend is a row here, and the three things it needs — its sentinel, its table label,
    // and the `Backend` a `resolve` command builds — cannot be added to one step and forgotten in
    // another. A sentinel missing from the `retain` below is the sharpest of those: it would reach
    // `apply_packages`, which rejects the bare prefix and warns about a package the user declared
    // correctly. The constructors are bound as `fn` pointers first because the array needs one
    // element type and each closure has its own.
    let tarball_resolve: fn(Vec<String>) -> Backend = |command| Backend::TarballResolve { command };
    let deb_resolve: fn(Vec<String>) -> Backend = |command| Backend::DebResolve { command };
    let appimage_resolve: fn(Vec<String>) -> Backend =
        |command| Backend::AppImageResolve { command };
    let binary_resolve: fn(Vec<String>) -> Backend = |command| Backend::BinaryResolve { command };
    let backends = [
        (
            tarball,
            TARBALL_RESOLVE_SENTINEL,
            "tarball",
            tarball_resolve,
        ),
        (deb, DEB_RESOLVE_SENTINEL, "deb", deb_resolve),
        (
            appimage,
            APPIMAGE_RESOLVE_SENTINEL,
            "appimage",
            appimage_resolve,
        ),
        (binary, BINARY_RESOLVE_SENTINEL, "binary", binary_resolve),
    ];
    let resolve_names: Vec<BTreeSet<String>> = backends
        .iter()
        .map(|(_, sentinel, _, _)| collect_sentinel(&packages, sentinel))
        .collect();
    packages.retain(|_, v| {
        !backends
            .iter()
            .any(|(_, sentinel, _, _)| v.as_str() == *sentinel)
    });

    for name in packages.keys() {
        if flakes.contains_key(name) {
            warnings.push(format!(
                "{source}: `{name}` is declared as both a [packages] entry and a [flakes] table; \
                 the [flakes] inline source is used"
            ));
        }
    }
    apply_packages(
        out,
        warnings,
        source,
        packages,
        state,
        protect_trusted,
        allow_insecure_http,
    );
    apply_flakes(out, warnings, source, flakes, state, protect_trusted);
    // Each table is cloned rather than moved: `apply_resolvers` consumes it, and the `libs` pass
    // below reads the same table after every package is in `out`.
    for ((tables, sentinel, label, make_backend), names) in backends.iter().zip(&resolve_names) {
        apply_resolvers(
            out,
            warnings,
            source,
            tables.clone(),
            names,
            state,
            protect_trusted,
            sentinel,
            label,
            *make_backend,
        );
    }
    // A second pass, after the packages exist, since `libs` decorates a package rather than
    // declaring one: the table it comes from may pair with either declaration form, so both must
    // already be in `out`.
    for (tables, _, label, _) in &backends {
        apply_prebuilt_libs(out, warnings, source, tables, label, protect_trusted, state);
    }
}

/// Attach a `[<label>.<name>]` table's `libs` to the package it names — the extra nixpkgs attributes
/// that package's ELFs are autoPatchelf'd against, on top of the built-in Electron/Chromium set.
///
/// Separate from [`apply_resolvers`] because `libs` decorates a package instead of declaring one: it
/// applies to both declaration forms (a fixed URL, a `github:` locator, or the `resolve` sentinel),
/// so it runs once every package of this layer is in `out`. Each name is interpolated into the
/// generated derivation, so it passes the same charset barrier as a `nix:` attribute; an invalid one
/// is dropped on its own rather than voiding the list. A table naming a package this layer never
/// declared, or one whose backend is not this prebuilt backend, is warned about — both are config
/// mistakes whose silent form would be a package built against the wrong library set.
fn apply_prebuilt_libs(
    out: &mut [Package],
    warnings: &mut Vec<String>,
    source: &str,
    tables: &BTreeMap<String, RawResolve>,
    label: &str,
    protect_trusted: bool,
    state: TrustState,
) {
    for (name, raw) in tables {
        if raw.libs.is_empty() {
            continue;
        }
        let Some(slot) = out.iter_mut().find(|p| &p.name == name) else {
            warnings.push(format!(
                "{source}: ignoring `libs` in [{label}.{name}] — no `{name}` in [packages]"
            ));
            continue;
        };
        if slot.backend.label() != label {
            warnings.push(format!(
                "{source}: ignoring `libs` in [{label}.{name}] — `{name}` is a `{}` package, and \
                 `libs` only applies to a prebuilt one",
                slot.backend.label()
            ));
            continue;
        }
        // An untrusted layer may not re-patch a trusted app's tool against a library set of its
        // choosing, exactly as it may not replace the tool itself.
        if protect_trusted && slot.state == TrustState::Trusted {
            warnings.push(format!(
                "{source}: ignoring `libs` in [{label}.{name}] — it would override a trusted app's \
                 package"
            ));
            continue;
        }
        // The same rule for the **baseline** layers, which pass `protect_trusted = false` because
        // they may legitimately decorate a package a lower layer declared. What they may not do is
        // decorate one from *below their own trust*: every other contribution an untrusted layer
        // makes is neutralised by being stamped — `apply_packages`/`apply_resolvers` hand
        // `upsert_package` the layer's `state`, and `Kind::packages`/`Kind::resolve_packages`
        // withhold anything not `Trusted`. `libs` declares nothing, so it is stamped nowhere: it
        // mutates `slot.libs` in place and leaves `slot.state` alone, and the package stays trusted,
        // is provisioned, and `prebuilt::libs_of` reads the attacker's list straight into the
        // `buildInputs` its ELFs are autoPatchelf'd against. A cloned repo needed only
        // `[deb.<name>] libs = [...]` — no `[packages]` entry at all, which `apply_resolvers` also
        // declines to warn about for a libs-only table.
        if state != TrustState::Trusted && slot.state == TrustState::Trusted {
            refuse_untrusted(
                warnings,
                source,
                &format!("`libs` in [{label}.{name}] — it decorates a trusted package"),
                state,
            );
            continue;
        }
        // Two reasons to drop one, and they do not read alike to whoever wrote the field: a
        // character that has no business in an attribute at all, and one that is legal in an
        // attribute but not where this list is written.
        let mut valid = Vec::with_capacity(raw.libs.len());
        for attr in raw.libs.iter().cloned() {
            if !is_valid_attr(&attr) {
                warnings.push(format!(
                    "{source}: ignoring invalid library attribute `{attr}` in [{label}.{name}]"
                ));
            } else if !is_bare_nix_attr(&attr) {
                warnings.push(format!(
                    "{source}: ignoring library attribute `{attr}` in [{label}.{name}] — this list \
                     is written into the generated derivation, where nix reads its `+` as the \
                     addition operator rather than as part of a name"
                ));
            } else {
                valid.push(attr);
            }
        }
        slot.libs = valid;
    }
}

/// Bind each `<name> = "<label>:resolve"` sentinel to its `[<label>.<name>]` table, folding it into
/// `out` as the backend `make_backend` builds from the command. Shared by the `tarball:resolve` and
/// `deb:resolve` forms (the two differ only in the sentinel, the table label, and the backend built).
/// Modelled on [`apply_flakes`]: a malformed name, an empty `resolve` command, or the `protect_trusted`
/// override of a trusted app's tool is dropped with a warning (fail-closed). Both mismatch directions
/// are warned loudly so a half-declared package never silently vanishes: a `[<label>.<name>]` table
/// with no matching sentinel is ignored (the sentinel is the opt-in that keeps `[packages]` the
/// canonical tool list), and a sentinel with no table cannot resolve. Trust is *recorded*, not enforced
/// here — the launcher withholds an untrusted resolver package and **never runs its command**.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_resolvers(
    out: &mut Vec<Package>,
    warnings: &mut Vec<String>,
    source: &str,
    tables: BTreeMap<String, RawResolve>,
    resolve_names: &BTreeSet<String>,
    state: TrustState,
    protect_trusted: bool,
    sentinel: &str,
    label: &str,
    make_backend: fn(Vec<String>) -> Backend,
) {
    // Which sentinels actually have a `[<label>.<name>]` table (valid or not) — so the no-table
    // warning below fires only for a truly-orphan sentinel, never a second time for one whose table
    // was present but rejected above.
    let table_names: BTreeSet<String> = tables.keys().cloned().collect();
    for (name, raw) in tables {
        if !resolve_names.contains(&name) {
            // A table carrying only `libs` is not a resolver declaration at all: it decorates a
            // package declared with a fixed URL or a `github:` locator, and `apply_prebuilt_libs`
            // is what reads it. Only a table that meant to resolve is a mistake here.
            if !raw.resolve.is_empty() || raw.libs.is_empty() {
                warnings.push(format!(
                    "{source}: ignoring [{label}.{name}] — no matching `{name} = \
                     \"{sentinel}\"` in [packages]"
                ));
            }
            continue;
        }
        if !is_valid_package_name(&name) {
            warnings.push(format!(
                "{source}: ignoring malformed {label} name `{name}`"
            ));
            continue;
        }
        if protect_trusted
            && out
                .iter()
                .any(|p| p.name == name && p.state == TrustState::Trusted)
        {
            refuse_untrusted(
                warnings,
                source,
                &format!("{label} resolver `{name}` override of a trusted app"),
                state,
            );
            continue;
        }
        if raw.resolve.iter().all(|a| a.trim().is_empty()) {
            warnings.push(format!(
                "{source}: ignoring [{label}.{name}]: the `resolve` command is empty"
            ));
            continue;
        }
        upsert_package(out, name, make_backend(raw.resolve), state, Vec::new());
    }
    // A sentinel with no `[<label>.<name>]` table at all can never resolve — warn rather than
    // silently drop the package (a sentinel whose table was present but invalid was already warned).
    for name in resolve_names {
        if !table_names.contains(name) {
            warnings.push(format!(
                "{source}: ignoring package `{name}`: `{sentinel}` needs a `[{label}.{name}]` \
                 table declaring a `resolve` command"
            ));
        }
    }
}

/// Fold a layer's inline flakes (`[flakes.<name>]`) into `out` as [`Backend::FlakeInline`] tools,
/// stamping each with whether its source layer is trusted. Modelled on [`apply_packages`]: a
/// malformed name, an empty `flake` body, or an invalid output attribute is dropped with a warning
/// (fail-closed — a name keys an on-disk path and an empty flake could never build), and the
/// `protect_trusted` guard refuses an untrusted override of a trusted app's tool. The default
/// output attribute is `default`. Trust is *recorded*, not enforced here — the launcher withholds
/// an untrusted inline flake, exactly as for `flake:`.
pub(super) fn apply_flakes(
    out: &mut Vec<Package>,
    warnings: &mut Vec<String>,
    source: &str,
    flakes: BTreeMap<String, RawInlineFlake>,
    state: TrustState,
    protect_trusted: bool,
) {
    for (name, raw) in flakes {
        if !is_valid_package_name(&name) {
            warnings.push(format!("{source}: ignoring malformed flake name `{name}`"));
            continue;
        }
        if protect_trusted
            && out
                .iter()
                .any(|p| p.name == name && p.state == TrustState::Trusted)
        {
            refuse_untrusted(
                warnings,
                source,
                &format!("inline flake `{name}` override of a trusted app"),
                state,
            );
            continue;
        }
        let content = raw.flake;
        if content.trim().is_empty() {
            warnings.push(format!(
                "{source}: ignoring inline flake `{name}`: the `flake` field is empty"
            ));
            continue;
        }
        let attr = raw.attr.unwrap_or_else(|| "default".to_string());
        if !is_valid_attr(&attr) {
            warnings.push(format!(
                "{source}: ignoring inline flake `{name}`: invalid output attribute `{attr}`"
            ));
            continue;
        }
        upsert_package(
            out,
            name,
            Backend::FlakeInline { content, attr },
            state,
            Vec::new(),
        );
    }
}

/// Parse a `[packages]` value into its [`Backend`] from the mandatory prefix. `nix:<attr>`
/// routes to host-side nixpkgs provisioning, `mise:<token>` to the in-cage mise equip,
/// `flake:<ref>` to a host-side `nix build` of an arbitrary flake; a value with no recognized
/// prefix is rejected (there is no bare form, so the backend is always explicit). The part
/// after `mise:` is the full mise token — including a `nix:`-prefixed nixhub token
/// (`mise:nix:<pkg>`), which is mise's concern, not a third nix code path here. `flake:` is
/// matched before `nix:` only by being a distinct prefix; the two never overlap.
pub(super) fn parse_backend(value: &str, allow_insecure_http: bool) -> Result<Backend, String> {
    match classify_backend(value, allow_insecure_http) {
        Ok(backend) => Ok(backend),
        // The refusal names its remedy, but only when that remedy would actually have worked.
        // Each backend's message covers several causes at once (a wrong suffix, a character outside
        // the injection-free set, a plaintext scheme), so appending the hint unconditionally would
        // point a mistyped `.zip` at a switch that does not fix it. Re-asking with the opt-in on
        // answers exactly the question worth answering: was the transport the *only* thing wrong?
        Err(reason) if !allow_insecure_http && classify_backend(value, true).is_ok() => {
            Err(format!(
                "{reason}. This source is plaintext `http://`, which sbx refuses by default; \
                 set `allow_insecure_http = true` to admit it"
            ))
        }
        Err(reason) => Err(reason),
    }
}

/// [`parse_backend`] without the plaintext hint: the prefix match and per-backend validation.
///
/// Split out so the hint can be decided by asking this function the same question twice.
fn classify_backend(value: &str, allow_insecure_http: bool) -> Result<Backend, String> {
    if let Some(attr) = value.strip_prefix("nix:") {
        if !is_valid_attr(attr) {
            return Err(format!("invalid nix attribute `{attr}`"));
        }
        Ok(Backend::Nix(attr.to_string()))
    } else if let Some(token) = value.strip_prefix("mise:") {
        if !is_valid_mise_token(token) {
            return Err(format!("invalid mise token `{token}`"));
        }
        Ok(Backend::Mise(token.to_string()))
    } else if let Some(reference) = value.strip_prefix("flake:") {
        if !is_valid_flake_ref(reference, allow_insecure_http) {
            return Err(format!("invalid flake reference `{reference}`"));
        }
        Ok(Backend::Flake(reference.to_string()))
    } else if value == DEB_RESOLVE_SENTINEL {
        // Checked before the `deb:` strip below, or `deb:resolve` would parse as a `deb:` URL and be
        // rejected as invalid. Bound to its `[deb.<name>]` table by `apply_tools`; reaching here means
        // the table is missing or a context without one (e.g. a one-shot `--config` blob).
        Err(format!(
            "`{DEB_RESOLVE_SENTINEL}` needs a matching `[deb.<name>]` table declaring a \
             `resolve` command"
        ))
    } else if let Some(rest) = value.strip_prefix("deb:") {
        if !is_valid_deb_url(rest, allow_insecure_http)
            && !is_valid_deb_github_locator(rest)
            && !is_valid_deb_apt_locator(rest, allow_insecure_http)
        {
            return Err(format!(
                "invalid deb reference `{rest}` — use an `https://` URL ending in `.deb`, \
                 `github:<owner>/<repo>` to track the latest release's `.deb`, \
                 or `apt:<https-Packages-index-url>` to track an apt repo's latest `.deb`"
            ));
        }
        Ok(Backend::Deb(rest.to_string()))
    } else if value == APPIMAGE_RESOLVE_SENTINEL {
        // Checked before the `appimage:` strip below, or `appimage:resolve` would parse as an
        // `appimage:` URL and be rejected as invalid. Bound to its `[appimage.<name>]` table by
        // `apply_tools`; reaching here means the table is missing or a context without one (e.g. a
        // one-shot `--config` blob).
        Err(format!(
            "`{APPIMAGE_RESOLVE_SENTINEL}` needs a matching `[appimage.<name>]` table declaring a \
             `resolve` command"
        ))
    } else if let Some(rest) = value.strip_prefix("appimage:") {
        if !is_valid_appimage_url(rest, allow_insecure_http) && !is_valid_deb_github_locator(rest) {
            return Err(format!(
                "invalid appimage reference `{rest}` — use an `https://` URL ending in `.AppImage`, \
                 or `github:<owner>/<repo>` to track the latest release's `.AppImage`"
            ));
        }
        Ok(Backend::AppImage(rest.to_string()))
    } else if value == TARBALL_RESOLVE_SENTINEL {
        // The auto-upgrade sentinel is bound to its `[tarball.<name>]` table by `apply_tools`
        // (which strips it before this point), so reaching here means the table is missing or the
        // sentinel was used in a context without one (e.g. a one-shot `--config` blob) — fail closed.
        Err(format!(
            "`{TARBALL_RESOLVE_SENTINEL}` needs a matching `[tarball.<name>]` table declaring a \
             `resolve` command"
        ))
    } else if let Some(rest) = value.strip_prefix("tarball:") {
        if !is_valid_tarball_url(rest, allow_insecure_http) {
            return Err(format!(
                "invalid tarball reference `{rest}` — use an `https://` URL ending in `.tar.gz` \
                 or `.tgz`, or `tarball:resolve` with a `[tarball.<name>]` table"
            ));
        }
        Ok(Backend::Tarball(rest.to_string()))
    } else if value == BINARY_RESOLVE_SENTINEL {
        Err(format!(
            "`{BINARY_RESOLVE_SENTINEL}` needs a matching `[binary.<name>]` table declaring a \
             `resolve` command"
        ))
    } else if let Some(rest) = value.strip_prefix("binary:") {
        if !is_valid_binary_url(rest, allow_insecure_http) {
            return Err(format!(
                "invalid binary reference `{rest}` — use an `https://` URL to the program itself, \
                 or `binary:resolve` with a `[binary.<name>]` table"
            ));
        }
        Ok(Backend::Binary(rest.to_string()))
    } else {
        Err(format!(
            "`{value}` needs a backend prefix — use `nix:<attribute>`, `mise:<token>`, \
             `flake:<ref>`, `deb:<url>` / `deb:github:<owner>/<repo>` / `deb:resolve`, \
             `appimage:<url>` / `appimage:github:<owner>/<repo>` / `appimage:resolve`, \
             `tarball:<url>` / `tarball:resolve`, or `binary:<url>` / `binary:resolve`"
        ))
    }
}

/// The `[packages]` value that opts a package into the auto-upgrade resolver form: it declares the
/// package in `[packages]` (keeping that the canonical tool list) while its `resolve` command lives
/// in a paired `[tarball.<name>]` table. Not a real backend locator — [`apply_tools`] strips it
/// before [`apply_packages`] runs and binds it to the table by name.
pub(super) const TARBALL_RESOLVE_SENTINEL: &str = "tarball:resolve";

/// The `[packages]` value that opts a package into the `deb:` auto-upgrade resolver form — the exact
/// `deb:` analogue of [`TARBALL_RESOLVE_SENTINEL`]. Its `resolve` command lives in a paired
/// `[deb.<name>]` table; [`apply_tools`] strips it before [`apply_packages`] and binds it by name.
pub(super) const DEB_RESOLVE_SENTINEL: &str = "deb:resolve";

/// The `[packages]` value that opts a package into the `appimage:` auto-upgrade resolver form — the
/// exact `appimage:` analogue of [`TARBALL_RESOLVE_SENTINEL`]. Its `resolve` command lives in a
/// paired `[appimage.<name>]` table; [`apply_tools`] strips it before [`apply_packages`] and binds it
/// by name.
pub(super) const APPIMAGE_RESOLVE_SENTINEL: &str = "appimage:resolve";

/// The `[packages]` value that opts a package into the `binary:` auto-upgrade resolver form — the
/// exact `binary:` analogue of [`TARBALL_RESOLVE_SENTINEL`]. Its `resolve` command lives in a paired
/// `[binary.<name>]` table; [`apply_tools`] strips it before [`apply_packages`] and binds it by name.
/// It carries more weight for this backend than for the others: a bare program's URL is
/// version-stamped by construction, so the direct form cannot roll on its own.
const BINARY_RESOLVE_SENTINEL: &str = "binary:resolve";

/// The injection-free URL charset every fetched source is held to: the unreserved set plus the
/// sub-delims a real release URL uses, `%` included so a percent-encoded path segment (a vendor's
/// `My%20App.tar.gz`) is accepted. Nothing here can end or escape a shell word or a nix expression,
/// which is what the value is interpolated into: a generated derivation and a
/// `nix store prefetch-file` argument.
///
/// **One definition, five validators**, for the reason [`is_valid_attr`] states about its own
/// charset: two byte-identical copies are how a charset drifts on one path and not the other. It was
/// written out five times before, once per prebuilt backend, so widening it for one of them would
/// have been a change no reader of the other four could see.
fn is_injection_free_url(url: &str) -> bool {
    url.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '.' | '-' | '_' | '~' | '%'))
}

/// The transport a fetched package source may carry, returning the URL past its scheme so a caller
/// keeps checking the rest exactly as it did. `https://` is always admissible; `http://` only when
/// the resolved config opted in with [`Resolved::allow_insecure_http`].
///
/// **One definition, six validators.** Each of them used to spell `strip_prefix("https://")` itself,
/// which is how a rule drifts on one path and not the others: `is_valid_flake_ref` never had the
/// check at all and accepted `git+http://` while its five siblings refused plaintext. A single entry
/// point is what makes the opt-in mean the same thing everywhere it is honored — and what makes
/// widening it a decision taken once rather than five times.
fn strip_fetch_scheme(url: &str, allow_insecure_http: bool) -> Option<&str> {
    url.strip_prefix("https://").or_else(|| {
        allow_insecure_http
            .then(|| url.strip_prefix("http://"))
            .flatten()
    })
}

/// A `deb:` URL: an `https://` URL to a prebuilt `.deb`. Required to be HTTPS (the fetch is not
/// authenticated beyond TLS, and a `.deb` is executed after autoPatchelf, so a plaintext source is
/// refused — unless [`Resolved::allow_insecure_http`] opted in, see [`strip_fetch_scheme`]) and to
/// end in `.deb` (case-insensitively, as [`is_valid_appimage_url`] matches its own suffix, so a
/// mistyped value is caught and a `.DEB` spelling is not; the character set is the unreserved URL
/// set plus the sub-delims a release URL uses, so the value carries no shell/nix metacharacter —
/// it is interpolated into a generated nix expression and a `nix store prefetch-file` argument,
/// both of which must stay injection-free).
///
/// The case rule is not a preference. `sandbox::prebuilt::select_release_asset` lowercases an
/// asset's name before matching the extension it was asked for, so a release publishing
/// `app_amd64.DEB` is *selected* by the github and resolve forms and would then be refused here —
/// a whole release rejected for the spelling of three characters. (Named rather than linked: that
/// module is private to `sandbox`, so the path does not resolve from this one.)
pub(crate) fn is_valid_deb_url(url: &str, allow_insecure_http: bool) -> bool {
    strip_fetch_scheme(url, allow_insecure_http).is_some_and(|rest| {
        !rest.is_empty() && url.to_ascii_lowercase().ends_with(".deb") && is_injection_free_url(url)
    })
}

/// An `appimage:` URL: an `https://` URL to a prebuilt `.AppImage`. The sibling of [`is_valid_deb_url`]
/// — required to be HTTPS (the fetch is unauthenticated beyond TLS and the bundle is executed after
/// autoPatchelf, so a plaintext source is refused) and to end in `.AppImage` (case-insensitively, so
/// a `.appimage` spelling is accepted; a mistyped value is caught, not silently built). The character
/// set is the same injection-free URL set, so the value carries no shell/nix metacharacter — it is
/// interpolated into a generated nix expression and a `nix store prefetch-file` argument.
pub(crate) fn is_valid_appimage_url(url: &str, allow_insecure_http: bool) -> bool {
    strip_fetch_scheme(url, allow_insecure_http).is_some_and(|rest| {
        !rest.is_empty()
            && url.to_ascii_lowercase().ends_with(".appimage")
            && is_injection_free_url(url)
    })
}

/// A `binary:` URL: an `https://` URL to the program itself, with no archive around it.
///
/// The sibling of [`is_valid_tarball_url`], minus the extension requirement, and the difference is
/// the point rather than an oversight: a bare executable has no extension to check. What the three
/// archive backends get from their suffix is a typo catch, not a content guarantee — a `.tar.gz`
/// ending proves nothing about the bytes behind it. What actually binds a pin to one artefact is the
/// content hash, which this backend takes exactly like the others.
///
/// So the barrier here is what it always really was: HTTPS (the fetch is unauthenticated beyond TLS
/// and the file is executed after autoPatchelf, so a plaintext source is refused) and the same
/// injection-free character set (including `%`, for a percent-encoded path segment), because the
/// value is interpolated into a generated nix expression and a `nix store prefetch-file` argument.
/// A URL that is only a host is refused: the program is a path on it, never the root.
pub(crate) fn is_valid_binary_url(url: &str, allow_insecure_http: bool) -> bool {
    strip_fetch_scheme(url, allow_insecure_http).is_some_and(|rest| {
        rest.split('/').next().is_some_and(|host| !host.is_empty())
            && rest.contains('/')
            && !rest.ends_with('/')
            && is_injection_free_url(url)
    })
}

/// A `tarball:` URL: an `https://` URL to a prebuilt application `.tar.gz`/`.tgz`. The sibling of
/// [`is_valid_deb_url`] — required to be HTTPS (the fetch is unauthenticated beyond TLS and the
/// bundle is executed after autoPatchelf, so a plaintext source is refused) and to end in `.tar.gz`
/// or `.tgz` (case-insensitively; a mistyped value is caught, not silently built). The character set
/// is the same injection-free URL set (including `%`, so a percent-encoded space like a vendor's
/// `My%20App.tar.gz` is accepted), so the value carries no shell/nix metacharacter — it is
/// interpolated into a generated nix expression and a `nix store prefetch-file` argument.
pub(crate) fn is_valid_tarball_url(url: &str, allow_insecure_http: bool) -> bool {
    strip_fetch_scheme(url, allow_insecure_http).is_some_and(|rest| {
        let lower = url.to_ascii_lowercase();
        !rest.is_empty()
            && (lower.ends_with(".tar.gz") || lower.ends_with(".tgz"))
            && is_injection_free_url(url)
    })
}

/// A `deb:github:<owner>/<repo>` locator: track the newest GitHub release's linux `.deb` asset,
/// instead of pinning one versioned URL by hand. `owner` and `repo` are restricted to GitHub's
/// identifier set (`[A-Za-z0-9._-]`, exactly two segments, no empty or bare-dot segment), so the
/// value carries no shell/nix metacharacter — it is interpolated into a
/// `https://api.github.com/repos/<owner>/<repo>/releases/latest` request that must stay
/// injection-free, and the asset URL that request returns is re-validated by [`is_valid_deb_url`]
/// before it is fetched or built.
pub(crate) fn is_valid_deb_github_locator(s: &str) -> bool {
    let Some(path) = s.strip_prefix("github:") else {
        return false;
    };
    let mut parts = path.split('/');
    let (Some(owner), Some(repo), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    [owner, repo].iter().all(|seg| {
        !seg.is_empty()
            && *seg != "."
            && *seg != ".."
            && seg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    })
}

/// A `deb:apt:<packages-url>` locator: track the newest `.deb` in an apt repository's uncompressed
/// `Packages` index, for a vendor apt pool that publishes versioned filenames with no `latest` alias
/// (so a hand-pinned URL goes stale). The `<packages-url>` is an `https://` URL restricted to the
/// same injection-free character set as [`is_valid_deb_url`] (it is interpolated into a
/// `builtins.fetchurl`), but it points at the index, not a `.deb`, so the `.deb` suffix is **not**
/// required. sbx fetches the index, selects the highest version's `.deb`, and **re-validates that
/// derived URL through [`is_valid_deb_url`]** before it is fetched or built — so the remote index
/// cannot inject a bad URL. The index is then checked against the repository's signed `InRelease`,
/// whose signing key sbx pins the first time it verifies one, so a later index must be attested by
/// that same key or the resolve is refused. Scope (documented, not a gap): the index must be the
/// **uncompressed** `Packages` (no `.gz`/`.xz` decompression) and sbx expects a
/// **single-application** repo, not a general Debian mirror; a repository that publishes no
/// `InRelease` keeps the TLS-plus-unpack trust level of a direct `deb:` URL, and says so.
pub(crate) fn is_valid_deb_apt_locator(s: &str, allow_insecure_http: bool) -> bool {
    let Some(url) = s.strip_prefix("apt:") else {
        return false;
    };
    strip_fetch_scheme(url, allow_insecure_http)
        .is_some_and(|rest| !rest.is_empty() && is_injection_free_url(url))
}

/// Set the package named `name` to `backend` with the supplying layer's trust,
/// overriding an existing entry so a later layer wins while preserving declaration
/// order.
pub(super) fn upsert_package(
    out: &mut Vec<Package>,
    name: String,
    backend: Backend,
    state: TrustState,
    libs: Vec<String>,
) {
    match out.iter_mut().find(|p| p.name == name) {
        Some(slot) => {
            slot.backend = backend;
            slot.state = state;
            // A layer that re-declares a package re-declares what it is patched against too: the
            // decoration belongs to the declaration, so it never outlives it. `apply_prebuilt_libs`
            // fills the new one in from this layer's own table, right after.
            slot.libs = libs;
        }
        None => out.push(Package {
            name,
            backend,
            state,
            libs,
        }),
    }
}

/// A package label usable as a single path component (it names a garbage-collection
/// root) and a stable merge key: non-empty, neither `.` nor `..`, and built only
/// from portable filename characters — so it can never carry a path separator,
/// escape its directory, or collide with a traversal element.
pub(super) fn is_valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// A nixpkgs attribute path: a dotted chain of attribute names (e.g.
/// `python3Packages.requests`). Restricted to the characters a real attribute uses
/// so a declared value can never widen into a different flake reference or smuggle
/// shell- or flake-significant characters, even though it is passed to nix as a
/// single argument.
///
/// **This charset is the whole barrier on one path.** `[packages]` and `[plugin.<name>] programs`
/// both feed it, and the unfree provisioning branch composes its `--expr` by interpolating the
/// attribute into a nix expression ([`crate::store::provision_unfree`]); the free branch passes
/// `{flake_ref}#{attr}` positionally and does not. So the characters that would end or escape that
/// interpolation — `{`, `}`, `\`, a newline, a quote — are refused here and pinned by
/// `package_name_and_attribute_validators`, which is where a widening of this set has to argue with
/// a test rather than pass unnoticed.
///
/// One definition, shared with the nixhub path, which validates the attribute it reads from a third
/// party before it becomes a flake reference. Two byte-identical copies is how a charset drifts on
/// one path and not the other.
pub(crate) fn is_valid_attr(attr: &str) -> bool {
    !attr.is_empty()
        && attr
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+'))
}

/// An attribute that can be written **bare into a nix expression**, as opposed to one handed to nix
/// positionally as `<flakeref>#<attr>`.
///
/// [`is_valid_attr`] admits `+`, and that is right for the callers that pass an attribute as an
/// argument: a flake output name carrying one reaches nix as argv and never meets its grammar. It
/// is wrong for a caller that *interpolates*, because inside an expression `+` is the addition
/// operator: `with pkgs; [ libstdc++ ]` is a syntax error rather than a lookup, and the failure
/// surfaces from inside a derivation instead of from the field that caused it.
///
/// Nothing reachable is refused by the distinction. No attribute of the pinned nixpkgs carries a
/// `+`, at the top level or in the sets a library entry names in practice, so the character can be
/// rejected where it would break an expression without taking away a package anyone can install.
pub(crate) fn is_bare_nix_attr(attr: &str) -> bool {
    is_valid_attr(attr) && !attr.contains('+')
}

/// A mise backend token (the part after `mise:`), e.g. `aqua:example/demo-tool`, `bare-tool`,
/// `npm:@example/demo-tool`, or `aqua:example/demo-tool@0.141.0`. It rides the equip
/// wrapper positionally, so it cannot inject shell whatever it contains; the charset is
/// still restricted to what a real token uses (no whitespace or control characters) so a
/// malformed value is refused rather than handed to mise. The `[`, `]`, `,` and `=` are
/// admitted for PEP 508 extras (`pipx:demo-agent[web]`, `pipx:demo-agent[web,messaging]`) — a
/// Python install selects optional dependency groups that way — and for mise's tool options
/// (`github:owner/repo[version_prefix=v]`), which are how a repository publishing two release
/// lines is told which one it is being asked for. Without `=` the bracket pair was admitted
/// while the assignment it delimits was not, so an option could be spelled but never given a
/// value. None of the four are shell or nix metacharacters in any backend (the token is
/// positional argv to mise, and the equip never interpolates it into a nix expression or a
/// shell string), so admitting them adds no injection surface; a backend that does not
/// understand them simply rejects the token.
pub(super) fn is_valid_mise_token(token: &str) -> bool {
    !token.is_empty()
        && token.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    ':' | '/' | '@' | '.' | '_' | '-' | '+' | '[' | ']' | ',' | '='
                )
        })
}

/// A flake reference (the part after `flake:`), e.g. `github:owner/repo#attr`,
/// `github:owner/repo/rev#attr`, or `git+https://host/repo?ref=main#attr`. It rides the
/// in-cage build wrapper positionally, so it cannot inject shell whatever it contains; the
/// charset is still restricted to what a real flake ref uses — the URL-significant
/// characters (`:` `/` `#` `?` `=` `&` `~`) plus the identifier set — so a malformed or
/// shell/space-bearing value is refused rather than handed to nix. **Local sources are
/// rejected** so a package declaration can never point the in-cage build at a filesystem
/// path: not only the explicit local schemes (`path:`, and any `file:` or `+file:` scheme —
/// `file://`, `git+file:`, `tarball+file:`, …) but also a **bare path-flakeref** — nix treats a
/// ref starting with `/`, `.`, or `~` as a local path — and an ambiguous registry-indirect ref
/// (`nixpkgs`), by *requiring an explicit scheme* (a `:`). A real remote ref always carries one
/// (`github:`, `git+https:`, `gitlab:`, …).
fn is_valid_flake_ref(reference: &str, allow_insecure_http: bool) -> bool {
    if reference.is_empty()
        || reference.starts_with("path:")
        || reference.starts_with("file:")
        || reference.contains("+file:")
        || reference.starts_with('/')
        || reference.starts_with('.')
        || reference.starts_with('~')
        || !reference.contains(':')
    {
        return false;
    }
    // Plaintext transport, refused in the same shape the local schemes above are — a bare
    // `http://…` ref and the `+http://` composed forms (`git+http:`, `tarball+http:`). `https://`
    // and `+https://` do not match either test, the `s` sitting where the `:` must be. Measured
    // rather than assumed: nix accepts both composed http forms and fetches them, so this refusal
    // is what stands between an approved config and a source anyone on the path can rewrite.
    // The five sibling backends have required HTTPS since they were written; this validator is the
    // one that never did, which is why the opt-in below arrives here as a widening rather than as
    // the removal of a check it already had.
    if !allow_insecure_http && (reference.starts_with("http://") || reference.contains("+http://"))
    {
        return false;
    }
    reference.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                ':' | '/' | '#' | '?' | '=' | '&' | '~' | '@' | '.' | '_' | '-' | '+'
            )
    })
}
