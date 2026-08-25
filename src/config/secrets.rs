//! Secret SOURCE + validation layer: turn a `[secret."host"]` entry (a `from` ref or a
//! terse `key` expanded through `[secret.defaults]`) into a validated, host-scoped
//! [`HeaderSecret`], and fold a layer's entries into the resolved set. Every value here is a
//! host-side transform — the plaintext is resolved before the cage and never enters it.

use super::*;

/// Validate and fold a layer's `[secret]` host entries into `out`, expanding any terse `key`
/// through `defaults`. Each entry is fully validated (kind, source, target, header, type); a
/// malformed one is dropped with a warning naming the host — fail-closed, since a credential
/// injection is security-relevant. A later entry for the same (host, header) overrides an
/// earlier one (last-wins) with a warning, so a duplicate destination never silently emits two
/// header copies upstream.
pub(super) fn apply_secret_section(
    out: &mut Vec<HeaderSecret>,
    warnings: &mut Vec<String>,
    source: &str,
    hosts: BTreeMap<String, RawHostSecrets>,
    defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) {
    for (host, entry) in hosts {
        let list = match entry {
            RawHostSecrets::One(s) => vec![s],
            RawHostSecrets::Many(v) => v,
        };
        for raw in list {
            match validate_host_secret(&host, raw, defaults, plugins) {
                Ok(secret) => upsert_secret(out, warnings, source, secret),
                Err(e) => warnings.push(format!("{source}: ignoring secret for `{host}` — {e}")),
            }
        }
    }
}

/// Total host secrets in a section — counting each element of a `[[secret."host"]]` array — for
/// the one-line warning when an untrusted project's whole section is dropped.
pub(super) fn count_host_secrets(hosts: &BTreeMap<String, RawHostSecrets>) -> usize {
    hosts
        .values()
        .map(|h| match h {
            RawHostSecrets::One(_) => 1,
            RawHostSecrets::Many(v) => v.len(),
        })
        .sum()
}

/// Set the secret for its target and headers, overriding an existing one (last-wins) with a
/// warning while preserving declaration order. Two secrets to the same host that write the same
/// header would otherwise inject two copies of it upstream.
///
/// The comparison is over **every** header each declaration writes, not the one it is named by. A
/// signed declaration's `header` is only the first its plugin's manifest lists, so two signers for
/// one host whose manifests differ in that first header and agree on a later one read as unrelated
/// and both went on the wire — which is the exact collision this function exists to prevent, on the
/// declarations most likely to produce it (a signer writes several headers by design).
pub(super) fn upsert_secret(
    out: &mut Vec<HeaderSecret>,
    warnings: &mut Vec<String>,
    source: &str,
    secret: HeaderSecret,
) {
    let writes = secret.headers();
    let shared = |s: &HeaderSecret| -> Option<String> {
        s.headers()
            .iter()
            .find(|h| writes.iter().any(|w| w.eq_ignore_ascii_case(h)))
            .map(|h| (*h).to_string())
    };
    match out.iter_mut().find_map(|s| {
        (s.to == secret.to)
            .then(|| shared(s))
            .flatten()
            .map(|h| (s, h))
    }) {
        Some((slot, header)) => {
            warnings.push(format!(
                "{source}: a later secret overrides an earlier one for `{header}` -> {}",
                secret.to
            ));
            *slot = secret;
        }
        None => {
            // Two credentials under one name are legal (the name is a label, not a key) but
            // ambiguous where the name is *rendered*: a redacted value prints `${name}`, so the
            // reader could not tell which credential was withheld. Warn, naming both targets.
            if let Some(clash) = out.iter().find(|s| s.name == secret.name) {
                warnings.push(format!(
                    "{source}: two secrets share the name `{}` ({} and {}) — a redacted value \
                     names only the name, so give them distinct ones",
                    secret.name, clash.to, secret.to
                ));
            }
            out.push(secret);
        }
    }
}

/// Validate one host entry into a [`HeaderSecret`], or report why it is malformed. `host` is the
/// section key (the injection target). Every check fails closed: an unknown kind, a missing or
/// both-set source, a non-concrete target, a bad header name, or a missing/unknown type each
/// drops the secret. `kind` is optional, defaulting to the only kind today.
pub(super) fn validate_host_secret(
    host: &str,
    raw: RawHostSecret,
    defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) -> Result<HeaderSecret, String> {
    let kind = raw.kind.as_deref().unwrap_or("http-header");
    if kind != "http-header" {
        return Err(format!(
            "unknown kind `{kind}` (the only secret kind today is \"http-header\")"
        ));
    }
    let sources = resolve_host_sources(&raw, defaults, plugins)?;
    let to = validate_secret_target(host)?;
    // A signer answers what a fixed value cannot, and it answers *all* of it: which headers this
    // request carries comes from the plugin's reviewed manifest, so a declaration may not also
    // state one. Refused rather than ignored, because a `header` that looked honoured and was not
    // is exactly the silent misconfiguration this layer refuses everywhere else.
    let signer = match raw.sign.as_deref() {
        None => None,
        Some(name) => {
            for (field, present) in [
                ("header", raw.header.is_some()),
                ("type", raw.value_type.is_some()),
                ("prefix", raw.prefix.is_some()),
            ] {
                if present {
                    return Err(format!(
                        "`sign` and `{field}` cannot both be set — a signer's manifest says which \
                         headers it sets and how, so `{field}` here would state a second answer"
                    ));
                }
            }
            let plugin = plugins
                .signer(name)
                .ok_or_else(|| match plugins.name_conflict(name) {
                    Some(claimants) => format!(
                        "`sign` names `{name}`, which more than one installed plugin claims ({}) \
                         — they are all disabled until one remains",
                        crate::plugins::quoted_list(claimants)
                    ),
                    None => format!(
                        "`sign` names `{name}`, which is not an installed signer plugin (see \
                         `sbx plugins list`)"
                    ),
                })?;
            Some(Box::new(plugin.clone()))
        }
    };
    // `header` and `type` may come from the entry or fall back to `[secret.defaults]`; an entry
    // that names neither (on itself or in the defaults) is the same explicit error as before —
    // there is no silent built-in default. A signed declaration takes neither: its inventory label
    // is the first header its plugin declares, and its shape is the plugin.
    let (header, shape) = match &signer {
        // The first header the plugin declares — the declaration's *label*, not what
        // [`upsert_secret`] dedups on. That distinction is the correction: the dedup asks whether
        // two declarations to one host write any header in common, so two signers whose manifests
        // lead with different headers and agree on a later one are the same collision as an
        // ordinary duplicate and get the same last-wins answer. Reading the first header alone let
        // that pair through, and both went on the wire.
        Some(plugin) => (
            plugin.signer.sets_headers[0].clone(),
            // Never read for a signed declaration: the plugin forms every value. Spelled as the
            // empty transform rather than left unset, so nothing here can be mistaken for a shape
            // that applies.
            HeaderShape {
                prefix: String::new(),
                base64: false,
            },
        ),
        None => {
            let header = raw
                .header
                .as_deref()
                .or(defaults.header.as_deref())
                .ok_or_else(|| {
                    "set `header` (or a `[secret.defaults] header`) — the request header to set"
                        .to_string()
                })?;
            validate_header_name(header)?;
            let value_type = raw.value_type.as_deref().or(defaults.value_type.as_deref());
            (
                header.to_string(),
                validate_header_shape(value_type, raw.prefix.as_deref())?,
            )
        }
    };
    let name = match raw.name.as_deref() {
        Some(n) => validate_secret_name(n)?.to_string(),
        None => host.to_string(),
    };
    Ok(HeaderSecret {
        name,
        description: raw.description.as_deref().map(sanitize_description),
        sources,
        to,
        header,
        shape,
        signer,
    })
}

/// The longest description kept, in characters — a label for one terminal line, not a document.
const DESCRIPTION_MAX: usize = 200;

/// The longest logical name accepted, in characters.
const NAME_MAX: usize = 64;

/// Validate a secret's logical name: a short label of letters, digits, `_`, `-`, or `.`. The
/// character set is deliberately narrow because the name is *rendered into output* — a redacted
/// value is replaced by `${<name>}` — so a name carrying `}`, a newline, or an escape sequence
/// could forge a placeholder or a terminal control sequence in text a human then reads.
pub(super) fn validate_secret_name(name: &str) -> Result<&str, String> {
    if name.is_empty() {
        return Err("`name` is empty — omit it to default to the host".to_string());
    }
    if name.chars().count() > NAME_MAX {
        return Err(format!("`name` is longer than {NAME_MAX} characters"));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
    {
        return Err(format!(
            "`name` contains `{bad}` — use letters, digits, `_`, `-`, or `.` \
             (the name is rendered into output as `${{name}}`)"
        ));
    }
    Ok(name)
}

/// Reduce a free-text description to one safe display line: control characters (a newline, an
/// escape that could drive a terminal) become spaces, runs of whitespace collapse, and the result
/// is truncated. Never rejects — a description is a label, so a sloppy one is cleaned rather than
/// dropping the credential it documents.
pub(super) fn sanitize_description(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut out = String::with_capacity(cleaned.len());
    for word in cleaned.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    out.chars().take(DESCRIPTION_MAX).collect()
}

/// The resolver chain for a host secret: either the explicit `from` (a single `scheme://locator`
/// ref or a list tried in order) or the terse `key` expanded through `defaults` — exactly one of
/// the two. Both set, or neither, is rejected; an empty `from` list is rejected. The values are
/// not read here; that is host-side at launch.
fn resolve_host_sources(
    raw: &RawHostSecret,
    defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) -> Result<Vec<SecretSource>, String> {
    match (raw.key.as_deref(), &raw.from) {
        (Some(_), Some(_)) => {
            Err("set `key` or `from`, not both — a secret has one source form".to_string())
        }
        (None, None) => Err(
            "set `key` or `from` — a secret needs a source (e.g. `key = \"github_token\"` \
                 or `from = \"env://VAR\"`)"
                .to_string(),
        ),
        (Some(key), None) => expand_key(key, defaults, plugins),
        (None, Some(from)) => {
            let refs: &[String] = match from {
                SecretFrom::One(one) => std::slice::from_ref(one),
                SecretFrom::Many(list) => {
                    if list.is_empty() {
                        return Err(
                            "`from` is an empty list — declare at least one resolver ref"
                                .to_string(),
                        );
                    }
                    list
                }
            };
            refs.iter().map(|r| parse_secret_ref(r, plugins)).collect()
        }
    }
}

/// The validated `[secret.defaults]` — the resolver order and per-resolver bindings a terse `key`
/// expands through, plus a default `header`/`type` an entry may omit. Built per config layer;
/// bindings and the header/type are validated lazily, when an entry actually uses them, so a
/// defaults table no entry references never blocks a launch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct SecretDefaults {
    /// Resolver names to try, in order, for an unpinned key.
    order: Vec<String>,
    /// The sops file a terse sops key reads from (`sops://<file>#<key>`).
    sops_file: Option<String>,
    /// How to case a terse key before using it as a variable name (`upper`/`lower`/`asis`).
    env_case: Option<String>,
    /// The base directory a terse file key reads from (`file://<dir>/<key>`).
    file_dir: Option<String>,
    /// The default header name for an entry that omits `header`.
    header: Option<String>,
    /// The default value type for an entry that omits `type`.
    value_type: Option<String>,
    /// One locator template per plugin scheme, `{key}` standing for the terse key. A scheme with
    /// a table but no template holds the identity, so the entry says the same thing either way.
    resolver_locators: BTreeMap<String, String>,
}

/// What a scheme with no declared template expands to: the key, unchanged.
const IDENTITY_LOCATOR: &str = "{key}";

impl SecretDefaults {
    /// The defaults declared in one `[secret.defaults]` table.
    pub(super) fn from_raw(raw: &RawSecretDefaults) -> Self {
        Self {
            order: raw.order.clone(),
            sops_file: raw.sops.as_ref().map(|s| s.file.clone()),
            env_case: raw.env.as_ref().and_then(|e| e.case.clone()),
            file_dir: raw.file.as_ref().map(|f| f.dir.clone()),
            header: raw.header.clone(),
            value_type: raw.value_type.clone(),
            resolver_locators: resolver_locators(raw),
        }
    }

    /// These defaults overridden field-by-field by a project's `[secret.defaults]`: an order, a
    /// binding, or a header/type the project sets wins; anything it omits inherits the global value.
    pub(super) fn merged_with(&self, raw: &RawSecretDefaults) -> Self {
        Self {
            order: if raw.order.is_empty() {
                self.order.clone()
            } else {
                raw.order.clone()
            },
            sops_file: raw
                .sops
                .as_ref()
                .map(|s| s.file.clone())
                .or_else(|| self.sops_file.clone()),
            env_case: raw
                .env
                .as_ref()
                .and_then(|e| e.case.clone())
                .or_else(|| self.env_case.clone()),
            file_dir: raw
                .file
                .as_ref()
                .map(|f| f.dir.clone())
                .or_else(|| self.file_dir.clone()),
            header: raw.header.clone().or_else(|| self.header.clone()),
            value_type: raw.value_type.clone().or_else(|| self.value_type.clone()),
            // Per scheme, like every other binding: the project's table for a scheme replaces the
            // global one for that scheme alone, and a scheme it never names keeps what the global
            // config bound. Replacing the whole map would make declaring one plugin's template
            // silently unbind every other.
            resolver_locators: {
                let mut merged = self.resolver_locators.clone();
                merged.extend(resolver_locators(raw));
                merged
            },
        }
    }

    /// The locator template bound to `scheme`, or the identity for a scheme that declared none.
    fn resolver_locator(&self, scheme: &str) -> &str {
        self.resolver_locators
            .get(scheme)
            .map_or(IDENTITY_LOCATOR, String::as_str)
    }
}

/// Warn about a `[secret.defaults.resolver.<scheme>]` table that binds nothing, per layer, so a
/// misspelled scheme is reported where it was written rather than sitting inert.
///
/// A binding is not itself a source: nothing resolves until some entry names the scheme in `order`
/// or in a `key@scheme` pin, and that path already fails closed on an unknown name. What this
/// catches is the table nobody ever reaches — the same gap `[plugin.<name>]` reports for a name no
/// secret uses, and reported the same way.
pub(super) fn warn_resolver_bindings(
    warnings: &mut Vec<String>,
    source: &str,
    raw: &RawSecretDefaults,
    plugins: &PluginRegistry,
) {
    for scheme in raw.resolver.keys() {
        // A built-in has a binding table of its own, with a shape this one cannot express. Two
        // mechanisms for one expansion is the ambiguity; say which table is the real one.
        if matches!(scheme.as_str(), "env" | "file" | "sops") {
            warnings.push(format!(
                "{source}: ignoring `[secret.defaults.resolver.{scheme}]` — `{scheme}` is a \
                 built-in resolver, bound by `[secret.defaults.{scheme}]`"
            ));
        } else if plugins.resolver(scheme).is_none() {
            warnings.push(format!(
                "`[secret.defaults.resolver.{scheme}]`: no installed resolver plugin claims \
                 `{scheme}://` — check the spelling against `sbx plugins list` (the table is \
                 otherwise inert)"
            ));
        }
    }
}

/// The `[secret.defaults.resolver.<scheme>]` tables as templates, a scheme that set no `locator`
/// holding the identity — so a declared scheme is present in the map either way, and a caller
/// listing what a layer bound sees the table that was written.
fn resolver_locators(raw: &RawSecretDefaults) -> BTreeMap<String, String> {
    raw.resolver
        .iter()
        .map(|(scheme, binding)| {
            let template = binding
                .locator
                .clone()
                .unwrap_or_else(|| IDENTITY_LOCATOR.to_string());
            (scheme.clone(), template)
        })
        .collect()
}

/// Expand a terse `key` spec into a resolver chain. The spec is `name[@resolver[,resolver…]]`:
/// without a `@` pin the default `order` is used; with one, exactly those resolvers in that
/// order, for this secret only. The `name` is validated as a conservative dotted key (so it can
/// never carry a path separator into the `file`/`sops` locator), each resolver builds a
/// `scheme://locator` ref, and the existing [`parse_secret_ref`] validates it — one validation
/// path for terse and explicit sources alike. A missing binding or an empty order fails closed.
pub(super) fn expand_key(
    spec: &str,
    defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) -> Result<Vec<SecretSource>, String> {
    let (name, resolvers) = match spec.rsplit_once('@') {
        Some((name, pin)) => {
            let list: Vec<String> = pin.split(',').map(|r| r.trim().to_string()).collect();
            if list.iter().any(String::is_empty) {
                return Err(format!(
                    "the key `{spec}` has an empty resolver name after `@`"
                ));
            }
            (name, list)
        }
        None => (spec, defaults.order.clone()),
    };
    validate_terse_key(name)?;
    if resolvers.is_empty() {
        return Err(format!(
            "no resolver for key `{name}`: set `[secret.defaults] order` or pin it (e.g. \
             `{name}@env`)"
        ));
    }
    // A resolver name is a built-in or a scheme an installed plugin claims, so the registry is the
    // same one an explicit `from` ref is parsed against: whichever form names a source, it names
    // the same set of sources.
    resolvers
        .iter()
        .map(|r| parse_secret_ref(&build_ref(r, name, defaults, plugins)?, plugins))
        .collect()
}

/// Build a `scheme://locator` ref for one resolver from a terse `key`, applying that resolver's
/// binding: `env` cases the key into a variable name; `sops` joins the key onto the bound file
/// (`<file>#<key>`); `file` joins it onto the bound base directory (`<dir>/<key>`); a plugin
/// scheme writes the key into its `locator` template, which defaults to the key alone. A resolver
/// whose binding is unset, or a name neither built in nor claimed by an installed plugin, fails
/// closed.
fn build_ref(
    resolver: &str,
    key: &str,
    defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) -> Result<String, String> {
    match resolver {
        "env" => {
            let name = match defaults.env_case.as_deref() {
                None | Some("asis") => key.to_string(),
                Some("upper") => key.to_ascii_uppercase(),
                Some("lower") => key.to_ascii_lowercase(),
                Some(other) => {
                    return Err(format!(
                        "unknown env `case` `{other}` (expected \"upper\", \"lower\", or \"asis\")"
                    ));
                }
            };
            Ok(format!("env://{name}"))
        }
        "sops" => {
            let file = defaults.sops_file.as_deref().ok_or_else(|| {
                format!(
                    "key `{key}` uses the sops resolver, but `[secret.defaults.sops] file` is unset"
                )
            })?;
            if file.contains('#') {
                return Err(format!(
                    "the sops file `{file}` contains `#`, reserved by the `sops://<file>#<key>` form"
                ));
            }
            Ok(format!("sops://{file}#{key}"))
        }
        "file" => {
            let dir = defaults.file_dir.as_deref().ok_or_else(|| {
                format!(
                    "key `{key}` uses the file resolver, but `[secret.defaults.file] dir` is unset"
                )
            })?;
            if !std::path::Path::new(dir).is_absolute() {
                return Err(format!(
                    "the `[secret.defaults.file] dir` `{dir}` must be an absolute path"
                ));
            }
            let sep = if dir.ends_with('/') { "" } else { "/" };
            Ok(format!("file://{dir}{sep}{key}"))
        }
        // Any other name is a scheme an installed plugin claims. The plugin is not run here and its
        // registry entry is not carried either: this only decides that the scheme exists, so the
        // ref it builds fails on a misspelling instead of reaching `parse_secret_ref` as an
        // unknown scheme with a locator already shaped for it.
        other if plugins.resolver(other).is_some() => Ok(format!(
            "{other}://{}",
            expand_locator(defaults.resolver_locator(other), other, key)?
        )),
        other => Err(format!(
            "unknown resolver `{other}` for key `{key}` (built-in: env, file, sops; or a scheme \
             an installed resolver plugin claims — see `sbx plugins list`)"
        )),
    }
}

/// Write `key` into a plugin scheme's `locator` template, `{key}` being the one placeholder.
///
/// Two refusals, both fail-closed. A template that never writes `{key}` would give every terse key
/// the same locator, so one entry's secret would answer for another's. An unknown placeholder is
/// refused rather than passed through, because a `{`…`}` reaching the plugin's `argv[1]` is a
/// locator the user believes carries a value and that the plugin will look up literally.
fn expand_locator(template: &str, scheme: &str, key: &str) -> Result<String, String> {
    let mut out = String::with_capacity(template.len() + key.len());
    let mut rest = template;
    let mut wrote_key = false;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            break;
        };
        let name = &after[..close];
        if name != "key" {
            return Err(format!(
                "the `[secret.defaults.resolver.{scheme}] locator` names `{{{name}}}`, and the \
                 only placeholder a locator takes is `{{key}}`"
            ));
        }
        out.push_str(&rest[..open]);
        out.push_str(key);
        wrote_key = true;
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    if !wrote_key {
        return Err(format!(
            "the `[secret.defaults.resolver.{scheme}] locator` `{template}` never writes `{{key}}`, \
             so every terse key would resolve the same secret"
        ));
    }
    Ok(out)
}

/// Validate a terse `key`: dot-separated segments, each non-empty and made of letters, digits,
/// `_`, or `-`. Stricter than an env variable name on purpose — it forbids `/` and `..`, so a key
/// joined onto a `file`/`sops` locator can never carry a path separator or traverse out of the
/// bound directory.
fn validate_terse_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("a terse `key` is empty".to_string());
    }
    for seg in key.split('.') {
        if seg.is_empty() {
            return Err(format!("the key `{key}` has an empty segment"));
        }
        if !seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!(
                "the key `{key}` has an invalid segment `{seg}` (allowed: letters, digits, _, -, \
                 separated by `.`)"
            ));
        }
    }
    Ok(())
}

/// Parse one `from` entry — a `scheme://locator` resolver ref — into a [`SecretSource`]. The
/// built-in schemes are `env`, `file`, and `sops`; any other scheme must be claimed by an
/// installed resolver plugin, else it is an error. A bare token with no `://` is an error too
/// (fail-closed: never a silent mis-read as a path or a variable).
pub(super) fn parse_secret_ref(
    reff: &str,
    plugins: &PluginRegistry,
) -> Result<SecretSource, String> {
    let Some((scheme, locator)) = reff.split_once("://") else {
        return Err(format!(
            "a secret source needs a scheme, e.g. `env://VAR` or `file:///abs/path` (`{reff}`)"
        ));
    };
    match scheme {
        "env" => env_source(locator),
        "file" => file_source(locator),
        "sops" => sops_source(locator),
        other => match plugins.resolver(other) {
            Some(plugin) => {
                validate_plugin_locator(other, locator)?;
                Ok(SecretSource::Plugin {
                    plugin: Box::new(plugin.clone()),
                    locator: locator.to_string(),
                })
            }
            None => Err(format!(
                "unknown secret resolver scheme `{other}://` (built-in: env, file, sops; \
                 or install a resolver plugin that claims it)"
            )),
        },
    }
}

/// Validate a plugin ref's locator before it becomes the plugin's `argv[1]`: non-empty and free
/// of control characters (a NUL would truncate the argument, a newline could confuse a
/// line-oriented resolver). The trust gate is the real control — an untrusted project's secrets
/// are dropped before this is reached — so this is belt-and-suspenders for the trusted path.
fn validate_plugin_locator(scheme: &str, locator: &str) -> Result<(), String> {
    if locator.is_empty() {
        return Err(format!("the `{scheme}://` ref has an empty locator"));
    }
    if locator.chars().any(char::is_control) {
        return Err(format!(
            "the `{scheme}://` ref locator contains a control character"
        ));
    }
    Ok(())
}

/// An `env` source from a variable name, validated as a usable shell variable name.
fn env_source(var: &str) -> Result<SecretSource, String> {
    if !is_valid_env_key(var) {
        return Err(format!("`{var}` is not a valid environment variable name"));
    }
    Ok(SecretSource::Env(var.to_string()))
}

/// A `sops` source from `<file>[#<dotted.key>]`. The `#` is split off the **end** (a sops key
/// cannot contain `#`, so a `#` in the file path is preserved); the key, when present, is
/// charset-validated so it can never malform the `["seg"]["seg"]` extract expression sops parses.
/// The file may be relative (resolved against the project root host-side) or absolute.
fn sops_source(locator: &str) -> Result<SecretSource, String> {
    let (file, key) = match locator.rsplit_once('#') {
        Some((f, k)) => (f, Some(k)),
        None => (locator, None),
    };
    if file.is_empty() {
        return Err("a sops source needs a file path `sops://<file>[#<key>]`".to_string());
    }
    if let Some(k) = key {
        validate_sops_key(k)?;
    }
    Ok(SecretSource::Sops {
        file: PathBuf::from(file),
        key: key.map(String::from),
    })
}

/// Validate a sops `--extract` key path: dot-separated segments, each non-empty and made of
/// letters, digits, `_`, or `-`. Rejects an empty key (a trailing `#`), an empty segment
/// (`a..b`, `.a`, `a.`), and any character that could break the bracketed extract expression.
fn validate_sops_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("the sops source has an empty key after `#`".to_string());
    }
    for seg in key.split('.') {
        if seg.is_empty() {
            return Err(format!("the sops key `{key}` has an empty path segment"));
        }
        if !seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!(
                "the sops key `{key}` has an invalid segment `{seg}` (allowed: letters, digits, _, -)"
            ));
        }
    }
    Ok(())
}

/// A `file` source from an absolute host path (a relative path is rejected — it would resolve
/// against an unpredictable working directory).
fn file_source(file: &str) -> Result<SecretSource, String> {
    let path = PathBuf::from(file);
    if !path.is_absolute() {
        return Err(format!(
            "a file secret path must be an absolute path `{file}`"
        ));
    }
    Ok(SecretSource::File(path))
}

/// Classify a secret's `to` into a concrete-host rule. A credential goes to one known
/// destination, so only an exact host, IP, or `host[:port]/path` URL is allowed — a
/// `*.domain` wildcard or a `re:` regex is rejected, since either could match a host the
/// user never meant to hand the secret to.
pub(super) fn validate_secret_target(to: &str) -> Result<Rule, String> {
    let rule = crate::allowlist::classify(to).map_err(|e| format!("invalid `to` target — {e}"))?;
    // A credential is host-scoped — injected into every request to the destination, regardless of
    // verb — so a `{...}` (or `{*}`) method prefix on the `to` host is meaningless and would only
    // confuse. A bare `to` host classifies as `Methods::Unspecified`; anything else is an explicit
    // prefix, rejected fail-closed (a method constraint belongs only on an allow/deny rule).
    if rule.methods != Methods::Unspecified {
        return Err(format!(
            "a secret `to` host carries no method prefix — remove the `{{...}}` from `{to}` \
             (a credential is injected for the host on every method)"
        ));
    }
    // A credential is an HTTP-header injection, which only the inspected-over-TLS (MITM) path can
    // perform. A `tcp://` (raw L4) destination is spliced byte-for-byte, so there is no request head
    // to inject into; an `http://` (cleartext L7) destination has a head, but sending a bearer in the
    // clear would downgrade the credential. Reject either fail-closed rather than silently never
    // injecting (or injecting over plaintext).
    if rule.layer != Layer::L7 {
        let scheme = if rule.layer == Layer::L4 {
            "tcp://"
        } else {
            "http://"
        };
        return Err(format!(
            "a secret `to` host must be an inspected-over-TLS destination — remove the `{scheme}` \
             from `{to}` (a header credential is never injected into a raw or a cleartext stream)"
        ));
    }
    match rule.kind {
        RuleKind::Ip(..) | RuleKind::Host(..) | RuleKind::Url { .. } => Ok(rule),
        RuleKind::Subdomain(..) => Err(format!(
            "`to` must be a concrete host, not the `*.` wildcard `{to}` \
             (a credential is sent to one known host)"
        )),
        RuleKind::Regex { .. } => Err(format!(
            "`to` must be a concrete host, not the regex `{to}` \
             (a credential is sent to one known host)"
        )),
    }
}

/// A header name usable in a request head: a non-empty token free of control characters,
/// whitespace, and `:`, so it can never split the head or carry a second header.
fn validate_header_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("the `header` name is empty".to_string());
    }
    if name
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == ':')
    {
        return Err(format!("invalid `header` name `{name}`"));
    }
    Ok(())
}

/// Build the [`HeaderShape`] from the required `type` and the optional `prefix`. The type
/// is required — there is no default, so an omitted type is an explicit error rather than a
/// silent (and likely wrong) transform. A given `prefix` may carry no control character,
/// since it becomes part of the header value.
pub(super) fn validate_header_shape(
    value_type: Option<&str>,
    prefix: Option<&str>,
) -> Result<HeaderShape, String> {
    if let Some(p) = prefix
        && p.chars().any(char::is_control)
    {
        return Err("the `prefix` contains a control character".to_string());
    }
    let (default_prefix, base64) =
        match value_type {
            Some("bearer") => ("Bearer ", false),
            Some("raw") => ("", false),
            Some("basic") => ("Basic ", true),
            Some(other) => {
                return Err(format!(
                    "unknown `type` `{other}` (expected \"bearer\", \"basic\", or \"raw\")"
                ));
            }
            None => return Err(
                "missing `type` (one of \"bearer\", \"basic\", or \"raw\"; set it on the secret \
                 or as a `[secret.defaults] type`)"
                    .to_string(),
            ),
        };
    Ok(HeaderShape {
        prefix: prefix.unwrap_or(default_prefix).to_string(),
        base64,
    })
}
