//! The on-disk shape of an `ops` config file and its parse.

use serde::Deserialize;
use std::collections::BTreeMap;

/// The fields a global `ops.toml` or a project `.ops.toml` may declare. Every
/// field is optional, and unknown fields are ignored, so a config written for a
/// newer ops still loads on an older one — the schema is additive, never a hard
/// parse wall a project could trip a command on.
///
/// Fields are split by the trust gate, not by this struct: `env` is a *free*
/// field (applied even from an untrusted project, minus a reserved-key denylist),
/// `binds` is a *security* field (honored only from a trusted source). The
/// distinction lives in the loader so the schema stays a plain data shape.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
pub(crate) struct RawConfig {
    /// Extra environment variables for the sandbox.
    #[serde(default)]
    pub(crate) env: BTreeMap<String, String>,
    /// Extra host paths to expose read-only inside the sandbox.
    #[serde(default)]
    pub(crate) binds: Vec<String>,
    /// Tools to provision into the sandbox, as `name = "<nixpkgs attribute>"`. The
    /// name is a free label — the merge key across layers and the on-disk root name;
    /// the value is the nixpkgs attribute to realise (e.g. `nodejs_20`).
    #[serde(default)]
    pub(crate) packages: BTreeMap<String, String>,
    /// Override the nixpkgs reference the tools resolve against: a branch/channel
    /// (`nixos-23.11`) or a 40-hex revision under `NixOS/nixpkgs`. A security field
    /// — honored from the global config or a trusted project, ignored from an
    /// untrusted one (the source is a supply-chain-relevant choice).
    pub(crate) nixpkgs: Option<String>,
    /// The sandbox's network posture. Either a simple string — `"none"` (a fresh,
    /// empty network namespace) or `"shared"` (the host network, the default when
    /// unset) — or a table selecting the filtered-egress allowlist
    /// (`[network] mode = "allowlist"`, `allow = [...]`). A security field: honored
    /// from the global config or a trusted project, ignored from an untrusted one,
    /// since narrowing or widening the network is a confidentiality choice an
    /// untrusted project may not make.
    pub(crate) network: Option<NetworkField>,
    /// Credentials the egress proxy injects into matching outbound requests, declared
    /// as the `[secret]` section — a table keyed by destination host. A security field:
    /// honored from the global config or a trusted project, ignored from an untrusted one,
    /// and only effective under a network allowlist — the filtering proxy is what performs
    /// the injection, so the plaintext never enters the cage.
    pub(crate) secret: Option<RawSecretSection>,
}

/// The `[secret]` section: a reserved `defaults` table plus one entry per destination host.
/// `secret` is a TOML *table* keyed by host (`[secret."api.github.com"]`), not an array — the
/// host is the section, so a credential's destination reads at a glance. The reserved `defaults`
/// key holds the resolver order and per-resolver bindings the terse `key` form expands through;
/// every other key is a concrete host whose value is one secret or, as an array of tables
/// (`[[secret."host"]]`), several (different headers to the same host). A host can therefore not
/// be named `defaults` — that key is reserved for the settings table.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
pub(crate) struct RawSecretSection {
    /// Resolver order and per-resolver bindings the terse `key` form expands through.
    pub(crate) defaults: Option<RawSecretDefaults>,
    /// One entry per destination host; the value is a single secret or an array of them. The
    /// reserved `defaults` key is consumed above, so this holds only host entries.
    #[serde(flatten)]
    pub(crate) hosts: BTreeMap<String, RawHostSecrets>,
}

/// The secret(s) declared for one host: a single table (`[secret."host"]`) or an array of
/// tables (`[[secret."host"]]`) for several credentials (different headers) to that host.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum RawHostSecrets {
    /// `[secret."host"]` — one secret.
    One(RawHostSecret),
    /// `[[secret."host"]]` — several secrets to the same host.
    Many(Vec<RawHostSecret>),
}

/// One credential bound to a host (the host is the section key, so there is no `to` field). The
/// source is either the terse `key` (expanded through `[secret.defaults]`) or an explicit `from`
/// resolver ref/chain — exactly one of the two. `header`/`type`/`prefix` shape what is set.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct RawHostSecret {
    /// The broker kind; optional, defaulting to the only kind today, `"http-header"`.
    pub(crate) kind: Option<String>,
    /// The terse source: a key name resolved through the default resolver order, optionally
    /// pinned with a trailing `@resolver[,resolver]`. Mutually exclusive with `from`.
    pub(crate) key: Option<String>,
    /// An explicit source: one `scheme://locator` ref (`from = "env://VAR"`) or a fallback chain
    /// tried in order (`from = ["env://VAR", "sops://f#k"]`). Mutually exclusive with `key`.
    pub(crate) from: Option<SecretFrom>,
    /// The header name to set, e.g. `Authorization`. Optional only if `[secret.defaults] header`
    /// supplies it; a secret that names neither is an explicit error (never a silent default).
    pub(crate) header: Option<String>,
    /// How to shape the value: `bearer`, `basic`, or `raw`. Optional only if `[secret.defaults]
    /// type` supplies it; a secret that names neither is an explicit error rather than a silent
    /// (and likely wrong) transform.
    #[serde(rename = "type")]
    pub(crate) value_type: Option<String>,
    /// An optional prefix overriding the type's default (`Bearer ` for bearer, empty for
    /// raw, `Basic ` for basic).
    pub(crate) prefix: Option<String>,
}

/// The defaults declared once under `[secret.defaults]`: the resolver order and per-resolver
/// bindings the terse `key` form expands through, plus a default `header`/`type` an entry may omit.
/// The `header`/`type` defaults apply to **every** entry — a verbose `from` entry omitting `header`
/// inherits it just as a terse `key` one does; only the resolver order/bindings are terse-only.
/// A per-entry value always overrides the default; an entry that names neither a `header`/`type`
/// here nor on itself is still an explicit error (no silent built-in default). The resolver order
/// is a security setting — it selects a secret's source — so this whole table is honored from the
/// global config or a trusted project, never an untrusted one.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
pub(crate) struct RawSecretDefaults {
    /// The resolver names to try, in order, for a terse key — e.g. `["env", "sops"]`. The first
    /// that resolves at launch wins; a later one is a fallback. A per-secret `key@resolver`
    /// overrides this order for that secret.
    #[serde(default)]
    pub(crate) order: Vec<String>,
    /// The default header name for entries that omit `header` (e.g. `Authorization`). Note: the
    /// header is half the `(host, header)` dedup key, so several `[[secret."host"]]` entries that
    /// all fall back to this one default collapse to the last (with a warning).
    pub(crate) header: Option<String>,
    /// The default value type for entries that omit `type` (`bearer`/`basic`/`raw`).
    #[serde(rename = "type")]
    pub(crate) value_type: Option<String>,
    /// The `sops` binding: the encrypted file a terse sops key reads from.
    pub(crate) sops: Option<RawSopsDefaults>,
    /// The `env` binding: how to transform a terse key into a variable name.
    pub(crate) env: Option<RawEnvDefaults>,
    /// The `file` binding: the base directory a terse file key reads from.
    pub(crate) file: Option<RawFileDefaults>,
}

/// The `sops` resolver binding: a terse key `k` expands to `sops://<file>#k`.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct RawSopsDefaults {
    pub(crate) file: String,
}

/// The `env` resolver binding: a terse key `k` expands to `env://<case(k)>`.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct RawEnvDefaults {
    /// `"upper"`, `"lower"`, or `"asis"` (the default) — how to case the key before using it as
    /// a variable name.
    pub(crate) case: Option<String>,
}

/// The `file` resolver binding: a terse key `k` expands to `file://<dir>/k`.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct RawFileDefaults {
    pub(crate) dir: String,
}

/// The two shapes a secret's `from` accepts: a single resolver ref string, or a list of refs
/// tried in order. An untagged enum so both TOML forms parse — `from = "env://VAR"` and
/// `from = ["env://VAR", "file:///p"]` — keeping the single-source case a one-liner.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum SecretFrom {
    /// `from = "env://VAR"`.
    One(String),
    /// `from = ["env://VAR", "file:///p"]`.
    Many(Vec<String>),
}

/// The two shapes the `network` field accepts: a bare posture string, or a table for
/// the allowlist. An untagged enum so both TOML forms parse — `network = "none"` and
/// `[network] mode = "allowlist"` — keeping the simple case a one-liner.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum NetworkField {
    /// `network = "none"` | `"shared"`.
    Posture(String),
    /// `[network] mode = "<mode>"` with an optional `allow` list.
    Table(NetworkTable),
}

/// The table form of the `network` field: a mode plus, for the allowlist, the egress
/// entries (IPs, domains, `*.domain` wildcards, exact URLs — classified later). `deny`
/// carves exceptions out of `allow`, and deny always wins.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct NetworkTable {
    pub(crate) mode: String,
    #[serde(default)]
    pub(crate) allow: Vec<String>,
    #[serde(default)]
    pub(crate) deny: Vec<String>,
}

/// Parse config bytes as TOML. The error is a human-readable string: the loader
/// turns it into a warning and ignores the layer rather than aborting a command,
/// so a malformed config never wedges the sandbox.
pub(crate) fn parse(bytes: &[u8]) -> Result<RawConfig, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("not valid UTF-8: {e}"))?;
    toml::from_str(text).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_env_and_binds() {
        let cfg = parse(
            br#"
            binds = ["/etc/ssl/custom", "/opt/data"]
            [env]
            FOO = "bar"
            BAZ = "qux"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.env.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(cfg.env.get("BAZ").map(String::as_str), Some("qux"));
        assert_eq!(cfg.binds, vec!["/etc/ssl/custom", "/opt/data"]);
    }

    #[test]
    fn parses_packages_as_name_to_attribute() {
        let cfg = parse(b"[packages]\nnode = \"nodejs_20\"\npython = \"python311\"\n").unwrap();
        assert_eq!(
            cfg.packages.get("node").map(String::as_str),
            Some("nodejs_20")
        );
        assert_eq!(
            cfg.packages.get("python").map(String::as_str),
            Some("python311")
        );
    }

    #[test]
    fn parses_the_nixpkgs_override_and_defaults_to_none() {
        let cfg = parse(b"nixpkgs = \"nixos-23.11\"\n").unwrap();
        assert_eq!(cfg.nixpkgs.as_deref(), Some("nixos-23.11"));
        assert_eq!(parse(b"").unwrap().nixpkgs, None);
    }

    #[test]
    fn parses_the_network_posture_string_form() {
        let cfg = parse(b"network = \"none\"\n").unwrap();
        assert_eq!(cfg.network, Some(NetworkField::Posture("none".into())));
        // unset means no declared posture — the loader treats that as the default
        // (shared) rather than an explicit choice.
        assert_eq!(parse(b"").unwrap().network, None);
    }

    #[test]
    fn parses_the_network_allowlist_table_form() {
        let cfg = parse(
            br#"
            [network]
            mode = "allowlist"
            allow = ["github.com", "*.nixos.org", "1.2.3.4", "https://example.com/x"]
            deny  = ["evil.nixos.org"]
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.network,
            Some(NetworkField::Table(NetworkTable {
                mode: "allowlist".into(),
                allow: vec![
                    "github.com".into(),
                    "*.nixos.org".into(),
                    "1.2.3.4".into(),
                    "https://example.com/x".into(),
                ],
                deny: vec!["evil.nixos.org".into()],
            }))
        );
    }

    #[test]
    fn a_network_table_without_allow_or_deny_defaults_to_empty() {
        let cfg = parse(b"[network]\nmode = \"allowlist\"\n").unwrap();
        assert_eq!(
            cfg.network,
            Some(NetworkField::Table(NetworkTable {
                mode: "allowlist".into(),
                allow: vec![],
                deny: vec![],
            }))
        );
    }

    /// Pull the single secret declared for `host` out of a parsed section, failing the test if
    /// the host is absent or declared as an array.
    #[cfg(test)]
    fn one_host<'a>(cfg: &'a RawConfig, host: &str) -> &'a RawHostSecret {
        match cfg
            .secret
            .as_ref()
            .and_then(|s| s.hosts.get(host))
            .unwrap_or_else(|| panic!("no secret for host `{host}`"))
        {
            RawHostSecrets::One(s) => s,
            RawHostSecrets::Many(_) => panic!("host `{host}` is an array, expected one"),
        }
    }

    #[test]
    fn parses_a_secret_section_keyed_by_host() {
        let cfg = parse(
            br#"
            [secret."api.github.com"]
            kind   = "http-header"
            from   = "env://GITHUB_TOKEN"
            header = "Authorization"
            type   = "bearer"

            [secret."registry.npmjs.org"]
            from   = "file:///run/secrets/npm"
            header = "Authorization"
            type   = "raw"
            prefix = "Bearer "
            "#,
        )
        .unwrap();
        let section = cfg.secret.as_ref().unwrap();
        // the reserved `defaults` key is absent here, and the two host keys are present
        assert!(section.defaults.is_none());
        assert_eq!(section.hosts.len(), 2);

        let gh = one_host(&cfg, "api.github.com");
        assert_eq!(gh.kind.as_deref(), Some("http-header"));
        // a single-string `from` parses to the `One` shape
        assert_eq!(gh.from, Some(SecretFrom::One("env://GITHUB_TOKEN".into())));
        assert_eq!(gh.header.as_deref(), Some("Authorization"));
        assert_eq!(gh.value_type.as_deref(), Some("bearer"));
        assert_eq!(gh.prefix, None);

        let npm = one_host(&cfg, "registry.npmjs.org");
        // kind is optional, defaulting downstream
        assert_eq!(npm.kind, None);
        assert_eq!(
            npm.from,
            Some(SecretFrom::One("file:///run/secrets/npm".into()))
        );
        assert_eq!(npm.prefix.as_deref(), Some("Bearer "));

        // unset means no declared secrets
        assert!(parse(b"").unwrap().secret.is_none());
    }

    #[test]
    fn parses_a_terse_key_and_a_defaults_table() {
        let cfg = parse(
            br#"
            [secret.defaults]
            order  = ["env", "sops"]
            header = "Authorization"
            type   = "bearer"
            [secret.defaults.sops]
            file = "secrets/prod.yaml"
            [secret.defaults.env]
            case = "upper"

            [secret."api.github.com"]
            key = "github_token"
            "#,
        )
        .unwrap();
        let defaults = cfg.secret.as_ref().unwrap().defaults.as_ref().unwrap();
        assert_eq!(defaults.order, vec!["env".to_string(), "sops".to_string()]);
        assert_eq!(defaults.sops.as_ref().unwrap().file, "secrets/prod.yaml");
        assert_eq!(
            defaults.env.as_ref().unwrap().case.as_deref(),
            Some("upper")
        );
        // the default header/type let a terse entry name only its key
        assert_eq!(defaults.header.as_deref(), Some("Authorization"));
        assert_eq!(defaults.value_type.as_deref(), Some("bearer"));
        // `defaults` is consumed by the named field, never leaking into the host map
        assert_eq!(cfg.secret.as_ref().unwrap().hosts.len(), 1);

        let gh = one_host(&cfg, "api.github.com");
        assert_eq!(gh.key.as_deref(), Some("github_token"));
        assert_eq!(gh.from, None);
        // the entry omits header/type — they come from the defaults
        assert_eq!(gh.header, None);
        assert_eq!(gh.value_type, None);
    }

    #[test]
    fn a_host_named_defaults_is_swallowed_by_the_reserved_table() {
        // `defaults` is the reserved settings key, so `[secret."defaults"]` (a host literally named
        // "defaults") is consumed as the defaults table, not a host entry. Its secret fields are
        // ignored, so no credential is injected for a host named "defaults" — fail-closed, never a
        // silent injection to the wrong place.
        let cfg = parse(
            br#"
            [secret."defaults"]
            key    = "x"
            header = "Authorization"
            type   = "bearer"
            "#,
        )
        .unwrap();
        let section = cfg.secret.as_ref().unwrap();
        assert!(
            section.defaults.is_some(),
            "the `defaults` key is the reserved settings table"
        );
        assert!(
            section.hosts.is_empty(),
            "no host entry is produced for a host named `defaults`"
        );
    }

    #[test]
    fn parses_several_secrets_for_one_host_as_an_array() {
        let cfg = parse(
            br#"
            [[secret."api.github.com"]]
            key    = "github_token"
            header = "Authorization"
            type   = "bearer"

            [[secret."api.github.com"]]
            key    = "github_ci"
            header = "X-Api-Key"
            type   = "raw"
            "#,
        )
        .unwrap();
        let many = match cfg.secret.as_ref().unwrap().hosts.get("api.github.com") {
            Some(RawHostSecrets::Many(v)) => v,
            other => panic!("expected an array of secrets, got {other:?}"),
        };
        assert_eq!(many.len(), 2);
        assert_eq!(many[0].header.as_deref(), Some("Authorization"));
        assert_eq!(many[1].header.as_deref(), Some("X-Api-Key"));
    }

    #[test]
    fn parses_a_secret_from_resolver_chain() {
        let cfg = parse(
            br#"
            [secret."api.github.com"]
            from   = ["env://GH_TOKEN", "file:///run/secrets/gh"]
            header = "Authorization"
            type   = "bearer"
            "#,
        )
        .unwrap();
        // a list `from` parses to the `Many` shape, in order
        assert_eq!(
            one_host(&cfg, "api.github.com").from,
            Some(SecretFrom::Many(vec![
                "env://GH_TOKEN".into(),
                "file:///run/secrets/gh".into(),
            ]))
        );
    }

    #[test]
    fn an_empty_config_is_all_defaults() {
        let cfg = parse(b"").unwrap();
        assert_eq!(cfg, RawConfig::default());
    }

    #[test]
    fn unknown_fields_are_ignored_for_forward_compatibility() {
        // a field a newer ops understands must not break an older one
        let cfg = parse(b"some_future_field = 42\n[env]\nA = \"1\"\n").unwrap();
        assert_eq!(cfg.env.get("A").map(String::as_str), Some("1"));
    }

    #[test]
    fn malformed_toml_is_a_readable_error() {
        let err = parse(b"this is = = not toml").unwrap_err();
        assert!(!err.is_empty());
    }
}
