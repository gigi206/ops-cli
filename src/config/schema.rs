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
    /// as `[[secret]]` tables. A security field: honored from the global config or a
    /// trusted project, ignored from an untrusted one, and only effective under a
    /// network allowlist — the filtering proxy is what performs the injection, so the
    /// plaintext never enters the cage.
    #[serde(default)]
    pub(crate) secret: Vec<RawSecret>,
}

/// One `[[secret]]` entry: a credential the egress proxy injects into matching outbound
/// requests. For now the only `kind` is `"http-header"`. The source is exactly one of
/// `from_env` (a host variable name) or `from_file` (an absolute host path); the value is
/// read host-side at launch and never enters the cage. `to` is the concrete destination
/// (classified like an allowlist entry), and `header`/`type`/`prefix` shape what is set.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct RawSecret {
    /// The broker kind. `"http-header"` is the only one understood today.
    pub(crate) kind: String,
    /// Read the plaintext from this host environment variable (mutually exclusive with
    /// `from_file`).
    pub(crate) from_env: Option<String>,
    /// Read the plaintext from this absolute host file (mutually exclusive with `from_env`).
    pub(crate) from_file: Option<String>,
    /// The concrete destination the header is injected for — a host, IP, or `host/path`. A
    /// `*.` wildcard or `re:` regex is rejected: a credential is sent to one known host.
    pub(crate) to: String,
    /// The header name to set, e.g. `Authorization`.
    pub(crate) header: String,
    /// How to shape the value: `bearer`, `basic`, or `raw`. Required — there is no default,
    /// so an omitted `type` is an explicit error rather than a silent (and likely wrong)
    /// transform.
    #[serde(rename = "type")]
    pub(crate) value_type: Option<String>,
    /// An optional prefix overriding the type's default (`Bearer ` for bearer, empty for
    /// raw, `Basic ` for basic).
    pub(crate) prefix: Option<String>,
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

    #[test]
    fn parses_a_secret_table_array() {
        let cfg = parse(
            br#"
            [[secret]]
            kind     = "http-header"
            from_env = "GITHUB_TOKEN"
            to       = "api.github.com"
            header   = "Authorization"
            type     = "bearer"

            [[secret]]
            kind      = "http-header"
            from_file = "/run/secrets/npm"
            to        = "registry.npmjs.org"
            header    = "Authorization"
            type      = "raw"
            prefix    = "Bearer "
            "#,
        )
        .unwrap();
        assert_eq!(cfg.secret.len(), 2);
        assert_eq!(cfg.secret[0].kind, "http-header");
        assert_eq!(cfg.secret[0].from_env.as_deref(), Some("GITHUB_TOKEN"));
        assert_eq!(cfg.secret[0].to, "api.github.com");
        assert_eq!(cfg.secret[0].header, "Authorization");
        assert_eq!(cfg.secret[0].value_type.as_deref(), Some("bearer"));
        assert_eq!(cfg.secret[0].prefix, None);
        assert_eq!(cfg.secret[1].from_file.as_deref(), Some("/run/secrets/npm"));
        assert_eq!(cfg.secret[1].prefix.as_deref(), Some("Bearer "));
        // unset means no declared secrets
        assert!(parse(b"").unwrap().secret.is_empty());
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
