//! One-shot configuration overrides carried on the command line or in the environment.
//!
//! An override is the *final word* on a launch's configuration — it beats a trusted project
//! config **and** a named app's overlay — because it comes from the person running `ops`, whose
//! authority over the process's argv and environment no lower-trust context (an in-cage agent, a
//! project directory) can reach. So an override is trusted *by invocation*, distinct from the
//! direnv-style content trust of a project config: it touches no trust marker.
//!
//! Precedence, lowest to highest:
//!
//! ```text
//! OPS_CONFIG (env blob) < OPS_ENV_<KEY> (env, per key) < --config (cli blob) < --env (cli)
//! ```
//!
//! so any CLI input beats any environment one ("the CLI wins over the environment"), and within a
//! source the specific typed input beats the whole-schema blob.
//!
//! The blob forms (`--config`/`OPS_CONFIG`) carry inline TOML — or `@<file>` — shaped exactly like
//! an `ops.toml`, so an override can set *any* field the schema has. This module only *collects and
//! merges* the inputs into one overlay; the authoritative application onto a resolved configuration
//! is [`super::Resolved::apply_override`] (and [`super::Resolved::apply_override_channel`] for the
//! nixpkgs channel, which must land before the launch picks its lock).
//!
//! Fail-closed: unlike [`super::load`], which is infallible (a bad config warns and is dropped), a
//! malformed override is an explicit request the user got wrong — [`collect`] returns `Err`, so the
//! launch aborts rather than silently dropping the field and running a different posture than asked.

use super::schema::{self, RawConfig};
use std::collections::BTreeMap;

/// The environment-variable prefix that sets one cage environment variable per key:
/// `OPS_ENV_FOO=bar` contributes `FOO=bar` to the cage environment.
const OPS_ENV_PREFIX: &str = "OPS_ENV_";
/// The whole-schema environment blob: inline TOML (or `@<file>`) shaped like an `ops.toml`.
const OPS_CONFIG: &str = "OPS_CONFIG";

/// A collected, merged one-shot override plus the one-time notices to print before launch.
#[derive(Debug)]
pub(crate) struct Override {
    /// The merged overlay, shaped as a config file. Applied authoritatively last.
    pub(super) raw: RawConfig,
    /// Messages to surface **once**, at collection time — not per apply, which runs twice for
    /// `ops app` (before and after the app overlay merges). Two kinds: the security-field-via-
    /// environment notices and the ignored-field warnings.
    notices: Vec<String>,
}

impl Override {
    /// An empty override — the no-op the launch paths that take no override flags pass.
    pub(crate) fn none() -> Self {
        Override {
            raw: RawConfig::default(),
            notices: Vec::new(),
        }
    }

    /// The one-time notices to print before launch (borrowed).
    pub(crate) fn notices(&self) -> &[String] {
        &self.notices
    }

    /// Whether nothing was overridden, so a caller can skip the apply entirely (a no-op otherwise).
    pub(crate) fn is_empty(&self) -> bool {
        self.raw == RawConfig::default() && self.notices.is_empty()
    }

    /// Build an override directly from a raw overlay — for the `apply_override` tests, which exercise
    /// the application onto a resolved config, not the collection/merge (covered here).
    #[cfg(test)]
    pub(super) fn for_test(raw: RawConfig) -> Self {
        Override {
            raw,
            notices: Vec::new(),
        }
    }
}

/// Collect a one-shot override from the CLI `--config`/`--env` values (already stripped from argv by
/// the caller) and the `OPS_CONFIG`/`OPS_ENV_<KEY>` environment. Fail-closed: a malformed blob, an
/// unreadable `@file`, or a bad `--env KEY=VALUE` is an `Err(message)`.
pub(crate) fn collect(cli_config: &[String], cli_env: &[String]) -> Result<Override, String> {
    let ops_config = std::env::var(OPS_CONFIG).ok().filter(|s| !s.is_empty());
    let mut ops_env = BTreeMap::new();
    for (k, v) in std::env::vars() {
        if let Some(name) = k.strip_prefix(OPS_ENV_PREFIX) {
            if !name.is_empty() {
                ops_env.insert(name.to_string(), v);
            }
        }
    }
    collect_from(cli_config, cli_env, ops_config, ops_env)
}

/// The pure core of [`collect`]: the environment is passed in (the `OPS_CONFIG` blob and the
/// `OPS_ENV_<KEY>` map) rather than read, so the whole merge and its precedence are unit-testable
/// without touching the process environment.
fn collect_from(
    cli_config: &[String],
    cli_env: &[String],
    ops_config: Option<String>,
    ops_env: BTreeMap<String, String>,
) -> Result<Override, String> {
    // Parse the two blob sources (fail-closed). The CLI blob merges every `--config` occurrence in
    // order, a later one winning per field, so repeated flags compose predictably.
    let env_blob = match ops_config {
        Some(s) => Some(parse_blob(&s).map_err(|e| format!("{OPS_CONFIG}: {e}"))?),
        None => None,
    };
    let mut cli_blob: Option<RawConfig> = None;
    for (i, c) in cli_config.iter().enumerate() {
        let parsed = parse_blob(c).map_err(|e| format!("--config (#{}): {e}", i + 1))?;
        cli_blob = Some(match cli_blob {
            None => parsed,
            Some(base) => merge_raw(base, parsed),
        });
    }
    let cli_typed_env = parse_env_pairs(cli_env)?;

    let mut merged = RawConfig::default();
    let mut notices = Vec::new();

    // Ignored fields — flagged once, before the blobs are consumed for their launch fields. These
    // are not one-shot launch concepts: egress groups are a global-config affordance, and an
    // override shapes *the* launch rather than defining apps.
    let field_present = |has: fn(&RawConfig) -> bool| {
        cli_blob.as_ref().is_some_and(has) || env_blob.as_ref().is_some_and(has)
    };
    for (label, has) in [
        (
            "`[net.groups]`",
            (|c: &RawConfig| !c.net.groups.is_empty()) as fn(&RawConfig) -> bool,
        ),
        ("`[app.*]`", |c: &RawConfig| !c.app.is_empty()),
    ] {
        if field_present(has) {
            notices.push(format!(
                "ignoring {label} in the override — it is not a one-shot launch field"
            ));
        }
    }

    // The cage environment merges across sources in precedence order, a later one winning per key.
    if let Some(b) = &env_blob {
        merged.env.extend(b.env.clone());
    }
    merged.env.extend(ops_env);
    if let Some(b) = &cli_blob {
        merged.env.extend(b.env.clone());
    }
    for (k, v) in cli_typed_env {
        merged.env.insert(k, v);
    }

    // The security and other launch-shaping fields: the CLI blob wins over the environment blob per
    // field. A field that ends up sourced from the environment is noted, so a stale ambient variable
    // cannot silently widen (or narrow) a launch's posture without a word.
    fold_launch_fields(&mut merged, env_blob, cli_blob, &mut notices);

    Ok(Override {
        raw: merged,
        notices,
    })
}

/// The security/launch fields an override can carry, for the environment-source notice. `env` is a
/// *free* field (folded separately, no notice), so it is not here.
const SECURITY_FIELDS: &[&str] = &[
    "binds", "packages", "nixpkgs", "network", "gui", "limits", "secret",
];

/// Fold the launch-shaping fields of the two blobs into `merged` with the CLI winning over the
/// environment per field, and push a notice for each security field whose winning value came from
/// the environment. Consumes both blobs (their fields move into `merged`).
fn fold_launch_fields(
    merged: &mut RawConfig,
    env_blob: Option<RawConfig>,
    cli_blob: Option<RawConfig>,
    notices: &mut Vec<String>,
) {
    let e = env_blob.unwrap_or_default();
    let c = cli_blob.unwrap_or_default();

    // For each field: the CLI value wins when it set one; otherwise the environment's. A field
    // taken from the environment is recorded by name for the notice below.
    let mut from_env: Vec<&'static str> = Vec::new();

    if !c.binds.is_empty() {
        merged.binds = c.binds;
    } else if !e.binds.is_empty() {
        merged.binds = e.binds;
        from_env.push("binds");
    }
    if !c.packages.is_empty() {
        merged.packages = c.packages;
    } else if !e.packages.is_empty() {
        merged.packages = e.packages;
        from_env.push("packages");
    }
    merged.nixpkgs = pick(c.nixpkgs, e.nixpkgs, "nixpkgs", &mut from_env);
    merged.network = pick(c.network, e.network, "network", &mut from_env);
    merged.gui = pick(c.gui, e.gui, "gui", &mut from_env);
    merged.limits = pick(c.limits, e.limits, "limits", &mut from_env);
    merged.secret = pick(c.secret, e.secret, "secret", &mut from_env);

    for field in SECURITY_FIELDS {
        if from_env.contains(field) {
            notices.push(format!(
                "security field `{field}` set from the environment ({OPS_CONFIG}) — an ambient \
                 variable changes every launch; use `--config` on the command line for a true \
                 one-shot"
            ));
        }
    }
}

/// Pick the CLI value if set, else the environment's; record the field name when the environment's
/// is chosen (a security-field-via-environment notice is emitted for it).
fn pick<T>(
    cli: Option<T>,
    env: Option<T>,
    field: &'static str,
    from_env: &mut Vec<&'static str>,
) -> Option<T> {
    match cli {
        Some(v) => Some(v),
        None => {
            if env.is_some() {
                from_env.push(field);
            }
            env
        }
    }
}

/// Merge two parsed override blobs, `over` winning over `base` for any field it sets — the rule for
/// repeated `--config` flags. Maps extend (a later key wins); a set collection or option replaces.
fn merge_raw(mut base: RawConfig, over: RawConfig) -> RawConfig {
    base.env.extend(over.env);
    if !over.binds.is_empty() {
        base.binds = over.binds;
    }
    base.packages.extend(over.packages);
    if over.nixpkgs.is_some() {
        base.nixpkgs = over.nixpkgs;
    }
    if over.network.is_some() {
        base.network = over.network;
    }
    if over.gui.is_some() {
        base.gui = over.gui;
    }
    if over.secret.is_some() {
        base.secret = over.secret;
    }
    base.net.groups.extend(over.net.groups);
    base.app.extend(over.app);
    base
}

/// Parse one blob value: `@<path>` reads the file, anything else is inline TOML. The bytes are then
/// parsed as an `ops.toml`-shaped config.
fn parse_blob(value: &str) -> Result<RawConfig, String> {
    let bytes = match value.strip_prefix('@') {
        Some(path) => {
            std::fs::read(path).map_err(|e| format!("cannot read override file `{path}`: {e}"))?
        }
        None => value.as_bytes().to_vec(),
    };
    schema::parse(&bytes)
}

/// Parse the `--env KEY=VALUE` values into pairs, requiring the `=` (the key is validated
/// downstream by the env applier). An entry without `=` is a hard error — fail-closed, since a
/// silently dropped `--env FOO` would launch without the variable the user asked for.
fn parse_env_pairs(cli_env: &[String]) -> Result<Vec<(String, String)>, String> {
    cli_env
        .iter()
        .map(|e| {
            e.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| format!("--env `{e}`: expected KEY=VALUE"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_test(
        cli_config: &[&str],
        cli_env: &[&str],
        ops_config: Option<&str>,
        ops_env: &[(&str, &str)],
    ) -> Result<Override, String> {
        collect_from(
            &cli_config.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &cli_env.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            ops_config.map(str::to_string),
            ops_env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[test]
    fn an_empty_override_is_a_no_op() {
        let ov = collect_test(&[], &[], None, &[]).unwrap();
        assert!(ov.raw.env.is_empty());
        assert!(ov.raw.network.is_none());
        assert!(ov.notices().is_empty());
    }

    #[test]
    fn a_cli_config_blob_parses_every_field() {
        let ov = collect_test(&["network = \"none\"\ngui = \"wayland\""], &[], None, &[]).unwrap();
        assert!(ov.raw.network.is_some());
        assert_eq!(ov.raw.gui.as_deref(), Some("wayland"));
    }

    #[test]
    fn a_malformed_blob_is_a_hard_error_not_a_silent_drop() {
        let err = collect_test(&["network = = nope"], &[], None, &[]).unwrap_err();
        assert!(err.starts_with("--config (#1):"), "{err}");
        // and the same for the environment blob
        let err = collect_test(&[], &[], Some("not = = toml"), &[]).unwrap_err();
        assert!(err.starts_with("OPS_CONFIG:"), "{err}");
    }

    #[test]
    fn the_cli_beats_the_environment_per_field() {
        // OPS_CONFIG says shared, --config says none: the CLI wins, and because the winning value is
        // from the CLI, no security-via-env notice fires.
        let ov = collect_test(
            &["network = \"none\""],
            &[],
            Some("network = \"shared\""),
            &[],
        )
        .unwrap();
        assert_eq!(
            ov.raw.network,
            Some(super::schema::NetworkField::Posture("none".into()))
        );
        assert!(
            ov.notices().is_empty(),
            "a CLI-won security field must not notice: {:?}",
            ov.notices()
        );
    }

    #[test]
    fn a_security_field_only_in_the_environment_is_noticed() {
        let ov = collect_test(&[], &[], Some("network = \"none\""), &[]).unwrap();
        assert_eq!(
            ov.raw.network,
            Some(super::schema::NetworkField::Posture("none".into()))
        );
        assert_eq!(ov.notices().len(), 1);
        assert!(
            ov.notices()[0].contains("security field `network`"),
            "{:?}",
            ov.notices()
        );
    }

    #[test]
    fn env_precedence_is_ops_config_then_ops_env_then_config_then_env() {
        // K set in all four sources: --env wins. A key only in OPS_CONFIG survives untouched.
        let ov = collect_test(
            &["[env]\nK = \"from-config\"\nONLY_CFG = \"c\""],
            &["K=from-cli-env"],
            Some("[env]\nK = \"from-ops-config\"\nONLY_OPS = \"o\""),
            &[("K", "from-ops-env")],
        )
        .unwrap();
        assert_eq!(
            ov.raw.env.get("K").map(String::as_str),
            Some("from-cli-env")
        );
        assert_eq!(ov.raw.env.get("ONLY_OPS").map(String::as_str), Some("o"));
        assert_eq!(ov.raw.env.get("ONLY_CFG").map(String::as_str), Some("c"));
        // env is a free field — no security notice.
        assert!(ov.notices().is_empty());
    }

    #[test]
    fn ops_env_per_key_variables_become_cage_env() {
        let ov = collect_test(&[], &[], None, &[("FOO", "bar"), ("BAZ", "qux")]).unwrap();
        assert_eq!(ov.raw.env.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(ov.raw.env.get("BAZ").map(String::as_str), Some("qux"));
    }

    #[test]
    fn a_bad_env_pair_is_a_hard_error() {
        let err = collect_test(&[], &["NOEQUALS"], None, &[]).unwrap_err();
        assert!(err.contains("expected KEY=VALUE"), "{err}");
    }

    #[test]
    fn a_repeated_config_flag_merges_later_winning() {
        let ov = collect_test(
            &[
                "network = \"none\"\ngui = \"wayland\"",
                "network = \"shared\"",
            ],
            &[],
            None,
            &[],
        )
        .unwrap();
        // the second --config's network wins; the first's gui survives (unset in the second)
        assert_eq!(
            ov.raw.network,
            Some(super::schema::NetworkField::Posture("shared".into()))
        );
        assert_eq!(ov.raw.gui.as_deref(), Some("wayland"));
    }

    #[test]
    fn every_launch_field_survives_the_merge_into_the_overlay() {
        // Regression guard: the fold must copy *every* launch field from the blob into the merged
        // overlay — a field dropped here (as `limits` once was) silently defeats its validation and
        // application downstream. One blob sets one of each; the merged overlay must carry them all.
        let ov = collect_test(
            &[r#"
                nixpkgs = "nixos-23.11"
                network = "none"
                gui = "wayland"
                binds = ["/opt/data"]
                [env]
                E = "1"
                [packages]
                p = "nix:hello"
                [limits]
                tasks_max = 4096
                [secret."api.example.com"]
                from = "env://K"
                header = "X"
                type = "raw"
            "#],
            &[],
            None,
            &[],
        )
        .unwrap();
        assert_eq!(ov.raw.nixpkgs.as_deref(), Some("nixos-23.11"));
        assert!(ov.raw.network.is_some(), "network dropped in merge");
        assert_eq!(ov.raw.gui.as_deref(), Some("wayland"));
        assert!(!ov.raw.binds.is_empty(), "binds dropped in merge");
        assert_eq!(ov.raw.env.get("E").map(String::as_str), Some("1"));
        assert!(
            ov.raw.packages.contains_key("p"),
            "packages dropped in merge"
        );
        assert!(ov.raw.limits.is_some(), "limits dropped in merge");
        assert!(ov.raw.secret.is_some(), "secret dropped in merge");
    }

    #[test]
    fn net_groups_and_apps_in_an_override_are_ignored_with_a_notice() {
        let ov = collect_test(
            &["[net.groups]\nx = [\"a.example.com\"]\n[app.demo]\ncmd = \"demo\""],
            &[],
            None,
            &[],
        )
        .unwrap();
        assert!(
            ov.raw.net.groups.is_empty() || ov.notices().iter().any(|n| n.contains("net.groups"))
        );
        let text = ov.notices().join("\n");
        assert!(text.contains("[net.groups]"), "{text}");
        assert!(text.contains("[app.*]"), "{text}");
    }

    #[test]
    fn a_config_file_reference_reads_the_file() {
        let dir = std::env::temp_dir().join(format!("ops-ov-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("ov.toml");
        std::fs::write(&file, b"network = \"none\"\n").unwrap();
        let arg = format!("@{}", file.display());
        let ov = collect_test(&[&arg], &[], None, &[]).unwrap();
        assert_eq!(
            ov.raw.network,
            Some(super::schema::NetworkField::Posture("none".into()))
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_config_file_is_a_hard_error() {
        let err = collect_test(&["@/no/such/ops-override.toml"], &[], None, &[]).unwrap_err();
        assert!(err.contains("cannot read override file"), "{err}");
    }
}
