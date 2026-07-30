//! Task validation: turn a `[task.<name>]` declaration into a validated [`TaskSpec`], and fold a
//! config layer's section into the resolved set.
//!
//! Every check fails closed — a malformed task is dropped with a warning naming it, never accepted
//! in a weakened form. What the checks protect, in order of load-bearingness:
//!
//! 1. **The program is sbx's.** `cmd` is an argv list; `cmd[0]` may carry no `{param}` placeholder,
//!    so a caller can never choose or influence the program. Rejecting `;`/`&&` would be theater —
//!    nothing here ever reaches a shell, so those are inert bytes in an argv element; what bounds
//!    the command is the fixed program plus the parameter bounds.
//! 2. **Every caller-supplied value is bounded.** A `{param}` must be declared, and a declaration
//!    must carry a `match` pattern or an `enum` — an unbounded parameter can embed a comparison and
//!    rebuild an exit-status oracle over the credential.
//! 3. **Substitution cannot restructure the argv.** A placeholder substitutes inside the element
//!    that contains it; an unknown placeholder, or a missing value for a parameter with no
//!    `default`, is an error rather than an empty substitution.

use std::collections::{BTreeMap, BTreeSet};

use super::secrets::{
    expand_key, parse_secret_ref, sanitize_description, validate_host_secret, validate_secret_name,
};
use super::*;

/// Fold one layer's `[task]` section into `out`, validating each entry. A malformed task is dropped
/// with a warning naming it. A later layer's task with the same name replaces an earlier one
/// (last-wins) with a warning, mirroring how a redeclared secret behaves — a silent shadow would
/// make it unclear which command a caller actually gets.
pub(super) fn apply_task_section(
    out: &mut Vec<TaskSpec>,
    warnings: &mut Vec<String>,
    source: &str,
    section: RawTaskSection,
    defaults: &TaskDefaults,
    secret_defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) {
    for (name, raw) in section.tasks {
        match validate_task(&name, raw, defaults, secret_defaults, plugins) {
            Ok(task) => upsert_task(out, warnings, source, task),
            Err(e) => warnings.push(format!("{source}: ignoring task `{name}` — {e}")),
        }
    }
}

/// Set a task, replacing a same-named earlier one (last-wins) with a warning.
pub(super) fn upsert_task(
    out: &mut Vec<TaskSpec>,
    warnings: &mut Vec<String>,
    source: &str,
    task: TaskSpec,
) {
    match out.iter_mut().find(|t| t.name == task.name) {
        Some(slot) => {
            warnings.push(format!(
                "{source}: task `{}` overrides an earlier declaration of the same name",
                task.name
            ));
            *slot = task;
        }
        None => out.push(task),
    }
}

/// The section-wide task settings, from `[task.defaults]`. Validated per layer; a later layer
/// overrides field by field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TaskDefaults {
    /// The wall-clock ceiling a task that sets none inherits.
    pub(super) timeout: std::time::Duration,
    /// The per-stream captured-output ceiling a task that sets none inherits.
    pub(super) max_output: u64,
    /// Whether a substituted credential carries a per-invocation nonce.
    pub(super) nonce: bool,
}

/// sbx's built-in task ceilings, used when no layer sets them. A task is a short brokered
/// operation, not a job runner: 30 seconds and 64 KiB per stream are generous for that and keep a
/// misdeclared task from occupying a session or flooding a caller's context.
impl Default for TaskDefaults {
    fn default() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(30),
            max_output: 64 * 1024,
            nonce: false,
        }
    }
}

impl TaskDefaults {
    /// These defaults with a layer's `[task.defaults]` applied over them, field by field. A
    /// malformed value warns and leaves the inherited one — a ceiling is a safety limit, so falling
    /// back to the stricter inherited value is the fail-closed direction.
    pub(super) fn merged_with(
        &self,
        raw: &RawTaskDefaults,
        source: &str,
        warnings: &mut Vec<String>,
    ) -> Self {
        let mut out = self.clone();
        if let Some(raw_timeout) = &raw.timeout {
            match parse_task_timeout(raw_timeout) {
                Ok(d) => out.timeout = d,
                Err(e) => warnings.push(format!(
                    "{source}: ignoring `[task.defaults] timeout` — {e}"
                )),
            }
        }
        if let Some(raw_max) = &raw.max_output {
            match parse_output_cap(raw_max) {
                Ok(n) => out.max_output = n,
                Err(e) => warnings.push(format!(
                    "{source}: ignoring `[task.defaults] max_output` — {e}"
                )),
            }
        }
        if let Some(nonce) = raw.nonce {
            out.nonce = nonce;
        }
        out
    }
}

/// Parse a task duration — the same grammar as an `ask_timeout` (`"30s"`, `"5m"`, `"2h"`, or a bare
/// number of seconds) — but a task's ceiling may not be zero/indefinite: an operation that can hang
/// forever holds a caller and a credential open, so "no timeout" is not an available choice.
pub(super) fn parse_task_timeout(raw: &str) -> Result<std::time::Duration, String> {
    match super::parse_ask_timeout(raw)? {
        Some(d) => Ok(d),
        None => Err(format!(
            "`{raw}` is zero — a task must have a positive timeout"
        )),
    }
}

/// Validate one `[task.<name>]` entry into a [`TaskSpec`].
pub(super) fn validate_task(
    name: &str,
    raw: RawTask,
    defaults: &TaskDefaults,
    secret_defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) -> Result<TaskSpec, String> {
    validate_task_name(name)?;
    if raw.cmd.is_empty() {
        return Err("set `cmd` — the argv list sbx runs (never a shell string)".to_string());
    }
    // The program must be sbx's choice alone: a placeholder in argv0 would let a caller steer which
    // binary runs, which is the one thing a declared task exists to prevent.
    if placeholders(&raw.cmd[0]).next().is_some() {
        return Err(
            "`cmd[0]` carries a `{param}` placeholder — the program is never caller-supplied"
                .to_string(),
        );
    }

    let params = validate_params(raw.params)?;
    check_placeholders_declared(&raw.cmd, &params)?;

    let secrets = validate_task_secrets(raw.secret, secret_defaults, plugins)?;
    let injections = validate_task_injections(raw.inject, secret_defaults, plugins)?;
    let network = validate_task_network(&raw.network)?;
    if !injections.is_empty() && network.is_empty() {
        return Err(
            "an `[inject]` credential needs `network` reaching that host — the injection happens \
             in this task's own proxy, which only exists when the task has egress"
                .to_string(),
        );
    }
    for var in raw.env.keys().chain(raw.env_allow.iter()) {
        validate_env_name(var)?;
        if secrets.iter().any(|s| &s.var == var) {
            return Err(format!(
                "`{var}` is both a credential and a plain environment variable — one name, one \
                 source"
            ));
        }
    }
    // A caller-settable name that the declaration also fixes would be ambiguous: the fixed value
    // says "this is sbx's", the allowlist says "the caller's". Refuse rather than pick.
    if let Some(clash) = raw.env_allow.iter().find(|v| raw.env.contains_key(*v)) {
        return Err(format!(
            "`{clash}` is in `env_allow` and also fixed in `env` — a variable is either the \
             declaration's or the caller's"
        ));
    }

    let timeout = match &raw.timeout {
        Some(t) => parse_task_timeout(t)?,
        None => defaults.timeout,
    };
    let max_output = match &raw.max_output {
        Some(m) => parse_output_cap(m)?,
        None => defaults.max_output,
    };

    // A task cannot police what its command goes on to spawn, so it must not look as though it can.
    // Deciding an exec by path needs a seccomp user-notification supervisor, which needs a shim
    // binary inside the cage — and that cage is the one holding a plaintext credential. Refusing is
    // the honest answer: an ignored key here would read as a fence and be none.
    for field in ["allow", "deny"] {
        let declared = if field == "allow" {
            &raw.allow
        } else {
            &raw.deny
        };
        if !declared.is_empty() {
            return Err(format!(
                "`{field}` is not a task control — sbx does not police which programs a task's \
                 command may spawn; what bounds a task is its fixed `cmd`, the `params` bounds, and \
                 a cage with no network unless `network` declares one"
            ));
        }
    }

    let packages = validate_task_packages(&raw.packages)?;

    Ok(TaskSpec {
        name: name.to_string(),
        description: raw.description.as_deref().map(sanitize_description),
        cmd: raw.cmd,
        params,
        secrets,
        injections,
        env: raw.env,
        env_allow: raw.env_allow,
        stdout: parse_disposition("stdout", raw.stdout.as_deref())?,
        stderr: parse_disposition("stderr", raw.stderr.as_deref())?,
        timeout,
        max_output,
        network,
        nonce: defaults.nonce,
        packages,
    })
}

/// Validate a task's `packages` and return the bare mise tokens (the `mise:` prefix stripped).
///
/// Only `mise:` is accepted, and that is the whole point of the field rather than a limitation of
/// it: every other backend builds host-side into the shared store, which a task cage already mounts
/// read-only, so those binaries are on a task's path with nothing to declare. `mise:` is the one
/// backend that installs *in-cage* under a writable home, so it needs a pool of its own — and this
/// field is what fills it.
///
/// `mise:nix:…` is refused specifically: mise's `nix:` backend builds into the store the *cage*
/// writes, which is the provenance problem the pool exists to solve, and `[packages] nix:` already
/// does the same thing host-side into the shared store.
fn validate_task_packages(raw: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let Some(token) = entry.strip_prefix("mise:") else {
            return Err(format!(
                "`{entry}`: a task's `packages` takes `mise:` entries only — every other backend \
                 builds host-side into the shared store, which a task cage already mounts \
                 read-only, so declare it in `[packages]` and its binaries are on the task's path"
            ));
        };
        let token = token.trim();
        if token.is_empty() {
            return Err("`mise:` with no tool after it".to_string());
        }
        if token.starts_with("nix:") {
            return Err(format!(
                "`{entry}`: mise's `nix:` backend builds into the store the cage writes — declare \
                 it as `[packages] nix:{}` instead, which builds host-side into the shared store",
                token.trim_start_matches("nix:")
            ));
        }
        // The token reaches a `mise install` argv and a filesystem path under the pool. Refuse the
        // characters that would make either ambiguous rather than sanitising them into something
        // the author did not write.
        if token
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '\0')
        {
            return Err(format!(
                "`{entry}`: a mise tool token carries no whitespace"
            ));
        }
        if token.split('/').any(|c| c == "." || c == "..") {
            return Err(format!("`{entry}`: a mise tool token carries no `.`/`..`"));
        }
        if !out.iter().any(|t| t == token) {
            out.push(token.to_string());
        }
    }
    Ok(out)
}

/// A task name is addressed on a command line and over the control socket, and it names a log line,
/// so it takes the same narrow character set as a secret's logical name.
fn validate_task_name(name: &str) -> Result<(), String> {
    if name == "defaults" {
        return Err("`defaults` is the reserved settings table, not a task name".to_string());
    }
    validate_secret_name(name).map(|_| ())
}

/// Validate the parameter declarations, keeping declaration order. Each must carry exactly one bound
/// (`match` or `enum`): an unbounded parameter is what turns a fixed command into an oracle.
fn validate_params(raw: BTreeMap<String, RawTaskParam>) -> Result<Vec<TaskParam>, String> {
    let mut out = Vec::with_capacity(raw.len());
    for (name, param) in raw {
        validate_param_name(&name)?;
        let (bound, default) = match param {
            RawTaskParam::Pattern(pattern) => (compile_bound(&name, Some(&pattern), &[])?, None),
            RawTaskParam::Table(t) => (
                compile_bound(&name, t.pattern.as_deref(), &t.choices)?,
                t.default,
            ),
        };
        // A default must itself satisfy the bound, or the task ships a value it would refuse from a
        // caller — a contradiction that would surface only at invocation.
        if let Some(d) = &default {
            check_value(&name, d, &bound)?;
        }
        out.push(TaskParam {
            name,
            bound,
            default,
        });
    }
    Ok(out)
}

/// A parameter name appears as `{name}` in `cmd`, so it must not carry the brace grammar itself.
fn validate_param_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("a parameter name is empty".to_string());
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-')))
    {
        return Err(format!(
            "parameter name `{name}` contains `{bad}` — use letters, digits, `_`, or `-`"
        ));
    }
    Ok(())
}

/// Build a parameter's bound from the declared `match`/`enum`, requiring exactly one and validating
/// that a pattern compiles here (rather than at invocation, where it would fail a live call).
fn compile_bound(
    name: &str,
    pattern: Option<&str>,
    choices: &[String],
) -> Result<ParamBound, String> {
    match (pattern, choices.is_empty()) {
        (Some(_), false) => Err(format!(
            "parameter `{name}` sets both `match` and `enum` — one bound per parameter"
        )),
        (None, true) => Err(format!(
            "parameter `{name}` is unbounded — set `match = \"<regex>\"` or `enum = [...]`; an \
             unbounded value can carry a comparison and turn the exit status into an oracle"
        )),
        (Some(pattern), true) => {
            regex::Regex::new(pattern)
                .map_err(|e| format!("parameter `{name}` has an invalid `match` regex: {e}"))?;
            Ok(ParamBound::Pattern(pattern.to_string()))
        }
        (None, false) => Ok(ParamBound::Choices(choices.to_vec())),
    }
}

/// Whether a value satisfies a bound. A pattern must match the **whole** value: an unanchored regex
/// would accept anything containing a match, so the check anchors it here rather than trusting the
/// author to have written `^…$`.
pub(crate) fn check_value(name: &str, value: &str, bound: &ParamBound) -> Result<(), String> {
    match bound {
        ParamBound::Pattern(pattern) => {
            let re = regex::Regex::new(pattern)
                .map_err(|e| format!("parameter `{name}` has an invalid `match` regex: {e}"))?;
            match re.find(value) {
                Some(m) if m.start() == 0 && m.end() == value.len() => Ok(()),
                _ => Err(format!(
                    "parameter `{name}` does not match its declared pattern"
                )),
            }
        }
        ParamBound::Choices(choices) => {
            if choices.iter().any(|c| c == value) {
                Ok(())
            } else {
                Err(format!(
                    "parameter `{name}` is not one of its declared values"
                ))
            }
        }
    }
}

/// Every `{placeholder}` in `cmd` must name a declared parameter, and every declared parameter must
/// be used. An undeclared placeholder would be substituted from nothing (or left literal, worse);
/// an unused parameter is a declaration that silently does nothing.
fn check_placeholders_declared(cmd: &[String], params: &[TaskParam]) -> Result<(), String> {
    let declared: BTreeSet<&str> = params.iter().map(|p| p.name.as_str()).collect();
    let mut used: BTreeSet<&str> = BTreeSet::new();
    for element in cmd {
        for name in placeholders(element) {
            if !declared.contains(name) {
                return Err(format!(
                    "`cmd` uses `{{{name}}}`, which is not a declared parameter"
                ));
            }
            used.insert(name);
        }
    }
    if let Some(unused) = declared.iter().find(|d| !used.contains(*d)) {
        return Err(format!(
            "parameter `{unused}` is declared but never used in `cmd`"
        ));
    }
    Ok(())
}

/// The `{name}` placeholders in one argv element, in order. A `{` with no closing `}` (or an empty
/// `{}`) yields nothing — it is a literal brace, not a placeholder, and validation catches a
/// mistyped one through the "declared but never used" check.
pub(crate) fn placeholders(element: &str) -> impl Iterator<Item = &str> {
    let mut rest = element;
    std::iter::from_fn(move || loop {
        let open = rest.find('{')?;
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            rest = "";
            return None;
        };
        let name = &after[..close];
        rest = &after[close + 1..];
        if !name.is_empty() {
            return Some(name);
        }
    })
}

/// Validate the environment-injected credentials, keyed by variable name.
fn validate_task_secrets(
    raw: BTreeMap<String, RawTaskSecret>,
    defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) -> Result<Vec<TaskSecret>, String> {
    let mut out = Vec::with_capacity(raw.len());
    for (var, secret) in raw {
        validate_env_name(&var)?;
        let (sources, encode, description) = match secret {
            RawTaskSecret::Ref(reff) => (
                secret_sources(Some(&reff), None, defaults, plugins)?,
                Encoding::Raw,
                None,
            ),
            RawTaskSecret::Table(t) => {
                let encode = match t.encode.as_deref() {
                    None => Encoding::Raw,
                    Some(e) => Encoding::parse(e).ok_or_else(|| {
                        format!(
                            "credential `{var}` has an unknown `encode` `{e}` \
                             (raw, base64, url, json-string)"
                        )
                    })?,
                };
                (
                    secret_sources(t.key.as_deref(), t.from.as_ref(), defaults, plugins)?,
                    encode,
                    t.description.as_deref().map(sanitize_description),
                )
            }
        };
        out.push(TaskSecret {
            var,
            sources,
            encode,
            description,
        });
    }
    Ok(out)
}

/// The resolver chain for a task credential: the terse form is a bare key expanded through
/// `[secret.defaults]` *or* an explicit `scheme://locator` ref — a task's one-liner accepts both, so
/// the common `PGPASSWORD = "sops://f#k"` needs no table. The table form may set `key` or `from`,
/// never both.
fn secret_sources(
    terse: Option<&str>,
    from: Option<&SecretFrom>,
    defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) -> Result<Vec<SecretSource>, String> {
    match (terse, from) {
        (Some(_), Some(_)) => {
            Err("set `key` or `from`, not both — a credential has one source form".to_string())
        }
        (None, None) => Err("set `key` or `from` — a credential needs a source".to_string()),
        (Some(one), None) => {
            if one.contains("://") {
                Ok(vec![parse_secret_ref(one, plugins)?])
            } else {
                expand_key(one, defaults)
            }
        }
        (None, Some(SecretFrom::One(one))) => Ok(vec![parse_secret_ref(one, plugins)?]),
        (None, Some(SecretFrom::Many(list))) => {
            if list.is_empty() {
                return Err("`from` is an empty list — declare at least one resolver ref".into());
            }
            list.iter().map(|r| parse_secret_ref(r, plugins)).collect()
        }
    }
}

/// Validate the task's wire-injected credentials, reusing the host-keyed secret validator so a
/// task's injection is bound by exactly the same rules as a session's (concrete host only, a valid
/// header name, one source form).
fn validate_task_injections(
    raw: BTreeMap<String, RawHostSecrets>,
    defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) -> Result<Vec<HeaderSecret>, String> {
    let mut out = Vec::new();
    for (host, entry) in raw {
        let list = match entry {
            RawHostSecrets::One(s) => vec![s],
            RawHostSecrets::Many(v) => v,
        };
        for one in list {
            out.push(validate_host_secret(&host, one, defaults, plugins)?);
        }
    }
    Ok(out)
}

/// Classify the task's egress entries. The same grammar as `[network] allow`, so a task's rules read
/// like any other egress rule.
fn validate_task_network(raw: &[String]) -> Result<Vec<Rule>, String> {
    raw.iter()
        .map(|entry| {
            crate::allowlist::classify(entry)
                .map_err(|e| format!("invalid `network` entry `{entry}`: {e}"))
        })
        .collect()
}

/// An environment variable name: the POSIX shape (letters, digits, underscore; not starting with a
/// digit). Rejected outright are the loader- and interpreter-control names, whatever their case: a
/// task's command is sbx's choice, and `LD_PRELOAD`/`BASH_ENV`/`PATH` would hand that choice back to
/// whoever set the variable. This is an allowlist-shaped check on purpose — the `[env]`
/// reserved-key denylist is untrusted-*config*-only (a trusted config harms only itself), while a
/// caller reaching in over the control socket is a different actor entirely.
pub(super) fn validate_env_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("an environment variable name is empty".to_string());
    }
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(format!("`{name}` starts with a digit"));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '_'))
    {
        return Err(format!(
            "`{name}` contains `{bad}` — a variable name is letters, digits, and `_`"
        ));
    }
    const REFUSED_PREFIXES: &[&str] = &["LD_", "NIX_LD"];
    const REFUSED: &[&str] = &[
        "PATH",
        "HOME",
        "IFS",
        "ENV",
        "BASH_ENV",
        "SHELL",
        "GCONV_PATH",
        "GLIBC_TUNABLES",
        "LOCPATH",
        "NLSPATH",
        "HOSTALIASES",
        "RESOLV_HOST_CONF",
        "PYTHONSTARTUP",
        "PYTHONPATH",
        "NODE_OPTIONS",
        "PERL5OPT",
        "RUBYOPT",
        "GIT_SSH_COMMAND",
        "SSH_ASKPASS",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "CURL_CA_BUNDLE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    ];
    let upper = name.to_ascii_uppercase();
    if REFUSED_PREFIXES.iter().any(|p| upper.starts_with(p)) || REFUSED.contains(&upper.as_str()) {
        return Err(format!(
            "`{name}` steers how a program loads or connects, so it is never settable for a task \
             (the task's command and its trust anchors are sbx's choice)"
        ));
    }
    Ok(())
}

/// Parse a captured-output ceiling: a positive byte count with an optional binary suffix (`B`,
/// `KiB`, `MiB`, or the bare `K`/`M` spellings), e.g. `"64KiB"`, `"1MiB"`, `"4096"`.
///
/// Deliberately **not** [`crate::storage::parse_size`], whose job is sizing a storage volume: that
/// one has no `KiB` and enforces a gigabyte-scale minimum, so a 64 KiB output cap would be rejected
/// as "too small". Same word, different domain — reusing it here would be a bug wearing the costume
/// of code reuse.
pub(super) fn parse_output_cap(raw: &str) -> Result<u64, String> {
    let s = raw.trim();
    let malformed = || format!("`{raw}` is not a size (try \"64KiB\", \"1MiB\", \"4096\")");
    let lower = s.to_ascii_lowercase();
    let (digits, mult) = if let Some(n) = lower.strip_suffix("kib") {
        (n, 1024_u64)
    } else if let Some(n) = lower.strip_suffix("mib") {
        (n, 1024 * 1024)
    } else if let Some(n) = lower.strip_suffix('k') {
        (n, 1024)
    } else if let Some(n) = lower.strip_suffix('m') {
        (n, 1024 * 1024)
    } else if let Some(n) = lower.strip_suffix('b') {
        (n, 1)
    } else {
        (lower.as_str(), 1)
    };
    let n: u64 = digits.trim().parse().map_err(|_| malformed())?;
    let bytes = n
        .checked_mul(mult)
        .ok_or_else(|| format!("`{raw}` is too large"))?;
    if bytes == 0 {
        return Err(format!("`{raw}` is zero — it would capture nothing"));
    }
    Ok(bytes)
}

/// Parse an output disposition, defaulting to `show`. An unknown spelling is an error rather than a
/// silent default: `stdout = "mask"` (a spelling that no longer exists, since substitution is now
/// unconditional) must say so instead of quietly showing everything.
fn parse_disposition(field: &str, raw: Option<&str>) -> Result<OutputDisposition, String> {
    match raw {
        None | Some("show") => Ok(OutputDisposition::Show),
        Some("hide") => Ok(OutputDisposition::Hide),
        Some(other) => Err(format!(
            "unknown `{field}` `{other}` — use \"show\" or \"hide\" (secret substitution is \
             unconditional, so there is no \"mask\")"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{RawTaskParamTable, RawTaskSecretTable};

    /// A minimal valid task: a fixed program, one bounded parameter, one credential.
    fn raw_task() -> RawTask {
        RawTask {
            description: Some("Read-only SQL".into()),
            cmd: vec!["psql".into(), "-c".into(), "{sql}".into()],
            params: [(
                "sql".to_string(),
                RawTaskParam::Pattern("^SELECT [a-z, ]+$".into()),
            )]
            .into_iter()
            .collect(),
            secret: [(
                "PGPASSWORD".to_string(),
                RawTaskSecret::Ref("env://DEMO_DB_PASSWORD".into()),
            )]
            .into_iter()
            .collect(),
            ..RawTask::default()
        }
    }

    fn validate(raw: RawTask) -> Result<TaskSpec, String> {
        validate_task(
            "db-query",
            raw,
            &TaskDefaults::default(),
            &SecretDefaults::default(),
            &PluginRegistry::default(),
        )
    }

    #[test]
    fn a_minimal_task_validates_with_the_section_defaults() {
        let task = validate(raw_task()).unwrap();
        assert_eq!(task.name, "db-query");
        assert_eq!(task.cmd, vec!["psql", "-c", "{sql}"]);
        assert_eq!(task.params.len(), 1);
        assert_eq!(task.secrets[0].var, "PGPASSWORD");
        assert_eq!(task.secrets[0].encode, Encoding::Raw);
        assert_eq!(task.stdout, OutputDisposition::Show);
        assert_eq!(task.timeout, TaskDefaults::default().timeout);
        assert_eq!(task.max_output, TaskDefaults::default().max_output);
        assert!(task.network.is_empty(), "no egress unless declared");
    }

    // The one property the whole feature rests on: the program is sbx's. A placeholder in argv0
    // would let a caller pick the binary, which is exactly what a declared task exists to prevent.
    #[test]
    fn a_placeholder_in_the_program_is_refused() {
        let mut raw = raw_task();
        raw.cmd[0] = "{sql}".into();
        let e = validate(raw).unwrap_err();
        assert!(e.contains("cmd[0]"), "the error names argv0: {e}");
    }

    #[test]
    fn an_empty_cmd_is_refused() {
        let mut raw = raw_task();
        raw.cmd.clear();
        assert!(validate(raw).unwrap_err().contains("`cmd`"));
    }

    // An unbounded parameter re-opens the exit-status oracle over the credential, so it is refused
    // at validation rather than trusted to be used carefully.
    #[test]
    fn an_unbounded_parameter_is_refused() {
        let mut raw = raw_task();
        raw.params = [("sql".to_string(), RawTaskParam::Table(Default::default()))]
            .into_iter()
            .collect();
        let e = validate(raw).unwrap_err();
        assert!(e.contains("unbounded"), "{e}");
    }

    #[test]
    fn a_parameter_setting_both_bounds_is_refused() {
        let mut raw = raw_task();
        raw.params = [(
            "sql".to_string(),
            RawTaskParam::Table(RawTaskParamTable {
                pattern: Some("^a$".into()),
                choices: vec!["a".into()],
                default: None,
            }),
        )]
        .into_iter()
        .collect();
        assert!(validate(raw).unwrap_err().contains("both"));
    }

    // A placeholder with no declaration, and a declaration no placeholder uses, are both errors:
    // the first would substitute from nothing, the second is a bound that silently does nothing.
    #[test]
    fn placeholders_and_declarations_must_agree() {
        let mut undeclared = raw_task();
        undeclared.cmd.push("{limit}".into());
        assert!(validate(undeclared).unwrap_err().contains("{limit}"));

        let mut unused = raw_task();
        unused.params.insert(
            "limit".to_string(),
            RawTaskParam::Pattern("^[0-9]+$".into()),
        );
        let e = validate(unused).unwrap_err();
        assert!(e.contains("never used"), "{e}");
    }

    // A default is a value the task ships, so it must satisfy the same bound a caller's value would
    // — otherwise the task would refuse from a caller what it uses itself.
    #[test]
    fn a_default_must_satisfy_its_own_bound() {
        let mut raw = raw_task();
        raw.params = [(
            "sql".to_string(),
            RawTaskParam::Table(RawTaskParamTable {
                pattern: Some("^SELECT [a-z]+$".into()),
                choices: vec![],
                default: Some("DROP TABLE t".into()),
            }),
        )]
        .into_iter()
        .collect();
        assert!(validate(raw).unwrap_err().contains("does not match"));
    }

    // An unanchored pattern must not accept a value that merely *contains* a match: the check
    // anchors it, rather than trusting every author to have written `^…$`.
    #[test]
    fn a_pattern_bound_must_match_the_whole_value() {
        let bound = ParamBound::Pattern("SELECT".into());
        assert!(check_value("sql", "SELECT", &bound).is_ok());
        assert!(
            check_value("sql", "SELECT; DROP TABLE t", &bound).is_err(),
            "a containing value must not pass an unanchored pattern"
        );
    }

    // The loader-control and interpreter-hook variables would hand the choice of program back to
    // whoever sets them, so they are never settable for a task — fixed or caller-supplied.
    #[test]
    fn loader_and_interpreter_control_variables_are_refused() {
        for var in [
            "LD_PRELOAD",
            "ld_preload",
            "PATH",
            "BASH_ENV",
            "NODE_OPTIONS",
            "GIT_SSH_COMMAND",
            "SSL_CERT_FILE",
            "HTTPS_PROXY",
        ] {
            let mut raw = raw_task();
            raw.env_allow = vec![var.to_string()];
            assert!(
                validate(raw).is_err(),
                "`{var}` must never be settable for a task"
            );
        }
    }

    #[test]
    fn an_exec_policy_on_a_task_is_refused_rather_than_ignored() {
        // Unknown keys are ignored by design, so a security-shaped key sbx does not honour has to be
        // rejected explicitly — otherwise `deny = [...]` reads as a fence and silently is none.
        for (label, apply) in [
            (
                "allow",
                (|r: &mut RawTask| r.allow = vec!["/bin/sh".into()]) as fn(&mut RawTask),
            ),
            ("deny", |r: &mut RawTask| r.deny = vec!["curl".into()]),
        ] {
            let mut raw = raw_task();
            apply(&mut raw);
            let err = validate(raw).expect_err("an exec policy must not parse into silence");
            assert!(
                err.contains(label) && err.contains("not a task control"),
                "`{label}` must be refused by name, said plainly: {err}"
            );
        }
    }

    #[test]
    fn a_variable_cannot_be_both_fixed_and_caller_settable() {
        let mut raw = raw_task();
        raw.env = [("PGCONNECT_TIMEOUT".to_string(), "5".to_string())]
            .into_iter()
            .collect();
        raw.env_allow = vec!["PGCONNECT_TIMEOUT".into()];
        assert!(validate(raw).unwrap_err().contains("env_allow"));
    }

    #[test]
    fn a_variable_cannot_be_both_a_credential_and_plain_environment() {
        let mut raw = raw_task();
        raw.env = [("PGPASSWORD".to_string(), "not-a-secret".to_string())]
            .into_iter()
            .collect();
        assert!(validate(raw).unwrap_err().contains("one name, one source"));
    }

    // `mask` was a real spelling in the design before substitution became unconditional. Silently
    // treating it as `show` would hand back the whole stream to a caller who asked for less.
    #[test]
    fn the_removed_mask_disposition_is_an_explicit_error() {
        let mut raw = raw_task();
        raw.stdout = Some("mask".into());
        let e = validate(raw).unwrap_err();
        assert!(e.contains("show") && e.contains("hide"), "{e}");
    }

    // A task that can hang forever holds a caller and a resolved credential open, so "no timeout"
    // is not an available choice — unlike an `ask_timeout`, where indefinite is the default.
    #[test]
    fn a_zero_timeout_is_refused() {
        let mut raw = raw_task();
        raw.timeout = Some("0".into());
        assert!(validate(raw).unwrap_err().contains("positive"));

        let mut bad = raw_task();
        bad.timeout = Some("soon".into());
        assert!(validate(bad).is_err());
    }

    #[test]
    fn a_zero_max_output_is_refused() {
        let mut raw = raw_task();
        raw.max_output = Some("0".into());
        assert!(validate(raw).unwrap_err().contains("capture nothing"));
    }

    // A wire injection happens in the task's own proxy, which only exists when the task has egress.
    // Accepting the pair silently would mean the command sends an unauthenticated request and the
    // author never learns why.
    #[test]
    fn an_injection_without_egress_is_refused() {
        let mut raw = raw_task();
        raw.inject = [(
            "api.example.com".to_string(),
            RawHostSecrets::One(RawHostSecret {
                name: None,
                description: None,
                kind: None,
                key: None,
                from: Some(SecretFrom::One("env://DEMO_TOKEN".into())),
                header: Some("Authorization".into()),
                value_type: Some("bearer".into()),
                prefix: None,
            }),
        )]
        .into_iter()
        .collect();
        let e = validate(raw.clone()).unwrap_err();
        assert!(e.contains("network"), "{e}");

        raw.network = vec!["api.example.com".into()];
        let task = validate(raw).unwrap();
        assert_eq!(task.injections.len(), 1);
        assert_eq!(task.network.len(), 1);
    }

    #[test]
    fn an_unknown_encoding_is_refused_and_a_known_one_is_kept() {
        let mut bad = raw_task();
        bad.secret = [(
            "PGPASSWORD".to_string(),
            RawTaskSecret::Table(RawTaskSecretTable {
                from: Some(SecretFrom::One("env://DEMO_DB_PASSWORD".into())),
                encode: Some("rot13".into()),
                ..Default::default()
            }),
        )]
        .into_iter()
        .collect();
        assert!(validate(bad).unwrap_err().contains("rot13"));

        let mut ok = raw_task();
        ok.secret = [(
            "PGPASSWORD".to_string(),
            RawTaskSecret::Table(RawTaskSecretTable {
                from: Some(SecretFrom::One("env://DEMO_DB_PASSWORD".into())),
                encode: Some("base64".into()),
                description: Some("staging database password".into()),
                ..Default::default()
            }),
        )]
        .into_iter()
        .collect();
        let task = validate(ok).unwrap();
        assert_eq!(task.secrets[0].encode, Encoding::Base64);
        assert_eq!(
            task.secrets[0].description.as_deref(),
            Some("staging database password")
        );
    }

    // The terse credential form accepts both spellings a one-liner plausibly carries: an explicit
    // resolver ref, and a bare key expanded through `[secret.defaults]`.
    #[test]
    fn the_terse_credential_form_takes_a_ref_or_a_defaults_key() {
        let task = validate(raw_task()).unwrap();
        assert_eq!(
            task.secrets[0].sources,
            vec![SecretSource::Env("DEMO_DB_PASSWORD".into())]
        );

        let mut terse = raw_task();
        terse.secret = [(
            "PGPASSWORD".to_string(),
            RawTaskSecret::Ref("db_password".into()),
        )]
        .into_iter()
        .collect();
        // With no `[secret.defaults] order`, a bare key has no resolver to expand through — the
        // failure names that rather than silently treating the key as a literal value.
        assert!(validate(terse).is_err());
    }

    #[test]
    fn the_reserved_defaults_name_is_not_a_task() {
        let e = validate_task(
            "defaults",
            raw_task(),
            &TaskDefaults::default(),
            &SecretDefaults::default(),
            &PluginRegistry::default(),
        )
        .unwrap_err();
        assert!(e.contains("reserved"), "{e}");
    }

    // A same-named task from a later layer replaces the earlier one and says so: two operations a
    // caller cannot tell apart would be worse than either.
    #[test]
    fn a_redeclared_task_overrides_with_a_warning() {
        let mut out = Vec::new();
        let mut warnings = Vec::new();
        let first = validate(raw_task()).unwrap();
        let mut second_raw = raw_task();
        second_raw.description = Some("the later one".into());
        let second = validate(second_raw).unwrap();
        upsert_task(&mut out, &mut warnings, "global config", first);
        upsert_task(&mut out, &mut warnings, "app overlay", second);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].description.as_deref(), Some("the later one"));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("db-query"), "{:?}", warnings);
    }

    // The output cap has its own parser because the storage one means something else entirely (it
    // sizes a volume and rejects anything under a gigabyte). Pin the spellings a task plausibly
    // uses, and that a zero cap is refused rather than silently capturing nothing.
    #[test]
    fn the_output_cap_parser_reads_byte_scale_sizes() {
        assert_eq!(parse_output_cap("4096"), Ok(4096));
        assert_eq!(parse_output_cap("64KiB"), Ok(64 * 1024));
        assert_eq!(parse_output_cap("64kib"), Ok(64 * 1024));
        assert_eq!(parse_output_cap("1MiB"), Ok(1024 * 1024));
        assert_eq!(parse_output_cap("512B"), Ok(512));
        assert_eq!(parse_output_cap(" 8K "), Ok(8 * 1024));
        assert!(parse_output_cap("0").is_err());
        assert!(parse_output_cap("plenty").is_err());
        assert!(parse_output_cap("").is_err());
    }

    // The placeholder scanner underpins both the validation and the substitution, so pin its edge
    // cases: a lone brace is literal, an empty `{}` is not a placeholder.
    #[test]
    fn the_placeholder_scanner_reads_only_real_placeholders() {
        let names: Vec<&str> = placeholders("a{one}b{two}c").collect();
        assert_eq!(names, vec!["one", "two"]);
        assert_eq!(placeholders("no braces").count(), 0);
        assert_eq!(placeholders("{unclosed").count(), 0);
        assert_eq!(placeholders("empty {} here").count(), 0);
        assert_eq!(placeholders("${shell}").collect::<Vec<_>>(), vec!["shell"]);
    }

    // The section ceilings layer field by field, and a malformed value keeps the stricter inherited
    // one rather than silently widening.
    #[test]
    fn the_section_defaults_layer_and_fail_closed() {
        let mut warnings = Vec::new();
        let base = TaskDefaults::default();
        let merged = base.merged_with(
            &RawTaskDefaults {
                timeout: Some("5m".into()),
                nonce: None,
                max_output: Some("1MiB".into()),
            },
            "global config",
            &mut warnings,
        );
        assert_eq!(merged.timeout, std::time::Duration::from_secs(300));
        assert_eq!(merged.max_output, 1024 * 1024);
        assert!(warnings.is_empty());

        let kept = merged.merged_with(
            &RawTaskDefaults {
                timeout: Some("nope".into()),
                nonce: None,
                max_output: Some("0".into()),
            },
            ".sbx.toml",
            &mut warnings,
        );
        assert_eq!(kept.timeout, merged.timeout, "a bad value keeps the prior");
        assert_eq!(kept.max_output, merged.max_output);
        assert_eq!(warnings.len(), 2, "both are reported: {warnings:?}");
    }

    /// `packages` takes `mise:` and nothing else, and the prefix comes off — what reaches the pool
    /// is the bare mise token. Duplicates collapse, since the pool installs a tool once.
    #[test]
    fn task_packages_take_mise_and_strip_its_prefix() {
        assert_eq!(
            validate_task_packages(&[
                "mise:aqua:cli/gh".into(),
                "mise:node@22".into(),
                "mise:node@22".into(),
            ])
            .unwrap(),
            vec!["aqua:cli/gh".to_string(), "node@22".to_string()]
        );
        assert!(validate_task_packages(&[]).unwrap().is_empty());
    }

    /// A backend that already builds host-side into the shared store is refused here rather than
    /// given a second provisioning path — and the message says where it belongs.
    #[test]
    fn a_host_side_backend_is_refused_with_where_it_belongs() {
        let e = validate_task_packages(&["nix:jq".into()]).unwrap_err();
        assert!(e.contains("[packages]"), "{e}");
        let e = validate_task_packages(&["flake:github:owner/repo#tool".into()]).unwrap_err();
        assert!(e.contains("[packages]"), "{e}");
    }

    /// mise's own `nix:` backend builds into the store the cage writes — the very provenance problem
    /// the pool exists to solve — so it is refused by name, pointing at the host-side equivalent.
    #[test]
    fn mise_nix_is_refused_pointing_at_the_host_side_backend() {
        let e = validate_task_packages(&["mise:nix:jq".into()]).unwrap_err();
        assert!(e.contains("nix:jq"), "{e}");
    }

    /// A token reaches both a `mise install` argv and a path under the pool, so the characters that
    /// would make either ambiguous are refused rather than quietly rewritten.
    #[test]
    fn a_malformed_token_is_refused() {
        for bad in [
            "mise:",
            "mise:  ",
            "mise:a b",
            "mise:../escape",
            "mise:x/../y",
        ] {
            assert!(
                validate_task_packages(&[bad.into()]).is_err(),
                "`{bad}` must be refused"
            );
        }
    }
}
