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
//!
//! The inverse of check 1 — letting the caller compose the program, so an agent needing fifteen
//! subcommands of one tool stops needing fifteen declared tasks — is **held on an argument, not
//! merely unbuilt**. Such a tier has to deem the credential disclosed to the caller, and the
//! containment it would be argued from does not hold:
//!
//! - **The oracle.** A caller who writes the program encodes a byte of the credential in its exit
//!   status, which `write_outcome` answers verbatim, one character per call. No packet leaves the
//!   cage, so no allowlist bounds it. Under a *fixed* command that cannot happen: the caller never
//!   authors the program, and every value it supplies is checked against its parameter's bound.
//! - **The part that outlives the oracle**, and the real closer: once the caller holds the value,
//!   this cage's narrow allowlist governs nothing, because the caller spends the credential through
//!   its own, wider one. Lane separation protects a *careless* caller — a credential into a log or
//!   a prompt — never a hostile one, and untrusted is the default posture.
//!
//! The nearest sound thing already ships: a parameterized fixed command. A use case that does not
//! fit is usually one more `param`, not one more tier. Recorded here because the design note that
//! carried this argument no longer exists, and the sentence it replaced — that only the egress
//! allowlist and the empty netns contain the disclosure — reads as an invitation to build it.

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
    layer: &TaskLayer,
    section: RawTaskSection,
    defaults: &TaskDefaults,
    secret_defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) {
    let source = layer.source;
    for (name, raw) in section.tasks {
        match validate_task(
            &name,
            raw,
            &layer.origin,
            defaults,
            secret_defaults,
            plugins,
        ) {
            Ok(task) => upsert_task(out, warnings, source, task),
            Err(e) => warnings.push(format!("{source}: ignoring task `{name}` — {e}")),
        }
    }
}

/// Which config layer a `[task]` section came from — the same question asked twice: `source` names
/// it to a person reading a warning, `origin` is what each operation the layer declares is stamped
/// with. One value, because a layer that answered the two differently would be a bug.
pub(super) struct TaskLayer<'a> {
    pub(super) source: &'a str,
    pub(super) origin: TaskOrigin,
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
    /// Which layer's `[task.defaults]` set each ceiling, so a task that inherits one can say where
    /// it came from. Carried here because this is the only place that knows: by the time a task is
    /// validated the layers have already merged into one value.
    pub(super) timeout_from: Ceiling,
    pub(super) max_output_from: Ceiling,
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
            timeout_from: Ceiling::BuiltIn,
            max_output_from: Ceiling::BuiltIn,
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
        layer: &TaskLayer,
        warnings: &mut Vec<String>,
    ) -> Self {
        let source = layer.source;
        let mut out = self.clone();
        if let Some(raw_timeout) = &raw.timeout {
            match parse_task_timeout(raw_timeout) {
                Ok(d) => {
                    out.timeout = d;
                    out.timeout_from = Ceiling::Defaults(layer.origin.clone());
                }
                Err(e) => warnings.push(format!(
                    "{source}: ignoring `[task.defaults] timeout` — {e}"
                )),
            }
        }
        if let Some(raw_max) = &raw.max_output {
            match parse_output_cap(raw_max) {
                Ok(n) => {
                    out.max_output = n;
                    out.max_output_from = Ceiling::Defaults(layer.origin.clone());
                }
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
    match super::parse_duration(raw)? {
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
    origin: &TaskOrigin,
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
    check_placeholders_declared(&raw.cmd, &params, raw.output)?;

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

    // Each ceiling with where it came from: the block itself, or whichever layer's `[task.defaults]`
    // the merged defaults last took it from. An operation really is composed of two layers, and a
    // reader shown only the block would go and edit a file that does not contain the value.
    let (timeout, timeout_from) = match &raw.timeout {
        Some(t) => (parse_task_timeout(t)?, Ceiling::Declared),
        None => (defaults.timeout, defaults.timeout_from.clone()),
    };
    let (max_output, max_output_from) = match &raw.max_output {
        Some(m) => (parse_output_cap(m)?, Ceiling::Declared),
        None => (defaults.max_output, defaults.max_output_from.clone()),
    };

    // `[proc]`'s key names on a task, refused rather than parsed into silence: what a task's command
    // may run is declared by `spawn`, whose semantics are a task's (a fixed command plus what it may
    // run) and not a session's denylist. Accepting these as aliases would make two spellings of one
    // control, each with a different unmatched default.
    for field in ["allow", "deny"] {
        let declared = if field == "allow" {
            &raw.allow
        } else {
            &raw.deny
        };
        if !declared.is_empty() {
            return Err(format!(
                "`{field}` is not a task control — what a task's command may run beside itself is \
                 declared by `spawn`, and what else bounds a task is its fixed `cmd`, the `params` \
                 bounds, and a cage with no network unless `network` declares one"
            ));
        }
    }

    let spawn = spawn_entries(raw.spawn)?
        .map(|entries| validate_spawn_entries(name, "`spawn`", entries))
        .transpose()?;
    let exec = validate_task_exec(name, &raw.cmd, spawn.as_ref(), raw.exec)?;
    let packages = validate_task_packages(&raw.packages)?;
    let unmask = validate_unmask(&raw.unmask)?;

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
        spawn,
        exec,
        output: raw.output,
        unmask,
        // A bundle folded into an app keeps the bundle's name: the fold made the entry look like
        // the app's own, and the bundle is where a reader would go to change it.
        origin: match raw.from_bundle {
            Some(bundle) => TaskOrigin::Bundle(bundle),
            None => origin.clone(),
        },
        timeout_from,
        max_output_from,
    })
}

/// Programs whose whole job is to run whatever they are told, in a language of their own. Listing
/// one does not merely widen the set — it concedes the gate: an interpreter can take a credential
/// apart and put it back together with builtins alone, and nothing it does that way is an `execve`
/// to decide. A declaration is still allowed to make that trade (a command that genuinely shells
/// out has no other option), but it is worth saying out loud.
const OPEN_ENDED: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "fish", "env", "python", "python3", "perl", "ruby", "node",
    "awk", "gawk", "xargs",
];

/// Read the entries out of one `spawn` declaration, refusing the shapes that are not the field, and
/// return them **unvalidated** — [`validate_spawn_entries`] is what judges them, and it needs to
/// know which list it is naming.
///
/// Absent and empty are **different**: absent is no exec supervision at all (the command runs as it
/// always has), empty is a supervised cage where only the command itself may run. That distinction is
/// the field's whole ergonomics, so it is carried as an `Option` rather than flattened to a list.
fn spawn_entries(
    raw: Option<crate::config::schema::RawTaskSpawn>,
) -> Result<Option<Vec<String>>, String> {
    use crate::config::schema::{RawSpawnEntry, RawTaskSpawn};
    // Both spellings of a graph get the same refusal, because they are the same declaration: a
    // reader who guessed the other one deserves the reason and not a different treatment.
    let graph_refusal = || {
        "`spawn` is a flat list of programs; putting a table under one reads as \"this program may \
         run these\", and that is not what is enforced: the exec filter is inherited across `fork` \
         and `exec`, so an entry governs the whole cage at any depth rather than one parent's \
         children. Declare the flat set of programs that may run."
            .to_string()
    };
    let entries: Vec<String> = match raw {
        None => return Ok(None),
        Some(RawTaskSpawn::One(s)) => vec![s],
        Some(RawTaskSpawn::Flat(v)) => v
            .into_iter()
            .map(|entry| match entry {
                RawSpawnEntry::Name(s) => Ok(s),
                RawSpawnEntry::Nested(_) => Err(graph_refusal()),
            })
            .collect::<Result<_, _>>()?,
        Some(RawTaskSpawn::Nested(_)) => return Err(graph_refusal()),
    };
    Ok(Some(entries))
}

/// Validate the entries of one `spawn` list — the task's own or a node's — and return them trimmed,
/// with empty entries dropped. `whose` names the list in a refusal, since a task can hold several.
fn validate_spawn_entries(
    name: &str,
    whose: &str,
    entries: Vec<String>,
) -> Result<Vec<String>, String> {
    for entry in &entries {
        let trimmed = entry.trim();
        crate::proc_policy::validate_rule(trimmed)?;
        if trimmed == "*" || trimmed == "**" {
            return Err(format!(
                "{whose} lists `{trimmed}`, which allows everything — and that is what leaving \
                 `spawn` out already means. One way to say a thing: remove the key, or name the \
                 programs."
            ));
        }
        let base = trimmed.rsplit('/').next().unwrap_or(trimmed);
        if OPEN_ENDED.contains(&base) {
            crate::diag::warn(&format!(
                "task `{name}`: {whose} lists `{base}` — an interpreter concedes most of this \
                 guard, since what it does with its own builtins never reaches an `execve` to \
                 decide"
            ));
        }
    }
    Ok(entries
        .into_iter()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .collect())
}

/// Validate the `[task.<name>.exec.<program>]` sections against the root `spawn` list, and return
/// them as program → what that program may run.
///
/// A section addresses **a program, wherever it was reached from**: one rule per program, read off
/// the caller's own executable. That is why a section body is flat and why there is no deeper
/// address — a chain-scoped form would decide the same target differently depending on how it was
/// reached, and every deeper spelling would have to be written out.
///
/// Three things are refused rather than accepted-and-ignored, all of them the same failure: a
/// declaration that is read nowhere. A section with no supervisor to enforce it (`spawn` absent), a
/// section nothing can reach, and a section for the command itself — which already has `spawn`.
fn validate_task_exec(
    name: &str,
    cmd: &[String],
    root: Option<&Vec<String>>,
    raw: BTreeMap<String, crate::config::schema::RawTaskExecNode>,
) -> Result<BTreeMap<String, Vec<String>>, String> {
    if raw.is_empty() {
        return Ok(BTreeMap::new());
    }
    let Some(root) = root else {
        return Err(
            "`[exec.<program>]` says what a program may run once the command has run it, and \
             nothing enforces that unless the task declares `spawn` — which is what stands the \
             supervisor up. Declare `spawn` with the programs the command itself may run."
                .to_string(),
        );
    };
    let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (key, node) in raw {
        let program = key.trim().to_string();
        if program.is_empty() {
            return Err("`[exec.<program>]` needs a program name".to_string());
        }
        crate::proc_policy::validate_rule(&program)?;
        // A glob may say what *may run*, because there the answer is only yes or no. It cannot say
        // *who is running*: a caller is one program, and two overlapping patterns would both claim
        // it with no honest way to pick. So a name here is literal, and a program admitted by a
        // pattern simply has no node — it may run nothing, which is the fail-closed answer.
        if program.contains('*') || program.contains('?') {
            return Err(format!(
                "`[exec.{program}]` is a pattern, and a section names one program: the caller of an \
                 `execve` is a single executable, so two patterns matching it would both claim it. \
                 Write the program, or leave it without a section — it may then run nothing."
            ));
        }
        if cmd.first().is_some_and(|c| c.trim() == program) {
            return Err(format!(
                "`[exec.{program}]` is the command itself, and what the command may run is `spawn`. \
                 Two declarations of one thing would each be half of it."
            ));
        }
        if let Some(unknown) = node.rest.keys().next() {
            // A deeper section arrives here as a table under the node, which is the same message: a
            // node is addressed by its program and by nothing else.
            return Err(format!(
                "`[exec.{program}]` holds `{unknown}`, which is not a key of a node — a node \
                 declares `spawn`, the programs it may run. A section addresses a program, wherever \
                 that program was reached from, so there is nothing deeper to address."
            ));
        }
        let Some(spawn) = node.spawn else {
            return Err(format!(
                "`[exec.{program}]` declares nothing — a node without `spawn` says what a program \
                 may run and then names none of it, which is what having no section already means."
            ));
        };
        let entries = spawn_entries(Some(spawn))?.expect("a declared spawn is never absent");
        let whose = format!("`[exec.{program}]`'s `spawn`");
        let entries = validate_spawn_entries(name, &whose, entries)?;
        // An empty list is meaningful on the task — it is what stands the supervisor up, for a
        // command that must run nothing else. On a node it is not: a program with no node may
        // already run nothing, so this would be the second way to say one thing.
        if entries.is_empty() {
            return Err(format!(
                "`[exec.{program}]` allows nothing, which is what having no section for `{program}` \
                 already means. Remove the section, or name what it may run."
            ));
        }
        graph.insert(program, entries);
    }

    // Reachability, by the spelling each declaration uses: a node is reached when the root list or
    // some reached node names it. A node nothing reaches is a control that is read nowhere — the
    // failure a security-shaped field must never have, and the reason this walks rather than trusts.
    let mut reached: BTreeSet<&str> = BTreeSet::new();
    let mut queue: Vec<&str> = root.iter().map(String::as_str).collect();
    while let Some(program) = queue.pop() {
        if !reached.insert(program) {
            continue; // already walked: a self-edge and a cycle are both legitimate here
        }
        if let Some(children) = graph.get(program) {
            queue.extend(children.iter().map(String::as_str));
        }
    }
    if let Some(orphan) = graph.keys().find(|k| !reached.contains(k.as_str())) {
        return Err(format!(
            "`[exec.{orphan}]` says what `{orphan}` may run, but nothing may run `{orphan}`: it is \
             in neither `spawn` nor any section that is itself reachable. Name it where it is run, \
             spelled as it is there."
        ));
    }
    Ok(graph)
}

/// Validate a task's `unmask` entries against the same grammar `[fs]` uses, so an entry that could
/// never name a mask is refused where it is written rather than shrugged off at launch.
///
/// This checks the *spelling* only. Whether an entry names a path the `[fs] deny` list actually
/// carries is decided at launch, in the one place both lists are in hand — and it is a warning
/// there, not an error, because an entry that matches no mask lifts nothing: the path stays closed.
fn validate_unmask(raw: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        match crate::config::fspolicy::validate_entry(entry) {
            Ok(ok) if out.contains(&ok) => {}
            Ok(ok) => out.push(ok),
            Err(reason) => {
                return Err(format!(
                    "`unmask` entry `{entry}` {reason} — it names an `[fs] deny` entry, in the same \
                     form that list is written in"
                ));
            }
        }
    }
    Ok(out)
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

/// The placeholder sbx fills in itself: the invocation's writable output directory. It is **not** a
/// parameter — a caller who could choose where the command writes would choose the project — so the
/// name is reserved, and a declaration may only use it where `output` asks for the directory.
pub(crate) const OUT_PLACEHOLDER: &str = "out";

/// Every `{placeholder}` in `cmd` must name a declared parameter (or the reserved `{out}`), and every
/// declared parameter must be used. An undeclared placeholder would be substituted from nothing (or
/// left literal, worse); an unused parameter is a declaration that silently does nothing.
fn check_placeholders_declared(
    cmd: &[String],
    params: &[TaskParam],
    output: bool,
) -> Result<(), String> {
    if let Some(clash) = params.iter().find(|p| p.name == OUT_PLACEHOLDER) {
        return Err(format!(
            "`{}` is reserved — it names the output directory sbx supplies, which a caller must not \
             choose",
            clash.name
        ));
    }
    let declared: BTreeSet<&str> = params.iter().map(|p| p.name.as_str()).collect();
    let mut used: BTreeSet<&str> = BTreeSet::new();
    for element in cmd {
        for name in placeholders(element) {
            if name == OUT_PLACEHOLDER {
                if !output {
                    return Err(
                        "`cmd` uses `{out}`, but this task declares no `output` — there would be \
                         nothing to substitute, and a task cage keeps nothing it writes"
                            .to_string(),
                    );
                }
                continue;
            }
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
    std::iter::from_fn(move || {
        loop {
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
                expand_key(one, defaults, plugins)
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
            &TaskOrigin::Project,
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

    // Absent and empty are different declarations, and the difference is the whole ergonomics of the
    // field: leaving `spawn` out is "do not supervise this at all", while `spawn = []` is "supervise
    // it, and only the command itself may run". Flattening one into the other would either brick
    // every existing task or make the strict form unwritable.
    #[test]
    fn an_absent_spawn_is_not_the_same_declaration_as_an_empty_one() {
        let absent = validate(raw_task()).expect("a task with no spawn");
        assert_eq!(absent.spawn, None, "absent means no supervision at all");

        let mut raw = raw_task();
        raw.spawn = Some(crate::config::schema::RawTaskSpawn::Flat(vec![]));
        let empty = validate(raw).expect("a task declaring an empty spawn");
        assert_eq!(
            empty.spawn,
            Some(vec![]),
            "an empty list is a declaration, not the absence of one"
        );
    }

    // The terse single-program form, since one is the common case.
    #[test]
    fn a_bare_string_spawn_is_one_program() {
        let mut raw = raw_task();
        raw.spawn = Some(crate::config::schema::RawTaskSpawn::One("git".into()));
        assert_eq!(
            validate(raw).expect("a task").spawn,
            Some(vec!["git".to_string()])
        );
    }

    /// A `spawn` list of plain program names.
    fn spawn_names(names: &[&str]) -> crate::config::schema::RawTaskSpawn {
        crate::config::schema::RawTaskSpawn::Flat(
            names
                .iter()
                .map(|n| crate::config::schema::RawSpawnEntry::Name(n.to_string()))
                .collect(),
        )
    }

    // The table form reads as "this program may run these" — a per-parent restriction. What is
    // enforced is the flat set, because the exec filter is inherited across fork and exec. Accepting
    // the table and flattening it would be a declaration that means less than it says, which is the
    // failure this field exists to avoid.
    #[test]
    fn a_nested_spawn_is_refused_rather_than_flattened() {
        let mut raw = raw_task();
        raw.spawn = Some(crate::config::schema::RawTaskSpawn::Nested(
            [("git".to_string(), spawn_names(&["git-remote-https"]))]
                .into_iter()
                .collect(),
        ));
        let e = validate(raw).unwrap_err();
        assert!(
            e.contains("flat list") && e.contains("any depth"),
            "the refusal must say what is enforced instead: {e}"
        );
    }

    // The same declaration, spelled as a table *inside* the list. It has to reach the same refusal:
    // an untagged variant that matches nothing is a deserialization error, and that is reported
    // against the whole file — one mis-shaped key would take every other task down with it.
    #[test]
    fn a_table_inside_the_spawn_list_is_refused_by_name() {
        let mut raw = raw_task();
        raw.spawn = Some(crate::config::schema::RawTaskSpawn::Flat(vec![
            crate::config::schema::RawSpawnEntry::Name("git".into()),
            crate::config::schema::RawSpawnEntry::Nested(
                [("ssh".to_string(), spawn_names(&["gpg"]))]
                    .into_iter()
                    .collect(),
            ),
        ]));
        let e = validate(raw).unwrap_err();
        assert!(
            e.contains("flat list") && e.contains("any depth"),
            "both spellings of a graph get one reason: {e}"
        );
    }

    /// One `[task.<name>.exec.<program>]` section.
    fn node(spawn: &[&str]) -> crate::config::schema::RawTaskExecNode {
        crate::config::schema::RawTaskExecNode {
            spawn: Some(spawn_names(spawn)),
            rest: BTreeMap::new(),
        }
    }

    // The whole point of the graph: what a program may run in turn, addressed by that program.
    #[test]
    fn a_node_says_what_one_program_may_run_in_turn() {
        let mut raw = raw_task();
        raw.spawn = Some(spawn_names(&["git"]));
        raw.exec = [
            ("git".to_string(), node(&["ssh"])),
            ("ssh".to_string(), node(&["gpg"])),
        ]
        .into_iter()
        .collect();
        let task = validate(raw).expect("a task declaring a chain");
        assert_eq!(task.spawn, Some(vec!["git".to_string()]));
        assert_eq!(task.exec["git"], vec!["ssh".to_string()]);
        assert_eq!(task.exec["ssh"], vec!["gpg".to_string()]);
    }

    // A node with nothing to enforce it is a control that is read nowhere — the failure this field
    // exists to avoid, and the one a security-shaped key must never have.
    #[test]
    fn a_node_without_a_task_spawn_is_refused() {
        let mut raw = raw_task();
        raw.exec = [("git".to_string(), node(&["ssh"]))].into_iter().collect();
        let e = validate(raw).unwrap_err();
        assert!(e.contains("declares `spawn`"), "{e}");
    }

    // A node nothing can reach says what a program may run when no program may run it. Same failure,
    // caught by walking from the task's own list rather than trusting the declaration.
    #[test]
    fn a_node_nothing_reaches_is_refused() {
        let mut raw = raw_task();
        raw.spawn = Some(spawn_names(&["git"]));
        raw.exec = [
            ("git".to_string(), node(&["ssh"])),
            ("make".to_string(), node(&["cc"])),
        ]
        .into_iter()
        .collect();
        let e = validate(raw).unwrap_err();
        assert!(
            e.contains("[exec.make]") && e.contains("nothing may run"),
            "{e}"
        );
    }

    // A cycle is legitimate — recursive `make`, a shell that runs a script that runs the shell — so
    // the reachability walk must terminate on one rather than refuse it or spin.
    #[test]
    fn a_cycle_between_nodes_is_reachable_and_terminates() {
        let mut raw = raw_task();
        raw.spawn = Some(spawn_names(&["make"]));
        raw.exec = [
            ("make".to_string(), node(&["cc", "make"])),
            ("cc".to_string(), node(&["make"])),
        ]
        .into_iter()
        .collect();
        let task = validate(raw).expect("a cycle is a legitimate graph");
        assert_eq!(task.exec.len(), 2);
    }

    // A caller is one executable, so two patterns matching it would both claim it with no honest way
    // to choose. A pattern may still say what *may run*, where the answer is only yes or no.
    #[test]
    fn a_node_key_may_not_be_a_pattern() {
        let mut raw = raw_task();
        raw.spawn = Some(spawn_names(&["git*"]));
        raw.exec = [("git*".to_string(), node(&["ssh"]))].into_iter().collect();
        let e = validate(raw).unwrap_err();
        assert!(e.contains("is a pattern"), "{e}");
    }

    // What the command may run is `spawn`. A node for the command itself would be the other half of
    // one declaration, and a reader would have to know both to know either.
    #[test]
    fn a_node_for_the_command_itself_is_refused() {
        let mut raw = raw_task();
        raw.cmd = vec!["git".to_string(), "push".to_string()];
        raw.params.clear();
        raw.spawn = Some(spawn_names(&["ssh"]));
        raw.exec = [("git".to_string(), node(&["gpg"]))].into_iter().collect();
        let e = validate(raw).unwrap_err();
        assert!(e.contains("is the command itself"), "{e}");
    }

    // A deeper section arrives as an unknown key holding a table. Unknown keys are ignored by
    // design, so it has to be refused explicitly or a whole addressing scheme would parse into
    // silence — and a node addresses a program, wherever that program was reached from.
    #[test]
    fn a_deeper_section_is_refused_rather_than_ignored() {
        let mut raw = raw_task();
        raw.spawn = Some(spawn_names(&["git"]));
        let mut deeper = node(&["ssh"]);
        deeper
            .rest
            .insert("ssh".to_string(), crate::config::schema::RawIgnored);
        raw.exec = [("git".to_string(), deeper)].into_iter().collect();
        let e = validate(raw).unwrap_err();
        assert!(e.contains("nothing deeper to address"), "{e}");
    }

    // A node allowing nothing is what having no node already means.
    #[test]
    fn an_empty_node_is_refused() {
        let mut raw = raw_task();
        raw.spawn = Some(spawn_names(&["git"]));
        raw.exec = [("git".to_string(), node(&[]))].into_iter().collect();
        let e = validate(raw).unwrap_err();
        assert!(e.contains("allows nothing"), "{e}");
    }

    // Allowing everything is what leaving the key out already means. Two spellings of one thing
    // would make the declaration say nothing about whether its author considered the question.
    #[test]
    fn a_wildcard_spawn_is_refused() {
        for wildcard in ["*", "**"] {
            let mut raw = raw_task();
            raw.spawn = Some(spawn_names(&[wildcard]));
            let e = validate(raw).unwrap_err();
            assert!(
                e.contains("remove the key"),
                "`{wildcard}` must be refused with the alternative: {e}"
            );
        }
    }

    // `{out}` is filled by sbx, not by the caller — so a parameter of that name would be a caller
    // choosing where a credential-bearing command writes. Reserved, and said as such.
    #[test]
    fn a_parameter_cannot_be_named_out() {
        let mut raw = raw_task();
        raw.params.insert(
            "out".to_string(),
            crate::config::schema::RawTaskParam::Pattern("^.+$".into()),
        );
        raw.cmd.push("{out}".into());
        let e = validate(raw).unwrap_err();
        assert!(e.contains("reserved"), "{e}");
    }

    // `{out}` without `output` would substitute from nothing. Refused at load, where the author can
    // still act on it, rather than at the invocation with an unexplainable message.
    #[test]
    fn the_out_placeholder_needs_the_output_declaration() {
        let mut raw = raw_task();
        raw.cmd.push("{out}/dump.sql".into());
        let e = validate(raw.clone()).unwrap_err();
        assert!(e.contains("declares no `output`"), "{e}");

        raw.output = true;
        let task = validate(raw).expect("with output declared it is fine");
        assert!(task.output);
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
                sign: None,
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
            &TaskOrigin::Project,
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

    /// The fold reports where an operation was **declared**, never the layer that merged it. The
    /// merge names itself in the warning ("app overlay") and that string is one `origin: source`
    /// away from erasing exactly what this field exists to carry.
    #[test]
    fn folding_a_task_onto_the_baseline_keeps_where_it_was_declared() {
        let mut out = Vec::new();
        let mut warnings = Vec::new();
        let mut task = validate(raw_task()).unwrap();
        task.origin = TaskOrigin::Bundle("psql".to_string());
        upsert_task(&mut out, &mut warnings, "app overlay", task);
        assert_eq!(out[0].origin, TaskOrigin::Bundle("psql".to_string()));
        assert_eq!(out[0].origin.label(), "bundle:psql");
    }

    /// An operation really is composed of two layers: its own block, plus whatever `[task.defaults]`
    /// it inherits. Naming only the block would send a reader to a file that does not contain the
    /// value they are looking at — so a ceiling the block does not set carries where it came from.
    #[test]
    fn a_ceiling_the_task_does_not_set_says_which_layer_it_came_from() {
        let defaults = TaskDefaults::default().merged_with(
            &RawTaskDefaults {
                timeout: Some("90s".into()),
                max_output: None,
                nonce: None,
            },
            &TaskLayer {
                source: "sbx.toml",
                origin: TaskOrigin::Global,
            },
            &mut Vec::new(),
        );

        // Declared in the project, but its timeout is the global config's and its output cap is
        // sbx's own — three layers behind one operation, which is the whole point of the field.
        let inherited = validate_task(
            "db-query",
            raw_task(),
            &TaskOrigin::Project,
            &defaults,
            &SecretDefaults::default(),
            &PluginRegistry::default(),
        )
        .expect("valid");
        assert_eq!(inherited.origin, TaskOrigin::Project);
        assert_eq!(
            inherited.timeout_from.label().as_deref(),
            Some("global [task.defaults]")
        );
        assert_eq!(
            inherited.max_output_from.label().as_deref(),
            Some("sbx default")
        );

        // A task that sets its own says nothing: repeating "declared here" is what a reader already
        // assumes, and `label()` returning `None` is what drops the row.
        let own = validate_task(
            "db-query",
            RawTask {
                timeout: Some("10s".into()),
                max_output: Some("1KiB".into()),
                ..raw_task()
            },
            &TaskOrigin::Project,
            &defaults,
            &SecretDefaults::default(),
            &PluginRegistry::default(),
        )
        .expect("valid");
        assert_eq!(own.timeout, std::time::Duration::from_secs(10));
        assert_eq!(own.timeout_from.label(), None);
        assert_eq!(own.max_output_from.label(), None);
    }

    /// Each layer stamps its own, and a bundle's stamp survives the fold that made its entry look
    /// like the app's own.
    #[test]
    fn each_layer_stamps_the_operations_it_declares() {
        let cases = [
            (TaskOrigin::Global, None, "global"),
            (TaskOrigin::Project, None, "project"),
            (TaskOrigin::App("agent".into()), None, "app:agent"),
            // The app layer is what validates a bundle's entry, and the stamp still wins.
            (TaskOrigin::App("agent".into()), Some("psql"), "bundle:psql"),
        ];
        for (origin, from_bundle, expected) in cases {
            let raw = RawTask {
                from_bundle: from_bundle.map(str::to_string),
                ..raw_task()
            };
            let task = validate_task(
                "db-query",
                raw,
                &origin,
                &TaskDefaults::default(),
                &SecretDefaults::default(),
                &PluginRegistry::default(),
            )
            .expect("valid");
            assert_eq!(task.origin.label(), expected);
        }
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
            &TaskLayer {
                source: "global config",
                origin: TaskOrigin::Global,
            },
            &mut warnings,
        );
        assert_eq!(merged.timeout, std::time::Duration::from_secs(300));
        assert_eq!(merged.max_output, 1024 * 1024);
        assert!(warnings.is_empty());
        // And each ceiling remembers the layer that set it, which is not the layer a task inheriting
        // it was declared in.
        assert_eq!(
            merged.timeout_from,
            Ceiling::Defaults(TaskOrigin::Global),
            "a ceiling knows which `[task.defaults]` set it"
        );

        let kept = merged.merged_with(
            &RawTaskDefaults {
                timeout: Some("nope".into()),
                nonce: None,
                max_output: Some("0".into()),
            },
            &TaskLayer {
                source: ".sbx.toml",
                origin: TaskOrigin::Project,
            },
            &mut warnings,
        );
        assert_eq!(kept.timeout, merged.timeout, "a bad value keeps the prior");
        assert_eq!(kept.max_output, merged.max_output);
        assert_eq!(warnings.len(), 2, "both are reported: {warnings:?}");
        assert_eq!(
            kept.timeout_from,
            Ceiling::Defaults(TaskOrigin::Global),
            "a refused value leaves the earlier layer's, provenance included — the value shown and \
             the layer named must never come apart"
        );
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
