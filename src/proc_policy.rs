//! The process/exec policy: what an in-cage agent is allowed to `execve`, and the pure verdict a
//! parked syscall is decided against.
//!
//! This is the exec analogue of [`crate::allowlist`]'s `EgressPolicy`: a pure, I/O-free matcher that a
//! trusted config resolves into and that the host-side enforcement supervisor
//! ([`crate::sandbox::proc_enforce`]) consults for every notified `execve`. Keeping it pure means the
//! matching semantics — which are security-relevant — are unit-tested without a cage.
//!
//! ## Posture (denylist, deny-wins)
//!
//! The default posture is a **denylist**: everything is allowed except an explicit `deny` entry, so a
//! coding agent that spawns constantly is not bricked while specific dangerous binaries (`curl`,
//! `ssh`, …) are blocked *before the syscall runs*. `deny` always wins over `allow` (an entry in both
//! is denied), mirroring the egress rule. The two enforcing modes differ only in what an **unmatched**
//! target does: [`Enforce`](ProcMode::Enforce) allows it (static denylist), [`Ask`](ProcMode::Ask)
//! parks it for an interactive decision.
//!
//! ## Rule grammar
//!
//! A rule is a shell-style glob (`*` = any run, `?` = one character). A rule containing `/` matches
//! the **full exec path** (`/usr/bin/*`, `/nix/store/*/bin/git`); a rule without `/` matches the
//! target's **basename** (`curl` matches `/usr/bin/curl`), so a tool is named the way a user thinks of
//! it. Matching is exact otherwise — `curl` never matches `curlish`.
//!
//! ## The spelling a rule is matched against
//!
//! Both sides are folded to their canonical spelling before anything is compared ([`lexical_path`]):
//! `//` collapses, `.` drops out, and `..` folds into the component before it. The kernel resolves
//! the bytes an `execve` carries before it runs anything, so a matcher fed the raw spelling answers
//! about a path that is not the one that runs — and it does so in both directions. An allowlist
//! entry `/nix/store/*/bin/cc` matches `/nix/store/../../tmp/evil/bin/cc`, because `*` carries no
//! path-separator meaning and swallows the `..` run, while the kernel runs `/tmp/evil/bin/cc`; and a
//! `deny` on `/usr/bin/*` misses `//usr/bin/curl` and `/tmp/../usr/bin/curl`, which the kernel folds
//! straight back onto `/usr/bin/curl`.
//!
//! Two things the folding is not. It resolves **no symlink** — a component that is one makes the
//! lexical answer differ from the kernel's — so a path rule speaks about a spelling and never about
//! an inode. And a **relative** target stays relative: it is matched as the process spelled it,
//! which is what lets a declaration name `./build.sh` and have it match, and it means an absolute
//! path rule says nothing about a target reached by `chdir` plus a bare name. A rule that must hold
//! wherever its program is spelled from is a basename rule, which is the form to reach for: sbx
//! ships no `[proc]` rules of its own, so there is no worked example to copy, and this is the
//! sentence that stands in for one.

/// The process/exec lens mode, resolved from `[proc] mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ProcMode {
    /// The lens is disabled — no capture, no enforcement.
    #[default]
    Off,
    /// Capture only (the cheap `/proc` poll), no enforcement. The exec feed may miss a command shorter
    /// than a poll tick; blocking is not in effect.
    Observe,
    /// Enforce a static denylist via the seccomp user-notification supervisor: `deny` targets return
    /// `EPERM` (the syscall never runs), everything else is allowed.
    Enforce,
    /// Enforce interactively: `deny` targets return `EPERM`, `allow` targets run, and an **unmatched**
    /// target is parked for a live `sbx proc allow`/`deny` decision.
    Ask,
    /// Enforce a strict **allowlist**: only an `allow` match runs; anything unmatched is refused. The
    /// inverse posture of [`Enforce`](ProcMode::Enforce), for a cage whose whole program set is known
    /// up front — a declared task's, where the command is fixed and what it may run is declared beside
    /// it. Not reachable from `[proc] mode`: a posture that refuses everything undeclared is only
    /// honest where the declaration enumerates the programs, which a general agent's does not.
    Confine,
}

impl ProcMode {
    /// Parse the `[proc] mode` string. An unknown value fails closed to [`Off`](ProcMode::Off) with
    /// `None`, so the caller can warn — an unrecognised posture must never silently enforce or
    /// silently disable in a surprising direction.
    pub(crate) fn parse(s: &str) -> Option<ProcMode> {
        match s {
            "off" => Some(ProcMode::Off),
            "observe" => Some(ProcMode::Observe),
            "enforce" => Some(ProcMode::Enforce),
            "ask" => Some(ProcMode::Ask),
            _ => None,
        }
    }

    /// The canonical string for this mode, used by `sbx config show` and the one-shot override
    /// display. Every mode a config can *write* round-trips [`parse`](ProcMode::parse);
    /// [`Confine`](ProcMode::Confine) deliberately does not, because it has no config spelling — it
    /// is reached only by a declaration that enumerates the programs it admits. Adding it to `parse`
    /// would offer a refuse-everything-undeclared posture to a config that cannot say what the
    /// exceptions are.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ProcMode::Off => "off",
            ProcMode::Observe => "observe",
            ProcMode::Enforce => "enforce",
            ProcMode::Ask => "ask",
            ProcMode::Confine => "confine",
        }
    }

    /// Whether this mode stands up the seccomp user-notification enforcement path (the in-cage shim +
    /// host supervisor). `enforce`, `ask` and `confine` do; `off`/`observe` do not.
    pub(crate) fn enforcing(self) -> bool {
        matches!(self, ProcMode::Enforce | ProcMode::Ask | ProcMode::Confine)
    }
}

/// One compiled exec rule: the raw text (kept for display), the pattern the match is performed
/// against, and whether it matches the full path or a basename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcRule {
    raw: String,
    /// The raw text folded to its canonical spelling, which is what a target is compared against.
    /// Kept beside the raw text rather than replacing it, because the raw text is what its author
    /// wrote and what `sbx config show` and the control wire echo back.
    ///
    /// Folded for the same reason a target is: the two sides have to meet on one spelling, and a
    /// declared entry carrying a `/` reaches here exactly as it was written. A rule `./build.sh`
    /// would otherwise stop matching the target the kernel resolves to the same file.
    pattern: String,
    /// A rule with a `/` matches the whole exec path; without one, it matches the target's basename.
    /// Read from the raw text, so folding a rule down to a single component never quietly turns a
    /// path rule into a basename rule that would admit that name anywhere.
    on_path: bool,
}

impl ProcRule {
    /// Compile a rule string. Always succeeds (there is no invalid glob — an unbalanced `*` just
    /// matches literally); an empty string is a rule that never matches (the config layer drops empties
    /// before they get here, but the matcher stays total).
    pub(crate) fn new(raw: &str) -> ProcRule {
        ProcRule {
            raw: raw.to_string(),
            pattern: lexical_path(raw).into_owned(),
            on_path: raw.contains('/'),
        }
    }

    /// The raw rule text, for `sbx config show` / the wire.
    pub(crate) fn as_str(&self) -> &str {
        &self.raw
    }

    /// Whether this rule matches an exec target. A path rule globs the whole `path`; a basename rule
    /// globs the final component.
    ///
    /// Both sides arrive already folded — the pattern at compile time, the target in
    /// [`ProcPolicy::decide_chain`] — so what is decided is the path the kernel will resolve rather
    /// than the one the cage happened to spell.
    fn matches(&self, path: &str, basename: &str) -> bool {
        let subject = if self.on_path { path } else { basename };
        glob_match(&self.pattern, subject)
    }
}

/// Validate a rule string before it is persisted to a config file or injected into a live session.
/// [`ProcRule::new`] is total (any string compiles), so this is the fail-closed gate the write and
/// `--session` paths share: a rule must be non-empty after trimming and carry no control character —
/// a newline would break the line-based control-socket framing, and a control byte has no place in an
/// exec path or basename — and stay within a sane length. Returns a human reason on refusal.
pub(crate) fn validate_rule(rule: &str) -> Result<(), String> {
    let trimmed = rule.trim();
    if trimmed.is_empty() {
        return Err("a rule must not be empty".to_string());
    }
    if trimmed.chars().any(char::is_control) {
        return Err("a rule must not contain control characters (including newlines)".to_string());
    }
    const MAX: usize = 256;
    if trimmed.chars().count() > MAX {
        return Err(format!("a rule must be at most {MAX} characters"));
    }
    Ok(())
}

/// The pure verdict for one exec target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Allow the `execve` (the supervisor answers `CONTINUE`).
    Allow,
    /// Deny the `execve` (the supervisor answers `EPERM`; the syscall never runs).
    Deny,
    /// Park the `execve` for an interactive decision (only reachable under [`ProcMode::Ask`]).
    Ask,
}

impl Verdict {
    /// The stricter of two verdicts about the same `execve`, for a syscall that has more than one
    /// name to be decided under.
    ///
    /// One `execve` carries one path, but an explicitly invoked dynamic loader runs a program its
    /// own arguments name ([`loader_targets`]), and both are the policy's to speak about. The order
    /// is refuse, then ask, then allow: a `deny` on either name stops the call, and a name that
    /// would be put to a person is put to them rather than let through on the strength of the
    /// other. It is the same precedence [`ProcPolicy::decide_chain`] applies between the `deny` and
    /// `allow` sets, and for the same reason.
    pub(crate) fn stricter(self, other: Verdict) -> Verdict {
        match (self, other) {
            (Verdict::Deny, _) | (_, Verdict::Deny) => Verdict::Deny,
            (Verdict::Ask, _) | (_, Verdict::Ask) => Verdict::Ask,
            (Verdict::Allow, Verdict::Allow) => Verdict::Allow,
        }
    }
}

/// The resolved process/exec policy: the mode plus the classified allow/deny rules. Pure — the
/// enforcement supervisor calls [`decide`](ProcPolicy::decide) for every notified `execve`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ProcPolicy {
    pub(crate) mode: ProcMode,
    pub(crate) allow: Vec<ProcRule>,
    pub(crate) deny: Vec<ProcRule>,
    /// Present when what may run depends on **who is running it**. Absent is the flat model, where
    /// one set governs the whole cage at any depth.
    pub(crate) graph: Option<CallerGraph>,
}

/// What each program may run, keyed by the program doing the running.
///
/// The key is the caller's executable as `/proc/<pid>/exe` reports it — an absolute in-cage path
/// with every symlink already followed, since that is what the kernel records. A program with no
/// entry may run **nothing**: there is no inheritance from whoever ran it, because inheritance would
/// hand back the very shortcut a graph exists to remove.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct CallerGraph {
    pub(crate) callers: std::collections::BTreeMap<String, Vec<ProcRule>>,
}

impl ProcPolicy {
    /// A disabled policy (the default when `[proc]` is absent).
    pub(crate) fn off() -> ProcPolicy {
        ProcPolicy {
            mode: ProcMode::Off,
            allow: Vec::new(),
            deny: Vec::new(),
            graph: None,
        }
    }

    /// Whether this policy can refuse anything at all.
    ///
    /// True for the one shape a launch takes when only the **content lens** asked for a supervisor:
    /// `[proc]` is off, and the exec side is built as an `enforce` denylist with nothing on it so
    /// that every `execve` is notified and allowed. Nothing there can decide a second program, so
    /// the reads that would find one are not worth taking -- and a refusal formed on a read that
    /// failed would stop a program no rule speaks about. `ask` and `confine` are never this: the
    /// first parks an unmatched target and the second refuses it, both of which are decisions.
    pub(crate) fn governs_nothing(&self) -> bool {
        self.mode == ProcMode::Enforce
            && self.allow.is_empty()
            && self.deny.is_empty()
            && self.graph.is_none()
    }

    /// A per-caller allowlist: an unmatched target is refused, and what is matched depends on which
    /// program is doing the running.
    pub(crate) fn confined(graph: CallerGraph) -> ProcPolicy {
        ProcPolicy {
            mode: ProcMode::Confine,
            allow: Vec::new(),
            deny: Vec::new(),
            graph: Some(graph),
        }
    }

    /// Build a policy from a mode and raw allow/deny rule strings, dropping empty entries.
    pub(crate) fn new(mode: ProcMode, allow: &[String], deny: &[String]) -> ProcPolicy {
        let compile = |rules: &[String]| {
            rules
                .iter()
                .filter(|r| !r.trim().is_empty())
                .map(|r| ProcRule::new(r.trim()))
                .collect()
        };
        ProcPolicy {
            mode,
            allow: compile(allow),
            deny: compile(deny),
            graph: None,
        }
    }

    /// Whether enforcement is in effect (`enforce`/`ask`).
    pub(crate) fn enforcing(&self) -> bool {
        self.mode.enforcing()
    }

    /// Decide one exec target. Deny-wins: a `deny` match is [`Deny`](Verdict::Deny) even if `allow`
    /// also matches. Otherwise an `allow` match is [`Allow`](Verdict::Allow). An **unmatched** target
    /// is [`Allow`](Verdict::Allow) under `enforce` (the denylist default), [`Ask`](Verdict::Ask)
    /// under `ask`, and [`Deny`](Verdict::Deny) under `confine` (the allowlist default); under a
    /// non-enforcing mode it is [`Allow`](Verdict::Allow) (decide is never called there, but the
    /// fallback is the safe, non-blocking one).
    pub(crate) fn decide(&self, caller: &[String], exec_path: &str) -> Verdict {
        self.decide_chain(caller, exec_path, &[], &[])
    }

    /// Decide one exec target for a caller addressed by its chain of programs, innermost **last**,
    /// folding in a live `--session` overlay's extra allow/deny rules on top of this config policy.
    /// **Deny wins across both sets**: an overlay `deny` cuts a config-allowed target, and a config
    /// `deny` cannot be overridden by an overlay `allow`.
    ///
    /// Under a [`CallerGraph`] only the last element is read — a node addresses a program, wherever
    /// that program was reached from. The whole chain is taken rather than the one program it uses,
    /// so that a chain-scoped address could be added without touching a single call site: an address
    /// that grows is a slice that grows.
    ///
    /// An **empty** chain against a graph matches nothing, which under `confine` is a refusal. That
    /// is the wanted answer for a caller whose program could not be read: the one execve that must
    /// not run is the one nothing can account for.
    ///
    /// The target is folded to its canonical spelling here, at the one gate every rule set passes
    /// through — the config's, the graph's and the live overlay's — so no caller can decide against
    /// a spelling the kernel will re-resolve. See [`lexical_path`] and the module's rule grammar.
    pub(crate) fn decide_chain(
        &self,
        caller: &[String],
        exec_path: &str,
        overlay_allow: &[ProcRule],
        overlay_deny: &[ProcRule],
    ) -> Verdict {
        let exec_path = lexical_path(exec_path);
        let basename = basename(&exec_path);
        let any = |rules: &[ProcRule]| rules.iter().any(|r| r.matches(&exec_path, basename));
        if any(&self.deny) || any(overlay_deny) {
            return Verdict::Deny;
        }
        if let Some(graph) = &self.graph {
            // Only the caller's own node answers. An overlay `allow` is deliberately not folded in
            // here: it arrives from a live control plane, and a per-caller policy is a task's, whose
            // plane has no such channel — while an overlay `deny`, decided above, still cuts.
            let allowed = caller.last().and_then(|c| graph.callers.get(c.as_str()));
            return match allowed {
                Some(rules) if any(rules) => Verdict::Allow,
                _ => self.unmatched(),
            };
        }
        if any(&self.allow) || any(overlay_allow) {
            return Verdict::Allow;
        }
        self.unmatched()
    }

    /// The verdict for a target no rule spoke about. Exhaustive on purpose: this default is the whole
    /// difference between a denylist and an allowlist, so a new posture must state its own rather
    /// than inherit a catch-all.
    pub(crate) fn unmatched(&self) -> Verdict {
        match self.mode {
            ProcMode::Ask => Verdict::Ask,
            ProcMode::Confine => Verdict::Deny,
            ProcMode::Off | ProcMode::Observe | ProcMode::Enforce => Verdict::Allow,
        }
    }
}

/// Whether a file **name** is a dynamic loader -- the program interpreter an ELF binary is started
/// by, and the one program whose own command line names another program to run.
///
/// Asked of a basename, because that is what identifies a loader wherever a userland puts it: a nix
/// closure keeps it under `/nix/store/…-glibc-…/lib/`, a distro image under `/lib64` or
/// `/lib/<triple>/`, and both spell it the same way. The shapes are glibc's
/// (`ld-linux-x86-64.so.2`, `ld-linux-aarch64.so.1`), musl's (`ld-musl-x86_64.so.1`), and the bare
/// `ld.so`/`ld.so.1` some architectures ship -- an `ld-` or `ld.so` prefix together with a `.so`,
/// which is narrow enough that `ldconfig` and `ld` itself are not loaders here.
pub(crate) fn is_dynamic_loader(basename: &str) -> bool {
    basename.contains(".so") && (basename.starts_with("ld-") || basename.starts_with("ld.so"))
}

/// The options a dynamic loader accepts that take a **value** in the following word.
///
/// glibc's `rtld` and musl's `ldso` compare whole words, so neither accepts a `--option=value`
/// spelling: the value is always the next element. Measured on glibc 2.43, `--library-path=/x` is
/// answered with "unrecognized option" while `--library-path /x` runs. That is what makes the value
/// a word the walk below must step over rather than read as the program -- otherwise
/// `ld.so --library-path /x /usr/bin/curl` would be decided as `/x`.
const LOADER_VALUE_OPTIONS: &[&[u8]] = &[
    b"--library-path",
    b"--preload",
    b"--audit",
    b"--argv0",
    b"--inhibit-rpath",
    b"--glibc-hwcaps-prepend",
    b"--glibc-hwcaps-mask",
];

/// The options that take no value, so the word after one may be the program.
const LOADER_FLAGS: &[&[u8]] = &[
    b"--list",
    b"--verify",
    b"--inhibit-cache",
    b"--list-tunables",
    b"--list-diagnostics",
    b"--help",
    b"--version",
];

/// The programs a dynamic loader named on the command line would load, read from its own `argv`.
///
/// `execve("/lib64/ld-linux-x86-64.so.2", ["…", "/usr/bin/curl"], …)` is **one** syscall. The kernel
/// runs the loader, and the loader maps and enters `curl` inside that same call, so nothing further
/// is notified: a policy that reads only the notified path decides about the loader and never about
/// the program. Both are decided here, and the caller takes the stricter answer, so a `deny` on a
/// program holds whether or not an interpreter was named in front of it.
///
/// **The walk.** `argv[0]` is the loader's own name and is skipped. From there: a word beginning
/// with `--` is an option (both loaders test exactly that, so a single-dash word is a *program*
/// name and is classified as one -- measured, `ld.so -x /bin/true` reports "cannot open shared
/// object file `-x`"); a `--` on its own ends the options and the next word is the program; an
/// option in [`LOADER_VALUE_OPTIONS`] takes the following word with it. The first word that is
/// none of those is the program, and the walk stops there -- what follows are the program's own
/// arguments, and classifying those would refuse `ld.so /bin/grep curl` for a `deny` on `curl`.
///
/// **Where the walk stops being sure.** An option neither list names is one this build does not
/// know. If it takes a value in the loader the cage actually runs, the word after it is that value
/// and the program is further along -- so from an unknown option onwards *every* non-option word is
/// classified, and the walk does not stop at the first. That is the arm that costs precision, and
/// it is entered only where precision was already gone.
///
/// `None` means the question was not settled, and the caller refuses on it: a name that is not
/// valid UTF-8 (the policy matches `String`s, and a name it cannot carry is one no rule can speak
/// about), or an argument list that ran past what the supervisor read (`complete` is false) without
/// the walk having concluded. `Some(<empty>)` is the settled answer that the loader names no
/// program at all -- `ld.so --version`, or a value option with nothing after it -- where the loader
/// prints its usage and runs nothing, and the executed path's own verdict stands alone.
pub(crate) fn loader_targets(argv: &[&[u8]], complete: bool) -> Option<Vec<String>> {
    let name = |w: &[u8]| std::str::from_utf8(w).ok().map(str::to_string);
    let mut out: Vec<String> = Vec::new();
    let mut uncertain = false;
    let mut concluded = false;
    let mut i = 1;
    while i < argv.len() {
        let word = argv[i];
        if word == b"--" {
            if let Some(program) = argv.get(i + 1) {
                out.push(name(program)?);
                concluded = true;
            }
            break;
        }
        if word.starts_with(b"--") {
            if LOADER_VALUE_OPTIONS.contains(&word) {
                i += 2;
                continue;
            }
            if !LOADER_FLAGS.contains(&word) {
                uncertain = true;
            }
            i += 1;
            continue;
        }
        out.push(name(word)?);
        if !uncertain {
            concluded = true;
            break;
        }
        i += 1;
    }
    // Running off the end of a list that was itself cut short says nothing: the program may be in
    // the part that was not read. Refusing is safe here in a way allowing is not -- the syscall
    // never runs on a refusal.
    if !concluded && !complete {
        return None;
    }
    Some(out)
}

/// How many bytes of a file's start decide whether it is a script, and which interpreter it names.
///
/// `BINPRM_BUF_SIZE`, the whole of what the kernel itself reads before it makes that decision, so
/// reading the same amount is what makes this walk answer the kernel's question rather than a
/// smaller one: measured, a `#!` line longer than this is **truncated and still run**, so a walk
/// that stopped at the first newline it found in fewer bytes would disagree with the exec it is
/// deciding.
pub(crate) const SCRIPT_HEAD: usize = 256;

/// What the first bytes of an `execve` target say about a second program running inside that call.
///
/// Three states and not two, because "no interpreter" is two different answers to the caller. A file
/// that is not a script names no second program and its own path's verdict stands alone; a `#!` line
/// this walk could not settle names one it cannot put to a rule, and is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScriptHead {
    /// The first two bytes are not `#!`, so the kernel runs the file itself and nothing else.
    NotScript,
    /// The absolute path of the interpreter the kernel will run instead of the named file.
    Interpreter(String),
    /// A `#!` line that is there and cannot be turned into a name a rule could speak about.
    Unsettled,
}

/// The interpreter a `#!` line names, read from the first [`SCRIPT_HEAD`] bytes of an exec target.
///
/// `execve("./script")` on a file whose first two bytes are `#!` is a *single* syscall that runs a
/// *different* program: the kernel reads the line, and executes the interpreter it names with the
/// script's path appended. A supervisor deciding on the notified path alone therefore decides
/// `./script` and never `/bin/sh`, which is the rule the cage was reaching around. So the line is
/// read and the interpreter decided too, on the stricter of the two verdicts.
///
/// The grammar is the kernel's, measured rather than assumed:
///
/// * The line ends at the first `\n` **or** `\0`; a NUL cuts it exactly as a newline does.
/// * Spaces and tabs between `#!` and the path are skipped.
/// * At most one argument follows, and it is **not** judged -- the same rule
///   [`loader_targets`] states for a loader's arguments. `#!/usr/bin/env python3` is decided as
///   `/usr/bin/env`, so a payload carried in that argument runs only under an interpreter a rule
///   already allows.
///
/// [`ScriptHead::Unsettled`] is the answer wherever the name a rule would match cannot be
/// established, and the caller refuses on it: an empty interpreter, one that is not valid UTF-8 (the
/// policy matches `String`s), a **relative** path (the kernel execs it against a working directory
/// this walk does not resolve), or a word running to the end of a head that was itself cut short --
/// where the path may continue in bytes neither the kernel nor this read has.
pub(crate) fn shebang_interpreter(head: &[u8]) -> ScriptHead {
    let Some(line) = head.strip_prefix(b"#!") else {
        return ScriptHead::NotScript;
    };
    // A head filled to the ceiling may be the start of a longer line, which is what makes a word
    // ending at its edge undecidable below. A shorter one is the whole file, so its end is a real
    // end of line.
    let truncated = head.len() >= SCRIPT_HEAD;
    let terminator = line.iter().position(|b| *b == b'\n' || *b == 0);
    // Whether what follows is a whole line: one the file ended, or one a terminator closed. A head
    // filled to the ceiling with neither is a line that may go on in bytes this read does not have.
    let ended = terminator.is_some() || !truncated;
    let line = match terminator {
        Some(end) => &line[..end],
        None => line,
    };
    let rest = &line[line
        .iter()
        .position(|b| *b != b' ' && *b != b'\t')
        .unwrap_or(line.len())..];
    let word = &rest[..rest
        .iter()
        .position(|b| *b == b' ' || *b == b'\t')
        .unwrap_or(rest.len())];
    // A word the head's own edge ended is a word that may go on in bytes this read does not have.
    if word.is_empty() || (!ended && word.len() == rest.len()) {
        return ScriptHead::Unsettled;
    }
    match std::str::from_utf8(word) {
        Ok(path) if path.starts_with('/') => {
            ScriptHead::Interpreter(lexical_path(path).into_owned())
        }
        _ => ScriptHead::Unsettled,
    }
}

/// One `binfmt_misc` handler: an interpreter the kernel runs for files it recognises.
///
/// `binfmt_misc` lets a userland enrol an interpreter for a shape of file, and the kernel then runs
/// that interpreter inside the `execve` that named the file -- the same single-syscall substitution
/// a `#!` line performs, except that **nothing in the file names the interpreter**. A `.jar`, a
/// `.py` with no `#!`, a wine binary or a foreign-architecture ELF under `qemu` all reach their
/// interpreter this way, and a rule about that interpreter is not consulted unless the handler is
/// read as well.
///
/// Registered globally in the kernel rather than per namespace, so what this process reads under
/// `/proc/sys/fs/binfmt_misc` is what a cage's own `execve` will meet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BinfmtRule {
    /// The program the kernel runs instead of the named file.
    pub(crate) interpreter: String,
    /// Where in the file the magic starts.
    offset: usize,
    /// The bytes a file must carry at `offset`. Empty for an extension handler.
    magic: Vec<u8>,
    /// Bits that matter in the comparison, byte for byte with `magic`. Empty means all of them.
    mask: Vec<u8>,
    /// The trailing name component a file must have, without its dot. Empty for a magic handler.
    extension: String,
}

/// One handler as the kernel prints it under `/proc/sys/fs/binfmt_misc/<name>`.
///
/// The shape is fixed: a first line of `enabled` or `disabled`, then `interpreter <path>`, `flags:`,
/// and either `offset`/`magic` (with an optional `mask`) or `extension <ext>`. `magic` and `mask`
/// are printed as hex pairs whatever the bytes are, so both are read that way.
///
/// `None` for a handler this walk cannot act on: one the kernel has disabled, one naming no
/// interpreter, or one whose match this build does not understand -- where reading it as "matches
/// nothing" is the honest answer, since the alternative is a rule that silently covers less than it
/// claims.
pub(crate) fn parse_binfmt_rule(text: &str) -> Option<BinfmtRule> {
    let unhex = |s: &str| -> Option<Vec<u8>> {
        let s = s.trim();
        (s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| {
                (0..s.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
                    .collect::<Option<Vec<u8>>>()
            })
            .flatten()
    };
    let mut rule = BinfmtRule {
        interpreter: String::new(),
        offset: 0,
        magic: Vec::new(),
        mask: Vec::new(),
        extension: String::new(),
    };
    let mut enabled = false;
    for line in text.lines() {
        let line = line.trim();
        match line.split_once(' ') {
            _ if line == "enabled" => enabled = true,
            Some(("interpreter", v)) => rule.interpreter = v.trim().to_string(),
            Some(("offset", v)) => rule.offset = v.trim().parse().ok()?,
            Some(("magic", v)) => rule.magic = unhex(v)?,
            Some(("mask", v)) => rule.mask = unhex(v)?,
            Some(("extension", v)) => rule.extension = v.trim().to_string(),
            _ => {}
        }
    }
    let matches_something = !rule.magic.is_empty() || !rule.extension.is_empty();
    (enabled && !rule.interpreter.is_empty() && matches_something).then_some(rule)
}

/// The interpreter a registered handler would run for this file, if any recognises it.
///
/// Asked only of a file that is **not** a script and not an ordinary executable this kernel would
/// load itself: `binfmt_misc` is tried after the built-in formats, so an `execve` that ELF or the
/// `#!` handler accepts never reaches one of these.
///
/// Every handler that matches is returned rather than the first, because the order the kernel tries
/// them in is not the order they are read in here, and deciding the union is the answer that cannot
/// be less strict than the kernel's own. A handler with a `mask` compares only the bits the mask
/// names; one with an `extension` compares the file's trailing name component, case-sensitively, as
/// the kernel does.
pub(crate) fn binfmt_interpreters<'a>(
    rules: &'a [BinfmtRule],
    head: &[u8],
    path: &str,
) -> Vec<&'a str> {
    let extension = path.rsplit('/').next().and_then(|n| n.rsplit_once('.'));
    rules
        .iter()
        .filter(|rule| {
            if !rule.extension.is_empty() {
                return extension.is_some_and(|(_, ext)| ext == rule.extension);
            }
            let Some(window) = head.get(rule.offset..rule.offset + rule.magic.len()) else {
                return false;
            };
            window
                .iter()
                .zip(&rule.magic)
                .enumerate()
                .all(|(i, (a, b))| {
                    let bits = rule.mask.get(i).copied().unwrap_or(0xff);
                    a & bits == b & bits
                })
        })
        .map(|rule| rule.interpreter.as_str())
        .collect()
}

/// The final path component (the basename), or the whole string when there is no `/`. Taken from an
/// already-folded path ([`lexical_path`]), which carries no trailing slash and no `.` of its own, so
/// the component this returns is the file the target names. Total for any other input too: a string
/// ending in `/` yields an empty basename, which matches no non-empty rule.
pub(crate) fn basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// A path spelled the way the kernel will resolve it: `//` collapsed, `.` components dropped, and
/// each `..` folded into the component before it.
///
/// Every exec target passes through this before it meets a rule, and so does every rule's own
/// pattern, because a decision taken on the raw spelling is a decision about a different file — see
/// the module's rule grammar for both directions of that.
///
/// Purely lexical, in two senses that are the honest scope of the guard. It resolves no symlink:
/// this module is I/O-free, the path names a file inside a cage this process is not in, and a
/// component that *is* a link makes the kernel's answer differ from this one. And a relative path
/// stays relative, with any leading `..` kept — there is nothing here to fold it into, and the
/// working directory the kernel would resolve it against is not this module's to know.
///
/// `/..` is `/`, which is what the kernel does: the root is its own parent.
///
/// Borrowed back unchanged when there is nothing to fold, which is every target on the hot path of a
/// cage that is not trying anything.
pub(crate) fn lexical_path(path: &str) -> std::borrow::Cow<'_, str> {
    let absolute = path.starts_with('/');
    let body = if absolute { &path[1..] } else { path };
    if !path.is_empty()
        && !body
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return std::borrow::Cow::Borrowed(path);
    }
    let mut out: Vec<&str> = Vec::new();
    for part in body.split('/') {
        match part {
            // An empty part is a doubled separator (or a trailing one), and `.` names where it
            // already is.
            "" | "." => {}
            ".." => match out.last() {
                Some(&last) if last != ".." => {
                    out.pop();
                }
                _ if absolute => {}
                // `part` is the `".."` this arm matched: kept, because a relative path has nothing
                // above it to fold into.
                _ => out.push(part),
            },
            component => out.push(component),
        }
    }
    let mut folded = String::with_capacity(path.len());
    for part in &out {
        if absolute || !folded.is_empty() {
            folded.push('/');
        }
        folded.push_str(part);
    }
    if absolute && folded.is_empty() {
        folded.push('/');
    }
    std::borrow::Cow::Owned(folded)
}

/// A minimal shell-style glob match over bytes: `*` matches any run (including empty), `?` matches
/// exactly one character, everything else is literal. Iterative with backtracking (no recursion, so a
/// pathological pattern cannot blow the stack), O(pattern × text) worst case — the patterns here are
/// short, operator-authored config, so this is ample.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    // The last `*` seen and the text position to resume from if a later mismatch forces backtracking.
    let mut star: Option<usize> = None;
    let mut resume = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            resume = ti;
            pi += 1; // try matching `*` as empty first
        } else if let Some(s) = star {
            // Mismatch under an open `*`: let it swallow one more text char and retry.
            pi = s + 1;
            resume += 1;
            ti = resume;
        } else {
            return false;
        }
    }
    // Trailing `*`s in the pattern match the empty remainder.
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(mode: ProcMode, allow: &[&str], deny: &[&str]) -> ProcPolicy {
        ProcPolicy::new(
            mode,
            &allow.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &deny.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
    }

    #[test]
    fn glob_matches_star_and_question_and_literals() {
        assert!(glob_match("curl", "curl"));
        assert!(!glob_match("curl", "curlish"));
        assert!(!glob_match("curl", "url"));
        assert!(glob_match("py*", "python3"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("/usr/bin/*", "/usr/bin/git"));
        assert!(!glob_match("/usr/bin/*", "/usr/local/bin/git"));
        assert!(glob_match(
            "/nix/store/*/bin/git",
            "/nix/store/abc-git/bin/git"
        ));
        assert!(glob_match("c?rl", "curl"));
        assert!(!glob_match("c?rl", "crl"));
        // A trailing star swallows the rest, including empty.
        assert!(glob_match("git*", "git"));
    }

    #[test]
    fn basename_rule_matches_the_final_component_only() {
        let deny = policy(ProcMode::Enforce, &[], &["curl"]);
        assert_eq!(deny.decide(&[], "/usr/bin/curl"), Verdict::Deny);
        assert_eq!(deny.decide(&[], "curl"), Verdict::Deny);
        // A basename rule does not match a same-named directory prefix.
        assert_eq!(deny.decide(&[], "/opt/curl/bin/wget"), Verdict::Allow);
    }

    #[test]
    fn path_rule_matches_the_whole_path() {
        let deny = policy(ProcMode::Enforce, &[], &["/usr/bin/*"]);
        assert_eq!(deny.decide(&[], "/usr/bin/ssh"), Verdict::Deny);
        assert_eq!(deny.decide(&[], "/usr/local/bin/ssh"), Verdict::Allow);
    }

    #[test]
    fn folding_a_path_stops_at_the_root_and_leaves_a_relative_one_relative() {
        // The two rules the kernel applies to the bytes an `execve` carries, and the two this
        // matcher has to apply with it: `..` folds into the component before it, and it stops at the
        // root rather than walking above it.
        assert_eq!(lexical_path("/nix/store/../../tmp/evil"), "/tmp/evil");
        assert_eq!(lexical_path("//usr//bin/curl"), "/usr/bin/curl");
        assert_eq!(lexical_path("/usr/bin/./curl"), "/usr/bin/curl");
        assert_eq!(lexical_path("/usr/bin/"), "/usr/bin");
        assert_eq!(lexical_path("/../.."), "/", "the root is its own parent");
        assert_eq!(lexical_path("/"), "/");
        // A relative target has nothing to fold a leading `..` into: the working directory the
        // kernel would resolve it against is not this module's to know, so it is kept.
        assert_eq!(lexical_path("a/../../b"), "../b");
        assert_eq!(lexical_path("./build.sh"), "build.sh");
        assert_eq!(lexical_path(""), "");
        // Already canonical: handed straight back, since this runs on every notified `execve`.
        assert!(matches!(
            lexical_path("/usr/bin/curl"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn a_crafted_spelling_is_decided_as_the_kernel_resolves_it_and_not_as_it_was_written() {
        // The target is the bytes the cage wrote, and the kernel folds them before it runs anything.
        // Deciding on the raw spelling therefore decides about a different file, in both directions.
        //
        // The allow direction is the severe one, and it needs only the rule form the docs' own
        // worked example uses: `*` carries no path-separator meaning, so it swallows a `..` run and
        // admits a program the rule never named.
        let confine = ProcPolicy::confined(CallerGraph {
            callers: std::collections::BTreeMap::from([(
                "/bin/sh".to_string(),
                vec![ProcRule::new("/nix/store/*/bin/cc")],
            )]),
        });
        let caller = ["/bin/sh".to_string()];
        assert_eq!(
            confine.decide(&caller, "/nix/store/abc-cc/bin/cc"),
            Verdict::Allow,
            "the declared program still runs"
        );
        assert_eq!(
            confine.decide(&caller, "/nix/store/../../tmp/evil/bin/cc"),
            Verdict::Deny,
            "the kernel runs /tmp/evil/bin/cc, which the allowlist never named"
        );

        // The deny direction: a path rule must not be walked around by respelling its subject.
        let deny = policy(ProcMode::Enforce, &[], &["/usr/bin/*", "/opt/tool"]);
        for spelled in [
            "//usr/bin/curl",
            "/usr/bin//curl",
            "/usr/bin/./curl",
            "/tmp/../usr/bin/curl",
        ] {
            assert_eq!(deny.decide(&[], spelled), Verdict::Deny, "`{spelled}`");
        }
        assert_eq!(deny.decide(&[], "/opt/./tool"), Verdict::Deny);
        // And folding invents no match: a program that really is somewhere else still runs.
        assert_eq!(deny.decide(&[], "/usr/local/bin/curl"), Verdict::Allow);
        assert_eq!(deny.decide(&[], "/opt/tool/helper"), Verdict::Allow);
    }

    #[test]
    fn a_rule_is_folded_like_its_target_and_still_displays_as_it_was_written() {
        // A declared entry carrying a `/` reaches the matcher exactly as its author wrote it, so a
        // task may name `./build.sh` and the cage may spell the same file either way. Folding the
        // target alone would leave that declaration refusing its own program under `confine`, which
        // is why both sides are folded — and why the raw text is kept beside the pattern rather than
        // replaced by it.
        let p = policy(ProcMode::Enforce, &[], &["./build.sh"]);
        assert_eq!(p.decide(&[], "./build.sh"), Verdict::Deny);
        assert_eq!(
            p.decide(&[], "build.sh"),
            Verdict::Deny,
            "the kernel resolves both spellings against the working directory to one file"
        );
        assert_eq!(
            p.decide(&[], "/opt/build.sh"),
            Verdict::Allow,
            "a rule that carries a `/` still speaks about the whole path and not about a name"
        );
        assert_eq!(
            p.deny[0].as_str(),
            "./build.sh",
            "what `sbx config show` and the control wire echo back is what its author wrote"
        );
    }

    #[test]
    fn deny_wins_over_allow() {
        let p = policy(ProcMode::Ask, &["curl"], &["curl"]);
        assert_eq!(p.decide(&[], "/usr/bin/curl"), Verdict::Deny);
    }

    #[test]
    fn enforce_allows_an_unmatched_target_but_ask_parks_it() {
        let enforce = policy(ProcMode::Enforce, &["git"], &["curl"]);
        assert_eq!(
            enforce.decide(&[], "/bin/rg"),
            Verdict::Allow,
            "denylist default-allow"
        );
        assert_eq!(enforce.decide(&[], "/usr/bin/curl"), Verdict::Deny);

        let ask = policy(ProcMode::Ask, &["git"], &["curl"]);
        assert_eq!(ask.decide(&[], "/usr/bin/git"), Verdict::Allow);
        assert_eq!(ask.decide(&[], "/usr/bin/curl"), Verdict::Deny);
        assert_eq!(
            ask.decide(&[], "/bin/rg"),
            Verdict::Ask,
            "unmatched under ask parks"
        );
    }

    #[test]
    fn empty_rules_are_dropped_and_off_is_never_enforcing() {
        let p = policy(ProcMode::Enforce, &["", "  "], &["curl", ""]);
        assert_eq!(p.allow.len(), 0, "blank allow entries dropped");
        assert_eq!(p.deny.len(), 1);
        assert!(!ProcPolicy::off().enforcing());
        assert!(policy(ProcMode::Enforce, &[], &[]).enforcing());
        assert!(policy(ProcMode::Ask, &[], &[]).enforcing());
        assert!(!policy(ProcMode::Observe, &[], &[]).enforcing());
    }

    /// The loader test is on the name, because that is what identifies one wherever a userland
    /// puts it -- and it has to stay narrow enough that the linker and `ldconfig` are not loaders.
    #[test]
    fn a_loader_is_recognised_by_its_name_and_nothing_else_is() {
        for name in [
            "ld-linux-x86-64.so.2",
            "ld-linux-aarch64.so.1",
            "ld-linux.so.2",
            "ld-musl-x86_64.so.1",
            "ld.so",
            "ld.so.1",
        ] {
            assert!(is_dynamic_loader(name), "`{name}` is a program interpreter");
        }
        for name in [
            "ld",
            "ldd",
            "ldconfig",
            "libc.so.6",
            "old-loader",
            "sold.so",
        ] {
            assert!(!is_dynamic_loader(name), "`{name}` is not one");
        }
    }

    /// What a loader's command line says it will run, under the option grammar both loaders share.
    #[test]
    fn a_loaders_command_line_names_the_program_it_will_run() {
        let argv = |words: &[&str]| -> Vec<Vec<u8>> {
            words.iter().map(|w| w.as_bytes().to_vec()).collect()
        };
        let walk = |words: &[&str], complete: bool| {
            let owned = argv(words);
            let borrowed: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
            loader_targets(&borrowed, complete)
        };

        assert_eq!(
            walk(&["ld.so", "/usr/bin/curl"], true),
            Some(vec!["/usr/bin/curl".to_string()]),
            "the plain form"
        );
        assert_eq!(
            walk(&["ld.so", "/usr/bin/curl", "--version"], true),
            Some(vec!["/usr/bin/curl".to_string()]),
            "the program's own arguments are its own: classifying them would refuse \
             `ld.so /bin/grep curl` for a rule about curl"
        );
        assert_eq!(
            walk(&["ld.so", "--library-path", "/x", "/usr/bin/curl"], true),
            Some(vec!["/usr/bin/curl".to_string()]),
            "an option's value is stepped over, or the cage picks what the rule is matched against"
        );
        assert_eq!(
            walk(
                &["ld.so", "--inhibit-cache", "--list", "/usr/bin/curl"],
                true
            ),
            Some(vec!["/usr/bin/curl".to_string()]),
            "a flag takes no value"
        );
        assert_eq!(
            walk(&["ld.so", "--", "/usr/bin/curl"], true),
            Some(vec!["/usr/bin/curl".to_string()]),
            "`--` ends the options"
        );
        assert_eq!(
            walk(&["ld.so", "-x"], true),
            Some(vec!["-x".to_string()]),
            "a single dash is not an option to either loader, so such a word is the program"
        );

        // An option this build does not know may take a value in the loader the cage runs, which
        // would put the program one word further along. From there every non-option word is
        // classified rather than the first one only.
        assert_eq!(
            walk(
                &["ld.so", "--from-a-later-glibc", "value", "/usr/bin/curl"],
                true
            ),
            Some(vec!["value".to_string(), "/usr/bin/curl".to_string()]),
            "an unknown option gives up precision rather than coverage"
        );

        // Settled answers that name no program: the loader prints its usage and runs nothing.
        assert_eq!(walk(&["ld.so", "--version"], true), Some(Vec::new()));
        assert_eq!(walk(&["ld.so"], true), Some(Vec::new()));
        assert_eq!(walk(&["ld.so", "--library-path"], true), Some(Vec::new()));

        // Unsettled answers, which the caller refuses on.
        assert_eq!(
            walk(&["ld.so", "--inhibit-cache"], false),
            None,
            "a list cut short before the walk concluded says nothing about the program"
        );
        assert_eq!(
            walk(&["ld.so", "--from-a-later-glibc", "/usr/bin/curl"], false),
            None,
            "and the uncertain arm runs to the end, so a short list leaves it unsettled"
        );
        assert_eq!(
            walk(&["ld.so", "/usr/bin/curl"], false),
            Some(vec!["/usr/bin/curl".to_string()]),
            "but a walk that concluded inside what was read does not need the rest"
        );

        let odd = [b"ld.so".to_vec(), b"/usr/bin/\xffcurl".to_vec()];
        let borrowed: Vec<&[u8]> = odd.iter().map(Vec::as_slice).collect();
        assert_eq!(
            loader_targets(&borrowed, true),
            None,
            "a name the policy cannot carry is one no rule can speak about"
        );
    }

    /// The `#!` grammar this walk reads is the kernel's own, so each arm here was measured against
    /// a real `execve` before it was written down.
    #[test]
    fn a_shebang_line_names_its_interpreter_and_nothing_further() {
        use ScriptHead::{Interpreter, NotScript, Unsettled};
        let interp = |s: &str| Interpreter(s.to_string());

        assert_eq!(
            shebang_interpreter(b"#!/bin/sh\necho hi\n"),
            interp("/bin/sh")
        );
        // Spaces and tabs between `#!` and the path are skipped, both measured.
        assert_eq!(shebang_interpreter(b"#! /bin/sh\n"), interp("/bin/sh"));
        assert_eq!(shebang_interpreter(b"#!\t/bin/sh\n"), interp("/bin/sh"));
        // One argument may follow, and it is not judged: `env` is the interpreter here.
        assert_eq!(
            shebang_interpreter(b"#!/usr/bin/env python3\n"),
            interp("/usr/bin/env")
        );
        // A NUL cuts the line exactly as a newline does, which is what the kernel was seen to do.
        assert_eq!(shebang_interpreter(b"#!/bin/sh\0-x\n"), interp("/bin/sh"));
        // A last line with no newline at all is still a whole line: the file ended it.
        assert_eq!(shebang_interpreter(b"#!/bin/sh"), interp("/bin/sh"));
        // Folded like every other path a rule is matched against.
        assert_eq!(shebang_interpreter(b"#!/bin//./sh\n"), interp("/bin/sh"));

        // Not a script: the file's own path is the only thing the exec runs.
        assert_eq!(shebang_interpreter(b"\x7fELF\x02\x01"), NotScript);
        assert_eq!(shebang_interpreter(b"#/bin/sh\n"), NotScript);
        assert_eq!(shebang_interpreter(b""), NotScript);

        // Unsettled, and the caller refuses on each: no name a rule could speak about.
        assert_eq!(shebang_interpreter(b"#!\n"), Unsettled, "no interpreter");
        assert_eq!(shebang_interpreter(b"#!   \n"), Unsettled, "blank only");
        assert_eq!(
            shebang_interpreter(b"#!bin/sh\n"),
            Unsettled,
            "a relative interpreter is exec'd against a directory this walk does not resolve"
        );
        let mut odd = b"#!/bin/s".to_vec();
        odd.push(0xff);
        odd.push(b'\n');
        assert_eq!(
            shebang_interpreter(&odd),
            Unsettled,
            "a name the policy cannot carry is one no rule can speak about"
        );

        // A word running to the edge of a head that was itself cut short may go on in bytes this
        // read does not have, so it is not a settled name. Measured: the kernel truncates such a
        // line and runs it anyway, which is why the ceiling cannot simply be treated as a line end.
        let long = [b"#!/bin/".to_vec(), vec![b'x'; SCRIPT_HEAD]].concat();
        assert_eq!(shebang_interpreter(&long[..SCRIPT_HEAD]), Unsettled);
        // But a word the truncated head did end is settled, argument or not.
        let mut ended = b"#!/bin/sh ".to_vec();
        ended.extend(std::iter::repeat_n(b'x', SCRIPT_HEAD));
        assert_eq!(
            shebang_interpreter(&ended[..SCRIPT_HEAD]),
            interp("/bin/sh"),
            "the interpreter is whole; only its argument was cut, and arguments are not judged"
        );
    }

    /// A registered handler is read the way the kernel prints it, and matches what it says it does.
    ///
    /// The first fixture is a real handler as read from this kernel, so the shape is not invented.
    #[test]
    fn a_binfmt_handler_names_the_interpreter_it_would_run() {
        let real = "enabled\ninterpreter /usr/bin/python3.14\nflags: \noffset 0\nmagic 2b0e0d0a\n";
        let rule = parse_binfmt_rule(real).expect("a usable handler");
        assert_eq!(rule.interpreter, "/usr/bin/python3.14");

        let rules = vec![rule];
        // The magic sits at the offset the handler names, and nothing else matches.
        assert_eq!(
            binfmt_interpreters(&rules, b"\x2b\x0e\x0d\x0a rest", "/tmp/x.pyc"),
            vec!["/usr/bin/python3.14"]
        );
        assert!(binfmt_interpreters(&rules, b"\x7fELF\x02", "/tmp/x").is_empty());
        // A head shorter than the window the handler reads matches nothing rather than panicking.
        assert!(binfmt_interpreters(&rules, b"\x2b\x0e", "/tmp/x").is_empty());

        // An offset handler reads further in, and a mask compares only the bits it names.
        let masked = parse_binfmt_rule(
            "enabled\ninterpreter /usr/bin/qemu\nflags: F\noffset 2\nmagic 00ff\nmask 00f0\n",
        )
        .expect("a masked handler");
        let masked = vec![masked];
        assert_eq!(
            binfmt_interpreters(&masked, b"xx\x11\xf5", "/tmp/x"),
            vec!["/usr/bin/qemu"],
            "only the bits the mask names are compared"
        );
        assert!(binfmt_interpreters(&masked, b"xx\x11\x05", "/tmp/x").is_empty());

        // An extension handler compares the trailing name component, case-sensitively.
        let ext = vec![
            parse_binfmt_rule("enabled\ninterpreter /usr/bin/jre\nflags: \nextension jar\n")
                .expect("an extension handler"),
        ];
        assert_eq!(
            binfmt_interpreters(&ext, b"PK\x03\x04", "/srv/app.jar"),
            vec!["/usr/bin/jre"]
        );
        assert!(binfmt_interpreters(&ext, b"PK\x03\x04", "/srv/app.JAR").is_empty());
        assert!(binfmt_interpreters(&ext, b"PK\x03\x04", "/srv/jar").is_empty());
        // A dot in a directory above the file is not the file's own extension.
        assert!(binfmt_interpreters(&ext, b"PK", "/srv/x.jar/app").is_empty());

        // Not usable, and each for its own reason: switched off, no interpreter, nothing to match.
        assert!(parse_binfmt_rule("disabled\ninterpreter /usr/bin/x\nmagic 00\n").is_none());
        assert!(parse_binfmt_rule("enabled\ninterpreter \nmagic 00\n").is_none());
        assert!(parse_binfmt_rule("enabled\ninterpreter /usr/bin/x\nflags: \n").is_none());
    }

    /// Deny beats ask beats allow, which is what lets one syscall be decided under two names.
    #[test]
    fn the_stricter_of_two_verdicts_is_the_one_that_holds() {
        use Verdict::{Allow, Ask, Deny};
        for (a, b, want) in [
            (Allow, Allow, Allow),
            (Allow, Ask, Ask),
            (Ask, Allow, Ask),
            (Ask, Ask, Ask),
            (Allow, Deny, Deny),
            (Deny, Allow, Deny),
            (Ask, Deny, Deny),
            (Deny, Ask, Deny),
            (Deny, Deny, Deny),
        ] {
            assert_eq!(a.stricter(b), want, "{a:?} with {b:?}");
        }
    }

    #[test]
    fn mode_round_trips() {
        for m in [
            ProcMode::Off,
            ProcMode::Observe,
            ProcMode::Enforce,
            ProcMode::Ask,
        ] {
            assert_eq!(ProcMode::parse(m.as_str()), Some(m));
        }
        assert_eq!(ProcMode::parse("bogus"), None);
    }

    #[test]
    fn decide_with_folds_the_overlay_and_deny_wins() {
        let base = policy(ProcMode::Enforce, &["git"], &["curl"]);
        let one = |r: &str| vec![ProcRule::new(r)];

        // An overlay deny cuts a target the base would allow (unmatched → allow under enforce)…
        assert_eq!(
            base.decide_chain(&[], "/bin/wget", &[], &one("wget")),
            Verdict::Deny
        );
        // …while with no overlay that same target runs (denylist default-allow).
        assert_eq!(base.decide(&[], "/bin/wget"), Verdict::Allow);
        // Deny wins across BOTH sets: a base deny is not overridden by an overlay allow.
        assert_eq!(
            base.decide_chain(&[], "/bin/curl", &one("curl"), &[]),
            Verdict::Deny
        );
        // Under ask, an overlay allow un-parks an otherwise-unmatched target.
        let ask = policy(ProcMode::Ask, &[], &[]);
        assert_eq!(ask.decide(&[], "/bin/node"), Verdict::Ask);
        assert_eq!(
            ask.decide_chain(&[], "/bin/node", &one("node"), &[]),
            Verdict::Allow
        );
    }
}
