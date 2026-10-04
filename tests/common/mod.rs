//! What every integration suite shares: how a test says it did not run, where it puts its files,
//! and what the command tree is.
//!
//! Three things live here, each because a second copy of it drifts:
//!
//! * The **skip macros**, and the two gates built on them — `probe_or_skip!` for a host that
//!   cannot build a cage, `need_reachable!` for a remote that is not answering. A gate has to
//!   return from the test, so both are macros: a helper returning `bool` leaves the `return` at the
//!   call site, and a site that leaves it out does not fail, it runs the body anyway and reports a
//!   defect that is really an absent prerequisite. A probe that failed on a download is the
//!   network's skip, not the host's: [`probe`] tells the two apart, with the reading of nix's
//!   download faults the heavier e2es share, [`transient_fetch_failure`], and [`probe_with`] does
//!   the same for a verb that reports nix's failure in a sentence of its own.
//! * The **fixture directory**, in [`fixture`].
//! * The **command tree**. `tests/help.rs` and `tests/completion.rs` each assert a property over
//!   every command and subcommand, so both need the same answer to "what is the command tree?".
//!   Two copies drift, and a sweep walking a stale tree reports a coverage it does not have —
//!   which is exactly what a hand-written list did here before, missing a third of the surface
//!   while its header claimed to enumerate all of it.
//!
//! A shared test module is compiled *into* each test binary rather than linked once, so an item
//! only one suite needs is dead code in the others — hence the module-wide allow, which says
//! nothing about the crate itself.
#![allow(dead_code)]

// The skip macros, included rather than linked: an integration test is its own crate and cannot see
// into the binary's `testskip` module, so both halves of the suite compile the same text. One
// definition -- a second copy would drift, and a skip counted by one half and not the other is
// worse than no count at all. Reach them with `#[macro_use] mod common;`.
include!("../../src/testskip.rs");

// Where a fixture tree lives, included for the same reason: this module needs the root to isolate a
// launch's global config, and a second spelling of it would put that isolation somewhere the rest
// of the suite does not clean.
include!("../../src/testroot.rs");

/// The fixture root, reachable from a suite that builds its own command rather than going through
/// [`sbx`]. The included definition is private to this module, and a second spelling of the root
/// would put a suite's files where nothing else cleans them.
pub fn fixtures_root() -> std::path::PathBuf {
    fixture_root()
}

/// Gate a test on this host being able to build a cage, skipping it — with the probe's own
/// diagnosis — when it cannot.
///
/// `$probe` is an expression yielding a [`std::process::Output`] from a launch the test does not
/// otherwise need, conventionally `sbx run -- true`; on a capable host it also seeds the base
/// userland, so the gate doubles as the warm-up the real launch would otherwise pay for. The macro
/// expands to that `Output`, for the callers that go on to read what the probe printed.
///
/// A macro rather than a helper returning `bool`, because the gate has to leave the **test**. A
/// helper leaves the `return` at the call site, where it can be forgotten -- and a forgotten
/// `return` does not fail: it runs the body against a host that cannot support it and reports a
/// real defect. `$what` names the test in the skip line, which is the only record a skipped run
/// leaves behind.
///
/// A probe that failed on a download is not a host that cannot sandbox. The first launch fetches
/// the userland, and a cache that drops a connection halfway fails it as surely as a refused user
/// namespace does. Read as incapable, that turned an e2e into a skip on a capable runner, and made
/// `SBX_REQUIRE_CAPABLE` fail a run over the network. [`probe`] decides, and may evaluate `$probe`
/// a second time, so the expression must be a launch that can be repeated.
#[allow(unused_macros)]
macro_rules! probe_or_skip {
    ($what:literal, $probe:expr $(,)?) => {
        match $crate::common::probe(|| $probe) {
            $crate::common::Probe::Ran(probe) => probe,
            $crate::common::Probe::Unreachable(why) => {
                skip_unreachable!(
                    concat!(
                        "skipping ",
                        $what,
                        ": the launch failed on a download, twice ({})"
                    ),
                    why
                );
                return;
            }
            $crate::common::Probe::Incapable(why) => {
                skip_incapable!(
                    concat!("skipping ", $what, ": host cannot sandbox ({})"),
                    why
                );
                return;
            }
        }
    };
}

/// Gate a test on a remote it needs being available, skipping it when the remote is not.
///
/// `$available` is the caller's own predicate — the binary cache answers, GitHub still has quota,
/// a public echo server is up — and reads in the positive, so the macro name and the condition
/// agree. The reason is written out at each site rather than derived, because "unreachable" alone
/// does not say which remote went missing.
///
/// A macro for the reason `probe_or_skip!` is one: the gate returns from the test, and that
/// `return` must not be something a site can leave out.
#[allow(unused_macros)]
macro_rules! need_reachable {
    ($available:expr, $($reason:tt)+) => {
        if !$available {
            skip_unreachable!($($reason)+);
            return;
        }
    };
}

/// What a capability probe found, as [`probe`] reads it.
#[derive(Debug)]
pub enum Probe {
    /// The launch succeeded. Its output is kept for the callers that read what it printed.
    Ran(Output),
    /// The launch failed on a download, again on the second try. Carries the lines that say so.
    Unreachable(String),
    /// The launch failed for a reason of the host's. Carries its whole stderr.
    Incapable(String),
}

/// Run a capability probe and say whether a failure is the host's or the network's.
///
/// A launch that failed on a download is run once more. nix has retried each download by then, so
/// one more launch is a fresh start rather than a sixth attempt: it begins the fetch again and
/// keeps every path the first one finished. A second failure on a download is the network's
/// answer, and goes to [`skip_unreachable!`], which counts it and never enforces it. Anything else
/// is the host's, exactly as before.
///
/// The limit this draws: a regression that breaks substitution itself, a wrong substituter for one,
/// fails on a download every time and so reads as unreachable, which `SBX_REQUIRE_CAPABLE` does not
/// turn into a failure. It still lands in the skip report, once per probing test. So does a host
/// with a dead extra substituter beside a working cache, when a build nix then runs locally fails
/// for a reason of the host's: nix gave the dead cache up and built, the shape [`cache_given_up`]
/// reads as the network's.
pub fn probe(launch: impl FnMut() -> Output) -> Probe {
    probe_with(launch, download_fault)
}

/// [`probe`], with what reads a download fault out of a failure's stderr given: [`download_fault`]
/// for a launch, whose stderr is nix's own, and [`metadata_fetch_fault`] for `sbx upgrade`, which
/// folds nix's stderr into a sentence of its own.
pub fn probe_with(mut launch: impl FnMut() -> Output, fault: fn(&[u8]) -> Option<String>) -> Probe {
    let mut out = launch();
    if !out.status.success() && fault(&out.stderr).is_some() {
        out = launch();
    }
    if out.status.success() {
        return Probe::Ran(out);
    }
    match fault(&out.stderr) {
        Some(lines) => Probe::Unreachable(lines),
        None => Probe::Incapable(String::from_utf8_lossy(&out.stderr).trim().to_owned()),
    }
}

/// nix's word for a closure it could not fetch: one of the paths it needed came from no cache.
const NO_SUBSTITUTER: &str = "there is no substituter that can build it";

/// The lines of a failed launch's stderr that show it failed on a download, or `None` when it
/// failed for another reason.
///
/// nix's stderr reaches the launch's unchanged, because provisioning inherits it, and three shapes
/// mean a download. `sbx upgrade` is the exception: it folds nix's stderr onto one line, so its
/// failures are read by [`metadata_fetch_fault`] instead.
///
/// * an `error:` line [`transient_fetch_failure`] reads as a fault of the moment, such as a resumed
///   download the cache answers with a 416;
/// * nix's [`NO_SUBSTITUTER`] error, when the stderr also shows a download that failed and no
///   definite HTTP answer. It follows a dropped download, and it is also the one `error:` line nix
///   prints when it realises a path that no reachable cache offers: the download is then named only
///   in `warning:` lines;
/// * a binary cache nix gave up on before it set out to build the closure itself
///   ([`cache_given_up`]). The build that follows fails on a line that names no download, so what
///   is quoted is the warning in which nix gave the cache up.
///
/// The third is what a cache that answers nothing at all produces. Measured with nix 2.34.5 against
/// one that refused every connection, GitHub reachable: five warnings on the cache's
/// `nix-cache-info`, then `these 396 derivations will be built`, then, 3 s later and 24 s after the
/// launch began, a `hash mismatch in fixed-output derivation` on a bootstrap source, followed by
/// `Cannot build` for each derivation above it. The launch's `nix build` passes no `--max-jobs`, so
/// nothing keeps that bootstrap from starting. How long it runs when no step breaks early is not
/// measured, and [`probe`] runs it twice.
///
/// A download named in a `warning:` line is not enough on its own. nix warns for every retry,
/// including the ones that then succeed, so a launch that fetched its userland with one retry and
/// was then refused a user namespace carries that warning too. Reading it as the network's would
/// take that failure away from `SBX_REQUIRE_CAPABLE`. The one warning read is the one in which nix
/// says it gave a cache up, and only when nix then failed a build of its own.
fn download_fault(stderr: &[u8]) -> Option<String> {
    let stderr = String::from_utf8_lossy(stderr);
    let errors: Vec<&str> = stderr
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("error:"))
        .collect();
    let unreachable =
        errors.iter().any(|line| line.contains(NO_SUBSTITUTER)) && transient_fetch_failure(&stderr);
    if !unreachable && !transient_fetch_failure(&errors.join("\n")) {
        return cache_given_up(&stderr, &errors);
    }
    let named: Vec<&str> = errors
        .into_iter()
        .filter(|line| line.contains(NO_SUBSTITUTER) || transient_fetch_failure(line))
        .collect();
    Some(named.join("\n"))
}

/// What nix fetches first from each binary cache, named in the warning of every failed attempt.
const CACHE_INFO: &str = "/nix-cache-info'";

/// How a warning on a download nix will try again ends. The last attempt's does not.
const RETRYING: &str = "; retrying";

/// nix's word for a closure it set out to build itself.
const WILL_BE_BUILT: &str = "will be built";

/// The warnings in which nix gave a binary cache up, when it then set out to build the closure
/// itself and failed, or `None`.
///
/// nix asks each cache for its [`CACHE_INFO`] before anything else, and warns at every attempt that
/// fails. Each attempt it will follow with another says so ([`RETRYING`]); the last does not, and
/// nix drops the cache for the rest of the run. With no cache left it builds the whole closure from
/// source, says so ([`WILL_BE_BUILT`]), and fails on whichever bootstrap step breaks first.
///
/// Each warning that gives a cache up passes through [`transient_fetch_failure`], so a cache that
/// answered with a definite HTTP status, a substituter URL that does not exist, stays the host's.
/// nix's own failure is required too: a launch whose build nix finished, and that the host then
/// refused, carries the same warnings.
fn cache_given_up(stderr: &str, errors: &[&str]) -> Option<String> {
    if errors.is_empty() {
        return None;
    }
    let mut given_up = Vec::new();
    for line in stderr.lines().map(str::trim_start) {
        if line.starts_with("warning:") && line.contains(CACHE_INFO) && !line.contains(RETRYING) {
            if !transient_fetch_failure(line) {
                return None;
            }
            given_up.push(line);
        } else if !given_up.is_empty() && line.contains(WILL_BE_BUILT) {
            return Some(given_up.join("\n"));
        }
    }
    None
}

/// What `sbx upgrade` writes before nix's own words when a `nix flake metadata` it ran failed:
/// `` `nix flake metadata <ref>` failed: ``.
const METADATA_RUN: &str = "`nix flake metadata ";
const METADATA_FAILED: &str = "` failed: ";

/// nix's error in a failed `sbx upgrade`, when every `nix flake metadata` it ran that failed did so
/// on a download, or `None` when one failed for another reason, or none ran.
///
/// `sbx upgrade` resolves the nixpkgs channel and each `flake:` package with `nix flake metadata`,
/// and reports a failure as a sentence of its own: `` `nix flake metadata <ref>` failed: ``, then
/// nix's stderr folded onto the same line, its retry warnings and its error together
/// (`metadata_failed`, in `src/sandbox/flake.rs`). [`download_fault`] reads whole `error:` lines and
/// finds none there. This reads only what follows that sentence, so it cannot misread a launch,
/// whose stderr keeps nix's lines apart.
///
/// What counts is nix's error: the text from the first `error:` that opens one of its messages to
/// the end of the line, read by [`transient_fetch_failure`], veto included. The retry warnings
/// before it do not count, for the reason they do not in [`download_fault`]. In nix 2.34 a warning
/// opens on `warning:` alone, in older releases on `warning: error:`, and one may carry a `(curl
/// error: …)` inside, so an `error:` after `warning:` or `curl` opens nothing.
///
/// Every failed resolution has to read as a download. `sbx upgrade` rolls several at once, and a
/// `flake:` reference answered with a 404 is a regression even when the channel's fetch failed
/// beside it.
///
/// Measured with nix 2.34.5 behind a proxy that refuses every connection: four `warning: unable to
/// download '…': Could not connect to server (7) …; retrying`, then `error: … while fetching the
/// input '…' error: unable to download '…': Could not connect to server`. Neither a host that cannot
/// resolve a name nor a GitHub API quota that ran out has been measured. If the second answers 403,
/// the veto reads it as the host's, as every failure here was read before.
pub fn metadata_fetch_fault(log: &[u8]) -> Option<String> {
    let log = String::from_utf8_lossy(log);
    let mut faults = Vec::new();
    for line in log.lines() {
        let Some(run) = line.find(METADATA_RUN) else {
            continue;
        };
        let Some(failed) = line[run..].find(METADATA_FAILED) else {
            continue;
        };
        match nix_error(&line[run + failed + METADATA_FAILED.len()..]) {
            Some(error) if transient_fetch_failure(error) => faults.push(error),
            _ => return None,
        }
    }
    (!faults.is_empty()).then(|| faults.join("\n"))
}

/// The error in nix's stderr once folded onto one line: from the first `error:` that opens one of
/// its messages, to the end. A message opens the text or follows a space, and an `error:` after
/// `warning:` or `curl` is inside a warning ([`metadata_fetch_fault`] says which).
fn nix_error(folded: &str) -> Option<&str> {
    let mut from = 0;
    while let Some(i) = folded[from..].find("error:") {
        let at = from + i;
        let before = &folded[..at];
        let word = before.trim_end();
        if word.is_empty()
            || (before.ends_with(' ') && !word.ends_with("warning:") && !word.ends_with("curl"))
        {
            return Some(&folded[at..]);
        }
        from = at + "error:".len();
    }
    None
}

/// Whether a failed build log shows a *transient* upstream-download fault — a truncated tarball,
/// a reset connection, an upstream stall — rather than a real failure of the code under test. The
/// heavy `flake:` e2es fetch tens of megabytes of nixpkgs per fresh run, so an occasional
/// truncated download from a busy mirror is a property of the network, not a regression. A build
/// that fails *only* with one of these signatures should skip (never turn the suite red); a build
/// that fails for any other reason — or succeeds with the wrong output — must still assert.
pub fn transient_fetch_failure(log: &str) -> bool {
    const SIGNATURES: [&str; 8] = [
        "Truncated tar archive",
        "unexpected end-of-file",
        "unexpected EOF",
        "Connection reset by peer",
        "Couldn't resolve host",
        "Connection timed out",
        "transferred only",
        "unable to download",
    ];
    // `unable to download` is nix's wrapper around every fetch failure, and it carries the reason
    // after it: `Couldn't resolve host` on one run and `HTTP error 404` on another. A definite
    // client answer is not a property of the network. A 404 or a 403 is a URL this code fabricated
    // or a release that moved, which is precisely the regression these e2es exist to catch, and
    // reading it as transient turned that regression into a green skip. A 408 and a 429 are the
    // two 4xx that *are* about the moment, so they are left to the signatures above.
    const DEFINITE: [&str; 5] = [
        "HTTP error 400",
        "HTTP error 401",
        "HTTP error 403",
        "HTTP error 404",
        "HTTP error 410",
    ];
    if DEFINITE.iter().any(|s| log.contains(s)) {
        return false;
    }
    SIGNATURES.iter().any(|s| log.contains(s))
}

/// The fixture directory every suite creates its trees under, in one definition.
pub mod fixture;

/// The project-under-test harness the host-side verb suites drive, in one definition.
pub mod project;

use std::process::{Command, Output};

/// Run the binary under test with `args`.
///
/// The global config is isolated the way the launching suites isolate theirs: a fixed empty
/// directory under the test tree. Without it, a verb that reads the global config — the apps a
/// completion offers, the profiles a listing names — answers out of the developer's own
/// `~/.config/sbx`, and the assertion then measures that machine. The locale is pinned for the
/// reason [`project::Project::cmd_in`] gives.
pub fn sbx(args: &[&str]) -> Output {
    let config = fixture_root().join("isolated-config");
    let _ = std::fs::create_dir_all(&config);
    Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(args)
        .env("XDG_CONFIG_HOME", config)
        .env("LC_ALL", "C.UTF-8")
        .env_remove("LANG")
        .output()
        .expect("spawn sbx")
}

/// The first `nft` on `PATH`, where a launch looks for the one that installs its capture redirect,
/// or `None` on a host without nftables. Without it a launch wires no capture tap, and says nothing.
pub fn nft_on_path() -> Option<std::path::PathBuf> {
    on_path("nft")
}

/// The first `bwrap` on `PATH`, or `None` on a host without bubblewrap.
pub fn bwrap_on_path() -> Option<std::path::PathBuf> {
    on_path("bwrap")
}

/// The first file called `name` in a directory of `PATH`.
fn on_path(name: &str) -> Option<std::path::PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

pub fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Whether an attached shell has printed a prompt into `out` and is ready to be driven.
///
/// The last character of a shell prompt is bash's `\$`, which it renders `#` when the euid is 0 and
/// `$` otherwise — the cage's own rc sets `PS1='(\h) \w\$ '`, and the fallback `bash-5.x\$ ` ends
/// the same way. A wait that looked for `$` alone therefore never fired where the in-cage user is
/// root: the script was never written, and the failure read as a shell that never came up, with its
/// prompt sitting in the transcript the assertion printed.
///
/// Asked of the transcript's end, the prompt's last character and the space after it, because a
/// launch prints before its shell does and what it prints carries both characters: a nixpkgs flake
/// reference names its package after a `#`. A wait that took either character anywhere in the
/// transcript fired on that line, before the shell was up, and the supervisor, which discards
/// type-ahead as it takes the terminal, dropped the script.
pub fn shell_prompt_seen(out: &[u8]) -> bool {
    out.ends_with(b"$ ") || out.ends_with(b"# ")
}

/// A process's start-time ticks — field 22 of `/proc/<pid>/stat`.
///
/// This is what pairs with a pid to name one *incarnation* of a process across pid reuse, so it is
/// what a fabricated session record has to carry for sbx to accept the record as live. Seven
/// suites fabricate such records; they read the field through here.
///
/// Field 2 (`comm`) is the process name in parentheses and may itself contain spaces and `)`, so
/// splitting the whole line on whitespace is wrong. Everything after the *final* `)` is clean, and
/// field 3 (state) is the first token there — which puts field 22 twentieth.
pub fn start_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read /proc stat");
    let after = &stat[stat.rfind(')').expect("a stat line carries a comm field") + 1..];
    after
        .split_whitespace()
        .nth(19)
        .expect("a stat line carries field 22")
        .parse()
        .expect("start ticks are a number")
}

/// The candidate names the completion oracle offers after `path`, for the given cursor word.
pub fn oracle(path: &[String], cursor: &str) -> Vec<String> {
    let mut argv: Vec<String> = vec!["__complete".into(), "--".into()];
    argv.extend(path.iter().cloned());
    argv.push(cursor.to_string());
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    stdout_of(&sbx(&borrowed))
        .lines()
        .filter_map(|l| l.split('\t').next().map(str::to_string))
        .collect()
}

/// Every command path the binary's completion can reach, found by walking it from the root.
///
/// The sweeps run over this rather than over a list kept by hand, so they cover whatever the binary
/// actually offers: a subcommand added tomorrow is swept the day it lands. The `help` verb mirrors
/// the whole tree beneath itself, so the walk covers each path twice, once directly and once
/// through `sbx help ...`; a caller wanting only the pages filters the mirrored half out.
///
/// Only names that resolve to a page are descended into: the menus also hold value vocabulary —
/// live ids, literal targets — that is machine state, not command tree, and walking into it would
/// loop on a real registry the moment one exists.
///
/// What this is **not**: an independent enumeration. The oracle and the help table are both fed by
/// the same page table, so a walk cannot notice a verb the dispatcher accepts and the table never
/// heard of. It answers "what does the binary declare?", and the sweeps assert that everything
/// declared behaves; the other direction is a property of the dispatch, not of a list.
pub fn walk() -> Vec<Vec<String>> {
    /// Whether a path names a page, and so is command tree rather than a value.
    ///
    /// A leading `help` is stripped before asking, because it is exactly what the page tree does
    /// not contain: `sbx help` has no page of its own (`sbx help help` is refused), so probing the
    /// path verbatim would answer "not a page" for `help` and prune the mirrored half of the tree —
    /// the half this walk exists to cover.
    fn is_page(path: &[String]) -> bool {
        let under_help = path.first().is_some_and(|w| w == "help");
        let probed: Vec<&str> = path
            .iter()
            .skip(usize::from(under_help))
            .map(String::as_str)
            .collect();
        // `sbx help` itself: a real verb, and the root of the mirror.
        if probed.is_empty() {
            return under_help;
        }
        let mut argv = vec!["help"];
        argv.extend(probed.iter().copied());
        let out = sbx(&argv);
        out.status.success() && stdout_of(&out).contains(&format!("sbx {} —", probed.join(" ")))
    }
    let mut found: Vec<Vec<String>> = Vec::new();
    let mut queue: Vec<Vec<String>> = vec![Vec::new()];
    while let Some(path) = queue.pop() {
        // A tree this deep would mean the walk is looping, not that the CLI grew: stop loudly
        // rather than spin (an earlier `help` that offered itself did exactly that).
        assert!(path.len() < 6, "the completion tree loops at {path:?}");
        for child in oracle(&path, "") {
            let mut deeper = path.clone();
            deeper.push(child);
            if !is_page(&deeper) {
                continue;
            }
            queue.push(deeper.clone());
            found.push(deeper);
        }
    }
    found
}

/// Every page path the binary declares, the `help`-mirrored half dropped — the command tree as a
/// reader meets it. `sbx help` has no page of its own, so it is absent by the same filter.
pub fn page_paths() -> Vec<Vec<String>> {
    walk()
        .into_iter()
        .filter(|p| p.first().is_none_or(|w| w != "help"))
        .collect()
}
