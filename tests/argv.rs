//! No verb may accept an argument it does not use.
//!
//! An unknown flag that is *rejected* costs one retry; one that is silently *dropped* answers a
//! different question than the one asked, with a zero exit and output that looks right —
//! `sbx plugins store ls --installed` printing the whole listing reads as a filtered result. This
//! suite sweeps every read-only verb with a token it cannot mean, and requires a non-zero exit.
//!
//! Only side-effect-free verbs are swept: nothing here launches a cage, fetches, installs, or
//! writes outside its throwaway data directory. Verbs that legitimately take a positional (say
//! `test net <target>`) are swept with a *second* one, since the first is a valid argument.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// Where this suite's throwaway fixtures live: the repo's own test tree, overridable with
/// `SBX_TEST_TMPDIR`. Deliberately not the system tmpfs, whose inode budget is machine-wide.
fn fixture_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("SBX_TEST_TMPDIR") {
        return PathBuf::from(dir);
    }
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("target/test-tmp");
    d
}

struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = fixture_root();
        d.push(format!("argv-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        TmpDir(d)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run `sbx <args>` against a throwaway home and return its exit code with both streams.
fn run(args: &[&str], home: &Path) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home)
        .env("XDG_STATE_HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .output()
        .expect("spawn sbx");
    let mut streams = String::from_utf8_lossy(&out.stdout).into_owned();
    streams.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), streams)
}

/// Every read-only verb, with the arguments it legitimately takes (so the probe appends a token
/// that can only be surplus). Kept explicit rather than derived from the help pages: a verb added
/// without a thought for its argv should fail this suite, not be skipped by it.
const READ_ONLY_VERBS: &[&[&str]] = &[
    &["doctor"],
    &["path"],
    &["session", "ls"],
    &["app", "list"],
    &["projects", "ls"],
    &["config", "show"],
    &["config", "path"],
    &["net", "rules"],
    &["net", "pending"],
    &["net", "stats"],
    &["proc", "ls"],
    &["proc", "pending"],
    &["proc", "rules"],
    &["fs", "logs"],
    &["ssh-agent", "logs"],
    &["secret", "list"],
    &["task", "list"],
    &["task", "status"],
    &["storage", "status"],
    &["plugins", "list"],
    &["plugins", "store", "list"],
];

#[test]
fn no_read_only_verb_accepts_a_surplus_flag() {
    let home = TmpDir::new();
    let mut accepted = Vec::new();
    for verb in READ_ONLY_VERBS {
        let mut args = verb.to_vec();
        args.push("--zzz-not-a-flag");
        let (code, out) = run(&args, home.path());
        if code == 0 {
            accepted.push(format!("sbx {} --zzz-not-a-flag\n{out}", verb.join(" ")));
        }
    }
    assert!(
        accepted.is_empty(),
        "these verbs silently ignored an unknown flag:\n{}",
        accepted.join("\n")
    );
}

/// Verbs whose single positional is optional: a bare token is a legitimate argument, so only a
/// flag-shaped one can be surplus. They are swept for flags here and for a second positional in
/// [`a_verb_that_takes_a_positional_still_refuses_a_second_one`].
const VERBS_TAKING_AN_OPTIONAL_PATH: &[&[&str]] = &[&["untrust"]];

#[test]
fn a_verb_taking_a_path_still_refuses_an_unknown_flag() {
    let home = TmpDir::new();
    for verb in VERBS_TAKING_AN_OPTIONAL_PATH {
        let mut args = verb.to_vec();
        args.push("--zzz-not-a-flag");
        let (code, out) = run(&args, home.path());
        // Read as a path, an unknown flag would report "nothing to revoke" and exit 0 — a success
        // for something that never happened.
        assert_ne!(
            code,
            0,
            "`sbx {} --zzz-not-a-flag` treated a flag as a path:\n{out}",
            verb.join(" ")
        );
    }
}

#[test]
fn no_read_only_verb_accepts_a_surplus_argument() {
    let home = TmpDir::new();
    let mut accepted = Vec::new();
    for verb in READ_ONLY_VERBS {
        let mut args = verb.to_vec();
        args.push("zzz-not-an-argument");
        let (code, out) = run(&args, home.path());
        if code == 0 {
            accepted.push(format!("sbx {} zzz-not-an-argument\n{out}", verb.join(" ")));
        }
    }
    assert!(
        accepted.is_empty(),
        "these verbs silently ignored a surplus argument:\n{}",
        accepted.join("\n")
    );
}

#[test]
fn a_verb_that_takes_a_positional_still_refuses_a_second_one() {
    let home = TmpDir::new();
    // The first token is a legitimate argument, so only the second can be surplus.
    let cases: &[&[&str]] = &[
        &["untrust", ".sbx.toml", "zzz-surplus"],
        &["trust", ".sbx.toml", "zzz-surplus"],
        &["path", "zzz-one", "zzz-two"],
        &["plugins", "info", "vault", "zzz-surplus"],
        &["plugins", "store", "info", "nope", "zzz-surplus"],
        &["test", "net", "https://example.invalid/", "zzz-surplus"],
    ];
    std::fs::write(home.path().join(".sbx.toml"), "env = { A = \"1\" }\n").unwrap();
    for args in cases {
        let (code, out) = run(args, home.path());
        assert_ne!(
            code,
            0,
            "`sbx {}` accepted a surplus argument:\n{out}",
            args.join(" ")
        );
    }
}

#[test]
fn a_refusal_names_the_offending_token_and_prints_the_usage() {
    let home = TmpDir::new();
    // A refusal that only said "usage" would leave the user re-reading their own command line.
    let (code, out) = run(&["plugins", "store", "list", "--intalled"], home.path());
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("--intalled"), "{out}");
    assert!(out.contains("sbx: usage: sbx plugins store list"), "{out}");

    let (code, out) = run(&["session", "ls", "zzz"], home.path());
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("'zzz'"), "{out}");
    assert!(out.contains("sbx: usage: sbx session ls"), "{out}");
}
