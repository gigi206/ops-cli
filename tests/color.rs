//! Integration guard for the auto-gated terminal color: a captured (non-terminal) stream must be
//! byte-for-byte plain text. Every human-facing renderer decides its palette with
//! `Palette::for_stream(stdout().is_terminal())`, so a pipe is always plain — which is also why
//! every other integration test can assert exact substrings. This file is the end-to-end proof
//! that the commands actually take that path (not an accidental `colored()`), across the surface
//! the color pass touched. It exercises only the cheap, side-effect-free commands (no sandbox, no
//! nix, no network) so it runs everywhere and fast.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// A unique temp dir removed on drop, so a command's data-dir reads land in a throwaway location
/// instead of the real `$HOME`.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = std::env::temp_dir();
        d.push(format!("ops-color-{}-{n}", std::process::id()));
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

/// Run `ops <args>` with a throwaway home (data, state, config all redirected) and a clean cwd,
/// capturing stdout (a pipe — so color must be off). `NO_COLOR`/`TERM` are also neutralised so the
/// result does not depend on the host's environment leaking in.
fn run(args: &[&str], home: &Path, cwd: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ops"))
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home)
        .env("XDG_STATE_HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env_remove("NO_COLOR")
        .env_remove("TERM")
        .output()
        .expect("spawn ops")
}

#[test]
fn captured_output_carries_no_ansi_escapes() {
    let home = TmpDir::new();
    let cwd = TmpDir::new();
    // A real project config so `trust`/`untrust` take their confirmation path (recording then
    // revoking a marker), not an early read error — the colored confirmation lines must still be
    // plain when captured.
    std::fs::write(cwd.path().join(".ops.toml"), "env = { A = \"1\" }\n").unwrap();
    // Each is a renderer the color pass touched; all are cheap and host-agnostic. `doctor` is
    // included even though it probes the host — its output is captured, so it too must be plain.
    // `trust` precedes `untrust` so the revoke finds the marker it recorded (the `existed` path).
    let invocations: &[&[&str]] = &[
        &["config", "show"],
        // Bare `config` prints its page to stderr (a no-subcommand usage error) — captured, so it
        // too must be plain.
        &["config"],
        &["ls"],
        &["plugins", "list"],
        &["plugins", "store", "list"],
        &["test", "net", "https://example.com/x"],
        &["trust", "--show"],
        &["trust", ".ops.toml"],
        &["untrust", ".ops.toml"],
        &["doctor"],
    ];
    for args in invocations {
        let out = run(args, home.path(), cwd.path());
        assert!(
            !out.stdout.contains(&0x1b),
            "`ops {}` emitted an ANSI escape on a captured stream:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            !out.stderr.contains(&0x1b),
            "`ops {}` emitted an ANSI escape on captured stderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
