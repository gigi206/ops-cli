//! Integration tests for `ops doctor`, exercising the built binary end to end.

use std::process::Command;

fn ops() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ops"))
}

#[test]
fn doctor_prints_the_preflight_structure() {
    let out = ops().arg("doctor").output().expect("spawn ops doctor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("runtime preflight"), "stdout was: {stdout}");
    assert!(stdout.contains("bubblewrap"), "stdout was: {stdout}");
    assert!(stdout.contains("user namespaces"), "stdout was: {stdout}");
    // 0 (all prerequisites OK) or 1 (a hard requirement missing) — both valid
    // depending on the host; anything else is a bug.
    let code = out.status.code().expect("exited normally");
    assert!(code == 0 || code == 1, "unexpected exit code {code}");
}

#[test]
fn no_arguments_is_a_usage_error() {
    let out = ops().output().expect("spawn ops");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage"));
}

#[test]
fn unknown_command_is_rejected() {
    let out = ops().arg("bogus").output().expect("spawn ops bogus");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown command"));
}
