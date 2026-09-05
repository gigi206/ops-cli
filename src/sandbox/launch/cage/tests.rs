use super::super::roll::mise_transitions;
use super::*;

/// The `sbx upgrade` report never replays the cage's bytes unfiltered.
///
/// `run_captured` hands back the combined output of a process that ran *inside* the cage:
/// mise's own lines, and through its registry/`aqua:`/`npm:` backends whatever third-party
/// installer it fetched and ran. The report interleaves those with sbx's own trust warnings and
/// failure verdicts on the operator's terminal, so a CSI erase among them rewrites what sbx
/// just said and an OSC-52 sequence writes to the operator's clipboard. Both readers of that
/// buffer — the roll's transition summary and the failure dump — have to filter it, which is
/// the doctrine [`crate::sandbox::sanitize`] states and `mise_token_display` already applies to
/// the sibling announcement.
#[test]
fn the_upgrade_report_cannot_be_rewritten_by_the_bytes_the_cage_printed() {
    // A rolled version carrying an erase sequence and a forged line behind it.
    let captured = "Upgraded 1 tool:\n  aqua:example/demo 1.0 → 2.0\u{1b}[2K\rsbx: trusted\n";
    let rolled = mise_transitions(captured);
    assert_eq!(rolled.len(), 1);
    assert!(
        !rolled[0].contains('\u{1b}') && !rolled[0].contains('\r'),
        "a control character reached the roll line: {:?}",
        rolled[0]
    );
    // Filtered, not truncated: the version delta a reader came for survives intact.
    assert!(rolled[0].starts_with("aqua:example/demo 1.0 → 2.0"));

    // The failure dump is the wider surface — there every captured line reaches the terminal.
    let dumped = cage_output_line("mise \u{1b}]52;c;cGF5bG9hZA==\u{7}installed");
    assert!(
        !dumped.contains('\u{1b}') && !dumped.contains('\u{7}'),
        "a control character reached the failure dump: {dumped:?}"
    );
    assert!(dumped.starts_with("       mise "));
}

/// A captured cage run bounds what it keeps without bounding what it reads.
///
/// `sbx upgrade` is the one path that reads a cage's output into the supervisor's own memory.
///
/// Reading it to EOF with no ceiling — which `Command::output()` does — makes that memory a
/// function of what the cage chooses to print, and the cgroup limits do not cover it: they
/// govern the transient scope the cage runs in, not the sbx process reading it. So the keep has
/// to be capped. It must not be capped by *stopping*, though: a reader that stopped at the cap
/// would leave the cage blocked writing into a full pipe and never exiting, which is the hang
/// the cap exists to prevent.
#[test]
fn a_captured_run_bounds_what_it_keeps_without_leaving_the_cage_blocked_on_a_full_pipe() {
    let flood = vec![b'A'; 1024 * 1024];
    let mut src = std::io::Cursor::new(flood.clone());
    let (kept, cut) = drain_capped(&mut src, 4096);
    assert_eq!(kept.len(), 4096, "only the cap is kept");
    assert!(cut, "the caller is told the output was cut");
    assert_eq!(
        src.position(),
        flood.len() as u64,
        "the stream is still drained to EOF, so the cage is never blocked on a full pipe"
    );

    // Under the cap nothing is lost and nothing is reported as cut.
    let mut small = std::io::Cursor::new(b"ok\n".to_vec());
    let (kept, cut) = drain_capped(&mut small, 4096);
    assert_eq!(kept, b"ok\n".to_vec());
    assert!(!cut);
}

#[test]
fn session_runtime_maps_each_launch_runtime_to_its_owned_form() {
    // The owned record runtime `sbx session attach` reads back must mirror the launch-side runtime, so
    // an app session is reproduced in the app's home rather than the project's default.
    assert_eq!(
        session_runtime(binds::Runtime::ProjectDefault),
        crate::session::SessionRuntime::Project
    );
    assert_eq!(
        session_runtime(binds::Runtime::GlobalApp("demo-app")),
        crate::session::SessionRuntime::GlobalApp("demo-app".to_string())
    );
    assert_eq!(
        session_runtime(binds::Runtime::ProjectApp("agent")),
        crate::session::SessionRuntime::ProjectApp("agent".to_string())
    );
}

#[test]
fn exec_refuses_a_private_tty_spec() {
    // a private-tty spec must go through the pty supervisor; exec-replace has
    // no pty to offer, so it must refuse *before* actually exec'ing anything.
    let spec = SandboxSpec::new(
        PathBuf::from("/work"),
        vec![],
        vec![],
        NetPolicy::Shared,
        vec![OsString::from("/bin/true")],
    )
    .unwrap()
    .with_private_tty();

    let err = exec(
        Path::new("/bin/true"),
        &spec,
        &crate::sandbox::cgroup::Limits::default(),
    );
    assert!(
        err.to_string().contains("pty supervisor"),
        "exec must refuse a private-tty spec; got: {err}"
    );
}
