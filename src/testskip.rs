// The one definition of "this test did not run", shared by the unit tests and the integration
// tests.
//
// `cargo test` has no outcome for a precondition that fails at **runtime**. A test that finds its
// prerequisites absent returns early, and the harness counts it **passed**; libtest captures what
// it printed, so a passing run shows nothing at all. On a host without userns, bwrap or nix, that
// turns a suite into a green report of work it never did. `#[ignore]` is the only skip the harness
// shows, and it is decided at compile time, which is no help for a host capability.
//
// Two macros, because the two reasons are not the same promise:
//
// * [`skip_incapable!`] — the **host** cannot run this test: no userns, no bwrap, no nix, no
//   provisioned userland, no systemd. A host that is supposed to be capable can be made to prove
//   it: with `SBX_REQUIRE_CAPABLE` set to anything but `0`, this skip becomes a failure.
// * [`skip_unreachable!`] — something **outside** the host is unavailable: a binary cache, a
//   registry, the network. No host setting makes that dependable, so it is never enforced; it is
//   only counted, because a suite that skipped forty tests on a bad network should say so.
//
// Both record the skip when `SBX_SKIP_LOG` names a file: one line appended per skip, so a run can
// report how many of its green tests did nothing. The write is a single `write_all` of one line to
// a handle opened `O_APPEND`, which is what keeps it correct across the parallel test binaries.
//
// This file is **included**, not linked: the integration tests are separate crates and cannot see
// into the binary, so `src/testutil.rs` and `tests/common/mod.rs` both `include!` this text. One
// definition, two compilations — a second copy would drift, and a skip counted by one half of the
// suite and not the other is worse than no count at all.

/// Record one skip, and enforce it when the caller says the host was supposed to manage.
///
/// Not called directly: [`skip_incapable!`] and [`skip_unreachable!`] are the two spellings, and
/// which one a site uses is the whole point — it says whether a capable host could have run it.
#[allow(unused_macros)]
macro_rules! __skip_note {
    ($enforced:expr, $($arg:tt)*) => {{
        let reason = format!($($arg)*);
        eprintln!("{reason}");
        if let Some(path) = std::env::var_os("SBX_SKIP_LOG") {
            use std::io::Write as _;
            let line = format!("{reason}\n");
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
                let _ = f.write_all(line.as_bytes());
            }
        }
        if $enforced
            && std::env::var_os("SBX_REQUIRE_CAPABLE").is_some_and(|v| !v.is_empty() && v != "0")
        {
            panic!(
                "SBX_REQUIRE_CAPABLE is set, so this host was expected to run the test, and it \
                 could not: {reason}"
            );
        }
    }};
}

/// This **host** cannot run the test: userns, bwrap, nix, systemd or a provisioned userland is
/// missing. Enforceable — `SBX_REQUIRE_CAPABLE=1` turns it into a failure.
///
/// Formats like `eprintln!`. Does not return: the caller keeps its own `return`, so reading the
/// site still shows where the test stops.
#[allow(unused_macros)]
macro_rules! skip_incapable {
    ($($arg:tt)*) => { __skip_note!(true, $($arg)*) };
}

/// Something **outside** the host is unavailable: a binary cache, a registry, the network. Counted,
/// never enforced — no setting on this machine makes a remote dependable.
///
/// Formats like `eprintln!`. Does not return: the caller keeps its own `return`.
#[allow(unused_macros)]
macro_rules! skip_unreachable {
    ($($arg:tt)*) => { __skip_note!(false, $($arg)*) };
}
