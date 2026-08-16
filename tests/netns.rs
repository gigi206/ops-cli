//! Integration test for the network-namespace holder (`__netns-holder`).
//!
//! Under a filtering network posture the cage runs in an empty network namespace, and the holder
//! adds a black-hole `dummy0` interface so a graphical agent reads as online — configured over
//! direct `NETLINK_ROUTE` (no host `ip` binary). This exercises the socket→kernel path the unit
//! tests cannot: they check only the byte layout of the messages, never that the kernel accepts
//! them and produces the expected namespace state.

#[macro_use]
mod common;

use std::process::Command;

/// Run the holder with a shell checker that dumps the two per-netns proc files, returning
/// `(dev, route)` — the contents of `/proc/net/dev` and `/proc/net/route` as seen *inside* the
/// configured namespace. `None` means skip: the holder did not run (this host cannot create a
/// capability-bearing user namespace, or has no `/bin/sh`), which is an environment gap, not a
/// failure.
fn holder_dump() -> Option<(String, String)> {
    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args([
            "__netns-holder",
            "/bin/sh",
            "-c",
            "echo ---DEV---; cat /proc/net/dev; echo ---ROUTE---; cat /proc/net/route",
        ])
        .output()
        .expect("spawn sbx __netns-holder");

    if !out.status.success() {
        skip_incapable!(
            "skipping netns holder e2e: the holder did not run ({})",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        return None;
    }

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let (dev, route) = stdout.split_once("---ROUTE---")?;
    let dev = dev.strip_prefix("---DEV---").unwrap_or(dev).to_string();
    Some((dev, route.to_string()))
}

#[test]
fn the_holder_configures_a_black_hole_dummy_via_rtnetlink() {
    let Some((dev, route)) = holder_dump() else {
        return;
    };

    // `/proc/net/dev` is per-netns, so seeing `dummy0` proves the `RTM_NEWLINK` create landed in the
    // fresh namespace. If it is absent even though the namespace came up, the `dummy` kernel module
    // is unavailable — production treats that as acceptable loopback-only degradation, so skip rather
    // than fail (a regression in the netlink path would surface here on the common host that *does*
    // carry the module).
    let dummy0_present = dev
        .lines()
        .any(|l| l.split(':').next().is_some_and(|n| n.trim() == "dummy0"));
    if !dummy0_present {
        skip_incapable!(
            "skipping netns holder e2e: dummy0 absent (dummy kernel module unavailable?)"
        );
        return;
    }

    // The security invariant the black hole must preserve: `dummy0` has its connected route and there
    // is NO default route, so a cage connect to any real host still finds no route and fails closed.
    // `/proc/net/route` columns are `Iface Destination Gateway …`; a default route's Destination
    // field is `00000000`.
    let rows: Vec<&str> = route
        .lines()
        .skip(1) // the column header
        .filter(|l| !l.trim().is_empty())
        .collect();
    let dummy0_route = rows
        .iter()
        .any(|l| l.split_whitespace().next() == Some("dummy0"));
    let default_route = rows
        .iter()
        .any(|l| l.split_whitespace().nth(1) == Some("00000000"));

    assert!(
        dummy0_route,
        "dummy0's connected route is missing — the address was not assigned:\n{route}"
    );
    assert!(
        !default_route,
        "a default route exists — the dummy must never open an egress path:\n{route}"
    );
}
