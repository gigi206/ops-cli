//! Integration test for the network-namespace holder (`__netns-holder`).
//!
//! Under a filtering network posture the cage runs in an empty network namespace, and the holder
//! adds a black-hole `dummy0` interface so a graphical agent reads as online — configured over
//! direct `NETLINK_ROUTE` (no host `ip` binary). This exercises the socket→kernel path the unit
//! tests cannot: they check only the byte layout of the messages, never that the kernel accepts
//! them and produces the expected namespace state.

#[macro_use]
mod common;

use common::fixture::TmpDir;
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
            // The separator the production wrapper always emits (`holder_wrap`), tap or no tap: it
            // is what makes the command unambiguous to parse. Without it the holder exits on a
            // usage error, which this helper would read as an environment gap and skip.
            "--",
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

/// A query to the cage's resolver is answered through the capture tap, over UDP, and the name
/// reaches the report socket the holder handed the tap.
///
/// The cage's resolver is off loopback (`nettap::CAGE_RESOLVER`), so a query leaves with `dummy0`'s
/// address as its source, the `nat` chain bends it to the tap, and the tap answers at that address.
/// A refusal chain that let through only what leaves for loopback, DNS or TCP rejected that answer,
/// and every client resolving over UDP waited out its timeout. The query is written by hand rather
/// than asked of `getent`, which would ask the host's resolver: that one is on loopback, and its
/// answer never met the refusal.
///
/// The report is sent from a thread of the tap's own after the answer, and the tap ends with the
/// command, so the command waits for the report to land before it exits.
///
/// The tap parses what the cage writes, so it runs caged: the command reads, from outside, what the
/// tap and each of its threads hold. Every one of them is under its filter with no new privileges
/// and no capability, and the tap sees a mount namespace of its own, not the holder's.
///
/// A tap that did not start or did not come up fails this test rather than skipping it. The
/// environment gaps the capture has say so in their own words, and still skip: a kernel that
/// refuses the redirect rules, and one without the `dummy` module, which leaves no route.
#[test]
fn the_tap_answers_a_query_to_the_cages_resolver_over_udp() {
    let python = std::path::Path::new("/usr/bin/python3");
    if !python.exists() {
        skip_incapable!("skipping tap DNS e2e: no /usr/bin/python3 to ask the query");
        return;
    }
    let Some(nft) = common::nft_on_path() else {
        skip_incapable!("skipping tap DNS e2e: no nft on PATH to install the redirect");
        return;
    };
    let Some(bwrap) = common::bwrap_on_path() else {
        skip_incapable!("skipping tap DNS e2e: no bwrap on PATH to cage the tap");
        return;
    };
    // The egress socket a captured connection would be handed to. A query is answered by the tap
    // alone, but the socket is real so the tap starts as a launch starts it.
    let dir = TmpDir::new("tapdns");
    let egress = dir.join("egress.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&egress).expect("bind egress socket");
    // The report socket: its first line is written to `reported`, which the command waits for.
    let report = dir.join("report.sock");
    let reported = dir.join("reported");
    let listener = std::os::unix::net::UnixListener::bind(&report).expect("bind report socket");
    {
        let reported = reported.clone();
        std::thread::spawn(move || {
            use std::io::BufRead;
            if let Ok((stream, _)) = listener.accept() {
                let mut line = String::new();
                let _ = std::io::BufReader::new(stream).read_line(&mut line);
                let _ = std::fs::write(&reported, line.trim());
            }
        });
    }
    let query = r#"
import os, socket, struct, sys, time
q = struct.pack(">HHHHHH", 0x5b5b, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.sendto(q, ("198.19.255.254", 53))
    r = s.recv(512)
except OSError as e:
    print("error", e.errno, e)
else:
    count = struct.unpack(">H", r[6:8])[0]
    print("answer", count, socket.inet_ntoa(r[-4:]) if count else "-")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not os.path.exists(sys.argv[1]):
        time.sleep(0.05)
    if os.path.exists(sys.argv[1]):
        print("reported", open(sys.argv[1]).read())
# The tap, found among this process's descendants (this process is the holder, become the command).
def children(pid):
    out = []
    for task in os.listdir(f"/proc/{pid}/task"):
        out += open(f"/proc/{pid}/task/{task}/children").read().split()
    return out
todo, tap = children(os.getpid()), None
while todo and tap is None:
    pid = todo.pop()
    # The tap itself, not the bwrap that cages it, whose own arguments name it too.
    if open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")[1:2] == [b"__net-tap"]:
        tap = pid
    else:
        todo += children(pid)
if tap is None:
    print("tap none")
else:
    for task in sorted(os.listdir(f"/proc/{tap}/task")):
        fields = dict(l.split(":\t", 1) for l in open(f"/proc/{tap}/task/{task}/status").read().splitlines() if ":\t" in l)
        print("thread", fields["NoNewPrivs"], fields["Seccomp_filters"], fields["CapEff"])
    own = os.readlink(f"/proc/{tap}/ns/mnt") != os.readlink("/proc/self/ns/mnt")
    print("tap mount", "own" if own else "shared")
"#;
    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(["__netns-holder", "--tap"])
        .arg(&egress)
        .arg("--bwrap")
        .arg(&bwrap)
        .arg("--nft")
        .arg(&nft)
        .arg("--report")
        .arg(&report)
        .arg("--")
        .arg(python)
        .args(["-c", query])
        .arg(&reported)
        .output()
        .expect("spawn sbx __netns-holder");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    for own in [
        "cannot start the capture tap",
        "the capture tap did not come up",
    ] {
        assert!(
            !stderr.contains(own),
            "the capture tap must stand up: {stderr}"
        );
    }
    if !out.status.success() || stderr.contains("transparent capture unavailable") {
        skip_incapable!(
            "skipping tap DNS e2e: the holder, the redirect or its route did not stand up ({})",
            stderr.trim()
        );
        return;
    }
    if stdout.starts_with(&format!("error {} ", libc::ENETUNREACH)) {
        skip_incapable!(
            "skipping tap DNS e2e: no route to the resolver (dummy module unavailable?)"
        );
        return;
    }
    // One address, out of the tap's own range (`198.18.0.0/15`).
    let answered = match stdout
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["answer", "1", addr] => addr.starts_with("198.18.") || addr.starts_with("198.19."),
        _ => false,
    };
    assert!(
        answered,
        "the tap's answer did not come back: {stdout}{stderr}"
    );
    assert!(
        stdout.lines().any(|l| l == "reported RESOLVED example.com"),
        "the name must reach the report socket: {stdout}{stderr}"
    );
    let threads: Vec<&str> = stdout
        .lines()
        .filter_map(|l| l.strip_prefix("thread "))
        .collect();
    assert!(
        !threads.is_empty(),
        "the tap was not found: {stdout}{stderr}"
    );
    // Four filters: the two every cage gets from its bwrap, and the tap's own two (the program that
    // answers `clone3`, then its list). Without its own, a tap would show the cage's two alone.
    for thread in &threads {
        assert_eq!(
            *thread, "1 4 0000000000000000",
            "every thread of the tap: no new privileges, its own filters, no capability: {stdout}"
        );
    }
    assert!(
        stdout.lines().any(|l| l == "tap mount own"),
        "the tap must not see the holder's mount namespace: {stdout}"
    );
}
