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
use std::ffi::OsString;
use std::process::Command;

/// The holder's argument list for `cmd`, run in a bwrap that creates the namespaces a launch's cage
/// gets — a user and a network namespace, and a fresh `/dev`, which is what has bwrap map root in
/// the user namespace the holder joins — over the host's read-only root, so `cmd` and the test's
/// files are found where they are.
fn holder_argv(bwrap: &std::path::Path, cmd: &[OsString]) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![bwrap.into()];
    argv.extend(
        [
            "--unshare-user",
            "--unshare-net",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--",
        ]
        .map(OsString::from),
    );
    argv.extend_from_slice(cmd);
    argv
}

/// Run the holder with a shell checker that dumps the two per-netns proc files, returning
/// `(dev, route)` — the contents of `/proc/net/dev` and `/proc/net/route` as seen *inside* the
/// configured namespace. `None` means skip, and every one is recorded as one: no bwrap on PATH, a
/// holder or a cage that never ran the command (this host cannot create a capability-bearing user
/// namespace, or has no `/bin/sh`), or a namespace the configurer could not join, which leaves the
/// cage in bwrap's empty one. Those are environment gaps. A command that ran and then failed, or
/// whose output lacks the route table, fails the test: its first line says it ran.
fn holder_dump() -> Option<(String, String)> {
    let Some(bwrap) = common::bwrap_on_path() else {
        skip_incapable!("skipping netns holder e2e: no bwrap on PATH to create the namespace");
        return None;
    };
    let cmd = [
        "/bin/sh",
        "-c",
        "echo ---DEV---; cat /proc/net/dev; echo ---ROUTE---; cat /proc/net/route",
    ]
    .map(OsString::from);
    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        // The separator the production wrapper always emits (`holder_wrap`), tap or no tap: it is
        // what makes the command unambiguous to parse. Without it the holder exits on a usage
        // error, which this helper would read as an environment gap and skip.
        .args(["__netns-holder", "--"])
        .args(holder_argv(&bwrap, &cmd))
        .output()
        .expect("spawn sbx __netns-holder");

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr);
    // A failed join still releases the cage, into bwrap's empty namespace, and the command then
    // runs and succeeds: the message is what says so, whatever the status.
    if stderr.contains("could not be joined") || !stdout.starts_with("---DEV---\n") {
        skip_incapable!(
            "skipping netns holder e2e: the holder did not run ({}{})",
            stdout,
            stderr.trim()
        );
        return None;
    }
    assert!(
        out.status.success(),
        "the command ran and failed ({}): {stdout}{stderr}",
        out.status
    );
    let (dev, route) = stdout
        .split_once("---ROUTE---")
        .unwrap_or_else(|| panic!("the command's output has no route table: {stdout}{stderr}"));
    let dev = dev.strip_prefix("---DEV---").unwrap_or(dev).to_string();
    Some((dev, route.to_string()))
}

/// Whether this kernel has the `dummy` driver once the holder has asked it for a `dummy` link:
/// loaded (`/sys/module/dummy`), or built in (`modules.builtin` lists it). The holder reports no
/// failure of its own there, so a cage without `dummy0` is a host gap only when this is false: a
/// kernel without the driver, or one that did not load it. With the driver, it is the holder's.
fn kernel_has_dummy() -> bool {
    if std::path::Path::new("/sys/module/dummy").exists() {
        return true;
    }
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    std::fs::read_to_string(format!("/lib/modules/{}/modules.builtin", release.trim()))
        .is_ok_and(|list| list.lines().any(|l| l == "kernel/drivers/net/dummy.ko"))
}

/// The holder reads bwrap's `--info-fd` report to its end before it closes the pipe.
///
/// bwrap writes the report in several writes: the child's pid, each namespace id, the closing
/// brace. The pid is complete once the first namespace id follows it, and a holder that closed the
/// pipe then left bwrap's next write facing no reader. bwrap runs with `SIGPIPE` at its default, so
/// it died of the signal and the cage with it, before running anything — on a loaded host only,
/// where the holder won that race. A stand-in for bwrap makes the race certain: it runs the
/// real one, then writes its report in the same pieces with a pause after the first namespace id.
#[test]
fn the_holder_waits_for_the_whole_bwrap_report() {
    let Some(bwrap) = common::bwrap_on_path() else {
        skip_incapable!("skipping the bwrap report race: no bwrap on PATH");
        return;
    };
    let dir = TmpDir::new("netns-report");
    let report = dir.join("report");
    let slow = dir.join("slow-bwrap");
    let script = format!(
        r#"#!/bin/bash
[ "$1" = --info-fd ] && [ "$3" = --block-fd ] || exit 99
info=$2; block=$4; shift 4
"{bwrap}" --info-fd 9 --block-fd "$block" "$@" 9>"{report}" &
bw=$!
until grep -q '}}' "{report}" 2>/dev/null; do sleep 0.01; done
whole=$(cat "{report}")
pid_part=${{whole%%,*}}
rest=${{whole#"$pid_part"}}
tail_ns=${{rest#,}}; first_ns=",${{tail_ns%%,*}}"
printf '%s' "$pid_part" >&"$info"
printf '%s' "$first_ns" >&"$info"
sleep 1
printf '%s\n' "${{rest#"$first_ns"}}" >&"$info"
eval "exec $info>&-"
wait $bw
"#,
        bwrap = bwrap.display(),
        report = report.display(),
    );
    std::fs::write(&slow, script).expect("write the stand-in");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&slow, std::fs::Permissions::from_mode(0o755))
            .expect("make the stand-in executable");
    }
    let cmd = ["/bin/sh", "-c", "echo ran"].map(OsString::from);
    let mut argv = holder_argv(&bwrap, &cmd);
    argv[0] = slow.clone().into();
    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(["__netns-holder", "--"])
        .args(argv)
        .output()
        .expect("spawn sbx __netns-holder");
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("could not be joined") {
        skip_incapable!(
            "skipping the bwrap report race: the holder could not join the namespace ({})",
            stderr.trim()
        );
        return;
    }
    assert!(
        out.status.success(),
        "bwrap must outlive the end of its own report, not die of SIGPIPE ({}): {stderr}",
        out.status
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "ran",
        "{stderr}"
    );
}

#[test]
fn the_holder_configures_a_black_hole_dummy_via_rtnetlink() {
    let Some((dev, route)) = holder_dump() else {
        return;
    };

    // `/proc/net/dev` is per-netns, so seeing `dummy0` proves the `RTM_NEWLINK` create landed in the
    // fresh namespace. Production treats a kernel without the `dummy` driver as acceptable
    // loopback-only degradation, so that one skips. A kernel that has it fails here instead: the
    // holder says nothing when a create fails, and a regression in the netlink path would otherwise
    // read as the missing driver.
    let dummy0_present = dev
        .lines()
        .any(|l| l.split(':').next().is_some_and(|n| n.trim() == "dummy0"));
    if !dummy0_present {
        assert!(
            !kernel_has_dummy(),
            "this kernel has the dummy driver, yet the holder left no dummy0 in the namespace:\n{dev}"
        );
        skip_incapable!(
            "skipping netns holder e2e: dummy0 absent, with no dummy driver loaded, even after the \
             holder asked, and none built in"
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
/// reaches the report channel the holder handed the tap.
///
/// The cage's resolver is off loopback (`nettap::CAGE_RESOLVER`), so a query leaves with `dummy0`'s
/// address as its source, the `nat` chain bends it to the tap, and the tap answers at that address.
/// A refusal chain that let through only what leaves for loopback, DNS or TCP rejected that answer,
/// and every client resolving over UDP waited out its timeout. The query is written by hand rather
/// than asked of `getent`, which would ask the host's resolver: that one is on loopback, and its
/// answer never met the refusal.
///
/// The report is sent from a thread of the tap's own after the answer, and the tap ends with the
/// command, so the command waits for the report to land before it exits. It travels down the end
/// of the report channel the holder was handed on a descriptor, as a launch hands it, and the
/// holder adopts that end close-on-exec: the command, which stands where the cage's bwrap stands
/// in a launch, holds no descriptor onto it.
///
/// The tap parses what the cage writes, so it runs caged: the command reads, from outside, what
/// each of the tap's threads holds and which mounts the tap sees. Every thread is under its filter
/// with no new privileges and no capability, and the tap's mounts hold the egress socket its cage
/// binds, which the holder's do not. The mounts are read from `mountinfo`, which any process may
/// read, rather than compared through the namespace link, which takes a ptrace read access the
/// command does not have on every host.
///
/// A tap that did not start or did not come up fails this test rather than skipping it. The
/// environment gaps the capture has say so in their own words, and still skip: a kernel that
/// refuses the redirect rules, and one without the `dummy` driver, which leaves no route. So does a
/// holder or a cage that never ran the command. A command that ran and then failed is this test's
/// failure: its first line says it ran. So is no route on a kernel that has the driver.
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
    // The report channel, as a launch makes it: the holder inherits the tap's end, and the first
    // report the far end reads is written to `reported`, which the command waits for.
    let (tap_end, far) = std::os::unix::net::UnixDatagram::pair().expect("a report channel");
    let tap_fd = std::os::fd::AsRawFd::as_raw_fd(&tap_end);
    // SAFETY: `F_SETFD` on this process's own open descriptor clears its close-on-exec flag, so
    // the holder inherits it; the far end keeps the flag and stays here.
    assert_eq!(unsafe { libc::fcntl(tap_fd, libc::F_SETFD, 0) }, 0);
    // SAFETY: `fstat` fills the zeroed `stat` on the stack for the open end.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(tap_fd, &mut st) }, 0);
    let tap_socket = format!("socket:[{}]", st.st_ino);
    let reported = dir.join("reported");
    {
        let reported = reported.clone();
        std::thread::spawn(move || {
            let mut datagram = [0u8; 512];
            if let Ok(n) = far.recv(&mut datagram) {
                let line = String::from_utf8_lossy(&datagram[..n]);
                let _ = std::fs::write(&reported, line.trim());
            }
        });
    }
    let query = r#"
import os, socket, struct, sys, time
print("ran", flush=True)
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
# The tap, found among the descendants of this process's parent: the holder, become bwrap, whose
# configurer started it.
def children(pid):
    out = []
    for task in os.listdir(f"/proc/{pid}/task"):
        out += open(f"/proc/{pid}/task/{task}/children").read().split()
    return out
todo, tap = children(os.getppid()), None
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
    # The mount points each process sees, relative to its own root: the tap's cage binds the egress
    # socket at `/egress.sock`, and the holder, become bwrap, sees the host's mounts.
    def mounts(pid):
        return [line.split()[4] for line in open(f"/proc/{pid}/mountinfo")]
    own = "/egress.sock" in mounts(tap) and "/egress.sock" not in mounts(os.getppid())
    print("tap mount", "own" if own else "shared")
held = False
for fd in os.listdir("/proc/self/fd"):
    try:
        held = held or os.readlink(f"/proc/self/fd/{fd}") == sys.argv[2]
    except OSError:
        pass
print("report fd", "held" if held else "closed")
"#;
    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(["__netns-holder", "--tap"])
        .arg(&egress)
        .arg("--bwrap")
        .arg(&bwrap)
        .arg("--nft")
        .arg(&nft)
        .arg("--report-fd")
        .arg(tap_fd.to_string())
        .arg("--")
        .args(holder_argv(
            &bwrap,
            &[
                python.into(),
                "-c".into(),
                query.into(),
                reported.clone().into(),
                tap_socket.clone().into(),
            ],
        ))
        .output()
        .expect("spawn sbx __netns-holder");
    drop(tap_end);
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
    // Only a holder or a cage that never ran the command is a gap of this host's. A command that
    // ran and then failed is this test's failure, whatever it wrote.
    if stderr.contains("transparent capture unavailable") || !stdout.starts_with("ran\n") {
        skip_incapable!(
            "skipping tap DNS e2e: the holder, the redirect or its route did not stand up ({}{})",
            stdout,
            stderr.trim()
        );
        return;
    }
    assert!(
        out.status.success(),
        "the command ran and failed ({}): {stdout}{stderr}",
        out.status
    );
    let reply = stdout.lines().nth(1).unwrap_or_default();
    if reply.starts_with(&format!("error {} ", libc::ENETUNREACH)) {
        assert!(
            !kernel_has_dummy(),
            "this kernel has the dummy driver, yet the cage has no route to the resolver: \
             {stdout}{stderr}"
        );
        skip_incapable!(
            "skipping tap DNS e2e: no route to the resolver, with no dummy driver loaded, even \
             after the holder asked, and none built in"
        );
        return;
    }
    // One address, out of the tap's own range (`198.18.0.0/15`).
    let answered = match reply.split_whitespace().collect::<Vec<_>>().as_slice() {
        ["answer", "1", addr] => addr.starts_with("198.18.") || addr.starts_with("198.19."),
        _ => false,
    };
    assert!(
        answered,
        "the tap's answer did not come back: {stdout}{stderr}"
    );
    assert!(
        stdout.lines().any(|l| l == "reported RESOLVED example.com"),
        "the name must reach the report channel: {stdout}{stderr}"
    );
    assert!(
        stdout.lines().any(|l| l == "report fd closed"),
        "the holder must keep the report channel's end from the command it becomes: {stdout}"
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
        "the tap must see its cage's mounts, not the holder's: {stdout}"
    );
}
