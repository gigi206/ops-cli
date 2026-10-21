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

/// Whether bwrap, run alone in the namespaces [`holder_argv`] asks for, runs `cmd` to success.
///
/// A holder run that never reached its command leaves that question. When bwrap cannot here, the
/// gap is this host's: a kernel or a policy that refuses an unprivileged user namespace, or a
/// command the host lacks. When it can, the holder is what failed — a usage error, an argument
/// list bwrap refuses, a crash — and the test fails rather than skips.
///
/// The question is asked with the test's own namespaces and command rather than by a generic probe
/// of user namespaces: the binary's own probe is out of an integration test's reach, and what is in
/// question is whether this cage, with this command, can run here.
fn bwrap_runs(bwrap: &std::path::Path, cmd: &[OsString]) -> bool {
    let argv = holder_argv(bwrap, cmd);
    Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Whether `nft`, run in a user and a network namespace of its own, installs a ruleset that asks
/// the kernel for what the holder's redirect asks: a `nat` chain that redirects, and a `filter`
/// chain that reads conntrack's `dnat` status and rejects.
///
/// A kernel built without them, or one that will not load them for an unprivileged namespace,
/// refuses both rulesets, and that refusal is this host's gap. A kernel that installs this one and
/// refuses the holder's has been handed a ruleset that is wrong. Asked through `unshare -rn`, which
/// maps this user to root in the new user namespace, as the configurer holds `CAP_NET_ADMIN` in the
/// one that owns the cage's network namespace: a command bwrap starts with `--cap-add` is refused
/// by nft there.
fn nft_redirects(nft: &std::path::Path) -> bool {
    use std::io::Write as _;
    const PROBE: &str = "table ip probe {\n  \
        chain o { type nat hook output priority dstnat; policy accept; \
        udp dport 53 redirect to :5353; }\n  \
        chain f { type filter hook output priority filter; policy accept; \
        ct status dnat accept; reject with icmp type net-unreachable; }\n}\n";
    let Ok(mut child) = Command::new("unshare")
        .arg("-rn")
        .arg(nft)
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return false;
    };
    let written = child
        .stdin
        .take()
        .is_some_and(|mut stdin| stdin.write_all(PROBE.as_bytes()).is_ok());
    child.wait().is_ok_and(|status| written && status.success())
}

/// The holder's output for `cmd`, a run of `__netns-holder`, read within a bound.
///
/// A holder that lets bwrap die before bwrap has signalled its child — of `SIGPIPE`, on a report
/// nobody reads — leaves that child waiting on bwrap for good, holding the two streams it
/// inherited, and `output` would wait for it until the job timed out. Here the wait for the streams
/// ends a few seconds after the holder does ([`common::procs::output_within`]), so the run reads as
/// one that never reached its command, and a holder still running past the bound fails the test.
fn holder_output(cmd: &mut Command) -> std::process::Output {
    common::procs::output_within(cmd, std::time::Duration::from_secs(60))
        .unwrap_or_else(|| panic!("the holder did not end within 60 s: {cmd:?}"))
}

/// Run the holder with a shell checker that dumps the two per-netns proc files, returning
/// `(dev, route)` — the contents of `/proc/net/dev` and `/proc/net/route` as seen *inside* the
/// configured namespace. `None` means skip, and every one is recorded as one: no bwrap on PATH, a
/// cage bwrap itself cannot create on this host ([`bwrap_runs`]), or a namespace the configurer
/// could not join, which leaves the cage in bwrap's empty one. Those are environment gaps. A holder
/// that did not run a command bwrap runs here fails the test, and so does a command that ran and
/// then failed, or whose output lacks the route table: the marker it prints first says it ran.
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
    let out = holder_output(
        Command::new(env!("CARGO_BIN_EXE_sbx"))
            // The separator the production wrapper always emits (`holder_wrap`), tap or no tap: it
            // is what makes the command unambiguous to parse. Without it the holder exits on a
            // usage error, which fails this helper.
            .args(["__netns-holder", "--"])
            .args(holder_argv(&bwrap, &cmd)),
    );

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr);
    // A failed join still releases the cage, into bwrap's empty namespace, and the command then
    // runs and succeeds: the message is what says so, whatever the status.
    if stderr.contains("could not be joined") {
        skip_incapable!(
            "skipping netns holder e2e: the holder could not join the namespace ({})",
            stderr.trim()
        );
        return None;
    }
    let Some((_, ran)) = stdout.split_once("---DEV---\n") else {
        assert!(
            !bwrap_runs(&bwrap, &cmd),
            "bwrap runs the command on this host, yet the holder did not ({}): {stdout}{stderr}",
            out.status
        );
        skip_incapable!(
            "skipping netns holder e2e: bwrap cannot cage the command on this host ({})",
            stderr.trim()
        );
        return None;
    };
    assert!(
        out.status.success(),
        "the command ran and failed ({}): {stdout}{stderr}",
        out.status
    );
    let (dev, route) = ran
        .split_once("---ROUTE---")
        .unwrap_or_else(|| panic!("the command's output has no route table: {stdout}{stderr}"));
    Some((dev.to_string(), route.to_string()))
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

/// `common::bwrap_on_path` and `common::nft_on_path` name the program a launch's search of `PATH`
/// would take: the first file this process may execute, in an absolute entry. One it may not
/// execute is no program that search takes, and a test that runs it itself waits on a program that
/// never started, as the stand-in below would, which `exec`s the bwrap it is given. An entry that
/// is not absolute names a directory relative to wherever the test runs, and that search reads
/// none.
#[test]
fn a_program_on_path_is_one_this_process_may_execute() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = TmpDir::new("onpath");
    let (unrunnable, runnable, reached) = (
        dir.join("unrunnable"),
        dir.join("runnable"),
        dir.join("reached"),
    );
    for (entry, mode) in [(&unrunnable, 0o644), (&runnable, 0o755), (&reached, 0o755)] {
        std::fs::create_dir(entry).unwrap();
        let program = entry.join("tool");
        std::fs::write(&program, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    let path = std::env::join_paths([&unrunnable, &runnable]).unwrap();
    assert_eq!(
        common::program_in("tool", &path),
        Some(runnable.join("tool")),
        "a file this process may not execute is passed over"
    );

    // `reached` named from the working directory: one `..` per level climbs to `/`, and the path
    // then descends from there. Its `tool` is executable, and the entry is still not read.
    let cwd = std::env::current_dir().expect("the working directory");
    let relative = std::iter::repeat_n(std::path::Path::new(".."), cwd.components().count())
        .collect::<std::path::PathBuf>()
        .join(
            reached
                .strip_prefix("/")
                .expect("a fixture path is absolute"),
        );
    assert!(relative.join("tool").is_file(), "{}", relative.display());
    let path = std::env::join_paths([&relative, &runnable]).unwrap();
    assert_eq!(
        common::program_in("tool", &path),
        Some(runnable.join("tool")),
        "an entry that is not absolute is not read"
    );
}

/// A stand-in for bwrap, written at `dir/slow-bwrap`, that makes the race of the test below
/// certain: it becomes `bwrap`, while a copy of it left behind writes bwrap's report to the holder
/// in the pieces bwrap writes it, with a pause after the first namespace id. It `exec`s `bwrap`
/// rather than starting it, so the process the report names is a child of the process the holder
/// started, as the holder checks it is. The copy ignores `SIGPIPE` and records in `dir/unread` each
/// piece it could not write, the pipe having no reader.
///
/// The copy holds the holder's output streams until it ends, so a test reading that output waits
/// for it. A `bwrap` that never writes a whole report — one that does not start, or that fails
/// before reporting — would keep it waiting for good, and the copy running long after the test, so
/// it gives up once the stand-in has run `give_up` seconds, and says so on the holder's error
/// stream.
fn report_stand_in(dir: &TmpDir, bwrap: &std::path::Path, give_up: u32) -> std::path::PathBuf {
    let slow = dir.join("slow-bwrap");
    // Every path is a shell word (`common::sh`): the fixture root comes from the environment, and a
    // quote or a `$` in it would otherwise end a string early or run as code.
    let script = format!(
        r#"#!/bin/bash
[ "$1" = --info-fd ] && [ "$3" = --block-fd ] || exit 99
info=$2; block=$4; shift 4
(
trap '' PIPE
until grep -q '}}' {report} 2>/dev/null; do
    if (( SECONDS >= {give_up} )); then
        echo "slow-bwrap: no whole report from bwrap within {give_up} s" >&2
        exit 98
    fi
    sleep 0.01
done
whole=$(cat {report})
pid_part=${{whole%%,*}}
rest=${{whole#"$pid_part"}}
tail_ns=${{rest#,}}; first_ns=",${{tail_ns%%,*}}"
printf '%s' "$pid_part" >&"$info" || echo first >>{unread}
printf '%s' "$first_ns" >&"$info" || echo second >>{unread}
sleep 1
printf '%s\n' "${{rest#"$first_ns"}}" >&"$info" || echo rest >>{unread}
) &
exec {bwrap} --info-fd 9 --block-fd "$block" "$@" 9>{report} {{info}}>&-
"#,
        bwrap = common::sh(bwrap),
        report = common::sh(&dir.join("report")),
        unread = common::sh(&dir.join("unread")),
    );
    std::fs::write(&slow, script).expect("write the stand-in");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&slow, std::fs::Permissions::from_mode(0o755))
            .expect("make the stand-in executable");
    }
    slow
}

/// The holder reads bwrap's `--info-fd` report to its end before it closes the pipe.
///
/// bwrap writes the report in several writes: the child's pid, each namespace id, the closing
/// brace. The pid is complete once the first namespace id follows it, and a holder that closed the
/// pipe then left bwrap's next write facing no reader. bwrap runs with `SIGPIPE` at its default, so
/// it died of the signal and the cage with it, before running anything — on a loaded host only,
/// where the holder won that race. The stand-in [`report_stand_in`] makes the race certain, and a
/// piece its copy records as unread is the write that killed bwrap: the failure.
#[test]
fn the_holder_waits_for_the_whole_bwrap_report() {
    let Some(bwrap) = common::bwrap_on_path() else {
        skip_incapable!("skipping the bwrap report race: no bwrap on PATH");
        return;
    };
    let dir = TmpDir::new("netns-report");
    let unread = dir.join("unread");
    // bwrap reports within moments of starting; the bound only keeps a bwrap that never does from
    // holding the test.
    let slow = report_stand_in(&dir, &bwrap, 30);
    let cmd = ["/bin/sh", "-c", "echo ran"].map(OsString::from);
    let mut argv = holder_argv(&bwrap, &cmd);
    argv[0] = slow.into();
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
        std::fs::read_to_string(&unread).unwrap_or_default(),
        "",
        "the holder closed the report before its end, so these pieces met no reader"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "ran",
        "{stderr}"
    );
}

/// The stand-in gives up on a `bwrap` that never reports, and the holder's output then ends: such
/// a `bwrap` fails the race test rather than holding it, and leaves no copy of the stand-in
/// running. The `bwrap` here is a file this process may not execute, so the stand-in's `exec`
/// fails at once and the holder ends with it; only the copy is left to wait.
#[test]
fn the_report_stand_in_gives_up_on_a_bwrap_that_never_starts() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = TmpDir::new("netns-giveup");
    let unrunnable = dir.join("bwrap");
    std::fs::write(&unrunnable, "#!/bin/sh\n").expect("write the bwrap");
    std::fs::set_permissions(&unrunnable, std::fs::Permissions::from_mode(0o644))
        .expect("make the bwrap unrunnable");
    let mut argv = holder_argv(&unrunnable, &[OsString::from("/bin/true")]);
    argv[0] = report_stand_in(&dir, &unrunnable, 1).into();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbx"));
    cmd.args(["__netns-holder", "--"]).args(argv);
    // The race test reads the holder's output with `output`, which waits for every holder of the
    // two streams, the copy among them: that wait is the one bounded here.
    let (sent, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sent.send(cmd.output());
    });
    let out = received
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("the stand-in's copy still holds the holder's output: it waits for a report")
        .expect("spawn sbx __netns-holder");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a bwrap that never started is a failure: {stderr}"
    );
    assert!(
        stderr.contains("slow-bwrap: no whole report from bwrap within 1 s"),
        "the stand-in says why it gave up: {stderr}"
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

/// How many seccomp filters the calling thread runs under, its status's `Seccomp_filters`. A process
/// it starts inherits them, under whatever it adds: a test run under a service manager's filter, or
/// inside a cage, starts from more than none.
fn own_seccomp_filters() -> u32 {
    std::fs::read_to_string("/proc/thread-self/status")
        .expect("this thread's status")
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp_filters:"))
        .and_then(|count| count.trim().parse().ok())
        .expect("a `Seccomp_filters` count in this thread's status")
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
/// A tap that did not start or did not come up fails this test rather than skipping it, and so
/// does a configurer that bwrap left without a report. The environment gaps the capture has say so
/// in their own words, and still skip: a namespace the configurer may not join, a kernel that
/// refuses what the redirect rules ask of it ([`nft_redirects`]), and one without the `dummy`
/// driver, which leaves no route. So does a
/// cage bwrap itself cannot create on this host ([`bwrap_runs`]); a holder that did not run a
/// command bwrap runs here is this test's failure. So is a command that ran and then failed — the
/// line it prints first says it ran — and no route on a kernel that has the driver.
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
    // SAFETY: `fstat` fills the zeroed `stat` on the stack for the open end.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(tap_fd, &mut st) }, 0);
    let tap_socket = format!("socket:[{}]", st.st_ino);
    let reported = dir.join("reported");
    // The reader is woken through a second handle once the run is over: the tap's end closing does
    // not end a receive on a datagram pair, so a report that never came would hold it for good.
    // Shutting the far end's reading side does, with nothing read.
    let waker = far.try_clone().expect("a second handle on the far end");
    let reader = {
        let reported = reported.clone();
        std::thread::spawn(move || {
            let mut datagram = [0u8; 512];
            if let Ok(n @ 1..) = far.recv(&mut datagram) {
                let line = String::from_utf8_lossy(&datagram[..n]);
                // Written whole under another name, then renamed: the command reads the file as
                // soon as its name appears, and one created but not yet written reads as empty.
                let staged = reported.with_extension("part");
                if std::fs::write(&staged, line.trim()).is_ok() {
                    let _ = std::fs::rename(&staged, &reported);
                }
            }
        })
    };
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
    deadline = time.monotonic() + 30
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
    let mut holder = Command::new(env!("CARGO_BIN_EXE_sbx"));
    holder
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
        ));
    // SAFETY: `fcntl` is async-signal-safe and allocates nothing. It clears the close-on-exec flag
    // of the tap's end in the child alone, so the holder inherits it while this process keeps the
    // flag: the other tests of this binary start commands of their own at the same time, and none
    // of them may inherit the end.
    unsafe {
        use std::os::unix::process::CommandExt as _;
        holder.pre_exec(move || match libc::fcntl(tap_fd, libc::F_SETFD, 0) {
            -1 => Err(std::io::Error::last_os_error()),
            _ => Ok(()),
        });
    }
    let out = holder_output(&mut holder);
    // SAFETY: `F_GETFD` reads the descriptor flags of this process's own open end.
    let flags = unsafe { libc::fcntl(tap_fd, libc::F_GETFD) };
    assert!(
        flags >= 0 && flags & libc::FD_CLOEXEC != 0,
        "the tap's end stays close-on-exec here, where another test's command could inherit it"
    );
    drop(tap_end);
    let _ = waker.shutdown(std::net::Shutdown::Read);
    reader.join().expect("the report reader");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    for own in [
        "cannot start the capture tap",
        "the capture tap did not come up",
        "bwrap did not report its sandbox",
    ] {
        assert!(
            !stderr.contains(own),
            "the capture tap must stand up: {stderr}"
        );
    }
    // The two gaps of this host's that the capture names in its warning. A route that could not be
    // installed is read below, from the query it leaves without one.
    if stderr.contains("nft refused the redirect rules") {
        assert!(
            !nft_redirects(&nft),
            "nft installs a redirect in a namespace of its own on this host, yet refused the \
             holder's rules: {stderr}"
        );
        skip_incapable!(
            "skipping tap DNS e2e: this kernel refuses the redirect ({})",
            stderr.trim()
        );
        return;
    }
    if stderr.contains("could not be joined") {
        skip_incapable!(
            "skipping tap DNS e2e: the holder could not join the namespace ({})",
            stderr.trim()
        );
        return;
    }
    let lines: Vec<&str> = stdout.lines().collect();
    let Some(ran) = lines.iter().position(|l| *l == "ran") else {
        assert!(
            !bwrap_runs(&bwrap, &[python.into(), "-c".into(), "pass".into()]),
            "bwrap runs python on this host, yet the holder did not run the command ({}): \
             {stdout}{stderr}",
            out.status
        );
        skip_incapable!(
            "skipping tap DNS e2e: bwrap cannot cage the command on this host ({})",
            stderr.trim()
        );
        return;
    };
    assert!(
        out.status.success(),
        "the command ran and failed ({}): {stdout}{stderr}",
        out.status
    );
    let reply = lines.get(ran + 1).copied().unwrap_or_default();
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
    // Four filters on top of those this thread runs under, which every process it starts inherits:
    // the two every cage gets from its bwrap, and the tap's own two (the program that answers
    // `clone3`, then its list). Without its own, a tap would show the cage's two alone.
    let expected = format!("1 {} 0000000000000000", own_seccomp_filters() + 4);
    for thread in &threads {
        assert_eq!(
            *thread, expected,
            "every thread of the tap: no new privileges, its own filters, no capability: {stdout}"
        );
    }
    assert!(
        stdout.lines().any(|l| l == "tap mount own"),
        "the tap must see its cage's mounts, not the holder's: {stdout}"
    );
}
