//! Integration tests for `sbx fs` — the filesystem-observation CLI wiring: session resolution and the
//! error paths for `logs`, plus a cage-backed e2e for the detached file-write ring read over the
//! control socket. The pure error paths run against an isolated (empty) data directory (no sandbox);
//! the cage-backed one skips where the host cannot sandbox.

#[macro_use]
mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

// The fixtures' root, one definition shared with the unit tests.
include!("../src/testroot.rs");

struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut d = fixture_root();
        d.push(format!("f-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        TmpDir(d)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        force_remove(&self.0);
    }
}

/// Remove a tree that may contain read-only directories (a provisioned nix store makes its
/// directories `0555`): add write on the way down before deleting.
fn force_remove(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                force_remove(&entry.path());
            }
        }
        let _ = std::fs::remove_dir(path);
    } else {
        let _ = std::fs::remove_file(path);
    }
}

/// Run `sbx <args>` with an isolated, empty data directory so the session registry is empty and the
/// outcome is deterministic regardless of the host's real sessions.
fn sbx(args: &[&str], data: &Path, cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(args)
        .current_dir(cwd)
        .env("XDG_DATA_HOME", data)
        .env("LC_ALL", "C.UTF-8")
        .output()
        .expect("run sbx")
}

#[test]
fn fs_logs_with_no_sessions_reports_none_and_exits_2() {
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(&["fs", "logs"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("no active sandbox sessions"), "got: {err}");
}

#[test]
fn fs_logs_rejects_a_second_id() {
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(&["fs", "logs", "1", "2"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("at most one session id"), "got: {err}");
}

#[test]
fn fs_with_no_subcommand_prints_usage() {
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(&["fs"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("sbx fs"), "usage should name `sbx fs`: {err}");
}

#[test]
fn fs_unknown_subcommand_is_an_error() {
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(&["fs", "bogus"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("unknown subcommand"), "got: {err}");
}

/// Read a process's start-time ticks (`/proc/<pid>/stat` field 22) for the fabricated record.
fn read_start_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read stat");
    let after = &stat[stat.rfind(')').unwrap() + 1..];
    after.split_whitespace().nth(19).unwrap().parse().unwrap()
}

/// Write the session record `sbx fs logs` resolves, pointing at a live `pid`. A fabricated record (the
/// on-disk format is stable) isolates the property under test — the socket-missing path — from the
/// session-registration machinery, which is exercised elsewhere.
fn write_session_record(data: &Path, pid: u32, project: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let start = read_start_ticks(pid);
    let dir = data.join("sbx").join("sessions");
    std::fs::create_dir_all(&dir).unwrap();
    let hex: String = project
        .as_os_str()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let rec = format!("kind=run\npid={pid}\nstart={start}\nruntime=project\nproject={hex}\n");
    std::fs::write(dir.join(format!("{pid}-{start}")), rec).unwrap();
}

#[test]
fn fs_logs_reports_an_unobserved_session() {
    // A live session that was NOT launched with observation has no filesystem control socket, so
    // `sbx fs logs` reports it as unobserved (exit 2) rather than showing an empty feed. Fabricate a
    // record pointing at a plain live process (a `sleep`) — no cage, no socket — to isolate the
    // socket-missing path from the launch machinery. No sandbox needed.
    let (data, project) = (TmpDir::new(), TmpDir::new());
    let mut child = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sleep");
    let pid = child.id();
    write_session_record(data.path(), pid, project.path());

    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(["fs", "logs", &pid.to_string()])
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("run sbx fs logs");
    let _ = child.kill();
    let _ = child.wait();

    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(
        err.contains("is not being observed"),
        "an unobserved session should be named as such, not shown empty: {err}"
    );
}

/// A `Command` for the built binary with an isolated global config dir, so the cage-launching e2e
/// never depends on the developer's `~/.config/sbx`.
fn sbx_isolated() -> Command {
    let cfg = fixture_root().join("fs-isolated-config");
    let _ = std::fs::create_dir_all(&cfg);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbx"));
    cmd.env("XDG_CONFIG_HOME", cfg);
    cmd
}

/// Whether the host can launch a sandbox (also warms the userland cache so the real launch below
/// starts promptly).
fn host_can_sandbox(project: &Path, data: &Path) -> bool {
    sbx_isolated()
        .args(["run", "--", "true"])
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Extract the pid from the detached-launch line `sbx: started `run` as detached session <pid> …`.
fn parse_detached_pid(msg: &str) -> Option<u32> {
    let after = msg.split("detached session ").nth(1)?;
    after
        .split(|c: char| !c.is_ascii_digit())
        .find(|s| !s.is_empty())?
        .parse()
        .ok()
}

#[test]
fn detached_observe_records_fs_writes_for_fs_logs() {
    // The load-bearing property of this increment: a DETACHED session — which has no terminal for an
    // inline feed — still records the files it writes in its project tree, readable from a separate
    // process via `sbx fs logs` over the per-session control socket. The cage binds the project
    // read-write at its own host path, so a write the agent makes lands on the same host inode the
    // supervisor's inotify watches — visible across the mount namespace. Launch a detached observed run
    // that writes a recognizable marker into the project, then read the fs ring back and assert the
    // marker appears. This is the ONLY channel a detached session has (no inline feed), and it
    // exercises the whole chain: the synchronous initial inotify watch, force-supervision on the
    // detached path, the fs ring, the bound socket, and the `sbx fs logs` client. Skipped, not failed,
    // where the host cannot sandbox.
    let (project, data) = (TmpDir::new(), TmpDir::new());
    if !host_can_sandbox(project.path(), data.path()) {
        skip_incapable!("skipping detached fs --observe e2e: host cannot sandbox");
        return;
    }

    // Detached + observed: write a marker into the project (the cage's cwd is the project, bound rw at
    // its own path), then `sleep 30` so the session lives well past our reads.
    let started = sbx_isolated()
        .args([
            "run",
            "--detach",
            "--observe",
            "--",
            "sh",
            "-c",
            "echo hi > marker.txt; sleep 30",
        ])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("run --detach --observe");
    let msg = String::from_utf8_lossy(&started.stderr).into_owned();
    assert!(started.status.success(), "detached launch failed:\n{msg}");
    let pid =
        parse_detached_pid(&msg).unwrap_or_else(|| panic!("no detached session pid in:\n{msg}"));

    // Poll `sbx fs logs <pid>` until the marker write appears in the fs ring — read over the socket,
    // the ONLY channel for a detached session. A stunted watcher never converges and the assertion
    // below fires with the last output.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = String::new();
    let mut ok = false;
    while Instant::now() < deadline {
        let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
            .args(["fs", "logs", &pid.to_string()])
            .env("XDG_DATA_HOME", data.path())
            .output()
            .expect("run sbx fs logs");
        last = String::from_utf8_lossy(&out.stdout).into_owned();
        if out.status.code() == Some(0) && last.contains("marker.txt") {
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    // Stop the detached session before asserting, so a failure never leaks a background cage.
    let _ = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(["session", "stop", &pid.to_string()])
        .env("XDG_DATA_HOME", data.path())
        .output();

    assert!(
        ok,
        "the detached observed session's write to `marker.txt` must appear in `sbx fs logs` (read over \
         the control socket — a detached session has no inline feed). Last output:\n{last}"
    );
}

#[test]
fn fs_scan_lets_the_cage_make_files_inside_it_and_nowhere_else() {
    // The probe that examines a path opens it `O_PATH`, which creates nothing, so a creating open
    // finds its name absent and was told so — measured against a control arm, a cage under
    // `[fs] scan` could not write a single new file, which is most of what a build does.
    //
    // Both halves have teeth. Creating has to work, `..` included; and it must not become a way out,
    // since a file made through a walk that left the cage's mounts would land on the host.
    let (project, data, outside) = (TmpDir::new(), TmpDir::new(), TmpDir::new());
    if !host_can_sandbox(project.path(), data.path()) {
        skip_incapable!("skipping `[fs] scan` creation e2e: host cannot sandbox");
        return;
    }
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[fs]\nscan = [\"sk-[A-Za-z0-9]{12,}\"]\n",
    )
    .expect("write the project config");
    std::fs::write(
        project.path().join("carries.txt"),
        "API key: sk-ABC123DEF456GHI789\n",
    )
    .expect("write the matching fixture");
    std::fs::create_dir(project.path().join("sub")).expect("make the subdirectory");

    let elsewhere = outside
        .path()
        .to_str()
        .expect("utf-8 fixture path")
        .to_string();
    let script = format!(
        "echo un > made.txt; echo made=$?; cat made.txt; \
         echo deux >> made.txt; echo appended=$?; \
         (cd sub && echo trois > ../over.txt); echo dotdot=$?; \
         ls {elsewhere} >/dev/null 2>&1; echo sees_outside=$?; \
         ln -s {elsewhere} out; echo quatre > out/escaped.txt; echo escape=$?; \
         cat carries.txt 2>&1; echo done"
    );
    let out = sbx_isolated()
        .args(["run", "--", "sh", "-c", &script])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("run the cage");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let said = |key: &str| -> Option<&str> {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::trim)
    };

    assert_eq!(
        said("made="),
        Some("0"),
        "a name that is not there yet must be made rather than reported absent.\nstdout: {stdout}\n\
         stderr: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join("made.txt")).ok(),
        Some("un\ndeux\n".to_string()),
        "the file served to the cage has to be the one that appeared on disk, and an append after \
         it has to reach the same file.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert_eq!(
        said("appended="),
        Some("0"),
        "appending to what was just made must work too.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert_eq!(
        said("dotdot="),
        Some("0"),
        "a name reached through `..` is inside the cage as much as any other.\nstdout: {stdout}\n\
         stderr: {stderr}"
    );
    // The premise of the arm below, asserted rather than assumed: a directory the cage can already
    // see would make "nothing was created there" true for a reason that has nothing to do with the
    // guard.
    assert_ne!(
        said("sees_outside="),
        Some("0"),
        "this fixture only means something while the cage cannot reach it by name.\nstdout: \
         {stdout}\nstderr: {stderr}"
    );
    assert!(
        !outside.path().join("escaped.txt").exists(),
        "the cage made a file outside itself by naming a directory through an absolute symlink.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("sk-ABC123DEF456GHI789"),
        "creating must not have become a way to read: the matching file is still refused.\nstdout: \
         {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("done"),
        "the payload must reach its last line.\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn fs_scan_leaves_the_cage_its_own_proc_self() {
    // `/proc/self` is answered with the number of whoever performs the lookup, in the namespace the
    // `/proc` being walked belongs to. The supervisor is in neither of the cage's, so a path it
    // examines on the cage's behalf finds nothing there — and the cage, whose own open would have
    // succeeded, is told the file is not there. Every program that reads its own maps, status or
    // command line meets that.
    //
    // Teeth: the answer has to be the *cage's*. A supervisor answering with its own entry satisfies
    // "the read succeeded" while handing over something from outside the cage entirely.
    let (project, data) = (TmpDir::new(), TmpDir::new());
    if !host_can_sandbox(project.path(), data.path()) {
        skip_incapable!("skipping `[fs] scan` `/proc/self` e2e: host cannot sandbox");
        return;
    }
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[fs]\nscan = [\"sk-[A-Za-z0-9]{12,}\"]\n",
    )
    .expect("write the project config");

    let out = sbx_isolated()
        .args([
            "run",
            "--",
            "sh",
            "-c",
            // Named outright, and reached through the links `/dev` carries — `/dev/stdout` and
            // `/dev/fd` point into `/proc/self/fd`, so nothing in those names says `self` at all.
            "cat /proc/self/comm; head -1 /proc/thread-self/comm; echo viadev > /dev/stdout; \
             echo viafd > /dev/fd/1",
        ])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("run the cage");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        vec!["cat", "head", "viadev", "viafd"],
        "each program must read its own name under both spellings — `cat` for the one that named \
         `self` and `head` for the one that named `thread-self` — and a write aimed at the cage's \
         own output through `/dev` has to land in it rather than anywhere else.\nstdout: {stdout}\n\
         stderr: {stderr}"
    );
}

#[test]
fn fs_scan_never_serves_the_cage_an_object_from_outside_it() {
    // The supervisor resolves a notified open through `/proc/<pid>/root`, which starts the walk on
    // the cage's own mounts. A symlink whose target begins with `/` ends it somewhere else: such a
    // target restarts resolution at the root of whoever is resolving, and that is the supervisor.
    // A cage that plants one therefore names a path and receives the host's object at it — its
    // `/proc/self/comm` is the supervisor's, and `/dev/stdout` is the supervisor's descriptor.
    //
    // Teeth on both sides. The first arm fails if anything from outside crosses; the second fails if
    // the fix bought that by refusing more, since a secret named through an absolute link must still
    // be scanned and refused rather than quietly let past on a second, unexamined resolution.
    let (project, data) = (TmpDir::new(), TmpDir::new());
    if !host_can_sandbox(project.path(), data.path()) {
        skip_incapable!("skipping `[fs] scan` boundary e2e: host cannot sandbox");
        return;
    }

    std::fs::write(
        project.path().join(".sbx.toml"),
        "[fs]\nscan = [\"sk-[A-Za-z0-9]{12,}\"]\n",
    )
    .expect("write the project config");
    std::fs::write(
        project.path().join("carries.txt"),
        "API key: sk-ABC123DEF456GHI789\n",
    )
    .expect("write the matching fixture");
    std::fs::write(project.path().join("ordinary.txt"), "no credential here\n")
        .expect("write the clean fixture");

    let inside = project
        .path()
        .join("carries.txt")
        .to_str()
        .expect("utf-8 fixture path")
        .to_string();
    let script = format!(
        "ln -s /proc/self/comm outside; cat outside; \
         ln -s {inside} named_absolutely; cat named_absolutely; \
         cat ordinary.txt"
    );
    let out = sbx_isolated()
        .args(["run", "--", "sh", "-c", &script])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("run the cage");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !stdout.contains("sbx"),
        "the cage read the supervisor's own `/proc/self/comm` through a link it planted, so an \
         absolute symlink target is still being resolved against the supervisor's root.\nstdout: \
         {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("sk-ABC123DEF456GHI789"),
        "the matching file reached the cage when named through an absolute symlink, so the second \
         resolution served what the first had not examined.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("its content matches") && stderr.contains("named_absolutely"),
        "the refusal must name the link the cage opened and the pattern that closed it, which is \
         what tells a refusal apart from an open that failed for some other reason.\nstdout: \
         {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("no credential here"),
        "a file that matches nothing must still be readable — a guard that closed everything would \
         satisfy the assertions above without enforcing anything.\nstdout: {stdout}\nstderr: \
         {stderr}"
    );
}

#[test]
fn fs_scan_closes_a_matching_file_inside_a_real_cage() {
    // The one property the whole content lens rests on: the supervisor lives **outside** the cage's
    // mount namespace, so every path a notified open names has to be resolved through the target's
    // own `/proc` links. The unit tests fix the shape of that path; only a real cage proves it
    // resolves. Teeth: if the resolution were wrong, every open would fail to resolve and be allowed,
    // so the secret would come back in stdout and this test fails rather than silently passing.
    let (project, data) = (TmpDir::new(), TmpDir::new());
    if !host_can_sandbox(project.path(), data.path()) {
        skip_incapable!("skipping `[fs] scan` cage e2e: host cannot sandbox");
        return;
    }

    std::fs::write(
        project.path().join(".sbx.toml"),
        "[fs]\nscan = [\"sk-[A-Za-z0-9]{12,}\"]\n",
    )
    .expect("write the project config");
    std::fs::write(
        project.path().join("carries.txt"),
        "API key: sk-ABC123DEF456GHI789\n",
    )
    .expect("write the matching fixture");
    std::fs::write(project.path().join("ordinary.txt"), "no credential here\n")
        .expect("write the clean fixture");

    let out = sbx_isolated()
        .args(["run", "--", "sh", "-c", "cat carries.txt; cat ordinary.txt"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("run the cage");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !stdout.contains("sk-ABC123DEF456GHI789"),
        "the matching file's content reached the cage, so the open was not refused across the \
         mount namespace.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("no credential here"),
        "the file that matches nothing must still be readable — a lens that closed everything \
         would satisfy the assertion above without enforcing anything.\nstdout: {stdout}\nstderr: \
         {stderr}"
    );
    // Why it was refused, not merely that something failed: with the path resolution broken, the
    // read would fail for an unrelated reason and the assertion above would still pass.
    assert!(
        stderr.contains("its content matches") && stderr.contains("carries.txt"),
        "the refusal must name the file and the pattern that closed it, which is what makes a real \
         leak distinguishable from a false positive.\nstderr: {stderr}"
    );
}
