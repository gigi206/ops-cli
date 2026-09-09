//! Integration tests for `sbx fs` — the filesystem-observation CLI wiring: session resolution and the
//! error paths for `logs`, plus a cage-backed e2e for the detached file-write ring read over the
//! control socket. The pure error paths run against an isolated (empty) data directory (no sandbox);
//! the cage-backed one skips where the host cannot sandbox.

#[macro_use]
mod common;
use common::fixture::TmpDir;

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

// The fixtures' root, one definition shared with the unit tests.
include!("../src/testroot.rs");

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
    let (data, proj) = (TmpDir::new("f"), TmpDir::new("f"));
    let out = sbx(&["fs", "logs"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    // Scoped to the project, so it says that rather than denying sessions live elsewhere.
    assert!(
        err.contains("no live session in this project"),
        "got: {err}"
    );
}

#[test]
fn fs_logs_rejects_a_second_id() {
    let (data, proj) = (TmpDir::new("f"), TmpDir::new("f"));
    let out = sbx(&["fs", "logs", "1", "2"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("at most one session id"), "got: {err}");
}

#[test]
fn fs_with_no_subcommand_prints_usage() {
    let (data, proj) = (TmpDir::new("f"), TmpDir::new("f"));
    let out = sbx(&["fs"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("sbx fs"), "usage should name `sbx fs`: {err}");
}

#[test]
fn fs_unknown_subcommand_is_an_error() {
    let (data, proj) = (TmpDir::new("f"), TmpDir::new("f"));
    let out = sbx(&["fs", "bogus"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("unknown subcommand"), "got: {err}");
}

/// Write the session record `sbx fs logs` resolves, pointing at a live `pid`. A fabricated record (the
/// on-disk format is stable) isolates the property under test — the socket-missing path — from the
/// session-registration machinery, which is exercised elsewhere.
fn write_session_record(data: &Path, pid: u32, project: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let start = common::start_ticks(pid);
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
    let (data, project) = (TmpDir::new("f"), TmpDir::new("f"));
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

/// A launch that does nothing, run only to find out whether this host can build a cage at all. On
/// a capable host it also warms the userland cache, so the real launch below starts promptly.
///
/// Hands back the launch's own [`Output`] rather than a verdict, so `probe_or_skip!` can quote
/// what the refusal said: "host cannot sandbox" on its own names no cause, and the cause is the
/// only part a reader of a skipped run does not already know.
fn sandbox_probe(project: &Path, data: &Path) -> Output {
    sbx_isolated()
        .args(["run", "--", "true"])
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .output()
        .expect("spawn sbx run")
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
    let (project, data) = (TmpDir::new("f"), TmpDir::new("f"));
    probe_or_skip!(
        "detached fs --observe e2e",
        sandbox_probe(project.path(), data.path())
    );

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
    let (project, data, outside) = (TmpDir::new("f"), TmpDir::new("f"), TmpDir::new("f"));
    probe_or_skip!(
        "`[fs] scan` creation e2e",
        sandbox_probe(project.path(), data.path())
    );
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
         (umask 077; echo k > keyed.txt); echo keyed=$?; \
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
    // A file is made by the supervisor, so the kernel subtracts *its* umask unless the caller's is
    // applied — and a cage that tightened its own is one writing something it means to keep.
    assert_eq!(
        said("keyed="),
        Some("0"),
        "the masked creation must work.\nstdout: {stdout}"
    );
    assert_eq!(
        std::fs::metadata(project.path().join("keyed.txt"))
            .map(|at| std::os::unix::fs::PermissionsExt::mode(&at.permissions()) & 0o777)
            .ok(),
        Some(0o600),
        "a file made under `umask 077` has to land at `0600`, or what the cage meant to keep to \
         itself arrives readable by anyone.\nstdout: {stdout}\nstderr: {stderr}"
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
    let (project, data) = (TmpDir::new("f"), TmpDir::new("f"));
    probe_or_skip!(
        "`[fs] scan` `/proc/self` e2e",
        sandbox_probe(project.path(), data.path())
    );
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
    let (project, data) = (TmpDir::new("f"), TmpDir::new("f"));
    probe_or_skip!(
        "`[fs] scan` boundary e2e",
        sandbox_probe(project.path(), data.path())
    );

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
    let (project, data) = (TmpDir::new("f"), TmpDir::new("f"));
    probe_or_skip!(
        "`[fs] scan` cage e2e",
        sandbox_probe(project.path(), data.path())
    );

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

// ---------------------------------------------------------------------------
// `sbx fs deny|undeny|readonly|unreadonly` — the mask-writing verbs.
//
// They drive the shared `Project` harness rather than the bare `sbx()` above, because a mask write
// is trust-gated: it needs the trust store (`XDG_STATE_HOME`) and the global config
// (`XDG_CONFIG_HOME`) redirected too, which `sbx()` does not do.
// ---------------------------------------------------------------------------

use common::project::Project;

#[test]
fn fs_deny_writes_the_table_on_a_fresh_project_and_retrusts_it() {
    let p = Project::new("fsmask");
    let out = p.run(&["fs", "deny", "prod.key"]);
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("added deny prod.key"), "stdout: {stdout}");
    assert!(stdout.contains("re-trusted"), "must re-trust: {stdout}");

    let body = std::fs::read_to_string(p.proj.path().join(".sbx.toml")).unwrap();
    assert!(body.contains("[fs]"), "{body}");
    assert!(body.contains("deny = [\"prod.key\"]"), "{body}");
    // No posture is invented, unlike `sbx proc deny` which bootstraps `mode = "enforce"`: a mask
    // needs none, and inventing one here would change what an unrelated field means.
    assert!(!body.contains("mode"), "{body}");

    // A second write appends against the now-trusted config, so the trust pre-check passes.
    let again = p.run(&["fs", "readonly", "Cargo.lock"]);
    assert_eq!(again.status.code(), Some(0), "second write should append");
    let body = std::fs::read_to_string(p.proj.path().join(".sbx.toml")).unwrap();
    assert!(body.contains("readonly = [\"Cargo.lock\"]"), "{body}");
    assert!(
        body.contains("deny = [\"prod.key\"]"),
        "the first one stays: {body}"
    );
}

#[test]
fn fs_undeny_removes_what_fs_deny_wrote_and_is_idempotent() {
    let p = Project::new("fsmask");
    p.run(&["fs", "deny", "prod.key"]);

    let out = p.run(&["fs", "undeny", "prod.key"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}");
    assert!(stdout.contains("removed deny prod.key"), "stdout: {stdout}");
    let body = std::fs::read_to_string(p.proj.path().join(".sbx.toml")).unwrap();
    assert!(!body.contains("prod.key"), "{body}");

    // Removing what is already gone is a reported no-op, not an error.
    let again = p.run(&["fs", "undeny", "prod.key"]);
    let stdout = String::from_utf8_lossy(&again.stdout);
    assert_eq!(again.status.code(), Some(0), "stdout: {stdout}");
    assert!(stdout.contains("no change"), "stdout: {stdout}");
}

#[test]
fn fs_undeny_does_not_reach_the_readonly_list() {
    // The two lists are distinct, so the verb that undoes one must not silently undo the other:
    // `undeny` reaching a `readonly` entry would widen what the cage can *write*, which nobody
    // asked for.
    let p = Project::new("fsmask");
    p.run(&["fs", "readonly", "Cargo.lock"]);
    let out = p.run(&["fs", "undeny", "Cargo.lock"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}");
    assert!(stdout.contains("no change"), "stdout: {stdout}");
    let body = std::fs::read_to_string(p.proj.path().join(".sbx.toml")).unwrap();
    assert!(
        body.contains("readonly = [\"Cargo.lock\"]"),
        "still there: {body}"
    );

    // The verb spelled after the list it undoes does remove it.
    p.run(&["fs", "unreadonly", "Cargo.lock"]);
    let body = std::fs::read_to_string(p.proj.path().join(".sbx.toml")).unwrap();
    assert!(!body.contains("Cargo.lock"), "{body}");
}

#[test]
fn fs_deny_refuses_an_untrusted_existing_project() {
    // The gate is not about the mask — `[fs]` is honored from an untrusted source anyway — it is
    // about the re-trust, which covers the whole file. Same refusal and code as `sbx proc deny`.
    let p = Project::new("fsmask");
    p.write_project("binds = [\"/etc\"]\n");
    let out = p.run(&["fs", "deny", "prod.key"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("not trusted"), "stderr: {stderr}");
    let body = std::fs::read_to_string(p.proj.path().join(".sbx.toml")).unwrap();
    assert!(
        !body.contains("[fs]"),
        "a refused write leaves the file alone: {body}"
    );
}

#[test]
fn fs_mask_verbs_refuse_the_session_flags_and_say_why() {
    // A mask is a mount and a cage's mounts are fixed when it is built, so there is no live overlay
    // to load one into. The refusal must name that, since silence would read as "it worked".
    let p = Project::new("fsmask");
    for verb in ["deny", "readonly"] {
        let out = p.run(&["fs", verb, "prod.key", "--session"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{verb}: {stderr}");
        assert!(stderr.contains("mount"), "{verb} must say why: {stderr}");
        assert!(
            !p.proj.path().join(".sbx.toml").exists(),
            "{verb} must refuse before writing anything"
        );
    }
}

#[test]
fn fs_deny_lands_in_the_app_profile_under_a_global_app_scope() {
    // A global app scope reaches the profile file, not the global config, and the profile *is* the
    // app — so the table is a bare `[fs]` there rather than an `[app.<name>.fs]`. Asserted because
    // a mask written to the wrong file is silently inert, which is indistinguishable from working.
    let p = Project::new("fsmask");
    let out = p.run(&["fs", "deny", "prod.key", "-g", "-a", "demo"]);
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stdout.contains("app profile"),
        "it names where it landed: {stdout}"
    );
    let body = std::fs::read_to_string(p.profile_path("demo")).expect("the profile was written");
    assert!(body.contains("[fs]"), "{body}");
    assert!(body.contains("deny = [\"prod.key\"]"), "{body}");
    assert!(
        p.global_config().is_empty(),
        "the global config is not the target: {}",
        p.global_config()
    );
}

#[test]
fn fs_deny_scoped_to_an_app_in_the_project_config_nests_under_that_app() {
    // The other app scope: a `--local -a <name>` write keys the project file by app, so the mask
    // applies to that app's cage and not to the project's baseline.
    let p = Project::new("fsmask");
    let out = p.run(&["fs", "deny", "prod.key", "-a", "demo"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    let body = std::fs::read_to_string(p.proj.path().join(".sbx.toml")).unwrap();
    assert!(body.contains("[app.demo.fs]"), "{body}");
    assert!(body.contains("deny = [\"prod.key\"]"), "{body}");
}

// ---------------------------------------------------------------------------
// `sbx test fs` — the mask tester. Host-side: no cage, no nix.
// ---------------------------------------------------------------------------

/// Stage a project with the four shapes a mask answer has to tell apart.
fn masked_project() -> Project {
    let p = Project::new("tfs");
    let root = p.proj.path();
    std::fs::create_dir_all(root.join("secrets")).unwrap();
    std::fs::create_dir_all(root.join("certs")).unwrap();
    std::fs::write(root.join("secrets/token"), b"TOKEN").unwrap();
    std::fs::write(root.join("certs/server.pem"), b"CERT").unwrap();
    std::fs::write(root.join("certs/client.pem"), b"CERT2").unwrap();
    std::fs::write(root.join("main.rs"), b"fn main() {}").unwrap();
    p.write_project("[fs]\ndeny = [\"secrets/\", \"certs/server.pem\"]\nreadonly = [\"certs/\"]\n");
    p
}

#[test]
fn test_fs_reports_what_the_masks_would_do_to_each_shape() {
    let p = masked_project();
    // The project config must be trusted for its security fields to apply, exactly as a launch
    // requires — otherwise this would test the empty baseline and pass for the wrong reason.
    assert!(p.run(&["trust"]).status.success(), "trust the fixture");

    let verdict = |path: &str| -> String {
        let out = p.run(&["test", "fs", path]);
        assert!(
            out.status.success(),
            "test fs {path} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    };

    let listed = verdict("secrets/token");
    assert!(listed.contains("DENIED"), "{listed}");
    assert!(listed.contains("secrets/"), "the entry is named: {listed}");

    // A denied directory covers the names that appear inside it later in the session, so the
    // tester must answer for one that does not exist yet. Reporting "no such file, so it is open"
    // is the one answer the cage never gives.
    let future = verdict("secrets/written-later");
    assert!(future.contains("DENIED"), "{future}");

    let file = verdict("certs/server.pem");
    assert!(file.contains("DENIED"), "{file}");

    // Its sibling under the same read-only directory, so a tester that printed DENIED for
    // everything under `certs/` would fail here.
    let ro = verdict("certs/client.pem");
    assert!(ro.contains("READ-ONLY"), "{ro}");

    // And the other direction again: a path no entry names.
    let open = verdict("main.rs");
    assert!(open.contains("OPEN"), "{open}");
}

#[test]
fn test_fs_masks_apply_from_an_untrusted_project_like_a_launch_would() {
    // `[fs]` is the security table that is NOT trust-gated, and the tester has to match that or it
    // describes a different cage: a project closing its own files off gains nothing it could turn
    // on the user, while dropping the masks would leave a file the project asked to close wide
    // open. Written against an untrusted fixture on purpose — the sibling testers (`net`, `proc`)
    // report the baseline here, and copying their sentence into this verb would make it claim a
    // gate the loader does not apply.
    let p = masked_project();
    let out = p.run(&["test", "fs", "secrets/token"]);
    assert!(out.status.success(), "{:?}", out.status);
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        body.contains("DENIED"),
        "untrusted masks still apply: {body}"
    );
}

#[test]
fn test_fs_refuses_a_path_outside_the_project() {
    // `[fs]` closes paths of the project it is declared in and nothing else, which is the sentence
    // the expansion refuses an outside entry with. Answering OPEN here would read as a policy
    // decision about a path the table could never reach.
    let p = masked_project();
    assert!(p.run(&["trust"]).status.success(), "trust the fixture");
    let out = p.run(&["test", "fs", "/etc/hostname"]);
    assert_eq!(out.status.code(), Some(2), "{:?}", out.status);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("outside the project"), "{err}");
}

/// A path the **project** chose reaches this terminal through the verdict, and it must arrive as
/// text rather than as instructions.
///
/// `sbx test fs` resolves its argument through the project's own symlinks, so the name it prints
/// back can be one a file in the tree spells: a repository holding `a<ESC>[31mevil.key` and a
/// symlink to it puts that escape sequence on the screen at the moment the user is reading what
/// sbx would close. The launch already filters the warnings it prints for this reason; the whole
/// verb has to, which is why this asserts on both streams rather than on one line.
#[test]
fn test_fs_prints_no_escape_a_project_path_carried_into_it() {
    let p = masked_project();
    assert!(p.run(&["trust"]).status.success(), "trust the fixture");

    // The project spells the names; the caller says only `link.key` and `deep`, so an escape can
    // only enter through the resolution, never through the argument. The entries themselves are
    // globs, because an `[fs]` entry carrying a control byte is refused when the config loads.
    let root = p.proj.path();
    let evil = root.join("a\u{1b}[31mevil.key");
    std::fs::write(&evil, b"K").unwrap();
    std::os::unix::fs::symlink(&evil, root.join("link.key")).unwrap();
    // And the other shape: a name covered by a denied *directory*, which the verdict names too.
    let hidden = root.join("b\u{1b}[31mevil");
    std::fs::create_dir(&hidden).unwrap();
    std::fs::write(hidden.join("inside"), b"K").unwrap();
    std::os::unix::fs::symlink(hidden.join("inside"), root.join("deep")).unwrap();
    p.write_project("[fs]\ndeny = [\"*.key\", \"*evil\"]\n");
    assert!(
        p.run(&["trust"]).status.success(),
        "re-trust after the write"
    );

    for arg in ["link.key", "deep"] {
        let out = p.run(&["test", "fs", arg]);
        let body = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            body.contains("DENIED"),
            "{arg}: the verdict is still answered: {body}"
        );
        assert!(
            !body.contains('\u{1b}'),
            "{arg}: an escape the project chose reached the terminal: {body:?}"
        );
    }
}
