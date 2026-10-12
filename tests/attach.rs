//! Integration tests for `sbx session attach`.
//!
//! The headline property: attaching to a running **app** (agent) session drops a new interactive
//! shell into the agent's *isolated* home — not the project's shared home — so "attach to a running
//! agent" really means the same environment it works in. Driven through a pty (attach, like
//! `shell`, needs a controlling terminal). Skipped, not failed, where the host cannot sandbox.

#[macro_use]
mod common;
use common::fixture::TmpDir;
use common::pty::{Pty, Reaped};

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn sbx() -> Command {
    // The global config and the trust store come from fixed empty directories under the test tree
    // ([`common::isolated_sbx`]), so an e2e never depends on the developer's `~/.config/sbx` or on
    // their trust markers, which the app launch below looks its project config up in. No test here
    // writes either, so the shared directories are race-free.
    common::isolated_sbx("")
}

#[test]
fn attach_to_an_unknown_id_reports_and_exits_two() {
    // No tty needed: `attach` resolves the target before the terminal check, so an unknown id is a
    // clean exit-2 with a pointer to `sbx session ls` — never a panic or a misparse of garbage.
    let data = TmpDir::prefixed("a", "noid");
    for id in ["999999", "not-a-pid"] {
        let out = sbx()
            .arg("session")
            .arg("attach")
            .arg(id)
            .env("XDG_DATA_HOME", data.path())
            .stdin(Stdio::null())
            .output()
            .expect("spawn sbx session attach");
        assert_eq!(
            out.status.code(),
            Some(2),
            "attach to a missing id must exit 2 ({id})"
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("no live session"),
            "missing-id message: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// Whether the host can launch a sandbox (also warms the userland cache so later launches start
/// promptly, and creates the project's default home).
fn sandbox_probe(project: &Path, data: &Path) -> Output {
    sbx()
        .arg("run")
        .arg("--")
        .arg("true")
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .output()
        .expect("spawn sbx run")
}

/// The session record file for `pid`, once it appears under `<data>/sbx/sessions/` (the launch
/// registers it after seeding). `None` if it does not show up before the deadline.
fn wait_for_session(data: &Path, pid: u32, deadline: Instant) -> Option<PathBuf> {
    let dir = data.join("sbx").join("sessions");
    let prefix = format!("{pid}-");
    while Instant::now() < deadline {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().starts_with(&prefix) {
                    return Some(entry.path());
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    None
}

/// Drive an interactive `sbx session attach <pid>` through a pty: wait for the shell's prompt, send
/// `script`, and read until the session ends or the deadline. Returns the captured output.
fn drive_attach(pid: u32, data: &Path, script: &[u8]) -> String {
    let mut pty = Pty::open(None);
    let _child = Reaped(
        sbx()
            .arg("session")
            .arg("attach")
            .arg(pid.to_string())
            .env("XDG_DATA_HOME", data)
            .stdin(pty.stdio())
            .stdout(pty.stdio())
            .stderr(pty.stdio())
            .spawn()
            .expect("spawn sbx session attach"),
    );
    pty.release_slave();

    let mut out = Vec::new();
    // Generous: the setns join into a live cage plus the in-cage shell startup can be slow under
    // heavy parallel load (the whole test suite). It is not what made this test flaky — a run that
    // never sent its script had seen the whole prompt and not recognised it, which is what
    // `common::shell_prompt_seen` now answers in one place.
    let deadline = Instant::now() + Duration::from_secs(120);
    // Readiness is "a prompt appeared": see `common::shell_prompt_seen` for why the last
    // character is `$` or `#` and never only one of the two. An attach refused before any shell
    // started prints no prompt, and what it printed is handed back for the caller to read.
    if pty.read_until(&mut out, deadline, common::shell_prompt_seen) {
        pty.send(script);
        pty.read_until(&mut out, deadline, |_| false);
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn attach_to_a_running_app_lands_in_the_apps_isolated_home() {
    // A running `sbx app` agent uses its own isolated home. `sbx session attach <pid>` must drop the new
    // shell into THAT home, not the project's shared one — the property that makes attaching to a
    // running agent mean "the same environment". Teeth: a marker the attached shell writes to
    // `$HOME` must land in the app's home (`<data>/apps/probe/home`) and NOT in the project's
    // default home (which the warm-up launch created). A naive attach would use the project home
    // and fail both halves.
    let project = TmpDir::prefixed("a", "proj");
    let data = TmpDir::prefixed("a", "data");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[app.probe]\ncmd = [\"sleep\", \"300\"]\n",
    )
    .unwrap();

    probe_or_skip!(
        "sbx attach app e2e",
        sandbox_probe(project.path(), data.path())
    );

    // Launch the app in the background: it registers a global-app session and `exec`s into the
    // cage running `sleep`, so the spawned pid is the session's pid throughout.
    let mut agent = sbx()
        .arg("app")
        .arg("run")
        .arg("probe")
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sbx app probe");
    let pid = agent.id();

    let record = wait_for_session(data.path(), pid, Instant::now() + Duration::from_secs(60));
    if record.is_none() {
        let _ = agent.kill();
        let _ = agent.wait();
        skip_incapable!(
            "skipping sbx attach app e2e: the app session never registered (cannot sandbox?)"
        );
        return;
    }

    // Attach and have the shell drop a marker into its $HOME.
    //
    // A session record appears as soon as the launch registers it, but a cage only becomes
    // *enterable* once a process is running inside its namespaces — and the app's first launch
    // provisions its toolset before it ever reaches `sleep`. That gap is startup, not a defect, so
    // retry across it — and only across it: any other attach failure still fails on the first try.
    let attachable_by = Instant::now() + Duration::from_secs(60);
    let log = loop {
        // `$HOME` is echoed before the write so a failure says *where* the marker went: without
        // it, the assertion can only report that the file is absent from where it was expected,
        // which is the one thing already known.
        let log = drive_attach(
            pid,
            data.path(),
            b"echo \"ATTACH_HOME=[$HOME]\"\nprintf done > \"$HOME/ATTACH_OK\"\nexit\n",
        );
        if !log.contains("has no live process to enter") || Instant::now() >= attachable_by {
            break log;
        }
        std::thread::sleep(Duration::from_millis(500));
    };

    let app_home_marker = data.path().join("sbx/apps/probe/home/ATTACH_OK");
    // Allow a brief window for the in-cage write to become observable on the host-bound home after
    // the attached shell exits — a slow flush under load must not flake the assertion. The marker
    // lives in the app's persistent home, so it survives killing the agent below.
    let poll_until = Instant::now() + Duration::from_secs(15);
    while !app_home_marker.exists() && Instant::now() < poll_until {
        std::thread::sleep(Duration::from_millis(200));
    }

    let _ = agent.kill();
    let _ = agent.wait();

    // On failure, say what the host actually holds: which of the two candidate homes exists, and
    // what each contains. The shell's own `$HOME` is in `log`, so the two sides can be compared.
    let survey = |label: &str, dir: &std::path::Path| {
        let listing = std::fs::read_dir(dir).map_or_else(
            |e| format!("<unreadable: {e}>"),
            |entries| {
                let mut names: Vec<String> = entries
                    .filter_map(|e| Some(e.ok()?.file_name().to_string_lossy().into_owned()))
                    .collect();
                names.sort();
                if names.is_empty() {
                    "<empty>".to_string()
                } else {
                    names.join(", ")
                }
            },
        );
        format!("{label} {}: {listing}", dir.display())
    };
    assert!(
        app_home_marker.exists(),
        "the attached shell did not land in the app's isolated home ({app_home_marker:?})\n{}\n{}\n{log}",
        survey("app home", &data.path().join("sbx/apps/probe/home")),
        survey("apps dir", &data.path().join("sbx/apps")),
    );

    // Teeth: the project's default home (created by the warm-up `sbx run -- true`) must NOT have
    // received the marker — proving attach reproduced the app's home, not the project's.
    // Read loudly, and required to name at least one home: a check over nothing would pass however
    // attach behaved, and an unreadable or renamed directory reads as nothing.
    let projects = data.path().join("sbx/projects");
    let project_homes: Vec<PathBuf> = std::fs::read_dir(&projects)
        .unwrap_or_else(|e| panic!("{} cannot be read: {e}", projects.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|e| panic!("{} cannot be read: {e}", projects.display()))
                .path()
                .join("home")
        })
        .filter(|home| home.is_dir())
        .collect();
    assert!(
        !project_homes.is_empty(),
        "the warm-up launch left no project home under {}, so the check below would hold of nothing",
        projects.display()
    );
    for home in &project_homes {
        let m = home.join("ATTACH_OK");
        assert!(
            !m.exists(),
            "the marker landed in the project's shared home — attach used the wrong runtime: {m:?}\n{log}"
        );
    }
}

/// The prompt a cage whose user is root prints counts as a prompt.
///
/// The two transcripts are real: the first is what a hosted runner produced when this suite's
/// sibling in `tests/run.rs` failed — the shell was up and waiting, and the wait for it did not
/// recognise the line, so the script was never written and the failure read as a shell that never
/// came up. The second is the attach banner alone, which is what the wait sees before any shell
/// has spoken; a predicate that answered "ready" to it would send the script into nothing. The
/// third is what an interactive launch prints before its shell, a flake reference and a variable
/// among it: a predicate that took either character anywhere fired there, and the script it sent
/// was discarded with the type-ahead when the supervisor took the terminal.
#[test]
fn a_prompt_is_recognised_whichever_character_the_shell_ends_it_with() {
    let banner = "sbx: attaching to session 84845 (run) (a shell in its live cage \u{2014} type exit \
         to leave the agent running)\r\n";
    assert!(
        !common::shell_prompt_seen(banner.as_bytes()),
        "the banner is not a prompt: nothing has been asked of the shell yet"
    );
    // What an interactive launch prints before its shell is up: both characters, and no prompt.
    let launch = "\r\x1b[K'github:NixOS/nixpkgs/4975466d324710c576dc11ad614684e6bd8cad8e#fd'\
         \x1b[0m\x1b[K\r\nsbx: set $SBX_DATA_DIR to a shorter path\r\n";
    assert!(
        !common::shell_prompt_seen(launch.as_bytes()),
        "a launch's own output is not a prompt, whatever characters it carries"
    );
    for prompt in [
        format!("{launch}(sbx-sh-proj-2914738-0) /work/sh-proj$ "),
        format!("{banner}root@runnervm:~/.cache/sbx/test-tmp/r-attach-pro-28391-200# "),
        format!("{banner}(sbx-r-attach-pro-756913-0) /$ "),
        format!("{banner}bash-5.3$ "),
    ] {
        assert!(
            common::shell_prompt_seen(prompt.as_bytes()),
            "a shell that printed a prompt is ready to be driven: {prompt:?}"
        );
    }
}
