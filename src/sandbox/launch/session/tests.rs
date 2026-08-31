use super::*;
use crate::testutil::TmpDir;

#[test]
fn session_verb_confirmations_are_plain_text_when_uncolored() {
    // A plain palette must leave every confirmation byte-for-byte plain, so a captured stream
    // (and the existing `sbx session stop --all` substring assertion) stays unchanged.
    let p = crate::style::Palette::plain();
    let grace = Duration::from_secs(10);
    assert_eq!(
        render_attaching(4242, "app:demo-app", &p),
        "sbx: attaching to session 4242 (app:demo-app) \
         (a shell in its live cage — type `exit` to leave the agent running)"
    );
    assert_eq!(
        render_no_active_sessions(&p),
        "sbx session stop: no active sessions to stop."
    );
    assert_eq!(
        render_gui_stop_hint("demo-app", 4242, &p),
        "sbx: demo-app is graphical — press Ctrl+C twice here to quit (closing its window may only \
         hide it — a tray app keeps running); `sbx session stop 4242` also stops it."
    );
    assert_eq!(
        render_stop_outcome(
            4242,
            "run",
            &crate::session::StopOutcome::Terminated,
            grace,
            &p
        ),
        "sbx session stop: stopped session 4242 (run)."
    );
    assert_eq!(
        render_stop_outcome(
            7,
            "app:agent",
            &crate::session::StopOutcome::AlreadyGone,
            grace,
            &p
        ),
        "sbx session stop: session 7 (app:agent) had already exited."
    );
    assert_eq!(
        render_stop_outcome(9, "shell", &crate::session::StopOutcome::Killed, grace, &p),
        "sbx session stop: session 9 (shell) did not exit within 10s — sent SIGKILL."
    );
    // A refused handle must not read like the no-op above: it names the reason and says the
    // session may still be running, because nothing was signalled.
    assert_eq!(
        render_stop_outcome(
            11,
            "app:agent",
            &crate::session::StopOutcome::NotSignalled(libc::EINVAL),
            grace,
            &p
        ),
        "sbx session stop: cannot stop session 11 (app:agent): Invalid argument (os error 22) \
         — it was not signalled and may still be running."
    );
}

#[test]
fn a_stop_that_left_something_running_outranks_an_id_that_matched_nothing() {
    // Nothing wrong is a plain success; an id that named no live session is the long-standing
    // 2; a session the host refused a handle on is 1 — and when both happened in one run it is
    // still 1, because a cage that may still be up is what the caller has to act on.
    assert_eq!(stop_exit_code(false, false), 0);
    assert_eq!(stop_exit_code(false, true), 2);
    assert_eq!(stop_exit_code(true, false), 1);
    assert_eq!(stop_exit_code(true, true), 1);
}

#[test]
fn a_stop_that_signalled_nothing_keeps_the_session_record() {
    // The reap is what makes `sbx session ls` clean the moment a stop lands. Applied to a stop
    // that did *not* land, it would delete the only handle on a cage that is still up: the
    // session would vanish from every listing and no second `sbx session stop <pid>` could
    // name it. So the record survives exactly one outcome, and this test is the contrast —
    // same call, same registry, two records that differ only in why their pid has no handle.
    let data = TmpDir::new();
    let reg = crate::session::Registry::at(data.path());
    let pal = crate::style::Palette::plain();
    let sessions = data.path().join("sessions");
    let record_at = |pid: u32| crate::session::Session {
        project: PathBuf::from("/work/probe"),
        pid,
        start_ticks: 1,
        kind: crate::session::Kind::Run,
        runtime: crate::session::SessionRuntime::Project,
        detached: false,
    };
    let count = || {
        std::fs::read_dir(&sessions)
            .map(|d| d.filter_map(Result::ok).count())
            .unwrap_or(0)
    };

    // Pid 0 is not a pid a process can hold: `pidfd_open` refuses it with `EINVAL`, which says
    // nothing about a process being alive — the stop reports it and keeps the record.
    let refused = record_at(0);
    reg.register(&refused).unwrap();
    assert!(!stop_session(&reg, &refused, Duration::from_secs(0), &pal));
    assert_eq!(count(), 1, "an unsignalled session must stay addressable");

    // A pid above the kernel's ceiling cannot exist, so the same call answers `ESRCH` — truly
    // gone — and the record goes with it.
    let gone = record_at(1 << 30);
    reg.register(&gone).unwrap();
    assert!(stop_session(&reg, &gone, Duration::from_secs(0), &pal));
    assert_eq!(count(), 1, "only the unsignalled record is left");
}

#[test]
fn launch_display_name_prefers_the_app_then_the_program_basename() {
    // An `sbx app` launch names the app; a plain `sbx run` into a GUI project names the
    // program by its basename (never a store path); an empty command falls back cleanly.
    assert_eq!(
        launch_display_name(&binds::Runtime::GlobalApp("demo-app"), &[]),
        "demo-app"
    );
    assert_eq!(
        launch_display_name(&binds::Runtime::ProjectApp("agent"), &[]),
        "agent"
    );
    let cmd = vec![
        OsString::from("/nix/store/abc-foo/bin/foo"),
        OsString::from("--flag"),
    ];
    assert_eq!(
        launch_display_name(&binds::Runtime::ProjectDefault, &cmd),
        "foo"
    );
    assert_eq!(
        launch_display_name(&binds::Runtime::ProjectDefault, &[]),
        "the app"
    );
}

#[test]
fn session_verb_confirmations_color_their_outcome_and_identifier_spans() {
    // The hue carries the meaning: a clean stop is a real change (green), a forced kill is the
    // caution hue (yellow), a stop that could not happen is the error hue (red), a no-op is
    // dim, and an identifier is cyan. The verb of an attach announcement stays plain (it is not
    // a completed state change).
    let p = crate::style::Palette::colored();
    let grace = Duration::from_secs(10);

    let stopped = render_stop_outcome(
        4242,
        "run",
        &crate::session::StopOutcome::Terminated,
        grace,
        &p,
    );
    assert!(stopped.contains(&format!("{}stopped{}", p.ok, p.reset)));
    assert!(stopped.contains(&format!("{}4242{}", p.name, p.reset)));

    let gone = render_stop_outcome(
        7,
        "app:agent",
        &crate::session::StopOutcome::AlreadyGone,
        grace,
        &p,
    );
    assert!(gone.contains(&format!("{}had already exited{}", p.dim, p.reset)));

    let killed = render_stop_outcome(9, "shell", &crate::session::StopOutcome::Killed, grace, &p);
    assert!(killed.contains(&format!("{}sent SIGKILL{}", p.warn, p.reset)));

    let refused = render_stop_outcome(
        11,
        "app:agent",
        &crate::session::StopOutcome::NotSignalled(libc::EMFILE),
        grace,
        &p,
    );
    assert!(refused.contains(&format!("{}cannot stop{}", p.err, p.reset)));
    // Not the dim of a no-op: this one did not happen, it is not a state that was already
    // reached.
    assert!(!refused.contains(&format!("{}cannot stop", p.dim)));

    let attach = render_attaching(4242, "app:demo-app", &p);
    assert!(attach.contains(&format!("{}4242{}", p.name, p.reset)));
    assert!(attach.contains(&format!("{}app:demo-app{}", p.name, p.reset)));
    // The announcement verb is not green — only a completed change earns that.
    assert!(!attach.contains(&format!("{}attaching", p.ok)));

    // The graphical stop hint colors only its app-name identifier (cyan) and names the pid.
    let hint = render_gui_stop_hint("demo-app", 4242, &p);
    assert!(hint.contains(&format!("{}demo-app{}", p.name, p.reset)));
    assert!(hint.contains("sbx session stop 4242"));

    assert!(render_no_active_sessions(&p).contains(p.dim));
}

/// The C strings an `attach_argv` result carries, as UTF-8 for assertion.
fn argv_strings(argv: &[CString]) -> Vec<String> {
    argv.iter()
        .map(|c| c.to_str().unwrap().to_string())
        .collect()
}

#[test]
fn attach_argv_with_no_command_is_the_interactive_rc_shell() {
    // A bare attach reuses the same rc shell as an interactive `sbx run`, so the joined shell gets mise
    // activation and the `(sbx-<slug>)` prompt.
    let argv = attach_argv(&[]).expect("shell argv builds");
    assert_eq!(
        argv_strings(&argv),
        vec![
            binds::SANDBOX_BASH.to_string(),
            "--rcfile".to_string(),
            binds::SHELL_RC_INCAGE.to_string(),
        ]
    );
}

#[test]
fn attach_argv_with_a_command_runs_it_positionally_through_bash() {
    // The command is passed positionally after `bash -c 'exec "$@"' bash`, so bash resolves it
    // on the cage PATH and execs it in place — and no argument is ever interpreted as shell
    // syntax (the injection guard: a value like `; rm -rf /` is one literal argv element).
    let cmd = vec![
        OsString::from("grep"),
        OsString::from("-n"),
        OsString::from("; rm -rf /"),
    ];
    let argv = attach_argv(&cmd).expect("command argv builds");
    assert_eq!(
        argv_strings(&argv),
        vec![
            binds::SANDBOX_BASH.to_string(),
            "-c".to_string(),
            "exec \"$@\"".to_string(),
            "bash".to_string(),
            "grep".to_string(),
            "-n".to_string(),
            "; rm -rf /".to_string(),
        ]
    );
}

#[test]
fn attach_argv_rejects_a_command_argument_with_an_interior_nul() {
    // A NUL cannot be a C-string argument; it must fail closed rather than truncate the argv.
    use std::os::unix::ffi::OsStrExt;
    let cmd = vec![
        OsString::from("echo"),
        std::ffi::OsStr::from_bytes(b"a\0b").to_os_string(),
    ];
    assert!(attach_argv(&cmd).is_err());
}
