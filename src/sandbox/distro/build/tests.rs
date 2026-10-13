use super::*;

/// `bwrap` when this host can actually stand a cage up; otherwise `None` to skip.
fn bwrap() -> Option<PathBuf> {
    let bwrap = crate::pathfind::find_on_path("bwrap")?;
    matches!(crate::probe_userns(), crate::Userns::Ok).then_some(bwrap)
}

/// A context whose every field is inert: no network, and a CA bundle that exists so the cage can
/// bind it. Enough for a command that touches only the tree.
fn inert<'a>(
    commands: &'a [String],
    bwrap: &'a Path,
    ca: &'a Path,
    layout: &'a crate::store::Layout,
    project: &'a Path,
    network: &'a crate::config::NetworkPolicy,
) -> Context<'a> {
    Context {
        commands,
        bwrap,
        ca_bundle: ca,
        network,
        layout,
        project_root: project,
        // Never reached: these serve the forwarder, which is only wired under an allowlist, and
        // every context built here declares a posture that needs none.
        nix_store: Path::new("/nonexistent/nix"),
        socat: Path::new("/nonexistent/socat"),
        shell: Path::new("/nonexistent/bash"),
        limits: &INERT_LIMITS,
        slug: "demo-app",
    }
}

/// A stand-in for `bwrap` in `dir` that runs `body`, run once already so the cage it stands in for
/// is never the first exec of a file just written.
///
/// A launch reaches the stand-in through the resource scope's `systemd-run` where this host has
/// one, so the `ETXTBSY` of an executable written this instant ([`crate::testutil::write_script`])
/// would surface as the wrapper's exit rather than as a spawn failure that can be waited out. An
/// exec that succeeds says no descriptor open for writing is left, and none can appear after it.
fn stand_in(dir: &Path, body: &str) -> PathBuf {
    let fake = dir.join("fake-bwrap");
    crate::testutil::write_script(&fake, &format!("[ \"$1\" = --primed ] && exit 0\n{body}"));
    crate::testutil::output_past_etxtbsy(std::process::Command::new(&fake).arg("--primed"));
    fake
}

/// The default ceilings, which is what a launch that declares no `[limits]` runs under.
static INERT_LIMITS: crate::sandbox::cgroup::Limits = crate::sandbox::cgroup::Limits {
    memory_high: None,
    memory_max: None,
    tasks_max: None,
};

#[test]
fn an_image_with_no_shell_is_refused_before_a_cage_is_stood_up() {
    // The commands are handed to the image's own `/bin/sh`, so its absence is the failure to
    // report — and reporting it before a proxy and a cage exist is what keeps the message about the
    // image rather than about a command that could never have started.
    let tmp = crate::testutil::TmpDir::new();
    let rootfs = tmp.join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();
    let commands = vec!["true".to_string()];
    let network = crate::config::NetworkPolicy::Isolated;
    let layout = crate::store::Layout::under(tmp.path());
    let err = run(
        &rootfs,
        &inert(
            &commands,
            Path::new("/nonexistent/bwrap"),
            Path::new("/nonexistent/ca"),
            &layout,
            tmp.path(),
            &network,
        ),
    )
    .expect_err("an image with no shell cannot run anything");
    assert!(err.to_string().contains("`/bin/sh`"), "{err}");
}

/// The shell is looked up as the cage will see it: a link in the image names the image's own path,
/// never the host's. Looked up on the host, an image whose `bin` names a directory only the host
/// carries passes with no shell of its own, and one whose `bin` names a directory only the image
/// carries is refused on every host without it. Both shapes, because each is the other's mistake.
#[test]
fn the_shell_is_looked_up_inside_the_image_not_on_the_host() {
    let tmp = crate::testutil::TmpDir::new();
    let fake = stand_in(tmp.path(), "exit 0");
    let ca = tmp.join("ca.crt");
    std::fs::write(&ca, b"").unwrap();
    let layout = crate::store::Layout::under(tmp.path());
    let network = crate::config::NetworkPolicy::Isolated;
    let commands = vec!["true".to_string()];
    let context = || inert(&commands, &fake, &ca, &layout, tmp.path(), &network);

    // A shell the host has at the link's target, and the image does not.
    let on_the_host = tmp.join("on-the-host");
    std::fs::create_dir_all(&on_the_host).unwrap();
    std::fs::write(on_the_host.join("sh"), b"").unwrap();
    let borrowed = tmp.join("borrowed");
    std::fs::create_dir_all(&borrowed).unwrap();
    std::os::unix::fs::symlink(&on_the_host, borrowed.join("bin")).unwrap();
    let err = run(&borrowed, &context()).expect_err("the host's shell is not the image's");
    assert!(err.to_string().contains("carries no `/bin/sh`"), "{err}");

    // A shell the image has at the link's target, and the host does not.
    let in_the_image = tmp.join("in-the-image");
    let own = tmp.join("own");
    let target = own.join(in_the_image.strip_prefix("/").unwrap());
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("sh"), b"").unwrap();
    std::os::unix::fs::symlink(&in_the_image, own.join("bin")).unwrap();
    assert!(
        !in_the_image.exists(),
        "the fixture must name a path the host does not carry"
    );
    run(&own, &context()).expect("the shell the image's own link names");
}

#[test]
fn an_empty_command_list_stands_nothing_up() {
    // The consuming path passes no context at all, but a table that declared `run = []` must not
    // cost a cage either.
    let tmp = crate::testutil::TmpDir::new();
    let rootfs = tmp.join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();
    let network = crate::config::NetworkPolicy::Isolated;
    let layout = crate::store::Layout::under(tmp.path());
    run(
        &rootfs,
        &inert(
            &[],
            Path::new("/nonexistent/bwrap"),
            Path::new("/nonexistent/ca"),
            &layout,
            tmp.path(),
            &network,
        ),
    )
    .expect("nothing to run is not a failure");
}

#[test]
fn the_commands_run_in_order_on_the_tree_and_a_failure_names_the_one_that_failed() {
    let Some(bwrap) = bwrap() else {
        skip_incapable!("skipping the distribution build: need bwrap and a usable userns");
        return;
    };
    let Some(image) = crate::sandbox::distro::reference::parse("oci:docker.io/library/alpine:3.22")
    else {
        return;
    };
    let tmp = crate::testutil::TmpDir::new();
    let rootfs = tmp.join("rootfs");
    let Ok(resolved) = crate::sandbox::distro::registry::resolve(&image, None) else {
        skip_unreachable!("skipping the distribution build: the registry did not answer");
        return;
    };
    for layer in &resolved.layers {
        let Ok(blob) =
            crate::sandbox::distro::registry::fetch_layer(&image, layer, tmp.path(), None)
        else {
            skip_unreachable!("skipping the distribution build: a layer did not arrive");
            return;
        };
        crate::sandbox::distro::layers::apply(
            std::fs::File::open(&blob).unwrap(),
            &layer.media_type,
            &rootfs,
            &mut crate::sandbox::distro::layers::Budget::new(),
        )
        .expect("the layer applies");
    }

    let ca = tmp.join("ca.crt");
    std::fs::write(&ca, b"").unwrap();
    let layout = crate::store::Layout::under(tmp.path());
    let network = crate::config::NetworkPolicy::Isolated;

    // In order, and each one seeing what the last one wrote: the second reads the file the first
    // created, so a runner that reordered them or gave each its own tree would fail here.
    let ok = vec![
        "echo first > /built".to_string(),
        "cat /built > /second && echo done >> /second".to_string(),
    ];
    run(
        &rootfs,
        &inert(&ok, &bwrap, &ca, &layout, tmp.path(), &network),
    )
    .expect("both commands run");
    assert_eq!(
        std::fs::read_to_string(rootfs.join("second")).unwrap(),
        "first\ndone\n",
        "the second command saw what the first wrote"
    );

    // A failure names the command, and stops: the third never runs.
    let bad = vec![
        "echo one > /a".to_string(),
        "exit 3".to_string(),
        "echo three > /c".to_string(),
    ];
    let err = run(
        &rootfs,
        &inert(&bad, &bwrap, &ca, &layout, tmp.path(), &network),
    )
    .expect_err("a command that fails fails the build");
    let message = err.to_string();
    assert!(message.contains("exit 3"), "{message}");
    assert!(message.contains("exited 3"), "{message}");
    assert!(
        !rootfs.join("c").exists(),
        "the list stops at the first failure"
    );
}

#[test]
fn a_build_cage_cannot_see_the_project() {
    // A build is not a launch. A command that could read the project could carry it into an image
    // every other project on that digest then reads.
    use std::os::unix::ffi::OsStrExt as _;
    let Some(bwrap) = bwrap() else {
        skip_incapable!("skipping the build isolation check: need bwrap and a usable userns");
        return;
    };
    let tmp = crate::testutil::TmpDir::new();
    let project = crate::testutil::TmpDir::new();
    std::fs::write(project.path().join("SECRET"), b"private\n").unwrap();
    let rootfs = tmp.join("rootfs");
    for dir in ["bin", "proc", "dev", "tmp", "etc"] {
        std::fs::create_dir_all(rootfs.join(dir)).unwrap();
    }
    let Some(busybox) = crate::pathfind::find_on_path("busybox") else {
        skip_incapable!("skipping the build isolation check: need busybox for a minimal image");
        return;
    };
    std::fs::copy(&busybox, rootfs.join("bin/busybox")).unwrap();
    std::os::unix::fs::symlink("busybox", rootfs.join("bin/sh")).unwrap();

    let ca = tmp.join("ca.crt");
    std::fs::write(&ca, b"").unwrap();
    let layout = crate::store::Layout::under(tmp.path());
    let network = crate::config::NetworkPolicy::Isolated;
    let probe = vec![format!(
        "/bin/busybox ls {} > /seen 2>&1; true",
        crate::testutil::sh_word(project.path())
    )];
    run(
        &rootfs,
        &inert(&probe, &bwrap, &ca, &layout, project.path(), &network),
    )
    .expect("the probe itself succeeds");
    // Read as bytes: the probe's answer names the project, whose path need not be UTF-8.
    let seen = std::fs::read(rootfs.join("seen")).unwrap();
    let shown = String::from_utf8_lossy(&seen);
    assert!(
        memchr::memmem::find(&seen, b"SECRET").is_none(),
        "the project is visible to a build cage: {shown}"
    );
    // And the probe asked about the project itself: a path the shell split, or a probe that never
    // ran, sees no `SECRET` whatever the cage shows.
    assert!(
        memchr::memmem::find(&seen, project.path().as_os_str().as_bytes()).is_some(),
        "the probe did not ask about the project: {shown}"
    );
}

#[test]
fn a_build_cage_carries_the_mandatory_seccomp_filters() {
    // The filters are mandatory on every launch path, and this one runs a distribution's own
    // package scripts. What decides it is the argument list bubblewrap is handed, so the list is
    // read back from a stand-in that records it. Two commands, because the cages of one list are
    // stood up in sequence and each must be admissible on its own.
    let tmp = crate::testutil::TmpDir::new();
    let rootfs = tmp.join("rootfs");
    std::fs::create_dir_all(rootfs.join("bin")).unwrap();
    std::fs::write(rootfs.join("bin/sh"), b"").unwrap();
    let dump = tmp.join("argv.txt");
    let fake = stand_in(
        tmp.path(),
        &format!(
            "printf 'CAGE\\n' >> {0}\nprintf '%s\\n' \"$@\" >> {0}",
            crate::testutil::sh_word(&dump)
        ),
    );

    let ca = tmp.join("ca.crt");
    std::fs::write(&ca, b"").unwrap();
    let layout = crate::store::Layout::under(tmp.path());
    let network = crate::config::NetworkPolicy::Isolated;
    let commands = vec!["true".to_string(), "true".to_string()];
    run(
        &rootfs,
        &inert(&commands, &fake, &ca, &layout, tmp.path(), &network),
    )
    .expect("both recorded cages run");

    // Read as bytes: the recorded arguments carry fixture paths, which need not be UTF-8.
    let dumped = std::fs::read(&dump).unwrap();
    let lines: Vec<&[u8]> = dumped.split(|&b| b == b'\n').collect();
    let cages: Vec<&[&[u8]]> = lines.split(|&l| l == b"CAGE").skip(1).collect();
    let shown = String::from_utf8_lossy(&dumped);
    assert_eq!(cages.len(), 2, "both commands stand a cage up: {shown}");
    for argv in cages {
        assert!(
            argv.contains(&&b"--add-seccomp-fd"[..]),
            "a build cage is handed no seccomp filter: {shown}"
        );
    }
}

#[test]
fn a_build_cage_runs_inside_the_resource_limit_scope() {
    // A build is bounded like every other cage. Read from inside the cage rather than off the
    // command line, so what is asserted is the control group the process actually landed in.
    let tmp = crate::testutil::TmpDir::new();
    let rootfs = tmp.join("rootfs");
    std::fs::create_dir_all(rootfs.join("bin")).unwrap();
    std::fs::write(rootfs.join("bin/sh"), b"").unwrap();
    let seen = tmp.join("cgroup.txt");
    let fake = stand_in(
        tmp.path(),
        &format!(
            "cat /proc/self/cgroup > {}",
            crate::testutil::sh_word(&seen)
        ),
    );

    let ca = tmp.join("ca.crt");
    std::fs::write(&ca, b"").unwrap();
    let layout = crate::store::Layout::under(tmp.path());
    let network = crate::config::NetworkPolicy::Isolated;
    // Whether this host can carry a scope at all is the launch path's own decision, taken here
    // against the same limits the build will run under: where it applies none there is nothing to
    // assert, and saying so is not the same as passing.
    let limits = crate::sandbox::cgroup::Limits::default();
    let (wrapper, _) = crate::sandbox::cgroup::wrap(&fake, Vec::new(), &limits, "probe");
    if wrapper == fake {
        skip_incapable!("skipping the build scope check: this host applies no resource limits");
        return;
    }

    let commands = vec!["true".to_string()];
    run(
        &rootfs,
        &inert(&commands, &fake, &ca, &layout, tmp.path(), &network),
    )
    .expect("the recorded cage runs");

    let cgroup = std::fs::read_to_string(&seen).unwrap();
    let unit = format!("-{}.scope", std::process::id());
    assert!(
        cgroup.contains("sbx-") && cgroup.contains(&unit),
        "a build cage runs outside sbx's own resource scope: {cgroup}"
    );
}

/// A build lets go of what its cage is handed — the seccomp filters, the environment, each an
/// anonymous file — as soon as the spawn has handed them over. A command runs for minutes, and
/// nothing in this process reads them again.
///
/// Asked from inside the stand-in, while it runs: it names the anonymous files it was handed by
/// identity, then waits a bounded while for this process to hold none of them. The wait is the
/// spawn returning before the drop, and through `systemd-run` before the stand-in even starts.
#[test]
fn a_build_lets_go_of_its_cages_descriptors_once_it_has_spawned() {
    let tmp = crate::testutil::TmpDir::new();
    let rootfs = tmp.join("rootfs");
    std::fs::create_dir_all(rootfs.join("bin")).unwrap();
    std::fs::write(rootfs.join("bin/sh"), b"").unwrap();
    let seen = tmp.join("seen");
    let probe = format!(
        "mine=$(for f in /proc/$$/fd/*; do case $(readlink \"$f\") in /memfd:*) stat -L -c %d:%i \"$f\";; esac; done)\n\
         [ -n \"$mine\" ] || {{ echo none > {seen}; exit 0; }}\n\
         i=0\n\
         while [ $i -lt 100 ]; do\n\
         if ! for f in /proc/{pid}/fd/*; do stat -L -c %d:%i \"$f\" 2>/dev/null; done | grep -Fxq \"$mine\"; then echo released > {seen}; exit 0; fi\n\
         i=$((i + 1)); sleep 0.05\n\
         done\n\
         echo held > {seen}",
        seen = crate::testutil::sh_word(&seen),
        pid = std::process::id(),
    );
    let fake = stand_in(tmp.path(), &probe);

    let ca = tmp.join("ca.crt");
    std::fs::write(&ca, b"").unwrap();
    let layout = crate::store::Layout::under(tmp.path());
    let network = crate::config::NetworkPolicy::Isolated;
    let commands = vec!["true".to_string()];
    run(
        &rootfs,
        &inert(&commands, &fake, &ca, &layout, tmp.path(), &network),
    )
    .expect("the probe cage runs");

    let answer = std::fs::read_to_string(&seen).unwrap();
    assert_ne!(
        answer.trim(),
        "none",
        "the stand-in was handed no anonymous file, so there is nothing to ask about"
    );
    assert_eq!(
        answer.trim(),
        "released",
        "this process still holds the cage's descriptors while the command runs"
    );
}

/// A cage ended by a signal says which. A signal inside the cage reaches bwrap's exit as `128 + N`,
/// which the exit code already reports; a status with no code is bwrap itself killed — from
/// outside, by the scope, by the kernel — and the number is what tells those apart. `SIGTERM`
/// rather than `SIGKILL`, which is also how the ceiling ends a command.
#[test]
fn a_cage_killed_by_a_signal_names_the_signal() {
    let tmp = crate::testutil::TmpDir::new();
    let rootfs = tmp.join("rootfs");
    std::fs::create_dir_all(rootfs.join("bin")).unwrap();
    std::fs::write(rootfs.join("bin/sh"), b"").unwrap();
    let fake = stand_in(tmp.path(), "kill -TERM $$");

    let ca = tmp.join("ca.crt");
    std::fs::write(&ca, b"").unwrap();
    let layout = crate::store::Layout::under(tmp.path());
    let network = crate::config::NetworkPolicy::Isolated;
    let commands = vec!["true".to_string()];
    let err = run(
        &rootfs,
        &inert(&commands, &fake, &ca, &layout, tmp.path(), &network),
    )
    .expect_err("a cage killed by a signal fails the build");
    let message = err.to_string();
    assert!(
        message.contains("`true`") && message.contains("signal 15"),
        "{message}"
    );
}
