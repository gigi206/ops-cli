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
        crate::sandbox::distro::layers::apply(&blob, &layer.media_type, &rootfs)
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
        project.path().display()
    )];
    run(
        &rootfs,
        &inert(&probe, &bwrap, &ca, &layout, project.path(), &network),
    )
    .expect("the probe itself succeeds");
    let seen = std::fs::read_to_string(rootfs.join("seen")).unwrap();
    assert!(
        !seen.contains("SECRET"),
        "the project is visible to a build cage: {seen}"
    );
}

#[test]
fn a_build_cage_carries_the_mandatory_seccomp_filters() {
    // The filters are mandatory on every launch path, and this one runs a distribution's own
    // package scripts. What decides it is the argument list bubblewrap is handed, so the list is
    // read back from a stand-in that records it. Two commands, because the cages of one list are
    // stood up in sequence and each must be admissible on its own.
    use std::os::unix::fs::PermissionsExt;
    let tmp = crate::testutil::TmpDir::new();
    let rootfs = tmp.join("rootfs");
    std::fs::create_dir_all(rootfs.join("bin")).unwrap();
    std::fs::write(rootfs.join("bin/sh"), b"").unwrap();
    let dump = tmp.join("argv.txt");
    let fake = tmp.join("fake-bwrap");
    std::fs::write(
        &fake,
        format!(
            "#!/bin/sh\nprintf 'CAGE\\n' >> '{0}'\nprintf '%s\\n' \"$@\" >> '{0}'\n",
            dump.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

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

    let dumped = std::fs::read_to_string(&dump).unwrap();
    let cages: Vec<&str> = dumped.split("CAGE\n").skip(1).collect();
    assert_eq!(cages.len(), 2, "both commands stand a cage up: {dumped}");
    for argv in cages {
        assert!(
            argv.lines().any(|l| l == "--add-seccomp-fd"),
            "a build cage is handed no seccomp filter: {argv}"
        );
    }
}

#[test]
fn a_build_cage_runs_inside_the_resource_limit_scope() {
    // A build is bounded like every other cage. Read from inside the cage rather than off the
    // command line, so what is asserted is the control group the process actually landed in.
    use std::os::unix::fs::PermissionsExt;
    let tmp = crate::testutil::TmpDir::new();
    let rootfs = tmp.join("rootfs");
    std::fs::create_dir_all(rootfs.join("bin")).unwrap();
    std::fs::write(rootfs.join("bin/sh"), b"").unwrap();
    let seen = tmp.join("cgroup.txt");
    let fake = tmp.join("fake-bwrap");
    std::fs::write(
        &fake,
        format!("#!/bin/sh\ncat /proc/self/cgroup > '{}'\n", seen.display()),
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

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
