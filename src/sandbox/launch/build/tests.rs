use super::*;
use crate::testutil::TmpDir;

/// The zone a cage ends up in, held against a database that really is on disk.
///
/// The config layer already refused the shapes that are not zone names; what only this side can
/// decide is whether the database *carries* the zone, so the cases here are the ones that turn
/// on a file existing.
#[test]
fn a_zone_the_database_does_not_carry_falls_back_to_the_default() {
    // The database sits one level inside the fixture, so the traversal case below resolves to a
    // sibling the fixture owns rather than to a name outside the tree this test may write.
    let base = TmpDir::new();
    let db = base.path().join("zoneinfo");
    std::fs::create_dir_all(db.join("Europe")).unwrap();
    std::fs::write(db.join("Europe/Paris"), b"TZif").unwrap();
    std::fs::write(db.join("UTC"), b"TZif").unwrap();

    // Nothing declared: the built-in zone, which is a zone and not an absence.
    assert_eq!(cage_timezone(None, &db), "UTC");
    // Declared and present: taken.
    assert_eq!(cage_timezone(Some("Europe/Paris"), &db), "Europe/Paris");
    // Declared and absent: the default, not a refused launch — a misspelled zone costs a wrong
    // clock, never the session.
    assert_eq!(cage_timezone(Some("Europe/Pariss"), &db), "UTC");
    // A directory inside the database is not a zone: `Europe` resolves to something that
    // exists, so only the is-a-file test tells the two apart.
    assert_eq!(cage_timezone(Some("Europe"), &db), "UTC");
    // The shape rule is applied here too, at the join site: a traversal that would otherwise
    // resolve to a real file outside the database never becomes a link target.
    std::fs::write(base.path().join("escaped"), b"x").unwrap();
    assert_eq!(cage_timezone(Some("../escaped"), &db), "UTC");
    // And a database that is not there at all still yields a launchable cage.
    assert_eq!(
        cage_timezone(Some("Europe/Paris"), Path::new("/nonexistent-zoneinfo")),
        "UTC"
    );
}

/// Which of the two ways to name a zone decides the link. The property under test is not a
/// precedence preference, it is that **one** value drives both halves: `TZ` is what the cage's
/// clock will read, so the link has to follow it or the two answer differently with no error.
#[test]
fn the_link_follows_whatever_tz_will_finally_read() {
    let env = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    };

    // Neither: nothing is declared, and the caller falls back to the built-in zone.
    assert_eq!(declared_zone(&env(&[("LANG", "C.UTF-8")]), None), None);
    // The field alone.
    assert_eq!(
        declared_zone(&env(&[]), Some("Europe/Paris")),
        Some("Europe/Paris")
    );
    // `TZ` alone — the case that used to move the clock and leave the link behind.
    assert_eq!(
        declared_zone(&env(&[("TZ", "Asia/Tokyo")]), None),
        Some("Asia/Tokyo")
    );
    // Both, disagreeing: `TZ` wins, because `TZ` is what the cage will actually read.
    assert_eq!(
        declared_zone(&env(&[("TZ", "Asia/Tokyo")]), Some("Europe/Paris")),
        Some("Asia/Tokyo")
    );
    // Two layers both setting it: the later one wins, exactly as the assembler's upsert does.
    assert_eq!(
        declared_zone(&env(&[("TZ", "Asia/Tokyo"), ("TZ", "UTC")]), None),
        Some("UTC")
    );
}

/// The project root reaches the control-plane pin computation, which is the whole point: it is
/// bound read-write structurally rather than as a config bind, so it used to be invisible here
/// — and `cd ~ && sbx run` then handed the cage sbx's own data dir, trust store and global
/// config read-write with nothing pinning them.
#[test]
fn the_project_root_is_one_of_the_binds_the_control_plane_is_pinned_against() {
    let tmp = crate::testutil::TmpDir::new();
    let project = tmp.path().join("work");
    std::fs::create_dir_all(&project).expect("project dir");

    let declared = vec![crate::config::Bind {
        path: PathBuf::from("/srv/data"),
        writable: true,
    }];
    let sources = pin_sources(&declared, &project);

    assert!(
        sources.iter().any(|b| b.path == Path::new("/srv/data")),
        "the declared binds still reach the pins: {sources:?}"
    );
    let canon = std::fs::canonicalize(&project).expect("the project exists");
    let entry = sources
        .iter()
        .find(|b| b.path == canon)
        .expect("the project root is among the pin sources");
    assert!(
        entry.writable,
        "it has to be read-write to be pinned at all — `control_plane_pins` only walks writable binds"
    );
}

/// And it arrives canonicalized, because the roots it is tested for containment against are.
///
/// A symlinked component would otherwise mean the project never looks like it contains anything.
#[test]
fn the_project_root_is_canonicalized_before_it_is_pinned_against() {
    let tmp = crate::testutil::TmpDir::new();
    let real = tmp.path().join("real-home");
    std::fs::create_dir_all(&real).expect("real dir");
    let link = tmp.path().join("via-link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    let sources = pin_sources(&[], &link);
    let only = sources.last().expect("the project is always pushed");
    assert_eq!(
        only.path,
        std::fs::canonicalize(&real).expect("canonical real"),
        "the symlink was carried through instead of being resolved: {sources:?}"
    );
}

#[test]
fn establish_control_plane_pins_creates_each_pin_and_preserves_its_mode() {
    // A pin's host path is created (so a not-yet-existent control-plane root is present to be
    // frozen) and turned into an extra bind at that path that carries the pin's mode: a read-write
    // intermediate bound from itself, a read-only leaf bound from the empty decoy, so the cage
    // finds the root in place and nothing under it.
    let tmp = TmpDir::new();
    let inter = tmp.path().join("chain/intermediate");
    let leaf = tmp.path().join("chain/intermediate/root");
    let decoy = tmp.path().join("decoy");
    let pins = vec![
        crate::config::Bind {
            path: inter.clone(),
            writable: true,
        },
        crate::config::Bind {
            path: leaf.clone(),
            writable: false,
        },
    ];
    let binds = establish_control_plane_pins(&pins, Some(&decoy)).expect("pins establish");
    assert!(inter.is_dir() && leaf.is_dir(), "each pin path is created");
    assert_eq!(binds.len(), 2);
    assert_eq!(binds[0].src, inter);
    assert_eq!(binds[0].dest, inter);
    assert!(binds[0].writable, "the intermediate is read-write");
    assert_eq!(
        binds[1].src, decoy,
        "the leaf shows the decoy, not sbx's own tree"
    );
    assert_eq!(binds[1].dest, leaf);
    assert!(!binds[1].writable, "the leaf is read-only");

    // With nothing to bind the leaf from, the launch fails closed rather than binding the root
    // itself, which would show the cage what lives under it.
    let err = establish_control_plane_pins(&pins, None).expect_err("a leaf needs its decoy");
    assert!(
        err.to_string().contains(&leaf.display().to_string()),
        "the failure names the leaf: {err}"
    );
}

#[test]
fn a_launch_stages_a_decoy_only_for_a_read_only_pin() {
    let tmp = TmpDir::new();
    let pin = |writable: bool| crate::config::Bind {
        path: tmp.path().join("root"),
        writable,
    };
    // No read-only pin, no decoy: the launches whose project and binds contain none of sbx's
    // roots, and the chain's intermediates alone.
    assert_eq!(pin_decoy(tmp.path(), None, &[]).unwrap(), None);
    assert_eq!(pin_decoy(tmp.path(), None, &[pin(true)]).unwrap(), None);
    // The masks' decoy when they staged one, so a launch keeps a single empty directory.
    let masks = crate::sandbox::fsmask::stage_decoys(&tmp.path().join("masks")).unwrap();
    assert_eq!(
        pin_decoy(tmp.path(), Some(&masks), &[pin(false)]).unwrap(),
        Some(masks.dir.clone())
    );
    // Otherwise one staged for the pins, empty.
    let staged = pin_decoy(tmp.path(), None, &[pin(false)])
        .unwrap()
        .expect("a read-only pin gets a decoy");
    assert!(staged.starts_with(tmp.path()), "{}", staged.display());
    assert_eq!(std::fs::read_dir(&staged).unwrap().count(), 0);
}

#[test]
fn establish_control_plane_pins_fails_closed_when_a_pin_cannot_be_created() {
    // If a pin's path cannot be established (here a file sits where a parent directory must be),
    // the helper errors rather than returning a partial set — so the launch aborts instead of
    // running with the containing read-write bind left unprotected. The failure names the path.
    let tmp = TmpDir::new();
    let blocker = tmp.path().join("blocker");
    std::fs::write(&blocker, b"a file, not a directory").unwrap();
    let pins = vec![crate::config::Bind {
        // Under a regular file, so `create_dir_all` cannot succeed.
        path: blocker.join("root"),
        writable: false,
    }];
    let decoy = tmp.path().join("decoy");
    let err = establish_control_plane_pins(&pins, Some(&decoy))
        .expect_err("a blocked pin must fail closed");
    assert!(
        err.to_string().contains("blocker"),
        "the failure names the unestablishable path: {err}"
    );
}

/// A pin that would undo an `[fs]` mask is dropped, so the mask is not silently undone.
///
/// The pins are appended after the masks and the later bind at a destination wins, so a chain
/// running through a masked directory (`$HOME/.config` with the project root at `$HOME`) would
/// otherwise put the real, read-write directory back over a `deny`'s decoy — and turn a declared
/// `readonly` path read-write. The read-only leaf is the one pin that may stay, under `readonly`
/// only: bound from the empty decoy, it closes more than the mask.
#[test]
fn a_control_plane_pin_that_lands_on_an_fs_mask_is_dropped() {
    let home = PathBuf::from("/home/agent");
    let decoy = PathBuf::from("/data/fs/mask-1/dir");
    let pin = |path: PathBuf, writable: bool| binds::ExtraBind {
        src: if writable {
            path.clone()
        } else {
            decoy.clone()
        },
        dest: path,
        writable,
    };
    // The chain `cd ~ && sbx run` produces for the global config root: a read-write intermediate
    // and the read-only leaf under it.
    let pins = vec![
        pin(home.join(".config"), true),
        pin(home.join(".config/sbx"), false),
    ];
    let masked = |path: PathBuf| crate::sandbox::fsmask::Masked {
        path,
        is_dir: true,
        pattern: String::from(".config/"),
        builtin: false,
    };

    // `deny = [".config/"]`: the decoy is bound at the intermediate, so both it and everything
    // below it must stay the mask's, not the pin's.
    let mut masks = crate::sandbox::fsmask::Expanded {
        denied: vec![masked(home.join(".config"))],
        ..Default::default()
    };
    assert!(
        pins_clear_of_masks(pins.clone(), &masks, &[]).is_empty(),
        "a pin over a denied directory hands the cage back the real one, read-write"
    );

    // `readonly = [".config/"]`: same containment, and the intermediate would re-bind it
    // read-write. The leaf stays, since the mask would otherwise show the cage sbx's own config.
    masks = crate::sandbox::fsmask::Expanded {
        readonly: vec![masked(home.join(".config"))],
        ..Default::default()
    };
    assert_eq!(
        pins_clear_of_masks(pins.clone(), &masks, &[]),
        vec![pin(home.join(".config/sbx"), false)]
    );

    // A mask elsewhere in the project does not cost the control plane its pins.
    masks = crate::sandbox::fsmask::Expanded {
        denied: vec![masked(home.join("src"))],
        ..Default::default()
    };
    assert_eq!(
        pins_clear_of_masks(pins.clone(), &masks, &[]).len(),
        2,
        "only a mask the pin sits under may drop it"
    );
    // And neither does no mask at all, which is every launch without an `[fs]` section.
    assert_eq!(
        pins_clear_of_masks(pins, &crate::sandbox::fsmask::Expanded::default(), &[]).len(),
        2
    );
}

/// What the cage finds at `path` once `binds` are laid in order: the last one bound at the path or
/// at a directory above it. That is the rule measured with bubblewrap, which binds the host's view
/// of a directory and so covers every mount the cage had below it.
fn found_at<'b>(binds: &'b [binds::ExtraBind], path: &Path) -> Option<&'b binds::ExtraBind> {
    binds.iter().rev().find(|b| path.starts_with(&b.dest))
}

/// A control-plane pin laid above an `[fs]` bind must not cover it, and sbx's roots must stay
/// closed around a mask laid inside one, directories held there included.
///
/// The chains are the ones `cd ~ && sbx run` produces, and the `[fs]` binds are what a mask under
/// `.config` and a mask inside the data dir emit: the directories held above them, then the masks.
/// This is the arrangement itself. A mask inside a root is closed by the root's decoy, laid after
/// it, and is not laid again: its destination does not exist in the empty decoy.
#[test]
fn a_control_plane_pin_above_an_fs_bind_leaves_it_in_place() {
    let home = PathBuf::from("/home/agent");
    let bind = |path: &str, writable: bool| binds::ExtraBind {
        src: home.join(path),
        dest: home.join(path),
        writable,
    };
    let mask = |path: &str| binds::ExtraBind {
        src: PathBuf::from("/data/fs/mask-1/file"),
        dest: home.join(path),
        writable: false,
    };
    let root = |path: &str| binds::ExtraBind {
        src: PathBuf::from("/data/fs/mask-1/dir"),
        dest: home.join(path),
        writable: false,
    };
    let pins = vec![
        bind(".config", true),
        root(".config/sbx"),
        bind(".local", true),
        bind(".local/share", true),
        root(".local/share/sbx"),
    ];
    let fs_binds = vec![
        bind(".config", true),
        bind(".config/gh", true),
        bind(".local", true),
        bind(".local/share", true),
        bind(".local/share/sbx", true),
        bind(".local/share/sbx/sub", true),
        mask(".config/gh/hosts.yml"),
        mask(".local/share/sbx/sub/secret"),
    ];
    let laid: Vec<binds::ExtraBind> = fs_binds
        .iter()
        .cloned()
        .chain(pins_clear_of_masks(
            pins,
            &crate::sandbox::fsmask::Expanded::default(),
            &fs_binds,
        ))
        .collect();

    assert_eq!(
        found_at(&laid, &home.join(".config/gh/hosts.yml")),
        Some(&mask(".config/gh/hosts.yml")),
        "a mask outside sbx's roots must stay masked: {laid:#?}"
    );
    assert_eq!(
        found_at(&laid, &home.join(".config/gh")),
        Some(&bind(".config/gh", true)),
        "the directory held above a mask must stay held: {laid:#?}"
    );
    for (path, at) in [
        (".config/sbx", ".config/sbx"),
        (".local/share/sbx", ".local/share/sbx"),
        (".local/share/sbx/sub", ".local/share/sbx"),
        (".local/share/sbx/sub/secret", ".local/share/sbx"),
    ] {
        assert_eq!(
            found_at(&laid, &home.join(path)),
            Some(&root(at)),
            "`{path}` must stay under the decoy of sbx's root: {laid:#?}"
        );
    }
    assert_eq!(
        found_at(&laid, &home.join(".local/state")),
        Some(&bind(".local", true)),
        "a directory outside both keeps its read-write mount point: {laid:#?}"
    );
}

/// The same arrangement, laid by bubblewrap: a mask under `.config` and one inside sbx's data dir
/// stay closed, the directory held above the first cannot be renamed, and sbx's roots stay
/// read-only and show nothing of what they hold. bwrap and a user namespace are enough; no
/// userland is built.
#[test]
fn a_control_plane_pin_above_an_fs_bind_leaves_it_in_place_inside_the_cage() {
    let Some(bwrap) = crate::pathfind::find_on_path("bwrap") else {
        skip_incapable!("skipping control-plane arrangement smoke: need bwrap");
        return;
    };
    if !matches!(crate::probe_userns(), crate::Userns::Ok) {
        skip_incapable!("skipping control-plane arrangement smoke: need a user namespace");
        return;
    }
    let scratch = TmpDir::new();
    let home = scratch.path().join("home");
    for dir in [".config/gh", ".config/sbx", ".local/share/sbx/sub"] {
        std::fs::create_dir_all(home.join(dir)).unwrap();
    }
    std::fs::write(home.join(".config/gh/hosts.yml"), b"HOSTS").unwrap();
    std::fs::write(home.join(".local/share/sbx/sub/secret"), b"SECRET").unwrap();
    std::fs::write(home.join(".config/sbx/sbx.toml"), b"CONFIG").unwrap();
    let home = home.canonicalize().unwrap();

    let policy = crate::config::fspolicy::FsPolicy {
        deny: vec![
            ".config/gh/hosts.yml".to_string(),
            ".local/share/sbx/sub/secret".to_string(),
        ],
        ..Default::default()
    };
    let expanded = crate::sandbox::fsmask::expand(&home, &policy, &[], None);
    assert!(expanded.refused.is_none(), "{:?}", expanded.refused);
    let decoys = crate::sandbox::fsmask::stage_decoys(&scratch.path().join("mask")).unwrap();
    let fs_binds = crate::sandbox::fsmask::agent_binds(&expanded, &decoys, true);
    let pin = |path: &str, writable: bool| binds::ExtraBind {
        src: if writable {
            home.join(path)
        } else {
            decoys.dir.clone()
        },
        dest: home.join(path),
        writable,
    };
    let pins = vec![
        pin(".config", true),
        pin(".config/sbx", false),
        pin(".local", true),
        pin(".local/share", true),
        pin(".local/share/sbx", false),
    ];
    let mut mounts = vec![
        crate::sandbox::spec::Mount::RoBind {
            src: "/usr".into(),
            dest: "/usr".into(),
        },
        crate::sandbox::spec::Mount::Symlink {
            target: "usr/lib".into(),
            dest: "/lib".into(),
        },
        crate::sandbox::spec::Mount::Symlink {
            target: "usr/lib64".into(),
            dest: "/lib64".into(),
        },
        crate::sandbox::spec::Mount::RoBindTry {
            src: "/etc/ld.so.cache".into(),
            dest: "/etc/ld.so.cache".into(),
        },
        crate::sandbox::spec::Mount::Bind {
            src: home.clone(),
            dest: home.clone(),
        },
    ];
    mounts.extend(fs_binds.iter().map(binds::ExtraBind::mount));
    mounts.extend(
        pins_clear_of_masks(pins, &expanded, &fs_binds)
            .iter()
            .map(binds::ExtraBind::mount),
    );

    let script = r#"cd "$1" || exit 9
for f in .config/gh/hosts.yml .local/share/sbx/sub/secret; do
  if cat "$f" >&2; then echo "$f open"; else echo "$f closed"; fi
done
if mv .config/gh .config/gh.moved 2>&1; then echo ".config/gh moved"; mv .config/gh.moved .config/gh; else echo ".config/gh held"; fi
for d in .config/sbx .local/share/sbx; do
  if touch "$d/written" 2>&1; then echo "$d writable"; rm -f "$d/written"; else echo "$d read-only"; fi
  if [ -z "$(ls -A "$d")" ]; then echo "$d empty"; else echo "$d shows its contents"; fi
done
touch .config/new && echo ".config writable"
echo end"#;
    let spec = crate::sandbox::spec::SandboxSpec::new(
        "/".into(),
        mounts,
        Vec::new(),
        crate::sandbox::spec::NetPolicy::Shared,
        vec![
            std::ffi::OsString::from("/usr/bin/sh"),
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from(script),
            std::ffi::OsString::from("sh"),
            home.clone().into_os_string(),
        ],
    )
    .expect("a spec");
    let out = crate::sandbox::argv::run_bwrap(&bwrap, &spec).expect("spawn bwrap");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.lines().any(|l| l == "end"),
        "the cage did not run to its end:\n{stdout}\n{stderr}"
    );
    for line in [
        ".config/gh/hosts.yml closed",
        ".local/share/sbx/sub/secret closed",
        ".config/gh held",
        ".config/sbx read-only",
        ".config/sbx empty",
        ".local/share/sbx read-only",
        ".local/share/sbx empty",
        ".config writable",
    ] {
        assert!(
            stdout.lines().any(|l| l == line),
            "expected `{line}`:\n{stdout}\n{stderr}"
        );
    }
}

#[test]
fn keep_passthrough_drops_bare_c_locale_but_keeps_real_ones() {
    let out = keep_passthrough([
        ("TERM".to_string(), "xterm".to_string()),
        ("LANG".to_string(), "C".to_string()),
        ("LC_ALL".to_string(), "fr_FR.UTF-8".to_string()),
    ]);
    // TERM always passes; a bare `C` LANG is dropped so it cannot break the UTF-8 floor;
    // a real locale is kept
    assert!(out.iter().any(|(k, v)| k == "TERM" && v == "xterm"));
    assert!(!out.iter().any(|(k, _)| k == "LANG"));
    assert!(out.iter().any(|(k, v)| k == "LC_ALL" && v == "fr_FR.UTF-8"));

    // `POSIX` is dropped too (case-insensitive), while `C.UTF-8` — a real UTF-8 locale — passes
    let out = keep_passthrough([
        ("LC_ALL".to_string(), "posix".to_string()),
        ("LANG".to_string(), "C.UTF-8".to_string()),
    ]);
    assert!(!out.iter().any(|(k, _)| k == "LC_ALL"));
    assert!(out.iter().any(|(k, v)| k == "LANG" && v == "C.UTF-8"));
}

// The in-cage task client is a script, so the programs its shebang and its body name must be the
// ones the CAGE resolves. Naming the host's would produce a client that cannot run where it is
// bound — and the tests that exercise the client run it with the host's, so this is what pins
// the shipped pairing.
#[test]
fn the_task_client_is_written_against_the_cages_own_programs() {
    let userland = Userland {
        base_roots: vec![],
        interp_src: PathBuf::from("/store/nix-ld"),
        interp_dest: PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
        ca_bundle_src: PathBuf::from("/store/cacert/etc/ssl/certs/ca-bundle.crt"),
        base_loader: PathBuf::from("/nix/store/glibc/lib/ld"),
        foreign_lib_paths: vec![],
        bin_paths: vec![],
        distro: None,
        shell_bin: PathBuf::from("/nix/store/bash/bin/bash"),
        env_bin: PathBuf::from("/nix/store/coreutils/bin/env"),
        ldd_bin: PathBuf::from("/nix/store/glibc-bin/bin/ldd"),
        socat_bin: PathBuf::from("/nix/store/socat/bin/socat"),
        mise_bin: PathBuf::from("/nix/store/mise/bin/mise"),
        nix_bin: PathBuf::from("/nix/store/nix/bin/nix"),
        locale_archive: PathBuf::from("/nix/store/locales/lib/locale/locale-archive"),
        zoneinfo_src: PathBuf::from("/nix/store/tzdata/share/zoneinfo"),
    };
    let (bash, socat, head) = task_client_programs(&userland);
    assert_eq!(bash, PathBuf::from("/nix/store/bash/bin/bash"));
    assert_eq!(socat, PathBuf::from("/nix/store/socat/bin/socat"));
    assert_eq!(
        head,
        PathBuf::from("/nix/store/coreutils/bin/head"),
        "`head` comes from the same coreutils the cage already has"
    );
}

/// Every program a wrap's preamble execs is pinned read-only, from sbx's own store.
///
/// The exec-enforcement shim is the innermost wrap, so each preamble around it runs before any
/// filter exists. Those preambles name absolute paths in `/nix` — the project's own store,
/// bound read-write — so without these pins in-cage code replaces `bash`, `socat`, `mise`,
/// `nix` or the loader they all run under, and its replacement is the cage's first process,
/// unfiltered by the `[proc]` policy and the `[fs] scan` lens the launch reports as active.
///
/// What the pin has to get right is all three of: the whole store path (not the file, whose
/// directory would stay renameable), read-only, and sourced from the **shared** store — a pin
/// taken from the project's copy would freeze a trojan already planted there.
#[test]
fn the_programs_every_wrap_preamble_execs_are_pinned_read_only_from_the_shared_store() {
    let userland = Userland {
        base_roots: vec![],
        interp_src: PathBuf::from("/store/nix-ld"),
        interp_dest: PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
        ca_bundle_src: PathBuf::from("/store/cacert/etc/ssl/certs/ca-bundle.crt"),
        base_loader: PathBuf::from("/nix/store/hash-glibc/lib/ld-linux-x86-64.so.2"),
        foreign_lib_paths: vec![],
        bin_paths: vec![],
        distro: None,
        shell_bin: PathBuf::from("/nix/store/hash-bash/bin/bash"),
        env_bin: PathBuf::from("/nix/store/hash-coreutils/bin/env"),
        ldd_bin: PathBuf::from("/nix/store/hash-glibc-bin/bin/ldd"),
        socat_bin: PathBuf::from("/nix/store/hash-socat/bin/socat"),
        mise_bin: PathBuf::from("/nix/store/hash-mise/bin/mise"),
        nix_bin: PathBuf::from("/nix/store/hash-nix/bin/nix"),
        locale_archive: PathBuf::from("/nix/store/hash-locales/lib/locale/locale-archive"),
        zoneinfo_src: PathBuf::from("/nix/store/hash-tzdata/share/zoneinfo"),
    };
    let layout = crate::store::Layout::under(Path::new("/data/sbx"));
    // The two GUI holes contribute a preamble program each; they exist only under
    // `gui = "wayland"`, so they arrive as an explicit list rather than on `Userland`.
    let certutil = PathBuf::from("/nix/store/hash-nss-tools/bin/certutil");
    let dbus = PathBuf::from("/nix/store/hash-dbus/bin/dbus-daemon");
    let gui_programs = [certutil.as_path(), dbus.as_path()];
    let pins = plumbing_pins(&userland, &gui_programs, &layout);

    for program in [
        &userland.shell_bin,
        &userland.socat_bin,
        &userland.mise_bin,
        &userland.nix_bin,
        &userland.base_loader,
        // Coreutils, reached through `env`: the preambles run `mkdir`, `cat`, `ln`, `readlink`,
        // `touch`, `rm` and `sleep` from beside it, by absolute path.
        &userland.env_bin,
        &certutil,
        &dbus,
    ] {
        let pin = pins
            .iter()
            .find(|b| program.starts_with(&b.dest))
            .unwrap_or_else(|| panic!("{} is left on the writable store", program.display()));
        assert!(
            !pin.writable,
            "{} is pinned writable, which pins nothing",
            pin.dest.display()
        );
        assert_ne!(
            &pin.dest, program,
            "the pin must cover the whole store path, not just the binary: a writable \
             directory around it can be renamed aside and rebuilt with a forged binary"
        );
        assert_eq!(
            pin.src,
            PathBuf::from("/data/sbx/store/nix/store").join(pin.dest.file_name().unwrap()),
            "the pinned bytes must come from sbx's own store, not the project's copy"
        );
    }

    // Eight distinct store paths, so no pin is dropped by the de-duplication that keeps a
    // shared root from being mounted twice — and a launch with no GUI hole pins only the six
    // every posture runs.
    assert_eq!(pins.len(), 8);
    assert_eq!(plumbing_pins(&userland, &[], &layout).len(), 6);

    // A path that does not resolve through the store is not a store path and must not be
    // mounted over — the pin set is derived, never assumed.
    assert_eq!(store_root_of(Path::new("/opt/sbx/proc-shim")), None);
    assert_eq!(store_root_of(Path::new("/nix/store")), None);
}

#[test]
fn egress_ca_overrides_the_structural_cacert() {
    // The assembler upserts the overlay env on last-occurrence, so the winner for a key is
    // its last entry in this layering. Under a network allowlist the cage must trust the
    // egress proxy's per-session CA, not sbx's root bundle: egress is layered after cacert,
    // so it wins. A trusted config, layered last, still has the final say (self-harm only).
    let winner = |env: &[(String, String)]| {
        env.iter()
            .rev()
            .find(|(k, _)| k == "SSL_CERT_FILE")
            .map(|(_, v)| v.clone())
    };

    let cacert = || {
        vec![(
            "SSL_CERT_FILE".to_string(),
            "/etc/ssl/certs/ca-bundle.crt".to_string(),
        )]
    };
    let egress = || {
        vec![(
            "SSL_CERT_FILE".to_string(),
            "/opt/sbx/egress-ca.pem".to_string(),
        )]
    };

    let env = extra_cage_env(vec![
        (EnvLayer::Cacert, cacert()),
        (EnvLayer::Egress, egress()),
    ]);
    assert_eq!(
        winner(&env).as_deref(),
        Some("/opt/sbx/egress-ca.pem"),
        "egress CA must override the structural cacert"
    );

    let cfg = vec![("SSL_CERT_FILE".to_string(), "/cfg/ca.pem".to_string())];
    let env = extra_cage_env(vec![
        (EnvLayer::Cacert, cacert()),
        (EnvLayer::Egress, egress()),
        (EnvLayer::Config, cfg),
    ]);
    assert_eq!(
        winner(&env).as_deref(),
        Some("/cfg/ca.pem"),
        "a trusted config has the final say over the CA"
    );

    // with no egress (shared/isolated posture) the structural cacert stands
    let env = extra_cage_env(vec![(EnvLayer::Cacert, cacert())]);
    assert_eq!(
        winner(&env).as_deref(),
        Some("/etc/ssl/certs/ca-bundle.crt"),
        "without egress the hermetic cacert is the trust anchor"
    );
}

/// The nesting is the enum's, not the order the blocks in `build` happen to run in.
///
/// Each marker wrap prepends its own name, so the composed argv reads outermost first — which is
/// also the order the preambles run in. Registering them shuffled and still getting that order
/// is what the layer tag buys: the four constraints below used to hold only because their blocks
/// The composed startup is what the wraps nest around, not a peer of it.
///
/// `build` takes a `&Prepared`, so no unit test can reach it, and this ordering lives nowhere
/// else: [`wrap_cage_command`] cannot tell a bare command from a composed one, and every test of
/// [`compose_startup_cmd`] hands it a `cmd` directly. So the check is on the source, the way the
/// cage-suite and docs guards are, because the alternative is no check at all.
///
/// What it protects is not a style preference. An install step finishes making the command
/// runnable, so it needs everything the command needs. Composed *after* the wraps it ran outside
/// every layer: before the mise equip lanes, so a step asking `mise where` about a package found
/// nothing and aborted the launch before the equip that would have installed it; and before the
/// egress forwarder, so a step that downloads got `https_proxy` pointed at a port with nothing
/// listening. Measured on three shipped bundles whose step does exactly that.
#[test]
fn the_wraps_nest_around_the_composed_startup_and_not_the_bare_command() {
    // The whole file is production code now that the tests live in this sibling, so no cut is
    // needed to keep the tests' own calls to these helpers out of the search.
    let body = include_str!("../build.rs");
    let compose = body
        .find("compose_startup_cmd(&prep.cfg.provisions")
        .expect("`build` composes the startup from the resolved provisions");
    let wrap = body
        .find("wrap_cage_command(startup_cmd, wraps)")
        .expect("`build` nests the wraps around the composed startup, by that name");
    assert!(
        compose < wrap,
        "`build` applies its wraps at byte {wrap} and composes the startup at {compose}: the \
         composition has moved back outside the nesting, so every bundle's install step runs \
         before the mise equip lanes and before the egress forwarder is up"
    );
    // The bare command must no longer be wrapped anywhere: a second call site would reinstate
    // the old order for whichever branch reached it first.
    assert!(
        !body.contains("wrap_cage_command(cmd, wraps)"),
        "`build` still wraps the bare command somewhere, so a launch can take the old order"
    );
}

/// sat in the right places, hundreds of lines apart, and nothing checked it.
#[test]
fn the_wraps_nest_by_layer_however_the_blocks_registered_them() {
    let marker = |name: &'static str| -> CommandWrap<'static> {
        Box::new(move |cmd: Vec<OsString>| {
            let mut out = vec![OsString::from(name)];
            out.extend(cmd);
            out
        })
    };

    // Deliberately not in layer order, and with the two mise lanes registered in the order
    // `build` registers them: lane 2 (`install`) then lane 1 (`use -g`).
    let wraps = vec![
        (WrapLayer::Portal, marker("portal")),
        (WrapLayer::MiseEquip, marker("mise-install")),
        (WrapLayer::Egress, marker("egress")),
        (WrapLayer::ProcEnforce, marker("proc")),
        (WrapLayer::MiseEquip, marker("mise-use-g")),
        (WrapLayer::CaTrust, marker("catrust")),
        (WrapLayer::FlakeEquip, marker("flake")),
        (WrapLayer::Forward, marker("forward")),
    ];
    let out = wrap_cage_command(vec![OsString::from("the-command")], wraps);

    assert_eq!(
        out,
        [
            "portal",
            "catrust",
            "egress",
            "forward",
            "flake",
            "mise-use-g",
            "mise-install",
            "proc",
            "the-command",
        ]
        .map(OsString::from)
    );
}

/// A launch that contributes nothing runs its command bare — no preamble, no shell.
#[test]
fn a_launch_with_no_wraps_leaves_the_command_untouched() {
    let cmd = vec![OsString::from("jq"), OsString::from("--version")];
    assert_eq!(wrap_cage_command(cmd.clone(), vec![]), cmd);
}

/// The precedence is the enum's, not the caller's. Listing the layers backwards must produce
/// exactly the same environment as listing them in order — that is the whole reason the sources
/// carry a tag instead of riding an argument list, where two of them swapped would compile in
/// silence and change which CA the cage trusts.
#[test]
fn the_layer_decides_precedence_not_the_order_the_caller_lists_them_in() {
    let key = "SSL_CERT_FILE".to_string();
    let in_order = vec![
        (EnvLayer::Passthrough, vec![(key.clone(), "/host".into())]),
        (EnvLayer::Cacert, vec![(key.clone(), "/hermetic".into())]),
        (EnvLayer::Egress, vec![(key.clone(), "/mitm".into())]),
        (EnvLayer::Config, vec![(key.clone(), "/cfg".into())]),
    ];
    let mut backwards = in_order.clone();
    backwards.reverse();

    assert_eq!(extra_cage_env(in_order.clone()), extra_cage_env(backwards));
    assert_eq!(
        extra_cage_env(in_order).last().map(|(_, v)| v.clone()),
        Some("/cfg".to_string()),
        "the config layer stays last however the caller lists it"
    );
}

/// A caller contributing one layer in two pieces must keep the pieces in the order it gave
/// them: within a layer there is no precedence to derive, so only a stable sort is correct.
#[test]
fn two_pieces_of_one_layer_keep_the_order_they_were_given() {
    let env = extra_cage_env(vec![
        (EnvLayer::Gui, vec![("WAYLAND_DISPLAY".into(), "a".into())]),
        (
            EnvLayer::Cacert,
            vec![("SSL_CERT_FILE".into(), "ca".into())],
        ),
        (EnvLayer::Gui, vec![("WAYLAND_DISPLAY".into(), "b".into())]),
    ]);
    let seen: Vec<&str> = env
        .iter()
        .filter(|(k, _)| k == "WAYLAND_DISPLAY")
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(seen, ["a", "b"]);
}

#[test]
fn net_policy_maps_the_config_posture_to_the_cage_posture() {
    // the cheap, total map between the two posture vocabularies — the one place
    // a `network = "none"` config becomes an isolated cage.
    assert_eq!(
        net_policy(&crate::config::NetworkPolicy::Shared),
        NetPolicy::Shared
    );
    assert_eq!(
        net_policy(&crate::config::NetworkPolicy::Isolated),
        NetPolicy::Isolated
    );
    // an allowlist posture maps to an isolated (empty) namespace by design — the Model-B
    // foundation: the cage's only egress is the bound socket to the host filtering proxy,
    // never the shared host network.
    assert_eq!(
        net_policy(&crate::config::NetworkPolicy::Allowlist(Box::default())),
        NetPolicy::Isolated
    );
}

#[test]
fn resolve_wayland_hole_binds_the_socket_file_never_the_runtime_dir() {
    // The load-bearing invariant of the GUI hole: a relative display resolves under
    // XDG_RUNTIME_DIR to the socket *file*, never the runtime directory — which also holds the
    // dbus session bus, pulse, and the gpg/ssh agents a directory bind would leak.
    let (socket, env) = resolve_wayland_hole(Some("wayland-0"), Some("/run/user/1000")).unwrap();
    assert_eq!(socket, PathBuf::from("/run/user/1000/wayland-0"));
    assert_ne!(
        socket,
        PathBuf::from("/run/user/1000"),
        "the bind target must be the socket file, never the runtime directory"
    );
    assert_eq!(socket.file_name().unwrap(), "wayland-0");
    assert!(env.contains(&("WAYLAND_DISPLAY".to_string(), "wayland-0".to_string())));
    assert!(env.contains(&("XDG_RUNTIME_DIR".to_string(), "/run/user/1000".to_string())));

    // An absolute display is the socket path verbatim (XDG_RUNTIME_DIR is not needed to
    // locate it, per the Wayland convention).
    let (socket, env) = resolve_wayland_hole(Some("/tmp/wl.sock"), Some("/run/user/1000")).unwrap();
    assert_eq!(socket, PathBuf::from("/tmp/wl.sock"));
    assert!(env.contains(&("WAYLAND_DISPLAY".to_string(), "/tmp/wl.sock".to_string())));

    // No display, an empty display, or a relative display with no runtime dir cannot be
    // located → error, so the caller warns and runs without a display (fail-closed — it
    // never binds a wrong or guessed path).
    assert!(resolve_wayland_hole(None, Some("/run/user/1000")).is_err());
    assert!(resolve_wayland_hole(Some(""), Some("/run/user/1000")).is_err());
    assert!(resolve_wayland_hole(Some("wayland-0"), None).is_err());
}

/// Two grants contribute to the loader path, and a cage with both must keep the directories of
/// each. The union is what a path list means; the last-writer rule that governs every other shared
/// key would drop one grant's libraries with no message, which is how a caged app loses its audio
/// or its GPU while both are declared.
#[test]
fn the_loader_path_is_the_union_of_what_each_grant_contributed() {
    let mut env = vec![
        ("WAYLAND_DISPLAY".to_string(), "wayland-0".to_string()),
        (
            "LD_LIBRARY_PATH".to_string(),
            "/usr/lib/wsl/lib".to_string(),
        ),
        ("XDG_RUNTIME_DIR".to_string(), "/run/user/1000".to_string()),
        (
            "LD_LIBRARY_PATH".to_string(),
            "/store/pulse/lib".to_string(),
        ),
    ];
    super::merge_loader_path(&mut env);
    let loader: Vec<&(String, String)> =
        env.iter().filter(|(k, _)| k == "LD_LIBRARY_PATH").collect();
    assert_eq!(loader.len(), 1, "one entry, not two: {env:?}");
    assert_eq!(
        loader[0].1, "/usr/lib/wsl/lib:/store/pulse/lib",
        "in the order the grants added them"
    );
    assert_eq!(env.len(), 3, "the other keys are untouched: {env:?}");
    assert_eq!(env[0].0, "WAYLAND_DISPLAY", "and keep their order");

    // The ordinary cases: one grant, and none at all.
    let mut one = vec![("LD_LIBRARY_PATH".to_string(), "/only".to_string())];
    super::merge_loader_path(&mut one);
    assert_eq!(
        one,
        vec![("LD_LIBRARY_PATH".to_string(), "/only".to_string())]
    );

    let mut none = vec![("HOME".to_string(), "/home/a".to_string())];
    let before = none.clone();
    super::merge_loader_path(&mut none);
    assert_eq!(none, before, "a cage with neither grant is untouched");
}
