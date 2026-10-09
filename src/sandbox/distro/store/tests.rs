use super::*;

fn layout_under(dir: &Path) -> Layout {
    Layout::under(dir)
}

#[test]
fn a_digest_names_a_directory_nothing_has_to_quote() {
    let layout = layout_under(Path::new("/data/sbx"));
    let dir = image_dir(
        &layout,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_eq!(
        dir,
        Path::new(
            "/data/sbx/distro/sha256-0000000000000000000000000000000000000000000000000000000000000000"
        )
    );
    // One component, so the digest cannot be read as a path of its own.
    assert_eq!(dir.components().count(), 5);
}

#[test]
fn a_lock_answers_for_the_image_that_wrote_it_and_no_other() {
    let tmp = crate::testutil::TmpDir::new();
    let lock = tmp.join("distro.lock");
    let digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    crate::store::write_lock(&lock, "oci:docker.io/library/debian:10", digest).unwrap();

    assert_eq!(
        locked_key(&lock, "oci:docker.io/library/debian:10")
            .unwrap()
            .as_deref(),
        Some(digest)
    );
    // A lock left by another image is not this one's pin, however recent it is.
    assert_eq!(
        locked_key(&lock, "oci:docker.io/library/debian:11").unwrap(),
        None
    );
    // And no lock at all is not a pin either.
    assert_eq!(
        locked_key(&tmp.join("absent.lock"), "oci:x/y:z").unwrap(),
        None
    );
}

#[test]
fn a_lock_holding_something_that_is_not_a_digest_is_not_read_as_one() {
    // The value goes on to name a directory, so it is held to the grammar rather than trusted for
    // having been written by sbx: a lock is a file on disk like any other.
    let tmp = crate::testutil::TmpDir::new();
    let locator = "oci:docker.io/library/debian:10";
    for bad in [
        "../../etc",
        "sha256:short",
        "sha512:1111111111111111111111111111111111111111111111111111111111111111",
        "",
    ] {
        let lock = tmp.join("distro.lock");
        crate::store::write_lock(&lock, locator, bad).unwrap();
        assert_eq!(
            locked_key(&lock, locator).unwrap(),
            None,
            "`{bad}` must not be read as a digest"
        );
    }
}

#[test]
fn an_image_missing_what_a_userland_supplies_is_refused_by_name() {
    let tmp = crate::testutil::TmpDir::new();
    let rootfs = tmp.join("rootfs");
    std::fs::create_dir_all(rootfs.join("bin")).unwrap();
    std::os::unix::fs::symlink("busybox", rootfs.join("bin/sh")).unwrap();

    let err = check_supplied(&rootfs, "oci:docker.io/library/alpine:3.22")
        .expect_err("an image without bash or a loader cannot host a cage");
    let message = err.to_string();
    // Every missing path, not the first: a user fixing them one launch at a time learns the list
    // one entry at a time.
    for path in ["/bin/bash", "/usr/bin/env", "/lib64/ld-linux-x86-64.so.2"] {
        assert!(
            message.contains(path),
            "`{path}` is not named in `{message}`"
        );
    }
    assert!(
        !message.contains("/bin/sh,"),
        "the one path it does carry is not named: {message}"
    );
}

#[test]
fn a_dangling_symlink_counts_as_supplied() {
    // What an image puts at one of these paths is the image's business: Debian's `/etc/localtime`
    // is a link, and a link whose target only appears under a later mount is not a missing file.
    let tmp = crate::testutil::TmpDir::new();
    let rootfs = tmp.join("rootfs");
    for dir in ["bin", "usr/bin", "lib64", "etc"] {
        std::fs::create_dir_all(rootfs.join(dir)).unwrap();
    }
    for (link, target) in [
        ("bin/sh", "dash"),
        ("bin/bash", "/nowhere/bash"),
        ("usr/bin/env", "/nowhere/env"),
        ("usr/bin/ldd", "/nowhere/ldd"),
        ("lib64/ld-linux-x86-64.so.2", "/nowhere/ld"),
        ("etc/localtime", "/usr/share/zoneinfo/Etc/UTC"),
    ] {
        std::os::unix::fs::symlink(target, rootfs.join(link)).unwrap();
    }
    check_supplied(&rootfs, "oci:example.com/x/y:1").expect("every path is carried");
}

#[test]
fn a_provisioned_image_lands_with_its_lock_and_its_mountpoints() {
    // The whole chain against a real registry: resolve a tag, fetch and apply every layer, add the
    // mountpoints a read-only root cannot be given later, and record the pin.
    let tmp = crate::testutil::TmpDir::new();
    let layout = layout_under(tmp.path());
    let lock = tmp.join("distro.lock");
    let locator = "oci:docker.io/library/debian:10-slim";
    // Under test a layer is unpacked by this process rather than in a cage (see `super::unpack`),
    // so no bubblewrap is started and this one is never looked up.
    let bwrap = Path::new("bwrap");

    let rootfs = match provision(&layout, bwrap, locator, &lock, "proj0001", None, None) {
        Ok(r) => r,
        Err(e) => {
            skip_unreachable!("skipping the provision: {e}");
            return;
        }
    };

    let release = std::fs::read_to_string(rootfs.join("etc/os-release")).expect("os-release");
    assert!(release.contains("ID=debian"), "{release}");

    // The mountpoints the image does not carry, which no launch could add afterwards.
    for (path, kind) in crate::sandbox::binds::DISTRO_MOUNTPOINTS {
        let on_disk = rootfs.join(path.trim_start_matches('/'));
        let meta = on_disk
            .symlink_metadata()
            .unwrap_or_else(|e| panic!("`{path}` is not a mountpoint in the tree: {e}"));
        if *kind == crate::sandbox::binds::Mountpoint::Dir && !meta.file_type().is_symlink() {
            assert!(meta.is_dir(), "`{path}` must be a directory");
        }
    }

    // The pin, and the tree named by it.
    let (source, digest) = crate::store::read_lock_lines(&lock)
        .unwrap()
        .expect("a lock was written");
    assert_eq!(source, locator);
    let digest = digest.expect("the lock records a digest");
    assert!(reference::valid_digest(&digest).is_some(), "{digest}");
    assert_eq!(rootfs, image_dir(&layout, &digest).join("rootfs"));

    // Nothing half-written is left beside it: a partial tree is removed or renamed, never kept.
    let leftovers: Vec<_> = std::fs::read_dir(layout.distro_dir())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .filter(|n| n.contains(".partial"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    // A second call is a lock read and a `stat`: same tree, and nothing fetched again.
    let again = provision(&layout, bwrap, locator, &lock, "proj0002", None, None)
        .expect("the second call reuses the tree");
    assert_eq!(again, rootfs);

    // Each launch records its own holder, and a tree already unpacked records it too: the marker is
    // what a reclaim reads to tell a running cage from a lock's next choice.
    let roots = rootfs.parent().unwrap().join(ROOTS_DIR);
    for holder in ["proj0001", "proj0002"] {
        assert!(roots.join(holder).is_file(), "`{holder}` holds the tree");
    }
}

/// A launch reads the lock, provisions (up to an hour unpacking), then pins what it provisioned. An
/// `sbx upgrade` that rolled the image in between has written its newer digest, and the launch put
/// the older one back without a word, so every later launch stayed on it. A lock that no longer
/// reads as it did is left to whoever wrote it.
#[test]
fn a_launch_leaves_a_lock_that_moved_while_it_provisioned() {
    let tmp = crate::testutil::TmpDir::new();
    let lock = tmp.join("distro.lock");
    let locator = "oci:docker.io/library/debian:12";
    let older = format!("sha256:{}", "a".repeat(64));
    let newer = format!("sha256:{}", "b".repeat(64));

    // Nothing pinned before, nothing since: the launch pins what it provisioned.
    assert!(pin_unless_moved(&lock, locator, &older, &None).unwrap());
    let read = crate::store::read_lock_lines(&lock).unwrap();
    assert_eq!(read, Some((locator.to_string(), Some(older.clone()))));

    // An upgrade rolls the image while the launch provisions what it read.
    crate::store::write_lock(&lock, locator, &newer).unwrap();
    assert!(!pin_unless_moved(&lock, locator, &older, &read).unwrap());
    assert_eq!(
        crate::store::read_lock_lines(&lock).unwrap(),
        Some((locator.to_string(), Some(newer.clone()))),
        "the newer pin stands"
    );

    // Unmoved since the read: the launch writes what it resolved, a re-pin included.
    let read = crate::store::read_lock_lines(&lock).unwrap();
    let newest = format!("sha256:{}", "c".repeat(64));
    assert!(pin_unless_moved(&lock, locator, &newest, &read).unwrap());
    assert_eq!(
        crate::store::read_lock_lines(&lock).unwrap(),
        Some((locator.to_string(), Some(newest)))
    );
}

/// A dry run asks the same question a roll asks and reports the same answer, with the lock left
/// as it was. A locator that carries its digest resolves to itself, so this needs no registry.
#[test]
fn a_dry_run_reports_the_new_digest_and_leaves_the_lock() {
    let tmp = crate::testutil::TmpDir::new();
    let layout = layout_under(&tmp.join("data"));
    let lock = tmp.join("distro.lock");
    let old = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let new = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let locator = format!("oci:docker.io/library/debian@{new}");
    crate::store::write_lock(&lock, "oci:docker.io/library/debian:10", old).unwrap();
    let seeded = std::fs::read(&lock).unwrap();

    let dry = refresh(
        &layout,
        &locator,
        &[],
        &lock,
        None,
        crate::sandbox::RollMode::DryRun,
    )
    .unwrap();
    assert_eq!(dry.key, new);
    assert_eq!(dry.previous.as_deref(), Some(old));
    assert_eq!(
        std::fs::read(&lock).unwrap(),
        seeded,
        "a dry run writes nothing"
    );

    let rolled = refresh(
        &layout,
        &locator,
        &[],
        &lock,
        None,
        crate::sandbox::RollMode::Apply,
    )
    .unwrap();
    assert_eq!(rolled, dry, "the roll locks what the dry run reported");
    assert_eq!(locked_key(&lock, &locator).unwrap().as_deref(), Some(new));
}

/// Two `run` lists name two userlands, whatever bytes their commands carry: a command is hashed
/// behind its length, so one holding a NUL does not run into the next.
#[test]
fn two_run_lists_never_share_a_key() {
    let base = format!("sha256:{}", "1".repeat(64));
    let key = |run: &[&str]| {
        derived_key(
            &base,
            &run.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
        )
    };
    for (one, other) in [
        (&["a\0bc"][..], &["a", "bc"][..]),
        (&["a", "bc"][..], &["ab", "c"][..]),
        (&["a", "\0bc"][..], &["a\0", "bc"][..]),
        (&[""][..], &[][..]),
    ] {
        assert_ne!(key(one), key(other), "{one:?} and {other:?}");
    }
    assert!(
        valid_key(&key(&["a"])),
        "a derived key is one a lock is read back as"
    );
}

/// A key read from a lock names a tree under the store and nothing else: one that climbs out of it
/// through a tree that is really there is not read, and no `base` outside the store is reported.
#[test]
fn a_roll_reads_no_base_outside_the_store() {
    let tmp = crate::testutil::TmpDir::new();
    let layout = layout_under(&tmp.join("data"));
    let hex = "3".repeat(64);
    let planted = format!("sha256:{}", "1".repeat(64));
    std::fs::create_dir_all(layout.distro_dir().join(format!("derived-sha256-{hex}"))).unwrap();
    std::fs::create_dir_all(tmp.join("outside")).unwrap();
    std::fs::write(tmp.join("outside").join(BASE_FILE), &planted).unwrap();
    let lock = tmp.join("distro.lock");
    let escaping = format!("derived:sha256:{hex}/../../../outside");
    crate::store::write_lock(&lock, "oci:x/y:1", &escaping).unwrap();
    assert!(!valid_key(&escaping));

    let new = format!("sha256:{}", "2".repeat(64));
    let rolled = refresh(
        &layout,
        &format!("oci:docker.io/library/debian@{new}"),
        &[],
        &lock,
        None,
        crate::sandbox::RollMode::DryRun,
    )
    .unwrap();
    assert_eq!(rolled.previous.as_deref(), Some(escaping.as_str()));
    assert_eq!(rolled.previous_base, None);
}

/// A derived tree's `base` that is gone means "re-resolve"; one that is there and cannot be read
/// stops a launch naming it, and a roll, which only reports it, leaves it out.
#[test]
fn an_unreadable_base_is_an_error_and_a_missing_one_is_not() {
    let tmp = crate::testutil::TmpDir::new();
    let layout = layout_under(&tmp.join("data"));
    let key = format!("derived:sha256:{}", "4".repeat(64));
    let tree = image_dir(&layout, &key);
    std::fs::create_dir_all(&tree).unwrap();
    let lock = tmp.join("distro.lock");
    let locator = "oci:docker.io/library/debian:12";
    crate::store::write_lock(&lock, locator, &key).unwrap();

    assert_eq!(locked_base(&layout, &lock, locator).unwrap(), None);

    let base = format!("sha256:{}", "5".repeat(64));
    std::fs::write(tree.join(BASE_FILE), &base).unwrap();
    assert_eq!(locked_base(&layout, &lock, locator).unwrap(), Some(base));

    std::fs::remove_file(tree.join(BASE_FILE)).unwrap();
    std::fs::create_dir(tree.join(BASE_FILE)).unwrap();
    let err = locked_base(&layout, &lock, locator).expect_err("a directory is not a base");
    assert!(err.to_string().contains(BASE_FILE), "{err}");

    let new = format!("sha256:{}", "6".repeat(64));
    let rolled = refresh(
        &layout,
        &format!("oci:docker.io/library/debian@{new}"),
        &[],
        &lock,
        None,
        crate::sandbox::RollMode::DryRun,
    )
    .expect("a roll does not fail on what it only reports");
    assert_eq!(rolled.previous_base, None);
}

/// A lookup that fails for any reason but absence is not a path the image lacks: a loop is
/// reported as the failure it is, while a parent that is a file is an absent path.
#[test]
fn a_lookup_that_fails_is_not_a_missing_path() {
    let tmp = crate::testutil::TmpDir::new();
    let tree = |name: &str| {
        let rootfs = tmp.join(name).join("rootfs");
        for dir in ["bin", "usr/bin", "etc"] {
            std::fs::create_dir_all(rootfs.join(dir)).unwrap();
        }
        for file in [
            "bin/sh",
            "bin/bash",
            "usr/bin/env",
            "usr/bin/ldd",
            "etc/localtime",
        ] {
            std::fs::write(rootfs.join(file), "").unwrap();
        }
        rootfs
    };

    let looping = tree("loop");
    std::os::unix::fs::symlink("lib64", looping.join("lib64")).unwrap();
    let err = check_supplied(&looping, "oci:x/y:1").expect_err("a loop is not an answer");
    let message = err.to_string();
    assert!(
        message.contains("/lib64/ld-linux-x86-64.so.2") && !message.contains("does not carry"),
        "{message}"
    );

    let file = tree("file");
    std::fs::write(file.join("lib64"), "").unwrap();
    let err = check_supplied(&file, "oci:x/y:1").expect_err("no loader under a file");
    assert!(err.to_string().contains("does not carry"), "{err}");
}

/// What an image supplies is looked up as the cage will see it: a link in the image reads an
/// absolute target as the image's own path, never the host's. Looked up on the host, an image with
/// no loader passed through the host's `/usr/lib64` (on a host that carries one, as most do), and a
/// valid image whose `lib64` names `/opt/l64` was refused on a host without that directory.
#[test]
fn an_images_links_are_followed_inside_the_image_not_on_the_host() {
    let tmp = crate::testutil::TmpDir::new();
    let image = |name: &str| {
        let rootfs = tmp.join(name).join("rootfs");
        for dir in ["bin", "usr/bin", "etc"] {
            std::fs::create_dir_all(rootfs.join(dir)).unwrap();
        }
        for file in [
            "bin/sh",
            "bin/bash",
            "usr/bin/env",
            "usr/bin/ldd",
            "etc/localtime",
        ] {
            std::fs::write(rootfs.join(file), "").unwrap();
        }
        rootfs
    };

    let borrowed = image("borrowed");
    std::os::unix::fs::symlink("/usr/lib64", borrowed.join("lib64")).unwrap();
    let err =
        check_supplied(&borrowed, "oci:x/y:1").expect_err("the host's loader is not the image's");
    assert!(
        err.to_string()
            .contains("does not carry /lib64/ld-linux-x86-64.so.2"),
        "{err}"
    );

    let elsewhere = image("elsewhere");
    std::fs::create_dir_all(elsewhere.join("opt/l64")).unwrap();
    std::fs::write(elsewhere.join("opt/l64/ld-linux-x86-64.so.2"), "").unwrap();
    std::os::unix::fs::symlink("/opt/l64", elsewhere.join("lib64")).unwrap();
    check_supplied(&elsewhere, "oci:x/y:1").expect("the loader the image's own link names");

    let debian = image("debian");
    std::fs::create_dir_all(debian.join("lib64")).unwrap();
    std::fs::create_dir_all(debian.join("lib/x86_64-linux-gnu")).unwrap();
    std::fs::write(debian.join("lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"), "").unwrap();
    std::os::unix::fs::symlink(
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        debian.join("lib64/ld-linux-x86-64.so.2"),
    )
    .unwrap();
    check_supplied(&debian, "oci:x/y:1").expect("a loader that is an absolute link in the image");
}
