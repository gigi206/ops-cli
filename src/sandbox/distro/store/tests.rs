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
        locked_digest(&lock, "oci:docker.io/library/debian:10").as_deref(),
        Some(digest)
    );
    // A lock left by another image is not this one's pin, however recent it is.
    assert_eq!(
        locked_digest(&lock, "oci:docker.io/library/debian:11"),
        None
    );
    // And no lock at all is not a pin either.
    assert_eq!(locked_digest(&tmp.join("absent.lock"), "oci:x/y:z"), None);
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
            locked_digest(&lock, locator),
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

    let rootfs = match provision(&layout, locator, &lock) {
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
    let (source, digest) = crate::store::read_lock_lines(&lock).expect("a lock was written");
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
    let again = provision(&layout, locator, &lock).expect("the second call reuses the tree");
    assert_eq!(again, rootfs);
}
