use super::*;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

/// Build a tar in memory from `(path, kind, payload)` triples, so a test states the archive it
/// means rather than shipping a fixture nobody can read.
enum Member<'a> {
    File(&'a str),
    Dir,
    Symlink(&'a str),
    /// A member written with an explicit entry type, for the shapes an archiver picks and this
    /// unpacker has to recognise as files.
    Typed(tar::EntryType, &'a str),
}

fn tar_of(members: &[(&str, Member<'_>)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, member) in members {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        match member {
            Member::File(body) => {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(body.len() as u64);
                header.set_cksum();
                builder
                    .append_data(&mut header, path, body.as_bytes())
                    .unwrap();
            }
            Member::Dir => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_cksum();
                builder.append_data(&mut header, path, &[][..]).unwrap();
            }
            Member::Typed(kind, body) => {
                header.set_entry_type(*kind);
                header.set_size(body.len() as u64);
                header.set_cksum();
                builder
                    .append_data(&mut header, path, body.as_bytes())
                    .unwrap();
            }
            Member::Symlink(target) => {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                header.set_link_name(target).unwrap();
                header.set_cksum();
                builder.append_data(&mut header, path, &[][..]).unwrap();
            }
        }
    }
    builder.into_inner().unwrap()
}

/// Write `bytes` to a file under `dir` and apply it as an uncompressed layer.
fn apply_tar(dir: &Path, root: &Path, bytes: &[u8]) -> io::Result<()> {
    let blob = dir.join(format!("layer-{}", root.display().to_string().len()));
    let mut f = fs::File::create(&blob)?;
    f.write_all(bytes)?;
    drop(f);
    apply(
        &blob,
        "application/vnd.oci.image.layer.v1.tar",
        root,
        &mut Budget::new(),
    )
}

/// The same, with a budget the caller supplies, so a test can stand near a ceiling instead of
/// building the terabyte that would reach one.
fn apply_tar_within(dir: &Path, root: &Path, bytes: &[u8], budget: &mut Budget) -> io::Result<()> {
    let blob = dir.join("bounded-layer");
    let mut f = fs::File::create(&blob)?;
    f.write_all(bytes)?;
    drop(f);
    apply(
        &blob,
        "application/vnd.oci.image.layer.v1.tar",
        root,
        budget,
    )
}

/// The fetch was bounded and `safe_path` bounded where a member lands, but nothing bounded how
/// much arrived. gzip expands, so a blob inside the 8 GiB fetch ceiling inflates to orders of
/// magnitude more, and a layer of a million empty files exhausts inodes without approaching either
/// ceiling. Both ends of an image's unpack now have one, spanning the image rather than the layer.
#[test]
fn an_image_that_unpacks_past_its_ceilings_is_refused_rather_than_filling_the_disk() {
    let tmp = crate::testutil::TmpDir::new();
    let archive = tar_of(&[("big", Member::File("0123456789"))]);

    // Ten bytes to write and nine left: the refusal names the member it stopped on, and the file
    // on disk holds only what the ceiling allowed, never the whole member.
    let mut budget = Budget {
        bytes: MAX_UNPACKED_BYTES - 9,
        members: 0,
    };
    let root = tmp.join("over-bytes");
    let err = apply_tar_within(tmp.path(), &root, &archive, &mut budget)
        .expect_err("past the byte ceiling");
    assert!(err.to_string().contains("unpack to more than"), "{err}");
    assert!(
        std::fs::metadata(root.join("big"))
            .map(|m| m.len())
            .unwrap()
            <= 10,
        "the member is bounded as it is copied, not measured after it lands"
    );

    // The member ceiling answers the shape that never approaches the byte one.
    let mut budget = Budget {
        bytes: 0,
        members: MAX_MEMBERS,
    };
    let err = apply_tar_within(tmp.path(), &tmp.join("over-members"), &archive, &mut budget)
        .expect_err("past the member ceiling");
    assert!(err.to_string().contains("more than"), "{err}");

    // Witness: the same archive with a fresh budget applies, so neither ceiling is in the way of
    // an image. And the budget is spent, which is what makes it span an image's layers.
    let mut budget = Budget::new();
    let root = tmp.join("ok");
    apply_tar_within(tmp.path(), &root, &archive, &mut budget).unwrap();
    assert_eq!(
        std::fs::read_to_string(root.join("big")).unwrap(),
        "0123456789"
    );
    assert_eq!((budget.bytes, budget.members), (10, 1));
}

#[test]
fn a_layer_lands_with_its_files_directories_and_links() {
    let tmp = crate::testutil::TmpDir::new();
    let root = tmp.join("root");
    apply_tar(
        tmp.path(),
        &root,
        &tar_of(&[
            ("usr/", Member::Dir),
            ("usr/bin/", Member::Dir),
            ("usr/bin/tool", Member::File("#!/bin/sh\n")),
            ("bin", Member::Symlink("usr/bin")),
        ]),
    )
    .expect("the layer applies");
    assert_eq!(
        fs::read_to_string(root.join("usr/bin/tool")).unwrap(),
        "#!/bin/sh\n"
    );
    assert_eq!(
        fs::read_link(root.join("bin")).unwrap(),
        Path::new("usr/bin")
    );
}

/// A tar carrying one member whose name is written into the header verbatim.
///
/// `tar::Builder` refuses to *write* an absolute or climbing path, which is exactly why this
/// exists: a hostile archive is not built by a well-behaved writer, and a test that could only
/// produce well-behaved archives would never reach the check it means to exercise.
fn tar_with_raw_name(name: &str, body: &str) -> Vec<u8> {
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(body.len() as u64);
    let field = &mut header.as_gnu_mut().expect("a gnu header").name;
    field[..name.len()].copy_from_slice(name.as_bytes());
    header.set_cksum();
    let mut builder = tar::Builder::new(Vec::new());
    builder.append(&header, body.as_bytes()).unwrap();
    builder.into_inner().unwrap()
}

#[test]
fn an_absolute_or_climbing_member_is_refused_not_sanitised() {
    let tmp = crate::testutil::TmpDir::new();
    let root = tmp.join("root");
    for (i, path) in ["/etc/passwd", "../escaped", "usr/../../escaped"]
        .iter()
        .enumerate()
    {
        let blob = tmp.join(&format!("hostile-{i}"));
        fs::write(&blob, tar_with_raw_name(path, "x")).unwrap();
        let err = apply(
            &blob,
            "application/vnd.oci.image.layer.v1.tar",
            &root,
            &mut Budget::new(),
        )
        .expect_err("a member that leaves the root is refused");
        assert!(err.to_string().contains("leaves the image root"), "{err}");
    }
    assert!(
        !tmp.path().join("escaped").exists() && !tmp.path().join("etc").exists(),
        "nothing was written outside the root"
    );
}

#[test]
fn a_member_is_never_written_through_a_symlink_an_earlier_layer_planted() {
    // The escape a naive check misses: layer one ships `etc -> <somewhere else>`, layer two ships
    // `etc/passwd`. Resolving the second path through the first writes outside the tree.
    let tmp = crate::testutil::TmpDir::new();
    let root = tmp.join("root");
    let outside = tmp.join("outside");
    fs::create_dir_all(&outside).unwrap();

    apply_tar(
        tmp.path(),
        &root,
        &tar_of(&[("etc", Member::Symlink(outside.to_str().unwrap()))]),
    )
    .expect("a symlink is data, so the first layer applies");

    let second = tar_of(&[("etc/passwd", Member::File("root:x:0:0:"))]);
    let blob = tmp.join("second");
    fs::write(&blob, &second).unwrap();
    let err = apply(
        &blob,
        "application/vnd.oci.image.layer.v1.tar",
        &root,
        &mut Budget::new(),
    )
    .expect_err("writing through the planted link is refused");
    assert!(err.to_string().contains("through the symlink"), "{err}");
    assert!(
        !outside.join("passwd").exists(),
        "nothing was written outside the root"
    );
}

#[test]
fn a_whiteout_removes_what_a_lower_layer_put_there() {
    let tmp = crate::testutil::TmpDir::new();
    let root = tmp.join("root");
    apply_tar(
        tmp.path(),
        &root,
        &tar_of(&[
            ("var/", Member::Dir),
            ("var/keep", Member::File("kept")),
            ("var/gone", Member::File("gone")),
        ]),
    )
    .unwrap();

    let blob = tmp.join("whiteout");
    fs::write(&blob, tar_of(&[("var/.wh.gone", Member::File(""))])).unwrap();
    apply(
        &blob,
        "application/vnd.oci.image.layer.v1.tar",
        &root,
        &mut Budget::new(),
    )
    .unwrap();

    assert!(root.join("var/keep").exists(), "the sibling stays");
    assert!(!root.join("var/gone").exists(), "the marked entry is gone");
    assert!(
        !root.join("var/.wh.gone").exists(),
        "the marker itself is never written out"
    );
}

#[test]
fn an_opaque_marker_empties_the_directory_it_sits_in() {
    let tmp = crate::testutil::TmpDir::new();
    let root = tmp.join("root");
    apply_tar(
        tmp.path(),
        &root,
        &tar_of(&[
            ("opt/", Member::Dir),
            ("opt/a", Member::File("a")),
            ("opt/sub/", Member::Dir),
            ("opt/sub/b", Member::File("b")),
            ("keep", Member::File("keep")),
        ]),
    )
    .unwrap();

    let blob = tmp.join("opaque");
    fs::write(
        &blob,
        tar_of(&[
            ("opt/.wh..wh..opq", Member::File("")),
            ("opt/fresh", Member::File("fresh")),
        ]),
    )
    .unwrap();
    apply(
        &blob,
        "application/vnd.oci.image.layer.v1.tar",
        &root,
        &mut Budget::new(),
    )
    .unwrap();

    assert!(!root.join("opt/a").exists(), "the directory was emptied");
    assert!(!root.join("opt/sub").exists(), "including its subtrees");
    assert!(
        root.join("opt/fresh").exists(),
        "and refilled by this layer"
    );
    assert!(root.join("keep").exists(), "another directory is untouched");
}

#[test]
fn an_opaque_marker_never_empties_through_a_symlink_an_earlier_layer_planted() {
    // The escape the parent-chain check does not catch: the link is the marker's *own* directory,
    // whose final component `safe_path` exempts because a member may replace a link. An opaque
    // marker does not replace it, it reads the entries below, so following the link would empty
    // whatever it names outside the root.
    for target in ["an absolute target", "a relative target"] {
        let tmp = crate::testutil::TmpDir::new();
        let root = tmp.join("root");
        let outside = tmp.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep"), "keep").unwrap();
        let link = if target.starts_with("an absolute") {
            outside.to_str().unwrap().to_string()
        } else {
            "../outside".to_string()
        };

        apply_tar(
            tmp.path(),
            &root,
            &tar_of(&[("opt", Member::Symlink(&link))]),
        )
        .expect("a symlink is data, so the first layer applies");

        let blob = tmp.join("opaque");
        fs::write(&blob, tar_of(&[("opt/.wh..wh..opq", Member::File(""))])).unwrap();
        let err = apply(
            &blob,
            "application/vnd.oci.image.layer.v1.tar",
            &root,
            &mut Budget::new(),
        )
        .expect_err("emptying through the planted link is refused");
        assert!(err.to_string().contains("is a symlink"), "{err}");
        assert!(
            outside.join("keep").exists(),
            "nothing outside the root was emptied, with {target}"
        );
        assert!(
            root.join("opt").symlink_metadata().unwrap().is_symlink(),
            "and the link itself is left as the data it is, with {target}"
        );
    }
}

#[test]
fn a_layer_media_type_with_no_decoder_is_refused_by_name() {
    let tmp = crate::testutil::TmpDir::new();
    let blob = tmp.join("zstd");
    fs::write(&blob, b"not really zstd").unwrap();
    let err = apply(
        &blob,
        "application/vnd.oci.image.layer.v1.tar+zstd",
        &tmp.join("root"),
        &mut Budget::new(),
    )
    .expect_err("an unsupported framing is refused");
    assert!(err.to_string().contains("+zstd"), "{err}");
}

#[test]
fn a_real_image_unpacks_into_a_usable_root_filesystem() {
    // The end of the chain, against a real registry: resolve, fetch, apply. A synthetic archive
    // proves the rules; only a published image proves the framing, the ordering and the media
    // types agree with what a registry actually serves.
    use crate::sandbox::distro::reference;
    let image = reference::parse("oci:docker.io/library/alpine:3.22").unwrap();
    let Ok(resolved) = crate::sandbox::distro::registry::resolve(&image, None) else {
        skip_unreachable!("skipping the image unpack: the registry did not answer");
        return;
    };
    let tmp = crate::testutil::TmpDir::new();
    let root = tmp.join("rootfs");
    for layer in &resolved.layers {
        let Ok(blob) =
            crate::sandbox::distro::registry::fetch_layer(&image, layer, tmp.path(), None)
        else {
            skip_unreachable!("skipping the image unpack: a layer did not arrive");
            return;
        };
        apply(&blob, &layer.media_type, &root, &mut Budget::new()).expect("the layer applies");
    }
    let release = fs::read_to_string(root.join("etc/os-release")).expect("os-release landed");
    assert!(release.contains("ID=alpine"), "{release}");
    assert!(root.join("bin/busybox").exists(), "the shell landed");
    assert!(
        root.join("etc/apk/repositories").exists(),
        "the package manager's own configuration landed"
    );
    // The image ships `/bin/sh` as a link to busybox: a link is written as a link, not resolved.
    let sh = root.join("bin/sh");
    assert!(
        sh.symlink_metadata().unwrap().file_type().is_symlink(),
        "a symlink member stays a symlink"
    );
}

#[test]
fn a_directory_member_never_chmods_through_a_link_an_earlier_layer_planted() {
    // The variant the parent-chain check does not catch: the link is the member's *final*
    // component, which is exempt so a layer can replace a link. A directory member then reaches
    // `set_permissions`, and a test for "is this already a directory" that follows links answers
    // yes about the host directory the link names.
    let tmp = crate::testutil::TmpDir::new();
    let root = tmp.join("root");
    let outside = tmp.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();

    apply_tar(
        tmp.path(),
        &root,
        &tar_of(&[("etc", Member::Symlink(outside.to_str().unwrap()))]),
    )
    .expect("a symlink is data, so the first layer applies");
    apply_tar(tmp.path(), &root, &tar_of(&[("etc", Member::Dir)]))
        .expect("the second layer replaces it");

    assert_eq!(
        fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
        0o700,
        "the directory outside the image root kept the mode it had"
    );
    assert!(
        !root.join("etc").symlink_metadata().unwrap().is_symlink(),
        "the link was unlinked and a real directory put in its place"
    );
    assert!(fs::read_dir(root.join("etc")).is_ok());
}

#[test]
fn a_member_spelled_with_a_current_directory_component_lands_where_it_names() {
    // `./bin` and `bin` name the same destination, so the exemption that lets a layer replace a
    // link has to recognise the first as a final component too.
    let tmp = crate::testutil::TmpDir::new();
    let root = tmp.join("root");
    apply_tar(
        tmp.path(),
        &root,
        &tar_of(&[("bin", Member::Symlink("usr/bin"))]),
    )
    .unwrap();
    apply_tar(
        tmp.path(),
        &root,
        &tar_of(&[("./bin", Member::File("replaced"))]),
    )
    .expect("a final component spelled with `./` is still a final component");
    assert_eq!(fs::read_to_string(root.join("bin")).unwrap(), "replaced");
}

#[test]
fn the_archives_own_root_member_is_a_no_op_not_a_refusal() {
    // `./` as the first member is what a good many images ship, `debian:12-slim` among them. It
    // names the directory the unpack is already writing into, and refusing it cost that image its
    // whole unpack on an entry every other reader treats as nothing.
    let tmp = crate::testutil::TmpDir::new();
    let root = tmp.join("root");
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_mode(0o755);
    header.set_size(0);
    header.set_cksum();
    builder.append_data(&mut header, "./", &[][..]).unwrap();
    // One archive, not two concatenated: `into_inner` writes the end-of-archive blocks, and a
    // reader stops there rather than continuing into whatever follows.
    let body = b"ID=debian\n";
    let mut file = tar::Header::new_gnu();
    file.set_entry_type(tar::EntryType::Regular);
    file.set_mode(0o644);
    file.set_size(body.len() as u64);
    file.set_cksum();
    builder
        .append_data(&mut file, "etc/os-release", &body[..])
        .unwrap();
    let blob = builder.into_inner().unwrap();

    apply_tar(tmp.path(), &root, &blob).expect("the root member is skipped and the rest lands");
    assert_eq!(
        fs::read_to_string(root.join("etc/os-release")).unwrap(),
        "ID=debian\n"
    );
}

#[test]
fn a_member_with_no_final_component_that_climbs_is_still_refused() {
    // The skip above is for `.` and `./` alone. A member that has no final component *and* leaves
    // the tree keeps the refusal, and `safe_path` is what names which.
    let tmp = crate::testutil::TmpDir::new();
    let root = tmp.join("root");
    for name in ["/", "../"] {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_mode(0o755);
        header.set_size(0);
        header.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name.as_bytes());
        header.set_cksum();
        builder.append(&header, &[][..]).unwrap();
        let blob = builder.into_inner().unwrap();
        let err = apply_tar(tmp.path(), &root, &blob)
            .expect_err(&format!("`{name}` must not be treated as the archive root"));
        assert!(
            err.to_string().contains("leaves the image root"),
            "`{name}`: {err}"
        );
    }
}

/// A member an archiver spelled as contiguous or sparse is written, not dropped.
///
/// `is_file()` answers for the `0`/`\0` types only. A `7` is a regular file on every filesystem
/// this runs on, and a GNU sparse entry is read back with its holes filled by the tar reader, so
/// both fell into the branch for device nodes and were skipped without a word: an image built by
/// GNU tar with `--sparse` lost the file it declares. The witness is the same member as a plain
/// regular file, in the same loop.
#[test]
fn a_contiguous_or_sparse_member_lands_like_the_regular_file_it_is() {
    // A GNU sparse entry is covered by the predicate for the same reason and is not exercised
    // here: a well-formed one carries header fields (`real_size`, the extent map) this fixture
    // does not write, and the tar reader refuses the malformed header before the unpacker sees
    // the member at all.
    for kind in [tar::EntryType::Continuous, tar::EntryType::Regular] {
        let tmp = crate::testutil::TmpDir::new();
        let root = tmp.join("root");
        apply_tar(
            tmp.path(),
            &root,
            &tar_of(&[
                ("etc/", Member::Dir),
                ("etc/data", Member::Typed(kind, "x")),
            ]),
        )
        .unwrap_or_else(|e| panic!("{kind:?} applies: {e}"));
        assert!(
            root.join("etc/data").is_file(),
            "{kind:?}: the member the image declares must land"
        );
    }
}

/// A member of a type this cannot write is refused rather than dropped.
///
/// The fallback used to return `Ok(())` for everything that was not a file, a directory, a link or
/// a hard link, which is how the two above went missing. Device nodes, fifos and sockets keep the
/// skip: the cage mounts its own `/dev`, and unprivileged creation would fail anyway.
#[test]
fn a_member_of_an_unwritable_type_is_named_rather_than_skipped() {
    let tmp = crate::testutil::TmpDir::new();
    let root = tmp.join("root");
    let err = apply_tar(
        tmp.path(),
        &root,
        &tar_of(&[("weird", Member::Typed(tar::EntryType::new(b'Z'), ""))]),
    )
    .expect_err("an unknown member type is refused");
    assert!(err.to_string().contains("does not write"), "{err}");

    // The witness: a device node is still skipped, and the layer applies.
    let tmp = crate::testutil::TmpDir::new();
    let root = tmp.join("root");
    apply_tar(
        tmp.path(),
        &root,
        &tar_of(&[
            ("dev/null", Member::Typed(tar::EntryType::Char, "")),
            ("etc/keep", Member::File("k")),
        ]),
    )
    .expect("a device node is skipped, not refused");
    assert!(root.join("etc/keep").is_file());
    assert!(!root.join("dev/null").exists());
}

/// An opaque marker at the layer's own root empties the root, as every other applier does.
///
/// `safe_path` refuses a member that names the root itself, which is right for a member being
/// written and wrong for one that names a directory to empty. A squashed layer carrying
/// `.wh..wh..opq` at its root had the whole image refused.
#[test]
fn an_opaque_marker_at_the_layer_root_empties_the_root() {
    let tmp = crate::testutil::TmpDir::new();
    let root = tmp.join("root");
    apply_tar(
        tmp.path(),
        &root,
        &tar_of(&[("etc/", Member::Dir), ("etc/old", Member::File("old"))]),
    )
    .unwrap();

    let blob = tmp.join("opaque-root");
    fs::write(
        &blob,
        tar_of(&[
            (".wh..wh..opq", Member::File("")),
            ("etc/", Member::Dir),
            ("etc/new", Member::File("new")),
        ]),
    )
    .unwrap();
    apply(
        &blob,
        "application/vnd.oci.image.layer.v1.tar",
        &root,
        &mut Budget::new(),
    )
    .expect("a root-level opaque marker applies");

    assert!(!root.join("etc/old").exists(), "the root was emptied");
    assert!(root.join("etc/new").is_file(), "and refilled by this layer");
}
