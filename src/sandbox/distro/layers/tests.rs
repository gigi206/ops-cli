use super::*;
use proptest::collection::vec;
use proptest::prelude::{Just, Strategy, any, prop_oneof};
use proptest::sample::{Index, select};
use std::collections::BTreeMap;
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
    let body = "x".repeat(100);
    let archive = tar_of(&[("big", Member::File(&body))]);

    // A hundred bytes to write and nine left: the refusal names the member it stopped on, and the
    // file on disk holds the nine the ceiling allowed plus the one that proves it was exceeded,
    // never the hundred. Measuring after the copy would leave the whole member on disk.
    let mut budget = Budget {
        bytes: MAX_UNPACKED_BYTES - 9,
        members: 0,
    };
    let root = tmp.join("over-bytes");
    let err = apply_tar_within(tmp.path(), &root, &archive, &mut budget)
        .expect_err("past the byte ceiling");
    assert!(err.to_string().contains("unpack to more than"), "{err}");
    assert_eq!(
        std::fs::metadata(root.join("big"))
            .map(|m| m.len())
            .unwrap(),
        10,
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
    assert_eq!(std::fs::read_to_string(root.join("big")).unwrap(), body);
    assert_eq!((budget.bytes, budget.members), (100, 1));
}

/// A directory the unpack makes on the way to a member is an entry of the budget, not free.
///
/// `create_dir_all` made every missing parent for the price of the one member that named them, so
/// a member whose path is a few kilobytes long created close to two thousand directories while the
/// budget counted one. Here the three parents of `a/b/c/f` cost three entries: with four left the
/// member applies, with three it is refused at its last parent, before that parent is made.
#[test]
fn a_directory_made_for_a_members_path_counts_against_the_member_ceiling() {
    let tmp = crate::testutil::TmpDir::new();
    let archive = tar_of(&[("a/b/c/f", Member::File("x"))]);

    let mut budget = Budget {
        bytes: 0,
        members: MAX_MEMBERS - 4,
    };
    let root = tmp.join("fits");
    apply_tar_within(tmp.path(), &root, &archive, &mut budget).expect("four entries left");
    assert_eq!(budget.members, MAX_MEMBERS);
    assert!(root.join("a/b/c/f").is_file());

    let mut budget = Budget {
        bytes: 0,
        members: MAX_MEMBERS - 3,
    };
    let root = tmp.join("over");
    let err =
        apply_tar_within(tmp.path(), &root, &archive, &mut budget).expect_err("one entry short");
    assert!(
        err.to_string().contains("directories made to hold them"),
        "{err}"
    );
    assert!(
        root.join("a/b").is_dir() && !root.join("a/b/c").exists(),
        "refused before the parent past the ceiling was made"
    );

    // Witness: a parent the layer declares is its own member, and is not counted a second time.
    let mut budget = Budget::new();
    let declared = tar_of(&[("a/", Member::Dir), ("a/f", Member::File("x"))]);
    apply_tar_within(tmp.path(), &tmp.join("declared"), &declared, &mut budget).unwrap();
    assert_eq!(budget.members, 2);
}

/// A tar of `count` members, each described by a PAX record of `len` bytes: to reach a member, the
/// tar reader reads the record's header block, the record padded to a block, and the member's own
/// header block. Each member carries one block of data, so none leaves padding for the next.
fn tar_with_pax_records_of(len: usize, count: usize) -> Vec<u8> {
    // One record, `<len> comment=<value>\n`, whose leading length counts its own digits.
    let value = "c".repeat(len - len.to_string().len() - " comment=\n".len());
    let record = format!("{len} comment={value}\n");
    assert_eq!(record.len(), len);
    let mut builder = tar::Builder::new(Vec::new());
    for i in 0..count {
        let mut pax = tar::Header::new_ustar();
        pax.set_entry_type(tar::EntryType::XHeader);
        pax.set_path(format!("PaxHeader/f{i}")).unwrap();
        pax.set_size(len as u64);
        pax.set_mode(0o644);
        pax.set_cksum();
        builder.append(&pax, record.as_bytes()).unwrap();
        let mut file = tar::Header::new_ustar();
        file.set_entry_type(tar::EntryType::Regular);
        file.set_mode(0o644);
        file.set_size(512);
        builder
            .append_data(&mut file, format!("f{i}"), &[b'x'; 512][..])
            .unwrap();
    }
    builder.into_inner().unwrap()
}

/// What the tar reader reads to reach a member is bounded, so a long name is refused before it is
/// held in memory.
///
/// The `tar` crate reads a long name, a long link or a PAX record whole, at the size its header
/// declares, before the member it describes reaches the budget, so a small gzip layer could make
/// this process hold a name of any size. Records that bring what precedes each of two members to
/// exactly [`MAX_HEADER_BYTES`] still apply, the bound being per member, and one block more is
/// refused. So is a long name past the bound, which used to fail too, but later, on its length as a
/// path, once held. A long name of honest length applies, and so does a member whose own data is
/// past the bound, which is the budget's to count.
#[test]
fn a_long_name_or_pax_record_past_the_header_bound_is_refused_before_it_is_held() {
    let tmp = crate::testutil::TmpDir::new();
    let block = 512;
    let bound = MAX_HEADER_BYTES as usize;

    let root = tmp.join("at-the-bound");
    apply_tar(
        tmp.path(),
        &root,
        &tar_with_pax_records_of(bound - 2 * block, 2),
    )
    .expect("records that bring each member to the bound apply");
    assert!(root.join("f0").is_file() && root.join("f1").is_file());

    let long = "n".repeat(bound);
    for (what, archive) in [
        (
            "a PAX record",
            tar_with_pax_records_of(bound - 2 * block + 1, 1),
        ),
        ("a long name", tar_of(&[(&long, Member::File("x"))])),
    ] {
        let err = apply_tar(tmp.path(), &tmp.join("past-the-bound"), &archive).expect_err(what);
        assert!(
            err.to_string().contains("member headers run past"),
            "{what}: {err}"
        );
    }

    // Witness: a long name of honest length, twelve components of 250 bytes, lands, and so does a
    // member twice the bound in size.
    let honest = vec!["h".repeat(250); 12].join("/");
    let big = "d".repeat(2 * bound);
    let root = tmp.join("honest");
    apply_tar(
        tmp.path(),
        &root,
        &tar_of(&[(&honest, Member::File("x")), ("big", Member::File(&big))]),
    )
    .expect("an honest long name and a large member apply");
    assert!(root.join(&honest).is_file());
    assert_eq!(
        fs::metadata(root.join("big")).unwrap().len(),
        big.len() as u64
    );
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

/// Where a generated link points. The relative spellings may climb; `Outside` and `OutsideFile`
/// are absolute, the fixture's `outside` directory and a file in it, known once it exists.
#[derive(Clone, Debug)]
enum Aim {
    Relative(&'static str),
    Outside,
    OutsideFile,
}

/// What a generated member is. `Other` is a type flag the unpacker skips or refuses: a character
/// or block device, a fifo, a type no tar defines.
#[derive(Clone, Debug)]
enum Kind {
    Dir,
    File(Vec<u8>),
    Symlink(Aim),
    HardLink(Aim),
    Other(u8),
}

/// A generated member: its name as the archive spells it, what it is, and its mode.
#[derive(Clone, Debug)]
struct Generated {
    name: String,
    kind: Kind,
    mode: u32,
}

/// A name built from a few components, so that one layer's link and a later layer's path through
/// it meet often: two plain names, and the spellings that try to leave or that mark a deletion.
fn names() -> impl Strategy<Value = String> {
    let component = prop_oneof![
        6 => select(&["a", "b"][..]),
        1 => select(&[".", "..", ".wh.a", ".wh.b", ".wh..wh..opq", ".wh.", ".wh..."][..]),
    ];
    (
        prop_oneof![4 => Just(""), 1 => Just("./"), 1 => Just("/")],
        vec(component, 1..4),
        any::<bool>(),
    )
        .prop_map(|(lead, parts, slash)| {
            format!("{lead}{}{}", parts.join("/"), if slash { "/" } else { "" })
        })
}

fn aims() -> impl Strategy<Value = Aim> {
    prop_oneof![
        3 => select(&["a", "b", "a/b", ".", "..", "../..", "../outside", "../outside/a"][..])
            .prop_map(Aim::Relative),
        1 => Just(Aim::Outside),
        1 => Just(Aim::OutsideFile),
    ]
}

fn kinds() -> impl Strategy<Value = Kind> {
    prop_oneof![
        3 => Just(Kind::Dir),
        3 => vec(any::<u8>(), 0..32).prop_map(Kind::File),
        3 => aims().prop_map(Kind::Symlink),
        1 => aims().prop_map(Kind::HardLink),
        1 => select(&b"346Z"[..]).prop_map(Kind::Other),
    ]
}

fn modes() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(0o4755u32),
        Just(0o2755),
        Just(0o1777),
        Just(0),
        (0u32..0o10000),
    ]
}

fn generated() -> impl Strategy<Value = Generated> {
    (names(), kinds(), modes()).prop_map(|(name, kind, mode)| Generated { name, kind, mode })
}

/// An image's layers, each with whether it is framed by gzip: generated members in any order, or
/// starting with a pair of layers that meet, one planting a link at `a` or `b` and the next naming
/// paths at it and through it. Drawn at random, such a pair is rare, and it is the shape every
/// escape through a link needs.
fn images() -> impl Strategy<Value = Vec<(Vec<Generated>, bool)>> {
    let layers = |count| vec((vec(generated(), 1..8), any::<bool>()), count);
    let tails = select(&["", "/a", "/b", "/b/a", "/.wh.a", "/.wh.b", "/.wh..wh..opq"][..]);
    let pair = (
        select(&["a", "b"][..]),
        aims(),
        vec((tails, kinds(), modes()), 1..5),
        any::<bool>(),
    )
        .prop_map(|(link, aim, uses, gzip)| {
            let plant = Generated {
                name: link.to_string(),
                kind: Kind::Symlink(aim),
                mode: 0o777,
            };
            let uses = uses
                .into_iter()
                .map(|(tail, kind, mode)| Generated {
                    name: format!("{link}{tail}"),
                    kind,
                    mode,
                })
                .collect();
            vec![(vec![plant], gzip), (uses, !gzip)]
        });
    prop_oneof![
        layers(1..4),
        (pair, layers(0..3)).prop_map(|(mut pair, rest)| {
            pair.extend(rest);
            pair
        }),
    ]
    .boxed()
}

/// Where a layer is applied, and what lies around it for a member to reach.
///
/// The root is three levels below the fixture, so that a member climbing as far as a generated
/// name can climb stays inside it where the snapshot sees it. `outside` sits beside the root, where
/// a link spelled `../outside` from the root's top lands. It holds a file `a` and a directory `b`
/// with a file `a` in it, named as the members are so that a path through a link meets them, at
/// modes a chmod through a link would change.
struct Ground {
    tmp: crate::testutil::TmpDir,
    root: PathBuf,
    outside: PathBuf,
}

impl Ground {
    fn new() -> Self {
        let tmp = crate::testutil::TmpDir::new();
        let root = tmp.join("x/y/root");
        let outside = tmp.join("x/y/outside");
        fs::create_dir_all(outside.join("b")).unwrap();
        fs::write(outside.join("a"), "a").unwrap();
        fs::write(outside.join("b/a"), "b/a").unwrap();
        fs::write(tmp.join("sibling"), "sibling").unwrap();
        fs::set_permissions(outside.join("a"), fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(outside.join("b"), fs::Permissions::from_mode(0o750)).unwrap();
        fs::create_dir_all(tmp.join("blobs")).unwrap();
        Ground { tmp, root, outside }
    }

    fn aim(&self, aim: &Aim) -> String {
        match aim {
            Aim::Relative(path) => path.to_string(),
            Aim::Outside => self.outside.display().to_string(),
            Aim::OutsideFile => self.outside.join("a").display().to_string(),
        }
    }

    /// Everything around the root, which no layer may change: the root and the blobs aside.
    fn around(&self) -> BTreeMap<PathBuf, (&'static str, u32, Vec<u8>)> {
        snapshot(
            self.tmp.path(),
            &[self.root.clone(), self.tmp.join("blobs")],
        )
    }

    /// The files under the root that are also a file around it: a hard link out of the tree,
    /// which changes nothing the snapshot of the ground reads and hands the cage a file it was
    /// never given.
    fn linked_out(&self) -> Vec<PathBuf> {
        let files = |paths: Vec<PathBuf>| -> BTreeMap<(u64, u64), PathBuf> {
            use std::os::unix::fs::MetadataExt;
            paths
                .into_iter()
                .filter_map(|path| {
                    let meta = path.symlink_metadata().ok()?;
                    meta.is_file().then(|| ((meta.dev(), meta.ino()), path))
                })
                .collect()
        };
        let around = files(self.around().into_keys().collect());
        files(snapshot(&self.root, &[]).into_keys().collect())
            .into_iter()
            .filter(|(inode, _)| around.contains_key(inode))
            .map(|(_, path)| path)
            .collect()
    }

    /// Apply `layer` as the `n`th blob, framed by gzip when `gzip` says so.
    fn apply(&self, n: usize, layer: &[u8], gzip: bool, budget: &mut Budget) -> io::Result<()> {
        let blob = self.tmp.join(&format!("blobs/{n}"));
        let media_type = if gzip {
            fs::write(&blob, gzip_member(layer)).unwrap();
            "application/vnd.oci.image.layer.v1.tar+gzip"
        } else {
            fs::write(&blob, layer).unwrap();
            "application/vnd.oci.image.layer.v1.tar"
        };
        apply(&blob, media_type, &self.root, budget)
    }
}

/// Every entry under `dir` but the trees at `skip`, by path: its kind, its mode, and its contents
/// or its link's target. A link is read, never followed.
fn snapshot(dir: &Path, skip: &[PathBuf]) -> BTreeMap<PathBuf, (&'static str, u32, Vec<u8>)> {
    use std::os::unix::ffi::OsStrExt;
    let mut seen = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(at) = pending.pop() {
        let Ok(entries) = fs::read_dir(&at) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if skip.contains(&path) {
                continue;
            }
            let Ok(meta) = path.symlink_metadata() else {
                continue;
            };
            let mode = meta.permissions().mode();
            let what = if meta.file_type().is_symlink() {
                let target = fs::read_link(&path).unwrap_or_default();
                ("link", mode, target.as_os_str().as_bytes().to_vec())
            } else if meta.is_dir() {
                pending.push(path.clone());
                ("dir", mode, Vec::new())
            } else if meta.is_file() {
                ("file", mode, fs::read(&path).unwrap_or_default())
            } else {
                ("other", mode, Vec::new())
            };
            seen.insert(path, what);
        }
    }
    seen
}

/// Every entry under the root that carries a set-user-ID, set-group-ID or sticky bit, or that its
/// owner cannot read and write (search, too, on a directory).
fn privileged_or_locked(root: &Path) -> Vec<(PathBuf, u32)> {
    snapshot(root, &[])
        .into_iter()
        .filter(|(_, (kind, mode, _))| {
            let owner = if *kind == "dir" { 0o700 } else { 0o600 };
            *kind != "link" && (mode & 0o7000 != 0 || mode & owner != owner)
        })
        .map(|(path, (_, mode, _))| (path, mode & 0o7777))
        .collect()
}

/// `bytes` as one gzip member, the trailer left as zeros: the unpacker does not check it.
fn gzip_member(bytes: &[u8]) -> Vec<u8> {
    let mut member = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    member.extend(miniz_oxide::deflate::compress_to_vec(bytes, 1));
    member.extend([0u8; 8]);
    member
}

/// A tar of `members`, each name and link name written into its header field as generated, since
/// the hostile spellings are the ones a well-behaved writer refuses to write. Also where each
/// header starts.
fn raw_tar(members: &[Generated], ground: &Ground) -> (Vec<u8>, Vec<usize>) {
    let mut out = Vec::new();
    let mut headers = Vec::new();
    for member in members {
        let mut header = tar::Header::new_gnu();
        let (kind, link, data) = match &member.kind {
            Kind::Dir => (tar::EntryType::Directory, None, &[][..]),
            Kind::File(data) => (tar::EntryType::Regular, None, &data[..]),
            Kind::Symlink(aim) => (tar::EntryType::Symlink, Some(ground.aim(aim)), &[][..]),
            Kind::HardLink(aim) => (tar::EntryType::Link, Some(ground.aim(aim)), &[][..]),
            Kind::Other(flag) => (tar::EntryType::new(*flag), None, &[][..]),
        };
        header.set_entry_type(kind);
        header.set_mode(member.mode);
        header.set_size(data.len() as u64);
        let gnu = header.as_gnu_mut().expect("a gnu header");
        assert!(member.name.len() <= gnu.name.len(), "{}", member.name);
        gnu.name[..member.name.len()].copy_from_slice(member.name.as_bytes());
        if let Some(link) = link {
            assert!(
                link.len() <= gnu.linkname.len(),
                "the fixture's path is too long: {link}"
            );
            gnu.linkname[..link.len()].copy_from_slice(link.as_bytes());
        }
        header.set_cksum();
        headers.push(out.len());
        out.extend(header.as_bytes());
        out.extend(data);
        out.resize(out.len().next_multiple_of(512), 0);
    }
    out.extend([0u8; 1024]);
    (out, headers)
}

/// `layer`, each of `mutations` made to it in turn: a header field overwritten and the header's
/// checksum made right again, so the change reaches the unpacker rather than stopping at the tar
/// reader's check; a byte replaced; the layer cut; or a block inserted.
fn mutated(
    mut layer: Vec<u8>,
    headers: &[usize],
    mutations: &[(u8, Index, Index, u64)],
) -> Vec<u8> {
    // Name, mode, size, type flag and link name: where they start and how long they are.
    const FIELDS: [(usize, usize); 5] = [(0, 100), (100, 8), (124, 12), (156, 1), (157, 100)];
    for &(how, which, at, value) in mutations {
        match how {
            0 | 1 if !headers.is_empty() => {
                let start = headers[which.index(headers.len())];
                if start + 512 > layer.len() {
                    continue;
                }
                let (offset, len) = FIELDS[at.index(FIELDS.len())];
                let bytes = if how == 0 {
                    // A number in the octal the fields hold, so a size or a mode stays readable.
                    format!(
                        "{:0width$o}\0",
                        value % (1 << 33),
                        width = len.saturating_sub(1)
                    )
                    .into_bytes()
                } else {
                    value.to_le_bytes().to_vec()
                };
                let n = bytes.len().min(len);
                layer[start + offset..start + offset + n].copy_from_slice(&bytes[..n]);
                let mut header = tar::Header::from_byte_slice(&layer[start..start + 512]).clone();
                header.set_cksum();
                layer[start..start + 512].copy_from_slice(header.as_bytes());
            }
            2 if !layer.is_empty() => {
                let at = at.index(layer.len());
                layer[at] = value as u8;
            }
            3 => layer.truncate(at.index(layer.len() + 1)),
            _ => {
                let at = at.index(layer.len() + 1);
                layer.splice(at..at, [value as u8; 512]);
            }
        }
    }
    layer
}

/// A member of an honest layer, named so that no two kinds ever share a name: directories `d<n>`,
/// files `f<n>`, links `l<n>`, and the deletion of a file or a directory.
#[derive(Clone, Debug)]
struct Honest {
    parents: Vec<u8>,
    leaf: u8,
    kind: u8,
    size: usize,
}

impl Honest {
    fn name(&self) -> String {
        let leaf = match self.kind {
            0 => format!("d{}/", self.leaf),
            1 => format!("f{}", self.leaf),
            2 => format!("l{}", self.leaf),
            3 => format!(".wh.f{}", self.leaf),
            _ => format!(".wh.d{}", self.leaf),
        };
        let parents: String = self.parents.iter().map(|d| format!("d{d}/")).collect();
        format!("{parents}{leaf}")
    }

    /// What the member costs the budget at most: itself, and each parent it may have to make.
    fn entries_at_most(&self) -> u64 {
        1 + self.parents.len() as u64
    }
}

fn honest() -> impl Strategy<Value = Honest> {
    (vec(0u8..3, 0..3), 0u8..4, 0u8..5, 0usize..400).prop_map(|(parents, leaf, kind, size)| {
        Honest {
            parents,
            leaf,
            kind,
            size: if kind == 1 { size } else { 0 },
        }
    })
}

/// What `layers` declare: the bytes of their files, and at most how many entries they cost.
fn declared(layers: &[Vec<Honest>]) -> (u64, u64) {
    let members = || layers.iter().flatten();
    (
        members().map(|m| m.size as u64).sum(),
        members().map(Honest::entries_at_most).sum(),
    )
}

/// Honest layers, and what is left of each ceiling for them: drawn at random, or exactly what they
/// declare, or one short of it, where a ceiling off by one shows.
fn budgets() -> impl Strategy<Value = (Vec<Vec<Honest>>, u64, u64)> {
    vec(vec(honest(), 1..8), 1..4).prop_flat_map(|layers| {
        let (bytes, entries) = declared(&layers);
        (
            Just(layers),
            prop_oneof![0u64..3000, Just(bytes), Just(bytes.saturating_sub(1))],
            prop_oneof![0u64..40, Just(entries), Just(entries.saturating_sub(1))],
        )
    })
}

fn honest_tar(members: &[Honest]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for member in members {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(member.size as u64);
        let name = member.name();
        match member.kind {
            0 => header.set_entry_type(tar::EntryType::Directory),
            2 => {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_link_name("f0").unwrap();
            }
            _ => header.set_entry_type(tar::EntryType::Regular),
        }
        header.set_cksum();
        builder
            .append_data(&mut header, &name, &vec![b'x'; member.size][..])
            .unwrap();
    }
    builder.into_inner().unwrap()
}

/// What lies on disk under `root`: the bytes of its files, each counted once however many names
/// it has, and its entries.
fn on_disk(root: &Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let mut inodes = std::collections::BTreeSet::new();
    let (mut bytes, mut entries) = (0, 0);
    for path in snapshot(root, &[]).into_keys() {
        entries += 1;
        let meta = path.symlink_metadata().unwrap();
        if meta.is_file() && inodes.insert(meta.ino()) {
            bytes += meta.len();
        }
    }
    (bytes, entries)
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

    /// Nothing a layer holds reaches outside the root, whatever layers came before it: no file
    /// written, removed or chmodded around it, through a climbing or absolute name, a link an
    /// earlier layer planted, a hard link, or a deletion marker, and no file around it linked into
    /// the tree. Whatever it lands under the root carries no set-user-ID, set-group-ID or sticky
    /// bit, and its owner can read and write it.
    ///
    /// Each layer is applied over whatever the ones before left, refused or not, so the root is
    /// in states a real image's unpack, which stops at the first refusal, never leaves it in.
    #[test]
    fn no_layer_reaches_outside_its_root_or_keeps_a_privileged_bit(
        layers in images(),
    ) {
        let ground = Ground::new();
        let before = ground.around();
        for (n, (members, gzip)) in layers.iter().enumerate() {
            let (layer, _) = raw_tar(members, &ground);
            let _ = ground.apply(n, &layer, *gzip, &mut Budget::new());
        }
        proptest::prop_assert_eq!(ground.around(), before, "the ground around the root changed");
        let linked = ground.linked_out();
        proptest::prop_assert!(linked.is_empty(), "linked out of the tree: {:?}", linked);
        let wrong = privileged_or_locked(&ground.root);
        proptest::prop_assert!(wrong.is_empty(), "modes left under the root: {:?}", wrong);
    }

    /// An image's layers stay within what was left of both ceilings, and are refused only past
    /// one. On disk after them: no more bytes than were left plus the one that proves a member ran
    /// over, and no more entries than were left. Layers that fit both ceilings apply whole, and a
    /// refusal is a ceiling's. The layers are honest ones, whose only possible refusal is the
    /// budget's, applied as an image's are: one budget across them, stopping at the first refusal.
    #[test]
    fn an_images_layers_stay_within_both_ceilings_and_are_refused_only_past_one(
        (layers, bytes_left, entries_left) in budgets(),
    ) {
        let ground = Ground::new();
        let mut budget = Budget {
            bytes: MAX_UNPACKED_BYTES - bytes_left,
            members: MAX_MEMBERS - entries_left,
        };
        let mut refused = None;
        for (n, members) in layers.iter().enumerate() {
            if let Err(e) = ground.apply(n, &honest_tar(members), n % 2 == 1, &mut budget) {
                refused = Some(e.to_string());
                break;
            }
        }
        let (bytes, entries) = on_disk(&ground.root);
        proptest::prop_assert!(bytes <= bytes_left + 1, "{} bytes on disk, {} left", bytes, bytes_left);
        proptest::prop_assert!(entries <= entries_left, "{} entries on disk, {} left", entries, entries_left);
        let (bytes_declared, entries_at_most) = declared(&layers);
        if bytes_declared <= bytes_left && entries_at_most <= entries_left {
            proptest::prop_assert!(refused.is_none(), "refused within both ceilings: {:?}", refused);
        }
        if let Some(refusal) = refused {
            proptest::prop_assert!(refusal.contains("more than"), "refused for another reason: {}", refusal);
        }
    }

    /// Whatever bytes a layer holds, applying it ends in a tree or a refusal, without a panic and
    /// without reaching outside the root or leaving a privileged bit. The bytes are generated
    /// layers, then changed: a header field rewritten with its checksum made right, a byte, the
    /// layer cut, a block inserted.
    #[test]
    fn any_bytes_as_a_layer_are_applied_or_refused_without_reaching_outside(
        members in vec(generated(), 1..8),
        mutations in vec((0u8..5, any::<Index>(), any::<Index>(), any::<u64>()), 1..5),
        gzip in any::<bool>(),
    ) {
        let ground = Ground::new();
        let before = ground.around();
        let (layer, headers) = raw_tar(&members, &ground);
        let layer = mutated(layer, &headers, &mutations);
        let _ = ground.apply(0, &layer, gzip, &mut Budget::new());
        proptest::prop_assert_eq!(ground.around(), before, "the ground around the root changed");
        let linked = ground.linked_out();
        proptest::prop_assert!(linked.is_empty(), "linked out of the tree: {:?}", linked);
        let wrong = privileged_or_locked(&ground.root);
        proptest::prop_assert!(wrong.is_empty(), "modes left under the root: {:?}", wrong);
    }
}
