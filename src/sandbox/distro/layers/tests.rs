use super::*;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

/// Build a tar in memory from `(path, kind, payload)` triples, so a test states the archive it
/// means rather than shipping a fixture nobody can read.
enum Member<'a> {
    File(&'a str),
    Dir,
    Symlink(&'a str),
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
    apply(&blob, "application/vnd.oci.image.layer.v1.tar", root)
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
        let err = apply(&blob, "application/vnd.oci.image.layer.v1.tar", &root)
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
    let err = apply(&blob, "application/vnd.oci.image.layer.v1.tar", &root)
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
    apply(&blob, "application/vnd.oci.image.layer.v1.tar", &root).unwrap();

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
    apply(&blob, "application/vnd.oci.image.layer.v1.tar", &root).unwrap();

    assert!(!root.join("opt/a").exists(), "the directory was emptied");
    assert!(!root.join("opt/sub").exists(), "including its subtrees");
    assert!(
        root.join("opt/fresh").exists(),
        "and refilled by this layer"
    );
    assert!(root.join("keep").exists(), "another directory is untouched");
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
        apply(&blob, &layer.media_type, &root).expect("the layer applies");
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
