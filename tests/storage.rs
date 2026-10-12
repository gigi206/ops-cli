//! `sbx storage init` on a host without `btrfs-progs`, where sbx formats the volume with a copy it
//! provisions for itself. Where that copy is built decides whether the data directory can still
//! adopt the volume: a `store` left in it reads as data `sbx storage use` would strand, and `use`
//! refuses. Skipped, not failed, where the host cannot run the provisioned copy or the binary cache
//! is out of reach.

#[macro_use]
mod common;
use common::fixture::TmpDir;

use std::path::{Path, PathBuf};

/// A `PATH` of one directory under `root`, linking the programs a volume creation provisions with,
/// as the inherited `PATH` finds them, and no `mkfs.btrfs`, so sbx has to build its own. Leaving out
/// whole directories of the host's would take whatever else they hold with them: a runner may keep
/// `bwrap` beside its `mkfs.btrfs`.
fn path_without_mkfs_btrfs(root: &Path) -> PathBuf {
    let dir = root.join("bin");
    std::fs::create_dir_all(&dir).unwrap();
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    for name in ["nix", "nix-store", "bwrap"] {
        if let Some(found) = common::program_in(name, &inherited) {
            std::os::unix::fs::symlink(found, dir.join(name)).unwrap();
        }
    }
    dir
}

#[test]
fn a_volume_formatted_with_provisioned_btrfs_progs_leaves_the_data_directory_adoptable() {
    let root = TmpDir::prefixed("st", "noprogs");
    let data_home = root.join("data");
    let image = root.join("img/x.btrfs");
    // A directory of the user's own beside the image, under the name a store built beside the
    // image would take.
    let theirs = root.join("img/x.tools/keep");
    std::fs::create_dir_all(&theirs).unwrap();
    std::fs::write(theirs.join("file"), b"theirs").unwrap();

    // Built once: the probe runs its launch a second time after a download failure.
    let path = path_without_mkfs_btrfs(root.path());
    let out = probe_or_skip!(
        "storage init without btrfs-progs",
        common::isolated_sbx("st-")
            .args(["storage", "init", "--size", "2G", "--image"])
            .arg(&image)
            .env("PATH", &path)
            .env("XDG_DATA_HOME", &data_home)
            .env_remove("SBX_DATA_DIR")
            .output()
            .expect("spawn sbx storage init")
    );
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        said.contains("formatting with sbx's own btrfs-progs"),
        "the volume was not formatted with the copy sbx provisions: {said}"
    );
    assert!(image.is_file(), "no image was created: {said}");

    let data = data_home.join("sbx");
    assert!(
        data.join("store").symlink_metadata().is_err(),
        "the provisioned btrfs-progs was built into the data directory's store, which `sbx \
         storage use` then refuses to strand"
    );
    assert!(
        data.join("storage-tools").symlink_metadata().is_err(),
        "the store btrfs-progs was built into outlived the format"
    );
    assert_eq!(
        std::fs::read(theirs.join("file")).ok().as_deref(),
        Some(&b"theirs"[..]),
        "a directory beside the image that sbx did not create was removed"
    );
}
