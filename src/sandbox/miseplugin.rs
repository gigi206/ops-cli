//! The bundled mise "nix" backend plugin: embedded in the binary, materialized
//! into sbx's data directory, and registered for the in-cage mise so an agent
//! can self-equip a project's `nix:` tools (`mise install nix:<pkg>`) into the
//! project's own writable store.
//!
//! The plugin tree (`mise/` in the source) is carried inside the binary by the
//! build script, so a hermetic cage — which has no host copy to point mise at —
//! still gets a complete, version-matched plugin. It is staged read-only outside
//! every writable mount and bound into the cage; the registration that wires it
//! to mise is a symlink in the cage's writable mise data directory, recreated on
//! every launch so an sbx upgrade (which changes the embedded tree) re-points it.

include!(concat!(env!("OUT_DIR"), "/mise_plugin_files.rs"));

use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};

/// The backend name mise registers the plugin under: a `nix:<pkg>` tool routes to
/// it. Also the directory name the registration symlink takes under `plugins/`.
pub(crate) const PLUGIN_NAME: &str = "nix";

/// Where the staged plugin tree is bound read-only inside the cage, and the target
/// the registration symlink points at. An sbx-owned path that collides with no
/// structural mount.
pub(crate) const INCAGE_DIR: &str = "/opt/sbx/mise-nix-plugin";

/// Materialize the embedded plugin tree into sbx's data directory and return the
/// host directory holding it (ready to bind read-only at [`INCAGE_DIR`]).
///
/// Content-keyed: the directory name is a hash of the embedded bytes, so a given
/// sbx binary always stages to the same path (idempotent — re-materializing is
/// skipped) while a different build stages beside it. The tree is written into a
/// unique temp sibling and `rename`d into place, so a concurrent launch of the
/// same project never observes a half-written plugin (a lost rename race just
/// means the other launch staged the identical tree first).
pub(crate) fn stage(data_dir: &Path) -> io::Result<PathBuf> {
    let base = data_dir.join("mise-plugin");
    let dir = base.join(content_hash());
    // The sentinel proves a complete prior materialization (the rename below is
    // atomic, so its presence means the whole tree is there).
    if dir.join("metadata.lua").is_file() {
        return Ok(dir);
    }

    std::fs::create_dir_all(&base)?;
    let tmp = base.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        super::atomicfile::unique()
    ));
    if let Err(e) = write_tree(&tmp) {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }
    match std::fs::rename(&tmp, &dir) {
        Ok(()) => Ok(dir),
        // Lost the race (another launch placed the identical tree) or it already
        // existed: discard the redundant temp and use the winner.
        Err(_) if dir.join("metadata.lua").is_file() => {
            let _ = std::fs::remove_dir_all(&tmp);
            Ok(dir)
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            Err(e)
        }
    }
}

/// Register the staged plugin for a cage's mise by placing the `<plugins_dir>/nix`
/// symlink pointing at [`INCAGE_DIR`] — the same wiring `mise plugins link` would
/// create, but without running mise. `plugins_dir` is the host path of the cage's
/// `MISE_DATA_DIR/plugins`. Run on every launch (the target is constant, so this
/// only needs to (re)create the link, never re-point it).
///
/// Concurrency-safe: the link is created at a unique temp name and `rename`d onto
/// the registration path. `rename(2)` is atomic, so a second launch of the **same**
/// project (the "second terminal" case) only ever sees the old link or the new one —
/// never the missing-link window a remove-then-create would open — and two racing
/// registrations resolve to a last-writer-wins of identical links.
pub(crate) fn register(root: &Path, rel: &str) -> io::Result<()> {
    // Walked with symlinks refused, not `create_dir_all`ed. `root` is a bind's mount point — the
    // cage's `$HOME`, or the per-project mise pool — and every component of `rel` below it is an
    // ordinary directory in-cage code owns and can replace. Two things here follow such a link:
    // the placement itself, which would register the plugin outside the pool; and worse, the
    // `remove_dir_all(&link)` fallback below, which recursively deletes whatever sits at
    // `<plugins_dir>/nix`. A cage that left `ln -s /home/user/somewhere ~/.local/share/mise/plugins`
    // behind therefore had the *next* launch delete `/home/user/somewhere/nix` outright.
    let plugins_dir = super::cagedir::ensure_under(root, rel, 0o700)?;
    let plugins_dir = plugins_dir.as_path();
    let link = plugins_dir.join(PLUGIN_NAME);
    // The temp name carries the pid (like `stage`): `super::atomicfile::unique()` is a process-local counter starting
    // at 0, so without the pid two concurrent same-project launches would share `.nix.0.tmp` and one
    // could `remove_file` the other's temp mid-rename. A crashed launch's pid-tagged temp is then a
    // tiny dangling symlink the next launch does not match — the same self-healing GC class `stage`
    // already accepts.
    let tmp = plugins_dir.join(register_temp_name(
        std::process::id(),
        super::atomicfile::unique(),
    ));
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(INCAGE_DIR, &tmp)?;
    let placed = std::fs::rename(&tmp, &link).or_else(|_| {
        // `rename` replaces an existing symlink or file atomically, but not a real
        // directory — which only appears if an agent ran its own `mise plugins`
        // command into the slot. Clear it and retry (best-effort, self-inflicted case).
        let _ = std::fs::remove_dir_all(&link);
        std::fs::rename(&tmp, &link)
    });
    if placed.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    placed
}

/// The temp name `register` stages the plugin symlink at. It carries the pid because `super::atomicfile::unique()` is a
/// process-local counter starting at 0: without the pid two concurrent same-project launches would
/// both stage at `.nix.0.tmp` and one could `remove_file` the other's temp mid-rename.
fn register_temp_name(pid: u32, seq: u64) -> String {
    format!(".{PLUGIN_NAME}.{pid}.{seq}.tmp")
}

/// Write the embedded plugin tree under `root`, recreating each file's relative
/// path. Used on a temp directory that is then atomically renamed into place.
fn write_tree(root: &Path) -> io::Result<()> {
    for (rel, bytes) in PLUGIN_FILES {
        let dest = root.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, bytes)?;
    }
    Ok(())
}

/// A short hex hash of the embedded tree (paths and bytes), so the staging
/// directory changes exactly when the plugin does.
fn content_hash() -> String {
    let mut h = Sha256::new();
    for (rel, bytes) in PLUGIN_FILES {
        h.update((rel.len() as u64).to_le_bytes());
        h.update(rel.as_bytes());
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    crate::plugins::catalogue::to_hex(&h.finalize()[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    #[test]
    fn register_temp_names_are_unique_per_process() {
        // Two processes both start `super::atomicfile::unique()` at 0; the pid keeps their first temp distinct, so a
        // concurrent same-project register cannot collide on `.nix.0.tmp`.
        assert_ne!(register_temp_name(1000, 0), register_temp_name(2000, 0));
        // within one process the counter keeps them distinct too
        assert_ne!(register_temp_name(1000, 0), register_temp_name(1000, 1));
        // and the pid is actually in the name
        assert!(register_temp_name(4242, 7).contains("4242"));
    }

    #[test]
    fn the_embedded_tree_carries_the_plugin_entrypoints() {
        // The build script must have embedded the real plugin: its manifest, the
        // backend hooks mise calls, and the build library the `which`->`command -v`
        // fix lives in. A drift here means the embed regressed.
        let names: Vec<&str> = PLUGIN_FILES.iter().map(|(p, _)| *p).collect();
        for expected in [
            "metadata.lua",
            "hooks/backend_install.lua",
            "hooks/backend_list_versions.lua",
            "lib/platform.lua",
        ] {
            assert!(names.contains(&expected), "missing embedded {expected}");
        }
        // the `which` binary is absent from the hermetic cage, so the plugin must
        // probe for nix with the POSIX builtin, not the `which` command
        let platform = PLUGIN_FILES
            .iter()
            .find(|(p, _)| *p == "lib/platform.lua")
            .map(|(_, b)| String::from_utf8_lossy(b))
            .expect("platform.lua embedded");
        assert!(
            platform.contains("command -v nix"),
            "platform.lua must probe nix with `command -v`"
        );
        assert!(
            !platform.contains("which nix"),
            "platform.lua must not depend on the absent `which` binary"
        );
    }

    #[test]
    fn stage_materializes_a_complete_tree_idempotently() {
        let data = TmpDir::new();
        let first = stage(data.path()).expect("stage the plugin");

        // every embedded file is present with its exact bytes
        for (rel, bytes) in PLUGIN_FILES {
            let got = std::fs::read(first.join(rel)).expect("staged file present");
            assert_eq!(&got, bytes, "staged {rel} differs from the embedded bytes");
        }
        // content-keyed and idempotent: a second stage returns the same directory
        // and leaves no temp behind
        let second = stage(data.path()).expect("re-stage the plugin");
        assert_eq!(first, second);
        let leaked: Vec<_> = std::fs::read_dir(data.path().join("mise-plugin"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
            .collect();
        assert!(leaked.is_empty(), "a staging temp dir leaked: {leaked:?}");
    }

    #[test]
    fn register_links_the_backend_to_the_incage_plugin() {
        let home = TmpDir::new();
        const REL: &str = ".local/share/mise/plugins";
        let plugins = home.join(REL);
        register(home.path(), REL).expect("register the plugin");

        let link = plugins.join("nix");
        let target = std::fs::read_link(&link).expect("the registration is a symlink");
        assert_eq!(target, Path::new(INCAGE_DIR));

        // idempotent: a second registration (e.g. after an sbx upgrade) replaces the
        // link without error
        register(home.path(), REL).expect("re-register the plugin");
        assert_eq!(std::fs::read_link(&link).unwrap(), Path::new(INCAGE_DIR));
    }

    /// `plugins_dir` sits under the cage's own `$HOME`, so every component of it is one in-cage
    /// code can replace with a symlink and leave for the next launch. Two things here used to
    /// follow such a link: the placement, which would register the plugin outside the pool, and the
    /// `remove_dir_all(&link)` fallback, which recursively deletes whatever sits at
    /// `<plugins_dir>/nix` — so `ln -s /home/user/somewhere ~/.local/share/mise/plugins` had the
    /// next launch delete `/home/user/somewhere/nix` outright.
    #[test]
    fn register_refuses_a_plugins_dir_the_cage_pointed_out_of_the_home() {
        let home = TmpDir::new();
        const REL: &str = ".local/share/mise/plugins";
        let outside = home.join("outside");
        // The shape the fallback would delete: a real `nix` directory at the link's target.
        std::fs::create_dir_all(outside.join("nix").join("keep")).unwrap();
        std::fs::create_dir_all(home.path().join(".local/share/mise")).unwrap();
        std::os::unix::fs::symlink(&outside, home.path().join(REL)).unwrap();

        let err = register(home.path(), REL).expect_err("a repointed plugins dir must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
        assert!(
            outside.join("nix").join("keep").exists(),
            "the host directory the link pointed at was deleted"
        );
        assert!(
            std::fs::symlink_metadata(home.path().join(REL))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the planted link must be reported, not replaced"
        );
    }

    #[test]
    fn register_is_safe_under_concurrent_same_project_launches() {
        // Two launches of the same project register at once (the "second terminal"
        // case): the atomic rename means every one succeeds and the link always
        // resolves — no remove-then-create window leaves a launch with EEXIST/ENOENT.
        let home = TmpDir::new();
        const REL: &str = ".local/share/mise/plugins";
        let plugins = home.join(REL);
        std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| s.spawn(|| register(home.path(), REL)))
                .collect();
            for h in handles {
                h.join().expect("thread did not panic").expect("register");
            }
        });
        assert_eq!(
            std::fs::read_link(plugins.join("nix")).unwrap(),
            Path::new(INCAGE_DIR)
        );
        // no temp link leaked
        let leaked: Vec<_> = std::fs::read_dir(&plugins)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".nix."))
            .collect();
        assert!(leaked.is_empty(), "a registration temp leaked: {leaked:?}");
    }
}
