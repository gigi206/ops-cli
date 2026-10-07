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
use std::ffi::OsStr;
use std::io;
use std::os::fd::OwnedFd;
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
    // Before the fast path, so a crash's temps are swept even when the tree they were staging is
    // already in place; a `base` that does not exist yet lists nothing.
    sweep_dead_temps(&base, stage_temp_pid, |name| {
        let _ = std::fs::remove_dir_all(base.join(name));
    });
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
    fresh_temp(&tmp)?;
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

/// Create `tmp` empty and exclusively. A crashed launch whose pid this one reuses can have left a
/// temp under this very name, and writing into it would merge that older tree's files into the one
/// about to be renamed into place.
fn fresh_temp(tmp: &Path) -> io::Result<()> {
    let _ = std::fs::remove_dir_all(tmp);
    std::fs::create_dir(tmp)
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
    // fallback in [`place`], which recursively deletes whatever sits at `<plugins_dir>/nix`. A
    // cage that left `ln -s /home/user/somewhere ~/.local/share/mise/plugins` behind therefore had
    // the *next* launch delete `/home/user/somewhere/nix` outright.
    //
    // Held, not only walked: a cage of the same project can be running while this registers, and
    // swap the directory for such a link after the walk checked it. The placement goes through
    // the descriptor the walk reached, so it lands in the directory that was checked.
    let plugins_dir = super::cagedir::hold_under(root, rel, 0o700)?;
    place(&plugins_dir)
}

/// The placement behind [`register`], through the descriptor of the plugins directory its walk
/// reached ([`super::cagedir::entry`] names each entry inside it). Split from the walk so a test
/// can change the tree between the two, the way a running cage can.
fn place(plugins_dir: &OwnedFd) -> io::Result<()> {
    let link = super::cagedir::entry(plugins_dir, OsStr::new(PLUGIN_NAME))?;
    // The temp name carries the pid (like `stage`): `super::atomicfile::unique()` is a process-local
    // counter starting at 0, so without the pid two concurrent same-project launches would share
    // `.nix.0.tmp` and one could `remove_file` the other's temp mid-rename. A crashed launch's temp
    // is swept by the next placement once its pid is gone, as `stage` sweeps its own.
    let listed = PathBuf::from(format!(
        "/proc/self/fd/{}",
        std::os::fd::AsRawFd::as_raw_fd(plugins_dir)
    ));
    sweep_dead_temps(&listed, register_temp_pid, |name| {
        if let Ok(dead) = super::cagedir::entry(plugins_dir, name) {
            let _ = std::fs::remove_file(dead);
        }
    });
    let tmp = super::cagedir::entry(
        plugins_dir,
        OsStr::new(&register_temp_name(
            std::process::id(),
            super::atomicfile::unique(),
        )),
    )?;
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(INCAGE_DIR, &tmp)?;
    let placed = std::fs::rename(&tmp, &link).or_else(|e| {
        // `rename` replaces an existing symlink or file atomically, but not a real
        // directory — which only appears if an agent ran its own `mise plugins`
        // command into the slot. Clear it and retry (best-effort, self-inflicted case),
        // by descriptor, so the removal stays inside the directory that was checked.
        // Any other failure is returned as it is: clearing the slot cannot cure it, and
        // would delete what the slot held for nothing.
        if !slot_holds_a_directory(&e) {
            return Err(e);
        }
        let _ = super::gc::remove_child(plugins_dir, OsStr::new(PLUGIN_NAME));
        std::fs::rename(&tmp, &link)
    });
    if placed.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    placed
}

/// Whether a failed `rename` of the temp link onto the slot failed because the slot is a real
/// directory, the one case clearing the slot can cure: `EISDIR` for an empty or full directory,
/// and `ENOTEMPTY`/`EEXIST`, which `rename(2)` documents for a non-empty one.
fn slot_holds_a_directory(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EISDIR | libc::ENOTEMPTY | libc::EEXIST)
    )
}

/// Remove, through `remove`, each entry of `dir` that `pid_of` reads as a temp of a launch whose
/// process is gone. A live pid's temp is left alone: it may be another launch's, mid-rename. A pid
/// reused since the crash keeps its orphan until that process exits too, which costs one stray
/// entry, never a live one. Pids are read in this process's namespace, which is the host's: both
/// callers ([`stage`] and [`register`]) run in the launcher, before any cage exists.
fn sweep_dead_temps(dir: &Path, pid_of: fn(&str) -> Option<u32>, remove: impl Fn(&OsStr)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if let Some(pid) = name.to_str().and_then(pid_of)
            && pid != std::process::id()
            && !crate::session::pid_is_live(pid)
        {
            remove(&name);
        }
    }
}

/// The pid in a `stage` temp's name (`.tmp-<pid>-<seq>`).
fn stage_temp_pid(name: &str) -> Option<u32> {
    let (pid, seq) = name.strip_prefix(".tmp-")?.split_once('-')?;
    seq.parse::<u64>().ok()?;
    pid.parse().ok()
}

/// The pid in a `register` temp's name ([`register_temp_name`]).
fn register_temp_pid(name: &str) -> Option<u32> {
    let (pid, seq) = name
        .strip_prefix('.')?
        .strip_prefix(PLUGIN_NAME)?
        .strip_prefix('.')?
        .strip_suffix(".tmp")?
        .split_once('.')?;
    seq.parse::<u64>().ok()?;
    pid.parse().ok()
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

    /// A pid no process holds: a child that has been waited for.
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    #[test]
    fn only_a_directory_in_the_slot_lets_the_placement_clear_it() {
        for errno in [libc::EISDIR, libc::ENOTEMPTY, libc::EEXIST] {
            assert!(slot_holds_a_directory(&io::Error::from_raw_os_error(errno)));
        }
        for errno in [
            libc::EACCES,
            libc::EROFS,
            libc::EIO,
            libc::ENOSPC,
            libc::EXDEV,
        ] {
            assert!(
                !slot_holds_a_directory(&io::Error::from_raw_os_error(errno)),
                "errno {errno} would clear the slot for nothing"
            );
        }
    }

    #[test]
    fn a_real_directory_in_the_slot_is_replaced_by_the_registration() {
        let home = TmpDir::new();
        const REL: &str = ".local/share/mise/plugins";
        std::fs::create_dir_all(home.join(REL).join("nix").join("own")).unwrap();
        register(home.path(), REL).expect("a directory in the slot is cleared");
        assert_eq!(
            std::fs::read_link(home.join(REL).join("nix")).unwrap(),
            Path::new(INCAGE_DIR)
        );
    }

    #[test]
    fn temps_a_dead_launch_left_are_swept_and_a_live_ones_are_kept() {
        let data = TmpDir::new();
        let base = data.path().join("mise-plugin");
        let dead = dead_pid();
        let orphan = base.join(format!(".tmp-{dead}-0"));
        std::fs::create_dir_all(orphan.join("hooks")).unwrap();
        // The parent of this test process is alive and not this process.
        let parent = std::os::unix::process::parent_id();
        let busy = base.join(format!(".tmp-{parent}-3"));
        std::fs::create_dir_all(&busy).unwrap();
        stage(data.path()).unwrap();
        assert!(!orphan.exists(), "a dead launch's staging temp was kept");
        assert!(busy.exists(), "a live launch's staging temp was swept");
        // A crash under a tree that is already in place: the next stage takes the fast path, and
        // still sweeps.
        std::fs::create_dir_all(&orphan).unwrap();
        stage(data.path()).unwrap();
        assert!(
            !orphan.exists(),
            "the fast path kept a dead launch's staging temp"
        );

        let home = TmpDir::new();
        const REL: &str = ".local/share/mise/plugins";
        let plugins = home.join(REL);
        std::fs::create_dir_all(&plugins).unwrap();
        let stale = plugins.join(register_temp_name(dead, 0));
        let held = plugins.join(register_temp_name(parent, 1));
        std::os::unix::fs::symlink(INCAGE_DIR, &stale).unwrap();
        std::os::unix::fs::symlink(INCAGE_DIR, &held).unwrap();
        register(home.path(), REL).unwrap();
        assert!(
            std::fs::symlink_metadata(&stale).is_err(),
            "a dead launch's link temp was kept"
        );
        assert!(
            std::fs::symlink_metadata(&held).is_ok(),
            "a live launch's link temp was swept"
        );
    }

    #[test]
    fn a_staging_temp_left_under_a_reused_name_starts_empty() {
        let data = TmpDir::new();
        let reused = data.path().join(".tmp-1-0");
        std::fs::create_dir_all(reused.join("hooks")).unwrap();
        std::fs::write(reused.join("stale.lua"), b"left by an older build").unwrap();
        fresh_temp(&reused).unwrap();
        assert_eq!(
            std::fs::read_dir(&reused).unwrap().count(),
            0,
            "an older tree's files would be staged with the new one"
        );
    }

    #[test]
    fn every_embedded_path_is_a_plain_relative_path() {
        // `write_tree` joins each path onto the staging temp, so none may climb out of it.
        for (rel, _) in PLUGIN_FILES {
            let path = Path::new(rel);
            assert!(
                !rel.is_empty()
                    && path
                        .components()
                        .all(|c| matches!(c, std::path::Component::Normal(_))),
                "embedded path {rel:?} is not a plain relative path"
            );
        }
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

    /// The same link, swapped in after the walk checked the directory rather than left behind
    /// before it: a cage of the project that is running while another launch registers. The
    /// placement goes through the descriptor the walk reached, so it lands in the directory that
    /// was checked, and the directory behind the link keeps its contents.
    ///
    /// The descriptor is taken from the walk before the swap, as [`register`] takes it. A test that
    /// opened its own after the swap would hold the link's target and prove nothing.
    #[test]
    fn a_plugins_dir_swapped_for_a_link_after_the_walk_is_not_written_through() {
        let home = TmpDir::new();
        const REL: &str = ".local/share/mise/plugins";
        let outside = home.join("outside");
        std::fs::create_dir_all(outside.join("nix").join("keep")).unwrap();

        let held = super::super::cagedir::hold_under(home.path(), REL, 0o700).unwrap();
        let real = home.join("plugins.real");
        std::fs::rename(home.join(REL), &real).unwrap();
        std::os::unix::fs::symlink(&outside, home.join(REL)).unwrap();

        place(&held).expect("the placement lands in the directory it holds");

        assert!(
            outside.join("nix").join("keep").exists(),
            "the directory behind the link was deleted"
        );
        assert_eq!(
            std::fs::read_link(real.join("nix")).unwrap(),
            Path::new(INCAGE_DIR),
            "the registration did not land in the directory the walk checked"
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
