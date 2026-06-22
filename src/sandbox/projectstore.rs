//! A per-project, writable nix store seeded from the immutable shared store.
//!
//! The shared store is consumed read-only and stays byte-identical across every
//! sandbox. A project that needs to write into `/nix` — an agent self-equipping
//! its toolchain — gets its **own** nix store, seeded from the shared one. The
//! seed copies in **only the closure the project needs** (the base userland plus
//! the project's declared tools), not the whole shared store: each root's
//! transitive closure is enumerated against the shared store, those paths are
//! placed into the project store, and exactly that set is registered in the
//! project store's own database. Scoping to the closure bounds a project's store
//! to what it actually references, rather than growing it with every other
//! project's tools and every accumulated channel revision.
//!
//! Each path is *reflinked* (copy-on-write) where the filesystem supports it — so
//! identical content shares disk blocks until written — and fully copied
//! otherwise. Because every base path is a physically independent copy, a write
//! from inside the cage can never reach the shared store: it lands only in the
//! project's own copy (a hard link would instead share the inode and let that
//! write corrupt the shared base for every tenant). So the shared store stays
//! byte-identical, and concurrent same-project sandboxes serialise on their own
//! store's locks rather than contending on the shared one.
//!
//! Placement is atomic per store path: a path is copied into a unique temporary
//! sibling and then `rename`d into place, so a crash mid-copy — or a second
//! seed running concurrently — never leaves a half-written tree at a real
//! store-path name (which a later seed would wrongly see as already present and
//! skip forever). A path already present is left untouched, so re-seeding only
//! tops up what is missing without disturbing anything the project's own nix has
//! since written.
//!
//! The cage's nix reads and writes only this self-contained store; ops's own seed
//! is the only reader of the shared store, and only ever reads it.
//!
//! Concurrency needs no lock of ops's own. Two sandboxes of the same project can
//! seed at once: each path is placed by atomic rename, so a lost race is just a
//! redundant copy discarded — the winner's identical, content-addressed path is
//! already in place — and the database registration goes through `nix-store
//! --load-db`, whose concurrent merges serialise on the project database's own
//! SQLite locking. The broader case — a seed racing a live in-cage `nix build`, or
//! two agents building into one project store — rests on nix's own concurrent
//! store-access guarantee (that database locking plus the per-store-path `.lock`
//! files a build takes); it is nix's domain, not ops's, and is not exercised here.
//! The only cost of not serialising the copies is wasted I/O: each concurrent *cold*
//! seed copies the closure before its rename, so the losers' copies are thrown away
//! — bounded by the base closure, and only on a project's first, cold launches (a
//! per-project seed lock is a possible future optimisation).
//!
//! This module owns the per-project store's layout and its seed. The launcher seeds
//! it with the closure of the base userland and the project's tools, then binds it
//! read-write at `/nix` — so the cage runs from its own store and an agent's writes
//! land only there.

use crate::store::Layout;
use std::ffi::OsStr;
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Owner-only mode for the directories the seed creates. The shared store makes
/// path directories read-only (`0555`); the seed creates owner-writable ones
/// instead, so it can populate them and the cage's nix can later add new paths.
/// A path's content hash does not cover directory modes, so this does not affect
/// `nix-store --verify`; the copied *files* keep their own modes (`std::fs::copy`
/// and the reflink path both preserve them).
const DIR_MODE: u32 = 0o700;

/// A per-process counter feeding the unique temporary names the seed renames from
/// and the reflink probe. Combined with the pid it disambiguates concurrent seeds
/// — including a second same-project sandbox preparing at the same time.
static SEQ: AtomicU64 = AtomicU64::new(0);

/// A project's own writable nix store, rooted under its runtime tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectStore {
    /// The `--store` argument: the directory containing the project's `nix/` tree.
    store_dir: PathBuf,
}

impl ProjectStore {
    /// The directory passed to `nix --store`, backing the sandbox's `/nix`.
    pub(crate) fn store_dir(&self) -> &Path {
        &self.store_dir
    }
}

/// The per-project store directory for `project_id`, keyed on the same identity as
/// the rest of the project's runtime (home, synthetic identity, gcroots), so
/// housekeeping can reclaim it alongside them.
fn store_dir_for(layout: &Layout, project_id: &str) -> PathBuf {
    layout
        .data_dir()
        .join("projects")
        .join(project_id)
        .join("store")
}

/// Seed (or top up) `project_id`'s own store with the closure of `roots` from the
/// shared store and return it.
///
/// `roots` are the logical store paths the project references (its base userland
/// and declared tools). Their transitive closure is enumerated against the shared
/// store, those paths are placed into the project store — reflinked where the
/// filesystem supports copy-on-write, fully copied otherwise, each by atomic
/// rename — and exactly that closure is registered in the project store's database
/// with `nix-store --dump-db | --load-db`. The closure is the single source of
/// both the copy and the registration: every reference in every registered path
/// resolves to another path in the same set, so the seeded store is internally
/// consistent (`nix-store --verify` passes).
///
/// Both halves are idempotent: a path already present is skipped, and `--load-db`
/// merges into the target database, so re-running tops up new closure paths
/// without disturbing anything the project's own nix has since written. The shared
/// store is only ever read.
pub(crate) fn prepare(
    nix_store: &Path,
    layout: &Layout,
    project_id: &str,
    roots: &[PathBuf],
) -> io::Result<ProjectStore> {
    let store_dir = store_dir_for(layout, project_id);
    let project_paths = store_dir.join("nix").join("store");
    DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(&project_paths)?;

    // Enumerate the closure to copy and register. Passing no roots would make
    // `--dump-db` dump the *whole* shared database, so an empty request seeds
    // nothing rather than silently widening to everything.
    if roots.is_empty() {
        return Ok(ProjectStore { store_dir });
    }
    let shared_store = layout.store_dir();
    let closure = closure_of(nix_store, &shared_store, roots)?;

    // Probe once whether the project store's filesystem supports reflinks, rather
    // than attempting (and failing) a clone per file on a filesystem without them.
    let reflink_ok = supports_reflink(&project_paths);

    // Place each closure path: <shared>/nix/store/<p> -> <project>/nix/store/<p>,
    // each as a physically independent copy so an in-cage write cannot reach the
    // shared base, and atomically so a crash or a concurrent seed never leaves a
    // partial at a real store-path name.
    let shared_paths = shared_store.join("nix").join("store");
    for path in &closure {
        let Some(name) = path.file_name() else {
            continue;
        };
        seed_path(&shared_paths, &project_paths, name, reflink_ok)?;
    }

    // Register exactly that closure in the project store's own database.
    load_db(nix_store, &shared_store, &store_dir, &closure)?;

    // Root the seeded paths so a later `nix-store --gc` against this store keeps the
    // base userland and the project's tools while collecting only orphaned paths (a
    // rolled-away flake build, an abandoned in-cage install). Without a root, gc would
    // see the whole seed as dead and delete it; this also protects the base from an
    // in-cage `nix-collect-garbage`, which previously could remove the unrooted seed.
    gcroot_roots(&store_dir, roots)?;

    Ok(ProjectStore { store_dir })
}

/// The transitive closure of `roots` in `shared_store`, as logical store paths
/// (`/nix/store/<hash>-name`). `nix-store -qR` returns each root and every path it
/// references, so the result is closed under references — the property that makes
/// the registration in [`load_db`] internally consistent.
fn closure_of(
    nix_store: &Path,
    shared_store: &Path,
    roots: &[PathBuf],
) -> io::Result<Vec<PathBuf>> {
    use std::process::Command;
    let out = Command::new(nix_store)
        .env("NIX_REMOTE", "")
        .arg("--store")
        .arg(shared_store)
        .arg("--query")
        .arg("--requisites")
        .args(roots)
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "nix-store --query --requisites failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect())
}

/// Place one store path `name` from `shared_paths` into `project_paths` as a
/// physically independent, atomically-placed copy. A path already present is left
/// untouched (top-up only); otherwise it is copied into a unique temporary sibling
/// and moved into place by [`place_atomically`], so a half-written tree only ever
/// exists under the temporary name and a crash or a racing seed cannot leave a
/// partial at the real store-path name.
fn seed_path(
    shared_paths: &Path,
    project_paths: &Path,
    name: &OsStr,
    reflink_ok: bool,
) -> io::Result<()> {
    let dest = project_paths.join(name);
    if dest.symlink_metadata().is_ok() {
        return Ok(());
    }
    let mut tmp_name = std::ffi::OsString::from(format!(".tmp-{}-", unique()));
    tmp_name.push(name);
    let tmp = project_paths.join(tmp_name);
    copy_recursive(&shared_paths.join(name), &tmp, reflink_ok)?;
    place_atomically(&tmp, &dest)
}

/// Move the fully-copied `tmp` tree into place at its real store-path name `dest` by
/// `rename` — atomic, so a reader only ever sees the complete tree or nothing at the
/// real name. Losing a race is success: if the rename fails but `dest` now exists,
/// another seed of the same project placed the identical, content-addressed path
/// first, so the now-redundant temp is discarded and success reported. Any other
/// failure discards the temp and propagates, leaving no partial behind.
fn place_atomically(tmp: &Path, dest: &Path) -> io::Result<()> {
    match fs::rename(tmp, dest) {
        Ok(()) => Ok(()),
        Err(_) if dest.symlink_metadata().is_ok() => {
            discard(tmp);
            Ok(())
        }
        Err(e) => {
            discard(tmp);
            Err(e)
        }
    }
}

/// Recursively copy `from` to a fresh `to`: directories are created owner-writable
/// and recursed into, symlinks are recreated (never dereferenced), and regular
/// files are copied as physically independent copies (reflinked when `reflink_ok`,
/// else fully copied). `to` is assumed not to exist — the caller copies into a
/// unique temporary, so there is no existing content to preserve here.
fn copy_recursive(from: &Path, to: &Path, reflink_ok: bool) -> io::Result<()> {
    // `symlink_metadata` does not follow symlinks, so a store symlink is recreated
    // rather than dereferenced.
    let file_type = from.symlink_metadata()?.file_type();
    if file_type.is_dir() {
        DirBuilder::new().mode(DIR_MODE).create(to)?;
        for entry in fs::read_dir(from)? {
            let entry = entry?;
            copy_recursive(&entry.path(), &to.join(entry.file_name()), reflink_ok)?;
        }
        Ok(())
    } else if file_type.is_symlink() {
        std::os::unix::fs::symlink(fs::read_link(from)?, to)
    } else {
        place_file(from, to, reflink_ok)
    }
}

/// Place one regular file at `to` as a physically independent copy of `from`, so a
/// later in-cage write to it can never reach `from` (the shared store). When
/// `reflink_ok`, it is cloned copy-on-write — `from` and `to` share data extents
/// until one is written, then only the changed extent is copied, leaving `from`
/// untouched — costing no extra disk until a write. Otherwise (a filesystem without
/// reflink, e.g. ext4) it is a full content copy. Either way `to` is a distinct
/// inode with `from`'s mode.
fn place_file(from: &Path, to: &Path, reflink_ok: bool) -> io::Result<()> {
    if reflink_ok && reflink(from, to).is_ok() {
        return Ok(());
    }
    // a plain copy is independent on every filesystem and preserves the mode
    fs::copy(from, to).map(|_| ())
}

/// Clone `from` into a fresh `to` copy-on-write via the `FICLONE` ioctl, preserving
/// the source mode (the ioctl clones contents only). Returns an error — and removes
/// the empty `to` it created — when the filesystem does not support reflinks, so the
/// caller can fall back to a plain copy.
fn reflink(from: &Path, to: &Path) -> io::Result<()> {
    use std::fs::File;
    use std::os::unix::io::AsRawFd;
    let src = File::open(from)?;
    let mode = src.metadata()?.permissions();
    let dst = File::create(to)?;
    // SAFETY: both descriptors are valid for the call; FICLONE reads from `src` and
    // replaces `dst`'s contents, touching no Rust-owned memory.
    let rc = unsafe { libc::ioctl(dst.as_raw_fd(), libc::FICLONE, src.as_raw_fd()) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        drop(dst);
        let _ = fs::remove_file(to);
        return Err(err);
    }
    fs::set_permissions(to, mode)?;
    Ok(())
}

/// Whether `dir`'s filesystem supports reflinks, probed with a throwaway clone (both
/// files on the same filesystem as the seed's destination). The probe names are
/// unique per call (pid + counter) so a concurrent same-project seed never collides
/// on them. The probe files are removed before returning.
fn supports_reflink(dir: &Path) -> bool {
    let src = dir.join(format!(".reflink-probe-src-{}", unique()));
    let dst = dir.join(format!(".reflink-probe-dst-{}", unique()));
    let ok = fs::write(&src, b"probe")
        .and_then(|()| reflink(&src, &dst))
        .is_ok();
    let _ = fs::remove_file(&src);
    let _ = fs::remove_file(&dst);
    ok
}

/// A token unique to this process and call, for temporary names that must not
/// collide with a concurrent seed's.
fn unique() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// Remove a temporary placement, whether it ended up a directory tree or a single
/// file/symlink. Best effort: the temp is owner-writable (its directories are
/// created `0700`), so removal succeeds; a leftover only wastes disk, never
/// corrupts the store (it never carries a real store-path name).
fn discard(path: &Path) {
    if fs::remove_dir_all(path).is_err() {
        let _ = fs::remove_file(path);
    }
}

/// Register `closure` into the project store's database by piping the shared
/// store's registrations for exactly those paths (`nix-store --dump-db <closure>`)
/// into `nix-store --load-db` against the project store. Dumping the closure — not
/// the roots — is what makes the result consistent: every reference recorded in a
/// path's registration is itself a registered path. `--load-db` initialises the
/// database when the store is fresh and *merges* into a non-empty one, preserving
/// paths the project's own nix has registered — so this serves both the first seed
/// and a later top-up. Daemonless (`NIX_REMOTE` empty), like every other store
/// operation.
fn load_db(
    nix_store: &Path,
    shared_store: &Path,
    project_store: &Path,
    closure: &[PathBuf],
) -> io::Result<()> {
    use std::process::{Command, Stdio};
    let mut dump = Command::new(nix_store)
        .env("NIX_REMOTE", "")
        .arg("--store")
        .arg(shared_store)
        .arg("--dump-db")
        .args(closure)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let dump_out = dump.stdout.take().expect("stdout was requested as a pipe");
    // The reader child consumes the pipe directly, so a large dump never blocks on
    // a full pipe buffer; reap the writer only once the reader has finished.
    let load_status = Command::new(nix_store)
        .env("NIX_REMOTE", "")
        .arg("--store")
        .arg(project_store)
        .arg("--load-db")
        .stdin(Stdio::from(dump_out))
        .stderr(Stdio::inherit())
        .status()?;
    let dump_status = dump.wait()?;
    if !dump_status.success() {
        return Err(io::Error::other("nix-store --dump-db failed"));
    }
    if !load_status.success() {
        return Err(io::Error::other("nix-store --load-db failed"));
    }
    Ok(())
}

/// The project store's garbage-collector roots directory. `nix-store --gc` keeps every
/// path reachable from a symlink here, so this is where the seed anchors what the cage
/// needs. A sibling of the store's `db/`, under the relocated store's `nix/var` tree.
pub(crate) fn gcroots_dir(store_dir: &Path) -> PathBuf {
    store_dir.join("nix/var/nix/gcroots")
}

/// Register each logical `roots` path (`/nix/store/<hash>-name`) as a direct gc root in
/// `store_dir`'s store, so `nix-store --gc` keeps it and its closure. A root is a symlink
/// `gcroots/<hash-name> -> /nix/store/<hash-name>` — the relocated store interprets that
/// logical target as one of its own paths. The store-path name is unique per content, so
/// it is the root's stable, collision-free file name.
///
/// Idempotent and race-tolerant: a root already pointing at the right target is left
/// alone, and a concurrent same-project seed racing on the same name resolves to the same
/// link. Each link is placed atomically (write to a unique temp name, then `rename`), so a
/// reader never sees a half-made root and the loser of a race overwrites with an identical
/// link.
fn gcroot_roots(store_dir: &Path, roots: &[PathBuf]) -> io::Result<()> {
    let dir = gcroots_dir(store_dir);
    DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(&dir)?;
    for root in roots {
        let Some(name) = root.file_name() else {
            continue;
        };
        let link = dir.join(name);
        // Already the right root: nothing to do (the common warm re-seed).
        if fs::read_link(&link).is_ok_and(|t| t == *root) {
            continue;
        }
        let mut tmp_name = std::ffi::OsString::from(format!(".tmp-{}-", unique()));
        tmp_name.push(name);
        let tmp = dir.join(tmp_name);
        // A stale temp from a crashed seed would block the symlink; clear it first.
        let _ = fs::remove_file(&tmp);
        std::os::unix::fs::symlink(root, &tmp)?;
        match fs::rename(&tmp, &link) {
            Ok(()) => {}
            // Lost the race or the link already existed: another seed placed an identical
            // root, so discard the temp and accept it.
            Err(_) => {
                let _ = fs::remove_file(&tmp);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    /// A `(device, inode)` pair — equal across two paths iff they are the same
    /// inode. The device is part of the key because an inode number alone can
    /// collide across filesystems.
    fn ino(path: &Path) -> (u64, u64) {
        let m = std::fs::symlink_metadata(path).unwrap();
        (m.dev(), m.ino())
    }

    #[test]
    fn store_dir_is_under_the_project_runtime() {
        let layout = Layout::under(Path::new("/data/ops"));
        assert_eq!(
            store_dir_for(&layout, "abc"),
            PathBuf::from("/data/ops/projects/abc/store")
        );
    }

    #[test]
    fn gcroot_roots_links_each_root_and_is_idempotent() {
        let base = TmpDir::new();
        let store_dir = base.join("store");
        let roots = [
            PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-base"),
            PathBuf::from("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-tool"),
        ];

        gcroot_roots(&store_dir, &roots).unwrap();

        // each root is a direct gc-root symlink named for the store path, pointing at the
        // logical store path the relocated store resolves as its own
        let dir = gcroots_dir(&store_dir);
        for root in &roots {
            let link = dir.join(root.file_name().unwrap());
            assert_eq!(std::fs::read_link(&link).unwrap(), *root);
        }
        // no stray temp left behind by the atomic placement
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "a temp placement leaked");

        // re-running is a no-op (the warm re-seed path): the links keep the same identity
        let before = roots
            .iter()
            .map(|r| ino(&dir.join(r.file_name().unwrap())))
            .collect::<Vec<_>>();
        gcroot_roots(&store_dir, &roots).unwrap();
        let after = roots
            .iter()
            .map(|r| ino(&dir.join(r.file_name().unwrap())))
            .collect::<Vec<_>>();
        assert_eq!(
            before, after,
            "idempotent re-seed replaced an unchanged root"
        );
    }

    #[test]
    fn copy_recursive_copies_files_recreates_symlinks_and_creates_dirs() {
        let base = TmpDir::new();
        let src = base.join("src");
        let dst = base.join("dst");
        // a file (with the exec bit set), a nested dir + file, and a symlink
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("tool"), b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(src.join("tool"), std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::write(src.join("sub/data"), b"payload").unwrap();
        symlink("tool", src.join("link")).unwrap();

        copy_recursive(&src, &dst, true).unwrap();

        // regular files are physically independent copies (distinct inodes), with
        // their content intact
        assert_ne!(
            ino(&src.join("tool")),
            ino(&dst.join("tool")),
            "file shares the source inode — a write would reach the shared store"
        );
        assert_eq!(std::fs::read(dst.join("tool")).unwrap(), b"#!/bin/sh\n");
        assert_ne!(ino(&src.join("sub/data")), ino(&dst.join("sub/data")));
        assert_eq!(std::fs::read(dst.join("sub/data")).unwrap(), b"payload");
        // the executable bit survived — it is part of a path's NAR hash, so
        // dropping it would fail `nix-store --verify --check-contents`
        let mode = std::fs::metadata(dst.join("tool"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111;
        assert_eq!(mode, 0o111, "exec bit dropped");
        // the symlink was recreated as a symlink (never dereferenced), same target
        let meta = std::fs::symlink_metadata(dst.join("link")).unwrap();
        assert!(
            meta.file_type().is_symlink(),
            "link was not recreated as a symlink"
        );
        assert_eq!(
            std::fs::read_link(dst.join("link")).unwrap(),
            PathBuf::from("tool")
        );
    }

    #[test]
    fn seed_path_skips_an_existing_path_and_tops_up_a_missing_one() {
        let base = TmpDir::new();
        let shared = base.join("shared");
        let project = base.join("project");
        std::fs::create_dir_all(&project).unwrap();
        // the shared store holds two paths (each a directory tree, as a store path is)
        std::fs::create_dir_all(shared.join("aaa-old")).unwrap();
        std::fs::write(shared.join("aaa-old/file"), b"shared").unwrap();
        std::fs::create_dir_all(shared.join("bbb-new")).unwrap();
        std::fs::write(shared.join("bbb-new/file"), b"added").unwrap();
        // the project already holds `aaa-old` with content its own nix wrote
        std::fs::create_dir_all(project.join("aaa-old")).unwrap();
        std::fs::write(project.join("aaa-old/file"), b"project-wrote-this").unwrap();
        let pre = ino(&project.join("aaa-old/file"));

        seed_path(&shared, &project, OsStr::new("aaa-old"), true).unwrap();
        seed_path(&shared, &project, OsStr::new("bbb-new"), true).unwrap();

        // the pre-existing path was left untouched (same inode, same content),
        // never overwritten — protecting whatever the project's nix has written
        assert_eq!(
            ino(&project.join("aaa-old/file")),
            pre,
            "an existing store path must not be overwritten"
        );
        assert_eq!(
            std::fs::read(project.join("aaa-old/file")).unwrap(),
            b"project-wrote-this"
        );
        // ...and the missing one was placed in full
        assert!(
            project.join("bbb-new/file").exists(),
            "missing path not topped up"
        );
        assert_eq!(
            std::fs::read(project.join("bbb-new/file")).unwrap(),
            b"added"
        );
        // no temporary placement leaked into the store directory
        let leaked = std::fs::read_dir(&project)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with(".tmp-"));
        assert!(!leaked, "a temporary placement was left behind");
    }

    #[test]
    fn a_seeded_file_is_isolated_so_a_write_cannot_reach_the_source() {
        // The multi-tenant non-negotiable: a write to the project's copy must never
        // reach the shared store. A hard link would violate exactly this, so this is
        // the test that distinguishes the (safe) copy/reflink seed from a hard link.
        // `reflink_ok = true` asks for a copy-on-write clone where available; on this
        // host's ext4 (no reflink) it exercises the full-copy fallback, which is the
        // isolation proven here. A reflink's copy-on-write isolation, where the
        // filesystem supports it, is the kernel's FICLONE guarantee.
        let base = TmpDir::new();
        let shared = base.join("shared");
        let proj = base.join("proj");
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(shared.join("libc"), b"GENUINE").unwrap();
        std::fs::set_permissions(shared.join("libc"), std::fs::Permissions::from_mode(0o444))
            .unwrap();

        place_file(&shared.join("libc"), &proj.join("libc"), true).unwrap();

        // the copy is a distinct inode...
        assert_ne!(ino(&shared.join("libc")), ino(&proj.join("libc")));
        // ...so a same-uid agent removing the read-only mode and overwriting its
        // copy leaves the shared source byte-for-byte unchanged
        std::fs::set_permissions(proj.join("libc"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        std::fs::write(proj.join("libc"), b"TROJAN").unwrap();
        assert_eq!(
            std::fs::read(shared.join("libc")).unwrap(),
            b"GENUINE",
            "a write to the project copy reached the shared source"
        );
    }

    #[test]
    fn place_atomically_treats_a_lost_race_as_success_and_keeps_the_winner() {
        // The concurrency case: another seed of the same project already renamed the
        // identical, content-addressed path into place. Our rename then fails, but the
        // path is present — so this is success, the winner's tree is left untouched,
        // and our now-redundant temp is discarded.
        let base = TmpDir::new();
        // the winner's tree already sits at the real name. A store path is a non-empty
        // directory, so renaming our temp onto it fails (ENOTEMPTY) — exactly the race.
        let dest = base.join("aaa-pkg");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("file"), b"winner").unwrap();
        // our temp copy, ready to be moved in
        let tmp = base.join(".tmp-1-aaa-pkg");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("file"), b"loser").unwrap();

        place_atomically(&tmp, &dest).expect("a lost race is success, not an error");

        assert_eq!(
            std::fs::read(dest.join("file")).unwrap(),
            b"winner",
            "the winner's path was overwritten by the race loser"
        );
        assert!(
            !tmp.exists(),
            "the redundant temp was not discarded after losing the race"
        );
    }

    #[test]
    fn place_atomically_propagates_a_non_race_failure_and_discards_the_temp() {
        // A failure that is *not* a lost race — the destination is still absent — must
        // propagate, and must still leave no temp behind: a partial copy must never
        // accumulate in the store directory.
        let base = TmpDir::new();
        let tmp = base.join(".tmp-1-x");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("file"), b"payload").unwrap();
        // renaming into a parent that does not exist fails (ENOENT) with the
        // destination still absent — the propagating branch, not the race one
        let dest = base.join("missing-parent").join("x");

        place_atomically(&tmp, &dest).expect_err("a non-race failure must propagate");

        assert!(
            !tmp.exists(),
            "the temp was not discarded after a hard placement failure"
        );
    }
}

/// Proving the seed in isolation needs a real nix store, so this is a live smoke
/// that skips (does not fail) where nix is absent. The unit tests above check the
/// copy walk and atomic placement on synthetic trees; only this proves the seed
/// produces an internally consistent, **closure-scoped** nix store: two unrelated
/// packages are realised into a throwaway shared store, only one is seeded as a
/// root, and the result is verified to contain that root's whole closure, to
/// *exclude* the unrelated package, and to pass `nix-store --verify
/// --check-contents` — which holds only if the copied files and the database
/// (registered from the same single closure list) agree. It also proves the base
/// is a physically independent copy (a distinct inode), that the shared store is
/// left byte-identical, and that a re-seed tops up a new root's closure without
/// disturbing a path the project's own nix has written.
///
/// The first test exercises a single-process seed against a quiescent shared store;
/// the second proves two seeds of the same project at once converge to a consistent,
/// *fully registered* store — concurrent `--load-db` merges serialising on the project
/// database's SQLite locking. A seed running while another process provisions into the
/// *shared* store, and a seed racing a live in-cage build into the *same* project store,
/// rest on nix's own concurrent store-access guarantee (that database locking plus the
/// per-store-path `.lock` files a build takes) and are not separately exercised here.
#[cfg(test)]
mod smoke {
    use super::*;
    use crate::store::{self, Layout, LockTarget};
    use crate::testutil::TmpDir;
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;

    /// `(nix, nix-store)` when both are present; otherwise `None` to skip.
    fn prerequisites() -> Option<(PathBuf, PathBuf)> {
        Some((store::resolve_nix()?, store::resolve_nix_store()?))
    }

    fn ino(path: &Path) -> (u64, u64) {
        let m = std::fs::symlink_metadata(path).unwrap();
        (m.dev(), m.ino())
    }

    /// A sorted `(relative path, size)` fingerprint of a tree — sensitive to any
    /// addition, removal, or size change, enough to assert the shared store never
    /// moved under the seed.
    fn fingerprint(root: &Path) -> Vec<(PathBuf, u64)> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(meta) = path.symlink_metadata() else {
                    continue;
                };
                let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
                if meta.is_dir() {
                    out.push((rel, 0));
                    stack.push(path);
                } else {
                    out.push((rel, meta.len()));
                }
            }
        }
        out.sort();
        out
    }

    /// Whether a store path named like `<hash>-<name>` is present in the project
    /// store's `nix/store`.
    fn present(store_dir: &Path, logical: &Path) -> bool {
        let name = logical.file_name().unwrap();
        store_dir.join("nix").join("store").join(name).exists()
    }

    #[test]
    fn seed_is_closure_scoped_consistent_isolated_and_tops_up() {
        let Some((nix, nix_store)) = prerequisites() else {
            eprintln!("skipping projectstore smoke: need nix and nix-store");
            return;
        };

        // a throwaway shared store with two unrelated real packages realised into it
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let nixpkgs = LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .expect("resolve nixpkgs");
        let realise = |attr: &str, marker: &str, name: &str| {
            store::provision(
                &nix,
                &layout,
                &data.path().join("roots").join(name),
                &nixpkgs,
                attr,
                marker,
            )
            .unwrap_or_else(|e| panic!("provision {attr}: {e}"))
        };
        let hello = realise("hello", "bin/hello", "hello");
        let jq = realise("jq", "bin/jq", "jq");

        let shared_store = layout.store_dir();
        // The immutability that matters is the *content paths*: a base path another
        // tenant sees must never change. The registration database under `nix/var`
        // is excluded on purpose — `nix-store --dump-db` checkpoints the shared
        // database's write-ahead log (folding it into the main file), which every
        // read of the shared store does and which leaves the logical contents
        // unchanged; it is not a mutation of any store path.
        let shared_paths = shared_store.join("nix").join("store");
        let before = fingerprint(&shared_paths);

        // seed only `hello` as a root — `jq` is in the shared store but not in the
        // requested closure
        let project = prepare(&nix_store, &layout, "smoke", std::slice::from_ref(&hello))
            .expect("seed the project store");

        // the seeded store is internally consistent: every registered path's files
        // exist and hash as recorded — true only if the copied files and the
        // database (both from the one closure list) agree
        let verify = |label: &str| {
            let out = Command::new(&nix_store)
                .env("NIX_REMOTE", "")
                .arg("--store")
                .arg(project.store_dir())
                .args(["--verify", "--check-contents"])
                .output()
                .expect("spawn nix-store --verify");
            assert!(
                out.status.success(),
                "the seeded store failed verification ({label}): {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        verify("after first seed");

        // closure-scoped: hello and its whole closure are present, and the
        // unrelated jq — present in the shared store — was NOT dragged in
        assert!(
            present(project.store_dir(), &hello),
            "the seeded root is absent"
        );
        for dep in closure_of(&nix_store, &shared_store, std::slice::from_ref(&hello)).unwrap() {
            assert!(
                present(project.store_dir(), &dep),
                "a closure path of the root is missing: {}",
                dep.display()
            );
        }
        assert!(
            !present(project.store_dir(), &jq),
            "an unrelated shared-store path leaked into the project store — the seed is not closure-scoped"
        );

        // a base file is a physically independent copy: a distinct inode from the
        // shared store, so an in-cage write to it can never reach the shared base
        let logical_rel = hello.strip_prefix("/").unwrap();
        let shared_hello = store::physical_path(&layout, &hello).join("bin/hello");
        let project_hello = project.store_dir().join(logical_rel).join("bin/hello");
        let hello_ino = ino(&project_hello);
        assert_ne!(
            ino(&shared_hello),
            hello_ino,
            "the base binary shares the shared store's inode — a write would reach it"
        );

        // simulate a path the project's own nix has written into its store: a
        // re-seed must leave it untouched
        let agent_path = project
            .store_dir()
            .join("nix")
            .join("store")
            .join("zzzz-agent-built");
        std::fs::create_dir_all(&agent_path).unwrap();
        std::fs::write(agent_path.join("marker"), b"agent").unwrap();

        // re-seed with jq added as a root: a top-up brings jq's closure in, leaves
        // the already-seeded hello in place (same inode, not recopied), and does not
        // disturb the agent-written path
        let project = prepare(&nix_store, &layout, "smoke", &[hello.clone(), jq.clone()])
            .expect("re-seed the project store");
        verify("after top-up");
        assert!(
            present(project.store_dir(), &jq),
            "the top-up did not bring jq in"
        );
        assert_eq!(
            ino(&project_hello),
            hello_ino,
            "an already-seeded path was recopied instead of skipped"
        );
        assert_eq!(
            std::fs::read(agent_path.join("marker")).unwrap(),
            b"agent",
            "the re-seed disturbed a path the project's own nix wrote"
        );

        // the shared store's content paths are byte-identical: no path was added,
        // removed, or resized — the seed only ever read them
        assert_eq!(
            before,
            fingerprint(&shared_paths),
            "the shared store's paths changed under seeding"
        );
    }

    #[test]
    fn concurrent_same_project_seeds_converge_to_a_consistent_registered_store() {
        use std::collections::BTreeSet;
        let Some((nix, nix_store)) = prerequisites() else {
            eprintln!("skipping concurrent-seed smoke: need nix and nix-store");
            return;
        };

        // a throwaway shared store with one real package realised into it
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let nixpkgs = LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .expect("resolve nixpkgs");
        let hello = store::provision(
            &nix,
            &layout,
            &data.path().join("roots").join("hello"),
            &nixpkgs,
            "hello",
            "bin/hello",
        )
        .expect("provision hello");

        let shared_store = layout.store_dir();
        let shared_paths = shared_store.join("nix").join("store");
        let before = fingerprint(&shared_paths);

        // Several threads seed the SAME project from the SAME roots at once, into a
        // FRESH project store — so every thread races on first-creating the project's
        // database (the sharp interleave this settles; a top-up race is benign). All
        // must succeed: a lost rename is success (the path is present), and concurrent
        // `--load-db` merges serialise on the project store's own nix lock.
        let roots = std::slice::from_ref(&hello);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| scope.spawn(|| prepare(&nix_store, &layout, "concurrent", roots)))
                .collect();
            for handle in handles {
                handle
                    .join()
                    .expect("a concurrent seed thread panicked")
                    .expect("a concurrent seed failed");
            }
        });
        let store_dir = store_dir_for(&layout, "concurrent");

        // TEETH on registration, not just the on-disk copy. A bad concurrent merge
        // manifests as a path copied but never *registered* (or registered with a
        // dangling reference) — which `--verify` cannot flag (it iterates only
        // registered paths) and a file-existence check cannot see. Querying the project
        // database's reference graph returns the whole closure only if every path
        // registered with intact references, so assert it equals the shared store's.
        let in_project: BTreeSet<PathBuf> = closure_of(&nix_store, &store_dir, roots)
            .expect("query the project store's closure")
            .into_iter()
            .collect();
        let in_shared: BTreeSet<PathBuf> = closure_of(&nix_store, &shared_store, roots)
            .expect("query the shared store's closure")
            .into_iter()
            .collect();
        assert_eq!(
            in_project, in_shared,
            "the concurrently-seeded project database is missing registrations from the closure"
        );

        // and it passes full content verification: every registered path's files exist
        // and hash as recorded
        let verify = Command::new(&nix_store)
            .env("NIX_REMOTE", "")
            .arg("--store")
            .arg(&store_dir)
            .args(["--verify", "--check-contents"])
            .output()
            .expect("spawn nix-store --verify");
        assert!(
            verify.status.success(),
            "the concurrently-seeded store failed verification: {}",
            String::from_utf8_lossy(&verify.stderr)
        );

        // no temporary placement leaked into the project store under the race
        let leaked = std::fs::read_dir(store_dir.join("nix").join("store"))
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with(".tmp-"));
        assert!(
            !leaked,
            "a temporary placement was left behind under concurrent seeding"
        );

        // the shared store's content paths are byte-identical — every seed only read it
        assert_eq!(
            before,
            fingerprint(&shared_paths),
            "the shared store's paths changed under concurrent seeding"
        );
    }
}
