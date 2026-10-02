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
//! The seed writes into a tree a cage holds read-write: another launch of the same
//! project may be running while this one seeds. So every write below `nix/` goes
//! through a descriptor for the directory the walk checked, never through a path
//! re-resolved at the write, and every entry is created exclusively, so a link the
//! cage planted fails the seed instead of being written through (see
//! [`hold_dir_chain`]). `nix-store` opens the same tree by name, so every run of it on
//! the tree is in a cage of its own, where a link in the tree reaches nothing of the
//! host's and nix and SQLite read the database the project's cage wrote with nothing
//! else of the host's in reach: the registration every seed runs ([`load_cage`]), and
//! `sbx gc`'s collection and deduplication ([`HeldStore`]). The collection searches the
//! store's roots, and some lead out of it (`gcroots/auto`, the `result` links a build in
//! the cage leaves in the project): what nix asks of the host about those is answered on
//! the host and staged in its cage ([`collection_standins`]). The project itself is not
//! mounted there, since its cage sees it through masks this one would not apply.
//!
//! The cage's nix reads and writes only this self-contained store; sbx's own seed
//! is the only reader of the shared store, and only ever reads its content paths
//! (which stay byte-identical) — though `nix-store --dump-db` may checkpoint the
//! shared database's write-ahead log, a benign fold-in that mutates no store path.
//!
//! Concurrency needs no lock of sbx's own. Two sandboxes of the same project can
//! seed at once: each path is placed by atomic rename, so a lost race is just a
//! redundant copy discarded — the winner's identical, content-addressed path is
//! already in place — and the database registration goes through `nix-store
//! --load-db`, whose concurrent merges serialise on the project database's own
//! SQLite locking (and a lost lock race under heavy parallel load is retried, the
//! merge being idempotent — so this needs no lock of sbx's own here either). The
//! broader case — a seed racing a live in-cage `nix build`, or
//! two agents building into one project store — rests on nix's own concurrent
//! store-access guarantee (that database locking plus the per-store-path `.lock`
//! files a build takes); it is nix's domain, not sbx's, and is not exercised here.
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
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Owner-only mode for the directories the seed creates while it fills them, and the
/// mode sbx's own runtime-tree directories keep for good. A store path's directories
/// are read-only (`0555`) in the shared store, and a copy created at that mode could
/// take no entry, so [`copy_recursive`] creates each one writable and restores the
/// source's mode once it is full: a placed store path ends up mode-identical to the
/// one it was copied from.
///
/// A path's content hash does not cover directory modes, so neither the mode a
/// directory is built at nor the one it is sealed to affects `nix-store --verify`;
/// the copied *files* keep their own modes ([`place_file`] sets each to its source's,
/// cloned or copied).
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

/// What [`prepare`] runs nix with: `nix_store`, run on the host against the shared store, and the
/// cage the registration into the project's store runs in, started by `bwrap` in the launch's
/// resource scope (`limits`, under the name `slug`).
pub(crate) struct Engine<'a> {
    pub(crate) nix_store: &'a Path,
    pub(crate) bwrap: &'a Path,
    pub(crate) limits: &'a super::cgroup::Limits,
    pub(crate) slug: &'a str,
}

#[cfg(test)]
impl<'a> Engine<'a> {
    /// The engine a test seeds with: no limit of a configuration's own, under a test's name.
    pub(crate) fn for_tests(nix_store: &'a Path, bwrap: &'a Path) -> Self {
        static NO_OVERRIDE: super::cgroup::Limits = super::cgroup::Limits {
            memory_high: None,
            memory_max: None,
            tasks_max: None,
        };
        Self {
            nix_store,
            bwrap,
            limits: &NO_OVERRIDE,
            slug: "sbx-test",
        }
    }
}

/// The marker file recording a project's canonical path, beside its store under the runtime tree.
/// The id keying the tree is a one-way hash of that path, so this is what lets housekeeping
/// recognise a tree and reclaim it once the project directory is gone.
pub(crate) const PROJECT_MARKER: &str = "project";

/// A project's runtime tree directory, `<data>/projects/<id>` — the parent of its store, home,
/// synthetic identity, and locks. The single place that path is named, shared by the seed (which
/// records the marker) and by housekeeping (which reads it).
pub(crate) fn project_dir(layout: &Layout, project_id: &str) -> PathBuf {
    layout.data_dir().join("projects").join(project_id)
}

/// The per-project store directory for `project_id`, keyed on the same identity as
/// the rest of the project's runtime (home, synthetic identity, gcroots), so
/// housekeeping can reclaim it alongside them.
pub(crate) fn store_dir_for(layout: &Layout, project_id: &str) -> PathBuf {
    project_dir(layout, project_id).join("store")
}

/// Whether `project_id` already has a seeded store on disk. A project that was never launched has
/// none, so there is nothing to garbage-collect — and seeding one just to sweep it would be a heavy
/// (possibly networked) side effect, which is what lets `sbx gc` skip a never-launched directory
/// rather than materialise a store for it.
pub(crate) fn store_exists(layout: &Layout, project_id: &str) -> bool {
    store_dir_for(layout, project_id).exists()
}

/// An advisory lock serialising sbx's reads of the **shared** store against the shared-store
/// garbage collector. The seed below copies store paths out of the shared store *directly* — not
/// as a nix process — so nothing in nix stops a concurrent `nix-store --gc <shared>` from deleting
/// a path mid-copy and corrupting the project store it lands in. The seeder holds this **shared**
/// (so concurrent seeds never block each other); the collector holds it **exclusive** around the
/// whole `nix-store --gc`. Both sides call the same `flock`, so they serialise regardless of which
/// primitive nix uses internally (`flock` and POSIX `fcntl` locks occupy separate lock spaces and
/// do not interoperate). Dropping the guard closes the fd, releasing the lock.
pub(crate) struct SharedGcLock(
    // Held only for its `Drop`: closing the fd is what releases the `flock`. Never read.
    #[allow(dead_code)] std::fs::File,
);

/// The shared-store gc lock file — a top-level sibling of `store/`, `projects/`, and `gcroots/`, so
/// neither the dead-tree reaper nor the gcroot prune ever walks it.
fn shared_gc_lock_path(layout: &Layout) -> PathBuf {
    layout.data_dir().join("store-gc.lock")
}

fn acquire_shared_gc_lock(layout: &Layout, exclusive: bool) -> io::Result<SharedGcLock> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let path = shared_gc_lock_path(layout);
    if let Some(parent) = path.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)?;
    let op = if exclusive {
        libc::LOCK_EX
    } else {
        libc::LOCK_SH
    };
    // SAFETY: `flock` on a valid owned fd; it blocks until the lock is granted and returns 0 on
    // success. The fd lives in the returned guard, so the lock is held until the guard drops.
    if unsafe { libc::flock(file.as_raw_fd(), op) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(SharedGcLock(file))
}

/// Take the shared-store gc lock **shared** — for a seed's read of the shared store. Many seeds may
/// hold it at once; only the exclusive collector blocks them.
pub(crate) fn lock_shared(layout: &Layout) -> io::Result<SharedGcLock> {
    acquire_shared_gc_lock(layout, false)
}

/// Take the shared-store gc lock **exclusive** — for the shared-store collector, around the whole
/// gcroot prune and `nix-store --gc`. Blocks until every in-flight seed has released its shared
/// hold, and blocks new seeds until the collection finishes.
pub(crate) fn lock_exclusive(layout: &Layout) -> io::Result<SharedGcLock> {
    acquire_shared_gc_lock(layout, true)
}

/// Record the project's canonical path in a durable marker beside its store, so a later `sbx gc`
/// can recognise this tree (`<id>` alone is a one-way hash) and reclaim it once the project
/// directory is gone. Atomic (temp + rename) and owner-only; overwritten each launch — the path is
/// stable, so the write is idempotent. The path is stored as raw bytes, no newline, so even a
/// non-UTF-8 path round-trips exactly.
pub(crate) fn write_marker(layout: &Layout, project_id: &str, canonical: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let dir = project_dir(layout, project_id);
    DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(&dir)?;
    let marker = dir.join(PROJECT_MARKER);
    let tmp = dir.join(format!(".{PROJECT_MARKER}.tmp-{}", unique()));
    let _ = fs::remove_file(&tmp);
    fs::write(&tmp, canonical.as_os_str().as_bytes())?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    match fs::rename(&tmp, &marker) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
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
    engine: &Engine<'_>,
    layout: &Layout,
    project_id: &str,
    roots: &[PathBuf],
) -> io::Result<ProjectStore> {
    let store_dir = store_dir_for(layout, project_id);
    // Component-wise rather than `create_dir_all`, and held: everything under `store_dir/nix` is
    // bound read-write into the cage, so a component may be a symlink the cage left pointing
    // anywhere, or one it swaps in while this seed runs. See [`hold_dir_chain`]; the seed below
    // copies the whole base closure into this directory.
    let project_paths = hold_dir_chain(&store_dir, "store")?;
    // Before the first `nix-store` run, and before the early return below: `sbx gc` runs its own
    // `nix-store` calls on this store once this returns, so the check covers those too.
    ensure_nix_state(&store_dir)?;

    // Enumerate the closure to copy and register. Passing no roots would make
    // `--dump-db` dump the *whole* shared database, so an empty request seeds
    // nothing rather than silently widening to everything.
    if roots.is_empty() {
        return Ok(ProjectStore { store_dir });
    }

    // Serialise this whole read of the shared store against the shared-store collector. The copy
    // below reads store paths directly (not as a nix process), so without this a concurrent
    // `nix-store --gc <shared>` could delete a path between the closure query and the copy — or
    // mid-copy — and leave this store with paths registered but truncated. Held shared, so
    // concurrent same-project (and cross-project) seeds never block each other; only the exclusive
    // collector does. Released when `_shared` drops at the end of this function.
    let _shared = lock_shared(layout)?;
    let shared_store = layout.store_dir();
    let closure = closure_of(engine.nix_store, &shared_store, roots)?;

    // Probe once whether the project store's filesystem supports reflinks, rather
    // than attempting (and failing) a clone per file on a filesystem without them.
    let reflink_ok = supports_reflink(&project_paths);

    // Place each closure path: <shared>/nix/store/<p> -> <project>/nix/store/<p>,
    // each as a physically independent copy so an in-cage write cannot reach the
    // shared base, and atomically so a crash or a concurrent seed never leaves a
    // partial at a real store-path name.
    let shared_paths = shared_store.join("nix").join("store");
    let mut all_cloned = reflink_ok;
    for path in &closure {
        let Some(name) = path.file_name() else {
            continue;
        };
        all_cloned &= seed_path(&shared_paths, &project_paths, name, reflink_ok)?;
    }
    record_seed_mode(&store_dir, all_cloned)?;

    // Register exactly that closure in the project store's own database, through the `nix/` this
    // holds rather than its path, for the registration's cage to bind ([`load_cage`]).
    let nix_dir = super::cagedir::hold_under(&store_dir, "nix", DIR_MODE)?;
    load_db(engine, &shared_store, &store_dir, &nix_dir, &closure)?;

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

/// Place one store path `name` from `shared_paths` into the store directory
/// `project_paths` holds, as a physically independent, atomically-placed copy. A path
/// already present is left untouched (top-up only); otherwise it is copied into a unique
/// temporary sibling and moved into place by [`place_atomically`], so a half-written tree
/// only ever exists under the temporary name and a crash or a racing seed cannot leave a
/// partial at the real store-path name.
///
/// Returns whether every file placed was cloned rather than copied ([`place_file`]); a path
/// already present places nothing, and answers `true`.
fn seed_path(
    shared_paths: &Path,
    project_paths: &OwnedFd,
    name: &OsStr,
    reflink_ok: bool,
) -> io::Result<bool> {
    if super::cagedir::entry(project_paths, name)?
        .symlink_metadata()
        .is_ok()
    {
        return Ok(true);
    }
    let mut tmp = std::ffi::OsString::from(format!(".tmp-{}-", unique()));
    tmp.push(name);
    copy_into_place(
        &shared_paths.join(name),
        project_paths,
        name,
        &tmp,
        reflink_ok,
    )
}

/// Copy `src` into the entry `dest` of the directory `dir` holds, via the temporary sibling `tmp`,
/// atomically. Any stale `tmp` a crashed seed left behind is cleared first: `unique()` is
/// process-local, so two processes reuse temp names, and a leftover store-path temp is a
/// *directory tree*. So it goes through the recursive `discard` (a no-op when absent), or
/// `copy_recursive`'s exclusive `mkdir` would fail EEXIST.
fn copy_into_place(
    src: &Path,
    dir: &OwnedFd,
    dest: &OsStr,
    tmp: &OsStr,
    reflink_ok: bool,
) -> io::Result<bool> {
    discard(dir, tmp);
    let cloned = copy_recursive(src, dir, tmp, reflink_ok)?;
    place_atomically(dir, tmp, dest)?;
    Ok(cloned)
}

/// Move the fully-copied `tmp` tree into place at its real store-path name `dest`, both entries of
/// the directory `dir` holds, by `rename`: atomic, so a reader only ever sees the complete tree or
/// nothing at the real name. Losing a race is success: if the rename fails but `dest` now exists,
/// another seed of the same project placed the identical, content-addressed path first, so the
/// now-redundant temp is discarded and success reported. Any other failure discards the temp and
/// propagates, leaving no partial behind.
fn place_atomically(dir: &OwnedFd, tmp: &OsStr, dest: &OsStr) -> io::Result<()> {
    let at = super::cagedir::entry(dir, dest)?;
    match fs::rename(super::cagedir::entry(dir, tmp)?, &at) {
        Ok(()) => Ok(()),
        Err(_) if at.symlink_metadata().is_ok() => {
            discard(dir, tmp);
            Ok(())
        }
        Err(e) => {
            discard(dir, tmp);
            Err(e)
        }
    }
}

/// Recursively copy `from` to a fresh entry `name` of the directory `dir` holds: directories are
/// created owner-writable, filled through their own descriptor, then sealed to the mode of the
/// directory they were copied from; symlinks are recreated (never dereferenced); and regular files
/// are copied as physically independent copies ([`place_file`]). The entry must not exist yet: the
/// caller copies into a unique temporary, and in this tree an entry already at a name is one the
/// cage made, so it fails the copy rather than being written through.
///
/// Sealing is what gives a seeded path the shape nix gives its own (`0555`), so a stray
/// recursive delete meets the same refusal in a project's store as in the shared one,
/// and the two copies of a path differ in no attribute a walk can read. It is **not** a
/// boundary against the cage: the cage runs as the uid that owns these paths, and an
/// owner may `chmod` what it owns. What protects the shared store is that the cage never
/// holds it — the copy is physically independent ([`place_file`]) — never a mode.
///
/// Returns whether every regular file under `from` was cloned rather than copied.
fn copy_recursive(from: &Path, dir: &OwnedFd, name: &OsStr, reflink_ok: bool) -> io::Result<bool> {
    // `symlink_metadata` does not follow symlinks, so a store symlink is recreated
    // rather than dereferenced.
    let meta = from.symlink_metadata()?;
    let file_type = meta.file_type();
    let to = super::cagedir::entry(dir, name)?;
    if file_type.is_dir() {
        DirBuilder::new()
            .mode(DIR_MODE)
            .create(&to)
            .map_err(|e| already_there(dir, name, e))?;
        // Opened, never re-entered by name: a link swapped in after the `mkdir` fails this open,
        // by its path, and what is placed below goes into the directory it reached.
        let made = super::cagedir::open_entry_dir(dir, name)?;
        let mut cloned = true;
        for entry in fs::read_dir(from)? {
            let entry = entry?;
            cloned &= copy_recursive(&entry.path(), &made, &entry.file_name(), reflink_ok)?;
        }
        // After the entries, never before: a directory sealed read-only takes none. Through the
        // descriptor, so the mode lands on the directory that was filled.
        fs::File::from(made).set_permissions(meta.permissions())?;
        Ok(cloned)
    } else if file_type.is_symlink() {
        std::os::unix::fs::symlink(fs::read_link(from)?, &to)
            .map_err(|e| already_there(dir, name, e))?;
        Ok(true)
    } else {
        place_file(from, dir, name, reflink_ok)
    }
}

/// `e`, or, when it says the entry `name` of the directory `dir` holds was already there, the
/// error that names that entry by the path the user finds it at ([`super::cagedir::shown`]).
///
/// The copy creates every entry exclusively, and the kernel's answer, `File exists`, names
/// nothing. Below the temporary directory a copy starts with, an entry already there is one
/// something else made after that directory was, and a cage of the project writes this tree. At
/// that directory itself it may also be a leftover [`discard`] could not remove, so the error says
/// what is known: the entry was there, nothing was written through it, and it was left alone.
fn already_there(dir: &OwnedFd, name: &OsStr, e: io::Error) -> io::Error {
    if e.kind() != io::ErrorKind::AlreadyExists {
        return e;
    }
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "`{}` already exists where the seed creates a new entry, and nothing was written \
             through it. This tree is writable by a cage of this project, so the entry is left in \
             place for you to see",
            super::cagedir::shown(dir, name).display()
        ),
    )
}

/// Place one regular file at the entry `name` of the directory `dir` holds, as a physically
/// independent copy of `from`, so a later in-cage write to it can never reach `from` (the shared
/// store). When `reflink_ok`, it is cloned copy-on-write: the two share data extents until one is
/// written, then only the changed extent is copied, leaving `from` untouched, so the clone costs
/// no extra disk until a write. Otherwise (a filesystem without reflink, e.g. ext4) it is a full
/// content copy. Either way the result is a distinct inode with `from`'s mode.
///
/// The file is created exclusively (`O_CREAT | O_EXCL`), which fails on any entry already at that
/// name, a link included, instead of opening what the link names. This tree is the cage's, and a
/// create that followed a link the cage planted there would truncate and rewrite whatever file of
/// the user's it pointed at.
///
/// Returns `true` when the file was cloned, `false` when it was copied: a clone that fails on a
/// filesystem that supports them falls back to the copy, and the seed records that it did.
fn place_file(from: &Path, dir: &OwnedFd, name: &OsStr, reflink_ok: bool) -> io::Result<bool> {
    let mut src = fs::File::open(from)?;
    let mode = src.metadata()?.permissions();
    let mut dst = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(super::cagedir::entry(dir, name)?)
        .map_err(|e| already_there(dir, name, e))?;
    let cloned = reflink_ok && clone_into(&src, &dst).is_ok();
    if !cloned {
        // Whatever a failed clone left is cut first; a plain copy is independent on every
        // filesystem.
        dst.set_len(0)?;
        io::copy(&mut src, &mut dst)?;
    }
    dst.set_permissions(mode)?;
    Ok(cloned)
}

/// The file under a project's store directory that records how its store paths were seeded,
/// kept outside `store/nix`, the one part of the store bound into the cage, so nothing in the cage
/// writes it.
const SEED_MODE: &str = "seeded-by";

/// How the store paths of the project tree at `tree_dir` were seeded: `Some(true)` when every file
/// was cloned from the shared store, `Some(false)` when any was copied, `None` for a tree with no
/// record (seeded before one was kept, or never seeded).
///
/// Read by the figure for what removing the tree gives back (`gc::Reclaim`), which turns on
/// exactly this: a cloned store shares its data with the shared one and returns none of it, a
/// copied one returns all of it. Recorded where the answer is known, so a reading command need not
/// probe the filesystem to guess it.
pub(crate) fn seed_mode(tree_dir: &Path) -> Option<bool> {
    match fs::read_to_string(tree_dir.join("store").join(SEED_MODE))
        .ok()?
        .trim()
    {
        "reflink" => Some(true),
        "copy" => Some(false),
        _ => None,
    }
}

/// Record how this seed placed its paths, once any copy has made the store a mix: a store that ever
/// took a copied file stays recorded as copied, since those bytes are its own whatever later seeds
/// clone. Written only when the record changes, so a launch that seeds nothing new writes nothing.
fn record_seed_mode(store_dir: &Path, all_cloned: bool) -> io::Result<()> {
    let path = store_dir.join(SEED_MODE);
    let before = fs::read_to_string(&path).ok();
    let now = match before.as_deref().map(str::trim) {
        Some("copy") => "copy",
        _ if all_cloned => "reflink",
        _ => "copy",
    };
    if before.as_deref().map(str::trim) == Some(now) {
        return Ok(());
    }
    super::atomicfile::write_atomic(&path, format!("{now}\n").as_bytes())
}

/// Clone `src`'s contents into `dst` copy-on-write, via the `FICLONE` ioctl (contents
/// only: the mode is the caller's to set). Fails when the filesystem does not support
/// reflinks, so the caller can fall back to a plain copy.
fn clone_into(src: &fs::File, dst: &fs::File) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: both descriptors are valid for the call; FICLONE reads from `src` and
    // replaces `dst`'s contents, touching no Rust-owned memory.
    let rc = unsafe { libc::ioctl(dst.as_raw_fd(), libc::FICLONE, src.as_raw_fd()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether the filesystem of the directory `dir` holds supports reflinks, probed with a
/// throwaway clone (both files on the same filesystem as the seed's destination). A probe
/// that could not be carried out counts as "no", which is what a caller about to copy
/// needs: it cannot reflink into a directory it cannot write to either. A caller that
/// must tell the two apart wants [`reflink_verdict`].
fn supports_reflink(dir: &OwnedFd) -> bool {
    let (src, dst) = probe_names();
    match (
        super::cagedir::entry(dir, &src),
        super::cagedir::entry(dir, &dst),
    ) {
        (Ok(src), Ok(dst)) => probe_reflink(&src, &dst) == Some(true),
        _ => false,
    }
}

/// Whether `dir`'s filesystem supports reflinks, or `None` when the probe could not be
/// carried out at all — the directory is not writable, so nothing was learned about the
/// filesystem.
pub(crate) fn reflink_verdict(dir: &Path) -> Option<bool> {
    let (src, dst) = probe_names();
    probe_reflink(&dir.join(src), &dir.join(dst))
}

/// The two names a reflink probe writes, unique per call (pid + counter) so a concurrent
/// same-project seed never collides on them.
fn probe_names() -> (std::ffi::OsString, std::ffi::OsString) {
    (
        format!(".reflink-probe-src-{}", unique()).into(),
        format!(".reflink-probe-dst-{}", unique()).into(),
    )
}

/// The probe behind [`supports_reflink`] and [`reflink_verdict`]: write `src`, clone it into
/// `dst`, and remove both before returning. Only the write's failure is inconclusive: once the
/// source exists, the clone's outcome is the filesystem's answer.
///
/// Both files are created exclusively, so an entry already at either name, a link included, is
/// never opened through. One a crashed probe of an earlier process left there (the counter is
/// process-local) is removed first, which unlinks the entry itself and never what it names.
fn probe_reflink(src: &Path, dst: &Path) -> Option<bool> {
    use std::io::Write as _;
    let _ = fs::remove_file(src);
    let _ = fs::remove_file(dst);
    let exclusive = |write_only: bool| {
        let mut options = fs::OpenOptions::new();
        options.read(!write_only).write(true).create_new(true);
        options
    };
    let verdict = exclusive(false)
        .open(src)
        .and_then(|mut f| f.write_all(b"probe").map(|()| f))
        .ok()
        .map(|from| {
            exclusive(true)
                .open(dst)
                .is_ok_and(|to| clone_into(&from, &to).is_ok())
        });
    let _ = fs::remove_file(src);
    let _ = fs::remove_file(dst);
    verdict
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

/// Remove the temporary placement `name` from the directory `dir` holds, whether it ended up a
/// directory tree or a single file or symlink. Goes through [`super::gc::remove_child`], which
/// removes by descriptor at every depth, unlinks a link rather than following it, and adds write
/// to each directory as it descends: a temp [`copy_recursive`] finished is sealed read-only like
/// the store path it is about to become, and a plain `remove_dir_all` cannot empty such a
/// directory. Best effort, since a leftover only wastes disk and never corrupts the store (it never
/// carries a real store-path name), but a leftover that survived *would* fail the next seed of
/// that path, whose exclusive `mkdir` meets it as `EEXIST`.
fn discard(dir: &OwnedFd, name: &OsStr) {
    let _ = super::gc::remove_child(dir, name);
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
///
/// The two halves run apart. The dump reads the shared store, which no cage writes, on the host.
/// The load opens the project's store, which a cage of the project writes at will and may be
/// rewriting while this runs, so it runs in a cage of its own ([`load_cage`]) over `nix_dir`, the
/// project's `nix/` as [`prepare`] holds it: a link planted anywhere in that tree leads into the
/// load's cage, never to a file of the user's.
fn load_db(
    engine: &Engine<'_>,
    shared_store: &Path,
    store_dir: &Path,
    nix_dir: &OwnedFd,
    closure: &[PathBuf],
) -> io::Result<()> {
    retry_load(store_dir, || {
        load_db_once(engine, shared_store, nix_dir, closure)
    })
}

/// [`load_db`]'s attempts at the registration into `store_dir`, each made by `attempt`.
///
/// A failed attempt is followed by [`ensure_nix_state`] again. A cage of the project running while
/// the seed ran can replace a name the first check passed, and nix then fails on it inside the
/// registration's cage, naming it as that cage sees it. The second check names it on the host and
/// refuses the store, and its refusal is not retried. A failure the check does not explain keeps
/// nix's reason.
fn retry_load(store_dir: &Path, mut attempt: impl FnMut() -> io::Result<()>) -> io::Result<()> {
    // Retry a lost lock race. Several sandboxes of the same project can seed at once, and the
    // `--load-db` merge serialises on the project database's own lock (SQLite); under heavy
    // parallel load one attempt can exhaust nix's internal busy timeout and exit with the database
    // locked. The predicate deliberately retries ANY `--load-db`-half failure, not only a
    // recognized "locked" message — matching nix's exact lock wording would be fragile, and the
    // merge is idempotent (re-loading the same closure re-registers already-present paths as a
    // no-op), so a bounded retry is harmless even for a non-lock error: a genuinely broken seed (a
    // malformed dump) simply exhausts the small attempt budget and then fails, its captured reason
    // surfaced. The `--load-db` marker only distinguishes the load half from the dump half, and the
    // kind keeps a refusal out of the retries whatever its words.
    retry_transient(
        LOAD_DB_ATTEMPTS,
        || attempt().map_err(|e| refused_since(store_dir, e)),
        |e| e.kind() == io::ErrorKind::Other && e.to_string().contains("--load-db"),
    )
}

/// `failed`, or the refusal [`ensure_nix_state`] now makes of `store_dir`, when it makes one. Only a
/// refusal replaces `failed`: an error the check meets on its way is not the registration's reason.
fn refused_since(store_dir: &Path, failed: io::Error) -> io::Error {
    match ensure_nix_state(store_dir) {
        Err(refusal) if refusal.kind() == io::ErrorKind::InvalidData => refusal,
        _ => failed,
    }
}

/// How many times [`load_db`] attempts the registration merge before giving up. Small: a lost lock
/// race clears in well under a second, and a deterministic failure exhausts the budget promptly.
const LOAD_DB_ATTEMPTS: u32 = 6;

/// One `--dump-db | --load-db` registration pass (see [`load_db`], which retries this on a lost
/// lock race). The `--load-db` half's stderr is captured so a failure carries nix's reason (a
/// locked database vs. a real error) — surfaced to the caller after the retry budget is spent.
fn load_db_once(
    engine: &Engine<'_>,
    shared_store: &Path,
    nix_dir: &OwnedFd,
    closure: &[PathBuf],
) -> io::Result<()> {
    use std::process::{Command, Stdio};
    let mut dump = Command::new(engine.nix_store)
        .env("NIX_REMOTE", "")
        .arg("--store")
        .arg(shared_store)
        .arg("--dump-db")
        .args(closure)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    #[expect(
        clippy::expect_used,
        reason = "the child was spawned with `stdout(Stdio::piped())` three lines above and \
                  nothing takes the handle first"
    )]
    let dump_out = dump.stdout.take().expect("stdout was requested as a pipe");
    // The reader child consumes the pipe directly, so a large dump never blocks on
    // a full pipe buffer; reap the writer only once the reader has finished.
    let load = load_command(engine, nix_dir)?
        .stdin(Stdio::from(dump_out))
        .stderr(Stdio::piped())
        .output()?;
    let dump_status = dump.wait()?;
    // Attribute the failure to the LOAD half first, with its captured stderr — it is the consumer,
    // and every real failure is best explained by its reason: a lock loss makes `load` exit
    // non-zero after draining (dump exits 0), and a `load` that dies *early* makes `dump` then hit
    // EPIPE and also fail — checking dump first there would misattribute the death to dump and
    // discard load's captured root cause. A bare dump failure is reported only when load itself did
    // not fail, which for a truncated/failed dump is effectively never; retrying it (the message
    // still names `--load-db`) is bounded and harmless.
    if !load.status.success() {
        let reason = String::from_utf8_lossy(&load.stderr);
        let reason = reason.trim();
        return Err(io::Error::other(if reason.is_empty() {
            "nix-store --load-db failed".to_string()
        } else {
            format!(
                "nix-store --load-db failed (it sees the project's store at `{LOAD_ROOT}`): \
                 {reason}"
            )
        }));
    }
    if !dump_status.success() {
        return Err(io::Error::other("nix-store --dump-db failed"));
    }
    Ok(())
}

/// Where the registration's cage sees the project's store: the `--store` it names, with the
/// project's `nix/` bound below it.
const LOAD_ROOT: &str = "/project";

/// Where the registration's cage sees `nix-store`. nix is one binary that acts on the name it was
/// started under, so the destination keeps that name.
const LOAD_ENGINE: &str = "/bin/nix-store";

/// The registration's `nix-store --load-db` ready to start: the cage [`load_cage`] describes, with
/// the mandatory syscall filters, in the launch's resource scope, and holding a copy of `nix_dir`
/// for bwrap to bind. A copy per call, since a command gives up what it holds when it is spent and
/// [`load_db`] may make several.
///
/// In the scope because what runs is nix and SQLite over a database a project's cage wrote, which
/// is a program sbx did not write reading what a project chose, the way mise reads a project's
/// files.
fn load_command(engine: &Engine<'_>, nix_dir: &OwnedFd) -> io::Result<std::process::Command> {
    use std::os::fd::AsRawFd;
    let held = fs::File::from(nix_dir.try_clone()?);
    let spec = load_cage(engine.nix_store, held.as_raw_fd())?;
    caged_command(engine, held, &spec)
}

/// `spec` ready to start: composed with the mandatory syscall filters, in the launch's resource
/// scope, and holding `held`, the project's `nix/` the spec binds, until bwrap has it.
fn caged_command(
    engine: &Engine<'_>,
    held: fs::File,
    spec: &super::spec::SandboxSpec,
) -> io::Result<std::process::Command> {
    let mut cage = super::argv::compose(engine.bwrap, spec)?.wrapped(|bwrap, argv| {
        super::cgroup::wrap(
            bwrap,
            argv,
            engine.limits,
            &format!("{}-store", engine.slug),
        )
    });
    cage.hand(held);
    Ok(cage.into_command())
}

/// The cage the registration into a project's store runs in ([`store_cage`]), with the store at
/// [`LOAD_ROOT`].
///
/// What a link the project's cage planted in that tree can reach is decided by this mount
/// namespace: an absolute target, or a relative one that climbs out of the tree, resolves in here,
/// where nothing else of the host's is writable. The descriptor fixes `nix/` itself, which the
/// project's cage cannot replace, being where its own `/nix` is mounted.
fn load_cage(
    nix_store: &Path,
    nix_dir: std::os::fd::RawFd,
) -> io::Result<super::spec::SandboxSpec> {
    store_cage(
        nix_store,
        nix_dir,
        Path::new(LOAD_ROOT),
        Vec::new(),
        &[OsStr::new("--load-db")],
    )
    .map_err(|e| io::Error::other(format!("cannot build the store registration's cage: {e}")))
}

/// A cage `nix_store` runs in against a project's store, given `args` after `--store`: no network,
/// the host's userland and `/nix/store` read-only for an engine that loads its libraries from
/// either, `nix_store` at [`LOAD_ENGINE`], and the project's `nix/`, open as `nix_dir`, the one
/// writable thing of the host's, at `root`'s `nix`. That bind comes after the private `/tmp`, so a
/// store under `/tmp` is not hidden by it, and `standins` come last ([`collection_standins`]). nix
/// needs a home of its own; the private tmpfs is enough.
fn store_cage(
    nix_store: &Path,
    nix_dir: std::os::fd::RawFd,
    root: &Path,
    standins: Vec<super::spec::Mount>,
    args: &[&OsStr],
) -> Result<super::spec::SandboxSpec, String> {
    use super::spec::{Mount, NetPolicy, SandboxSpec};
    let mut mounts = super::selfcage::userland();
    mounts.extend([
        Mount::RoBindTry {
            src: "/nix/store".into(),
            dest: "/nix/store".into(),
        },
        Mount::RoBind {
            src: nix_store.into(),
            dest: LOAD_ENGINE.into(),
        },
        Mount::Proc {
            dest: "/proc".into(),
        },
        Mount::Dev {
            dest: "/dev".into(),
        },
        Mount::Tmpfs {
            dest: "/tmp".into(),
        },
        // Through the descriptor's own link, which names the directory it was opened on.
        Mount::Bind {
            src: format!("/proc/self/fd/{nix_dir}").into(),
            dest: root.join("nix"),
        },
    ]);
    mounts.extend(standins);
    let env = vec![
        ("HOME".to_string(), "/tmp".to_string()),
        ("NIX_REMOTE".to_string(), String::new()),
    ];
    let mut cmd = vec![
        std::ffi::OsString::from(LOAD_ENGINE),
        std::ffi::OsString::from("--store"),
        root.as_os_str().to_os_string(),
    ];
    cmd.extend(args.iter().map(|arg| arg.to_os_string()));
    SandboxSpec::new("/".into(), mounts, env, NetPolicy::Isolated, cmd)
        .map_err(|e| format!("{e:?}"))
}

/// A project's store held for `sbx gc`'s `nix-store` runs, each in a cage of its own
/// ([`HeldStore::command`]): its `nix/` is open here, so every run binds the directory that was
/// checked rather than whatever the name holds by then.
///
/// The cage is the registration's, with the store at its own path rather than at [`LOAD_ROOT`]: a
/// root whose target is relative is resolved by nix against the root's own directory, and the
/// answer must be the one the host would give. What the search for roots asks of the host outside
/// the store is staged in the cage ([`collection_standins`]).
///
/// Two answers differ from a run on the host. The runtime roots nix finds in `/proc` are the
/// cage's own processes rather than the host's, which counted only while a session of the project
/// ran, and `sbx gc` refuses that. And nix names its temporary-roots file after its pid, which is
/// the same in every such cage, so creating one unlinks another of that name as stale.
pub(crate) struct HeldStore<'a> {
    engine: &'a Engine<'a>,
    store_dir: &'a Path,
    nix_dir: OwnedFd,
}

impl<'a> HeldStore<'a> {
    /// Hold `store_dir`'s `nix/`, refusing a link on the way to it.
    pub(crate) fn hold(engine: &'a Engine<'a>, store_dir: &'a Path) -> io::Result<Self> {
        let nix_dir = super::cagedir::open_beneath(store_dir, Path::new("nix"))?;
        Ok(Self {
            engine,
            store_dir,
            nix_dir,
        })
    }

    /// The store's directory, the `--store` every run names.
    pub(crate) fn store_dir(&self) -> &Path {
        self.store_dir
    }

    /// `nix-store --store <store> <args>` ready to start in the collection's cage, with the
    /// stand-ins for what the search for roots asks of the host when `roots`
    /// ([`collection_standins`]): a run that searches them and does not have them finds the
    /// indirect roots stale, unlinks them, and collects their builds, a dry run included.
    pub(crate) fn command(
        &self,
        args: &[&OsStr],
        roots: bool,
    ) -> io::Result<std::process::Command> {
        use std::os::fd::AsRawFd;
        let standins = if roots {
            collection_standins(self.store_dir)?
        } else {
            Vec::new()
        };
        let held = fs::File::from(self.nix_dir.try_clone()?);
        let spec = store_cage(
            self.engine.nix_store,
            held.as_raw_fd(),
            self.store_dir,
            standins,
            args,
        )
        .map_err(|e| io::Error::other(format!("cannot build the store collection's cage: {e}")))?;
        caged_command(self.engine, held, &spec)
    }
}

/// How many entries [`collection_standins`] reads under a project's `gcroots/` and `profiles/`, and
/// how deep it goes. nix lays them out a few levels deep (`gcroots/auto/<name>`,
/// `profiles/per-user/<user>/<profile>`) and a seed adds one root per path it roots.
const ROOTS_READ_MAX: usize = 65_536;
const ROOTS_DEPTH_MAX: usize = 16;

/// How many stand-ins the collection's cage takes: each is a few arguments to bwrap, and one that
/// stands for something other than a link is a mount.
const STANDINS_MAX: usize = 1024;

/// What a stand-in for a link the host holds points at when the host's own does not name a store
/// path: any name that is none gives nix the answer the host's gave.
const NOT_A_STORE_PATH: &str = "/.sbx-not-a-store-path";

/// Where the collection's cage keeps something of its own, and so cannot stand in for the host:
/// a root whose target falls there refuses the collection.
const CAGE_OWN: &[&str] = &[
    "/proc",
    "/dev",
    "/bin",
    "/lib",
    "/lib64",
    "/etc/ld.so.cache",
];

/// What the collection's cage holds from the host unchanged: a target there gets the host's answer
/// without a stand-in.
const CAGE_FROM_HOST: &[&str] = &["/usr", "/nix/store"];

/// Where [`store_cage`] mounts something, the store's own `nix/` aside: a target on the way to one
/// of them is a directory in the cage, made by bwrap.
const CAGE_MOUNTS: &[&str] = &[
    "/usr",
    "/lib",
    "/lib64",
    "/etc/ld.so.cache",
    "/nix/store",
    LOAD_ENGINE,
    "/proc",
    "/dev",
    "/tmp",
];

/// The answers to what nix's search for gc roots asks of the host outside the project's store,
/// staged as mounts for the collection's cage, so its nix decides as one on the host would with
/// nothing of the host's in reach but those answers.
///
/// The search (`LocalStore::findRoots`, nix 2.34) walks `gcroots/` and `profiles/` without following
/// a linked directory. For each link it makes the link's target absolute against the link's own
/// directory and normalises it lexically; a target naming a store path is a root and asks nothing
/// more. Otherwise the target is looked at without being followed: missing, and the link is under
/// `gcroots/auto`, nix unlinks the link as stale; a link itself, its own target is a root when it
/// names a store path; anything else, nothing. Those are the answers staged: a link to the same
/// target where it names a store path and to [`NOT_A_STORE_PATH`] otherwise, an empty directory
/// for anything else that is there, and nothing for what is missing. A target inside the store
/// needs none, since the cage holds the store at its own path, nor one under [`CAGE_FROM_HOST`].
///
/// Refused, rather than staged from a view nix on the host would not have: a target under
/// [`CAGE_OWN`], one on the way to what the cage mounts that is not a directory on the host, one
/// below another target the host holds as a link, an answer the host gives as an error other than
/// "missing", more entries than [`ROOTS_READ_MAX`] or deeper than [`ROOTS_DEPTH_MAX`], and more
/// stand-ins than [`STANDINS_MAX`]. A root left out would be a live build collected. The walk goes
/// through descriptors ([`super::cagedir::open_beneath`], [`super::cagedir::open_entry_dir`]), so a
/// link the project's cage left on the way refuses it too.
fn collection_standins(store_dir: &Path) -> io::Result<Vec<super::spec::Mount>> {
    use super::spec::Mount;
    use std::os::fd::AsRawFd;
    let tree = store_dir.join("nix");
    let mut found: std::collections::BTreeMap<PathBuf, Option<PathBuf>> =
        std::collections::BTreeMap::new();
    let mut read = 0usize;
    for top in ["var/nix/gcroots", "var/nix/profiles"] {
        let dir = match super::cagedir::open_beneath(store_dir, &Path::new("nix").join(top)) {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let mut pending = vec![(dir, tree.join(top), 0usize)];
        while let Some((dir, at, depth)) = pending.pop() {
            for entry in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
                let entry = entry?;
                read += 1;
                if read > ROOTS_READ_MAX {
                    return Err(roots_refusal(&format!(
                        "`{}` and `{}` hold more than {ROOTS_READ_MAX} entries",
                        tree.join("var/nix/gcroots").display(),
                        tree.join("var/nix/profiles").display()
                    )));
                }
                let name = entry.file_name();
                let path = at.join(&name);
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    if depth == ROOTS_DEPTH_MAX {
                        return Err(roots_refusal(&format!(
                            "`{}` lies more than {ROOTS_DEPTH_MAX} directories deep",
                            path.display()
                        )));
                    }
                    let below = super::cagedir::open_entry_dir(&dir, &name)?;
                    pending.push((below, path, depth + 1));
                } else if kind.is_symlink() {
                    let target = fs::read_link(super::cagedir::entry(&dir, &name)?)?;
                    if let Some((at, standin)) = standin_for(&tree, &path, &target)? {
                        found.insert(at, standin);
                    }
                }
            }
        }
    }
    let mut mounts = Vec::new();
    for (at, standin) in &found {
        let holds_another = found
            .range::<Path, _>((
                std::ops::Bound::Excluded(at.as_path()),
                std::ops::Bound::Unbounded,
            ))
            .next()
            .is_some_and(|(next, _)| next.starts_with(at));
        match standin {
            Some(_) if holds_another => {
                return Err(roots_refusal(&format!(
                    "`{}` is a link on the host, and another root's target lies below it",
                    at.display()
                )));
            }
            Some(target) => mounts.push(Mount::Symlink {
                target: target.clone(),
                dest: at.clone(),
            }),
            // The directories bwrap makes on the way to the stand-ins below give the same answer.
            None if holds_another => {}
            None => mounts.push(Mount::Tmpfs { dest: at.clone() }),
        }
    }
    if mounts.len() > STANDINS_MAX {
        return Err(roots_refusal(&format!(
            "the roots of `{}` lead to more than {STANDINS_MAX} places outside it",
            tree.display()
        )));
    }
    Ok(mounts)
}

/// The stand-in the root `link`, a link to `target` under the store's `tree`, needs: `None` for
/// none, otherwise where it goes and what it is, a link to that target or, as `None`, something
/// that is not a link ([`collection_standins`]).
fn standin_for(
    tree: &Path,
    link: &Path,
    target: &Path,
) -> io::Result<Option<(PathBuf, Option<PathBuf>)>> {
    let at = lexical(&link.parent().unwrap_or(tree).join(target));
    if at.starts_with(tree) || CAGE_FROM_HOST.iter().any(|from| at.starts_with(from)) {
        return Ok(None);
    }
    if let Some(own) = CAGE_OWN.iter().find(|own| at.starts_with(own)) {
        return Err(roots_refusal(&format!(
            "`{}` leads to `{}`, under `{own}`, which the collection's cage keeps for itself",
            link.display(),
            at.display()
        )));
    }
    let meta = match fs::symlink_metadata(&at) {
        Ok(meta) => meta,
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => {
            return Ok(None);
        }
        Err(e) => {
            return Err(roots_refusal(&format!(
                "`{}` leads to `{}`, which cannot be looked at ({e})",
                link.display(),
                at.display()
            )));
        }
    };
    let on_the_way = CAGE_MOUNTS
        .iter()
        .map(Path::new)
        .chain(std::iter::once(tree))
        .any(|mounted| mounted.starts_with(&at));
    if on_the_way {
        return if meta.is_dir() {
            Ok(None)
        } else {
            Err(roots_refusal(&format!(
                "`{}` leads to `{}`, on the way to what the collection's cage mounts, and it is \
                 not a directory on the host",
                link.display(),
                at.display()
            )))
        };
    }
    if !meta.file_type().is_symlink() {
        return Ok(Some((at, None)));
    }
    let named = fs::read_link(&at)?;
    let names_the_store = {
        let mut parts = named.components();
        parts.next() == Some(std::path::Component::RootDir)
            && parts.next() == Some(std::path::Component::Normal(OsStr::new("nix")))
            && parts.next() == Some(std::path::Component::Normal(OsStr::new("store")))
    };
    let standin = if names_the_store {
        named
    } else {
        PathBuf::from(NOT_A_STORE_PATH)
    };
    Ok(Some((at, Some(standin))))
}

/// `path` with `.` dropped and `..` taken back lexically, never above the root: how nix makes a
/// root's target absolute (`absPath`, `canonPath`), without following a link.
fn lexical(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::from("/");
    for part in path.components() {
        match part {
            Component::Normal(name) => out.push(name),
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    out
}

/// The refusal a root the collection's cage cannot stand in for earns, `why` naming it.
fn roots_refusal(why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "{why}: the collection runs in a cage of its own and cannot answer for it as the host \
             would, so nothing is collected rather than a build still in use. This tree is \
             writable by a cage of this project: remove that root by hand, then run again"
        ),
    )
}

/// Retry `op` while it fails with an error `transient` deems worth retrying, up to `attempts` total
/// tries with a short backoff between them. A non-transient error (or a success) returns at once, so
/// a real failure surfaces without burning the whole budget. Pure control flow over the closures —
/// no knowledge of what is being retried — so it is unit-testable without spawning a process.
fn retry_transient<T>(
    attempts: u32,
    mut op: impl FnMut() -> io::Result<T>,
    transient: impl Fn(&io::Error) -> bool,
) -> io::Result<T> {
    let mut last = op();
    for _ in 1..attempts {
        match &last {
            Err(e) if transient(e) => {
                // A base delay plus a per-thread jitter: concurrent seeders that lost the same lock
                // race must not re-collide in lockstep on the next attempt. The jitter is constant
                // per thread (so a single-threaded caller — and the tests — back off deterministically)
                // but differs across threads, spreading their retries apart.
                std::thread::sleep(std::time::Duration::from_millis(50 + backoff_jitter_ms()));
                last = op();
            }
            _ => break,
        }
    }
    last
}

/// A small backoff offset (0..40 ms), derived from the pid AND the thread id so it is stable within
/// one caller yet distinct across concurrent ones — enough to desynchronise retriers that lost the
/// same lock race, without a randomness source. The pid is essential: the real racers are separate
/// `sbx` processes seeding the same project, and each on its main thread would hash the same thread
/// id and re-collide in lockstep; mixing the (process-unique) pid spreads them apart.
fn backoff_jitter_ms() -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    std::process::id().hash(&mut h);
    std::thread::current().id().hash(&mut h);
    h.finish() % 40
}

/// The project store's garbage-collector roots directory. `nix-store --gc` keeps every
/// path reachable from a symlink here, so this is where the seed anchors what the cage
/// needs. A sibling of the store's `db/`, under the relocated store's `nix/var` tree.
pub(crate) fn gcroots_dir(store_dir: &Path) -> PathBuf {
    store_dir.join("nix/var/nix/gcroots")
}

/// Make `store_dir`'s `nix/<rel>` chain, refusing a component the cage repointed.
///
/// [`super::cagedir::ensure_under`] with `store_dir` as the anchor. Everything under
/// `store_dir/nix` is bound read-write at `/nix` (`NixMount { writable: true }`), the cage runs
/// same-uid, and the directories are `0700` owned by that uid — so in-cage code may
/// `mv /nix/store /nix/store.real && ln -s /somewhere /nix/store`, or do the same to `var`, and
/// leave it for the next launch. The seed below then copies the whole base closure, gigabytes of
/// it, into wherever the cage pointed, and `gcroot_roots` writes its symlinks there.
///
/// `store_dir` itself sits under `<data>/projects/<id>/`, which the cage never sees, so it is a
/// sound anchor; `nix` is the bind's own source, which from inside the cage is the mount point and
/// so cannot be exchanged either.
fn ensure_dir_chain(store_dir: &Path, rel: &str) -> io::Result<PathBuf> {
    super::cagedir::ensure_under(store_dir, &format!("nix/{rel}"), DIR_MODE)
}

/// [`ensure_dir_chain`], holding the leaf: the descriptor the walk reached it with
/// ([`super::cagedir::hold_under`]), for the seed to write through.
///
/// The path [`ensure_dir_chain`] returns is checked, not held. In-cage code that is live while a
/// second launch of the same project seeds can swap `/nix/store` for a link between the check and
/// the copy, or plant one inside a temporary tree as it is filled. So everything the seed writes
/// below `nix/` goes through this descriptor and [`super::cagedir::entry`]: it lands in the
/// directory that was checked, and a name the cage planted is refused rather than followed.
fn hold_dir_chain(store_dir: &Path, rel: &str) -> io::Result<OwnedFd> {
    super::cagedir::hold_under(store_dir, &format!("nix/{rel}"), DIR_MODE)
}

/// The directories under `nix/` that `nix-store` creates or writes into when it opens a store: the
/// database, the gc roots, the temporary roots, the gc socket and the deduplication pool, and the
/// two `per-user` directories, which it creates and then sets to mode `0755` by path, following a
/// link to wherever it points. The walk checks each ancestor, so `var/nix/profiles` is covered by
/// its `per-user`.
const NIX_STATE_DIRS: &[&str] = &[
    "store/.links",
    "var/nix/db",
    "var/nix/gcroots",
    "var/nix/gcroots/per-user",
    "var/nix/profiles/per-user",
    "var/nix/temproots",
    "var/nix/gc-socket",
];

/// The files under `nix/` that `nix-store` opens for writing: the database with its journals and
/// locks, and the gc lock.
const NIX_STATE_FILES: &[&str] = &[
    "var/nix/db/big-lock",
    "var/nix/db/db.sqlite",
    "var/nix/db/db.sqlite-journal",
    "var/nix/db/db.sqlite-shm",
    "var/nix/db/db.sqlite-wal",
    "var/nix/db/reserved",
    "var/nix/db/schema",
    "var/nix/gc.lock",
];

/// Check the part of `store_dir`'s tree that `nix-store` writes, before any `nix-store` runs on it.
///
/// `nix-store` runs as the user against a tree the cage rewrites at will (see
/// [`ensure_dir_chain`]), and it opens each name below by path. So each directory of
/// [`NIX_STATE_DIRS`] must be a real directory, each file of [`NIX_STATE_FILES`] that exists must
/// be a regular file, and so must every entry of `temproots`, which `nix-store` names after its
/// own pid. Anything else is refused before `nix-store` is started, and left in place for the user
/// to see.
///
/// A missing directory is created, as `nix-store` would create it. The names are checked, not held:
/// the tree is still the cage's between this check and the `nix-store` run. `sbx gc` refuses a
/// store a live cage of the project holds. A launch does not, since two launches of one project
/// may run at once, so a cage of the project that is running while another launch seeds can
/// replace a checked name before `nix-store` opens it. The registration a launch runs answers that
/// with its cage ([`load_cage`]), and this check, made again when the registration fails
/// ([`retry_load`]), is then what makes a name the cage planted a refusal that names it rather than
/// a failure inside that cage. `sbx gc` runs its own in a cage too ([`HeldStore`]), and there the
/// check names a planted entry before the collection starts.
fn ensure_nix_state(store_dir: &Path) -> io::Result<()> {
    for rel in NIX_STATE_DIRS {
        ensure_dir_chain(store_dir, rel)?;
    }
    let nix = store_dir.join("nix");
    for rel in NIX_STATE_FILES {
        refuse_unless_file(&nix.join(rel))?;
    }
    for entry in fs::read_dir(nix.join("var/nix/temproots"))? {
        refuse_unless_file(&entry?.path())?;
    }
    Ok(())
}

/// Refuse `path` when it exists and is not a regular file. `lstat`, so a symlink is reported as
/// one rather than judged by what it points at; an entry that is gone is no refusal.
fn refuse_unless_file(path: &Path) -> io::Result<()> {
    let kind = match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => return Ok(()),
        Ok(meta) if meta.file_type().is_symlink() => "a symlink",
        Ok(_) => "not a regular file",
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "`{}` is {kind}, where `nix-store` keeps a file of its own. This tree is writable by \
             the cage, so `nix-store` is not run on it until that entry is removed by hand",
            path.display()
        ),
    ))
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
    // Same guard as the store directory, and for the same reason: `nix/var` is under the cage's
    // writable `/nix` too, so this walk refuses a component the cage repointed rather than writing
    // its root symlinks wherever that led, and the links go through the descriptor it reached.
    let dir = hold_dir_chain(store_dir, "var/nix/gcroots")?;
    for root in roots {
        let Some(name) = root.file_name() else {
            continue;
        };
        let link = super::cagedir::entry(&dir, name)?;
        // Already the right root: nothing to do (the common warm re-seed).
        if fs::read_link(&link).is_ok_and(|t| t == *root) {
            continue;
        }
        let mut tmp_name = std::ffi::OsString::from(format!(".tmp-{}-", unique()));
        tmp_name.push(name);
        let tmp = super::cagedir::entry(&dir, &tmp_name)?;
        // A stale temp from a crashed seed would block the symlink; clear it first.
        let _ = fs::remove_file(&tmp);
        std::os::unix::fs::symlink(root, &tmp)?;
        // `rename` atomically REPLACES any existing link — including one a concurrent seed just
        // placed (which points at the same content-addressed root anyway) — so it does not fail on
        // "the link already exists". A failure here is therefore a genuine I/O error (out of space,
        // a read-only store), not a lost race: clean up the temp, then propagate it rather than
        // silently leaving the seed path unrooted (a later GC could then collect it).
        if let Err(e) = fs::rename(&tmp, &link) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    /// The seed's record of how it placed its paths, which `gc::Reclaim` reads: cloned while every
    /// file was, and copied for good once one was, since those bytes stay the tree's own whatever a
    /// later seed clones. A seed that changes nothing writes nothing.
    #[test]
    fn the_seed_mode_record_turns_to_copy_and_stays_there() {
        let tmp = TmpDir::new();
        let tree = tmp.path().join("tree");
        let store = tree.join("store");
        std::fs::create_dir_all(&store).unwrap();
        assert_eq!(
            seed_mode(&tree),
            None,
            "a tree seeded before the record has none"
        );

        record_seed_mode(&store, true).unwrap();
        assert_eq!(seed_mode(&tree), Some(true));
        let before = ino(&store.join(SEED_MODE));
        record_seed_mode(&store, true).unwrap();
        let after = ino(&store.join(SEED_MODE));
        assert_eq!(before, after, "an unchanged record is not rewritten");

        record_seed_mode(&store, false).unwrap();
        assert_eq!(seed_mode(&tree), Some(false));
        record_seed_mode(&store, true).unwrap();
        assert_eq!(
            seed_mode(&tree),
            Some(false),
            "a copied file stays the tree's own"
        );
    }

    /// A `(device, inode)` pair — equal across two paths iff they are the same
    /// inode. The device is part of the key because an inode number alone can
    /// collide across filesystems.
    fn ino(path: &Path) -> (u64, u64) {
        let m = std::fs::symlink_metadata(path).unwrap();
        (m.dev(), m.ino())
    }

    /// A descriptor for `dir`, the way the seed holds its store directory.
    fn hold(dir: &Path) -> OwnedFd {
        OwnedFd::from(std::fs::File::open(dir).unwrap())
    }

    #[test]
    fn a_probe_that_could_not_run_is_not_an_answer_about_the_filesystem() {
        let base = TmpDir::new();
        // A writable directory yields a verdict either way — which one depends on the host.
        assert!(reflink_verdict(base.path()).is_some());

        // One the probe cannot write into yields none: nothing was learned, and a caller deciding
        // on the filesystem's capabilities must not read the failure as "it cannot".
        //
        // A regular file, so the probe's write answers `ENOTDIR` for every uid. A mode-locked
        // directory would refuse an ordinary user and admit root, who would then run the probe and
        // get a real verdict — so on a host running the suite as root this branch would assert
        // nothing.
        let closed = base.path().join("closed");
        std::fs::write(&closed, b"not a directory\n").unwrap();
        assert_eq!(reflink_verdict(&closed), None);
        // The seeding caller, about to copy into it, is right to read it as "no" all the same.
        assert!(!supports_reflink(&hold(&closed)));
    }

    #[test]
    fn store_dir_is_under_the_project_runtime() {
        let layout = Layout::under(Path::new("/data/sbx"));
        assert_eq!(
            store_dir_for(&layout, "abc"),
            PathBuf::from("/data/sbx/projects/abc/store")
        );
        // the marker is a sibling of the store under the same runtime tree
        assert_eq!(
            project_dir(&layout, "abc").join(PROJECT_MARKER),
            PathBuf::from("/data/sbx/projects/abc/project")
        );
    }

    #[test]
    fn shared_gc_lock_serialises_a_shared_hold_against_an_exclusive_acquire() {
        use std::sync::mpsc;
        use std::time::Duration;
        let data = TmpDir::new();
        let layout = Layout::under(data.path());

        // hold the lock shared (as a seed does)
        let held = lock_shared(&layout).unwrap();

        // a second actor's exclusive acquire (as the collector does) must block while the shared
        // hold is live, then proceed once it is released.
        let (tx, rx) = mpsc::channel();
        let path = data.path().to_path_buf();
        let handle = std::thread::spawn(move || {
            let layout = Layout::under(&path);
            let guard = lock_exclusive(&layout).unwrap();
            tx.send(()).unwrap();
            // hold briefly so the release is observable, then drop
            std::thread::sleep(Duration::from_millis(50));
            drop(guard);
        });

        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "the exclusive acquire completed while a shared hold was live — the guard released \
             early (a `let _ =` instead of a bound guard), or the lock is not actually held"
        );
        drop(held); // release the shared hold
        assert!(
            rx.recv_timeout(Duration::from_secs(2)).is_ok(),
            "the exclusive acquire did not proceed after the shared hold was released"
        );
        handle.join().unwrap();
    }

    #[test]
    fn write_marker_records_the_canonical_path_owner_only_and_idempotently() {
        use std::os::unix::ffi::OsStrExt;
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let id = "deadbeefdeadbeef";
        let marker = project_dir(&layout, id).join(PROJECT_MARKER);

        let canonical = PathBuf::from("/home/user/some/project");
        write_marker(&layout, id, &canonical).unwrap();
        // stored as the raw path bytes, no newline — so a non-UTF-8 path would round-trip exactly
        let read = std::fs::read(&marker).unwrap();
        assert_eq!(std::ffi::OsStr::from_bytes(&read), canonical.as_os_str());
        // owner-only
        let mode = std::fs::metadata(&marker).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // overwriting (the every-launch idempotent path) replaces the content, leaks no temp
        write_marker(&layout, id, &PathBuf::from("/new/path")).unwrap();
        assert_eq!(std::fs::read(&marker).unwrap(), b"/new/path");
        let leftovers: Vec<_> = std::fs::read_dir(project_dir(&layout, id))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".project.tmp"))
            .collect();
        assert!(leftovers.is_empty(), "a temp placement leaked");
    }

    /// `store_dir/nix` is bound read-write into the cage at `/nix`, so every directory under it is
    /// one in-cage code can replace with a symlink and leave behind for the *next* launch. The seed
    /// then copies the base closure — gigabytes — into wherever that points, and `gcroot_roots`
    /// writes its symlinks there. `create_dir_all` cannot tell the difference: it stats through the
    /// link, finds a directory, and reports the parents as made.
    ///
    /// Each component the host creates under `nix/` is therefore checked, and a redirected one is a
    /// hard error rather than something repaired in place.
    #[test]
    fn a_store_skeleton_the_cage_repointed_is_refused_rather_than_written_through() {
        // `store` is the seed's own walk; the other three lie on the gc-roots walk. Both callers go
        // through the same guard, and each component of each is covered.
        for (rel, walk) in [
            ("store", "store"),
            ("var", "var/nix/gcroots"),
            ("var/nix", "var/nix/gcroots"),
            ("var/nix/gcroots", "var/nix/gcroots"),
        ] {
            let base = TmpDir::new();
            let store_dir = base.join("store");
            let elsewhere = base.join("elsewhere");
            std::fs::create_dir_all(&elsewhere).unwrap();

            // Plant the link exactly where in-cage code could: under the writable `nix/` root.
            let planted = store_dir.join("nix").join(rel);
            std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&elsewhere, &planted).unwrap();

            let err = ensure_dir_chain(&store_dir, walk)
                .err()
                .unwrap_or_else(|| panic!("a symlink at nix/{rel} must be refused"));
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{rel}");
            assert!(
                err.to_string().contains("is a symlink"),
                "the refusal must name what it found: {err}"
            );

            // And the caller that walks this chain refuses too, rather than only the helper.
            if walk == "var/nix/gcroots" {
                assert!(
                    gcroot_roots(
                        &store_dir,
                        &[PathBuf::from(
                            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-base"
                        )],
                    )
                    .is_err(),
                    "nix/{rel}: gcroot_roots wrote its links through the link"
                );
            }

            assert_eq!(
                std::fs::read_dir(&elsewhere).unwrap().count(),
                0,
                "nix/{rel}: the host wrote through the link into the directory the cage chose"
            );
            assert_eq!(
                std::fs::read_link(&planted).unwrap(),
                elsewhere,
                "nix/{rel}: the planted link must be reported, not silently replaced"
            );
        }
    }

    /// And the ordinary skeleton is still made: a guard that refused everything would pass the test
    /// above while breaking every launch.
    #[test]
    fn a_missing_store_skeleton_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let base = TmpDir::new();
        let store_dir = base.join("store");

        let made = ensure_dir_chain(&store_dir, "var/nix/gcroots").unwrap();

        assert_eq!(made, gcroots_dir(&store_dir));
        assert!(made.is_dir());
        for dir in [
            store_dir.join("nix"),
            store_dir.join("nix/var"),
            store_dir.join("nix/var/nix"),
            made.clone(),
        ] {
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, DIR_MODE, "{} is not owner-only", dir.display());
        }
        // Idempotent: a second walk over an existing chain is a no-op, not an error.
        assert_eq!(
            ensure_dir_chain(&store_dir, "var/nix/gcroots").unwrap(),
            made
        );
    }

    /// A stand-in for `nix-store` that appends each run's arguments to `ran` and prints nothing,
    /// which [`prepare`] reads as an empty closure. It tells whether `nix-store` was started at all.
    fn fake_nix_store(dir: &Path, ran: &Path) -> PathBuf {
        let path = dir.join("nix-store");
        std::fs::write(
            &path,
            format!("#!/bin/sh\necho \"$*\" >> '{}'\n", ran.display()),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// [`prepare`] with the fake `nix_store`, waiting out the `ETXTBSY` a just-written executable
    /// meets under the parallel runner, which says nothing about `prepare` itself. The
    /// registration's cage is given a bwrap that does not exist: every caller expects a refusal
    /// before any `nix-store` starts, so reaching it is already a failure.
    fn prepare_past_etxtbsy(
        nix_store: &Path,
        layout: &Layout,
        roots: &[PathBuf],
    ) -> io::Result<()> {
        let engine = Engine::for_tests(nix_store, Path::new("/nonexistent/bwrap"));
        for _ in 0..100 {
            match prepare(&engine, layout, "p", roots) {
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                other => return other.map(drop),
            }
        }
        panic!("the fake nix-store stayed held open for writing by another thread");
    }

    /// `nix-store` opens by path the directories and files it keeps in a tree the cage writes. Each
    /// one the cage replaced is refused before any `nix-store` starts, and left in place.
    #[test]
    fn nix_store_is_not_started_on_a_store_whose_state_the_cage_replaced() {
        let roots = [PathBuf::from(
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-base",
        )];
        // Every directory `nix-store` creates or writes into, with each ancestor below `nix/`.
        let dirs = [
            "store/.links",
            "var",
            "var/nix",
            "var/nix/db",
            "var/nix/gcroots",
            "var/nix/gcroots/per-user",
            "var/nix/profiles",
            "var/nix/profiles/per-user",
            "var/nix/temproots",
            "var/nix/gc-socket",
        ];
        // Every file it opens there, and a temporary root, which it names after its own pid.
        let files = [
            "var/nix/db/big-lock",
            "var/nix/db/db.sqlite",
            "var/nix/db/db.sqlite-journal",
            "var/nix/db/db.sqlite-shm",
            "var/nix/db/db.sqlite-wal",
            "var/nix/db/reserved",
            "var/nix/db/schema",
            "var/nix/gc.lock",
            "var/nix/temproots/4242",
        ];
        let cases = dirs
            .iter()
            .map(|rel| (*rel, true))
            .chain(files.iter().map(|rel| (*rel, false)));

        for (rel, is_dir) in cases {
            let base = TmpDir::new();
            let layout = Layout::under(&base.join("data"));
            let store_dir = store_dir_for(&layout, "p");
            let ran = base.join("ran");
            let nix_store = fake_nix_store(base.path(), &ran);
            let elsewhere = base.join("elsewhere");
            std::fs::create_dir_all(&elsewhere).unwrap();
            std::fs::write(elsewhere.join("held"), b"held\n").unwrap();
            let target = if is_dir {
                elsewhere.clone()
            } else {
                elsewhere.join("held")
            };

            let planted = store_dir.join("nix").join(rel);
            std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
            symlink(&target, &planted).unwrap();

            let err = prepare_past_etxtbsy(&nix_store, &layout, &roots)
                .err()
                .unwrap_or_else(|| panic!("a symlink at nix/{rel} must be refused"));
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "nix/{rel}: {err}");
            assert!(
                err.to_string().contains("is a symlink"),
                "nix/{rel}: the refusal must name what it found: {err}"
            );
            assert!(
                !ran.exists(),
                "nix/{rel}: nix-store was started on the store before the refusal"
            );
            assert_eq!(
                std::fs::read_dir(&elsewhere).unwrap().count(),
                1,
                "nix/{rel}: something was written where the link points"
            );
            assert_eq!(std::fs::read(elsewhere.join("held")).unwrap(), b"held\n");
            assert_eq!(
                std::fs::read_link(&planted).unwrap(),
                target,
                "nix/{rel}: the planted link must be left for the user to see"
            );
        }

        // Not a link, but still not what `nix-store` keeps there: refused the same way.
        for (rel, make) in [("var/nix/db", "file"), ("var/nix/db/db.sqlite", "dir")] {
            let base = TmpDir::new();
            let layout = Layout::under(&base.join("data"));
            let ran = base.join("ran");
            let nix_store = fake_nix_store(base.path(), &ran);
            let planted = store_dir_for(&layout, "p").join("nix").join(rel);
            std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
            if make == "file" {
                std::fs::write(&planted, b"").unwrap();
            } else {
                std::fs::create_dir(&planted).unwrap();
            }
            let err = prepare_past_etxtbsy(&nix_store, &layout, &roots)
                .err()
                .unwrap_or_else(|| panic!("a {make} at nix/{rel} must be refused"));
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "nix/{rel}: {err}");
            assert!(!ran.exists(), "nix/{rel}: nix-store was started");
        }
    }

    /// And a store whose state is its own passes the check, first seed or not: a check that refused
    /// everything would pass the test above while stopping every launch. That the registration
    /// then runs on such a store is a smoke test's, since it needs a real `nix-store`
    /// (`smoke::the_registration_runs_in_its_cage_and_a_planted_link_reaches_nothing_of_the_host`).
    #[test]
    fn a_store_whose_state_is_its_own_passes_the_check() {
        for seeded_before in [false, true] {
            let base = TmpDir::new();
            let store_dir = base.join("store");
            let nix = store_dir.join("nix");
            if seeded_before {
                std::fs::create_dir_all(nix.join("var/nix/db")).unwrap();
                std::fs::create_dir_all(nix.join("var/nix/temproots")).unwrap();
                for file in [
                    "var/nix/db/db.sqlite",
                    "var/nix/gc.lock",
                    "var/nix/temproots/77",
                ] {
                    std::fs::write(nix.join(file), b"").unwrap();
                }
            }

            ensure_nix_state(&store_dir)
                .unwrap_or_else(|e| panic!("seeded before: {seeded_before}: {e}"));

            for dir in [
                "store/.links",
                "var/nix/db",
                "var/nix/gcroots/per-user",
                "var/nix/profiles/per-user",
                "var/nix/temproots",
                "var/nix/gc-socket",
            ] {
                let meta = std::fs::symlink_metadata(nix.join(dir)).unwrap();
                assert!(meta.is_dir(), "nix/{dir} is not a real directory");
            }
        }
    }

    /// The registration's cage: the project's `nix/`, bound from the descriptor, is the one thing of
    /// the host's it can write, it has no network, and it runs nothing but the load.
    #[test]
    fn the_registrations_cage_writes_only_the_project_store() {
        use super::super::spec::{Mount, NetPolicy};
        let spec = load_cage(Path::new("/opt/engine/nix-store"), 7).unwrap();
        let writable: Vec<&Mount> = spec
            .mounts
            .iter()
            .filter(|m| matches!(m, Mount::Bind { .. } | Mount::DevBind { .. }))
            .collect();
        assert_eq!(
            writable,
            [&Mount::Bind {
                src: "/proc/self/fd/7".into(),
                dest: "/project/nix".into(),
            }]
        );
        assert_eq!(spec.net, NetPolicy::Isolated);
        assert_eq!(
            spec.cmd,
            ["/bin/nix-store", "--store", "/project", "--load-db"].map(std::ffi::OsString::from)
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

        copy_recursive(&src, &hold(base.path()), OsStr::new("dst"), true).unwrap();

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
    fn copy_recursive_seals_each_directory_to_its_source_mode() {
        // A real store path arrives read-only (`0555`), which is the mode a copy has to
        // end at and cannot be built at: a directory sealed before its entries takes
        // none. Both halves are asserted here, the second by the content being present.
        let base = TmpDir::new();
        let src = base.join("src");
        let dst = base.join("dst");
        std::fs::create_dir_all(src.join("bin")).unwrap();
        std::fs::write(src.join("bin/tool"), b"payload").unwrap();
        // nix's own shape: every directory of the path read-only, written innermost
        // first so each one is still writable when its entries are placed
        for d in ["bin", ""] {
            std::fs::set_permissions(src.join(d), std::fs::Permissions::from_mode(0o555)).unwrap();
        }

        copy_recursive(&src, &hold(base.path()), OsStr::new("dst"), false)
            .expect("a read-only source must still copy");

        assert_eq!(std::fs::read(dst.join("bin/tool")).unwrap(), b"payload");
        for d in ["", "bin"] {
            let mode = std::fs::metadata(dst.join(d)).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o555,
                "the copy of `{d}` kept the mode it was built at instead of its source's"
            );
        }
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

        let held = hold(&project);
        seed_path(&shared, &held, OsStr::new("aaa-old"), true).unwrap();
        seed_path(&shared, &held, OsStr::new("bbb-new"), true).unwrap();

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
    fn copy_into_place_clears_a_stale_temp_dir_before_copying() {
        // A crashed/SIGKILL'd seed can leave a directory tree at the temp name a later seed reuses
        // (the temp name is process-local). The copy must clear it first — `copy_recursive`'s
        // non-recursive dir-create would otherwise fail EEXIST and brick the re-seed.
        let base = TmpDir::new();
        let src = base.join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("sub/file"), b"content").unwrap();
        let dest = base.join("dest");
        let tmp = base.join(".tmp-stale-dest");
        // the leftover from a crashed seed: a non-empty directory tree at the temp name
        std::fs::create_dir_all(tmp.join("leftover")).unwrap();

        copy_into_place(
            &src,
            &hold(base.path()),
            OsStr::new("dest"),
            OsStr::new(".tmp-stale-dest"),
            false,
        )
        .expect("a stale temp must be cleared, not fail EEXIST");
        assert_eq!(std::fs::read(dest.join("sub/file")).unwrap(), b"content");
        assert!(!tmp.exists(), "the temp was consumed by the atomic rename");
    }

    #[test]
    fn copy_into_place_clears_a_stale_temp_dir_that_was_already_sealed() {
        // The stale temp a crash actually leaves: one `copy_recursive` had finished, so
        // its directories are sealed read-only and a plain `remove_dir_all` cannot empty
        // them. Clearing it has to add write back, or the re-seed of that path meets its
        // own leftover as `EEXIST` and never recovers.
        let base = TmpDir::new();
        let src = base.join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("sub/file"), b"content").unwrap();
        let dest = base.join("dest");
        let tmp = base.join(".tmp-sealed-dest");
        std::fs::create_dir_all(tmp.join("leftover")).unwrap();
        std::fs::write(tmp.join("leftover/half"), b"partial").unwrap();
        for d in ["leftover", ""] {
            std::fs::set_permissions(tmp.join(d), std::fs::Permissions::from_mode(0o555)).unwrap();
        }

        copy_into_place(
            &src,
            &hold(base.path()),
            OsStr::new("dest"),
            OsStr::new(".tmp-sealed-dest"),
            false,
        )
        .expect("a sealed stale temp must be cleared, not fail EEXIST");
        assert_eq!(std::fs::read(dest.join("sub/file")).unwrap(), b"content");
        assert!(!tmp.exists(), "the temp was consumed by the atomic rename");
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

        place_file(&shared.join("libc"), &hold(&proj), OsStr::new("libc"), true).unwrap();

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

        place_atomically(
            &hold(base.path()),
            OsStr::new(".tmp-1-aaa-pkg"),
            OsStr::new("aaa-pkg"),
        )
        .expect("a lost race is success, not an error");

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
        // renaming onto a name no filesystem can hold fails (ENAMETOOLONG) with the
        // destination still absent — the propagating branch, not the race one
        let dest = "x".repeat(300);

        place_atomically(
            &hold(base.path()),
            OsStr::new(".tmp-1-x"),
            OsStr::new(&dest),
        )
        .expect_err("a non-race failure must propagate");

        assert!(
            !tmp.exists(),
            "the temp was not discarded after a hard placement failure"
        );
    }

    /// A link the cage planted at a name the seed is about to create is refused, and the file it
    /// names keeps its bytes.
    ///
    /// The seed fills its temporary tree inside the store the cage holds read-write, so in-cage
    /// code watching that directory can put a link at a file's name before the file is made. A
    /// create that follows it truncates the file the link names and writes the store's content
    /// over it. Both branches are covered, the clone and the copy.
    #[test]
    fn a_link_planted_at_a_seeded_name_is_refused_and_not_written_through() {
        for reflink_ok in [true, false] {
            let base = TmpDir::new();
            let src = base.join("src");
            std::fs::write(&src, b"store content").unwrap();
            let witness = base.join("witness");
            std::fs::write(&witness, b"the user's file").unwrap();
            let tree = base.join("tree");
            std::fs::create_dir_all(&tree).unwrap();
            symlink(&witness, tree.join("file")).unwrap();

            let placed = place_file(&src, &hold(&tree), OsStr::new("file"), reflink_ok);

            assert_eq!(
                placed.map_err(|e| e.kind()).err(),
                Some(io::ErrorKind::AlreadyExists),
                "reflink_ok={reflink_ok}: a planted name must fail the placement"
            );
            assert_eq!(
                std::fs::read(&witness).unwrap(),
                b"the user's file",
                "reflink_ok={reflink_ok}: the file the link names was written"
            );
            assert!(
                std::fs::symlink_metadata(tree.join("file"))
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "reflink_ok={reflink_ok}: the planted link is left for the user to see"
            );
        }
    }

    /// An entry already at a name the seed creates is reported by the path the user finds it at,
    /// for each kind of entry the copy makes: a directory, a link and a file. The kernel's answer,
    /// `File exists`, names nothing, and the seed meets it in a tree a cage of the project writes.
    #[test]
    fn an_entry_already_at_a_name_the_seed_creates_is_named_by_its_path() {
        let base = TmpDir::new();
        let src = base.join("src");
        std::fs::create_dir_all(src.join("dir")).unwrap();
        std::fs::write(src.join("file"), b"store content").unwrap();
        symlink("file", src.join("link")).unwrap();
        let witness = base.join("witness");
        std::fs::write(&witness, b"the user's file").unwrap();
        let tree = base.join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        // The descriptor's path, as the kernel resolves it: the test's directory may sit behind a
        // link.
        let shown = std::fs::canonicalize(&tree).unwrap();

        for kind in ["dir", "link", "file"] {
            symlink(&witness, tree.join(kind)).unwrap();
            let err = copy_recursive(&src.join(kind), &hold(&tree), OsStr::new(kind), false)
                .expect_err(kind);
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{kind}: {err}");
            let path = shown.join(kind);
            assert!(
                err.to_string().contains(&format!("`{}`", path.display())),
                "{kind}: the error does not name `{}`: {err}",
                path.display()
            );
            assert_eq!(
                std::fs::read(&witness).unwrap(),
                b"the user's file",
                "{kind}: the file the link names was written"
            );
        }
    }

    /// A store directory the cage swaps for a link after the walk checked it does not redirect the
    /// seed: what is placed lands in the directory the walk reached.
    ///
    /// The descriptor is taken from the walk before the swap, as [`prepare`] takes it. A test that
    /// opened its own after the swap would hold the link's target and prove nothing.
    #[test]
    fn a_store_swapped_for_a_link_after_the_walk_is_not_written_through() {
        let base = TmpDir::new();
        let store_dir = base.join("store");
        let shared = base.join("shared");
        std::fs::create_dir_all(shared.join("aaa-pkg")).unwrap();
        std::fs::write(shared.join("aaa-pkg/file"), b"payload").unwrap();
        let elsewhere = base.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();

        let held = hold_dir_chain(&store_dir, "store").unwrap();
        let real = store_dir.join("nix/store.real");
        std::fs::rename(store_dir.join("nix/store"), &real).unwrap();
        symlink(&elsewhere, store_dir.join("nix/store")).unwrap();

        seed_path(&shared, &held, OsStr::new("aaa-pkg"), false)
            .expect("the seed places the path in the directory it holds");

        let landed: Vec<_> = std::fs::read_dir(&elsewhere)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert!(
            landed.is_empty(),
            "the seed wrote through the link: {landed:?}"
        );
        assert_eq!(
            std::fs::read(real.join("aaa-pkg/file")).unwrap(),
            b"payload",
            "the path did not land in the directory the walk checked"
        );
    }

    #[test]
    fn retry_transient_retries_a_transient_error_then_succeeds() {
        use std::cell::Cell;
        // The load-db retry's control flow, exercised without a process: an error the predicate
        // deems transient is retried, and a success on a later attempt is returned. The counter
        // proves it actually re-ran (twice failing, then ok).
        let calls = Cell::new(0);
        let out = retry_transient(
            6,
            || {
                let n = calls.get() + 1;
                calls.set(n);
                if n < 3 {
                    Err(io::Error::other(
                        "nix-store --load-db failed: database is locked",
                    ))
                } else {
                    Ok(n)
                }
            },
            |e| e.to_string().contains("--load-db"),
        );
        assert_eq!(out.unwrap(), 3, "it must succeed on the third attempt");
        assert_eq!(
            calls.get(),
            3,
            "it must have retried exactly to the success"
        );
    }

    #[test]
    fn retry_transient_stops_after_the_attempt_budget() {
        use std::cell::Cell;
        // A persistently transient error is retried up to the budget, then the last error is
        // returned — it never loops unbounded.
        let calls = Cell::new(0);
        let out: io::Result<()> = retry_transient(
            4,
            || {
                calls.set(calls.get() + 1);
                Err(io::Error::other("nix-store --load-db failed: still locked"))
            },
            |e| e.to_string().contains("--load-db"),
        );
        assert!(out.is_err());
        assert_eq!(
            calls.get(),
            4,
            "it must try exactly the budgeted number of times"
        );
    }

    #[test]
    fn retry_transient_does_not_retry_a_non_transient_error() {
        use std::cell::Cell;
        // A failure the predicate does not recognise (a real, deterministic error) surfaces at once,
        // without burning the retry budget — so a genuinely broken seed fails promptly.
        let calls = Cell::new(0);
        let out: io::Result<()> = retry_transient(
            6,
            || {
                calls.set(calls.get() + 1);
                Err(io::Error::other("nix-store --dump-db failed"))
            },
            |e| e.to_string().contains("--load-db"),
        );
        assert!(out.is_err());
        assert_eq!(calls.get(), 1, "a non-transient error must not be retried");
    }

    /// A name planted in the store's state while the registration ran fails it at once, by the path
    /// the host knows it at, where nix in its cage names it as that cage sees it. On a store whose
    /// state is its own, a failure keeps nix's reason and is retried.
    #[test]
    fn a_name_planted_while_the_registration_ran_is_refused_by_name_and_not_retried() {
        use std::cell::Cell;
        let nix_says = "nix-store --load-db failed (it sees the project's store at `/project`): \
                        error: creating directory \"/project/nix/var/nix/db\": File exists";
        let base = TmpDir::new();
        let store_dir = base.join("store");
        ensure_nix_state(&store_dir).unwrap();
        let calls = Cell::new(0);
        let failing = || {
            calls.set(calls.get() + 1);
            Err(io::Error::other(nix_says))
        };

        let err = retry_load(&store_dir, failing).unwrap_err();
        assert_eq!(calls.get(), LOAD_DB_ATTEMPTS, "a lost lock race is retried");
        assert_eq!(err.to_string(), nix_says, "nix's reason is lost");

        let db = store_dir.join("nix/var/nix/db");
        std::fs::remove_dir(&db).unwrap();
        symlink(base.join("elsewhere"), &db).unwrap();
        calls.set(0);
        let err = retry_load(&store_dir, failing).unwrap_err();
        assert_eq!(calls.get(), 1, "a planted name was retried: {err}");
        assert!(
            err.to_string().contains(&format!("`{}`", db.display())),
            "the refusal does not name `{}`: {err}",
            db.display()
        );
        assert!(
            db.symlink_metadata().unwrap().file_type().is_symlink(),
            "the planted link is left for the user to see"
        );
    }

    /// The collection's cage is given what nix's search for roots reads of the host and nothing
    /// more: a link standing in for an out-link that names a store path, one naming no store path
    /// for one that names something else, an empty directory for something that is not a link, and
    /// nothing for a target that is missing, inside the store, or under what the cage binds
    /// unchanged. A relative target is resolved against the root's own directory.
    #[test]
    fn the_collection_stands_in_for_what_its_roots_ask_of_the_host() {
        use super::super::spec::Mount;
        let base = TmpDir::new();
        let store_dir = base.join("store");
        ensure_nix_state(&store_dir).unwrap();
        let proj = base.join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let gcroots = gcroots_dir(&store_dir);
        let auto = gcroots.join("auto");
        std::fs::create_dir_all(&auto).unwrap();
        let built = PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-built");
        let other = PathBuf::from("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-other");

        symlink(&built, proj.join("result")).unwrap();
        symlink(proj.join("result"), auto.join("in-store")).unwrap();
        symlink("/etc/hostname", proj.join("elsewhere")).unwrap();
        symlink(proj.join("elsewhere"), auto.join("not-in-store")).unwrap();
        symlink(proj.join("absent"), auto.join("missing")).unwrap();
        std::fs::write(proj.join("file"), b"").unwrap();
        symlink(proj.join("file"), auto.join("not-a-link")).unwrap();
        symlink(&other, proj.join("rel")).unwrap();
        symlink("../../../../../../proj/rel", auto.join("relative")).unwrap();
        symlink(&other, gcroots.join("direct")).unwrap();
        symlink(store_dir.join("nix/var/nix/db"), auto.join("inside")).unwrap();
        symlink("/usr", auto.join("from-host")).unwrap();
        let profiles = store_dir.join("nix/var/nix/profiles");
        symlink(&built, profiles.join("profile")).unwrap();

        let mut staged = collection_standins(&store_dir).unwrap();
        staged.sort_by(|a, b| a.dest().cmp(b.dest()));
        assert_eq!(
            staged,
            [
                Mount::Symlink {
                    target: NOT_A_STORE_PATH.into(),
                    dest: proj.join("elsewhere"),
                },
                Mount::Tmpfs {
                    dest: proj.join("file"),
                },
                Mount::Symlink {
                    target: other,
                    dest: proj.join("rel"),
                },
                Mount::Symlink {
                    target: built,
                    dest: proj.join("result"),
                },
            ]
        );
    }

    /// A root whose answer the collection's cage cannot give as the host does refuses the
    /// collection, by name, rather than leaving it out: one under what the cage keeps for itself,
    /// one below another the host holds as a link, and more of them, or deeper, than it reads.
    #[test]
    fn a_root_the_collections_cage_cannot_stand_in_for_refuses_it() {
        let refused = |store_dir: &Path, why: &str| {
            let err = collection_standins(store_dir).expect_err(why);
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{why}: {err}");
            err.to_string()
        };

        let base = TmpDir::new();
        let store_dir = base.join("store");
        ensure_nix_state(&store_dir).unwrap();
        let auto = gcroots_dir(&store_dir).join("auto");
        std::fs::create_dir_all(&auto).unwrap();
        symlink("/proc/self/root/result", auto.join("own")).unwrap();
        let why = refused(&store_dir, "under the cage's /proc");
        assert!(why.contains("under `/proc`"), "{why}");
        std::fs::remove_file(auto.join("own")).unwrap();

        let proj = base.join("proj");
        std::fs::create_dir_all(proj.join("real")).unwrap();
        symlink(proj.join("real"), proj.join("link")).unwrap();
        symlink(
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x",
            proj.join("real/result"),
        )
        .unwrap();
        symlink(proj.join("link"), auto.join("outer")).unwrap();
        symlink(proj.join("link/result"), auto.join("inner")).unwrap();
        let why = refused(
            &store_dir,
            "a target below another the host holds as a link",
        );
        assert!(
            why.contains(&format!(
                "`{}` is a link on the host",
                proj.join("link").display()
            )),
            "{why}"
        );
        std::fs::remove_file(auto.join("outer")).unwrap();
        collection_standins(&store_dir).expect("the inner root alone is staged");
        std::fs::remove_file(auto.join("inner")).unwrap();

        let many = base.join("many");
        std::fs::create_dir_all(&many).unwrap();
        for i in 0..=STANDINS_MAX {
            std::fs::write(many.join(i.to_string()), b"").unwrap();
            symlink(many.join(i.to_string()), auto.join(format!("r{i}"))).unwrap();
        }
        let why = refused(&store_dir, "more stand-ins than the cage takes");
        assert!(
            why.contains(&format!("more than {STANDINS_MAX} places")),
            "{why}"
        );
        std::fs::remove_dir_all(&auto).unwrap();

        let mut deep = gcroots_dir(&store_dir);
        for _ in 0..=ROOTS_DEPTH_MAX {
            deep.push("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        let why = refused(&store_dir, "deeper than it reads");
        assert!(
            why.contains(&format!("more than {ROOTS_DEPTH_MAX} directories deep")),
            "{why}"
        );
    }

    /// The collection's cage binds nothing of the host's but its store, read-write from the
    /// descriptor at the store's own path, and what every engine needs read-only: no project, no
    /// home. It has no network, runs the arguments it is given, and takes the stand-ins last.
    #[test]
    fn the_collections_cage_binds_nothing_of_the_host_but_its_store() {
        use super::super::spec::{Mount, NetPolicy};
        let standin = Mount::Symlink {
            target: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".into(),
            dest: "/work/proj/result".into(),
        };
        let spec = store_cage(
            Path::new("/opt/engine/nix-store"),
            7,
            Path::new("/data/projects/p/store"),
            vec![standin.clone()],
            &[OsStr::new("--gc"), OsStr::new("--print-dead")],
        )
        .unwrap();
        let from_host: Vec<(&Path, &Path)> = spec
            .mounts
            .iter()
            .filter_map(|m| match m {
                Mount::Bind { src, dest }
                | Mount::RoBind { src, dest }
                | Mount::RoBindTry { src, dest }
                | Mount::DevBind { src, dest } => Some((src.as_path(), dest.as_path())),
                _ => None,
            })
            .collect();
        assert_eq!(
            from_host,
            [
                (Path::new("/usr"), Path::new("/usr")),
                (Path::new("/etc/ld.so.cache"), Path::new("/etc/ld.so.cache")),
                (Path::new("/nix/store"), Path::new("/nix/store")),
                (
                    Path::new("/opt/engine/nix-store"),
                    Path::new("/bin/nix-store")
                ),
                (
                    Path::new("/proc/self/fd/7"),
                    Path::new("/data/projects/p/store/nix")
                ),
            ]
        );
        assert!(
            matches!(spec.mounts.last(), Some(m) if *m == standin),
            "the stand-ins come last"
        );
        assert_eq!(spec.net, NetPolicy::Isolated);
        assert_eq!(
            spec.cmd,
            [
                "/bin/nix-store",
                "--store",
                "/data/projects/p/store",
                "--gc",
                "--print-dead"
            ]
            .map(std::ffi::OsString::from)
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
    use crate::testutil::{TmpDir, fingerprint};
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;

    /// `(nix, nix-store, bwrap)` when all three are present and bwrap can make the user namespace
    /// the registration's cage needs; otherwise `None` to skip.
    fn prerequisites() -> Option<(PathBuf, PathBuf, PathBuf)> {
        let bwrap = crate::pathfind::find_on_path("bwrap")
            .filter(|_| matches!(crate::probe_userns(), crate::Userns::Ok))?;
        Some((
            store::resolve_nix(None)?,
            store::resolve_nix_store(None)?,
            bwrap,
        ))
    }

    fn ino(path: &Path) -> (u64, u64) {
        let m = std::fs::symlink_metadata(path).unwrap();
        (m.dev(), m.ino())
    }

    /// Whether a store path named like `<hash>-<name>` is present in the project
    /// store's `nix/store`.
    fn present(store_dir: &Path, logical: &Path) -> bool {
        let name = logical.file_name().unwrap();
        store_dir.join("nix").join("store").join(name).exists()
    }

    #[test]
    fn seed_is_closure_scoped_consistent_isolated_and_tops_up() {
        let Some((nix, nix_store, bwrap)) = prerequisites() else {
            skip_incapable!("skipping projectstore smoke: need nix, nix-store, bwrap and userns");
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
        let engine = Engine::for_tests(&nix_store, &bwrap);
        let project = prepare(&engine, &layout, "smoke", std::slice::from_ref(&hello))
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
        let project = prepare(&engine, &layout, "smoke", &[hello.clone(), jq.clone()])
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
        let Some((nix, nix_store, bwrap)) = prerequisites() else {
            skip_incapable!(
                "skipping concurrent-seed smoke: need nix, nix-store, bwrap and userns"
            );
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
        let engine = Engine::for_tests(&nix_store, &bwrap);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| scope.spawn(|| prepare(&engine, &layout, "concurrent", roots)))
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

    /// The registration runs in its cage, through the real composition (the mandatory filters, the
    /// descriptor bind): on a store whose state is its own it creates the database there, and a
    /// link planted after the tree was held, the race a cage of the project running beside a
    /// launch can win, leads it nowhere on the host, absolute or climbing out by `..`.
    ///
    /// The control arm gives the same store and link to `nix-store` on the host, as the
    /// registration ran before it had a cage. It writes where the link points, so the link does
    /// reach the host and the caged arm's silence is the cage's. Neither arm is given a dump: nix
    /// opens and writes the database before it reads one, so no shared store is needed.
    #[test]
    fn the_registration_runs_in_its_cage_and_a_planted_link_reaches_nothing_of_the_host() {
        use std::process::{Command, Stdio};
        let Some(bwrap) = crate::pathfind::find_on_path("bwrap")
            .filter(|_| matches!(crate::probe_userns(), crate::Userns::Ok))
        else {
            skip_incapable!(
                "skipping the registration's cage: no bwrap or no capability-bearing userns"
            );
            return;
        };
        let Some(nix_store) = crate::store::resolve_nix_store(None) else {
            skip_incapable!("skipping the registration's cage: no nix-store");
            return;
        };
        let engine = Engine::for_tests(&nix_store, &bwrap);
        let caged = |nix_dir: &OwnedFd| {
            load_command(&engine, nix_dir)
                .unwrap()
                .stdin(Stdio::null())
                .output()
                .unwrap()
        };
        let entries = |dir: &Path| {
            let mut names: Vec<String> = std::fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };

        let base = TmpDir::new();
        let store_dir = base.join("store");
        ensure_nix_state(&store_dir).unwrap();
        let nix_dir = super::super::cagedir::hold_under(&store_dir, "nix", DIR_MODE).unwrap();
        let ran = caged(&nix_dir);
        assert!(
            ran.status.success(),
            "the load failed in its cage: {}",
            String::from_utf8_lossy(&ran.stderr)
        );
        assert!(
            store_dir.join("nix/var/nix/db/db.sqlite").is_file(),
            "the load ran without creating the project's database"
        );

        let base = TmpDir::new();
        let outside = base.join("outside");
        // The relative link sits in `<store>/nix/var/nix`, four levels below `base`.
        for (kind, target) in [
            ("absolute", outside.clone()),
            ("relative", PathBuf::from("../../../../outside")),
        ] {
            let store_dir = base.join(&format!("store-{kind}"));
            ensure_nix_state(&store_dir).unwrap();
            let nix_dir = super::super::cagedir::hold_under(&store_dir, "nix", DIR_MODE).unwrap();
            let _ = std::fs::remove_dir_all(&outside);
            std::fs::create_dir(&outside).unwrap();
            std::fs::write(outside.join("mine"), b"mine\n").unwrap();
            let db = store_dir.join("nix/var/nix/db");
            std::fs::remove_dir(&db).unwrap();
            std::os::unix::fs::symlink(&target, &db).unwrap();
            assert_eq!(
                std::fs::canonicalize(&db).unwrap(),
                std::fs::canonicalize(&outside).unwrap(),
                "{kind}: the planted link must reach the outside directory on the host"
            );

            caged(&nix_dir);
            assert_eq!(
                entries(&outside),
                ["mine"],
                "{kind}: the load in its cage wrote where the link points"
            );
            assert_eq!(std::fs::read(outside.join("mine")).unwrap(), b"mine\n");

            let host = Command::new(&nix_store)
                .env("NIX_REMOTE", "")
                .arg("--store")
                .arg(&store_dir)
                .arg("--load-db")
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert!(
                entries(&outside).len() > 1,
                "{kind}: the control arm on the host wrote nothing through the link, so this test \
                 shows nothing about the cage: {}",
                String::from_utf8_lossy(&host.stderr)
            );
        }
    }

    /// `sbx gc`'s collection runs in its cage and keeps a build whose only root is a `result` link
    /// outside the store, the way nix on the host keeps it, and the sweep collects what nothing
    /// roots.
    ///
    /// The control arm runs the same search in the same cage without the stand-ins: the build is
    /// then dead and its root unlinked as stale, even on a dry run. So what keeps it in the first
    /// arm is the stand-ins, and the cage alone would collect a build still in use.
    #[test]
    fn the_collection_runs_in_its_cage_and_keeps_a_build_rooted_outside_the_store() {
        use std::process::Stdio;
        let Some(bwrap) = crate::pathfind::find_on_path("bwrap")
            .filter(|_| matches!(crate::probe_userns(), crate::Userns::Ok))
        else {
            skip_incapable!(
                "skipping the collection's cage: no bwrap or no capability-bearing userns"
            );
            return;
        };
        let Some(nix_store) = crate::store::resolve_nix_store(None) else {
            skip_incapable!("skipping the collection's cage: no nix-store");
            return;
        };
        let base = TmpDir::new();
        let store_dir = base.join("store");
        ensure_nix_state(&store_dir).unwrap();
        let add = |name: &str| {
            let file = base.join(name);
            std::fs::write(&file, format!("{name}\n")).unwrap();
            let out = Command::new(&nix_store)
                .env("NIX_REMOTE", "")
                .arg("--store")
                .arg(&store_dir)
                .arg("--add")
                .arg(&file)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            PathBuf::from(String::from_utf8(out.stdout).unwrap().trim())
        };
        let built = add("built");
        let orphan = add("orphan");
        let proj = base.join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::os::unix::fs::symlink(&built, proj.join("result")).unwrap();
        let auto = gcroots_dir(&store_dir).join("auto");
        std::fs::create_dir_all(&auto).unwrap();
        std::os::unix::fs::symlink(proj.join("result"), auto.join("r")).unwrap();

        let engine = Engine::for_tests(&nix_store, &bwrap);
        let held = HeldStore::hold(&engine, &store_dir).unwrap();
        let dead = |roots: bool| {
            let out = held
                .command(&[OsStr::new("--gc"), OsStr::new("--print-dead")], roots)
                .unwrap()
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "the search failed in its cage: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };
        let named = |listed: &str, path: &Path| listed.lines().any(|l| Path::new(l) == path);

        let listed = dead(true);
        assert!(named(&listed, &orphan), "the orphan is not dead: {listed}");
        assert!(
            !named(&listed, &built),
            "the rooted build is dead: {listed}"
        );
        assert!(
            auto.join("r").symlink_metadata().is_ok(),
            "the root was unlinked as stale"
        );

        let report =
            crate::sandbox::gc::collect(&crate::sandbox::gc::StoreAt::Project(&held), true)
                .unwrap();
        assert_eq!(report.paths, 1);
        assert!(
            present(&store_dir, &built),
            "the sweep took the rooted build"
        );
        assert!(!present(&store_dir, &orphan), "the sweep left the orphan");

        let listed = dead(false);
        assert!(
            named(&listed, &built),
            "the control arm kept the build without the stand-ins, so this test shows nothing \
             about them: {listed}"
        );
        assert!(
            auto.join("r").symlink_metadata().is_err(),
            "the control arm left the root, so the cage did not find it stale"
        );
    }

    /// The collection in its cage decides as `nix-store` on the host does, for every shape of
    /// root the stand-ins answer for: two stores built alike, one searched on the host and one in
    /// the cage, leave the same paths dead and the same `gcroots/auto` links in place.
    ///
    /// The shapes are those nix was traced on: a `result` link to a store path, a missing one, one
    /// reached through a linked directory, a direct root that is a link to such a link, a profile,
    /// a link to something that is no store path, a regular file, and a relative target.
    #[test]
    fn the_collection_in_its_cage_decides_as_nix_on_the_host() {
        use std::process::Stdio;
        let Some(bwrap) = crate::pathfind::find_on_path("bwrap")
            .filter(|_| matches!(crate::probe_userns(), crate::Userns::Ok))
        else {
            skip_incapable!(
                "skipping the collection's parity: no bwrap or no capability-bearing userns"
            );
            return;
        };
        let Some(nix_store) = crate::store::resolve_nix_store(None) else {
            skip_incapable!("skipping the collection's parity: no nix-store");
            return;
        };
        let base = TmpDir::new();
        let proj = base.join("proj");
        let real = base.join("real");
        let ext = base.join("ext");
        for dir in [&proj, &real, &ext] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::os::unix::fs::symlink(&real, base.join("linked")).unwrap();
        let names = ["a", "b", "c", "d", "e", "f", "g"];
        for name in names {
            std::fs::write(base.join(name), format!("parity {name}\n")).unwrap();
        }
        // One store per arm, at the same depth below `base`, so a relative target leads to the
        // same place from either.
        let build = |arm: &str| -> (PathBuf, Vec<PathBuf>) {
            let store_dir = base.join(arm).join("store");
            ensure_nix_state(&store_dir).unwrap();
            let paths = names
                .iter()
                .map(|name| {
                    let out = Command::new(&nix_store)
                        .env("NIX_REMOTE", "")
                        .arg("--store")
                        .arg(&store_dir)
                        .arg("--add")
                        .arg(base.join(name))
                        .output()
                        .unwrap();
                    assert!(
                        out.status.success(),
                        "{}",
                        String::from_utf8_lossy(&out.stderr)
                    );
                    PathBuf::from(String::from_utf8(out.stdout).unwrap().trim())
                })
                .collect();
            (store_dir, paths)
        };
        let (host_store, paths) = build("host");
        let (cage_store, same) = build("cage");
        assert_eq!(paths, same, "both stores hold the same paths");

        let link = |target: &Path, at: &Path| {
            if at.symlink_metadata().is_err() {
                std::os::unix::fs::symlink(target, at).unwrap();
            }
        };
        link(&paths[0], &proj.join("result"));
        link(&paths[2], &real.join("result"));
        link(&paths[3], &ext.join("out"));
        link(Path::new("/etc/hostname"), &proj.join("elsewhere"));
        std::fs::write(proj.join("file"), b"").unwrap();
        link(&paths[6], &proj.join("rel"));
        for store_dir in [&host_store, &cage_store] {
            let gcroots = gcroots_dir(store_dir);
            let auto = gcroots.join("auto");
            std::fs::create_dir_all(&auto).unwrap();
            link(&proj.join("result"), &auto.join("result"));
            link(&proj.join("absent"), &auto.join("missing"));
            link(&base.join("linked/result"), &auto.join("through-a-link"));
            link(&ext.join("out"), &gcroots.join("direct"));
            link(&paths[4], &store_dir.join("nix/var/nix/profiles/profile"));
            link(&proj.join("elsewhere"), &auto.join("elsewhere"));
            link(&proj.join("file"), &auto.join("file"));
            link(
                Path::new("../../../../../../../proj/rel"),
                &auto.join("relative"),
            );
        }

        let dead = |out: std::process::Output| {
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let mut dead: Vec<String> = String::from_utf8(out.stdout)
                .unwrap()
                .lines()
                .map(str::to_string)
                .collect();
            dead.sort();
            dead
        };
        let left = |store_dir: &Path| {
            let mut names: Vec<String> = std::fs::read_dir(gcroots_dir(store_dir).join("auto"))
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        let on_host = dead(
            Command::new(&nix_store)
                .env("NIX_REMOTE", "")
                .arg("--store")
                .arg(&host_store)
                .args(["--gc", "--print-dead"])
                .stdin(Stdio::null())
                .output()
                .unwrap(),
        );
        let engine = Engine::for_tests(&nix_store, &bwrap);
        let held = HeldStore::hold(&engine, &cage_store).unwrap();
        let in_cage = dead(
            held.command(&[OsStr::new("--gc"), OsStr::new("--print-dead")], true)
                .unwrap()
                .stdin(Stdio::null())
                .output()
                .unwrap(),
        );

        let expected: Vec<String> = [&paths[1], &paths[5]]
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        assert_eq!(on_host, expected, "the host arm: only b and f are unrooted");
        assert_eq!(
            in_cage, on_host,
            "the cage left other paths dead than the host"
        );
        assert_eq!(
            left(&cage_store),
            left(&host_store),
            "the cage left other auto roots than the host"
        );
        assert!(
            !left(&host_store).contains(&"missing".to_string()),
            "the host arm kept the stale root, so this test shows nothing about its removal"
        );
    }
}
