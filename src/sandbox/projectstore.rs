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
//! [`hold_dir_chain`]). What this cannot cover is `nix-store` itself, which opens
//! the same tree by name ([`ensure_nix_state`]).
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
    nix_store: &Path,
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
    let closure = closure_of(nix_store, &shared_store, roots)?;

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
        DirBuilder::new().mode(DIR_MODE).create(&to)?;
        // Opened, never re-entered by name: a link swapped in after the `mkdir` fails this open,
        // and what is placed below goes into the directory it reached.
        let made = OwnedFd::from(
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(&to)?,
        );
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
        std::os::unix::fs::symlink(fs::read_link(from)?, &to)?;
        Ok(true)
    } else {
        place_file(from, dir, name, reflink_ok)
    }
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
        .open(super::cagedir::entry(dir, name)?)?;
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
fn load_db(
    nix_store: &Path,
    shared_store: &Path,
    project_store: &Path,
    closure: &[PathBuf],
) -> io::Result<()> {
    // Retry a lost lock race. Several sandboxes of the same project can seed at once, and the
    // `--load-db` merge serialises on the project database's own lock (SQLite); under heavy
    // parallel load one attempt can exhaust nix's internal busy timeout and exit with the database
    // locked. The predicate deliberately retries ANY `--load-db`-half failure, not only a
    // recognized "locked" message — matching nix's exact lock wording would be fragile, and the
    // merge is idempotent (re-loading the same closure re-registers already-present paths as a
    // no-op), so a bounded retry is harmless even for a non-lock error: a genuinely broken seed (a
    // malformed dump) simply exhausts the small attempt budget and then fails, its captured reason
    // surfaced. The `--load-db` marker only distinguishes the load half from the dump half.
    retry_transient(
        LOAD_DB_ATTEMPTS,
        || load_db_once(nix_store, shared_store, project_store, closure),
        |e| e.to_string().contains("--load-db"),
    )
}

/// How many times [`load_db`] attempts the registration merge before giving up. Small: a lost lock
/// race clears in well under a second, and a deterministic failure exhausts the budget promptly.
const LOAD_DB_ATTEMPTS: u32 = 6;

/// One `--dump-db | --load-db` registration pass (see [`load_db`], which retries this on a lost
/// lock race). The `--load-db` half's stderr is captured so a failure carries nix's reason (a
/// locked database vs. a real error) — surfaced to the caller after the retry budget is spent.
fn load_db_once(
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
    #[expect(
        clippy::expect_used,
        reason = "the child was spawned with `stdout(Stdio::piped())` three lines above and \
                  nothing takes the handle first"
    )]
    let dump_out = dump.stdout.take().expect("stdout was requested as a pipe");
    // The reader child consumes the pipe directly, so a large dump never blocks on
    // a full pipe buffer; reap the writer only once the reader has finished.
    let load = Command::new(nix_store)
        .env("NIX_REMOTE", "")
        .arg("--store")
        .arg(project_store)
        .arg("--load-db")
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
            format!("nix-store --load-db failed: {reason}")
        }));
    }
    if !dump_status.success() {
        return Err(io::Error::other("nix-store --dump-db failed"));
    }
    Ok(())
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

/// The directories under `nix/` that `nix-store` writes into when it opens a store: the database,
/// the gc roots, the temporary roots, the gc socket and the deduplication pool.
const NIX_STATE_DIRS: &[&str] = &[
    "store/.links",
    "var/nix/db",
    "var/nix/gcroots",
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
/// `nix-store` runs on the host, as the user, against a tree the cage rewrites at will (see
/// [`ensure_dir_chain`]), and it opens each name below by path. So each directory of
/// [`NIX_STATE_DIRS`] must be a real directory, each file of [`NIX_STATE_FILES`] that exists must
/// be a regular file, and so must every entry of `temproots`, which `nix-store` names after its
/// own pid. Anything else is refused before `nix-store` is started, and left in place for the user
/// to see.
///
/// A missing directory is created, as `nix-store` would create it. The names are checked, not held:
/// the tree is still the cage's between this check and the `nix-store` run, which is why a live
/// cage keeps `sbx gc` away from its store.
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

    /// [`prepare`], waiting out the `ETXTBSY` a just-written executable meets under the parallel
    /// runner, which says nothing about `prepare` itself.
    fn prepare_past_etxtbsy(
        nix_store: &Path,
        layout: &Layout,
        roots: &[PathBuf],
    ) -> io::Result<()> {
        for _ in 0..100 {
            match prepare(nix_store, layout, "p", roots) {
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                other => return other.map(drop),
            }
        }
        panic!("the fake nix-store stayed held open for writing by another thread");
    }

    /// `nix-store` runs on the host, as the user, on a tree the cage writes, and opens by path the
    /// directories and files it keeps there. Each one the cage replaced is refused before
    /// `nix-store` starts, and left in place.
    #[test]
    fn nix_store_is_not_started_on_a_store_whose_state_the_cage_replaced() {
        let roots = [PathBuf::from(
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-base",
        )];
        // Every directory `nix-store` writes into, with each ancestor below `nix/`.
        let dirs = [
            "store/.links",
            "var",
            "var/nix",
            "var/nix/db",
            "var/nix/gcroots",
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

    /// And a store whose state is its own is still handed to `nix-store`, first seed or not: a
    /// check that refused everything would pass the test above while stopping every launch.
    #[test]
    fn a_store_whose_state_is_its_own_is_handed_to_nix_store() {
        let roots = [PathBuf::from(
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-base",
        )];
        for seeded_before in [false, true] {
            let base = TmpDir::new();
            let layout = Layout::under(&base.join("data"));
            let nix = store_dir_for(&layout, "p").join("nix");
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
            let ran = base.join("ran");
            let nix_store = fake_nix_store(base.path(), &ran);

            prepare_past_etxtbsy(&nix_store, &layout, &roots)
                .unwrap_or_else(|e| panic!("seeded before: {seeded_before}: {e}"));

            let runs = std::fs::read_to_string(&ran).unwrap_or_default();
            assert!(
                runs.contains("--load-db"),
                "seeded before: {seeded_before}: nix-store never registered the seed: {runs:?}"
            );
            for dir in [
                "store/.links",
                "var/nix/db",
                "var/nix/temproots",
                "var/nix/gc-socket",
            ] {
                let meta = std::fs::symlink_metadata(nix.join(dir)).unwrap();
                assert!(meta.is_dir(), "nix/{dir} is not a real directory");
            }
        }
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

    /// `(nix, nix-store)` when both are present; otherwise `None` to skip.
    fn prerequisites() -> Option<(PathBuf, PathBuf)> {
        Some((store::resolve_nix(None)?, store::resolve_nix_store(None)?))
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
        let Some((nix, nix_store)) = prerequisites() else {
            skip_incapable!("skipping projectstore smoke: need nix and nix-store");
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
            skip_incapable!("skipping concurrent-seed smoke: need nix and nix-store");
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
