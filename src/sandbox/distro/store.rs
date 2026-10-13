//! Where a provisioned root filesystem lives, and the lock that pins which one.
//!
//! Three questions, answered in this order because each depends on the last:
//!
//! * **which image** — the locator from the config, and the digest a tag currently resolves to;
//! * **is it already here** — the tree is keyed by that digest, so the answer is a `stat`;
//! * **if not, unpack it** — fetch each layer and apply it, into a directory that only becomes the
//!   tree once every layer has landed.
//!
//! ## The digest is the pin, and the lock is what remembers it
//!
//! A tag moves. Resolving one costs a request to the registry, and a launch that did it every time
//! would both need the network and silently follow the tag wherever it went. So the resolution is
//! recorded in a lock beside the project's other state, and a launch that finds one does no
//! resolution at all: the digest names the tree, the tree is already unpacked, and nothing is
//! fetched. Moving to a new image is then an act ([`crate::cli::upgrade`]), never a side effect of
//! launching.
//!
//! A locator that already names a digest needs no resolution and locks to itself, so the lock's
//! shape is the same either way and the roll that refreshes it has one path rather than two.
//!
//! ## What the unpacked tree is, and is not
//!
//! It is the image's layers applied in order, plus the empty directories and files sbx's own mounts
//! need as mountpoints (see [`crate::sandbox::binds`] for why a read-only root cannot be given a
//! mountpoint at launch). It is never a place a cage writes: the launch binds it read-only, which
//! is what lets one copy serve every project on that digest.

use super::reference::{self, ImageRef, Reference};
use super::{layers, registry};
use crate::store::Layout;
use std::io;
use std::path::{Path, PathBuf};

/// The file recording a distribution locator and the digest it resolved to. Named beside the
/// channel lock (`nixpkgs.lock`) and in the same two-line format, so the two read alike and a
/// project's pinned state is one directory rather than two mechanisms.
pub(crate) const DISTRO_LOCK: &str = "distro.lock";

/// The prefix a derived userland's key carries, ahead of the `sha256:` its content hashes to.
///
/// A **distinct** form rather than a widened digest: `sha256:<hex>` is the grammar of a *registry*
/// digest and the registry client rests on it, so teaching that grammar a second meaning would put
/// a key nothing published where a digest is expected. Kept apart, a lock written by one form and
/// read by the other yields `None` and the launch re-resolves, which is the safe failure.
pub(crate) const DERIVED_PREFIX: &str = "derived:sha256:";

/// The key a derived userland is addressed by: the base digest and the commands, hashed together.
///
/// Both go in because both decide what the tree contains. Editing a command therefore builds a
/// different userland rather than mutating this one, and a base that moved does the same — which is
/// the answer to "if I change `run`, does it rebuild?" and to the same question about the base.
///
/// Each command is hashed behind its length, so two lists cannot hash alike by running into each
/// other: `["a", "bc"]` and `["ab", "c"]` are different userlands. A separator byte cannot promise
/// that, because a command may carry any byte a TOML string can: `["a\0bc"]` hashed like
/// `["a", "bc"]` behind a NUL separator, and launched on the tree those two commands built.
fn derived_key(base_digest: &str, run: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(base_digest.as_bytes());
    for command in run {
        hasher.update((command.len() as u64).to_le_bytes());
        hasher.update(command.as_bytes());
    }
    format!(
        "{DERIVED_PREFIX}{}",
        crate::plugins::catalogue::to_hex(&hasher.finalize())
    )
}

/// The file inside a derived tree recording the base digest it was built from.
///
/// The lock cannot answer this: its second line is the derived key, which is a hash *of* the base
/// digest and does not contain it. Without this file a roll would have nothing to compare the
/// registry's current answer against, and could only ever report "rebuilt" or nothing at all.
pub(crate) const BASE_FILE: &str = "base";

/// The directory holding one unpacked tree, keyed by its digest or its derived key.
///
/// Every `:` becomes `-`: a colon is a legal path byte on Linux, but this directory is named in
/// messages, in `PATH`-like lists and on command lines, and a component that needs quoting in half
/// of them is a component that will eventually be split in one of them. Both forms stay one path
/// component, and stay distinguishable: `sha256-<hex>` and `derived-sha256-<hex>`.
fn image_dir(layout: &Layout, key: &str) -> PathBuf {
    layout.distro_dir().join(key.replace(':', "-"))
}

/// The directory of holder markers beside a tree: one empty file per project that has launched on
/// it. See [`provision`] for why they exist and [`crate::sandbox::gc::sweep_distro_trees`] for what reads them.
pub(crate) const ROOTS_DIR: &str = "roots";

/// Provision the root filesystem `locator` names, and return the directory to bind at `/`.
///
/// `lock_path` is where this launch's pin is recorded — the project's own lock under a project
/// declaration, the shared one otherwise. It is written on every call, not only when it changes, so
/// that a tree provisioned before the lock existed still ends up pinned, unless it moved while this
/// call provisioned ([`pin_unless_moved`]).
///
/// `bwrap` starts the cage each layer is unpacked in ([`super::unpack`]).
///
/// `holder` is the runtime id of the project this launch is for, recorded as an empty file under
/// [`ROOTS_DIR`]. It is a garbage-collection root, in the sense nix uses the word: a lock says which
/// tree the *next* launch wants, and that is not the same question as which tree a *running* cage is
/// executing from. The two diverge for as long as a session outlives a roll, and removing a tree
/// under a live cage is not a degraded launch but a broken one, measured: the cage keeps its mount
/// and loses every file through it, so its own shell disappears mid-command.
///
/// Written on every launch and removed by nothing, which is what makes it self-healing: a marker is
/// read against the set of live sessions, so one left by a cage that crashed holds nothing, and
/// [`crate::sandbox::gc::sweep_distro_trees`] removes it when it sweeps.
pub(crate) fn provision(
    layout: &Layout,
    bwrap: &Path,
    locator: &str,
    lock_path: &Path,
    holder: &str,
    credential: Option<&str>,
    build: Option<&super::build::Context<'_>>,
) -> io::Result<PathBuf> {
    let credential = credential.map(registry::Credential::basic);
    let run: &[String] = build.map(|b| b.commands).unwrap_or_default();
    let image = reference::parse(locator).ok_or_else(|| {
        io::Error::other(format!(
            "`{locator}` is not a usable image locator (expected `oci:<registry>/<repository>:<tag>` or `…@sha256:<digest>`)"
        ))
    })?;

    // What the lock said before anything else happens, compared again before it is written.
    let read = crate::store::read_lock_lines(lock_path)?;
    let digest = match &image.reference {
        // A digest names the image itself, so there is nothing to resolve and nothing a registry
        // could answer differently.
        Reference::Digest(digest) => digest.clone(),
        Reference::Tag(_) => match locked_base(layout, lock_path, locator)? {
            Some(digest) => digest,
            None => registry::resolve(&image, credential.as_ref())?.digest,
        },
    };

    // What names the tree: the digest alone when the image is taken as published, the digest and
    // the commands together when it is derived.
    let key = if run.is_empty() {
        digest.clone()
    } else {
        derived_key(&digest, run)
    };
    let dir = image_dir(layout, &key);
    let rootfs = dir.join("rootfs");
    if !rootfs.is_dir() {
        unpack_into(
            bwrap,
            &image.pinned(&digest),
            &digest,
            &dir,
            credential.as_ref(),
            build,
        )?;
    }
    // Checked on every launch rather than once at unpack: the list of paths a distribution has to
    // supply is sbx's, so a tree unpacked by an earlier version is held to the current one.
    check_supplied(&rootfs, locator)?;
    let roots = dir.join(ROOTS_DIR);
    std::fs::create_dir_all(&roots)?;
    std::fs::File::create(roots.join(holder))?;
    pin_unless_moved(lock_path, locator, &key, &read)?;
    Ok(rootfs)
}

/// What a lock read as before a provision: its source line and its key line, as
/// [`crate::store::read_lock_lines`] answers them.
type LockRead = Option<(String, Option<String>)>;

/// Record `key` for `locator` in the lock, unless the lock moved since it was `read`; whether the
/// lock now pins `key`.
///
/// A launch reads the lock first, may spend up to an hour unpacking, and then pins what it
/// provisioned. An `sbx upgrade` that rolled the image in between has written the digest it
/// resolved, and writing here put the older one back without a word, so every later launch stayed
/// on it. A lock that no longer reads as it did is left to whoever wrote it, and the launch says
/// so: it still runs on the tree it provisioned, which its holder marker keeps from a sweep, and
/// the next launch takes the newer pin. A lock unchanged since the read is written, which is what
/// pins a tree provisioned before the lock existed. The comparison and the write are made under the
/// lock's writer guard ([`crate::store::hold_lock_for_write`]), which [`refresh`] takes for its own
/// write, so a roll cannot land between the two.
fn pin_unless_moved(
    lock_path: &Path,
    locator: &str,
    key: &str,
    read: &LockRead,
) -> io::Result<bool> {
    let _writing = crate::store::hold_lock_for_write(
        lock_path,
        &crate::store::waiting_for_writer("the image lock"),
    )?;
    let now = crate::store::read_lock_lines(lock_path)?;
    if now == Some((locator.to_string(), Some(key.to_string()))) {
        return Ok(true);
    }
    if now != *read {
        crate::diag::note(&format!(
            "the image lock `{}` changed while this launch provisioned `{}`, as when `sbx \
             upgrade` rolls the image meanwhile: this launch runs on what it provisioned and \
             leaves the lock as it now reads, which the next launch follows",
            lock_path.display(),
            crate::diag::visible(locator)
        ));
        return Ok(false);
    }
    crate::store::write_lock(lock_path, locator, key)?;
    Ok(true)
}

/// What a roll of the distribution lock did: the image it names, the digest it now records, and
/// what it recorded before.
///
/// `previous` is read across sources, not scoped to this locator, because the question it answers is
/// "was there a tree here that this roll supersedes?" — and a lock recording another image answers
/// yes. Changing the declared image repoints the cage root exactly as rolling a tag forward does,
/// which is the same distinction [`crate::store::LockTarget::previously_locked`] draws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rolled {
    pub(crate) locator: String,
    /// What the lock now records: the digest for an image taken as published, the derived key for
    /// one a `run` list builds.
    pub(crate) key: String,
    /// What it recorded before, whatever image wrote it.
    pub(crate) previous: Option<String>,
    /// The base digest behind [`Self::key`], and the one behind [`Self::previous`]. Equal to the
    /// key itself when nothing is derived.
    ///
    /// Carried apart from the keys because a derived key is a hash of its base and its commands:
    /// without them a roll could say that something changed but never which, and "the base moved"
    /// and "you edited a command" are different answers to the only question a roll is asked.
    pub(crate) base: String,
    pub(crate) previous_base: Option<String>,
}

/// Re-resolve `locator` and rewrite its lock, whatever the lock already said.
///
/// The one difference from [`provision`] is that the lock is not consulted: a roll exists precisely
/// to ask the registry again, so a tag that has moved is followed and one that has not reports no
/// change. A locator that names a digest resolves to itself, which is not a special case here but
/// the same answer the grammar already gives — a digest is the image.
///
/// Nothing is fetched or unpacked. The new digest names a tree the next launch provisions, on the
/// rule every channel here follows: a roll rewrites a lock, and the build happens when something is
/// actually run. Under [`crate::sandbox::RollMode::DryRun`] the registry is asked the same question
/// and the lock is left as it is.
pub(crate) fn refresh(
    layout: &Layout,
    locator: &str,
    run: &[String],
    lock_path: &Path,
    credential: Option<&str>,
    mode: crate::sandbox::RollMode,
) -> io::Result<Rolled> {
    let credential = credential.map(registry::Credential::basic);
    let image = reference::parse(locator)
        .ok_or_else(|| io::Error::other(format!("`{locator}` is not a usable image locator")))?;
    // Read across sources rather than scoped to this locator: the question is what this roll
    // supersedes, and a lock recording another image answers it.
    let previous = crate::store::read_lock_lines(lock_path)?.and_then(|(_, key)| key);
    // Only reported, so a base that cannot be read is said and left out rather than failing the
    // roll: what the roll writes does not depend on it.
    let previous_base = previous
        .as_deref()
        .and_then(|key| match recorded_base(layout, key) {
            Ok(base) => base,
            Err(e) => {
                crate::diag::note(&format!(
                    "the image lock `{}` recorded a tree whose base cannot be read ({e}), so this \
                     roll does not say which base it replaces",
                    lock_path.display()
                ));
                None
            }
        });
    let base = match &image.reference {
        Reference::Digest(digest) => digest.clone(),
        Reference::Tag(_) => registry::resolve(&image, credential.as_ref())?.digest,
    };
    let key = if run.is_empty() {
        base.clone()
    } else {
        derived_key(&base, run)
    };
    if mode.applies() {
        let _writing = crate::store::hold_lock_for_write(
            lock_path,
            &crate::store::waiting_for_writer("the image lock"),
        )?;
        crate::store::write_lock(lock_path, locator, &key)?;
    }
    Ok(Rolled {
        locator: locator.to_string(),
        key,
        previous,
        base,
        previous_base,
    })
}

/// The digest this lock records for `locator`, or `None` when it records another image or none.
///
/// Scoped to the locator so a lock left by a different image never resurfaces as this one's pin —
/// the same rule [`crate::store::LockTarget::locked_revision`] applies to a channel. Held to the
/// digest grammar here rather than trusted, because a lock is a file on disk and this value goes on
/// to name a directory.
fn locked_key(lock_path: &Path, locator: &str) -> io::Result<Option<String>> {
    let Some((source, key)) = crate::store::read_lock_lines(lock_path)? else {
        return Ok(None);
    };
    Ok((source == locator)
        .then_some(key)
        .flatten()
        .filter(|k| valid_key(k)))
}

/// Whether `key` is in one of the two forms that name a tree: a registry digest, or a derived key.
///
/// A key is read from a lock, which is a file on disk, and goes on to name a directory under the
/// distribution store ([`image_dir`]), so anything else — a `/`, a `..` — is not a key at all.
fn valid_key(key: &str) -> bool {
    // `DERIVED_PREFIX` is `derived:` ahead of the digest grammar's own `sha256:`, so what follows
    // `derived:` is held to that grammar whole.
    reference::valid_digest(key).is_some()
        || (key.starts_with(DERIVED_PREFIX)
            && key
                .strip_prefix("derived:")
                .and_then(reference::valid_digest)
                .is_some())
}

/// The base digest behind `key`: the key itself when it is a registry digest, and the [`BASE_FILE`]
/// of the tree it names when it is derived.
///
/// `Ok(None)` for a key in neither form, and for a derived tree that is gone or predates the file,
/// which callers read as "re-resolve". A file that is there and cannot be read is an error naming
/// it: read as absent, it sent every launch back to the registry without a word.
fn recorded_base(layout: &Layout, key: &str) -> io::Result<Option<String>> {
    if !valid_key(key) {
        return Ok(None);
    }
    if !key.starts_with(DERIVED_PREFIX) {
        return Ok(Some(key.to_string()));
    }
    let path = image_dir(layout, key).join(BASE_FILE);
    match std::fs::read_to_string(&path) {
        Ok(recorded) => Ok(reference::valid_digest(recorded.trim()).map(str::to_string)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!("cannot read `{}`: {e}", path.display()),
        )),
    }
}

/// The **base** digest this lock stands for: the key itself when the image is taken as published,
/// and the `base` file of the tree the key names when it is derived.
///
/// The indirection is what a derived key costs: it is a hash of the base digest, so the lock alone
/// cannot say which base it stands for. A tree that is gone, or one from before this file existed,
/// yields `None` and the launch re-resolves — the same safe failure a lock recording another image
/// gets. A `base` file that is there and cannot be read is an error ([`recorded_base`]).
fn locked_base(layout: &Layout, lock_path: &Path, locator: &str) -> io::Result<Option<String>> {
    match locked_key(lock_path, locator)? {
        Some(key) => recorded_base(layout, &key),
        None => Ok(None),
    }
}

/// What separates a staging directory's name from the pid that owns it.
///
/// Named because two modules spell it: the unpack that builds the name, and the sweep that reads
/// it back.
pub(crate) const PARTIAL_INFIX: &str = ".partial.";

/// The name an unpack assembles a tree under before renaming it into place:
/// `<final name>.partial.<pid>.<seq>`.
///
/// One definition because two parties depend on the shape. This side writes it; the sweep in
/// [`mod@crate::sandbox::gc`] recognises a staging by it and reclaims one only when the pid it
/// carries is gone. A spelling changed on this side alone leaves the sweep unable to see its own
/// subject, and a staging directory then falls to the rule written for a *published* tree — which
/// makes no liveness check, because a published tree has no owner to be alive.
///
/// `pid` and `seq` are parameters rather than read in here, so a caller naming a staging that is
/// not this process's — the sweep's own test — derives the name instead of rewriting it.
pub(crate) fn partial_staging_name(final_name: &str, pid: u32, seq: u64) -> String {
    format!("{final_name}{PARTIAL_INFIX}{pid}.{seq}")
}

/// Fetch every layer of `image` and apply it, then move the result into place.
///
/// Each layer is applied by [`super::unpack::apply`], in a cage `bwrap` starts whose only writable
/// path is the tree being assembled: the fetch happens here, the parsing of the layer there.
///
/// The tree is assembled under a sibling name and renamed at the end, so the directory a launch
/// binds at `/` exists only once every layer has landed: an interrupted unpack leaves a partial
/// directory that no launch will ever name, rather than a root filesystem missing half its files.
/// The name comes from [`partial_staging_name`], which carries this process's pid **and a sequence
/// number** so two launches provisioning the same image at once each assemble their own, and the
/// loser of the rename finds the winner's tree already there. The pid alone did not say that: a
/// single process provisions more than one image — a roll walks every declared one — and two of
/// those sharing a name meant the second emptied the tree the first was still writing into, since
/// the staging directory is cleared on the way in. The sequence number is what makes the name this
/// *call's* rather than this process's.
fn unpack_into(
    bwrap: &Path,
    image: &ImageRef,
    digest: &str,
    dir: &Path,
    credential: Option<&registry::Credential>,
    build: Option<&super::build::Context<'_>>,
) -> io::Result<()> {
    let parent = dir
        .parent()
        .ok_or_else(|| io::Error::other(format!("`{}` has no parent directory", dir.display())))?;
    std::fs::create_dir_all(parent)?;
    let partial = parent.join(partial_staging_name(
        &dir.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id(),
        crate::sandbox::atomicfile::unique(),
    ));
    let _ = std::fs::remove_dir_all(&partial);

    let outcome = (|| -> io::Result<()> {
        let blobs = partial.join("blobs");
        std::fs::create_dir_all(&blobs)?;
        let manifest = registry::resolve(image, credential)?;
        let rootfs = partial.join("rootfs");
        // One budget for the image, not one per layer, and one time to unpack it in: the layers are
        // applied over the same tree, so a per-layer ceiling would multiply by however many the
        // manifest lists.
        let mut budget = layers::Budget::new();
        let mut time_left = super::unpack::TIME_PER_IMAGE;
        for layer in &manifest.layers {
            let blob = registry::fetch_layer(image, layer, &blobs, credential)?;
            super::unpack::apply(
                bwrap,
                &blob,
                &layer.media_type,
                &rootfs,
                &mut budget,
                &mut time_left,
            )?;
            // Freed as soon as it is applied: the layers of one image can outweigh the tree they
            // produce, and keeping them all would double the cost of every provision for a set of
            // files nothing reads again.
            let _ = std::fs::remove_file(&blob);
        }
        std::fs::remove_dir_all(&blobs)?;
        // The commands run on the base, before the mountpoints and before the check: they see the
        // image as the image published it, and a command that removes something a userland has to
        // supply is caught by the check afterwards rather than hidden by a mountpoint created over
        // it. Then the base digest is recorded, because the key that names this tree is a hash of
        // it and cannot be read backwards.
        if let Some(build) = build {
            super::build::run(&rootfs, build)?;
            std::fs::write(partial.join(BASE_FILE), digest.as_bytes())?;
        }
        crate::sandbox::binds::create_distro_mountpoints(&rootfs)
    })();

    if outcome.is_err() {
        let _ = std::fs::remove_dir_all(&partial);
        return outcome;
    }
    // The tree reaches the device before its name does. Thousands of files are written above and
    // none is flushed, so a rename that reached the device first would leave, after a power loss, a
    // tree under the digest's name whose files hold zeros, and every later launch of the image
    // would take it as unpacked: its name and a handful of paths are all that is checked. One
    // `syncfs` on the tree's filesystem flushes them all, where a walk would `fsync` each file.
    if let Err(e) = sync_filesystem_of(&partial) {
        let _ = std::fs::remove_dir_all(&partial);
        return Err(io::Error::other(format!(
            "cannot flush the unpacked root filesystem for {digest}: {e}"
        )));
    }
    match std::fs::rename(&partial, dir) {
        Ok(()) => {
            crate::sandbox::atomicfile::sync_dir(parent);
            Ok(())
        }
        // Another launch provisioned the same digest first. Its tree is this one's tree — the
        // digest says so — so the loser drops what it built rather than overwriting a directory a
        // running cage may already be reading.
        Err(_) if dir.join("rootfs").is_dir() => {
            let _ = std::fs::remove_dir_all(&partial);
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&partial);
            Err(io::Error::other(format!(
                "cannot place the unpacked root filesystem for {digest}: {e}"
            )))
        }
    }
}

/// Flush every write pending on the filesystem that holds `path` to its device.
fn sync_filesystem_of(path: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;
    let dir = std::fs::File::open(path)?;
    // SAFETY: `syncfs` takes a descriptor this function holds open for the length of the call.
    if unsafe { libc::syncfs(dir.as_raw_fd()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Whether the image whose root is `root` carries `path`, an absolute path in it, and `image` how
/// a failure names that image.
///
/// A path is missing when looking it up says it is not there (`ENOENT`, or `ENOTDIR` for a parent
/// that is a file). Any other failure is not an answer about the image, and is reported as itself
/// rather than as a path the image lacks.
///
/// Looked up as the cage will see it: everything but the last component is resolved beneath the
/// image's root ([`crate::sandbox::attach::open_in_root`]), so a link the image carries reads
/// `..` and an absolute target as the image's, never the host's, and the last component is looked
/// at without following it, a link there being the image's business. Resolved on the host instead,
/// an image with no loader would pass through the host's own `/usr/lib64`, and a valid one whose
/// `lib64` names `/opt/…` would be refused on a host without that directory. A kernel without
/// `openat2` cannot resolve this way, and the lookup fails rather than resolving on the host.
pub(super) fn carries(root: &std::os::fd::OwnedFd, path: &str, image: &str) -> io::Result<bool> {
    const DIR: libc::c_int = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
    let relative = Path::new(path.trim_start_matches('/'));
    let parent = relative
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let looked = crate::sandbox::attach::open_in_root(root, parent, DIR).and_then(|dir| {
        crate::sandbox::attach::lstat_at(&dir, relative.file_name().unwrap_or_default())
    });
    match looked {
        Ok(_) => Ok(true),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(false)
        }
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOSYS | libc::EPERM)) => {
            Err(io::Error::new(
                e.kind(),
                format!(
                    "cannot look up `{path}` in {image} as the cage will see it: this kernel does \
                     not resolve a path beneath a root (`openat2`, Linux 5.6): {e}"
                ),
            ))
        }
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!("cannot look up `{path}` in {image}: {e}"),
        )),
    }
}

/// Refuse a tree that does not carry what a distribution has to supply.
///
/// The paths in [`crate::sandbox::binds::DISTRO_SUPPLIED`] are the ones sbx stops emitting once an
/// image is in force, and every one of them is a symlink or the ELF interpreter — neither of which
/// can be created at launch, because bubblewrap makes them at a destination whose parent is the
/// image's own read-only tree (`Can't make symlink at …: Read-only file system`). So an image
/// missing one leaves a cage without it, and the failure would surface much later as an exec error
/// naming a path nobody declared. Refusing here names the image and every path it lacks, each
/// looked up as the cage will see it ([`carries`]).
fn check_supplied(rootfs: &Path, locator: &str) -> io::Result<()> {
    let root = crate::sandbox::attach::open_dir_path(rootfs)?;
    let image = format!("the image `{locator}`");
    let mut missing: Vec<&str> = Vec::new();
    for p in crate::sandbox::binds::DISTRO_SUPPLIED.iter().copied() {
        if !carries(&root, p, &image)? {
            missing.push(p);
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "the image `{locator}` does not carry {}, which a distribution userland has to supply \
         (sbx cannot add them: they sit under the image's own read-only tree)",
        missing.join(", ")
    )))
}

#[cfg(test)]
mod tests;
