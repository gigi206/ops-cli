//! Applying an image's layers into a root filesystem, in order.
//!
//! A layer is a tar of the changes it makes, so applying an image is unpacking each one over the
//! last. Two things make that more than a loop around an extractor.
//!
//! ## Whiteouts
//!
//! A layer cannot carry an absence, so a deletion is spelled as a file: `.wh.<name>` beside where
//! `<name>` would be means the entry is gone from here down, and `.wh..wh..opq` in a directory
//! means everything the lower layers put in that directory is gone. Neither marker is itself
//! written out. An applier that ignored them would produce a tree carrying files the image
//! deleted, which is the kind of failure that is silent until something reads one.
//!
//! ## Where a member is allowed to land
//!
//! Every destination is decided here, never by the archive. Three ways an archive tries to leave
//! its directory, and all three are refused rather than sanitised, because a member that wanted out
//! is not a member whose corrected path is worth writing:
//!
//! * an **absolute** path, which would land at the host's root;
//! * a `..` **component**, which climbs;
//! * a **symlink in the path**, which is the one that survives a naive check: layer one ships
//!   `etc -> /`, layer two ships `etc/passwd`, and an extractor that resolves the second path
//!   through the first writes to the host's `/etc/passwd`. So no component of a member's parent
//!   may be a symlink, checked against what is already on disk rather than against the archive.
//!
//! Unprivileged, so ownership is not restored and a device node or fifo is skipped rather than
//! failing the unpack: the cage runs as one uid and mounts the tree read-only, so an image's uid
//! table and its `/dev` entries describe a world it does not get.
//!
//! ## Two deliberate departures from the archive's modes
//!
//! The owner's read and write bits are **added** to every member, search as well on a directory,
//! and `setuid`/`setgid` are **removed**.
//!
//! Adding write is what lets a later layer replace a member of a read-only directory, and it is
//! what lets the tree be deleted again: a store that cannot be reclaimed without a recursive
//! `chmod` first is a store that leaks. It costs nothing where it shows, since the cage mounts the
//! tree read-only and every process in it runs as the one uid that already owns these files.
//!
//! Read comes along with it, which is worth saying out loud because it is visible: a member the
//! image published as `0o000` is readable in the cage. Nothing is reachable through that which the
//! same uid could not already read by unpacking the layer itself, and the alternative is a tree
//! whose own assembler cannot re-read what it wrote.
//!
//! Removing `setuid` is defence in depth rather than a fix: the cage is same-uid behind
//! `no_new_privs`, so a set-user-ID bit on a file this user already owns grants nothing. It is
//! dropped anyway, because a bit that grants nothing today is not a bit worth carrying into
//! whatever the cage looks like later.

use super::gzip::GzipReader;
use std::cell::Cell;
use std::fs;
use std::io::{self, BufReader};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

/// The most one image's layers may unpack to on disk, and the most entries they may create: a
/// member, or a directory made on the way to one.
///
/// The fetch is bounded ([`super::http::MAX_STREAMED_BODY`], 8 GiB per blob) and `safe_path` bounds
/// *where* a member lands, but nothing bounded how much arrives: gzip expands, so a blob inside the
/// fetch ceiling inflates to orders of magnitude more, and a layer of a million empty files
/// exhausts inodes without approaching either. Both ceilings are far above any userland: a full
/// Debian with every package installed is under 40 GiB and around half a million files, and the
/// images this is pointed at are bases an order of magnitude smaller than that.
///
/// The budget spans the **image**, not the layer, because the layers of one image are applied over
/// the same tree and a per-layer ceiling would multiply by however many the manifest lists.
///
/// A directory the unpack makes for a member's path counts as an entry of its own: one member names
/// as many directories as its path has components, and a path of a few kilobytes is close to two
/// thousand of them, each an inode and a block the byte ceiling does not see.
const MAX_UNPACKED_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub(super) const MAX_MEMBERS: u64 = 1_000_000;

/// What one image's unpack has spent, carried across its layers. See [`MAX_UNPACKED_BYTES`].
pub(super) struct Budget {
    bytes: u64,
    members: u64,
}

impl Budget {
    /// A fresh budget for one image.
    pub(super) fn new() -> Self {
        Self {
            bytes: 0,
            members: 0,
        }
    }

    /// The budget of an image whose earlier layers spent `bytes` and `members`: how a layer
    /// applied by a process of its own ([`super::unpack`]) takes up where the one before stopped.
    pub(super) fn resumed(bytes: u64, members: u64) -> Self {
        Self { bytes, members }
    }

    /// What the image has spent so far, in bytes written and entries created.
    pub(super) fn spent(&self) -> (u64, u64) {
        (self.bytes, self.members)
    }

    /// Count one entry, a member or a directory made for one, refusing past [`MAX_MEMBERS`].
    fn member(&mut self) -> io::Result<()> {
        // Saturating, because a resumed count is a number another process handed over.
        self.members = self.members.saturating_add(1);
        if self.members > MAX_MEMBERS {
            return Err(io::Error::other(format!(
                "this image's layers create more than {MAX_MEMBERS} entries (members, and the \
                 directories made to hold them), which is past what a userland is: refusing \
                 rather than filling the store's filesystem"
            )));
        }
        Ok(())
    }

    /// What is left of the byte ceiling.
    fn remaining_bytes(&self) -> u64 {
        MAX_UNPACKED_BYTES.saturating_sub(self.bytes)
    }

    /// Record `n` written bytes, refusing past [`MAX_UNPACKED_BYTES`].
    fn spend(&mut self, n: u64, dest: &Path) -> io::Result<()> {
        self.bytes = self.bytes.saturating_add(n);
        if self.bytes > MAX_UNPACKED_BYTES {
            return Err(io::Error::other(format!(
                "this image's layers unpack to more than {MAX_UNPACKED_BYTES} bytes (reached at \
                 `{}`): refusing rather than filling the store's filesystem",
                dest.display()
            )));
        }
        Ok(())
    }
}

/// The most the tar reader may read to reach the next member: its header block, the long name,
/// long link or PAX record describing it, and whatever the member before left unread.
///
/// The `tar` crate holds a long name, a long link or a PAX record whole in memory, at the size its
/// own header declares, while it looks for the member they describe: before that member reaches the
/// budget, and in bytes the budget never counts. Gzip expands, so a layer small enough to fetch
/// could declare a name of gigabytes and have this process hold it, and then copy it as a path.
/// Nothing in an honest layer comes near the bound: a path is at most `PATH_MAX`, 4 KiB, and an
/// extended attribute a PAX record carries at most 64 KiB.
const MAX_HEADER_BYTES: u64 = 1024 * 1024;

/// The layer as the tar reader reads it, refusing past what is left while [`unpack`] sets a limit.
/// See [`MAX_HEADER_BYTES`].
struct Metered<R> {
    inner: R,
    /// What may still be read before the next member, or `None` while a member is being read.
    left: Rc<Cell<Option<u64>>>,
}

impl<R: io::Read> io::Read for Metered<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(left) = self.left.get() else {
            return self.inner.read(buf);
        };
        if left == 0 && !buf.is_empty() {
            return Err(io::Error::other(format!(
                "a layer's member headers run past {MAX_HEADER_BYTES} bytes before the member they \
                 describe (a long name, a long link or a PAX record this large is not a \
                 userland's): refusing rather than holding them in memory"
            )));
        }
        let room = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..room])?;
        self.left.set(Some(left - n as u64));
        Ok(n)
    }
}

/// The prefix a deletion marker carries, and the exact name of the opaque-directory marker.
const WHITEOUT: &str = ".wh.";
const OPAQUE: &str = ".wh..wh..opq";

/// Apply the layer `blob` reads over `root`, creating `root` if it is not there yet.
///
/// `media_type` decides the framing: the gzip layer types are inflated, an uncompressed one is read
/// as a tar, and anything else is refused by name rather than guessed at. `zstd` layers are the
/// refusal that will be met in practice, and naming it is the point: an image pushed that way is
/// not unpacked wrongly, it is not unpacked at all.
pub(super) fn apply(
    blob: impl io::Read,
    media_type: &str,
    root: &Path,
    budget: &mut Budget,
) -> io::Result<()> {
    fs::create_dir_all(root)?;
    let file = BufReader::new(blob);
    if media_type.ends_with("+zstd") {
        return Err(io::Error::other(format!(
            "layer media type `{media_type}` is not supported (only tar and tar+gzip layers are)"
        )));
    }
    if media_type.ends_with("+gzip") || media_type.ends_with(".tar.gzip") || media_type.is_empty() {
        // An empty media type is the ambiguous case a hand-written manifest can produce; gzip is
        // the overwhelmingly common framing, and a tar that is not one fails at its header rather
        // than being written as garbage.
        return unpack(GzipReader::new(file)?, root, budget);
    }
    unpack(file, root, budget)
}

/// Walk one layer's members, applying each.
fn unpack<R: io::Read>(layer: R, root: &Path, budget: &mut Budget) -> io::Result<()> {
    let root = &Root::open(root)?;
    let left = Rc::new(Cell::new(None));
    let mut archive = tar::Archive::new(Metered {
        inner: layer,
        left: Rc::clone(&left),
    });
    let mut entries = archive.entries()?;
    loop {
        // Bounded while the tar reader looks for the next member, and only then: a member's own
        // data is read below, under the budget.
        left.set(Some(MAX_HEADER_BYTES));
        let next = entries.next();
        left.set(None);
        let Some(entry) = next else {
            return Ok(());
        };
        budget.member()?;
        let mut entry = entry?;
        // A PAX global header describes the archive rather than a member (`git archive` writes one
        // carrying the commit it archived), and every other reader ignores it. The tar reader hands
        // it on as an entry of its own, so it is skipped here rather than refused as a type this
        // does not write.
        if entry.header().entry_type() == tar::EntryType::XGlobalHeader {
            continue;
        }
        let path = entry.path()?.into_owned();
        resolvable(&path)?;
        let name = match path.file_name() {
            Some(raw) => match raw.to_str() {
                Some(name) => name,
                // A final component that is not UTF-8 cannot be compared against the whiteout
                // markers, and a name that cannot be read is a name that cannot be checked.
                None => {
                    return Err(io::Error::other(format!(
                        "layer member has an unreadable name: {}",
                        path.display()
                    )));
                }
            },
            // The archive's own root, `.` or `./`, which a good many images ship as their first
            // member: it names the directory the unpack is already writing into. There is nothing
            // to create and no marker to read, so skipping it is the whole of the handling. Refusing
            // it instead cost a `debian:12-slim` unpack its whole image, on a member every other
            // reader treats as a no-op.
            None if path.components().all(|c| matches!(c, Component::CurDir)) => continue,
            // Anything else with no final component is absolute or climbs out. `safe_path` is the
            // one definition of which, so it answers rather than a second rule here.
            None => {
                safe_path(root, &path)?;
                return Err(io::Error::other(format!(
                    "layer member `{}` names no file",
                    path.display()
                )));
            }
        };

        if name == OPAQUE {
            let parent = path.parent().unwrap_or(Path::new(""));
            // A marker at the layer's own root says everything the lower layers put at the root is
            // gone. `safe_path` refuses a member that names the root itself, which is right for a
            // member being *written* and wrong here: this one names a directory to empty, and
            // every other applier empties the root for it. Refusing cost the whole image.
            let dir = if parent.components().all(|c| matches!(c, Component::CurDir)) {
                root.path.to_path_buf()
            } else {
                safe_path(root, parent)?
            };
            clear_directory(&dir)?;
            continue;
        }
        if let Some(target) = name.strip_prefix(WHITEOUT) {
            // A whiteout deletes the entry beside it that it names. An empty name or `.` would name
            // the directory it sits in and remove it whole, and `..` the one above: none is an entry
            // beside the marker.
            if matches!(target, "" | "." | "..") {
                return Err(io::Error::other(format!(
                    "layer member `{}` is a whiteout that names no entry beside it",
                    path.display()
                )));
            }
            let parent = path.parent().unwrap_or(Path::new(""));
            let dest = safe_path(root, &parent.join(target))?;
            remove(&dest)?;
            continue;
        }

        let dest = safe_path(root, &path)?;
        write_member(&mut entry, &dest, root, budget)?;
    }
}

/// The tree a layer is applied over: its path, and a descriptor on it that the directories of each
/// member are resolved beneath ([`safe_path`]).
struct Root<'a> {
    path: &'a Path,
    dir: fs::File,
}

impl<'a> Root<'a> {
    fn open(path: &'a Path) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
            .open(path)?;
        Ok(Root { path, dir })
    }

    /// Refuse `rel` when one of the directories on the way to its final component, `parents`, is
    /// a symlink on disk.
    ///
    /// One `openat2` resolves them all, refusing to follow any link: a look at each directory in
    /// turn restarts from the root every time, so it costs the square of the depth, for every
    /// member of the layer. A resolution that stops at a directory that is missing, or at a
    /// component that is not one, met no link before it, and nothing past it is there to follow.
    /// On a kernel without the call (5.6 brought it) the look at each directory
    /// ([`Self::first_link`]) answers instead; any other failure refuses the member, since a check
    /// that could not run is not one that passed.
    fn check_parents(&self, rel: &Path, parents: &Path) -> io::Result<()> {
        let through = |link: Option<PathBuf>| {
            let link = link.map_or_else(String::new, |l| format!(" `{}`", l.display()));
            io::Error::other(format!(
                "layer member `{}` would be written through the symlink{link}",
                rel.display()
            ))
        };
        match self.resolve(parents) {
            Ok(()) => Ok(()),
            Err(e) => match e.raw_os_error() {
                Some(libc::ENOENT | libc::ENOTDIR) => Ok(()),
                Some(libc::ELOOP) => Err(through(self.first_link(rel))),
                Some(libc::ENOSYS) => self
                    .first_link(rel)
                    .map_or(Ok(()), |l| Err(through(Some(l)))),
                _ => Err(io::Error::other(format!(
                    "layer member `{}`: its directories cannot be resolved: {e}",
                    rel.display()
                ))),
            },
        }
    }

    /// `parents`, relative to the root, resolved without following a single link.
    fn resolve(&self, parents: &Path) -> io::Result<()> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(parents.as_os_str().as_bytes())
            .map_err(|_| io::Error::other("a layer member's path carries a NUL byte"))?;
        // SAFETY: `open_how` is three `u64`s, so all-zero is a valid value, and the one the kernel
        // reads as "unset" for the field this leaves alone.
        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
        how.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_BENEATH;
        // SAFETY: the descriptor is the root's, open for the whole call; `path` is a live
        // NUL-terminated string and `how` a live `open_how` of the size passed.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                self.dir.as_raw_fd(),
                path.as_ptr(),
                std::ptr::addr_of!(how),
                std::mem::size_of::<libc::open_how>(),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh descriptor the call returned, owned here and closed once, on drop.
        drop(unsafe { OwnedFd::from_raw_fd(fd as std::os::fd::RawFd) });
        Ok(())
    }

    /// The first directory on the way to `rel`'s final component that is a symlink on disk, looked
    /// at one at a time. The look stops at the first that is not there to look at: nothing past it
    /// is.
    fn first_link(&self, rel: &Path) -> Option<PathBuf> {
        let mut out = self.path.to_path_buf();
        let mut parents: Vec<_> = rel
            .components()
            .filter_map(|c| match c {
                Component::Normal(part) => Some(part),
                _ => None,
            })
            .collect();
        parents.pop();
        for part in parents {
            out.push(part);
            match out.symlink_metadata() {
                Ok(meta) if meta.file_type().is_symlink() => return Some(out),
                Ok(_) => {}
                Err(_) => return None,
            }
        }
        None
    }
}

/// Refuse a path the kernel would refuse to resolve: it names nothing a layer can hold. Checked
/// before any walk, since a whiteout or an opaque marker there creates nothing that would fail
/// instead.
fn resolvable(path: &Path) -> io::Result<()> {
    let longest = libc::PATH_MAX as usize - 1;
    let len = path.as_os_str().len();
    if len > longest {
        return Err(io::Error::other(format!(
            "a layer member names a path of {len} bytes, longer than the kernel resolves (at most \
             {longest})"
        )));
    }
    Ok(())
}

/// Resolve `rel` under `root`, refusing every shape that would leave it.
///
/// The symlink check looks at what is **on disk**, because that is what an `open` would follow: a
/// link planted by an earlier layer is exactly the case a check against the archive's own paths
/// misses. The final component is exempt because a layer replacing a link writes *at* it and not
/// *through* it, which is why every branch of `write_member` unlinks what is there before creating
/// anything.
fn safe_path(root: &Root<'_>, rel: &Path) -> io::Result<PathBuf> {
    resolvable(rel)?;
    let mut out = root.path.to_path_buf();
    // Which component is the last one, counted rather than compared against a rebuilt path: a
    // member spelled `./bin` has the same destination as `bin`, and a comparison would find the two
    // unequal and refuse the first for a symlink the second is allowed to replace.
    let last = rel
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count();
    let mut parents = PathBuf::new();
    let mut seen = 0;
    for component in rel.components() {
        match component {
            Component::Normal(part) => {
                seen += 1;
                out.push(part);
                if seen < last {
                    parents.push(part);
                }
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::other(format!(
                    "refusing layer member `{}`: it leaves the image root",
                    rel.display()
                )));
            }
        }
    }
    if out == *root.path {
        return Err(io::Error::other("a layer member names the root itself"));
    }
    if last > 1 {
        root.check_parents(rel, &parents)?;
    }
    Ok(out)
}

/// Remove whatever is at `path`, if anything. A whiteout for something no lower layer created is
/// not an error: layers are written against an assumed base, not against this one. Nothing there
/// is the one answer taken for none; a path that could not be looked at is not one that was empty.
fn remove(path: &Path) -> io::Result<()> {
    match path.symlink_metadata() {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if absent(&e) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Whether `e` says there is nothing at a path: nothing by that name, or a component on the way
/// that is not a directory.
fn absent(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// Empty a directory without removing it: what an opaque marker means.
///
/// A symlink is refused rather than followed. This is the one place that reads *through* the path
/// `safe_path` hands back, whose final component is deliberately left unresolved so that a layer
/// may replace a link: that holds for `write_member`, where every branch unlinks what is there
/// before creating anything, and it does not hold for a read of the entries below. A link has no
/// entries of its own, so an honest image never asks for this, and following one would empty the
/// directory it names instead.
fn clear_directory(dir: &Path) -> io::Result<()> {
    if dir
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
    {
        return Err(io::Error::other(format!(
            "an opaque marker names `{}`, which is a symlink: emptying it would reach through",
            dir.display()
        )));
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if absent(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries {
        remove(&entry?.path())?;
    }
    Ok(())
}

/// Create the directories missing on the way to `dir`, each counted as an entry of the budget.
///
/// `create_dir_all` made them for the price of the one member that named them, which is how a
/// single member could create thousands. See [`MAX_UNPACKED_BYTES`].
fn create_parents(dir: &Path, budget: &mut Budget) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut at = dir;
    while at.symlink_metadata().is_err() {
        missing.push(at);
        match at.parent() {
            Some(parent) => at = parent,
            None => break,
        }
    }
    for dir in missing.into_iter().rev() {
        budget.member()?;
        fs::create_dir(dir)?;
    }
    Ok(())
}

/// Write one member at `dest`.
fn write_member<R: io::Read>(
    entry: &mut tar::Entry<'_, R>,
    dest: &Path,
    root: &Root<'_>,
    budget: &mut Budget,
) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let kind = entry.header().entry_type();
    // `setuid`/`setgid`/sticky are masked off here rather than at each call below, so no path
    // through this function can carry one through by omission.
    let mode = entry.header().mode().unwrap_or(0o644) & 0o777;

    if let Some(parent) = dest.parent() {
        create_parents(parent, budget)?;
    }

    if kind.is_dir() {
        // `symlink_metadata`, never `is_dir`, which follows: the exemption for a final component
        // that is a link means `dest` may be one an earlier layer planted, and a link to a
        // directory answers `is_dir` with a yes about somewhere else entirely. Taking that yes
        // would skip the removal below and leave `set_permissions` to chmod that somewhere else.
        let present = dest.symlink_metadata().ok();
        if !present.is_some_and(|m| m.is_dir()) {
            // A later layer may replace a file, or a link, with a directory of the same name.
            remove(dest)?;
            fs::create_dir_all(dest)?;
        }
        // Owner write and search, so a later layer can add to this directory and `sbx gc` can
        // remove it.
        let _ = fs::set_permissions(dest, fs::Permissions::from_mode(mode | 0o700));
        return Ok(());
    }

    if kind.is_symlink() {
        let target = entry
            .link_name()?
            .ok_or_else(|| io::Error::other("a symlink member names no target"))?;
        remove(dest)?;
        // The *target* is not checked: a symlink is data until something follows it, and inside a
        // read-only cage root a link pointing out of the tree resolves against the cage's own root,
        // not the host's. What must not happen is writing *through* one, which `safe_path` refuses.
        std::os::unix::fs::symlink(target, dest)?;
        return Ok(());
    }

    if kind.is_hard_link() {
        let link = entry
            .link_name()?
            .ok_or_else(|| io::Error::other("a hard link member names no target"))?;
        let target = safe_path(root, &link)?;
        remove(dest)?;
        // A hard link to something no layer created cannot be made; copying is not equivalent and
        // guessing is worse, so the image is refused rather than silently changed.
        fs::hard_link(&target, dest).map_err(|e| {
            io::Error::other(format!(
                "hard link {} -> {}: {e}",
                dest.display(),
                target.display()
            ))
        })?;
        return Ok(());
    }

    // Three spellings of "this member is a file". A GNU sparse entry (`S`) is read back with its
    // holes as zeros, which [`copy_sparse`] leaves as holes, and a `7` (contiguous) is a regular
    // file on every filesystem this runs on: both took the fallback below and were dropped without
    // a word, so an image built by GNU tar with `--sparse` lost the file it declared.
    if kind.is_file() || kind.is_gnu_sparse() || kind == tar::EntryType::Continuous {
        remove(dest)?;
        let mut file = fs::File::create(dest)?;
        // Bounded by what the budget has left, plus the one byte that proves it was exceeded, so
        // a member declaring a terabyte writes the remainder of the ceiling and no more. The
        // header's own size is not the check: a tar reader is handed a stream, and a header that
        // understates its member would write past a ceiling read from it.
        let allowed = budget.remaining_bytes();
        let mut bounded = io::Read::take(&mut *entry, allowed + 1);
        let written = if kind.is_gnu_sparse() {
            copy_sparse(&mut bounded, &mut file)?
        } else {
            io::copy(&mut bounded, &mut file)?
        };
        budget.spend(written, dest)?;
        // The owner keeps read and write access whatever the archive says: the tree is assembled
        // by this user, a later layer has to be able to replace a member of it, and reclaiming the
        // store must not need a recursive `chmod` first.
        let _ = fs::set_permissions(dest, fs::Permissions::from_mode(mode | 0o600));
        return Ok(());
    }

    // A device node, fifo or socket: unprivileged creation would fail, and the cage mounts its own
    // `/dev` over whatever the image carries. Skipping is not a loss of anything the cage would use.
    if kind.is_block_special() || kind.is_character_special() || kind.is_fifo() {
        return Ok(());
    }
    // Anything else is a type this does not know how to write, and dropping it is how a member the
    // image declares goes missing in silence. Named and refused, the way every other shape this
    // cannot honour is: by the type flag its header carries, the name the tar format gives it, and
    // escaped, since the archive chose that byte.
    Err(io::Error::other(format!(
        "layer member `{}` is of a type this unpacker does not write (type flag `{}`)",
        dest.display(),
        std::ascii::escape_default(kind.as_byte())
    )))
}

/// Copy a sparse member's content into `file`, leaving its holes as holes, and return its length.
///
/// The tar reader hands a hole back as zeros, and written out they took the hole's whole size on
/// disk: a hole of a hundred mebibytes is a few bytes of a layer. A read that brought only zeros is
/// skipped over rather than written, and the file is given its length at the end, for a hole it
/// ends on. The length is still what the budget counts, since it is what the tar reader produced.
fn copy_sparse(from: &mut impl io::Read, file: &mut fs::File) -> io::Result<u64> {
    use std::io::{Seek, SeekFrom, Write};
    let mut buf = vec![0; 64 * 1024];
    let mut length = 0u64;
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if buf[..n].iter().all(|&b| b == 0) {
            file.seek(SeekFrom::Current(n as i64))?;
        } else {
            file.write_all(&buf[..n])?;
        }
        length += n as u64;
    }
    file.set_len(length)?;
    Ok(length)
}

#[cfg(test)]
mod tests;
