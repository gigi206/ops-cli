//! What a tree really occupies on a filesystem that shares and compresses blocks, read extent by
//! extent.
//!
//! [`super::tree_usage`] counts `st_blocks`, which on a copy-on-write filesystem over-states both
//! what a tree occupies and what removing it frees: a store seeded by reflink reports its full
//! size while owning almost none of it. The kernel does say which blocks a file shares, through
//! `FS_IOC_FIEMAP`: a generic ioctl, unprivileged on any file the caller can open, that lists a
//! file's extents with their physical address and a `SHARED` flag. That is all `btrfs filesystem
//! du` reads too.
//!
//! This walks a tree once, attributes every file to an **owner** (a subtree the caller names, or
//! the rest), and answers per owner: what its files reference, and what is referenced by that
//! owner alone — the bytes removing all of its trees frees inside the filesystem. It is opt-in and
//! slower than a block count, since every regular file is opened and queried.
//!
//! Two things it still cannot see, and says so where it reports:
//!
//! - **Compression.** FIEMAP reports an extent's logical length, never its compressed size. The
//!   per-owner figures are therefore uncompressed; what the data occupies once compressed is known
//!   only for the whole filesystem, from its own space accounting.
//! - **References from outside the walk.** An extent shared with a file the walk never visits (a
//!   snapshot, a reflink copy elsewhere on the same filesystem) is taken for one owner's own when
//!   that owner is the only one seen referencing it.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

/// The last extent of the file.
const EXTENT_LAST: u32 = 0x1;
/// The extent's location is not known yet: no physical address to compare.
const EXTENT_UNKNOWN: u32 = 0x2;
/// Delayed allocation: written but not yet placed, so not shared with anything.
const EXTENT_DELALLOC: u32 = 0x4;
/// Compressed. btrfs then reports the extent's start as its physical address whatever part of it
/// the file references, and its logical length.
const EXTENT_ENCODED: u32 = 0x8;
/// Stored inside the filesystem's metadata rather than in a data extent.
const EXTENT_DATA_INLINE: u32 = 0x200;
/// Referenced more than once, by this file or another.
const EXTENT_SHARED: u32 = 0x2000;

/// One extent as FIEMAP reports it, reduced to what the accounting reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Extent {
    pub(crate) physical: u64,
    pub(crate) length: u64,
    pub(crate) flags: u32,
}

/// What one owner's files occupy.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OwnerUsage {
    /// Allocated bytes from `st_blocks`, every inode counted once across the whole walk: the
    /// figure [`super::tree_usage`] reports, on the same base as the rest of this report.
    pub(crate) blocks: u64,
    /// Inodes, each counted once across the whole walk.
    pub(crate) inodes: u64,
    /// Bytes the owner's files reference in data extents, before compression and counting every
    /// reference: what `btrfs filesystem du` calls the total.
    pub(crate) extent_bytes: u64,
    /// The part of `extent_bytes` no other owner references: freed inside the filesystem, before
    /// compression, once every tree of this owner is removed.
    pub(crate) exclusive_bytes: u64,
    /// Files whose contents are held inline in the metadata.
    pub(crate) inline_files: u64,
    /// Their apparent size. FIEMAP rounds an inline extent up to a sector, so its length would
    /// over-state them; these bytes are metadata, not data, and are never part of `extent_bytes`.
    pub(crate) inline_bytes: u64,
}

/// The whole walk.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ExtentReport {
    /// One entry per owner the caller named, in the same order, then one for the rest of the tree.
    pub(crate) owners: Vec<OwnerUsage>,
    /// Bytes the data extents hold once each is counted once, before compression.
    pub(crate) distinct_bytes: u64,
    /// Entries the walk could not read — a directory it could not list, a file it could not open
    /// or query. Their bytes are missing from every figure above.
    pub(crate) unreadable: u64,
}

impl ExtentReport {
    /// The figures of every owner added up.
    pub(crate) fn total(&self) -> OwnerUsage {
        self.owners.iter().fold(OwnerUsage::default(), |mut t, o| {
            t.blocks += o.blocks;
            t.inodes += o.inodes;
            t.extent_bytes += o.extent_bytes;
            t.exclusive_bytes += o.exclusive_bytes;
            t.inline_files += o.inline_files;
            t.inline_bytes += o.inline_bytes;
            t
        })
    }
}

/// Who references a shared extent: one owner, or several.
#[derive(Debug, Clone, Copy)]
enum Holders {
    One(usize),
    Many,
}

impl Holders {
    fn add(self, owner: usize) -> Self {
        match self {
            Holders::One(o) if o == owner => self,
            _ => Holders::Many,
        }
    }
}

/// The extent accounting, kept apart from the ioctl so it can be fed extents directly.
#[derive(Debug)]
struct Ledger {
    owners: Vec<OwnerUsage>,
    /// Bytes no file references twice, which need no comparison.
    unshared: u64,
    /// Shared compressed extents, keyed by their start: the longest reference seen, and who holds
    /// it. Every reference to a compressed extent reports the same start, so the key is the
    /// extent; its longest reference is a lower bound of its logical length.
    encoded: HashMap<u64, (u64, Holders)>,
    /// Shared uncompressed references as physical ranges. A reference to part of an extent reports
    /// that part's own address, so overlapping ranges are resolved by [`sweep`].
    plain: Vec<(u64, u64, usize)>,
}

impl Ledger {
    fn new(owners: usize) -> Self {
        Ledger {
            owners: vec![OwnerUsage::default(); owners],
            unshared: 0,
            encoded: HashMap::new(),
            plain: Vec::new(),
        }
    }

    /// Account one extent of a file belonging to `owner`, whose apparent size is `size`.
    fn record(&mut self, owner: usize, size: u64, e: Extent) {
        let usage = &mut self.owners[owner];
        if e.flags & EXTENT_DATA_INLINE != 0 {
            usage.inline_files += 1;
            usage.inline_bytes += size;
            return;
        }
        usage.extent_bytes += e.length;
        // An extent with no address yet cannot be compared with anything, and is not shared.
        if e.flags & EXTENT_SHARED == 0 || e.flags & (EXTENT_UNKNOWN | EXTENT_DELALLOC) != 0 {
            usage.exclusive_bytes += e.length;
            self.unshared += e.length;
        } else if e.flags & EXTENT_ENCODED != 0 {
            self.encoded
                .entry(e.physical)
                .and_modify(|(len, holders)| {
                    *len = (*len).max(e.length);
                    *holders = holders.add(owner);
                })
                .or_insert((e.length, Holders::One(owner)));
        } else if e.length > 0 {
            self.plain
                .push((e.physical, e.physical.saturating_add(e.length), owner));
        }
    }

    /// Resolve the shared extents: what each owner holds alone, and the distinct total.
    fn finish(mut self) -> (Vec<OwnerUsage>, u64) {
        let mut distinct = self.unshared;
        for (len, holders) in self.encoded.values() {
            distinct += len;
            if let Holders::One(o) = holders {
                self.owners[*o].exclusive_bytes += len;
            }
        }
        distinct += sweep(&self.plain, &mut self.owners);
        (self.owners, distinct)
    }
}

/// Lay the shared ranges out on the device: return the bytes they cover, and credit each owner
/// with the bytes only it covers.
fn sweep(ranges: &[(u64, u64, usize)], owners: &mut [OwnerUsage]) -> u64 {
    let mut events: Vec<(u64, bool, usize)> = Vec::with_capacity(ranges.len() * 2);
    for &(start, end, owner) in ranges {
        events.push((start, true, owner));
        events.push((end, false, owner));
    }
    events.sort_unstable();
    // Owner -> how many of its ranges cover the current position. An owner whose count drops to
    // zero is removed, so the map's length is the number of distinct owners covering it.
    let mut active: HashMap<usize, u32> = HashMap::new();
    let mut covered = 0;
    let mut at = 0;
    for (pos, opens, owner) in events {
        if pos > at && !active.is_empty() {
            let len = pos - at;
            covered += len;
            if active.len() == 1
                && let Some(only) = active.keys().next()
            {
                owners[*only].exclusive_bytes += len;
            }
        }
        at = pos;
        if opens {
            *active.entry(owner).or_insert(0) += 1;
        } else if let Some(n) = active.get_mut(&owner) {
            *n -= 1;
            if *n == 0 {
                active.remove(&owner);
            }
        }
    }
    covered
}

/// Extents fetched per ioctl.
const BATCH: usize = 128;

/// `struct fiemap_extent`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct RawExtent {
    logical: u64,
    physical: u64,
    length: u64,
    reserved64: [u64; 2],
    flags: u32,
    reserved: [u32; 3],
}

/// `struct fiemap` with room for [`BATCH`] extents after its header.
#[repr(C)]
#[derive(Debug)]
struct Request {
    start: u64,
    length: u64,
    flags: u32,
    mapped: u32,
    count: u32,
    reserved: u32,
    extents: [RawExtent; BATCH],
}

/// `_IOWR('f', 11, struct fiemap)`, the header alone being 32 bytes.
const FS_IOC_FIEMAP: libc::c_ulong = (3 << 30) | (32 << 16) | ((b'f' as libc::c_ulong) << 8) | 11;

/// Every extent of the open file `fd`, handed to `visit` in order.
fn file_extents(fd: i32, req: &mut Request, mut visit: impl FnMut(Extent)) -> io::Result<()> {
    let mut start = 0u64;
    loop {
        req.start = start;
        req.length = u64::MAX;
        req.flags = 0;
        req.mapped = 0;
        req.count = BATCH as u32;
        req.reserved = 0;
        // SAFETY: `req` is a `struct fiemap` followed by `count` extent slots, which is exactly
        // what the kernel reads and writes; `fd` is a file this function's caller holds open.
        if unsafe { libc::ioctl(fd, FS_IOC_FIEMAP as libc::Ioctl, req as *mut Request) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let got = (req.mapped as usize).min(BATCH);
        if got == 0 {
            return Ok(());
        }
        let mut last = false;
        for e in &req.extents[..got] {
            visit(Extent {
                physical: e.physical,
                length: e.length,
                flags: e.flags,
            });
            last |= e.flags & EXTENT_LAST != 0;
        }
        let tail = req.extents[got - 1];
        let next = tail.logical.saturating_add(tail.length);
        // A file rewritten under the walk could report an extent that does not move the cursor
        // forward; stopping there keeps the query from repeating itself forever.
        if last || next <= start {
            return Ok(());
        }
        start = next;
    }
}

/// Whether an ioctl error means the filesystem does not implement FIEMAP at all.
fn unsupported(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EOPNOTSUPP) | Some(libc::ENOTTY) | Some(libc::EINVAL)
    )
}

/// The walk's state, threaded through the recursion.
struct Walk<'a> {
    roots: &'a HashMap<PathBuf, usize>,
    seen: HashSet<(u64, u64)>,
    ledger: Ledger,
    request: Box<Request>,
    unreadable: u64,
    /// Whether some file answered FIEMAP, and whether one refused it as unsupported.
    answered: bool,
    refused: bool,
}

/// Measure `root`, attributing each entry to the owner one of whose paths in `owners` it lies under
/// (the deepest such path, should they nest), else to the rest. An owner may hold several trees:
/// an app's global home and its per-project ones are removed together, so they own together.
///
/// Symlinks are not followed and a hardlinked file counts once, under the owner it is first met
/// in: sbx's trees do not hardlink across one another (a store's `.links` pool stays under its own
/// root), so the owner is the one it belongs to. Fails when the root cannot be read, and when the
/// filesystem does not implement FIEMAP: there is then no extent to report, and zeros would read
/// as a measurement.
pub(crate) fn measure(root: &Path, owners: &[Vec<PathBuf>]) -> io::Result<ExtentReport> {
    let roots: HashMap<PathBuf, usize> = owners
        .iter()
        .enumerate()
        .flat_map(|(i, paths)| paths.iter().map(move |p| (p.clone(), i)))
        .collect();
    let rest = owners.len();
    let mut walk = Walk {
        roots: &roots,
        seen: HashSet::new(),
        ledger: Ledger::new(owners.len() + 1),
        request: Box::new(Request {
            start: 0,
            length: 0,
            flags: 0,
            mapped: 0,
            count: 0,
            reserved: 0,
            extents: [RawExtent::default(); BATCH],
        }),
        unreadable: 0,
        answered: false,
        refused: false,
    };
    let owner = roots.get(root).copied().unwrap_or(rest);
    let meta = root.symlink_metadata()?;
    walk.entry(root, &meta, owner);
    if walk.refused && !walk.answered {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "the filesystem holding {} does not report file extents (FIEMAP)",
                root.display()
            ),
        ));
    }
    let unreadable = walk.unreadable;
    let (owners, distinct_bytes) = walk.ledger.finish();
    Ok(ExtentReport {
        owners,
        distinct_bytes,
        unreadable,
    })
}

impl Walk<'_> {
    /// Count one entry already `lstat`ed, and descend into it or query its extents.
    fn entry(&mut self, path: &Path, meta: &std::fs::Metadata, owner: usize) {
        use std::os::unix::fs::MetadataExt;
        if !meta.is_dir() && meta.nlink() > 1 && !self.seen.insert((meta.dev(), meta.ino())) {
            return;
        }
        let usage = &mut self.ledger.owners[owner];
        usage.blocks += meta.blocks() * 512;
        usage.inodes += 1;
        if meta.is_dir() {
            self.dir(path, owner);
        } else if meta.is_file() {
            self.file(path, meta, owner);
        }
    }

    fn dir(&mut self, path: &Path, owner: usize) {
        let Ok(entries) = std::fs::read_dir(path) else {
            self.unreadable += 1;
            return;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                self.unreadable += 1;
                continue;
            };
            let child = entry.path();
            let Ok(meta) = child.symlink_metadata() else {
                self.unreadable += 1;
                continue;
            };
            let child_owner = self.roots.get(&child).copied().unwrap_or(owner);
            self.entry(&child, &meta, child_owner);
        }
    }

    fn file(&mut self, path: &Path, meta: &std::fs::Metadata, owner: usize) {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        use std::os::unix::io::AsRawFd;
        // Not following a link, and not waiting on a FIFO swapped in since the `lstat`.
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        else {
            self.unreadable += 1;
            return;
        };
        // The file opened must be the one counted: an entry replaced since the `lstat` is skipped
        // rather than measured under another file's name.
        match file.metadata() {
            Ok(m) if m.is_file() && m.dev() == meta.dev() && m.ino() == meta.ino() => {}
            _ => {
                self.unreadable += 1;
                return;
            }
        }
        let size = meta.size();
        let ledger = &mut self.ledger;
        match file_extents(file.as_raw_fd(), &mut self.request, |e| {
            ledger.record(owner, size, e)
        }) {
            Ok(()) => self.answered = true,
            Err(e) => {
                if unsupported(&e) {
                    self.refused = true;
                }
                self.unreadable += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(physical: u64, length: u64, flags: u32) -> Extent {
        Extent {
            physical,
            length,
            flags,
        }
    }

    #[test]
    fn an_unshared_extent_belongs_to_its_owner_alone() {
        let mut l = Ledger::new(2);
        l.record(0, 10, ext(4096, 8192, EXTENT_LAST));
        let (owners, distinct) = l.finish();
        assert_eq!(owners[0].extent_bytes, 8192);
        assert_eq!(owners[0].exclusive_bytes, 8192);
        assert_eq!(owners[1], OwnerUsage::default());
        assert_eq!(distinct, 8192);
    }

    /// The shape a seeded project store takes: the same extent referenced from two trees. Neither
    /// owns it, and it counts once in the distinct total.
    #[test]
    fn an_extent_shared_across_owners_is_nobodys_and_counts_once() {
        for flags in [EXTENT_SHARED, EXTENT_SHARED | EXTENT_ENCODED] {
            let mut l = Ledger::new(2);
            l.record(0, 0, ext(1 << 20, 65536, flags));
            l.record(1, 0, ext(1 << 20, 65536, flags));
            let (owners, distinct) = l.finish();
            assert_eq!(
                (owners[0].exclusive_bytes, owners[1].exclusive_bytes),
                (0, 0),
                "{flags:#x}"
            );
            assert_eq!(owners[0].extent_bytes + owners[1].extent_bytes, 131072);
            assert_eq!(distinct, 65536, "{flags:#x}");
        }
    }

    /// Shared, but only inside one owner (a reflink copy within an app's own home): removing that
    /// owner frees it, so it is that owner's.
    #[test]
    fn an_extent_shared_within_one_owner_is_that_owners() {
        for flags in [EXTENT_SHARED, EXTENT_SHARED | EXTENT_ENCODED] {
            let mut l = Ledger::new(2);
            l.record(1, 0, ext(1 << 20, 4096, flags));
            l.record(1, 0, ext(1 << 20, 4096, flags));
            let (owners, distinct) = l.finish();
            assert_eq!(owners[1].exclusive_bytes, 4096, "{flags:#x}");
            assert_eq!(owners[1].extent_bytes, 8192, "{flags:#x}");
            assert_eq!(distinct, 4096, "{flags:#x}");
        }
    }

    /// Every reference to a compressed extent reports its start, so references to different parts
    /// of it share one key, and the extent counts as long as its longest reference.
    #[test]
    fn references_to_one_compressed_extent_are_one_extent() {
        let mut l = Ledger::new(2);
        let flags = EXTENT_SHARED | EXTENT_ENCODED;
        l.record(0, 0, ext(1 << 20, 131072, flags));
        l.record(1, 0, ext(1 << 20, 16384, flags));
        let (owners, distinct) = l.finish();
        assert_eq!(distinct, 131072);
        assert_eq!(
            (owners[0].exclusive_bytes, owners[1].exclusive_bytes),
            (0, 0)
        );
    }

    /// An uncompressed reference to part of an extent reports that part's own address, so the
    /// ranges overlap without being equal. Only the bytes one owner covers alone are its own.
    #[test]
    fn overlapping_plain_ranges_split_into_shared_and_owned_parts() {
        let mut l = Ledger::new(3);
        // Owner 0 covers [0, 100), owner 1 [50, 150), owner 2 [150, 200) and again [180, 200).
        l.record(0, 0, ext(0, 100, EXTENT_SHARED));
        l.record(1, 0, ext(50, 100, EXTENT_SHARED));
        l.record(2, 0, ext(150, 50, EXTENT_SHARED));
        l.record(2, 0, ext(180, 20, EXTENT_SHARED));
        let (owners, distinct) = l.finish();
        assert_eq!(distinct, 200, "the union of the ranges");
        assert_eq!(owners[0].exclusive_bytes, 50, "[0, 50)");
        assert_eq!(owners[1].exclusive_bytes, 50, "[100, 150)");
        assert_eq!(
            owners[2].exclusive_bytes, 50,
            "[150, 200): adjacent to owner 1's range, and doubly covered by its own"
        );
    }

    /// Inline contents live in the metadata. FIEMAP rounds them to a sector, so their apparent size
    /// is what is reported, and none of it enters the data figures.
    #[test]
    fn an_inline_file_is_reported_apart_from_the_data() {
        let mut l = Ledger::new(1);
        l.record(
            0,
            56,
            ext(0, 4096, EXTENT_DATA_INLINE | EXTENT_ENCODED | EXTENT_LAST),
        );
        let (owners, distinct) = l.finish();
        assert_eq!((owners[0].inline_files, owners[0].inline_bytes), (1, 56));
        assert_eq!((owners[0].extent_bytes, distinct), (0, 0));
    }

    /// Delayed allocation and unknown placement carry no physical address (zero). Grouping them by
    /// that address would merge unrelated files into one "shared" extent.
    #[test]
    fn an_extent_with_no_address_yet_is_never_matched_with_another() {
        let mut l = Ledger::new(2);
        l.record(0, 0, ext(0, 4096, EXTENT_SHARED | EXTENT_DELALLOC));
        l.record(1, 0, ext(0, 4096, EXTENT_SHARED | EXTENT_UNKNOWN));
        let (owners, distinct) = l.finish();
        assert_eq!(
            (owners[0].exclusive_bytes, owners[1].exclusive_bytes),
            (4096, 4096)
        );
        assert_eq!(distinct, 8192);
    }

    /// A walk on a real filesystem: the test fixtures live under the user's cache, not on `/tmp`,
    /// so this reaches a filesystem that has FIEMAP on most hosts, and skips where it has none.
    #[test]
    fn a_real_walk_counts_a_hardlinked_file_once_and_attributes_it_by_path() {
        let base = crate::testutil::TmpDir::new();
        let app = base.join("apps/demo");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::create_dir_all(base.join("store")).unwrap();
        // Large enough to need a data extent rather than inline storage.
        let body = vec![7u8; 256 * 1024];
        std::fs::write(app.join("big"), &body).unwrap();
        std::fs::hard_link(app.join("big"), app.join("big-again")).unwrap();
        std::fs::write(base.join("store/other"), &body).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", base.join("store/link")).unwrap();
        // Written data may still be in delayed allocation; it counts as the owner's either way.
        let _ = std::fs::File::open(app.join("big")).and_then(|f| f.sync_all());
        let _ = std::fs::File::open(base.join("store/other")).and_then(|f| f.sync_all());

        let report = match measure(base.path(), &[vec![app.clone()], vec![base.join("store")]]) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                skip_incapable!("skipping: the fixtures' filesystem has no FIEMAP: {e}");
                return;
            }
            Err(e) => panic!("{e}"),
        };
        assert_eq!(report.unreadable, 0, "{report:?}");
        assert_eq!(report.owners.len(), 3);
        let (demo, store) = (report.owners[0], report.owners[1]);
        assert_eq!(
            demo.extent_bytes,
            body.len() as u64,
            "the hardlinked file once: {report:?}"
        );
        assert_eq!(demo.exclusive_bytes, body.len() as u64);
        assert_eq!(store.extent_bytes, body.len() as u64);
        assert_eq!(store.inodes, 3, "the directory, the file and the link");
        assert_eq!(report.distinct_bytes, 2 * body.len() as u64);
        assert_eq!(
            report.owners[2].inodes, 2,
            "the walk's root and `apps/` belong to the rest"
        );
    }

    #[test]
    fn a_missing_root_is_an_error_not_an_empty_report() {
        let base = crate::testutil::TmpDir::new();
        assert!(measure(&base.join("absent"), &[]).is_err());
    }

    /// An app's global home and its per-project home are removed together by `--purge`, so both
    /// trees' bytes and inodes add up under the one owner that holds them.
    #[test]
    fn an_owner_of_several_trees_adds_them_up_as_one() {
        let base = crate::testutil::TmpDir::new();
        let global = base.join("apps/demo");
        let project = base.join("projects/p1/apps/demo");
        for d in [&global, &project] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("data"), vec![1u8; 128 * 1024]).unwrap();
        }
        let report = match measure(base.path(), &[vec![global, project]]) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                skip_incapable!("skipping: the fixtures' filesystem has no FIEMAP: {e}");
                return;
            }
            Err(e) => panic!("{e}"),
        };
        assert_eq!(report.owners.len(), 2, "the one owner, then the rest");
        assert_eq!(report.owners[0].extent_bytes, 2 * 128 * 1024, "{report:?}");
        assert_eq!(report.owners[0].exclusive_bytes, 2 * 128 * 1024);
        assert_eq!(report.owners[0].inodes, 4, "two directories, two files");
    }
}
