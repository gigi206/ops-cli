//! A self-managed, compressed volume for sbx's data directory.
//!
//! sbx's data directory is the one tree that grows without bound — the shared nix store, a
//! runtime tree per project and a home per app. It is inode-heavy by nature (a store is a
//! multitude of small files), so on a filesystem whose inode table is fixed at creation it
//! can crowd the host long before the disk is full.
//!
//! This module lets sbx own a filesystem instead of borrowing the host's: a sparse image
//! file carrying a btrfs filesystem, mounted with compression. The whole tree then costs the
//! host **one inode**, occupies only what is actually written, and — because the filesystem
//! shares blocks between files — the per-project store seeding sbx already performs stops
//! being a physical copy.
//!
//! # Why it needs no privilege
//!
//! Creating a filesystem, attaching a loop device and mounting are privileged operations, yet
//! the whole chain runs as an ordinary user:
//!
//! - `mkfs.btrfs --rootdir <dir>` builds the image from a seed directory and gives the
//!   filesystem root **that directory's ownership** — without it the root belongs to `root`
//!   and the invoking user cannot write a byte into their own volume.
//! - `udisks` performs the loop attach and the mount over D-Bus, and ships polkit rules
//!   granting both to a **locally active** session without authentication.
//!
//! That last point bounds where this works: a remote, headless or inactive session falls
//! under a rule requiring administrator authentication, so it cannot mount unattended. The
//! feature is therefore opt-in and never a prerequisite — sbx without a volume behaves
//! exactly as before.
//!
//! # What is deliberately not shelled out
//!
//! Compression is set through the `btrfs.compression` extended attribute rather than
//! `btrfs property set`, and space accounting through an ioctl rather than
//! `btrfs filesystem usage`. Both work unprivileged, so `btrfs-progs` is needed only to
//! *create* a volume, never to use one.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The filesystem label, which is also the last component of the directory `udisks` mounts
/// at. Kept short: the mount point becomes sbx's data directory, and sockets bound under it
/// must fit a Unix socket path.
pub(crate) const DEFAULT_LABEL: &str = "sbx-storage";

/// The default image location — a *sibling* of the default data directory, never inside it,
/// since the volume is what that directory becomes.
pub(crate) const DEFAULT_IMAGE_NAME: &str = "sbx-storage.btrfs";

/// The logical size of a volume created without an explicit one. The image is sparse, so this
/// is a ceiling rather than an allocation: a fresh volume occupies a few megabytes.
pub(crate) const DEFAULT_SIZE_BYTES: u64 = 200 * 1024 * 1024 * 1024;

/// The smallest volume worth creating. Below this btrfs itself struggles, and a store needs
/// far more anyway.
const MIN_SIZE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Where a volume is in its lifecycle. Distinguishing "attached but not mounted" from
/// "absent" matters: they need different repairs, and conflating them would let a half-set-up
/// volume look like no volume at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum State {
    /// No image file.
    Absent,
    /// The image exists but no loop device is backed by it.
    Detached,
    /// A loop device is attached, but nothing is mounted from it.
    Attached { loop_dev: String },
    /// Mounted and usable. `mount_point` is what `SBX_DATA_DIR` should name.
    Mounted {
        loop_dev: String,
        mount_point: PathBuf,
        options: String,
    },
}

impl State {
    /// The mount point, when there is one.
    pub(crate) fn mount_point(&self) -> Option<&Path> {
        match self {
            State::Mounted { mount_point, .. } => Some(mount_point.as_path()),
            _ => None,
        }
    }
}

/// The default image path for a given XDG data base — `<base>/sbx-storage.btrfs`, beside the
/// `<base>/sbx/` directory it stands in for.
pub(crate) fn default_image(xdg_data_base: &Path) -> PathBuf {
    xdg_data_base.join(DEFAULT_IMAGE_NAME)
}

/// The file, in the *default* data directory, recording that sbx's data has moved into a
/// volume. Its presence is what makes every later command mount and follow that volume, so
/// adopting one is a single deliberate act rather than a variable each shell must carry.
pub(crate) const POINTER: &str = "storage.toml";

/// Read the image a pointer names, if the default data directory carries one.
///
/// Deliberately hand-parsed rather than deserialized: this runs before anything else sbx
/// does, on a file it wrote itself, and a whole parser in that position is a dependency the
/// resolution path does not need.
pub(crate) fn read_pointer(default_data_dir: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(default_data_dir.join(POINTER)).ok()?;
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("image") else {
            continue;
        };
        let Some(value) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        if !value.is_empty() {
            return Some(PathBuf::from(value));
        }
    }
    None
}

/// Whether the pointer file can name `image` — the one rule [`write_pointer`] writes by and the
/// command that parses `--image` refuses by, so a path that cannot be recorded is rejected before a
/// volume is mounted rather than after.
///
/// The value goes into the file as a TOML basic string on one line, and [`read_pointer`] takes it
/// back with `trim`/`trim_matches('"')` and no unescaping at all. Three kinds of character break
/// that, each in its own way, and none of them loudly:
///
/// - a **line break** ends the line, so what comes back is the *prefix* before it and sbx follows a
///   path that is not the one recorded. The reader keeps the first `image` line it can read, so a
///   second one written past the break is dead — except where the break is the value's first
///   character, which leaves that first line empty and hands the reader the injected one instead;
/// - a **quote** is eaten by `trim_matches`, which strips every one it finds at either end, so a
///   path that begins or ends with one comes back short;
/// - a **backslash**, and any other control character, leaves the file no longer valid TOML, which
///   the file promises to be for anything that reads it as such. This hand parser would return the
///   backslash unharmed; the promise is what it breaks.
///
/// A fourth is not a character at all. A Linux path is bytes, and one that is not valid UTF-8 is a
/// path like any other, which `--image` takes from argv unchanged; but the file is text, written
/// through `Display`, so those bytes land as `U+FFFD` and come back as a path that is not the one
/// adopted. Refused for that reason, and no other: nothing here objects to the bytes.
///
/// So the rule is what a basic string carries with no escaping: UTF-8, printable characters, and
/// neither `"` nor `\`. Refusing is right rather than escaping — an escape needs a decoder, and
/// [`read_pointer`] runs before everything else sbx does, on the resolution path, where a
/// round-trip bug would point the whole installation at the wrong data directory in silence.
pub(crate) fn pointer_can_name(image: &Path) -> Result<(), String> {
    let refuse = |what: &str| {
        Err(format!(
            "the volume image path cannot be recorded: it {what}, and `{POINTER}` cannot carry that \
             (the path is stored as one quoted line of text, unescaped). Give the image a path that \
             is valid UTF-8 with no control character, quote or backslash — `--image` takes any \
             absolute path."
        ))
    };
    let Some(shown) = image.to_str() else {
        return refuse("is not valid UTF-8");
    };
    match shown
        .chars()
        .find(|c| c.is_control() || *c == '"' || *c == '\\')
    {
        None => Ok(()),
        Some(c) => refuse(&match c {
            '"' => "contains a quote".to_string(),
            '\\' => "contains a backslash".to_string(),
            '\n' => "contains a line break".to_string(),
            other => format!("contains the control character U+{:04X}", other as u32),
        }),
    }
}

/// The scratch file [`write_pointer`] fills before the rename, named per process.
///
/// A shared name would void the atomicity the rename is there for. Two writers open it, and both
/// hold a descriptor on the same inode: whichever renames first publishes it *while the other is
/// still writing into it*, so the loser's bytes land in the live `storage.toml`, at offset zero, in
/// a file it already truncated. Measured with that interleaving forced, the published file holds one
/// writer's record followed by the tail of the other's — the partial the comment at the rename says
/// cannot happen. `read_pointer` still finds a path there, since the surviving tail is the middle of
/// one and can spell no header; what is lost is the file being the TOML it promises to be.
///
/// Per process rather than per call: one process writes this file once per command, and the same
/// shape (`std::process::id`) already names the temp of the egress rollup.
fn pointer_tmp_name() -> String {
    format!(".{POINTER}.tmp.{}", std::process::id())
}

/// Record that sbx's data lives in the volume backed by `image`.
///
/// Refuses a path [`pointer_can_name`] rules out. That guard is here, and not only at the command
/// that parses `--image`, because this is the function that owes the file its shape: every caller
/// reaches the format through it, and one that forgot to ask would otherwise write a file no reader
/// can take back.
pub(crate) fn write_pointer(default_data_dir: &Path, image: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    pointer_can_name(image).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(default_data_dir)?;
    let path = default_data_dir.join(POINTER);
    let tmp = default_data_dir.join(pointer_tmp_name());
    // The value needs no escaping — `pointer_can_name` is what makes that true — and quoting it
    // keeps the file valid TOML for anyone who reads it as such.
    std::fs::write(
        &tmp,
        format!(
            "# sbx's data lives in this volume. Remove this file (or run `sbx storage unuse`)\n\
             # to go back to using this directory directly.\n\
             image = \"{}\"\n",
            image.display()
        ),
    )?;
    // Renamed into place so a reader sees the old file or the new one, never a partial. The
    // temp's name is what makes that true for a *second* writer as well — see [`pointer_tmp_name`].
    std::fs::rename(&tmp, &path)
}

/// Stop following a volume. The volume and its contents are untouched.
pub(crate) fn clear_pointer(default_data_dir: &Path) -> io::Result<()> {
    match std::fs::remove_file(default_data_dir.join(POINTER)) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// The file recording that the one-time offer to adopt a volume has been shown. Its presence is
/// what makes the offer happen exactly once — whatever the answer was — so a declined suggestion
/// never becomes a nag. Kept beside the pointer in the *default* data directory, so it survives
/// whether or not a volume is adopted.
pub(crate) const OFFERED_MARKER: &str = ".storage-offered";

/// Whether the one-time volume offer has already been shown.
pub(crate) fn has_been_offered(default_data_dir: &Path) -> bool {
    default_data_dir.join(OFFERED_MARKER).exists()
}

/// Record that the one-time volume offer has been shown. Best-effort: the worst a failed write
/// costs is the offer appearing once more, never a broken launch, so it is never fatal.
pub(crate) fn mark_offered(default_data_dir: &Path) {
    use std::os::unix::fs::DirBuilderExt;
    let _ = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(default_data_dir);
    let _ = std::fs::write(default_data_dir.join(OFFERED_MARKER), b"");
}

/// Make sure the volume is mounted, and return where. Idempotent, and cheap when it already
/// is: the check reads two kernel tables and starts no process.
pub(crate) fn ensure_mounted(image: &Path) -> Result<PathBuf, String> {
    if let Ok(State::Mounted {
        mount_point,
        options,
        ..
    }) = state(image)
    {
        // Checked on the way out, not only where the mount is made — see [`refuse_noexec`].
        return refuse_noexec(mount_point, &options);
    }
    up(image)
}

/// Whether a label is safe to become both a filesystem label and a path component. Refuses
/// anything that could traverse or confuse a mount point.
pub(crate) fn is_valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 32
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Parse a human size such as `200G` into bytes. Suffixes are binary (`G` = 2^30), because
/// that is what every filesystem tool reports back. A bare number is bytes.
pub(crate) fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (digits, mult) = match s.as_bytes().last() {
        Some(b'G' | b'g') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        Some(b'T' | b't') => (&s[..s.len() - 1], 1024_u64.pow(4)),
        Some(b'M' | b'm') => (&s[..s.len() - 1], 1024 * 1024),
        _ => (s, 1),
    };
    let n: u64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("not a size: {s} (try 200G)"))?;
    let bytes = n
        .checked_mul(mult)
        .ok_or_else(|| format!("size too large: {s}"))?;
    if bytes < MIN_SIZE_BYTES {
        return Err(format!(
            "size too small: {s} (at least {}G)",
            MIN_SIZE_BYTES / (1024 * 1024 * 1024)
        ));
    }
    Ok(bytes)
}

/// Extract the loop device from `udisksctl loop-setup` output, which reads
/// `Mapped file <path> as /dev/loop3.`
pub(crate) fn parse_loop_setup(out: &str) -> Option<String> {
    let (_, tail) = out.rsplit_once(" as ")?;
    Some(tail.trim().trim_end_matches('.').to_string())
}

/// Extract the mount point from `udisksctl mount` output, which reads
/// `Mounted /dev/loop3 at /run/media/you/sbx-storage`.
///
/// The path is read back rather than constructed: `udisks` decides it, and it varies with the
/// version (`/run/media` or `/media`) and disambiguates a label collision by appending a digit.
pub(crate) fn parse_mount(out: &str) -> Option<PathBuf> {
    let (_, tail) = out.rsplit_once(" at ")?;
    let p = tail.trim().trim_end_matches('.');
    (!p.is_empty()).then(|| PathBuf::from(p))
}

/// Find where a device is mounted, and with which options, by reading a `mountinfo` table.
///
/// Pure over the table's text so it is testable without a mount.
///
/// The format is `id parent maj:min root mountpoint options ... - fstype source superopts`;
/// the source after the separator is what names the device.
pub(crate) fn mount_of(device: &str, mountinfo: &str) -> Option<(PathBuf, String)> {
    for line in mountinfo.lines() {
        // A line that does not parse is skipped, never fatal: the table is the kernel's and
        // carries whatever else is mounted, so one unexpected line must not end the search
        // before the device we are looking for is reached.
        let Some((head, tail)) = line.split_once(" - ") else {
            continue;
        };
        let mut fields = head.split(' ');
        let (Some(mount_point), Some(options)) = (fields.nth(4), fields.next()) else {
            continue;
        };
        let Some(source) = tail.split(' ').nth(1) else {
            continue;
        };
        if source == device {
            return Some((PathBuf::from(unescape_mountinfo(mount_point)), {
                let super_opts = tail.split(' ').nth(2).unwrap_or("");
                if super_opts.is_empty() {
                    options.to_string()
                } else {
                    format!("{options},{super_opts}")
                }
            }));
        }
    }
    None
}

/// Whether a comma-separated mount-option string carries the exact `noexec` flag.
///
/// Exact token, not substring: an option that merely contains those letters (`noexecfoo`) is a
/// different flag, and matching it would refuse a perfectly runnable volume. The flag sbx does
/// forbid is precisely the one that stops a store's binaries from running. Fed the same option
/// string [`mount_of`] returns.
fn mount_is_noexec(options: &str) -> bool {
    options.split(',').any(|o| o == "noexec")
}

/// Refuse a mount point whose options say `noexec`, or pass it through.
///
/// Applied wherever a mount point is **returned**, not only where one is created. The check used to
/// sit after the `udisksctl mount` in [`up`] alone, which put it behind two early returns that skip
/// it — `ensure_mounted` hands back `State::Mounted` without looking, and `up` does the same. So it
/// ran on exactly one call in a volume's life: the one that performed the transition. Worse, it
/// poisoned itself — a refusal returned `Err` without unmounting, leaving the volume mounted, so the
/// very next call saw `State::Mounted` and returned that noexec mount point with no complaint at all.
///
/// `State::Mounted` has carried `options` all along; both early returns simply discarded it.
fn refuse_noexec(mount_point: PathBuf, options: &str) -> Result<PathBuf, String> {
    if mount_is_noexec(options) {
        return Err(format!(
            "{} is mounted noexec, so a store there cannot run anything \
             (check the udisks mount options configured on this host)",
            mount_point.display()
        ));
    }
    Ok(mount_point)
}

/// `mountinfo` escapes space, tab, newline and backslash as octal. Only a path containing one
/// of those is affected, but a data directory may well sit under such a path.
///
/// Decoded through bytes rather than chars, and reassembled once at the end. Pushing each input
/// byte as a `char` re-encoded everything above ASCII: a path under `/media/josé` came back as
/// `/media/josÃ©`, which matches no mount point, so `state` reported a mounted volume as detached
/// and `up` would try to mount it again. Only the escapes are ASCII; the rest of the line is UTF-8
/// that must be carried through untouched.
fn unescape_mountinfo(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        // Three octal digits exactly — `u8::from_str_radix` would also take a sign, which is not an
        // escape the kernel writes and not a byte this should invent.
        if b[i] == b'\\'
            && let Some(octal) = b.get(i + 1..i + 4)
            && octal.iter().all(|d| d.is_ascii_digit() && *d < b'8')
            && let Ok(c) = u8::from_str_radix(&String::from_utf8_lossy(octal), 8)
        {
            out.push(c);
            i += 4;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The loop device currently backed by `image`, if any.
///
/// Discovering an existing attachment is what keeps `up` idempotent. Without it, two launches
/// racing on the same image would each attach their own loop device to the same bytes — two
/// writable views of one filesystem, which corrupts it.
///
/// Compared canonically as well as literally, because the two sides need not spell the path the
/// same way: the kernel records the backing file as it resolved it, while `image` is built from
/// whatever data directory the caller was given, and a single symlink anywhere along it (a data
/// directory under `/home` where `/home` is a link, a relocated volume) makes the strings differ
/// for the same bytes. A missed match is not a missed optimization here: it is the second
/// attachment this function exists to prevent. The literal comparison stays first and answers the
/// case canonicalization cannot — a backing file the kernel has already marked deleted.
pub(crate) fn loop_for(image: &Path, sys_block: &Path) -> io::Result<Option<String>> {
    let Ok(entries) = std::fs::read_dir(sys_block) else {
        return Ok(None);
    };
    let canonical_image = std::fs::canonicalize(image).ok();
    for e in entries.flatten() {
        let name = e.file_name();
        if !name.as_encoded_bytes().starts_with(b"loop") {
            continue;
        }
        let backing = e.path().join("loop/backing_file");
        let Ok(target) = std::fs::read_to_string(&backing) else {
            continue;
        };
        // The kernel may mark a deleted backing file; compare the path itself.
        let target = target.trim_end_matches('\n').trim_end_matches(" (deleted)");
        if Path::new(target) == image || same_file(Path::new(target), &canonical_image) {
            return Ok(Some(format!("/dev/{}", name.to_string_lossy())));
        }
    }
    Ok(None)
}

/// Whether a backing-file path resolves to the same file as `canonical_image`, the image's
/// already-resolved form. Split out so the image is resolved once per scan rather than once per
/// loop device, and so a path that cannot be resolved at all (either side gone, either side never
/// existing) answers `false` rather than a guess — the literal comparison the caller makes first is
/// what covers that case.
fn same_file(target: &Path, canonical_image: &Option<PathBuf>) -> bool {
    let Some(canonical_image) = canonical_image else {
        return false;
    };
    std::fs::canonicalize(target).is_ok_and(|t| &t == canonical_image)
}

/// Report where the volume stands, without changing anything.
pub(crate) fn state(image: &Path) -> io::Result<State> {
    if !image.is_file() {
        return Ok(State::Absent);
    }
    let Some(loop_dev) = loop_for(image, Path::new("/sys/block"))? else {
        return Ok(State::Detached);
    };
    // Propagated, not defaulted. An empty table makes `mount_of` answer `None`, which is this
    // function's word for "attached but not mounted" — so a read that failed would be reported as a
    // *state*, and the `noexec` guard keyed on `State::Mounted`'s options would never run. A table
    // that cannot be read is not a volume that is unmounted.
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
    match mount_of(&loop_dev, &mountinfo) {
        Some((mount_point, options)) => Ok(State::Mounted {
            loop_dev,
            mount_point,
            options,
        }),
        None => Ok(State::Attached { loop_dev }),
    }
}

/// Ask the filesystem to compress everything written under `dir` from now on.
///
/// Set as an extended attribute, which the kernel honours per directory and children inherit,
/// rather than as a mount option: `udisks` filters the options it accepts, and which ones made
/// its list varies by version, so a mount option would work on one host and be refused on
/// another. The attribute needs no privilege and no `btrfs` binary.
pub(crate) fn set_compression(dir: &Path, algorithm: &str) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("path contains an interior NUL"))?;
    let name = c"btrfs.compression";
    // SAFETY: all four arguments are valid for the call — two NUL-terminated C strings that
    // outlive it, and a length matching the value's bytes. The call only sets an attribute.
    let rc = unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            algorithm.as_ptr() as *const libc::c_void,
            algorithm.len(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The compression in force under `dir`, if any.
///
/// Read from the extended attribute rather than inferred from the mount options, because that
/// is where [`set_compression`] puts it: a volume can be compressed with no `compress` among
/// its mount options at all. A mount option remains a valid second source, so a caller that
/// has the options should fall back to them.
pub(crate) fn compression(dir: &Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    let name = c"btrfs.compression";
    let mut buf = [0u8; 32];
    // SAFETY: both C strings outlive the call, and the length passed matches the buffer, so
    // the kernel writes at most that many bytes into it. The call only reads an attribute.
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if n <= 0 {
        return None;
    }
    String::from_utf8(buf[..n as usize].to_vec()).ok()
}

/// How much of the volume the filesystem has claimed, and how much of that holds data — both
/// counted as they occupy the device.
///
/// btrfs keeps its accounting in *logical* bytes: a block group whose profile writes two copies
/// of everything — `DUP`, the default for metadata on a single device — reports one. That answers
/// "how much information did I store", where every question asked here is about blocks: what the
/// image costs on the host, and what a discard would return. So each block group is counted as
/// its profile writes it, which makes both figures directly comparable with the image's size on
/// the host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Space {
    /// Device bytes the filesystem has reserved into block groups.
    pub(crate) allocated: u64,
    /// Device bytes of that reservation actually in use.
    pub(crate) used: u64,
}

/// Each block group the space ioctl reports is three `u64`s: profile flags, total, used.
const ENTRY: usize = 24;

/// Copies of every byte a block group's profile writes to the device.
///
/// Read off the flags the kernel already returns beside each figure, and checked against its own
/// device-side counters: a metadata block group holding 972 308 480 logical bytes reports
/// 1 944 616 960 in `/sys/fs/btrfs/<uuid>/allocation/metadata/disk_used`.
///
/// The parity profiles are missing on purpose. `RAID5`/`RAID6` spread a stripe across several
/// devices, so their cost cannot be derived from one block group's flags at all — and neither
/// they nor the multi-device mirrors can arise here, where the filesystem is created over a
/// single loop image. An unrecognised profile is therefore counted once, which under-states the
/// figure rather than inventing one.
fn device_factor(flags: u64) -> u64 {
    const RAID1: u64 = 1 << 4;
    const DUP: u64 = 1 << 5;
    const RAID10: u64 = 1 << 6;
    const RAID1C3: u64 = 1 << 9;
    const RAID1C4: u64 = 1 << 10;

    if flags & RAID1C4 != 0 {
        4
    } else if flags & RAID1C3 != 0 {
        3
    } else if flags & (DUP | RAID1 | RAID10) != 0 {
        2
    } else {
        1
    }
}

/// Sum the block groups the kernel reported, as they occupy the device.
///
/// `entries` is the ioctl's payload with its header already stripped. A trailing partial entry
/// cannot occur — the buffer is sized from the kernel's own count — and is dropped rather than
/// read out of a half-written slot.
fn tally(entries: &[u8]) -> Space {
    // A reservation btrfs holds back *within* the metadata it has already claimed, reported
    // alongside the block groups rather than as one. Adding it would count those bytes twice.
    const GLOBAL_RSV: u64 = 1 << 49;

    let mut space = Space::default();
    for e in entries.chunks_exact(ENTRY) {
        let flags = u64::from_ne_bytes(e[0..8].try_into().unwrap());
        if flags & GLOBAL_RSV != 0 {
            continue;
        }
        let factor = device_factor(flags);
        space.allocated += u64::from_ne_bytes(e[8..16].try_into().unwrap()) * factor;
        space.used += u64::from_ne_bytes(e[16..24].try_into().unwrap()) * factor;
    }
    space
}

/// Bytes the image carries on the host beyond the data alive inside it.
///
/// The image is sparse: a block appears in it the first time it is written and leaves only when
/// the filesystem discards it, which punches it back out. What the image costs above what it now
/// holds is therefore what a discard has yet to return — the space `fstrim` acts on, and which
/// the kernel's own queue ([`discard_queue`]) has listed a part of.
///
/// The two counters are independent and agree only to within a few megabytes — btrfs's own
/// per-block-group totals against the host's block accounting for the image — so the image can
/// read *smaller* than the data inside it. Measured right after a successful `fstrim`: 5.3 MiB
/// under, stably. What that shortfall means depends on the host filesystem, which is why it is
/// passed in:
///
/// - one that cannot compress: the counters simply crossed, and the honest reading is that there
///   is nothing left to reclaim — `Some(0)`, not a vanished line at the very moment the volume is
///   in its best state;
/// - one that can: the image is structurally smaller than its contents and the subtraction
///   measures nothing at all, so there is no figure to report.
pub(crate) fn reclaimable_bytes(
    host_bytes: u64,
    used_on_device: u64,
    host_may_compress: bool,
) -> Option<u64> {
    match host_bytes.checked_sub(used_on_device) {
        Some(gap) => Some(gap),
        None if host_may_compress => None,
        // A crossing is two accountings of the same thing disagreeing at rounding scale — the
        // measured one was 0.04% of the volume. Past a thousandth, the shortfall is not skew but
        // something wrong (a miscount, a truncated image), and answering "nothing to reclaim"
        // with confidence would be worse than answering nothing. Relative rather than a byte
        // count, so the rule holds for a volume of any size.
        None if used_on_device - host_bytes <= used_on_device / 1000 => Some(0),
        None => None,
    }
}

/// How many block groups the space ioctl's header reports, refused when it is not a number a
/// buffer can be sized from.
///
/// The whole of [`space`]'s second call rests on this: the buffer it writes into is
/// `HEADER + count * ENTRY` bytes, and that call's SAFETY argument is that the kernel writes
/// within it. Multiplying an unchecked `u64` would make the argument depend on arithmetic that
/// wraps, and a wrapped size is a small buffer the ioctl then writes past. The ceiling is generous
/// on purpose — a volume with a million block groups is far beyond anything btrfs builds — and what
/// it is for is refusing an implausible number rather than trying to allocate it.
///
/// Split out from [`space`] so the refusal can be reached without a filesystem: the value it guards
/// against comes from an ioctl, and a test cannot make one lie.
fn reported_count(header: &[u8; 16]) -> io::Result<usize> {
    /// Block groups a volume may report before the answer is treated as nonsense.
    const MAX_SPACES: u64 = 1 << 20;

    let count = u64::from_ne_bytes(header[8..16].try_into().unwrap());
    if count > MAX_SPACES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the btrfs space ioctl reported {count} block groups, which is not a count"),
        ));
    }
    Ok(count as usize)
}

/// Read the volume's own space accounting.
///
/// Reported because deleting files does not shrink the image immediately: the kernel returns
/// freed extents to the host in the background, and a reservation it has not yet released
/// still counts. Showing both figures makes that gap visible instead of implying it is zero.
pub(crate) fn space(mount_point: &Path) -> io::Result<Space> {
    use std::os::unix::io::AsRawFd;

    // _IOWR(0x94, 20, struct btrfs_ioctl_space_args), whose two u64 fields make it 16 bytes.
    const BTRFS_IOC_SPACE_INFO: libc::c_ulong = (3 << 30) | (16 << 16) | (0x94 << 8) | 20;
    const HEADER: usize = 16;

    let dir = std::fs::File::open(mount_point)?;
    let fd = dir.as_raw_fd();

    // First call: ask how many spaces there are, by offering room for none.
    let mut header = [0u8; HEADER];
    // SAFETY: the buffer is at least the 16 bytes the ioctl reads and writes, and the fd is a
    // valid open directory. A non-btrfs filesystem fails the call rather than writing.
    if unsafe { libc::ioctl(fd, BTRFS_IOC_SPACE_INFO as libc::Ioctl, header.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let count = reported_count(&header)?;

    // Second call: room for every space, requested by writing the slot count back.
    let mut buf = vec![0u8; HEADER + count * ENTRY];
    buf[0..8].copy_from_slice(&(count as u64).to_ne_bytes());
    // SAFETY: the buffer is sized from the count the kernel just reported, so the ioctl writes
    // within it; the fd is unchanged and still valid.
    if unsafe { libc::ioctl(fd, BTRFS_IOC_SPACE_INFO as libc::Ioctl, buf.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let got = u64::from_ne_bytes(buf[8..16].try_into().unwrap()) as usize;

    Ok(tally(&buf[HEADER..HEADER + got.min(count) * ENTRY]))
}

/// Whether the kernel has discard work queued for the volume, and how much it has listed.
///
/// With `discard=async` a delete does not shrink the image at once: the kernel lists the freed
/// space and a deliberately throttled worker punches it out later. This counter is that list.
///
/// **Its figure is not what the host will get back**, which is why callers take it as a signal
/// rather than an amount. It counts free space *eligible* for discard, including regions already
/// punched out of the image — the kernel keeps the running total of those skipped in the sibling
/// `discard_bytes_saved`. Measured live on a volume where 800 MiB had just been deleted: the queue
/// read 1 178 042 368 and the host got 838 860 800 back. [`reclaimable_bytes`] is the figure that
/// tracks the return.
///
/// `None` where the kernel keeps no such list (mounted without async discard, or an older kernel)
/// and where there is nothing queued, which are reported alike: both mean nothing is pending.
pub(crate) fn discard_queue(loop_dev: &str) -> Option<u64> {
    discard_queue_under(Path::new("/sys/fs/btrfs"), loop_dev)
}

/// [`discard_queue`] against a given sysfs root, so the lookup is exercised without one.
fn discard_queue_under(sysfs: &Path, loop_dev: &str) -> Option<u64> {
    // Every mounted btrfs filesystem has a sysfs directory keyed by its UUID, listing the block
    // devices that back it. A host can have several, so the loop device the volume is attached to
    // is what says which directory is this volume's.
    let device = Path::new(loop_dev).file_name()?;
    let fs = std::fs::read_dir(sysfs)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|fs| fs.join("devices").join(device).symlink_metadata().is_ok())?;
    let raw = std::fs::read_to_string(fs.join("discard/discardable_bytes")).ok()?;
    // Read as signed: the counter is maintained incrementally and can sit slightly below zero,
    // which is a queue of nothing rather than a figure to report.
    let pending = raw.trim().parse::<i64>().ok()?;
    (pending > 0).then_some(pending as u64)
}

/// Bytes available to this user on the filesystem holding `path`.
///
/// Read from the filesystem rather than from the volume's own accounting, because that is the
/// figure a copy will actually run out of.
pub(crate) fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid NUL-terminated path and a zeroed struct the call fills in.
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

/// A tally of a tree's shape, taken on both sides of a copy so the result can be checked
/// against the original before anything is committed to it.
///
/// Counting *distinct inodes* rather than names is what makes it meaningful here: a nix store
/// deduplicates identical content into hardlinks, so a copy that silently expanded them would
/// match on every other count while occupying twice the space.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Census {
    pub(crate) dirs: u64,
    pub(crate) files: u64,
    pub(crate) symlinks: u64,
    /// Distinct file inodes — fewer than `files` wherever hardlinks are in play.
    pub(crate) inodes: u64,
    /// Apparent bytes of regular files, each inode counted once.
    pub(crate) bytes: u64,
    /// Entries that are neither a directory, a symlink nor a regular file — the Unix sockets
    /// a launch leaves under the data directory, and anything else of that kind. Counted so
    /// the two sides still tally, and reported so their absence is stated rather than hidden.
    pub(crate) special: u64,
}

/// Walk a tree and tally it. Entries named in `skip` are ignored at the top level only.
pub(crate) fn census(root: &Path, skip: &[&str]) -> io::Result<Census> {
    use std::os::unix::fs::MetadataExt;
    let mut c = Census::default();
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![root.to_path_buf()];
    let mut first = true;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if first && skip.contains(&entry.file_name().to_string_lossy().as_ref()) {
                continue;
            }
            let path = entry.path();
            let meta = entry.metadata()?;
            if meta.is_symlink() {
                c.symlinks += 1;
            } else if meta.is_dir() {
                c.dirs += 1;
                stack.push(path);
            } else if meta.is_file() {
                c.files += 1;
                if meta.nlink() == 1 || seen.insert((meta.dev(), meta.ino())) {
                    c.inodes += 1;
                    c.bytes += meta.len();
                }
            } else {
                c.special += 1;
            }
        }
        first = false;
    }
    Ok(c)
}

/// Copy a tree, preserving what a nix store depends on: hardlinks, symlinks, permissions and
/// modification times. Entries named in `skip` are left behind, at the top level only.
///
/// Two details are load-bearing, and both come from what a store looks like on disk:
///
/// - **Hardlinks are re-created as hardlinks.** A store deduplicates identical files into a
///   `.links` pool — here, over 170 000 of them. Copying each name as its own file would
///   roughly double the space and defeat the deduplication the store depends on.
/// - **Directory permissions are applied last, deepest first.** A store's directories are
///   read-only (`0555`); creating them with their final mode would make writing their contents
///   impossible, so they are created writable and tightened on the way back out.
pub(crate) fn copy_tree(src: &Path, dst: &Path, skip: &[&str]) -> io::Result<Census> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mut c = Census::default();
    // Every hardlinked file's first destination, so later names link to it instead of copying.
    let mut linked: std::collections::HashMap<(u64, u64), PathBuf> =
        std::collections::HashMap::new();
    // (destination, mode) for each directory, applied after everything is written.
    let mut dir_modes: Vec<(PathBuf, u32)> = Vec::new();

    std::fs::create_dir_all(dst)?;
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf(), true)];
    while let Some((from, to, top)) = stack.pop() {
        for entry in std::fs::read_dir(&from)? {
            let entry = entry?;
            let name = entry.file_name();
            if top && skip.contains(&name.to_string_lossy().as_ref()) {
                continue;
            }
            let s = entry.path();
            let d = to.join(&name);
            let meta = entry.metadata()?;

            if meta.is_symlink() {
                let target = std::fs::read_link(&s)?;
                std::os::unix::fs::symlink(target, &d)?;
                c.symlinks += 1;
            } else if meta.is_dir() {
                // Writable for now: its contents still have to be written into it.
                std::fs::create_dir_all(&d)?;
                std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))?;
                dir_modes.push((d.clone(), meta.mode() & 0o7777));
                c.dirs += 1;
                stack.push((s, d, false));
            } else if !meta.is_file() {
                // A socket or a fifo cannot be copied — `std::fs::copy` fails outright on
                // one — and a dead launch's socket is worthless anyway. Counted, not carried.
                c.special += 1;
            } else {
                let key = (meta.dev(), meta.ino());
                if meta.nlink() > 1 {
                    if let Some(first) = linked.get(&key) {
                        std::fs::hard_link(first, &d)?;
                        c.files += 1;
                        continue;
                    }
                    linked.insert(key, d.clone());
                }
                std::fs::copy(&s, &d)?;
                set_mtime(&d, &meta)?;
                c.files += 1;
                c.inodes += 1;
                c.bytes += meta.len();
            }
        }
    }

    // Deepest first, so tightening a parent never blocks writing into a child.
    dir_modes.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (path, mode) in dir_modes {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(c)
}

/// Carry a file's modification time across, so a copied tree is indistinguishable from the
/// original to anything that looks at timestamps.
fn set_mtime(path: &Path, meta: &std::fs::Metadata) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("path contains an interior NUL"))?;
    let times = [
        libc::timespec {
            tv_sec: meta.atime(),
            tv_nsec: meta.atime_nsec(),
        },
        libc::timespec {
            tv_sec: meta.mtime(),
            tv_nsec: meta.mtime_nsec(),
        },
    ];
    // SAFETY: a valid NUL-terminated path and a two-element timespec array, exactly what
    // `utimensat` reads. `AT_FDCWD` applies it to the absolute path given.
    let rc = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// An advisory lock over the image, held across the whole attach-and-mount sequence so two
/// concurrent `up` calls cannot each attach a loop device to the same bytes.
struct ImageLock(#[allow(dead_code)] std::fs::File);

fn lock_image(image: &Path) -> io::Result<ImageLock> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let path = image.with_extension("lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)?;
    // SAFETY: `flock` on a valid owned fd; it blocks until granted and returns 0 on success.
    // The fd lives in the guard, so the lock is held until the guard drops.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ImageLock(file))
}

/// Locate a required host program, with an error naming what it belongs to.
///
/// `udisks` is the one piece sbx genuinely cannot ship: it is a system daemon, and the polkit
/// privilege lives with it rather than with any binary.
fn tool(name: &str, provided_by: &str) -> Result<PathBuf, String> {
    crate::pathfind::find_on_path(name)
        .ok_or_else(|| format!("{name} not found on PATH — install {provided_by}"))
}

/// How `mkfs.btrfs` will be run.
///
/// `btrfs-progs` is not installed on every distribution, and requiring it would make creating
/// a volume depend on the host — which is exactly what sbx avoids elsewhere by shipping its
/// own `nix` and `bwrap`. So the host's copy is a shortcut, not a requirement: without one,
/// sbx provisions `btrfs-progs` into its own store.
pub(crate) enum Mkfs {
    /// Found on the host. Run directly.
    Host(PathBuf),
    /// Provisioned by sbx. A binary in a relocated store hard-codes its interpreter under
    /// `/nix/store/…`, a path the host does not have, so it runs inside a minimal bubblewrap
    /// with sbx's store bound there — the same way sbx already drives its own mise engine.
    Owned {
        bwrap: PathBuf,
        store_nix: PathBuf,
        bin: PathBuf,
    },
}

impl Mkfs {
    /// A one-line description of where this came from, for the caller to report.
    pub(crate) fn origin(&self) -> &'static str {
        match self {
            Mkfs::Host(_) => "host btrfs-progs",
            Mkfs::Owned { .. } => "sbx's own btrfs-progs",
        }
    }
}

/// Find `mkfs.btrfs`, provisioning it if the host has none.
///
/// Only ever needed to *create* a volume. Using one needs no `btrfs` binary at all —
/// compression rides an extended attribute and space accounting an ioctl.
pub(crate) fn resolve_mkfs() -> Result<Mkfs, String> {
    if let Some(host) = crate::pathfind::find_on_path("mkfs.btrfs") {
        return Ok(Mkfs::Host(host));
    }
    let layout = crate::store::Layout::from_env()
        .ok_or_else(|| "cannot locate sbx's data directory".to_string())?;
    let nix = crate::store::resolve_nix(Some(&layout))
        .ok_or_else(|| "no mkfs.btrfs on PATH, and no nix to provision one with".to_string())?;
    let bwrap = crate::store::resolve_bwrap(Some(&layout))
        .map(|c| c.path)
        .ok_or("no mkfs.btrfs on PATH, and no bubblewrap to run a provisioned one")?;
    let nixpkgs = crate::store::LockTarget::global(&layout, None)
        .resolve(&nix, &layout)
        .map_err(|e| format!("cannot resolve the nixpkgs channel: {e}"))?;
    let gcroot = layout
        .data_dir()
        .join("gcroots/storage")
        .join(crate::store::revision_of(&nixpkgs));
    let logical = crate::store::provision(
        &nix,
        &layout,
        &gcroot,
        &nixpkgs,
        "btrfs-progs",
        "bin/mkfs.btrfs",
    )
    .map_err(|e| format!("cannot provision btrfs-progs: {e}"))?;
    Ok(Mkfs::Owned {
        bwrap,
        store_nix: layout.store_dir().join("nix"),
        bin: logical.join("bin/mkfs.btrfs"),
    })
}

/// Build the command that formats `image`, taking its root's ownership from `seed`.
fn mkfs_command(
    mkfs: &Mkfs,
    image: &Path,
    seed: &Path,
    label: &str,
) -> (Command, Vec<std::fs::File>) {
    let args = |c: &mut Command| {
        c.arg("-q")
            .arg("-L")
            .arg(label)
            .arg("--rootdir")
            .arg(seed)
            .arg(image);
    };
    match mkfs {
        // The host's own tool, run as the user runs it: there is no cage here to harden.
        Mkfs::Host(path) => {
            let mut c = Command::new(path);
            args(&mut c);
            (c, Vec::new())
        }
        Mkfs::Owned {
            bwrap,
            store_nix,
            bin,
        } => {
            let mut c = Command::new(bwrap);
            // The mandatory syscall denylist, which "as everywhere else" below has to include or
            // the claim is not true: this argv is assembled by hand rather than through the
            // `SandboxSpec` keystone, and had the namespaces and the capabilities without it.
            let seccomp = crate::sandbox::seccomp::memfds(&Default::default())
                .expect("the statically-defined filters compile");
            c.args(crate::sandbox::seccomp::argv_prefix(&seccomp));
            // Every namespace unshared and every capability dropped, as everywhere else sbx
            // runs a helper. The network included: formatting needs none.
            for ns in [
                "--unshare-user",
                "--unshare-ipc",
                "--unshare-pid",
                "--unshare-net",
                "--unshare-uts",
                "--unshare-cgroup",
            ] {
                c.arg(ns);
            }
            c.arg("--clearenv").arg("--die-with-parent");
            c.arg("--cap-drop").arg("ALL");
            // The store backs the relocated binary; `/proc`, `/dev` and a `/tmp` tmpfs make a
            // minimal usable root.
            c.arg("--ro-bind").arg(store_nix).arg("/nix");
            c.arg("--proc").arg("/proc");
            c.arg("--dev").arg("/dev");
            c.arg("--tmpfs").arg("/tmp");
            // The seed is read; the image's directory is written. Each is bound at its own
            // path so the arguments below stay valid inside.
            //
            // The order is load-bearing, and it used to be the other way round. The seed lives
            // beside the image (`image.with_extension("seed")`), so it is *inside* the directory
            // bound below; bwrap applies binds in argv order, and a writable parent emitted after
            // the seed's read-only bind mounted straight over it — mkfs got a writable seed and the
            // "the seed is read" above was not true of the cage it built. The narrower mount lands
            // last.
            if let Some(parent) = image.parent() {
                c.arg("--bind").arg(parent).arg(parent);
            }
            c.arg("--ro-bind").arg(seed).arg(seed);
            c.arg("--").arg(bin);
            args(&mut c);
            // Handed back rather than dropped here: the filters' descriptors are not
            // close-on-exec, and bwrap reads them at the exec.
            (c, seccomp)
        }
    }
}

/// Run a command, returning its stdout, or its stderr as the error.
fn run(cmd: &mut Command) -> Result<String, String> {
    let out = cmd
        .output()
        .map_err(|e| format!("cannot run {:?}: {e}", cmd.get_program()))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = err.trim();
        let err = if err.is_empty() {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        } else {
            err.to_string()
        };
        return Err(format!("{:?} failed: {err}", cmd.get_program()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Create the volume: a sparse image carrying an empty btrfs filesystem whose root belongs to
/// the invoking user. Refuses to touch an existing image, so it can never destroy a store.
pub(crate) fn init(image: &Path, size_bytes: u64, label: &str, mkfs: &Mkfs) -> Result<(), String> {
    if !is_valid_label(label) {
        return Err(format!(
            "invalid label {label:?} — letters, digits, '-' and '_', at most 32"
        ));
    }
    if image.exists() {
        return Err(format!(
            "{} already exists — remove it first, or pass another path",
            image.display()
        ));
    }
    if let Some(parent) = image.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }

    // The seed directory decides the filesystem root's ownership, so it must be ours and it
    // must be empty — every byte it held would be copied into the new volume.
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
    let seed = image.with_extension("seed");
    let _ = std::fs::remove_dir_all(&seed);
    // Owner-only, like every other directory this crate makes: the seed's mode is what the new
    // filesystem's root carries, and `store::ensure` tightens the *mounted* root to `0700` anyway —
    // so taking the umask's answer here only opened a window, it never decided anything.
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&seed)
        .map_err(|e| format!("cannot create {}: {e}", seed.display()))?;

    let made = (|| -> Result<(), String> {
        // Sparse: the file declares its size but occupies only what gets written.
        //
        // `create_new` + `mode(0o600)` rather than `File::create`, on two counts. The mode: this one
        // file *is* the whole data directory once the volume is adopted — the shared nix store,
        // every project's home and runtime tree, `apt-keys/`, session state — and `File::create`
        // takes `0666 & ~umask`, so under the near-universal `umask 022` it landed `0644` and any
        // other local account could read every byte of it by loop-mounting a copy. Every other
        // creation site here refuses to trust the umask for far less: `lock_image` passes
        // `mode(0o600)` for a file that holds nothing but an flock, and `store::ensure` builds
        // `0700` "so a loose umask never leaves a world-readable window between creation and
        // tightening". Tightening later would not help either — the image is read as raw bytes on
        // the host, not through the mount.
        //
        // And `create_new` is what makes this function's own promise — "Refuses to touch an existing
        // image, so it can never destroy a store" — hold as stated. The `exists()` check above is a
        // separate stat, so an image appearing between the two would have been *truncated* by
        // `File::create`. The check stays for the message it gives; the atomicity is here.
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(image)
            .map_err(|e| format!("cannot create image: {e}"))?;
        f.set_len(size_bytes)
            .map_err(|e| format!("cannot size image: {e}"))?;
        drop(f);
        let (mut cmd, _seccomp) = mkfs_command(mkfs, image, &seed, label);
        run(&mut cmd).map(|_| ())
    })();
    let _ = std::fs::remove_dir_all(&seed);
    if made.is_err() {
        // Never leave a half-formatted image: it would look like a volume to `state`.
        let _ = std::fs::remove_file(image);
    }
    made
}

/// Attach and mount the volume, and return where it landed. Idempotent: an already-mounted
/// volume is reported, not mounted twice.
pub(crate) fn up(image: &Path) -> Result<PathBuf, String> {
    let _lock = lock_image(image).map_err(|e| format!("cannot lock {}: {e}", image.display()))?;
    let udisks = tool("udisksctl", "udisks2")?;

    let loop_dev = match state(image).map_err(|e| e.to_string())? {
        State::Absent => {
            return Err(format!(
                "{} does not exist — create it with `sbx storage init`",
                image.display()
            ));
        }
        State::Mounted {
            mount_point,
            options,
            ..
        } => return refuse_noexec(mount_point, &options),
        State::Attached { loop_dev } => loop_dev,
        State::Detached => {
            let out = run(Command::new(&udisks).arg("loop-setup").arg("-f").arg(image))?;
            parse_loop_setup(&out)
                .ok_or_else(|| format!("cannot read the loop device from: {}", out.trim()))?
        }
    };

    let out = run(Command::new(&udisks).arg("mount").arg("-b").arg(&loop_dev))?;
    let mount_point = parse_mount(&out)
        .ok_or_else(|| format!("cannot read the mount point from: {}", out.trim()))?;

    // A volume mounted `noexec` would host a store whose binaries cannot run — a failure that
    // surfaces far from its cause, so it is caught here rather than at the first launch.
    //
    // Undone before refusing. Returning `Err` on a mount this call had just made left the volume up,
    // and the two `State::Mounted` arms then handed that same mount point back to every later
    // call — so the guard fired once and was never reachable again. `down` is best-effort: if it
    // cannot undo the mount the refusal still stands, and the arms above now refuse it too.
    // Read errors are fatal here for the reason [`state`] states: an empty table answers `None`,
    // which is indistinguishable from "this mount is not noexec" and would wave the volume through
    // on the one call that performs the transition.
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|e| format!("cannot read /proc/self/mountinfo: {e}"))?;
    if let Some((_, options)) = mount_of(&loop_dev, &mountinfo)
        && mount_is_noexec(&options)
    {
        // The lock goes first: `down` takes the same one, and `flock` on a second open of the
        // file would block against this call's own hold.
        drop(_lock);
        let _ = down(image);
        return refuse_noexec(mount_point, &options);
    }

    // Best-effort: an uncompressed volume is a working volume, just a larger one.
    if let Err(e) = set_compression(&mount_point, "zstd") {
        crate::diag::error(&format!(
            "sbx: could not enable compression on {}: {e}",
            mount_point.display()
        ));
    }
    Ok(mount_point)
}

/// Unmount the volume and release its loop device.
pub(crate) fn down(image: &Path) -> Result<(), String> {
    let _lock = lock_image(image).map_err(|e| format!("cannot lock {}: {e}", image.display()))?;
    let udisks = tool("udisksctl", "udisks2")?;
    match state(image).map_err(|e| e.to_string())? {
        State::Absent => Err(format!("{} does not exist", image.display())),
        State::Detached => Ok(()),
        State::Attached { loop_dev } => {
            run(Command::new(&udisks)
                .arg("loop-delete")
                .arg("-b")
                .arg(&loop_dev))?;
            Ok(())
        }
        State::Mounted { loop_dev, .. } => {
            run(Command::new(&udisks)
                .arg("unmount")
                .arg("-b")
                .arg(&loop_dev))?;
            run(Command::new(&udisks)
                .arg("loop-delete")
                .arg("-b")
                .arg(&loop_dev))?;
            Ok(())
        }
    }
}

/// The host bytes the image actually occupies, as opposed to the size it declares.
pub(crate) fn image_bytes(image: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(image).ok().map(|m| m.blocks() * 512)
}

/// The size the image declares to the filesystem inside it.
pub(crate) fn image_capacity(image: &Path) -> Option<u64> {
    std::fs::metadata(image).ok().map(|m| m.len())
}

/// The kind of filesystem a directory sits on, insofar as it bears on whether an encapsulated
/// volume would help. The distinction that matters is copy-on-write: a volume's whole value —
/// compression and block sharing — a copy-on-write filesystem already provides, so wrapping one
/// inside a loop-mounted image would add a layer without adding a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FsKind {
    /// btrfs — already copy-on-write, and what a volume itself is.
    Btrfs,
    /// ZFS — copy-on-write.
    Zfs,
    /// bcachefs — copy-on-write.
    Bcachefs,
    /// ext2/3/4 — a fixed inode table, the classic case a volume relieves.
    Ext,
    /// XFS — dynamic inodes and, with `reflink=1` (the `mkfs.xfs` default), block sharing too;
    /// but no compression, which is what a volume adds there.
    Xfs,
    /// A RAM-backed filesystem; nothing persistent lives here.
    Tmpfs,
    /// Anything else, kept as its magic so an unrecognized one is still named.
    Other(u32),
}

impl FsKind {
    /// Whether the filesystem is already copy-on-write, so an encapsulated volume would only
    /// duplicate what it offers.
    pub(crate) fn is_cow(self) -> bool {
        matches!(self, FsKind::Btrfs | FsKind::Zfs | FsKind::Bcachefs)
    }

    /// Whether nothing stored here survives a reboot — a data directory's real problem, and one
    /// no volume addresses.
    pub(crate) fn is_ephemeral(self) -> bool {
        matches!(self, FsKind::Tmpfs)
    }

    /// Whether a file here can occupy fewer blocks than it contains, which decides how to read an
    /// image that appears smaller than the data inside it (see [`reclaimable_bytes`]).
    ///
    /// An unrecognised filesystem counts as one that might, so an unknown case falls through to
    /// "no answer" rather than to a confident figure. Kept apart from [`FsKind::is_cow`] on
    /// purpose: that one decides whether to *offer a volume*, and the two questions would only
    /// coincide by accident.
    pub(crate) fn may_compress(self) -> bool {
        match self {
            FsKind::Btrfs | FsKind::Zfs | FsKind::Bcachefs | FsKind::Other(_) => true,
            FsKind::Ext | FsKind::Xfs | FsKind::Tmpfs => false,
        }
    }

    /// A short human name.
    pub(crate) fn name(self) -> String {
        match self {
            FsKind::Btrfs => "btrfs".to_string(),
            FsKind::Zfs => "zfs".to_string(),
            FsKind::Bcachefs => "bcachefs".to_string(),
            FsKind::Ext => "ext4".to_string(),
            FsKind::Xfs => "xfs".to_string(),
            FsKind::Tmpfs => "tmpfs".to_string(),
            FsKind::Other(m) => format!("an unrecognized filesystem (0x{m:08x})"),
        }
    }
}

/// Classify the filesystem holding `path` by its superblock magic. `None` when the path cannot
/// be statted — it does not exist, or the call fails.
pub(crate) fn fs_kind(path: &Path) -> Option<FsKind> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid NUL-terminated path and a zeroed struct the call fills in.
    if unsafe { libc::statfs(c_path.as_ptr(), &mut st) } != 0 {
        return None;
    }
    // The magic is a 32-bit constant; masking to 32 bits makes the comparison identical whether
    // `f_type` is signed (glibc) or unsigned (musl).
    let magic = (st.f_type as u64 & 0xffff_ffff) as u32;
    Some(match magic {
        0x9123_683E => FsKind::Btrfs,
        0x2FC1_2FC1 => FsKind::Zfs,
        0xCA45_1A4E => FsKind::Bcachefs,
        0xEF53 => FsKind::Ext,
        0x5846_5342 => FsKind::Xfs,
        0x0102_1994 => FsKind::Tmpfs,
        other => FsKind::Other(other),
    })
}

/// The filesystem holding `path`, or — if it does not exist yet — the nearest ancestor that
/// does. The data directory may be absent on a first run, but the filesystem it will live on is
/// already there, and that is what decides whether a volume is worth it.
pub(crate) fn fs_kind_of_nearest(path: &Path) -> Option<FsKind> {
    nearest_existing(path).and_then(fs_kind)
}

/// The nearest ancestor of `path` that can be statted — `path` itself when it exists. Exposed
/// alongside [`fs_kind_of_nearest`] so a caller that also wants to *measure* something about that
/// filesystem measures it on the very directory whose kind was read, never on a different one.
fn nearest_existing(path: &Path) -> Option<&Path> {
    let mut p = path;
    loop {
        if fs_kind(p).is_some() {
            return Some(p);
        }
        p = p.parent()?;
    }
}

/// Whether `path` (or, if it does not exist yet, its nearest existing ancestor) sits on
/// btrfs — the one filesystem where the inherited `btrfs.compression` attribute
/// [`set_compression`] relies on can exist. Callers scope btrfs-specific accommodations
/// (nix must leave that attribute in place) to where they can matter at all.
pub(crate) fn on_btrfs(path: &Path) -> bool {
    matches!(fs_kind_of_nearest(path), Some(FsKind::Btrfs))
}

/// Whether the running kernel can mount btrfs.
///
/// `/proc/filesystems` lists only what is built in or already loaded, so a host where btrfs is
/// an unloaded module would look incapable there. The module file under the running kernel's
/// tree is the second signal, so a desktop that simply has not mounted btrfs yet — the very
/// audience a volume is for — is still recognized. Kept advisory rather than a hard gate: a
/// mount autoloads the module, so a false negative costs a recommendation, never a refusal.
fn kernel_supports_btrfs() -> bool {
    let listed = std::fs::read_to_string("/proc/filesystems")
        .map(|t| {
            t.lines()
                .any(|l| l.split_whitespace().last() == Some("btrfs"))
        })
        .unwrap_or(false);
    if listed {
        return true;
    }
    // A loadable module under the running kernel's release directory.
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|rel| Path::new(&format!("/lib/modules/{}/kernel/fs/btrfs", rel.trim())).exists())
        .unwrap_or(false)
}

/// What the host offers for an encapsulated volume, probed cheaply so a caller can decide
/// whether it can be mounted, whether it is worth recommending, or why neither.
///
/// The fields separate the reliably-detectable hard requirements (a loop device and the udisks
/// daemon) from the advisory ones (kernel btrfs, which autoloads; the session kind, which only
/// bears on whether udisks mounts without a password). That split is deliberate: the hard set
/// gates `up`, while the advisory set only steers a recommendation.
#[derive(Debug, Clone)]
pub(crate) struct Preflight {
    /// The kernel can mount btrfs (built in, loaded, or a loadable module).
    pub(crate) kernel_btrfs: bool,
    /// Loop devices are available (`/dev/loop-control` is present).
    pub(crate) loop_control: bool,
    /// `udisksctl` is on `PATH` — the daemon that performs the unprivileged loop-attach and
    /// mount, and where the polkit privilege lives.
    pub(crate) udisks: bool,
    /// The filesystem the data directory sits on, or will.
    pub(crate) host_fs: Option<FsKind>,
    /// Whether that filesystem shares blocks between files, *measured* by attempting one —
    /// consulted only where [`FsKind`] does not settle the question, so the recognized
    /// filesystems cost no I/O and carry `None` here.
    pub(crate) shares_blocks: Option<bool>,
    /// A remote session (`$SSH_CONNECTION`/`$SSH_TTY` set), under which udisks' polkit rule
    /// asks for administrator authentication and so cannot mount unattended.
    pub(crate) remote_session: bool,
}

/// Whether this is a remote session, under which udisks' polkit rule demands administrator
/// authentication and so cannot mount a volume unattended.
///
/// Detected from the SSH environment, and pure over its inputs so the decision is testable
/// without a live remote session. The mount *refusal* it feeds only manifests over a genuine
/// SSH/inactive session and cannot be exercised from a locally active one — this predicate is
/// the seam that is testable.
fn is_remote_session(
    ssh_connection: Option<&std::ffi::OsStr>,
    ssh_tty: Option<&std::ffi::OsStr>,
) -> bool {
    ssh_connection.is_some() || ssh_tty.is_some()
}

impl Preflight {
    /// Probe the host. `data_base` is where the data directory sits, or would; its filesystem
    /// decides whether a volume relieves anything.
    pub(crate) fn probe(data_base: &Path) -> Self {
        // The same directory throughout: on a first run the data directory does not exist yet, so
        // both the kind and the measurement must describe the filesystem it will land on.
        let base = nearest_existing(data_base);
        let host_fs = base.and_then(fs_kind);
        Self {
            kernel_btrfs: kernel_supports_btrfs(),
            loop_control: Path::new("/dev/loop-control").exists(),
            udisks: crate::pathfind::find_on_path("udisksctl").is_some(),
            host_fs,
            // Measured only for a filesystem this does not recognize, where there is no table to
            // consult — so the ordinary case writes nothing. A probe that could not be carried out
            // stays `None`: an unwritable directory says nothing about its filesystem, and this
            // decision must not read it as an answer.
            shares_blocks: matches!(host_fs, Some(FsKind::Other(_)))
                .then(|| base.and_then(crate::sandbox::reflink_verdict))
                .flatten(),
            remote_session: is_remote_session(
                std::env::var_os("SSH_CONNECTION").as_deref(),
                std::env::var_os("SSH_TTY").as_deref(),
            ),
        }
    }

    /// Whether the reliably-detectable prerequisites to *mount* a volume are present. Creating
    /// one is pointless without this.
    ///
    /// Kernel btrfs support is deliberately not part of it: a mount autoloads the module, so
    /// gating on a `/proc/filesystems` reading would refuse a volume that would in fact work.
    ///
    /// The loop device and the daemon, by contrast, are genuinely fatal when absent.
    pub(crate) fn can_mount(&self) -> bool {
        self.loop_control && self.udisks
    }

    /// The reason a volume cannot be mounted here, naming everything missing — so a refusal is
    /// one clear message up front rather than the first obstacle hit deep inside `up`.
    pub(crate) fn mount_blocker(&self) -> Option<String> {
        let mut missing = Vec::new();
        if !self.loop_control {
            missing.push("loop devices are unavailable (/dev/loop-control)");
        }
        if !self.udisks {
            missing.push("udisksctl is not installed (part of udisks2)");
        }
        (!missing.is_empty()).then(|| missing.join("; "))
    }

    /// Whether an encapsulated volume is worth *recommending*: it can be mounted, the kernel
    /// supports btrfs, the session is local (so udisks mounts without a password), and the volume
    /// would actually add something. A "no" is advisory — it decides whether to suggest one,
    /// never whether `sbx storage` works when asked.
    pub(crate) fn recommends_volume(&self) -> bool {
        self.can_mount()
            && self.kernel_btrfs
            && !self.remote_session
            && volume_adds_anything(self.host_fs, self.shares_blocks)
    }
}

/// Whether an encapsulated volume would give the data directory something its filesystem does not
/// already provide. Kept pure over its two inputs, so every filesystem's case is exercised without
/// one being present.
///
/// A volume brings two distinct things — it shares blocks between files (so seeding a per-project
/// store from the shared one costs almost nothing) and it compresses — and the question is whether
/// *either* is missing here. That is why block sharing alone does not settle it: XFS shares blocks
/// and still gains compression from a volume.
fn volume_adds_anything(host_fs: Option<FsKind>, shares_blocks: Option<bool>) -> bool {
    match host_fs {
        // Both already present, so a volume would only duplicate them — and nesting one
        // copy-on-write filesystem inside another compounds the fragmentation both are prone to.
        Some(FsKind::Btrfs | FsKind::Zfs | FsKind::Bcachefs) => false,
        // Nothing here survives a reboot, so there is no long-lived data directory to house.
        Some(FsKind::Tmpfs) => false,
        // ext has neither, and a fixed inode table besides. XFS does share blocks, but does not
        // compress, which is what a volume adds there.
        Some(FsKind::Ext | FsKind::Xfs) => true,
        // No table covers it, so fall back to the one thing that can be measured. A filesystem
        // that cannot share blocks pays a full copy per project — the clearest thing a volume
        // fixes. One that can is left alone rather than guessed at, since whether it also
        // compresses is exactly what is unknown.
        Some(FsKind::Other(_)) => shares_blocks == Some(false),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_reads_binary_suffixes_and_refuses_the_unusable() {
        assert_eq!(parse_size("200G"), Ok(200 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("2g"), Ok(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("1T"), Ok(1024_u64.pow(4)));
        // Too small to hold a store, and a bare number is bytes — so it is refused too.
        assert!(parse_size("1G").is_err());
        assert!(parse_size("200").is_err());
        assert!(parse_size("lots").is_err());
        // Overflow must not wrap into a plausible size.
        assert!(parse_size("99999999999999T").is_err());
    }

    #[test]
    fn labels_that_could_escape_a_mount_point_are_refused() {
        assert!(is_valid_label("sbx-storage"));
        assert!(is_valid_label("vol_1"));
        assert!(!is_valid_label(""));
        assert!(!is_valid_label("../etc"));
        assert!(!is_valid_label("a/b"));
        assert!(!is_valid_label("with space"));
        assert!(!is_valid_label(&"x".repeat(33)));
    }

    #[test]
    fn udisks_output_is_read_back_rather_than_guessed() {
        assert_eq!(
            parse_loop_setup("Mapped file /home/u/sbx-storage.btrfs as /dev/loop7.\n").as_deref(),
            Some("/dev/loop7")
        );
        assert_eq!(
            parse_mount("Mounted /dev/loop7 at /run/media/u/sbx-storage\n"),
            Some(PathBuf::from("/run/media/u/sbx-storage"))
        );
        // A collision makes udisks append a digit, and older versions use /media —
        // neither of which a constructed path would predict.
        assert_eq!(
            parse_mount("Mounted /dev/loop7 at /media/u/sbx-storage1\n"),
            Some(PathBuf::from("/media/u/sbx-storage1"))
        );
        assert_eq!(parse_loop_setup("unexpected"), None);
        assert_eq!(parse_mount("unexpected"), None);
    }

    #[test]
    fn mount_of_finds_the_device_and_keeps_the_options() {
        let table = "\
25 30 0:22 / /proc rw,nosuid - proc proc rw
41 30 7:60 / /run/media/u/sbx-storage rw,nosuid,nodev - btrfs /dev/loop60 rw,compress=zstd:3,discard=async
";
        let (mp, opts) = mount_of("/dev/loop60", table).expect("the device is in the table");
        assert_eq!(mp, PathBuf::from("/run/media/u/sbx-storage"));
        // Both the per-mount and the superblock options matter: `noexec` is per-mount,
        // `compress` is a superblock option, and the check below reads the same string.
        assert!(opts.contains("nosuid"), "{opts}");
        assert!(opts.contains("compress=zstd:3"), "{opts}");
        assert_eq!(mount_of("/dev/loop61", table), None);
    }

    #[test]
    fn noexec_is_matched_as_an_exact_option_not_a_substring() {
        // The flag that would make a store unrunnable, in the middle and alone.
        assert!(mount_is_noexec("rw,nosuid,noexec,nodev"));
        assert!(mount_is_noexec("noexec"));
        // A volume with none of it runs.
        assert!(!mount_is_noexec("rw,nodev,compress=zstd:3"));
        // Teeth: a token that merely spells the letters is a different flag, not this one —
        // matching it as a substring would refuse a runnable volume.
        assert!(!mount_is_noexec("rw,noexecutable"));
        assert!(!mount_is_noexec("rw,barnoexec"));
    }

    #[test]
    fn an_unparseable_line_does_not_end_the_search() {
        // The table is the kernel's and lists everything mounted on the host. A line that does
        // not fit the shape must be stepped over, or a device listed after it becomes
        // invisible — and `up` would then mount a second time over an existing mount.
        let table = "\
this line has no separator at all
25 30 0:22 / /proc rw,nosuid - proc proc rw
41 30 7:60 / /run/media/u/sbx-storage rw - btrfs /dev/loop60 rw,compress=zstd:3
";
        let (mp, _) = mount_of("/dev/loop60", table).expect("found past the bad line");
        assert_eq!(mp, PathBuf::from("/run/media/u/sbx-storage"));
    }

    #[test]
    fn a_mount_point_containing_a_space_is_unescaped() {
        let table = "41 30 7:60 / /run/media/u/my\\040vol rw - btrfs /dev/loop3 rw\n";
        let (mp, _) = mount_of("/dev/loop3", table).expect("present");
        assert_eq!(mp, PathBuf::from("/run/media/u/my vol"));
    }

    /// The escapes are ASCII; everything else on the line is UTF-8 that must survive untouched.
    /// A byte-at-a-time `as char` re-encoded every byte above ASCII, so a data directory under an
    /// accented path never matched its own mount point: `state` called a mounted volume detached,
    /// and `up` set out to mount it a second time.
    #[test]
    fn a_mount_point_outside_ascii_survives_unescaping() {
        let table = "41 30 7:60 / /run/media/josé/my\\040vol rw - btrfs /dev/loop3 rw\n";
        let (mp, _) = mount_of("/dev/loop3", table).expect("present");
        assert_eq!(mp, PathBuf::from("/run/media/josé/my vol"));
        // Every escape the kernel writes, alongside the multi-byte text.
        assert_eq!(
            unescape_mountinfo("/tmp/日本\\040a\\011b\\012c\\134d"),
            "/tmp/日本 a\tb\nc\\d"
        );
        // A backslash that begins no escape is a byte like any other.
        assert_eq!(unescape_mountinfo("/tmp/a\\9b"), "/tmp/a\\9b");
        assert_eq!(unescape_mountinfo("/tmp/trailing\\"), "/tmp/trailing\\");
    }

    /// The kernel records a backing file as *it* resolved it, while the image path is built from
    /// whatever data directory the caller was handed. One symlink along the way and the two spell
    /// the same bytes differently — and a `loop_for` that misses the match does not merely miss an
    /// optimization: it reports no attachment, and `up` attaches a second loop device to the same
    /// filesystem, which is the corruption this function exists to prevent.
    #[test]
    fn loop_for_matches_an_image_reached_through_a_symlink() {
        let base = crate::testutil::TmpDir::new();
        let sys = base.path().join("block");
        let real = base.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let image = real.join("vol.btrfs");
        std::fs::write(&image, b"").unwrap();
        // The kernel's side: the resolved path.
        let d = sys.join("loop7").join("loop");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("backing_file"),
            format!("{}\n", std::fs::canonicalize(&image).unwrap().display()),
        )
        .unwrap();
        // The caller's side: the same image through a symlinked data directory.
        let link = base.path().join("data");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(
            loop_for(&link.join("vol.btrfs"), &sys).unwrap().as_deref(),
            Some("/dev/loop7"),
            "an image reached by another spelling of its path is still attached"
        );
        // A different image under the same directory is still not this device.
        let other = real.join("other.btrfs");
        std::fs::write(&other, b"").unwrap();
        assert_eq!(
            loop_for(&other, &sys).unwrap(),
            None,
            "resolving the path must not blur two images into one"
        );
    }

    #[test]
    fn loop_for_matches_the_backing_file_and_ignores_others() {
        let base = crate::testutil::TmpDir::new();
        let sys = base.path().join("block");
        let image = base.path().join("vol.btrfs");
        for (name, backing) in [
            ("loop0", "/some/other.img"),
            ("loop9", image.to_str().unwrap()),
            ("sda", image.to_str().unwrap()),
        ] {
            let d = sys.join(name).join("loop");
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("backing_file"), format!("{backing}\n")).unwrap();
        }
        // Found by its backing file, and a non-loop block device is never considered.
        assert_eq!(
            loop_for(&image, &sys).unwrap().as_deref(),
            Some("/dev/loop9")
        );
        assert_eq!(
            loop_for(Path::new("/nowhere.img"), &sys).unwrap(),
            None,
            "an unbacked image must report no device, or `up` would mount someone else's"
        );
    }

    #[test]
    fn a_deleted_backing_file_still_matches_its_image() {
        let base = crate::testutil::TmpDir::new();
        let sys = base.path().join("block");
        let image = base.path().join("vol.btrfs");
        let d = sys.join("loop4").join("loop");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("backing_file"),
            format!("{} (deleted)\n", image.display()),
        )
        .unwrap();
        assert_eq!(
            loop_for(&image, &sys).unwrap().as_deref(),
            Some("/dev/loop4")
        );
    }

    #[test]
    fn compression_reports_none_where_the_attribute_cannot_exist() {
        // A directory on an ordinary filesystem carries no such attribute. Reporting `None`
        // rather than failing matters: `status` runs against whatever the volume turns out to
        // be, and must render a plain answer instead of an error.
        let base = crate::testutil::TmpDir::new();
        assert_eq!(compression(base.path()), None);
        assert_eq!(compression(Path::new("/nonexistent-by-construction")), None);
    }

    /// Build a stand-in for one filesystem's sysfs directory: the device it is backed by, and
    /// the discard counter's contents.
    fn fake_btrfs_sysfs(sysfs: &Path, uuid: &str, device: &str, counter: Option<&str>) {
        let fs = sysfs.join(uuid);
        std::fs::create_dir_all(fs.join("devices")).unwrap();
        std::fs::write(fs.join("devices").join(device), b"").unwrap();
        if let Some(c) = counter {
            std::fs::create_dir_all(fs.join("discard")).unwrap();
            std::fs::write(fs.join("discard/discardable_bytes"), c).unwrap();
        }
    }

    /// One block group as the space ioctl lays it out: profile flags, logical total, logical used.
    fn block_group(flags: u64, total: u64, used: u64) -> Vec<u8> {
        let mut e = Vec::with_capacity(ENTRY);
        for v in [flags, total, used] {
            e.extend_from_slice(&v.to_ne_bytes());
        }
        e
    }

    #[test]
    fn a_mirrored_block_group_is_counted_as_it_occupies_the_device() {
        // The figures are compared against the image's size on the host, so they must be counted
        // the way the host carries them. btrfs reports logical bytes: metadata written twice
        // reports once. The values are a real volume's, whose device-side counters read
        // 1 944 616 960 for that same metadata group.
        const DATA: u64 = 1 << 0;
        const SYSTEM: u64 = 1 << 1;
        const METADATA: u64 = 1 << 2;
        const DUP: u64 = 1 << 5;
        const GLOBAL_RSV: u64 = 1 << 49;

        let mut entries = block_group(DATA, 17_179_869_184, 12_645_679_104);
        entries.extend(block_group(METADATA | DUP, 2_147_483_648, 972_308_480));
        entries.extend(block_group(SYSTEM | DUP, 8_388_608, 16_384));
        // Reported beside the block groups, but held back inside metadata already claimed above.
        entries.extend(block_group(GLOBAL_RSV, 51_953_664, 0));

        let space = tally(&entries);
        assert_eq!(space.used, 12_645_679_104 + 1_944_616_960 + 32_768);
        assert_eq!(space.allocated, 17_179_869_184 + 4_294_967_296 + 16_777_216);
        // The logical sums, which counting a mirror once (or adding the reservation) would give.
        assert_ne!(space.used, 13_618_003_968);
        assert_ne!(space.allocated, 19_387_695_104);

        // A payload that does not divide into whole entries drops its tail rather than reading a
        // half-written slot: `chunks_exact` is what makes every index inside the loop bounded by
        // the chunk's own length, so no answer from the kernel can shorten a slice under them.
        let mut ragged = block_group(DATA, 4096, 4096);
        ragged.extend_from_slice(&[0u8; ENTRY - 1]);
        assert_eq!(
            tally(&ragged).allocated,
            4096,
            "the partial entry is dropped"
        );
        assert_eq!(tally(&[]).allocated, 0);
    }

    /// The number of block groups is the kernel's, and the buffer the second ioctl writes into is
    /// sized from it: a count that cannot size a buffer is refused instead of multiplied.
    ///
    /// Teeth: `count as usize * ENTRY` on `u64::MAX` panics in a debug build and, in the release
    /// build that ships, wraps to a small number — a buffer the ioctl then writes past, under a
    /// SAFETY comment claiming it writes within it.
    #[test]
    fn a_block_group_count_a_buffer_cannot_be_sized_from_is_refused() {
        let header = |count: u64| {
            let mut h = [0u8; 16];
            h[8..16].copy_from_slice(&count.to_ne_bytes());
            h
        };
        assert_eq!(reported_count(&header(0)).unwrap(), 0);
        assert_eq!(reported_count(&header(7)).unwrap(), 7);
        assert_eq!(
            reported_count(&header(1 << 20)).unwrap(),
            1 << 20,
            "the ceiling itself is admissible"
        );
        for absurd in [(1u64 << 20) + 1, u64::MAX, u64::MAX / 24] {
            let err = reported_count(&header(absurd)).expect_err("refused");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            assert!(
                err.to_string().contains("which is not a count"),
                "the refusal says what it refused: {err}"
            );
        }
    }

    #[test]
    fn a_profile_that_cannot_arise_here_is_counted_once_rather_than_guessed() {
        // Every mirror is a whole number of copies and is derived from the flags. The parity
        // profiles are not: their cost depends on the device count, which one block group does
        // not carry — and neither they nor the multi-device mirrors can occur on a single loop
        // image. Counting them once under-states the figure instead of inventing one.
        assert_eq!(device_factor(1 << 0), 1, "single data");
        assert_eq!(device_factor(1 << 5), 2, "DUP");
        assert_eq!(device_factor(1 << 4), 2, "RAID1");
        assert_eq!(device_factor(1 << 6), 2, "RAID10");
        assert_eq!(device_factor(1 << 9), 3, "RAID1C3");
        assert_eq!(device_factor(1 << 10), 4, "RAID1C4");
        assert_eq!(device_factor(1 << 7), 1, "RAID5");
        assert_eq!(device_factor(1 << 8), 1, "RAID6");
    }

    #[test]
    fn a_gap_that_cannot_be_measured_is_told_apart_from_one_that_is_simply_empty() {
        // The figure is what the image carries above the data alive inside it.
        assert_eq!(
            reclaimable_bytes(14_655_836_160, 14_590_328_832, false),
            Some(65_507_328)
        );
        assert_eq!(reclaimable_bytes(4096, 4096, false), Some(0));
        // The real values right after a successful trim: the image reads 5.3 MiB *under* the data
        // btrfs says is alive, because the two counters are independent. On a host filesystem that
        // cannot compress, that is the counters crossing and the answer is that there is nothing
        // left — the line must not vanish exactly when the volume is at its tidiest.
        assert_eq!(
            reclaimable_bytes(14_584_774_656, 14_590_328_832, false),
            Some(0)
        );
        // Where the host filesystem compresses, the same shortfall is structural: the image really
        // does hold more than it occupies, and the subtraction measures nothing.
        // A shortfall past a thousandth of the volume is not two counters rounding differently.
        // Whatever it is — a miscount, a truncated image — "nothing to reclaim" would be a
        // confident falsehood, so it gets no answer even where nothing can compress.
        assert_eq!(
            reclaimable_bytes(14_000_000_000, 14_590_328_832, false),
            None
        );
        assert_eq!(
            reclaimable_bytes(14_590_328_832 - 14_590_328, 14_590_328_832, false),
            Some(0),
            "exactly a thousandth is still the crossing"
        );
        assert_eq!(
            reclaimable_bytes(14_584_774_656, 14_590_328_832, true),
            None
        );
    }

    #[test]
    fn an_unrecognized_host_filesystem_is_assumed_to_compress() {
        // The predicate decides whether an image smaller than its contents is a crossing or a
        // real saving. Guessing "cannot compress" for an unknown filesystem would turn that into
        // a confident `0`; assuming it might yields no answer instead.
        assert!(FsKind::Other(0x1234).may_compress());
        assert!(FsKind::Btrfs.may_compress());
        assert!(FsKind::Zfs.may_compress());
        assert!(FsKind::Bcachefs.may_compress());
        assert!(!FsKind::Ext.may_compress());
        assert!(!FsKind::Xfs.may_compress());
        assert!(!FsKind::Tmpfs.may_compress());
        // Separate from the volume-recommendation axis: XFS shares blocks and is not offered a
        // volume for that reason, yet cannot compress. The two questions must not be conflated.
        assert!(!FsKind::Xfs.is_cow() && !FsKind::Xfs.may_compress());
    }

    #[test]
    fn the_reclaiming_queue_is_read_from_the_volumes_own_filesystem() {
        // A host can run several btrfs filesystems, so reading "the" counter is not enough: the
        // one reported must be the one backed by the loop device this volume is attached to.
        let base = crate::testutil::TmpDir::new();
        let sysfs = base.path();
        fake_btrfs_sysfs(sysfs, "1111-aaaa", "sda2", Some("999999999\n"));
        fake_btrfs_sysfs(sysfs, "2222-bbbb", "loop7", Some("1178599424\n"));

        assert_eq!(
            discard_queue_under(sysfs, "/dev/loop7"),
            Some(1_178_599_424)
        );
        // A device no filesystem here is backed by has no queue to report.
        assert_eq!(discard_queue_under(sysfs, "/dev/loop9"), None);
    }

    #[test]
    fn a_queue_of_nothing_is_reported_as_nothing_to_wait_for() {
        // `status` shows the line only when there is something pending, so every way of having
        // nothing pending must arrive as `None` rather than as a figure to render. The negative
        // case is real: the counter is maintained incrementally and can sit just below zero.
        let base = crate::testutil::TmpDir::new();
        let sysfs = base.path();
        for (i, raw) in ["0", "0\n", "-25165824\n", "", "not-a-number\n"]
            .iter()
            .enumerate()
        {
            let uuid = format!("fs-{i}");
            fake_btrfs_sysfs(sysfs, &uuid, &format!("loop{i}"), Some(raw));
            assert_eq!(
                discard_queue_under(sysfs, &format!("/dev/loop{i}")),
                None,
                "counter {raw:?} should report nothing pending"
            );
        }
        // A kernel that keeps no such counter at all: the directory is simply absent.
        fake_btrfs_sysfs(sysfs, "fs-none", "loop90", None);
        assert_eq!(discard_queue_under(sysfs, "/dev/loop90"), None);
        // And a host with no btrfs sysfs tree whatsoever.
        assert_eq!(
            discard_queue_under(Path::new("/nonexistent-by-construction"), "/dev/loop0"),
            None
        );
    }

    #[test]
    fn the_pointer_round_trips_and_its_absence_is_the_ordinary_case() {
        let base = crate::testutil::TmpDir::new();
        let dir = base.path().join("sbx");
        let image = PathBuf::from("/vol/sbx-storage.btrfs");

        // No pointer is what an ordinary installation looks like, and it must cost nothing.
        assert_eq!(read_pointer(&dir), None);

        write_pointer(&dir, &image).expect("written");
        assert_eq!(read_pointer(&dir).as_deref(), Some(image.as_path()));

        // Still valid TOML for anyone who reads it as such, comments and all.
        let text = std::fs::read_to_string(dir.join(POINTER)).unwrap();
        assert!(
            text.contains("image = \"/vol/sbx-storage.btrfs\""),
            "{text}"
        );

        clear_pointer(&dir).expect("cleared");
        assert_eq!(read_pointer(&dir), None);
        // Clearing what is not there is not an error: `unuse` must be safe to repeat.
        clear_pointer(&dir).expect("idempotent");
    }

    /// The pointer names the data directory of the whole installation, and it is read back with no
    /// unescaping at all — so a path the one line cannot carry is refused when it is given, not
    /// written and misread later. Each refused character is shown here alongside what it would have
    /// cost, since none of them fails loudly on their own.
    #[test]
    fn a_path_the_pointer_cannot_carry_is_refused_rather_than_misread() {
        let base = crate::testutil::TmpDir::new();
        let dir = base.path().join("sbx");

        for bad in [
            // A line break: what comes back is the prefix before it, so sbx would follow
            // `/vol/a.btrfs` — a volume nobody adopted.
            "/vol/a.btrfs\nimage = \"/vol/elsewhere.btrfs\"",
            // A quote at either end is eaten by `trim_matches`, so the path comes back short.
            "/vol/a.btrfs\"",
            "\"/vol/a.btrfs",
            // A backslash leaves the file no longer valid TOML, which it promises to be.
            "/vol/a\\b.btrfs",
            // Any other control character, for the same reason.
            "/vol/a\u{7}b.btrfs",
        ] {
            let err = write_pointer(&dir, Path::new(bad))
                .expect_err(&format!("{bad:?} must be refused, not recorded"));
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(
                !dir.join(POINTER).exists(),
                "a refused path still left a pointer behind: {bad:?}"
            );
        }

        // Not a character but a byte: a Linux path need not be UTF-8, and `--image` takes one from
        // argv unchanged. It carries no quote, no backslash and no control character, so only an
        // encoding check catches it — the file is text, and `Display` would put `U+FFFD` where the
        // bytes were, handing back a path that is not the one adopted.
        {
            use std::os::unix::ffi::OsStringExt;
            let raw = PathBuf::from(std::ffi::OsString::from_vec(b"/vol/a\xffb.btrfs".to_vec()));
            let err = write_pointer(&dir, &raw).expect_err("a non-UTF-8 path must be refused");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(err.to_string().contains("UTF-8"), "{err}");
            assert!(!dir.join(POINTER).exists());
        }

        // The rule refuses what the format cannot carry, and nothing else: spaces, accents and the
        // rest of an ordinary path still round-trip exactly.
        let ok = PathBuf::from("/vol/mes données/sbx storage (2).btrfs");
        write_pointer(&dir, &ok).expect("an ordinary path is recordable");
        assert_eq!(read_pointer(&dir).as_deref(), Some(ok.as_path()));
    }

    /// Two writers must not share the scratch file, or the rename stops being atomic for the second
    /// one: it goes on writing into the inode the first has already published. A second *process* is
    /// what the name has to distinguish, so what a single-process test can hold is that the name
    /// carries this process's identity — and therefore that no other process derives it.
    #[test]
    fn the_scratch_file_is_this_processs_own() {
        let name = pointer_tmp_name();
        assert!(
            name.contains(&std::process::id().to_string()),
            "a name two processes both derive is a shared scratch file: {name}"
        );
        assert!(name.starts_with(&format!(".{POINTER}.")), "{name}");

        // And it is gone once the record is in place, whatever its name: a leftover would be read by
        // nothing and cleaned by nobody.
        let base = crate::testutil::TmpDir::new();
        let dir = base.path().join("sbx");
        write_pointer(&dir, Path::new("/vol/a.btrfs")).unwrap();
        assert!(
            !dir.join(&name).exists(),
            "the scratch file outlived the rename"
        );
    }

    #[test]
    fn a_pointer_survives_being_rewritten_over_an_older_one() {
        let base = crate::testutil::TmpDir::new();
        let dir = base.path().join("sbx");
        write_pointer(&dir, Path::new("/vol/one.btrfs")).unwrap();
        write_pointer(&dir, Path::new("/vol/two.btrfs")).unwrap();
        assert_eq!(
            read_pointer(&dir).as_deref(),
            Some(Path::new("/vol/two.btrfs")),
            "the newer record must win outright, never merge with the old"
        );
        // The rename leaves no temp file behind for the next reader to trip over.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .filter(|n| n.to_string_lossy().starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn the_offer_marker_makes_the_proposal_a_one_time_event() {
        let base = crate::testutil::TmpDir::new();
        let dir = base.path().join("sbx");
        // Never offered on a fresh installation — the offer must be able to happen.
        assert!(!has_been_offered(&dir));
        // Marking it creates the directory if need be and records the offer...
        mark_offered(&dir);
        assert!(has_been_offered(&dir));
        // ...and it stays recorded, so a declined suggestion never becomes a nag.
        mark_offered(&dir);
        assert!(has_been_offered(&dir));
    }

    #[test]
    fn a_malformed_pointer_reads_as_no_pointer() {
        let base = crate::testutil::TmpDir::new();
        let dir = base.path().join("sbx");
        std::fs::create_dir_all(&dir).unwrap();
        for junk in ["", "# only a comment\n", "image =\n", "nothing here\n"] {
            std::fs::write(dir.join(POINTER), junk).unwrap();
            assert_eq!(read_pointer(&dir), None, "{junk:?}");
        }
    }

    /// Build a tree with the two shapes a nix store actually has: files deduplicated into
    /// hardlinks, and directories left read-only.
    fn store_shaped_tree(root: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(root.join("store/pkg/bin")).unwrap();
        std::fs::create_dir_all(root.join("store/.links")).unwrap();
        std::fs::write(root.join("store/pkg/bin/tool"), b"payload").unwrap();
        // The same content reachable under two names, as `.links` deduplication leaves it.
        std::fs::hard_link(
            root.join("store/pkg/bin/tool"),
            root.join("store/.links/deadbeef"),
        )
        .unwrap();
        std::os::unix::fs::symlink("bin/tool", root.join("store/pkg/current")).unwrap();
        std::fs::write(root.join("nixpkgs.lock"), b"rev").unwrap();
        // A store's directories are read-only; a copy that created them that way could not
        // then write their contents.
        std::fs::set_permissions(
            root.join("store/pkg/bin"),
            std::fs::Permissions::from_mode(0o555),
        )
        .unwrap();
    }

    #[test]
    fn copying_a_store_shaped_tree_keeps_its_hardlinks_and_read_only_directories() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let base = crate::testutil::TmpDir::new();
        let src = base.path().join("src");
        let dst = base.path().join("dst");
        store_shaped_tree(&src);

        let before = census(&src, &[]).unwrap();
        let copied = copy_tree(&src, &dst, &[]).unwrap();
        assert_eq!(copied, before, "the copy must tally with the original");

        // Two names, one file — the property the whole migration hinges on. Without it the
        // census would report 3 distinct inodes here instead of 2, and a real store would
        // double in size.
        assert_eq!(before.files, 3);
        assert_eq!(before.inodes, 2, "the hardlinked pair counts once");
        let a = std::fs::metadata(dst.join("store/pkg/bin/tool")).unwrap();
        let b = std::fs::metadata(dst.join("store/.links/deadbeef")).unwrap();
        assert_eq!(
            (a.dev(), a.ino()),
            (b.dev(), b.ino()),
            "the copy must re-create the hardlink, not duplicate the content"
        );

        // The read-only directory is read-only again — and its contents made it in, which is
        // what proves the mode was applied after the writes rather than before.
        let mode = std::fs::metadata(dst.join("store/pkg/bin"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o555, "directory permissions must be carried across");
        assert_eq!(
            std::fs::read(dst.join("store/pkg/bin/tool")).unwrap(),
            b"payload"
        );

        // Symlinks are re-created as symlinks, pointing where they did.
        assert_eq!(
            std::fs::read_link(dst.join("store/pkg/current")).unwrap(),
            PathBuf::from("bin/tool")
        );
        assert!(
            std::fs::symlink_metadata(dst.join("store/pkg/current"))
                .unwrap()
                .is_symlink()
        );
    }

    #[test]
    fn a_socket_is_counted_but_not_copied() {
        use std::os::unix::net::UnixListener;
        let base = crate::testutil::TmpDir::new();
        let src = base.path().join("src");
        let dst = base.path().join("dst");
        std::fs::create_dir_all(src.join("egress")).unwrap();
        std::fs::write(src.join("keep"), b"real").unwrap();
        // Exactly what a launch leaves behind. `std::fs::copy` fails outright on one, so a
        // copy that did not classify it would abort the whole migration.
        let _sock = UnixListener::bind(src.join("egress/proxy-1.sock")).unwrap();

        let before = census(&src, &[]).unwrap();
        assert_eq!(before.special, 1, "the socket is seen");
        assert_eq!(before.files, 1, "and is not counted as a file");

        let copied = copy_tree(&src, &dst, &[]).expect("a socket must not abort the copy");
        assert_eq!(copied, before, "both sides tally");
        assert!(dst.join("keep").exists());
        assert!(
            !dst.join("egress/proxy-1.sock").exists(),
            "a dead socket is not carried across"
        );
    }

    #[test]
    fn a_skipped_top_level_entry_is_left_behind_but_a_nested_namesake_is_not() {
        let base = crate::testutil::TmpDir::new();
        let src = base.path().join("src");
        let dst = base.path().join("dst");
        std::fs::create_dir_all(src.join("store")).unwrap();
        std::fs::write(src.join(POINTER), b"image = \"/x\"\n").unwrap();
        // A file of the same name deeper in the tree must still be copied: the skip list
        // names top-level entries, not a pattern.
        std::fs::write(src.join("store").join(POINTER), b"not the pointer").unwrap();

        let c = copy_tree(&src, &dst, &[POINTER]).unwrap();
        assert!(!dst.join(POINTER).exists(), "the pointer stays behind");
        assert!(dst.join("store").join(POINTER).exists(), "nested is copied");
        assert_eq!(c.files, 1);
        assert_eq!(census(&src, &[POINTER]).unwrap(), c);
    }

    #[test]
    fn a_provisioned_mkfs_runs_hardened_with_only_what_it_needs() {
        let args = |c: &Command| -> Vec<String> {
            std::iter::once(c.get_program())
                .chain(c.get_args())
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        let image = Path::new("/data/vol/sbx-storage.btrfs");
        let seed = Path::new("/data/vol/sbx-storage.seed");

        let (host, host_fds) = mkfs_command(
            &Mkfs::Host(PathBuf::from("/usr/bin/mkfs.btrfs")),
            image,
            seed,
            "l",
        );
        assert!(
            host_fds.is_empty(),
            "the host's own tool runs uncaged, so there is nothing to keep open"
        );
        assert_eq!(
            args(&host),
            vec![
                "/usr/bin/mkfs.btrfs",
                "-q",
                "-L",
                "l",
                "--rootdir",
                "/data/vol/sbx-storage.seed",
                "/data/vol/sbx-storage.btrfs"
            ]
        );

        let (owned, owned_fds) = mkfs_command(
            &Mkfs::Owned {
                bwrap: PathBuf::from("/e/bwrap"),
                store_nix: PathBuf::from("/d/store/nix"),
                bin: PathBuf::from("/nix/store/x-btrfs-progs/bin/mkfs.btrfs"),
            },
            image,
            seed,
            "l",
        );
        let a = args(&owned);
        assert_eq!(a[0], "/e/bwrap");
        // The mandatory syscall denylist, ahead of everything: this argv is built by hand rather
        // than through the `SandboxSpec` keystone, so "hardened like every other helper" below is
        // only true if the filters are here too.
        assert_eq!(
            (a[1].as_str(), a[3].as_str()),
            ("--add-seccomp-fd", "--add-seccomp-fd"),
            "{a:?}"
        );
        assert_eq!(owned_fds.len(), 2, "one descriptor per filter, held open");
        // Hardened like every other helper sbx runs, the network included: formatting an
        // image reaches nothing.
        for expected in [
            "--unshare-user",
            "--unshare-net",
            "--unshare-pid",
            "--clearenv",
            "--die-with-parent",
            "--cap-drop",
        ] {
            assert!(
                a.contains(&expected.to_string()),
                "{expected} missing: {a:?}"
            );
        }
        // The store is read-only — it backs the binary's interpreter, nothing more.
        let nix_at = a.iter().position(|x| x == "/d/store/nix").expect("bound");
        assert_eq!(a[nix_at - 1], "--ro-bind");
        assert_eq!(a[nix_at + 1], "/nix");
        // The seed is read; only the image's own directory is writable. Binding the whole
        // parent is what lets mkfs create the file, and it is the sole write surface.
        let seed_at = a
            .iter()
            .position(|x| x == "/data/vol/sbx-storage.seed")
            .expect("bound");
        assert_eq!(a[seed_at - 1], "--ro-bind");
        assert_eq!(a.iter().filter(|x| *x == "--bind").count(), 1);
        // And the read-only seed has to survive the writable parent that contains it: bwrap
        // applies binds in argv order, so the parent must be emitted first or it covers the seed.
        let parent_at = a.iter().position(|x| x == "/data/vol").expect("bound");
        assert_eq!(a[parent_at - 1], "--bind");
        assert!(
            parent_at < seed_at,
            "the writable parent bind shadows the seed's read-only bind: {a:?}"
        );
        // The command still ends with the real invocation, arguments intact.
        assert_eq!(
            &a[a.len() - 6..],
            &[
                "-q",
                "-L",
                "l",
                "--rootdir",
                "/data/vol/sbx-storage.seed",
                "/data/vol/sbx-storage.btrfs"
            ]
        );
    }

    #[test]
    fn free_bytes_reads_the_filesystem_holding_the_path() {
        let base = crate::testutil::TmpDir::new();
        // A real figure, and the same for a file as for its directory — enough to know the
        // call is answering about the filesystem rather than the entry.
        let dir = free_bytes(base.path()).expect("a mounted filesystem reports its free space");
        assert!(dir > 0);
        assert_eq!(free_bytes(Path::new("/nonexistent-by-construction")), None);
    }

    #[test]
    fn state_reports_absent_for_a_missing_image() {
        let base = crate::testutil::TmpDir::new();
        assert_eq!(
            state(&base.path().join("nope.btrfs")).unwrap(),
            State::Absent
        );
    }

    /// The `noexec` refusal used to live only after the `udisksctl mount` in `up`, which put it
    /// behind two early returns that skip it: `ensure_mounted` and `up` both hand back
    /// `State::Mounted` without looking at the options it carries. So it ran on exactly one call in
    /// a volume's life — and since the refusal returned `Err` without unmounting, the volume it had
    /// just refused stayed up, and the *next* call took the early return and accepted it.
    ///
    /// The decision itself is what is pinned here; the two arms now route through it.
    #[test]
    fn a_noexec_mount_point_is_refused_wherever_it_is_handed_back() {
        let mp = PathBuf::from("/run/media/u/sbx");
        let err = refuse_noexec(mp.clone(), "rw,noexec,relatime")
            .expect_err("a noexec volume cannot host a store");
        assert!(err.contains("noexec"), "{err}");
        assert!(
            err.contains("/run/media/u/sbx"),
            "the refusal must name the mount point: {err}"
        );

        // An ordinary mount passes through unchanged, options that merely *contain* the word
        // included — the option list is comma-separated, not a substring search.
        assert_eq!(refuse_noexec(mp.clone(), "rw,relatime").unwrap(), mp);
        assert_eq!(
            refuse_noexec(mp.clone(), "rw,noexecfoo,relatime").unwrap(),
            mp,
            "`noexecfoo` is not `noexec`"
        );
        assert_eq!(refuse_noexec(mp.clone(), "").unwrap(), mp);
    }

    #[test]
    fn init_refuses_an_existing_image_so_a_store_is_never_destroyed() {
        let base = crate::testutil::TmpDir::new();
        let image = base.path().join("vol.btrfs");
        std::fs::write(&image, b"a store lives here").unwrap();
        let nowhere = Mkfs::Host(PathBuf::from("/nonexistent-by-construction"));
        let err = init(&image, DEFAULT_SIZE_BYTES, DEFAULT_LABEL, &nowhere).unwrap_err();
        assert!(err.contains("already exists"), "{err}");
        // Untouched.
        assert_eq!(std::fs::read(&image).unwrap(), b"a store lives here");
    }

    /// The image *is* the whole data directory once the volume is adopted — the shared nix store,
    /// every project's home, `apt-keys/`, session state. `File::create` takes `0666 & ~umask`, so
    /// under the near-universal `umask 022` it landed `0644` and any other local account could read
    /// every byte by loop-mounting a copy. Tightening it later would not help: the image is read as
    /// raw bytes on the host, not through the mount.
    ///
    /// Asserted under a deliberately loose umask, because the umask is exactly what must not decide
    /// this. `lock_image` beside it already passes `mode(0o600)` for a file holding nothing but an
    /// flock.
    #[test]
    fn the_image_is_owner_only_whatever_the_umask_says() {
        use std::os::unix::fs::PermissionsExt;
        let base = crate::testutil::TmpDir::new();
        let image = base.path().join("vol.btrfs");
        // A `mkfs` that succeeds without doing anything, so `init` runs to the end and leaves the
        // image it created in place to be inspected. What is under test is the open, not the format.
        let noop = Mkfs::Host(PathBuf::from("/bin/true"));

        // SAFETY: `umask` is a per-process scalar syscall; the previous value is restored below.
        let previous = unsafe { libc::umask(0o022) };
        let made = init(&image, DEFAULT_SIZE_BYTES, DEFAULT_LABEL, &noop);
        // SAFETY: restoring the value the call above returned.
        unsafe { libc::umask(previous) };
        made.expect("a no-op mkfs leaves init on its success path");

        let mode = std::fs::metadata(&image).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the image carries the whole data directory and must not take the umask's answer"
        );
        assert!(
            !image.with_extension("seed").exists(),
            "the seed directory is cleaned up either way"
        );
    }

    /// `init` promises it "can never destroy a store". The `exists()` check is a separate stat from
    /// the create, so the atomicity has to come from the open itself: `create_new` refuses an image
    /// that appeared in between, where `File::create` would have truncated it.
    #[test]
    fn init_never_truncates_an_image_that_appears_after_the_existence_check() {
        let base = crate::testutil::TmpDir::new();
        let image = base.path().join("vol.btrfs");
        let nowhere = Mkfs::Host(PathBuf::from("/nonexistent-by-construction"));

        // Stand in for the racing writer by creating the image the `exists()` check did not see:
        // calling `init` on a path that already holds a store must fail without writing to it.
        std::fs::write(&image, b"a store lives here").unwrap();
        assert!(init(&image, DEFAULT_SIZE_BYTES, DEFAULT_LABEL, &nowhere).is_err());
        assert_eq!(std::fs::read(&image).unwrap(), b"a store lives here");
    }

    #[test]
    fn init_refuses_an_unsafe_label_before_touching_the_disk() {
        let base = crate::testutil::TmpDir::new();
        let image = base.path().join("vol.btrfs");
        let nowhere = Mkfs::Host(PathBuf::from("/nonexistent-by-construction"));
        assert!(init(&image, DEFAULT_SIZE_BYTES, "../escape", &nowhere).is_err());
        assert!(
            !image.exists(),
            "nothing may be created for a refused label"
        );
    }

    #[test]
    fn the_default_image_is_a_sibling_of_the_data_directory_not_inside_it() {
        let img = default_image(Path::new("/home/u/.local/share"));
        assert_eq!(img, PathBuf::from("/home/u/.local/share/sbx-storage.btrfs"));
        // Load-bearing: the volume *becomes* `<base>/sbx`, so an image inside it would be
        // hidden by its own mount.
        assert!(!img.starts_with("/home/u/.local/share/sbx/"));
    }

    #[test]
    fn a_volume_is_recommended_only_where_it_adds_something() {
        // The two things a volume brings are block sharing and compression, so the question is
        // whether either is missing — not whether the filesystem is copy-on-write.
        for cow in [FsKind::Btrfs, FsKind::Zfs, FsKind::Bcachefs] {
            assert!(
                !volume_adds_anything(Some(cow), None),
                "{} already has both",
                cow.name()
            );
        }
        // Nothing persistent lives on a tmpfs, so housing a data directory in a volume there is
        // beside the point — however un-copy-on-write it is.
        assert!(!volume_adds_anything(Some(FsKind::Tmpfs), None));
        // ext lacks both; XFS shares blocks but does not compress, which the volume still adds.
        assert!(volume_adds_anything(Some(FsKind::Ext), None));
        assert!(volume_adds_anything(Some(FsKind::Xfs), None));

        // An unrecognized filesystem has no table to consult, so the measurement decides — and
        // only a definite "it cannot share blocks" is enough to recommend one.
        let unknown = Some(FsKind::Other(0xdead));
        assert!(volume_adds_anything(unknown, Some(false)));
        assert!(!volume_adds_anything(unknown, Some(true)));
        assert!(
            !volume_adds_anything(unknown, None),
            "an unmeasurable unknown filesystem is not a recommendation"
        );

        // And a filesystem that could not be identified at all is never a recommendation.
        assert!(!volume_adds_anything(None, Some(false)));
    }

    #[test]
    fn a_copy_on_write_filesystem_is_recognized_as_one() {
        assert!(FsKind::Btrfs.is_cow());
        assert!(FsKind::Zfs.is_cow());
        assert!(FsKind::Bcachefs.is_cow());
        // The filesystems a volume actually helps are not copy-on-write.
        assert!(!FsKind::Ext.is_cow());
        assert!(!FsKind::Xfs.is_cow());
        // Ephemeral is a separate axis from copy-on-write, and the reason a volume is pointless
        // on a tmpfs — where the data directory's problem is that it will not be there at all.
        assert!(FsKind::Tmpfs.is_ephemeral());
        assert!(!FsKind::Btrfs.is_ephemeral());
        assert!(!FsKind::Ext.is_ephemeral());
        assert_eq!(FsKind::Ext.name(), "ext4");
        assert!(FsKind::Other(0xdead).name().contains("0x0000dead"));
    }

    #[test]
    fn fs_kind_reads_the_filesystem_and_walks_up_to_an_existing_ancestor() {
        let base = crate::testutil::TmpDir::new();
        // A real directory sits on some filesystem — whichever the test host uses.
        assert!(fs_kind(base.path()).is_some());
        // A path that does not exist yet has no filesystem of its own...
        let missing = base.path().join("a/b/c");
        assert_eq!(fs_kind(&missing), None);
        // ...but resolves to the nearest ancestor that does — the filesystem it would be
        // created on, which is what a first-run probe needs before the data directory exists.
        assert_eq!(fs_kind_of_nearest(&missing), fs_kind(base.path()));
        // And that ancestor is reachable as a path, not only as a kind: a probe that measures
        // something about the filesystem must measure it on the very directory whose kind was
        // read, or the two signals would describe different filesystems on a first run.
        assert_eq!(nearest_existing(&missing), Some(base.path()));
        assert_eq!(nearest_existing(base.path()), Some(base.path()));
    }

    /// Build a `Preflight` with each signal set explicitly, so the derived decisions can be
    /// exercised without a real host, a mount, or a daemon.
    fn preflight(
        kernel_btrfs: bool,
        loop_control: bool,
        udisks: bool,
        host_fs: Option<FsKind>,
        remote_session: bool,
    ) -> Preflight {
        Preflight {
            kernel_btrfs,
            loop_control,
            udisks,
            host_fs,
            // Only an unrecognized filesystem is ever measured, and these cases name theirs.
            shares_blocks: None,
            remote_session,
        }
    }

    #[test]
    fn preflight_separates_can_mount_from_worth_recommending() {
        // A local ext4 desktop with everything present: mountable and worth recommending.
        let ideal = preflight(true, true, true, Some(FsKind::Ext), false);
        assert!(ideal.can_mount());
        assert!(ideal.mount_blocker().is_none());
        assert!(ideal.recommends_volume());

        // Already copy-on-write: mountable, but a volume would add nothing, so not recommended.
        let cow = preflight(true, true, true, Some(FsKind::Btrfs), false);
        assert!(cow.can_mount());
        assert!(
            !cow.recommends_volume(),
            "no point wrapping a copy-on-write filesystem in a volume"
        );

        // Remote session: udisks would ask for a password, so it is not recommended — but it is
        // not a hard blocker either, since the mount could still be authorized.
        let remote = preflight(true, true, true, Some(FsKind::Ext), true);
        assert!(remote.can_mount());
        assert!(!remote.recommends_volume());

        // Kernel btrfs not detected but the hardware is there: not recommended (conservative),
        // yet not blocked — a mount would try to autoload the module.
        let no_kernel = preflight(false, true, true, Some(FsKind::Ext), false);
        assert!(no_kernel.can_mount());
        assert!(no_kernel.mount_blocker().is_none());
        assert!(!no_kernel.recommends_volume());
    }

    #[test]
    fn a_remote_session_is_detected_from_either_ssh_variable() {
        use std::ffi::OsStr;
        let set = Some(OsStr::new("x"));
        // Either SSH variable alone marks the session remote — so a client that exports only one
        // is still recognised, and the recommendation is withheld where udisks would need a password.
        assert!(is_remote_session(set, None), "SSH_CONNECTION alone");
        assert!(is_remote_session(None, set), "SSH_TTY alone");
        assert!(is_remote_session(set, set));
        // Neither set is the locally-active session the whole feature is built for.
        assert!(!is_remote_session(None, None));
    }

    #[test]
    fn a_missing_hard_requirement_is_a_named_blocker() {
        // No udisks and no loop are the genuinely fatal cases, and the blocker names each.
        let no_udisks = preflight(true, true, false, Some(FsKind::Ext), false);
        assert!(!no_udisks.can_mount());
        assert!(no_udisks.mount_blocker().unwrap().contains("udisks"));

        let no_loop = preflight(true, false, true, Some(FsKind::Ext), false);
        assert!(no_loop.mount_blocker().unwrap().contains("loop"));

        // Both missing: both are named, so one message explains the whole situation.
        let neither = preflight(true, false, false, Some(FsKind::Ext), false);
        let msg = neither.mount_blocker().unwrap();
        assert!(msg.contains("loop") && msg.contains("udisks"), "{msg}");
    }
}
