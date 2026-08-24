//! `sbx storage`: create, mount and inspect a volume sbx owns for its data directory.
//!
//! The data directory is the one tree that grows without bound, and on a filesystem whose
//! inode table is fixed at creation it can crowd the host long before the disk is full. A
//! volume turns the whole tree into a single host file that compresses and grows on demand.
//!
//! Adopting a volume is one deliberate act — `sbx storage use` — which records it so every
//! later command mounts and follows it with nothing to remember and no variable to carry.
//! Until then nothing changes, so no existing installation behaves differently for having
//! been upgraded. `SBX_DATA_DIR` still overrides everything, for a one-off.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::{diag, help, sandbox, session, storage, store, style};

/// The data directory sbx would use with no volume in play. Everything here is anchored to it
/// rather than to the live one: once a pointer redirects sbx into a volume, the live directory
/// *is* the mount point, whose parent is somewhere under `/run` — not where the image and the
/// pointer live.
fn default_dir() -> Result<PathBuf, String> {
    store::Layout::default_data_dir()
        .ok_or_else(|| "cannot locate sbx's data directory".to_string())
}

/// Resolve the image path: an explicit `--image`, else the default beside the data directory.
fn image_path(explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    let image = match explicit {
        Some(p) => {
            if !p.is_absolute() {
                return Err(format!(
                    "--image must be an absolute path (got {})",
                    p.display()
                ));
            }
            p
        }
        None => {
            let dir = default_dir()?;
            let base = dir
                .parent()
                .ok_or_else(|| "cannot locate the data directory's parent".to_string())?;
            storage::default_image(base)
        }
    };
    // Checked here, where every subcommand resolves its image, so a path the pointer file cannot
    // carry is refused before anything is created or mounted — `storage::write_pointer` holds the
    // same rule, and would otherwise only reach it once a volume was already up. The default path is
    // checked too: it is built from the data directory, which `$HOME` or `SBX_DATA_DIR` decides.
    storage::pointer_can_name(&image)?;
    Ok(image)
}

/// The subtrees whose presence means the default data directory holds real data — exactly what
/// adopting a volume would strand.
const DATA_SUBTREES: &[&str] = &["store", "projects", "apps"];

/// What the default data directory already holds, so adoption can refuse to orphan it.
fn occupied_subtrees(dir: &Path) -> Vec<&'static str> {
    DATA_SUBTREES
        .iter()
        .copied()
        .filter(|n| dir.join(n).is_dir())
        .collect()
}

pub(crate) fn storage_cmd(args: Vec<OsString>) -> ExitCode {
    if let Some(code) = help::maybe_help("storage", &args) {
        return code;
    }
    match args.first().and_then(|a| a.to_str()) {
        Some("init") => init(args[1..].to_vec()),
        Some("status") => status(args[1..].to_vec()),
        Some("up") => up(args[1..].to_vec()),
        Some("down") => down(args[1..].to_vec()),
        Some("use") => use_volume(args[1..].to_vec()),
        Some("migrate") => migrate(args[1..].to_vec()),
        Some("unuse") => unuse_volume(args[1..].to_vec()),
        None => {
            eprint!("{}", help::page_usage(&["storage"]).unwrap_or_default());
            ExitCode::from(2)
        }
        Some(other) => {
            diag::error(&format!("sbx: storage: unknown subcommand `{other}`"));
            diag::hint("       run `sbx help storage` for usage.");
            ExitCode::from(2)
        }
    }
}

/// Pull the options these verbs share out of an argument list.
struct Opts {
    image: Option<PathBuf>,
    size: Option<String>,
    label: Option<String>,
    json: bool,
    force: bool,
}

fn parse_opts(args: Vec<OsString>) -> Result<Opts, String> {
    let mut o = Opts {
        image: None,
        size: None,
        label: None,
        json: false,
        force: false,
    };
    // The image is kept as an `OsString`: a path is not required to be UTF-8, and refusing
    // one that is not would rule out a perfectly good directory.
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let text = |v: Option<OsString>, what: &str| -> Result<String, String> {
            v.ok_or_else(|| format!("{what} needs a value"))?
                .into_string()
                .map_err(|_| format!("{what} must be text"))
        };
        match a.to_str() {
            Some("--json") => o.json = true,
            Some("--force") => o.force = true,
            Some("--image") => {
                o.image = Some(PathBuf::from(
                    it.next().ok_or("--image needs a path".to_string())?,
                ))
            }
            Some("--size") => o.size = Some(text(it.next(), "--size (e.g. 200G)")?),
            Some("--label") => o.label = Some(text(it.next(), "--label")?),
            _ => return Err(format!("unknown option `{}`", a.to_string_lossy())),
        }
    }
    Ok(o)
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    diag::error(&format!("sbx storage: {msg}"));
    ExitCode::FAILURE
}

/// Fail early, with one message naming every missing prerequisite, when this host cannot mount a
/// btrfs volume — rather than surfacing the first obstacle deep inside the mount sequence, where
/// the message would be about a socket or a device instead of about the missing capability.
fn ensure_mountable(image: &Path) -> Result<(), String> {
    let base = image.parent().unwrap_or(image);
    match storage::Preflight::probe(base).mount_blocker() {
        Some(blocker) => Err(format!(
            "this host cannot mount a btrfs volume: {blocker}\n\
             \x20      $SBX_DATA_DIR can still point sbx at an existing btrfs mount"
        )),
        None => Ok(()),
    }
}

fn init(args: Vec<OsString>) -> ExitCode {
    let opts = match parse_opts(args) {
        Ok(o) => o,
        Err(e) => return fail(e),
    };
    let image = match image_path(opts.image) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    let size = match opts.size.as_deref().map(storage::parse_size).transpose() {
        Ok(s) => s.unwrap_or(storage::DEFAULT_SIZE_BYTES),
        Err(e) => return fail(e),
    };
    let label = opts.label.as_deref().unwrap_or(storage::DEFAULT_LABEL);

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    // A volume that cannot be mounted here is still worth creating on request — the user may know
    // more than the probe — so this warns rather than refuses, but says so before the work.
    if let Some(blocker) =
        storage::Preflight::probe(image.parent().unwrap_or(&image)).mount_blocker()
    {
        diag::error(&format!(
            "sbx storage: note: this host cannot mount it — {blocker}"
        ));
        diag::hint(
            "       the volume will still be created; `sbx storage use` needs those to start using it.",
        );
    }
    println!(
        "creating {} ({} logical, sparse — it occupies only what is written)",
        image.display(),
        sandbox::human_bytes(size)
    );
    // Resolved before the image is created, so a host without btrfs-progs learns that sbx is
    // fetching its own rather than watching an unexplained pause.
    let mkfs = match storage::resolve_mkfs() {
        Ok(m) => m,
        Err(e) => return fail(e),
    };
    println!("  formatting with {}", mkfs.origin());
    if let Err(e) = storage::init(&image, size, label, &mkfs) {
        return fail(e);
    }
    println!(
        "  {}created{} — {}",
        pal.ok,
        pal.reset,
        style::prose("start using it with `sbx storage use`", &pal)
    );
    ExitCode::SUCCESS
}

fn up(args: Vec<OsString>) -> ExitCode {
    let opts = match parse_opts(args) {
        Ok(o) => o,
        Err(e) => return fail(e),
    };
    let image = match image_path(opts.image) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    if let Err(e) = ensure_mountable(&image) {
        return fail(e);
    }
    let mount_point = match storage::up(&image) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    println!("mounted at {}", mount_point.display());
    // Mounting is not adopting. Say what the remaining step is, unless it is already done —
    // in which case `up` was only a manual nudge and there is nothing to suggest.
    let adopted = default_dir()
        .ok()
        .and_then(|d| storage::read_pointer(&d))
        .as_deref()
        == Some(image.as_path());
    if !adopted {
        println!(
            "\nsbx is not using it yet:\n  {}sbx storage use{}",
            pal.head, pal.reset
        );
    }
    ExitCode::SUCCESS
}

fn down(args: Vec<OsString>) -> ExitCode {
    let opts = match parse_opts(args) {
        Ok(o) => o,
        Err(e) => return fail(e),
    };
    let image = match image_path(opts.image) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };

    // Never pull the volume out from under a running sandbox: its store lives there.
    let mounted = storage::state(&image)
        .ok()
        .and_then(|s| s.mount_point().map(Path::to_path_buf));
    if let Some(mp) = mounted.as_deref() {
        let live = live_sessions_under(mp);
        if live > 0 {
            return fail(format!(
                "{live} session(s) are still running from {} — stop them first \
                 (`sbx session ls`, `sbx session stop --all`)",
                mp.display()
            ));
        }
    }
    if let Err(e) = storage::down(&image) {
        return fail(e);
    }
    println!("unmounted and detached");

    // Unmounting a volume sbx is set to follow is temporary by design: the next command
    // mounts it again. Saying so beats leaving the user to wonder why it came back.
    if let Ok(dir) = default_dir()
        && storage::read_pointer(&dir).as_deref() == Some(image.as_path())
    {
        let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
        println!(
            "\n{}",
            style::prose(
                "note: sbx is still set to use this volume, so the next command will mount \
                     it again.\n      `sbx storage unuse` stops that.",
                &pal
            )
        );
    }
    ExitCode::SUCCESS
}

/// `sbx storage use`: record that sbx's data lives in the volume, so every later command
/// mounts and follows it with nothing to remember.
fn use_volume(args: Vec<OsString>) -> ExitCode {
    let opts = match parse_opts(args) {
        Ok(o) => o,
        Err(e) => return fail(e),
    };
    let image = match image_path(opts.image) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    let dir = match default_dir() {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    if let Err(e) = ensure_mountable(&image) {
        return fail(e);
    }

    // Mount before adopting: a pointer at a volume that will not mount would leave every
    // later command failing closed, with no obvious way back.
    let mount_point = match storage::ensure_mounted(&image) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };

    // Adopting does not move anything. Data already in the default directory would simply
    // stop being visible, which for a store of tens of gigabytes is not a mistake to make
    // quietly.
    let occupied = occupied_subtrees(&dir);
    if !occupied.is_empty() && !opts.force {
        return fail(format!(
            "{} already holds {} — adopting the volume would leave that behind, not move it.\n\
             \x20      Copy it into {} while no sandbox is running, then re-run; or pass \
             --force to adopt an empty volume anyway.",
            dir.display(),
            occupied.join(", "),
            mount_point.display()
        ));
    }

    if let Err(e) = storage::write_pointer(&dir, &image) {
        return fail(format!("cannot record the volume: {e}"));
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    println!(
        "{}sbx now uses{} {}",
        pal.ok,
        pal.reset,
        mount_point.display()
    );
    println!("it is mounted automatically from now on — no environment variable needed.");
    ExitCode::SUCCESS
}

/// `sbx storage migrate`: copy the existing data directory into the volume, then start using
/// it — the step `use` refuses to take on your behalf.
///
/// The order is what makes this safe. Everything is copied and checked **before** anything
/// changes, so the original stays authoritative for the whole long part; the switch is a
/// single atomic write; and only then is the original set aside, under a name that says what
/// it is. An interruption before the switch leaves the installation exactly as it was.
fn migrate(args: Vec<OsString>) -> ExitCode {
    let opts = match parse_opts(args) {
        Ok(o) => o,
        Err(e) => return fail(e),
    };
    let image = match image_path(opts.image) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    let dir = match default_dir() {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());

    if storage::read_pointer(&dir).is_some() {
        return fail("sbx already uses a volume — `sbx storage unuse` first if you meant to");
    }
    if !dir.is_dir() {
        return fail(format!(
            "{} does not exist — there is nothing to migrate; `sbx storage use` adopts an \
             empty volume",
            dir.display()
        ));
    }

    // A sandbox writing into the source while it is copied would put an inconsistent store in
    // the volume — and the copy would then be checked against a moving original.
    let live = live_sessions_under(&dir);
    if live > 0 {
        return fail(format!(
            "{live} session(s) are running — stop them first (`sbx session stop --all`)"
        ));
    }
    if let Err(e) = ensure_mountable(&image) {
        return fail(e);
    }

    let mount_point = match storage::ensure_mounted(&image) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    // Migrating into a volume that already holds a data directory would interleave two of
    // them. The pointer file is not data, so a previously-adopted volume can be re-migrated.
    let occupied = occupied_subtrees(&mount_point);
    if !occupied.is_empty() && !opts.force {
        return fail(format!(
            "{} already holds {} — refusing to migrate into it (--force overrides)",
            mount_point.display(),
            occupied.join(", ")
        ));
    }

    // The pointer stays behind in the source directory; it is what is written at the end.
    let skip = [storage::POINTER];
    let before = match storage::census(&dir, &skip) {
        Ok(c) => c,
        Err(e) => return fail(format!("cannot read {}: {e}", dir.display())),
    };
    println!("migrating {} → {}", dir.display(), mount_point.display());
    println!(
        "  {} files ({} distinct), {} dirs, {} symlinks, {}",
        before.files,
        before.inodes,
        before.dirs,
        before.symlinks,
        sandbox::human_bytes(before.bytes)
    );
    if before.special > 0 {
        println!(
            "  {} runtime socket(s) are not carried across — a stopped launch's socket is dead",
            before.special
        );
    }

    // Fail before starting rather than half-way: the volume compresses and shares blocks, so
    // needing the full apparent size is a deliberate over-estimate.
    if let Some(free) = storage::free_bytes(&mount_point)
        && free < before.bytes
    {
        return fail(format!(
            "the volume has {} free but the data is {} — grow the volume, or run \
                 `sbx gc --all --prune` first",
            sandbox::human_bytes(free),
            sandbox::human_bytes(before.bytes)
        ));
    }

    println!("  copying (the original is untouched until this succeeds)…");
    // Read from the directory, not from `occupied` — see [`volume_is_empty`].
    let volume_was_empty = volume_is_empty(&mount_point);
    let copied = match storage::copy_tree(&dir, &mount_point, &skip) {
        Ok(c) => c,
        Err(e) => {
            let swept = volume_was_empty && clear_tree(&mount_point).is_ok();
            return fail(format!(
                "copy failed: {e}\n       nothing was changed; {} is still in use{}",
                dir.display(),
                if swept {
                    " and the volume was cleared, so this can simply be re-run"
                } else {
                    ""
                }
            ));
        }
    };

    // Checked against the original, not merely reported. A count that drifted means something
    // was not carried across — most consequentially the hardlinks a store deduplicates into.
    if copied != before {
        return fail(format!(
            "the copy does not match the original, so nothing was switched over:\n\
             \x20      original {before:?}\n\
             \x20      copy     {copied:?}\n\
             \x20      {} is untouched and still in use",
            dir.display()
        ));
    }
    println!("  {}copy verified{}", pal.ok, pal.reset);

    // The switch. A single atomic write: before it the old directory is authoritative, after
    // it the volume is, and there is no moment in between.
    if let Err(e) = storage::write_pointer(&dir, &image) {
        return fail(format!(
            "cannot record the volume: {e}\n       the copy is in place but unused; \
             {} is still authoritative",
            dir.display()
        ));
    }

    // Only now is the original moved aside — never deleted. Anything that fails from here is
    // cosmetic: sbx is already reading from the volume.
    match set_aside(&dir, &skip) {
        Ok(Some(old)) => {
            println!(
                "\n{}sbx now uses{} {}",
                pal.ok,
                pal.reset,
                mount_point.display()
            );
            println!(
                "the previous data is kept at {} — delete it when you are satisfied:\n  rm -rf {}",
                old.display(),
                old.display()
            );
        }
        Ok(None) => println!(
            "\n{}sbx now uses{} {}",
            pal.ok,
            pal.reset,
            mount_point.display()
        ),
        Err(e) => {
            println!(
                "\n{}sbx now uses{} {}",
                pal.ok,
                pal.reset,
                mount_point.display()
            );
            diag::error(&format!(
                "sbx storage: could not set the previous data aside: {e}"
            ));
            diag::hint("       it is unused now; remove it by hand when you are satisfied.");
        }
    }
    ExitCode::SUCCESS
}

/// Whether the volume holds nothing but sbx's own pointer file — the question the failure sweep in
/// [`migrate`] must answer before it deletes everything in there.
///
/// Asked of the directory rather than of `occupied_subtrees`, which is a different question wearing
/// a similar name. That one tests exactly three entries (`store`, `projects`, `apps`) because its
/// job is "would adopting this strand a data directory". A volume holding anything else — `engine/`,
/// `sessions/`, a `gcroots/` from an older layout, or files with nothing to do with sbx because the
/// user mounted a filesystem of their own at that path — answered *empty* to it, and the sweep then
/// cleared the whole volume on a copy failure, on a comment that said "The volume was verified empty
/// just above".
///
/// `storage::POINTER` is the one entry that does not count: it is sbx's own marker rather than data,
/// which is what lets a previously-adopted volume be re-migrated — the same exemption the refusal
/// above it states.
///
/// A directory that cannot be read answers `false`: the sweep is the destructive branch, so not
/// knowing must mean not sweeping.
fn volume_is_empty(mount_point: &Path) -> bool {
    std::fs::read_dir(mount_point).is_ok_and(|mut entries| {
        entries.all(|e| e.is_ok_and(|e| e.file_name() == storage::POINTER))
    })
}

/// Empty a directory of everything it contains, leaving the directory itself.
///
/// A store's directories are read-only, so they are made writable on the way down — otherwise
/// most of the tree would silently survive the removal.
fn clear_tree(root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut dirs = vec![root.to_path_buf()];
    let mut seen = 0;
    while seen < dirs.len() {
        let dir = dirs[seen].clone();
        seen += 1;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                dirs.push(entry.path());
            }
        }
    }
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

/// Move the migrated subtrees out of the data directory into a dated sibling, leaving the
/// pointer behind. Renames within one filesystem, so it is instant whatever the size.
fn set_aside(dir: &Path, skip: &[&str]) -> std::io::Result<Option<PathBuf>> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let old = dir.with_file_name(format!(
        "{}.old-{stamp}",
        dir.file_name().unwrap_or_default().to_string_lossy()
    ));
    std::fs::create_dir_all(&old)?;
    let mut moved = false;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if skip.contains(&name.to_string_lossy().as_ref()) {
            continue;
        }
        std::fs::rename(entry.path(), old.join(&name))?;
        moved = true;
    }
    if !moved {
        let _ = std::fs::remove_dir(&old);
        return Ok(None);
    }
    Ok(Some(old))
}

/// `sbx storage unuse`: go back to the ordinary data directory. The volume and everything in
/// it are left untouched.
fn unuse_volume(args: Vec<OsString>) -> ExitCode {
    // Parsed for its validation alone: `unuse` clears the pointer wherever it is, so none of
    // the shared options bear on it — but a mistyped one must still be an error, not ignored.
    if let Err(e) = parse_opts(args) {
        return fail(e);
    }
    let dir = match default_dir() {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    if storage::read_pointer(&dir).is_none() {
        println!("sbx is not using a volume.");
        return ExitCode::SUCCESS;
    }
    if let Err(e) = storage::clear_pointer(&dir) {
        return fail(format!("cannot clear the volume record: {e}"));
    }
    println!("sbx now uses {} again.", dir.display());
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    println!(
        "{}",
        style::prose(
            "the volume is untouched — `sbx storage use` goes back to it.",
            &pal
        )
    );
    ExitCode::SUCCESS
}

/// How many live sandboxes are running from the volume.
///
/// The registry lives *inside* a data directory, so the volume's own `sessions/` is the
/// authoritative answer for sandboxes started from it — a registry anywhere else describes a
/// different data directory entirely. Records are liveness-validated on read, so a crashed
/// sandbox never keeps a volume hostage; only a genuinely running one does.
fn live_sessions_under(mount_point: &Path) -> usize {
    session::Registry::at(mount_point)
        .list()
        .map(|v| v.len())
        .unwrap_or(0)
}

/// Describe what sbx's data directory is *currently* backed by, independent of the image being
/// inspected: `volume (<fs>)` when an adopted volume is mounted, else `local (<fs>)` for the host
/// filesystem the default directory sits on. The same distinction `sbx doctor` leads with.
fn active_backing_kind(adopted: Option<&Path>) -> String {
    if let Some(image) = adopted
        && let Ok(storage::State::Mounted { mount_point, .. }) = storage::state(image)
    {
        let fs = storage::fs_kind(&mount_point)
            .map(|k| k.name())
            .unwrap_or_else(|| "btrfs".to_string());
        return format!("volume ({fs})");
    }
    let fs = default_dir()
        .ok()
        .and_then(|d| storage::fs_kind_of_nearest(&d))
        .map(|k| k.name())
        .unwrap_or_else(|| "unknown".to_string());
    format!("local ({fs})")
}

#[derive(serde::Serialize)]
struct StatusView {
    image: PathBuf,
    /// What sbx's data directory is backed by right now — `"local (<fs>)"` or `"volume (<fs>)"`.
    #[serde(rename = "type")]
    kind: String,
    exists: bool,
    /// `"absent"`, `"detached"`, `"attached"` or `"mounted"`.
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    loop_device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mount_point: Option<PathBuf>,
    /// The compression algorithm in force, when the volume has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    compression: Option<String>,
    /// Host bytes the image occupies — what the volume actually costs.
    #[serde(skip_serializing_if = "Option::is_none")]
    host_bytes: Option<u64>,
    /// The size the image declares to the filesystem inside it.
    #[serde(skip_serializing_if = "Option::is_none")]
    capacity_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allocated_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    used_bytes: Option<u64>,
    /// Bytes the image carries on the host beyond the data alive inside it — what a discard has
    /// yet to return. Absent where the two figures it is derived from are not comparable.
    #[serde(skip_serializing_if = "Option::is_none")]
    reclaimable_bytes: Option<u64>,
    /// Whether the kernel has discard work queued, so the figure above can fall on its own.
    ///
    /// A flag rather than the kernel's byte count, which was measured to overstate what the image
    /// would give back — it tracks free space *eligible* for discard, including regions already
    /// punched out of the image, as the sibling `discard_bytes_saved` counter records. Live: a
    /// queue of 1 178 042 368 preceded a return of 838 860 800.
    discard_queued: bool,
    /// Whether sbx is set to follow this volume — the pointer names it — whether or not it is
    /// mounted right now. A volume adopted before a reboot is `adopted` but not mounted.
    adopted: bool,
    /// Whether sbx is reading from it right now: the pointer names it *and* it is mounted.
    in_use: bool,
}

fn status(args: Vec<OsString>) -> ExitCode {
    let opts = match parse_opts(args) {
        Ok(o) => o,
        Err(e) => return fail(e),
    };
    let image = match image_path(opts.image) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    let st = match storage::state(&image) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };

    // Read from the pointer rather than from the live layout: `status` must say what sbx
    // will do next time, which stands even when the volume happens to be unmounted now.
    let adopted = default_dir().ok().and_then(|d| storage::read_pointer(&d));
    let is_adopted = adopted.as_deref() == Some(image.as_path());
    let mut view = StatusView {
        kind: active_backing_kind(adopted.as_deref()),
        exists: !matches!(st, storage::State::Absent),
        state: match st {
            storage::State::Absent => "absent",
            storage::State::Detached => "detached",
            storage::State::Attached { .. } => "attached",
            storage::State::Mounted { .. } => "mounted",
        },
        loop_device: None,
        mount_point: None,
        compression: None,
        host_bytes: storage::image_bytes(&image),
        capacity_bytes: storage::image_capacity(&image),
        allocated_bytes: None,
        used_bytes: None,
        reclaimable_bytes: None,
        discard_queued: false,
        adopted: is_adopted,
        in_use: false,
        image: image.clone(),
    };
    match &st {
        storage::State::Attached { loop_dev } => view.loop_device = Some(loop_dev.clone()),
        storage::State::Mounted {
            loop_dev,
            mount_point,
            options,
        } => {
            view.loop_device = Some(loop_dev.clone());
            view.mount_point = Some(mount_point.clone());
            // The attribute is where `up` records it; a `compress=` mount option is the
            // other way a volume can be compressed, so it stands as a fallback.
            view.compression = storage::compression(mount_point).or_else(|| {
                options
                    .split(',')
                    .find_map(|o| o.strip_prefix("compress=").map(str::to_string))
            });
            view.in_use = is_adopted;
            if let Ok(sp) = storage::space(mount_point) {
                view.allocated_bytes = Some(sp.allocated);
                view.used_bytes = Some(sp.used);
                // Read on the directory holding the image, since that is the filesystem whose
                // block accounting `host_bytes` came from — and a file's blocks are always on its
                // own directory's filesystem, so the two cannot name different ones. The walk-up
                // inside `fs_kind_of_nearest` never fires here: `host_bytes` is `Some` only for an
                // image that exists, and an existing file has an existing parent. Unstattable
                // counts as compressing, which yields no answer rather than a figure on a guess.
                let may_compress = image
                    .parent()
                    .and_then(storage::fs_kind_of_nearest)
                    .is_none_or(storage::FsKind::may_compress);
                view.reclaimable_bytes = view
                    .host_bytes
                    .and_then(|host| storage::reclaimable_bytes(host, sp.used, may_compress));
            }
            view.discard_queued = storage::discard_queue(loop_dev).is_some();
        }
        _ => {}
    }

    if opts.json {
        match serde_json::to_string_pretty(&view) {
            Ok(s) => println!("{s}"),
            Err(e) => return fail(e),
        }
        return ExitCode::SUCCESS;
    }
    render(&view);
    ExitCode::SUCCESS
}

/// Which one-line next-step `status` prints, from whether the volume is mounted and whether sbx
/// is set to follow it. Kept pure so the mapping is unit-tested: the point of the choice is that
/// every branch names `use` (mount *and* adopt) as the way to start using the volume, never `up`
/// (mount only), which is what makes a freshly `init`ed volume look like it was ignored.
enum StatusHint {
    /// Mounted and adopted — sbx reads from it now; nothing to do.
    InUse,
    /// Mounted but not adopted — `sbx storage use` adopts it (or `SBX_DATA_DIR` for a one-off).
    MountedNotAdopted,
    /// Adopted but unmounted, typically after a reboot — sbx re-mounts it on its own.
    AdoptedUnmounted,
    /// Created but neither mounted nor adopted (the state right after `init`) — `use` starts it.
    StartUse,
}

fn status_next_step(mounted: bool, adopted: bool) -> StatusHint {
    match (mounted, adopted) {
        (true, true) => StatusHint::InUse,
        (true, false) => StatusHint::MountedNotAdopted,
        (false, true) => StatusHint::AdoptedUnmounted,
        (false, false) => StatusHint::StartUse,
    }
}

fn render(v: &StatusView) {
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, r, dim) = (pal.head, pal.reset, pal.dim);
    println!("{h}sbx storage{r} — {}", v.image.display());
    println!("  type        {}", v.kind);
    println!("  state       {}", v.state);
    if !v.exists {
        println!(
            "\n{}",
            style::prose("create one with `sbx storage init`.", &pal)
        );
        return;
    }
    if let (Some(host), Some(cap)) = (v.host_bytes, v.capacity_bytes) {
        println!(
            "  on host     {} {dim}of {} logical{r}",
            sandbox::human_bytes(host),
            sandbox::human_bytes(cap)
        );
    }
    if let Some(l) = &v.loop_device {
        println!("  device      {l}");
    }
    if let Some(mp) = &v.mount_point {
        println!("  mounted at  {}", mp.display());
        println!(
            "  compression {}",
            v.compression.as_deref().unwrap_or("off")
        );
        if let (Some(a), Some(u)) = (v.allocated_bytes, v.used_bytes) {
            println!(
                "  inside      {} used {dim}of {} the filesystem has claimed{r}",
                sandbox::human_bytes(u),
                sandbox::human_bytes(a)
            );
        }
        // Written so the arithmetic can be checked on screen: this is `on host` minus what
        // `inside` says is alive, which is why all three are counted the same way.
        if let Some(gap) = v.reclaimable_bytes {
            // Zero is a state worth reading as a sentence — it is what a volume looks like right
            // after a trim, and "0 B the image carries beyond live data" reads as a fragment.
            let note = if gap == 0 {
                "nothing the image can give back"
            } else {
                "the image carries beyond live data"
            };
            println!("  reclaimable {} {dim}{note}{r}", sandbox::human_bytes(gap));
            // Deliberately unquantified: the kernel's queue counts free space it *may* discard,
            // which measurably exceeds what the image would give back — much of it has already
            // been punched out, as its own `discard_bytes_saved` counter records. So the queue
            // says only that the figure above can fall without being asked, never how far.
            if v.discard_queued {
                println!("              {dim}some of it queued for automatic return{r}");
            }
        }
    }

    // The next step always names `use` — the verb that makes sbx *use* the volume (mount and
    // adopt) — never `up`, which only mounts and leaves sbx still reading its old directory.
    match status_next_step(v.mount_point.is_some(), v.adopted) {
        StatusHint::InUse => {
            println!("\n  {}sbx is reading its data from this volume.{r}", pal.ok);
        }
        StatusHint::MountedNotAdopted => {
            println!(
                "\n  {}",
                style::dim_prose(
                    "mounted but not in use — start using it with `sbx storage use`",
                    &pal
                )
            );
            if let Some(mp) = &v.mount_point {
                println!(
                    "    {dim}(or, for a one-off, export SBX_DATA_DIR={}){r}",
                    mp.display()
                );
            }
        }
        StatusHint::AdoptedUnmounted => {
            println!(
                "\n{}",
                style::prose(
                    "adopted — sbx mounts it automatically next command; \
                     `sbx storage up` mounts it now.",
                    &pal
                )
            );
        }
        StatusHint::StartUse => {
            println!(
                "\n{}",
                style::prose("start using it with `sbx storage use`.", &pal)
            );
        }
    }

    // Only worth a root command past a certain size. A tool that suggests one for a few
    // megabytes every single run teaches the reader to skip the line — and the kernel's own
    // queue covers the small change without being asked.
    const WORTH_TRIMMING: u64 = 1 << 30;
    let worth_trimming = v.reclaimable_bytes.is_some_and(|gap| gap >= WORTH_TRIMMING);
    if let Some(mp) = v.mount_point.as_ref().filter(|_| worth_trimming) {
        println!(
            "\n{}",
            style::dim_prose(
                &format!(
                    "return it now with `sudo fstrim {}`; left alone, only the part already \
                     on the way back goes home.",
                    mp.display()
                ),
                &pal
            )
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The one-time first-launch proposal.
//
// On the first *interactive* launch of a host where a volume is worth it, sbx offers to adopt
// one — exactly once, recorded so a decline never becomes a nag. It is confined to a real
// terminal, so an agent, a pipe or CI never meets it: sbx has no other blocking prompt, and the
// autonomous-agent path must keep none. The standing discoverability route is `sbx doctor`, so a
// declined offer is never a dead end.
// ---------------------------------------------------------------------------------------------

/// The full rule for whether to show the proposal, as a pure predicate over its six signals — so
/// the decision is exercised in tests without a terminal, a data directory or a mount.
fn should_propose(
    is_launch: bool,
    is_tty: bool,
    override_set: bool,
    offered: bool,
    already_using_a_volume: bool,
    recommended: bool,
) -> bool {
    is_launch && is_tty && !override_set && !offered && !already_using_a_volume && recommended
}

/// Whether this invocation is an actual sandbox launch — `sbx run`, or `sbx app run <name>` — as
/// opposed to a management subcommand, an internal `__*` verb, or a help request. Only a launch
/// is a moment where proposing a data-directory volume makes sense.
fn is_launch_invocation(name: &str, rest: &[OsString]) -> bool {
    if rest
        .iter()
        .any(|a| matches!(a.to_str(), Some("--help" | "-h")))
    {
        return false;
    }
    match name {
        "run" => true,
        "app" => rest.first().and_then(|a| a.to_str()) == Some("run"),
        _ => false,
    }
}

/// Offer to adopt a volume, once, when a launch on an eligible host meets a terminal. Called for
/// every command and cheap in the common case: three predicate checks reject an ordinary launch
/// before the data directory is even resolved.
pub(crate) fn maybe_propose_on_launch(name: &str, rest: &[OsString]) {
    let is_launch = is_launch_invocation(name, rest);
    let is_tty = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let override_set = std::env::var_os("SBX_DATA_DIR").is_some_and(|v| !v.is_empty());
    // The cheap gates decide most launches without touching the disk.
    if !is_launch || !is_tty || override_set {
        return;
    }
    let Ok(default_dir) = default_dir() else {
        return;
    };
    let offered = storage::has_been_offered(&default_dir);
    let has_pointer = storage::read_pointer(&default_dir).is_some();
    let pre = storage::Preflight::probe(&default_dir);
    if !should_propose(
        is_launch,
        is_tty,
        override_set,
        offered,
        has_pointer,
        pre.recommends_volume(),
    ) {
        return;
    }
    propose(&default_dir, &pre);
}

/// Show the offer. Empty data directory → a blocking yes/no whose "yes" adopts inline (instant,
/// and it cannot fail on a copy). A data directory that already holds a store → a single
/// non-blocking line pointing at `sbx storage migrate`, since copying it is slow and can fail on
/// its own checks, and hijacking the launch the user typed with that is the wrong trade.
fn propose(default_dir: &Path, pre: &storage::Preflight) {
    use std::io::Write as _;
    let pal = style::Palette::for_stream(std::io::stderr().is_terminal());
    let fs = pre
        .host_fs
        .map(|k| k.name())
        .unwrap_or_else(|| "this filesystem".to_string());

    if !occupied_subtrees(default_dir).is_empty() {
        storage::mark_offered(default_dir);
        diag::error(&format!(
            "{}sbx:{} your data directory is on {fs}. A compressed btrfs volume would cut its \
             inode use to one and roughly halve its size.",
            pal.head, pal.reset
        ));
        diag::hint(&format!(
            "     migrate into one when convenient: {}sbx storage migrate{} \
             (shown once; `sbx doctor` repeats the suggestion).",
            pal.head, pal.reset
        ));
        return;
    }

    // An empty data directory is the true first launch: adopting is instant and cannot fail on a
    // copy, so this is the one place the blocking question is cheap and safe. The default stays
    // *no* — the safe answer for an unattended Enter — but the proposal only fires on a host where
    // a volume is genuinely worth it, so `y` is the recommended answer and the prompt says so.
    eprint!(
        "{}sbx:{} first launch on {fs}. sbx can keep its data in a compressed btrfs volume it \
         mounts itself — one host inode instead of thousands, about half the disk.\n     \
         Adopt one now? [y/N]  (recommended: y — N changes nothing) ",
        pal.head, pal.reset
    );
    let _ = std::io::stderr().flush();
    let yes = read_yes();
    // Recorded whatever the answer, so the question is asked exactly once.
    storage::mark_offered(default_dir);
    if !yes {
        diag::error(
            "sbx: keeping the plain data directory — adopt one later with `sbx storage init` \
             then `sbx storage use`.",
        );
        return;
    }
    match adopt_empty(default_dir) {
        Ok(mount_point) => {
            diag::error(&format!(
                "{}sbx: now using the volume at {}{}",
                pal.ok,
                mount_point.display(),
                pal.reset
            ));
            // The pointer-following path is memoised once per process and may already have been
            // consulted — and cached as "no volume" — while provisioning btrfs-progs into the
            // host store just above. So this process is steered onto the volume by the override,
            // which `from_env` honours *before* the pointer; later processes follow the pointer
            // normally. (btrfs-progs is provisioned into the host store, not the volume — it is
            // only needed to create the filesystem, so that is harmless.)
            // SAFETY: this runs on the first line of `cli::dispatch`, before any command
            // handler has started a thread, and behind a blocking prompt on a terminal —
            // so sbx is single-threaded here and nothing else can be reading the
            // environment while it is rewritten.
            unsafe { std::env::set_var("SBX_DATA_DIR", &mount_point) };
        }
        Err(e) => {
            diag::error(&format!("sbx: could not set up the volume: {e}"));
            diag::hint(
                "     continuing on the plain data directory; `sbx storage init` retries it.",
            );
        }
    }
}

/// Read a single yes/no answer, defaulting to no — an empty line, EOF or an unreadable stdin are
/// all "no", the safe default for a suggestion.
fn read_yes() -> bool {
    use std::io::BufRead;
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Adopt a fresh volume for an empty data directory: create the image if it is not there, mount
/// it, and record the pointer. The empty precondition is the caller's, so nothing is stranded.
fn adopt_empty(default_dir: &Path) -> Result<PathBuf, String> {
    let image = image_path(None)?;
    if matches!(
        storage::state(&image).map_err(|e| e.to_string())?,
        storage::State::Absent
    ) {
        let mkfs = storage::resolve_mkfs()?;
        diag::error(&format!(
            "sbx: formatting a new volume with {}…",
            mkfs.origin()
        ));
        storage::init(
            &image,
            storage::DEFAULT_SIZE_BYTES,
            storage::DEFAULT_LABEL,
            &mkfs,
        )?;
    }
    let mount_point = storage::ensure_mounted(&image)?;
    storage::write_pointer(default_dir, &image).map_err(|e| e.to_string())?;
    Ok(mount_point)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every subcommand resolves its image through one function, so the check that the pointer file
    /// can name the path belongs there: `use` mounts the volume before it records it, and a refusal
    /// discovered at the recording would leave the user with a volume up and an adoption that failed.
    #[test]
    fn an_image_path_the_pointer_cannot_carry_is_refused_before_anything_is_mounted() {
        let err = image_path(Some(PathBuf::from("/vol/a\"b.btrfs")))
            .expect_err("a quote in the path must be refused");
        assert!(err.contains("quote"), "{err}");
        assert!(
            image_path(Some(PathBuf::from("/vol/mes données/a (2).btrfs"))).is_ok(),
            "an ordinary path must still be accepted"
        );
        // The absolute-path rule still comes first, and says its own thing.
        let err = image_path(Some(PathBuf::from("relative.btrfs"))).expect_err("not absolute");
        assert!(err.contains("absolute"), "{err}");
    }

    /// The failure sweep clears the **whole** volume, so what it needs is real emptiness — not the
    /// three-name check `occupied_subtrees` performs for a different question. A volume holding
    /// anything outside that list answered "empty" and was wiped on a copy failure, including files
    /// the user put there themselves.
    #[test]
    fn only_a_volume_holding_nothing_but_the_pointer_counts_as_empty() {
        let tmp = crate::testutil::TmpDir::new();
        let vol = tmp.path();
        assert!(volume_is_empty(vol), "a bare directory is empty");

        // sbx's own marker is not data — this is what lets an adopted volume be re-migrated.
        std::fs::write(vol.join(storage::POINTER), "image = \"/x.btrfs\"\n").unwrap();
        assert!(volume_is_empty(vol), "the pointer alone is still empty");

        // Anything else is not, including the entries `occupied_subtrees` does not name.
        for entry in ["engine", "sessions", "gcroots", "my-own-backup"] {
            std::fs::create_dir(vol.join(entry)).unwrap();
            assert!(
                !volume_is_empty(vol),
                "`{entry}` is content the sweep must not delete"
            );
            assert!(
                occupied_subtrees(vol).is_empty(),
                "`{entry}` is outside DATA_SUBTREES — which is exactly why that check cannot \
                 answer this question"
            );
            std::fs::remove_dir(vol.join(entry)).unwrap();
        }

        // A directory that cannot be read is not "empty": not knowing must mean not sweeping.
        assert!(!volume_is_empty(&vol.join("absent")));
    }

    #[test]
    fn status_next_step_always_points_at_use_never_up() {
        // The state right after `init`: created, not mounted, not adopted. The user must be sent
        // to `use` (mount and adopt), not `up` (mount only) — the confusion this fix removes.
        assert!(matches!(
            status_next_step(false, false),
            StatusHint::StartUse
        ));
        // Adopted before a reboot: unmounted now, but sbx re-mounts it on its own.
        assert!(matches!(
            status_next_step(false, true),
            StatusHint::AdoptedUnmounted
        ));
        // Mounted by `up` but never adopted: adoption is still the missing step.
        assert!(matches!(
            status_next_step(true, false),
            StatusHint::MountedNotAdopted
        ));
        // Mounted and adopted: in use, nothing to do.
        assert!(matches!(status_next_step(true, true), StatusHint::InUse));
    }

    #[test]
    fn parse_opts_reads_the_shared_options_and_refuses_unknown_ones() {
        let o = parse_opts(vec![
            "--image".into(),
            "/vol/a.btrfs".into(),
            "--size".into(),
            "50G".into(),
            "--label".into(),
            "mine".into(),
            "--json".into(),
        ])
        .expect("well-formed");
        assert_eq!(o.image.as_deref(), Some(Path::new("/vol/a.btrfs")));
        assert_eq!(o.size.as_deref(), Some("50G"));
        assert_eq!(o.label.as_deref(), Some("mine"));
        assert!(o.json);

        assert!(parse_opts(vec!["--nope".into()]).is_err());
        // An option that swallows the next argument must not silently take nothing.
        assert!(parse_opts(vec!["--image".into()]).is_err());
        assert!(parse_opts(vec!["--size".into()]).is_err());
    }

    #[test]
    fn adoption_notices_a_data_directory_that_would_be_stranded() {
        let base = crate::testutil::TmpDir::new();
        let dir = base.path().join("sbx");
        std::fs::create_dir_all(&dir).unwrap();

        // A fresh installation has nothing to lose, so adoption is unobstructed.
        assert!(occupied_subtrees(&dir).is_empty());

        // Each of these is data a volume would hide rather than move — the whole reason
        // `use` refuses without --force.
        std::fs::create_dir_all(dir.join("store")).unwrap();
        std::fs::create_dir_all(dir.join("apps")).unwrap();
        assert_eq!(occupied_subtrees(&dir), vec!["store", "apps"]);

        // A pointer file alone is not data: re-adopting an already-adopted volume must not
        // trip the guard.
        let fresh = base.path().join("other");
        storage::write_pointer(&fresh, Path::new("/vol/a.btrfs")).unwrap();
        assert!(occupied_subtrees(&fresh).is_empty());
    }

    #[test]
    fn an_explicit_image_must_be_absolute() {
        // A relative image would resolve against the launch directory, so a volume created
        // from one directory would be invisible from another.
        assert!(image_path(Some(PathBuf::from("rel.btrfs"))).is_err());
        assert_eq!(
            image_path(Some(PathBuf::from("/vol/a.btrfs"))).unwrap(),
            PathBuf::from("/vol/a.btrfs")
        );
    }

    #[test]
    fn the_proposal_needs_every_gate_open() {
        // Every gate open is the one combination that proposes.
        assert!(should_propose(true, true, false, false, false, true));
        // Each gate, closed on its own, suppresses the proposal — the properties that keep it
        // off the agent path and out of an unwanted spot.
        assert!(
            !should_propose(false, true, false, false, false, true),
            "not a launch"
        );
        assert!(
            !should_propose(true, false, false, false, false, true),
            "not a terminal — the agent/pipe/CI guarantee"
        );
        assert!(
            !should_propose(true, true, true, false, false, true),
            "the invoker set SBX_DATA_DIR, which settles it"
        );
        assert!(
            !should_propose(true, true, false, true, false, true),
            "already offered once — never a nag"
        );
        assert!(
            !should_propose(true, true, false, false, true, true),
            "already using a volume"
        );
        assert!(
            !should_propose(true, true, false, false, false, false),
            "the host is not eligible"
        );
    }

    #[test]
    fn only_a_real_launch_is_a_launch_invocation() {
        let os = |s: &str| OsString::from(s);
        // `sbx run …` and `sbx app run <name>` are launches.
        assert!(is_launch_invocation("run", &[os("--"), os("id")]));
        assert!(is_launch_invocation("run", &[]));
        assert!(is_launch_invocation("app", &[os("run"), os("claude")]));
        // A management subcommand and a bare `app` are not.
        assert!(!is_launch_invocation("app", &[os("list")]));
        assert!(!is_launch_invocation("app", &[]));
        // Other verbs — including the internal re-exec verbs — are never launches.
        assert!(!is_launch_invocation("doctor", &[]));
        assert!(!is_launch_invocation("__netns-holder", &[os("bwrap")]));
        // A help request is never a launch, even on a launch verb.
        assert!(!is_launch_invocation("run", &[os("--help")]));
        assert!(!is_launch_invocation("app", &[os("run"), os("-h")]));
    }
}
