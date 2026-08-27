//! Closing part of the project tree off inside the cage — the `[fs]` table, realised as mounts.
//!
//! A `deny` entry is mounted over with a **decoy**: an empty, mode-000 file for a file, an empty
//! directory for a directory. The path keeps its name (a listing still shows it, so nothing about
//! the project's shape changes) and its contents are gone — `EACCES` for the file, `ENOENT` for
//! anything inside the directory. A `readonly` entry is re-bound over itself read-only, so it stays
//! readable and refuses writes in a tree that is otherwise writable. The host file is never touched
//! by either.
//!
//! Two decoys serve every mask in a cage: bubblewrap is happy to bind one source at many
//! destinations, so the number of artifacts staged per launch is fixed rather than growing with the
//! policy. They live under the data dir, never in the project — the cage can write the project, and
//! a decoy it could replace would be no mask at all.
//!
//! **What this is and is not.** It reduces exposure; it is not a boundary of the same class as
//! `[network] deny`. Three things it does not cover, each measured rather than assumed:
//! a second **hard link** to the same file elsewhere in the project reads the content (a mount
//! covers a *path*, not an inode); a file appearing **mid-session** outside a denied *directory* is
//! not covered (mounts are resolved once, at launch — a denied directory, by contrast, stays sealed
//! for the session); and a path nobody listed is simply open. What the cage cannot do is defeat a
//! mask from inside: `umount2`, `mount`, `unshare` and the rest of that family are refused by the
//! mandatory seccomp filter, and it holds no capability in its user namespace.
//!
//! **Why the mid-session gap is not closed by re-masking a live cage.** Applying a mask after
//! launch is reachable — a launcher that creates its own user namespace before `execve`ing
//! bubblewrap leaves the cage's namespaces joinable, and that shape is already built for another
//! purpose. It is not done because of what it would be racing. The mask would have to be in place
//! before the first open, and anything waiting for the file wins that moment reliably: the guard
//! would hold against a path created by accident, never against one created by something that
//! wanted it. A boundary that only holds when nobody is trying is not the class of boundary this
//! table claims to be.
//!
//! What remains useful of the idea is served without joining anything. A path that exists at launch
//! is masked here; a file whose *contents* become sensitive during a session is answered by the
//! `[fs] scan` lens, which examines each open on the supervisor already in place and refuses the
//! next one — no relaunch, and a different question asked at a different moment. What neither
//! covers is closing a path by name when a file appears mid-session and `scan` does not recognise
//! it: a denied *directory* seals that case outright, and a `deny` entry costs a relaunch. That
//! residue is the trigger for reopening this, and the only one.
//!
//! The task plane is the deliberate exception. A masked path is closed in **every** cage the
//! session builds, the agent's and each task's, and a task that legitimately needs the file names
//! it in its own `unmask` — so the credential-bearing operation reads the key while the agent that
//! invokes it never can.

use super::binds::ExtraBind;
use super::spec::Mount;
use crate::config::fspolicy::{FsPolicy, has_wildcard, matches_component};
use std::collections::BTreeSet;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// How many masks a launch may emit before it says the cost is getting real.
///
/// Each mask is one bind, and bubblewrap re-reads `/proc/self/mountinfo` per bind, so the launch
/// cost grows with the *square* of the count — measured at 32 ms for 100 masks and 384 ms for 500.
/// The cure is always the same and is in the message: name the directory instead of its files.
const MASK_WARN: usize = 64;

/// How many masks a launch will emit at all. Past this the wait is seconds and an argv ceiling
/// bubblewrap shares with every other mount comes into view, so the launch refuses rather than
/// quietly dropping the tail — a silently truncated mask list reads exactly like a complete one.
const MASK_MAX: usize = 256;

/// The largest `.git/index` the tracked-file guard will read. An index is a few MiB on a large
/// repository; a file past this is not one the guard needs to be right about, and reading it would
/// be the only unbounded allocation in a launch.
const INDEX_MAX: u64 = 64 * 1024 * 1024;

/// One project path a mask covers, and the entry that named it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Masked {
    /// The absolute host path, canonical and verified to be inside the project.
    pub(crate) path: PathBuf,
    /// Whether it is a directory, which decides which decoy covers it.
    pub(crate) is_dir: bool,
    /// The `[fs]` entry that matched, for a message that points at what to edit.
    pub(crate) pattern: String,
}

/// The project paths a launch will close, expanded from a policy against the project on disk.
#[derive(Debug, Default, Clone)]
pub(crate) struct Expanded {
    /// Paths whose contents the cage may not read.
    pub(crate) denied: Vec<Masked>,
    /// Paths the cage may read but not write.
    pub(crate) readonly: Vec<Masked>,
    /// What the expansion found worth saying: an entry that matched nothing, a file reachable by a
    /// second name, a path git tracks. Surfaced by the launch, never fatal on its own.
    pub(crate) warnings: Vec<String>,
    /// Set when the expansion cannot stand behind the policy: it asks for more masks than
    /// [`MASK_MAX`], or one of its entries names a path this process cannot read at all. The launch
    /// fails closed on either. Dropping the excess would leave paths open while the config says they
    /// are shut, and so would treating a path that cannot be stat'ed as a path that is not there.
    pub(crate) refused: Option<String>,
}

impl Expanded {
    /// Whether anything will be mounted, so a launch with an empty policy stages nothing.
    pub(crate) fn is_empty(&self) -> bool {
        self.denied.is_empty() && self.readonly.is_empty()
    }

    /// How many binds this expansion costs.
    fn count(&self) -> usize {
        self.denied.len() + self.readonly.len()
    }
}

/// The two staged sources every mask in a cage is bound from.
#[derive(Debug, Clone)]
pub(crate) struct Decoys {
    /// An empty, mode-000 regular file: bound over a denied file, it keeps the name in a listing
    /// and answers `EACCES` on open. Mode 000 rather than an empty readable file because "there is
    /// nothing here" and "you may not look" are different answers, and the second is the true one.
    pub(crate) file: PathBuf,
    /// An empty directory: bound over a denied directory, it lists as empty and answers `ENOENT`
    /// for everything inside — including a file the host creates there later in the session, which
    /// is what makes a denied *directory* the only shape that stays sealed over time.
    pub(crate) dir: PathBuf,
}

/// Where a launch stages its decoys: one directory per launcher pid, under the data dir's `fs/`
/// beside the observation socket. Swept by `sbx gc` on the pid, like every other per-launch
/// runtime directory.
pub(crate) fn mask_dir(data_dir: &Path, pid: u32) -> PathBuf {
    data_dir.join("fs").join(format!("mask-{pid}"))
}

/// Create the two decoys for this launch, replacing any residue from a previous run at the same
/// pid. Fails loudly: a mask whose source is missing is a mask bubblewrap would refuse to mount,
/// and a launch that silently continued would run with the paths open.
pub(crate) fn stage_decoys(dir: &Path) -> io::Result<Decoys> {
    let file = dir.join("file");
    let d = dir.join("dir");
    // A leftover from a crashed run at this pid could hold anything, and `gc` keeps entries whose
    // pid reads live — which this launch's pid does. So both decoys are re-made rather than reused:
    // an "empty" directory that still held a predecessor's contents would be no mask at all.
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_file(&file);
    std::fs::create_dir_all(&d)?;
    std::fs::write(&file, b"")?;
    // Written empty first, then closed off: a decoy the launch could not read either is what makes
    // the refusal come from the file's own mode rather than from where it happens to sit.
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000))?;
    Ok(Decoys { file, dir: d })
}

/// Expand a policy against the project tree, resolving each entry to the paths it covers.
///
/// Read-only I/O: one directory read per entry that carries a wildcard, one `symlink_metadata` per
/// candidate, and one read of `.git/index` for the tracked-path guard. Nothing recursive — the
/// grammar guarantees every component above the last is a literal name, which is what keeps this
/// bounded on a repository with millions of files.
pub(crate) fn expand(project: &Path, policy: &FsPolicy) -> Expanded {
    let mut out = Expanded::default();
    if policy.is_empty() {
        return out;
    }
    let Ok(root) = project.canonicalize() else {
        out.warnings.push(format!(
            "cannot resolve the project directory {} — no `[fs]` mask is applied, so every path it \
             names stays open to the cage",
            project.display()
        ));
        return out;
    };

    out.denied = resolve_list(
        &root,
        &policy.deny,
        "deny",
        &mut out.warnings,
        &mut out.refused,
    );
    out.readonly = resolve_list(
        &root,
        &policy.readonly,
        "readonly",
        &mut out.warnings,
        &mut out.refused,
    );

    // A denied *directory* already covers everything under it: the cage sees an empty directory, so
    // nothing inside is nameable. Any other mask below one is therefore redundant — and worse than
    // redundant, since bubblewrap would be asked to mount over a path that no longer exists inside
    // the empty directory and would fail the launch outright ("Can't create file at …"). So the
    // covered entries are dropped, and `deny` wins over `readonly` wherever the two meet: one closes
    // the path and the other only protects it, which is a right answer rather than a mount order.
    //
    // One warning per config *entry*, not per path: a `deny = ["secrets/", "secrets/*.key"]` should
    // say one thing, not one thing per key.
    let denied_dirs: Vec<PathBuf> = out
        .denied
        .iter()
        .filter(|m| m.is_dir)
        .map(|m| m.path.clone())
        .collect();
    let denied_paths: BTreeSet<PathBuf> = out.denied.iter().map(|m| m.path.clone()).collect();
    let mut covered: Vec<(&str, String)> = Vec::new();
    out.denied.retain(|m| {
        let hit = denied_dirs
            .iter()
            .any(|d| *d != m.path && m.path.starts_with(d));
        if hit && !covered.contains(&("deny", m.pattern.clone())) {
            covered.push(("deny", m.pattern.clone()));
        }
        !hit
    });
    out.readonly.retain(|ro| {
        let hit = denied_paths
            .iter()
            .any(|d| ro.path == *d || ro.path.starts_with(d));
        if hit && !covered.contains(&("readonly", ro.pattern.clone())) {
            covered.push(("readonly", ro.pattern.clone()));
        }
        !hit
    });
    for (field, pattern) in covered {
        out.warnings.push(format!(
            "`[fs] {field}` entry `{pattern}` is already covered by a `[fs] deny` entry above it, \
             which closes the whole path — this one adds nothing and is dropped"
        ));
    }

    guard_hard_links(&out.denied, "deny", &mut out.warnings);
    guard_hard_links(&out.readonly, "readonly", &mut out.warnings);
    guard_git_tracked(&root, &out.denied, &mut out.warnings);

    let count = out.count();
    if count > MASK_MAX {
        out.refused = Some(format!(
            "`[fs]` asks for {count} masks and {MASK_MAX} is the ceiling — each one is a mount, and \
             a launch pays for them faster than one-for-one. Name a directory instead of its files: \
             one entry closes it, at constant cost, and it stays closed for anything created inside \
             it later"
        ));
    } else if count > MASK_WARN {
        out.warnings.push(format!(
            "`[fs]` masks {count} paths — past about {MASK_WARN} the launch slows down noticeably \
             (each mask is a mount). Naming a directory closes it in one entry, at constant cost"
        ));
    }
    out
}

/// Resolve one list of entries into the paths it covers, warning on each entry that yields none and
/// refusing the launch on one whose paths cannot be read at all.
fn resolve_list(
    root: &Path,
    entries: &[String],
    field: &str,
    warnings: &mut Vec<String>,
    refused: &mut Option<String>,
) -> Vec<Masked> {
    let mut out: Vec<Masked> = Vec::new();
    for entry in entries {
        let dir_only = entry.ends_with('/');
        let body = entry.trim_end_matches('/');
        let hits = match body.rsplit_once('/') {
            // A wildcard sits only in the last component (the grammar guarantees it), so at most
            // one directory is read, and only when there is a wildcard to match.
            Some((parent, last)) if has_wildcard(last) => match_in_dir(&root.join(parent), last),
            None if has_wildcard(body) => match_in_dir(root, body),
            _ => Ok(vec![root.join(body)]),
        };
        let mut hits = match hits {
            Ok(hits) => hits,
            Err(reason) => {
                refuse(field, entry, &reason, warnings, refused);
                continue;
            }
        };
        hits.sort();
        let mut matched = 0;
        for candidate in hits {
            match admit(root, &candidate, entry, dir_only) {
                Ok(Some(masked)) => {
                    matched += 1;
                    // A path already covered by an earlier entry needs no second mount.
                    if !out.iter().any(|m| m.path == masked.path) {
                        out.push(masked);
                    }
                }
                Ok(None) => {}
                Err(Unmasked::Entry(reason)) => warnings.push(format!(
                    "`[fs] {field}` entry `{entry}`: {reason} — that path stays open to the cage"
                )),
                Err(Unmasked::Unreadable(reason)) => {
                    refuse(field, entry, &reason, warnings, refused);
                    matched += 1; // said already, and not by "matches nothing"
                }
            }
        }
        if matched == 0 {
            warnings.push(format!(
                "`[fs] {field}` entry `{entry}` matches nothing in this project — nothing is closed \
                 by it"
            ));
        }
    }
    out
}

/// Record an entry the expansion could not evaluate: warn about it, and fail the launch closed on
/// the first one.
///
/// The launch refuses rather than warning alone because the two states are indistinguishable from
/// the config's side and only one of them is safe. An entry whose path cannot be stat'ed or whose
/// directory cannot be read produces no mask, and a launch that went on would run with exactly the
/// paths the policy names left open — which is what the mask ceiling and a failed decoy staging
/// already refuse to do.
fn refuse(
    field: &str,
    entry: &str,
    reason: &str,
    warnings: &mut Vec<String>,
    refused: &mut Option<String>,
) {
    let said = format!(
        "`[fs] {field}` entry `{entry}`: {reason} — what it closes cannot be established, and \
         launching would leave that path open to the cage"
    );
    warnings.push(said.clone());
    if refused.is_none() {
        *refused = Some(said);
    }
}

/// The entries of `dir` whose name matches `pattern`, or nothing when the directory is absent (an
/// entry naming a directory that is not there matches nothing, which its own warning covers).
///
/// A directory that is *there* and cannot be read is an error rather than an empty list, and the
/// difference is the whole point: the cage owns the project tree, so a `chmod 000` inside it would
/// otherwise turn `certs/*.pem` into an entry that quietly matches nothing and closes nothing.
fn match_in_dir(dir: &Path, pattern: &str) -> Result<Vec<PathBuf>, String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot read `{}` ({e})", dir.display())),
    };
    Ok(entries
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| matches_component(pattern, n))
        })
        .map(|e| e.path())
        .collect())
}

/// Why one candidate path yields no mask, and whether the launch may go on without it.
enum Unmasked {
    /// The entry is answered on its merits: the path resolves outside the project, it is the
    /// project root, or its shape is not what the entry asked for. Warned per entry, and the launch
    /// runs — nothing about it is uncertain.
    Entry(String),
    /// The path could not be read at all, so what the entry covers is unknown. The launch refuses
    /// ([`refuse`]).
    Unreadable(String),
}

/// Judge one candidate path: it must exist, resolve inside the project, and match the entry's
/// file/directory intent. `Ok(None)` is "not there", which the caller reports per entry rather than
/// per path.
///
/// **Absent is read from the errno, never from a boolean.** `Path::exists` is `metadata(..).is_ok()`,
/// which answers `false` for a path that is there but cannot be stat'ed — an `EACCES` on an ancestor
/// reads exactly like an `ENOENT`. The cage runs as this uid and the project is bound read-write, so
/// one `chmod 000` on a directory inside it made every entry naming a path below that directory
/// report "matches nothing in this project", which is a warning the launch runs past: the session
/// then started with the mask absent and the file readable. So only `NotFound` is absence; anything
/// else is [`Unmasked::Unreadable`] and fails the launch closed.
///
/// The containment check is on the **canonical** path, and it is the load-bearing one. `[fs]` is
/// honored from any source, including an untrusted project, on the grounds that it can only take
/// access away — a symlink pointing out of the tree would break exactly that, by turning a `deny`
/// entry into a mount over an arbitrary path in the cage (`/etc/passwd`, the CA bundle, the task
/// client). So a path that resolves outside the project is refused, loudly.
fn admit(
    root: &Path,
    candidate: &Path,
    entry: &str,
    dir_only: bool,
) -> Result<Option<Masked>, Unmasked> {
    match std::fs::symlink_metadata(candidate) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Unmasked::Unreadable(format!(
                "cannot stat `{}` ({e})",
                candidate.display()
            )));
        }
    }
    let canon = match candidate.canonicalize() {
        Ok(canon) => canon,
        // A symlink whose target is gone: the name is there, the file it points at is not, and
        // there is nothing to close.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Unmasked::Unreadable(format!(
                "cannot resolve `{}` ({e})",
                candidate.display()
            )));
        }
    };
    if !canon.starts_with(root) {
        return Err(Unmasked::Entry(format!(
            "`{}` resolves to `{}`, outside the project — `[fs]` closes paths of the project it is \
             declared in, and nothing else",
            candidate.display(),
            canon.display()
        )));
    }
    if canon == root {
        return Err(Unmasked::Entry(
            "names the project root itself, which would close the whole tree".to_string(),
        ));
    }
    let meta = std::fs::metadata(&canon)
        .map_err(|e| Unmasked::Unreadable(format!("cannot stat `{}` ({e})", canon.display())))?;
    let is_dir = meta.is_dir();
    if dir_only && !is_dir {
        return Err(Unmasked::Entry(format!(
            "`{}` is not a directory, but the entry ends in `/`",
            canon.display()
        )));
    }
    Ok(Some(Masked {
        path: canon,
        is_dir,
        pattern: entry.to_string(),
    }))
}

/// Warn about a masked file reachable under a second name.
///
/// A mount covers a **path**. A hard link is a second path to the same inode, so the content is
/// still readable through it — measured, not assumed. The cage cannot *make* one (a link across the
/// mask's mount boundary fails with `EXDEV`), so what this catches is a link that already existed
/// when the launch started, which is the only way the hole opens.
///
/// Both lists are walked, because both leak through an alias and they leak differently: a `deny`
/// alias is still *readable*, while a `readonly` alias is still *writable* — the re-bind refuses
/// writes on the path it covers, and the second name reaches the same inode around it. Running
/// this over `deny` alone left the more surprising of the two silent.
fn guard_hard_links(masked: &[Masked], field: &str, warnings: &mut Vec<String>) {
    for m in masked.iter().filter(|m| !m.is_dir) {
        let Ok(meta) = std::fs::metadata(&m.path) else {
            continue;
        };
        if meta.nlink() > 1 {
            let leak = if field == "readonly" {
                "the same file stays writable under every other name for it"
            } else {
                "the same content stays readable under every other name for it"
            };
            warnings.push(format!(
                "`[fs] {field}` covers `{}`, which has {} hard links — the mask covers this path, \
                 and {leak}",
                m.pattern,
                meta.nlink()
            ));
        }
    }
}

/// Warn when a masked path is tracked by git, and say what to do about it.
///
/// This is the one interaction that turns a mask into a broken workflow: git compares the worktree
/// against its index, a masked file reads as modified and unreadable, and `git commit` then fails
/// **wholesale** — the agent cannot commit anything at all. Nothing is corrupted (the content and
/// the history are intact), but the session is unusable until the mask goes away.
///
/// `git update-index --skip-worktree` is the cure, and it composes exactly: the mask still closes
/// the file, `git status` reads clean, and a commit of everything else succeeds. sbx never runs it
/// — it is a local flag on the user's own clone, and a launcher that silently reconfigured a
/// repository would be a worse surprise than the warning.
fn guard_git_tracked(root: &Path, denied: &[Masked], warnings: &mut Vec<String>) {
    if denied.is_empty() {
        return;
    }
    let Some(tracked) = git_tracked_paths(&root.join(".git")) else {
        return;
    };
    for m in denied {
        // The index holds paths relative to the repository root, with `/` separators and no
        // trailing slash on a directory (git tracks files, so a masked directory matches by prefix).
        let Ok(rel) = m.path.strip_prefix(root) else {
            continue;
        };
        let Some(rel) = rel.to_str() else { continue };
        let hit = if m.is_dir {
            let prefix = format!("{rel}/");
            tracked.iter().any(|t| t.starts_with(&prefix))
        } else {
            tracked.contains(rel)
        };
        if hit {
            warnings.push(format!(
                "`[fs] deny` covers `{}`, which git tracks — a masked tracked path makes every \
                 `git commit` in the cage fail, not just one touching it. Run \
                 `git update-index --skip-worktree {rel}` in this project and both work: the file \
                 stays closed and commits succeed",
                m.pattern
            ));
        }
    }
}

/// The paths git's index lists *and still compares against the worktree*, read directly from
/// `.git/index`.
///
/// Read rather than asked, deliberately: running `git` here would execute git's own configuration,
/// and this launcher is pointed at a project it treats as untrusted — `core.fsmonitor` alone turns
/// a status query into "run this program". Reading the index is the same answer with no execution.
///
/// Handles index versions 2 and 3, which is what git writes unless a repository opts into 4's
/// path compression. An unreadable, oversized, unknown or malformed index yields `None`, and the
/// guard simply does not fire — it is an aid, not a gate.
fn git_tracked_paths(git_dir: &Path) -> Option<BTreeSet<String>> {
    let index = git_dir.join("index");
    let meta = std::fs::metadata(&index).ok()?;
    if !meta.is_file() || meta.len() > INDEX_MAX {
        return None;
    }
    let data = std::fs::read(&index).ok()?;
    parse_git_index(&data)
}

/// The path list out of a git index blob. Split from the I/O so the format is testable from bytes.
///
/// A path flagged `skip-worktree` is deliberately **left out**. That flag is the cure this guard
/// recommends, and it works: with it set, git stops comparing the path against the worktree, so the
/// mask no longer breaks commits. Reporting the path anyway would leave the warning standing after
/// the user did exactly what it asked, which is the fastest way to teach someone to ignore it.
fn parse_git_index(data: &[u8]) -> Option<BTreeSet<String>> {
    if data.len() < 12 || &data[0..4] != b"DIRC" {
        return None;
    }
    let version = u32::from_be_bytes(data[4..8].try_into().ok()?);
    if !matches!(version, 2 | 3) {
        return None;
    }
    let count = u32::from_be_bytes(data[8..12].try_into().ok()?) as usize;
    let mut out = BTreeSet::new();
    let mut pos = 12;
    for _ in 0..count {
        let start: usize = pos;
        // 62 bytes of fixed metadata, the last two being the flags whose top bit says a second
        // pair follows (version 3's extended flags).
        let flags_at = start.checked_add(60)?;
        if flags_at + 2 > data.len() {
            return None;
        }
        let flags = u16::from_be_bytes(data[flags_at..flags_at + 2].try_into().ok()?);
        let mut name_at = start + 62;
        // Bit 0x4000 of the base flags says a second pair follows (version 3's extended flags);
        // bit 0x4000 *of those* is `skip-worktree`, which git sets on `update-index
        // --skip-worktree` and which switches the index to version 3 to carry it.
        let mut skip_worktree = false;
        if flags & 0x4000 != 0 {
            if name_at + 2 > data.len() {
                return None;
            }
            let extended = u16::from_be_bytes(data[name_at..name_at + 2].try_into().ok()?);
            skip_worktree = extended & 0x4000 != 0;
            name_at += 2;
        }
        if name_at > data.len() {
            return None;
        }
        // The 12-bit length in the flags saturates at 0xFFF, so the NUL is the authority either way.
        let end = name_at + data[name_at..].iter().position(|&b| b == 0)?;
        if !skip_worktree {
            out.insert(String::from_utf8_lossy(&data[name_at..end]).into_owned());
        }
        // Entries are padded with NULs to a multiple of 8 from the entry's own start, with at least
        // one NUL of terminator.
        let unpadded = end + 1 - start;
        pos = start + unpadded.div_ceil(8) * 8;
        if pos > data.len() {
            return None;
        }
    }
    Some(out)
}

/// The binds that realise this expansion in the agent's cage.
///
/// Emitted among the launcher-injected binds, which land **after** the structural mounts — the
/// project included. Order is the whole mechanism: a mask emitted before the project mount would be
/// covered by it, which is exactly why a `binds` entry aimed inside the project cannot mask
/// anything today.
pub(crate) fn agent_binds(expanded: &Expanded, decoys: &Decoys) -> Vec<ExtraBind> {
    let mut out = Vec::with_capacity(expanded.count());
    // `readonly` first, then `deny`. The two can legitimately nest the one way round that is left
    // after the expansion drops the other (`readonly = [".git/"]` with `deny = [".git/config"]`),
    // and the later mount is the one that wins — so the closed path has to be applied over the
    // merely-protected one, never under it.
    for m in &expanded.readonly {
        // Its own path, re-bound read-only over itself: the content is the real one, and the mount
        // is what refuses the write.
        out.push(ExtraBind {
            src: m.path.clone(),
            dest: m.path.clone(),
            writable: false,
        });
    }
    for m in &expanded.denied {
        out.push(ExtraBind {
            src: if m.is_dir {
                decoys.dir.clone()
            } else {
                decoys.file.clone()
            },
            dest: m.path.clone(),
            writable: false,
        });
    }
    out
}

/// The mounts that realise this expansion in a task's cage, minus what the task's `unmask` lifts.
///
/// Only `deny` is carried. A task cage binds the project **read-only** already, so every `readonly`
/// entry is redundant there — re-emitting it would cost a mount to restate what the cage's shape
/// says.
///
/// Returns the mounts and the entries of `unmask` that lifted nothing: an entry naming a path no
/// mask covers is a warning and no more, because it grants nothing — the path it names is either
/// already open or does not exist. Making it fatal would let an untrusted project's edit to the
/// `[fs] deny` list turn a working task declaration into a failed launch.
pub(crate) fn task_mounts(
    expanded: &Expanded,
    decoys: &Decoys,
    project: &Path,
    unmask: &[String],
) -> (Vec<Mount>, Vec<String>) {
    let lifted = lift_paths(expanded, project, unmask);
    let mounts = expanded
        .denied
        .iter()
        .filter(|m| !lifted.contains(&m.path))
        .map(|m| Mount::RoBind {
            src: if m.is_dir {
                decoys.dir.clone()
            } else {
                decoys.file.clone()
            },
            dest: m.path.clone(),
        })
        .collect();
    let unused = unmask
        .iter()
        .filter(|entry| !lifts_anything(expanded, project, entry))
        .map(|entry| {
            format!(
                "`unmask` entry `{entry}` names no `[fs] deny` path — it lifts nothing, and that \
                 path stays closed to this task"
            )
        })
        .collect();
    (mounts, unused)
}

/// The masked paths a task's `unmask` list lifts: the intersection of what the entries name with
/// what is actually masked. The intersection is the rule — `unmask` lifts a mask, it never exposes
/// anything the `[fs] deny` list did not already close, which is what keeps it from being a second
/// `binds` without that field's gate.
fn lift_paths(expanded: &Expanded, project: &Path, unmask: &[String]) -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    for entry in unmask {
        for m in &expanded.denied {
            if entry_names(project, entry, &m.path) {
                out.insert(m.path.clone());
            }
        }
    }
    out
}

/// Whether one `unmask` entry lifts at least one mask, for the "this entry did nothing" warning.
fn lifts_anything(expanded: &Expanded, project: &Path, entry: &str) -> bool {
    expanded
        .denied
        .iter()
        .any(|m| entry_names(project, entry, &m.path))
}

/// Whether an entry (in the `[fs]` grammar) names a given masked path.
///
/// Matching is on the path, not on the text of the `deny` entry that produced it, so a task can
/// lift one file out of a mask written as a wildcard: `deny = ["certs/*.pem"]` with
/// `unmask = ["certs/client.pem"]` opens that one certificate to that one task.
fn entry_names(project: &Path, entry: &str, path: &Path) -> bool {
    let body = entry.trim_end_matches('/');
    let Ok(rel) = path.strip_prefix(project) else {
        return false;
    };
    let Some(rel) = rel.to_str() else {
        return false;
    };
    let (pattern_parts, rel_parts): (Vec<&str>, Vec<&str>) =
        (body.split('/').collect(), rel.split('/').collect());
    if pattern_parts.len() != rel_parts.len() {
        return false;
    }
    pattern_parts
        .iter()
        .zip(rel_parts.iter())
        .all(|(p, r)| matches_component(p, r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    /// A project with a key, a certificate directory and an ordinary file.
    fn project(tmp: &TmpDir) -> PathBuf {
        let root = tmp.path().join("proj");
        std::fs::create_dir_all(root.join("certs")).unwrap();
        std::fs::create_dir_all(root.join("secrets")).unwrap();
        std::fs::write(root.join("prod.key"), b"SECRET").unwrap();
        std::fs::write(root.join("certs/server.pem"), b"CERT").unwrap();
        std::fs::write(root.join("certs/client.pem"), b"CERT2").unwrap();
        std::fs::write(root.join("secrets/token"), b"TOKEN").unwrap();
        std::fs::write(root.join("main.rs"), b"fn main() {}").unwrap();
        root
    }

    fn policy(deny: &[&str], readonly: &[&str]) -> FsPolicy {
        FsPolicy {
            deny: deny.iter().map(|s| s.to_string()).collect(),
            readonly: readonly.iter().map(|s| s.to_string()).collect(),
            ..FsPolicy::default()
        }
    }

    #[test]
    fn an_entry_resolves_to_the_paths_it_covers() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let e = expand(
            &root,
            &policy(&["prod.key", "certs/*.pem", "secrets/"], &[]),
        );
        let paths: Vec<&Path> = e.denied.iter().map(|m| m.path.as_path()).collect();
        assert_eq!(
            paths,
            [
                root.join("prod.key"),
                root.join("certs/client.pem"),
                root.join("certs/server.pem"),
                root.join("secrets"),
            ]
            .iter()
            .map(|p| p.as_path())
            .collect::<Vec<_>>(),
            "the wildcard covers one directory's matches, sorted"
        );
        assert!(
            e.denied
                .iter()
                .find(|m| m.path.ends_with("secrets"))
                .unwrap()
                .is_dir
        );
        assert!(e.refused.is_none());
        assert!(e.warnings.is_empty(), "{:?}", e.warnings);
    }

    #[test]
    fn an_entry_matching_nothing_warns_and_closes_nothing() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let e = expand(&root, &policy(&["absent.key", "certs/*.crt"], &[]));
        assert!(e.denied.is_empty());
        assert_eq!(e.warnings.len(), 2, "{:?}", e.warnings);
        assert!(e.warnings.iter().all(|w| w.contains("matches nothing")));
    }

    /// A masked path that is **there** and cannot be stat'ed must not read as a path that is not
    /// there. The cage runs as this uid and the project is bound read-write, so it can `chmod 000` a
    /// directory of its own and make every entry naming a path below it report "matches nothing" —
    /// a warning the launch runs past, after which the file it was told to close is open. The
    /// expansion refuses instead, the way it already refuses the mask ceiling.
    #[test]
    fn an_entry_whose_path_cannot_be_stated_refuses_the_launch() {
        // Root searches a directory whatever its mode, so the errno this test is about never
        // arrives there.
        if unsafe { libc::geteuid() } == 0 {
            skip_incapable!(
                "skipping the unstattable-mask test: running as root, which stats a path under a \
                 mode-000 directory instead of being refused by it"
            );
            return;
        }
        let tmp = TmpDir::new();
        let root = project(&tmp);
        std::fs::set_permissions(root.join("certs"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        let e = expand(&root, &policy(&["certs/server.pem"], &[]));
        // Put it back, so the fixture can be torn down whatever the assertions do.
        std::fs::set_permissions(root.join("certs"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        assert!(
            e.refused
                .as_ref()
                .is_some_and(|r| r.contains("certs/server.pem")),
            "a path that cannot be stat'ed fails the launch closed rather than expanding to \
             nothing: refused={:?} warnings={:?}",
            e.refused,
            e.warnings
        );
        assert!(
            !e.warnings.iter().any(|w| w.contains("matches nothing")),
            "and it is never reported as an entry that matches nothing: {:?}",
            e.warnings
        );
    }

    /// The wildcard half of the same rule: a directory a wildcard entry has to read, which cannot be
    /// read at all, is not an empty match list. The cause here is a symlink loop rather than a mode
    /// (root is refused by one and not the other), and the branch it exercises is the one every
    /// errno but `NotFound` takes.
    #[test]
    fn an_entry_whose_directory_cannot_be_read_refuses_the_launch() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let loop_dir = root.join("loop");
        std::os::unix::fs::symlink(&loop_dir, &loop_dir).unwrap();
        let e = expand(&root, &policy(&["loop/*.pem"], &[]));
        assert!(
            e.refused.as_ref().is_some_and(|r| r.contains("loop/*.pem")),
            "a directory that cannot be read fails the launch closed: refused={:?} warnings={:?}",
            e.refused,
            e.warnings
        );
        assert!(
            !e.warnings.iter().any(|w| w.contains("matches nothing")),
            "and it is never reported as an entry that matches nothing: {:?}",
            e.warnings
        );
    }

    /// An entry naming a path that genuinely is not there still warns and still lets the launch run:
    /// the refusal above is about a path whose state could not be established, not about one whose
    /// absence is established.
    #[test]
    fn an_absent_path_is_still_a_warning_rather_than_a_refusal() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        std::os::unix::fs::symlink(root.join("gone.key"), root.join("dangling.key")).unwrap();
        let e = expand(&root, &policy(&["absent.key", "dangling.key"], &[]));
        assert!(e.refused.is_none(), "{:?}", e.refused);
        assert_eq!(e.warnings.len(), 2, "{:?}", e.warnings);
        assert!(e.warnings.iter().all(|w| w.contains("matches nothing")));
    }

    #[test]
    fn a_path_resolving_outside_the_project_is_refused() {
        // The check that lets `[fs]` be honored from an untrusted source: a symlink out of the tree
        // must not turn a mask into a mount over an arbitrary path in the cage.
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let outside = tmp.path().join("outside.txt");
        std::fs::write(&outside, b"HOST").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link.key")).unwrap();
        let e = expand(&root, &policy(&["link.key"], &[]));
        assert!(
            e.denied.is_empty(),
            "nothing outside the project is mounted over"
        );
        assert!(
            e.warnings.iter().any(|w| w.contains("outside the project")),
            "{:?}",
            e.warnings
        );
    }

    #[test]
    fn deny_wins_over_readonly_where_they_meet() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let e = expand(&root, &policy(&["secrets/"], &["secrets/token", "main.rs"]));
        let ro: Vec<&Path> = e.readonly.iter().map(|m| m.path.as_path()).collect();
        assert_eq!(
            ro,
            vec![root.join("main.rs").as_path()],
            "the covered entry is dropped"
        );
        assert!(
            e.warnings
                .iter()
                .any(|w| w.contains("already covered by a `[fs] deny`")),
            "{:?}",
            e.warnings
        );
    }

    #[test]
    fn a_mask_under_a_denied_directory_is_dropped_rather_than_mounted() {
        // Not merely redundant: the directory is already an *empty* one inside the cage, so asking
        // bubblewrap to mount over a path within it fails the whole launch ("Can't create file
        // at …: Read-only file system"). A config that says the same thing twice must not do that.
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let e = expand(
            &root,
            &policy(&["secrets/", "secrets/token"], &["secrets/token"]),
        );
        assert_eq!(
            e.denied
                .iter()
                .map(|m| m.path.as_path())
                .collect::<Vec<_>>(),
            vec![root.join("secrets").as_path()],
            "only the directory is mounted"
        );
        assert!(e.readonly.is_empty());
        let covered: Vec<&String> = e
            .warnings
            .iter()
            .filter(|w| w.contains("already covered"))
            .collect();
        assert_eq!(
            covered.len(),
            2,
            "one per entry, deny and readonly: {covered:?}"
        );
    }

    #[test]
    fn a_deny_inside_a_readonly_directory_is_emitted_over_it() {
        // The one nesting the expansion leaves standing, and the ordering it depends on: protecting
        // `.git/` while closing `.git/config` is a real policy, and the closed path has to be
        // applied *after* the protected one or the later mount would restore what it closed.
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let decoys = stage_decoys(&tmp.path().join("mask-1")).unwrap();
        let e = expand(&root, &policy(&["secrets/token"], &["secrets/"]));
        assert_eq!(
            e.denied.len(),
            1,
            "the file mask survives a readonly parent"
        );
        assert_eq!(e.readonly.len(), 1);
        let binds = agent_binds(&e, &decoys);
        assert_eq!(binds[0].dest, root.join("secrets"), "readonly first");
        assert_eq!(
            binds[1].dest,
            root.join("secrets/token"),
            "then the mask over it"
        );
    }

    #[test]
    fn staging_replaces_a_previous_launchs_residue() {
        // `gc` keeps a directory whose pid reads live, and a recycled pid is live — so a crashed
        // predecessor's contents could otherwise be served as this launch's "empty" directory.
        let tmp = TmpDir::new();
        let dir = tmp.path().join("mask-1");
        let first = stage_decoys(&dir).unwrap();
        std::fs::write(first.dir.join("leftover"), b"x").unwrap();
        let second = stage_decoys(&dir).unwrap();
        assert!(
            std::fs::read_dir(&second.dir).unwrap().next().is_none(),
            "the decoy directory must be empty, whatever the last launch left in it"
        );
    }

    #[test]
    fn a_second_hard_link_to_a_masked_file_is_reported() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        std::fs::hard_link(root.join("prod.key"), root.join("copy.key")).unwrap();
        let e = expand(&root, &policy(&["prod.key"], &[]));
        assert_eq!(e.denied.len(), 1);
        assert!(
            e.warnings.iter().any(|w| w.contains("hard links")),
            "the mask covers a path, not an inode, and that has to be said: {:?}",
            e.warnings
        );
    }

    /// A `readonly` entry leaks through a second link too, and worse than a `deny` one: the
    /// re-bind refuses writes on the path it covers, so the alias is a *writable* way to the same
    /// inode. The guard used to walk `deny` only, which left that silent.
    #[test]
    fn a_second_hard_link_to_a_read_only_file_is_reported_as_writable() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        std::fs::hard_link(root.join("certs/server.pem"), root.join("certs/alias.pem")).unwrap();
        let e = expand(&root, &policy(&[], &["certs/server.pem", "main.rs"]));
        let hits: Vec<&String> = e
            .warnings
            .iter()
            .filter(|w| w.contains("hard links"))
            .collect();
        assert!(
            !hits.is_empty(),
            "a `readonly` mask reachable under a second name must warn: the re-bind covers the \
             path it names, and the alias writes the same inode: {:?}",
            e.warnings
        );
        assert_eq!(
            hits.len(),
            1,
            "only the aliased path warns — `main.rs` has one link and must not: {:?}",
            e.warnings
        );
        assert!(
            hits[0].contains("`[fs] readonly`") && hits[0].contains("writable"),
            "the warning must name the field that produced it and say the alias is writable, not \
             merely readable: {}",
            hits[0]
        );
    }

    #[test]
    fn the_mask_ceiling_refuses_rather_than_truncating() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let dir = root.join("many");
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..MASK_MAX + 5 {
            std::fs::write(dir.join(format!("f{i}.key")), b"x").unwrap();
        }
        let e = expand(&root, &policy(&["many/*.key"], &[]));
        assert!(
            e.refused.as_ref().is_some_and(|r| r.contains("ceiling")),
            "a policy past the ceiling fails closed rather than dropping the tail: {:?}",
            e.refused
        );
    }

    #[test]
    fn the_decoys_are_one_closed_file_and_one_empty_directory() {
        let tmp = TmpDir::new();
        let dir = tmp.path().join("mask-1");
        let d = stage_decoys(&dir).unwrap();
        let meta = std::fs::metadata(&d.file).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0,
            "the file refuses every read"
        );
        assert_eq!(meta.len(), 0);
        assert!(
            std::fs::read_dir(&d.dir).unwrap().next().is_none(),
            "the directory is empty"
        );
        // Staging twice at the same pid replaces the residue rather than failing.
        let again = stage_decoys(&dir).unwrap();
        assert_eq!(again.file, d.file);
    }

    #[test]
    fn the_agent_binds_point_each_mask_at_the_right_decoy() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let decoys = stage_decoys(&tmp.path().join("mask-1")).unwrap();
        let e = expand(&root, &policy(&["prod.key", "secrets/"], &["main.rs"]));
        let binds = agent_binds(&e, &decoys);
        assert_eq!(binds.len(), 3);
        // `readonly` is emitted first, so a `deny` nested inside one lands over it rather than
        // under it (see `a_deny_inside_a_readonly_directory_is_emitted_over_it`).
        assert_eq!(
            binds[0].src, binds[0].dest,
            "readonly re-binds the real path over itself"
        );
        assert_eq!(binds[0].dest, root.join("main.rs"));
        assert_eq!(binds[1].src, decoys.file, "a file gets the closed file");
        assert_eq!(binds[1].dest, root.join("prod.key"));
        assert_eq!(
            binds[2].src, decoys.dir,
            "a directory gets the empty directory"
        );
        assert!(binds.iter().all(|b| !b.writable));
    }

    #[test]
    fn a_task_sees_every_mask_it_did_not_unmask() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let decoys = stage_decoys(&tmp.path().join("mask-1")).unwrap();
        // `readonly` is not carried into a task cage: the project is bound read-only there already.
        let e = expand(&root, &policy(&["prod.key", "certs/*.pem"], &["main.rs"]));

        let (none, unused) = task_mounts(&e, &decoys, &root, &[]);
        assert_eq!(
            none.len(),
            3,
            "with no unmask, every denied path is closed there too"
        );
        assert!(unused.is_empty());

        // One file lifted out of a wildcard mask: the task reads that certificate and nothing else.
        let (some, unused) = task_mounts(&e, &decoys, &root, &["certs/client.pem".to_string()]);
        let dests: Vec<&Path> = some
            .iter()
            .map(|m| match m {
                Mount::RoBind { dest, .. } => dest.as_path(),
                _ => unreachable!("only ro-binds are emitted"),
            })
            .collect();
        assert!(!dests.contains(&root.join("certs/client.pem").as_path()));
        assert!(dests.contains(&root.join("certs/server.pem").as_path()));
        assert!(dests.contains(&root.join("prod.key").as_path()));
        assert!(unused.is_empty());
    }

    #[test]
    fn an_unmask_naming_no_mask_lifts_nothing_and_says_so() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let decoys = stage_decoys(&tmp.path().join("mask-1")).unwrap();
        let e = expand(&root, &policy(&["prod.key"], &[]));
        // `main.rs` is a real file that no mask covers: lifting it would be a bind, not an unmask.
        let (mounts, unused) = task_mounts(&e, &decoys, &root, &["main.rs".to_string()]);
        assert_eq!(mounts.len(), 1, "the real mask is untouched");
        assert_eq!(unused.len(), 1);
        assert!(unused[0].contains("lifts nothing"), "{unused:?}");
    }

    #[test]
    fn a_directory_unmask_lifts_the_directory() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let decoys = stage_decoys(&tmp.path().join("mask-1")).unwrap();
        let e = expand(&root, &policy(&["secrets/"], &[]));
        let (mounts, unused) = task_mounts(&e, &decoys, &root, &["secrets/".to_string()]);
        assert!(mounts.is_empty(), "the directory is open to this task");
        assert!(unused.is_empty());
        // Written without the trailing slash it means the same path.
        let (mounts, _) = task_mounts(&e, &decoys, &root, &["secrets".to_string()]);
        assert!(mounts.is_empty());
    }

    #[test]
    fn the_git_index_parse_reads_the_tracked_paths() {
        // A version-2 index with two entries, built to the format's own rules: 62 bytes of
        // metadata, a NUL-terminated name, NUL padding to a multiple of 8 from the entry's start.
        fn entry(name: &str) -> Vec<u8> {
            let mut e = vec![0u8; 60];
            e.extend_from_slice(&(name.len() as u16).to_be_bytes());
            e.extend_from_slice(name.as_bytes());
            e.push(0);
            while !e.len().is_multiple_of(8) {
                e.push(0);
            }
            e
        }
        let mut data = b"DIRC".to_vec();
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend(entry("prod.key"));
        data.extend(entry("sub/deep.txt"));
        let tracked = parse_git_index(&data).expect("a well-formed v2 index parses");
        assert!(tracked.contains("prod.key"));
        assert!(tracked.contains("sub/deep.txt"));

        // A version-3 entry carrying `skip-worktree` is left out: the flag is the cure this guard
        // recommends, so a path that has it must stop being reported.
        fn v3_entry(name: &str, extended: u16) -> Vec<u8> {
            let mut e = vec![0u8; 60];
            e.extend_from_slice(&(0x4000u16 | name.len() as u16).to_be_bytes());
            e.extend_from_slice(&extended.to_be_bytes());
            e.extend_from_slice(name.as_bytes());
            e.push(0);
            while !e.len().is_multiple_of(8) {
                e.push(0);
            }
            e
        }
        let mut v3 = b"DIRC".to_vec();
        v3.extend_from_slice(&3u32.to_be_bytes());
        v3.extend_from_slice(&2u32.to_be_bytes());
        v3.extend(v3_entry("skipped.key", 0x4000));
        v3.extend(v3_entry("watched.key", 0));
        let tracked = parse_git_index(&v3).expect("a well-formed v3 index parses");
        assert!(!tracked.contains("skipped.key"), "skip-worktree drops out");
        assert!(
            tracked.contains("watched.key"),
            "an ordinary v3 entry stays"
        );

        // What must yield `None` rather than a wrong answer: not an index, a version whose paths
        // are compressed, a truncated one.
        assert!(parse_git_index(b"not an index at all").is_none());
        let mut v4 = data.clone();
        v4[4..8].copy_from_slice(&4u32.to_be_bytes());
        assert!(parse_git_index(&v4).is_none(), "version 4 compresses paths");
        assert!(parse_git_index(&data[..20]).is_none(), "truncated");
    }

    #[test]
    fn a_git_tracked_mask_warns_with_the_command_that_fixes_it() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let git = root.join(".git");
        std::fs::create_dir_all(&git).unwrap();
        let mut data = b"DIRC".to_vec();
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend_from_slice(&1u32.to_be_bytes());
        let mut e = vec![0u8; 60];
        e.extend_from_slice(&8u16.to_be_bytes());
        e.extend_from_slice(b"prod.key");
        e.push(0);
        while !e.len().is_multiple_of(8) {
            e.push(0);
        }
        data.extend(e);
        std::fs::write(git.join("index"), &data).unwrap();

        let warned = expand(&root, &policy(&["prod.key"], &[])).warnings;
        assert!(
            warned
                .iter()
                .any(|w| w.contains("update-index --skip-worktree prod.key")),
            "the warning has to carry the cure, not just the problem: {warned:?}"
        );
        // An untracked mask in the same repository says nothing.
        let quiet = expand(&root, &policy(&["secrets/"], &[])).warnings;
        assert!(
            !quiet.iter().any(|w| w.contains("update-index")),
            "{quiet:?}"
        );
    }
}
