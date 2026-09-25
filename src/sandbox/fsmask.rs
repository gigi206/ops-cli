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
//! `[network] deny`. Four things it does not cover, each measured rather than assumed:
//! a second **hard link** to the same file elsewhere in the project reads the content (a mount
//! covers a *path*, not an inode); a file appearing **mid-session** outside a denied *directory* is
//! not covered (mounts are resolved once, at launch — a denied directory, by contrast, stays sealed
//! for the session); a file whose **name is not valid UTF-8** cannot be reached by a *wildcard*
//! entry at all, since the matcher compares text (naming the file or its directory literally closes
//! it, and the launch warns rather than passing over it in silence); and a path nobody listed is
//! simply open. What the cage cannot do is defeat a mask from inside: `umount2`, `mount`, `unshare`
//! and the rest of that family are refused by the mandatory seccomp filter, and it holds no
//! capability in its user namespace. Nor can it move one: every directory between the project root,
//! or the read-write bind a mask lies in, and the mask is held in place for the session
//! ([`holding_dirs`]), so the path a mask was placed on
//! still names the file it protects when the host's git reads it after the session and when the
//! next launch resolves `[fs]` again.
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
use crate::diag::visible;
use std::collections::BTreeSet;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// How many mounts `[fs]` may cost a launch before it says the cost is getting real.
///
/// Each mask is one bind, as is each directory held in place above one ([`holding_dirs`]), and
/// bubblewrap re-reads `/proc/self/mountinfo` per bind, so the launch
/// cost grows with the *square* of the count — measured at 32 ms for 100 masks and 384 ms for 500.
/// The cure is always the same and is in the message: name the directory instead of its files.
const MASK_WARN: usize = 64;

/// How many mounts `[fs]` may cost a launch at all. Past this the wait is seconds and an argv
/// ceiling bubblewrap shares with every other mount comes into view, so the launch refuses rather
/// than quietly dropping the tail: a truncated mask list reads exactly like a complete one.
const MASK_MAX: usize = 256;

/// The largest `.git/index` the tracked-file guard will read. An index is a few MiB on a large
/// repository; a file past this is not one the guard needs to be right about, and reading it would
/// be the only unbounded allocation in a launch.
const INDEX_MAX: u64 = 64 * 1024 * 1024;

/// One project path a mask covers, and the entry that named it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Masked {
    /// The absolute host path, canonical and verified to be inside the project, or for a file the
    /// host's git reads, where the cage writes ([`Reach`]).
    pub(crate) path: PathBuf,
    /// Whether it is a directory, which decides which decoy covers it.
    pub(crate) is_dir: bool,
    /// The `[fs]` entry that matched, for a message that points at what to edit.
    pub(crate) pattern: String,
    /// Whether sbx added the entry itself rather than a config declaring it, so a message does not
    /// send its reader to edit a line nobody wrote ([`BUILTIN_READONLY`]).
    pub(crate) builtin: bool,
}

/// The project paths a launch will close, expanded from a policy against the project on disk.
#[derive(Debug, Default, Clone)]
pub(crate) struct Expanded {
    /// Paths whose contents the cage may not read.
    pub(crate) denied: Vec<Masked>,
    /// Paths the cage may read but not write.
    pub(crate) readonly: Vec<Masked>,
    /// The directories between a mask and the directory the cage writes it through, shallow to
    /// deep, that the agent's cage holds in place so each mask keeps naming the file it protects.
    /// See [`holding_dirs`].
    pub(crate) pins: Vec<PathBuf>,
    /// What the expansion found worth saying: an entry that matched nothing, a file reachable by a
    /// second name, a path git tracks. Surfaced by the launch, never fatal on its own.
    pub(crate) warnings: Vec<String>,
    /// Set when the expansion cannot deliver what the policy asks for: the project root does not
    /// resolve, or the policy needs more mounts than [`MASK_MAX`]. The launch fails closed on it,
    /// because the alternative is a run whose paths are open while the config says they are shut.
    pub(crate) refused: Option<String>,
    /// Where the cage writes at a host path's own name, which each mask lies under.
    pub(crate) reach: Reach,
}

/// Where the cage writes host paths, canonical: at their own name in the project and in the
/// read-write config binds, and under other names in sbx's data directory.
///
/// A file the host's git reads that lies at its own name in the project or in a read-write bind is
/// one the cage could rewrite before that git reads it, so it is held; a link there is a name the
/// cage could point elsewhere. sbx's data directory holds the cage's home, its store and the
/// install pools, which the cage writes at `/home/sandbox`, `/nix` and the pool paths: a mask at
/// the host name would hold nothing there, so a file git reads in it refuses the launch. A path
/// under none of these directories is not the cage's to write.
///
/// A read-write bind that holds the global configuration the host's git reads is the exception:
/// the cage can name a program there that git runs in every repository, so holding git's other
/// files in that bind protects nothing, and nothing in it is held. The launch says so instead
/// ([`Reach::unheld`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Reach {
    /// The canonical project root.
    project: PathBuf,
    /// The config binds the cage finds at their own path, in the order they are mounted.
    binds: Vec<BindReach>,
    /// sbx's data directory, canonical, or `None` when it did not resolve.
    data: Option<PathBuf>,
}

/// One config bind as the reach sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BindReach {
    /// The canonical bind path.
    path: PathBuf,
    /// Whether the cage writes through it.
    writable: bool,
    /// The global git configuration file a read-write bind holds, which leaves nothing in it held.
    git_global: Option<PathBuf>,
}

impl Reach {
    /// The reach of a launch in the project at canonical `root`, with the config's canonical
    /// `binds` and sbx's data directory, against the global git configuration the environment
    /// names ([`git_global_configs`]).
    pub(crate) fn of(root: &Path, binds: &[crate::config::Bind], data: Option<&Path>) -> Self {
        Reach::with_git_global(root, binds, data, &git_global_configs())
    }

    /// [`Reach::of`] against the global git configuration files `git_global`, as the host names
    /// them.
    ///
    /// A bind a later mount covers is left out ([`super::binds::bind_reaches_the_cage`]): inside
    /// the project, the project's own mount is what the cage writes through. A read-write bind
    /// holds a global configuration file when it contains the file's name, which the cage can
    /// replace, or what a link there resolves to, which the cage can rewrite.
    fn with_git_global(
        root: &Path,
        binds: &[crate::config::Bind],
        data: Option<&Path>,
        git_global: &[PathBuf],
    ) -> Self {
        let named: Vec<(PathBuf, PathBuf)> = git_global
            .iter()
            .flat_map(|file| {
                let parent = file.parent().unwrap_or(Path::new("/"));
                let name = file.file_name().map(PathBuf::from).unwrap_or_default();
                [
                    crate::trust::canonicalize_existing_prefix(parent).join(name),
                    crate::trust::canonicalize_existing_prefix(file),
                ]
                .map(|at| (at, file.clone()))
            })
            .collect();
        // The file named is one that is there when any is, so the warning points at what to read.
        let held_in = |bind: &Path| {
            let held: Vec<&PathBuf> = named
                .iter()
                .filter(|(at, _)| at.starts_with(bind))
                .map(|(_, file)| file)
                .collect();
            held.iter()
                .find(|file| std::fs::symlink_metadata(file).is_ok())
                .or(held.first())
                .map(|file| (*file).clone())
        };
        Reach {
            project: root.to_path_buf(),
            binds: binds
                .iter()
                .filter(|b| super::binds::bind_reaches_the_cage(&b.path, Some(root)))
                .map(|b| BindReach {
                    path: b.path.clone(),
                    writable: b.writable,
                    git_global: b.writable.then(|| held_in(&b.path)).flatten(),
                })
                .collect(),
            data: data.map(crate::trust::canonicalize_existing_prefix),
        }
    }

    /// The canonical project root.
    fn project(&self) -> &Path {
        &self.project
    }

    /// Whether `path` lies at or under the project root.
    fn in_project(&self, path: &Path) -> bool {
        !self.project.as_os_str().is_empty() && path.starts_with(&self.project)
    }

    /// The bind the cage finds at `path`, when the project does not answer for it.
    ///
    /// The project's mount comes after the config binds, so it answers first. Among the binds, a
    /// later mount at a directory above a path covers an earlier one, and one below it lands
    /// inside it: the last bind that contains the path is the one the cage finds there.
    fn bind_at(&self, path: &Path) -> Option<&BindReach> {
        if self.in_project(path) {
            return None;
        }
        self.binds.iter().rev().find(|b| path.starts_with(&b.path))
    }

    /// The directory through which the cage writes `path` at its own name and sbx holds what git
    /// reads there, the project root or a read-write bind, or `None`.
    fn root_of(&self, path: &Path) -> Option<&Path> {
        if self.in_project(path) {
            return Some(self.project.as_path());
        }
        self.bind_at(path)
            .filter(|b| b.writable && b.git_global.is_none())
            .map(|b| b.path.as_path())
    }

    /// Whether the cage writes `path` at its own name and sbx holds the files git reads there.
    fn holds(&self, path: &Path) -> bool {
        self.root_of(path).is_some()
    }

    /// Whether the cage writes `path` at its own name, in the project or a read-write bind.
    pub(crate) fn writes(&self, path: &Path) -> bool {
        self.in_project(path) || self.bind_at(path).is_some_and(|b| b.writable)
    }

    /// The read-write binds that hold the global git configuration, each with the file it holds:
    /// the cage writes them, and nothing in them is held.
    fn unheld(&self) -> impl Iterator<Item = (&Path, &Path)> {
        self.binds
            .iter()
            .filter_map(|b| Some((b.path.as_path(), b.git_global.as_deref()?)))
    }

    /// Whether the cage writes `path` under another name: it lies in sbx's data directory, outside
    /// the project.
    fn written_elsewhere(&self, path: &Path) -> bool {
        !self.in_project(path) && self.data.as_ref().is_some_and(|d| path.starts_with(d))
    }
}

/// The files the host's git reads as its global configuration, as git finds them:
/// `$GIT_CONFIG_GLOBAL` alone when it is set, otherwise `$XDG_CONFIG_HOME/git/config` (with
/// `~/.config` in its place when that is unset) and `~/.gitconfig`. Absent ones are listed too,
/// since the cage could create one.
fn git_global_configs() -> Vec<PathBuf> {
    let var = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    if let Some(file) = var("GIT_CONFIG_GLOBAL") {
        return vec![file];
    }
    let home = var("HOME");
    let xdg = var("XDG_CONFIG_HOME").or_else(|| home.as_ref().map(|h| h.join(".config")));
    xdg.map(|x| x.join("git/config"))
        .into_iter()
        .chain(home.map(|h| h.join(".gitconfig")))
        .collect()
}

/// What an expansion does to one project path: the two answers a bind produces, and the entry
/// that produces it.
///
/// It exists so that "this path is closed" has **one** definition. The launch never asks the
/// question — it emits the binds and the kernel answers it — so a caller that needs the answer
/// without launching (`sbx test fs`) would otherwise restate the containment rule in its own
/// words, and a restatement drifts from the mounts in silence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Cover<'a> {
    /// The contents are unreachable: a decoy is bound at this path, or at a directory above it.
    Denied(&'a Masked),
    /// The contents are the real ones and a write is refused: the path, or a directory above it,
    /// is re-bound over itself read-only.
    ReadOnly(&'a Masked),
}

impl Expanded {
    /// Whether anything will be mounted, so a launch with an empty policy stages nothing.
    pub(crate) fn is_empty(&self) -> bool {
        self.denied.is_empty() && self.readonly.is_empty()
    }

    /// What this expansion does to `path`, which is expected to be canonical and inside the
    /// project. `None` is "no mask names it": open to the cage as far as `[fs]` is concerned.
    ///
    /// Two rules, both of them properties of the mounts rather than choices made here:
    ///
    /// - **A directory carries its subtree.** A bind at a directory covers every path below it, so
    ///   a path under a denied directory is denied even when nothing on disk bears its name yet —
    ///   which is the one shape that stays closed for a whole session.
    /// - **`deny` is checked first.** `agent_binds` emits `readonly` and then `deny`, and the later
    ///   mount is the one that wins, so where a denied file sits inside a read-only directory the
    ///   answer is the decoy. The opposite nesting cannot occur: [`expand`] drops a `readonly`
    ///   entry that a `deny` already covers.
    pub(crate) fn covering(&self, path: &Path) -> Option<Cover<'_>> {
        fn under<'m>(masks: &'m [Masked], path: &Path) -> Option<&'m Masked> {
            masks
                .iter()
                .find(|m| m.path == path || (m.is_dir && path.starts_with(&m.path)))
        }
        under(&self.denied, path)
            .map(Cover::Denied)
            .or_else(|| under(&self.readonly, path).map(Cover::ReadOnly))
    }

    /// How many binds this expansion costs: its masks and the directories that hold them in place.
    fn count(&self) -> usize {
        self.denied.len() + self.readonly.len() + self.pins.len()
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
///
/// `binds` are the config's canonical binds and `data` sbx's data directory: with the project,
/// they are where the cage writes ([`Reach`]), which decides which of the files the host's git
/// reads are held.
pub(crate) fn expand(
    project: &Path,
    policy: &FsPolicy,
    binds: &[crate::config::Bind],
    data: Option<&Path>,
) -> Expanded {
    let mut out = Expanded::default();
    if policy.is_empty()
        && builtin_readonly_names(project, policy.git_writable()).is_empty()
        && !git_protected(project, policy.git_writable())
        && !git_linked(project, policy.git_writable())
    {
        return out;
    }
    let Ok(root) = project.canonicalize() else {
        // Refused, not warned. Everything below resolves against this root, so without it the
        // expansion yields nothing and the launch would run with **no** mask at all — the answer a
        // policy that names none produces, which is the opposite of what this one says. A warning
        // left that difference for a reader to notice in passing; `resolve_list` already refuses an
        // entry whose parent it cannot read, and this is the same failure one level up.
        out.refused = Some(format!(
            "cannot resolve the project directory {} — the `[fs]` masks it names cannot be placed, \
             and a run without them leaves open exactly the paths the policy closes",
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
    // The built-in entries join after the declared ones, and only where nothing declared already
    // covers them: a path a `deny` closes needs no protection, and one a declared `readonly` names
    // needs no second mount.
    let builtin = resolve_list(
        &root,
        &builtin_readonly_names(&root, policy.git_writable()),
        BUILTIN_READONLY,
        &mut out.warnings,
        &mut out.refused,
    );
    // Every question below is asked of the host's git, and a `.git` or a `.git/config` reached
    // through a link, or a `.git/commondir`, would have it answer from elsewhere: refused first,
    // and nothing is asked.
    let reach = Reach::of(&root, binds, data);
    let main = GitRepo::main(&root);
    let protected = git_protected(&root, policy.git_writable());
    // A read-write bind holding the global git configuration leaves the carrier open whatever is
    // held, and nothing in it is held: said rather than refused, since the bind is a trusted grant.
    if protected || git_file_protected(&root, policy.git_writable()) {
        for (bind, file) in reach.unheld() {
            out.warnings.push(format!(
                "the read-write bind `{}` holds `{}`, the global configuration your git reads in \
                 every repository: the cage can name a program there that your git runs in this \
                 project too, so sbx holds none of git's files inside that bind. Bind a narrower \
                 directory, or this one read-only, to keep them held",
                bind.display(),
                file.display()
            ));
        }
    }
    let layout = git_dir_link_refusal(&root, policy.git_writable())
        .or_else(|| git_file_target_refusal(&reach, policy.git_writable()))
        .or_else(|| protected.then(|| git_repo_refusal(&reach, &main)).flatten());
    let mut carrier: Vec<Masked> = Vec::new();
    let mut submodules = 0;
    match layout {
        Some(reason) => {
            out.refused.get_or_insert(reason);
        }
        None if !protected => {}
        None => {
            carrier.extend(git_hook_dirs(
                &reach,
                &main,
                &mut out.warnings,
                &mut out.refused,
            ));
            carrier.extend(git_include_files(&reach, &main, &mut out.refused));
            carrier.extend(git_worktree_files(&reach, &main, &mut out.refused));
            submodules = submodule_carrier(
                &reach,
                &main,
                0,
                &mut carrier,
                &mut out.warnings,
                &mut out.refused,
            );
        }
    }
    for mut m in builtin.into_iter().chain(carrier) {
        m.builtin = true;
        let covered = out
            .denied
            .iter()
            .chain(&out.readonly)
            .any(|c| c.path == m.path || (c.is_dir && m.path.starts_with(&c.path)));
        if !covered {
            out.readonly.push(m);
        }
    }

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
    out.reach = reach;
    out.pins = holding_dirs(&out);

    guard_hard_links(&out.denied, "deny", &mut out.warnings);
    guard_hard_links(&out.readonly, "readonly", &mut out.warnings);
    guard_git_tracked(&root, &out.denied, &mut out.warnings);

    let count = out.count();
    // A submodule's files are git's: sbx lays them itself, and naming a directory does not apply.
    let among = if submodules > 0 {
        format!(
            " The git files of {submodules} submodule repositories, which sbx protects by itself, \
             are among them."
        )
    } else {
        String::new()
    };
    if count > MASK_MAX {
        let advice = if submodules > 0 {
            format!(
                " An `[fs]` entry costs less naming a directory than its files. {GIT_WRITABLE_HINT}"
            )
        } else {
            " Name a directory instead of its files: one entry closes it, at constant cost, and it \
             stays closed for anything created inside it later"
                .to_string()
        };
        out.refused = Some(format!(
            "`[fs]` needs {count} mounts, its masks and the directories that hold them in place, \
             and {MASK_MAX} is the ceiling: a launch pays for mounts faster than one-for-one.\
             {among}{advice}"
        ));
    } else if count > MASK_WARN {
        out.warnings.push(format!(
            "`[fs]` needs {count} mounts, its masks and the directories that hold them in place: \
             past about {MASK_WARN} the launch slows down noticeably.{among} Naming a directory \
             closes an `[fs]` entry in one mount, at constant cost"
        ));
    }
    out
}

/// The directories the agent's cage holds in place so that each mask keeps naming the file it
/// protects: every directory strictly between a masked path and the directory the cage writes it
/// through, the project root or a read-write bind ([`Reach`]), shallow to deep.
///
/// A mask is a mount point, which the cage can neither rename nor remove; the directories above it
/// are ordinary ones in a writable tree. The path a mask was placed on names the protected file
/// only while none of them can be renamed, and that path is what the host's git reads after the
/// session and what the next launch resolves `[fs]` against. So each of them is bound over itself
/// read-write: its contents stay writable, and it becomes a mount point too. The project root or
/// the bind needs no pin, being a mount of its own.
///
/// None is laid at or under a read-only directory mask. Nothing inside a read-only mount can be
/// renamed already, and a read-write bind there would reopen that directory to writes.
///
/// What holding a directory costs the cage: renaming or removing it is refused (`EBUSY`), and a
/// `rename` across its boundary is refused (`EXDEV`), which `mv` answers by copying. The one git
/// command this reaches is `submodule absorbgitdirs`, which moves a submodule's repository into a
/// held `.git` and is refused with nothing changed.
fn holding_dirs(expanded: &Expanded) -> Vec<PathBuf> {
    let read_only_dirs: Vec<&Path> = expanded
        .readonly
        .iter()
        .filter(|m| m.is_dir)
        .map(|m| m.path.as_path())
        .collect();
    let mut pins: BTreeSet<PathBuf> = BTreeSet::new();
    for m in expanded.denied.iter().chain(&expanded.readonly) {
        let Some(root) = expanded.reach.root_of(&m.path) else {
            continue;
        };
        for dir in m
            .path
            .ancestors()
            .skip(1)
            .take_while(|d| *d != root && d.starts_with(root))
        {
            if !read_only_dirs.iter().any(|ro| dir.starts_with(ro)) {
                pins.insert(dir.to_path_buf());
            }
        }
    }
    // Ordered component by component, so a directory comes before everything below it: a pin laid
    // after a deeper one would cover it.
    pins.into_iter().collect()
}

/// How a built-in entry is named in a message, in place of the `[fs]` field a declared one comes
/// from: nobody wrote it, so a warning must not send its reader looking for it in their config.
/// See [`builtin_readonly_names`].
const BUILTIN_READONLY: &str = "readonly (built-in)";

/// The project files every cage gets read-only without anyone listing them.
///
/// **The project config.** The `.sbx.toml` and each of the mise files the trust gate hashes beside
/// it, those present at launch. These are the files that govern the cage, and the tree they sit in
/// is writable from inside it. A write to one re-arms the trust gate, and the re-approval that
/// follows is where an addition the user never made gets granted by reflex; refusing the write
/// takes that step away from the agent. Only a file present at launch can be protected — a mount
/// needs something to land on — so a file the cage creates is answered by the review `sbx trust`
/// shows, not here. The mise files are protected only beside a `.sbx.toml`: without one sbx does
/// not honor them, and there is nothing for a write to them to re-arm.
///
/// **The git carrier.** `.git/hooks/` and `.git/config`, when the project's `.git` is a directory.
/// A hook, or a key of the config that names a program (`core.hooksPath`, `core.fsmonitor`,
/// `core.pager`, a filter, an alias), runs on the host at the user's next git command, outside any
/// cage. The directory is named, so a hook created mid-session is refused too. What it costs is
/// what writes the config: `remote add`, `config user.*`, and the upstream `push -u` records
/// (the push itself succeeds); and, `.git` being held in place above them ([`holding_dirs`]),
/// `submodule absorbgitdirs`, which moves a repository into it. The files git reads as
/// configuration beside `.git/config` are added by [`git_worktree_files`], and a `.git/commondir`
/// refuses the launch ([`git_commondir_refusal`]). A symbolic link inside the project on the way
/// to any of these paths, `.git` itself included, refuses the launch too ([`git_dir_link_refusal`],
/// [`git_link_on_the_way`]): a mask holds what a path resolved to at launch, and a link is a name
/// the cage could point elsewhere. `git_writable` lifts all of it: the one opening in `[fs]`, and
/// why it is honored only from a trusted layer. A `.git` that is a file (a linked worktree, a
/// submodule) is read-only itself ([`git_file_protected`]): it names the repository git reads,
/// outside the project where the cage does not reach, and one that names a repository inside the
/// project refuses the launch ([`git_file_target_refusal`]). The repositories of the submodules
/// the index names get the same carrier as the project's own ([`submodule_carrier`]).
///
/// Returned as `[fs]` entries relative to the project, for [`resolve_list`], which is what refuses
/// one that cannot be looked at: an absent file is left out here, every other answer goes through.
fn builtin_readonly_names(root: &Path, git_writable: bool) -> Vec<String> {
    let present = |name: &str| {
        !matches!(
            std::fs::symlink_metadata(root.join(name)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound
        )
    };
    let mut out: Vec<String> = Vec::new();
    if present(crate::config::PROJECT_CONFIG) {
        out.extend(
            std::iter::once(crate::config::PROJECT_CONFIG)
                .chain(crate::trust::MISE_CONFIG_NAMES.iter().copied())
                .filter(|name| present(name))
                .map(str::to_string),
        );
    }
    // A link there is refused rather than followed ([`git_dir_link_refusal`]).
    let linked = |name: &str| {
        std::fs::symlink_metadata(root.join(name)).is_ok_and(|m| m.file_type().is_symlink())
    };
    if git_protected(root, git_writable) && present(".git/config") && !linked(".git/config") {
        out.push(".git/config".to_string());
    }
    if git_file_protected(root, git_writable) {
        out.push(".git".to_string());
    }
    out
}

/// Whether this launch protects the git carrier: the project's `.git` is a directory, and no
/// trusted layer set `git_writable`.
fn git_protected(root: &Path, git_writable: bool) -> bool {
    !git_writable && std::fs::symlink_metadata(root.join(".git")).is_ok_and(|m| m.is_dir())
}

/// A repository whose files the host's git reads: its git directory, and the top of the work tree
/// a relative `core.hooksPath` resolves against.
struct GitRepo {
    dir: PathBuf,
    work_tree: PathBuf,
}

impl GitRepo {
    /// The project's own repository: `<root>/.git`, with the project as its work tree.
    fn main(root: &Path) -> Self {
        GitRepo {
            dir: root.join(".git"),
            work_tree: root.to_path_buf(),
        }
    }

    /// `name` inside the git directory, as the project spells it, for a pattern or a message.
    fn shown(&self, root: &Path, name: &str) -> String {
        let path = self.dir.join(name);
        path.strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string()
    }
}

/// Whether the project's `.git` is a file while no trusted layer set `git_writable`: the pointer a
/// linked worktree or a submodule keeps to its repository, which is read-only in the cage.
fn git_file_protected(root: &Path, git_writable: bool) -> bool {
    !git_writable && std::fs::symlink_metadata(root.join(".git")).is_ok_and(|m| m.is_file())
}

/// The refusal the repository a `.git` file names earns, or `None` when it lies outside the project
/// and sbx's data directory, or the file is not one git reads as a pointer.
///
/// git reads `gitdir: <path>` there, relative to the project root when it is not absolute, and uses
/// the directory it names as the repository: its configuration and its hooks. A linked worktree's
/// or a submodule's lies outside the project, where the cage does not reach, and the file itself is
/// read-only in the cage ([`git_file_protected`]). One inside the project would be a repository
/// whose configuration and hooks nothing protects, since the carrier is looked for in a `.git`
/// directory, so it refuses the launch, and so does a link inside the project on the way to it
/// ([`git_link_on_the_way`]). One in sbx's data directory refuses the launch too, since the cage
/// writes there under other names ([`Reach::written_elsewhere`]).
fn git_file_target_refusal(reach: &Reach, git_writable: bool) -> Option<String> {
    let root = reach.project();
    if !git_file_protected(root, git_writable) {
        return None;
    }
    let file = root.join(".git");
    let target = match gitfile_target(&file) {
        Ok(target) => target?,
        Err(e) => return Some(visible(&git_unreadable("read", &file, &e))),
    };
    let what = "the repository your git reads";
    if let Some(reason) = git_link_on_the_way(reach, &target, what, GIT_LINK_INSTEAD) {
        return Some(reason);
    }
    let canon = crate::trust::canonicalize_existing_prefix(&target);
    if reach.written_elsewhere(&canon) {
        return Some(git_data_refusal(what, &canon));
    }
    canon.starts_with(root).then(|| {
        visible(&format!(
            "`{}` names a repository inside the project (`{}`): sbx protects the files git reads \
             in a `.git` directory, and a repository elsewhere in the tree would be left open to \
             the cage. Move the repository into `.git` in place of the file, then launch again. \
             {GIT_WRITABLE_HINT}",
            file.display(),
            canon.display()
        ))
    })
}

/// How deep submodules of submodules are followed; one nested deeper refuses the launch.
const SUBMODULE_DEPTH: usize = 8;

/// The repositories of `repo`'s submodules that the host's git reads, and theirs below them, each
/// with the carrier its own repository has, as read-only masks added to `masks`; the number of
/// repositories found is returned.
///
/// The host's git reads a submodule's configuration whenever a gitlink of the index has a
/// repository in its directory, whether or not `.gitmodules` names it: a `git status` in the
/// superproject reads it, and a submodule's own submodules the same way. So the submodules are
/// found in the index ([`gitlinks`]), and for each the `.git` in its directory decides: a file is
/// held read-only and the repository it names is protected when the cage writes it ([`Reach`]) and
/// refuses the launch when it lies in sbx's data directory, a directory is the repository, a link
/// refuses the launch, and none means there is no repository for git to read yet. Each repository
/// found gets what the project's own does: its `config`, its hooks, the files it includes and the
/// files beside its configuration, and a link or a `commondir` in it refuses the launch
/// ([`git_repo_refusal`]).
///
/// An index this cannot read refuses the launch when the repository shows submodules (a
/// `.gitmodules`, or a `modules` directory in its git directory), since their repositories could not
/// be found; otherwise there is nothing to look for.
fn submodule_carrier(
    reach: &Reach,
    repo: &GitRepo,
    depth: usize,
    masks: &mut Vec<Masked>,
    warnings: &mut Vec<String>,
    refused: &mut Option<String>,
) -> usize {
    let links = match gitlinks(repo) {
        Ok(links) => links,
        Err(reason) => {
            let shows =
                repo.work_tree.join(".gitmodules").exists() || repo.dir.join("modules").exists();
            if shows {
                refused.get_or_insert_with(|| visible(&reason));
            }
            return 0;
        }
    };
    let mut found = 0;
    for dir in links {
        let dot_git = dir.join(".git");
        let what = "a submodule's repository";
        if let Some(reason) = git_link_on_the_way(reach, &dot_git, what, GIT_LINK_INSTEAD) {
            refused.get_or_insert(reason);
            continue;
        }
        let git_dir = match std::fs::symlink_metadata(&dot_git) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                refused.get_or_insert_with(|| visible(&git_unreadable("look at", &dot_git, &e)));
                continue;
            }
            Ok(meta) if meta.is_dir() => dot_git,
            Ok(meta) if meta.is_file() => {
                git_file(reach, &dot_git, None, refused, masks);
                let target = match gitfile_target(&dot_git) {
                    Ok(Some(target)) => target,
                    Ok(None) => continue,
                    Err(e) => {
                        refused
                            .get_or_insert_with(|| visible(&git_unreadable("read", &dot_git, &e)));
                        continue;
                    }
                };
                if let Some(reason) = git_link_on_the_way(reach, &target, what, GIT_LINK_INSTEAD) {
                    refused.get_or_insert(reason);
                    continue;
                }
                let canon = crate::trust::canonicalize_existing_prefix(&target);
                if reach.written_elsewhere(&canon) {
                    refused.get_or_insert_with(|| git_data_refusal(what, &canon));
                    continue;
                }
                // Where the cage does not write, it does not reach it; the file naming it is held.
                if !reach.holds(&canon) {
                    continue;
                }
                if !canon.is_dir() {
                    refused.get_or_insert_with(|| {
                        visible(&format!(
                            "`{}` names a submodule's repository at `{}`, which does not exist: the \
                             cage could create it and your git would read it. Check the file, \
                             then launch again. {GIT_WRITABLE_HINT}",
                            dot_git.display(),
                            canon.display()
                        ))
                    });
                    continue;
                }
                canon
            }
            Ok(_) => continue,
        };
        let sub = GitRepo {
            dir: git_dir,
            work_tree: dir,
        };
        if let Some(reason) = git_repo_refusal(reach, &sub) {
            refused.get_or_insert(reason);
            continue;
        }
        found += 1;
        git_file(reach, &sub.dir.join("config"), None, refused, masks);
        masks.extend(git_hook_dirs(reach, &sub, warnings, refused));
        masks.extend(git_include_files(reach, &sub, refused));
        masks.extend(git_worktree_files(reach, &sub, refused));
        if depth + 1 == SUBMODULE_DEPTH {
            refused.get_or_insert_with(|| {
                visible(&format!(
                    "`{}` is a submodule nested {SUBMODULE_DEPTH} deep, deeper than sbx follows \
                     submodules to protect their repositories. {GIT_WRITABLE_HINT}",
                    sub.work_tree.display()
                ))
            });
            continue;
        }
        found += submodule_carrier(reach, &sub, depth + 1, masks, warnings, refused);
        if found > MASK_MAX {
            break;
        }
    }
    found
}

/// The repository a `.git` file names, or `None` when git would not read the file as a pointer.
///
/// The file is read the way git reads it: everything after `gitdir: `, less the line ends that close
/// it, is the path, relative to the file's directory when it is not absolute. The read stops past
/// the longest path the kernel resolves, since a file longer than that names a path git cannot
/// open.
fn gitfile_target(file: &Path) -> io::Result<Option<PathBuf>> {
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    /// Past the kernel's `PATH_MAX`, with room for the `gitdir: ` prefix.
    const GITFILE_MAX: u64 = 8192;
    let mut head = Vec::new();
    std::fs::File::open(file)?
        .take(GITFILE_MAX)
        .read_to_end(&mut head)?;
    if head.len() as u64 == GITFILE_MAX {
        return Ok(None);
    }
    let Some(mut named) = head.strip_prefix(b"gitdir: ") else {
        return Ok(None);
    };
    while let Some(rest) = named
        .strip_suffix(b"\n")
        .or_else(|| named.strip_suffix(b"\r"))
    {
        named = rest;
    }
    let base = file.parent().unwrap_or(Path::new("/"));
    Ok(Some(base.join(std::ffi::OsStr::from_bytes(named))))
}

/// Whether the project's `.git` is a symbolic link while no trusted layer set `git_writable`, which
/// refuses the launch ([`git_dir_link_refusal`]).
fn git_linked(root: &Path, git_writable: bool) -> bool {
    !git_writable
        && std::fs::symlink_metadata(root.join(".git")).is_ok_and(|m| m.file_type().is_symlink())
}

/// The refusal a `.git` that is a symbolic link earns, or `None`.
///
/// The launch holds `.git` in place and lays its masks on the paths inside it, which protects what
/// git reads there only while those paths are the ones git reads. A `.git` that is a link is a name
/// the cage could point elsewhere during the session ([`git_link_on_the_way`]), and it would leave
/// nothing protected at all, since the carrier is looked for in a directory. It is checked before
/// any question is asked of the host's git, which would read through it.
fn git_dir_link_refusal(root: &Path, git_writable: bool) -> Option<String> {
    git_linked(root, git_writable).then(|| {
        git_link_refusal(
            &root.join(".git"),
            "the repository your git reads",
            "Replace it with the directory it names",
        )
    })
}

/// The refusal a repository's own layout earns, or `None`: a `config` that is a symbolic link, the
/// same name the cage could point elsewhere as a `.git` link ([`git_link_on_the_way`]), or a
/// `commondir` ([`git_commondir_refusal`]). Both are checked before any question is asked of the
/// host's git, which would read through them.
fn git_repo_refusal(reach: &Reach, repo: &GitRepo) -> Option<String> {
    git_link_on_the_way(
        reach,
        &repo.dir.join("config"),
        "the configuration your git reads",
        "Replace it with the file it names, or keep that file in the project and include it from a \
         `.git/config` of its own (`git config include.path <file>`), which sbx protects in place",
    )
    .or_else(|| git_commondir_refusal(reach, repo))
}

/// The directories git runs hooks from, as read-only masks: `.git/hooks`, and the directory
/// `core.hooksPath` names when the cage writes it ([`Reach`]).
///
/// **Absent ones included.** A mount needs something to land on, and the cage can create a
/// directory it does not find: a repository initialised without the template's `hooks/`, or a
/// `core.hooksPath` whose directory does not exist yet, would otherwise take a hook written from
/// inside the cage and run it at the user's next commit. So an absent directory is masked here all
/// the same, and the launch creates it, empty, before binding it ([`create_absent_dirs`]) —
/// which is what `git init` makes. `sbx test fs` and the in-cage contract read this same list, so
/// they describe the directory the launch will protect, not the absence it found.
///
/// **`core.hooksPath` is asked of the host's own git** (`git --git-dir <git dir> config --get`),
/// because the value that matters is the one the host's git will act on, include files and the
/// global config among what decides it. husky points it at `.husky/_`, inside the working tree and
/// ignored by git: a hook rewritten there does not even show in `git status`. With no git on the
/// host, no hook can run on it, and there is nothing to ask. A value the cage does not write is
/// left alone, and one in sbx's data directory, which the cage writes under other names, refuses
/// the launch.
///
/// **A link on the way refuses the launch**, whether it is `.git/hooks` itself or a directory above
/// the one `core.hooksPath` names, and wherever it leads ([`git_link_on_the_way`]). The refusal
/// names the form sbx holds in place: `core.hooksPath` pointed at the directory itself.
fn git_hook_dirs(
    reach: &Reach,
    repo: &GitRepo,
    warnings: &mut Vec<String>,
    refused: &mut Option<String>,
) -> Vec<Masked> {
    let mut dirs = vec![(
        repo.dir.join("hooks"),
        format!("{}/", repo.shown(reach.project(), "hooks")),
        "Replace it with the directory it names, or remove it and point `core.hooksPath` at that \
         directory (`git config core.hooksPath <dir>`), which sbx protects in place",
    )];
    if let Some(named) = git_hooks_path(repo) {
        let shown = format!("core.hooksPath = {}", named.display());
        dirs.push((
            named,
            shown,
            "Point `core.hooksPath` at the directory by a path with no link in it",
        ));
    }
    let mut out: Vec<Masked> = Vec::new();
    for (path, pattern, instead) in dirs {
        let what = format!("the directory your git runs hooks from ({pattern})");
        if let Some(reason) = git_link_on_the_way(reach, &path, &what, instead) {
            refused.get_or_insert(reason);
            continue;
        }
        let canon = match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                crate::trust::canonicalize_existing_prefix(&path)
            }
            Err(e) => {
                refused.get_or_insert_with(|| {
                    visible(&format!(
                        "{pattern}: {}",
                        git_unreadable("look at", &path, &e)
                    ))
                });
                continue;
            }
            Ok(_) => match path.canonicalize() {
                Ok(c) if c.is_dir() => c,
                // A file where hooks are looked for runs none; nothing to protect.
                Ok(_) => continue,
                Err(e) => {
                    refused.get_or_insert_with(|| {
                        visible(&format!(
                            "{pattern}: {}",
                            git_unreadable("resolve", &path, &e)
                        ))
                    });
                    continue;
                }
            },
        };
        if reach.written_elsewhere(&canon) {
            refused.get_or_insert_with(|| git_data_refusal(&what, &canon));
            continue;
        }
        let Some(root) = reach.root_of(&canon) else {
            continue;
        };
        if canon == root {
            let whole = if root == reach.project() {
                "the project root itself: its hooks cannot be protected without making the whole \
                 project read-only"
                    .to_string()
            } else {
                format!(
                    "the read-write bind `{}` itself: its hooks cannot be protected without \
                     making the whole bind read-only",
                    root.display()
                )
            };
            warnings.push(format!(
                "`{pattern}` names {whole}, so they stay writable to the cage"
            ));
            continue;
        }
        if !out.iter().any(|m| m.path == canon) {
            out.push(Masked {
                path: canon,
                is_dir: true,
                pattern,
                builtin: true,
            });
        }
    }
    out
}

/// Ask the host's own git a `config` question about `repo`, returning its standard output, or
/// `None` when there is no trusted git on the host, when git does not read the repository's git
/// directory as one, or when nothing matches (git's exit status 1).
///
/// `--git-dir` rather than `-C`, so a `.git` git does not recognise is not answered by a repository
/// discovered above it. The answer is the one the host's git acts on — the global and system files
/// and every include count — which is the point of asking git rather than reading the file. And
/// `git config` reads configuration and runs nothing it names: no hook, no fsmonitor, no pager.
fn host_git_config(repo: &GitRepo, args: &[&str]) -> Option<Vec<u8>> {
    let git = crate::store::resolve_git()?;
    let out = std::process::Command::new(git)
        .arg("--git-dir")
        .arg(&repo.dir)
        .arg("config")
        .args(args)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

/// A path as git reads one in its configuration: `~/` against the home, a relative one against
/// `base`, or `None` when it is relative and there is no base to read it against.
fn git_config_path(value: &str, base: Option<&Path>) -> Option<PathBuf> {
    let path = match value.strip_prefix("~/") {
        Some(rest) => PathBuf::from(std::env::var_os("HOME")?).join(rest),
        None => PathBuf::from(value),
    };
    if path.is_absolute() {
        Some(path)
    } else {
        base.map(|b| b.join(path))
    }
}

/// The host git's `core.hooksPath` for `repo`, resolved the way git resolves it for a working tree
/// (a relative value against the top of the tree), or `None` when it is unset or cannot be asked
/// ([`host_git_config`]).
fn git_hooks_path(repo: &GitRepo) -> Option<PathBuf> {
    let out = host_git_config(repo, &["--get", "core.hooksPath"])?;
    let value = String::from_utf8(out).ok()?;
    let value = value.trim_end_matches('\n');
    if value.is_empty() {
        return None;
    }
    git_config_path(value, Some(&repo.work_tree))
}

/// The files the cage writes ([`Reach`]) that an `include.path` or `includeIf.<condition>.path`
/// makes part of the configuration the host's git reads, as read-only masks.
///
/// `.git/config` being read-only is worth nothing if a file it includes is writable: git reads the
/// included file as configuration, `core.hooksPath` and `core.fsmonitor` included. So every include
/// the host's git reports is followed, from whichever file declares it (the global config among
/// them, and an included file's own includes, each listed with its origin), and one that lands
/// where the cage writes is protected. A conditional include is protected whether or not its
/// condition holds today: the condition is a property of where the repository is, which the cage
/// does not decide but a later move could change.
///
/// An include naming a file where the cage writes that does not exist refuses the launch rather
/// than being created: the cage could create it and git would read it, and a configuration file is
/// not sbx's to write into the user's tree the way an empty hooks directory is. The refusal names
/// the file and the way out. An include reached through a symbolic link where the cage writes
/// refuses the launch as well, wherever the link leads ([`git_link_on_the_way`]), and so does an
/// include in sbx's data directory, present or not, which the cage writes under other names.
fn git_include_files(reach: &Reach, repo: &GitRepo, refused: &mut Option<String>) -> Vec<Masked> {
    let Some(out) = host_git_config(
        repo,
        &[
            "-z",
            "--show-origin",
            "--get-regexp",
            r"^include(if\..*)?\.path$",
        ],
    ) else {
        return Vec::new();
    };
    // `-z` records: `file:<origin>` NUL `<key>` LF `<value>` NUL.
    let text = String::from_utf8_lossy(&out);
    let mut fields = text.split('\0');
    let mut masks: Vec<Masked> = Vec::new();
    while let (Some(origin), Some(entry)) = (fields.next(), fields.next()) {
        let Some((key, value)) = entry.split_once('\n') else {
            continue;
        };
        let base = origin
            .strip_prefix("file:")
            .and_then(|f| Path::new(f).parent().map(Path::to_path_buf));
        let Some(path) = git_config_path(value, base.as_deref()) else {
            continue;
        };
        let pattern = format!("{key} = {value}");
        let what = format!("{GIT_CONFIG_READ} ({pattern})");
        if let Some(reason) = git_link_on_the_way(
            reach,
            &path,
            &what,
            "Name the file by a path with no link in it",
        ) {
            refused.get_or_insert(reason);
            continue;
        }
        let canon = match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let canon = crate::trust::canonicalize_existing_prefix(&path);
                if reach.written_elsewhere(&canon) {
                    refused.get_or_insert_with(|| git_data_refusal(&what, &canon));
                } else if reach.holds(&canon) {
                    refused.get_or_insert_with(|| {
                        visible(&format!(
                            "git includes `{}` as configuration ({pattern}), and it does not \
                             exist: the cage could create it and your git would read it. Create \
                             it (empty is enough) or remove the include, then launch again. \
                             {GIT_WRITABLE_HINT}",
                            canon.display()
                        ))
                    });
                }
                continue;
            }
            Err(e) => {
                refused.get_or_insert_with(|| {
                    visible(&format!(
                        "{pattern}: {}",
                        git_unreadable("look at", &path, &e)
                    ))
                });
                continue;
            }
            Ok(_) => match path.canonicalize() {
                Ok(c) => c,
                Err(e) => {
                    refused.get_or_insert_with(|| {
                        visible(&format!(
                            "{pattern}: {}",
                            git_unreadable("resolve", &path, &e)
                        ))
                    });
                    continue;
                }
            },
        };
        if reach.written_elsewhere(&canon) {
            refused.get_or_insert_with(|| git_data_refusal(&what, &canon));
            continue;
        }
        // A directory is not a configuration file git can read; where the cage does not write,
        // there is nothing to hold.
        if !reach.holds(&canon) || canon.is_dir() {
            continue;
        }
        if !masks.iter().any(|m| m.path == canon) {
            masks.push(Masked {
                path: canon,
                is_dir: false,
                pattern,
                builtin: true,
            });
        }
    }
    masks
}

/// The refusal a `commondir` in `repo`'s own git directory earns, or `None` when there is none.
///
/// git writes `commondir` only in a linked worktree's directory under `.git/worktrees/`, never in a
/// main repository's `.git`. Where one is present, the configuration the host's git reads comes
/// from the directory it names rather than from `.git/config`, so the protection of `.git/config`
/// would protect a file git no longer reads, and every question [`host_git_config`] asks would be
/// answered from there too. It is therefore checked before any of them and refuses the launch,
/// whatever its shape: a file the launch cannot look at is refused the same way.
///
/// An absent one cannot be protected: no mount can hold a path that does not exist, and nothing can
/// stand in its place, since git refuses to run on an empty file or a directory there. The cage can
/// therefore create one during a session: the end of that session names it ([`GitWatch`]), and the
/// next launch refuses on it.
fn git_commondir_refusal(reach: &Reach, repo: &GitRepo) -> Option<String> {
    let path = repo.dir.join("commondir");
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => Some(format!(
            "`{}`: {}",
            repo.shown(reach.project(), "commondir"),
            visible(&git_unreadable("look at", &path, &e))
        )),
        Ok(_) => Some(format!(
            "`{}` is present: git writes this file only for a linked worktree, and in the \
             project's own `.git` it makes your git read its configuration from the directory it \
             names instead of `.git/config`, which sbx protects. Check what it names and remove \
             it, then launch again. {GIT_WRITABLE_HINT}",
            path.display()
        )),
    }
}

/// The files beside `.git/config` that the host's git also reads as configuration, as read-only
/// masks: `.git/config.worktree`, and for each linked worktree under `.git/worktrees/`, its own
/// `config.worktree` and the `commondir` that names the repository its configuration comes from.
///
/// A `config.worktree` is configuration when the repository's own `.git/config` turns
/// `extensions.worktreeConfig` on, which is where git honors that setting and nowhere else (not
/// from the global config, not from an included file); `.git/config` is read-only in the cage, so
/// the cage cannot turn it on. With it on, an absent `config.worktree` refuses the launch, naming
/// the file, for the reason an absent included file does. With it off, a present one is protected
/// all the same, at no cost, and an absent one is not read.
///
/// **Links refuse the launch.** git never makes these as links, and a link is a name the cage can
/// point elsewhere during the session while the mask holds the file it pointed to at launch. The
/// same goes for `.git/worktrees` and for a worktree's own directory.
///
/// A worktree's name is chosen by whoever created it, the cage included, so the entries are built
/// here rather than passed through [`resolve_list`] as patterns, and the listing stops past
/// [`MASK_MAX`]: more worktrees than masks can hold refuses the launch rather than reading on. What
/// holding these costs is `git worktree remove` and `prune` of a worktree that existed at launch,
/// which cannot delete its directory from the cage.
fn git_worktree_files(reach: &Reach, repo: &GitRepo, refused: &mut Option<String>) -> Vec<Masked> {
    let extension = host_git_config(
        repo,
        &[
            "--local",
            "--type=bool",
            "--get",
            "extensions.worktreeConfig",
        ],
    )
    .is_some_and(|out| out.trim_ascii() == b"true");
    let mut out: Vec<Masked> = Vec::new();
    let git = &repo.dir;
    let config = repo.shown(reach.project(), "config");
    let required = extension.then_some(config.as_str());
    git_file(
        reach,
        &git.join("config.worktree"),
        required,
        refused,
        &mut out,
    );

    let worktrees = git.join("worktrees");
    let listing = match std::fs::symlink_metadata(&worktrees) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return out,
        Err(e) => {
            refused.get_or_insert_with(|| visible(&git_unreadable("look at", &worktrees, &e)));
            return out;
        }
        Ok(meta) if meta.file_type().is_symlink() => {
            refused.get_or_insert_with(|| {
                git_link_refusal(&worktrees, GIT_CONFIG_READ, GIT_LINK_INSTEAD)
            });
            return out;
        }
        Ok(meta) if !meta.is_dir() => return out,
        Ok(_) => worktree_entries(&worktrees),
    };
    let dirs = match listing {
        Ok((dirs, false)) => dirs,
        Ok((_, true)) => {
            refused.get_or_insert_with(|| {
            visible(&format!(
                "`{}` holds more than {MASK_MAX} entries, more linked worktrees than a launch can \
                 protect: remove the ones you no longer use (`git worktree prune`), then launch \
                 again. {GIT_WRITABLE_HINT}",
                    worktrees.display()
                ))
            });
            return out;
        }
        Err(e) => {
            refused.get_or_insert_with(|| visible(&git_unreadable("list", &worktrees, &e)));
            return out;
        }
    };
    for dir in dirs {
        match std::fs::symlink_metadata(&dir) {
            Ok(meta) if meta.file_type().is_symlink() => {
                refused.get_or_insert_with(|| {
                    git_link_refusal(&dir, GIT_CONFIG_READ, GIT_LINK_INSTEAD)
                });
            }
            Ok(meta) if meta.is_dir() => {
                git_file(
                    reach,
                    &dir.join("config.worktree"),
                    required,
                    refused,
                    &mut out,
                );
                git_file(reach, &dir.join("commondir"), None, refused, &mut out);
            }
            // Not a worktree: git reads nothing from a file here.
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                refused.get_or_insert_with(|| visible(&git_unreadable("look at", &dir, &e)));
            }
        }
    }
    out
}

/// The entries of a `.git/worktrees` directory, sorted, and whether it holds more than
/// [`MASK_MAX`]: at most that many and one are read, since the cage can fill the directory and
/// neither the launch nor the end of a session reads it to the end.
fn worktree_entries(worktrees: &Path) -> io::Result<(Vec<PathBuf>, bool)> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(worktrees)?.take(MASK_MAX + 1) {
        dirs.push(entry?.path());
    }
    let more = dirs.len() > MASK_MAX;
    dirs.truncate(MASK_MAX);
    dirs.sort();
    Ok((dirs, more))
}

/// What the end of a session looks for in the project's git, where no mount reaches: a file git
/// reads as configuration that was not there at launch.
///
/// Three can appear. A `.git/commondir` has the host's git read its configuration from the
/// directory it names ([`git_commondir_refusal`]), a `config.worktree` is read as configuration
/// while `extensions.worktreeConfig` is on ([`git_worktree_files`]), and a repository in a
/// gitlink's directory is a submodule whose configuration a `git status` in the superproject reads
/// ([`submodule_carrier`]); the cage writes the index, so it can add the gitlink as well as the
/// repository. A mount can only hold a path that exists, and a placeholder would stop git, so the
/// launch notes which of these exist, and once the cage has exited the supervisor names each that
/// appeared, and a link where the launch refuses one, for the user to check before their own git
/// reads them. It reads names and file types, the indexes ([`gitlinks`]) and the `.git` files that
/// point at a submodule's repository, each within a bound, never following a link to open what it
/// names; an index it could read at launch and cannot read after the session is named too, rather
/// than passed over. Every name it prints is escaped.
///
/// It needs sbx alive when the cage exits, which is why a launch with a watch supervises the cage
/// rather than replacing itself with it. A supervisor killed along with its terminal says nothing,
/// and a detached session says it in its log; the next launch, which refuses a `.git/commondir`
/// and protects every `config.worktree` present, covers both.
pub(crate) struct GitWatch {
    root: PathBuf,
    reach: Reach,
    configs: BTreeSet<PathBuf>,
    submodules: GitlinkScan,
}

impl GitWatch {
    /// The watch for a launch in `project`, or `None` when the launch does not protect the git
    /// carrier, where there is nothing for it to look at. `binds` and `data` are what [`expand`]
    /// is given, so the watch follows a submodule's repository where the launch held one.
    pub(crate) fn start(
        project: &Path,
        git_writable: bool,
        binds: &[crate::config::Bind],
        data: Option<&Path>,
    ) -> Option<Self> {
        let root = project.canonicalize().ok()?;
        if !git_protected(&root, git_writable) {
            return None;
        }
        let reach = Reach::of(&root, binds, data);
        let configs = WorktreeScan::of(&root).configs;
        let submodules = GitlinkScan::of(&reach);
        Some(GitWatch {
            root,
            reach,
            configs,
            submodules,
        })
    }

    /// What appeared during the session, one message per finding, escaped for the terminal.
    pub(crate) fn findings(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let commondir = self.root.join(".git/commondir");
        if std::fs::symlink_metadata(&commondir).is_ok() {
            out.push(format!(
                "`{}` appeared during the session: git writes this file only for a linked \
                 worktree, and in the project's own `.git` it makes your git read its \
                 configuration from the directory it names instead of `.git/config`. Check what it \
                 names and remove it before running git here; the next launch refuses until it is \
                 gone",
                commondir.display()
            ));
        }
        let now = WorktreeScan::of(&self.root);
        for path in now.configs.difference(&self.configs) {
            out.push(format!(
                "`{}` appeared during the session: git reads it as configuration for its worktree \
                 while `extensions.worktreeConfig` is on in `.git/config`. Check it before running \
                 git in that worktree",
                path.display()
            ));
        }
        for link in &now.links {
            out.push(format!(
                "`{}` is a symbolic link after the session: git would read a worktree's \
                 configuration through it. Check where it points before running git in a worktree; \
                 the next launch refuses until it is replaced",
                link.display()
            ));
        }
        if now.more {
            out.push(format!(
                "`{}` holds more than {MASK_MAX} entries after the session, more than sbx reads: \
                 check what was created there before running git in a worktree",
                self.root.join(".git/worktrees").display()
            ));
        }
        let now = GitlinkScan::of(&self.reach);
        for dot_git in now.repos.difference(&self.submodules.repos) {
            out.push(format!(
                "`{}` is a submodule's repository that sbx did not protect at launch: a `git \
                 status` in the superproject reads its configuration. Check it, or remove it, \
                 before running git here",
                dot_git.display()
            ));
        }
        for index in now
            .unread
            .iter()
            .filter(|index| !self.submodules.unread.contains(index))
        {
            out.push(format!(
                "`{}` cannot be read in full after the session (split, larger than sbx reads, or of \
                 another format), so a submodule's repository added during it cannot be named. \
                 Check the gitlinks from a cage (`sbx run -- git ls-files --stage`) before running \
                 git here",
                index.display()
            ));
        }
        if now.more && !self.submodules.more {
            out.push(format!(
                "`{}` names more submodules after the session than sbx follows: check them from a \
                 cage (`sbx run -- git submodule status --recursive`) before running git here",
                self.root.join(".git/index").display()
            ));
        }
        out.iter().map(|m| visible(m)).collect()
    }
}

/// The `config.worktree` files of a repository, main and linked, found by file type without
/// following a link, with the links met where [`git_worktree_files`] refuses one, and whether
/// `.git/worktrees` held more entries than were read.
struct WorktreeScan {
    configs: BTreeSet<PathBuf>,
    links: Vec<PathBuf>,
    more: bool,
}

impl WorktreeScan {
    fn of(root: &Path) -> Self {
        let git = root.join(".git");
        let mut scan = WorktreeScan {
            configs: BTreeSet::new(),
            links: Vec::new(),
            more: false,
        };
        let present = |path: &Path| std::fs::symlink_metadata(path).is_ok();
        let main = git.join("config.worktree");
        if present(&main) {
            scan.configs.insert(main);
        }
        let worktrees = git.join("worktrees");
        match std::fs::symlink_metadata(&worktrees) {
            Ok(meta) if meta.file_type().is_symlink() => scan.links.push(worktrees),
            Ok(meta) if meta.is_dir() => {
                let (dirs, more) = worktree_entries(&worktrees).unwrap_or_default();
                scan.more = more;
                for dir in dirs {
                    match std::fs::symlink_metadata(&dir) {
                        Ok(meta) if meta.file_type().is_symlink() => scan.links.push(dir),
                        Ok(meta) if meta.is_dir() => {
                            let config = dir.join("config.worktree");
                            if present(&config) {
                                scan.configs.insert(config);
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        scan
    }
}

/// The `.git` in each gitlink's directory that holds one, from the project's index and, below it,
/// from the index of each submodule's repository the cage writes, with the indexes that could not
/// be read in full and whether the walk stopped at its bound.
///
/// Found by file type, as [`submodule_carrier`] finds them, and followed through a `.git` file only
/// to a repository the cage writes ([`Reach`]), the one kind it can have added a gitlink to.
#[derive(Default)]
struct GitlinkScan {
    repos: BTreeSet<PathBuf>,
    unread: Vec<PathBuf>,
    more: bool,
}

impl GitlinkScan {
    fn of(reach: &Reach) -> Self {
        let mut scan = GitlinkScan::default();
        scan.walk(reach, &GitRepo::main(reach.project()), 0);
        scan
    }

    fn walk(&mut self, reach: &Reach, repo: &GitRepo, depth: usize) {
        let Ok(links) = gitlinks(repo) else {
            self.unread.push(repo.dir.join("index"));
            return;
        };
        for dir in links {
            if depth >= SUBMODULE_DEPTH || self.repos.len() >= MASK_MAX {
                self.more = true;
                return;
            }
            let dot_git = dir.join(".git");
            let Ok(meta) = std::fs::symlink_metadata(&dot_git) else {
                continue;
            };
            self.repos.insert(dot_git.clone());
            let git_dir = if meta.is_dir() {
                dot_git
            } else if meta.is_file()
                && let Ok(Some(target)) = gitfile_target(&dot_git)
            {
                let canon = crate::trust::canonicalize_existing_prefix(&target);
                if !reach.holds(&canon) || !canon.is_dir() {
                    continue;
                }
                canon
            } else {
                continue;
            };
            let sub = GitRepo {
                dir: git_dir,
                work_tree: dir,
            };
            self.walk(reach, &sub, depth + 1);
        }
    }
}

/// Protect one of the files the host's git reads, adding it to `out` when it is there. `required`
/// names the configuration that turns `extensions.worktreeConfig` on when git reads the file as
/// configuration, which makes an absent one a refusal: the cage could create it and git would read
/// it.
fn git_file(
    reach: &Reach,
    path: &Path,
    required: Option<&str>,
    refused: &mut Option<String>,
    out: &mut Vec<Masked>,
) {
    let root = reach.root_of(path).unwrap_or(reach.project());
    let rel = visible(
        &path
            .strip_prefix(reach.project())
            .unwrap_or(path)
            .display()
            .to_string(),
    );
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(config) = required {
                refused.get_or_insert_with(|| {
                    visible(&format!(
                        "git reads `{}` as configuration (`extensions.worktreeConfig` is on in \
                         `{config}`), and it does not exist: the cage could create it and your \
                         git would read it. Create it (empty is enough), then launch again. \
                         {GIT_WRITABLE_HINT}",
                        path.display()
                    ))
                });
            }
        }
        Err(e) => {
            refused.get_or_insert_with(|| visible(&git_unreadable("look at", path, &e)));
        }
        Ok(meta) if meta.file_type().is_symlink() => {
            refused
                .get_or_insert_with(|| git_link_refusal(path, GIT_CONFIG_READ, GIT_LINK_INSTEAD));
        }
        Ok(_) => match admit(root, path, &rel, false) {
            Ok(Some(mut masked)) => {
                masked.builtin = true;
                out.push(masked);
            }
            Ok(None) => {}
            Err(NotMasked::Warn(reason) | NotMasked::Refuse(reason)) => {
                refused.get_or_insert_with(|| format!("`{rel}`: {}", visible(&reason)));
            }
        },
    }
}

/// The refusal a symbolic link where the cage writes, on the way to what the host's git reads,
/// earns, or `None` when resolving `path` meets none.
///
/// A mask holds what a path resolved to at launch. A link is a name, and one where the cage writes
/// ([`Reach`]) is a name the cage could point elsewhere during the session, after which the host's
/// git would read what the link names instead of what the mask holds. So each link the resolution
/// meets is looked at, in the order the kernel meets them ([`crate::trust::resolution_stop`]): one
/// the cage does not write is followed, and a link it writes that the resolution leads through
/// still counts. `what` says what git reads there, and `instead` the form sbx holds in
/// place.
fn git_link_on_the_way(reach: &Reach, path: &Path, what: &str, instead: &str) -> Option<String> {
    use crate::trust::ResolutionStop;
    match crate::trust::resolution_stop(path, |at, link| link && reach.holds(at))? {
        ResolutionStop::At(link) => Some(git_link_refusal(&link, what, instead)),
        ResolutionStop::TooManyLinks(link) => Some(visible(&format!(
            "`{}`: resolving the path to {what} meets more symbolic links than the kernel follows \
             in one resolution. Name it by a path with fewer links, then launch again. \
             {GIT_WRITABLE_HINT}",
            link.display()
        ))),
    }
}

/// The refusal a symbolic link on the way to what the host's git reads earns, with the path escaped
/// for the terminal: the project's names are whoever created them's to spell, the cage included.
/// `what` names what git reads through it, and `instead` the form sbx holds in place.
fn git_link_refusal(link: &Path, what: &str, instead: &str) -> String {
    visible(&format!(
        "`{}` is a symbolic link on the way to {what}, and the cage could point it elsewhere \
         during the session: your git would then read what it names rather than what sbx \
         protects. {instead}, then launch again. {GIT_WRITABLE_HINT}",
        link.display()
    ))
}

/// The refusal a path the host's git reads earns when it lies in sbx's data directory
/// ([`Reach::written_elsewhere`]), with the path escaped for the terminal. `what` names what git
/// reads there.
fn git_data_refusal(what: &str, path: &Path) -> String {
    visible(&format!(
        "{what} is `{}`, in sbx's data directory: the cage writes there under other names (its \
         home, its store, the install pools), where no mask at this name holds it, and your git \
         would read what the cage put there. Point git at a path outside it, then launch again. \
         {GIT_WRITABLE_HINT}",
        path.display()
    ))
}

/// What [`git_link_refusal`] tells a link among the files git reads as configuration to become.
const GIT_LINK_INSTEAD: &str = "Replace it with what it names";

/// What git reads through the files [`git_worktree_files`] protects, for [`git_link_refusal`].
const GIT_CONFIG_READ: &str = "a file your git reads as configuration";

/// Create, empty, each built-in directory mask whose directory is absent, so its bind has
/// something to land on. See [`git_hook_dirs`] for why an absent one is masked at all.
///
/// One component at a time below `root`, each checked with `symlink_metadata` and made with a
/// non-recursive `mkdir`: `create_dir_all` would follow a link the cage planted in an intermediate
/// component and make the directory wherever it points. A component that exists and is not a
/// directory is an error, and the launch refuses on it, since the mask it was for cannot be placed.
pub(crate) fn create_absent_dirs(expanded: &Expanded) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    for m in expanded.readonly.iter().filter(|m| m.builtin && m.is_dir) {
        let Some(root) = expanded.reach.root_of(&m.path) else {
            continue;
        };
        let Ok(rel) = m.path.strip_prefix(root) else {
            continue;
        };
        let mut at = root.to_path_buf();
        for part in rel.components() {
            at.push(part);
            match std::fs::symlink_metadata(&at) {
                Ok(meta) if meta.is_dir() => continue,
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("{} is not a directory", at.display()),
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            match std::fs::DirBuilder::new().mode(0o755).create(&at) {
                Ok(()) => {}
                // Made by someone else in between: acceptable only if it is a directory.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    if !std::fs::symlink_metadata(&at).is_ok_and(|m| m.is_dir()) {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

/// The refusal a path that cannot be looked at earns, whichever call could not look at it.
///
/// One sentence in one place, because it is one decision taken at three sites: `NotFound` is "not
/// there" and every other error is "cannot be looked at", and the second refuses the launch. The
/// cage runs as the user's own uid and holds the project tree writable, so it can `chmod 000` a
/// directory and have the next launch read its own masked path as absent — the entry matches
/// nothing, the launch says so as a warning about a seemingly stale config entry, no mount is
/// laid, and the session after that puts the mode back and reads the file. That is the mask
/// switched off by the thing it exists to close.
fn unreadable_refusal(verb: &str, path: &Path, e: &std::io::Error) -> String {
    format!(
        "cannot {verb} `{}` ({e}) — an entry that cannot be resolved is refused rather than \
         reported as matching nothing, because an unreadable path and one hidden to defeat the \
         mask are the same answer from here",
        path.display()
    )
}

/// The way out every refusal about git's files ends with: `git_writable`, the one opening in
/// `[fs]`, with the command that records it and the approval a project's own copy needs.
const GIT_WRITABLE_HINT: &str = "Or, to let the cage write git's files in this project, run `sbx \
    config set fs.git_writable true` here and approve it with `sbx trust` (`--global` sets it for \
    every project)";

/// [`unreadable_refusal`] for one of the files the host's git reads, ending with the way out
/// [`GIT_WRITABLE_HINT`] names.
fn git_unreadable(verb: &str, path: &Path, e: &std::io::Error) -> String {
    format!("{}. {GIT_WRITABLE_HINT}", unreadable_refusal(verb, path, e))
}

/// Why a candidate yielded no mask. The two are not interchangeable: one is a line the author can
/// read and delete, the other stops the launch.
enum NotMasked {
    /// Reported, and the launch continues: the path is not there, or the entry cannot mean it.
    Warn(String),
    /// The launch stops.
    Refuse(String),
}

/// Resolve one list of entries into the paths it covers, warning on each entry that yields none and
/// on each candidate the matcher could not judge.
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
        let mut unresolvable = false;
        let listing = match body.rsplit_once('/') {
            // A wildcard sits only in the last component (the grammar guarantees it), so at most
            // one directory is read, and only when there is a wildcard to match.
            Some((parent, last)) if has_wildcard(last) => match_in_dir(&root.join(parent), last),
            None if has_wildcard(body) => match_in_dir(root, body),
            _ => Ok((vec![root.join(body)], Vec::new())),
        };
        let (mut hits, mut unjudged) = match listing {
            Ok(both) => both,
            // A directory that is not there covers nothing, and neither does a pattern under a
            // path that is a file: both are entries their author can read and correct, and the
            // "matches nothing" warning below is what says so.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                (Vec::new(), Vec::new())
            }
            Err(e) => {
                let dir = match body.rsplit_once('/') {
                    Some((parent, _)) => root.join(parent),
                    None => root.to_path_buf(),
                };
                refused.get_or_insert_with(|| {
                    format!(
                        "`[fs] {field}` entry `{entry}`: {}",
                        unreadable_refusal("list", &dir, &e)
                    )
                });
                unresolvable = true;
                (Vec::new(), Vec::new())
            }
        };
        hits.sort();
        // Sorted for the same reason the hits are: the warning list a launch prints must not depend
        // on the order the kernel happened to hand back the directory.
        unjudged.sort();
        // A candidate the matcher could not compare against the pattern is reported, never dropped.
        // `[fs]` may only take access away, so its one intolerable failure mode is a quiet one: an
        // entry that covered three of four files reads exactly like one that covered all four.
        for path in unjudged {
            warnings.push(format!(
                "`[fs] {field}` entry `{entry}`: `{}` has a name that is not valid UTF-8, so it \
                 cannot be matched against the pattern — if the entry meant to close it, that path \
                 stays open to the cage",
                path.display()
            ));
        }
        let mut matched = 0;
        for candidate in hits {
            // "Not there" and "cannot be looked at" are different answers, and `Path::exists` gives
            // the same one to both: it is `metadata(..).is_ok()`, false for an absent path and
            // equally false for a path whose parent the caller cannot traverse — including when the
            // caller owns that parent. The cage runs as the user's own uid and holds the project
            // tree writable, so it can `chmod 000` a directory and have the next launch read its own
            // masked path as absent: the entry matches nothing, the launch says so as a warning
            // about a seemingly stale config entry, no mount is laid, and the session after that
            // puts the mode back and reads the file. That is the mask switched off by the thing it
            // exists to close.
            //
            // `NotFound` alone is "not there". Every other error refuses the launch, because an
            // entry that cannot be resolved is indistinguishable from one hidden to defeat it, and
            // the whole point of the entry is that the path not be reachable. The first refusal is
            // the one reported: they are all the same failure, and a launch stops on any of them.
            match std::fs::symlink_metadata(&candidate) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    refused.get_or_insert_with(|| {
                        format!(
                            "`[fs] {field}` entry `{entry}`: {}",
                            unreadable_refusal("look at", &candidate, &e)
                        )
                    });
                    unresolvable = true;
                    continue;
                }
            }
            match admit(root, &candidate, entry, dir_only) {
                Ok(Some(masked)) => {
                    matched += 1;
                    // A path already covered by an earlier entry needs no second mount.
                    if !out.iter().any(|m| m.path == masked.path) {
                        out.push(masked);
                    }
                }
                Ok(None) => {}
                Err(NotMasked::Warn(reason)) => warnings.push(format!(
                    "`[fs] {field}` entry `{entry}`: {reason} — that path stays open to the cage"
                )),
                Err(NotMasked::Refuse(reason)) => {
                    refused.get_or_insert(format!("`[fs] {field}` entry `{entry}`: {reason}"));
                    unresolvable = true;
                }
            }
        }
        // Not said of an entry that could not be resolved: "matches nothing" reads as a stale
        // config line the author may delete, which is the opposite of what happened. That entry
        // matched something it was not allowed to look at, and the launch is refusing over it.
        if matched == 0 && !unresolvable {
            warnings.push(format!(
                "`[fs] {field}` entry `{entry}` matches nothing in this project — nothing is closed \
                 by it"
            ));
        }
    }
    out
}

/// The entries of `dir` whose name matches `pattern`, and — separately — the entries that could not
/// be matched at all. The error of a directory that cannot be read is handed back rather than
/// folded into "no entries": the caller is the one that knows an absent directory covers nothing
/// while an unreadable one is the mask being switched off from inside the cage.
///
/// The second list exists because a Linux filename is arbitrary non-NUL bytes while
/// [`matches_component`] compares `str`s: a name that is not valid UTF-8 can never match any pattern,
/// so folding it into "did not match" would turn a path the entry could not cover into one it
/// deliberately left out. The caller warns about each, which is the whole difference between a mask
/// with a known gap and a mask that reports success it did not achieve.
fn match_in_dir(dir: &Path, pattern: &str) -> std::io::Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let (mut hits, mut unjudged) = (Vec::new(), Vec::new());
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        match name.to_str() {
            Some(n) if matches_component(pattern, n) => hits.push(entry.path()),
            Some(_) => {}
            None => unjudged.push(entry.path()),
        }
    }
    Ok((hits, unjudged))
}

/// Judge one candidate path that is known to be there: it must resolve inside the project and match
/// the entry's file/directory intent. Whether the path is there at all is [`resolve_list`]'s
/// question, because the two ways to answer "no" have different consequences and only one of them
/// is a warning. `Ok(None)` is left for a candidate that vanished between the two calls.
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
) -> Result<Option<Masked>, NotMasked> {
    // Resolving follows the path, so it answers about the target rather than about the link
    // `resolve_list` has already looked at. A dangling link is a stale entry; a target behind a
    // directory this launch may not traverse is the same answer as one hidden to defeat the mask,
    // and is refused for the same reason.
    let canon = candidate.canonicalize().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            NotMasked::Warn(format!("cannot resolve `{}` ({e})", candidate.display()))
        } else {
            NotMasked::Refuse(unreadable_refusal("resolve", candidate, &e))
        }
    })?;
    if !canon.starts_with(root) {
        return Err(NotMasked::Warn(format!(
            "`{}` resolves to `{}`, outside the project — `[fs]` closes paths of the project it is \
             declared in, and nothing else",
            candidate.display(),
            canon.display()
        )));
    }
    if canon == root {
        return Err(NotMasked::Warn(
            "names the project root itself, which would close the whole tree".to_string(),
        ));
    }
    let meta = std::fs::metadata(&canon).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            NotMasked::Warn(format!("cannot stat `{}` ({e})", canon.display()))
        } else {
            NotMasked::Refuse(unreadable_refusal("stat", &canon, &e))
        }
    })?;
    let is_dir = meta.is_dir();
    if dir_only && !is_dir {
        return Err(NotMasked::Warn(format!(
            "`{}` is not a directory, but the entry ends in `/`",
            canon.display()
        )));
    }
    Ok(Some(Masked {
        path: canon,
        is_dir,
        pattern: entry.to_string(),
        builtin: false,
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
    Some(
        parse_git_index_entries(data, SHA1_LEN)?
            .into_iter()
            .filter(|entry| !entry.skip_worktree)
            .map(|entry| String::from_utf8_lossy(&entry.path).into_owned())
            .collect(),
    )
}

/// The length of an object name in a repository that keeps SHA-1 names, git's default.
const SHA1_LEN: usize = 20;

/// The length of an object name in a repository whose `extensions.objectFormat` is `sha256`.
const SHA256_LEN: usize = 32;

/// The mode git records for a gitlink: a submodule's commit, whose directory holds a repository.
const GITLINK_MODE: u32 = 0o160000;

/// One entry of a git index, as far as the checks here read it.
struct IndexEntry {
    path: Vec<u8>,
    mode: u32,
    skip_worktree: bool,
}

/// The entries of a git index blob whose object names are `hash_len` bytes long, or `None` when the
/// blob is not an index this reads in full.
///
/// Versions 2 and 3 pad each entry to a multiple of 8 bytes; version 4, which git writes when a
/// repository asks for it and which `git update-index --index-version 4` switches any index to,
/// writes each path as the length it strips from the previous one and the rest. A split index keeps
/// most of its entries in a shared file of its own, so an index that carries one is not read in
/// full here and answers `None`.
fn parse_git_index_entries(data: &[u8], hash_len: usize) -> Option<Vec<IndexEntry>> {
    if data.len() < 12 || &data[0..4] != b"DIRC" {
        return None;
    }
    let version = u32::from_be_bytes(data[4..8].try_into().ok()?);
    if !matches!(version, 2..=4) {
        return None;
    }
    let count = u32::from_be_bytes(data[8..12].try_into().ok()?) as usize;
    let mut out = Vec::new();
    let mut previous: Vec<u8> = Vec::new();
    let mut pos = 12;
    for _ in 0..count {
        let start: usize = pos;
        // Ten 4-byte fields, the fifth being the mode, then the object name, then the flags whose
        // bit 0x4000 says a second pair follows (version 3's extended flags).
        let mode_at = start.checked_add(24)?;
        let flags_at = start.checked_add(40)?.checked_add(hash_len)?;
        if flags_at + 2 > data.len() {
            return None;
        }
        let mode = u32::from_be_bytes(data[mode_at..mode_at + 4].try_into().ok()?);
        let flags = u16::from_be_bytes(data[flags_at..flags_at + 2].try_into().ok()?);
        let mut name_at = flags_at + 2;
        // Bit 0x4000 of the extended flags is `skip-worktree`, which git sets on `update-index
        // --skip-worktree`.
        let mut skip_worktree = false;
        if flags & 0x4000 != 0 {
            if name_at + 2 > data.len() {
                return None;
            }
            let extended = u16::from_be_bytes(data[name_at..name_at + 2].try_into().ok()?);
            skip_worktree = extended & 0x4000 != 0;
            name_at += 2;
        }
        let path = if version == 4 {
            let (strip, used) = index_varint(data.get(name_at..)?)?;
            name_at += used;
            let end = name_at + data.get(name_at..)?.iter().position(|&b| b == 0)?;
            let mut path = previous[..previous.len().checked_sub(strip)?].to_vec();
            path.extend_from_slice(&data[name_at..end]);
            pos = end + 1;
            path
        } else {
            // The 12-bit length in the flags saturates at 0xFFF, so the NUL is the authority
            // either way; entries are padded with NULs to a multiple of 8 from their own start.
            let end = name_at + data.get(name_at..)?.iter().position(|&b| b == 0)?;
            pos = start + (end + 1 - start).div_ceil(8) * 8;
            data[name_at..end].to_vec()
        };
        if pos > data.len() {
            return None;
        }
        previous.clone_from(&path);
        out.push(IndexEntry {
            path,
            mode,
            skip_worktree,
        });
    }
    // The extensions run from the last entry to the checksum: four bytes of signature and four of
    // length each.
    let body_end = data.len().saturating_sub(hash_len);
    while pos + 8 <= body_end {
        let size = u32::from_be_bytes(data[pos + 4..pos + 8].try_into().ok()?) as usize;
        if &data[pos..pos + 4] == b"link" {
            return None;
        }
        pos = pos.checked_add(8)?.checked_add(size)?;
    }
    Some(out)
}

/// git's offset varint, which index version 4 writes the stripped length in, and how many bytes
/// it took.
fn index_varint(data: &[u8]) -> Option<(usize, usize)> {
    let mut used = 0;
    let mut byte = *data.get(used)?;
    used += 1;
    let mut value = usize::from(byte & 0x7f);
    while byte & 0x80 != 0 {
        byte = *data.get(used)?;
        used += 1;
        value = value
            .checked_add(1)?
            .checked_mul(0x80)?
            .checked_add(usize::from(byte & 0x7f))?;
    }
    Some((value, used))
}

/// The gitlinks of `repo`'s index, as directories of its work tree: where the host's git looks for a
/// submodule's repository, whether or not `.gitmodules` names it. `Ok` and empty when there is no
/// index; `Err` with the reason when there is one this cannot read in full, so the caller decides
/// whether that stops the launch.
///
/// Read rather than asked, for the reason [`git_tracked_paths`] gives: listing the index through
/// git runs what its configuration names. A path that is not plain names below the work tree is
/// not one git writes, and is left out.
fn gitlinks(repo: &GitRepo) -> Result<Vec<PathBuf>, String> {
    use std::os::unix::ffi::OsStrExt;
    let index = repo.dir.join("index");
    let meta = match std::fs::metadata(&index) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(git_unreadable("look at", &index, &e)),
        Ok(meta) => meta,
    };
    let unread = || {
        format!(
            "`{}` is not an index sbx reads in full (larger than {} MiB, split, or of another \
             format), so the submodules whose repositories git reads cannot be found. {GIT_WRITABLE_HINT}",
            index.display(),
            INDEX_MAX / (1024 * 1024)
        )
    };
    if !meta.is_file() || meta.len() > INDEX_MAX {
        return Err(unread());
    }
    let data = std::fs::read(&index).map_err(|e| git_unreadable("read", &index, &e))?;
    let hash_len = if host_git_config(repo, &["--get", "extensions.objectFormat"])
        .is_some_and(|out| out.trim_ascii() == b"sha256")
    {
        SHA256_LEN
    } else {
        SHA1_LEN
    };
    let entries = parse_git_index_entries(&data, hash_len).ok_or_else(unread)?;
    Ok(entries
        .into_iter()
        .filter(|entry| entry.mode == GITLINK_MODE)
        .map(|entry| PathBuf::from(std::ffi::OsStr::from_bytes(&entry.path)))
        .filter(|rel| {
            rel.components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
        })
        .map(|rel| repo.work_tree.join(rel))
        .collect())
}

/// The binds that realise this expansion in the agent's cage.
///
/// Emitted among the launcher-injected binds, which land **after** the structural mounts — the
/// project included. Order is the whole mechanism: a mask emitted before the project mount would be
/// covered by it, which is exactly why a `binds` entry aimed inside the project cannot mask
/// anything today.
///
/// `project_writable` is whether the project itself is mounted read-write. The directories that
/// hold the masks in place ([`holding_dirs`]) inside the project are bound only then: in a
/// read-only project nothing can be renamed, and a read-write bind of one of its directories would
/// reopen it to writes. Those in a read-write bind are bound either way, since the bind is.
pub(crate) fn agent_binds(
    expanded: &Expanded,
    decoys: &Decoys,
    project_writable: bool,
) -> Vec<ExtraBind> {
    let mut out = Vec::with_capacity(expanded.count());
    // The held directories first, shallow to deep, so every mask lands inside the directories
    // already held above it rather than being covered by one laid after it.
    out.extend(
        expanded
            .pins
            .iter()
            .filter(|dir| project_writable || !expanded.reach.in_project(dir))
            .map(|dir| ExtraBind {
                src: dir.clone(),
                dest: dir.clone(),
                writable: true,
            }),
    );
    // Then `readonly`, then `deny`. The two can legitimately nest the one way round that is left
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

    /// The coverage rule answers for a path *under* a denied directory, not only for the paths the
    /// expansion listed.
    ///
    /// That is the whole point of a denied directory: the cage sees an empty one, so a file created
    /// there later in the session is unreachable too. A rule that only compared against the listed
    /// paths would report a name that does not exist yet as open, which is the opposite of what the
    /// mount does.
    #[test]
    fn covering_answers_for_a_path_under_a_denied_directory() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let out = expand(&root, &policy(&["secrets/"], &[]), &[], None);
        assert!(out.refused.is_none(), "{:?}", out.refused);

        let listed = out.covering(&root.join("secrets"));
        assert!(matches!(listed, Some(Cover::Denied(_))), "{listed:?}");
        let inside = out.covering(&root.join("secrets/token"));
        assert!(matches!(inside, Some(Cover::Denied(_))), "{inside:?}");
        // Nothing bears this name on disk; the empty directory covers it all the same.
        let future = out.covering(&root.join("secrets/written-later"));
        assert!(matches!(future, Some(Cover::Denied(_))), "{future:?}");
        assert!(out.covering(&root.join("main.rs")).is_none());
    }

    /// Where a denied file sits inside a read-only directory, the answer is the deny.
    ///
    /// `agent_binds` emits `readonly` first and `deny` second, and the later mount wins, so any
    /// other answer here would describe a cage that is not the one a launch builds. Written as a
    /// pair — the sibling under the same read-only directory must still read as read-only — so the
    /// test cannot pass by reporting `Denied` for everything.
    #[test]
    fn covering_lets_deny_win_inside_a_readonly_directory() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let out = expand(
            &root,
            &policy(&["certs/server.pem"], &["certs/"]),
            &[],
            None,
        );
        assert!(out.refused.is_none(), "{:?}", out.refused);

        let denied = out.covering(&root.join("certs/server.pem"));
        assert!(matches!(denied, Some(Cover::Denied(_))), "{denied:?}");
        let sibling = out.covering(&root.join("certs/client.pem"));
        assert!(matches!(sibling, Some(Cover::ReadOnly(_))), "{sibling:?}");
    }

    /// The entry that decides comes back with the verdict, so a caller can name what to edit.
    #[test]
    fn covering_names_the_entry_that_decides() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let out = expand(&root, &policy(&["*.key"], &[]), &[], None);
        assert!(out.refused.is_none(), "{:?}", out.refused);

        match out.covering(&root.join("prod.key")) {
            Some(Cover::Denied(m)) => assert_eq!(m.pattern, "*.key"),
            other => panic!("{other:?}"),
        }
    }

    /// A project root that does not resolve refuses the launch instead of dropping every mask.
    ///
    /// Everything the expansion does resolves against that root, so failing to read it yields the
    /// same empty answer a policy naming nothing produces — while the config says the opposite. The
    /// launch reads `refused` as fatal and `warnings` as prose, so this is the difference between a
    /// run that stops and a run whose secrets are readable under a line nobody had to act on.
    #[test]
    fn a_project_root_that_does_not_resolve_refuses_rather_than_dropping_every_mask() {
        let tmp = TmpDir::new();
        let absent = tmp.path().join("gone");

        let e = expand(&absent, &policy(&["prod.key"], &[]), &[], None);
        let refusal = e
            .refused
            .expect("an unresolvable root must refuse the launch");
        assert!(
            refusal.contains("gone"),
            "the refusal must name the directory it could not resolve: {refusal}"
        );
        assert!(
            e.denied.is_empty() && e.readonly.is_empty(),
            "and it must place nothing, which is why it cannot be a warning"
        );

        // The control arm: a policy that asks for nothing is not a policy that failed, and the same
        // unresolvable path must stay silent for it — the early return above it sees to that.
        let empty = expand(&absent, &policy(&[], &[]), &[], None);
        assert!(
            empty.refused.is_none(),
            "a launch declaring no `[fs]` masks has nothing to place and nothing to refuse"
        );
    }

    #[test]
    fn an_entry_resolves_to_the_paths_it_covers() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let e = expand(
            &root,
            &policy(&["prod.key", "certs/*.pem", "secrets/"], &[]),
            &[],
            None,
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
        let e = expand(
            &root,
            &policy(&["absent.key", "certs/*.crt"], &[]),
            &[],
            None,
        );
        assert!(e.denied.is_empty());
        assert_eq!(e.warnings.len(), 2, "{:?}", e.warnings);
        assert!(e.warnings.iter().all(|w| w.contains("matches nothing")));
    }

    /// A mask the cage can switch off is not a mask. `Path::exists` answers false for a path whose
    /// parent is not traversable exactly as it does for one that is absent, and the cage owns the
    /// project tree under the user's own uid, so `chmod 000` on a directory used to turn a masked
    /// path into "matches nothing": a warning about a seemingly stale config entry, no mount, and
    /// the file readable again the moment the mode goes back.
    ///
    /// The launch must refuse instead. `NotFound` stays the one error that means "not there" — the
    /// sibling test above covers it and must keep passing, or this fix would have closed the hole
    /// by refusing every absent entry, which is a different and much louder change.
    #[test]
    fn an_entry_hidden_behind_an_unreadable_parent_refuses_the_launch() {
        // root traverses whatever it likes, so the premise does not hold there.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let sub = root.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("secrets.env"), b"SECRET").unwrap();

        // Sanity: the entry is honoured while the parent can be traversed.
        let ok = expand(&root, &policy(&["sub/secrets.env"], &[]), &[], None);
        assert_eq!(ok.denied.len(), 1);
        assert!(ok.refused.is_none());

        // The cage makes its own directory untraversable, as it may.
        std::fs::set_permissions(&sub, std::os::unix::fs::PermissionsExt::from_mode(0o000))
            .unwrap();
        let hidden = expand(&root, &policy(&["sub/secrets.env"], &[]), &[], None);
        // Restore before asserting, so a failure does not leave the fixture undeletable.
        std::fs::set_permissions(&sub, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();

        assert!(
            hidden.refused.is_some(),
            "an entry the cage hid must refuse the launch, not warn: {:?}",
            hidden.warnings
        );
        assert!(
            !hidden
                .warnings
                .iter()
                .any(|w| w.contains("matches nothing")),
            "and it must not read as a stale config entry: {:?}",
            hidden.warnings
        );
    }

    #[test]
    fn a_wildcard_entry_hidden_behind_an_unreadable_parent_refuses_the_launch() {
        // The same defeat as the literal entry above, through the branch that reads a directory.
        // `read_dir` on a `chmod 000` parent fails, and an empty listing reads exactly like a
        // pattern that matched nothing — the warning an author would delete the entry over.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let sub = root.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("a.env"), b"SECRET").unwrap();

        let ok = expand(&root, &policy(&["sub/*.env"], &[]), &[], None);
        assert_eq!(ok.denied.len(), 1, "honoured while the parent is readable");
        assert!(ok.refused.is_none());

        std::fs::set_permissions(&sub, std::os::unix::fs::PermissionsExt::from_mode(0o000))
            .unwrap();
        let hidden = expand(&root, &policy(&["sub/*.env"], &[]), &[], None);
        std::fs::set_permissions(&sub, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();

        assert!(
            hidden.refused.is_some(),
            "a wildcard entry the cage hid must refuse the launch, not warn: {:?}",
            hidden.warnings
        );
        assert!(
            !hidden
                .warnings
                .iter()
                .any(|w| w.contains("matches nothing")),
            "and it must not read as a stale config entry: {:?}",
            hidden.warnings
        );
    }

    #[test]
    fn an_entry_naming_a_link_into_an_unreadable_directory_refuses_the_launch() {
        // The third site: the link itself is there, so `symlink_metadata` succeeds and the entry
        // reaches `admit`, where following it needs the directory the cage closed.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let sub = root.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("secrets.env"), b"SECRET").unwrap();
        std::os::unix::fs::symlink(sub.join("secrets.env"), root.join("link.env")).unwrap();

        let ok = expand(&root, &policy(&["link.env"], &[]), &[], None);
        assert_eq!(ok.denied.len(), 1, "honoured while the target is reachable");
        assert!(ok.refused.is_none());

        std::fs::set_permissions(&sub, std::os::unix::fs::PermissionsExt::from_mode(0o000))
            .unwrap();
        let hidden = expand(&root, &policy(&["link.env"], &[]), &[], None);
        std::fs::set_permissions(&sub, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();

        assert!(
            hidden.refused.is_some(),
            "a link whose target the cage hid must refuse the launch, not warn: {:?}",
            hidden.warnings
        );
    }

    #[test]
    fn an_entry_that_is_merely_absent_or_misspelt_still_only_warns() {
        // The boundary the refusal must not cross. Neither of these is a path anyone hid: one
        // names a directory that is not there, the other puts a pattern under a file. Both are
        // entries their author can read and correct, so both keep the warning.
        let tmp = TmpDir::new();
        let root = project(&tmp);
        std::fs::write(root.join("notadir"), b"x").unwrap();

        for entry in ["nothere/*.env", "notadir/*.env"] {
            let out = expand(&root, &policy(&[entry], &[]), &[], None);
            assert!(
                out.refused.is_none(),
                "`{entry}` must not refuse the launch: {:?}",
                out.refused
            );
            assert!(
                out.warnings.iter().any(|w| w.contains("matches nothing")),
                "`{entry}` must say it matches nothing: {:?}",
                out.warnings
            );
        }
    }

    #[test]
    fn a_wildcard_says_so_when_a_sibling_name_is_not_valid_utf8() {
        // A filename on Linux is arbitrary bytes; the pattern matcher compares text. A candidate the
        // matcher cannot judge used to be dropped as "did not match", so an entry that covered two of
        // three certificates reported exactly what a complete mask reports — and the third stayed
        // readable in the cage. A mask that may only take access away must never claim coverage it
        // does not have, so the gap is named at launch. The UTF-8 siblings must still be masked: the
        // report is an addition, not a refusal of the whole entry.
        use std::os::unix::ffi::OsStrExt;
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let odd = std::ffi::OsStr::from_bytes(b"priv\xe9.pem");
        std::fs::write(root.join("certs").join(odd), b"KEY").unwrap();

        let e = expand(&root, &policy(&["certs/*.pem"], &[]), &[], None);
        let paths: Vec<&Path> = e.denied.iter().map(|m| m.path.as_path()).collect();
        assert_eq!(
            paths,
            [root.join("certs/client.pem"), root.join("certs/server.pem")]
                .iter()
                .map(|p| p.as_path())
                .collect::<Vec<_>>(),
            "the siblings the matcher can judge are still closed"
        );
        assert_eq!(
            e.warnings.len(),
            1,
            "exactly the one unjudgeable candidate is reported: {:?}",
            e.warnings
        );
        assert!(
            e.warnings[0].contains("not valid UTF-8") && e.warnings[0].contains("stays open"),
            "the warning names the gap and its consequence: {}",
            e.warnings[0]
        );
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
        let e = expand(&root, &policy(&["link.key"], &[]), &[], None);
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

    /// The files that govern the cage are read-only in it without anyone listing them: the
    /// `.sbx.toml` and the mise files beside it that are present at launch.
    #[test]
    fn the_config_and_its_present_mise_files_are_read_only_by_default() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        std::fs::write(root.join(".sbx.toml"), b"network = \"none\"\n").unwrap();
        std::fs::write(root.join("mise.toml"), b"[tools]\n").unwrap();
        std::fs::create_dir_all(root.join(".config/mise")).unwrap();
        std::fs::write(root.join(".config/mise/config.toml"), b"[tools]\n").unwrap();

        let e = expand(&root, &FsPolicy::default(), &[], None);
        let ro: Vec<&Path> = e.readonly.iter().map(|m| m.path.as_path()).collect();
        assert_eq!(
            ro,
            vec![
                root.join(".sbx.toml").as_path(),
                root.join("mise.toml").as_path(),
                root.join(".config/mise/config.toml").as_path(),
            ],
            "the present files only, in the gate's order"
        );
        assert!(e.denied.is_empty());
        assert!(
            e.warnings.is_empty(),
            "an absent mise file is no warning: {:?}",
            e.warnings
        );
        assert!(
            matches!(
                e.covering(&root.join(".sbx.toml")),
                Some(Cover::ReadOnly(_))
            ),
            "`sbx test fs` answers from the same expansion"
        );
    }

    /// Without a `.sbx.toml` sbx honors no mise file, so there is nothing a write to one re-arms,
    /// and a project that only uses mise keeps writing its own config.
    #[test]
    fn without_a_project_config_nothing_is_read_only_by_default() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        std::fs::write(root.join("mise.toml"), b"[tools]\n").unwrap();
        let e = expand(&root, &FsPolicy::default(), &[], None);
        assert!(e.is_empty(), "{:?}", e.readonly);
    }

    /// A declared entry that already covers a built-in one takes its place: a `deny` closes the
    /// file outright, and a declared `readonly` of it or of a directory above needs no second
    /// mount.
    #[test]
    fn a_declared_entry_covering_a_builtin_one_takes_its_place() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        std::fs::write(root.join(".sbx.toml"), b"").unwrap();
        std::fs::create_dir_all(root.join(".mise")).unwrap();
        std::fs::write(root.join(".mise/config.toml"), b"").unwrap();
        std::fs::write(root.join(".tool-versions"), b"").unwrap();

        let e = expand(&root, &policy(&[".tool-versions"], &[".mise/"]), &[], None);
        let ro: Vec<&Path> = e.readonly.iter().map(|m| m.path.as_path()).collect();
        assert_eq!(
            ro,
            vec![
                root.join(".mise").as_path(),
                root.join(".sbx.toml").as_path()
            ],
            "the declared directory, then the one built-in entry nothing declared covers"
        );
        let denied: Vec<&Path> = e.denied.iter().map(|m| m.path.as_path()).collect();
        assert_eq!(denied, vec![root.join(".tool-versions").as_path()]);
        assert!(e.warnings.is_empty(), "{:?}", e.warnings);
    }

    /// The git carrier is read-only by default, with or without a `.sbx.toml`: the hooks
    /// directory, so a hook created mid-session is refused too, and the config, whose keys can name
    /// a program as surely as a hook can.
    #[test]
    fn the_git_hooks_and_config_are_read_only_by_default_and_git_writable_lifts_them() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        std::fs::create_dir_all(root.join(".git/hooks")).unwrap();
        std::fs::write(root.join(".git/config"), b"[core]\n").unwrap();

        let e = expand(&root, &FsPolicy::default(), &[], None);
        let ro: Vec<(&Path, bool)> = e
            .readonly
            .iter()
            .map(|m| (m.path.as_path(), m.is_dir))
            .collect();
        assert_eq!(
            ro,
            vec![
                (root.join(".git/config").as_path(), false),
                (root.join(".git/hooks").as_path(), true),
            ]
        );
        assert!(e.readonly.iter().all(|m| m.builtin));

        let lifted = FsPolicy {
            git_writable: Some(true),
            ..FsPolicy::default()
        };
        assert!(
            expand(&root, &lifted, &[], None).is_empty(),
            "the one opening in the table"
        );
    }

    /// A hooks directory that is not there is masked all the same, and the launch makes it before
    /// binding it: otherwise the cage would create it and fill it. The creation walks the path one
    /// component at a time and refuses a link planted in the way rather than following it.
    #[test]
    fn an_absent_hooks_directory_is_masked_and_made_empty_but_never_through_a_link() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".git/config"), b"[core]\n").unwrap();

        let e = expand(&root, &FsPolicy::default(), &[], None);
        let hooks = root.join(".git/hooks");
        assert!(
            e.readonly
                .iter()
                .any(|m| m.path == hooks && m.is_dir && m.builtin),
            "{:?}",
            e.readonly
        );
        assert!(
            !hooks.exists(),
            "expanding is read-only: the launch makes it"
        );
        create_absent_dirs(&e).unwrap();
        assert!(hooks.is_dir() && std::fs::read_dir(&hooks).unwrap().next().is_none());

        // A link where a component should be is refused, never followed.
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::remove_dir(&hooks).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &hooks).unwrap();
        let planted = Expanded {
            readonly: vec![Masked {
                path: hooks.join("sub"),
                is_dir: true,
                pattern: String::new(),
                builtin: true,
            }],
            reach: Reach::of(&root, &[], None),
            ..Expanded::default()
        };
        assert!(create_absent_dirs(&planted).is_err());
        assert!(
            !elsewhere.join("sub").exists(),
            "nothing made through the link"
        );
    }

    /// `core.hooksPath` inside the project is protected like `.git/hooks` — husky's `.husky/_`,
    /// ignored by git, is where a rewritten hook would not even show in `git status`. Read from the
    /// host's git, so this needs one.
    #[test]
    fn the_directory_core_hooks_path_names_inside_the_project_is_read_only() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(&root)
                .output()
        };
        let Ok(init) = git(&["init", "-q"]) else {
            return; // no git on this host: no hook can run on it either
        };
        assert!(init.status.success());
        std::fs::create_dir_all(root.join(".husky/_")).unwrap();
        assert!(
            git(&["config", "core.hooksPath", ".husky/_"])
                .unwrap()
                .status
                .success()
        );

        let e = expand(&root, &FsPolicy::default(), &[], None);
        assert!(
            e.readonly
                .iter()
                .any(|m| m.path == root.join(".husky/_") && m.is_dir && m.builtin),
            "{:?}",
            e.readonly
        );
        let lifted = FsPolicy {
            git_writable: Some(true),
            ..FsPolicy::default()
        };
        assert!(
            expand(&root, &lifted, &[], None).readonly.is_empty(),
            "git_writable lifts it too"
        );

        // Outside the project: the cage does not hold it, so nothing is added.
        let outside = tmp.path().join("hooks-elsewhere");
        let value = outside.display().to_string();
        assert!(
            git(&["config", "core.hooksPath", &value])
                .unwrap()
                .status
                .success()
        );
        let e = expand(&root, &FsPolicy::default(), &[], None);
        assert!(!e.readonly.iter().any(|m| m.path.starts_with(&outside)));
    }

    /// A file an include makes part of the host's git configuration is protected when it is in
    /// the project, nested includes and conditional ones alike; one that does not exist refuses
    /// the launch instead of being created; one outside the project is left alone.
    #[test]
    fn a_file_git_includes_as_configuration_is_read_only_or_the_launch_refuses() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(&root)
                .output()
        };
        let Ok(init) = git(&["init", "-q"]) else {
            return; // no git on this host: no configuration to read either
        };
        assert!(init.status.success());
        let root = root.canonicalize().unwrap();
        std::fs::write(
            root.join("inc.gitconfig"),
            "[include]\n\tpath = nested.cfg\n",
        )
        .unwrap();
        std::fs::write(root.join("nested.cfg"), "[core]\n").unwrap();
        // Relative to the file that declares it: `.git/config` is in `.git`.
        assert!(
            git(&["config", "include.path", "../inc.gitconfig"])
                .unwrap()
                .status
                .success()
        );
        let outside = tmp.path().join("outside.cfg");
        std::fs::write(&outside, "").unwrap();
        let cond = format!("{}", outside.display());
        assert!(
            git(&["config", "includeIf.gitdir:/nowhere/.path", &cond])
                .unwrap()
                .status
                .success()
        );

        let e = expand(&root, &FsPolicy::default(), &[], None);
        assert!(e.refused.is_none(), "{:?}", e.refused);
        let files: Vec<&Path> = e
            .readonly
            .iter()
            .filter(|m| m.builtin && !m.is_dir)
            .map(|m| m.path.as_path())
            .collect();
        assert!(
            files.contains(&root.join("inc.gitconfig").as_path()),
            "{files:?}"
        );
        assert!(
            files.contains(&root.join("nested.cfg").as_path()),
            "nested: {files:?}"
        );
        assert!(
            !files
                .iter()
                .any(|p| p.starts_with(tmp.path().join("outside.cfg")))
        );

        // An include of a project file that is not there: refused, named, nothing created.
        assert!(
            git(&["config", "--add", "include.path", "../later.cfg"])
                .unwrap()
                .status
                .success()
        );
        let e = expand(&root, &FsPolicy::default(), &[], None);
        let why = e
            .refused
            .expect("an absent included file refuses the launch");
        assert!(
            why.contains("later.cfg") && why.contains("git_writable"),
            "{why}"
        );
        assert!(!root.join("later.cfg").exists());

        let lifted = FsPolicy {
            git_writable: Some(true),
            ..FsPolicy::default()
        };
        assert!(
            expand(&root, &lifted, &[], None).refused.is_none(),
            "git_writable lifts it"
        );
    }

    /// A project with a git repository made by the host's own git and one commit, or `None` where
    /// there is no git to make it. The identity is passed on the command line and hooks are not
    /// run, so the developer's own configuration writes nothing into the fixture.
    fn git_project(tmp: &TmpDir) -> Option<(PathBuf, impl Fn(&[&str]) -> bool)> {
        let root = project(tmp);
        let dir = root.clone();
        let git = move |args: &[&str]| {
            std::process::Command::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@t"])
                .args(args)
                .current_dir(&dir)
                .output()
                .is_ok_and(|o| o.status.success())
        };
        if !git(&["init", "-q"]) {
            return None;
        }
        assert!(git(&[
            "commit",
            "-q",
            "--no-verify",
            "--allow-empty",
            "-m",
            "i"
        ]));
        Some((root.canonicalize().unwrap(), git))
    }

    /// A `.git/commondir` in the project's own repository refuses the launch, and before the host's
    /// git is asked anything: here the directory it names carries a `core.hooksPath` into the
    /// project, and no mask for that directory may come of it.
    #[test]
    fn a_commondir_in_the_main_repository_refuses_before_git_is_asked() {
        let tmp = TmpDir::new();
        let Some((root, git)) = git_project(&tmp) else {
            skip_incapable!("skipping commondir refusal: no git on this host");
            return;
        };
        // A repository git accepts as the common directory, or it would answer nothing at all and
        // the assertion below would hold whatever the order.
        assert!(git(&["init", "-q", "--bare", "other.git"]));
        assert!(git(&[
            "--git-dir",
            "other.git",
            "config",
            "core.hooksPath",
            "named-hooks"
        ]));
        std::fs::create_dir_all(root.join("named-hooks")).unwrap();
        std::fs::write(root.join(".git/commondir"), "../other.git\n").unwrap();

        let e = expand(&root, &FsPolicy::default(), &[], None);
        let why = e.refused.as_deref().expect("a main commondir refuses");
        assert!(
            why.contains(".git/commondir") && why.contains("git_writable"),
            "{why}"
        );
        assert!(
            !e.readonly
                .iter()
                .any(|m| m.path == root.join("named-hooks")),
            "nothing was asked of git: {:?}",
            e.readonly
        );

        // Whatever its shape.
        std::fs::remove_file(root.join(".git/commondir")).unwrap();
        std::fs::create_dir(root.join(".git/commondir")).unwrap();
        assert!(
            expand(&root, &FsPolicy::default(), &[], None)
                .refused
                .is_some()
        );

        let lifted = FsPolicy {
            git_writable: Some(true),
            ..FsPolicy::default()
        };
        assert!(
            expand(&root, &lifted, &[], None).refused.is_none(),
            "git_writable lifts it"
        );
    }

    /// `.git/config.worktree` is read-only when present. When `.git/config` turns
    /// `extensions.worktreeConfig` on, git reads it, so an absent one refuses the launch; the
    /// setting in an included file is not honored by git, and does not refuse.
    #[test]
    fn a_config_worktree_is_read_only_and_an_absent_one_refuses_when_git_reads_it() {
        let tmp = TmpDir::new();
        let Some((root, git)) = git_project(&tmp) else {
            skip_incapable!("skipping config.worktree protection: no git on this host");
            return;
        };
        let worktree_config = root.join(".git/config.worktree");
        let protected = |e: &Expanded| e.readonly.iter().any(|m| m.path == worktree_config);

        let e = expand(&root, &FsPolicy::default(), &[], None);
        assert!(e.refused.is_none(), "{:?}", e.refused);
        assert!(!protected(&e), "absent and not read: nothing to hold");

        std::fs::write(&worktree_config, "").unwrap();
        let e = expand(&root, &FsPolicy::default(), &[], None);
        assert!(protected(&e), "present: read-only whatever the setting");

        std::fs::remove_file(&worktree_config).unwrap();
        std::fs::write(
            root.join("inc.cfg"),
            "[extensions]\n\tworktreeConfig = true\n",
        )
        .unwrap();
        assert!(git(&["config", "include.path", "../inc.cfg"]));
        assert!(
            expand(&root, &FsPolicy::default(), &[], None)
                .refused
                .is_none(),
            "git honors the setting from `.git/config` only"
        );

        assert!(git(&["config", "extensions.worktreeConfig", "true"]));
        let e = expand(&root, &FsPolicy::default(), &[], None);
        let why = e.refused.as_deref().expect("read by git and absent");
        assert!(
            why.contains("config.worktree") && why.contains("git_writable"),
            "{why}"
        );
        assert!(!worktree_config.exists(), "nothing is created");
    }

    /// Each linked worktree's `commondir` and `config.worktree` are read-only, whatever its name,
    /// and the directories above them are held in place.
    #[test]
    fn each_linked_worktrees_configuration_files_are_read_only() {
        let tmp = TmpDir::new();
        let Some((root, git)) = git_project(&tmp) else {
            skip_incapable!("skipping linked worktree protection: no git on this host");
            return;
        };
        assert!(git(&["config", "extensions.worktreeConfig", "true"]));
        std::fs::write(root.join(".git/config.worktree"), "").unwrap();
        let linked = tmp.path().join("linked");
        assert!(git(&[
            "worktree",
            "add",
            "-q",
            "--detach",
            linked.to_str().unwrap()
        ]));
        // git turns such a name into `w-t` for a worktree it makes; one made by hand keeps it.
        let odd = root.join(".git/worktrees/w*t");
        std::fs::create_dir_all(&odd).unwrap();
        std::fs::write(odd.join("commondir"), "../..\n").unwrap();
        std::fs::write(odd.join("config.worktree"), "").unwrap();

        let e = expand(&root, &FsPolicy::default(), &[], None);
        assert!(e.refused.is_none(), "{:?}", e.refused);
        let files: Vec<&Path> = e
            .readonly
            .iter()
            .filter(|m| m.builtin)
            .map(|m| m.path.as_path())
            .collect();
        for worktree in ["linked", "w*t"] {
            for name in ["commondir", "config.worktree"] {
                let path = root.join(".git/worktrees").join(worktree).join(name);
                assert!(
                    files.contains(&path.as_path()),
                    "{worktree}/{name}: {files:?}"
                );
            }
            assert!(
                e.pins.contains(&root.join(".git/worktrees").join(worktree)),
                "{:?}",
                e.pins
            );
        }
    }

    /// A link among these files, or in place of `.git/worktrees`, refuses the launch: the cage
    /// could point it elsewhere while the mask holds what it pointed to. A name the cage chose is
    /// escaped in the refusal rather than written to the terminal as it is.
    #[test]
    fn a_link_among_the_worktree_configuration_files_refuses_and_is_shown_escaped() {
        let tmp = TmpDir::new();
        let Some((root, _git)) = git_project(&tmp) else {
            skip_incapable!("skipping worktree link refusal: no git on this host");
            return;
        };
        std::fs::write(root.join("real.cfg"), "").unwrap();
        std::os::unix::fs::symlink("../real.cfg", root.join(".git/config.worktree")).unwrap();
        let why = expand(&root, &FsPolicy::default(), &[], None)
            .refused
            .expect("a link refuses");
        assert!(why.contains("symbolic link"), "{why}");
        std::fs::remove_file(root.join(".git/config.worktree")).unwrap();

        let named = root.join(".git/worktrees/a\u{1b}[2Jb");
        std::fs::create_dir_all(&named).unwrap();
        std::os::unix::fs::symlink("/elsewhere", named.join("commondir")).unwrap();
        let why = expand(&root, &FsPolicy::default(), &[], None)
            .refused
            .expect("a link refuses");
        assert!(
            !why.contains('\u{1b}') && why.contains("\\x1b"),
            "the name is escaped: {why:?}"
        );
        std::fs::remove_dir_all(root.join(".git/worktrees")).unwrap();

        std::os::unix::fs::symlink(tmp.path(), root.join(".git/worktrees")).unwrap();
        let why = expand(&root, &FsPolicy::default(), &[], None)
            .refused
            .expect("a linked worktrees directory refuses");
        assert!(why.contains("symbolic link"), "{why}");
    }

    /// More worktree entries than masks can hold refuse the launch rather than being read on.
    #[test]
    fn more_worktrees_than_masks_can_hold_refuse_the_launch() {
        let tmp = TmpDir::new();
        let Some((root, _git)) = git_project(&tmp) else {
            skip_incapable!("skipping worktree ceiling: no git on this host");
            return;
        };
        for i in 0..=MASK_MAX {
            std::fs::create_dir_all(root.join(format!(".git/worktrees/w{i}"))).unwrap();
        }
        let why = expand(&root, &FsPolicy::default(), &[], None)
            .refused
            .expect("past the ceiling");
        assert!(why.contains("more than"), "{why}");
    }

    /// A `.git`, a `.git/hooks` or a `.git/config` that is a symbolic link refuses the launch,
    /// wherever it leads, naming the link and the form sbx holds in place; `git_writable` lifts it.
    /// A `.git/config` that leads out of the project is refused rather than warned about twice.
    #[test]
    fn a_link_at_the_paths_git_reads_refuses_the_launch() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".git/config"), b"[core]\n").unwrap();
        let root = root.canonicalize().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("config"), b"[core]\n").unwrap();
        std::fs::create_dir_all(root.join("kept-hooks")).unwrap();
        std::fs::write(root.join("repo.gitconfig"), b"[core]\n").unwrap();
        let lifted = FsPolicy {
            git_writable: Some(true),
            ..FsPolicy::default()
        };
        let refused = |link: &str, instead: &str| {
            let e = expand(&root, &FsPolicy::default(), &[], None);
            let why = e.refused.expect("a link refuses");
            assert!(
                why.contains(&format!(
                    "{}` is a symbolic link",
                    root.join(link).display()
                )) && why.contains(instead),
                "{why}"
            );
            assert!(
                e.warnings.is_empty(),
                "refused, not warned about: {:?}",
                e.warnings
            );
            assert!(
                expand(&root, &lifted, &[], None).refused.is_none(),
                "git_writable lifts it"
            );
        };

        let hooks = root.join(".git/hooks");
        for target in [Path::new("../kept-hooks"), outside.as_path()] {
            std::os::unix::fs::symlink(target, &hooks).unwrap();
            refused(".git/hooks", "core.hooksPath");
            std::fs::remove_file(&hooks).unwrap();
        }

        let config = root.join(".git/config");
        std::fs::remove_file(&config).unwrap();
        let outside_config = outside.join("config");
        for target in [Path::new("../repo.gitconfig"), outside_config.as_path()] {
            std::os::unix::fs::symlink(target, &config).unwrap();
            refused(".git/config", "include.path");
            std::fs::remove_file(&config).unwrap();
        }
        std::fs::write(&config, b"[core]\n").unwrap();

        std::fs::rename(root.join(".git"), root.join("realgit")).unwrap();
        std::os::unix::fs::symlink("realgit", root.join(".git")).unwrap();
        refused(".git", "the directory it names");
    }

    /// Every refusal about git's files ends with the command that lifts the protection, an
    /// unreadable one included, so a project that needs git's files writable is told how.
    #[test]
    fn a_refusal_about_gits_files_names_the_command_that_lifts_it() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".git/config"), b"[core]\n").unwrap();
        let root = root.canonicalize().unwrap();
        let refused = || {
            let why = expand(&root, &FsPolicy::default(), &[], None)
                .refused
                .expect("refused");
            assert!(
                why.contains("`sbx config set fs.git_writable true`"),
                "{why}"
            );
        };

        std::os::unix::fs::symlink("elsewhere", root.join(".git/hooks")).unwrap();
        refused();
        std::fs::remove_file(root.join(".git/hooks")).unwrap();

        std::fs::write(root.join(".git/commondir"), "../x\n").unwrap();
        refused();
        std::fs::remove_file(root.join(".git/commondir")).unwrap();

        // root traverses whatever it likes, so an unreadable directory is no premise there.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let worktrees = root.join(".git/worktrees");
        std::fs::create_dir_all(&worktrees).unwrap();
        std::fs::set_permissions(
            &worktrees,
            std::os::unix::fs::PermissionsExt::from_mode(0o000),
        )
        .unwrap();
        let why = expand(&root, &FsPolicy::default(), &[], None).refused;
        // Restore before asserting, so a failure does not leave the fixture undeletable.
        std::fs::set_permissions(
            &worktrees,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        let why = why.expect("an unreadable worktrees directory refuses");
        assert!(
            why.contains("cannot list") && why.contains("`sbx config set fs.git_writable true`"),
            "{why}"
        );
    }

    /// A link above the directory `core.hooksPath` names, or on the way to a file git includes,
    /// refuses the launch as well: a link inside the project counts wherever the resolution meets
    /// it, including through a link outside the project that leads back in, and a resolution
    /// that meets more links than the kernel follows is refused too.
    #[test]
    fn a_link_on_the_way_to_the_hooks_path_or_an_include_refuses_the_launch() {
        let tmp = TmpDir::new();
        let Some((root, git)) = git_project(&tmp) else {
            skip_incapable!("skipping links on the way to git's files: no git on this host");
            return;
        };
        let refused_at = |link: &Path| {
            let why = expand(&root, &FsPolicy::default(), &[], None)
                .refused
                .expect("a link refuses");
            assert!(
                why.contains(&format!("{}` is a symbolic link", link.display())),
                "{why}"
            );
        };

        std::fs::create_dir_all(root.join("tools-husky/_")).unwrap();
        std::os::unix::fs::symlink("tools-husky", root.join(".husky")).unwrap();
        assert!(git(&["config", "core.hooksPath", ".husky/_"]));
        refused_at(&root.join(".husky"));
        assert!(git(&["config", "--unset", "core.hooksPath"]));

        std::fs::create_dir_all(root.join("realcfg")).unwrap();
        std::fs::write(root.join("realcfg/inc.cfg"), "").unwrap();
        std::os::unix::fs::symlink("realcfg", root.join("cfgdir")).unwrap();
        assert!(git(&["config", "include.path", "../cfgdir/inc.cfg"]));
        refused_at(&root.join("cfgdir"));

        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(root.join("cfgdir/inc.cfg"), outside.join("back-in")).unwrap();
        let back_in = outside.join("back-in");
        assert!(git(&["config", "include.path", back_in.to_str().unwrap()]));
        refused_at(&root.join("cfgdir"));

        // git refuses to read an include it cannot resolve, so the loop is met by the hooks path,
        // whose value git reports without resolving it.
        assert!(git(&["config", "--unset", "include.path"]));
        std::os::unix::fs::symlink("loop-b", outside.join("loop-a")).unwrap();
        std::os::unix::fs::symlink("loop-a", outside.join("loop-b")).unwrap();
        let looped = outside.join("loop-a");
        assert!(git(&["config", "core.hooksPath", looped.to_str().unwrap()]));
        let why = expand(&root, &FsPolicy::default(), &[], None)
            .refused
            .expect("a loop refuses");
        assert!(why.contains("more symbolic links"), "{why}");
    }

    /// The forms a link refusal names are held in place: `core.hooksPath` pointed at a directory of
    /// the tree, and a `.git/config` of its own that includes a file of the tree. Each is masked at
    /// the path git reads, and one outside the project is left alone with no refusal.
    #[test]
    fn the_forms_a_link_refusal_names_are_masked_where_git_reads_them() {
        let tmp = TmpDir::new();
        let Some((root, git)) = git_project(&tmp) else {
            skip_incapable!("skipping the forms a link refusal names: no git on this host");
            return;
        };
        std::fs::create_dir_all(root.join(".githooks")).unwrap();
        std::fs::write(root.join("repo.gitconfig"), "").unwrap();
        assert!(git(&["config", "core.hooksPath", ".githooks"]));
        assert!(git(&["config", "include.path", "../repo.gitconfig"]));
        let e = expand(&root, &FsPolicy::default(), &[], None);
        assert!(e.refused.is_none(), "{:?}", e.refused);
        for held in [".githooks", ".git/hooks", ".git/config", "repo.gitconfig"] {
            assert!(
                e.readonly.iter().any(|m| m.path == root.join(held)),
                "{held}: {:?}",
                e.readonly
            );
        }

        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("inc.cfg"), "").unwrap();
        assert!(git(&[
            "config",
            "core.hooksPath",
            outside.to_str().unwrap()
        ]));
        let inc = outside.join("inc.cfg");
        assert!(git(&["config", "include.path", inc.to_str().unwrap()]));
        let e = expand(&root, &FsPolicy::default(), &[], None);
        assert!(e.refused.is_none(), "{:?}", e.refused);
    }

    /// The reach answers where the cage writes at a host path's own name: the project first, then
    /// the last bind mounted over the path, which holds it only when it is read-write. sbx's data
    /// directory is written under other names, outside the project.
    #[test]
    fn the_reach_of_a_path_is_the_last_mount_over_it() {
        let root = PathBuf::from("/w/proj");
        let bind = |path: &str, writable| crate::config::Bind {
            path: PathBuf::from(path),
            writable,
        };
        let binds = [
            bind("/w", true),
            bind("/w/main/ro", false),
            bind("/w/proj/inner", false),
            bind("/w/main/ro/again", true),
        ];
        let reach = Reach::of(&root, &binds, Some(Path::new("/d/sbx")));
        // The bind inside the project is covered by the project's own mount.
        assert_eq!(
            reach.root_of(Path::new("/w/proj/inner/x")),
            Some(root.as_path())
        );
        assert_eq!(reach.root_of(Path::new("/w/main/x")), Some(Path::new("/w")));
        assert!(!reach.holds(Path::new("/w/main/ro/x")), "read-only there");
        assert_eq!(
            reach.root_of(Path::new("/w/main/ro/again/x")),
            Some(Path::new("/w/main/ro/again"))
        );
        assert!(!reach.holds(Path::new("/elsewhere")));
        assert!(reach.written_elsewhere(Path::new("/d/sbx/projects/h/home/hooks")));
        assert!(!reach.written_elsewhere(Path::new("/d/sbx-other")));
        // A project inside the data directory is answered for as the project.
        let inside = Reach::of(Path::new("/d/sbx/p"), &[], Some(Path::new("/d/sbx")));
        assert!(!inside.written_elsewhere(Path::new("/d/sbx/p/.git/hooks")));
        assert!(inside.written_elsewhere(Path::new("/d/sbx/other")));
    }

    /// A read-write bind that holds the global git configuration, by its name or through a link
    /// that resolves into it, is written by the cage and holds nothing: the warning names the file
    /// that is there. A read-write bind mounted after it inside it, or elsewhere, still holds, and
    /// a read-only bind holding the configuration is not written at all.
    #[test]
    fn a_read_write_bind_holding_the_global_git_configuration_holds_nothing() {
        let tmp = TmpDir::new();
        let base = tmp.path().canonicalize().unwrap();
        let (home, dots, other) = (base.join("home"), base.join("dots"), base.join("other"));
        if !crate::sandbox::binds::bind_reaches_the_cage(&home, Some(&base.join("proj"))) {
            skip_incapable!(
                "skipping the global git configuration: the fixture root is a cage mount"
            );
            return;
        }
        for dir in [&home.join("src"), &dots, &other, &base.join("home2")] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(home.join(".gitconfig"), "").unwrap();
        std::fs::write(dots.join("gitconfig"), "").unwrap();
        std::os::unix::fs::symlink(dots.join("gitconfig"), base.join("home2/.gitconfig")).unwrap();
        let read_only = crate::config::Bind {
            path: base.join("home2"),
            writable: false,
        };
        let binds = [
            rw_bind(&home),
            rw_bind(&home.join("src")),
            rw_bind(&dots),
            rw_bind(&other),
            read_only,
        ];
        let global = [
            home.join(".config/git/config"),
            home.join(".gitconfig"),
            base.join("home2/.gitconfig"),
        ];
        let reach = Reach::with_git_global(&base.join("proj"), &binds, None, &global);

        assert!(!reach.holds(&home.join("x")) && reach.writes(&home.join("x")));
        assert!(!reach.holds(&dots.join("x")), "through the link");
        assert!(reach.holds(&home.join("src/x")) && reach.holds(&other.join("x")));
        assert!(!reach.writes(&base.join("home2/x")));
        let unheld: Vec<(&Path, &Path)> = reach.unheld().collect();
        assert_eq!(
            unheld,
            vec![
                (home.as_path(), home.join(".gitconfig").as_path()),
                (dots.as_path(), base.join("home2/.gitconfig").as_path()),
            ],
            "the file that is there is the one named"
        );
    }

    /// A read-write bind at `path`, as the config's canonical binds carry it.
    fn rw_bind(path: &Path) -> crate::config::Bind {
        crate::config::Bind {
            path: path.to_path_buf(),
            writable: true,
        }
    }

    /// A read-write bind is written by the cage at its own name like the project: the directory
    /// `core.hooksPath` names there and a file git includes from there are held, with the
    /// directories above them, in a read-only project too. In a read-only bind, or under a
    /// read-only bind mounted after the read-write one, nothing is added.
    #[test]
    fn what_git_reads_in_a_read_write_bind_is_held_and_nothing_in_a_read_only_one() {
        let tmp = TmpDir::new();
        let Some((root, git)) = git_project(&tmp) else {
            skip_incapable!("skipping git's files in a bind: no git on this host");
            return;
        };
        let shared = tmp.path().canonicalize().unwrap().join("shared");
        if !crate::sandbox::binds::bind_reaches_the_cage(&shared, Some(&root)) {
            skip_incapable!("skipping git's files in a bind: the fixture root is a cage mount");
            return;
        }
        std::fs::create_dir_all(shared.join("tools")).unwrap();
        let (hooks, inc) = (
            shared.join("tools/hooks"),
            shared.join("tools/team.gitconfig"),
        );
        std::fs::write(&inc, "").unwrap();
        assert!(git(&["config", "core.hooksPath", hooks.to_str().unwrap()]));
        assert!(git(&["config", "include.path", inc.to_str().unwrap()]));

        let e = expand(&root, &FsPolicy::default(), &[rw_bind(&shared)], None);
        assert!(e.refused.is_none(), "{:?}", e.refused);
        for (held, is_dir) in [(&hooks, true), (&inc, false)] {
            assert!(
                e.readonly
                    .iter()
                    .any(|m| m.path == *held && m.is_dir == is_dir && m.builtin),
                "{}: {:?}",
                held.display(),
                e.readonly
            );
        }
        assert!(e.pins.contains(&shared.join("tools")), "{:?}", e.pins);
        // Absent at launch, so made empty in the bind before it is bound.
        create_absent_dirs(&e).unwrap();
        assert!(hooks.is_dir());
        let decoys = stage_decoys(&tmp.path().join("mask-1")).unwrap();
        let binds = agent_binds(&e, &decoys, false);
        assert!(
            binds
                .iter()
                .any(|b| b.writable && b.dest == shared.join("tools")),
            "held in the bind whatever the project's mode: {binds:?}"
        );
        assert!(
            !binds
                .iter()
                .any(|b| b.writable && b.dest.starts_with(&root)),
            "{binds:?}"
        );

        let read_only = |path: &Path| crate::config::Bind {
            path: path.to_path_buf(),
            writable: false,
        };
        for binds in [
            vec![read_only(&shared)],
            vec![rw_bind(&shared), read_only(&shared.join("tools"))],
        ] {
            let e = expand(&root, &FsPolicy::default(), &binds, None);
            assert!(e.refused.is_none(), "{:?}", e.refused);
            assert!(
                !e.readonly.iter().any(|m| m.path.starts_with(&shared)),
                "{binds:?}: {:?}",
                e.readonly
            );
        }
    }

    /// A link inside a read-write bind, on the way to the directory `core.hooksPath` names, is a
    /// name the cage could point elsewhere, and refuses the launch as one inside the project does.
    #[test]
    fn a_link_in_a_read_write_bind_on_the_way_to_the_hooks_path_refuses_the_launch() {
        let tmp = TmpDir::new();
        let Some((root, git)) = git_project(&tmp) else {
            skip_incapable!("skipping a link in a bind: no git on this host");
            return;
        };
        let shared = tmp.path().canonicalize().unwrap().join("shared");
        if !crate::sandbox::binds::bind_reaches_the_cage(&shared, Some(&root)) {
            skip_incapable!("skipping a link in a bind: the fixture root is a cage mount");
            return;
        }
        std::fs::create_dir_all(shared.join("real/hooks")).unwrap();
        std::os::unix::fs::symlink("real", shared.join("tools")).unwrap();
        let named = shared.join("tools/hooks");
        assert!(git(&["config", "core.hooksPath", named.to_str().unwrap()]));
        let why = expand(&root, &FsPolicy::default(), &[rw_bind(&shared)], None)
            .refused
            .expect("a link in the bind refuses");
        let link = shared.join("tools");
        assert!(
            why.contains(&format!("{}` is a symbolic link", link.display())),
            "{why}"
        );
        let e = expand(&root, &FsPolicy::default(), &[], None);
        assert!(e.refused.is_none(), "outside the reach: {:?}", e.refused);
    }

    /// A file git reads in sbx's data directory refuses the launch, since the cage writes there
    /// under other names and a mask at the host name would hold nothing: the directory
    /// `core.hooksPath` names, a file git includes, absent or present, and the repository a `.git`
    /// file names, a submodule's or the project's own.
    #[test]
    fn a_file_git_reads_in_sbxs_data_directory_refuses_the_launch() {
        let tmp = TmpDir::new();
        let Some((root, git)) = git_project(&tmp) else {
            skip_incapable!("skipping git's files in the data directory: no git on this host");
            return;
        };
        let data = tmp.path().canonicalize().unwrap().join("data");
        let home = data.join("projects/h/home");
        std::fs::create_dir_all(home.join("hooks")).unwrap();
        let refused_at = |path: &Path| {
            let why = expand(&root, &FsPolicy::default(), &[], Some(&data))
                .refused
                .expect("a file git reads in the data directory refuses");
            assert!(
                why.contains("sbx's data directory")
                    && why.contains(&path.display().to_string())
                    && why.contains("git_writable"),
                "{why}"
            );
        };
        let hooks = home.join("hooks");
        assert!(git(&["config", "core.hooksPath", hooks.to_str().unwrap()]));
        refused_at(&hooks);
        assert!(git(&["config", "--unset", "core.hooksPath"]));

        let inc = home.join("team.gitconfig");
        assert!(git(&["config", "include.path", inc.to_str().unwrap()]));
        refused_at(&inc);
        std::fs::write(&inc, "").unwrap();
        refused_at(&inc);
        let e = expand(&root, &FsPolicy::default(), &[], None);
        assert!(e.refused.is_none(), "{:?}", e.refused);
        assert!(git(&["config", "--unset", "include.path"]));

        std::fs::create_dir_all(data.join("modules")).unwrap();
        let repo = data.join("modules/sub");
        let separate = ["--separate-git-dir", repo.to_str().unwrap()];
        assert!(git_repo_at(&root.join("sub"), &separate) && git(&["add", "sub"]));
        refused_at(&repo);

        let worktree = tmp.path().join("linked");
        let repo = data.join("linked.git");
        let separate = ["--separate-git-dir", repo.to_str().unwrap()];
        assert!(git_repo_at(&worktree, &separate));
        let why = expand(&worktree, &FsPolicy::default(), &[], Some(&data))
            .refused
            .expect("a `.git` file naming the data directory refuses");
        assert!(
            why.contains("sbx's data directory") && why.contains(&repo.display().to_string()),
            "{why}"
        );
    }

    /// A submodule whose `.git` file names a repository in a read-write bind has that repository
    /// held like one in the project, and the end of the session follows it there: a gitlink added
    /// inside it during the session is named.
    #[test]
    fn a_submodules_repository_in_a_read_write_bind_is_held_and_watched() {
        let tmp = TmpDir::new();
        let Some((root, git)) = git_project(&tmp) else {
            skip_incapable!("skipping a submodule's repository in a bind: no git on this host");
            return;
        };
        let shared = tmp.path().canonicalize().unwrap().join("shared");
        if !crate::sandbox::binds::bind_reaches_the_cage(&shared, Some(&root)) {
            skip_incapable!(
                "skipping a submodule's repository in a bind: the fixture root is a \
                 cage mount"
            );
            return;
        }
        let repo = shared.join("modules/sub");
        std::fs::create_dir_all(shared.join("modules")).unwrap();
        let separate = ["--separate-git-dir", repo.to_str().unwrap()];
        assert!(git_repo_at(&root.join("sub"), &separate) && git(&["add", "sub"]));
        let binds = [rw_bind(&shared)];

        let e = expand(&root, &FsPolicy::default(), &binds, None);
        assert!(e.refused.is_none(), "{:?}", e.refused);
        for held in [repo.join("config"), repo.join("hooks")] {
            assert!(
                e.readonly.iter().any(|m| m.path == held && m.builtin),
                "{}: {:?}",
                held.display(),
                e.readonly
            );
        }
        let e = expand(&root, &FsPolicy::default(), &[], None);
        assert!(!e.readonly.iter().any(|m| m.path.starts_with(&shared)));

        let watch = GitWatch::start(&root, false, &binds, None).expect("a protected `.git`");
        assert!(watch.findings().is_empty(), "{:#?}", watch.findings());
        let in_sub = |args: &[&str]| {
            std::process::Command::new("git")
                .args(["-C", root.join("sub").to_str().unwrap()])
                .args(args)
                .output()
                .is_ok_and(|o| o.status.success())
        };
        assert!(git_repo_at(&root.join("sub/inner"), &[]) && in_sub(&["add", "inner"]));
        let found = watch.findings();
        assert!(
            found
                .iter()
                .any(|f| f.contains("sub/inner/.git` is a submodule's repository")),
            "{found:#?}"
        );
    }

    /// A repository at `dir` with one empty commit, made by the host's git; `false` when git is
    /// not there to make it.
    fn git_repo_at(dir: &Path, args: &[&str]) -> bool {
        let git = |extra: &[&str]| {
            std::process::Command::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@t"])
                .args(extra)
                .output()
                .is_ok_and(|o| o.status.success())
        };
        let dir = dir.to_str().unwrap();
        git(&[&["init", "-q"], args, &[dir]].concat())
            && git(&[
                "-C",
                dir,
                "commit",
                "-q",
                "--no-verify",
                "--allow-empty",
                "-m",
                "i",
            ])
    }

    /// A submodule the index names is protected like the project's own repository: its
    /// configuration and hooks, and the `.git` file in its directory, and so is a submodule of
    /// that submodule and a repository embedded in the tree. `git_writable` lifts all of it.
    #[test]
    fn a_submodules_repository_is_read_only_like_the_projects_own() {
        let tmp = TmpDir::new();
        let Some((root, git)) = git_project(&tmp) else {
            skip_incapable!("skipping submodule protection: no git on this host");
            return;
        };
        let (inner, mid) = (tmp.path().join("inner"), tmp.path().join("mid"));
        assert!(git_repo_at(&inner, &[]) && git_repo_at(&mid, &[]));
        let file = ["-c", "protocol.file.allow=always"];
        let in_mid = |args: &[&str]| {
            std::process::Command::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@t", "-C"])
                .arg(&mid)
                .args(args)
                .output()
                .is_ok_and(|o| o.status.success())
        };
        let add_inner = [
            &file[..],
            &["submodule", "add", "-q", inner.to_str().unwrap(), "in"],
        ];
        assert!(in_mid(&add_inner.concat()) && in_mid(&["commit", "-q", "-m", "in"]));
        let add_mid = [
            &file[..],
            &["submodule", "add", "-q", mid.to_str().unwrap(), "sub"],
        ];
        assert!(git(&add_mid.concat()));
        let update = [
            &file[..],
            &["submodule", "update", "-q", "--init", "--recursive"],
        ];
        assert!(git(&update.concat()));
        assert!(git_repo_at(&root.join("emb"), &[]) && git(&["add", "emb"]));

        let e = expand(&root, &FsPolicy::default(), &[], None);
        assert!(e.refused.is_none(), "{:?}", e.refused);
        for held in [
            ".git/modules/sub/config",
            ".git/modules/sub/hooks",
            "sub/.git",
            ".git/modules/sub/modules/in/config",
            ".git/modules/sub/modules/in/hooks",
            "sub/in/.git",
            "emb/.git/config",
            "emb/.git/hooks",
        ] {
            assert!(
                e.readonly
                    .iter()
                    .any(|m| m.path == root.join(held) && m.builtin),
                "{held}: {:?}",
                e.readonly
            );
        }
        let lifted = FsPolicy {
            git_writable: Some(true),
            ..FsPolicy::default()
        };
        assert!(
            expand(&root, &lifted, &[], None).is_empty(),
            "git_writable lifts it"
        );
    }

    /// Where a submodule's `.git` cannot be held to the repository git reads, the launch refuses:
    /// a link there, or a `.git` file naming a repository inside the project that does not exist.
    /// One naming a repository outside the project holds the file alone.
    #[test]
    fn a_submodules_git_that_cannot_be_held_refuses_the_launch() {
        let tmp = TmpDir::new();
        let Some((root, git)) = git_project(&tmp) else {
            skip_incapable!("skipping submodule refusals: no git on this host");
            return;
        };
        let head = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&root)
            .output()
            .unwrap();
        let head = String::from_utf8(head.stdout).unwrap();
        let gitlink = |path: &str| {
            let info = format!("160000,{},{path}", head.trim());
            assert!(git(&["update-index", "--add", "--cacheinfo", &info]));
            std::fs::create_dir_all(root.join(path)).unwrap();
        };
        let refused = || {
            expand(&root, &FsPolicy::default(), &[], None)
                .refused
                .expect("refused")
        };

        gitlink("lnk");
        std::os::unix::fs::symlink(tmp.path(), root.join("lnk/.git")).unwrap();
        assert!(refused().contains("lnk/.git` is a symbolic link"));
        std::fs::remove_file(root.join("lnk/.git")).unwrap();

        gitlink("gone");
        std::fs::write(root.join("gone/.git"), "gitdir: ../.git/modules/gone\n").unwrap();
        assert!(refused().contains("which does not exist"));
        std::fs::remove_file(root.join("gone/.git")).unwrap();

        let outside = tmp.path().join("outside-repo");
        assert!(git_repo_at(&outside, &[]));
        gitlink("out");
        let pointer = format!("gitdir: {}/.git\n", outside.display());
        std::fs::write(root.join("out/.git"), pointer).unwrap();
        let e = expand(&root, &FsPolicy::default(), &[], None);
        assert!(e.refused.is_none(), "{:?}", e.refused);
        assert!(e.readonly.iter().any(|m| m.path == root.join("out/.git")));
        assert!(
            !e.readonly.iter().any(|m| m.path.starts_with(&outside)),
            "nothing outside the project"
        );
    }

    /// The index is read in the formats git writes it in: version 4, and the longer object names of
    /// a SHA-256 repository. A split index, whose entries this does not read in full, refuses the
    /// launch where the repository shows submodules.
    #[test]
    fn the_index_is_read_in_the_formats_git_writes() {
        let tmp = TmpDir::new();
        let Some((root, git)) = git_project(&tmp) else {
            skip_incapable!("skipping index formats: no git on this host");
            return;
        };
        let source = tmp.path().join("source");
        assert!(git_repo_at(&source, &[]));
        let add = ["-c", "protocol.file.allow=always", "submodule", "add", "-q"];
        assert!(git(&[&add[..], &[source.to_str().unwrap(), "sub"]].concat()));
        let held = |root: &Path| {
            let e = expand(root, &FsPolicy::default(), &[], None);
            e.refused.is_none()
                && e.readonly
                    .iter()
                    .any(|m| m.path == root.join(".git/modules/sub/config"))
        };
        assert!(git(&["update-index", "--index-version", "4"]));
        assert!(held(&root), "version 4");
        assert!(git(&["update-index", "--split-index"]));
        let why = expand(&root, &FsPolicy::default(), &[], None)
            .refused
            .expect("a split index refuses");
        assert!(why.contains("not an index sbx reads in full"), "{why}");

        let sha = tmp.path().join("sha");
        if !git_repo_at(&sha, &["--object-format=sha256"]) {
            skip_incapable!("skipping a SHA-256 index: this git does not make one");
            return;
        }
        let sha = sha.canonicalize().unwrap();
        assert!(git_repo_at(&sha.join("emb"), &["--object-format=sha256"]));
        let add = std::process::Command::new("git")
            .args(["-C", sha.to_str().unwrap(), "add", "emb"])
            .output()
            .unwrap();
        assert!(add.status.success());
        let e = expand(&sha, &FsPolicy::default(), &[], None);
        assert!(e.refused.is_none(), "{:?}", e.refused);
        assert!(
            e.readonly
                .iter()
                .any(|m| m.path == sha.join("emb/.git/config"))
        );
    }

    /// The end of a session names a submodule's repository that was not there at launch, found in
    /// an index the cage rewrote in version 4 or in the index of a submodule held at launch, and an
    /// index it can no longer read in full. One present at launch is not named.
    #[test]
    fn the_git_watch_names_a_submodule_repository_that_appeared() {
        let tmp = TmpDir::new();
        let Some((root, git)) = git_project(&tmp) else {
            skip_incapable!("skipping the submodule watch: no git on this host");
            return;
        };
        assert!(git_repo_at(&root.join("kept"), &[]) && git(&["add", "kept"]));
        let watch =
            GitWatch::start(&root, false, &[], None).expect("a protected `.git` is watched");
        assert!(watch.findings().is_empty(), "{:#?}", watch.findings());

        assert!(git(&["update-index", "--index-version", "4"]));
        assert!(git_repo_at(&root.join("emb"), &[]) && git(&["add", "emb"]));
        let found = watch.findings();
        assert!(
            found
                .iter()
                .any(|f| f.contains("emb/.git` is a submodule's repository")),
            "{found:#?}"
        );
        assert!(
            !found.iter().any(|f| f.contains("kept/.git`")),
            "{found:#?}"
        );

        // A gitlink added inside a submodule held at launch is followed there too.
        let in_kept = |args: &[&str]| {
            std::process::Command::new("git")
                .args(["-C", root.join("kept").to_str().unwrap()])
                .args(args)
                .output()
                .is_ok_and(|o| o.status.success())
        };
        assert!(git_repo_at(&root.join("kept/inner"), &[]) && in_kept(&["add", "inner"]));
        let found = watch.findings();
        assert!(
            found
                .iter()
                .any(|f| f.contains("kept/inner/.git` is a submodule's repository")),
            "{found:#?}"
        );

        assert!(git(&["update-index", "--split-index"]));
        let found = watch.findings();
        assert!(
            found
                .iter()
                .any(|f| f.contains(".git/index` cannot be read in full")),
            "{found:#?}"
        );
    }

    /// The end of a session names what appeared in the project's git that no mount could hold: a
    /// `.git/commondir`, a `config.worktree` absent at launch, and a link where the launch refuses
    /// one. A file present at launch is not reported, and every name is escaped.
    #[test]
    fn the_git_watch_names_what_appeared_during_the_session() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        std::fs::create_dir_all(root.join(".git/worktrees/kept")).unwrap();
        std::fs::write(root.join(".git/config"), "[core]\n").unwrap();
        std::fs::write(root.join(".git/worktrees/kept/config.worktree"), "").unwrap();
        let root = root.canonicalize().unwrap();

        let watch =
            GitWatch::start(&root, false, &[], None).expect("a protected `.git` is watched");
        assert!(watch.findings().is_empty(), "nothing appeared yet");
        assert!(
            GitWatch::start(&root, true, &[], None).is_none(),
            "git_writable: nothing to watch"
        );

        std::fs::write(root.join(".git/commondir"), "../x\n").unwrap();
        std::fs::write(root.join(".git/config.worktree"), "").unwrap();
        let odd = root.join(".git/worktrees/n\u{1b}[2Jew");
        std::fs::create_dir_all(&odd).unwrap();
        std::fs::write(odd.join("config.worktree"), "").unwrap();
        std::os::unix::fs::symlink("/elsewhere", root.join(".git/worktrees/linked")).unwrap();

        let found = watch.findings();
        assert_eq!(found.len(), 4, "{found:#?}");
        assert!(found.iter().any(|f| f.contains(".git/commondir`")));
        assert!(found.iter().any(|f| f.contains(".git/config.worktree`")));
        assert!(
            found
                .iter()
                .any(|f| f.contains("\\x1b") && f.contains("config.worktree"))
        );
        assert!(
            found
                .iter()
                .any(|f| f.contains("worktrees/linked") && f.contains("symbolic link"))
        );
        assert!(
            found.iter().all(|f| !f.contains('\u{1b}')),
            "escaped: {found:#?}"
        );
        assert!(
            !found.iter().any(|f| f.contains("kept")),
            "present at launch: {found:#?}"
        );
    }

    /// A `.git` that is a file is read-only itself, and `git_writable` lifts it. The repository it
    /// names outside the project is left alone, spelled absolute or relative. One inside the
    /// project refuses the launch, present or not yet, and so does a link inside the project on
    /// the way to it. A file git would not read as a pointer names no repository.
    #[test]
    fn a_git_file_is_read_only_and_one_naming_a_repository_inside_the_project_refuses() {
        let tmp = TmpDir::new();
        let root = project(&tmp).canonicalize().unwrap();
        let git = root.join(".git");
        let lifted = FsPolicy {
            git_writable: Some(true),
            ..FsPolicy::default()
        };
        let outside = tmp.path().join("main/.git/worktrees/w");
        std::fs::create_dir_all(&outside).unwrap();
        let held_alone = |e: &Expanded| {
            assert!(e.refused.is_none(), "{:?}", e.refused);
            let ro: Vec<(&Path, bool, bool)> = e
                .readonly
                .iter()
                .map(|m| (m.path.as_path(), m.is_dir, m.builtin))
                .collect();
            assert_eq!(ro, vec![(git.as_path(), false, true)]);
        };

        for pointer in [
            format!("gitdir: {}\n", outside.display()),
            "gitdir: ../main/.git/worktrees/w\r\n".to_string(),
        ] {
            std::fs::write(&git, pointer).unwrap();
            held_alone(&expand(&root, &FsPolicy::default(), &[], None));
            assert!(
                expand(&root, &lifted, &[], None).is_empty(),
                "git_writable lifts it"
            );
        }

        std::fs::create_dir_all(root.join("repo")).unwrap();
        for pointer in ["gitdir: repo\n", "gitdir: not-there-yet"] {
            std::fs::write(&git, pointer).unwrap();
            let why = expand(&root, &FsPolicy::default(), &[], None)
                .refused
                .expect("a repository inside the project refuses");
            assert!(
                why.contains("names a repository inside the project"),
                "{why}"
            );
            assert!(expand(&root, &lifted, &[], None).refused.is_none());
        }

        std::os::unix::fs::symlink(&outside, root.join("via")).unwrap();
        std::fs::write(&git, "gitdir: via\n").unwrap();
        let why = expand(&root, &FsPolicy::default(), &[], None)
            .refused
            .expect("a link on the way refuses");
        assert!(why.contains("via` is a symbolic link"), "{why}");

        std::fs::write(&git, "not a pointer\n").unwrap();
        held_alone(&expand(&root, &FsPolicy::default(), &[], None));
    }

    #[test]
    fn deny_wins_over_readonly_where_they_meet() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let e = expand(
            &root,
            &policy(&["secrets/"], &["secrets/token", "main.rs"]),
            &[],
            None,
        );
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
            &[],
            None,
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
        let e = expand(&root, &policy(&["secrets/token"], &["secrets/"]), &[], None);
        assert_eq!(
            e.denied.len(),
            1,
            "the file mask survives a readonly parent"
        );
        assert_eq!(e.readonly.len(), 1);
        let binds = agent_binds(&e, &decoys, true);
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
        let e = expand(&root, &policy(&["prod.key"], &[]), &[], None);
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
        let e = expand(
            &root,
            &policy(&[], &["certs/server.pem", "main.rs"]),
            &[],
            None,
        );
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
        let e = expand(&root, &policy(&["many/*.key"], &[]), &[], None);
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
        let e = expand(
            &root,
            &policy(&["prod.key", "secrets/"], &["main.rs"]),
            &[],
            None,
        );
        let binds = agent_binds(&e, &decoys, true);
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

    /// Every directory between the project root and a mask is held in place, shallow to deep, and
    /// before any mask: a mask's path then keeps naming the file it protects for the host's git
    /// after the session and for the next launch. The built-in git masks count as masks.
    #[test]
    fn each_directory_above_a_mask_is_held_in_place_before_the_masks() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        std::fs::create_dir_all(root.join(".git/hooks")).unwrap();
        std::fs::write(root.join(".git/config"), b"[core]\n").unwrap();
        std::fs::create_dir_all(root.join("config/sub")).unwrap();
        std::fs::write(root.join("config/sub/prod.key"), b"KEY").unwrap();
        let decoys = stage_decoys(&tmp.path().join("mask-1")).unwrap();

        let e = expand(
            &root,
            &policy(&["config/sub/prod.key", "prod.key"], &[]),
            &[],
            None,
        );
        assert!(e.refused.is_none(), "{:?}", e.refused);
        assert_eq!(
            e.pins,
            vec![
                root.join(".git"),
                root.join("config"),
                root.join("config/sub")
            ],
            "each directory above a mask, the project root excepted, shallow to deep"
        );
        let binds = agent_binds(&e, &decoys, true);
        let (held, masks) = binds.split_at(e.pins.len());
        assert!(
            held.iter()
                .zip(&e.pins)
                .all(|(b, dir)| b.writable && b.src == *dir && b.dest == *dir),
            "each held directory is bound over itself read-write, first: {binds:?}"
        );
        assert!(
            masks.iter().all(|b| !b.writable),
            "every mask comes after them: {binds:?}"
        );
    }

    /// Inside a read-only directory mask nothing can be renamed already, and a read-write bind
    /// there would reopen the directory to writes, so no directory at or under one is held. A mask
    /// elsewhere in the same policy still has its own held.
    #[test]
    fn no_directory_is_held_at_or_under_a_read_only_directory() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        std::fs::create_dir_all(root.join("config/sub")).unwrap();
        std::fs::write(root.join("config/sub/prod.key"), b"KEY").unwrap();

        let e = expand(
            &root,
            &policy(&["config/sub/prod.key", "certs/server.pem"], &["config/"]),
            &[],
            None,
        );
        assert!(e.refused.is_none(), "{:?}", e.refused);
        assert_eq!(e.denied.len(), 2, "both files are closed");
        assert_eq!(
            e.pins,
            vec![root.join("certs")],
            "nothing held inside `config/`, which is read-only"
        );
    }

    /// A project mounted read-only (sbx's own control plane) has nothing to rename, and a
    /// read-write bind of one of its directories would reopen it to writes: no held directory is
    /// emitted there, and the masks still are.
    #[test]
    fn a_read_only_project_gets_no_read_write_bind() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let decoys = stage_decoys(&tmp.path().join("mask-1")).unwrap();
        let e = expand(&root, &policy(&["certs/server.pem"], &[]), &[], None);
        assert_eq!(e.pins, vec![root.join("certs")]);

        let binds = agent_binds(&e, &decoys, false);
        assert_eq!(binds.len(), 1, "the mask alone: {binds:?}");
        assert!(binds.iter().all(|b| !b.writable), "{binds:?}");
    }

    /// The held directories are mounts, and the ceiling counts mounts: a policy whose masks alone
    /// fit is refused once the directories above them are counted.
    #[test]
    fn the_mask_ceiling_counts_the_held_directories() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let entries: Vec<String> = (0..MASK_MAX / 2 + 1)
            .map(|i| {
                let dir = root.join(format!("d{i}"));
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("f.key"), b"x").unwrap();
                format!("d{i}/f.key")
            })
            .collect();
        let entries: Vec<&str> = entries.iter().map(String::as_str).collect();
        let e = expand(&root, &policy(&entries, &[]), &[], None);
        assert!(e.denied.len() < MASK_MAX, "the masks alone fit");
        assert!(
            e.refused.as_ref().is_some_and(|r| r.contains("ceiling")),
            "with their held directories they do not: {:?}",
            e.refused
        );
    }

    #[test]
    fn a_task_sees_every_mask_it_did_not_unmask() {
        let tmp = TmpDir::new();
        let root = project(&tmp);
        let decoys = stage_decoys(&tmp.path().join("mask-1")).unwrap();
        // `readonly` is not carried into a task cage: the project is bound read-only there already.
        let e = expand(
            &root,
            &policy(&["prod.key", "certs/*.pem"], &["main.rs"]),
            &[],
            None,
        );

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
        let e = expand(&root, &policy(&["prod.key"], &[]), &[], None);
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
        let e = expand(&root, &policy(&["secrets/"], &[]), &[], None);
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

        // What must yield `None` rather than a wrong answer: not an index, a version-2 layout
        // labelled version 4, whose paths it does not compress, a truncated one.
        assert!(parse_git_index(b"not an index at all").is_none());
        let mut v4 = data.clone();
        v4[4..8].copy_from_slice(&4u32.to_be_bytes());
        assert!(parse_git_index(&v4).is_none(), "not version 4's layout");
        assert!(parse_git_index(&data[..20]).is_none(), "truncated");
    }

    /// A version-4 index writes each path as the length it strips from the previous one and the
    /// rest, unpadded, and the mode tells a gitlink from a file.
    #[test]
    fn the_git_index_parse_reads_version_4_and_the_mode() {
        fn entry(strip: u8, suffix: &str, mode: u32) -> Vec<u8> {
            let mut e = vec![0u8; 60];
            e[24..28].copy_from_slice(&mode.to_be_bytes());
            e.extend_from_slice(&(suffix.len() as u16).to_be_bytes());
            e.push(strip);
            e.extend_from_slice(suffix.as_bytes());
            e.push(0);
            e
        }
        let mut v4 = b"DIRC".to_vec();
        v4.extend_from_slice(&4u32.to_be_bytes());
        v4.extend_from_slice(&3u32.to_be_bytes());
        v4.extend(entry(0, "sub/a.txt", 0o100644));
        v4.extend(entry(5, "b.txt", 0o100644));
        v4.extend(entry(9, "vendor/lib", GITLINK_MODE));
        let entries =
            parse_git_index_entries(&v4, SHA1_LEN).expect("a well-formed v4 index parses");
        let read: Vec<(String, u32)> = entries
            .iter()
            .map(|e| (String::from_utf8_lossy(&e.path).into_owned(), e.mode))
            .collect();
        assert_eq!(
            read,
            vec![
                ("sub/a.txt".to_string(), 0o100644),
                ("sub/b.txt".to_string(), 0o100644),
                ("vendor/lib".to_string(), GITLINK_MODE),
            ]
        );

        // A strip longer than the previous path is not an index git wrote.
        let mut bad = v4[..12].to_vec();
        bad[8..12].copy_from_slice(&1u32.to_be_bytes());
        bad.extend(entry(3, "x", 0o100644));
        assert!(parse_git_index_entries(&bad, SHA1_LEN).is_none());
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

        let warned = expand(&root, &policy(&["prod.key"], &[]), &[], None).warnings;
        assert!(
            warned
                .iter()
                .any(|w| w.contains("update-index --skip-worktree prod.key")),
            "the warning has to carry the cure, not just the problem: {warned:?}"
        );
        // An untracked mask in the same repository says nothing.
        let quiet = expand(&root, &policy(&["secrets/"], &[]), &[], None).warnings;
        assert!(
            !quiet.iter().any(|w| w.contains("update-index")),
            "{quiet:?}"
        );
    }
}
