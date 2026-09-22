//! The ergonomics tripwire that tells a user a `[[binds]]` entry will not behave as written.
//!
//! A config bind whose destination *nests* with one of the cage's own structural mounts is not
//! reconciled the way an exact collision is: a descendant is mounted over and vanishes, an ancestor
//! exposes the host directory around sbx's own files. Neither is refused — the `binds` field is
//! trusted-only, so this is guidance rather than a control — and neither is visible from the
//! resulting cage, which is why it is said at validation time instead.
//!
//! Nothing here produces a mount. The warnings are prose read at validation time, one of them
//! ([`unestablishable_bind_warning`]) also dropping the bind it names; the one thing a launch reads
//! is [`bind_reaches_the_cage`], the same shadowing asked as a predicate for the in-cage contract.
//! The list all of them read, [`super::STRUCTURAL_DESTS`], stays with the mount plan that declares
//! it.

use super::{
    CAGE_CA_BUNDLE, DISTRO_SUPPLIED, LAUNCHER_DESTS, STRUCTURAL_DESTS, STRUCTURAL_SYMLINKS,
};
use std::path::Path;

/// How a config bind's destination overlaps a structural mount destination.
enum Nesting {
    /// The bind sits at or under the structural path: the cage mounts over it, so the bind is
    /// shadowed and never appears inside.
    Shadowed,
    /// The bind contains the structural path: the cage mounts that path over part of the bound
    /// directory, so that sub-path inside the cage is sbx's, not the bind's.
    Contains,
}

/// If the canonical config-bind destination `dest` *nests* with a fixed structural mount
/// destination — it is a strict ancestor or descendant of one — return that structural path and
/// the relationship. An *exact* match is deliberately not reported: that collision is reconciled
/// correctly by [`super::assemble`] (the structural mount wins — the control that stops a config
/// bind displacing `/nix`). A nesting overlap is *not* reconciled — a descendant is shadowed by
/// the later mount and vanishes; an ancestor over-exposes the host directory around the
/// structural files — so it is the footgun worth surfacing.
fn structural_nesting_conflict(dest: &Path) -> Option<(&'static str, Nesting)> {
    let nesting = |s: &'static str| {
        let structural = Path::new(s);
        if dest == structural {
            None
        } else if dest.starts_with(structural) {
            Some((s, Nesting::Shadowed))
        } else if structural.starts_with(dest) {
            Some((s, Nesting::Contains))
        } else {
            None
        }
    };
    if let Some(hit) = STRUCTURAL_DESTS.iter().copied().find_map(nesting) {
        return Some(hit);
    }
    // The launcher's own destinations, mounted after the config binds like the structural ones and
    // shadowing a bind the same way — but with the exact match reported rather than passed over.
    // For a structural mount that collision is the control working (a config bind must not displace
    // `/nix`), and the user who wrote it learns nothing from being told. For one of these it is the
    // opposite: nobody writes `[[binds]] path = "/run/sbx-pulse"` meaning "let sbx replace this",
    // and what they get is a bind that does nothing, silently. See [`super::LAUNCHER_DESTS`].
    LAUNCHER_DESTS.iter().copied().find_map(|s| {
        if dest == Path::new(s) {
            Some((s, Nesting::Shadowed))
        } else {
            nesting(s)
        }
    })
}

/// Whether a config bind at canonical `dest` is what the cage finds at that path, or `false` when a
/// mount the launch emits after the config binds replaces it: the project, at or under its root,
/// and a structural or launcher destination, at or under it.
///
/// For the in-cage contract, which must not describe a bind the cage never sees. A read-only bind
/// inside the project is covered by the project's read-write mount, so listing it as refusing a
/// write would tell a process the opposite of what the mount does. The shadowing is the one
/// [`structural_nesting_warning`] names host-side, asked here as a yes or no; the exact collision
/// that warning passes over is included, since there the structural mount is what the cage finds.
///
/// `project` is the canonical project root, as for the warning.
pub(crate) fn bind_reaches_the_cage(dest: &Path, project: Option<&Path>) -> bool {
    project_over(dest, project).is_none()
        && !STRUCTURAL_DESTS
            .iter()
            .chain(LAUNCHER_DESTS)
            .any(|s| dest.starts_with(s))
}

/// A warning when a config bind at canonical `dest` cannot be established, or `None` when it can.
/// The caller drops the bind on `Some`: a launch carrying it would fail in bwrap, before the cage
/// exists, with a message naming a path the user never wrote.
///
/// The case is a bind that **contains** one of sbx's own mounts it cannot make room for. sbx
/// mounts after the config binds, so each of its destinations under a bind has to be placed inside
/// the bound directory: a missing file or directory there must be created, which a read-only bind
/// refuses, and a symlink ([`STRUCTURAL_SYMLINKS`]) has to be created too, or replace an existing
/// entry, which bwrap refuses outright. The two binds a user most plausibly writes are both of this
/// shape: `/etc/ssl` holds sbx's `ca-bundle.crt`, which a Debian host does not carry, and `/etc`
/// holds the `/etc/localtime` link.
///
/// Dropped rather than refused, because that is the failure the `binds` field already has: fewer
/// binds, never a wider exposure, and the launch goes ahead. A declared distribution supplies the
/// paths in [`DISTRO_SUPPLIED`] itself, so `distro` takes them out of the question. Only the fixed
/// structural mounts are asked about: the [`LAUNCHER_DESTS`] are conditional, and dropping a bind
/// over one on a launch that does not make it would refuse something that works.
///
/// A **writable** bind is dropped for a link, which fails in any mode since bwrap refuses to
/// replace an existing entry, and for a missing mountpoint the host will not let this uid create
/// ([`Room::Missing`]). One it will is created in the host directory itself (the write-through the
/// ancestor note of [`structural_nesting_warning`] names), and the bind is kept.
pub(crate) fn unestablishable_bind_warning(
    dest: &Path,
    writable: bool,
    distro: bool,
) -> Option<String> {
    let blocking = blocking_dest(dest, writable, distro, host_room)?;
    Some(dropped_note(
        dest,
        blocking,
        STRUCTURAL_SYMLINKS.contains(&blocking),
    ))
}

/// The launch-time counterpart of [`unestablishable_bind_warning`], for the destinations the
/// launcher adds on this launch only (the audio socket, the desktop portal, the GPU bridge, all
/// under `/run`). Whether one is mounted is decided by the posture and by the hardware found at the
/// launch, so it cannot be asked where the configuration is folded: a `/run` bind works on a launch
/// that mounts none of them and fails on one that mounts any. `mounted` is this launch's own list.
///
/// A missing mountpoint is the one case, read by [`Room`] as for the structural mounts; the
/// launcher mounts no link. A destination under a structural mount that itself lies inside the bind
/// is made in that mount rather than in the bind, so it blocks nothing.
pub(crate) fn launch_unestablishable_bind_warning<'a>(
    dest: &Path,
    writable: bool,
    mounted: impl IntoIterator<Item = &'a Path>,
) -> Option<String> {
    let blocking = blocked_launcher_dest(dest, writable, mounted, host_room)?;
    Some(dropped_note(dest, &blocking.display().to_string(), false))
}

/// The pure core of [`launch_unestablishable_bind_warning`], with the host taken as a closure.
pub(super) fn blocked_launcher_dest<'a>(
    dest: &Path,
    writable: bool,
    mounted: impl IntoIterator<Item = &'a Path>,
    room: impl Fn(&Path) -> Room,
) -> Option<&'a Path> {
    mounted.into_iter().find(|&m| {
        m != dest && m.starts_with(dest) && !covered_between(dest, m) && room(m).blocks(writable)
    })
}

/// What the host holds at a path sbx will mount on, which decides whether a bind above it can make
/// room: bwrap creates a missing mountpoint inside the bound directory, as this uid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Room {
    /// An entry is already there.
    Present,
    /// Nothing is there, and this uid may write the nearest directory that exists above it.
    Creatable,
    /// Nothing is there, and the nearest directory that exists above it refuses this uid a write:
    /// root-owned, or on a read-only mount.
    Missing,
}

impl Room {
    /// Whether a bind of the given mode cannot hold a mountpoint here. A read-only bind cannot
    /// create anything, whatever the host would allow; a writable one creates what the host lets
    /// it.
    fn blocks(self, writable: bool) -> bool {
        match self {
            Room::Present => false,
            Room::Creatable => !writable,
            Room::Missing => true,
        }
    }
}

/// What this host holds at `p`, asked of the kernel ([`crate::pathfind::access_ok`]) rather than
/// read from mode bits, so ownership, ACLs and a read-only mount all count.
fn host_room(p: &Path) -> Room {
    if p.symlink_metadata().is_ok() {
        return Room::Present;
    }
    let nearest = p.ancestors().skip(1).find(|a| a.symlink_metadata().is_ok());
    match nearest {
        Some(dir) if crate::pathfind::access_ok(dir, libc::W_OK) => Room::Creatable,
        _ => Room::Missing,
    }
}

/// Whether a structural mount lies strictly inside the bind at `dest` and at or above `inner`, in
/// which case `inner`'s mountpoint is made in that mount rather than in the bind.
fn covered_between(dest: &Path, inner: &Path) -> bool {
    STRUCTURAL_DESTS
        .iter()
        .map(Path::new)
        .any(|s| s != dest && s != inner && s.starts_with(dest) && inner.starts_with(s))
}

/// The note naming a bind dropped because it holds `blocking`, one of sbx's own mounts it cannot
/// make room for; `link` says whether that mount is a link rather than a missing path.
fn dropped_note(dest: &Path, blocking: &str, link: bool) -> String {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let shown = elided(dest, home.as_deref());
    let why = if link {
        "a link the sandbox creates there, which cannot be placed inside a bind"
    } else {
        "a path the sandbox mounts there, which this host does not have and which cannot be \
         created inside the bind"
    };
    let ca_note = if blocking == CAGE_CA_BUNDLE {
        "; the cage's TLS does not need it, since sbx binds its own CA bundle"
    } else {
        ""
    };
    format!(
        "bind `{shown}` is dropped: it contains `{blocking}`, {why}, so a launch could not \
         establish it. Bind a narrower path beside it instead{ca_note}"
    )
}

/// The pure core of [`unestablishable_bind_warning`]: the first structural destination strictly
/// under `dest` that a bind there cannot make room for, given `room`, which says what the host
/// holds at a path. Taken as a closure so the rule is exercised without a host.
pub(super) fn blocking_dest(
    dest: &Path,
    writable: bool,
    distro: bool,
    room: impl Fn(&Path) -> Room,
) -> Option<&'static str> {
    STRUCTURAL_DESTS.iter().copied().find(|&s| {
        let structural = Path::new(s);
        structural != dest
            && structural.starts_with(dest)
            && !(distro && DISTRO_SUPPLIED.contains(&s))
            && !covered_between(dest, structural)
            && (STRUCTURAL_SYMLINKS.contains(&s) || room(structural).blocks(writable))
    })
}

/// The project root when `dest` is at or under it, which the project's own mount, emitted after
/// every config bind, then covers. One definition for the warning and for the predicate, so the
/// contract never lists a bind the warning calls ineffective.
fn project_over<'a>(dest: &Path, project: Option<&'a Path>) -> Option<&'a Path> {
    project.filter(|p| dest.starts_with(p))
}

/// A bind path as a nesting note names it: the host home written `~`, everything else verbatim.
///
/// These notes reach `sbx config show`'s compact view, whose contract is counts by default and
/// expansion only under `--details`, and that view is what a user pastes into an issue or a support
/// channel. The home prefix is both the expansion the contract rules out and the segment that
/// identifies a machine and its user, so it is the segment that goes; the rest of the path is what
/// the note is *about* and stays, or the note could not be acted on.
///
/// `home` is passed rather than read here so the rule is a pure function of its inputs and can be
/// exercised without an ambient environment. A `home` of `/` is left alone: it is a prefix of every
/// absolute path, so eliding it would replace the whole tree with `~`.
pub(super) fn elided(path: &Path, home: Option<&Path>) -> String {
    let verbatim = || path.display().to_string();
    let Some(home) = home.filter(|h| h.parent().is_some()) else {
        return verbatim();
    };
    match path.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => verbatim(),
    }
}

/// A warning when a config bind's canonical destination `dest` nests with one of the cage's own
/// structural mounts, or `None` when it does not. `writable` marks a `mode = "rw"` bind, which the
/// `Contains` case flags specially: a read-write ancestor bind grants the cage write-through to the
/// host files around the structural mount. The `binds` field is trusted-only, so this is an
/// ergonomics tripwire (the launch does not drop the bind), not a security control — it tells the
/// user their bind will not behave as a naive reading suggests.
pub(crate) fn structural_nesting_warning(
    dest: &Path,
    writable: bool,
    project: Option<&Path>,
) -> Option<String> {
    // Read once for every note this call may produce, so the three renderings can never disagree
    // on how a path is shown.
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let shown = elided(dest, home.as_deref());
    // The project is a structural mount too — it is emitted with them, after every config bind —
    // but its path is a per-launch value rather than a constant, so it cannot live in the list
    // above. Only the shadowed direction is worth a word. A bind that *contains* the project is
    // the ordinary case (a bind of `$HOME`), and the project still lands correctly inside it.
    //
    // An exact collision warns here where it does not for the constants, and that difference is
    // the point: `[[binds]] path = "<project>", mode = "ro"` reads as making the project
    // read-only, and what actually happens is that the project's own read-write mount replaces it.
    // A bind that does the opposite of what it says is worth more than a bind that does nothing.
    if let Some(project) = project_over(dest, project) {
        let what = if dest == project {
            "is the project itself".to_string()
        } else {
            "sits inside the project".to_string()
        };
        return Some(format!(
            "bind `{shown}` {what}, which the cage mounts after it and over it — the bind has no \
             effect, whatever its mode. To narrow a path inside the project, use an `[fs] deny` \
             mask: those are applied after the project rather than before it"
        ));
    }
    structural_nesting_conflict(dest).map(|(structural, nesting)| match nesting {
        Nesting::Shadowed => {
            // A `/dev/*` path is the common case worth steering: a plain bind of a device node is
            // both shadowed here *and* (were it not) `nodev` — visible but unusable. `[devices]` is
            // the field that actually exposes a host device with device access.
            let dev_hint = if structural == "/dev" {
                " — to expose a host device with device access, use `[devices]` instead"
            } else {
                ""
            };
            format!(
                "bind `{shown}` sits at or under the sandbox's own mount `{structural}` — the cage mounts \
                 over it, so the bind is shadowed and will not appear inside{dev_hint}"
            )
        }
        Nesting::Contains => {
            let write_note = if writable {
                " — and being read-write, the cage can write through to the host files around it"
            } else {
                ""
            };
            format!(
                "bind `{shown}` contains the sandbox's own mount `{structural}` — the cage mounts that \
                 path over part of it, so `{structural}` inside the cage is sbx's, not your \
                 bind's{write_note}"
            )
        }
    })
}
