//! The ergonomics tripwire that tells a user a `[[binds]]` entry will not behave as written.
//!
//! A config bind whose destination *nests* with one of the cage's own structural mounts is not
//! reconciled the way an exact collision is: a descendant is mounted over and vanishes, an ancestor
//! exposes the host directory around sbx's own files. Neither is refused — the `binds` field is
//! trusted-only, so this is guidance rather than a control — and neither is visible from the
//! resulting cage, which is why it is said at validation time instead.
//!
//! Prose only: nothing here is reached from a launch, and nothing here produces a mount. The list
//! it reads, [`super::STRUCTURAL_DESTS`], stays with the mount plan that declares it.

use super::STRUCTURAL_DESTS;
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
    STRUCTURAL_DESTS.iter().find_map(|s| {
        let structural = Path::new(s);
        if dest == structural {
            None
        } else if dest.starts_with(structural) {
            Some((*s, Nesting::Shadowed))
        } else if structural.starts_with(dest) {
            Some((*s, Nesting::Contains))
        } else {
            None
        }
    })
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
    // The project is a structural mount too — it is emitted with them, after every config bind —
    // but its path is a per-launch value rather than a constant, so it cannot live in the list
    // above. Only the shadowed direction is worth a word. A bind that *contains* the project is
    // the ordinary case (a bind of `$HOME`), and the project still lands correctly inside it.
    //
    // An exact collision warns here where it does not for the constants, and that difference is
    // the point: `[[binds]] path = "<project>", mode = "ro"` reads as making the project
    // read-only, and what actually happens is that the project's own read-write mount replaces it.
    // A bind that does the opposite of what it says is worth more than a bind that does nothing.
    if let Some(project) = project
        && dest.starts_with(project)
    {
        let what = if dest == project {
            "is the project itself".to_string()
        } else {
            "sits inside the project".to_string()
        };
        return Some(format!(
            "bind `{}` {what}, which the cage mounts after it and over it — the bind has no \
             effect, whatever its mode. To narrow a path inside the project, use an `[fs] deny` \
             mask: those are applied after the project rather than before it",
            dest.display()
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
                "bind `{}` sits at or under the sandbox's own mount `{structural}` — the cage mounts \
                 over it, so the bind is shadowed and will not appear inside{dev_hint}",
                dest.display()
            )
        }
        Nesting::Contains => {
            let write_note = if writable {
                " — and being read-write, the cage can write through to the host files around it"
            } else {
                ""
            };
            format!(
                "bind `{}` contains the sandbox's own mount `{structural}` — the cage mounts that \
                 path over part of it, so `{structural}` inside the cage is sbx's, not your \
                 bind's{write_note}",
                dest.display()
            )
        }
    })
}
