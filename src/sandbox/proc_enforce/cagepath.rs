//! What host path names the object a cage's syscall named.
//!
//! Resolution through `/proc/<pid>/root`, `/cwd` and `/fd/<n>`; the `self` / `thread-self`
//! rewrite; the `/dev/stdout`-class link chase; and the two `/proc/<pid>/status` parsers those
//! need. One question answered in one place, touching neither policy nor the content lens.

use std::path::PathBuf;

/// Replace the shortest prefix of `path` that is a symlink with what it points at.
///
/// Left to right rather than whole-path, because the link is not always the last component:
/// `/dev/fd/1` is not one, `/dev/fd` is. Reading the whole path would leave that intermediate link
/// to the kernel, which resolves what it points at against *this* process.
///
/// Only an absolute target ends the search with an answer. A relative one names something the
/// ordinary walk already reaches correctly, and stopping there keeps this from turning into a
/// resolution of its own.
pub(super) fn splice_first_link(pid: u32, dirfd: libc::c_int, path: &str) -> Option<String> {
    let cuts = path
        .match_indices('/')
        .map(|(at, _)| at)
        .filter(|&at| at > 0)
        .chain(std::iter::once(path.len()));
    for cut in cuts {
        let Ok(target) = std::fs::read_link(open_target_path(pid, dirfd, &path[..cut])) else {
            continue;
        };
        let target = target.to_str()?;
        if !target.starts_with('/') {
            return None;
        }
        return Some(format!("{target}{}", &path[cut..]));
    }
    None
}

/// The caller's own `/proc` entry, when a path arrives there through a link rather than naming it.
///
/// `/dev/stdout`, `/dev/stderr`, `/dev/stdin` and `/dev/fd` are links into `/proc/self/fd`. Nothing
/// in the name the cage wrote says `self`, so the rewriting that handles the spelled-out form cannot
/// act on them, and a kernel asked to follow them resolves `self` against whoever is asking — this
/// process. The links are therefore read here rather than followed.
///
/// The hop count only has to outlast what a `/dev` entry uses; the kernel gives up at forty.
pub(super) fn proc_self_behind_a_link(pid: u32, dirfd: libc::c_int, path: &str) -> Option<String> {
    let mut here = splice_first_link(pid, dirfd, path)?;
    for _ in 0..8 {
        if caller_proc_path(pid, &here).is_some() {
            return Some(here);
        }
        here = splice_first_link(pid, dirfd, &here)?;
    }
    None
}

/// The caller's own numbers as its **cage** spells them.
///
/// `status` lists a task's id in each pid namespace it belongs to, outermost first, so the last
/// field is the one the cage's own `/proc` uses. Both are needed: `self` names the thread group and
/// `thread-self` names the thread inside it.
pub(super) fn caller_ids_in_cage(pid: u32) -> Option<(u32, u32)> {
    innermost_ids(&std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?)
}

/// The umask the caller creates files under, as its own `status` reports it.
pub(super) fn caller_umask(pid: u32) -> Option<u32> {
    umask_of(&std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?)
}

/// The `Umask` line of a `status` file, read as the octal it is written in.
///
/// Apart from the read so the parse can be pinned on a literal, like [`innermost_ids`] next door.
pub(super) fn umask_of(status: &str) -> Option<u32> {
    u32::from_str_radix(
        status
            .lines()
            .find_map(|line| line.strip_prefix("Umask:"))?
            .trim(),
        8,
    )
    .ok()
}

/// The innermost `NStgid`/`NSpid` a `status` file carries.
///
/// Apart from the read so that the shape it parses can be pinned on a literal. The line a cage
/// produces carries two numbers and the file this process reads carries one, so the case that
/// matters here is the one a host cannot show by reading its own.
pub(super) fn innermost_ids(status: &str) -> Option<(u32, u32)> {
    let innermost = |field: &str| -> Option<u32> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(field))?
            .split_whitespace()
            .next_back()?
            .parse()
            .ok()
    };
    Some((innermost("NStgid:")?, innermost("NSpid:")?))
}

/// Rewrite a path that names `self` or `thread-self` into one that names the caller.
///
/// Those two are not ordinary entries: the kernel answers them with the number of whoever is
/// performing the lookup, in the pid namespace the `/proc` being walked belongs to. A supervisor
/// walking the cage's `/proc` is in neither, so it finds nothing — and the cage, whose open would
/// have succeeded, is told the file is not there.
///
/// The caller is who the path means, and it can be named outright. The result is spelled the way the
/// **cage** spells it, so the walk stays on the cage's own `/proc` mount and the descriptor handed
/// over is one the cage could have opened itself.
///
/// Only a path that names them outright is rewritten. A link the cage plants to one of them is
/// followed by the kernel against this process's root instead, and is refused rather than served —
/// the same answer, reached by [`super::open_lens::vouched_probe`] rather than here.
pub(super) fn caller_proc_path(pid: u32, path: &str) -> Option<String> {
    let (rest, thread) = match path.strip_prefix("/proc/self") {
        Some(rest) => (rest, false),
        None => (path.strip_prefix("/proc/thread-self")?, true),
    };
    // `/proc/selfish` is not `/proc/self`.
    if !rest.is_empty() && !rest.starts_with('/') {
        return None;
    }
    let (tgid, tid) = caller_ids_in_cage(pid)?;
    Some(if thread {
        format!("/proc/{tgid}/task/{tid}{rest}")
    } else {
        format!("/proc/{tgid}{rest}")
    })
}

/// The host-side path naming what a cage's `openat(dirfd, path, …)` is about to open.
///
/// The supervisor runs outside the cage's mount namespace, so a path the cage wrote means something
/// else — or nothing — applied to the host root. Every form is therefore resolved through the
/// target's own `/proc` links, which the kernel resolves in *the target's* namespace:
///
/// - an absolute path, through `/proc/<pid>/root`;
/// - a relative path against `AT_FDCWD`, through `/proc/<pid>/cwd`;
/// - a relative path against a directory descriptor, through `/proc/<pid>/fd/<dirfd>`.
///
/// Concatenated rather than [`PathBuf::push`]ed, because pushing an absolute path *replaces* the
/// prefix — which would silently turn a cage path into the supervisor's own view of it.
///
/// Pure construction: whether the result resolves, and to what, is what the caller's `open` finds
/// out. Like [`super::target::read_exec_path`], nothing here closes the TOCTOU window on an
/// *allow* — the path can be re-pointed after it is read, which is why only a refusal is sound
/// (module header).
pub(super) fn open_target_path(pid: u32, dirfd: libc::c_int, path: &str) -> PathBuf {
    if path.starts_with('/') {
        // `self` and `thread-self` mean the caller, and mean it only to whoever resolves them; a
        // walk from here would resolve them to this process, which is in neither of the cage's
        // namespaces. Named outright instead, so the walk reaches the caller's own entry.
        let named = caller_proc_path(pid, path);
        let path = named.as_deref().unwrap_or(path);
        return PathBuf::from(format!("/proc/{pid}/root{path}"));
    }
    let base = if dirfd == libc::AT_FDCWD {
        format!("/proc/{pid}/cwd")
    } else {
        format!("/proc/{pid}/fd/{dirfd}")
    };
    // A relative path is joined normally: it cannot take over the prefix.
    PathBuf::from(base).join(path)
}
