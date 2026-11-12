//! Where a project's runtime state lives on the host, and the identity it is keyed by.
//!
//! A different question from "what does the cage see": nothing here names an in-cage destination,
//! and nothing here produces a mount. It is nevertheless the part of [`super`] the rest of the crate
//! depends on most — the per-project id keys the runtime tree that the store, the pin locks and
//! housekeeping all address, so a module with no interest in binds still reaches through this one.
//!
//! The home and the synthetic `/etc` are always allocated as siblings, which is what the parent's
//! integrity note rests on: the identity files must sit outside every read-write bind.

use std::io;
use std::path::{Path, PathBuf};

/// Host-side paths backing one project's sandbox. The writable home and the
/// read-only synthetic `/etc` are deliberately *siblings*: nothing read-write
/// contains the identity files (see the module integrity note).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectRuntime {
    /// The sandbox `$HOME` on the host, bound read-write.
    pub(crate) home_src: PathBuf,
    /// Directory holding the synthetic `passwd`/`group`, bound read-only.
    pub(crate) etc_dir: PathBuf,
    /// For a **global app** only: the host path of the per-project mise data pool, bound writable
    /// as mise's primary [`super::MISE_PROJECT_INCAGE`] so a `nix:` self-equip's install aligns
    /// with the per-project `/nix` store. `None` for `sbx run` and a per-project app, whose home —
    /// and thus mise's data dir — is already per-project, so they keep the single-pool wiring.
    pub(crate) mise_project_src: Option<PathBuf>,
}

/// Which persistent runtime a launch uses — the writable `$HOME` and its sibling synthetic
/// `/etc`. `sbx run` use the project's shared default; an app gets a dedicated,
/// persistent home so its config, login state, and history never bleed into the project shell
/// or another app. An app's home is either shared across projects (`GlobalApp`, one identity
/// everywhere) or keyed per-project (`ProjectApp`, isolated per project).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Runtime<'a> {
    /// The project's default shared home — `sbx run`.
    ProjectDefault,
    /// `sbx app <name>` with one home per app, shared across every project.
    GlobalApp(&'a str),
    /// `sbx app <name>` with a home per (project, app).
    ProjectApp(&'a str),
}

impl<'a> Runtime<'a> {
    /// The app this launch is for, when it is one. Which of the two app runtimes it is says where
    /// the home lives, never who the launch is: everything that names a launch — its cage slug, its
    /// hostname, its scope, the lock it resolves against — asks only for the name.
    pub(crate) fn app(self) -> Option<&'a str> {
        match self {
            Runtime::ProjectDefault => None,
            Runtime::GlobalApp(name) | Runtime::ProjectApp(name) => Some(name),
        }
    }
}

/// Host-side runtime paths for `project` under sbx's data directory, for the given
/// [`Runtime`]. The home and the synthetic `/etc` are always siblings so the latter sits
/// outside every read-write bind (module integrity note). An app name is a validated single
/// path component (the config app-name check), so joining it cannot traverse out of the data
/// directory.
pub(super) fn project_runtime(data_dir: &Path, project: &Path, runtime: Runtime) -> ProjectRuntime {
    let project_base = || data_dir.join("projects").join(project_id(project));
    let (base, mise_project_src) = match runtime {
        Runtime::ProjectDefault => (project_base(), None),
        // A global app's home is project-independent — keyed only by the app name, so the same
        // identity is reused in every project. Its mise data pool, however, is keyed per (project,
        // app) — `projects/<id>/apps/<name>/mise`, the same base a per-project app roots its home
        // under, plus `/mise` — so a `nix:` self-equip's install record aligns with the per-project
        // `/nix` store and never points at another project's store. App-keyed (not project-keyed),
        // so a tool the agent self-equips in app A stays private to app A, preserving per-app
        // isolation for mise install records exactly as before the split.
        Runtime::GlobalApp(name) => (
            data_dir.join("apps").join(name),
            Some(project_base().join("apps").join(name).join("mise")),
        ),
        // A per-project app's home nests under the project, isolating its state per project — its
        // mise data dir is therefore already per-project-aligned, so it keeps the single-pool wiring.
        Runtime::ProjectApp(name) => (project_base().join("apps").join(name), None),
    };
    ProjectRuntime {
        home_src: base.join("home"),
        etc_dir: base.join("etc"),
        mise_project_src,
    }
}

/// The host path of the cage's persistent `$HOME` for this launch — the exact directory
/// [`super::build_spec`] binds writable as the home (derived identically: canonicalise the cwd, then
/// [`project_runtime`]). Lets a host-side helper place a file the cage reads through the home bind
/// (the live-theme keyfile the in-cage portal watches).
pub(crate) fn home_src(data_dir: &Path, cwd: &Path, runtime: Runtime) -> io::Result<PathBuf> {
    let project = canonicalize_project(cwd)?;
    Ok(project_runtime(data_dir, &project, runtime).home_src)
}

/// A collision-resistant directory name for a canonical project path. A project's runtime tree —
/// its home, its store, its pin locks — sits under `<data>/projects/<id>/`, and housekeeping hashes
/// a running session's recorded canonical path with this to match it against a tree, so it can skip
/// a tree a live session still holds.
///
/// Both need the same id from every build of sbx. An id that moved would leave each project's home
/// and store behind under the old one, and would read a session a previous binary started as holding
/// no tree: `sbx projects rm` would remove the tree it runs in, and `sbx gc --all` would no longer
/// count it among the holders of the distribution tree it runs from. The
/// derivation is therefore written out here rather than taken from `DefaultHasher`, whose algorithm
/// std leaves unspecified and whose hashes it says not to rely on across releases: SipHash-1-3 under
/// the zero key ([`siphash13`]) over the bytes std's `impl Hash for Path` hands a hasher on Unix
/// ([`path_hash_input`]), which is the derivation the existing trees are keyed by.
pub(crate) fn project_id(project: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    format!(
        "{:016x}",
        siphash13(&path_hash_input(project.as_os_str().as_bytes()))
    )
}

/// The bytes std's `impl Hash for Path` writes to a hasher on Unix, in order: each component between
/// separators — leaving out a `.` that follows a separator, as [`Path::components`] does — and then
/// a mix of the components' lengths, as eight little-endian bytes. A hasher that streams, as SipHash
/// does, gives the same value for those writes as for their concatenation, so one buffer stands for
/// them.
fn path_hash_input(bytes: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(bytes.len() + 8);
    // Mixed in after the components so that `["foo", "bar"]` and `["foobar"]`, which write the same
    // bytes, still hash apart.
    let mut lengths: u64 = 0;
    let mut take = |piece: &[u8], input: &mut Vec<u8>| {
        lengths = lengths.wrapping_add(piece.len() as u64).rotate_right(2);
        input.extend_from_slice(piece);
    };
    let mut start = 0;
    for (at, &byte) in bytes.iter().enumerate() {
        if byte != b'/' {
            continue;
        }
        if at > start {
            take(&bytes[start..at], &mut input);
        }
        start = at + 1;
        if matches!(&bytes[start..], [b'.'] | [b'.', b'/', ..]) {
            start += 1;
        }
    }
    if start < bytes.len() {
        take(&bytes[start..], &mut input);
    }
    input.extend_from_slice(&lengths.to_le_bytes());
    input
}

/// SipHash-1-3 of `input` under the zero key: one round per eight-byte word, read little-endian,
/// then a last word holding the remaining bytes with the input's length in its top byte, then three
/// rounds to finish.
fn siphash13(input: &[u8]) -> u64 {
    // SipHash's initialisation constants, each XORed with a key half, which is zero here.
    let mut v = [
        0x736f_6d65_7073_6575_u64,
        0x646f_7261_6e64_6f6d,
        0x6c79_6765_6e65_7261,
        0x7465_6462_7974_6573,
    ];
    let absorb = |v: &mut [u64; 4], word: u64| {
        v[3] ^= word;
        sip_round(v);
        v[0] ^= word;
    };
    let (words, rest) = input.as_chunks::<8>();
    for word in words {
        absorb(&mut v, u64::from_le_bytes(*word));
    }
    let mut last = (input.len() as u64 & 0xff) << 56;
    for (at, &byte) in rest.iter().enumerate() {
        last |= u64::from(byte) << (8 * at);
    }
    absorb(&mut v, last);
    v[2] ^= 0xff;
    for _ in 0..3 {
        sip_round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

/// One SipRound over the state `v0, v1, v2, v3`.
fn sip_round(v: &mut [u64; 4]) {
    let [v0, v1, v2, v3] = v;
    *v0 = v0.wrapping_add(*v1);
    *v2 = v2.wrapping_add(*v3);
    *v1 = v1.rotate_left(13) ^ *v0;
    *v3 = v3.rotate_left(16) ^ *v2;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v1);
    *v0 = v0.wrapping_add(*v3);
    *v1 = v1.rotate_left(17) ^ *v2;
    *v3 = v3.rotate_left(21) ^ *v0;
    *v2 = v2.rotate_left(32);
}

/// The stable per-project identity sbx keys runtime state on. The writable home,
/// the synthetic identity, and a project's garbage-collection roots all derive from
/// it, so housekeeping can reclaim a project's tools alongside the rest of its
/// runtime. Canonicalises first, so a relative or symlinked `cwd` maps to the same
/// identity as the real path (the same pin [`canonicalize_project`] applies to the
/// bind source).
pub(crate) fn project_runtime_id(cwd: &Path) -> io::Result<String> {
    Ok(project_identity(cwd)?.0)
}

/// The per-project identity together with the canonical project path it derives from. The id keys
/// the project's runtime tree (home, store, gcroots); the canonical path is what a launch records
/// in a durable marker so housekeeping can later recognise — and reclaim — that tree once the
/// project directory is gone (the id alone is a one-way hash). Canonicalises once, so id and path
/// agree and both match the bind source's pinned location.
pub(crate) fn project_identity(cwd: &Path) -> io::Result<(String, PathBuf)> {
    let canonical = canonicalize_project(cwd)?;
    let id = project_id(&canonical);
    Ok((id, canonical))
}

/// Resolve `path` to a real, existing directory, following symlinks in the host
/// namespace. Canonicalising up front *narrows* the project mount's TOCTOU window:
/// the source is pinned to its real location, so a later project-controlled
/// symlink swap no longer trivially redirects the bind. It is not an absolute
/// guarantee — a parent component swapped between this call and the actual bind
/// still races, and the project root is mounted by path. The config-declared binds,
/// whose parents another session's cage can write when they lie in its project, its
/// read-write binds or its mise pool, are held open instead and mounted from their
/// descriptors ([`super::hold_bind_sources`]).
pub(super) fn canonicalize_project(path: &Path) -> io::Result<PathBuf> {
    let canon = path.canonicalize()?;
    if !canon.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("project path is not a directory: {}", canon.display()),
        ));
    }
    Ok(canon)
}
