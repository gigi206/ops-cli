//! Staging an inline `[flakes.<name>]` flake — the `flake.nix` source written directly in the
//! config — to a content-keyed directory on disk, ready to be bound read-only into the cage and
//! built with `nix build path:<dir>#<attr>`.
//!
//! Unlike a `flake:<ref>` package (a reference to an external flake), the source is ours, so sbx
//! materializes it as a real directory a `path:` flake can point at. The directory name is a hash
//! of the source, so a launch reuses the same staged flake (warm) while *editing* the flake in the
//! config stages a fresh directory beside it — and, crucially, changes the hash the out-link is
//! keyed by, so the edited flake actually rebuilds instead of the warm short-circuit reusing the
//! stale build.

use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};

/// The data-directory root holding every staged inline flake, one content-keyed directory each.
///
/// Named here rather than joined at the use site because two readers depend on agreeing: the
/// staging below, and the overview in [`crate::paths`], whose claim to list every directory sbx
/// owns is only true if a directory added here is added there.
pub(crate) fn staging_root(data_dir: &Path) -> PathBuf {
    data_dir.join("flake-inline")
}

/// Stage the `flake.nix` `content` to a content-keyed directory `<data>/flake-inline/<hash>/`
/// holding a single `flake.nix`, returning `(dir, hash)`. Content-keyed and atomic like the staged
/// fontconfig/mise plugin: the directory is assembled in a unique temp sibling and `rename`d into
/// place, so a concurrent launch of the same project never observes a half-written flake (a lost
/// rename race just means the other launch wrote the identical bytes first). The `hash` keys the
/// cage out-link, so an edited flake (a new hash) rebuilds at the next launch.
///
/// A directory already there is used only once it is seen to hold this source ([`holds`]), and one
/// that holds another is an error.
pub(crate) fn stage(data_dir: &Path, content: &str) -> io::Result<(PathBuf, String)> {
    let base = staging_root(data_dir);
    std::fs::create_dir_all(&base)?;
    let hash = content_hash(content);
    let dir = base.join(&hash);
    if holds(&dir, content)? {
        return Ok((dir, hash));
    }

    let tmp = base.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        super::atomicfile::unique()
    ));
    let assemble = || -> io::Result<()> {
        std::fs::create_dir(&tmp)?;
        std::fs::write(tmp.join("flake.nix"), content)
    };
    if let Err(e) = assemble() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }
    settle(&tmp, &dir, content).map(|()| (dir, hash))
}

/// Move the assembled `tmp` into place at `dir`, or settle on the directory a concurrent launch put
/// there first.
///
/// A lost race is taken only once `dir` is seen to hold this source ([`holds`]); any other failure
/// is the rename's own. Either way `tmp` is gone afterwards.
fn settle(tmp: &Path, dir: &Path, content: &str) -> io::Result<()> {
    match std::fs::rename(tmp, dir) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_dir_all(tmp);
            match holds(dir, content)? {
                true => Ok(()),
                false => Err(e),
            }
        }
    }
}

/// Whether `dir` already holds this flake: `true` when its `flake.nix` is these bytes, `false` when
/// it has none, and an error when it holds other bytes.
///
/// The directory is named by a 64-bit prefix of the source's hash and shared by every project, so
/// its name does not say whose source is in it. Reused unread, a directory a second source had
/// taken under the same prefix, or a file changed since it was staged, would be built in this
/// flake's place. Nothing removes a staged directory, so the refusal names the one to remove: the
/// next launch stages this source there afresh.
fn holds(dir: &Path, content: &str) -> io::Result<bool> {
    let path = dir.join("flake.nix");
    match std::fs::read(&path) {
        Ok(found) if found == content.as_bytes() => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} holds another flake under this one's name, so it is not built in its place; \
                 remove {} to stage this one",
                path.display(),
                dir.display()
            ),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// A short hex hash of the source, so the staging directory name — and the out-link keyed by it —
/// change exactly when the flake does.
fn content_hash(content: &str) -> String {
    let mut h = Sha256::new();
    h.update(content.as_bytes());
    crate::plugins::catalogue::to_hex(&h.finalize()[..CONTENT_HASH_BYTES])
}

/// How many bytes of the source's SHA-256 [`content_hash`] keeps.
const CONTENT_HASH_BYTES: usize = 8;

/// Whether `s` has the shape of a [`content_hash`]: the lowercase hex of its bytes. What follows
/// `<name>-` in a build out-link is one, which is how a reader tells that out-link from the one of
/// a flake whose own name begins with `<name>-`.
pub(crate) fn is_content_hash(s: &str) -> bool {
    s.len() == 2 * CONTENT_HASH_BYTES && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    /// A content hash reads back as one, and a name that merely follows a dash does not.
    #[test]
    fn a_content_hash_is_told_from_a_name() {
        assert!(is_content_hash(&content_hash(
            "{ outputs = { self }: {}; }\n"
        )));
        for not_one in [
            "bar",
            "deadbeef",
            "0123456789ABCDEF",
            "0123456789abcdef0",
            "bar-0123456789ab",
        ] {
            assert!(!is_content_hash(not_one), "{not_one}");
        }
    }

    #[test]
    fn stage_writes_flake_nix_content_keyed_and_idempotent() {
        let data = TmpDir::new();
        let content = "{ outputs = { self }: {}; }\n";
        let (dir, hash) = stage(data.path(), content).unwrap();
        // The flake.nix holds exactly the source, at a hash-named directory.
        assert_eq!(
            std::fs::read_to_string(dir.join("flake.nix")).unwrap(),
            content
        );
        assert!(dir.ends_with(&hash));

        // Re-staging identical content returns the same directory (warm reuse), no temp left.
        let (dir2, hash2) = stage(data.path(), content).unwrap();
        assert_eq!(dir2, dir);
        assert_eq!(hash2, hash);

        // Editing the flake stages a DISTINCT directory (a new hash) — the property that makes the
        // hash-keyed out-link rebuild an edited flake rather than reuse the stale build.
        let (edited, edited_hash) =
            stage(data.path(), "{ outputs = { self }: { x = 1; }; }\n").unwrap();
        assert_ne!(edited_hash, hash);
        assert_ne!(edited, dir);
    }

    /// A staged directory is used only while it holds this source. One whose `flake.nix` holds
    /// other bytes, a second source staged under the same name or a file changed since, is refused
    /// rather than built in this flake's place, and is used again once it holds the source.
    #[test]
    fn a_staged_directory_holding_another_source_is_not_used() {
        let data = TmpDir::new();
        let content = "{ outputs = { self }: {}; }\n";
        let (dir, _) = stage(data.path(), content).unwrap();

        std::fs::write(
            dir.join("flake.nix"),
            "{ outputs = { self }: { x = 1; }; }\n",
        )
        .unwrap();
        let refused = stage(data.path(), content).expect_err("another source is not used");
        assert_eq!(refused.kind(), io::ErrorKind::AlreadyExists, "{refused}");

        std::fs::write(dir.join("flake.nix"), content).unwrap();
        assert_eq!(stage(data.path(), content).unwrap().0, dir);
    }

    /// A rename that lost the race settles on the winner only once it holds this source: the same
    /// bytes are used, other bytes are refused, and a directory with no `flake.nix` leaves the
    /// rename's own error. The temp is gone in every case.
    #[test]
    fn a_lost_rename_settles_only_on_a_winner_holding_the_source() {
        let content = "{ outputs = { self }: {}; }\n";
        let other = "{ outputs = { self }: { x = 1; }; }\n";
        let shapes = [
            ("the same bytes", Some(content), Ok(())),
            (
                "other bytes",
                Some(other),
                Err(io::ErrorKind::AlreadyExists),
            ),
            ("no flake.nix", None, Err(io::ErrorKind::DirectoryNotEmpty)),
        ];
        for (shape, there, expected) in shapes {
            let base = TmpDir::new();
            let (tmp, dir) = (base.path().join(".tmp"), base.path().join("winner"));
            std::fs::create_dir(&tmp).unwrap();
            std::fs::write(tmp.join("flake.nix"), content).unwrap();
            std::fs::create_dir(&dir).unwrap();
            match there {
                Some(bytes) => std::fs::write(dir.join("flake.nix"), bytes).unwrap(),
                None => std::fs::write(dir.join("other"), "x").unwrap(),
            }
            let settled = settle(&tmp, &dir, content).map_err(|e| e.kind());
            assert_eq!(settled, expected, "{shape}");
            assert!(!tmp.exists(), "{shape}: the temp is gone");
        }
    }
}
