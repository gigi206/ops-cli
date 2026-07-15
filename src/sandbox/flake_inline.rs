//! Staging an inline `[flakes.<name>]` flake — the `flake.nix` source written directly in the
//! config — to a content-keyed directory on disk, ready to be bound read-only into the cage and
//! built with `nix build path:<dir>#<attr>`.
//!
//! Unlike a `flake:<ref>` package (a reference to an external flake), the source is ours, so ops
//! materializes it as a real directory a `path:` flake can point at. The directory name is a hash
//! of the source, so a launch reuses the same staged flake (warm) while *editing* the flake in the
//! config stages a fresh directory beside it — and, crucially, changes the hash the out-link is
//! keyed by, so the edited flake actually rebuilds instead of the warm short-circuit reusing the
//! stale build.

use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};

/// Stage the `flake.nix` `content` to a content-keyed directory `<data>/flake-inline/<hash>/`
/// holding a single `flake.nix`, returning `(dir, hash)`. Content-keyed and atomic like the staged
/// fontconfig/mise plugin: the directory is assembled in a unique temp sibling and `rename`d into
/// place, so a concurrent launch of the same project never observes a half-written flake (a lost
/// rename race just means the other launch wrote the identical bytes first). The `hash` keys the
/// cage out-link, so an edited flake (a new hash) rebuilds at the next launch.
pub(crate) fn stage(data_dir: &Path, content: &str) -> io::Result<(PathBuf, String)> {
    let base = data_dir.join("flake-inline");
    std::fs::create_dir_all(&base)?;
    let hash = content_hash(content);
    let dir = base.join(&hash);
    if dir.join("flake.nix").is_file() {
        return Ok((dir, hash));
    }

    let tmp = base.join(format!(".tmp-{}-{}", std::process::id(), unique()));
    let assemble = || -> io::Result<()> {
        std::fs::create_dir(&tmp)?;
        std::fs::write(tmp.join("flake.nix"), content)
    };
    if let Err(e) = assemble() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }
    match std::fs::rename(&tmp, &dir) {
        Ok(()) => Ok((dir, hash)),
        // Lost the race (another launch staged the identical flake first) or it already existed:
        // discard the redundant temp and use the winner.
        Err(_) if dir.join("flake.nix").is_file() => {
            let _ = std::fs::remove_dir_all(&tmp);
            Ok((dir, hash))
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            Err(e)
        }
    }
}

/// A short hex hash of the source, so the staging directory name — and the out-link keyed by it —
/// change exactly when the flake does.
fn content_hash(content: &str) -> String {
    let mut h = Sha256::new();
    h.update(content.as_bytes());
    let digest = h.finalize();
    let mut s = String::with_capacity(16);
    for b in &digest[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A per-call-unique suffix for the staging temp directory (pid alone is not enough if a process
/// stages twice). Monotonic process-local counter, so it needs no clock or RNG.
fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

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
}
