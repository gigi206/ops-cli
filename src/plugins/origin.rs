//! Where an installed resolver plugin came from.
//!
//! A plugin's own manifest says what it is, never where it was obtained: the same `plugin.toml`
//! is byte-identical whether it arrived from a local directory or a signed store. The install therefore records its provenance beside the plugin, so a later
//! listing can say which store a plugin belongs to — and, when two stores list a plugin of the
//! same name, which one won the name.
//!
//! The record lives **outside** the plugin's own directory, under
//! `<data>/plugins/.origins/<name>.toml`. A plugin directory is content-addressed by a store
//! catalogue (`catalogue::dir_digest` hashes every regular file in the tree), so a sidecar placed
//! *inside* it would put every installed plugin permanently out of agreement with the hash that
//! was signed. The `.origins` directory itself is invisible to the registry: discovery skips a
//! directory carrying no manifest, and an install name may not begin with a dot, so no plugin can
//! ever collide with it.
//!
//! Reading is **lenient**, like manifest discovery: a missing, unreadable, or malformed record
//! yields [`Origin::Unknown`] rather than an error. An unknown origin is the honest answer for a
//! plugin installed before origins were recorded, and it must never be able to break a listing.

use super::ensure_owner_only;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The directory holding one record per installed plugin. Dot-prefixed so it cannot collide with
/// a plugin (an install name may not begin with a dot) and is skipped by discovery.
const ORIGINS_DIR: &str = ".origins";

/// Where an installed plugin came from — display-only provenance, never a trust input: the
/// security of an installed plugin rests on the owner-only data directory, not on this record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Origin {
    /// A local directory copied in (`sbx plugins install ./dir`). The path is absent when it was
    /// not representable as UTF-8.
    Local {
        path: Option<String>,
        sha256: Option<String>,
    },
    /// A configured signed store (`sbx plugins store install <store> <plugin>`), with the store's
    /// URL and the content hash of the tree that was placed.
    Store {
        store: String,
        url: Option<String>,
        sha256: Option<String>,
    },
    /// No record — installed before origins were recorded, or placed by hand.
    Unknown,
}

impl Origin {
    /// The digest of the plugin's tree as it was placed, when one was recorded. Recomputing it and
    /// comparing tells whether the tree changed since — see [`crate::plugins::integrity`]. Absent
    /// for a plugin installed before sbx recorded digests, and for one placed by hand.
    pub(crate) fn digest(&self) -> Option<&str> {
        match self {
            Origin::Local { sha256, .. } | Origin::Store { sha256, .. } => sha256.as_deref(),
            Origin::Unknown => None,
        }
    }

    /// The same origin carrying `digest` — the install records what it actually placed, which the
    /// caller only knows once the tree is in place.
    pub(crate) fn with_digest(self, digest: Option<String>) -> Self {
        match self {
            Origin::Local { path, .. } => Origin::Local {
                path,
                sha256: digest,
            },
            Origin::Store { store, url, .. } => Origin::Store {
                store,
                url,
                sha256: digest,
            },
            Origin::Unknown => Origin::Unknown,
        }
    }
    /// A full sentence for a per-plugin detail line, e.g. `sbx plugins list`.
    pub(crate) fn label(&self) -> String {
        match self {
            Origin::Local { path: Some(p), .. } => format!("local directory {p}"),
            Origin::Local { path: None, .. } => "a local directory".to_string(),
            Origin::Store {
                store,
                url: Some(url),
                ..
            } => format!("store '{store}' ({url})"),
            Origin::Store { store, .. } => format!("store '{store}'"),
            Origin::Unknown => {
                "unknown (installed before sbx recorded plugin origins, or placed by hand)"
                    .to_string()
            }
        }
    }

    /// A short noun phrase for an inline marker, e.g. `[name taken by store 'mine']`.
    pub(crate) fn short(&self) -> String {
        match self {
            Origin::Local { .. } => "a local install".to_string(),
            Origin::Store { store, .. } => format!("store '{store}'"),
            Origin::Unknown => "an unknown source".to_string(),
        }
    }

    /// Whether this plugin was installed from the named configured store — the test that decides
    /// whether a catalogue entry reads `[installed]` or `[name taken by …]`.
    pub(crate) fn is_store(&self, name: &str) -> bool {
        matches!(self, Origin::Store { store, .. } if store == name)
    }

    /// Whether two origins name the same source, ignoring what may have moved within it (a store's
    /// URL, a pinned hash, a local path). It separates "you already have this from somewhere else"
    /// from "you already have this from here" — the second is a re-install, which a plain
    /// name-collision message would not explain. An unknown origin matches nothing: it names no
    /// source to be the same as.
    pub(crate) fn same_source_as(&self, other: &Origin) -> bool {
        match other {
            Origin::Store { store, .. } => self.is_store(store),
            Origin::Local { .. } => matches!(self, Origin::Local { .. }),
            Origin::Unknown => false,
        }
    }

    /// The record's TOML form. Only [`Origin::Unknown`] has none — an unknown origin is the
    /// *absence* of a record, so it is never written.
    fn to_toml(&self) -> Option<String> {
        match self {
            Origin::Local { path, sha256 } => {
                let mut s = String::from("kind = \"local\"\n");
                if let Some(p) = path {
                    s.push_str(&format!("path = \"{}\"\n", escape(p)));
                }
                if let Some(hash) = sha256 {
                    s.push_str(&format!("sha256 = \"{}\"\n", escape(hash)));
                }
                Some(s)
            }
            Origin::Store { store, url, sha256 } => {
                let mut s = format!("kind = \"store\"\nstore = \"{}\"\n", escape(store));
                if let Some(url) = url {
                    s.push_str(&format!("url = \"{}\"\n", escape(url)));
                }
                if let Some(hash) = sha256 {
                    s.push_str(&format!("sha256 = \"{}\"\n", escape(hash)));
                }
                Some(s)
            }
            Origin::Unknown => None,
        }
    }
}

/// The raw record, before validation. Every field is optional so a truncated or partially-written
/// file degrades to a weaker origin instead of failing the read.
#[derive(Debug, Deserialize)]
struct RawOrigin {
    kind: Option<String>,
    path: Option<String>,
    store: Option<String>,
    url: Option<String>,
    sha256: Option<String>,
}

/// Record where a freshly-installed plugin came from, replacing any earlier record for that name.
/// Called *after* the plugin is in place: a record without a plugin would be a lie a later install
/// of the same name could inherit, whereas a plugin without a record simply reads as unknown.
pub(crate) fn record(
    layout: &crate::store::Layout,
    plugin: &str,
    origin: &Origin,
) -> Result<(), String> {
    let Some(text) = origin.to_toml() else {
        return Ok(());
    };
    crate::plugins::validate_install_name(plugin)?;
    let dir = dir(layout);
    ensure_owner_only(&dir)?;
    // Write to a private temp file and rename over the target: a concurrent reader sees either the
    // previous record or the new one, never a half-written file, and an existing record (including
    // one orphaned by a hand-removed plugin) is replaced rather than kept.
    let tmp = dir.join(format!(".tmp-{}-{}", std::process::id(), unique()));
    let _ = std::fs::remove_file(&tmp);
    write_owner_only(&tmp, text.as_bytes())?;
    if let Err(e) = std::fs::rename(&tmp, path_of(layout, plugin)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("cannot record the plugin's origin: {e}"));
    }
    Ok(())
}

/// Where a plugin came from, or [`Origin::Unknown`] when nothing usable is recorded. Infallible by
/// design — a listing must never fail because a record is missing or malformed.
pub(crate) fn read(layout: &crate::store::Layout, plugin: &str) -> Origin {
    if crate::plugins::validate_install_name(plugin).is_err() {
        return Origin::Unknown;
    }
    let Ok(text) = std::fs::read_to_string(path_of(layout, plugin)) else {
        return Origin::Unknown;
    };
    parse(&text)
}

/// Parse a record's text. Split from the read so the degradation rules are testable without a
/// data directory.
fn parse(text: &str) -> Origin {
    let Ok(raw) = toml::from_str::<RawOrigin>(text) else {
        return Origin::Unknown;
    };
    // Every field is displayed verbatim in a terminal, so a control character (which could smuggle
    // an escape sequence) drops that field rather than being printed. The fields are written by sbx
    // itself, so this only ever fires on a corrupted or hand-edited record.
    let clean = |v: Option<String>| v.filter(|s| !s.is_empty() && !s.chars().any(char::is_control));
    match raw.kind.as_deref() {
        Some("local") => Origin::Local {
            path: clean(raw.path),
            sha256: clean(raw.sha256),
        },
        Some("store") => match clean(raw.store) {
            // A store record with no store name names nothing — weaker than useless, so it reads
            // as unknown rather than as an anonymous store.
            None => Origin::Unknown,
            Some(store) => Origin::Store {
                store,
                url: clean(raw.url),
                sha256: clean(raw.sha256),
            },
        },
        _ => Origin::Unknown,
    }
}

/// Drop a plugin's record, when the plugin itself is removed. Best-effort: a leftover record is
/// harmless (a later install of that name overwrites it, and nothing reads a record for a plugin
/// that is not installed).
pub(crate) fn forget(layout: &crate::store::Layout, plugin: &str) {
    if crate::plugins::validate_install_name(plugin).is_ok() {
        let _ = std::fs::remove_file(path_of(layout, plugin));
    }
}

/// The directory holding the origin records.
fn dir(layout: &crate::store::Layout) -> PathBuf {
    layout.plugins_dir().join(ORIGINS_DIR)
}

/// The record file for one plugin. The name is validated by every caller before this is used, so
/// it is a single safe path component.
fn path_of(layout: &crate::store::Layout, plugin: &str) -> PathBuf {
    dir(layout).join(format!("{plugin}.toml"))
}

/// Escape the two characters that would break a TOML basic string. Control characters are already
/// excluded by the callers' own validation (a store URL, a store name, a hex hash); a local path
/// is the one free-form field, and a control byte in it is dropped on read.
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Write a file owner-readable/writable only, creating it fresh.
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// A per-call-unique suffix for the temp record, so two installs in one process never collide.
/// A monotonic process-local counter — no clock or RNG.
fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Layout;

    fn layout(base: &Path) -> Layout {
        Layout::under(&base.join("sbx"))
    }

    #[test]
    fn a_recorded_origin_reads_back_in_full() {
        let tmp = crate::testutil::TmpDir::new();
        let layout = layout(tmp.path());
        let origin = Origin::Store {
            store: "mine".to_string(),
            url: Some("https://example.invalid/plugins.git".to_string()),
            sha256: Some("a".repeat(64)),
        };
        record(&layout, "kp", &origin).unwrap();
        assert_eq!(read(&layout, "kp"), origin);
        assert!(read(&layout, "kp").is_store("mine"));
        assert!(!read(&layout, "kp").is_store("other"));
    }

    #[test]
    fn each_kind_round_trips() {
        let tmp = crate::testutil::TmpDir::new();
        let layout = layout(tmp.path());
        for origin in [
            Origin::Local {
                path: Some("/home/u/plugins/kp".to_string()),
                sha256: Some("b".repeat(64)),
            },
            Origin::Local {
                path: Some("/home/u/plugins/kp".to_string()),
                sha256: None,
            },
            Origin::Local {
                path: None,
                sha256: None,
            },
        ] {
            record(&layout, "kp", &origin).unwrap();
            assert_eq!(read(&layout, "kp"), origin);
        }
    }

    #[test]
    fn recording_replaces_an_earlier_record() {
        let tmp = crate::testutil::TmpDir::new();
        let layout = layout(tmp.path());
        record(
            &layout,
            "kp",
            &Origin::Store {
                store: "mine".to_string(),
                url: None,
                sha256: None,
            },
        )
        .unwrap();
        // The orphan case: a hand-removed plugin leaves its record behind, and installing a plugin
        // of that name again must not inherit the stale provenance.
        let fresh = Origin::Local {
            path: Some("/src/kp".to_string()),
            sha256: None,
        };
        record(&layout, "kp", &fresh).unwrap();
        assert_eq!(read(&layout, "kp"), fresh);
    }

    #[test]
    fn a_missing_or_broken_record_reads_as_unknown() {
        let tmp = crate::testutil::TmpDir::new();
        let layout = layout(tmp.path());
        assert_eq!(read(&layout, "never-installed"), Origin::Unknown);
        record(
            &layout,
            "kp",
            &Origin::Local {
                path: None,
                sha256: None,
            },
        )
        .unwrap();
        std::fs::write(path_of(&layout, "kp"), b"kind = \"store\"\nstore = ").unwrap();
        assert_eq!(read(&layout, "kp"), Origin::Unknown);
        // A well-formed record naming a kind sbx does not know is unknown, not a hard error.
        std::fs::write(path_of(&layout, "kp"), b"kind = \"carrier-pigeon\"\n").unwrap();
        assert_eq!(read(&layout, "kp"), Origin::Unknown);
        // A store record with no store name names nothing.
        std::fs::write(path_of(&layout, "kp"), b"kind = \"store\"\n").unwrap();
        assert_eq!(read(&layout, "kp"), Origin::Unknown);
    }

    #[test]
    fn a_control_character_in_a_displayed_field_is_dropped() {
        // A record is written by sbx, but a hand-edited one must not be able to smuggle a terminal
        // escape into a listing.
        assert_eq!(
            parse("kind = \"local\"\npath = \"/tmp/\\u001b[31mred\"\n"),
            Origin::Local {
                path: None,
                sha256: None
            }
        );
        assert_eq!(
            parse("kind = \"store\"\nstore = \"mine\"\nurl = \"https://a\\u0007b\"\n"),
            Origin::Store {
                store: "mine".to_string(),
                url: None,
                sha256: None,
            }
        );
    }

    #[test]
    fn a_path_with_toml_metacharacters_round_trips() {
        let tmp = crate::testutil::TmpDir::new();
        let layout = layout(tmp.path());
        let origin = Origin::Local {
            path: Some("/home/u/a\"b\\c/kp".to_string()),
            sha256: Some("c".repeat(64)),
        };
        record(&layout, "kp", &origin).unwrap();
        assert_eq!(read(&layout, "kp"), origin);
    }

    #[test]
    fn same_source_as_ignores_what_moved_within_a_source() {
        let a = Origin::Store {
            store: "mine".to_string(),
            url: Some("https://example.invalid/a.git".to_string()),
            sha256: Some("a".repeat(64)),
        };
        // The same store after a re-publish: a new hash (and even a moved URL) is still the same
        // source, so a re-install is told apart from a name collision with another store.
        let moved = Origin::Store {
            store: "mine".to_string(),
            url: Some("https://example.invalid/moved.git".to_string()),
            sha256: Some("b".repeat(64)),
        };
        assert!(a.same_source_as(&moved));
        let other = Origin::Store {
            store: "other".to_string(),
            url: None,
            sha256: None,
        };
        assert!(!a.same_source_as(&other));
        // A store and a local directory are never the same source, whichever way round.
        let local = Origin::Local {
            path: Some("/a".to_string()),
            sha256: None,
        };
        assert!(!a.same_source_as(&local));
        assert!(!local.same_source_as(&a));
        // Two local installs are the same source: what changed is which directory it came from.
        assert!(local.same_source_as(&Origin::Local {
            path: Some("/b".to_string()),
            sha256: None,
        }));
        // An unknown origin names no source, so it is never "the same" as one.
        assert!(!Origin::Unknown.same_source_as(&a));
        assert!(!a.same_source_as(&Origin::Unknown));
    }

    #[test]
    fn forget_drops_the_record() {
        let tmp = crate::testutil::TmpDir::new();
        let layout = layout(tmp.path());
        record(
            &layout,
            "kp",
            &Origin::Local {
                path: None,
                sha256: None,
            },
        )
        .unwrap();
        forget(&layout, "kp");
        assert_eq!(read(&layout, "kp"), Origin::Unknown);
        // Forgetting what was never recorded is a no-op, not a failure.
        forget(&layout, "kp");
    }

    #[test]
    fn an_unsafe_name_never_reaches_the_filesystem() {
        let tmp = crate::testutil::TmpDir::new();
        let layout = layout(tmp.path());
        assert!(
            record(
                &layout,
                "../escape",
                &Origin::Local {
                    path: None,
                    sha256: None
                }
            )
            .is_err()
        );
        assert_eq!(read(&layout, "../escape"), Origin::Unknown);
    }

    #[test]
    fn the_records_directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = crate::testutil::TmpDir::new();
        let layout = layout(tmp.path());
        record(
            &layout,
            "kp",
            &Origin::Local {
                path: None,
                sha256: None,
            },
        )
        .unwrap();
        let mode = std::fs::metadata(dir(&layout))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        let mode = std::fs::metadata(path_of(&layout, "kp"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
