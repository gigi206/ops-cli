//! `sbx path` — the on-disk locations sbx uses, grouped by XDG base (data,
//! config, state). A read-only, no-trust-gate, network-free overview: it lists
//! every directory sbx owns plus the two config anchor files, marks which exist,
//! and enumerates the per-project / per-app / per-profile entries actually on
//! disk so the layout reads at a glance. The counterpart of `sbx config path`
//! (which covers the config *files* in resolution order) for the rest of the
//! filesystem — a single place to answer "where on disk does sbx put things?".
//!
//! The model is one [`PathView`] built by [`view`]: a small set of bases, each
//! with a root and a fixed list of known entries, optionally carrying the
//! children found on disk. Pure derivation of the roots (no I/O) lives in the
//! callers already cited below; [`view`] does the probing (existence + a single
//! `read_dir` per enumerated entry) and is the only place I/O happens, so the
//! text and JSON renders share one source of truth and cannot disagree.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::{config, sandbox, session, store::Layout, trust};

/// What to list under an entry when it exists. `None` lists nothing; `Dirs` lists
/// the child directories (a global app home); `Profiles` lists the `*.toml` profile
/// files (an imported app profile); `Projects` lists each project's runtime tree
/// classified by liveness and dated, so `sbx path` answers "is this project still
/// used, and when was it last touched?" alongside the layout.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Enumerate {
    None,
    Dirs,
    Profiles,
    Projects,
}

/// One known location under a base, as a static spec — label, relative path,
/// one-line description, and whether to enumerate its on-disk children. The label
/// carries a trailing `/` when the entry is a directory (and `sbx.toml` when it is
/// the config anchor file), so the kind reads from the label with no separate field.
struct Entry {
    label: &'static str,
    rel: &'static str,
    desc: &'static str,
    enumerate: Enumerate,
}

const DATA_ENTRIES: &[Entry] = &[
    Entry {
        label: "store/",
        rel: "store",
        desc: "shared daemonless nix store (the `nix --store` target)",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "engine/",
        rel: "engine",
        desc: "embedded engines and the exec shim sbx materializes",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "plugins/",
        rel: "plugins",
        desc: "installed resolver plugins (one directory each)",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "stores/",
        rel: "stores",
        desc: "cached remote plugin stores (catalogue + checkout)",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "sessions/",
        rel: "sessions",
        desc: "session registry read by `sbx session ls`",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "egress/",
        rel: "egress",
        desc: "per-launch egress proxy sockets + CAs",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "mise/",
        rel: "mise",
        desc: "mise engine private home (host-side)",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "gcroots/",
        rel: "gcroots",
        desc: "nix gcroots (base, mise, gui, projects)",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "mise-plugin/",
        rel: "mise-plugin",
        desc: "the `nix:` mise backend plugin, staged content-keyed",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "fontconfig/",
        rel: "fontconfig",
        desc: "generated fontconfig for the Wayland hole",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "audio/",
        rel: "audio",
        desc: "generated ALSA config for the audio hole",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "dbus/",
        rel: "dbus",
        desc: "per-launch filtered D-Bus proxy sockets",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "portal/",
        rel: "portal",
        desc: "per-launch in-cage desktop portal state",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "forward/",
        rel: "forward",
        desc: "per-launch inbound port-forward sockets",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "proc/",
        rel: "proc",
        desc: "per-launch exec-enforcement sockets",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "logs/",
        rel: "logs",
        desc: "detached sessions' output, read by `sbx session logs`",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "projects/",
        rel: "projects",
        desc: "per-project runtime trees (store, home, locks)",
        enumerate: Enumerate::Projects,
    },
    Entry {
        label: "apps/",
        rel: "apps",
        desc: "global app homes (one per app, shared across projects)",
        enumerate: Enumerate::Dirs,
    },
];

/// What a data-directory subtree is for, keyed by its directory name, for a caller that enumerates
/// the directory itself (`sbx store`) and wants to label what it found. `None` for an entry sbx does
/// not document — enumeration stays the source of truth, so an unlisted entry is still reported,
/// just without a description.
pub(crate) fn data_entry_purpose(name: &str) -> Option<&'static str> {
    DATA_ENTRIES.iter().find(|e| e.rel == name).map(|e| e.desc)
}

const CONFIG_ENTRIES: &[Entry] = &[
    Entry {
        label: "sbx.toml",
        rel: "sbx.toml",
        desc: "global config (trusted by location)",
        enumerate: Enumerate::None,
    },
    Entry {
        label: "apps/",
        rel: "apps",
        desc: "imported app profiles (one file per app)",
        enumerate: Enumerate::Profiles,
    },
];

const STATE_ENTRIES: &[Entry] = &[Entry {
    label: "trusted/",
    rel: "trusted",
    desc: "trust markers (one per trusted config file)",
    enumerate: Enumerate::None,
}];

/// The complete on-disk layout view: one [`BaseView`] per XDG base sbx uses.
#[derive(Serialize)]
pub(crate) struct PathView {
    bases: Vec<BaseView>,
}

#[derive(Serialize)]
struct BaseView {
    /// `"data"` / `"config"` / `"state"` — the XDG base's short name.
    label: &'static str,
    /// The env-var contract for the base, e.g. `"$XDG_DATA_HOME/sbx (else ~/.local/share/sbx)"`.
    env_hint: &'static str,
    /// The resolved base directory (`<xdg>/sbx`). `None` only when no `$HOME`/XDG base resolves.
    root: Option<PathBuf>,
    /// Whether the base directory itself exists on disk.
    exists: bool,
    /// The known entries under this base, in canonical order.
    entries: Vec<EntryView>,
}

#[derive(Serialize)]
struct EntryView {
    label: &'static str,
    path: PathBuf,
    desc: &'static str,
    exists: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    children: Vec<ChildView>,
}

#[derive(Serialize)]
struct ChildView {
    /// The on-disk entry name — a project id, an app name, or a profile name
    /// (the `.toml` suffix stripped).
    name: String,
    path: PathBuf,
    /// Only set for per-project trees: `live`/`idle`/`dead`/`markerless`. `None` for app homes and
    /// profiles, which have no liveness state.
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'static str>,
    /// Only set for per-project trees: the last-used date as `YYYY-MM-DD` (the marker's mtime, or
    /// the tree dir's mtime when there is no marker). `None` for app homes and profiles.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_used: Option<String>,
    /// Only set for per-project trees: the canonical project path the marker records (the answer
    /// to "which project does this id belong to?"). `None` for markerless trees (unknown) and
    /// for app homes / profiles.
    #[serde(skip_serializing_if = "Option::is_none")]
    project_path: Option<PathBuf>,
    /// Only set for the one project tree matching the current working directory — a `*` marker in
    /// the text render, a boolean in JSON. False for every other child (skipped in JSON).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    current: bool,
}

/// Build the full layout view, probing existence and enumerating on-disk children.
/// `layout` is `None` only when the data directory cannot be resolved (no `$HOME`),
/// in which case the data base reports no root and its entries are all absent.
pub(crate) fn view(layout: Option<&Layout>) -> PathView {
    // The three `<xdg>/sbx` roots sbx owns. The data root comes from the store
    // layout; the config root is the parent of the profiles directory (sibling of
    // `sbx.toml`); the state root is the parent of the trust marker directory.
    // Each is `None` only when its XDG base + `$HOME` yield no absolute path.
    let data_root = layout.map(|l| l.data_dir().to_path_buf());
    let config_root = config::profiles_dir().and_then(|d| d.parent().map(Path::to_path_buf));
    let state_root = trust::default_store_dir().and_then(|d| d.parent().map(Path::to_path_buf));
    view_with_roots(data_root, config_root, state_root)
}

/// Build the view from explicit roots — the test seam that lets a unit test point
/// the three bases at throwaway directories without mutating process-global env
/// vars (which would race parallel tests). The production [`view`] resolves the
/// same three roots from the environment; this is the pure core shared with it.
fn view_with_roots(
    data_root: Option<PathBuf>,
    config_root: Option<PathBuf>,
    state_root: Option<PathBuf>,
) -> PathView {
    // The live project ids — the set a running session holds — for the data base's per-project
    // liveness annotation. Computed once from the session registry at the data root (the same
    // self-healing housekeep `sbx session ls` runs); empty when there is no data root or no sessions. Only
    // the data base's `projects/` entry consumes it; config and state ignore it.
    let live_ids: BTreeSet<String> = data_root
        .as_ref()
        .map(|d| live_project_ids(d))
        .unwrap_or_default();
    // The project id of the current working directory, so the matching tree (if any) is marked
    // `current` in the render — the answer to "which of these am I in right now?". `None` when the
    // cwd cannot be canonicalized (it was deleted mid-run, or no cwd at all) — then no tree is
    // marked. Hashed the way [`sandbox::project_id`] hashes a launch's cwd.
    let current_id = current_project_id();
    let bases = [
        (
            "data",
            "$SBX_DATA_DIR, else $XDG_DATA_HOME/sbx (else ~/.local/share/sbx)",
            DATA_ENTRIES,
            data_root,
        ),
        (
            "config",
            "$XDG_CONFIG_HOME/sbx (else ~/.config/sbx)",
            CONFIG_ENTRIES,
            config_root,
        ),
        (
            "state",
            "$XDG_STATE_HOME/sbx (else ~/.local/state/sbx)",
            STATE_ENTRIES,
            state_root,
        ),
    ];

    PathView {
        bases: bases
            .into_iter()
            .map(|(label, env_hint, entries, root)| {
                probe_base(
                    label,
                    env_hint,
                    entries,
                    root,
                    &live_ids,
                    current_id.as_deref(),
                )
            })
            .collect(),
    }
}

/// The project id of the current working directory, so `sbx path` can mark the tree you're in.
/// Best-effort: returns `None` when the cwd cannot be read or canonicalized (deleted mid-run, or
/// no cwd), in which case no tree is marked `current`.
fn current_project_id() -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    let canonical = cwd.canonicalize().ok()?;
    Some(sandbox::project_id(&canonical))
}

/// The set of project ids a running session holds, for the per-project `live` annotation. Reads
/// the session registry and prunes dead records (the same self-healing `sbx session ls` performs — a
/// benign side effect, not a violation of `sbx path`'s read-only stance, which is about no
/// sandbox launch / no trust gate / no network, not no filesystem housekeeping). Each live
/// session's recorded canonical path is hashed the way [`sandbox::project_id`] hashes a launch's
/// cwd, so the id matches the runtime tree's directory name.
fn live_project_ids(data_dir: &Path) -> BTreeSet<String> {
    let Ok((live, _)) = session::Registry::at(data_dir).housekeep() else {
        return BTreeSet::new();
    };
    live.iter()
        .map(|s| sandbox::project_id(&s.project))
        .collect()
}

/// Probe one base: its root's existence, then each entry's existence and (for
/// enumerated entries) the children found on disk. Best-effort throughout — a
/// `read_dir` that fails (a race, a permission wall) yields no children rather
/// than failing the whole overview, since `sbx path` is read-only and advisory.
/// `live_ids` is the live-session project-id set, consulted only by the `projects/`
/// enumeration. `current_id` is the cwd's project id, so the matching tree is marked
/// `current`. Both are ignored by bases that carry no project trees.
fn probe_base(
    label: &'static str,
    env_hint: &'static str,
    entries: &'static [Entry],
    root: Option<PathBuf>,
    live_ids: &BTreeSet<String>,
    current_id: Option<&str>,
) -> BaseView {
    let exists = root
        .as_ref()
        .map(|r| r.try_exists().unwrap_or(false))
        .unwrap_or(false);

    let mut views = Vec::with_capacity(entries.len());
    for e in entries {
        let (path, entry_exists) = match &root {
            Some(r) => {
                let p = r.join(e.rel);
                let exists = p.try_exists().unwrap_or(false);
                (p, exists)
            }
            None => (PathBuf::new(), false),
        };
        let children = if e.enumerate != Enumerate::None && entry_exists {
            enumerate(&path, e.enumerate, live_ids, current_id)
        } else {
            Vec::new()
        };
        views.push(EntryView {
            label: e.label,
            path,
            desc: e.desc,
            exists: entry_exists,
            children,
        });
    }

    BaseView {
        label,
        env_hint,
        root,
        exists,
        entries: views,
    }
}

/// List the on-disk children of `dir` that match `what`: subdirectories (`Dirs`),
/// `*.toml` profile files (`Profiles`, with the suffix stripped to show the app name), or
/// per-project runtime trees (`Projects`, each classified by liveness, dated, and carrying its
/// recorded project path). Sorted by name for a stable, readable listing. `live_ids` and
/// `current_id` are consulted only by `Projects`.
fn enumerate(
    dir: &Path,
    what: Enumerate,
    live_ids: &BTreeSet<String>,
    current_id: Option<&str>,
) -> Vec<ChildView> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<ChildView> = rd
        .flatten()
        .filter_map(|ent| {
            let raw = ent.file_name();
            let name = raw.to_string_lossy().into_owned();
            let path = ent.path();
            match what {
                Enumerate::Dirs if path.is_dir() => Some(ChildView {
                    name,
                    path,
                    state: None,
                    last_used: None,
                    project_path: None,
                    current: false,
                }),
                Enumerate::Profiles if path.is_file() && name.ends_with(".toml") => {
                    Some(ChildView {
                        name: name.trim_end_matches(".toml").to_string(),
                        path,
                        state: None,
                        last_used: None,
                        project_path: None,
                        current: false,
                    })
                }
                Enumerate::Projects if path.is_dir() => {
                    let class = sandbox::classify_tree(&path, live_ids);
                    Some(ChildView {
                        current: current_id == Some(name.as_str()),
                        name,
                        path,
                        state: Some(class.state.label()),
                        last_used: Some(civil_date(class.last_used)),
                        project_path: class.project_path,
                    })
                }
                _ => None,
            }
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Format a `SystemTime` as a stable `YYYY-MM-DD` (UTC) — the column `sbx path` shows beside each
/// project's liveness state. Civil-from-days-since-epoch via the Howard Hinnant algorithm, so no
/// `chrono` dependency; UTC is the right choice for a date-only column (a local day would shift by
/// your timezone and mislead across a midnight boundary). `UNIX_EPOCH` falls back to `-`.
pub(crate) fn civil_date(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if secs == 0 {
        return "-".to_string();
    }
    let days = (secs / 86_400) as i64;
    // Howard Hinnant's civil-from-days — maps a count of days since 1970-01-01 to a (y, m, d).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Render the layout as aligned, optionally colored text. Mirrors the shape of
/// `sbx config path`'s resolution overview: a header per base, then each entry
/// with its path and a `(present)`/`(absent)`/`(no base)` tag, and enumerated
/// children indented under their parent. Color spans are empty when the palette
/// is plain, so a captured test stream is byte-for-byte plain text.
pub(crate) fn render(view: &PathView, pal: &crate::style::Palette) -> String {
    use std::fmt::Write as _;
    let (h, nm, ok, dim, r) = (pal.head, pal.name, pal.ok, pal.dim, pal.reset);
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{h}sbx on-disk locations{r} {dim}(grouped by XDG base){r}"
    );

    for base in &view.bases {
        let _ = writeln!(o);
        // The base label padded to the widest (`config:`) so the root path column
        // starts aligned; two spaces separate the label column from the path so a
        // label of exactly the column width (e.g. `sessions/`) still has a gap.
        let label = format!("{}:", base.label);
        match &base.root {
            Some(root) => {
                let (state, hue) = if base.exists {
                    ("present", ok)
                } else {
                    ("absent", dim)
                };
                let _ = writeln!(
                    o,
                    "{nm}{:<7}{r}  {}  {hue}({state}){r}  {dim}{}{r}",
                    label,
                    root.display(),
                    base.env_hint,
                );
            }
            None => {
                let _ = writeln!(
                    o,
                    "{nm}{:<7}{r}  {dim}(no base — {}){r}",
                    label, base.env_hint,
                );
                // Without a root the entries have no path to show, so the header's
                // env hint is the whole answer for this base.
                continue;
            }
        }

        let width = base
            .entries
            .iter()
            .map(|e| e.label.len())
            .max()
            .unwrap_or(0);
        for e in &base.entries {
            let (state, hue) = if e.exists {
                ("present", ok)
            } else {
                ("absent", dim)
            };
            let _ = writeln!(
                o,
                "  {nm}{:<width$}{r}  {}  {hue}({state}){r}  {dim}{}{r}",
                e.label,
                e.path.display(),
                e.desc,
            );
            if !e.children.is_empty() {
                let cw = e.children.iter().map(|c| c.name.len()).max().unwrap_or(0);
                for c in &e.children {
                    // Per-project trees carry a liveness state + a last-used date; app homes and
                    // profiles carry neither, so the line ends at the path. The state is colored:
                    // live/idle in ok (green), dead/markerless in dim — the stale hues.
                    match (c.state, c.last_used.as_deref()) {
                        (Some(st), Some(date)) => {
                            let hue = if matches!(st, "live" | "idle") {
                                ok
                            } else {
                                dim
                            };
                            // The project tree line: id, tree path, (state), date, recorded
                            // project path (or "(unknown)" for markerless), and a `*` when it is
                            // the tree of the cwd sbx path was launched from.
                            let proj = c
                                .project_path
                                .as_deref()
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|| "(unknown)".to_string());
                            let cur = if c.current { "  *" } else { "" };
                            let _ = writeln!(
                                o,
                                "    {nm}{:<cw$}{r}  {}  {hue}({st}){r}  {dim}{date}{r}  {dim}{}{r}{cur}",
                                c.name,
                                c.path.display(),
                                proj,
                            );
                        }
                        _ => {
                            let _ =
                                writeln!(o, "    {nm}{:<cw$}{r}  {}", c.name, c.path.display(),);
                        }
                    }
                }
            }
        }
    }

    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "{}",
        crate::style::dim_prose(
            "for the config files in resolution order, see `sbx config path`.",
            pal
        )
    );
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    /// The view must be serializable to a valid JSON document — the `--json`
    /// contract a script relies on. Exercises every base and an enumerated child.
    #[test]
    fn view_serializes_to_valid_json() {
        let data = TmpDir::new();
        let cfg = TmpDir::new();
        let state = TmpDir::new();
        // A data root with a project and a global app home.
        std::fs::create_dir_all(data.path().join("projects").join("abc123")).unwrap();
        std::fs::create_dir_all(data.path().join("apps").join("demo-app")).unwrap();
        // A config root with `sbx.toml` and an imported profile.
        std::fs::write(cfg.path().join("sbx.toml"), "").unwrap();
        std::fs::create_dir_all(cfg.path().join("apps")).unwrap();
        std::fs::write(cfg.path().join("apps").join("demo-tool.toml"), "").unwrap();
        // A state root with a `trusted/` dir.
        std::fs::create_dir_all(state.path().join("trusted")).unwrap();

        let v = view_with_roots(
            Some(data.path().to_path_buf()),
            Some(cfg.path().to_path_buf()),
            Some(state.path().to_path_buf()),
        );
        let json = serde_json::to_string(&v).expect("serialize");
        let doc: serde_json::Value = serde_json::from_str(&json).expect("valid json");

        let bases = doc["bases"].as_array().expect("bases array");
        assert_eq!(bases.len(), 3, "three bases: data, config, state");

        let data_v = &bases[0];
        assert_eq!(data_v["label"], "data");
        assert_eq!(data_v["exists"], true, "data root exists");
        let projects = data_v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == "projects/")
            .expect("projects entry");
        let kids = projects["children"].as_array().expect("children");
        let abc = kids
            .iter()
            .find(|c| c["name"] == "abc123")
            .expect("abc123 project enumerated");
        // A markerless project (no `project` file) reports its state, a last-used date, and no
        // recorded project path (the field is absent — `skip_serializing_if = Option::is_none`).
        assert_eq!(abc["state"], "markerless", "state for a markerless tree");
        assert!(
            abc["last_used"].as_str().is_some_and(|d| d.len() == 10),
            "last_used is a YYYY-MM-DD date: {:?}",
            abc["last_used"]
        );
        assert!(
            abc.get("project_path").is_none(),
            "markerless tree carries no project_path in JSON"
        );
        assert!(
            abc.get("current").is_none(),
            "`current` is absent (false) in JSON"
        );
        let apps = data_v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == "apps/")
            .expect("apps entry");
        assert!(
            apps["children"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["name"] == "demo-app"),
            "enumerated global app home"
        );

        let config_v = &bases[1];
        let sbx_toml = config_v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == "sbx.toml")
            .expect("sbx.toml entry");
        assert_eq!(sbx_toml["exists"], true, "sbx.toml exists");
        let profiles = config_v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == "apps/")
            .expect("apps/ entry");
        assert!(
            profiles["children"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["name"] == "demo-tool"),
            "enumerated profile (suffix stripped)"
        );

        let state_v = &bases[2];
        let trusted = state_v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == "trusted/")
            .expect("trusted/ entry");
        assert_eq!(trusted["exists"], true, "trusted/ exists");
    }

    /// When no data root resolves, the data base reports no root and every entry
    /// is absent — `sbx path` still succeeds and stays useful as a map of intent.
    #[test]
    fn view_with_no_data_root_lists_entries_absent() {
        let v = view_with_roots(None, None, None);
        let data = v
            .bases
            .iter()
            .find(|b| b.label == "data")
            .expect("data base");
        assert!(data.root.is_none(), "no data root");
        assert!(!data.exists);
        assert!(data.entries.iter().all(|e| !e.exists), "all entries absent");
    }

    /// The text render is plain (no ANSI) when the palette is plain — the
    /// captured-stream contract every render in sbx honors.
    #[test]
    fn render_plain_has_no_escapes() {
        let pal = crate::style::Palette::plain();
        let v = view_with_roots(None, None, None);
        let s = render(&v, &pal);
        assert!(!s.contains('\x1b'), "plain render must not emit ANSI");
        assert!(s.contains("sbx on-disk locations"), "header present");
        assert!(s.contains("data"), "data base listed");
        assert!(s.contains("sbx config path"), "cross-reference note");
    }

    /// Enumerated children render indented under their parent, and a directory
    /// entry that does not exist enumerates nothing.
    #[test]
    fn render_lists_enumerated_children_indented() {
        let data = TmpDir::new();
        std::fs::create_dir_all(data.path().join("projects").join("p1")).unwrap();
        std::fs::create_dir_all(data.path().join("projects").join("p2")).unwrap();
        let pal = crate::style::Palette::plain();
        let v = view_with_roots(Some(data.path().to_path_buf()), None, None);
        let s = render(&v, &pal);
        // Both project ids appear, indented (4-space lead) under projects/.
        assert!(s.contains("    p1"), "p1 indented: {s}");
        assert!(s.contains("    p2"), "p2 indented: {s}");
        // Sorted: p1 before p2.
        assert!(s.find("    p1") < s.find("    p2"), "sorted: {s}");
    }

    /// A profile child is shown by app name (`.toml` stripped), not by filename.
    #[test]
    fn enumerate_profiles_strips_the_toml_suffix() {
        let tmp = TmpDir::new();
        let apps = tmp.path().join("apps");
        std::fs::create_dir_all(&apps).unwrap();
        std::fs::write(apps.join("demo-app.toml"), "").unwrap();
        std::fs::write(apps.join("not-a-profile.txt"), "").unwrap();
        let live = BTreeSet::new();
        let kids = enumerate(&apps, Enumerate::Profiles, &live, None);
        assert_eq!(kids.len(), 1, "only .toml files kept");
        assert_eq!(kids[0].name, "demo-app", "suffix stripped");
        assert!(kids[0].path.ends_with("demo-app.toml"), "full path kept");
        // Profiles carry no liveness state — the field is absent.
        assert!(kids[0].state.is_none() && kids[0].last_used.is_none());
    }

    /// `Dirs` enumeration keeps directories and rejects files; `Profiles` does
    /// the inverse — the two never cross.
    #[test]
    fn enumerate_dirs_keeps_only_directories() {
        let tmp = TmpDir::new();
        std::fs::create_dir_all(tmp.path().join("subdir")).unwrap();
        std::fs::write(tmp.path().join("a-file"), "").unwrap();
        let live = BTreeSet::new();
        let kids = enumerate(tmp.path(), Enumerate::Dirs, &live, None);
        assert_eq!(kids.len(), 1, "only the directory kept");
        assert_eq!(kids[0].name, "subdir");
        assert!(kids[0].state.is_none() && kids[0].last_used.is_none());
    }

    /// Per-project trees are classified by liveness (`idle`/`dead`/`markerless`) and carry a
    /// last-used date — the annotation the user asked for. A live one needs a running session
    /// record, which is covered by the gc cross-project test instead.
    #[test]
    fn projects_are_classified_with_state_and_date() {
        let data = TmpDir::new();
        let projects = data.path().join("projects");
        // idle: marker points at a project directory that still exists on disk.
        let real_proj = data.path().join("real-proj");
        std::fs::create_dir_all(&real_proj).unwrap();
        std::fs::create_dir_all(projects.join("idleid")).unwrap();
        std::fs::write(
            projects.join("idleid").join(crate::sandbox::PROJECT_MARKER),
            real_proj.to_string_lossy().as_bytes(),
        )
        .unwrap();
        // dead: marker points at a gone path whose parent still exists (the parent-exists guard
        // is what `project_is_gone` checks).
        let workspace = data.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(projects.join("deadid")).unwrap();
        std::fs::write(
            projects.join("deadid").join(crate::sandbox::PROJECT_MARKER),
            workspace.join("gone-proj").to_string_lossy().as_bytes(),
        )
        .unwrap();
        // markerless: no marker file.
        std::fs::create_dir_all(projects.join("markerlessid")).unwrap();

        let v = view_with_roots(Some(data.path().to_path_buf()), None, None);
        let data_base = v.bases.iter().find(|b| b.label == "data").unwrap();
        let projects_entry = data_base
            .entries
            .iter()
            .find(|e| e.label == "projects/")
            .unwrap();
        let by_name: std::collections::HashMap<&str, &ChildView> = projects_entry
            .children
            .iter()
            .map(|c| (c.name.as_str(), c))
            .collect();
        assert_eq!(by_name["idleid"].state, Some("idle"), "idle");
        assert_eq!(by_name["deadid"].state, Some("dead"), "dead");
        assert_eq!(
            by_name["markerlessid"].state,
            Some("markerless"),
            "markerless"
        );
        // The marker carries the canonical project path, so `sbx path` answers "which project
        // does this id belong to?" for every identified tree — and honestly cannot for a markerless
        // one (`project_path` is `None`).
        assert_eq!(
            by_name["idleid"].project_path.as_deref(),
            Some(real_proj.as_path()),
            "idle tree records its project path"
        );
        assert_eq!(
            by_name["deadid"]
                .project_path
                .as_deref()
                .unwrap()
                .file_name()
                .unwrap(),
            "gone-proj",
            "dead tree still records the gone project path"
        );
        assert!(
            by_name["markerlessid"].project_path.is_none(),
            "markerless tree has no recorded path"
        );
        // Every project child carries a YYYY-MM-DD date (just-created trees → today).
        for c in &projects_entry.children {
            let d = c.last_used.as_deref().expect("date present");
            assert!(
                d.len() == 10 && d.as_bytes()[4] == b'-' && d.as_bytes()[7] == b'-',
                "date shape YYYY-MM-DD: {d}"
            );
        }
    }

    /// The project tree matching the current working directory is marked `current` — so `sbx path`
    /// answers "which of these am I in right now?". A tree whose id is not the cwd's hash is not
    /// marked. Drives the `*` marker in the text render and the `current` boolean in JSON.
    #[test]
    fn the_cwd_project_is_marked_current() {
        let data = TmpDir::new();
        let projects = data.path().join("projects");
        // A project tree that *is* the cwd: write a marker pointing at a real dir, then run the
        // view with the cwd set to that dir. `current_project_id` reads the process cwd, so the
        // test chdirs into the project dir before building the view.
        let here = data.path().join("here-proj");
        std::fs::create_dir_all(&here).unwrap();
        std::fs::create_dir_all(projects.join("hereid")).unwrap();
        std::fs::write(
            projects.join("hereid").join(crate::sandbox::PROJECT_MARKER),
            here.to_string_lossy().as_bytes(),
        )
        .unwrap();
        // An unrelated tree, so the test is discriminating: only `hereid` should be `current`.
        std::fs::create_dir_all(projects.join("otherid")).unwrap();

        let prev = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(&here).expect("chdir into the project");
        // Compute the id sbx will derive for `here`, so the tree's directory name matches it —
        // otherwise `current` would never fire. Rename the tree to that id.
        let id = crate::sandbox::project_id(&here.canonicalize().unwrap());
        std::fs::rename(projects.join("hereid"), projects.join(&id))
            .expect("rename tree to its project id");
        let v = view_with_roots(Some(data.path().to_path_buf()), None, None);
        std::env::set_current_dir(&prev).expect("restore cwd");
        let data_base = v.bases.iter().find(|b| b.label == "data").unwrap();
        let projects_entry = data_base
            .entries
            .iter()
            .find(|e| e.label == "projects/")
            .unwrap();
        let here_child = projects_entry
            .children
            .iter()
            .find(|c| c.name == id)
            .expect("the cwd's tree is enumerated");
        assert!(here_child.current, "the cwd's tree is marked current");
        let other = projects_entry
            .children
            .iter()
            .find(|c| c.name == "otherid")
            .expect("the other tree is enumerated");
        assert!(!other.current, "no other tree is marked current");
    }

    /// `civil_date` renders the epoch as `-` (the fallback) and a known timestamp as the right
    /// calendar date — pinning the algorithm so a future refactor cannot silently drift it.
    #[test]
    fn civil_date_handles_epoch_and_a_known_timestamp() {
        assert_eq!(civil_date(UNIX_EPOCH), "-");
        // 1970-01-02 00:00:01 UTC → day 1 → 1970-01-02.
        let t = UNIX_EPOCH + std::time::Duration::from_secs(86_401);
        assert_eq!(civil_date(t), "1970-01-02");
        // 2026-07-05 00:00:00 UTC → 2026-07-05. A fixed timestamp keeps the test deterministic
        // (no wall-clock dependency): 1_783_209_600 s since the epoch.
        let t = UNIX_EPOCH + std::time::Duration::from_secs(1_783_209_600);
        assert_eq!(civil_date(t), "2026-07-05");
    }
}
