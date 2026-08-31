//! `sbx store`: what sbx's data directory occupies on disk, subtree by subtree.
//!
//! The missing third of the footprint picture. `sbx app list` accounts for the app homes and
//! `sbx projects list` for the per-project runtime trees, but the shared nix store — routinely the
//! largest single tree — had no inspection verb at all: `sbx gc` reports only what is *reclaimable*,
//! never what is *there*. This reports the whole data directory, so nothing is unaccounted for.
//!
//! Cheap and all but read-only: a filesystem walk, no nix, no network, no sandbox. The one thing
//! it writes is the reflink probe — a pair of small files created in the data directory and removed
//! again — which is what decides whether the reported sizes are exact or an upper bound. Both
//! figures come from [`sandbox::tree_usage`], so a hardlinked file counts once — which matters here
//! above all, since a nix store deduplicates identical content into `.links`.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use crate::{diag, help, layout_or_fail, paths, print_json, sandbox, storage, store, style};

/// One top-level subtree of the data directory.
#[derive(serde::Serialize)]
struct SubtreeView {
    /// The entry's name as it appears in the data directory, directories with a trailing slash.
    label: String,
    bytes: u64,
    /// Rendered size, so a consumer of `--json` need not reimplement the units.
    size: String,
    inodes: u64,
    /// What the subtree is for, when it is one of the directories sbx documents.
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<&'static str>,
}

/// The whole report.
#[derive(serde::Serialize)]
struct StoreView {
    data_dir: String,
    bytes: u64,
    size: String,
    inodes: u64,
    /// Whether the data directory's filesystem shares storage between files (reflink/copy-on-write).
    /// When it does, the reported sizes are upper bounds rather than exact; when it does not, each
    /// file's blocks are its own and the sizes are exact.
    ///
    /// `None` when the probe could not be carried out — an unwritable data directory, or a
    /// filesystem with no room left for the probe file. That is not an answer, and reading it as
    /// "does not share" would print the strongest possible claim about the sizes ("they are exact")
    /// precisely where the filesystem is least able to say so. This is a report, so it states the
    /// unknown; the sibling `Preflight` probe keeps the same three-valued answer for the same
    /// reason.
    shares_storage: Option<bool>,
    subtrees: Vec<SubtreeView>,
    /// The shared nix store's own detail, absent until it has been provisioned.
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_store: Option<SharedStoreView>,
    /// When sbx's data lives in a storage volume, what that volume's image really costs the host.
    /// Absent on a plain data directory. Distinct from the tree sizes above, which are apparent:
    /// this is the sparse image's actual on-disk footprint, after btrfs compression and sharing.
    #[serde(skip_serializing_if = "Option::is_none")]
    volume: Option<VolumeView>,
}

/// The storage volume backing the data directory, when there is one.
#[derive(serde::Serialize)]
struct VolumeView {
    /// The image file on the host — where the volume actually lives.
    image: String,
    /// Bytes the image occupies on the host: the true cost, after compression and block sharing.
    host_bytes: u64,
    /// Rendered `host_bytes`, so `--json` need not reimplement the units.
    host_size: String,
}

/// The shared nix store, described in its own terms rather than as a plain directory.
#[derive(serde::Serialize)]
struct SharedStoreView {
    /// Realised store paths (the `.links` dedup pool is not one of them).
    paths: u64,
    /// Entries in nix's `.links` pool. A populated pool means identical files across the store
    /// already share one inode.
    deduplicated_files: u64,
}

/// `sbx store` — report sbx's on-disk footprint.
pub(crate) fn store_cmd(args: Vec<OsString>) -> ExitCode {
    if let Some(code) = help::maybe_help("store", &args) {
        return code;
    }
    let mut json = false;
    for a in &args {
        match a.to_str() {
            Some("--json") => json = true,
            Some(other) => {
                diag::error(&format!("sbx: store: unknown argument `{other}`"));
                diag::hint("       run `sbx help store` for usage.");
                return ExitCode::from(2);
            }
            None => {
                diag::error("sbx: store: argument is not valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    let layout = match layout_or_fail() {
        Ok(l) => l,
        Err(code) => return code,
    };
    let mut view = build(layout.data_dir(), &layout.store_dir());
    view.volume = volume_view();

    if json {
        if let Err(code) = print_json("store", &view) {
            return code;
        }
        return ExitCode::SUCCESS;
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render(&view, &pal));
    ExitCode::SUCCESS
}

/// Measure the data directory: every top-level entry, largest first.
fn build(data_dir: &Path, store_dir: &Path) -> StoreView {
    let mut subtrees: Vec<SubtreeView> = match std::fs::read_dir(data_dir) {
        Ok(rd) => rd
            .flatten()
            .map(|e| {
                let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                let name = e.file_name().to_string_lossy().into_owned();
                let usage = sandbox::tree_usage(&e.path());
                SubtreeView {
                    label: if is_dir { format!("{name}/") } else { name },
                    bytes: usage.bytes,
                    size: sandbox::human_bytes(usage.bytes),
                    inodes: usage.inodes,
                    purpose: paths::data_entry_purpose(&e.file_name().to_string_lossy()),
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    // Largest first: the point of the report is to show where the space went.
    subtrees.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.label.cmp(&b.label)));

    let bytes = subtrees.iter().map(|s| s.bytes).sum();
    StoreView {
        data_dir: data_dir.display().to_string(),
        bytes,
        size: sandbox::human_bytes(bytes),
        inodes: subtrees.iter().map(|s| s.inodes).sum(),
        // Probe the real filesystem, capability rather than name, so the honesty of the sizes is
        // decided by what this filesystem actually does — not a hardcoded list of filesystem types.
        // `reflink_verdict` rather than `supports_reflink`: the latter collapses "could not probe"
        // into "does not share", which is the answer a caller about to *copy* needs and the wrong
        // one for a caller about to *describe*.
        shares_storage: sandbox::reflink_verdict(data_dir),
        subtrees,
        shared_store: shared_store_view(store_dir),
        // Filled in by the caller, which has the environment `build` deliberately does not touch.
        volume: None,
    }
}

/// The storage volume sbx is currently following, if any — for the real host cost of its image.
///
/// Only when sbx is *following* a volume: an explicit `SBX_DATA_DIR` override runs against that
/// directory directly, not through a volume pointer, so it reports no volume even if an image and
/// its pointer happen to exist. The pointer and image live in the default (unfollowed) data
/// directory, which stays reachable after a pointer has redirected everything else.
fn volume_view() -> Option<VolumeView> {
    if store::data_dir_overridden() {
        return None;
    }
    let default_dir = store::Layout::default_data_dir()?;
    let image = storage::read_pointer(&default_dir)?;
    let host_bytes = storage::image_bytes(&image)?;
    Some(VolumeView {
        image: image.display().to_string(),
        host_bytes,
        host_size: sandbox::human_bytes(host_bytes),
    })
}

/// Count the shared store's realised paths and its dedup pool. `None` before the store exists.
fn shared_store_view(store_dir: &Path) -> Option<SharedStoreView> {
    let nix_store = store_dir.join("nix/store");
    let entries = std::fs::read_dir(&nix_store).ok()?;
    let mut paths = 0;
    for entry in entries.flatten() {
        // `.links` is nix's dedup pool, not a realised store path.
        if entry.file_name() == ".links" {
            continue;
        }
        paths += 1;
    }
    let deduplicated_files = std::fs::read_dir(nix_store.join(".links"))
        .map(|rd| rd.flatten().count() as u64)
        .unwrap_or(0);
    Some(SharedStoreView {
        paths,
        deduplicated_files,
    })
}

/// Render the report as aligned text.
fn render(v: &StoreView, pal: &style::Palette) -> String {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let mut s = String::new();

    let _ = writeln!(
        s,
        "{h}sbx store{r} {dim}— {} ({}, {} inodes){r}",
        v.data_dir,
        v.size,
        thousands(v.inodes)
    );
    // On a volume the header size is apparent; the image's real host cost is the number that
    // answers "what does this actually take on my disk", so state it plainly, right at the top.
    if let Some(vol) = &v.volume {
        let _ = writeln!(
            s,
            "  {dim}btrfs volume — {r}{}{dim} on host ({}){r}",
            vol.host_size, vol.image
        );
    }
    if v.subtrees.is_empty() {
        let _ = writeln!(s, "  {dim}(nothing provisioned yet){r}");
        return s;
    }

    let label_w = v.subtrees.iter().map(|t| t.label.len()).max().unwrap_or(0);
    let size_w = v.subtrees.iter().map(|t| t.size.len()).max().unwrap_or(0);
    let inode_w = v
        .subtrees
        .iter()
        .map(|t| thousands(t.inodes).len())
        .max()
        .unwrap_or(0);
    for t in &v.subtrees {
        let purpose = t.purpose.unwrap_or("");
        let unit = if t.inodes == 1 { "inode " } else { "inodes" };
        let _ = writeln!(
            s,
            "  {n}{label:<label_w$}{r}  {size:>size_w$}  {dim}{inodes:>inode_w$} {unit}{r}  {dim}{purpose}{r}",
            label = t.label,
            size = t.size,
            inodes = thousands(t.inodes),
        );
    }

    if let Some(store) = &v.shared_store {
        let _ = writeln!(
            s,
            "\n  {}",
            style::prose(
                &format!(
                    "shared store: {} realised path(s), {} file(s) deduplicated into `.links`",
                    thousands(store.paths),
                    thousands(store.deduplicated_files),
                ),
                pal
            )
        );
    }

    // How honest the sizes are depends on the filesystem, so say only what is true of this one. A
    // hardlinked file is always counted once (essential for a nix store, which deduplicates into
    // `.links`). Whether a size is exact or an upper bound depends on whether the filesystem shares
    // storage between files: where it does, a store seeded by a copy-on-write clone reports its full
    // size though it shares most of its storage with the store it was seeded from — and the true
    // footprint is smaller still if the filesystem compresses. No per-file measurement can see
    // either saving, so the honest thing is to state the bound, not invent a number. And where the
    // probe could not run at all, the honest thing is to say that rather than pick a side: the two
    // definite sentences are the strongest claims this report makes about its own numbers.
    match v.shares_storage {
        Some(true) => {
            let _ = writeln!(
                s,
                "{dim}sizes count allocated blocks and a hardlinked file once. this filesystem shares\n  \
                 storage between files, so each size is an upper bound — the real footprint is smaller\n  \
                 (more so if the filesystem compresses).{r}"
            );
        }
        Some(false) => {
            let _ = writeln!(
                s,
                "{dim}sizes count allocated blocks and a hardlinked file once; on this filesystem they are exact.{r}"
            );
        }
        None => {
            let _ = writeln!(
                s,
                "{dim}sizes count allocated blocks and a hardlinked file once. whether this filesystem\n  \
                 shares storage between files could not be probed, so each size may be an upper bound.{r}"
            );
        }
    }
    let _ = writeln!(
        s,
        "{}",
        style::dim_prose(
            "reclaim with `sbx gc --all --prune`, `sbx projects rm <id>`, `sbx app rm <name> --purge`.",
            pal
        )
    );
    s
}

/// Group a count in threes (`613802` → `613 802`) — six-digit inode counts are the norm here, and
/// unseparated they are hard to compare down a column.
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    #[test]
    fn thousands_groups_in_threes() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1 000");
        assert_eq!(thousands(613_802), "613 802");
        assert_eq!(thousands(1_234_567), "1 234 567");
    }

    /// The report ranks subtrees by size and describes the store in its own terms: realised paths
    /// exclude the `.links` dedup pool, which is reported separately.
    #[test]
    fn build_ranks_subtrees_and_reads_the_stores_own_shape() {
        let tmp = TmpDir::new();
        let data = tmp.path().join("data");
        let nix_store = data.join("store/nix/store");
        std::fs::create_dir_all(nix_store.join(".links")).unwrap();
        std::fs::create_dir_all(nix_store.join("aaa-pkg")).unwrap();
        std::fs::create_dir_all(nix_store.join("bbb-pkg")).unwrap();
        std::fs::write(nix_store.join(".links/hash1"), b"x").unwrap();
        // A second subtree, deliberately larger than the store so the ordering is observable.
        std::fs::create_dir_all(data.join("apps")).unwrap();
        std::fs::write(data.join("apps/blob"), vec![b'x'; 200_000]).unwrap();

        let v = build(&data, &data.join("store"));

        assert_eq!(v.subtrees.first().map(|t| t.label.as_str()), Some("apps/"));
        assert!(v.subtrees.iter().any(|t| t.label == "store/"));
        assert_eq!(v.inodes, v.subtrees.iter().map(|t| t.inodes).sum::<u64>());

        let store = v.shared_store.expect("the store directory exists");
        assert_eq!(store.paths, 2, "`.links` is not a realised store path");
        assert_eq!(store.deduplicated_files, 1);
    }

    /// The closing note tells the truth about *this* filesystem: exact where storage is not shared,
    /// an upper bound where it is, and neither of those where the probe could not run. A size we
    /// cannot measure precisely is never invented, and an answer we do not have is never asserted.
    #[test]
    fn the_note_states_whether_sizes_are_exact_or_an_upper_bound() {
        let one = SubtreeView {
            label: "store/".into(),
            bytes: 4096,
            size: "4.0 KiB".into(),
            inodes: 1,
            purpose: None,
        };
        let exact = StoreView {
            data_dir: "/d".into(),
            bytes: 4096,
            size: "4.0 KiB".into(),
            inodes: 1,
            shares_storage: Some(false),
            subtrees: vec![one],
            shared_store: None,
            volume: None,
        };
        let out = render(&exact, &style::Palette::plain());
        assert!(out.contains("exact"), "{out}");
        assert!(!out.contains("upper bound"), "{out}");

        let shared = StoreView {
            shares_storage: Some(true),
            ..exact
        };
        let out = render(&shared, &style::Palette::plain());
        assert!(out.contains("upper bound"), "{out}");
        assert!(
            out.contains("compresses"),
            "the note must flag compression, which no per-file measure sees: {out}"
        );

        // The probe has a third answer, and it is not "does not share". `reflink_verdict` returns
        // `None` when the probe file could not be written — an unwritable data directory, or a
        // filesystem with no room left — which is exactly when someone runs `sbx store`. Collapsed
        // to `false`, that printed "on this filesystem they are exact" for a copy-on-write,
        // compressing filesystem where every size shown is an over-estimate.
        let unprobed = StoreView {
            shares_storage: None,
            ..shared
        };
        let out = render(&unprobed, &style::Palette::plain());
        assert!(
            !out.contains("are exact"),
            "an unprobed filesystem must not be reported as measured exactly: {out}"
        );
        assert!(
            out.contains("could not be probed") && out.contains("may be an upper bound"),
            "the unknown is stated, with what it means for the numbers: {out}"
        );
    }

    /// On a volume the report states the image's real host cost — the number a plain per-file
    /// tree size cannot show, since it is post-compression and post-sharing. Absent otherwise.
    #[test]
    fn a_volume_reports_its_images_real_host_cost() {
        let one = SubtreeView {
            label: "store/".into(),
            bytes: 4096,
            size: "4.0 KiB".into(),
            inodes: 1,
            purpose: None,
        };
        let base = StoreView {
            data_dir: "/run/media/you/sbx-storage".into(),
            bytes: 4096,
            size: "4.0 KiB".into(),
            inodes: 1,
            shares_storage: Some(true),
            subtrees: vec![one],
            shared_store: None,
            volume: None,
        };

        // Without a volume, no such line.
        let out = render(&base, &style::Palette::plain());
        assert!(!out.contains("on host"), "{out}");

        let on_volume = StoreView {
            volume: Some(VolumeView {
                image: "/home/you/.local/share/sbx-storage.btrfs".into(),
                host_bytes: 603_979_776,
                host_size: "576.0 MiB".into(),
            }),
            ..base
        };
        let out = render(&on_volume, &style::Palette::plain());
        assert!(out.contains("576.0 MiB on host"), "{out}");
        assert!(
            out.contains("/home/you/.local/share/sbx-storage.btrfs"),
            "the image path is named so the number is traceable: {out}"
        );
    }

    /// Before anything is provisioned the report is empty rather than an error, and it never
    /// invents a shared store.
    #[test]
    fn an_empty_data_directory_reports_nothing_provisioned() {
        let tmp = TmpDir::new();
        let data = tmp.path().join("empty");
        std::fs::create_dir_all(&data).unwrap();

        let v = build(&data, &data.join("store"));

        assert!(v.subtrees.is_empty());
        assert_eq!(v.bytes, 0);
        assert!(v.shared_store.is_none());
        let out = render(&v, &style::Palette::plain());
        assert!(out.contains("nothing provisioned yet"), "{out}");
    }
}
