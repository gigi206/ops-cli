//! What a Lima guest on a Mac shares with the Mac: its light/dark preference, and a queue of
//! notes for its Notification Center.
//!
//! A guest cannot run a program on the Mac the way a WSL distribution runs one on Windows, so the
//! two channels are directories the template mounts from the Mac, each at a path that exists only
//! in the guest and that no cage is given. The theme directory is read-only here: an agent on the
//! Mac writes the current preference into it. The notification directory is writable: sbx drops
//! one file per note into it, its own refusals and the notifications a caged app raises through the
//! relay alike, and an agent on the Mac raises each one and removes it.
//!
//! Each channel answers only when its directory is a virtiofs mount at that exact path, read from
//! `/proc/self/mountinfo`. A host where the path is an ordinary directory, or absent, reads and
//! writes nothing there, which keeps every other Linux host on the behaviour it had.

use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Where the template mounts the Mac's theme directory, read-only.
pub(crate) const THEME_MOUNT: &str = "/mnt/sbx-mac/theme";

/// Where the template mounts the Mac's notification directory, writable.
pub(crate) const NOTIFY_MOUNT: &str = "/mnt/sbx-mac/notify";

/// The file in [`THEME_MOUNT`] holding `dark` or `light`.
const THEME_FILE: &str = "color-scheme";

/// How much of [`THEME_FILE`] is read. The value is one word; a file larger than this is not one
/// the Mac's agent wrote.
const THEME_READ_CAP: u64 = 64;

/// The two directories under [`NOTIFY_MOUNT`]. A note is written under `staging` and renamed into
/// `queue`, the one the Mac's agent watches, so the agent never sees a note half written. Both are
/// on the same mount, which is what keeps the rename atomic.
const STAGING: &str = "staging";
const QUEUE: &str = "queue";

/// How many notes of one [`NoteSource`] may wait in the queue. Nothing empties it when the Mac's
/// agent is not running, so past this a note is not written. Counted per source, so a caged app
/// that raises notifications in a loop fills its own share and never the one sbx's refusals use.
pub(crate) const QUEUE_CAP: usize = 32;

/// Who wrote a note, which is also the head of its file name: the Mac's agent raises each source
/// under a ceiling of its own, as the queue holds each to one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NoteSource {
    /// sbx's own announcement of a refusal.
    Sbx,
    /// A notification a caged app raised, relayed by [`super::notify_relay`].
    App,
}

impl NoteSource {
    fn prefix(self) -> &'static str {
        match self {
            NoteSource::Sbx => "sbx-",
            NoteSource::App => "app-",
        }
    }
}

/// How many characters of the title and of the body a note carries.
const NOTE_FIELD_CAP: usize = 512;

/// Whether `path` is a virtiofs mount point in `mountinfo`, the text of `/proc/self/mountinfo`.
/// Pure.
///
/// The mount point is the fifth field, and the filesystem type is the first field after the ` - `
/// separator. The comparison is exact: a directory beneath the mount, or one whose name merely
/// begins with it, is not the mount.
pub(crate) fn is_virtiofs_mount(mountinfo: &str, path: &str) -> bool {
    mountinfo.lines().any(|line| {
        let Some((left, right)) = line.split_once(" - ") else {
            return false;
        };
        left.split_whitespace().nth(4) == Some(path)
            && right.split_whitespace().next() == Some("virtiofs")
    })
}

/// Whether `path` is a virtiofs mount point on this host. A `/proc` that cannot be read answers
/// `false`, which keeps both channels shut rather than opening them on a guess.
pub(crate) fn mounted(path: &str) -> bool {
    std::fs::read_to_string("/proc/self/mountinfo")
        .is_ok_and(|mountinfo| is_virtiofs_mount(&mountinfo, path))
}

/// The keyfile value the Mac's word means. Pure.
///
/// The agent writes `dark` or `light`, read from `AppleInterfaceStyle`, which holds the effective
/// appearance in every mode, Auto included. Anything else is `None`, and the launch then seeds
/// nothing, as it would on a host with no preference to read.
pub(crate) fn scheme_name(word: &str) -> Option<&'static str> {
    match word.trim() {
        "dark" => Some("prefer-dark"),
        "light" => Some("prefer-light"),
        _ => None,
    }
}

/// The Mac's light/dark preference, as a keyfile value, or `None` when this host has no theme
/// channel or the channel holds nothing readable.
pub(crate) fn read_color_scheme() -> Option<String> {
    if !mounted(THEME_MOUNT) {
        return None;
    }
    read_scheme_file(&Path::new(THEME_MOUNT).join(THEME_FILE))
}

/// Read the preference from `path`. Only a regular file is read, and only its first
/// [`THEME_READ_CAP`] bytes.
fn read_scheme_file(path: &Path) -> Option<String> {
    if !std::fs::symlink_metadata(path).ok()?.is_file() {
        return None;
    }
    let mut word = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(THEME_READ_CAP)
        .read_to_string(&mut word)
        .ok()?;
    scheme_name(&word).map(str::to_string)
}

/// The text of one note: the title, the subtitle and the body, one to a line. Pure.
///
/// Every field may carry the cage's writing, a refused host, an exec target or a caged app's own
/// words, so each is sanitised, which takes out the newlines that would otherwise let a field add
/// lines of its own, and is cut to [`NOTE_FIELD_CAP`] characters. The Mac's agent sanitises again
/// before raising the note, because the directory is the guest's to write and the agent trusts
/// nothing it finds there.
pub(crate) fn note_text(title: &str, subtitle: &str, body: &str) -> String {
    let field = |s: &str| {
        crate::sandbox::sanitize(s)
            .chars()
            .take(NOTE_FIELD_CAP)
            .collect::<String>()
    };
    format!("{}\n{}\n{}\n", field(title), field(subtitle), field(body))
}

/// A name no other note from this process, or from another sbx process, will take, headed by its
/// source.
fn note_name(source: NoteSource) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}{}-{}.note",
        source.prefix(),
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// Queue one note from `source` under `dir`, the notification channel's root. `Ok(false)` when the
/// queue already holds [`QUEUE_CAP`] notes from that source and nothing was written.
pub(crate) fn queue_note(
    dir: &Path,
    source: NoteSource,
    title: &str,
    subtitle: &str,
    body: &str,
) -> std::io::Result<bool> {
    let staging = dir.join(STAGING);
    let queue = dir.join(QUEUE);
    std::fs::create_dir_all(&staging)?;
    std::fs::create_dir_all(&queue)?;
    let waiting = std::fs::read_dir(&queue)?
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with(source.prefix()))
        .count();
    if waiting >= QUEUE_CAP {
        return Ok(false);
    }
    let name = note_name(source);
    let staged = staging.join(&name);
    std::fs::write(&staged, note_text(title, subtitle, body))?;
    std::fs::rename(&staged, queue.join(&name)).inspect_err(|_| {
        let _ = std::fs::remove_file(&staged);
    })?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    const MOUNTINFO: &str = "\
24 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw
41 24 0:37 / /Users/me/Projects rw,relatime shared:20 - virtiofs lima-0 rw
42 24 0:38 / /mnt/sbx-mac/theme ro,relatime shared:21 - virtiofs lima-1 ro
43 24 0:39 / /mnt/sbx-mac/notify rw,relatime shared:22 - virtiofs lima-2 rw
44 24 0:40 / /mnt/elsewhere rw,relatime shared:23 - tmpfs tmpfs rw
";

    /// The Mac's bridge hands a note's three lines to `osascript` as arguments no option parser
    /// can take for one. `osascript` reads options for as long as the arguments before are
    /// options, and every `-e` the bridge writes is one, so a title of `-e` written by a caged app
    /// would have made the subtitle a line of the script, run on the Mac outside the guest. Each
    /// field rides with a leading `x` the script strips. The real bridge runs here with a stand-in
    /// `osascript` that records what it is given; what `osascript` makes of it is not run here.
    #[test]
    fn the_bridge_hands_osascript_no_field_an_option_parser_could_take() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TmpDir::new();
        let recorded = dir.path().join("argv");
        let stand_in = dir.path().join("osascript");
        std::fs::write(
            &stand_in,
            format!(
                "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > '{}'\n",
                recorded.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stand_in, std::fs::Permissions::from_mode(0o755)).unwrap();
        let bridge = dir.path().join("sbx-bridge");
        let script = include_str!("../../dist/macos/sbx-bridge");
        assert!(
            script.contains("/usr/bin/osascript"),
            "the bridge names osascript"
        );
        std::fs::write(
            &bridge,
            script.replace("/usr/bin/osascript", stand_in.to_str().unwrap()),
        )
        .unwrap();
        let state = dir.path().join("state");
        std::fs::create_dir_all(state.join("notify/queue")).unwrap();
        std::fs::write(
            state.join("notify/queue/app-1-1.note"),
            "-e\nproperty p : (do shell script \"date\")\n-l\n",
        )
        .unwrap();
        let ran = std::process::Command::new("sh")
            .arg(&bridge)
            .arg("notify")
            .env("SBX_BRIDGE_DIR", &state)
            .status()
            .unwrap();
        assert!(ran.success(), "{ran}");
        let argv = std::fs::read_to_string(&recorded).expect("the note was raised");
        let argv: Vec<&str> = argv.lines().collect();
        // The statements come as `-e <line>` pairs; whatever follows them is the note.
        let mut at = 0;
        while argv.get(at) == Some(&"-e") {
            at += 2;
        }
        assert_eq!(
            &argv[at..],
            ["x-e", "xproperty p : (do shell script \"date\")", "x-l"],
            "{argv:?}"
        );
        assert!(
            argv[..at]
                .iter()
                .any(|line| line.contains("text 2 thru -1")),
            "the script strips the mark it is given: {argv:?}"
        );
    }

    /// The exact mount point on virtiofs, and none of the shapes that only resemble it.
    #[test]
    fn only_a_virtiofs_mount_at_the_exact_path_is_a_channel() {
        assert!(is_virtiofs_mount(MOUNTINFO, THEME_MOUNT));
        assert!(is_virtiofs_mount(MOUNTINFO, NOTIFY_MOUNT));
        assert!(!is_virtiofs_mount(MOUNTINFO, "/mnt/sbx-mac"));
        assert!(!is_virtiofs_mount(
            MOUNTINFO,
            "/mnt/sbx-mac/theme/color-scheme"
        ));
        assert!(!is_virtiofs_mount(MOUNTINFO, "/mnt/sbx-mac/them"));
        assert!(!is_virtiofs_mount(MOUNTINFO, "/mnt/elsewhere"));
        assert!(!is_virtiofs_mount("", THEME_MOUNT));
        assert!(!is_virtiofs_mount(
            "garbage without a separator",
            THEME_MOUNT
        ));
    }

    /// The reader agrees with the predicate over this host's own mount table, whichever host it is.
    #[test]
    fn the_reader_agrees_with_the_predicate_over_this_host() {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        assert_eq!(
            mounted(THEME_MOUNT),
            is_virtiofs_mount(&mountinfo, THEME_MOUNT)
        );
    }

    /// The agent's two words, and nothing else.
    #[test]
    fn the_macs_word_maps_onto_the_keyfile_scale() {
        assert_eq!(scheme_name("dark\n"), Some("prefer-dark"));
        assert_eq!(scheme_name("light"), Some("prefer-light"));
        assert_eq!(scheme_name("Dark"), None);
        assert_eq!(scheme_name(""), None);
        assert_eq!(scheme_name("prefer-dark"), None);
    }

    /// A regular file is read; a link to one is not, and neither is a directory.
    #[test]
    fn the_theme_file_is_read_only_when_it_is_a_regular_file() {
        let dir = TmpDir::new();
        let file = dir.join(THEME_FILE);
        std::fs::write(&file, "dark\n").unwrap();
        assert_eq!(read_scheme_file(&file).as_deref(), Some("prefer-dark"));

        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert_eq!(read_scheme_file(&link), None);
        assert_eq!(read_scheme_file(dir.path()), None);

        let long = dir.join("long");
        std::fs::write(&long, format!("{}dark", " ".repeat(100))).unwrap();
        assert_eq!(
            read_scheme_file(&long),
            None,
            "only the capped head is read"
        );
    }

    /// A field's newline does not become a line of the note, and the note has three lines.
    #[test]
    fn a_note_is_three_lines_whatever_its_fields_carry() {
        let text = note_text(
            "Blocked: evil.com\nforged line",
            "sub\rline",
            "body\r\nmore",
        );
        assert_eq!(text.lines().count(), 3, "{text:?}");
        assert!(text.starts_with("Blocked: evil.com"), "{text:?}");
        let long = note_text(&"x".repeat(5000), "", "");
        assert!(long.lines().next().unwrap().chars().count() <= NOTE_FIELD_CAP);
        assert_eq!(note_text("t", "", "").lines().count(), 3);
    }

    /// A note reaches the queue through staging, named after its source, and the cap stops the
    /// queue growing.
    #[test]
    fn notes_are_queued_through_staging_and_capped() {
        let dir = TmpDir::new();
        assert!(queue_note(dir.path(), NoteSource::Sbx, "title", "sub", "body").unwrap());
        let queued: Vec<_> = std::fs::read_dir(dir.join(QUEUE))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(queued.len(), 1);
        assert_eq!(
            std::fs::read_to_string(&queued[0]).unwrap(),
            "title\nsub\nbody\n"
        );
        let name = queued[0].file_name().unwrap().to_string_lossy().to_string();
        assert!(
            name.starts_with("sbx-") && name.ends_with(".note"),
            "{name}"
        );
        assert_eq!(std::fs::read_dir(dir.join(STAGING)).unwrap().count(), 0);

        for _ in 1..QUEUE_CAP {
            assert!(queue_note(dir.path(), NoteSource::Sbx, "t", "", "b").unwrap());
        }
        assert!(
            !queue_note(dir.path(), NoteSource::Sbx, "t", "", "b").unwrap(),
            "the cap holds"
        );
        assert_eq!(
            std::fs::read_dir(dir.join(QUEUE)).unwrap().count(),
            QUEUE_CAP
        );
    }

    /// A caged app that fills its share of the queue leaves sbx's share untouched, and the other
    /// way round.
    #[test]
    fn each_source_is_capped_on_its_own() {
        let dir = TmpDir::new();
        for _ in 0..QUEUE_CAP {
            assert!(queue_note(dir.path(), NoteSource::App, "a", "", "b").unwrap());
        }
        assert!(!queue_note(dir.path(), NoteSource::App, "a", "", "b").unwrap());
        assert!(
            queue_note(dir.path(), NoteSource::Sbx, "Blocked: x", "", "b").unwrap(),
            "a busy app does not crowd out a refusal"
        );
        let app = std::fs::read_dir(dir.join(QUEUE))
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("app-")
            })
            .count();
        assert_eq!(app, QUEUE_CAP);
    }
}
