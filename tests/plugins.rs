//! What the plugin listings tell a user about where a plugin came from.
//!
//! A manifest is identical whatever the source, so provenance is recorded at install time and read
//! back here end-to-end: `plugins list` names the source of each installed plugin, and the store
//! listings mark which of their entries are already in place. Most of it exercises the built-in
//! store (compiled into the binary — no fetch, no signature), so it runs everywhere; the one case
//! that needs a real remote store builds a signed one in a local git repository and clones it over
//! `file://`, and skips itself when git is not on PATH.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// Where this suite's throwaway fixtures live: the repo's own test tree, overridable with
/// `SBX_TEST_TMPDIR`. Deliberately not the system tmpfs, whose inode budget is machine-wide.
fn fixture_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("SBX_TEST_TMPDIR") {
        return PathBuf::from(dir);
    }
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("target/test-tmp");
    d
}

/// A unique temp dir removed on drop, so the commands' data-dir writes land in a throwaway
/// location instead of the real `$HOME`.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = fixture_root();
        d.push(format!("plugins-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        TmpDir(d)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run `sbx <args>` with a throwaway home (data, state, config all redirected), returning stdout.
/// The stream is a pipe, so the output is plain text and can be asserted verbatim.
fn run(args: &[&str], home: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home)
        .env("XDG_STATE_HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .output()
        .expect("spawn sbx");
    assert!(
        out.status.success(),
        "`sbx {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf-8 stdout")
}

/// A local plugin source directory: a manifest and the executable it names.
fn local_plugin(root: &Path, name: &str, scheme: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("plugin.toml"),
        format!("name=\"{name}\"\ntype=\"resolver\"\nscheme=\"{scheme}\"\nexec=\"resolve\"\n"),
    )
    .unwrap();
    let exec = dir.join("resolve");
    std::fs::write(&exec, "#!/bin/sh\necho secret\n").unwrap();
    std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

#[test]
fn the_listings_say_where_each_installed_plugin_came_from() {
    let home = TmpDir::new();
    let src = TmpDir::new();

    // No store configured: the section is stated as empty rather than omitted — an omitted section
    // reads as "there is nothing to configure here".
    let listing = run(&["plugins", "store", "list"], home.path());
    assert!(
        listing.contains("configured plugin stores: (none)"),
        "an empty section must still be named:\n{listing}"
    );
    assert!(
        listing.contains("sbx plugins store add"),
        "the empty section points at how to add one:\n{listing}"
    );

    // A local install records the directory it was copied from — the only thing that can tell one
    // plugin's provenance from another's, since manifests are identical whatever the source.
    let source = local_plugin(src.path(), "kp", "kp");
    run(
        &["plugins", "install", source.to_str().unwrap()],
        home.path(),
    );
    let list = run(&["plugins", "list"], home.path());
    assert!(
        list.contains(&format!(
            "from: local directory {}",
            std::fs::canonicalize(&source).unwrap().display()
        )),
        "{list}"
    );
    let info = run(&["plugins", "info", "kp"], home.path());
    assert!(
        info.contains("origin:      local directory"),
        "`plugins info` names the source too:\n{info}"
    );

    // Removing it drops the record with the tree.
    run(&["plugins", "rm", "kp"], home.path());
    let list = run(&["plugins", "list"], home.path());
    assert!(
        list.contains("installed resolver plugins: (none)"),
        "{list}"
    );
}

#[test]
fn a_plugin_installed_without_a_record_reads_as_unknown() {
    let home = TmpDir::new();
    let src = TmpDir::new();
    // A plugin placed by hand (or installed before origins were recorded) has no record. The
    // listing must say so plainly instead of guessing a source.
    let source = local_plugin(src.path(), "kp", "kp");
    run(
        &["plugins", "install", source.to_str().unwrap()],
        home.path(),
    );
    std::fs::remove_file(home.path().join("sbx/plugins/.origins/kp.toml")).unwrap();
    let list = run(&["plugins", "list"], home.path());
    assert!(
        list.contains("from: unknown (installed before sbx recorded plugin origins"),
        "{list}"
    );
    // The records directory is bookkeeping, not a plugin: it must not appear as one.
    assert!(!list.contains(".origins"), "{list}");
}

/// Run `sbx <args>` like [`run`], but tolerate any exit status and return the code with both
/// streams — a command that reports a broken state writes to each.
fn run_both(args: &[&str], home: &Path) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home)
        .env("XDG_STATE_HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .output()
        .expect("spawn sbx");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run `sbx <args>` like [`run`], but return the exit code and stderr — the streams a refusal uses.
fn run_failing(args: &[&str], home: &Path) -> (i32, String) {
    let (code, _stdout, stderr) = run_both(args, home);
    (code, stderr)
}

fn git_run(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()
        .expect("spawn git")
        .status
        .success();
    assert!(ok, "git {args:?} failed");
}

#[test]
fn adding_a_store_with_no_trust_anchor_shows_the_key_it_ships_and_configures_nothing() {
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skipping: git is not on PATH");
        return;
    }
    let home = TmpDir::new();
    let repo = TmpDir::new();
    // A real signed store: publish a plugin directory, then commit it so it can be cloned.
    local_plugin(&repo.path().join("plugins"), "kp", "kp");
    let published = run(
        &[
            "plugins",
            "store",
            "publish",
            repo.path().to_str().unwrap(),
            "--key",
            home.path().join("signing-key").to_str().unwrap(),
        ],
        home.path(),
    );
    let key = published
        .lines()
        .find_map(|l| l.strip_prefix("pubkey: "))
        .expect("the published public key")
        .to_string();
    git_run(repo.path(), &["init", "-q"]);
    git_run(repo.path(), &["add", "-A"]);
    git_run(repo.path(), &["commit", "-qm", "store"]);
    let url = format!("file://{}", repo.path().to_str().unwrap());

    // No --key and no --trust: the refusal shows the key the store ships, so the choice is made
    // with the key in view instead of after pinning it.
    let (code, err) = run_failing(
        &["plugins", "store", "add", "--name", "mine", "--url", &url],
        home.path(),
    );
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("this store needs a trust anchor"), "{err}");
    assert!(err.contains(&key), "the shipped key must be shown:\n{err}");
    assert!(
        err.contains(&format!("--key {key}")),
        "the pinning command must be ready to paste:\n{err}"
    );
    assert!(err.contains("--trust"), "{err}");
    assert!(
        err.contains("whoever controls the URL controls the key"),
        "what the shipped key is worth must be stated:\n{err}"
    );

    // Nothing was configured, and no probe residue is left in the data directory.
    let listing = run(&["plugins", "store", "list"], home.path());
    assert!(
        listing.contains("configured plugin stores: (none)"),
        "the refused add must configure nothing:\n{listing}"
    );
    let residue: Vec<_> = std::fs::read_dir(home.path().join("sbx"))
        .expect("the data dir")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(".store-probe-"))
        .collect();
    assert!(residue.is_empty(), "a probe clone leaked: {residue:?}");

    // The key it printed is the one that actually configures the store.
    run(
        &[
            "plugins", "store", "add", "--name", "mine", "--url", &url, "--key", &key,
        ],
        home.path(),
    );
    let listing = run(&["plugins", "store", "list"], home.path());
    assert!(listing.contains("kp  (kp://)"), "{listing}");
    // A key the user supplied carries no caution — and confirming it again is a no-op, not an
    // error.
    assert!(
        !listing.contains("[key not confirmed elsewhere]"),
        "{listing}"
    );
    let verified = run(
        &["plugins", "store", "verify", "mine", "--key", &key],
        home.path(),
    );
    assert!(verified.contains("nothing to confirm"), "{verified}");
}

#[test]
fn confirming_a_key_accepted_on_first_use_ends_the_standing_caution() {
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skipping: git is not on PATH");
        return;
    }
    let home = TmpDir::new();
    let repo = TmpDir::new();
    local_plugin(&repo.path().join("plugins"), "kp", "kp");
    let published = run(
        &[
            "plugins",
            "store",
            "publish",
            repo.path().to_str().unwrap(),
            "--key",
            home.path().join("signing-key").to_str().unwrap(),
        ],
        home.path(),
    );
    let key = published
        .lines()
        .find_map(|l| l.strip_prefix("pubkey: "))
        .expect("the published public key")
        .to_string();
    git_run(repo.path(), &["init", "-q"]);
    git_run(repo.path(), &["add", "-A"]);
    git_run(repo.path(), &["commit", "-qm", "store"]);
    let url = format!("file://{}", repo.path().to_str().unwrap());

    run(
        &[
            "plugins", "store", "add", "--name", "mine", "--url", &url, "--trust",
        ],
        home.path(),
    );
    let listing = run(&["plugins", "store", "list"], home.path());
    assert!(
        listing.contains("[key not confirmed elsewhere]"),
        "{listing}"
    );
    // The marker names the gap; the line under it names the command that closes it.
    assert!(
        listing.contains("confirm its key with: sbx plugins store verify mine"),
        "{listing}"
    );

    // A key that is not this store's changes nothing — the caution stands.
    let (code, err) = run_failing(
        &[
            "plugins",
            "store",
            "verify",
            "mine",
            "--key",
            &"a".repeat(64),
        ],
        home.path(),
    );
    assert_ne!(code, 0, "{err}");
    assert!(err.contains("is not the one you supplied"), "{err}");
    let listing = run(&["plugins", "store", "list"], home.path());
    assert!(
        listing.contains("[key not confirmed elsewhere]"),
        "{listing}"
    );

    // The real key, obtained elsewhere: the caution ends, and what is enforced is unchanged.
    let verified = run(
        &["plugins", "store", "verify", "mine", "--key", &key],
        home.path(),
    );
    assert!(
        verified.contains("the pinned key is the one you supplied"),
        "{verified}"
    );
    let listing = run(&["plugins", "store", "list"], home.path());
    assert!(
        !listing.contains("[key not confirmed elsewhere]"),
        "{listing}"
    );
    assert!(!listing.contains("confirm its key with"), "{listing}");
    let info = run(&["plugins", "store", "info", "mine"], home.path());
    assert!(
        info.contains("a key you supplied out of band, pinned"),
        "{info}"
    );
    assert!(
        info.contains(&key),
        "the pinned key itself is unchanged:\n{info}"
    );
    // The store still works: its catalogue is intact and its plugin still installable.
    run(&["plugins", "store", "install", "mine", "kp"], home.path());
    let list = run(&["plugins", "list"], home.path());
    assert!(list.contains("from: store 'mine'"), "{list}");
}

/// Publish a signed store into `repo` with `key_file`, commit it, and return (url, pubkey).
fn signed_store(home: &Path, repo: &Path, key_file: &str, rev: Option<&str>) -> (String, String) {
    let mut args = vec![
        "plugins",
        "store",
        "publish",
        repo.to_str().unwrap(),
        "--key",
        key_file,
    ];
    if let Some(rev) = rev {
        args.push("--rev");
        args.push(rev);
    }
    let published = run(&args, home);
    let key = published
        .lines()
        .find_map(|l| l.strip_prefix("pubkey: "))
        .expect("the published public key")
        .to_string();
    if !repo.join(".git").exists() {
        git_run(repo, &["init", "-q"]);
    }
    git_run(repo, &["add", "-A"]);
    git_run(repo, &["commit", "-qm", "publish"]);
    (format!("file://{}", repo.to_str().unwrap()), key)
}

/// Write a plugin with an explicit version and resolver body, over whatever was there — the shape a
/// store republishes.
fn versioned_plugin(root: &Path, name: &str, scheme: &str, version: &str, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("plugin.toml"),
        format!(
            "name=\"{name}\"\ntype=\"resolver\"\nscheme=\"{scheme}\"\nexec=\"resolve\"\n\
             version=\"{version}\"\n"
        ),
    )
    .unwrap();
    let exec = dir.join("resolve");
    std::fs::write(&exec, format!("#!/bin/sh\nprintf '{body}'\n")).unwrap();
    std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn upgrading_follows_the_digest_and_keeps_what_is_installed_when_it_cannot() {
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skipping: git is not on PATH");
        return;
    }
    let home = TmpDir::new();
    let repo = TmpDir::new();
    let plugins = repo.path().join("plugins");
    versioned_plugin(&plugins, "kp", "kp", "1.0.0", "one");
    let key = home.path().join("signing-key");
    let (url, pubkey) = signed_store(home.path(), repo.path(), key.to_str().unwrap(), None);
    run(
        &[
            "plugins", "store", "add", "--name", "mine", "--url", &url, "--key", &pubkey,
        ],
        home.path(),
    );
    run(&["plugins", "store", "install", "mine", "kp"], home.path());

    // Nothing has moved: the installed tree is the one the catalogue pins, and the answer names
    // what it was compared against rather than implying a freshness nothing checked.
    let up = run(&["plugins", "upgrade"], home.path());
    assert!(up.contains("already the build store 'mine' lists"), "{up}");
    assert!(up.contains("cached catalogues"), "{up}");

    // The store republishes **under the same version string** — the case no version comparison can
    // see, and the reason the digest is what decides.
    versioned_plugin(&plugins, "kp", "kp", "1.0.0", "two");
    signed_store(home.path(), repo.path(), key.to_str().unwrap(), Some("2"));
    run(&["plugins", "store", "update", "mine"], home.path());

    let listing = run(&["plugins", "store", "list"], home.path());
    assert!(
        listing.contains("[installed v1.0.0, the store lists a different build of v1.0.0]"),
        "{listing}"
    );

    // `--dry-run` reports and installs nothing.
    let installed_exec = home.path().join("sbx/plugins/kp/resolve");
    let dry = run(&["plugins", "upgrade", "--dry-run"], home.path());
    assert!(dry.contains("different build of v1.0.0"), "{dry}");
    assert!(
        std::fs::read_to_string(&installed_exec)
            .unwrap()
            .contains("one"),
        "--dry-run must change nothing"
    );

    let done = run(&["plugins", "upgrade"], home.path());
    assert!(done.contains("upgraded"), "{done}");
    assert!(
        std::fs::read_to_string(&installed_exec)
            .unwrap()
            .contains("two"),
        "the new tree must be in place"
    );
    // The record follows the tree: an upgraded plugin must not read as tampered with.
    let verified = run(&["plugins", "verify"], home.path());
    assert!(verified.contains("unchanged since install"), "{verified}");

    // Now the property the verb exists for. The store offers a newer build, but its cached checkout
    // no longer reproduces the signed digest — so the upgrade is refused, and what is installed must
    // survive it. Doing this with `rm` then install would have left nothing.
    versioned_plugin(&plugins, "kp", "kp", "2.0.0", "three");
    signed_store(home.path(), repo.path(), key.to_str().unwrap(), Some("3"));
    run(&["plugins", "store", "update", "mine"], home.path());
    std::fs::write(
        home.path()
            .join("sbx/stores/mine/checkout/plugins/kp/resolve"),
        "#!/bin/sh\nprintf 'tampered'\n",
    )
    .unwrap();

    let (code, out, err) = run_both(&["plugins", "upgrade"], home.path());
    assert_eq!(code, 1, "{out}{err}");
    assert!(err.contains("does not match the catalogue"), "{err}");
    assert!(
        std::fs::read_to_string(&installed_exec)
            .unwrap()
            .contains("two"),
        "a refused upgrade must leave the installed plugin untouched"
    );
    let verified = run(&["plugins", "verify"], home.path());
    assert!(verified.contains("unchanged since install"), "{verified}");
}

#[test]
fn a_store_that_changes_its_key_is_named_and_rotated_only_deliberately() {
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skipping: git is not on PATH");
        return;
    }
    let home = TmpDir::new();
    let repo = TmpDir::new();
    local_plugin(&repo.path().join("plugins"), "kp", "kp");
    let key1 = home.path().join("key1");
    let (url, first) = signed_store(home.path(), repo.path(), key1.to_str().unwrap(), None);
    run(
        &[
            "plugins", "store", "add", "--name", "mine", "--url", &url, "--key", &first,
        ],
        home.path(),
    );

    // The store re-signs under a new identity.
    let key2 = home.path().join("key2");
    let (_, second) = signed_store(home.path(), repo.path(), key2.to_str().unwrap(), Some("2"));

    // `update` refuses and says exactly what happened, instead of an opaque signature failure.
    let (code, err) = run_failing(&["plugins", "store", "update", "mine"], home.path());
    assert_ne!(code, 0, "{err}");
    assert!(err.contains("has CHANGED"), "{err}");
    assert!(err.contains(&first), "the pinned key is shown:\n{err}");
    assert!(err.contains(&second), "the new key is shown:\n{err}");
    assert!(err.contains("sbx plugins store rekey mine"), "{err}");

    // Rotating without a terminal and without --yes is refused: nothing changes a signing identity
    // unattended by accident.
    let (code, err) = run_failing(
        &["plugins", "store", "rekey", "mine", "--key", &second],
        home.path(),
    );
    assert_ne!(code, 0, "{err}");
    assert!(err.contains("SECURITY"), "the alert is shown first:\n{err}");
    assert!(err.contains("pass --yes"), "{err}");
    let info = run(&["plugins", "store", "info", "mine"], home.path());
    assert!(info.contains(&first), "the pin is untouched:\n{info}");

    // The filter reaches a remote store's entries too, and says when it has none installed.
    let listing = run(&["plugins", "store", "list", "--installed"], home.path());
    assert!(
        listing.contains("mine"),
        "the store is still named:\n{listing}"
    );
    assert!(
        listing.contains("(nothing from this store is installed)"),
        "{listing}"
    );
    assert!(!listing.contains("kp  (kp://)"), "{listing}");

    // With --yes it rotates, and the store verifies against the new key again.
    let out = run(
        &[
            "plugins", "store", "rekey", "mine", "--key", &second, "--yes",
        ],
        home.path(),
    );
    assert!(out.contains("rotated the key of store 'mine'"), "{out}");
    let info = run(&["plugins", "store", "info", "mine"], home.path());
    assert!(info.contains(&second), "{info}");
    assert!(!info.contains(&first), "the old key is gone:\n{info}");
    run(&["plugins", "store", "update", "mine"], home.path());
}

#[test]
fn the_markers_and_the_installed_filter_agree_on_what_is_in_place() {
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skipping: git is not on PATH");
        return;
    }
    let home = TmpDir::new();
    let repo = TmpDir::new();
    let src = TmpDir::new();
    local_plugin(&repo.path().join("plugins"), "kp", "kp");
    local_plugin(&repo.path().join("plugins"), "otp", "otp");
    let key_file = home.path().join("signing-key");
    let (url, key) = signed_store(home.path(), repo.path(), key_file.to_str().unwrap(), None);
    run(
        &[
            "plugins", "store", "add", "--name", "mine", "--url", &url, "--key", &key,
        ],
        home.path(),
    );

    // Nothing installed yet: both entries are offered, and the filter shows the store with none.
    let listing = run(&["plugins", "store", "list"], home.path());
    assert!(listing.contains("kp  (kp://)"), "{listing}");
    assert!(!listing.contains("[installed]"), "{listing}");
    let filtered = run(&["plugins", "store", "list", "--installed"], home.path());
    assert!(
        filtered.contains("mine"),
        "the store is still named:\n{filtered}"
    );
    assert!(
        filtered.contains("(nothing from this store is installed)"),
        "{filtered}"
    );
    assert!(!filtered.contains("kp  (kp://)"), "{filtered}");
    // The install hint belongs to the unfiltered listing: under --installed it answers a question
    // that was not asked.
    assert!(!filtered.contains("(install one with:"), "{filtered}");

    // One installed from the store: it is marked, and the filter keeps it and drops the other.
    run(&["plugins", "store", "install", "mine", "kp"], home.path());
    let listing = run(&["plugins", "store", "list"], home.path());
    let kp_line = listing
        .lines()
        .find(|l| l.trim_start().starts_with("kp  "))
        .expect("the kp entry");
    assert!(kp_line.contains("[installed]"), "{listing}");
    let filtered = run(&["plugins", "store", "list", "--installed"], home.path());
    assert!(filtered.contains("kp  (kp://)"), "{filtered}");
    assert!(!filtered.contains("otp  (otp://)"), "{filtered}");

    // A local plugin taking the *name* of the store's other entry: only one can hold it, so that
    // entry names the holder instead of claiming to be installed.
    let shadow = local_plugin(src.path(), "otp", "other");
    run(
        &["plugins", "install", shadow.to_str().unwrap()],
        home.path(),
    );
    let listing = run(&["plugins", "store", "list"], home.path());
    let otp_line = listing
        .lines()
        .find(|l| l.trim_start().starts_with("otp  "))
        .expect("the otp entry");
    assert!(
        otp_line.contains("[name taken by a local install]"),
        "{listing}"
    );
    assert!(!otp_line.contains("[installed]"), "{listing}");
    // ...and the filter drops it: holding the name is not being installed *from this store*.
    let filtered = run(&["plugins", "store", "list", "--installed"], home.path());
    assert!(!filtered.contains("otp  (otp://)"), "{filtered}");
}

#[test]
fn a_plugin_holding_a_stores_scheme_blocks_that_entry_visibly() {
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skipping: git is not on PATH");
        return;
    }
    let home = TmpDir::new();
    let repo = TmpDir::new();
    let src = TmpDir::new();
    local_plugin(&repo.path().join("plugins"), "kp", "kp");
    let key_file = home.path().join("signing-key");
    let (url, key) = signed_store(home.path(), repo.path(), key_file.to_str().unwrap(), None);
    run(
        &[
            "plugins", "store", "add", "--name", "mine", "--url", &url, "--key", &key,
        ],
        home.path(),
    );

    // A different name, but it claims the scheme the store's entry advertises: the install would be
    // refused on the scheme, which the catalogue alone could never show.
    let squatter = local_plugin(src.path(), "my-kp", "kp");
    run(
        &["plugins", "install", squatter.to_str().unwrap()],
        home.path(),
    );
    let listing = run(&["plugins", "store", "list"], home.path());
    let kp_line = listing
        .lines()
        .find(|l| l.trim_start().starts_with("kp  "))
        .expect("the kp entry");
    assert!(
        kp_line.contains("[scheme kp:// taken by the installed plugin 'my-kp']"),
        "{listing}"
    );

    // A second hand-placed claimant makes the scheme resolve to nothing — but the entry is *more*
    // blocked, not less: the install is refused on the conflict, so the listing must say so rather
    // than fall back to offering it.
    local_plugin(&home.path().join("sbx/plugins"), "other-kp", "kp");
    let listing = run(&["plugins", "store", "list"], home.path());
    let kp_line = listing
        .lines()
        .find(|l| l.trim_start().starts_with("kp  "))
        .expect("the kp entry");
    assert!(
        kp_line.contains("[scheme kp:// in conflict between `my-kp`, `other-kp`]"),
        "{listing}"
    );
}

#[test]
fn a_verb_given_without_its_argument_prints_usage_instead_of_crashing() {
    // Each of these takes exactly one argument, and the dispatch slices the argv past it to reject
    // extras — a slice that is out of range when the argument is simply missing. The user-visible
    // symptom was a panic (exit 101) on the most ordinary typo there is: the verb on its own.
    let home = TmpDir::new();
    for verb in [
        &["plugins", "rm"][..],
        &["plugins", "info"],
        &["plugins", "install"],
        &["plugins", "store", "info"],
        &["plugins", "store", "rm"],
    ] {
        let (code, _out, err) = run_both(verb, home.path());
        assert_ne!(code, 101, "`sbx {}` panicked: {err}", verb.join(" "));
        assert_eq!(code, 2, "`sbx {}`: {err}", verb.join(" "));
        assert!(
            err.contains("usage:"),
            "`sbx {}` must name its usage: {err}",
            verb.join(" ")
        );
    }
    // `verify` is the one whose argument is optional: bare, it checks everything — with nothing
    // installed, that is a clean success, not a usage error.
    let (code, out, err) = run_both(&["plugins", "verify"], home.path());
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("no installed resolver plugins"), "{out}");
}

#[test]
fn plugins_rm_takes_several_names_and_one_failure_spares_the_rest() {
    let home = TmpDir::new();
    let src = TmpDir::new();
    // Two installed plugins on distinct schemes (a scheme claimed twice would disable both).
    let one = local_plugin(src.path(), "demo-one", "one");
    let two = local_plugin(src.path(), "demo-two", "two");
    run(&["plugins", "install", one.to_str().unwrap()], home.path());
    run(&["plugins", "install", two.to_str().unwrap()], home.path());

    // Three names with an absent one in the middle: each plugin is removed on its own, so the
    // failing name is reported without stopping the one after it, and the call exits non-zero.
    let (code, out, err) = run_both(
        &["plugins", "rm", "demo-one", "demo-absent", "demo-two"],
        home.path(),
    );
    assert_eq!(code, 1, "an absent plugin must colour the exit code: {err}");
    assert!(
        err.contains("no installed plugin named `demo-absent`"),
        "the failing name is not the one reported: {err}"
    );
    assert!(
        out.contains("demo-one") && out.contains("demo-two"),
        "both removals must be reported:\n{out}"
    );
    let listing = run(&["plugins", "list"], home.path());
    assert!(
        listing.contains("installed resolver plugins: (none)"),
        "the failing name stopped the batch — the name after it was skipped:\n{listing}"
    );
}

#[test]
fn plugins_rm_rejects_an_unsafe_name_before_removing_anything() {
    let home = TmpDir::new();
    let src = TmpDir::new();
    let one = local_plugin(src.path(), "demo-one", "one");
    run(&["plugins", "install", one.to_str().unwrap()], home.path());

    // A path-shaped name is refused, and the valid name ahead of it is left installed: a removal is
    // destructive, so a typo at the end must not cost the names before it.
    let (code, err) = run_failing(&["plugins", "rm", "demo-one", "../escape"], home.path());
    assert_eq!(code, 1, "an unsafe plugin name must be refused: {err}");
    assert!(
        err.contains("must not start with a dot"),
        "the refusal must be the name check, not a removal that failed at the sink: {err}"
    );
    let listing = run(&["plugins", "list"], home.path());
    assert!(
        listing.contains("demo-one"),
        "a plugin was removed before the unsafe name was rejected:\n{listing}"
    );
}

#[test]
fn a_plugin_edited_after_install_is_reported_by_every_inspection_path() {
    let home = TmpDir::new();
    let src = TmpDir::new();
    let source = local_plugin(src.path(), "kp", "kp");
    run(
        &["plugins", "install", source.to_str().unwrap()],
        home.path(),
    );

    // Freshly installed: the tree matches the digest recorded when it was placed.
    let verified = run(&["plugins", "verify"], home.path());
    assert!(
        verified.contains("kp") && verified.contains("unchanged since install"),
        "{verified}"
    );
    let info = run(&["plugins", "info", "kp"], home.path());
    assert!(
        info.contains("integrity:   unchanged since install"),
        "{info}"
    );

    // Edit the manifest in place — the sharpest case, because it carries the sandbox grant, so the
    // registry would otherwise honor a widened grant without a word.
    let manifest = home.path().join("sbx/plugins/kp/plugin.toml");
    let widened = std::fs::read_to_string(&manifest).unwrap() + "\n[sandbox]\nnetwork=true\n";
    std::fs::write(&manifest, widened).unwrap();

    let list = run(&["plugins", "list"], home.path());
    assert!(list.contains("[modified since install]"), "{list}");
    let info = run(&["plugins", "info", "kp"], home.path());
    assert!(
        info.contains("integrity:   MODIFIED since install"),
        "{info}"
    );
    let (code, out, err) = run_both(&["plugins", "verify"], home.path());
    assert_eq!(code, 1, "a changed tree must fail the check: {out}{err}");
    assert!(out.contains("MODIFIED since install"), "{out}");
    // The claim is bounded where the bad news is read: an integrity indicator mistaken for a
    // security boundary is worse than none.
    assert!(err.contains("detects drift, not an attacker"), "{err}");

    // Reinstalling restores a known tree, and the check goes quiet again.
    run(&["plugins", "rm", "kp"], home.path());
    run(
        &["plugins", "install", source.to_str().unwrap()],
        home.path(),
    );
    let (code, out, _err) = run_both(&["plugins", "verify"], home.path());
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("unchanged since install"), "{out}");

    // A plugin placed by hand was never attested — a distinct answer from "this changed", and it
    // must not fail the command.
    local_plugin(&home.path().join("sbx/plugins"), "handmade", "hm");
    let (code, out, _err) = run_both(&["plugins", "verify"], home.path());
    assert_eq!(code, 0, "an unattested plugin is not a failure: {out}");
    assert!(out.contains("no digest recorded"), "{out}");

    // Exit 1 means "a tree changed", and only that: a name that names nothing is a usage error, so
    // a script branching on the status can tell a tampered plugin from a typo.
    let (code, _out, err) = run_both(&["plugins", "verify", "no-such-plugin"], home.path());
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("no installed plugin named"), "{err}");
}

#[test]
fn a_scheme_claimed_twice_disables_every_claimant_until_one_remains() {
    let home = TmpDir::new();
    let src = TmpDir::new();
    // One plugin installed the supported way…
    let a = local_plugin(src.path(), "vault-a", "vault");
    run(&["plugins", "install", a.to_str().unwrap()], home.path());
    // …and one placed by hand under the data directory, which is the only way to reach a conflict:
    // every install path refuses a scheme that is claimed or contested.
    let plugins_dir = home.path().join("sbx/plugins");
    local_plugin(&plugins_dir, "vault-b", "vault");

    // The listing reports the conflict, names both claimants, and lists neither as resolving.
    let list = run(&["plugins", "list"], home.path());
    assert!(
        list.contains("scheme conflicts") && list.contains("claimed by 2 plugins"),
        "{list}"
    );
    assert!(
        list.contains("vault-a") && list.contains("vault-b"),
        "{list}"
    );
    assert!(
        !list.contains("vault://  vault-a") && !list.contains("vault://  vault-b"),
        "a contested scheme resolves to nothing:\n{list}"
    );

    // `info` answers with the conflict and the way out, and still fails — the scheme is unusable.
    let (code, out, err) = run_both(&["plugins", "info", "vault"], home.path());
    assert_eq!(code, 1, "stdout:\n{out}stderr:\n{err}");
    assert!(
        out.contains("vault-a") && out.contains("vault-b") && out.contains("sbx plugins rm"),
        "{out}"
    );
    assert!(err.contains("claimed by 2 installed plugins"), "{err}");

    // A third claimant is refused: an ambiguous scheme resolves to nothing, so a guard that only
    // asked "does this scheme resolve?" would let the breakage deepen.
    let c = local_plugin(src.path(), "vault-c", "vault");
    let (code, _out, err) = run_both(&["plugins", "install", c.to_str().unwrap()], home.path());
    assert_ne!(code, 0, "{err}");
    assert!(
        err.contains("claimed by more than one installed plugin"),
        "{err}"
    );
    assert!(!plugins_dir.join("vault-c").exists(), "{err}");

    // And the conflict is not a dead end: removing one claimant restores the other.
    run(&["plugins", "rm", "vault-b"], home.path());
    let list = run(&["plugins", "list"], home.path());
    assert!(!list.contains("scheme conflicts"), "{list}");
    assert!(list.contains("vault://  vault-a"), "{list}");
    let info = run(&["plugins", "info", "vault"], home.path());
    assert!(info.contains("scheme:      vault://"), "{info}");
}

/// A signer plugin source directory: a manifest declaring an auth point, and the executable it
/// names.
fn local_signer(root: &Path, name: &str, sets: &str, extra: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("plugin.toml"),
        format!(
            "name=\"{name}\"\ntype=\"signer\"\nexec=\"sign\"\n[signer]\nsets_headers=[\"{sets}\"]\n{extra}"
        ),
    )
    .unwrap();
    let exec = dir.join("sign");
    std::fs::write(&exec, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

/// The one signer manifest field that changes how sbx **forwards** a request rather than what the
/// plugin is shown: declaring it means request bodies to this destination are held before they
/// leave, so it belongs on the page someone reads before installing.
#[test]
fn a_signer_that_asks_for_a_body_digest_says_so_on_its_page() {
    let home = TmpDir::new();
    let src = TmpDir::new();
    let source = local_signer(
        src.path(),
        "demo-digest",
        "Authorization",
        "body_digest=\"sha256\"\n",
    );
    run(
        &["plugins", "install", source.to_str().unwrap()],
        home.path(),
    );
    let info = run(&["plugins", "info", "demo-digest"], home.path());
    assert!(
        info.contains(
            "body:        its sha256 digest, which sbx holds the request body to compute"
        ),
        "{info}"
    );
}

/// The third kind, through the real binary: installed by name, listed as its own section, and
/// inspected by that name rather than by a scheme it does not claim.
#[test]
fn a_signer_installs_under_its_name_and_states_the_auth_point_it_holds() {
    let home = TmpDir::new();
    let src = TmpDir::new();
    let source = local_signer(src.path(), "demo-sigv4", "Authorization", "");
    run(
        &["plugins", "install", source.to_str().unwrap()],
        home.path(),
    );

    let list = run(&["plugins", "list"], home.path());
    assert!(
        list.contains("installed signer plugins:") && list.contains("sets Authorization"),
        "the listing names the kind and what the plugin may put on a request:\n{list}"
    );

    // Named by its name, and by nothing else: a signer claims no `scheme://`.
    let info = run(&["plugins", "info", "demo-sigv4"], home.path());
    assert!(info.contains("signer plugin: demo-sigv4"), "{info}");
    assert!(
        info.contains("sets:        Authorization"),
        "the detail view states the bound on what it may write:\n{info}"
    );
    assert!(
        info.contains("the method, the host and the target only"),
        "and what of the request it is shown:\n{info}"
    );
    assert!(
        info.contains("a marker standing in for it"),
        "and that the plaintext stays out of it by default:\n{info}"
    );
    assert!(
        !info.contains("body:"),
        "a signer that asks for no body digest says nothing about bodies:\n{info}"
    );

    // A plugin's name is one namespace across the kinds reached by it. A broker answering to the
    // same name is placed by hand under another directory, which is the only way to reach the
    // state: every install path refuses a name another plugin already holds.
    let plugins_dir = home.path().join("sbx/plugins");
    let clash = plugins_dir.join("also-demo");
    std::fs::create_dir_all(&clash).unwrap();
    std::fs::write(
        clash.join("plugin.toml"),
        "name=\"demo-sigv4\"\ntype=\"broker\"\nexec=\"broker\"\n[broker]\n\
         cage_env=[\"DEMO_SOCK\"]\nframing=\"line\"\nmax_frame=1024\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let exec = clash.join("broker");
        std::fs::write(&exec, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Both are disabled, and the name answers as neither.
    let (code, out, err) = run_both(&["plugins", "info", "demo-sigv4"], home.path());
    assert_ne!(code, 0, "stdout:\n{out}stderr:\n{err}");
    assert!(
        err.contains("claimed by 2 installed plugins"),
        "`info` says why the name reaches nothing:\n{err}"
    );
    assert!(
        out.contains("also-demo") && out.contains("sbx plugins rm"),
        "and names every claimant with the way out:\n{out}"
    );

    let listing = run(&["plugins", "list"], home.path());
    assert!(
        listing.contains("name conflicts") && listing.contains("claimed by 2 plugins"),
        "the listing reports the conflict as the state it is:\n{listing}"
    );
    assert!(
        listing.contains("also-demo") && listing.contains("demo-sigv4"),
        "and names every claimant to remove:\n{listing}"
    );
    assert!(
        !listing.contains("installed signer plugins:"),
        "a contested name resolves to nothing, so nothing lists as a signer:\n{listing}"
    );
}
