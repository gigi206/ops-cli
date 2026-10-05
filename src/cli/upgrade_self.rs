//! `sbx upgrade self`: replace the running sbx with what the release it was published as serves
//! now.
//!
//! The release is the one stamped into the build ([`crate::release`]). A rolling tag (`latest`,
//! `nightly`) is fetched again; a version tag is followed to the newest stable release. A build from
//! source carries no release and is refused, and so is a binary its user cannot replace: the Lima
//! guest's, which provisioning installs as root, or one a package manager placed.
//!
//! The steps are `install.sh`'s, through the fetcher sbx already drives. The `.sha256` published
//! beside the asset is read first, always afresh, since a rolling tag keeps its address while its
//! content changes. When it names the bytes running now, nothing is downloaded. Otherwise the asset
//! is fetched into sbx's store with that digest handed to nix, so a mismatched download never lands.
//! Its copy is written beside the binary, run once with `--version`, and renamed over it only if
//! that run succeeds: a binary that cannot run here never replaces one that can.
//!
//! What the checksum proves is integrity, not authenticity. It comes from the same release as the
//! binary, so it catches a download corrupted or cut short, not a release that was tampered with,
//! which is the limit `install.sh` states for the same check. Like every fetch nix makes for sbx, a
//! redirect may also leave `https://` without a word (see [`crate::sandbox::nixhub::fetch_url_text`]).
//!
//! The rename gives the path a new file and leaves the old one to whatever still runs it, so a
//! session started before the upgrade goes on with the sbx it started with until it ends.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::release::{self, Channel, Release};
use crate::sandbox::{atomicfile, nixhub};
use crate::store::{self, Layout};
use crate::{diag, layout_or_fail};

/// Where a release's files are fetched from.
struct Source {
    /// The base of the download addresses: `<download>/<tag>/<asset>`.
    download: String,
    /// The base of the releases API, whose `<api>/latest` names the newest stable release.
    api: String,
}

impl Source {
    /// The addresses GitHub serves `repo`'s releases at, the ones `install.sh` uses.
    fn github(repo: &str) -> Self {
        Self {
            download: format!("https://github.com/{repo}/releases/download"),
            api: format!("https://api.github.com/repos/{repo}/releases"),
        }
    }
}

/// The asset a release publishes for this binary's architecture, named as `install.sh` names it.
fn asset() -> String {
    format!("sbx-linux-{}", std::env::consts::ARCH)
}

/// What one run found, and what it did about it.
#[derive(Debug, PartialEq)]
enum Outcome {
    /// The release serves the bytes running now.
    Current,
    /// A version tag that no stable release ranks above: `newest` is the newest one.
    NoNewer { newest: String },
    /// The binary was replaced, and the new one reports `to` as its version.
    Replaced { to: String },
}

/// One upgrade: which release to follow, through which tools, and which file it replaces.
struct Upgrade<'a> {
    release: Release,
    source: Source,
    nix: &'a Path,
    layout: &'a Layout,
    /// The file the new binary is renamed over.
    target: &'a Path,
    /// The bytes running now, hashed to tell whether the release still serves them:
    /// `/proc/self/exe`, which names them even when the path has moved on.
    running: &'a Path,
}

/// `sbx upgrade self`: find the binary to replace, then fetch and install what its release serves.
pub(crate) fn upgrade_self_cmd() -> ExitCode {
    let Some(release) = release::PUBLISHED else {
        diag::error(
            "sbx: upgrade self: this sbx was built from source rather than published as a \
             release, so there is no release for it to follow. Rebuild it from its source, or \
             install a published build with the installation script.",
        );
        return ExitCode::FAILURE;
    };
    let target = match replaceable_target() {
        Ok(target) => target,
        Err(why) => {
            diag::error(&format!("sbx: upgrade self: {why}"));
            return ExitCode::FAILURE;
        }
    };
    let layout = match layout_or_fail() {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let nix = match store::try_resolve_nix(Some(&layout)) {
        Ok(nix) => nix,
        Err(miss) => {
            diag::error(&format!(
                "sbx: upgrade self: {}, and the download goes through it. See `sbx doctor`.",
                miss.clause("nix")
            ));
            return ExitCode::FAILURE;
        }
    };
    let from = release::version_line();
    let run = Upgrade {
        release,
        source: Source::github(release.repo),
        nix: &nix,
        layout: &layout,
        target: &target,
        running: Path::new("/proc/self/exe"),
    };
    match upgrade(&run) {
        Ok(Outcome::Current) => {
            outln!(
                "sbx is up to date: `{}` serves this build, {from}.",
                release.tag
            );
        }
        Ok(Outcome::NoNewer { newest }) => {
            outln!(
                "sbx is up to date: no stable release ranks above {}, and the newest is {newest}.",
                release.tag
            );
        }
        Ok(Outcome::Replaced { to }) => {
            outln!("sbx: replaced {}: {from} → {to}", target.display());
            let running = crate::session::Registry::at(layout.data_dir())
                .live()
                .map_or(0, |live| live.len());
            if running > 0 {
                diag::note(&format!(
                    "the sessions already running ({running}) keep the sbx they started with \
                     until they end; `sbx session ls` lists them."
                ));
            }
        }
        Err(why) => {
            diag::error(&format!("sbx: upgrade self: {why}"));
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

/// The file this process was started from, when its user can replace it.
fn replaceable_target() -> Result<PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot locate the running sbx binary: {e}"))?;
    // The kernel names a file replaced or removed since the process started with this suffix.
    if exe.as_os_str().to_string_lossy().ends_with(" (deleted)") {
        return Err(format!(
            "the file this sbx was started from has been replaced or removed since ({}); run the \
             sbx installed now",
            exe.display()
        ));
    }
    let dir = exe.parent().unwrap_or_else(|| Path::new("/"));
    if !writable(dir) {
        let remedy = if crate::sandbox::lima_mac::mounted(crate::sandbox::lima_mac::NOTIFY_MOUNT) {
            "in the Lima guest, provisioning installs the release the instance was created with \
             each time it starts, so restart it from the Mac (limactl stop sbx && limactl start \
             sbx), which brings a rolling one such as latest to its newest build"
        } else {
            "replace it the way it was installed"
        };
        return Err(format!(
            "{} is in a directory you cannot write ({}); {remedy}",
            exe.display(),
            dir.display()
        ));
    }
    Ok(exe)
}

/// Whether this process may create and rename entries in `dir`.
fn writable(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let Ok(path) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `access` only reads the NUL-terminated path it is given.
    unsafe { libc::access(path.as_ptr(), libc::W_OK | libc::X_OK) == 0 }
}

/// Fetch what `run.release` serves now and install it over `run.target`, unless it is what runs.
fn upgrade(run: &Upgrade) -> Result<Outcome, String> {
    let channel = run.release.channel();
    let tag = match channel {
        Channel::Rolling(tag) => tag.to_string(),
        Channel::Stable => {
            let newest = newest_stable(run)?;
            if crate::version::version_order(&newest, run.release.tag)
                != Some(std::cmp::Ordering::Greater)
            {
                return Ok(Outcome::NoNewer { newest });
            }
            newest
        }
    };
    // A rolling tag is republished by deleting its release and creating it again, and between the
    // two it serves nothing, or an asset beside the previous build's checksum. Said with every
    // failure to fetch one, since that window is the likeliest cause and waiting is its remedy.
    let in_flux = |e: io::Error| match channel {
        Channel::Rolling(_) => format!(
            "{e}. `{tag}` is published again on every build, and serves nothing whole while that \
             runs; try again in a few minutes"
        ),
        Channel::Stable => e.to_string(),
    };

    let asset = asset();
    let url = format!("{}/{tag}/{asset}", run.source.download);
    let sums = nixhub::fetch_url_text(run.nix, run.layout, &format!("{url}.sha256"), true)
        .map_err(in_flux)?;
    let expected = parse_checksum(&sums)
        .ok_or_else(|| format!("the checksum `{tag}` publishes for {asset} is not a SHA-256"))?;
    if matches!(channel, Channel::Rolling(_)) {
        let running = std::fs::read(run.running)
            .map_err(|e| format!("cannot read the running binary to compare it: {e}"))?;
        if crate::trust::hash_bytes(&running) == expected {
            return Ok(Outcome::Current);
        }
    }

    let fetched = crate::sandbox::prefetch_file(run.nix, run.layout, &url, true, Some(expected))
        .map_err(in_flux)?;
    let bytes = std::fs::read(store::physical_path(run.layout, &fetched.store_path))
        .map_err(|e| format!("cannot read the downloaded {asset}: {e}"))?;
    let mut to = String::new();
    atomicfile::write_atomic_checked(run.target, &bytes, Some(0o755), |staged| {
        to = version_of(staged)?;
        Ok(())
    })
    .map_err(|e| format!("{} was left as it was: {e}", run.target.display()))?;
    Ok(Outcome::Replaced { to })
}

/// The tag of the newest stable release, as the releases API names it.
fn newest_stable(run: &Upgrade) -> Result<String, String> {
    let url = format!("{}/latest", run.source.api);
    let answer = nixhub::fetch_url_json(run.nix, run.layout, &url, true).map_err(|e| {
        format!("could not look up the newest stable release (none may be published yet): {e}")
    })?;
    match answer.get("tag_name").and_then(|t| t.as_str()) {
        Some(tag) if release::is_tag(tag) => Ok(tag.to_string()),
        _ => Err(format!("{url} names no release tag")),
    }
}

/// The digest a `.sha256` asset holds: its first field, as `sha256sum` writes it.
fn parse_checksum(text: &str) -> Option<&str> {
    let digest = text.split_whitespace().next()?;
    release::is_hex(digest, 64).then_some(digest)
}

/// What the binary at `path` reports as its version, which is also the proof that it runs here.
fn version_of(path: &Path) -> io::Result<String> {
    let mut command = std::process::Command::new(path);
    command
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // The file was written a moment ago, and a child forked by another thread in that window holds
    // it open for writing until its own `exec`, which makes this one fail with ETXTBSY until then.
    // sbx forks nothing else here, so the loop runs once; a multi-threaded test binary is where it
    // waits.
    let mut tries = 0;
    let out = loop {
        match command.output() {
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && tries < 100 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            other => break other?,
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().next().unwrap_or_default().trim();
    if out.status.success() && line.starts_with("sbx ") {
        Ok(line.to_string())
    } else {
        Err(io::Error::other(format!(
            "the downloaded binary does not run here (`--version` ended with {}: {})",
            out.status,
            diag::one_line(&format!("{line} {}", String::from_utf8_lossy(&out.stderr)))
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TmpDir, output_past_etxtbsy, write_script};
    use std::os::unix::fs::PermissionsExt as _;

    const COMMIT: &str = "0a9ad1c73748cfa9b09d1994ece8a2aaa4ed8fe5";

    /// A release, a stand-in nix that answers from files, and a binary to replace.
    struct Bench {
        dir: TmpDir,
        layout: Layout,
        nix: PathBuf,
        target: PathBuf,
        running: PathBuf,
    }

    impl Bench {
        /// `served` is the binary the release serves, `sums` its `.sha256`, `api` the releases
        /// API's answer. The stand-in records each call's arguments, one line per call.
        fn new(served: &str, sums: &str, api: &str) -> Self {
            let dir = TmpDir::new();
            let layout = Layout::under(&dir.join("data"));
            let logical = "/nix/store/0000000000000000000000000000000a-sbx-linux";
            let physical = store::physical_path(&layout, Path::new(logical));
            std::fs::create_dir_all(physical.parent().unwrap()).unwrap();
            std::fs::write(&physical, served).unwrap();
            std::fs::write(dir.join("sums"), sums).unwrap();
            std::fs::write(dir.join("api.json"), api).unwrap();
            let nix = dir.join("nix");
            write_script(
                &nix,
                &format!(
                    "echo \"$*\" >> '{calls}'\n\
                     case \"$*\" in\n\
                       *' eval '*releases/latest*) cat '{api}' ;;\n\
                       *' eval '*.sha256*) cat '{sums}' ;;\n\
                       *'store prefetch-file'*) \
                         printf '{{\"hash\":\"sha256-AAAA\",\"storePath\":\"{logical}\"}}' ;;\n\
                       *) exit 1 ;;\n\
                     esac",
                    calls = dir.join("calls").display(),
                    api = dir.join("api.json").display(),
                    sums = dir.join("sums").display(),
                ),
            );
            // Run once past the ETXTBSY a just-written executable meets in a multi-threaded test.
            output_past_etxtbsy(std::process::Command::new(&nix).arg("warm"));
            let target = dir.join("bin/sbx");
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(&target, "the old binary").unwrap();
            let running = dir.join("running");
            std::fs::write(&running, "the old binary").unwrap();
            Bench {
                dir,
                layout,
                nix,
                target,
                running,
            }
        }

        fn run(&self, tag: &'static str) -> Result<Outcome, String> {
            upgrade(&Upgrade {
                release: Release {
                    tag,
                    commit: COMMIT,
                    repo: "owner/name",
                },
                source: Source::github("owner/name"),
                nix: &self.nix,
                layout: &self.layout,
                target: &self.target,
                running: &self.running,
            })
        }

        fn calls(&self) -> String {
            std::fs::read_to_string(self.dir.join("calls")).unwrap_or_default()
        }
    }

    /// A stand-in release binary that reports `version` and exits `status`.
    fn binary(version: &str, status: u8) -> String {
        format!("#!/bin/sh\necho '{version}'\nexit {status}\n")
    }

    fn sha256(text: &str) -> String {
        crate::trust::hash_bytes(text.as_bytes())
    }

    /// The target's directory holds the binary and nothing else: no temp left behind.
    fn left_alone(bench: &Bench) -> Vec<String> {
        left_alone_in(&bench.target)
    }

    /// What the directory of `target` holds.
    fn left_alone_in(target: &Path) -> Vec<String> {
        std::fs::read_dir(target.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn a_release_serving_the_running_bytes_downloads_nothing() {
        let bench = Bench::new(
            "unused",
            &format!("{}  sbx-linux\n", sha256("the old binary")),
            "{}",
        );
        assert_eq!(bench.run("latest"), Ok(Outcome::Current));
        let calls = bench.calls();
        assert!(
            calls.contains(&format!("/latest/{}.sha256", asset())),
            "the checksum is read from the rolling tag: {calls}"
        );
        assert!(
            calls.contains("tarball-ttl 0"),
            "the checksum is read afresh, not from nix's cache: {calls}"
        );
        assert!(
            !calls.contains("prefetch-file"),
            "nothing is downloaded: {calls}"
        );
        assert_eq!(
            std::fs::read_to_string(&bench.target).unwrap(),
            "the old binary"
        );
    }

    #[test]
    fn a_new_build_replaces_the_binary_once_it_runs_and_the_digest_rides_the_fetch() {
        let served = binary("sbx 0.1.0 (latest, 1111111)", 0);
        let bench = Bench::new(&served, &format!("{}  sbx-linux\n", sha256(&served)), "{}");
        assert_eq!(
            bench.run("latest"),
            Ok(Outcome::Replaced {
                to: "sbx 0.1.0 (latest, 1111111)".into()
            })
        );
        assert_eq!(std::fs::read_to_string(&bench.target).unwrap(), served);
        let mode = std::fs::metadata(&bench.target)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
        let calls = bench.calls();
        assert!(
            calls.contains(&format!("--expected-hash sha256:{}", sha256(&served))),
            "the published digest is handed to nix, so a mismatch never lands: {calls}"
        );
        assert_eq!(left_alone(&bench), ["sbx"]);
    }

    #[test]
    fn a_build_that_does_not_run_here_never_replaces_the_one_that_does() {
        let served = binary("Exec format error", 126);
        let bench = Bench::new(&served, &format!("{}  sbx-linux\n", sha256(&served)), "{}");
        let why = bench
            .run("latest")
            .expect_err("a binary that fails is refused");
        assert!(why.contains("does not run here"), "{why}");
        assert!(why.contains("was left as it was"), "{why}");
        assert_eq!(
            std::fs::read_to_string(&bench.target).unwrap(),
            "the old binary"
        );
        assert_eq!(left_alone(&bench), ["sbx"]);
    }

    #[test]
    fn a_checksum_that_is_not_one_stops_before_the_download() {
        let bench = Bench::new("unused", "<html>Not Found</html>", "{}");
        let why = bench.run("latest").expect_err("no digest, no download");
        assert!(why.contains("is not a SHA-256"), "{why}");
        assert!(!bench.calls().contains("prefetch-file"));
    }

    #[test]
    fn a_rolling_tag_that_cannot_be_fetched_says_it_may_be_mid_publication() {
        let bench = Bench::new("unused", "", "{}");
        std::fs::remove_file(bench.dir.join("sums")).unwrap();
        let why = bench
            .run("latest")
            .expect_err("the stand-in fails the fetch");
        assert!(why.contains("try again in a few minutes"), "{why}");
    }

    #[test]
    fn a_version_tag_follows_the_newest_stable_release_and_never_steps_back() {
        let served = binary("sbx 0.1.0 (v2.0.0, 2222222)", 0);
        let sums = format!("{}  sbx-linux\n", sha256(&served));

        let bench = Bench::new(&served, &sums, r#"{"tag_name":"v2.0.0"}"#);
        assert_eq!(
            bench.run("v1.9.0"),
            Ok(Outcome::Replaced {
                to: "sbx 0.1.0 (v2.0.0, 2222222)".into()
            })
        );
        assert!(bench.calls().contains(&format!("/v2.0.0/{}", asset())));

        for (current, newest) in [("v2.0.0", "v2.0.0"), ("v2.1.0-rc1", "v2.0.0")] {
            let bench = Bench::new(&served, &sums, &format!(r#"{{"tag_name":"{newest}"}}"#));
            assert_eq!(
                bench.run(current),
                Ok(Outcome::NoNewer {
                    newest: newest.into()
                }),
                "{current} against {newest}"
            );
            assert!(!bench.calls().contains(".sha256"));
        }

        let bench = Bench::new(&served, &sums, r#"{"tag_name":"../x"}"#);
        let why = bench
            .run("v1.9.0")
            .expect_err("a tag that is not one is refused");
        assert!(why.contains("names no release tag"), "{why}");
    }

    /// The stand-in above answers as the real nix is taken to. This drives the real one, on files
    /// alone: a release that changes at the same address is fetched as it is now, not as an earlier
    /// fetch of that address left it, and a download its checksum does not name never lands.
    #[test]
    fn the_real_nix_follows_a_release_that_changes_at_one_address_and_refuses_a_mismatch() {
        let Some(nix) = store::resolve_nix(None) else {
            skip_incapable!("skipping the upgrade through nix: no nix on this host");
            return;
        };
        let dir = TmpDir::new();
        let layout = Layout::under(&dir.join("data"));
        let published = dir.join("releases/latest");
        std::fs::create_dir_all(&published).unwrap();
        let asset_path = published.join(asset());
        let publish = |binary: &str, sums: &str| {
            std::fs::write(&asset_path, binary).unwrap();
            std::fs::write(published.join(format!("{}.sha256", asset())), sums).unwrap();
        };
        let target = dir.join("bin/sbx");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "the old binary").unwrap();
        let running = dir.join("running");
        let run = |running_bytes: &str| {
            std::fs::write(&running, running_bytes).unwrap();
            upgrade(&Upgrade {
                release: Release {
                    tag: "latest",
                    commit: COMMIT,
                    repo: "owner/name",
                },
                source: Source {
                    download: format!("file://{}", dir.join("releases").display()),
                    api: String::new(),
                },
                nix: &nix,
                layout: &layout,
                target: &target,
                running: &running,
            })
        };

        let first = binary("sbx 0.1.0 (latest, 1111111)", 0);
        publish(&first, &format!("{}  {}\n", sha256(&first), asset()));
        assert_eq!(
            run("the old binary"),
            Ok(Outcome::Replaced {
                to: "sbx 0.1.0 (latest, 1111111)".into()
            })
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), first);

        // The same address now serves another build, as `latest` does after a push.
        let second = binary("sbx 0.1.0 (latest, 2222222)", 0);
        publish(&second, &format!("{}  {}\n", sha256(&second), asset()));
        assert_eq!(
            run(&first),
            Ok(Outcome::Replaced {
                to: "sbx 0.1.0 (latest, 2222222)".into()
            }),
            "the second build is fetched, not the first one again"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), second);
        assert_eq!(run(&second), Ok(Outcome::Current));

        // A checksum that names other bytes than the ones served.
        let third = binary("sbx 0.1.0 (latest, 3333333)", 0);
        publish(
            "not the build the checksum names",
            &format!("{}\n", sha256(&third)),
        );
        let why = run(&second).expect_err("a download its checksum does not name is refused");
        assert!(why.contains("try again"), "{why}");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), second);
        assert_eq!(left_alone_in(&target), ["sbx"]);
    }

    #[test]
    fn the_checksum_is_the_first_field_and_nothing_but_a_sha256() {
        let digest = sha256("x");
        assert_eq!(
            parse_checksum(&format!("{digest}  sbx-linux-x86_64\n")),
            Some(digest.as_str())
        );
        assert_eq!(
            parse_checksum(&format!("{digest}\n")),
            Some(digest.as_str())
        );
        assert_eq!(parse_checksum(""), None);
        assert_eq!(parse_checksum(&digest.to_uppercase()), None);
        assert_eq!(parse_checksum(&digest[1..]), None);
    }

    #[test]
    fn the_asset_is_the_one_install_sh_fetches_for_this_architecture() {
        let script = include_str!("../../install.sh");
        assert!(script.contains("asset=\"sbx-linux-$(release_arch)\""));
        assert!(matches!(
            asset().as_str(),
            "sbx-linux-x86_64" | "sbx-linux-aarch64"
        ));
    }
}
