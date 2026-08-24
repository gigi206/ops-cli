//! `deb:` packages — a prebuilt Debian package (`.deb`) provisioned host-side.
//!
//! For a GUI/desktop app distributed only as a `.deb` (no runnable release binary, no nixpkgs
//! attribute, and — for one such app — an official flake whose from-source build is broken by a
//! bun-version mismatch), sbx packages the prebuilt `.deb` directly: resolve the URL to a content
//! hash, then build a generated derivation that `dpkg-deb -x`-unpacks it and `autoPatchelfHook`s the
//! ELF binaries against a curated Electron/Chromium library set. **No build script runs**
//! (`dontBuild`), so — unlike an arbitrary `flake:` — evaluating and building it host-side is safe;
//! it is therefore provisioned like `nix:` (into sbx's store, seeded, offline-reusable) rather than
//! in-cage.
//!
//! Three source forms (all trusted-only, like every `[packages]` backend):
//!   * `deb:<https url>` — a fixed `.deb` URL. A GitHub `…/releases/latest/download/<stable>.deb`
//!     URL already rolls forward via the redirect; a version-embedding URL does not.
//!   * `deb:github:<owner>/<repo>` — query the repo's latest release and select its linux `.deb`
//!     asset, so even a project whose asset name embeds the version rolls forward.
//!   * `deb:apt:<https Packages-index url>` — track an apt repository's highest-version `.deb`, for a
//!     vendor pool that publishes versioned filenames with no `latest` alias (so a hand-pinned URL
//!     goes stale). sbx fetches the uncompressed `Packages` index, **checks those very bytes
//!     against the repository's clearsigned `InRelease`** ([`attest_index`]), picks the newest
//!     version, and **re-validates the derived `.deb` URL** through the same charset check a
//!     hand-written `deb:` URL passes. The signing key is pinned on first encounter, and a
//!     repository that is later re-keyed, or whose `InRelease` disappears once pinned, is refused
//!     rather than downgraded. Scope, not a gap: uncompressed index only, a single-application
//!     repo, and a first encounter that has nothing but TLS to judge the key by — which warns,
//!     naming what is and is not attested, rather than failing.
//!
//! Update model: pin-on-first-use. A launch resolves the source to a concrete `.deb` URL and its
//! content hash, records both in a per-project lock (`deb-packages.lock`), and later launches reuse
//! the pin offline — the launch hot path never touches the network. `sbx upgrade` re-resolves each
//! declared source forward (re-querying GitHub for the `github:` form, the apt index for the `apt:`
//! form) and rewrites the lock.

use super::openpgp;
use super::prebuilt;
use crate::store::Layout;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

/// A locked `deb:` package, keyed in the lock by its declared *locator* (the `.deb` URL, a
/// `github:<owner>/<repo>`, or an `apt:` index). Its `url` is the concrete `.deb` the pin resolved
/// to — the locator itself for a direct URL, the selected release asset for a `github:` locator —
/// so a warm launch builds it offline without re-querying GitHub. See [`prebuilt::Pin`].
#[cfg(test)]
type DebPin = prebuilt::Pin;

/// The shapes a declared `deb:` locator can take, dispatched from its prefix.
enum DebSource {
    /// A direct `https://…/….deb` URL — resolved to itself.
    Url(String),
    /// `github:<owner>/<repo>` — resolved via the repo's latest release.
    Github { owner: String, repo: String },
    /// `apt:<packages-index-url>` — resolved via an apt repository's uncompressed `Packages` index
    /// (its highest-version `.deb`), for a vendor pool with no `latest` alias.
    Apt { packages_url: String },
}

/// Parse a declared locator (already validated by `config::parse_backend`) into its [`DebSource`].
fn parse_source(locator: &str) -> DebSource {
    if let Some(url) = locator.strip_prefix("apt:") {
        return DebSource::Apt {
            packages_url: url.to_string(),
        };
    }
    if let Some(path) = locator.strip_prefix("github:")
        && let Some((owner, repo)) = path.split_once('/')
    {
        return DebSource::Github {
            owner: owner.to_string(),
            repo: repo.to_string(),
        };
    }
    DebSource::Url(locator.to_string())
}

/// The outcome of re-resolving one declared `deb:` reference during `sbx upgrade`.
///
/// See [`prebuilt::Upgrade`].
pub(crate) type DebUpgrade = prebuilt::Upgrade;

/// Where this backend's lock lives. Production reads and writes it through [`prebuilt`]; this names
/// the same path for the tests that assert the on-disk format.
#[cfg(test)]
fn lock_path(layout: &Layout, project_id: &str) -> std::path::PathBuf {
    prebuilt::lock_path(layout, project_id, &prebuilt::lock_file(&Deb))
}

/// Read the per-project deb lock. A three-column line is a `github:`/`apt:` pin, whose resolved
/// asset URL differs from its key; see [`prebuilt::pins`] for the format.
#[cfg(test)]
fn pins(layout: &Layout, project_id: &str) -> BTreeMap<String, DebPin> {
    prebuilt::pins(layout, project_id, &prebuilt::lock_file(&Deb))
}

/// The pinned content hashes for a project's `deb:` packages, keyed by the declared locator so
/// `sbx config` can look each up directly. See [`prebuilt::pinned_hashes`].
pub(crate) fn pinned_hashes(cwd: &Path) -> BTreeMap<String, String> {
    prebuilt::pinned_hashes(cwd, &prebuilt::lock_file(&Deb))
}

/// Write the per-project deb lock atomically, for the tests that assert the on-disk
/// format. Production writes it through [`prebuilt::upgrade`].
#[cfg(test)]
fn write_pins(
    layout: &Layout,
    project_id: &str,
    lock: &BTreeMap<String, DebPin>,
) -> io::Result<()> {
    prebuilt::write_pins(layout, project_id, &prebuilt::lock_file(&Deb), lock)
}

/// Resolve a declared `deb:` locator to `(concrete .deb url, SRI content hash)`. A direct URL
/// resolves to itself; a `github:<owner>/<repo>` locator queries the repo's latest release, selects
/// its linux `.deb` asset, and **re-validates that GitHub-supplied URL** through the same
/// injection-free barrier a hand-written `deb:` URL passes before it is fetched or interpolated into
/// the generated derivation. `fresh` marks an `sbx upgrade` re-resolve: the release or index query
/// bypasses nix's metadata cache so it sees a new entry, and the artefact fetch stays quiet for the
/// summary. Fail-closed: an unvalidated or unselectable asset returns an error and no pin.
pub(crate) fn resolve_source(
    nix: &Path,
    layout: &Layout,
    locator: &str,
    system: &str,
    fresh: bool,
    allow_insecure_http: bool,
) -> io::Result<(String, String)> {
    let url = match parse_source(locator) {
        DebSource::Url(url) => url,
        DebSource::Github { owner, repo } => {
            let api = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest");
            let json = super::nixhub::fetch_url_json(nix, layout, &api, fresh)?;
            github_asset_url(&json, system, &owner, &repo)?
        }
        DebSource::Apt { packages_url } => {
            resolve_apt_deb_url(nix, layout, &packages_url, fresh, allow_insecure_http)?
        }
    };
    // A re-resolve (`fresh`) is an `sbx upgrade` step — capture nix's output and fold the cause
    // into the error; a first launch streams the download progress live.
    let hash = prebuilt::prefetch_hash(nix, layout, &url, fresh)?;
    Ok((url, hash))
}

/// Resolve an `apt:` locator's Packages index to the concrete `.deb` URL of its highest-version
/// package — the one network+derivation step `deb:apt:` adds over a direct `deb:` URL, kept as a
/// seam so it is testable against a real index without the heavy `.deb` prefetch. Fetches the index
/// (fresh past the cache on `sbx upgrade`), **checks it against the repository's signed `InRelease`**
/// ([`attest_index`]), selects the newest version, resolves its `Filename:`
/// against the repo root, and **re-validates that derived URL through [`is_valid_deb_url`](crate::config::is_valid_deb_url)** — the
/// index is remote-controlled, so this is the injection boundary before the URL is fetched or
/// interpolated into the generated derivation. Fail-closed at every step.
fn resolve_apt_deb_url(
    nix: &Path,
    layout: &Layout,
    packages_url: &str,
    fresh: bool,
    allow_insecure_http: bool,
) -> io::Result<String> {
    let index = super::nixhub::fetch_url_text(nix, layout, packages_url, fresh)?;
    // Between the fetch and the selection, and over this very buffer: what the signature attests
    // and what the selection reads are the same bytes, with no second fetch to diverge from.
    if let Attested::Unpinned(why) = attest_index(nix, layout, packages_url, &index, fresh)? {
        crate::diag::warn(&format!(
            "the apt repository at {packages_url} is trusted on TLS alone, because {why}; the \
             `.deb` it selects is pinned by content hash, but nothing attests that this index is \
             the one the repository published"
        ));
    }
    let (version, filename) = select_latest_apt_deb(&index).map_err(|e| {
        io::Error::other(format!(
            "the apt Packages index at {packages_url} could not be resolved: {e}"
        ))
    })?;
    let root = apt_repo_root(packages_url).ok_or_else(|| {
        io::Error::other(format!(
            "the apt Packages URL must contain a `/dists/` segment to locate the repo root: \
             {packages_url}"
        ))
    })?;
    let url = format!("{root}/{}", filename.trim_start_matches('/'));
    if !crate::config::is_valid_deb_url(&url, allow_insecure_http) {
        return Err(io::Error::other(format!(
            "the apt index at {packages_url} selected a `.deb` URL (version {version}) that is not \
             a valid `.deb` URL: {url}"
        )));
    }
    Ok(url)
}

/// The `InRelease` that attests an apt repository's indexes: the signed file at the root of the
/// suite whose `Packages` a locator names. Derived from the locator rather than configured, because
/// the layout is fixed — `<root>/dists/<suite>/<component>/binary-<arch>/Packages` — and a second
/// place to write the same fact is a second place for it to be wrong.
fn inrelease_url(packages_url: &str) -> Option<String> {
    let (root, rest) = packages_url.split_once("/dists/")?;
    let suite = rest.split('/').next().filter(|s| !s.is_empty())?;
    Some(format!("{root}/dists/{suite}/InRelease"))
}

/// The index's path as `InRelease` names it — everything after the suite, which is what the signed
/// digest lines are keyed by (`main/binary-amd64/Packages`).
fn index_path(packages_url: &str) -> Option<&str> {
    let (_, rest) = packages_url.split_once("/dists/")?;
    let (_, path) = rest.split_once('/')?;
    Some(path).filter(|p| !p.is_empty())
}

/// The digest a signed `Release` body attests for one indexed file, as `(algorithm, hex, size)`.
///
/// A `Release` lists the same file four times, under `MD5Sum:`, `SHA1:`, `SHA256:` and `SHA512:`.
/// Only the last two are read, strongest first, and **MD5 and SHA-1 are not fallbacks**: a
/// repository that publishes only those is treated as publishing nothing, because a digest an
/// attacker can collide attests nothing about the bytes it names. Sections are recognised by their
/// header sitting at column zero, so a filename inside a section can never be read as one.
fn signed_digest(release: &str, path: &str) -> Option<(&'static str, String, u64)> {
    let mut section: Option<&'static str> = None;
    let mut found: Option<(&'static str, String, u64)> = None;
    for line in release.lines() {
        if !line.starts_with([' ', '\t']) {
            section = match line.trim_end() {
                "SHA256:" => Some("SHA256"),
                "SHA512:" => Some("SHA512"),
                _ => None,
            };
            continue;
        }
        let Some(algorithm) = section else { continue };
        // ` <hex> <size> <path>`, whitespace-separated and padded for alignment.
        let mut fields = line.split_whitespace();
        let (Some(hex), Some(size), Some(name)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if name != path || fields.next().is_some() {
            continue;
        }
        let Ok(size) = size.parse::<u64>() else {
            continue;
        };
        if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        // SHA-512 wins when both are published; otherwise take what there is.
        if algorithm == "SHA512" || found.is_none() {
            found = Some((algorithm, hex.to_ascii_lowercase(), size));
        }
    }
    found
}

/// Whether the bytes an index was fetched as are the ones a signed `Release` attests. The digest is
/// computed over the caller's own buffer — the same `String` the selection then parses — so there
/// is no arrangement in which the verified bytes and the parsed bytes are two different fetches.
fn index_matches(index: &str, algorithm: &str, expected: &str, size: u64) -> bool {
    use crate::plugins::catalogue::to_hex;
    use sha2::Digest as _;
    if index.len() as u64 != size {
        return false;
    }
    let digest = match algorithm {
        "SHA512" => to_hex(&sha2::Sha512::digest(index.as_bytes())),
        _ => to_hex(&sha2::Sha256::digest(index.as_bytes())),
    };
    // Compared as lowercase hex on both sides; `Release` publishes lowercase, but a repository that
    // published uppercase would otherwise fail for a reason that is not the one being tested.
    digest == expected.to_ascii_lowercase()
}

/// Where the signing key of one apt repository is pinned. Named by the digest of the suite the
/// locator points at rather than by the repository's own name, which nothing publishes: two
/// locators into the same suite share one pin, and two suites of one vendor pin separately, which
/// is what signing them separately would mean.
fn pinned_key_path(layout: &Layout, inrelease_url: &str) -> std::path::PathBuf {
    use crate::plugins::catalogue::to_hex;
    use sha2::Digest as _;
    let name = to_hex(&sha2::Sha256::digest(inrelease_url.as_bytes()));
    layout.apt_keys_dir().join(format!("{name}.asc"))
}

/// Where a key is fetched from on a first pin, by the fingerprint the signature claims. A keyserver
/// attests **nothing** — anyone may upload a key under any identity — which is exactly why the
/// fingerprint is the anchor and the fetched material is bound back to it before it is used. What
/// this endpoint provides is availability, not authority.
///
/// The URL is interpolated into a `builtins.fetchurl` expression, and it carries no metacharacter
/// by construction: a fingerprint is a fixed-size byte array, so its rendering is always forty hex
/// digits. Nothing remote reaches this string.
fn keyserver_url(fingerprint: &openpgp::Fingerprint) -> String {
    format!(
        "https://keys.openpgp.org/vks/v1/by-fingerprint/{}",
        openpgp::hex(fingerprint)
    )
}

/// Read a key and say what fingerprint it must answer to.
///
/// `claim` is `Some` only on a **first pin**, carrying the fingerprint the signature named. The key
/// then comes from a keyserver, which serves whatever it is asked for and vouches for nothing, so
/// the anchor is the claim and not the material: a keyserver answering with a different key is
/// refused by the comparison rather than tried against the signature. With no claim the key is the
/// one sbx itself pinned, and it answers to its own fingerprint — there the enforcement is the
/// signature, which a re-keyed repository cannot satisfy.
fn anchored_key(
    armored: &str,
    claim: Option<openpgp::Fingerprint>,
) -> Result<(openpgp::PublicKey, openpgp::Fingerprint), String> {
    let key = openpgp::parse_public_key(armored)?;
    let anchor = claim.unwrap_or(key.fingerprint);
    Ok((key, anchor))
}

/// The verdict of checking an index against its repository's signature, so the caller can tell a
/// repository that failed its own attestation from one that never had a pin to enforce.
enum Attested {
    /// The index is the one a signature by the pinned key attests.
    Yes,
    /// No key is pinned for this repository and none could be learned, so nothing was enforced.
    /// This is the trust level a `deb:` URL has always had, reached only on a first pin.
    Unpinned(String),
}

/// Check an apt index against the `InRelease` its repository publishes, pinning the signing key on
/// a first encounter and enforcing that pin ever after.
///
/// The chain this closes runs signature -> index digest -> the `.deb` hash the caller already pins,
/// and it is only a chain if every link is checked against the artefact the next one consumes.
///
/// So `index` is the caller's own buffer, and the digest is taken over it rather than over a
/// second fetch.
///
/// **Trust on first use, deliberately.** A first pin has no authenticity: the fingerprint is read
/// from the signature itself and the key is fetched by it, so whoever served the index chose both.
/// Its value is the pin it establishes — every later `sbx upgrade deb` must present a signature by
/// that same key, so a repository that is re-keyed, or an index served by someone else, is refused
/// rather than resolved. This is the trust model [`crate::plugins::stores`] already applies to a
/// plugin store, for the same reason.
///
/// A first pin that cannot be established — no `InRelease`, no reachable key, a signature this
/// module does not read — leaves the resolve at the trust level it has always had and says so. It
/// does not fail the launch: the repository's own availability, and a keyserver's, would otherwise
/// decide whether a project can be provisioned. Once a key is pinned that latitude ends.
fn attest_index(
    nix: &Path,
    layout: &Layout,
    packages_url: &str,
    index: &str,
    fresh: bool,
) -> io::Result<Attested> {
    let Some(url) = inrelease_url(packages_url) else {
        return Ok(Attested::Unpinned(
            "its URL names no `/dists/<suite>/` to find an `InRelease` under".to_string(),
        ));
    };
    let path = index_path(packages_url).ok_or_else(|| {
        io::Error::other(format!(
            "the apt Packages URL names no index path under its suite: {packages_url}"
        ))
    })?;
    let pin = pinned_key_path(layout, &url);
    // Only *absent* means "never pinned". `.ok()` collapsed every error to that — a permission
    // problem, an I/O error, a directory left at the path — and "never pinned" is the branch that
    // runs trust-on-first-use, taking whatever key the repository's signature names today. So a
    // pin that merely could not be read re-pinned the repository, silently, which is the one
    // outcome pinning exists to prevent.
    //
    // The refusal beside it, for an `InRelease` that stopped being published, already states the
    // rule: a repository whose key is pinned has attested before, so the attestation going missing
    // "is the shape of an attacker removing the attestation, not of a repository that never had
    // one". An unreadable pin is the same shape one file over.
    let pinned = match std::fs::read_to_string(&pin) {
        Ok(armored) => Some(armored),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(io::Error::other(format!(
                "the signing key sbx pinned for {url} cannot be read ({}): {e} — refusing to \
                 re-pin, which would trust whatever key the repository names today",
                pin.display()
            )));
        }
    };
    let signed = match super::nixhub::fetch_url_text(nix, layout, &url, fresh) {
        Ok(text) => text,
        Err(e) if pinned.is_none() => {
            return Ok(Attested::Unpinned(format!(
                "it publishes no `InRelease` sbx could fetch ({e})"
            )));
        }
        // A repository whose key is pinned has published an `InRelease` before. Its disappearance
        // is the shape of an attacker removing the attestation, not of a repository that never had
        // one, so it is refused rather than downgraded.
        Err(e) => {
            return Err(io::Error::other(format!(
                "the apt repository at {url} no longer publishes the `InRelease` whose signing key \
                 sbx pinned, so the index it serves cannot be attested: {e}"
            )));
        }
    };
    // Three things travel together on purpose: the key, the armor to pin if it attests, and the
    // fingerprint the key must answer to. On a first pin that fingerprint is the one the SIGNATURE
    // claims, not the fetched key's own — a keyserver serves whatever it is asked for, so binding
    // the material back to the claim is what makes the fetch safe to use at all.
    let (key, armored, expected) = match pinned {
        Some(armored) => {
            let (key, anchor) = anchored_key(&armored, None).map_err(|e| {
                io::Error::other(format!(
                    "the signing key pinned for {url} cannot be read ({e}); remove {} to pin it \
                     again from the repository",
                    pin.display()
                ))
            })?;
            (key, None, anchor)
        }
        None => {
            let claimed = match openpgp::issuer_fingerprint(&signed) {
                Ok(fingerprint) => fingerprint,
                Err(e) => {
                    return Ok(Attested::Unpinned(format!(
                        "its `InRelease` carries no signature sbx can read ({e})"
                    )));
                }
            };
            let armored =
                match super::nixhub::fetch_url_text(nix, layout, &keyserver_url(&claimed), fresh) {
                    Ok(armored) => armored,
                    Err(e) => {
                        return Ok(Attested::Unpinned(format!(
                            "the key {} its `InRelease` is signed with is published nowhere sbx \
                             could fetch it ({e})",
                            openpgp::hex(&claimed)
                        )));
                    }
                };
            match anchored_key(&armored, Some(claimed)) {
                Ok((key, anchor)) => (key, Some(armored), anchor),
                Err(e) => {
                    return Ok(Attested::Unpinned(format!(
                        "the key {} its `InRelease` names cannot be read ({e})",
                        openpgp::hex(&claimed)
                    )));
                }
            }
        }
    };
    // The comparison happens inside `verify_clearsigned`, before the key reaches the verifier, so a
    // key that is not the expected one is refused rather than tried. On a first pin that rejects a
    // keyserver answering with something other than what was asked for; afterwards `expected` is the
    // pinned key's own, and it is the signature that has to hold.
    let release = openpgp::verify_clearsigned(&signed, &key, &expected)
        .map_err(|e| io::Error::other(format!("the `InRelease` at {url} is not valid: {e}")))?;
    let (algorithm, digest, size) = signed_digest(&release, path).ok_or_else(|| {
        io::Error::other(format!(
            "the signed `InRelease` at {url} attests no SHA-256 or SHA-512 digest for `{path}`, so \
             the index it serves is not covered by its signature"
        ))
    })?;
    if !index_matches(index, algorithm, &digest, size) {
        // Fail closed, and name both causes rather than only the alarming one: the index and the
        // attestation are two fetches, so a repository that published between them mismatches for a
        // reason that is not an attack. Retrying on a mismatch is deliberately not done, since it
        // would let whoever controls the index decide how many attempts a refusal costs.
        return Err(io::Error::other(format!(
            "the apt index at {packages_url} is not the one its signed `InRelease` attests \
             ({algorithm} mismatch). Either the repository published between the two fetches, in \
             which case resolving again succeeds, or the index served is not the one it signed"
        )));
    }
    if let Some(armored) = armored {
        // Pinned only now, so a key is recorded when it has actually attested an index and never
        // merely because it parsed.
        write_pinned_key(&pin, &armored)?;
        crate::diag::note(&format!(
            "pinned the signing key of the apt repository at {url} ({}); every later `sbx upgrade \
             deb` must present a signature by this key",
            openpgp::hex(&key.fingerprint)
        ));
    }
    if let Some(until) = valid_until(&release)
        && expired(until)
    {
        // A warning, not a refusal. `Valid-Until` is a staleness signal, and this check runs on a
        // first pin and on `sbx upgrade deb`, never on the launch hot path — so a machine that has
        // been offline past the window still resolves, while a repository that has stopped being
        // republished is named.
        crate::diag::warn(&format!(
            "the signed `InRelease` at {url} expired on {until}; its signature still holds, but the \
             repository has not republished it, so what it attests may have been superseded"
        ));
    }
    Ok(Attested::Yes)
}

/// Write a pinned key with the directory it lives in, owner-only, so what sbx verified cannot be
/// replaced by anything a project can reach.
fn write_pinned_key(path: &Path, armored: &str) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if let Some(parent) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    std::fs::write(path, armored)
}

/// The `Valid-Until` a signed `Release` carries, verbatim. Returned as the repository wrote it so a
/// message can quote it, rather than reformatted into a shape the user would then have to match
/// against the file.
fn valid_until(release: &str) -> Option<&str> {
    release
        .lines()
        .find_map(|l| l.strip_prefix("Valid-Until:"))
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

/// Whether an apt `Valid-Until` stamp is in the past. The format is fixed by the Debian repository
/// specification (`Tue, 25 Aug 2026 23:37:43 UTC`), so it is read directly rather than by pulling in
/// a date parser for one field. An unparseable stamp is **not** expired: this drives a warning, and
/// a warning that fires on a format sbx failed to read would train the user to ignore it.
fn expired(stamp: &str) -> bool {
    expired_at(stamp, now_seconds())
}

/// The comparison itself, against a caller-supplied clock, so the rule is testable without one.
fn expired_at(stamp: &str, now: u64) -> bool {
    parse_valid_until(stamp).is_some_and(|until| until < now)
}

/// Seconds since the epoch, as the only reading of the clock this file makes.
fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse `[Day, ]DD Mon YYYY HH:MM:SS UTC` into seconds since the epoch. Only UTC is accepted — the
/// specification requires it — so a stamp in another zone reads as unparseable rather than as a
/// time shifted by an unknown offset.
fn parse_valid_until(stamp: &str) -> Option<u64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let stamp = stamp.split_once(", ").map_or(stamp, |(_, rest)| rest);
    let mut fields = stamp.split_whitespace();
    let day: u64 = fields.next()?.parse().ok()?;
    let name = fields.next()?;
    let month = MONTHS.iter().position(|m| *m == name)? as u64 + 1;
    let year: u64 = fields.next()?.parse().ok()?;
    let mut time = fields.next()?.split(':');
    let (h, m, sec): (u64, u64, u64) = (
        time.next()?.parse().ok()?,
        time.next()?.parse().ok()?,
        time.next()?.parse().ok()?,
    );
    if time.next().is_some() || fields.next()? != "UTC" || fields.next().is_some() {
        return None;
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || (h, m, sec) >= (24, 60, 60) {
        return None;
    }
    // Days from the civil epoch, by the shift-the-year-to-March algorithm: it makes the leap day the
    // last day of the shifted year, so no month-length table is needed and no leap rule is special.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let year_of_era = y - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era;
    Some((days - 719_468) * 86_400 + h * 3_600 + m * 60 + sec)
}

/// Select the newest package's `.deb` from an apt `Packages` index. The index is RFC822-style
/// stanzas separated by blank lines, each carrying `Package:`, `Version:`, and `Filename:` fields.
/// sbx targets a **single-application** apt repo (a vendor's own pool), so every stanza must name the
/// SAME `Package:` — a multi-package Debian mirror is refused (it is ambiguous which app to track).
/// The highest `Version:` wins, compared as dotted **decimal** components (`1.21459.0` > `1.18286.2`);
/// a version carrying a non-numeric component is **refused** rather than mis-ordered — this is
/// deliberately not full dpkg ordering (no epochs, no `~`). Returns `(version, filename)` of the
/// winner, `filename` being the path relative to the repo root. Pure, so it is unit-tested against a
/// captured index.
fn select_latest_apt_deb(index: &str) -> Result<(String, String), String> {
    let mut stanzas: Vec<(String, String, String)> = Vec::new();
    let (mut pkg, mut ver, mut file): (Option<String>, Option<String>, Option<String>) =
        (None, None, None);
    // Group RFC822 stanzas on blank lines by iterating `lines()` (which strips both `\n` and `\r\n`)
    // rather than splitting on `"\n\n"` — so an apt `Packages` served with CRLF still parses into
    // separate stanzas instead of collapsing into one. A trailing sentinel flushes the final stanza
    // when the file does not end in a blank line.
    for line in index.lines().chain(std::iter::once("")) {
        if line.trim().is_empty() {
            if let (Some(p), Some(v), Some(f)) = (pkg.take(), ver.take(), file.take())
                && !p.is_empty()
                && !v.is_empty()
                && !f.is_empty()
            {
                stanzas.push((p, v, f));
            }
        } else if let Some(v) = line.strip_prefix("Package:") {
            pkg = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Version:") {
            ver = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Filename:") {
            file = Some(v.trim().to_string());
        }
    }
    let first = stanzas
        .first()
        .ok_or("no package stanza (Package/Version/Filename) found")?;
    let name = first.0.clone();
    if stanzas.iter().any(|(p, _, _)| *p != name) {
        return Err(format!(
            "the index names more than one package (e.g. `{name}`); `deb:apt:` tracks a \
             single-application repo"
        ));
    }
    // Parse EVERY version (so a non-numeric one anywhere is refused, not just the winner) and keep
    // the index of the highest — dotted-decimal order, so `1.21459.0` > `1.18286.2`.
    let bad = |v: &str| {
        format!("version `{v}` is not a plain dotted-decimal version `deb:apt:` can order")
    };
    let mut best_idx = 0usize;
    let mut best_ver = parse_numeric_version(&stanzas[0].1).ok_or_else(|| bad(&stanzas[0].1))?;
    for (i, stanza) in stanzas.iter().enumerate().skip(1) {
        let ver = parse_numeric_version(&stanza.1).ok_or_else(|| bad(&stanza.1))?;
        if ver > best_ver {
            best_ver = ver;
            best_idx = i;
        }
    }
    let winner = &stanzas[best_idx];
    Ok((winner.1.clone(), winner.2.clone()))
}

/// Parse a dotted-decimal version (`1.21459.0`) into comparable numeric components. Returns `None` if
/// any component is not a plain non-negative integer, so [`select_latest_apt_deb`] refuses such a
/// version rather than mis-ordering it (it does not implement dpkg epoch/`~` semantics).
fn parse_numeric_version(v: &str) -> Option<Vec<u64>> {
    if v.is_empty() {
        return None;
    }
    v.split('.').map(|c| c.parse::<u64>().ok()).collect()
}

/// The repository root of an apt `Packages` URL — the base each stanza's `Filename:` (a repo-relative
/// `pool/…/*.deb` path) resolves against. In the standard layout the index lives at
/// `<root>/dists/<suite>/<component>/binary-<arch>/Packages`, so the root is the URL up to (not
/// including) the `/dists/` segment. Returns `None` if there is no `/dists/` segment.
fn apt_repo_root(packages_url: &str) -> Option<&str> {
    packages_url.split_once("/dists/").map(|(root, _)| root)
}

/// The `.deb` asset URL a `github:<owner>/<repo>` locator's newest release names, validated.
///
/// **`allow_insecure_http` deliberately does not reach here, and the `apt:` sibling is the contrast
/// that argues it.** An `apt:` locator names its own repository root, so a user who wrote
/// `apt:http://…` chose plaintext and the `.deb` URL derived from that root inherits the choice; the
/// flag must follow it there or the opt-in would not work at all. A `github:` locator names no
/// scheme. This URL is a field in a JSON document fetched from `api.github.com` over TLS, chosen by
/// GitHub and not by the config, so a plaintext value in it is an anomaly in a third party's answer
/// rather than a posture anyone here asked for. Opting into plaintext for your own server is not
/// opting into following whatever scheme a remote API hands back, and one switch cannot honestly
/// mean both.
fn github_asset_url(
    json: &serde_json::Value,
    system: &str,
    owner: &str,
    repo: &str,
) -> io::Result<String> {
    let url = prebuilt::select_release_asset(json, system, ".deb").ok_or_else(|| {
        io::Error::other(format!(
            "no linux {} `.deb` asset in the latest release of {owner}/{repo}",
            prebuilt::arch_label(system)
        ))
    })?;
    if !crate::config::is_valid_deb_url(&url, false) {
        return Err(io::Error::other(format!(
            "the latest release of {owner}/{repo} selected an asset URL that is not a \
             valid `https://` `.deb` URL: {url}"
        )));
    }
    Ok(url)
}

/// The generated nix expression building one `deb:` package: fetch the pinned `.deb`, unpack it, and
/// autoPatchelf it against [`prebuilt::ELECTRON_LIBS`] from the pinned `nixpkgs`. The install phase
/// is generic for an Electron layout — it locates the app directory by its `resources/` signature
/// (a packed `resources/app.asar` or, for an asar-less VS Code fork, the `resources/app/`
/// directory) and wraps the app's own launcher (the executable beside it that is not a `.so` or a
/// Chromium helper), so no per-app path is hardcoded. Every interpolated value is sbx-controlled
/// and charset-validated (`name`, `url`, `hash`, the pinned `nixpkgs`, the `system`), so the
/// expression carries nothing to escape; placeholders keep nix's `${…}`/`{…}` out of Rust's
/// formatter.
fn derivation_expr(
    nixpkgs: &str,
    system: &str,
    name: &str,
    url: &str,
    hash: &str,
    libs: &[String],
) -> String {
    const TEMPLATE: &str = r#"let pkgs = (builtins.getFlake "@NIXPKGS@").legacyPackages.@SYSTEM@;
in pkgs.stdenvNoCC.mkDerivation (finalAttrs: {
  name = "@NAME@";
  src = pkgs.fetchurl { url = "@URL@"; hash = "@HASH@"; };
  nativeBuildInputs = with pkgs; [ dpkg makeWrapper autoPatchelfHook ];
  buildInputs = with pkgs; [ @LIBS@ ];
  autoPatchelfIgnoreMissingDeps = [ "libc.musl-x86_64.so.1" ];
  # Extract the data tarball with a plain, unprivileged `tar` instead of `dpkg-deb -x`. The latter
  # restores exact modes and aborts when a `.deb` ships a setuid file (Chromium's `chrome-sandbox`,
  # mode 04755): a non-root nix builder cannot chmod setuid ("Operation not permitted"), which fails
  # the whole unpack. `tar` without `--preserve-permissions` simply does not restore the setuid bit.
  # This is safe and load-bearing for Electron apps: the launcher runs with `--no-sandbox` (bubblewrap
  # + seccomp + the empty netns is the boundary), so that helper is never used, and setuid could not
  # take effect in the cage anyway.
  unpackPhase = ''
    mkdir extracted
    dpkg-deb --fsys-tarfile $src | tar -x --no-same-permissions --no-same-owner -C extracted
  '';
  dontConfigure = true;
  dontBuild = true;
  installPhase = ''
    mkdir -p $out
    cp -r extracted/. "$out"
@WRAP@
  '';
  meta.mainProgram = "@NAME@";
})
"#;
    // The `.deb` binary lives under its own prefix and finds its sibling `.so`s via RUNPATH, so the
    // wrapper's `LD_LIBRARY_PATH` is just the buildInputs closure — no bundle-root prefix (unlike an
    // AppImage, whose Chromium `.so`s sit loose beside the launcher).
    let wrap = prebuilt::launcher_wrap(name, "${pkgs.lib.makeLibraryPath finalAttrs.buildInputs}");
    TEMPLATE
        .replace("@WRAP@", &wrap)
        .replace("@NIXPKGS@", nixpkgs)
        .replace("@SYSTEM@", system)
        .replace("@LIBS@", &prebuilt::lib_set(libs))
        .replace("@URL@", url)
        .replace("@HASH@", hash)
        .replace("@NAME@", name)
}

/// The `deb:` backend — the two decisions [`prebuilt::Kind`] leaves to it are its locator forms (a
/// direct URL, `github:`, `apt:`) and unpacking the `.deb`'s data tarball.
pub(crate) struct Deb;

impl prebuilt::Kind for Deb {
    fn name(&self) -> &'static str {
        "deb"
    }

    fn artefact(&self) -> &'static str {
        "`.deb`"
    }

    fn url_validator(&self) -> fn(&str, bool) -> bool {
        crate::config::is_valid_deb_url
    }

    fn resolve_source(
        &self,
        nix: &Path,
        layout: &Layout,
        locator: &str,
        system: &str,
        fresh: bool,
        allow_insecure_http: bool,
    ) -> io::Result<(String, String)> {
        resolve_source(nix, layout, locator, system, fresh, allow_insecure_http)
    }

    fn derivation_expr(
        &self,
        nixpkgs: &str,
        system: &str,
        name: &str,
        url: &str,
        hash: &str,
        libs: &[String],
    ) -> String {
        derivation_expr(nixpkgs, system, name, url, hash, libs)
    }

    fn form(&self, package: &crate::config::Package) -> Option<prebuilt::Form> {
        match &package.backend {
            crate::config::Backend::Deb(locator) => Some(prebuilt::Form::Direct(locator.clone())),
            crate::config::Backend::DebResolve { command } => {
                Some(prebuilt::Form::Resolve(command.clone()))
            }
            // Spelled out rather than `_`: a new backend variant must fail to compile here. Falling
            // through to `None` would leave its packages out of the prune universe, and `upgrade`
            // would drop a still-declared pin without a word.
            crate::config::Backend::Nix(_)
            | crate::config::Backend::Mise(_)
            | crate::config::Backend::Flake(_)
            | crate::config::Backend::FlakeInline { .. }
            | crate::config::Backend::AppImage(_)
            | crate::config::Backend::AppImageResolve { .. }
            | crate::config::Backend::Tarball(_)
            | crate::config::Backend::TarballResolve { .. }
            | crate::config::Backend::Binary(_)
            | crate::config::Backend::BinaryResolve { .. } => None,
        }
    }
}

/// `sbx upgrade deb`: roll a project's declared `deb:` packages forward. See
/// [`prebuilt::upgrade_project`].
pub(crate) fn upgrade_project(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    cfg: &crate::config::Resolved,
) -> io::Result<Vec<DebUpgrade>> {
    prebuilt::upgrade_project(&Deb, nix, layout, project, cfg)
}

/// How many declared `deb:` packages are withheld for being untrusted. See [`prebuilt::withheld`].
pub(crate) fn withheld(cfg: &crate::config::Resolved) -> usize {
    prebuilt::withheld(&Deb, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store;
    use crate::testutil::{TmpDir, app_with, resolved};

    const HASH: &str = "sha256-jBGtMS5lpJWVXe+KzQgRSho8BcaEzGvONzIbAWled0w=";

    #[test]
    fn the_generated_derivation_pins_the_source_and_wraps_the_electron_launcher() {
        let expr = derivation_expr(
            "github:NixOS/nixpkgs/abc",
            "x86_64-linux",
            "demo-app",
            "https://example.com/x/demo-app-linux-amd64.deb",
            HASH,
            &[],
        );
        // pinned source (url + resolved hash), against the pinned nixpkgs for this system
        assert!(expr.contains(
            "(builtins.getFlake \"github:NixOS/nixpkgs/abc\").legacyPackages.x86_64-linux"
        ));
        assert!(expr.contains("url = \"https://example.com/x/demo-app-linux-amd64.deb\";"));
        assert!(expr.contains(&format!("hash = \"{HASH}\";")));
        // unpack-only, no build script (safe host-side); the Electron lib set is present. The
        // extraction pipes the data tarball through a non-root `tar` so a setuid file (Chromium's
        // `chrome-sandbox`) does not abort the unpack in the unprivileged nix builder.
        assert!(expr.contains("dpkg-deb --fsys-tarfile $src | tar -x --no-same-permissions"));
        assert!(expr.contains("dontBuild = true;"));
        assert!(expr.contains("nss") && expr.contains("gtk3") && expr.contains("libx11"));
        // generic Electron install: find the app by its app.asar, wrap the launcher as bin/<name>
        assert!(expr.contains("resources/"));
        assert!(expr.contains("app.asar"));
        assert!(expr.contains("$out/bin/demo-app"));
        assert!(expr.contains("meta.mainProgram = \"demo-app\";"));
        // no leftover placeholder
        assert!(!expr.contains('@'), "unreplaced placeholder in:\n{expr}");
    }

    #[test]
    fn a_packages_own_libs_join_the_build_inputs_of_its_derivation() {
        // What lets a GTK/WebKit `.deb` resolve its `NEEDED` entries without every Electron app
        // paying for WebKitGTK's closure: the attributes ride the package, not the shared set.
        let plain = derivation_expr(
            "github:NixOS/nixpkgs/abc",
            "x86_64-linux",
            "demo-app",
            "https://example.com/x/demo-app-linux-amd64.deb",
            HASH,
            &[],
        );
        assert!(!plain.contains("webkitgtk_4_1"));

        let with_libs = derivation_expr(
            "github:NixOS/nixpkgs/abc",
            "x86_64-linux",
            "demo-app",
            "https://example.com/x/demo-app-linux-amd64.deb",
            HASH,
            &["webkitgtk_4_1".to_string(), "libsoup_3".to_string()],
        );
        assert!(with_libs.contains("webkitgtk_4_1") && with_libs.contains("libsoup_3"));
        // The built-in set is unioned, never replaced — an app declaring one attribute must not
        // lose the Electron/Chromium libraries the unpacked tree still links against.
        assert!(with_libs.contains("gtk3") && with_libs.contains("nss"));
        assert!(!with_libs.contains('@'), "unreplaced placeholder");
    }

    #[test]
    fn the_lock_round_trips_both_forms_and_a_corrupt_line_self_heals() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let id = "proj1";
        let mut lock = BTreeMap::new();
        // a direct-URL pin (url == key) and a `github:` pin (url != key, the resolved asset).
        lock.insert(
            "https://example.com/a.deb".to_string(),
            DebPin {
                hash: HASH.to_string(),
                url: "https://example.com/a.deb".to_string(),
            },
        );
        lock.insert(
            "github:example/demo-app".to_string(),
            DebPin {
                hash: HASH.to_string(),
                url: "https://github.com/example/demo-app/releases/download/v2.1.35/demo-app-2.1.35-linux-amd64.deb".to_string(),
            },
        );
        write_pins(&layout, id, &lock).expect("write the lock");

        // the direct-URL pin stays a compact two-column line (byte-compatible with the legacy lock).
        let raw = std::fs::read_to_string(lock_path(&layout, id)).unwrap();
        assert!(
            raw.contains(&format!("https://example.com/a.deb\t{HASH}\n")),
            "a direct-URL pin keeps the two-column form:\n{raw}"
        );

        let read = pins(&layout, id);
        assert_eq!(read.len(), 2);
        assert_eq!(
            read["https://example.com/a.deb"].url,
            "https://example.com/a.deb"
        );
        assert_eq!(
            read["github:example/demo-app"].url,
            "https://github.com/example/demo-app/releases/download/v2.1.35/demo-app-2.1.35-linux-amd64.deb"
        );
        assert_eq!(read["github:example/demo-app"].hash, HASH);

        // a legacy two-column line reads with url == key; a corrupt (non-SRI) line self-heals (drop).
        std::fs::write(
            lock_path(&layout, id),
            format!("https://example.com/a.deb\t{HASH}\nhttps://bad.example/b.deb\tnot-a-hash\n"),
        )
        .unwrap();
        let read = pins(&layout, id);
        assert_eq!(read.len(), 1, "the corrupt line must self-heal (drop)");
        assert_eq!(
            read["https://example.com/a.deb"].url, "https://example.com/a.deb",
            "a two-column (legacy) line takes its key as the resolved url"
        );
    }

    #[test]
    fn parse_source_dispatches_github_from_url() {
        match parse_source("github:example/demo-app") {
            DebSource::Github { owner, repo } => {
                assert_eq!(owner, "example");
                assert_eq!(repo, "demo-app");
            }
            DebSource::Url(_) | DebSource::Apt { .. } => panic!("github locator misparsed"),
        }
        assert!(matches!(
            parse_source("https://example.com/x.deb"),
            DebSource::Url(u) if u == "https://example.com/x.deb"
        ));
    }

    // A trimmed capture of a desktop app's `releases/latest` asset set (the same names + URL shape a
    // real release carries), the shape [`prebuilt::select_release_asset`] must pick from: two linux `.deb`s (amd64
    // + arm64) beside mac/win.
    const RELEASE_ASSETS: &str = r#"{
      "tag_name": "v2.1.35",
      "assets": [
        { "name": "demo-app-2.1.35-linux-amd64.deb",
          "browser_download_url": "https://github.com/example/demo-app/releases/download/v2.1.35/demo-app-2.1.35-linux-amd64.deb" },
        { "name": "demo-app-2.1.35-linux-arm64.deb",
          "browser_download_url": "https://github.com/example/demo-app/releases/download/v2.1.35/demo-app-2.1.35-linux-arm64.deb" },
        { "name": "demo-app-2.1.35-mac-x64.dmg",
          "browser_download_url": "https://github.com/example/demo-app/releases/download/v2.1.35/demo-app-2.1.35-mac-x64.dmg" },
        { "name": "demo-app-2.1.35-win-x64.exe",
          "browser_download_url": "https://github.com/example/demo-app/releases/download/v2.1.35/demo-app-2.1.35-win-x64.exe" }
      ]
    }"#;

    #[test]
    fn a_github_release_asset_is_held_to_tls_whatever_the_launch_allows() {
        // The seventh path the plaintext switch could have reached, and the one it deliberately does
        // not. This URL is GitHub's answer over TLS, not the config's choice, so it stays https-only
        // even when the launch opted into plaintext for its own sources.
        let http_asset = serde_json::json!({
            "assets": [
                { "name": "demo-app_1.0_amd64.deb",
                  "browser_download_url": "http://e/demo-app_1.0_amd64.deb" }
            ]
        });
        // The selection itself is scheme-agnostic: it finds the asset, and the refusal is the
        // validation, so this test is about the gate and not about a failure to find anything.
        assert_eq!(
            prebuilt::select_release_asset(&http_asset, "x86_64-linux", ".deb").as_deref(),
            Some("http://e/demo-app_1.0_amd64.deb")
        );
        let err = github_asset_url(&http_asset, "x86_64-linux", "o", "r")
            .expect_err("a plaintext asset URL is refused");
        assert!(
            err.to_string().contains("https://"),
            "the refusal does not say what it wanted: {err}"
        );
        // The `apt:` sibling is the contrast: there the flag *does* follow the declared root, which
        // is why this one has to be argued rather than assumed. See `github_asset_url`'s docstring.
        let https_asset = serde_json::json!({
            "assets": [
                { "name": "demo-app_1.0_amd64.deb",
                  "browser_download_url": "https://e/demo-app_1.0_amd64.deb" }
            ]
        });
        assert_eq!(
            github_asset_url(&https_asset, "x86_64-linux", "o", "r").expect("TLS asset passes"),
            "https://e/demo-app_1.0_amd64.deb"
        );
    }

    #[test]
    fn select_deb_asset_picks_the_native_arch_and_rejects_the_foreign_one() {
        let json: serde_json::Value = serde_json::from_str(RELEASE_ASSETS).unwrap();
        // x86_64 selects the amd64 deb, never the arm64 deb or the mac/win assets.
        assert_eq!(
            prebuilt::select_release_asset(&json, "x86_64-linux", ".deb").as_deref(),
            Some(
                "https://github.com/example/demo-app/releases/download/v2.1.35/demo-app-2.1.35-linux-amd64.deb"
            )
        );
        // aarch64 selects the arm64 deb from the same release.
        assert_eq!(
            prebuilt::select_release_asset(&json, "aarch64-linux", ".deb").as_deref(),
            Some(
                "https://github.com/example/demo-app/releases/download/v2.1.35/demo-app-2.1.35-linux-arm64.deb"
            )
        );
    }

    #[test]
    fn select_deb_asset_falls_back_to_a_single_untokened_deb_and_none_when_absent() {
        // a single-arch repo whose one `.deb` carries no arch token is taken (x86_64 host).
        let single = serde_json::json!({
            "assets": [
                { "name": "myapp_1.2.3.deb", "browser_download_url": "https://e/myapp_1.2.3.deb" },
                { "name": "myapp_1.2.3.AppImage", "browser_download_url": "https://e/x.AppImage" }
            ]
        });
        assert_eq!(
            prebuilt::select_release_asset(&single, "x86_64-linux", ".deb").as_deref(),
            Some("https://e/myapp_1.2.3.deb")
        );
        // no `.deb` at all → None (the caller turns this into a fail-closed error, no pin).
        let none = serde_json::json!({
            "assets": [ { "name": "app.AppImage", "browser_download_url": "https://e/app.AppImage" } ]
        });
        assert_eq!(
            prebuilt::select_release_asset(&none, "x86_64-linux", ".deb"),
            None
        );
        // two arch-tokened debs but neither native, and >1 survivor → ambiguous → None (no guess).
        let foreign = serde_json::json!({
            "assets": [
                { "name": "app-arm64.deb", "browser_download_url": "https://e/arm64.deb" },
                { "name": "app-armhf.deb", "browser_download_url": "https://e/armhf.deb" }
            ]
        });
        assert_eq!(
            prebuilt::select_release_asset(&foreign, "x86_64-linux", ".deb"),
            None
        );
    }

    #[test]
    fn select_deb_asset_prefers_the_plain_arch_build_over_a_same_arch_gpu_variant() {
        // A repo that ships a GPU variant of the same architecture beside the plain build. The arch
        // token sorts `amd64-vulkan.deb` before `amd64.deb` (`-` < `.`), so a naive first-contains
        // match would take the variant; the terminal-arch preference selects the plain build.
        let json = serde_json::json!({
            "assets": [
                { "name": "demo-app_1.43.0_amd64-vulkan.deb",
                  "browser_download_url": "https://e/demo-app_1.43.0_amd64-vulkan.deb" },
                { "name": "demo-app_1.43.0_amd64.deb",
                  "browser_download_url": "https://e/demo-app_1.43.0_amd64.deb" }
            ]
        });
        assert_eq!(
            prebuilt::select_release_asset(&json, "x86_64-linux", ".deb").as_deref(),
            Some("https://e/demo-app_1.43.0_amd64.deb")
        );
    }

    fn deb_pkg(name: &str, url: &str, trusted: bool) -> crate::config::Package {
        crate::config::Package {
            name: name.into(),
            backend: crate::config::Backend::Deb(url.into()),
            state: if trusted {
                crate::trust::TrustState::Trusted
            } else {
                crate::trust::TrustState::Untrusted
            },
            libs: Vec::new(),
        }
    }

    #[test]
    fn declared_trusted_covers_baseline_and_apps_dedups_and_drops_untrusted() {
        let cfg = resolved(
            vec![
                deb_pkg("a", "https://e/a.deb", true),
                deb_pkg("evil", "https://e/evil.deb", false), // untrusted: dropped
            ],
            vec![
                (
                    "alpha",
                    app_with(vec![
                        deb_pkg("b", "https://e/b.deb", true),
                        deb_pkg("a2", "https://e/a.deb", true), // duplicate url: deduped
                    ]),
                ),
                ("beta", app_with(vec![])), // no deb package: contributes nothing
            ],
        );
        // baseline first, then the app's new url; the duplicate and the untrusted one are gone.
        let keys: Vec<String> = prebuilt::declared(&Deb, &cfg)
            .trusted
            .iter()
            .map(prebuilt::Ref::key)
            .collect();
        assert_eq!(keys, vec!["https://e/a.deb", "https://e/b.deb"]);
    }

    #[test]
    fn the_prune_universe_keeps_untrusted_so_upgrade_never_prunes_a_withheld_pin() {
        // The prune universe must NOT drop a still-declared url just because the project is
        // untrusted — else `sbx upgrade deb` on a Changed project unpins it. Unlike the trusted roll
        // set, `declared().all` keeps the untrusted url; `withheld` counts it so the summary is honest.
        let cfg = resolved(
            vec![
                deb_pkg("a", "https://e/a.deb", true),
                deb_pkg("evil", "https://e/evil.deb", false),
            ],
            vec![(
                "app",
                app_with(vec![deb_pkg("c", "https://e/c.deb", false)]),
            )],
        );
        let universe = prebuilt::declared(&Deb, &cfg).all;
        assert!(universe.contains("https://e/a.deb"));
        assert!(
            universe.contains("https://e/evil.deb"),
            "a withheld-but-declared url must survive pruning"
        );
        assert!(universe.contains("https://e/c.deb"));
        assert_eq!(
            withheld(&cfg),
            2,
            "the two untrusted deb packages are counted"
        );
    }

    #[test]
    fn parse_source_dispatches_apt_url_and_github_by_prefix() {
        assert!(matches!(parse_source("apt:https://h/x/dists/s/Packages"),
            DebSource::Apt { packages_url } if packages_url == "https://h/x/dists/s/Packages"));
        assert!(matches!(
            parse_source("github:o/r"),
            DebSource::Github { .. }
        ));
        assert!(matches!(parse_source("https://h/x.deb"), DebSource::Url(_)));
    }

    // A trimmed apt `Packages` index shaped like a vendor's single-application pool: several versions
    // of one package, newest NOT last, so the ordering (not the file order) is what's under test.
    const APT_INDEX: &str = "\
Package: demo-app
Version: 1.18286.2
Filename: pool/main/d/demo-app/demo-app_1.18286.2_amd64.deb

Package: demo-app
Version: 1.21459.0
Filename: pool/main/d/demo-app/demo-app_1.21459.0_amd64.deb

Package: demo-app
Version: 1.17377.0
Filename: pool/main/d/demo-app/demo-app_1.17377.0_amd64.deb
";

    #[test]
    fn select_latest_apt_deb_picks_the_highest_version_not_the_last_line() {
        let (version, filename) = select_latest_apt_deb(APT_INDEX).expect("resolves");
        // 1.21459.0 > 1.18286.2 numerically (a lexical/`sort`-style compare would pick 1.18286.2);
        // and it is not the last stanza, so file order is not what won.
        assert_eq!(version, "1.21459.0");
        assert_eq!(
            filename,
            "pool/main/d/demo-app/demo-app_1.21459.0_amd64.deb"
        );
    }

    #[test]
    fn select_latest_apt_deb_is_crlf_safe() {
        // The same index served with CRLF line endings must parse into the same stanzas and pick the
        // same newest version — grouping on `lines()` (not `split("\n\n")`) makes it CRLF-safe. A
        // `\n\n`-based parser would collapse this to one block and return the LAST stanza (1.17377.0).
        let crlf = APT_INDEX.replace('\n', "\r\n");
        let (version, _) = select_latest_apt_deb(&crlf).expect("resolves");
        assert_eq!(version, "1.21459.0");
    }

    #[test]
    fn select_latest_apt_deb_refuses_a_multi_package_index() {
        let multi =
            format!("{APT_INDEX}\nPackage: other-app\nVersion: 9.9.9\nFilename: pool/o.deb\n");
        let err = select_latest_apt_deb(&multi).unwrap_err();
        assert!(err.contains("more than one package"), "got: {err}");
    }

    #[test]
    fn select_latest_apt_deb_refuses_a_non_numeric_version_rather_than_misordering() {
        let idx = "Package: p\nVersion: 2.0.0~rc1\nFilename: pool/p.deb\n";
        let err = select_latest_apt_deb(idx).unwrap_err();
        assert!(err.contains("dotted-decimal"), "got: {err}");
        // an empty index is refused too
        assert!(select_latest_apt_deb("").is_err());
    }

    // Live check (skip-not-fail, like the nixhub resolution test): resolve a REAL vendor apt index
    // through the whole Rust chain — nix fetch of the uncompressed `Packages`, version selection,
    // repo-root join, and the `is_valid_deb_url` re-validation — WITHOUT the heavy `.deb` prefetch.
    // Anthropic's claude-desktop pool has no `latest` alias, which is exactly what `deb:apt:` is for.
    #[test]
    fn resolve_apt_deb_url_derives_a_current_deb_from_the_real_claude_index() {
        let Some(nix) = store::resolve_nix(None) else {
            skip_incapable!("skipping deb:apt live resolve: no nix on PATH");
            return;
        };
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        const INDEX: &str = "https://downloads.claude.ai/claude-desktop/apt/stable/dists/stable/main/binary-amd64/Packages";
        let url = match resolve_apt_deb_url(&nix, &layout, INDEX, true, false) {
            Ok(u) => u,
            Err(e) => {
                skip_unreachable!("skipping deb:apt live resolve (network/nix): {e}");
                return;
            }
        };
        // The derived URL passed the same charset validation a hand-written `deb:` URL does, and
        // names the claude-desktop pool.
        assert!(
            crate::config::is_valid_deb_url(&url, false),
            "derived URL invalid: {url}"
        );
        assert!(
            url.starts_with("https://downloads.claude.ai/claude-desktop/apt/stable/pool/")
                && url.contains("/claude-desktop_")
                && url.ends_with("_amd64.deb"),
            "unexpected derived URL: {url}"
        );
        // It is a *current* pick: the version embedded in the resolved filename orders at or above
        // the version this profile used to hand-pin (1.18286.2), proving newest-wins on the live
        // index, not a stale or lexical choice.
        let ver = url
            .rsplit_once("claude-desktop_")
            .and_then(|(_, tail)| tail.strip_suffix("_amd64.deb"))
            .expect("version token in filename");
        let (parsed, floor) = (
            parse_numeric_version(ver).expect("numeric version"),
            parse_numeric_version("1.18286.2").unwrap(),
        );
        assert!(
            parsed >= floor,
            "resolved {ver} is older than the former pin 1.18286.2"
        );
    }

    #[test]
    fn numeric_version_parse_and_repo_root() {
        assert_eq!(parse_numeric_version("1.21459.0"), Some(vec![1, 21459, 0]));
        assert!(parse_numeric_version("1.2~rc").is_none());
        assert!(parse_numeric_version("").is_none());
        // repo root is the URL up to the `/dists/` segment; Filename resolves against it.
        assert_eq!(
            apt_repo_root(
                "https://apt.example.com/demo-app/apt/stable/dists/stable/main/binary-amd64/Packages"
            ),
            Some("https://apt.example.com/demo-app/apt/stable")
        );
        assert_eq!(apt_repo_root("https://h/no-dists/Packages"), None);
    }

    /// The exact bytes the clearsigned fixture attests, so a digest computed here can be compared
    /// against one a signature covers rather than against one this test computed for itself.
    const ATTESTED_INDEX: &str = concat!(
        "Package: demo-app\n",
        "Version: 1.2.3\n",
        "Filename: pool/main/d/demo-app/demo-app_1.2.3_amd64.deb\n"
    );
    const ATTESTED_PATH: &str = "main/binary-amd64/Packages";

    /// The signed `Release` body, obtained the way production obtains it: by verifying, not by
    /// reading the file past its signature.
    fn attested_release() -> String {
        let armored = include_str!("openpgp/clearsigned.txt");
        let key = openpgp::parse_public_key(include_str!("openpgp/key.asc")).expect("key parses");
        openpgp::verify_clearsigned(armored, &key, &key.fingerprint).expect("fixture verifies")
    }

    #[test]
    fn a_pin_that_no_longer_signs_the_repository_refuses_instead_of_resolving() {
        let Some(nix) = store::resolve_nix(None) else {
            skip_incapable!("skipping deb:apt pin enforcement: no nix on PATH");
            return;
        };
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        const INDEX: &str = "https://downloads.claude.ai/claude-desktop/apt/stable/dists/stable/main/binary-amd64/Packages";
        // Pin a key that did not sign this repository — the shape of a repository that was re-keyed,
        // or of an index served by someone else. Everything else about the resolve is unchanged, so
        // what the refusal is about is the pin and nothing else.
        let pin = pinned_key_path(&layout, &inrelease_url(INDEX).unwrap());
        write_pinned_key(&pin, include_str!("openpgp/key.asc")).expect("the pin is written");
        let err = match resolve_apt_deb_url(&nix, &layout, INDEX, true, false) {
            Err(e) => e.to_string(),
            Ok(url) => panic!("a repository whose pinned key no longer signs it resolved to {url}"),
        };
        // Refused at the signature, which is the enforcement: this is the whole value of pinning,
        // and a resolve that merely warned here would leave the TOFU open at every upgrade.
        assert!(err.contains("is not valid"), "{err}");
        assert!(err.contains("signature verification failed"), "{err}");
        // And with the pin removed the same call resolves, so the refusal is not the network or the
        // index failing under another name.
        std::fs::remove_file(&pin).expect("the pin is removed");
        match resolve_apt_deb_url(&nix, &layout, INDEX, true, false) {
            Ok(url) => assert!(url.ends_with("_amd64.deb"), "{url}"),
            Err(e) => skip_unreachable!("skipping deb:apt pin enforcement (network/nix): {e}"),
        }
    }

    /// Only an *absent* pin means "never pinned". `.ok()` collapsed every read error to that — and
    /// "never pinned" is the branch that runs trust-on-first-use, taking whatever key the
    /// repository's signature names today. A pin that merely could not be read therefore re-pinned
    /// the repository silently, which is the one outcome pinning exists to prevent.
    ///
    /// Offline: the pin is read before anything is fetched, so the refusal lands before the network
    /// is touched — which is also what this asserts by passing a `nix` that does not exist.
    #[test]
    fn a_pin_that_cannot_be_read_refuses_rather_than_re_pinning() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        const INDEX: &str = "https://vendor.test/apt/dists/stable/main/binary-amd64/Packages";
        let nowhere = std::path::Path::new("/nonexistent-by-construction/nix");

        // A directory where the pinned key belongs: unreadable as a file, and not `NotFound`.
        let pin = pinned_key_path(&layout, &inrelease_url(INDEX).unwrap());
        std::fs::create_dir_all(&pin).expect("the obstruction is placed");

        let err = match attest_index(nowhere, &layout, INDEX, "", false) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("an unreadable pin must refuse, not fall back to first use"),
        };
        assert!(
            err.contains("cannot be read") && err.contains("re-pin"),
            "the refusal must name what it will not do: {err}"
        );

        // With nothing at that path the same call reaches the fetch instead — so the refusal above
        // is about the pin and not about this repository being unreachable.
        std::fs::remove_dir(&pin).expect("the obstruction is removed");
        match attest_index(nowhere, &layout, INDEX, "", false) {
            Ok(Attested::Unpinned(_)) => {}
            Ok(_) => panic!("a repository that publishes nothing sbx can fetch cannot be attested"),
            Err(e) => panic!("an absent pin is the ordinary first-use path, not an error: {e}"),
        }
    }

    #[test]
    fn a_first_pin_holds_a_fetched_key_to_the_fingerprint_the_signature_claimed() {
        let armored = include_str!("openpgp/key.asc");
        let signed = include_str!("openpgp/clearsigned.txt");
        let other = openpgp::parse_public_key(include_str!("openpgp/key_other.asc")).unwrap();

        // With no claim the key is one sbx pinned itself, so it answers to its own fingerprint and
        // the signature is what enforces.
        let (key, anchor) = anchored_key(armored, None).expect("the pinned key reads");
        assert_eq!(anchor, key.fingerprint);
        assert!(openpgp::verify_clearsigned(signed, &key, &anchor).is_ok());

        // On a first pin the anchor is the CLAIM, not the material. A keyserver that answered with
        // some other key is then refused by the comparison instead of being tried against the
        // signature — which is the only thing that makes fetching a key by fingerprint safe.
        let (fetched, anchor) =
            anchored_key(armored, Some(other.fingerprint)).expect("the fetched key reads");
        assert_eq!(anchor, other.fingerprint);
        assert_ne!(anchor, fetched.fingerprint);
        let err = openpgp::verify_clearsigned(signed, &fetched, &anchor)
            .expect_err("a key that is not the one claimed must be refused");
        assert!(err.contains("not the pinned one"), "{err}");
        // And when the keyserver answers with the key that was asked for, the anchor is satisfied
        // and the resolve proceeds, so the refusal above is about the mismatch and nothing else.
        let (fetched, anchor) =
            anchored_key(armored, Some(key.fingerprint)).expect("the fetched key reads");
        assert_eq!(anchor, fetched.fingerprint);
        assert!(openpgp::verify_clearsigned(signed, &fetched, &anchor).is_ok());
    }

    #[test]
    fn a_signed_release_attests_an_index_by_a_digest_an_attacker_cannot_collide() {
        let release = attested_release();
        let (algorithm, hex, size) =
            signed_digest(&release, ATTESTED_PATH).expect("the fixture attests the index");
        // A `Release` lists the same file under MD5Sum and SHA1 as well, and lists them FIRST. A
        // lookup that scanned for the filename would take the MD5 line — which is why sections are
        // recognised by their header and only the strong two are read.
        assert_eq!(algorithm, "SHA256");
        assert_eq!(hex.len(), 64);
        assert_eq!(size, ATTESTED_INDEX.len() as u64);
        assert!(
            release.contains("MD5Sum:"),
            "the fixture must carry the weak sections"
        );
        assert!(release.contains("SHA1:"));
        // Neither weak digest may be reachable as the answer, whatever the file is called.
        let md5 = release
            .lines()
            .find(|l| l.starts_with(' ') && l.ends_with(ATTESTED_PATH))
            .expect("the MD5 line exists");
        assert!(
            !md5.contains(&hex),
            "the answer must not come from the MD5 section"
        );
    }

    /// Pad every message line of a clearsigned document on the right, the way an attacker can.
    ///
    /// Only the message is padded, never the armor: a padded blank line in the armor header block
    /// would stop `\n\n` from being found and the document would be refused for the wrong reason,
    /// which is a harness that measures its own mistake rather than the property.
    fn padded_on_the_right(armored: &str) -> String {
        const SIG: &str = "-----BEGIN PGP SIGNATURE-----";
        let body_at = armored
            .find("\n\n")
            .expect("the fixture has an armor header block")
            + 2;
        let sig_at = armored.find(SIG).expect("the fixture carries a signature");
        // The message ends with the newline that belongs to the armor below it, so splitting leaves
        // a final empty piece. Padding THAT one would append a whitespace line to the canonical text
        // rather than pad an existing one, and the signature would fail — a harness editing the
        // structure it means to leave alone.
        let pieces: Vec<&str> = armored[body_at..sig_at].split('\n').collect();
        let last = pieces.len() - 1;
        let padded: Vec<String> = pieces
            .iter()
            .enumerate()
            .map(|(i, l)| {
                if i == last {
                    (*l).to_string()
                } else {
                    format!("{l} \t ")
                }
            })
            .collect();
        format!(
            "{}{}{}",
            &armored[..body_at],
            padded.join("\n"),
            &armored[sig_at..]
        )
    }

    #[test]
    fn a_release_padded_where_the_signature_does_not_look_attests_the_very_same_digest() {
        // An OpenPGP canonical text signature is computed over lines trimmed on the RIGHT only, so
        // trailing whitespace added after signing still verifies while leading whitespace does not.
        // The asymmetry is why this guard is one-sided: a right-pad is reachable by anyone who can
        // rewrite the document in flight, a left-pad is not.
        //
        // `openpgp::verify_clearsigned` hands back the message **as transmitted**, padding included
        // (its own test pins that, and it is the correct behaviour: only the hash input is
        // canonicalised). So the padding an attacker adds reaches this module intact, and what makes
        // it harmless is here rather than there — `signed_digest` splits on whitespace and trims its
        // section headers, `valid_until` trims its value. Nothing tested that until this test, and
        // the two halves of the property live in two files, which is how one of them gets
        // "simplified" away. Measured against GnuPG on 2026-08-21: gpg strips the padding from its
        // output and sbx keeps it, so the two disagree about the message and agree about what it
        // attests. This asserts the second half.
        let armored = include_str!("openpgp/clearsigned.txt");
        let key = openpgp::parse_public_key(include_str!("openpgp/key.asc")).expect("key parses");
        let padded = padded_on_the_right(armored);
        assert_ne!(
            padded, armored,
            "the padding must actually change the document"
        );

        // First: the padded document still verifies. Without this the rest would be asserting
        // whitespace handling on a document no attacker could get past the signature.
        let release = openpgp::verify_clearsigned(&padded, &key, &key.fingerprint)
            .expect("a right-padded document still verifies, which is what makes this reachable");
        assert!(
            release.contains(" \t \n"),
            "the padding must survive into the message the caller acts on"
        );

        // Then: every answer this module draws from that message is unchanged.
        assert_eq!(
            signed_digest(&release, ATTESTED_PATH),
            signed_digest(&attested_release(), ATTESTED_PATH),
            "a padded `InRelease` must attest exactly what the unpadded one attests"
        );
        assert_eq!(
            valid_until(&release),
            valid_until(&attested_release()),
            "padding must not change the staleness stamp either"
        );
        // And the chain still closes on the real index, so the property is asserted end to end
        // rather than only on the parse.
        let (algorithm, hex, size) =
            signed_digest(&release, ATTESTED_PATH).expect("the padded release still attests");
        assert!(index_matches(ATTESTED_INDEX, algorithm, &hex, size));
    }

    #[test]
    fn an_index_the_signature_does_not_cover_is_refused_though_the_signature_is_valid() {
        let release = attested_release();
        let (algorithm, hex, size) = signed_digest(&release, ATTESTED_PATH).unwrap();
        // The chain closes: these bytes are the ones the signature covers.
        assert!(index_matches(ATTESTED_INDEX, algorithm, &hex, size));
        // And this is the property that separates a chain from a signature check that then trusts
        // the pin it already held. The signature over the `Release` is untouched and still verifies;
        // only the index was swapped, for one of the same length so the size check is not what
        // catches it.
        let swapped = ATTESTED_INDEX.replacen("1.2.3_amd64", "9.9.9_amd64", 1);
        assert_eq!(swapped.len(), ATTESTED_INDEX.len());
        assert_ne!(swapped, ATTESTED_INDEX);
        assert!(!index_matches(&swapped, algorithm, &hex, size));
        // A truncation is caught too, and by the digest rather than only by the length.
        assert!(!index_matches(
            &ATTESTED_INDEX[..ATTESTED_INDEX.len() - 1],
            algorithm,
            &hex,
            size
        ));
    }

    #[test]
    fn a_stronger_digest_wins_and_an_unattested_path_has_no_answer() {
        let release = "SHA256:\n abcd 10 main/x\nSHA512:\n ef01 10 main/x\n";
        let (algorithm, hex, _) = signed_digest(release, "main/x").expect("attested");
        assert_eq!((algorithm, hex.as_str()), ("SHA512", "ef01"));
        // A path the signature says nothing about must not fall back to anything.
        assert!(signed_digest(release, "main/y").is_none());
        // A file named inside a section, but under a weak header, is not an answer either.
        assert!(signed_digest("MD5Sum:\n abcd 10 main/x\n", "main/x").is_none());
        // An indented line under no section at all is ignored rather than adopted by the last one.
        assert!(signed_digest(" ef01 10 main/x\n", "main/x").is_none());
    }

    #[test]
    fn the_attestation_is_looked_for_where_the_layout_puts_it() {
        let index = "https://apt.example.com/demo/stable/dists/stable/main/binary-amd64/Packages";
        assert_eq!(
            inrelease_url(index).as_deref(),
            Some("https://apt.example.com/demo/stable/dists/stable/InRelease")
        );
        // The path the signed digests are keyed by is everything under the suite — the same string
        // `signed_digest` is then asked about, so the two cannot drift.
        assert_eq!(index_path(index), Some("main/binary-amd64/Packages"));
        assert_eq!(inrelease_url("https://h/no-dists/Packages"), None);
        assert_eq!(index_path("https://h/x/dists/stable"), None);
    }

    #[test]
    fn an_expiry_is_read_only_in_the_form_the_specification_fixes() {
        let release = "Valid-Until: Tue, 25 Aug 2026 23:37:43 UTC\n";
        assert_eq!(valid_until(release), Some("Tue, 25 Aug 2026 23:37:43 UTC"));
        let stamp = "Tue, 25 Aug 2026 23:37:43 UTC";
        // One second either side of the stamp, so the comparison is the boundary and not a window.
        let at = parse_valid_until(stamp).expect("the specification's form parses");
        assert!(!expired_at(stamp, at));
        assert!(expired_at(stamp, at + 1));
        assert!(!expired_at(stamp, at - 1));
        // A known instant, so the epoch arithmetic is held to a value and not to itself.
        assert_eq!(parse_valid_until("Thu, 01 Jan 1970 00:00:00 UTC"), Some(0));
        // Both sides of a leap-year boundary, checked against `date -u -d ... +%s`.
        assert_eq!(
            parse_valid_until("Sat, 01 Mar 2036 00:00:00 UTC"),
            Some(2_087_942_400)
        );
        assert_eq!(
            parse_valid_until("Fri, 29 Feb 2036 00:00:00 UTC"),
            Some(2_087_856_000)
        );
        // Anything sbx cannot read is NOT expired: a warning that fired on an unread format would
        // teach the user to ignore it.
        assert!(!expired_at("Tue, 25 Aug 2026 23:37:43 CEST", u64::MAX));
        assert!(!expired_at("whenever", u64::MAX));
        assert!(!expired_at("Tue, 25 Foo 2026 23:37:43 UTC", u64::MAX));
        assert!(valid_until("Origin: demo\n").is_none());
    }
}
