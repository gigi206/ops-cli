//! Talking to an OCI registry: resolve a reference to a digest, then fetch the layers it names.
//!
//! Three requests and one rule. The rule is that **nothing is trusted because of where it came
//! from**: a manifest is accepted only when its own bytes hash to the digest that asked for it, and
//! a layer blob likewise. Content addressing is what a registry is for, so the transport is a
//! convenience and the digest is the guarantee. That is also why a redirect to object storage is
//! harmless here, and why the pin recorded in a lock is worth what it says.
//!
//! ## The authentication dance, and why it is not hard-coded
//!
//! A registry answers an unauthenticated request with `401` and a `WWW-Authenticate` header naming
//! where to get a token and for what scope. Following that header, rather than special-casing Docker
//! Hub's endpoint, is what makes ghcr, quay and a private registry work without a line each: every
//! conformant registry publishes its own realm the same way. A registry that needs no token simply
//! never sends the challenge, and the first request is the only one.

use super::http;
use super::reference::{self, ImageRef, Reference};
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};

/// The media types a manifest request accepts, most specific first. Both the OCI names and Docker's
/// older ones, because a registry serves whichever the image was pushed as and an image is not
/// re-pushed to suit a client.
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json,\
application/vnd.docker.distribution.manifest.list.v2+json,\
application/vnd.oci.image.manifest.v1+json,\
application/vnd.docker.distribution.manifest.v2+json";

/// The platform an image has to carry. The cage's loader path is x86-64-specific
/// ([`crate::sandbox::fhs`]), so an image for another architecture would resolve, fetch and unpack
/// into a tree nothing in it can execute. Selecting here means the refusal names the platform
/// instead of surfacing later as an `Exec format error`.
const OS: &str = "linux";
const ARCH: &str = "amd64";

/// A blob the manifest points at: what to fetch and how big it claims to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Layer {
    pub(super) digest: String,
    pub(super) media_type: String,
    pub(super) size: u64,
}

/// What a resolved image is: the digest that pins it, and the layers to apply in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Image {
    /// The digest the reference resolved to: the **index**'s when the image is multi-platform,
    /// which is what a tag names and what every other tool reports for it. Re-resolving by it picks
    /// the same platform manifest, so it is a pin as exact as the per-platform digest and it is the
    /// one a reader can paste into another tool.
    pub(super) digest: String,
    /// The layers of the `linux/amd64` manifest, in the order they are applied.
    pub(super) layers: Vec<Layer>,
}

/// The `/v2/` URL for a manifest or a blob under `image`'s registry.
fn v2_url(image: &ImageRef, kind: &str, reference: &str) -> String {
    format!(
        "https://{}/v2/{}/{}/{}",
        image.api_host(),
        image.repository,
        kind,
        reference
    )
}

/// A registry credential, already in the form a header carries it.
///
/// Built once from the `<username>:<password>` a `[distro] auth` reference resolved to, so the
/// encoding happens at the boundary rather than at each of the three requests that may need it, and
/// the plaintext pair is not carried around beside the encoded one.
#[derive(Clone)]
pub(super) struct Credential(String);

impl Credential {
    /// Encode `<username>:<password>` as the value of a `Basic` `Authorization` header.
    pub(super) fn basic(user_password: &str) -> Credential {
        Credential(format!("Basic {}", base64(user_password.as_bytes())))
    }

    fn header(&self) -> &str {
        &self.0
    }
}

// A credential must not reach a log, a panic message or a `{:?}` of the struct that holds it.
impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential(<redacted>)")
    }
}

/// Standard base64, written here for the reason the gzip reader was: what it needs is one table and
/// a three-bytes-to-four-characters loop, and a dependency for that would cost more than it saves.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i)) as usize & 0x3f] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A bearer token for `image`, or `None` when the registry answered without asking for one.
///
/// `challenge` is the `WWW-Authenticate` value the registry sent with its `401`. Only the `Bearer`
/// scheme is followed here; a `Basic` challenge is answered by the caller, which has the credential
/// and the original request to repeat.
///
/// `credential` goes on **this** request and nowhere else. It is what the registry's token service
/// exchanges for a token scoped to one repository, and once that token exists it is what every
/// later request carries — so the credential itself never reaches the registry's blob storage, its
/// CDN, or whatever host a redirect names.
fn token(challenge: &str, credential: Option<&Credential>) -> io::Result<Option<String>> {
    let Some(params) = challenge.trim().strip_prefix("Bearer ") else {
        return Ok(None);
    };
    let mut realm = None;
    let mut extra: Vec<(String, String)> = Vec::new();
    for part in params.split(',') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        match key.trim() {
            "realm" => realm = Some(value),
            "service" | "scope" => extra.push((key.trim().to_string(), value)),
            _ => {}
        }
    }
    let realm = realm.ok_or_else(|| {
        io::Error::other(format!("registry challenge names no realm: {challenge}"))
    })?;
    // The realm is a URL the registry chose, so it goes through the same https-only gate every
    // other hop does; `http::get` refuses anything else.
    let query: Vec<String> = extra
        .iter()
        .map(|(k, v)| format!("{k}={}", percent_encode(v)))
        .collect();
    let url = if query.is_empty() {
        realm
    } else {
        format!("{realm}?{}", query.join("&"))
    };
    let headers: Vec<(&str, &str)> = credential
        .map(|c| vec![("Authorization", c.header())])
        .unwrap_or_default();
    let response = http::get(&url, &headers)?;
    if response.status != 200 {
        return Err(io::Error::other(format!(
            "token endpoint answered {}{}",
            response.status,
            if credential.is_some() {
                " (the `distro` credential was presented)"
            } else {
                " (no `distro` credential is configured)"
            }
        )));
    }
    let doc: serde_json::Value = serde_json::from_slice(&response.body)
        .map_err(|e| io::Error::other(format!("parsing the token document: {e}")))?;
    // Registries disagree on the field name and both spellings are in the wild.
    let token = doc
        .get("token")
        .or_else(|| doc.get("access_token"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| io::Error::other("the token document carries no token"))?;
    Ok(Some(token.to_string()))
}

/// Percent-encode a query parameter value. The scope carries a repository path with `/` and `:` in
/// it, which are legal in a query but only by accident of the grammar; encoding them keeps the URL
/// unambiguous whatever the registry's parser does with them.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Fetch `url`, obtaining a token first if the registry asks for one.
///
/// The challenge is followed exactly once: a second `401` after presenting a token means the token
/// does not authorise this repository, and retrying would loop.
fn get_authenticated(
    url: &str,
    accept: Option<&str>,
    credential: Option<&Credential>,
) -> io::Result<http::Response> {
    let base: Vec<(&str, &str)> = accept.map(|a| vec![("Accept", a)]).unwrap_or_default();
    let first = http::get(url, &base)?;
    if first.status != 401 {
        return Ok(first);
    }
    let Some(challenge) = first.header("www-authenticate") else {
        return Ok(first);
    };
    // A registry that asks for `Basic` has no token service to go through, so the credential
    // answers the original request. Common on a self-hosted registry, and the reason the challenge
    // is read rather than assumed to be `Bearer`.
    let authorization = match basic_answer(challenge, credential) {
        Some(header) => header.to_string(),
        None => match token(challenge, credential)? {
            Some(token) => format!("Bearer {token}"),
            None => return Ok(first),
        },
    };
    let mut headers = base;
    headers.push(("Authorization", &authorization));
    http::get(url, &headers)
}

/// The credential to answer a `Basic` challenge with, or `None` when the challenge is not `Basic`
/// or no credential was configured. A `Basic` challenge with nothing to answer it falls through to
/// the token path, which returns the registry's own `401` rather than inventing an error.
fn basic_answer<'a>(challenge: &str, credential: Option<&'a Credential>) -> Option<&'a str> {
    challenge
        .trim()
        .to_ascii_lowercase()
        .starts_with("basic")
        .then(|| credential.map(Credential::header))
        .flatten()
}

/// The same, for a blob streamed to `sink`. The token is obtained against the blob URL itself, so
/// the scope the registry names is the one this request needs.
fn get_authenticated_to_writer<W: io::Write>(
    url: &str,
    credential: Option<&Credential>,
    sink: &mut W,
    cap: u64,
) -> io::Result<u64> {
    let probe = http::get(url, &[])?;
    if probe.status == 401
        && let Some(challenge) = probe.header("www-authenticate")
    {
        let authorization = match basic_answer(challenge, credential) {
            Some(header) => Some(header.to_string()),
            None => token(challenge, credential)?.map(|t| format!("Bearer {t}")),
        };
        if let Some(authorization) = authorization {
            return http::get_to_writer(url, &[("Authorization", &authorization)], sink, cap);
        }
    }
    http::get_to_writer(url, &[], sink, cap)
}

/// Resolve `image` to the digest and layer list of a `linux/amd64` image.
///
/// A tag becomes the digest the registry serves for it *now*, which is what a lock records. A
/// locator that already carries a digest is not re-resolved into something else: the manifest is
/// fetched by that digest and checked against it, so this path proves the pin rather than trusting
/// it.
pub(super) fn resolve(image: &ImageRef, credential: Option<&Credential>) -> io::Result<Image> {
    let selector = match &image.reference {
        Reference::Tag(tag) => tag.clone(),
        Reference::Digest(digest) => digest.clone(),
    };
    let url = v2_url(image, "manifests", &selector);
    let response = get_authenticated(&url, Some(MANIFEST_ACCEPT), credential)?;
    if response.status != 200 {
        return Err(io::Error::other(format!(
            "{} answered {} for {}",
            image.api_host(),
            response.status,
            image.locator()
        )));
    }
    let digest = digest_of(&response.body);
    // A locator that named a digest gets it checked against the bytes that came back: the point of
    // pinning by content is lost if the content is taken on the registry's word.
    if let Reference::Digest(pinned) = &image.reference
        && &digest != pinned
    {
        return Err(io::Error::other(format!(
            "{} served a manifest hashing to {digest} for the pin {pinned}",
            image.api_host()
        )));
    }
    let doc: serde_json::Value = serde_json::from_slice(&response.body)
        .map_err(|e| io::Error::other(format!("parsing the manifest: {e}")))?;

    // An index names one manifest per platform; a manifest names layers. Which came back depends on
    // how the image was pushed, so the shape decides rather than the request.
    if let Some(manifests) = doc.get("manifests").and_then(|m| m.as_array()) {
        let picked = manifests
            .iter()
            .find(|entry| {
                let platform = entry.get("platform");
                let os = platform.and_then(|p| p.get("os")).and_then(|v| v.as_str());
                let arch = platform
                    .and_then(|p| p.get("architecture"))
                    .and_then(|v| v.as_str());
                os == Some(OS) && arch == Some(ARCH)
            })
            .and_then(|entry| entry.get("digest"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                io::Error::other(format!("{} carries no {OS}/{ARCH} image", image.locator()))
            })?;
        let picked = reference::valid_digest(picked)
            .ok_or_else(|| io::Error::other("the index names a malformed digest"))?;
        // The layers come from the platform manifest, but the pin stays the digest the reference
        // resolved to: a lock that named the per-platform manifest would not match what a tag
        // resolves to anywhere else.
        let platform = resolve(&image.pinned(picked), credential)?;
        return Ok(Image {
            digest,
            layers: platform.layers,
        });
    }

    let layers = doc
        .get("layers")
        .and_then(|l| l.as_array())
        .ok_or_else(|| io::Error::other(format!("{} names no layers", image.locator())))?
        .iter()
        .map(|entry| {
            let digest = entry
                .get("digest")
                .and_then(|v| v.as_str())
                .and_then(reference::valid_digest)
                .ok_or_else(|| io::Error::other("a layer names a malformed digest"))?;
            Ok(Layer {
                digest: digest.to_string(),
                media_type: entry
                    .get("mediaType")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                size: entry.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    Ok(Image { digest, layers })
}

/// Fetch one layer into `dir`, named by its digest, and return the path.
///
/// The digest is verified over the bytes as they are written, so a blob that is not what was asked
/// for never becomes a file the applier reads: the partial download is removed and the fetch fails
/// naming both digests.
pub(super) fn fetch_layer(
    image: &ImageRef,
    layer: &Layer,
    dir: &Path,
    credential: Option<&Credential>,
) -> io::Result<PathBuf> {
    let name = layer.digest.replace(':', "-");
    let path = dir.join(&name);
    if path.exists() {
        return Ok(path);
    }
    let partial = dir.join(format!("{name}.partial"));
    let url = v2_url(image, "blobs", &layer.digest);
    let mut sink = HashingWriter {
        inner: std::fs::File::create(&partial)?,
        hasher: Sha256::new(),
    };
    // What may be written before the digest can answer. The digest is computed from the bytes as
    // they land, so it is known only once the body is fully written: it bounds what is *kept*, not
    // what is *written*, and a body that never ends fills the disk before it is ever declared
    // wrong. A manifest that states a size holds the fetch to it; one that does not falls back to
    // the absolute ceiling rather than to no ceiling at all.
    let cap = if layer.size > 0 {
        layer.size
    } else {
        http::MAX_STREAMED_BODY
    };
    // Any failure removes the partial file, not only a digest mismatch: a fetch that stopped
    // halfway leaves bytes that are not a layer, and a later run must not find them and take them
    // for one.
    let written = match get_authenticated_to_writer(&url, credential, &mut sink, cap) {
        Ok(written) => written,
        Err(e) => {
            let _ = std::fs::remove_file(&partial);
            return Err(e);
        }
    };
    let got = format!(
        "sha256:{}",
        crate::plugins::catalogue::to_hex(&sink.hasher.finalize())
    );
    if got != layer.digest {
        let _ = std::fs::remove_file(&partial);
        return Err(io::Error::other(format!(
            "layer {} came back as {got}",
            layer.digest
        )));
    }
    // A stated size is also checked exactly: the cap above refuses a body that overruns it, this
    // refuses one that stops short of it.
    if layer.size > 0 && written != layer.size {
        let _ = std::fs::remove_file(&partial);
        return Err(io::Error::other(format!(
            "layer {} is {written} bytes, the manifest says {}",
            layer.digest, layer.size
        )));
    }
    std::fs::rename(&partial, &path)?;
    Ok(path)
}

/// A writer that hashes what passes through it, so the digest is computed from the very bytes that
/// land on disk rather than from a second read of the file.
struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
}

impl<W: io::Write> io::Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// The `sha256:` digest of `bytes`, in the spelling a manifest uses.
fn digest_of(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        crate::plugins::catalogue::to_hex(&Sha256::digest(bytes))
    )
}

#[cfg(test)]
mod tests;
