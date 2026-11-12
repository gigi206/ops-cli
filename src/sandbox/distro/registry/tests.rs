use super::*;

#[test]
fn a_v2_url_is_built_from_the_serving_host_not_the_published_one() {
    let image = reference::parse("oci:docker.io/library/debian:10").unwrap();
    assert_eq!(
        v2_url(&image, "manifests", "10"),
        "https://registry-1.docker.io/v2/library/debian/manifests/10"
    );
    let image = reference::parse("oci:ghcr.io/owner/img:1").unwrap();
    assert_eq!(
        v2_url(&image, "blobs", "sha256:0"),
        "https://ghcr.io/v2/owner/img/blobs/sha256:0"
    );
}

#[test]
fn a_scope_is_percent_encoded_so_the_query_cannot_be_read_two_ways() {
    assert_eq!(
        percent_encode("repository:library/debian:pull"),
        "repository%3Alibrary%2Fdebian%3Apull"
    );
    assert_eq!(percent_encode("registry.docker.io"), "registry.docker.io");
    assert_eq!(percent_encode("a-b_c.d~e"), "a-b_c.d~e");
}

#[test]
fn only_a_bearer_challenge_is_followed() {
    // `Basic` would mean presenting a credential sbx neither has nor was given.
    assert!(token("Basic realm=\"private\"", None).unwrap().is_none());
    assert!(token("", None).unwrap().is_none());
    // A Bearer challenge with no realm names nowhere to go, which is an error rather than a
    // silent unauthenticated retry.
    let err = token("Bearer service=\"registry.docker.io\"", None).expect_err("no realm");
    assert!(err.to_string().contains("names no realm"), "{err}");
}

#[test]
fn a_digest_is_computed_over_the_bytes_that_came_back() {
    // The empty document's SHA-256, which is what the manifest check compares a pin against.
    assert_eq!(
        digest_of(b""),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_ne!(digest_of(b"{}"), digest_of(b"{ }"));
}

/// Whether `e` says the registry was never heard from, or answered only that this is a bad moment.
///
/// The tests below run against a real registry, and only the network's failures are theirs to skip.
/// Everything else is asserted: a `401`, a `404` or a manifest that does not hash to its pin is the
/// registry's verdict on what this client sent, and reading it as a bad network turns the
/// regressions these tests exist for into green runs. A cause this does not recognise is asserted
/// too, so a message reworded in [`http`] fails the first run that meets it rather than skipping
/// every run after.
///
/// What a registry that was not heard from looks like, as this module's client reports it:
/// - the socket's own error, with its kind: a reset, an early close, or the read timeout, which
///   Linux reports as `WouldBlock`;
/// - `resolving …` and `connecting to …`, which [`http`] wraps the name lookup and the connection
///   in;
/// - `no complete response head …`, which any failure while a response head was arriving becomes;
/// - `… body shorter than Content-Length`, a body the connection stopped delivering before the
///   length it declared, which is how a layer download cut half-way ends. A body cut where no
///   length was declared reaches the caller as a size or a digest that does not match, which a
///   registry serving the wrong bytes also produces, so it is asserted;
/// - `answered` with `408`, `429` or a `5xx`, the statuses about the moment rather than the
///   request, as `tests/common`'s `transient_fetch_failure` splits them for nix's downloads.
///
/// The image store's provisioning test asks it of `provision`, which passes this client's errors
/// on as they are.
pub(in crate::sandbox::distro) fn transient(e: &io::Error) -> bool {
    if matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
    ) {
        return true;
    }
    let text = e.to_string();
    ["resolving ", "connecting to ", "no complete response head "]
        .iter()
        .any(|shape| text.starts_with(shape))
        || text.ends_with("body shorter than Content-Length")
        || answered(e).is_some_and(momentary)
}

/// Whether `status` is about the moment rather than the request: a timeout, a rate limit, or a
/// registry that is failing.
fn momentary(status: u16) -> bool {
    matches!(status, 408 | 429 | 500..=599)
}

/// The status in an `… answered <status> …` error, the shape in which [`resolve`], [`token`] and
/// [`http::get_to_writer`] refuse an answer they received.
fn answered(e: &io::Error) -> Option<u16> {
    let text = e.to_string();
    let (_, after) = text.split_once(" answered ")?;
    after.get(..3)?.parse().ok()
}

#[test]
fn a_registry_never_heard_from_is_told_apart_from_one_that_answered() {
    // The client's own errors, through its real paths: a port nothing listens on, and a peer that
    // accepts and closes before the TLS handshake is done.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    let port = listener.local_addr().expect("a bound port").port();
    let closer = std::thread::spawn(move || drop(listener.accept()));
    let Err(closed) = http::get(&format!("https://127.0.0.1:{port}/v2/"), &[]) else {
        panic!("the peer closed without answering, and a response came back");
    };
    // A client that failed before it connected leaves the peer waiting in `accept`: one connection
    // here ends that wait, and is refused when the peer has already gone.
    let _ = std::net::TcpStream::connect(("127.0.0.1", port));
    closer.join().expect("the closing peer");
    assert!(transient(&closed), "{closed}");
    let Err(refused) = http::get(&format!("https://127.0.0.1:{port}/v2/"), &[]) else {
        panic!("nothing listens on the port any more, and a response came back");
    };
    assert!(transient(&refused), "{refused}");

    // A body the connection stopped delivering before its declared length, as the copy every
    // `Content-Length` body goes through reports it: the cut a layer download meets half-way.
    let mut cut: &[u8] = b"ab";
    let short = crate::sandbox::proxy::wire::copy_exact(&mut cut, &mut Vec::new(), 5)
        .expect_err("a body shorter than its length is refused");
    assert!(transient(&short), "{short}");

    // The shapes the network's failures and the moment's statuses take in this module's errors.
    assert!(transient(&io::Error::from(io::ErrorKind::WouldBlock)));
    for unheard in [
        "resolving registry-1.docker.io:443: failed to lookup address information: Temporary \
         failure in name resolution",
        "connecting to registry-1.docker.io:443: Network is unreachable (os error 101)",
        "no complete response head from registry-1.docker.io",
        "registry-1.docker.io answered 429 for docker.io/library/alpine:3.22",
        "token endpoint answered 503 (no `distro` credential is configured)",
        "https://registry-1.docker.io/v2/library/alpine/blobs/sha256:0 answered 502",
    ] {
        assert!(transient(&io::Error::other(unheard)), "{unheard}");
    }

    // A verdict on what the client sent, or on what came back, is never the network's.
    for verdict in [
        "registry-1.docker.io answered 401 for docker.io/library/alpine:3.22",
        "https://registry-1.docker.io/v2/library/alpine/blobs/sha256:0 answered 404",
        "registry-1.docker.io served a manifest hashing to sha256:0 for the pin sha256:1",
        "layer sha256:0 came back as sha256:1",
        "docker.io/library/alpine:3.22 carries no linux/amd64 image",
        "oci:registry.example/team/app:1 nests more than 4 indexes before naming a manifest",
    ] {
        assert!(!transient(&io::Error::other(verdict)), "{verdict}");
    }
    let malformed = io::Error::new(
        io::ErrorKind::InvalidData,
        "a malformed header line from registry-1.docker.io",
    );
    assert!(!transient(&malformed), "{malformed}");
}

/// One `alpine:3.22` index, named by digest. It is deliberately not what that tag resolves to
/// today: a tag moves whenever Alpine republishes a patch release, while a digest names one
/// document for as long as the registry keeps it, which is what a by-digest pin has to be tested
/// against.
const ALPINE_3_22: &str = "sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce";

/// A tag's oracle is the registry's own `Docker-Content-Digest`, never a digest written down here.
///
/// A constant held that role until `alpine:3.22` moved under it: the index digest changed between
/// two runs hours apart, and a check that had passed went red on nothing the client had done. The
/// registry states the digest of the bytes it has just served, so comparing that against the digest
/// computed from those same bytes proves everything the constant proved — the challenge was
/// followed, the right media types were asked for, and the document was hashed the way a registry
/// hashes it — against a second implementation that cannot drift.
///
/// That a `linux/amd64` entry was picked out of the index is what the layers say: an index carries
/// none of its own, so a resolve that returns any fetched the platform manifest behind one.
#[test]
fn a_tag_resolves_to_the_digest_the_registry_itself_reports() {
    let image = reference::parse("oci:docker.io/library/alpine:3.22").unwrap();
    let url = v2_url(&image, "manifests", "3.22");
    let served = match get_authenticated(&url, Some(MANIFEST_ACCEPT), None) {
        Ok(served) => served,
        Err(e) if transient(&e) => {
            skip_unreachable!("skipping the registry resolve: no verdict came back: {e}");
            return;
        }
        Err(e) => panic!("fetching the manifest failed, and not on the network: {e}"),
    };
    if momentary(served.status) {
        skip_unreachable!(
            "skipping the registry resolve: the registry answered {}",
            served.status
        );
        return;
    }
    assert_eq!(
        served.status, 200,
        "the registry serves the manifest a tag names"
    );
    let advertised = served
        .header("docker-content-digest")
        .expect("a registry states the digest of the manifest it serves")
        .to_string();
    assert_eq!(
        digest_of(&served.body),
        advertised,
        "the manifest is hashed the way the registry that served it hashes it"
    );

    // The tag names an index, so resolving it fetches the platform manifest behind it by digest:
    // this is the test that exercises a by-digest URL against a document the registry still holds.
    let document: serde_json::Value =
        serde_json::from_slice(&served.body).expect("the manifest is a JSON document");
    assert!(
        document.get("manifests").is_some(),
        "`alpine:3.22` names an index"
    );

    let resolved = match resolve(&image, None) {
        Ok(resolved) => resolved,
        Err(e) if transient(&e) => {
            skip_unreachable!("skipping the registry resolve: no verdict came back: {e}");
            return;
        }
        Err(e) => panic!("resolving `alpine:3.22` failed, and not on the network: {e}"),
    };
    assert_eq!(
        resolved.digest, advertised,
        "a tag resolves to the digest of the index it names, not of the manifest behind it"
    );
    assert!(!resolved.layers.is_empty(), "an image carries layers");
    for layer in &resolved.layers {
        assert!(reference::valid_digest(&layer.digest).is_some());
        assert!(layer.size > 0, "a layer descriptor carries its size");
    }
}

#[test]
fn a_digest_locator_is_checked_against_the_bytes_the_registry_serves() {
    // Resolving by digest proves the pin rather than trusting it: the manifest that comes back is
    // hashed and compared, so a registry serving something else fails here.
    let image = reference::parse(&format!("oci:docker.io/library/alpine@{ALPINE_3_22}")).unwrap();
    let resolved = match resolve(&image, None) {
        Ok(resolved) => resolved,
        Err(e) if transient(&e) => {
            skip_unreachable!("skipping the resolve by digest: no verdict came back: {e}");
            return;
        }
        // A registry keeps a document only as long as it chooses to, and this one is no longer what
        // its tag resolves to. A `404` for it says the pin is gone and nothing about the client: the
        // URL is the one `a_tag_resolves_to_the_digest_the_registry_itself_reports` fetches a
        // platform manifest with, so a client that built it wrong fails there.
        Err(e) if answered(&e) == Some(404) => {
            skip_unreachable!(
                "skipping the resolve by digest: the registry no longer serves `ALPINE_3_22`, \
                 which needs a digest it still holds: {e}"
            );
            return;
        }
        Err(e) => panic!("resolving a pinned digest failed, and not on the network: {e}"),
    };
    assert_eq!(resolved.digest, ALPINE_3_22);
}

#[test]
fn a_layer_is_verified_against_its_digest_as_it_lands() {
    let image = reference::parse("oci:docker.io/library/alpine:3.22").unwrap();
    let resolved = match resolve(&image, None) {
        Ok(resolved) => resolved,
        Err(e) if transient(&e) => {
            skip_unreachable!("skipping the layer fetch: no verdict came back: {e}");
            return;
        }
        Err(e) => panic!("resolving `alpine:3.22` failed, and not on the network: {e}"),
    };
    let dir = crate::testutil::TmpDir::new();
    let layer = &resolved.layers[0];
    let path = match fetch_layer(&image, layer, dir.path(), None) {
        Ok(path) => path,
        Err(e) if transient(&e) => {
            skip_unreachable!("skipping the layer fetch: no verdict came back: {e}");
            return;
        }
        Err(e) => panic!("fetching a layer the manifest names failed, and not on the network: {e}"),
    };
    let bytes = std::fs::metadata(&path).expect("the layer landed").len();
    assert_eq!(bytes, layer.size, "the blob is the size the manifest names");

    // A descriptor whose digest does not match what the registry serves is refused, and leaves no
    // partial file behind for an applier to read.
    let wrong = Layer {
        digest: format!("sha256:{}", "b".repeat(64)),
        ..layer.clone()
    };
    let err =
        fetch_layer(&image, &wrong, dir.path(), None).expect_err("a mismatched digest is refused");
    // Only a registry that answered can refuse, and a registry never heard from carries no verdict
    // to read: the error is the network's, and asserting the refusal's wording against it reports
    // a broken client where there was a broken connection. The refusal itself stays asserted for
    // every answer that did arrive.
    if transient(&err) {
        skip_unreachable!("skipping the refusal check: no verdict came back: {err}");
        return;
    }
    assert!(
        err.to_string().contains("came back as") || err.to_string().contains("answered"),
        "{err}"
    );
    // Nothing is left of the refused blob: not its partial download, and not a file under its
    // digest that a reader of the directory could take for the layer.
    let left: Vec<_> = std::fs::read_dir(dir.path())
        .expect("the layer directory")
        .map(|entry| entry.expect("a directory entry").file_name())
        .collect();
    assert_eq!(
        left,
        [std::ffi::OsString::from(layer.digest.replace(':', "-"))],
        "the directory holds the layer that was fetched, and nothing of the one refused"
    );
}

#[test]
fn base64_matches_the_standard_alphabet_and_padding() {
    // The RFC 4648 vectors, which is what a registry's token service decodes with.
    for (plain, encoded) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64(plain.as_bytes()), encoded, "`{plain}`");
    }
    // The two characters that separate this from the URL-safe alphabet: a token endpoint reads
    // standard base64, and `-`/`_` here would be rejected as a malformed credential.
    assert_eq!(base64(&[0xfb, 0xff, 0xbe]), "+/++");
}

#[test]
fn a_credential_carries_its_header_and_never_prints_itself() {
    let c = Credential::basic("robot$ci:hunter2");
    assert_eq!(c.header(), "Basic cm9ib3QkY2k6aHVudGVyMg==");
    // A `{:?}` of anything holding one must not put the secret in a log or a panic message.
    let printed = format!("{c:?}");
    assert!(!printed.contains("hunter2"), "{printed}");
    assert!(!printed.contains("cm9ib3Qk"), "{printed}");
}

#[test]
fn only_a_basic_challenge_is_answered_with_the_credential_itself() {
    let c = Credential::basic("u:p");
    // A registry with no token service: the credential answers the original request.
    assert_eq!(
        basic_answer("Basic realm=\"private\"", Some(&c)),
        Some(c.header())
    );
    assert_eq!(
        basic_answer("basic realm=\"x\"", Some(&c)),
        Some(c.header())
    );
    // A bearer challenge goes to the token endpoint instead, whatever credential exists.
    assert_eq!(
        basic_answer("Bearer realm=\"https://auth\"", Some(&c)),
        None
    );
    // And a Basic challenge with nothing configured falls through rather than inventing an error.
    assert_eq!(basic_answer("Basic realm=\"private\"", None), None);
}

#[test]
fn a_challenge_from_a_redirect_hop_is_not_answered() {
    let challenge = "Bearer realm=\"https://elsewhere.example/token\",service=\"x\"";
    let answered = |redirected| super::super::http::Response {
        status: 401,
        headers: vec![("WWW-Authenticate".to_string(), challenge.to_string())],
        body: Vec::new(),
        redirected,
    };
    // The registry itself challenged: this is the exchange the credential exists for.
    assert_eq!(
        answerable_challenge(&answered(false)).unwrap(),
        Some(challenge)
    );
    // A host the registry redirected to challenged: it names a realm of its own choosing, and
    // presenting the credential there would hand it to whoever the redirect pointed at.
    let err = answerable_challenge(&answered(true)).expect_err("a redirect hop is refused");
    assert!(err.to_string().contains("redirect"), "{err}");
    // A redirect that simply serves the blob is not a challenge and is not refused.
    let mut served = answered(true);
    served.status = 200;
    assert_eq!(answerable_challenge(&served).unwrap(), None);
}

/// A stated layer size bounds the fetch, but never past the absolute ceiling.
///
/// The size comes out of the manifest, so it is the registry's number: taken verbatim it let a
/// registry name a terabyte and then stream until the disk filled, because the digest that would
/// declare the blob wrong is known only once every byte has landed.
#[test]
fn a_stated_layer_size_cannot_raise_the_write_ceiling() {
    assert_eq!(blob_cap(0), http::MAX_STREAMED_BODY);
    assert_eq!(blob_cap(4096), 4096);
    assert_eq!(blob_cap(u64::MAX), http::MAX_STREAMED_BODY);
    assert_eq!(
        blob_cap(http::MAX_STREAMED_BODY + 1),
        http::MAX_STREAMED_BODY
    );
}

/// A sink that takes nothing: its first write records that a body got this far, and is refused.
struct Refusing {
    reached: bool,
}

impl io::Write for Refusing {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        self.reached = true;
        Err(io::Error::other("the sink takes nothing"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A registry that does not challenge can still serve a layer larger than the document cap.
///
/// A fetch first asks the blob's URL whether the registry wants a credential, and asks it with a
/// `HEAD`. Asked with a `GET`, the answer from a registry that challenges is a small `401`
/// document, but from one that does not — quay.io, registry.k8s.io, a local `registry:2` — it is
/// the blob itself, which [`http::get`] refuses past [`http::MAX_DOCUMENT`]. Docker Hub challenges
/// and its alpine layers are under that cap, so only a registry that does not challenge and a layer
/// past the cap tell the two apart.
///
/// The fetch runs the way [`fetch_layer`] runs it, against the largest layer of an image on
/// quay.io, into a sink that refuses its first write: a body that reached the sink got past the
/// probe, and the download stops there rather than moving the blob.
#[test]
fn the_challenge_probe_does_not_read_the_blob_it_asks_about() {
    let image =
        crate::sandbox::distro::reference::parse("oci:quay.io/prometheus/prometheus:latest")
            .expect("a valid reference");
    let resolved = match super::resolve(&image, None) {
        Ok(resolved) => resolved,
        Err(e) if transient(&e) => {
            skip_unreachable!(
                "skipping the unchallenged-registry probe: no verdict came back: {e}"
            );
            return;
        }
        Err(e) => panic!("resolving a quay.io image failed, and not on the network: {e}"),
    };
    let biggest = resolved
        .layers
        .iter()
        .max_by_key(|l| l.size)
        .expect("an image has layers");
    assert!(
        biggest.size > http::MAX_DOCUMENT,
        "the test needs a layer past the document cap, got {} bytes",
        biggest.size
    );
    let url = v2_url(&image, "blobs", &biggest.digest);
    // Only a registry that does not challenge for the blob tells the two probes apart: one that
    // does answers a `GET` with its small `401` document as well, and either probe then reaches
    // the body.
    let asked = match http::head(&url, &[]) {
        Ok(asked) => asked,
        Err(e) if transient(&e) => {
            skip_unreachable!(
                "skipping the unchallenged-registry probe: no verdict came back: {e}"
            );
            return;
        }
        Err(e) => panic!("asking quay.io about the blob failed, and not on the network: {e}"),
    };
    assert_ne!(
        asked.status, 401,
        "quay.io challenges for this blob, so this test no longer tells a probe that reads the \
         blob from one that does not"
    );
    let mut sink = Refusing { reached: false };
    match get_authenticated_to_writer(&url, None, &mut sink, blob_cap(biggest.size)) {
        Err(_) if sink.reached => {}
        Err(e) if transient(&e) => {
            skip_unreachable!(
                "skipping the unchallenged-registry probe: no verdict came back: {e}"
            );
        }
        Err(e) => panic!("the fetch stopped before the blob's body, and not on the network: {e}"),
        Ok(written) => panic!("a sink that takes nothing was reported {written} bytes"),
    }
}

/// A layer digest the canned manifests below name. No test fetches its bytes.
const LAYER: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

/// A manifest naming one layer, as a registry serves it.
fn manifest_naming(layer: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": layer,
            "size": 1,
        }],
    }))
    .expect("a manifest serializes")
}

/// The platform an index entry states, as its `os` and `architecture`, or `None` for an entry
/// that states none.
type Stated<'a> = Option<(&'a str, &'a str)>;

/// An index whose one entry names the document `below`, for `platform` when one is given.
fn index_naming(below: &[u8], platform: Stated<'_>) -> Vec<u8> {
    index_of(&[(below, platform)])
}

/// An index of `entries`, each the document it names and the platform it states, if any.
fn index_of(entries: &[(&[u8], Stated<'_>)]) -> Vec<u8> {
    let manifests: Vec<serde_json::Value> = entries
        .iter()
        .map(|(below, platform)| {
            let mut entry = serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": digest_of(below),
                "size": below.len(),
            });
            if let Some((os, architecture)) = platform {
                entry["platform"] = serde_json::json!({ "os": os, "architecture": architecture });
            }
            entry
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({ "schemaVersion": 2, "manifests": manifests }))
        .expect("an index serializes")
}

/// A registry serving `documents`: the first for a tag, and each under the digest of its bytes.
fn serving(documents: &[Vec<u8>]) -> impl FnMut(&ImageRef) -> io::Result<Vec<u8>> + '_ {
    move |image| match &image.reference {
        Reference::Tag(_) => Ok(documents[0].clone()),
        Reference::Digest(digest) => documents
            .iter()
            .find(|document| digest_of(document) == *digest)
            .cloned()
            .ok_or_else(|| io::Error::other(format!("nothing is served under {digest}"))),
    }
}

/// An index may name another, and the nest is followed as deep as [`MAX_INDEX_DEPTH`] and no
/// deeper.
///
/// Each level is fetched by the digest the level above names, so a registry cannot make a loop of
/// them, but it can build a chain from the leaf up for as long as it likes, and every link is one
/// more request.
#[test]
fn a_nest_of_indexes_is_followed_only_so_deep() {
    let image = reference::parse("oci:registry.example/team/app:1").expect("a valid reference");
    // Built from the leaf up, as a registry would have to: each index names the digest of the
    // document below it, and the top comes first.
    let chain = |indexes: usize| {
        let mut documents = vec![manifest_naming(LAYER)];
        for _ in 0..indexes {
            let below = documents.last().expect("the leaf").clone();
            documents.push(index_naming(&below, Some((OS, ARCH))));
        }
        documents.reverse();
        documents
    };

    let deepest = chain(MAX_INDEX_DEPTH);
    let resolved =
        resolve_with(&image, serving(&deepest)).expect("a nest as deep as the bound resolves");
    assert_eq!(
        resolved.digest,
        digest_of(&deepest[0]),
        "pinned to the top index"
    );
    let layers: Vec<&str> = resolved.layers.iter().map(|l| l.digest.as_str()).collect();
    assert_eq!(layers, [LAYER], "the layers of the manifest at the bottom");

    let deeper = chain(MAX_INDEX_DEPTH + 1);
    let mut requests = 0;
    let err = resolve_with(&image, |image| {
        requests += 1;
        serving(&deeper)(image)
    })
    .expect_err("one level more is refused");
    assert!(err.to_string().contains("nests more than"), "{err}");
    assert_eq!(
        requests,
        MAX_INDEX_DEPTH + 1,
        "the level past the bound is refused before it is asked for"
    );
}

/// The platform manifest an index picks is held to the digest the index names, as a pin the
/// configuration wrote is.
#[test]
fn a_platform_manifest_is_checked_against_the_digest_its_index_names() {
    let image = reference::parse("oci:registry.example/team/app:1").expect("a valid reference");
    let named = manifest_naming(LAYER);
    let index = index_naming(&named, Some((OS, ARCH)));
    let other = manifest_naming(&format!("sha256:{}", "2".repeat(64)));
    // The registry answers the digest the index names with other bytes.
    let err = resolve_with(&image, |image: &ImageRef| match image.reference {
        Reference::Tag(_) => Ok(index.clone()),
        Reference::Digest(_) => Ok(other.clone()),
    })
    .expect_err("bytes that do not hash to the digest the index names are refused");
    assert!(
        err.to_string().contains("served a manifest hashing to"),
        "{err}"
    );
}

/// An index of one entry that states no platform is taken as the manifest it names, which is how
/// that manifest is taken when a registry serves it on its own. Nothing looser: an entry that
/// states another platform is not a fallback, and neither is one that states none beside an entry
/// that does.
#[test]
fn an_index_of_one_entry_without_a_platform_is_taken_as_its_manifest() {
    let image = reference::parse("oci:registry.example/team/app:1").expect("a valid reference");
    let named = manifest_naming(LAYER);
    let elsewhere = manifest_naming(&format!("sha256:{}", "3".repeat(64)));

    let lone = index_of(&[(&named, None)]);
    let resolved = resolve_with(&image, serving(&[lone.clone(), named.clone()]))
        .expect("an index of one entry stating no platform resolves");
    assert_eq!(resolved.digest, digest_of(&lone), "pinned to the index");
    let layers: Vec<&str> = resolved.layers.iter().map(|l| l.digest.as_str()).collect();
    assert_eq!(
        layers,
        [LAYER],
        "the layers of the manifest the entry names"
    );
    // A `null` platform is the field left out, written by hand since the builder cannot say it.
    let null = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": digest_of(&named),
            "size": named.len(),
            "platform": null,
        }],
    }))
    .expect("an index serializes");
    resolve_with(&image, serving(&[null, named.clone()]))
        .expect("an entry whose platform is null states none, and is taken alone");

    let refused = |documents: &[Vec<u8>], shape: &str| {
        let err = resolve_with(&image, serving(documents)).expect_err(shape);
        assert!(
            err.to_string().contains("carries no linux/amd64 image"),
            "{shape}: {err}"
        );
    };
    refused(
        &[index_of(&[(&named, Some((OS, "arm64")))]), named.clone()],
        "a lone entry stating another platform is refused",
    );
    refused(
        &[
            index_of(&[(&elsewhere, Some((OS, "arm64"))), (&named, None)]),
            elsewhere.clone(),
            named.clone(),
        ],
        "an entry stating no platform beside one that states another is refused",
    );
}

/// A file already under a layer's name is not handed back as the layer. Nothing checked it, and
/// the fetch replaces it with the bytes that hash to the digest.
#[test]
fn a_file_already_under_the_layers_name_is_not_taken_for_the_layer() {
    let dir = crate::testutil::TmpDir::new();
    let body = b"the layer's own bytes";
    let layer = Layer {
        digest: digest_of(body),
        media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
        size: body.len() as u64,
    };
    let planted = dir.path().join(layer.digest.replace(':', "-"));
    std::fs::write(&planted, b"bytes nothing checked").expect("plant a file under the name");

    let path = fetch_layer_with(&layer, dir.path(), |sink, _| {
        sink.write_all(body)?;
        Ok(body.len() as u64)
    })
    .expect("the layer is fetched over the planted file");
    assert_eq!(path, planted, "the layer lands under its digest");
    assert_eq!(
        std::fs::read(&path).expect("the layer"),
        body,
        "and holds the bytes that hash to the digest, not the ones planted"
    );
}

/// A layer's download is never written through a symlink left where it goes: not at
/// `<digest>.partial`, a name that is the same for every fetch of the layer, and not at the names a
/// fetch takes for a temp of its own.
///
/// The names are planted over a span because the sequence number is the process's, shared with
/// whatever else stages a file while this runs. The refusal has to be the collision itself, which
/// is what says a planted name was reached rather than one nobody tried.
#[test]
fn a_link_where_a_layer_downloads_is_refused_rather_than_written_through() {
    let dir = crate::testutil::TmpDir::new();
    let outside = crate::testutil::TmpDir::new();
    let target = outside.path().join("elsewhere");
    std::fs::write(&target, b"untouched").expect("the link's target");

    let body: &[u8] = b"the layer's own bytes";
    let layer = Layer {
        digest: digest_of(body),
        media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
        size: body.len() as u64,
    };
    let name = layer.digest.replace(':', "-");
    let link = |at: std::path::PathBuf| {
        std::os::unix::fs::symlink(&target, &at).expect("plant a link");
    };
    link(dir.path().join(format!("{name}.partial")));
    let next = crate::sandbox::atomicfile::unique() + 1;
    for n in next..next + 64 {
        link(
            dir.path()
                .join(format!(".{name}.tmp.{}.{n}", std::process::id())),
        );
    }

    let err = fetch_layer_with(&layer, dir.path(), |sink, _| {
        sink.write_all(body)?;
        Ok(body.len() as u64)
    })
    .expect_err("a name this fetch did not create is not one it may write through");
    assert_eq!(
        err.kind(),
        io::ErrorKind::AlreadyExists,
        "the refusal must be the collision itself: {err}"
    );
    assert_eq!(
        std::fs::read(&target).expect("the link's target"),
        b"untouched",
        "the link's target must not have been written through"
    );
    assert!(
        !dir.path().join(&name).exists(),
        "and nothing was published under the layer's name"
    );
}

/// No way a layer fetch fails leaves its download behind: not the transport stopping, not a body
/// that hashes to another digest, not one shorter than the manifest says, and not a rename the
/// layer's name refuses.
///
/// Every shape runs before any is asserted, so a cleanup that misses names each exit it misses
/// rather than only the first.
#[test]
fn no_failure_of_a_layer_fetch_leaves_its_download_behind() {
    type Body = Box<dyn FnOnce(&mut dyn io::Write, u64) -> io::Result<u64>>;
    const BODY: &[u8] = b"the layer's own bytes";
    let whole = || -> Body {
        Box::new(|sink, _| {
            sink.write_all(BODY)?;
            Ok(BODY.len() as u64)
        })
    };
    let stated = BODY.len() as u64;
    let shapes: Vec<(&str, u64, bool, Body)> = vec![
        (
            "the transport stopping",
            stated,
            false,
            Box::new(move |sink, cap| {
                assert_eq!(
                    cap,
                    blob_cap(stated),
                    "the fetch is held to the layer's cap"
                );
                sink.write_all(&BODY[..4])?;
                Err(io::Error::other("the connection closed"))
            }),
        ),
        (
            "a body hashing to another digest",
            0,
            false,
            Box::new(|sink, cap| {
                // A manifest that states no size holds the fetch to the absolute ceiling.
                assert_eq!(cap, blob_cap(0), "the fetch is held to the layer's cap");
                sink.write_all(b"other bytes")?;
                Ok(11)
            }),
        ),
        (
            "a body shorter than the manifest says",
            stated + 1,
            false,
            whole(),
        ),
        ("a rename the layer's name refuses", stated, true, whole()),
    ];

    let mut failures = Vec::new();
    for (shape, size, planted, body) in shapes {
        let dir = crate::testutil::TmpDir::new();
        let layer = Layer {
            digest: digest_of(BODY),
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
            size,
        };
        let name = layer.digest.replace(':', "-");
        if planted {
            std::fs::create_dir(dir.path().join(&name)).expect("plant a directory at the name");
        }
        let result = fetch_layer_with(&layer, dir.path(), body);
        let mut left: Vec<String> = std::fs::read_dir(dir.path())
            .expect("the layer directory")
            .map(|e| {
                e.expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        left.sort();
        let expected: Vec<String> = if planted { vec![name] } else { Vec::new() };
        if result.is_ok() || left != expected {
            failures.push(format!("{shape}: {result:?}, leaving {left:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The token parameters extend a realm's own query rather than start a second one.
#[test]
fn a_realm_with_a_query_of_its_own_keeps_the_token_parameters_apart() {
    let params = [
        ("service".to_string(), "registry.example".to_string()),
        ("scope".to_string(), "repository:team/app:pull".to_string()),
    ];
    // Calibration: a realm without a query takes one, and a challenge that names no parameter
    // leaves the realm as it is.
    assert_eq!(
        token_url("https://auth.example/token".to_string(), &params),
        "https://auth.example/token?service=registry.example&scope=repository%3Ateam%2Fapp%3Apull"
    );
    assert_eq!(
        token_url("https://auth.example/token".to_string(), &[]),
        "https://auth.example/token"
    );
    assert_eq!(
        token_url("https://auth.example/token?account=ci".to_string(), &params),
        "https://auth.example/token?account=ci&service=registry.example\
         &scope=repository%3Ateam%2Fapp%3Apull",
        "a second `?` would make the first parameter part of the realm's last value"
    );
}

/// A `Bearer` challenge is read with the authentication grammar, not by splitting on commas: a
/// quoted value keeps its commas and its escaped quotes, the scheme and the parameter names are
/// read without case, and a `Bearer` challenge is found behind another in the same field. An
/// unquoted realm, a URL the grammar's token would cut at its `:`, still reads whole.
///
/// Every shape runs before any is asserted, so a reading that fails names each shape it fails.
#[test]
fn a_bearer_challenge_is_read_with_the_authentication_grammar() {
    let shapes = [
        (
            "the form registries send",
            r#"Bearer realm="https://auth.example/token",service="registry.example",scope="repository:team/app:pull""#,
            "https://auth.example/token?service=registry.example&scope=repository%3Ateam%2Fapp%3Apull",
        ),
        (
            "an unquoted realm",
            "Bearer realm=https://auth.example/token,service=registry.example",
            "https://auth.example/token?service=registry.example",
        ),
        (
            "a scope with a comma inside its quotes",
            r#"Bearer realm="https://auth.example/token",scope="repository:team/app:pull,push""#,
            "https://auth.example/token?scope=repository%3Ateam%2Fapp%3Apull%2Cpush",
        ),
        (
            "a realm with a comma inside its quotes",
            r#"Bearer realm="https://auth.example/token,v2",service="registry.example""#,
            "https://auth.example/token,v2?service=registry.example",
        ),
        (
            "an escaped quote",
            r#"Bearer realm="https://auth.example/token",service="a\"b""#,
            "https://auth.example/token?service=a%22b",
        ),
        (
            "the scheme in another case",
            r#"bearer realm="https://auth.example/token""#,
            "https://auth.example/token",
        ),
        (
            "a parameter name in another case",
            r#"Bearer REALM="https://auth.example/token""#,
            "https://auth.example/token",
        ),
        (
            "a realm named twice, the last one read",
            r#"Bearer realm="https://first.example/token",realm="https://auth.example/token""#,
            "https://auth.example/token",
        ),
        (
            "a Bearer challenge behind a Basic one",
            r#"Basic realm="private", Bearer realm="https://auth.example/token""#,
            "https://auth.example/token",
        ),
    ];
    let mut failures = Vec::new();
    for (shape, field, url) in shapes {
        match bearer_request(field) {
            Ok(Some(read)) if read == url => {}
            other => failures.push(format!("{shape}: {other:?}, wanted {url}")),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A field the grammar cannot read is read no further, and never panics or loops on the way: the
/// field is the registry's to write. The reading runs on a thread of its own, so a loop fails the
/// test at its deadline rather than holding the run.
#[test]
fn a_challenge_field_the_grammar_cannot_read_ends_the_reading() {
    let challenge = |scheme: &str, params: &[(&str, &str)]| Challenge {
        scheme: scheme.to_string(),
        params: params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    };
    let fields = [
        "",
        "=",
        ",",
        ",,,",
        "\"",
        "é",
        "realm=\"x\"",
        "Bearer realm=\"https://auth.example/token",
        "Bearer realm=\"a\\",
        "Bearer realm",
        "Bearer =x",
        "Bearer realm=é",
        "Bearer realm=\"é\",scope=\"ü\"",
        "Negotiate YIIF==, Bearer realm=\"https://auth.example/token\"",
    ];
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let read: Vec<Vec<Challenge>> = fields.iter().map(|field| challenges(field)).collect();
        let _ = tx.send(read);
    });
    let read = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("every field is read to an end, without a panic, inside the deadline");
    let bearer = || challenge("Bearer", &[]);
    let expected: Vec<Vec<Challenge>> = vec![
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![bearer()],
        vec![bearer()],
        vec![bearer()],
        // The grammar lets space stand before a parameter's `=`, so this is a parameter named
        // `Bearer`, which a field cannot start with.
        vec![],
        vec![challenge("Bearer", &[("realm", "é")])],
        vec![challenge("Bearer", &[("realm", "é"), ("scope", "ü")])],
        vec![
            challenge("Negotiate", &[]),
            challenge("Bearer", &[("realm", "https://auth.example/token")]),
        ],
    ];
    for ((field, read), expected) in fields.iter().zip(read).zip(expected) {
        assert_eq!(read, expected, "`{field}`");
    }
}
