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
/// - `answered` with `408`, `429` or a `5xx`, the statuses about the moment rather than the
///   request, as `tests/common`'s `transient_fetch_failure` splits them for nix's downloads.
fn transient(e: &io::Error) -> bool {
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
        || answered(e).is_some_and(|status| matches!(status, 408 | 429 | 500..=599))
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
    let Ok(served) = get_authenticated(&url, Some(MANIFEST_ACCEPT), None) else {
        skip_unreachable!("skipping the registry resolve: the registry did not answer");
        return;
    };
    if served.status != 200 {
        skip_unreachable!("skipping the registry resolve: the registry did not serve the manifest");
        return;
    }
    let Some(advertised) = served.header("docker-content-digest").map(str::to_string) else {
        skip_unreachable!("skipping the registry resolve: the registry advertised no digest");
        return;
    };
    assert_eq!(
        digest_of(&served.body),
        advertised,
        "the manifest is hashed the way the registry that served it hashes it"
    );

    let Ok(resolved) = resolve(&image, None) else {
        skip_unreachable!("skipping the registry resolve: the registry did not answer");
        return;
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
    let Ok(resolved) = resolve(&image, None) else {
        skip_unreachable!("skipping the resolve by digest: the registry did not answer");
        return;
    };
    assert_eq!(resolved.digest, ALPINE_3_22);
}

#[test]
fn a_layer_is_verified_against_its_digest_as_it_lands() {
    let image = reference::parse("oci:docker.io/library/alpine:3.22").unwrap();
    let Ok(resolved) = resolve(&image, None) else {
        skip_unreachable!("skipping the layer fetch: the registry did not answer");
        return;
    };
    let dir = crate::testutil::TmpDir::new();
    let layer = &resolved.layers[0];
    let Ok(path) = fetch_layer(&image, layer, dir.path(), None) else {
        skip_unreachable!("skipping the layer fetch: the blob did not arrive");
        return;
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
    assert!(
        !dir.path()
            .join(format!("{}.partial", wrong.digest.replace(':', "-")))
            .exists(),
        "a refused blob leaves no partial file"
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

/// A registry that does not challenge can still serve a layer larger than the document cap.
///
/// The challenge probe used to be a `GET`: on a registry that answers `401` first, its body is the
/// small error document, and on one that does not — quay.io, registry.k8s.io, a local `registry:2`
/// — it is the blob itself, which the document cap then refused. So no layer past four megabytes
/// could be fetched from those registries at all, and the tests never saw it because they use a
/// registry that challenges and a layer under the cap. The probe asks with a `HEAD` now.
///
/// This asks the question without moving the blob: the manifest is resolved, the largest layer is
/// picked, and the probe is run against its URL. What it must not be is an error about a cap.
#[test]
fn the_challenge_probe_does_not_read_the_blob_it_asks_about() {
    let image =
        crate::sandbox::distro::reference::parse("oci:quay.io/prometheus/prometheus:latest")
            .expect("a valid reference");
    let Ok(resolved) = super::resolve(&image, None) else {
        skip_unreachable!("skipping the unchallenged-registry probe: the registry did not answer");
        return;
    };
    let biggest = resolved
        .layers
        .iter()
        .max_by_key(|l| l.size)
        .expect("an image has layers");
    assert!(
        biggest.size > 4 * 1024 * 1024,
        "the test needs a layer past the document cap, got {} bytes",
        biggest.size
    );
    let url = v2_url(&image, "blobs", &biggest.digest);
    let probe = super::super::http::head(&url, &[]).expect("the probe asks and does not read");
    assert!(
        (200..400).contains(&probe.status) || probe.status == 401,
        "the probe reached the registry: status {}",
        probe.status
    );
    assert!(
        probe.body.is_empty(),
        "a HEAD carries no body, so nothing was read"
    );
}
