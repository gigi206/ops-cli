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

/// The digest `skopeo inspect docker://docker.io/library/alpine:3.22` reports for the image this
/// test resolves. A second implementation is the only oracle worth having here: it says the client
/// followed the challenge, asked for the right media types, picked the `linux/amd64` entry out of
/// the index, and hashed the manifest the way a registry does.
const ALPINE_3_22: &str = "sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce";

#[test]
fn a_tag_resolves_to_the_digest_a_second_implementation_reports() {
    let image = reference::parse("oci:docker.io/library/alpine:3.22").unwrap();
    let Ok(resolved) = resolve(&image, None) else {
        skip_unreachable!("skipping the registry resolve: the registry did not answer");
        return;
    };
    assert_eq!(resolved.digest, ALPINE_3_22);
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
