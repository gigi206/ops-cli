use super::*;

fn digest() -> String {
    format!("sha256:{}", "a".repeat(64))
}

#[test]
fn a_tagged_locator_splits_into_registry_repository_and_tag() {
    let parsed = parse("oci:docker.io/library/debian:10").expect("valid");
    assert_eq!(parsed.registry, "docker.io");
    assert_eq!(parsed.repository, "library/debian");
    assert_eq!(parsed.reference, Reference::Tag("10".to_string()));
    // Rebuilt, it is the string it came from: a message or a lock names the image as written.
    assert_eq!(parsed.locator(), "oci:docker.io/library/debian:10");
}

#[test]
fn a_digest_locator_carries_its_pin() {
    let d = digest();
    let parsed = parse(&format!("oci:ghcr.io/owner/image@{d}")).expect("valid");
    assert_eq!(parsed.registry, "ghcr.io");
    assert_eq!(parsed.repository, "owner/image");
    assert_eq!(parsed.reference, Reference::Digest(d.clone()));
    assert_eq!(parsed.locator(), format!("oci:ghcr.io/owner/image@{d}"));
}

#[test]
fn a_port_is_part_of_the_registry_not_a_tag_separator() {
    let parsed = parse("oci:registry.example.com:8443/team/base:2024a").expect("valid");
    assert_eq!(parsed.registry, "registry.example.com:8443");
    assert_eq!(parsed.repository, "team/base");
    assert_eq!(parsed.reference, Reference::Tag("2024a".to_string()));

    // …and a port with no tag at all is still not a tag.
    assert_eq!(parse("oci:localhost:5000/img"), None);
    let parsed = parse("oci:localhost:5000/img:tag").expect("valid");
    assert_eq!(parsed.registry, "localhost:5000");
}

#[test]
fn docker_hub_is_addressed_at_the_host_that_serves_its_api() {
    // The published name and the serving name differ, and a fetcher that used the published one
    // would be following a redirect to a host it never checked.
    let parsed = parse("oci:docker.io/library/debian:10").expect("valid");
    assert_eq!(parsed.api_host(), "registry-1.docker.io");
    let parsed = parse("oci:ghcr.io/owner/image:1").expect("valid");
    assert_eq!(parsed.api_host(), "ghcr.io");
}

#[test]
fn pinning_replaces_the_reference_and_nothing_else() {
    let d = digest();
    let parsed = parse("oci:docker.io/library/debian:10").expect("valid");
    let pinned = parsed.pinned(&d);
    assert_eq!(pinned.registry, parsed.registry);
    assert_eq!(pinned.repository, parsed.repository);
    assert_eq!(pinned.reference, Reference::Digest(d));
}

#[test]
fn the_grammar_refuses_what_would_reach_a_registry_as_something_else() {
    let d = digest();
    for bad in [
        "",
        // no prefix: the scheme is what keeps a second image source additive
        "docker.io/library/debian:10",
        // no registry: a bare name resolves against a client's own default
        "oci:debian:10",
        // no reference: an unpinned name floats
        "oci:docker.io/library/debian",
        "oci:docker.io/library/debian:",
        // a path that climbs out of the repository it appears to name
        "oci:docker.io/library/../etc:10",
        "oci:docker.io//debian:10",
        // a digest that is not one
        "oci:docker.io/library/debian@sha256:short",
        "oci:docker.io/library/debian@md5:0123",
        &format!("oci:docker.io/library/debian@SHA256:{}", "A".repeat(64)),
        // a tag and a digest at once: the digest alone pins
        &format!("oci:docker.io/library/debian:10@{d}"),
        // an empty or unhostlike registry, an uppercase repository, and bytes a URL must not see
        "oci:/library/debian:10",
        "oci:registry/library/debian:10",
        "oci:docker.io/Library/debian:10",
        "oci:docker.io/lib rary/debian:10",
        "oci:docker.io/library/debian:10;rm",
        "oci:docker.io:/library/debian:10",
    ] {
        assert!(parse(bad).is_none(), "`{bad}` must not parse");
    }
}

#[test]
fn a_digest_is_held_to_one_algorithm_and_one_width() {
    assert!(valid_digest(&digest()).is_some());
    assert!(valid_digest(&format!("sha256:{}", "0123456789abcdef".repeat(4))).is_some());
    for bad in [
        "sha256:",
        "sha512:0000",
        &"a".repeat(64),
        &format!("sha256:{}", "a".repeat(63)),
        &format!("sha256:{}", "a".repeat(65)),
        &format!("sha256:{}", "g".repeat(64)),
        &format!("sha256:{}", "A".repeat(64)),
    ] {
        assert!(valid_digest(bad).is_none(), "`{bad}` is not a digest");
    }
}
