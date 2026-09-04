use super::*;

fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

#[test]
fn a_url_splits_into_host_port_and_request_target() {
    let u = parse_url("https://registry-1.docker.io/v2/library/debian/manifests/10").unwrap();
    assert_eq!(u.host, "registry-1.docker.io");
    assert_eq!(u.port, 443);
    assert_eq!(u.target, "/v2/library/debian/manifests/10");

    // A query string is part of the request target, not of the host.
    let u = parse_url("https://auth.docker.io/token?service=registry.docker.io&scope=x").unwrap();
    assert_eq!(u.host, "auth.docker.io");
    assert_eq!(u.target, "/token?service=registry.docker.io&scope=x");

    // An explicit port, and a URL with no path at all.
    let u = parse_url("https://localhost:5000").unwrap();
    assert_eq!(
        (u.host.as_str(), u.port, u.target.as_str()),
        ("localhost", 5000, "/")
    );
}

#[test]
fn only_https_is_parsed_at_all() {
    for bad in [
        "http://registry.example.com/v2/",
        "ftp://registry.example.com/v2/",
        "//registry.example.com/v2/",
        "registry.example.com/v2/",
        "https://",
        "https://host:notaport/v2/",
    ] {
        assert!(parse_url(bad).is_err(), "`{bad}` must not parse");
    }
}

#[test]
fn a_redirect_out_of_tls_is_refused_rather_than_followed() {
    // The gate that matters: the scheme of a hop the *registry* chose, not the one the config
    // wrote. A blob hand-off names a URL nobody here reviewed.
    let err = redirect_target(
        302,
        &headers(&[("Location", "http://cdn.example.com/blob")]),
        "https://registry-1.docker.io/v2/x/blobs/sha256:0",
    )
    .expect_err("a downgrade is refused");
    assert!(err.to_string().contains("only https"), "{err}");

    // …and the same for anything that is not a scheme we follow.
    assert!(
        redirect_target(
            307,
            &headers(&[("Location", "gopher://elsewhere/blob")]),
            "https://registry-1.docker.io/v2/x/blobs/sha256:0",
        )
        .is_err()
    );
}

#[test]
fn an_absolute_https_redirect_is_followed_and_a_rooted_one_is_resolved() {
    let target = redirect_target(
        302,
        &headers(&[("location", "https://cdn.example.com/blob?sig=1")]),
        "https://registry-1.docker.io/v2/x/blobs/sha256:0",
    )
    .unwrap();
    assert_eq!(
        target.as_deref(),
        Some("https://cdn.example.com/blob?sig=1")
    );

    // A rooted relative target resolves against the current origin, port included.
    let target = redirect_target(
        307,
        &headers(&[("Location", "/v2/other/blobs/sha256:1")]),
        "https://localhost:5000/v2/x/blobs/sha256:0",
    )
    .unwrap();
    assert_eq!(
        target.as_deref(),
        Some("https://localhost:5000/v2/other/blobs/sha256:1")
    );
}

#[test]
fn a_redirect_that_names_nowhere_is_an_error_not_a_body() {
    let err = redirect_target(302, &headers(&[]), "https://registry.example.com/v2/")
        .expect_err("a redirect with no Location is unusable");
    assert!(err.to_string().contains("no Location"), "{err}");

    // A relative target that is not rooted is refused rather than guessed at.
    assert!(
        redirect_target(
            302,
            &headers(&[("Location", "../elsewhere")]),
            "https://registry.example.com/v2/x/",
        )
        .is_err()
    );
}

#[test]
fn a_status_that_is_not_a_redirect_yields_no_target() {
    for status in [200u16, 201, 401, 404, 500] {
        assert!(
            redirect_target(
                status,
                &headers(&[("Location", "https://elsewhere.example.com/")]),
                "https://registry.example.com/v2/",
            )
            .unwrap()
            .is_none(),
            "{status} is not a redirect, whatever header it carries"
        );
    }
}

#[test]
fn a_header_is_read_case_insensitively() {
    let r = Response {
        status: 401,
        headers: headers(&[("WWW-Authenticate", "Bearer realm=\"https://auth\"")]),
        body: Vec::new(),
    };
    assert_eq!(
        r.header("www-authenticate"),
        Some("Bearer realm=\"https://auth\"")
    );
    assert_eq!(r.header("Www-Authenticate"), r.header("WWW-AUTHENTICATE"));
    assert_eq!(r.header("content-type"), None);
}
