use super::*;

fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// A pair of in-memory ends, so a test can read the bytes `send` actually wrote.
#[derive(Debug)]
struct Wire {
    written: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
    response: std::io::Cursor<Vec<u8>>,
}

impl Read for Wire {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.response.read(buf)
    }
}

impl Write for Wire {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The response head is split on `\r\n`, so a bare `\n` inside a header value survives into the
/// string this fetch carries forward: a registry's `Location`, or the token its auth challenge
/// hands back and the next request re-sends. Written into a request line or a header, that byte
/// ends the line, and what follows it is a request the registry composed. Nothing sbx fetches
/// names a control byte, so it is refused rather than escaped.
#[test]
fn a_control_byte_in_a_request_part_is_refused_before_a_byte_is_written() {
    let wire = || Wire {
        written: std::rc::Rc::new(std::cell::RefCell::new(Vec::new())),
        response: std::io::Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()),
    };
    let url = |host: &str, target: &str| Url {
        host: host.to_string(),
        port: 443,
        target: target.to_string(),
    };

    for (u, hs) in [
        (url("r.test", "/v2/\nGET /other HTTP/1.1"), vec![]),
        (url("r.test\nX-Injected: 1", "/v2/"), vec![]),
        (
            url("r.test", "/v2/"),
            vec![("Authorization", "Bearer a\nX-Injected: 1")],
        ),
        (url("r.test", "/v2/"), vec![("X-A\nX-B", "v")]),
    ] {
        let w = wire();
        let seen = std::rc::Rc::clone(&w.written);
        let err = send(w, &u, &hs, "GET").expect_err("a control byte must be refused");
        assert!(err.to_string().contains("control character"), "{err}");
        assert!(
            seen.borrow().is_empty(),
            "the refusal lands before a byte reaches the wire"
        );
    }

    // Witness: the ordinary shape still composes, and the header rides where it belongs.
    let w = wire();
    let seen = std::rc::Rc::clone(&w.written);
    send(
        w,
        &url("r.test", "/v2/library/debian/manifests/10"),
        &[("Authorization", "Bearer abc")],
        "GET",
    )
    .expect("an ordinary request composes");
    let text = String::from_utf8(seen.borrow().clone()).unwrap();
    assert!(
        text.starts_with("GET /v2/library/debian/manifests/10 HTTP/1.1\r\n"),
        "{text}"
    );
    assert!(text.contains("\r\nAuthorization: Bearer abc\r\n"), "{text}");
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

/// A streamed body is bounded whatever framing the server chose.
///
/// The digest a blob is checked against is computed from the bytes as they land, so it is known
/// only once the whole body has been written: it says whether what arrived was the right content,
/// never how much of it may arrive. A registry that answers `Transfer-Encoding: chunked` and does
/// not stop therefore filled the disk and was declared wrong afterwards. The cap is what makes the
/// refusal happen first.
#[test]
fn a_streamed_body_is_refused_once_it_passes_the_cap() {
    // Read to end of stream: nothing announces a length, so only the cap bounds it. This is the
    // framing a server falls back to, and the one a server that simply never stops would use.
    let head = b"HTTP/1.1 200 OK\r\n\r\n";
    let body = [b'a'; 64];
    let mut sink = Vec::new();
    let err = stream_body(&mut &body[..], head, &mut sink, 8)
        .expect_err("a body past the cap is refused, not written");
    assert!(
        err.to_string().contains("larger than the 8 bytes"),
        "the refusal names the ceiling it applied: {err}"
    );

    // The same body under a cap that admits it still arrives whole.
    let mut sink = Vec::new();
    let n = stream_body(&mut &body[..], head, &mut sink, 1024).expect("within the cap");
    assert_eq!(n, 64);
    assert_eq!(sink.len(), 64);

    // Chunked takes the same branch, and the bytes are copied as they arrive rather than decoded —
    // a blob served this way fails its digest, which is the caller's business. What matters here is
    // that the cap applies to it too.
    let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut sink = Vec::new();
    assert!(
        stream_body(&mut &body[..], chunked, &mut sink, 8).is_err(),
        "a chunked body is bounded by the same cap"
    );
}

/// A `Content-Length` is the registry's claim, not a fact this side has checked, so it is held to
/// the same cap: a length larger than the caller will accept is refused before the body is read
/// rather than after it has been written.
#[test]
fn an_announced_length_larger_than_the_cap_is_refused_before_the_body_is_read() {
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
    let mut sink = Vec::new();
    let err = stream_body(&mut &b""[..], head, &mut sink, 8)
        .expect_err("an over-long announced length is refused");
    assert!(err.to_string().contains("larger than the 8 bytes"), "{err}");
    assert!(
        sink.is_empty(),
        "nothing is written for a body that was refused on its announced length"
    );
}
