//! Tests for the transparent-capture tap.
//!
//! Two halves. The codec and the table are pure and are exercised directly. The connection paths
//! need sockets but no privilege: [`serve_capture`] takes its destination as an argument precisely
//! so a plain loopback connection stands in for a redirected one, and a stand-in listener on a Unix
//! socket stands in for the proxy — which is also how the synthesized `CONNECT` is read back as
//! bytes rather than asserted about in prose.

use super::*;
use crate::testutil::TmpDir;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;

/// A DNS query on the wire: header, one question, no additional records.
fn query(name: &str, qtype: u16) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        q.push(u8::try_from(label.len()).expect("label fits a byte"));
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

fn rcode(reply: &[u8]) -> u16 {
    u16::from_be_bytes([reply[2], reply[3]]) & 0x000f
}

fn ancount(reply: &[u8]) -> u16 {
    u16::from_be_bytes([reply[6], reply[7]])
}

#[test]
fn a_well_formed_question_is_read_back_whole() {
    let q = parse_question(&query("cache.nixos.org", QTYPE_A)).expect("parsed");
    assert_eq!(q.name, "cache.nixos.org");
    assert_eq!(q.qtype, QTYPE_A);
    // 13 label bytes + 3 label lengths + root + qtype + qclass
    assert_eq!(q.qlen, 13 + 3 + 1 + 4);
}

/// The one function that reads bytes the workload chose. Every refusal here is a way a parser gets
/// walked off the end of its buffer or into its own tail, so they are asserted as a set: a new
/// bound may be added, none may be dropped.
#[test]
fn a_malformed_question_is_refused_not_parsed() {
    let good = query("example.test", QTYPE_A);

    assert!(parse_question(&[]).is_none(), "empty");
    assert!(parse_question(&good[..8]).is_none(), "truncated header");
    assert!(
        parse_question(&good[..good.len() - 2]).is_none(),
        "question cut before qclass"
    );

    // A compression pointer in a question: legal nowhere, and the way a parser is made to loop.
    let mut pointer = good.clone();
    pointer[12] = 0xc0;
    pointer[13] = 0x0c;
    assert!(parse_question(&pointer).is_none(), "compression pointer");

    // A label length past the buffer.
    let mut over = good.clone();
    over[12] = 60;
    assert!(parse_question(&over).is_none(), "label runs off the end");

    // A label longer than the protocol's 63.
    let mut long_label = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    long_label.push(64);
    long_label.extend_from_slice(&[b'a'; 64]);
    long_label.push(0);
    long_label.extend_from_slice(&QTYPE_A.to_be_bytes());
    long_label.extend_from_slice(&1u16.to_be_bytes());
    assert!(parse_question(&long_label).is_none(), "label over 63");

    // A name longer than the protocol's 255, built from legal labels.
    let mut long_name = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for _ in 0..6 {
        long_name.push(63);
        long_name.extend_from_slice(&[b'a'; 63]);
    }
    long_name.push(0);
    long_name.extend_from_slice(&QTYPE_A.to_be_bytes());
    long_name.extend_from_slice(&1u16.to_be_bytes());
    assert!(parse_question(&long_name).is_none(), "name over 255");

    // Several questions in one message: not what a resolver in this position serves.
    let mut two = good.clone();
    two[5] = 2;
    assert!(parse_question(&two).is_none(), "qdcount != 1");

    // A non-ASCII label — an international name reaches the wire as punycode, so this is malformed.
    let mut utf8 = good.clone();
    utf8[13] = 0xff;
    assert!(parse_question(&utf8).is_none(), "non-ascii label");

    // Longer than any query this tap answers.
    assert!(
        parse_question(&vec![0u8; DNS_MAX + 1]).is_none(),
        "over DNS_MAX"
    );
}

#[test]
fn an_a_question_is_answered_with_the_synthetic_address() {
    let table = Mutex::new(FakeIps::new());
    let q = query("github.com", QTYPE_A);
    let reply = answer_query(&q, &table).expect("answered");

    assert_eq!(reply[0..2], q[0..2], "the query's id is echoed");
    assert_eq!(rcode(&reply), 0, "NOERROR");
    assert_eq!(ancount(&reply), 1);
    let addr = &reply[reply.len() - 4..];
    assert_eq!(addr[0], 198, "the answer is in the benchmarking range");
    assert_eq!(addr[1], 18);
    // The record's TTL sits four bytes before the two-byte rdlength and the four-byte address.
    let ttl_at = reply.len() - 4 - 2 - 4;
    assert_eq!(
        u32::from_be_bytes(reply[ttl_at..ttl_at + 4].try_into().expect("four bytes")),
        FAKE_TTL
    );
}

/// The rule that keeps a dual-stack client on the address the tap can actually route: an `AAAA`
/// question is answered NOERROR with no records — *not* NXDOMAIN, which would tell the client the
/// name does not exist at all and strand it before it ever asks for an `A`.
#[test]
fn a_non_a_question_is_answered_noerror_and_empty() {
    let table = Mutex::new(FakeIps::new());
    for qtype in [
        28u16, /* AAAA */
        65,    /* HTTPS */
        33,    /* SRV */
    ] {
        let reply = answer_query(&query("github.com", qtype), &table).expect("answered");
        assert_eq!(rcode(&reply), 0, "qtype {qtype} must be NOERROR");
        assert_eq!(ancount(&reply), 0, "qtype {qtype} must carry no answer");
    }
    assert_eq!(
        table.lock().expect("lock").len(),
        0,
        "a question the tap cannot route must not consume an address"
    );
}

#[test]
fn the_same_name_keeps_its_address_and_a_second_name_gets_another() {
    let table = Mutex::new(FakeIps::new());
    let first = answer_query(&query("github.com", QTYPE_A), &table).expect("answered");
    let again = answer_query(&query("github.com", QTYPE_A), &table).expect("answered");
    let other = answer_query(&query("cache.nixos.org", QTYPE_A), &table).expect("answered");

    assert_eq!(first[first.len() - 4..], again[again.len() - 4..]);
    assert_ne!(first[first.len() - 4..], other[other.len() - 4..]);
}

#[test]
fn a_claimed_address_names_its_host() {
    let mut t = FakeIps::new();
    let ip = t.alloc("api.anthropic.com").expect("allocated");
    assert_eq!(t.claim(ip).as_deref(), Some("api.anthropic.com"));
    assert_eq!(
        t.claim(Ipv4Addr::new(198, 18, 200, 200)),
        None,
        "never handed out"
    );
}

/// The eviction rule, stated as the failure it prevents: a client that cached a synthetic address
/// and connects to it later must never be told it bypassed DNS. So a connect pins, and only names
/// that were resolved and never used are reclaimed.
#[test]
fn eviction_reclaims_an_unused_name_and_never_a_connected_one() {
    let mut t = FakeIps::new();
    let pinned = t.alloc("pinned.test").expect("allocated");
    t.claim(pinned);
    let doomed = t.alloc("unused.test").expect("allocated");
    for i in 0..FAKE_IP_CAP - 2 {
        t.alloc(&format!("filler{i}.test")).expect("allocated");
    }
    assert_eq!(t.len(), FAKE_IP_CAP);

    t.alloc("newcomer.test").expect("evicts to make room");
    assert_eq!(
        t.peek(pinned),
        Some("pinned.test"),
        "a connected name must survive"
    );
    assert_eq!(t.peek(doomed), None, "the oldest unused name is reclaimed");
}

/// A reclaimed address is never handed to a second name inside one session: a client holding a
/// stale answer must get a refusal it can be told about, never another host's traffic.
#[test]
fn a_reclaimed_address_is_not_handed_out_again() {
    let mut t = FakeIps::new();
    let first = t.alloc("first.test").expect("allocated");
    for i in 0..FAKE_IP_CAP {
        t.alloc(&format!("filler{i}.test"));
    }
    assert_eq!(t.peek(first), None, "reclaimed");
    let seen: std::collections::HashSet<_> = (0..64)
        .filter_map(|i| t.alloc(&format!("later{i}.test")))
        .collect();
    assert!(
        !seen.contains(&first),
        "an address must not be reused within a session"
    );
}

/// A table whose every name is in use cannot promise another address, and says so with SERVFAIL —
/// a client retries on that, where an empty NOERROR would be cached as "no such host".
#[test]
fn a_table_full_of_connected_names_answers_servfail() {
    let table = Mutex::new(FakeIps::new());
    {
        let mut t = table.lock().expect("lock");
        for i in 0..FAKE_IP_CAP {
            let ip = t.alloc(&format!("held{i}.test")).expect("allocated");
            t.claim(ip);
        }
    }
    let reply = answer_query(&query("overflow.test", QTYPE_A), &table).expect("answered");
    assert_eq!(rcode(&reply), 2, "SERVFAIL");
    assert_eq!(ancount(&reply), 0);
}

#[test]
fn the_synthesized_request_is_the_one_an_obedient_client_sends() {
    assert_eq!(
        synthesize_connect("github.com", 443),
        "CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n"
    );
}

#[test]
fn only_a_two_hundred_opens_the_tunnel() {
    assert!(head_is_success(
        b"HTTP/1.1 200 Connection established\r\n\r\n"
    ));
    assert!(head_is_success(b"HTTP/1.0 200 OK\r\n\r\n"));
    assert!(!head_is_success(b"HTTP/1.1 403 Forbidden\r\n\r\n"));
    assert!(!head_is_success(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"));
    assert!(!head_is_success(b"HTTP/1.1 nonsense\r\n\r\n"));
    assert!(!head_is_success(b"\x16\x03\x01 not http at all"));
    assert!(!head_is_success(b""));
}

/// A stand-in proxy: accepts one connection on `uds`, hands back the request head it was given,
/// answers `status`, then echoes whatever follows so the pump can be observed end to end.
fn stand_in_proxy(uds: &Path, status: &'static str) -> std::sync::mpsc::Receiver<String> {
    let listener = UnixListener::bind(uds).expect("bind the stand-in proxy");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut head = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let end = line == "\r\n";
            head.push_str(&line);
            if end {
                break;
            }
        }
        tx.send(head).expect("report the head");
        let mut stream = stream;
        if stream.write_all(status.as_bytes()).is_err() {
            return;
        }
        let _ = stream.flush();
        // Echo one payload back so the caller can prove bytes flow after the tunnel opens.
        let mut buf = [0u8; 64];
        if let Ok(n) = reader.read(&mut buf)
            && n > 0
        {
            let _ = stream.write_all(&buf[..n]);
            let _ = stream.flush();
        }
    });
    rx
}

/// Drive one captured connection through `serve_capture` on a real socket pair, with `dest` given
/// explicitly — the redirect's job, done by the test.
fn capture_through(
    dest_ip: Ipv4Addr,
    table: &Mutex<FakeIps>,
    uds: &Path,
    payload: &[u8],
) -> (Capture, Vec<u8>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind the client side");
    let addr = listener.local_addr().expect("addr");
    let payload = payload.to_vec();
    let client = std::thread::spawn(move || {
        let mut c = TcpStream::connect(addr).expect("connect");
        let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
        if !payload.is_empty() {
            let _ = c.write_all(&payload);
        }
        let mut back = Vec::new();
        let _ = c.read_to_end(&mut back);
        back
    });
    let (server_side, _) = listener.accept().expect("accept");
    let outcome = serve_capture(server_side, SocketAddrV4::new(dest_ip, 443), table, uds);
    let echoed = client.join().expect("client thread");
    (outcome, echoed)
}

#[test]
fn a_named_address_reaches_the_proxy_as_a_connect_and_then_pumps() {
    let dir = TmpDir::new();
    let uds = dir.join("egress.sock");
    let heads = stand_in_proxy(&uds, "HTTP/1.1 200 Connection established\r\n\r\n");

    let table = Mutex::new(FakeIps::new());
    let ip = table
        .lock()
        .expect("lock")
        .alloc("github.com")
        .expect("allocated");

    let (outcome, echoed) = capture_through(ip, &table, &uds, b"hello");
    assert_eq!(
        outcome,
        Capture::Proxied {
            host: "github.com".to_string(),
            port: 443
        }
    );
    let head = heads.recv_timeout(Duration::from_secs(5)).expect("head");
    assert_eq!(head, synthesize_connect("github.com", 443));
    assert_eq!(
        echoed, b"hello",
        "bytes must flow both ways once the tunnel is open"
    );
}

/// A refusal cannot be explained to a client that believes it is already speaking to its
/// destination, so the connection is closed — and, unlike today's silent `ENETUNREACH`, it is named.
#[test]
fn a_refused_request_closes_the_captured_connection() {
    let dir = TmpDir::new();
    let uds = dir.join("egress.sock");
    let heads = stand_in_proxy(&uds, "HTTP/1.1 403 Forbidden\r\n\r\n");

    let table = Mutex::new(FakeIps::new());
    let ip = table
        .lock()
        .expect("lock")
        .alloc("blocked.test")
        .expect("allocated");

    let (outcome, echoed) = capture_through(ip, &table, &uds, b"hello");
    assert_eq!(
        outcome,
        Capture::Refused {
            host: "blocked.test".to_string(),
            port: 443
        }
    );
    assert!(echoed.is_empty(), "nothing is relayed after a refusal");
    heads.recv_timeout(Duration::from_secs(5)).expect("head");
    assert!(outcome.describe().contains("refused by policy"));
}

/// The visibility this design buys: a connect the tap never handed an address for is refused *and
/// named*, where the empty netns alone would have failed it silently at `connect(2)`.
#[test]
fn an_address_the_tap_never_handed_out_is_refused_and_named() {
    let dir = TmpDir::new();
    // No stand-in proxy: nothing must be dialed for an unmapped address.
    let uds = dir.join("never-dialed.sock");
    let table = Mutex::new(FakeIps::new());

    let (outcome, echoed) = capture_through(Ipv4Addr::new(93, 184, 216, 34), &table, &uds, b"x");
    assert_eq!(
        outcome,
        Capture::Unmapped {
            addr: SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443)
        }
    );
    assert!(echoed.is_empty());
    assert!(outcome.describe().contains("bypassed DNS"));
    assert!(!uds.exists(), "an unmapped capture dials nothing");
}

/// `SO_ORIGINAL_DST` does *not* fail on a connection that was never redirected — it answers with
/// the socket's own local address (measured: a plain loopback connect returns `127.0.0.1:<the
/// listener's port>`). So a cage process dialing the tap's port directly arrives here with a
/// loopback destination, and without its own refusal it would be told it bypassed DNS: a wrong
/// diagnosis, on a connection that never carried a destination at all.
#[test]
fn a_connection_made_to_the_tap_itself_is_refused_under_its_own_name() {
    let dir = TmpDir::new();
    let uds = dir.join("never-dialed.sock");
    let table = Mutex::new(FakeIps::new());

    let (outcome, echoed) = capture_through(Ipv4Addr::LOCALHOST, &table, &uds, b"x");
    assert_eq!(outcome, Capture::Direct { port: 443 });
    assert!(echoed.is_empty());
    assert!(outcome.describe().contains("direct connection"));
    assert!(
        !outcome.describe().contains("bypassed DNS"),
        "a direct connection must not be reported as a DNS bypass: {}",
        outcome.describe()
    );
    assert!(!uds.exists(), "nothing is dialed for a direct connection");
}

#[test]
fn a_proxy_that_is_not_there_is_reported_not_hung() {
    let dir = TmpDir::new();
    let uds = dir.join("absent.sock");
    let table = Mutex::new(FakeIps::new());
    let ip = table
        .lock()
        .expect("lock")
        .alloc("github.com")
        .expect("allocated");

    let (outcome, _) = capture_through(ip, &table, &uds, b"x");
    assert_eq!(
        outcome,
        Capture::ProxyUnreachable {
            host: "github.com".to_string(),
            port: 443
        }
    );
}

/// RFC 7766: one TCP connection carries several queries. Serving only the first is a hang for every
/// client that reuses the connection — and a resolver that passes a one-query test can still have
/// that defect, because glibc happens to open a fresh connection per lookup.
#[test]
fn one_dns_connection_serves_several_queries() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let table = Arc::new(Mutex::new(FakeIps::new()));
    let served = Arc::clone(&table);
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let _ = serve_dns_stream(stream, &served);
    });

    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut addrs = Vec::new();
    for name in ["one.test", "two.test", "three.test"] {
        let q = query(name, QTYPE_A);
        let len = u16::try_from(q.len()).expect("fits");
        c.write_all(&len.to_be_bytes()).expect("write length");
        c.write_all(&q).expect("write query");
        c.flush().expect("flush");

        let mut hdr = [0u8; 2];
        c.read_exact(&mut hdr).expect("reply length");
        let mut reply = vec![0u8; usize::from(u16::from_be_bytes(hdr))];
        c.read_exact(&mut reply).expect("reply body");
        assert_eq!(
            ancount(&reply),
            1,
            "{name} must be answered on this same connection"
        );
        addrs.push(reply[reply.len() - 4..].to_vec());
    }
    addrs.sort();
    addrs.dedup();
    assert_eq!(addrs.len(), 3, "each name gets its own address");
}

/// A malformed query is dropped, and the connection stays serving — the workload cannot take its
/// own resolver down (and with it the cage's egress) by writing rubbish at it.
#[test]
fn rubbish_on_the_dns_connection_does_not_end_the_service() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let table = Arc::new(Mutex::new(FakeIps::new()));
    let served = Arc::clone(&table);
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let _ = serve_dns_stream(stream, &served);
    });

    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let junk = [0xffu8; 24];
    c.write_all(&u16::try_from(junk.len()).expect("fits").to_be_bytes())
        .expect("write length");
    c.write_all(&junk).expect("write junk");
    c.flush().expect("flush");

    let q = query("after.test", QTYPE_A);
    c.write_all(&u16::try_from(q.len()).expect("fits").to_be_bytes())
        .expect("write length");
    c.write_all(&q).expect("write query");
    c.flush().expect("flush");

    let mut hdr = [0u8; 2];
    c.read_exact(&mut hdr).expect("the service still answers");
    let mut reply = vec![0u8; usize::from(u16::from_be_bytes(hdr))];
    c.read_exact(&mut reply).expect("reply body");
    assert_eq!(ancount(&reply), 1);
}

/// The resolver address the cage is pointed at must never be one the table can hand out, or a name
/// would answer with the address of the resolver itself.
#[test]
fn allocation_stays_inside_the_low_half_of_the_synthetic_block() {
    let highest = addr_for(FAKE_IP_MAX_INDEX).expect("the last index the range expresses");
    assert_eq!(
        highest.octets()[0..2],
        FAKE_NET_HIGH,
        "every address must stay in the benchmarking block"
    );
    assert_eq!(
        highest,
        Ipv4Addr::new(198, 18, 255, 255),
        "the walk must stop at the top of the low half, leaving the high half free"
    );
    assert_eq!(
        addr_for(FAKE_IP_MAX_INDEX + 1),
        None,
        "the range is bounded"
    );
    assert_eq!(addr_for(0), None, "the network address is never handed out");
}

/// The rule order is load-bearing: a nat statement is terminal, so the first match decides. With
/// the general TCP rule first, a DNS query to a public resolver would be captured as ordinary
/// traffic and never answered — the cage would resolve nothing at all.
#[test]
fn the_ruleset_reaches_the_resolver_before_the_general_capture() {
    let rules = redirect_ruleset();
    let dns_udp = rules.find(&format!("udp dport 53 redirect to :{TAP_DNS_PORT}"));
    let dns_tcp = rules.find(&format!("tcp dport 53 redirect to :{TAP_DNS_PORT}"));
    let general = rules.find(&format!("redirect to :{TAP_PORT}"));
    let (dns_udp, dns_tcp, general) = (
        dns_udp.expect("udp/53"),
        dns_tcp.expect("tcp/53"),
        general.expect("capture"),
    );
    assert!(dns_udp < general && dns_tcp < general, "{rules}");
}

/// Two properties nftables itself enforces, and one the egress path depends on. They are asserted
/// on the text because the kernel is what proves them and a unit test cannot install a rule: the
/// ruleset was measured against a live namespace, and this pins the spelling that passed.
#[test]
fn the_ruleset_keeps_what_nftables_and_the_egress_forwarder_require() {
    let rules = redirect_ruleset();
    assert!(
        rules.contains("meta l4proto tcp ip daddr != 127.0.0.0/8"),
        "nftables refuses a `redirect to :port` with no transport-protocol match, and the \
         loopback exclusion is what keeps the egress forwarder's own connections out: {rules}"
    );
    assert!(
        rules.starts_with("table ip sbx {"),
        "the rules live in sbx's own table, never a shared chain: {rules}"
    );
    assert!(
        rules.contains("type nat hook output priority dstnat"),
        "{rules}"
    );
}

#[test]
fn the_cage_resolver_file_names_an_address_the_redirect_catches() {
    let body = resolv_conf();
    assert!(body.contains(&CAGE_RESOLVER.to_string()), "{body}");
    assert!(
        !CAGE_RESOLVER.is_loopback(),
        "a loopback resolver would be excluded from the redirect by the rule above"
    );
    assert!(
        body.lines().any(|l| l.starts_with("nameserver ")),
        "glibc needs a nameserver line: {body}"
    );
}
