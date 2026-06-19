# bwrap network-sandbox spike — raw findings (2026-06-18)

Throwaway research spike. Goal: gather evidence to decide between two egress
architectures for the `ops` bwrap cage. **No source touched, nothing installed.**

Host facts (recorded once, referenced below):
- kernel 7.0.0, uid 1000, rootless unprivileged user namespaces work.
- `bubblewrap 0.11.1`, `pasta 0.0~git20260120.386b5f5-1` (passt), `socat`,
  linuxbrew `curl`/`python3`, daemonless `nix`.
- Host `/etc/resolv.conf` → `nameserver 127.0.0.53` (systemd-resolved **stub** on
  loopback) + `search .`. This is the central DNS complication (see Q2).
- Host default route: `default via 192.168.1.254 dev wlp0s20f3 src 192.168.1.100`.
- CA bundle present at `/etc/ssl/certs/ca-certificates.crt` (211 KB).

Cage construction note (applies to every test): the cage is built **non-hermetic**
on purpose — `bwrap --ro-bind / / --tmpfs /tmp --dev /dev --proc /proc …`. Network
topology is the variable under test, not the FHS; binding the whole host rootfs ro
means the linuxbrew `curl`/`python3` find their libs and "just work", so failures
are unambiguously network failures.

---

## Q1 — Topology (Model P): give a `--unshare-net` cage egress via host pasta

Two patterns tried.

### P-inherit — pasta creates the netns, bwrap inherits it (`--share-net`) → WORKS, clean

Command (real egress proof, by IP so DNS is out of the picture):

```sh
printf 'nameserver 1.1.1.1\n' > resolv.public.conf
pasta -4 -f --config-net -- \
  bwrap --ro-bind / / --tmpfs /tmp --dev /dev --proc /proc --unshare-all --share-net \
  --bind "$PWD/resolv.public.conf" /etc/resolv.conf \
  -- /bin/sh -c 'curl -sS -m 8 -o /dev/null -w "connect=%{http_code} ip=%{remote_ip}\n" https://1.1.1.1/'
```

Output:

```
connect=301 ip=1.1.1.1
```

Inside the cage pasta had configured a real interface + default route (from an
earlier `ip addr`/`ip route` run in the same invocation):

```
2: wlp0s20f3: <...UP...> inet 192.168.1.100/24 ... scope global noprefixroute wlp0s20f3
default via 192.168.1.254 dev wlp0s20f3 proto dhcp metric 600
```

No stray pasta after exit (pasta `-f` foreground dies with the child).

**Verdict P-inherit: works cleanly.** `pasta … -- bwrap --unshare-all --share-net …`
is the documented "everything-except-net" combo; pasta builds the netns + userns,
configures the tap, and bwrap inherits it. This is the clean Model-P invocation.

### P-attach — start the cage, attach pasta to its existing netns → FAILS (unprivileged)

Tried three ways; all fail the same way. The cage is started in the background, its
unprivileged child-pid read from `bwrap --info-fd 3`, then pasta is pointed at
`/proc/<pid>/ns/net`:

- `pasta --config-net --userns … --netns …` (join both): `Couldn't switch to pasta namespaces: Operation not permitted`
- `pasta --config-net --netns-only --netns …` (join netns only): same error.
- bwrap with `--unshare-net` **only** (no explicit `--unshare-user`): same error.

The decisive observation (variant B): even `--unshare-net` alone makes bwrap create
its **own** userns —

```
child userns: user:[4026533616]   (host self: user:[4026531837])
child netns:  net:[4026533055]
pasta: Couldn't switch to pasta namespaces: Operation not permitted
```

and the cage stays egress-less (loopback only, no route, `curl: (7) … Could not
connect`).

**Verdict P-attach: not feasible fully-unprivileged on this host.** Root cause: an
unprivileged `bwrap` *must* create a user namespace to gain the capabilities to
unshare net; that netns is then owned by a userns in which the host-side `pasta`
holds no `CAP_SYS_ADMIN`, so `setns()` is refused. P-attach would only work if
pasta could join that userns (it can't) or if bwrap ran in the init userns (it
can't, unprivileged). **Use P-inherit, not P-attach.**

---

## Q2 — DNS inside the cage

All three resolv.conf strategies were tried inside a P-inherit cage. Surprise up
front: **all three resolve**, including the host's `127.0.0.53` stub — the prior
prediction (stub fails in the isolated loopback) was wrong, and *why* it works is
load-bearing for Q4.

### (2) `nameserver 1.1.1.1` (public resolver over the NAT uplink) → WORKS

```sh
printf 'nameserver 1.1.1.1\n' > resolv.public.conf
# ./q2-dns.sh resolv.public.conf  → P-inherit cage, getent + curl-by-name
```
```
--- getent hosts cache.nixos.org ---   2a04:4e42::347 ... cache.nixos.org
--- curl by name ---                   code=200 ip=151.101.1.91
```

### (1) inherited host resolv.conf (`nameserver 127.0.0.53`) → WORKS (via loopback splice)

```
--- getent hosts cache.nixos.org ---   2a04:4e42:1d::347 ... cache.nixos.org
--- curl by name ---                   code=200 ip=151.101.121.91
```

Why it works — pasta debug (`-d`) shows it **splices the cage's loopback onto the
host's loopback**, so a query to `127.0.0.53` in the cage hits the host's
systemd-resolved stub:

```
Flow 0 (TGT): SPLICE [127.0.0.1]:44125 -> [127.0.0.53]:53 => HOST [127.0.0.1]:44125 -> [127.0.0.53]:53
```

The same debug header also prints `NAT to host 127.0.0.1: 192.168.1.254` and
`router: 192.168.1.254`. **This is the Q4 crux**: by default pasta bridges the
cage to host loopback services. Convenient for DNS, a confidentiality leak for
everything else on host 127.0.0.1.

### (3) `pasta --dns-forward 10.0.2.3` + `nameserver 10.0.2.3` → WORKS (architecturally clean)

```sh
printf 'nameserver 10.0.2.3\n' > resolv.fwd.conf
pasta -4 --config-net --dns-forward 10.0.2.3 -- bwrap … --bind resolv.fwd.conf /etc/resolv.conf …
```
```
DNS:  10.0.2.3
--- getent ---  2a04:4e42:6a::347 ... cache.nixos.org
code=200 ip=199.232.169.91
```

pasta intercepts queries sent to the virtual `10.0.2.3` and forwards them to the
host's real upstream resolver — no public nameserver hard-coded, no reliance on
loopback splicing.

**Verdict Q2:** DNS works three ways. The cleanest for ops is **`--dns-forward
<addr>` + a cage `/etc/resolv.conf` naming that addr** (a fixed virtual address,
host-resolver-independent). A hard-coded public `nameserver 1.1.1.1` also works and
is the simplest. The inherited host stub works *only because* pasta splices
loopback — do not rely on it, and note it implies the Q4 leak.

> Process-hygiene note: a `cargo test` network smoke (`mise use -g nix:jq`) from the
> ops-cli suite was running concurrently during this spike under
> `target/test-tmp/ops-test-*`. Those bwrap processes are **not** spike strays; the
> stray checks below were re-scoped to match only this spike's own pasta/bwrap (by
> cmdline referencing the spike dir / resolv files), not every `bwrap` on the host.

---

## Q3 — Real fetch through the uplink

Inside a P-inherit cage (`--dns-forward 10.0.2.3`, cage `/etc/resolv.conf` →
`nameserver 10.0.2.3`). Binds required: the whole rootfs ro already carries
`/etc/ssl` (CA bundle) and the nix store/binaries; only `/etc/resolv.conf` is
overlaid. No `NIX_SSL_CERT_FILE` was set — the host CA bundle under the ro rootfs
sufficed.

### Q3a — `curl -sSI https://cache.nixos.org/nix-cache-info` → HTTP/2 200

```
HTTP/2 200
content-type: text/x-nix-cache-info
server: AmazonS3
```

### Q3b — `nix-prefetch-url` (nix's own curl/TLS, writes to the store) → success

```sh
# … --bind nixhome /home/gigi --setenv HOME /home/gigi …
nix-prefetch-url https://cache.nixos.org/nix-cache-info
```
```
path is '/nix/store/kafk9kay95hx7qnbx56p81qih2282isv-nix-cache-info'
15sqg1j6gq6081nk0v5c6npadlswb9238l336wb2g9bmmrry779c
```

**Verdict Q3:** real HTTPS egress works end-to-end through the pasta uplink for both
plain `curl` and nix's own fetcher. Required binds: `/etc/resolv.conf` (overlaid)
plus the ro rootfs that already supplies `/etc/ssl` and the nix store. This matches
what M3.3d already proved for the host-shared-net case — pasta changes the topology,
not the TLS/cert story.

---

## Q4 — Metadata + host-loopback reachability under pasta (the P-vs-B security crux)

Host-side service stood up for the test: `python3 http.server` on
`127.0.0.1:18080` returning `HOST_LOOPBACK_SECRET_REACHED`. Cage = P-inherit,
`--dns-forward 10.0.2.3`. Cage gateway observed as `192.168.1.254`.

### DEFAULT pasta (no hardening flags)

```
(a) metadata 169.254.169.254   → curl: (28) Connection timed out (connect=000)
(b) cage 127.0.0.1:18080       → HOST_LOOPBACK_SECRET_REACHED   ← LEAK
(c) gateway 192.168.1.254:18080→ HOST_LOOPBACK_SECRET_REACHED   ← LEAK
```

- **(a)** `169.254.169.254` does not connect — **but this is absence-of-service**
  (non-cloud host), **not isolation**. On a cloud host pasta NATs outbound, so the
  real metadata endpoint would be reachable. Not proof of a boundary.
- **(b)** + **(c)**: by default the cage reaches the **host's** loopback service by
  **two** paths — directly via the cage's own `127.0.0.1` (pasta splices loopback,
  the same mechanism that made the `127.0.0.53` DNS stub work in Q2), and via the
  gateway IP (pasta's `--map-host-loopback` defaults to the gateway address). This
  is a real confidentiality leak: anything the host runs on loopback (other agents'
  proxies, dev servers, `ssh-agent`-over-tcp, systemd-resolved) is exposed to the
  cage.

### HARDENED pasta — closing the leaks

`--no-map-gw --no-splice` alone is **insufficient** — it closes (c) but **not** (b):

```
(c) gateway:18080  → Could not connect (7)              ← closed
(b) 127.0.0.1:18080→ HOST_LOOPBACK_SECRET_REACHED       ← STILL LEAKS
```

The flag set that closes **both** while keeping egress + DNS is
`--no-map-gw -T none -U none` (disable TCP/UDP forwarding to the init namespace =
the host-loopback bridge):

```sh
pasta -4 --config-net --no-map-gw -T none -U none --dns-forward 10.0.2.3 -- bwrap … --share-net …
```
```
egress 1.1.1.1      → code=301                           ← egress preserved
DNS                 → cache.nixos.org resolves           ← --dns-forward unaffected
(b) 127.0.0.1:18080 → Could not connect (7)              ← closed
(c) gateway:18080   → Could not connect (7)              ← closed
```

DNS survives because `--dns-forward` is a separate path from generic port
forwarding.

**Verdict Q4:** under **default** pasta the cage reaches host loopback services
(two paths) — metadata would be reachable on a real cloud host. Isolation is **not
free under Model P**: it requires explicit opt-out flags (`--no-map-gw -T none -U
none`), and `--no-splice` alone is a trap (leaves the direct `127.0.0.1` path open).
Model B (empty netns, no uplink) gets all of this isolation **by construction** —
nothing to remember to disable.

---

## Q5 — Model B feasibility (empty netns + host-side proxy over a bound UDS)

### (a) Direct egress from an empty netns must fail → confirmed

`bwrap --unshare-all --unshare-net` (no pasta), only loopback:

```
ip -o addr        → lo only (127.0.0.1/8, ::1/128)
curl https://cache.nixos.org → curl: (6) Could not resolve host
curl https://1.1.1.1/        → curl: (7) … Could not connect to server
```

Deny-by-construction: no route, no DNS, nothing leaves.

### (b) UDS bridge to a host-side proxy → works, clean

Host proxy (one line): `socat UNIX-LISTEN:proxy.sock,fork,reuseaddr
TCP:cache.nixos.org:80`. Bind the socket into the empty-netns cage **inside the
tmpfs** (a bind onto the ro rootfs root fails — `Can't create file at /cage.sock:
Read-only file system`; bind it at `/tmp/cage.sock` *after* `--tmpfs /tmp`):

```sh
bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
  --bind "$PWD/proxy.sock" /tmp/cage.sock --unshare-all --unshare-net \
  -- /bin/sh -c 'curl --unix-socket /tmp/cage.sock http://cache.nixos.org/nix-cache-info; …'
```
```
via-uds   code=301                              ← reaches ONLY the proxy
direct https://1.1.1.1/   → Could not connect   ← nothing else
host 127.0.0.1:18080      → Could not connect   ← host loopback unreachable
```

`curl --unix-socket` is the clean client trick — no manual TLS in the spike (a real
proxy would terminate TLS; HTTP backend here proves byte transport). The contrast is
run from the *same* cage, so "only the proxy, nothing else" is proven, not asserted.

**Verdict Q5:** Model B is feasible and clean. Empty netns denies everything by
construction; a single bound UNIX socket is the *only* egress, and the cage reaches
exactly the host proxy and nothing else (no metadata, no host loopback, no direct
TCP). The one fiddly bit is purely mechanical: bind the UDS into a writable
mountpoint (the tmpfs), not the ro root.

---

## Q6 — Proxy-awareness friction

```
curl HTTPS_PROXY=http://127.0.0.1:59999 …  → curl: (7) … port 443 via 127.0.0.1     (honored)
curl https_proxy=http://127.0.0.1:59999 …  → same "via 127.0.0.1"                    (lowercase honored)
nix  https_proxy=http://127.0.0.1:59999 nix-prefetch-url …
     → warning: unable to download … via 127.0.0.1 … (attempt 2/5 … 5/5) → error    (honored, libcurl)
nix --help | grep proxy → (none)  — nix has no proxy flag; it uses libcurl's
                                    http_proxy / https_proxy / no_proxy env vars.
```

**Verdict Q6:** both `curl` and `nix` honor the standard libcurl proxy env vars
(`http_proxy`/`https_proxy`, either case) — the "via 127.0.0.1" in every error proves
they route through the named proxy. So a Model-B HTTP-proxy approach needs no special
support for these two tools; set the env vars and they comply. (Caveat not tested:
tools that ignore proxy env and `connect()` directly would simply get nothing in
Model B — which is the desired fail-closed behavior, but breaks non-proxy-aware
tools. `nix`'s `http-connections` is a *concurrency* setting, unrelated to proxying.)

---

## Observations for the P-vs-B decision (what I SAW, not opinions)

- **P-attach is out.** A fully-unprivileged host pasta cannot `setns()` into a
  bwrap-owned netns (bwrap always creates a userns where the host has no rights).
  Model P is only reachable via **P-inherit** (`pasta … -- bwrap --share-net …`),
  which works cleanly.
- **Both models deliver working HTTPS egress + DNS + nix fetch.** Topology aside,
  the TLS/cert/store story is identical to today's host-shared-net cage (host CA
  bundle under the ro rootfs suffices; no `NIX_SSL_CERT_FILE` needed).
- **The split is isolation posture, and it's stark:**
  - **Model P leaks by default.** Out of the box the cage reaches the host's
    loopback (two paths) and would reach cloud metadata. Closing it needs a
    *specific, non-obvious* flag set (`--no-map-gw -T none -U none`); the intuitive
    `--no-splice` is a trap that leaves `127.0.0.1` open. Security depends on
    getting pasta flags exactly right — a fail-*open* default.
  - **Model B denies by construction.** Empty netns → no route, no DNS, no
    metadata, no host loopback, for free. The single bound UDS is the only egress.
    A misconfiguration fails *closed* (no socket → no network).
- **Friction tradeoff:** Model P is "general internet, then filter" — every tool
  works unmodified, the filter is the hard part (a transparent/intercepting proxy or
  pasta port rules). Model B is "nothing, then allow" — the allowlist is explicit
  and simple (which proxy, which UDS), but every fetch must be proxy-aware;
  `curl`/`nix` already are (Q6), unknown tools may not be.
- **Model B has no DNS of its own.** The empty-netns cage cannot resolve names; in
  Q5 the *host-side* socat did the resolution. So Model B's proxy must do DNS **and**
  allowlisting — the socat here is only a byte-transport stand-in for that real
  proxy. Under Model P, DNS resolves inside the cage (Q2) and the filter sits
  downstream of name resolution.
- **Mechanical notes for whichever path:** bind targets must land on writable
  mountpoints (use the tmpfs / an existing dir, never the ro root); pasta `-4` cuts
  IPv6 noise; pasta daemonizes by default (use `-f` foreground tied to the child,
  or `-P pidfile` to kill deterministically); `--dns-forward <addr>` is the clean
  host-resolver-independent DNS path in both the splice-on and splice-off cases.

---

## Follow-up micro-spike — the integrated Model-B data path (with teeth)

After the user **chose Model B**, a second throwaway micro-spike proved the *integrated*
path the first spike left untested: not just the primitives, but the real chain
**tool (in cage) → in-cage `socat` TCP→UDS forwarder → bound UDS → host CONNECT
allowlisting proxy**, and — the load-bearing part — that the allowlist **refuses** a
non-allowlisted host (not merely that an allowed one works).

Setup: a ~70-line host-side Python CONNECT proxy listening on a UNIX socket, hostname
allowlist `{cache.nixos.org}`, logging every decision. Cage = `bwrap --unshare-all
--unshare-net` (empty netns) with the proxy's UDS bound at `/tmp/proxy.sock`; inside,
`socat TCP-LISTEN:8080,bind=127.0.0.1,fork UNIX-CONNECT:/tmp/proxy.sock` is the
forwarder, and tools run with `https_proxy=http://127.0.0.1:8080`.

| Test | Result | Proves |
|---|---|---|
| cage interfaces | `lo` only (`127.0.0.1/8`, `::1/128`) | empty netns |
| **curl → ALLOWED** `cache.nixos.org` | **HTTP 200** | the full data path works end to end |
| **curl → DENIED** `example.com` | **`curl: (7) CONNECT tunnel failed, response 403`** | the proxy **actively refuses** (teeth) |
| curl DIRECT (no proxy) | `curl: (6) Could not resolve host` | deny-by-construction; **DNS is host-side** (the cage can't even resolve) |
| **nix-prefetch-url → ALLOWED** | fetched `nix-cache-info` (hash returned) | nix's libcurl routes through the same path |
| **nix-prefetch-url → DENIED** | `CONNECT tunnel failed, response 403` on all 5 retries | nix is refused too (teeth) |

Host proxy decision log (the source of truth): `ALLOW cache.nixos.org:443` for the allowed
fetches, `DENY example.com:443` for every denied attempt — the proxy, not a timeout, refuses.

**Verdict:** Model B's integrated data path is proven with teeth for both `curl` and `nix`
— allowlisted egress succeeds, non-allowlisted egress is actively refused at the proxy, and
a tool that ignores the proxy reaches nothing (empty netns, no route, no DNS). DNS happens
host-side in the proxy (`CONNECT host:port` carries the hostname; the cage never resolves),
which also closes DNS-based exfiltration. This de-risks the 6.2 build: the in-cage forwarder
+ host CONNECT allowlisting proxy is the mechanism, and the spike's proxy (a CONNECT handler
+ a hostname set + a per-connection byte-pipe) is the shape of it.

---

## Second micro-spike — the MITM proxy (exact-URL filtering, + does nix survive it?)

The user then required the allowlist to support **four** granularities — an IP, an exact
domain, a domain + its subdomains, and an **exact URL** (path-level) — and chose to do the
**TLS-terminating MITM** needed for the path-level case from the start. A plain CONNECT proxy
only sees `host:port` for HTTPS, so this third spike proved the MITM path and its load-bearing
unknown: **does `nix` fetch through a proxy that decrypts TLS with an ops-generated CA?**

Setup: a ~200-line host-side Python MITM proxy (`cryptography` for an **ephemeral CA**, the
`ssl` module to terminate TLS). On `CONNECT host:443` it presents a leaf cert for `host`
signed by the ops CA (the cage trusts **only** that CA via `CURL_CA_BUNDLE` /
`NIX_SSL_CERT_FILE`), decrypts, checks `host`+`path` against the allowlist, and — the
non-negotiable — opens its **own TLS to the real upstream with full system-bundle validation**
before relaying. Same empty-netns cage + in-cage `socat` forwarder as before.

| Test | Result | Proves |
|---|---|---|
| **(1) nix → ALLOWED exact URL** | fetched `nix-cache-info` (hash returned) | **nix works through the MITM** with ops's CA trusted — the load-bearing unknown |
| **(2) curl → ALLOWED exact URL** | HTTP 200; log `upstream cert validated` | the MITM data path works; upstream validation runs |
| **(3) curl SAME host, DIFFERENT path** | **403** (`DENY .../other/secret`) | **exact-URL (path-level) filtering has teeth** — only a TLS-terminating proxy can do this |
| **(4) curl fully-denied host** | 403 | host-level deny |
| **(5) allowed host, SELF-SIGNED upstream** | **502** (`UPSTREAM-CERT-REJECT … self-signed certificate`) | the proxy **validates the upstream cert** — the MITM does **not** downgrade transport security |

**Verdict:** the MITM mechanism is proven. `nix`'s TLS rides libcurl + the cert bundle, and
`require-sigs` / NAR-hash verification is orthogonal to transport, so a CA the cage trusts is
all nix needs — confirmed live. Exact-URL filtering works (the reason for MITM), and the
upstream-cert validation has teeth (a self-signed upstream is refused, not relayed). The 6.2b
build target is now an ops-owned MITM allowlisting proxy: ephemeral per-session CA (cage trust
store only, owner-only key), the four-granularity matcher (IP / exact host / subdomain suffix /
exact URL — note the matcher must include the **port** in URL reconstruction, a bug this spike's
first run surfaced), and mandatory upstream validation. The in-cage forwarder + `ops run`
exec→supervise lifecycle (so the host proxy outlives the cage) stays as in the prior section.

