# squid-go
[![codecov](https://codecov.io/gh/define42/squid-go/graph/badge.svg?token=C1HBYRR7IJ)](https://codecov.io/gh/define42/squid-go)

A small, opinionated **forward HTTPS proxy** written in Go.

`squid-go` is *not* a port of Squid. It is a minimal, single-binary alternative
that speaks HTTP `CONNECT` for HTTPS tunneling and plain-HTTP forwarding,
authenticates clients with SHA-256-hashed Basic credentials, and terminates
its own TLS using a certificate obtained automatically from Let's Encrypt
(or an ephemeral self-signed certificate when no domain is configured). It
ships as a static binary and a distroless container image, and is designed
to run unattended behind a network boundary you already trust.

## Features

- **TLS-terminated forward proxy** — clients connect to `squid-go` over
  HTTPS, then issue `CONNECT` (for HTTPS targets) or plain HTTP requests.
- **Automatic certificates** — Let's Encrypt via the TLS-ALPN-01 challenge,
  for both DNS names and public IP addresses. Falls back to an ephemeral
  self-signed certificate when no domain is configured.
- **SHA-256 hashed Basic auth** — credentials are stored as
  `sha256(user:password)` digests; raw passwords never touch the config.
  Constant-time comparison prevents timing oracles.
- **SSRF-hardened dialer** — every outbound dial resolves once and refuses
  loopback, private, link-local, CGNAT, multicast, unspecified, TEST-NET,
  RFC 2544 benchmark, broadcast, the RFC 1122 "this host" block
  (`0.0.0.0/8`), and IPv6 documentation ranges. IPv4-mapped IPv6 addresses
  are unwrapped before classification, and the NAT64 well-known prefix
  (`64:ff9b::/96`) is blocked, so a private IPv4 destination cannot be
  smuggled through an IPv6 literal. The resolved IP is dialled directly, so
  DNS rebinding cannot redirect an already-validated hostname onto an
  internal address.
- **CONNECT port allow-list** — only ports listed in
  `CONNECT_ALLOWED_PORTS` (default `443`) may be tunneled.
- **PAC file at `/proxy.pac`** — clients can be configured with the URL
  `https://<your-host>/proxy.pac` to auto-discover the proxy. The file
  returns a single `HTTPS` directive pointing at the configured
  `ACME_DOMAIN` (or the request `Host` header in self-signed mode) on
  the proxy's listen port. The endpoint is served unauthenticated so
  browsers can fetch it before any proxy credentials are configured.
- **Graceful shutdown** — SIGINT / SIGTERM drain in-flight requests, with
  up to 30 seconds for active `CONNECT` tunnels to finish.
- **Distroless container** — non-root runtime, no shell, ~10 MB image.

## Quick start

### Run from source

```sh
# 1. Generate a digest for each user:password pair
printf '%s' 'alice:s3cret' | sha256sum | awk '{print $1}'

# 2. Start the proxy (self-signed TLS, no public reachability required)
export PROXY_AUTH_SHA256="<digest-from-step-1>"
export LISTEN_ADDR=":8443"
go run .
```

Then point a client at `https://localhost:8443` as its HTTPS proxy,
supplying `alice:s3cret` as Basic credentials.

### Run with Docker and Let's Encrypt

```sh
docker build -t squid-go .

docker run --rm -p 443:443 \
  -e ACME_DOMAIN="proxy.example.com" \
  -e ACME_EMAIL="ops@example.com" \
  -e PROXY_AUTH_SHA256="$(printf '%s' 'alice:s3cret' | sha256sum | awk '{print $1}')" \
  -v squid-go-certs:/var/lib/squid-go \
  squid-go
```

`proxy.example.com` must resolve to the host running the container, and
external TCP/443 must reach it so Let's Encrypt can complete the
TLS-ALPN-01 challenge.

### Run with Docker Compose

The repository includes a Compose example at
[`docker-compose.example.yml`](./docker-compose.example.yml). Update
`ACME_DOMAIN` and `ACME_EMAIL` in that file, then export a digest for
`PROXY_AUTH_SHA256` before starting it:

```sh
export PROXY_AUTH_SHA256="$(printf '%s' 'alice:s3cret' | sha256sum | awk '{print $1}')"
docker compose -f docker-compose.example.yml up --build -d
```

The example publishes TCP/443 and stores issued certificates in the
named volume `squid-go-certs`.

## Configuration

All configuration is via environment variables.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PROXY_AUTH_SHA256` | *(none, required)* | Comma-separated `sha256(user:password)` hex digests. Empty = reject all. |
| `LISTEN_ADDR` | `:443` | Local TCP address to bind for the TLS proxy listener. |
| `HTTP_LISTEN_ADDR` | *(unset)* | Optional local TCP address for an additional **unencrypted** HTTP proxy listener (e.g. `:80`). When unset, only the TLS listener runs. |
| `ACME_DOMAIN` | *(unset)* | Comma-separated DNS names / IP literals to obtain a Let's Encrypt cert for. Unset = self-signed. |
| `ACME_EMAIL` | *(unset, required when `ACME_DOMAIN` is set)* | Contact address for Let's Encrypt account. |
| `ACME_PROFILE` | *(auto: `shortlived` if any `ACME_DOMAIN` entry is an IP literal, else unset)* | Optional Let's Encrypt [ACME profile](https://letsencrypt.org/docs/profiles/) to request. IP-address identifiers require `shortlived` (~6-day certs); LE's default profile rejects them. |
| `CERT_STORAGE_PATH` | `./certmagic-storage` (image: `/var/lib/squid-go`) | Directory for ACME account key + issued certs. Created `0700`. |
| `CONNECT_ALLOWED_PORTS` | `443` | Comma-separated allow-list of TCP ports for `CONNECT` tunnels, or `all` to permit any port. |
| `NO_AUTH_CIDRS` | *(unset)* | Comma-separated IPs / CIDRs of clients allowed to use the proxy **without** authentication. Bare IPs are treated as `/32` (IPv4) or `/128` (IPv6). |

### TLS certificates

`squid-go` terminates TLS itself. The certificate strategy depends on
`ACME_DOMAIN`:

- **`ACME_DOMAIN` set** — Let's Encrypt issues a certificate via
  TLS-ALPN-01 for every listed name. Public TCP/443 must reach the process
  for issuance and renewal. If `LISTEN_ADDR` is a non-standard port,
  port-forward external 443 → the local port. Multiple names are
  comma-separated; each is validated independently and must resolve to
  this host. Bracketed IPv6 literals (e.g. `[2001:db8::1]`) and
  surrounding whitespace are accepted per entry. Let's Encrypt issues
  certificates for both DNS names and public IP addresses through this
  flow.

  ```sh
  export ACME_DOMAIN="proxy.example.com,www.proxy.example.com"
  export ACME_EMAIL="ops@example.com"
  ```

  `ACME_EMAIL` is required in this mode and is rejected if it uses a
  reserved `example.{com,org,net}` domain, since those addresses are
  undeliverable.

  **IP-address certificates.** Let's Encrypt's default ACME profile
  refuses IP-address identifiers. When any `ACME_DOMAIN` entry parses as
  an IP literal, `squid-go` automatically requests the `shortlived`
  profile (≤ 6-day certificates), which is currently the only LE profile
  that issues IP certs. The account submitting the order must be
  allow-listed by Let's Encrypt for IP issuance; otherwise the order is
  still rejected. Renewal happens automatically while the process is
  running and TCP/443 stays reachable. Set `ACME_PROFILE` to override
  the auto-selection (e.g. `ACME_PROFILE=classic` for a DNS-only setup
  that wants long-lived certificates explicitly). See
  <https://letsencrypt.org/docs/profiles/> for the current profile list.

- **`ACME_DOMAIN` unset or empty** — the proxy generates a fresh
  self-signed certificate at startup. No domain or public reachability
  is required. Clients must trust (or pin) this certificate out of band.

### Certificate storage

`CERT_STORAGE_PATH` holds ACME account keys, **issued certificate private
keys**, and certificates. It is created with mode `0700` because it
contains long-lived private key material — treat it as sensitive,
restrict filesystem access to the proxy user, and include it in your
backup and key-rotation plans. The Docker image ships with this set to
`/var/lib/squid-go`, pre-created with the correct ownership for the
non-root runtime user.

### Authentication

`PROXY_AUTH_SHA256` is a comma-separated list of `sha256(user:password)`
hex digests. Each digest authorises one `user:password` pair for HTTP
Basic proxy authentication.

```sh
printf '%s' 'user:pass' | sha256sum | awk '{print $1}'
export PROXY_AUTH_SHA256="<digest1>,<digest2>"
```

If `PROXY_AUTH_SHA256` is empty or unset, all proxy requests are
rejected. To rotate a credential, replace its digest in the variable and
restart the process.

#### Allow-listing client IPs without authentication

`NO_AUTH_CIDRS` is an optional comma-separated list of IP addresses and
CIDR ranges. Clients whose remote address falls inside any listed range
are allowed to use the proxy **without supplying any
`Proxy-Authorization` header**. This is useful for trusted internal
networks that should reach the proxy without managing credentials.

```sh
# Trust everything from a private /24 plus a single static host
export NO_AUTH_CIDRS="10.0.0.0/24,192.0.2.7"
# IPv6 ranges and single addresses work too
export NO_AUTH_CIDRS="2001:db8::/32,[2001:db8::1]"
```

Bare IP literals are treated as a single host (`/32` for IPv4, `/128`
for IPv6). Whitespace and empty entries are ignored. When the variable
is unset or empty, every request must authenticate via
`PROXY_AUTH_SHA256`.

> **Warning.** Only list networks you fully trust. `squid-go` matches
> against the TCP peer address, so if you front the proxy with a load
> balancer or other reverse proxy every request will appear to come
> from that intermediary's IP. Do not put such an intermediary into
> `NO_AUTH_CIDRS` unless you also enforce authentication upstream.

### CONNECT tunnels

`CONNECT_ALLOWED_PORTS` is a comma-separated allow-list. The default
`443` permits only standard HTTPS tunnels. Add additional ports as
needed:

```sh
export CONNECT_ALLOWED_PORTS="443,8443"
```

`CONNECT` requests to any other port are rejected with HTTP 403.

Set it to `all` (case-insensitive) to disable the allow-list and permit
`CONNECT` to any port:

```sh
export CONNECT_ALLOWED_PORTS="all"
```

### Listen address

`LISTEN_ADDR` (default `:443`) is useful when running behind a load
balancer or NAT that forwards public TCP/443 to a non-privileged local
port. TLS-ALPN-01 certificate validation still works as long as external
TCP/443 reaches the process.

```sh
# Listen on 8443 while port-forwarding external 443 → local 8443
export LISTEN_ADDR=":8443"
```

### Plain-HTTP (unencrypted) listener

`HTTP_LISTEN_ADDR` (unset by default) optionally enables an additional
**unencrypted** proxy listener alongside the TLS listener. When set to
a non-empty TCP address, the same handler is served over cleartext HTTP
in parallel with the TLS listener, so authentication, SSRF protection,
and `CONNECT_ALLOWED_PORTS` apply identically.

```sh
# Run the standard TLS proxy on :443 and an additional plain-HTTP proxy on :80
export LISTEN_ADDR=":443"
export HTTP_LISTEN_ADDR=":80"
```

> **Warning.** On this listener, client `Proxy-Authorization` credentials
> and any forwarded plain-HTTP request/response bodies travel in
> cleartext. `CONNECT` tunnels remain end-to-end encrypted between the
> client and the origin, but the tunnel setup (including credentials)
> is still visible to on-path observers. Only enable this listener on
> a trusted network segment.

## SSRF protection

Both `CONNECT` and plain-HTTP forwarding resolve the requested target
once and refuse to dial any address in a private, loopback, link-local,
unspecified, multicast, or carrier-grade-NAT (`100.64.0.0/10`) range.
The RFC 1122 "this host on this network" block (`0.0.0.0/8`), TEST-NET
ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), the RFC
2544 benchmark range (`198.18.0.0/15`), the limited broadcast address
(`255.255.255.255`), and the IPv6 documentation prefix (`2001:db8::/32`)
are also blocked. IPv4-mapped IPv6 addresses are unwrapped before
classification, and the NAT64 well-known prefix (`64:ff9b::/96`) is
refused outright, so a private IPv4 destination cannot be smuggled
through an IPv6 literal. The resolved IP is dialled directly so DNS
rebinding cannot redirect an already-validated hostname onto an internal
address.

## Graceful shutdown

The proxy installs a SIGINT / SIGTERM handler that drains in-flight
requests before exiting. Active `CONNECT` tunnels are given up to 30
seconds to complete; afterwards they are closed. This is the standard
container-orchestrator stop signal, so rolling deploys on Kubernetes,
ECS, or systemd do not abruptly sever client connections.

## Threat model and non-goals

`squid-go` is a forward HTTPS proxy with HTTP `CONNECT` tunneling and
SHA-256-hashed Basic authentication. The following are explicit
**non-goals** of the project:

- **TLS interception / MITM.** The proxy does *not* inspect, decrypt, or
  rewrite the bytes inside a `CONNECT` tunnel. End-to-end TLS between the
  client and the origin is preserved. No content filtering, antivirus
  scanning, or DLP is performed.
- **Open / anonymous relay.** Requests are refused unless they carry a
  valid `Proxy-Authorization` header whose `sha256(user:password)` digest
  appears in `PROXY_AUTH_SHA256`. Operating with an empty allow-list
  rejects all traffic by design.
- **DDoS or abuse mitigation.** There is no built-in rate limiting,
  connection cap per credential, request quota, or IP reputation
  filtering. **Do not expose this proxy directly to the open internet
  without putting a rate limiter (e.g. a reverse proxy, WAF, or
  cloud-edge service) in front of it**, and rotate compromised
  credentials by removing their digest from `PROXY_AUTH_SHA256`.
- **Egress policy / URL category filtering.** The proxy accepts any
  hostname that resolves to a non-blocked IP and any `CONNECT` target on
  an allow-listed port (see `CONNECT_ALLOWED_PORTS`). It does not
  enforce per-user destination policy.
- **Auditing and per-request log retention.** Requests are logged to
  stderr in structured form via `log/slog`, but no long-term audit log,
  request body capture, or tamper-evident logging is provided.

What the proxy **does** defend against:

- **SSRF and DNS rebinding.** Both `CONNECT` and plain-HTTP forwarding
  resolve targets once and refuse to dial loopback, private, link-local,
  CGNAT, multicast, unspecified, TEST-NET, benchmark, and IPv6
  documentation addresses. See the [SSRF protection](#ssrf-protection)
  section for the full list.
- **Credential brute-force timing.** Authentication uses constant-time
  comparison against SHA-256 digests; raw passwords are never stored.
- **Hop-by-hop header smuggling.** `Connection`, `Keep-Alive`, `TE`,
  `Trailer`, `Transfer-Encoding`, `Upgrade`, and the `Proxy-*` auth
  headers are stripped before forwarding plain-HTTP requests.
- **Slow-loris on the TLS listener.** `ReadHeaderTimeout` is enforced;
  long-lived `CONNECT` tunnels are explicitly exempt from
  `WriteTimeout`.

Deploy behind authenticated network paths (VPN, Tailscale, Cloudflare
Tunnel, an authenticated reverse proxy, …) whenever the listed
non-goals matter to your environment.

## Building and testing

```sh
go vet ./...
go build ./...
go test -race -v ./...
```

The same commands run in CI (see `.github/workflows/test.yml`).

## License

See [LICENSE](LICENSE).
