# squid-go

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
  RFC 2544 benchmark, broadcast, and IPv6 documentation ranges. IPv4-mapped
  IPv6 addresses are unwrapped before classification. The resolved IP is
  dialled directly, so DNS rebinding cannot redirect an already-validated
  hostname onto an internal address.
- **CONNECT port allow-list** — only ports listed in
  `CONNECT_ALLOWED_PORTS` (default `443`) may be tunneled.
- **Graceful shutdown** — SIGINT / SIGTERM drain in-flight requests, with
  up to 30 seconds for active `CONNECT` tunnels to finish.
- **Distroless container** — non-root runtime, no shell, ~10 MB image.

## Quick start

### Run from source

```sh
# 1. Generate a digest for each user:password pair
printf '%s' 'alice:s3cret' | sha256sum

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
| `LISTEN_ADDR` | `:443` | Local TCP address to bind. |
| `ACME_DOMAIN` | *(unset)* | Comma-separated DNS names / IP literals to obtain a Let's Encrypt cert for. Unset = self-signed. |
| `ACME_EMAIL` | *(unset, required when `ACME_DOMAIN` is set)* | Contact address for Let's Encrypt account. |
| `CERT_STORAGE_PATH` | `./certmagic-storage` (image: `/var/lib/squid-go`) | Directory for ACME account key + issued certs. Created `0700`. |
| `CONNECT_ALLOWED_PORTS` | `443` | Comma-separated allow-list of TCP ports for `CONNECT` tunnels. |

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
printf '%s' 'user:pass' | sha256sum
export PROXY_AUTH_SHA256="<digest1>,<digest2>"
```

If `PROXY_AUTH_SHA256` is empty or unset, all proxy requests are
rejected. To rotate a credential, replace its digest in the variable and
restart the process.

### CONNECT tunnels

`CONNECT_ALLOWED_PORTS` is a comma-separated allow-list. The default
`443` permits only standard HTTPS tunnels. Add additional ports as
needed:

```sh
export CONNECT_ALLOWED_PORTS="443,8443"
```

`CONNECT` requests to any other port are rejected with HTTP 403.

### Listen address

`LISTEN_ADDR` (default `:443`) is useful when running behind a load
balancer or NAT that forwards public TCP/443 to a non-privileged local
port. TLS-ALPN-01 certificate validation still works as long as external
TCP/443 reaches the process.

```sh
# Listen on 8443 while port-forwarding external 443 → local 8443
export LISTEN_ADDR=":8443"
```

## SSRF protection

Both `CONNECT` and plain-HTTP forwarding resolve the requested target
once and refuse to dial any address in a private, loopback, link-local,
unspecified, multicast, or carrier-grade-NAT (`100.64.0.0/10`) range.
TEST-NET ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
the RFC 2544 benchmark range (`198.18.0.0/15`), the limited broadcast
address (`255.255.255.255`), and the IPv6 documentation prefix
(`2001:db8::/32`) are also blocked. IPv4-mapped IPv6 addresses are
unwrapped before classification so they cannot smuggle a private IPv4
destination through an IPv6 literal. The resolved IP is dialled directly
so DNS rebinding cannot redirect an already-validated hostname onto an
internal address.

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
