# squid-go
A Squid proxy in Golang

## Configuration

TLS certificate management uses the `ACME_DOMAIN` environment variable.
Set it to the public DNS name(s) or IP address(es) that should receive the
certificate (e.g. `proxy.example.com` or `203.0.113.8`). Multiple values
may be supplied as a comma-separated list, which is useful for covering
both apex and `www` hostnames:

```sh
export ACME_DOMAIN="proxy.example.com,www.proxy.example.com"
```

Every value must resolve to this host, because each one is validated
independently with TLS-ALPN-01. Surrounding whitespace and bracketed
IPv6 literals (e.g. `[2001:db8::1]`) are accepted per entry.

When `ACME_DOMAIN` is set, the proxy uses Let's Encrypt with the
TLS-ALPN-01 challenge to obtain and renew a certificate automatically.
Let's Encrypt issues certificates for both DNS names and IP addresses
through this flow. Public TCP/443 must reach the process for issuance
and renewal. If you run the process on a non-standard local port (see
`LISTEN_ADDR` below), port-forward external TCP/443 to that local port
so challenge traffic still reaches the process.

When `ACME_DOMAIN` is set, you must also set `ACME_EMAIL` to a real
contact address. Let's Encrypt uses it for expiration notices and
account recovery. The proxy refuses to start in ACME mode if
`ACME_EMAIL` is unset or uses a reserved `example.{com,org,net}`
domain, since those addresses are undeliverable.

When `ACME_DOMAIN` is unset or empty, the proxy starts with an ephemeral
self-signed certificate generated at startup. No domain or public reachability
is required in this mode.

The directory where ACME account keys, **issued certificate private keys**,
and certificates are stored is controlled by the `CERT_STORAGE_PATH`
environment variable. It defaults to `./certmagic-storage` (resolved
relative to the working directory) and must be writable by the process.
This directory is created with mode `0700` because it holds long-lived
private key material; treat it as sensitive, restrict filesystem access
to the proxy user, and include it in your backup and key-rotation plans.
The Docker image ships with this set to `/var/lib/squid-go`, which is
created with the correct ownership for the non-root runtime user.

Proxy authentication is configured via the `PROXY_AUTH_SHA256` environment
variable. Its value is a list of `sha256(user:password)` hex digests,
separated by commas (`,`). Each digest authorises the corresponding
`user:password` pair for HTTP Basic proxy authentication.

Generate a digest for a credential pair:

```sh
printf '%s' 'user:pass' | sha256sum
```

Then start the proxy with one or more digests:

```sh
export PROXY_AUTH_SHA256="<sha256-of-user1:pass1>,<sha256-of-user2:pass2>"
./squid-go
```

If `PROXY_AUTH_SHA256` is empty or unset, all proxy requests are rejected.

## CONNECT tunnels

The proxy permits HTTP `CONNECT` tunnels only to ports listed in the
`CONNECT_ALLOWED_PORTS` environment variable. The default is `443`, so
without configuration only standard HTTPS tunnels are accepted. To allow
additional ports (for example alternative HTTPS endpoints), set a
comma-separated list:

```sh
export CONNECT_ALLOWED_PORTS="443,8443"
```

CONNECT requests to any other port are rejected with HTTP 403.

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
requests before exiting. Active CONNECT tunnels are given up to 30
seconds to complete; afterwards they are closed. This is the standard
container-orchestrator stop signal, so rolling deploys on Kubernetes,
ECS, or systemd do not abruptly sever client connections.

## Listen address

The `LISTEN_ADDR` environment variable controls the local TCP address the
proxy binds to. It defaults to `:443`.

```sh
# Listen on port 8443 while port-forwarding external 443 → local 8443
export LISTEN_ADDR=":8443"
./squid-go
```

This is useful when running behind a load balancer or NAT that forwards
public TCP/443 to a non-privileged local port. TLS-ALPN-01 certificate
validation still works as long as external TCP/443 reaches the process.

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
Tunnel, an authenticated reverse proxy, ...) whenever the listed
non-goals matter to your environment.
