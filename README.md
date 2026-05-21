# squid-go
A Squid proxy in Golang

## Configuration

TLS certificate management uses the `ACME_DOMAIN` environment variable.
Set it to the public DNS name or IP address that should receive the
certificate (e.g. `proxy.example.com` or `203.0.113.8`).

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

## SSRF protection

Both `CONNECT` and plain-HTTP forwarding resolve the requested target
once and refuse to dial any address in a private, loopback, link-local,
unspecified, or multicast range. This blocks SSRF pivoting into the
host's internal network and cloud metadata endpoints (e.g.
`169.254.169.254`). The resolved IP is dialed directly so DNS
rebinding cannot redirect an already-validated hostname onto an
internal address.

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
