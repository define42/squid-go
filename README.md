# squid-go
A Squid proxy in Golang

## Configuration

TLS certificate management uses the `ACME_DOMAIN` environment variable.
Set it to the public DNS name or IP address that should receive the
certificate (e.g. `proxy.example.com` or `203.0.113.8`).

When `ACME_DOMAIN` is a DNS name, the proxy uses Let's Encrypt with the
TLS-ALPN-01 challenge. Public TCP/443 must reach the process for issuance
and renewal. If you run the process on a non-standard local port (see
`LISTEN_ADDR` below), port-forward external TCP/443 to that local port.

When `ACME_DOMAIN` is an IP address, the proxy uses ZeroSSL's API because
IP certificates are not handled by the Let's Encrypt ACME path used for DNS
names here. In this mode:

- `ZEROSSL_API_KEY` is required
- public TCP/80 must reach the temporary HTTP validation listener
- if validation traffic is port-forwarded to a non-standard local port, set
  `ACME_HTTP_PORT` to that local port

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

## IP certificate validation

For IP certificates, ZeroSSL validation uses HTTP reachability instead of the
TLS-ALPN flow used for DNS names.

```sh
export ACME_DOMAIN="203.0.113.8"
export ZEROSSL_API_KEY="<your-zerossl-api-key>"

# Optional: if external TCP/80 is forwarded to a different local port
export ACME_HTTP_PORT="8080"

./squid-go
```

If `ACME_HTTP_PORT` is set, forward public TCP/80 to that local port so the
ZeroSSL validation server can answer the challenge.
