# squid-go
A Squid proxy in Golang

## Configuration

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
