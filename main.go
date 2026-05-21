package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

const (
	// proxyAuthEnv is the environment variable that holds one or more
	// sha256(user:password) hex digests, separated by proxyAuthDelimiter.
	proxyAuthEnv       = "PROXY_AUTH_SHA256"
	proxyAuthDelimiter = ","

	// acmeEmailEnv is the environment variable that supplies the contact
	// email used to register the ACME account with Let's Encrypt. It is
	// required when running in ACME mode (i.e. when ACME_DOMAIN is set)
	// so account recovery and expiration notices reach a real mailbox.
	acmeEmailEnv  = "ACME_EMAIL"
	acmeDomainEnv = "ACME_DOMAIN"

	// listenAddrEnv overrides the TCP address the proxy listens on.
	// Defaults to ":443".  When running behind NAT or a port-forward you can
	// choose any local port (e.g. ":8443") as long as external TCP/443 is
	// forwarded to it so TLS-ALPN-01 ACME challenges still reach the process.
	listenAddrEnv     = "LISTEN_ADDR"
	listenAddrDefault = ":443"

	certStoragePath = "./certmagic-storage"
)

var httpProxyTransport = &http.Transport{
	Proxy: nil,

	DialContext: safeDialContext,

	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   20,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// errBlockedAddress is returned when the requested target resolves to an
// IP address that the proxy refuses to connect to (loopback, private,
// link-local, unspecified, multicast, etc.). Blocking these prevents the
// proxy from being abused for SSRF against the host's internal network
// and cloud metadata endpoints (e.g. 169.254.169.254).
var errBlockedAddress = errors.New("target resolves to a blocked address")

// safeDialContext is a net.Dialer-compatible DialContext that resolves the
// host once, rejects any unsafe IP, and dials the exact resolved IP. This
// prevents DNS-rebinding attacks where a hostname resolves to a public IP
// at resolution time but to a private IP at connect time.
func safeDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return safeDial(ctx, network, address, 10*time.Second)
}

func safeDial(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ip, err := resolveSafeIP(ctx, host)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
}

// resolveSafeIP resolves host to an IP address, returning the first IP
// that is not blocked by isBlockedIP. If every resolved address is
// unsafe, it returns errBlockedAddress.
func resolveSafeIP(ctx context.Context, host string) (net.IP, error) {
	// If the host is already a literal IP, validate it directly.
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return nil, errBlockedAddress
		}
		return ip, nil
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses found for %s", host)
	}

	for _, a := range addrs {
		if !isBlockedIP(a.IP) {
			return a.IP, nil
		}
	}
	return nil, errBlockedAddress
}

// isBlockedIP reports whether ip is in a range the proxy refuses to
// forward to. Blocking these ranges prevents SSRF pivoting into the
// host's loopback interface, RFC1918/ULA networks, link-local ranges
// (including cloud metadata at 169.254.169.254 and fe80::/10), and
// unspecified/multicast destinations.
//
// Declared as a var so tests that need to dial loopback fixtures can
// override it. Production code never reassigns it.
var isBlockedIP = func(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	return false
}

func main() {
	acmeDomain := configuredACMEDomain()
	listenAddr := configuredListenAddr()

	var tlsConfig *tls.Config

	if acmeDomain == "" {
		log.Printf("ACME_DOMAIN not set; using auto-generated self-signed certificate")

		cfg, err := selfSignedTLSConfig()
		if err != nil {
			log.Fatalf("failed to generate self-signed certificate: %v", err)
		}

		tlsConfig = cfg
	} else {
		acmeEmail, err := configuredACMEEmail()
		if err != nil {
			log.Fatalf("invalid ACME configuration: %v", err)
		}

		cfg, err := managedTLSConfig(acmeDomain, acmeEmail)
		if err != nil {
			log.Fatalf("failed to manage certificate for %s: %v", acmeDomain, err)
		}
		tlsConfig = cfg

		log.Printf("HTTPS proxy listening on https://%s", listenerHostPort(acmeDomain, listenAddr))
	}

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           http.HandlerFunc(proxyHandler),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsConfig,
	}

	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func configuredACMEDomain() string {
	domain := strings.TrimSpace(os.Getenv(acmeDomainEnv))
	if domain == "" {
		return ""
	}
	return strings.Trim(domain, "[]")
}

// configuredListenAddr returns the TCP address the proxy should bind to.
// It reads the LISTEN_ADDR environment variable and falls back to ":443".
func configuredListenAddr() string {
	addr := strings.TrimSpace(os.Getenv(listenAddrEnv))
	if addr == "" {
		return listenAddrDefault
	}
	return addr
}

// configuredACMEEmail returns the contact email used to register the
// ACME account. It is required when ACME mode is enabled so Let's Encrypt
// can deliver expiration notices and account recovery emails. The default
// "admin@example.com" is intentionally rejected because example.com is a
// reserved domain whose mail is undeliverable, leaving the account
// orphaned.
func configuredACMEEmail() (string, error) {
	email := strings.TrimSpace(os.Getenv(acmeEmailEnv))
	if email == "" {
		return "", fmt.Errorf("%s must be set to a contact email when %s is configured", acmeEmailEnv, acmeDomainEnv)
	}
	if !strings.Contains(email, "@") {
		return "", fmt.Errorf("%s=%q is not a valid email address", acmeEmailEnv, email)
	}
	lower := strings.ToLower(email)
	if strings.HasSuffix(lower, "@example.com") ||
		strings.HasSuffix(lower, "@example.org") ||
		strings.HasSuffix(lower, "@example.net") {
		return "", fmt.Errorf("%s=%q uses a reserved example domain; mail is undeliverable", acmeEmailEnv, email)
	}
	return email, nil
}

func managedTLSConfig(acmeDomain, acmeEmail string) (*tls.Config, error) {
	if err := os.MkdirAll(certStoragePath, 0700); err != nil {
		return nil, fmt.Errorf("could not create CertMagic storage directory: %w", err)
	}

	certmagic.Default.Storage = &certmagic.FileStorage{
		Path: certStoragePath,
	}

	certmagic.DefaultACME.Email = acmeEmail
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA

	magic := certmagic.NewDefault()

	if err := magic.ManageSync(context.Background(), []string{acmeDomain}); err != nil {
		return nil, err
	}

	cfg := magic.TLSConfig()
	cfg.NextProtos = []string{
		"http/1.1",
		"acme-tls/1",
	}

	return cfg, nil
}

// selfSignedTLSConfig generates an ephemeral ECDSA P-256 key and a
// self-signed certificate valid for 10 years. Use this when no ACME_DOMAIN
// is configured and domain-based certificate management is not needed.
func selfSignedTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "squid-go"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}, nil
}

func listenerHostPort(host, addr string) string {
	port := strings.TrimPrefix(addr, ":")
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if !authorized(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="go-https-proxy"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

	switch r.Method {
	case http.MethodConnect:
		handleConnect(w, r)
	default:
		handlePlainHTTP(w, r)
	}
}

func authorized(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return false
	}

	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, prefix))
	if err != nil {
		return false
	}

	// Require a non-empty "user:password" pair.
	colon := strings.IndexByte(string(raw), ':')
	if colon <= 0 || colon == len(raw)-1 {
		return false
	}

	sum := sha256.Sum256(raw)
	got := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(got, sum[:])

	allowed := allowedAuthHashes()
	if len(allowed) == 0 {
		return false
	}

	match := 0
	for _, want := range allowed {
		if len(want) != len(got) {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(want), got) == 1 {
			match = 1
		}
	}
	return match == 1
}

// allowedAuthHashes returns the configured sha256(user:password) hex digests
// from the proxyAuthEnv environment variable. Multiple values may be provided,
// separated by proxyAuthDelimiter. Empty entries and surrounding whitespace
// are ignored, and hex digests are lower-cased for comparison.
func allowedAuthHashes() []string {
	raw := os.Getenv(proxyAuthEnv)
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, proxyAuthDelimiter)
	hashes := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		hashes = append(hashes, p)
	}
	return hashes
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host

	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		http.Error(w, "bad CONNECT target", http.StatusBadRequest)
		return
	}

	// Safety rule:
	// only allow tunneling to normal HTTPS targets.
	if port != "443" {
		http.Error(w, "CONNECT only allowed to port 443", http.StatusForbidden)
		return
	}

	dstConn, err := safeDial(r.Context(), "tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		if errors.Is(err, errBlockedAddress) {
			log.Printf("CONNECT %s blocked: %v", target, err)
			http.Error(w, "target address is not allowed", http.StatusForbidden)
			return
		}
		http.Error(w, "failed to connect to target", http.StatusBadGateway)
		return
	}
	defer dstConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "connection hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, buffered, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "failed to hijack client connection", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = buffered.Flush()

	// Any bytes the client pipelined immediately after the CONNECT request
	// (typically the TLS ClientHello) may already sit in the bufio.Reader.
	// Forward them to the destination before splice-copying from the raw
	// connection, otherwise they would be silently dropped.
	if n := buffered.Reader.Buffered(); n > 0 {
		if _, err := io.CopyN(dstConn, buffered.Reader, int64(n)); err != nil {
			log.Printf("CONNECT %s: drain buffered client bytes: %v", target, err)
			return
		}
	}

	log.Printf("CONNECT %s", target)

	errCh := make(chan error, 2)

	go func() {
		errCh <- proxyCopy(dstConn, clientConn)
	}()

	go func() {
		errCh <- proxyCopy(clientConn, dstConn)
	}()

	<-errCh
}

func handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	// HTTP proxy clients send absolute-form requests:
	//
	//   GET http://example.com/path HTTP/1.1
	//
	// This handler supports plain HTTP websites through the HTTPS proxy.
	if r.URL.Scheme == "" || r.URL.Host == "" {
		http.Error(w, "expected absolute URL for HTTP proxy request", http.StatusBadRequest)
		return
	}

	if r.URL.Scheme != "http" {
		http.Error(w, "use CONNECT for HTTPS targets", http.StatusBadRequest)
		return
	}

	outReq := r.Clone(r.Context())

	// Required for http.Transport.RoundTrip.
	outReq.RequestURI = ""

	// Never forward proxy credentials to the origin server.
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Del("Proxy-Authenticate")

	removeHopByHopHeaders(outReq.Header)

	resp, err := httpProxyTransport.RoundTrip(outReq)
	if err != nil {
		if errors.Is(err, errBlockedAddress) {
			log.Printf("%s %s blocked: %v", r.Method, r.URL.String(), err)
			http.Error(w, "target address is not allowed", http.StatusForbidden)
			return
		}
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	_, _ = io.Copy(w, resp.Body)

	log.Printf("%s %s -> %d", r.Method, r.URL.String(), resp.StatusCode)
}

func proxyCopy(dst net.Conn, src net.Conn) error {
	_, err := io.Copy(dst, src)

	_ = dst.SetDeadline(time.Now())
	_ = src.SetDeadline(time.Now())

	return err
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func removeHopByHopHeaders(h http.Header) {
	// Remove headers listed by the Connection header first.
	for _, value := range h.Values("Connection") {
		for _, field := range strings.Split(value, ",") {
			field = strings.TrimSpace(field)
			if field != "" {
				h.Del(field)
			}
		}
	}

	for _, header := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		h.Del(header)
	}
}
