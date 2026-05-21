package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

const (
	// TLS-ALPN-01 requires this service to be reachable on public TCP/443.
	// You may run directly on :443, or port-forward external 443 to this process.
	proxyListen = ":443"

	// proxyAuthEnv is the environment variable that holds one or more
	// sha256(user:password) hex digests, separated by proxyAuthDelimiter.
	proxyAuthEnv       = "PROXY_AUTH_SHA256"
	proxyAuthDelimiter = ","

	acmeEmail         = "admin@example.com"
	acmeDomainEnv     = "ACME_DOMAIN"
	defaultACMEDomain = "proxy.example.com"

	certStoragePath = "./certmagic-storage"
)

var httpProxyTransport = &http.Transport{
	Proxy: nil,

	DialContext: (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,

	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   20,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

func main() {
	acmeDomain := configuredACMEDomain()

	if err := os.MkdirAll(certStoragePath, 0700); err != nil {
		log.Fatalf("could not create CertMagic storage directory: %v", err)
	}

	certmagic.Default.Storage = &certmagic.FileStorage{
		Path: certStoragePath,
	}

	certmagic.DefaultACME.Email = acmeEmail
	certmagic.DefaultACME.Agreed = true

	// Let’s Encrypt production CA.
	certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA

	// No DNS01Solver.
	// No HTTP-01 listener.
	// TLS-ALPN-01 is handled through the TLS listener on :443.
	magic := certmagic.NewDefault()

	// Start certificate management.
	// CertMagic will obtain/renew certs automatically.
	if err := magic.ManageSync(context.Background(), []string{acmeDomain}); err != nil {
		log.Fatalf("failed to manage certificate for %s: %v", acmeDomain, err)
	}

	tlsConfig := magic.TLSConfig()

	// Important for a traditional HTTP proxy:
	// keep HTTP/1.1 enabled because CONNECT tunneling uses Hijacker here.
	//
	// Keep acme-tls/1 so TLS-ALPN-01 can work.
	tlsConfig.NextProtos = []string{
		"http/1.1",
		"acme-tls/1",
	}

	server := &http.Server{
		Addr:              proxyListen,
		Handler:           http.HandlerFunc(proxyHandler),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsConfig,
	}

	log.Printf("HTTPS proxy listening on https://%s", listenerHostPort(acmeDomain, proxyListen))

	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func configuredACMEDomain() string {
	domain := strings.TrimSpace(os.Getenv(acmeDomainEnv))
	if domain == "" {
		return defaultACMEDomain
	}
	return strings.Trim(domain, "[]")
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

	dstConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
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
