package main

import (
	"crypto/subtle"
	"encoding/base64"
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

	proxyUser = "user"
	proxyPass = "pass"

	acmeEmail  = "admin@example.com"
	acmeDomain = "proxy.example.com"

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
	if err := magic.ManageSync([]string{acmeDomain}); err != nil {
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

	log.Printf("HTTPS proxy listening on https://%s%s", acmeDomain, proxyListen)

	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
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

	expected := proxyUser + ":" + proxyPass

	return subtle.ConstantTimeCompare(raw, []byte(expected)) == 1
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
