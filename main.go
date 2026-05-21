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
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
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
	// acmeDomainEnv is a comma-separated list of DNS names or IP addresses
	// that the ACME certificate should cover (e.g.
	// "proxy.example.com,www.proxy.example.com"). All listed names must
	// resolve to this host so the TLS-ALPN-01 challenge succeeds for each
	// one. Bracketed IPv6 literals (e.g. "[2001:db8::1]") are unwrapped
	// per entry.
	acmeDomainEnv = "ACME_DOMAIN"

	// listenAddrEnv overrides the TCP address the proxy listens on.
	// Defaults to ":443".  When running behind NAT or a port-forward you can
	// choose any local port (e.g. ":8443") as long as external TCP/443 is
	// forwarded to it so TLS-ALPN-01 ACME challenges still reach the process.
	listenAddrEnv     = "LISTEN_ADDR"
	listenAddrDefault = ":443"

	// certStoragePathEnv overrides the directory where CertMagic stores the
	// ACME account key and issued certificates. Defaults to certStoragePathDefault.
	// Operators running in read-only filesystems (e.g. distroless containers)
	// must point this at a writable volume.
	certStoragePathEnv     = "CERT_STORAGE_PATH"
	certStoragePathDefault = "./certmagic-storage"

	// connectPortsEnv is a comma-separated allow-list of TCP ports the proxy
	// permits as CONNECT targets. Defaults to "443" (HTTPS only).
	connectPortsEnv     = "CONNECT_ALLOWED_PORTS"
	connectPortsDefault = "443"
)

var httpProxyTransport = &http.Transport{
	Proxy: nil,

	DialContext: safeDialContext,

	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   20,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
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

// extraBlockedCIDRs lists ranges that Go's net.IP helpers do not classify
// as private/loopback/link-local but which the proxy still refuses to
// forward to. Notably:
//   - 100.64.0.0/10  RFC 6598 carrier-grade NAT (often used for cloud
//     management networks and internal load balancers)
//   - 192.0.0.0/24   RFC 6890 IETF protocol assignments
//   - 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24  TEST-NET docs
//   - 198.18.0.0/15  RFC 2544 benchmark
//   - 255.255.255.255/32  limited broadcast
var extraBlockedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"100.64.0.0/10",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"255.255.255.255/32",
		"2001:db8::/32",
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, s := range cidrs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic(fmt.Sprintf("invalid built-in CIDR %q: %v", s, err))
		}
		out = append(out, n)
	}
	return out
}()

// isBlockedIP reports whether ip is in a range the proxy refuses to
// forward to. Blocking these ranges prevents SSRF pivoting into the
// host's loopback interface, RFC1918/ULA networks, link-local ranges
// (including cloud metadata at 169.254.169.254 and fe80::/10), CGNAT
// (100.64.0.0/10), and unspecified/multicast destinations.
//
// IPv4-mapped IPv6 addresses (::ffff:0:0/96) are unwrapped to their
// underlying IPv4 form before classification so they cannot be used to
// smuggle a private IPv4 destination through an IPv6 literal.
//
// Declared as a var so tests that need to dial loopback fixtures can
// override it. Production code never reassigns it.
var isBlockedIP = func(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
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
	for _, n := range extraBlockedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func main() {
	if err := run(); err != nil {
		slog.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}

func run() error {
	acmeDomains := configuredACMEDomains()
	listenAddr := configuredListenAddr()

	allowedPorts, err := configuredConnectPorts()
	if err != nil {
		return fmt.Errorf("invalid %s: %w", connectPortsEnv, err)
	}

	var tlsConfig *tls.Config

	if len(acmeDomains) == 0 {
		slog.Info("ACME_DOMAIN not set; using auto-generated self-signed certificate")

		cfg, err := selfSignedTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to generate self-signed certificate: %w", err)
		}
		tlsConfig = cfg
	} else {
		acmeEmail, err := configuredACMEEmail()
		if err != nil {
			return fmt.Errorf("invalid ACME configuration: %w", err)
		}

		cfg, err := managedTLSConfig(acmeDomains, acmeEmail)
		if err != nil {
			return fmt.Errorf("failed to manage certificate for %s: %w", strings.Join(acmeDomains, ","), err)
		}
		tlsConfig = cfg

		slog.Info("HTTPS proxy listening",
			"url", "https://"+listenerHostPort(acmeDomains[0], listenAddr),
			"domains", acmeDomains,
		)
	}

	handler := newProxyHandler(allowedPorts)

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// WriteTimeout is intentionally unset: long-lived CONNECT tunnels
		// would otherwise be killed mid-stream.
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MiB
		TLSConfig:      tlsConfig,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErr := make(chan error, 1)
	go func() {
		err := server.ListenAndServeTLS("", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received; draining connections")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("graceful shutdown failed", "err", err)
		}
		// Wait for the serve goroutine to finish so we don't return while
		// it may still be writing to the server's TLS listener.
		<-serverErr
		return nil
	case err := <-serverErr:
		return err
	}
}

// configuredACMEDomains returns the list of DNS names or IP addresses
// the ACME certificate should cover. The ACME_DOMAIN environment
// variable holds a comma-separated list (e.g.
// "proxy.example.com,www.proxy.example.com"). Whitespace and empty
// entries are ignored, and bracketed IPv6 literals are unwrapped per
// entry. Returns nil when the variable is unset or contains only empty
// values, which selects self-signed mode.
func configuredACMEDomains() []string {
	raw := strings.TrimSpace(os.Getenv(acmeDomainEnv))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		p = strings.Trim(strings.TrimSpace(p), "[]")
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
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

// configuredCertStoragePath returns the absolute path where CertMagic
// should store account keys and issued certificates. It reads the
// CERT_STORAGE_PATH environment variable and falls back to a default
// directory beside the binary.
func configuredCertStoragePath() (string, error) {
	p := strings.TrimSpace(os.Getenv(certStoragePathEnv))
	if p == "" {
		p = certStoragePathDefault
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("resolving %s=%q: %w", certStoragePathEnv, p, err)
	}
	return abs, nil
}

// configuredConnectPorts returns the set of TCP ports the proxy is willing
// to tunnel via CONNECT. The CONNECT_ALLOWED_PORTS env var contains a
// comma-separated list; whitespace and empty entries are ignored. Each
// entry must be a decimal integer in the valid TCP range.
func configuredConnectPorts() (map[string]struct{}, error) {
	raw := strings.TrimSpace(os.Getenv(connectPortsEnv))
	if raw == "" {
		raw = connectPortsDefault
	}
	out := make(map[string]struct{})
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := parsePort(p)
		if err != nil {
			return nil, err
		}
		out[fmt.Sprintf("%d", n)] = struct{}{}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports configured")
	}
	return out, nil
}

func parsePort(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty port")
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid port %q", s)
		}
		n = n*10 + int(c-'0')
		if n > 65535 {
			return 0, fmt.Errorf("invalid port %q", s)
		}
	}
	if n < 1 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return n, nil
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

func managedTLSConfig(acmeDomains []string, acmeEmail string) (*tls.Config, error) {
	if len(acmeDomains) == 0 {
		return nil, fmt.Errorf("no ACME domains configured")
	}
	storagePath, err := configuredCertStoragePath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(storagePath, 0700); err != nil {
		return nil, fmt.Errorf("could not create CertMagic storage directory %q: %w", storagePath, err)
	}

	certmagic.Default.Storage = &certmagic.FileStorage{
		Path: storagePath,
	}

	certmagic.DefaultACME.Email = acmeEmail
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA

	magic := certmagic.NewDefault()

	if err := magic.ManageSync(context.Background(), acmeDomains); err != nil {
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

// newProxyHandler returns an http.Handler that authenticates inbound
// requests and dispatches CONNECT vs plain-HTTP traffic. allowedPorts
// is the set of TCP ports the proxy is willing to tunnel via CONNECT;
// all other ports are rejected with 403 Forbidden.
func newProxyHandler(allowedPorts map[string]struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			w.Header().Set("Proxy-Authenticate", `Basic realm="go-https-proxy"`)
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}

		switch r.Method {
		case http.MethodConnect:
			handleConnect(w, r, allowedPorts)
		default:
			handlePlainHTTP(w, r)
		}
	})
}

// proxyHandler is the package-default handler used by tests. It permits
// CONNECT to port 443 only, mirroring the historical behavior.
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	newProxyHandler(map[string]struct{}{"443": {}}).ServeHTTP(w, r)
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

	// Require a non-empty user and non-empty password. RFC 7617 forbids
	// `:` in the userid; the first colon delimits the two fields.
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

func handleConnect(w http.ResponseWriter, r *http.Request, allowedPorts map[string]struct{}) {
	target := r.Host

	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		http.Error(w, "bad CONNECT target", http.StatusBadRequest)
		return
	}

	// Reject hostnames containing characters that would confuse downstream
	// parsing (zone IDs, control bytes). net.SplitHostPort already strips
	// brackets from IPv6 literals.
	if strings.ContainsAny(host, "%\x00") {
		http.Error(w, "bad CONNECT target", http.StatusBadRequest)
		return
	}

	if _, ok := allowedPorts[port]; !ok {
		http.Error(w, "CONNECT to this port is not allowed", http.StatusForbidden)
		return
	}

	dstConn, err := safeDial(r.Context(), "tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		if errors.Is(err, errBlockedAddress) {
			slog.Warn("CONNECT blocked", "target", target, "err", err)
			http.Error(w, "target address is not allowed", http.StatusForbidden)
			return
		}
		http.Error(w, "failed to connect to target", http.StatusBadGateway)
		return
	}
	defer dstConn.Close() //nolint:errcheck

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
	defer clientConn.Close() //nolint:errcheck

	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		slog.Warn("CONNECT write 200 failed", "target", target, "err", err)
		return
	}
	if err := buffered.Flush(); err != nil {
		slog.Warn("CONNECT flush 200 failed", "target", target, "err", err)
		return
	}

	// Any bytes the client pipelined immediately after the CONNECT request
	// (typically the TLS ClientHello) may already sit in the bufio.Reader.
	// Forward them to the destination before splice-copying from the raw
	// connection, otherwise they would be silently dropped.
	if n := buffered.Reader.Buffered(); n > 0 {
		if _, err := io.CopyN(dstConn, buffered.Reader, int64(n)); err != nil {
			slog.Warn("CONNECT drain buffered client bytes failed", "target", target, "err", err)
			return
		}
	}

	slog.Info("CONNECT", "target", target)

	// Splice both directions and wait for BOTH to finish before returning.
	// The first goroutine to exit calls SetDeadline on both ends so that
	// the peer goroutine's blocked Read unblocks promptly. Waiting for
	// both ensures we don't close the underlying connections while the
	// other direction is still writing in-flight bytes.
	errCh := make(chan error, 2)
	go func() { errCh <- proxyCopy(dstConn, clientConn) }()
	go func() { errCh <- proxyCopy(clientConn, dstConn) }()
	<-errCh
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
			slog.Warn("HTTP request blocked", "method", r.Method, "url", r.URL.String(), "err", err)
			http.Error(w, "target address is not allowed", http.StatusForbidden)
			return
		}
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close() //nolint:errcheck

	removeHopByHopHeaders(resp.Header)

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	if _, err := io.Copy(w, resp.Body); err != nil {
		slog.Warn("response body copy failed", "method", r.Method, "url", r.URL.String(), "status", resp.StatusCode, "err", err)
		return
	}

	slog.Info("HTTP proxy request", "method", r.Method, "url", r.URL.String(), "status", resp.StatusCode)
}

// proxyCopy splices data from src to dst. When src reports EOF, it
// propagates a half-close to dst (via CloseWrite if available) so the
// peer of the other copy direction observes EOF and finishes its own
// io.Copy naturally. On any non-EOF error it sets immediate deadlines
// on both sides so the sibling goroutine unblocks. Returns the
// underlying error (nil on a clean EOF).
func proxyCopy(dst net.Conn, src net.Conn) error {
	_, err := io.Copy(dst, src)
	if err == nil {
		// Clean EOF on the read side. Half-close the write side of dst
		// to forward EOF without disturbing the other direction.
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
			return nil
		}
	}
	// Error path (or no half-close support): force the sibling to
	// unblock by tripping read/write deadlines. The deferred Close()
	// in handleConnect tears the connections down once both copies
	// have returned.
	_ = dst.SetDeadline(time.Now())
	_ = src.SetDeadline(time.Now())
	return err
}

// closeWriter is implemented by *net.TCPConn and *tls.Conn for clean
// TCP half-close semantics.
type closeWriter interface {
	CloseWrite() error
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
