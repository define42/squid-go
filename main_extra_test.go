package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// allowAllIPs overrides the SSRF filter for the duration of a test so
// fixtures listening on loopback can be dialed through the real proxy
// code paths. It restores the original filter on cleanup.
func allowAllIPs(t *testing.T) {
	t.Helper()
	orig := isBlockedIP
	isBlockedIP = func(net.IP) bool { return false }
	t.Cleanup(func() { isBlockedIP = orig })
}

// startTCPFixture starts a loopback TCP listener and runs serve for each
// accepted connection. The listener is closed on test cleanup.
func startTCPFixture(t *testing.T, serve func(net.Conn)) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fixture: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
	return ln.Addr()
}

// --- run() ---

// runInBackground invokes run in a goroutine and returns the channel its
// result is delivered on.
func runInBackground() <-chan error {
	errCh := make(chan error, 1)
	go func() { errCh <- run() }()
	return errCh
}

func waitRunResult(t *testing.T, errCh <-chan error) error {
	t.Helper()
	select {
	case err := <-errCh:
		return err
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not return in time")
		return nil
	}
}

func TestRun_SelfSignedGracefulShutdown(t *testing.T) {
	t.Setenv(acmeDomainEnv, "")
	t.Setenv(listenAddrEnv, "127.0.0.1:0")
	t.Setenv(httpListenAddrEnv, "127.0.0.1:0")
	t.Setenv(noAuthCIDRsEnv, "127.0.0.1")
	t.Setenv(connectPortsEnv, "")
	t.Setenv(proxyAuthEnv, "")

	errCh := runInBackground()

	// Give run() time to install its signal handler and start both
	// listeners, then deliver SIGTERM to trigger the graceful path.
	time.Sleep(500 * time.Millisecond)
	select {
	case err := <-errCh:
		// Bail out before SIGTERM: with run() gone no handler is
		// installed and the signal would kill the test binary.
		t.Fatalf("run() exited early: %v", err)
	default:
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("kill: %v", err)
	}

	if err := waitRunResult(t, errCh); err != nil {
		t.Fatalf("run() = %v, want nil after graceful shutdown", err)
	}
}

func TestRun_InvalidConnectPorts(t *testing.T) {
	t.Setenv(connectPortsEnv, "not-a-port")

	if err := run(); err == nil || !strings.Contains(err.Error(), connectPortsEnv) {
		t.Fatalf("run() = %v, want %s error", err, connectPortsEnv)
	}
}

func TestRun_InvalidNoAuthCIDRs(t *testing.T) {
	t.Setenv(connectPortsEnv, "")
	t.Setenv(noAuthCIDRsEnv, "not-an-ip")

	if err := run(); err == nil || !strings.Contains(err.Error(), noAuthCIDRsEnv) {
		t.Fatalf("run() = %v, want %s error", err, noAuthCIDRsEnv)
	}
}

func TestRun_ACMEMissingEmail(t *testing.T) {
	t.Setenv(connectPortsEnv, "")
	t.Setenv(noAuthCIDRsEnv, "")
	t.Setenv(acmeDomainEnv, "proxy.example.com")
	t.Setenv(acmeEmailEnv, "")

	if err := run(); err == nil || !strings.Contains(err.Error(), "invalid ACME configuration") {
		t.Fatalf("run() = %v, want invalid ACME configuration error", err)
	}
}

func TestRun_ACMECertStorageFailure(t *testing.T) {
	// Point CERT_STORAGE_PATH below a regular file so MkdirAll fails
	// before any ACME network activity can start.
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	t.Setenv(connectPortsEnv, "")
	t.Setenv(noAuthCIDRsEnv, "")
	t.Setenv(acmeDomainEnv, "proxy.example.com")
	t.Setenv(acmeEmailEnv, "ops@proxy-operator.test")
	t.Setenv(certStoragePathEnv, filepath.Join(file, "storage"))

	if err := run(); err == nil || !strings.Contains(err.Error(), "failed to manage certificate") {
		t.Fatalf("run() = %v, want certificate management error", err)
	}
}

func TestRun_SelfSignedCertFailure(t *testing.T) {
	t.Setenv(connectPortsEnv, "")
	t.Setenv(noAuthCIDRsEnv, "")
	t.Setenv(acmeDomainEnv, "")

	orig := rand.Reader
	rand.Reader = &limitedEntropyReader{orig: orig}
	defer func() { rand.Reader = orig }()

	if err := run(); err == nil || !strings.Contains(err.Error(), "self-signed certificate") {
		t.Fatalf("run() = %v, want self-signed certificate error", err)
	}
}

func TestRun_TLSListenFailure(t *testing.T) {
	// Occupy a port so the TLS listener cannot bind it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	t.Setenv(connectPortsEnv, "")
	t.Setenv(noAuthCIDRsEnv, "")
	t.Setenv(acmeDomainEnv, "")
	t.Setenv(listenAddrEnv, ln.Addr().String())
	t.Setenv(httpListenAddrEnv, "127.0.0.1:0")

	if err := waitRunResult(t, runInBackground()); err == nil {
		t.Fatal("run() = nil, want listen error for occupied TLS address")
	}
}

func TestRun_HTTPListenFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	t.Setenv(connectPortsEnv, "")
	t.Setenv(noAuthCIDRsEnv, "")
	t.Setenv(acmeDomainEnv, "")
	t.Setenv(listenAddrEnv, "127.0.0.1:0")
	t.Setenv(httpListenAddrEnv, ln.Addr().String())

	if err := waitRunResult(t, runInBackground()); err == nil {
		t.Fatal("run() = nil, want listen error for occupied HTTP address")
	}
}

// --- managedTLSConfig ---

func TestManagedTLSConfig_NoDomains(t *testing.T) {
	if _, err := managedTLSConfig(nil, "ops@proxy-operator.test"); err == nil {
		t.Fatal("managedTLSConfig(nil domains) = nil error, want error")
	}
}

func TestManagedTLSConfig_StorageDirIsFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	t.Setenv(certStoragePathEnv, filepath.Join(file, "storage"))

	_, err := managedTLSConfig([]string{"proxy.example.com"}, "ops@proxy-operator.test")
	if err == nil || !strings.Contains(err.Error(), "storage directory") {
		t.Fatalf("managedTLSConfig() = %v, want storage directory error", err)
	}
}

func TestManagedTLSConfig_StoragePathError(t *testing.T) {
	chdirToDeletedDir(t)
	t.Setenv(certStoragePathEnv, "relative/storage")

	if _, err := managedTLSConfig([]string{"proxy.example.com"}, "ops@proxy-operator.test"); err == nil {
		t.Fatal("managedTLSConfig() = nil error, want storage path resolution error")
	}
}

// chdirToDeletedDir switches the working directory to a directory that is
// then removed, so os.Getwd (and thus filepath.Abs on relative paths)
// fails for the remainder of the test.
func chdirToDeletedDir(t *testing.T) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "gone")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Chdir(dir)
	if err := os.Remove(dir); err != nil {
		t.Fatalf("remove cwd: %v", err)
	}
	if _, err := os.Getwd(); err == nil {
		t.Skip("os.Getwd still succeeds in deleted directory on this platform")
	}
}

func TestConfiguredCertStoragePath_AbsError(t *testing.T) {
	chdirToDeletedDir(t)
	t.Setenv(certStoragePathEnv, "relative/storage")

	if _, err := configuredCertStoragePath(); err == nil {
		t.Fatal("configuredCertStoragePath() = nil error, want resolution error")
	}
}

// --- handleConnect through the real handler ---

// TestHandleConnect_EndToEndTunnel drives a CONNECT request through the
// real newProxyHandler/handleConnect path (with the SSRF filter opened
// for loopback) and verifies pipelined client bytes are drained to the
// destination and the destination's reply is spliced back.
func TestHandleConnect_EndToEndTunnel(t *testing.T) {
	allowAllIPs(t)

	const clientPayload = "HELLO-VIA-TUNNEL"
	const dstReply = "REPLY-FROM-DEST"

	dstAddr := startTCPFixture(t, func(c net.Conn) {
		defer c.Close() //nolint:errcheck
		buf := make([]byte, len(clientPayload))
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != clientPayload {
			return
		}
		_, _ = c.Write([]byte(dstReply))
		if tcp, ok := c.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		_, _ = io.Copy(io.Discard, c)
	})

	setAuthEnv(t, sha256Hex(testProxyUser, testProxyPass))
	handler := newProxyHandler(map[string]struct{}{connectPortsAll: {}}, allowedAuthHashes(), nil, "")

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	defer proxyLn.Close() //nolint:errcheck
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(proxyLn) }()
	defer srv.Close() //nolint:errcheck

	conn, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Pipeline the CONNECT request and the first payload bytes in one
	// write so the payload is parked in the server-side bufio.Reader and
	// must be drained by handleConnect.
	req := "CONNECT " + dstAddr.String() + " HTTP/1.1\r\n" +
		"Host: " + dstAddr.String() + "\r\n" +
		"Proxy-Authorization: " + basicAuthHeader(testProxyUser, testProxyPass) + "\r\n" +
		"\r\n" + clientPayload
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write connect: %v", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	got := make([]byte, len(dstReply))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read tunneled reply: %v", err)
	}
	if string(got) != dstReply {
		t.Fatalf("tunneled reply = %q, want %q", got, dstReply)
	}
}

func TestHandleConnect_HijackUnsupported(t *testing.T) {
	allowAllIPs(t)

	dstAddr := startTCPFixture(t, func(c net.Conn) {
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
	})

	req := httptest.NewRequest(http.MethodConnect, "http://"+dstAddr.String(), nil)
	req.Host = dstAddr.String()
	// httptest.ResponseRecorder does not implement http.Hijacker.
	rec := httptest.NewRecorder()

	handleConnect(rec, req, map[string]struct{}{connectPortsAll: {}})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if !strings.Contains(rec.Body.String(), "hijacking not supported") {
		t.Fatalf("body = %q, want hijacking not supported", rec.Body.String())
	}
}

// hijackRecorder implements http.Hijacker on top of a ResponseRecorder,
// returning either a scripted error or a caller-supplied connection and
// buffered read/writer.
type hijackRecorder struct {
	*httptest.ResponseRecorder
	conn      net.Conn
	rw        *bufio.ReadWriter
	hijackErr error
}

func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h.hijackErr != nil {
		return nil, nil, h.hijackErr
	}
	return h.conn, h.rw, nil
}

// failingWriter always refuses writes.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write refused") }

func TestHandleConnect_HijackFails(t *testing.T) {
	allowAllIPs(t)

	dstAddr := startTCPFixture(t, func(c net.Conn) {
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
	})

	req := httptest.NewRequest(http.MethodConnect, "http://"+dstAddr.String(), nil)
	req.Host = dstAddr.String()
	rec := &hijackRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		hijackErr:        errors.New("hijack refused"),
	}

	handleConnect(rec, req, map[string]struct{}{connectPortsAll: {}})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if !strings.Contains(rec.Body.String(), "failed to hijack") {
		t.Fatalf("body = %q, want hijack failure", rec.Body.String())
	}
}

func TestHandleConnect_Write200Fails(t *testing.T) {
	allowAllIPs(t)

	dstAddr := startTCPFixture(t, func(c net.Conn) {
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
	})

	client, peer := net.Pipe()
	defer client.Close() //nolint:errcheck
	defer peer.Close()   //nolint:errcheck

	req := httptest.NewRequest(http.MethodConnect, "http://"+dstAddr.String(), nil)
	req.Host = dstAddr.String()
	rec := &hijackRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             client,
		// A one-byte write buffer forces WriteString to flush through to
		// the failing writer immediately.
		rw: bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriterSize(failingWriter{}, 1)),
	}

	// Must return (after logging) without panicking; nothing is written
	// to the recorder because the connection is already hijacked.
	handleConnect(rec, req, map[string]struct{}{connectPortsAll: {}})
}

func TestHandleConnect_Flush200Fails(t *testing.T) {
	allowAllIPs(t)

	dstAddr := startTCPFixture(t, func(c net.Conn) {
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
	})

	client, peer := net.Pipe()
	defer client.Close() //nolint:errcheck
	defer peer.Close()   //nolint:errcheck

	req := httptest.NewRequest(http.MethodConnect, "http://"+dstAddr.String(), nil)
	req.Host = dstAddr.String()
	rec := &hijackRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             client,
		// The buffer is large enough to hold the 200 response, so the
		// write succeeds and only the explicit Flush hits the error.
		rw: bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriterSize(failingWriter{}, 128)),
	}

	handleConnect(rec, req, map[string]struct{}{connectPortsAll: {}})
}

func TestHandleConnect_RejectsPercentInBracketedHost(t *testing.T) {
	// net.SplitHostPort accepts a zone ID inside brackets, so this must
	// be caught by handleConnect's own host character check.
	req := httptest.NewRequest(http.MethodConnect, "http://example.com", nil)
	req.Host = "[fe80::1%eth0]:443"
	rec := httptest.NewRecorder()

	handleConnect(rec, req, map[string]struct{}{"443": {}})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// --- handlePlainHTTP error paths ---

func TestHandlePlainHTTP_UpstreamDialFailure(t *testing.T) {
	// The reserved .invalid TLD never resolves (trailing dot avoids
	// search-domain expansion), so RoundTrip fails without a blocked
	// address, which must surface as 502.
	req := httptest.NewRequest(http.MethodGet, "http://nonexistent-host.invalid./", nil)
	rec := httptest.NewRecorder()

	handlePlainHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

func TestHandlePlainHTTP_BodyCopyFailure(t *testing.T) {
	allowAllIPs(t)

	// Origin promises 500 body bytes but sends only a few, then slams
	// the connection so the proxy's body copy fails mid-stream.
	originAddr := startTCPFixture(t, func(c net.Conn) {
		defer c.Close() //nolint:errcheck
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\npartial")
	})

	req := httptest.NewRequest(http.MethodGet, "http://"+originAddr.String()+"/", nil)
	rec := httptest.NewRecorder()

	handlePlainHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with truncated body", rec.Code)
	}
	if got := rec.Body.String(); got != "partial" {
		t.Fatalf("body = %q, want %q", got, "partial")
	}
}

// --- proxyCopy without CloseWrite support ---

func TestProxyCopy_NoCloseWriter(t *testing.T) {
	// net.Pipe connections do not implement CloseWrite, so a clean EOF
	// must fall through to the deadline-tripping path and return nil.
	srcA, srcB := net.Pipe()
	dstA, dstB := net.Pipe()
	defer srcA.Close() //nolint:errcheck
	defer dstA.Close() //nolint:errcheck
	defer dstB.Close() //nolint:errcheck

	_ = srcB.Close() // immediate EOF on the read side

	if err := proxyCopy(dstA, srcA); err != nil {
		t.Fatalf("proxyCopy() = %v, want nil on clean EOF", err)
	}
}

// --- resolveSafeIP / safeDial small branches ---

func TestResolveSafeIP_AllResolvedBlocked(t *testing.T) {
	// localhost resolves via the hosts file to loopback only, so every
	// candidate address is rejected.
	_, err := resolveSafeIP(context.Background(), "localhost")
	if !errors.Is(err, errBlockedAddress) {
		t.Fatalf("resolveSafeIP(localhost) error = %v, want errBlockedAddress", err)
	}
}

func TestResolveSafeIP_LookupFailure(t *testing.T) {
	_, err := resolveSafeIP(context.Background(), "nonexistent-host.invalid.")
	if err == nil {
		t.Fatal("resolveSafeIP() = nil error, want lookup failure")
	}
	if errors.Is(err, errBlockedAddress) {
		t.Fatalf("resolveSafeIP() error = %v, want plain lookup failure", err)
	}
}

func TestSafeDial_InvalidAddress(t *testing.T) {
	if _, err := safeDial(context.Background(), "tcp", "missing-port", time.Second); err == nil {
		t.Fatal("safeDial() = nil error, want host:port split failure")
	}
}

func TestIsBlockedIP_Nil(t *testing.T) {
	if !isBlockedIP(nil) {
		t.Fatal("isBlockedIP(nil) = false, want true")
	}
}

// --- configuration edge cases ---

func TestConfiguredACMEDomains_OnlyEmptyEntries(t *testing.T) {
	t.Setenv(acmeDomainEnv, " ,  , ")
	if got := configuredACMEDomains(); got != nil {
		t.Fatalf("configuredACMEDomains() = %v, want nil", got)
	}
}

func TestConfiguredConnectPorts_AllSentinel(t *testing.T) {
	t.Setenv(connectPortsEnv, " ALL ")
	got, err := configuredConnectPorts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := got[connectPortsAll]; !ok || len(got) != 1 {
		t.Fatalf("ports = %v, want all-ports sentinel", got)
	}
}

func TestConfiguredConnectPorts_OnlySeparators(t *testing.T) {
	t.Setenv(connectPortsEnv, " , ,")
	if _, err := configuredConnectPorts(); err == nil {
		t.Fatal("configuredConnectPorts() = nil error, want no ports configured")
	}
}

func TestParsePort_Empty(t *testing.T) {
	if _, err := parsePort(""); err == nil {
		t.Fatal("parsePort(\"\") = nil error, want error")
	}
}

func TestListenAddrPort_NoPort(t *testing.T) {
	if got := listenAddrPort("localhost"); got != "" {
		t.Fatalf("listenAddrPort(%q) = %q, want \"\"", "localhost", got)
	}
}

func TestAuthorized_LengthMismatchHash(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Proxy-Authorization", basicAuthHeader(testProxyUser, testProxyPass))

	// A configured digest of the wrong length must be skipped without
	// authorizing the request.
	if authorized(req, []string{"deadbeef"}) {
		t.Fatal("authorized() = true for wrong-length digest, want false")
	}
}

// --- selfSignedTLSConfig entropy failures ---

// limitedEntropyReader serves at most budget bytes from the real random
// source, then fails, letting tests trigger the error returns inside
// selfSignedTLSConfig at whichever stage exhausts the budget.
type limitedEntropyReader struct {
	orig   io.Reader
	budget int
}

func (l *limitedEntropyReader) Read(p []byte) (int, error) {
	if len(p) > l.budget {
		return 0, errors.New("entropy exhausted")
	}
	n, err := l.orig.Read(p)
	l.budget -= n
	return n, err
}

func TestSelfSignedTLSConfig_EntropyFailures(t *testing.T) {
	orig := rand.Reader
	defer func() { rand.Reader = orig }()

	// Budget 0 deterministically fails key generation. Increasing
	// budgets walk the failure point through serial-number generation
	// and certificate signing until the whole config succeeds.
	sawError := false
	succeeded := false
	for budget := 0; budget <= 4096; budget += 8 {
		rand.Reader = &limitedEntropyReader{orig: orig, budget: budget}
		cfg, err := selfSignedTLSConfig()
		if err != nil {
			sawError = true
			continue
		}
		if len(cfg.Certificates) != 1 {
			t.Fatalf("config has %d certificates, want 1", len(cfg.Certificates))
		}
		succeeded = true
		break
	}
	if !sawError {
		t.Fatal("no entropy budget produced an error")
	}
	if !succeeded {
		t.Fatal("selfSignedTLSConfig never succeeded within the tested budgets")
	}
}
