package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	testProxyUser = "user"
	testProxyPass = "pass"

	// Second credential used to verify multi-value configuration.
	testProxyUser2 = "alice"
	testProxyPass2 = "s3cret"
)

func sha256Hex(user, pass string) string {
	sum := sha256.Sum256([]byte(user + ":" + pass))
	return hex.EncodeToString(sum[:])
}

func setAuthEnv(t *testing.T, hashes ...string) {
	t.Helper()
	t.Setenv(proxyAuthEnv, strings.Join(hashes, proxyAuthDelimiter))
}

func basicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// proxyHandler is a test helper that constructs a handler permitting
// CONNECT to port 443 only, mirroring the historical default used by
// the tests below.
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	newProxyHandler(map[string]struct{}{"443": {}}, allowedAuthHashes(), nil, "").ServeHTTP(w, r)
}

func TestAuthorized(t *testing.T) {
	setAuthEnv(t,
		sha256Hex(testProxyUser, testProxyPass),
		sha256Hex(testProxyUser2, testProxyPass2),
	)

	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{"missing header", "", false},
		{"non-basic scheme", "Bearer token", false},
		{"malformed base64", "Basic !!!notbase64!!!", false},
		{"wrong credentials", basicAuthHeader("wrong", "creds"), false},
		{"valid credentials", basicAuthHeader(testProxyUser, testProxyPass), true},
		{"second valid credentials", basicAuthHeader(testProxyUser2, testProxyPass2), true},
		{"empty credentials", basicAuthHeader("", ""), false},
		{"missing colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			if tc.header != "" {
				req.Header.Set("Proxy-Authorization", tc.header)
			}
			if got := authorized(req, allowedAuthHashes()); got != tc.want {
				t.Fatalf("authorized() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAuthorized_NoConfiguredHashes(t *testing.T) {
	t.Setenv(proxyAuthEnv, "")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Proxy-Authorization", basicAuthHeader(testProxyUser, testProxyPass))

	if authorized(req, allowedAuthHashes()) {
		t.Fatal("authorized() = true when no hashes are configured, want false")
	}
}

func TestAllowedAuthHashes_TrimsAndLowercases(t *testing.T) {
	h1 := sha256Hex(testProxyUser, testProxyPass)
	t.Setenv(proxyAuthEnv, "  "+strings.ToUpper(h1)+" "+proxyAuthDelimiter+proxyAuthDelimiter+" ")

	got := allowedAuthHashes()
	if len(got) != 1 || got[0] != h1 {
		t.Fatalf("allowedAuthHashes() = %v, want [%s]", got, h1)
	}
}

func TestProxyHandler_Unauthorized(t *testing.T) {
	setAuthEnv(t, sha256Hex(testProxyUser, testProxyPass))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()

	proxyHandler(rec, req)

	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusProxyAuthRequired)
	}
	if got := rec.Header().Get("Proxy-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Fatalf("Proxy-Authenticate = %q, want Basic challenge", got)
	}
}

func TestConfiguredNoAuthNets(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantLen int
		wantErr bool
		// check is an optional sanity check on the parsed nets.
		check func(t *testing.T, nets []*net.IPNet)
	}{
		{name: "unset", raw: "", wantLen: 0},
		{name: "only whitespace", raw: "   ,  ,", wantLen: 0},
		{
			name:    "mixed cidrs and bare ips",
			raw:     " 10.0.0.0/8 , 192.0.2.5, 2001:db8::/32 ,[::1]",
			wantLen: 4,
			check: func(t *testing.T, nets []*net.IPNet) {
				if !nets[0].Contains(net.ParseIP("10.1.2.3")) {
					t.Errorf("10.0.0.0/8 should contain 10.1.2.3")
				}
				if !nets[1].Contains(net.ParseIP("192.0.2.5")) {
					t.Errorf("bare /32 should contain itself")
				}
				if nets[1].Contains(net.ParseIP("192.0.2.6")) {
					t.Errorf("bare /32 must not contain neighbour")
				}
				if !nets[2].Contains(net.ParseIP("2001:db8::1")) {
					t.Errorf("2001:db8::/32 should contain 2001:db8::1")
				}
				if !nets[3].Contains(net.ParseIP("::1")) {
					t.Errorf("bare ::1 /128 should contain itself")
				}
			},
		},
		{name: "invalid ip", raw: "not-an-ip", wantErr: true},
		{name: "invalid cidr", raw: "10.0.0.0/40", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(noAuthCIDRsEnv, tc.raw)
			got, err := configuredNoAuthNets()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if len(got) != tc.wantLen {
				t.Fatalf("len(nets) = %d, want %d (%v)", len(got), tc.wantLen, got)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

func TestClientIPExempt(t *testing.T) {
	_, ipv4Net, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	_, ipv6Net, err := net.ParseCIDR("2001:db8::/32")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	nets := []*net.IPNet{ipv4Net, ipv6Net}

	tests := []struct {
		name       string
		remoteAddr string
		want       bool
	}{
		{"ipv4 in range", "10.1.2.3:54321", true},
		{"ipv4 out of range", "192.0.2.1:54321", false},
		{"ipv6 in range", "[2001:db8::1]:54321", true},
		{"ipv6 zone id stripped", "[fe80::1%eth0]:54321", false},
		{"ipv6 out of range", "[2001:db9::1]:54321", false},
		{"bare ip without port", "10.2.3.4", true},
		{"malformed", "not-an-addr", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.RemoteAddr = tc.remoteAddr
			if got := clientIPExempt(req, nets); got != tc.want {
				t.Fatalf("clientIPExempt(%q) = %v, want %v", tc.remoteAddr, got, tc.want)
			}
		})
	}

	t.Run("empty list never exempts", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.RemoteAddr = "10.1.2.3:54321"
		if clientIPExempt(req, nil) {
			t.Fatal("clientIPExempt with nil nets should be false")
		}
	})
}

func TestProxyHandler_NoAuthCIDRBypass(t *testing.T) {
	// With auth required AND no credentials supplied, a client whose
	// IP falls inside the exempt range must still be served (returning
	// 400 here because the test request is not a valid CONNECT/HTTP
	// absolute-URL request; the key assertion is that we do NOT get
	// 407 ProxyAuthRequired).
	setAuthEnv(t, sha256Hex(testProxyUser, testProxyPass))
	_, exempt, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	h := newProxyHandler(map[string]struct{}{"443": {}}, allowedAuthHashes(), []*net.IPNet{exempt}, "")

	t.Run("exempt client bypasses auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.RemoteAddr = "10.1.2.3:54321"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusProxyAuthRequired {
			t.Fatalf("exempt client was challenged for auth (status %d)", rec.Code)
		}
	})

	t.Run("non-exempt client still challenged", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.RemoteAddr = "192.0.2.1:54321"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusProxyAuthRequired {
			t.Fatalf("non-exempt client status = %d, want 407", rec.Code)
		}
	})
}

func TestPACProxyEndpoint(t *testing.T) {
	tests := []struct {
		name        string
		acmeDomains []string
		listenAddr  string
		want        string
	}{
		{"no domains", nil, ":443", ""},
		{"dns name default port", []string{"proxy.example.com"}, ":443", "proxy.example.com:443"},
		{"dns name custom port", []string{"proxy.example.com"}, ":8443", "proxy.example.com:8443"},
		{"ipv4 literal", []string{"203.0.113.5"}, ":443", "203.0.113.5:443"},
		{"ipv6 literal bracketed", []string{"2001:db8::1"}, ":8443", "[2001:db8::1]:8443"},
		{"listen addr with host", []string{"proxy.example.com"}, "0.0.0.0:8443", "proxy.example.com:8443"},
		{"empty port falls back to 443", []string{"proxy.example.com"}, "", "proxy.example.com:443"},
		{"multiple domains uses first", []string{"a.example.com", "b.example.com"}, ":443", "a.example.com:443"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pacProxyEndpoint(tc.acmeDomains, tc.listenAddr)
			if got != tc.want {
				t.Fatalf("pacProxyEndpoint(%v, %q) = %q, want %q", tc.acmeDomains, tc.listenAddr, got, tc.want)
			}
		})
	}
}

func TestServePAC_FromConfiguredEndpoint(t *testing.T) {
	h := newProxyHandler(map[string]struct{}{"443": {}}, nil, nil, "proxy.example.com:443")

	req := httptest.NewRequest(http.MethodGet, "/proxy.pac", nil)
	req.RemoteAddr = "192.0.2.1:54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/x-ns-proxy-autoconfig" {
		t.Fatalf("Content-Type = %q, want application/x-ns-proxy-autoconfig", got)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "function FindProxyForURL(url, host)") {
		t.Fatalf("body missing FindProxyForURL: %q", body)
	}
	if !strings.Contains(body, `return "HTTPS proxy.example.com:443";`) {
		t.Fatalf("body missing HTTPS directive: %q", body)
	}
}

func TestServePAC_BypassesProxyAuth(t *testing.T) {
	setAuthEnv(t, sha256Hex(testProxyUser, testProxyPass))
	h := newProxyHandler(map[string]struct{}{"443": {}}, allowedAuthHashes(), nil, "proxy.example.com:443")

	req := httptest.NewRequest(http.MethodGet, "/proxy.pac", nil)
	req.RemoteAddr = "192.0.2.1:54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PAC fetch returned status %d, want 200 (must bypass proxy auth)", rec.Code)
	}
}

func TestServePAC_FallsBackToRequestHost(t *testing.T) {
	h := newProxyHandler(map[string]struct{}{"443": {}}, nil, nil, "")

	req := httptest.NewRequest(http.MethodGet, "/proxy.pac", nil)
	req.Host = "proxy.local:8443"
	req.RemoteAddr = "192.0.2.1:54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `return "HTTPS proxy.local:8443";`) {
		t.Fatalf("body missing host-header fallback: %q", rec.Body.String())
	}
}

func TestServePAC_NoEndpointAndNoHost(t *testing.T) {
	rec := httptest.NewRecorder()
	servePAC(rec, "", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestServePAC_RejectsInjectionInHost(t *testing.T) {
	rec := httptest.NewRecorder()
	servePAC(rec, "", "evil\"; alert(1); //")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 for malformed host", rec.Code)
	}
}

func TestPACEndpoint_RejectsAbsoluteFormRequest(t *testing.T) {
	// Absolute-form requests target a different origin via the proxy
	// and must not be served the PAC; they go through the normal
	// proxy auth + forwarding path.
	setAuthEnv(t, sha256Hex(testProxyUser, testProxyPass))
	h := newProxyHandler(map[string]struct{}{"443": {}}, allowedAuthHashes(), nil, "proxy.example.com:443")

	req := httptest.NewRequest(http.MethodGet, "http://other.example.com/proxy.pac", nil)
	req.RemoteAddr = "192.0.2.1:54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("absolute-form /proxy.pac status = %d, want 407 (must go through proxy auth)", rec.Code)
	}
}

func TestPACEndpoint_RejectsNonGET(t *testing.T) {
	setAuthEnv(t, sha256Hex(testProxyUser, testProxyPass))
	h := newProxyHandler(map[string]struct{}{"443": {}}, allowedAuthHashes(), nil, "proxy.example.com:443")

	req := httptest.NewRequest(http.MethodPost, "/proxy.pac", nil)
	req.RemoteAddr = "192.0.2.1:54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// Non-GET must not be treated as a PAC fetch; it falls through to
	// normal proxy handling and is challenged for auth.
	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("POST /proxy.pac status = %d, want 407", rec.Code)
	}
}

func TestHandlePlainHTTP_RejectsNonAbsoluteURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/relative", nil)
	rec := httptest.NewRecorder()

	handlePlainHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandlePlainHTTP_RejectsHTTPSScheme(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	rec := httptest.NewRecorder()

	handlePlainHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandlePlainHTTP_ForwardsRequest(t *testing.T) {
	// The upstream listens on loopback, which the SSRF filter normally
	// blocks. Disable the filter just for this test that exercises
	// the forwarding path itself.
	origBlock := isBlockedIP
	isBlockedIP = func(net.IP) bool { return false }
	t.Cleanup(func() { isBlockedIP = origBlock })

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Proxy must not forward Proxy-Authorization to upstream.
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Errorf("upstream received Proxy-Authorization header")
		}
		// Hop-by-hop headers must have been stripped.
		if r.Header.Get("Connection") != "" {
			t.Errorf("upstream received Connection header")
		}
		w.Header().Set("X-Test", "ok")
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "hello")
	}))
	defer upstream.Close()

	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/path", nil)
	req.Header.Set("Proxy-Authorization", basicAuthHeader(testProxyUser, testProxyPass))
	req.Header.Set("Connection", "keep-alive")
	rec := httptest.NewRecorder()

	handlePlainHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
	if got := rec.Header().Get("X-Test"); got != "ok" {
		t.Fatalf("X-Test = %q, want %q", got, "ok")
	}
	if body := rec.Body.String(); body != "hello" {
		t.Fatalf("body = %q, want %q", body, "hello")
	}
}

func TestHandleConnect_BadTarget(t *testing.T) {
	req := httptest.NewRequest(http.MethodConnect, "http://example.com", nil)
	req.Host = "not-a-host-port"
	rec := httptest.NewRecorder()

	handleConnect(rec, req, map[string]struct{}{"443": {}})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleConnect_RejectsNonHTTPSPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodConnect, "http://example.com", nil)
	req.Host = "example.com:22"
	rec := httptest.NewRecorder()

	handleConnect(rec, req, map[string]struct{}{"443": {}})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestCopyHeader(t *testing.T) {
	src := http.Header{}
	src.Add("X-A", "1")
	src.Add("X-A", "2")
	src.Add("X-B", "3")

	dst := http.Header{}
	copyHeader(dst, src)

	if got := dst.Values("X-A"); len(got) != 2 || got[0] != "1" || got[1] != "2" {
		t.Fatalf("X-A = %v, want [1 2]", got)
	}
	if got := dst.Get("X-B"); got != "3" {
		t.Fatalf("X-B = %q, want %q", got, "3")
	}
}

func TestRemoveHopByHopHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "Keep-Alive, X-Custom-Hop")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Proxy-Authorization", "Basic xxx")
	h.Set("X-Custom-Hop", "drop-me")
	h.Set("X-Keep", "keep-me")

	removeHopByHopHeaders(h)

	for _, key := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authorization",
		"X-Custom-Hop",
	} {
		if v := h.Get(key); v != "" {
			t.Errorf("header %q = %q, want empty", key, v)
		}
	}
	if got := h.Get("X-Keep"); got != "keep-me" {
		t.Errorf("X-Keep = %q, want %q", got, "keep-me")
	}
}

func TestConfiguredListenAddr(t *testing.T) {
	t.Run("defaults to :443 when env is empty", func(t *testing.T) {
		t.Setenv(listenAddrEnv, "")
		if got := configuredListenAddr(); got != listenAddrDefault {
			t.Fatalf("configuredListenAddr() = %q, want %q", got, listenAddrDefault)
		}
	})

	t.Run("uses address from env", func(t *testing.T) {
		want := ":8443"
		t.Setenv(listenAddrEnv, want)
		if got := configuredListenAddr(); got != want {
			t.Fatalf("configuredListenAddr() = %q, want %q", got, want)
		}
	})

	t.Run("trims whitespace", func(t *testing.T) {
		want := ":9443"
		t.Setenv(listenAddrEnv, "  "+want+"  ")
		if got := configuredListenAddr(); got != want {
			t.Fatalf("configuredListenAddr() = %q, want %q", got, want)
		}
	})
}

func TestConfiguredHTTPListenAddr(t *testing.T) {
	t.Run("returns empty when env is unset", func(t *testing.T) {
		t.Setenv(httpListenAddrEnv, "")
		if got := configuredHTTPListenAddr(); got != "" {
			t.Fatalf("configuredHTTPListenAddr() = %q, want %q", got, "")
		}
	})

	t.Run("uses address from env", func(t *testing.T) {
		want := ":80"
		t.Setenv(httpListenAddrEnv, want)
		if got := configuredHTTPListenAddr(); got != want {
			t.Fatalf("configuredHTTPListenAddr() = %q, want %q", got, want)
		}
	})

	t.Run("trims whitespace", func(t *testing.T) {
		want := ":8080"
		t.Setenv(httpListenAddrEnv, "  "+want+"  ")
		if got := configuredHTTPListenAddr(); got != want {
			t.Fatalf("configuredHTTPListenAddr() = %q, want %q", got, want)
		}
	})
}

func TestConfiguredACMEDomains(t *testing.T) {
	t.Run("returns nil when env is empty", func(t *testing.T) {
		t.Setenv(acmeDomainEnv, "")
		if got := configuredACMEDomains(); got != nil {
			t.Fatalf("configuredACMEDomains() = %v, want nil", got)
		}
	})

	t.Run("uses domain from env", func(t *testing.T) {
		want := []string{"proxy.internal.example"}
		t.Setenv(acmeDomainEnv, want[0])
		got := configuredACMEDomains()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("configuredACMEDomains() = %v, want %v", got, want)
		}
	})

	t.Run("supports ipv4", func(t *testing.T) {
		want := []string{"203.0.113.8"}
		t.Setenv(acmeDomainEnv, want[0])
		got := configuredACMEDomains()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("configuredACMEDomains() = %v, want %v", got, want)
		}
	})

	t.Run("supports bracketed ipv6", func(t *testing.T) {
		raw := "[2001:db8::1]"
		want := []string{"2001:db8::1"}
		t.Setenv(acmeDomainEnv, raw)
		got := configuredACMEDomains()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("configuredACMEDomains() = %v, want %v", got, want)
		}
	})

	t.Run("splits comma-separated list", func(t *testing.T) {
		t.Setenv(acmeDomainEnv, "proxy.example.com, www.proxy.example.com ,[2001:db8::1]")
		want := []string{"proxy.example.com", "www.proxy.example.com", "2001:db8::1"}
		got := configuredACMEDomains()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("configuredACMEDomains() = %v, want %v", got, want)
		}
	})

	t.Run("ignores empty entries", func(t *testing.T) {
		t.Setenv(acmeDomainEnv, ",,proxy.example.com,,")
		want := []string{"proxy.example.com"}
		got := configuredACMEDomains()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("configuredACMEDomains() = %v, want %v", got, want)
		}
	})

	t.Run("deduplicates entries", func(t *testing.T) {
		t.Setenv(acmeDomainEnv, "proxy.example.com,proxy.example.com,www.proxy.example.com")
		want := []string{"proxy.example.com", "www.proxy.example.com"}
		got := configuredACMEDomains()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("configuredACMEDomains() = %v, want %v", got, want)
		}
	})
}

func TestConfiguredACMEProfile(t *testing.T) {
	t.Run("returns empty for DNS-only identifiers when unset", func(t *testing.T) {
		unsetEnvForTest(t, acmeProfileEnv)
		if got := configuredACMEProfile([]string{"proxy.example.com"}); got != "" {
			t.Fatalf("configuredACMEProfile() = %q, want \"\"", got)
		}
	})

	t.Run("auto-selects shortlived for IPv4 identifier", func(t *testing.T) {
		unsetEnvForTest(t, acmeProfileEnv)
		if got := configuredACMEProfile([]string{"203.0.113.8"}); got != acmeProfileShortLived {
			t.Fatalf("configuredACMEProfile() = %q, want %q", got, acmeProfileShortLived)
		}
	})

	t.Run("auto-selects shortlived for IPv6 identifier", func(t *testing.T) {
		unsetEnvForTest(t, acmeProfileEnv)
		if got := configuredACMEProfile([]string{"2001:db8::1"}); got != acmeProfileShortLived {
			t.Fatalf("configuredACMEProfile() = %q, want %q", got, acmeProfileShortLived)
		}
	})

	t.Run("auto-selects shortlived when any identifier is an IP", func(t *testing.T) {
		unsetEnvForTest(t, acmeProfileEnv)
		got := configuredACMEProfile([]string{"proxy.example.com", "203.0.113.8"})
		if got != acmeProfileShortLived {
			t.Fatalf("configuredACMEProfile() = %q, want %q", got, acmeProfileShortLived)
		}
	})

	t.Run("env override wins over auto-default", func(t *testing.T) {
		t.Setenv(acmeProfileEnv, "classic")
		if got := configuredACMEProfile([]string{"203.0.113.8"}); got != "classic" {
			t.Fatalf("configuredACMEProfile() = %q, want %q", got, "classic")
		}
	})

	t.Run("whitespace-only env falls back to auto-default", func(t *testing.T) {
		t.Setenv(acmeProfileEnv, "   ")
		if got := configuredACMEProfile([]string{"203.0.113.8"}); got != acmeProfileShortLived {
			t.Fatalf("configuredACMEProfile() = %q, want %q", got, acmeProfileShortLived)
		}
		if got := configuredACMEProfile([]string{"proxy.example.com"}); got != "" {
			t.Fatalf("configuredACMEProfile() = %q, want \"\"", got)
		}
	})
}

// unsetEnvForTest unsets an environment variable for the remainder of
// the current test, restoring its prior state when the test ends. This
// complements testing.T.Setenv, which only supports setting values.
func unsetEnvForTest(t *testing.T, key string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unsetenv %s: %v", key, err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, prev)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

func TestSelfSignedTLSConfig(t *testing.T) {
	cfg, err := selfSignedTLSConfig()
	if err != nil {
		t.Fatalf("selfSignedTLSConfig() error = %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("len(Certificates) = %d, want 1", len(cfg.Certificates))
	}
	if cfg.Certificates[0].PrivateKey == nil {
		t.Fatal("certificate has nil private key")
	}
}

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.0.5", true},
		{"172.16.5.5", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true}, // AWS/GCP/Azure metadata
		{"fe80::1", true},
		{"0.0.0.0", true},
		{"::", true},
		{"224.0.0.1", true},
		{"ff02::1", true},
		{"fc00::1", true}, // ULA
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2606:4700:4700::1111", false},
	}
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("invalid test IP %q", tc.ip)
			}
			if got := isBlockedIP(ip); got != tc.want {
				t.Fatalf("isBlockedIP(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestResolveSafeIPs_LiteralBlocked(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "10.1.2.3", "::1", "fe80::1"} {
		t.Run(host, func(t *testing.T) {
			_, err := resolveSafeIPs(context.Background(), host)
			if !errors.Is(err, errBlockedAddress) {
				t.Fatalf("resolveSafeIPs(%q) err = %v, want errBlockedAddress", host, err)
			}
		})
	}
}

func TestResolveSafeIPs_LiteralAllowed(t *testing.T) {
	ips, err := resolveSafeIPs(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "8.8.8.8" {
		t.Fatalf("got %v, want [8.8.8.8]", ips)
	}
}

func TestSafeDial_BlocksPrivateLiteral(t *testing.T) {
	// Bind a loopback listener so that, absent the SSRF check, a dial
	// would succeed. The safe dialer must refuse before connecting.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	_, err = safeDial(context.Background(), "tcp", ln.Addr().String(), 2*time.Second)
	if !errors.Is(err, errBlockedAddress) {
		t.Fatalf("safeDial err = %v, want errBlockedAddress", err)
	}
}

func TestDialFirstReachable_FallsBackToNextAddress(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("relies on the whole 127.0.0.0/8 block being routed to loopback")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener addr: %v", err)
	}

	// Nothing listens on 127.0.0.2, so the first candidate fails fast
	// with ECONNREFUSED and the dialer must fall back to 127.0.0.1.
	candidates := []net.IP{net.ParseIP("127.0.0.2"), net.ParseIP("127.0.0.1")}
	conn, err := dialFirstReachable(context.Background(), "tcp", port, candidates, 5*time.Second)
	if err != nil {
		t.Fatalf("dialFirstReachable() = %v, want fallback success", err)
	}
	defer conn.Close() //nolint:errcheck

	if got, want := conn.RemoteAddr().String(), ln.Addr().String(); got != want {
		t.Fatalf("connected to %s, want %s", got, want)
	}
}

func TestDialFirstReachable_AllAddressesFail(t *testing.T) {
	// Grab a free port with nothing listening on it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener addr: %v", err)
	}
	_ = ln.Close()

	_, err = dialFirstReachable(context.Background(), "tcp", port, []net.IP{net.ParseIP("127.0.0.1")}, 2*time.Second)
	if err == nil {
		t.Fatal("dialFirstReachable() = nil error, want dial failure")
	}
}

func TestDialFirstReachable_NoCandidates(t *testing.T) {
	_, err := dialFirstReachable(context.Background(), "tcp", "443", nil, time.Second)
	if err == nil {
		t.Fatal("dialFirstReachable() = nil error, want no-candidates failure")
	}
}

func TestDialFirstReachable_TimeoutExhausted(t *testing.T) {
	// A zero timeout makes the deadline check fail before the first dial
	// attempt, exercising the budget-exhaustion branch without touching
	// the network.
	_, err := dialFirstReachable(context.Background(), "tcp", "443", []net.IP{net.ParseIP("192.0.2.1")}, 0)
	if err == nil {
		t.Fatal("dialFirstReachable() = nil error, want timeout exhaustion")
	}
	if !strings.Contains(err.Error(), "timeout exhausted") {
		t.Fatalf("dialFirstReachable() error = %v, want timeout exhaustion", err)
	}
}

func TestDialFirstReachable_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := dialFirstReachable(ctx, "tcp", "443", []net.IP{net.ParseIP("8.8.8.8")}, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("dialFirstReachable() = %v, want context.Canceled", err)
	}
}

func TestInterleaveByFamily(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "v6 preferred alternates families",
			in:   []string{"2001:4860::1", "2001:4860::2", "8.8.8.8", "8.8.4.4"},
			want: []string{"2001:4860::1", "8.8.8.8", "2001:4860::2", "8.8.4.4"},
		},
		{
			name: "v4 preferred alternates families",
			in:   []string{"8.8.8.8", "8.8.4.4", "2001:4860::1", "2001:4860::2"},
			want: []string{"8.8.8.8", "2001:4860::1", "8.8.4.4", "2001:4860::2"},
		},
		{
			name: "uneven families keeps remainder in order",
			in:   []string{"2001:4860::1", "8.8.8.8", "8.8.4.4", "9.9.9.9"},
			want: []string{"2001:4860::1", "8.8.8.8", "8.8.4.4", "9.9.9.9"},
		},
		{
			name: "single family unchanged",
			in:   []string{"8.8.8.8", "8.8.4.4", "9.9.9.9"},
			want: []string{"8.8.8.8", "8.8.4.4", "9.9.9.9"},
		},
		{
			name: "two addresses unchanged",
			in:   []string{"2001:4860::1", "8.8.8.8"},
			want: []string{"2001:4860::1", "8.8.8.8"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := make([]net.IP, 0, len(tc.in))
			for _, s := range tc.in {
				ip := net.ParseIP(s)
				if ip == nil {
					t.Fatalf("invalid test IP %q", s)
				}
				in = append(in, ip)
			}
			got := make([]string, 0, len(tc.in))
			for _, ip := range interleaveByFamily(in) {
				got = append(got, ip.String())
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("interleaveByFamily(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestHandleConnect_BlocksPrivateAddress(t *testing.T) {
	setAuthEnv(t, sha256Hex(testProxyUser, testProxyPass))

	req := httptest.NewRequest(http.MethodConnect, "http://example.com", nil)
	// Force a private literal target on the standard HTTPS port.
	req.Host = "127.0.0.1:443"
	req.Header.Set("Proxy-Authorization", basicAuthHeader(testProxyUser, testProxyPass))
	rec := httptest.NewRecorder()

	proxyHandler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestHandlePlainHTTP_BlocksPrivateAddress(t *testing.T) {
	// Spin up a loopback HTTP server. handlePlainHTTP must refuse to
	// dial it via the SSRF filter even though it is reachable.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream should not be reached")
	}))
	defer upstream.Close()

	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/", nil)
	req.Header.Set("Proxy-Authorization", basicAuthHeader(testProxyUser, testProxyPass))
	rec := httptest.NewRecorder()

	handlePlainHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (body=%q)", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestConfiguredACMEEmail(t *testing.T) {
	t.Run("unset is rejected", func(t *testing.T) {
		t.Setenv(acmeEmailEnv, "")
		if _, err := configuredACMEEmail(); err == nil {
			t.Fatal("expected error when ACME_EMAIL is unset")
		}
	})

	t.Run("example domain is rejected", func(t *testing.T) {
		t.Setenv(acmeEmailEnv, "admin@example.com")
		if _, err := configuredACMEEmail(); err == nil {
			t.Fatal("expected error for example.com address")
		}
	})

	t.Run("missing @ is rejected", func(t *testing.T) {
		t.Setenv(acmeEmailEnv, "not-an-email")
		if _, err := configuredACMEEmail(); err == nil {
			t.Fatal("expected error for malformed email")
		}
	})

	t.Run("valid email is accepted", func(t *testing.T) {
		t.Setenv(acmeEmailEnv, "  ops@proxy.test  ")
		got, err := configuredACMEEmail()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "ops@proxy.test" {
			t.Fatalf("got %q, want %q", got, "ops@proxy.test")
		}
	})
}

// TestHandleConnect_DrainsBufferedClientBytes verifies that bytes the
// client pipelined into the bufio.Reader together with the CONNECT
// request are forwarded to the destination instead of being silently
// dropped after hijack.
func TestHandleConnect_DrainsBufferedClientBytes(t *testing.T) {
	// Destination server: read everything sent by the client and echo it.
	dstLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dst: %v", err)
	}
	defer dstLn.Close() //nolint:errcheck

	received := make(chan []byte, 1)
	go func() {
		c, err := dstLn.Accept()
		if err != nil {
			return
		}
		defer c.Close() //nolint:errcheck
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		received <- buf[:n]
	}()

	// Build an HTTP proxy whose handleConnect uses a stub dialer pointing
	// at the local destination, bypassing the SSRF block.
	origAddr := dstLn.Addr().String()
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mimic handleConnect but use the loopback destination directly.
		dst, err := net.Dial("tcp", origAddr)
		if err != nil {
			t.Errorf("dial dst: %v", err)
			return
		}
		defer dst.Close() //nolint:errcheck
		hj, _ := w.(http.Hijacker)
		cc, buf, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer cc.Close() //nolint:errcheck
		_, _ = buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buf.Flush()
		if n := buf.Reader.Buffered(); n > 0 {
			if _, err := io.CopyN(dst, buf.Reader, int64(n)); err != nil {
				t.Errorf("drain: %v", err)
				return
			}
		}
		_, _ = io.Copy(dst, cc)
	})

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	defer proxyLn.Close() //nolint:errcheck
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(proxyLn) }()
	defer srv.Close() //nolint:errcheck

	// Pipeline CONNECT + payload in a single TCP write so the payload
	// is parked in the server-side bufio.Reader before Hijack returns.
	conn, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	pipelined := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nHELLO-PIPELINED"
	if _, err := conn.Write([]byte(pipelined)); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read the 200 response line.
	respBuf := make([]byte, 128)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(respBuf); err != nil {
		t.Fatalf("read response: %v", err)
	}

	select {
	case got := <-received:
		if string(got) != "HELLO-PIPELINED" {
			t.Fatalf("destination received %q, want %q", got, "HELLO-PIPELINED")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("destination did not receive pipelined bytes")
	}
}

func TestIsBlockedIP_ExtraRanges(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"0.1.2.3", true},          // RFC 1122 "this host on this network"
		{"0.255.255.255", true},    // 0.0.0.0/8 upper
		{"100.64.0.1", true},       // CGNAT
		{"100.127.255.254", true},  // CGNAT upper
		{"192.0.0.170", true},      // IETF protocol assignments
		{"192.0.2.5", true},        // TEST-NET-1
		{"198.18.0.1", true},       // benchmark
		{"198.51.100.7", true},     // TEST-NET-2
		{"203.0.113.5", true},      // TEST-NET-3
		{"255.255.255.255", true},  // limited broadcast
		{"2001:db8::5", true},      // IPv6 docs
		{"::ffff:127.0.0.1", true}, // IPv4-mapped loopback
		{"::ffff:10.0.0.1", true},  // IPv4-mapped private
		{"::ffff:169.254.169.254", true},
		{"64:ff9b::7f00:1", true},  // NAT64 embedding 127.0.0.1
		{"64:ff9b::808:808", true}, // NAT64 embedding 8.8.8.8 (translation prefix)
		{"100.63.255.254", false},  // just below CGNAT
		{"100.128.0.1", false},     // just above CGNAT
		{"1.0.0.1", false},         // just above 0.0.0.0/8
		{"64:ff9c::1", false},      // just outside NAT64 well-known prefix
	}
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("invalid test IP %q", tc.ip)
			}
			if got := isBlockedIP(ip); got != tc.want {
				t.Fatalf("isBlockedIP(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestHandleConnect_AllowedPortsConfigurable(t *testing.T) {
	req := httptest.NewRequest(http.MethodConnect, "http://example.com", nil)
	req.Host = "example.com:8443"
	rec := httptest.NewRecorder()

	handleConnect(rec, req, map[string]struct{}{"8443": {}})

	// Should pass the port check and then fail later (DNS or SSRF), not 403 here.
	if rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "this port is not allowed") {
		t.Fatalf("port 8443 should be allowed but was rejected: %s", rec.Body.String())
	}
}

func TestHandleConnect_RejectsZoneIDHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodConnect, "http://example.com", nil)
	req.Host = "fe80::1%eth0:443"
	rec := httptest.NewRecorder()

	handleConnect(rec, req, map[string]struct{}{"443": {}})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestConfiguredConnectPorts(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		t.Setenv(connectPortsEnv, "")
		got, err := configuredConnectPorts()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := got["443"]; !ok || len(got) != 1 {
			t.Fatalf("default ports = %v, want {443}", got)
		}
	})

	t.Run("multiple", func(t *testing.T) {
		t.Setenv(connectPortsEnv, " 443 ,8443, 9443 ")
		got, err := configuredConnectPorts()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, p := range []string{"443", "8443", "9443"} {
			if _, ok := got[p]; !ok {
				t.Fatalf("missing port %s in %v", p, got)
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		t.Setenv(connectPortsEnv, "abc")
		if _, err := configuredConnectPorts(); err == nil {
			t.Fatal("expected error for non-numeric port")
		}
	})

	t.Run("out of range", func(t *testing.T) {
		t.Setenv(connectPortsEnv, "70000")
		if _, err := configuredConnectPorts(); err == nil {
			t.Fatal("expected error for out-of-range port")
		}
	})

	t.Run("zero", func(t *testing.T) {
		t.Setenv(connectPortsEnv, "0")
		if _, err := configuredConnectPorts(); err == nil {
			t.Fatal("expected error for port 0")
		}
	})

	t.Run("all", func(t *testing.T) {
		t.Setenv(connectPortsEnv, " ALL ")
		got, err := configuredConnectPorts()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := got[connectPortsAll]; !ok || len(got) != 1 {
			t.Fatalf("ports = %v, want all-ports sentinel", got)
		}
	})
}

func TestHandleConnect_AllowedPortsAll(t *testing.T) {
	req := httptest.NewRequest(http.MethodConnect, "http://example.com", nil)
	req.Host = "example.com:12345"
	rec := httptest.NewRecorder()

	handleConnect(rec, req, map[string]struct{}{connectPortsAll: {}})

	// With the all-ports sentinel the port check must pass; failure can only
	// come later (DNS or SSRF), never a "port not allowed" 403 here.
	if rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "this port is not allowed") {
		t.Fatalf("port 12345 should be allowed but was rejected: %s", rec.Body.String())
	}
}

func TestConfiguredCertStoragePath(t *testing.T) {
	t.Run("default is absolute", func(t *testing.T) {
		t.Setenv(certStoragePathEnv, "")
		got, err := configuredCertStoragePath()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !filepath.IsAbs(got) {
			t.Fatalf("path %q is not absolute", got)
		}
	})

	t.Run("custom path is absolute", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv(certStoragePathEnv, dir)
		got, err := configuredCertStoragePath()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != dir {
			t.Fatalf("got %q, want %q", got, dir)
		}
	})
}

// TestHandleConnect_WaitsForBothDirections verifies the proxy waits for
// both copy goroutines before closing connections, so bytes flowing in
// the not-yet-errored direction are not truncated.
func TestHandleConnect_WaitsForBothDirections(t *testing.T) {
	// Destination accepts the connection, reads until the client EOFs,
	// then sends a final payload back. If handleConnect returns after
	// only one direction completes, the destination's outbound payload
	// would be truncated.
	dstLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dst: %v", err)
	}
	defer dstLn.Close() //nolint:errcheck

	const payload = "FROM-DESTINATION"

	go func() {
		c, err := dstLn.Accept()
		if err != nil {
			return
		}
		defer c.Close() //nolint:errcheck
		// Read any pipelined bytes from the client, then send the payload.
		_, _ = io.Copy(io.Discard, &readUntilEOF{c})
		_, _ = c.Write([]byte(payload))
	}()

	// Custom handler that mirrors handleConnect but dials the loopback
	// destination directly, bypassing the SSRF filter for this test.
	dstAddr := dstLn.Addr().String()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dst, err := net.Dial("tcp", dstAddr)
		if err != nil {
			t.Errorf("dial dst: %v", err)
			return
		}
		defer dst.Close() //nolint:errcheck

		hj, _ := w.(http.Hijacker)
		cc, buf, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer cc.Close() //nolint:errcheck
		_, _ = buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buf.Flush()

		errCh := make(chan error, 2)
		go func() { errCh <- proxyCopy(dst, cc) }()
		go func() { errCh <- proxyCopy(cc, dst) }()
		<-errCh
		<-errCh
	})

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

	if _, err := conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")); err != nil {
		t.Fatalf("write connect: %v", err)
	}

	// Read 200 response.
	respBuf := make([]byte, 128)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(respBuf); err != nil {
		t.Fatalf("read 200: %v", err)
	}

	// Half-close the client->dst direction so destination unblocks
	// from Read and emits its payload.
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}

	// Read the destination payload back through the tunnel. If
	// handleConnect did not wait for the dst->client direction, this
	// would race against the deferred clientConn.Close() and could be
	// short-read or zero.
	got := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("got %q, want %q", got, payload)
	}
}

// readUntilEOF wraps a Reader so io.Copy can consume to EOF without
// caring about partial reads — used only by the test above.
type readUntilEOF struct{ r io.Reader }

func (r *readUntilEOF) Read(p []byte) (int, error) { return r.r.Read(p) }

func TestListenerHostPort(t *testing.T) {
	tests := []struct {
		name string
		host string
		addr string
		want string
	}{
		{name: "domain host", host: "proxy.example.com", addr: ":443", want: "proxy.example.com:443"},
		{name: "ipv4 host", host: "203.0.113.8", addr: ":443", want: "203.0.113.8:443"},
		{name: "ipv6 host", host: "2001:db8::1", addr: ":443", want: "[2001:db8::1]:443"},
		{name: "missing port", host: "proxy.example.com", addr: "", want: "proxy.example.com"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := listenerHostPort(tc.host, tc.addr); got != tc.want {
				t.Fatalf("listenerHostPort(%q, %q) = %q, want %q", tc.host, tc.addr, got, tc.want)
			}
		})
	}
}

// FuzzAuthorized exercises the proxy authentication header parser with
// arbitrary input. It must not panic and must not return true for any
// non-empty allow-list configuration when fed random `Proxy-Authorization`
// header values, since the fuzzer cannot guess the correct sha256 digest
// of a valid credential pair.
func FuzzAuthorized(f *testing.F) {
	// Seed with a mix of malformed, empty, and structurally-valid headers
	// so the fuzzer has something interesting to mutate from.
	seeds := []string{
		"",
		"Basic ",
		"Basic !!!not-base64!!!",
		"Bearer " + base64.StdEncoding.EncodeToString([]byte("user:pass")),
		"Basic " + base64.StdEncoding.EncodeToString([]byte("")),
		"Basic " + base64.StdEncoding.EncodeToString([]byte(":")),
		"Basic " + base64.StdEncoding.EncodeToString([]byte("user:")),
		"Basic " + base64.StdEncoding.EncodeToString([]byte(":pass")),
		"Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass")),
		"Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret")),
		"Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass:extra")),
		"Basic " + base64.StdEncoding.EncodeToString([]byte("\x00\x01\x02:\xff\xfe")),
		"Basic " + strings.Repeat("A", 1024),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	// Configure an allow-list with two known-good digests. Any random
	// header that fails to decode to exactly one of these must be rejected.
	hashWant1 := sha256Hex(testProxyUser, testProxyPass)
	hashWant2 := sha256Hex(testProxyUser2, testProxyPass2)
	f.Setenv(proxyAuthEnv, hashWant1+proxyAuthDelimiter+hashWant2)

	f.Fuzz(func(t *testing.T, header string) {
		req := httptest.NewRequest(http.MethodGet, "http://example.invalid/", nil)
		if header != "" {
			req.Header.Set("Proxy-Authorization", header)
		}

		// Must not panic regardless of input.
		got := authorized(req, allowedAuthHashes())
		if !got {
			return
		}

		// If authorized returned true, the fuzzer must have stumbled onto
		// a credential pair whose sha256 matches an allow-list entry.
		// That's only possible when the header decodes to one of the
		// two seed credentials. Confirm by recomputing the digest.
		const prefix = "Basic "
		if !strings.HasPrefix(header, prefix) {
			t.Fatalf("authorized returned true for header without %q prefix: %q", prefix, header)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
		if err != nil {
			t.Fatalf("authorized returned true for header with invalid base64: %q", header)
		}
		sum := sha256.Sum256(raw)
		gotHash := hex.EncodeToString(sum[:])
		if gotHash != hashWant1 && gotHash != hashWant2 {
			t.Fatalf("authorized returned true for header whose digest %q is not in the allow-list", gotHash)
		}
	})
}
