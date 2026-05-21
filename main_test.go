package main

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func basicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestAuthorized(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{"missing header", "", false},
		{"non-basic scheme", "Bearer token", false},
		{"malformed base64", "Basic !!!notbase64!!!", false},
		{"wrong credentials", basicAuthHeader("wrong", "creds"), false},
		{"valid credentials", basicAuthHeader(proxyUser, proxyPass), true},
		{"empty credentials", basicAuthHeader("", ""), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			if tc.header != "" {
				req.Header.Set("Proxy-Authorization", tc.header)
			}
			if got := authorized(req); got != tc.want {
				t.Fatalf("authorized() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProxyHandler_Unauthorized(t *testing.T) {
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
	req.Header.Set("Proxy-Authorization", basicAuthHeader(proxyUser, proxyPass))
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

	handleConnect(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleConnect_RejectsNonHTTPSPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodConnect, "http://example.com", nil)
	req.Host = "example.com:22"
	rec := httptest.NewRecorder()

	handleConnect(rec, req)

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
