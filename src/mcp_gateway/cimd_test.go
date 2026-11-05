// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// localTLSClient trusts the test server's cert; it stands in for
// cimdHTTPClient(), which would refuse loopback by design.
func localTLSClient(srv *httptest.Server) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func cimdServer(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
}

func TestFetchCIMDValid(t *testing.T) {
	var srv *httptest.Server
	srv = cimdServer(t, "", 200)
	defer srv.Close()
	// Rewrite the handler's body now that the URL is known.
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"client_id":` + quote(srv.URL) + `,"redirect_uris":["https://app.example/cb"],"client_name":"demo"}`))
	})
	doc, err := fetchCIMD(context.Background(), localTLSClient(srv), srv.URL)
	if err != nil {
		t.Fatalf("fetchCIMD: %v", err)
	}
	if doc.ClientName != "demo" || len(doc.RedirectURIs) != 1 {
		t.Fatalf("doc = %+v", doc)
	}
}

func quote(s string) string {
	return `"` + s + `"`
}

func TestFetchCIMDRejects(t *testing.T) {
	var srv *httptest.Server
	var body string
	srv = cimdServer(t, "", 200)
	defer srv.Close()
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	})
	cases := map[string]string{
		"client_id mismatch": `{"client_id":"https://evil.example/other","redirect_uris":["https://app.example/cb"]}`,
		"no redirect_uris":   `{"client_id":"SELF"}`,
		"not JSON":           `not json`,
		"wrong grant":        `{"client_id":"SELF","redirect_uris":["https://app.example/cb"],"grant_types":["client_credentials"]}`,
		"confidential auth":  `{"client_id":"SELF","redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}`,
	}
	for name, b := range cases {
		body = strings.ReplaceAll(b, `"SELF"`, quote(srv.URL))
		if _, err := fetchCIMD(context.Background(), localTLSClient(srv), srv.URL); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Oversize document.
	body = `{"client_id":` + quote(srv.URL) + `,"redirect_uris":["https://app.example/cb"],"pad":"` + strings.Repeat("x", maxCIMDBytes) + `"}`
	if _, err := fetchCIMD(context.Background(), localTLSClient(srv), srv.URL); err == nil {
		t.Error("oversize document accepted")
	}
	// Non-https and fragment client_ids never reach the network.
	for _, id := range []string{"http://app.example/meta", "https://app.example/meta#frag", "not-a-url"} {
		if _, err := fetchCIMD(context.Background(), localTLSClient(srv), id); err == nil {
			t.Errorf("client_id %q accepted", id)
		}
	}
}

func TestProductionCIMDClientRefusesLoopback(t *testing.T) {
	srv := cimdServer(t, `{}`, 200)
	defer srv.Close()
	// The test server is https on 127.0.0.1: the production dial guard must
	// refuse it before any byte is exchanged.
	if _, err := fetchCIMD(context.Background(), cimdHTTPClient(), srv.URL); err == nil {
		t.Fatal("production client fetched from loopback")
	}
}

func TestIsPublicIP(t *testing.T) {
	public := []string{"8.8.8.8", "1.1.1.1", "203.0.113.7", "2001:db8::1", "2606:4700:4700::1111"}
	for _, s := range public {
		if !isPublicIP(net.ParseIP(s)) {
			t.Errorf("%s: refused, want public", s)
		}
	}
	private := []string{"127.0.0.1", "::1", "0.0.0.0", "10.1.2.3", "172.16.0.1", "172.31.255.1",
		"192.168.1.1", "169.254.169.254", "100.64.0.1", "224.0.0.1", "ff02::1", "fe80::1", "fc00::1", "::ffff:10.0.0.1"}
	for _, s := range private {
		if isPublicIP(net.ParseIP(s)) {
			t.Errorf("%s: accepted, want refused", s)
		}
	}
	// Adjacent addresses that must NOT be swept up by the private ranges.
	edge := []string{"172.15.255.255", "172.32.0.0", "100.63.255.255", "100.128.0.0", "169.253.1.1", "169.255.1.1"}
	for _, s := range edge {
		if !isPublicIP(net.ParseIP(s)) {
			t.Errorf("%s: refused, want public", s)
		}
	}
}
