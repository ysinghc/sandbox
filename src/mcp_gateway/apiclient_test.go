// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// fakeAPI mimics the one #27 behavior the gateway needs so far: GET
// /v1/sessions is 200 for the good token, 401 otherwise.
func fakeAPI(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sessions" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer good-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"sessions":[]}`))
	}))
}

func TestValidTokenTCP(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	c, err := NewAPIClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !c.ValidToken("good-token") {
		t.Fatal("good token rejected")
	}
	if c.ValidToken("bad-token") {
		t.Fatal("bad token accepted")
	}
	if c.ValidToken("") {
		t.Fatal("empty token accepted")
	}
}

func TestValidTokenUnix(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "api.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &httptest.Server{
		Listener: ln,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// sandbox-api's Unix socket keys identity off SO_PEERCRED and
			// takes no token; accept anything here, the transport is the test.
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"sessions":[]}`))
		})},
	}
	srv.Start()
	defer srv.Close()
	c, err := NewAPIClient("unix://" + sock)
	if err != nil {
		t.Fatal(err)
	}
	if !c.ValidToken("anything") {
		t.Fatal("unix transport call failed")
	}
	_ = os.Remove(sock)
}

func TestNewAPIClientRejects(t *testing.T) {
	for _, base := range []string{"", "ftp://x", "unix://", "notaurl"} {
		if _, err := NewAPIClient(base); err == nil {
			t.Errorf("base %q accepted", base)
		}
	}
}
