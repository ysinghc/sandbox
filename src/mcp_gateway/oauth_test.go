// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// testServer builds a Server with a temp store, a stubbed #27 token check
// ("api-token-ok" passes) and no network dependencies.
func testServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "api-token")
	if err := os.WriteFile(tokFile, []byte("operator-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Config{
		Listen:       "127.0.0.1:0",
		PublicURL:    "https://mcp.example.org",
		StorePath:    filepath.Join(dir, "state.json"),
		APIBase:      "unix:///nonexistent",
		APITokenFile: tokFile,
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	s.validateAPI = func(token string) bool { return token == "api-token-ok" }
	return s
}

func getJSON(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("GET %s: not JSON: %s", url, raw)
	}
	return resp.StatusCode, body
}

func postFormNoRedirect(t *testing.T, url string, form url.Values) (int, http.Header, []byte) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.PostForm(url, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, raw
}

func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	verifier, err := randomB64(48)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestMetadataEndpoints(t *testing.T) {
	s := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	status, rm := getJSON(t, srv.URL+"/.well-known/oauth-protected-resource")
	if status != 200 {
		t.Fatalf("resource metadata status = %d", status)
	}
	if rm["resource"] != "https://mcp.example.org/mcp" {
		t.Fatalf("resource = %v", rm["resource"])
	}
	if as, _ := rm["authorization_servers"].([]any); len(as) != 1 || as[0] != "https://mcp.example.org" {
		t.Fatalf("authorization_servers = %v", as)
	}
	status, am := getJSON(t, srv.URL+"/.well-known/oauth-authorization-server")
	if status != 200 {
		t.Fatalf("server metadata status = %d", status)
	}
	for k, want := range map[string]string{
		"issuer":                 "https://mcp.example.org",
		"authorization_endpoint": "https://mcp.example.org/oauth/authorize",
		"token_endpoint":         "https://mcp.example.org/oauth/token",
		"registration_endpoint":  "https://mcp.example.org/oauth/register",
	} {
		if am[k] != want {
			t.Errorf("%s = %v, want %s", k, am[k], want)
		}
	}
	if am["client_id_metadata_document_supported"] != true {
		t.Error("CIMD support not advertised")
	}
	if ch, _ := am["code_challenge_methods_supported"].([]any); len(ch) != 1 || ch[0] != "S256" {
		t.Errorf("challenge methods = %v", ch)
	}
}

func registerClient(t *testing.T, srvURL, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(srvURL+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("register response not JSON: %s", raw)
	}
	return resp.StatusCode, out
}

func TestDCRValid(t *testing.T) {
	s := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	status, out := registerClient(t, srv.URL, `{"redirect_uris":["https://app.example/cb"],"client_name":"demo"}`)
	if status != http.StatusCreated {
		t.Fatalf("register status = %d (%v)", status, out)
	}
	id, _ := out["client_id"].(string)
	if !strings.HasPrefix(id, "client_") {
		t.Fatalf("client_id = %q", id)
	}
	if out["token_endpoint_auth_method"] != "none" {
		t.Fatalf("auth method = %v", out["token_endpoint_auth_method"])
	}
	if _, ok := s.store.Client(id); !ok {
		t.Fatal("registered client not persisted")
	}
}

func TestDCRRejects(t *testing.T) {
	s := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	cases := map[string]string{
		"empty body":        ``,
		"not JSON":          `{oops`,
		"no redirect_uris":  `{"client_name":"x"}`,
		"http redirect":     `{"redirect_uris":["http://app.example/cb"]}`,
		"fragment redirect": `{"redirect_uris":["https://app.example/cb#frag"]}`,
		"relative redirect": `{"redirect_uris":["/cb"]}`,
		"bad grant":         `{"redirect_uris":["https://app.example/cb"],"grant_types":["password"]}`,
		"bad response":      `{"redirect_uris":["https://app.example/cb"],"response_types":["token"]}`,
		"confidential":      `{"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}`,
		"bad scope":         `{"redirect_uris":["https://app.example/cb"],"scope":"sandbox:admin"}`,
	}
	for name, body := range cases {
		status, out := registerClient(t, srv.URL, body)
		if status == http.StatusCreated {
			t.Errorf("%s: accepted", name)
			continue
		}
		if _, hasErr := out["error"]; !hasErr {
			t.Errorf("%s: status %d without error code", name, status)
		}
	}
	// Loopback http redirects are the documented exception.
	status, _ := registerClient(t, srv.URL, `{"redirect_uris":["http://127.0.0.1:9/cb"]}`)
	if status != http.StatusCreated {
		t.Errorf("loopback http redirect rejected: %d", status)
	}
}

func TestDCRRegistryCap(t *testing.T) {
	s := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	for i := 0; i < maxClients; i++ {
		if err := s.store.SaveClient(&Client{ID: fmt.Sprintf("client_fill_%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	status, _ := registerClient(t, srv.URL, `{"redirect_uris":["https://app.example/cb"]}`)
	if status != http.StatusForbidden {
		t.Fatalf("register past the cap = %d, want 403", status)
	}
}

var reqidRe = regexp.MustCompile(`name="reqid" value="([^"]+)"`)

// fullCodeFlow runs register → authorize → approve → code, returning the code,
// the client id and the verifier for the exchange.
func fullCodeFlow(t *testing.T, srvURL string, s *Server) (code, clientID, verifier, redirect string) {
	t.Helper()
	status, out := registerClient(t, srvURL, `{"redirect_uris":["https://app.example/cb"],"client_name":"demo"}`)
	if status != http.StatusCreated {
		t.Fatalf("register: %d %v", status, out)
	}
	clientID = out["client_id"].(string)
	redirect = "https://app.example/cb"
	var challenge string
	verifier, challenge = pkcePair(t)
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"scope": {"sandbox:read sandbox:write"}, "state": {"st-1"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"resource": {"https://mcp.example.org/mcp"},
	}
	resp, err := http.Get(srvURL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	page, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("authorize form = %d: %s", resp.StatusCode, page)
	}
	m := reqidRe.FindSubmatch(page)
	if m == nil {
		t.Fatalf("consent page carries no reqid: %s", page)
	}
	if !strings.Contains(string(page), "demo") || !strings.Contains(string(page), ScopeWrite) {
		t.Fatalf("consent page lacks client/scopes: %s", page)
	}
	st, hdr, _ := postFormNoRedirect(t, srvURL+"/oauth/authorize", url.Values{
		"reqid": {string(m[1])}, "decision": {"approve"}, "api_token": {"api-token-ok"},
	})
	if st != http.StatusFound {
		t.Fatalf("approve = %d, want 302", st)
	}
	loc, err := url.Parse(hdr.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("state") != "st-1" || loc.Query().Get("iss") != "https://mcp.example.org" {
		t.Fatalf("code redirect lacks state/iss: %s", loc)
	}
	code = loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %s", loc)
	}
	return code, clientID, verifier, redirect
}

func exchangeCode(t *testing.T, srvURL string, form url.Values) (int, map[string]any) {
	t.Helper()
	status, _, raw := postFormNoRedirect(t, srvURL+"/oauth/token", form)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("token response not JSON: %s", raw)
	}
	return status, out
}

func TestFullCodeFlowAndRefresh(t *testing.T) {
	s := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	code, clientID, verifier, redirect := fullCodeFlow(t, srv.URL, s)
	status, tok := exchangeCode(t, srv.URL, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID},
		"code": {code}, "code_verifier": {verifier}, "redirect_uri": {redirect},
		"resource": {"https://mcp.example.org/mcp"},
	})
	if status != 200 {
		t.Fatalf("code exchange = %d %v", status, tok)
	}
	access, _ := tok["access_token"].(string)
	refresh, _ := tok["refresh_token"].(string)
	if access == "" || refresh == "" || tok["token_type"] != "Bearer" {
		t.Fatalf("token response = %v", tok)
	}
	if tok["scope"] != "sandbox:read sandbox:write" {
		t.Fatalf("scope = %v", tok["scope"])
	}
	// The access token validates against the store with its scopes.
	rec, ok := s.store.Access(access)
	if !ok || len(rec.Scopes) != 2 || rec.Resource != "https://mcp.example.org/mcp" {
		t.Fatalf("stored access = %+v, %v", rec, ok)
	}
	// Refresh rotates: the new pair works, the old refresh is spent.
	status, tok2 := exchangeCode(t, srv.URL, url.Values{
		"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refresh},
	})
	if status != 200 {
		t.Fatalf("refresh = %d %v", status, tok2)
	}
	if tok2["refresh_token"] == refresh || tok2["access_token"] == access {
		t.Fatal("refresh did not rotate the pair")
	}
	// Replaying the spent refresh revokes the whole grant: even the fresh
	// pair dies with it.
	status, replay := exchangeCode(t, srv.URL, url.Values{
		"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refresh},
	})
	if status != 400 || replay["error"] != "invalid_grant" {
		t.Fatalf("replay = %d %v", status, replay)
	}
	status, _ = exchangeCode(t, srv.URL, url.Values{
		"grant_type": {"refresh_token"}, "client_id": {clientID},
		"refresh_token": {tok2["refresh_token"].(string)},
	})
	if status != 400 {
		t.Fatal("grant survived a refresh replay")
	}
	if _, ok := s.store.Access(tok2["access_token"].(string)); ok {
		t.Fatal("access token survived its grant's revocation")
	}
}

func TestAuthorizeRejects(t *testing.T) {
	s := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	_, out := registerClient(t, srv.URL, `{"redirect_uris":["https://app.example/cb"]}`)
	clientID := out["client_id"].(string)
	_, challenge := pkcePair(t)
	base := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://app.example/cb"},
		"scope": {"sandbox:read"}, "state": {"st"}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}, "resource": {"https://mcp.example.org/mcp"},
	}
	noRedirect := map[string]url.Values{
		"unknown client":    with(base, "client_id", "client_nope"),
		"redirect mismatch": with(base, "redirect_uri", "https://evil.example/cb"),
		"missing redirect":  without(base, "redirect_uri"),
		"CIMD unreachable":  with(base, "client_id", "https://127.0.0.1:9/meta"),
		"missing client":    without(base, "client_id"),
	}
	for name, q := range noRedirect {
		resp, err := http.Get(srv.URL + "/oauth/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("%s: status %d, want direct 400", name, resp.StatusCode)
		}
	}
	redirectErr := map[string]url.Values{
		"bad response_type": with(base, "response_type", "token"),
		"no challenge":      without(base, "code_challenge"),
		"plain method":      with(base, "code_challenge_method", "plain"),
		"short challenge":   with(base, "code_challenge", "short"),
		"bad scope":         with(base, "scope", "sandbox:admin"),
		"bad resource":      with(base, "resource", "https://evil.example/mcp"),
	}
	for name, q := range redirectErr {
		client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		resp, err := client.Get(srv.URL + "/oauth/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 302 {
			t.Errorf("%s: status %d, want 302 with error", name, resp.StatusCode)
			continue
		}
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if loc.Query().Get("error") == "" || loc.Query().Get("state") != "st" {
			t.Errorf("%s: redirect lacks error/state: %s", name, loc)
		}
	}
}

func with(v url.Values, k, val string) url.Values {
	out := url.Values{}
	for key, vs := range v {
		out[key] = append([]string{}, vs...)
	}
	out.Set(k, val)
	return out
}

func without(v url.Values, k string) url.Values {
	out := url.Values{}
	for key, vs := range v {
		if key == k {
			continue
		}
		out[key] = append([]string{}, vs...)
	}
	return out
}

func TestAuthorizeDenyAndBadToken(t *testing.T) {
	s := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	_, out := registerClient(t, srv.URL, `{"redirect_uris":["https://app.example/cb"]}`)
	clientID := out["client_id"].(string)
	_, challenge := pkcePair(t)
	getReqid := func() string {
		q := url.Values{
			"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://app.example/cb"},
			"code_challenge": {challenge}, "code_challenge_method": {"S256"},
		}
		resp, err := http.Get(srv.URL + "/oauth/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		page, _ := io.ReadAll(resp.Body)
		m := reqidRe.FindSubmatch(page)
		if m == nil {
			t.Fatalf("no reqid in %s", page)
		}
		return string(m[1])
	}
	// Deny redirects access_denied and consumes the request.
	status, hdr, _ := postFormNoRedirect(t, srv.URL+"/oauth/authorize", url.Values{
		"reqid": {getReqid()}, "decision": {"deny"},
	})
	if status != 302 {
		t.Fatalf("deny = %d", status)
	}
	loc, _ := url.Parse(hdr.Get("Location"))
	if loc.Query().Get("error") != "access_denied" {
		t.Fatalf("deny redirect = %s", loc)
	}
	// A bad API token re-renders with an error and keeps the request pending.
	reqid := getReqid()
	status, _, page := postFormNoRedirect(t, srv.URL+"/oauth/authorize", url.Values{
		"reqid": {reqid}, "decision": {"approve"}, "api_token": {"wrong"},
	})
	if status != 200 || !strings.Contains(string(page), "did not authenticate") {
		t.Fatalf("bad token = %d %s", status, page)
	}
	status, _, _ = postFormNoRedirect(t, srv.URL+"/oauth/authorize", url.Values{
		"reqid": {reqid}, "decision": {"approve"}, "api_token": {"api-token-ok"},
	})
	if status != 302 {
		t.Fatalf("approve after bad token = %d, want 302", status)
	}
	// Unknown reqids fail closed.
	status, _, _ = postFormNoRedirect(t, srv.URL+"/oauth/authorize", url.Values{
		"reqid": {"bogus"}, "decision": {"approve"}, "api_token": {"api-token-ok"},
	})
	if status != 400 {
		t.Fatalf("bogus reqid = %d, want 400", status)
	}
}

func TestTokenRejects(t *testing.T) {
	s := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	code, clientID, verifier, redirect := fullCodeFlow(t, srv.URL, s)
	good := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID},
		"code": {code}, "code_verifier": {verifier}, "redirect_uri": {redirect},
	}
	// Wrong verifier consumes the code: the retry with the right one fails too.
	badVerifier, _ := pkcePair(t)
	status, out := exchangeCode(t, srv.URL, with(good, "code_verifier", badVerifier))
	if status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("bad verifier = %d %v", status, out)
	}
	status, _ = exchangeCode(t, srv.URL, good)
	if status != 400 {
		t.Fatal("code survived a failed exchange")
	}
	// Each tamper case mints a fresh code: the first present consumes it, so
	// reusing one code would fail every case for the wrong reason. The wrong
	// client is a second *registered* client, so the exchange reaches the
	// code's client binding instead of failing on an unknown id.
	_, other := registerClient(t, srv.URL, `{"redirect_uris":["https://app.example/cb"]}`)
	otherID := other["client_id"].(string)
	tampers := map[string]struct {
		mutate func(url.Values) url.Values
		want   string
	}{
		"wrong redirect": {func(f url.Values) url.Values { return with(f, "redirect_uri", "https://app.example/other") }, "invalid_grant"},
		"wrong client":   {func(f url.Values) url.Values { return with(f, "client_id", otherID) }, "invalid_grant"},
		"bad resource":   {func(f url.Values) url.Values { return with(f, "resource", "https://evil.example/mcp") }, "invalid_target"},
	}
	for name, tc := range tampers {
		c, cid, v, r := fullCodeFlow(t, srv.URL, s)
		form := tc.mutate(url.Values{
			"grant_type": {"authorization_code"}, "client_id": {cid},
			"code": {c}, "code_verifier": {v}, "redirect_uri": {r},
		})
		status, out := exchangeCode(t, srv.URL, form)
		if status != 400 || out["error"] != tc.want {
			t.Errorf("%s: = %d %v, want 400 %s", name, status, out, tc.want)
		}
	}
	// Unknown grant type and JSON (non-form) bodies.
	status, out = exchangeCode(t, srv.URL, url.Values{"grant_type": {"password"}, "client_id": {clientID}})
	if status != 400 || out["error"] != "unsupported_grant_type" {
		t.Fatalf("password grant = %d %v", status, out)
	}
	resp, err := http.Post(srv.URL+"/oauth/token", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("JSON token body = %d, want 400", resp.StatusCode)
	}
	// Credentials smuggled in the query string are not read.
	resp, err = http.Post(srv.URL+"/oauth/token?grant_type=refresh_token&client_id="+clientID+"&refresh_token=x",
		"application/x-www-form-urlencoded", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var qout map[string]any
	_ = json.Unmarshal(raw, &qout)
	if resp.StatusCode == 200 || qout["error"] == "invalid_grant" {
		t.Fatalf("query credentials honored: %d %s", resp.StatusCode, raw)
	}
}

func TestClientCredentials(t *testing.T) {
	newSrv := func(testClient string) (*Server, *httptest.Server) {
		dir := t.TempDir()
		tokFile := filepath.Join(dir, "api-token")
		if err := os.WriteFile(tokFile, []byte("operator-token\n"), 0600); err != nil {
			t.Fatal(err)
		}
		st, err := Open(filepath.Join(dir, "state.json"))
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewServer(Config{
			PublicURL: "https://mcp.example.org", StorePath: filepath.Join(dir, "state.json"),
			APIBase: "unix:///nonexistent", APITokenFile: tokFile, TestClient: testClient,
		}, st)
		if err != nil {
			t.Fatal(err)
		}
		return s, httptest.NewServer(s.Handler())
	}
	t.Run("enabled", func(t *testing.T) {
		s, srv := newSrv("test-id:test-secret")
		defer srv.Close()
		status, out := exchangeCode(t, srv.URL, url.Values{
			"grant_type": {"client_credentials"}, "client_id": {"test-id"}, "client_secret": {"test-secret"},
		})
		if status != 200 {
			t.Fatalf("client_credentials = %d %v", status, out)
		}
		if out["access_token"] == "" || tokHas(out, "refresh_token") {
			t.Fatalf("response = %v", out)
		}
		if _, ok := s.store.Access(out["access_token"].(string)); !ok {
			t.Fatal("issued token does not validate")
		}
		// Wrong secret: 401, and the id cannot use other grants.
		status, _ = exchangeCode(t, srv.URL, url.Values{
			"grant_type": {"client_credentials"}, "client_id": {"test-id"}, "client_secret": {"wrong"},
		})
		if status != 401 {
			t.Fatalf("bad secret = %d, want 401", status)
		}
		status, out = exchangeCode(t, srv.URL, url.Values{
			"grant_type": {"authorization_code"}, "client_id": {"test-id"}, "client_secret": {"test-secret"},
		})
		if status != 400 || out["error"] != "unsupported_grant_type" {
			t.Fatalf("code grant on test id = %d %v", status, out)
		}
	})
	t.Run("disabled", func(t *testing.T) {
		_, srv := newSrv("")
		defer srv.Close()
		status, out := exchangeCode(t, srv.URL, url.Values{
			"grant_type": {"client_credentials"}, "client_id": {"test-id"}, "client_secret": {"test-secret"},
		})
		if status != 400 {
			t.Fatalf("disabled grant = %d %v", status, out)
		}
	})
}

func tokHas(m map[string]any, k string) bool {
	_, ok := m[k]
	return ok
}

func TestCIMDAuthorize(t *testing.T) {
	s := testServer(t)
	var doc string
	meta := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(doc))
	}))
	defer meta.Close()
	s.cimdClient = localTLSClient(meta)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	doc = `{"client_id":` + quote(meta.URL) + `,"redirect_uris":["https://app.example/cb"],"client_name":"cimd-app"}`
	_, challenge := pkcePair(t)
	q := url.Values{
		"response_type": {"code"}, "client_id": {meta.URL}, "redirect_uri": {"https://app.example/cb"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	resp, err := http.Get(srv.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	page, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(page), "cimd-app") {
		t.Fatalf("CIMD authorize = %d %s", resp.StatusCode, page)
	}
	if _, ok := s.store.Client(meta.URL); !ok {
		t.Fatal("CIMD snapshot not persisted")
	}
	// A redirect outside the document fails closed without redirecting.
	q2 := url.Values{
		"response_type": {"code"}, "client_id": {meta.URL}, "redirect_uri": {"https://evil.example/cb"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	resp2, err := http.Get(srv.URL + "/oauth/authorize?" + q2.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 400 {
		t.Fatalf("CIMD redirect escape = %d, want 400", resp2.StatusCode)
	}
}

func TestRefreshNarrowing(t *testing.T) {
	s := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	code, clientID, verifier, redirect := fullCodeFlow(t, srv.URL, s)
	_, tok := exchangeCode(t, srv.URL, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID},
		"code": {code}, "code_verifier": {verifier}, "redirect_uri": {redirect},
	})
	status, narrow := exchangeCode(t, srv.URL, url.Values{
		"grant_type": {"refresh_token"}, "client_id": {clientID},
		"refresh_token": {tok["refresh_token"].(string)}, "scope": {"sandbox:read"},
	})
	if status != 200 || narrow["scope"] != "sandbox:read" {
		t.Fatalf("narrow = %d %v", status, narrow)
	}
	status, wide := exchangeCode(t, srv.URL, url.Values{
		"grant_type": {"refresh_token"}, "client_id": {clientID},
		"refresh_token": {narrow["refresh_token"].(string)}, "scope": {"sandbox:read sandbox:write sandbox:admin"},
	})
	if status != 400 || wide["error"] != "invalid_scope" {
		t.Fatalf("widen = %d %v", status, wide)
	}
}
