// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testServerWithToken builds a server and mints a live access token with the
// given scopes directly in the store.
func testServerWithToken(t *testing.T, scopes []string) (*Server, *httptest.Server, string) {
	t.Helper()
	s := testServer(t)
	if err := s.store.SaveGrant(&Grant{ID: "g-tok", ClientID: "c", Principal: "operator", Scopes: scopes}); err != nil {
		t.Fatal(err)
	}
	const tok = "mcp-access-token"
	if err := s.store.SaveAccess(&AccessToken{TokenHash: hashSecret(tok), GrantID: "g-tok",
		ClientID: "c", Scopes: scopes, Resource: s.resourceURL(),
		ExpiresAt: time.Now().Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	return s, httptest.NewServer(s.Handler()), tok
}

func mcpPost(t *testing.T, url, token, body, accept string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest("POST", url+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, raw
}

func mcpCall(t *testing.T, url, token, payload string) map[string]any {
	t.Helper()
	status, _, raw := mcpPost(t, url, token, payload, "application/json")
	if status != 200 {
		t.Fatalf("mcp call status = %d: %s", status, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("mcp call not JSON: %s", raw)
	}
	return out
}

func TestMCPRequiresAuth(t *testing.T) {
	_, srv, _ := testServerWithToken(t, allScopes)
	defer srv.Close()
	status, hdr, _ := mcpPost(t, srv.URL, "", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, "")
	if status != 401 {
		t.Fatalf("no token = %d, want 401", status)
	}
	if wa := hdr.Get("WWW-Authenticate"); !strings.Contains(wa, "oauth-protected-resource") {
		t.Fatalf("WWW-Authenticate lacks resource metadata: %q", wa)
	}
	status, _, _ = mcpPost(t, srv.URL, "bogus", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, "")
	if status != 401 {
		t.Fatalf("bad token = %d, want 401", status)
	}
}

func TestMCPRejectsForeignResource(t *testing.T) {
	s := testServer(t)
	if err := s.store.SaveGrant(&Grant{ID: "g-f", Principal: "operator", Scopes: allScopes}); err != nil {
		t.Fatal(err)
	}
	const tok = "foreign-resource-token"
	_ = s.store.SaveAccess(&AccessToken{TokenHash: hashSecret(tok), GrantID: "g-f",
		Scopes: allScopes, Resource: "https://other.example/mcp",
		ExpiresAt: time.Now().Add(time.Hour).Unix()})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	status, _, _ := mcpPost(t, srv.URL, tok, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, "")
	if status != 401 {
		t.Fatalf("foreign-resource token = %d, want 401", status)
	}
}

func TestMCPInitializeNegotiates(t *testing.T) {
	_, srv, tok := testServerWithToken(t, allScopes)
	defer srv.Close()
	for client, want := range map[string]string{
		"2025-11-25": "2025-11-25", "2026-07-28": "2026-07-28", "1999-01-01": "2026-07-28", "": "2026-07-28",
	} {
		out := mcpCall(t, srv.URL, tok, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":`+quote(client)+`}}`)
		res, _ := out["result"].(map[string]any)
		if res["protocolVersion"] != want {
			t.Errorf("client %q negotiated %v, want %s", client, res["protocolVersion"], want)
		}
		if _, ok := res["capabilities"].(map[string]any)["tools"]; !ok {
			t.Errorf("client %q: no tools capability", client)
		}
	}
	// Stateless: no session id is ever issued.
	status, hdr, _ := mcpPost(t, srv.URL, tok, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "")
	if status != 200 || hdr.Get("Mcp-Session-Id") != "" {
		t.Fatalf("initialize = %d session %q", status, hdr.Get("Mcp-Session-Id"))
	}
}

func TestMCPPingAndInitialized(t *testing.T) {
	_, srv, tok := testServerWithToken(t, allScopes)
	defer srv.Close()
	out := mcpCall(t, srv.URL, tok, `{"jsonrpc":"2.0","id":7,"method":"ping"}`)
	if out["error"] != nil {
		t.Fatalf("ping error: %v", out["error"])
	}
	status, _, raw := mcpPost(t, srv.URL, tok, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, "")
	if status != 202 || len(raw) != 0 {
		t.Fatalf("initialized notification = %d %q, want 202 empty", status, raw)
	}
}

func TestMCPToolsList(t *testing.T) {
	_, srv, tok := testServerWithToken(t, allScopes)
	defer srv.Close()
	out := mcpCall(t, srv.URL, tok, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	res, _ := out["result"].(map[string]any)
	tools, _ := res["tools"].([]any)
	if len(tools) != 12 {
		t.Fatalf("tools/list returned %d tools, want 12", len(tools))
	}
	want := map[string]bool{
		"create_session": true, "list_sessions": true, "get_status": true, "run": true,
		"read_file": true, "write_file": true, "list_files": true, "get_file_stat": true,
		"make_directory": true, "delete_file": true, "renew": true, "destroy_session": true,
	}
	for _, e := range tools {
		td, _ := e.(map[string]any)
		name, _ := td["name"].(string)
		if !want[name] {
			t.Errorf("unexpected tool %q", name)
			continue
		}
		delete(want, name)
		if td["description"] == "" || td["inputSchema"] == nil || td["annotations"] == nil {
			t.Errorf("tool %q lacks description/schema/annotations", name)
		}
	}
	for name := range want {
		t.Errorf("tool %q missing from tools/list", name)
	}
}

func TestMCPProtocolErrors(t *testing.T) {
	_, srv, tok := testServerWithToken(t, allScopes)
	defer srv.Close()
	out := mcpCall(t, srv.URL, tok, `{"jsonrpc":"2.0","id":1,"method":"nope"}`)
	if errObj, _ := out["error"].(map[string]any); errObj["code"] != float64(-32601) {
		t.Fatalf("unknown method = %v", out["error"])
	}
	status, _, raw := mcpPost(t, srv.URL, tok, `{"jsonrpc":`, "")
	var perr map[string]any
	_ = json.Unmarshal(raw, &perr)
	if status != 200 {
		t.Fatalf("garbage body status = %d", status)
	}
	if e, _ := perr["error"].(map[string]any); e["code"] != float64(-32700) {
		t.Fatalf("garbage body = %v", perr)
	}
	out = mcpCall(t, srv.URL, tok, `[]`)
	if e, _ := out["error"].(map[string]any); e["code"] != float64(-32600) {
		t.Fatalf("empty batch = %v", out)
	}
}

func TestMCPBatch(t *testing.T) {
	_, srv, tok := testServerWithToken(t, allScopes)
	defer srv.Close()
	status, _, raw := mcpPost(t, srv.URL, tok, `[
		{"jsonrpc":"2.0","id":1,"method":"ping"},
		{"jsonrpc":"2.0","method":"notifications/initialized"},
		{"jsonrpc":"2.0","id":2,"method":"nope"}]`, "")
	if status != 200 {
		t.Fatalf("batch status = %d", status)
	}
	var out []map[string]any
	if err := json.Unmarshal(raw, &out); err != nil || len(out) != 2 {
		t.Fatalf("batch response = %s", raw)
	}
	if out[0]["error"] != nil {
		t.Fatalf("batch[0] error: %v", out[0])
	}
	if e, _ := out[1]["error"].(map[string]any); e["code"] != float64(-32601) {
		t.Fatalf("batch[1] = %v", out[1])
	}
}

func TestMCPSSE(t *testing.T) {
	_, srv, tok := testServerWithToken(t, allScopes)
	defer srv.Close()
	status, hdr, raw := mcpPost(t, srv.URL, tok, `{"jsonrpc":"2.0","id":3,"method":"ping"}`, "text/event-stream")
	if status != 200 {
		t.Fatalf("SSE status = %d", status)
	}
	if ct := hdr.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("SSE content type = %q", ct)
	}
	if !strings.HasPrefix(string(raw), "event: message\ndata: ") || !strings.HasSuffix(string(raw), "\n\n") {
		t.Fatalf("SSE framing = %q", raw)
	}
	var out map[string]any
	payload := strings.TrimSuffix(strings.TrimPrefix(string(raw), "event: message\ndata: "), "\n\n")
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		t.Fatalf("SSE payload not JSON: %q", payload)
	}
	if out["id"] != float64(3) || out["error"] != nil {
		t.Fatalf("SSE payload = %v", out)
	}
}

func TestMCPGetDelete405(t *testing.T) {
	_, srv, tok := testServerWithToken(t, allScopes)
	defer srv.Close()
	for _, method := range []string{"GET", "DELETE"} {
		req, _ := http.NewRequest(method, srv.URL+"/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 405 {
			t.Errorf("%s /mcp = %d, want 405", method, resp.StatusCode)
		}
	}
}

func TestMCPOrigin(t *testing.T) {
	_, srv, tok := testServerWithToken(t, allScopes)
	defer srv.Close()
	call := func(origin string) int {
		req, _ := http.NewRequest("POST", srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if st := call(""); st != 200 {
		t.Errorf("no origin = %d", st)
	}
	if st := call("https://mcp.example.org"); st != 200 {
		t.Errorf("public origin = %d", st)
	}
	if st := call("http://localhost:3000"); st != 200 {
		t.Errorf("loopback origin = %d", st)
	}
	if st := call("https://evil.example"); st != 403 {
		t.Errorf("foreign origin = %d, want 403", st)
	}
}

func TestMCPToolScopeEnforced(t *testing.T) {
	_, srv, tok := testServerWithToken(t, []string{"sandbox:read"})
	defer srv.Close()
	out := mcpCall(t, srv.URL, tok, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run","arguments":{"session_id":"ses_x","command":"id"}}}`)
	if e, _ := out["error"].(map[string]any); e["code"] != float64(-32001) {
		t.Fatalf("write tool on read token = %v", out)
	}
	// Unknown tools fail the same way regardless of scopes.
	out = mcpCall(t, srv.URL, tok, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nope"}}`)
	if e, _ := out["error"].(map[string]any); e["code"] != float64(-32602) {
		t.Fatalf("unknown tool = %v", out)
	}
}
