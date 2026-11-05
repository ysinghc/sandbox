// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// recordedCall is one request the fake #27 API received.
type recordedCall struct {
	method string
	path   string
	query  string
	header http.Header
	body   []byte
	json   map[string]any
}

// fakeAPI27 is a scripted sandbox-api: canned responses shaped like the real
// ones (see jb_session/jb_exec_result), every call recorded for passthrough
// assertions.
type fakeAPI27 struct {
	t     *testing.T
	mu    sync.Mutex
	calls []recordedCall
}

func (f *fakeAPI27) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var jm map[string]any
		_ = json.Unmarshal(body, &jm)
		f.mu.Lock()
		f.calls = append(f.calls, recordedCall{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), body, jm})
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer operator-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		je := func(v any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		}
		apiErr := func(status int, code, msg string) {
			w.WriteHeader(status)
			je(map[string]any{"error": map[string]any{"code": code, "message": msg}})
		}
		session := map[string]any{"id": "ses_abc", "key": "k-1", "state": "ready",
			"template": "debian", "memory_mib": 512, "vcpus": 1, "created_at": 1700000000,
			"last_active_at": 1700000060, "expires_at": 1700604800, "workspace": "/workspace",
			"egress": map[string]any{"allow": nil}}
		p := r.URL.Path
		switch {
		case r.Method == "POST" && p == "/v1/sessions":
			w.WriteHeader(http.StatusCreated)
			je(session)
		case r.Method == "GET" && p == "/v1/sessions":
			je(map[string]any{"sessions": []any{session}})
		case r.Method == "GET" && p == "/v1/sessions/ses_abc":
			je(session)
		case r.Method == "DELETE" && p == "/v1/sessions/ses_abc":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "POST" && p == "/v1/sessions/ses_abc/renew":
			session["expires_at"] = 1700691200
			je(session)
		case r.Method == "POST" && p == "/v1/sessions/ses_abc/exec":
			je(map[string]any{"exit_code": 0, "term_signal": 0, "timed_out": false,
				"output_truncated": false, "duration_ms": 12, "stdout": "hi\n", "stderr": "",
				"stdout_bytes": 3, "stderr_bytes": 0, "stdout_returned": 3, "stderr_returned": 0,
				"encoding": "utf8"})
		case r.Method == "PUT" && p == "/v1/sessions/ses_abc/files":
			je(map[string]any{"path": r.URL.Query().Get("path"), "bytes": len(body)})
		case r.Method == "GET" && p == "/v1/sessions/ses_abc/files":
			if r.URL.Query().Get("path") == "/workspace/nope" {
				apiErr(404, "not_found", "no such file")
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write([]byte("file-bytes"))
		case r.Method == "DELETE" && p == "/v1/sessions/ses_abc/files":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "GET" && p == "/v1/sessions/ses_abc/stat":
			je(map[string]any{"path": r.URL.Query().Get("path"), "type": "file", "size": 10, "mode": "644", "mtime": 1700000100})
		case r.Method == "GET" && p == "/v1/sessions/ses_abc/ls":
			je(map[string]any{"path": r.URL.Query().Get("path"), "entries": []any{
				map[string]any{"name": "a.txt", "type": "file", "size": 10, "mtime": 1700000100},
				map[string]any{"name": "sub", "type": "dir", "size": 0, "mtime": 1700000200},
			}, "truncated": false})
		case r.Method == "POST" && p == "/v1/sessions/ses_abc/mkdir":
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(p, "/v1/sessions/"):
			apiErr(404, "not_found", "no such session")
		default:
			http.NotFound(w, r)
		}
	})
}

func (f *fakeAPI27) last() recordedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		f.t.Fatal("fake API received no calls")
	}
	return f.calls[len(f.calls)-1]
}

// toolServer wires a gateway to the fake API and returns a call helper bound
// to a full-scope token.
func toolServer(t *testing.T) (*fakeAPI27, string, func(method string, args map[string]any) map[string]any) {
	t.Helper()
	fake := &fakeAPI27{t: t}
	api := httptest.NewServer(fake.handler())
	t.Cleanup(api.Close)
	s := testServer(t)
	cli, err := NewAPIClient(api.URL)
	if err != nil {
		t.Fatal(err)
	}
	s.api = cli
	if err := s.store.SaveGrant(&Grant{ID: "g-tools", Principal: "operator", Scopes: allScopes}); err != nil {
		t.Fatal(err)
	}
	const tok = "tools-token"
	if err := s.store.SaveAccess(&AccessToken{TokenHash: hashSecret(tok), GrantID: "g-tools",
		Scopes: allScopes, Resource: s.resourceURL(), ExpiresAt: 2000000000}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	call := func(name string, args map[string]any) map[string]any {
		t.Helper()
		payload := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": name, "arguments": args}}
		raw, _ := json.Marshal(payload)
		status, _, body := mcpPost(t, srv.URL, tok, string(raw), "")
		if status != 200 {
			t.Fatalf("tools/call %s status = %d: %s", name, status, body)
		}
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("tools/call %s not JSON: %s", name, body)
		}
		return out
	}
	return fake, srv.URL, call
}

func callText(t *testing.T, out map[string]any) (string, bool) {
	t.Helper()
	if out["error"] != nil {
		t.Fatalf("unexpected protocol error: %v", out["error"])
	}
	res, _ := out["result"].(map[string]any)
	content, _ := res["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("content = %v", res["content"])
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	isErr, _ := res["isError"].(bool)
	return text, isErr
}

func TestToolCreateSession(t *testing.T) {
	fake, _, call := toolServer(t)
	out := call("create_session", map[string]any{
		"key": "k-1", "template": "debian", "memory_mib": 512, "ttl_seconds": 3600,
		"env": map[string]any{"A": "b"}, "egress_allow": []any{"pypi.org"},
	})
	text, isErr := callText(t, out)
	if isErr {
		t.Fatalf("isError: %s", text)
	}
	if !strings.Contains(text, "ses_abc") || !strings.Contains(text, "ready") {
		t.Fatalf("text = %q", text)
	}
	got := fake.last()
	if got.method != "POST" || got.path != "/v1/sessions" {
		t.Fatalf("api call = %s %s", got.method, got.path)
	}
	for k, want := range map[string]any{"key": "k-1", "template": "debian", "memory_mib": float64(512)} {
		if got.json[k] != want {
			t.Errorf("field %s = %v, want %v", k, got.json[k], want)
		}
	}
}

func TestToolListAndStatus(t *testing.T) {
	_, _, call := toolServer(t)
	text, isErr := callText(t, call("list_sessions", map[string]any{}))
	if isErr || !strings.Contains(text, "ses_abc") {
		t.Fatalf("list = %q err=%v", text, isErr)
	}
	text, isErr = callText(t, call("get_status", map[string]any{"session_id": "ses_abc"}))
	if isErr || !strings.Contains(text, "debian") || !strings.Contains(text, "1700604800") {
		t.Fatalf("status = %q err=%v", text, isErr)
	}
	out := call("get_status", map[string]any{"session_id": "ses_nope"})
	text, isErr = callText(t, out)
	if !isErr || !strings.Contains(text, "not_found") {
		t.Fatalf("missing session = %q err=%v", text, isErr)
	}
}

func TestToolRun(t *testing.T) {
	fake, _, call := toolServer(t)
	out := call("run", map[string]any{"session_id": "ses_abc", "command": "echo hi",
		"timeout_ms": 5000, "idempotency_key": "k-9"})
	text, isErr := callText(t, out)
	if isErr {
		t.Fatalf("isError: %s", text)
	}
	if !strings.Contains(text, "exit 0") || !strings.Contains(text, "hi") || !strings.Contains(text, "12 ms") {
		t.Fatalf("text = %q", text)
	}
	got := fake.last()
	if got.path != "/v1/sessions/ses_abc/exec" || got.json["command"] != "echo hi" {
		t.Fatalf("api call = %s %v", got.path, got.json)
	}
	if got.header.Get("Idempotency-Key") != "k-9" {
		t.Fatal("Idempotency-Key not forwarded")
	}
	// argv form.
	out = call("run", map[string]any{"session_id": "ses_abc", "argv": []any{"echo", "hi"}})
	if text, isErr := callText(t, out); isErr {
		t.Fatalf("argv form isError: %s", text)
	}
	if got := fake.last(); got.json["command"] != nil {
		t.Fatalf("argv form sent command: %v", got.json)
	}
}

func TestToolRunValidation(t *testing.T) {
	_, _, call := toolServer(t)
	for name, args := range map[string]map[string]any{
		"neither":   {"session_id": "ses_abc"},
		"both":      {"session_id": "ses_abc", "command": "id", "argv": []any{"id"}},
		"bad enc":   {"session_id": "ses_abc", "command": "id", "output_encoding": "rot13"},
		"both stds": {"session_id": "ses_abc", "command": "id", "stdin": "a", "stdin_base64": "Yg=="},
		"no sid":    {"command": "id"},
	} {
		out := call("run", args)
		if e, _ := out["error"].(map[string]any); e["code"] != float64(-32602) {
			t.Errorf("%s: = %v", name, out)
		}
	}
}

func TestToolFiles(t *testing.T) {
	fake, _, call := toolServer(t)
	text, isErr := callText(t, call("read_file", map[string]any{"session_id": "ses_abc", "path": "/workspace/f"}))
	if isErr || text != "file-bytes" {
		t.Fatalf("read = %q err=%v", text, isErr)
	}
	text, _ = callText(t, call("read_file", map[string]any{"session_id": "ses_abc", "path": "/workspace/f", "encoding": "base64"}))
	if text != "ZmlsZS1ieXRlcw==" {
		t.Fatalf("read base64 = %q", text)
	}
	out := call("read_file", map[string]any{"session_id": "ses_abc", "path": "/workspace/nope"})
	if text, isErr := callText(t, out); !isErr || !strings.Contains(text, "not_found") {
		t.Fatalf("missing file = %q err=%v", text, isErr)
	}
	text, isErr = callText(t, call("write_file", map[string]any{"session_id": "ses_abc", "path": "/workspace/w", "content": "hello"}))
	if isErr || !strings.Contains(text, "5 bytes") {
		t.Fatalf("write = %q err=%v", text, isErr)
	}
	if got := fake.last(); string(got.body) != "hello" || !strings.Contains(got.query, "path=") {
		t.Fatalf("write call = %s %q", got.query, got.body)
	}
	text, _ = callText(t, call("write_file", map[string]any{"session_id": "ses_abc", "path": "/workspace/w",
		"content_base64": "aGk=", "append": true, "exclusive": false}))
	if !strings.Contains(text, "appended 2 bytes") {
		t.Fatalf("append = %q", text)
	}
	if got := fake.last(); string(got.body) != "hi" || !strings.Contains(got.query, "append=1") {
		t.Fatalf("append call = %s %q", got.query, got.body)
	}
	out = call("write_file", map[string]any{"session_id": "ses_abc", "path": "/workspace/w"})
	if e, _ := out["error"].(map[string]any); e["code"] != float64(-32602) {
		t.Fatalf("contentless write = %v", out)
	}
	out = call("write_file", map[string]any{"session_id": "ses_abc", "path": "/workspace/w", "content_base64": "!!!"})
	if e, _ := out["error"].(map[string]any); e["code"] != float64(-32602) {
		t.Fatalf("bad base64 write = %v", out)
	}
}

func TestToolListStatMkdirDelete(t *testing.T) {
	fake, _, call := toolServer(t)
	text, isErr := callText(t, call("list_files", map[string]any{"session_id": "ses_abc"}))
	if isErr || !strings.Contains(text, "a.txt") || !strings.Contains(text, "sub") {
		t.Fatalf("ls = %q err=%v", text, isErr)
	}
	text, isErr = callText(t, call("get_file_stat", map[string]any{"session_id": "ses_abc", "path": "/workspace/a.txt"}))
	if isErr || !strings.Contains(text, "file, 10 bytes") || !strings.Contains(text, "mode 644") {
		t.Fatalf("stat = %q err=%v", text, isErr)
	}
	text, isErr = callText(t, call("make_directory", map[string]any{"session_id": "ses_abc", "path": "/workspace/d", "parents": true, "mode": 493}))
	if isErr || !strings.Contains(text, "created /workspace/d") {
		t.Fatalf("mkdir = %q err=%v", text, isErr)
	}
	if got := fake.last(); got.json["parents"] != true || got.json["mode"] != float64(493) {
		t.Fatalf("mkdir call = %v", got.json)
	}
	out := call("make_directory", map[string]any{"session_id": "ses_abc", "path": "/workspace/d", "mode": 999})
	if e, _ := out["error"].(map[string]any); e["code"] != float64(-32602) {
		t.Fatalf("bad mode mkdir = %v", out)
	}
	text, isErr = callText(t, call("delete_file", map[string]any{"session_id": "ses_abc", "path": "/workspace/d", "recursive": true}))
	if isErr || !strings.Contains(text, "removed /workspace/d") {
		t.Fatalf("delete = %q err=%v", text, isErr)
	}
	if got := fake.last(); got.method != "DELETE" || !strings.Contains(got.query, "recursive=1") {
		t.Fatalf("delete call = %s %s", got.method, got.query)
	}
}

func TestToolRenewDestroy(t *testing.T) {
	_, _, call := toolServer(t)
	text, isErr := callText(t, call("renew", map[string]any{"session_id": "ses_abc", "ttl_seconds": 7200}))
	if isErr || !strings.Contains(text, "1700691200") {
		t.Fatalf("renew = %q err=%v", text, isErr)
	}
	text, isErr = callText(t, call("destroy_session", map[string]any{"session_id": "ses_abc"}))
	if isErr || !strings.Contains(text, "deleted") || !strings.Contains(text, "workspace is kept until its TTL") {
		t.Fatalf("destroy = %q err=%v", text, isErr)
	}
	out := call("destroy_session", map[string]any{"session_id": "ses_nope"})
	if text, isErr := callText(t, out); !isErr || !strings.Contains(text, "not_found") {
		t.Fatalf("destroy missing = %q err=%v", text, isErr)
	}
}
