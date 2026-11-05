// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxAPIResponse caps one sandbox-api reply: file bodies run to 4 MiB.
const maxAPIResponse = 8 << 20

// APIClient speaks the #27 control-plane API over TCP or a Unix socket. The
// gateway holds no engine state of its own; every tool call is one API call.
type APIClient struct {
	http *http.Client
	base string // "http://localhost" for unix, else the configured base.
}

// NewAPIClient builds a client for an --api base: http(s)://host:port or
// unix:///path/to/api.sock.
func NewAPIClient(apiBase string) (*APIClient, error) {
	if rest, ok := strings.CutPrefix(apiBase, "unix://"); ok {
		if rest == "" {
			return nil, fmt.Errorf("bad api base %q: missing socket path", apiBase)
		}
		path := rest
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		}
		return &APIClient{http: &http.Client{Transport: tr}, base: "http://localhost"}, nil
	}
	if !strings.HasPrefix(apiBase, "http://") && !strings.HasPrefix(apiBase, "https://") {
		return nil, fmt.Errorf("bad api base %q: want http(s):// or unix://", apiBase)
	}
	return &APIClient{http: &http.Client{}, base: strings.TrimSuffix(apiBase, "/")}, nil
}

// get performs an authenticated GET and returns status + bounded body.
func (c *APIClient) get(ctx context.Context, token, path string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.base+path, nil)
	if err != nil {
		return 0, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

// ValidToken reports whether the token authenticates against sandbox-api. The
// consent page uses it to prove the consenter owns a live principal; the token
// itself is never stored.
func (c *APIClient) ValidToken(token string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	status, _, err := c.get(ctx, token, "/v1/sessions")
	return err == nil && status == http.StatusOK
}

// apiResult is one sandbox-api reply: status plus the bounded body.
type apiResult struct {
	Status int
	Body   []byte
}

// json decodes a JSON body best-effort; nil when the body is not an object.
func (r *apiResult) json() map[string]any {
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		return nil
	}
	return m
}

// errText renders the API's {"error":{"code","message"}} envelope, or the bare
// status when the body carries no envelope.
func (r *apiResult) errText() string {
	if m := r.json(); m != nil {
		if e, ok := m["error"].(map[string]any); ok {
			code, _ := e["code"].(string)
			msg, _ := e["message"].(string)
			if code != "" || msg != "" {
				return fmt.Sprintf("%s: %s (http %d)", code, msg, r.Status)
			}
		}
	}
	return fmt.Sprintf("http %d", r.Status)
}

// do performs one authenticated request. query may be nil; body with a
// contentType is sent verbatim (JSON callers marshal first).
func (c *APIClient) do(ctx context.Context, token, method, path string, query url.Values, body []byte, contentType string, headers map[string]string) (*apiResult, error) {
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxAPIResponse {
		return nil, fmt.Errorf("api reply over %d bytes", maxAPIResponse)
	}
	return &apiResult{Status: resp.StatusCode, Body: raw}, nil
}

func (c *APIClient) doJSON(ctx context.Context, token, method, path string, query url.Values, fields map[string]any, headers map[string]string) (*apiResult, error) {
	var body []byte
	if fields != nil {
		var err error
		if body, err = json.Marshal(fields); err != nil {
			return nil, err
		}
	}
	return c.do(ctx, token, method, path, query, body, "application/json", headers)
}

func esc(id string) string { return url.PathEscape(id) }

// The typed wrappers below map 1:1 onto the #27 endpoints; tools.go formats
// their results for models.

func (c *APIClient) CreateSession(ctx context.Context, token string, fields map[string]any) (*apiResult, error) {
	return c.doJSON(ctx, token, "POST", "/v1/sessions", nil, fields, nil)
}

func (c *APIClient) ListSessions(ctx context.Context, token string) (*apiResult, error) {
	return c.do(ctx, token, "GET", "/v1/sessions", nil, nil, "", nil)
}

func (c *APIClient) GetSession(ctx context.Context, token, id string) (*apiResult, error) {
	return c.do(ctx, token, "GET", "/v1/sessions/"+esc(id), nil, nil, "", nil)
}

func (c *APIClient) DeleteSession(ctx context.Context, token, id string) (*apiResult, error) {
	return c.do(ctx, token, "DELETE", "/v1/sessions/"+esc(id), nil, nil, "", nil)
}

func (c *APIClient) RenewSession(ctx context.Context, token, id string, fields map[string]any) (*apiResult, error) {
	return c.doJSON(ctx, token, "POST", "/v1/sessions/"+esc(id)+"/renew", nil, fields, nil)
}

func (c *APIClient) Exec(ctx context.Context, token, id string, fields map[string]any, idemKey string) (*apiResult, error) {
	var headers map[string]string
	if idemKey != "" {
		headers = map[string]string{"Idempotency-Key": idemKey}
	}
	return c.doJSON(ctx, token, "POST", "/v1/sessions/"+esc(id)+"/exec", nil, fields, headers)
}

func (c *APIClient) PutFile(ctx context.Context, token, id, path string, data []byte, appendMode, exclusive bool) (*apiResult, error) {
	q := url.Values{"path": {path}}
	if appendMode {
		q.Set("append", "1")
	}
	if exclusive {
		q.Set("exclusive", "1")
	}
	return c.do(ctx, token, "PUT", "/v1/sessions/"+esc(id)+"/files", q, data, "application/octet-stream", nil)
}

func (c *APIClient) GetFile(ctx context.Context, token, id, path string) (*apiResult, error) {
	return c.do(ctx, token, "GET", "/v1/sessions/"+esc(id)+"/files", url.Values{"path": {path}}, nil, "", nil)
}

func (c *APIClient) DeleteFile(ctx context.Context, token, id, path string, recursive bool) (*apiResult, error) {
	q := url.Values{"path": {path}}
	if recursive {
		q.Set("recursive", "1")
	}
	return c.do(ctx, token, "DELETE", "/v1/sessions/"+esc(id)+"/files", q, nil, "", nil)
}

func (c *APIClient) StatPath(ctx context.Context, token, id, path string) (*apiResult, error) {
	return c.do(ctx, token, "GET", "/v1/sessions/"+esc(id)+"/stat", url.Values{"path": {path}}, nil, "", nil)
}

func (c *APIClient) ListPath(ctx context.Context, token, id, path string) (*apiResult, error) {
	return c.do(ctx, token, "GET", "/v1/sessions/"+esc(id)+"/ls", url.Values{"path": {path}}, nil, "", nil)
}

func (c *APIClient) Mkdir(ctx context.Context, token, id string, fields map[string]any) (*apiResult, error) {
	return c.doJSON(ctx, token, "POST", "/v1/sessions/"+esc(id)+"/mkdir", nil, fields, nil)
}
