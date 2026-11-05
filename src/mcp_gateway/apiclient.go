// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

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
