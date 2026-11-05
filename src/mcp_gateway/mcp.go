// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxMCPBody caps a Streamable HTTP request: tool arguments can carry a whole
// file as base64 (4 MiB becomes ~5.4), so this fits the largest write plus its
// envelope.
const maxMCPBody = 8 << 20

// protocolVersions the gateway speaks, newest first. A client asking for one
// of these gets it echoed; anything else gets the newest (the handlers behave
// identically across versions — the gateway is stateless either way).
var protocolVersions = []string{"2026-07-28", "2025-11-25"}

// JSON-RPC 2.0 error codes used on the wire.
const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
	rpcInternalError  = -32603
	rpcNoScope        = -32001 // server-defined: token lacks the tool's scope.
)

type rpcRequest struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id"`
	Result  any              `json:"result,omitempty"`
	Error   *rpcError        `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func rpcErr(id *json.RawMessage, code int, msg string) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

// mcpPOST serves the Streamable HTTP endpoint: one JSON-RPC message or a batch
// per POST, answered as JSON or SSE per the client's Accept.
func (s *Server) mcpPOST(w http.ResponseWriter, r *http.Request) {
	if !s.originAllowed(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden_origin"})
		return
	}
	var rec *AccessToken
	if tok := bearerToken(r); tok != "" {
		if t, valid := s.store.Access(tok); valid && t.Resource == s.resourceURL() {
			rec = t
		}
	}
	if rec == nil {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(
			`Bearer resource_metadata=%q, error="invalid_token"`,
			s.cfg.PublicURL+"/.well-known/oauth-protected-resource"))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxMCPBody+1))
	if err != nil || len(raw) == 0 {
		writeRPC(w, r, rpcErr(nil, rpcParseError, "unreadable body"))
		return
	}
	if len(raw) > maxMCPBody {
		writeRPC(w, r, rpcErr(nil, rpcInvalidRequest, "request over 8 MiB"))
		return
	}
	msgs, batch, bad := parseRPCBatch(raw)
	if bad {
		writeRPC(w, r, rpcErr(nil, rpcParseError, "request is not JSON"))
		return
	}
	if len(msgs) == 0 {
		writeRPC(w, r, rpcErr(nil, rpcInvalidRequest, "empty batch"))
		return
	}
	var out []*rpcResponse
	for _, m := range msgs {
		if m.JSONRPC != "2.0" || m.Method == "" {
			if m.ID != nil {
				out = append(out, rpcErr(m.ID, rpcInvalidRequest, "not a JSON-RPC 2.0 request"))
			}
			continue
		}
		res := s.dispatch(r, rec, m)
		if m.ID != nil {
			out = append(out, res)
		}
		// Notifications (no id) get no response, by definition.
	}
	if len(out) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if batch {
		writeRPC(w, r, out)
	} else {
		writeRPC(w, r, out[0])
	}
}

// parseRPCBatch accepts one message object or an array of them.
func parseRPCBatch(raw []byte) (msgs []rpcRequest, batch bool, bad bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, false, true
	}
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &msgs); err != nil {
			return nil, false, true
		}
		return msgs, true, false
	}
	var one rpcRequest
	if err := json.Unmarshal(trimmed, &one); err != nil {
		return nil, false, true
	}
	return []rpcRequest{one}, false, false
}

// writeRPC serializes one response or a batch as SSE when the client Accept()s
// event streams, else as JSON. Plain-JSON clients (curl, tests) that send no
// Accept get JSON.
func writeRPC(w http.ResponseWriter, r *http.Request, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "encode failure"})
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		writeSSE(w, raw)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || tok == "" || strings.Contains(tok, " ") {
		return ""
	}
	return tok
}

// originAllowed is the DNS-rebinding rule: server-side MCP clients send no
// Origin, the Inspector sends a loopback one, and anything else must be the
// public host itself.
func (s *Server) originAllowed(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" {
		return false
	}
	if isLoopbackHost(u.Hostname()) {
		return true
	}
	pub, err := url.Parse(s.cfg.PublicURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, pub.Host)
}

// mcpGET and mcpDELETE exist only to say there are no sessions: a client that
// was issued no Mcp-Session-Id must not open a stream or close one.
func (s *Server) mcpGET(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", "POST")
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "no sessions: this server is stateless"})
}

func (s *Server) mcpDELETE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", "POST")
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "no sessions: this server is stateless"})
}

// dispatch routes one JSON-RPC message. res.ID echoes the request id; callers
// drop the response for notifications.
func (s *Server) dispatch(r *http.Request, tok *AccessToken, m rpcRequest) *rpcResponse {
	id := m.ID
	switch m.Method {
	case "initialize":
		return s.rpcInitialize(id, m.Params)
	case "notifications/initialized":
		return &rpcResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{}}
	case "ping":
		return &rpcResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{}}
	case "tools/list":
		return &rpcResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{"tools": toolDefs}}
	case "tools/call":
		return s.rpcToolCall(r.Context(), id, tok, m.Params)
	default:
		return rpcErr(id, rpcMethodNotFound, "unknown method "+m.Method)
	}
}

func (s *Server) rpcInitialize(id *json.RawMessage, params json.RawMessage) *rpcResponse {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return rpcErr(id, rpcInvalidParams, "initialize params are not an object")
		}
	}
	version := protocolVersions[0]
	for _, v := range protocolVersions {
		if p.ProtocolVersion == v {
			version = v
			break
		}
	}
	return &rpcResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": "sandbox-mcp-gateway", "version": version},
	}}
}
