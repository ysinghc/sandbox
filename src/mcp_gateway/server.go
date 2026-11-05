// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// Scopes the gateway understands. Read covers the listing and inspection
// tools; write covers everything that creates, runs, changes or destroys.
const (
	ScopeRead  = "sandbox:read"
	ScopeWrite = "sandbox:write"
)

var allScopes = []string{ScopeRead, ScopeWrite}

// operatorPrincipal is the single sandbox-api principal M2 serves. Tool calls
// authenticate with the configured --api-token-file bearer token; per-user
// principals arrive with multi-tenancy (#17).
const operatorPrincipal = "operator"

// Lifetimes for OAuth artifacts.
const (
	codeTTL    = 10 * time.Minute
	accessTTL  = time.Hour
	refreshTTL = 30 * 24 * time.Hour
	pendingTTL = 10 * time.Minute
	maxClients = 128
)

// pendingAuth is one authorize request awaiting the user's decision. It lives
// in memory only: a restart drops pending approvals, which fail closed (the
// user simply starts the flow again).
type pendingAuth struct {
	clientID    string
	clientName  string
	redirectURI string
	scope       string
	state       string
	challenge   string
	resource    string
	expiresAt   int64
}

// Server wires configuration, state and the sandbox-api client to the HTTP
// routes. validateToken and cimdFetch are fields (not direct calls) so tests
// can stub the #27 round-trip and the CIMD fetch.
type Server struct {
	cfg         Config
	store       *Store
	api         *APIClient
	apiToken    string
	cimdClient  *http.Client
	validateAPI func(token string) bool

	mu      sync.Mutex
	pending map[string]*pendingAuth
}

// NewServer builds a serving instance. The API token is read once at startup.
func NewServer(cfg Config, st *Store) (*Server, error) {
	api, err := NewAPIClient(cfg.APIBase)
	if err != nil {
		return nil, err
	}
	tok, err := cfg.LoadAPIToken()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:        cfg,
		store:      st,
		api:        api,
		apiToken:   tok,
		cimdClient: cimdHTTPClient(),
		pending:    map[string]*pendingAuth{},
	}
	s.validateAPI = api.ValidToken
	return s, nil
}

// Handler registers every route.
func (s *Server) Handler() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.protectedResourceMeta)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.authServerMeta)
	mux.HandleFunc("POST /oauth/register", s.register)
	mux.HandleFunc("GET /oauth/authorize", s.authorizeForm)
	mux.HandleFunc("POST /oauth/authorize", s.authorizeSubmit)
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("POST /mcp", s.mcpPOST)
	mux.HandleFunc("GET /mcp", s.mcpGET)
	mux.HandleFunc("DELETE /mcp", s.mcpDELETE)
	return mux
}

// resourceURL is the canonical MCP resource: the token audience and the
// RFC 8707 indicator value.
func (s *Server) resourceURL() string { return s.cfg.PublicURL + "/mcp" }

// randomB64 returns n crypto-random bytes base64url-encoded (no padding).
func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
