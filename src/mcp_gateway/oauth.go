// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// --- well-known metadata ---

func (s *Server) protectedResourceMeta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.resourceURL(),
		"authorization_servers":    []string{s.cfg.PublicURL},
		"scopes_supported":         allScopes,
		"bearer_methods_supported": []string{"header"},
	})
}

func (s *Server) authServerMeta(w http.ResponseWriter, r *http.Request) {
	p := s.cfg.PublicURL
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p,
		"authorization_endpoint":                p + "/oauth/authorize",
		"token_endpoint":                        p + "/oauth/token",
		"registration_endpoint":                 p + "/oauth/register",
		"scopes_supported":                      allScopes,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"client_id_metadata_document_supported": true,
	})
}

// --- dynamic client registration (RFC 7591) ---

// dcrRequest is the subset of client metadata the gateway honors. Unknown
// fields are ignored (clients send contacts, logos, software ids); the fields
// below are validated.
type dcrRequest struct {
	RedirectURIs      []string `json:"redirect_uris"`
	GrantTypes        []string `json:"grant_types"`
	ResponseTypes     []string `json:"response_types"`
	Scope             string   `json:"scope"`
	TokenEndpointAuth string   `json:"token_endpoint_auth_method"`
	ClientName        string   `json:"client_name"`
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxCIMDBytes))
	if err != nil || len(raw) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "unreadable request body")
		return
	}
	var req dcrRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "request is not JSON")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !validRedirectURI(u) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", fmt.Sprintf("redirect_uri %q must be https (or loopback http) with no fragment", u))
			return
		}
	}
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}
	for _, g := range grantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", fmt.Sprintf("grant_type %q unsupported", g))
			return
		}
	}
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}
	for _, t := range responseTypes {
		if t != "code" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", fmt.Sprintf("response_type %q unsupported", t))
			return
		}
	}
	if req.TokenEndpointAuth != "" && req.TokenEndpointAuth != "none" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "only public clients (token_endpoint_auth_method none) in M2")
		return
	}
	scope := req.Scope
	if scope == "" {
		scope = strings.Join(allScopes, " ")
	}
	if !validScopeSubset(scope) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", fmt.Sprintf("scope %q exceeds the supported scopes", scope))
		return
	}
	id, err := randomHex(16)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "randomness failure")
		return
	}
	client := &Client{
		ID:           "client_" + id,
		RedirectURIs: req.RedirectURIs,
		Name:         req.ClientName,
		CreatedAt:    time.Now().UTC().Unix(),
	}
	// Bound the registry: DCR is unauthenticated, so without a cap anyone
	// could grow the store file without bound.
	s.store.mu.Lock()
	n := len(s.store.db.Clients)
	s.store.mu.Unlock()
	if n >= maxClients {
		writeOAuthError(w, http.StatusForbidden, "invalid_client_metadata", "client registry full")
		return
	}
	if err := s.store.SaveClient(client); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "cannot persist client")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"client_id":                  client.ID,
		"client_name":                client.Name,
		"redirect_uris":              client.RedirectURIs,
		"grant_types":                grantTypes,
		"response_types":             responseTypes,
		"scope":                      scope,
		"token_endpoint_auth_method": "none",
		"client_id_issued_at":        client.CreatedAt,
	})
}

// validRedirectURI enforces the M2 rule: absolute https, or http on loopback
// for native apps and the Inspector, never carrying a fragment.
func validRedirectURI(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	if parsed.Fragment != "" || parsed.Host == "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	return parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())
}

func validScopeSubset(scope string) bool {
	for _, f := range strings.Fields(scope) {
		if f != ScopeRead && f != ScopeWrite {
			return false
		}
	}
	return true
}

// --- authorize ---

// resolveClient returns the client record for an authorize request: a DCR
// registration from the store, or a CIMD URL fetched and snapshotted. A stale
// snapshot covers a transient fetch failure; no snapshot and no fetch means no
// client.
func (s *Server) resolveClient(ctx context.Context, clientID string) (*Client, error) {
	if c, ok := s.store.Client(clientID); ok && !strings.HasPrefix(clientID, "https://") {
		return c, nil
	}
	if !strings.HasPrefix(clientID, "https://") {
		return nil, fmt.Errorf("unknown client")
	}
	doc, err := fetchCIMD(ctx, s.cimdClient, clientID)
	if err != nil {
		if c, ok := s.store.Client(clientID); ok {
			return c, nil
		}
		return nil, err
	}
	c := &Client{ID: clientID, RedirectURIs: doc.RedirectURIs, Name: doc.ClientName, CreatedAt: nowUnix()}
	if err := s.store.SaveClient(c); err != nil {
		return nil, err
	}
	return c, nil
}

// authorizeForm validates an authorization request and renders the consent
// page. Client and redirect_uri failures answer with a direct 400 page: the
// redirect target itself is untrusted, so nothing is sent there. Every other
// failure redirects back with an error code.
func (s *Server) authorizeForm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client, err := s.resolveClient(r.Context(), q.Get("client_id"))
	if err != nil {
		s.authorizeErrorPage(w, "unknown or unreachable client")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" || !contains(client.RedirectURIs, redirectURI) {
		s.authorizeErrorPage(w, "redirect_uri does not match this client")
		return
	}
	state := q.Get("state")
	fail := func(code, desc string) {
		params := url.Values{"error": {code}, "error_description": {desc}, "iss": {s.cfg.PublicURL}}
		if state != "" {
			params.Set("state", state)
		}
		s.oauthRedirect(w, r, redirectURI, params)
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only response_type=code")
		return
	}
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" || !validChallengeShape(challenge) {
		fail("invalid_request", "code_challenge with method S256 is required")
		return
	}
	scope := q.Get("scope")
	if scope == "" {
		scope = strings.Join(allScopes, " ")
	}
	if !validScopeSubset(scope) {
		fail("invalid_scope", "unknown scope requested")
		return
	}
	resource := q.Get("resource")
	if resource != "" && resource != s.resourceURL() {
		fail("invalid_target", "unknown resource")
		return
	}
	reqid, err := randomHex(16)
	if err != nil {
		s.authorizeErrorPage(w, "randomness failure")
		return
	}
	s.mu.Lock()
	if len(s.pending) >= 1024 {
		s.sweepPendingLocked()
		if len(s.pending) >= 1024 {
			s.mu.Unlock()
			s.authorizeErrorPage(w, "server busy, try again")
			return
		}
	}
	s.pending[reqid] = &pendingAuth{
		clientID: client.ID, clientName: client.Name, redirectURI: redirectURI,
		scope: scope, state: state, challenge: challenge, resource: resource,
		expiresAt: time.Now().UTC().Add(pendingTTL).Unix(),
	}
	s.mu.Unlock()
	s.renderConsent(w, client, scope, reqid, "")
}

// authorizeSubmit consumes one pending request: deny redirects access_denied,
// approve mints a grant and a code after the sandbox-api token checks out. A
// bad token re-renders the form (the request stays pending so the user can
// retype); anything else consumes it.
func (s *Server) authorizeSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.authorizeErrorPage(w, "unreadable form")
		return
	}
	reqid := r.PostForm.Get("reqid")
	s.mu.Lock()
	p, ok := s.pending[reqid]
	if ok && p.expiresAt < time.Now().UTC().Unix() {
		delete(s.pending, reqid)
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		s.authorizeErrorPage(w, "request expired, start again")
		return
	}
	deny := func() {
		s.mu.Lock()
		delete(s.pending, reqid)
		s.mu.Unlock()
		params := url.Values{"error": {"access_denied"}, "iss": {s.cfg.PublicURL}}
		if p.state != "" {
			params.Set("state", p.state)
		}
		s.oauthRedirect(w, r, p.redirectURI, params)
	}
	if r.PostForm.Get("decision") != "approve" {
		deny()
		return
	}
	if tok := r.PostForm.Get("api_token"); tok == "" || !s.validateAPI(tok) {
		client, _ := s.store.Client(p.clientID)
		if client == nil {
			client = &Client{ID: p.clientID, Name: p.clientName}
		}
		s.renderConsent(w, client, p.scope, reqid, "that API token did not authenticate")
		return
	}
	s.mu.Lock()
	delete(s.pending, reqid)
	s.mu.Unlock()
	grantSuffix, err := randomHex(8)
	if err != nil {
		s.authorizeErrorPage(w, "randomness failure")
		return
	}
	grant := &Grant{
		ID: "grant_" + grantSuffix, ClientID: p.clientID,
		Principal: operatorPrincipal, Scopes: strings.Fields(p.scope),
		CreatedAt: nowUnix(),
	}
	if err := s.store.SaveGrant(grant); err != nil {
		s.authorizeErrorPage(w, "cannot persist grant")
		return
	}
	code, err := randomB64(32)
	if err != nil {
		s.authorizeErrorPage(w, "randomness failure")
		return
	}
	resource := p.resource
	if resource == "" {
		resource = s.resourceURL()
	}
	if err := s.store.SaveCode(&AuthCode{
		CodeHash: hashSecret(code), ClientID: p.clientID, RedirectURI: p.redirectURI,
		Challenge: p.challenge, GrantID: grant.ID, Resource: resource,
		ExpiresAt: time.Now().UTC().Add(codeTTL).Unix(),
	}); err != nil {
		s.authorizeErrorPage(w, "cannot persist code")
		return
	}
	params := url.Values{"code": {code}, "iss": {s.cfg.PublicURL}}
	if p.state != "" {
		params.Set("state", p.state)
	}
	s.oauthRedirect(w, r, p.redirectURI, params)
}

func (s *Server) sweepPendingLocked() {
	now := time.Now().UTC().Unix()
	for id, p := range s.pending {
		if p.expiresAt < now {
			delete(s.pending, id)
		}
	}
}

// --- token ---

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "form body required")
		return
	}
	// Body only: credentials in the query string leak into logs, so the token
	// endpoint never reads them there.
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unreadable body")
		return
	}
	form, err := url.ParseQuery(string(raw))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed body")
		return
	}
	clientID, secret, hasBasic := r.BasicAuth()
	if !hasBasic {
		clientID, secret = form.Get("client_id"), form.Get("client_secret")
	}
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id required")
		return
	}
	if res := form.Get("resource"); res != "" && res != s.resourceURL() {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "unknown resource")
		return
	}
	if id, want, ok := strings.Cut(s.cfg.TestClient, ":"); ok && clientID == id {
		if subtle.ConstantTimeCompare([]byte(secret), []byte(want)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="mcp-gateway"`)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "bad client secret")
			return
		}
		s.tokenClientCredentials(w, form, id)
		return
	}
	client, ok := s.store.Client(clientID)
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unknown client")
		return
	}
	switch form.Get("grant_type") {
	case "authorization_code":
		s.tokenCode(w, form, client)
	case "refresh_token":
		s.tokenRefresh(w, form, client)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "want authorization_code or refresh_token")
	}
}

func (s *Server) tokenCode(w http.ResponseWriter, form url.Values, client *Client) {
	code, verifier, redirect := form.Get("code"), form.Get("code_verifier"), form.Get("redirect_uri")
	if code == "" || verifier == "" || redirect == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code, code_verifier and redirect_uri are required")
		return
	}
	if !validVerifierShape(verifier) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed code_verifier")
		return
	}
	// TakeCode consumes on first present, even if the checks below fail: a
	// code must not survive a guess at its verifier.
	rec, ok := s.store.TakeCode(code)
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code unknown, expired or reused")
		return
	}
	if rec.ClientID != client.ID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code was issued to another client")
		return
	}
	if rec.RedirectURI != redirect {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != rec.Challenge {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE check failed")
		return
	}
	grant, ok := s.store.Grant(rec.GrantID)
	if !ok || grant.Revoked {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "grant is gone")
		return
	}
	s.issuePair(w, grant, rec.Resource)
}

func (s *Server) tokenRefresh(w http.ResponseWriter, form url.Values, client *Client) {
	rec, fresh, ok := s.store.TakeRefresh(form.Get("refresh_token"))
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token unknown or expired")
		return
	}
	if rec.ClientID != client.ID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token belongs to another client")
		return
	}
	if !fresh {
		// Reuse of a rotated token: the token leaked. Kill the grant.
		_ = s.store.RevokeGrant(rec.GrantID)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token reused; grant revoked")
		return
	}
	grant, ok := s.store.Grant(rec.GrantID)
	if !ok || grant.Revoked {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "grant is gone")
		return
	}
	scopes := grant.Scopes
	if want := form.Get("scope"); want != "" {
		if !validScopeSubset(want) || !scopeSubset(strings.Fields(want), grant.Scopes) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "cannot widen a grant")
			return
		}
		scopes = strings.Fields(want)
	}
	narrowed := &Grant{ID: grant.ID, ClientID: grant.ClientID, Principal: grant.Principal,
		Scopes: scopes, CreatedAt: grant.CreatedAt}
	s.issuePair(w, narrowed, s.resourceURL())
}

// tokenClientCredentials serves the testing-only grant: config-gated,
// unadvertised in metadata, access token only, no refresh.
func (s *Server) tokenClientCredentials(w http.ResponseWriter, form url.Values, id string) {
	if s.cfg.TestClient == "" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "client_credentials is disabled")
		return
	}
	if form.Get("grant_type") != "client_credentials" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "this client allows client_credentials only")
		return
	}
	scope := form.Get("scope")
	if scope == "" {
		scope = strings.Join(allScopes, " ")
	}
	if !validScopeSubset(scope) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "unknown scope requested")
		return
	}
	suffix, err := randomHex(8)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "randomness failure")
		return
	}
	grant := &Grant{ID: "grant_" + suffix, ClientID: id, Principal: operatorPrincipal,
		Scopes: strings.Fields(scope), CreatedAt: nowUnix()}
	if err := s.store.SaveGrant(grant); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "cannot persist grant")
		return
	}
	access, err := randomB64(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "randomness failure")
		return
	}
	now := time.Now().UTC().Unix()
	if err := s.store.SaveAccess(&AccessToken{TokenHash: hashSecret(access), GrantID: grant.ID,
		ClientID: id, Scopes: grant.Scopes, Resource: s.resourceURL(),
		ExpiresAt: now + int64(accessTTL/time.Second)}); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "cannot persist token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(accessTTL / time.Second),
		"scope":        strings.Join(grant.Scopes, " "),
	})
}

// issuePair mints a rotated access + refresh pair under the grant.
func (s *Server) issuePair(w http.ResponseWriter, grant *Grant, resource string) {
	access, err := randomB64(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "randomness failure")
		return
	}
	refresh, err := randomB64(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "randomness failure")
		return
	}
	now := time.Now().UTC().Unix()
	if err := s.store.SaveAccess(&AccessToken{TokenHash: hashSecret(access), GrantID: grant.ID,
		ClientID: grant.ClientID, Scopes: grant.Scopes, Resource: resource,
		ExpiresAt: now + int64(accessTTL/time.Second)}); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "cannot persist token")
		return
	}
	if err := s.store.SaveRefresh(&RefreshToken{TokenHash: hashSecret(refresh), GrantID: grant.ID,
		ClientID: grant.ClientID, ExpiresAt: now + int64(refreshTTL/time.Second)}); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "cannot persist token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(accessTTL / time.Second),
		"refresh_token": refresh,
		"scope":         strings.Join(grant.Scopes, " "),
	})
}

func scopeSubset(want, have []string) bool {
	for _, s := range want {
		if !contains(have, s) {
			return false
		}
	}
	return true
}

// validVerifierShape enforces RFC 7636 §4.1: 43–128 chars of unreserved mark.
func validVerifierShape(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			continue
		}
		return false
	}
	return true
}

// validChallengeShape bounds the S256 challenge the same way: base64url of a
// SHA-256 is always 43 chars, but accept the RFC range and let the token
// endpoint do the exact check.
func validChallengeShape(c string) bool {
	if len(c) < 43 || len(c) > 128 {
		return false
	}
	for i := 0; i < len(c); i++ {
		ch := c[i]
		if ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' ||
			ch == '-' || ch == '_' {
			continue
		}
		return false
	}
	return true
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}
