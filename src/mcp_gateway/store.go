// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// storeVersion is the on-disk format version. Bump it if database changes
// shape; Open refuses anything it does not understand rather than misreading
// it.
const storeVersion = 1

// Client is an OAuth client: one DCR registration, one CIMD document fetch, or
// one testing client-credentials entry. Public clients (the MCP norm) carry no
// secret; the redirect URIs and PKCE are the binding.
type Client struct {
	ID           string   `json:"id"`
	SecretHash   string   `json:"secret_hash,omitempty"` // hex sha256, "" for public
	RedirectURIs []string `json:"redirect_uris"`
	Name         string   `json:"name,omitempty"`
	CreatedAt    int64    `json:"created_at"`
}

// Grant binds one user's approval to one client: the sandbox-api principal
// every tool call of the grant acts as, and the scopes that were approved.
type Grant struct {
	ID        string   `json:"id"`
	ClientID  string   `json:"client_id"`
	Principal string   `json:"principal"`
	Scopes    []string `json:"scopes"`
	CreatedAt int64    `json:"created_at"`
	Revoked   bool     `json:"revoked"`
}

// AuthCode is a single-use authorization code. Only its hash is a map key, so
// the store file never holds a live code in the clear.
type AuthCode struct {
	CodeHash    string `json:"code_hash"`
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	Challenge   string `json:"challenge"` // PKCE S256 code_challenge
	GrantID     string `json:"grant_id"`
	Resource    string `json:"resource"`
	ExpiresAt   int64  `json:"expires_at"`
	Used        bool   `json:"used"`
}

// AccessToken is a short-lived bearer token, also keyed by hash.
type AccessToken struct {
	TokenHash string   `json:"token_hash"`
	GrantID   string   `json:"grant_id"`
	ClientID  string   `json:"client_id"`
	Scopes    []string `json:"scopes"`
	Resource  string   `json:"resource"`
	ExpiresAt int64    `json:"expires_at"`
}

// RefreshToken rotates on every use: TakeRefresh marks the presented token
// used and the caller issues its replacement. Presenting an already-used token
// is a replay signal — the caller must revoke the whole grant.
type RefreshToken struct {
	TokenHash string `json:"token_hash"`
	GrantID   string `json:"grant_id"`
	ClientID  string `json:"client_id"`
	ExpiresAt int64  `json:"expires_at"`
	Used      bool   `json:"used"`
}

type database struct {
	Version int                      `json:"version"`
	Clients map[string]*Client       `json:"clients"`
	Grants  map[string]*Grant        `json:"grants"`
	Codes   map[string]*AuthCode     `json:"codes"`
	Access  map[string]*AccessToken  `json:"access"`
	Refresh map[string]*RefreshToken `json:"refresh"`
}

// Store is a mutex-guarded, file-backed OAuth state database. Every mutation
// persists atomically (temp file + fsync + rename); the write rate is auth
// flows only, so there is no batching to lose data in.
type Store struct {
	mu   sync.Mutex
	path string
	db   database
}

func hashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func newDatabase() database {
	return database{
		Version: storeVersion,
		Clients: map[string]*Client{},
		Grants:  map[string]*Grant{},
		Codes:   map[string]*AuthCode{},
		Access:  map[string]*AccessToken{},
		Refresh: map[string]*RefreshToken{},
	}
}

// Open loads the store file, creating it mode 0600 if absent. A file readable
// beyond its owner is refused: it holds token hashes worth brute-forcing.
func Open(path string) (*Store, error) {
	s := &Store{path: path, db: newDatabase()}
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
		return s, nil
	}
	if fi, err := os.Stat(path); err != nil {
		return nil, err
	} else if fi.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("refusing unsafe store %s: mode %04o, want 0600", path, fi.Mode().Perm())
	}
	var db database
	if err := json.Unmarshal(raw, &db); err != nil {
		return nil, fmt.Errorf("corrupt store %s: %w", path, err)
	}
	if db.Version != storeVersion {
		return nil, fmt.Errorf("store %s is version %d, want %d", path, db.Version, storeVersion)
	}
	if db.Clients == nil || db.Grants == nil || db.Codes == nil || db.Access == nil || db.Refresh == nil {
		return nil, fmt.Errorf("corrupt store %s: missing tables", path)
	}
	s.db = db
	return s, nil
}

func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.db, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".store-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename.
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}

func nowUnix() int64 { return time.Now().UTC().Unix() }

// --- clients ---

func (s *Store) SaveClient(c *Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Clients[c.ID] = c
	return s.saveLocked()
}

func (s *Store) Client(id string) (*Client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.db.Clients[id]
	return c, ok
}

// --- grants ---

func (s *Store) SaveGrant(g *Grant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Grants[g.ID] = g
	return s.saveLocked()
}

// RevokeGrant marks the grant revoked and drops every code and token issued
// under it. Refresh reuse calls this.
func (s *Store) RevokeGrant(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g, ok := s.db.Grants[id]; ok {
		g.Revoked = true
	}
	for h, c := range s.db.Codes {
		if c.GrantID == id {
			delete(s.db.Codes, h)
		}
	}
	for h, t := range s.db.Access {
		if t.GrantID == id {
			delete(s.db.Access, h)
		}
	}
	for h, t := range s.db.Refresh {
		if t.GrantID == id {
			delete(s.db.Refresh, h)
		}
	}
	return s.saveLocked()
}

func (s *Store) grantLiveLocked(id string) bool {
	g, ok := s.db.Grants[id]
	return ok && !g.Revoked
}

// --- authorization codes ---

func (s *Store) SaveCode(c *AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Codes[c.CodeHash] = c
	return s.saveLocked()
}

// TakeCode redeems a code once: unknown, expired, reused, or revoked-grant
// codes all fail closed.
func (s *Store) TakeCode(code string) (*AuthCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.db.Codes[hashSecret(code)]
	if !ok || c.Used || c.ExpiresAt < nowUnix() || !s.grantLiveLocked(c.GrantID) {
		return nil, false
	}
	c.Used = true
	if err := s.saveLocked(); err != nil {
		return nil, false
	}
	return c, true
}

// --- access tokens ---

func (s *Store) SaveAccess(t *AccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Access[t.TokenHash] = t
	return s.saveLocked()
}

// Access validates a presented bearer token: known, unexpired, grant live.
func (s *Store) Access(token string) (*AccessToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.db.Access[hashSecret(token)]
	if !ok || t.ExpiresAt < nowUnix() || !s.grantLiveLocked(t.GrantID) {
		return nil, false
	}
	return t, true
}

// --- refresh tokens ---

// SaveRefresh stores a refresh token record.
func (s *Store) SaveRefresh(t *RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Refresh[t.TokenHash] = t
	return s.saveLocked()
}

// TakeRefresh redeems a refresh token. It reports fresh=false when the token
// was already used — a replay, which the caller answers by revoking the grant.
func (s *Store) TakeRefresh(token string) (rec *RefreshToken, fresh bool, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, found := s.db.Refresh[hashSecret(token)]
	if !found || t.ExpiresAt < nowUnix() || !s.grantLiveLocked(t.GrantID) {
		return nil, false, false
	}
	if t.Used {
		return t, false, true
	}
	t.Used = true
	if err := s.saveLocked(); err != nil {
		return nil, false, false
	}
	return t, true, true
}

// Sweep drops expired codes and tokens. Cheap; run at startup and on a timer.
func (s *Store) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := nowUnix()
	changed := false
	for h, c := range s.db.Codes {
		if c.ExpiresAt < now {
			delete(s.db.Codes, h)
			changed = true
		}
	}
	for h, t := range s.db.Access {
		if t.ExpiresAt < now {
			delete(s.db.Access, h)
			changed = true
		}
	}
	for h, t := range s.db.Refresh {
		if t.ExpiresAt < now {
			delete(s.db.Refresh, h)
			changed = true
		}
	}
	if changed {
		_ = s.saveLocked()
	}
}
