// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return st, path
}

func TestStoreCreates0600(t *testing.T) {
	_, path := testStore(t)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("store mode = %04o, want 0600", fi.Mode().Perm())
	}
}

func TestStoreRefusesOpenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open accepted a group-readable store")
	}
}

func TestStoreClientRoundTrip(t *testing.T) {
	st, path := testStore(t)
	c := &Client{ID: "abc", RedirectURIs: []string{"https://app.example/cb"}, Name: "app", CreatedAt: nowUnix()}
	if err := st.SaveClient(c); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	// A reopen proves it persisted, not just sat in memory.
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, ok := st2.Client("abc")
	if !ok || got.Name != "app" || len(got.RedirectURIs) != 1 {
		t.Fatalf("Client after reopen = %+v, %v", got, ok)
	}
	if _, ok := st2.Client("nope"); ok {
		t.Fatal("unknown client returned ok")
	}
}

func TestStoreCodeSingleUse(t *testing.T) {
	st, _ := testStore(t)
	if err := st.SaveGrant(&Grant{ID: "g1", ClientID: "c", Principal: "alice"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveCode(&AuthCode{CodeHash: hashSecret("code-1"), ClientID: "c",
		RedirectURI: "https://app.example/cb", Challenge: "ch", GrantID: "g1",
		ExpiresAt: time.Now().Add(time.Minute).Unix()}); err != nil {
		t.Fatal(err)
	}
	c, ok := st.TakeCode("code-1")
	if !ok || c.GrantID != "g1" {
		t.Fatalf("first TakeCode = %+v, %v", c, ok)
	}
	if _, ok := st.TakeCode("code-1"); ok {
		t.Fatal("second TakeCode of the same code succeeded")
	}
	if _, ok := st.TakeCode("bogus"); ok {
		t.Fatal("TakeCode of an unknown code succeeded")
	}
}

func TestStoreCodeExpiry(t *testing.T) {
	st, _ := testStore(t)
	_ = st.SaveGrant(&Grant{ID: "g1"})
	_ = st.SaveCode(&AuthCode{CodeHash: hashSecret("old"), GrantID: "g1",
		ExpiresAt: time.Now().Add(-time.Minute).Unix()})
	if _, ok := st.TakeCode("old"); ok {
		t.Fatal("TakeCode of an expired code succeeded")
	}
}

func TestStoreAccessValidation(t *testing.T) {
	st, _ := testStore(t)
	_ = st.SaveGrant(&Grant{ID: "g1", Scopes: []string{"sandbox:read"}})
	fresh := time.Now().Add(time.Hour).Unix()
	stale := time.Now().Add(-time.Hour).Unix()
	_ = st.SaveAccess(&AccessToken{TokenHash: hashSecret("a-live"), GrantID: "g1", ExpiresAt: fresh})
	_ = st.SaveAccess(&AccessToken{TokenHash: hashSecret("a-dead"), GrantID: "g1", ExpiresAt: stale})
	if _, ok := st.Access("a-live"); !ok {
		t.Fatal("live token rejected")
	}
	if _, ok := st.Access("a-dead"); ok {
		t.Fatal("expired token accepted")
	}
	if _, ok := st.Access("bogus"); ok {
		t.Fatal("unknown token accepted")
	}
}

func TestStoreRefreshRotationAndReuse(t *testing.T) {
	st, _ := testStore(t)
	_ = st.SaveGrant(&Grant{ID: "g1"})
	_ = st.SaveRefresh(&RefreshToken{TokenHash: hashSecret("r1"), GrantID: "g1",
		ExpiresAt: time.Now().Add(time.Hour).Unix()})
	rec, fresh, ok := st.TakeRefresh("r1")
	if !ok || !fresh || rec.GrantID != "g1" {
		t.Fatalf("first TakeRefresh = %+v, fresh=%v ok=%v", rec, fresh, ok)
	}
	_, fresh, ok = st.TakeRefresh("r1")
	if !ok || fresh {
		t.Fatalf("replay TakeRefresh = fresh=%v ok=%v, want fresh=false ok=true", fresh, ok)
	}
	if _, _, ok := st.TakeRefresh("bogus"); ok {
		t.Fatal("unknown refresh token accepted")
	}
}

func TestStoreRevokeGrantDropsEverything(t *testing.T) {
	st, _ := testStore(t)
	_ = st.SaveGrant(&Grant{ID: "g1"})
	_ = st.SaveGrant(&Grant{ID: "g2"})
	fresh := time.Now().Add(time.Hour).Unix()
	_ = st.SaveCode(&AuthCode{CodeHash: hashSecret("c1"), GrantID: "g1", ExpiresAt: fresh})
	_ = st.SaveAccess(&AccessToken{TokenHash: hashSecret("a1"), GrantID: "g1", ExpiresAt: fresh})
	_ = st.SaveRefresh(&RefreshToken{TokenHash: hashSecret("r1"), GrantID: "g1", ExpiresAt: fresh})
	_ = st.SaveAccess(&AccessToken{TokenHash: hashSecret("a2"), GrantID: "g2", ExpiresAt: fresh})
	if err := st.RevokeGrant("g1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.TakeCode("c1"); ok {
		t.Fatal("code of a revoked grant still redeemable")
	}
	if _, ok := st.Access("a1"); ok {
		t.Fatal("access token of a revoked grant still valid")
	}
	if _, _, ok := st.TakeRefresh("r1"); ok {
		t.Fatal("refresh token of a revoked grant still redeemable")
	}
	if _, ok := st.Access("a2"); !ok {
		t.Fatal("revoking g1 killed g2's token")
	}
}

func TestStoreSweep(t *testing.T) {
	st, path := testStore(t)
	_ = st.SaveGrant(&Grant{ID: "g1"})
	stale := time.Now().Add(-time.Hour).Unix()
	fresh := time.Now().Add(time.Hour).Unix()
	_ = st.SaveAccess(&AccessToken{TokenHash: hashSecret("a-dead"), GrantID: "g1", ExpiresAt: stale})
	_ = st.SaveAccess(&AccessToken{TokenHash: hashSecret("a-live"), GrantID: "g1", ExpiresAt: fresh})
	_ = st.SaveRefresh(&RefreshToken{TokenHash: hashSecret("r-dead"), GrantID: "g1", ExpiresAt: stale})
	st.Sweep()
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st2.Access("a-dead"); ok {
		t.Fatal("sweep left an expired access token")
	}
	if _, _, ok := st2.TakeRefresh("r-dead"); ok {
		t.Fatal("sweep left an expired refresh token")
	}
	if _, ok := st2.Access("a-live"); !ok {
		t.Fatal("sweep dropped a live token")
	}
}

func TestStoreRejectsForeignVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"version":999}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open accepted a foreign store version")
	}
}
