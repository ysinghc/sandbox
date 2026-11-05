// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"os"
	"testing"
)

func validArgs() []string {
	return []string{"--public-url", "https://mcp.example.org", "--store", "/tmp/s.json",
		"--api", "unix:///run/sandbox-api/api.sock", "--api-token-file", "/tmp/tok"}
}

func TestParseFlagsValid(t *testing.T) {
	c, err := parseFlags(validArgs())
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if c.Listen != "127.0.0.1:8090" {
		t.Fatalf("default listen = %q", c.Listen)
	}
}

func TestParseFlagsRejects(t *testing.T) {
	base := validArgs()
	cases := map[string][]string{
		"missing public-url": drop(base, "--public-url"),
		"missing store":      drop(base, "--store"),
		"missing api":        drop(base, "--api"),
		"missing token file": drop(base, "--api-token-file"),
		"bad api scheme":     set(base, "--api", "ftp://x"),
		"bad test client":    append(append([]string{}, base...), "--test-client", "nosep"),
		"bad listen":         append(append([]string{}, base...), "--listen", "nope"),
		"relative url":       set(base, "--public-url", "/mcp"),
		"http off loopback":  set(base, "--public-url", "http://mcp.example.org"),
		"positional arg":     append(append([]string{}, base...), "extra"),
	}
	for name, args := range cases {
		if _, err := parseFlags(args); err == nil {
			t.Errorf("%s: accepted, want rejection", name)
		}
	}
}

// drop removes a flag and its value; set replaces a flag's value.
func drop(args []string, flag string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if args[i] == flag {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func set(args []string, flag, val string) []string {
	out := append([]string{}, args...)
	for i := 0; i < len(out); i++ {
		if out[i] == flag {
			out[i+1] = val
		}
	}
	return out
}

func TestParseFlagsAllowsHTTPLoopback(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1:8090", "http://localhost:8090", "http://[::1]:8090"} {
		if _, err := parseFlags(set(validArgs(), "--public-url", u)); err != nil {
			t.Errorf("%s: rejected: %v", u, err)
		}
	}
}

func TestFlagsReadEnv(t *testing.T) {
	t.Setenv("SANDBOX_MCP_LISTEN", "127.0.0.1:9999")
	t.Setenv("SANDBOX_MCP_PUBLIC_URL", "https://mcp.example.org")
	t.Setenv("SANDBOX_MCP_STORE", "/tmp/s.json")
	t.Setenv("SANDBOX_MCP_API", "http://127.0.0.1:8088")
	t.Setenv("SANDBOX_MCP_API_TOKEN_FILE", "/tmp/tok")
	t.Setenv("SANDBOX_MCP_TLS_SELF_SIGNED", "yes")
	c, err := parseFlags(nil)
	if err != nil {
		t.Fatalf("env-only config rejected: %v", err)
	}
	if c.Listen != "127.0.0.1:9999" || !c.SelfSignedTLS {
		t.Fatalf("env not applied: %+v", c)
	}
	// An explicit flag wins over the environment.
	c, err = parseFlags([]string{"--listen", "127.0.0.1:1111"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:1111" {
		t.Fatalf("flag did not win: %+v", c)
	}
	t.Setenv("SANDBOX_MCP_TLS_SELF_SIGNED", "maybe")
	if _, err := parseFlags(nil); err == nil {
		t.Fatal("garbage bool env accepted")
	}
}

func TestLoadAPIToken(t *testing.T) {
	dir := t.TempDir()
	ok := dir + "/tok"
	if err := os.WriteFile(ok, []byte("sekret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := Config{APITokenFile: ok}
	tok, err := c.LoadAPIToken()
	if err != nil || tok != "sekret" {
		t.Fatalf("LoadAPIToken = %q, %v", tok, err)
	}
	open := dir + "/open"
	if err := os.WriteFile(open, []byte("sekret\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := (Config{APITokenFile: open}).LoadAPIToken(); err == nil {
		t.Fatal("LoadAPIToken accepted a group-readable file")
	}
	if _, err := (Config{APITokenFile: dir + "/missing"}).LoadAPIToken(); err == nil {
		t.Fatal("LoadAPIToken accepted a missing file")
	}
}
