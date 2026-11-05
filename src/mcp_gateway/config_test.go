// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"testing"
)

func TestParseFlagsValid(t *testing.T) {
	c, err := parseFlags([]string{"--public-url", "https://mcp.example.org", "--store", "/tmp/s.json"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if c.Listen != "127.0.0.1:8090" {
		t.Fatalf("default listen = %q", c.Listen)
	}
}

func TestParseFlagsRejects(t *testing.T) {
	cases := map[string][]string{
		"missing public-url": {"--store", "/tmp/s.json"},
		"missing store":      {"--public-url", "https://mcp.example.org"},
		"bad listen":         {"--listen", "nope", "--public-url", "https://m.example.org", "--store", "s"},
		"relative url":       {"--public-url", "/mcp", "--store", "s"},
		"http off loopback":  {"--public-url", "http://mcp.example.org", "--store", "s"},
		"positional arg":     {"--public-url", "https://m.example.org", "--store", "s", "extra"},
	}
	for name, args := range cases {
		if _, err := parseFlags(args); err == nil {
			t.Errorf("%s: accepted, want rejection", name)
		}
	}
}

func TestParseFlagsAllowsHTTPLoopback(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1:8090", "http://localhost:8090", "http://[::1]:8090"} {
		if _, err := parseFlags([]string{"--public-url", u, "--store", "s"}); err != nil {
			t.Errorf("%s: rejected: %v", u, err)
		}
	}
}
