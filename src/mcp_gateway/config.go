// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Config is the gateway's static configuration. Everything is a flag, in the
// sandbox-api style; there is no config file to keep in sync.
type Config struct {
	// Listen is the local bind address, e.g. "127.0.0.1:8090".
	Listen string
	// PublicURL is the canonical base URL clients see
	// (e.g. "https://mcp.example.org"). It is the OAuth issuer and the
	// token audience, so it must be stable and, off loopback, https.
	PublicURL string
	// StorePath is the JSON state file for OAuth clients, codes and
	// tokens. It is created mode 0600 and refused if more open than that.
	StorePath string
}

func parseFlags(args []string) (Config, error) {
	var c Config
	fs := flag.NewFlagSet("mcp-gateway", flag.ContinueOnError)
	fs.StringVar(&c.Listen, "listen", "127.0.0.1:8090", "local bind address")
	fs.StringVar(&c.PublicURL, "public-url", "", "canonical public base URL (required)")
	fs.StringVar(&c.StorePath, "store", "", "OAuth state file (required)")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() > 0 {
		return Config{}, fmt.Errorf("unexpected argument: %q", fs.Arg(0))
	}
	return c, c.validate()
}

func (c Config) validate() error {
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("bad --listen %q: %w", c.Listen, err)
	}
	if c.PublicURL == "" {
		return errors.New("--public-url is required")
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("bad --public-url %q: want an absolute URL", c.PublicURL)
	}
	// Plain HTTP is a credential leak anywhere but the loopback interface,
	// where MCP Inspector and the e2e suite live.
	if u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("bad --public-url %q: https required off loopback", c.PublicURL)
	}
	if c.StorePath == "" {
		return errors.New("--store is required")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
