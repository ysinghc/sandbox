// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
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
	// APIBase is the #27 sandbox-api base URL: http(s)://host:port or
	// unix:///path/to/api.sock. Tools and consent-token checks call it.
	APIBase string
	// APITokenFile holds the sandbox-api bearer token (one line) the
	// gateway acts with. M2 serves a single operator principal; per-user
	// principals arrive with multi-tenancy (#17).
	APITokenFile string
	// TestClient enables the client_credentials grant for self-host and
	// e2e testing, as "id:secret". Empty disables the grant entirely.
	TestClient string
	// SelfSignedTLS serves HTTPS with an ephemeral loopback certificate
	// instead of plain HTTP. Development only: clients must pin the
	// logged fingerprint, and the cert lasts 24 hours.
	SelfSignedTLS bool
}

func parseFlags(args []string) (Config, error) {
	var c Config
	fs := flag.NewFlagSet("mcp-gateway", flag.ContinueOnError)
	fs.StringVar(&c.Listen, "listen", "127.0.0.1:8090", "local bind address")
	fs.StringVar(&c.PublicURL, "public-url", "", "canonical public base URL (required)")
	fs.StringVar(&c.StorePath, "store", "", "OAuth state file (required)")
	fs.StringVar(&c.APIBase, "api", "", "#27 sandbox-api base URL, http(s):// or unix:// (required)")
	fs.StringVar(&c.APITokenFile, "api-token-file", "", "file holding the sandbox-api bearer token (required)")
	fs.StringVar(&c.TestClient, "test-client", "", "enable client_credentials as id:secret (testing only)")
	fs.BoolVar(&c.SelfSignedTLS, "tls-self-signed", false, "serve HTTPS with an ephemeral loopback cert (dev only)")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() > 0 {
		return Config{}, fmt.Errorf("unexpected argument: %q", fs.Arg(0))
	}
	// Every flag also reads SANDBOX_MCP_<NAME> from the environment, in the
	// sandbox-api style. Explicit flags win over the environment.
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	strEnv := func(name, env string, dst *string) {
		if !set[name] {
			if v := os.Getenv(env); v != "" {
				*dst = v
			}
		}
	}
	strEnv("listen", "SANDBOX_MCP_LISTEN", &c.Listen)
	strEnv("public-url", "SANDBOX_MCP_PUBLIC_URL", &c.PublicURL)
	strEnv("store", "SANDBOX_MCP_STORE", &c.StorePath)
	strEnv("api", "SANDBOX_MCP_API", &c.APIBase)
	strEnv("api-token-file", "SANDBOX_MCP_API_TOKEN_FILE", &c.APITokenFile)
	strEnv("test-client", "SANDBOX_MCP_TEST_CLIENT", &c.TestClient)
	if !set["tls-self-signed"] {
		switch strings.ToLower(os.Getenv("SANDBOX_MCP_TLS_SELF_SIGNED")) {
		case "", "0", "false", "no":
		case "1", "true", "yes":
			c.SelfSignedTLS = true
		default:
			return Config{}, fmt.Errorf("bad SANDBOX_MCP_TLS_SELF_SIGNED: want 1/true/yes or 0/false/no")
		}
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
	if c.APIBase == "" {
		return errors.New("--api is required")
	}
	if !(strings.HasPrefix(c.APIBase, "http://") || strings.HasPrefix(c.APIBase, "https://") ||
		strings.HasPrefix(c.APIBase, "unix://")) {
		return fmt.Errorf("bad --api %q: want http(s):// or unix://", c.APIBase)
	}
	if c.APITokenFile == "" {
		return errors.New("--api-token-file is required")
	}
	if c.TestClient != "" {
		id, secret, ok := strings.Cut(c.TestClient, ":")
		if !ok || id == "" || secret == "" {
			return fmt.Errorf("bad --test-client: want id:secret")
		}
	}
	if c.SelfSignedTLS {
		host, _, _ := net.SplitHostPort(c.Listen)
		// A dev cert on a public socket would look secure and not be: refuse.
		if host != "" && !isLoopbackHost(host) {
			return fmt.Errorf("--tls-self-signed requires a loopback --listen")
		}
	}
	return nil
}

// LoadAPIToken reads the bearer token from APITokenFile (first line). The
// file must not be readable beyond its owner: it is a live credential.
func (c Config) LoadAPIToken() (string, error) {
	fi, err := os.Stat(c.APITokenFile)
	if err != nil {
		return "", err
	}
	if fi.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("refusing unsafe token file %s: mode %04o", c.APITokenFile, fi.Mode().Perm())
	}
	raw, err := os.ReadFile(c.APITokenFile)
	if err != nil {
		return "", err
	}
	tok, _, _ := strings.Cut(string(raw), "\n")
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", fmt.Errorf("token file %s is empty", c.APITokenFile)
	}
	return tok, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
