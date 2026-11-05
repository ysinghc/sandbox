// SPDX-License-Identifier: GPL-2.0-only
// Command mcp-gateway is the remote MCP server for web assistants (#28): a Go
// gateway that speaks Streamable HTTP + OAuth 2.1 on the front and the #27
// control-plane API on the back. Deliberately standard-library only: no module
// downloads, no supply chain beyond the toolchain, reproducible offline builds.
package main

import (
	"fmt"
	"net/http"
	"os"
)

// version is the build version, overridden at link time:
// go build -ldflags "-X main.version=$(git describe --tags --always)".
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "mcp-gateway: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}
	st, err := Open(cfg.StorePath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	st.Sweep()
	srv, err := NewServer(cfg, st)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "mcp-gateway %s listening on %s (public %s)\n",
		version, cfg.Listen, cfg.PublicURL)
	return (&http.Server{Addr: cfg.Listen, Handler: srv.Handler()}).ListenAndServe()
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "mcp-gateway",
		"version": version,
	})
}
