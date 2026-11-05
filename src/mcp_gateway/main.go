// SPDX-License-Identifier: GPL-2.0-only
// Command mcp-gateway is the remote MCP server for web assistants (#28): a Go
// gateway that speaks Streamable HTTP + OAuth 2.1 on the front and the #27
// control-plane API on the back. Deliberately standard-library only: no module
// downloads, no supply chain beyond the toolchain, reproducible offline builds.
package main

import (
	"encoding/json"
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
	srv := &http.Server{Addr: cfg.Listen, Handler: newMux(cfg, st)}
	fmt.Fprintf(os.Stderr, "mcp-gateway %s listening on %s (public %s)\n",
		version, cfg.Listen, cfg.PublicURL)
	return srv.ListenAndServe()
}

func newMux(cfg Config, st *Store) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"service": "mcp-gateway",
			"version": version,
		})
	})
	_ = st // the OAuth and MCP routes register here as they land.
	return mux
}
