// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// maxCIMDBytes caps a Client ID Metadata Document (draft-ietf-oauth-client-id-
// metadata-document): it is a small JSON object, never a bulk download.
const maxCIMDBytes = 64 << 10

// cimdDoc is the subset of client metadata the gateway enforces. Anything else
// in the document is ignored, never fetched.
type cimdDoc struct {
	ClientID          string   `json:"client_id"`
	RedirectURIs      []string `json:"redirect_uris"`
	GrantTypes        []string `json:"grant_types"`
	ResponseTypes     []string `json:"response_types"`
	Scope             string   `json:"scope"`
	TokenEndpointAuth string   `json:"token_endpoint_auth_method"`
	ClientName        string   `json:"client_name"`
}

// cimdHTTPClient is the production fetcher: 10 s total, no redirects (a
// redirect target is not re-validated cheaply, so any 3xx fails the fetch),
// TLS 1.2+, and a dialer that connects only to public addresses — a client_id
// URL is attacker-influenced input, and the metadata address or a cloud
// metadata endpoint must never be reachable through it.
func cimdHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("cimd: redirects not followed")
		},
		Transport: &http.Transport{
			DialTLSContext:        guardedDialTLS,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}
}

func guardedDialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("cimd: unexpected network %q", network)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("cimd: bad address %q", addr)
	}
	// Resolve once and dial the chosen IP, so a DNS rebinding between the
	// check and the connect cannot steer us at a private address.
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("cimd: cannot resolve %q", host)
	}
	var picked net.IP
	for _, ip := range ips {
		if isPublicIP(ip) {
			picked = ip
			break
		}
	}
	if picked == nil {
		return nil, fmt.Errorf("cimd: %q resolves to no public address", host)
	}
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(picked.String(), port))
	if err != nil {
		return nil, err
	}
	// SNI and certificate verification use the real hostname, not the IP.
	tlsConn := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tlsConn, nil
}

// isPublicIP mirrors the broker's upstream rule: loopback, unspecified,
// multicast, RFC 1918, CGNAT and link-local (which covers the VM /30s and the
// cloud metadata address) are all refused.
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		// 10/8, 172.16/12, 192.168/16.
		if ip4[0] == 10 || (ip4[0] == 172 && ip4[1]&0xf0 == 16) || (ip4[0] == 192 && ip4[1] == 168) {
			return false
		}
		// 100.64/10 CGNAT.
		if ip4[0] == 100 && ip4[1]&0xc0 == 64 {
			return false
		}
		// 169.254/16 link-local (also matched above for v6-mapped forms).
		if ip4[0] == 169 && ip4[1] == 254 {
			return false
		}
		return true
	}
	// v6: unique-local fc00::/7 and link-local fe80::/10 (link-local unicast
	// is already out above; this keeps the intent explicit for ULA).
	return len(ip) == net.IPv6len && ip[0]&0xfe != 0xfc
}

// fetchCIMD validates that clientID is an https URL, fetches the document it
// points at, and checks the document describes that same client. httpClient is
// injected so tests can trust a local TLS server; production passes
// cimdHTTPClient().
func fetchCIMD(ctx context.Context, httpClient *http.Client, clientID string) (*cimdDoc, error) {
	if !strings.HasPrefix(clientID, "https://") {
		return nil, fmt.Errorf("cimd: client_id %q is not an https URL", clientID)
	}
	if strings.Contains(clientID, "#") {
		return nil, fmt.Errorf("cimd: client_id %q must not carry a fragment", clientID)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", clientID, nil)
	if err != nil {
		return nil, fmt.Errorf("cimd: bad client_id URL: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cimd: fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cimd: fetch returned %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxCIMDBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cimd: read failed: %w", err)
	}
	if len(raw) > maxCIMDBytes {
		return nil, fmt.Errorf("cimd: document over %d bytes", maxCIMDBytes)
	}
	var doc cimdDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("cimd: not JSON: %w", err)
	}
	if doc.ClientID == "" || doc.ClientID != clientID {
		return nil, fmt.Errorf("cimd: document client_id mismatch")
	}
	if len(doc.RedirectURIs) == 0 {
		return nil, fmt.Errorf("cimd: document lists no redirect_uris")
	}
	if len(doc.GrantTypes) > 0 && !contains(doc.GrantTypes, "authorization_code") {
		return nil, fmt.Errorf("cimd: document does not allow authorization_code")
	}
	if doc.TokenEndpointAuth != "" && doc.TokenEndpointAuth != "none" {
		return nil, fmt.Errorf("cimd: token_endpoint_auth_method %q unsupported (M2: public clients only)", doc.TokenEndpointAuth)
	}
	return &doc, nil
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
