// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSelfSignedCertShape(t *testing.T) {
	cert, fingerprint, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != 1 {
		t.Fatalf("%d certificates, want a bare leaf", len(cert.Certificate))
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.DNSNames[0] != "localhost" || len(leaf.IPAddresses) != 2 {
		t.Fatalf("SANs = %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > 25*time.Hour {
		t.Fatalf("validity = %v, want ~24h", leaf.NotAfter.Sub(leaf.NotBefore))
	}
	if leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("EKU = %v", leaf.ExtKeyUsage)
	}
	sum := sha256.Sum256(cert.Certificate[0])
	if fingerprint != hex.EncodeToString(sum[:]) {
		t.Fatal("fingerprint is not the leaf's sha256")
	}
	if _, ok := cert.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("private key is %T, want *ecdsa.PrivateKey", cert.PrivateKey)
	}
}

func TestSelfSignedCertServes(t *testing.T) {
	cert, fingerprint, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tls-ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	client := srv.Client()
	client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if len(resp.TLS.PeerCertificates) != 1 {
		t.Fatalf("%d peer certs", len(resp.TLS.PeerCertificates))
	}
	sum := sha256.Sum256(resp.TLS.PeerCertificates[0].Raw)
	if hex.EncodeToString(sum[:]) != fingerprint {
		t.Fatal("served cert does not match the minted fingerprint")
	}
}

func TestSelfSignedRequiresLoopbackListen(t *testing.T) {
	args := append(validArgs(), "--tls-self-signed")
	if _, err := parseFlags(args); err != nil {
		t.Fatalf("loopback dev TLS rejected: %v", err)
	}
	args = append(validArgs(), "--tls-self-signed", "--listen", "0.0.0.0:8090")
	if _, err := parseFlags(args); err == nil {
		t.Fatal("public dev TLS accepted")
	}
}
