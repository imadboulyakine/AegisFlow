// Test cases for go-tls-insecure-config (run: make sast-test).
package semgreptest

import (
	"crypto/tls"
	"crypto/x509"
)

func goodTLS(pool *x509.CertPool) *tls.Config {
	// ok: go-tls-insecure-config
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
}

func goodTLS13() *tls.Config {
	// ok: go-tls-insecure-config
	return &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: false}
}

func skipVerify() *tls.Config {
	// ruleid: go-tls-insecure-config
	return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
}

func skipVerifyAssign(cfg *tls.Config) {
	// ruleid: go-tls-insecure-config
	cfg.InsecureSkipVerify = true
}

func oldProtocol() *tls.Config {
	// ruleid: go-tls-insecure-config
	return &tls.Config{MinVersion: tls.VersionTLS10}
}

func oldProtocolAssign(cfg *tls.Config) {
	// ruleid: go-tls-insecure-config
	cfg.MinVersion = tls.VersionTLS11
}
