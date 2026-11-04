// Package tlspin builds the TLS settings for appliances that ship with their
// own self-signed certificate (a NAS, a firewall): normal verification, a
// pinned SHA-256 certificate fingerprint, or, when the person chose it, no
// verification at all.
package tlspin

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
)

// Normalize turns "AB:CD:…" or "abcd…" into lowercase hex, or fails when it
// isn't a SHA-256 fingerprint.
func Normalize(s string) (string, error) {
	h := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s)))
	if b, err := hex.DecodeString(h); err != nil || len(b) != sha256.Size {
		return "", errors.New("the fingerprint is a SHA-256 fingerprint: 32 bytes in hex, like AB:CD:…")
	}
	return h, nil
}

// Config returns the TLS configuration for a fingerprint (may be empty) and
// the insecure flag. A fingerprint wins over insecure.
func Config(fingerprint string, insecure bool) (*tls.Config, error) {
	if fingerprint != "" {
		fp, err := Normalize(fingerprint)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // replaced by the pin check below
			VerifyPeerCertificate: func(certs [][]byte, _ [][]*x509.Certificate) error {
				if len(certs) == 0 {
					return errors.New("the server sent no certificate")
				}
				sum := sha256.Sum256(certs[0])
				if hex.EncodeToString(sum[:]) != fp {
					return errors.New("the server's certificate doesn't match the pinned fingerprint")
				}
				return nil
			},
		}, nil
	}
	if insecure {
		return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, nil //nolint:gosec // the person chose it
	}
	return &tls.Config{MinVersion: tls.VersionTLS12}, nil
}
