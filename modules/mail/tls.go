package mail

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
)

// Connection security for one endpoint.
const (
	secTLS      = "tls"      // implicit TLS (993, 465)
	secStartTLS = "starttls" // plain connect, then upgrade (143, 587, Proton Bridge)
	secNone     = "none"     // loopback only
)

// Certificate trust.
const (
	trustSystem = "system" // the operating system's certificate authorities
	trustPinned = "pinned" // one exact certificate, by SHA-256 fingerprint
)

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// security returns how to connect to host:port.
func security(set string, host string, port int, legacyInsecure bool) (string, error) {
	s := strings.ToLower(strings.TrimSpace(set))
	if s == "" {
		switch {
		case legacyInsecure && isLoopback(host):
			s = secNone
		case port == 993 || port == 465:
			s = secTLS
		default:
			s = secStartTLS
		}
	}
	switch s {
	case secTLS, secStartTLS:
		return s, nil
	case secNone:
		if !isLoopback(host) {
			return "", fmt.Errorf("unencrypted connections are only allowed to this machine (127.0.0.1 or localhost), not %s", host)
		}
		return s, nil
	}
	return "", fmt.Errorf("unknown connection security %q (use tls, starttls or none)", set)
}

// Fingerprint formats a certificate's SHA-256 fingerprint as colon-separated
// upper-case hex, the way browsers and openssl show it.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return strings.ToUpper(colons(hex.EncodeToString(sum[:])))
}

// normFingerprint accepts hex with or without colons or spaces, any case,
// optionally prefixed "SHA256:".
func normFingerprint(s string) (string, error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '='); i >= 0 && strings.Contains(strings.ToLower(s[:i]), "sha256") {
		s = s[i+1:] // "SHA256 Fingerprint=AB:CD…" from openssl
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "SHA256:"), "sha256:")
	r := strings.NewReplacer(":", "", " ", "", "-", "")
	h := strings.ToLower(r.Replace(s))
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != sha256.Size {
		return "", errors.New("a certificate fingerprint is 64 hex characters (SHA-256)")
	}
	return strings.ToUpper(colons(h)), nil
}

func colons(h string) string {
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// pemFingerprint reads the first certificate of a PEM block (Proton Bridge
// exports cert.pem) and returns its fingerprint.
func pemFingerprint(p string) (string, *x509.Certificate, error) {
	rest := []byte(strings.TrimSpace(p))
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return "", nil, errors.New("the certificate isn't PEM (it should start with -----BEGIN CERTIFICATE-----)")
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return "", nil, fmt.Errorf("the certificate can't be read: %w", err)
		}
		return Fingerprint(blk.Bytes), c, nil
	}
}

// ErrPinMismatch is returned when a server presents a different certificate
// from the pinned one.
type ErrPinMismatch struct {
	Endpoint, Want, Got string
}

func (e *ErrPinMismatch) Error() string {
	return fmt.Sprintf("the %s server's certificate changed: it presents %s but %s is pinned. If you regenerated Proton Bridge's certificate (or the server changed it on purpose), trust the new one with trust_certificate or paste it into the settings; otherwise someone may be intercepting the connection", strings.ToUpper(e.Endpoint), e.Got, e.Want)
}

// tlsConfig returns the TLS settings for one endpoint.
func (a *account) tlsConfig(endpoint, host string) *tls.Config {
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if a.trust != trustPinned {
		return cfg
	}
	// Pinning replaces chain verification with an exact match on the
	// certificate the person trusts. The standard verifier is switched off
	// only so a self-signed certificate can be checked this way; the
	// VerifyConnection callback below refuses every other certificate.
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("the server sent no certificate")
		}
		leaf := cs.PeerCertificates[0]
		got := Fingerprint(leaf.Raw)
		if want := a.pinFor(endpoint); want != "" {
			if want != got {
				return &ErrPinMismatch{Endpoint: endpoint, Want: want, Got: got}
			}
			return nil
		}
		// Trust on first use: remember this certificate and require it from
		// now on.
		err := a.state.update(func(d *stateData) {
			if _, ok := d.Pins[endpoint]; !ok {
				d.Pins[endpoint] = pin{Fingerprint: got, Since: time.Now().UTC().Format(time.RFC3339), Subject: leaf.Subject.String()}
			}
		})
		if err != nil {
			a.log("warn", "could not save the pinned certificate", "err", err)
		}
		if p := a.state.get().Pins[endpoint]; p.Fingerprint != got {
			return &ErrPinMismatch{Endpoint: endpoint, Want: p.Fingerprint, Got: got}
		}
		a.log("info", "pinned the server certificate on first use", "endpoint", endpoint, "fingerprint", got)
		return nil
	}
	return cfg
}

// pinFor is the fingerprint an endpoint must present, or "" when the next
// connection should pin on first use.
func (a *account) pinFor(endpoint string) string {
	if a.configPin != "" {
		return a.configPin
	}
	return a.state.get().Pins[endpoint].Fingerprint
}

// pinInfo describes the trust for one endpoint, for Health and tls_status.
func (a *account) pinInfo(endpoint string) map[string]any {
	out := map[string]any{"trust": a.trust}
	if a.trust != trustPinned {
		return out
	}
	switch {
	case a.configPin != "":
		out["pinned"], out["source"] = a.configPin, a.configPinSource
	default:
		if p, ok := a.state.get().Pins[endpoint]; ok {
			out["pinned"], out["source"], out["since"] = p.Fingerprint, "first use", p.Since
			if p.Subject != "" {
				out["subject"] = p.Subject
			}
		} else {
			out["source"] = "first use (not connected yet)"
		}
	}
	return out
}

// probe connects to an endpoint, completes the TLS handshake without
// trusting anything, and returns the certificate it presents. No
// credentials are sent.
func probe(ctx context.Context, proto, host string, port int, sec string) (*x509.Certificate, error) {
	if sec == secNone {
		return nil, errors.New("this connection isn't encrypted")
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	var leaf *x509.Certificate
	capture := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, // probing only; nothing is sent
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 0 {
				leaf = cs.PeerCertificates[0]
			}
			return nil
		}}
	d := &net.Dialer{Timeout: 10 * time.Second}
	if sec == secTLS {
		c, err := tls.DialWithDialer(d, "tcp", addr, capture)
		if err != nil {
			return nil, err
		}
		c.Close()
		return leaf, nil
	}
	if proto == "imap" {
		c, err := imapclient.DialStartTLS(addr, &imapclient.Options{TLSConfig: capture, Dialer: d})
		if err != nil {
			return nil, err
		}
		c.Close()
		return leaf, nil
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := smtpStartTLS(conn, capture); err != nil {
		return nil, err
	}
	return leaf, nil
}

// smtpStartTLS speaks just enough SMTP to upgrade a connection.
func smtpStartTLS(conn net.Conn, cfg *tls.Config) error {
	r := bufio.NewReader(conn)
	reply := func() (int, error) {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return 0, err
			}
			if len(line) < 4 {
				return 0, fmt.Errorf("unexpected SMTP reply %q", line)
			}
			code, _ := strconv.Atoi(line[:3])
			if line[3] != '-' {
				return code, nil
			}
		}
	}
	if code, err := reply(); err != nil || code != 220 {
		return fmt.Errorf("no SMTP greeting (%d, %v)", code, err)
	}
	fmt.Fprintf(conn, "EHLO conduit\r\n")
	if code, err := reply(); err != nil || code != 250 {
		return fmt.Errorf("EHLO refused (%d, %v)", code, err)
	}
	fmt.Fprintf(conn, "STARTTLS\r\n")
	if code, err := reply(); err != nil || code != 220 {
		return fmt.Errorf("the server doesn't offer STARTTLS (%d, %v)", code, err)
	}
	tc := tls.Client(conn, cfg)
	if err := tc.Handshake(); err != nil {
		return err
	}
	fmt.Fprintf(tc, "QUIT\r\n")
	return nil
}

// tlsHint makes certificate errors actionable.
func tlsHint(err error) error {
	if err == nil {
		return nil
	}
	var mm *ErrPinMismatch
	if errors.As(err, &mm) {
		return mm
	}
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	if errors.As(err, &ua) || errors.As(err, &hn) || strings.Contains(err.Error(), "certificate signed by unknown authority") {
		return fmt.Errorf("%w (if this is Proton Mail Bridge or another server with a self-signed certificate, set Certificate trust to Pinned)", err)
	}
	return err
}
