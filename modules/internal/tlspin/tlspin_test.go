package tlspin

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPinned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	good := strings.ToUpper(hex.EncodeToString(sum[:]))

	get := func(fp string, insecure bool) error {
		tc, err := Config(fp, insecure)
		if err != nil {
			return err
		}
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}
		res, err := c.Get(srv.URL)
		if err == nil {
			res.Body.Close()
		}
		return err
	}
	if err := get(good[:2]+":"+good[2:], false); err != nil {
		t.Fatalf("pinned certificate refused: %v", err)
	}
	if err := get(strings.Repeat("ab", 32), false); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("wrong pin accepted: %v", err)
	}
	if err := get("", false); err == nil {
		t.Fatal("self-signed certificate accepted without a pin")
	}
	if err := get("", true); err != nil {
		t.Fatal(err)
	}
	if _, err := Config("xyz", false); err == nil {
		t.Fatal("accepted a bad fingerprint")
	}
}
