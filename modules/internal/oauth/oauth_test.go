package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestExchangeErrorsQuoteOnlyTheCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		io.WriteString(w, `{"error":"invalid_grant","error_description":"token SECRET-VALUE is bad"}`)
	}))
	defer srv.Close()
	_, err := Exchange(context.Background(), srv.Client(), srv.URL, url.Values{"refresh_token": {"SECRET-VALUE"}}, "", "")
	var e *Error
	if !errors.As(err, &e) || e.Code != "invalid_grant" || strings.Contains(err.Error(), "SECRET") {
		t.Fatal(err)
	}
}

func TestCache(t *testing.T) {
	now := time.Now()
	c := &Cache{Now: func() time.Time { return now }}
	n := 0
	fetch := func(context.Context) (Grant, error) { n++; return Grant{Access: "a", ExpiresIn: 120}, nil }
	for i := 0; i < 3; i++ {
		if _, err := c.Get(context.Background(), fetch); err != nil {
			t.Fatal(err)
		}
	}
	if n != 1 {
		t.Fatal(n)
	}
	now = now.Add(61 * time.Second) // within a minute of expiry
	c.Get(context.Background(), fetch)
	c.Drop()
	c.Get(context.Background(), fetch)
	if n != 3 {
		t.Fatal(n)
	}
}

func TestExchangeRefusesCrossHostRedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		t.Errorf("the form reached another host: %s", b)
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/token", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	_, err := Exchange(context.Background(), &http.Client{}, srv.URL, url.Values{"client_secret": {"SECRET-VALUE"}}, "", "")
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal(err)
	}
}

func TestCacheCapsLifetime(t *testing.T) {
	now := time.Now()
	c := &Cache{Now: func() time.Time { return now }}
	n := 0
	fetch := func(context.Context) (Grant, error) { n++; return Grant{Access: "a", ExpiresIn: 1 << 30}, nil }
	c.Get(context.Background(), fetch)
	now = now.Add(25 * time.Hour)
	c.Get(context.Background(), fetch)
	if n != 2 {
		t.Fatal(n)
	}
}
