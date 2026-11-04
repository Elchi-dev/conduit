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
