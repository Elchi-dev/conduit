package rest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSameHostRedirects(t *testing.T) {
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("X-Api-Key")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer other.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/away":
			http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
		case "/moved":
			http.Redirect(w, r, "/here", http.StatusMovedPermanently)
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer api.Close()

	c := New(api.URL, func(_ context.Context, r *http.Request) error {
		r.Header.Set("X-Api-Key", "s3cret")
		return nil
	})
	c.HTTP = SameHostOnly(c.HTTP)
	if c.HTTP.Timeout == 0 {
		t.Fatal("SameHostOnly dropped the timeout")
	}
	var out struct{ OK bool }
	if _, err := c.Do(context.Background(), "GET", "/moved", nil, nil, &out); err != nil || !out.OK {
		t.Fatalf("same-host redirect: %v %+v", err, out)
	}
	_, err := c.Do(context.Background(), "GET", "/away", nil, nil, nil)
	if !errors.Is(err, ErrCrossHostRedirect) || !strings.Contains(err.Error(), "another host") {
		t.Fatalf("cross-host redirect: %v", err)
	}
	if leaked != "" {
		t.Fatalf("key reached the other host: %q", leaked)
	}
}
