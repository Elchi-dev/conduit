package rest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTransportErrorDropsQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, _ := w.(http.Hijacker).Hijack()
		c.Close()
	}))
	defer srv.Close()
	c := New(srv.URL, nil)
	_, err := c.Do(context.Background(), "GET", "/v1/orders", url.Values{"filter[user_email]": {"victim@example.org"}}, nil, nil)
	if err == nil || strings.Contains(err.Error(), "victim") || strings.Contains(err.Error(), "?") || !strings.Contains(err.Error(), "/v1/orders") {
		t.Fatalf("Do: %v", err)
	}
	var ue *url.Error
	if !errors.As(err, &ue) || strings.Contains(ue.URL, "victim") {
		t.Fatalf("no clean *url.Error: %#v", err)
	}
	_, err = c.Send(context.Background(), "GET", "/x", url.Values{"api_key": {"k"}}, nil, nil)
	if err == nil || strings.Contains(err.Error(), "api_key") {
		t.Fatalf("Send: %v", err)
	}
}

func TestTransportErrorTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(200 * time.Millisecond) }))
	defer srv.Close()
	c := New(srv.URL, nil)
	c.HTTP.Timeout = 20 * time.Millisecond
	_, err := c.Do(context.Background(), "GET", "/x", url.Values{"q": {"private"}}, nil, nil)
	var te interface{ Timeout() bool }
	if !errors.As(err, &te) || !te.Timeout() || strings.Contains(err.Error(), "private") {
		t.Fatalf("timeout: %v", err)
	}
}

func TestRefusedRedirectNamesOnlyHost(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://store.example.net/logs/x?X-Amz-Credential=AKIAEXAMPLE&X-Amz-Signature=deadbeef", http.StatusFound)
	}))
	defer api.Close()
	c := New(api.URL, nil)
	c.HTTP = SameHostOnly(c.HTTP)
	for _, send := range []bool{false, true} {
		var err error
		if send {
			_, err = c.Send(context.Background(), "GET", "/log", nil, nil, nil)
		} else {
			_, err = c.Do(context.Background(), "GET", "/log", nil, nil, nil)
		}
		if !errors.Is(err, ErrCrossHostRedirect) || err.Error() != "refusing redirect to another host (store.example.net)" {
			t.Fatalf("send=%v: %v", send, err)
		}
	}
}

func TestCleanURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://u:p@h.example/a/b?k=v#f": "https://h.example/a/b",
		"http://h:8080/x?":                "http://h:8080/x",
		"https://h/x":                     "https://h/x",
		"not a url?secret=1":              "not a url",
	} {
		if got := CleanURL(in); got != want {
			t.Errorf("CleanURL(%q) = %q, want %q", in, got, want)
		}
	}
}
