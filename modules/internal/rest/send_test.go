package rest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/patch":
			if r.Header.Get("Content-Type") != "application/json-patch+json" || r.Header.Get("X-Key") != "k" || r.URL.Query().Get("v") != "1" {
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, "ok")
		case "/jsonapi":
			w.WriteHeader(409)
			io.WriteString(w, `{"errors":[{"status":"409","title":"conflict","detail":"already locked"}]}`)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"type":"error","error":{"message":"Repository not found"}}`)
		}
	}))
	defer srv.Close()
	c := New(srv.URL, func(_ context.Context, r *http.Request) error { r.Header.Set("X-Key", "k"); return nil })
	res, err := c.Send(context.Background(), http.MethodPatch, "/patch", map[string][]string{"v": {"1"}}, strings.NewReader("[]"), http.Header{"Content-Type": {"application/json-patch+json"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(b) != "ok" {
		t.Fatal(string(b))
	}
	if _, err := c.Send(context.Background(), http.MethodGet, "/jsonapi", nil, nil, nil); !IsStatus(err, 409) || err.Error() != "already locked" {
		t.Fatal(err)
	}
	if _, err := c.Send(context.Background(), http.MethodGet, "/x", nil, nil, nil); !IsStatus(err, 404) || err.Error() != "Repository not found" {
		t.Fatal(err)
	}
}
