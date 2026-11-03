package vault

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCloudflareRotation(t *testing.T) {
	live := "old-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+live {
			fmt.Fprint(w, `{"success":false,"errors":[{"message":"Invalid API Token"}]}`)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /user/tokens/verify":
			fmt.Fprint(w, `{"success":true,"result":{"id":"t1","status":"active"}}`)
		case "PUT /user/tokens/t1/value":
			live = "new-token"
			fmt.Fprint(w, `{"success":true,"result":"new-token"}`)
		}
	}))
	defer srv.Close()
	RegisterRotator(Cloudflare{API: srv.URL})
	defer RegisterRotator(Cloudflare{})

	v, _, _ := newVault(t)
	ctx := context.Background()
	if err := v.Setup(ctx, "a long vault passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(ctx, Meta{Name: "cf", Kind: KindToken, Description: "DNS"}, "old-token"); err != nil {
		t.Fatal(err)
	}
	if err := v.Rotate(ctx, "cf", "cloudflare"); err != nil {
		t.Fatal(err)
	}
	if got, _ := v.Get(ctx, "cf"); got != "new-token" {
		t.Fatalf("stored %q", got)
	}
	list, _ := v.List(ctx)
	if list[0].Description != "DNS" || list[0].Kind != KindToken {
		t.Fatalf("metadata lost: %+v", list[0])
	}
	if err := v.Rotate(ctx, "cf", "nope"); err == nil {
		t.Fatal("unknown provider accepted")
	}
}
