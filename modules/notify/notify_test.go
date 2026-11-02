package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

type host struct{ vals map[string]string }

func (h host) Secret(_ context.Context, ref string) (string, error) {
	if v, ok := h.vals[ref]; ok {
		return v, nil
	}
	return "", errors.New("no")
}
func (host) Publish(context.Context, sdk.Event) {}
func (host) Log(string, string, ...any)         {}

func TestWebhookSignedAndNtfy(t *testing.T) {
	var gotSig, gotTitle, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotSig = r.Header.Get("X-Conduit-Signature")
		gotTitle = r.Header.Get("Title")
	}))
	defer srv.Close()
	m := New()
	ctx := context.Background()
	h := host{vals: map[string]string{"secret://hook": srv.URL + "/in", "secret://key": "k3y"}}

	cfg, _ := json.Marshal(Config{Channel: "webhook", URL: "secret://hook", Secret: "secret://key"})
	if err := m.Configure(ctx, h, "w", cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "w", Action: "send", Input: json.RawMessage(`{"title":"Disk","message":"95% full","priority":"high"}`)}); err != nil {
		t.Fatal(err)
	}
	if gotSig != Sign("k3y", []byte(gotBody)) {
		t.Fatalf("signature %q does not match body", gotSig)
	}

	cfg, _ = json.Marshal(Config{Channel: "ntfy", Server: srv.URL, Topic: "my-topic", MinPriority: "normal"})
	_ = m.Configure(ctx, h, "n", cfg)
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "n", Action: "test"}); err != nil {
		t.Fatal(err)
	}
	if gotTitle != "Conduit" || gotBody == "" {
		t.Fatalf("ntfy title=%q body=%q", gotTitle, gotBody)
	}
	r, _ := m.Invoke(ctx, sdk.Call{Instance: "n", Action: "send", Input: json.RawMessage(`{"message":"meh","priority":"low"}`)})
	if string(r.Output) != `{"reason":"below this channel's minimum priority","sent":false}` {
		t.Fatalf("min priority not applied: %s", r.Output)
	}
	if err := m.Configure(ctx, h, "x", json.RawMessage(`{"channel":"telegram"}`)); err == nil {
		t.Fatal("telegram without token accepted")
	}
}

func TestEscapeMD(t *testing.T) {
	if got := escapeMD("a_b.c!"); got != `a\_b\.c\!` {
		t.Fatalf("got %s", got)
	}
}
