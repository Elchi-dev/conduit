package auth

import (
	"context"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/core"
)

func TestPasswordHash(t *testing.T) {
	h := HashPassword("correct horse battery")
	if !VerifyPassword(h, "correct horse battery") {
		t.Fatal("valid password rejected")
	}
	if VerifyPassword(h, "correct horse batterY") {
		t.Fatal("wrong password accepted")
	}
	if HashPassword("x") == HashPassword("x") {
		t.Fatal("hashes must be salted")
	}
}

func TestScopes(t *testing.T) {
	cases := []struct {
		granted []string
		need    string
		ok      bool
	}{
		{[]string{"actions:*:invoke"}, "actions:mail:invoke", true},
		{[]string{"actions:mail:invoke"}, "actions:mail:invoke", true},
		{[]string{"actions:mail:invoke"}, "actions:servers:invoke", false},
		{[]string{"audit:*:read"}, "audit:*:undo", false},
		{[]string{"audit:*:*"}, "audit:*:undo", true},
		{[]string{"admin:*:*"}, "keys:*:manage", true},
		{nil, "modules:*:read", false},
	}
	for _, c := range cases {
		if got := Allows(c.granted, c.need); got != c.ok {
			t.Errorf("Allows(%v, %s) = %v", c.granted, c.need, got)
		}
	}
	for _, bad := range []string{"actions", "actions:*", "nope:*:read", "audit:*:write"} {
		if ValidateScope(bad) == nil {
			t.Errorf("ValidateScope(%q) should fail", bad)
		}
	}
}

func TestRateLimit(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !l.allow("k", 3, now) {
			t.Fatalf("request %d should pass", i)
		}
	}
	if l.allow("k", 3, now) {
		t.Fatal("4th request in the same instant should be limited")
	}
	if !l.allow("k", 3, now.Add(21*time.Second)) {
		t.Fatal("bucket should refill (3/min = 1 per 20s)")
	}
}

func TestIPAllow(t *testing.T) {
	if !ipAllowed([]string{"10.0.0.0/8"}, "10.1.2.3") || ipAllowed([]string{"10.0.0.0/8"}, "192.168.1.1") {
		t.Fatal("CIDR matching broken")
	}
	if !ipAllowed([]string{"::1"}, "::1") || !ipAllowed([]string{"127.0.0.1"}, "::ffff:127.0.0.1") {
		t.Fatal("single-address matching broken")
	}
}

func TestSessionsAndKeys(t *testing.T) {
	ctx := context.Background()
	st, err := core.OpenStore(ctx, t.TempDir()+"/a.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := New(st)
	if _, err := s.Setup(ctx, "", "short@example.com", "short"); err == nil {
		t.Fatal("short password accepted")
	}
	u, err := s.Setup(ctx, "Me", "me@example.com", "long enough pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Setup(ctx, "", "two@example.com", "long enough pw"); err != ErrSetupDone {
		t.Fatalf("second setup: %v", err)
	}
	_, tok, _ := s.CreateSession(ctx, u.ID, "test")
	if _, _, err := s.SessionUser(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SessionUser(ctx, tok+"x"); err == nil {
		t.Fatal("altered token accepted")
	}
	k, full, err := s.CreateKey(ctx, u.ID, NewKey{Name: "exp", Scopes: []string{"modules:*:read"}, ExpiresAt: ptr(time.Now().Add(-time.Second))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupKey(ctx, full, "127.0.0.1"); err == nil {
		t.Fatalf("expired key %s accepted", k.ID)
	}
	// Swap the kind in an otherwise valid key: must be rejected.
	_, full2, _ := s.CreateKey(ctx, u.ID, NewKey{Name: "agent", Kind: KeyAgent, Scopes: []string{"modules:*:read"}})
	forged := "cdt_live_" + full2[len("cdt_agent_"):]
	if _, err := s.LookupKey(ctx, forged, "127.0.0.1"); err == nil {
		t.Fatal("kind-swapped key accepted")
	}
}

func ptr[T any](v T) *T { return &v }
