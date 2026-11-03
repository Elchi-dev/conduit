package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1, last six digits.
func TestRFC6238(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		if got := Code(secret, Step(time.Unix(v.unix, 0))); got != v.want {
			t.Errorf("t=%d: %s, want %s", v.unix, got, v.want)
		}
	}
}

func TestVerifyWindowAndReplay(t *testing.T) {
	s := NewSecret()
	now := time.Unix(1_800_000_000, 0)
	cur := Step(now)
	st, ok := Verify(s, Code(s, cur), now, 0)
	if !ok || st != cur {
		t.Fatal("current code refused")
	}
	if _, ok := Verify(s, Code(s, cur), now, st); ok {
		t.Fatal("the same code was accepted twice")
	}
	if _, ok := Verify(s, Code(s, cur-1), now, cur-2); !ok {
		t.Fatal("previous step refused")
	}
	if _, ok := Verify(s, Code(s, cur-2), now, 0); ok {
		t.Fatal("a code two steps old was accepted")
	}
	if _, ok := Verify(s, "12345", now, 0); ok {
		t.Fatal("short code accepted")
	}
}

func TestSealAndRecovery(t *testing.T) {
	k := NewKey()
	sealed, err := Seal(k, []byte("abc"), "user_1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(k, sealed, "user_1"); err != nil || string(got) != "abc" {
		t.Fatal("round trip")
	}
	if _, err := Open(k, sealed, "user_2"); err == nil {
		t.Fatal("opened for another account")
	}
	codes, hashes := NewRecoveryCodes(RecoveryCodes)
	if len(codes) != 10 || len(codes[0]) != 24 || !LooksLikeRecoveryCode(codes[0]) {
		t.Fatalf("%v", codes)
	}
	if HashRecoveryCode(" "+codes[3]+" ") != hashes[3] || HashRecoveryCode(strings.ToUpper(codes[3])) != hashes[3] {
		t.Fatal("normalisation")
	}
}

func TestChallenges(t *testing.T) {
	c := NewChallenges()
	id := c.Put("acct", "Laptop")
	if a, d, ok := c.Peek(id); !ok || a != "acct" || d != "Laptop" {
		t.Fatal("peek")
	}
	for i := 0; i < MaxAttempts; i++ {
		c.Failed(id)
	}
	if _, _, ok := c.Peek(id); ok {
		t.Fatal("still there after too many wrong codes")
	}
	id = c.Put("acct", "")
	c.Done(id)
	if _, _, ok := c.Peek(id); ok {
		t.Fatal("reused")
	}
	now := time.Now()
	c.now = func() time.Time { return now.Add(time.Hour) }
	id2 := c.Put("x", "")
	c.now = func() time.Time { return now.Add(3 * time.Hour) }
	if _, _, ok := c.Peek(id2); ok {
		t.Fatal("expired challenge used")
	}
}
