// Package totp implements two-factor sign-in with authenticator apps (TOTP,
// RFC 6238: HMAC-SHA1, 6 digits, 30-second steps) and one-time recovery
// codes. The daemon (internal/auth) and the hub (internal/hub) both use it.
//
// Secrets are encrypted at rest with XChaCha20-Poly1305 under a random key
// kept separately in the same database's settings, so a copy of the
// two-factor table alone (a backup excerpt, a log) doesn't reveal them.
// Codes are accepted one step either side of now, and a step that was used
// once (or any older one) is refused, so a code seen over someone's shoulder
// can't be replayed.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Period is the length of one time step.
	Period = 30
	// Digits is the length of a code.
	Digits = 6
	// RecoveryCodes is how many recovery codes are issued at a time.
	RecoveryCodes = 10
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a fresh 160-bit secret.
func NewSecret() []byte {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// Encode is the secret as people type it into an app (base32).
func Encode(secret []byte) string { return b32.EncodeToString(secret) }

// URI is the otpauth:// link authenticator apps scan as a QR code.
func URI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {Encode(secret)}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {fmt.Sprint(Digits)}, "period": {fmt.Sprint(Period)}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Step is the time step of t.
func Step(t time.Time) int64 { return t.Unix() / Period }

// Code is the code for one step.
func Code(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%06d", n)
}

// Verify checks a code against the steps around now and returns the step
// it matched. Steps at or before last (the last one used) are refused.
func Verify(secret []byte, code string, now time.Time, last int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != Digits {
		return 0, false
	}
	cur := Step(now)
	for _, st := range []int64{cur - 1, cur, cur + 1} {
		if st <= last {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(Code(secret, st)), []byte(code)) == 1 {
			return st, true
		}
	}
	return 0, false
}

// NewRecoveryCodes returns n codes to show once, and their hashes to store.
// Each code carries 100 random bits, written as five groups of four.
func NewRecoveryCodes(n int) (codes, hashes []string) {
	for i := 0; i < n; i++ {
		b := make([]byte, 13)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		s := strings.ToLower(b32.EncodeToString(b))[:20]
		c := s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20]
		codes = append(codes, c)
		hashes = append(hashes, HashRecoveryCode(c))
	}
	return codes, hashes
}

// HashRecoveryCode normalises a recovery code (case, dashes, spaces) and
// hashes it. The codes are long and random, so a fast hash is enough.
func HashRecoveryCode(code string) string {
	c := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	h := sha256.Sum256([]byte("conduit-recovery-v1 " + c))
	return hex.EncodeToString(h[:])
}

// LooksLikeRecoveryCode tells recovery codes from six-digit codes.
func LooksLikeRecoveryCode(s string) bool {
	return len(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s))) == 20
}

// --- encryption at rest -------------------------------------------------------

// NewKey returns a fresh key for Seal and Open, base64-encoded for storage.
func NewKey() string {
	k := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(k)
}

// Seal encrypts a secret for the given owner (account id, as associated data).
func Seal(key string, secret []byte, owner string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, secret, []byte("conduit-totp-v1 "+owner))), nil
}

// Open decrypts a sealed secret.
func Open(key, sealed, owner string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil || len(b) < aead.NonceSize() {
		return nil, errors.New("damaged two-factor secret")
	}
	pt, err := aead.Open(nil, b[:aead.NonceSize()], b[aead.NonceSize():], []byte("conduit-totp-v1 "+owner))
	if err != nil {
		return nil, errors.New("damaged two-factor secret")
	}
	return pt, nil
}

// --- sign-in challenges -------------------------------------------------------

// Challenges hold the half-finished sign-ins between the password and the
// code: short-lived, bound to one account, at most a few code attempts.
type Challenges struct {
	mu  sync.Mutex
	m   map[string]*challenge
	TTL time.Duration
	Max int // pending challenges at most
	now func() time.Time
}

type challenge struct {
	account  string
	device   string
	expires  time.Time
	attempts int
}

// MaxAttempts is how many wrong codes one challenge takes.
const MaxAttempts = 5

// NewChallenges returns a store with a 5-minute lifetime.
func NewChallenges() *Challenges {
	return &Challenges{m: map[string]*challenge{}, TTL: 5 * time.Minute, Max: 10000, now: time.Now}
}

// Put starts a challenge for an account; "" when the store is full.
func (c *Challenges) Put(account, device string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.m) >= c.Max {
		for k, v := range c.m {
			if now.After(v.expires) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= c.Max {
			return ""
		}
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)
	c.m[id] = &challenge{account: account, device: device, expires: now.Add(c.TTL)}
	return id
}

// Peek returns a live challenge's account and device without using it up.
func (c *Challenges) Peek(id string) (account, device string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := c.m[id]
	if ch == nil || c.now().After(ch.expires) {
		delete(c.m, id)
		return "", "", false
	}
	return ch.account, ch.device, true
}

// Done forgets a challenge after a successful code.
func (c *Challenges) Done(id string) {
	c.mu.Lock()
	delete(c.m, id)
	c.mu.Unlock()
}

// Failed counts a wrong code; after MaxAttempts the challenge is gone and
// the person starts again with their password.
func (c *Challenges) Failed(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch := c.m[id]; ch != nil {
		ch.attempts++
		if ch.attempts >= MaxAttempts {
			delete(c.m, id)
		}
	}
}
