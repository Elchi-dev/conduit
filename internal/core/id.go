package core

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

var idEncoding = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

// NewID returns a random, URL-safe identifier with a readable prefix, e.g.
// "appr_7k2m9x4q1c8v3b6n". 80 bits of randomness.
func NewID(prefix string) string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return prefix + "_" + strings.ToLower(idEncoding.EncodeToString(b))
}
