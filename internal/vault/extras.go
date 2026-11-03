package vault

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

// --- password generator ------------------------------------------------------

const (
	lower   = "abcdefghijkmnopqrstuvwxyz"
	upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	digits  = "23456789"
	symbols = "!#$%&*+-=?@^_~"
)

// Generate returns a random password of length n (16–128) drawn from
// letters, digits and, if withSymbols, symbols, with at least one of each.
func Generate(n int, withSymbols bool) (string, error) {
	if n < 16 || n > 128 {
		return "", errors.New("length must be between 16 and 128")
	}
	sets := []string{lower, upper, digits}
	if withSymbols {
		sets = append(sets, symbols)
	}
	all := strings.Join(sets, "")
	pick := func(s string) byte {
		i, err := rand.Int(rand.Reader, big.NewInt(int64(len(s))))
		if err != nil {
			panic(err)
		}
		return s[i.Int64()]
	}
	out := make([]byte, n)
	for i := range out {
		if i < len(sets) {
			out[i] = pick(sets[i])
		} else {
			out[i] = pick(all)
		}
	}
	// Shuffle so the guaranteed characters are not always first.
	for i := len(out) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		out[i], out[j.Int64()] = out[j.Int64()], out[i]
	}
	return string(out), nil
}

// --- TOTP (RFC 6238) -----------------------------------------------------------

// TOTP returns the current 6-digit code for a base32 secret or an otpauth://
// URI, and the seconds until it changes.
func TOTP(secret string, now time.Time) (string, int, error) {
	period := int64(30)
	if strings.HasPrefix(secret, "otpauth://") {
		u, err := url.Parse(secret)
		if err != nil {
			return "", 0, err
		}
		secret = u.Query().Get("secret")
		if p := u.Query().Get("period"); p != "" {
			if _, err := fmt.Sscan(p, &period); err != nil || period < 1 || period > 3600 {
				return "", 0, errors.New("the TOTP period must be between 1 and 3600 seconds")
			}
		}
	}
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(clean, "="))
	if err != nil {
		return "", 0, errors.New("the TOTP secret is not valid base32")
	}
	counter := now.Unix() / period
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1_000_000
	remaining := int(period - now.Unix()%period)
	return fmt.Sprintf("%06d", code), remaining, nil
}

// --- .env import ----------------------------------------------------------------

// ParseEnv reads KEY=value lines (comments and blank lines ignored, optional
// "export ", single or double quotes stripped).
func ParseEnv(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		if k != "" {
			out[k] = v
		}
	}
	return out, sc.Err()
}

// EnvName turns an environment variable name into a secret name:
// "DATABASE_URL" with prefix "app" becomes "app/database-url".
func EnvName(prefix, key string) string {
	n := strings.ToLower(strings.ReplaceAll(key, "_", "-"))
	if prefix != "" {
		n = strings.Trim(strings.ToLower(prefix), "/") + "/" + n
	}
	return n
}

// --- leak watch -------------------------------------------------------------------

// Leak is one place a vault secret's value was found.
type Leak struct {
	Secret string `json:"secret"`
	File   string `json:"file,omitempty"`
	Line   int    `json:"line"`
}

// minLeakLen avoids false positives from short values like "1234".
const minLeakLen = 8

// ScanText reports vault secrets whose values appear in text.
func (v *Vault) ScanText(ctx context.Context, text string) ([]Leak, error) {
	vals, err := v.values(ctx)
	if err != nil {
		return nil, err
	}
	defer wipe(vals)
	var out []Leak
	for i, line := range strings.Split(text, "\n") {
		for name, val := range vals {
			if len(val) >= minLeakLen && strings.Contains(line, val) {
				out = append(out, Leak{Secret: name, Line: i + 1})
			}
		}
	}
	return out, nil
}

// skipDirs are never scanned.
var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "target": true, "dist": true, ".venv": true, "__pycache__": true}

// ScanPath walks a file or directory (up to maxFiles files of at most 2 MiB
// each) and reports where vault secret values appear.
func (v *Vault) ScanPath(ctx context.Context, root string, maxFiles int) ([]Leak, int, error) {
	vals, err := v.values(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer wipe(vals)
	if maxFiles <= 0 {
		maxFiles = 20000
	}
	var out []Leak
	scanned := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skipDirs[d.Name()] && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if scanned >= maxFiles {
			return filepath.SkipAll
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil || isBinary(b) {
			return nil
		}
		scanned++
		text := string(b)
		for name, val := range vals {
			if len(val) < minLeakLen || !strings.Contains(text, val) {
				continue
			}
			for i, line := range strings.Split(text, "\n") {
				if strings.Contains(line, val) {
					rel, _ := filepath.Rel(root, path)
					if rel == "." {
						rel = filepath.Base(path)
					}
					out = append(out, Leak{Secret: name, File: rel, Line: i + 1})
				}
			}
		}
		return nil
	})
	return out, scanned, err
}

func isBinary(b []byte) bool {
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	for _, c := range b[:n] {
		if c == 0 {
			return true
		}
	}
	return false
}

func wipe(m map[string]string) {
	for k := range m {
		delete(m, k)
	}
}

// --- OS keychain ------------------------------------------------------------------

// OSKeychain stores the data key in the operating system's credential store
// (macOS Keychain, Windows Credential Manager, Secret Service on Linux).
type OSKeychain struct{ Account string }

const keychainService = "dev.elchi.conduit.vault"

// Get implements Keychain.
func (k OSKeychain) Get() ([]byte, error) {
	s, err := keyring.Get(keychainService, k.Account)
	if err != nil {
		return nil, err
	}
	return base32.StdEncoding.DecodeString(s)
}

// Set implements Keychain.
func (k OSKeychain) Set(key []byte) error {
	return keyring.Set(keychainService, k.Account, base32.StdEncoding.EncodeToString(key))
}

// Delete implements Keychain.
func (k OSKeychain) Delete() error {
	err := keyring.Delete(keychainService, k.Account)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}
