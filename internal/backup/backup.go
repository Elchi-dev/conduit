// Package backup writes and restores a whole daemon as one encrypted file.
//
// A backup holds a consistent snapshot of the database (SQLite VACUUM INTO,
// taken while the daemon runs) and every other file in the data folder
// (notes, sandboxed modules, settings files), as a tar archive. It is
// encrypted with a key derived from a passphrase the person chooses
// (Argon2id), in 64 KiB chunks sealed with XChaCha20-Poly1305: each chunk's
// nonce is a random prefix, the chunk number and a final-chunk flag, so
// chunks can't be reordered, dropped or cut off without the restore
// failing.
//
// The vault inside stays encrypted with its own passphrase: restoring a
// backup needs both the backup passphrase and, to use the secrets, the
// vault passphrase.
//
// File layout:
//
//	"CONDUIT-BACKUP\n"  magic
//	uint32 big-endian   header length
//	header (JSON)       {"v":1,"created":…,"version":…,"kdf":{"salt":…,"t":3,"m":65536,"p":2},"nonce":<16-byte prefix>}
//	chunks              each: uint32 big-endian sealed length, sealed bytes
package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	magic     = "CONDUIT-BACKUP\n"
	chunkSize = 64 << 10
	// DBName is the database file inside the data folder and the archive.
	DBName = "conduit.db"
	// MinPassphrase is the shortest backup passphrase accepted.
	MinPassphrase = 12
)

// Header is the unencrypted start of a backup file. It names no secrets.
type Header struct {
	V       int       `json:"v"`
	Created time.Time `json:"created"`
	Version string    `json:"version"` // daemon version that wrote it
	KDF     struct {
		Salt []byte `json:"salt"`
		T    uint32 `json:"t"`
		M    uint32 `json:"m"`
		P    uint8  `json:"p"`
	} `json:"kdf"`
	Nonce []byte `json:"nonce"` // 16-byte prefix of every chunk nonce
}

// skipped files are never in a backup: the live database (a snapshot is
// taken instead), its journal files, and one-time setup material.
func skipped(rel string) bool {
	base := filepath.Base(rel)
	switch {
	case rel == DBName, strings.HasPrefix(rel, DBName+"-"), base == "setup-token":
		return true
	case strings.HasPrefix(rel, "backups"+string(filepath.Separator)) || rel == "backups":
		return true // scheduled backups don't back up themselves
	case strings.HasSuffix(base, ".tmp"):
		return true
	}
	return false
}

// Write streams an encrypted backup of the data folder to w.
func Write(ctx context.Context, w io.Writer, db *sql.DB, dataDir, passphrase, version string) error {
	if len(passphrase) < MinPassphrase {
		return fmt.Errorf("the backup passphrase must be at least %d characters", MinPassphrase)
	}
	tmp, err := os.MkdirTemp("", "conduit-backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	snap := filepath.Join(tmp, DBName)
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, snap); err != nil {
		return fmt.Errorf("snapshot the database: %w", err)
	}

	h := Header{V: 1, Created: time.Now().UTC(), Version: version}
	h.KDF.Salt, h.KDF.T, h.KDF.M, h.KDF.P = random(16), 3, 64*1024, 2
	h.Nonce = random(16)
	key := argon2.IDKey([]byte(passphrase), h.KDF.Salt, h.KDF.T, h.KDF.M, h.KDF.P, chacha20poly1305.KeySize)
	hb, _ := json.Marshal(h)
	if _, err := io.WriteString(w, magic); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(hb))); err != nil {
		return err
	}
	if _, err := w.Write(hb); err != nil {
		return err
	}
	sw, err := newSealer(w, key, h.Nonce, hb)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(sw)
	if err := addFile(tw, snap, DBName); err != nil {
		return err
	}
	err = filepath.WalkDir(dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, _ := filepath.Rel(dataDir, path)
		if rel == "." || skipped(rel) {
			if d.IsDir() && rel != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || (!d.IsDir() && !d.Type().IsRegular()) {
			return nil // links and special files aren't part of a daemon's data
		}
		if d.IsDir() {
			return tw.WriteHeader(&tar.Header{Name: filepath.ToSlash(rel) + "/", Typeflag: tar.TypeDir, Mode: 0o700, ModTime: time.Now()})
		}
		return addFile(tw, path, filepath.ToSlash(rel))
	})
	if err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return sw.Close()
}

func addFile(tw *tar.Writer, path, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: st.Size(), ModTime: st.ModTime()}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// --- chunked encryption -----------------------------------------------------

type sealer struct {
	w     io.Writer
	aead  cipherAEAD
	pre   []byte
	ad    []byte
	buf   bytes.Buffer
	n     uint64
	close bool
}

type cipherAEAD interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
}

func newSealer(w io.Writer, key, prefix, header []byte) (*sealer, error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &sealer{w: w, aead: a, pre: prefix, ad: header}, nil
}

func chunkNonce(prefix []byte, n uint64, final bool) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSizeX) // 24
	copy(nonce, prefix)                                // 16 bytes
	binary.BigEndian.PutUint64(nonce[16:], n<<1)       // counter, low bit = final
	if final {
		nonce[23] |= 1
	}
	return nonce
}

func (s *sealer) Write(p []byte) (int, error) {
	n := len(p)
	s.buf.Write(p)
	for s.buf.Len() > chunkSize {
		if err := s.flush(s.buf.Next(chunkSize), false); err != nil {
			return 0, err
		}
	}
	return n, nil
}

func (s *sealer) flush(chunk []byte, final bool) error {
	sealed := s.aead.Seal(nil, chunkNonce(s.pre, s.n, final), chunk, s.ad)
	s.n++
	if err := binary.Write(s.w, binary.BigEndian, uint32(len(sealed))); err != nil {
		return err
	}
	_, err := s.w.Write(sealed)
	return err
}

// Close seals the last chunk (possibly empty) with the final flag.
func (s *sealer) Close() error {
	if s.close {
		return nil
	}
	s.close = true
	return s.flush(s.buf.Next(s.buf.Len()), true)
}

type opener struct {
	r    io.Reader
	aead cipherAEAD
	pre  []byte
	ad   []byte
	n    uint64
	buf  []byte
	done bool
}

// ErrWrongPassphrase means the backup didn't decrypt.
var ErrWrongPassphrase = errors.New("the backup didn't decrypt: wrong passphrase, or the file was changed")

func (o *opener) Read(p []byte) (int, error) {
	for len(o.buf) == 0 {
		if o.done {
			return 0, io.EOF
		}
		var l uint32
		if err := binary.Read(o.r, binary.BigEndian, &l); err != nil {
			return 0, errors.New("the backup ends early (cut off?)")
		}
		if l > chunkSize+64 {
			return 0, errors.New("the backup is damaged")
		}
		sealed := make([]byte, l)
		if _, err := io.ReadFull(o.r, sealed); err != nil {
			return 0, errors.New("the backup ends early (cut off?)")
		}
		// Try as a middle chunk, then as the final one.
		pt, err := o.aead.Open(nil, chunkNonce(o.pre, o.n, false), sealed, o.ad)
		if err != nil {
			pt, err = o.aead.Open(nil, chunkNonce(o.pre, o.n, true), sealed, o.ad)
			if err != nil {
				return 0, ErrWrongPassphrase
			}
			o.done = true
		}
		o.n++
		o.buf = pt
	}
	n := copy(p, o.buf)
	o.buf = o.buf[n:]
	return n, nil
}

// ReadHeader reads a backup's header without decrypting anything.
func ReadHeader(r io.Reader) (Header, []byte, error) {
	var h Header
	m := make([]byte, len(magic))
	if _, err := io.ReadFull(r, m); err != nil || string(m) != magic {
		return h, nil, errors.New("this isn't a Conduit backup")
	}
	var l uint32
	if err := binary.Read(r, binary.BigEndian, &l); err != nil || l > 64<<10 {
		return h, nil, errors.New("this isn't a Conduit backup")
	}
	hb := make([]byte, l)
	if _, err := io.ReadFull(r, hb); err != nil {
		return h, nil, errors.New("the backup is damaged")
	}
	if err := json.Unmarshal(hb, &h); err != nil || h.V != 1 || len(h.Nonce) != 16 || len(h.KDF.Salt) < 16 {
		return h, nil, errors.New("this backup is from a newer Conduit, or damaged")
	}
	if h.KDF.M > 1<<20 || h.KDF.T > 10 || h.KDF.P == 0 {
		return h, nil, errors.New("the backup asks for unreasonable key settings")
	}
	return h, hb, nil
}

// Restore decrypts a backup into dataDir, which must be empty or missing.
// Nothing is written until the passphrase is known to be right, and a
// partial restore is removed.
func Restore(r io.Reader, dataDir, passphrase string) (Header, error) {
	h, hb, err := ReadHeader(r)
	if err != nil {
		return h, err
	}
	if entries, err := os.ReadDir(dataDir); err == nil && len(entries) > 0 {
		return h, fmt.Errorf("%s isn't empty; restore into a new folder", dataDir)
	}
	key := argon2.IDKey([]byte(passphrase), h.KDF.Salt, h.KDF.T, h.KDF.M, h.KDF.P, chacha20poly1305.KeySize)
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return h, err
	}
	o := &opener{r: r, aead: a, pre: h.Nonce, ad: hb}
	tmp := dataDir + ".restoring"
	_ = os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return h, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	tr := tar.NewReader(o)
	sawDB := false
	for {
		th, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if errors.Is(err, ErrWrongPassphrase) {
				return h, err
			}
			return h, fmt.Errorf("the backup is damaged: %w", err)
		}
		name := filepath.FromSlash(th.Name)
		if !filepath.IsLocal(name) {
			return h, fmt.Errorf("the backup contains an unsafe path %q", th.Name)
		}
		dst := filepath.Join(tmp, name)
		switch th.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o700); err != nil {
				return h, err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return h, err
			}
			f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return h, err
			}
			_, err = io.Copy(f, tr)
			f.Close()
			if err != nil {
				return h, err
			}
			sawDB = sawDB || name == DBName
		default:
			return h, fmt.Errorf("the backup contains an unexpected entry %q", th.Name)
		}
	}
	// The final chunk must have been seen: otherwise the file was cut off.
	if !o.done {
		if _, err := io.Copy(io.Discard, o); err != nil || !o.done {
			return h, errors.New("the backup ends early (cut off?)")
		}
	}
	if !sawDB {
		return h, errors.New("the backup has no database")
	}
	_ = os.Remove(dataDir) // an empty folder, if it exists
	if err := os.Rename(tmp, dataDir); err != nil {
		return h, err
	}
	ok = true
	return h, nil
}
