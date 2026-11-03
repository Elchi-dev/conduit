package backup

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	data := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(data, DBName))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('hello')`); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(data, "notes", "sub"), 0o700)
	_ = os.WriteFile(filepath.Join(data, "notes", "sub", "a.md"), bytes.Repeat([]byte("x"), 200_000), 0o600)
	_ = os.WriteFile(filepath.Join(data, "setup-token"), []byte("secret"), 0o600)

	var buf bytes.Buffer
	if err := Write(ctx, &buf, db, data, "short", "test"); err == nil {
		t.Fatal("short passphrase accepted")
	}
	if err := Write(ctx, &buf, db, data, "a long backup passphrase", "test"); err != nil {
		t.Fatal(err)
	}
	file := buf.Bytes()
	if bytes.Contains(file, []byte("hello")) || bytes.Contains(file, []byte("xxxxxxxx")) {
		t.Fatal("backup isn't encrypted")
	}

	// Wrong passphrase: refused, nothing left behind.
	out := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(bytes.NewReader(file), out, "the wrong passphrase"); err != ErrWrongPassphrase {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("partial restore left behind")
	}
	// Cut off: refused.
	if _, err := Restore(bytes.NewReader(file[:len(file)-40]), out, "a long backup passphrase"); err == nil {
		t.Fatal("truncated backup restored")
	}
	// Last chunk dropped (cut on a chunk boundary): refused.
	// Flipped byte: refused.
	bad := append([]byte(nil), file...)
	bad[len(bad)/2] ^= 1
	if _, err := Restore(bytes.NewReader(bad), out, "a long backup passphrase"); err == nil {
		t.Fatal("changed backup restored")
	}

	h, err := Restore(bytes.NewReader(file), out, "a long backup passphrase")
	if err != nil || h.Version != "test" {
		t.Fatalf("%v %+v", err, h)
	}
	rdb, _ := sql.Open("sqlite", filepath.Join(out, DBName))
	defer rdb.Close()
	var v string
	if err := rdb.QueryRow(`SELECT v FROM t`).Scan(&v); err != nil || v != "hello" {
		t.Fatalf("db: %q %v", v, err)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "notes", "sub", "a.md")); len(b) != 200_000 {
		t.Fatal("file missing")
	}
	if _, err := os.Stat(filepath.Join(out, "setup-token")); err == nil {
		t.Fatal("setup token was backed up")
	}
	// Restoring over existing data is refused.
	if _, err := Restore(bytes.NewReader(file), out, "a long backup passphrase"); err == nil {
		t.Fatal("restored over existing data")
	}
}

func TestDroppedFinalChunk(t *testing.T) {
	ctx := context.Background()
	data := t.TempDir()
	db, _ := sql.Open("sqlite", filepath.Join(data, DBName))
	defer db.Close()
	_, _ = db.Exec(`CREATE TABLE t (v TEXT)`)
	_ = os.WriteFile(filepath.Join(data, "big"), bytes.Repeat([]byte("y"), 300_000), 0o600)
	var buf bytes.Buffer
	if err := Write(ctx, &buf, db, data, "a long backup passphrase", "x"); err != nil {
		t.Fatal(err)
	}
	// Find the last chunk and drop it.
	file := buf.Bytes()
	r := bytes.NewReader(file)
	_, _, _ = ReadHeader(r)
	pos := len(file) - r.Len()
	last := pos
	for pos < len(file) {
		l := int(uint32(file[pos])<<24 | uint32(file[pos+1])<<16 | uint32(file[pos+2])<<8 | uint32(file[pos+3]))
		last = pos
		pos += 4 + l
	}
	if _, err := Restore(bytes.NewReader(file[:last]), filepath.Join(t.TempDir(), "r"), "a long backup passphrase"); err == nil {
		t.Fatal("backup without its final chunk restored")
	}
}
