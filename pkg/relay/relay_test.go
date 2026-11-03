package relay

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestHandshakeAndFrames(t *testing.T) {
	daemon, _ := NewKeyPair()
	client, _ := NewKeyPair()
	hello, cs, err := ClientHandshake(client, daemon.Public(), "pair-secret", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	ds, intro, err := DaemonHandshake(daemon, hello)
	if err != nil {
		t.Fatal(err)
	}
	if intro.PairingSecret != "pair-secret" || intro.Name != "Phone" {
		t.Fatalf("intro %+v", intro)
	}
	// The hub-visible hello carries no secret.
	if bytes.Contains([]byte(hello.Proof+hello.Static+hello.Salt), []byte("pair-secret")) {
		t.Fatal("pairing secret visible in the hello")
	}
	for i := 0; i < 3; i++ {
		f := cs.Seal([]byte("ping"))
		got, err := ds.Open(f)
		if err != nil || string(got) != "ping" {
			t.Fatalf("c→d %d: %q %v", i, got, err)
		}
		r := ds.Seal([]byte("pong"))
		got, err = cs.Open(r)
		if err != nil || string(got) != "pong" {
			t.Fatalf("d→c %d: %q %v", i, got, err)
		}
	}
	// Replay of an old frame fails.
	old := cs.Seal([]byte("a"))
	if _, err := ds.Open(old); err != nil {
		t.Fatal(err)
	}
	if _, err := ds.Open(old); err == nil {
		t.Fatal("replayed frame accepted")
	}
}

func TestTamperAndWrongKey(t *testing.T) {
	daemon, _ := NewKeyPair()
	impostor, _ := NewKeyPair()
	client, _ := NewKeyPair()
	// A hub that substitutes its own key can't read: the client pinned the
	// real daemon key.
	hello, cs, _ := ClientHandshake(client, daemon.Public(), "", "")
	if _, _, err := DaemonHandshake(impostor, hello); err == nil {
		t.Fatal("impostor opened the proof")
	}
	// A client claiming someone else's static key can't produce a proof.
	victim, _ := NewKeyPair()
	forged := hello
	forged.Static = victim.Public()
	if _, _, err := DaemonHandshake(daemon, forged); err == nil {
		t.Fatal("forged static key accepted")
	}
	ds, _, err := DaemonHandshake(daemon, hello)
	if err != nil {
		t.Fatal(err)
	}
	f := cs.Seal([]byte("hello"))
	f[len(f)-1] ^= 1
	if _, err := ds.Open(f); err == nil {
		t.Fatal("tampered frame accepted")
	}
}

func TestDirectionsUseDifferentKeys(t *testing.T) {
	daemon, _ := NewKeyPair()
	client, _ := NewKeyPair()
	hello, cs, _ := ClientHandshake(client, daemon.Public(), "", "")
	ds, _, _ := DaemonHandshake(daemon, hello)
	a := cs.Seal([]byte("same"))
	b := ds.Seal([]byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("both directions produced the same ciphertext")
	}
	// A client frame reflected back to the client must not open.
	if _, err := cs.Open(a); err == nil {
		t.Fatal("reflected frame accepted")
	}
}

func TestFingerprintStable(t *testing.T) {
	k, _ := NewKeyPair()
	k2, _ := KeyPairFromBytes(k.Private.Bytes())
	if Fingerprint(k.Public()) != Fingerprint(k2.Public()) || len(Fingerprint(k.Public())) != 22 {
		t.Fatal("fingerprint")
	}
}

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

// vectors pins the wire format; web/src/lib/relay.test.ts checks the
// TypeScript implementation against the same file.
type vectors struct {
	DaemonPrivate string `json:"daemonPrivate"`
	ClientPrivate string `json:"clientPrivate"`
	EphPrivate    string `json:"ephemeralPrivate"`
	Salt          string `json:"salt"`
	Intro         Intro  `json:"intro"`
	Hello         Hello  `json:"hello"`
	Fingerprint   string `json:"daemonFingerprint"`
	// Frames after the proof: client→daemon "ping" (counter 1),
	// daemon→client {"ok":true} (counter 0).
	ClientFrame string `json:"clientFrame"`
	DaemonFrame string `json:"daemonFrame"`
}

func TestVectors(t *testing.T) {
	seed := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	daemon, _ := KeyPairFromBytes(seed(1))
	client, _ := KeyPairFromBytes(seed(2))
	eph, _ := ecdh.X25519().NewPrivateKey(seed(3))
	salt := seed(4)
	intro := Intro{Name: "Pixel", PairingSecret: "s3cret"}
	hello, cs, err := clientHandshake(client, daemon.Public(), eph, salt, intro)
	if err != nil {
		t.Fatal(err)
	}
	ds, got, err := DaemonHandshake(daemon, hello)
	if err != nil || got != intro {
		t.Fatalf("%v %+v", err, got)
	}
	v := vectors{DaemonPrivate: Enc(seed(1)), ClientPrivate: Enc(seed(2)), EphPrivate: Enc(seed(3)), Salt: Enc(salt), Intro: intro, Hello: hello,
		Fingerprint: Fingerprint(daemon.Public()), ClientFrame: Enc(cs.Seal([]byte("ping"))), DaemonFrame: Enc(ds.Seal([]byte(`{"ok":true}`)))}
	b, _ := json.MarshalIndent(v, "", "  ")
	path := filepath.Join("testdata", "vectors.json")
	if *update {
		_ = os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("run go test ./pkg/relay -run Vectors -update:", err)
	}
	if string(bytes.TrimSpace(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")))) != string(b) {
		t.Fatal("wire format changed; if intended, run with -update and update the TypeScript side")
	}
}
