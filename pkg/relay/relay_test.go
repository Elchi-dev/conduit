package relay

import (
	"bytes"
	"testing"
)

func TestHandshakeAndFrames(t *testing.T) {
	daemon, _ := NewKeyPair()
	client, _ := NewKeyPair()
	hello, cs, err := ClientHandshake(client, daemon.Public(), "pair-secret", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	ds, err := DaemonHandshake(daemon, hello)
	if err != nil {
		t.Fatal(err)
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
	is, _ := DaemonHandshake(impostor, hello)
	if _, err := is.Open(cs.Seal([]byte("secret"))); err == nil {
		t.Fatal("impostor decrypted the frame")
	}
	ds, _ := DaemonHandshake(daemon, hello)
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
	ds, _ := DaemonHandshake(daemon, hello)
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
