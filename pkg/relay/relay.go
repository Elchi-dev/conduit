// Package relay is Conduit's end-to-end encrypted tunnel between a client
// (phone, browser elsewhere) and a daemon, carried over a hub that only ever
// sees ciphertext.
//
// Keys. Every daemon and client has a long-term X25519 key pair. A client
// learns the daemon's public key from the pairing QR code the daemon shows,
// never from the hub, so a dishonest hub can't substitute its own key. The
// daemon accepts a client's key the first time only together with the
// one-time pairing secret from that QR code; afterwards it recognises the
// client's key.
//
// Handshake. The client sends its static public key, a fresh ephemeral
// public key and a random 32-byte salt. Both sides compute
//
//	ikm = X25519(e_c, S_d) || X25519(s_c, S_d)
//	k   = HKDF-SHA256(ikm, salt, "conduit-relay-v1 " + direction)
//
// giving one AES-256-GCM key per direction. The first DH gives forward
// secrecy against later theft of the client's static key; the second
// authenticates the client to the daemon. The hello also carries the
// client's first encrypted frame (an Intro with its name and, when pairing,
// the one-time secret), so the daemon admits a key only after the client
// proved it holds it, and the hub never sees the pairing secret. The daemon
// proves itself by being able to decrypt and answer.
//
// Frames. Each message is sealed with AES-256-GCM using a 96-bit nonce made of
// four zero bytes and a 64-bit big-endian counter that starts at 0 and
// increases by one per message in that direction. A replayed, reordered or
// altered frame fails to open.
//
// The same construction is implemented in TypeScript in the web app
// (web/src/lib/relay.ts); the test vectors in relay_test.go pin both.
package relay

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Version is the relay protocol version.
const Version = 1

// KeyPair is a long-term X25519 key pair.
type KeyPair struct {
	Private *ecdh.PrivateKey
}

// NewKeyPair generates a key pair.
func NewKeyPair() (KeyPair, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	return KeyPair{Private: k}, err
}

// KeyPairFromBytes restores a key pair from its 32-byte private key.
func KeyPairFromBytes(b []byte) (KeyPair, error) {
	k, err := ecdh.X25519().NewPrivateKey(b)
	return KeyPair{Private: k}, err
}

// Public returns the base64url-encoded public key.
func (k KeyPair) Public() string { return Enc(k.Private.PublicKey().Bytes()) }

// Enc and Dec are the base64url (no padding) encoding used on the wire.
func Enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Dec decodes base64url without padding.
func Dec(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// Fingerprint is a short, comparable form of a public key (first 16 bytes of
// its SHA-256, base64url), shown in the UI and in pairing QR codes.
func Fingerprint(pub string) string {
	b, err := Dec(pub)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return Enc(h[:16])
}

// Hello is the first message from client to daemon. It is the only frame
// the hub can read, and it carries nothing secret.
type Hello struct {
	V         int    `json:"v"`
	Static    string `json:"static"`    // client's long-term public key
	Ephemeral string `json:"ephemeral"` // fresh public key for this session
	Salt      string `json:"salt"`      // 32 random bytes
	// Proof is the client's first encrypted frame (an Intro). Opening it
	// proves the client holds the private half of Static and pinned the
	// right daemon key, and it keeps the pairing secret away from the hub.
	Proof string `json:"proof"`
}

// Intro is sealed inside Hello.Proof.
type Intro struct {
	Name string `json:"name,omitempty"` // device name, e.g. "Pixel 9"
	// PairingSecret is present only on the first connection after scanning
	// the daemon's QR code.
	PairingSecret string `json:"pairingSecret,omitempty"`
}

// Session encrypts and decrypts one tunnel's frames.
type Session struct {
	send, recv       cipher.AEAD
	sendSeq, recvSeq uint64
}

func derive(ikm, salt []byte, info string) (cipher.AEAD, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, salt, []byte(info)), key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newSession(ikm, salt []byte, client bool) (*Session, error) {
	c2d, err := derive(ikm, salt, "conduit-relay-v1 c2d")
	if err != nil {
		return nil, err
	}
	d2c, err := derive(ikm, salt, "conduit-relay-v1 d2c")
	if err != nil {
		return nil, err
	}
	if client {
		return &Session{send: c2d, recv: d2c}, nil
	}
	return &Session{send: d2c, recv: c2d}, nil
}

// ClientHandshake builds the Hello for a daemon whose public key the client
// pinned at pairing, and the client's session.
func ClientHandshake(me KeyPair, daemonPub string, pairingSecret, name string) (Hello, *Session, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Hello{}, nil, err
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return Hello{}, nil, err
	}
	return clientHandshake(me, daemonPub, eph, salt, Intro{Name: name, PairingSecret: pairingSecret})
}

// clientHandshake is ClientHandshake with the randomness supplied, for test
// vectors shared with the TypeScript implementation.
func clientHandshake(me KeyPair, daemonPub string, eph *ecdh.PrivateKey, salt []byte, intro Intro) (Hello, *Session, error) {
	dpub, err := Dec(daemonPub)
	if err != nil {
		return Hello{}, nil, err
	}
	dkey, err := ecdh.X25519().NewPublicKey(dpub)
	if err != nil {
		return Hello{}, nil, err
	}
	dh1, err := eph.ECDH(dkey)
	if err != nil {
		return Hello{}, nil, err
	}
	dh2, err := me.Private.ECDH(dkey)
	if err != nil {
		return Hello{}, nil, err
	}
	s, err := newSession(append(dh1, dh2...), salt, true)
	if err != nil {
		return Hello{}, nil, err
	}
	proof, err := s.SealJSON(intro)
	if err != nil {
		return Hello{}, nil, err
	}
	return Hello{V: Version, Static: me.Public(), Ephemeral: Enc(eph.PublicKey().Bytes()), Salt: Enc(salt), Proof: Enc(proof)}, s, nil
}

// DaemonHandshake derives the daemon's session from a client's Hello and
// opens its proof. An error means the client must not be admitted.
func DaemonHandshake(me KeyPair, h Hello) (*Session, Intro, error) {
	var in Intro
	if h.V != Version {
		return nil, in, fmt.Errorf("unsupported relay version %d", h.V)
	}
	s, err := daemonSession(me, h)
	if err != nil {
		return nil, in, err
	}
	proof, err := Dec(h.Proof)
	if err != nil {
		return nil, in, errors.New("bad proof")
	}
	if err := s.OpenJSON(proof, &in); err != nil {
		return nil, in, errors.New("the client's proof didn't open: wrong pinned daemon key or forged static key")
	}
	return s, in, nil
}

func daemonSession(me KeyPair, h Hello) (*Session, error) {
	pub := func(s string) (*ecdh.PublicKey, error) {
		b, err := Dec(s)
		if err != nil {
			return nil, err
		}
		return ecdh.X25519().NewPublicKey(b)
	}
	eph, err := pub(h.Ephemeral)
	if err != nil {
		return nil, fmt.Errorf("bad ephemeral key: %w", err)
	}
	stat, err := pub(h.Static)
	if err != nil {
		return nil, fmt.Errorf("bad static key: %w", err)
	}
	salt, err := Dec(h.Salt)
	if err != nil || len(salt) != 32 {
		return nil, errors.New("bad salt")
	}
	dh1, err := me.Private.ECDH(eph)
	if err != nil {
		return nil, err
	}
	dh2, err := me.Private.ECDH(stat)
	if err != nil {
		return nil, err
	}
	return newSession(append(dh1, dh2...), salt, false)
}

func nonce(seq uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

// Seal encrypts the next outgoing frame.
func (s *Session) Seal(plaintext []byte) []byte {
	out := s.send.Seal(nil, nonce(s.sendSeq), plaintext, nil)
	s.sendSeq++
	return out
}

// Open decrypts the next incoming frame. Frames must arrive in order.
func (s *Session) Open(frame []byte) ([]byte, error) {
	pt, err := s.recv.Open(nil, nonce(s.recvSeq), frame, nil)
	if err != nil {
		return nil, errors.New("relay frame failed to decrypt (tampered, replayed or out of order)")
	}
	s.recvSeq++
	return pt, nil
}

// Request is an HTTP request carried through the tunnel.
type Request struct {
	ID      uint64            `json:"id"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
}

// Response answers a Request. A streamed answer (the event stream) is a
// series of Responses with the same ID and Stream set, ended by one without.
type Response struct {
	ID      uint64            `json:"id"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
	Stream  bool              `json:"stream,omitempty"`
}

// MethodCancel, sent as a Request's method, stops the stream with that ID.
const MethodCancel = "CANCEL"

// SealJSON encrypts a JSON value.
func (s *Session) SealJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return s.Seal(b), nil
}

// OpenJSON decrypts into v.
func (s *Session) OpenJSON(frame []byte, v any) error {
	b, err := s.Open(frame)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
