package bitwardensm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// Bitwarden Secrets Manager encrypts names and values on the client: the
// server only ever holds EncStrings. This file is the part of the Bitwarden
// SDK's crypto a machine account needs, done with the standard library:
//
//   - the access token "0.<id>.<client secret>:<key>" carries a 16-byte key;
//   - HMAC-SHA256 keyed with "bitwarden-accesstoken" over that key, then
//     HKDF-Expand (SHA-256, info "sm-access-token") to 64 bytes, gives an
//     AES-256 key and an HMAC-SHA256 key;
//   - those decrypt the login's encrypted_payload, a JSON object whose
//     encryptionKey is the organization's 64-byte key (AES and HMAC halves);
//   - which decrypts every project name, secret key and value: EncStrings of
//     type 2, "2.<iv>|<ciphertext>|<mac>" in base64, AES-256-CBC with PKCS#7
//     padding, the MAC an HMAC-SHA256 over iv || ciphertext.

// symKey is an AES-256-CBC key with its HMAC-SHA256 key.
type symKey struct {
	enc, mac []byte
}

// accessToken is a parsed machine account access token.
type accessToken struct {
	id, secret string
	key        []byte // 16 bytes
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

var errTokenFormat = errors.New("the access token isn't a Secrets Manager machine account access token (0.<id>.<secret>:<key>)")

// parseAccessToken splits "0.<id>.<client secret>:<encryption key>". Errors
// never quote the token.
func parseAccessToken(s string) (accessToken, error) {
	s = strings.TrimSpace(s)
	creds, keyB64, ok := strings.Cut(s, ":")
	if !ok {
		return accessToken{}, errTokenFormat
	}
	parts := strings.Split(creds, ".")
	if len(parts) != 3 || parts[0] != "0" || !uuidRe.MatchString(parts[1]) || parts[2] == "" {
		return accessToken{}, errTokenFormat
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(key) != 16 {
		return accessToken{}, errTokenFormat
	}
	return accessToken{id: parts[1], secret: parts[2], key: key}, nil
}

// shareableKey derives the key that decrypts the login payload.
func shareableKey(secret []byte, name, info string) (symKey, error) {
	h := hmac.New(sha256.New, []byte("bitwarden-"+name))
	h.Write(secret)
	k, err := hkdf.Expand(sha256.New, h.Sum(nil), info, 64)
	if err != nil {
		return symKey{}, err
	}
	return symKey{enc: k[:32], mac: k[32:]}, nil
}

func (t accessToken) payloadKey() (symKey, error) {
	return shareableKey(t.key, "accesstoken", "sm-access-token")
}

var errDecrypt = errors.New("couldn't decrypt (wrong key or damaged data)")

// decrypt opens a type 2 EncString.
func (k symKey) decrypt(s string) ([]byte, error) {
	typ, rest, ok := strings.Cut(s, ".")
	if !ok || typ != "2" {
		return nil, errors.New("unsupported encryption type (only AES-256-CBC with HMAC-SHA256)")
	}
	parts := strings.Split(rest, "|")
	if len(parts) != 3 {
		return nil, errDecrypt
	}
	iv, err1 := base64.StdEncoding.DecodeString(parts[0])
	ct, err2 := base64.StdEncoding.DecodeString(parts[1])
	mac, err3 := base64.StdEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || len(iv) != aes.BlockSize || len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errDecrypt
	}
	h := hmac.New(sha256.New, k.mac)
	h.Write(iv)
	h.Write(ct)
	if !hmac.Equal(h.Sum(nil), mac) {
		return nil, errDecrypt
	}
	block, err := aes.NewCipher(k.enc)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	n := int(out[len(out)-1])
	if n == 0 || n > aes.BlockSize || n > len(out) {
		return nil, errDecrypt
	}
	for _, b := range out[len(out)-n:] {
		if int(b) != n {
			return nil, errDecrypt
		}
	}
	return out[:len(out)-n], nil
}

func (k symKey) decryptString(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	b, err := k.decrypt(s)
	return string(b), err
}

// orgKey opens the login's encrypted_payload and returns the organization key.
func (t accessToken) orgKey(payload string) (symKey, error) {
	pk, err := t.payloadKey()
	if err != nil {
		return symKey{}, err
	}
	raw, err := pk.decrypt(payload)
	if err != nil {
		return symKey{}, errors.New("couldn't decrypt the organization key with the access token's key (is the token complete, including the part after the colon?)")
	}
	var p struct {
		EncryptionKey string `json:"encryptionKey"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return symKey{}, errors.New("the login's payload isn't what Secrets Manager sends")
	}
	key, err := base64.StdEncoding.DecodeString(p.EncryptionKey)
	if err != nil || len(key) != 64 {
		return symKey{}, errors.New("the organization key isn't a 64-byte key")
	}
	return symKey{enc: key[:32], mac: key[32:]}, nil
}

// jwtOrganization reads the organization claim of the bearer token.
func jwtOrganization(tok string) (string, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", errors.New("the login didn't return a JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", errors.New("the login's JWT can't be read")
	}
	var c struct {
		Organization string `json:"organization"`
	}
	if json.Unmarshal(b, &c) != nil || !uuidRe.MatchString(c.Organization) {
		return "", errors.New("the login's JWT names no organization (is this a machine account access token?)")
	}
	return c.Organization, nil
}
