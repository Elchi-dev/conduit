package gcp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"time"
)

// serviceAccount is the part of a service-account JSON key that's used.
// Errors about it never quote it: the key is a credential.
type serviceAccount struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
}

func parseKey(raw string) (serviceAccount, *rsa.PrivateKey, error) {
	var sa serviceAccount
	if json.Unmarshal([]byte(strings.TrimSpace(raw)), &sa) != nil {
		return sa, nil, errors.New("the stored service-account key isn't JSON (store the whole downloaded key file)")
	}
	if sa.Type != "service_account" || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return sa, nil, errors.New("the stored key isn't a service-account key (type service_account with client_email and private_key)")
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return sa, nil, errors.New("the service-account key's private_key isn't PEM")
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return sa, nil, errors.New("the service-account key isn't an RSA key")
		}
		key = rk
	} else if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else {
		return sa, nil, errors.New("the service-account key's private_key can't be read")
	}
	return sa, key, nil
}

var b64 = base64.RawURLEncoding

// signJWT makes the RS256 assertion Google's token endpoint exchanges for
// an access token (RFC 7523).
func signJWT(sa serviceAccount, key *rsa.PrivateKey, aud, scope string, now time.Time) (string, error) {
	hdr := map[string]string{"alg": "RS256", "typ": "JWT"}
	if sa.PrivateKeyID != "" {
		hdr["kid"] = sa.PrivateKeyID
	}
	h, _ := json.Marshal(hdr)
	c, _ := json.Marshal(map[string]any{"iss": sa.ClientEmail, "scope": scope, "aud": aud, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return in + "." + b64.EncodeToString(sig), nil
}
