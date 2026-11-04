package oauth

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
)

// ServiceAccount is the part of a Google service-account JSON key that's
// used. Errors about it never quote it: the key is a credential.
type ServiceAccount struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
}

// ParseServiceAccount reads a service-account JSON key and its RSA key.
func ParseServiceAccount(raw string) (ServiceAccount, *rsa.PrivateKey, error) {
	var sa ServiceAccount
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
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return sa, nil, errors.New("the service-account key isn't an RSA key")
		}
		return sa, rk, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return sa, k, nil
	}
	return sa, nil, errors.New("the service-account key's private_key can't be read")
}

var b64 = base64.RawURLEncoding

// SignRS256 makes a compact RS256 JWT with these claims (RFC 7515, 7523).
func SignRS256(key *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	hdr := map[string]string{"alg": "RS256", "typ": "JWT"}
	if kid != "" {
		hdr["kid"] = kid
	}
	h, _ := json.Marshal(hdr)
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return in + "." + b64.EncodeToString(sig), nil
}
