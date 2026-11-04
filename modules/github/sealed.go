package github

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/nacl/box"
)

// sealSecret encrypts a secret value for GitHub Actions: a libsodium sealed
// box (crypto_box_seal) to the repository's, environment's or
// organization's public key, base64 encoded. Only GitHub can open it.
func sealSecret(publicKeyB64, value string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(k) != 32 {
		return "", errors.New("GitHub returned an unusable public key")
	}
	var pub [32]byte
	copy(pub[:], k)
	sealed, err := box.SealAnonymous(nil, []byte(value), &pub, rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}
