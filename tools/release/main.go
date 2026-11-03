// Command release signs daemon binaries into the update manifest that
// conduitd checks (internal/update). Run in the release workflow:
//
//	CONDUIT_RELEASE_PRIVATE_KEY=<base64 seed> go run ./tools/release \
//	  -version 0.1.0 -dir dist \
//	  -base https://github.com/Elchi-dev/conduit/releases/download/v0.1.0 \
//	  -notes "First release" -out dist/conduitd-release.json
//
// It signs every dist/conduitd-<os>-<arch>[.exe] it finds. The same signed
// payloads can be published to a hub with POST /v1/releases.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/elchi-dev/conduit/internal/update"
)

func main() {
	ver := flag.String("version", "", "release version, e.g. 0.1.0")
	dir := flag.String("dir", "dist", "folder with conduitd-<os>-<arch> binaries")
	base := flag.String("base", "", "download URL prefix for those files")
	channel := flag.String("channel", "stable", "release channel")
	notes := flag.String("notes", "", "release notes")
	out := flag.String("out", "conduitd-release.json", "manifest to write")
	sign := flag.String("sign", "", "instead: sign this file (e.g. dist/SHA256SUMS) into <file>.sig")
	flag.Parse()
	if *sign != "" {
		signFile(*sign)
		return
	}
	if *ver == "" || *base == "" {
		fail("-version and -base are required")
	}
	seed, err := base64.StdEncoding.DecodeString(os.Getenv("CONDUIT_RELEASE_PRIVATE_KEY"))
	if err != nil || len(seed) != ed25519.SeedSize {
		fail("set CONDUIT_RELEASE_PRIVATE_KEY to the base64 32-byte release key seed")
	}
	key := ed25519.NewKeyFromSeed(seed)
	files, _ := filepath.Glob(filepath.Join(*dir, "conduitd-*"))
	m := update.Manifest{Version: strings.TrimPrefix(*ver, "v"), Releases: map[string]update.Signed{}}
	for _, f := range files {
		name := filepath.Base(f)
		platform := strings.TrimSuffix(strings.TrimPrefix(name, "conduitd-"), ".exe")
		if strings.Count(platform, "-") != 1 || strings.HasSuffix(name, ".json") {
			continue
		}
		sum, err := fileSum(f)
		if err != nil {
			fail(err.Error())
		}
		p := update.Payload{Component: "daemon", Channel: *channel, Platform: platform, Version: m.Version,
			URL: strings.TrimRight(*base, "/") + "/" + name, SHA256: sum, Notes: *notes}
		raw, _ := json.Marshal(p)
		m.Releases[platform] = update.Signed{Payload: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))}
		fmt.Println("signed", platform, sum[:12])
	}
	if len(m.Releases) == 0 {
		fail("no conduitd-<os>-<arch> files in " + *dir)
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		fail(err.Error())
	}
	fmt.Println("wrote", *out, "public key", base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))
}

// signFile writes <path>.sig: the base64 ed25519 signature of the file's
// bytes. The install scripts check SHA256SUMS.sig with the public release
// key, so a mirror or a swapped download can't change both a binary and
// its checksum.
func signFile(path string) {
	seed, err := base64.StdEncoding.DecodeString(os.Getenv("CONDUIT_RELEASE_PRIVATE_KEY"))
	if err != nil || len(seed) != ed25519.SeedSize {
		fail("set CONDUIT_RELEASE_PRIVATE_KEY to the base64 32-byte release key seed")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		fail(err.Error())
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), b)
	if err := os.WriteFile(path+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		fail(err.Error())
	}
	fmt.Println("signed", path)
}

func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "release:", msg)
	os.Exit(1)
}
