package games

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/elchi-dev/conduit/internal/netguard"
)

// maxCover bounds a cover image's size.
const maxCover = 8 << 20

// ErrNoCover means a game has no cover image.
var ErrNoCover = errors.New("this game has no cover image")

var errLocalCover = errors.New("covers can't come from the local network")

// Cover returns a game's cover image: from the launcher's local cache when
// it has one, else downloaded once from the launcher's image server and
// kept in the data folder. The web app shows covers through the daemon
// (GET /api/v1/games/covers/{id}) so the page never loads other sites.
func (m *Module) Cover(ctx context.Context, id string) ([]byte, string, error) {
	g, err := m.find(id)
	if err != nil {
		return nil, "", err
	}
	if g.coverFile != "" {
		if b, err := readFileLimit(g.coverFile, maxCover); err == nil {
			if ct := imageType(b); ct != "" {
				return b, ct, nil
			}
		}
	}
	if g.Cover == "" {
		return nil, "", ErrNoCover
	}
	cacheDir := ""
	if m.DataDir != "" {
		cacheDir = filepath.Join(m.DataDir, "covers")
		sum := sha256.Sum256([]byte(g.Cover))
		p := filepath.Join(cacheDir, hex.EncodeToString(sum[:16]))
		if b, err := readFileLimit(p, maxCover); err == nil {
			if ct := imageType(b); ct != "" {
				return b, ct, nil
			}
		}
		b, ct, err := m.download(ctx, g.Cover)
		if err != nil {
			return nil, "", err
		}
		if os.MkdirAll(cacheDir, 0o700) == nil {
			_ = os.WriteFile(p, b, 0o600)
		}
		return b, ct, nil
	}
	return m.download(ctx, g.Cover)
}

// coverClient fetches covers from the internet only: no proxy, https only,
// at most 3 redirects (each to https), and every connection checked when
// it's made, so neither a second DNS answer, a rebinding name nor a redirect
// can reach the local network.
var coverClient = netguard.PublicHTTPSClient(20*time.Second, 3)

func (m *Module) download(ctx context.Context, raw string) ([]byte, string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" && !(m.allowPrivateCovers && u.Scheme == "http") || u.Host == "" {
		return nil, "", errors.New("covers are only fetched over https")
	}
	client := coverClient
	if m.allowPrivateCovers {
		client = m.HTTP // tests, with a local server
	} else if ip, err := netip.ParseAddr(u.Hostname()); err == nil && netguard.ReservedAddr(ip) {
		return nil, "", errLocalCover
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	res, err := client.Do(req)
	if err != nil {
		if errors.Is(err, netguard.ErrReserved) {
			return nil, "", errLocalCover
		}
		return nil, "", fmt.Errorf("couldn't download the cover from %s", u.Hostname())
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, "", fmt.Errorf("%s answered %s for the cover", u.Hostname(), res.Status)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxCover+1))
	if err != nil {
		return nil, "", err
	}
	if len(b) > maxCover {
		return nil, "", errors.New("the cover image is too large")
	}
	ct := imageType(b)
	if ct == "" {
		return nil, "", errors.New("the cover isn't an image")
	}
	return b, ct, nil
}

// imageType sniffs the image formats covers come in. SVG is refused: it can
// carry scripts.
func imageType(b []byte) string {
	ct := http.DetectContentType(b)
	switch ct {
	case "image/jpeg", "image/png", "image/webp", "image/gif", "image/avif":
		return ct
	}
	if len(b) > 12 && string(b[4:12]) == "ftypavif" {
		return "image/avif"
	}
	return ""
}

func readFileLimit(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, n+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > n {
		return nil, errors.New("file too large")
	}
	return b, nil
}
