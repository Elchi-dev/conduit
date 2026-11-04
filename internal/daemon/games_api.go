package daemon

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/elchi-dev/conduit/modules/games"
)

// coverSource is implemented by the games module.
type coverSource interface {
	Cover(ctx context.Context, id string) ([]byte, string, error)
}

func (s *Server) gamesRoutes() []route {
	return []route{{"GET /api/v1/games/covers/{id}", s.need("modules:games:read", s.gameCover)}}
}

// gameCover serves a game's cover image, so the web app can show covers
// from launcher caches and image servers without loading other sites.
func (s *Server) gameCover(w http.ResponseWriter, r *http.Request) {
	m, ok := s.Engine.Module("games")
	src, ok2 := m.(coverSource)
	if !ok || !ok2 {
		writeErr(w, http.StatusNotFound, "the games module isn't available")
		return
	}
	b, ct, err := src.Cover(r.Context(), r.PathValue("id"))
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, games.ErrNoCover) || errors.Is(err, games.ErrUnknownGame) {
			code = http.StatusNotFound
		}
		writeErr(w, code, err.Error())
		return
	}
	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("Content-Length", strconv.Itoa(len(b)))
	h.Set("Cache-Control", "private, max-age=86400")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	_, _ = w.Write(b)
}
