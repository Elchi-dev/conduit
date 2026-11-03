package daemon

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Home tiles: each person pins read actions (CPU load, unread mail, players
// online, next meeting…) to their home board. The board only stores which
// action to run; the app runs it through the normal API, so the policy and
// audit apply as usual and only read actions can be pinned.

// Tile is one pinned read action.
type Tile struct {
	ID       string          `json:"id"`
	Instance string          `json:"instance"`
	Action   string          `json:"action"`
	Input    json.RawMessage `json:"input,omitempty"`
	Label    string          `json:"label"`
	// Field picks what to show from the result: a dot path such as
	// "unread" or "cpu.percent"; empty shows a summary.
	Field string `json:"field,omitempty"`
	// Refresh is seconds between updates (15 to 3600).
	Refresh int `json:"refresh"`
}

const maxTiles = 24

func (s *Server) tileRoutes() []route {
	return []route{
		{"GET /api/v1/me/tiles", s.need("", s.getTiles)},
		{"PUT /api/v1/me/tiles", s.need("", s.putTiles)},
	}
}

func tilesKey(userID string) string { return "home.tiles." + userID }

func (s *Server) getTiles(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	tiles := []Tile{}
	var raw string
	if s.DB.QueryRowContext(r.Context(), `SELECT value FROM settings WHERE key = ?`, tilesKey(p.User.ID)).Scan(&raw) == nil {
		_ = json.Unmarshal([]byte(raw), &tiles)
	}
	writeJSON(w, http.StatusOK, tiles)
}

func (s *Server) putTiles(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	var tiles []Tile
	if err := readJSON(r, &tiles); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(tiles) > maxTiles {
		writeErr(w, http.StatusBadRequest, "a board holds at most 24 tiles")
		return
	}
	for i, t := range tiles {
		in, ok := s.Engine.Instance(t.Instance)
		if !ok {
			writeErr(w, http.StatusBadRequest, "no such instance "+t.Instance)
			return
		}
		m, ok := s.Engine.Module(in.Module)
		if !ok {
			writeErr(w, http.StatusBadRequest, "no such module")
			return
		}
		var spec *sdk.ActionSpec
		for _, a := range m.Manifest().Actions {
			if a.Name == t.Action {
				a := a
				spec = &a
			}
		}
		if spec == nil || spec.Risk != sdk.RiskRead || spec.Sensitive {
			writeErr(w, http.StatusBadRequest, t.Action+" can't be a tile: only actions that read, and don't return secrets, can")
			return
		}
		if t.Refresh < 15 {
			tiles[i].Refresh = 60
		}
		if t.Refresh > 3600 {
			tiles[i].Refresh = 3600
		}
		if strings.TrimSpace(t.Label) == "" {
			tiles[i].Label = in.Name
		}
		if len(t.Label) > 60 || len(t.Field) > 100 || len(t.Input) > 4096 {
			writeErr(w, http.StatusBadRequest, "label, field or input too long")
			return
		}
		if t.ID == "" {
			tiles[i].ID = t.Instance + ":" + t.Action + ":" + randomSuffix()
		}
	}
	b, _ := json.Marshal(tiles)
	if _, err := s.DB.ExecContext(r.Context(), `INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, tilesKey(p.User.ID), string(b)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, tiles)
}

func randomSuffix() string { return randomToken()[:8] }
