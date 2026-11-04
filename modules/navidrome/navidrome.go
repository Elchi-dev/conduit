// Package navidrome works with a Navidrome music server (or any server
// with the Subsonic API: Airsonic, Gonic, ...) through the Subsonic API
// with token authentication: what's playing now, recently added or played
// albums, search, playlists, and the library scan.
package navidrome

import (
	"context"
	"crypto/md5" //nolint:gosec // the Subsonic API's token is md5(password + salt)
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one server.
type Config struct {
	URL                string `json:"url"` // e.g. https://music.example.com
	Username           string `json:"username"`
	Password           string `json:"password"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api  *rest.Client
	user string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Navidrome module.
func New() *Module { return &Module{} }

const apiVersion = "1.16.1"

var errNotFound = errors.New("not found")

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	idRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

var albumTypes = map[string]bool{"newest": true, "recent": true, "frequent": true, "highest": true, "starred": true, "random": true, "alphabeticalByName": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "navidrome", Name: "Navidrome", Version: "0.1.0", Category: "Media", Icon: "music",
		Description: "Navidrome or any Subsonic server: now playing, recent albums, search, playlists, library scans.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","username","password"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://music.example.com"},
			"username":{"type":"string"},
			"password":{"type":"string","x-secret":true,"description":"That user's password (sent only as a salted token)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "now_playing", Title: "Now playing", Description: "What each user is playing, on which player, and how long ago it started.", Risk: sdk.RiskRead},
			{Name: "albums", Title: "Albums", Description: "Albums by list: newest (recently added, the default), recent (recently played), frequent, highest, starred, random or alphabeticalByName.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"type":{"type":"string","enum":["newest","recent","frequent","highest","starred","random","alphabeticalByName"],"default":"newest"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
			{Name: "search", Title: "Search", Description: "Artists, albums and songs matching words.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":50,"default":10,"description":"Per kind"}}}`)},
			{Name: "playlists", Title: "Playlists", Description: "The playlists the user can see, with owner, song count and length.", Risk: sdk.RiskRead},
			{Name: "playlist", Title: "Playlist", Description: "One playlist's songs.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"Playlist id (see playlists)"}}}`)},
			{Name: "scan_status", Title: "Scan status", Description: "Whether a library scan is running, how many files it has counted and when the last one ran.", Risk: sdk.RiskRead},
			{Name: "start_scan", Title: "Scan the library", Description: "Starts a library scan (an admin user is needed). fullScan rescans every file, not only changed ones (Navidrome).", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{"fullScan":{"type":"boolean","default":false}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://music.example.com")
	}
	user := strings.TrimSpace(c.Username)
	if user == "" || len(user) > 256 || strings.ContainsAny(user, "\x00\r\n") {
		return errors.New("enter the username")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h) // through the instance's network, if any
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	ref := c.Password
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/rest")
	api := rest.New(base+"/rest", func(ctx context.Context, r *http.Request) error {
		pw, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		salt := make([]byte, 8)
		if _, err := rand.Read(salt); err != nil {
			return err
		}
		s := hex.EncodeToString(salt)
		sum := md5.Sum([]byte(pw + s)) //nolint:gosec // required by the API
		q := r.URL.Query()
		q.Set("u", user)
		q.Set("t", hex.EncodeToString(sum[:]))
		q.Set("s", s)
		q.Set("v", apiVersion)
		q.Set("c", "conduit")
		q.Set("f", "json")
		r.URL.RawQuery = q.Encode()
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, user: user})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// envelope is the shape of every Subsonic answer.
type envelope struct {
	Status        string `json:"status"`
	Version       string `json:"version"`
	Type          string `json:"type"`
	ServerVersion string `json:"serverVersion"`
	Error         *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// call runs one API method and decodes the answer into out (which sees
// the inside of "subsonic-response").
func (c *conn) call(ctx context.Context, method string, q url.Values, out any) (envelope, error) {
	var raw struct {
		R json.RawMessage `json:"subsonic-response"`
	}
	var env envelope
	_, err := c.api.Do(ctx, http.MethodGet, "/"+method+".view", q, nil, &raw)
	if err != nil {
		// The request URL carries the token and salt: never show it.
		var ue *url.Error
		if errors.As(err, &ue) {
			return env, fmt.Errorf("can't reach the server: %w", ue.Err)
		}
		switch {
		case rest.IsStatus(err, http.StatusUnauthorized):
			return env, errors.New("the server refused the username or password")
		case rest.IsStatus(err, http.StatusNotFound):
			return env, errors.New("no Subsonic API at this address")
		}
		return env, err
	}
	if len(raw.R) == 0 {
		return env, errors.New("no Subsonic API at this address")
	}
	if err := json.Unmarshal(raw.R, &env); err != nil {
		return env, errors.New("unexpected answer from the server")
	}
	if env.Status != "ok" {
		if env.Error == nil {
			return env, errors.New("the server answered with an error")
		}
		switch env.Error.Code {
		case 40:
			return env, errors.New("the server refused the username or password")
		case 41:
			return env, errors.New("this user can't sign in with a token (an LDAP user?)")
		case 50:
			return env, errors.New("the user isn't allowed to do this (an admin is needed)")
		case 70:
			return env, errNotFound
		}
		return env, fmt.Errorf("the server refused: %s", env.Error.Message)
	}
	if out != nil {
		if err := json.Unmarshal(raw.R, out); err != nil {
			return env, errors.New("unexpected answer from the server")
		}
	}
	return env, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	env, err := c.call(ctx, "ping", nil, nil)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + c.user
	if env.Type != "" {
		name := env.Type
		if name == "navidrome" {
			name = "Navidrome"
		}
		msg += " · " + strings.TrimSpace(name+" "+env.ServerVersion)
	}
	return sdk.Health{Status: "ok", Message: msg + " (Subsonic API " + env.Version + ")"}
}

type song struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Artist     string `json:"artist"`
	Album      string `json:"album"`
	Year       int    `json:"year"`
	Track      int    `json:"track"`
	Duration   int    `json:"duration"`
	Genre      string `json:"genre"`
	PlayCount  int    `json:"playCount"`
	Username   string `json:"username"`
	PlayerName string `json:"playerName"`
	MinutesAgo int    `json:"minutesAgo"`
}

func (s song) out() map[string]any {
	e := map[string]any{"id": s.ID, "title": s.Title, "artist": s.Artist, "album": s.Album}
	if s.Year > 0 {
		e["year"] = s.Year
	}
	if s.Duration > 0 {
		e["seconds"] = s.Duration
	}
	if s.Genre != "" {
		e["genre"] = s.Genre
	}
	return e
}

type album struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Artist    string `json:"artist"`
	Year      int    `json:"year"`
	Genre     string `json:"genre"`
	SongCount int    `json:"songCount"`
	Duration  int    `json:"duration"`
	PlayCount int    `json:"playCount"`
	Created   string `json:"created"`
	Played    string `json:"played"`
	Starred   string `json:"starred"`
}

func (a album) out() map[string]any {
	e := map[string]any{"id": a.ID, "name": a.Name, "artist": a.Artist, "songs": a.SongCount, "seconds": a.Duration}
	if a.Year > 0 {
		e["year"] = a.Year
	}
	if a.Genre != "" {
		e["genre"] = a.Genre
	}
	if a.PlayCount > 0 {
		e["plays"] = a.PlayCount
	}
	if a.Created != "" {
		e["added"] = a.Created
	}
	if a.Played != "" {
		e["lastPlayed"] = a.Played
	}
	if a.Starred != "" {
		e["starred"] = a.Starred
	}
	return e
}

type playlist struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Owner     string `json:"owner"`
	Public    bool   `json:"public"`
	SongCount int    `json:"songCount"`
	Duration  int    `json:"duration"`
	Changed   string `json:"changed"`
	Comment   string `json:"comment"`
	Entry     []song `json:"entry"`
}

func (p playlist) out() map[string]any {
	e := map[string]any{"id": p.ID, "name": p.Name, "owner": p.Owner, "public": p.Public, "songs": p.SongCount, "seconds": p.Duration, "changed": p.Changed}
	if p.Comment != "" {
		e["comment"] = p.Comment
	}
	return e
}

type scanStatus struct {
	ScanStatus struct {
		Scanning    bool   `json:"scanning"`
		Count       int    `json:"count"`
		FolderCount int    `json:"folderCount"`
		LastScan    string `json:"lastScan"`
	} `json:"scanStatus"`
}

func (s scanStatus) out() map[string]any {
	e := map[string]any{"scanning": s.ScanStatus.Scanning, "count": s.ScanStatus.Count}
	if s.ScanStatus.FolderCount > 0 {
		e["folders"] = s.ScanStatus.FolderCount
	}
	if s.ScanStatus.LastScan != "" {
		e["lastScan"] = s.ScanStatus.LastScan
	}
	return e
}

type input struct {
	Type     string `json:"type"`
	Limit    int    `json:"limit"`
	Query    string `json:"query"`
	ID       string `json:"id"`
	FullScan bool   `json:"fullScan"`
}

func limit(n, def, max int) (int, error) {
	if n == 0 {
		return def, nil
	}
	if n < 1 || n > max {
		return 0, fmt.Errorf("limit is between 1 and %d", max)
	}
	return n, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p input
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "now_playing":
		var r struct {
			NowPlaying struct {
				Entry []song `json:"entry"`
			} `json:"nowPlaying"`
		}
		if _, err := c.call(ctx, "getNowPlaying", nil, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range r.NowPlaying.Entry {
			e := s.out()
			e["user"], e["player"], e["minutesAgo"] = s.Username, s.PlayerName, s.MinutesAgo
			out = append(out, e)
		}
		return sdk.JSON(out)

	case "albums":
		t := p.Type
		if t == "" {
			t = "newest"
		}
		if !albumTypes[t] {
			return sdk.Result{}, errors.New("type is newest, recent, frequent, highest, starred, random or alphabeticalByName")
		}
		n, err := limit(p.Limit, 20, 100)
		if err != nil {
			return sdk.Result{}, err
		}
		var r struct {
			AlbumList2 struct {
				Album []album `json:"album"`
			} `json:"albumList2"`
		}
		if _, err := c.call(ctx, "getAlbumList2", url.Values{"type": {t}, "size": {strconv.Itoa(n)}}, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, a := range r.AlbumList2.Album {
			out = append(out, a.out())
		}
		return sdk.JSON(map[string]any{"type": t, "albums": out})

	case "search":
		q := strings.TrimSpace(p.Query)
		if q == "" || len(q) > 200 || strings.ContainsRune(q, 0) {
			return sdk.Result{}, errors.New("enter what to search for (up to 200 characters)")
		}
		n, err := limit(p.Limit, 10, 50)
		if err != nil {
			return sdk.Result{}, err
		}
		ns := strconv.Itoa(n)
		var r struct {
			SearchResult3 struct {
				Artist []struct {
					ID         string `json:"id"`
					Name       string `json:"name"`
					AlbumCount int    `json:"albumCount"`
				} `json:"artist"`
				Album []album `json:"album"`
				Song  []song  `json:"song"`
			} `json:"searchResult3"`
		}
		if _, err := c.call(ctx, "search3", url.Values{"query": {q}, "artistCount": {ns}, "albumCount": {ns}, "songCount": {ns}}, &r); err != nil {
			return sdk.Result{}, err
		}
		artists, albums, songs := []map[string]any{}, []map[string]any{}, []map[string]any{}
		for _, a := range r.SearchResult3.Artist {
			artists = append(artists, map[string]any{"id": a.ID, "name": a.Name, "albums": a.AlbumCount})
		}
		for _, a := range r.SearchResult3.Album {
			albums = append(albums, a.out())
		}
		for _, s := range r.SearchResult3.Song {
			songs = append(songs, s.out())
		}
		return sdk.JSON(map[string]any{"artists": artists, "albums": albums, "songs": songs})

	case "playlists":
		var r struct {
			Playlists struct {
				Playlist []playlist `json:"playlist"`
			} `json:"playlists"`
		}
		if _, err := c.call(ctx, "getPlaylists", nil, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, pl := range r.Playlists.Playlist {
			out = append(out, pl.out())
		}
		return sdk.JSON(out)

	case "playlist":
		id := strings.TrimSpace(p.ID)
		if !idRe.MatchString(id) {
			return sdk.Result{}, errors.New("enter the playlist's id (see playlists)")
		}
		var r struct {
			Playlist playlist `json:"playlist"`
		}
		if _, err := c.call(ctx, "getPlaylist", url.Values{"id": {id}}, &r); err != nil {
			if errors.Is(err, errNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no playlist %s", id)
			}
			return sdk.Result{}, err
		}
		e := r.Playlist.out()
		songs := []map[string]any{}
		for _, s := range r.Playlist.Entry {
			songs = append(songs, s.out())
		}
		e["entries"] = songs
		return sdk.JSON(e)

	case "scan_status":
		var r scanStatus
		if _, err := c.call(ctx, "getScanStatus", nil, &r); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(r.out())

	case "start_scan":
		var cur scanStatus
		if _, err := c.call(ctx, "getScanStatus", nil, &cur); err != nil {
			return sdk.Result{}, err
		}
		kind := "Scan the library for changes"
		if p.FullScan {
			kind = "Rescan every file in the library"
		}
		if call.DryRun {
			sum := kind
			if cur.ScanStatus.Scanning {
				sum += " (a scan is already running)"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "music library", Op: "scan", Before: mustJSON(cur.out())}}}}, nil
		}
		if cur.ScanStatus.Scanning {
			return sdk.Result{}, errors.New("a scan is already running")
		}
		q := url.Values{}
		if p.FullScan {
			q.Set("fullScan", "true")
		}
		var r scanStatus
		if _, err := c.call(ctx, "startScan", q, &r); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(r.out())
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
