// Package komga works with a Komga comics and manga server through its REST
// API, with an API key or a user name and password: libraries, series,
// recently added books, reading progress (in progress and On Deck) and
// library scans.
package komga

import (
	"context"
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

// Config is one Komga server.
type Config struct {
	URL                string `json:"url"`      // e.g. https://komga.example.com
	APIKey             string `json:"apiKey"`   // secret:// API key, or
	Username           string `json:"username"` // a user name (email) with
	Password           string `json:"password"` // a secret:// password
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	origin string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Komga module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	idRe   = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := `"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}`
	lib := `"library":{"type":"string","description":"Library id (see libraries)"}`
	return sdk.Manifest{
		ID: "komga", Name: "Komga", Version: "0.1.0", Category: "Media", Icon: "book",
		Description: "Your Komga comics and manga: libraries, series, what's new, what you're reading and what's next, and library scans.",
		Presets:     []string{"homelab", "gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"Komga's address, e.g. https://komga.example.com"},
			"apiKey":{"type":"string","x-secret":true,"description":"An API key (Account settings → API keys, Komga 1.20 or later). Use this or a user name and password"},
			"username":{"type":"string","description":"Your Komga login (an email address), if you don't use an API key"},
			"password":{"type":"string","x-secret":true,"description":"Its password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "libraries", Title: "Libraries", Description: "Your libraries with their folders.", Risk: sdk.RiskRead},
			{Name: "series", Title: "Series", Description: "Series by title, in one library or all, optionally matching a search: book counts, how many you've read and the series status.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + lib + `,"search":{"type":"string"},` + limit + `}}`)},
			{Name: "recent", Title: "Recently added", Description: "The newest books, everywhere or in one library.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + lib + `,` + limit + `}}`)},
			{Name: "on_deck", Title: "Reading progress", Description: "Books you're in the middle of (page and progress) and On Deck: the next book in series you're reading.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + limit + `}}`)},
			{Name: "scan_library", Title: "Scan a library", Description: "Asks Komga to look for new, changed and removed files in a library now (needs an admin account). It runs in the background; deep re-reads every file.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["library"],"properties":{` + lib + `,"deep":{"type":"boolean","default":false}}}`)},
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
		return errors.New("the address is like https://komga.example.com")
	}
	user := strings.TrimSpace(c.Username)
	switch {
	case c.APIKey != "" && (user != "" || c.Password != ""):
		return errors.New("use an API key or a user name and password, not both")
	case c.APIKey != "":
		if !strings.HasPrefix(c.APIKey, "secret://") {
			return errors.New("store the API key in the vault and enter its secret:// reference")
		}
	case user != "" || c.Password != "":
		if user == "" || strings.ContainsAny(user, ":\r\n") || len(user) > 320 {
			return errors.New("enter your Komga login")
		}
		if !strings.HasPrefix(c.Password, "secret://") {
			return errors.New("store the password in the vault and enter its secret:// reference")
		}
	default:
		return errors.New("enter an API key, or a user name and password")
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
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	key, pass := c.APIKey, c.Password
	api := rest.New(origin+"/api", func(ctx context.Context, r *http.Request) error {
		if key != "" {
			t, err := h.Secret(ctx, key)
			if err != nil {
				return err
			}
			r.Header.Set("X-API-Key", strings.TrimSpace(t))
			return nil
		}
		pw, err := h.Secret(ctx, pass)
		if err != nil {
			return err
		}
		r.SetBasicAuth(user, pw)
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	// Komga answers a browser-looking 401 with a login prompt; this keeps
	// it to a plain status.
	api.Header.Set("X-Requested-With", "XMLHttpRequest")
	m.set.Put(id, &conn{api: api, origin: origin})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func explain(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Komga refused the API key or the user name and password")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Komga refused: this needs an admin account")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return explain(err)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		Email string `json:"email"`
	}
	if err := c.do(ctx, http.MethodGet, "/v2/users/me", nil, nil, &me); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Komga API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + me.Email}
}

type library struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Root        string `json:"root"`
	Unavailable bool   `json:"unavailable"`
}

type series struct {
	ID         string `json:"id"`
	LibraryID  string `json:"libraryId"`
	Name       string `json:"name"`
	Books      int    `json:"booksCount"`
	Read       int    `json:"booksReadCount"`
	Unread     int    `json:"booksUnreadCount"`
	InProgress int    `json:"booksInProgressCount"`
	Metadata   struct {
		Title  string `json:"title"`
		Status string `json:"status"`
	} `json:"metadata"`
}

type book struct {
	ID          string `json:"id"`
	SeriesID    string `json:"seriesId"`
	SeriesTitle string `json:"seriesTitle"`
	LibraryID   string `json:"libraryId"`
	Name        string `json:"name"`
	Created     string `json:"created"`
	Media       struct {
		Pages int `json:"pagesCount"`
	} `json:"media"`
	Metadata struct {
		Title  string `json:"title"`
		Number string `json:"number"`
	} `json:"metadata"`
	Progress *struct {
		Page      int    `json:"page"`
		Completed bool   `json:"completed"`
		ReadDate  string `json:"readDate"`
	} `json:"readProgress"`
}

type page[T any] struct {
	Content []T `json:"content"`
	Total   int `json:"totalElements"`
}

func (c *conn) book(b book) map[string]any {
	title := b.Metadata.Title
	if title == "" {
		title = b.Name
	}
	out := map[string]any{"id": b.ID, "title": title, "series": b.SeriesTitle, "seriesId": b.SeriesID, "number": b.Metadata.Number,
		"pages": b.Media.Pages, "added": b.Created, "open": c.origin + "/book/" + url.PathEscape(b.ID)}
	if p := b.Progress; p != nil {
		out["page"], out["completed"], out["lastRead"] = p.Page, p.Completed, p.ReadDate
		if b.Media.Pages > 0 {
			out["percent"] = p.Page * 100 / b.Media.Pages
		}
	}
	return out
}

func (c *conn) books(ctx context.Context, path string, q url.Values) ([]map[string]any, int, error) {
	var res page[book]
	if err := c.do(ctx, http.MethodGet, path, q, nil, &res); err != nil {
		return nil, 0, err
	}
	out := []map[string]any{}
	for _, b := range res.Content {
		out = append(out, c.book(b))
	}
	return out, res.Total, nil
}

type input struct {
	Library string `json:"library"`
	Search  string `json:"search"`
	Limit   int    `json:"limit"`
	Deep    bool   `json:"deep"`
}

func limitOf(n int) string {
	if n <= 0 || n > 100 {
		n = 20
	}
	return strconv.Itoa(n)
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
	p.Library = strings.TrimSpace(p.Library)
	if p.Library != "" && !idRe.MatchString(p.Library) {
		return sdk.Result{}, errors.New("the library is a library id (see libraries)")
	}
	switch call.Action {
	case "libraries":
		var libs []library
		if err := c.do(ctx, http.MethodGet, "/v1/libraries", nil, nil, &libs); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, l := range libs {
			r := map[string]any{"id": l.ID, "name": l.Name, "root": l.Root}
			if l.Unavailable {
				r["unavailable"] = true
			}
			out = append(out, r)
		}
		return sdk.JSON(out)

	case "series":
		q := url.Values{"page": {"0"}, "size": {limitOf(p.Limit)}, "sort": {"metadata.titleSort,asc"}}
		if p.Library != "" {
			q.Set("library_id", p.Library)
		}
		if s := strings.TrimSpace(p.Search); s != "" {
			if len(s) > 200 {
				return sdk.Result{}, errors.New("the search is too long")
			}
			q.Set("search", s)
		}
		var res page[series]
		if err := c.do(ctx, http.MethodGet, "/v1/series", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range res.Content {
			title := s.Metadata.Title
			if title == "" {
				title = s.Name
			}
			out = append(out, map[string]any{"id": s.ID, "title": title, "libraryId": s.LibraryID, "books": s.Books, "read": s.Read,
				"unread": s.Unread, "inProgress": s.InProgress, "status": strings.ToLower(s.Metadata.Status), "open": c.origin + "/series/" + url.PathEscape(s.ID)})
		}
		return sdk.JSON(map[string]any{"series": out, "total": res.Total})

	case "recent":
		q := url.Values{"page": {"0"}, "size": {limitOf(p.Limit)}}
		if p.Library != "" {
			q.Set("library_id", p.Library)
		}
		out, _, err := c.books(ctx, "/v1/books/latest", q)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"books": out})

	case "on_deck":
		q := url.Values{"page": {"0"}, "size": {limitOf(p.Limit)}}
		reading, _, err := c.books(ctx, "/v1/books", url.Values{"page": {"0"}, "size": {limitOf(p.Limit)}, "read_status": {"IN_PROGRESS"}, "sort": {"readProgress.readDate,desc"}})
		if err != nil {
			return sdk.Result{}, err
		}
		next, _, err := c.books(ctx, "/v1/books/ondeck", q)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"inProgress": reading, "onDeck": next})

	case "scan_library":
		if p.Library == "" {
			return sdk.Result{}, errors.New("give the library to scan (see libraries)")
		}
		var l library
		if err := c.do(ctx, http.MethodGet, "/v1/libraries/"+p.Library, nil, nil, &l); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no library %s", p.Library)
			}
			return sdk.Result{}, err
		}
		kind := "Scan"
		if p.Deep {
			kind = "Deep scan"
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s library %q", kind, l.Name), Changes: []sdk.Change{{Target: fmt.Sprintf("library %q (%s)", l.Name, l.Root), Op: "scan"}}}}, nil
		}
		if err := c.do(ctx, http.MethodPost, "/v1/libraries/"+l.ID+"/scan", url.Values{"deep": {strconv.FormatBool(p.Deep)}}, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"scanning": l.Name, "deep": p.Deep})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
