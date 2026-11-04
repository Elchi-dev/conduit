// Package kavita works with a Kavita reading server (manga, comics and
// books) through its API: an API key is exchanged for a short-lived token,
// then libraries, series (by library or by search), recently added series
// and library scans.
package kavita

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
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Kavita server.
type Config struct {
	URL                string `json:"url"`    // e.g. https://kavita.example.com
	APIKey             string `json:"apiKey"` // secret:// API key
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client // Bearer token
	login  *rest.Client // the API key, for the token only
	origin string

	mu      sync.Mutex
	token   string
	user    string
	fetched time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Kavita module.
func New() *Module { return &Module{} }

// tokenAge is how long a token is reused; Kavita's last much longer.
const tokenAge = 30 * time.Minute

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := `"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}`
	lib := `"library":{"type":"integer","minimum":1,"description":"Library id (see libraries)"}`
	return sdk.Manifest{
		ID: "kavita", Name: "Kavita", Version: "0.1.0", Category: "Media", Icon: "book",
		Description: "Your Kavita manga, comics and books: libraries, series, search, what's new, and library scans.",
		Presets:     []string{"homelab", "gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"Kavita's address, e.g. https://kavita.example.com"},
			"apiKey":{"type":"string","x-secret":true,"description":"Your API key (User settings, 3rd Party Clients or Account); it acts as your user"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "libraries", Title: "Libraries", Description: "Your libraries: type (manga, comic, book, image, light novel), folders and when each was last scanned.", Risk: sdk.RiskRead},
			{Name: "series", Title: "Series", Description: "Series by name, in one library or all, or the ones matching a search: format, pages and how many you've read.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + lib + `,"search":{"type":"string","maxLength":200},` + limit + `}}`)},
			{Name: "recent", Title: "Recently added", Description: "The series that got new chapters or volumes most recently, everywhere or in one library.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + lib + `,` + limit + `}}`)},
			{Name: "scan_library", Title: "Scan a library", Description: "Asks Kavita to look for new and changed files in a library now (needs an admin). It runs in the background. With force, every file is re-read, not only changed folders.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["library"],"properties":{` + lib + `,"force":{"type":"boolean","default":false}}}`)},
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
		return errors.New("the address is like https://kavita.example.com")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	client = rest.SameHostOnly(client)
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	ref := c.APIKey
	cn := &conn{origin: origin}
	cn.login = rest.New(origin+"/api", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		q := r.URL.Query()
		q.Set("apiKey", strings.TrimSpace(k))
		r.URL.RawQuery = q.Encode()
		return nil
	})
	cn.login.HTTP = client
	cn.api = rest.New(origin+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := cn.bearer(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	cn.api.HTTP = client
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errKey = errors.New("Kavita refused the API key")

// bearer returns a token, exchanging the API key for one when there's none
// or it's old.
func (c *conn) bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Since(c.fetched) < tokenAge {
		return c.token, nil
	}
	var u struct {
		Username string `json:"username"`
		Token    string `json:"token"`
		// The refresh token and the API key it echoes aren't decoded.
	}
	_, err := c.login.Do(ctx, http.MethodPost, "/Plugin/authenticate", url.Values{"pluginName": {"Conduit"}}, nil, &u)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden), rest.IsStatus(err, http.StatusBadRequest):
		return "", errKey
	case rest.IsStatus(err, http.StatusNotFound):
		return "", errors.New("no Kavita API at this address")
	case err != nil:
		return "", err
	case u.Token == "":
		return "", errKey
	}
	c.token, c.user, c.fetched = u.Token, u.Username, time.Now()
	return c.token, nil
}

func (c *conn) forget() {
	c.mu.Lock()
	c.token = ""
	c.mu.Unlock()
}

// do calls the API, getting a new token once if Kavita refuses the old one.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) (http.Header, error) {
	hdr, err := c.api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.forget()
		hdr, err = c.api.Do(ctx, method, path, q, body, out)
	}
	switch {
	case errors.Is(err, errKey):
		return nil, err
	case rest.IsStatus(err, http.StatusUnauthorized):
		return nil, errKey
	case rest.IsStatus(err, http.StatusForbidden):
		return nil, errors.New("Kavita refused: this needs an admin account")
	}
	return hdr, err
}

type library struct {
	ID          int      `json:"id"`
	Name        string   `json:"name"`
	Type        int      `json:"type"`
	LastScanned string   `json:"lastScanned"`
	Folders     []string `json:"folders"`
}

var libTypes = map[int]string{0: "manga", 1: "comic", 2: "book", 3: "image", 4: "light novel", 5: "comic (ComicVine)"}

func (c *conn) libraries(ctx context.Context) ([]library, error) {
	var libs []library
	_, err := c.do(ctx, http.MethodGet, "/Library/libraries", nil, nil, &libs)
	return libs, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	libs, err := c.libraries(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	c.mu.Lock()
	user := c.user
	c.mu.Unlock()
	msg := fmt.Sprintf("%d libraries", len(libs))
	if user != "" {
		msg = "signed in as " + user + " · " + msg
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type series struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Localized   string `json:"localizedName"`
	Pages       int    `json:"pages"`
	PagesRead   int    `json:"pagesRead"`
	Format      int    `json:"format"`
	LibraryID   int    `json:"libraryId"`
	LibraryName string `json:"libraryName"`
	Created     string `json:"created"`
	LastAdded   string `json:"lastChapterAdded"`
}

var formats = map[int]string{0: "image", 1: "archive", 2: "unknown", 3: "epub", 4: "pdf"}

func (c *conn) seriesRow(s series) map[string]any {
	row := map[string]any{"id": s.ID, "name": s.Name, "libraryId": s.LibraryID,
		"open": fmt.Sprintf("%s/library/%d/series/%d", c.origin, s.LibraryID, s.ID)}
	if s.Localized != "" && s.Localized != s.Name {
		row["localizedName"] = s.Localized
	}
	if s.LibraryName != "" {
		row["library"] = s.LibraryName
	}
	if f, ok := formats[s.Format]; ok {
		row["format"] = f
	}
	if s.Pages > 0 {
		row["pages"], row["pagesRead"], row["percentRead"] = s.Pages, s.PagesRead, s.PagesRead*100/s.Pages
	}
	if s.LastAdded != "" && !strings.HasPrefix(s.LastAdded, "0001-") {
		row["lastAdded"] = s.LastAdded
	}
	return row
}

// filter is Kavita's FilterV2Dto: all series, or one library's.
func filter(lib int, sortField int, asc bool) map[string]any {
	st := []map[string]any{}
	if lib > 0 {
		// Field 19 is Libraries, comparison 0 is Equal.
		st = append(st, map[string]any{"comparison": 0, "field": 19, "value": strconv.Itoa(lib)})
	}
	return map[string]any{"statements": st, "combination": 1, "limitTo": 0,
		"sortOptions": map[string]any{"sortField": sortField, "isAscending": asc}}
}

type input struct {
	Library *int   `json:"library"`
	Search  string `json:"search"`
	Limit   int    `json:"limit"`
	Force   bool   `json:"force"`
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
	lib := 0
	if p.Library != nil {
		if *p.Library < 1 {
			return sdk.Result{}, errors.New("the library is a library id (see libraries)")
		}
		lib = *p.Library
	}
	search := strings.TrimSpace(p.Search)
	if len(search) > 200 || strings.ContainsAny(search, "\r\n\x00") {
		return sdk.Result{}, errors.New("the search is one line of at most 200 characters")
	}
	page := url.Values{"PageNumber": {"1"}, "PageSize": {limitOf(p.Limit)}}
	switch call.Action {
	case "libraries":
		libs, err := c.libraries(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, l := range libs {
			row := map[string]any{"id": l.ID, "name": l.Name, "type": libTypes[l.Type], "folders": l.Folders}
			if l.LastScanned != "" && !strings.HasPrefix(l.LastScanned, "0001-") {
				row["lastScanned"] = l.LastScanned
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "series":
		if search != "" {
			return c.search(ctx, search, lib, p.Limit)
		}
		var ss []series
		hdr, err := c.do(ctx, http.MethodPost, "/Series/all-v2", page, filter(lib, 1, true), &ss)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range ss {
			out = append(out, c.seriesRow(s))
		}
		return sdk.JSON(map[string]any{"series": out, "total": total(hdr, len(out))})

	case "recent":
		var ss []series
		if _, err := c.do(ctx, http.MethodPost, "/Series/recently-added-v2", page, filter(lib, 2, false), &ss); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range ss {
			out = append(out, c.seriesRow(s))
		}
		return sdk.JSON(map[string]any{"series": out})

	case "scan_library":
		if lib == 0 {
			return sdk.Result{}, errors.New("give the library to scan (see libraries)")
		}
		libs, err := c.libraries(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		var l *library
		for i := range libs {
			if libs[i].ID == lib {
				l = &libs[i]
			}
		}
		if l == nil {
			return sdk.Result{}, fmt.Errorf("there's no library %d", lib)
		}
		if call.DryRun {
			kind := "Scan"
			if p.Force {
				kind = "Force scan"
			}
			after, _ := json.Marshal(map[string]bool{"force": p.Force})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s library %q", kind, l.Name),
				Changes: []sdk.Change{{Target: fmt.Sprintf("library %q (%s)", l.Name, strings.Join(l.Folders, ", ")), Op: "scan", After: after}}}}, nil
		}
		q := url.Values{"libraryId": {strconv.Itoa(l.ID)}, "force": {strconv.FormatBool(p.Force)}}
		if _, err := c.do(ctx, http.MethodPost, "/Library/scan", q, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"scanning": l.Name, "force": p.Force})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) search(ctx context.Context, term string, lib, limit int) (sdk.Result, error) {
	var res struct {
		Series []struct {
			SeriesID    int    `json:"seriesId"`
			Name        string `json:"name"`
			Localized   string `json:"localizedName"`
			Format      int    `json:"format"`
			LibraryID   int    `json:"libraryId"`
			LibraryName string `json:"libraryName"`
		} `json:"series"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/Search/search", url.Values{"queryString": {term}}, nil, &res); err != nil {
		return sdk.Result{}, err
	}
	n, _ := strconv.Atoi(limitOf(limit))
	out := []map[string]any{}
	for _, s := range res.Series {
		if lib > 0 && s.LibraryID != lib {
			continue
		}
		if len(out) == n {
			break
		}
		out = append(out, c.seriesRow(series{ID: s.SeriesID, Name: s.Name, Localized: s.Localized, Format: s.Format, LibraryID: s.LibraryID, LibraryName: s.LibraryName}))
	}
	return sdk.JSON(map[string]any{"series": out, "total": len(out)})
}

// total reads Kavita's Pagination header.
func total(h http.Header, fallback int) int {
	var p struct {
		TotalItems int `json:"totalItems"`
	}
	if h != nil && json.Unmarshal([]byte(h.Get("Pagination")), &p) == nil && p.TotalItems > 0 {
		return p.TotalItems
	}
	return fallback
}
