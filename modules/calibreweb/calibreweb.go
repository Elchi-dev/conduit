// Package calibreweb works with a Calibre-Web library through its OPDS
// catalog and a user's login: searching books, the newest books, and the
// user's shelves with the books on each.
package calibreweb

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Calibre-Web server.
type Config struct {
	URL                string `json:"url"`      // e.g. https://books.example.com
	Username           string `json:"username"` // a Calibre-Web user
	Password           string `json:"password"` // secret:// its password
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	origin string
	user   string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Calibre-Web module.
func New() *Module { return &Module{} }

var (
	pathRe     = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	downloadRe = regexp.MustCompile(`/opds/download/(\d+)/([A-Za-z0-9]+)/?$`)
	shelfRe    = regexp.MustCompile(`/opds/shelf/(\d+)/?$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := `"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}`
	return sdk.Manifest{
		ID: "calibreweb", Name: "Calibre-Web", Version: "0.1.0", Category: "Media", Icon: "book",
		Description: "Your Calibre-Web library: search books, see what's new, and browse your shelves.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","username","password"],"properties":{
			"url":{"type":"string","description":"Calibre-Web's address, e.g. https://books.example.com"},
			"username":{"type":"string","description":"A Calibre-Web user; the shelves shown are this user's"},
			"password":{"type":"string","x-secret":true,"description":"Its password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "search", Title: "Search books", Description: "Books whose title, author, series, tag or publisher match: authors, series, tags, language, formats and a link to open each.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string","minLength":1,"maxLength":200},` + limit + `}}`)},
			{Name: "recent", Title: "Recently added", Description: "The newest books in the library.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + limit + `}}`)},
			{Name: "shelves", Title: "Shelves", Description: "Your shelves and the public ones, by name.", Risk: sdk.RiskRead},
			{Name: "shelf", Title: "Books on a shelf", Description: "The books on one shelf.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["shelf"],"properties":{"shelf":{"type":"integer","minimum":1,"description":"Shelf id (see shelves)"},` + limit + `}}`)},
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
		return errors.New("the address is like https://books.example.com")
	}
	user := strings.TrimSpace(c.Username)
	if user == "" || strings.ContainsAny(user, ":\r\n") || len(user) > 200 {
		return errors.New("enter your Calibre-Web user name")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
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
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/opds")
	ref := c.Password
	api := rest.New(origin, func(ctx context.Context, r *http.Request) error {
		pw, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.SetBasicAuth(user, pw)
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, origin: origin, user: user})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

type link struct {
	Rel  string `xml:"rel,attr"`
	Href string `xml:"href,attr"`
	Type string `xml:"type,attr"`
}

type entry struct {
	Title   string `xml:"title"`
	ID      string `xml:"id"`
	Updated string `xml:"updated"`
	Authors []struct {
		Name string `xml:"name"`
	} `xml:"author"`
	Categories []struct {
		Label string `xml:"label,attr"`
		Term  string `xml:"term,attr"`
	} `xml:"category"`
	Language  []string `xml:"language"`
	Publisher struct {
		Name string `xml:"name"`
		Text string `xml:",chardata"`
	} `xml:"publisher"`
	Issued string `xml:"issued"`
	Links  []link `xml:"link"`
}

type feed struct {
	XMLName xml.Name `xml:"feed"`
	Title   string   `xml:"title"`
	Entries []entry  `xml:"entry"`
}

// feed fetches one OPDS feed.
func (c *conn) feed(ctx context.Context, path string) (feed, error) {
	var f feed
	res, err := c.api.Send(ctx, http.MethodGet, path, nil, nil, http.Header{"Accept": {"application/atom+xml"}})
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return f, errors.New("Calibre-Web refused the user name or password")
	case rest.IsStatus(err, http.StatusNotFound):
		return f, errors.New("not found (is this Calibre-Web, and does the shelf exist?)")
	case err != nil:
		return f, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return f, fmt.Errorf("Calibre-Web answered %s", res.Status)
	}
	if err := xml.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(&f); err != nil {
		return f, errors.New("unexpected answer: is this Calibre-Web's OPDS catalog?")
	}
	return f, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	f, err := c.feed(ctx, "/opds")
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "catalog reachable as " + c.user
	if t := strings.TrimSpace(f.Title); t != "" {
		msg = t + " · " + msg
	}
	return sdk.Health{Status: "ok", Message: msg}
}

func (c *conn) book(e entry) (map[string]any, bool) {
	id := ""
	formats := []string{}
	for _, l := range e.Links {
		if mm := downloadRe.FindStringSubmatch(l.Href); mm != nil {
			id = mm[1]
			formats = append(formats, strings.ToLower(mm[2]))
		}
	}
	if id == "" {
		return nil, false
	}
	sort.Strings(formats)
	authors := []string{}
	for _, a := range e.Authors {
		if n := strings.TrimSpace(a.Name); n != "" {
			authors = append(authors, n)
		}
	}
	tags := []string{}
	for _, t := range e.Categories {
		if s := strings.TrimSpace(t.Label); s != "" {
			tags = append(tags, s)
		} else if s := strings.TrimSpace(t.Term); s != "" {
			tags = append(tags, s)
		}
	}
	n, _ := strconv.Atoi(id)
	out := map[string]any{"id": n, "title": strings.TrimSpace(e.Title), "authors": authors, "formats": formats, "open": c.origin + "/book/" + id}
	if len(tags) > 0 {
		out["tags"] = tags
	}
	if len(e.Language) > 0 {
		out["languages"] = e.Language
	}
	if pub := strings.TrimSpace(e.Publisher.Name + e.Publisher.Text); pub != "" {
		out["publisher"] = pub
	}
	if e.Issued != "" {
		out["published"] = strings.TrimSpace(e.Issued)
	}
	if e.Updated != "" {
		out["updated"] = e.Updated
	}
	return out, true
}

func (c *conn) books(ctx context.Context, path string, limit int) (sdk.Result, error) {
	f, err := c.feed(ctx, path)
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, e := range f.Entries {
		if len(out) == limit {
			break
		}
		if b, ok := c.book(e); ok {
			out = append(out, b)
		}
	}
	return sdk.JSON(map[string]any{"books": out})
}

type input struct {
	Query string `json:"query"`
	Shelf *int   `json:"shelf"`
	Limit int    `json:"limit"`
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
	limit := p.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	switch call.Action {
	case "search":
		q := strings.TrimSpace(p.Query)
		if q == "" || len(q) > 200 || strings.ContainsAny(q, "\r\n\x00") {
			return sdk.Result{}, errors.New("the query is one line of 1 to 200 characters")
		}
		return c.books(ctx, "/opds/search/"+url.PathEscape(q), limit)

	case "recent":
		return c.books(ctx, "/opds/new", limit)

	case "shelves":
		f, err := c.feed(ctx, "/opds/shelfindex")
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, e := range f.Entries {
			id := ""
			for _, s := range append([]string{e.ID}, hrefs(e.Links)...) {
				if mm := shelfRe.FindStringSubmatch(s); mm != nil {
					id = mm[1]
				}
			}
			if id == "" {
				continue
			}
			n, _ := strconv.Atoi(id)
			out = append(out, map[string]any{"id": n, "name": strings.TrimSpace(e.Title), "open": c.origin + "/shelf/" + id})
		}
		return sdk.JSON(out)

	case "shelf":
		if p.Shelf == nil || *p.Shelf < 1 {
			return sdk.Result{}, errors.New("the shelf is a shelf id (see shelves)")
		}
		return c.books(ctx, "/opds/shelf/"+strconv.Itoa(*p.Shelf), limit)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func hrefs(ls []link) []string {
	out := []string{}
	for _, l := range ls {
		out = append(out, l.Href)
	}
	return out
}
