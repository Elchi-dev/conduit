// Package wikijs works with a Wiki.js 2.x wiki through its GraphQL API and an
// API key: listing and searching pages, reading a page's source, and
// creating and editing pages, with an undo that puts back the page's
// previous version.
package wikijs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/textdiff"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Wiki.js site.
type Config struct {
	URL   string `json:"url"`   // e.g. https://wiki.example.com
	Token string `json:"token"` // secret:// API key
	// Public says guests can read the wiki (Wiki.js's default Guests group
	// can). Unset counts as public.
	Public             *bool  `json:"public"`
	Locale             string `json:"locale"` // default locale for paths, "en" when empty
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	origin string
	public bool
	locale string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Wiki.js module.
func New() *Module { return &Module{} }

const (
	maxTitle   = 255
	maxDesc    = 1000
	maxContent = 1 << 20 // 1 MiB
	maxPath    = 255
	maxTags    = 50
)

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	localeRe = regexp.MustCompile(`^[a-z]{2,3}(-[A-Za-z]{2,4})?$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	page := `"id":{"type":"integer","minimum":1,"description":"Page id (see pages or search)"},"path":{"type":"string","description":"The page's path, e.g. ops/backups, instead of id"},"locale":{"type":"string","description":"The path's locale (default: the setting, or en)"}`
	restore := `{"type":"object","required":["id","version","at"],"properties":{"id":{"type":"integer","minimum":1},"version":{"type":"integer","minimum":1,"description":"The history version holding the page before the edit"},"at":{"type":"string","description":"When the edit saved the page (its updatedAt)"}}}`
	fields := `"title":{"type":"string"},"description":{"type":"string"},"content":{"type":"string","description":"The page source (Markdown for Markdown pages), replacing it whole; 1 MiB at most"}`
	return sdk.Manifest{
		ID: "wikijs", Name: "Wiki.js", Version: "0.1.0", Category: "Productivity", Icon: "book",
		Description: "List and search a Wiki.js wiki, read pages as Markdown, and create and edit pages, with an undo that puts back the previous version.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Wiki.js's address, e.g. https://wiki.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API key from Administration → API Access (turn the API on there). It acts with its group's permissions; editing needs write:pages and reading a page's source manage:pages"},
			"public":{"type":"boolean","default":true,"description":"Guests can read this wiki (Wiki.js's default). Then editing a published page, or publishing one, is destructive. Turn it off when the Guests group can't read pages"},
			"locale":{"type":"string","default":"en","description":"The locale of page paths, when an action doesn't give one"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "pages", Title: "Pages", Description: "Pages, most recently updated first: id, path, title, description, tags and whether each is published. No page text.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"locale":{"type":"string"},"tags":{"type":"array","maxItems":10,"items":{"type":"string"}},"limit":{"type":"integer","minimum":1,"maximum":500,"default":50}}}`)},
			{Name: "search", Title: "Search", Description: "Pages matching words, from Wiki.js's search engine: id, path, title and description, no page text.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string"},"path":{"type":"string","description":"Only pages under this path"},"locale":{"type":"string"}}}`)},
			{Name: "read_page", Title: "Read a page", Description: "A page's source (Markdown for Markdown pages) with its title, description, tags, editor and dates. Page content is private, so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + page + `,"maxChars":{"type":"integer","minimum":1,"maximum":200000,"default":50000}}}`)},
			{Name: "create_page", Title: "Create a page", Description: "A new Markdown page at a path. On a public wiki it's created unpublished (only editors see it); publish it with update_public_page. There's no undo: deleting pages isn't offered here.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["path","title","content"],"properties":{"path":{"type":"string"},"locale":{"type":"string"},` + fields + `,"tags":{"type":"array","maxItems":50,"items":{"type":"string"}}}}`)},
			{Name: "update_page", Title: "Edit a page", Description: "Changes a page's title, description or source (only the fields given), on a private wiki or for an unpublished page on a public one; published may be set too (to true only on a private wiki; unpublishing a page guests can read is update_public_page). The preview shows the lines added and removed. Undo puts back the previous version, if nobody has edited the page since.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + page + `,` + fields + `,"published":{"type":"boolean"}}}`)},
			{Name: "update_public_page", Title: "Edit or publish a public page", Description: "Like update_page, for a page guests can read on a public wiki, or to publish a page there (published: true): what it writes is public at once. Undo puts back the previous version, if nobody has edited the page since.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + page + `,` + fields + `,"published":{"type":"boolean"}}}`)},
			{Name: "restore_version", Title: "Undo the latest edit", Description: "Puts a page back as it was before its latest edit (title, description, source and published), only while the page is still exactly as that edit left it, and only when guests can read neither the page nor the version put back (otherwise restore_public_version). Used by update_page's undo.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(restore)},
			{Name: "restore_public_version", Title: "Undo the latest edit of a public page", Description: "Like restore_version, for a page guests can read on a public wiki, or when putting the earlier version back publishes the page: what it puts back is public at once. Used by update_public_page's undo.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(restore)},
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
		return errors.New("the address is like https://wiki.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	loc := strings.TrimSpace(c.Locale)
	if loc == "" {
		loc = "en"
	}
	if !localeRe.MatchString(loc) {
		return errors.New("the locale is a language code like en or pt-BR")
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
	ref := c.Token
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/graphql")
	api := rest.New(origin, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		if t == "" || strings.ContainsAny(t, " \r\n") {
			return errors.New("the Wiki.js API key is one line with no spaces")
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, origin: origin, public: c.Public == nil || *c.Public, locale: loc})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// gql sends one GraphQL operation; values only ever travel as variables.
func (c *conn) gql(ctx context.Context, query string, vars map[string]any, out any) error {
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if vars == nil {
		vars = map[string]any{}
	}
	_, err := c.api.Do(ctx, http.MethodPost, "/graphql", nil, map[string]any{"query": query, "variables": vars}, &env)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Wiki.js refused the API key")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("no Wiki.js GraphQL API at this address")
	case err != nil:
		return err
	}
	if len(env.Errors) > 0 {
		return &gqlError{msg: clean(env.Errors[0].Message)}
	}
	if out != nil {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("unexpected answer from Wiki.js: %w", err)
		}
	}
	return nil
}

// gqlError is an error Wiki.js reported in a GraphQL answer.
type gqlError struct{ msg string }

func (e *gqlError) Error() string {
	switch e.msg {
	case "Forbidden", "Unauthorized":
		return "Wiki.js refused the request (" + e.msg + "): the API key's group lacks the permission, or the key isn't valid"
	}
	return "Wiki.js: " + e.msg
}

// clean redacts a server message, then keeps it to one short line.
func clean(s string) string {
	s = strings.Join(strings.Fields(rest.Redact(s)), " ")
	if r := []rune(s); len(r) > 300 {
		s = string(r[:300]) + "…"
	}
	if s == "" {
		s = "unknown error"
	}
	return s
}

type result struct {
	Succeeded bool   `json:"succeeded"`
	Slug      string `json:"slug"`
	Message   string `json:"message"`
}

func (r result) err() error {
	if r.Succeeded {
		return nil
	}
	return fmt.Errorf("Wiki.js: %s", clean(r.Message))
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	// An unknown key makes Wiki.js treat the request as a guest's, so ask
	// for the key's own profile, which a guest doesn't have.
	var out struct {
		Users struct {
			Profile *struct {
				ID int `json:"id"`
			} `json:"profile"`
		} `json:"users"`
	}
	err = c.gql(ctx, `query { users { profile { id } } }`, nil, &out)
	var ge *gqlError
	if errors.As(err, &ge) || (err == nil && out.Users.Profile == nil) {
		return sdk.Health{Status: "down", Message: "Wiki.js refused the API key (it answered as to a guest)"}
	}
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var list struct {
		Pages struct {
			List []struct {
				ID int `json:"id"`
			} `json:"list"`
		} `json:"pages"`
	}
	msg := "connected"
	if c.gql(ctx, `query ($limit: Int) { pages { list(limit: $limit) { id } } }`, map[string]any{"limit": 1000}, &list) == nil {
		n := len(list.Pages.List)
		msg = fmt.Sprintf("%d pages", n)
		if n == 1000 {
			msg = "1000+ pages"
		}
	}
	if c.public {
		msg += " · public"
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type tag struct {
	Tag string `json:"tag"`
}

type page struct {
	ID               int     `json:"id"`
	Path             string  `json:"path"`
	Title            string  `json:"title"`
	Description      string  `json:"description"`
	IsPrivate        bool    `json:"isPrivate"`
	IsPublished      bool    `json:"isPublished"`
	PublishStartDate *string `json:"publishStartDate"`
	PublishEndDate   *string `json:"publishEndDate"`
	Tags             []tag   `json:"tags"`
	Content          string  `json:"content"`
	ContentType      string  `json:"contentType"`
	CreatedAt        string  `json:"createdAt"`
	UpdatedAt        string  `json:"updatedAt"`
	Editor           string  `json:"editor"`
	Locale           string  `json:"locale"`
	ScriptCSS        *string `json:"scriptCss"`
	ScriptJS         *string `json:"scriptJs"`
}

const pageFields = `id path title description isPrivate isPublished publishStartDate publishEndDate tags { tag } content contentType createdAt updatedAt editor locale scriptCss scriptJs`

func (p page) tagNames() []string {
	out := []string{}
	for _, t := range p.Tags {
		out = append(out, t.Tag)
	}
	return out
}

func (c *conn) link(p page) string {
	return c.origin + "/" + url.PathEscape(p.Locale) + "/" + escapePath(p.Path)
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

// visible says guests can see p.
func (c *conn) visible(p page) bool { return c.public && p.IsPublished }

// cleanPath checks a page path as Wiki.js accepts it and returns it
// without leading or trailing slashes.
func cleanPath(s string) (string, error) {
	s = strings.Trim(strings.TrimSpace(s), "/")
	bad := errors.New("the path is like ops/backups: letters, digits, - and _, parts separated by /")
	if s == "" || len(s) > maxPath || strings.Contains(s, "//") {
		return "", bad
	}
	for _, r := range s {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '/') {
			return "", bad
		}
	}
	return s, nil
}

func (c *conn) localeOf(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return c.locale, nil
	}
	if !localeRe.MatchString(s) {
		return "", errors.New("the locale is a language code like en or pt-BR")
	}
	return s, nil
}

type input struct {
	ID          int       `json:"id"`
	Path        string    `json:"path"`
	Locale      string    `json:"locale"`
	Query       string    `json:"query"`
	Tags        *[]string `json:"tags"`
	Limit       int       `json:"limit"`
	MaxChars    int       `json:"maxChars"`
	Title       *string   `json:"title"`
	Description *string   `json:"description"`
	Content     *string   `json:"content"`
	Published   *bool     `json:"published"`
	Version     int       `json:"version"`
	At          string    `json:"at"`
}

// target checks how the input names a page, before any request.
func (c *conn) target(p input) (id int, path, locale string, err error) {
	if p.ID < 0 || (p.ID > 0) == (strings.TrimSpace(p.Path) != "") {
		return 0, "", "", errors.New("name the page by its id or its path")
	}
	if p.ID > 0 {
		return p.ID, "", "", nil
	}
	if path, err = cleanPath(p.Path); err != nil {
		return 0, "", "", err
	}
	if locale, err = c.localeOf(p.Locale); err != nil {
		return 0, "", "", err
	}
	return 0, path, locale, nil
}

func (c *conn) get(ctx context.Context, id int, path, locale string) (page, error) {
	var out struct {
		Pages struct {
			Single       *page `json:"single"`
			SingleByPath *page `json:"singleByPath"`
		} `json:"pages"`
	}
	var err error
	if id > 0 {
		err = c.gql(ctx, `query ($id: Int!) { pages { single(id: $id) { `+pageFields+` } } }`, map[string]any{"id": id}, &out)
	} else {
		err = c.gql(ctx, `query ($path: String!, $locale: String!) { pages { singleByPath(path: $path, locale: $locale) { `+pageFields+` } } }`, map[string]any{"path": path, "locale": locale}, &out)
	}
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") || strings.Contains(err.Error(), "not found") {
			return page{}, errors.New("there's no such page (or the key can't see it)")
		}
		return page{}, err
	}
	p := out.Pages.Single
	if p == nil {
		p = out.Pages.SingleByPath
	}
	if p == nil || p.ID == 0 {
		return page{}, errors.New("there's no such page (or the key can't see it)")
	}
	return *p, nil
}

func checkText(name string, s *string, maxLen int, empty bool) (string, error) {
	v := strings.TrimSpace(*s)
	if (!empty && v == "") || len([]rune(v)) > maxLen {
		if empty {
			return "", fmt.Errorf("the %s is at most %d characters", name, maxLen)
		}
		return "", fmt.Errorf("the %s is 1 to %d characters", name, maxLen)
	}
	return v, nil
}

func checkContent(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("the content can't be empty (Wiki.js refuses empty pages)")
	}
	if len(s) > maxContent {
		return errors.New("the content is too long (1 MiB at most)")
	}
	return nil
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func limitOf(n int) int {
	if n <= 0 || n > 500 {
		return 50
	}
	return n
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
	case "pages":
		vars := map[string]any{"limit": limitOf(p.Limit), "orderBy": "UPDATED", "dir": "DESC"}
		if p.Locale != "" {
			loc, err := c.localeOf(p.Locale)
			if err != nil {
				return sdk.Result{}, err
			}
			vars["locale"] = loc
		}
		if p.Tags != nil {
			if len(*p.Tags) > 10 {
				return sdk.Result{}, errors.New("at most 10 tags")
			}
			ts := []string{}
			for _, t := range *p.Tags {
				t = strings.TrimSpace(t)
				if t == "" || len([]rune(t)) > maxTitle {
					return sdk.Result{}, errors.New("each tag is 1 to 255 characters")
				}
				ts = append(ts, t)
			}
			vars["tags"] = ts
		}
		var out struct {
			Pages struct {
				List []struct {
					ID          int      `json:"id"`
					Path        string   `json:"path"`
					Locale      string   `json:"locale"`
					Title       string   `json:"title"`
					Description string   `json:"description"`
					IsPublished bool     `json:"isPublished"`
					UpdatedAt   string   `json:"updatedAt"`
					Tags        []string `json:"tags"`
				} `json:"list"`
			} `json:"pages"`
		}
		if err := c.gql(ctx, `query ($limit: Int, $orderBy: PageOrderBy, $dir: PageOrderByDirection, $locale: String, $tags: [String!]) { pages { list(limit: $limit, orderBy: $orderBy, orderByDirection: $dir, locale: $locale, tags: $tags) { id path locale title description isPublished updatedAt tags } } }`, vars, &out); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, x := range out.Pages.List {
			r := map[string]any{"id": x.ID, "path": x.Path, "locale": x.Locale, "title": x.Title, "published": x.IsPublished, "updated": x.UpdatedAt,
				"url": c.link(page{Path: x.Path, Locale: x.Locale})}
			if d := strings.TrimSpace(x.Description); d != "" {
				r["description"] = d
			}
			if len(x.Tags) > 0 {
				r["tags"] = x.Tags
			}
			list = append(list, r)
		}
		return sdk.JSON(map[string]any{"total": len(list), "pages": list})

	case "search":
		q := strings.TrimSpace(p.Query)
		if q == "" {
			return sdk.Result{}, errors.New("enter what to search for")
		}
		if len(q) > 1000 {
			return sdk.Result{}, errors.New("the query is too long")
		}
		vars := map[string]any{"query": q}
		if p.Path != "" {
			path, err := cleanPath(p.Path)
			if err != nil {
				return sdk.Result{}, err
			}
			vars["path"] = path
		}
		if p.Locale != "" {
			loc, err := c.localeOf(p.Locale)
			if err != nil {
				return sdk.Result{}, err
			}
			vars["locale"] = loc
		}
		var out struct {
			Pages struct {
				Search struct {
					Results []struct {
						ID          string `json:"id"`
						Title       string `json:"title"`
						Description string `json:"description"`
						Path        string `json:"path"`
						Locale      string `json:"locale"`
					} `json:"results"`
					TotalHits int `json:"totalHits"`
				} `json:"search"`
			} `json:"pages"`
		}
		if err := c.gql(ctx, `query ($query: String!, $path: String, $locale: String) { pages { search(query: $query, path: $path, locale: $locale) { results { id title description path locale } totalHits } } }`, vars, &out); err != nil {
			return sdk.Result{}, err
		}
		res := []map[string]any{}
		for _, x := range out.Pages.Search.Results {
			res = append(res, map[string]any{"id": x.ID, "title": x.Title, "description": x.Description, "path": x.Path, "locale": x.Locale, "url": c.link(page{Path: x.Path, Locale: x.Locale})})
		}
		return sdk.JSON(map[string]any{"total": out.Pages.Search.TotalHits, "results": res})

	case "read_page":
		id, path, loc, err := c.target(p)
		if err != nil {
			return sdk.Result{}, err
		}
		pg, err := c.get(ctx, id, path, loc)
		if err != nil {
			return sdk.Result{}, err
		}
		n := p.MaxChars
		if n <= 0 || n > 200000 {
			n = 50000
		}
		text, cut := []rune(pg.Content), false
		if len(text) > n {
			text, cut = text[:n], true
		}
		return sdk.JSON(map[string]any{"id": pg.ID, "path": pg.Path, "locale": pg.Locale, "title": pg.Title, "description": pg.Description,
			"tags": pg.tagNames(), "editor": pg.Editor, "published": pg.IsPublished, "public": c.visible(pg), "created": pg.CreatedAt, "updated": pg.UpdatedAt,
			"url": c.link(pg), "chars": len([]rune(pg.Content)), "truncated": cut, "content": string(text)})

	case "create_page":
		return c.create(ctx, call, p)
	case "update_page", "update_public_page":
		return c.update(ctx, call, p)
	case "restore_version", "restore_public_version":
		return c.restore(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) create(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.Title == nil || p.Content == nil {
		return sdk.Result{}, errors.New("the page needs a path, a title and content")
	}
	path, err := cleanPath(p.Path)
	if err != nil {
		return sdk.Result{}, err
	}
	loc, err := c.localeOf(p.Locale)
	if err != nil {
		return sdk.Result{}, err
	}
	title, err := checkText("title", p.Title, maxTitle, false)
	if err != nil {
		return sdk.Result{}, err
	}
	desc := ""
	if p.Description != nil {
		if desc, err = checkText("description", p.Description, maxDesc, true); err != nil {
			return sdk.Result{}, err
		}
	}
	if err := checkContent(*p.Content); err != nil {
		return sdk.Result{}, err
	}
	tags := []string{}
	if p.Tags != nil {
		if len(*p.Tags) > maxTags {
			return sdk.Result{}, fmt.Errorf("at most %d tags", maxTags)
		}
		for _, t := range *p.Tags {
			t = strings.TrimSpace(t)
			if t == "" || len([]rune(t)) > maxTitle {
				return sdk.Result{}, errors.New("each tag is 1 to 255 characters")
			}
			tags = append(tags, t)
		}
	}
	// On a public wiki a new page starts unpublished, so guests don't see
	// it until someone publishes it (update_public_page, destructive).
	published := !c.public
	where := loc + "/" + path
	if call.DryRun {
		state := "published"
		if !published {
			state = "unpublished (the wiki is public: publish it with update_public_page)"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create page %q at %s, %s", title, where, state),
			Changes: []sdk.Change{{Target: "page " + where, Op: "create", After: mustJSON(map[string]any{"title": title, "description": desc, "tags": tags, "published": published, "diff": textdiff.Diff("", *p.Content)})}}}}, nil
	}
	var out struct {
		Pages struct {
			Create struct {
				ResponseResult result `json:"responseResult"`
				Page           *page  `json:"page"`
			} `json:"create"`
		} `json:"pages"`
	}
	vars := map[string]any{"content": *p.Content, "description": desc, "editor": "markdown", "isPublished": published, "isPrivate": false,
		"locale": loc, "path": path, "tags": tags, "title": title}
	if err := c.gql(ctx, `mutation ($content: String!, $description: String!, $editor: String!, $isPublished: Boolean!, $isPrivate: Boolean!, $locale: String!, $path: String!, $tags: [String]!, $title: String!) { pages { create(content: $content, description: $description, editor: $editor, isPublished: $isPublished, isPrivate: $isPrivate, locale: $locale, path: $path, tags: $tags, title: $title) { responseResult { succeeded slug message } page { id path locale title } } } }`, vars, &out); err != nil {
		return sdk.Result{}, err
	}
	if err := out.Pages.Create.ResponseResult.err(); err != nil {
		return sdk.Result{}, err
	}
	res := map[string]any{"path": path, "locale": loc, "title": title, "published": published, "url": c.link(page{Path: path, Locale: loc})}
	if pg := out.Pages.Create.Page; pg != nil && pg.ID > 0 {
		res["id"] = pg.ID
	}
	if !published {
		res["note"] = "created unpublished, since the wiki is public; publish it with update_public_page"
	}
	return sdk.JSON(res)
}

// fieldsOf are the arguments that save p as it is; Wiki.js's update
// replaces every field, so each one is sent back.
func fieldsOf(p page) map[string]any {
	opt := func(s *string) any {
		if s == nil || *s == "" {
			return nil
		}
		return *s
	}
	return map[string]any{"id": p.ID, "content": p.Content, "description": p.Description, "editor": p.Editor, "isPrivate": p.IsPrivate,
		"isPublished": p.IsPublished, "locale": p.Locale, "path": p.Path, "publishStartDate": opt(p.PublishStartDate), "publishEndDate": opt(p.PublishEndDate),
		"scriptCss": opt(p.ScriptCSS), "scriptJs": opt(p.ScriptJS), "tags": p.tagNames(), "title": p.Title}
}

const updateMutation = `mutation ($id: Int!, $content: String, $description: String, $editor: String, $isPrivate: Boolean, $isPublished: Boolean, $locale: String, $path: String, $publishStartDate: Date, $publishEndDate: Date, $scriptCss: String, $scriptJs: String, $tags: [String], $title: String) { pages { update(id: $id, content: $content, description: $description, editor: $editor, isPrivate: $isPrivate, isPublished: $isPublished, locale: $locale, path: $path, publishStartDate: $publishStartDate, publishEndDate: $publishEndDate, scriptCss: $scriptCss, scriptJs: $scriptJs, tags: $tags, title: $title) { responseResult { succeeded slug message } } } }`

// save writes next over cur after checking nobody saved the page since cur
// was read, then returns an undo to cur's version (nil when Wiki.js's
// history doesn't show it).
func (c *conn) save(ctx context.Context, cur, next page, label string) (*sdk.Undo, error) {
	var chk struct {
		Pages struct {
			CheckConflicts bool `json:"checkConflicts"`
		} `json:"pages"`
	}
	if err := c.gql(ctx, `query ($id: Int!, $at: Date!) { pages { checkConflicts(id: $id, checkoutDate: $at) } }`, map[string]any{"id": cur.ID, "at": cur.UpdatedAt}, &chk); err != nil {
		return nil, err
	}
	if chk.Pages.CheckConflicts {
		return nil, errors.New("someone saved the page in the meantime; read it again and redo the change")
	}
	var out struct {
		Pages struct {
			Update struct {
				ResponseResult result `json:"responseResult"`
			} `json:"update"`
		} `json:"pages"`
	}
	if err := c.gql(ctx, updateMutation, fieldsOf(next), &out); err != nil {
		return nil, err
	}
	if err := out.Pages.Update.ResponseResult.err(); err != nil {
		return nil, err
	}
	// Wiki.js keeps the page as it was before the update as the newest
	// history version, dated with the old updatedAt.
	var hist struct {
		Pages struct {
			History struct {
				Trail []struct {
					VersionID   int    `json:"versionId"`
					VersionDate string `json:"versionDate"`
				} `json:"trail"`
			} `json:"history"`
		} `json:"pages"`
	}
	if c.gql(ctx, `query ($id: Int!) { pages { history(id: $id, offsetPage: 0, offsetSize: 1) { trail { versionId versionDate } } } }`, map[string]any{"id": cur.ID}, &hist) != nil || len(hist.Pages.History.Trail) == 0 {
		return nil, nil
	}
	v := hist.Pages.History.Trail[0]
	if v.VersionID <= 0 || !sameTime(v.VersionDate, cur.UpdatedAt) {
		return nil, nil
	}
	now, err := c.get(ctx, cur.ID, "", "")
	if err != nil || now.UpdatedAt == "" {
		return nil, nil
	}
	// Putting cur back over next is public when guests can read either.
	action := "restore_version"
	if c.visible(cur) || c.visible(next) || c.visible(now) {
		action = "restore_public_version"
	}
	return sdk.UndoWith(action, map[string]any{"id": cur.ID, "version": v.VersionID, "at": now.UpdatedAt}, fmt.Sprintf("Put page %q back as it was", label)), nil
}

func sameTime(a, b string) bool {
	if a == b {
		return true
	}
	ta, e1 := time.Parse(time.RFC3339Nano, a)
	tb, e2 := time.Parse(time.RFC3339Nano, b)
	return e1 == nil && e2 == nil && ta.Equal(tb)
}

func (c *conn) update(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	id, path, loc, err := c.target(p)
	if err != nil {
		return sdk.Result{}, err
	}
	var title, desc string
	if p.Title != nil {
		if title, err = checkText("title", p.Title, maxTitle, false); err != nil {
			return sdk.Result{}, err
		}
	}
	if p.Description != nil {
		if desc, err = checkText("description", p.Description, maxDesc, true); err != nil {
			return sdk.Result{}, err
		}
	}
	if p.Content != nil {
		if err := checkContent(*p.Content); err != nil {
			return sdk.Result{}, err
		}
	}
	if p.Title == nil && p.Description == nil && p.Content == nil && p.Published == nil {
		return sdk.Result{}, errors.New("say what to change: title, description, content or published")
	}
	cur, err := c.get(ctx, id, path, loc)
	if err != nil {
		return sdk.Result{}, err
	}
	next := cur
	if p.Title != nil {
		next.Title = title
	}
	if p.Description != nil {
		next.Description = desc
	}
	if p.Content != nil {
		next.Content = *p.Content
	}
	if p.Published != nil {
		next.IsPublished = *p.Published
	}
	public := call.Action == "update_public_page"
	if !public && (c.visible(cur) || c.visible(next)) {
		if c.visible(cur) {
			return sdk.Result{}, errors.New("guests can read this page (the wiki is public and the page published): edit it with update_public_page, which is destructive")
		}
		return sdk.Result{}, errors.New("publishing a page on a public wiki makes it readable by anyone: use update_public_page, which is destructive")
	}
	return c.apply(ctx, call, cur, next, "Edit", true)
}

// apply previews or saves the change from cur to next. quote says the new
// content is the agent's own, so its added lines may be quoted; content put
// back from the page's history is the page's (private) text, so its diff
// gives only counts and line numbers.
func (c *conn) apply(ctx context.Context, call sdk.Call, cur, next page, verb string, quote bool) (sdk.Result, error) {
	target := fmt.Sprintf("page %d %s/%s", cur.ID, cur.Locale, cur.Path)
	before, after := map[string]any{}, map[string]any{}
	if next.Title != cur.Title {
		before["title"], after["title"] = cur.Title, next.Title
	}
	if next.Description != cur.Description {
		before["description"], after["description"] = cur.Description, next.Description
	}
	if next.IsPublished != cur.IsPublished {
		before["published"], after["published"] = cur.IsPublished, next.IsPublished
	}
	if next.Content != cur.Content {
		// Never the old text: page content is private, and previews are
		// kept in approvals.
		before["chars"] = len([]rune(cur.Content))
		d := textdiff.Diff(cur.Content, next.Content)
		if !quote {
			d = d.Unquoted()
		}
		after["chars"], after["diff"] = len([]rune(next.Content)), d
	}
	if len(after) == 0 {
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Nothing to change on page %q", cur.Title)}}, nil
		}
		return sdk.JSON(map[string]any{"id": cur.ID, "title": cur.Title, "note": "nothing to change: the page already is like that"})
	}
	summary := fmt.Sprintf("%s page %q", verb, cur.Title)
	if c.visible(cur) || c.visible(next) {
		summary += " (guests can read it)"
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: target, Op: "update", Before: mustJSON(before), After: mustJSON(after)}}}}, nil
	}
	undo, err := c.save(ctx, cur, next, next.Title)
	if err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"id": cur.ID, "path": cur.Path, "locale": cur.Locale, "title": next.Title, "published": next.IsPublished, "url": c.link(cur), "changed": after}
	if undo == nil {
		out["note"] = "saved; Wiki.js's history didn't show the previous version, so there's no undo here (the page history in Wiki.js has it)"
	}
	res, err := sdk.JSON(out)
	res.Undo = undo
	return res, err
}

// restore puts a page back as it was before its latest edit, only while
// the page is still as that edit left it.
func (c *conn) restore(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	at := strings.TrimSpace(p.At)
	if p.ID <= 0 || p.Version <= 0 || at == "" || len(at) > 64 {
		return sdk.Result{}, errors.New("give the page id, the version and when the edit saved the page (at)")
	}
	cur, err := c.get(ctx, p.ID, "", "")
	if err != nil {
		return sdk.Result{}, err
	}
	if !sameTime(cur.UpdatedAt, at) {
		return sdk.Result{}, errors.New("the page was edited again since; nothing is put back (its history in Wiki.js has every version)")
	}
	var hist struct {
		Pages struct {
			History struct {
				Trail []struct {
					VersionID int `json:"versionId"`
				} `json:"trail"`
			} `json:"history"`
		} `json:"pages"`
	}
	if err := c.gql(ctx, `query ($id: Int!) { pages { history(id: $id, offsetPage: 0, offsetSize: 1) { trail { versionId } } } }`, map[string]any{"id": cur.ID}, &hist); err != nil {
		return sdk.Result{}, err
	}
	if len(hist.Pages.History.Trail) == 0 || hist.Pages.History.Trail[0].VersionID != p.Version {
		return sdk.Result{}, errors.New("that version isn't the one before the page's latest edit; nothing is put back")
	}
	var ver struct {
		Pages struct {
			Version *struct {
				Content     string `json:"content"`
				Title       string `json:"title"`
				Description string `json:"description"`
				IsPublished bool   `json:"isPublished"`
				PageID      int    `json:"pageId"`
			} `json:"version"`
		} `json:"pages"`
	}
	if err := c.gql(ctx, `query ($pageId: Int!, $versionId: Int!) { pages { version(pageId: $pageId, versionId: $versionId) { content title description isPublished pageId } } }`, map[string]any{"pageId": cur.ID, "versionId": p.Version}, &ver); err != nil {
		return sdk.Result{}, err
	}
	v := ver.Pages.Version
	if v == nil || v.PageID != cur.ID {
		return sdk.Result{}, errors.New("there's no such version of this page")
	}
	if err := checkContent(v.Content); err != nil {
		return sdk.Result{}, fmt.Errorf("the earlier version can't be put back: %w", err)
	}
	next := cur
	next.Content, next.Title, next.Description, next.IsPublished = v.Content, v.Title, v.Description, v.IsPublished
	// Like update_page: a page guests can read, or putting back a version
	// that publishes it, is the destructive action's.
	if call.Action != "restore_public_version" && (c.visible(cur) || c.visible(next)) {
		return sdk.Result{}, errors.New("guests can read this page, or putting the earlier version back would publish it: use restore_public_version, which is destructive")
	}
	return c.apply(ctx, call, cur, next, "Put back", false)
}
