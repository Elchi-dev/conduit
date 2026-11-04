// Package mediawiki works with a MediaWiki wiki through its Action API and a
// bot password: searching, reading a page's wikitext and editing existing
// pages, with conflict detection and an undo that puts back the previous
// revision.
package mediawiki

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/textdiff"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one wiki and its bot password.
type Config struct {
	URL      string `json:"url"`      // the api.php address, e.g. https://wiki.example.com/w/api.php
	Username string `json:"username"` // the bot password's login name, e.g. Elchi@conduit
	Password string `json:"password"` // secret:// bot password
	// Assert is "user" (default) or "bot": every request asks MediaWiki to
	// check the session is still that.
	Assert             string `json:"assert"`
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	http   *http.Client
	api    string
	user   string
	ref    string
	host   sdk.Host
	assert string

	mu       sync.Mutex // guards loggedIn and the login itself
	loggedIn bool

	wait func(ctx context.Context, d time.Duration) error
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Wait replaces the pause before a request is retried after maxlag
	// (tests).
	Wait func(ctx context.Context, d time.Duration) error
}

// New returns the MediaWiki module.
func New() *Module { return &Module{} }

const (
	maxText    = 1 << 20 // 1 MiB of wikitext
	maxSummary = 500
	maxLag     = "5" // seconds, as MediaWiki recommends
	maxTries   = 3   // attempts while the wiki reports maxlag
)

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// A bot password's login name: User@BotName.
	userRe = regexp.MustCompile(`^[^@:#<>\[\]|{}/\x00-\x1f\x7f]{1,85}@[A-Za-z0-9_. -]{1,32}$`)
	// Characters MediaWiki never allows in a title.
	badTitle = regexp.MustCompile(`[#<>\[\]|{}\x00-\x1f\x7f]`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	page := `"title":{"type":"string","description":"Page title, e.g. Help:Backups"},"pageid":{"type":"integer","minimum":1,"description":"Page id, instead of title"}`
	edit := `{"type":"object","required":["text"],"properties":{` + page + `,"text":{"type":"string","description":"The new wikitext, replacing the page's; 1 MiB at most"},"summary":{"type":"string","description":"Edit summary"},"minor":{"type":"boolean"}}}`
	return sdk.Manifest{
		ID: "mediawiki", Name: "MediaWiki", Version: "0.1.0", Category: "Productivity", Icon: "book",
		Description: "Search a MediaWiki wiki, read pages as wikitext, and edit existing pages with a bot password, with an undo that puts back the previous revision.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","username","password"],"properties":{
			"url":{"type":"string","description":"The wiki's api.php address, e.g. https://wiki.example.com/w/api.php"},
			"username":{"type":"string","description":"The bot password's login name from Special:BotPasswords, like YourName@conduit"},
			"password":{"type":"string","x-secret":true,"description":"The bot password. Give it the grants it needs (basic rights and high-volume editing or edit existing pages)"},
			"assert":{"type":"string","enum":["user","bot"],"default":"user","description":"user: each request checks the session is signed in. bot: also that the account has the bot right (and edits are marked as bot edits)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "search", Title: "Search", Description: "Pages whose title or text matches: title, page id, size, word count and last edit. No page text.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string"},"namespace":{"type":"integer","minimum":0,"description":"Namespace number (0 is articles)"},"limit":{"type":"integer","minimum":1,"maximum":50,"default":20}}}`)},
			{Name: "read_page", Title: "Read a page", Description: "A page's wikitext with its revision id, timestamp and size. Page content is private, so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + page + `,"maxChars":{"type":"integer","minimum":1,"maximum":200000,"default":50000}}}`)},
			{Name: "edit_page", Title: "Edit a page", Description: "Replaces an existing page's wikitext on a wiki anonymous visitors can't read (it never creates a page). The preview shows the lines added and removed; an edit made by someone else in the meantime is refused. Undo puts back the previous revision, if nobody has edited the page since.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(edit)},
			{Name: "edit_public_page", Title: "Edit a public page", Description: "Like edit_page, on a wiki anyone can read: what it writes is public at once. Undo puts back the previous revision, if nobody has edited the page since.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(edit)},
			{Name: "restore_revision", Title: "Undo the latest edit", Description: "Puts a page back to the revision before its latest one, only while that latest revision is still the current one. Used by the edits' undo.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["pageid","revision","current"],"properties":{"pageid":{"type":"integer","minimum":1},"revision":{"type":"integer","minimum":1,"description":"The revision to put back"},"current":{"type":"integer","minimum":1,"description":"The revision that must still be the page's latest"}}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) || !strings.HasSuffix(u.Path, "/api.php") {
		return errors.New("the address is the wiki's api.php, like https://wiki.example.com/w/api.php")
	}
	user := strings.TrimSpace(c.Username)
	if !userRe.MatchString(user) {
		return errors.New("the user name is the bot password's login name, like YourName@conduit (see Special:BotPasswords)")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the bot password in the vault and enter its secret:// reference")
	}
	assert := c.Assert
	switch assert {
	case "":
		assert = "user"
	case "user", "bot":
	default:
		return errors.New("assert is user or bot")
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
	hc := rest.SameHostOnly(client)
	hc.Jar, _ = cookiejar.New(nil) // the session lives in cookies
	wait := m.Wait
	if wait == nil {
		wait = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	m.set.Put(id, &conn{http: hc, api: u.Scheme + "://" + u.Host + u.Path, user: user, ref: c.Password, host: h, assert: assert, wait: wait})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// apiError is an error MediaWiki reported.
type apiError struct{ Code, Info string }

func (e *apiError) Error() string {
	switch e.Code {
	case "editconflict":
		return "someone edited the page in the meantime; read it again and redo the change"
	case "assertuserfailed":
		return "MediaWiki says the session isn't signed in"
	case "assertbotfailed":
		return "the account doesn't have the bot right; set assert to user"
	case "permissiondenied", "protectedpage", "cascadeprotected", "protectednamespace":
		return "MediaWiki refused the edit (" + e.Code + "): the bot password's grants or the account's rights don't allow it"
	}
	return "MediaWiki: " + e.Code + ": " + clean(e.Info)
}

// clean redacts a server message, then keeps it to one short line.
func clean(s string) string {
	s = strings.Join(strings.Fields(rest.Redact(s)), " ")
	if r := []rune(s); len(r) > 300 {
		s = string(r[:300]) + "…"
	}
	return s
}

// do sends one API request (a POST when form is set: its token goes last)
// and decodes the answer into out, waiting and retrying while the wiki
// reports maxlag.
func (c *conn) do(ctx context.Context, q url.Values, form url.Values, out any) error {
	q.Set("format", "json")
	q.Set("formatversion", "2")
	q.Set("maxlag", maxLag)
	for try := 1; ; try++ {
		var body io.Reader
		method := http.MethodGet
		u := c.api + "?" + q.Encode()
		if form != nil {
			method = http.MethodPost
			tok := form.Get("token")
			others := url.Values{}
			for k, v := range form {
				if k != "token" {
					others[k] = v
				}
			}
			s := others.Encode()
			if tok != "" {
				s += "&token=" + url.QueryEscape(tok)
			}
			body = strings.NewReader(s)
		}
		req, err := http.NewRequestWithContext(ctx, method, u, body)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "Conduit")
		req.Header.Set("Accept", "application/json")
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		res, err := c.http.Do(req)
		if err != nil {
			return rest.TransportError(err)
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
		res.Body.Close()
		if err != nil {
			return err
		}
		lag := res.Header.Get("MediaWiki-API-Error") == "maxlag"
		var env struct {
			Error *apiError `json:"error"`
		}
		if json.Unmarshal(raw, &env) == nil && env.Error != nil && env.Error.Code == "maxlag" {
			lag = true
		}
		if lag {
			if try >= maxTries {
				return errors.New("the wiki's database is lagging behind (maxlag); try again in a while")
			}
			d := 5 * time.Second
			if n, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && n > 0 {
				d = time.Duration(min(n, 30)) * time.Second
			}
			if err := c.wait(ctx, d); err != nil {
				return err
			}
			continue
		}
		if res.StatusCode >= 300 {
			if res.StatusCode == http.StatusNotFound {
				return &rest.Error{Status: res.StatusCode, Message: "no MediaWiki API at this address"}
			}
			return &rest.Error{Status: res.StatusCode, Message: res.Status}
		}
		if env.Error != nil {
			return env.Error
		}
		if out != nil {
			if err := json.Unmarshal(raw, out); err != nil {
				return errors.New("unexpected answer from the wiki (is this its api.php?)")
			}
		}
		return nil
	}
}

func code(err error) string {
	var e *apiError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// login signs in with the bot password, unless the session already is.
func (c *conn) login(ctx context.Context, again bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loggedIn && !again {
		return nil
	}
	c.loggedIn = false
	pass, err := c.host.Secret(ctx, c.ref)
	if err != nil {
		return err
	}
	if pass == "" || strings.ContainsAny(pass, "\r\n") {
		return errors.New("the bot password is one line")
	}
	var tok struct {
		Query struct {
			Tokens struct {
				LoginToken string `json:"logintoken"`
			} `json:"tokens"`
		} `json:"query"`
	}
	if err := c.do(ctx, url.Values{"action": {"query"}, "meta": {"tokens"}, "type": {"login"}}, nil, &tok); err != nil {
		return err
	}
	if tok.Query.Tokens.LoginToken == "" {
		return errors.New("the wiki gave no login token")
	}
	var res struct {
		Login struct {
			Result string `json:"result"`
		} `json:"login"`
	}
	if err := c.do(ctx, url.Values{"action": {"login"}}, url.Values{"lgname": {c.user}, "lgpassword": {pass}, "lgtoken": {tok.Query.Tokens.LoginToken}}, &res); err != nil {
		return err
	}
	switch res.Login.Result {
	case "Success":
		c.loggedIn = true
		return nil
	case "Aborted":
		return errors.New("MediaWiki refused the login: use a bot password from Special:BotPasswords, not the account's own password")
	}
	return errors.New("MediaWiki refused the bot password")
}

// query sends a signed-in request; when the session has lapsed it signs in
// again once.
func (c *conn) query(ctx context.Context, q url.Values, form url.Values, out any) error {
	if err := c.login(ctx, false); err != nil {
		return err
	}
	q.Set("assert", c.assert)
	err := c.do(ctx, q, form, out)
	if cd := code(err); cd == "assertuserfailed" || cd == "assertbotfailed" || cd == "notloggedin" {
		if err := c.login(ctx, true); err != nil {
			return err
		}
		err = c.do(ctx, q, form, out)
	}
	return err
}

// public says anonymous visitors can read the wiki: the all-users group
// "*" has the read right. Anything unclear counts as public.
func (c *conn) public(ctx context.Context) (bool, error) {
	var si struct {
		Query struct {
			UserGroups []struct {
				Name   string   `json:"name"`
				Rights []string `json:"rights"`
			} `json:"usergroups"`
		} `json:"query"`
	}
	if err := c.query(ctx, url.Values{"action": {"query"}, "meta": {"siteinfo"}, "siprop": {"usergroups"}}, nil, &si); err != nil {
		return true, err
	}
	for _, g := range si.Query.UserGroups {
		if g.Name == "*" {
			for _, r := range g.Rights {
				if r == "read" {
					return true, nil
				}
			}
			return false, nil
		}
	}
	return true, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var info struct {
		Query struct {
			UserInfo struct {
				Name string `json:"name"`
			} `json:"userinfo"`
			General struct {
				SiteName  string `json:"sitename"`
				Generator string `json:"generator"`
			} `json:"general"`
		} `json:"query"`
	}
	if err := c.query(ctx, url.Values{"action": {"query"}, "meta": {"userinfo|siteinfo"}, "siprop": {"general"}}, nil, &info); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + info.Query.UserInfo.Name
	if g := info.Query.General; g.SiteName != "" {
		msg += " · " + g.SiteName
		if g.Generator != "" {
			msg += " (" + g.Generator + ")"
		}
	}
	if pub, err := c.public(ctx); err == nil && pub {
		msg += " · public"
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Title     string  `json:"title"`
	PageID    int     `json:"pageid"`
	Query     string  `json:"query"`
	Namespace *int    `json:"namespace"`
	Limit     int     `json:"limit"`
	MaxChars  int     `json:"maxChars"`
	Text      *string `json:"text"`
	Summary   string  `json:"summary"`
	Minor     bool    `json:"minor"`
	Revision  int     `json:"revision"`
	Current   int     `json:"current"`
}

// pageQuery checks how the input names a page and returns the matching
// query parameter.
func pageQuery(p input) (url.Values, error) {
	t := strings.TrimSpace(p.Title)
	if p.PageID < 0 || (p.PageID > 0) == (t != "") {
		return nil, errors.New("name the page by its title or its page id")
	}
	if p.PageID > 0 {
		return url.Values{"pageids": {strconv.Itoa(p.PageID)}}, nil
	}
	if len(t) > 255 || badTitle.MatchString(t) || strings.HasPrefix(t, ":") {
		return nil, errors.New("that isn't a valid page title")
	}
	return url.Values{"titles": {t}}, nil
}

type revision struct {
	RevID     int    `json:"revid"`
	ParentID  int    `json:"parentid"`
	Timestamp string `json:"timestamp"`
	Size      int    `json:"size"`
	Slots     struct {
		Main struct {
			ContentModel string `json:"contentmodel"`
			Content      string `json:"content"`
			TextHidden   bool   `json:"texthidden"`
			TextMissing  bool   `json:"textmissing"`
		} `json:"main"`
	} `json:"slots"`
}

type pageInfo struct {
	PageID    int        `json:"pageid"`
	NS        int        `json:"ns"`
	Title     string     `json:"title"`
	Missing   bool       `json:"missing"`
	Invalid   bool       `json:"invalid"`
	LastRevID int        `json:"lastrevid"`
	Revisions []revision `json:"revisions"`
}

// get returns the page with its latest revision (its content too, when
// content is set) and the server's time.
func (c *conn) get(ctx context.Context, which url.Values, content bool) (pageInfo, string, error) {
	q := url.Values{"action": {"query"}, "prop": {"revisions|info"}, "rvprop": {"ids|timestamp|size"}, "curtimestamp": {"1"}}
	if content {
		q.Set("rvprop", "ids|timestamp|size|content")
		q.Set("rvslots", "main")
	}
	for k, v := range which {
		q[k] = v
	}
	var res struct {
		CurTimestamp string `json:"curtimestamp"`
		Query        struct {
			Pages []pageInfo `json:"pages"`
		} `json:"query"`
	}
	if err := c.query(ctx, q, nil, &res); err != nil {
		return pageInfo{}, "", err
	}
	if len(res.Query.Pages) == 0 {
		return pageInfo{}, "", errors.New("the wiki returned no page")
	}
	pg := res.Query.Pages[0]
	switch {
	case pg.Invalid:
		return pageInfo{}, "", errors.New("that isn't a valid page title")
	case pg.Missing || pg.PageID == 0 || len(pg.Revisions) == 0:
		return pageInfo{}, "", errors.New("there's no such page (or the account can't read it)")
	}
	if content && (pg.Revisions[0].Slots.Main.TextHidden || pg.Revisions[0].Slots.Main.TextMissing) {
		return pageInfo{}, "", errors.New("the page's latest revision text is hidden")
	}
	return pg, res.CurTimestamp, nil
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
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
	case "search":
		q := strings.TrimSpace(p.Query)
		if q == "" {
			return sdk.Result{}, errors.New("enter what to search for")
		}
		if len(q) > 300 {
			return sdk.Result{}, errors.New("the query is too long (300 characters at most)")
		}
		limit := p.Limit
		if limit <= 0 || limit > 50 {
			limit = 20
		}
		v := url.Values{"action": {"query"}, "list": {"search"}, "srsearch": {q}, "srlimit": {strconv.Itoa(limit)}, "srprop": {"size|wordcount|timestamp"}, "srinfo": {"totalhits"}}
		if p.Namespace != nil {
			if *p.Namespace < 0 || *p.Namespace > 100000 {
				return sdk.Result{}, errors.New("the namespace is a namespace number, like 0")
			}
			v.Set("srnamespace", strconv.Itoa(*p.Namespace))
		}
		var res struct {
			Query struct {
				SearchInfo struct {
					TotalHits int `json:"totalhits"`
				} `json:"searchinfo"`
				Search []struct {
					NS        int    `json:"ns"`
					Title     string `json:"title"`
					PageID    int    `json:"pageid"`
					Size      int    `json:"size"`
					WordCount int    `json:"wordcount"`
					Timestamp string `json:"timestamp"`
				} `json:"search"`
			} `json:"query"`
		}
		if err := c.query(ctx, v, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range res.Query.Search {
			out = append(out, map[string]any{"title": s.Title, "pageid": s.PageID, "namespace": s.NS, "size": s.Size, "words": s.WordCount, "updated": s.Timestamp})
		}
		return sdk.JSON(map[string]any{"total": res.Query.SearchInfo.TotalHits, "results": out})

	case "read_page":
		which, err := pageQuery(p)
		if err != nil {
			return sdk.Result{}, err
		}
		pg, _, err := c.get(ctx, which, true)
		if err != nil {
			return sdk.Result{}, err
		}
		r := pg.Revisions[0]
		n := p.MaxChars
		if n <= 0 || n > 200000 {
			n = 50000
		}
		text, cut := []rune(r.Slots.Main.Content), false
		if len(text) > n {
			text, cut = text[:n], true
		}
		return sdk.JSON(map[string]any{"title": pg.Title, "pageid": pg.PageID, "namespace": pg.NS, "revid": r.RevID, "updated": r.Timestamp, "size": r.Size,
			"contentModel": r.Slots.Main.ContentModel, "chars": len([]rune(r.Slots.Main.Content)), "truncated": cut, "wikitext": string(text)})

	case "edit_page", "edit_public_page":
		which, err := pageQuery(p)
		if err != nil {
			return sdk.Result{}, err
		}
		if p.Text == nil {
			return sdk.Result{}, errors.New("give the new text")
		}
		if len(*p.Text) > maxText {
			return sdk.Result{}, errors.New("the text is too long (1 MiB at most)")
		}
		if len([]rune(p.Summary)) > maxSummary || strings.ContainsAny(p.Summary, "\r\n") {
			return sdk.Result{}, fmt.Errorf("the summary is one line of at most %d characters", maxSummary)
		}
		pub, err := c.public(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		if pub && call.Action == "edit_page" {
			return sdk.Result{}, errors.New("anyone can read this wiki, so an edit is public at once: use edit_public_page, which is destructive")
		}
		pg, start, err := c.get(ctx, which, true)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.apply(ctx, call, pg, start, *p.Text, strings.TrimSpace(p.Summary), p.Minor, "Edit", pub)

	case "restore_revision":
		return c.restore(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// apply previews or makes the edit that replaces pg's latest revision with
// text.
func (c *conn) apply(ctx context.Context, call sdk.Call, pg pageInfo, start, text, summary string, minor bool, verb string, pub bool) (sdk.Result, error) {
	cur := pg.Revisions[0]
	old := cur.Slots.Main.Content
	// MediaWiki drops trailing whitespace when it saves.
	if strings.TrimRight(old, " \t\r\n") == strings.TrimRight(text, " \t\r\n") {
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Nothing to change on %q", pg.Title)}}, nil
		}
		return sdk.JSON(map[string]any{"title": pg.Title, "pageid": pg.PageID, "revid": cur.RevID, "note": "nothing to change: the page already has this text"})
	}
	target := fmt.Sprintf("page %q (revision %d)", pg.Title, cur.RevID)
	if call.DryRun {
		s := fmt.Sprintf("%s %q", verb, pg.Title)
		if pub {
			s += " (anyone can read this wiki)"
		}
		// Never the old text: page content is private, and previews are
		// kept in approvals.
		return sdk.Result{Plan: &sdk.Plan{Summary: s, Changes: []sdk.Change{{Target: target, Op: "update",
			Before: mustJSON(map[string]any{"revid": cur.RevID, "chars": len([]rune(old))}),
			After:  mustJSON(map[string]any{"chars": len([]rune(text)), "summary": summary, "diff": textdiff.Diff(old, text)})}}}}, nil
	}
	var res struct {
		Edit struct {
			Result       string `json:"result"`
			NoChange     bool   `json:"nochange"`
			PageID       int    `json:"pageid"`
			Title        string `json:"title"`
			OldRevID     int    `json:"oldrevid"`
			NewRevID     int    `json:"newrevid"`
			NewTimestamp string `json:"newtimestamp"`
		} `json:"edit"`
	}
	form := url.Values{"pageid": {strconv.Itoa(pg.PageID)}, "text": {text}, "summary": {summary}, "baserevid": {strconv.Itoa(cur.RevID)},
		"basetimestamp": {cur.Timestamp}, "nocreate": {"1"}}
	if start != "" {
		form.Set("starttimestamp", start)
	}
	if minor {
		form.Set("minor", "1")
	}
	if c.assert == "bot" {
		form.Set("bot", "1")
	}
	send := func() error {
		// A fresh CSRF token for each edit.
		var tok struct {
			Query struct {
				Tokens struct {
					CSRF string `json:"csrftoken"`
				} `json:"tokens"`
			} `json:"query"`
		}
		if err := c.query(ctx, url.Values{"action": {"query"}, "meta": {"tokens"}}, nil, &tok); err != nil {
			return err
		}
		if t := tok.Query.Tokens.CSRF; t == "" || t == `+\` {
			return errors.New("the wiki gave no edit token (the session isn't signed in)")
		}
		form.Set("token", tok.Query.Tokens.CSRF)
		return c.query(ctx, url.Values{"action": {"edit"}}, form, &res)
	}
	err := send()
	if code(err) == "badtoken" {
		err = send()
	}
	if err != nil {
		return sdk.Result{}, err
	}
	if res.Edit.Result != "Success" {
		return sdk.Result{}, fmt.Errorf("MediaWiki didn't save the edit (%s)", clean(res.Edit.Result))
	}
	if res.Edit.NoChange {
		return sdk.JSON(map[string]any{"title": pg.Title, "pageid": pg.PageID, "revid": cur.RevID, "note": "nothing to change: the page already has this text"})
	}
	out := map[string]any{"title": pg.Title, "pageid": pg.PageID, "revid": res.Edit.NewRevID, "previous": cur.RevID, "updated": res.Edit.NewTimestamp,
		"diff": textdiff.Diff(old, text)}
	r, err := sdk.JSON(out)
	if res.Edit.NewRevID > 0 && cur.RevID > 0 {
		r.Undo = sdk.UndoWith("restore_revision", map[string]any{"pageid": pg.PageID, "revision": cur.RevID, "current": res.Edit.NewRevID}, fmt.Sprintf("Put %q back to revision %d", pg.Title, cur.RevID))
	}
	return r, err
}

// restore puts a page back to the revision before its latest one, only
// while that latest one is still current.
func (c *conn) restore(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.PageID <= 0 || p.Revision <= 0 || p.Current <= 0 || p.Revision == p.Current {
		return sdk.Result{}, errors.New("give the page id, the revision to put back and the page's current revision")
	}
	pg, start, err := c.get(ctx, url.Values{"pageids": {strconv.Itoa(p.PageID)}}, true)
	if err != nil {
		return sdk.Result{}, err
	}
	cur := pg.Revisions[0]
	if cur.RevID != p.Current {
		return sdk.Result{}, fmt.Errorf("the page was edited again since (its latest revision is %d, not %d); nothing is put back (its history on the wiki has every revision)", cur.RevID, p.Current)
	}
	if cur.ParentID != p.Revision {
		return sdk.Result{}, errors.New("that revision isn't the one before the page's latest; nothing is put back")
	}
	var res struct {
		Query struct {
			Pages []pageInfo `json:"pages"`
		} `json:"query"`
	}
	if err := c.query(ctx, url.Values{"action": {"query"}, "prop": {"revisions"}, "revids": {strconv.Itoa(p.Revision)}, "rvprop": {"ids|content"}, "rvslots": {"main"}}, nil, &res); err != nil {
		return sdk.Result{}, err
	}
	if len(res.Query.Pages) == 0 || res.Query.Pages[0].PageID != pg.PageID || len(res.Query.Pages[0].Revisions) == 0 {
		return sdk.Result{}, errors.New("there's no such revision of this page")
	}
	old := res.Query.Pages[0].Revisions[0].Slots.Main
	if old.TextHidden || old.TextMissing {
		return sdk.Result{}, errors.New("that revision's text is hidden, so it can't be put back")
	}
	if len(old.Content) > maxText {
		return sdk.Result{}, errors.New("that revision is too long to put back here (1 MiB at most)")
	}
	pub, err := c.public(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	return c.apply(ctx, call, pg, start, old.Content, fmt.Sprintf("Undo revision %d", cur.RevID), false, "Put back", pub)
}
