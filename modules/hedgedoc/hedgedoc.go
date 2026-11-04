// Package hedgedoc works with a HedgeDoc server: with HedgeDoc 2 and an API
// token, listing your notes, reading one as Markdown and creating notes;
// with HedgeDoc 1, which has no API tokens, reading notes anyone may view
// and creating notes through its public API.
package hedgedoc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/textdiff"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one HedgeDoc server.
type Config struct {
	URL string `json:"url"` // e.g. https://md.example.com
	// Version is 2 (default; needs Token) or 1 (public API, no token).
	Version            int    `json:"version"`
	Token              string `json:"token"` // secret:// API token (HedgeDoc 2)
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	origin string
	host   string
	v1     bool
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the HedgeDoc module.
func New() *Module { return &Module{} }

const maxContent = 1 << 20 // 1 MiB of Markdown

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// A note id or alias: HedgeDoc 1's base64url ids and short ids,
	// HedgeDoc 2's ids and aliases.
	noteRe = regexp.MustCompile(`^[A-Za-z0-9_~-][A-Za-z0-9_.~-]{0,127}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	note := `{"type":"object","required":["note"],"properties":{"note":{"type":"string","description":"The note's id or alias, or its address"},"maxChars":{"type":"integer","minimum":1,"maximum":200000,"default":50000}}}`
	return sdk.Manifest{
		ID: "hedgedoc", Name: "HedgeDoc", Version: "0.1.0", Category: "Productivity", Icon: "document",
		Description: "HedgeDoc collaborative Markdown notes: list your notes, read one, and create new ones (HedgeDoc 2 with an API token, or HedgeDoc 1's public API).",
		Presets:     []string{"homelab", "team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"HedgeDoc's address, e.g. https://md.example.com"},
			"version":{"type":"integer","enum":[1,2],"default":2,"description":"2: HedgeDoc 2 with an API token. 1: HedgeDoc 1.x through its public API, without a token (reading notes anyone may view, creating anonymous notes)"},
			"token":{"type":"string","x-secret":true,"description":"HedgeDoc 2: an API token from your profile's settings. It acts as you"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "notes", Title: "My notes", Description: "Your notes (HedgeDoc 2): id, alias, title, description, tags and last change. No note text.", Risk: sdk.RiskRead},
			{Name: "read_note", Title: "Read a note", Description: "A note's Markdown with its title, description and dates. Note content is private, so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(note)},
			{Name: "create_note", Title: "Create a note", Description: "A new note with the Markdown given, at a random address. HedgeDoc 2: it belongs to you, with the server's default permissions. HedgeDoc 1: it's anonymous, and anyone who has its address can read and edit it. There's no undo: deleting notes isn't offered here.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["content"],"properties":{"content":{"type":"string","description":"Markdown, 1 MiB at most"}}}`)},
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
		return errors.New("the address is like https://md.example.com")
	}
	switch c.Version {
	case 0:
		c.Version = 2
	case 1, 2:
	default:
		return errors.New("the version is 1 or 2")
	}
	v1 := c.Version == 1
	switch {
	case v1 && c.Token != "":
		return errors.New("HedgeDoc 1 has no API tokens: leave the token empty")
	case !v1 && !strings.HasPrefix(c.Token, "secret://"):
		return errors.New("store the API token in the vault and enter its secret:// reference")
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
	origin := u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/")
	var auth func(context.Context, *http.Request) error
	if !v1 {
		ref := c.Token
		auth = func(ctx context.Context, r *http.Request) error {
			t, err := h.Secret(ctx, ref)
			if err != nil {
				return err
			}
			t = strings.TrimSpace(t)
			if t == "" || strings.ContainsAny(t, " \r\n") {
				return errors.New("the HedgeDoc API token is one line with no spaces")
			}
			r.Header.Set("Authorization", "Bearer "+t)
			return nil
		}
	}
	api := rest.New(origin, auth)
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, origin: origin, host: u.Host, v1: v1})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) explain(err error) error {
	switch {
	case c.v1 && rest.IsStatus(err, http.StatusForbidden):
		return errors.New("HedgeDoc refused: this needs a signed-in user (the note isn't open to guests, or the server doesn't allow anonymous notes)")
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		// HedgeDoc 2 answers 403 to an unknown token as to a missing permission.
		return errors.New("HedgeDoc refused the API token, or it may not do this")
	case rest.IsStatus(err, http.StatusRequestEntityTooLarge):
		return errors.New("the note is larger than the server accepts")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, nil, nil, out)
	return c.explain(err)
}

// text reads a Markdown answer, up to limit bytes (more is an error).
func (c *conn) text(ctx context.Context, path string, limit int64) (string, error) {
	res, err := c.api.Send(ctx, http.MethodGet, path, nil, nil, http.Header{"Accept": {"text/markdown, text/plain"}})
	if err != nil {
		return "", c.explain(err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return "", errors.New("HedgeDoc sent a redirect instead of the note")
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(b)) > limit {
		return "", errors.New("the note is too large to read here")
	}
	return string(b), nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	if c.v1 {
		var st struct {
			NotesCount  *int `json:"notesCount"`
			OnlineUsers int  `json:"onlineUsers"`
		}
		if err := c.get(ctx, "/status", &st); err != nil || st.NotesCount == nil {
			if err == nil || rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Health{Status: "down", Message: "no HedgeDoc 1 at this address"}
			}
			return sdk.Health{Status: "down", Message: err.Error()}
		}
		return sdk.Health{Status: "ok", Message: fmt.Sprintf("HedgeDoc 1 · %d notes · %d online", *st.NotesCount, st.OnlineUsers)}
	}
	var me struct {
		Username    string `json:"username"`
		DisplayName string `json:"displayName"`
	}
	if err := c.get(ctx, "/api/v2/me", &me); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no HedgeDoc 2 API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if me.Username == "" {
		return sdk.Health{Status: "down", Message: "no HedgeDoc 2 API at this address"}
	}
	name := me.Username
	if me.DisplayName != "" {
		name = me.DisplayName + " (" + me.Username + ")"
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + name}
}

type alias struct {
	Name    string `json:"name"`
	Primary bool   `json:"primaryAlias"`
}

type metadata struct {
	ID             any      `json:"id"`
	Aliases        []alias  `json:"aliases"`
	PrimaryAddress string   `json:"primaryAddress"`
	PrimaryAlias   string   `json:"primaryAlias"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Tags           []string `json:"tags"`
	UpdatedAt      string   `json:"updatedAt"`
	CreatedAt      string   `json:"createdAt"`
	ViewCount      int      `json:"viewCount"`
}

// address is how to name the note in a later call.
func (md metadata) address() string {
	for _, a := range md.Aliases {
		if a.Primary && a.Name != "" {
			return a.Name
		}
	}
	for _, s := range []string{md.PrimaryAlias, md.PrimaryAddress} {
		if s != "" {
			return s
		}
	}
	if md.ID != nil {
		return fmt.Sprint(md.ID)
	}
	return ""
}

func (md metadata) summary() map[string]any {
	out := map[string]any{"note": md.address(), "title": md.Title, "updated": md.UpdatedAt}
	if d := strings.TrimSpace(md.Description); d != "" {
		out["description"] = d
	}
	if len(md.Tags) > 0 {
		out["tags"] = md.Tags
	}
	if md.CreatedAt != "" {
		out["created"] = md.CreatedAt
	}
	return out
}

// noteID checks a note id, alias or address before any request.
func (c *conn) noteID(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		u, err := url.Parse(s)
		if err != nil || !strings.EqualFold(u.Host, c.host) || u.User != nil {
			return "", errors.New("that address isn't on this HedgeDoc")
		}
		p := strings.Trim(u.Path, "/")
		if pre := strings.Trim(strings.TrimPrefix(c.origin, u.Scheme+"://"+u.Host), "/"); pre != "" {
			p = strings.Trim(strings.TrimPrefix(p, pre), "/")
		}
		p = strings.TrimPrefix(p, "n/") // HedgeDoc 2's note pages
		s = p
	}
	if !noteRe.MatchString(s) || s == "." || s == ".." || strings.Contains(s, "..") {
		return "", errors.New("the note is its id, alias or address")
	}
	return s, nil
}

type input struct {
	Note     string  `json:"note"`
	MaxChars int     `json:"maxChars"`
	Content  *string `json:"content"`
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
	case "notes":
		if c.v1 {
			return sdk.Result{}, errors.New("listing notes needs HedgeDoc 2: HedgeDoc 1 keeps a user's notes in a history that only a signed-in browser can read")
		}
		var list []metadata
		if err := c.get(ctx, "/api/v2/me/notes", &list); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, md := range list {
			out = append(out, md.summary())
		}
		return sdk.JSON(map[string]any{"total": len(out), "notes": out})

	case "read_note":
		id, err := c.noteID(p.Note)
		if err != nil {
			return sdk.Result{}, err
		}
		n := p.MaxChars
		if n <= 0 || n > 200000 {
			n = 50000
		}
		esc := url.PathEscape(id)
		var out map[string]any
		var body string
		if c.v1 {
			var info struct {
				Title       string `json:"title"`
				Description string `json:"description"`
				ViewCount   int    `json:"viewcount"`
				CreateTime  string `json:"createtime"`
				UpdateTime  string `json:"updatetime"`
			}
			if err := c.get(ctx, "/"+esc+"/info", &info); err != nil {
				if rest.IsStatus(err, http.StatusNotFound) {
					return sdk.Result{}, fmt.Errorf("there's no note %s", id)
				}
				return sdk.Result{}, err
			}
			if body, err = c.text(ctx, "/"+esc+"/download", 8<<20); err != nil {
				return sdk.Result{}, err
			}
			out = map[string]any{"note": id, "title": info.Title, "description": info.Description, "created": info.CreateTime, "updated": info.UpdateTime, "views": info.ViewCount, "url": c.origin + "/" + esc}
		} else {
			var md metadata
			if err := c.get(ctx, "/api/v2/notes/"+esc+"/metadata", &md); err != nil {
				if rest.IsStatus(err, http.StatusNotFound) {
					return sdk.Result{}, fmt.Errorf("there's no note %s (or you can't see it)", id)
				}
				return sdk.Result{}, err
			}
			if body, err = c.text(ctx, "/api/v2/notes/"+esc+"/content", 8<<20); err != nil {
				return sdk.Result{}, err
			}
			out = md.summary()
			out["note"] = id
		}
		text, cut := []rune(body), false
		if len(text) > n {
			text, cut = text[:n], true
		}
		out["chars"], out["truncated"], out["content"] = len([]rune(body)), cut, string(text)
		return sdk.JSON(out)

	case "create_note":
		if p.Content == nil {
			return sdk.Result{}, errors.New("give the note's Markdown")
		}
		if len(*p.Content) > maxContent {
			return sdk.Result{}, errors.New("the note is too long (1 MiB at most)")
		}
		if call.DryRun {
			s := "Create a note"
			if c.v1 {
				s = "Create an anonymous note (anyone with its address can read and edit it)"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: s, Changes: []sdk.Change{{Target: "new note", Op: "create",
				After: mustJSON(map[string]any{"chars": len([]rune(*p.Content)), "diff": textdiff.Diff("", *p.Content)})}}}}, nil
		}
		return c.create(ctx, *p.Content)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (c *conn) create(ctx context.Context, content string) (sdk.Result, error) {
	hdr := http.Header{"Content-Type": {"text/markdown"}}
	if !c.v1 {
		hdr.Set("Accept", "application/json")
		res, err := c.api.Send(ctx, http.MethodPost, "/api/v2/notes", nil, strings.NewReader(content), hdr)
		if err != nil {
			return sdk.Result{}, c.explain(err)
		}
		defer res.Body.Close()
		var dto struct {
			Metadata metadata `json:"metadata"`
		}
		if err := json.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(&dto); err != nil || res.StatusCode >= 300 {
			return sdk.Result{}, errors.New("unexpected answer from HedgeDoc")
		}
		return sdk.JSON(dto.Metadata.summary())
	}
	// HedgeDoc 1 answers with a redirect to the new note: read where it
	// points instead of following it.
	nc := *c.api
	hc := *c.api.HTTP
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	nc.HTTP = &hc
	res, err := nc.Send(ctx, http.MethodPost, "/new", nil, strings.NewReader(content), hdr)
	if err != nil {
		return sdk.Result{}, c.explain(err)
	}
	res.Body.Close()
	loc, err := url.Parse(res.Header.Get("Location"))
	if res.StatusCode < 300 || res.StatusCode >= 400 || err != nil {
		return sdk.Result{}, errors.New("HedgeDoc didn't say where the new note is")
	}
	id := loc.Path[strings.LastIndexByte(loc.Path, '/')+1:]
	if !noteRe.MatchString(id) {
		return sdk.Result{}, errors.New("HedgeDoc didn't say where the new note is")
	}
	return sdk.JSON(map[string]any{"note": id, "url": c.origin + "/" + url.PathEscape(id),
		"access": "anonymous: anyone who has the address can read and edit it"})
}
