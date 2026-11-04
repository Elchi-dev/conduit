// Package onepassword works with a 1Password Connect server through its REST
// API: the server's health, the vaults the Connect token can use, items with
// their titles, categories, tags and field labels (never values), and the
// values of named fields only through the destructive reveal_field. It never
// creates, edits or deletes items, and never touches access (tokens, vault
// grants): Connect tokens are managed in 1Password itself.
package onepassword

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one 1Password Connect server.
type Config struct {
	URL                string `json:"url"`   // e.g. http://localhost:8080
	Token              string `json:"token"` // secret:// Connect access token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the 1Password Connect module.
func New() *Module { return &Module{} }

const (
	maxReveal = 10
	maxItems  = 1000
)

// idRe matches 1Password's 26-character vault, item and field ids.
var idRe = regexp.MustCompile(`^[a-z0-9]{26}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	vault := `"vault":{"type":"string","description":"Vault name or id"}`
	item := `"item":{"type":"string","description":"Item title or id"}`
	return sdk.Manifest{
		ID: "onepassword", Name: "1Password Connect", Version: "0.1.0", Category: "Security", Icon: "key",
		Description: "1Password through a Connect server: health, vaults, item titles, categories and field labels (never values), revealing named fields (destructive).",
		Presets:     []string{"homelab", "developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The Connect server, e.g. http://localhost:8080"},
			"token":{"type":"string","x-secret":true,"description":"Connect access token. Grant it read on only the vaults Conduit should see"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "health", Title: "Connect server health", Description: "The Connect server's name, version and the state of its sync and database dependencies.", Risk: sdk.RiskRead},
			{Name: "vaults", Title: "Vaults", Description: "The vaults the Connect token can read: name, id, description, type, item count and dates.", Risk: sdk.RiskRead},
			{Name: "items", Title: "Items", Description: "Items in a vault: title, id, category, tags, favorite, version, state, dates and the hosts of their URLs. Never field values.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["vault"],"properties":{` + vault + `,"title":{"type":"string","description":"Only items with exactly this title"}}}`)},
			{Name: "item", Title: "Item details", Description: "One item's metadata: category, tags, sections, and each field's label, id, type, purpose and section, file names and sizes. Never values: reveal_field returns those.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["vault","item"],"properties":{` + vault + `,` + item + `}}`)},
			{Name: "reveal_field", Title: "Reveal field values", Description: "The values of the named fields (labels or field ids, up to 10) of one item, and only those. Revealing a credential is destructive: it can't be taken back.", Risk: sdk.RiskDestructive, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["vault","item","fields"],"properties":{` + vault + `,` + item + `,"fields":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":10,"description":"Field labels or ids whose values to return"}}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the URL is the Connect server, like http://localhost:8080")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the Connect token in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		client = sdk.HTTPClient(h, 30*time.Second)
		client.Transport.(*http.Transport).TLSClientConfig = tc
	}
	tok := c.Token
	base := u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/")
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case err == nil:
		return nil
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("1Password Connect refused the token (expired, revoked or for another server)")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("the Connect token has no access to %s", what)
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	}
	return err
}

type serverHealth struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Dependencies []struct {
		Service string `json:"service"`
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"dependencies"`
}

type vaultInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Items       int    `json:"items"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

type urlInfo struct {
	Href    string `json:"href"`
	Primary bool   `json:"primary"`
}

type itemSummary struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Category  string    `json:"category"`
	Tags      []string  `json:"tags"`
	Favorite  bool      `json:"favorite"`
	Version   int       `json:"version"`
	State     string    `json:"state"`
	URLs      []urlInfo `json:"urls"`
	CreatedAt string    `json:"createdAt"`
	UpdatedAt string    `json:"updatedAt"`
	EditedBy  string    `json:"lastEditedBy"`
}

type field struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Type    string `json:"type"`
	Purpose string `json:"purpose"`
	Value   string `json:"value"`
	Section *struct {
		ID string `json:"id"`
	} `json:"section"`
}

type fullItem struct {
	itemSummary
	Sections []struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	} `json:"sections"`
	Fields []field `json:"fields"`
	Files  []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Size    int64  `json:"size"`
		Section *struct {
			ID string `json:"id"`
		} `json:"section"`
	} `json:"files"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var hs serverHealth
	if _, err := c.api.Do(ctx, http.MethodGet, "/health", nil, nil, &hs); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var vs []vaultInfo
	if _, err := c.api.Do(ctx, http.MethodGet, "/v1/vaults", nil, nil, &vs); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Health{Status: "down", Message: "1Password Connect refused the token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("%d vault(s)", len(vs))
	if hs.Version != "" {
		msg = "Connect " + hs.Version + " · " + msg
	}
	for _, d := range hs.Dependencies {
		if d.Status != "" && !strings.EqualFold(d.Status, "ACTIVE") {
			return sdk.Health{Status: "degraded", Message: msg + " · " + d.Service + " is " + strings.ToLower(d.Status)}
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Vault  string   `json:"vault"`
	Item   string   `json:"item"`
	Title  string   `json:"title"`
	Fields []string `json:"fields"`
}

// validName accepts a vault name or item title that can go in a filter.
func validName(s string) bool {
	return s != "" && len(s) <= 512 && utf8.ValidString(s) && !strings.ContainsAny(s, `"\`) &&
		!strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func (c *conn) vaults(ctx context.Context) ([]vaultInfo, error) {
	var vs []vaultInfo
	if _, err := c.api.Do(ctx, http.MethodGet, "/v1/vaults", nil, nil, &vs); err != nil {
		return nil, friendly(err, "vault list")
	}
	return vs, nil
}

// vault resolves a vault name or id to its id and name.
func (c *conn) vault(ctx context.Context, s string) (string, string, error) {
	s = strings.TrimSpace(s)
	if !validName(s) {
		return "", "", errors.New("name the vault (its name or id; see vaults)")
	}
	vs, err := c.vaults(ctx)
	if err != nil {
		return "", "", err
	}
	var folded []vaultInfo
	for _, v := range vs {
		if v.ID == s || v.Name == s {
			return v.ID, v.Name, nil
		}
		if strings.EqualFold(v.Name, s) {
			folded = append(folded, v)
		}
	}
	if len(folded) == 1 {
		return folded[0].ID, folded[0].Name, nil
	}
	if len(folded) > 1 {
		return "", "", fmt.Errorf("more than one vault is called %q; give its id", s)
	}
	return "", "", fmt.Errorf("there's no vault %q the Connect token can read", s)
}

func (c *conn) items(ctx context.Context, vaultID, title string) ([]itemSummary, error) {
	var q url.Values
	if title != "" {
		q = url.Values{"filter": {`title eq "` + title + `"`}}
	}
	var out []itemSummary
	if _, err := c.api.Do(ctx, http.MethodGet, "/v1/vaults/"+vaultID+"/items", q, nil, &out); err != nil {
		return nil, friendly(err, "vault "+vaultID)
	}
	return out, nil
}

// item resolves an item title or id in a vault and returns the full item.
func (c *conn) item(ctx context.Context, vaultID, s string) (fullItem, error) {
	s = strings.TrimSpace(s)
	if !validName(s) {
		return fullItem{}, errors.New("name the item (its title or id; see items)")
	}
	id := s
	if !idRe.MatchString(s) {
		list, err := c.items(ctx, vaultID, s)
		if err != nil {
			return fullItem{}, err
		}
		var match []string
		for _, it := range list {
			if it.Title == s {
				match = append(match, it.ID)
			}
		}
		switch len(match) {
		case 0:
			return fullItem{}, fmt.Errorf("there's no item %q in that vault", s)
		case 1:
			id = match[0]
		default:
			return fullItem{}, fmt.Errorf("%d items are called %q; give the id of one: %s", len(match), s, strings.Join(match, ", "))
		}
	}
	var it fullItem
	if _, err := c.api.Do(ctx, http.MethodGet, "/v1/vaults/"+vaultID+"/items/"+id, nil, nil, &it); err != nil {
		return fullItem{}, friendly(err, "item "+s)
	}
	return it, nil
}

// hosts returns the hosts of an item's URLs: a URL can carry a token in its
// path, query or user info, so only the host leaves the module, and only
// when it has a dot and is a host name.
func hosts(us []urlInfo) []string {
	out := []string{}
	for _, u := range us {
		p, err := url.Parse(strings.TrimSpace(u.Href))
		h := ""
		if err == nil {
			h = p.Hostname()
		}
		if h == "" && err == nil && p.Scheme == "" {
			// "example.com/login" without a scheme.
			if q, err := url.Parse("https://" + strings.TrimSpace(u.Href)); err == nil {
				h = q.Hostname()
			}
		}
		if h = strings.TrimSuffix(h, "."); hostNameRe.MatchString(h) && len(h) <= 253 {
			out = append(out, h)
		}
	}
	return out
}

// hostNameRe is a host name of two or more labels (or an IPv4 address).
// Anything else a URL field holds (an otpauth:// secret's "totp", a bare
// word or a password typed into the field) isn't output.
var hostNameRe = regexp.MustCompile(`^(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?$`)

func summary(it itemSummary) map[string]any {
	e := map[string]any{"id": it.ID, "title": it.Title, "category": it.Category, "version": it.Version, "created": it.CreatedAt, "updated": it.UpdatedAt}
	if len(it.Tags) > 0 {
		e["tags"] = it.Tags
	}
	if it.Favorite {
		e["favorite"] = true
	}
	if it.State != "" {
		e["state"] = it.State
	}
	if h := hosts(it.URLs); len(h) > 0 {
		e["urlHosts"] = h
	}
	return e
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
	case "health":
		var hs serverHealth
		if _, err := c.api.Do(ctx, http.MethodGet, "/health", nil, nil, &hs); err != nil {
			return sdk.Result{}, err
		}
		deps := []map[string]any{}
		for _, d := range hs.Dependencies {
			deps = append(deps, map[string]any{"service": d.Service, "status": d.Status, "message": rest.Redact(d.Message)})
		}
		return sdk.JSON(map[string]any{"name": hs.Name, "version": hs.Version, "dependencies": deps})

	case "vaults":
		vs, err := c.vaults(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, v := range vs {
			list = append(list, map[string]any{"id": v.ID, "name": v.Name, "description": v.Description, "type": v.Type, "items": v.Items, "created": v.CreatedAt, "updated": v.UpdatedAt})
		}
		sort.Slice(list, func(i, j int) bool { return list[i]["name"].(string) < list[j]["name"].(string) })
		return sdk.JSON(map[string]any{"vaults": list})

	case "items":
		title := strings.TrimSpace(p.Title)
		if title != "" && !validName(title) {
			return sdk.Result{}, errors.New("the title can't hold quotes, backslashes or control characters")
		}
		vid, vname, err := c.vault(ctx, p.Vault)
		if err != nil {
			return sdk.Result{}, err
		}
		list, err := c.items(ctx, vid, title)
		if err != nil {
			return sdk.Result{}, err
		}
		sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i].Title) < strings.ToLower(list[j].Title) })
		out := []map[string]any{}
		for i, it := range list {
			if i == maxItems {
				break
			}
			out = append(out, summary(it))
		}
		res := map[string]any{"vault": vname, "vaultId": vid, "count": len(list), "items": out}
		if len(list) > maxItems {
			res["truncated"] = true
		}
		return sdk.JSON(res)

	case "item":
		vid, vname, err := c.vault(ctx, p.Vault)
		if err != nil {
			return sdk.Result{}, err
		}
		it, err := c.item(ctx, vid, p.Item)
		if err != nil {
			return sdk.Result{}, err
		}
		sections := map[string]string{}
		secList := []map[string]any{}
		for _, s := range it.Sections {
			sections[s.ID] = s.Label
			secList = append(secList, map[string]any{"id": s.ID, "label": s.Label})
		}
		fields := []map[string]any{}
		for _, f := range it.Fields {
			e := map[string]any{"id": f.ID, "label": f.Label, "type": f.Type}
			if f.Purpose != "" {
				e["purpose"] = f.Purpose
			}
			if f.Section != nil && f.Section.ID != "" {
				e["section"] = sections[f.Section.ID]
			}
			if f.Value == "" {
				e["empty"] = true
			}
			fields = append(fields, e)
		}
		files := []map[string]any{}
		for _, f := range it.Files {
			files = append(files, map[string]any{"id": f.ID, "name": f.Name, "size": f.Size})
		}
		out := summary(it.itemSummary)
		out["vault"] = vname
		out["sections"] = secList
		out["fields"] = fields
		out["files"] = files
		if it.EditedBy != "" {
			out["lastEditedBy"] = it.EditedBy
		}
		return sdk.JSON(out)

	case "reveal_field":
		if len(p.Fields) == 0 {
			return sdk.Result{}, errors.New("name the fields whose values to reveal (item lists their labels)")
		}
		if len(p.Fields) > maxReveal {
			return sdk.Result{}, fmt.Errorf("reveal up to %d fields at a time", maxReveal)
		}
		for _, f := range p.Fields {
			if !validName(f) {
				return sdk.Result{}, fmt.Errorf("%q isn't a field label", f)
			}
		}
		if !validName(strings.TrimSpace(p.Item)) {
			return sdk.Result{}, errors.New("name the item (its title or id; see items)")
		}
		vid, vname, err := c.vault(ctx, p.Vault)
		if err != nil {
			return sdk.Result{}, err
		}
		it, err := c.item(ctx, vid, p.Item)
		if err != nil {
			return sdk.Result{}, err
		}
		vals := map[string]string{}
		var missing []string
		for _, want := range p.Fields {
			var hit []field
			for _, f := range it.Fields {
				if f.ID == want {
					hit = []field{f}
					break
				}
				if f.Label == want {
					hit = append(hit, f)
				}
			}
			switch len(hit) {
			case 0:
				missing = append(missing, want)
			case 1:
				vals[want] = hit[0].Value
			default:
				ids := make([]string, len(hit))
				for i, f := range hit {
					ids[i] = f.ID
				}
				return sdk.Result{}, fmt.Errorf("%d fields are labelled %q; give the id of one: %s", len(hit), want, strings.Join(ids, ", "))
			}
		}
		out := map[string]any{"vault": vname, "item": it.Title, "itemId": it.ID, "values": vals}
		if len(missing) > 0 {
			out["missing"] = missing
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
