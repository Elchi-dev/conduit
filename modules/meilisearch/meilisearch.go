// Package meilisearch looks into a Meilisearch server: health, indexes
// with their stats, searching an index, recent and failed tasks, API keys
// (never their values), and deleting an index.
package meilisearch

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

// Config is one Meilisearch server.
type Config struct {
	URL                string `json:"url"`    // e.g. https://search.example.com
	APIKey             string `json:"apiKey"` // secret://, master, admin or search key
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

// New returns the Meilisearch module.
func New() *Module { return &Module{} }

// Limits.
const (
	MaxHits  = 100
	maxQuery = 1024
)

var (
	uidRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,400}$`)
	attrRe   = regexp.MustCompile(`^[A-Za-z0-9_.*-]{1,256}$`)
	sortRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,256}:(asc|desc)$`)
	statuses = map[string]bool{"enqueued": true, "processing": true, "succeeded": true, "failed": true, "canceled": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	index := `"index":{"type":"string","description":"Index uid"}`
	return sdk.Manifest{
		ID: "meilisearch", Name: "Meilisearch", Version: "0.1.0", Category: "Development", Icon: "search",
		Description: "Meilisearch: health, indexes with stats, searching, recent and failed tasks, API keys (never their values), deleting an index.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"e.g. https://search.example.com or http://localhost:7700"},
			"apiKey":{"type":"string","x-secret":true,"description":"The master key or an admin key for everything; a search key only allows searching"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "health", Title: "Health", Description: "Status, version and database size.", Risk: sdk.RiskRead},
			{Name: "indexes", Title: "Indexes", Description: "Indexes with primary key, documents, whether they're indexing, and dates, at most 100.", Risk: sdk.RiskRead},
			{Name: "search", Title: "Search an index", Description: "Search one index, at most 100 hits. Documents can hold personal data, so results stay out of the audit log.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["index"],"properties":{` + index + `,
					"q":{"type":"string","description":"Search words"},
					"filter":{"type":"string","description":"Filter expression, e.g. genre = horror AND year > 2000"},
					"sort":{"type":"array","items":{"type":"string"},"description":"e.g. [\"year:desc\"]"},
					"attributes":{"type":"array","items":{"type":"string"},"description":"Fields to return"},
					"limit":{"type":"integer","minimum":1,"maximum":100,"default":20},
					"offset":{"type":"integer","minimum":0}}}`)},
			{Name: "tasks", Title: "Tasks", Description: "Recent tasks (or only failed ones) with type, status, index, duration and error. Errors can quote documents, so they stay out of the audit log.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["enqueued","processing","succeeded","failed","canceled"]},` + index + `,"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
			{Name: "keys", Title: "API keys", Description: "API keys by uid and name with their actions, indexes and expiry. Never the key values.", Risk: sdk.RiskRead},
			{Name: "delete_index", Title: "Delete an index", Description: "Deletes an index with all its documents and settings. The preview shows how many documents it holds. There's no undo.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["index"],"properties":{` + index + `}}`)},
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
		return errors.New("the url is like https://search.example.com")
	}
	if c.APIKey != "" && !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
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
	key := c.APIKey
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/"), func(ctx context.Context, r *http.Request) error {
		if key == "" {
			return nil
		}
		k, err := h.Secret(ctx, key)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k))
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
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Meilisearch refused: an API key is needed")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Meilisearch refused the API key (or it doesn't allow this)")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any, what string) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err, what)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var h struct {
		Status string `json:"status"`
	}
	if err := c.do(ctx, http.MethodGet, "/health", nil, nil, &h, "health endpoint"); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if h.Status != "available" {
		return sdk.Health{Status: "down", Message: "Meilisearch says " + h.Status}
	}
	// /health needs no key; /version checks it (a search key can't read it).
	var v struct {
		PkgVersion string `json:"pkgVersion"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/version", nil, nil, &v); err != nil {
		if rest.IsStatus(err, http.StatusForbidden) {
			// Meilisearch answers a wrong key and a key without this
			// permission (a search key) the same way.
			return sdk.Health{Status: "degraded", Message: "available, but the key was refused for /version (a search-only key, or a wrong one)"}
		}
		return sdk.Health{Status: "down", Message: friendly(err, "version endpoint").Error()}
	}
	return sdk.Health{Status: "ok", Message: "Meilisearch " + v.PkgVersion}
}

type input struct {
	Index      string   `json:"index"`
	Q          string   `json:"q"`
	Filter     string   `json:"filter"`
	Sort       []string `json:"sort"`
	Attributes []string `json:"attributes"`
	Limit      *int     `json:"limit"`
	Offset     int      `json:"offset"`
	Status     string   `json:"status"`
}

type indexStats struct {
	NumberOfDocuments int64 `json:"numberOfDocuments"`
	IsIndexing        bool  `json:"isIndexing"`
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
	p.Index = strings.TrimSpace(p.Index)
	switch call.Action {
	case "search", "delete_index":
		if !uidRe.MatchString(p.Index) {
			return sdk.Result{}, errors.New("give an index uid (letters, digits, - and _)")
		}
	case "tasks":
		if p.Index != "" && !uidRe.MatchString(p.Index) {
			return sdk.Result{}, errors.New("the index is a uid (letters, digits, - and _)")
		}
	}
	switch call.Action {
	case "health":
		var h struct {
			Status string `json:"status"`
		}
		if err := c.do(ctx, http.MethodGet, "/health", nil, nil, &h, "health endpoint"); err != nil {
			return sdk.Result{}, err
		}
		var v struct {
			PkgVersion string `json:"pkgVersion"`
		}
		var st struct {
			DatabaseSize int64  `json:"databaseSize"`
			LastUpdate   string `json:"lastUpdate"`
		}
		out := map[string]any{"status": h.Status}
		if c.do(ctx, http.MethodGet, "/version", nil, nil, &v, "") == nil {
			out["version"] = v.PkgVersion
		}
		if c.do(ctx, http.MethodGet, "/stats", nil, nil, &st, "") == nil {
			out["databaseBytes"], out["lastUpdate"] = st.DatabaseSize, st.LastUpdate
		}
		return sdk.JSON(out)
	case "indexes":
		var r struct {
			Results []struct {
				UID        string `json:"uid"`
				PrimaryKey string `json:"primaryKey"`
				CreatedAt  string `json:"createdAt"`
				UpdatedAt  string `json:"updatedAt"`
			} `json:"results"`
			Total int `json:"total"`
		}
		if err := c.do(ctx, http.MethodGet, "/indexes", url.Values{"limit": {"100"}}, nil, &r, "indexes"); err != nil {
			return sdk.Result{}, err
		}
		var st struct {
			Indexes map[string]indexStats `json:"indexes"`
		}
		_ = c.do(ctx, http.MethodGet, "/stats", nil, nil, &st, "stats") // a key without stats.get still lists
		out := []map[string]any{}
		for _, ix := range r.Results {
			e := map[string]any{"uid": ix.UID, "primaryKey": ix.PrimaryKey, "createdAt": ix.CreatedAt, "updatedAt": ix.UpdatedAt}
			if s, ok := st.Indexes[ix.UID]; ok {
				e["documents"], e["isIndexing"] = s.NumberOfDocuments, s.IsIndexing
			}
			out = append(out, e)
		}
		return sdk.JSON(out)
	case "search":
		body, err := SearchBody(p)
		if err != nil {
			return sdk.Result{}, err
		}
		var r struct {
			Hits               []json.RawMessage `json:"hits"`
			EstimatedTotalHits *int64            `json:"estimatedTotalHits"`
			ProcessingTimeMs   int               `json:"processingTimeMs"`
			Query              string            `json:"query"`
		}
		if err := c.do(ctx, http.MethodPost, "/indexes/"+p.Index+"/search", nil, body, &r, "index "+p.Index); err != nil {
			return sdk.Result{}, err
		}
		if r.Hits == nil {
			r.Hits = []json.RawMessage{}
		}
		return sdk.JSON(map[string]any{"hits": r.Hits, "estimatedTotalHits": r.EstimatedTotalHits, "processingTimeMs": r.ProcessingTimeMs})
	case "tasks":
		limit := 20
		if p.Limit != nil {
			limit = *p.Limit
		}
		if limit < 1 || limit > 100 {
			return sdk.Result{}, errors.New("limit is 1 to 100")
		}
		q := url.Values{"limit": {strconv.Itoa(limit)}}
		if p.Status != "" {
			if !statuses[p.Status] {
				return sdk.Result{}, errors.New("status is enqueued, processing, succeeded, failed or canceled")
			}
			q.Set("statuses", p.Status)
		}
		if p.Index != "" {
			q.Set("indexUids", p.Index)
		}
		var r struct {
			Results []struct {
				UID        int64   `json:"uid"`
				IndexUID   *string `json:"indexUid"`
				Status     string  `json:"status"`
				Type       string  `json:"type"`
				Duration   *string `json:"duration"`
				EnqueuedAt string  `json:"enqueuedAt"`
				FinishedAt *string `json:"finishedAt"`
				Error      *struct {
					Message string `json:"message"`
					Code    string `json:"code"`
				} `json:"error"`
			} `json:"results"`
		}
		if err := c.do(ctx, http.MethodGet, "/tasks", q, nil, &r, "tasks"); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, t := range r.Results {
			e := map[string]any{"uid": t.UID, "index": t.IndexUID, "status": t.Status, "type": t.Type, "duration": t.Duration, "enqueuedAt": t.EnqueuedAt, "finishedAt": t.FinishedAt}
			if t.Error != nil {
				e["error"] = clip(rest.Redact(t.Error.Message), 300)
				e["errorCode"] = t.Error.Code
			}
			out = append(out, e)
		}
		return sdk.JSON(out)
	case "keys":
		var r struct {
			Results []struct {
				UID         string   `json:"uid"`
				Name        *string  `json:"name"`
				Description *string  `json:"description"`
				Actions     []string `json:"actions"`
				Indexes     []string `json:"indexes"`
				ExpiresAt   *string  `json:"expiresAt"`
				CreatedAt   string   `json:"createdAt"`
				UpdatedAt   string   `json:"updatedAt"`
				// Key is never decoded: the value doesn't leave this function.
			} `json:"results"`
		}
		if err := c.do(ctx, http.MethodGet, "/keys", url.Values{"limit": {"100"}}, nil, &r, "keys"); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, k := range r.Results {
			out = append(out, map[string]any{"uid": k.UID, "name": k.Name, "description": k.Description, "actions": k.Actions, "indexes": k.Indexes, "expiresAt": k.ExpiresAt, "createdAt": k.CreatedAt, "updatedAt": k.UpdatedAt})
		}
		return sdk.JSON(out)
	case "delete_index":
		var ix struct {
			UID        string `json:"uid"`
			PrimaryKey string `json:"primaryKey"`
		}
		if err := c.do(ctx, http.MethodGet, "/indexes/"+p.Index, nil, nil, &ix, "index "+p.Index); err != nil {
			return sdk.Result{}, err
		}
		var st indexStats
		if err := c.do(ctx, http.MethodGet, "/indexes/"+p.Index+"/stats", nil, nil, &st, "index "+p.Index); err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			before, _ := json.Marshal(map[string]any{"uid": ix.UID, "documents": st.NumberOfDocuments, "primaryKey": ix.PrimaryKey})
			return sdk.Result{Plan: &sdk.Plan{
				Summary: fmt.Sprintf("Delete index %s with its %d documents and settings. They're gone for good: there's no undo.", ix.UID, st.NumberOfDocuments),
				Changes: []sdk.Change{{Target: "index " + ix.UID, Op: "delete", Before: before}},
			}}, nil
		}
		var task struct {
			TaskUID int64  `json:"taskUid"`
			Status  string `json:"status"`
		}
		if err := c.do(ctx, http.MethodDelete, "/indexes/"+p.Index, nil, nil, &task, "index "+p.Index); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"index": ix.UID, "documents": st.NumberOfDocuments, "taskUid": task.TaskUID, "status": task.Status})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// SearchBody checks a search's parameters and builds its body, with the
// limit capped.
func SearchBody(p input) (map[string]any, error) {
	limit := 20
	if p.Limit != nil {
		limit = *p.Limit
	}
	if limit < 1 || limit > MaxHits {
		return nil, fmt.Errorf("limit is 1 to %d", MaxHits)
	}
	if p.Offset < 0 || p.Offset > 10000 {
		return nil, errors.New("offset is 0 to 10000")
	}
	if len(p.Q) > maxQuery || len(p.Filter) > 4*maxQuery {
		return nil, errors.New("the query or filter is too long")
	}
	body := map[string]any{"q": p.Q, "limit": limit, "offset": p.Offset}
	if f := strings.TrimSpace(p.Filter); f != "" {
		body["filter"] = f
	}
	if len(p.Sort) > 10 || len(p.Attributes) > 50 {
		return nil, errors.New("at most 10 sort rules and 50 attributes")
	}
	for _, s := range p.Sort {
		if !sortRe.MatchString(s) {
			return nil, fmt.Errorf("%q isn't a sort rule like year:desc", s)
		}
	}
	for _, a := range p.Attributes {
		if !attrRe.MatchString(a) {
			return nil, fmt.Errorf("%q isn't an attribute name", a)
		}
	}
	if len(p.Sort) > 0 {
		body["sort"] = p.Sort
	}
	if len(p.Attributes) > 0 {
		body["attributesToRetrieve"] = p.Attributes
	}
	return body, nil
}

func clip(s string, k int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > k {
		return string(r[:k]) + "…"
	}
	return string(r)
}
