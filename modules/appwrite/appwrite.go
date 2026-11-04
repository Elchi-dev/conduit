// Package appwrite reads an Appwrite project (Appwrite Cloud or self-hosted,
// 1.5 or later) with an API key: databases, collections and their
// attributes, documents, functions and their recent executions, and how many
// users there are. It never changes anything.
//
// Users are only counted: their e-mails, phone numbers and password hashes
// are never read. Functions are decoded field by field, so their environment
// variables are never read, and executions leave out request headers,
// response bodies, logs and errors.
package appwrite

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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/records"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Appwrite project.
type Config struct {
	URL                string `json:"url"`     // default https://cloud.appwrite.io/v1
	Project            string `json:"project"` // project id
	Key                string `json:"key"`     // secret:// API key
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://cloud.appwrite.io/v1 as the default address.
	Base string
}

// New returns the Appwrite module.
func New() *Module { return &Module{} }

const defaultBase = "https://cloud.appwrite.io/v1"

var (
	pathRe  = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	idRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,35}$`)
	fieldRe = regexp.MustCompile(`^\$?[A-Za-z0-9_][A-Za-z0-9_]{0,63}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	db := `"database":{"type":"string","description":"Database id (from databases)"}`
	coll := `"collection":{"type":"string","description":"Collection id (from collections)"}`
	fn := `"function":{"type":"string","description":"Function id (from functions)"}`
	limit := `"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}`
	return sdk.Manifest{
		ID: "appwrite", Name: "Appwrite", Version: "0.1.0", Category: "Development", Icon: "cloud",
		Description: "Appwrite: databases, collections, documents, functions and their executions, and the number of users. Read only.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["project","key"],"properties":{
			"url":{"type":"string","default":"https://cloud.appwrite.io/v1","description":"The API endpoint (Settings, API credentials), e.g. https://fra.cloud.appwrite.io/v1 or https://appwrite.example.com/v1"},
			"project":{"type":"string","description":"The project id"},
			"key":{"type":"string","x-secret":true,"description":"An API key (Overview, Integrations, API keys) with the scopes databases.read, collections.read, documents.read, functions.read, execution.read and users.read"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "databases", Title: "Databases", Description: "The project's databases: id, name, whether they're enabled.", Risk: sdk.RiskRead},
			{Name: "collections", Title: "Collections", Description: "A database's collections with their attributes (key, type, required, array) and whether document security is on.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["database"],"properties":{` + db + `}}`)},
			{Name: "documents", Title: "Documents", Description: "Documents of a collection, with conditions, a sort and pages (at most 100 a page). Documents can hold personal data, so they're kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["database","collection"],"properties":{` + db + `,` + coll + `,` + records.WhereSchema + `,` + records.SortSchema + `,` + limit + `,"page":{"type":"integer","minimum":1,"default":1}}}`)},
			{Name: "functions", Title: "Functions", Description: "Functions: name, runtime, enabled, live, schedule, events, timeout and the active deployment. Never their variables.", Risk: sdk.RiskRead},
			{Name: "executions", Title: "Function executions", Description: "A function's recent executions: when, trigger, status, HTTP status, duration, method and path. Never bodies, headers or logs.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["function"],"properties":{` + fn + `,` + limit + `}}`)},
			{Name: "users_count", Title: "Number of users", Description: "How many users the project has (only the count).", Risk: sdk.RiskRead},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if strings.TrimSpace(c.URL) == "" {
		c.URL = defaultBase
		if m.Base != "" {
			c.URL = m.Base
		}
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is the API endpoint, like https://cloud.appwrite.io/v1")
	}
	c.Project = strings.TrimSpace(c.Project)
	if !idRe.MatchString(c.Project) {
		return errors.New("enter the project id (Settings, Project ID)")
	}
	if !strings.HasPrefix(c.Key, "secret://") {
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
	path := strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(path, "/v1") {
		path += "/v1"
	}
	ref, project := c.Key, c.Project
	api := rest.New(u.Scheme+"://"+u.Host+path, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-Appwrite-Project", project)
		r.Header.Set("X-Appwrite-Key", strings.TrimSpace(k))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Appwrite refused the API key (or it lacks the scope for this)")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the API key isn't allowed to do this in Appwrite")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err)
}

// query encodes one Appwrite query (the JSON form of Appwrite 1.5 and later).
func query(method, attr string, values ...any) string {
	q := map[string]any{"method": method}
	if attr != "" {
		q["attribute"] = attr
	}
	if values != nil {
		q["values"] = values
	}
	b, _ := json.Marshal(q)
	return string(b)
}

var awOps = map[string]string{"eq": "equal", "ne": "notEqual", "gt": "greaterThan", "gte": "greaterThanEqual", "lt": "lessThan", "lte": "lessThanEqual", "contains": "contains"}

// Queries renders checked conditions as Appwrite queries.
func Queries(cs []records.Cond) []string {
	out := []string{}
	for _, c := range cs {
		switch c.Op {
		case "empty":
			out = append(out, query("isNull", c.Field))
		case "notempty":
			out = append(out, query("isNotNull", c.Field))
		default:
			out = append(out, query(awOps[c.Op], c.Field, c.Value))
		}
	}
	return out
}

func checkID(s, what string) (string, error) {
	s = strings.TrimSpace(s)
	if !idRe.MatchString(s) {
		return "", fmt.Errorf("a %s is its id (letters, digits, ., _ and -, at most 36)", what)
	}
	return s, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var page struct {
		Total int `json:"total"`
	}
	if err := c.get(ctx, "/databases", url.Values{"queries[]": {query("limit", "", 1)}}, &page); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Appwrite project with this id at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d databases", page.Total)}
}

type input struct {
	Database   string         `json:"database"`
	Collection string         `json:"collection"`
	Function   string         `json:"function"`
	Where      []records.Cond `json:"where"`
	Sort       string         `json:"sort"`
	Limit      int            `json:"limit"`
	Page       int            `json:"page"`
}

type attribute struct {
	Key      string `json:"key"`
	Type     string `json:"type"`
	Format   string `json:"format"`
	Status   string `json:"status"`
	Required bool   `json:"required"`
	Array    bool   `json:"array"`
}

type collection struct {
	ID               string      `json:"$id"`
	Name             string      `json:"name"`
	Enabled          bool        `json:"enabled"`
	DocumentSecurity bool        `json:"documentSecurity"`
	Attributes       []attribute `json:"attributes"`
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
	case "databases":
		var page struct {
			Total     int `json:"total"`
			Databases []struct {
				ID      string `json:"$id"`
				Name    string `json:"name"`
				Enabled bool   `json:"enabled"`
			} `json:"databases"`
		}
		if err := c.get(ctx, "/databases", url.Values{"queries[]": {query("limit", "", 100)}}, &page); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range page.Databases {
			out = append(out, map[string]any{"id": d.ID, "name": d.Name, "enabled": d.Enabled})
		}
		return sdk.JSON(map[string]any{"total": page.Total, "databases": out})

	case "collections":
		db, err := checkID(p.Database, "database")
		if err != nil {
			return sdk.Result{}, err
		}
		var page struct {
			Total       int          `json:"total"`
			Collections []collection `json:"collections"`
		}
		if err := c.get(ctx, "/databases/"+url.PathEscape(db)+"/collections", url.Values{"queries[]": {query("limit", "", 100)}}, &page); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no database %s", db)
			}
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, col := range page.Collections {
			attrs := []map[string]any{}
			for _, a := range col.Attributes {
				row := map[string]any{"key": a.Key, "type": a.Type, "required": a.Required, "array": a.Array}
				if a.Format != "" {
					row["format"] = a.Format
				}
				if a.Status != "" && a.Status != "available" {
					row["status"] = a.Status
				}
				attrs = append(attrs, row)
			}
			out = append(out, map[string]any{"id": col.ID, "name": col.Name, "enabled": col.Enabled, "documentSecurity": col.DocumentSecurity, "attributes": attrs})
		}
		return sdk.JSON(map[string]any{"database": db, "total": page.Total, "collections": out})

	case "documents":
		return c.documents(ctx, p)

	case "functions":
		var page struct {
			Total     int `json:"total"`
			Functions []struct {
				ID         string   `json:"$id"`
				Name       string   `json:"name"`
				Runtime    string   `json:"runtime"`
				Enabled    bool     `json:"enabled"`
				Live       bool     `json:"live"`
				Schedule   string   `json:"schedule"`
				Events     []string `json:"events"`
				Timeout    int      `json:"timeout"`
				Deployment string   `json:"deployment"`
				UpdatedAt  string   `json:"$updatedAt"`
				// vars aren't decoded: they hold the function's secrets.
			} `json:"functions"`
		}
		if err := c.get(ctx, "/functions", url.Values{"queries[]": {query("limit", "", 100)}}, &page); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, f := range page.Functions {
			row := map[string]any{"id": f.ID, "name": f.Name, "runtime": f.Runtime, "enabled": f.Enabled, "live": f.Live, "timeout": f.Timeout, "deployment": f.Deployment, "updated": f.UpdatedAt}
			if f.Schedule != "" {
				row["schedule"] = f.Schedule
			}
			if len(f.Events) > 0 {
				row["events"] = f.Events
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"total": page.Total, "functions": out})

	case "executions":
		fn, err := checkID(p.Function, "function")
		if err != nil {
			return sdk.Result{}, err
		}
		var page struct {
			Total      int `json:"total"`
			Executions []struct {
				ID         string  `json:"$id"`
				CreatedAt  string  `json:"$createdAt"`
				Trigger    string  `json:"trigger"`
				Status     string  `json:"status"`
				HTTPStatus int     `json:"responseStatusCode"`
				Duration   float64 `json:"duration"`
				Method     string  `json:"requestMethod"`
				Path       string  `json:"requestPath"`
			} `json:"executions"`
		}
		q := url.Values{"queries[]": {query("limit", "", records.Limit(p.Limit, 25, 100)), query("orderDesc", "$createdAt")}}
		if err := c.get(ctx, "/functions/"+url.PathEscape(fn)+"/executions", q, &page); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no function %s", fn)
			}
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, e := range page.Executions {
			path := e.Path
			if i := strings.IndexAny(path, "?#"); i >= 0 {
				path = path[:i] // a query can carry a token
			}
			out = append(out, map[string]any{"id": e.ID, "created": e.CreatedAt, "trigger": e.Trigger, "status": e.Status, "httpStatus": e.HTTPStatus,
				"seconds": e.Duration, "method": e.Method, "path": records.Clip(path)})
		}
		return sdk.JSON(map[string]any{"function": fn, "total": page.Total, "executions": out})

	case "users_count":
		var page struct {
			Total int `json:"total"`
		}
		if err := c.get(ctx, "/users", url.Values{"queries[]": {query("limit", "", 1)}}, &page); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"users": page.Total})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// dropped are document keys left out of every answer: plumbing, not data.
var dropped = []string{"$permissions", "$databaseId", "$collectionId", "$sequence", "$tenant"}

func (c *conn) documents(ctx context.Context, p input) (sdk.Result, error) {
	db, err := checkID(p.Database, "database")
	if err != nil {
		return sdk.Result{}, err
	}
	coll, err := checkID(p.Collection, "collection")
	if err != nil {
		return sdk.Result{}, err
	}
	if err := records.Check(p.Where, fieldRe.MatchString, ""); err != nil {
		return sdk.Result{}, err
	}
	var col collection
	if err := c.get(ctx, "/databases/"+url.PathEscape(db)+"/collections/"+url.PathEscape(coll), nil, &col); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no collection %s in database %s", coll, db)
		}
		return sdk.Result{}, err
	}
	known := map[string]bool{"$id": true, "$createdAt": true, "$updatedAt": true}
	for _, a := range col.Attributes {
		known[a.Key] = true
	}
	has := func(s string) bool { return fieldRe.MatchString(s) && known[s] }
	if err := records.Check(p.Where, has, ""); err != nil {
		return sdk.Result{}, err
	}
	sortBy, desc, err := records.Sort(p.Sort, has)
	if err != nil {
		return sdk.Result{}, err
	}
	limit := records.Limit(p.Limit, 25, 100)
	qs := append(Queries(p.Where), query("limit", "", limit), query("offset", "", (records.Page(p.Page)-1)*limit))
	if sortBy != "" {
		if desc {
			qs = append(qs, query("orderDesc", sortBy))
		} else {
			qs = append(qs, query("orderAsc", sortBy))
		}
	}
	var page struct {
		Total     int              `json:"total"`
		Documents []map[string]any `json:"documents"`
	}
	if err := c.get(ctx, "/databases/"+url.PathEscape(db)+"/collections/"+url.PathEscape(coll)+"/documents", url.Values{"queries[]": qs}, &page); err != nil {
		return sdk.Result{}, err
	}
	rows := []map[string]any{}
	for _, d := range page.Documents {
		for _, k := range dropped {
			delete(d, k)
		}
		rows = append(rows, records.Clip(d).(map[string]any))
	}
	rows, cut := records.Fit(rows)
	out := map[string]any{"database": db, "collection": coll, "total": page.Total, "page": records.Page(p.Page), "documents": rows}
	if cut {
		out["truncated"] = true
	}
	return sdk.JSON(out)
}
