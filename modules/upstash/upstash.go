// Package upstash reads an Upstash account through the Developer API with
// the account email and a management API key: Redis databases with their
// plan, regions and state, and a database's usage (keys, storage,
// requests, bandwidth, connections, cost this month).
//
// Upstash puts each database's password and REST tokens in its answers.
// They are decoded field by field, so passwords, tokens and connection
// strings are never read, let alone returned.
package upstash

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Upstash account.
type Config struct {
	Email string `json:"email"` // the account's email address
	Key   string `json:"key"`   // secret:// management API key
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.upstash.com (tests).
	Base string
}

// New returns the Upstash module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.upstash.com"

var (
	idRe  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	keyRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "upstash", Name: "Upstash", Version: "0.1.0", Category: "Development", Icon: "database",
		Description: "Upstash Redis databases: plan, regions, state, and usage (keys, storage, requests, bandwidth, cost). Never passwords or tokens.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["email","key"],"properties":{
			"email":{"type":"string","description":"The Upstash account's email address"},
			"key":{"type":"string","x-secret":true,"description":"A management API key (Console, Account, Management API); a read-only key is enough"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "redis_databases", Title: "Redis databases", Description: "Every Redis database: name, id, plan, primary and read regions, state, endpoint host and port, TLS, eviction and monthly budget.", Risk: sdk.RiskRead},
			{Name: "redis_stats", Title: "Redis usage", Description: "One database's keys, storage, connections, requests (reads and writes) and bandwidth this month, cost this month, and daily requests.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["database"],"properties":{"database":{"type":"string","description":"Database id, a UUID (see redis_databases)"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	email := strings.TrimSpace(c.Email)
	if a, err := mail.ParseAddress(email); err != nil || a.Address != email || strings.ContainsAny(email, ":") {
		return errors.New("the email is the Upstash account's address, like you@example.com")
	}
	if !strings.HasPrefix(c.Key, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	ref := c.Key
	api := rest.New(base+"/v2", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		k = strings.TrimSpace(k)
		if !keyRe.MatchString(k) {
			return errors.New("the stored key doesn't look like an Upstash API key")
		}
		r.SetBasicAuth(email, k)
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Upstash refused the email and API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the API key isn't allowed to do this in Upstash")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, nil, nil, out)
	return friendly(err)
}

// redis is the whitelist of a database's fields: password, rest_token,
// read_only_rest_token and the like are left out on purpose.
type redis struct {
	ID            string   `json:"database_id"`
	Name          string   `json:"database_name"`
	Type          string   `json:"type"`
	DatabaseType  string   `json:"database_type"`
	Region        string   `json:"region"`
	PrimaryRegion string   `json:"primary_region"`
	ReadRegions   []string `json:"read_regions"`
	State         string   `json:"state"`
	Endpoint      string   `json:"endpoint"`
	Port          int      `json:"port"`
	TLS           bool     `json:"tls"`
	Eviction      bool     `json:"eviction"`
	Budget        float64  `json:"budget"`
	CreationTime  int64    `json:"creation_time"`
}

func redisOut(d redis) map[string]any {
	plan := d.Type
	if plan == "" {
		plan = d.DatabaseType
	}
	region := d.PrimaryRegion
	if region == "" {
		region = d.Region
	}
	row := map[string]any{"id": d.ID, "name": d.Name, "plan": plan, "primaryRegion": region, "state": d.State, "host": d.Endpoint, "port": d.Port, "tls": d.TLS, "eviction": d.Eviction}
	if len(d.ReadRegions) > 0 {
		row["readRegions"] = d.ReadRegions
	}
	if d.Budget > 0 {
		row["budget"] = d.Budget
	}
	if d.CreationTime > 0 {
		row["created"] = time.Unix(d.CreationTime, 0).UTC().Format(time.RFC3339)
	}
	return row
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var ds []redis
	if err := c.get(ctx, "/redis/databases", &ds); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	off := 0
	for _, d := range ds {
		if d.State != "" && d.State != "active" {
			off++
		}
	}
	msg := fmt.Sprintf("%d Redis databases", len(ds))
	if off > 0 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%s, %d not active", msg, off)}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// point is one sample of a stats series; Upstash sends {x, y}.
type point struct {
	X any     `json:"x"`
	Y float64 `json:"y"`
}

// series reads a series leniently: a shape Upstash changes is left out
// rather than failing the whole answer.
func series(raw json.RawMessage) []point {
	var ps []point
	if json.Unmarshal(raw, &ps) != nil {
		return nil
	}
	return ps
}

func number(raw json.RawMessage) (float64, bool) {
	var f float64
	if json.Unmarshal(raw, &f) == nil {
		return f, true
	}
	return 0, false
}

func human(b float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for b >= 1024 && i < len(units)-1 {
		b /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f B", b)
	}
	return fmt.Sprintf("%.1f %s", b, units[i])
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Database string `json:"database"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "redis_databases":
		var ds []redis
		if err := c.get(ctx, "/redis/databases", &ds); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range ds {
			out = append(out, redisOut(d))
		}
		return sdk.JSON(out)

	case "redis_stats":
		id := strings.ToLower(strings.TrimSpace(p.Database))
		if !idRe.MatchString(id) {
			return sdk.Result{}, errors.New("the database is its id, a UUID (see redis_databases)")
		}
		var d redis
		if err := c.get(ctx, "/redis/database/"+url.PathEscape(id), &d); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusBadRequest) {
				return sdk.Result{}, fmt.Errorf("there's no Redis database %s", id)
			}
			return sdk.Result{}, err
		}
		if !strings.EqualFold(d.ID, id) {
			return sdk.Result{}, errors.New("unexpected database from Upstash")
		}
		var s map[string]json.RawMessage
		if err := c.get(ctx, "/redis/stats/"+url.PathEscape(id), &s); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"database": d.ID, "name": d.Name, "state": d.State}
		for k, as := range map[string]string{
			"keyspace":                     "keys",
			"total_monthly_requests":       "requestsThisMonth",
			"total_monthly_read_requests":  "readsThisMonth",
			"total_monthly_write_requests": "writesThisMonth",
			"total_monthly_billing":        "costThisMonth",
		} {
			if v, ok := number(s[k]); ok {
				out[as] = v
			}
		}
		if v, ok := number(s["current_storage"]); ok {
			out["storage"] = human(v)
		}
		if v, ok := number(s["total_monthly_bandwidth"]); ok {
			out["bandwidthThisMonth"] = human(v)
		}
		if cs := series(s["connection_count"]); len(cs) > 0 {
			out["connections"] = cs[len(cs)-1].Y
		}
		if ds := series(s["dailyrequests"]); len(ds) > 0 {
			daily := []map[string]any{}
			for _, x := range ds {
				daily = append(daily, map[string]any{"day": fmt.Sprint(x.X), "requests": x.Y})
			}
			out["dailyRequests"] = daily
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
