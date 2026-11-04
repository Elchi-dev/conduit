// Package supabase works with Supabase projects through the Management API
// and a personal access token: organisations, projects with their status
// and region, the health of each project's services, database size and
// connections, edge functions, and pausing or restoring a project.
//
// API keys, database passwords and connection strings are never requested
// or returned.
package supabase

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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Supabase account.
type Config struct {
	Token string `json:"token"` // secret:// personal access token (sbp_…)
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.supabase.com (tests).
	Base string
}

// New returns the Supabase module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.supabase.com"

var (
	refRe   = regexp.MustCompile(`^[a-z]{20}$`)
	tokenRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{20,512}$`)
)

// services the health check asks about.
var services = []string{"auth", "db", "pooler", "realtime", "rest", "storage"}

func projectRef(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !refRe.MatchString(s) {
		return "", errors.New("the project is its reference id: 20 lowercase letters, as in <ref>.supabase.co")
	}
	return s, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	project := `"project":{"type":"string","description":"Project reference id (20 letters, as in <ref>.supabase.co)"}`
	in := sdk.Schema(`{"type":"object","required":["project"],"properties":{` + project + `}}`)
	return sdk.Manifest{
		ID: "supabase", Name: "Supabase", Version: "0.1.0", Category: "Development", Icon: "database",
		Description: "Supabase projects: status and region, service health, database size, edge functions, pause and restore.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"Personal access token (Account, Access tokens), with an expiry"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "organizations", Title: "Organizations", Description: "The organizations the token can see.", Risk: sdk.RiskRead},
			{Name: "projects", Title: "Projects", Description: "Every project with its status, region, organization and Postgres version.", Risk: sdk.RiskRead},
			{Name: "health", Title: "Service health", Description: "Whether a project's database, auth, REST, realtime, storage and pooler are healthy.", Risk: sdk.RiskRead, Input: in},
			{Name: "database_usage", Title: "Database usage", Description: "Database size, connections in use and the largest tables (a fixed read-only query).", Risk: sdk.RiskRead, Input: in},
			{Name: "functions", Title: "Edge functions", Description: "A project's edge functions with their status, version and whether they check JWTs.", Risk: sdk.RiskRead, Input: in},
			{Name: "pause", Title: "Pause a project", Description: "Pauses a project: its database, APIs and functions stop answering until it's restored (free plan only). Undo restores it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: in},
			{Name: "restore", Title: "Restore a project", Description: "Brings a paused project back (takes a few minutes). Undo pauses it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: in},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	tok := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		if !tokenRe.MatchString(t) {
			return errors.New("the stored token doesn't look like a Supabase access token (sbp_…)")
		}
		r.Header.Set("Authorization", "Bearer "+t)
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

type project struct {
	ID             string `json:"id"`
	Ref            string `json:"ref"`
	Name           string `json:"name"`
	OrganizationID string `json:"organization_id"`
	Region         string `json:"region"`
	Status         string `json:"status"`
	CreatedAt      string `json:"created_at"`
	Database       *struct {
		Version        string `json:"version"`
		PostgresEngine string `json:"postgres_engine"`
		ReleaseChannel string `json:"release_channel"`
	} `json:"database"`
}

func (p project) ref() string {
	if p.Ref != "" {
		return p.Ref
	}
	return p.ID
}

// status names Supabase's project states in words.
var status = map[string]string{
	"ACTIVE_HEALTHY":   "running",
	"ACTIVE_UNHEALTHY": "running, unhealthy",
	"INACTIVE":         "paused",
	"COMING_UP":        "starting",
	"GOING_DOWN":       "pausing",
	"PAUSING":          "pausing",
	"RESTORING":        "restoring",
	"RESTARTING":       "restarting",
	"UPGRADING":        "upgrading",
	"INIT_FAILED":      "failed to start",
	"REMOVED":          "removed",
	"RESTORE_FAILED":   "restore failed",
	"PAUSE_FAILED":     "pause failed",
	"RESIZING":         "resizing",
}

func projectOut(p project) map[string]any {
	out := map[string]any{"ref": p.ref(), "name": p.Name, "status": p.Status, "region": p.Region, "organization": p.OrganizationID, "created": p.CreatedAt, "url": "https://" + p.ref() + ".supabase.co"}
	if s := status[p.Status]; s != "" {
		out["state"] = s
	}
	if d := p.Database; d != nil {
		out["postgres"] = d.Version
	}
	return out
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var ps []project
	if _, err := c.api.Do(ctx, http.MethodGet, "/v1/projects", nil, nil, &ps); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Health{Status: "down", Message: "Supabase refused the access token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	unhealthy := 0
	for _, p := range ps {
		if p.Status == "ACTIVE_UNHEALTHY" || strings.HasSuffix(p.Status, "_FAILED") {
			unhealthy++
		}
	}
	msg := fmt.Sprintf("%d projects", len(ps))
	if unhealthy > 0 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%s, %d unhealthy", msg, unhealthy)}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

func (c *conn) project(ctx context.Context, raw string) (project, error) {
	var p project
	ref, err := projectRef(raw)
	if err != nil {
		return p, err
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/v1/projects/"+ref, nil, nil, &p); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return p, fmt.Errorf("there's no project %s (or the token can't see it)", ref)
		}
		return p, err
	}
	if p.ref() != ref {
		return p, errors.New("unexpected project from Supabase")
	}
	return p, nil
}

type input struct {
	Project string `json:"project"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
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

// The usage queries are fixed and read-only; no input reaches them.
const (
	usageSQL  = `select pg_database_size(current_database())::bigint as bytes, (select count(*) from pg_stat_activity)::int as connections, (select setting::int from pg_settings where name = 'max_connections') as max_connections`
	tablesSQL = `select schemaname || '.' || relname as name, pg_total_relation_size(relid)::bigint as bytes, n_live_tup::bigint as rows from pg_stat_user_tables order by pg_total_relation_size(relid) desc limit 10`
)

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
	case "organizations":
		var os []struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
			Name string `json:"name"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/v1/organizations", nil, nil, &os); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, o := range os {
			id := o.Slug
			if id == "" {
				id = o.ID
			}
			out = append(out, map[string]any{"id": id, "name": o.Name})
		}
		return sdk.JSON(out)

	case "projects":
		var ps []project
		if _, err := c.api.Do(ctx, http.MethodGet, "/v1/projects", nil, nil, &ps); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, p := range ps {
			out = append(out, projectOut(p))
		}
		return sdk.JSON(out)

	case "health":
		ref, err := projectRef(p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		var hs []struct {
			Name    string `json:"name"`
			Healthy bool   `json:"healthy"`
			Status  string `json:"status"`
			Error   string `json:"error"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/v1/projects/"+ref+"/health", url.Values{"services": services}, nil, &hs); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no project %s (or the token can't see it)", ref)
			}
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		ok := true
		for _, h := range hs {
			o := map[string]any{"service": h.Name, "healthy": h.Healthy, "status": h.Status}
			if h.Error != "" {
				o["error"] = h.Error
			}
			ok = ok && h.Healthy
			out = append(out, o)
		}
		return sdk.JSON(map[string]any{"project": ref, "healthy": ok, "services": out})

	case "database_usage":
		ref, err := projectRef(p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		var usage []struct {
			Bytes          float64 `json:"bytes"`
			Connections    int     `json:"connections"`
			MaxConnections int     `json:"max_connections"`
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/v1/projects/"+ref+"/database/query", nil, map[string]any{"query": usageSQL}, &usage); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no project %s (or the token can't see it)", ref)
			}
			return sdk.Result{}, fmt.Errorf("couldn't read the database usage (is the project running?): %w", err)
		}
		if len(usage) != 1 {
			return sdk.Result{}, errors.New("unexpected answer from Supabase")
		}
		var tables []struct {
			Name  string  `json:"name"`
			Bytes float64 `json:"bytes"`
			Rows  int64   `json:"rows"`
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/v1/projects/"+ref+"/database/query", nil, map[string]any{"query": tablesSQL}, &tables); err != nil {
			return sdk.Result{}, err
		}
		top := []map[string]any{}
		for _, t := range tables {
			top = append(top, map[string]any{"table": t.Name, "size": human(t.Bytes), "rows": t.Rows})
		}
		u := usage[0]
		return sdk.JSON(map[string]any{"project": ref, "size": human(u.Bytes), "bytes": int64(u.Bytes), "connections": u.Connections, "maxConnections": u.MaxConnections, "largestTables": top})

	case "functions":
		ref, err := projectRef(p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		var fs []struct {
			Slug      string  `json:"slug"`
			Name      string  `json:"name"`
			Status    string  `json:"status"`
			Version   int     `json:"version"`
			VerifyJWT bool    `json:"verify_jwt"`
			CreatedAt float64 `json:"created_at"`
			UpdatedAt float64 `json:"updated_at"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/v1/projects/"+ref+"/functions", nil, nil, &fs); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no project %s (or the token can't see it)", ref)
			}
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, f := range fs {
			o := map[string]any{"slug": f.Slug, "name": f.Name, "status": f.Status, "version": f.Version, "verifyJWT": f.VerifyJWT, "url": "https://" + ref + ".supabase.co/functions/v1/" + url.PathEscape(f.Slug)}
			if f.UpdatedAt > 0 {
				o["updated"] = time.UnixMilli(int64(f.UpdatedAt)).UTC().Format(time.RFC3339)
			}
			out = append(out, o)
		}
		sort.Slice(out, func(i, j int) bool { return out[i]["slug"].(string) < out[j]["slug"].(string) })
		return sdk.JSON(out)

	case "pause", "restore":
		return c.pauseRestore(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) pauseRestore(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	pausing := call.Action == "pause"
	pr, err := c.project(ctx, p.Project)
	if err != nil {
		return sdk.Result{}, err
	}
	ref := pr.ref()
	if pausing && pr.Status == "INACTIVE" {
		return sdk.JSON(map[string]any{"project": ref, "note": "it is already paused"})
	}
	if !pausing && pr.Status != "INACTIVE" {
		return sdk.JSON(map[string]any{"project": ref, "note": "it isn't paused (" + pr.Status + ")"})
	}
	if pausing && pr.Status != "ACTIVE_HEALTHY" && pr.Status != "ACTIVE_UNHEALTHY" {
		return sdk.Result{}, fmt.Errorf("%s is %s; only a running project can be paused", pr.Name, pr.Status)
	}
	label := fmt.Sprintf("project %s (%s, %s)", pr.Name, ref, pr.Region)
	if call.DryRun {
		sum := "Pause " + label + ": its database, APIs and edge functions stop answering until restored"
		after := "INACTIVE"
		if !pausing {
			sum, after = "Restore "+label+"; it takes a few minutes to come up", "ACTIVE_HEALTHY"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: label, Op: call.Action, Before: mustJSON(map[string]any{"status": pr.Status}), After: mustJSON(map[string]any{"status": after})}}}}, nil
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "/v1/projects/"+ref+"/"+call.Action, nil, nil, nil); err != nil {
		if pausing && rest.IsStatus(err, http.StatusBadRequest) {
			return sdk.Result{}, fmt.Errorf("%w (Supabase only pauses projects on the free plan)", err)
		}
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"project": ref, "name": pr.Name, "requested": call.Action})
	if pausing {
		res.Undo = sdk.UndoWith("restore", map[string]any{"project": ref}, "Restore "+pr.Name)
	} else {
		res.Undo = sdk.UndoWith("pause", map[string]any{"project": ref}, "Pause "+pr.Name+" again")
	}
	return res, err
}
