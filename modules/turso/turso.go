// Package turso works with a Turso organization through the Platform API
// and a platform API token: databases, groups, locations, the
// organization's usage, and creating or deleting databases.
//
// Database auth tokens are never created or returned, and answers are
// decoded field by field.
package turso

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

// Config is one Turso organization.
type Config struct {
	Token        string `json:"token"`        // secret:// platform API token
	Organization string `json:"organization"` // organization slug (a personal account's is the user name)
}

type conn struct {
	api *rest.Client
	org string // checked slug
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.turso.tech (tests).
	Base string
}

// New returns the Turso module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.turso.tech"

var (
	slugRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)
	tokenRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{20,1000}$`)
)

func checkName(what, s string) (string, error) {
	s = strings.TrimSpace(s)
	if !slugRe.MatchString(s) || strings.Contains(s, "--") {
		return "", fmt.Errorf("the %s name is lowercase letters, digits and dashes (up to 64), like my-db", what)
	}
	return s, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	db := `"database":{"type":"string","description":"Database name (see databases)"}`
	return sdk.Manifest{
		ID: "turso", Name: "Turso", Version: "0.1.0", Category: "Development", Icon: "database",
		Description: "Turso databases: groups, locations, usage, and creating or deleting databases. Never database tokens.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token","organization"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"A platform API token (turso auth api-tokens mint, or Settings, API tokens)"},
			"organization":{"type":"string","description":"Organization slug; a personal account's is your user name"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "databases", Title: "Databases", Description: "Every database with its group, primary location and replicas, version, whether reads or writes are blocked, sleeping and delete protection.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"group":{"type":"string","description":"Only databases in this group"}}}`)},
			{Name: "groups", Title: "Groups", Description: "Groups with their primary location, other locations, version, archived and delete protection, and how many databases each holds.", Risk: sdk.RiskRead},
			{Name: "locations", Title: "Locations", Description: "The locations Turso can place a group in, by code and name.", Risk: sdk.RiskRead},
			{Name: "usage", Title: "Usage", Description: "Rows read and written, storage, bytes synced and database count in the current period, for the organization and per database (or for one database).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + db + `}}`)},
			{Name: "create_database", Title: "Create a database", Description: "Creates an empty database in a group (default: default). It counts toward the plan's database and storage limits. Undo deletes it, with anything written to it since.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["name"],"properties":{"name":{"type":"string","description":"New database name: lowercase letters, digits and dashes"},"group":{"type":"string","default":"default","description":"Group to create it in (see groups)"}}}`)},
			{Name: "delete_database", Title: "Delete a database", Description: "Deletes a database with its data and replicas, for good. A database with delete protection is refused.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["database"],"properties":{` + db + `}}`)},
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
		return errors.New("store the platform API token in the vault and enter its secret:// reference")
	}
	org := strings.ToLower(strings.TrimSpace(c.Organization))
	if !slugRe.MatchString(org) {
		return errors.New("the organization is its slug, like acme (turso org list); a personal account's is your user name")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	tok := c.Token
	api := rest.New(base+"/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		if !tokenRe.MatchString(t) {
			return errors.New("the stored token doesn't look like a Turso platform API token")
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
	m.set.Put(id, &conn{api: api, org: org})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Turso refused the platform API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the token isn't allowed to do this in the Turso organization")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, body, out any) error {
	_, err := c.api.Do(ctx, method, "/organizations/"+url.PathEscape(c.org)+path, nil, body, out)
	return friendly(err)
}

type database struct {
	Name             string   `json:"Name"`
	ID               string   `json:"DbId"`
	Hostname         string   `json:"Hostname"`
	Group            string   `json:"group"`
	PrimaryRegion    string   `json:"primaryRegion"`
	Regions          []string `json:"regions"`
	Version          string   `json:"version"`
	BlockReads       bool     `json:"block_reads"`
	BlockWrites      bool     `json:"block_writes"`
	Sleeping         bool     `json:"sleeping"`
	Archived         bool     `json:"archived"`
	DeleteProtection bool     `json:"delete_protection"`
	IsSchema         bool     `json:"is_schema"`
	Schema           string   `json:"schema"`
}

func dbOut(d database) map[string]any {
	row := map[string]any{"name": d.Name, "id": d.ID, "host": d.Hostname, "group": d.Group, "primaryLocation": d.PrimaryRegion, "locations": d.Regions,
		"version": d.Version, "blockReads": d.BlockReads, "blockWrites": d.BlockWrites, "sleeping": d.Sleeping || d.Archived, "deleteProtection": d.DeleteProtection}
	if d.IsSchema {
		row["schemaDatabase"] = true
	}
	if d.Schema != "" {
		row["schema"] = d.Schema
	}
	return row
}

func (c *conn) databases(ctx context.Context) ([]database, error) {
	var res struct {
		Databases []database `json:"databases"`
	}
	if err := c.do(ctx, http.MethodGet, "/databases", nil, &res); err != nil {
		return nil, err
	}
	return res.Databases, nil
}

// database returns one database; ok is false when there's none by that name.
func (c *conn) database(ctx context.Context, name string) (database, bool, error) {
	var res struct {
		Database database `json:"database"`
	}
	if err := c.do(ctx, http.MethodGet, "/databases/"+url.PathEscape(name), nil, &res); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return database{}, false, nil
		}
		return database{}, false, err
	}
	if res.Database.Name != name {
		return database{}, false, errors.New("unexpected database from Turso")
	}
	return res.Database, true, nil
}

type usage struct {
	RowsRead     int64 `json:"rows_read"`
	RowsWritten  int64 `json:"rows_written"`
	StorageBytes int64 `json:"storage_bytes"`
	BytesSynced  int64 `json:"bytes_synced"`
	Databases    int64 `json:"databases"`
	Locations    int64 `json:"locations"`
	Groups       int64 `json:"groups"`
}

func human(b int64) string {
	f := float64(b)
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f B", f)
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

func usageOut(u usage) map[string]any {
	return map[string]any{"rowsRead": u.RowsRead, "rowsWritten": u.RowsWritten, "storage": human(u.StorageBytes), "storageBytes": u.StorageBytes, "bytesSynced": u.BytesSynced}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ds, err := c.databases(ctx)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "there's no Turso organization " + c.org}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	blocked := 0
	for _, d := range ds {
		if d.BlockReads || d.BlockWrites {
			blocked++
		}
	}
	if blocked > 0 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%d databases, %d with reads or writes blocked", len(ds), blocked)}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d databases", len(ds))}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Database string `json:"database"`
		Name     string `json:"name"`
		Group    string `json:"group"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "databases":
		group := ""
		if strings.TrimSpace(p.Group) != "" {
			if group, err = checkName("group", p.Group); err != nil {
				return sdk.Result{}, err
			}
		}
		ds, err := c.databases(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range ds {
			if group == "" || d.Group == group {
				out = append(out, dbOut(d))
			}
		}
		return sdk.JSON(out)

	case "groups":
		var res struct {
			Groups []struct {
				Name             string   `json:"name"`
				UUID             string   `json:"uuid"`
				Version          string   `json:"version"`
				Primary          string   `json:"primary"`
				Locations        []string `json:"locations"`
				Archived         bool     `json:"archived"`
				DeleteProtection bool     `json:"delete_protection"`
			} `json:"groups"`
		}
		if err := c.do(ctx, http.MethodGet, "/groups", nil, &res); err != nil {
			return sdk.Result{}, err
		}
		count := map[string]int{}
		if ds, err := c.databases(ctx); err == nil {
			for _, d := range ds {
				count[d.Group]++
			}
		}
		out := []map[string]any{}
		for _, g := range res.Groups {
			out = append(out, map[string]any{"name": g.Name, "id": g.UUID, "version": g.Version, "primaryLocation": g.Primary, "locations": g.Locations,
				"archived": g.Archived, "deleteProtection": g.DeleteProtection, "databases": count[g.Name]})
		}
		return sdk.JSON(out)

	case "locations":
		var res struct {
			Locations map[string]string `json:"locations"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/locations", nil, nil, &res); err != nil {
			return sdk.Result{}, friendly(err)
		}
		out := []map[string]any{}
		for code, name := range res.Locations {
			out = append(out, map[string]any{"code": code, "name": name})
		}
		sort.Slice(out, func(i, j int) bool { return out[i]["code"].(string) < out[j]["code"].(string) })
		return sdk.JSON(out)

	case "usage":
		if strings.TrimSpace(p.Database) != "" {
			name, err := checkName("database", p.Database)
			if err != nil {
				return sdk.Result{}, err
			}
			var res struct {
				Database struct {
					UUID  string `json:"uuid"`
					Usage usage  `json:"usage"`
				} `json:"database"`
			}
			if err := c.do(ctx, http.MethodGet, "/databases/"+url.PathEscape(name)+"/usage", nil, &res); err != nil {
				if rest.IsStatus(err, http.StatusNotFound) {
					return sdk.Result{}, fmt.Errorf("there's no database %s", name)
				}
				return sdk.Result{}, err
			}
			out := usageOut(res.Database.Usage)
			out["database"] = name
			return sdk.JSON(out)
		}
		var res struct {
			Organization struct {
				Usage     usage `json:"usage"`
				Databases []struct {
					UUID  string `json:"uuid"`
					Usage usage  `json:"usage"`
				} `json:"databases"`
			} `json:"organization"`
		}
		if err := c.do(ctx, http.MethodGet, "/usage", nil, &res); err != nil {
			return sdk.Result{}, err
		}
		names := map[string]string{}
		if ds, err := c.databases(ctx); err == nil {
			for _, d := range ds {
				names[d.ID] = d.Name
			}
		}
		per := []map[string]any{}
		for _, d := range res.Organization.Databases {
			row := usageOut(d.Usage)
			row["id"] = d.UUID
			if n := names[d.UUID]; n != "" {
				row["database"] = n
			}
			per = append(per, row)
		}
		sort.Slice(per, func(i, j int) bool { return per[i]["storageBytes"].(int64) > per[j]["storageBytes"].(int64) })
		u := res.Organization.Usage
		out := usageOut(u)
		out["organization"] = c.org
		out["databases"] = u.Databases
		out["locations"] = u.Locations
		out["groups"] = u.Groups
		out["perDatabase"] = per
		return sdk.JSON(out)

	case "create_database":
		name, err := checkName("database", p.Name)
		if err != nil {
			return sdk.Result{}, err
		}
		group := "default"
		if strings.TrimSpace(p.Group) != "" {
			if group, err = checkName("group", p.Group); err != nil {
				return sdk.Result{}, err
			}
		}
		return c.create(ctx, call, name, group)

	case "delete_database":
		name, err := checkName("database", p.Database)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.delete(ctx, call, name)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) create(ctx context.Context, call sdk.Call, name, group string) (sdk.Result, error) {
	d, ok, err := c.database(ctx, name)
	if err != nil {
		return sdk.Result{}, err
	}
	if ok {
		return sdk.JSON(map[string]any{"database": d.Name, "group": d.Group, "note": "nothing to change: the database exists"})
	}
	var g struct {
		Group struct {
			Name      string   `json:"name"`
			Primary   string   `json:"primary"`
			Locations []string `json:"locations"`
		} `json:"group"`
	}
	if err := c.do(ctx, http.MethodGet, "/groups/"+url.PathEscape(group), nil, &g); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no group %s (see groups)", group)
		}
		return sdk.Result{}, err
	}
	label := fmt.Sprintf("database %s in group %s (%s)", name, group, strings.Join(g.Group.Locations, ", "))
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: "Create " + label + "; it counts toward the plan's database limit",
			Changes: []sdk.Change{{Target: label, Op: "create", After: mustJSON(map[string]string{"name": name, "group": group})}}}}, nil
	}
	var res struct {
		Database struct {
			Name     string `json:"Name"`
			ID       string `json:"DbId"`
			Hostname string `json:"Hostname"`
		} `json:"database"`
	}
	if err := c.do(ctx, http.MethodPost, "/databases", map[string]string{"name": name, "group": group}, &res); err != nil {
		if rest.IsStatus(err, http.StatusConflict) {
			return sdk.Result{}, fmt.Errorf("a database named %s exists already", name)
		}
		return sdk.Result{}, err
	}
	out, err := sdk.JSON(map[string]any{"database": name, "id": res.Database.ID, "host": res.Database.Hostname, "group": group, "created": true})
	out.Undo = sdk.UndoWith("delete_database", map[string]string{"database": name}, "Delete database "+name)
	return out, err
}

func (c *conn) delete(ctx context.Context, call sdk.Call, name string) (sdk.Result, error) {
	d, ok, err := c.database(ctx, name)
	if err != nil {
		return sdk.Result{}, err
	}
	if !ok {
		return sdk.Result{}, fmt.Errorf("there's no database %s", name)
	}
	if d.DeleteProtection {
		return sdk.Result{}, fmt.Errorf("%s has delete protection; turn it off in Turso first", name)
	}
	label := fmt.Sprintf("database %s (group %s, %s)", d.Name, d.Group, strings.Join(d.Regions, ", "))
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: "Delete " + label + " with its data and replicas, for good",
			Changes: []sdk.Change{{Target: label, Op: "delete", Before: mustJSON(map[string]any{"name": d.Name, "group": d.Group, "locations": d.Regions})}}}}, nil
	}
	if err := c.do(ctx, http.MethodDelete, "/databases/"+url.PathEscape(d.Name), nil, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"database": d.Name, "group": d.Group, "deleted": true})
}
