// Package pterodactyl runs game servers on a Pterodactyl or Pelican panel
// through its client API with a client API key: servers with their state and
// resource use, power, console commands, backups and files.
package pterodactyl

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
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one panel.
type Config struct {
	URL                string `json:"url"`    // e.g. https://panel.example.com
	APIKey             string `json:"apiKey"` // secret:// client API key (ptlc_…)
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Pterodactyl module.
func New() *Module { return &Module{} }

var (
	// A server is named by its short identifier (8 hex) or its full UUID.
	serverRe = regexp.MustCompile(`^[0-9a-f]{8}(-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?$`)
	uuidRe   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

const (
	srvProp    = `"server":{"type":"string","description":"Server identifier (8 characters, from servers) or UUID"}`
	backupProp = `"backup":{"type":"string","description":"Backup UUID, from backups"}`
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	one := `{"type":"object","required":["server"],"properties":{` + srvProp + `}}`
	bk := `{"type":"object","required":["server","backup"],"properties":{` + srvProp + `,` + backupProp + `}}`
	return sdk.Manifest{
		ID: "pterodactyl", Name: "Pterodactyl", Version: "0.1.0", Category: "Gaming", Icon: "gamepad",
		Description: "Game servers on a Pterodactyl or Pelican panel: state, power, console commands, backups and files.",
		Presets:     []string{"gamer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"The panel's address, e.g. https://panel.example.com"},
			"apiKey":{"type":"string","x-secret":true,"description":"Client API key (Account, API Credentials; starts with ptlc_). It acts with your account's rights"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-signed certificate to trust"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "servers", Title: "Servers", Description: "Every server you can reach, with its state, CPU, memory and disk use.", Risk: sdk.RiskRead},
			{Name: "status", Title: "Server status", Description: "One server's state, limits and resource use.", Risk: sdk.RiskRead, Input: sdk.Schema(one)},
			{Name: "start", Title: "Start a server", Description: "Undo stops it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(one)},
			{Name: "stop", Title: "Stop a server", Description: "Stops it the way its egg says (players are disconnected). Undo starts it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(one)},
			{Name: "restart", Title: "Restart a server", Description: "Players are disconnected while it restarts.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(one)},
			{Name: "kill", Title: "Kill a server", Description: "Ends the process at once, without saving; unsaved world changes are lost. Undo starts it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(one)},
			{Name: "command", Title: "Run a console command", Description: "Sends one line to the server console (the server must be running). Commands can carry passwords, so this is sensitive. It can't be undone.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["server","command"],"properties":{` + srvProp + `,"command":{"type":"string","maxLength":500}}}`)},
			{Name: "backups", Title: "Backups", Description: "A server's backups with size, state and date.", Risk: sdk.RiskRead, Input: sdk.Schema(one)},
			{Name: "create_backup", Title: "Create a backup", Description: "Starts a backup of the server's files (it runs on the node). Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["server"],"properties":{` + srvProp + `,"name":{"type":"string","maxLength":191}}}`)},
			{Name: "delete_backup", Title: "Delete a backup", Description: "Deletes the backup for good. Locked backups are refused.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(bk)},
			{Name: "restore_backup", Title: "Restore a backup", Description: "Overwrites the server's files with the backup's (truncate deletes every file first). The server is stopped meanwhile. Can't be undone.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["server","backup"],"properties":{` + srvProp + `,` + backupProp + `,"truncate":{"type":"boolean","default":false,"description":"Delete every file before restoring"}}}`)},
			{Name: "files", Title: "Files", Description: "Files and folders in one of the server's directories.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["server"],"properties":{` + srvProp + `,"directory":{"type":"string","default":"/","maxLength":1024}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "server", Title: "Game servers", ListAction: "servers", GetAction: "status", ViewHint: "table"}},
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
		return errors.New("the address is like https://panel.example.com")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the client API key in the vault and enter its secret:// reference")
	}
	tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
	if err != nil {
		return err
	}
	key := c.APIKey
	p := strings.TrimRight(u.Path, "/")
	p = strings.TrimSuffix(strings.TrimSuffix(p, "/api/client"), "/api")
	api := rest.New(u.Scheme+"://"+u.Host+p+"/api/client", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, key)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k))
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		tr := sdk.Transport(h) // through the instance's network, if any
		tr.TLSClientConfig = tc
		api.HTTP = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	// Go drops Authorization on a cross-host redirect, but refusing it keeps
	// the panel's answers from coming from somewhere else, too.
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var acct struct {
		Attributes struct {
			Username string `json:"username"`
		} `json:"attributes"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/account", nil, nil, &acct); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Health{Status: "down", Message: "the panel refused the API key (use a client key, ptlc_…)"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	list, err := c.servers(ctx)
	if err != nil {
		return sdk.Health{Status: "degraded", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%s · %d servers", acct.Attributes.Username, len(list))}
}

type server struct {
	Identifier  string `json:"identifier"`
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Node        string `json:"node"`
	Description string `json:"description"`
	Suspended   bool   `json:"is_suspended"`
	Installing  bool   `json:"is_installing"`
	Status      string `json:"status"`
	Limits      struct {
		Memory int64 `json:"memory"`
		Disk   int64 `json:"disk"`
		CPU    int64 `json:"cpu"`
	} `json:"limits"`
}

type stats struct {
	State     string `json:"current_state"`
	Suspended bool   `json:"is_suspended"`
	Resources struct {
		Memory int64   `json:"memory_bytes"`
		CPU    float64 `json:"cpu_absolute"`
		Disk   int64   `json:"disk_bytes"`
		RX     int64   `json:"network_rx_bytes"`
		TX     int64   `json:"network_tx_bytes"`
		Uptime int64   `json:"uptime"` // milliseconds
	} `json:"resources"`
}

type backup struct {
	UUID       string `json:"uuid"`
	Name       string `json:"name"`
	Successful bool   `json:"is_successful"`
	Locked     bool   `json:"is_locked"`
	Bytes      int64  `json:"bytes"`
	Created    string `json:"created_at"`
	Completed  string `json:"completed_at"`
}

func (b backup) summary() map[string]any {
	state := "running"
	switch {
	case b.Completed != "" && b.Successful:
		state = "done"
	case b.Completed != "":
		state = "failed"
	}
	return map[string]any{"uuid": b.UUID, "name": b.Name, "state": state, "locked": b.Locked, "sizeMB": mb(b.Bytes), "created": b.Created}
}

func mb(b int64) float64 { return float64(b*10/(1<<20)) / 10 }

func (c *conn) servers(ctx context.Context) ([]server, error) {
	var out []server
	for page := 1; page <= 20; page++ {
		var r struct {
			Data []struct {
				Attributes server `json:"attributes"`
			} `json:"data"`
			Meta struct {
				Pagination struct {
					TotalPages int `json:"total_pages"`
				} `json:"pagination"`
			} `json:"meta"`
		}
		q := url.Values{"per_page": {"100"}, "page": {fmt.Sprint(page)}}
		if _, err := c.api.Do(ctx, http.MethodGet, "", q, nil, &r); err != nil {
			return nil, err
		}
		for _, d := range r.Data {
			out = append(out, d.Attributes)
		}
		if page >= r.Meta.Pagination.TotalPages {
			break
		}
	}
	return out, nil
}

func (c *conn) server(ctx context.Context, id string) (server, error) {
	var r struct {
		Attributes server `json:"attributes"`
	}
	_, err := c.api.Do(ctx, http.MethodGet, "/servers/"+id, nil, nil, &r)
	return r.Attributes, err
}

func (c *conn) stats(ctx context.Context, id string) (stats, error) {
	var r struct {
		Attributes stats `json:"attributes"`
	}
	_, err := c.api.Do(ctx, http.MethodGet, "/servers/"+id+"/resources", nil, nil, &r)
	return r.Attributes, err
}

func (c *conn) backup(ctx context.Context, id, uuid string) (backup, error) {
	var r struct {
		Attributes backup `json:"attributes"`
	}
	_, err := c.api.Do(ctx, http.MethodGet, "/servers/"+id+"/backups/"+uuid, nil, nil, &r)
	return r.Attributes, err
}

func row(s server, st *stats) map[string]any {
	out := map[string]any{"id": s.Identifier, "name": s.Name, "node": s.Node,
		"memoryLimitMB": s.Limits.Memory, "diskLimitMB": s.Limits.Disk, "cpuLimit": s.Limits.CPU}
	if s.Description != "" {
		out["description"] = s.Description
	}
	switch {
	case s.Suspended:
		out["state"] = "suspended"
	case s.Installing || s.Status == "installing":
		out["state"] = "installing"
	case st != nil:
		out["state"] = st.State
	}
	if st != nil {
		r := st.Resources
		out["cpu"] = float64(int(r.CPU*10)) / 10
		out["memoryMB"], out["diskMB"] = mb(r.Memory), mb(r.Disk)
		out["networkInMB"], out["networkOutMB"] = mb(r.RX), mb(r.TX)
		if r.Uptime > 0 {
			out["uptime"] = (time.Duration(r.Uptime) * time.Millisecond).Truncate(time.Second).String()
		}
	}
	return out
}

type input struct {
	Server    string `json:"server"`
	Backup    string `json:"backup"`
	Command   string `json:"command"`
	Name      string `json:"name"`
	Truncate  bool   `json:"truncate"`
	Directory string `json:"directory"`
}

func plan(summary, target, op string, before, after any) *sdk.Plan {
	ch := sdk.Change{Target: target, Op: op}
	if before != nil {
		ch.Before, _ = json.Marshal(before)
	}
	if after != nil {
		ch.After, _ = json.Marshal(after)
	}
	return &sdk.Plan{Summary: summary, Changes: []sdk.Change{ch}}
}

// checkLine vets one console line: printable, one line, 1 to 500 characters.
func checkLine(s string) error {
	if strings.TrimSpace(s) == "" || len(s) > 500 {
		return errors.New("a command is one line of 1 to 500 characters")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return errors.New("a command is one line without control characters")
		}
	}
	return nil
}

// checkDir vets a directory inside the server's files.
func checkDir(d string) (string, error) {
	if d == "" {
		return "/", nil
	}
	if len(d) > 1024 || !strings.HasPrefix(d, "/") || strings.ContainsAny(d, "\\\x00\r\n") {
		return "", errors.New("the directory is a path inside the server, like /plugins")
	}
	for _, part := range strings.Split(d, "/") {
		if part == ".." {
			return "", errors.New("the directory may not contain ..")
		}
	}
	return d, nil
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
	if call.Action == "servers" {
		list, err := c.servers(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for i, s := range list {
			var st *stats
			if i < 50 && !s.Suspended && !s.Installing {
				if r, err := c.stats(ctx, s.Identifier); err == nil {
					st = &r
				}
			}
			out = append(out, row(s, st))
		}
		return sdk.JSON(out)
	}
	if !known(m.Manifest(), call.Action) {
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	p.Server = strings.ToLower(strings.TrimSpace(p.Server))
	if !serverRe.MatchString(p.Server) {
		return sdk.Result{}, errors.New("enter the server's identifier (8 characters, from servers) or UUID")
	}
	id := p.Server
	if strings.Contains(call.Action, "backup") && call.Action != "backups" && call.Action != "create_backup" {
		p.Backup = strings.ToLower(strings.TrimSpace(p.Backup))
		if !uuidRe.MatchString(p.Backup) {
			return sdk.Result{}, errors.New("enter the backup's UUID, from backups")
		}
	}

	switch call.Action {
	case "status":
		s, err := c.server(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		st, err := c.stats(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(row(s, &st))

	case "start", "stop", "restart", "kill":
		s, err := c.server(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		st, err := c.stats(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		running := st.State == "running" || st.State == "starting"
		switch {
		case call.Action == "start" && running:
			return sdk.Result{}, fmt.Errorf("%s is already %s", s.Name, st.State)
		case call.Action != "start" && call.Action != "restart" && st.State == "offline":
			return sdk.Result{}, fmt.Errorf("%s is already offline", s.Name)
		}
		if call.DryRun {
			after := map[string]string{"start": "running", "stop": "offline", "kill": "offline", "restart": "running"}[call.Action]
			sum := fmt.Sprintf("%s server %s (%s) on %s", upper(call.Action), s.Name, id, s.Node)
			if call.Action == "kill" {
				sum += "; the process ends without saving"
			}
			return sdk.Result{Plan: plan(sum, "server "+s.Name, call.Action, map[string]string{"state": st.State}, map[string]string{"state": after})}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/servers/"+id+"/power", nil, map[string]string{"signal": call.Action}, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"server": s.Name, "signal": call.Action})
		switch call.Action {
		case "start":
			res.Undo = sdk.UndoWith("stop", map[string]string{"server": id}, "Stop "+s.Name)
		case "stop", "kill":
			res.Undo = sdk.UndoWith("start", map[string]string{"server": id}, "Start "+s.Name)
		}
		return res, err

	case "command":
		if err := checkLine(p.Command); err != nil {
			return sdk.Result{}, err
		}
		s, err := c.server(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: plan(fmt.Sprintf("Run on %s's console: %s", s.Name, p.Command), "server "+s.Name, "command", nil, map[string]string{"command": p.Command})}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/servers/"+id+"/command", nil, map[string]string{"command": p.Command}, nil); err != nil {
			if rest.IsStatus(err, http.StatusBadGateway) {
				return sdk.Result{}, fmt.Errorf("%s isn't running, so it can't take commands", s.Name)
			}
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"server": s.Name, "sent": true})

	case "backups":
		var r struct {
			Data []struct {
				Attributes backup `json:"attributes"`
			} `json:"data"`
			Meta struct {
				BackupCount int `json:"backup_count"`
			} `json:"meta"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/servers/"+id+"/backups", url.Values{"per_page": {"100"}}, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, b := range r.Data {
			out = append(out, b.Attributes.summary())
		}
		return sdk.JSON(out)

	case "create_backup":
		name := strings.TrimSpace(p.Name)
		if len(name) > 191 || strings.ContainsAny(name, "\r\n\x00") {
			return sdk.Result{}, errors.New("a backup name is one line of at most 191 characters")
		}
		s, err := c.server(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			label := name
			if label == "" {
				label = "(named by the panel)"
			}
			return sdk.Result{Plan: plan(fmt.Sprintf("Back up %s's files", s.Name), "server "+s.Name, "create", nil, map[string]string{"backup": label})}, nil
		}
		body := map[string]any{}
		if name != "" {
			body["name"] = name
		}
		var r struct {
			Attributes backup `json:"attributes"`
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/servers/"+id+"/backups", nil, body, &r); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(r.Attributes.summary())
		if uuidRe.MatchString(r.Attributes.UUID) {
			res.Undo = sdk.UndoWith("delete_backup", map[string]string{"server": id, "backup": r.Attributes.UUID}, "Delete backup "+r.Attributes.Name)
		}
		return res, err

	case "delete_backup", "restore_backup":
		s, err := c.server(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		b, err := c.backup(ctx, id, p.Backup)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.Action == "delete_backup" && b.Locked {
			return sdk.Result{}, fmt.Errorf("backup %s is locked; unlock it in the panel first", b.Name)
		}
		if call.Action == "restore_backup" && (b.Completed == "" || !b.Successful) {
			return sdk.Result{}, fmt.Errorf("backup %s didn't finish, so it can't be restored", b.Name)
		}
		if call.DryRun {
			if call.Action == "delete_backup" {
				return sdk.Result{Plan: plan(fmt.Sprintf("Delete backup %s of %s for good", b.Name, s.Name), "backup "+b.Name, "delete", b.summary(), nil)}, nil
			}
			sum := fmt.Sprintf("Restore %s from backup %s (%s); its files are overwritten", s.Name, b.Name, b.Created)
			if p.Truncate {
				sum = fmt.Sprintf("Delete every file of %s, then restore backup %s (%s)", s.Name, b.Name, b.Created)
			}
			return sdk.Result{Plan: plan(sum, "server "+s.Name, "restore", nil, map[string]any{"backup": b.summary(), "truncate": p.Truncate})}, nil
		}
		path := "/servers/" + id + "/backups/" + p.Backup
		if call.Action == "delete_backup" {
			if _, err := c.api.Do(ctx, http.MethodDelete, path, nil, nil, nil); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]any{"server": s.Name, "deleted": b.Name})
		}
		if _, err := c.api.Do(ctx, http.MethodPost, path+"/restore", nil, map[string]bool{"truncate": p.Truncate}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"server": s.Name, "restoring": b.Name, "truncate": p.Truncate})

	case "files":
		dir, err := checkDir(p.Directory)
		if err != nil {
			return sdk.Result{}, err
		}
		var r struct {
			Data []struct {
				Attributes struct {
					Name     string `json:"name"`
					Mode     string `json:"mode"`
					Size     int64  `json:"size"`
					IsFile   bool   `json:"is_file"`
					Symlink  bool   `json:"is_symlink"`
					Mime     string `json:"mimetype"`
					Modified string `json:"modified_at"`
				} `json:"attributes"`
			} `json:"data"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/servers/"+id+"/files/list", url.Values{"directory": {dir}}, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, f := range r.Data {
			a := f.Attributes
			kind := "folder"
			if a.IsFile {
				kind = "file"
			}
			if a.Symlink {
				kind = "link"
			}
			out = append(out, map[string]any{"name": a.Name, "type": kind, "size": a.Size, "mode": a.Mode, "modified": a.Modified})
		}
		return sdk.JSON(map[string]any{"directory": dir, "entries": out})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func known(mf sdk.Manifest, action string) bool {
	for _, a := range mf.Actions {
		if a.Name == action {
			return true
		}
	}
	return false
}

func upper(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
