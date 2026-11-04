// Package crafty runs Minecraft servers on a Crafty Controller 4 install
// through its v2 API with an API token: servers, live stats, power, backups,
// console commands and logs.
package crafty

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Config is one Crafty install.
type Config struct {
	URL                string `json:"url"`   // e.g. https://crafty.example.com:8443
	Token              string `json:"token"` // secret:// API token
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

// New returns the Crafty Controller module.
func New() *Module { return &Module{} }

// Crafty 4.0 to 4.3 number servers; 4.4 and later use UUIDs.
var (
	idRe   = regexp.MustCompile(`^([0-9]{1,9}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

const srvProp = `"server":{"type":["string","integer"],"description":"Server id (a number, or a UUID on Crafty 4.4 and later), from servers"}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	one := `{"type":"object","required":["server"],"properties":{` + srvProp + `}}`
	return sdk.Manifest{
		ID: "crafty", Name: "Crafty Controller", Version: "0.1.0", Category: "Gaming", Icon: "gamepad",
		Description: "Minecraft servers on Crafty Controller 4: players online, CPU and memory, start, stop, backups and console commands.",
		Presets:     []string{"gamer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Crafty's address, e.g. https://crafty.example.com:8443"},
			"token":{"type":"string","x-secret":true,"description":"API token (Panel config, Users, edit a user, API keys). It acts with that key's permissions"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of Crafty's self-signed certificate (it makes one on install)"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "servers", Title: "Servers", Description: "Every server with whether it's running, players online and its version.", Risk: sdk.RiskRead},
			{Name: "stats", Title: "Server stats", Description: "Players online (and who), CPU and memory use, world size and version.", Risk: sdk.RiskRead, Input: sdk.Schema(one)},
			{Name: "start", Title: "Start a server", Description: "Undo stops it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(one)},
			{Name: "stop", Title: "Stop a server", Description: "Saves and stops it; players are disconnected. Undo starts it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(one)},
			{Name: "restart", Title: "Restart a server", Description: "Players are disconnected while it restarts.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(one)},
			{Name: "kill", Title: "Kill a server", Description: "Ends the process at once, without saving. Undo starts it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(one)},
			{Name: "backup", Title: "Back up a server", Description: "Runs a backup with the server's backup settings (or the named backup configuration on Crafty 4.4 and later). Crafty then deletes the oldest backups beyond the configuration's maximum, and a configuration can shut the server down while it runs; the preview says both.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["server"],"properties":{` + srvProp + `,"backupConfig":{"type":"string","description":"Backup configuration UUID (Crafty 4.4 and later); the default one when left out"}}}`)},
			{Name: "command", Title: "Run a console command", Description: "Sends one line to the server console. Commands can carry passwords, so this is sensitive. It can't be undone.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["server","command"],"properties":{` + srvProp + `,"command":{"type":"string","maxLength":500}}}`)},
			{Name: "logs", Title: "Console log", Description: "The last lines of the server's log. Logs can hold IP addresses and passwords typed into the console, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["server"],"properties":{` + srvProp + `,"lines":{"type":"integer","minimum":1,"maximum":500,"default":100}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "server", Title: "Minecraft servers", ListAction: "servers", GetAction: "stats", ViewHint: "table"}},
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
		return errors.New("the address is like https://crafty.example.com:8443")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
	if err != nil {
		return err
	}
	tok := c.Token
	p := strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v2"), "/api")
	api := rest.New(u.Scheme+"://"+u.Host+p+"/api/v2", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		tr := sdk.Transport(h) // through the instance's network, if any
		tr.TLSClientConfig = tc
		api.HTTP = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
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
	list, err := c.servers(ctx)
	if err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Health{Status: "down", Message: "Crafty refused the API token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d servers", len(list))}
}

// envelope is Crafty's answer shape: {"status":"ok","data":…}.
type envelope[T any] struct {
	Status string `json:"status"`
	Data   T      `json:"data"`
}

func get[T any](ctx context.Context, c *conn, path string, q url.Values) (T, error) {
	var e envelope[T]
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, &e)
	if err == nil && e.Status != "" && e.Status != "ok" {
		err = fmt.Errorf("Crafty answered %s", e.Status)
	}
	return e.Data, err
}

// flexID is a server id that's a number on older Crafty and a string on newer.
type flexID string

func (f *flexID) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*f = flexID(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return errors.New("the server id is a number or a UUID")
	}
	*f = flexID(n.String())
	return nil
}

type server struct {
	ID   flexID `json:"server_id"`
	Name string `json:"server_name"`
	Type string `json:"type"`
	Port int    `json:"server_port"`
}

type stats struct {
	Running     bool            `json:"running"`
	CPU         float64         `json:"cpu"`
	Mem         json.RawMessage `json:"mem"`
	MemPercent  float64         `json:"mem_percent"`
	Online      int             `json:"online"`
	Max         int             `json:"max"`
	Players     json.RawMessage `json:"players"`
	Version     string          `json:"version"`
	Desc        string          `json:"desc"`
	World       string          `json:"world_name"`
	WorldSize   string          `json:"world_size"`
	Port        int             `json:"server_port"`
	Started     string          `json:"started"`
	Crashed     bool            `json:"crashed"`
	Updating    bool            `json:"updating"`
	Downloading bool            `json:"downloading"`
	Waiting     bool            `json:"waiting_start"`
}

func (s stats) state() string {
	switch {
	case s.Crashed:
		return "crashed"
	case s.Updating || s.Downloading:
		return "updating"
	case s.Waiting:
		return "starting"
	case s.Running:
		return "running"
	}
	return "stopped"
}

// players reads Crafty's player list, which is a Python list rendered as a
// string ("['Steve', 'Alex']"), or a JSON list, or false.
func (s stats) players() []string {
	out := []string{}
	var list []string
	if json.Unmarshal(s.Players, &list) == nil {
		return append(out, list...)
	}
	var str string
	if json.Unmarshal(s.Players, &str) != nil {
		return out
	}
	str = strings.TrimSpace(str)
	if !strings.HasPrefix(str, "[") || !strings.HasSuffix(str, "]") {
		return out
	}
	for _, p := range strings.Split(str[1:len(str)-1], ",") {
		if p = strings.Trim(strings.TrimSpace(p), `'"`); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s stats) summary(srv server) map[string]any {
	out := map[string]any{"id": string(srv.ID), "name": srv.Name, "state": s.state(),
		"players": s.Online, "maxPlayers": s.Max, "cpu": s.CPU, "memoryPercent": s.MemPercent}
	if s.Version != "" {
		out["version"] = s.Version
	}
	var mem string
	if json.Unmarshal(s.Mem, &mem) == nil && mem != "" {
		out["memory"] = mem
	} else if n, err := strconv.ParseFloat(string(s.Mem), 64); err == nil && n > 0 {
		out["memory"] = fmt.Sprintf("%.0f", n)
	}
	if s.Port > 0 {
		out["port"] = s.Port
	} else if srv.Port > 0 {
		out["port"] = srv.Port
	}
	return out
}

func (c *conn) servers(ctx context.Context) ([]server, error) {
	return get[[]server](ctx, c, "/servers", nil)
}

type input struct {
	Server       flexID `json:"server"`
	Command      string `json:"command"`
	BackupConfig string `json:"backupConfig"`
	Lines        int    `json:"lines"`
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

// backupConf is one backup configuration (Crafty 4.4 and later name them;
// older ones have a single unnamed one).
type backupConf struct {
	ID       string `json:"backup_id"`
	Name     string `json:"backup_name"`
	Max      *int   `json:"max_backups"`
	Shutdown bool   `json:"shutdown"`
	Default  bool   `json:"default"`
}

// unwrap returns the data of a {"status":…,"data":…} answer, or the answer
// itself (some of Crafty's backup routes answer bare).
func unwrap(raw json.RawMessage) json.RawMessage {
	var e struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Status != "" && len(e.Data) > 0 {
		return e.Data
	}
	return raw
}

// backupConfs reads the server's backup configurations: a map of id to
// configuration (4.4 and later), a list, or one configuration.
func (c *conn) backupConfs(ctx context.Context, id string) ([]backupConf, error) {
	var raw json.RawMessage
	if _, err := c.api.Do(ctx, http.MethodGet, "/servers/"+id+"/backups", nil, nil, &raw); err != nil {
		return nil, err
	}
	raw = unwrap(raw)
	var list []backupConf
	if json.Unmarshal(raw, &list) == nil {
		return list, nil
	}
	var one backupConf
	if json.Unmarshal(raw, &one) == nil && one.Max != nil {
		return []backupConf{one}, nil
	}
	var byID map[string]backupConf
	if err := json.Unmarshal(raw, &byID); err != nil {
		return nil, errors.New("unexpected backup settings from Crafty")
	}
	for k, b := range byID {
		if b.ID == "" {
			b.ID = k
		}
		list = append(list, b)
	}
	return list, nil
}

// backupPlan says what a backup will do: how many backups the
// configuration keeps and has now (so how many Crafty deletes), and
// whether it shuts the server down. What can't be read is said plainly.
func (c *conn) backupPlan(ctx context.Context, srv server, id, cfgID string, st stats) *sdk.Plan {
	name := "its default backup settings"
	if cfgID != "" {
		name = "backup configuration " + cfgID
	}
	sum := fmt.Sprintf("Back up %s with %s", srv.Name, name)
	before := map[string]any{}
	confs, err := c.backupConfs(ctx, id)
	var conf *backupConf
	for i, b := range confs {
		if (cfgID != "" && strings.EqualFold(b.ID, cfgID)) || (cfgID == "" && (b.Default || len(confs) == 1)) {
			conf = &confs[i]
			break
		}
	}
	if err != nil || conf == nil {
		sum += ". Couldn't read the backup configuration, so how many old backups Crafty deletes, and whether it shuts the server down, is unknown"
		return plan(sum, "server "+srv.Name, "backup", nil, nil)
	}
	if conf.Name != "" {
		sum = fmt.Sprintf("Back up %s with backup configuration %q", srv.Name, conf.Name)
	}
	count := -1
	if conf.ID != "" && uuidRe.MatchString(strings.ToLower(conf.ID)) {
		var files struct {
			Total *int `json:"total"`
		}
		var raw json.RawMessage
		if _, err := c.api.Do(ctx, http.MethodGet, "/servers/"+id+"/backups/backup/"+strings.ToLower(conf.ID)+"/files", nil, nil, &raw); err == nil &&
			json.Unmarshal(unwrap(raw), &files) == nil && files.Total != nil {
			count = *files.Total
		}
	}
	keep := 0
	if conf.Max != nil {
		keep = *conf.Max
	}
	before["maxBackups"] = keep
	switch {
	case keep <= 0:
		sum += "; it keeps every backup (no maximum)"
	case count >= 0:
		before["backups"] = count
		sum += fmt.Sprintf("; it keeps at most %d and has %d now", keep, count)
		if drop := count + 1 - keep; drop > 0 {
			sum += fmt.Sprintf(", so Crafty deletes the %d oldest", drop)
		}
	default:
		sum += fmt.Sprintf("; it keeps at most %d (the current count couldn't be read), and Crafty deletes the oldest beyond that", keep)
	}
	before["shutdown"] = conf.Shutdown
	if conf.Shutdown {
		sum += "; it shuts the server down while backing up"
		if st.Online > 0 {
			sum += fmt.Sprintf(", disconnecting %d players", st.Online)
		}
	}
	return plan(sum, "server "+srv.Name, "backup", before, nil)
}

var actions = map[string]bool{"servers": true, "stats": true, "start": true, "stop": true, "restart": true, "kill": true, "backup": true, "command": true, "logs": true}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	if !actions[call.Action] {
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
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
			row := map[string]any{"id": string(s.ID), "name": s.Name, "type": s.Type}
			if i < 50 && idRe.MatchString(string(s.ID)) {
				if st, err := get[stats](ctx, c, "/servers/"+string(s.ID)+"/stats", nil); err == nil {
					row = st.summary(s)
					row["type"] = s.Type
				}
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	}

	id := strings.ToLower(strings.TrimSpace(string(p.Server)))
	if !idRe.MatchString(id) {
		return sdk.Result{}, errors.New("enter the server's id (a number or a UUID, from servers)")
	}
	switch call.Action {
	case "command":
		if err := checkLine(p.Command); err != nil {
			return sdk.Result{}, err
		}
	case "backup":
		p.BackupConfig = strings.ToLower(strings.TrimSpace(p.BackupConfig))
		if p.BackupConfig != "" && !uuidRe.MatchString(p.BackupConfig) {
			return sdk.Result{}, errors.New("the backup configuration is a UUID")
		}
	case "logs":
		if p.Lines == 0 {
			p.Lines = 100
		}
		if p.Lines < 1 || p.Lines > 500 {
			return sdk.Result{}, errors.New("lines is 1 to 500")
		}
	}
	srv, err := get[server](ctx, c, "/servers/"+id, nil)
	if err != nil {
		return sdk.Result{}, err
	}
	if srv.Name == "" {
		srv.Name = id
	}
	srv.ID = flexID(id)
	st, err := get[stats](ctx, c, "/servers/"+id+"/stats", nil)
	if err != nil {
		return sdk.Result{}, err
	}

	switch call.Action {
	case "stats":
		out := st.summary(srv)
		out["online"] = st.players()
		for k, v := range map[string]string{"motd": st.Desc, "world": st.World, "worldSize": st.WorldSize, "started": st.Started} {
			if v != "" {
				out[k] = v
			}
		}
		return sdk.JSON(out)

	case "start", "stop", "restart", "kill":
		state := st.state()
		switch {
		case call.Action == "start" && (state == "running" || state == "starting"):
			return sdk.Result{}, fmt.Errorf("%s is already %s", srv.Name, state)
		case (call.Action == "stop" || call.Action == "kill") && state == "stopped":
			return sdk.Result{}, fmt.Errorf("%s is already stopped", srv.Name)
		}
		if call.DryRun {
			after := map[string]string{"start": "running", "stop": "stopped", "kill": "stopped", "restart": "running"}[call.Action]
			sum := fmt.Sprintf("%s server %s", strings.ToUpper(call.Action[:1])+call.Action[1:], srv.Name)
			if st.Online > 0 && call.Action != "start" {
				sum += fmt.Sprintf("; %d players are disconnected", st.Online)
			}
			if call.Action == "kill" {
				sum += "; the process ends without saving"
			}
			return sdk.Result{Plan: plan(sum, "server "+srv.Name, call.Action, map[string]any{"state": state, "players": st.Online}, map[string]string{"state": after})}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/servers/"+id+"/action/"+call.Action+"_server", nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"server": srv.Name, "done": call.Action})
		switch call.Action {
		case "start":
			res.Undo = sdk.UndoWith("stop", map[string]string{"server": id}, "Stop "+srv.Name)
		case "stop", "kill":
			res.Undo = sdk.UndoWith("start", map[string]string{"server": id}, "Start "+srv.Name)
		}
		return res, err

	case "backup":
		if call.DryRun {
			return sdk.Result{Plan: c.backupPlan(ctx, srv, id, p.BackupConfig, st)}, nil
		}
		path := "/servers/" + id + "/action/backup_server"
		if p.BackupConfig != "" {
			path += "/" + p.BackupConfig
		}
		if _, err := c.api.Do(ctx, http.MethodPost, path, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"server": srv.Name, "backup": "started"})

	case "command":
		if call.DryRun {
			return sdk.Result{Plan: plan(fmt.Sprintf("Run on %s's console: %s", srv.Name, p.Command), "server "+srv.Name, "command", nil, map[string]string{"command": p.Command})}, nil
		}
		if !st.Running {
			return sdk.Result{}, fmt.Errorf("%s isn't running, so it can't take commands", srv.Name)
		}
		res, err := c.api.Send(ctx, http.MethodPost, "/servers/"+id+"/stdin", nil, strings.NewReader(p.Command), http.Header{"Content-Type": {"text/plain; charset=utf-8"}})
		if err != nil {
			return sdk.Result{}, err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
		res.Body.Close()
		return sdk.JSON(map[string]any{"server": srv.Name, "sent": true})

	case "logs":
		lines, err := get[[]string](ctx, c, "/servers/"+id+"/logs", url.Values{"file": {"true"}, "colors": {"false"}, "raw": {"true"}})
		if err != nil {
			return sdk.Result{}, err
		}
		if len(lines) > p.Lines {
			lines = lines[len(lines)-p.Lines:]
		}
		return sdk.JSON(map[string]any{"server": srv.Name, "lines": lines})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
