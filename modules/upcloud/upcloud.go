// Package upcloud manages UpCloud servers through the UpCloud API 1.3:
// status, start, stop and restart, storage devices and account credits.
package upcloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one UpCloud API user.
type Config struct {
	Username string `json:"username"` // an API (sub-account) user name
	Password string `json:"password"` // secret:// its password
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.upcloud.com/1.3 (tests).
	Base string
}

// New returns the UpCloud module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.upcloud.com/1.3"

var (
	uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	userRe = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	one := sdk.Schema(`{"type":"object","required":["server"],"properties":{"server":{"type":"string","description":"Server UUID (from Servers)"}}}`)
	return sdk.Manifest{
		ID: "upcloud", Name: "UpCloud", Version: "0.1.0", Category: "Infrastructure", Icon: "server",
		Description: "Your UpCloud servers: state, zone and plan, start, stop and restart; storage devices and account credits.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["username","password"],"properties":{
			"username":{"type":"string","description":"An API user (People, a sub-account with API connections allowed). Give it only the servers and storage Conduit should see"},
			"password":{"type":"string","x-secret":true,"description":"That user's password"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "servers", Title: "Servers", Description: "State, zone, plan, cores, memory and addresses.", Risk: sdk.RiskRead},
			{Name: "storages", Title: "Storage", Description: "The account's storage devices and backups: type, size, tier, state and zone.", Risk: sdk.RiskRead},
			{Name: "credits", Title: "Credits", Description: "The account's remaining credits.", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "start", Title: "Start a server", Description: "Starts a stopped server. Undo stops it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: one},
			{Name: "stop", Title: "Stop a server", Description: "Shuts a server down (soft, then hard after 60 seconds if the OS doesn't stop). Its services go down until it's started, and it's still billed (destructive). Undo starts it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: one},
			{Name: "restart", Title: "Restart a server", Description: "Soft-restarts a running server; its services go down while it restarts (destructive).", Risk: sdk.RiskDestructive, DryRun: true, Input: one},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	c.Username = strings.TrimSpace(c.Username)
	if strings.HasPrefix(c.Username, "secret://") {
		return errors.New("enter the user name as it is; only the password goes in the vault")
	}
	if !userRe.MatchString(c.Username) {
		return errors.New("enter the API user's name (letters, digits and . _ @ + -)")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	user, ref := c.Username, c.Password
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		pw, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.SetBasicAuth(user, strings.TrimRight(pw, "\r\n"))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("UpCloud refused the user name and password (and the user needs API connections allowed)")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("UpCloud refused: this user can't do this (check its permissions and allowed addresses)")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusConflict):
		return fmt.Errorf("UpCloud refused: %s is busy or in the wrong state for this", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("UpCloud's rate limit was hit; try again in a moment")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, body, out any, what string) error {
	_, err := c.api.Do(ctx, method, path, nil, body, out)
	return friendly(err, what)
}

type server struct {
	UUID     string `json:"uuid"`
	Hostname string `json:"hostname"`
	Title    string `json:"title"`
	State    string `json:"state"`
	Zone     string `json:"zone"`
	Plan     string `json:"plan"`
	Cores    any    `json:"core_number"`   // a string in lists
	Memory   any    `json:"memory_amount"` // MiB, a string in lists
	Tags     struct {
		Tag []string `json:"tag"`
	} `json:"tags"`
}

func (s server) name() string {
	if s.Title != "" {
		return s.Title
	}
	return s.Hostname
}

func (c *conn) servers(ctx context.Context) ([]server, error) {
	var r struct {
		Servers struct {
			Server []server `json:"server"`
		} `json:"servers"`
	}
	err := c.do(ctx, http.MethodGet, "/server", nil, &r, "server list")
	return r.Servers.Server, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	list, err := c.servers(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	off, broken := 0, 0
	for _, s := range list {
		switch s.State {
		case "started":
		case "error":
			broken++
		default:
			off++
		}
	}
	msg := fmt.Sprintf("%d servers", len(list))
	if off > 0 {
		msg += fmt.Sprintf(", %d not started", off)
	}
	if broken > 0 {
		return sdk.Health{Status: "degraded", Message: msg + fmt.Sprintf(", %d in error", broken)}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

func state(s string) json.RawMessage { b, _ := json.Marshal(map[string]string{"state": s}); return b }

func num(v any) any {
	if s, ok := v.(string); ok {
		if i, err := strconv.Atoi(s); err == nil {
			return i
		}
		return s
	}
	return v
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Server string `json:"server"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "servers":
		list, err := c.servers(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			UUID     string   `json:"uuid"`
			Name     string   `json:"name"`
			Hostname string   `json:"hostname"`
			State    string   `json:"state"`
			Zone     string   `json:"zone"`
			Plan     string   `json:"plan"`
			Cores    any      `json:"cores"`
			MemoryMB any      `json:"memoryMb"`
			Tags     []string `json:"tags,omitempty"`
		}
		out := []row{}
		for _, s := range list {
			out = append(out, row{UUID: s.UUID, Name: s.name(), Hostname: s.Hostname, State: s.State, Zone: s.Zone, Plan: s.Plan,
				Cores: num(s.Cores), MemoryMB: num(s.Memory), Tags: s.Tags.Tag})
		}
		return sdk.JSON(out)

	case "storages":
		var r struct {
			Storages struct {
				Storage []struct {
					UUID  string `json:"uuid"`
					Title string `json:"title"`
					Type  string `json:"type"`
					Size  int    `json:"size"`
					State string `json:"state"`
					Tier  string `json:"tier"`
					Zone  string `json:"zone"`
				} `json:"storage"`
			} `json:"storages"`
		}
		if err := c.do(ctx, http.MethodGet, "/storage/private", nil, &r, "storage list"); err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			UUID   string `json:"uuid"`
			Title  string `json:"title"`
			Type   string `json:"type"`
			SizeGB int    `json:"sizeGb"`
			State  string `json:"state"`
			Tier   string `json:"tier,omitempty"`
			Zone   string `json:"zone"`
		}
		out := []row{}
		for _, s := range r.Storages.Storage {
			out = append(out, row{UUID: s.UUID, Title: s.Title, Type: s.Type, SizeGB: s.Size, State: s.State, Tier: s.Tier, Zone: s.Zone})
		}
		return sdk.JSON(out)

	case "credits":
		// Only the credits: the account also carries the user name and
		// resource limits.
		var r struct {
			Account struct {
				Credits float64 `json:"credits"`
			} `json:"account"`
		}
		if err := c.do(ctx, http.MethodGet, "/account", nil, &r, "account"); err != nil {
			return sdk.Result{}, err
		}
		cr := r.Account.Credits
		return sdk.JSON(map[string]any{"credits": cr, "amount": math.Round(cr) / 100, "note": "UpCloud reports credits in cents of the account's currency; amount is in whole units"})

	case "start", "stop", "restart":
		if !uuidRe.MatchString(p.Server) {
			return sdk.Result{}, errors.New("which server? (its UUID, from Servers)")
		}
		var r struct {
			Server server `json:"server"`
		}
		if err := c.do(ctx, http.MethodGet, "/server/"+p.Server, nil, &r, "such server"); err != nil {
			return sdk.Result{}, err
		}
		s := r.Server
		target := s.name() + " (" + p.Server + ")"
		switch call.Action {
		case "start":
			if s.State != "stopped" {
				return sdk.Result{}, fmt.Errorf("%s is %s; only a stopped server can be started", target, s.State)
			}
		case "stop", "restart":
			if s.State != "started" {
				return sdk.Result{}, fmt.Errorf("%s is %s; only a started server can be stopped or restarted", target, s.State)
			}
		}
		want := map[string]string{"start": "started", "stop": "stopped", "restart": "started"}[call.Action]
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: call.Action + " " + target,
				Changes: []sdk.Change{{Target: target, Op: call.Action, Before: state(s.State), After: state(want)}}}}, nil
		}
		var body any
		switch call.Action {
		case "stop":
			body = map[string]any{"stop_server": map[string]string{"stop_type": "soft", "timeout": "60"}}
		case "restart":
			body = map[string]any{"restart_server": map[string]string{"stop_type": "soft", "timeout": "60", "timeout_action": "ignore"}}
		}
		if err := c.do(ctx, http.MethodPost, "/server/"+p.Server+"/"+call.Action, body, nil, "such server"); err != nil {
			return sdk.Result{}, err
		}
		res, _ := sdk.JSON(map[string]any{"server": target, "was": s.State, "requested": call.Action})
		switch call.Action {
		case "start":
			res.Undo = sdk.UndoWith("stop", map[string]string{"server": p.Server}, "Stop "+s.name()+" again")
		case "stop":
			res.Undo = sdk.UndoWith("start", map[string]string{"server": p.Server}, "Start "+s.name()+" again")
		}
		return res, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
