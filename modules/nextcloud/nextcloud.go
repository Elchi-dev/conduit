// Package nextcloud reads a Nextcloud server's health and storage, your
// notifications, and shares files by link.
package nextcloud

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
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Nextcloud account.
type Config struct {
	URL         string `json:"url"`
	User        string `json:"user"`
	AppPassword string `json:"appPassword"` // secret://
}

type conn struct {
	cfg Config
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Nextcloud module.
func New() *Module { return &Module{} }

var (
	userRe  = regexp.MustCompile(`^[A-Za-z0-9_.@\- ]{1,64}$`)
	shareRe = regexp.MustCompile(`^[0-9]{1,12}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "nextcloud", Name: "Nextcloud", Version: "0.1.0", Category: "Storage", Icon: "cloud",
		Description: "Server version, storage and active users, your notifications, and sharing files by link.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","user","appPassword"],"properties":{
			"url":{"type":"string","description":"e.g. https://cloud.example.com"},
			"user":{"type":"string","description":"Your user name"},
			"appPassword":{"type":"string","x-secret":true,"description":"An app password (Personal settings, Security, Devices & sessions)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "server", Title: "Server", Description: "Version, free space, files, users and who was active (needs an admin account).", Risk: sdk.RiskRead},
			{Name: "notifications", Title: "Notifications", Risk: sdk.RiskRead},
			{Name: "usage", Title: "Storage used", Description: "How much a user stores, and their quota.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"user":{"type":"string","description":"Default: you"}}}`)},
			{Name: "share", Title: "Share a file by link", Description: "A read-only public link, optionally with a password and an expiry date.", Risk: sdk.RiskDestructive, Reversible: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["path"],"properties":{"path":{"type":"string","description":"e.g. /Documents/report.pdf"},"password":{"type":"string"},"expires":{"type":"string","format":"date","description":"YYYY-MM-DD"}}}`)},
			{Name: "unshare", Title: "Remove a share", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return errors.New("the address is like https://cloud.example.com")
	}
	if !userRe.MatchString(c.User) {
		return errors.New("enter your Nextcloud user name")
	}
	if !strings.HasPrefix(c.AppPassword, "secret://") {
		return errors.New("store the app password in the vault and enter its secret:// reference")
	}
	ref, user := c.AppPassword, c.User
	api := rest.New(strings.TrimRight(u.String(), "/"), func(ctx context.Context, r *http.Request) error {
		pw, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.SetBasicAuth(user, pw)
		r.Header.Set("OCS-APIRequest", "true")
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	}
	m.set.Put(id, &conn{cfg: c, api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// ocs calls an OCS endpoint and unwraps {"ocs":{"meta":…,"data":…}}.
func (c *conn) ocs(ctx context.Context, method, path string, q url.Values, body, out any) error {
	if q == nil {
		q = url.Values{}
	}
	q.Set("format", "json")
	var env struct {
		OCS struct {
			Meta struct {
				Status     string `json:"status"`
				StatusCode int    `json:"statuscode"`
				Message    string `json:"message"`
			} `json:"meta"`
			Data json.RawMessage `json:"data"`
		} `json:"ocs"`
	}
	_, err := c.api.Do(ctx, method, path, q, body, &env)
	if err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) {
			return errors.New("Nextcloud refused the app password")
		}
		return err
	}
	if env.OCS.Meta.Status != "" && env.OCS.Meta.Status != "ok" {
		msg := env.OCS.Meta.Message
		if msg == "" {
			msg = "status " + strconv.Itoa(env.OCS.Meta.StatusCode)
		}
		return errors.New("Nextcloud: " + msg)
	}
	if out != nil && len(env.OCS.Data) > 0 {
		return json.Unmarshal(env.OCS.Data, out)
	}
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		DisplayName string `json:"displayname"`
	}
	if err := c.ocs(ctx, "GET", "/ocs/v2.php/cloud/user", nil, nil, &me); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "Signed in as " + me.DisplayName}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		User     string `json:"user"`
		Path     string `json:"path"`
		Password string `json:"password"`
		Expires  string `json:"expires"`
		ID       string `json:"id"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "server":
		var info struct {
			Nextcloud struct {
				System struct {
					Version   string `json:"version"`
					FreeSpace int64  `json:"freespace"`
				} `json:"system"`
				Storage struct {
					NumUsers int64 `json:"num_users"`
					NumFiles int64 `json:"num_files"`
				} `json:"storage"`
			} `json:"nextcloud"`
			ActiveUsers struct {
				Last5 int64 `json:"last5minutes"`
				Last1 int64 `json:"last1hour"`
				Last  int64 `json:"last24hours"`
			} `json:"activeUsers"`
		}
		if err := c.ocs(ctx, "GET", "/ocs/v2.php/apps/serverinfo/api/v1/info", nil, nil, &info); err != nil {
			return sdk.Result{}, err
		}
		n := info.Nextcloud
		return sdk.JSON(map[string]any{"version": n.System.Version, "freeBytes": n.System.FreeSpace, "users": n.Storage.NumUsers, "files": n.Storage.NumFiles,
			"active": map[string]int64{"last5Minutes": info.ActiveUsers.Last5, "lastHour": info.ActiveUsers.Last1, "lastDay": info.ActiveUsers.Last}})
	case "notifications":
		var ns []struct {
			ID       int64  `json:"notification_id"`
			App      string `json:"app"`
			Subject  string `json:"subject"`
			Message  string `json:"message"`
			Datetime string `json:"datetime"`
			Link     string `json:"link"`
		}
		if err := c.ocs(ctx, "GET", "/ocs/v2.php/apps/notifications/api/v2/notifications", nil, nil, &ns); err != nil {
			return sdk.Result{}, err
		}
		if ns == nil {
			return sdk.JSON([]any{})
		}
		return sdk.JSON(ns)
	case "usage":
		u := p.User
		if u == "" {
			u = c.cfg.User
		}
		if !userRe.MatchString(u) {
			return sdk.Result{}, errors.New("that isn't a user name")
		}
		var info struct {
			Quota struct {
				Used     int64   `json:"used"`
				Total    int64   `json:"total"`
				Quota    float64 `json:"quota"`
				Relative float64 `json:"relative"`
			} `json:"quota"`
		}
		if err := c.ocs(ctx, "GET", "/ocs/v2.php/cloud/users/"+url.PathEscape(u), nil, nil, &info); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"user": u, "usedBytes": info.Quota.Used, "quotaBytes": info.Quota.Quota, "percent": info.Quota.Relative})
	case "share":
		path := "/" + strings.TrimLeft(p.Path, "/")
		if p.Path == "" || strings.Contains(path, "/../") || strings.HasSuffix(path, "/..") || strings.ContainsAny(path, "\x00\r\n") {
			return sdk.Result{}, errors.New("give the file's path in your Nextcloud, like /Documents/report.pdf")
		}
		body := map[string]any{"path": path, "shareType": 3, "permissions": 1}
		if p.Password != "" {
			body["password"] = p.Password
		}
		if p.Expires != "" {
			if _, err := time.Parse("2006-01-02", p.Expires); err != nil {
				return sdk.Result{}, errors.New("the expiry date is YYYY-MM-DD")
			}
			body["expireDate"] = p.Expires
		}
		var sh struct {
			ID  json.Number `json:"id"`
			URL string      `json:"url"`
		}
		if err := c.ocs(ctx, "POST", "/ocs/v2.php/apps/files_sharing/api/v1/shares", nil, body, &sh); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"id": sh.ID.String(), "url": sh.URL, "path": path})
		r.Undo = sdk.UndoWith("unshare", map[string]string{"id": sh.ID.String()}, "Remove the link to "+path)
		return r, nil
	case "unshare":
		if !shareRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("give the share's id")
		}
		if err := c.ocs(ctx, "DELETE", "/ocs/v2.php/apps/files_sharing/api/v1/shares/"+p.ID, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"removed": p.ID})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
