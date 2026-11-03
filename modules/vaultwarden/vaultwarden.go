// Package vaultwarden watches a Vaultwarden server: is it up, which version,
// and (with the admin token) how many accounts it has and how many lack
// two-factor sign-in. It never reads vault items and changes nothing.
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Vaultwarden server.
type Config struct {
	URL        string `json:"url"`        // e.g. https://vault.example.com
	AdminToken string `json:"adminToken"` // optional secret:// ADMIN_TOKEN, for account counts
}

type conn struct {
	base  string
	admin string
	host  sdk.Host
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Vaultwarden module.
func New() *Module { return &Module{} }

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "vaultwarden", Name: "Vaultwarden", Version: "0.1.0", Category: "Security", Icon: "shield",
		Description: "Keeps an eye on your Vaultwarden server: up or down, version, and how many accounts are missing two-factor sign-in. Never touches passwords.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://vault.example.com"},
			"adminToken":{"type":"string","x-secret":true,"description":"Optional: the ADMIN_TOKEN, for account counts (the /admin page must be enabled)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Server status", Description: "Whether it answers, how fast, and the version it reports.", Risk: sdk.RiskRead},
			{Name: "accounts", Title: "Accounts", Description: "Counts of accounts: total, disabled, without two-factor, not seen for 90 days. No names or emails.", Risk: sdk.RiskRead},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" {
		return errors.New("the address is like https://vault.example.com")
	}
	if c.AdminToken != "" && !strings.HasPrefix(c.AdminToken, "secret://") {
		return errors.New("store the admin token in the vault and enter its secret:// reference")
	}
	m.set.Put(id, &conn{base: u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/"), admin: c.AdminToken, host: h})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (m *Module) client() *http.Client {
	c := &http.Client{Timeout: 20 * time.Second}
	if m.HTTP != nil {
		cp := *m.HTTP
		c = &cp
	}
	// The admin login answers with a redirect that carries the cookie.
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func (m *Module) get(ctx context.Context, c *conn, path, cookie string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Conduit")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	res, err := m.client().Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return res.StatusCode, err
	}
	if res.StatusCode >= 300 {
		return res.StatusCode, fmt.Errorf("%s answered %s", path, res.Status)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return res.StatusCode, fmt.Errorf("unexpected answer from %s", path)
		}
	}
	return res.StatusCode, nil
}

// login trades the admin token for the admin session cookie.
func (m *Module) login(ctx context.Context, c *conn) (string, error) {
	tok, err := c.host.Secret(ctx, c.admin)
	if err != nil {
		return "", err
	}
	form := url.Values{"token": {strings.TrimSpace(tok)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/admin", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Conduit")
	res, err := m.client().Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
	for _, ck := range res.Cookies() {
		if ck.Name == "VW_ADMIN" && ck.Value != "" {
			return ck.Name + "=" + ck.Value, nil
		}
	}
	switch res.StatusCode {
	case http.StatusNotFound:
		return "", errors.New("the admin page is turned off on this server (set ADMIN_TOKEN)")
	case http.StatusTooManyRequests:
		return "", errors.New("too many admin sign-ins; the server is rate limiting")
	}
	return "", errors.New("the server refused the admin token")
}

type status struct {
	Up        bool   `json:"up"`
	LatencyMS int64  `json:"latencyMs"`
	Version   string `json:"version,omitempty"`
	Server    string `json:"server,omitempty"`
	Vault     string `json:"vault,omitempty"`
}

func (m *Module) status(ctx context.Context, c *conn) (status, error) {
	start := time.Now()
	var alive any
	if _, err := m.get(ctx, c, "/alive", "", &alive); err != nil {
		return status{}, err
	}
	s := status{Up: true, LatencyMS: time.Since(start).Milliseconds()}
	var cfg struct {
		Version string `json:"version"`
		Server  *struct {
			Name string `json:"name"`
		} `json:"server"`
		Environment struct {
			Vault string `json:"vault"`
		} `json:"environment"`
	}
	if _, err := m.get(ctx, c, "/api/config", "", &cfg); err == nil {
		s.Version = cfg.Version
		s.Vault = cfg.Environment.Vault
		if cfg.Server != nil {
			s.Server = cfg.Server.Name
		}
	}
	return s, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	s, err := m.status(ctx, c)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := strings.TrimSpace(s.Server + " " + s.Version)
	if s.LatencyMS > 3000 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("slow: %d ms", s.LatencyMS)}
	}
	if msg == "" {
		msg = "up"
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "status":
		s, err := m.status(ctx, c)
		if err != nil {
			return sdk.JSON(status{Up: false})
		}
		return sdk.JSON(s)

	case "accounts":
		if c.admin == "" {
			return sdk.Result{}, errors.New("add the admin token in this module's settings to see account counts")
		}
		cookie, err := m.login(ctx, c)
		if err != nil {
			return sdk.Result{}, err
		}
		var users []struct {
			Enabled    *bool  `json:"_enabled"`
			TwoFactor  bool   `json:"twoFactorEnabled"`
			LastActive string `json:"lastActive"`
			Created    string `json:"createdAt"`
		}
		if _, err := m.get(ctx, c, "/admin/users", cookie, &users); err != nil {
			return sdk.Result{}, err
		}
		cutoff := time.Now().AddDate(0, 0, -90)
		var total, disabled, no2fa, idle int
		for _, u := range users {
			total++
			if u.Enabled != nil && !*u.Enabled {
				disabled++
				continue
			}
			if !u.TwoFactor {
				no2fa++
			}
			if t, err := parseTime(u.LastActive); err == nil && t.Before(cutoff) {
				idle++
			}
		}
		return sdk.JSON(map[string]int{"total": total, "disabled": disabled, "withoutTwoFactor": no2fa, "idle90Days": idle})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// parseTime reads the admin API's dates ("2026-11-03 12:00:00 UTC" or RFC 3339).
func parseTime(s string) (time.Time, error) {
	for _, f := range []string{time.RFC3339, "2006-01-02 15:04:05 MST", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("no date")
}
