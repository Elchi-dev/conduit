// Package tailscale lists and manages the devices of a tailnet through the
// Tailscale API, and warns before device keys expire.
package tailscale

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
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one tailnet. Use an API key, or an OAuth client (preferred:
// scoped and doesn't expire with a person's account).
type Config struct {
	Tailnet      string `json:"tailnet"`      // "-" (the key's default tailnet) or the tailnet name
	APIKey       string `json:"apiKey"`       // secret:// tskey-api-…
	ClientID     string `json:"clientId"`     // OAuth client id
	ClientSecret string `json:"clientSecret"` // secret:// OAuth client secret
	API          string `json:"api"`          // default https://api.tailscale.com (tests)
}

type conn struct {
	cfg  Config
	api  *rest.Client
	http *http.Client
	host sdk.Host

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
	now  func() time.Time
}

// New returns the Tailscale module.
func New() *Module { return &Module{now: time.Now} }

// ExpiryWarning is how far ahead health warns about expiring device keys.
const ExpiryWarning = 14 * 24 * time.Hour

var (
	tailnetRe = regexp.MustCompile(`^(-|[A-Za-z0-9][A-Za-z0-9._@-]{0,99})$`)
	deviceRe  = regexp.MustCompile(`^[A-Za-z0-9]{1,40}$`)
	tagRe     = regexp.MustCompile(`^tag:[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)
	clientRe  = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	dev := `"device":{"type":"string","description":"Device id (from Devices)"}`
	return sdk.Manifest{
		ID: "tailscale", Name: "Tailscale", Version: "0.1.0", Category: "Network", Icon: "network",
		Description: "The devices of your tailnet: who's online, addresses, key expiry; authorize, tag or remove devices.",
		Presets:     []string{"homelab", "developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"tailnet":{"type":"string","default":"-","description":"Leave as - for the key's own tailnet"},
			"apiKey":{"type":"string","x-secret":true,"description":"An API access token (admin console, Settings, Keys); expires after at most 90 days"},
			"clientId":{"type":"string","description":"Or an OAuth client id (Settings, OAuth clients), preferred"},
			"clientSecret":{"type":"string","x-secret":true,"description":"The OAuth client's secret"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "devices", Title: "Devices", Description: "Online state, last seen, OS, addresses, key expiry and tags.", Risk: sdk.RiskRead},
			{Name: "dns", Title: "DNS settings", Description: "Nameservers, MagicDNS and search domains.", Risk: sdk.RiskRead},
			{Name: "acl", Title: "Access policy", Description: "The tailnet's policy file.", Risk: sdk.RiskRead},
			{Name: "authorize", Title: "Authorize a device", Risk: sdk.RiskWrite, Input: sdk.Schema(`{"type":"object","required":["device"],"properties":{` + dev + `}}`)},
			{Name: "set_tags", Title: "Set a device's tags", Description: "Replaces its tags; tags decide what the access policy lets it reach.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["device","tags"],"properties":{` + dev + `,"tags":{"type":"array","items":{"type":"string","pattern":"^tag:"}}}}`)},
			{Name: "expire_key", Title: "Expire a device's key", Description: "The device has to log in again.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["device"],"properties":{` + dev + `}}`)},
			{Name: "delete", Title: "Remove a device", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(`{"type":"object","required":["device"],"properties":{` + dev + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if c.Tailnet == "" {
		c.Tailnet = "-"
	}
	if !tailnetRe.MatchString(c.Tailnet) {
		return errors.New("the tailnet is - or its name, like example.com")
	}
	oauth := c.ClientID != "" || c.ClientSecret != ""
	switch {
	case oauth && (c.ClientID == "" || c.ClientSecret == ""):
		return errors.New("an OAuth client needs both its id and its secret")
	case oauth && !clientRe.MatchString(c.ClientID):
		return errors.New("the OAuth client id is letters and digits")
	case !oauth && c.APIKey == "":
		return errors.New("add an API key or an OAuth client (stored in the vault)")
	}
	if c.API == "" {
		c.API = "https://api.tailscale.com"
	}
	cn := &conn{cfg: c, host: h, http: m.HTTP}
	if cn.http == nil {
		cn.http = &http.Client{Timeout: 30 * time.Second}
	}
	cn.api = rest.New(strings.TrimRight(c.API, "/")+"/api/v2", func(ctx context.Context, r *http.Request) error {
		tok, err := cn.bearer(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		return nil
	})
	cn.api.HTTP = cn.http
	m.set.Put(id, cn)
	return nil
}

// bearer returns the API key, or a cached OAuth access token.
func (c *conn) bearer(ctx context.Context) (string, error) {
	if c.cfg.ClientID == "" {
		k, err := c.host.Secret(ctx, c.cfg.APIKey)
		return strings.TrimSpace(k), err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expires.Add(-time.Minute)) {
		return c.token, nil
	}
	sec, err := c.host.Secret(ctx, c.cfg.ClientSecret)
	if err != nil {
		return "", err
	}
	form := url.Values{"client_id": {c.cfg.ClientID}, "client_secret": {strings.TrimSpace(sec)}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.API, "/")+"/api/v2/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(res.Body).Decode(&t) != nil || t.AccessToken == "" {
		return "", fmt.Errorf("Tailscale refused the OAuth client (%s)", res.Status)
	}
	c.token, c.expires = t.AccessToken, time.Now().Add(time.Duration(t.ExpiresIn)*time.Second)
	return c.token, nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

type device struct {
	ID                 string   `json:"id"`
	NodeID             string   `json:"nodeId"`
	Name               string   `json:"name"`
	Hostname           string   `json:"hostname"`
	OS                 string   `json:"os"`
	User               string   `json:"user"`
	Addresses          []string `json:"addresses"`
	LastSeen           string   `json:"lastSeen"`
	Expires            string   `json:"expires"`
	KeyExpiryDisabled  bool     `json:"keyExpiryDisabled"`
	Authorized         bool     `json:"authorized"`
	ConnectedToControl *bool    `json:"connectedToControl"`
	UpdateAvailable    bool     `json:"updateAvailable"`
	Tags               []string `json:"tags"`
}

func (c *conn) devices(ctx context.Context) ([]device, error) {
	var res struct {
		Devices []device `json:"devices"`
	}
	_, err := c.api.Do(ctx, "GET", "/tailnet/"+url.PathEscape(c.cfg.Tailnet)+"/devices", url.Values{"fields": {"all"}}, nil, &res)
	return res.Devices, err
}

func (m *Module) expiringSoon(d device) (time.Time, bool) {
	if d.KeyExpiryDisabled || d.Expires == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, d.Expires)
	if err != nil || t.Year() < 2000 {
		return time.Time{}, false
	}
	return t, t.Sub(m.now()) < ExpiryWarning
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ds, err := c.devices(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var soon []string
	online := 0
	for _, d := range ds {
		if d.ConnectedToControl != nil && *d.ConnectedToControl {
			online++
		}
		if t, ok := m.expiringSoon(d); ok {
			when := "has expired"
			if t.After(m.now()) {
				when = "expires " + t.Format("2 Jan")
			}
			soon = append(soon, d.Hostname+" "+when)
		}
	}
	if len(soon) > 0 {
		sort.Strings(soon)
		return sdk.Health{Status: "degraded", Message: "Key " + strings.Join(soon, "; ")}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d devices, %d online", len(ds), online)}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Device string   `json:"device"`
		Tags   []string `json:"tags"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	tn := "/tailnet/" + url.PathEscape(c.cfg.Tailnet)
	switch call.Action {
	case "devices":
		ds, err := c.devices(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range ds {
			row := map[string]any{"id": d.ID, "name": d.Hostname, "dnsName": d.Name, "os": d.OS, "user": d.User, "addresses": d.Addresses,
				"lastSeen": d.LastSeen, "authorized": d.Authorized, "tags": d.Tags, "updateAvailable": d.UpdateAvailable}
			if d.ConnectedToControl != nil {
				row["online"] = *d.ConnectedToControl
			}
			if d.KeyExpiryDisabled {
				row["keyExpires"] = "never"
			} else {
				row["keyExpires"] = d.Expires
				if _, soon := m.expiringSoon(d); soon {
					row["keyExpiresSoon"] = true
				}
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "dns":
		out := map[string]json.RawMessage{}
		for k, path := range map[string]string{"nameservers": "/dns/nameservers", "preferences": "/dns/preferences", "searchPaths": "/dns/searchpaths"} {
			var v json.RawMessage
			if _, err := c.api.Do(ctx, "GET", tn+path, nil, nil, &v); err != nil {
				return sdk.Result{}, err
			}
			out[k] = v
		}
		return sdk.JSON(out)

	case "acl":
		var v json.RawMessage
		if _, err := c.api.Do(ctx, "GET", tn+"/acl", nil, nil, &v); err != nil {
			return sdk.Result{}, err
		}
		return sdk.Result{Output: v}, nil
	}

	if !deviceRe.MatchString(p.Device) {
		return sdk.Result{}, errors.New("a device is its id from the device list")
	}
	dp := "/device/" + p.Device
	var cur device
	if _, err := c.api.Do(ctx, "GET", dp, url.Values{"fields": {"all"}}, nil, &cur); err != nil {
		return sdk.Result{}, err
	}
	label := cur.Hostname
	if label == "" {
		label = p.Device
	}
	switch call.Action {
	case "authorize":
		if _, err := c.api.Do(ctx, "POST", dp+"/authorized", nil, map[string]bool{"authorized": true}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"authorized": label})

	case "set_tags":
		tags := []string{}
		for _, t := range p.Tags {
			if !tagRe.MatchString(t) {
				return sdk.Result{}, fmt.Errorf("%q isn't a tag; tags look like tag:server", t)
			}
			tags = append(tags, t)
		}
		before := cur.Tags
		if before == nil {
			before = []string{}
		}
		if call.DryRun {
			b, _ := json.Marshal(before)
			a, _ := json.Marshal(tags)
			return sdk.Result{Plan: &sdk.Plan{Summary: "Set the tags of " + label, Changes: []sdk.Change{{Target: label, Op: "update", Before: b, After: a}}}}, nil
		}
		if _, err := c.api.Do(ctx, "POST", dp+"/tags", nil, map[string][]string{"tags": tags}, nil); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"device": label, "tags": tags})
		r.Undo = sdk.UndoWith("set_tags", map[string]any{"device": p.Device, "tags": before}, "Put the old tags back")
		return r, nil

	case "expire_key", "delete":
		if call.DryRun {
			sum := map[string]string{"expire_key": "Expire the key of ", "delete": "Remove "}[call.Action] + label
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: label, Op: map[string]string{"expire_key": "expire", "delete": "delete"}[call.Action]}}}}, nil
		}
		var err error
		if call.Action == "delete" {
			_, err = c.api.Do(ctx, "DELETE", dp, nil, nil, nil)
		} else {
			_, err = c.api.Do(ctx, "POST", dp+"/expire", nil, map[string]any{}, nil)
		}
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{call.Action: label})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
