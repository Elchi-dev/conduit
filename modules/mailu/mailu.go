// Package mailu works with a Mailu mail server through its API and the
// API token: domains, users with their quota use, aliases, and disabling or
// enabling users.
package mailu

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

// Config is one Mailu server.
type Config struct {
	URL   string `json:"url"`   // e.g. https://mail.example.com
	Token string `json:"token"` // secret:// API token (API_TOKEN in mailu.env)
	// AllowAdminAccounts lets disable_user and enable_user act on global
	// administrators and on postmaster@, abuse@, admin@ and the like.
	AllowAdminAccounts bool   `json:"allowAdminAccounts"`
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api        *rest.Client
	allowAdmin bool
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Mailu module.
func New() *Module { return &Module{} }

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$`)
	localRe  = regexp.MustCompile(`^[a-z0-9._%+=-]{1,64}$`)
	// Role accounts that mail standards or the server's own reports rely on.
	protected = map[string]bool{"postmaster": true, "abuse": true, "admin": true, "administrator": true, "root": true, "hostmaster": true, "webmaster": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	who := `{"type":"object","required":["email"],"properties":{"email":{"type":"string","description":"The user's address, e.g. jane@example.com"}}}`
	return sdk.Manifest{
		ID: "mailu", Name: "Mailu", Version: "0.1.0", Category: "Communication", Icon: "mail",
		Description: "Mailu: domains, users and their quota use, aliases, and disabling or enabling users.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://mail.example.com"},
			"token":{"type":"string","x-secret":true,"description":"The API token: API_TOKEN in mailu.env (the API must be on). It has full access"},
			"allowAdminAccounts":{"type":"boolean","default":false,"description":"Let Conduit disable or enable global administrators and postmaster@, abuse@, admin@, administrator@, root@, hostmaster@ and webmaster@"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "domains", Title: "Domains", Description: "Domains with user and alias limits, the largest mailbox allowed, sign-up, alternative names and how many managers they have.", Risk: sdk.RiskRead},
			{Name: "users", Title: "Users", Description: "Users with display name, enabled, global admin, quota, storage used and percent, IMAP and POP3, and whether forwarding, auto-reply and the spam filter are on. Addresses and names are personal data, so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"domain":{"type":"string","description":"Only this domain"},"enabled":{"type":"boolean","description":"Only enabled (true) or disabled (false) users"}}}`)},
			{Name: "aliases", Title: "Aliases", Description: "Aliases with their destinations, wildcard and disabled. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"domain":{"type":"string","description":"Only this domain"}}}`)},
			{Name: "disable_user", Title: "Disable a user", Description: "Stops a user signing in to webmail, the admin interface, IMAP and POP3, and sending mail. The mailbox and its mail stay. Refused for global administrators and for a user a role address (postmaster@ and the like) delivers to, unless allowed. Undo enables it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(who)},
			{Name: "enable_user", Title: "Enable a user", Description: "Lets a disabled user sign in and send mail again. Undo disables it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(who)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://mail.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
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
	ref := c.Token
	p := strings.TrimRight(u.Path, "/")
	p = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(p, "/v1"), "/api"), "/admin")
	api := rest.New(u.Scheme+"://"+u.Host+p+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, allowAdmin: c.AllowAdminAccounts})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	// Mailu answers 401 without a token and 403 for a wrong one.
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Mailu refused the API token")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Mailu is rate-limiting this address after failed attempts; wait and try again")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, nil, nil, out)
	return friendly(err)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var ds []struct {
		Name string `json:"name"`
	}
	if err := c.get(ctx, "/domain", &ds); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Mailu API at this address"}
		}
		if rest.IsStatus(err, http.StatusInternalServerError) {
			// What Mailu answers when API_TOKEN isn't set.
			return sdk.Health{Status: "down", Message: err.Error() + " (is API_TOKEN set in mailu.env?)"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d domains", len(ds))}
}

type input struct {
	Domain  string `json:"domain"`
	Enabled *bool  `json:"enabled"`
	Email   string `json:"email"`
}

func cleanDomain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if len(s) > 253 || !domainRe.MatchString(s) {
		return "", errors.New("the domain is a name like example.com")
	}
	return s, nil
}

func cleanAddress(s string) (local, dom string, err error) {
	bad := errors.New("the email is an address like jane@example.com")
	s = strings.ToLower(strings.TrimSpace(s))
	i := strings.LastIndexByte(s, '@')
	if i <= 0 || len(s) > 254 {
		return "", "", bad
	}
	local = s[:i]
	if !localRe.MatchString(local) || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return "", "", bad
	}
	if dom, err = cleanDomain(s[i+1:]); err != nil {
		return "", "", bad
	}
	return local, dom, nil
}

func domainOf(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		return strings.ToLower(addr[i+1:])
	}
	return ""
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
	if strings.TrimSpace(p.Domain) != "" {
		if p.Domain, err = cleanDomain(p.Domain); err != nil {
			return sdk.Result{}, err
		}
	}
	switch call.Action {
	case "domains":
		return c.domains(ctx)
	case "users":
		return c.users(ctx, p)
	case "aliases":
		return c.aliases(ctx, p)
	case "disable_user", "enable_user":
		local, dom, err := cleanAddress(p.Email)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.setEnabled(ctx, call, local, dom)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) domains(ctx context.Context) (sdk.Result, error) {
	// Decoded field by field: DNS records (DKIM among them) aren't read.
	var ds []struct {
		Name          string   `json:"name"`
		Comment       string   `json:"comment"`
		Managers      []string `json:"managers"`
		MaxUsers      *int     `json:"max_users"`
		MaxAliases    *int     `json:"max_aliases"`
		MaxQuotaBytes *int64   `json:"max_quota_bytes"`
		Signup        bool     `json:"signup_enabled"`
		Alternatives  []string `json:"alternatives"`
	}
	if err := c.get(ctx, "/domain", &ds); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, d := range ds {
		row := map[string]any{"domain": d.Name, "signupEnabled": d.Signup, "managers": len(d.Managers), "alternatives": append([]string{}, d.Alternatives...)}
		if d.MaxUsers != nil {
			row["maxUsers"] = *d.MaxUsers // -1: no limit
		}
		if d.MaxAliases != nil {
			row["maxAliases"] = *d.MaxAliases
		}
		if d.MaxQuotaBytes != nil {
			row["maxQuotaBytes"] = *d.MaxQuotaBytes
		}
		if d.Comment != "" {
			row["comment"] = d.Comment
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

// user is decoded field by field: the password hash, forward destinations
// and auto-reply text are never read.
type user struct {
	Email          string `json:"email"`
	DisplayedName  string `json:"displayed_name"`
	Enabled        *bool  `json:"enabled"`
	GlobalAdmin    *bool  `json:"global_admin"`
	QuotaBytes     int64  `json:"quota_bytes"`
	QuotaBytesUsed int64  `json:"quota_bytes_used"`
	EnableIMAP     bool   `json:"enable_imap"`
	EnablePOP      bool   `json:"enable_pop"`
	Forward        bool   `json:"forward_enabled"`
	Reply          bool   `json:"reply_enabled"`
	Spam           bool   `json:"spam_enabled"`
}

func (u user) enabled() bool { return u.Enabled == nil || *u.Enabled }

func (u user) admin() bool { return u.GlobalAdmin != nil && *u.GlobalAdmin }

func (c *conn) users(ctx context.Context, p input) (sdk.Result, error) {
	var us []user
	if err := c.get(ctx, "/user", &us); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, u := range us {
		if p.Domain != "" && domainOf(u.Email) != p.Domain {
			continue
		}
		if p.Enabled != nil && u.enabled() != *p.Enabled {
			continue
		}
		row := map[string]any{"email": u.Email, "name": u.DisplayedName, "enabled": u.enabled(), "globalAdmin": u.admin(),
			"quotaBytes": u.QuotaBytes, "usedBytes": u.QuotaBytesUsed, "imap": u.EnableIMAP, "pop3": u.EnablePOP,
			"forwarding": u.Forward, "autoReply": u.Reply, "spamFilter": u.Spam}
		if u.QuotaBytes > 0 {
			row["percentUsed"] = u.QuotaBytesUsed * 100 / u.QuotaBytes
		}
		out = append(out, row)
	}
	return sdk.JSON(map[string]any{"total": len(out), "users": out})
}

func (c *conn) aliases(ctx context.Context, p input) (sdk.Result, error) {
	var as []struct {
		Email       string   `json:"email"`
		Destination []string `json:"destination"`
		Wildcard    bool     `json:"wildcard"`
		Disabled    bool     `json:"disabled"`
		Comment     string   `json:"comment"`
	}
	if err := c.get(ctx, "/alias", &as); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, a := range as {
		if p.Domain != "" && domainOf(a.Email) != p.Domain {
			continue
		}
		row := map[string]any{"email": a.Email, "destination": append([]string{}, a.Destination...), "wildcard": a.Wildcard, "disabled": a.Disabled}
		if a.Comment != "" {
			row["comment"] = a.Comment
		}
		out = append(out, row)
	}
	return sdk.JSON(map[string]any{"total": len(out), "aliases": out})
}

func (c *conn) getUser(ctx context.Context, addr string) (user, error) {
	var u user
	if err := c.get(ctx, "/user/"+url.PathEscape(addr), &u); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return u, fmt.Errorf("there's no user %s", addr)
		}
		return u, err
	}
	if !strings.EqualFold(u.Email, addr) {
		return u, fmt.Errorf("there's no user %s", addr)
	}
	return u, nil
}

// roleLocal reports whether a local part is a role account, also with a
// +tag (postmaster+x@ reaches postmaster@).
func roleLocal(local string) bool {
	base, _, _ := strings.Cut(local, "+")
	return protected[local] || protected[base]
}

// roleAliasTo returns a role address (postmaster@ and the like) whose alias
// delivers to addr, or "".
func (c *conn) roleAliasTo(ctx context.Context, addr string) (string, error) {
	var as []struct {
		Email       string   `json:"email"`
		Destination []string `json:"destination"`
	}
	if err := c.get(ctx, "/alias", &as); err != nil {
		return "", err
	}
	for _, a := range as {
		email := strings.ToLower(strings.TrimSpace(a.Email))
		local, _, ok := strings.Cut(email, "@")
		if !ok || !roleLocal(local) {
			continue
		}
		for _, d := range a.Destination {
			if strings.EqualFold(strings.TrimSpace(d), addr) {
				return email, nil
			}
		}
	}
	return "", nil
}

func (c *conn) setEnabled(ctx context.Context, call sdk.Call, local, dom string) (sdk.Result, error) {
	enabling := call.Action == "enable_user"
	addr := local + "@" + dom
	if roleLocal(local) && !c.allowAdmin {
		return sdk.Result{}, fmt.Errorf("%s is a role account; turn on allowAdminAccounts in the settings to change it", addr)
	}
	u, err := c.getUser(ctx, addr)
	if err != nil {
		return sdk.Result{}, err
	}
	if u.Enabled == nil {
		// Without the state, neither the read-back nor undo can be trusted.
		return sdk.Result{}, fmt.Errorf("Mailu didn't say whether %s is enabled; nothing was changed", addr)
	}
	if !c.allowAdmin {
		if u.GlobalAdmin == nil {
			return sdk.Result{}, fmt.Errorf("Mailu didn't say whether %s is a global administrator, so nothing was changed", addr)
		}
		if *u.GlobalAdmin {
			return sdk.Result{}, fmt.Errorf("%s is a global administrator; turn on allowAdminAccounts in the settings to change it", addr)
		}
	}
	if u.enabled() == enabling {
		return sdk.JSON(map[string]any{"email": addr, "enabled": enabling, "note": "nothing to change"})
	}
	if !c.allowAdmin {
		role, err := c.roleAliasTo(ctx, addr)
		if err != nil {
			return sdk.Result{}, fmt.Errorf("couldn't check whether a role address delivers to %s, so nothing was changed: %w", addr, err)
		}
		if role != "" {
			return sdk.Result{}, fmt.Errorf("%s receives the mail of %s, a role account; turn on allowAdminAccounts in the settings to change it", addr, role)
		}
	}
	verb, back := "Disable", "enable_user"
	if enabling {
		verb, back = "Enable", "disable_user"
	}
	if call.DryRun {
		target := "user " + addr
		if u.admin() {
			target += ", a global administrator"
		}
		b, _ := json.Marshal(map[string]bool{"enabled": u.enabled()})
		a, _ := json.Marshal(map[string]bool{"enabled": enabling})
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " " + addr, Changes: []sdk.Change{{Target: target, Op: strings.ToLower(verb), Before: b, After: a}}}}, nil
	}
	if _, err := c.api.Do(ctx, http.MethodPatch, "/user/"+url.PathEscape(addr), nil, map[string]bool{"enabled": enabling}, nil); err != nil {
		return sdk.Result{}, friendly(err)
	}
	after, err := c.getUser(ctx, addr)
	if err != nil {
		return sdk.Result{}, err
	}
	if after.Enabled == nil || *after.Enabled != enabling {
		return sdk.Result{}, fmt.Errorf("Mailu answered, but %s is still %s", addr, map[bool]string{true: "enabled", false: "disabled"}[after.enabled()])
	}
	res, err := sdk.JSON(map[string]any{"email": addr, "enabled": enabling})
	undo := "Enable " + addr + " again"
	if enabling {
		undo = "Disable " + addr + " again"
	}
	res.Undo = sdk.UndoWith(back, map[string]string{"email": addr}, undo)
	return res, err
}
