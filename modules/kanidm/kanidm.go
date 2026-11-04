// Package kanidm works with a Kanidm identity server through a service
// account's API token: people, groups, which accounts are usable, expired
// or not yet valid, and locking and unlocking accounts through their expiry.
package kanidm

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
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Kanidm server.
type Config struct {
	URL                string `json:"url"`   // e.g. https://idm.example.com
	Token              string `json:"token"` // secret:// service account API token
	AllowAdmins        bool   `json:"allowAdmins"`
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api         *rest.Client
	allowAdmins bool
	now         func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Kanidm module.
func New() *Module { return &Module{} }

var (
	pathRe    = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	accountRe = regexp.MustCompile(`^([a-z0-9][a-z0-9_.-]{0,63}(@[a-z0-9.-]{1,253})?|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	// Built-in accounts and groups that hold administrative rights.
	adminNames  = map[string]bool{"admin": true, "idm_admin": true}
	adminGroups = map[string]bool{"idm_high_privilege": true, "idm_admins": true, "system_admins": true, "domain_admins": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	who := `{"type":"object","required":["account"],"properties":{"account":{"type":"string","description":"Account name, SPN or UUID (from persons or account_status)"}}}`
	return sdk.Manifest{
		ID: "kanidm", Name: "Kanidm", Version: "0.1.0", Category: "Security", Icon: "shield",
		Description: "Kanidm: people, groups and whether accounts are usable; lock and unlock accounts.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://idm.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API token of a service account (kanidm service-account api-token generate). Make the account a member of idm_people_admins (or idm_service_account_admins) to lock and unlock"},
			"allowAdmins":{"type":"boolean","default":false,"description":"Let Conduit lock accounts in admin or high-privilege groups (off: refused)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "persons", Title: "People", Description: "People with name, display name, SPN, groups and whether the account is usable. Emails only when asked. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Part of the name or display name"},"includeEmail":{"type":"boolean","default":false}}}`)},
			{Name: "groups", Title: "Groups", Description: "Groups with their description and member count.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Part of the group name"}}}`)},
			{Name: "account_status", Title: "Account status", Description: "Every person and service account (or one): active, expired (locked) or not yet valid, with the dates.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"account":{"type":"string","description":"Only this account (name, SPN or UUID)"}}}`)},
			{Name: "lock_account", Title: "Lock an account", Description: "Expires the account now, so it can't sign in; nothing else changes. Refused for the token's own account, and for admins unless allowed. Undo unlocks it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(who)},
			{Name: "unlock_account", Title: "Unlock an account", Description: "Clears an account's past expiry so it can sign in again. Undo locks it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(who)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://idm.example.com")
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
	p := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/v1")
	api := rest.New(u.Scheme+"://"+u.Host+p+"/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	now := m.Now
	if now == nil {
		now = time.Now
	}
	m.set.Put(id, &conn{api: api, allowAdmins: c.AllowAdmins, now: now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Kanidm refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the service account isn't allowed to do this in Kanidm")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, body, out any) error {
	_, err := c.api.Do(ctx, method, path, nil, body, out)
	return friendly(err)
}

// entry is a Kanidm entry. Only the attributes named in attr are read out of
// it: credentials, passkeys, RADIUS secrets, sessions and API tokens never
// leave this package.
type entry struct {
	Attrs map[string][]string `json:"attrs"`
}

func (e entry) attr(k string) string {
	if v := e.Attrs[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func (e entry) name() string { return e.attr("name") }

// groups returns the names of the groups the entry is in (memberof holds
// SPNs like idm_admins@idm.example.com).
func (e entry) groups() []string {
	var out []string
	for _, g := range e.Attrs["memberof"] {
		n, _, _ := strings.Cut(g, "@")
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// status says whether an account can sign in now.
func (c *conn) status(e entry) string {
	now := c.now()
	if t, ok := when(e.attr("account_expire")); ok && !now.Before(t) {
		return "expired"
	}
	if t, ok := when(e.attr("account_valid_from")); ok && now.Before(t) {
		return "not yet valid"
	}
	return "active"
}

func when(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

func (c *conn) self(ctx context.Context) (entry, error) {
	var res struct {
		YouAre *entry              `json:"youare"`
		Attrs  map[string][]string `json:"attrs"`
	}
	if err := c.do(ctx, http.MethodGet, "/self", nil, &res); err != nil {
		return entry{}, err
	}
	if res.YouAre != nil {
		return *res.YouAre, nil
	}
	return entry{Attrs: res.Attrs}, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	me, err := c.self(ctx)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Kanidm API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	n := me.attr("spn")
	if n == "" {
		n = me.name()
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + n}
}

type input struct {
	Search       string `json:"search"`
	IncludeEmail bool   `json:"includeEmail"`
	Account      string `json:"account"`
}

func search(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > 200 || strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("the search is one line of at most 200 characters")
	}
	return strings.ToLower(s), nil
}

func account(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", errors.New("enter the account's name, SPN or UUID")
	}
	if !accountRe.MatchString(s) {
		return "", errors.New("the account is a name like alice, an SPN like alice@idm.example.com, or a UUID")
	}
	return s, nil
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
	switch call.Action {
	case "persons":
		return c.persons(ctx, p)
	case "groups":
		return c.groups(ctx, p)
	case "account_status":
		return c.accountStatus(ctx, p)
	case "lock_account", "unlock_account":
		return c.setLocked(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) list(ctx context.Context, kind string) ([]entry, error) {
	var es []entry
	err := c.do(ctx, http.MethodGet, "/"+kind, nil, &es)
	sort.Slice(es, func(i, j int) bool { return es[i].name() < es[j].name() })
	return es, err
}

func (c *conn) persons(ctx context.Context, p input) (sdk.Result, error) {
	s, err := search(p.Search)
	if err != nil {
		return sdk.Result{}, err
	}
	es, err := c.list(ctx, "person")
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, e := range es {
		if s != "" && !strings.Contains(e.name(), s) && !strings.Contains(strings.ToLower(e.attr("displayname")), s) {
			continue
		}
		row := map[string]any{"name": e.name(), "displayName": e.attr("displayname"), "spn": e.attr("spn"), "uuid": e.attr("uuid"), "groups": e.groups(), "status": c.status(e)}
		if p.IncludeEmail {
			row["email"] = e.Attrs["mail"]
		}
		out = append(out, row)
	}
	return sdk.JSON(map[string]any{"count": len(out), "persons": out})
}

func (c *conn) groups(ctx context.Context, p input) (sdk.Result, error) {
	s, err := search(p.Search)
	if err != nil {
		return sdk.Result{}, err
	}
	es, err := c.list(ctx, "group")
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, e := range es {
		if s != "" && !strings.Contains(e.name(), s) {
			continue
		}
		row := map[string]any{"name": e.name(), "uuid": e.attr("uuid"), "members": len(e.Attrs["member"]), "admin": adminGroups[e.name()]}
		if d := e.attr("description"); d != "" {
			row["description"] = d
		}
		out = append(out, row)
	}
	return sdk.JSON(map[string]any{"count": len(out), "groups": out})
}

func (c *conn) statusRow(e entry, kind string) map[string]any {
	row := map[string]any{"name": e.name(), "kind": kind, "status": c.status(e)}
	if v := e.attr("account_expire"); v != "" {
		row["expires"] = v
	}
	if v := e.attr("account_valid_from"); v != "" {
		row["validFrom"] = v
	}
	return row
}

func (c *conn) accountStatus(ctx context.Context, p input) (sdk.Result, error) {
	if strings.TrimSpace(p.Account) != "" {
		a, err := account(p.Account)
		if err != nil {
			return sdk.Result{}, err
		}
		e, kind, err := c.find(ctx, a)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(c.statusRow(e, kind))
	}
	out := []map[string]any{}
	counts := map[string]int{}
	for _, kind := range []string{"person", "service_account"} {
		es, err := c.list(ctx, kind)
		if err != nil {
			return sdk.Result{}, err
		}
		for _, e := range es {
			row := c.statusRow(e, kind)
			counts[row["status"].(string)]++
			out = append(out, row)
		}
	}
	return sdk.JSON(map[string]any{"counts": counts, "accounts": out})
}

// find looks an account up as a person, then as a service account.
func (c *conn) find(ctx context.Context, a string) (entry, string, error) {
	for _, kind := range []string{"person", "service_account"} {
		var e *entry
		err := c.do(ctx, http.MethodGet, "/"+kind+"/"+url.PathEscape(a), nil, &e)
		if rest.IsStatus(err, http.StatusNotFound) || (err == nil && (e == nil || e.name() == "")) {
			continue
		}
		if err != nil {
			return entry{}, "", err
		}
		return *e, kind, nil
	}
	return entry{}, "", fmt.Errorf("there's no account %q", a)
}

func (c *conn) setLocked(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	locking := call.Action == "lock_account"
	a, err := account(p.Account)
	if err != nil {
		return sdk.Result{}, err
	}
	e, kind, err := c.find(ctx, a)
	if err != nil {
		return sdk.Result{}, err
	}
	name := e.name()
	if !accountRe.MatchString(name) {
		return sdk.Result{}, errors.New("Kanidm answered with an unusable account name")
	}
	me, err := c.self(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	if (me.attr("uuid") != "" && me.attr("uuid") == e.attr("uuid")) || me.name() == name {
		return sdk.Result{}, errors.New("that's the token's own service account; locking it would lock Conduit out")
	}
	if !c.allowAdmins {
		if adminNames[name] {
			return sdk.Result{}, fmt.Errorf("%s is a built-in admin account; turn on allowAdmins in the settings to act on admins", name)
		}
		for _, g := range e.groups() {
			if adminGroups[g] {
				return sdk.Result{}, fmt.Errorf("%s is in %s; turn on allowAdmins in the settings to act on admins", name, g)
			}
		}
	}
	before := e.attr("account_expire")
	expired := c.status(e) == "expired"
	if locking == expired {
		// Already expired, or (unlocking) not expired: a later expiry date
		// stays as it is.
		row := c.statusRow(e, kind)
		row["note"] = "nothing to change"
		return sdk.JSON(row)
	}
	path := "/" + kind + "/" + url.PathEscape(name) + "/_attr/account_expire"
	verb := "Lock"
	after := c.now().UTC().Truncate(time.Second).Format(time.RFC3339)
	if !locking {
		verb, after = "Unlock", ""
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]string{"expires": before, "status": c.status(e)})
		st := "expired"
		if !locking {
			st = "active"
		}
		af, _ := json.Marshal(map[string]string{"expires": after, "status": st})
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " " + name, Changes: []sdk.Change{{Target: strings.ReplaceAll(kind, "_", " ") + " " + name, Op: strings.ToLower(verb), Before: b, After: af}}}}, nil
	}
	if locking {
		err = c.do(ctx, http.MethodPut, path, []string{after}, nil)
	} else {
		err = c.do(ctx, http.MethodDelete, path, nil, nil)
	}
	if err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"name": name, "kind": kind, "locked": locking}
	if locking && before != "" {
		out["previousExpiry"] = before
	}
	res, err := sdk.JSON(out)
	switch {
	case !locking:
		res.Undo = sdk.UndoWith("lock_account", map[string]string{"account": name}, "Lock "+name+" again")
	case before == "":
		// An account that had a later expiry set isn't offered an undo:
		// unlocking would clear that date too.
		res.Undo = sdk.UndoWith("unlock_account", map[string]string{"account": name}, "Unlock "+name)
	}
	return res, err
}
