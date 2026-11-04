// Package azure works with Azure Resource Manager through a service
// principal (client credentials): subscriptions, resource groups, virtual
// machines with their power state, starting, deallocating and restarting
// them, App Service apps (start, stop, restart) and this month's costs.
package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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

// Config is one service principal.
type Config struct {
	TenantID       string `json:"tenantId"`       // directory (tenant) id or its domain
	ClientID       string `json:"clientId"`       // application (client) id
	ClientSecret   string `json:"clientSecret"`   // secret:// client secret
	SubscriptionID string `json:"subscriptionId"` // optional default subscription
}

type conn struct {
	cfg   Config
	host  sdk.Host
	api   *rest.Client
	login *rest.Client
	now   func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://management.azure.com (tests).
	Base string
	// LoginBase replaces https://login.microsoftonline.com (tests).
	LoginBase string
}

// New returns the Azure module.
func New() *Module { return &Module{} }

const (
	defaultBase  = "https://management.azure.com"
	defaultLogin = "https://login.microsoftonline.com"
	computeAPI   = "2024-07-01"
	webAPI       = "2023-12-01"
)

var (
	guidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	tenantRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)+[A-Za-z]{2,63}$`)
	groupRe  = regexp.MustCompile(`^[A-Za-z0-9._()-]{1,90}$`)
	vmRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	siteRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,58}[A-Za-z0-9]$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	sub := `"subscription":{"type":"string","description":"Subscription id (default: the instance's)"}`
	vm := sdk.Schema(`{"type":"object","required":["resourceGroup","vm"],"properties":{` + sub + `,"resourceGroup":{"type":"string"},"vm":{"type":"string","description":"VM name (from vms)"}}}`)
	app := sdk.Schema(`{"type":"object","required":["resourceGroup","app"],"properties":{` + sub + `,"resourceGroup":{"type":"string"},"app":{"type":"string","description":"App name (from webapps)"}}}`)
	return sdk.Manifest{
		ID: "azure", Name: "Azure", Version: "0.1.0", Category: "Infrastructure", Icon: "cloud",
		Description: "Azure subscriptions, resource groups, virtual machines with their power state (start, deallocate, restart), App Service apps (start, stop, restart) and this month's costs.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["tenantId","clientId","clientSecret"],"properties":{
			"tenantId":{"type":"string","description":"Directory (tenant) id, or its domain such as contoso.onmicrosoft.com"},
			"clientId":{"type":"string","description":"Application (client) id of an app registration (service principal)"},
			"clientSecret":{"type":"string","x-secret":true,"description":"A client secret of that app registration"},
			"subscriptionId":{"type":"string","description":"The subscription actions use when none is given"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "subscriptions", Title: "Subscriptions", Description: "Subscriptions the service principal can see: id, name and state.", Risk: sdk.RiskRead},
			{Name: "resource_groups", Title: "Resource groups", Description: "Name, location and provisioning state.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + sub + `}}`)},
			{Name: "vms", Title: "Virtual machines", Description: "Name, resource group, location, size, OS type and power state (running, stopped, deallocated).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + sub + `,"resourceGroup":{"type":"string","description":"Only this resource group"}}}`)},
			{Name: "start_vm", Title: "Start a VM", Description: "Starts a stopped or deallocated VM; compute billing resumes. Undo deallocates it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: vm},
			{Name: "deallocate_vm", Title: "Deallocate a VM", Description: "Shuts the VM down and releases its compute, so it's no longer billed for it; its services go down until it's started, and a dynamic public IP is released. Undo starts it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: vm},
			{Name: "restart_vm", Title: "Restart a VM", Description: "Restarts a running VM; its services go down while it restarts.", Risk: sdk.RiskDestructive, DryRun: true, Input: vm},
			{Name: "webapps", Title: "App Service apps", Description: "Web and function apps: name, kind, state, host name, location and plan. Never settings or connection strings.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + sub + `}}`)},
			{Name: "start_webapp", Title: "Start an app", Description: "Starts a stopped App Service app. Undo stops it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: app},
			{Name: "stop_webapp", Title: "Stop an app", Description: "Stops an App Service app; it stops answering until started (the plan is still billed). Undo starts it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: app},
			{Name: "restart_webapp", Title: "Restart an app", Description: "Restarts an App Service app; requests fail while it restarts.", Risk: sdk.RiskDestructive, DryRun: true, Input: app},
			{Name: "costs", Title: "Costs this month", Description: "Actual cost so far this month, by service (needs Cost Management Reader). Financial data, kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + sub + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	c.TenantID, c.ClientID, c.SubscriptionID = strings.TrimSpace(c.TenantID), strings.TrimSpace(c.ClientID), strings.TrimSpace(c.SubscriptionID)
	if !guidRe.MatchString(c.TenantID) && !tenantRe.MatchString(c.TenantID) {
		return errors.New("the tenant is its directory id (a GUID) or domain, such as contoso.onmicrosoft.com")
	}
	if !guidRe.MatchString(c.ClientID) {
		return errors.New("the client id is the app registration's application id (a GUID)")
	}
	if c.SubscriptionID != "" && !guidRe.MatchString(c.SubscriptionID) {
		return errors.New("the subscription id is a GUID")
	}
	if !strings.HasPrefix(c.ClientSecret, "secret://") {
		return errors.New("store the client secret in the vault and enter its secret:// reference")
	}
	base, login := defaultBase, defaultLogin
	if m.Base != "" {
		base = m.Base
	}
	if m.LoginBase != "" {
		login = m.LoginBase
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	cn := &conn{cfg: c, host: h, now: time.Now}
	cn.api = rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := cn.accessToken(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	cn.api.HTTP = rest.SameHostOnly(client)
	cn.login = rest.New(login, nil)
	cn.login.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// accessToken returns a cached token, or gets a new one with the client
// secret. Tokens are kept in memory only, until a minute before expiry.
func (c *conn) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Before(c.expires) {
		return c.token, nil
	}
	secret, err := c.host.Secret(ctx, c.cfg.ClientSecret)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.cfg.ClientID},
		"client_secret": {strings.TrimSpace(secret)},
		"scope":         {"https://management.azure.com/.default"},
	}
	res, err := c.login.Send(ctx, http.MethodPost, "/"+url.PathEscape(c.cfg.TenantID)+"/oauth2/v2.0/token", nil,
		strings.NewReader(form.Encode()), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}})
	if err != nil {
		var e *rest.Error
		if errors.As(err, &e) && e.Status >= 400 && e.Status < 500 {
			return "", errors.New("Azure refused the tenant, client id or client secret")
		}
		return "", err
	}
	defer res.Body.Close()
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&t); err != nil || t.AccessToken == "" {
		return "", errors.New("Azure's sign-in answered without a token")
	}
	life := time.Duration(t.ExpiresIn) * time.Second
	if life <= 0 {
		life = 5 * time.Minute
	}
	c.token, c.expires = t.AccessToken, c.now().Add(life-time.Minute)
	return c.token, nil
}

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Azure refused the service principal's token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the service principal isn't allowed to do this (check its role assignments)")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusConflict):
		return fmt.Errorf("Azure refused: %s is busy or in the wrong state for this", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Azure's rate limit was hit; try again in a moment")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path, version string, body, out any, what string) error {
	_, err := c.api.Do(ctx, method, path, url.Values{"api-version": {version}}, body, out)
	return friendly(err, what)
}

// list gets every page of an ARM list. nextLink is followed only on the
// API's own host.
func list[T any](ctx context.Context, c *conn, path string, q url.Values, what string) ([]T, error) {
	var out []T
	base, _ := url.Parse(c.api.Base)
	for page := 0; page < 50; page++ {
		var r struct {
			Value    []T    `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, path, q, nil, &r); err != nil {
			return nil, friendly(err, what)
		}
		out = append(out, r.Value...)
		if r.NextLink == "" {
			break
		}
		next, err := url.Parse(r.NextLink)
		if err != nil || next.Scheme != base.Scheme || !strings.EqualFold(next.Host, base.Host) || !strings.HasPrefix(next.Path, base.Path+"/") {
			return nil, errors.New("Azure's next page pointed somewhere else")
		}
		path, q = strings.TrimPrefix(next.EscapedPath(), base.Path), next.Query()
	}
	return out, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	subs, err := c.subscriptions(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if len(subs) == 0 {
		return sdk.Health{Status: "degraded", Message: "signed in, but the service principal has no role on any subscription"}
	}
	if s := c.cfg.SubscriptionID; s != "" {
		for _, x := range subs {
			if strings.EqualFold(x.ID, s) {
				return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d subscriptions; %s is %s", len(subs), x.Name, x.State)}
			}
		}
		return sdk.Health{Status: "degraded", Message: "the service principal can't see subscription " + s}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d subscriptions", len(subs))}
}

type subscription struct {
	ID    string `json:"subscriptionId"`
	Name  string `json:"displayName"`
	State string `json:"state"`
}

func (c *conn) subscriptions(ctx context.Context) ([]subscription, error) {
	return list[subscription](ctx, c, "/subscriptions", url.Values{"api-version": {"2022-12-01"}}, "subscription list")
}

type input struct {
	Subscription  string `json:"subscription"`
	ResourceGroup string `json:"resourceGroup"`
	VM            string `json:"vm"`
	App           string `json:"app"`
}

func (c *conn) sub(p input) (string, error) {
	s := strings.TrimSpace(p.Subscription)
	if s == "" {
		s = c.cfg.SubscriptionID
	}
	if s == "" {
		return "", errors.New("which subscription? (its id, from subscriptions; or set one in the instance)")
	}
	if !guidRe.MatchString(s) {
		return "", errors.New("a subscription id is a GUID (from subscriptions)")
	}
	return strings.ToLower(s), nil
}

func validGroup(g string) bool { return groupRe.MatchString(g) && !strings.HasSuffix(g, ".") }

// groupOf reads the resource group out of a resource id.
func groupOf(id string) string {
	parts := strings.Split(id, "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			return parts[i+1]
		}
	}
	return ""
}

type status struct {
	Code          string `json:"code"`
	DisplayStatus string `json:"displayStatus"`
}

func powerState(ss []status) string {
	for _, s := range ss {
		if p, ok := strings.CutPrefix(s.Code, "PowerState/"); ok {
			return p
		}
	}
	return "unknown"
}

func provisioning(ss []status) string {
	for _, s := range ss {
		if p, ok := strings.CutPrefix(s.Code, "ProvisioningState/"); ok {
			return p
		}
	}
	return ""
}

// vm holds only what's shown: osProfile (custom data, admin password),
// userData and extensions are never decoded.
type vm struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Location string   `json:"location"`
	Zones    []string `json:"zones"`
	Props    struct {
		Hardware struct {
			Size string `json:"vmSize"`
		} `json:"hardwareProfile"`
		Storage struct {
			OSDisk struct {
				OSType string `json:"osType"`
			} `json:"osDisk"`
		} `json:"storageProfile"`
		Provisioning string `json:"provisioningState"`
		InstanceView *struct {
			Statuses []status `json:"statuses"`
		} `json:"instanceView"`
	} `json:"properties"`
}

func state(s string) json.RawMessage { b, _ := json.Marshal(map[string]string{"state": s}); return b }

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
	p.ResourceGroup, p.VM, p.App = strings.TrimSpace(p.ResourceGroup), strings.TrimSpace(p.VM), strings.TrimSpace(p.App)
	if call.Action == "subscriptions" {
		subs, err := c.subscriptions(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]string{}
		for _, s := range subs {
			out = append(out, map[string]string{"id": s.ID, "name": s.Name, "state": s.State})
		}
		return sdk.JSON(out)
	}
	sub, err := c.sub(p)
	if err != nil {
		return sdk.Result{}, err
	}
	subPath := "/subscriptions/" + url.PathEscape(sub)
	switch call.Action {
	case "resource_groups":
		gs, err := list[struct {
			Name     string `json:"name"`
			Location string `json:"location"`
			Props    struct {
				State string `json:"provisioningState"`
			} `json:"properties"`
		}](ctx, c, subPath+"/resourcegroups", url.Values{"api-version": {"2021-04-01"}}, "subscription "+sub)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]string{}
		for _, g := range gs {
			out = append(out, map[string]string{"name": g.Name, "location": g.Location, "state": g.Props.State})
		}
		return sdk.JSON(out)

	case "vms":
		if p.ResourceGroup != "" && !validGroup(p.ResourceGroup) {
			return sdk.Result{}, errors.New("that isn't a valid resource group name")
		}
		vms, err := list[vm](ctx, c, subPath+"/providers/Microsoft.Compute/virtualMachines", url.Values{"api-version": {computeAPI}, "statusOnly": {"true"}}, "subscription "+sub)
		if err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			Name          string   `json:"name"`
			ResourceGroup string   `json:"resourceGroup"`
			Location      string   `json:"location"`
			Zones         []string `json:"zones,omitempty"`
			Size          string   `json:"size"`
			OS            string   `json:"os,omitempty"`
			PowerState    string   `json:"powerState"`
			Provisioning  string   `json:"provisioningState,omitempty"`
		}
		out := []row{}
		for _, v := range vms {
			g := groupOf(v.ID)
			if p.ResourceGroup != "" && !strings.EqualFold(g, p.ResourceGroup) {
				continue
			}
			r := row{Name: v.Name, ResourceGroup: g, Location: v.Location, Zones: v.Zones, Size: v.Props.Hardware.Size, OS: v.Props.Storage.OSDisk.OSType,
				PowerState: "unknown", Provisioning: v.Props.Provisioning}
			if v.Props.InstanceView != nil {
				r.PowerState = powerState(v.Props.InstanceView.Statuses)
			}
			out = append(out, r)
		}
		sort.Slice(out, func(i, j int) bool {
			return out[i].ResourceGroup+"/"+out[i].Name < out[j].ResourceGroup+"/"+out[j].Name
		})
		return sdk.JSON(out)

	case "start_vm", "deallocate_vm", "restart_vm":
		if !validGroup(p.ResourceGroup) {
			return sdk.Result{}, errors.New("which resource group? (its name, from resource_groups)")
		}
		if !vmRe.MatchString(p.VM) {
			return sdk.Result{}, errors.New("which VM? (its name, from vms)")
		}
		return c.vmPower(ctx, call, sub, p)

	case "webapps":
		sites, err := list[site](ctx, c, subPath+"/providers/Microsoft.Web/sites", url.Values{"api-version": {webAPI}}, "subscription "+sub)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range sites {
			out = append(out, s.row())
		}
		return sdk.JSON(out)

	case "start_webapp", "stop_webapp", "restart_webapp":
		if !validGroup(p.ResourceGroup) {
			return sdk.Result{}, errors.New("which resource group? (its name, from resource_groups)")
		}
		if !siteRe.MatchString(p.App) {
			return sdk.Result{}, errors.New("which app? (its name, from webapps)")
		}
		return c.sitePower(ctx, call, sub, p)

	case "costs":
		return c.costs(ctx, subPath)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) vmPower(ctx context.Context, call sdk.Call, sub string, p input) (sdk.Result, error) {
	path := "/subscriptions/" + url.PathEscape(sub) + "/resourceGroups/" + url.PathEscape(p.ResourceGroup) + "/providers/Microsoft.Compute/virtualMachines/" + url.PathEscape(p.VM)
	what := "VM " + p.VM + " in " + p.ResourceGroup
	var iv struct {
		Statuses []status `json:"statuses"`
	}
	if err := c.do(ctx, http.MethodGet, path+"/instanceView", computeAPI, nil, &iv, what); err != nil {
		return sdk.Result{}, err
	}
	was := powerState(iv.Statuses)
	target := p.VM + " (" + p.ResourceGroup + ")"
	in := map[string]string{"subscription": sub, "resourceGroup": p.ResourceGroup, "vm": p.VM}
	var want, op string
	switch call.Action {
	case "start_vm":
		if was == "running" || was == "starting" {
			return sdk.JSON(map[string]any{"vm": target, "powerState": was, "note": "nothing to change"})
		}
		if was != "stopped" && was != "deallocated" {
			return sdk.Result{}, fmt.Errorf("%s is %s; only a stopped or deallocated VM can be started", target, was)
		}
		want, op = "running", "start"
	case "deallocate_vm":
		if was == "deallocated" || was == "deallocating" {
			return sdk.JSON(map[string]any{"vm": target, "powerState": was, "note": "nothing to change"})
		}
		if was != "running" && was != "stopped" {
			return sdk.Result{}, fmt.Errorf("%s is %s; wait until it's running or stopped", target, was)
		}
		want, op = "deallocated", "deallocate"
	case "restart_vm":
		if was != "running" {
			return sdk.Result{}, fmt.Errorf("%s is %s; only a running VM can be restarted", target, was)
		}
		want, op = "running", "restart"
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: strings.ToUpper(op[:1]) + op[1:] + " " + target,
			Changes: []sdk.Change{{Target: target, Op: op, Before: state(was), After: state(want)}}}}, nil
	}
	if err := c.do(ctx, http.MethodPost, path+"/"+op, computeAPI, nil, nil, what); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"vm": target, "was": was, "requested": op})
	switch {
	case call.Action == "start_vm" && was == "deallocated":
		res.Undo = sdk.UndoWith("deallocate_vm", in, "Deallocate "+p.VM+" again")
	case call.Action == "deallocate_vm" && was == "running":
		res.Undo = sdk.UndoWith("start_vm", in, "Start "+p.VM+" again")
	}
	return res, err
}

// site holds only what's shown: site config, app settings and connection
// strings are never decoded.
type site struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Location string `json:"location"`
	Props    struct {
		State        string `json:"state"`
		Host         string `json:"defaultHostName"`
		Enabled      bool   `json:"enabled"`
		HTTPSOnly    bool   `json:"httpsOnly"`
		Availability string `json:"availabilityState"`
		ServerFarmID string `json:"serverFarmId"`
	} `json:"properties"`
}

func (s site) row() map[string]any {
	plan := s.Props.ServerFarmID
	if i := strings.LastIndex(plan, "/"); i >= 0 {
		plan = plan[i+1:]
	}
	return map[string]any{"name": s.Name, "resourceGroup": groupOf(s.ID), "kind": s.Kind, "location": s.Location, "state": s.Props.State,
		"hostName": s.Props.Host, "enabled": s.Props.Enabled, "httpsOnly": s.Props.HTTPSOnly, "availability": s.Props.Availability, "plan": plan}
}

func (c *conn) sitePower(ctx context.Context, call sdk.Call, sub string, p input) (sdk.Result, error) {
	path := "/subscriptions/" + url.PathEscape(sub) + "/resourceGroups/" + url.PathEscape(p.ResourceGroup) + "/providers/Microsoft.Web/sites/" + url.PathEscape(p.App)
	what := "app " + p.App + " in " + p.ResourceGroup
	var s site
	if err := c.do(ctx, http.MethodGet, path, webAPI, nil, &s, what); err != nil {
		return sdk.Result{}, err
	}
	was := s.Props.State
	target := p.App + " (" + p.ResourceGroup + ")"
	in := map[string]string{"subscription": sub, "resourceGroup": p.ResourceGroup, "app": p.App}
	op := strings.TrimSuffix(call.Action, "_webapp")
	running := strings.EqualFold(was, "Running")
	switch op {
	case "start":
		if running {
			return sdk.JSON(map[string]any{"app": target, "state": was, "note": "nothing to change"})
		}
	case "stop":
		if strings.EqualFold(was, "Stopped") {
			return sdk.JSON(map[string]any{"app": target, "state": was, "note": "nothing to change"})
		}
	case "restart":
		if !running {
			return sdk.Result{}, fmt.Errorf("%s is %s; only a running app can be restarted", target, was)
		}
	}
	want := map[string]string{"start": "Running", "stop": "Stopped", "restart": "Running"}[op]
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: strings.ToUpper(op[:1]) + op[1:] + " " + target,
			Changes: []sdk.Change{{Target: target, Op: op, Before: state(was), After: state(want)}}}}, nil
	}
	if err := c.do(ctx, http.MethodPost, path+"/"+op, webAPI, nil, nil, what); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"app": target, "was": was, "requested": op})
	switch op {
	case "start":
		res.Undo = sdk.UndoWith("stop_webapp", in, "Stop "+p.App+" again")
	case "stop":
		if running {
			res.Undo = sdk.UndoWith("start_webapp", in, "Start "+p.App+" again")
		}
	}
	return res, err
}

func (c *conn) costs(ctx context.Context, subPath string) (sdk.Result, error) {
	body := map[string]any{"type": "ActualCost", "timeframe": "MonthToDate", "dataset": map[string]any{
		"granularity": "None",
		"aggregation": map[string]any{"totalCost": map[string]string{"name": "Cost", "function": "Sum"}},
		"grouping":    []map[string]string{{"type": "Dimension", "name": "ServiceName"}},
	}}
	var r struct {
		Props struct {
			Columns []struct {
				Name string `json:"name"`
			} `json:"columns"`
			Rows [][]any `json:"rows"`
		} `json:"properties"`
	}
	if err := c.do(ctx, http.MethodPost, subPath+"/providers/Microsoft.CostManagement/query", "2023-03-01", body, &r, "cost data for this subscription"); err != nil {
		return sdk.Result{}, err
	}
	col := map[string]int{}
	for i, cl := range r.Props.Columns {
		col[strings.ToLower(cl.Name)] = i
	}
	get := func(row []any, name string) any {
		if i, ok := col[name]; ok && i < len(row) {
			return row[i]
		}
		return nil
	}
	type line struct {
		Service string  `json:"service"`
		Cost    float64 `json:"cost"`
	}
	lines := []line{}
	total, currency := 0.0, ""
	for _, row := range r.Props.Rows {
		v, _ := get(row, "cost").(float64)
		if v == 0 {
			v, _ = get(row, "pretaxcost").(float64)
		}
		svc, _ := get(row, "servicename").(string)
		if cur, ok := get(row, "currency").(string); ok {
			currency = cur
		}
		total += v
		lines = append(lines, line{Service: svc, Cost: math.Round(v*100) / 100})
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].Cost > lines[j].Cost })
	return sdk.JSON(map[string]any{"period": "month to date", "currency": currency, "total": math.Round(total*100) / 100, "byService": lines})
}
