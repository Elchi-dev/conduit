// Package huggingface works with a Hugging Face account through the Hub API
// with an access token: who the token belongs to, your models, datasets and
// Spaces, a Space's runtime, restarting and pausing Spaces, and Inference
// Endpoints with their state, scaling to zero, pausing and resuming.
package huggingface

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

// Config is one Hugging Face account.
type Config struct {
	Token string `json:"token"` // secret://
}

type conn struct {
	hub *rest.Client
	ep  *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://huggingface.co (tests).
	Base string
	// EndpointsBase replaces https://api.endpoints.huggingface.cloud (tests).
	EndpointsBase string
}

// New returns the Hugging Face module.
func New() *Module { return &Module{} }

var (
	nameRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
	endpointRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	searchRe   = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,100}$`)
)

const (
	repoListIn = `{"type":"object","properties":{"author":{"type":"string","description":"A user or organization; you by default"},"search":{"type":"string","description":"Only names containing this"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":50}}}`
	spaceIn    = `{"type":"object","required":["space"],"properties":{"space":{"type":"string","description":"owner/name, e.g. me/my-demo"}}}`
	endpointIn = `{"type":"object","required":["name"],"properties":{"name":{"type":"string","description":"Endpoint name"},"namespace":{"type":"string","description":"User or organization that owns it; you by default"}}}`
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "huggingface", Name: "Hugging Face", Version: "0.1.0", Category: "Development", Icon: "package",
		Description: "Hugging Face Hub: your models, datasets and Spaces, a Space's runtime, restart and pause Spaces, Inference Endpoints with scale to zero, pause and resume.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"Access token (Settings, Access Tokens). Read is enough to look; restarting and pausing Spaces and managing endpoints need write, or a fine-grained token with those permissions"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "whoami", Title: "Who am I", Description: "The account the token belongs to, its organizations, and the token's name and role. Never the token or e-mail.", Risk: sdk.RiskRead},
			{Name: "models", Title: "Models", Description: "Models of an account (yours by default), recently changed first, with task, library, downloads, likes and whether private.", Risk: sdk.RiskRead, Input: sdk.Schema(repoListIn)},
			{Name: "datasets", Title: "Datasets", Description: "Datasets of an account (yours by default), recently changed first, with downloads, likes and whether private.", Risk: sdk.RiskRead, Input: sdk.Schema(repoListIn)},
			{Name: "spaces", Title: "Spaces", Description: "Spaces of an account (yours by default), recently changed first, with SDK, likes and whether private.", Risk: sdk.RiskRead, Input: sdk.Schema(repoListIn)},
			{Name: "space_status", Title: "Space status", Description: "A Space's runtime: stage (running, building, sleeping, paused, error), hardware now and requested, sleep time and error message.", Risk: sdk.RiskRead, Input: sdk.Schema(spaceIn)},
			{Name: "restart_space", Title: "Restart a Space", Description: "Restarts a Space (also wakes a sleeping or paused one, which starts billing for paid hardware). factory rebuilds it from scratch. Destructive: the Space is down while it restarts.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["space"],"properties":{"space":{"type":"string","description":"owner/name"},"factory":{"type":"boolean","description":"Factory reboot: rebuild the image and drop the cache"}}}`)},
			{Name: "pause_space", Title: "Pause a Space", Description: "Pauses a Space: it stops, stops billing, and stays off until someone restarts it. Destructive: it takes the Space offline.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(spaceIn)},
			{Name: "endpoints", Title: "Inference Endpoints", Description: "Inference Endpoints of an account (yours by default) with state, model, hardware, replicas and scaling.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"namespace":{"type":"string","description":"User or organization; you by default"}}}`)},
			{Name: "endpoint_status", Title: "Endpoint status", Description: "One Inference Endpoint: state, message, replicas ready and wanted, model, hardware, scaling and address.", Risk: sdk.RiskRead, Input: sdk.Schema(endpointIn)},
			{Name: "scale_endpoint_to_zero", Title: "Scale an endpoint to zero", Description: "Stops an endpoint's replicas so it stops billing; the next request wakes it (a cold start, which can take minutes and fail requests meanwhile). Destructive: it interrupts whoever is using the endpoint.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(endpointIn)},
			{Name: "pause_endpoint", Title: "Pause an endpoint", Description: "Pauses an endpoint: it stops billing and refuses requests until it's resumed. Destructive: it takes the endpoint offline.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(endpointIn)},
			{Name: "resume_endpoint", Title: "Resume an endpoint", Description: "Starts a paused or scaled-to-zero endpoint. Destructive: its hardware is billed by the hour from then on.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(endpointIn)},
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
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	ref := c.Token
	auth := func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	base, ebase := "https://huggingface.co", "https://api.endpoints.huggingface.cloud"
	if m.Base != "" {
		base = m.Base
	}
	if m.EndpointsBase != "" {
		ebase = m.EndpointsBase
	}
	hub := rest.New(base, auth)
	hub.HTTP = rest.SameHostOnly(client)
	ep := rest.New(ebase, auth)
	ep.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{hub: hub, ep: ep})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Hugging Face refused the token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Hugging Face refused: the token lacks the permission for this (it needs write, or a fine-grained token with it)")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s (or the token can't see it)", what)
	}
	return err
}

type who struct {
	Name     string `json:"name"`
	Fullname string `json:"fullname"`
	Type     string `json:"type"`
	IsPro    bool   `json:"isPro"`
	Orgs     []struct {
		Name string `json:"name"`
	} `json:"orgs"`
	Auth struct {
		AccessToken struct {
			DisplayName string `json:"displayName"`
			Role        string `json:"role"`
		} `json:"accessToken"`
	} `json:"auth"`
}

func (c *conn) whoami(ctx context.Context) (who, error) {
	var w who
	_, err := c.hub.Do(ctx, http.MethodGet, "/api/whoami-v2", nil, nil, &w)
	return w, friendly(err, "account")
}

// owner is the given user or organization, or the token's own account.
func (c *conn) owner(ctx context.Context, s string) (string, error) {
	if s = strings.TrimSpace(s); s != "" {
		if !nameRe.MatchString(s) || strings.Contains(s, "..") {
			return "", errors.New("the account is a user or organization name, like huggingface")
		}
		return s, nil
	}
	w, err := c.whoami(ctx)
	if err != nil {
		return "", err
	}
	if !nameRe.MatchString(w.Name) {
		return "", errors.New("Hugging Face didn't say whose token this is")
	}
	return w.Name, nil
}

func spaceID(s string) (string, error) {
	owner, name, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok || !nameRe.MatchString(owner) || !nameRe.MatchString(name) || strings.Contains(s, "..") {
		return "", errors.New("the Space is owner/name, like me/my-demo")
	}
	return owner + "/" + name, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	w, err := c.whoami(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + w.Name
	if r := w.Auth.AccessToken.Role; r != "" {
		msg += " (" + r + " token)"
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type runtime struct {
	Stage    string `json:"stage"`
	Hardware struct {
		Current   *string `json:"current"`
		Requested *string `json:"requested"`
	} `json:"hardware"`
	GCTimeout    *int64 `json:"gcTimeout"`
	ErrorMessage string `json:"errorMessage"`
}

func (c *conn) runtime(ctx context.Context, space string) (runtime, error) {
	var r runtime
	_, err := c.hub.Do(ctx, http.MethodGet, "/api/spaces/"+space+"/runtime", nil, nil, &r)
	return r, friendly(err, "Space "+space)
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func (r runtime) summary(space string) map[string]any {
	out := map[string]any{"space": space, "stage": r.Stage, "hardware": str(r.Hardware.Current), "requestedHardware": str(r.Hardware.Requested)}
	if r.GCTimeout != nil {
		out["sleepAfterSeconds"] = *r.GCTimeout
	}
	if r.ErrorMessage != "" {
		out["error"] = clip(rest.Redact(r.ErrorMessage), 500)
	}
	return out
}

type endpoint struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Model struct {
		Repository string `json:"repository"`
		Revision   string `json:"revision"`
		Task       string `json:"task"`
		Framework  string `json:"framework"`
	} `json:"model"`
	Compute struct {
		Accelerator  string `json:"accelerator"`
		InstanceType string `json:"instanceType"`
		InstanceSize string `json:"instanceSize"`
		Scaling      struct {
			Min               int  `json:"minReplica"`
			Max               int  `json:"maxReplica"`
			ScaleToZeroMinute *int `json:"scaleToZeroTimeout"`
		} `json:"scaling"`
	} `json:"compute"`
	Provider struct {
		Vendor string `json:"vendor"`
		Region string `json:"region"`
	} `json:"provider"`
	Status struct {
		State     string `json:"state"`
		Message   string `json:"message"`
		URL       string `json:"url"`
		Ready     int    `json:"readyReplica"`
		Target    int    `json:"targetReplica"`
		UpdatedAt string `json:"updatedAt"`
	} `json:"status"`
}

func (e endpoint) summary() map[string]any {
	out := map[string]any{"name": e.Name, "state": e.Status.State, "type": e.Type, "model": e.Model.Repository, "task": e.Model.Task,
		"hardware": strings.Trim(e.Compute.InstanceType+" "+e.Compute.InstanceSize, " "), "accelerator": e.Compute.Accelerator,
		"provider": strings.Trim(e.Provider.Vendor+" "+e.Provider.Region, " "), "readyReplicas": e.Status.Ready, "targetReplicas": e.Status.Target,
		"minReplicas": e.Compute.Scaling.Min, "maxReplicas": e.Compute.Scaling.Max, "updated": e.Status.UpdatedAt}
	if e.Compute.Scaling.ScaleToZeroMinute != nil {
		out["scaleToZeroAfterMinutes"] = *e.Compute.Scaling.ScaleToZeroMinute
	}
	if e.Status.URL != "" {
		out["url"] = rest.ShortURL(e.Status.URL)
	}
	if e.Status.Message != "" {
		out["message"] = clip(rest.Redact(e.Status.Message), 300)
	}
	return out
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Author    string `json:"author"`
		Search    string `json:"search"`
		Limit     int    `json:"limit"`
		Space     string `json:"space"`
		Factory   bool   `json:"factory"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "whoami":
		w, err := c.whoami(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		orgs := []string{}
		for _, o := range w.Orgs {
			orgs = append(orgs, o.Name)
		}
		return sdk.JSON(map[string]any{"name": w.Name, "fullname": w.Fullname, "type": w.Type, "pro": w.IsPro, "orgs": orgs,
			"tokenName": w.Auth.AccessToken.DisplayName, "tokenRole": w.Auth.AccessToken.Role})
	case "models", "datasets", "spaces":
		if p.Search != "" && !searchRe.MatchString(p.Search) {
			return sdk.Result{}, errors.New("search with letters, digits, spaces and . _ - only")
		}
		if p.Limit <= 0 || p.Limit > 100 {
			p.Limit = 50
		}
		owner, err := c.owner(ctx, p.Author)
		if err != nil {
			return sdk.Result{}, err
		}
		q := url.Values{"author": {owner}, "limit": {strconv.Itoa(p.Limit)}, "sort": {"lastModified"}, "direction": {"-1"}}
		if p.Search != "" {
			q.Set("search", p.Search)
		}
		var out []struct {
			ID        string `json:"id"`
			Private   bool   `json:"private"`
			Gated     any    `json:"gated"`
			Downloads int64  `json:"downloads"`
			Likes     int64  `json:"likes"`
			Pipeline  string `json:"pipeline_tag"`
			Library   string `json:"library_name"`
			SDK       string `json:"sdk"`
			CreatedAt string `json:"createdAt"`
		}
		if _, err := c.hub.Do(ctx, http.MethodGet, "/api/"+call.Action, q, nil, &out); err != nil {
			return sdk.Result{}, friendly(err, "account "+owner)
		}
		list := []map[string]any{}
		for _, x := range out {
			r := map[string]any{"id": x.ID, "private": x.Private, "likes": x.Likes, "created": x.CreatedAt}
			switch call.Action {
			case "models":
				r["task"], r["library"], r["downloads"] = x.Pipeline, x.Library, x.Downloads
			case "datasets":
				r["downloads"] = x.Downloads
			case "spaces":
				r["sdk"] = x.SDK
			}
			if g, ok := x.Gated.(string); ok && g != "" {
				r["gated"] = g
			}
			list = append(list, r)
		}
		return sdk.JSON(list)
	case "space_status":
		id, err := spaceID(p.Space)
		if err != nil {
			return sdk.Result{}, err
		}
		r, err := c.runtime(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(r.summary(id))
	case "restart_space", "pause_space":
		id, err := spaceID(p.Space)
		if err != nil {
			return sdk.Result{}, err
		}
		pause := call.Action == "pause_space"
		if pause && p.Factory {
			return sdk.Result{}, errors.New("factory is for restart_space")
		}
		r, err := c.runtime(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			before, _ := json.Marshal(r.summary(id))
			op, sum := "restart", "Restart the Space "+id
			switch {
			case pause:
				op, sum = "pause", "Pause the Space "+id+" (it stays off until restarted)"
			case p.Factory:
				sum = "Factory-rebuild the Space " + id
			}
			sum += ", now " + strings.ToLower(r.Stage)
			if hw := str(r.Hardware.Requested); hw != "" {
				sum += " on " + hw
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "Space " + id, Op: op, Before: before}}}}, nil
		}
		path, q := "/api/spaces/"+id+"/restart", url.Values(nil)
		if pause {
			path = "/api/spaces/" + id + "/pause"
		} else if p.Factory {
			q = url.Values{"factory": {"true"}}
		}
		if _, err := c.hub.Do(ctx, http.MethodPost, path, q, nil, nil); err != nil {
			return sdk.Result{}, friendly(err, "Space "+id)
		}
		after, err := c.runtime(ctx, id)
		if err != nil {
			return sdk.JSON(map[string]any{"space": id, "done": call.Action})
		}
		return sdk.JSON(after.summary(id))
	case "endpoints":
		ns, err := c.owner(ctx, p.Namespace)
		if err != nil {
			return sdk.Result{}, err
		}
		var out struct {
			Items []endpoint `json:"items"`
		}
		if _, err := c.ep.Do(ctx, http.MethodGet, "/v2/endpoint/"+ns, nil, nil, &out); err != nil {
			return sdk.Result{}, friendly(err, "account "+ns)
		}
		list := []map[string]any{}
		for _, e := range out.Items {
			list = append(list, e.summary())
		}
		return sdk.JSON(list)
	case "endpoint_status", "scale_endpoint_to_zero", "pause_endpoint", "resume_endpoint":
		if !endpointRe.MatchString(p.Name) {
			return sdk.Result{}, errors.New("give an endpoint name from endpoints")
		}
		ns, err := c.owner(ctx, p.Namespace)
		if err != nil {
			return sdk.Result{}, err
		}
		path := "/v2/endpoint/" + ns + "/" + p.Name
		var e endpoint
		if _, err := c.ep.Do(ctx, http.MethodGet, path, nil, nil, &e); err != nil {
			return sdk.Result{}, friendly(err, "endpoint "+ns+"/"+p.Name)
		}
		if call.Action == "endpoint_status" {
			return sdk.JSON(e.summary())
		}
		op := map[string]string{"scale_endpoint_to_zero": "scale-to-zero", "pause_endpoint": "pause", "resume_endpoint": "resume"}[call.Action]
		if call.DryRun {
			before, _ := json.Marshal(e.summary())
			sum := map[string]string{
				"scale-to-zero": "Scale the endpoint " + ns + "/" + p.Name + " to zero (the next request cold-starts it)",
				"pause":         "Pause the endpoint " + ns + "/" + p.Name + " (it refuses requests until resumed)",
				"resume":        "Resume the endpoint " + ns + "/" + p.Name + ", billed by the hour on " + strings.Trim(e.Compute.InstanceType+" "+e.Compute.InstanceSize, " "),
			}[op]
			sum += "; now " + e.Status.State
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "endpoint " + ns + "/" + p.Name, Op: op, Before: before}}}}, nil
		}
		var after endpoint
		if _, err := c.ep.Do(ctx, http.MethodPost, path+"/"+op, nil, nil, &after); err != nil {
			return sdk.Result{}, friendly(err, "endpoint "+ns+"/"+p.Name)
		}
		if after.Name == "" {
			return sdk.JSON(map[string]any{"name": e.Name, "done": op, "stateBefore": e.Status.State})
		}
		return sdk.JSON(after.summary())
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
