// Package portainer works with a Portainer server through an access token
// (X-API-Key): environments, stacks, and the containers and images of each
// Docker environment.
package portainer

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

// Config is one Portainer server.
type Config struct {
	URL   string `json:"url"`   // e.g. https://portainer.example.com:9443
	Token string `json:"token"` // secret:// access token
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Portainer module.
func New() *Module { return &Module{} }

// Container ids are hex; names are letters, digits, _ . and -.
var containerRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	env := `"environment":{"type":"integer","minimum":1,"description":"Environment (endpoint) id"}`
	stack := `{"type":"object","required":["id"],"properties":{"id":{"type":"integer","minimum":1,"description":"Stack id"}}}`
	ctr := `{"type":"object","required":["environment","container"],"properties":{` + env + `,"container":{"type":"string","description":"Container id or name"}}}`
	return sdk.Manifest{
		ID: "portainer", Name: "Portainer", Version: "0.1.0", Category: "Infrastructure", Icon: "container",
		Description: "Portainer environments, stacks, containers and images: start, stop and redeploy.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://portainer.example.com:9443"},
			"token":{"type":"string","x-secret":true,"description":"Access token (My account, Access tokens). It acts with that user's rights"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "environments", Title: "Environments", Description: "Each environment with its state and container counts.", Risk: sdk.RiskRead},
			{Name: "stacks", Title: "Stacks", Description: "Stacks, optionally of one environment.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + env + `}}`)},
			{Name: "start_stack", Title: "Start a stack", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(stack)},
			{Name: "stop_stack", Title: "Stop a stack", Description: "Stops every container of the stack. Undo starts it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(stack)},
			{Name: "redeploy_stack", Title: "Redeploy a stack", Description: "Pulls the stack's Git repository (or reuses its compose file) and recreates its containers. Can't be undone.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"integer","minimum":1},"pullImage":{"type":"boolean","default":true,"description":"Pull newer images first"}}}`)},
			{Name: "containers", Title: "Containers", Description: "Containers of a Docker environment, running and stopped.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["environment"],"properties":{` + env + `}}`)},
			{Name: "start_container", Title: "Start a container", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(ctr)},
			{Name: "stop_container", Title: "Stop a container", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(ctr)},
			{Name: "restart_container", Title: "Restart a container", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(ctr)},
			{Name: "images", Title: "Images", Description: "Images of a Docker environment with size and tags.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["environment"],"properties":{` + env + `}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the address is like https://portainer.example.com:9443")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	tok := c.Token
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api") + "/api"
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("X-API-Key", strings.TrimSpace(t))
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 60*time.Second) // through the instance's network, if any; redeploys take a while
	}
	// The token travels in X-API-Key, which Go would forward to another host.
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
	envs, err := c.environments(ctx)
	if err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) {
			return sdk.Health{Status: "down", Message: "Portainer refused the access token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var st struct {
		Version string `json:"Version"`
	}
	_, _ = c.api.Do(ctx, http.MethodGet, "/system/status", nil, nil, &st)
	down := 0
	for _, e := range envs {
		if e.Status != 1 {
			down++
		}
	}
	msg := fmt.Sprintf("%d environments", len(envs))
	if st.Version != "" {
		msg += " · Portainer " + st.Version
	}
	if down > 0 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%s · %d down", msg, down)}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type environment struct {
	ID        int    `json:"Id"`
	Name      string `json:"Name"`
	Type      int    `json:"Type"`
	URL       string `json:"URL"`
	Status    int    `json:"Status"`
	Snapshots []struct {
		DockerVersion         string `json:"DockerVersion"`
		RunningContainerCount int    `json:"RunningContainerCount"`
		StoppedContainerCount int    `json:"StoppedContainerCount"`
		StackCount            int    `json:"StackCount"`
		ImageCount            int    `json:"ImageCount"`
	} `json:"Snapshots"`
}

var envTypes = map[int]string{1: "docker", 2: "agent", 3: "azure", 4: "edge-agent", 5: "kubernetes", 6: "kubernetes-agent", 7: "kubernetes-edge-agent"}

func (c *conn) environments(ctx context.Context) ([]environment, error) {
	var envs []environment
	_, err := c.api.Do(ctx, http.MethodGet, "/endpoints", nil, nil, &envs)
	return envs, err
}

type envVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type stack struct {
	ID         int      `json:"Id"`
	Name       string   `json:"Name"`
	Type       int      `json:"Type"`
	EndpointID int      `json:"EndpointId"`
	Status     int      `json:"Status"`
	Env        []envVar `json:"Env"`
	GitConfig  *struct {
		URL            string `json:"URL"`
		ReferenceName  string `json:"ReferenceName"`
		ConfigFilePath string `json:"ConfigFilePath"`
	} `json:"GitConfig"`
	UpdateDate int64 `json:"UpdateDate"`
}

var stackTypes = map[int]string{1: "swarm", 2: "compose", 3: "kubernetes"}

func stackState(s int) string {
	switch s {
	case 1:
		return "active"
	case 2:
		return "inactive"
	}
	return "unknown"
}

func (s stack) summary() map[string]any {
	out := map[string]any{"id": s.ID, "name": s.Name, "type": stackTypes[s.Type], "environment": s.EndpointID, "state": stackState(s.Status)}
	if s.GitConfig != nil {
		out["git"] = rest.StripUserinfo(s.GitConfig.URL)
		out["ref"] = s.GitConfig.ReferenceName
	}
	if s.UpdateDate > 0 {
		out["updated"] = time.Unix(s.UpdateDate, 0).UTC().Format(time.RFC3339)
	}
	return out
}

type container struct {
	ID     string   `json:"Id"`
	Names  []string `json:"Names"`
	Image  string   `json:"Image"`
	State  string   `json:"State"`
	Status string   `json:"Status"`
	Labels map[string]string
}

func (c container) name() string {
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	return c.ID
}

type input struct {
	ID          int    `json:"id"`
	Environment int    `json:"environment"`
	Container   string `json:"container"`
	PullImage   *bool  `json:"pullImage"`
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
	case "environments":
		envs, err := c.environments(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, e := range envs {
			state := "down"
			if e.Status == 1 {
				state = "up"
			}
			row := map[string]any{"id": e.ID, "name": e.Name, "type": envTypes[e.Type], "url": rest.StripUserinfo(e.URL), "state": state}
			if len(e.Snapshots) > 0 {
				s := e.Snapshots[len(e.Snapshots)-1]
				row["running"], row["stopped"], row["stacks"], row["images"] = s.RunningContainerCount, s.StoppedContainerCount, s.StackCount, s.ImageCount
				if s.DockerVersion != "" {
					row["dockerVersion"] = s.DockerVersion
				}
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "stacks":
		if p.Environment < 0 {
			return sdk.Result{}, errors.New("the environment id is positive")
		}
		var list []stack
		if _, err := c.api.Do(ctx, http.MethodGet, "/stacks", nil, nil, &list); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range list {
			if p.Environment == 0 || s.EndpointID == p.Environment {
				out = append(out, s.summary())
			}
		}
		return sdk.JSON(out)

	case "start_stack", "stop_stack":
		s, err := c.stack(ctx, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		verb, back, want := "start", "stop_stack", 1
		if call.Action == "stop_stack" {
			verb, back, want = "stop", "start_stack", 2
		}
		if s.Status == want {
			return sdk.Result{}, fmt.Errorf("stack %s is already %s", s.Name, stackState(want))
		}
		if call.DryRun {
			before, _ := json.Marshal(map[string]any{"state": stackState(s.Status)})
			after, _ := json.Marshal(map[string]any{"state": stackState(want)})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s stack %s on environment %d", upper(verb), s.Name, s.EndpointID),
				Changes: []sdk.Change{{Target: "stack " + s.Name, Op: verb, Before: before, After: after}}}}, nil
		}
		q := url.Values{"endpointId": {strconv.Itoa(s.EndpointID)}}
		if _, err := c.api.Do(ctx, http.MethodPost, fmt.Sprintf("/stacks/%d/%s", s.ID, verb), q, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"stack": s.Name, "state": stackState(want)})
		res.Undo = sdk.UndoWith(back, map[string]any{"id": s.ID}, fmt.Sprintf("%s stack %s", upper(strings.TrimSuffix(back, "_stack")), s.Name))
		return res, err

	case "redeploy_stack":
		s, err := c.stack(ctx, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		if s.Type == 3 {
			return sdk.Result{}, errors.New("redeploying Kubernetes stacks isn't supported here")
		}
		pull := p.PullImage == nil || *p.PullImage
		q := url.Values{"endpointId": {strconv.Itoa(s.EndpointID)}}
		env := s.Env
		if env == nil {
			env = []envVar{}
		}
		var path string
		var body map[string]any
		mode := "compose file"
		if s.GitConfig != nil {
			mode = "Git " + rest.StripUserinfo(s.GitConfig.URL) + "@" + s.GitConfig.ReferenceName
			path = fmt.Sprintf("/stacks/%d/git/redeploy", s.ID)
			body = map[string]any{"pullImage": pull, "prune": false, "env": env, "repositoryReferenceName": s.GitConfig.ReferenceName}
		} else {
			var f struct {
				StackFileContent string `json:"StackFileContent"`
			}
			if _, err := c.api.Do(ctx, http.MethodGet, fmt.Sprintf("/stacks/%d/file", s.ID), nil, nil, &f); err != nil {
				return sdk.Result{}, err
			}
			path = fmt.Sprintf("/stacks/%d", s.ID)
			body = map[string]any{"stackFileContent": f.StackFileContent, "env": env, "prune": false, "pullImage": pull}
		}
		if call.DryRun {
			before, _ := json.Marshal(s.summary())
			after, _ := json.Marshal(map[string]any{"from": mode, "pullImage": pull})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Redeploy stack %s from its %s; its containers are recreated", s.Name, mode),
				Changes: []sdk.Change{{Target: "stack " + s.Name, Op: "redeploy", Before: before, After: after}}}}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodPut, path, q, body, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"redeployed": s.Name, "from": mode, "pullImage": pull})

	case "containers", "images":
		if p.Environment <= 0 {
			return sdk.Result{}, errors.New("enter the environment id")
		}
		d := fmt.Sprintf("/endpoints/%d/docker", p.Environment)
		if call.Action == "images" {
			var list []struct {
				ID       string   `json:"Id"`
				RepoTags []string `json:"RepoTags"`
				Size     int64    `json:"Size"`
				Created  int64    `json:"Created"`
			}
			if _, err := c.api.Do(ctx, http.MethodGet, d+"/images/json", nil, nil, &list); err != nil {
				return sdk.Result{}, err
			}
			out := []map[string]any{}
			for _, im := range list {
				out = append(out, map[string]any{"id": shortID(im.ID), "tags": im.RepoTags, "sizeMB": im.Size / 1e6, "created": time.Unix(im.Created, 0).UTC().Format(time.RFC3339)})
			}
			return sdk.JSON(out)
		}
		var list []container
		if _, err := c.api.Do(ctx, http.MethodGet, d+"/containers/json", url.Values{"all": {"1"}}, nil, &list); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, ct := range list {
			row := map[string]any{"id": shortID(ct.ID), "name": ct.name(), "image": ct.Image, "state": ct.State, "status": ct.Status}
			if s := ct.Labels["com.docker.compose.project"]; s != "" {
				row["stack"] = s
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "start_container", "stop_container", "restart_container":
		if p.Environment <= 0 {
			return sdk.Result{}, errors.New("enter the environment id")
		}
		if !containerRe.MatchString(p.Container) {
			return sdk.Result{}, errors.New("enter the container's id or name")
		}
		verb := strings.TrimSuffix(call.Action, "_container")
		path := fmt.Sprintf("/endpoints/%d/docker/containers/%s", p.Environment, p.Container)
		var info struct {
			ID    string `json:"Id"`
			Name  string `json:"Name"`
			State struct {
				Status string `json:"Status"`
			} `json:"State"`
			Config struct {
				Image string `json:"Image"`
			} `json:"Config"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, path+"/json", nil, nil, &info); err != nil {
			return sdk.Result{}, err
		}
		name := strings.TrimPrefix(info.Name, "/")
		if call.DryRun {
			before, _ := json.Marshal(map[string]any{"state": info.State.Status, "image": info.Config.Image})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s container %s on environment %d", upper(verb), name, p.Environment),
				Changes: []sdk.Change{{Target: "container " + name, Op: verb, Before: before}}}}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodPost, path+"/"+verb, nil, nil, nil); err != nil {
			if rest.IsStatus(err, http.StatusNotModified) {
				return sdk.Result{}, fmt.Errorf("container %s is already %s", name, map[string]string{"start": "running", "stop": "stopped"}[verb])
			}
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"container": name, "done": verb})
		undo := map[string]any{"environment": p.Environment, "container": p.Container}
		switch verb {
		case "start":
			res.Undo = sdk.UndoWith("stop_container", undo, "Stop "+name)
		case "stop":
			res.Undo = sdk.UndoWith("start_container", undo, "Start "+name)
		}
		return res, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) stack(ctx context.Context, id int) (stack, error) {
	var s stack
	if id <= 0 {
		return s, errors.New("enter the stack id")
	}
	_, err := c.api.Do(ctx, http.MethodGet, "/stacks/"+strconv.Itoa(id), nil, nil, &s)
	return s, err
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func upper(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
