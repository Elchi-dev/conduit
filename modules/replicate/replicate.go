// Package replicate works with a Replicate account through its HTTP API and
// an API token: the account, models, predictions (recent runs with status
// and timing, one run in full), cancelling a running prediction, and
// deployments with their hardware and scaling. It never starts a run.
package replicate

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
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Replicate account.
type Config struct {
	Token string `json:"token"` // secret:// API token
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.replicate.com/v1 (tests).
	Base string
}

// New returns the Replicate module.
func New() *Module { return &Module{} }

var (
	predictionRe = regexp.MustCompile(`^[a-z0-9]{1,64}$`)
	nameRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	cursorRe     = regexp.MustCompile(`^[A-Za-z0-9+/=_.%-]{1,300}$`)
)

const (
	cursorIn     = `{"type":"object","properties":{"cursor":{"type":"string","description":"The next cursor from an earlier page"}}}`
	predictionIn = `{"type":"object","required":["prediction"],"properties":{"prediction":{"type":"string","description":"Prediction id (from predictions)"}}}`
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "replicate", Name: "Replicate", Version: "0.1.0", Category: "Development", Icon: "cpu",
		Description: "Replicate: the account, models, recent predictions with status and run time, one prediction in full, cancel a running one, and deployments with hardware and scaling.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"API token (replicate.com, Account settings, API tokens)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "account", Title: "Account", Description: "The account the token belongs to: user or organization, username and name.", Risk: sdk.RiskRead},
			{Name: "models", Title: "Models", Description: "One model (owner/name) with its description, visibility, run count and latest version, or a page of public models.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"model":{"type":"string","description":"owner/name, e.g. black-forest-labs/flux-schnell"},"cursor":{"type":"string","description":"The next cursor from an earlier page"}}}`)},
			{Name: "predictions", Title: "Predictions", Description: "Recent predictions, newest first: model, status, source (API or web), created, started and finished, run time and any error. Not their inputs or outputs.", Risk: sdk.RiskRead, Input: sdk.Schema(cursorIn)},
			{Name: "prediction", Title: "One prediction", Description: "One prediction in full: status, timing, input, output, logs and error. Inputs and outputs can hold personal data (sensitive).", Risk: sdk.RiskRead, Sensitive: true, Input: sdk.Schema(predictionIn)},
			{Name: "cancel_prediction", Title: "Cancel a prediction", Description: "Stops a prediction that's starting or running; its work so far is lost and it can't be resumed (destructive). Run time used until then is still billed.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(predictionIn)},
			{Name: "deployments", Title: "Deployments", Description: "Deployments with their current release: model and version, hardware, and minimum and maximum instances.", Risk: sdk.RiskRead, Input: sdk.Schema(cursorIn)},
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
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	base := "https://api.replicate.com/v1"
	if m.Base != "" {
		base = m.Base
	}
	ref := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
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
		return errors.New("Replicate refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Replicate refused: the token's account isn't allowed to do this")
	case rest.IsStatus(err, http.StatusNotFound) && what != "":
		return fmt.Errorf("there's no %s (or the token can't see it)", what)
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any, what string) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err, what)
}

type account struct {
	Type     string `json:"type"`
	Username string `json:"username"`
	Name     string `json:"name"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var a account
	if err := c.get(ctx, "/account", nil, &a, ""); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + a.Username}
}

type prediction struct {
	ID          string `json:"id"`
	Model       string `json:"model"`
	Version     string `json:"version"`
	Status      string `json:"status"`
	Source      string `json:"source"`
	CreatedAt   string `json:"created_at"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
	Error       any    `json:"error"`
	DataRemoved bool   `json:"data_removed"`
	Deployment  string `json:"deployment"`
	Metrics     struct {
		PredictTime *float64 `json:"predict_time"`
		TotalTime   *float64 `json:"total_time"`
	} `json:"metrics"`
	// The webhook address (which can carry a secret) and the stream and
	// cancel links aren't decoded.
}

// full is a prediction with its input, output and logs (sensitive).
type full struct {
	prediction
	Input  json.RawMessage `json:"input"`
	Output json.RawMessage `json:"output"`
	Logs   string          `json:"logs"`
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func running(status string) bool { return status == "starting" || status == "processing" }

func (p prediction) summary() map[string]any {
	out := map[string]any{"id": p.ID, "model": p.Model, "status": p.Status, "created": p.CreatedAt}
	for k, v := range map[string]string{"version": p.Version, "source": p.Source, "started": p.StartedAt, "completed": p.CompletedAt, "deployment": p.Deployment} {
		if v != "" {
			out[k] = v
		}
	}
	if p.Metrics.PredictTime != nil {
		out["runSeconds"] = *p.Metrics.PredictTime
	}
	if p.Metrics.TotalTime != nil {
		out["totalSeconds"] = *p.Metrics.TotalTime
	}
	if p.Error != nil {
		s, ok := p.Error.(string)
		if !ok {
			b, _ := json.Marshal(p.Error)
			s = string(b)
		}
		if s != "" {
			out["error"] = rest.Redact(clip(s, 500))
		}
	}
	if p.DataRemoved {
		out["dataRemoved"] = true
	}
	return out
}

// page reads the cursor out of a next link, so only the cursor (never a
// whole address) goes back to the caller.
func page(next string) string {
	if next == "" {
		return ""
	}
	u, err := url.Parse(next)
	if err != nil {
		return ""
	}
	if c := u.Query().Get("cursor"); cursorRe.MatchString(c) {
		return c
	}
	return ""
}

func cursorQuery(c string) (url.Values, error) {
	c = strings.TrimSpace(c)
	if c == "" {
		return nil, nil
	}
	if !cursorRe.MatchString(c) {
		return nil, errors.New("the cursor is the next value from an earlier page")
	}
	return url.Values{"cursor": {c}}, nil
}

func modelPath(s string) (string, error) {
	owner, name, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok || !nameRe.MatchString(owner) || !nameRe.MatchString(name) || strings.Contains(s, "..") {
		return "", errors.New("the model is owner/name, like black-forest-labs/flux-schnell")
	}
	return "/models/" + url.PathEscape(owner) + "/" + url.PathEscape(name), nil
}

type model struct {
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Visibility    string `json:"visibility"`
	RunCount      int64  `json:"run_count"`
	URL           string `json:"url"`
	GithubURL     string `json:"github_url"`
	PaperURL      string `json:"paper_url"`
	LicenseURL    string `json:"license_url"`
	LatestVersion *struct {
		ID        string `json:"id"`
		CreatedAt string `json:"created_at"`
	} `json:"latest_version"`
}

func (x model) summary() map[string]any {
	out := map[string]any{"model": x.Owner + "/" + x.Name, "visibility": x.Visibility, "runs": x.RunCount}
	if x.Description != "" {
		out["description"] = clip(x.Description, 300)
	}
	for k, v := range map[string]string{"url": x.URL, "github": x.GithubURL, "paper": x.PaperURL, "license": x.LicenseURL} {
		if v != "" {
			out[k] = rest.ShortURL(v)
		}
	}
	if x.LatestVersion != nil {
		out["latestVersion"] = x.LatestVersion.ID
		out["latestVersionCreated"] = x.LatestVersion.CreatedAt
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
		Model      string `json:"model"`
		Cursor     string `json:"cursor"`
		Prediction string `json:"prediction"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "account":
		var a account
		if err := c.get(ctx, "/account", nil, &a, ""); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"type": a.Type, "username": a.Username, "name": a.Name})
	case "models":
		if strings.TrimSpace(p.Model) != "" {
			path, err := modelPath(p.Model)
			if err != nil {
				return sdk.Result{}, err
			}
			var x model
			if err := c.get(ctx, path, nil, &x, "model "+strings.TrimSpace(p.Model)); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(x.summary())
		}
		q, err := cursorQuery(p.Cursor)
		if err != nil {
			return sdk.Result{}, err
		}
		var out struct {
			Next    string  `json:"next"`
			Results []model `json:"results"`
		}
		if err := c.get(ctx, "/models", q, &out, ""); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, x := range out.Results {
			list = append(list, x.summary())
		}
		return sdk.JSON(withNext(map[string]any{"models": list}, out.Next))
	case "predictions":
		q, err := cursorQuery(p.Cursor)
		if err != nil {
			return sdk.Result{}, err
		}
		var out struct {
			Next    string       `json:"next"`
			Results []prediction `json:"results"`
		}
		if err := c.get(ctx, "/predictions", q, &out, ""); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, x := range out.Results {
			list = append(list, x.summary())
		}
		return sdk.JSON(withNext(map[string]any{"predictions": list}, out.Next))
	case "prediction", "cancel_prediction":
		id := strings.TrimSpace(p.Prediction)
		if !predictionRe.MatchString(id) {
			return sdk.Result{}, errors.New("a prediction is its id from predictions")
		}
		var x full
		if err := c.get(ctx, "/predictions/"+id, nil, &x, "prediction "+id); err != nil {
			return sdk.Result{}, err
		}
		if x.ID != id {
			// The id goes into the cancel's path.
			return sdk.Result{}, fmt.Errorf("Replicate answered with another prediction for %s", id)
		}
		if call.Action == "prediction" {
			out := x.summary()
			if len(x.Input) > 0 && string(x.Input) != "null" {
				out["input"] = x.Input
			}
			if len(x.Output) > 0 && string(x.Output) != "null" {
				out["output"] = x.Output
			}
			if x.Logs != "" {
				out["logs"] = rest.Redact(clip(x.Logs, 4000))
			}
			return sdk.JSON(out)
		}
		return c.cancel(ctx, call, x.prediction)
	case "deployments":
		q, err := cursorQuery(p.Cursor)
		if err != nil {
			return sdk.Result{}, err
		}
		var out struct {
			Next    string `json:"next"`
			Results []struct {
				Owner   string `json:"owner"`
				Name    string `json:"name"`
				Release *struct {
					Number    int    `json:"number"`
					Model     string `json:"model"`
					Version   string `json:"version"`
					CreatedAt string `json:"created_at"`
					Config    struct {
						Hardware     string `json:"hardware"`
						MinInstances int    `json:"min_instances"`
						MaxInstances int    `json:"max_instances"`
					} `json:"configuration"`
				} `json:"current_release"`
			} `json:"results"`
		}
		if err := c.get(ctx, "/deployments", q, &out, ""); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, d := range out.Results {
			row := map[string]any{"deployment": d.Owner + "/" + d.Name}
			if r := d.Release; r != nil {
				row["release"], row["model"], row["version"], row["released"] = r.Number, r.Model, r.Version, r.CreatedAt
				row["hardware"], row["minInstances"], row["maxInstances"] = r.Config.Hardware, r.Config.MinInstances, r.Config.MaxInstances
			}
			list = append(list, row)
		}
		return sdk.JSON(withNext(map[string]any{"deployments": list}, out.Next))
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func withNext(out map[string]any, next string) map[string]any {
	if c := page(next); c != "" {
		out["next"] = c
	}
	return out
}

func (c *conn) cancel(ctx context.Context, call sdk.Call, x prediction) (sdk.Result, error) {
	if !running(x.Status) {
		return sdk.JSON(map[string]any{"prediction": x.ID, "model": x.Model, "status": x.Status, "note": "nothing to change"})
	}
	if call.DryRun {
		sum := "Cancel the " + x.Status + " prediction " + x.ID + " of " + x.Model
		if t, err := time.Parse(time.RFC3339Nano, x.CreatedAt); err == nil {
			sum += fmt.Sprintf(" (created %s ago)", time.Since(t).Round(time.Second))
		}
		before, _ := json.Marshal(x.summary())
		after, _ := json.Marshal(map[string]string{"status": "canceled"})
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "prediction " + x.ID, Op: "cancel", Before: before, After: after}}}}, nil
	}
	var after prediction
	if _, err := c.api.Do(ctx, http.MethodPost, "/predictions/"+x.ID+"/cancel", nil, nil, &after); err != nil {
		return sdk.Result{}, friendly(err, "prediction "+x.ID)
	}
	status := after.Status
	if status == "" {
		status = "canceled"
	}
	return sdk.JSON(map[string]any{"prediction": x.ID, "model": x.Model, "status": status, "statusBefore": x.Status})
}
