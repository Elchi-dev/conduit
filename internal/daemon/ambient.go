package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// ambientModule is signature feature 9: Conduit's state shown outside the
// app, on a light, a Stream Deck key, a Discord channel or anything that
// takes a webhook. It boils everything down to one of four states and
// pushes only when the state changes.
type ambientModule struct {
	app *App

	mu   sync.Mutex
	cfg  ambientConfig
	host sdk.Host
	last Ambient
	http *http.Client
}

const ambientID = "status"

type ambientConfig struct {
	// Webhook receives the state as JSON on every change. May be a vault
	// reference, since webhook URLs often carry a token.
	Webhook string `json:"webhook"`
	// Light is a Home Assistant light that takes the state's colour.
	Light struct {
		Instance string `json:"instance"`
		Entity   string `json:"entity"`
	} `json:"light"`
	// Discord posts changes through a Discord instance.
	Discord string `json:"discord"`
}

// Ambient is the boiled-down state.
type Ambient struct {
	State   string    `json:"state"` // ok, attention, down, stopped
	Color   string    `json:"color"` // green, amber, red, purple
	Summary string    `json:"summary"`
	Waiting int       `json:"approvalsWaiting"`
	Down    []string  `json:"down"`
	Since   time.Time `json:"since"`
}

var ambientColors = map[string]string{"ok": "green", "attention": "amber", "down": "red", "stopped": "purple"}

func (a *ambientModule) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "status", Name: "Ambient status", Version: "0.1.0", Category: "Conduit", Icon: "lamp",
		Description: "Conduit's state on a smart light, a Stream Deck key, Discord or any webhook: green, amber, red.",
		Presets:     []string{"gamer", "homelab", "developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"webhook":{"type":"string","x-secret":true,"description":"A URL that receives the state as JSON whenever it changes"},
			"light":{"type":"object","properties":{
				"instance":{"type":"string","description":"Your Home Assistant connection's ID"},
				"entity":{"type":"string","description":"A light, e.g. light.desk"}}},
			"discord":{"type":"string","description":"A Discord connection's ID, to post changes"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Current state", Description: "ok, attention, down or stopped, with why.", Risk: sdk.RiskRead},
			{Name: "push", Title: "Send it now", Description: "Pushes the current state to the light, webhook and Discord.", Risk: sdk.RiskWrite},
		},
		Events: []sdk.EventSpec{{Type: "status.changed", Description: "The ambient state changed"}},
	}
}

func (a *ambientModule) Configure(_ context.Context, h sdk.Host, _ string, raw json.RawMessage) error {
	var c ambientConfig
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("invalid settings: %w", err)
		}
	}
	if (c.Light.Instance == "") != (c.Light.Entity == "") {
		return errors.New("for a status light, set both the Home Assistant connection and the light")
	}
	if c.Light.Entity != "" && !strings.HasPrefix(c.Light.Entity, "light.") {
		return errors.New("the status light must be a light.* entity")
	}
	a.mu.Lock()
	a.cfg, a.host = c, h
	if a.http == nil {
		a.http = &http.Client{Timeout: 10 * time.Second}
	}
	a.mu.Unlock()
	return nil
}

func (a *ambientModule) Health(context.Context, string) sdk.Health {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.last.State == "" {
		return sdk.Health{Status: "ok", Message: "Starting"}
	}
	return sdk.Health{Status: "ok", Message: "Showing " + a.last.State}
}

func (a *ambientModule) Close(string) error { return nil }

// compute boils the daemon's state down.
func (a *ambientModule) compute(ctx context.Context) Ambient {
	e := a.app.Engine
	st := Ambient{State: "ok", Down: []string{}}
	if frozen, _ := e.Policy.Frozen(ctx); frozen {
		st.State, st.Summary = "stopped", "Emergency stop is on"
	}
	if list, err := e.Approvals.List(ctx, "pending"); err == nil {
		st.Waiting = len(list)
	}
	degraded := 0
	for _, in := range e.Instances("") {
		if in.ID == ambientID || !in.Enabled {
			continue
		}
		hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		h := e.Health(hctx, in.ID)
		cancel()
		switch h.Status {
		case "down":
			st.Down = append(st.Down, in.Name)
		case "degraded":
			degraded++
		}
	}
	if st.State == "stopped" {
		return st
	}
	switch {
	case len(st.Down) > 0:
		st.State, st.Summary = "down", "Down: "+strings.Join(st.Down, ", ")
	case st.Waiting > 0 || degraded > 0:
		st.State = "attention"
		var parts []string
		if st.Waiting == 1 {
			parts = append(parts, "1 approval waiting")
		} else if st.Waiting > 1 {
			parts = append(parts, fmt.Sprintf("%d approvals waiting", st.Waiting))
		}
		if degraded == 1 {
			parts = append(parts, "1 connection needs a look")
		} else if degraded > 1 {
			parts = append(parts, fmt.Sprintf("%d connections need a look", degraded))
		}
		st.Summary = strings.Join(parts, ", ")
	default:
		st.Summary = "All good"
	}
	return st
}

// Current returns the last computed state, computing it if needed.
func (a *ambientModule) Current(ctx context.Context) Ambient {
	a.mu.Lock()
	last := a.last
	a.mu.Unlock()
	if last.State != "" {
		return last
	}
	st := a.compute(ctx)
	st.Color, st.Since = ambientColors[st.State], time.Now().UTC()
	return st
}

// push sends a state everywhere configured. Errors are logged, not fatal.
func (a *ambientModule) push(ctx context.Context, st Ambient) []string {
	a.mu.Lock()
	cfg, h, client := a.cfg, a.host, a.http
	a.mu.Unlock()
	var problems []string
	if cfg.Webhook != "" {
		u := cfg.Webhook
		if strings.HasPrefix(u, "secret://") && h == nil {
			u = ""
		} else if strings.HasPrefix(u, "secret://") {
			var err error
			if u, err = h.Secret(ctx, u); err != nil {
				problems = append(problems, "webhook: "+err.Error())
				u = ""
			}
		}
		if u != "" {
			b, _ := json.Marshal(st)
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "Conduit")
			if res, err := client.Do(req); err != nil {
				problems = append(problems, "webhook unreachable")
			} else {
				res.Body.Close()
				if res.StatusCode >= 300 {
					problems = append(problems, "webhook answered "+res.Status)
				}
			}
		}
	}
	invoke := func(instance, action string, in any) {
		b, _ := json.Marshal(in)
		if _, err := a.app.Engine.Invoke(ctx, systemActor, sdk.Call{Instance: instance, Action: action, Input: b}, core.InvokeOptions{NoWait: true}); err != nil {
			problems = append(problems, instance+": "+err.Error())
		}
	}
	if cfg.Light.Entity != "" {
		invoke(cfg.Light.Instance, "set_light", map[string]any{"entity": cfg.Light.Entity, "color": st.Color})
	}
	if cfg.Discord != "" {
		invoke(cfg.Discord, "send", map[string]string{"message": "Conduit: " + st.Summary})
	}
	return problems
}

// Watch recomputes every 15 seconds and on relevant events, and pushes when
// the state changes.
func (a *ambientModule) Watch(ctx context.Context) {
	events, stop := a.app.Engine.Bus.Subscribe("", 64)
	defer stop()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	check := func() {
		st := a.compute(ctx)
		a.mu.Lock()
		prev := a.last
		changed := prev.State != st.State
		if changed {
			st.Since = time.Now().UTC()
		} else {
			st.Since = prev.Since
		}
		st.Color = ambientColors[st.State]
		a.last = st
		configured := a.host != nil
		a.mu.Unlock()
		if !changed || !configured {
			return
		}
		b, _ := json.Marshal(st)
		a.app.Engine.Bus.Publish(sdk.Event{Type: "status.changed", Module: "status", Instance: ambientID, Data: b})
		if prev.State != "" { // don't flash the light on every start
			if p := a.push(ctx, st); len(p) > 0 {
				a.app.Server.Log.Warn("ambient status: push problems", "problems", strings.Join(p, "; "))
			}
		}
	}
	check()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		case ev, ok := <-events:
			if !ok {
				return
			}
			if strings.HasPrefix(ev.Type, "approval.") || strings.HasPrefix(ev.Type, "panic.") || strings.HasSuffix(ev.Type, ".down") || strings.HasSuffix(ev.Type, ".up") {
				check()
			}
		}
	}
}

func (a *ambientModule) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	switch c.Action {
	case "status":
		return sdk.JSON(a.Current(ctx))
	case "push":
		st := a.Current(ctx)
		if p := a.push(ctx, st); len(p) > 0 {
			return sdk.Result{}, errors.New(strings.Join(p, "; "))
		}
		return sdk.JSON(st)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}

// ambientRoute serves the state for devices that poll (a Stream Deck
// plugin, a status bar), with any key that can read modules.
func (s *Server) ambientRoutes() []route {
	return []route{{"GET /api/v1/ambient", s.need("modules:*:read", s.ambient)}}
}

func (s *Server) ambient(w http.ResponseWriter, r *http.Request) {
	if s.Ambient == nil {
		writeErr(w, http.StatusNotFound, "ambient status isn't running")
		return
	}
	writeJSON(w, http.StatusOK, s.Ambient.Current(r.Context()))
}
