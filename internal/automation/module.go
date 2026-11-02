package automation

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// InstanceID is the fixed id of the automations module's instance.
const InstanceID = "automations"

// Module exposes automations to agents and keys. Anything saved through it
// is a draft: disabled and untrusted until a person reviews and enables it in
// the app. People manage automations through the REST API and the app.
type Module struct{ S *Service }

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "automations", Name: "Automations", Version: "0.1.0", Category: "Conduit", Icon: "workflow",
		Description: "Chains of actions that run on a schedule, an event or a webhook.",
		Presets:     []string{"developer", "gamer", "homelab", "team"},
		Actions: []sdk.ActionSpec{
			{Name: "list", Title: "Automations", Risk: sdk.RiskRead},
			{Name: "runs", Title: "Recent runs", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string"}}}`)},
			{Name: "run", Title: "Run now", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string"}}}`)},
			{Name: "draft", Title: "Draft an automation", Description: "Saved disabled; a person reviews and enables it.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["name","trigger","steps"],"properties":{"name":{"type":"string"},"trigger":{"type":"object"},"steps":{"type":"array","items":{"type":"object"}}}}`)},
			{Name: "disable", Title: "Turn off", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string"}}}`)},
		},
		Events: []sdk.EventSpec{
			{Type: "automation.run.ok", Description: "An automation finished"},
			{Type: "automation.run.error", Description: "An automation step failed"},
			{Type: "automation.run.denied", Description: "An automation step was blocked or not approved"},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(context.Context, sdk.Host, string, json.RawMessage) error { return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, _ string) sdk.Health {
	list, err := m.S.List(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	on := 0
	for _, a := range list {
		if a.Enabled {
			on++
		}
	}
	return sdk.Health{Status: "ok", Message: plural(on, "automation") + " on"}
}

func plural(n int, w string) string {
	if n == 1 {
		return "1 " + w
	}
	return itoa(n) + " " + w + "s"
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// Close implements sdk.Module.
func (m *Module) Close(string) error { return nil }

var draftActor = core.Actor{ID: "module", Kind: core.ActorAgent, Name: "drafted through the automations module"}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	var in struct {
		ID string `json:"id"`
	}
	switch c.Action {
	case "list":
		l, err := m.S.List(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		for i := range l {
			l[i].HookURL = "" // webhook secrets are for people only
		}
		return sdk.JSON(l)
	case "runs":
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		r, err := m.S.Runs(ctx, in.ID, 20)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(r)
	case "run":
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		a, err := m.S.Get(ctx, in.ID)
		if err != nil {
			return sdk.Result{}, errors.New("no such automation")
		}
		if !a.Enabled {
			return sdk.Result{}, errors.New("this automation is turned off")
		}
		r, err := m.S.Run(ctx, in.ID, json.RawMessage(`{"kind":"manual"}`))
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(r)
	case "draft":
		var a Automation
		if err := sdk.Decode(c, &a); err != nil {
			return sdk.Result{}, err
		}
		a.ID = ""
		saved, err := m.S.Save(ctx, a, draftActor)
		if err != nil {
			return sdk.Result{}, err
		}
		saved.HookURL = ""
		return sdk.JSON(map[string]any{"automation": saved, "note": "Saved as a draft. A person must review and turn it on in Conduit."})
	case "disable":
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		a, err := m.S.SetEnabled(ctx, in.ID, false, draftActor)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"id": a.ID, "enabled": false})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}
