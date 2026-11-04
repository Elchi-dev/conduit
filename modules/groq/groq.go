// Package groq reads a GroqCloud account through its API: the models the
// key can use, whether each is active, its owner and context window.
// Nothing it does sends prompts or spends credit.
package groq

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one GroqCloud account.
type Config struct {
	APIKey string `json:"apiKey"` // secret://
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.groq.com/openai/v1 (tests).
	Base string
}

// New returns the Groq module.
func New() *Module { return &Module{} }

const maxModels = 200

var searchRe = regexp.MustCompile(`^[A-Za-z0-9 ._:/@+-]{1,100}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "groq", Name: "Groq", Version: "0.1.0", Category: "Development", Icon: "chip",
		Description: "GroqCloud: the models your API key can use, whether each is active, its owner and context window. Read-only.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey"],"properties":{
			"apiKey":{"type":"string","x-secret":true,"description":"API key (console.groq.com, API Keys)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "models", Title: "Models", Description: "Models the key can use: owner, whether it's active, context window and largest completion.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","maxLength":100,"description":"Only ids or owners containing this, e.g. llama"},"active":{"type":"boolean","description":"Only active (true) or inactive (false) models"},"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	base := "https://api.groq.com/openai/v1"
	if m.Base != "" {
		base = m.Base
	}
	ref := c.APIKey
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k))
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

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Groq refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Groq refused: the API key isn't allowed to list models")
	}
	return err
}

type model struct {
	ID                  string `json:"id"`
	Created             int64  `json:"created"`
	OwnedBy             string `json:"owned_by"`
	Active              *bool  `json:"active"`
	ContextWindow       int64  `json:"context_window"`
	MaxCompletionTokens int64  `json:"max_completion_tokens"`
}

func (c *conn) models(ctx context.Context) ([]model, error) {
	var out struct {
		Data []model `json:"data"`
	}
	_, err := c.api.Do(ctx, http.MethodGet, "/models", nil, nil, &out)
	return out.Data, friendly(err)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	list, err := c.models(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("API key accepted, %d models", len(list))}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Search string `json:"search"`
		Active *bool  `json:"active"`
		Limit  int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "models":
		if p.Search != "" && !searchRe.MatchString(p.Search) {
			return sdk.Result{}, errors.New("search with letters, digits and . _ : / @ + - only")
		}
		if p.Limit <= 0 || p.Limit > maxModels {
			p.Limit = 50
		}
		all, err := c.models(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			ID                  string `json:"id"`
			OwnedBy             string `json:"ownedBy,omitempty"`
			Active              bool   `json:"active"`
			ContextWindow       int64  `json:"contextWindow,omitempty"`
			MaxCompletionTokens int64  `json:"maxCompletionTokens,omitempty"`
			Created             string `json:"created,omitempty"`
		}
		q := strings.ToLower(p.Search)
		list := []row{}
		for _, x := range all {
			active := x.Active == nil || *x.Active
			if p.Active != nil && active != *p.Active {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(x.ID), q) && !strings.Contains(strings.ToLower(x.OwnedBy), q) {
				continue
			}
			r := row{ID: x.ID, OwnedBy: x.OwnedBy, Active: active, ContextWindow: x.ContextWindow, MaxCompletionTokens: x.MaxCompletionTokens}
			if x.Created > 0 {
				r.Created = time.Unix(x.Created, 0).UTC().Format("2006-01-02")
			}
			list = append(list, r)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		total := len(list)
		if len(list) > p.Limit {
			list = list[:p.Limit]
		}
		return sdk.JSON(map[string]any{"models": list, "matching": total})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
