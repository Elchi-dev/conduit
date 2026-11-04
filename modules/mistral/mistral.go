// Package mistral reads a Mistral AI account through its API: the models
// the key can use, with context length, capabilities, aliases and
// deprecation dates. Nothing it does sends prompts or spends credit.
package mistral

import (
	"bytes"
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

// Config is one Mistral account.
type Config struct {
	APIKey string `json:"apiKey"` // secret://
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.mistral.ai/v1 (tests).
	Base string
}

// New returns the Mistral module.
func New() *Module { return &Module{} }

const maxModels = 200

var searchRe = regexp.MustCompile(`^[A-Za-z0-9 ._:/@+-]{1,100}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "mistral", Name: "Mistral AI", Version: "0.1.0", Category: "Development", Icon: "chip",
		Description: "Mistral AI: the models your API key can use, with context length, capabilities, aliases and deprecation dates. Read-only.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey"],"properties":{
			"apiKey":{"type":"string","x-secret":true,"description":"API key (Mistral console, API keys)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "models", Title: "Models", Description: "Models the key can use (base and your fine-tuned ones): context length, capabilities, aliases and deprecation date.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","maxLength":100,"description":"Only ids or names containing this, e.g. large"},"type":{"type":"string","enum":["base","fine-tuned"]},"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}}}`)},
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
	base := "https://api.mistral.ai/v1"
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
		return errors.New("Mistral refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Mistral refused: the API key isn't allowed to list models")
	}
	return err
}

type card struct {
	ID               string         `json:"id"`
	Name             *string        `json:"name"`
	Created          int64          `json:"created"`
	OwnedBy          string         `json:"owned_by"`
	MaxContextLength int64          `json:"max_context_length"`
	Aliases          []string       `json:"aliases"`
	Deprecation      *string        `json:"deprecation"`
	Replacement      *string        `json:"deprecation_replacement_model"`
	Type             string         `json:"type"`
	Archived         bool           `json:"archived"`
	Capabilities     map[string]any `json:"capabilities"`
}

func (c *conn) models(ctx context.Context) ([]card, error) {
	var raw json.RawMessage
	if _, err := c.api.Do(ctx, http.MethodGet, "/models", nil, nil, &raw); err != nil {
		return nil, friendly(err)
	}
	// The API answers {"object":"list","data":[...]}; its documented
	// example is a bare list, so both are read.
	var list []card
	if t := bytes.TrimSpace(raw); len(t) > 0 && t[0] == '[' {
		if err := json.Unmarshal(t, &list); err != nil {
			return nil, errors.New("unexpected answer from Mistral")
		}
		return list, nil
	}
	var out struct {
		Data []card `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, errors.New("unexpected answer from Mistral")
	}
	return out.Data, nil
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

func day(s *string) string {
	if s == nil || len(*s) < 10 {
		return ""
	}
	return (*s)[:10]
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Search string `json:"search"`
		Type   string `json:"type"`
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
		if p.Type != "" && p.Type != "base" && p.Type != "fine-tuned" {
			return sdk.Result{}, errors.New("type is base or fine-tuned")
		}
		if p.Limit <= 0 || p.Limit > maxModels {
			p.Limit = 50
		}
		cards, err := c.models(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		type model struct {
			ID            string   `json:"id"`
			Name          string   `json:"name,omitempty"`
			Type          string   `json:"type"`
			OwnedBy       string   `json:"ownedBy,omitempty"`
			ContextLength int64    `json:"contextLength,omitempty"`
			Capabilities  []string `json:"capabilities"`
			Aliases       []string `json:"aliases,omitempty"`
			Deprecation   string   `json:"deprecation,omitempty"`
			Replacement   string   `json:"replacement,omitempty"`
			Archived      bool     `json:"archived,omitempty"`
		}
		q := strings.ToLower(p.Search)
		list := []model{}
		for _, x := range cards {
			typ := x.Type
			if typ == "" {
				typ = "base"
			}
			name := ""
			if x.Name != nil {
				name = *x.Name
			}
			if q != "" && !strings.Contains(strings.ToLower(x.ID), q) && !strings.Contains(strings.ToLower(name), q) {
				continue
			}
			if p.Type != "" && typ != p.Type {
				continue
			}
			caps := []string{}
			for k, v := range x.Capabilities {
				if b, ok := v.(bool); ok && b {
					caps = append(caps, k)
				}
			}
			sort.Strings(caps)
			mo := model{ID: x.ID, Name: name, Type: typ, OwnedBy: x.OwnedBy, ContextLength: x.MaxContextLength, Capabilities: caps,
				Aliases: x.Aliases, Deprecation: day(x.Deprecation), Archived: x.Archived}
			if x.Replacement != nil {
				mo.Replacement = *x.Replacement
			}
			list = append(list, mo)
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
