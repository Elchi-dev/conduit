// Package sentry shows a Sentry organization's errors and resolves or
// ignores issues. Works with sentry.io and self-hosted Sentry.
package sentry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Sentry organization.
type Config struct {
	URL          string `json:"url"`          // default https://sentry.io
	Organization string `json:"organization"` // org slug
	Token        string `json:"token"`        // secret:// auth token
}

type conn struct {
	cfg Config
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Sentry module.
func New() *Module { return &Module{} }

var (
	slugRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,49}$`)
	issueRe = regexp.MustCompile(`^[0-9]{1,20}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	id := sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"The issue's numeric id"}}}`)
	return sdk.Manifest{
		ID: "sentry", Name: "Sentry", Version: "0.1.0", Category: "Development", Icon: "bug",
		Description: "Unresolved errors in your Sentry projects, with their latest event; resolve or ignore them.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["organization","token"],"properties":{
			"url":{"type":"string","format":"uri","default":"https://sentry.io","description":"Your Sentry address; leave as is for sentry.io (or https://de.sentry.io)"},
			"organization":{"type":"string","description":"Organization slug, as in the address bar"},
			"token":{"type":"string","x-secret":true,"description":"An auth token (Settings, Auth Tokens) with org:read, project:read and event:write"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Risk: sdk.RiskRead},
			{Name: "issues", Title: "Unresolved issues", Description: "Most recent first, with event and user counts.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"project":{"type":"string","description":"Project slug (optional)"},"query":{"type":"string","description":"Extra Sentry search, e.g. level:error"}}}`)},
			{Name: "issue", Title: "Issue details", Description: "The issue and a summary of its latest event.", Risk: sdk.RiskRead, Input: id},
			{Name: "resolve", Title: "Resolve an issue", Risk: sdk.RiskWrite, Reversible: true, Input: id},
			{Name: "ignore", Title: "Ignore an issue", Risk: sdk.RiskWrite, Reversible: true, Input: id},
			{Name: "unresolve", Title: "Mark an issue unresolved", Risk: sdk.RiskWrite, Input: id},
		},
	}
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if c.URL == "" {
		c.URL = "https://sentry.io"
	}
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || u.Host == "" || !(u.Scheme == "https" || (u.Scheme == "http" && loopback(u.Hostname()))) {
		return errors.New("the address is https://sentry.io or your self-hosted Sentry's https:// address")
	}
	if !slugRe.MatchString(c.Organization) {
		return errors.New("the organization is its slug, as in the address bar (lowercase)")
	}
	if c.Token == "" {
		return errors.New("add an auth token (stored in the vault)")
	}
	tok := c.Token
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/")+"/api/0", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	}
	m.set.Put(id, &conn{cfg: c, api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) org() string { return "/organizations/" + c.cfg.Organization }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var o struct {
		Name string `json:"name"`
	}
	if _, err := c.api.Do(ctx, "GET", c.org()+"/", nil, nil, &o); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: o.Name}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		ID      string `json:"id"`
		Project string `json:"project"`
		Query   string `json:"query"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "projects":
		var ps []struct {
			Slug     string `json:"slug"`
			Name     string `json:"name"`
			Platform string `json:"platform"`
		}
		if _, err := c.api.Do(ctx, "GET", c.org()+"/projects/", nil, nil, &ps); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]string{}
		for _, x := range ps {
			out = append(out, map[string]string{"project": x.Slug, "name": x.Name, "platform": x.Platform})
		}
		return sdk.JSON(out)

	case "issues":
		q := "is:unresolved"
		if p.Project != "" {
			if !slugRe.MatchString(p.Project) {
				return sdk.Result{}, errors.New("a project is its slug")
			}
			q += " project:" + p.Project
		}
		if extra := strings.TrimSpace(p.Query); extra != "" {
			q += " " + extra
		}
		var is []struct {
			ID        string                `json:"id"`
			ShortID   string                `json:"shortId"`
			Title     string                `json:"title"`
			Culprit   string                `json:"culprit"`
			Level     string                `json:"level"`
			Count     string                `json:"count"`
			UserCount int                   `json:"userCount"`
			LastSeen  string                `json:"lastSeen"`
			Permalink string                `json:"permalink"`
			Project   struct{ Slug string } `json:"project"`
		}
		if _, err := c.api.Do(ctx, "GET", c.org()+"/issues/", url.Values{"query": {q}, "limit": {"25"}, "sort": {"date"}}, nil, &is); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, i := range is {
			out = append(out, map[string]any{"id": i.ID, "shortId": i.ShortID, "title": i.Title, "where": i.Culprit, "level": i.Level,
				"events": i.Count, "users": i.UserCount, "lastSeen": i.LastSeen, "project": i.Project.Slug, "url": i.Permalink})
		}
		return sdk.JSON(out)

	case "issue":
		if !issueRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("an issue id is a number")
		}
		var i struct {
			ShortID   string `json:"shortId"`
			Title     string `json:"title"`
			Culprit   string `json:"culprit"`
			Status    string `json:"status"`
			Count     string `json:"count"`
			UserCount int    `json:"userCount"`
			FirstSeen string `json:"firstSeen"`
			LastSeen  string `json:"lastSeen"`
			Permalink string `json:"permalink"`
		}
		if _, err := c.api.Do(ctx, "GET", c.org()+"/issues/"+p.ID+"/", nil, nil, &i); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"shortId": i.ShortID, "title": i.Title, "where": i.Culprit, "status": i.Status, "events": i.Count,
			"users": i.UserCount, "firstSeen": i.FirstSeen, "lastSeen": i.LastSeen, "url": i.Permalink}
		var ev struct {
			EventID     string `json:"eventID"`
			DateCreated string `json:"dateCreated"`
			Message     string `json:"message"`
			Platform    string `json:"platform"`
			Tags        []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"tags"`
		}
		if _, err := c.api.Do(ctx, "GET", c.org()+"/issues/"+p.ID+"/events/latest/", nil, nil, &ev); err == nil {
			tags := map[string]string{}
			for _, t := range ev.Tags {
				switch t.Key {
				case "environment", "release", "browser", "os", "server_name", "level", "url", "transaction":
					tags[t.Key] = t.Value
				}
			}
			out["latest"] = map[string]any{"event": ev.EventID, "at": ev.DateCreated, "message": ev.Message, "platform": ev.Platform, "tags": tags}
		}
		return sdk.JSON(out)

	case "resolve", "ignore", "unresolve":
		if !issueRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("an issue id is a number")
		}
		status := map[string]string{"resolve": "resolved", "ignore": "ignored", "unresolve": "unresolved"}[call.Action]
		if _, err := c.api.Do(ctx, "PUT", c.org()+"/issues/"+p.ID+"/", nil, map[string]string{"status": status}, nil); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"id": p.ID, "status": status})
		if call.Action != "unresolve" {
			r.Undo = sdk.UndoWith("unresolve", map[string]string{"id": p.ID}, "Mark it unresolved again")
		}
		return r, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
