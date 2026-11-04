// Package netlify works with Netlify sites through a personal access token:
// sites and deploys (status and build summary), triggering builds, rolling
// production back to an earlier deploy, and locking auto-publishing.
package netlify

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

// Config is one Netlify user (optionally narrowed to one team).
type Config struct {
	Token   string `json:"token"`   // secret:// personal access token
	Account string `json:"account"` // team slug; empty for every team
}

type conn struct {
	api     *rest.Client
	account string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.netlify.com/api/v1 (tests).
	Base string
}

// New returns the Netlify module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.netlify.com/api/v1"

var (
	// A site is its API id (a UUID) or its domain (name.netlify.app, or a
	// custom domain).
	siteRe    = regexp.MustCompile(`^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[a-z0-9](?:[a-z0-9-]{0,62})(?:\.[a-z0-9](?:[a-z0-9-]{0,62}))*)$`)
	deployRe  = regexp.MustCompile(`^[0-9a-f]{24}$`)
	accountRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

func siteID(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > 253 || !siteRe.MatchString(s) {
		return "", errors.New("the site is its API id or its domain, like my-site.netlify.app")
	}
	return s, nil
}

func deployID(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !deployRe.MatchString(s) {
		return "", errors.New("the deploy is a deploy id (24 hex characters, see deploys)")
	}
	return s, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	site := `"site":{"type":"string","description":"Site id or domain (my-site.netlify.app)"}`
	deploy := `"deploy":{"type":"string","description":"Deploy id (see deploys)"}`
	return sdk.Manifest{
		ID: "netlify", Name: "Netlify", Version: "0.1.0", Category: "Development", Icon: "rocket",
		Description: "Netlify sites and deploys: build status and summary, trigger builds, roll back production, lock auto-publishing.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"Personal access token (User settings, Applications, Personal access tokens), with an expiry"},
			"account":{"type":"string","description":"Team slug, to see only that team's sites; empty for every team you're in"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "sites", Title: "Sites", Description: "Every site with its address, repository and the deploy that's live.", Risk: sdk.RiskRead},
			{Name: "site", Title: "Site details", Description: "A site's settings, live deploy and whether auto-publishing is locked.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["site"],"properties":{` + site + `}}`)},
			{Name: "deploys", Title: "Deploys", Description: "A site's recent deploys: state, context, branch, commit, build time, error.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["site"],"properties":{` + site + `,"limit":{"type":"integer","default":20,"maximum":100},"production":{"type":"boolean","description":"Only production deploys"}}}`)},
			{Name: "deploy", Title: "Deploy status", Description: "One deploy's state and build summary: what the build reported, the error, timing.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["deploy"],"properties":{` + deploy + `}}`)},
			{Name: "trigger_build", Title: "Trigger a build", Description: "Starts a new build of the production branch.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["site"],"properties":{` + site + `,"clearCache":{"type":"boolean","description":"Clear the build cache first"}}}`)},
			{Name: "rollback", Title: "Roll back production", Description: "Publishes an earlier deploy as production (the previous good one unless given). Visitors see it at once. Undo publishes the one that was live.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["site"],"properties":{` + site + `,` + deploy + `}}`)},
			{Name: "lock_publishing", Title: "Lock auto-publishing", Description: "Locks the live deploy so new builds stop going live by themselves. Undo unlocks.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["site"],"properties":{` + site + `}}`)},
			{Name: "unlock_publishing", Title: "Unlock auto-publishing", Description: "New production builds go live again (the next one replaces what's live). Undo locks again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["site"],"properties":{` + site + `}}`)},
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
	acct := strings.TrimSpace(c.Account)
	if acct != "" && !accountRe.MatchString(acct) {
		return errors.New("the team slug is lowercase letters, digits and dashes, as in app.netlify.com/teams/<slug>")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	tok := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &conn{api: api, account: acct})
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
	var u struct {
		FullName string `json:"full_name"`
		Slug     string `json:"slug"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/user", nil, nil, &u); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Health{Status: "down", Message: "Netlify refused the token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	name := u.FullName
	if name == "" {
		name = u.Slug
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + name}
}

type deploy struct {
	ID           string  `json:"id"`
	SiteID       string  `json:"site_id"`
	State        string  `json:"state"`
	Context      string  `json:"context"`
	Branch       string  `json:"branch"`
	CommitRef    *string `json:"commit_ref"`
	CommitURL    *string `json:"commit_url"`
	Title        *string `json:"title"`
	ErrorMessage *string `json:"error_message"`
	DeployURL    string  `json:"deploy_ssl_url"`
	AdminURL     string  `json:"admin_url"`
	CreatedAt    string  `json:"created_at"`
	PublishedAt  *string `json:"published_at"`
	DeployTime   *int    `json:"deploy_time"`
	Locked       *bool   `json:"locked"`
	Skipped      *bool   `json:"skipped"`
	Summary      *struct {
		Status   string `json:"status"`
		Messages []struct {
			Type        string `json:"type"`
			Title       string `json:"title"`
			Description string `json:"description"`
			Details     string `json:"details"`
		} `json:"messages"`
	} `json:"summary"`
}

type site struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	URL             string  `json:"ssl_url"`
	AdminURL        string  `json:"admin_url"`
	State           string  `json:"state"`
	UpdatedAt       string  `json:"updated_at"`
	AccountSlug     string  `json:"account_slug"`
	PublishedDeploy *deploy `json:"published_deploy"`
	BuildSettings   *struct {
		RepoURL    string `json:"repo_url"`
		RepoBranch string `json:"repo_branch"`
		StopBuilds bool   `json:"stop_builds"`
	} `json:"build_settings"`
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

func deployOut(d deploy) map[string]any {
	out := map[string]any{"id": d.ID, "state": d.State, "context": d.Context, "branch": d.Branch, "created": d.CreatedAt, "url": d.DeployURL}
	if c := str(d.CommitRef); c != "" {
		out["commit"] = c
	}
	if t := str(d.Title); t != "" {
		out["title"] = clip(t, 200)
	}
	if e := str(d.ErrorMessage); e != "" {
		out["error"] = clip(e, 500)
	}
	if d.DeployTime != nil {
		out["buildSeconds"] = *d.DeployTime
	}
	if p := str(d.PublishedAt); p != "" {
		out["published"] = p
	}
	if d.Locked != nil && *d.Locked {
		out["locked"] = true
	}
	return out
}

func siteOut(s site) map[string]any {
	out := map[string]any{"id": s.ID, "name": s.Name, "url": s.URL, "admin": s.AdminURL, "team": s.AccountSlug, "updated": s.UpdatedAt}
	if s.BuildSettings != nil {
		out["repo"], out["branch"] = s.BuildSettings.RepoURL, s.BuildSettings.RepoBranch
		if s.BuildSettings.StopBuilds {
			out["buildsStopped"] = true
		}
	}
	if d := s.PublishedDeploy; d != nil {
		live := map[string]any{"id": d.ID, "created": d.CreatedAt, "commit": str(d.CommitRef)}
		if p := str(d.PublishedAt); p != "" {
			live["published"] = p
		}
		out["live"] = live
		out["autoPublishLocked"] = d.Locked != nil && *d.Locked
	}
	return out
}

func (c *conn) getSite(ctx context.Context, raw string) (site, error) {
	var s site
	id, err := siteID(raw)
	if err != nil {
		return s, err
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/sites/"+id, nil, nil, &s); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return s, fmt.Errorf("there's no site %s (or the token can't see it)", id)
		}
		return s, err
	}
	if !siteRe.MatchString(s.ID) {
		return s, errors.New("unexpected site id from Netlify")
	}
	return s, nil
}

func (c *conn) getDeploy(ctx context.Context, raw string) (deploy, error) {
	var d deploy
	id, err := deployID(raw)
	if err != nil {
		return d, err
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/deploys/"+id, nil, nil, &d); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return d, fmt.Errorf("there's no deploy %s", id)
		}
		return d, err
	}
	return d, nil
}

type input struct {
	Site       string `json:"site"`
	Deploy     string `json:"deploy"`
	Limit      int    `json:"limit"`
	Production bool   `json:"production"`
	ClearCache bool   `json:"clearCache"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
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
	case "sites":
		path := "/sites"
		if c.account != "" {
			path = "/" + c.account + "/sites"
		}
		out := []map[string]any{}
		for pg := 1; pg <= 10; pg++ {
			var ss []site
			q := url.Values{"filter": {"all"}, "page": {strconv.Itoa(pg)}, "per_page": {"100"}}
			if _, err := c.api.Do(ctx, http.MethodGet, path, q, nil, &ss); err != nil {
				return sdk.Result{}, err
			}
			for _, s := range ss {
				out = append(out, siteOut(s))
			}
			if len(ss) < 100 {
				break
			}
		}
		return sdk.JSON(out)

	case "site":
		s, err := c.getSite(ctx, p.Site)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(siteOut(s))

	case "deploys":
		s, err := c.getSite(ctx, p.Site)
		if err != nil {
			return sdk.Result{}, err
		}
		ds, err := c.deploys(ctx, s.ID, p.Limit, p.Production)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range ds {
			o := deployOut(d)
			if s.PublishedDeploy != nil && d.ID == s.PublishedDeploy.ID {
				o["live"] = true
			}
			out = append(out, o)
		}
		return sdk.JSON(out)

	case "deploy":
		d, err := c.getDeploy(ctx, p.Deploy)
		if err != nil {
			return sdk.Result{}, err
		}
		out := deployOut(d)
		out["admin"] = d.AdminURL
		if d.Skipped != nil && *d.Skipped {
			out["skipped"] = true
		}
		if d.Summary != nil {
			msgs := []map[string]any{}
			for i, msg := range d.Summary.Messages {
				if i == 30 {
					break
				}
				msgs = append(msgs, map[string]any{"type": msg.Type, "title": clip(msg.Title, 200), "description": clip(msg.Description, 1000), "details": clip(msg.Details, 2000)})
			}
			out["summary"] = map[string]any{"status": d.Summary.Status, "messages": msgs}
		}
		return sdk.JSON(out)

	case "trigger_build":
		s, err := c.getSite(ctx, p.Site)
		if err != nil {
			return sdk.Result{}, err
		}
		if s.BuildSettings == nil || s.BuildSettings.RepoURL == "" {
			return sdk.Result{}, fmt.Errorf("%s isn't linked to a repository, so there's nothing to build", s.Name)
		}
		branch := s.BuildSettings.RepoBranch
		if call.DryRun {
			sum := fmt.Sprintf("Build %s from %s", s.Name, branch)
			if p.ClearCache {
				sum += " with a clear cache"
			}
			if s.PublishedDeploy != nil && s.PublishedDeploy.Locked != nil && *s.PublishedDeploy.Locked {
				sum += " (auto-publishing is locked, so it won't go live by itself)"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "site " + s.Name, Op: "build", After: mustJSON(map[string]any{"branch": branch, "clearCache": p.ClearCache})}}}}, nil
		}
		var b struct {
			ID       string `json:"id"`
			DeployID string `json:"deploy_id"`
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/sites/"+s.ID+"/builds", nil, map[string]any{"clear_cache": p.ClearCache}, &b); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"site": s.Name, "build": b.ID, "deploy": b.DeployID, "branch": branch})

	case "rollback":
		return c.rollback(ctx, call, p)
	case "lock_publishing", "unlock_publishing":
		return c.lock(ctx, call, p.Site)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) deploys(ctx context.Context, site string, limit int, production bool) ([]deploy, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	q := url.Values{"per_page": {strconv.Itoa(limit)}}
	if production {
		q.Set("production", "true")
	}
	var ds []deploy
	if _, err := c.api.Do(ctx, http.MethodGet, "/sites/"+site+"/deploys", q, nil, &ds); err != nil {
		return nil, err
	}
	if len(ds) > limit {
		ds = ds[:limit]
	}
	return ds, nil
}

func deployLabel(d *deploy) map[string]any {
	if d == nil {
		return nil
	}
	return map[string]any{"id": d.ID, "commit": str(d.CommitRef), "created": d.CreatedAt, "title": clip(str(d.Title), 120)}
}

func (c *conn) rollback(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.Deploy != "" {
		if _, err := deployID(p.Deploy); err != nil {
			return sdk.Result{}, err
		}
	}
	s, err := c.getSite(ctx, p.Site)
	if err != nil {
		return sdk.Result{}, err
	}
	live := s.PublishedDeploy
	var target deploy
	if p.Deploy != "" {
		if target, err = c.getDeploy(ctx, p.Deploy); err != nil {
			return sdk.Result{}, err
		}
		if target.SiteID != s.ID {
			return sdk.Result{}, fmt.Errorf("deploy %s belongs to another site", target.ID)
		}
	} else {
		// The newest ready production deploy older than the live one.
		ds, err := c.deploys(ctx, s.ID, 50, true)
		if err != nil {
			return sdk.Result{}, err
		}
		seenLive := live == nil
		for _, d := range ds {
			if live != nil && d.ID == live.ID {
				seenLive = true
				continue
			}
			if seenLive && d.State == "ready" && d.Context == "production" {
				target = d
				break
			}
		}
		if target.ID == "" {
			return sdk.Result{}, errors.New("there's no earlier ready production deploy to roll back to")
		}
	}
	if target.State != "ready" {
		return sdk.Result{}, fmt.Errorf("deploy %s is %s; only a ready deploy can be published", target.ID, target.State)
	}
	if !deployRe.MatchString(target.ID) {
		return sdk.Result{}, errors.New("unexpected deploy id from Netlify")
	}
	if live != nil && live.ID == target.ID {
		return sdk.JSON(map[string]any{"site": s.Name, "note": "that deploy is already live"})
	}
	locked := live != nil && live.Locked != nil && *live.Locked
	if call.DryRun {
		sum := fmt.Sprintf("Publish deploy %s of %s (%s) as production", target.ID, s.Name, clip(str(target.CommitRef), 12))
		if !locked {
			sum += "; auto-publishing is on, so the next production build will replace it (lock_publishing keeps it)"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "site " + s.Name + " production", Op: "publish", Before: mustJSON(deployLabel(live)), After: mustJSON(deployLabel(&target))}}}}, nil
	}
	var after deploy
	if _, err := c.api.Do(ctx, http.MethodPost, "/sites/"+s.ID+"/deploys/"+target.ID+"/restore", nil, nil, &after); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"site": s.Name, "live": target.ID, "previous": deployLabel(live), "autoPublishLocked": locked})
	if live != nil && deployRe.MatchString(live.ID) {
		res.Undo = sdk.UndoWith("rollback", map[string]any{"site": s.ID, "deploy": live.ID}, fmt.Sprintf("Publish %s's previous deploy again", s.Name))
	}
	return res, err
}

func (c *conn) lock(ctx context.Context, call sdk.Call, raw string) (sdk.Result, error) {
	locking := call.Action == "lock_publishing"
	s, err := c.getSite(ctx, raw)
	if err != nil {
		return sdk.Result{}, err
	}
	d := s.PublishedDeploy
	if d == nil || !deployRe.MatchString(d.ID) {
		return sdk.Result{}, fmt.Errorf("%s has no live deploy", s.Name)
	}
	isLocked := d.Locked != nil && *d.Locked
	if isLocked == locking {
		state := "unlocked"
		if isLocked {
			state = "locked"
		}
		return sdk.JSON(map[string]any{"site": s.Name, "note": "auto-publishing is already " + state})
	}
	verb, back, backDesc, path := "Lock", "unlock_publishing", "Unlock auto-publishing of %s", "/deploys/"+d.ID+"/lock"
	if !locking {
		verb, back, backDesc, path = "Unlock", "lock_publishing", "Lock auto-publishing of %s again", "/deploys/"+d.ID+"/unlock"
	}
	if call.DryRun {
		sum := fmt.Sprintf("%s auto-publishing of %s at deploy %s", verb, s.Name, d.ID)
		if !locking {
			sum += "; the next production build goes live"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "site " + s.Name, Op: strings.ToLower(verb), Before: mustJSON(map[string]any{"locked": isLocked}), After: mustJSON(map[string]any{"locked": locking})}}}}, nil
	}
	if _, err := c.api.Do(ctx, http.MethodPost, path, nil, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"site": s.Name, "deploy": d.ID, "autoPublishLocked": locking})
	res.Undo = sdk.UndoWith(back, map[string]any{"site": s.ID}, fmt.Sprintf(backDesc, s.Name))
	return res, err
}
