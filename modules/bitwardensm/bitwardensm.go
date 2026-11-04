// Package bitwardensm works with Bitwarden Secrets Manager as a machine
// account: it logs in with the access token, decrypts the organization key
// with the token's own key (see crypto.go), and lists projects and secret
// keys. Values come only from the destructive reveal_secret, for the secrets
// it names; notes are never returned, since they often hold secrets too. It
// never creates, edits or deletes secrets and never changes access (machine
// accounts, access tokens, project grants).
package bitwardensm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one machine account.
type Config struct {
	AccessToken        string `json:"accessToken"` // secret:// machine account access token
	Region             string `json:"region"`      // us (default), eu, self-hosted
	ServerURL          string `json:"serverUrl"`   // self-hosted, e.g. https://bitwarden.example.com
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type session struct {
	bearer  string
	org     string
	key     symKey
	expires time.Time
}

type conn struct {
	host     sdk.Host
	tokenRef string
	api      *rest.Client
	identity *rest.Client

	mu   sync.Mutex
	sess *session
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Bitwarden Secrets Manager module.
func New() *Module { return &Module{} }

const (
	maxReveal  = 10
	maxSecrets = 2000
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "bitwardensm", Name: "Bitwarden Secrets Manager", Version: "0.1.0", Category: "Security", Icon: "key",
		Description: "Bitwarden Secrets Manager as a machine account: projects and secret keys (decrypted on this machine; never values or notes), revealing named secrets (destructive).",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["accessToken"],"properties":{
			"accessToken":{"type":"string","x-secret":true,"description":"A machine account access token (0.<id>.<secret>:<key>). Give the machine account read access to only the projects Conduit should see"},
			"region":{"type":"string","enum":["us","eu","self-hosted"],"default":"us","description":"bitwarden.com (us), bitwarden.eu (eu), or your own server"},
			"serverUrl":{"type":"string","description":"Self-hosted only: the server's address, e.g. https://bitwarden.example.com"},
			"fingerprint":{"type":"string","description":"Self-hosted only: SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Self-hosted only: skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "The projects the machine account can read: name, id and dates.", Risk: sdk.RiskRead},
			{Name: "secrets", Title: "Secret keys", Description: "Secret keys (names) with id, projects and dates, in the organization or one project. Never values or notes.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"project":{"type":"string","description":"Project name or id; all readable secrets when empty"}}}`)},
			{Name: "reveal_secret", Title: "Reveal secret values", Description: "The values of the named secrets (by id or key, up to 10), and only those; never notes. Revealing a credential is destructive: it can't be taken back.", Risk: sdk.RiskDestructive, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"ids":{"type":"array","items":{"type":"string"},"maxItems":10,"description":"Secret ids"},"keys":{"type":"array","items":{"type":"string"},"maxItems":10,"description":"Secret keys (names); a key that more than one secret has is refused"},"project":{"type":"string","description":"Look keys up in this project only (name or id)"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.AccessToken, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	var apiBase, idBase string
	switch strings.ToLower(strings.TrimSpace(c.Region)) {
	case "", "us":
		apiBase, idBase = "https://api.bitwarden.com", "https://identity.bitwarden.com"
	case "eu":
		apiBase, idBase = "https://api.bitwarden.eu", "https://identity.bitwarden.eu"
	case "self-hosted":
		u, err := url.Parse(strings.TrimSpace(c.ServerURL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("for a self-hosted server, the server URL is like https://bitwarden.example.com")
		}
		base := u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/")
		apiBase, idBase = base+"/api", base+"/identity"
	default:
		return errors.New("the region is us, eu or self-hosted")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		client = sdk.HTTPClient(h, 30*time.Second)
		client.Transport.(*http.Transport).TLSClientConfig = tc
	}
	cn := &conn{host: h, tokenRef: c.AccessToken}
	cn.identity = rest.New(idBase, nil)
	cn.identity.HTTP = rest.SameHostOnly(client)
	cn.api = rest.New(apiBase, func(ctx context.Context, r *http.Request) error {
		s, err := cn.session(ctx, false)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+s.bearer)
		return nil
	})
	cn.api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// session logs in when there's no current bearer token (or fresh is set).
func (c *conn) session(ctx context.Context, fresh bool) (*session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !fresh && c.sess != nil && time.Now().Before(c.sess.expires) {
		return c.sess, nil
	}
	c.sess = nil
	raw, err := c.host.Secret(ctx, c.tokenRef)
	if err != nil {
		return nil, err
	}
	at, err := parseAccessToken(raw)
	if err != nil {
		return nil, err
	}
	form := url.Values{"scope": {"api.secrets"}, "grant_type": {"client_credentials"}, "client_id": {at.id}, "client_secret": {at.secret}}
	res, err := c.identity.Send(ctx, http.MethodPost, "/connect/token", nil, strings.NewReader(form.Encode()),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}})
	if err != nil {
		if rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusUnauthorized) {
			return nil, errors.New("Bitwarden refused the access token (revoked, expired, or for another region)")
		}
		return nil, fmt.Errorf("logging in: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("logging in: unexpected status %s", res.Status)
	}
	var lr struct {
		AccessToken      string `json:"access_token"`
		ExpiresIn        int    `json:"expires_in"`
		EncryptedPayload string `json:"encrypted_payload"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&lr); err != nil || lr.AccessToken == "" {
		return nil, errors.New("the login's answer isn't what Bitwarden sends")
	}
	if lr.EncryptedPayload == "" {
		return nil, errors.New("the login returned no encrypted payload (is this a Secrets Manager machine account?)")
	}
	org, err := jwtOrganization(lr.AccessToken)
	if err != nil {
		return nil, err
	}
	key, err := at.orgKey(lr.EncryptedPayload)
	if err != nil {
		return nil, err
	}
	ttl := time.Duration(lr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	// Renew a minute early so a call doesn't start on an expiring token.
	if ttl > 2*time.Minute {
		ttl -= time.Minute
	}
	c.sess = &session{bearer: lr.AccessToken, org: org, key: key, expires: time.Now().Add(ttl)}
	return c.sess, nil
}

func friendly(err error, what string) error {
	switch {
	case err == nil:
		return nil
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Bitwarden refused the machine account's session")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("the machine account has no access to %s", what)
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s the machine account can read", what)
	}
	return err
}

// do calls the API, logging in again once if the session was refused.
func (c *conn) do(ctx context.Context, method, path string, body, out any) error {
	_, err := c.api.Do(ctx, method, path, nil, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		if _, lerr := c.session(ctx, true); lerr != nil {
			return lerr
		}
		_, err = c.api.Do(ctx, method, path, nil, body, out)
	}
	return err
}

type project struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Created  string `json:"creationDate"`
	Revision string `json:"revisionDate"`
}

type secretIdent struct {
	ID       string `json:"id"`
	Key      string `json:"key"`
	Created  string `json:"creationDate"`
	Revision string `json:"revisionDate"`
	Projects []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"projects"`
}

type secretFull struct {
	secretIdent
	Value string `json:"value"`
	Note  string `json:"note"` // never returned
}

// projects returns the readable projects with their names decrypted.
func (c *conn) projects(ctx context.Context) ([]project, error) {
	s, err := c.session(ctx, false)
	if err != nil {
		return nil, err
	}
	var out struct {
		Data []project `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/organizations/"+s.org+"/projects", nil, &out); err != nil {
		return nil, friendly(err, "project list")
	}
	s, err = c.session(ctx, false)
	if err != nil {
		return nil, err
	}
	for i := range out.Data {
		if out.Data[i].Name, err = s.key.decryptString(out.Data[i].Name); err != nil {
			return nil, fmt.Errorf("project %s: %w", out.Data[i].ID, err)
		}
	}
	sort.Slice(out.Data, func(i, j int) bool { return strings.ToLower(out.Data[i].Name) < strings.ToLower(out.Data[j].Name) })
	return out.Data, nil
}

// project resolves a project name or id.
func (c *conn) project(ctx context.Context, s string) (project, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 512 {
		return project{}, errors.New("name the project (its name or id; see projects)")
	}
	ps, err := c.projects(ctx)
	if err != nil {
		return project{}, err
	}
	var hit []project
	for _, p := range ps {
		if strings.EqualFold(p.ID, s) {
			return p, nil
		}
		if p.Name == s {
			hit = append(hit, p)
		}
	}
	switch len(hit) {
	case 0:
		return project{}, fmt.Errorf("there's no project %q the machine account can read", s)
	case 1:
		return hit[0], nil
	}
	return project{}, fmt.Errorf("more than one project is called %q; give its id", s)
}

// secrets lists secret identifiers (in a project, or all) with keys decrypted.
func (c *conn) secrets(ctx context.Context, projectID string) ([]secretIdent, error) {
	s, err := c.session(ctx, false)
	if err != nil {
		return nil, err
	}
	path := "/organizations/" + s.org + "/secrets"
	if projectID != "" {
		path = "/projects/" + projectID + "/secrets"
	}
	var out struct {
		Secrets []secretIdent `json:"secrets"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, friendly(err, "secret list")
	}
	s, err = c.session(ctx, false)
	if err != nil {
		return nil, err
	}
	for i := range out.Secrets {
		e := &out.Secrets[i]
		if e.Key, err = s.key.decryptString(e.Key); err != nil {
			return nil, fmt.Errorf("secret %s: %w", e.ID, err)
		}
		for j := range e.Projects {
			if e.Projects[j].Name, err = s.key.decryptString(e.Projects[j].Name); err != nil {
				return nil, fmt.Errorf("project %s: %w", e.Projects[j].ID, err)
			}
		}
	}
	sort.Slice(out.Secrets, func(i, j int) bool { return out.Secrets[i].Key < out.Secrets[j].Key })
	return out.Secrets, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ps, err := c.projects(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d project(s) readable", len(ps))}
}

type input struct {
	Project string   `json:"project"`
	IDs     []string `json:"ids"`
	Keys    []string `json:"keys"`
}

func validKey(k string) bool {
	return k != "" && len(k) <= 512 && !strings.ContainsFunc(k, func(r rune) bool { return r < 0x20 || r == 0x7f })
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
	case "projects":
		ps, err := c.projects(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, pr := range ps {
			list = append(list, map[string]any{"id": pr.ID, "name": pr.Name, "created": pr.Created, "updated": pr.Revision})
		}
		return sdk.JSON(map[string]any{"projects": list})

	case "secrets":
		pid, pname := "", ""
		if strings.TrimSpace(p.Project) != "" {
			pr, err := c.project(ctx, p.Project)
			if err != nil {
				return sdk.Result{}, err
			}
			pid, pname = pr.ID, pr.Name
		}
		ss, err := c.secrets(ctx, pid)
		if err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for i, s := range ss {
			if i == maxSecrets {
				break
			}
			projects := []string{}
			for _, pr := range s.Projects {
				projects = append(projects, pr.Name)
			}
			list = append(list, map[string]any{"id": s.ID, "key": s.Key, "projects": projects, "created": s.Created, "updated": s.Revision})
		}
		out := map[string]any{"count": len(ss), "secrets": list}
		if pname != "" {
			out["project"] = pname
		}
		if len(ss) > maxSecrets {
			out["truncated"] = true
		}
		return sdk.JSON(out)

	case "reveal_secret":
		return c.reveal(ctx, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) reveal(ctx context.Context, p input) (sdk.Result, error) {
	if len(p.IDs)+len(p.Keys) == 0 {
		return sdk.Result{}, errors.New("name the secrets whose values to reveal, by ids or keys (secrets lists them)")
	}
	if len(p.IDs)+len(p.Keys) > maxReveal {
		return sdk.Result{}, fmt.Errorf("reveal up to %d secrets at a time", maxReveal)
	}
	for _, id := range p.IDs {
		if !uuidRe.MatchString(id) {
			return sdk.Result{}, fmt.Errorf("%q isn't a secret id", id)
		}
	}
	for _, k := range p.Keys {
		if !validKey(k) {
			return sdk.Result{}, fmt.Errorf("%q isn't a secret key", k)
		}
	}
	ids := map[string]bool{}
	var order []string
	add := func(id string) {
		id = strings.ToLower(id)
		if !ids[id] {
			ids[id] = true
			order = append(order, id)
		}
	}
	for _, id := range p.IDs {
		add(id)
	}
	var missing []string
	if len(p.Keys) > 0 {
		pid := ""
		if strings.TrimSpace(p.Project) != "" {
			pr, err := c.project(ctx, p.Project)
			if err != nil {
				return sdk.Result{}, err
			}
			pid = pr.ID
		}
		ss, err := c.secrets(ctx, pid)
		if err != nil {
			return sdk.Result{}, err
		}
		for _, k := range p.Keys {
			var hit []string
			for _, s := range ss {
				if s.Key == k {
					hit = append(hit, s.ID)
				}
			}
			switch len(hit) {
			case 0:
				missing = append(missing, k)
			case 1:
				add(hit[0])
			default:
				return sdk.Result{}, fmt.Errorf("%d secrets have the key %q; give a project or the id of one: %s", len(hit), k, strings.Join(hit, ", "))
			}
		}
	}
	vals := []map[string]any{}
	if len(order) > 0 {
		var out struct {
			Data []secretFull `json:"data"`
		}
		if err := c.do(ctx, http.MethodPost, "/secrets/get-by-ids", map[string]any{"ids": order}, &out); err != nil {
			return sdk.Result{}, friendly(err, "secret among those ids")
		}
		s, err := c.session(ctx, false)
		if err != nil {
			return sdk.Result{}, err
		}
		got := map[string]secretFull{}
		for _, sf := range out.Data {
			got[strings.ToLower(sf.ID)] = sf
		}
		for _, id := range order {
			sf, ok := got[id]
			if !ok {
				missing = append(missing, id)
				continue
			}
			key, err := s.key.decryptString(sf.Key)
			if err != nil {
				return sdk.Result{}, fmt.Errorf("secret %s: %w", sf.ID, err)
			}
			val, err := s.key.decryptString(sf.Value)
			if err != nil {
				return sdk.Result{}, fmt.Errorf("secret %s: %w", sf.ID, err)
			}
			vals = append(vals, map[string]any{"id": sf.ID, "key": key, "value": val})
		}
	}
	res := map[string]any{"secrets": vals}
	if len(missing) > 0 {
		res["missing"] = missing
	}
	return sdk.JSON(res)
}
