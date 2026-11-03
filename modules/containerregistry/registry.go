// Package containerregistry reads OCI / Docker registries (Docker Hub, GHCR,
// Quay, Harbor, GitLab, a plain registry:2): tags, the digest and size of a
// tag, and whether a newer version tag exists. It never pushes or deletes.
package containerregistry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one registry.
type Config struct {
	Registry string `json:"registry"` // docker.io, ghcr.io, quay.io, harbor.example.com:8443, http://localhost:5000
	Username string `json:"username"` // optional
	Password string `json:"password"` // optional secret:// password or access token
}

type conn struct {
	base   string // https://host[:port]
	hub    bool   // Docker Hub: bare names live under library/
	user   string
	pass   string
	host   sdk.Host
	mu     sync.Mutex
	tokens map[string]token // scope -> bearer token
}

type token struct {
	value   string
	expires time.Time
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the container registry module.
func New() *Module { return &Module{} }

var (
	// The OCI distribution spec's repository name grammar.
	nameRe = regexp.MustCompile(`^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*$`)
	tagRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	hostRe = regexp.MustCompile(`^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$`)
	userRe = regexp.MustCompile(`^[^\s:]{1,256}$`)
)

const manifestTypes = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	repo := `"repository":{"type":"string","description":"e.g. library/nginx, grafana/grafana or elchi-dev/conduit"}`
	tag := `"tag":{"type":"string","default":"latest"}`
	return sdk.Manifest{
		ID: "containerregistry", Name: "Container registry", Version: "0.1.0", Category: "Development", Icon: "package",
		Description: "Look up image tags and digests on Docker Hub, GHCR, Quay, Harbor or your own registry, and spot newer versions.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["registry"],"properties":{
			"registry":{"type":"string","default":"docker.io","description":"docker.io, ghcr.io, quay.io, or your registry's host (http://localhost:5000 for a local one)"},
			"username":{"type":"string","description":"Optional, for private images"},
			"password":{"type":"string","x-secret":true,"description":"Password or access token (GHCR: a token with read:packages)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "tags", Title: "Tags", Description: "Tags of an image (at most 5,000).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["repository"],"properties":{` + repo + `}}`)},
			{Name: "manifest", Title: "Digest and size", Description: "The digest a tag points to, its total size and the platforms it's built for.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["repository"],"properties":{` + repo + `,` + tag + `}}`)},
			{Name: "newer", Title: "Newer version?", Description: "Version tags newer than the given one, in the same style (1.2.3, v1.2, 1.2.3-alpine).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["repository","tag"],"properties":{` + repo + `,"tag":{"type":"string","description":"Your current version tag, e.g. 1.27.2"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	reg := strings.TrimRight(strings.TrimSpace(c.Registry), "/")
	if reg == "" {
		reg = "docker.io"
	}
	scheme := "https"
	if s, rest, ok := strings.Cut(reg, "://"); ok {
		scheme, reg = s, rest
	}
	if !hostRe.MatchString(reg) || (scheme != "https" && scheme != "http") {
		return errors.New("the registry is a host like ghcr.io or harbor.example.com:8443")
	}
	if scheme == "http" {
		h := reg
		if i := strings.LastIndex(h, ":"); i > 0 {
			h = h[:i]
		}
		if h != "localhost" && h != "127.0.0.1" {
			return errors.New("use https for registries that aren't on this machine")
		}
	}
	hub := false
	switch reg {
	case "docker.io", "index.docker.io", "registry-1.docker.io", "hub.docker.com":
		reg, hub = "registry-1.docker.io", true
	}
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password or token in the vault and enter its secret:// reference")
	}
	if c.Password != "" && !userRe.MatchString(c.Username) {
		return errors.New("enter the username that goes with the password")
	}
	m.set.Put(id, &conn{base: scheme + "://" + reg, hub: hub, user: c.Username, pass: c.Password, host: h, tokens: map[string]token{}})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (m *Module) client() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *conn) repo(s string) (string, error) {
	s = strings.TrimSpace(s)
	if c.hub && s != "" && !strings.Contains(s, "/") {
		s = "library/" + s
	}
	if len(s) > 255 || !nameRe.MatchString(s) {
		return "", errors.New("the repository is lowercase, like library/nginx or owner/image")
	}
	return s, nil
}

func (c *conn) basic(ctx context.Context, r *http.Request) error {
	if c.pass == "" {
		return nil
	}
	p, err := c.host.Secret(ctx, c.pass)
	if err != nil {
		return err
	}
	r.SetBasicAuth(c.user, strings.TrimSpace(p))
	return nil
}

// challenge parses `Bearer realm="…",service="…",scope="…"`.
func challenge(h string) (scheme string, params map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	params = map[string]string{}
	for rest != "" {
		rest = strings.TrimLeft(rest, " ,")
		k, v, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if strings.HasPrefix(v, `"`) {
			end := strings.Index(v[1:], `"`)
			if end < 0 {
				break
			}
			params[k], rest = v[1:end+1], v[end+2:]
		} else {
			val, after, _ := strings.Cut(v, ",")
			params[k], rest = strings.TrimSpace(val), after
		}
	}
	return strings.ToLower(scheme), params
}

// bearer fetches (or reuses) a token for the challenge's scope.
func (m *Module) bearer(ctx context.Context, c *conn, p map[string]string, scope string) (string, error) {
	if s := p["scope"]; s != "" {
		scope = s
	}
	c.mu.Lock()
	if t, ok := c.tokens[scope]; ok && time.Now().Before(t.expires) {
		c.mu.Unlock()
		return t.value, nil
	}
	c.mu.Unlock()
	realm, err := url.Parse(p["realm"])
	if err != nil || realm.Host == "" || (realm.Scheme != "https" && !(realm.Scheme == "http" && strings.HasPrefix(c.base, "http://"))) {
		return "", errors.New("the registry sent an unusable sign-in address")
	}
	q := realm.Query()
	if p["service"] != "" {
		q.Set("service", p["service"])
	}
	q.Set("scope", scope)
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Conduit")
	if err := c.basic(ctx, req); err != nil {
		return "", err
	}
	res, err := m.client().Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		if res.StatusCode == http.StatusUnauthorized {
			return "", errors.New("the registry refused the username and password")
		}
		return "", fmt.Errorf("the registry's sign-in answered %s", res.Status)
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &t); err != nil {
		return "", errors.New("unexpected answer from the registry's sign-in")
	}
	v := t.Token
	if v == "" {
		v = t.AccessToken
	}
	if v == "" {
		return "", errors.New("the registry's sign-in returned no token")
	}
	ttl := time.Duration(t.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	c.mu.Lock()
	c.tokens[scope] = token{value: v, expires: time.Now().Add(ttl - 10*time.Second)}
	c.mu.Unlock()
	return v, nil
}

type response struct {
	status int
	header http.Header
	body   []byte
}

// do sends a request to the registry, answering one auth challenge.
func (m *Module) do(ctx context.Context, c *conn, method, path, accept, repo string) (response, error) {
	scope := "registry:catalog:*"
	if repo != "" {
		scope = "repository:" + repo + ":pull"
	}
	var auth string
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, nil)
		if err != nil {
			return response{}, err
		}
		req.Header.Set("User-Agent", "Conduit")
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if auth == "basic" {
			if err := c.basic(ctx, req); err != nil {
				return response{}, err
			}
		} else if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		res, err := m.client().Do(req)
		if err != nil {
			return response{}, err
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
		res.Body.Close()
		if err != nil {
			return response{}, err
		}
		if res.StatusCode == http.StatusUnauthorized && attempt == 0 {
			sch, p := challenge(res.Header.Get("WWW-Authenticate"))
			switch sch {
			case "bearer":
				if auth, err = m.bearer(ctx, c, p, scope); err != nil {
					return response{}, err
				}
				continue
			case "basic":
				if c.pass == "" {
					return response{}, errors.New("this registry needs a username and password")
				}
				auth = "basic"
				continue
			}
		}
		if res.StatusCode >= 300 {
			var e struct {
				Errors []struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"errors"`
			}
			if json.Unmarshal(body, &e) == nil && len(e.Errors) > 0 {
				msg := e.Errors[0].Message
				switch e.Errors[0].Code {
				case "NAME_UNKNOWN", "MANIFEST_UNKNOWN":
					msg = "not found (or private: add a username and token)"
				case "UNAUTHORIZED", "DENIED":
					msg = "access denied (private image? check the username and token)"
				}
				return response{}, errors.New(msg)
			}
			if res.StatusCode == http.StatusNotFound {
				return response{}, errors.New("not found")
			}
			if res.StatusCode == http.StatusTooManyRequests {
				return response{}, errors.New("the registry is rate limiting (Docker Hub allows few anonymous requests; add an account)")
			}
			return response{}, fmt.Errorf("the registry answered %s", res.Status)
		}
		return response{status: res.StatusCode, header: res.Header, body: body}, nil
	}
	return response{}, errors.New("the registry refused access")
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	// GET /v2/ is the API version check; an anonymous 401 still proves the
	// registry is there, so only a refused sign-in counts as down.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/v2/", nil)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	req.Header.Set("User-Agent", "Conduit")
	res, err := m.client().Do(req)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode != http.StatusUnauthorized {
		return sdk.Health{Status: "down", Message: "not a registry: /v2/ answered " + res.Status}
	}
	if c.pass != "" && res.StatusCode == http.StatusUnauthorized {
		sch, p := challenge(res.Header.Get("WWW-Authenticate"))
		if sch == "bearer" {
			if _, err := m.bearer(ctx, c, p, "registry:catalog:*"); err != nil {
				return sdk.Health{Status: "down", Message: err.Error()}
			}
		}
	}
	return sdk.Health{Status: "ok", Message: strings.TrimPrefix(strings.TrimPrefix(c.base, "https://"), "http://")}
}

func (m *Module) tags(ctx context.Context, c *conn, repo string) ([]string, error) {
	const maxTags = 5000
	path := "/v2/" + repo + "/tags/list?n=1000"
	var all []string
	for page := 0; page < 10 && path != ""; page++ {
		res, err := m.do(ctx, c, http.MethodGet, path, "application/json", repo)
		if err != nil {
			return nil, err
		}
		var r struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(res.body, &r); err != nil {
			return nil, errors.New("unexpected tag list from the registry")
		}
		all = append(all, r.Tags...)
		if len(all) >= maxTags {
			all = all[:maxTags]
			break
		}
		path = nextLink(res.header.Get("Link"), repo)
	}
	return all, nil
}

// nextLink follows `</v2/<repo>/tags/list?last=x&n=1000>; rel="next"`, only
// within the same repository on the same registry.
func nextLink(h, repo string) string {
	if h == "" || !strings.Contains(h, `rel="next"`) {
		return ""
	}
	s, e := strings.Index(h, "<"), strings.Index(h, ">")
	if s < 0 || e <= s {
		return ""
	}
	u, err := url.Parse(h[s+1 : e])
	if err != nil || u.Host != "" || u.Path != "/v2/"+repo+"/tags/list" {
		return ""
	}
	return u.RequestURI()
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
	} `json:"platform"`
}

type manifest struct {
	MediaType string       `json:"mediaType"`
	Config    descriptor   `json:"config"`
	Layers    []descriptor `json:"layers"`
	Manifests []descriptor `json:"manifests"`
}

func (m *Module) manifest(ctx context.Context, c *conn, repo, ref string, depth int) (map[string]any, error) {
	res, err := m.do(ctx, c, http.MethodGet, "/v2/"+repo+"/manifests/"+ref, manifestTypes, repo)
	if err != nil {
		return nil, err
	}
	var mf manifest
	if err := json.Unmarshal(res.body, &mf); err != nil {
		return nil, errors.New("unexpected manifest from the registry")
	}
	out := map[string]any{"repository": repo, "tag": ref, "digest": res.header.Get("Docker-Content-Digest"), "mediaType": res.header.Get("Content-Type")}
	if len(mf.Manifests) > 0 {
		platforms := []map[string]any{}
		for _, d := range mf.Manifests {
			if d.Platform == nil || d.Platform.OS == "unknown" { // attestations
				continue
			}
			p := d.Platform.OS + "/" + d.Platform.Architecture
			if d.Platform.Variant != "" {
				p += "/" + d.Platform.Variant
			}
			entry := map[string]any{"platform": p, "digest": d.Digest}
			if depth == 0 && len(platforms) < 4 && validDigest(d.Digest) {
				if sub, err := m.manifest(ctx, c, repo, d.Digest, 1); err == nil {
					entry["size"] = sub["size"]
				}
			}
			platforms = append(platforms, entry)
		}
		out["platforms"] = platforms
		return out, nil
	}
	size := mf.Config.Size
	for _, l := range mf.Layers {
		size += l.Size
	}
	out["size"] = size
	out["layers"] = len(mf.Layers)
	return out, nil
}

var digestRe = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func validDigest(s string) bool { return digestRe.MatchString(s) }

// --- version comparison ------------------------------------------------------

var verRe = regexp.MustCompile(`^(v?)([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?(?:\.([0-9]+))?([-_+].*)?$`)

type version struct {
	prefix string
	nums   []int
	suffix string
}

func parseVersion(s string) (version, bool) {
	g := verRe.FindStringSubmatch(s)
	if g == nil {
		return version{}, false
	}
	v := version{prefix: g[1], suffix: g[6]}
	for _, n := range g[2:6] {
		if n == "" {
			break
		}
		i, err := strconv.Atoi(n)
		if err != nil {
			return version{}, false
		}
		v.nums = append(v.nums, i)
	}
	return v, true
}

// sameStyle: 1.2.3 is compared with 1.2.4, not with 1.3 or 1.2.4-alpine.
func (v version) sameStyle(o version) bool {
	return v.prefix == o.prefix && len(v.nums) == len(o.nums) && v.suffix == o.suffix
}

func (v version) less(o version) bool {
	for i := range v.nums {
		if v.nums[i] != o.nums[i] {
			return v.nums[i] < o.nums[i]
		}
	}
	return false
}

// Newer returns the tags newer than current in the same style, newest first.
func Newer(current string, tags []string) ([]string, error) {
	cur, ok := parseVersion(current)
	if !ok {
		return nil, fmt.Errorf("%q isn't a version tag like 1.2.3", current)
	}
	type tv struct {
		tag string
		v   version
	}
	var found []tv
	for _, t := range tags {
		v, ok := parseVersion(t)
		if ok && v.sameStyle(cur) && cur.less(v) {
			found = append(found, tv{t, v})
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[j].v.less(found[i].v) })
	out := []string{}
	for _, f := range found {
		out = append(out, f.tag)
	}
	return out, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Repository string `json:"repository"`
		Tag        string `json:"tag"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	repo, err := c.repo(p.Repository)
	if err != nil {
		return sdk.Result{}, err
	}
	if p.Tag == "" && call.Action == "manifest" {
		p.Tag = "latest"
	}
	if p.Tag != "" && !tagRe.MatchString(p.Tag) && !validDigest(p.Tag) {
		return sdk.Result{}, errors.New("tags are letters, digits, _ . and - (up to 128), or a sha256: digest")
	}
	switch call.Action {
	case "tags":
		tags, err := m.tags(ctx, c, repo)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"repository": repo, "tags": tags, "count": len(tags)})

	case "manifest":
		out, err := m.manifest(ctx, c, repo, p.Tag, 0)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(out)

	case "newer":
		if p.Tag == "" {
			return sdk.Result{}, errors.New("enter your current version tag")
		}
		tags, err := m.tags(ctx, c, repo)
		if err != nil {
			return sdk.Result{}, err
		}
		newer, err := Newer(p.Tag, tags)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"repository": repo, "current": p.Tag, "upToDate": len(newer) == 0}
		if len(newer) > 0 {
			out["latest"] = newer[0]
			cur, _ := parseVersion(p.Tag)
			lat, _ := parseVersion(newer[0])
			out["majorUpdate"] = lat.nums[0] != cur.nums[0]
		}
		if len(newer) > 20 {
			newer = newer[:20]
		}
		out["newer"] = newer
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
