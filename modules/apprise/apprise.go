// Package apprise sends notifications through a self-hosted Apprise API
// server's stored configurations, by tag, and lists what each allowed
// configuration holds (tags and kinds of service, never the stored URLs,
// which carry the services' credentials).
package apprise

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Apprise API server.
type Config struct {
	URL                string   `json:"url"`      // e.g. https://apprise.example.com
	Keys               []string `json:"keys"`     // the configuration keys this instance may use
	Username           string   `json:"username"` // optional, for a server behind basic authentication
	Password           string   `json:"password"` // secret://
	Fingerprint        string   `json:"fingerprint"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
}

type conn struct {
	api  *rest.Client
	keys []string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Apprise module.
func New() *Module { return &Module{} }

const (
	maxTitle = 250
	maxBody  = 10000
	maxKeys  = 50
	maxTag   = 200
)

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	keyRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	tagRe    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	schemeRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]{0,30})://`)
	types    = map[string]bool{"info": true, "success": true, "warning": true, "failure": true}
	formats  = map[string]bool{"text": true, "markdown": true, "html": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "apprise", Name: "Apprise", Version: "0.1.0", Category: "Communication", Icon: "notification",
		Description: "Apprise API: send a notification through a stored configuration by tag; list configurations' tags and kinds of service.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","keys"],"properties":{
			"url":{"type":"string","description":"Your Apprise API server's address, e.g. https://apprise.example.com"},
			"keys":{"type":"array","items":{"type":"string"},"description":"The configuration keys (config ids) this connection may use, e.g. [\"homelab\"]"},
			"username":{"type":"string","description":"For a server behind basic authentication"},
			"password":{"type":"string","x-secret":true,"description":"That user's password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "configs", Title: "Configurations", Description: "For each allowed configuration key: its tags, how many services it holds and their kinds (mailto, tgram, discord…). Never the stored URLs, which contain the services' credentials.", Risk: sdk.RiskRead},
			{Name: "notify", Title: "Send a notification", Description: "Sends a notification through a stored configuration to the services matching a tag (\"all\" for every one). They can be email, SMS or chats reaching other people. The preview shows how many services and which kinds match; the run must give that number as expectedServices.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(fmt.Sprintf(`{"type":"object","required":["key","tag","body"],"properties":{"key":{"type":"string","description":"A configuration key from the settings"},"tag":{"type":"string","maxLength":%d,"description":"Which services: a tag, \"a b\" for both a and b, \"a, b\" for either, or all"},"body":{"type":"string","maxLength":%d},"title":{"type":"string","maxLength":%d},"type":{"type":"string","enum":["info","success","warning","failure"],"default":"info"},"format":{"type":"string","enum":["text","markdown","html"],"default":"text"},"expectedServices":{"type":"integer","minimum":1,"description":"The number of services the preview showed"}}}`, maxTag, maxBody, maxTitle))},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://apprise.example.com")
	}
	if len(c.Keys) == 0 || len(c.Keys) > maxKeys {
		return fmt.Errorf("enter between 1 and %d configuration keys", maxKeys)
	}
	keys := []string{}
	for _, k := range c.Keys {
		if !keyRe.MatchString(k) {
			return errors.New("a configuration key is letters, digits, - and _ (up to 128)")
		}
		keys = append(keys, k)
	}
	if (c.Username == "") != (c.Password == "") {
		return errors.New("basic authentication needs both a username and a password")
	}
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	if strings.ContainsAny(c.Username, ":\r\n") || len(c.Username) > 128 {
		return errors.New("the username can't contain a colon")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	user, ref := c.Username, c.Password
	var auth func(context.Context, *http.Request) error
	if ref != "" {
		auth = func(ctx context.Context, r *http.Request) error {
			p, err := h.Secret(ctx, ref)
			if err != nil {
				return err
			}
			r.SetBasicAuth(user, strings.TrimSpace(p))
			return nil
		}
	}
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/"), auth)
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, keys: keys})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("the Apprise server refused the username or password")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the Apprise server doesn't let this connection use that configuration")
	}
	return err
}

// services is a configuration's contents with its URLs reduced to their
// schemes. The URLs are read with privacy=1 and dropped right away.
type services struct {
	Tags  []string
	Kinds []string
	Count int
}

// matches applies Apprise's tag logic to one service's tags: a comma-
// separated group matches when every word in it is one of the tags (or is
// all), and a service tagged always matches any selection. The server's
// /json/urls filter can't be used for this: it reads a space as "or" where
// /notify reads it as "and", so it would count services the send skips.
func matches(groups [][]string, tags []string) bool {
	has := map[string]bool{}
	for _, t := range tags {
		has[strings.ToLower(t)] = true
	}
	if has["always"] {
		return true
	}
	for _, g := range groups {
		ok := true
		for _, w := range g {
			if w = strings.ToLower(w); w != "all" && !has[w] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// services counts the services of a configuration that a cleaned tag
// selects ("all" for every one).
func (c *conn) services(ctx context.Context, key, tag string) (services, error) {
	var raw struct {
		Tags []string `json:"tags"`
		URLs []struct {
			URL  string   `json:"url"`
			Tags []string `json:"tags"`
		} `json:"urls"`
	}
	q := url.Values{"privacy": {"1"}, "tag": {"all"}}
	if _, err := c.api.Do(ctx, http.MethodGet, "/json/urls/"+url.PathEscape(key), q, nil, &raw); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return services{}, fmt.Errorf("no Apprise API server (or no configuration %s) at this address", key)
		}
		return services{}, friendly(err)
	}
	var groups [][]string
	for _, g := range strings.Split(tag, ",") {
		groups = append(groups, strings.Fields(g))
	}
	s := services{Tags: []string{}, Kinds: []string{}}
	seen := map[string]bool{}
	for _, u := range raw.URLs {
		if !matches(groups, u.Tags) {
			continue
		}
		s.Count++
		k := "unknown"
		if mm := schemeRe.FindStringSubmatch(u.URL); mm != nil {
			k = strings.ToLower(mm[1])
		}
		if !seen[k] {
			seen[k] = true
			s.Kinds = append(s.Kinds, k)
		}
	}
	for _, t := range raw.Tags {
		if tagRe.MatchString(t) && len(t) <= 64 {
			s.Tags = append(s.Tags, t)
		}
	}
	sort.Strings(s.Kinds)
	sort.Strings(s.Tags)
	return s, nil
}

// Health implements sdk.Module. /status reads the server's state and sends
// nothing.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	msg := fmt.Sprintf("Apprise API · %d configuration keys", len(c.keys))
	if _, err := c.api.Do(ctx, http.MethodGet, "/status", nil, nil, nil); err != nil {
		switch {
		case rest.IsStatus(err, http.StatusExpectationFailed):
			return sdk.Health{Status: "degraded", Message: msg + " · the server reports a problem (its storage or configuration directory)"}
		case rest.IsStatus(err, http.StatusNotFound):
			return sdk.Health{Status: "down", Message: "no Apprise API server at this address"}
		}
		return sdk.Health{Status: "down", Message: friendly(err).Error()}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Key      string `json:"key"`
	Tag      string `json:"tag"`
	Body     string `json:"body"`
	Title    string `json:"title"`
	Type     string `json:"type"`
	Format   string `json:"format"`
	Expected int    `json:"expectedServices"`
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
	case "configs":
		out := []map[string]any{}
		for _, k := range c.keys {
			row := map[string]any{"key": k}
			s, err := c.services(ctx, k, "all")
			if err != nil {
				row["error"] = err.Error()
			} else {
				row["tags"], row["services"], row["kinds"] = s.Tags, s.Count, s.Kinds
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	case "notify":
		return c.notify(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// cleanTag checks Apprise's tag syntax: words of letters, digits, - and _,
// a space or + for AND, a comma for OR.
func cleanTag(t string) (string, error) {
	t = strings.TrimSpace(t)
	if t == "" || len(t) > maxTag {
		return "", errors.New("enter a tag (all for every service)")
	}
	var groups []string
	for _, g := range strings.Split(t, ",") {
		words := strings.FieldsFunc(g, func(r rune) bool { return r == ' ' || r == '+' })
		if len(words) == 0 {
			return "", errors.New("a tag is words of letters, digits, - and _; a space means and, a comma means or")
		}
		for _, w := range words {
			if !tagRe.MatchString(w) {
				return "", errors.New("a tag is words of letters, digits, - and _; a space means and, a comma means or")
			}
		}
		groups = append(groups, strings.Join(words, " "))
	}
	return strings.Join(groups, ", "), nil
}

func (c *conn) allowed(key string) bool {
	for _, k := range c.keys {
		if k == key {
			return true
		}
	}
	return false
}

func (c *conn) notify(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if !keyRe.MatchString(p.Key) || !c.allowed(p.Key) {
		return sdk.Result{}, fmt.Errorf("the key is one of the configuration keys in the settings: %s", strings.Join(c.keys, ", "))
	}
	tag, err := cleanTag(p.Tag)
	if err != nil {
		return sdk.Result{}, err
	}
	p.Title = strings.TrimSpace(p.Title)
	if strings.TrimSpace(p.Body) == "" {
		return sdk.Result{}, errors.New("enter the notification's text")
	}
	if utf8.RuneCountInString(p.Body) > maxBody || utf8.RuneCountInString(p.Title) > maxTitle {
		return sdk.Result{}, fmt.Errorf("the title is at most %d characters and the text at most %d", maxTitle, maxBody)
	}
	if p.Type == "" {
		p.Type = "info"
	}
	if p.Format == "" {
		p.Format = "text"
	}
	if !types[p.Type] || !formats[p.Format] {
		return sdk.Result{}, errors.New("the type is info, success, warning or failure, and the format text, markdown or html")
	}
	if p.Expected < 0 {
		return sdk.Result{}, errors.New("expectedServices is the number the preview showed")
	}
	s, err := c.services(ctx, p.Key, tag)
	if err != nil {
		return sdk.Result{}, err
	}
	if s.Count == 0 {
		return sdk.Result{}, fmt.Errorf("no service in %s matches the tag %q", p.Key, tag)
	}
	body := map[string]any{"body": p.Body, "tag": tag, "type": p.Type, "format": p.Format}
	if p.Title != "" {
		body["title"] = p.Title
	}
	if call.DryRun {
		after, _ := json.Marshal(map[string]any{"key": p.Key, "tag": tag, "services": s.Count, "kinds": s.Kinds, "title": p.Title, "body": p.Body, "type": p.Type, "format": p.Format})
		return sdk.Result{Plan: &sdk.Plan{
			Summary: fmt.Sprintf("Send an Apprise notification through %s to %d services tagged %q (%s); run it with expectedServices %d", p.Key, s.Count, tag, strings.Join(s.Kinds, ", "), s.Count),
			Changes: []sdk.Change{{Target: "Apprise " + p.Key, Op: "send", After: after}},
		}}, nil
	}
	if p.Expected == 0 {
		return sdk.Result{}, fmt.Errorf("give expectedServices %d, the number of services the preview showed", s.Count)
	}
	if p.Expected != s.Count {
		return sdk.Result{}, fmt.Errorf("the configuration changed since the preview: %d services match now, not %d; preview it again", s.Count, p.Expected)
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "/notify/"+url.PathEscape(p.Key), nil, body, nil); err != nil {
		switch {
		case rest.IsStatus(err, http.StatusFailedDependency):
			return sdk.Result{}, errors.New("Apprise couldn't deliver to at least one service (or no service matched the tag)")
		case rest.IsStatus(err, http.StatusNotFound):
			return sdk.Result{}, fmt.Errorf("there's no stored configuration %s", p.Key)
		}
		return sdk.Result{}, friendly(err)
	}
	return sdk.JSON(map[string]any{"sent": true, "key": p.Key, "tag": tag, "services": s.Count})
}
