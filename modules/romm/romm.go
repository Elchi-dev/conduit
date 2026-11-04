// Package romm works with a RomM game library through its API and a user's
// login: platforms with their game counts, games (by platform or search),
// and starting a library scan.
package romm

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
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one RomM server.
type Config struct {
	URL                string `json:"url"`      // e.g. https://romm.example.com
	Username           string `json:"username"` // a RomM user
	Password           string `json:"password"` // secret:// its password
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	origin string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the RomM module.
func New() *Module { return &Module{} }

const maxPlatforms = 50

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

// metadataSources are the names RomM's scan takes; it uses only the ones
// set up on the server.
var metadataSources = []string{"igdb", "moby", "ss", "ra", "lb", "hasheous", "tgdb", "sgdb", "flashpoint", "hltb"}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "romm", Name: "RomM", Version: "0.1.0", Category: "Gaming", Icon: "game",
		Description: "Your RomM game library: platforms and game counts, games by platform or search, and library scans.",
		Presets:     []string{"gamer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","username","password"],"properties":{
			"url":{"type":"string","description":"RomM's address, e.g. https://romm.example.com"},
			"username":{"type":"string","description":"A RomM user (an editor or admin to scan)"},
			"password":{"type":"string","x-secret":true,"description":"Its password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "platforms", Title: "Platforms", Description: "Every platform in the library with its number of games.", Risk: sdk.RiskRead},
			{Name: "roms", Title: "Games", Description: "Games by name, on one platform or all, optionally matching a search: file, size, regions, languages and when it was added.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"platform":{"type":"integer","minimum":1,"description":"Platform id (see platforms)"},"search":{"type":"string","maxLength":200},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
			{Name: "scan_library", Title: "Scan the library", Description: "Starts a RomM scan for new games (quick) or new platforms, on some platforms or all, fetching metadata from the sources set up in RomM. It runs in the background.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{"platforms":{"type":"array","maxItems":50,"items":{"type":"integer","minimum":1},"description":"Platform ids (default: all)"},"mode":{"type":"string","enum":["quick","new_platforms"],"default":"quick"}}}`)},
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
		return errors.New("the address is like https://romm.example.com")
	}
	user := strings.TrimSpace(c.Username)
	if user == "" || strings.ContainsAny(user, ":\r\n") || len(user) > 200 {
		return errors.New("enter your RomM user name")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
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
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	ref := c.Password
	api := rest.New(origin, func(ctx context.Context, r *http.Request) error {
		pw, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.SetBasicAuth(user, pw)
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, origin: origin})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func explain(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("RomM refused the user name or password")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("RomM refused: this user's role isn't allowed to do this")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("no RomM API at this address")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return explain(err)
}

type platform struct {
	ID          int    `json:"id"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	CustomName  string `json:"custom_name"`
	Roms        int    `json:"rom_count"`
}

func (p platform) label() string {
	for _, s := range []string{p.CustomName, p.DisplayName, p.Name, p.Slug} {
		if s != "" {
			return s
		}
	}
	return strconv.Itoa(p.ID)
}

func (c *conn) platforms(ctx context.Context) ([]platform, error) {
	var ps []platform
	err := c.get(ctx, "/api/platforms", nil, &ps)
	sort.Slice(ps, func(i, j int) bool { return strings.ToLower(ps[i].label()) < strings.ToLower(ps[j].label()) })
	return ps, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var hb struct {
		Version string `json:"VERSION"`
		System  struct {
			Version string `json:"VERSION"`
		} `json:"SYSTEM"`
	}
	if err := c.get(ctx, "/api/heartbeat", nil, &hb); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var me struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if err := c.get(ctx, "/api/users/me", nil, &me); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	ps, err := c.platforms(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	games := 0
	for _, p := range ps {
		games += p.Roms
	}
	v := hb.System.Version
	if v == "" {
		v = hb.Version
	}
	return sdk.Health{Status: "ok", Message: strings.TrimSpace(fmt.Sprintf("RomM %s · %d platforms, %d games", v, len(ps), games))}
}

type rom struct {
	ID         int      `json:"id"`
	Name       string   `json:"name"`
	FileName   string   `json:"fs_name"`
	PlatformID int      `json:"platform_id"`
	Size       int64    `json:"fs_size_bytes"`
	Regions    []string `json:"regions"`
	Languages  []string `json:"languages"`
	Revision   string   `json:"revision"`
	Created    string   `json:"created_at"`
}

// roms decodes either a page ({"items": [...], "total": n}) or, from older
// RomM, a plain list.
func decodeRoms(raw json.RawMessage) ([]rom, int, error) {
	var page struct {
		Items []rom `json:"items"`
		Total int   `json:"total"`
	}
	if err := json.Unmarshal(raw, &page); err == nil {
		return page.Items, page.Total, nil
	}
	var list []rom
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, 0, errors.New("unexpected answer from RomM")
	}
	return list, len(list), nil
}

type input struct {
	Platform  *int   `json:"platform"`
	Search    string `json:"search"`
	Limit     int    `json:"limit"`
	Platforms []int  `json:"platforms"`
	Mode      string `json:"mode"`
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
	case "platforms":
		ps, err := c.platforms(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range ps {
			out = append(out, map[string]any{"id": x.ID, "name": x.label(), "slug": x.Slug, "games": x.Roms, "open": fmt.Sprintf("%s/platform/%d", c.origin, x.ID)})
		}
		return sdk.JSON(out)

	case "roms":
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 25
		}
		q := url.Values{"limit": {strconv.Itoa(limit)}, "offset": {"0"}, "order_by": {"name"}, "order_dir": {"asc"}}
		if p.Platform != nil {
			if *p.Platform < 1 {
				return sdk.Result{}, errors.New("the platform is a platform id (see platforms)")
			}
			// platform_id for RomM 3, platform_ids for RomM 4.
			q.Set("platform_id", strconv.Itoa(*p.Platform))
			q.Set("platform_ids", strconv.Itoa(*p.Platform))
		}
		if s := strings.TrimSpace(p.Search); s != "" {
			if len(s) > 200 || strings.ContainsAny(s, "\r\n\x00") {
				return sdk.Result{}, errors.New("the search is one line of at most 200 characters")
			}
			q.Set("search_term", s)
		}
		var raw json.RawMessage
		if err := c.get(ctx, "/api/roms", q, &raw); err != nil {
			return sdk.Result{}, err
		}
		rs, total, err := decodeRoms(raw)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, r := range rs {
			if len(out) == limit {
				break
			}
			row := map[string]any{"id": r.ID, "name": r.Name, "file": r.FileName, "platformId": r.PlatformID, "sizeMB": float64(r.Size*10>>20) / 10,
				"open": fmt.Sprintf("%s/rom/%d", c.origin, r.ID)}
			if len(r.Regions) > 0 {
				row["regions"] = r.Regions
			}
			if len(r.Languages) > 0 {
				row["languages"] = r.Languages
			}
			if r.Revision != "" {
				row["revision"] = r.Revision
			}
			if r.Created != "" {
				row["added"] = r.Created
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"games": out, "total": total})

	case "scan_library":
		return c.scan(ctx, call.DryRun, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) scan(ctx context.Context, dry bool, p input) (sdk.Result, error) {
	mode := p.Mode
	if mode == "" {
		mode = "quick"
	}
	if mode != "quick" && mode != "new_platforms" {
		return sdk.Result{}, errors.New("mode is quick or new_platforms")
	}
	if len(p.Platforms) > maxPlatforms {
		return sdk.Result{}, fmt.Errorf("pick at most %d platforms", maxPlatforms)
	}
	ids := []int{}
	seen := map[int]bool{}
	for _, id := range p.Platforms {
		if id < 1 {
			return sdk.Result{}, errors.New("a platform is its id (see platforms)")
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	ps, err := c.platforms(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	by := map[int]platform{}
	for _, x := range ps {
		by[x.ID] = x
	}
	names := []string{}
	for _, id := range ids {
		x, ok := by[id]
		if !ok {
			return sdk.Result{}, fmt.Errorf("there's no platform %d", id)
		}
		names = append(names, x.label())
	}
	what := "every platform"
	if len(names) > 0 {
		what = strings.Join(names, ", ")
	}
	if dry {
		after, _ := json.Marshal(map[string]any{"mode": mode, "platforms": ids})
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Scan %s (%s)", what, strings.ReplaceAll(mode, "_", " ")),
			Changes: []sdk.Change{{Target: "RomM library: " + what, Op: "scan", After: after}}}}, nil
	}
	if err := c.emit(ctx, "scan", map[string]any{"platforms": ids, "type": mode, "apis": metadataSources}); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"scanning": what, "mode": mode})
}

// emit sends one Socket.IO event over Engine.IO v4 long-polling, the way
// RomM's web app starts a scan: open a session, connect to the default
// namespace, send the event, close.
func (c *conn) emit(ctx context.Context, event string, data any) error {
	body, err := c.poll(ctx, http.MethodGet, "", "")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(body, "0") {
		return errors.New("unexpected answer from RomM's live connection")
	}
	var open struct {
		SID string `json:"sid"`
	}
	if json.Unmarshal([]byte(body[1:]), &open) != nil || open.SID == "" || len(open.SID) > 200 {
		return errors.New("unexpected answer from RomM's live connection")
	}
	sid := open.SID
	defer c.poll(context.WithoutCancel(ctx), http.MethodPost, sid, "1") //nolint:errcheck // best effort close
	if _, err := c.poll(ctx, http.MethodPost, sid, "40"); err != nil {
		return err
	}
	ack, err := c.poll(ctx, http.MethodGet, sid, "")
	if err != nil {
		return err
	}
	connected := false
	for _, pkt := range strings.Split(ack, "\x1e") {
		switch {
		case strings.HasPrefix(pkt, "40"):
			connected = true
		case strings.HasPrefix(pkt, "44"):
			return errors.New("RomM refused the live connection (check the user's role)")
		}
	}
	if !connected {
		return errors.New("RomM didn't accept the live connection")
	}
	msg, err := json.Marshal([]any{event, data})
	if err != nil {
		return err
	}
	_, err = c.poll(ctx, http.MethodPost, sid, "42"+string(msg))
	return err
}

func (c *conn) poll(ctx context.Context, method, sid, payload string) (string, error) {
	q := url.Values{"EIO": {"4"}, "transport": {"polling"}}
	if sid != "" {
		q.Set("sid", sid)
	}
	var rd io.Reader
	hdr := http.Header{"Accept": {"*/*"}}
	if method == http.MethodPost {
		rd = strings.NewReader(payload)
		hdr.Set("Content-Type", "text/plain;charset=UTF-8")
	}
	res, err := c.api.Send(ctx, method, "/ws/socket.io/", q, rd, hdr)
	if rest.IsStatus(err, http.StatusNotFound) {
		return "", errors.New("this RomM has no live connection at /ws (RomM 3 or later is needed to scan)")
	}
	if err != nil {
		return "", explain(err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return "", fmt.Errorf("RomM answered %s", res.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return string(raw), err
}
