// Package streamerbot works with Streamer.bot on your streaming PC: it
// lists the actions through Streamer.bot's HTTP server, runs one (which can
// do anything those actions do on stream), and reads the global variables
// through its WebSocket server.
package streamerbot

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

	"github.com/coder/websocket"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Streamer.bot.
type Config struct {
	URL       string `json:"url"`       // HTTP server, default http://127.0.0.1:7474
	WebSocket string `json:"websocket"` // WebSocket server for globals, e.g. ws://127.0.0.1:8080/; optional
	Password  string `json:"password"`  // secret://, the WebSocket server's password if authentication is on
}

type conn struct {
	cfg  Config
	host sdk.Host
	api  *rest.Client
	ws   *http.Client // for the WebSocket handshake
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Streamer.bot module.
func New() *Module { return &Module{} }

var (
	guidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	argRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]{0,63}$`)
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "streamerbot", Name: "Streamer.bot", Version: "0.1.0", Category: "Gaming", Icon: "workflow",
		Description: "Streamer.bot on your streaming PC: list its actions, run one, read its global variables.",
		Presets:     []string{"gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"url":{"type":"string","default":"http://127.0.0.1:7474","description":"Streamer.bot: Servers/Clients, HTTP Server (turn it on)"},
			"websocket":{"type":"string","description":"Optional, for global variables: the WebSocket Server address, e.g. ws://127.0.0.1:8080/"},
			"password":{"type":"string","x-secret":true,"description":"The WebSocket Server's password, if authentication is on"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "actions", Title: "Actions", Description: "Streamer.bot's actions with their groups and whether they're enabled.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"group":{"type":"string","description":"Only this group"}}}`)},
			{Name: "run_action", Title: "Run an action", Description: "Runs a Streamer.bot action by name or id, with optional arguments. An action can do anything on stream (chat, scenes, raids, sounds), so this is destructive; the preview names the action.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{"action":{"type":"string","maxLength":200,"description":"The action's name"},"id":{"type":"string","description":"The action's id (a GUID), instead of the name"},"args":{"type":"object","maxProperties":20,"additionalProperties":{"type":["string","number","boolean"]},"description":"Arguments the action reads as %name%"}}}`)},
			{Name: "globals", Title: "Global variables", Description: "Streamer.bot's global variables with their values (through the WebSocket server). They often hold counters, viewer names and tokens, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"persisted":{"type":"boolean","default":true,"description":"Persisted globals (true) or temporary ones"}}}`)},
		},
	}
}

func parseURL(s string, schemes ...string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return nil, errors.New("bad address")
	}
	for _, sc := range schemes {
		if u.Scheme == sc {
			return u, nil
		}
	}
	return nil, errors.New("bad scheme")
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if strings.TrimSpace(c.URL) == "" {
		c.URL = "http://127.0.0.1:7474"
	}
	u, err := parseURL(c.URL, "http", "https")
	if err != nil {
		return errors.New("the HTTP server's address is like http://127.0.0.1:7474")
	}
	c.URL = u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/")
	if c.WebSocket != "" {
		w, err := parseURL(c.WebSocket, "ws", "wss")
		if err != nil {
			return errors.New("the WebSocket server's address is like ws://127.0.0.1:8080/")
		}
		c.WebSocket = w.String()
	}
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the WebSocket password in the vault and enter its secret:// reference")
	}
	if c.Password != "" && c.WebSocket == "" {
		return errors.New("the password is for the WebSocket server; add its address too")
	}
	cl := m.HTTP
	if cl == nil {
		cl = &http.Client{Timeout: 15 * time.Second, Transport: sdk.Transport(h)}
	}
	api := rest.New(c.URL, nil)
	api.HTTP = rest.SameHostOnly(cl)
	// The WebSocket library wants the context for timeouts, not the client.
	ws := rest.SameHostOnly(&http.Client{Transport: cl.Transport})
	m.set.Put(id, &conn{cfg: c, host: h, api: api, ws: ws})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

type action struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Group    string `json:"group"`
	Enabled  *bool  `json:"enabled"`
	Subcount int    `json:"subaction_count"`
}

func (c *conn) actions(ctx context.Context) ([]action, error) {
	var out struct {
		Actions []action `json:"actions"`
	}
	if _, err := c.api.Do(ctx, "GET", "/GetActions", nil, nil, &out); err != nil {
		return nil, reach(err)
	}
	return out.Actions, nil
}

func reach(err error) error {
	var re *rest.Error
	if errors.As(err, &re) || errors.Is(err, rest.ErrCrossHostRedirect) || errors.Is(err, context.Canceled) {
		return err
	}
	return fmt.Errorf("couldn't reach Streamer.bot's HTTP server (is it running with the HTTP server on?): %w", err)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	as, err := c.actions(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("%d actions", len(as))
	if c.cfg.WebSocket != "" {
		if err := c.withWS(ctx, func(context.Context, *wsSession) error { return nil }); err != nil {
			return sdk.Health{Status: "degraded", Message: msg + "; the WebSocket server (for globals) doesn't answer: " + err.Error()}
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Auth computes the WebSocket server's authentication string: base64 of
// SHA-256(base64(SHA-256(password+salt)) + challenge).
func Auth(password, salt, challenge string) string {
	s := sha256.Sum256([]byte(password + salt))
	secret := base64.StdEncoding.EncodeToString(s[:])
	a := sha256.Sum256([]byte(secret + challenge))
	return base64.StdEncoding.EncodeToString(a[:])
}

type wsSession struct {
	ws *websocket.Conn
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// read returns the next message that answers id (or, with id "", the next
// Hello), skipping events.
func (s *wsSession) read(ctx context.Context, id string) (map[string]json.RawMessage, error) {
	for {
		_, b, err := s.ws.Read(ctx)
		if err != nil {
			return nil, err
		}
		var msg map[string]json.RawMessage
		if json.Unmarshal(b, &msg) != nil {
			continue
		}
		var got, req string
		_ = json.Unmarshal(msg["id"], &got)
		_ = json.Unmarshal(msg["request"], &req)
		if (id == "" && req == "Hello") || (id != "" && got == id) {
			return msg, nil
		}
	}
}

func (s *wsSession) request(ctx context.Context, req map[string]any) (map[string]json.RawMessage, error) {
	id := newID()
	req["id"] = id
	b, _ := json.Marshal(req)
	if err := s.ws.Write(ctx, websocket.MessageText, b); err != nil {
		return nil, err
	}
	msg, err := s.read(ctx, id)
	if err != nil {
		return nil, err
	}
	var status, e string
	_ = json.Unmarshal(msg["status"], &status)
	_ = json.Unmarshal(msg["error"], &e)
	if status != "" && status != "ok" {
		if e == "" {
			e = status
		}
		return nil, errors.New("Streamer.bot: " + rest.Redact(e))
	}
	return msg, nil
}

// wsTimeout bounds a whole WebSocket session (a variable for tests).
var wsTimeout = 15 * time.Second

// withWS opens an authenticated session and runs f with a context bounded
// by wsTimeout; f must use that context for its requests.
func (c *conn) withWS(ctx context.Context, f func(context.Context, *wsSession) error) error {
	if c.cfg.WebSocket == "" {
		return errors.New("global variables come through Streamer.bot's WebSocket server: add its address in the settings")
	}
	ctx, cancel := context.WithTimeout(ctx, wsTimeout)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, c.cfg.WebSocket, &websocket.DialOptions{HTTPClient: c.ws})
	if err != nil {
		return fmt.Errorf("couldn't reach Streamer.bot's WebSocket server: %w", rest.TransportError(err))
	}
	defer ws.CloseNow()
	ws.SetReadLimit(8 << 20)
	s := &wsSession{ws: ws}
	hello, err := s.read(ctx, "")
	if err != nil {
		return fmt.Errorf("Streamer.bot didn't say hello: %w", err)
	}
	var a *struct {
		Salt      string `json:"salt"`
		Challenge string `json:"challenge"`
	}
	if raw, ok := hello["authentication"]; ok {
		_ = json.Unmarshal(raw, &a)
	}
	if a != nil && a.Salt != "" {
		if c.cfg.Password == "" {
			return errors.New("Streamer.bot's WebSocket server asks for a password; add it in the settings")
		}
		pw, err := c.host.Secret(ctx, c.cfg.Password)
		if err != nil {
			return err
		}
		if _, err := s.request(ctx, map[string]any{"request": "Authenticate", "authentication": Auth(pw, a.Salt, a.Challenge)}); err != nil {
			return errors.New("Streamer.bot refused the WebSocket password")
		}
	}
	if err := f(ctx, s); err != nil {
		return err
	}
	return ws.Close(websocket.StatusNormalClosure, "")
}

// validArgs checks run_action's arguments: a few named, short, plain values.
func validArgs(args map[string]any) error {
	if len(args) > 20 {
		return errors.New("pass up to 20 arguments")
	}
	for k, v := range args {
		if !argRe.MatchString(k) {
			return fmt.Errorf("%q isn't an argument name (letters, digits, _ and .)", k)
		}
		switch x := v.(type) {
		case string:
			if !utf8.ValidString(x) || len(x) > 2000 {
				return fmt.Errorf("argument %s is text of up to 2000 bytes", k)
			}
			for _, r := range x {
				if r < 0x20 && r != '\n' && r != '\t' {
					return fmt.Errorf("argument %s can't contain control characters", k)
				}
			}
		case float64, bool:
		default:
			return fmt.Errorf("argument %s is text, a number or true/false", k)
		}
	}
	return nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Group     string         `json:"group"`
		Action    string         `json:"action"`
		ID        string         `json:"id"`
		Args      map[string]any `json:"args"`
		Persisted *bool          `json:"persisted"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "actions":
		as, err := c.actions(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			Name       string `json:"name"`
			ID         string `json:"id"`
			Group      string `json:"group,omitempty"`
			Enabled    *bool  `json:"enabled,omitempty"`
			Subactions int    `json:"subactions,omitempty"`
		}
		rows := []row{}
		for _, a := range as {
			if p.Group != "" && !strings.EqualFold(a.Group, p.Group) {
				continue
			}
			rows = append(rows, row{Name: a.Name, ID: a.ID, Group: a.Group, Enabled: a.Enabled, Subactions: a.Subcount})
		}
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].Group != rows[j].Group {
				return rows[i].Group < rows[j].Group
			}
			return rows[i].Name < rows[j].Name
		})
		return sdk.JSON(rows)

	case "run_action":
		if (p.Action == "") == (p.ID == "") {
			return sdk.Result{}, errors.New("name the action, or give its id (not both)")
		}
		if p.ID != "" && !guidRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("an action id is a GUID, as actions lists")
		}
		if p.Action != "" && (!utf8.ValidString(p.Action) || len(p.Action) > 200 || strings.ContainsAny(p.Action, "\x00\r\n")) {
			return sdk.Result{}, errors.New("an action name is one line of up to 200 characters")
		}
		if err := validArgs(p.Args); err != nil {
			return sdk.Result{}, err
		}
		as, err := c.actions(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		var found []action
		for _, a := range as {
			if (p.ID != "" && strings.EqualFold(a.ID, p.ID)) || (p.Action != "" && a.Name == p.Action) {
				found = append(found, a)
			}
		}
		switch {
		case len(found) == 0:
			return sdk.Result{}, errors.New("Streamer.bot has no such action; see actions")
		case len(found) > 1:
			return sdk.Result{}, fmt.Errorf("%d actions are called %q; give the id instead", len(found), p.Action)
		}
		a := found[0]
		if a.Enabled != nil && !*a.Enabled {
			return sdk.Result{}, fmt.Errorf("the action %q is disabled in Streamer.bot", a.Name)
		}
		target := a.Name
		if a.Group != "" {
			target = a.Group + " / " + a.Name
		}
		if call.DryRun {
			after, _ := json.Marshal(map[string]any{"action": a.Name, "id": a.ID, "args": p.Args})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Run the Streamer.bot action %q (it can do anything on stream)", a.Name),
				Changes: []sdk.Change{{Target: target, Op: "run", After: after}}}}, nil
		}
		body := map[string]any{"action": map[string]string{"id": a.ID, "name": a.Name}}
		if len(p.Args) > 0 {
			body["args"] = p.Args
		}
		if _, err := c.api.Do(ctx, "POST", "/DoAction", nil, body, nil); err != nil {
			return sdk.Result{}, reach(err)
		}
		return sdk.JSON(map[string]any{"ran": a.Name, "id": a.ID})

	case "globals":
		persisted := p.Persisted == nil || *p.Persisted
		type row struct {
			Name      string          `json:"name"`
			Value     json.RawMessage `json:"value"`
			LastWrite string          `json:"lastWrite,omitempty"`
		}
		rows := []row{}
		err := c.withWS(ctx, func(ctx context.Context, s *wsSession) error {
			msg, err := s.request(ctx, map[string]any{"request": "GetGlobals", "persisted": persisted})
			if err != nil {
				return err
			}
			var byName map[string]row
			var list []row
			if json.Unmarshal(msg["variables"], &byName) == nil {
				for k, v := range byName {
					if v.Name == "" {
						v.Name = k
					}
					list = append(list, v)
				}
			} else if err := json.Unmarshal(msg["variables"], &list); err != nil {
				return errors.New("unexpected answer from Streamer.bot")
			}
			rows = append(rows, list...)
			return nil
		})
		if err != nil {
			return sdk.Result{}, err
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
		return sdk.JSON(map[string]any{"persisted": persisted, "count": len(rows), "variables": rows})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
