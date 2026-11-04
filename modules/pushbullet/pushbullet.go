// Package pushbullet works with a Pushbullet account through an access
// token: its devices, pushing a note to your own devices, recent pushes and
// deleting pushes you sent.
package pushbullet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Pushbullet account.
type Config struct {
	Token string `json:"token"` // secret:// access token
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Base replaces https://api.pushbullet.com/v2 (tests).
	Base string
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Pushbullet module.
func New() *Module { return &Module{} }

const (
	defaultBase = "https://api.pushbullet.com/v2"
	maxTitle    = 250
	maxBody     = 10000
	// maxShown is how much of a push's text pushes returns.
	maxShown = 2000
	// scan is how many recent pushes delete_push looks through.
	scan = 500
)

var (
	idenRe   = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
	cursorRe = regexp.MustCompile(`^[A-Za-z0-9_=-]{1,256}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "pushbullet", Name: "Pushbullet", Version: "0.1.0", Category: "Communication", Icon: "notification",
		Description: "Pushbullet: your devices, push a note to them, recent pushes and deleting pushes you sent.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"An access token (pushbullet.com, Settings, Account, Create Access Token)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "devices", Title: "Devices", Description: "Your active devices: id, nickname, maker, model, app version and whether it can send SMS. Never their push tokens or key fingerprints.", Risk: sdk.RiskRead},
			{Name: "push_note", Title: "Push a note", Description: "Pushes a note to all your own devices, or one of them. It goes to nobody else. Undo deletes it from Pushbullet; a notification already shown may stay on a device.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(fmt.Sprintf(`{"type":"object","required":["body"],"properties":{"title":{"type":"string","maxLength":%d},"body":{"type":"string","maxLength":%d},"device":{"type":"string","description":"Only this device (id from devices); all your devices when left out"}}}`, maxTitle, maxBody))},
			{Name: "pushes", Title: "Recent pushes", Description: "Recent pushes, newest first: type, direction (self, outgoing, incoming), sender name, title, text (up to 2000 characters), link and date. Their contents can be private.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":100,"default":20},"cursor":{"type":"string","description":"From the previous page, for the next one"}}}`)},
			{Name: "delete_push", Title: "Delete a push", Description: "Deletes a push you sent (to yourself or someone else) from Pushbullet everywhere. Can't be undone. Pushes others sent you are refused.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["push"],"properties":{"push":{"type":"string","description":"Push id (from pushes or push_note)"}}}`)},
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
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	ref := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Access-Token", strings.TrimSpace(t))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	// Access-Token is a custom header, which Go would forward to another host.
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Pushbullet refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the access token isn't allowed to do this in Pushbullet")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Pushbullet's rate limit is used up; try again later")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

// device is decoded field by field: Pushbullet's answer carries push tokens
// and key fingerprints.
type device struct {
	Iden         string `json:"iden"`
	Active       bool   `json:"active"`
	Nickname     string `json:"nickname"`
	Generated    bool   `json:"generated_nickname"`
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	AppVersion   int    `json:"app_version"`
	Icon         string `json:"icon"`
	HasSMS       bool   `json:"has_sms"`
}

// push leaves out sender and receiver email addresses and file links.
type push struct {
	Iden       string  `json:"iden"`
	Active     bool    `json:"active"`
	Created    float64 `json:"created"`
	Type       string  `json:"type"`
	Direction  string  `json:"direction"`
	Dismissed  bool    `json:"dismissed"`
	SenderName string  `json:"sender_name"`
	Target     string  `json:"target_device_iden"`
	Title      string  `json:"title"`
	Body       string  `json:"body"`
	URL        string  `json:"url"`
	FileName   string  `json:"file_name"`
}

type pushPage struct {
	Pushes []push `json:"pushes"`
	Cursor string `json:"cursor"`
}

func (c *conn) devices(ctx context.Context) ([]device, error) {
	var d struct {
		Devices []device `json:"devices"`
	}
	err := c.do(ctx, http.MethodGet, "/devices", url.Values{"active": {"true"}}, nil, &d)
	return d.Devices, err
}

func when(ts float64) string {
	if ts <= 0 || math.IsNaN(ts) || ts > 1e11 {
		return ""
	}
	sec, frac := math.Modf(ts)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC().Format(time.RFC3339)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		Name string `json:"name"`
	}
	if err := c.do(ctx, http.MethodGet, "/users/me", nil, nil, &me); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	ds, err := c.devices(ctx)
	if err != nil {
		return sdk.Health{Status: "degraded", Message: "Pushbullet · " + err.Error()}
	}
	msg := "Pushbullet"
	if me.Name != "" && utf8.RuneCountInString(me.Name) < 60 {
		msg += " · " + me.Name
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%s · %d devices", msg, len(ds))}
}

type input struct {
	Title  string `json:"title"`
	Body   string `json:"body"`
	Device string `json:"device"`
	Limit  int    `json:"limit"`
	Cursor string `json:"cursor"`
	Push   string `json:"push"`
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
	case "devices":
		ds, err := c.devices(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range ds {
			if !d.Active {
				continue
			}
			row := map[string]any{"id": d.Iden, "nickname": d.Nickname, "hasSms": d.HasSMS}
			for k, v := range map[string]string{"manufacturer": d.Manufacturer, "model": d.Model, "icon": d.Icon} {
				if v != "" {
					row[k] = v
				}
			}
			if d.AppVersion > 0 {
				row["appVersion"] = d.AppVersion
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	case "push_note":
		return c.note(ctx, call, p)
	case "pushes":
		if p.Limit < 0 || p.Limit > 100 || (p.Cursor != "" && !cursorRe.MatchString(p.Cursor)) {
			return sdk.Result{}, errors.New("the limit is between 1 and 100, and the cursor comes from the previous page")
		}
		return c.pushes(ctx, p)
	case "delete_push":
		if !idenRe.MatchString(p.Push) {
			return sdk.Result{}, errors.New("a push is its id from pushes")
		}
		return c.delete(ctx, call, p.Push)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func clip(s string) string {
	if len(s) <= maxShown {
		return s
	}
	n := maxShown
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func show(p push) map[string]any {
	row := map[string]any{"id": p.Iden, "type": p.Type, "direction": p.Direction, "created": when(p.Created), "dismissed": p.Dismissed}
	for k, v := range map[string]string{"sender": p.SenderName, "title": clip(p.Title), "body": clip(p.Body), "url": clip(p.URL), "fileName": p.FileName, "device": p.Target} {
		if v != "" {
			row[k] = v
		}
	}
	return row
}

func (c *conn) pushes(ctx context.Context, p input) (sdk.Result, error) {
	if p.Limit == 0 {
		p.Limit = 20
	}
	q := url.Values{"active": {"true"}, "limit": {strconv.Itoa(p.Limit)}}
	if p.Cursor != "" {
		q.Set("cursor", p.Cursor)
	}
	var pg pushPage
	if err := c.do(ctx, http.MethodGet, "/pushes", q, nil, &pg); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, ps := range pg.Pushes {
		if ps.Active {
			out = append(out, show(ps))
		}
	}
	res := map[string]any{"pushes": out}
	if pg.Cursor != "" && cursorRe.MatchString(pg.Cursor) {
		res["cursor"] = pg.Cursor
	}
	return sdk.JSON(res)
}

func (c *conn) note(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	p.Title = strings.TrimSpace(p.Title)
	if strings.TrimSpace(p.Body) == "" {
		return sdk.Result{}, errors.New("enter the note's text")
	}
	if utf8.RuneCountInString(p.Body) > maxBody || utf8.RuneCountInString(p.Title) > maxTitle {
		return sdk.Result{}, fmt.Errorf("the title is at most %d characters and the text at most %d", maxTitle, maxBody)
	}
	if p.Device != "" && !idenRe.MatchString(p.Device) {
		return sdk.Result{}, errors.New("a device is its id from devices")
	}
	// Only device_iden is ever set: no email, channel or client target, so
	// the note reaches the token's own devices and nobody else.
	body := map[string]any{"type": "note", "title": p.Title, "body": p.Body}
	target := "all your devices"
	if p.Device != "" {
		ds, err := c.devices(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		name := ""
		for _, d := range ds {
			if d.Iden == p.Device && d.Active {
				name = d.Nickname
				if name == "" {
					name = d.Iden
				}
			}
		}
		if name == "" {
			return sdk.Result{}, fmt.Errorf("you have no active device %s", p.Device)
		}
		body["device_iden"] = p.Device
		target = "your device " + name
	}
	if call.DryRun {
		after, _ := json.Marshal(body)
		return sdk.Result{Plan: &sdk.Plan{Summary: "Push a Pushbullet note to " + target, Changes: []sdk.Change{{Target: "Pushbullet", Op: "send", After: after}}}}, nil
	}
	var sent push
	if err := c.do(ctx, http.MethodPost, "/pushes", nil, body, &sent); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"id": sent.Iden, "sent": true, "to": target})
	if idenRe.MatchString(sent.Iden) {
		res.Undo = sdk.UndoWith("delete_push", map[string]string{"push": sent.Iden}, "Delete the note from Pushbullet")
	}
	return res, err
}

func (c *conn) delete(ctx context.Context, call sdk.Call, iden string) (sdk.Result, error) {
	// There's no documented single-push read: look through the recent ones.
	var pg pushPage
	if err := c.do(ctx, http.MethodGet, "/pushes", url.Values{"active": {"true"}, "limit": {strconv.Itoa(scan)}}, nil, &pg); err != nil {
		return sdk.Result{}, err
	}
	var found *push
	for i := range pg.Pushes {
		if pg.Pushes[i].Iden == iden && pg.Pushes[i].Active {
			found = &pg.Pushes[i]
		}
	}
	if found == nil {
		return sdk.JSON(map[string]any{"id": iden, "deleted": true, "note": fmt.Sprintf("nothing to change: there's no push with this id among your %d most recent", scan)})
	}
	if found.Direction != "self" && found.Direction != "outgoing" {
		return sdk.Result{}, errors.New("this push was sent to you by someone else; only pushes you sent can be deleted here")
	}
	if call.DryRun {
		// The preview names the push, never its text: delete_push isn't sensitive.
		before, _ := json.Marshal(map[string]any{"id": found.Iden, "type": found.Type, "direction": found.Direction, "created": when(found.Created)})
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete Pushbullet push %s (%s, %s)", iden, found.Type, found.Direction), Changes: []sdk.Change{{Target: "push " + iden, Op: "delete", Before: before}}}}, nil
	}
	if err := c.do(ctx, http.MethodDelete, "/pushes/"+url.PathEscape(iden), nil, nil, nil); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.JSON(map[string]any{"id": iden, "deleted": true, "note": "nothing to change: the push is already gone"})
		}
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"id": iden, "deleted": true})
}
