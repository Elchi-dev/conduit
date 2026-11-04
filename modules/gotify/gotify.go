// Package gotify works with a Gotify server: its applications (never their
// tokens), the messages it has received, sending a message through an
// application token and deleting messages through a client token.
package gotify

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
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Gotify server.
type Config struct {
	URL                string `json:"url"`         // e.g. https://gotify.example.com
	ClientToken        string `json:"clientToken"` // secret:// client token: read applications and messages, delete messages
	AppToken           string `json:"appToken"`    // secret:// application token: send messages
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	client, app *rest.Client // nil when that token isn't set
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Gotify module.
func New() *Module { return &Module{} }

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

const (
	maxTitle   = 250
	maxMessage = 10000
	// maxShown is how much of a message's text messages returns.
	maxShown = 2000
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "gotify", Name: "Gotify", Version: "0.1.0", Category: "Communication", Icon: "notification",
		Description: "Gotify: applications and received messages; send a message and delete messages.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"Your Gotify server's address, e.g. https://gotify.example.com"},
			"clientToken":{"type":"string","x-secret":true,"description":"A client token (Clients, Create client): reads applications and messages and deletes messages"},
			"appToken":{"type":"string","x-secret":true,"description":"An application token (Apps, Create application): sends messages as that application"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "applications", Title: "Applications", Description: "Applications that send messages: name, description, default priority, last used. Never their tokens. Needs the client token.", Risk: sdk.RiskRead},
			{Name: "messages", Title: "Messages", Description: "Received messages, newest first: application, title, text, priority and date. Needs the client token.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"application":{"type":"integer","minimum":1,"description":"Only this application's messages (id from applications)"},"limit":{"type":"integer","minimum":1,"maximum":200,"default":20},"before":{"type":"integer","minimum":1,"description":"Only messages older than this message id, for the next page"}}}`)},
			{Name: "send_message", Title: "Send a message", Description: "Sends a message through the application token; it shows on every device signed in to that Gotify user. Undo deletes it from Gotify (needs a client token of the same user); a notification already shown stays on the device.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(fmt.Sprintf(`{"type":"object","required":["message"],"properties":{"title":{"type":"string","maxLength":%d},"message":{"type":"string","maxLength":%d,"description":"The text (plain; markdown shows as markdown when markdown is true)"},"priority":{"type":"integer","minimum":0,"maximum":10,"description":"0 to 10; the application's default when left out. Phones make a sound from 4 and override do-not-disturb from 8, depending on their settings"},"markdown":{"type":"boolean","default":false}}}`, maxTitle, maxMessage))},
			{Name: "delete_message", Title: "Delete a message", Description: "Deletes one received message. Can't be undone. Needs the client token.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"integer","minimum":1,"description":"Message id (from messages)"}}}`)},
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
		return errors.New("the address is like https://gotify.example.com")
	}
	if c.ClientToken == "" && c.AppToken == "" {
		return errors.New("enter a client token, an application token, or both")
	}
	for _, t := range []string{c.ClientToken, c.AppToken} {
		if t != "" && !strings.HasPrefix(t, "secret://") {
			return errors.New("store the tokens in the vault and enter their secret:// references")
		}
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
	// The tokens travel in X-Gotify-Key, which Go would forward to another host.
	client = rest.SameHostOnly(client)
	base := u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/")
	mk := func(ref string) *rest.Client {
		if ref == "" {
			return nil
		}
		api := rest.New(base, func(ctx context.Context, r *http.Request) error {
			t, err := h.Secret(ctx, ref)
			if err != nil {
				return err
			}
			r.Header.Set("X-Gotify-Key", strings.TrimSpace(t))
			return nil
		})
		api.HTTP = client
		return api
	}
	m.set.Put(id, &conn{client: mk(c.ClientToken), app: mk(c.AppToken)})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var (
	errNoClient = errors.New("this needs a client token in the settings")
	errNoApp    = errors.New("sending needs an application token in the settings")
)

func friendly(err error, which string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return fmt.Errorf("Gotify refused the %s token", which)
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("the %s token isn't allowed to do this in Gotify", which)
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	if c.client == nil {
		return errNoClient
	}
	_, err := c.client.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err, "client")
}

// application is decoded field by field: Gotify's answer carries its token.
type application struct {
	ID              int    `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	Internal        bool   `json:"internal"`
	DefaultPriority int    `json:"defaultPriority"`
	LastUsed        string `json:"lastUsed"`
}

func (c *conn) applications(ctx context.Context) ([]application, error) {
	var as []application
	err := c.get(ctx, "/application", nil, &as)
	return as, err
}

// message is decoded without its extras, which clients use for anything
// from click URLs to credentials.
type message struct {
	ID       int    `json:"id"`
	AppID    int    `json:"appid"`
	Title    string `json:"title"`
	Message  string `json:"message"`
	Priority int    `json:"priority"`
	Date     string `json:"date"`
}

type page struct {
	Messages []message `json:"messages"`
	Paging   struct {
		Since int `json:"since"`
	} `json:"paging"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	api := c.client
	if api == nil {
		api = c.app
	}
	var st struct {
		Health   string `json:"health"`
		Database string `json:"database"`
	}
	if _, err := api.Do(ctx, http.MethodGet, "/health", nil, nil, &st); err != nil && !rest.IsStatus(err, http.StatusInternalServerError) {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Gotify server at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var v struct {
		Version string `json:"version"`
	}
	_, _ = api.Do(ctx, http.MethodGet, "/version", nil, nil, &v)
	msg := "Gotify"
	if v.Version != "" && len(v.Version) < 40 {
		msg += " " + v.Version
	}
	if c.client != nil {
		as, err := c.applications(ctx)
		if err != nil {
			return sdk.Health{Status: "down", Message: err.Error()}
		}
		msg += fmt.Sprintf(" · %d applications", len(as))
	} else {
		msg += " · application token only (it can send, not read)"
	}
	if st.Health == "" {
		return sdk.Health{Status: "degraded", Message: msg + " · its health check failed"}
	}
	if st.Health != "green" || (st.Database != "" && st.Database != "green") {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%s · health %s, database %s", msg, st.Health, st.Database)}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Application int    `json:"application"`
	Limit       int    `json:"limit"`
	Before      int    `json:"before"`
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Message     string `json:"message"`
	Priority    *int   `json:"priority"`
	Markdown    bool   `json:"markdown"`
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
	case "applications":
		as, err := c.applications(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, a := range as {
			row := map[string]any{"id": a.ID, "name": a.Name, "defaultPriority": a.DefaultPriority, "internal": a.Internal}
			if a.Description != "" {
				row["description"] = a.Description
			}
			if a.LastUsed != "" && !strings.HasPrefix(a.LastUsed, "0001-") {
				row["lastUsed"] = a.LastUsed
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	case "messages":
		if p.Application < 0 || p.Before < 0 || p.Limit < 0 || p.Limit > 200 {
			return sdk.Result{}, errors.New("the application and before are ids from Gotify, the limit between 1 and 200")
		}
		return c.messages(ctx, p)
	case "send_message":
		return c.send(ctx, call, p)
	case "delete_message":
		if p.ID <= 0 {
			return sdk.Result{}, errors.New("a message is its id from messages")
		}
		return c.delete(ctx, call, p.ID)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) appNames(ctx context.Context) map[int]string {
	out := map[int]string{}
	if as, err := c.applications(ctx); err == nil {
		for _, a := range as {
			out[a.ID] = a.Name
		}
	}
	return out
}

func (c *conn) messages(ctx context.Context, p input) (sdk.Result, error) {
	if c.client == nil {
		return sdk.Result{}, errNoClient
	}
	if p.Limit == 0 {
		p.Limit = 20
	}
	q := url.Values{"limit": {strconv.Itoa(p.Limit)}}
	if p.Before > 0 {
		q.Set("since", strconv.Itoa(p.Before))
	}
	path := "/message"
	if p.Application > 0 {
		path = "/application/" + strconv.Itoa(p.Application) + "/message"
	}
	var pg page
	if err := c.get(ctx, path, q, &pg); err != nil {
		if p.Application > 0 && rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no application %d", p.Application)
		}
		return sdk.Result{}, err
	}
	names := c.appNames(ctx)
	out := []map[string]any{}
	for _, msg := range pg.Messages {
		out = append(out, show(msg, names))
	}
	res := map[string]any{"messages": out}
	if len(pg.Messages) == p.Limit && pg.Paging.Since > 0 {
		res["before"] = pg.Paging.Since
	}
	return sdk.JSON(res)
}

func show(msg message, names map[int]string) map[string]any {
	text := msg.Message
	if len(text) > maxShown {
		text = text[:maxShown]
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
		text += "…"
	}
	row := map[string]any{"id": msg.ID, "application": names[msg.AppID], "applicationId": msg.AppID, "message": text, "priority": msg.Priority, "date": msg.Date}
	if msg.Title != "" {
		row["title"] = msg.Title
	}
	return row
}

func (c *conn) send(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	p.Title = strings.TrimSpace(p.Title)
	if strings.TrimSpace(p.Message) == "" {
		return sdk.Result{}, errors.New("enter the message's text")
	}
	if utf8.RuneCountInString(p.Message) > maxMessage || utf8.RuneCountInString(p.Title) > maxTitle {
		return sdk.Result{}, fmt.Errorf("the title is at most %d characters and the message at most %d", maxTitle, maxMessage)
	}
	if p.Priority != nil && (*p.Priority < 0 || *p.Priority > 10) {
		return sdk.Result{}, errors.New("the priority is between 0 and 10")
	}
	if c.app == nil {
		return sdk.Result{}, errNoApp
	}
	body := map[string]any{"message": p.Message}
	if p.Title != "" {
		body["title"] = p.Title
	}
	if p.Priority != nil {
		body["priority"] = *p.Priority
	}
	if p.Markdown {
		body["extras"] = map[string]any{"client::display": map[string]string{"contentType": "text/markdown"}}
	}
	if call.DryRun {
		after, _ := json.Marshal(body)
		summary := "Send a Gotify message to the devices of the application token's user"
		if p.Title != "" {
			summary = fmt.Sprintf("Send %q to the devices of the application token's user", p.Title)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "Gotify", Op: "send", After: after}}}}, nil
	}
	var sent message
	if _, err := c.app.Do(ctx, http.MethodPost, "/message", nil, body, &sent); err != nil {
		return sdk.Result{}, friendly(err, "application")
	}
	res, err := sdk.JSON(map[string]any{"id": sent.ID, "applicationId": sent.AppID, "priority": sent.Priority, "sent": true})
	// The client token deletes only its own user's messages; for another
	// user's application the undo would report the message gone while it
	// stays, so there's none.
	if c.client != nil && sent.ID > 0 {
		if _, ours := c.appNames(ctx)[sent.AppID]; ours {
			res.Undo = sdk.UndoWith("delete_message", map[string]int{"id": sent.ID}, "Delete the message from Gotify")
		}
	}
	return res, err
}

func (c *conn) delete(ctx context.Context, call sdk.Call, id int) (sdk.Result, error) {
	if c.client == nil {
		return sdk.Result{}, errNoClient
	}
	// Gotify has no single-message read: the page older than id+1 starts
	// with the message, if it's there.
	var pg page
	if err := c.get(ctx, "/message", url.Values{"limit": {"1"}, "since": {strconv.Itoa(id + 1)}}, &pg); err != nil {
		return sdk.Result{}, err
	}
	if len(pg.Messages) == 0 || pg.Messages[0].ID != id {
		return sdk.JSON(map[string]any{"id": id, "deleted": true, "note": "nothing to change: there's no message with this id"})
	}
	msg := pg.Messages[0]
	if call.DryRun {
		before, _ := json.Marshal(show(msg, c.appNames(ctx)))
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete Gotify message %d", id), Changes: []sdk.Change{{Target: fmt.Sprintf("message %d", id), Op: "delete", Before: before}}}}, nil
	}
	if _, err := c.client.Do(ctx, http.MethodDelete, "/message/"+strconv.Itoa(id), nil, nil, nil); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.JSON(map[string]any{"id": id, "deleted": true, "note": "nothing to change: there's no message with this id"})
		}
		return sdk.Result{}, friendly(err, "client")
	}
	return sdk.JSON(map[string]any{"id": id, "deleted": true})
}
