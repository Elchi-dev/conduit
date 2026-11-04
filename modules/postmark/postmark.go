// Package postmark reads one Postmark server through its API with a server
// token: outbound stats, bounces and message streams. It can reactivate a
// bounced address.
//
// Bounces name recipients, so listing them is sensitive (kept out of the
// audit log), and so is reactivating one, whose preview names the address.
// Reactivating lets mail reach an address that bounced or complained again,
// so it is destructive.
package postmark

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

// Config is one Postmark server.
type Config struct {
	Token string `json:"token"` // secret:// server API token
}

const defaultBase = "https://api.postmarkapp.com"

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.postmarkapp.com (tests).
	Base string
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Postmark module.
func New() *Module { return &Module{} }

func (m *Module) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

var (
	tokenRe  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	streamRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,29}$`)
	tagRe    = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,1000}$`)
)

var bounceTypes = map[string]bool{"HardBounce": true, "Transient": true, "Unsubscribe": true, "Subscribe": true, "AutoResponder": true, "AddressChange": true, "DnsError": true, "SpamNotification": true, "OpenRelayTest": true, "Unknown": true, "SoftBounce": true, "VirusNotification": true, "ChallengeVerification": true, "BadEmailAddress": true, "SpamComplaint": true, "ManuallyDeactivated": true, "Unconfirmed": true, "Blocked": true, "SMTPApiError": true, "InboundError": true, "DMARCPolicy": true, "TemplateRenderingFailed": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	stream := `"stream":{"type":"string","description":"Only this message stream (outbound, broadcast or a stream id)"}`
	return sdk.Manifest{
		ID: "postmark", Name: "Postmark", Version: "0.1.0", Category: "Communication", Icon: "mail",
		Description: "A Postmark server: outbound stats, bounces and message streams; reactivate a bounced address with a preview.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"The server's API token (Servers, your server, API Tokens); an account token won't work"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "stats", Title: "Outbound stats", Description: "Sent, bounced, spam complaints, bounce and complaint rates, opens and clicks over the last days.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"days":{"type":"integer","default":30,"minimum":1,"maximum":365},` + stream + `,"tag":{"type":"string","description":"Only messages with this tag"}}}`)},
			{Name: "bounces", Title: "Bounces", Description: "Recent bounces, newest first: address, type, description, when, and whether the address was deactivated and can be reactivated.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"count":{"type":"integer","default":50,"minimum":1,"maximum":500},"offset":{"type":"integer","minimum":0,"maximum":10000},"type":{"type":"string","description":"A Postmark bounce type, e.g. HardBounce, SoftBounce, SpamComplaint"},"inactive":{"type":"boolean","description":"Only bounces that deactivated their address"},` + stream + `}}`)},
			{Name: "reactivate_bounce", Title: "Reactivate a bounced address", Description: "Reactivates the address of a bounce that deactivated it, so Postmark sends to it again. The preview names the address and why it bounced.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["bounce"],"properties":{"bounce":{"type":"integer","minimum":1,"description":"Bounce id (see bounces)"}}}`)},
			{Name: "message_streams", Title: "Message streams", Description: "The server's message streams (transactional, broadcast, inbound) with their type and unsubscribe handling.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"includeArchived":{"type":"boolean"}}}`)},
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
		return errors.New("store the server token in the vault and enter its secret:// reference")
	}
	base := defaultBase
	if m.Base != "" {
		base = strings.TrimRight(m.Base, "/")
	}
	hc := m.HTTP
	if hc == nil {
		hc = sdk.HTTPClient(h, 30*time.Second)
	}
	ref := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		if !tokenRe.MatchString(t) {
			return errors.New("the stored token doesn't look like a Postmark server token")
		}
		r.Header.Set("X-Postmark-Server-Token", t)
		return nil
	})
	api.HTTP = rest.SameHostOnly(hc)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		return errors.New("Postmark refused the server token (an account token won't work here)")
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	// /server also returns the server's API tokens: only the name is read.
	var s struct {
		Name string `json:"Name"`
	}
	if err := c.do(ctx, http.MethodGet, "/server", nil, nil, &s); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "connected to server " + clip(s.Name, 100)}
}

type input struct {
	Days            int    `json:"days"`
	Stream          string `json:"stream"`
	Tag             string `json:"tag"`
	Count           int    `json:"count"`
	Offset          int    `json:"offset"`
	Type            string `json:"type"`
	Inactive        bool   `json:"inactive"`
	Bounce          int64  `json:"bounce"`
	IncludeArchived bool   `json:"includeArchived"`
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

type bounce struct {
	ID            int64  `json:"ID"`
	Type          string `json:"Type"`
	Name          string `json:"Name"`
	Tag           string `json:"Tag"`
	MessageID     string `json:"MessageID"`
	MessageStream string `json:"MessageStream"`
	Description   string `json:"Description"`
	Details       string `json:"Details"`
	Email         string `json:"Email"`
	From          string `json:"From"`
	BouncedAt     string `json:"BouncedAt"`
	Inactive      bool   `json:"Inactive"`
	CanActivate   bool   `json:"CanActivate"`
	Subject       string `json:"Subject"`
}

func (b bounce) out() map[string]any {
	o := map[string]any{"id": b.ID, "type": b.Type, "email": b.Email, "bouncedAt": b.BouncedAt, "inactive": b.Inactive, "canActivate": b.CanActivate}
	for k, v := range map[string]string{"name": b.Name, "description": clip(b.Description, 300), "details": clip(b.Details, 300), "from": b.From, "subject": clip(b.Subject, 200), "stream": b.MessageStream, "tag": b.Tag, "messageId": b.MessageID} {
		if v != "" {
			o[k] = v
		}
	}
	return o
}

func (c *conn) stream(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s != "" && !streamRe.MatchString(s) {
		return "", errors.New("the stream is a message stream id like outbound or broadcast")
	}
	return s, nil
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
	case "stats":
		days := p.Days
		if days <= 0 || days > 365 {
			days = 30
		}
		stream, err := c.stream(p.Stream)
		if err != nil {
			return sdk.Result{}, err
		}
		end := m.now().UTC()
		q := url.Values{"fromdate": {end.AddDate(0, 0, -(days - 1)).Format("2006-01-02")}, "todate": {end.Format("2006-01-02")}}
		if stream != "" {
			q.Set("messagestream", stream)
		}
		if p.Tag != "" {
			if !tagRe.MatchString(p.Tag) {
				return sdk.Result{}, errors.New("the tag is one line")
			}
			q.Set("tag", p.Tag)
		}
		var s map[string]any
		if err := c.do(ctx, http.MethodGet, "/stats/outbound", q, nil, &s); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"from": q.Get("fromdate"), "to": q.Get("todate")}
		for api, key := range map[string]string{"Sent": "sent", "Bounced": "bounced", "SMTPApiErrors": "smtpApiErrors", "BounceRate": "bounceRate", "SpamComplaints": "spamComplaints", "SpamComplaintsRate": "spamComplaintsRate", "Opens": "opens", "UniqueOpens": "uniqueOpens", "Tracked": "tracked", "TotalClicks": "clicks", "UniqueLinksClicked": "uniqueLinksClicked", "WithOpenTracking": "withOpenTracking", "WithLinkTracking": "withLinkTracking"} {
			if v, ok := s[api].(float64); ok {
				out[key] = v
			}
		}
		if stream != "" {
			out["stream"] = stream
		}
		return sdk.JSON(out)

	case "bounces":
		stream, err := c.stream(p.Stream)
		if err != nil {
			return sdk.Result{}, err
		}
		count := p.Count
		if count <= 0 || count > 500 {
			count = 50
		}
		if p.Offset < 0 || p.Offset > 10000 {
			return sdk.Result{}, errors.New("offset is between 0 and 10000")
		}
		q := url.Values{"count": {strconv.Itoa(count)}, "offset": {strconv.Itoa(p.Offset)}}
		if p.Type != "" {
			if !bounceTypes[p.Type] {
				return sdk.Result{}, fmt.Errorf("type %q isn't a Postmark bounce type (HardBounce, SoftBounce, SpamComplaint, …)", p.Type)
			}
			q.Set("type", p.Type)
		}
		if p.Inactive {
			q.Set("inactive", "true")
		}
		if stream != "" {
			q.Set("messagestream", stream)
		}
		var l struct {
			TotalCount int      `json:"TotalCount"`
			Bounces    []bounce `json:"Bounces"`
		}
		if err := c.do(ctx, http.MethodGet, "/bounces", q, nil, &l); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, b := range l.Bounces {
			out = append(out, b.out())
		}
		return sdk.JSON(map[string]any{"total": l.TotalCount, "items": out})

	case "reactivate_bounce":
		return c.reactivate(ctx, call, p)

	case "message_streams":
		q := url.Values{"MessageStreamType": {"All"}, "IncludeArchivedStreams": {strconv.FormatBool(p.IncludeArchived)}}
		var l struct {
			MessageStreams []struct {
				ID                string  `json:"ID"`
				Name              string  `json:"Name"`
				Description       string  `json:"Description"`
				MessageStreamType string  `json:"MessageStreamType"`
				CreatedAt         string  `json:"CreatedAt"`
				ArchivedAt        *string `json:"ArchivedAt"`
				Subscription      struct {
					UnsubscribeHandlingType string `json:"UnsubscribeHandlingType"`
				} `json:"SubscriptionManagementConfiguration"`
			} `json:"MessageStreams"`
		}
		if err := c.do(ctx, http.MethodGet, "/message-streams", q, nil, &l); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range l.MessageStreams {
			o := map[string]any{"id": s.ID, "name": s.Name, "type": s.MessageStreamType, "created": s.CreatedAt}
			if s.Description != "" {
				o["description"] = clip(s.Description, 300)
			}
			if s.Subscription.UnsubscribeHandlingType != "" {
				o["unsubscribeHandling"] = s.Subscription.UnsubscribeHandlingType
			}
			if s.ArchivedAt != nil && *s.ArchivedAt != "" {
				o["archivedAt"] = *s.ArchivedAt
			}
			out = append(out, o)
		}
		return sdk.JSON(map[string]any{"items": out})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) reactivate(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.Bounce <= 0 {
		return sdk.Result{}, errors.New("the bounce is its id (see bounces)")
	}
	id := strconv.FormatInt(p.Bounce, 10)
	var b bounce
	if err := c.do(ctx, http.MethodGet, "/bounces/"+id, nil, nil, &b); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusUnprocessableEntity) {
			return sdk.Result{}, fmt.Errorf("there's no bounce %s", id)
		}
		return sdk.Result{}, err
	}
	if !b.Inactive {
		return sdk.JSON(map[string]any{"bounce": b.ID, "email": b.Email, "note": "the address is active already"})
	}
	if !b.CanActivate {
		return sdk.Result{}, fmt.Errorf("Postmark won't reactivate the address of bounce %s (%s); spam complaints and some hard bounces can only be reactivated by Postmark support", id, b.Type)
	}
	if call.DryRun {
		before, _ := json.Marshal(b.out())
		return sdk.Result{Plan: &sdk.Plan{
			Summary: fmt.Sprintf("Reactivate %s: Postmark will send to it again, though it bounced (%s) on %s", b.Email, b.Type, b.BouncedAt),
			Changes: []sdk.Change{{Target: b.Email, Op: "reactivate", Before: before, After: json.RawMessage(`{"inactive":false}`)}},
		}}, nil
	}
	var r struct {
		Message string `json:"Message"`
		Bounce  bounce `json:"Bounce"`
	}
	if err := c.do(ctx, http.MethodPut, "/bounces/"+id+"/activate", nil, map[string]any{}, &r); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"bounce": b.ID, "email": b.Email, "reactivated": !r.Bounce.Inactive, "message": clip(r.Message, 200)})
}
