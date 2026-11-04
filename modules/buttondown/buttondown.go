// Package buttondown works with a Buttondown newsletter through its API with
// an API key: subscriber counts, emails with their status and analytics,
// creating a draft email, and sending one.
//
// Sending an email delivers it to the newsletter's subscribers and can't be
// taken back, so it is destructive and its preview names the newsletter,
// who gets it, how many they are and the subject. Subscribers' addresses
// are never read: only counts are. Drafts are always created with the
// status set to draft, since Buttondown sends an email created without one.
package buttondown

import (
	"bytes"
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

// Config is one Buttondown newsletter.
type Config struct {
	Key string `json:"key"` // secret:// API key
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.buttondown.com/v1 (tests).
	Base string
}

// New returns the Buttondown module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.buttondown.com/v1"

var (
	keyRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{16,100}$`)
	uuidRe   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	scriptRe = regexp.MustCompile(`(?i)<\s*/?\s*script\b`)
)

var subTypes = map[string]bool{"regular": true, "premium": true, "gifted": true, "trialed": true, "unactivated": true, "unsubscribed": true, "churning": true, "past_due": true}

var emailStatuses = map[string]bool{"draft": true, "scheduled": true, "about_to_send": true, "in_flight": true, "sent": true, "imported": true, "errored": true}

// reachTypes are the subscriber types an email of each type goes to.
var reachTypes = map[string][]string{
	"public":  {"regular", "premium", "gifted", "trialed"},
	"premium": {"premium", "gifted", "trialed"},
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	email := `"email":{"type":"string","description":"Email id (see emails)"}`
	return sdk.Manifest{
		ID: "buttondown", Name: "Buttondown", Version: "0.1.0", Category: "Communication", Icon: "mail",
		Description: "Buttondown newsletters: subscriber counts, emails with status and analytics, create drafts and send them.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["key"],"properties":{
			"key":{"type":"string","x-secret":true,"description":"Your Buttondown API key (Settings, API)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "subscribers_count", Title: "Subscriber count", Description: "How many subscribers there are of one type (regular by default). Counts only, no addresses.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"type":{"type":"string","enum":["regular","premium","gifted","trialed","unactivated","unsubscribed","churning","past_due"],"default":"regular"}}}`)},
			{Name: "emails", Title: "Emails", Description: "Emails, newest first: subject, status, type (public or premium), publish date, and recipients, opens and clicks once sent.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["draft","scheduled","about_to_send","in_flight","sent","imported","errored"]},"limit":{"type":"integer","default":20,"minimum":1,"maximum":100}}}`)},
			{Name: "create_draft", Title: "Create a draft", Description: "Creates a draft email from Markdown (HTML inside it is kept); nothing is sent. The preview shows the body in full. Undo deletes the draft.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["subject","body"],"properties":{"subject":{"type":"string","maxLength":200},"body":{"type":"string","maxLength":200000,"description":"Markdown, as Buttondown renders it; script tags are refused"},"description":{"type":"string","maxLength":300,"description":"Short summary for the archive and previews"}}}`)},
			{Name: "delete_draft", Title: "Delete a draft", Description: "Deletes a draft email for good. Only drafts; the preview names it.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["email"],"properties":{` + email + `}}`)},
			{Name: "send_email", Title: "Send an email", Description: "Sends a draft email to its subscribers now (public emails to every paying and free subscriber, premium ones to paying subscribers). Can't be taken back. The preview names the newsletter, the recipients and their count, and the subject.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["email"],"properties":{` + email + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.Key, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	ref := c.Key
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		k = strings.TrimSpace(k)
		if !keyRe.MatchString(k) {
			return errors.New("the stored key doesn't look like a Buttondown API key")
		}
		r.Header.Set("Authorization", "Token "+k)
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Buttondown refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("Buttondown refused: %v", err)
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("Buttondown has no such email")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Buttondown's rate limit was hit; try again in a minute")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

// plain encodes a preview value without escaping <, > and &, so authored
// content reads as written.
func plain(v any) json.RawMessage {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimSpace(b.Bytes())
}

type email struct {
	ID          string `json:"id"`
	Subject     string `json:"subject"`
	Status      string `json:"status"`
	Type        string `json:"email_type"`
	Created     string `json:"creation_date"`
	PublishDate string `json:"publish_date"`
	URL         string `json:"absolute_url"`
	Filters     *struct {
		Filters []json.RawMessage `json:"filters"`
		Groups  []json.RawMessage `json:"groups"`
	} `json:"filters"`
	Analytics *struct {
		Recipients int `json:"recipients"`
		Deliveries int `json:"deliveries"`
		Opens      int `json:"opens"`
		Clicks     int `json:"clicks"`
		Unsubs     int `json:"unsubscriptions"`
	} `json:"analytics"`
}

func (e email) brief() map[string]any {
	out := map[string]any{"email": e.ID, "subject": clip(e.Subject, 200), "status": e.Status, "type": e.Type, "created": e.Created}
	if e.PublishDate != "" {
		out["publishDate"] = e.PublishDate
	}
	if e.Status == "sent" && e.Type == "public" && e.URL != "" {
		out["url"] = e.URL
	}
	if a := e.Analytics; a != nil && e.Status == "sent" {
		out["recipients"], out["deliveries"], out["opens"], out["clicks"], out["unsubscribes"] = a.Recipients, a.Deliveries, a.Opens, a.Clicks, a.Unsubs
	}
	return out
}

func (c *conn) email(ctx context.Context, id string) (email, error) {
	id = strings.TrimSpace(id)
	if !uuidRe.MatchString(id) {
		return email{}, errors.New("the email is its id (see emails)")
	}
	var e email
	if err := c.do(ctx, http.MethodGet, "/emails/"+url.PathEscape(id), nil, nil, &e); err != nil {
		return email{}, err
	}
	if e.ID != id {
		return email{}, errors.New("unexpected answer from Buttondown")
	}
	return e, nil
}

func (c *conn) count(ctx context.Context, typ string) (int, error) {
	var res struct {
		Count *int `json:"count"`
	}
	if err := c.do(ctx, http.MethodGet, "/subscribers", url.Values{"type": {typ}}, nil, &res); err != nil {
		return 0, err
	}
	if res.Count == nil {
		return 0, errors.New("Buttondown didn't return a count")
	}
	return *res.Count, nil
}

func (c *conn) newsletter(ctx context.Context) string {
	var res struct {
		Results []struct {
			Name     string `json:"name"`
			Username string `json:"username"`
		} `json:"results"`
	}
	if c.do(ctx, http.MethodGet, "/newsletters", nil, nil, &res) == nil && len(res.Results) > 0 {
		if n := clip(res.Results[0].Name, 100); n != "" {
			return n
		}
		return clip(res.Results[0].Username, 100)
	}
	return ""
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	n, err := c.count(ctx, "regular")
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("%d subscribers", n)
	if name := c.newsletter(ctx); name != "" {
		msg = name + ": " + msg
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Email       string `json:"email"`
		Type        string `json:"type"`
		Status      string `json:"status"`
		Limit       int    `json:"limit"`
		Subject     string `json:"subject"`
		Body        string `json:"body"`
		Description string `json:"description"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "subscribers_count":
		t := p.Type
		if t == "" {
			t = "regular"
		}
		if !subTypes[t] {
			return sdk.Result{}, errors.New("type is regular, premium, gifted, trialed, unactivated, unsubscribed, churning or past_due")
		}
		n, err := c.count(ctx, t)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"type": t, "subscribers": n})

	case "emails":
		n := p.Limit
		if n <= 0 {
			n = 20
		}
		if n > 100 {
			n = 100
		}
		q := url.Values{"ordering": {"-creation_date"}}
		if p.Status != "" {
			if !emailStatuses[p.Status] {
				return sdk.Result{}, errors.New("status is draft, scheduled, about_to_send, in_flight, sent, imported or errored")
			}
			q.Set("status", p.Status)
		}
		var res struct {
			Results []email `json:"results"`
			Count   int     `json:"count"`
		}
		if err := c.do(ctx, http.MethodGet, "/emails", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for i, e := range res.Results {
			if i >= n {
				break
			}
			list = append(list, e.brief())
		}
		return sdk.JSON(map[string]any{"total": res.Count, "emails": list})

	case "create_draft":
		subject, desc := strings.TrimSpace(p.Subject), strings.TrimSpace(p.Description)
		switch {
		case subject == "" || len([]rune(subject)) > 200 || strings.ContainsAny(subject, "\r\n\x00"):
			return sdk.Result{}, errors.New("the subject is up to 200 characters on one line")
		case strings.TrimSpace(p.Body) == "" || len(p.Body) > 200000:
			return sdk.Result{}, errors.New("the body is the email's Markdown, up to 200000 characters")
		case len([]rune(desc)) > 300 || strings.ContainsAny(desc, "\x00"):
			return sdk.Result{}, errors.New("the description is up to 300 characters")
		case scriptRe.MatchString(p.Body):
			return sdk.Result{}, errors.New("the body has a script tag; email clients don't run scripts, so remove it")
		}
		if call.DryRun {
			// The body is authored, not personal data: shown in full.
			after := plain(map[string]any{"subject": subject, "description": desc, "status": "draft", "format": "markdown", "body": p.Body})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create the draft %q; nothing is sent", clip(subject, 80)),
				Changes: []sdk.Change{{Target: "email " + clip(subject, 80), Op: "create", After: after}}}}, nil
		}
		body := map[string]any{"subject": subject, "body": p.Body, "status": "draft"}
		if desc != "" {
			body["description"] = desc
		}
		var e email
		if err := c.do(ctx, http.MethodPost, "/emails", nil, body, &e); err != nil {
			return sdk.Result{}, err
		}
		if e.Status != "draft" || !uuidRe.MatchString(e.ID) {
			return sdk.Result{}, fmt.Errorf("Buttondown didn't keep the email as a draft (status %q); check it in Buttondown", clip(e.Status, 40))
		}
		r, err := sdk.JSON(e.brief())
		r.Undo = sdk.UndoWith("delete_draft", map[string]string{"email": e.ID}, "Delete the draft")
		return r, err

	case "delete_draft":
		e, err := c.email(ctx, p.Email)
		if err != nil {
			return sdk.Result{}, err
		}
		if e.Status != "draft" {
			return sdk.Result{}, fmt.Errorf("the email is %s; only drafts are deleted here", e.Status)
		}
		if call.DryRun {
			before, _ := json.Marshal(e.brief())
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete the draft %q for good", clip(e.Subject, 80)),
				Changes: []sdk.Change{{Target: "email " + e.ID, Op: "delete", Before: before}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/emails/"+url.PathEscape(e.ID), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": e.ID})

	case "send_email":
		e, err := c.email(ctx, p.Email)
		if err != nil {
			return sdk.Result{}, err
		}
		switch e.Status {
		case "sent", "about_to_send", "in_flight":
			return sdk.JSON(map[string]any{"email": e.ID, "status": e.Status, "note": "nothing to change: it has already gone out"})
		case "scheduled":
			return sdk.Result{}, fmt.Errorf("the email is scheduled for %s; change its schedule in Buttondown to send it now", e.PublishDate)
		case "draft":
		default:
			return sdk.Result{}, fmt.Errorf("the email is %s; only drafts can be sent", e.Status)
		}
		types, ok := reachTypes[e.Type]
		if !ok || (e.Filters != nil && (len(e.Filters.Filters) > 0 || len(e.Filters.Groups) > 0)) {
			return sdk.Result{}, errors.New("this email goes to a filtered or special set of subscribers that Conduit can't count; send it from Buttondown")
		}
		if call.DryRun {
			total := 0
			parts := []string{}
			for _, t := range types {
				n, err := c.count(ctx, t)
				if err != nil {
					return sdk.Result{}, err
				}
				total += n
				parts = append(parts, t+" "+strconv.Itoa(n))
			}
			nl := c.newsletter(ctx)
			if nl == "" {
				nl = "your newsletter"
			}
			after := plain(map[string]any{"newsletter": nl, "type": e.Type, "subscribers": total, "subject": clip(e.Subject, 200)})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Email %q from %s to %d subscribers now (%s email: %s). Sent emails can't be recalled.", clip(e.Subject, 100), nl, total, e.Type, strings.Join(parts, ", ")),
				Changes: []sdk.Change{{Target: "newsletter " + nl, Op: "email", After: after}}}}, nil
		}
		var after email
		if err := c.do(ctx, http.MethodPatch, "/emails/"+url.PathEscape(e.ID), nil, map[string]string{"status": "about_to_send"}, &after); err != nil {
			return sdk.Result{}, err
		}
		st := after.Status
		if st == "" {
			st = "about_to_send"
		}
		return sdk.JSON(map[string]any{"email": e.ID, "status": st})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
