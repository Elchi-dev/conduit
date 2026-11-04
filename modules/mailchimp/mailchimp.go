// Package mailchimp works with a Mailchimp account through the Marketing API
// with an API key: audiences with member counts, campaigns and their
// reports, creating a draft campaign, sending a test of it to an allowed
// address, and scheduling, unscheduling or sending a campaign.
//
// The key ends in its data center ("…-us21"), which names the API host. The
// suffix is read from the key and checked (letters then digits) before the
// host is built, so a crafted key can't point the request, and the key, at
// another host. Sending or scheduling a campaign emails a whole audience and
// can't be taken back, so both are destructive and their previews name the
// audience, its recipient count, the subject and the sender. Subscriber
// addresses are never read: audiences report counts only.
package mailchimp

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

// Config is one Mailchimp account.
type Config struct {
	Key string `json:"key"` // secret:// API key, like 0123…cdef-us21
	// TestRecipients are the addresses send_test may reach besides the
	// account owner's.
	TestRecipients []string `json:"testRecipients"`
}

type conn struct {
	h     sdk.Host
	ref   string
	base  string // set in tests; otherwise built from the key's data center
	http  *http.Client
	allow []string // lower-case addresses
	now   func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://<dc>.api.mailchimp.com/3.0 (tests). The key's
	// data center is still checked.
	Base string
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Mailchimp module.
func New() *Module { return &Module{} }

var (
	keyRe   = regexp.MustCompile(`^([A-Za-z0-9]{16,64})-([A-Za-z0-9]{1,16})$`)
	dcRe    = regexp.MustCompile(`^[a-z]{1,8}[0-9]{1,4}$`)
	idRe    = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)
	emailRe = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+=?^_{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$`)
	// scriptRe finds script elements, remote or inline, in authored HTML.
	scriptRe = regexp.MustCompile(`(?i)<\s*/?\s*script\b`)
)

var statuses = map[string]bool{"save": true, "paused": true, "schedule": true, "sending": true, "sent": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	campaign := `"campaign":{"type":"string","description":"Campaign id (see campaigns)"}`
	return sdk.Manifest{
		ID: "mailchimp", Name: "Mailchimp", Version: "0.1.0", Category: "Communication", Icon: "mail",
		Description: "Mailchimp: audiences with member counts, campaigns and reports, create draft campaigns, send tests, schedule, unschedule and send campaigns.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["key"],"properties":{
			"key":{"type":"string","x-secret":true,"description":"A Mailchimp API key (Profile, Extras, API keys), like 0123…cdef-us21; it ends in the account's data center"},
			"testRecipients":{"type":"array","maxItems":10,"items":{"type":"string"},"description":"Addresses send_test may send to, besides the account owner's own address; anything else is refused"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "audiences", Title: "Audiences", Description: "Audiences (lists) with subscribed, unsubscribed and cleaned counts and their default sender. Counts only, no addresses.", Risk: sdk.RiskRead},
			{Name: "campaigns", Title: "Campaigns", Description: "Campaigns, newest first: title, subject, status, audience, recipient count, send time, open and click rates.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["save","paused","schedule","sending","sent"],"description":"save is a draft, schedule a scheduled campaign"},"limit":{"type":"integer","default":20,"minimum":1,"maximum":100}}}`)},
			{Name: "campaign_report", Title: "Campaign report", Description: "A sent campaign's report: emails sent, opens, clicks, bounces, unsubscribes and abuse reports.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["campaign"],"properties":{` + campaign + `}}`)},
			{Name: "create_draft", Title: "Create a draft campaign", Description: "Creates a draft campaign for one audience from plain text or HTML; nothing is sent. The preview shows the content in full. Undo deletes the draft.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["audience","subject"],"properties":{"audience":{"type":"string","description":"Audience id (see audiences)"},"subject":{"type":"string","maxLength":150},"title":{"type":"string","maxLength":100,"description":"Internal name (default: the subject)"},"previewText":{"type":"string","maxLength":150},"fromName":{"type":"string","maxLength":100,"description":"Default: the audience's sender name"},"replyTo":{"type":"string","description":"Default: the audience's sender address"},"text":{"type":"string","maxLength":200000,"description":"Plain-text content (a plain-text campaign); give text or html"},"html":{"type":"string","maxLength":500000,"description":"HTML content; script tags are refused"}}}`)},
			{Name: "delete_draft", Title: "Delete a draft", Description: "Deletes a draft campaign for good. Only drafts; the preview names it.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["campaign"],"properties":{` + campaign + `}}`)},
			{Name: "send_test", Title: "Send a test email", Description: "Sends a test of a campaign to one address: the account owner's, or one of the test recipients in this instance's settings. Any other address is refused.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["campaign"],"properties":{` + campaign + `,"to":{"type":"string","description":"The address (default: the only test recipient, or the account owner)"}}}`)},
			{Name: "schedule_campaign", Title: "Schedule a campaign", Description: "Schedules a draft campaign to email its audience at a time (on a quarter hour). The preview names the audience, its recipient count, the subject and the sender. Undo unschedules it while it hasn't gone out.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["campaign","at"],"properties":{` + campaign + `,"at":{"type":"string","description":"When, like 2026-11-10T09:15:00Z (minutes 00, 15, 30 or 45)"}}}`)},
			{Name: "unschedule_campaign", Title: "Unschedule a campaign", Description: "Turns a scheduled campaign back into a draft; nothing is sent. Undo schedules it again for the same time.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["campaign"],"properties":{` + campaign + `}}`)},
			{Name: "send_campaign", Title: "Send a campaign", Description: "Sends a draft campaign to its audience now. Can't be taken back. The preview names the audience, its recipient count, the subject and the sender.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["campaign"],"properties":{` + campaign + `}}`)},
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
	if len(c.TestRecipients) > 10 {
		return errors.New("list at most 10 test recipients")
	}
	allow := []string{}
	for _, r := range c.TestRecipients {
		r = strings.ToLower(strings.TrimSpace(r))
		if len(r) > 254 || !emailRe.MatchString(r) {
			return fmt.Errorf("test recipient %q isn't a plain email address", clip(r, 80))
		}
		allow = append(allow, r)
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	now := m.Now
	if now == nil {
		now = time.Now
	}
	m.set.Put(id, &conn{h: h, ref: c.Key, base: strings.TrimRight(m.Base, "/"), http: rest.SameHostOnly(client), allow: allow, now: now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// api reads the key, checks its data center and returns a client for its
// host. Nothing is sent when the key or its suffix doesn't look right.
func (c *conn) api(ctx context.Context) (*rest.Client, error) {
	k, err := c.h.Secret(ctx, c.ref)
	if err != nil {
		return nil, err
	}
	k = strings.TrimSpace(k)
	mm := keyRe.FindStringSubmatch(k)
	if mm == nil {
		return nil, errors.New("the stored key doesn't look like a Mailchimp API key (like 0123…cdef-us21)")
	}
	dc := mm[2]
	if !dcRe.MatchString(dc) {
		return nil, errors.New("the API key's data center suffix isn't valid (it's like -us21)")
	}
	base := "https://" + dc + ".api.mailchimp.com/3.0"
	if c.base != "" {
		base = c.base
	}
	api := rest.New(base, func(_ context.Context, r *http.Request) error {
		r.SetBasicAuth("conduit", k)
		return nil
	})
	api.HTTP = c.http
	return api, nil
}

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Mailchimp refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("Mailchimp refused: %v", err)
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("Mailchimp has no such campaign or audience")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Mailchimp's rate limit was hit; try again in a minute")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	api, err := c.api(ctx)
	if err != nil {
		return err
	}
	_, err = api.Do(ctx, method, path, q, body, out)
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
// HTML and "Name <address>" read as written.
func plain(v any) json.RawMessage {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimSpace(b.Bytes())
}

func oneLine(s string, n int) bool {
	return s != "" && len([]rune(s)) <= n && !strings.ContainsAny(s, "\r\n\x00")
}

type audience struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Created  string `json:"date_created"`
	Defaults struct {
		FromName  string `json:"from_name"`
		FromEmail string `json:"from_email"`
	} `json:"campaign_defaults"`
	Stats struct {
		Members      int `json:"member_count"`
		Unsubscribed int `json:"unsubscribe_count"`
		Cleaned      int `json:"cleaned_count"`
		Campaigns    int `json:"campaign_count"`
	} `json:"stats"`
}

type campaign struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	Created    string `json:"create_time"`
	SendTime   string `json:"send_time"`
	EmailsSent int    `json:"emails_sent"`
	Recipients struct {
		ListID      string `json:"list_id"`
		ListName    string `json:"list_name"`
		SegmentText string `json:"segment_text"`
		Count       int    `json:"recipient_count"`
	} `json:"recipients"`
	Settings struct {
		Subject string `json:"subject_line"`
		Preview string `json:"preview_text"`
		Title   string `json:"title"`
		From    string `json:"from_name"`
		ReplyTo string `json:"reply_to"`
	} `json:"settings"`
	Summary *struct {
		Opens     int     `json:"opens"`
		OpenRate  float64 `json:"open_rate"`
		Clicks    int     `json:"clicks"`
		ClickRate float64 `json:"click_rate"`
	} `json:"report_summary"`
}

func (cp campaign) brief() map[string]any {
	out := map[string]any{"campaign": cp.ID, "title": clip(cp.Settings.Title, 100), "subject": clip(cp.Settings.Subject, 150), "status": cp.Status, "type": cp.Type,
		"audience": clip(cp.Recipients.ListName, 100), "recipients": cp.Recipients.Count, "created": cp.Created}
	if cp.SendTime != "" {
		out["sendTime"] = cp.SendTime
	}
	if cp.EmailsSent > 0 {
		out["emailsSent"] = cp.EmailsSent
	}
	if cp.Summary != nil {
		out["openRate"], out["clickRate"] = cp.Summary.OpenRate, cp.Summary.ClickRate
	}
	return out
}

func (cp campaign) from() string {
	return fmt.Sprintf("%s <%s>", clip(cp.Settings.From, 100), clip(cp.Settings.ReplyTo, 254))
}

func (c *conn) campaign(ctx context.Context, id string) (campaign, error) {
	id = strings.TrimSpace(id)
	if !idRe.MatchString(id) {
		return campaign{}, errors.New("the campaign is its id (see campaigns)")
	}
	var cp campaign
	if err := c.do(ctx, http.MethodGet, "/campaigns/"+url.PathEscape(id), nil, nil, &cp); err != nil {
		return campaign{}, err
	}
	if cp.ID != id {
		return campaign{}, errors.New("unexpected answer from Mailchimp")
	}
	return cp, nil
}

func (c *conn) audience(ctx context.Context, id string) (audience, error) {
	var a audience
	if err := c.do(ctx, http.MethodGet, "/lists/"+url.PathEscape(id), nil, nil, &a); err != nil {
		return audience{}, err
	}
	if a.ID != id {
		return audience{}, errors.New("unexpected answer from Mailchimp")
	}
	return a, nil
}

// reach is how many the campaign would email: Mailchimp's recipient count,
// or, for a whole audience it hasn't counted yet, the audience's subscribers.
func (c *conn) reach(ctx context.Context, cp campaign) (int, error) {
	if cp.Recipients.Count > 0 || cp.Recipients.SegmentText != "" {
		return cp.Recipients.Count, nil
	}
	if !idRe.MatchString(cp.Recipients.ListID) {
		return 0, errors.New("the campaign has no audience yet")
	}
	a, err := c.audience(ctx, cp.Recipients.ListID)
	return a.Stats.Members, err
}

// mailPlan is the preview of emailing a campaign's audience.
func (c *conn) mailPlan(ctx context.Context, cp campaign, verb, when string) (sdk.Result, error) {
	n, err := c.reach(ctx, cp)
	if err != nil {
		return sdk.Result{}, err
	}
	aud := fmt.Sprintf("audience %q", clip(cp.Recipients.ListName, 100))
	if cp.Recipients.SegmentText != "" {
		aud += " (a segment)"
	}
	after := plain(map[string]any{"audience": clip(cp.Recipients.ListName, 100), "recipients": n, "subject": clip(cp.Settings.Subject, 150), "from": cp.from(), "when": when})
	return sdk.Result{Plan: &sdk.Plan{
		Summary: fmt.Sprintf("%s %q from %s to %d subscribers of %s %s. Sent emails can't be recalled.", verb, clip(cp.Settings.Subject, 100), cp.from(), n, aud, when),
		Changes: []sdk.Change{{Target: aud, Op: "email", After: after}}}}, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var acct struct {
		Name        string `json:"account_name"`
		Subscribers int    `json:"total_subscribers"`
	}
	if err := c.do(ctx, http.MethodGet, "/", url.Values{"fields": {"account_name,total_subscribers"}}, nil, &acct); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%s: %d subscribers", clip(acct.Name, 80), acct.Subscribers)}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Campaign    string `json:"campaign"`
		Audience    string `json:"audience"`
		Status      string `json:"status"`
		Limit       int    `json:"limit"`
		Subject     string `json:"subject"`
		Title       string `json:"title"`
		PreviewText string `json:"previewText"`
		FromName    string `json:"fromName"`
		ReplyTo     string `json:"replyTo"`
		Text        string `json:"text"`
		HTML        string `json:"html"`
		To          string `json:"to"`
		At          string `json:"at"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "audiences":
		var res struct {
			Lists []audience `json:"lists"`
			Total int        `json:"total_items"`
		}
		q := url.Values{"count": {"1000"}, "fields": {"lists.id,lists.name,lists.date_created,lists.campaign_defaults.from_name,lists.campaign_defaults.from_email,lists.stats.member_count,lists.stats.unsubscribe_count,lists.stats.cleaned_count,lists.stats.campaign_count,total_items"}}
		if err := c.do(ctx, http.MethodGet, "/lists", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, a := range res.Lists {
			out = append(out, map[string]any{"audience": a.ID, "name": clip(a.Name, 100), "subscribed": a.Stats.Members, "unsubscribed": a.Stats.Unsubscribed, "cleaned": a.Stats.Cleaned,
				"campaigns": a.Stats.Campaigns, "fromName": clip(a.Defaults.FromName, 100), "fromEmail": clip(a.Defaults.FromEmail, 254), "created": a.Created})
		}
		return sdk.JSON(out)

	case "campaigns":
		n := p.Limit
		if n <= 0 {
			n = 20
		}
		if n > 100 {
			n = 100
		}
		q := url.Values{"count": {strconv.Itoa(n)}, "sort_field": {"create_time"}, "sort_dir": {"DESC"}}
		if p.Status != "" {
			if !statuses[p.Status] {
				return sdk.Result{}, errors.New("status is save (draft), paused, schedule, sending or sent")
			}
			q.Set("status", p.Status)
		}
		var res struct {
			Campaigns []campaign `json:"campaigns"`
			Total     int        `json:"total_items"`
		}
		if err := c.do(ctx, http.MethodGet, "/campaigns", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, cp := range res.Campaigns {
			list = append(list, cp.brief())
		}
		return sdk.JSON(map[string]any{"total": res.Total, "campaigns": list})

	case "campaign_report":
		id := strings.TrimSpace(p.Campaign)
		if !idRe.MatchString(id) {
			return sdk.Result{}, errors.New("the campaign is its id (see campaigns)")
		}
		var r struct {
			ID           string `json:"id"`
			Subject      string `json:"subject_line"`
			ListName     string `json:"list_name"`
			EmailsSent   int    `json:"emails_sent"`
			AbuseReports int    `json:"abuse_reports"`
			Unsubscribed int    `json:"unsubscribed"`
			SendTime     string `json:"send_time"`
			Bounces      struct {
				Hard int `json:"hard_bounces"`
				Soft int `json:"soft_bounces"`
			} `json:"bounces"`
			Opens struct {
				Total  int     `json:"opens_total"`
				Unique int     `json:"unique_opens"`
				Rate   float64 `json:"open_rate"`
			} `json:"opens"`
			Clicks struct {
				Total  int     `json:"clicks_total"`
				Unique int     `json:"unique_subscriber_clicks"`
				Rate   float64 `json:"click_rate"`
			} `json:"clicks"`
		}
		if err := c.do(ctx, http.MethodGet, "/reports/"+url.PathEscape(id), nil, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		if r.ID != id {
			return sdk.Result{}, errors.New("unexpected answer from Mailchimp")
		}
		return sdk.JSON(map[string]any{"campaign": r.ID, "subject": clip(r.Subject, 150), "audience": clip(r.ListName, 100), "sendTime": r.SendTime, "emailsSent": r.EmailsSent,
			"opens": r.Opens.Total, "uniqueOpens": r.Opens.Unique, "openRate": r.Opens.Rate, "clicks": r.Clicks.Total, "uniqueClicks": r.Clicks.Unique, "clickRate": r.Clicks.Rate,
			"hardBounces": r.Bounces.Hard, "softBounces": r.Bounces.Soft, "unsubscribed": r.Unsubscribed, "abuseReports": r.AbuseReports})

	case "create_draft":
		return c.createDraft(ctx, call, p.Audience, p.Subject, p.Title, p.PreviewText, p.FromName, p.ReplyTo, p.Text, p.HTML)

	case "delete_draft":
		cp, err := c.campaign(ctx, p.Campaign)
		if err != nil {
			return sdk.Result{}, err
		}
		if cp.Status != "save" {
			return sdk.Result{}, fmt.Errorf("the campaign is %s; only drafts are deleted here", cp.Status)
		}
		if call.DryRun {
			before, _ := json.Marshal(cp.brief())
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete the draft %q (%q, audience %q) for good", clip(cp.Settings.Title, 80), clip(cp.Settings.Subject, 80), clip(cp.Recipients.ListName, 80)),
				Changes: []sdk.Change{{Target: "campaign " + cp.ID, Op: "delete", Before: before}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/campaigns/"+url.PathEscape(cp.ID), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": cp.ID})

	case "send_test":
		to := strings.ToLower(strings.TrimSpace(p.To))
		if to != "" && (len(to) > 254 || !emailRe.MatchString(to)) {
			return sdk.Result{}, errors.New("to is one plain email address")
		}
		if !idRe.MatchString(strings.TrimSpace(p.Campaign)) {
			return sdk.Result{}, errors.New("the campaign is its id (see campaigns)")
		}
		to, err := c.testRecipient(ctx, to)
		if err != nil {
			return sdk.Result{}, err
		}
		cp, err := c.campaign(ctx, p.Campaign)
		if err != nil {
			return sdk.Result{}, err
		}
		kind := "html"
		if cp.Type == "plaintext" {
			kind = "plaintext"
		}
		if call.DryRun {
			after := plain(map[string]any{"to": to, "subject": clip(cp.Settings.Subject, 150), "from": cp.from()})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Send a test of %q to %s; nobody else gets it", clip(cp.Settings.Subject, 80), to),
				Changes: []sdk.Change{{Target: to, Op: "email", After: after}}}}, nil
		}
		if err := c.do(ctx, http.MethodPost, "/campaigns/"+url.PathEscape(cp.ID)+"/actions/test", nil, map[string]any{"test_emails": []string{to}, "send_type": kind}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"campaign": cp.ID, "sentTo": to})

	case "schedule_campaign":
		at, err := c.scheduleTime(p.At)
		if err != nil {
			return sdk.Result{}, err
		}
		cp, err := c.campaign(ctx, p.Campaign)
		if err != nil {
			return sdk.Result{}, err
		}
		switch cp.Status {
		case "schedule":
			if t, err := time.Parse(time.RFC3339, cp.SendTime); err == nil && t.Equal(at) {
				return sdk.JSON(map[string]any{"campaign": cp.ID, "status": cp.Status, "sendTime": cp.SendTime, "note": "nothing to change"})
			}
			return sdk.Result{}, fmt.Errorf("the campaign is already scheduled for %s; unschedule it first", cp.SendTime)
		case "sent", "sending":
			return sdk.JSON(map[string]any{"campaign": cp.ID, "status": cp.Status, "note": "nothing to change: it has already gone out"})
		case "save":
		default:
			return sdk.Result{}, fmt.Errorf("the campaign is %s; only drafts can be scheduled", cp.Status)
		}
		when := at.Format(time.RFC3339)
		if call.DryRun {
			return c.mailPlan(ctx, cp, "Schedule emailing", "at "+when)
		}
		if err := c.do(ctx, http.MethodPost, "/campaigns/"+url.PathEscape(cp.ID)+"/actions/schedule", nil, map[string]string{"schedule_time": when}, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"campaign": cp.ID, "status": "schedule", "sendTime": when})
		res.Undo = sdk.UndoWith("unschedule_campaign", map[string]string{"campaign": cp.ID}, "Unschedule the campaign")
		return res, err

	case "unschedule_campaign":
		cp, err := c.campaign(ctx, p.Campaign)
		if err != nil {
			return sdk.Result{}, err
		}
		switch cp.Status {
		case "save":
			return sdk.JSON(map[string]any{"campaign": cp.ID, "status": cp.Status, "note": "nothing to change: it isn't scheduled"})
		case "schedule":
		default:
			return sdk.Result{}, fmt.Errorf("the campaign is %s; only scheduled campaigns can be unscheduled", cp.Status)
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Unschedule %q (was due %s); it becomes a draft and nothing is sent", clip(cp.Settings.Subject, 80), cp.SendTime),
				Changes: []sdk.Change{{Target: "campaign " + cp.ID, Op: "update", Before: json.RawMessage(strconv.Quote(cp.SendTime)), After: json.RawMessage(`"draft"`)}}}}, nil
		}
		if err := c.do(ctx, http.MethodPost, "/campaigns/"+url.PathEscape(cp.ID)+"/actions/unschedule", nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"campaign": cp.ID, "status": "save"})
		if t, perr := time.Parse(time.RFC3339, cp.SendTime); perr == nil {
			at := t.UTC().Format(time.RFC3339)
			res.Undo = sdk.UndoWith("schedule_campaign", map[string]string{"campaign": cp.ID, "at": at}, "Schedule the campaign again for "+at)
		}
		return res, err

	case "send_campaign":
		cp, err := c.campaign(ctx, p.Campaign)
		if err != nil {
			return sdk.Result{}, err
		}
		switch cp.Status {
		case "sent", "sending":
			return sdk.JSON(map[string]any{"campaign": cp.ID, "status": cp.Status, "note": "nothing to change: it has already gone out"})
		case "schedule":
			return sdk.Result{}, fmt.Errorf("the campaign is scheduled for %s; unschedule it first to send it now", cp.SendTime)
		case "save":
		default:
			return sdk.Result{}, fmt.Errorf("the campaign is %s; only drafts can be sent", cp.Status)
		}
		if call.DryRun {
			return c.mailPlan(ctx, cp, "Email", "now")
		}
		if err := c.do(ctx, http.MethodPost, "/campaigns/"+url.PathEscape(cp.ID)+"/actions/send", nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"campaign": cp.ID, "status": "sending"})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// scheduleTime checks a send time: RFC 3339, in the future, on a quarter
// hour (Mailchimp's rule).
func (c *conn) scheduleTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, errors.New("at is a time like 2026-11-10T09:15:00Z")
	}
	t = t.UTC()
	if t.Minute()%15 != 0 || t.Second() != 0 || t.Nanosecond() != 0 {
		return time.Time{}, errors.New("Mailchimp schedules on the quarter hour: minutes 00, 15, 30 or 45")
	}
	if !t.After(c.now().Add(time.Minute)) {
		return time.Time{}, errors.New("at must be in the future")
	}
	return t, nil
}

// testRecipient picks the address for a test email: one of the configured
// test recipients or the account owner's address, and nothing else.
func (c *conn) testRecipient(ctx context.Context, to string) (string, error) {
	for _, a := range c.allow {
		if a == to {
			return to, nil
		}
	}
	if to == "" && len(c.allow) == 1 {
		return c.allow[0], nil
	}
	var acct struct {
		Email string `json:"email"`
	}
	if err := c.do(ctx, http.MethodGet, "/", url.Values{"fields": {"email"}}, nil, &acct); err != nil {
		return "", err
	}
	owner := strings.ToLower(strings.TrimSpace(acct.Email))
	if !emailRe.MatchString(owner) {
		owner = ""
	}
	switch {
	case to == "" && len(c.allow) == 0 && owner != "":
		return owner, nil
	case to == "":
		return "", errors.New("give to: the account owner's address or one of the test recipients")
	case to == owner:
		return to, nil
	}
	return "", errors.New("test emails go only to the account owner's address or the test recipients in this instance's settings")
}

func (c *conn) createDraft(ctx context.Context, call sdk.Call, aud, subject, title, preview, fromName, replyTo, text, html string) (sdk.Result, error) {
	aud, subject, title = strings.TrimSpace(aud), strings.TrimSpace(subject), strings.TrimSpace(title)
	preview, fromName, replyTo = strings.TrimSpace(preview), strings.TrimSpace(fromName), strings.TrimSpace(replyTo)
	if title == "" {
		title = subject
	}
	switch {
	case !idRe.MatchString(aud):
		return sdk.Result{}, errors.New("the audience is its id (see audiences)")
	case !oneLine(subject, 150):
		return sdk.Result{}, errors.New("the subject is up to 150 characters on one line")
	case !oneLine(title, 100):
		return sdk.Result{}, errors.New("the title is up to 100 characters on one line")
	case preview != "" && !oneLine(preview, 150):
		return sdk.Result{}, errors.New("the previewText is up to 150 characters on one line")
	case fromName != "" && !oneLine(fromName, 100):
		return sdk.Result{}, errors.New("the fromName is up to 100 characters on one line")
	case replyTo != "" && (len(replyTo) > 254 || !emailRe.MatchString(replyTo)):
		return sdk.Result{}, errors.New("replyTo is one plain email address")
	case (strings.TrimSpace(text) == "") == (strings.TrimSpace(html) == ""):
		return sdk.Result{}, errors.New("give the content as text (plain text) or as html, one of them")
	case len(text) > 200000 || len(html) > 500000:
		return sdk.Result{}, errors.New("the content is too long")
	case scriptRe.MatchString(html):
		return sdk.Result{}, errors.New("the html has a script tag; email clients don't run scripts, so remove it")
	}
	a, err := c.audience(ctx, aud)
	if err != nil {
		return sdk.Result{}, err
	}
	if fromName == "" {
		fromName = a.Defaults.FromName
	}
	if replyTo == "" {
		replyTo = a.Defaults.FromEmail
	}
	if fromName == "" || replyTo == "" {
		return sdk.Result{}, errors.New("the audience has no default sender; give fromName and replyTo")
	}
	kind, format, content := "regular", "html", map[string]string{"html": html}
	if html == "" {
		kind, format, content = "plaintext", "text", map[string]string{"plain_text": text}
	}
	settings := map[string]string{"subject_line": subject, "title": title, "from_name": fromName, "reply_to": replyTo}
	if preview != "" {
		settings["preview_text"] = preview
	}
	if call.DryRun {
		// The content is authored, not personal data: shown in full.
		after := plain(map[string]any{"audience": clip(a.Name, 100), "subject": subject, "title": title, "previewText": preview, "from": fromName + " <" + replyTo + ">", "format": format, "content": text + html})
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create the %s draft %q for audience %q (%d subscribers); nothing is sent", format, clip(subject, 80), clip(a.Name, 80), a.Stats.Members),
			Changes: []sdk.Change{{Target: "campaign " + clip(title, 80), Op: "create", After: after}}}}, nil
	}
	var cp campaign
	if err := c.do(ctx, http.MethodPost, "/campaigns", nil, map[string]any{"type": kind, "recipients": map[string]string{"list_id": a.ID}, "settings": settings}, &cp); err != nil {
		return sdk.Result{}, err
	}
	if !idRe.MatchString(cp.ID) {
		return sdk.Result{}, errors.New("unexpected answer from Mailchimp")
	}
	if err := c.do(ctx, http.MethodPut, "/campaigns/"+url.PathEscape(cp.ID)+"/content", nil, content, nil); err != nil {
		// Don't leave an empty draft behind.
		_ = c.do(ctx, http.MethodDelete, "/campaigns/"+url.PathEscape(cp.ID), nil, nil, nil)
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"campaign": cp.ID, "status": "save", "type": kind, "audience": clip(a.Name, 100), "subject": subject})
	res.Undo = sdk.UndoWith("delete_draft", map[string]string{"campaign": cp.ID}, "Delete the draft")
	return res, err
}
