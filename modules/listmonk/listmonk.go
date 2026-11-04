// Package listmonk works with a listmonk newsletter server (v4 or later)
// through its API with an API user and token: lists with subscriber counts,
// campaigns with status and stats, creating a draft campaign, starting
// (sending) one, pausing one and deleting one.
//
// Starting a campaign emails everyone on its lists and can't be taken back,
// so it is destructive and its preview shows how many subscribers each list
// would reach.
package listmonk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// Config is one listmonk server.
type Config struct {
	Address            string `json:"address"`  // https://lists.example.com
	Username           string `json:"username"` // API user
	Token              string `json:"token"`    // secret:// API token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the listmonk module.
func New() *Module { return &Module{} }

func (m *Module) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

var (
	userRe   = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,100}$`)
	prefixRe = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)*$`)
	emailRe  = regexp.MustCompile(`^([^<>\r\n]{0,100}<)?[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+>?$`)
	tagRe    = regexp.MustCompile(`^[^\x00-\x1f\x7f,]{1,50}$`)
)

var statuses = map[string]bool{"draft": true, "scheduled": true, "running": true, "paused": true, "cancelled": true, "finished": true}
var contentTypes = map[string]bool{"richtext": true, "html": true, "markdown": true, "plain": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	campaign := `"campaign":{"type":"integer","minimum":1,"description":"Campaign id (see campaigns)"}`
	return sdk.Manifest{
		ID: "listmonk", Name: "listmonk", Version: "0.1.0", Category: "Communication", Icon: "mail",
		Description: "listmonk newsletters: lists and subscriber counts, campaigns with stats, create drafts, send, pause and delete campaigns.",
		Presets:     []string{"team", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["address","username","token"],"properties":{
			"address":{"type":"string","description":"Your listmonk, e.g. https://lists.example.com"},
			"username":{"type":"string","description":"API user name (Admin, Users, New, type API)"},
			"token":{"type":"string","x-secret":true,"description":"That API user's token"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-signed certificate to trust"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "lists", Title: "Lists", Description: "Mailing lists with type, opt-in and subscriber counts by status.", Risk: sdk.RiskRead},
			{Name: "subscribers_count", Title: "Subscriber count", Description: "How many subscribers there are, in all or on one list, optionally by subscription status.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"list":{"type":"integer","minimum":1,"description":"List id (default: all subscribers)"},"status":{"type":"string","enum":["confirmed","unconfirmed","unsubscribed"],"description":"Only subscriptions with this status (needs a list)"}}}`)},
			{Name: "campaigns", Title: "Campaigns", Description: "Campaigns, newest first, with status, lists, sent and to-send counts, views, clicks and bounces.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["draft","scheduled","running","paused","cancelled","finished"]},"limit":{"type":"integer","default":20,"minimum":1,"maximum":100}}}`)},
			{Name: "campaign", Title: "Campaign", Description: "One campaign's status and stats, with the send rate while it runs.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["campaign"],"properties":{` + campaign + `}}`)},
			{Name: "create_campaign", Title: "Create a draft campaign", Description: "Creates a draft campaign for some lists; nothing is sent. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["name","subject","lists","body"],"properties":{"name":{"type":"string","maxLength":200},"subject":{"type":"string","maxLength":500},"lists":{"type":"array","items":{"type":"integer","minimum":1},"minItems":1,"maxItems":20},"body":{"type":"string","maxLength":200000},"contentType":{"type":"string","enum":["richtext","html","markdown","plain"],"default":"markdown"},"fromEmail":{"type":"string","description":"Default: the server's from address"},"templateId":{"type":"integer","minimum":1},"tags":{"type":"array","items":{"type":"string"},"maxItems":10}}}`)},
			{Name: "send_campaign", Title: "Send a campaign", Description: "Starts a draft, scheduled or paused campaign: it emails every subscriber on its lists (or is scheduled, when a draft has a send time, or a paused one is given its sendAt back). Can't be taken back. The preview shows each list's size.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["campaign"],"properties":{` + campaign + `,"sendAt":{"type":"string","description":"Only for a paused campaign that was scheduled: its send time (unchanged), to schedule it again instead of sending now"}}}`)},
			{Name: "pause_campaign", Title: "Pause a campaign", Description: "Pauses a running or scheduled campaign; emails already sent stay sent. Undo resumes a running one (which sends the rest) or schedules a scheduled one again for its original time.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["campaign"],"properties":{` + campaign + `}}`)},
			{Name: "delete_campaign", Title: "Delete a campaign", Description: "Deletes a campaign that isn't running, with its stats, for good.", Risk: sdk.RiskDestructive, DryRun: true,
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
	u, err := url.Parse(strings.TrimSpace(c.Address))
	prefix := ""
	if err == nil {
		prefix = strings.TrimRight(u.Path, "/")
	}
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !prefixRe.MatchString(prefix) || strings.Contains(prefix, "/..") {
		return errors.New("the address is your listmonk's URL, like https://lists.example.com")
	}
	user := strings.TrimSpace(c.Username)
	if !userRe.MatchString(user) {
		return errors.New("the username is the API user's name")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
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
	ref := c.Token
	api := rest.New(u.Scheme+"://"+u.Host+prefix+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "token "+user+":"+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("listmonk refused the API user or token")
	case rest.IsStatus(err, http.StatusForbidden):
		// listmonk answers 403 both for a wrong token and for a missing role.
		return fmt.Errorf("listmonk refused: %v (check the API user, its token and its role's permissions)", err)
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("listmonk has no such campaign or list")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if _, err := c.api.Do(ctx, method, path, q, body, &env); err != nil {
		return friendly(err)
	}
	if out == nil || len(env.Data) == 0 {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("unexpected answer from listmonk: %w", err)
	}
	return nil
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

type list struct {
	ID       int            `json:"id"`
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	Optin    string         `json:"optin"`
	Count    int            `json:"subscriber_count"`
	Statuses map[string]int `json:"subscriber_statuses"`
}

// reach is how many subscribers on the list a campaign would email:
// confirmed ones on double opt-in lists, everyone not unsubscribed otherwise.
func (l list) reach() int {
	if l.Optin == "double" {
		return l.Statuses["confirmed"]
	}
	if n := l.Count - l.Statuses["unsubscribed"]; n > 0 {
		return n
	}
	return 0
}

type campaign struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Subject   string `json:"subject"`
	Status    string `json:"status"`
	Type      string `json:"type"`
	FromEmail string `json:"from_email"`
	Lists     []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"lists"`
	Sent      int     `json:"sent"`
	ToSend    int     `json:"to_send"`
	Views     int     `json:"views"`
	Clicks    int     `json:"clicks"`
	Bounces   int     `json:"bounces"`
	CreatedAt string  `json:"created_at"`
	StartedAt *string `json:"started_at"`
	SendAt    *string `json:"send_at"`
}

func (c campaign) brief() map[string]any {
	lists := []map[string]any{}
	for _, l := range c.Lists {
		lists = append(lists, map[string]any{"id": l.ID, "name": clip(l.Name, 200)})
	}
	out := map[string]any{"campaign": c.ID, "name": clip(c.Name, 200), "subject": clip(c.Subject, 500), "status": c.Status, "lists": lists,
		"sent": c.Sent, "toSend": c.ToSend, "views": c.Views, "clicks": c.Clicks, "bounces": c.Bounces, "created": c.CreatedAt}
	if c.StartedAt != nil && *c.StartedAt != "" {
		out["started"] = *c.StartedAt
	}
	if c.SendAt != nil && *c.SendAt != "" {
		out["sendAt"] = *c.SendAt
	}
	return out
}

func (c *conn) campaign(ctx context.Context, id int) (campaign, error) {
	if id <= 0 {
		return campaign{}, errors.New("the campaign is its numeric id (see campaigns)")
	}
	var cp campaign
	if err := c.do(ctx, http.MethodGet, "/campaigns/"+strconv.Itoa(id), nil, nil, &cp); err != nil {
		return campaign{}, err
	}
	if cp.ID != id {
		return campaign{}, errors.New("unexpected answer from listmonk")
	}
	return cp, nil
}

func (c *conn) lists(ctx context.Context) (map[int]list, error) {
	var res struct {
		Results []list `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, "/lists", url.Values{"per_page": {"all"}}, nil, &res); err != nil {
		return nil, err
	}
	out := map[int]list{}
	for _, l := range res.Results {
		out[l.ID] = l
	}
	return out, nil
}

func (c *conn) setStatus(ctx context.Context, id int, status string) (campaign, error) {
	var cp campaign
	err := c.do(ctx, http.MethodPut, "/campaigns/"+strconv.Itoa(id)+"/status", nil, map[string]string{"status": status}, &cp)
	return cp, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ls, err := c.lists(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d lists", len(ls))}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Campaign    int      `json:"campaign"`
		List        int      `json:"list"`
		Status      string   `json:"status"`
		Limit       int      `json:"limit"`
		Name        string   `json:"name"`
		Subject     string   `json:"subject"`
		Lists       []int    `json:"lists"`
		Body        string   `json:"body"`
		ContentType string   `json:"contentType"`
		FromEmail   string   `json:"fromEmail"`
		TemplateID  int      `json:"templateId"`
		Tags        []string `json:"tags"`
		SendAt      string   `json:"sendAt"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "lists":
		ls, err := c.lists(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, l := range ls {
			out = append(out, map[string]any{"list": l.ID, "name": clip(l.Name, 200), "type": l.Type, "optin": l.Optin, "subscribers": l.Count, "byStatus": l.Statuses, "reach": l.reach()})
		}
		sort.Slice(out, func(i, j int) bool { return out[i]["list"].(int) < out[j]["list"].(int) })
		return sdk.JSON(out)

	case "subscribers_count":
		if p.List < 0 {
			return sdk.Result{}, errors.New("the list is its numeric id (see lists)")
		}
		q := url.Values{"per_page": {"1"}}
		if p.List > 0 {
			q.Set("list_id", strconv.Itoa(p.List))
		}
		if p.Status != "" {
			if p.Status != "confirmed" && p.Status != "unconfirmed" && p.Status != "unsubscribed" {
				return sdk.Result{}, errors.New("status is confirmed, unconfirmed or unsubscribed")
			}
			if p.List == 0 {
				return sdk.Result{}, errors.New("a subscription status needs a list")
			}
			q.Set("subscription_status", p.Status)
		}
		var res struct {
			Total int `json:"total"`
		}
		if err := c.do(ctx, http.MethodGet, "/subscribers", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"subscribers": res.Total}
		if p.List > 0 {
			out["list"] = p.List
		}
		if p.Status != "" {
			out["status"] = p.Status
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
		q := url.Values{"per_page": {strconv.Itoa(n)}, "order_by": {"created_at"}, "order": {"desc"}}
		if p.Status != "" {
			if !statuses[p.Status] {
				return sdk.Result{}, errors.New("status is draft, scheduled, running, paused, cancelled or finished")
			}
			q.Set("status", p.Status)
		}
		var res struct {
			Results []campaign `json:"results"`
			Total   int        `json:"total"`
		}
		if err := c.do(ctx, http.MethodGet, "/campaigns", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, cp := range res.Results {
			list = append(list, cp.brief())
		}
		return sdk.JSON(map[string]any{"total": res.Total, "campaigns": list})

	case "campaign":
		cp, err := c.campaign(ctx, p.Campaign)
		if err != nil {
			return sdk.Result{}, err
		}
		out := cp.brief()
		if cp.Status == "running" {
			var st []struct {
				Rate    float64 `json:"rate"`
				NetRate float64 `json:"net_rate"`
			}
			if err := c.do(ctx, http.MethodGet, "/campaigns/running/stats", url.Values{"campaign_id": {strconv.Itoa(cp.ID)}}, nil, &st); err == nil && len(st) > 0 {
				out["ratePerMinute"] = st[0].Rate
			}
		}
		return sdk.JSON(out)

	case "create_campaign":
		name, subject := strings.TrimSpace(p.Name), strings.TrimSpace(p.Subject)
		switch {
		case name == "" || len([]rune(name)) > 200 || strings.ContainsAny(name, "\r\n\x00"):
			return sdk.Result{}, errors.New("the name is up to 200 characters on one line")
		case subject == "" || len([]rune(subject)) > 500 || strings.ContainsAny(subject, "\r\n\x00"):
			return sdk.Result{}, errors.New("the subject is up to 500 characters on one line")
		case strings.TrimSpace(p.Body) == "" || len(p.Body) > 200000:
			return sdk.Result{}, errors.New("the body is the campaign's content, up to 200000 characters")
		case len(p.Lists) == 0 || len(p.Lists) > 20:
			return sdk.Result{}, errors.New("give 1 to 20 list ids")
		case p.TemplateID < 0:
			return sdk.Result{}, errors.New("the templateId is a template's numeric id")
		case len(p.Tags) > 10:
			return sdk.Result{}, errors.New("give at most 10 tags")
		}
		for _, l := range p.Lists {
			if l <= 0 {
				return sdk.Result{}, errors.New("lists are numeric list ids (see lists)")
			}
		}
		for _, t := range p.Tags {
			if !tagRe.MatchString(t) {
				return sdk.Result{}, fmt.Errorf("%q isn't a tag", clip(t, 50))
			}
		}
		ct := p.ContentType
		if ct == "" {
			ct = "markdown"
		}
		if !contentTypes[ct] {
			return sdk.Result{}, errors.New("contentType is richtext, html, markdown or plain")
		}
		from := strings.TrimSpace(p.FromEmail)
		if from != "" && !emailRe.MatchString(from) {
			return sdk.Result{}, errors.New("fromEmail is an address like News <news@example.com>")
		}
		ls, err := c.lists(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		names := []string{}
		for _, id := range p.Lists {
			l, ok := ls[id]
			if !ok {
				return sdk.Result{}, fmt.Errorf("there's no list %d", id)
			}
			names = append(names, fmt.Sprintf("%s (%d)", clip(l.Name, 100), l.reach()))
		}
		if call.DryRun {
			after, _ := json.Marshal(map[string]any{"name": name, "subject": subject, "lists": p.Lists, "contentType": ct})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create the draft campaign %q for %s; nothing is sent", name, strings.Join(names, ", ")),
				Changes: []sdk.Change{{Target: "campaign " + name, Op: "create", After: after}}}}, nil
		}
		body := map[string]any{"name": name, "subject": subject, "lists": p.Lists, "type": "regular", "content_type": ct, "body": p.Body, "messenger": "email"}
		if from != "" {
			body["from_email"] = from
		}
		if p.TemplateID > 0 {
			body["template_id"] = p.TemplateID
		}
		if len(p.Tags) > 0 {
			body["tags"] = p.Tags
		}
		var cp campaign
		if err := c.do(ctx, http.MethodPost, "/campaigns", nil, body, &cp); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(cp.brief())
		if cp.ID > 0 {
			res.Undo = sdk.UndoWith("delete_campaign", map[string]int{"campaign": cp.ID}, "Delete the draft campaign")
		}
		return res, err

	case "send_campaign":
		cp, err := c.campaign(ctx, p.Campaign)
		if err != nil {
			return sdk.Result{}, err
		}
		if cp.Status != "draft" && cp.Status != "scheduled" && cp.Status != "paused" {
			return sdk.Result{}, fmt.Errorf("the campaign is %s; only draft, scheduled or paused campaigns can be sent", cp.Status)
		}
		target := "running"
		if cp.Status == "draft" && cp.SendAt != nil && *cp.SendAt != "" {
			if t, err := time.Parse(time.RFC3339, *cp.SendAt); err == nil && t.After(m.now()) {
				target = "scheduled"
			}
		}
		// Undoing the pause of a scheduled campaign: schedule it again,
		// for the time it had.
		if p.SendAt != "" {
			want, err := time.Parse(time.RFC3339, p.SendAt)
			if err != nil {
				return sdk.Result{}, errors.New("sendAt is a time like 2026-11-10T09:00:00Z")
			}
			if cp.Status != "paused" {
				return sdk.Result{}, fmt.Errorf("the campaign is %s; sendAt only schedules a paused campaign again", cp.Status)
			}
			have, err := time.Parse(time.RFC3339, ptrStr(cp.SendAt))
			if err != nil || !have.Equal(want) {
				return sdk.Result{}, errors.New("the campaign's send time has changed since it was paused; check it in Listmonk")
			}
			if !want.After(m.now()) {
				return sdk.Result{}, errors.New("the campaign's send time has passed; send it without sendAt to send the rest now")
			}
			target = "scheduled"
		}
		if call.DryRun {
			ls, err := c.lists(ctx)
			if err != nil {
				return sdk.Result{}, err
			}
			total := 0
			parts := []string{}
			changes := []sdk.Change{}
			for _, l := range cp.Lists {
				n := ls[l.ID].reach()
				total += n
				parts = append(parts, fmt.Sprintf("%s (%d)", clip(l.Name, 100), n))
				after, _ := json.Marshal(map[string]any{"subscribers": n, "optin": ls[l.ID].Optin})
				changes = append(changes, sdk.Change{Target: "list " + clip(l.Name, 100), Op: "email", After: after})
			}
			verb := "Email"
			when := "now"
			if target == "scheduled" {
				verb, when = "Schedule emailing", "at "+*cp.SendAt
			}
			if cp.Status == "paused" && target == "running" {
				verb = "Resume emailing"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s %q to up to %d subscribers %s: %s. Sent emails can't be recalled.", verb, clip(cp.Subject, 80), total, when, strings.Join(parts, ", ")),
				Changes: changes}}, nil
		}
		after, err := c.setStatus(ctx, cp.ID, target)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"campaign": cp.ID, "status": after.Status})

	case "pause_campaign":
		cp, err := c.campaign(ctx, p.Campaign)
		if err != nil {
			return sdk.Result{}, err
		}
		if cp.Status != "running" && cp.Status != "scheduled" {
			return sdk.Result{}, fmt.Errorf("the campaign is %s; only running or scheduled campaigns can be paused", cp.Status)
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Pause %q (%d of %d sent)", clip(cp.Name, 80), cp.Sent, cp.ToSend),
				Changes: []sdk.Change{{Target: "campaign " + strconv.Itoa(cp.ID), Op: "update", Before: json.RawMessage(strconv.Quote(cp.Status)), After: json.RawMessage(`"paused"`)}}}}, nil
		}
		after, err := c.setStatus(ctx, cp.ID, "paused")
		if err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"campaign": cp.ID, "status": after.Status, "sent": after.Sent})
		if cp.Status == "scheduled" && ptrStr(cp.SendAt) != "" {
			res.Undo = sdk.UndoWith("send_campaign", map[string]any{"campaign": cp.ID, "sendAt": *cp.SendAt}, "Schedule the campaign again for "+*cp.SendAt)
		} else {
			res.Undo = sdk.UndoWith("send_campaign", map[string]int{"campaign": cp.ID}, "Resume the campaign")
		}
		return res, err

	case "delete_campaign":
		cp, err := c.campaign(ctx, p.Campaign)
		if err != nil {
			return sdk.Result{}, err
		}
		if cp.Status == "running" {
			return sdk.Result{}, errors.New("the campaign is running; pause it first")
		}
		if call.DryRun {
			before, _ := json.Marshal(cp.brief())
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete the %s campaign %q with its stats", cp.Status, clip(cp.Name, 80)),
				Changes: []sdk.Change{{Target: "campaign " + strconv.Itoa(cp.ID), Op: "delete", Before: before}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/campaigns/"+strconv.Itoa(cp.ID), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": cp.ID})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
