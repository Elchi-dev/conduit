// Package brevo works with a Brevo (formerly Sendinblue) account through its
// API with an API key: contact lists with subscriber counts, email
// campaigns with their statistics, transactional email statistics, creating
// a draft campaign, sending a test of it to an allowed address, and sending
// a campaign.
//
// Sending a campaign emails everyone on its lists and can't be taken back,
// so it is destructive and its preview names each list with its subscriber
// count, the subject and the sender. Contacts' addresses are never read:
// lists report counts only.
package brevo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
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

// Config is one Brevo account.
type Config struct {
	Key string `json:"key"` // secret:// API key (xkeysib-…)
	// TestRecipients are the addresses send_test may reach besides the
	// account's own address.
	TestRecipients []string `json:"testRecipients"`
}

type conn struct {
	api   *rest.Client
	allow []string // lower-case addresses
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.brevo.com/v3 (tests).
	Base string
}

// New returns the Brevo module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.brevo.com/v3"

// maxListPages bounds how many pages of 50 lists one listing reads.
const maxListPages = 20

var (
	keyRe   = regexp.MustCompile(`^xkeysib-[A-Za-z0-9-]{20,200}$`)
	emailRe = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+=?^_{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$`)
)

var statuses = map[string]bool{"draft": true, "sent": true, "queued": true, "suspended": true, "archive": true, "inProcess": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	campaign := `"campaign":{"type":"integer","minimum":1,"description":"Campaign id (see campaigns)"}`
	return sdk.Manifest{
		ID: "brevo", Name: "Brevo", Version: "0.1.0", Category: "Communication", Icon: "mail",
		Description: "Brevo: contact lists with subscriber counts, email campaigns and their stats, transactional email stats, create draft campaigns, send tests and send campaigns.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["key"],"properties":{
			"key":{"type":"string","x-secret":true,"description":"A Brevo API key (Settings, SMTP & API, API keys), like xkeysib-…"},
			"testRecipients":{"type":"array","maxItems":10,"items":{"type":"string"},"description":"Addresses send_test may send to, besides the account's own address; anything else is refused"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "lists", Title: "Contact lists", Description: "Contact lists with subscriber and blocklisted counts. Counts only, no addresses.", Risk: sdk.RiskRead},
			{Name: "campaigns", Title: "Email campaigns", Description: "Email campaigns, newest first: name, subject, status, sender, lists, schedule and delivery, open and click counts.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["draft","sent","queued","suspended","archive","inProcess"],"description":"queued is a scheduled campaign"},"limit":{"type":"integer","default":20,"minimum":1,"maximum":100}}}`)},
			{Name: "campaign", Title: "Email campaign", Description: "One campaign's status, lists and statistics.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["campaign"],"properties":{` + campaign + `}}`)},
			{Name: "transactional_stats", Title: "Transactional stats", Description: "Transactional email totals over the last days: requests, delivered, opens, clicks, bounces, blocked, spam reports and unsubscribes.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"days":{"type":"integer","default":7,"minimum":1,"maximum":90}}}`)},
			{Name: "create_draft", Title: "Create a draft campaign", Description: "Creates a draft email campaign for some lists from plain text or HTML; nothing is sent. The preview shows the content in full. Undo deletes the draft.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["name","subject","lists"],"properties":{"name":{"type":"string","maxLength":200},"subject":{"type":"string","maxLength":200},"lists":{"type":"array","items":{"type":"integer","minimum":1},"minItems":1,"maxItems":20},"previewText":{"type":"string","maxLength":200},"senderEmail":{"type":"string","description":"One of the account's active senders (default: the only one)"},"text":{"type":"string","maxLength":200000,"description":"Plain-text content, sent as simple HTML; give text or html"},"html":{"type":"string","maxLength":500000,"description":"HTML content; scripts, event handlers and javascript: links are refused"}}}`)},
			{Name: "delete_draft", Title: "Delete a draft", Description: "Deletes a draft campaign for good. Only drafts; the preview names it.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["campaign"],"properties":{` + campaign + `}}`)},
			{Name: "send_test", Title: "Send a test email", Description: "Sends a test of a campaign to one address: the account's own, or one of the test recipients in this instance's settings. Any other address is refused.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["campaign"],"properties":{` + campaign + `,"to":{"type":"string","description":"The address (default: the only test recipient, or the account's address)"}}}`)},
			{Name: "send_campaign", Title: "Send a campaign", Description: "Sends a draft campaign to its lists now. Can't be taken back. The preview names each list with its subscriber count, the subject and the sender, and shows the content and its sha256, which the run must give: it's refused if the campaign changed since.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["campaign"],"properties":{` + campaign + `,"sha256":{"type":"string","pattern":"^[0-9a-f]{64}$","description":"The campaign's sha256 from the preview; needed to send, refused if the campaign changed since"}}}`)},
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
			return errors.New("the stored key doesn't look like a Brevo API key (xkeysib-…)")
		}
		r.Header.Set("api-key", k)
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, allow: allow})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Brevo refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("Brevo refused: %v", err)
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("Brevo has no such campaign or list")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Brevo's rate limit was hit; try again in a minute")
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

func oneLine(s string, n int) bool {
	return s != "" && len([]rune(s)) <= n && !strings.ContainsAny(s, "\r\n\x00")
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

// textHTML turns plain text into simple HTML: escaped, one paragraph per
// blank-line-separated block, line breaks kept.
func textHTML(s string) string {
	var b strings.Builder
	for _, para := range strings.Split(strings.ReplaceAll(strings.TrimSpace(s), "\r\n", "\n"), "\n\n") {
		if para = strings.TrimSpace(para); para != "" {
			b.WriteString("<p>" + strings.ReplaceAll(html.EscapeString(para), "\n", "<br>") + "</p>\n")
		}
	}
	return b.String()
}

type list struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Subscribers int    `json:"totalSubscribers"`
	Unique      int    `json:"uniqueSubscribers"`
	Blocklisted int    `json:"totalBlacklisted"`
}

func (c *conn) lists(ctx context.Context) (map[int]list, []list, error) {
	by := map[int]list{}
	all := []list{}
	for page := 0; page < maxListPages; page++ {
		var res struct {
			Lists []list `json:"lists"`
			Count int    `json:"count"`
		}
		if err := c.do(ctx, http.MethodGet, "/contacts/lists", url.Values{"limit": {"50"}, "offset": {strconv.Itoa(page * 50)}, "sort": {"asc"}}, nil, &res); err != nil {
			return nil, nil, err
		}
		for _, l := range res.Lists {
			by[l.ID] = l
			all = append(all, l)
		}
		if len(res.Lists) < 50 || len(all) >= res.Count {
			break
		}
	}
	return by, all, nil
}

type campaign struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Subject     string `json:"subject"`
	PreviewText string `json:"previewText"`
	ReplyTo     string `json:"replyTo"`
	HTML        string `json:"htmlContent"`
	Type        string `json:"type"`
	Status      string `json:"status"`
	ScheduledAt string `json:"scheduledAt"`
	SentDate    string `json:"sentDate"`
	CreatedAt   string `json:"createdAt"`
	Sender      struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"sender"`
	Recipients struct {
		Lists     []int `json:"lists"`
		Exclusion []int `json:"exclusionLists"`
		// Segments, in either name Brevo uses; only checked for being set.
		Segments   json.RawMessage `json:"segments"`
		SegmentIDs json.RawMessage `json:"segmentIds"`
	} `json:"recipients"`
	Statistics struct {
		Global *struct {
			Sent         int `json:"sent"`
			Delivered    int `json:"delivered"`
			UniqueViews  int `json:"uniqueViews"`
			UniqueClicks int `json:"uniqueClicks"`
			HardBounces  int `json:"hardBounces"`
			SoftBounces  int `json:"softBounces"`
			Unsubscribed int `json:"unsubscriptions"`
			Complaints   int `json:"complaints"`
		} `json:"globalStats"`
	} `json:"statistics"`
}

func (cp campaign) from() string {
	return fmt.Sprintf("%s <%s>", clip(cp.Sender.Name, 100), clip(cp.Sender.Email, 254))
}

func (cp campaign) brief() map[string]any {
	out := map[string]any{"campaign": cp.ID, "name": clip(cp.Name, 200), "subject": clip(cp.Subject, 200), "status": cp.Status, "type": cp.Type,
		"from": cp.from(), "lists": cp.Recipients.Lists, "created": cp.CreatedAt}
	if len(cp.Recipients.Exclusion) > 0 {
		out["exclusionLists"] = cp.Recipients.Exclusion
	}
	if cp.ScheduledAt != "" {
		out["scheduledAt"] = cp.ScheduledAt
	}
	if cp.SentDate != "" {
		out["sent"] = cp.SentDate
	}
	if g := cp.Statistics.Global; g != nil {
		out["stats"] = map[string]int{"sent": g.Sent, "delivered": g.Delivered, "uniqueOpens": g.UniqueViews, "uniqueClicks": g.UniqueClicks,
			"hardBounces": g.HardBounces, "softBounces": g.SoftBounces, "unsubscribed": g.Unsubscribed, "complaints": g.Complaints}
	}
	return out
}

// segmented reports whether the campaign also goes to segments, whose size
// Conduit can't show.
func (cp campaign) segmented() bool {
	for _, raw := range []json.RawMessage{cp.Recipients.Segments, cp.Recipients.SegmentIDs} {
		if s := strings.TrimSpace(string(raw)); s != "" && s != "null" && s != "[]" {
			return true
		}
	}
	return false
}

func (c *conn) campaign(ctx context.Context, id int) (campaign, error) {
	return c.readCampaign(ctx, id, false)
}

// readCampaign reads a campaign, with its HTML when withHTML is set.
func (c *conn) readCampaign(ctx context.Context, id int, withHTML bool) (campaign, error) {
	if id <= 0 {
		return campaign{}, errors.New("the campaign is its numeric id (see campaigns)")
	}
	q := url.Values{"statistics": {"globalStats"}, "excludeHtmlContent": {"true"}}
	if withHTML {
		q.Set("excludeHtmlContent", "false")
	}
	var cp campaign
	if err := c.do(ctx, http.MethodGet, "/emailCampaigns/"+strconv.Itoa(id), q, nil, &cp); err != nil {
		return campaign{}, err
	}
	if cp.ID != id {
		return campaign{}, errors.New("unexpected answer from Brevo")
	}
	return cp, nil
}

// account is the account's own address and name.
func (c *conn) account(ctx context.Context) (string, string, error) {
	var a struct {
		Email   string `json:"email"`
		Company string `json:"companyName"`
	}
	err := c.do(ctx, http.MethodGet, "/account", nil, nil, &a)
	return strings.ToLower(strings.TrimSpace(a.Email)), a.Company, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	_, company, err := c.account(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	_, ls, err := c.lists(ctx)
	if err != nil {
		return sdk.Health{Status: "degraded", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%s: %d contact lists", clip(company, 80), len(ls))}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Campaign    int    `json:"campaign"`
		Status      string `json:"status"`
		Limit       int    `json:"limit"`
		Days        int    `json:"days"`
		Name        string `json:"name"`
		Subject     string `json:"subject"`
		Lists       []int  `json:"lists"`
		PreviewText string `json:"previewText"`
		SenderEmail string `json:"senderEmail"`
		Text        string `json:"text"`
		HTML        string `json:"html"`
		To          string `json:"to"`
		SHA256      string `json:"sha256"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if err := checkSHA(p.SHA256); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "lists":
		_, ls, err := c.lists(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, l := range ls {
			out = append(out, map[string]any{"list": l.ID, "name": clip(l.Name, 200), "subscribers": l.Subscribers, "uniqueSubscribers": l.Unique, "blocklisted": l.Blocklisted})
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
		q := url.Values{"type": {"classic"}, "limit": {strconv.Itoa(n)}, "offset": {"0"}, "sort": {"desc"}, "statistics": {"globalStats"}, "excludeHtmlContent": {"true"}}
		if p.Status != "" {
			if !statuses[p.Status] {
				return sdk.Result{}, errors.New("status is draft, sent, queued, suspended, archive or inProcess")
			}
			q.Set("status", p.Status)
		}
		var res struct {
			Campaigns []campaign `json:"campaigns"`
			Count     int        `json:"count"`
		}
		if err := c.do(ctx, http.MethodGet, "/emailCampaigns", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, cp := range res.Campaigns {
			list = append(list, cp.brief())
		}
		return sdk.JSON(map[string]any{"total": res.Count, "campaigns": list})

	case "campaign":
		cp, err := c.campaign(ctx, p.Campaign)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(cp.brief())

	case "transactional_stats":
		d := p.Days
		if d == 0 {
			d = 7
		}
		if d < 1 || d > 90 {
			return sdk.Result{}, errors.New("days is 1 to 90")
		}
		var s struct {
			Range        string `json:"range"`
			Requests     int    `json:"requests"`
			Delivered    int    `json:"delivered"`
			HardBounces  int    `json:"hardBounces"`
			SoftBounces  int    `json:"softBounces"`
			Clicks       int    `json:"clicks"`
			UniqueClicks int    `json:"uniqueClicks"`
			Opens        int    `json:"opens"`
			UniqueOpens  int    `json:"uniqueOpens"`
			SpamReports  int    `json:"spamReports"`
			Blocked      int    `json:"blocked"`
			Invalid      int    `json:"invalid"`
			Unsubscribed int    `json:"unsubscribed"`
		}
		if err := c.do(ctx, http.MethodGet, "/smtp/statistics/aggregatedReport", url.Values{"days": {strconv.Itoa(d)}}, nil, &s); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"days": d, "range": clip(s.Range, 40), "requests": s.Requests, "delivered": s.Delivered, "opens": s.Opens, "uniqueOpens": s.UniqueOpens,
			"clicks": s.Clicks, "uniqueClicks": s.UniqueClicks, "hardBounces": s.HardBounces, "softBounces": s.SoftBounces, "spamReports": s.SpamReports,
			"blocked": s.Blocked, "invalid": s.Invalid, "unsubscribed": s.Unsubscribed})

	case "create_draft":
		return c.createDraft(ctx, call, p.Name, p.Subject, p.PreviewText, p.SenderEmail, p.Text, p.HTML, p.Lists)

	case "delete_draft":
		cp, err := c.campaign(ctx, p.Campaign)
		if err != nil {
			return sdk.Result{}, err
		}
		if cp.Status != "draft" {
			return sdk.Result{}, fmt.Errorf("the campaign is %s; only drafts are deleted here", cp.Status)
		}
		if call.DryRun {
			before, _ := json.Marshal(cp.brief())
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete the draft %q (%q) for good", clip(cp.Name, 80), clip(cp.Subject, 80)),
				Changes: []sdk.Change{{Target: "campaign " + strconv.Itoa(cp.ID), Op: "delete", Before: before}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/emailCampaigns/"+strconv.Itoa(cp.ID), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": cp.ID})

	case "send_test":
		to := strings.ToLower(strings.TrimSpace(p.To))
		if to != "" && (len(to) > 254 || !emailRe.MatchString(to)) {
			return sdk.Result{}, errors.New("to is one plain email address")
		}
		if p.Campaign <= 0 {
			return sdk.Result{}, errors.New("the campaign is its numeric id (see campaigns)")
		}
		to, err := c.testRecipient(ctx, to)
		if err != nil {
			return sdk.Result{}, err
		}
		cp, err := c.campaign(ctx, p.Campaign)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			after := plain(map[string]any{"to": to, "subject": clip(cp.Subject, 200), "from": cp.from()})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Send a test of %q to %s; nobody else gets it", clip(cp.Subject, 80), to),
				Changes: []sdk.Change{{Target: to, Op: "email", After: after}}}}, nil
		}
		if err := c.do(ctx, http.MethodPost, "/emailCampaigns/"+strconv.Itoa(cp.ID)+"/sendTest", nil, map[string]any{"emailTo": []string{to}}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"campaign": cp.ID, "sentTo": to})

	case "send_campaign":
		cp, err := c.readCampaign(ctx, p.Campaign, true)
		if err != nil {
			return sdk.Result{}, err
		}
		switch cp.Status {
		case "sent", "in_process", "inProcess":
			return sdk.JSON(map[string]any{"campaign": cp.ID, "status": cp.Status, "note": "nothing to change: it has already gone out"})
		case "queued":
			return sdk.Result{}, fmt.Errorf("the campaign is scheduled for %s; change its schedule in Brevo to send it now", cp.ScheduledAt)
		case "draft":
		default:
			return sdk.Result{}, fmt.Errorf("the campaign is %s; only drafts can be sent", cp.Status)
		}
		if cp.segmented() {
			return sdk.Result{}, errors.New("the campaign also goes to segments, whose size Conduit can't show; send it from Brevo")
		}
		if len(cp.Recipients.Lists) == 0 {
			return sdk.Result{}, errors.New("the campaign has no lists to send to")
		}
		if strings.TrimSpace(cp.HTML) == "" {
			return sdk.Result{}, errors.New("the campaign has no content yet")
		}
		// What's sent: recipients, subject, preview text, sender and HTML.
		sum := fingerprint(cp.ID, cp.Recipients.Lists, cp.Recipients.Exclusion, cp.Subject, cp.PreviewText, cp.Sender.Name, cp.Sender.Email, cp.ReplyTo, cp.HTML)
		if call.DryRun {
			by, _, err := c.lists(ctx)
			if err != nil {
				return sdk.Result{}, err
			}
			total := 0
			parts := []string{}
			changes := []sdk.Change{}
			for _, id := range cp.Recipients.Lists {
				l, ok := by[id]
				if !ok {
					return sdk.Result{}, fmt.Errorf("the campaign's list %d can't be read, so its size can't be shown; check it in Brevo", id)
				}
				name := clip(l.Name, 100)
				total += l.Subscribers
				parts = append(parts, fmt.Sprintf("%s (%d)", name, l.Subscribers))
				changes = append(changes, sdk.Change{Target: "list " + name, Op: "email", After: plain(map[string]any{"subscribers": l.Subscribers})})
			}
			excl := ""
			if len(cp.Recipients.Exclusion) > 0 {
				excl = fmt.Sprintf(", minus %d exclusion lists", len(cp.Recipients.Exclusion))
			}
			// The content is authored, not personal data: shown in full, as sent.
			changes = append(changes, sdk.Change{Target: "campaign " + strconv.Itoa(cp.ID), Op: "email", After: plain(map[string]any{"subject": cp.Subject, "previewText": cp.PreviewText,
				"from": cp.from(), "replyTo": clip(cp.ReplyTo, 254), "html": cp.HTML, "sha256": sum})})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Email %q from %s to up to %d contacts now: %s%s (content sha256 %s). Sent emails can't be recalled.%s", clip(cp.Subject, 100), cp.from(), total, strings.Join(parts, ", "), excl, sum, changedNote("campaign", p.SHA256, sum)),
				Changes: changes}}, nil
		}
		if err := sameContent("campaign", p.SHA256, sum); err != nil {
			return sdk.Result{}, err
		}
		if err := c.do(ctx, http.MethodPost, "/emailCampaigns/"+strconv.Itoa(cp.ID)+"/sendNow", nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"campaign": cp.ID, "status": "in_process"})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// testRecipient picks the address for a test email: one of the configured
// test recipients or the account's own address, and nothing else.
func (c *conn) testRecipient(ctx context.Context, to string) (string, error) {
	for _, a := range c.allow {
		if a == to {
			return to, nil
		}
	}
	if to == "" && len(c.allow) == 1 {
		return c.allow[0], nil
	}
	owner, _, err := c.account(ctx)
	if err != nil {
		return "", err
	}
	if !emailRe.MatchString(owner) {
		owner = ""
	}
	switch {
	case to == "" && len(c.allow) == 0 && owner != "":
		return owner, nil
	case to == "":
		return "", errors.New("give to: the account's address or one of the test recipients")
	case to == owner:
		return to, nil
	}
	return "", errors.New("test emails go only to the account's address or the test recipients in this instance's settings")
}

func (c *conn) createDraft(ctx context.Context, call sdk.Call, name, subject, preview, sender, text, htm string, lists []int) (sdk.Result, error) {
	name, subject, preview, sender = strings.TrimSpace(name), strings.TrimSpace(subject), strings.TrimSpace(preview), strings.ToLower(strings.TrimSpace(sender))
	switch {
	case !oneLine(name, 200):
		return sdk.Result{}, errors.New("the name is up to 200 characters on one line")
	case !oneLine(subject, 200):
		return sdk.Result{}, errors.New("the subject is up to 200 characters on one line")
	case preview != "" && !oneLine(preview, 200):
		return sdk.Result{}, errors.New("the previewText is up to 200 characters on one line")
	case sender != "" && (len(sender) > 254 || !emailRe.MatchString(sender)):
		return sdk.Result{}, errors.New("senderEmail is one plain email address")
	case len(lists) == 0 || len(lists) > 20:
		return sdk.Result{}, errors.New("give 1 to 20 list ids")
	case (strings.TrimSpace(text) == "") == (strings.TrimSpace(htm) == ""):
		return sdk.Result{}, errors.New("give the content as text (plain text) or as html, one of them")
	case len(text) > 200000 || len(htm) > 500000:
		return sdk.Result{}, errors.New("the content is too long")
	}
	if bad := unsafeHTML(htm); bad != "" {
		return sdk.Result{}, fmt.Errorf("the html has %s, which would run code in the web version of the email; remove it", bad)
	}
	for _, l := range lists {
		if l <= 0 {
			return sdk.Result{}, errors.New("lists are numeric list ids (see lists)")
		}
	}
	format, body := "html", htm
	if htm == "" {
		format, body = "text", textHTML(text)
	}
	by, _, err := c.lists(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	names := []string{}
	for _, id := range lists {
		l, ok := by[id]
		if !ok {
			return sdk.Result{}, fmt.Errorf("there's no list %d", id)
		}
		names = append(names, fmt.Sprintf("%s (%d)", clip(l.Name, 100), l.Subscribers))
	}
	var ss struct {
		Senders []struct {
			ID     int    `json:"id"`
			Name   string `json:"name"`
			Email  string `json:"email"`
			Active bool   `json:"active"`
		} `json:"senders"`
	}
	if err := c.do(ctx, http.MethodGet, "/senders", nil, nil, &ss); err != nil {
		return sdk.Result{}, err
	}
	var from struct {
		ID          int
		Name, Email string
	}
	n := 0
	for _, s := range ss.Senders {
		if !s.Active || (sender != "" && strings.ToLower(s.Email) != sender) {
			continue
		}
		n++
		from.ID, from.Name, from.Email = s.ID, s.Name, s.Email
	}
	switch {
	case n == 0 && sender != "":
		return sdk.Result{}, fmt.Errorf("%s isn't one of the account's active senders", sender)
	case n == 0:
		return sdk.Result{}, errors.New("the account has no active sender; add one in Brevo")
	case n > 1 && sender == "":
		return sdk.Result{}, errors.New("the account has several senders; give senderEmail")
	}
	fromText := fmt.Sprintf("%s <%s>", clip(from.Name, 100), clip(from.Email, 254))
	if call.DryRun {
		// The content is authored, not personal data: shown in full, as sent.
		after := plain(map[string]any{"name": name, "subject": subject, "previewText": preview, "from": fromText, "lists": lists, "format": format, "html": body})
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create the %s draft %q for %s; nothing is sent", format, clip(subject, 80), strings.Join(names, ", ")),
			Changes: []sdk.Change{{Target: "campaign " + clip(name, 80), Op: "create", After: after}}}}, nil
	}
	req := map[string]any{"name": name, "subject": subject, "sender": map[string]int{"id": from.ID}, "htmlContent": body, "recipients": map[string]any{"listIds": lists}}
	if preview != "" {
		req["previewText"] = preview
	}
	var res struct {
		ID int `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/emailCampaigns", nil, req, &res); err != nil {
		return sdk.Result{}, err
	}
	if res.ID <= 0 {
		return sdk.Result{}, errors.New("unexpected answer from Brevo")
	}
	r, err := sdk.JSON(map[string]any{"campaign": res.ID, "status": "draft", "name": name, "subject": subject, "from": fromText})
	r.Undo = sdk.UndoWith("delete_draft", map[string]int{"campaign": res.ID}, "Delete the draft")
	return r, err
}
