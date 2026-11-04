// Package kit works with a Kit (formerly ConvertKit) account through the v4
// API with an API key: subscriber counts (in all or by tag), tags,
// broadcasts and their stats, creating a draft broadcast, and scheduling or
// unscheduling one.
//
// Scheduling a broadcast emails its subscribers when the time comes and
// can't be recalled once it has gone out, so it is destructive and its
// preview names the recipients (all subscribers or the tags), their count,
// the subject and the sender. Subscribers' addresses and names are never
// read: only counts are.
package kit

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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Kit account.
type Config struct {
	Key string `json:"key"` // secret:// v4 API key
}

type conn struct {
	api *rest.Client
	now func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.kit.com/v4 (tests).
	Base string
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Kit module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.kit.com/v4"

// maxTags bounds how many tags one broadcast may target, so a preview can't
// turn into many requests.
const maxTags = 10

var (
	keyRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{16,200}$`)
	emailRe = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+=?^_{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$`)
)

var subStatuses = map[string]bool{"active": true, "inactive": true, "bounced": true, "complained": true, "cancelled": true, "all": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	broadcast := `"broadcast":{"type":"integer","minimum":1,"description":"Broadcast id (see broadcasts)"}`
	return sdk.Manifest{
		ID: "kit", Name: "Kit", Version: "0.1.0", Category: "Communication", Icon: "mail",
		Description: "Kit (ConvertKit): subscriber counts, tags, broadcasts and their stats, create draft broadcasts, schedule and unschedule them.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["key"],"properties":{
			"key":{"type":"string","x-secret":true,"description":"A Kit v4 API key (Settings, Developer, API keys)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "subscribers_count", Title: "Subscriber count", Description: "How many subscribers there are, by status (active by default), in all or with one tag. Counts only, no addresses.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["active","inactive","bounced","complained","cancelled","all"],"default":"active"},"tag":{"type":"integer","minimum":1,"description":"Only subscribers with this tag (see tags)"}}}`)},
			{Name: "tags", Title: "Tags", Description: "Tags with their ids, to target a broadcast.", Risk: sdk.RiskRead},
			{Name: "broadcasts", Title: "Broadcasts", Description: "Broadcasts, newest first: subject, status (draft, scheduled or sent), send time, recipients filter and whether it's public.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":20,"minimum":1,"maximum":100}}}`)},
			{Name: "broadcast_stats", Title: "Broadcast stats", Description: "One broadcast's stats: recipients, open and click rates, clicks, unsubscribes and sending status.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["broadcast"],"properties":{` + broadcast + `}}`)},
			{Name: "create_draft", Title: "Create a draft broadcast", Description: "Creates a draft broadcast (never public) for all subscribers or some tags, from plain text or HTML; nothing is sent. The preview shows the content in full. Undo deletes the draft.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["subject"],"properties":{"subject":{"type":"string","maxLength":200},"previewText":{"type":"string","maxLength":200},"description":{"type":"string","maxLength":200,"description":"Internal note"},"tags":{"type":"array","items":{"type":"integer","minimum":1},"maxItems":10,"description":"Send to subscribers with any of these tags (default: all subscribers)"},"emailAddress":{"type":"string","description":"A confirmed sending address (default: the account's)"},"text":{"type":"string","maxLength":200000,"description":"Plain-text content, sent as simple HTML; give text or html"},"html":{"type":"string","maxLength":500000,"description":"HTML content; scripts, event handlers and javascript: links are refused"}}}`)},
			{Name: "delete_draft", Title: "Delete a draft", Description: "Deletes a draft broadcast for good. Only drafts; the preview names it.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["broadcast"],"properties":{` + broadcast + `}}`)},
			{Name: "schedule_broadcast", Title: "Schedule a broadcast", Description: "Schedules a draft broadcast to email its recipients at a time. The preview names the recipients, their count, the subject and the sender, and shows the content and its sha256, which the run must give: it's refused if the broadcast changed since. Undo unschedules it while it hasn't gone out.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["broadcast","at"],"properties":{` + broadcast + `,"at":{"type":"string","description":"When, like 2026-11-10T09:00:00Z"},"sha256":{"type":"string","pattern":"^[0-9a-f]{64}$","description":"The broadcast's sha256 from the preview; needed to run, refused if the broadcast changed since"}}}`)},
			{Name: "unschedule_broadcast", Title: "Unschedule a broadcast", Description: "Turns a scheduled broadcast back into a draft; nothing is sent. Undo schedules it again for the same time.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["broadcast"],"properties":{` + broadcast + `}}`)},
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
			return errors.New("the stored key doesn't look like a Kit v4 API key")
		}
		r.Header.Set("X-Kit-Api-Key", k)
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	now := m.Now
	if now == nil {
		now = time.Now
	}
	m.set.Put(id, &conn{api: api, now: now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Kit refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("Kit refused: %v", err)
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("Kit has no such broadcast or tag")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Kit's rate limit was hit; try again in a minute")
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
// HTML reads as written.
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

type filterPart struct {
	Type string `json:"type"`
	IDs  []int  `json:"ids,omitempty"`
}

type filter struct {
	All  []filterPart `json:"all"`
	Any  []filterPart `json:"any"`
	None []filterPart `json:"none"`
}

type broadcast struct {
	ID          int     `json:"id"`
	CreatedAt   string  `json:"created_at"`
	Subject     string  `json:"subject"`
	PreviewText string  `json:"preview_text"`
	Description string  `json:"description"`
	Content     string  `json:"content"`
	Public      bool    `json:"public"`
	PublishedAt *string `json:"published_at"`
	SendAt      *string `json:"send_at"`
	ThumbAlt    *string `json:"thumbnail_alt"`
	ThumbURL    *string `json:"thumbnail_url"`
	Email       string  `json:"email_address"`
	Template    *struct {
		ID int `json:"id"`
	} `json:"email_template"`
	Filter []filter `json:"subscriber_filter"`
}

// status is draft without a send time, scheduled with a future one and
// sent once it has passed.
func (b broadcast) status(now time.Time) string {
	if b.SendAt == nil || *b.SendAt == "" {
		return "draft"
	}
	if t, err := time.Parse(time.RFC3339, *b.SendAt); err == nil && t.After(now) {
		return "scheduled"
	}
	return "sent"
}

// audience describes the filter: all subscribers, or tag ids (any of). ok
// is false for a filter Conduit can't count (segments, exclusions…).
func (b broadcast) audience() (all bool, tags []int, ok bool) {
	if len(b.Filter) == 0 {
		return true, nil, true
	}
	if len(b.Filter) != 1 || len(b.Filter[0].None) > 0 {
		return false, nil, false
	}
	f := b.Filter[0]
	parts := append(append([]filterPart{}, f.All...), f.Any...)
	if len(parts) == 1 && parts[0].Type == "all_subscribers" {
		return true, nil, true
	}
	// Tags in "any" (or one tag in "all"): everyone with any of them.
	if len(f.All) > 1 || (len(f.All) == 1 && len(f.Any) > 0) {
		return false, nil, false
	}
	for _, p := range parts {
		if p.Type != "tag" || len(p.IDs) == 0 {
			return false, nil, false
		}
		tags = append(tags, p.IDs...)
	}
	if len(tags) == 0 || len(tags) > maxTags || (len(f.All) == 1 && len(tags) > 1) {
		return false, nil, false
	}
	return false, tags, true
}

func (b broadcast) brief(now time.Time) map[string]any {
	out := map[string]any{"broadcast": b.ID, "subject": clip(b.Subject, 200), "status": b.status(now), "public": b.Public, "created": b.CreatedAt}
	if b.SendAt != nil && *b.SendAt != "" {
		out["sendAt"] = *b.SendAt
	}
	if all, tags, ok := b.audience(); ok && all {
		out["recipients"] = "all subscribers"
	} else if ok {
		out["recipients"] = map[string]any{"tags": tags}
	} else {
		out["recipients"] = "a filter (see Kit)"
	}
	return out
}

func (c *conn) broadcast(ctx context.Context, id int) (broadcast, error) {
	if id <= 0 {
		return broadcast{}, errors.New("the broadcast is its numeric id (see broadcasts)")
	}
	var res struct {
		Broadcast broadcast `json:"broadcast"`
	}
	if err := c.do(ctx, http.MethodGet, "/broadcasts/"+strconv.Itoa(id), nil, nil, &res); err != nil {
		return broadcast{}, err
	}
	if res.Broadcast.ID != id {
		return broadcast{}, errors.New("unexpected answer from Kit")
	}
	return res.Broadcast, nil
}

func (c *conn) count(ctx context.Context, path, status string) (int, error) {
	q := url.Values{"per_page": {"1"}, "include_total_count": {"true"}}
	if status != "" {
		q.Set("status", status)
	}
	var res struct {
		Pagination struct {
			Total *int `json:"total_count"`
		} `json:"pagination"`
	}
	if err := c.do(ctx, http.MethodGet, path, q, nil, &res); err != nil {
		return 0, err
	}
	if res.Pagination.Total == nil {
		return 0, errors.New("Kit didn't return a count")
	}
	return *res.Pagination.Total, nil
}

func (c *conn) tagNames(ctx context.Context) (map[int]string, error) {
	var res struct {
		Tags []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"tags"`
	}
	if err := c.do(ctx, http.MethodGet, "/tags", url.Values{"per_page": {"1000"}}, nil, &res); err != nil {
		return nil, err
	}
	out := map[int]string{}
	for _, t := range res.Tags {
		out[t.ID] = clip(t.Name, 100)
	}
	return out, nil
}

// reach names a broadcast's recipients and counts them (an upper bound for
// several tags, which can overlap).
func (c *conn) reach(ctx context.Context, b broadcast) (string, int, error) {
	all, tags, ok := b.audience()
	if !ok {
		return "", 0, errors.New("this broadcast's recipients use a filter Conduit can't count (segments or exclusions); schedule it in Kit")
	}
	if all {
		n, err := c.count(ctx, "/subscribers", "active")
		return "all subscribers", n, err
	}
	names, err := c.tagNames(ctx)
	if err != nil {
		return "", 0, err
	}
	total := 0
	parts := []string{}
	for _, id := range tags {
		n, err := c.count(ctx, "/tags/"+strconv.Itoa(id)+"/subscribers", "active")
		if err != nil {
			return "", 0, err
		}
		name := names[id]
		if name == "" {
			name = "#" + strconv.Itoa(id)
		}
		total += n
		parts = append(parts, fmt.Sprintf("%s (%d)", name, n))
	}
	return "subscribers tagged " + strings.Join(parts, ", "), total, nil
}

func (c *conn) sender(ctx context.Context, b broadcast) string {
	if b.Email != "" {
		return clip(b.Email, 254)
	}
	var a struct {
		Account struct {
			Name  string `json:"name"`
			Email string `json:"primary_email_address"`
		} `json:"account"`
	}
	if c.do(ctx, http.MethodGet, "/account", nil, nil, &a) == nil && a.Account.Email != "" {
		return fmt.Sprintf("%s <%s>", clip(a.Account.Name, 100), clip(a.Account.Email, 254))
	}
	return "the account's sending address"
}

// sum is the fingerprint of what scheduling the broadcast would send and
// post: recipients, subject, preview text, sender, template, content and
// whether (and how) it's public.
func (b broadcast) sum() string {
	tmpl := 0
	if b.Template != nil {
		tmpl = b.Template.ID
	}
	return fingerprint(b.ID, b.Filter, b.Subject, b.PreviewText, b.Email, tmpl, b.Content, b.Public, b.ThumbURL, b.ThumbAlt)
}

// update sends the broadcast back with a new send time, keeping its other
// fields as they are.
func (c *conn) update(ctx context.Context, b broadcast, sendAt *string) (broadcast, error) {
	body := map[string]any{"subject": b.Subject, "preview_text": b.PreviewText, "description": b.Description, "content": b.Content,
		"public": b.Public, "send_at": sendAt, "subscriber_filter": b.Filter}
	if b.Email != "" {
		body["email_address"] = b.Email
	}
	if b.Template != nil && b.Template.ID > 0 {
		body["email_template_id"] = b.Template.ID
	}
	if b.ThumbURL != nil {
		body["thumbnail_url"], body["thumbnail_alt"] = *b.ThumbURL, b.ThumbAlt
	}
	if b.Public && b.PublishedAt != nil {
		body["published_at"] = *b.PublishedAt
	}
	var res struct {
		Broadcast broadcast `json:"broadcast"`
	}
	err := c.do(ctx, http.MethodPut, "/broadcasts/"+strconv.Itoa(b.ID), nil, body, &res)
	return res.Broadcast, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var a struct {
		Account struct {
			Name string `json:"name"`
			Plan string `json:"plan_type"`
		} `json:"account"`
	}
	if err := c.do(ctx, http.MethodGet, "/account", nil, nil, &a); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	n, err := c.count(ctx, "/subscribers", "active")
	if err != nil {
		return sdk.Health{Status: "degraded", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%s: %d active subscribers", clip(a.Account.Name, 80), n)}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Broadcast    int    `json:"broadcast"`
		Status       string `json:"status"`
		Tag          int    `json:"tag"`
		Limit        int    `json:"limit"`
		Subject      string `json:"subject"`
		PreviewText  string `json:"previewText"`
		Description  string `json:"description"`
		Tags         []int  `json:"tags"`
		EmailAddress string `json:"emailAddress"`
		Text         string `json:"text"`
		HTML         string `json:"html"`
		At           string `json:"at"`
		SHA256       string `json:"sha256"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if err := checkSHA(p.SHA256); err != nil {
		return sdk.Result{}, err
	}
	now := c.now()
	switch call.Action {
	case "subscribers_count":
		st := p.Status
		if st == "" {
			st = "active"
		}
		if !subStatuses[st] {
			return sdk.Result{}, errors.New("status is active, inactive, bounced, complained, cancelled or all")
		}
		if p.Tag < 0 {
			return sdk.Result{}, errors.New("the tag is its numeric id (see tags)")
		}
		path := "/subscribers"
		if p.Tag > 0 {
			path = "/tags/" + strconv.Itoa(p.Tag) + "/subscribers"
		}
		n, err := c.count(ctx, path, st)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"subscribers": n, "status": st}
		if p.Tag > 0 {
			out["tag"] = p.Tag
		}
		return sdk.JSON(out)

	case "tags":
		names, err := c.tagNames(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for id, n := range names {
			out = append(out, map[string]any{"tag": id, "name": n})
		}
		sort.Slice(out, func(i, j int) bool { return out[i]["tag"].(int) < out[j]["tag"].(int) })
		return sdk.JSON(out)

	case "broadcasts":
		n := p.Limit
		if n <= 0 {
			n = 20
		}
		if n > 100 {
			n = 100
		}
		var res struct {
			Broadcasts []broadcast `json:"broadcasts"`
		}
		if err := c.do(ctx, http.MethodGet, "/broadcasts", url.Values{"per_page": {"1000"}}, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		sort.SliceStable(res.Broadcasts, func(i, j int) bool { return res.Broadcasts[i].CreatedAt > res.Broadcasts[j].CreatedAt })
		out := []map[string]any{}
		for i, b := range res.Broadcasts {
			if i >= n {
				break
			}
			out = append(out, b.brief(now))
		}
		return sdk.JSON(out)

	case "broadcast_stats":
		if p.Broadcast <= 0 {
			return sdk.Result{}, errors.New("the broadcast is its numeric id (see broadcasts)")
		}
		var res struct {
			Broadcast struct {
				ID    int `json:"id"`
				Stats struct {
					Recipients   int     `json:"recipients"`
					OpenRate     float64 `json:"open_rate"`
					EmailsOpened int     `json:"emails_opened"`
					ClickRate    float64 `json:"click_rate"`
					TotalClicks  int     `json:"total_clicks"`
					Unsubscribes int     `json:"unsubscribes"`
					Status       string  `json:"status"`
					Progress     float64 `json:"progress"`
				} `json:"stats"`
			} `json:"broadcast"`
		}
		if err := c.do(ctx, http.MethodGet, "/broadcasts/"+strconv.Itoa(p.Broadcast)+"/stats", nil, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		if res.Broadcast.ID != p.Broadcast {
			return sdk.Result{}, errors.New("unexpected answer from Kit")
		}
		s := res.Broadcast.Stats
		return sdk.JSON(map[string]any{"broadcast": p.Broadcast, "status": clip(s.Status, 40), "progress": s.Progress, "recipients": s.Recipients, "opened": s.EmailsOpened,
			"openRate": s.OpenRate, "clicks": s.TotalClicks, "clickRate": s.ClickRate, "unsubscribes": s.Unsubscribes})

	case "create_draft":
		return c.createDraft(ctx, call, p.Subject, p.PreviewText, p.Description, p.EmailAddress, p.Text, p.HTML, p.Tags)

	case "delete_draft":
		b, err := c.broadcast(ctx, p.Broadcast)
		if err != nil {
			return sdk.Result{}, err
		}
		if st := b.status(now); st != "draft" {
			return sdk.Result{}, fmt.Errorf("the broadcast is %s; only drafts are deleted here", st)
		}
		if call.DryRun {
			before, _ := json.Marshal(b.brief(now))
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete the draft broadcast %q for good", clip(b.Subject, 80)),
				Changes: []sdk.Change{{Target: "broadcast " + strconv.Itoa(b.ID), Op: "delete", Before: before}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/broadcasts/"+strconv.Itoa(b.ID), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": b.ID})

	case "schedule_broadcast":
		at, err := time.Parse(time.RFC3339, strings.TrimSpace(p.At))
		if err != nil {
			return sdk.Result{}, errors.New("at is a time like 2026-11-10T09:00:00Z")
		}
		at = at.UTC().Truncate(time.Second)
		if !at.After(now.Add(time.Minute)) {
			return sdk.Result{}, errors.New("at must be in the future")
		}
		b, err := c.broadcast(ctx, p.Broadcast)
		if err != nil {
			return sdk.Result{}, err
		}
		switch b.status(now) {
		case "sent":
			return sdk.JSON(map[string]any{"broadcast": b.ID, "status": "sent", "note": "nothing to change: it has already gone out"})
		case "scheduled":
			if t, err := time.Parse(time.RFC3339, *b.SendAt); err == nil && t.Equal(at) {
				return sdk.JSON(map[string]any{"broadcast": b.ID, "status": "scheduled", "sendAt": *b.SendAt, "note": "nothing to change"})
			}
			return sdk.Result{}, fmt.Errorf("the broadcast is already scheduled for %s; unschedule it first", *b.SendAt)
		}
		if strings.TrimSpace(b.Subject) == "" || strings.TrimSpace(b.Content) == "" {
			return sdk.Result{}, errors.New("the broadcast needs a subject and content before it's scheduled")
		}
		when := at.Format(time.RFC3339)
		sum := b.sum()
		if call.DryRun {
			who, n, err := c.reach(ctx, b)
			if err != nil {
				return sdk.Result{}, err
			}
			from := c.sender(ctx, b)
			pub := ""
			if b.Public {
				pub = " It is public, so it's also posted on the creator profile."
			}
			// The content is authored, not personal data: shown in full, as sent.
			after := plain(map[string]any{"recipients": who, "count": n, "subject": b.Subject, "previewText": b.PreviewText, "from": from, "sendAt": when, "public": b.Public,
				"content": b.Content, "sha256": sum})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Schedule emailing %q from %s to %d %s at %s (content sha256 %s). Sent emails can't be recalled.%s%s", clip(b.Subject, 100), from, n, who, when, sum, pub, changedNote("broadcast", p.SHA256, sum)),
				Changes: []sdk.Change{{Target: "broadcast " + strconv.Itoa(b.ID), Op: "email", After: after}}}}, nil
		}
		if _, _, ok := b.audience(); !ok {
			return sdk.Result{}, errors.New("this broadcast's recipients use a filter Conduit can't count (segments or exclusions); schedule it in Kit")
		}
		if err := sameContent("broadcast", p.SHA256, sum); err != nil {
			return sdk.Result{}, err
		}
		after, err := c.update(ctx, b, &when)
		if err != nil {
			return sdk.Result{}, err
		}
		if after.ID != 0 && (after.SendAt == nil || *after.SendAt == "") {
			return sdk.Result{}, errors.New("Kit kept the broadcast unscheduled")
		}
		res, err := sdk.JSON(map[string]any{"broadcast": b.ID, "status": "scheduled", "sendAt": when})
		res.Undo = sdk.UndoWith("unschedule_broadcast", map[string]int{"broadcast": b.ID}, "Unschedule the broadcast")
		return res, err

	case "unschedule_broadcast":
		b, err := c.broadcast(ctx, p.Broadcast)
		if err != nil {
			return sdk.Result{}, err
		}
		switch b.status(now) {
		case "draft":
			return sdk.JSON(map[string]any{"broadcast": b.ID, "status": "draft", "note": "nothing to change: it isn't scheduled"})
		case "sent":
			return sdk.Result{}, errors.New("the broadcast has already gone out")
		}
		was := *b.SendAt
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Unschedule %q (was due %s); it becomes a draft and nothing is sent", clip(b.Subject, 80), was),
				Changes: []sdk.Change{{Target: "broadcast " + strconv.Itoa(b.ID), Op: "update", Before: json.RawMessage(strconv.Quote(was)), After: json.RawMessage(`"draft"`)}}}}, nil
		}
		if _, err := c.update(ctx, b, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"broadcast": b.ID, "status": "draft"})
		if t, perr := time.Parse(time.RFC3339, was); perr == nil {
			at := t.UTC().Format(time.RFC3339)
			res.Undo = sdk.UndoWith("schedule_broadcast", map[string]any{"broadcast": b.ID, "at": at, "sha256": b.sum()}, "Schedule the broadcast again for "+at)
		}
		return res, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) createDraft(ctx context.Context, call sdk.Call, subject, preview, desc, email, text, htm string, tags []int) (sdk.Result, error) {
	subject, preview, desc, email = strings.TrimSpace(subject), strings.TrimSpace(preview), strings.TrimSpace(desc), strings.TrimSpace(email)
	switch {
	case !oneLine(subject, 200):
		return sdk.Result{}, errors.New("the subject is up to 200 characters on one line")
	case preview != "" && !oneLine(preview, 200):
		return sdk.Result{}, errors.New("the previewText is up to 200 characters on one line")
	case desc != "" && !oneLine(desc, 200):
		return sdk.Result{}, errors.New("the description is up to 200 characters on one line")
	case email != "" && (len(email) > 254 || !emailRe.MatchString(email)):
		return sdk.Result{}, errors.New("emailAddress is one plain email address")
	case len(tags) > maxTags:
		return sdk.Result{}, fmt.Errorf("give at most %d tags", maxTags)
	case (strings.TrimSpace(text) == "") == (strings.TrimSpace(htm) == ""):
		return sdk.Result{}, errors.New("give the content as text (plain text) or as html, one of them")
	case len(text) > 200000 || len(htm) > 500000:
		return sdk.Result{}, errors.New("the content is too long")
	}
	if bad := unsafeHTML(htm); bad != "" {
		return sdk.Result{}, fmt.Errorf("the html has %s, which would run code in the web version of the email; remove it", bad)
	}
	for _, t := range tags {
		if t <= 0 {
			return sdk.Result{}, errors.New("tags are numeric tag ids (see tags)")
		}
	}
	format, content := "html", htm
	if htm == "" {
		format, content = "text", textHTML(text)
	}
	f := []filter{{All: []filterPart{{Type: "all_subscribers"}}}}
	who := "all subscribers"
	if len(tags) > 0 {
		names, err := c.tagNames(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		ns := []string{}
		for _, t := range tags {
			if names[t] == "" {
				return sdk.Result{}, fmt.Errorf("there's no tag %d", t)
			}
			ns = append(ns, names[t])
		}
		f = []filter{{Any: []filterPart{{Type: "tag", IDs: tags}}}}
		who = "subscribers tagged " + strings.Join(ns, ", ")
	}
	if call.DryRun {
		// The content is authored, not personal data: shown in full, as sent.
		after := plain(map[string]any{"subject": subject, "previewText": preview, "recipients": who, "emailAddress": email, "public": false, "format": format, "content": content})
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create the %s draft broadcast %q for %s; nothing is sent", format, clip(subject, 80), who),
			Changes: []sdk.Change{{Target: "broadcast " + clip(subject, 80), Op: "create", After: after}}}}, nil
	}
	body := map[string]any{"subject": subject, "content": content, "public": false, "send_at": nil, "subscriber_filter": f}
	if preview != "" {
		body["preview_text"] = preview
	}
	if desc != "" {
		body["description"] = desc
	}
	if email != "" {
		body["email_address"] = email
	}
	var res struct {
		Broadcast broadcast `json:"broadcast"`
	}
	if err := c.do(ctx, http.MethodPost, "/broadcasts", nil, body, &res); err != nil {
		return sdk.Result{}, err
	}
	if res.Broadcast.ID <= 0 {
		return sdk.Result{}, errors.New("unexpected answer from Kit")
	}
	r, err := sdk.JSON(map[string]any{"broadcast": res.Broadcast.ID, "status": "draft", "subject": subject, "recipients": who})
	r.Undo = sdk.UndoWith("delete_draft", map[string]int{"broadcast": res.Broadcast.ID}, "Delete the draft")
	return r, err
}
