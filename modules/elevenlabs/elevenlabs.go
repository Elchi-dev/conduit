// Package elevenlabs reads an ElevenLabs account through its API and an API
// key: the subscription with characters used and left, character usage by
// day, voices, and the generation history. Nothing it does spends
// characters.
package elevenlabs

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

// Config is one ElevenLabs account.
type Config struct {
	APIKey string `json:"apiKey"` // secret://
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.elevenlabs.io (tests).
	Base string
	// now replaces time.Now (tests).
	now func() time.Time
}

// New returns the ElevenLabs module.
func New() *Module { return &Module{} }

var (
	idRe       = regexp.MustCompile(`^[A-Za-z0-9]{1,40}$`)
	categories = map[string]bool{"premade": true, "cloned": true, "generated": true, "professional": true, "famous": true, "high_quality": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "elevenlabs", Name: "ElevenLabs", Version: "0.1.0", Category: "Media", Icon: "music",
		Description: "ElevenLabs: the subscription with characters used and left, usage by day, voices, and the generation history. Read-only.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey"],"properties":{
			"apiKey":{"type":"string","x-secret":true,"description":"API key (elevenlabs.io, Developers, API Keys). A restricted key needs read access to User, Voices and History"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "subscription", Title: "Subscription", Description: "Plan and status, characters used, limit and left, when they reset, voice slots used and allowed, and the next invoice.", Risk: sdk.RiskRead},
			{Name: "usage", Title: "Character usage", Description: "Characters used per day over the last days (30 by default), with the total.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"days":{"type":"integer","minimum":1,"maximum":90,"default":30}}}`)},
			{Name: "voices", Title: "Voices", Description: "Voices in the account: id, name, category (premade, cloned, generated, professional), labels and description. Never the voice samples.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"category":{"type":"string","enum":["premade","cloned","generated","professional","famous","high_quality"],"description":"Only voices of this category"}}}`)},
			{Name: "history", Title: "History", Description: "Recent generations, newest first: date, voice, model, characters used and the text spoken. The text can hold personal data (sensitive).", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":100,"default":20},"voice":{"type":"string","description":"Only this voice id"},"after":{"type":"string","description":"The next value from an earlier page"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	base := "https://api.elevenlabs.io"
	if m.Base != "" {
		base = m.Base
	}
	ref := c.APIKey
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("xi-api-key", strings.TrimSpace(k))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	// The key travels in its own header, which Go would forward on a
	// redirect to another host: SameHostOnly refuses those.
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("ElevenLabs refused the API key (or the key lacks the permission for this)")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("ElevenLabs refused: the API key lacks the permission for this")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err)
}

type subscription struct {
	Tier                string `json:"tier"`
	Status              string `json:"status"`
	CharacterCount      int64  `json:"character_count"`
	CharacterLimit      int64  `json:"character_limit"`
	CanExtend           bool   `json:"can_extend_character_limit"`
	NextReset           int64  `json:"next_character_count_reset_unix"`
	VoiceSlotsUsed      *int   `json:"voice_slots_used"`
	VoiceLimit          int    `json:"voice_limit"`
	ProfessionalLimit   int    `json:"professional_voice_limit"`
	Currency            string `json:"currency"`
	BillingPeriod       string `json:"billing_period"`
	CharacterRefreshPer string `json:"character_refresh_period"`
	NextInvoice         *struct {
		AmountDueCents int64 `json:"amount_due_cents"`
		NextAttempt    int64 `json:"next_payment_attempt_unix"`
	} `json:"next_invoice"`
}

func unix(s int64) string {
	if s <= 0 {
		return ""
	}
	return time.Unix(s, 0).UTC().Format(time.RFC3339)
}

func (c *conn) subscription(ctx context.Context) (subscription, error) {
	var s subscription
	err := c.get(ctx, "/v1/user/subscription", nil, &s)
	return s, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	s, err := c.subscription(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("%s plan, %d of %d characters used", s.Tier, s.CharacterCount, s.CharacterLimit)
	if s.CharacterLimit > 0 && s.CharacterCount >= s.CharacterLimit {
		return sdk.Health{Status: "degraded", Message: msg + "; none left until " + unix(s.NextReset)}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Days     int    `json:"days"`
		Category string `json:"category"`
		Limit    int    `json:"limit"`
		Voice    string `json:"voice"`
		After    string `json:"after"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "subscription":
		s, err := c.subscription(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		left := s.CharacterLimit - s.CharacterCount
		if left < 0 {
			left = 0
		}
		out := map[string]any{"tier": s.Tier, "status": s.Status, "charactersUsed": s.CharacterCount, "characterLimit": s.CharacterLimit, "charactersLeft": left,
			"canExtendLimit": s.CanExtend, "voiceLimit": s.VoiceLimit, "professionalVoiceLimit": s.ProfessionalLimit}
		if r := unix(s.NextReset); r != "" {
			out["resets"] = r
		}
		if s.VoiceSlotsUsed != nil {
			out["voiceSlotsUsed"] = *s.VoiceSlotsUsed
		}
		if s.BillingPeriod != "" {
			out["billingPeriod"] = s.BillingPeriod
		}
		if s.NextInvoice != nil {
			out["nextInvoice"] = map[string]any{"amount": float64(s.NextInvoice.AmountDueCents) / 100, "currency": strings.ToUpper(s.Currency), "date": unix(s.NextInvoice.NextAttempt)}
		}
		return sdk.JSON(out)
	case "usage":
		if p.Days == 0 {
			p.Days = 30
		}
		if p.Days < 1 || p.Days > 90 {
			return sdk.Result{}, errors.New("days is 1 to 90")
		}
		now := time.Now
		if m.now != nil {
			now = m.now
		}
		end := now().UTC()
		start := end.AddDate(0, 0, -p.Days)
		q := url.Values{"start_unix": {strconv.FormatInt(start.UnixMilli(), 10)}, "end_unix": {strconv.FormatInt(end.UnixMilli(), 10)}, "aggregation_interval": {"day"}}
		var out struct {
			Time  []int64              `json:"time"`
			Usage map[string][]float64 `json:"usage"`
		}
		if err := c.get(ctx, "/v1/usage/character-stats", q, &out); err != nil {
			return sdk.Result{}, err
		}
		all := out.Usage["All"]
		if all == nil {
			// One breakdown only: add the series up.
			for _, s := range out.Usage {
				if all == nil {
					all = make([]float64, len(s))
				}
				for i := range s {
					if i < len(all) {
						all[i] += s[i]
					}
				}
			}
		}
		days := []map[string]any{}
		var total float64
		for i, t := range out.Time {
			var n float64
			if i < len(all) {
				n = all[i]
			}
			total += n
			days = append(days, map[string]any{"date": time.UnixMilli(t).UTC().Format("2006-01-02"), "characters": n})
		}
		return sdk.JSON(map[string]any{"days": days, "total": total, "from": start.Format("2006-01-02"), "to": end.Format("2006-01-02")})
	case "voices":
		if p.Category != "" && !categories[p.Category] {
			return sdk.Result{}, errors.New("category is premade, cloned, generated, professional, famous or high_quality")
		}
		var out struct {
			Voices []struct {
				ID          string            `json:"voice_id"`
				Name        string            `json:"name"`
				Category    string            `json:"category"`
				Labels      map[string]string `json:"labels"`
				Description string            `json:"description"`
				CreatedAt   int64             `json:"created_at_unix"`
				IsOwner     *bool             `json:"is_owner"`
				// Samples, the preview and the fine-tuning recordings
				// aren't decoded.
			} `json:"voices"`
		}
		if err := c.get(ctx, "/v1/voices", nil, &out); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, v := range out.Voices {
			if p.Category != "" && v.Category != p.Category {
				continue
			}
			row := map[string]any{"id": v.ID, "name": v.Name, "category": v.Category}
			if len(v.Labels) > 0 {
				row["labels"] = v.Labels
			}
			if v.Description != "" {
				row["description"] = clip(v.Description, 300)
			}
			if t := unix(v.CreatedAt); t != "" {
				row["created"] = t
			}
			if v.IsOwner != nil {
				row["yours"] = *v.IsOwner
			}
			list = append(list, row)
		}
		return sdk.JSON(list)
	case "history":
		if p.Limit == 0 {
			p.Limit = 20
		}
		if p.Limit < 1 || p.Limit > 100 {
			return sdk.Result{}, errors.New("limit is 1 to 100")
		}
		q := url.Values{"page_size": {strconv.Itoa(p.Limit)}}
		for k, v := range map[string]string{"voice_id": p.Voice, "start_after_history_item_id": p.After} {
			if v = strings.TrimSpace(v); v == "" {
				continue
			}
			if !idRe.MatchString(v) {
				return sdk.Result{}, errors.New("voice and after are ids from voices and history")
			}
			q.Set(k, v)
		}
		var out struct {
			History []struct {
				ID        string `json:"history_item_id"`
				VoiceID   string `json:"voice_id"`
				VoiceName string `json:"voice_name"`
				ModelID   string `json:"model_id"`
				Text      string `json:"text"`
				Date      int64  `json:"date_unix"`
				From      int64  `json:"character_count_change_from"`
				To        int64  `json:"character_count_change_to"`
				Source    string `json:"source"`
				State     string `json:"state"`
			} `json:"history"`
			HasMore bool   `json:"has_more"`
			Last    string `json:"last_history_item_id"`
		}
		if err := c.get(ctx, "/v1/history", q, &out); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, x := range out.History {
			row := map[string]any{"id": x.ID, "date": unix(x.Date), "voice": x.VoiceName, "voiceId": x.VoiceID, "model": x.ModelID,
				"characters": x.To - x.From, "text": clip(x.Text, 500)}
			if x.Source != "" {
				row["source"] = x.Source
			}
			list = append(list, row)
		}
		res := map[string]any{"history": list}
		if out.HasMore && idRe.MatchString(out.Last) {
			res["next"] = out.Last
		}
		return sdk.JSON(res)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
