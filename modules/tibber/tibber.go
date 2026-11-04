// Package tibber reads a Tibber account through its GraphQL API and a
// personal access token: the homes on the account (never their address or
// coordinates), the electricity price now and for today and tomorrow, and
// consumption over the last hours or days. It changes nothing.
package tibber

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Tibber account.
type Config struct {
	Token string `json:"token"` // secret:// personal access token
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.tibber.com/v1-beta (tests).
	Base string
}

// New returns the Tibber module.
func New() *Module { return &Module{} }

const (
	defaultBase = "https://api.tibber.com/v1-beta"
	maxHours    = 744 // 31 days
	maxDays     = 366
	maxPrices   = 96 // a day in quarter hours
	maxHomes    = 50
)

var homeRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	home := `"home":{"type":"string","description":"Home id (from homes); default: the first home"}`
	return sdk.Manifest{
		ID: "tibber", Name: "Tibber", Version: "0.1.0", Category: "Smart home", Icon: "gauge",
		Description: "Tibber: your homes, the electricity price now, today and tomorrow, and consumption over the last hours or days.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"A personal access token from developer.tibber.com (Settings, Access token)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "homes", Title: "Homes", Description: "The homes on the account: id, nickname, type, time zone, whether the subscription is running and whether live data (Pulse or Watty) is on. Never the address or coordinates.", Risk: sdk.RiskRead},
			{Name: "prices", Title: "Electricity prices", Description: "The price now with its level (very cheap to very expensive), and today's and tomorrow's prices (tomorrow's come around 13:00 CET), with the cheapest and dearest hour.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + home + `}}`)},
			{Name: "consumption", Title: "Consumption", Description: "Energy used and its cost for each of the last hours (up to 744, 31 days) or days (up to 366), with the totals.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + home + `,"resolution":{"type":"string","enum":["hourly","daily"],"default":"hourly"},"last":{"type":"integer","minimum":1,"maximum":744,"description":"How many hours (default 24, up to 744) or days (default 7, up to 366)"}}}`)},
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
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
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

var errToken = errors.New("Tibber refused the access token")

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && s[n]&0xc0 == 0x80 {
		n--
	}
	return s[:n] + "…"
}

// gql runs one fixed query; everything the caller chose goes in variables.
func (c *conn) gql(ctx context.Context, query string, vars map[string]any, out any) error {
	var r struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message    string `json:"message"`
			Extensions struct {
				Code string `json:"code"`
			} `json:"extensions"`
		} `json:"errors"`
	}
	body := map[string]any{"query": query}
	if len(vars) > 0 {
		body["variables"] = vars
	}
	_, err := c.api.Do(ctx, http.MethodPost, "/gql", nil, body, &r)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errToken
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Tibber's rate limit was hit; try again in a few minutes")
	case rest.IsStatus(err, http.StatusBadRequest) && strings.Contains(strings.ToLower(err.Error()), "token"):
		return errToken
	case err != nil:
		return err
	}
	if len(r.Errors) > 0 {
		e := r.Errors[0]
		if e.Extensions.Code == "UNAUTHENTICATED" || e.Extensions.Code == "UNAUTHORIZED" {
			return errToken
		}
		// Redacted first, so cutting it can't leave half a token behind.
		return errors.New("Tibber answered: " + clip(rest.Redact(e.Message), 200))
	}
	if out != nil {
		if len(r.Data) == 0 || string(r.Data) == "null" || json.Unmarshal(r.Data, out) != nil {
			return errors.New("unexpected answer from Tibber")
		}
	}
	return nil
}

type home struct {
	ID          string `json:"id"`
	AppNickname string `json:"appNickname"`
	Type        string `json:"type"`
	TimeZone    string `json:"timeZone"`
	Features    *struct {
		RealTime bool `json:"realTimeConsumptionEnabled"`
	} `json:"features"`
	CurrentSubscription *struct {
		Status string `json:"status"`
	} `json:"currentSubscription"`
	// The address, coordinates and owner aren't queried: they're personal
	// data and would end up in the audit log.
}

const homesQuery = `query { viewer { homes { id appNickname type timeZone features { realTimeConsumptionEnabled } currentSubscription { status } } } }`

func (c *conn) homes(ctx context.Context) ([]home, error) {
	var d struct {
		Viewer struct {
			Homes []home `json:"homes"`
		} `json:"viewer"`
	}
	if err := c.gql(ctx, homesQuery, nil, &d); err != nil {
		return nil, err
	}
	hs := d.Viewer.Homes
	if len(hs) > maxHomes {
		hs = hs[:maxHomes]
	}
	return hs, nil
}

// homeID returns the home asked for (checked), or the first home.
func (c *conn) homeID(ctx context.Context, asked string) (string, error) {
	if asked != "" {
		return asked, nil
	}
	hs, err := c.homes(ctx)
	if err != nil {
		return "", err
	}
	if len(hs) == 0 {
		return "", errors.New("there are no homes on this Tibber account")
	}
	return hs[0].ID, nil
}

type price struct {
	Total    *float64 `json:"total"`
	Energy   *float64 `json:"energy"`
	Tax      *float64 `json:"tax"`
	StartsAt string   `json:"startsAt"`
	Level    string   `json:"level"`
	Currency string   `json:"currency"`
}

const priceFields = `total energy tax startsAt level currency`

const pricesQuery = `query($id: ID!) { viewer { home(id: $id) { id currentSubscription { status priceInfo { current { ` + priceFields + ` } today { ` + priceFields + ` } tomorrow { ` + priceFields + ` } } } } } }`

const consumptionQuery = `query($id: ID!, $res: EnergyResolution!, $last: Int!) { viewer { home(id: $id) { id consumption(resolution: $res, last: $last) { nodes { from to consumption consumptionUnit cost unitPrice currency } } } } }`

func r4(p *float64) any {
	if p == nil {
		return nil
	}
	return math.Round(*p*10000) / 10000
}

func put(e map[string]any, k string, v any) {
	if v != nil {
		e[k] = v
	}
}

func priceOut(p price) map[string]any {
	e := map[string]any{"startsAt": p.StartsAt}
	put(e, "total", r4(p.Total))
	put(e, "energy", r4(p.Energy))
	put(e, "tax", r4(p.Tax))
	if p.Level != "" {
		e["level"] = strings.ToLower(p.Level)
	}
	return e
}

// day lists a day's prices with the cheapest and dearest slot.
func day(ps []price) map[string]any {
	if len(ps) > maxPrices {
		ps = ps[:maxPrices]
	}
	list := []map[string]any{}
	var lo, hi *price
	sum, n := 0.0, 0
	for i := range ps {
		p := &ps[i]
		list = append(list, priceOut(*p))
		if p.Total == nil {
			continue
		}
		sum, n = sum+*p.Total, n+1
		if lo == nil || *p.Total < *lo.Total {
			lo = p
		}
		if hi == nil || *p.Total > *hi.Total {
			hi = p
		}
	}
	out := map[string]any{"prices": list}
	if n > 0 {
		out["average"] = math.Round(sum/float64(n)*10000) / 10000
		out["cheapest"] = map[string]any{"startsAt": lo.StartsAt, "total": r4(lo.Total)}
		out["dearest"] = map[string]any{"startsAt": hi.StartsAt, "total": r4(hi.Total)}
	}
	return out
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	hs, err := c.homes(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	active := 0
	for _, h := range hs {
		if h.CurrentSubscription != nil && h.CurrentSubscription.Status == "running" {
			active++
		}
	}
	msg := fmt.Sprintf("%d home(s), %d with a running subscription", len(hs), active)
	if len(hs) == 0 {
		return sdk.Health{Status: "degraded", Message: "no homes on this account"}
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
		Home       string `json:"home"`
		Resolution string `json:"resolution"`
		Last       *int   `json:"last"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	p.Home = strings.TrimSpace(p.Home)
	if p.Home != "" && !homeRe.MatchString(p.Home) {
		return sdk.Result{}, errors.New("a home is its id from homes")
	}
	switch call.Action {
	case "homes":
		hs, err := c.homes(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, h := range hs {
			e := map[string]any{"id": h.ID, "type": strings.ToLower(h.Type), "timeZone": h.TimeZone, "realTimeData": h.Features != nil && h.Features.RealTime}
			if h.AppNickname != "" {
				e["nickname"] = h.AppNickname
			}
			if h.CurrentSubscription != nil {
				e["subscription"] = h.CurrentSubscription.Status
			} else {
				e["subscription"] = "none"
			}
			out = append(out, e)
		}
		return sdk.JSON(out)

	case "prices":
		id, err := c.homeID(ctx, p.Home)
		if err != nil {
			return sdk.Result{}, err
		}
		var d struct {
			Viewer struct {
				Home *struct {
					ID                  string `json:"id"`
					CurrentSubscription *struct {
						Status    string `json:"status"`
						PriceInfo *struct {
							Current  *price  `json:"current"`
							Today    []price `json:"today"`
							Tomorrow []price `json:"tomorrow"`
						} `json:"priceInfo"`
					} `json:"currentSubscription"`
				} `json:"home"`
			} `json:"viewer"`
		}
		if err := c.gql(ctx, pricesQuery, map[string]any{"id": id}, &d); err != nil {
			return sdk.Result{}, err
		}
		h := d.Viewer.Home
		if h == nil {
			return sdk.Result{}, fmt.Errorf("there's no home %s on this account (see homes)", id)
		}
		if h.CurrentSubscription == nil || h.CurrentSubscription.PriceInfo == nil {
			return sdk.Result{}, errors.New("this home has no subscription with prices")
		}
		pi := h.CurrentSubscription.PriceInfo
		out := map[string]any{"home": id, "today": day(pi.Today)}
		if len(pi.Tomorrow) > 0 {
			out["tomorrow"] = day(pi.Tomorrow)
		} else {
			out["tomorrow"] = nil
			out["note"] = "tomorrow's prices aren't published yet (usually around 13:00 CET)"
		}
		if pi.Current != nil {
			out["current"] = priceOut(*pi.Current)
			if pi.Current.Currency != "" {
				out["currency"] = pi.Current.Currency
			}
		}
		return sdk.JSON(out)

	case "consumption":
		res, def, limit := "HOURLY", 24, maxHours
		switch p.Resolution {
		case "", "hourly":
		case "daily":
			res, def, limit = "DAILY", 7, maxDays
		default:
			return sdk.Result{}, errors.New("resolution is hourly or daily")
		}
		n := def
		if p.Last != nil {
			n = *p.Last
		}
		if n < 1 || n > limit {
			return sdk.Result{}, fmt.Errorf("last is between 1 and %d for %s data", limit, strings.ToLower(res))
		}
		id, err := c.homeID(ctx, p.Home)
		if err != nil {
			return sdk.Result{}, err
		}
		var d struct {
			Viewer struct {
				Home *struct {
					Consumption *struct {
						Nodes []struct {
							From        string   `json:"from"`
							To          string   `json:"to"`
							Consumption *float64 `json:"consumption"`
							Unit        string   `json:"consumptionUnit"`
							Cost        *float64 `json:"cost"`
							UnitPrice   *float64 `json:"unitPrice"`
							Currency    string   `json:"currency"`
						} `json:"nodes"`
					} `json:"consumption"`
				} `json:"home"`
			} `json:"viewer"`
		}
		if err := c.gql(ctx, consumptionQuery, map[string]any{"id": id, "res": res, "last": n}, &d); err != nil {
			return sdk.Result{}, err
		}
		if d.Viewer.Home == nil {
			return sdk.Result{}, fmt.Errorf("there's no home %s on this account (see homes)", id)
		}
		list := []map[string]any{}
		total, cost, currency, unit := 0.0, 0.0, "", "kWh"
		if d.Viewer.Home.Consumption != nil {
			nodes := d.Viewer.Home.Consumption.Nodes
			if len(nodes) > limit {
				nodes = nodes[len(nodes)-limit:]
			}
			for _, x := range nodes {
				e := map[string]any{"from": x.From, "to": x.To}
				put(e, "consumption", r4(x.Consumption))
				put(e, "cost", r4(x.Cost))
				put(e, "unitPrice", r4(x.UnitPrice))
				if x.Consumption != nil {
					total += *x.Consumption
				}
				if x.Cost != nil {
					cost += *x.Cost
				}
				if x.Currency != "" {
					currency = x.Currency
				}
				if x.Unit != "" {
					unit = x.Unit
				}
				list = append(list, e)
			}
		}
		out := map[string]any{"home": id, "resolution": strings.ToLower(res), "unit": unit, "total": math.Round(total*1000) / 1000, "totalCost": math.Round(cost*100) / 100, "periods": list}
		if currency != "" {
			out["currency"] = currency
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
