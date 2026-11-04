// Package openxbl reads an Xbox Live account through OpenXBL (xbl.io) with
// its API key: the profile, friends and their presence, recent achievements
// and the titles played. It's read-only.
package openxbl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one OpenXBL key.
type Config struct {
	APIKey string `json:"apiKey"` // secret:// OpenXBL API key
}

type conn struct {
	api *rest.Client

	mu   sync.Mutex
	xuid string // the account's, learned from /account
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// API replaces https://xbl.io/api/v2 and HTTP the client (tests).
	API  string
	HTTP *http.Client
}

// New returns the OpenXBL module.
func New() *Module { return &Module{} }

var digitsRe = regexp.MustCompile(`^[0-9]{1,20}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "openxbl", Name: "Xbox (OpenXBL)", Version: "0.1.0", Category: "Gaming", Icon: "gamepad",
		Description: "Your Xbox profile, which friends are online and what they play, recent achievements and the games you've played, through OpenXBL.",
		Presets:     []string{"gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey"],"properties":{
			"apiKey":{"type":"string","x-secret":true,"description":"OpenXBL API key (xbl.io, sign in with your Xbox account, Profile, API keys)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "profile", Title: "Profile", Description: "Gamertag, gamerscore, tier and what you're doing now.", Risk: sdk.RiskRead},
			{Name: "friends", Title: "Friends", Description: "Friends with their presence and current game, online first. It names other people, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"onlineOnly":{"type":"boolean","default":false}}}`)},
			{Name: "achievements", Title: "Recent achievements", Description: "Achievements unlocked lately, across the last games played or in one game.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"titleId":{"type":"string","description":"Only this game (its title id, from titles)"},"count":{"type":"integer","minimum":1,"maximum":50,"default":10}}}`)},
			{Name: "titles", Title: "Games played", Description: "Games played, most recent first, with achievement and gamerscore progress.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"count":{"type":"integer","minimum":1,"maximum":200,"default":25}}}`)},
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
		return errors.New("store the OpenXBL API key in the vault and enter its secret:// reference")
	}
	key := c.APIKey
	base := m.API
	if base == "" {
		base = "https://xbl.io/api/v2"
	}
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, key)
		if err != nil {
			return err
		}
		r.Header.Set("X-Authorization", strings.TrimSpace(k))
		return nil
	})
	api.Header.Set("Accept-Language", "en-US")
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 30*time.Second)
	}
	// The key travels in X-Authorization, which Go would forward to another host.
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, path string, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, nil, nil, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden):
		return errors.New("OpenXBL refused the API key")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("OpenXBL's hourly request limit is reached; try again later")
	}
	return err
}

type account struct {
	XUID     string
	Settings map[string]string
}

func (c *conn) account(ctx context.Context) (account, error) {
	var r struct {
		Users []struct {
			ID       string `json:"id"`
			Settings []struct {
				ID    string `json:"id"`
				Value string `json:"value"`
			} `json:"settings"`
		} `json:"profileUsers"`
	}
	if err := c.do(ctx, "/account", &r); err != nil {
		return account{}, err
	}
	if len(r.Users) == 0 || !digitsRe.MatchString(r.Users[0].ID) {
		return account{}, errors.New("OpenXBL didn't return the account")
	}
	a := account{XUID: r.Users[0].ID, Settings: map[string]string{}}
	for _, s := range r.Users[0].Settings {
		a.Settings[s.ID] = s.Value
	}
	c.mu.Lock()
	c.xuid = a.XUID
	c.mu.Unlock()
	return a, nil
}

func (c *conn) myXUID(ctx context.Context) (string, error) {
	c.mu.Lock()
	x := c.xuid
	c.mu.Unlock()
	if x != "" {
		return x, nil
	}
	a, err := c.account(ctx)
	return a.XUID, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	a, err := c.account(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: a.Settings["Gamertag"]}
}

type title struct {
	TitleID     string `json:"titleId"`
	Name        string `json:"name"`
	Devices     []string
	Achievement struct {
		Current      int     `json:"currentAchievements"`
		Total        int     `json:"totalAchievements"`
		Score        int     `json:"currentGamerscore"`
		TotalScore   int     `json:"totalGamerscore"`
		ProgressPerc float64 `json:"progressPercentage"`
	} `json:"achievement"`
	History struct {
		LastPlayed string `json:"lastTimePlayed"`
	} `json:"titleHistory"`
}

func (c *conn) titles(ctx context.Context) ([]title, error) {
	var r struct {
		Titles []title `json:"titles"`
	}
	if err := c.do(ctx, "/achievements", &r); err != nil {
		return nil, err
	}
	sort.SliceStable(r.Titles, func(i, j int) bool { return r.Titles[i].History.LastPlayed > r.Titles[j].History.LastPlayed })
	return r.Titles, nil
}

type input struct {
	OnlineOnly bool   `json:"onlineOnly"`
	TitleID    string `json:"titleId"`
	Count      int    `json:"count"`
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
	case "achievements":
		if p.Count == 0 {
			p.Count = 10
		}
		if p.Count < 1 || p.Count > 50 {
			return sdk.Result{}, errors.New("count is 1 to 50")
		}
		p.TitleID = strings.TrimSpace(p.TitleID)
		if p.TitleID != "" && !digitsRe.MatchString(p.TitleID) {
			return sdk.Result{}, errors.New("the title id is a number, from titles")
		}
	case "titles":
		if p.Count == 0 {
			p.Count = 25
		}
		if p.Count < 1 || p.Count > 200 {
			return sdk.Result{}, errors.New("count is 1 to 200")
		}
	}

	switch call.Action {
	case "profile":
		a, err := c.account(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"xuid": a.XUID, "gamertag": a.Settings["Gamertag"], "tier": a.Settings["AccountTier"], "reputation": a.Settings["XboxOneRep"]}
		if n, err := strconv.Atoi(a.Settings["Gamerscore"]); err == nil {
			out["gamerscore"] = n
		}
		var pr []struct {
			State   string `json:"state"`
			Devices []struct {
				Type   string `json:"type"`
				Titles []struct {
					Name      string `json:"name"`
					Placement string `json:"placement"`
					State     string `json:"state"`
				} `json:"titles"`
			} `json:"devices"`
		}
		var one struct {
			State string `json:"state"`
		}
		var raw json.RawMessage
		if c.do(ctx, "/presence", &raw) == nil {
			if json.Unmarshal(raw, &pr) != nil && json.Unmarshal(raw, &one) == nil {
				out["presence"] = one.State
			}
			if len(pr) > 0 {
				out["presence"] = pr[0].State
				for _, d := range pr[0].Devices {
					for _, t := range d.Titles {
						if t.Placement == "Full" && t.Name != "Home" && t.Name != "Online" {
							out["playing"], out["device"] = t.Name, d.Type
						}
					}
				}
			}
		}
		return sdk.JSON(out)

	case "friends":
		var r struct {
			People []struct {
				XUID       string `json:"xuid"`
				Gamertag   string `json:"gamertag"`
				Display    string `json:"displayName"`
				Favorite   bool   `json:"isFavorite"`
				Presence   string `json:"presenceState"`
				Text       string `json:"presenceText"`
				Gamerscore string `json:"gamerScore"`
			} `json:"people"`
		}
		if err := c.do(ctx, "/friends", &r); err != nil {
			return sdk.Result{}, err
		}
		people := r.People
		sort.SliceStable(people, func(i, j int) bool {
			oi, oj := people[i].Presence == "Online", people[j].Presence == "Online"
			if oi != oj {
				return oi
			}
			return strings.ToLower(people[i].Gamertag) < strings.ToLower(people[j].Gamertag)
		})
		out := []map[string]any{}
		online := 0
		for _, f := range people {
			on := f.Presence == "Online"
			if on {
				online++
			}
			if p.OnlineOnly && !on {
				continue
			}
			row := map[string]any{"xuid": f.XUID, "gamertag": f.Gamertag, "online": on, "presence": f.Text}
			if f.Favorite {
				row["favorite"] = true
			}
			if n, err := strconv.Atoi(f.Gamerscore); err == nil {
				row["gamerscore"] = n
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"total": len(people), "online": online, "friends": out})

	case "titles":
		list, err := c.titles(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, t := range list {
			if len(out) >= p.Count {
				break
			}
			a := t.Achievement
			out = append(out, map[string]any{"titleId": t.TitleID, "name": t.Name, "lastPlayed": t.History.LastPlayed, "devices": t.Devices,
				"achievements": a.Current, "totalAchievements": a.Total, "gamerscore": a.Score, "totalGamerscore": a.TotalScore, "progress": a.ProgressPerc})
		}
		return sdk.JSON(out)

	case "achievements":
		xuid, err := c.myXUID(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		ids := []string{p.TitleID}
		if p.TitleID == "" {
			list, err := c.titles(ctx)
			if err != nil {
				return sdk.Result{}, err
			}
			ids = nil
			for _, t := range list {
				if t.Achievement.Current > 0 && digitsRe.MatchString(t.TitleID) {
					ids = append(ids, t.TitleID)
				}
				if len(ids) == 3 { // the free plan allows 150 calls an hour
					break
				}
			}
		}
		type unlocked struct {
			Name        string `json:"name"`
			Game        string `json:"game"`
			Description string `json:"description,omitempty"`
			Unlocked    string `json:"unlocked"`
			Gamerscore  int    `json:"gamerscore,omitempty"`
			Rarity      string `json:"rarity,omitempty"`
		}
		got := []unlocked{}
		for _, id := range ids {
			var r struct {
				List []struct {
					Name        string `json:"name"`
					Description string `json:"description"`
					State       string `json:"progressState"`
					Titles      []struct {
						Name string `json:"name"`
					} `json:"titleAssociations"`
					Progression struct {
						Unlocked string `json:"timeUnlocked"`
					} `json:"progression"`
					Rewards []struct {
						Type  string `json:"type"`
						Value string `json:"value"`
					} `json:"rewards"`
					Rarity struct {
						Category string  `json:"currentCategory"`
						Percent  float64 `json:"currentPercentage"`
					} `json:"rarity"`
				} `json:"achievements"`
			}
			if err := c.do(ctx, "/achievements/player/"+xuid+"/"+id, &r); err != nil {
				return sdk.Result{}, err
			}
			for _, a := range r.List {
				if a.State != "Achieved" {
					continue
				}
				u := unlocked{Name: a.Name, Description: a.Description, Unlocked: a.Progression.Unlocked}
				if len(a.Titles) > 0 {
					u.Game = a.Titles[0].Name
				}
				for _, rw := range a.Rewards {
					if rw.Type == "Gamerscore" {
						u.Gamerscore, _ = strconv.Atoi(rw.Value)
					}
				}
				if a.Rarity.Category != "" {
					u.Rarity = fmt.Sprintf("%s (%.1f%%)", a.Rarity.Category, a.Rarity.Percent)
				}
				got = append(got, u)
			}
		}
		sort.SliceStable(got, func(i, j int) bool { return got[i].Unlocked > got[j].Unlocked })
		if len(got) > p.Count {
			got = got[:p.Count]
		}
		return sdk.JSON(got)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
