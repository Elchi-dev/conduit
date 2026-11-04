package games

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// owned lists owned Steam games and hours through the Steam Web API.
func (m *Module) owned(ctx context.Context) (sdk.Result, error) {
	m.mu.Lock()
	cfg, h := m.cfg, m.host
	m.mu.Unlock()
	if cfg.APIKey == "" || h == nil {
		return sdk.Result{}, errors.New("add a Steam Web API key and your Steam id in the settings")
	}
	key, err := h.Secret(ctx, cfg.APIKey)
	if err != nil {
		return sdk.Result{}, err
	}
	q := url.Values{"key": {key}, "steamid": {cfg.SteamID}, "include_appinfo": {"1"}, "format": {"json"}}
	req, _ := http.NewRequestWithContext(ctx, "GET", m.API+"/IPlayerService/GetOwnedGames/v1/?"+q.Encode(), nil)
	res, err := m.HTTP.Do(req)
	if err != nil {
		return sdk.Result{}, errors.New("couldn't reach Steam") // never echo the URL: it holds the key
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return sdk.Result{}, fmt.Errorf("Steam answered %s; check the key and Steam id", res.Status)
	}
	var d struct {
		Response struct {
			Games []struct {
				AppID    int    `json:"appid"`
				Name     string `json:"name"`
				Playtime int    `json:"playtime_forever"`
				Recent   int    `json:"playtime_2weeks"`
			} `json:"games"`
		} `json:"response"`
	}
	if err := json.NewDecoder(res.Body).Decode(&d); err != nil {
		return sdk.Result{}, err
	}
	type row struct {
		AppID  int     `json:"appId"`
		Name   string  `json:"name"`
		Hours  float64 `json:"hours"`
		Recent float64 `json:"lastTwoWeeks"`
	}
	out := []row{}
	for _, g := range d.Response.Games {
		out = append(out, row{AppID: g.AppID, Name: g.Name, Hours: float64(g.Playtime/6) / 10, Recent: float64(g.Recent/6) / 10})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hours > out[j].Hours })
	return sdk.JSON(out)
}
