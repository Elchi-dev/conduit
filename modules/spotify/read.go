package spotify

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// input is every field any action takes.
type input struct {
	URI          string   `json:"uri"`
	URIs         []string `json:"uris"`
	Device       string   `json:"device"`
	Percent      *int     `json:"percent"`
	Query        string   `json:"query"`
	Type         string   `json:"type"`
	Types        []string `json:"types"`
	Limit        int      `json:"limit"`
	Offset       int      `json:"offset"`
	Range        string   `json:"range"`
	Playlist     string   `json:"playlist"`
	PositionMS   *int     `json:"positionMs"`
	Seconds      *int     `json:"seconds"`
	StartAt      string   `json:"startAt"`
	On           *bool    `json:"on"`
	Mode         string   `json:"mode"`
	Play         *bool    `json:"play"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Public       bool     `json:"public"`
	Position     *int     `json:"position"`
	RangeStart   *int     `json:"rangeStart"`
	InsertBefore *int     `json:"insertBefore"`
	RangeLength  int      `json:"rangeLength"`
	Since        string   `json:"since"`
	Until        string   `json:"until"`
	Artist       string   `json:"artist"`
	Days         int      `json:"days"`
	Top          int      `json:"top"`
	RedirectURI  string   `json:"redirectUri"`
	// undo-only
	Restore []restoreAt `json:"restore"`
	Context string      `json:"context"`
	Snap    string      `json:"snapshot"`
}

type restoreAt struct {
	URI      string `json:"uri"`
	Position int    `json:"position"`
}

func limit(n, def, max int) string {
	if n <= 0 {
		n = def
	}
	if n > max {
		n = max
	}
	return strconv.Itoa(n)
}

func page(p input, def, max int) url.Values {
	q := url.Values{"limit": {limit(p.Limit, def, max)}}
	if p.Offset > 0 {
		q.Set("offset", strconv.Itoa(p.Offset))
	}
	return q
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
	if p.Device != "" && !deviceRe.MatchString(p.Device) {
		return sdk.Result{}, errors.New("that isn't a Spotify device id; see devices")
	}
	r, err := m.invoke(ctx, c, call, p)
	if err != nil {
		return sdk.Result{}, friendly(err)
	}
	return r, nil
}

func (m *Module) invoke(ctx context.Context, c *conn, call sdk.Call, p input) (sdk.Result, error) {
	switch call.Action {
	case "now_playing":
		return c.nowPlaying(ctx)

	case "recently_played":
		var pg recentPage
		if err := c.do(ctx, "GET", "/me/player/recently-played", url.Values{"limit": {limit(p.Limit, 20, 50)}}, nil, &pg); err != nil {
			return sdk.Result{}, err
		}
		if c.hist != nil {
			_, _ = c.hist.add(pg.plays())
		}
		type row struct {
			Track
			PlayedAt string `json:"playedAt"`
			Context  string `json:"context,omitempty"`
		}
		out := []row{}
		for _, it := range pg.Items {
			r := row{Track: it.Track.out(), PlayedAt: it.PlayedAt.In(c.tz).Format(time.RFC3339)}
			if it.Context != nil {
				r.Context = it.Context.URI
			}
			out = append(out, r)
		}
		return sdk.JSON(out)

	case "top_tracks", "top_artists":
		rng := p.Range
		if rng == "" {
			rng = "medium"
		}
		if rng != "short" && rng != "medium" && rng != "long" {
			return sdk.Result{}, errors.New("range is short, medium or long")
		}
		q := page(p, 20, 50)
		q.Set("time_range", rng+"_term")
		if call.Action == "top_tracks" {
			var pg struct{ Items []item }
			if err := c.do(ctx, "GET", "/me/top/tracks", q, nil, &pg); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(tracks(pg.Items))
		}
		var pg struct{ Items []artist }
		if err := c.do(ctx, "GET", "/me/top/artists", q, nil, &pg); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(artists(pg.Items))

	case "saved_tracks":
		var pg struct {
			Total int
			Items []struct {
				AddedAt string `json:"added_at"`
				Track   item   `json:"track"`
			}
		}
		if err := c.do(ctx, "GET", "/me/tracks", page(p, 20, 50), nil, &pg); err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			Track
			Added string `json:"added"`
		}
		out := []row{}
		for _, it := range pg.Items {
			out = append(out, row{it.Track.out(), it.AddedAt})
		}
		return sdk.JSON(map[string]any{"total": pg.Total, "tracks": out})

	case "saved_albums":
		var pg struct {
			Total int
			Items []struct {
				AddedAt string `json:"added_at"`
				Album   album  `json:"album"`
			}
		}
		if err := c.do(ctx, "GET", "/me/albums", page(p, 20, 50), nil, &pg); err != nil {
			return sdk.Result{}, err
		}
		out := []Album{}
		for _, it := range pg.Items {
			a := it.Album
			a.Tracks = nil
			out = append(out, a.out())
		}
		return sdk.JSON(map[string]any{"total": pg.Total, "albums": out})

	case "playlists":
		var pg struct {
			Total int
			Items []playlist
		}
		if err := c.do(ctx, "GET", "/me/playlists", page(p, 20, 50), nil, &pg); err != nil {
			return sdk.Result{}, err
		}
		me := c.me(ctx)
		out := []Playlist{}
		for _, pl := range pg.Items {
			out = append(out, pl.out(me))
		}
		return sdk.JSON(map[string]any{"total": pg.Total, "playlists": out})

	case "playlist_tracks":
		r, err := parseKind(p.Playlist, "playlist")
		if err != nil {
			return sdk.Result{}, err
		}
		var pl playlist
		if err := c.do(ctx, "GET", "/playlists/"+r.ID, url.Values{"fields": {"id,name,uri,owner,snapshot_id,description,public,collaborative"}}, nil, &pl); err != nil {
			return sdk.Result{}, err
		}
		entries, total, err := c.playlistItems(ctx, r.ID, p.Offset, atoiDef(limit(p.Limit, 50, 100)))
		if err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			Position int `json:"position"`
			Track
			Added string `json:"added,omitempty"`
		}
		out := []row{}
		for i, e := range entries {
			if it := e.it(); it != nil {
				out = append(out, row{p.Offset + i, it.out(), e.AddedAt})
			}
		}
		return sdk.JSON(map[string]any{"playlist": pl.out(c.me(ctx)), "total": total, "tracks": out})

	case "search":
		if strings.TrimSpace(p.Query) == "" {
			return sdk.Result{}, errors.New("what should I search for?")
		}
		types := p.Types
		if len(types) == 0 {
			types = []string{"track"}
			if p.Type != "" {
				types = []string{p.Type}
			}
		}
		for _, t := range types {
			if !kinds[t] {
				return sdk.Result{}, fmt.Errorf("can't search for %q", t)
			}
		}
		res, err := c.search(ctx, p.Query, types, atoiDef(limit(p.Limit, 5, 10)), p.Offset)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(res)

	case "track":
		r, err := parseKind(p.URI, "track", "episode")
		if err != nil {
			return sdk.Result{}, err
		}
		var it item
		if err := c.do(ctx, "GET", "/"+r.Kind+"s/"+r.ID, nil, nil, &it); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(it.out())

	case "album":
		r, err := parseKind(p.URI, "album")
		if err != nil {
			return sdk.Result{}, err
		}
		var a album
		if err := c.do(ctx, "GET", "/albums/"+r.ID, nil, nil, &a); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(a.out())

	case "artist":
		r, err := parseKind(p.URI, "artist")
		if err != nil {
			return sdk.Result{}, err
		}
		var a artist
		if err := c.do(ctx, "GET", "/artists/"+r.ID, nil, nil, &a); err != nil {
			return sdk.Result{}, err
		}
		var al struct{ Items []album }
		_ = c.do(ctx, "GET", "/artists/"+r.ID+"/albums", url.Values{"limit": {"20"}, "include_groups": {"album,single"}}, nil, &al)
		albums := []Album{}
		for _, x := range al.Items {
			o := x.out()
			o.Artists = ""
			albums = append(albums, o)
		}
		return sdk.JSON(map[string]any{"name": a.Name, "uri": a.URI, "genres": a.Genres, "albums": albums})

	case "queue":
		if p.URI != "" {
			return sdk.Result{}, errors.New("queue lists what plays next; use add_to_queue to add a track")
		}
		var q struct {
			Current *item  `json:"currently_playing"`
			Queue   []item `json:"queue"`
		}
		if err := c.do(ctx, "GET", "/me/player/queue", nil, nil, &q); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"next": tracks(q.Queue)}
		if q.Current != nil && q.Current.URI != "" {
			out["current"] = q.Current.out()
		}
		return sdk.JSON(out)

	case "devices":
		var d struct{ Devices []device }
		if err := c.do(ctx, "GET", "/me/player/devices", nil, nil, &d); err != nil {
			if errors.Is(err, errNoWeb) && c.local != nil {
				return sdk.JSON([]map[string]any{{"id": "", "name": "Spotify app on this computer (" + c.local.Name() + ")", "type": "Computer", "active": true}})
			}
			return sdk.Result{}, err
		}
		type dev struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Type    string `json:"type"`
			Active  bool   `json:"active"`
			Volume  *int   `json:"volume,omitempty"`
			Private bool   `json:"privateSession,omitempty"`
		}
		list := []dev{}
		for _, x := range d.Devices {
			list = append(list, dev{x.ID, x.Name, x.Type, x.IsActive, x.Volume, x.Private})
		}
		return sdk.JSON(list)

	case "history":
		return c.historyList(ctx, p)
	case "listening_stats":
		return c.listeningStats(ctx, p)

	case "auth_url":
		if !c.web && c.cfg.ClientID == "" {
			return sdk.Result{}, errors.New("add the client id first")
		}
		redirect := p.RedirectURI
		if redirect == "" {
			redirect = "http://127.0.0.1:8888/callback"
		}
		u := "https://accounts.spotify.com/authorize?" + url.Values{"response_type": {"code"}, "client_id": {c.cfg.ClientID},
			"redirect_uri": {redirect}, "scope": {strings.Join(Scopes, " ")}}.Encode()
		return sdk.JSON(map[string]any{"url": u, "redirectUri": redirect, "scopes": Scopes,
			"next": "Open the link, approve, copy the code from the address you're sent to, and exchange it for a refresh token as the module docs show. Add the redirect URI to your app first."})
	}
	return m.write(ctx, c, call, p)
}

func atoiDef(s string) int { n, _ := strconv.Atoi(s); return n }

func artists(list []artist) []Artist {
	out := make([]Artist, 0, len(list))
	for _, a := range list {
		out = append(out, Artist{Name: a.Name, URI: a.URI, Genres: a.Genres})
	}
	return out
}

// me is the signed-in user's id, cached.
func (c *conn) me(ctx context.Context) string {
	c.mu.Lock()
	id := c.user
	c.mu.Unlock()
	if id != "" {
		return id
	}
	var me struct {
		ID      string `json:"id"`
		Product string `json:"product"`
	}
	if c.do(ctx, "GET", "/me", nil, nil, &me) == nil {
		c.mu.Lock()
		c.user = me.ID
		if me.Product != "" {
			c.product = me.Product
		}
		c.mu.Unlock()
	}
	return me.ID
}

func (c *conn) playlistItems(ctx context.Context, id string, offset, n int) ([]playlistEntry, int, error) {
	var pg struct {
		Total int
		Items []playlistEntry
	}
	q := url.Values{"limit": {strconv.Itoa(n)}}
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	if err := c.do(ctx, "GET", "/playlists/"+id+"/items", q, nil, &pg); err != nil {
		if isStatus(err, 403) || isStatus(err, 404) {
			return nil, 0, fmt.Errorf("Spotify only lists the tracks of playlists you own or collaborate on (%v)", err)
		}
		return nil, 0, err
	}
	return pg.Items, pg.Total, nil
}

// allPlaylistItems reads up to 2,000 entries (for undo bookkeeping).
func (c *conn) allPlaylistItems(ctx context.Context, id string) ([]playlistEntry, error) {
	var all []playlistEntry
	for off := 0; off < 2000; off += 100 {
		items, total, err := c.playlistItems(ctx, id, off, 100)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if len(items) < 100 || len(all) >= total {
			break
		}
	}
	return all, nil
}

func (c *conn) search(ctx context.Context, query string, types []string, n, offset int) (map[string]any, error) {
	q := url.Values{"q": {query}, "type": {strings.Join(types, ",")}, "limit": {strconv.Itoa(n)}}
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	var s struct {
		Tracks    *struct{ Items []item }      `json:"tracks"`
		Episodes  *struct{ Items []item }      `json:"episodes"`
		Albums    *struct{ Items []album }     `json:"albums"`
		Artists   *struct{ Items []artist }    `json:"artists"`
		Playlists *struct{ Items []*playlist } `json:"playlists"`
		Shows     *struct{ Items []*named }    `json:"shows"`
	}
	if err := c.do(ctx, "GET", "/search", q, nil, &s); err != nil {
		return nil, err
	}
	out := map[string]any{}
	if s.Tracks != nil {
		out["tracks"] = tracks(s.Tracks.Items)
	}
	if s.Episodes != nil {
		out["episodes"] = tracks(s.Episodes.Items)
	}
	if s.Albums != nil {
		l := []Album{}
		for _, a := range s.Albums.Items {
			l = append(l, a.out())
		}
		out["albums"] = l
	}
	if s.Artists != nil {
		out["artists"] = artists(s.Artists.Items)
	}
	if s.Playlists != nil {
		l := []Playlist{}
		for _, p := range s.Playlists.Items {
			if p != nil { // Spotify returns null for playlists it hides
				l = append(l, p.out(""))
			}
		}
		out["playlists"] = l
	}
	if s.Shows != nil {
		l := []map[string]string{}
		for _, sh := range s.Shows.Items {
			if sh != nil {
				l = append(l, map[string]string{"name": sh.Name, "uri": sh.URI})
			}
		}
		out["shows"] = l
	}
	return out, nil
}

func (c *conn) nowPlaying(ctx context.Context) (sdk.Result, error) {
	if c.mode() == "local" && (!c.web || c.cfg.Playback == "local") {
		st, err := c.local.Status(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"playing": st.State == "playing", "via": "app", "track": st.Track, "artists": st.Artists, "album": st.Album,
			"uri": st.URI, "progressSeconds": st.Progress, "durationSeconds": st.Duration, "volume": st.Volume, "shuffle": st.Shuffle})
	}
	st, err := c.state(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	if st == nil || st.Item == nil {
		if c.local != nil {
			if ls, err := c.local.Status(ctx); err == nil && ls.Track != "" {
				return sdk.JSON(map[string]any{"playing": ls.State == "playing", "via": "app", "track": ls.Track, "artists": ls.Artists, "album": ls.Album, "uri": ls.URI,
					"progressSeconds": ls.Progress, "durationSeconds": ls.Duration})
			}
		}
		return sdk.JSON(map[string]any{"playing": false})
	}
	t := st.Item.out()
	out := map[string]any{"playing": st.IsPlaying, "track": t.Name, "artists": t.Artists, "album": t.Album, "uri": t.URI,
		"progressSeconds": st.Progress / 1000, "durationSeconds": t.Duration, "device": st.Device.Name, "deviceId": st.Device.ID,
		"volume": st.Device.Volume, "shuffle": st.Shuffle, "repeat": st.Repeat}
	if t.Show != "" {
		out["show"] = t.Show
	}
	if st.Context != nil && st.Context.URI != "" {
		out["context"] = st.Context.URI
	}
	return sdk.JSON(out)
}

// state returns the player, or nil when nothing is active (204).
func (c *conn) state(ctx context.Context) (*player, error) {
	var p player
	if err := c.do(ctx, "GET", "/me/player", url.Values{"additional_types": {"episode"}}, nil, &p); err != nil {
		return nil, err
	}
	if p.Device.ID == "" && p.Item == nil && !p.IsPlaying {
		return nil, nil
	}
	return &p, nil
}

func parseWhen(s string, loc *time.Location, endOfDay bool) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	t, err := time.ParseInLocation("2006-01-02", s, loc)
	if err != nil {
		return time.Time{}, fmt.Errorf("dates are YYYY-MM-DD or RFC 3339, not %q", s)
	}
	if endOfDay {
		t = t.AddDate(0, 0, 1)
	}
	return t, nil
}

func (c *conn) historyList(ctx context.Context, p input) (sdk.Result, error) {
	if c.hist == nil {
		return sdk.Result{}, errNoWeb
	}
	_, _ = c.sync(ctx) // best effort: include what was played since the last collection
	from, to := time.Time{}, time.Now().Add(time.Hour)
	var err error
	if p.Since != "" {
		if from, err = parseWhen(p.Since, c.tz, false); err != nil {
			return sdk.Result{}, err
		}
	}
	if p.Until != "" {
		if to, err = parseWhen(p.Until, c.tz, true); err != nil {
			return sdk.Result{}, err
		}
	}
	n := atoiDef(limit(p.Limit, 100, 1000))
	_, plays := c.hist.between(from, to)
	type row struct {
		PlayedAt string `json:"playedAt"`
		Name     string `json:"name"`
		Artists  string `json:"artists"`
		Album    string `json:"album,omitempty"`
		URI      string `json:"uri"`
		Context  string `json:"context,omitempty"`
	}
	out := []row{}
	for i := len(plays) - 1; i >= 0 && len(out) < n; i-- {
		pl := plays[i]
		a := strings.Join(pl.Artists, ", ")
		if p.Artist != "" && !strings.Contains(strings.ToLower(a), strings.ToLower(p.Artist)) {
			continue
		}
		out = append(out, row{pl.At.In(c.tz).Format(time.RFC3339), pl.Name, a, pl.Album, pl.URI, pl.Context})
	}
	total, first := c.hist.stats()
	res := map[string]any{"plays": out, "logged": total}
	if !first.IsZero() {
		res["loggedSince"] = first.In(c.tz).Format(time.RFC3339)
	}
	return sdk.JSON(res)
}

func (c *conn) listeningStats(ctx context.Context, p input) (sdk.Result, error) {
	if c.hist == nil {
		return sdk.Result{}, errNoWeb
	}
	_, _ = c.sync(ctx)
	days := p.Days
	if days <= 0 {
		days = 7
	}
	if days > 366 {
		days = 366
	}
	n := p.Top
	if n <= 0 || n > 50 {
		n = 10
	}
	now := time.Now().In(c.tz)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, c.tz)
	from := today.AddDate(0, 0, -(days - 1))
	prev, plays := c.hist.between(from, today.AddDate(0, 0, 1))
	est := listened(prev, plays)

	type day struct {
		Date    string  `json:"date"`
		Minutes float64 `json:"minutes"`
		Plays   int     `json:"plays"`
	}
	perDay := make([]day, days)
	for i := range perDay {
		perDay[i].Date = from.AddDate(0, 0, i).Format("2006-01-02")
	}
	byArtist, byTrack, byAlbum := map[string]*countRow{}, map[string]*countRow{}, map[string]*countRow{}
	var total time.Duration
	for i, pl := range plays {
		mins := est[i].Minutes()
		total += est[i]
		local := pl.At.In(c.tz)
		d := int(time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, c.tz).Sub(from).Hours()/24 + 0.5)
		if d >= 0 && d < days {
			perDay[d].Minutes += mins
			perDay[d].Plays++
		}
		for _, a := range pl.Artists {
			r := byArtist[a]
			if r == nil {
				r = &countRow{Name: a}
				byArtist[a] = r
			}
			r.Plays++
			r.Minutes += mins / float64(len(pl.Artists))
		}
		key := pl.URI
		if key == "" {
			key = pl.Name
		}
		r := byTrack[key]
		if r == nil {
			r = &countRow{Name: pl.Name, Artists: strings.Join(pl.Artists, ", "), URI: pl.URI}
			byTrack[key] = r
		}
		r.Plays++
		r.Minutes += mins
		if pl.Album != "" {
			r := byAlbum[pl.Album]
			if r == nil {
				r = &countRow{Name: pl.Album}
				byAlbum[pl.Album] = r
			}
			r.Plays++
			r.Minutes += mins
		}
	}
	for i := range perDay {
		perDay[i].Minutes = round1(perDay[i].Minutes)
	}
	hours := map[int]int{}
	for _, pl := range plays {
		hours[pl.At.In(c.tz).Hour()]++
	}
	busiest, best := -1, 0
	keys := make([]int, 0, len(hours))
	for h := range hours {
		keys = append(keys, h)
	}
	sort.Ints(keys)
	for _, h := range keys {
		if hours[h] > best {
			busiest, best = h, hours[h]
		}
	}
	out := map[string]any{
		"from": from.Format("2006-01-02"), "to": today.Format("2006-01-02"), "days": days,
		"plays": len(plays), "minutes": round1(total.Minutes()),
		"minutesPerDay": perDay, "topArtists": top(byArtist, n), "topTracks": top(byTrack, n), "topAlbums": top(byAlbum, n),
		"note": "Minutes are estimated from track lengths and the time between plays; Spotify only reports plays of 30 seconds or more.",
	}
	if busiest >= 0 {
		out["busiestHour"] = busiest
	}
	if total, first := c.hist.stats(); total > 0 && first.After(from) {
		out["loggedSince"] = first.In(c.tz).Format(time.RFC3339)
	}
	return sdk.JSON(out)
}
