package spotify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// control runs a playback command through the Web API, or through the
// Spotify app on this computer when that is the mode or the Web API says
// the account isn't Premium. It reports which was used ("web" or "app").
func (c *conn) control(ctx context.Context, web func() error, local func(lp localPlayer) error) (string, error) {
	if c.mode() == "local" {
		if c.local == nil {
			return "", errNoPremium
		}
		if local == nil {
			return "", errors.New("the Spotify app on this computer can't do that; it needs the Web API with Premium")
		}
		return "app", local(c.local)
	}
	err := web()
	if isPremiumRequired(err) {
		c.markFree()
		if c.local != nil && local != nil && c.cfg.Playback == "auto" {
			return "app", local(c.local)
		}
		return "", errNoPremium
	}
	return "web", err
}

func devQuery(dev string) url.Values {
	q := url.Values{}
	if dev != "" {
		q.Set("device_id", dev)
	}
	return q
}

func withDevice(m map[string]any, dev string) map[string]any {
	if dev != "" {
		m["device"] = dev
	}
	return m
}

// webState is the player before a change, when the Web API is in use.
func (c *conn) webState(ctx context.Context) *player {
	if c.mode() != "web" {
		return nil
	}
	st, err := c.state(ctx)
	if err != nil {
		return nil
	}
	return st
}

func (c *conn) label(ctx context.Context, r ref) string {
	var v struct {
		Name    string  `json:"name"`
		Artists []named `json:"artists"`
	}
	if c.do(ctx, "GET", "/"+r.Kind+"s/"+r.ID, nil, nil, &v) != nil || v.Name == "" {
		return r.URI()
	}
	if len(v.Artists) > 0 {
		return fmt.Sprintf("%s by %s (%s)", v.Name, v.Artists[0].Name, r.Kind)
	}
	return fmt.Sprintf("%s (%s)", v.Name, r.Kind)
}

func parseItems(list []string) ([]string, error) {
	var out []string
	for _, s := range list {
		r, err := parseKind(s, "track", "episode")
		if err != nil {
			return nil, err
		}
		out = append(out, r.URI())
	}
	return out, nil
}

func (m *Module) write(ctx context.Context, c *conn, call sdk.Call, p input) (sdk.Result, error) {
	dev := p.Device
	via := func(how string, out map[string]any) map[string]any {
		out["via"] = map[string]string{"web": "Web API", "app": "Spotify app on this computer"}[how]
		return out
	}
	switch call.Action {
	case "play", "resume":
		var target *ref
		var uris []string
		var err error
		switch {
		case call.Action == "resume":
		case p.Query != "":
			kind := p.Type
			if kind == "" {
				kind = "track"
			}
			if !kinds[kind] {
				return sdk.Result{}, fmt.Errorf("can't search for %q", kind)
			}
			res, err := c.search(ctx, p.Query, []string{kind}, 1, 0)
			if err != nil {
				return sdk.Result{}, err
			}
			uri := firstURI(res)
			if uri == "" {
				return sdk.Result{}, fmt.Errorf("nothing on Spotify matches %q", p.Query)
			}
			r, _ := parseRef(uri)
			target = &r
		case p.URI != "":
			r, err := parseRef(p.URI, "track")
			if err != nil {
				return sdk.Result{}, err
			}
			target = &r
		case len(p.URIs) > 0:
			if uris, err = parseItems(p.URIs); err != nil {
				return sdk.Result{}, err
			}
		}
		if target != nil && (target.Kind == "track" || target.Kind == "episode") {
			uris, target = []string{target.URI()}, nil
		}
		var startAt string
		if p.StartAt != "" {
			if target == nil {
				return sdk.Result{}, errors.New("startAt needs an album, playlist or show to start within")
			}
			r, err := parseKind(p.StartAt, "track", "episode")
			if err != nil {
				return sdk.Result{}, err
			}
			startAt = r.URI()
		}
		what := "Resume playback"
		switch {
		case target != nil:
			what = "Play " + c.label(ctx, *target)
		case len(uris) == 1:
			r, _ := parseRef(uris[0])
			what = "Play " + c.label(ctx, r)
		case len(uris) > 1:
			what = fmt.Sprintf("Play %d tracks", len(uris))
		}
		if call.DryRun {
			where := "the active device"
			if dev != "" {
				where = "device " + dev
			}
			if c.mode() == "local" {
				where = "the Spotify app on this computer"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: what + " on " + where, Changes: []sdk.Change{{Target: where, Op: "play", After: mustJSON(map[string]any{"uris": uris, "context": target, "startAt": startAt})}}}}, nil
		}
		before := c.webState(ctx)
		body := map[string]any{}
		if len(uris) > 0 {
			body["uris"] = uris
		}
		if target != nil {
			body["context_uri"] = target.URI()
			if startAt != "" {
				body["offset"] = map[string]string{"uri": startAt}
			}
		}
		if p.PositionMS != nil && *p.PositionMS > 0 {
			body["position_ms"] = *p.PositionMS
		}
		var send any
		if len(body) > 0 {
			send = body
		}
		how, err := c.control(ctx, func() error { return c.do(ctx, "PUT", "/me/player/play", devQuery(dev), send, nil) },
			func(lp localPlayer) error {
				switch {
				case target != nil:
					return lp.Open(ctx, target.URI())
				case len(uris) > 0:
					return lp.Open(ctx, uris[0])
				}
				return lp.Command(ctx, "play")
			})
		if err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(via(how, map[string]any{"playing": true, "what": strings.TrimPrefix(what, "Play ")}))
		r.Undo = sdk.UndoWith("pause", withDevice(map[string]any{}, dev), "Pause")
		if before != nil && before.IsPlaying && before.Item != nil && (target != nil || len(uris) > 0) {
			in := map[string]any{"positionMs": before.Progress}
			if before.Context != nil && before.Context.URI != "" {
				if _, err := parseRef(before.Context.URI); err == nil {
					in["uri"], in["startAt"] = before.Context.URI, before.Item.URI
				}
			}
			if in["uri"] == nil {
				in["uri"] = before.Item.URI
			}
			r.Undo = sdk.UndoWith("play", withDevice(in, before.Device.ID), "Go back to "+before.Item.Name)
		}
		return r, nil

	case "pause":
		how, err := c.control(ctx, func() error { return c.do(ctx, "PUT", "/me/player/pause", devQuery(dev), nil, nil) },
			func(lp localPlayer) error { return lp.Command(ctx, "pause") })
		if err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(via(how, map[string]any{"playing": false}))
		r.Undo = sdk.UndoWith("resume", withDevice(map[string]any{}, dev), "Resume")
		return r, nil

	case "next", "previous":
		how, err := c.control(ctx, func() error { return c.do(ctx, "POST", "/me/player/"+call.Action, devQuery(dev), nil, nil) },
			func(lp localPlayer) error { return lp.Command(ctx, call.Action) })
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(via(how, map[string]any{"skipped": call.Action}))

	case "seek":
		ms := -1
		if p.PositionMS != nil {
			ms = *p.PositionMS
		} else if p.Seconds != nil {
			ms = *p.Seconds * 1000
		}
		if ms < 0 {
			return sdk.Result{}, errors.New("give positionMs or seconds")
		}
		before := c.webState(ctx)
		q := devQuery(dev)
		q.Set("position_ms", strconv.Itoa(ms))
		how, err := c.control(ctx, func() error { return c.do(ctx, "PUT", "/me/player/seek", q, nil, nil) },
			func(lp localPlayer) error { return lp.Seek(ctx, ms) })
		if err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(via(how, map[string]any{"positionSeconds": ms / 1000}))
		if before != nil {
			r.Undo = sdk.UndoWith("seek", withDevice(map[string]any{"positionMs": before.Progress}, dev), "Jump back")
		}
		return r, nil

	case "volume":
		if p.Percent == nil || *p.Percent < 0 || *p.Percent > 100 {
			return sdk.Result{}, errors.New("volume is 0 to 100")
		}
		var prev *int
		if before := c.webState(ctx); before != nil {
			prev = before.Device.Volume
		} else if c.mode() == "local" && c.local != nil {
			if st, err := c.local.Status(ctx); err == nil {
				prev = st.Volume
			}
		}
		q := devQuery(dev)
		q.Set("volume_percent", strconv.Itoa(*p.Percent))
		how, err := c.control(ctx, func() error { return c.do(ctx, "PUT", "/me/player/volume", q, nil, nil) },
			func(lp localPlayer) error { return lp.Volume(ctx, *p.Percent) })
		if err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(via(how, map[string]any{"volume": *p.Percent}))
		if prev != nil {
			r.Undo = sdk.UndoWith("volume", withDevice(map[string]any{"percent": *prev}, dev), fmt.Sprintf("Set the volume back to %d%%", *prev))
		}
		return r, nil

	case "shuffle":
		if p.On == nil {
			return sdk.Result{}, errors.New("on is required")
		}
		before := c.webState(ctx)
		q := devQuery(dev)
		q.Set("state", strconv.FormatBool(*p.On))
		how, err := c.control(ctx, func() error { return c.do(ctx, "PUT", "/me/player/shuffle", q, nil, nil) },
			func(lp localPlayer) error { return lp.Shuffle(ctx, *p.On) })
		if err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(via(how, map[string]any{"shuffle": *p.On}))
		if before != nil {
			r.Undo = sdk.UndoWith("shuffle", withDevice(map[string]any{"on": before.Shuffle}, dev), "Undo shuffle")
		} else {
			r.Undo = sdk.UndoWith("shuffle", withDevice(map[string]any{"on": !*p.On}, dev), "Undo shuffle")
		}
		return r, nil

	case "repeat":
		if p.Mode != "off" && p.Mode != "track" && p.Mode != "context" {
			return sdk.Result{}, errors.New("mode is off, track or context")
		}
		before := c.webState(ctx)
		q := devQuery(dev)
		q.Set("state", p.Mode)
		how, err := c.control(ctx, func() error { return c.do(ctx, "PUT", "/me/player/repeat", q, nil, nil) }, nil)
		if err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(via(how, map[string]any{"repeat": p.Mode}))
		if before != nil && before.Repeat != "" {
			r.Undo = sdk.UndoWith("repeat", withDevice(map[string]any{"mode": before.Repeat}, dev), "Repeat "+before.Repeat+" again")
		}
		return r, nil

	case "add_to_queue":
		r, err := parseKind(p.URI, "track", "episode")
		if err != nil {
			return sdk.Result{}, err
		}
		q := devQuery(dev)
		q.Set("uri", r.URI())
		how, err := c.control(ctx, func() error { return c.do(ctx, "POST", "/me/player/queue", q, nil, nil) }, nil)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(via(how, map[string]any{"queued": r.URI()}))

	case "transfer":
		if dev == "" {
			return sdk.Result{}, errors.New("which device? see devices")
		}
		play := p.Play == nil || *p.Play
		before := c.webState(ctx)
		if call.DryRun {
			from := "nothing"
			if before != nil {
				from = before.Device.Name
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: "Move playback from " + from + " to device " + dev,
				Changes: []sdk.Change{{Target: dev, Op: "transfer", After: mustJSON(map[string]any{"play": play})}}}}, nil
		}
		how, err := c.control(ctx, func() error {
			return c.do(ctx, "PUT", "/me/player", nil, map[string]any{"device_ids": []string{dev}, "play": play}, nil)
		}, nil)
		if err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(via(how, map[string]any{"device": dev}))
		if before != nil && before.Device.ID != "" && before.Device.ID != dev {
			r.Undo = sdk.UndoWith("transfer", map[string]any{"device": before.Device.ID, "play": before.IsPlaying}, "Move back to "+before.Device.Name)
		}
		return r, nil

	case "create_playlist":
		if strings.TrimSpace(p.Name) == "" {
			return sdk.Result{}, errors.New("name is required")
		}
		uris, err := parseItems(p.URIs)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			vis := "private"
			if p.Public {
				vis = "public"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create the %s playlist %q with %d tracks", vis, p.Name, len(uris)),
				Changes: []sdk.Change{{Target: p.Name, Op: "create", After: mustJSON(map[string]any{"description": p.Description, "public": p.Public, "uris": uris})}}}}, nil
		}
		var pl playlist
		if err := c.do(ctx, "POST", "/me/playlists", nil, map[string]any{"name": p.Name, "description": p.Description, "public": p.Public}, &pl); err != nil {
			return sdk.Result{}, err
		}
		for i := 0; i < len(uris); i += 100 {
			end := min(i+100, len(uris))
			if err := c.do(ctx, "POST", "/playlists/"+pl.ID+"/items", nil, map[string]any{"uris": uris[i:end]}, nil); err != nil {
				return sdk.Result{}, fmt.Errorf("created %s but adding tracks failed: %w", pl.URI, err)
			}
		}
		r, _ := sdk.JSON(map[string]any{"created": pl.URI, "name": pl.Name, "tracks": len(uris)})
		r.Undo = sdk.UndoWith("unsave", map[string]any{"uris": []string{pl.URI}}, "Delete the playlist "+pl.Name)
		return r, nil

	case "playlist_add":
		pr, err := parseKind(p.Playlist, "playlist")
		if err != nil {
			return sdk.Result{}, err
		}
		if len(p.Restore) > 0 {
			return c.restore(ctx, pr, p.Restore)
		}
		uris, err := parseItems(p.URIs)
		if err != nil || len(uris) == 0 {
			return sdk.Result{}, errors.New("uris are required (tracks or episodes)")
		}
		if len(uris) > 100 {
			return sdk.Result{}, errors.New("at most 100 tracks at once")
		}
		entries, err := c.allPlaylistItems(ctx, pr.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		set := map[string]bool{}
		for _, u := range uris {
			set[u] = true
		}
		var already []restoreAt
		for i, e := range entries {
			if it := e.it(); it != nil && set[it.URI] {
				already = append(already, restoreAt{it.URI, i})
			}
		}
		if call.DryRun {
			where := "at the end"
			if p.Position != nil {
				where = fmt.Sprintf("at position %d", *p.Position)
			}
			plan := &sdk.Plan{Summary: fmt.Sprintf("Add %d track(s) to %s %s", len(uris), pr.URI(), where)}
			for _, u := range uris {
				plan.Changes = append(plan.Changes, sdk.Change{Target: u, Op: "add"})
			}
			if len(already) > 0 {
				plan.Summary += fmt.Sprintf(" (%d already there)", len(already))
			}
			return sdk.Result{Plan: plan}, nil
		}
		body := map[string]any{"uris": uris}
		if p.Position != nil {
			body["position"] = *p.Position
		}
		var snap struct {
			SnapshotID string `json:"snapshot_id"`
		}
		if err := c.do(ctx, "POST", "/playlists/"+pr.ID+"/items", nil, body, &snap); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"added": len(uris), "playlist": pr.URI(), "snapshot": snap.SnapshotID})
		r.Undo = sdk.UndoWith("playlist_remove", map[string]any{"playlist": pr.URI(), "uris": uris, "restore": already}, fmt.Sprintf("Take the %d track(s) out again", len(uris)))
		return r, nil

	case "playlist_remove":
		pr, err := parseKind(p.Playlist, "playlist")
		if err != nil {
			return sdk.Result{}, err
		}
		uris, err := parseItems(p.URIs)
		if err != nil || len(uris) == 0 {
			return sdk.Result{}, errors.New("uris are required (tracks or episodes)")
		}
		entries, err := c.allPlaylistItems(ctx, pr.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		set := map[string]bool{}
		for _, u := range uris {
			set[u] = true
		}
		var removed []restoreAt
		for i, e := range entries {
			if it := e.it(); it != nil && set[it.URI] {
				removed = append(removed, restoreAt{it.URI, i})
			}
		}
		if call.DryRun {
			plan := &sdk.Plan{Summary: fmt.Sprintf("Remove %d track(s) from %s", len(removed), pr.URI())}
			for _, r := range removed {
				plan.Changes = append(plan.Changes, sdk.Change{Target: fmt.Sprintf("%s at position %d", r.URI, r.Position), Op: "remove"})
			}
			return sdk.Result{Plan: plan}, nil
		}
		items := make([]map[string]string, 0, len(uris))
		for _, u := range uris {
			items = append(items, map[string]string{"uri": u})
		}
		if err := c.do(ctx, "DELETE", "/playlists/"+pr.ID+"/items", nil, map[string]any{"items": items}, nil); err != nil {
			return sdk.Result{}, err
		}
		if len(p.Restore) > 0 { // undoing an add: put back what was there before
			if _, err := c.restore(ctx, pr, p.Restore); err != nil {
				return sdk.Result{}, err
			}
		}
		r, _ := sdk.JSON(map[string]any{"removed": len(removed), "playlist": pr.URI()})
		if len(removed) > 0 && len(p.Restore) == 0 {
			r.Undo = sdk.UndoWith("playlist_add", map[string]any{"playlist": pr.URI(), "restore": removed}, fmt.Sprintf("Put the %d track(s) back", len(removed)))
		}
		return r, nil

	case "playlist_reorder":
		pr, err := parseKind(p.Playlist, "playlist")
		if err != nil {
			return sdk.Result{}, err
		}
		if p.RangeStart == nil || p.InsertBefore == nil || *p.RangeStart < 0 || *p.InsertBefore < 0 {
			return sdk.Result{}, errors.New("rangeStart and insertBefore are required (0-based)")
		}
		s, b, n := *p.RangeStart, *p.InsertBefore, p.RangeLength
		if n <= 0 {
			n = 1
		}
		if b >= s && b <= s+n {
			return sdk.Result{}, errors.New("that wouldn't move anything")
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Move %d track(s) from position %d to before %d in %s", n, s, b, pr.URI()),
				Changes: []sdk.Change{{Target: pr.URI(), Op: "reorder", Before: mustJSON(map[string]int{"rangeStart": s}), After: mustJSON(map[string]int{"insertBefore": b})}}}}, nil
		}
		var snap struct {
			SnapshotID string `json:"snapshot_id"`
		}
		if err := c.do(ctx, "PUT", "/playlists/"+pr.ID+"/items", nil, map[string]any{"range_start": s, "insert_before": b, "range_length": n}, &snap); err != nil {
			return sdk.Result{}, err
		}
		// The inverse move: where the range ended up, back to where it was.
		us, ub := b, s+n
		if b > s {
			us, ub = b-n, s
		}
		r, _ := sdk.JSON(map[string]any{"moved": n, "playlist": pr.URI(), "snapshot": snap.SnapshotID})
		r.Undo = sdk.UndoWith("playlist_reorder", map[string]any{"playlist": pr.URI(), "rangeStart": us, "insertBefore": ub, "rangeLength": n}, "Move them back")
		return r, nil

	case "save", "unsave":
		if len(p.URIs) == 0 || len(p.URIs) > 40 {
			return sdk.Result{}, errors.New("give 1 to 40 uris")
		}
		var uris []string
		for _, s := range p.URIs {
			r, err := parseRef(s)
			if err != nil {
				return sdk.Result{}, err
			}
			uris = append(uris, r.URI())
		}
		joined := strings.Join(uris, ",")
		var have []bool
		_ = c.do(ctx, "GET", "/me/library/contains", url.Values{"uris": {joined}}, nil, &have)
		save := call.Action == "save"
		var change []string
		for i, u := range uris {
			if i < len(have) && have[i] == save {
				continue // already as asked
			}
			change = append(change, u)
		}
		if len(have) != len(uris) {
			change = uris
		}
		if call.DryRun {
			op := map[bool]string{true: "save", false: "remove"}[save]
			plan := &sdk.Plan{Summary: fmt.Sprintf("%s %d item(s) in your library", strings.ToUpper(op[:1])+op[1:], len(change))}
			for _, u := range change {
				plan.Changes = append(plan.Changes, sdk.Change{Target: u, Op: op})
			}
			return sdk.Result{Plan: plan}, nil
		}
		if len(change) == 0 {
			return sdk.JSON(map[string]any{"changed": 0})
		}
		method := map[bool]string{true: "PUT", false: "DELETE"}[save]
		if err := c.do(ctx, method, "/me/library", url.Values{"uris": {strings.Join(change, ",")}}, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		inverse := map[bool]string{true: "unsave", false: "save"}[save]
		r, _ := sdk.JSON(map[string]any{"changed": len(change), "uris": change})
		r.Undo = sdk.UndoWith(inverse, map[string]any{"uris": change}, "Undo "+call.Action)
		return r, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// restore puts tracks back at their positions, lowest first, so each lands
// where it was.
func (c *conn) restore(ctx context.Context, pr ref, list []restoreAt) (sdk.Result, error) {
	sort.Slice(list, func(i, j int) bool { return list[i].Position < list[j].Position })
	if len(list) > 200 {
		return sdk.Result{}, errors.New("too many tracks to put back")
	}
	for _, r := range list {
		if _, err := parseKind(r.URI, "track", "episode"); err != nil {
			return sdk.Result{}, err
		}
		if err := c.do(ctx, "POST", "/playlists/"+pr.ID+"/items", nil, map[string]any{"uris": []string{r.URI}, "position": r.Position}, nil); err != nil {
			return sdk.Result{}, err
		}
	}
	return sdk.JSON(map[string]any{"restored": len(list), "playlist": pr.URI()})
}

func firstURI(res map[string]any) string {
	for _, k := range []string{"tracks", "albums", "artists", "playlists", "shows", "episodes"} {
		switch v := res[k].(type) {
		case []Track:
			if len(v) > 0 {
				return v[0].URI
			}
		case []Album:
			if len(v) > 0 {
				return v[0].URI
			}
		case []Artist:
			if len(v) > 0 {
				return v[0].URI
			}
		case []Playlist:
			if len(v) > 0 {
				return v[0].URI
			}
		case []map[string]string:
			if len(v) > 0 {
				return v[0]["uri"]
			}
		}
	}
	return ""
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
