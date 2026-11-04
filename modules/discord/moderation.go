package discord

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
	"unicode"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// maxTimeout is the longest timeout Discord allows.
const maxTimeout = 28 * 24 * time.Hour

var durationRe = regexp.MustCompile(`^(\d{1,5})\s*(m|min|h|d)$`)

type member struct {
	User     user     `json:"user"`
	Nick     string   `json:"nick"`
	Roles    []string `json:"roles"`
	JoinedAt string   `json:"joined_at"`
	Until    *string  `json:"communication_disabled_until"`
}

// timedOutUntil is when the member's timeout ends, or zero when none is in force.
func (mb *member) timedOutUntil() time.Time {
	if mb == nil || mb.Until == nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, *mb.Until)
	if err != nil || !t.After(time.Now()) {
		return time.Time{}
	}
	return t.UTC()
}

// target is the person a moderation action is about, in the configured server.
type target struct {
	id     string
	server string
	owner  string
	user   user
	member *member // nil when they aren't in the server
}

// who names them as people see them: "Kim (@kim)".
func (t target) who() string {
	name := t.user.display()
	if t.member != nil && t.member.Nick != "" {
		name = t.member.Nick
	}
	switch {
	case t.user.Username == "":
		return "user " + t.id
	case name == "" || name == t.user.Username:
		return "@" + t.user.Username
	}
	return name + " (@" + t.user.Username + ")"
}

func (t target) label() string { return t.who() + " in " + t.server }

// lookup reads the server and the user (as a member when they're in it).
func (m *Module) lookup(ctx context.Context, c *conn, id string) (target, error) {
	t := target{id: id}
	var g struct {
		Name    string `json:"name"`
		OwnerID string `json:"owner_id"`
	}
	if err := m.do(ctx, c.bot, http.MethodGet, seg("guilds", c.cfg.Guild), nil, nil, &g); err != nil {
		return t, err
	}
	t.server, t.owner = g.Name, g.OwnerID
	if t.server == "" {
		t.server = "server " + c.cfg.Guild
	}
	var mb member
	err := m.do(ctx, c.bot, http.MethodGet, seg("guilds", c.cfg.Guild, "members", id), nil, nil, &mb)
	switch {
	case err == nil:
		t.member, t.user = &mb, mb.User
		return t, nil
	case !rest.IsStatus(err, http.StatusNotFound):
		return t, err
	}
	if err := m.do(ctx, c.bot, http.MethodGet, seg("users", id), nil, nil, &t.user); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return t, fmt.Errorf("there's no Discord user %s", id)
		}
		return t, err
	}
	return t, nil
}

// refuse stops moderation of the server's owner and of the bot itself.
func (m *Module) refuse(ctx context.Context, c *conn, t target) error {
	if t.owner != "" && t.id == t.owner {
		return fmt.Errorf("%s owns %s; Conduit doesn't moderate the server owner", t.who(), t.server)
	}
	me, err := m.myID(ctx, c)
	if err != nil {
		return err
	}
	if t.id == me {
		return errors.New("that's the bot itself; Conduit doesn't moderate its own bot")
	}
	return nil
}

// reasoned is the bot client with the audit-log reason "Conduit: …".
func (c *conn) reasoned(reason string) (*rest.Client, error) {
	reason = strings.TrimSpace(reason)
	v := "Conduit"
	if reason != "" {
		if utf8.RuneCountInString(reason) > 400 || strings.ContainsFunc(reason, unicode.IsControl) {
			return nil, errors.New("the reason is up to 400 characters on one line")
		}
		v += ": " + reason
	}
	cp := *c.bot
	cp.Header = c.bot.Header.Clone()
	cp.Header.Set("X-Audit-Log-Reason", url.PathEscape(v))
	return &cp, nil
}

// endsAt reads a duration ("10m", "2h", "7d") or a time into when a
// timeout ends.
func endsAt(duration, until string, now time.Time) (time.Time, error) {
	duration, until = strings.TrimSpace(strings.ToLower(duration)), strings.TrimSpace(until)
	var t time.Time
	switch {
	case duration != "" && until != "":
		return t, errors.New("give a duration or an end time, not both")
	case duration != "":
		g := durationRe.FindStringSubmatch(duration)
		if g == nil {
			return t, errors.New("the duration is like 10m, 2h or 7d")
		}
		n, _ := strconv.Atoi(g[1])
		unit := map[string]time.Duration{"m": time.Minute, "min": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[g[2]]
		d := time.Duration(n) * unit
		if d <= 0 || d > maxTimeout {
			return t, errors.New("a timeout lasts from a minute to 28 days")
		}
		t = now.Add(d)
	case until != "":
		var err error
		if t, err = time.Parse(time.RFC3339, until); err != nil {
			return t, errors.New("until is a time like 2026-11-05T18:00:00Z")
		}
		if !t.After(now) {
			return t, errors.New("that time has passed")
		}
		if t.Sub(now) > maxTimeout {
			return t, errors.New("a timeout lasts at most 28 days")
		}
	default:
		return t, errors.New("say how long, like 10m, 2h or 7d")
	}
	return t.UTC().Truncate(time.Second), nil
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func plan(sum, target, op string, before, after any) sdk.Result {
	ch := sdk.Change{Target: target, Op: op}
	if before != nil {
		ch.Before, _ = json.Marshal(before)
	}
	if after != nil {
		ch.After, _ = json.Marshal(after)
	}
	return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{ch}}}
}

// guildAction runs members and the moderation actions.
func (m *Module) guildAction(ctx context.Context, c *conn, call sdk.Call, p params) (sdk.Result, error) {
	if call.Action == "members" {
		return m.members(ctx, c, p)
	}
	if err := checkID("user", p.User); err != nil {
		return sdk.Result{}, err
	}
	api, err := c.reasoned(p.Reason)
	if err != nil {
		return sdk.Result{}, err
	}
	now := time.Now()
	var until time.Time
	switch call.Action {
	case "timeout_member":
		if until, err = endsAt(p.Duration, p.Until, now); err != nil {
			return sdk.Result{}, err
		}
	case "ban_member":
		if p.DeleteHours < 0 || p.DeleteHours > 168 {
			return sdk.Result{}, errors.New("deleteMessageHours is 0 to 168 (7 days)")
		}
	}
	t, err := m.lookup(ctx, c, p.User)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "timeout_member", "kick_member", "ban_member":
		if err := m.refuse(ctx, c, t); err != nil {
			return sdk.Result{}, err
		}
	}
	memberPath := seg("guilds", c.cfg.Guild, "members", p.User)
	banPath := seg("guilds", c.cfg.Guild, "bans", p.User)
	out := map[string]any{"user": p.User, "member": t.who(), "server": t.server}

	switch call.Action {
	case "timeout_member", "remove_timeout":
		if t.member == nil {
			return sdk.Result{}, fmt.Errorf("%s isn't in %s", t.who(), t.server)
		}
		was := t.member.timedOutUntil()
		if call.Action == "remove_timeout" {
			if was.IsZero() {
				out["note"] = "nothing to change: " + t.who() + " isn't timed out"
				return sdk.JSON(out)
			}
			if call.DryRun {
				return plan(fmt.Sprintf("Lift the timeout on %s now (it would end %s)", t.label(), ts(was)), t.label(), "update",
					map[string]string{"timedOutUntil": ts(was)}, map[string]string{"timedOutUntil": ""}), nil
			}
			if err := m.do(ctx, api, http.MethodPatch, memberPath, nil, map[string]any{"communication_disabled_until": nil}, nil); err != nil {
				return sdk.Result{}, err
			}
			out["timedOutUntil"] = ""
			r, err := sdk.JSON(out)
			r.Undo = sdk.UndoWith("timeout_member", map[string]string{"user": p.User, "until": ts(was)}, "Put the timeout back until "+ts(was))
			return r, err
		}
		if was.Equal(until) {
			out["timedOutUntil"] = ts(was)
			out["note"] = "nothing to change: " + t.who() + " is already timed out until then"
			return sdk.JSON(out)
		}
		if call.DryRun {
			sum := fmt.Sprintf("Time out %s until %s", t.label(), ts(until))
			if !was.IsZero() {
				sum += " (now until " + ts(was) + ")"
			}
			return plan(sum, t.label(), "update", map[string]string{"timedOutUntil": ts(was)}, map[string]string{"timedOutUntil": ts(until)}), nil
		}
		if err := m.do(ctx, api, http.MethodPatch, memberPath, nil, map[string]any{"communication_disabled_until": ts(until)}, nil); err != nil {
			return sdk.Result{}, err
		}
		out["timedOutUntil"] = ts(until)
		r, err := sdk.JSON(out)
		if was.IsZero() {
			r.Undo = sdk.UndoWith("remove_timeout", map[string]string{"user": p.User}, "Lift the timeout")
		} else {
			r.Undo = sdk.UndoWith("timeout_member", map[string]string{"user": p.User, "until": ts(was)}, "Restore the earlier timeout, until "+ts(was))
		}
		return r, err

	case "kick_member":
		if t.member == nil {
			out["note"] = "nothing to change: " + t.who() + " isn't in " + t.server
			return sdk.JSON(out)
		}
		if call.DryRun {
			return plan("Kick "+t.label()+" (they can rejoin with an invite; this can't be undone)", t.label(), "kick",
				map[string]any{"member": true, "joined": stamp(t.member.JoinedAt)}, map[string]any{"member": false}), nil
		}
		if err := m.do(ctx, api, http.MethodDelete, memberPath, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		out["kicked"] = true
		return sdk.JSON(out)

	case "ban_member", "unban_member":
		var ban struct {
			Reason *string `json:"reason"`
		}
		banned := true
		if err := m.do(ctx, c.bot, http.MethodGet, banPath, nil, nil, &ban); err != nil {
			if !rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, err
			}
			banned = false
		}
		if call.Action == "unban_member" {
			if !banned {
				out["note"] = "nothing to change: " + t.who() + " isn't banned from " + t.server
				return sdk.JSON(out)
			}
			if call.DryRun {
				before := map[string]any{"banned": true}
				if ban.Reason != nil {
					before["reason"] = clip(*ban.Reason, 200)
				}
				return plan("Unban "+t.label()+" (they can rejoin with an invite)", t.label(), "unban", before, map[string]any{"banned": false}), nil
			}
			if err := m.do(ctx, api, http.MethodDelete, banPath, nil, nil, nil); err != nil {
				return sdk.Result{}, err
			}
			out["banned"] = false
			r, err := sdk.JSON(out)
			r.Undo = sdk.UndoWith("ban_member", map[string]string{"user": p.User}, "Ban them again")
			return r, err
		}
		if banned {
			out["note"] = "nothing to change: " + t.who() + " is already banned from " + t.server
			return sdk.JSON(out)
		}
		if call.DryRun {
			sum := "Ban " + t.label()
			if t.member == nil {
				sum += " (not a member now; keeps them from joining)"
			}
			if p.DeleteHours > 0 {
				sum += fmt.Sprintf(", deleting their messages from the past %d hours (that part can't be undone)", p.DeleteHours)
			}
			return plan(sum, t.label(), "ban", map[string]any{"member": t.member != nil, "banned": false}, map[string]any{"member": false, "banned": true}), nil
		}
		body := map[string]any{"delete_message_seconds": p.DeleteHours * 3600}
		if err := m.do(ctx, api, http.MethodPut, banPath, nil, body, nil); err != nil {
			return sdk.Result{}, err
		}
		out["banned"] = true
		r, err := sdk.JSON(out)
		r.Undo = sdk.UndoWith("unban_member", map[string]string{"user": p.User}, "Unban them")
		return r, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// members lists the server's members by user id, a page at a time.
func (m *Module) members(ctx context.Context, c *conn, p params) (sdk.Result, error) {
	limit := p.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if p.After != "" {
		if err := checkID("after user", p.After); err != nil {
			return sdk.Result{}, err
		}
		q.Set("after", p.After)
	}
	var ms []member
	if err := m.do(ctx, c.bot, http.MethodGet, seg("guilds", c.cfg.Guild, "members"), q, nil, &ms); err != nil {
		if rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Result{}, errors.New("Discord: listing members needs the Server Members intent (Developer Portal, Bot, Privileged Gateway Intents)")
		}
		return sdk.Result{}, err
	}
	var roles []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	names := map[string]string{}
	if err := m.do(ctx, c.bot, http.MethodGet, seg("guilds", c.cfg.Guild, "roles"), nil, nil, &roles); err == nil {
		for _, r := range roles {
			names[r.ID] = r.Name
		}
	}
	out := []map[string]any{}
	for i := range ms {
		x := &ms[i]
		rs := []string{}
		for _, id := range x.Roles {
			if id == c.cfg.Guild { // @everyone
				continue
			}
			if n := names[id]; n != "" {
				rs = append(rs, clip(n, 100))
			} else {
				rs = append(rs, id)
			}
		}
		name := x.User.display()
		if x.Nick != "" {
			name = x.Nick
		}
		row := map[string]any{"id": x.User.ID, "name": clip(name, 100), "username": x.User.Username, "roles": rs, "joined": stamp(x.JoinedAt)}
		if x.User.Bot {
			row["bot"] = true
		}
		if u := x.timedOutUntil(); !u.IsZero() {
			row["timedOutUntil"] = ts(u)
		}
		out = append(out, row)
	}
	res := map[string]any{"members": out}
	if len(ms) == limit {
		res["next"] = ms[len(ms)-1].User.ID
	}
	return sdk.JSON(res)
}
