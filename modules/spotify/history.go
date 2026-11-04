package spotify

import (
	"bufio"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"
)

// play is one entry in the listening log.
type play struct {
	At      time.Time `json:"at"` // when Spotify says it was played (the end of the play)
	URI     string    `json:"uri"`
	Name    string    `json:"name"`
	Artists []string  `json:"artists,omitempty"`
	Album   string    `json:"album,omitempty"`
	MS      int       `json:"ms"`
	Context string    `json:"context,omitempty"`
}

// history is an append-only JSON-lines file of plays, collected from
// recently-played so it reaches back further than Spotify's 50 items.
type history struct {
	path string

	mu     sync.Mutex
	loaded bool
	plays  []play // oldest first
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

func openHistory(dir, instance string) *history {
	h := &history{}
	if dir != "" {
		h.path = filepath.Join(dir, unsafeName.ReplaceAllString(instance, "_")+".history.jsonl")
	}
	return h
}

func (h *history) loadLocked() {
	if h.loaded {
		return
	}
	h.loaded = true
	if h.path == "" {
		return
	}
	f, err := os.Open(h.path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var p play
		if json.Unmarshal(sc.Bytes(), &p) == nil && !p.At.IsZero() {
			h.plays = append(h.plays, p)
		}
	}
	sort.SliceStable(h.plays, func(i, j int) bool { return h.plays[i].At.Before(h.plays[j].At) })
}

// add appends plays newer than the newest stored one and returns how many
// were new.
func (h *history) add(ps []play) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.loadLocked()
	sort.Slice(ps, func(i, j int) bool { return ps[i].At.Before(ps[j].At) })
	var last time.Time
	if n := len(h.plays); n > 0 {
		last = h.plays[n-1].At
	}
	var fresh []play
	for _, p := range ps {
		if p.At.After(last) {
			fresh = append(fresh, p)
			last = p.At
		}
	}
	if len(fresh) == 0 {
		return 0, nil
	}
	h.plays = append(h.plays, fresh...)
	if h.path == "" {
		return len(fresh), nil
	}
	if err := os.MkdirAll(filepath.Dir(h.path), 0o700); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(h.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, p := range fresh {
		b, _ := json.Marshal(p)
		w.Write(b)
		w.WriteByte('\n')
	}
	return len(fresh), w.Flush()
}

func (h *history) newest() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.loadLocked()
	if n := len(h.plays); n > 0 {
		return h.plays[n-1].At
	}
	return time.Time{}
}

func (h *history) stats() (int, time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.loadLocked()
	if len(h.plays) == 0 {
		return 0, time.Time{}
	}
	return len(h.plays), h.plays[0].At
}

// between returns the plays in [from, to), oldest first, plus the play
// just before from (to estimate the first one's listening time).
func (h *history) between(from, to time.Time) (prev *play, out []play) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.loadLocked()
	i := sort.Search(len(h.plays), func(i int) bool { return !h.plays[i].At.Before(from) })
	if i > 0 {
		p := h.plays[i-1]
		prev = &p
	}
	for ; i < len(h.plays) && h.plays[i].At.Before(to); i++ {
		out = append(out, h.plays[i])
	}
	return prev, out
}

// collect polls recently-played until ctx ends.
func (c *conn) collect(ctx context.Context, every time.Duration) {
	defer close(c.done)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := c.sync(ctx); err != nil && ctx.Err() == nil {
			c.log("warn", "collecting Spotify listening history failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type recentPage struct {
	Items []struct {
		PlayedAt time.Time `json:"played_at"`
		Track    item      `json:"track"`
		Context  *struct {
			URI string `json:"uri"`
		} `json:"context"`
	} `json:"items"`
}

func (p recentPage) plays() []play {
	out := make([]play, 0, len(p.Items))
	for _, it := range p.Items {
		pl := play{At: it.PlayedAt.UTC(), URI: it.Track.URI, Name: it.Track.Name, MS: it.Track.DurationMS, Album: it.Track.Album.Name}
		for _, a := range it.Track.Artists {
			pl.Artists = append(pl.Artists, a.Name)
		}
		if it.Context != nil {
			pl.Context = it.Context.URI
		}
		out = append(out, pl)
	}
	return out
}

// sync stores the plays since the newest one in the log.
func (c *conn) sync(ctx context.Context) (int, error) {
	if c.hist == nil {
		return 0, errNoWeb
	}
	q := url.Values{"limit": {"50"}}
	if last := c.hist.newest(); !last.IsZero() {
		q.Set("after", strconv.FormatInt(last.UnixMilli(), 10))
	}
	var page recentPage
	if err := c.do(ctx, "GET", "/me/player/recently-played", q, nil, &page); err != nil {
		return 0, err
	}
	return c.hist.add(page.plays())
}

// listened estimates how long each play lasted: its duration, or less when
// the next play started sooner (skips).
func listened(prev *play, ps []play) []time.Duration {
	out := make([]time.Duration, len(ps))
	for i, p := range ps {
		d := time.Duration(p.MS) * time.Millisecond
		var before *play
		if i > 0 {
			before = &ps[i-1]
		} else {
			before = prev
		}
		if before != nil {
			if gap := p.At.Sub(before.At); gap > 0 && gap < d {
				d = gap
			}
		}
		out[i] = d
	}
	return out
}

type countRow struct {
	Name    string  `json:"name"`
	Artists string  `json:"artists,omitempty"`
	URI     string  `json:"uri,omitempty"`
	Plays   int     `json:"plays"`
	Minutes float64 `json:"minutes"`
}

func top(m map[string]*countRow, n int) []countRow {
	out := make([]countRow, 0, len(m))
	for _, r := range m {
		r.Minutes = round1(r.Minutes)
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Plays != out[j].Plays {
			return out[i].Plays > out[j].Plays
		}
		if out[i].Minutes != out[j].Minutes {
			return out[i].Minutes > out[j].Minutes
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }
