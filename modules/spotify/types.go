package spotify

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// ref is a Spotify object: kind and 22-character id.
type ref struct {
	Kind, ID string
}

func (r ref) URI() string { return "spotify:" + r.Kind + ":" + r.ID }

var (
	idRe     = regexp.MustCompile(`^[A-Za-z0-9]{22}$`)
	deviceRe = regexp.MustCompile(`^[A-Za-z0-9]{8,64}$`)
	kinds    = map[string]bool{"track": true, "album": true, "artist": true, "playlist": true, "episode": true, "show": true}
)

// parseRef accepts spotify:kind:id, an open.spotify.com link (as Share,
// Copy link gives it) or, with a default kind, a bare id.
func parseRef(s string, defaultKind ...string) (ref, error) {
	s = strings.TrimSpace(s)
	bad := errors.New("give a Spotify link or URI, like spotify:track:… or https://open.spotify.com/track/…")
	switch {
	case strings.HasPrefix(s, "spotify:"):
		p := strings.Split(s, ":")
		// spotify:user:x:playlist:id is the old playlist form
		if len(p) == 5 && p[1] == "user" && p[3] == "playlist" {
			p = []string{"spotify", "playlist", p[4]}
		}
		if len(p) != 3 || !kinds[p[1]] || !idRe.MatchString(p[2]) {
			return ref{}, bad
		}
		return ref{p[1], p[2]}, nil
	case strings.HasPrefix(s, "https://open.spotify.com/") || strings.HasPrefix(s, "http://open.spotify.com/"):
		u, err := url.Parse(s)
		if err != nil {
			return ref{}, bad
		}
		seg := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(seg) > 0 && strings.HasPrefix(seg[0], "intl-") {
			seg = seg[1:]
		}
		if len(seg) == 4 && seg[0] == "user" && seg[2] == "playlist" {
			seg = seg[2:]
		}
		if len(seg) != 2 || !kinds[seg[0]] || !idRe.MatchString(seg[1]) {
			return ref{}, bad
		}
		return ref{seg[0], seg[1]}, nil
	case len(defaultKind) > 0 && idRe.MatchString(s):
		return ref{defaultKind[0], s}, nil
	}
	return ref{}, bad
}

// parseKind parses s and requires one of the kinds.
func parseKind(s string, allowed ...string) (ref, error) {
	r, err := parseRef(s, allowed[0])
	if err != nil {
		return r, err
	}
	for _, k := range allowed {
		if r.Kind == k {
			return r, nil
		}
	}
	return ref{}, errors.New("that is a " + r.Kind + "; this needs a " + strings.Join(allowed, " or "))
}

type named struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URI  string `json:"uri"`
}

// item is a track or an episode as the Web API returns it.
type item struct {
	Type       string  `json:"type"`
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	URI        string  `json:"uri"`
	DurationMS int     `json:"duration_ms"`
	Explicit   bool    `json:"explicit"`
	Artists    []named `json:"artists"`
	Album      struct {
		named
		ReleaseDate string `json:"release_date"`
	} `json:"album"`
	Show        *named `json:"show"`
	TrackNumber int    `json:"track_number"`
}

// Track is a track or episode as the module returns it.
type Track struct {
	Name     string `json:"name"`
	Artists  string `json:"artists,omitempty"`
	Album    string `json:"album,omitempty"`
	Show     string `json:"show,omitempty"`
	URI      string `json:"uri"`
	Duration int    `json:"durationSeconds,omitempty"`
	Explicit bool   `json:"explicit,omitempty"`
	Released string `json:"released,omitempty"`
}

func (it item) out() Track {
	t := Track{Name: it.Name, URI: it.URI, Duration: it.DurationMS / 1000, Explicit: it.Explicit, Album: it.Album.Name, Released: it.Album.ReleaseDate}
	var a []string
	for _, x := range it.Artists {
		a = append(a, x.Name)
	}
	t.Artists = strings.Join(a, ", ")
	if it.Show != nil {
		t.Show = it.Show.Name
	}
	return t
}

func tracks(items []item) []Track {
	out := make([]Track, 0, len(items))
	for _, it := range items {
		if it.URI != "" {
			out = append(out, it.out())
		}
	}
	return out
}

type artist struct {
	named
	Genres []string `json:"genres"`
}

// Artist as the module returns it.
type Artist struct {
	Name   string   `json:"name"`
	URI    string   `json:"uri"`
	Genres []string `json:"genres,omitempty"`
}

type album struct {
	named
	AlbumType   string  `json:"album_type"`
	ReleaseDate string  `json:"release_date"`
	TotalTracks int     `json:"total_tracks"`
	Artists     []named `json:"artists"`
	Tracks      *struct {
		Items []item `json:"items"`
		Total int    `json:"total"`
	} `json:"tracks"`
}

// Album as the module returns it.
type Album struct {
	Name     string  `json:"name"`
	Artists  string  `json:"artists"`
	URI      string  `json:"uri"`
	Type     string  `json:"type,omitempty"`
	Released string  `json:"released,omitempty"`
	Tracks   int     `json:"tracks,omitempty"`
	List     []Track `json:"trackList,omitempty"`
}

func (a album) out() Album {
	var ar []string
	for _, x := range a.Artists {
		ar = append(ar, x.Name)
	}
	o := Album{Name: a.Name, Artists: strings.Join(ar, ", "), URI: a.URI, Type: a.AlbumType, Released: a.ReleaseDate, Tracks: a.TotalTracks}
	if a.Tracks != nil {
		o.List = tracks(a.Tracks.Items)
		for i := range o.List {
			o.List[i].Album = ""
		}
	}
	return o
}

type playlist struct {
	named
	Description   string `json:"description"`
	Public        *bool  `json:"public"`
	Collaborative bool   `json:"collaborative"`
	SnapshotID    string `json:"snapshot_id"`
	Owner         struct {
		ID   string `json:"id"`
		Name string `json:"display_name"`
	} `json:"owner"`
	// Spotify renamed tracks to items in 2026; both are read.
	Items  *struct{ Total int } `json:"items"`
	Tracks *struct{ Total int } `json:"tracks"`
}

// Playlist as the module returns it.
type Playlist struct {
	Name          string `json:"name"`
	URI           string `json:"uri"`
	Owner         string `json:"owner"`
	Tracks        int    `json:"tracks"`
	Public        *bool  `json:"public,omitempty"`
	Collaborative bool   `json:"collaborative,omitempty"`
	Description   string `json:"description,omitempty"`
	Mine          bool   `json:"mine,omitempty"`
}

func (p playlist) out(me string) Playlist {
	o := Playlist{Name: p.Name, URI: p.URI, Owner: p.Owner.Name, Public: p.Public, Collaborative: p.Collaborative, Description: p.Description, Mine: me != "" && p.Owner.ID == me}
	if o.Owner == "" {
		o.Owner = p.Owner.ID
	}
	if p.Items != nil {
		o.Tracks = p.Items.Total
	} else if p.Tracks != nil {
		o.Tracks = p.Tracks.Total
	}
	return o
}

// playlistEntry is one row of a playlist's items (item, or track before
// the 2026 rename).
type playlistEntry struct {
	AddedAt string `json:"added_at"`
	Item    *item  `json:"item"`
	Track   *item  `json:"track"`
}

func (e playlistEntry) it() *item {
	if e.Item != nil {
		return e.Item
	}
	return e.Track
}

type device struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	IsActive bool   `json:"is_active"`
	Volume   *int   `json:"volume_percent"`
	Private  bool   `json:"is_private_session"`
}

type player struct {
	IsPlaying bool   `json:"is_playing"`
	Progress  int    `json:"progress_ms"`
	Shuffle   bool   `json:"shuffle_state"`
	Repeat    string `json:"repeat_state"`
	Device    device `json:"device"`
	Context   *struct {
		URI  string `json:"uri"`
		Type string `json:"type"`
	} `json:"context"`
	Type string `json:"currently_playing_type"`
	Item *item  `json:"item"`
}
