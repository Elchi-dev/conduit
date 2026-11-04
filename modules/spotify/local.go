package spotify

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

// localPlayer controls the Spotify desktop app on the computer the daemon
// runs on. It works without Premium and without the Web API.
type localPlayer interface {
	Name() string
	Status(ctx context.Context) (*localStatus, error)
	// Command is play, pause, playpause, next or previous.
	Command(ctx context.Context, cmd string) error
	// Open plays a spotify: URI (track, album, playlist, artist, episode).
	Open(ctx context.Context, uri string) error
	Seek(ctx context.Context, ms int) error
	Volume(ctx context.Context, percent int) error
	Shuffle(ctx context.Context, on bool) error
}

type localStatus struct {
	State    string `json:"state"` // playing, paused, stopped
	Track    string `json:"track,omitempty"`
	Artists  string `json:"artists,omitempty"`
	Album    string `json:"album,omitempty"`
	URI      string `json:"uri,omitempty"`
	Progress int    `json:"progressSeconds"`
	Duration int    `json:"durationSeconds,omitempty"`
	Volume   *int   `json:"volume,omitempty"`
	Shuffle  *bool  `json:"shuffle,omitempty"`
}

var errUnsupportedLocal = errors.New("the Spotify app doesn't support that here")

func newLocal() localPlayer {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd", "netbsd":
		return &mpris{}
	case "darwin":
		return &appleScript{run: runOsascript}
	}
	return nil // Windows: media keys can't target Spotify reliably
}

func localHint() string {
	switch runtime.GOOS {
	case "windows":
		return " (controlling the Spotify app directly isn't supported on Windows)"
	case "linux", "freebsd", "openbsd", "netbsd", "darwin":
		return ", or the Spotify app running on this computer with playback set to auto or local"
	}
	return ""
}

// mpris talks to Spotify's MPRIS interface on the D-Bus session bus.
type mpris struct {
	// bus overrides the session bus (tests).
	bus func() (*dbus.Conn, error)
}

const (
	mprisPath   = "/org/mpris/MediaPlayer2"
	mprisPlayer = "org.mpris.MediaPlayer2.Player"
)

func (p *mpris) Name() string { return "MPRIS" }

func (p *mpris) object(ctx context.Context) (*dbus.Conn, dbus.BusObject, error) {
	connect := p.bus
	if connect == nil {
		connect = func() (*dbus.Conn, error) { return dbus.ConnectSessionBus(dbus.WithContext(ctx)) }
	}
	conn, err := connect()
	if err != nil {
		return nil, nil, fmt.Errorf("no D-Bus session (is a desktop session running for this user?): %w", err)
	}
	var names []string
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.ListNames", 0).Store(&names); err != nil {
		conn.Close()
		return nil, nil, err
	}
	for _, n := range names {
		if n == "org.mpris.MediaPlayer2.spotify" || strings.HasPrefix(n, "org.mpris.MediaPlayer2.spotify.") {
			return conn, conn.Object(n, mprisPath), nil
		}
	}
	conn.Close()
	return nil, nil, errors.New("the Spotify app isn't running")
}

func (p *mpris) call(ctx context.Context, method string, args ...any) error {
	conn, obj, err := p.object(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return obj.CallWithContext(ctx, mprisPlayer+"."+method, 0, args...).Err
}

func (p *mpris) Command(ctx context.Context, cmd string) error {
	m, ok := map[string]string{"play": "Play", "pause": "Pause", "playpause": "PlayPause", "next": "Next", "previous": "Previous"}[cmd]
	if !ok {
		return errUnsupportedLocal
	}
	return p.call(ctx, m)
}

func (p *mpris) Open(ctx context.Context, uri string) error { return p.call(ctx, "OpenUri", uri) }

func (p *mpris) Seek(ctx context.Context, ms int) error {
	conn, obj, err := p.object(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	v, err := obj.GetProperty(mprisPlayer + ".Metadata")
	if err != nil {
		return err
	}
	md, _ := v.Value().(map[string]dbus.Variant)
	id, ok := md["mpris:trackid"].Value().(dbus.ObjectPath)
	if !ok {
		if s, ok2 := md["mpris:trackid"].Value().(string); ok2 && dbus.ObjectPath(s).IsValid() {
			id, ok = dbus.ObjectPath(s), true
		}
	}
	if !ok {
		return errors.New("the Spotify app didn't say which track is playing")
	}
	return obj.CallWithContext(ctx, mprisPlayer+".SetPosition", 0, id, int64(ms)*1000).Err
}

func (p *mpris) Volume(context.Context, int) error {
	return errors.New("the Spotify app on Linux ignores volume over MPRIS; change it in the app or the system mixer")
}

func (p *mpris) Shuffle(ctx context.Context, on bool) error {
	conn, obj, err := p.object(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return obj.SetProperty(mprisPlayer+".Shuffle", dbus.MakeVariant(on))
}

func (p *mpris) Status(ctx context.Context) (*localStatus, error) {
	conn, obj, err := p.object(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	st := &localStatus{State: "stopped"}
	if v, err := obj.GetProperty(mprisPlayer + ".PlaybackStatus"); err == nil {
		if s, ok := v.Value().(string); ok {
			st.State = strings.ToLower(s)
		}
	}
	if v, err := obj.GetProperty(mprisPlayer + ".Metadata"); err == nil {
		md, _ := v.Value().(map[string]dbus.Variant)
		st.Track, _ = md["xesam:title"].Value().(string)
		st.Album, _ = md["xesam:album"].Value().(string)
		if a, ok := md["xesam:artist"].Value().([]string); ok {
			st.Artists = strings.Join(a, ", ")
		}
		switch l := md["mpris:length"].Value().(type) {
		case int64:
			st.Duration = int(l / 1e6)
		case uint64:
			st.Duration = int(l / 1e6)
		}
		st.URI = mprisURI(md)
	}
	if v, err := obj.GetProperty(mprisPlayer + ".Position"); err == nil {
		if n, ok := v.Value().(int64); ok {
			st.Progress = int(n / 1e6)
		}
	}
	if v, err := obj.GetProperty(mprisPlayer + ".Shuffle"); err == nil {
		if b, ok := v.Value().(bool); ok {
			st.Shuffle = &b
		}
	}
	return st, nil
}

// mprisURI turns Spotify's track id ("/com/spotify/track/ID", or an
// open.spotify.com URL in xesam:url) into a spotify: URI.
func mprisURI(md map[string]dbus.Variant) string {
	var cands []string
	if id, ok := md["mpris:trackid"].Value().(dbus.ObjectPath); ok {
		cands = append(cands, string(id))
	}
	if s, ok := md["mpris:trackid"].Value().(string); ok {
		cands = append(cands, s)
	}
	if s, ok := md["xesam:url"].Value().(string); ok {
		cands = append(cands, s)
	}
	for _, c := range cands {
		if strings.HasPrefix(c, "/com/spotify/") {
			parts := strings.Split(strings.TrimPrefix(c, "/com/spotify/"), "/")
			if len(parts) == 2 {
				c = "spotify:" + parts[0] + ":" + parts[1]
			}
		}
		if r, err := parseRef(c); err == nil {
			return r.URI()
		}
	}
	return ""
}

// appleScript drives the Spotify app on macOS through osascript. Only
// validated URIs and numbers are ever put into a script.
type appleScript struct {
	run func(ctx context.Context, script string) (string, error)
}

func runOsascript(ctx context.Context, script string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "osascript", "-e", script).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "-1743") || strings.Contains(msg, "Not authorized") {
			return "", errors.New("macOS hasn't allowed Conduit to control Spotify; allow it in System Settings, Privacy & Security, Automation")
		}
		return "", fmt.Errorf("osascript: %s", firstNonEmpty(msg, err.Error()))
	}
	return strings.TrimSpace(string(out)), nil
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

func (a *appleScript) Name() string { return "AppleScript" }

// tell runs a command only when Spotify is already open, so a status check
// never launches it.
func (a *appleScript) tell(ctx context.Context, cmd string) (string, error) {
	out, err := a.run(ctx, `if application "Spotify" is running then
tell application "Spotify" to `+cmd+`
else
return "not running"
end if`)
	if err != nil {
		return "", err
	}
	if out == "not running" {
		return "", errors.New("the Spotify app isn't running")
	}
	return out, nil
}

func (a *appleScript) Command(ctx context.Context, cmd string) error {
	s, ok := map[string]string{"play": "play", "pause": "pause", "playpause": "playpause", "next": "next track", "previous": "previous track"}[cmd]
	if !ok {
		return errUnsupportedLocal
	}
	_, err := a.tell(ctx, s)
	return err
}

func (a *appleScript) Open(ctx context.Context, uri string) error {
	r, err := parseRef(uri)
	if err != nil {
		return err
	}
	_, err = a.tell(ctx, `play track "`+r.URI()+`"`)
	return err
}

func (a *appleScript) Seek(ctx context.Context, ms int) error {
	_, err := a.tell(ctx, "set player position to "+strconv.FormatFloat(float64(ms)/1000, 'f', 1, 64))
	return err
}

func (a *appleScript) Volume(ctx context.Context, percent int) error {
	_, err := a.tell(ctx, "set sound volume to "+strconv.Itoa(percent))
	return err
}

func (a *appleScript) Shuffle(ctx context.Context, on bool) error {
	_, err := a.tell(ctx, "set shuffling to "+strconv.FormatBool(on))
	return err
}

const asStatus = `return (player state as string) & linefeed & (name of current track) & linefeed & (artist of current track) & linefeed & (album of current track) & linefeed & (spotify url of current track) & linefeed & (player position as string) & linefeed & ((duration of current track) as string) & linefeed & (sound volume as string) & linefeed & (shuffling as string)`

func (a *appleScript) Status(ctx context.Context) (*localStatus, error) {
	out, err := a.tell(ctx, asStatus)
	if err != nil {
		return nil, err
	}
	f := strings.Split(out, "\n")
	for len(f) < 9 {
		f = append(f, "")
	}
	num := func(s string) float64 {
		v, _ := strconv.ParseFloat(strings.ReplaceAll(strings.TrimSpace(s), ",", "."), 64)
		return v
	}
	st := &localStatus{State: strings.TrimSpace(f[0]), Track: f[1], Artists: f[2], Album: f[3], Progress: int(num(f[5])), Duration: int(num(f[6]) / 1000)}
	if r, err := parseRef(strings.TrimSpace(f[4])); err == nil {
		st.URI = r.URI()
	}
	if v := strings.TrimSpace(f[7]); v != "" {
		n := int(num(v))
		st.Volume = &n
	}
	if v := strings.TrimSpace(f[8]); v != "" {
		b := v == "true"
		st.Shuffle = &b
	}
	return st, nil
}
