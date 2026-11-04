package spotify

import "github.com/elchi-dev/conduit/pkg/sdk"

const (
	deviceProp = `"device":{"type":"string","description":"Device id from devices; empty uses the active one"}`
	pageProps  = `"limit":{"type":"integer","default":20,"maximum":50},"offset":{"type":"integer"}`
	rangeProp  = `"range":{"type":"string","enum":["short","medium","long"],"default":"medium","description":"short: about 4 weeks, medium: about 6 months, long: about a year"}`
	refProp    = `"uri":{"type":"string","description":"spotify:…:… or an open.spotify.com link"}`
	urisProp   = `"uris":{"type":"array","items":{"type":"string"},"description":"Tracks or episodes (URIs or links)"}`
	plProp     = `"playlist":{"type":"string","description":"Playlist URI or link"}`
)

func obj(props string, required ...string) []byte {
	req := ""
	if len(required) > 0 {
		req = `"required":["` + joinQ(required) + `"],`
	}
	return sdk.Schema(`{"type":"object",` + req + `"properties":{` + props + `}}`)
}

func joinQ(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += `","`
		}
		out += x
	}
	return out
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "spotify", Name: "Spotify", Version: "0.2.0", Category: "Media", Icon: "music",
		Description: "What you listen to (now, recently, most, saved, history) and playback of anything on your devices.",
		Presets:     []string{"gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"clientId":{"type":"string","description":"From your own app at developer.spotify.com/dashboard"},
			"clientSecret":{"type":"string","x-secret":true},
			"refreshToken":{"type":"string","x-secret":true,"description":"From the Authorization Code flow; see the module docs"},
			"playback":{"type":"string","enum":["auto","web","local"],"default":"auto","description":"auto: the Web API, or the Spotify app on this computer when the account isn't Premium. local: always the app (Linux, macOS)."},
			"history":{"type":"boolean","default":true,"title":"Keep a listening history","description":"Collect recently played tracks into a local log for stats"},
			"historyMinutes":{"type":"integer","default":10,"minimum":2,"title":"Collect every (minutes)"},
			"timezone":{"type":"string","description":"For per-day stats, e.g. Europe/Berlin; default this computer's"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "now_playing", Title: "Now playing", Description: "Track or episode, progress, device, shuffle and repeat, what it plays from.", Risk: sdk.RiskRead},
			{Name: "recently_played", Title: "Recently played", Description: "The last tracks with the time each was played (Spotify keeps 50).", Risk: sdk.RiskRead,
				Input: obj(`"limit":{"type":"integer","default":20,"maximum":50}`)},
			{Name: "top_tracks", Title: "Top tracks", Risk: sdk.RiskRead, Input: obj(rangeProp + "," + pageProps)},
			{Name: "top_artists", Title: "Top artists", Risk: sdk.RiskRead, Input: obj(rangeProp + "," + pageProps)},
			{Name: "saved_tracks", Title: "Liked songs", Risk: sdk.RiskRead, Input: obj(pageProps)},
			{Name: "saved_albums", Title: "Saved albums", Risk: sdk.RiskRead, Input: obj(pageProps)},
			{Name: "playlists", Title: "Playlists", Description: "Your playlists, own and followed.", Risk: sdk.RiskRead, Input: obj(pageProps)},
			{Name: "playlist_tracks", Title: "Playlist tracks", Description: "Tracks of a playlist you own or collaborate on.", Risk: sdk.RiskRead, Input: obj(plProp+","+`"limit":{"type":"integer","default":50,"maximum":100},"offset":{"type":"integer"}`, "playlist")},
			{Name: "search", Title: "Search", Description: "Tracks, albums, artists, playlists, shows or episodes, with URIs to play.", Risk: sdk.RiskRead,
				Input: obj(`"query":{"type":"string"},"types":{"type":"array","items":{"type":"string","enum":["track","album","artist","playlist","show","episode"]},"default":["track"]},"limit":{"type":"integer","default":5,"maximum":10},"offset":{"type":"integer"}`, "query")},
			{Name: "track", Title: "Track", Risk: sdk.RiskRead, Input: obj(refProp, "uri")},
			{Name: "album", Title: "Album", Description: "Album with its track list.", Risk: sdk.RiskRead, Input: obj(refProp, "uri")},
			{Name: "artist", Title: "Artist", Description: "Artist with genres and albums.", Risk: sdk.RiskRead, Input: obj(refProp, "uri")},
			{Name: "queue", Title: "Queue", Description: "What plays next.", Risk: sdk.RiskRead},
			{Name: "devices", Title: "Devices", Description: "Device ids for the other actions.", Risk: sdk.RiskRead},
			{Name: "history", Title: "Listening history", Description: "Plays from the local log (kept beyond Spotify's 50), newest first.", Risk: sdk.RiskRead,
				Input: obj(`"since":{"type":"string","description":"YYYY-MM-DD or RFC 3339"},"until":{"type":"string"},"artist":{"type":"string"},"limit":{"type":"integer","default":100,"maximum":1000}`)},
			{Name: "listening_stats", Title: "Listening stats", Description: "Top artists, tracks and albums and minutes listened per day, from the local log.", Risk: sdk.RiskRead,
				Input: obj(`"days":{"type":"integer","default":7,"maximum":366},"top":{"type":"integer","default":10,"maximum":50}`)},
			{Name: "auth_url", Title: "Authorize link", Description: "The link to get a refresh token with every scope this module uses.", Risk: sdk.RiskRead,
				Input: obj(`"redirectUri":{"type":"string","default":"http://127.0.0.1:8888/callback"}`)},

			{Name: "play", Title: "Play", Description: "Resume, or play a track, album, playlist, artist, episode or the top search result.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: obj(refProp + "," + urisProp + `,"query":{"type":"string","description":"Search and play the first result"},"type":{"type":"string","enum":["track","album","artist","playlist","show","episode"],"default":"track","description":"What the query looks for"},"startAt":{"type":"string","description":"Start at this track within an album or playlist"},"positionMs":{"type":"integer"},` + deviceProp)},
			{Name: "pause", Title: "Pause", Risk: sdk.RiskWrite, Reversible: true, Input: obj(deviceProp)},
			{Name: "resume", Title: "Resume", Risk: sdk.RiskWrite, Reversible: true, Input: obj(deviceProp)},
			{Name: "next", Title: "Next track", Risk: sdk.RiskWrite, Input: obj(deviceProp)},
			{Name: "previous", Title: "Previous track", Risk: sdk.RiskWrite, Input: obj(deviceProp)},
			{Name: "seek", Title: "Seek", Risk: sdk.RiskWrite, Reversible: true, Input: obj(`"positionMs":{"type":"integer"},"seconds":{"type":"integer"},` + deviceProp)},
			{Name: "volume", Title: "Volume", Risk: sdk.RiskWrite, Reversible: true,
				Input: obj(`"percent":{"type":"integer","minimum":0,"maximum":100},`+deviceProp, "percent")},
			{Name: "shuffle", Title: "Shuffle", Risk: sdk.RiskWrite, Reversible: true, Input: obj(`"on":{"type":"boolean"},`+deviceProp, "on")},
			{Name: "repeat", Title: "Repeat", Risk: sdk.RiskWrite, Reversible: true, Input: obj(`"mode":{"type":"string","enum":["off","track","context"]},`+deviceProp, "mode")},
			{Name: "add_to_queue", Title: "Add to queue", Risk: sdk.RiskWrite, Input: obj(refProp+","+deviceProp, "uri")},
			{Name: "transfer", Title: "Move playback", Description: "Continue playing on another device.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: obj(deviceProp+`,"play":{"type":"boolean","default":true}`, "device")},
			{Name: "create_playlist", Title: "Create a playlist", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: obj(`"name":{"type":"string"},"description":{"type":"string"},"public":{"type":"boolean","default":false},`+urisProp, "name")},
			{Name: "playlist_add", Title: "Add to a playlist", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: obj(plProp+","+urisProp+`,"position":{"type":"integer","description":"0 is the top; empty appends"}`, "playlist", "uris")},
			{Name: "playlist_remove", Title: "Remove from a playlist", Description: "Removes every occurrence of the tracks. Undo puts them back where they were.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: obj(plProp+","+urisProp, "playlist", "uris")},
			{Name: "playlist_reorder", Title: "Reorder a playlist", Description: "Move rangeLength tracks starting at rangeStart to before insertBefore (0-based).", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: obj(plProp+`,"rangeStart":{"type":"integer"},"insertBefore":{"type":"integer"},"rangeLength":{"type":"integer","default":1}`, "playlist", "rangeStart", "insertBefore")},
			{Name: "save", Title: "Save to library", Description: "Like tracks, save albums or episodes, follow artists or playlists.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: obj(urisProp, "uris")},
			{Name: "unsave", Title: "Remove from library", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: obj(urisProp, "uris")},
		},
		Resources: []sdk.ResourceSpec{{Kind: "playlist", Title: "Playlists", ListAction: "playlists", GetAction: "playlist_tracks", ViewHint: "table"}},
	}
}
