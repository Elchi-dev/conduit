package games

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func write(t *testing.T, path, s string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// sqliteFrom builds a database at path from a .sql fixture.
func sqliteFrom(t *testing.T, path, fixtureName string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, stmt := range strings.Split(fixture(t, fixtureName), ";\n") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v\n%s", fixtureName, err, stmt)
		}
	}
}

type fakeReg map[string][]regKey

func (r fakeReg) subkeys(root, path string) []regKey { return r[root+`\`+path] }
func (r fakeReg) values(root, path string) map[string]string {
	i := strings.LastIndex(path, `\`)
	for _, k := range r[root+`\`+path[:max(i, 0)]] {
		if k.Name == path[i+1:] {
			return k.Values
		}
	}
	return nil
}

func emptyEnv(t *testing.T, goos string) *env {
	home := t.TempDir()
	return &env{GOOS: goos, Home: home, ConfigHome: filepath.Join(home, ".config"), DataHome: filepath.Join(home, ".local", "share"),
		ProgramData: filepath.Join(home, "ProgramData"), AppData: filepath.Join(home, "AppData", "Roaming"),
		LocalAppData: filepath.Join(home, "AppData", "Local")}
}

var t0 = time.Date(2026, 11, 3, 20, 0, 0, 0, time.UTC)

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestModule(t *testing.T, e *env, h sdk.Host) (*Module, *clock, *[]string) {
	t.Helper()
	m := New()
	c := &clock{t0}
	m.Env, m.Now, m.Loc, m.DataDir = e, c.now, time.UTC, t.TempDir()
	var launched []string
	m.Open = func(u string) error { launched = append(launched, u); return nil }
	m.Exec = func(exe string, args []string, dir string) error {
		launched = append(launched, strings.TrimSpace(exe+" "+strings.Join(args, " ")))
		return nil
	}
	m.Procs = func(context.Context) ([]proc, error) { return nil, nil }
	if h == nil {
		h = fakehost.New(nil)
	}
	if err := m.Configure(context.Background(), h, InstanceID, nil); err != nil {
		t.Fatal(err)
	}
	return m, c, &launched
}

func call(t *testing.T, m *Module, action string, input any, out any) sdk.Result {
	t.Helper()
	b, _ := json.Marshal(input)
	r, err := m.Invoke(context.Background(), sdk.Call{Instance: InstanceID, Action: action, Input: b})
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	if out != nil {
		if err := json.Unmarshal(r.Output, out); err != nil {
			t.Fatalf("%s output %s: %v", action, r.Output, err)
		}
	}
	return r
}

func byID(gs []Game) map[string]Game {
	out := map[string]Game{}
	for _, g := range gs {
		out[g.ID] = g
	}
	return out
}

func TestSteamLibraryAndLaunch(t *testing.T) {
	steam := t.TempDir()
	extra := t.TempDir()
	write(t, filepath.Join(steam, "steamapps", "libraryfolders.vdf"), `"libraryfolders"
{
	"0" { "path" "`+strings.ReplaceAll(steam, `\`, `\\`)+`" }
	"1" { "path"	"`+strings.ReplaceAll(extra, `\`, `\\`)+`" // second drive
	}
}`)
	write(t, filepath.Join(steam, "steamapps", "appmanifest_570.acf"), `"AppState" { "appid" "570" "name" "Dota 2" "installdir" "dota 2 beta" "SizeOnDisk" "40000000000" "LastUpdated" "1761800000" }`)
	write(t, filepath.Join(extra, "steamapps", "appmanifest_1086940.acf"), `"AppState"
{
	"appid"		"1086940"
	"name"		"Baldur's Gate 3"
	"installdir"		"Baldurs Gate 3"
	"SizeOnDisk"		"150000000000"
}`)
	write(t, filepath.Join(extra, "steamapps", "appmanifest_228980.acf"), `"AppState" { "appid" "228980" "name" "Steamworks Common Redistributables" }`)
	write(t, filepath.Join(extra, "steamapps", "appmanifest_2805730.acf"), `"AppState" { "appid" "2805730" "name" "Proton 9.0" }`)
	write(t, filepath.Join(steam, "userdata", "12345678", "config", "localconfig.vdf"), fixture(t, "localconfig.vdf"))
	write(t, filepath.Join(steam, "appcache", "librarycache", "570", "library_600x900.jpg"), "\xff\xd8\xff\xe0 fake jpeg")

	e := emptyEnv(t, "linux")
	e.SteamPath = steam
	m, _, launched := newTestModule(t, e, nil)
	ctx := context.Background()
	if h := m.Health(ctx, InstanceID); h.Status != "ok" || h.Message != "2 games installed" {
		t.Fatalf("health %+v", h)
	}
	var gs []Game
	call(t, m, "library", nil, &gs)
	if len(gs) != 2 || gs[0].Title != "Baldur's Gate 3" || gs[0].Size != "150.0 GB" || gs[1].Updated == "" || gs[1].AppID != 570 {
		t.Fatalf("library %+v", gs)
	}
	dota := byID(gs)["steam:570"]
	if dota.LauncherPlaySeconds != 12345*60 || dota.TotalPlaySeconds != 12345*60 || dota.LastPlayed != "2025-10-31T08:40:00Z" {
		t.Fatalf("play time from localconfig: %+v", dota)
	}
	if dota.Cover != "https://cdn.cloudflare.steamstatic.com/steam/apps/570/library_600x900.jpg" || !dota.HasCover {
		t.Fatalf("cover %q", dota.Cover)
	}
	// The local cache is preferred over the CDN.
	if b, ct, err := m.Cover(ctx, "steam:570"); err != nil || ct != "image/jpeg" || !strings.Contains(string(b), "fake jpeg") {
		t.Fatalf("cover %v %s", err, ct)
	}
	call(t, m, "library", map[string]any{"sort": "played"}, &gs)
	if gs[0].ID != "steam:570" {
		t.Fatalf("most played first: %+v", gs[0])
	}
	call(t, m, "library", map[string]any{"query": "gate"}, &gs)
	if len(gs) != 1 || gs[0].ID != "steam:1086940" {
		t.Fatalf("query %+v", gs)
	}
	call(t, m, "launch", map[string]int{"appId": 570}, nil)
	call(t, m, "play", map[string]string{"id": "steam:1086940"}, nil)
	if strings.Join(*launched, ",") != "steam://rungameid/570,steam://rungameid/1086940" {
		t.Fatalf("launched %v", *launched)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: "launch", Input: json.RawMessage(`{"appId":1}`)}); err == nil {
		t.Fatal("launching an uninstalled app must fail")
	}
}

func TestEpicWindows(t *testing.T) {
	e := emptyEnv(t, "windows")
	data := filepath.Join(e.ProgramData, "Epic", "EpicGamesLauncher", "Data")
	write(t, filepath.Join(data, "Manifests", "6D1A0E9C.item"), fixture(t, "epic_fortnite.item"))
	write(t, filepath.Join(data, "Manifests", "AA11BB22.item"), fixture(t, "epic_dlc.item"))
	write(t, filepath.Join(data, "Catalog", "catcache.bin"), base64.StdEncoding.EncodeToString([]byte(fixture(t, "epic_catcache.json"))))
	found, gs, err := scanEpic(e)
	if err != nil || !found || len(gs) != 1 {
		t.Fatalf("epic %v %v %+v", found, err, gs)
	}
	g := gs[0]
	if g.ID != "epic:Fortnite" || g.Title != "Fortnite" || g.SizeBytes != 34512345678 || g.InstallPath != `C:\Program Files\Epic Games\Fortnite` {
		t.Fatalf("game %+v", g)
	}
	if g.launch.URI != "com.epicgames.launcher://apps/fn%3A4fe75bbc5a674f4f9b356b5c90567da5%3AFortnite?action=launch&silent=true" {
		t.Fatalf("uri %s", g.launch.URI)
	}
	if g.Cover != "https://cdn1.epicgames.com/offer/fn/box-tall_1200x1600.jpg" {
		t.Fatalf("cover %q", g.Cover)
	}
	if strings.Join(g.ProcessNames, ",") != "FortniteLauncher.exe,FortniteClient-Win64-Shipping.exe" {
		t.Fatalf("process names %v", g.ProcessNames)
	}
}

func TestLegendaryAndHeroicLinux(t *testing.T) {
	skipOnWindows(t)
	e := emptyEnv(t, "linux")
	write(t, filepath.Join(e.ConfigHome, "heroic", "legendaryConfig", "legendary", "installed.json"), fixture(t, "legendary_installed.json"))
	write(t, filepath.Join(e.ConfigHome, "heroic", "store_cache", "legendary_library.json"), fixture(t, "heroic_legendary_library.json"))
	// The same game installed with plain Legendary is listed once.
	write(t, filepath.Join(e.ConfigHome, "legendary", "installed.json"), fixture(t, "legendary_installed.json"))
	found, gs, _ := scanEpic(e)
	if !found || len(gs) != 1 {
		t.Fatalf("legendary %v %+v", found, gs)
	}
	g := gs[0]
	if g.ID != "epic:Sugar" || g.Title != "Rocket League" || g.launch.URI != "heroic://launch?appName=Sugar&runner=legendary" ||
		g.Cover != "https://cdn1.epicgames.com/offer/9773aa1aa54f4f7b80e44bef04986cea/rl-tall.jpg" ||
		g.Executables[0] != "/home/ana/Games/Heroic/rocketleague/RocketLeague/Binaries/Win64/RocketLeague.exe" {
		t.Fatalf("game %+v %+v", g, g.launch)
	}
	// Plain Legendary alone launches through its command.
	e2 := emptyEnv(t, "linux")
	write(t, filepath.Join(e2.ConfigHome, "legendary", "installed.json"), fixture(t, "legendary_installed.json"))
	_, gs, _ = scanEpic(e2)
	if len(gs) != 1 || gs[0].launch.Exe != "legendary" || strings.Join(gs[0].launch.Args, " ") != "launch Sugar" {
		t.Fatalf("legendary launch %+v", gs)
	}
}

func TestRiot(t *testing.T) {
	e := emptyEnv(t, "windows")
	root := filepath.Join(e.ProgramData, "Riot Games")
	write(t, filepath.Join(root, "RiotClientInstalls.json"), fixture(t, "RiotClientInstalls.json"))
	write(t, filepath.Join(root, "Metadata", "league_of_legends.live", "league_of_legends.live.product_settings.yaml"), fixture(t, "league_of_legends.live.product_settings.yaml"))
	write(t, filepath.Join(root, "Metadata", "valorant.live", "valorant.live.product_settings.yaml"), fixture(t, "valorant.live.product_settings.yaml"))
	write(t, filepath.Join(root, "Metadata", "riot_client", "riot_client.product_settings.yaml"), "product_install_full_path: \"C:/Riot Games/Riot Client\"\n")
	found, gs, _ := scanRiot(e)
	if !found || len(gs) != 2 {
		t.Fatalf("riot %+v", gs)
	}
	ids := byID(gs)
	lol := ids["riot:league_of_legends"]
	if lol.Title != "League of Legends" || filepath.ToSlash(lol.InstallPath) != "C:/Riot Games/League of Legends" {
		t.Fatalf("lol %+v", lol)
	}
	if filepath.ToSlash(lol.launch.Exe) != "C:/Riot Games/Riot Client/RiotClientServices.exe" || strings.Join(lol.launch.Args, " ") != "--launch-product=league_of_legends --launch-patchline=live" {
		t.Fatalf("launch %+v", lol.launch)
	}
	if ids["riot:valorant"].Title != "VALORANT" {
		t.Fatalf("valorant %+v", ids["riot:valorant"])
	}
}

func TestGOG(t *testing.T) {
	e := emptyEnv(t, "windows")
	reg := fakeReg{
		`HKLM\SOFTWARE\WOW6432Node\GOG.com\Games`: {
			{Name: "1207658924", Values: map[string]string{"gameID": "1207658924", "gameName": "The Witcher 3: Wild Hunt - Game of the Year Edition",
				"path": `C:\GOG Games\The Witcher 3 Wild Hunt GOTY`, "exe": `C:\GOG Games\The Witcher 3 Wild Hunt GOTY\bin\x64\witcher3.exe`,
				"workingDir": `C:\GOG Games\The Witcher 3 Wild Hunt GOTY\bin\x64`, "launchParam": ""}},
			{Name: "1640424747", Values: map[string]string{"gameID": "1640424747", "gameName": "The Witcher 3 - Hearts of Stone", "dependsOn": "1207658924", "path": `C:\GOG Games\The Witcher 3 Wild Hunt GOTY`}},
		},
	}
	e.Reg, e.RegValues = reg.subkeys, reg.values
	sqliteFrom(t, filepath.Join(e.ProgramData, "GOG.com", "Galaxy", "storage", "galaxy-2.0.db"), "galaxy.sql")
	found, gs, err := scanGOG(e)
	if err != nil || !found || len(gs) != 2 {
		t.Fatalf("gog %v %+v", err, gs)
	}
	ids := byID(gs)
	w3 := ids["gog:1207658924"]
	if w3.Cover != "https://images.gog-statics.com/w3vertical_342x482.jpg" || w3.LauncherPlaySeconds != 7380*60 || w3.launcherLast.IsZero() {
		t.Fatalf("witcher %+v", w3)
	}
	if w3.launch.Exe == "" || !strings.HasSuffix(w3.launch.Exe, "witcher3.exe") || w3.launch.Dir == "" {
		t.Fatalf("gog games start directly: %+v", w3.launch)
	}
	de := ids["gog:1495134320"]
	if de.Title != "Disco Elysium - The Final Cut" || de.launch.URI != "goggalaxy://openGameView/1495134320" {
		t.Fatalf("galaxy-only game %+v", de)
	}

	// Heroic on Linux.
	l := emptyEnv(t, "linux")
	write(t, filepath.Join(l.ConfigHome, "heroic", "gog_store", "installed.json"), fixture(t, "heroic_gog_installed.json"))
	write(t, filepath.Join(l.ConfigHome, "heroic", "store_cache", "gog_library.json"), fixture(t, "heroic_gog_library.json"))
	_, gs, _ = scanGOG(l)
	if len(gs) != 1 || gs[0].Title != "Cyberpunk 2077" || gs[0].launch.URI != "heroic://launch?appName=1423049311&runner=gog" || !gs[0].HasCover {
		t.Fatalf("heroic gog %+v", gs)
	}
}

// pb encodes protobuf fields for the product.db fixture.
func pbLen(num int, b []byte) []byte {
	out := pbUvarint(uint64(num<<3 | 2))
	out = append(out, pbUvarint(uint64(len(b)))...)
	return append(out, b...)
}

func pbInt(num int, v uint64) []byte { return append(pbUvarint(uint64(num<<3)), pbUvarint(v)...) }

func pbUvarint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

func productInstall(uid, code, path string) []byte {
	var b []byte
	b = append(b, pbLen(1, []byte(uid))...)
	b = append(b, pbLen(2, []byte(code))...)
	settings := append(pbLen(1, []byte(path)), pbLen(2, []byte("EU"))...)
	settings = append(settings, pbLen(3, []byte("enUS"))...)
	b = append(b, pbLen(3, settings)...)
	base := append(pbInt(1, 1), pbInt(2, 1)...)
	base = append(base, pbLen(7, []byte("2.0.1.12345"))...)
	b = append(b, pbLen(4, pbLen(1, base))...)
	b = append(b, pbLen(6, []byte(code))...)
	return b
}

func TestBattleNet(t *testing.T) {
	e := emptyEnv(t, "windows")
	var db []byte
	db = append(db, pbLen(1, productInstall("prometheus", "pro", "C:/Program Files (x86)/Overwatch"))...)
	db = append(db, pbLen(1, productInstall("diablo3_dede", "d3", "C:/Program Files (x86)/Diablo III"))...)
	db = append(db, pbLen(1, productInstall("battle.net", "bna", "C:/Program Files (x86)/Battle.net"))...)
	db = append(db, pbLen(1, productInstall("agent", "agent", "C:/ProgramData/Battle.net/Agent"))...)
	db = append(db, pbLen(2, []byte{0x08, 0x01})...) // an unrelated top-level field
	write(t, filepath.Join(e.ProgramData, "Battle.net", "Agent", "product.db"), string(db))
	found, gs, err := scanBattleNet(e)
	if err != nil || !found || len(gs) != 2 {
		t.Fatalf("battle.net %v %+v", err, gs)
	}
	ow := byID(gs)["battlenet:pro"]
	if ow.Title != "Overwatch 2" || ow.launch.URI != "battlenet://Pro" || filepath.ToSlash(ow.InstallPath) != "C:/Program Files (x86)/Overwatch" {
		t.Fatalf("overwatch %+v", ow)
	}
	// A broken file is reported, not fatal.
	write(t, filepath.Join(e.ProgramData, "Battle.net", "Agent", "product.db"), "\x0a\xff\xff\xff\xff\x0f")
	if _, _, err := scanBattleNet(e); err == nil {
		t.Fatal("expected an error for a corrupt product.db")
	}
}

func TestWindowsRegistryLaunchers(t *testing.T) {
	e := emptyEnv(t, "windows")
	apex := filepath.Join(e.Home, "EA Games", "Apex")
	write(t, filepath.Join(apex, "__Installer", "installerdata.xml"), fixture(t, "installerdata.xml"))
	unin := `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
	reg := fakeReg{
		unin: {
			{Name: "{58B7B8E6-0F80-4A2B-9C2E-5D8C4F6F6E60}", Values: map[string]string{"DisplayName": "Apex Legends", "Publisher": "Electronic Arts", "InstallLocation": apex, "DisplayIcon": apex + `\r5apex.exe,0`, "EstimatedSize": "73400320"}},
			{Name: "Uplay Install 5059", Values: map[string]string{"DisplayName": "Assassin's Creed Valhalla", "Publisher": "Ubisoft", "InstallLocation": `D:\Ubisoft\Assassin's Creed Valhalla`}},
			{Name: "Rockstar Games Launcher", Values: map[string]string{"DisplayName": "Rockstar Games Launcher", "Publisher": "Rockstar Games", "InstallLocation": `C:\Program Files\Rockstar Games\Launcher`}},
			{Name: "{GTA5}", Values: map[string]string{"DisplayName": "Grand Theft Auto V", "Publisher": "Rockstar Games", "InstallLocation": `C:\Program Files\Rockstar Games\Grand Theft Auto V`, "DisplayIcon": `"C:\Program Files\Rockstar Games\Grand Theft Auto V\PlayGTAV.exe"`, "EstimatedSize": "99000000"}},
			{Name: "Diablo III", Values: map[string]string{"DisplayName": "Diablo III", "Publisher": "Blizzard Entertainment", "InstallLocation": `C:\Program Files (x86)\Diablo III`, "DisplayIcon": `C:\Program Files (x86)\Diablo III\Diablo III Launcher.exe`}},
			{Name: "Steam App 570", Values: map[string]string{"DisplayName": "Dota 2", "Publisher": "Valve", "InstallLocation": `C:\Steam\steamapps\common\dota 2 beta`}},
			{Name: "{7-Zip}", Values: map[string]string{"DisplayName": "7-Zip 24.08", "Publisher": "Igor Pavlov", "InstallLocation": `C:\Program Files\7-Zip`}},
		},
		`HKLM\SOFTWARE\WOW6432Node\Ubisoft\Launcher\Installs`: {
			{Name: "5059", Values: map[string]string{"InstallDir": "D:/Ubisoft/Assassin's Creed Valhalla/"}},
		},
	}
	e.Reg, e.RegValues = reg.subkeys, reg.values

	_, ea, _ := scanEA(e)
	if len(ea) != 1 || ea[0].Title != "Apex Legends" || ea[0].launch.URI != "origin2://game/launch?offerIds=Origin.OFR.50.0004643,Origin.OFR.50.0004644" || ea[0].SizeBytes != 73400320*1024 {
		t.Fatalf("ea %+v", ea)
	}
	_, ub, _ := scanUbisoft(e)
	if len(ub) != 1 || ub[0].ID != "ubisoft:5059" || ub[0].Title != "Assassin's Creed Valhalla" || ub[0].launch.URI != "uplay://launch/5059/0" {
		t.Fatalf("ubisoft %+v", ub)
	}
	_, other, _ := scanUninstall(e)
	ids := byID(other)
	if len(other) != 2 || ids["windows:grand-theft-auto-v"].launch.Exe == "" || ids["battlenet:diablo-iii"].Launcher != "battlenet" {
		t.Fatalf("uninstall fallback %+v", other)
	}

	// Xbox app games, from MicrosoftGame.config.
	drive := t.TempDir()
	e.Drives = []string{drive}
	write(t, filepath.Join(drive, "XboxGames", "Forza Horizon 5", "Content", "MicrosoftGame.config"), fixture(t, "MicrosoftGame.config"))
	_, xb, _ := scanXbox(e)
	if len(xb) != 1 || xb[0].Title != "Forza Horizon 5" || xb[0].launch.URI != "msxbox://game/?productId=9NSR2Q8CZ3DS" || xb[0].ProcessNames[0] != "ForzaHorizon5.exe" {
		t.Fatalf("xbox %+v", xb)
	}
}

func TestItchAndLutris(t *testing.T) {
	skipOnWindows(t)
	e := emptyEnv(t, "linux")
	sqliteFrom(t, filepath.Join(e.ConfigHome, "itch", "db", "butler.db"), "itch_butler.sql")
	sqliteFrom(t, filepath.Join(e.DataHome, "lutris", "pga.db"), "lutris_pga.sql")
	write(t, filepath.Join(e.DataHome, "lutris", "coverart", "diablo-ii-lord-of-destruction.jpg"), "\xff\xd8\xff\xe0 jpeg")
	found, gs, err := scanItch(e)
	if err != nil || !found || len(gs) != 2 {
		t.Fatalf("itch %v %+v", err, gs)
	}
	hike := byID(gs)["itch:1191"]
	if hike.Title != "A Short Hike" || hike.LauncherPlaySeconds != 15600 || hike.InstallPath != "/home/ana/.config/itch/apps/a-short-hike" ||
		!strings.HasSuffix(hike.Cover, "hike.png") || hike.launch.URI != "itch://caves/e2c1f4a0-4a0b-4c8f-9a51-1b2c3d4e5f60/launch" || hike.launcherLast.IsZero() {
		t.Fatalf("hike %+v", hike)
	}
	if c := byID(gs)["itch:5432"]; c.InstallPath != "/home/ana/.config/itch/apps/celeste-classic" {
		t.Fatalf("celeste %+v", c)
	}
	found, gs, err = scanLutris(e)
	if err != nil || !found || len(gs) != 1 {
		t.Fatalf("lutris %v %+v", err, gs)
	}
	d2 := gs[0]
	if d2.ID != "lutris:diablo-ii-lord-of-destruction" || d2.LauncherPlaySeconds != 45000 || d2.launch.URI != "lutris:rungameid/3" || d2.coverFile == "" {
		t.Fatalf("lutris %+v", d2)
	}
	if found, _, _ := scanLutris(emptyEnv(t, "windows")); found {
		t.Fatal("Lutris is Linux only")
	}
}

func TestMatcher(t *testing.T) {
	games := []Game{
		{ID: "steam:570", Launcher: "steam", NativeID: "570", Installed: true, InstallPath: "/home/ana/.steam/steam/steamapps/common/dota 2 beta"},
		{ID: "steam:1", Launcher: "steam", NativeID: "1", Installed: true, InstallPath: "/home/ana/.steam/steam/steamapps/common/Outer"},
		{ID: "steam:2", Launcher: "steam", NativeID: "2", Installed: true, InstallPath: "/home/ana/.steam/steam/steamapps/common/Outer/Inner"},
		{ID: "steam:1245620", Launcher: "steam", NativeID: "1245620", Installed: true, InstallPath: "/mnt/games/SteamLibrary/steamapps/common/ELDEN RING"},
		{ID: "custom:minecraft", Launcher: "custom", Custom: true, Installed: true, ProcessNames: []string{"java"}},
		{ID: "lutris:x", Launcher: "lutris", Installed: true, Executables: []string{"/opt/x/run.sh"}},
		{ID: "windows:broad", Launcher: "windows", Installed: true, InstallPath: "/usr/bin"},
		{ID: "epic:gone", Launcher: "epic", Installed: false, InstallPath: "/games/gone"},
		{ID: "epic:Fortnite", Launcher: "epic", Installed: true, InstallPath: "/games/Fortnite", ProcessNames: []string{"FortniteClient-Win64-Shipping.exe"}},
	}
	procs := []proc{
		{PID: 10, Name: "dota2", Exe: "/home/ana/.steam/steam/steamapps/common/dota 2 beta/game/bin/linuxsteamrt64/dota2"},
		{PID: 11, Name: "inner", Exe: "/home/ana/.steam/steam/steamapps/common/Outer/Inner/inner.bin"},
		{PID: 12, Name: "wine64-preloader", Exe: "/home/ana/.steam/steam/steamapps/common/Proton 9.0/files/bin/wine64-preloader",
			Cmdline: []string{"Z:\\mnt\\games\\SteamLibrary\\steamapps\\common\\ELDEN RING\\Game\\eldenring.exe"}},
		{PID: 13, Name: "reaper", Exe: "/home/ana/.steam/steam/ubuntu12_32/reaper", Cmdline: []string{"reaper", "SteamLaunch", "AppId=570", "--", "x"}},
		{PID: 14, Name: "java", Exe: "/usr/lib/jvm/bin/java"},
		{PID: 15, Name: "bash", Exe: "/usr/bin/bash", Cmdline: []string{"/bin/bash", "/opt/x/run.sh"}},
		{PID: 16, Name: "ls", Exe: "/usr/bin/ls"},
		{PID: 17, Name: "gone", Exe: "/games/gone/gone"},
		{PID: 18, Name: "wine", Exe: "/usr/bin/wine", Cmdline: []string{"C:\\Games\\x.exe"}},
		{PID: 19, Name: "FortniteClient-Win64-Shipping.exe"},                                                      // path hidden: matched by name
		{PID: 20, Name: "FortniteClient-Win64-Shipping.exe", Exe: "/elsewhere/FortniteClient-Win64-Shipping.exe"}, // path known elsewhere: not this game
	}
	got := matchProcs(procs, games, "linux", "/home/ana")
	want := map[string][]int32{"steam:570": {10, 13}, "steam:2": {11}, "steam:1245620": {12}, "custom:minecraft": {14}, "lutris:x": {15}, "epic:Fortnite": {19}}
	if len(got) != len(want) {
		t.Fatalf("matched %+v", got)
	}
	for id, pids := range want {
		if ps := got[id]; len(ps) != len(pids) || ps[0].PID != pids[0] || ps[len(ps)-1].PID != pids[len(pids)-1] {
			t.Fatalf("%s: %+v, want %v", id, ps, pids)
		}
	}
	// Windows paths compare without case.
	win := matchProcs([]proc{{PID: 1, Exe: `C:\PROGRAM FILES\Epic Games\Fortnite\FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping.exe`}},
		[]Game{{ID: "epic:Fortnite", Installed: true, InstallPath: `C:\Program Files\Epic Games\Fortnite`}}, "windows", `C:\Users\ana`)
	if len(win["epic:Fortnite"]) != 1 {
		t.Fatalf("windows match %+v", win)
	}
}

func TestSessionsEventsAndResume(t *testing.T) {
	skipOnWindows(t)
	steam := t.TempDir()
	write(t, filepath.Join(steam, "steamapps", "appmanifest_570.acf"), `"AppState" { "appid" "570" "name" "Dota 2" "installdir" "dota 2 beta" }`)
	e := emptyEnv(t, "linux")
	e.SteamPath = steam
	h := fakehost.New(nil)
	m, c, _ := newTestModule(t, e, h)
	exe := filepath.Join(steam, "steamapps", "common", "dota 2 beta", "game", "dota2")
	var procs []proc
	m.Procs = func(context.Context) ([]proc, error) { return procs, nil }
	ctx := context.Background()

	m.poll(ctx)
	procs = []proc{{PID: 42, Name: "dota2", Exe: exe, Started: c.t.Add(-5 * time.Second)}}
	c.add(10 * time.Second)
	m.poll(ctx)
	if ev := h.Events(); len(ev) != 1 || ev[0].Type != "games.started" || !strings.Contains(string(ev[0].Data), `"id":"steam:570"`) {
		t.Fatalf("events %+v", ev)
	}
	var rs []Running
	call(t, m, "running", nil, &rs)
	if len(rs) != 1 || rs[0].PID != 42 || rs[0].Seconds != 15 {
		t.Fatalf("running %+v", rs)
	}
	var gs []Game
	call(t, m, "library", nil, &gs)
	if !gs[0].Running || gs[0].PlaySeconds != 15 {
		t.Fatalf("library while playing %+v", gs[0])
	}
	c.add(30 * time.Minute)
	m.poll(ctx)
	procs = nil
	c.add(10 * time.Second)
	m.poll(ctx)
	ev := h.Events()
	if len(ev) != 2 || ev[1].Type != "games.stopped" || !strings.Contains(string(ev[1].Data), `"seconds":1825`) {
		t.Fatalf("stopped %+v", ev)
	}
	ss := m.st.sessions()
	if len(ss) != 1 || ss[0].Seconds != 1825 || ss[0].Title != "Dota 2" {
		t.Fatalf("sessions %+v", ss)
	}

	// The daemon restarts while the game runs: the session carries on.
	procs = []proc{{PID: 43, Name: "dota2", Exe: exe, Started: c.t}}
	c.add(time.Minute)
	m.poll(ctx)
	m.flush()
	m2 := New()
	m2.Env, m2.Now, m2.Loc, m2.DataDir, m2.Procs = e, c.now, time.UTC, m.DataDir, m.Procs
	m2.Configure(ctx, fakehost.New(nil), InstanceID, nil)
	c.add(time.Minute)
	m2.poll(ctx)
	if a := m2.active["steam:570"]; a == nil || !a.Start.Equal(t0.Add(10*time.Second+30*time.Minute+10*time.Second+time.Minute)) {
		t.Fatalf("resumed %+v", m2.active)
	}
	// Restarted again after the game quit: closed where it was last seen.
	m2.flush()
	procs = nil
	m3 := New()
	m3.Env, m3.Now, m3.Loc, m3.DataDir, m3.Procs = e, c.now, time.UTC, m.DataDir, m.Procs
	m3.Configure(ctx, fakehost.New(nil), InstanceID, nil)
	c.add(time.Hour)
	m3.poll(ctx)
	if ss := m3.st.sessions(); len(ss) != 2 || ss[1].Seconds != 60 {
		t.Fatalf("closed at last seen: %+v", ss)
	}
}

func TestStats(t *testing.T) {
	at := func(d, h int) time.Time { return time.Date(2026, 11, d, h, 0, 0, 0, time.UTC) }
	ss := []Session{
		{GameID: "a", Title: "A", Start: at(1, 23), End: at(2, 1), Seconds: 7200}, // across midnight
		{GameID: "b", Title: "B", Start: at(2, 10), End: at(2, 11), Seconds: 3600},
		{GameID: "a", Title: "A", Start: at(3, 20), End: at(3, 21), Seconds: 3600},
		{GameID: "a", Title: "A", Start: at(4, 8), End: at(4, 9), Seconds: 3600},
		{GameID: "c", Title: "C", Start: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC), End: time.Date(2026, 9, 1, 11, 0, 0, 0, time.UTC), Seconds: 3600},
	}
	now := at(4, 12)
	st := computeStats(ss, now, 7, "", time.UTC)
	if st.From != "2026-10-29" || st.To != "2026-11-04" || len(st.PerDay) != 7 || st.TotalSeconds != 18000 || st.Sessions != 4 {
		t.Fatalf("stats %+v", st)
	}
	day := map[string]int64{}
	for _, d := range st.PerDay {
		day[d.Date] = d.Seconds
	}
	if day["2026-11-01"] != 3600 || day["2026-11-02"] != 7200 || day["2026-11-04"] != 3600 {
		t.Fatalf("per day %+v", st.PerDay)
	}
	if st.Top[0].ID != "a" || st.Top[0].Seconds != 14400 || st.Top[0].Sessions != 3 || st.PerGame[1].ID != "b" {
		t.Fatalf("top %+v", st.Top)
	}
	if st.Streak.Current != 4 || st.Streak.Longest != 4 || st.Streak.Since != "2026-11-01" || st.DaysPlayed != 4 {
		t.Fatalf("streak %+v", st.Streak)
	}
	if st.LongestSession == nil || st.LongestSession.Seconds != 7200 || st.TotalHours != 5 {
		t.Fatalf("longest %+v", st.LongestSession)
	}
	if len(st.Series) != 1 || len(st.Series[0].Points) != 7 || st.Series[0].Points[4][1] != 2 {
		t.Fatalf("series %+v", st.Series)
	}
	one := computeStats(ss, now, 30, "b", time.UTC)
	if one.TotalSeconds != 3600 || one.Streak.Current != 0 || one.Streak.Longest != 1 {
		t.Fatalf("one game %+v", one)
	}
	// Yesterday still counts for the current streak.
	if s := computeStats(ss, at(5, 9), 7, "", time.UTC).Streak; s.Current != 4 {
		t.Fatalf("streak through yesterday %+v", s)
	}
}

func TestStopPlanAndClose(t *testing.T) {
	skipOnWindows(t)
	steam := t.TempDir()
	write(t, filepath.Join(steam, "steamapps", "appmanifest_570.acf"), `"AppState" { "appid" "570" "name" "Dota 2" "installdir" "dota 2 beta" }`)
	e := emptyEnv(t, "linux")
	e.SteamPath = steam
	m, _, _ := newTestModule(t, e, nil)
	exe := filepath.Join(steam, "steamapps", "common", "dota 2 beta", "dota2")
	m.Procs = func(context.Context) ([]proc, error) {
		return []proc{{PID: 7, Name: "dota2", Exe: exe}, {PID: 8, Name: "dota2-helper", Exe: exe + "-helper"}}, nil
	}
	alive := map[int32]bool{7: true, 8: true}
	var signals []string
	m.Signal = func(pid int32, force bool) error {
		signals = append(signals, map[bool]string{false: "term", true: "kill"}[force]+":"+string(rune('0'+pid)))
		if pid == 7 || force {
			alive[pid] = false // 7 closes when asked; 8 needs force
		}
		return nil
	}
	m.Alive = func(pid int32) bool { return alive[pid] }
	m.Now = time.Now
	ctx := context.Background()
	r, err := m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: "stop", Input: json.RawMessage(`{"id":"steam:570"}`), DryRun: true})
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "Dota 2 (2 processes)") || len(r.Plan.Changes) != 2 ||
		!strings.Contains(r.Plan.Changes[0].Target, "dota2 (pid 7)") || len(signals) != 0 {
		t.Fatalf("plan %v %+v", err, r.Plan)
	}
	var out struct {
		Graceful bool    `json:"closedGracefully"`
		Killed   []int32 `json:"killed"`
	}
	call(t, m, "stop", map[string]any{"id": "steam:570", "timeoutSeconds": 1}, &out)
	if out.Graceful || len(out.Killed) != 1 || out.Killed[0] != 8 || strings.Join(signals, ",") != "term:7,term:8,kill:8" {
		t.Fatalf("stop %+v %v", out, signals)
	}
	m.Procs = func(context.Context) ([]proc, error) { return nil, nil }
	if _, err := m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: "stop", Input: json.RawMessage(`{"id":"steam:570"}`)}); err == nil {
		t.Fatal("stopping a game that isn't running must fail")
	}
}

func TestCustomGames(t *testing.T) {
	e := emptyEnv(t, "linux")
	m, _, launched := newTestModule(t, e, nil)
	ctx := context.Background()
	exe := filepath.Join(t.TempDir(), "mc", "launcher.sh")
	write(t, exe, "#!/bin/sh\n")
	var g Game
	r := call(t, m, "add_custom", map[string]any{"title": "Minecraft", "executable": exe, "args": []string{"--fullscreen"},
		"processNames": []string{"java"}, "coverUrl": "https://example.com/mc.jpg"}, &g)
	if g.ID != "custom:minecraft" || !g.Installed || !g.HasCover || r.Undo == nil || r.Undo.Action != "remove_custom" {
		t.Fatalf("added %+v %+v", g, r.Undo)
	}
	call(t, m, "add_custom", map[string]any{"title": "Minecraft", "uri": "steam://rungameid/1"}, &g)
	if g.ID != "custom:minecraft-2" {
		t.Fatalf("second id %s", g.ID)
	}
	call(t, m, "play", map[string]string{"id": "custom:minecraft"}, nil)
	if len(*launched) != 1 || (*launched)[0] != exe+" --fullscreen" {
		t.Fatalf("launched %v", *launched)
	}
	var gs []Game
	call(t, m, "library", map[string]string{"launcher": "custom"}, &gs)
	if len(gs) != 2 {
		t.Fatalf("custom library %+v", gs)
	}
	r = call(t, m, "remove_custom", map[string]string{"id": "custom:minecraft"}, nil)
	if r.Undo == nil || r.Undo.Action != "add_custom" {
		t.Fatalf("undo %+v", r.Undo)
	}
	// Undo brings it back with the same id.
	var back Game
	b := r.Undo.Input
	if out, err := m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: "add_custom", Input: b}); err != nil {
		t.Fatal(err)
	} else {
		json.Unmarshal(out.Output, &back)
	}
	if back.ID != "custom:minecraft" || back.Executables[0] != exe {
		t.Fatalf("restored %+v", back)
	}
	for _, bad := range []string{`{"title":""}`, `{"title":"x"}`, `{"title":"x","uri":"file:///etc/passwd"}`, `{"title":"x","uri":"javascript:alert(1)"}`, `{"title":"x","uri":"a://b","coverUrl":"http://x"}`} {
		if _, err := m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: "add_custom", Input: json.RawMessage(bad)}); err == nil {
			t.Fatalf("%s should be refused", bad)
		}
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: "remove_custom", Input: json.RawMessage(`{"id":"steam:570"}`)}); err == nil {
		t.Fatal("only added games can be removed")
	}
	// Saved on disk.
	b, _ = os.ReadFile(filepath.Join(m.DataDir, "games.json"))
	if !strings.Contains(string(b), `"custom:minecraft"`) {
		t.Fatalf("store %s", b)
	}
}

func TestRefreshReportsLaunchers(t *testing.T) {
	m, _, _ := newTestModule(t, emptyEnv(t, "linux"), nil)
	var out struct {
		Games     int              `json:"games"`
		Launchers []LauncherStatus `json:"launchers"`
	}
	call(t, m, "refresh", nil, &out)
	st := map[string]LauncherStatus{}
	for _, l := range out.Launchers {
		st[l.ID] = l
	}
	if out.Games != 0 || st["riot"].Supported || !strings.Contains(st["riot"].Note, "isn't available") || !st["lutris"].Supported || st["steam"].Detected {
		t.Fatalf("refresh %+v", out)
	}
	if h := m.Health(context.Background(), InstanceID); h.Status != "unconfigured" {
		t.Fatalf("health %+v", h)
	}
}

func TestCoverDownload(t *testing.T) {
	png := "\x89PNG\r\n\x1a\n" + strings.Repeat("\x00", 32)
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/svg" {
			io.WriteString(w, `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
			return
		}
		io.WriteString(w, png)
	}))
	defer srv.Close()
	m, _, _ := newTestModule(t, emptyEnv(t, "linux"), nil)
	m.allowPrivateCovers = true
	ctx := context.Background()
	st, _ := m.store()
	st.d.Custom = []CustomGame{{ID: "custom:a", Title: "A", URI: "x://a", CoverURL: srv.URL + "/a.png"}, {ID: "custom:b", Title: "B", URI: "x://b", CoverURL: srv.URL + "/svg"}}
	m.invalidate()
	for i := 0; i < 2; i++ {
		if b, ct, err := m.Cover(ctx, "custom:a"); err != nil || ct != "image/png" || string(b) != png {
			t.Fatalf("cover %v %s", err, ct)
		}
	}
	if hits != 1 {
		t.Fatalf("cover should be cached, %d downloads", hits)
	}
	if _, _, err := m.Cover(ctx, "custom:b"); err == nil {
		t.Fatal("svg must be refused")
	}
	m.allowPrivateCovers = false
	st.d.Custom[0].CoverURL = "https://127.0.0.1/x.png"
	m.invalidate()
	if _, _, err := m.Cover(ctx, "custom:a"); err == nil || !strings.Contains(err.Error(), "local network") {
		t.Fatalf("local network cover: %v", err)
	}
}

func TestOwned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "k" {
			w.WriteHeader(403)
			return
		}
		io.WriteString(w, `{"response":{"games":[{"appid":1,"name":"A","playtime_forever":600},{"appid":2,"name":"B","playtime_forever":6000,"playtime_2weeks":90}]}}`)
	}))
	defer srv.Close()
	m := New()
	m.API = srv.URL
	cfg, _ := json.Marshal(Config{APIKey: "secret://steam", SteamID: "7656"})
	m.Configure(context.Background(), fakehost.New(map[string]string{"secret://steam": "k"}), InstanceID, cfg)
	r, err := m.Invoke(context.Background(), sdk.Call{Instance: InstanceID, Action: "owned"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(r.Output), `"name":"B","hours":100,"lastTwoWeeks":1.5`) {
		t.Fatalf("owned %s", r.Output)
	}
	if strings.Contains(string(r.Output), "k") && strings.Contains(string(r.Output), "key") {
		t.Fatal("key leaked")
	}
}

// skipOnWindows skips tests whose fixtures use Linux paths (Heroic, Lutris,
// /proc-style process paths); Windows separators change how they match.
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses Linux paths")
	}
}
