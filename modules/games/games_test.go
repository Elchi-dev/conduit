package games

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/modules/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func write(t *testing.T, path, s string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLibraryAndLaunch(t *testing.T) {
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

	m := New()
	var opened string
	m.Open = func(u string) error { opened = u; return nil }
	ctx := context.Background()
	cfg, _ := json.Marshal(Config{SteamPath: steam})
	if err := m.Configure(ctx, fakehost.New(nil), InstanceID, cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, InstanceID); h.Status != "ok" || h.Message != "2 games installed" {
		t.Fatalf("health %+v", h)
	}
	r, err := m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: "library"})
	if err != nil {
		t.Fatal(err)
	}
	var gs []Game
	json.Unmarshal(r.Output, &gs)
	if len(gs) != 2 || gs[0].Name != "Baldur's Gate 3" || gs[0].SizeGB != "150.0 GB" || gs[1].Updated == "" {
		t.Fatalf("library %+v", gs)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: "launch", Input: json.RawMessage(`{"appId":570}`)}); err != nil || opened != "steam://rungameid/570" {
		t.Fatalf("launch %v %q", err, opened)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: InstanceID, Action: "launch", Input: json.RawMessage(`{"appId":1}`)}); err == nil {
		t.Fatal("launching an uninstalled app must fail")
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
