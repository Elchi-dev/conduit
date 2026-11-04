package daemon

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The app builds /api/v1/registry/media/{icon} from search results, so a
// hub's icon value only passes when it's a media id the daemon serves.
func TestRegistrySearchFiltersIcons(t *testing.T) {
	app, c, _, _ := setup(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/registry/packages" {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `[
			{"name":"acme/good","icon":"0123456789abcdef0123456789abcdef","source":"https://git.example/acme/good"},
			{"name":"acme/bad","icon":"../../../api/v1/keys?x=","source":"javascript:alert(1)"},
			{"name":"acme/upper","icon":"0123456789ABCDEF0123456789ABCDEF"}]`)
	}))
	defer srv.Close()
	old := regHTTP
	regHTTP = srv.Client()
	defer func() { regHTTP = old }()
	if _, err := app.Store.DB.Exec(`INSERT INTO settings(key, value) VALUES ('registry.url', ?)`, srv.URL); err != nil {
		t.Fatal(err)
	}
	var out []regListing
	if code := c.do("GET", "/api/v1/registry?q=x", nil, &out); code != 200 || len(out) != 3 {
		t.Fatalf("search %d %+v", code, out)
	}
	if out[0].Icon != "0123456789abcdef0123456789abcdef" || out[0].Source != "https://git.example/acme/good" {
		t.Fatalf("valid icon dropped: %+v", out[0])
	}
	if out[1].Icon != "" || out[1].Source != "" || out[2].Icon != "" {
		t.Fatalf("invalid values passed: %+v %+v", out[1], out[2])
	}
}
