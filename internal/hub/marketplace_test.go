package hub

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// publisher registers an author and publishes versions of a package.
type publisher struct {
	h      *harness
	tok    string
	handle string
	priv   ed25519.PrivateKey
}

func newPublisher(h *harness, email, handle string) *publisher {
	tok := h.signup(email)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h.do("POST", "/v1/registry/authors", tok, map[string]string{"handle": handle, "publicKey": base64.StdEncoding.EncodeToString(pub)}, 201)
	return &publisher{h: h, tok: tok, handle: handle, priv: priv}
}

func (p *publisher) publish(module, version, desc string) string {
	name := p.handle + "/" + module
	payload := VersionPayload{Name: name, Version: version, Description: desc, Manifest: json.RawMessage(`{}`),
		Artifacts: []Artifact{{Platform: "wasm", URL: "https://example.com/" + module + ".wasm", SHA256: strings.Repeat("c", 64)}}}
	p.h.do("POST", "/v1/registry/packages/"+url.PathEscape(name)+"/versions", p.tok, signed(p.h.t, p.priv, payload), 201)
	return url.PathEscape(name)
}

func names(items []any) []string {
	out := []string{}
	for _, it := range items {
		out = append(out, it.(map[string]any)["name"].(string))
	}
	return out
}

var pngBytes = append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 40)...)

func TestMarketplaceListing(t *testing.T) {
	h := newHarness(t, nil)
	acme := newPublisher(h, "a@example.com", "acme")
	bob := newPublisher(h, "b@example.com", "bob")
	w := acme.publish("weather", "1.0.0", "Forecasts for anywhere")
	acme.publish("router", "0.1.0", "Home router stats")
	bob.publish("backup", "2.0.0", "Encrypted backups")

	// Only the author edits a listing; fields are checked.
	listing := map[string]any{"readme": "# Weather\n\n<script>alert(1)</script> stays text", "categories": []string{"home", "monitoring"},
		"tags": []string{"Weather", "forecast", "weather"}, "homepage": "https://acme.example", "source": "https://git.example/acme/weather", "license": "MIT"}
	h.do("PUT", "/v1/registry/packages/"+w+"/listing", bob.tok, listing, 404)
	h.do("PUT", "/v1/registry/packages/"+w+"/listing", acme.tok, map[string]any{"categories": []string{"nope"}}, 400)
	h.do("PUT", "/v1/registry/packages/"+w+"/listing", acme.tok, map[string]any{"homepage": "javascript:alert(1)"}, 400)
	h.do("PUT", "/v1/registry/packages/"+w+"/listing", acme.tok, map[string]any{"readme": strings.Repeat("x", maxReadme+1)}, 400)
	h.do("PUT", "/v1/registry/packages/"+w+"/listing", acme.tok, map[string]any{"categories": []string{"home", "dev", "media", "games"}}, 400)
	got := h.do("PUT", "/v1/registry/packages/"+w+"/listing", acme.tok, listing, 200)
	p := got["package"].(map[string]any)
	if p["license"] != "MIT" || p["source"] != "https://git.example/acme/weather" || len(p["tags"].([]any)) != 2 || len(p["categories"].([]any)) != 2 {
		t.Fatalf("listing %v", p)
	}
	if !strings.Contains(got["readme"].(string), "<script>") {
		t.Fatal("the readme is stored as written; clients render it as text")
	}
	// A key without registry:publish can't edit it.
	key := h.do("POST", "/v1/keys", acme.tok, map[string]any{"name": "r", "scopes": []string{"registry:read"}}, 201)["secret"].(string)
	h.do("PUT", "/v1/registry/packages/"+w+"/listing", key, listing, 403)

	// Icons: PNG or WebP only, size-capped; served with a locked-down type.
	h.do("PUT", "/v1/registry/packages/"+w+"/icon", acme.tok, map[string]string{"data": base64.StdEncoding.EncodeToString([]byte(`<svg onload="alert(1)"/>`))}, 415)
	h.do("PUT", "/v1/registry/packages/"+w+"/icon", acme.tok, map[string]string{"data": base64.StdEncoding.EncodeToString(append(pngBytes, make([]byte, maxIcon)...))}, 413)
	icon := h.do("PUT", "/v1/registry/packages/"+w+"/icon", acme.tok, map[string]string{"data": base64.StdEncoding.EncodeToString(pngBytes)}, 200)["icon"].(string)
	res, err := http.Get(h.ts.URL + "/v1/registry/media/" + icon)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "image/png" || !strings.Contains(res.Header.Get("Content-Security-Policy"), "sandbox") || len(body) != len(pngBytes) {
		t.Fatalf("media: %d %v", res.StatusCode, res.Header)
	}
	webp := append([]byte("RIFF\x00\x00\x00\x00WEBPVP8 "), make([]byte, 20)...)
	shots := h.do("POST", "/v1/registry/packages/"+w+"/screenshots", acme.tok, map[string]string{"data": base64.StdEncoding.EncodeToString(webp), "caption": "Today"}, 201)["items"].([]any)
	shotID := shots[0].(map[string]any)["id"].(string)
	h.do("DELETE", "/v1/registry/packages/"+w+"/screenshots/"+shotID, acme.tok, nil, 204)
	h.do("GET", "/v1/registry/media/"+shotID, "", nil, 404) // unused images are deleted
	h.do("DELETE", "/v1/registry/packages/"+w+"/icon", acme.tok, nil, 204)
	h.do("GET", "/v1/registry/media/"+icon, "", nil, 404)

	// Categories count listed packages.
	cats := h.do("GET", "/v1/registry/categories", "", nil, 200)["items"].([]any)
	for _, c := range cats {
		c := c.(map[string]any)
		if c["id"] == "home" && c["count"] != 1.0 {
			t.Fatalf("category count %v", c)
		}
	}
	if got := names(h.do("GET", "/v1/registry/packages?category=home", "", nil, 200)["items"].([]any)); len(got) != 1 || got[0] != "acme/weather" {
		t.Fatalf("category filter %v", got)
	}
	h.do("GET", "/v1/registry/packages?category=nope", "", nil, 400)
	h.do("GET", "/v1/registry/packages?sort=nope", "", nil, 400)

	// Relevance: a name match beats a description match; tags count.
	if got := names(h.do("GET", "/v1/registry/packages?q=forecast", "", nil, 200)["items"].([]any)); len(got) != 1 || got[0] != "acme/weather" {
		t.Fatalf("tag search %v", got)
	}
	if got := names(h.do("GET", "/v1/registry/packages?q=%25", "", nil, 200)["items"].([]any)); len(got) != 0 {
		t.Fatalf("a %% is matched literally: %v", got)
	}
	if got := names(h.do("GET", "/v1/registry/packages?q=backup", "", nil, 200)["items"].([]any)); got[0] != "bob/backup" {
		t.Fatalf("relevance %v", got)
	}
	// Newest first.
	if got := names(h.do("GET", "/v1/registry/packages?sort=newest", "", nil, 200)["items"].([]any)); len(got) != 3 || got[0] != "bob/backup" {
		t.Fatalf("newest %v", got)
	}
	// Paging, with the total in a header.
	req, _ := http.NewRequest("GET", h.ts.URL+"/v1/registry/packages?limit=1&offset=1", nil)
	res, _ = http.DefaultClient.Do(req)
	var page []any
	_ = json.NewDecoder(res.Body).Decode(&page)
	res.Body.Close()
	if res.Header.Get("X-Total-Count") != "3" || len(page) != 1 {
		t.Fatalf("paging: %s %d", res.Header.Get("X-Total-Count"), len(page))
	}
	// Publishing again keeps an edited listing.
	acme.publish("weather", "1.1.0", "")
	if d := h.do("GET", "/v1/registry/packages/"+w, "", nil, 200)["package"].(map[string]any)["description"]; d != "Forecasts for anywhere" {
		t.Fatalf("description after an empty one: %v", d)
	}
}

func TestMarketplaceInstallCounts(t *testing.T) {
	h := newHarness(t, nil)
	acme := newPublisher(h, "a@example.com", "acme")
	w := acme.publish("weather", "1.0.0", "Forecasts")
	acme.publish("router", "1.0.0", "Router")
	ping := func(event, daemon string, want int) {
		h.do("POST", "/v1/registry/installs", "", map[string]string{"name": "acme/weather", "version": "1.0.0", "event": event, "daemon": daemon}, want)
	}
	d1, d2 := strings.Repeat("a", 32), strings.Repeat("b", 32)
	ping("install", d1, 202)
	ping("install", d1, 202) // the same day: not counted again
	ping("install", d2, 202)
	ping("install", "short", 400)
	ping("explode", d1, 400)
	h.do("POST", "/v1/registry/installs", "", map[string]string{"name": "acme/none", "event": "install", "daemon": d1}, 404)
	p := h.do("GET", "/v1/registry/packages/"+w, "", nil, 200)["package"].(map[string]any)
	if p["downloads"] != 2.0 || p["installs"] != 2.0 {
		t.Fatalf("counts %v %v", p["downloads"], p["installs"])
	}
	ping("uninstall", d2, 202)
	p = h.do("GET", "/v1/registry/packages/"+w, "", nil, 200)["package"].(map[string]any)
	if p["downloads"] != 2.0 || p["installs"] != 1.0 {
		t.Fatalf("after uninstall %v %v", p["downloads"], p["installs"])
	}
	// A day later the same daemon counts again.
	h.srv.now = func() time.Time { return time.Now().Add(26 * time.Hour) }
	ping("install", d1, 202)
	if p := h.do("GET", "/v1/registry/packages/"+w, "", nil, 200)["package"].(map[string]any); p["downloads"] != 3.0 || p["installs"] != 1.0 {
		t.Fatalf("next day %v %v", p["downloads"], p["installs"])
	}
	// Daemons silent for 45 days drop out of the installs.
	h.srv.now = func() time.Time { return time.Now().AddDate(0, 0, 50) }
	ping("heartbeat", d2, 202)
	if p := h.do("GET", "/v1/registry/packages/"+w, "", nil, 200)["package"].(map[string]any); p["installs"] != 1.0 {
		t.Fatalf("stale installs %v", p["installs"])
	}
	if got := names(h.do("GET", "/v1/registry/packages?sort=installs", "", nil, 200)["items"].([]any)); got[0] != "acme/weather" {
		t.Fatalf("sort by installs %v", got)
	}
}

func TestMarketplaceReviews(t *testing.T) {
	h := newHarness(t, nil)
	acme := newPublisher(h, "a@example.com", "acme")
	w := acme.publish("weather", "1.0.0", "Forecasts")
	r := acme.publish("router", "1.0.0", "Router")
	carol := h.signup("c@example.com")
	dave := h.signup("d@example.com")
	path := "/v1/registry/packages/" + w + "/reviews"

	h.do("PUT", path+"/mine", "", map[string]any{"rating": 5}, 401)
	h.do("PUT", path+"/mine", acme.tok, map[string]any{"rating": 5}, 403) // not your own
	h.do("PUT", path+"/mine", carol, map[string]any{"rating": 6}, 400)
	h.do("PUT", path+"/mine", carol, map[string]any{"rating": 3, "body": strings.Repeat("x", maxReviewBody+1)}, 400)
	h.do("PUT", path+"/mine", carol, map[string]any{"rating": 4, "body": "Good", "version": "1.0.0"}, 201)
	mine := h.do("PUT", path+"/mine", carol, map[string]any{"rating": 5, "body": "Great now"}, 200) // edit
	h.do("GET", path+"/mine", carol, nil, 200)
	h.do("GET", path+"/mine", dave, nil, 404)

	// A paired daemon rates for its account.
	_, dev := pairDaemon(h, dave)
	h.do("PUT", path+"/mine", dev, map[string]any{"rating": 2, "body": "Crashes on start"}, 201)
	// API keys need registry:review.
	k := h.do("POST", "/v1/keys", dave, map[string]any{"name": "r", "scopes": []string{"registry:read"}}, 201)["secret"].(string)
	h.do("PUT", path+"/mine", k, map[string]any{"rating": 1}, 403)
	// Unconfirmed accounts can't.
	h.do("POST", "/v1/accounts", "", map[string]string{"email": "e@example.com", "password": "correct horse battery"}, 202)
	eve := h.do("POST", "/v1/sessions", "", map[string]string{"email": "e@example.com", "password": "correct horse battery"}, 200)["token"].(string)
	h.do("PUT", path+"/mine", eve, map[string]any{"rating": 1}, 403)

	list := h.do("GET", path, "", nil, 200)
	if list["count"] != 2.0 || list["average"] != 3.5 || len(list["items"].([]any)) != 2 {
		t.Fatalf("reviews %v", list)
	}
	if hist := list["histogram"].([]any); hist[1] != 1.0 || hist[4] != 1.0 {
		t.Fatalf("histogram %v", hist)
	}
	if p := h.do("GET", "/v1/registry/packages/"+w, "", nil, 200)["package"].(map[string]any); p["rating"] != 3.5 || p["ratingCount"] != 2.0 {
		t.Fatalf("package rating %v", p)
	}
	if strings.Contains(strings.ToLower(jsonOf(list)), "example.com") {
		t.Fatal("reviews must not show email addresses")
	}

	// The author replies; others can't.
	id := mine["id"].(string)
	h.do("POST", path+"/"+id+"/reply", dave, map[string]string{"body": "me too"}, 404)
	if rep := h.do("POST", path+"/"+id+"/reply", acme.tok, map[string]string{"body": "Thanks!"}, 200); rep["reply"] != "Thanks!" {
		t.Fatalf("reply %v", rep)
	}

	// Sorting by rating uses a weighted average.
	h.do("PUT", "/v1/registry/packages/"+r+"/reviews/mine", carol, map[string]any{"rating": 5}, 201)
	h.do("PUT", "/v1/registry/packages/"+r+"/reviews/mine", dave, map[string]any{"rating": 5}, 201)
	if got := names(h.do("GET", "/v1/registry/packages?sort=rating", "", nil, 200)["items"].([]any)); got[0] != "acme/router" {
		t.Fatalf("sort by rating %v", got)
	}

	h.do("DELETE", path+"/mine", carol, nil, 204)
	h.do("DELETE", path+"/mine", carol, nil, 404)
	if p := h.do("GET", "/v1/registry/packages/"+w, "", nil, 200)["package"].(map[string]any); p["ratingCount"] != 1.0 || p["rating"] != 2.0 {
		t.Fatalf("after delete %v", p)
	}

	// Rate-limited per account.
	limited := false
	for i := 0; i < 40; i++ {
		res := h.raw("PUT", path+"/mine", carol, map[string]any{"rating": 1 + i%5})
		if res == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("review writes aren't rate-limited")
	}
}

func jsonOf(v any) string { b, _ := json.Marshal(v); return string(b) }

// raw is do without a status check.
func (h *harness) raw(method, path, tok string, body any) int {
	h.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, h.ts.URL+path, strings.NewReader(string(b)))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

func TestMarketplaceModeration(t *testing.T) {
	h := newHarness(t, nil)
	root := h.signup("root@example.com")
	acme := newPublisher(h, "a@example.com", "acme")
	w := acme.publish("weather", "1.0.0", "Forecasts")
	acme.publish("weather", "1.1.0", "Forecasts")
	acme.publish("router", "1.0.0", "Router")
	bob := newPublisher(h, "b@example.com", "bob")
	bob.publish("backup", "1.0.0", "Backups")
	carol := h.signup("c@example.com")
	rp := "/v1/registry/packages/" + w + "/reports"

	// Reports: a known reason, one open per account per package.
	h.do("POST", rp, "", map[string]string{"reason": "spam"}, 401)
	h.do("POST", rp, carol, map[string]string{"reason": "evil"}, 400)
	h.do("POST", rp, carol, map[string]string{"reason": "other"}, 400) // needs details
	h.do("POST", rp, carol, map[string]string{"reason": "malware", "version": "9.9.9"}, 404)
	h.do("POST", rp, carol, map[string]string{"reason": "malware", "version": "1.1.0", "details": "Sends my tokens to evil.example"}, 201)
	h.do("POST", rp, carol, map[string]string{"reason": "spam"}, 409)
	if !waitMail(h, "root@example.com", "Malware report") {
		t.Fatal("operators aren't told about malware reports")
	}
	other := h.signup("o@example.com")
	h.do("POST", rp, other, map[string]string{"reason": "broken", "details": "Doesn't start"}, 201)
	h.do("POST", "/v1/registry/packages/"+url.PathEscape("bob/backup")+"/reports", carol, map[string]string{"reason": "spam"}, 201)

	// The queue is for operators only; malware first.
	h.do("GET", "/v1/admin/reports", carol, nil, 403)
	q := h.do("GET", "/v1/admin/reports", root, nil, 200)
	items := q["items"].([]any)
	if q["total"] != 3.0 || items[0].(map[string]any)["reason"] != "malware" || items[0].(map[string]any)["reporter"] != "c@example.com" || items[0].(map[string]any)["openReports"] != 2.0 {
		t.Fatalf("queue %v", q)
	}
	if st := h.do("GET", "/v1/admin/stats", root, nil, 200); st["openReports"] != 3.0 {
		t.Fatalf("stats %v", st)
	}
	malware := items[0].(map[string]any)["id"].(string)
	var spam string
	for _, it := range items {
		if it.(map[string]any)["name"] == "bob/backup" {
			spam = it.(map[string]any)["id"].(string)
		}
	}

	// Dismiss one.
	h.do("POST", "/v1/admin/reports/"+spam+"/resolve", root, map[string]string{"action": "nope"}, 400)
	h.do("POST", "/v1/admin/reports/"+spam+"/resolve", root, map[string]string{"action": "dismiss", "note": "Looks fine"}, 200)
	h.do("POST", "/v1/admin/reports/"+spam+"/resolve", root, map[string]string{"action": "dismiss"}, 409)

	// Yank the reported version: hidden, and daemons are told why.
	h.do("POST", "/v1/admin/reports/"+malware+"/resolve", root, map[string]string{"action": "yank", "note": "Confirmed"}, 200)
	pkg := h.do("GET", "/v1/registry/packages/"+w, "", nil, 200)
	if pkg["package"].(map[string]any)["latest"] != "1.0.0" {
		t.Fatalf("latest after yank %v", pkg["package"])
	}
	for _, v := range pkg["versions"].([]any) {
		v := v.(map[string]any)
		if v["version"] == "1.1.0" && (v["yanked"] != true || v["yankedBy"] != "operator" || v["yankReason"] != "malware") {
			t.Fatalf("yanked version %v", v)
		}
	}
	// The author can't turn an operator yank into their own.
	h.do("POST", "/v1/registry/packages/"+w+"/versions/1.1.0/yank", acme.tok, nil, 204)
	adv := h.do("POST", "/v1/registry/advisories", "", map[string]any{"modules": []map[string]string{
		{"name": "acme/weather", "version": "1.1.0"}, {"name": "acme/weather", "version": "1.0.0"}, {"name": "acme/gone", "version": "1.0.0"}, {"name": "bad name"}}}, 200)["items"].([]any)
	if len(adv) != 3 {
		t.Fatalf("advisories %v", adv)
	}
	if a := adv[0].(map[string]any); a["status"] != "yanked" || a["by"] != "operator" || a["reason"] != "malware" || a["note"] != "Confirmed" || a["latest"] != "1.0.0" {
		t.Fatalf("advisory %v", a)
	}
	if adv[1].(map[string]any)["status"] != "ok" || adv[2].(map[string]any)["status"] != "missing" {
		t.Fatalf("advisories %v", adv)
	}
	if !waitMail(h, "a@example.com", "was yanked") {
		t.Fatal("the author isn't told")
	}
	h.do("POST", "/v1/admin/registry/packages/"+w+"/versions/1.1.0/unyank", root, nil, 204)
	h.do("POST", "/v1/admin/registry/packages/"+w+"/versions/1.1.0/unyank", root, nil, 404)
	h.do("POST", "/v1/admin/registry/packages/"+w+"/versions/1.1.0/yank", root, map[string]string{"reason": "malware"}, 204)

	// The other open report on the package is still there; delisting closes it.
	if q := h.do("GET", "/v1/admin/reports", root, nil, 200); q["total"] != 1.0 {
		t.Fatalf("open reports %v", q)
	}
	h.do("POST", "/v1/admin/registry/packages/"+w+"/delist", carol, map[string]string{"reason": "broken"}, 403)
	h.do("POST", "/v1/admin/registry/packages/"+w+"/delist", root, map[string]string{"reason": "bogus"}, 400)
	h.do("POST", "/v1/admin/registry/packages/"+w+"/delist", root, map[string]string{"reason": "broken", "note": "Doesn't start"}, 204)
	if q := h.do("GET", "/v1/admin/reports", root, nil, 200); q["total"] != 0.0 {
		t.Fatalf("open reports after delist %v", q)
	}
	if got := names(h.do("GET", "/v1/registry/packages?q=weather", "", nil, 200)["items"].([]any)); len(got) != 0 {
		t.Fatalf("delisted packages show in search: %v", got)
	}
	p := h.do("GET", "/v1/registry/packages/"+w, "", nil, 200)["package"].(map[string]any)
	if p["delisted"] != true || p["delistReason"] != "broken" {
		t.Fatalf("delisted package %v", p)
	}
	a := h.do("POST", "/v1/registry/advisories", "", map[string]any{"modules": []map[string]string{{"name": "acme/weather", "version": "1.0.0"}, {"name": "acme/weather", "version": "1.1.0"}}}, 200)["items"].([]any)
	if a[0].(map[string]any)["status"] != "delisted" || a[0].(map[string]any)["reason"] != "broken" || a[1].(map[string]any)["reason"] != "malware" {
		t.Fatalf("delisted advisories %v", a)
	}
	h.do("PUT", "/v1/registry/packages/"+w+"/reviews/mine", carol, map[string]any{"rating": 1}, 409)
	h.do("POST", "/v1/admin/registry/packages/"+w+"/relist", root, nil, 204)
	if got := names(h.do("GET", "/v1/registry/packages?q=weather", "", nil, 200)["items"].([]any)); len(got) != 1 {
		t.Fatalf("relisted: %v", got)
	}

	// Verify, then ban: the handle stays taken, packages are delisted, and
	// nothing new can be published.
	h.do("POST", "/v1/admin/registry/authors/acme/verify", root, map[string]bool{"verified": true}, 200)
	if p := h.do("GET", "/v1/registry/packages?q=router", "", nil, 200)["items"].([]any)[0].(map[string]any); p["verified"] != true {
		t.Fatalf("verified badge %v", p)
	}
	h.do("POST", "/v1/admin/registry/authors/nobody/ban", root, map[string]string{"reason": "malware"}, 404)
	h.do("POST", "/v1/admin/registry/authors/acme/ban", root, map[string]string{"reason": "malware"}, 204)
	if got := names(h.do("GET", "/v1/registry/packages", "", nil, 200)["items"].([]any)); len(got) != 1 || got[0] != "bob/backup" {
		t.Fatalf("after ban %v", got)
	}
	payload := VersionPayload{Name: "acme/weather", Version: "2.0.0", Manifest: json.RawMessage(`{}`),
		Artifacts: []Artifact{{Platform: "wasm", URL: "https://example.com/w.wasm", SHA256: strings.Repeat("c", 64)}}}
	h.do("POST", "/v1/registry/packages/"+w+"/versions", acme.tok, signed(t, acme.priv, payload), 403)
	h.do("PUT", "/v1/registry/packages/"+w+"/listing", acme.tok, map[string]any{"license": "MIT"}, 403)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h.do("POST", "/v1/registry/authors", acme.tok, map[string]string{"handle": "acme", "publicKey": base64.StdEncoding.EncodeToString(pub)}, 403) // no key rotation
	h.do("POST", "/v1/registry/authors", carol, map[string]string{"handle": "acme", "publicKey": base64.StdEncoding.EncodeToString(pub)}, 409)    // no takeover
	full := h.do("GET", "/v1/registry/packages/"+w, "", nil, 200)
	if full["author"].(map[string]any)["banned"] != true || full["author"].(map[string]any)["verified"] != false || full["authorKey"] == "" {
		t.Fatalf("banned author %v", full["author"])
	}
	h.do("POST", "/v1/admin/registry/authors/acme/verify", root, map[string]bool{"verified": true}, 409)
	h.do("POST", "/v1/admin/registry/authors/acme/unban", root, nil, 204)
	if got := names(h.do("GET", "/v1/registry/packages", "", nil, 200)["items"].([]any)); len(got) != 1 {
		t.Fatalf("unbanning doesn't relist: %v", got)
	}

	// Ban from a report.
	bp := url.PathEscape("bob/backup")
	id := h.do("POST", "/v1/registry/packages/"+bp+"/reports", other, map[string]string{"reason": "impersonation", "details": "Pretends to be acme"}, 201)["id"].(string)
	h.do("POST", "/v1/admin/reports/"+id+"/resolve", root, map[string]string{"action": "ban"}, 200)
	if p := h.do("GET", "/v1/registry/packages/"+bp, "", nil, 200)["package"].(map[string]any); p["delisted"] != true || p["delistReason"] != "impersonation" {
		t.Fatalf("ban from report %v", p)
	}
	if q := h.do("GET", "/v1/admin/reports?status=resolved", root, nil, 200); q["total"] != 4.0 {
		t.Fatalf("resolved reports %v", q)
	}

	// Deleting an account removes its reviews from the ratings.
	h.do("PUT", "/v1/registry/packages/"+url.PathEscape("acme/router")+"/reviews/mine", carol, map[string]any{"rating": 5}, 409) // still delisted
	h.do("POST", "/v1/admin/registry/packages/"+url.PathEscape("acme/router")+"/relist", root, nil, 204)
	h.do("PUT", "/v1/registry/packages/"+url.PathEscape("acme/router")+"/reviews/mine", carol, map[string]any{"rating": 5}, 201)
	var carolID string
	_ = h.srv.db.Row(context.Background(), `SELECT id FROM accounts WHERE email = ?`, "c@example.com").Scan(&carolID)
	h.do("DELETE", "/v1/admin/accounts/"+carolID, root, nil, 204)
	if p := h.do("GET", "/v1/registry/packages/"+url.PathEscape("acme/router"), "", nil, 200)["package"].(map[string]any); p["ratingCount"] != 0.0 {
		t.Fatalf("ratings after account deletion %v", p)
	}
}
