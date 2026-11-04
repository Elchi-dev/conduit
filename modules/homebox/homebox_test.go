package homebox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	locGarage = "11111111-1111-4111-8111-111111111111"
	locOffice = "22222222-2222-4222-8222-222222222222"
	itemDrill = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	itemTV    = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

type item struct {
	name, loc, warranty string
	qty                 int
}

type fakeHomebox struct {
	mu     sync.Mutex
	seen   []string
	logins int
	valid  map[string]bool
	items  map[string]*item
	n      int
}

func (f *fakeHomebox) itemJSON(id string) string {
	it := f.items[id]
	locName := map[string]string{locGarage: "Garage", locOffice: "Office"}[it.loc]
	w := it.warranty
	if w == "" {
		w = "0001-01-01T00:00:00Z"
	}
	return fmt.Sprintf(`{"id":%q,"assetId":"000-001","name":%q,"description":"","quantity":%d,"archived":false,"location":{"id":%q,"name":%q},"labels":[{"id":"l","name":"Tools"}],"serialNumber":"SN-SECRET","notes":"private notes","warrantyExpires":%q,"lifetimeWarranty":false,"manufacturer":"Acme"}`, id, it.name, it.qty, it.loc, locName, w)
}

func (f *fakeHomebox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if path == "/users/login" {
		var b struct{ Username, Password string }
		json.Unmarshal(body, &b)
		if b.Username != "me@example.com" || b.Password != "hunter22" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"authentication failed"}`)
			return
		}
		f.logins++
		tok := fmt.Sprintf("sess%d", f.logins)
		f.valid[tok] = true
		fmt.Fprintf(w, `{"token":"Bearer %s","expiresAt":"2026-11-11T12:00:00Z","attachmentToken":"x"}`, tok)
		return
	}
	if !f.valid[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"unauthorized"}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	switch {
	case path == "/users/self":
		io.WriteString(w, `{"item":{"name":"Elchi","email":"me@example.com"}}`)
	case path == "/locations":
		io.WriteString(w, `[{"id":"`+locGarage+`","name":"Garage","itemCount":1},{"id":"`+locOffice+`","name":"Office","description":"Upstairs","itemCount":1}]`)
	case path == "/items" && r.Method == "GET":
		q := r.URL.Query()
		var ids []string
		for id, it := range f.items {
			if (q.Get("locations") == "" || q.Get("locations") == it.loc) && (q.Get("q") == "" || strings.Contains(strings.ToLower(it.name), strings.ToLower(q.Get("q")))) {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		var rows []string
		for _, id := range ids {
			rows = append(rows, f.itemJSON(id))
		}
		fmt.Fprintf(w, `{"page":1,"pageSize":100,"total":%d,"items":[%s]}`, len(ids), strings.Join(rows, ","))
	case path == "/items" && r.Method == "POST":
		var b struct {
			Name       string `json:"name"`
			Quantity   int    `json:"quantity"`
			LocationID string `json:"locationId"`
		}
		json.Unmarshal(body, &b)
		f.n++
		id := fmt.Sprintf("cccccccc-cccc-4ccc-8ccc-%012d", f.n)
		// Like older versions, create makes one; the module patches it.
		f.items[id] = &item{name: b.Name, loc: b.LocationID, qty: 1}
		w.WriteHeader(201)
		io.WriteString(w, f.itemJSON(id))
	case strings.HasPrefix(path, "/items/"):
		id := strings.TrimPrefix(path, "/items/")
		it := f.items[id]
		if it == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"item not found"}`)
			return
		}
		switch r.Method {
		case "GET":
			io.WriteString(w, f.itemJSON(id))
		case "PATCH":
			var b struct {
				ID       string `json:"id"`
				Quantity *int   `json:"quantity"`
			}
			json.Unmarshal(body, &b)
			if b.ID != id || b.Quantity == nil {
				w.WriteHeader(422)
				return
			}
			it.qty = *b.Quantity
			io.WriteString(w, f.itemJSON(id))
		case "DELETE":
			delete(f.items, id)
			w.WriteHeader(204)
		}
	default:
		w.WriteHeader(404)
	}
}

func newFake() *fakeHomebox {
	return &fakeHomebox{valid: map[string]bool{"apikey1": true}, items: map[string]*item{
		itemDrill: {name: "Cordless drill", loc: locGarage, qty: 1, warranty: "2026-11-20"},
		itemTV:    {name: "Television", loc: locOffice, qty: 1, warranty: "2027-06-01T00:00:00Z"},
	}}
}

func configure(t *testing.T, f *fakeHomebox, cfg Config) *Module {
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	cfg.URL = srv.URL
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "hunter22", "secret://bad": "wrong", "secret://key": "apikey1"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	return m
}

func setup(t *testing.T) (*Module, *fakeHomebox) {
	f := newFake()
	return configure(t, f, Config{Username: "me@example.com", Password: "secret://pw"}), f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "k", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestHomebox(t *testing.T) {
	m, f := setup(t)
	if h := m.Health(context.Background(), "k"); h.Status != "ok" || h.Message != "signed in as Elchi" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"search_items", `{"query":"drill"}`, `"location":"Garage","name":"Cordless drill"`},
		{"search_items", `{"location":"office"}`, `"name":"Television"`},
		{"locations", `{}`, `{"description":"Upstairs","id":"` + locOffice + `","items":1,"name":"Office"}`},
		{"item", `{"item":"` + itemDrill + `"}`, `"warrantyExpires":"2026-11-20"`},
		{"warranty_soon", `{"days":30}`, `"items":[{"assetId":"000-001","id":"` + itemDrill + `"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "SN-SECRET") || strings.Contains(string(r.Output), "private notes") {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
		if c.action == "search_items" && c.in == `{"location":"office"}` && strings.Contains(string(r.Output), "drill") {
			t.Fatalf("location filter: %s", r.Output)
		}
	}
	if r, _ := invoke(m, "warranty_soon", `{"days":30}`, false); strings.Contains(string(r.Output), "Television") {
		t.Fatalf("%s", r.Output)
	}
	if f.logins != 1 {
		t.Fatalf("signed in %d times", f.logins)
	}

	// A session that ends early is renewed once.
	f.valid = map[string]bool{}
	if h := m.Health(context.Background(), "k"); h.Status != "ok" || f.logins != 2 {
		t.Fatalf("%+v %d", h, f.logins)
	}

	r, err := invoke(m, "add_item", `{"name":"Ladder","location":"Garage","quantity":2}`, true)
	if err != nil || r.Plan == nil || len(f.items) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "add_item", `{"name":"Ladder","location":"Garage","quantity":2}`, false)
	id := "cccccccc-cccc-4ccc-8ccc-000000000001"
	if err != nil || f.items[id] == nil || f.items[id].qty != 2 || r.Undo == nil || r.Undo.Action != "delete_item" || string(r.Undo.Input) != `{"item":"`+id+`"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.items[id] != nil {
		t.Fatal(err)
	}

	r, err = invoke(m, "update_quantity", `{"item":"`+itemDrill+`","quantity":3}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Set the quantity of "Cordless drill" from 1 to 3` || f.items[itemDrill].qty != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "update_quantity", `{"item":"`+itemDrill+`","quantity":3}`, false)
	if err != nil || f.items[itemDrill].qty != 3 || string(r.Undo.Input) != `{"item":"`+itemDrill+`","quantity":1}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.items[itemDrill].qty != 1 {
		t.Fatal(err)
	}
	if r, err := invoke(m, "update_quantity", `{"item":"`+itemDrill+`","quantity":1}`, false); err != nil || r.Undo != nil {
		t.Fatalf("no-op: %+v %v", r, err)
	}

	r, err = invoke(m, "delete_item", `{"item":"`+itemTV+`"}`, true)
	if err != nil || r.Plan == nil || f.items[itemTV] == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "delete_item", `{"item":"`+itemTV+`"}`, false); err != nil || r.Undo != nil || f.items[itemTV] != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "item", `{"item":"`+itemTV+`"}`, false); err == nil || !strings.Contains(err.Error(), "no item") {
		t.Fatal(err)
	}
}

func TestHomeboxAPIKey(t *testing.T) {
	f := newFake()
	m := configure(t, f, Config{Token: "secret://key"})
	if h := m.Health(context.Background(), "k"); h.Status != "ok" || f.logins != 0 {
		t.Fatalf("%+v", h)
	}
}

func TestHomeboxValidation(t *testing.T) {
	m, f := setup(t)
	for _, c := range []struct{ action, in string }{
		{"item", `{}`},
		{"item", `{"item":"../users/self"}`},
		{"delete_item", `{"item":"` + itemDrill + `/../x"}`},
		{"update_quantity", `{"item":"` + itemDrill + `"}`},
		{"update_quantity", `{"item":"` + itemDrill + `","quantity":-1}`},
		{"update_quantity", `{"item":"` + itemDrill + `","quantity":1000001}`},
		{"add_item", `{"name":"","location":"Garage"}`},
		{"add_item", `{"name":"a\nb","location":"Garage"}`},
		{"add_item", `{"name":"` + strings.Repeat("x", 256) + `","location":"Garage"}`},
		{"add_item", `{"name":"x"}`},
		{"add_item", `{"name":"x","location":"Garage","quantity":-2}`},
		{"add_item", `{"name":"x","location":"Garage","description":"` + strings.Repeat("x", 1001) + `"}`},
		{"warranty_soon", `{"days":731}`},
		{"warranty_soon", `{"includeExpired":-1}`},
		{"search_items", `{"query":"` + strings.Repeat("x", 501) + `"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || f.logins != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	if _, err := invoke(m, "add_item", `{"name":"x","location":"Attic"}`, false); err == nil || !strings.Contains(err.Error(), "no location") {
		t.Fatal(err)
	}
	for _, c := range []Config{
		{URL: "https://hb.example.com", Username: "me@example.com", Password: "hunter22"},
		{URL: "https://hb.example.com", Token: "plainkey"},
		{URL: "https://hb.example.com", Token: "secret://key", Username: "me@example.com", Password: "secret://pw"},
		{URL: "https://hb.example.com", Username: "me@example.com"},
		{URL: "hb.example.com", Token: "secret://key"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad := configure(t, newFake(), Config{Username: "me@example.com", Password: "secret://bad"})
	if h := bad.Health(context.Background(), "k"); h.Status != "down" || !strings.Contains(h.Message, "refused") || strings.Contains(h.Message, "wrong") {
		t.Fatalf("%+v", h)
	}
	badKey := configure(t, newFake(), Config{Token: "secret://bad"})
	if h := badKey.Health(context.Background(), "k"); h.Status != "down" || !strings.Contains(h.Message, "refused the API key") {
		t.Fatalf("%+v", h)
	}
}

func TestHomeboxRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	for _, cfg := range []Config{{URL: srv.URL, Token: "secret://key"}, {URL: srv.URL, Username: "me@example.com", Password: "secret://pw"}} {
		m := New()
		raw, _ := json.Marshal(cfg)
		if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://key": "apikey1", "secret://pw": "hunter22"}), "k", raw); err != nil {
			t.Fatal(err)
		}
		if h := m.Health(context.Background(), "k"); h.Status != "down" || hit {
			t.Fatalf("followed the redirect: %+v", h)
		}
	}
}
