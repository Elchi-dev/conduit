package mealie

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	listID = "11111111-1111-1111-1111-111111111111"
	milkID = "22222222-2222-2222-2222-222222222222"
	newID  = "33333333-3333-3333-3333-333333333333"
)

type fakeMealie struct {
	mu      sync.Mutex
	version string
	items   map[string]map[string]any
	writes  []string
	seen    []string
}

func (f *fakeMealie) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer tok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"detail":"Could not validate credentials"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	scope := "/api/households"
	if strings.HasPrefix(f.version, "v1") {
		scope = "/api/groups"
	}
	body, _ := io.ReadAll(r.Body)
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	if r.Method != "GET" {
		f.writes = append(f.writes, r.Method+" "+r.URL.Path+" "+string(body))
	}
	q := r.URL.Query()
	enc := json.NewEncoder(w)
	switch r.Method + " " + r.URL.Path {
	case "GET /api/users/self":
		io.WriteString(w, `{"username":"cook","email":"c@example.com","password":"LEAKME"}`)
	case "GET /api/app/about":
		io.WriteString(w, `{"version":"`+f.version+`","production":true}`)
	case "GET /api/recipes":
		if q.Get("perPage") != "5" || q.Get("search") != "lemon" {
			w.WriteHeader(422)
			return
		}
		io.WriteString(w, `{"page":1,"per_page":5,"total":1,"items":[{"id":"r1","slug":"lemon-tart","name":"Lemon tart","description":"Sharp and sweet","totalTime":"1 hour","prepTime":"20 minutes","performTime":"40 minutes","recipeYield":"8 slices","rating":5,"tags":[{"name":"Dessert"}],"recipeCategory":[{"name":"Baking"}]}]}`)
	case "GET /api/recipes/lemon-tart":
		io.WriteString(w, `{"id":"r1","slug":"lemon-tart","name":"Lemon tart","description":"Sharp and sweet","recipeServings":8,"orgURL":"https://example.com/tart","rating":null,"tags":[],"recipeCategory":[],
			"recipeIngredient":[{"title":"Crust","display":"200 g flour","note":""},{"display":"","quantity":3,"unit":{"name":"tbsp"},"food":{"name":"sugar"},"note":"fine"}],
			"recipeInstructions":[{"title":"","text":"Blind bake the crust."},{"title":"Filling","text":"Whisk lemons and eggs."}],
			"notes":[{"title":"Tip","text":"Use unwaxed lemons"}],"nutrition":{"calories":"320","fatContent":null}}`)
	case "GET " + scope + "/mealplans":
		if q.Get("start_date") != "2026-11-02" || q.Get("end_date") != "2026-11-08" {
			if q.Get("start_date") == "2026-11-04" && q.Get("end_date") == "2026-11-04" {
				io.WriteString(w, `{"items":[{"date":"2026-11-04","entryType":"dinner","title":"","text":"","recipe":{"slug":"lemon-tart","name":"Lemon tart"}}]}`)
				return
			}
			w.WriteHeader(422)
			return
		}
		io.WriteString(w, `{"items":[{"date":"2026-11-05","entryType":"dinner","title":"Pizza night","text":"order in"},
			{"date":"2026-11-04","entryType":"dinner","recipe":{"slug":"lemon-tart","name":"Lemon tart"}},
			{"date":"2026-11-04","entryType":"breakfast","title":"Porridge"}]}`)
	case "GET " + scope + "/shopping/lists":
		io.WriteString(w, `{"items":[{"id":"`+listID+`","name":"Groceries"},{"id":"44444444-4444-4444-4444-444444444444","name":"Hardware"}]}`)
	case "GET " + scope + "/shopping/lists/" + listID:
		items := []any{}
		for _, id := range []string{milkID, newID} {
			if it, ok := f.items[id]; ok {
				items = append(items, it)
			}
		}
		enc.Encode(map[string]any{"id": listID, "name": "Groceries", "listItems": items})
	case "GET " + scope + "/shopping/items/" + milkID, "GET " + scope + "/shopping/items/" + newID:
		it, ok := f.items[strings.TrimPrefix(r.URL.Path, scope+"/shopping/items/")]
		if !ok {
			w.WriteHeader(404)
			return
		}
		enc.Encode(it)
	case "POST " + scope + "/shopping/items":
		var b map[string]any
		json.Unmarshal(body, &b)
		if b["shoppingListId"] != listID {
			w.WriteHeader(422)
			return
		}
		if strings.EqualFold(b["note"].(string), "milk") {
			it := f.items[milkID]
			it["quantity"] = it["quantity"].(float64) + b["quantity"].(float64)
			enc.Encode(map[string]any{"createdItems": []any{}, "updatedItems": []any{it}, "deletedItems": []any{}})
			return
		}
		it := map[string]any{"id": newID, "shoppingListId": listID, "note": b["note"], "quantity": b["quantity"], "checked": false, "display": fmt.Sprint(b["quantity"], " ", b["note"]), "position": 1}
		f.items[newID] = it
		enc.Encode(map[string]any{"createdItems": []any{it}, "updatedItems": []any{}, "deletedItems": []any{}})
	case "PUT " + scope + "/shopping/items/" + milkID, "PUT " + scope + "/shopping/items/" + newID:
		var b map[string]any
		json.Unmarshal(body, &b)
		id := strings.TrimPrefix(r.URL.Path, scope+"/shopping/items/")
		it := f.items[id]
		for _, k := range []string{"note", "quantity", "checked"} {
			it[k] = b[k]
		}
		it["display"] = fmt.Sprint(it["quantity"], " ", it["note"])
		enc.Encode(map[string]any{"updatedItems": []any{it}})
	case "DELETE " + scope + "/shopping/items/" + newID:
		delete(f.items, newID)
		io.WriteString(w, `{"message":"deleted"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"detail":"Not Found"}`)
	}
}

func setup(t *testing.T, version, token string) (*Module, *fakeMealie) {
	f := &fakeMealie{version: version, items: map[string]map[string]any{
		milkID: {"id": milkID, "shoppingListId": listID, "note": "milk", "quantity": 1.0, "checked": false, "display": "1 milk", "position": 0},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", Token: token})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "tok", "secret://bad": "x"}), "m", raw); err != nil {
		t.Fatal(err)
	}
	c, _ := m.set.Get("m")
	c.now = func() time.Time { return time.Date(2026, 11, 4, 18, 0, 0, 0, time.Local) } // a Wednesday
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "m", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestMealieRead(t *testing.T) {
	for _, ver := range []string{"v2.1.0", "v1.12.0"} {
		m, _ := setup(t, ver, "secret://t")
		if h := m.Health(context.Background(), "m"); h.Status != "ok" || h.Message != "signed in as cook · Mealie "+ver {
			t.Fatalf("%+v", h)
		}
		for _, c := range []struct{ action, in, want string }{
			{"search_recipes", `{"query":"lemon","limit":5}`, `"categories":["Baking"],"cookTime":"40 minutes"`},
			{"recipe", `{"slug":"lemon-tart"}`, `"ingredients":["## Crust","200 g flour","3 tbsp sugar fine"]`},
			{"recipe", `{"slug":"lemon-tart"}`, `"steps":["Blind bake the crust.","Filling: Whisk lemons and eggs."]`},
			{"recipe", `{"slug":"lemon-tart"}`, `"nutrition":{"calories":"320"}`},
			{"meal_plan", `{}`, `{"date":"2026-11-04","meals":[{"recipe":"Lemon tart","slug":"lemon-tart","type":"dinner"}]}`},
			{"meal_plan", `{"range":"week"}`, `"meals":[{"title":"Porridge","type":"breakfast"},{"recipe":"Lemon tart"`},
			{"meal_plan", `{"range":"week"}`, `"start":"2026-11-02"`},
			{"shopping_lists", `{}`, `{"id":"` + listID + `","name":"Groceries"}`},
			{"shopping_list", `{"list":"groceries"}`, `"items":[{"checked":false,"id":"` + milkID + `","quantity":1,"text":"1 milk"}]`},
		} {
			r, err := invoke(m, c.action, c.in, false)
			if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "LEAKME") {
				t.Fatalf("%s %s %s: %s %v", ver, c.action, c.in, r.Output, err)
			}
		}
	}
}

func TestMealieShopping(t *testing.T) {
	m, f := setup(t, "v2.1.0", "secret://t")
	p, err := invoke(m, "add_shopping_item", `{"list":"Groceries","note":"lemons","quantity":3}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != `Add "lemons" to Groceries` || len(f.writes) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	r, err := invoke(m, "add_shopping_item", `{"list":"Groceries","note":"lemons","quantity":3}`, false)
	if err != nil || f.items[newID] == nil || r.Undo == nil || r.Undo.Action != "remove_shopping_item" || string(r.Undo.Input) != `{"item":"`+newID+`"}` {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if !m.Manifest().Actions[7].Reversible || m.Manifest().Actions[7].Risk != sdk.RiskDestructive {
		t.Fatal("remove is destructive and reversible")
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.items[newID] != nil || r.Undo.Action != "add_shopping_item" || !strings.Contains(string(r.Undo.Input), `"note":"lemons","quantity":3`) {
		t.Fatalf("%+v %v", r, err)
	}
	// A merge into the existing milk item: undo puts the old quantity back.
	r, err = invoke(m, "add_shopping_item", `{"list":"`+listID+`","note":"Milk","quantity":2}`, false)
	if err != nil || f.items[milkID]["quantity"] != 3.0 || r.Undo == nil || r.Undo.Action != "update_shopping_item" || !strings.Contains(string(r.Undo.Input), `"quantity":1`) {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.items[milkID]["quantity"] != 1.0 {
		t.Fatalf("%+v %v %v", r, err, f.items[milkID])
	}
	p, err = invoke(m, "update_shopping_item", `{"item":"`+milkID+`","checked":true}`, true)
	if err != nil || p.Plan == nil || !strings.Contains(string(p.Plan.Changes[0].After), `"checked":true`) || f.items[milkID]["checked"] != false {
		t.Fatalf("%+v %v", p, err)
	}
	r, err = invoke(m, "update_shopping_item", `{"item":"`+milkID+`","checked":true}`, false)
	if err != nil || f.items[milkID]["checked"] != true || !strings.Contains(string(r.Undo.Input), `"checked":false`) {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "add_shopping_item", `{"list":"Party","note":"x"}`, false); err == nil || !strings.Contains(err.Error(), "lists: Groceries, Hardware") {
		t.Fatal(err)
	}
}

func TestMealieRefusals(t *testing.T) {
	bad, _ := setup(t, "v2.1.0", "secret://bad")
	if h := bad.Health(context.Background(), "m"); h.Status != "down" || h.Message != "Mealie refused the API token" {
		t.Fatalf("%+v", h)
	}
	m, f := setup(t, "v2.1.0", "secret://t")
	for _, c := range []struct{ action, in string }{
		{"recipe", `{"slug":"../users/self"}`},
		{"recipe", `{"slug":"a/b"}`},
		{"recipe", `{"slug":""}`},
		{"remove_shopping_item", `{"item":"../../lists"}`},
		{"update_shopping_item", `{"item":"` + milkID + `"}`},
		{"update_shopping_item", `{"item":"x/y","checked":true}`},
		{"add_shopping_item", `{"list":"Groceries"}`},
		{"add_shopping_item", `{"list":"Groceries","note":"x","quantity":-1}`},
		{"add_shopping_item", `{"list":"Groceries","note":"x","foodId":"../x"}`},
		{"meal_plan", `{"range":"year"}`},
		{"meal_plan", `{"start":"2026-11-04","end":"2026-01-01"}`},
		{"meal_plan", `{"start":"2026-11-04&x=1","end":"2026-11-05"}`},
		{"search_recipes", `{"limit":500}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.writes) != 0 {
		t.Fatal(f.writes)
	}
	for _, c := range []Config{{URL: "http://m", Token: "plaintok"}, {URL: "mealie:9000", Token: "secret://t"}, {URL: "http://u:p@m", Token: "secret://t"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	rm := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://t"})
	if err := rm.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "tok"}), "m", raw); err != nil {
		t.Fatal(err)
	}
	if h := rm.Health(context.Background(), "m"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
