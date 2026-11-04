package grocy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type line struct {
	product int
	note    string
	amount  float64
	list    int
}

type fakeGrocy struct {
	mu     sync.Mutex
	seen   []string
	stock  map[int]float64
	list   map[int]*line
	nextID int
	txs    map[string][2]float64 // id -> product, signed amount
	undone map[string]bool
	execs  map[int]bool
	nTx    int
}

var productNames = map[int]string{1: "Milk", 2: "Eggs"}

func (f *fakeGrocy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("GROCY-API-KEY") != "good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error_message":"Unauthorized"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	path := strings.TrimPrefix(r.URL.Path, "/api")
	var b map[string]any
	json.Unmarshal(body, &b)
	prod := func(id int) string {
		return fmt.Sprintf(`{"id":%d,"name":%q,"qu_id_stock":"1","qu_id_purchase":1,"min_stock_amount":"2"}`, id, productNames[id])
	}
	tx := func(p int, amt float64, kind string) {
		f.nTx++
		id := fmt.Sprintf("tx%d", f.nTx)
		f.txs[id] = [2]float64{float64(p), amt}
		f.stock[p] += amt
		fmt.Fprintf(w, `[{"id":"%d","product_id":"%d","amount":"%v","transaction_id":%q,"transaction_type":%q}]`, f.nTx, p, amt, id, kind)
	}
	switch {
	case path == "/objects/shopping_lists":
		io.WriteString(w, `[{"id":1,"name":"Shopping list"}]`)
	case path == "/system/info":
		io.WriteString(w, `{"grocy_version":{"Version":"4.2.0","ReleaseDate":"2024-01-01"}}`)
	case path == "/objects/quantity_units":
		io.WriteString(w, `[{"id":1,"name":"Piece","name_plural":"Pieces"}]`)
	case path == "/stock":
		io.WriteString(w, `[{"product_id":"2","amount":"12","amount_opened":"0","best_before_date":"2026-11-20","product":`+prod(2)+`},{"product_id":1,"amount":1,"amount_opened":1,"best_before_date":"2999-12-31","product":`+prod(1)+`}]`)
	case path == "/stock/volatile":
		if r.URL.Query().Get("due_soon_days") != "" && r.URL.Query().Get("due_soon_days") != "3" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"due_products":[{"product_id":2,"amount":12,"best_before_date":"2026-11-06","product":`+prod(2)+`}],"overdue_products":[],"expired_products":[{"product_id":1,"amount":1,"best_before_date":"2026-11-01","product":`+prod(1)+`}],"missing_products":[{"id":"1","name":"Milk","amount_missing":"1","is_partly_in_stock":"1"}]}`)
	case path == "/objects/products":
		io.WriteString(w, `[`+prod(1)+`,`+prod(2)+`]`)
	case strings.HasPrefix(path, "/objects/products/"):
		id, _ := strconv.Atoi(strings.TrimPrefix(path, "/objects/products/"))
		if productNames[id] == "" {
			w.WriteHeader(404)
			io.WriteString(w, `{"error_message":"Object not found"}`)
			return
		}
		io.WriteString(w, prod(id))
	case path == "/objects/shopping_list" && r.Method == "GET":
		if r.URL.Query().Get("query[]") != "shopping_list_id=1" {
			w.WriteHeader(400)
			return
		}
		var ids []int
		for id := range f.list {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		var rows []string
		for _, id := range ids {
			l := f.list[id]
			p := "null"
			if l.product > 0 {
				p = strconv.Itoa(l.product)
			}
			rows = append(rows, fmt.Sprintf(`{"id":%d,"product_id":%s,"note":%q,"amount":"%v","shopping_list_id":%d,"done":"0","qu_id":null}`, id, p, l.note, l.amount, l.list))
		}
		io.WriteString(w, "["+strings.Join(rows, ",")+"]")
	case path == "/objects/shopping_list" && r.Method == "POST":
		f.nextID++
		f.list[f.nextID] = &line{note: b["note"].(string), amount: b["amount"].(float64), list: int(b["shopping_list_id"].(float64))}
		fmt.Fprintf(w, `{"created_object_id":%d}`, f.nextID)
	case strings.HasPrefix(path, "/objects/shopping_list/"):
		id, _ := strconv.Atoi(strings.TrimPrefix(path, "/objects/shopping_list/"))
		l := f.list[id]
		if l == nil {
			w.WriteHeader(400)
			io.WriteString(w, `{"error_message":"Object not found"}`)
			return
		}
		if r.Method == "DELETE" {
			delete(f.list, id)
			w.WriteHeader(204)
			return
		}
		p := "null"
		if l.product > 0 {
			p = strconv.Itoa(l.product)
		}
		fmt.Fprintf(w, `{"id":%d,"product_id":%s,"note":%q,"amount":%v,"shopping_list_id":%d,"done":0}`, id, p, l.note, l.amount, l.list)
	case path == "/stock/shoppinglist/add-product":
		p := int(b["product_id"].(float64))
		for _, l := range f.list {
			if l.product == p {
				l.amount += b["product_amount"].(float64)
				w.WriteHeader(204)
				return
			}
		}
		f.nextID++
		f.list[f.nextID] = &line{product: p, amount: b["product_amount"].(float64), list: int(b["list_id"].(float64))}
		w.WriteHeader(204)
	case path == "/stock/shoppinglist/remove-product":
		p := int(b["product_id"].(float64))
		for id, l := range f.list {
			if l.product == p {
				l.amount -= b["product_amount"].(float64)
				if l.amount <= 0 {
					delete(f.list, id)
				}
			}
		}
		w.WriteHeader(204)
	case strings.HasPrefix(path, "/stock/products/"):
		rest := strings.TrimPrefix(path, "/stock/products/")
		idS, sub, _ := strings.Cut(rest, "/")
		id, _ := strconv.Atoi(idS)
		if productNames[id] == "" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error_message":"Product does not exist"}`)
			return
		}
		switch sub {
		case "":
			fmt.Fprintf(w, `{"product":%s,"stock_amount":"%v","quantity_unit_stock":{"id":1,"name":"Piece"}}`, prod(id), f.stock[id])
		case "consume":
			if b["transaction_type"] != "consume" {
				w.WriteHeader(400)
				return
			}
			tx(id, -b["amount"].(float64), "consume")
		case "add":
			tx(id, b["amount"].(float64), "purchase")
		}
	case strings.HasPrefix(path, "/stock/transactions/"):
		rest := strings.TrimPrefix(path, "/stock/transactions/")
		id, sub, _ := strings.Cut(rest, "/")
		t, ok := f.txs[id]
		if !ok {
			w.WriteHeader(400)
			io.WriteString(w, `{"error_message":"Transaction does not exist"}`)
			return
		}
		if sub == "undo" {
			if f.undone[id] {
				w.WriteHeader(400)
				return
			}
			f.undone[id] = true
			f.stock[int(t[0])] -= t[1]
			w.WriteHeader(204)
			return
		}
		kind := "purchase"
		if t[1] < 0 {
			kind = "consume"
		}
		fmt.Fprintf(w, `[{"id":1,"product_id":%d,"amount":%v,"transaction_id":%q,"transaction_type":%q,"undone":%d}]`, int(t[0]), t[1], id, kind, map[bool]int{false: 0, true: 1}[f.undone[id]])
	case path == "/chores":
		io.WriteString(w, `[{"chore_id":"1","chore_name":"Vacuum","last_tracked_time":"2026-10-28 09:00:00","next_estimated_execution_time":"2026-11-03 09:00:00","track_date_only":"0"},{"chore_id":2,"chore_name":"Water plants","last_tracked_time":null,"next_estimated_execution_time":"2026-11-08 00:00:00","track_date_only":1},{"chore_id":3,"chore_name":"Clean gutters","next_estimated_execution_time":"2027-03-01 00:00:00"},{"chore_id":4,"chore_name":"Whenever","next_estimated_execution_time":"2999-12-31 23:59:59"}]`)
	case strings.HasPrefix(path, "/chores/executions/"):
		id, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(path, "/chores/executions/"), "/undo"))
		if !f.execs[id] {
			w.WriteHeader(400)
			io.WriteString(w, `{"error_message":"Execution does not exist or was already undone"}`)
			return
		}
		delete(f.execs, id)
		w.WriteHeader(204)
	case strings.HasPrefix(path, "/chores/") && strings.HasSuffix(path, "/execute"):
		f.execs[77] = true
		io.WriteString(w, `{"id":77,"chore_id":1,"tracked_time":"2026-11-04 12:00:00"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error_message":"Not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeGrocy) {
	f := &fakeGrocy{stock: map[int]float64{1: 1, 2: 12}, list: map[int]*line{}, txs: map[string][2]float64{}, undone: map[string]bool{}, execs: map[int]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "good", "secret://bad": "nope"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "k", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func undo(t *testing.T, m *Module, r sdk.Result) sdk.Result {
	t.Helper()
	if r.Undo == nil {
		t.Fatalf("no undo: %s", r.Output)
	}
	res, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil {
		t.Fatalf("undo %s %s: %v", r.Undo.Action, r.Undo.Input, err)
	}
	return res
}

func TestGrocyReads(t *testing.T) {
	m, _ := setup(t, "secret://k")
	if h := m.Health(context.Background(), "k"); h.Status != "ok" || h.Message != "Grocy 4.2.0" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"stock", `{}`, `{"stock":[{"amount":12,"due":"2026-11-20","name":"Eggs","product":2,"unit":"Piece"},{"amount":1,"name":"Milk","opened":1,"product":1,"unit":"Piece"}],"total":2}`},
		{"expiring", `{"days":3}`, `"expired":[{"amount":1,"due":"2026-11-01","name":"Milk"`},
		{"below_minimum", `{}`, `{"belowMinimum":[{"missing":1,"name":"Milk","partlyInStock":true,"product":1}]}`},
		{"chores_due", `{}`, `{"chores":[{"chore":1,"due":"2026-11-03 09:00:00","last":"2026-10-28 09:00:00","name":"Vacuum","overdue":true},{"chore":2,"due":"2026-11-08","name":"Water plants"}],"days":7}`},
		{"shopping_list", `{}`, `{"items":[],"list":1}`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}
}

func TestGrocyShoppingList(t *testing.T) {
	m, f := setup(t, "secret://k")
	r, err := invoke(m, "add_to_shopping_list", `{"product":"milk","amount":2}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Add 2 Milk to shopping list 1" || len(f.list) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "add_to_shopping_list", `{"product":"milk","amount":2}`, false)
	if err != nil || len(f.list) != 1 || string(r.Undo.Input) != `{"amount":2,"list":1,"product":1}` || r.Undo.Action != "remove_from_shopping_list" {
		t.Fatalf("%+v %v", r, err)
	}
	// Added again: Grocy merges, undo takes only this amount off.
	r2, err := invoke(m, "add_to_shopping_list", `{"product":1,"amount":3}`, false)
	if err != nil || !strings.Contains(string(r2.Output), "from 2 to 5") || f.list[1].amount != 5 {
		t.Fatalf("%s %v", r2.Output, err)
	}
	undo(t, m, r2)
	if f.list[1].amount != 2 {
		t.Fatalf("%+v", f.list[1])
	}
	out, _ := invoke(m, "shopping_list", `{}`, false)
	if !strings.Contains(string(out.Output), `"amount":2,"item":1,"name":"Milk","product":1,"unit":"Piece"`) {
		t.Fatalf("%s", out.Output)
	}
	undo(t, m, r)
	if len(f.list) != 0 {
		t.Fatalf("%+v", f.list)
	}

	// A free-text line, removed by its id; that removal's undo adds it back.
	r, err = invoke(m, "add_to_shopping_list", `{"note":"birthday candles"}`, false)
	if err != nil || string(r.Undo.Input) != `{"item":2}` {
		t.Fatalf("%+v %v", r, err)
	}
	p, err := invoke(m, "remove_from_shopping_list", `{"item":2}`, true)
	if err != nil || p.Plan == nil || p.Plan.Changes[0].Op != "delete" || len(f.list) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	back := undo(t, m, r)
	if len(f.list) != 0 || back.Undo == nil || back.Undo.Action != "add_to_shopping_list" {
		t.Fatalf("%+v %+v", f.list, back)
	}
	undo(t, m, back)
	if len(f.list) != 1 || f.list[3].note != "birthday candles" {
		t.Fatalf("%+v", f.list)
	}
	if _, err := invoke(m, "remove_from_shopping_list", `{"product":"Eggs","amount":1}`, false); err == nil || !strings.Contains(err.Error(), "isn't on") {
		t.Fatal(err)
	}
}

func TestGrocyStockAndChores(t *testing.T) {
	m, f := setup(t, "secret://k")
	r, err := invoke(m, "consume_product", `{"product":"Eggs","amount":4}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Consume 4 Piece of Eggs" || f.stock[2] != 12 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "consume_product", `{"product":"Eggs","amount":13}`, false); err == nil || !strings.Contains(err.Error(), "only 12") {
		t.Fatal(err)
	}
	r, err = invoke(m, "consume_product", `{"product":"Eggs","amount":4}`, false)
	if err != nil || f.stock[2] != 8 || r.Undo.Action != "undo_stock_transaction" || string(r.Undo.Input) != `{"id":"tx1"}` {
		t.Fatalf("%+v %v", r, err)
	}
	p, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Revert the consume of 4 Eggs" {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	undo(t, m, r)
	if f.stock[2] != 12 {
		t.Fatal(f.stock)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatal(err)
	}
	r, err = invoke(m, "add_stock", `{"product":1,"amount":2,"bestBefore":"2026-11-14"}`, false)
	if err != nil || f.stock[1] != 3 || !strings.Contains(f.seen[len(f.seen)-1], `"best_before_date":"2026-11-14"`) {
		t.Fatalf("%+v %v", r, err)
	}
	undo(t, m, r)
	if f.stock[1] != 1 {
		t.Fatal(f.stock)
	}

	r, err = invoke(m, "complete_chore", `{"chore":"vacuum"}`, true)
	if err != nil || r.Plan == nil || len(f.execs) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "complete_chore", `{"chore":1}`, false)
	if err != nil || string(r.Undo.Input) != `{"id":77}` || !f.execs[77] {
		t.Fatalf("%+v %v", r, err)
	}
	undo(t, m, r)
	if f.execs[77] {
		t.Fatal("not reverted")
	}
	if _, err := invoke(m, "undo_chore_execution", `{"id":77}`, false); err == nil || !strings.Contains(err.Error(), "reverted already") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "complete_chore", `{"chore":"Dishes"}`, false); err == nil {
		t.Fatal("unknown chore")
	}
}

func TestGrocyValidation(t *testing.T) {
	m, f := setup(t, "secret://k")
	for _, a := range m.Manifest().Actions {
		if strings.HasPrefix(a.Name, "remove") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s isn't destructive", a.Name)
		}
	}
	for _, c := range []struct{ action, in string }{
		{"expiring", `{"days":0}`},
		{"expiring", `{"days":91}`},
		{"chores_due", `{"days":-1}`},
		{"shopping_list", `{"list":-1}`},
		{"add_to_shopping_list", `{}`},
		{"add_to_shopping_list", `{"note":"x","amount":-1}`},
		{"add_to_shopping_list", `{"note":"x","amount":1e9}`},
		{"add_to_shopping_list", `{"note":"` + strings.Repeat("x", 501) + `"}`},
		{"add_to_shopping_list", `{"note":"bad\u0000note"}`},
		{"add_to_shopping_list", `{"product":"` + strings.Repeat("x", 201) + `"}`},
		{"remove_from_shopping_list", `{}`},
		{"remove_from_shopping_list", `{"item":1,"product":1,"amount":1}`},
		{"remove_from_shopping_list", `{"item":-3}`},
		{"remove_from_shopping_list", `{"product":1}`},
		{"consume_product", `{"product":1}`},
		{"consume_product", `{"product":1,"amount":0}`},
		{"consume_product", `{"product":"","amount":1}`},
		{"consume_product", `{"product":1,"amount":1,"bestBefore":"2026-01-01"}`},
		{"add_stock", `{"product":1,"amount":1,"bestBefore":"tomorrow"}`},
		{"add_stock", `{"product":["x"],"amount":1}`},
		{"undo_stock_transaction", `{"id":"../../system/info"}`},
		{"undo_stock_transaction", `{}`},
		{"undo_chore_execution", `{"id":"1/../../x"}`},
		{"undo_chore_execution", `{"id":0}`},
		{"complete_chore", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://grocy.example.com", Token: "plainkey"}, {URL: "grocy.example.com", Token: "secret://k"}, {URL: "https://grocy.example.com/?x=1", Token: "secret://k"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "k"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestGrocyRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("GROCY-API-KEY") + "!" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://k"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "good"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "k"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
