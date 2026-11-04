package azure

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

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	tenant = "11111111-2222-3333-4444-555555555555"
	client = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	subID  = "01234567-89ab-cdef-0123-456789abcdef"
)

type fakeAzure struct {
	mu     sync.Mutex
	srv    *httptest.Server
	seen   []string
	logins int
	power  map[string]string
	sites  map[string]string
}

func (f *fakeAzure) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/"+tenant+"/oauth2/v2.0/token" {
		r.ParseForm()
		if r.Method != "POST" || r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != client ||
			r.PostForm.Get("scope") != "https://management.azure.com/.default" || r.PostForm.Get("client_secret") != "s3cret-value" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}`)
			return
		}
		f.logins++
		io.WriteString(w, `{"token_type":"Bearer","expires_in":3599,"access_token":"arm-token-xyz"}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer arm-token-xyz" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"code":"InvalidAuthenticationToken","message":"bad token"}}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	sp := "/subscriptions/" + subID
	vmBase := sp + "/resourceGroups/web-rg/providers/Microsoft.Compute/virtualMachines/"
	siteBase := sp + "/resourceGroups/web-rg/providers/Microsoft.Web/sites/"
	switch {
	case r.URL.Path == "/subscriptions" && r.URL.Query().Get("page") == "":
		fmt.Fprintf(w, `{"value":[{"subscriptionId":%q,"displayName":"Prod","state":"Enabled","tenantId":"x"}],"nextLink":%q}`, subID, f.srv.URL+"/subscriptions?api-version=2022-12-01&page=2")
	case r.URL.Path == "/subscriptions":
		io.WriteString(w, `{"value":[{"subscriptionId":"99999999-89ab-cdef-0123-456789abcdef","displayName":"Dev","state":"Disabled"}]}`)
	case r.URL.Path == sp+"/resourcegroups":
		io.WriteString(w, `{"value":[{"name":"web-rg","location":"westeurope","tags":{"owner":"LEAKME"},"properties":{"provisioningState":"Succeeded"}}]}`)
	case r.URL.Path == sp+"/providers/Microsoft.Compute/virtualMachines":
		if r.URL.Query().Get("statusOnly") != "true" {
			w.WriteHeader(400)
			return
		}
		fmt.Fprintf(w, `{"value":[{"id":"%sweb1","name":"web1","location":"westeurope","zones":["1"],"properties":{"hardwareProfile":{"vmSize":"Standard_B2s"},
			"osProfile":{"adminUsername":"LEAKME","customData":"LEAKME"},"userData":"LEAKME","storageProfile":{"osDisk":{"osType":"Linux"}},
			"instanceView":{"statuses":[{"code":"ProvisioningState/succeeded"},{"code":"PowerState/%s"}]}}}]}`, vmBase, f.power["web1"])
	case strings.HasPrefix(r.URL.Path, vmBase) && strings.HasSuffix(r.URL.Path, "/instanceView"):
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, vmBase), "/instanceView")
		st, ok := f.power[name]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":{"code":"ResourceNotFound","message":"not found"}}`)
			return
		}
		fmt.Fprintf(w, `{"statuses":[{"code":"ProvisioningState/succeeded"},{"code":"PowerState/%s"}]}`, st)
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, vmBase):
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, vmBase), "/")
		f.power[parts[0]] = map[string]string{"start": "running", "deallocate": "deallocated", "restart": "running"}[parts[1]]
		w.WriteHeader(202)
	case r.URL.Path == sp+"/providers/Microsoft.Web/sites":
		fmt.Fprintf(w, `{"value":[{"id":"%sshop","name":"shop","kind":"app,linux","location":"westeurope","properties":{"state":%q,"defaultHostName":"shop.azurewebsites.net",
			"enabled":true,"httpsOnly":true,"serverFarmId":"/subscriptions/x/serverfarms/plan1","siteConfig":{"appSettings":[{"name":"DB","value":"LEAKME"}],"connectionStrings":"LEAKME"}}}]}`, siteBase, f.sites["shop"])
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, siteBase):
		fmt.Fprintf(w, `{"id":"%sshop","name":"shop","properties":{"state":%q,"siteConfig":{"appSettings":"LEAKME"}}}`, siteBase, f.sites["shop"])
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, siteBase):
		op := strings.TrimPrefix(r.URL.Path, siteBase+"shop/")
		f.sites["shop"] = map[string]string{"start": "Running", "stop": "Stopped", "restart": "Running"}[op]
	case r.URL.Path == sp+"/providers/Microsoft.CostManagement/query":
		io.WriteString(w, `{"properties":{"columns":[{"name":"Cost","type":"Number"},{"name":"ServiceName","type":"String"},{"name":"Currency","type":"String"}],
			"rows":[[12.345,"Virtual Machines","EUR"],[40.1,"Storage","EUR"]]}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":{"code":"NotFound","message":"no route"}}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeAzure) {
	f := &fakeAzure{power: map[string]string{"web1": "deallocated"}, sites: map[string]string{"shop": "Running"}}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	m := New()
	m.Base, m.LoginBase = f.srv.URL, f.srv.URL
	raw, _ := json.Marshal(Config{TenantID: tenant, ClientID: client, ClientSecret: ref, SubscriptionID: subID})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://az": "s3cret-value\n", "secret://bad": "wrong"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestAzure(t *testing.T) {
	m, f := setup(t, "secret://az")
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || h.Message != "2 subscriptions; Prod is Enabled" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"subscriptions", `{}`, `"name":"Dev"`},
		{"resource_groups", `{}`, `"location":"westeurope"`},
		{"vms", `{}`, `"powerState":"deallocated"`},
		{"vms", `{"resourceGroup":"web-rg"}`, `"resourceGroup":"web-rg"`},
		{"webapps", `{}`, `"plan":"plan1"`},
		{"costs", `{}`, `"total":52.45`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "s3cret") || strings.Contains(out, "arm-token") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if r, _ := invoke(m, "vms", `{"resourceGroup":"other"}`, false); string(r.Output) != "[]" {
		t.Fatal(string(r.Output))
	}
	if f.logins != 1 {
		t.Fatalf("token not cached: %d sign-ins", f.logins)
	}

	vm := `{"resourceGroup":"web-rg","vm":"web1"}`
	r, err := invoke(m, "start_vm", vm, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Start web1 (web-rg)" || f.power["web1"] != "deallocated" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "start_vm", vm, false)
	if err != nil || f.power["web1"] != "running" || r.Undo == nil || r.Undo.Action != "deallocate_vm" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "start_vm", vm, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || r.Undo != nil {
		t.Fatalf("no-op: %s %v", r.Output, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.power["web1"] != "deallocated" {
		t.Fatal(err, f.power)
	}
	if _, err := invoke(m, "restart_vm", vm, false); err == nil || !strings.Contains(err.Error(), "only a running VM") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "start_vm", `{"resourceGroup":"web-rg","vm":"nope"}`, false); err == nil || !strings.Contains(err.Error(), "there's no VM nope") {
		t.Fatal(err)
	}

	app := `{"resourceGroup":"web-rg","app":"shop"}`
	if r, _ := invoke(m, "start_webapp", app, false); !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(string(r.Output))
	}
	r, err = invoke(m, "stop_webapp", app, false)
	if err != nil || f.sites["shop"] != "Stopped" || r.Undo == nil || r.Undo.Action != "start_webapp" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.sites["shop"] != "Running" {
		t.Fatal(err)
	}
	if r, err := invoke(m, "restart_webapp", app, true); err != nil || r.Plan == nil {
		t.Fatal(err)
	}

	for _, a := range m.Manifest().Actions {
		destructive := strings.HasPrefix(a.Name, "deallocate") || strings.HasPrefix(a.Name, "stop") || strings.HasPrefix(a.Name, "restart")
		if destructive != (a.Risk == sdk.RiskDestructive) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestAzureValidation(t *testing.T) {
	m, f := setup(t, "secret://az")
	for _, c := range []struct{ action, in string }{
		{"start_vm", `{"vm":"web1"}`},
		{"start_vm", `{"resourceGroup":"web-rg","vm":"../../x"}`},
		{"start_vm", `{"resourceGroup":"web rg","vm":"web1"}`},
		{"start_vm", `{"resourceGroup":"rg.","vm":"web1"}`},
		{"deallocate_vm", `{"subscription":"not-a-guid","resourceGroup":"web-rg","vm":"web1"}`},
		{"stop_webapp", `{"resourceGroup":"web-rg","app":"a/b"}`},
		{"vms", `{"resourceGroup":"a?b"}`},
		{"resource_groups", `{"subscription":"../providers"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || f.logins != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{TenantID: tenant, ClientID: client, ClientSecret: "plain"},
		{TenantID: "../x", ClientID: client, ClientSecret: "secret://az"},
		{TenantID: tenant, ClientID: "nope", ClientSecret: "secret://az"},
		{TenantID: tenant, ClientID: client, ClientSecret: "secret://az", SubscriptionID: "x"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "a"); h.Status != "down" || h.Message != "Azure refused the tenant, client id or client secret" {
		t.Fatalf("%+v", h)
	}
}

func TestAzureNextLinkStaysOnHost(t *testing.T) {
	m, f := setup(t, "secret://az")
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Errorf("reached %s", r.URL) }))
	defer evil.Close()
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			f.ServeHTTP(w, r)
			return
		}
		fmt.Fprintf(w, `{"value":[],"nextLink":%q}`, evil.URL+"/subscriptions?x=1")
	})
	if _, err := invoke(m, "subscriptions", `{}`, false); err == nil || !strings.Contains(err.Error(), "somewhere else") {
		t.Fatal(err)
	}
}

func TestAzureRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		leaked = r.Header.Get("Authorization") + r.PostForm.Get("client_secret")
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base, m.LoginBase = srv.URL, srv.URL
	raw, _ := json.Marshal(Config{TenantID: tenant, ClientID: client, ClientSecret: "secret://az"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://az": "s3cret-value"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "a"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
