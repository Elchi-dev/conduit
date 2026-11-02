package metrics

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

func fakeProm() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/alerts", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"status":"success","data":{"alerts":[{"labels":{"alertname":"DiskFull","severity":"critical","instance":"web-2"},"annotations":{"summary":"Disk 95% full"},"state":"firing","activeAt":"2026-11-03T00:00:00Z"}]}}`))
	})
	mux.HandleFunc("/api/v1/query", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"instance":"a"},"value":[1700000000,"1.5"]},{"metric":{"instance":"b"},"value":[1700000000,"9"]}]}}`))
	})
	mux.HandleFunc("/api/v1/query_range", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("step") == "" {
			http.Error(w, `{"status":"error","error":"no step"}`, 400)
			return
		}
		w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"up","job":"node"},"values":[[1700000000,"1"],[1700000060,"0"]]}]}}`))
	})
	return httptest.NewServer(mux)
}

func TestMetrics(t *testing.T) {
	srv := fakeProm()
	defer srv.Close()
	m := New()
	ctx := context.Background()
	cfg, _ := json.Marshal(Config{Prometheus: srv.URL})
	if err := m.Configure(ctx, nil, "p", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "p"); h.Status != "degraded" || h.Message != "1 alerts firing" {
		t.Fatalf("health = %+v", h)
	}
	r, err := m.Invoke(ctx, sdk.Call{Instance: "p", Action: "query", Input: json.RawMessage(`{"query":"up"}`)})
	if err != nil || !strings.HasPrefix(string(r.Output), `[{"series":"{instance=b}","value":9}`) {
		t.Fatalf("query: %s %v", r.Output, err)
	}
	r, err = m.Invoke(ctx, sdk.Call{Instance: "p", Action: "chart", Input: json.RawMessage(`{"query":"up","hours":1}`)})
	if err != nil || !strings.Contains(string(r.Output), `"name":"up{job=node}","points":[[1700000000,1],[1700000060,0]]`) {
		t.Fatalf("chart: %s %v", r.Output, err)
	}
	if err := m.Configure(ctx, nil, "bad", json.RawMessage(`{"prometheus":"file:///etc/passwd"}`)); err == nil {
		t.Fatal("non-http URL accepted")
	}
}
