//go:build !windows

package docker

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// fakeDocker serves a tiny subset of the Engine API on a Unix socket.
func fakeDocker(t *testing.T) (string, *sync.Map) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	state := &sync.Map{}
	state.Store("web", "running")
	state.Store("db", "running")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1.43/info", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"Containers": 2, "ContainersRunning": 2, "ServerVersion": "27.0"})
	})
	mux.HandleFunc("GET /v1.43/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		var out []map[string]any
		for _, n := range []string{"web", "db"} {
			s, _ := state.Load(n)
			out = append(out, map[string]any{"Id": n + "0123456789abcdef", "Names": []string{"/" + n}, "Image": n + ":latest", "State": s, "Status": s,
				"Labels": map[string]string{"com.docker.compose.project": "shop"}})
		}
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1.43/containers/{id}/{verb}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if i := strings.Index(id, "0123"); i > 0 {
			id = id[:i] // Docker accepts full and 12-character short IDs
		}
		switch r.PathValue("verb") {
		case "stop":
			state.Store(id, "exited")
		case "start", "restart":
			state.Store(id, "running")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1.43/containers/{id}/logs", func(w http.ResponseWriter, _ *http.Request) {
		for _, line := range []string{"hello\n", "world\n"} {
			hdr := make([]byte, 8)
			hdr[0] = 1
			binary.BigEndian.PutUint32(hdr[4:], uint32(len(line)))
			w.Write(hdr)
			w.Write([]byte(line))
		}
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock, state
}

func TestDockerModule(t *testing.T) {
	sock, state := fakeDocker(t)
	m := New()
	ctx := context.Background()
	cfg, _ := json.Marshal(map[string]string{"mode": "local", "socket": sock})
	if err := m.Configure(ctx, nil, "d1", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "d1"); h.Status != "ok" || !strings.Contains(h.Message, "2 of 2") {
		t.Fatalf("health = %+v", h)
	}
	r, err := m.Invoke(ctx, sdk.Call{Instance: "d1", Action: "containers"})
	if err != nil || !strings.Contains(string(r.Output), `"project":"shop"`) {
		t.Fatalf("containers: %s %v", r.Output, err)
	}
	stop, _ := json.Marshal(map[string]string{"container": "web"})
	plan, err := m.Invoke(ctx, sdk.Call{Instance: "d1", Action: "stop", Input: stop, DryRun: true})
	if err != nil || plan.Plan == nil {
		t.Fatalf("dry run: %v", err)
	}
	if s, _ := state.Load("web"); s != "running" {
		t.Fatal("dry run changed state")
	}
	r, err = m.Invoke(ctx, sdk.Call{Instance: "d1", Action: "stop", Input: stop})
	if err != nil || r.Undo == nil || r.Undo.Action != "start" {
		t.Fatalf("stop: %+v %v", r, err)
	}
	if s, _ := state.Load("web"); s != "exited" {
		t.Fatal("not stopped")
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "d1", Action: "start", Input: r.Undo.Input}); err != nil {
		t.Fatal(err)
	}
	logs, _ := m.Invoke(ctx, sdk.Call{Instance: "d1", Action: "logs", Input: stop})
	if string(logs.Output) != `"hello\nworld\n"` {
		t.Fatalf("logs not demultiplexed: %s", logs.Output)
	}
	bad, _ := json.Marshal(map[string]string{"container": "../../etc"})
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "d1", Action: "stop", Input: bad}); err == nil {
		t.Fatal("path traversal in container name accepted")
	}
	sa, _ := json.Marshal(map[string]string{"project": "shop", "action": "stop"})
	r, err = m.Invoke(ctx, sdk.Call{Instance: "d1", Action: "stack_action", Input: sa})
	if err != nil || r.Undo == nil {
		t.Fatalf("stack stop: %v", err)
	}
	if s, _ := state.Load("db"); s != "exited" {
		t.Fatal("stack not stopped")
	}
}
