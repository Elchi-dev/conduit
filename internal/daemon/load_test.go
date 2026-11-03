package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLoad drives one daemon with many callers at once: reads, writes with
// undo, instance changes, the audit log and a live event stream. Every call
// must succeed, every write must reach the event stream, and the audit
// chain must still verify. Skipped with -short.
func TestLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("load test")
	}
	_, c, _, id := setup(t)

	// More instances to spread the work.
	ids := []string{id}
	for i := 0; i < 20; i++ {
		var in struct {
			ID string `json:"id"`
		}
		if code := c.do("POST", "/api/v1/instances", map[string]any{"module": "lamp", "name": fmt.Sprintf("Lamp %d", i)}, &in); code != 201 {
			t.Fatalf("instance %d: %d", i, code)
		}
		ids = append(ids, in.ID)
	}

	// A live event stream, counting action events.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var events atomic.Int64
	req, _ := http.NewRequestWithContext(ctx, "GET", c.base+"/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("event stream: %v %v", err, res)
	}
	go func() {
		defer res.Body.Close()
		sc := bufio.NewScanner(res.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "data:") && strings.Contains(sc.Text(), "toggle") {
				events.Add(1)
			}
		}
	}()
	time.Sleep(100 * time.Millisecond)

	call := func(method, path string, body any) (int, error) {
		var b []byte
		if body != nil {
			b, _ = json.Marshal(body)
		}
		r, _ := http.NewRequest(method, c.base+path, bytes.NewReader(b))
		r.Header.Set("Authorization", "Bearer "+c.token)
		r.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			return 0, err
		}
		defer res.Body.Close()
		var sink json.RawMessage
		_ = json.NewDecoder(res.Body).Decode(&sink)
		return res.StatusCode, nil
	}

	const workers, perWorker = 32, 40
	var writes atomic.Int64
	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	start := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				in := ids[(w+i)%len(ids)]
				var code int
				var err error
				switch i % 4 {
				case 0, 1:
					code, err = call("POST", "/api/v1/instances/"+in+"/actions/status", map[string]any{})
				case 2:
					code, err = call("POST", "/api/v1/instances/"+in+"/actions/toggle", map[string]any{})
					if code == 200 {
						writes.Add(1)
					}
				case 3:
					code, err = call("GET", "/api/v1/audit?limit=20", nil)
				}
				if err != nil || code != 200 {
					errs <- fmt.Errorf("worker %d call %d: %d %v", w, i, code, err)
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	elapsed := time.Since(start)
	t.Logf("%d calls in %s (%.0f/s)", workers*perWorker, elapsed.Round(time.Millisecond), float64(workers*perWorker)/elapsed.Seconds())

	// Every write shows up on the event stream.
	deadline := time.Now().Add(5 * time.Second)
	for events.Load() < writes.Load() && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if events.Load() < writes.Load() {
		t.Errorf("event stream saw %d of %d writes", events.Load(), writes.Load())
	}

	var v struct {
		OK bool `json:"ok"`
	}
	if code := c.do("GET", "/api/v1/audit/verify", nil, &v); code != 200 || !v.OK {
		t.Fatalf("audit chain after load: %d %+v", code, v)
	}
}
