package redis

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// fakeRedis speaks enough RESP2 for the module.
type fakeRedis struct {
	mu   sync.Mutex
	data map[string]string
	pass string
	ln   net.Listener
}

func newFake(t *testing.T) *fakeRedis {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRedis{ln: ln, pass: "s3cret", data: map[string]string{"session:1": "token-abc", "session:2": "token-def", "cache:x": "1"}}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func bulk(s string) string { return "$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n" }

func (f *fakeRedis) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	authed := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
		args := make([]string, n)
		for i := range args {
			l, _ := r.ReadString('\n')
			sz, _ := strconv.Atoi(strings.TrimSpace(l[1:]))
			b := make([]byte, sz+2)
			_, _ = r.Read(b[:0])
			for got := 0; got < sz+2; {
				k, err := r.Read(b[got:])
				if err != nil {
					return
				}
				got += k
			}
			args[i] = string(b[:sz])
		}
		f.mu.Lock()
		var out string
		cmd := strings.ToUpper(args[0])
		switch {
		case cmd == "AUTH":
			if args[len(args)-1] == f.pass {
				authed = true
				out = "+OK\r\n"
			} else {
				out = "-WRONGPASS invalid username-password pair\r\n"
			}
		case !authed:
			out = "-NOAUTH Authentication required.\r\n"
		case cmd == "PING":
			out = "+PONG\r\n"
		case cmd == "INFO":
			out = bulk("# Server\r\nredis_version:7.2.4\r\nuptime_in_seconds:100\r\n# Memory\r\nused_memory:2048\r\nused_memory_human:2K\r\nkeyspace_hits:3\r\nkeyspace_misses:1\r\nconnected_clients:2\r\nrole:master\r\n")
		case cmd == "DBSIZE":
			out = ":" + strconv.Itoa(len(f.data)) + "\r\n"
		case cmd == "SCAN":
			pat := strings.TrimSuffix(args[3], "*")
			var keys []string
			for k := range f.data {
				if strings.HasPrefix(k, pat) {
					keys = append(keys, k)
				}
			}
			out = "*2\r\n" + bulk("0") + "*" + strconv.Itoa(len(keys)) + "\r\n"
			for _, k := range keys {
				out += bulk(k)
			}
		case cmd == "TYPE":
			if _, ok := f.data[args[1]]; ok {
				out = "+string\r\n"
			} else {
				out = "+none\r\n"
			}
		case cmd == "TTL":
			out = ":-1\r\n"
		case cmd == "GETRANGE":
			out = bulk(f.data[args[1]])
		case cmd == "UNLINK":
			_, ok := f.data[args[1]]
			delete(f.data, args[1])
			if ok {
				out = ":1\r\n"
			} else {
				out = ":0\r\n"
			}
		case cmd == "FLUSHDB":
			f.data = map[string]string{}
			out = "+OK\r\n"
		default:
			out = fmt.Sprintf("-ERR unknown command '%s'\r\n", cmd)
		}
		f.mu.Unlock()
		if _, err := c.Write([]byte(out)); err != nil {
			return
		}
	}
}

func TestRedis(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	m := New()
	h := fakehost.New(map[string]string{"secret://redis": "s3cret", "secret://wrong": "nope"})
	cfg, _ := json.Marshal(Config{Address: f.ln.Addr().String(), Password: "secret://redis"})
	if err := m.Configure(ctx, h, "r", cfg); err != nil {
		t.Fatal(err)
	}
	if bad, _ := json.Marshal(Config{Address: "x:1", Password: "plain"}); m.Configure(ctx, h, "b", bad) == nil {
		t.Fatal("plaintext password accepted")
	}
	if hl := m.Health(ctx, "r"); hl.Status != "ok" {
		t.Fatalf("health %+v", hl)
	}
	run := func(action, in string, dry bool) (sdk.Result, error) {
		return m.Invoke(ctx, sdk.Call{Instance: "r", Action: action, Input: json.RawMessage(in), DryRun: dry})
	}
	r, err := run("info", "", false)
	var info map[string]any
	_ = json.Unmarshal(r.Output, &info)
	if err != nil || info["version"] != "7.2.4" || info["keys"] != 3.0 || info["hitRatePercent"] != 75.0 {
		t.Fatalf("info %v %v", info, err)
	}
	r, _ = run("keys", `{"pattern":"session:*"}`, false)
	var keys struct{ Keys []string }
	_ = json.Unmarshal(r.Output, &keys)
	if len(keys.Keys) != 2 {
		t.Fatalf("keys %v", keys)
	}
	r, err = run("get", `{"key":"session:1"}`, false)
	if err != nil || !strings.Contains(string(r.Output), "token-abc") {
		t.Fatalf("get %s %v", r.Output, err)
	}
	if _, err := run("get", `{"key":"missing"}`, false); err == nil {
		t.Fatal("missing key found")
	}
	r, err = run("flushdb", "", true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "all 3 keys") || len(f.data) != 3 {
		t.Fatalf("flush dry run %+v %v", r.Plan, err)
	}
	if _, err := run("delete", `{"key":"cache:x"}`, false); err != nil || len(f.data) != 2 {
		t.Fatalf("delete %v", err)
	}
	if _, err := run("flushdb", "", false); err != nil || len(f.data) != 0 {
		t.Fatalf("flush %v", err)
	}

	// A wrong password is reported as such.
	cfg, _ = json.Marshal(Config{Address: f.ln.Addr().String(), Password: "secret://wrong"})
	_ = m.Configure(ctx, h, "w", cfg)
	if hl := m.Health(ctx, "w"); hl.Status != "down" || !strings.Contains(hl.Message, "refused") {
		t.Fatalf("wrong password health %+v", hl)
	}
}

func TestReadReplyLimits(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("*999999999\r\n"))
	if _, err := readReply(r, 0); err == nil {
		t.Fatal("huge array accepted")
	}
	deep := strings.Repeat("*1\r\n", 20) + ":1\r\n"
	if _, err := readReply(bufio.NewReader(strings.NewReader(deep)), 0); err == nil {
		t.Fatal("deep nesting accepted")
	}
}
