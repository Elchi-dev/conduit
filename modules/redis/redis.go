// Package redis looks into a Redis or Valkey server: memory, keys and their
// values, and can delete keys or empty a database.
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Redis server.
type Config struct {
	Address  string `json:"address"`  // host:port, default port 6379
	Username string `json:"username"` // ACL user (Redis 6+); empty for the default user
	Password string `json:"password"` // secret://, optional
	DB       int    `json:"db"`
	TLS      bool   `json:"tls"`
}

type conn struct {
	cfg  Config
	host sdk.Host
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
}

// New returns the Redis module.
func New() *Module { return &Module{} }

const (
	maxKeys    = 1000
	previewLen = 2000
	timeout    = 10 * time.Second
)

const keyIn = `{"type":"object","required":["key"],"properties":{"key":{"type":"string","maxLength":1024}}}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "redis", Name: "Redis", Version: "0.1.0", Category: "Infrastructure", Icon: "database",
		Description: "Memory, keys and values of a Redis or Valkey server; delete keys or empty a database.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["address"],"properties":{
			"address":{"type":"string","description":"host:port, e.g. 127.0.0.1:6379"},
			"username":{"type":"string","description":"ACL user, if you use one"},
			"password":{"type":"string","x-secret":true},
			"db":{"type":"integer","default":0,"minimum":0,"maximum":15},
			"tls":{"type":"boolean","default":false}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "info", Title: "Summary", Description: "Version, memory, clients, hit rate.", Risk: sdk.RiskRead},
			{Name: "keys", Title: "Find keys", Description: "Keys matching a pattern (SCAN), at most 1000.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"pattern":{"type":"string","default":"*","maxLength":256}}}`)},
			{Name: "get", Title: "Look at a key", Description: "Type, time to live and the start of the value. Values can be secrets, so they stay out of the audit log.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(keyIn)},
			{Name: "delete", Title: "Delete a key", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(keyIn)},
			{Name: "flushdb", Title: "Empty the database", Description: "Deletes every key in this database.", Risk: sdk.RiskDestructive, DryRun: true},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.Contains(c.Address, ":") || strings.HasPrefix(c.Address, "[") && !strings.Contains(c.Address, "]:") {
		c.Address = net.JoinHostPort(strings.Trim(c.Address, "[]"), "6379")
	}
	host, port, err := net.SplitHostPort(c.Address)
	if err != nil || host == "" || strings.ContainsAny(host, "/@ ") {
		return errors.New("the address is host:port, like 127.0.0.1:6379")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return errors.New("the port is 1 to 65535")
	}
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	if c.DB < 0 || c.DB > 15 || strings.ContainsAny(c.Username, " \r\n") {
		return errors.New("db is 0 to 15")
	}
	m.set.Put(id, &conn{cfg: c, host: h})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) open(ctx context.Context) (*client, error) {
	cl, err := dial(c.cfg.Address, c.cfg.TLS, timeout)
	if err != nil {
		return nil, err
	}
	if c.cfg.Password != "" {
		pw, err := c.host.Secret(ctx, c.cfg.Password)
		if err != nil {
			cl.Close()
			return nil, err
		}
		args := []string{"AUTH", pw}
		if c.cfg.Username != "" {
			args = []string{"AUTH", c.cfg.Username, pw}
		}
		if _, err := cl.do(args...); err != nil {
			cl.Close()
			return nil, fmt.Errorf("sign-in refused: %w", err)
		}
	}
	if c.cfg.DB != 0 {
		if _, err := cl.do("SELECT", strconv.Itoa(c.cfg.DB)); err != nil {
			cl.Close()
			return nil, err
		}
	}
	return cl, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	cl, err := c.open(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	defer cl.Close()
	if v, err := cl.do("PING"); err != nil || asString(v) != "PONG" {
		return sdk.Health{Status: "down", Message: "no answer to PING"}
	}
	return sdk.Health{Status: "ok", Message: c.cfg.Address}
}

func parseInfo(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, ":"); ok && !strings.HasPrefix(line, "#") {
			out[k] = v
		}
	}
	return out
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Pattern string `json:"pattern"`
		Key     string `json:"key"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "info", "keys", "get", "delete", "flushdb":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	if (call.Action == "get" || call.Action == "delete") && (p.Key == "" || len(p.Key) > 1024) {
		return sdk.Result{}, errors.New("give a key")
	}
	cl, err := c.open(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	defer cl.Close()

	switch call.Action {
	case "info":
		v, err := cl.do("INFO")
		if err != nil {
			return sdk.Result{}, err
		}
		i := parseInfo(asString(v))
		size, _ := cl.do("DBSIZE")
		hits, misses := asInt(i["keyspace_hits"]), asInt(i["keyspace_misses"])
		rate := 0.0
		if hits+misses > 0 {
			rate = float64(hits) / float64(hits+misses) * 100
		}
		return sdk.JSON(map[string]any{
			"version": i["redis_version"], "uptimeSeconds": asInt(i["uptime_in_seconds"]),
			"usedMemory": asInt(i["used_memory"]), "usedMemoryHuman": i["used_memory_human"], "maxMemory": asInt(i["maxmemory"]),
			"clients": asInt(i["connected_clients"]), "keys": asInt(size), "hitRatePercent": rate,
			"role": i["role"], "evictedKeys": asInt(i["evicted_keys"]),
		})
	case "keys":
		pat := p.Pattern
		if pat == "" {
			pat = "*"
		}
		keys := []string{}
		cursor := "0"
		for i := 0; i < 200; i++ {
			v, err := cl.do("SCAN", cursor, "MATCH", pat, "COUNT", "500")
			if err != nil {
				return sdk.Result{}, err
			}
			arr, ok := v.([]any)
			if !ok || len(arr) != 2 {
				return sdk.Result{}, errors.New("unexpected SCAN reply")
			}
			cursor = asString(arr[0])
			batch, _ := arr[1].([]any)
			for _, k := range batch {
				if len(keys) < maxKeys {
					keys = append(keys, asString(k))
				}
			}
			if cursor == "0" || len(keys) >= maxKeys {
				break
			}
		}
		return sdk.JSON(map[string]any{"keys": keys, "complete": cursor == "0" && len(keys) < maxKeys})
	case "get":
		t, err := cl.do("TYPE", p.Key)
		if err != nil {
			return sdk.Result{}, err
		}
		typ := asString(t)
		if typ == "none" {
			return sdk.Result{}, errors.New("no such key")
		}
		ttl, _ := cl.do("TTL", p.Key)
		var val any
		switch typ {
		case "string":
			v, err := cl.do("GETRANGE", p.Key, "0", strconv.Itoa(previewLen-1))
			if err != nil {
				return sdk.Result{}, err
			}
			val = asString(v)
		case "list":
			val, err = cl.do("LRANGE", p.Key, "0", "49")
		case "set":
			var v any
			v, err = cl.do("SSCAN", p.Key, "0", "COUNT", "50")
			if arr, ok := v.([]any); ok && len(arr) == 2 {
				val = arr[1]
			}
		case "zset":
			val, err = cl.do("ZRANGE", p.Key, "0", "49", "WITHSCORES")
		case "hash":
			var v any
			v, err = cl.do("HSCAN", p.Key, "0", "COUNT", "50")
			if arr, ok := v.([]any); ok && len(arr) == 2 {
				val = arr[1]
			}
		default:
			val = "(" + typ + ": not shown)"
		}
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"key": p.Key, "type": typ, "ttlSeconds": asInt(ttl), "value": val})
	case "delete":
		if call.DryRun {
			t, _ := cl.do("TYPE", p.Key)
			if asString(t) == "none" {
				return sdk.Result{}, errors.New("no such key")
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: "Delete " + p.Key, Changes: []sdk.Change{{Target: p.Key, Op: "delete"}}}}, nil
		}
		v, err := cl.do("UNLINK", p.Key)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": asInt(v)})
	case "flushdb":
		size, err := cl.do("DBSIZE")
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete all %d keys in database %d of %s", asInt(size), c.cfg.DB, c.cfg.Address),
				Changes: []sdk.Change{{Target: fmt.Sprintf("database %d", c.cfg.DB), Op: "delete", Before: json.RawMessage(strconv.FormatInt(asInt(size), 10))}}}}, nil
		}
		if _, err := cl.do("FLUSHDB", "ASYNC"); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": asInt(size)})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
