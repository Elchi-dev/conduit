// Package elasticsearch looks into an Elasticsearch or OpenSearch cluster
// through its REST API: cluster health, nodes, indices, searching an index
// with the query DSL (scripts refused), and deleting one index.
package elasticsearch

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one cluster.
type Config struct {
	URL                string `json:"url"`      // e.g. https://es.example.com:9200
	APIKey             string `json:"apiKey"`   // secret://, the encoded API key (id:key in base64)
	Username           string `json:"username"` // for basic auth instead of an API key
	Password           string `json:"password"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Elasticsearch module.
func New() *Module { return &Module{} }

// Limits for searches.
const (
	MaxSize       = 100
	MaxFrom       = 10000
	maxBody       = 64 << 10
	maxDepth      = 32
	searchTimeout = "10s"
	maxIndices    = 1000
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	index := `"index":{"type":"string","description":"Index name"}`
	return sdk.Manifest{
		ID: "elasticsearch", Name: "Elasticsearch", Version: "0.1.0", Category: "Infrastructure", Icon: "search",
		Description: "Elasticsearch and OpenSearch: cluster health, nodes, indices, searching an index, deleting an index.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"The REST API, e.g. https://es.example.com:9200"},
			"apiKey":{"type":"string","x-secret":true,"description":"An API key (the encoded form). Best one whose role can only read, plus delete_index on the indices you want to delete"},
			"username":{"type":"string","description":"For a user and password instead of an API key"},
			"password":{"type":"string","x-secret":true},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "health", Title: "Cluster health", Description: "Status (green, yellow, red), nodes, shards and pending tasks.", Risk: sdk.RiskRead},
			{Name: "nodes", Title: "Nodes", Description: "Each node with roles, heap, RAM, CPU, load, disk and version.", Risk: sdk.RiskRead},
			{Name: "indices", Title: "Indices", Description: "Indices with health, status, documents, size and shards (system and hidden ones only when asked), at most 1000.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"pattern":{"type":"string","description":"Name or pattern, e.g. logs-*"},"includeHidden":{"type":"boolean","description":"Also system and hidden indices"}}}`)},
			{Name: "search", Title: "Search an index", Description: "Query DSL search of one index or pattern, at most 100 hits and 10 seconds. Scripts (script queries and fields, scripted metrics, runtime mappings, painless) are refused. Documents can hold personal data, so results stay out of the audit log.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["index"],"properties":{` + index + `,
					"q":{"type":"string","description":"Lucene query string, e.g. status:500 AND service:api"},
					"query":{"type":"object","description":"Query DSL, e.g. {\"match\":{\"message\":\"timeout\"}}"},
					"aggs":{"type":"object","description":"Aggregations"},
					"sort":{"description":"Sort, e.g. [{\"@timestamp\":\"desc\"}]"},
					"source":{"description":"Fields to return (_source filter), e.g. [\"message\",\"@timestamp\"]"},
					"size":{"type":"integer","minimum":0,"maximum":100,"default":10},
					"from":{"type":"integer","minimum":0,"maximum":10000}}}`)},
			{Name: "delete_index", Title: "Delete an index", Description: "Deletes one index by its exact name, with all its documents. Wildcards, aliases, data streams and system or hidden indices are refused. The preview shows its documents and size. There's no undo.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["index"],"properties":{` + index + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the url is like https://es.example.com:9200")
	}
	if c.APIKey != "" && !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	if c.APIKey != "" && c.Username != "" {
		return errors.New("use an API key or a username and password, not both")
	}
	if (c.Username == "") != (c.Password == "") {
		return errors.New("a username needs a password, and a password a username")
	}
	if strings.ContainsAny(c.Username, ":\r\n") {
		return errors.New("the username can't contain : or line breaks")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		client = sdk.HTTPClient(h, 30*time.Second)
		client.Transport.(*http.Transport).TLSClientConfig = tc
	}
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/"), func(ctx context.Context, r *http.Request) error {
		switch {
		case c.APIKey != "":
			k, err := h.Secret(ctx, c.APIKey)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "ApiKey "+strings.TrimSpace(k))
		case c.Username != "":
			pw, err := h.Secret(ctx, c.Password)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Username+":"+pw)))
		}
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("the cluster refused the credentials")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("the cluster refused: permission denied (%v)", err)
	}
	return err
}

type clusterHealth struct {
	ClusterName         string  `json:"cluster_name"`
	Status              string  `json:"status"`
	TimedOut            bool    `json:"timed_out"`
	Nodes               int     `json:"number_of_nodes"`
	DataNodes           int     `json:"number_of_data_nodes"`
	ActivePrimaryShards int     `json:"active_primary_shards"`
	ActiveShards        int     `json:"active_shards"`
	Relocating          int     `json:"relocating_shards"`
	Initializing        int     `json:"initializing_shards"`
	Unassigned          int     `json:"unassigned_shards"`
	PendingTasks        int     `json:"number_of_pending_tasks"`
	ActiveShardsPercent float64 `json:"active_shards_percent_as_number"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var h clusterHealth
	if _, err := c.api.Do(ctx, http.MethodGet, "/_cluster/health", nil, nil, &h); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err).Error()}
	}
	msg := fmt.Sprintf("%s: %s, %d nodes", h.ClusterName, h.Status, h.Nodes)
	switch h.Status {
	case "green":
		return sdk.Health{Status: "ok", Message: msg}
	case "yellow":
		return sdk.Health{Status: "degraded", Message: msg + fmt.Sprintf(", %d unassigned shards", h.Unassigned)}
	}
	return sdk.Health{Status: "down", Message: msg}
}

type input struct {
	Index         string          `json:"index"`
	Pattern       string          `json:"pattern"`
	IncludeHidden bool            `json:"includeHidden"`
	Q             string          `json:"q"`
	Query         json.RawMessage `json:"query"`
	Aggs          json.RawMessage `json:"aggs"`
	Sort          json.RawMessage `json:"sort"`
	Source        json.RawMessage `json:"source"`
	Size          *int            `json:"size"`
	From          int             `json:"from"`
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p input
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	var res sdk.Result
	switch call.Action {
	case "health":
		var h clusterHealth
		err = c.do(ctx, http.MethodGet, "/_cluster/health", nil, nil, &h)
		if err == nil {
			res, err = sdk.JSON(h)
		}
	case "nodes":
		res, err = c.nodes(ctx)
	case "indices":
		res, err = c.indices(ctx, p)
	case "search":
		res, err = c.search(ctx, p)
	case "delete_index":
		res, err = c.deleteIndex(ctx, p.Index, call.DryRun)
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	return res, err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

func (c *conn) nodes(ctx context.Context) (sdk.Result, error) {
	q := url.Values{"format": {"json"}, "h": {"name,ip,node.role,master,heap.percent,ram.percent,cpu,load_1m,disk.used_percent,version"}, "s": {"name"}}
	var rows []map[string]any
	if err := c.do(ctx, http.MethodGet, "/_cat/nodes", q, nil, &rows); err != nil {
		return sdk.Result{}, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]any{
			"name": r["name"], "ip": r["ip"], "roles": r["node.role"], "master": r["master"] == "*",
			"heapPercent": num(r["heap.percent"]), "ramPercent": num(r["ram.percent"]), "cpuPercent": num(r["cpu"]),
			"load1m": num(r["load_1m"]), "diskUsedPercent": num(r["disk.used_percent"]), "version": r["version"],
		})
	}
	return sdk.JSON(out)
}

// num turns the strings _cat returns into numbers (nil when empty).
func num(v any) any {
	s, ok := v.(string)
	if !ok {
		return v
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return nil
}

type catIndex struct {
	Index  string `json:"index"`
	Health string `json:"health"`
	Status string `json:"status"`
	Docs   string `json:"docs.count"`
	Size   string `json:"store.size"`
	Pri    string `json:"pri"`
	Rep    string `json:"rep"`
}

func (ci catIndex) summary() map[string]any {
	return map[string]any{"index": ci.Index, "health": ci.Health, "status": ci.Status, "docs": num(ci.Docs), "bytes": num(ci.Size), "primaries": num(ci.Pri), "replicas": num(ci.Rep)}
}

func (c *conn) catIndices(ctx context.Context, target string, hidden bool) ([]catIndex, error) {
	q := url.Values{"format": {"json"}, "bytes": {"b"}, "h": {"index,health,status,docs.count,store.size,pri,rep"}, "s": {"index"}}
	if hidden {
		q.Set("expand_wildcards", "all")
	} else {
		q.Set("expand_wildcards", "open,closed")
	}
	path := "/_cat/indices"
	if target != "" {
		path += "/" + url.PathEscape(target)
	}
	var rows []catIndex
	err := c.do(ctx, http.MethodGet, path, q, nil, &rows)
	return rows, err
}

func (c *conn) indices(ctx context.Context, p input) (sdk.Result, error) {
	pat := strings.TrimSpace(p.Pattern)
	if pat != "" {
		if err := CheckTarget(pat, true); err != nil {
			return sdk.Result{}, err
		}
	}
	rows, err := c.catIndices(ctx, pat, p.IncludeHidden)
	if err != nil {
		return sdk.Result{}, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Index < rows[j].Index })
	out := []map[string]any{}
	for _, r := range rows {
		if !p.IncludeHidden && strings.HasPrefix(r.Index, ".") {
			continue
		}
		if len(out) >= maxIndices {
			break
		}
		out = append(out, r.summary())
	}
	return sdk.JSON(out)
}

var (
	// indexRe is one index name: lowercase, no \ / * ? " < > | space , #.
	indexRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.+-]{0,254}$`)
	patternRe = regexp.MustCompile(`^[a-z0-9*][a-z0-9_.+*-]{0,254}$`)
)

// CheckTarget checks an index name or, with patterns, a comma-separated
// list of names and wildcard patterns to search or list. Names starting
// with "." (system and hidden indices, data stream backing indices) or "_"
// (API endpoints such as _all or _update_by_query) are refused, and so is
// anything with a slash, so the request path stays the one Conduit builds.
func CheckTarget(s string, patterns bool) error {
	if s == "" {
		return errors.New("give an index name")
	}
	if len(s) > 1024 {
		return errors.New("the index list is too long")
	}
	parts := []string{s}
	if patterns {
		parts = strings.Split(s, ",")
	}
	for _, p := range parts {
		re := indexRe
		if patterns {
			re = patternRe
		}
		switch {
		case strings.HasPrefix(p, "."):
			return fmt.Errorf("%q: system and hidden indices (names starting with .) aren't searched here", p)
		case strings.HasPrefix(p, "_"):
			return fmt.Errorf("%q isn't an index name", p)
		case !patterns && strings.ContainsAny(p, "*?,"):
			return fmt.Errorf("%q: give one exact index name, not a pattern or a list", p)
		case !re.MatchString(p) || p == "." || p == "..":
			return fmt.Errorf("%q isn't an index name (lowercase letters, digits and _ . + -)", p)
		}
	}
	return nil
}

// CheckDSL walks a query DSL fragment and refuses what can run code or read
// what an index search shouldn't: any key naming a script (script,
// script_score, script_fields, scripted_metric, …), runtime_mappings (which
// define fields by script), a script language, and lookups into system
// indices (terms lookup, more_like_this). It also bounds the depth.
func CheckDSL(raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if len(raw) > maxBody {
		return errors.New("the query is too long")
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("the query isn't valid JSON: %w", err)
	}
	if err := noDuplicateKeys(raw); err != nil {
		return err
	}
	return walkDSL(v, 0)
}

// CheckAggs checks the aggregations: everything CheckDSL refuses, plus
// bucket sizes. A size or shard_size is at most MaxAggSize (MaxTopHits
// under top_hits), and the buckets of nested bucket aggregations multiply:
// their product is at most MaxBuckets.
func CheckAggs(raw json.RawMessage) error {
	if err := CheckDSL(raw); err != nil {
		return err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var v any
	_ = json.Unmarshal(raw, &v) // CheckDSL parsed it already
	return walkAggs(v, 1, 0)
}

// Limits for aggregations.
const (
	MaxAggSize = 1000
	MaxTopHits = 100
	MaxBuckets = 10000
	// defaultBuckets is what a terms-like aggregation returns without a size.
	defaultBuckets = 10
)

// bucketAggs return up to size buckets each (10 without a size).
var bucketAggs = map[string]bool{
	"terms": true, "multi_terms": true, "significant_terms": true, "significant_text": true,
	"rare_terms": true, "composite": true, "categorize_text": true, "frequent_item_sets": true,
}

func walkAggs(v any, mult, depth int) error {
	if depth > maxDepth {
		return errors.New("the aggregations are nested too deeply")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return errors.New("aggs is an object of named aggregations, like {\"by_status\":{\"terms\":{\"field\":\"status\"}}}")
	}
	for name, def := range m {
		d, ok := def.(map[string]any)
		if !ok {
			return fmt.Errorf("aggregation %q is an object, like {\"terms\":{\"field\":\"status\"}}", name)
		}
		local := 1
		for typ, body := range d {
			lt := strings.ToLower(typ)
			if lt == "aggs" || lt == "aggregations" || lt == "meta" {
				continue
			}
			params, _ := body.(map[string]any)
			limit := MaxAggSize
			if lt == "top_hits" {
				limit = MaxTopHits
			}
			n := -1
			for k, val := range params {
				lk := strings.ToLower(k)
				if lk != "size" && lk != "shard_size" {
					continue
				}
				x, err := sizeValue(val)
				if err != nil {
					return fmt.Errorf("aggregation %q: %s %w", name, k, err)
				}
				max := limit
				if lk == "shard_size" {
					max = 2 * limit
				}
				if x > max {
					return fmt.Errorf("aggregation %q: %s is at most %d here", name, k, max)
				}
				if lk == "size" {
					n = x
				}
			}
			if bucketAggs[lt] {
				if n < 0 {
					n = defaultBuckets
				}
				if n > local {
					local = n
				}
			}
		}
		total := mult * local
		if total > MaxBuckets {
			return fmt.Errorf("aggregation %q: nested aggregations would make more than %d buckets; lower the sizes", name, MaxBuckets)
		}
		for _, key := range []string{"aggs", "aggregations"} {
			for k, sub := range d {
				if strings.ToLower(k) == key {
					if err := walkAggs(sub, total, depth+1); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// sizeValue reads a size given as a number or a numeric string (both work
// with Elasticsearch).
func sizeValue(v any) (int, error) {
	var f float64
	switch x := v.(type) {
	case float64:
		f = x
	case string:
		g, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		if err != nil {
			return 0, errors.New("is a number")
		}
		f = g
	default:
		return 0, errors.New("is a number")
	}
	if f < 0 || f > 1e9 {
		return 0, errors.New("is out of range")
	}
	return int(f), nil
}

// noDuplicateKeys refuses JSON with an object that has the same key twice:
// Go's map keeps one of them, so the check could miss the other.
func noDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	type frame struct {
		obj    bool
		keys   map[string]bool
		expKey bool
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("the query isn't valid JSON: %w", err)
		}
		if n := len(stack); n > 0 && stack[n-1].obj && stack[n-1].expKey {
			if k, ok := tok.(string); ok {
				if stack[n-1].keys[k] {
					return fmt.Errorf("the key %q appears twice in one object", k)
				}
				stack[n-1].keys[k] = true
				stack[n-1].expKey = false
				continue
			}
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{':
				stack = append(stack, &frame{obj: true, keys: map[string]bool{}, expKey: true})
				continue
			case '[':
				stack = append(stack, &frame{})
				continue
			default:
				stack = stack[:len(stack)-1]
			}
		}
		if n := len(stack); n > 0 && stack[n-1].obj {
			stack[n-1].expKey = true
		}
	}
}

// lookupIndexOK reports whether an index named in a query (terms lookup,
// more_like_this) is a plain one: not a system or hidden index, an API
// endpoint, date math (<.security-{now}>, which can resolve to a system
// index), an exclusion, or another cluster's system index.
func lookupIndexOK(s string) bool {
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if i := strings.LastIndex(p, ":"); i >= 0 {
			p = p[i+1:]
		}
		if p == "" || strings.ContainsAny(p[:1], "._<-+%") || strings.ContainsAny(p, "<>{}") {
			return false
		}
	}
	return true
}

func walkDSL(v any, depth int) error {
	if depth > maxDepth {
		return errors.New("the query is nested too deeply")
	}
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			lk := strings.ToLower(k)
			switch {
			case strings.Contains(lk, "script"), strings.Contains(lk, "painless"):
				return fmt.Errorf("scripts (%s) aren't allowed here", k)
			case lk == "runtime_mappings", lk == "lang":
				return fmt.Errorf("%s isn't allowed here", k)
			case lk == "wrapper":
				// A wrapper query is base64-encoded DSL, unchecked here.
				return errors.New("wrapper queries aren't allowed here")
			case lk == "index" || lk == "_index":
				if s, ok := val.(string); ok && !lookupIndexOK(s) {
					return fmt.Errorf("lookups into system indices (%s) aren't allowed here", s)
				}
			case lk == "inner_hits":
				// Hits per matching document, like top_hits.
				if ih, ok := val.(map[string]any); ok {
					for ik, iv := range ih {
						if strings.EqualFold(ik, "size") {
							if n, err := sizeValue(iv); err != nil || n > MaxTopHits {
								return fmt.Errorf("inner_hits size is a number, at most %d", MaxTopHits)
							}
						}
					}
				}
			}
			if s, ok := val.(string); ok && strings.EqualFold(strings.TrimSpace(s), "painless") {
				return errors.New("painless isn't allowed here")
			}
			if err := walkDSL(val, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range x {
			if err := walkDSL(e, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// SearchBody builds the request body of a search, with the size and from
// capped and a timeout, after checking every part.
func SearchBody(p input) (map[string]any, error) {
	body := map[string]any{"timeout": searchTimeout, "track_total_hits": true}
	size := 10
	if p.Size != nil {
		size = *p.Size
	}
	if size < 0 || size > MaxSize {
		return nil, fmt.Errorf("size is 0 to %d", MaxSize)
	}
	if p.From < 0 || p.From+size > MaxFrom {
		return nil, fmt.Errorf("from plus size is at most %d", MaxFrom)
	}
	body["size"] = size
	if p.From > 0 {
		body["from"] = p.From
	}
	q := strings.TrimSpace(p.Q)
	if q != "" && len(p.Query) > 0 && string(p.Query) != "null" {
		return nil, errors.New("give q or query, not both")
	}
	if len(q) > 4096 {
		return nil, errors.New("q is too long")
	}
	for name, part := range map[string]json.RawMessage{"query": p.Query, "aggs": p.Aggs, "sort": p.Sort, "_source": p.Source} {
		if len(part) == 0 || string(part) == "null" {
			continue
		}
		check := CheckDSL
		if name == "aggs" {
			check = CheckAggs
		}
		if err := check(part); err != nil {
			return nil, err
		}
		body[name] = part
	}
	if q != "" {
		// query_string can't run scripts; allow_leading_wildcard off keeps a
		// stray *foo from scanning every term.
		body["query"] = map[string]any{"query_string": map[string]any{"query": q, "allow_leading_wildcard": false}}
	}
	return body, nil
}

func (c *conn) search(ctx context.Context, p input) (sdk.Result, error) {
	idx := strings.TrimSpace(p.Index)
	if err := CheckTarget(idx, true); err != nil {
		return sdk.Result{}, err
	}
	body, err := SearchBody(p)
	if err != nil {
		return sdk.Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var r struct {
		Took     int  `json:"took"`
		TimedOut bool `json:"timed_out"`
		Hits     struct {
			Total struct {
				Value    int64  `json:"value"`
				Relation string `json:"relation"`
			} `json:"total"`
			Hits []struct {
				Index  string          `json:"_index"`
				ID     string          `json:"_id"`
				Score  *float64        `json:"_score"`
				Source json.RawMessage `json:"_source"`
				Sort   json.RawMessage `json:"sort"`
			} `json:"hits"`
		} `json:"hits"`
		Aggregations json.RawMessage `json:"aggregations"`
	}
	// The path is built here, never taken from input: only _search is
	// reached. expand_wildcards=open keeps patterns off hidden indices.
	// On clusters where dot-prefixed indices aren't hidden yet, a pattern
	// excludes them explicitly.
	target := idx
	if strings.Contains(idx, "*") {
		target += ",-.*"
	}
	q := url.Values{"expand_wildcards": {"open"}, "allow_partial_search_results": {"true"}}
	if err := c.do(ctx, http.MethodPost, "/"+url.PathEscape(target)+"/_search", q, body, &r); err != nil {
		return sdk.Result{}, err
	}
	hits := make([]map[string]any, 0, len(r.Hits.Hits))
	for _, h := range r.Hits.Hits {
		e := map[string]any{"index": h.Index, "id": h.ID, "score": h.Score, "source": h.Source}
		if len(h.Sort) > 0 {
			e["sort"] = h.Sort
		}
		hits = append(hits, e)
	}
	out := map[string]any{"tookMs": r.Took, "timedOut": r.TimedOut, "total": r.Hits.Total.Value, "totalRelation": r.Hits.Total.Relation, "hits": hits}
	if len(r.Aggregations) > 0 {
		out["aggregations"] = r.Aggregations
	}
	return sdk.JSON(out)
}

func (c *conn) deleteIndex(ctx context.Context, name string, dry bool) (sdk.Result, error) {
	name = strings.TrimSpace(name)
	if err := CheckTarget(name, false); err != nil {
		return sdk.Result{}, err
	}
	rows, err := c.catIndices(ctx, name, true)
	if rest.IsStatus(err, http.StatusNotFound) {
		return sdk.Result{}, fmt.Errorf("there's no index %s", name)
	}
	if err != nil {
		return sdk.Result{}, err
	}
	// An alias or a data stream resolves to other names: only an index of
	// exactly this name is deleted.
	if len(rows) != 1 || rows[0].Index != name {
		return sdk.Result{}, fmt.Errorf("%s isn't a single index (an alias or data stream?); give the index's own name", name)
	}
	var settings map[string]struct {
		Settings struct {
			Index struct {
				Hidden any `json:"hidden"`
			} `json:"index"`
		} `json:"settings"`
	}
	if err := c.do(ctx, http.MethodGet, "/"+url.PathEscape(name)+"/_settings/index.hidden", url.Values{"expand_wildcards": {"all"}}, nil, &settings); err != nil {
		return sdk.Result{}, err
	}
	if s, ok := settings[name]; ok && fmt.Sprint(s.Settings.Index.Hidden) == "true" {
		return sdk.Result{}, fmt.Errorf("%s is a hidden index, which Conduit doesn't delete", name)
	}
	ix := rows[0]
	if dry {
		before, _ := json.Marshal(ix.summary())
		return sdk.Result{Plan: &sdk.Plan{
			Summary: fmt.Sprintf("Delete index %s: %s documents, %s bytes (health %s). Its documents are gone for good: there's no undo.", name, ix.Docs, ix.Size, ix.Health),
			Changes: []sdk.Change{{Target: "index " + name, Op: "delete", Before: before}},
		}}, nil
	}
	var ack struct {
		Acknowledged bool `json:"acknowledged"`
	}
	q := url.Values{"expand_wildcards": {"none"}, "allow_no_indices": {"false"}}
	if err := c.do(ctx, http.MethodDelete, "/"+url.PathEscape(name), q, nil, &ack); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"deleted": name, "acknowledged": ack.Acknowledged, "docs": num(ix.Docs), "bytes": num(ix.Size)})
}
