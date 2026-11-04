// Package mongodb looks into a MongoDB deployment with the official Go
// driver: databases, collections with document counts, find and aggregate
// (read-only: stages and operators that write or run JavaScript are
// refused, results capped) and a serverStatus summary. It never writes.
package mongodb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one MongoDB deployment.
type Config struct {
	// URI without credentials, e.g. mongodb://db1:27017,db2:27017/?replicaSet=rs0
	// or mongodb+srv://cluster0.example.mongodb.net/.
	URI        string `json:"uri"`
	Username   string `json:"username"`
	Password   string `json:"password"` // secret://
	AuthSource string `json:"authSource"`
}

// Limits for queries.
const (
	QueryTimeout = 10 * time.Second
	MaxDocs      = 100
	MaxBytes     = 4 << 20
	maxInput     = 64 << 10
	maxDepth     = 32
	maxCounted   = 200
)

type conn struct {
	cfg  Config
	host sdk.Host
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
}

// New returns the MongoDB module.
func New() *Module { return &Module{} }

var (
	dbRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)
	collRe = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,254}$`)
	userRe = regexp.MustCompile(`^[^\x00-\x1f]{1,256}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	target := `"database":{"type":"string"},"collection":{"type":"string"}`
	return sdk.Manifest{
		ID: "mongodb", Name: "MongoDB", Version: "0.1.0", Category: "Infrastructure", Icon: "database",
		Description: "MongoDB: databases, collections with counts, read-only find and aggregate, a server status summary.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["uri"],"properties":{
			"uri":{"type":"string","description":"Connection string without the user and password, e.g. mongodb://db.internal:27017/?tls=true or mongodb+srv://cluster0.example.mongodb.net/"},
			"username":{"type":"string","description":"Best a user with only the read role (readAnyDatabase, plus clusterMonitor for the server status)"},
			"password":{"type":"string","x-secret":true},
			"authSource":{"type":"string","description":"Database the user is defined in (admin when empty)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "databases", Title: "Databases", Description: "Databases the user can see, with size on disk.", Risk: sdk.RiskRead},
			{Name: "collections", Title: "Collections", Description: "Collections and views of a database, with estimated document counts.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["database"],"properties":{"database":{"type":"string"}}}`)},
			{Name: "find", Title: "Find documents", Description: "Documents matching a filter (MongoDB JSON, e.g. {\"status\":\"failed\"}), at most 100 and 10 seconds. $where, $function, $accumulator and JavaScript code are refused. Documents can hold personal data, so results stay out of the audit log.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["database","collection"],"properties":{` + target + `,
					"filter":{"type":"object"},"projection":{"type":"object"},"sort":{"type":"object","description":"e.g. {\"createdAt\":-1}"},
					"limit":{"type":"integer","minimum":1,"maximum":100,"default":20},"skip":{"type":"integer","minimum":0}}}`)},
			{Name: "aggregate", Title: "Aggregate", Description: "Runs an aggregation pipeline, with a $limit of at most 100 added at the end and 10 seconds. $out, $merge, $function, $accumulator, $where and change streams are refused. Results stay out of the audit log.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["database","collection","pipeline"],"properties":{` + target + `,
					"pipeline":{"type":"array","items":{"type":"object"},"description":"e.g. [{\"$match\":{\"status\":\"failed\"}},{\"$group\":{\"_id\":\"$code\",\"n\":{\"$sum\":1}}}]"},
					"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
			{Name: "server_status", Title: "Server status", Description: "Version, uptime, connections, operation counters, memory and replica set role.", Risk: sdk.RiskRead},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	c.URI = strings.TrimSpace(c.URI)
	if err := CheckURI(c.URI); err != nil {
		return err
	}
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	if (c.Username == "") != (c.Password == "") {
		return errors.New("a username needs a password, and a password a username")
	}
	if c.Username != "" && !userRe.MatchString(c.Username) {
		return errors.New("the username is a plain name")
	}
	if c.AuthSource != "" && !dbRe.MatchString(c.AuthSource) {
		return errors.New("authSource is a database name, like admin")
	}
	if err := ClientOptions(c, "x", nil).Validate(); err != nil {
		return fmt.Errorf("the connection string isn't valid: %s", rest.Redact(err.Error()))
	}
	m.set.Put(id, &conn{cfg: c, host: h})
	return nil
}

// CheckURI accepts a mongodb:// or mongodb+srv:// connection string without
// credentials, and without options that carry a password or token or point
// the driver at local files.
func CheckURI(s string) error {
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok || (scheme != "mongodb" && scheme != "mongodb+srv") {
		return errors.New("the uri is like mongodb://db.internal:27017/ or mongodb+srv://cluster0.example.mongodb.net/")
	}
	if strings.Contains(rest, "#") {
		return errors.New("the uri has no #fragment")
	}
	hosts, query, _ := strings.Cut(rest, "?")
	hosts, _, _ = strings.Cut(hosts, "/")
	if strings.Contains(hosts, "@") {
		return errors.New("leave the user and password out of the uri: enter the username, and the password as a secret:// reference")
	}
	if hosts == "" || strings.ContainsAny(hosts, " \\") {
		return errors.New("the uri names the server, like mongodb://db.internal:27017/")
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		return errors.New("the uri's options aren't valid")
	}
	for k := range q {
		lk := strings.ToLower(k)
		switch {
		case strings.Contains(lk, "password"), strings.Contains(lk, "token"), lk == "authmechanismproperties":
			return fmt.Errorf("the %s option carries a credential: Conduit doesn't take it in the uri", k)
		case strings.HasSuffix(lk, "file"):
			return fmt.Errorf("the %s option reads a file on this computer, which Conduit doesn't allow", k)
		}
	}
	return nil
}

// ClientOptions builds the driver's options: the uri, the credential, a
// 10-second timeout on every operation (sent to the server as maxTimeMS),
// small pools, and the instance's dialer.
func ClientOptions(c Config, password string, dial dialFunc) *options.ClientOptions {
	o := options.Client().ApplyURI(c.URI).
		SetAppName("conduit").
		SetTimeout(QueryTimeout).
		SetConnectTimeout(10 * time.Second).
		SetServerSelectionTimeout(10 * time.Second).
		SetMaxPoolSize(2).
		SetRetryWrites(false)
	if c.Username != "" {
		o.SetAuth(options.Credential{Username: c.Username, Password: password, PasswordSet: true, AuthSource: c.AuthSource})
	}
	if dial != nil {
		o.SetDialer(dial)
	}
	return o
}

// dialFunc is the instance's dialer as the driver's ContextDialer.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func (d dialFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d(ctx, network, addr)
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) open(ctx context.Context) (*mongo.Client, error) {
	pw := ""
	if c.cfg.Password != "" {
		var err error
		if pw, err = c.host.Secret(ctx, c.cfg.Password); err != nil {
			return nil, err
		}
	}
	cl, err := mongo.Connect(ClientOptions(c.cfg, pw, sdk.DialContext(c.host)))
	if err != nil {
		return nil, cleanErr(err)
	}
	return cl, nil
}

// cleanErr keeps driver errors free of anything that looks like a
// credential.
func cleanErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || mongo.IsTimeout(err) {
		return errors.New("MongoDB didn't answer within 10 seconds")
	}
	return errors.New(rest.Redact(err.Error()))
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
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	defer cl.Disconnect(context.Background()) //nolint:errcheck // nothing to keep
	var info struct {
		Version string `bson:"version"`
	}
	if err := cl.Database("admin").RunCommand(ctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&info); err != nil {
		return sdk.Health{Status: "down", Message: cleanErr(err).Error()}
	}
	return sdk.Health{Status: "ok", Message: "MongoDB " + info.Version}
}

type input struct {
	Database   string          `json:"database"`
	Collection string          `json:"collection"`
	Filter     json.RawMessage `json:"filter"`
	Projection json.RawMessage `json:"projection"`
	Sort       json.RawMessage `json:"sort"`
	Pipeline   json.RawMessage `json:"pipeline"`
	Limit      *int64          `json:"limit"`
	Skip       int64           `json:"skip"`
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
	// Everything is checked before connecting.
	var run func(ctx context.Context, cl *mongo.Client) (any, error)
	switch call.Action {
	case "databases":
		run = databases
	case "server_status":
		run = serverStatus
	case "collections":
		if err := checkDB(p.Database); err != nil {
			return sdk.Result{}, err
		}
		run = func(ctx context.Context, cl *mongo.Client) (any, error) {
			return collections(ctx, cl.Database(p.Database))
		}
	case "find":
		f, err := BuildFind(p)
		if err != nil {
			return sdk.Result{}, err
		}
		run = func(ctx context.Context, cl *mongo.Client) (any, error) {
			cur, err := cl.Database(p.Database).Collection(p.Collection).Find(ctx, f.filter, f.opts)
			if err != nil {
				return nil, err
			}
			return drain(ctx, cur, int(f.limit))
		}
	case "aggregate":
		pipe, limit, err := BuildPipeline(p)
		if err != nil {
			return sdk.Result{}, err
		}
		run = func(ctx context.Context, cl *mongo.Client) (any, error) {
			cur, err := cl.Database(p.Database).Collection(p.Collection).Aggregate(ctx, pipe, options.Aggregate().SetAllowDiskUse(false).SetBatchSize(int32(limit)))
			if err != nil {
				return nil, err
			}
			return drain(ctx, cur, int(limit))
		}
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	cl, err := c.open(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	defer cl.Disconnect(context.Background()) //nolint:errcheck // nothing to keep
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	out, err := run(ctx, cl)
	if err != nil {
		return sdk.Result{}, cleanErr(err)
	}
	return sdk.JSON(out)
}

func databases(ctx context.Context, cl *mongo.Client) (any, error) {
	r, err := cl.ListDatabases(ctx, bson.D{}, options.ListDatabases().SetAuthorizedDatabases(true))
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, d := range r.Databases {
		out = append(out, map[string]any{"name": d.Name, "sizeOnDisk": d.SizeOnDisk, "empty": d.Empty})
	}
	return map[string]any{"databases": out, "totalSize": r.TotalSize}, nil
}

func collections(ctx context.Context, db *mongo.Database) (any, error) {
	specs, err := db.ListCollectionSpecifications(ctx, bson.D{}, options.ListCollections().SetAuthorizedCollections(true))
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for i, s := range specs {
		e := map[string]any{"name": s.Name, "type": s.Type}
		if s.Type == "collection" && i < maxCounted && !strings.HasPrefix(s.Name, "system.") {
			if n, err := db.Collection(s.Name).EstimatedDocumentCount(ctx); err == nil {
				e["count"] = n
			}
		}
		out = append(out, e)
	}
	return out, nil
}

func serverStatus(ctx context.Context, cl *mongo.Client) (any, error) {
	var s struct {
		Host        string  `bson:"host"`
		Version     string  `bson:"version"`
		Process     string  `bson:"process"`
		Uptime      float64 `bson:"uptime"`
		Connections struct {
			Current      int64 `bson:"current"`
			Available    int64 `bson:"available"`
			TotalCreated int64 `bson:"totalCreated"`
		} `bson:"connections"`
		Opcounters map[string]any `bson:"opcounters"`
		Mem        struct {
			Resident int64 `bson:"resident"`
			Virtual  int64 `bson:"virtual"`
		} `bson:"mem"`
		Repl *struct {
			SetName           string `bson:"setName"`
			IsWritablePrimary bool   `bson:"isWritablePrimary"`
			Secondary         bool   `bson:"secondary"`
			Primary           string `bson:"primary"`
		} `bson:"repl"`
		StorageEngine struct {
			Name string `bson:"name"`
		} `bson:"storageEngine"`
	}
	// Only the sections used here: the full status is large.
	cmd := bson.D{{Key: "serverStatus", Value: 1}, {Key: "metrics", Value: 0}, {Key: "locks", Value: 0}, {Key: "wiredTiger", Value: 0}, {Key: "tcmalloc", Value: 0}}
	if err := cl.Database("admin").RunCommand(ctx, cmd).Decode(&s); err != nil {
		return nil, err
	}
	out := map[string]any{
		"host": s.Host, "version": s.Version, "process": s.Process, "uptimeSeconds": s.Uptime,
		"connections":   map[string]any{"current": s.Connections.Current, "available": s.Connections.Available, "totalCreated": s.Connections.TotalCreated},
		"opcounters":    s.Opcounters,
		"memoryMB":      map[string]any{"resident": s.Mem.Resident, "virtual": s.Mem.Virtual},
		"storageEngine": s.StorageEngine.Name,
	}
	if s.Repl != nil {
		role := "other"
		switch {
		case s.Repl.IsWritablePrimary:
			role = "primary"
		case s.Repl.Secondary:
			role = "secondary"
		}
		out["replicaSet"] = map[string]any{"name": s.Repl.SetName, "role": role, "primary": s.Repl.Primary}
	}
	return out, nil
}

// drain reads up to limit documents as relaxed Extended JSON, stopping at
// MaxBytes.
func drain(ctx context.Context, cur *mongo.Cursor, limit int) (any, error) {
	defer cur.Close(context.Background()) //nolint:errcheck // read-only cursor
	docs := []json.RawMessage{}
	size, truncated := 0, false
	for cur.Next(ctx) {
		if len(docs) >= limit {
			truncated = true
			break
		}
		b, err := bson.MarshalExtJSON(cur.Current, false, false)
		if err != nil {
			return nil, err
		}
		if size+len(b) > MaxBytes {
			truncated = true
			break
		}
		size += len(b)
		docs = append(docs, b)
	}
	if err := cur.Err(); err != nil {
		return nil, err
	}
	return map[string]any{"documents": docs, "truncated": truncated}, nil
}

func checkDB(s string) error {
	if !dbRe.MatchString(s) {
		return fmt.Errorf("%q isn't a database name (letters, digits, _ and -)", s)
	}
	return nil
}

func checkTarget(p input) error {
	if err := checkDB(p.Database); err != nil {
		return err
	}
	if !collRe.MatchString(p.Collection) || strings.Contains(p.Collection, "..") {
		return fmt.Errorf("%q isn't a collection name", p.Collection)
	}
	if strings.HasPrefix(p.Collection, "system.") {
		return errors.New("system collections (users, roles, profile) aren't read here")
	}
	return nil
}

type findPlan struct {
	filter any
	opts   *options.FindOptionsBuilder
	limit  int64
}

// BuildFind checks a find's input and builds the filter and options.
func BuildFind(p input) (*findPlan, error) {
	if err := checkTarget(p); err != nil {
		return nil, err
	}
	limit, err := limitOf(p.Limit)
	if err != nil {
		return nil, err
	}
	if p.Skip < 0 || p.Skip > 100000 {
		return nil, errors.New("skip is 0 to 100000")
	}
	filter, err := Doc(p.Filter, "filter")
	if err != nil {
		return nil, err
	}
	o := options.Find().SetLimit(limit).SetBatchSize(int32(limit))
	if p.Skip > 0 {
		o.SetSkip(p.Skip)
	}
	if len(p.Projection) > 0 && string(p.Projection) != "null" {
		proj, err := Doc(p.Projection, "projection")
		if err != nil {
			return nil, err
		}
		o.SetProjection(proj)
	}
	if len(p.Sort) > 0 && string(p.Sort) != "null" {
		sort, err := Doc(p.Sort, "sort")
		if err != nil {
			return nil, err
		}
		o.SetSort(sort)
	}
	return &findPlan{filter: filter, opts: o, limit: limit}, nil
}

func limitOf(l *int64) (int64, error) {
	if l == nil {
		return 20, nil
	}
	if *l < 1 || *l > MaxDocs {
		return 0, fmt.Errorf("limit is 1 to %d", MaxDocs)
	}
	return *l, nil
}

// deniedOps run JavaScript on the server (or write, for the stages).
// Matched as keys anywhere in a filter, projection, sort or pipeline,
// including inside $expr, $lookup and $facet.
var deniedOps = map[string]string{
	"$where":         "$where (JavaScript)",
	"$function":      "$function (JavaScript)",
	"$accumulator":   "$accumulator (JavaScript)",
	"$code":          "JavaScript code",
	"$codewithscope": "JavaScript code",
	"$out":           "$out (it writes a collection)",
	"$merge":         "$merge (it writes a collection)",
	"$changestream":  "change streams (they don't end)",
}

// Check walks a decoded query (bson.D, bson.A, or the plain JSON forms
// map[string]any and []any) and refuses JavaScript (operators and BSON
// code values), writing stages, lookups into system collections or another
// database, and bounds its depth. Every element of a bson.D is looked at,
// duplicates included, since the server sees them all.
func Check(v any, depth int) error {
	if depth > maxDepth {
		return errors.New("the query is nested too deeply")
	}
	switch x := v.(type) {
	case bson.D:
		hasColl := false
		for _, e := range x {
			if e.Key == "coll" {
				hasColl = true
			}
		}
		for _, e := range x {
			if err := checkKey(e.Key, e.Value, hasColl); err != nil {
				return err
			}
			if err := Check(e.Value, depth+1); err != nil {
				return err
			}
		}
	case bson.M:
		_, hasColl := x["coll"]
		for k, val := range x {
			if err := checkKey(k, val, hasColl); err != nil {
				return err
			}
			if err := Check(val, depth+1); err != nil {
				return err
			}
		}
	case map[string]any:
		_, hasColl := x["coll"]
		for k, val := range x {
			if err := checkKey(k, val, hasColl); err != nil {
				return err
			}
			if err := Check(val, depth+1); err != nil {
				return err
			}
		}
	case bson.A:
		for _, e := range x {
			if err := Check(e, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range x {
			if err := Check(e, depth+1); err != nil {
				return err
			}
		}
	case bson.JavaScript, bson.CodeWithScope, *bson.CodeWithScope:
		return errors.New("JavaScript code isn't allowed here")
	}
	return nil
}

// checkKey refuses one key of a document: an operator that runs JavaScript
// or writes, a collection named as a string ($lookup's and $graphLookup's
// from, $unionWith's coll or its string form) in the system namespace, and
// a db next to a coll (another database).
func checkKey(k string, val any, hasColl bool) error {
	lk := strings.ToLower(k)
	if why, ok := deniedOps[lk]; ok {
		return fmt.Errorf("%s isn't allowed here", why)
	}
	switch lk {
	case "from", "coll", "$unionwith":
		if s, ok := val.(string); ok && systemColl(s) {
			return errors.New("system collections aren't read here")
		}
	case "db":
		if hasColl {
			return errors.New("reading another database from a pipeline isn't allowed here")
		}
	}
	return nil
}

// systemColl reports whether a collection name is in the system namespace
// (system.users, system.profile, …), in any case and with or without a
// database prefix.
func systemColl(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(s, "system.") || strings.Contains(s, ".system.")
}

// noDuplicateKeys refuses JSON with an object that has the same key twice
// (after unescaping): a JSON map keeps one of them, the server sees both.
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
			return err
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.obj && top.expKey {
			if k, ok := tok.(string); ok {
				if top.keys[k] {
					return fmt.Errorf("the key %q appears twice in one object", k)
				}
				top.keys[k] = true
				top.expKey = false
				continue
			}
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, &frame{obj: true, keys: map[string]bool{}, expKey: true})
				continue
			case '[':
				stack = append(stack, &frame{})
				continue
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
		}
		// A value ended: the enclosing object wants a key next.
		if len(stack) > 0 && stack[len(stack)-1].obj {
			stack[len(stack)-1].expKey = true
		}
	}
}

// Doc checks one MongoDB JSON object (Extended JSON, so {"$oid": …} and
// {"$date": …} work) and converts it to a BSON document. The check runs on
// the decoded BSON, exactly what is sent.
func Doc(raw json.RawMessage, what string) (bson.D, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return bson.D{}, nil
	}
	if len(raw) > maxInput {
		return nil, fmt.Errorf("the %s is too long", what)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("the %s isn't valid JSON: %w", what, err)
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, fmt.Errorf("the %s is an object, like {\"status\":\"failed\"}", what)
	}
	if err := noDuplicateKeys(raw); err != nil {
		return nil, fmt.Errorf("the %s: %w", what, err)
	}
	if err := Check(v, 0); err != nil {
		return nil, err
	}
	var d bson.D
	if err := bson.UnmarshalExtJSON(raw, false, &d); err != nil {
		return nil, fmt.Errorf("the %s isn't valid MongoDB JSON: %w", what, err)
	}
	if err := Check(d, 0); err != nil {
		return nil, err
	}
	return d, nil
}

// BuildPipeline checks a pipeline (each stage one $-operator) and adds a
// final $limit.
func BuildPipeline(p input) ([]bson.D, int64, error) {
	if err := checkTarget(p); err != nil {
		return nil, 0, err
	}
	limit, err := limitOf(p.Limit)
	if err != nil {
		return nil, 0, err
	}
	if len(p.Pipeline) > maxInput {
		return nil, 0, errors.New("the pipeline is too long")
	}
	var stages []json.RawMessage
	if err := json.Unmarshal(p.Pipeline, &stages); err != nil {
		return nil, 0, errors.New("the pipeline is a list of stages, like [{\"$match\":{…}}]")
	}
	if len(stages) > 50 {
		return nil, 0, errors.New("at most 50 stages")
	}
	out := make([]bson.D, 0, len(stages)+1)
	for i, s := range stages {
		d, err := Doc(s, fmt.Sprintf("stage %d", i+1))
		if err != nil {
			return nil, 0, err
		}
		if len(d) != 1 || !strings.HasPrefix(d[0].Key, "$") {
			return nil, 0, fmt.Errorf("stage %d has one operator, like {\"$match\":{…}}", i+1)
		}
		out = append(out, d)
	}
	out = append(out, bson.D{{Key: "$limit", Value: limit}})
	return out, limit, nil
}
