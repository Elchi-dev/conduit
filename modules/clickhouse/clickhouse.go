// Package clickhouse looks into a ClickHouse server through its HTTP
// interface: databases, tables with rows and size, read-only queries (with
// readonly=1 set on every request, so the server itself refuses writes) and
// the slowest recent queries from system.query_log.
package clickhouse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one ClickHouse server.
type Config struct {
	URL                string `json:"url"`      // e.g. https://ch.example.com:8443
	Username           string `json:"username"` // default "default"
	Password           string `json:"password"` // secret://, optional
	Database           string `json:"database"` // default database for queries
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

// Limits for queries.
const (
	QueryTimeout = 10 * time.Second
	MaxRows      = 1000
	MaxBytes     = 8 << 20
	maxQuery     = 64 << 10
	// MaxMemory caps the memory one query may use on the server, so a
	// read (a huge GROUP BY or JOIN) can't exhaust it.
	MaxMemory = 2 << 30
)

type conn struct {
	cfg  Config
	base string
	http *http.Client
	host sdk.Host
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the ClickHouse module.
func New() *Module { return &Module{} }

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "clickhouse", Name: "ClickHouse", Version: "0.1.0", Category: "Infrastructure", Icon: "database",
		Description: "ClickHouse over HTTP: databases, tables with rows and size, read-only queries, the slowest recent queries.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"The HTTP interface, e.g. https://ch.example.com:8443 or http://localhost:8123"},
			"username":{"type":"string","default":"default","description":"Best a user granted only SELECT (and SHOW)"},
			"password":{"type":"string","x-secret":true},
			"database":{"type":"string","description":"Default database for queries"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "databases", Title: "Databases", Description: "Databases and their engines.", Risk: sdk.RiskRead},
			{Name: "tables", Title: "Tables", Description: "Tables with engine, rows and bytes (system databases left out), at most 1000.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"database":{"type":"string","description":"Only this database"}}}`)},
			{Name: "query", Title: "Run a read-only query", Description: "One SELECT, WITH, SHOW, DESCRIBE, EXISTS or EXPLAIN, run with readonly=1 (the server refuses writes), at most 10 seconds and 1000 rows. Table functions that reach files or other servers are refused. Results can hold personal data, so they stay out of the audit log.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["sql"],"properties":{"sql":{"type":"string","x-multiline":true},"database":{"type":"string"}}}`)},
			{Name: "slow_queries", Title: "Slow queries", Description: "The slowest queries that finished recently, from system.query_log: duration, user, rows and bytes read, memory and the start of the query text (which can hold data, so it stays out of the audit log).", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"hours":{"type":"integer","minimum":1,"maximum":168,"default":24},"minMs":{"type":"integer","minimum":0,"default":1000},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
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
		return errors.New("the url is like https://ch.example.com:8443")
	}
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	if c.Username == "" {
		c.Username = "default"
	}
	if !nameRe.MatchString(c.Username) {
		return errors.New("the username is a plain name")
	}
	if c.Database != "" && !nameRe.MatchString(c.Database) {
		return errors.New("the database is a plain name")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		client = sdk.HTTPClient(h, QueryTimeout+20*time.Second)
		client.Transport.(*http.Transport).TLSClientConfig = tc
	}
	// The credentials are custom headers, which Go would forward on a
	// redirect to another host.
	m.set.Put(id, &conn{cfg: c, base: u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/"), http: rest.SameHostOnly(client), host: h})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Settings returns the query string sent with every query: limits first,
// readonly=1 last, so the server refuses anything but reads whatever the
// statement says.
func Settings(database string, params map[string]string) string {
	q := url.Values{}
	if database != "" {
		q.Set("database", database)
	}
	q.Set("default_format", "JSONCompact")
	q.Set("max_execution_time", strconv.Itoa(int(QueryTimeout.Seconds())))
	q.Set("max_result_rows", strconv.Itoa(MaxRows))
	q.Set("max_result_bytes", strconv.Itoa(MaxBytes))
	q.Set("max_memory_usage", strconv.Itoa(MaxMemory))
	q.Set("result_overflow_mode", "break")
	q.Set("wait_end_of_query", "1")
	for k, v := range params {
		q.Set("param_"+k, v)
	}
	return q.Encode() + "&readonly=1"
}

type result struct {
	Meta []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"meta"`
	Data       [][]any `json:"data"`
	Rows       int     `json:"rows"`
	Statistics struct {
		Elapsed   float64 `json:"elapsed"`
		RowsRead  int64   `json:"rows_read"`
		BytesRead int64   `json:"bytes_read"`
	} `json:"statistics"`
	RowsBeforeLimit *int64 `json:"rows_before_limit_at_least"`
}

var codeRe = regexp.MustCompile(`Code: (\d+)\. DB::Exception: ([^\n]*?)(\(version|\n|$)`)

// run posts one statement and decodes the JSONCompact answer.
func (c *conn) run(ctx context.Context, stmt, database string, params map[string]string) (*result, error) {
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout+15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/?"+Settings(database, params), strings.NewReader(stmt))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Conduit")
	req.Header.Set("X-ClickHouse-User", c.cfg.Username)
	if c.cfg.Password != "" {
		pw, err := c.host.Secret(ctx, c.cfg.Password)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-ClickHouse-Key", pw)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, rest.TransportError(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, MaxBytes+(1<<20)))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 || res.Header.Get("X-ClickHouse-Exception-Code") != "" {
		status := res.StatusCode
		if status < 300 {
			status = http.StatusInternalServerError
		}
		return nil, &rest.Error{Status: status, Message: serverError(res.Status, raw)}
	}
	var r result
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, errors.New("unexpected answer from ClickHouse (the result may be over 8 MB)")
	}
	return &r, nil
}

// serverError pulls ClickHouse's message out of its plain-text error, with
// anything that looks like a credential redacted and the length capped.
func serverError(status string, raw []byte) string {
	s := string(raw)
	if m := codeRe.FindStringSubmatch(s); m != nil {
		msg := strings.TrimSpace(m[2])
		if len(msg) > 400 {
			msg = msg[:400] + "…"
		}
		return "ClickHouse error " + m[1] + ": " + rest.Redact(msg)
	}
	return "ClickHouse answered " + status
}

func friendly(err error) error {
	var e *rest.Error
	if errors.As(err, &e) && (strings.Contains(e.Message, "error 516:") || strings.Contains(e.Message, "error 194:")) {
		return &rest.Error{Status: e.Status, Message: "ClickHouse refused the username or password"}
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	r, err := c.run(ctx, "SELECT version(), uptime()", "", nil)
	if err != nil {
		return sdk.Health{Status: "down", Message: friendly(err).Error()}
	}
	if len(r.Data) != 1 || len(r.Data[0]) != 2 {
		return sdk.Health{Status: "down", Message: "unexpected answer from ClickHouse"}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("ClickHouse %v, up %vs", r.Data[0][0], r.Data[0][1])}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		SQL      string `json:"sql"`
		Database string `json:"database"`
		Hours    *int   `json:"hours"`
		MinMs    *int   `json:"minMs"`
		Limit    *int   `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if p.Database != "" && !nameRe.MatchString(p.Database) {
		return sdk.Result{}, fmt.Errorf("%q isn't a database name", p.Database)
	}
	switch call.Action {
	case "databases":
		r, err := c.run(ctx, `SELECT name, engine FROM system.databases ORDER BY name LIMIT 1000`, "", nil)
		if err != nil {
			return sdk.Result{}, friendly(err)
		}
		out := []map[string]any{}
		for _, row := range r.Data {
			if len(row) == 2 {
				out = append(out, map[string]any{"name": row[0], "engine": row[1]})
			}
		}
		return sdk.JSON(out)
	case "tables":
		q := `SELECT database, name, engine, total_rows, total_bytes FROM system.tables
			WHERE database NOT IN ('system', 'INFORMATION_SCHEMA', 'information_schema') AND NOT is_temporary`
		params := map[string]string{}
		if p.Database != "" {
			q += ` AND database = {db:String}`
			params["db"] = p.Database
		}
		r, err := c.run(ctx, q+` ORDER BY database, name LIMIT 1000`, "", params)
		if err != nil {
			return sdk.Result{}, friendly(err)
		}
		out := []map[string]any{}
		for _, row := range r.Data {
			if len(row) == 5 {
				out = append(out, map[string]any{"database": row[0], "name": row[1], "engine": row[2], "rows": row[3], "bytes": row[4]})
			}
		}
		return sdk.JSON(out)
	case "query":
		if err := CheckStatement(p.SQL); err != nil {
			return sdk.Result{}, err
		}
		db := p.Database
		if db == "" {
			db = c.cfg.Database
		}
		r, err := c.run(ctx, p.SQL, db, nil)
		if err != nil {
			return sdk.Result{}, friendly(err)
		}
		cols := make([]map[string]string, 0, len(r.Meta))
		for _, m := range r.Meta {
			cols = append(cols, map[string]string{"name": m.Name, "type": m.Type})
		}
		rows := r.Data
		truncated := false
		if len(rows) > MaxRows {
			rows, truncated = rows[:MaxRows], true
		}
		if r.RowsBeforeLimit != nil && *r.RowsBeforeLimit > int64(len(rows)) && len(rows) >= MaxRows {
			truncated = true
		}
		if rows == nil {
			rows = [][]any{}
		}
		return sdk.JSON(map[string]any{"columns": cols, "rows": rows, "truncated": truncated,
			"elapsedSeconds": r.Statistics.Elapsed, "rowsRead": r.Statistics.RowsRead, "bytesRead": r.Statistics.BytesRead})
	case "slow_queries":
		hours, minMs, limit := intOr(p.Hours, 24), intOr(p.MinMs, 1000), intOr(p.Limit, 20)
		if hours < 1 || hours > 168 || minMs < 0 || minMs > 86_400_000 || limit < 1 || limit > 100 {
			return sdk.Result{}, errors.New("hours is 1 to 168, minMs 0 or more, limit 1 to 100")
		}
		q := `SELECT event_time, query_duration_ms, user, current_database, read_rows, read_bytes, result_rows, memory_usage, substring(query, 1, 500)
			FROM system.query_log
			WHERE type = 'QueryFinish' AND event_time > now() - toIntervalHour({hours:UInt32}) AND query_duration_ms >= {min:UInt64}
			ORDER BY query_duration_ms DESC LIMIT ` + strconv.Itoa(limit)
		r, err := c.run(ctx, q, "", map[string]string{"hours": strconv.Itoa(hours), "min": strconv.Itoa(minMs)})
		if err != nil {
			return sdk.Result{}, friendly(err)
		}
		out := []map[string]any{}
		for _, row := range r.Data {
			if len(row) == 9 {
				out = append(out, map[string]any{"time": row[0], "durationMs": row[1], "user": row[2], "database": row[3], "readRows": row[4], "readBytes": row[5],
					"resultRows": row[6], "memoryBytes": row[7], "query": row[8]})
			}
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func intOr(p *int, d int) int {
	if p == nil {
		return d
	}
	return *p
}

var (
	firstWord = regexp.MustCompile(`^[A-Za-z]+`)
	spaces    = regexp.MustCompile(`\s+`)

	// deniedSyntax is matched against the statement with comments and quoted
	// text removed and whitespace collapsed.
	deniedSyntax = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"INSERT", regexp.MustCompile(`(?i)\bINSERT\s+INTO\b`)},
		{"changing the schema or access", regexp.MustCompile(`(?i)\b(ALTER|DROP|TRUNCATE|CREATE|RENAME|ATTACH|DETACH|OPTIMIZE|EXCHANGE|UNDROP|GRANT|REVOKE)\s+(TEMPORARY\s+)?(TABLE|TABLES|DATABASE|DICTIONARY|VIEW|MATERIALIZED|LIVE|USER|ROLE|QUOTA|POLICY|ROW|SETTINGS|FUNCTION|NAMED|ALL|SELECT|INSERT)\b`)},
		{"INTO OUTFILE", regexp.MustCompile(`(?i)\bINTO\s+OUTFILE\b`)},
		{"FORMAT (results always come back as JSON)", regexp.MustCompile(`(?i)\bFORMAT\s+[A-Za-z]`)},
		{"SETTINGS", regexp.MustCompile(`(?i)\bSETTINGS\s+[A-Za-z_][A-Za-z0-9_]*\s*=`)},
	}

	// deniedFuncs are table functions and functions that read files, reach
	// other servers or run programs, or stall: readonly=1 doesn't stop all
	// of them. Matched anywhere in the raw text, before a "(".
	deniedFuncs = regexp.MustCompile(`(?i)(^|[^a-z0-9_])(` + strings.Join([]string{
		`url`, `urlCluster`, `s3`, `s3Cluster`, `gcs`, `oss`, `cosn`, `azureBlobStorage\w*`, `hdfs\w*`,
		`file`, `fileCluster`, `remote`, `remoteSecure`, `mysql`, `postgresql`, `mongodb`, `redis`, `sqlite`,
		`jdbc`, `odbc`, `executable\w*`, `input`, `iceberg\w*`, `deltaLake\w*`, `hudi\w*`, `paimon\w*`,
		`ytsaurus\w*`, `prometheusQuery\w*`, `arrowFlight\w*`,
		`sleep`, `sleepEachRow`,
	}, "|") + `)\s*\(`)
)

// CheckStatement accepts exactly one statement that starts with a reading
// keyword. readonly=1 is what really prevents writes; this check gives a
// clear message first, refuses multiple statements, and refuses table
// functions that reach outside the server.
func CheckStatement(q string) error {
	if len(q) > maxQuery {
		return errors.New("the query is too long")
	}
	s := strings.TrimSpace(stripSQL(q))
	s = strings.TrimRight(s, "; \t\r\n")
	if s == "" {
		return errors.New("enter a query")
	}
	if strings.Contains(s, ";") {
		return errors.New("one statement at a time")
	}
	w := strings.ToUpper(firstWord.FindString(s))
	switch w {
	case "SELECT", "WITH", "SHOW", "DESCRIBE", "DESC", "EXPLAIN", "EXISTS":
	default:
		return fmt.Errorf("only reading queries (SELECT, WITH, SHOW, DESCRIBE, EXPLAIN) run here, not %s", w)
	}
	norm := spaces.ReplaceAllString(s, " ")
	for _, d := range deniedSyntax {
		if d.re.MatchString(norm) {
			return fmt.Errorf("%s isn't allowed here", d.name)
		}
	}
	// Backquoted names are blanked above, and ClickHouse accepts `url`(…),
	// so the names are also looked for in the raw text; a false positive
	// (the name inside a string) only costs a rephrased query.
	for _, t := range []string{s, strings.ReplaceAll(strings.ReplaceAll(q, "`", ""), `"`, "")} {
		if m := deniedFuncs.FindStringSubmatch(t); m != nil {
			return fmt.Errorf("%s isn't allowed here", m[2])
		}
	}
	return nil
}

// stripSQL removes comments and the contents of quoted strings and
// identifiers, so keywords and semicolons inside them don't count.
func stripSQL(q string) string {
	var b strings.Builder
	for i := 0; i < len(q); i++ {
		ch := q[i]
		switch {
		case ch == '-' && i+1 < len(q) && q[i+1] == '-', ch == '#':
			for i < len(q) && q[i] != '\n' {
				i++
			}
			b.WriteByte(' ')
		case ch == '/' && i+1 < len(q) && q[i+1] == '*':
			end := strings.Index(q[i+2:], "*/")
			if end < 0 {
				return b.String() + " ;unterminated"
			}
			i += end + 3
			b.WriteByte(' ')
		case ch == '\'' || ch == '"' || ch == '`':
			quote := ch
			i++
			for i < len(q) {
				if q[i] == '\\' {
					i += 2
					continue
				}
				if q[i] == quote {
					if i+1 < len(q) && q[i+1] == quote {
						i += 2
						continue
					}
					break
				}
				i++
			}
			if i >= len(q) {
				return b.String() + " ;unterminated"
			}
			if quote == '\'' {
				b.WriteString("''")
			} else {
				b.WriteString("x")
			}
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}
