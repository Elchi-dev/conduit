// Package database looks into PostgreSQL and MySQL/MariaDB databases:
// tables, size, connections, running queries, and read-only queries. It
// never writes: every query runs in a read-only transaction with a time
// limit and a row cap, and only one statement is accepted.
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one database connection.
type Config struct {
	Kind     string `json:"kind"` // postgres or mysql
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"` // secret://
	Database string `json:"database"`
	// TLS: "disable", "require" (encrypted, certificate not checked) or
	// "verify" (encrypted and the certificate checked). Default "verify"
	// except on localhost, where it's "disable".
	TLS string `json:"tls"`
}

// Limits for queries.
const (
	QueryTimeout = 10 * time.Second
	MaxRows      = 1000
)

// dialect holds the SQL that differs between database kinds.
type dialect struct {
	driver   string
	readOnly string // run first inside a read-only transaction
	timeout  string // run next: limits the statement's time
	tables   string
	stats    string // returns one row: size_bytes, connections, longest_seconds
	active   string // pid, user, state, seconds, query
	kill     func(id int64) (string, []any)
}

var dialects = map[string]dialect{
	"postgres": {
		driver:   "pgx",
		readOnly: `SET TRANSACTION READ ONLY`,
		timeout:  fmt.Sprintf(`SET LOCAL statement_timeout = %d`, QueryTimeout.Milliseconds()),
		tables: `SELECT table_schema, table_name, COALESCE(pg_total_relation_size(quote_ident(table_schema)||'.'||quote_ident(table_name)), 0)
			FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') AND table_type = 'BASE TABLE' ORDER BY 1, 2 LIMIT 1000`,
		stats: `SELECT pg_database_size(current_database()),
			(SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()),
			COALESCE((SELECT EXTRACT(EPOCH FROM max(now() - query_start)) FROM pg_stat_activity WHERE state = 'active' AND pid <> pg_backend_pid()), 0)`,
		active: `SELECT pid, COALESCE(usename, ''), COALESCE(state, ''), COALESCE(EXTRACT(EPOCH FROM now() - query_start), 0), COALESCE(left(query, 500), '')
			FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid() AND state <> 'idle' ORDER BY 4 DESC LIMIT 50`,
		kill: func(id int64) (string, []any) { return `SELECT pg_cancel_backend($1)`, []any{id} },
	},
	"mysql": {
		driver:   "mysql",
		readOnly: ``, // START TRANSACTION READ ONLY via TxOptions
		timeout:  fmt.Sprintf(`SET SESSION MAX_EXECUTION_TIME = %d`, QueryTimeout.Milliseconds()),
		tables: `SELECT table_schema, table_name, COALESCE(data_length + index_length, 0)
			FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' ORDER BY 1, 2 LIMIT 1000`,
		stats: `SELECT (SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables WHERE table_schema = DATABASE()),
			(SELECT COUNT(*) FROM information_schema.processlist),
			(SELECT COALESCE(MAX(time), 0) FROM information_schema.processlist WHERE command = 'Query' AND id <> CONNECTION_ID())`,
		active: `SELECT id, COALESCE(user, ''), COALESCE(command, ''), COALESCE(time, 0), COALESCE(LEFT(info, 500), '')
			FROM information_schema.processlist WHERE command <> 'Sleep' AND id <> CONNECTION_ID() ORDER BY 4 DESC LIMIT 50`,
		kill: func(id int64) (string, []any) { return "KILL QUERY " + strconv.FormatInt(id, 10), nil },
	},
}

type conn struct {
	cfg  Config
	host sdk.Host
	d    dialect
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Open opens a database; tests replace it.
	Open func(driver, dsn string) (*sql.DB, error)
	// dialects can be replaced in tests.
	dialects map[string]dialect
}

// New returns the database module.
func New() *Module { return &Module{Open: sql.Open, dialects: dialects} }

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "database", Name: "Databases", Version: "0.1.0", Category: "Infrastructure", Icon: "database",
		Description: "Look into PostgreSQL and MySQL/MariaDB: tables, size, running queries, and read-only queries.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["kind","host","user","password","database"],"properties":{
			"kind":{"type":"string","enum":["postgres","mysql"],"description":"MySQL also covers MariaDB"},
			"host":{"type":"string"},
			"port":{"type":"integer","description":"Default 5432 for PostgreSQL, 3306 for MySQL"},
			"user":{"type":"string","description":"Best a user that can only read"},
			"password":{"type":"string","x-secret":true},
			"database":{"type":"string"},
			"tls":{"type":"string","enum":["verify","require","disable"],"description":"verify checks the certificate; the default, except on localhost"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "tables", Title: "Tables", Description: "Tables and their size.", Risk: sdk.RiskRead},
			{Name: "stats", Title: "Size and load", Description: "Database size, connections and the longest running query.", Risk: sdk.RiskRead},
			{Name: "active", Title: "Running queries", Description: "Queries running now, longest first.", Risk: sdk.RiskRead},
			{Name: "query", Title: "Run a read-only query", Description: "One SELECT (or WITH, SHOW, EXPLAIN) in a read-only transaction, at most 10 seconds and 1000 rows.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["sql"],"properties":{"sql":{"type":"string","x-multiline":true}}}`)},
			{Name: "kill", Title: "Stop a running query", Description: "By its process id from Running queries.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"integer","minimum":1}}}`)},
		},
	}
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_.$\-]{1,128}$`)

// DSN builds the driver's connection string.
func DSN(c Config, password string) (string, error) {
	tls := c.TLS
	local := c.Host == "localhost" || c.Host == "127.0.0.1" || c.Host == "::1"
	if tls == "" {
		tls = "verify"
		if local {
			tls = "disable"
		}
	}
	switch c.Kind {
	case "postgres":
		mode := map[string]string{"verify": "verify-full", "require": "require", "disable": "disable"}[tls]
		if mode == "" {
			return "", errors.New("tls is verify, require or disable")
		}
		port := c.Port
		if port == 0 {
			port = 5432
		}
		u := url.URL{Scheme: "postgres", User: url.UserPassword(c.User, password), Host: net.JoinHostPort(c.Host, strconv.Itoa(port)), Path: "/" + c.Database}
		q := url.Values{"sslmode": {mode}, "application_name": {"conduit"}, "connect_timeout": {"10"}}
		u.RawQuery = q.Encode()
		return u.String(), nil
	case "mysql":
		mc := mysql.NewConfig()
		mc.User, mc.Passwd, mc.DBName = c.User, password, c.Database
		port := c.Port
		if port == 0 {
			port = 3306
		}
		mc.Net, mc.Addr = "tcp", net.JoinHostPort(c.Host, strconv.Itoa(port))
		switch tls {
		case "verify":
			mc.TLSConfig = "true"
		case "require":
			mc.TLSConfig = "skip-verify"
		case "disable":
			mc.TLSConfig = "false"
		default:
			return "", errors.New("tls is verify, require or disable")
		}
		mc.Timeout, mc.ReadTimeout = 10*time.Second, QueryTimeout+5*time.Second
		mc.ParseTime = true
		mc.MultiStatements = false
		mc.InterpolateParams = false
		return mc.FormatDSN(), nil
	}
	return "", errors.New("kind is postgres or mysql")
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	d, ok := m.dialects[c.Kind]
	if !ok {
		return errors.New("kind is postgres or mysql")
	}
	if c.Host == "" || strings.ContainsAny(c.Host, "/@?# ") {
		return errors.New("the host is a name or address, like db.internal")
	}
	if !nameRe.MatchString(c.User) || !nameRe.MatchString(c.Database) {
		return errors.New("user and database are plain names")
	}
	if c.Port < 0 || c.Port > 65535 {
		return errors.New("the port is 1 to 65535")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	if _, err := DSN(c, "x"); err != nil {
		return err
	}
	m.set.Put(id, &conn{cfg: c, host: h, d: d})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (m *Module) open(ctx context.Context, c *conn) (*sql.DB, error) {
	pw, err := c.host.Secret(ctx, c.cfg.Password)
	if err != nil {
		return nil, err
	}
	dsn, err := DSN(c.cfg, pw)
	if err != nil {
		return nil, err
	}
	db, err := m.Open(c.d.driver, dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetConnMaxLifetime(time.Minute)
	return db, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	db, err := m.open(ctx, c)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: c.cfg.Kind + " " + c.cfg.Database}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		SQL string `json:"sql"`
		ID  int64  `json:"id"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "tables", "stats", "active", "query", "kill":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	if call.Action == "query" {
		if err := CheckStatement(p.SQL); err != nil {
			return sdk.Result{}, err
		}
	}
	if call.Action == "kill" {
		if p.ID <= 0 {
			return sdk.Result{}, errors.New("give the id of a running query (from Running queries)")
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Stop query %d on %s", p.ID, c.cfg.Database),
				Changes: []sdk.Change{{Target: fmt.Sprintf("query %d", p.ID), Op: "stop"}}}}, nil
		}
	}
	db, err := m.open(ctx, c)
	if err != nil {
		return sdk.Result{}, err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	switch call.Action {
	case "tables":
		rows, err := db.QueryContext(ctx, c.d.tables)
		if err != nil {
			return sdk.Result{}, err
		}
		defer rows.Close()
		type tbl struct {
			Schema string `json:"schema"`
			Name   string `json:"name"`
			Bytes  int64  `json:"bytes"`
		}
		out := []tbl{}
		for rows.Next() {
			var t tbl
			if err := rows.Scan(&t.Schema, &t.Name, &t.Bytes); err != nil {
				return sdk.Result{}, err
			}
			out = append(out, t)
		}
		return sdk.JSON(out)
	case "stats":
		var size, conns int64
		var longest float64
		if err := db.QueryRowContext(ctx, c.d.stats).Scan(&size, &conns, &longest); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"sizeBytes": size, "connections": conns, "longestQuerySeconds": longest})
	case "active":
		rows, err := db.QueryContext(ctx, c.d.active)
		if err != nil {
			return sdk.Result{}, err
		}
		defer rows.Close()
		type q struct {
			ID      int64   `json:"id"`
			User    string  `json:"user"`
			State   string  `json:"state"`
			Seconds float64 `json:"seconds"`
			Query   string  `json:"query"`
		}
		out := []q{}
		for rows.Next() {
			var x q
			if err := rows.Scan(&x.ID, &x.User, &x.State, &x.Seconds, &x.Query); err != nil {
				return sdk.Result{}, err
			}
			out = append(out, x)
		}
		return sdk.JSON(out)
	case "query":
		return m.query(ctx, db, c, p.SQL)
	case "kill":
		q, args := c.d.kill(p.ID)
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"stopped": p.ID})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// query runs one statement in a read-only transaction that is always rolled
// back.
func (m *Module) query(ctx context.Context, db *sql.DB, c *conn, stmt string) (sdk.Result, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return sdk.Result{}, err
	}
	defer tx.Rollback() //nolint:errcheck // read-only; nothing to keep
	if c.d.readOnly != "" {
		if _, err := tx.ExecContext(ctx, c.d.readOnly); err != nil {
			return sdk.Result{}, err
		}
	}
	if c.d.timeout != "" {
		if _, err := tx.ExecContext(ctx, c.d.timeout); err != nil {
			return sdk.Result{}, err
		}
	}
	rows, err := tx.QueryContext(ctx, stmt)
	if err != nil {
		return sdk.Result{}, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return sdk.Result{}, err
	}
	out := [][]any{}
	truncated := false
	for rows.Next() {
		if len(out) >= MaxRows {
			truncated = true
			break
		}
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return sdk.Result{}, err
		}
		for i, v := range vals {
			switch x := v.(type) {
			case []byte:
				vals[i] = string(x)
			case time.Time:
				vals[i] = x.UTC().Format(time.RFC3339Nano)
			}
		}
		out = append(out, vals)
	}
	if err := rows.Err(); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"columns": cols, "rows": out, "truncated": truncated})
}

var firstWord = regexp.MustCompile(`^[A-Za-z]+`)

// CheckStatement accepts exactly one statement that starts with a reading
// keyword. The read-only transaction is what really prevents writes; this
// check gives a clear message first and refuses multiple statements, which
// some drivers would run one after another.
func CheckStatement(q string) error {
	s := stripSQL(q)
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "; \t\r\n")
	if s == "" {
		return errors.New("enter a query")
	}
	if strings.Contains(s, ";") {
		return errors.New("one statement at a time")
	}
	w := strings.ToUpper(firstWord.FindString(s))
	switch w {
	case "SELECT", "WITH", "SHOW", "EXPLAIN", "DESCRIBE", "DESC", "VALUES", "TABLE":
	default:
		return fmt.Errorf("only reading queries (SELECT, WITH, SHOW, EXPLAIN) run here, not %s", w)
	}
	norm := spaces.ReplaceAllString(s, " ")
	for _, d := range deniedSyntax {
		if d.re.MatchString(norm) {
			return fmt.Errorf("%s isn't allowed here", d.name)
		}
	}
	// String literals and quoted identifiers are blanked above, and PostgreSQL
	// accepts a quoted function name ("pg_sleep"(1)) or one spelled with
	// Unicode escapes (U&"..."), so the function names are also looked for in
	// the raw text. A false positive (the name inside a string) only costs a
	// rephrased query.
	if m := deniedFuncs.FindStringSubmatch(q); m != nil {
		return fmt.Errorf("%s isn't allowed here", strings.ToLower(m[2]))
	}
	if unicodeEscape.MatchString(q) {
		return errors.New("U& escaped names and strings aren't allowed here")
	}
	return nil
}

var (
	spaces = regexp.MustCompile(`\s+`)

	// deniedSyntax is matched against the statement with comments and quoted
	// text removed and whitespace collapsed.
	deniedSyntax = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"INTO OUTFILE", regexp.MustCompile(`(?i)\bINTO\s*(OUT|DUMP)FILE\b`)},
		{"COPY", regexp.MustCompile(`(?i)\bCOPY\b`)},
		{"SLEEP", regexp.MustCompile(`(?i)\bSLEEP\s*\(`)},
		{"BENCHMARK", regexp.MustCompile(`(?i)\bBENCHMARK\s*\(`)},
		{"GET_LOCK", regexp.MustCompile(`(?i)\bGET_LOCK\s*\(`)},
	}

	// deniedFuncs are server functions that read or write files, reach other
	// servers, change settings, signal other sessions, or stall: none of them
	// are stopped by a read-only transaction. Matched anywhere in the raw text.
	deniedFuncs = regexp.MustCompile(`(?i)(^|[^a-z0-9_$])(` + strings.Join([]string{
		`pg_terminate_backend`, `pg_cancel_backend`, `pg_reload_conf`, `pg_rotate_logfile`,
		`pg_promote`, `pg_switch_wal`, `pg_create_restore_point`, `pg_logdir_ls`,
		`set_config`,
		`query_to_xml\w*`, `query_to_xmlschema`, `cursor_to_xml\w*`,
		`lo_\w+`,
		`pg_ls_\w+`, `pg_stat_file`, `pg_read_file`, `pg_read_binary_file`, `pg_file_\w+`,
		`dblink\w*`,
		`pg_sleep\w*`, `sleep`, `benchmark`, `load_file`, `sys_exec`, `sys_eval`,
	}, "|") + `)($|[^a-z0-9_$])`)

	unicodeEscape = regexp.MustCompile(`(?i)(^|[^a-z0-9_])U&["']`)
)

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
				if q[i] == '\\' && quote != '"' {
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
			b.WriteString("''")
		case ch == '$' && i+1 < len(q) && (q[i+1] == '$' || isIdentStart(q[i+1])):
			// PostgreSQL dollar quoting: $$…$$ or $tag$…$tag$.
			end := strings.IndexByte(q[i+1:], '$')
			if end < 0 {
				b.WriteByte(ch)
				continue
			}
			tag := q[i : i+end+2]
			if strings.ContainsAny(tag[1:len(tag)-1], " \t\n;") {
				b.WriteByte(ch)
				continue
			}
			close := strings.Index(q[i+len(tag):], tag)
			if close < 0 {
				return b.String() + " ;unterminated"
			}
			i += len(tag) + close + len(tag) - 1
			b.WriteString("''")
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
