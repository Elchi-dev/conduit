package hub

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx"
	_ "modernc.org/sqlite"             // registers "sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// DB wraps the hub database. Queries are written with ? placeholders and
// rewritten to $1, $2, … for PostgreSQL.
type DB struct {
	*sql.DB
	postgres bool
}

// OpenDB opens a "postgres://…" URL with pgx, anything else as a SQLite file.
func OpenDB(ctx context.Context, url string) (*DB, error) {
	var db *sql.DB
	var err error
	pg := strings.HasPrefix(url, "postgres://") || strings.HasPrefix(url, "postgresql://")
	if pg {
		db, err = sql.Open("pgx", url)
	} else {
		dsn := "file:" + url + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
		if url == ":memory:" {
			dsn = "file::memory:?cache=shared"
		}
		db, err = sql.Open("sqlite", dsn)
		if err == nil {
			db.SetMaxOpenConns(1)
		}
	}
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("database: %w", err)
	}
	d := &DB{DB: db, postgres: pg}
	if err := d.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return d, nil
}

func (d *DB) rebind(q string) string {
	if !d.postgres {
		return q
	}
	var b strings.Builder
	n := 0
	for _, r := range q {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Exec runs a statement with ? placeholders.
func (d *DB) Exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return d.ExecContext(ctx, d.rebind(q), args...)
}

// Query runs a query with ? placeholders.
func (d *DB) Query(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return d.QueryContext(ctx, d.rebind(q), args...)
}

// Row runs a single-row query with ? placeholders.
func (d *DB) Row(ctx context.Context, q string, args ...any) *sql.Row {
	return d.QueryRowContext(ctx, d.rebind(q), args...)
}

func (d *DB) migrate(ctx context.Context) error {
	if _, err := d.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS hub_schema (name TEXT PRIMARY KEY)`); err != nil {
		return err
	}
	names, _ := fs.Glob(migrations, "migrations/*.sql")
	sort.Strings(names)
	for _, name := range names {
		var n int
		if err := d.Row(ctx, `SELECT COUNT(*) FROM hub_schema WHERE name = ?`, name).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		body, _ := migrations.ReadFile(name)
		tx, err := d.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, stmt := range strings.Split(string(body), ";\n") {
			lines := []string{}
			for _, l := range strings.Split(stmt, "\n") {
				if !strings.HasPrefix(strings.TrimSpace(l), "--") {
					lines = append(lines, l)
				}
			}
			if s := strings.TrimSpace(strings.Join(lines, "\n")); s != "" {
				if _, err := tx.ExecContext(ctx, s); err != nil {
					tx.Rollback()
					return fmt.Errorf("%s: %w", name, err)
				}
			}
		}
		if _, err := tx.ExecContext(ctx, d.rebind(`INSERT INTO hub_schema (name) VALUES (?)`), name); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
