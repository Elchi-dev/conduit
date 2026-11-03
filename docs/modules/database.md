# Databases

Look into a PostgreSQL or MySQL/MariaDB database: tables and their size,
how big the database is, who's connected, which queries are running, and
answers to read-only queries. It never changes data.

**Setup.** Kind, host, port, database, a user and its password (stored in
the vault). Use a user that can only read: in PostgreSQL the built-in
`pg_read_all_data` role (and `pg_read_all_stats` to see other sessions'
queries); in MySQL `GRANT SELECT, PROCESS ON app.* TO …` (PROCESS shows
other sessions). TLS: `verify` (the default) checks the server certificate,
`require` encrypts without checking, `disable` only makes sense on
localhost (the default there).

| Action | Risk | Notes |
| --- | --- | --- |
| `tables` | read | Schema, name and size of each table (up to 1000) |
| `stats` | read | Database size, connections, the longest running query in seconds |
| `active` | read | Running queries, longest first, with their process id |
| `query` | read (sensitive) | One `SELECT`, `WITH`, `SHOW` or `EXPLAIN`, in a read-only transaction, at most 10 seconds and 1000 rows. Results can hold personal data or secrets, so they stay out of the audit log |
| `kill` | destructive | Stops a running query by its process id (PostgreSQL `pg_cancel_backend`, MySQL `KILL QUERY`); preview first |

**How "read-only" is enforced.** Three layers: the query must be a single
statement starting with a reading keyword (comments and quoted text are
ignored when checking, and file and sleep functions such as
`pg_read_file`, `INTO OUTFILE` and `pg_sleep` are refused); it runs inside a
read-only transaction (`BEGIN READ ONLY` / `START TRANSACTION READ ONLY`),
so the server itself refuses writes that look like reads, such as a
`DELETE` inside a `WITH`; and the transaction is always rolled back. A
read-only database user is still the best protection.

Tests: the query path runs against SQLite in every build, and against real
PostgreSQL 16 and MySQL 8.4 in CI (`go test -tags dbintegration`).
