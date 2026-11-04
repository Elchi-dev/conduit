# ClickHouse

A ClickHouse server through its HTTP interface: databases, tables with rows
and size, read-only queries, and the slowest recent queries. It never
changes data.

**Setup.** Enter the HTTP interface's `url` (`http://localhost:8123`, or
`https://ch.example.com:8443` with TLS), a `username` (`default` when
empty) and its `password` (stored in the vault), and optionally the
`database` queries run in. For a self-signed certificate, enter its SHA-256
`fingerprint`.

Use a user that can only read:
`GRANT SELECT, SHOW ON app.* TO conduit` (and `SELECT ON system.query_log`
for `slow_queries`). Don't put the user in a profile with `readonly = 1`:
Conduit sends its limits as settings on every request, which such a profile
forbids changing (`readonly = 2` in the profile works).

| Action | Risk | Notes |
| --- | --- | --- |
| `databases` | read | Databases and their engines. |
| `tables` | read | Tables (of one `database`, or all but the system ones) with engine, rows and bytes, up to 1000. |
| `query` | read, sensitive | One `SELECT`, `WITH`, `SHOW`, `DESCRIBE`, `EXISTS` or `EXPLAIN`, at most 10 seconds and 1000 rows (8 MB). Results can hold personal data, so they stay out of the audit log. |
| `slow_queries` | read, sensitive | The slowest queries that finished in the last `hours` (24) taking at least `minMs` (1000), up to `limit` (20): time, duration, user, database, rows and bytes read, result rows, memory and the first 500 characters of the query. Query text can hold data, so it stays out of the audit log. |

**The server enforces read-only.** Every request carries
`readonly=1` (placed after the limits, so it can't be undone by anything in
the request), `max_execution_time=10`, `max_result_rows=1000`,
`max_result_bytes`, `result_overflow_mode=break` and
`wait_end_of_query=1`. With `readonly=1` ClickHouse refuses writes, schema
changes and changing settings, whatever the statement says. Values for
`tables` and `slow_queries` are passed as query parameters, never pasted
into the SQL.

Conduit adds checks on top, which give a clear message and catch what
`readonly` doesn't stop: the query must be one statement starting with a
reading keyword (comments and quoted text are ignored when checking);
`INSERT INTO`, schema and access changes, `INTO OUTFILE`, `FORMAT` (results
always come back as JSON) and a `SETTINGS` clause are refused; and table
functions and functions that read files, reach other servers or run
programs (`url`, `s3`, `gcs`, `azureBlobStorage`, `hdfs`, `file`,
`remote`, `remoteSecure`, `mysql`, `postgresql`, `mongodb`, `redis`,
`sqlite`, `jdbc`, `odbc`, `executable`, `iceberg`, `deltaLake`, `hudi`,
...) and `sleep`/`sleepEachRow` are refused wherever the name appears before
a `(`, even backquoted (a false positive only means rephrasing).

**Security.** The user and password are sent in the `X-ClickHouse-User` and
`X-ClickHouse-Key` headers, never in the URL. Since Go forwards custom
headers on redirects, the client follows redirects only within the same
host and never from https to http. Error messages are cut to ClickHouse's
own message and redacted.
