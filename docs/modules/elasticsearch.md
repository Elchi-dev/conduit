# Elasticsearch

An Elasticsearch or OpenSearch cluster through its REST API: cluster
health, nodes, indices, searching an index, and deleting one.

**Setup.** Enter the REST API's `url`, such as `https://es.example.com:9200`,
and either an `apiKey` (the encoded form Elasticsearch shows when it creates
the key) or a `username` with its `password`, both stored in the vault. For a
cluster with security off, leave both empty. For a self-signed certificate,
enter its SHA-256 `fingerprint`.

Give Conduit a key or user whose role can only read: cluster privilege
`monitor`, and index privileges `read`, `monitor` and `view_index_metadata`
on the indices it should see. Add `delete_index` only on the indices it may
delete. That role is the real boundary: Conduit's checks below catch
mistakes and the obvious tricks, but anything the role allows can be done.

| Action | Risk | Notes |
| --- | --- | --- |
| `health` | read | Cluster status (green, yellow, red), nodes, data nodes, shards (active, relocating, initializing, unassigned) and pending tasks. |
| `nodes` | read | Each node with IP, roles, whether it's the elected master, heap, RAM and CPU percent, load, disk used and version. |
| `indices` | read | Indices (or those matching `pattern`, such as `logs-*`) with health, status, documents, size in bytes, primaries and replicas, up to 1000. System and hidden indices (names starting with `.`) only with `includeHidden`. |
| `search` | read, sensitive | Searches an `index` (or a pattern or comma-separated list) with a Lucene query string `q` or a query DSL `query`, plus `aggs`, `sort`, `source` filtering, `size` (at most 100) and `from` (`from` + `size` at most 10,000). The search runs with a 10-second timeout. Documents can hold personal data, so results stay out of the audit log. |
| `delete_index` | destructive | Deletes one index by its exact name. The preview shows its documents, size and health. No undo: the documents are gone. |

**What search refuses.** Anything that runs code: any key naming a script
(`script`, `script_score`, `script_fields`, `scripted_metric`, `_script`
sort, ...), `runtime_mappings` (fields defined by a script), a `lang` key
and the word `painless` as a value. `wrapper` queries (base64-encoded DSL
that would skip these checks). Lookups into system indices (a terms lookup
or `more_like_this` naming an index that starts with `.`, `_` or `<` (date
math, such as `<.security-{now}>`), or another cluster's index). JSON with
the same key twice in one object. Oversized aggregations: a `size` or
`shard_size` above 1000 (`shard_size` 2000), a `top_hits` or `inner_hits`
size above 100, and nested bucket aggregations whose sizes multiply to more
than 10,000 buckets (a terms-like aggregation without a size counts as 10).
Index names starting with `.` or `_` (so no `_all`, and nothing such as
`_update_by_query`, `_delete_by_query` or another API), names with `/`,
`:` (cross-cluster search) or uppercase letters. Conduit builds the request
path itself, so only `/<index>/_search` is reached; a pattern also excludes
dot-prefixed indices (`,-.*`) and doesn't expand to hidden ones. The query
string has leading wildcards turned off.

**What delete refuses.** Wildcards, lists, `_all`, names starting with `.`
(system indices, data stream backing indices), aliases and data streams
(the name must resolve to exactly one index of that name), and indices with
`index.hidden` set. The delete is sent with `expand_wildcards=none`.

**Security.** Credentials are resolved from the vault at call time and sent
as `Authorization: ApiKey …` or basic auth. The client follows redirects
only within the same host and never from https to http.
