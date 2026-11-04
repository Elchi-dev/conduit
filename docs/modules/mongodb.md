# MongoDB

A MongoDB deployment through the official Go driver: databases,
collections with document counts, `find` and `aggregate`, and a server
status summary. It never writes.

**Setup.** Enter the connection string as `uri` without the user and
password, such as `mongodb://db1:27017,db2:27017/?replicaSet=rs0&tls=true`
or `mongodb+srv://cluster0.example.mongodb.net/`, then the `username`, its
`password` (stored in the vault) and the `authSource` if the user isn't
defined in `admin`. Options that carry a credential (anything with
`password` or `token` in its name, `authMechanismProperties`) or read a
file on this computer (`tlsCAFile`, `tlsCertificateKeyFile`, ...) are
refused in the uri.

**The real boundary is a read-only user.** MongoDB has no read-only mode
for a request, so give Conduit a user with only the `read` role on the
databases it should see (or `readAnyDatabase`), plus `clusterMonitor` for
`server_status`:

```js
db.getSiblingDB("admin").createUser({user: "conduit", pwd: passwordPrompt(),
  roles: ["readAnyDatabase", "clusterMonitor"]})
```

Conduit only ever sends reading commands (`listDatabases`,
`listCollections`, `count`, `find`, `aggregate`, `buildInfo`,
`serverStatus`), and its checks catch the ways those could write or run
code, but anything the user is allowed to do should be assumed possible.

| Action | Risk | Notes |
| --- | --- | --- |
| `databases` | read | Databases the user can see, with size on disk and the total. |
| `collections` | read | Collections and views of a `database`, with estimated document counts (for up to 200 collections). |
| `find` | read, sensitive | Documents of a `collection` matching a `filter`, with `projection`, `sort`, `skip` and `limit` (at most 100), in MongoDB Extended JSON (so `{"$oid": …}` and `{"$date": …}` work). At most 10 seconds (sent to the server as `maxTimeMS`) and 4 MB. Results stay out of the audit log. |
| `aggregate` | read, sensitive | Runs a `pipeline` (up to 50 stages, each a single `$` operator) with `{"$limit": limit}` (at most 100) added at the end. Same time and size limits; disk use is off. Results stay out of the audit log. |
| `server_status` | read | Host, version, uptime, connections (current, available, created), operation counters, resident and virtual memory, storage engine and replica set role. |

**What's refused.** Anywhere in a filter, projection, sort or pipeline,
including inside `$expr`, `$facet` and `$lookup`: `$where`, `$function`
and `$accumulator` (server-side JavaScript), `$code` (JavaScript values),
`$out` and `$merge` (they write a collection) and `$changeStream` (it
doesn't end). System collections (`system.users`, `system.profile`, ...)
can't be read, also not through `$lookup`, `$graphLookup` or `$unionWith`,
and a pipeline can't name another database. Database and collection names
are checked, input is at most 64 KB and 32 levels deep.

Tests: query building and checking run in every build; the module runs
against a real MongoDB with `go test -tags mongointegration` (see
`modules/mongodb/integration_test.go`).
