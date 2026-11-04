//go:build mongointegration

package mongodb

// Run against a real MongoDB:
//
//	docker run -d -p 27017:27017 -e MONGO_INITDB_ROOT_USERNAME=conduit -e MONGO_INITDB_ROOT_PASSWORD=conduit mongo:8
//	CONDUIT_TEST_MONGO=mongodb://127.0.0.1:27017 go test -tags mongointegration ./modules/mongodb
//
// The user is "conduit" with password "conduit" (authSource admin).

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func TestRealMongo(t *testing.T) {
	uri := os.Getenv("CONDUIT_TEST_MONGO")
	if uri == "" {
		t.Skip("CONDUIT_TEST_MONGO not set")
	}
	ctx := context.Background()
	seed, err := mongo.Connect(options.Client().ApplyURI(uri).SetAuth(options.Credential{Username: "conduit", Password: "conduit"}))
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Disconnect(ctx)
	coll := seed.Database("conduit_test").Collection("orders")
	_ = coll.Drop(ctx)
	docs := []any{}
	for i := 0; i < 150; i++ {
		docs = append(docs, bson.D{{Key: "n", Value: i}, {Key: "status", Value: []string{"ok", "failed"}[i%2]}})
	}
	if _, err := coll.InsertMany(ctx, docs); err != nil {
		t.Fatal(err)
	}

	m := New()
	cfg, _ := json.Marshal(Config{URI: uri, Username: "conduit", Password: "secret://m"})
	if err := m.Configure(ctx, fakehost.New(map[string]string{"secret://m": "conduit"}), "m", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "m"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	call := func(action, in string) string {
		t.Helper()
		r, err := m.Invoke(ctx, sdk.Call{Instance: "m", Action: action, Input: json.RawMessage(in)})
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		return string(r.Output)
	}
	if out := call("databases", `{}`); !strings.Contains(out, `"conduit_test"`) {
		t.Fatal(out)
	}
	if out := call("collections", `{"database":"conduit_test"}`); !strings.Contains(out, `"count":150`) {
		t.Fatal(out)
	}
	if out := call("find", `{"database":"conduit_test","collection":"orders","filter":{"status":"failed","n":{"$lt":10}},"sort":{"n":1},"projection":{"_id":0}}`); !strings.Contains(out, `{"n":1,"status":"failed"}`) || strings.Count(out, `"n":`) != 5 {
		t.Fatal(out)
	}
	if out := call("find", `{"database":"conduit_test","collection":"orders","limit":100}`); strings.Count(out, `"n":`) != 100 {
		t.Fatal(out)
	}
	if out := call("aggregate", `{"database":"conduit_test","collection":"orders","pipeline":[{"$group":{"_id":"$status","c":{"$sum":1}}},{"$sort":{"_id":1}}]}`); !strings.Contains(out, `{"_id":"failed","c":75}`) {
		t.Fatal(out)
	}
	if out := call("server_status", `{}`); !strings.Contains(out, `"connections"`) {
		t.Fatal(out)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "m", Action: "aggregate", Input: json.RawMessage(`{"database":"conduit_test","collection":"orders","pipeline":[{"$out":"copy"}]}`)}); err == nil {
		t.Fatal("$out ran")
	}
	if n, _ := seed.Database("conduit_test").Collection("copy").EstimatedDocumentCount(ctx); n != 0 {
		t.Fatal("a collection was written")
	}
}
