package mongodb

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func in(s string) input {
	var p input
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		panic(err)
	}
	return p
}

func TestBuildFind(t *testing.T) {
	f, err := BuildFind(in(`{"database":"app","collection":"orders","filter":{"_id":{"$oid":"64b7f0c2a1b2c3d4e5f60718"},"status":{"$in":["failed","late"]},"total":{"$gt":10}},"projection":{"email":0},"sort":{"createdAt":-1},"limit":5,"skip":10}`))
	if err != nil {
		t.Fatal(err)
	}
	d := f.filter.(bson.D)
	if d[0].Key != "_id" {
		t.Fatal(d)
	}
	if _, ok := d[0].Value.(bson.ObjectID); !ok {
		t.Fatalf("$oid not decoded: %T", d[0].Value)
	}
	if f.limit != 5 {
		t.Fatal(f.limit)
	}
	// Defaults: limit 20 and an empty filter.
	f, err = BuildFind(in(`{"database":"app","collection":"orders"}`))
	if err != nil || f.limit != 20 || len(f.filter.(bson.D)) != 0 {
		t.Fatal(f, err)
	}
	for _, s := range []string{
		`{"database":"app","collection":"orders","filter":{"$where":"this.a > 1"}}`,
		`{"database":"app","collection":"orders","filter":{"$WHERE":"sleep(10000)"}}`,
		`{"database":"app","collection":"orders","filter":{"$expr":{"$function":{"body":"function(){return true}","args":[],"lang":"js"}}}}`,
		`{"database":"app","collection":"orders","filter":{"$and":[{"a":1},{"$expr":{"$gt":[{"$function":{"body":"x","args":[],"lang":"js"}},1]}}]}}`,
		`{"database":"app","collection":"orders","filter":{"a":{"$code":"function(){}"}}}`,
		`{"database":"app","collection":"orders","projection":{"x":{"$function":{"body":"x","args":[],"lang":"js"}}}}`,
		`{"database":"app","collection":"orders","filter":{"x":{"$accumulator":{}}}}`,
		`{"database":"app","collection":"orders","filter":[1,2]}`,
		`{"database":"app","collection":"orders","filter":"a"}`,
		`{"database":"app","collection":"orders","limit":0}`,
		`{"database":"app","collection":"orders","limit":1000}`,
		`{"database":"app","collection":"orders","skip":-1}`,
		`{"database":"app","collection":"system.users"}`,
		`{"database":"admin","collection":"system.version"}`,
		`{"database":"a.b","collection":"orders"}`,
		`{"database":"a/b","collection":"orders"}`,
		`{"database":"","collection":"orders"}`,
		`{"database":"app","collection":""}`,
		`{"database":"app","collection":"a$b"}`,
		`{"database":"app","collection":"orders","filter":{"a":{"$oid":"nothex"}}}`,
		`{"database":"app","collection":"orders","filter":` + strings.Repeat(`{"a":`, 40) + `1` + strings.Repeat(`}`, 40) + `}`,
	} {
		if _, err := BuildFind(in(s)); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
}

func TestBuildPipeline(t *testing.T) {
	pipe, limit, err := BuildPipeline(in(`{"database":"app","collection":"orders","pipeline":[{"$match":{"status":"failed"}},{"$group":{"_id":"$code","n":{"$sum":1}}},{"$lookup":{"from":"users","localField":"u","foreignField":"_id","as":"user"}},{"$sort":{"n":-1}}],"limit":10}`))
	if err != nil || limit != 10 || len(pipe) != 5 {
		t.Fatal(pipe, err)
	}
	if last := pipe[len(pipe)-1]; last[0].Key != "$limit" || last[0].Value != int64(10) {
		t.Fatal(last)
	}
	if pipe, _, err := BuildPipeline(in(`{"database":"app","collection":"orders","pipeline":[]}`)); err != nil || len(pipe) != 1 {
		t.Fatal(pipe, err)
	}
	for _, s := range []string{
		`{"database":"app","collection":"orders","pipeline":[{"$out":"copy"}]}`,
		`{"database":"app","collection":"orders","pipeline":[{"$match":{}},{"$merge":{"into":"copy"}}]}`,
		`{"database":"app","collection":"orders","pipeline":[{"$facet":{"a":[{"$out":"x"}]}}]}`,
		`{"database":"app","collection":"orders","pipeline":[{"$group":{"_id":null,"x":{"$accumulator":{"init":"function(){}","accumulate":"x","accumulateArgs":[],"merge":"x","lang":"js"}}}}]}`,
		`{"database":"app","collection":"orders","pipeline":[{"$addFields":{"x":{"$function":{"body":"x","args":[],"lang":"js"}}}}]}`,
		`{"database":"app","collection":"orders","pipeline":[{"$match":{"$where":"1"}}]}`,
		`{"database":"app","collection":"orders","pipeline":[{"$changeStream":{}}]}`,
		`{"database":"app","collection":"orders","pipeline":[{"$lookup":{"from":"system.users","localField":"a","foreignField":"b","as":"c"}}]}`,
		`{"database":"app","collection":"orders","pipeline":[{"$unionWith":{"coll":"system.profile"}}]}`,
		`{"database":"app","collection":"orders","pipeline":[{"$lookup":{"from":{"db":"admin","coll":"x"},"localField":"a","foreignField":"b","as":"c"}}]}`,
		`{"database":"app","collection":"orders","pipeline":[{"$match":{},"$out":"x"}]}`,
		`{"database":"app","collection":"orders","pipeline":[{"match":{}}]}`,
		`{"database":"app","collection":"orders","pipeline":[{}]}`,
		`{"database":"app","collection":"orders","pipeline":{"$match":{}}}`,
		`{"database":"app","collection":"orders"}`,
		`{"database":"app","collection":"orders","pipeline":[{"$match":{}}],"limit":101}`,
		`{"database":"app","collection":"system.users","pipeline":[]}`,
	} {
		if _, _, err := BuildPipeline(in(s)); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
	many := `[` + strings.TrimSuffix(strings.Repeat(`{"$match":{}},`, 51), ",") + `]`
	if _, _, err := BuildPipeline(in(`{"database":"app","collection":"orders","pipeline":` + many + `}`)); err == nil {
		t.Fatal("accepted 51 stages")
	}
}

func TestCheckURIAndConfigure(t *testing.T) {
	for _, u := range []string{
		"mongodb://localhost:27017", "mongodb://db1:27017,db2:27017/?replicaSet=rs0&tls=true",
		"mongodb+srv://cluster0.example.mongodb.net/?retryWrites=true", "mongodb://db/?authMechanism=SCRAM-SHA-256",
	} {
		if err := CheckURI(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range []string{
		"", "http://db:27017", "mongodb://user:pass@db:27017", "mongodb://user@db:27017",
		"mongodb://db/?tlsCertificateKeyFilePassword=x", "mongodb://db/?proxyPassword=x", "mongodb://db/?tlsCAFile=/etc/x",
		"mongodb://db/?authMechanismProperties=AWS_SESSION_TOKEN:abc", "mongodb://db/#x",
	} {
		if err := CheckURI(u); err == nil {
			t.Errorf("accepted %q", u)
		}
	}
	h := fakehost.New(map[string]string{"secret://m": "pw"})
	for _, c := range []Config{
		{URI: "mongodb://db", Username: "u", Password: "plain"},
		{URI: "mongodb://db", Username: "u"},
		{URI: "mongodb://db", Password: "secret://m"},
		{URI: "mongodb://db", Username: "u", Password: "secret://m", AuthSource: "a/b"},
		{URI: "mongodb://db/?maxPoolSize=abc"},
		{URI: "mongodb://db:99999"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), h, "x", raw); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
	m := New()
	raw, _ := json.Marshal(Config{URI: "mongodb://db.internal:27017/?tls=true", Username: "reader", Password: "secret://m", AuthSource: "admin"})
	if err := m.Configure(context.Background(), h, "x", raw); err != nil {
		t.Fatal(err)
	}
	o := ClientOptions(Config{URI: "mongodb://db.internal:27017", Username: "reader", AuthSource: "admin"}, "pw", nil)
	if o.Auth == nil || o.Auth.Username != "reader" || o.Auth.Password != "pw" || o.Auth.AuthSource != "admin" || o.Timeout == nil || *o.Timeout != QueryTimeout || *o.AppName != "conduit" || *o.MaxPoolSize != 2 {
		t.Fatalf("%+v", o)
	}
	if o.Validate() != nil {
		t.Fatal(o.Validate())
	}
}

func TestInvokeChecksFirst(t *testing.T) {
	m := New()
	raw, _ := json.Marshal(Config{URI: "mongodb://127.0.0.1:1"})
	if err := m.Configure(context.Background(), fakehost.New(nil), "x", raw); err != nil {
		t.Fatal(err)
	}
	// Refused input fails without connecting (nothing listens on port 1,
	// so a connection attempt would end in a timeout error instead).
	for action, s := range map[string]string{
		"find":        `{"database":"app","collection":"orders","filter":{"$where":"1"}}`,
		"aggregate":   `{"database":"app","collection":"orders","pipeline":[{"$out":"x"}]}`,
		"collections": `{"database":"a b"}`,
		"drop":        `{}`,
	} {
		_, err := m.Invoke(context.Background(), sdk.Call{Instance: "x", Action: action, Input: json.RawMessage(s)})
		if err == nil || strings.Contains(err.Error(), "10 seconds") || strings.Contains(err.Error(), "server selection") {
			t.Errorf("%s: %v", action, err)
		}
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Errorf("%s: MongoDB offers no writes", a.Name)
		}
		if (a.Name == "find" || a.Name == "aggregate") != a.Sensitive {
			t.Errorf("%s: sensitive is %v", a.Name, a.Sensitive)
		}
	}
	if h := New().Health(context.Background(), "nope"); h.Status != "unconfigured" {
		t.Fatal(h)
	}
}

func TestCleanErr(t *testing.T) {
	err := cleanErr(errString("auth error: sasl conversation error: password=hunter2abc mongodb://u:p@db"))
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "u:p@") {
		t.Fatal(err)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// The check runs on the decoded BSON, where duplicate keys survive (a Go
// map kept only the last one), and duplicate keys are refused outright.
func TestDuplicateKeysAndDecodedCheck(t *testing.T) {
	for _, s := range []string{
		`{"database":"app","collection":"orders","filter":{"$expr":{"$function":{"body":"function(){while(true){}}","args":[],"lang":"js"}},"$expr":true}}`,
		`{"database":"app","collection":"orders","filter":{"a":1,"a":2}}`,
		`{"database":"app","collection":"orders","sort":{"a":1,"a":-1}}`,
	} {
		if _, err := BuildFind(in(s)); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
	if _, _, err := BuildPipeline(in(`{"database":"app","collection":"orders","pipeline":[{"$match":{"$and":[{"$where":"sleep(100000)"}],"$and":[{}]}}]}`)); err == nil {
		t.Error("accepted a duplicate $and hiding $where")
	}
	// Check itself walks every element of a bson.D, duplicates included,
	// and refuses BSON JavaScript values.
	for _, d := range []bson.D{
		{{Key: "$expr", Value: bson.D{{Key: "$function", Value: bson.D{}}}}, {Key: "$expr", Value: true}},
		{{Key: "$and", Value: bson.A{bson.D{{Key: "$where", Value: "1"}}}}, {Key: "$and", Value: bson.A{}}},
		{{Key: "a", Value: bson.JavaScript("function(){}")}},
		{{Key: "a", Value: bson.CodeWithScope{Code: "x"}}},
		{{Key: "$unionWith", Value: "system.users"}},
	} {
		if err := Check(d, 0); err == nil {
			t.Errorf("Check accepted %v", d)
		}
	}
	if err := Check(bson.D{{Key: "a", Value: 1}, {Key: "b", Value: bson.A{bson.D{{Key: "c", Value: "system"}}}}}, 0); err != nil {
		t.Fatal(err)
	}
}

// Collections named as strings in $unionWith, $lookup and $graphLookup
// are kept out of the system namespace.
func TestSystemCollectionStrings(t *testing.T) {
	for _, st := range []string{
		`{"$unionWith":"system.users"}`,
		`{"$unionWith":"System.Profile"}`,
		`{"$unionWith":{"coll":"system.users","pipeline":[]}}`,
		`{"$graphLookup":{"from":"system.roles","startWith":"$a","connectFromField":"a","connectToField":"b","as":"c"}}`,
		`{"$lookup":{"from":"system.views","as":"c","pipeline":[]}}`,
		`{"$facet":{"x":[{"$unionWith":"system.js"}]}}`,
		`{"$unionWith":{"db":"admin","coll":"x"}}`,
	} {
		if _, _, err := BuildPipeline(in(`{"database":"admin","collection":"x","pipeline":[` + st + `]}`)); err == nil {
			t.Errorf("accepted %s", st)
		}
	}
	if _, _, err := BuildPipeline(in(`{"database":"app","collection":"orders","pipeline":[{"$unionWith":"archive"},{"$lookup":{"from":"users","localField":"u","foreignField":"_id","as":"user"}}]}`)); err != nil {
		t.Fatal(err)
	}
}
