package aws

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

var fixed = time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)

// fakeAWS answers EC2, STS, CloudWatch and S3 calls, and checks every
// request's signature by signing it again with the same key.
type fakeAWS struct {
	t     *testing.T
	svc   string
	state map[string]string
	seen  []string
}

func (f *fakeAWS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	again, _ := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), nil)
	for _, h := range []string{"Content-Type", "X-Amz-Security-Token"} {
		if v := r.Header.Get(h); v != "" {
			again.Header.Set(h, v)
		}
	}
	Sign(again, body, Credentials{AccessKeyID: "AKIAEXAMPLE123456789", SecretAccessKey: "s3cr3t", SessionToken: r.Header.Get("X-Amz-Security-Token")}, "eu-central-1", f.svc, fixed)
	if again.Header.Get("Authorization") != r.Header.Get("Authorization") {
		w.WriteHeader(403)
		io.WriteString(w, `<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code><Message>The request signature we calculated does not match</Message></Error></ErrorResponse>`)
		return
	}
	form, _ := url.ParseQuery(string(body))
	action := form.Get("Action")
	f.seen = append(f.seen, f.svc+" "+r.Method+" "+r.URL.Path+" "+action)
	switch {
	case action == "GetCallerIdentity":
		io.WriteString(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/conduit</Arn><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`)
	case action == "DescribeInstances":
		if form.Get("NextToken") == "" {
			io.WriteString(w, `<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-0aaaaaaaaaaaaaaa1</instanceId><instanceType>t3.micro</instanceType><instanceState><code>16</code><name>`+f.state["i-0aaaaaaaaaaaaaaa1"]+`</name></instanceState><ipAddress>3.3.3.3</ipAddress><placement><availabilityZone>eu-central-1a</availabilityZone></placement><tagSet><item><key>Name</key><value>web-1</value></item></tagSet></item></instancesSet></item></reservationSet><nextToken>p2</nextToken></DescribeInstancesResponse>`)
			return
		}
		io.WriteString(w, `<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-0bbbbbbbbbbbbbbb2</instanceId><instanceType>m7g.large</instanceType><instanceState><name>stopped</name></instanceState></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`)
	case action == "StartInstances" || action == "StopInstances" || action == "RebootInstances":
		id := form.Get("InstanceId.1")
		if form.Get("DryRun") == "true" {
			w.WriteHeader(412)
			io.WriteString(w, `<Response><Errors><Error><Code>DryRunOperation</Code><Message>Request would have succeeded, but DryRun flag is set.</Message></Error></Errors></Response>`)
			return
		}
		if _, ok := f.state[id]; !ok {
			w.WriteHeader(400)
			io.WriteString(w, `<Response><Errors><Error><Code>InvalidInstanceID.NotFound</Code><Message>The instance ID '`+id+`' does not exist</Message></Error></Errors></Response>`)
			return
		}
		prev := f.state[id]
		next := map[string]string{"StartInstances": "pending", "StopInstances": "stopping", "RebootInstances": prev}[action]
		f.state[id] = map[string]string{"pending": "running", "stopping": "stopped"}[next]
		if action == "RebootInstances" {
			f.state[id] = prev
			io.WriteString(w, `<RebootInstancesResponse><return>true</return></RebootInstancesResponse>`)
			return
		}
		io.WriteString(w, `<R><instancesSet><item><instanceId>`+id+`</instanceId><currentState><name>`+next+`</name></currentState><previousState><name>`+prev+`</name></previousState></item></instancesSet></R>`)
	case action == "DescribeAlarms":
		if form.Get("StateValue") != "ALARM" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `<DescribeAlarmsResponse><DescribeAlarmsResult><MetricAlarms><member><AlarmName>api-5xx</AlarmName><StateValue>ALARM</StateValue><StateReason>Threshold crossed</StateReason><MetricName>5XXError</MetricName><Namespace>AWS/ApiGateway</Namespace></member></MetricAlarms></DescribeAlarmsResult></DescribeAlarmsResponse>`)
	case r.Method == "GET" && r.URL.Path == "/":
		if r.Header.Get("X-Amz-Content-Sha256") == "" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `<ListAllMyBucketsResult><Buckets><Bucket><Name>backups</Name><CreationDate>2025-01-01T00:00:00.000Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>`)
	case r.Method == "GET" && r.URL.Path == "/backups":
		if r.URL.Query().Get("list-type") != "2" || r.URL.Query().Get("prefix") != "db dumps/" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>db dumps/a.sql.gz</Key><Size>1024</Size><LastModified>2026-11-02T03:00:00.000Z</LastModified></Contents><CommonPrefixes><Prefix>db dumps/old/</Prefix></CommonPrefixes></ListBucketResult>`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, secret string) (*Module, *fakeAWS) {
	t.Helper()
	state := map[string]string{"i-0aaaaaaaaaaaaaaa1": "stopped"}
	eps := map[string]string{}
	var ec2 *fakeAWS
	for _, svc := range []string{"ec2", "s3", "sts", "monitoring"} {
		f := &fakeAWS{t: t, svc: svc, state: state}
		if svc == "ec2" {
			ec2 = f
		}
		srv := httptest.NewServer(f)
		t.Cleanup(srv.Close)
		eps[svc] = srv.URL
	}
	m := New()
	m.now = func() time.Time { return fixed }
	cfg, _ := json.Marshal(Config{Region: "eu-central-1", AccessKeyID: "AKIAEXAMPLE123456789", SecretAccessKey: secret, SessionToken: "secret://tok", Endpoints: eps})
	host := fakehost.New(map[string]string{"secret://aws": "s3cr3t", "secret://bad": "wrong", "secret://tok": "session-token"})
	if err := m.Configure(context.Background(), host, "a", cfg); err != nil {
		t.Fatal(err)
	}
	return m, ec2
}

func run(t *testing.T, m *Module, action, input string, dry bool) sdk.Result {
	t.Helper()
	if input == "" {
		input = "{}"
	}
	r, err := m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(input), DryRun: dry})
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	return r
}

func TestAWS(t *testing.T) {
	m, ec2 := setup(t, "secret://aws")
	ctx := context.Background()
	if h := m.Health(ctx, "a"); h.Status != "ok" || !strings.Contains(h.Message, "user/conduit") {
		t.Fatalf("health %+v", h)
	}
	var list []map[string]any
	_ = json.Unmarshal(run(t, m, "ec2_instances", "", false).Output, &list)
	if len(list) != 2 || list[0]["name"] != "web-1" || list[0]["publicIp"] != "3.3.3.3" || list[1]["type"] != "m7g.large" {
		t.Fatalf("instances (both pages) %v", list)
	}

	id := `{"instance":"i-0aaaaaaaaaaaaaaa1"}`
	plan := run(t, m, "ec2_start", id, true)
	if plan.Plan == nil || ec2.state["i-0aaaaaaaaaaaaaaa1"] != "stopped" {
		t.Fatalf("dry run changed something or had no plan: %+v", plan)
	}
	r := run(t, m, "ec2_start", id, false)
	if ec2.state["i-0aaaaaaaaaaaaaaa1"] != "running" || r.Undo == nil || r.Undo.Action != "ec2_stop" {
		t.Fatalf("start %+v", r)
	}
	run(t, m, r.Undo.Action, string(r.Undo.Input), false)
	if ec2.state["i-0aaaaaaaaaaaaaaa1"] != "stopped" {
		t.Fatal("undo start")
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "a", Action: "ec2_stop", Input: json.RawMessage(`{"instance":"i-0ccccccccccccccc3"}`)}); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("unknown instance: %v", err)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "a", Action: "ec2_reboot", Input: json.RawMessage(`{"instance":"web-1"}`)}); err == nil {
		t.Fatal("bad instance id accepted")
	}

	var buckets []map[string]string
	_ = json.Unmarshal(run(t, m, "s3_buckets", "", false).Output, &buckets)
	if len(buckets) != 1 || buckets[0]["name"] != "backups" {
		t.Fatalf("buckets %v", buckets)
	}
	var objs struct {
		Objects []map[string]any `json:"objects"`
	}
	_ = json.Unmarshal(run(t, m, "s3_list", `{"bucket":"backups","prefix":"db dumps/"}`, false).Output, &objs)
	if len(objs.Objects) != 2 || objs.Objects[0]["folder"] != true || objs.Objects[1]["size"] != 1024.0 {
		t.Fatalf("objects %v", objs)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "a", Action: "s3_list", Input: json.RawMessage(`{"bucket":"../etc"}`)}); err == nil {
		t.Fatal("bad bucket accepted")
	}

	var alarms []map[string]string
	_ = json.Unmarshal(run(t, m, "cloudwatch_alarms", "", false).Output, &alarms)
	if len(alarms) != 1 || alarms[0]["name"] != "api-5xx" {
		t.Fatalf("alarms %v", alarms)
	}
}

func TestAWSWrongKey(t *testing.T) {
	m, _ := setup(t, "secret://bad")
	if h := m.Health(context.Background(), "a"); h.Status != "down" || !strings.Contains(h.Message, "SignatureDoesNotMatch") {
		t.Fatalf("health %+v", h)
	}
}

func TestAWSConfig(t *testing.T) {
	m := New()
	h := fakehost.New(nil)
	for _, c := range []string{
		`{"region":"mars-1","accessKeyId":"AKIAEXAMPLE123456789","secretAccessKey":"secret://a"}`,
		`{"region":"us-east-1","accessKeyId":"nope","secretAccessKey":"secret://a"}`,
		`{"region":"us-east-1","accessKeyId":"AKIAEXAMPLE123456789","secretAccessKey":"plaintext"}`,
	} {
		if err := m.Configure(context.Background(), h, "a", json.RawMessage(c)); err == nil {
			t.Errorf("%s accepted", c)
		}
	}
}
