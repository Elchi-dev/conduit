package mqtt

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	mqttsrv "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// hook checks the username and password, denies the secret/ tree and
// records what clients publish.
type hook struct {
	mqttsrv.HookBase
	mu        sync.Mutex
	published []string
}

func (h *hook) ID() string { return "test" }
func (h *hook) Provides(b byte) bool {
	return b == mqttsrv.OnConnectAuthenticate || b == mqttsrv.OnACLCheck || b == mqttsrv.OnPublished
}
func (h *hook) OnConnectAuthenticate(_ *mqttsrv.Client, pk packets.Packet) bool {
	return string(pk.Connect.Username) == "u" && string(pk.Connect.Password) == "pw"
}
func (h *hook) OnACLCheck(_ *mqttsrv.Client, topic string, _ bool) bool {
	return !strings.HasPrefix(topic, "secret/")
}
func (h *hook) OnPublished(cl *mqttsrv.Client, pk packets.Packet) {
	if cl.Net.Inline {
		return
	}
	h.mu.Lock()
	h.published = append(h.published, pk.TopicName+"="+string(pk.Payload))
	h.mu.Unlock()
}
func (h *hook) writes() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.published...)
}

type broker struct {
	srv  *mqttsrv.Server
	hook *hook
	addr string
}

func startBroker(t *testing.T, tc *tls.Config) *broker {
	t.Helper()
	srv := mqttsrv.New(&mqttsrv.Options{InlineClient: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	h := &hook{}
	if err := srv.AddHook(h, nil); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if tc != nil {
		l = tls.NewListener(l, tc)
	}
	if err := srv.AddListener(listeners.NewNet("t", l)); err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return &broker{srv: srv, hook: h, addr: addr}
}

func (b *broker) retain(t *testing.T, topic, payload string) {
	t.Helper()
	if err := b.srv.Publish(topic, []byte(payload), true, 0); err != nil {
		t.Fatal(err)
	}
}

func configure(t *testing.T, c Config) (*Module, error) {
	m := New()
	raw, _ := json.Marshal(c)
	err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://bad": "nope"}), "b", raw)
	if err == nil {
		cn, _ := m.set.Get("b")
		cn.settle = 150 * time.Millisecond
		cn.timeout = 3 * time.Second
	}
	return m, err
}

func setup(t *testing.T, b *broker, mod func(*Config)) *Module {
	t.Helper()
	c := Config{URL: "mqtt://" + b.addr, Username: "u", Password: "secret://pw", PublishTopics: []string{"home/+/set", "conduit/#"}, AllowRetain: true}
	if mod != nil {
		mod(&c)
	}
	m, err := configure(t, c)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "b", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestMQTTRead(t *testing.T) {
	b := startBroker(t, nil)
	b.retain(t, "home/kitchen/temp", "21.5")
	b.retain(t, "home/door", `{"open":false}`)
	b.retain(t, "home", "root")
	b.retain(t, "homeassistant/x", "elsewhere")
	b.retain(t, "home/bin", "\xff\x00\x01")
	m := setup(t, b, nil)
	if h := m.Health(context.Background(), "b"); h.Status != "ok" || h.Message != "connected to "+b.addr+" as u · may publish to 2 topic filter(s)" {
		t.Fatalf("%+v", h)
	}

	r, err := invoke(m, "retained", `{"prefix":"home"}`, false)
	if err != nil {
		t.Fatal(err)
	}
	want := `"complete":true,"count":4,"messages":[{"bytes":4,"payload":"root","topic":"home"},{"bytes":3,"payloadBase64":"/wAB","topic":"home/bin"},{"bytes":14,"payload":"{\"open\":false}","topic":"home/door"},{"bytes":4,"payload":"21.5","topic":"home/kitchen/temp"}]`
	if !strings.Contains(string(r.Output), want) {
		t.Fatalf("%s", r.Output)
	}
	if r, err = invoke(m, "retained", `{"prefix":"home","maxMessages":2}`, false); err != nil || !strings.Contains(string(r.Output), `"complete":false,"count":2`) || !strings.Contains(string(r.Output), `"stoppedBy":"maxMessages"`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Live messages: the retained one first, then what is published.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				_ = b.srv.Publish("live/a", []byte("tick"), false, 0)
			}
		}
	}()
	b.retain(t, "live/b", "kept")
	r, err = invoke(m, "subscribe_once", `{"filter":"live/+","seconds":5,"maxMessages":3}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"count":3`) || !strings.Contains(string(r.Output), `"stoppedBy":"maxMessages"`) ||
		!strings.Contains(string(r.Output), `"messages":[{"bytes":4,"payload":"kept","retained":true,"topic":"live/b"},{"bytes":4,"payload":"tick","topic":"live/a"}`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err = invoke(m, "subscribe_once", `{"filter":"live/a","seconds":5,"maxBytes":10}`, false); err != nil || !strings.Contains(string(r.Output), `"bytes":8,"count":2`) || !strings.Contains(string(r.Output), `"stoppedBy":"maxBytes"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	start := time.Now()
	if r, err = invoke(m, "subscribe_once", `{"filter":"quiet/#","seconds":0.3}`, false); err != nil || !strings.Contains(string(r.Output), `"count":0`) || !strings.Contains(string(r.Output), `"stoppedBy":"seconds"`) || time.Since(start) > 2*time.Second {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "subscribe_once", `{"filter":"secret/#","seconds":0.3}`, false); err == nil || !strings.Contains(err.Error(), "refused the subscription") {
		t.Fatal(err)
	}

	// A message over the 1 MiB cap ends the read without the client
	// allocating it.
	b.retain(t, "big/one", strings.Repeat("x", 2<<20))
	if r, err = invoke(m, "subscribe_once", `{"filter":"big/#","seconds":2}`, false); err != nil || !strings.Contains(string(r.Output), `"stoppedBy":"a message over 1 MiB"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "subscribe_once" || a.Name == "retained") != a.Sensitive {
			t.Fatalf("%s: sensitive is %v", a.Name, a.Sensitive)
		}
	}
}

func TestMQTTPublish(t *testing.T) {
	b := startBroker(t, nil)
	m := setup(t, b, nil)
	p, err := invoke(m, "publish", `{"topic":"home/lamp/set","payload":"ON"}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Publish 2 bytes to home/lamp/set" || len(b.hook.writes()) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	r, err := invoke(m, "publish", `{"topic":"home/lamp/set","payload":"ON"}`, false)
	if err != nil || r.Undo != nil || string(r.Output) != `{"bytes":2,"qos":1,"retained":false,"topic":"home/lamp/set"}` {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if r, err = invoke(m, "publish", `{"topic":"conduit/bin","payload":"AAEC","encoding":"base64","qos":0}`, false); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100 && len(b.hook.writes()) < 2; i++ {
		time.Sleep(10 * time.Millisecond) // QoS 0 has no acknowledgement to wait for
	}
	if w := b.hook.writes(); len(w) != 2 || w[0] != "home/lamp/set=ON" || w[1] != "conduit/bin=\x00\x01\x02" {
		t.Fatalf("%q", w)
	}

	// Retained: a new one undoes by clearing, a replacement by putting the
	// old one back.
	r, err = invoke(m, "publish", `{"topic":"conduit/state","payload":"first","retain":true}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "clear_retained" || string(r.Undo.Input) != `{"topic":"conduit/state"}` {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	p, err = invoke(m, "publish", `{"topic":"conduit/state","payload":"second","retain":true}`, true)
	if err != nil || !strings.Contains(string(p.Plan.Changes[0].Before), `"payload":"first"`) || !strings.Contains(string(p.Plan.Changes[0].After), `"payload":"second"`) {
		t.Fatalf("%+v %v", p, err)
	}
	r, err = invoke(m, "publish", `{"topic":"conduit/state","payload":"second","retain":true}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "publish" || !strings.Contains(string(r.Undo.Input), `"payload":"Zmlyc3Q="`) {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}
	got, _ := invoke(m, "retained", `{"prefix":"conduit/state"}`, false)
	if !strings.Contains(string(got.Output), `"payload":"first"`) {
		t.Fatalf("%s", got.Output)
	}

	p, err = invoke(m, "clear_retained", `{"topic":"conduit/state"}`, true)
	if err != nil || p.Plan.Changes[0].Op != "delete" || !strings.Contains(string(p.Plan.Changes[0].Before), `"payload":"first"`) {
		t.Fatalf("%+v %v", p, err)
	}
	r, err = invoke(m, "clear_retained", `{"topic":"conduit/state"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"cleared":true`) || r.Undo == nil || r.Undo.Action != "publish" {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if got, _ = invoke(m, "retained", `{"prefix":"conduit"}`, false); !strings.Contains(string(got.Output), `"count":0`) {
		t.Fatalf("%s", got.Output)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}
	if got, _ = invoke(m, "retained", `{"prefix":"conduit"}`, false); !strings.Contains(string(got.Output), `"payload":"first"`) {
		t.Fatalf("%s", got.Output)
	}
	r, err = invoke(m, "clear_retained", `{"topic":"conduit/none"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"cleared":false`) || r.Undo != nil {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "clear_retained" && a.Risk != sdk.RiskDestructive || a.Name == "publish" && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestMQTTRefusals(t *testing.T) {
	b := startBroker(t, nil)
	bad := setup(t, b, func(c *Config) { c.Password = "secret://bad" })
	if h := bad.Health(context.Background(), "b"); h.Status != "down" || !strings.Contains(h.Message, "refused the username or password") && !strings.Contains(h.Message, "not authorised") {
		t.Fatalf("%+v", h)
	}
	m := setup(t, b, nil)
	for _, c := range []struct{ action, in string }{
		{"publish", `{"topic":"home/lamp","payload":"x"}`},        // not in publishTopics
		{"publish", `{"topic":"home/+/set","payload":"x"}`},       // wildcard
		{"publish", `{"topic":"home/#","payload":"x"}`},           // wildcard
		{"publish", `{"topic":"conduit/a\u0000b","payload":"x"}`}, // NUL
		{"publish", `{"topic":"conduit/a\u0007","payload":"x"}`},  // control character
		{"publish", `{"topic":"","payload":"x"}`},                 // empty
		{"publish", `{"topic":"$SYS/broker","payload":"x"}`},      // broker's own
		{"publish", `{"topic":"conduit/x","payload":"!!","encoding":"base64"}`},
		{"publish", `{"topic":"conduit/x","payload":"x","qos":3}`},
		{"publish", `{"topic":"conduit/x","payload":"","retain":true}`},
		{"publish", `{"topic":"conduit/x","payload":"x","encoding":"hex"}`},
		{"publish", `{"topic":"conduit/` + strings.Repeat("a", 1100) + `","payload":"x"}`},
		{"publish", `{"topic":"conduit/x","payload":"` + strings.Repeat("a", 300<<10) + `"}`},
		{"clear_retained", `{"topic":"home/lamp"}`},
		{"clear_retained", `{"topic":"conduit/#"}`},
		{"subscribe_once", `{"filter":"$share/workers/jobs/#"}`}, // joins a shared group
		{"subscribe_once", `{"filter":"$queue/jobs/#"}`},         // joins a shared queue
		{"subscribe_once", `{"filter":"$SHARE/workers/jobs/#"}`},
		{"subscribe_once", `{"filter":"$other/x"}`},
		{"retained", `{"prefix":"$share/workers/jobs"}`},
		{"retained", `{"prefix":"$queue/jobs"}`},
		{"subscribe_once", `{"filter":"a/#/b"}`},
		{"subscribe_once", `{"filter":"a/b#"}`},
		{"subscribe_once", `{"filter":"a+/b"}`},
		{"subscribe_once", `{"filter":""}`},
		{"subscribe_once", `{"filter":"a\u0000"}`},
		{"subscribe_once", `{"filter":"a/#","seconds":60}`},
		{"subscribe_once", `{"filter":"a/#","maxMessages":5000}`},
		{"subscribe_once", `{"filter":"a/#","maxBytes":99999999}`},
		{"subscribe_once", `{"filter":"a/#","qos":2}`},
		{"retained", `{"prefix":"home/+"}`},
		{"retained", `{"prefix":"home/#"}`},
		{"retained", `{"seconds":100}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	// Retain needs allowRetain; publishing at all needs publishTopics.
	noRetain := setup(t, b, func(c *Config) { c.AllowRetain = false })
	for _, in := range []string{`{"topic":"conduit/x","payload":"x","retain":true}`} {
		if _, err := invoke(noRetain, "publish", in, false); err == nil || !strings.Contains(err.Error(), "allowRetain") {
			t.Fatal(err)
		}
	}
	if _, err := invoke(noRetain, "clear_retained", `{"topic":"conduit/x"}`, false); err == nil || !strings.Contains(err.Error(), "allowRetain") {
		t.Fatal(err)
	}
	readOnly := setup(t, b, func(c *Config) { c.PublishTopics = nil })
	if _, err := invoke(readOnly, "publish", `{"topic":"conduit/x","payload":"x"}`, false); err == nil || !strings.Contains(err.Error(), "publishTopics") {
		t.Fatal(err)
	}
	if h := readOnly.Health(context.Background(), "b"); !strings.HasSuffix(h.Message, "read only") {
		t.Fatalf("%+v", h)
	}
	if w := b.hook.writes(); len(w) != 0 {
		t.Fatalf("refused input reached the broker: %q", w)
	}

	for _, c := range []Config{
		{URL: "mqtt://" + b.addr, Username: "u", Password: "pw"},           // plain password
		{URL: "mqtt://" + b.addr, Password: "secret://pw"},                 // password without user
		{URL: "ws://" + b.addr},                                            // websocket
		{URL: "http://" + b.addr},                                          // not MQTT
		{URL: "mqtt://user:pw@" + b.addr},                                  // credentials in the address
		{URL: "mqtt://" + b.addr + "/x"},                                   // path
		{URL: "mqtt://broker:99999"},                                       // port
		{URL: "mqtt://" + b.addr, PublishTopics: []string{"a/#/b"}},        // bad filter
		{URL: "mqtt://" + b.addr, PublishTopics: []string{"a\x00"}},        // NUL
		{URL: "mqtt://" + b.addr, Fingerprint: strings.Repeat("ab", 32)},   // pin on plain TCP
		{URL: "mqtts://" + b.addr, Fingerprint: "abcd"},                    // short pin
		{URL: "mqtt://" + b.addr, ClientIDPrefix: "far-too-long-a-prefix"}, // client id
		{URL: "mqtt://" + b.addr, ClientIDPrefix: "a/b"},
	} {
		if _, err := configure(t, c); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}

func selfSigned(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "broker"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:])
}

func TestMQTTTLS(t *testing.T) {
	cert, fp := selfSigned(t)
	b := startBroker(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	for _, c := range []struct {
		fp   string
		want string
	}{
		{fp, "ok"},
		{strings.ToUpper(fp[:2]) + ":" + fp[2:], "ok"},
		{strings.Repeat("ab", 32), "down"},
		{"", "down"}, // self-signed, not trusted
	} {
		m := setup(t, b, func(cf *Config) { cf.URL = "mqtts://" + b.addr; cf.Fingerprint = c.fp })
		if h := m.Health(context.Background(), "b"); h.Status != c.want {
			t.Fatalf("%q: %+v", c.fp, h)
		}
	}
}

func TestMatches(t *testing.T) {
	for _, c := range []struct {
		f, t string
		want bool
	}{
		{"home/+/set", "home/lamp/set", true},
		{"home/+/set", "home/lamp/x/set", false},
		{"home/+/set", "home/set", false},
		{"conduit/#", "conduit", true},
		{"conduit/#", "conduit/a/b", true},
		{"conduit/#", "conduitx/a", false},
		{"#", "$SYS/x", false},
		{"+/x", "$SYS/x", false},
		{"a/b", "a/b", true},
		{"a/b", "a/b/c", false},
		{"+", "a", true},
		{"+", "a/b", false},
		{"a/+", "a/", true},
	} {
		if got := matches(c.f, c.t); got != c.want {
			t.Errorf("%s ~ %s: %v", c.f, c.t, got)
		}
	}
}

// chunks returns its data in reads of at most n bytes.
type chunks struct {
	net.Conn
	r io.Reader
}

func (c *chunks) Read(p []byte) (int, error) { return c.r.Read(p) }

func TestGuard(t *testing.T) {
	// A small packet, a pingresp, then a publish claiming 2 MiB.
	stream := []byte{0x30, 0x03, 'a', 'b', 'c', 0xd0, 0x00, 0x30, 0x80, 0x80, 0x80, 0x01}
	g := &guard{Conn: &chunks{r: bytes.NewReader(stream)}, max: maxPacket}
	got, err := io.ReadAll(g)
	if !errors.Is(err, errTooBig) || !bytes.Equal(got, stream[:7]) {
		t.Fatalf("%x %v", got, err)
	}
	// Split across reads, a packet at the limit passes.
	ok := append([]byte{0x30, 0x80, 0x80, 0x01}, bytes.Repeat([]byte{'x'}, 16384)...)
	g = &guard{Conn: &chunks{r: io.MultiReader(bytes.NewReader(ok[:2]), bytes.NewReader(ok[2:9]), bytes.NewReader(ok[9:]))}, max: 16384}
	if got, err := io.ReadAll(g); err != nil || len(got) != len(ok) {
		t.Fatalf("%d %v", len(got), err)
	}
	g = &guard{Conn: &chunks{r: bytes.NewReader([]byte{0x30, 0xff, 0xff, 0xff, 0xff, 0x01})}, max: 1 << 30}
	if _, err := io.ReadAll(g); err == nil {
		t.Fatal("accepted a five-byte length")
	}
}

// Shared-subscription filters ($share/, $queue/) would divert messages away
// from the group's real consumers; only $SYS may start with $.
func TestValidFilterDollar(t *testing.T) {
	for f, ok := range map[string]bool{
		"$SYS/#":                true,
		"$SYS":                  true,
		"$SYS/broker/clients/+": true,
		"home/#":                true,
		"$share/g/home/#":       false,
		"$queue/home/#":         false,
		"$Share/g/#":            false,
		"$sys/#":                false,
		"$":                     false,
	} {
		if err := validFilter(f); (err == nil) != ok {
			t.Errorf("%q: %v", f, err)
		}
	}
}
