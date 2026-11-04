// Package mqtt works with any MQTT broker (Mosquitto, EMQX, HiveMQ, the
// Home Assistant add-on, ...) over MQTT 3.1.1: collecting the messages on a
// topic filter for a few seconds, a snapshot of the retained messages under
// a prefix, and publishing to topics the settings allow. Every call opens
// its own short connection with a clean session, so nothing stays
// subscribed between calls.
package mqtt

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	paho "github.com/eclipse/paho.mqtt.golang"
	"github.com/eclipse/paho.mqtt.golang/packets"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one broker.
type Config struct {
	URL      string `json:"url"`      // mqtt://broker.local:1883 or mqtts://broker.local:8883
	Username string `json:"username"` // optional
	Password string `json:"password"` // secret://, with username
	// ClientIDPrefix starts the client id of every connection; a random
	// suffix keeps two calls from taking each other's session.
	ClientIDPrefix string `json:"clientIdPrefix"`
	// PublishTopics are the topic filters publish may write to. Empty
	// means nothing can be published.
	PublishTopics []string `json:"publishTopics"`
	// AllowRetain lets publish set the retain flag and clear_retained
	// remove retained messages.
	AllowRetain        bool   `json:"allowRetain"`
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	host    sdk.Host
	addr    string      // host:port
	tls     *tls.Config // nil for plain TCP
	user    string
	pass    string // secret:// reference
	prefix  string
	publish []string
	retain  bool
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	timeout time.Duration
	// settle is how long to wait after the subscription is acknowledged
	// for the broker's retained messages to stop arriving.
	settle time.Duration
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
}

// New returns the MQTT module.
func New() *Module { return &Module{} }

const (
	maxTopic      = 1024      // bytes in a topic or filter we accept
	maxPublish    = 256 << 10 // bytes in a published payload
	maxCollect    = 1 << 20   // bytes of payload one read collects
	maxPacket     = maxCollect + 64<<10
	maxUndoBytes  = 64 << 10 // a previous retained message larger than this gets no undo
	defaultPrefix = "conduit"
)

var prefixRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,14}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limits := `"maxMessages":{"type":"integer","minimum":1,"maximum":1000},"maxBytes":{"type":"integer","minimum":1,"maximum":1048576,"description":"Payload bytes to collect at most"}`
	topic := `"topic":{"type":"string","description":"A topic without wildcards, inside the publishTopics setting"}`
	return sdk.Manifest{
		ID: "mqtt", Name: "MQTT", Version: "0.1.0", Category: "Smart home", Icon: "network",
		Description: "Any MQTT broker: read the messages on a topic for a few seconds, snapshot retained messages, publish to allowed topics.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"The broker, e.g. mqtt://broker.local:1883 or mqtts://broker.local:8883 for TLS"},
			"username":{"type":"string"},
			"password":{"type":"string","x-secret":true,"description":"The user's password"},
			"clientIdPrefix":{"type":"string","default":"conduit","description":"Start of the client id (a random suffix is added); up to 14 letters, digits, - and _"},
			"publishTopics":{"type":"array","items":{"type":"string"},"description":"Topic filters publish may write to, e.g. home/lights/+/set or conduit/#. Empty: publishing is off"},
			"allowRetain":{"type":"boolean","default":false,"description":"Let publish set the retain flag and clear_retained remove retained messages"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the broker's certificate, to trust a self-signed one (mqtts only)"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "subscribe_once", Title: "Read a topic", Description: "Subscribes to a topic filter (+ and # allowed), collects what arrives (retained messages first) for up to `seconds`, then disconnects. Bounded by maxMessages and maxBytes.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["filter"],"properties":{"filter":{"type":"string","description":"e.g. zigbee2mqtt/+/availability or sensors/#"},"seconds":{"type":"number","minimum":0.1,"maximum":30,"default":3},` + limits + `,"qos":{"type":"integer","enum":[0,1],"default":0}}}`)},
			{Name: "retained", Title: "Retained messages", Description: "The retained messages under a topic prefix (the prefix itself and everything below it), sorted by topic. Empty prefix: the whole broker except $SYS.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"prefix":{"type":"string","description":"e.g. homeassistant or zigbee2mqtt/bridge"},"seconds":{"type":"number","minimum":0.5,"maximum":15,"default":5},` + limits + `}}`)},
			{Name: "publish", Title: "Publish", Description: "Publishes a message to a topic allowed by the publishTopics setting. Retained only when allowRetain is on; then undo puts back the retained message that was there before.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["topic","payload"],"properties":{` + topic + `,"payload":{"type":"string"},"encoding":{"type":"string","enum":["text","base64"],"default":"text"},"qos":{"type":"integer","enum":[0,1,2],"default":1},"retain":{"type":"boolean","default":false}}}`)},
			{Name: "clear_retained", Title: "Clear a retained message", Description: "Removes the retained message on a topic (allowed by publishTopics, with allowRetain on). Undo publishes it again.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["topic"],"properties":{` + topic + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return errors.New("the broker is like mqtt://broker.local:1883 or mqtts://broker.local:8883")
	}
	secure := false
	port := "1883"
	switch strings.ToLower(u.Scheme) {
	case "mqtt", "tcp":
	case "mqtts", "ssl", "tls":
		secure, port = true, "8883"
	default:
		return errors.New("the broker is like mqtt://broker.local:1883 or mqtts://broker.local:8883 (WebSocket brokers aren't supported)")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return errors.New("the broker's port is a number up to 65535")
		}
		port = p
	}
	hostname := u.Hostname()
	user := c.Username
	if strings.TrimSpace(user) != user || len(user) > 256 || hasControl(user) {
		return errors.New("the username has spaces at the ends, control characters or is too long")
	}
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	if c.Password != "" && user == "" {
		return errors.New("enter the username too (MQTT has no password without a username)")
	}
	prefix := c.ClientIDPrefix
	if prefix == "" {
		prefix = defaultPrefix
	}
	if !prefixRe.MatchString(prefix) {
		return errors.New("the client id prefix is up to 14 letters, digits, - and _")
	}
	if len(c.PublishTopics) > 100 {
		return errors.New("list at most 100 publish topics")
	}
	var pub []string
	for _, f := range c.PublishTopics {
		if err := validFilter(f); err != nil {
			return fmt.Errorf("publish topic %q: %w", f, err)
		}
		pub = append(pub, f)
	}
	if !secure && (c.Fingerprint != "" || c.InsecureSkipVerify) {
		return errors.New("the certificate settings need a TLS broker address (mqtts://)")
	}
	cn := &conn{host: h, addr: net.JoinHostPort(hostname, port), user: user, pass: c.Password, prefix: prefix, publish: pub, retain: c.AllowRetain,
		dial: sdk.DialContext(h), timeout: 10 * time.Second, settle: 400 * time.Millisecond}
	if secure {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tc.ServerName = hostname
		cn.tls = tc
	}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// checkChars applies what MQTT asks of topics and filters: UTF-8, no NUL,
// and (as the spec recommends) no other control characters.
func checkChars(s string) error {
	switch {
	case s == "":
		return errors.New("it's empty")
	case len(s) > maxTopic:
		return fmt.Errorf("it's longer than %d bytes", maxTopic)
	case !utf8.ValidString(s):
		return errors.New("it isn't valid UTF-8")
	case hasControl(s):
		return errors.New("it has control characters")
	}
	return nil
}

// validTopic checks a topic to publish to: no wildcards.
func validTopic(t string) error {
	if err := checkChars(t); err != nil {
		return err
	}
	if strings.ContainsAny(t, "+#") {
		return errors.New("a topic to publish to has no + or # wildcards")
	}
	return nil
}

// checkDollar keeps subscriptions out of the broker's special $ namespaces
// except $SYS (its read-only statistics). $share/<group>/... and
// $queue/... don't read a topic: they join a shared subscription, so the
// broker diverts part of that group's messages away from its real consumers
// to Conduit. Any other $ prefix is refused too, in any letter case.
func checkDollar(f string) error {
	if !strings.HasPrefix(f, "$") || f == "$SYS" || strings.HasPrefix(f, "$SYS/") {
		return nil
	}
	return errors.New("filters starting with $ are only allowed under $SYS/ ($share/ and $queue/ would take messages away from a shared subscription's consumers)")
}

// validFilter checks a subscription filter: + only as a whole level, # only
// as the whole last level, and $ only for $SYS.
func validFilter(f string) error {
	if err := checkChars(f); err != nil {
		return err
	}
	if err := checkDollar(f); err != nil {
		return err
	}
	levels := strings.Split(f, "/")
	for i, l := range levels {
		switch {
		case strings.Contains(l, "#") && (l != "#" || i != len(levels)-1):
			return errors.New("# is only allowed as the whole last level, like sensors/#")
		case strings.Contains(l, "+") && l != "+":
			return errors.New("+ is only allowed as a whole level, like sensors/+/temperature")
		}
	}
	return nil
}

// matches reports whether a topic is matched by a filter, per MQTT 3.1.1
// 4.7: wildcards at the start don't match topics beginning with $.
func matches(filter, topic string) bool {
	if strings.HasPrefix(topic, "$") && (strings.HasPrefix(filter, "+") || strings.HasPrefix(filter, "#")) {
		return false
	}
	f, t := strings.Split(filter, "/"), strings.Split(topic, "/")
	for i, l := range f {
		if l == "#" {
			return true // also matches the parent level: sport/# matches sport
		}
		if i >= len(t) {
			return false
		}
		if l != "+" && l != t[i] {
			return false
		}
	}
	return len(f) == len(t)
}

// allowed checks a topic against the publishTopics setting.
func (c *conn) allowed(topic string) error {
	if err := validTopic(topic); err != nil {
		return fmt.Errorf("topic %q: %w", topic, err)
	}
	if strings.HasPrefix(topic, "$") {
		return errors.New("topics starting with $ belong to the broker; they can't be published to")
	}
	if len(c.publish) == 0 {
		return errors.New("publishing is off: list the topics it may use in the publishTopics setting")
	}
	for _, f := range c.publish {
		if matches(f, topic) {
			return nil
		}
	}
	return fmt.Errorf("%s isn't in the publishTopics setting (%s)", topic, strings.Join(c.publish, ", "))
}

// guard is the connection under the MQTT client. It follows the packet
// framing and fails the connection before a packet larger than max is
// read, since the client allocates a packet's whole length up front.
type guard struct {
	net.Conn
	max  int
	err  error
	st   byte // 0: next is a fixed header; 1: in the length; 2: in the body
	mul  int
	n    int
	left int
}

var errTooBig = errors.New("the broker sent a message larger than 1 MiB")

func (g *guard) Read(p []byte) (int, error) {
	if g.err != nil {
		return 0, g.err
	}
	n, err := g.Conn.Read(p)
	start := 0 // where the packet being read began in p (0 when before p)
	for i := 0; i < n; i++ {
		switch g.st {
		case 0:
			g.st, g.mul, g.n, start = 1, 1, 0, i
		case 1:
			b := int(p[i])
			g.n += (b & 127) * g.mul
			switch {
			case g.n > g.max:
				g.err = errTooBig
			case b&128 != 0 && g.mul == 128*128*128:
				g.err = errors.New("the broker sent a malformed packet")
			case b&128 != 0:
				g.mul *= 128
			case g.n == 0:
				g.st = 0
			default:
				g.st, g.left = 2, g.n
			}
			if g.err != nil {
				if start == 0 {
					return 0, g.err
				}
				return start, nil // deliver the packets before this one; fail on the next read
			}
		case 2:
			k := min(g.left, n-i)
			g.left -= k
			i += k - 1
			if g.left == 0 {
				g.st = 0
			}
		}
	}
	return n, err
}

func (c *conn) open(ctx context.Context) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	raw, err := c.dial(dctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("can't reach the broker at %s: %w", c.addr, err)
	}
	nc := raw
	if c.tls != nil {
		tc := tls.Client(raw, c.tls.Clone())
		if err := tc.HandshakeContext(dctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("TLS with the broker failed: %w", err)
		}
		nc = tc
	}
	return &guard{Conn: nc, max: maxPacket}, nil
}

func randomID(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

// wait waits for a token, the context or the timeout.
func (c *conn) wait(ctx context.Context, t paho.Token) error {
	select {
	case <-t.Done():
		return t.Error()
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(c.timeout):
		return errors.New("the broker didn't answer in time")
	}
}

// session is one connection to the broker.
type session struct {
	cl   paho.Client
	lost chan error
}

func (s *session) close() { s.cl.Disconnect(100) }

func (c *conn) connect(ctx context.Context) (*session, error) {
	pw := ""
	if c.pass != "" {
		var err error
		if pw, err = c.host.Secret(ctx, c.pass); err != nil {
			return nil, err
		}
	}
	s := &session{lost: make(chan error, 1)}
	o := paho.NewClientOptions()
	o.AddBroker("tcp://" + c.addr) // the address the custom dialer below uses
	o.SetClientID(randomID(c.prefix))
	o.SetProtocolVersion(4)
	o.SetCleanSession(true)
	o.SetAutoReconnect(false)
	o.SetConnectRetry(false)
	o.SetResumeSubs(false)
	o.SetConnectTimeout(c.timeout)
	o.SetWriteTimeout(c.timeout)
	o.SetKeepAlive(30 * time.Second)
	o.SetPingTimeout(c.timeout)
	o.SetOrderMatters(true)
	if c.user != "" {
		o.SetUsername(c.user)
		o.SetPassword(pw)
	}
	o.SetCustomOpenConnectionFn(func(*url.URL, paho.ClientOptions) (net.Conn, error) { return c.open(ctx) })
	o.SetConnectionLostHandler(func(_ paho.Client, err error) {
		select {
		case s.lost <- err:
		default:
		}
	})
	s.cl = paho.NewClient(o)
	if err := c.wait(ctx, s.cl.Connect()); err != nil {
		s.cl.Disconnect(0)
		return nil, connectError(err)
	}
	return s, nil
}

func connectError(err error) error {
	switch {
	case errors.Is(err, packets.ErrorRefusedBadUsernameOrPassword):
		return errors.New("the broker refused the username or password")
	case errors.Is(err, packets.ErrorRefusedNotAuthorised):
		return errors.New("the broker refused the connection: not authorised (check the username and password)")
	case errors.Is(err, packets.ErrorRefusedIDRejected):
		return errors.New("the broker rejected the client id (try a shorter clientIdPrefix)")
	case errors.Is(err, packets.ErrorRefusedBadProtocolVersion):
		return errors.New("the broker doesn't speak MQTT 3.1.1")
	}
	return err
}

type message struct {
	topic    string
	payload  []byte
	retained bool
	qos      byte
}

func (m message) out() map[string]any {
	e := map[string]any{"topic": m.topic, "bytes": len(m.payload)}
	if m.retained {
		e["retained"] = true
	}
	if m.qos > 0 {
		e["qos"] = m.qos
	}
	if utf8.Valid(m.payload) {
		e["payload"] = string(m.payload)
	} else {
		e["payloadBase64"] = base64.StdEncoding.EncodeToString(m.payload)
	}
	return e
}

// collector gathers messages up to the limits.
type collector struct {
	mu           sync.Mutex
	retainedOnly bool
	maxN, maxB   int
	msgs         []message
	seen         map[string]int // retainedOnly: topic → index in msgs
	bytes        int
	last         time.Time
	stop         string
	full         chan struct{}
}

func (k *collector) add(_ paho.Client, m paho.Message) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.stop != "" || (k.retainedOnly && !m.Retained()) {
		return
	}
	p := m.Payload()
	if k.bytes+len(p) > k.maxB {
		k.stop = "maxBytes"
		close(k.full)
		return
	}
	msg := message{topic: m.Topic(), payload: append([]byte(nil), p...), retained: m.Retained(), qos: m.Qos()}
	if k.retainedOnly {
		// One per topic: overlapping filters can bring a topic twice.
		if i, ok := k.seen[msg.topic]; ok {
			k.bytes += len(p) - len(k.msgs[i].payload)
			k.msgs[i] = msg
			k.last = time.Now()
			return
		}
		if k.seen == nil {
			k.seen = map[string]int{}
		}
		k.seen[msg.topic] = len(k.msgs)
	}
	k.msgs = append(k.msgs, msg)
	k.bytes += len(p)
	k.last = time.Now()
	if len(k.msgs) >= k.maxN {
		k.stop = "maxMessages"
		close(k.full)
	}
}

type readInput struct {
	Filter      string   `json:"filter"`
	Prefix      *string  `json:"prefix"`
	Seconds     *float64 `json:"seconds"`
	MaxMessages int      `json:"maxMessages"`
	MaxBytes    int      `json:"maxBytes"`
	QoS         *int     `json:"qos"`
}

func limits(p readInput, defN, defB int) (int, int, error) {
	n, b := p.MaxMessages, p.MaxBytes
	if n == 0 {
		n = defN
	}
	if b == 0 {
		b = defB
	}
	if n < 1 || n > 1000 {
		return 0, 0, errors.New("maxMessages is between 1 and 1000")
	}
	if b < 1 || b > maxCollect {
		return 0, 0, errors.New("maxBytes is between 1 and 1048576")
	}
	return n, b, nil
}

func seconds(v *float64, def, lo, hi float64) (time.Duration, error) {
	s := def
	if v != nil {
		s = *v
	}
	if s < lo || s > hi {
		return 0, fmt.Errorf("seconds is between %g and %g", lo, hi)
	}
	return time.Duration(s * float64(time.Second)), nil
}

// collect subscribes to filter and gathers messages until the limits, the
// time or (when settle is set) a quiet gap after the last message.
func (c *conn) collect(ctx context.Context, filters []string, qos byte, k *collector, d time.Duration, settle bool) (string, error) {
	k.full = make(chan struct{})
	s, err := c.connect(ctx)
	if err != nil {
		return "", err
	}
	defer s.close()
	deadline := time.Now().Add(d)
	subs := map[string]byte{}
	for _, f := range filters {
		subs[f] = qos
	}
	t := s.cl.SubscribeMultiple(subs, k.add)
	if err := c.wait(ctx, t); err != nil {
		return "", err
	}
	if st, ok := t.(*paho.SubscribeToken); ok {
		for _, f := range filters {
			if code, ok := st.Result()[f]; ok && code == 0x80 {
				return "", fmt.Errorf("the broker refused the subscription to %s (its access rules don't allow it)", f)
			}
		}
	}
	acked := time.Now()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-k.full:
			k.mu.Lock()
			defer k.mu.Unlock()
			return k.stop, nil
		case err := <-s.lost:
			if errors.Is(err, errTooBig) {
				return "a message over 1 MiB", nil
			}
			return "", fmt.Errorf("the broker closed the connection: %v", err)
		case <-ctx.Done():
			return "", ctx.Err()
		case now := <-tick.C:
			if now.After(deadline) {
				return "seconds", nil
			}
			if settle {
				k.mu.Lock()
				last := k.last
				k.mu.Unlock()
				if last.Before(acked) {
					last = acked
				}
				if now.Sub(last) >= c.settle {
					return "", nil // the retained messages are all in
				}
			}
		}
	}
}

// current reads the retained message on one topic (nil when there's none).
func (c *conn) current(ctx context.Context, topic string) (*message, error) {
	k := &collector{retainedOnly: true, maxN: 1, maxB: maxCollect}
	if _, err := c.collect(ctx, []string{topic}, 0, k, c.timeout, true); err != nil {
		return nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, m := range k.msgs {
		if m.topic == topic {
			return &m, nil
		}
	}
	return nil, nil
}

type pubInput struct {
	Topic    string `json:"topic"`
	Payload  string `json:"payload"`
	Encoding string `json:"encoding"`
	QoS      *int   `json:"qos"`
	Retain   bool   `json:"retain"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func preview(m *message) json.RawMessage {
	if m == nil {
		return mustJSON(map[string]any{"retained": nil})
	}
	e := m.out()
	if s, ok := e["payload"].(string); ok && len(s) > 500 {
		e["payload"] = s[:500] + "…"
	}
	if s, ok := e["payloadBase64"].(string); ok && len(s) > 500 {
		e["payloadBase64"] = s[:500] + "…"
	}
	return mustJSON(e)
}

// restore is the undo for replacing or clearing a retained message.
func restore(topic string, old *message, qos byte) *sdk.Undo {
	if old == nil {
		return sdk.UndoWith("clear_retained", map[string]string{"topic": topic}, "Clear the retained message on "+topic)
	}
	if len(old.payload) > maxUndoBytes {
		return nil
	}
	return sdk.UndoWith("publish", map[string]any{"topic": topic, "payload": base64.StdEncoding.EncodeToString(old.payload), "encoding": "base64", "retain": true, "qos": qos},
		"Put back the previous retained message on "+topic)
}

func (c *conn) send(ctx context.Context, topic string, qos byte, retain bool, payload []byte) error {
	s, err := c.connect(ctx)
	if err != nil {
		return err
	}
	defer s.close()
	return c.wait(ctx, s.cl.Publish(topic, qos, retain, payload))
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "subscribe_once":
		var p readInput
		if err := sdk.Decode(call, &p); err != nil {
			return sdk.Result{}, err
		}
		if err := validFilter(p.Filter); err != nil {
			return sdk.Result{}, fmt.Errorf("filter: %w", err)
		}
		n, b, err := limits(p, 100, 256<<10)
		if err != nil {
			return sdk.Result{}, err
		}
		d, err := seconds(p.Seconds, 3, 0.1, 30)
		if err != nil {
			return sdk.Result{}, err
		}
		qos := 0
		if p.QoS != nil {
			qos = *p.QoS
		}
		if qos != 0 && qos != 1 {
			return sdk.Result{}, errors.New("qos is 0 or 1")
		}
		k := &collector{maxN: n, maxB: b}
		stop, err := c.collect(ctx, []string{p.Filter}, byte(qos), k, d, false)
		if err != nil {
			return sdk.Result{}, err
		}
		k.mu.Lock()
		defer k.mu.Unlock()
		out := []map[string]any{}
		for _, msg := range k.msgs {
			out = append(out, msg.out())
		}
		return sdk.JSON(map[string]any{"filter": p.Filter, "count": len(out), "bytes": k.bytes, "stoppedBy": stop, "messages": out})

	case "retained":
		var p readInput
		if err := sdk.Decode(call, &p); err != nil {
			return sdk.Result{}, err
		}
		filters := []string{"#"}
		prefix := ""
		if p.Prefix != nil {
			prefix = strings.TrimSuffix(*p.Prefix, "/")
		}
		if prefix != "" {
			if err := validTopic(prefix); err != nil {
				return sdk.Result{}, fmt.Errorf("prefix: %w", err)
			}
			if err := checkDollar(prefix); err != nil {
				return sdk.Result{}, fmt.Errorf("prefix: %w", err)
			}
			// prefix/# covers the prefix itself in the spec, but not on
			// every broker.
			filters = []string{prefix, prefix + "/#"}
		}
		n, b, err := limits(p, 200, 512<<10)
		if err != nil {
			return sdk.Result{}, err
		}
		d, err := seconds(p.Seconds, 5, 0.5, 15)
		if err != nil {
			return sdk.Result{}, err
		}
		k := &collector{retainedOnly: true, maxN: n, maxB: b}
		stop, err := c.collect(ctx, filters, 0, k, d, true)
		if err != nil {
			return sdk.Result{}, err
		}
		k.mu.Lock()
		defer k.mu.Unlock()
		latest := map[string]message{}
		for _, msg := range k.msgs {
			latest[msg.topic] = msg
		}
		topics := make([]string, 0, len(latest))
		for t := range latest {
			topics = append(topics, t)
		}
		sort.Strings(topics)
		out := []map[string]any{}
		for _, t := range topics {
			e := latest[t].out()
			delete(e, "retained")
			out = append(out, e)
		}
		res := map[string]any{"prefix": prefix, "count": len(out), "bytes": k.bytes, "complete": stop == "", "messages": out}
		if stop != "" {
			res["stoppedBy"] = stop
		}
		return sdk.JSON(res)

	case "publish":
		var p pubInput
		if err := sdk.Decode(call, &p); err != nil {
			return sdk.Result{}, err
		}
		if err := c.allowed(p.Topic); err != nil {
			return sdk.Result{}, err
		}
		var payload []byte
		switch p.Encoding {
		case "", "text":
			if !utf8.ValidString(p.Payload) {
				return sdk.Result{}, errors.New("the payload isn't valid UTF-8; send binary as base64")
			}
			payload = []byte(p.Payload)
		case "base64":
			if payload, err = base64.StdEncoding.DecodeString(p.Payload); err != nil {
				return sdk.Result{}, errors.New("the payload isn't valid base64")
			}
		default:
			return sdk.Result{}, errors.New("encoding is text or base64")
		}
		if len(payload) > maxPublish {
			return sdk.Result{}, errors.New("the payload is larger than 256 KiB")
		}
		qos := 1
		if p.QoS != nil {
			qos = *p.QoS
		}
		if qos < 0 || qos > 2 {
			return sdk.Result{}, errors.New("qos is 0, 1 or 2")
		}
		if p.Retain && !c.retain {
			return sdk.Result{}, errors.New("retained messages are off: turn on allowRetain in the settings to publish with retain")
		}
		if p.Retain && len(payload) == 0 {
			return sdk.Result{}, errors.New("an empty retained message removes the retained one; use clear_retained")
		}
		var old *message
		if p.Retain {
			if old, err = c.current(ctx, p.Topic); err != nil {
				return sdk.Result{}, err
			}
		}
		next := &message{topic: p.Topic, payload: payload, retained: p.Retain, qos: byte(qos)}
		if call.DryRun {
			ch := sdk.Change{Target: "topic " + p.Topic, Op: "publish", After: preview(next)}
			summary := fmt.Sprintf("Publish %d bytes to %s", len(payload), p.Topic)
			if p.Retain {
				ch.Before = preview(old)
				summary += " (retained)"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{ch}}}, nil
		}
		if err := c.send(ctx, p.Topic, byte(qos), p.Retain, payload); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"topic": p.Topic, "bytes": len(payload), "qos": qos, "retained": p.Retain})
		if p.Retain {
			res.Undo = restore(p.Topic, old, byte(qos))
		}
		return res, err

	case "clear_retained":
		var p pubInput
		if err := sdk.Decode(call, &p); err != nil {
			return sdk.Result{}, err
		}
		if err := c.allowed(p.Topic); err != nil {
			return sdk.Result{}, err
		}
		if !c.retain {
			return sdk.Result{}, errors.New("retained messages are off: turn on allowRetain in the settings to clear one")
		}
		old, err := c.current(ctx, p.Topic)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			sum := "Clear the retained message on " + p.Topic
			if old == nil {
				sum = "There's no retained message on " + p.Topic + "; nothing would change"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "topic " + p.Topic, Op: "delete", Before: preview(old)}}}}, nil
		}
		if old == nil {
			return sdk.JSON(map[string]any{"topic": p.Topic, "cleared": false, "note": "there was no retained message on this topic"})
		}
		if err := c.send(ctx, p.Topic, 1, true, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"topic": p.Topic, "cleared": true, "bytes": len(old.payload)})
		if old.qos == 0 {
			old.qos = 1
		}
		res.Undo = restore(p.Topic, old, old.qos)
		return res, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	s, err := c.connect(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	s.close()
	msg := "connected to " + c.addr
	if c.user != "" {
		msg += " as " + c.user
	}
	if len(c.publish) == 0 {
		msg += " · read only"
	} else {
		msg += fmt.Sprintf(" · may publish to %d topic filter(s)", len(c.publish))
	}
	return sdk.Health{Status: "ok", Message: msg}
}
