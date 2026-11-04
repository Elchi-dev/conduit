// Package mqttx is the MQTT 3.1.1 client shared by the modules that talk to
// a broker (mqtt, zigbee2mqtt): checking a broker address and credentials,
// short connections with a clean session through the instance's network,
// a guard against oversized packets, topic and filter validation, and
// collecting the messages on a set of filters for a while.
package mqttx

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	paho "github.com/eclipse/paho.mqtt.golang"
	"github.com/eclipse/paho.mqtt.golang/packets"

	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	MaxTopic      = 1024    // bytes in a topic or filter we accept
	MaxCollect    = 1 << 20 // bytes of payload one read collects
	MaxPacket     = MaxCollect + 64<<10
	DefaultPrefix = "conduit"
)

var prefixRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,14}$`)

// Options are the connection settings of one broker.
type Options struct {
	URL      string // mqtt://broker.local:1883 or mqtts://broker.local:8883
	Username string
	Password string // secret://, with Username
	// ClientIDPrefix starts the client id of every connection; a random
	// suffix keeps two calls from taking each other's session.
	ClientIDPrefix     string
	Fingerprint        string
	InsecureSkipVerify bool
}

// Broker is a validated broker address with its credentials.
type Broker struct {
	Host   sdk.Host
	Addr   string      // host:port
	TLS    *tls.Config // nil for plain TCP
	User   string
	Pass   string // secret:// reference
	Prefix string
	Dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	// Timeout bounds connecting and each acknowledgement.
	Timeout time.Duration
	// Settle is how long to wait after the subscription is acknowledged
	// for the broker's retained messages to stop arriving.
	Settle time.Duration
}

// New checks the options and returns the broker they describe.
func New(h sdk.Host, o Options) (*Broker, error) {
	u, err := url.Parse(strings.TrimSpace(o.URL))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return nil, errors.New("the broker is like mqtt://broker.local:1883 or mqtts://broker.local:8883")
	}
	secure := false
	port := "1883"
	switch strings.ToLower(u.Scheme) {
	case "mqtt", "tcp":
	case "mqtts", "ssl", "tls":
		secure, port = true, "8883"
	default:
		return nil, errors.New("the broker is like mqtt://broker.local:1883 or mqtts://broker.local:8883 (WebSocket brokers aren't supported)")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, errors.New("the broker's port is a number up to 65535")
		}
		port = p
	}
	hostname := u.Hostname()
	user := o.Username
	if strings.TrimSpace(user) != user || len(user) > 256 || HasControl(user) {
		return nil, errors.New("the username has spaces at the ends, control characters or is too long")
	}
	if o.Password != "" && !strings.HasPrefix(o.Password, "secret://") {
		return nil, errors.New("store the password in the vault and enter its secret:// reference")
	}
	if o.Password != "" && user == "" {
		return nil, errors.New("enter the username too (MQTT has no password without a username)")
	}
	prefix := o.ClientIDPrefix
	if prefix == "" {
		prefix = DefaultPrefix
	}
	if !prefixRe.MatchString(prefix) {
		return nil, errors.New("the client id prefix is up to 14 letters, digits, - and _")
	}
	if !secure && (o.Fingerprint != "" || o.InsecureSkipVerify) {
		return nil, errors.New("the certificate settings need a TLS broker address (mqtts://)")
	}
	b := &Broker{Host: h, Addr: net.JoinHostPort(hostname, port), User: user, Pass: o.Password, Prefix: prefix,
		Dial: sdk.DialContext(h), Timeout: 10 * time.Second, Settle: 400 * time.Millisecond}
	if secure {
		tc, err := tlspin.Config(o.Fingerprint, o.InsecureSkipVerify)
		if err != nil {
			return nil, err
		}
		tc.ServerName = hostname
		b.TLS = tc
	}
	return b, nil
}

// HasControl reports whether s has a control character.
func HasControl(s string) bool {
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
	case len(s) > MaxTopic:
		return fmt.Errorf("it's longer than %d bytes", MaxTopic)
	case !utf8.ValidString(s):
		return errors.New("it isn't valid UTF-8")
	case HasControl(s):
		return errors.New("it has control characters")
	}
	return nil
}

// ValidTopic checks a topic to publish to: no wildcards.
func ValidTopic(t string) error {
	if err := checkChars(t); err != nil {
		return err
	}
	if strings.ContainsAny(t, "+#") {
		return errors.New("a topic to publish to has no + or # wildcards")
	}
	return nil
}

// CheckDollar keeps subscriptions out of the broker's special $ namespaces
// except $SYS (its read-only statistics). $share/<group>/... and
// $queue/... don't read a topic: they join a shared subscription, so the
// broker diverts part of that group's messages away from its real consumers
// to Conduit. Any other $ prefix is refused too, in any letter case.
func CheckDollar(f string) error {
	if !strings.HasPrefix(f, "$") || f == "$SYS" || strings.HasPrefix(f, "$SYS/") {
		return nil
	}
	return errors.New("filters starting with $ are only allowed under $SYS/ ($share/ and $queue/ would take messages away from a shared subscription's consumers)")
}

// ValidFilter checks a subscription filter: + only as a whole level, # only
// as the whole last level, and $ only for $SYS.
func ValidFilter(f string) error {
	if err := checkChars(f); err != nil {
		return err
	}
	if err := CheckDollar(f); err != nil {
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

// Matches reports whether a topic is matched by a filter, per MQTT 3.1.1
// 4.7: wildcards at the start don't match topics beginning with $.
func Matches(filter, topic string) bool {
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

// ErrTooBig ends a connection whose broker sent an oversized packet.
var ErrTooBig = errors.New("the broker sent a message larger than 1 MiB")

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
				g.err = ErrTooBig
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

func (b *Broker) open(ctx context.Context) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	raw, err := b.Dial(dctx, "tcp", b.Addr)
	if err != nil {
		return nil, fmt.Errorf("can't reach the broker at %s: %w", b.Addr, err)
	}
	nc := raw
	if b.TLS != nil {
		tc := tls.Client(raw, b.TLS.Clone())
		if err := tc.HandshakeContext(dctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("TLS with the broker failed: %w", err)
		}
		nc = tc
	}
	return &guard{Conn: nc, max: MaxPacket}, nil
}

func randomID(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

// RandomHex returns n random bytes in hex (transaction ids and the like).
func RandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// wait waits for a token, the context or the timeout.
func (b *Broker) wait(ctx context.Context, t paho.Token) error {
	select {
	case <-t.Done():
		return t.Error()
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(b.Timeout):
		return errors.New("the broker didn't answer in time")
	}
}

// Session is one connection to the broker.
type Session struct {
	b    *Broker
	cl   paho.Client
	lost chan error
}

// Close disconnects.
func (s *Session) Close() { s.cl.Disconnect(100) }

// Lost delivers the error that ended the connection.
func (s *Session) Lost() <-chan error { return s.lost }

// Connect opens a connection with a clean session and a random client id.
func (b *Broker) Connect(ctx context.Context) (*Session, error) {
	pw := ""
	if b.Pass != "" {
		var err error
		if pw, err = b.Host.Secret(ctx, b.Pass); err != nil {
			return nil, err
		}
	}
	s := &Session{b: b, lost: make(chan error, 1)}
	o := paho.NewClientOptions()
	o.AddBroker("tcp://" + b.Addr) // the address the custom dialer below uses
	o.SetClientID(randomID(b.Prefix))
	o.SetProtocolVersion(4)
	o.SetCleanSession(true)
	o.SetAutoReconnect(false)
	o.SetConnectRetry(false)
	o.SetResumeSubs(false)
	o.SetConnectTimeout(b.Timeout)
	o.SetWriteTimeout(b.Timeout)
	o.SetKeepAlive(30 * time.Second)
	o.SetPingTimeout(b.Timeout)
	o.SetOrderMatters(true)
	if b.User != "" {
		o.SetUsername(b.User)
		o.SetPassword(pw)
	}
	o.SetCustomOpenConnectionFn(func(*url.URL, paho.ClientOptions) (net.Conn, error) { return b.open(ctx) })
	o.SetConnectionLostHandler(func(_ paho.Client, err error) {
		select {
		case s.lost <- err:
		default:
		}
	})
	s.cl = paho.NewClient(o)
	if err := b.wait(ctx, s.cl.Connect()); err != nil {
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

// Message is one message received.
type Message struct {
	Topic    string
	Payload  []byte
	Retained bool
	QoS      byte
}

// Subscribe subscribes to the filters and calls h for each message; it
// fails when the broker refuses one of them.
func (s *Session) Subscribe(ctx context.Context, filters []string, qos byte, h func(Message)) error {
	subs := map[string]byte{}
	for _, f := range filters {
		subs[f] = qos
	}
	t := s.cl.SubscribeMultiple(subs, func(_ paho.Client, m paho.Message) {
		h(Message{Topic: m.Topic(), Payload: append([]byte(nil), m.Payload()...), Retained: m.Retained(), QoS: m.Qos()})
	})
	if err := s.b.wait(ctx, t); err != nil {
		return err
	}
	if st, ok := t.(*paho.SubscribeToken); ok {
		for _, f := range filters {
			if code, ok := st.Result()[f]; ok && code == 0x80 {
				return fmt.Errorf("the broker refused the subscription to %s (its access rules don't allow it)", f)
			}
		}
	}
	return nil
}

// Publish sends one message and waits for its acknowledgement (QoS 1, 2).
func (s *Session) Publish(ctx context.Context, topic string, qos byte, retain bool, payload []byte) error {
	return s.b.wait(ctx, s.cl.Publish(topic, qos, retain, payload))
}

// Send publishes one message on its own connection.
func (b *Broker) Send(ctx context.Context, topic string, qos byte, retain bool, payload []byte) error {
	s, err := b.Connect(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Publish(ctx, topic, qos, retain, payload)
}

// Collector gathers messages up to its limits.
type Collector struct {
	RetainedOnly bool
	MaxN, MaxB   int
	mu           sync.Mutex
	msgs         []Message
	seen         map[string]int // RetainedOnly: topic → index in msgs
	bytes        int
	last         time.Time
	stop         string
	full         chan struct{}
}

// Add takes one message.
func (k *Collector) Add(m Message) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.stop != "" || (k.RetainedOnly && !m.Retained) {
		return
	}
	if k.bytes+len(m.Payload) > k.MaxB {
		k.stop = "maxBytes"
		close(k.full)
		return
	}
	if k.RetainedOnly {
		// One per topic: overlapping filters can bring a topic twice.
		if i, ok := k.seen[m.Topic]; ok {
			k.bytes += len(m.Payload) - len(k.msgs[i].Payload)
			k.msgs[i] = m
			k.last = time.Now()
			return
		}
		if k.seen == nil {
			k.seen = map[string]int{}
		}
		k.seen[m.Topic] = len(k.msgs)
	}
	k.msgs = append(k.msgs, m)
	k.bytes += len(m.Payload)
	k.last = time.Now()
	if len(k.msgs) >= k.MaxN {
		k.stop = "maxMessages"
		close(k.full)
	}
}

// Messages returns what was collected, in arrival order.
func (k *Collector) Messages() []Message {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]Message(nil), k.msgs...)
}

// Bytes returns the payload bytes collected.
func (k *Collector) Bytes() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.bytes
}

// Collect subscribes to the filters and gathers messages until the limits,
// the time or (when settle is set) a quiet gap after the last message. It
// returns what stopped it: "" when settled, "seconds", "maxMessages",
// "maxBytes" or "a message over 1 MiB".
func (b *Broker) Collect(ctx context.Context, filters []string, qos byte, k *Collector, d time.Duration, settle bool) (string, error) {
	s, err := b.Connect(ctx)
	if err != nil {
		return "", err
	}
	defer s.Close()
	return s.Collect(ctx, filters, qos, k, d, settle, nil)
}

// Collect is Broker.Collect on an open session. after, when set, runs once
// the subscription is acknowledged (to publish a request whose answer is
// collected).
func (s *Session) Collect(ctx context.Context, filters []string, qos byte, k *Collector, d time.Duration, settle bool, after func() error) (string, error) {
	k.mu.Lock()
	k.full = make(chan struct{})
	k.mu.Unlock()
	deadline := time.Now().Add(d)
	if err := s.Subscribe(ctx, filters, qos, k.Add); err != nil {
		return "", err
	}
	if after != nil {
		if err := after(); err != nil {
			return "", err
		}
	}
	acked := time.Now()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-k.full:
			k.mu.Lock()
			defer k.mu.Unlock()
			return k.stop, nil
		case err := <-s.lost:
			if errors.Is(err, ErrTooBig) {
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
				if now.Sub(last) >= s.b.Settle {
					return "", nil // the retained messages are all in
				}
			}
		}
	}
}

// Current reads the retained message on one topic (nil when there's none).
func (b *Broker) Current(ctx context.Context, topic string) (*Message, error) {
	k := &Collector{RetainedOnly: true, MaxN: 1, MaxB: MaxCollect}
	if _, err := b.Collect(ctx, []string{topic}, 0, k, b.Timeout, true); err != nil {
		return nil, err
	}
	for _, m := range k.Messages() {
		if m.Topic == topic {
			return &m, nil
		}
	}
	return nil, nil
}
