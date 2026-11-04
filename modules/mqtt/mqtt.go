// Package mqtt works with any MQTT broker (Mosquitto, EMQX, HiveMQ, the
// Home Assistant add-on, ...) over MQTT 3.1.1: collecting the messages on a
// topic filter for a few seconds, a snapshot of the retained messages under
// a prefix, and publishing to topics the settings allow. Every call opens
// its own short connection with a clean session, so nothing stays
// subscribed between calls.
package mqtt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/mqttx"
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
	*mqttx.Broker
	publish []string
	retain  bool
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
}

// New returns the MQTT module.
func New() *Module { return &Module{} }

const (
	maxPublish   = 256 << 10 // bytes in a published payload
	maxCollect   = mqttx.MaxCollect
	maxUndoBytes = 64 << 10 // a previous retained message larger than this gets no undo
)

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
	b, err := mqttx.New(h, mqttx.Options{URL: c.URL, Username: c.Username, Password: c.Password, ClientIDPrefix: c.ClientIDPrefix,
		Fingerprint: c.Fingerprint, InsecureSkipVerify: c.InsecureSkipVerify})
	if err != nil {
		return err
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
	cn := &conn{Broker: b, publish: pub, retain: c.AllowRetain}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func validTopic(t string) error  { return mqttx.ValidTopic(t) }
func validFilter(f string) error { return mqttx.ValidFilter(f) }
func checkDollar(f string) error { return mqttx.CheckDollar(f) }
func matches(f, t string) bool   { return mqttx.Matches(f, t) }

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

type message = mqttx.Message

func msgOut(m message) map[string]any {
	e := map[string]any{"topic": m.Topic, "bytes": len(m.Payload)}
	if m.Retained {
		e["retained"] = true
	}
	if m.QoS > 0 {
		e["qos"] = m.QoS
	}
	if utf8.Valid(m.Payload) {
		e["payload"] = string(m.Payload)
	} else {
		e["payloadBase64"] = base64.StdEncoding.EncodeToString(m.Payload)
	}
	return e
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
	e := msgOut(*m)
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
	if len(old.Payload) > maxUndoBytes {
		return nil
	}
	return sdk.UndoWith("publish", map[string]any{"topic": topic, "payload": base64.StdEncoding.EncodeToString(old.Payload), "encoding": "base64", "retain": true, "qos": qos},
		"Put back the previous retained message on "+topic)
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
		k := &mqttx.Collector{MaxN: n, MaxB: b}
		stop, err := c.Collect(ctx, []string{p.Filter}, byte(qos), k, d, false)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, msg := range k.Messages() {
			out = append(out, msgOut(msg))
		}
		return sdk.JSON(map[string]any{"filter": p.Filter, "count": len(out), "bytes": k.Bytes(), "stoppedBy": stop, "messages": out})

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
		k := &mqttx.Collector{RetainedOnly: true, MaxN: n, MaxB: b}
		stop, err := c.Collect(ctx, filters, 0, k, d, true)
		if err != nil {
			return sdk.Result{}, err
		}
		latest := map[string]message{}
		for _, msg := range k.Messages() {
			latest[msg.Topic] = msg
		}
		topics := make([]string, 0, len(latest))
		for t := range latest {
			topics = append(topics, t)
		}
		sort.Strings(topics)
		out := []map[string]any{}
		for _, t := range topics {
			e := msgOut(latest[t])
			delete(e, "retained")
			out = append(out, e)
		}
		res := map[string]any{"prefix": prefix, "count": len(out), "bytes": k.Bytes(), "complete": stop == "", "messages": out}
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
			if old, err = c.Current(ctx, p.Topic); err != nil {
				return sdk.Result{}, err
			}
		}
		next := &message{Topic: p.Topic, Payload: payload, Retained: p.Retain, QoS: byte(qos)}
		if call.DryRun {
			ch := sdk.Change{Target: "topic " + p.Topic, Op: "publish", After: preview(next)}
			summary := fmt.Sprintf("Publish %d bytes to %s", len(payload), p.Topic)
			if p.Retain {
				ch.Before = preview(old)
				summary += " (retained)"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{ch}}}, nil
		}
		if err := c.Send(ctx, p.Topic, byte(qos), p.Retain, payload); err != nil {
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
		old, err := c.Current(ctx, p.Topic)
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
		if err := c.Send(ctx, p.Topic, 1, true, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"topic": p.Topic, "cleared": true, "bytes": len(old.Payload)})
		if old.QoS == 0 {
			old.QoS = 1
		}
		res.Undo = restore(p.Topic, old, old.QoS)
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
	s, err := c.Connect(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	s.Close()
	msg := "connected to " + c.Addr
	if c.User != "" {
		msg += " as " + c.User
	}
	if len(c.publish) == 0 {
		msg += " · read only"
	} else {
		msg += fmt.Sprintf(" · may publish to %d topic filter(s)", len(c.publish))
	}
	return sdk.Health{Status: "ok", Message: msg}
}
