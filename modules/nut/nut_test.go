package nut

import (
	"bufio"
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
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// fakeUPSD speaks enough of upsd's protocol for the module.
type fakeUPSD struct {
	ln       net.Listener
	tls      *tls.Config // nil: STARTTLS not configured
	mu       sync.Mutex
	lines    []string // every request, in order
	tlsLines []string // requests received after STARTTLS
	beeper   string
	track    bool
}

func (f *fakeUPSD) vars(ups string) [][2]string {
	switch ups {
	case "rack":
		return [][2]string{
			{"battery.charge", "100"}, {"battery.charge.low", "10"}, {"battery.runtime", "1860"}, {"battery.voltage", "27.1"},
			{"device.mfr", "CyberPower"}, {"device.model", "CP1500PFCLCD"}, {"input.voltage", "231.0"}, {"output.voltage", "230.0"},
			{"ups.load", "23"}, {"ups.realpower.nominal", "900"}, {"ups.status", "OL CHRG"}, {"ups.beeper.status", f.beeper},
			{"ups.test.result", "Done and \"passed\""}, {"driver.name", "usbhid-ups"},
		}
	case "desk":
		return [][2]string{{"battery.charge", "8"}, {"battery.charge.low", "10"}, {"battery.runtime", "240"}, {"ups.load", "61"},
			{"input.voltage", "0.0"}, {"ups.status", "OB DISCHRG RB"}, {"ups.alarm", "Replace battery!"}}
	}
	return nil
}

func (f *fakeUPSD) serve(t *testing.T) {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

func (f *fakeUPSD) handle(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := c
	var user, pass string
	secure := false
	send := func(s string) { fmt.Fprint(w, s+"\n") }
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\n")
		f.mu.Lock()
		f.lines = append(f.lines, line)
		if secure {
			f.tlsLines = append(f.tlsLines, line)
		}
		f.mu.Unlock()
		words, _ := split(line)
		if len(words) == 0 {
			send("ERR UNKNOWN-COMMAND")
			continue
		}
		switch {
		case line == "STARTTLS":
			if f.tls == nil {
				send("ERR FEATURE-NOT-CONFIGURED")
				continue
			}
			send("OK STARTTLS")
			tc := tls.Server(c, f.tls)
			if tc.Handshake() != nil {
				return
			}
			r, w, secure = bufio.NewReader(tc), tc, true
		case line == "LIST UPS":
			send("BEGIN LIST UPS")
			send(`UPS desk "Desk \"UPS\""`)
			send(`UPS rack "Rack UPS"`)
			send(`UPS stale "Unavailable"`)
			send("END LIST UPS")
		case len(words) == 3 && words[0] == "LIST" && words[1] == "VAR":
			if words[2] == "stale" {
				send("ERR DATA-STALE")
				continue
			}
			vs := f.vars(words[2])
			if vs == nil {
				send("ERR UNKNOWN-UPS")
				continue
			}
			send("BEGIN LIST VAR " + words[2])
			for _, v := range vs {
				send("VAR " + words[2] + " " + v[0] + ` "` + strings.ReplaceAll(v[1], `"`, `\"`) + `"`)
			}
			send("END LIST VAR " + words[2])
		case len(words) == 3 && words[0] == "LIST" && words[1] == "CMD":
			send("BEGIN LIST CMD " + words[2])
			for _, x := range []string{"beeper.disable", "beeper.enable", "load.off", "shutdown.return", "test.battery.start"} {
				if words[2] == "rack" || !strings.HasPrefix(x, "beeper") {
					send("CMD " + words[2] + " " + x)
				}
			}
			send("END LIST CMD " + words[2])
		case len(words) == 4 && words[0] == "GET" && words[1] == "VAR":
			found := false
			for _, v := range f.vars(words[2]) {
				if v[0] == words[3] {
					send("VAR " + words[2] + " " + v[0] + ` "` + v[1] + `"`)
					found = true
				}
			}
			if !found {
				send("ERR VAR-NOT-SUPPORTED")
			}
		case words[0] == "USERNAME" && len(words) == 2:
			user = words[1]
			send("OK")
		case words[0] == "PASSWORD" && len(words) == 2:
			pass = words[1]
			send("OK")
		case words[0] == "INSTCMD" && len(words) == 3:
			if user != "monuser" || pass != `pa ss"word` {
				send("ERR ACCESS-DENIED")
				continue
			}
			if words[1] != "rack" || !strings.HasPrefix(words[2], "beeper.") {
				send("ERR CMD-NOT-SUPPORTED")
				continue
			}
			f.mu.Lock()
			f.beeper = map[string]string{"beeper.disable": "disabled", "beeper.enable": "enabled"}[words[2]]
			f.mu.Unlock()
			if f.track {
				send("OK TRACKING 1bd31808-cb49-4aec-9d75-d056e6f018d2")
			} else {
				send("OK")
			}
		case words[0] == "GET" && len(words) == 3 && words[1] == "TRACKING":
			send("SUCCESS")
		case line == "LOGOUT":
			send("OK Goodbye")
			return
		default:
			send("ERR UNKNOWN-COMMAND")
		}
	}
}

func (f *fakeUPSD) sent() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.lines...)
}

func selfSigned(t *testing.T) (*tls.Config, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upsd"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, hex.EncodeToString(sum[:])
}

func start(t *testing.T, tc *tls.Config) *fakeUPSD {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUPSD{ln: ln, tls: tc, beeper: "enabled"}
	t.Cleanup(func() { ln.Close() })
	go f.serve(t)
	return f
}

var secrets = map[string]string{"secret://pw": `pa ss"word`, "secret://bad": "wrong"}

func configure(t *testing.T, f *fakeUPSD, c Config) *Module {
	m := New()
	c.Address = f.ln.Addr().String()
	raw, _ := json.Marshal(c)
	if err := m.Configure(context.Background(), fakehost.New(secrets), "u", raw); err != nil {
		t.Fatal(err)
	}
	return m
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "u", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestNUTRead(t *testing.T) {
	f := start(t, nil)
	m := configure(t, f, Config{})
	h := m.Health(context.Background(), "u")
	if h.Status != "degraded" || !strings.Contains(h.Message, "upsd · 3 UPS") || !strings.Contains(h.Message, "desk on battery") || !strings.Contains(h.Message, "stale") || strings.Contains(h.Message, "TLS") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"upses", `{}`, `{"batteryCharge":100,"batteryRuntimeSeconds":1860,"description":"Rack UPS","flags":["online","charging"],"inputVoltage":231,"loadPercent":23,"onBattery":false,"status":"OL CHRG","ups":"rack","watts":207,"wattsEstimated":true}`},
		{"upses", `{}`, `"description":"Desk \"UPS\""`},
		{"upses", `{}`, `{"description":"Unavailable","error":"upsd's data for this UPS is stale (the driver lost contact with the UPS)","ups":"stale"}`},
		{"status", `{"ups":"rack@nas"}`, `"lastSelfTest":"Done and \"passed\""`},
		{"status", `{"ups":"rack"}`, `"alarms":[]`},
		{"status", `{"ups":"desk"}`, `"flags":["on battery","discharging","replace battery"]`},
		{"alarms", `{}`, `{"ups":"desk","severity":"warning","alarm":"on battery, about 4 min left"}`},
		{"alarms", `{}`, `{"ups":"desk","severity":"critical","alarm":"battery at 8%, at or below its low mark of 10%"}`},
		{"alarms", `{}`, `{"ups":"desk","severity":"warning","alarm":"Replace battery!"}`},
		{"alarms", `{}`, `"count":5`},
		{"variables", `{"ups":"rack"}`, `{"name":"ups.status","value":"OL CHRG"}`},
		{"commands", `{"ups":"rack"}`, `{"command":"beeper.disable","conduitSends":true}`},
		{"commands", `{"ups":"rack"}`, `{"command":"shutdown.return","conduitSends":false}`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if _, err := invoke(m, "status", `{}`, false); err == nil || !strings.Contains(err.Error(), "several UPSes; name one (desk, rack, stale)") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "status", `{"ups":"garage"}`, false); err == nil || !strings.Contains(err.Error(), "no UPS garage") {
		t.Fatal(err)
	}
	for _, l := range f.sent() {
		if strings.HasPrefix(l, "LOGIN") || strings.HasPrefix(l, "INSTCMD") || strings.HasPrefix(l, "USERNAME") {
			t.Fatalf("reads sent %q", l)
		}
	}
}

func TestNUTBeeper(t *testing.T) {
	f := start(t, nil)
	f.track = true
	m := configure(t, f, Config{Username: "monuser", Password: "secret://pw"})
	p, err := invoke(m, "beeper_disable", `{"ups":"rack"}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Silence the beeper on UPS rack" || string(p.Plan.Changes[0].Before) != `{"beeper":"enabled"}` {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	for _, l := range f.sent() {
		if strings.HasPrefix(l, "INSTCMD") || strings.HasPrefix(l, "PASSWORD") {
			t.Fatal("dry run sent", l)
		}
	}
	r, err := invoke(m, "beeper_disable", `{"ups":"rack"}`, false)
	if err != nil || f.beeper != "disabled" || r.Undo == nil || r.Undo.Action != "beeper_enable" || string(r.Undo.Input) != `{"ups":"rack"}` ||
		!strings.Contains(string(r.Output), `"beeper":"disabled"`) {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	sent := strings.Join(f.sent(), "\n")
	if !strings.Contains(sent, "USERNAME \"monuser\"\nPASSWORD \"pa ss\\\"word\"\nINSTCMD rack beeper.disable\nGET TRACKING 1bd31808-cb49-4aec-9d75-d056e6f018d2") {
		t.Fatal(sent)
	}
	if r2, err := invoke(m, "beeper_disable", `{"ups":"rack"}`, false); err != nil || r2.Undo != nil || !strings.Contains(string(r2.Output), `"changed":false`) {
		t.Fatalf("%s %v", r2.Output, err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.beeper != "enabled" || r.Undo.Action != "beeper_disable" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "beeper_enable", `{"ups":"desk"}`, false); err == nil || !strings.Contains(err.Error(), "doesn't offer beeper.enable") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if strings.HasPrefix(a.Name, "beeper_") != (a.Risk == sdk.RiskWrite && a.Reversible && a.DryRun) || strings.Contains(a.Name, "shutdown") || a.Name == "instcmd" {
			t.Fatal(a.Name)
		}
	}

	bad := configure(t, f, Config{Username: "monuser", Password: "secret://bad"})
	if _, err := invoke(bad, "beeper_disable", `{"ups":"rack"}`, false); err == nil || !strings.Contains(err.Error(), "wrong username or password") || f.beeper != "enabled" {
		t.Fatal(err)
	}
	anon := configure(t, f, Config{})
	n := len(f.sent())
	if _, err := invoke(anon, "beeper_disable", `{"ups":"rack"}`, false); err == nil || !strings.Contains(err.Error(), "need a upsd user") {
		t.Fatal(err)
	}
	for _, l := range f.sent()[n:] {
		if strings.HasPrefix(l, "INSTCMD") {
			t.Fatal("sent without credentials")
		}
	}
}

func TestNUTRefusesShutdown(t *testing.T) {
	f := start(t, nil)
	m := configure(t, f, Config{Username: "monuser", Password: "secret://pw"})
	for _, c := range []struct{ action, in string }{
		{"beeper_disable", `{"ups":"rack","command":"shutdown.return"}`},
		{"beeper_enable", `{"ups":"rack","cmd":"load.off"}`},
		{"beeper_enable", `{"ups":"rack\nINSTCMD rack shutdown.stayoff"}`},
		{"beeper_enable", `{"ups":"rack shutdown.stayoff"}`},
		{"status", `{"ups":"rack\"; LOGOUT"}`},
		{"variables", `{"ups":"../x"}`},
		{"instcmd", `{"ups":"rack","command":"shutdown.return"}`},
		{"shutdown", `{"ups":"rack"}`},
		{"load_off", `{"ups":"rack"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if s := f.sent(); len(s) != 0 {
		t.Fatalf("refused input reached upsd: %q", s)
	}
	c, _ := m.set.Get("u")
	s, err := c.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	for _, cmd := range []string{"shutdown.return", "shutdown.stayoff", "load.off", "load.off.delay", "load.on", "outlet.1.load.off", "test.battery.start", "calibrate.start", "beeper.toggle", "BEEPER.DISABLE "} {
		err := c.instcmd(context.Background(), s, "rack", cmd)
		if err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("%s: %v", cmd, err)
		}
		if strings.HasPrefix(cmd, "shutdown") || strings.Contains(cmd, "load.") {
			if !strings.Contains(err.Error(), "never sends shutdown") {
				t.Fatalf("%s: %v", cmd, err)
			}
		}
	}
	for _, l := range f.sent() {
		if strings.HasPrefix(l, "INSTCMD") || strings.HasPrefix(l, "USERNAME") {
			t.Fatalf("sent %q", l)
		}
	}
}

func TestNUTTLS(t *testing.T) {
	tc, fp := selfSigned(t)
	f := start(t, tc)
	m := configure(t, f, Config{Username: "monuser", Password: "secret://pw", TLS: "require", Fingerprint: fp})
	if h := m.Health(context.Background(), "u"); !strings.Contains(h.Message, "TLS") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(m, "beeper_disable", `{"ups":"rack"}`, false); err != nil || f.beeper != "disabled" {
		t.Fatal(err)
	}
	f.mu.Lock()
	inTLS := strings.Join(f.tlsLines, "\n")
	f.mu.Unlock()
	if !strings.Contains(inTLS, "PASSWORD") || !strings.Contains(inTLS, "INSTCMD") {
		t.Fatalf("credentials not sent inside TLS: %s", inTLS)
	}
	wrong := configure(t, f, Config{TLS: "require", Fingerprint: strings.Repeat("ab", 32)})
	if h := wrong.Health(context.Background(), "u"); h.Status != "down" || !strings.Contains(h.Message, "fingerprint") {
		t.Fatalf("%+v", h)
	}

	plain := start(t, nil)
	req := configure(t, plain, Config{Username: "monuser", Password: "secret://pw", TLS: "require", InsecureSkipVerify: true})
	if _, err := invoke(req, "beeper_disable", `{"ups":"rack"}`, false); err == nil || !strings.Contains(err.Error(), "doesn't offer STARTTLS") {
		t.Fatal(err)
	}
	if s := plain.sent(); len(s) < 1 || s[0] != "STARTTLS" || strings.Contains(strings.Join(s, " "), "PASSWORD") || strings.Contains(strings.Join(s, " "), "LIST") {
		t.Fatalf("talked to upsd without TLS: %q", s)
	}
	auto := configure(t, plain, Config{})
	if h := auto.Health(context.Background(), "u"); h.Status != "degraded" {
		t.Fatalf("%+v", h)
	}
	off := configure(t, plain, Config{TLS: "off"})
	n := len(plain.sent())
	off.Health(context.Background(), "u")
	if after := strings.Join(plain.sent()[n:], " "); strings.Contains(after, "STARTTLS") || !strings.Contains(after, "LIST UPS") {
		t.Fatal(plain.sent()[n:])
	}
}

func TestNUTSettings(t *testing.T) {
	for _, c := range []Config{
		{Address: "nas.local", Username: "u", Password: "plaintext"},
		{Address: "nas.local", Username: "u"},
		{Address: "nas.local", Password: "secret://pw"},
		{Address: "nas.local", Username: "a b", Password: "secret://pw"},
		{Address: "nas.local", Username: "a\nINSTCMD", Password: "secret://pw"},
		{Address: "nas local"},
		{Address: "nas.local:99999"},
		{Address: "-nas"},
		{Address: ""},
		{Address: "nas.local", TLS: "maybe"},
		{Address: "nas.local", TLS: "off", Fingerprint: strings.Repeat("ab", 32)},
		{Address: "nas.local", Fingerprint: "nope"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	for _, a := range []string{"nas.local", "nas.local:3493", "192.168.1.10", "[::1]:3493", "nut://nas.local"} {
		raw, _ := json.Marshal(Config{Address: a})
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err != nil {
			t.Fatalf("%s: %v", a, err)
		}
	}
	if New().Health(context.Background(), "nope").Status != "unconfigured" {
		t.Fatal("health of a missing instance")
	}
}

func TestSplit(t *testing.T) {
	got, err := split(`VAR ups ups.alarm "a \"b\" \\ c" ""`)
	if err != nil || len(got) != 5 || got[3] != `a "b" \ c` || got[4] != "" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := split(`VAR "open`); err == nil {
		t.Fatal("unterminated quote")
	}
}
