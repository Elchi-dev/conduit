// Package nut works with Network UPS Tools through upsd's network protocol
// (TCP, port 3493): the UPSes upsd serves with their status, battery,
// runtime, load and input voltage, the alarms they raise, their variables
// and instant commands, and turning a UPS's beeper off or on.
//
// It never sends any other instant command. Shutdown, load.off/load.on,
// calibration and battery tests can cut power to whatever the UPS feeds, so
// the module has no generic instcmd action and refuses those commands even
// if asked for one by name. It also never sends LOGIN, which would register
// it with upsd as a client that upsmon waits for during a shutdown.
package nut

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one upsd.
type Config struct {
	Address            string `json:"address"`  // host or host:port, default port 3493
	Username           string `json:"username"` // from upsd.users, for the beeper commands
	Password           string `json:"password"` // secret://
	TLS                string `json:"tls"`      // "auto" (default), "require" or "off"
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	host    sdk.Host
	addr    string
	user    string
	pass    string // secret:// reference
	mode    string
	tls     *tls.Config
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	timeout time.Duration
	// track is how long to wait for a tracked instant command to finish.
	track time.Duration
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
}

// New returns the NUT module.
func New() *Module { return &Module{} }

const (
	defaultPort = "3493"
	maxLine     = 4096 // upsd's own limit on a line is lower
	maxItems    = 5000 // entries in one LIST answer
	maxUPS      = 64   // UPSes whose variables are read in one call
)

var (
	// upsRe is what a UPS name in ups.conf may be (no spaces, quotes or
	// newlines, so it can't add arguments or commands to a request).
	upsRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	hostRe = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
)

// allowed are the only instant commands the module ever sends.
var allowed = map[string]bool{"beeper.disable": true, "beeper.enable": true}

// refuseCommand explains why an instant command will not be sent.
func refuseCommand(cmd string) error {
	if allowed[cmd] {
		return nil
	}
	c := strings.ToLower(strings.TrimSpace(cmd))
	for _, p := range []string{"shutdown.", "load.off", "load.on", "calibrate.", "test.", "bypass.", "reset.", "outlet."} {
		if strings.HasPrefix(c, p) || strings.Contains(c, "."+strings.TrimSuffix(p, ".")) {
			return fmt.Errorf("refusing %q: Conduit never sends shutdown, load, outlet, test or calibration commands to a UPS; use upsmon or upscmd for those", cmd)
		}
	}
	return fmt.Errorf("refusing %q: the only instant commands Conduit sends are beeper.disable and beeper.enable", cmd)
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	ups := `"ups":{"type":"string","description":"UPS name as upsd knows it (e.g. ups for ups@nas); may be left out when upsd serves one UPS"}`
	beeper := `{"type":"object","properties":{` + ups + `}}`
	return sdk.Manifest{
		ID: "nut", Name: "Network UPS Tools", Version: "0.1.0", Category: "Infrastructure", Icon: "battery",
		Description: "UPSes through NUT's upsd: status, battery charge and runtime, load, input voltage, alarms, and the beeper. Never sends shutdown or load commands.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["address"],"properties":{
			"address":{"type":"string","description":"upsd's host, with :port when it isn't 3493 (e.g. nas.local or 192.168.1.10:3493)"},
			"username":{"type":"string","description":"A upsd.users user allowed instcmds = beeper.disable, beeper.enable; only needed for the beeper actions"},
			"password":{"type":"string","x-secret":true,"description":"That user's password"},
			"tls":{"type":"string","enum":["auto","require","off"],"default":"auto","description":"STARTTLS: auto uses it when upsd offers it, require refuses to talk without it, off never asks"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of upsd's certificate (CERTFILE in upsd.conf is usually self-signed)"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "upses", Title: "UPSes", Description: "Every UPS upsd serves with its status, battery charge, runtime and load.", Risk: sdk.RiskRead},
			{Name: "status", Title: "Status", Description: "One UPS: status flags, battery charge, runtime and voltage, load and estimated watts, input and output voltage, temperature, beeper, last self-test, alarms.", Risk: sdk.RiskRead,
				Input: sdk.Schema(beeper)},
			{Name: "alarms", Title: "Alarms", Description: "What needs attention across all UPSes: on battery, low battery, replace battery, overload, forced shutdown, driver alarms, stale data.", Risk: sdk.RiskRead},
			{Name: "variables", Title: "Variables", Description: "All of a UPS's variables (as upsc shows them).", Risk: sdk.RiskRead, Input: sdk.Schema(beeper)},
			{Name: "commands", Title: "Instant commands", Description: "The instant commands the UPS's driver offers, and which of them Conduit will send (only the beeper ones).", Risk: sdk.RiskRead, Input: sdk.Schema(beeper)},
			{Name: "beeper_disable", Title: "Silence beeper", Description: "Turns the UPS's audible alarm off (instcmd beeper.disable). Undo turns it back on. Destructive because a silenced UPS no longer warns anyone nearby of a power failure or a failing battery.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true, Input: sdk.Schema(beeper)},
			{Name: "beeper_enable", Title: "Enable beeper", Description: "Turns the UPS's audible alarm on (instcmd beeper.enable). Undo turns it off again.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true, Input: sdk.Schema(beeper)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	addr := strings.TrimSpace(c.Address)
	addr = strings.TrimPrefix(strings.TrimPrefix(addr, "nut://"), "tcp://")
	hostname, port := addr, defaultPort
	if hp, pp, err := net.SplitHostPort(addr); err == nil {
		hostname, port = hp, pp
	}
	if ip := net.ParseIP(strings.Trim(hostname, "[]")); ip != nil {
		hostname = ip.String()
	} else if !hostRe.MatchString(hostname) || strings.HasPrefix(hostname, "-") {
		return errors.New("the address is upsd's host, like nas.local or 192.168.1.10:3493")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return errors.New("the port is a number up to 65535")
	}
	user := c.Username
	if strings.TrimSpace(user) != user || len(user) > 64 || hasControl(user) || strings.ContainsAny(user, " \"\\") {
		return errors.New("the username has spaces, quotes, control characters or is too long")
	}
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	if (c.Password == "") != (user == "") {
		return errors.New("enter both the username and the password, or neither")
	}
	mode := strings.ToLower(strings.TrimSpace(c.TLS))
	switch mode {
	case "":
		mode = "auto"
	case "auto", "require", "off":
	default:
		return errors.New(`tls is "auto", "require" or "off"`)
	}
	if mode == "off" && (c.Fingerprint != "" || c.InsecureSkipVerify) {
		return errors.New("the certificate settings need tls set to auto or require")
	}
	if c.Fingerprint != "" && mode == "auto" {
		mode = "require" // a pinned certificate means upsd has TLS; don't fall back
	}
	cn := &conn{host: h, addr: net.JoinHostPort(hostname, port), user: user, pass: c.Password, mode: mode,
		dial: sdk.DialContext(h), timeout: 10 * time.Second, track: 5 * time.Second}
	if mode != "off" {
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

// protoErr is an "ERR <code>" answer from upsd.
type protoErr struct{ code string }

func (e *protoErr) Error() string {
	switch e.code {
	case "ACCESS-DENIED":
		return "upsd refused: wrong username or password, or the user isn't allowed this command (instcmds in upsd.users)"
	case "INVALID-USERNAME", "INVALID-PASSWORD", "USERNAME-REQUIRED", "PASSWORD-REQUIRED":
		return "upsd refused the username or password (" + strings.ToLower(e.code) + ")"
	case "UNKNOWN-UPS":
		return "upsd has no UPS by that name"
	case "CMD-NOT-SUPPORTED":
		return "the UPS's driver doesn't offer that command"
	case "VAR-NOT-SUPPORTED":
		return "the UPS doesn't report that variable"
	case "DATA-STALE":
		return "upsd's data for this UPS is stale (the driver lost contact with the UPS)"
	case "DRIVER-NOT-CONNECTED":
		return "upsd isn't connected to this UPS's driver"
	}
	return "upsd answered ERR " + e.code
}

func isCode(err error, codes ...string) bool {
	var pe *protoErr
	if !errors.As(err, &pe) {
		return false
	}
	for _, c := range codes {
		if pe.code == c {
			return true
		}
	}
	return false
}

// session is one connection to upsd.
type session struct {
	nc     net.Conn
	r      *bufio.Reader
	secure bool
	stop   func() bool
}

func (c *conn) open(ctx context.Context) (*session, error) {
	dctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	raw, err := c.dial(dctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("can't reach upsd at %s: %w", c.addr, err)
	}
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = raw.SetDeadline(deadline)
	s := &session{nc: raw, r: bufio.NewReaderSize(raw, maxLine)}
	s.stop = context.AfterFunc(ctx, func() { raw.Close() })
	if c.mode == "off" {
		return s, nil
	}
	line, err := s.cmd("STARTTLS")
	switch {
	case err == nil && strings.HasPrefix(line, "OK STARTTLS"):
		tc := tls.Client(raw, c.tls.Clone())
		if err := tc.HandshakeContext(dctx); err != nil {
			s.close()
			return nil, fmt.Errorf("TLS with upsd failed: %w", err)
		}
		s.nc, s.r, s.secure = tc, bufio.NewReaderSize(tc, maxLine), true
		return s, nil
	case err != nil && c.mode == "auto" && isCode(err, "FEATURE-NOT-CONFIGURED", "FEATURE-NOT-SUPPORTED", "UNKNOWN-COMMAND"):
		return s, nil
	case err != nil && c.mode == "require" && isCode(err, "FEATURE-NOT-CONFIGURED", "FEATURE-NOT-SUPPORTED", "UNKNOWN-COMMAND"):
		s.close()
		return nil, errors.New("upsd doesn't offer STARTTLS (set CERTFILE in upsd.conf, or set tls to auto)")
	case err != nil:
		s.close()
		return nil, err
	}
	s.close()
	return nil, fmt.Errorf("unexpected answer to STARTTLS: %q", line)
}

func (s *session) close() {
	if s.nc == nil {
		return
	}
	_, _ = io.WriteString(s.nc, "LOGOUT\n")
	s.nc.Close()
	s.stop()
	s.nc = nil
}

func (s *session) readLine() (string, error) {
	b, err := s.r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", errors.New("upsd sent a line that is too long")
	}
	if err != nil {
		return "", fmt.Errorf("upsd closed the connection: %w", err)
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// cmd sends one request line and reads the one-line answer.
func (s *session) cmd(line string) (string, error) {
	if strings.ContainsAny(line, "\r\n") {
		return "", errors.New("refusing a request with a line break")
	}
	if _, err := io.WriteString(s.nc, line+"\n"); err != nil {
		return "", fmt.Errorf("can't write to upsd: %w", err)
	}
	ans, err := s.readLine()
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(ans, "ERR ") || ans == "ERR" {
		f := strings.Fields(ans)
		code := "UNKNOWN"
		if len(f) > 1 {
			code = f[1]
		}
		return "", &protoErr{code: code}
	}
	return ans, nil
}

// list runs "LIST <what>" and returns the fields of each line between BEGIN
// and END (with the leading keyword dropped).
func (s *session) list(what string) ([][]string, error) {
	ans, err := s.cmd("LIST " + what)
	if err != nil {
		return nil, err
	}
	if ans != "BEGIN LIST "+what {
		return nil, fmt.Errorf("unexpected answer from upsd: %q", ans)
	}
	var out [][]string
	for {
		line, err := s.readLine()
		if err != nil {
			return nil, err
		}
		if line == "END LIST "+what {
			return out, nil
		}
		if len(out) >= maxItems {
			return nil, errors.New("upsd sent too long a list")
		}
		f, err := split(line)
		if err != nil {
			return nil, err
		}
		if len(f) > 0 {
			out = append(out, f[1:])
		}
	}
}

// split breaks an answer into words, honouring "quoted strings" with
// backslash escapes.
func split(line string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQ, esc, have := false, false, false
	for _, r := range line {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\' && inQ:
			esc = true
		case r == '"':
			inQ = !inQ
			have = true
		case r == ' ' && !inQ:
			if have || cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(r)
		}
	}
	if inQ || esc {
		return nil, fmt.Errorf("unterminated quote in upsd's answer: %q", line)
	}
	if have || cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out, nil
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

type upsEntry struct{ name, desc string }

func (s *session) upsList() ([]upsEntry, error) {
	rows, err := s.list("UPS")
	if err != nil {
		return nil, err
	}
	var out []upsEntry
	for _, r := range rows {
		if len(r) == 0 || !upsRe.MatchString(r[0]) {
			continue
		}
		e := upsEntry{name: r[0]}
		if len(r) > 1 {
			e.desc = r[1]
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

func (s *session) vars(ups string) (map[string]string, error) {
	rows, err := s.list("VAR " + ups)
	if err != nil {
		return nil, err
	}
	v := map[string]string{}
	for _, r := range rows {
		if len(r) >= 3 && r[0] == ups {
			v[r[1]] = r[2]
		}
	}
	return v, nil
}

func (s *session) commands(ups string) ([]string, error) {
	rows, err := s.list("CMD " + ups)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rows {
		if len(r) >= 2 && r[0] == ups {
			out = append(out, r[1])
		}
	}
	sort.Strings(out)
	return out, nil
}

// pick resolves the UPS a call is about: the named one, or the only one.
func (s *session) pick(name string) (upsEntry, error) {
	list, err := s.upsList()
	if err != nil {
		return upsEntry{}, err
	}
	names := []string{}
	for _, u := range list {
		if u.name == name || (name == "" && len(list) == 1) {
			return u, nil
		}
		names = append(names, u.name)
	}
	if name == "" {
		if len(list) == 0 {
			return upsEntry{}, errors.New("upsd serves no UPS")
		}
		return upsEntry{}, fmt.Errorf("upsd serves several UPSes; name one (%s)", strings.Join(names, ", "))
	}
	return upsEntry{}, fmt.Errorf("upsd has no UPS %s (UPSes: %s)", name, strings.Join(names, ", "))
}

// checkUPS validates a UPS name before it goes into a request.
func checkUPS(name string) (string, error) {
	name = strings.TrimSpace(name)
	if i := strings.IndexByte(name, '@'); i > 0 {
		name = name[:i] // upsc-style ups@host
	}
	if name != "" && !upsRe.MatchString(name) {
		return "", errors.New("a UPS name is up to 64 letters, digits, '.', '_', '+' and '-'")
	}
	return name, nil
}

var statusFlags = map[string]string{
	"OL": "online", "OB": "on battery", "LB": "low battery", "HB": "high battery", "RB": "replace battery",
	"CHRG": "charging", "DISCHRG": "discharging", "BYPASS": "on bypass", "CAL": "calibrating", "OFF": "output off",
	"OVER": "overloaded", "TRIM": "trimming voltage", "BOOST": "boosting voltage", "FSD": "forced shutdown",
	"ALARM": "alarm", "TEST": "self-test running",
}

func num(v map[string]string, keys ...string) (float64, bool) {
	for _, k := range keys {
		if s, ok := v[k]; ok {
			if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
				return f, true
			}
		}
	}
	return 0, false
}

func first(v map[string]string, keys ...string) string {
	for _, k := range keys {
		if s := strings.TrimSpace(v[k]); s != "" {
			return s
		}
	}
	return ""
}

func round(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }

type alarm struct {
	UPS      string `json:"ups"`
	Severity string `json:"severity"` // "critical" or "warning"
	Alarm    string `json:"alarm"`
}

// alarmsOf lists what a UPS's variables say needs attention.
func alarmsOf(ups string, v map[string]string) []alarm {
	var out []alarm
	add := func(sev, msg string) { out = append(out, alarm{UPS: ups, Severity: sev, Alarm: msg}) }
	flags := strings.Fields(v["ups.status"])
	has := map[string]bool{}
	for _, f := range flags {
		has[f] = true
	}
	if has["FSD"] {
		add("critical", "forced shutdown in progress")
	}
	if has["LB"] {
		add("critical", "battery low")
	}
	if has["OVER"] {
		add("critical", "overloaded")
	}
	if has["OFF"] {
		add("critical", "output is off")
	}
	if has["OB"] {
		msg := "on battery"
		if rt, ok := num(v, "battery.runtime"); ok {
			msg += fmt.Sprintf(", about %d min left", int(rt/60))
		}
		add("warning", msg)
	}
	if has["RB"] {
		add("warning", "battery needs replacing")
	}
	if has["BYPASS"] {
		add("warning", "on bypass (the load isn't protected)")
	}
	if a := first(v, "ups.alarm"); a != "" {
		add("warning", a)
	} else if has["ALARM"] {
		add("warning", "the UPS reports an alarm")
	}
	if !has["LB"] {
		if ch, ok := num(v, "battery.charge"); ok {
			if low, ok := num(v, "battery.charge.low"); ok && ch <= low {
				add("critical", fmt.Sprintf("battery at %.0f%%, at or below its low mark of %.0f%%", ch, low))
			}
		}
	}
	if tr := strings.ToLower(first(v, "ups.test.result")); tr != "" && (strings.Contains(tr, "fail") || strings.Contains(tr, "warning")) {
		add("warning", "last self-test: "+v["ups.test.result"])
	}
	return out
}

// summary turns a UPS's variables into its status.
func summary(u upsEntry, v map[string]string, full bool) map[string]any {
	st := v["ups.status"]
	flags := []string{}
	for _, f := range strings.Fields(st) {
		if h, ok := statusFlags[f]; ok {
			flags = append(flags, h)
		} else {
			flags = append(flags, f)
		}
	}
	e := map[string]any{"ups": u.name, "status": st, "flags": flags, "onBattery": strings.Contains(" "+st+" ", " OB ")}
	if u.desc != "" && u.desc != "Unavailable" {
		e["description"] = u.desc
	}
	set := func(key string, f float64, ok bool) {
		if ok {
			e[key] = round(f)
		}
	}
	ch, ok := num(v, "battery.charge")
	set("batteryCharge", ch, ok)
	rt, ok := num(v, "battery.runtime")
	if ok {
		e["batteryRuntimeSeconds"] = int64(rt)
	}
	load, lok := num(v, "ups.load")
	set("loadPercent", load, lok)
	iv, ok := num(v, "input.voltage")
	set("inputVoltage", iv, ok)
	if real, ok := num(v, "ups.realpower"); ok {
		e["watts"] = round(real)
	} else if nom, ok := num(v, "ups.realpower.nominal"); ok && lok {
		e["watts"] = round(nom * load / 100)
		e["wattsEstimated"] = true
	}
	if full {
		bv, ok := num(v, "battery.voltage")
		set("batteryVoltage", bv, ok)
		ov, ok := num(v, "output.voltage")
		set("outputVoltage", ov, ok)
		f, ok := num(v, "input.frequency")
		set("inputFrequency", f, ok)
		t, ok := num(v, "ups.temperature", "battery.temperature")
		set("temperature", t, ok)
		nom, ok := num(v, "ups.realpower.nominal")
		set("nominalWatts", nom, ok)
		low, ok := num(v, "battery.charge.low")
		set("batteryChargeLow", low, ok)
		if rl, ok := num(v, "battery.runtime.low"); ok {
			e["batteryRuntimeLowSeconds"] = int64(rl)
		}
		for key, vars := range map[string][]string{
			"manufacturer": {"device.mfr", "ups.mfr"}, "model": {"device.model", "ups.model"}, "serial": {"device.serial", "ups.serial"},
			"firmware": {"ups.firmware"}, "driver": {"driver.name"}, "beeper": {"ups.beeper.status"}, "lastSelfTest": {"ups.test.result"},
			"batteryDate": {"battery.date", "battery.mfr.date"}, "batteryType": {"battery.type"},
		} {
			if s := first(v, vars...); s != "" {
				e[key] = s
			}
		}
		al := alarmsOf(u.name, v)
		if al == nil {
			al = []alarm{}
		}
		e["alarms"] = al
	}
	return e
}

type input struct {
	UPS string `json:"ups"`
	// Command and Cmd are never sent; they're decoded so a request for a
	// shutdown through a beeper action is refused by name.
	Command string `json:"command"`
	Cmd     string `json:"cmd"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	s, err := c.open(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	defer s.close()
	list, err := s.upsList()
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("upsd · %d UPS", len(list))
	if s.secure {
		msg += " · TLS"
	}
	var problems []string
	for i, u := range list {
		if i >= maxUPS {
			break
		}
		v, err := s.vars(u.name)
		if err != nil {
			problems = append(problems, u.name+": "+err.Error())
			continue
		}
		for _, a := range alarmsOf(u.name, v) {
			problems = append(problems, u.name+" "+a.Alarm)
		}
	}
	if len(problems) > 0 {
		return sdk.Health{Status: "degraded", Message: msg + " · " + strings.Join(problems, "; ")}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p input
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "upses", "status", "alarms", "variables", "commands", "beeper_disable", "beeper_enable":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	// Everything is checked before upsd is contacted.
	for _, x := range []string{p.Command, p.Cmd} {
		if x != "" {
			return sdk.Result{}, refuseCommand(x)
		}
	}
	name, err := checkUPS(p.UPS)
	if err != nil {
		return sdk.Result{}, err
	}
	s, err := c.open(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	defer s.close()

	switch call.Action {
	case "upses":
		list, err := s.upsList()
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for i, u := range list {
			if i >= maxUPS {
				break
			}
			v, err := s.vars(u.name)
			if err != nil {
				out = append(out, map[string]any{"ups": u.name, "description": u.desc, "error": err.Error()})
				continue
			}
			out = append(out, summary(u, v, false))
		}
		return sdk.JSON(out)

	case "alarms":
		list, err := s.upsList()
		if err != nil {
			return sdk.Result{}, err
		}
		out := []alarm{}
		for i, u := range list {
			if i >= maxUPS {
				break
			}
			v, err := s.vars(u.name)
			if err != nil {
				out = append(out, alarm{UPS: u.name, Severity: "critical", Alarm: err.Error()})
				continue
			}
			out = append(out, alarmsOf(u.name, v)...)
		}
		return sdk.JSON(map[string]any{"count": len(out), "alarms": out})
	}

	u, err := s.pick(name)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "status":
		v, err := s.vars(u.name)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(summary(u, v, true))

	case "variables":
		v, err := s.vars(u.name)
		if err != nil {
			return sdk.Result{}, err
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []map[string]string{}
		for _, k := range keys {
			out = append(out, map[string]string{"name": k, "value": v[k]})
		}
		return sdk.JSON(map[string]any{"ups": u.name, "variables": out})

	case "commands":
		cmds, err := s.commands(u.name)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range cmds {
			out = append(out, map[string]any{"command": x, "conduitSends": allowed[x]})
		}
		return sdk.JSON(map[string]any{"ups": u.name, "commands": out})
	}
	return c.beeper(ctx, s, call, u, call.Action == "beeper_enable")
}

func (c *conn) beeper(ctx context.Context, s *session, call sdk.Call, u upsEntry, enable bool) (sdk.Result, error) {
	cmd, want, verb, undo := "beeper.disable", "disabled", "Silence", "beeper_enable"
	if enable {
		cmd, want, verb, undo = "beeper.enable", "enabled", "Enable", "beeper_disable"
	}
	cmds, err := s.commands(u.name)
	if err != nil {
		return sdk.Result{}, err
	}
	offered := false
	for _, x := range cmds {
		offered = offered || x == cmd
	}
	if !offered {
		return sdk.Result{}, fmt.Errorf("%s's driver doesn't offer %s", u.name, cmd)
	}
	before := ""
	if line, err := s.cmd("GET VAR " + u.name + " ups.beeper.status"); err == nil {
		if f, err := split(line); err == nil && len(f) >= 4 {
			before = f[3]
		}
	}
	target := "UPS " + u.name
	if call.DryRun {
		sum := verb + " the beeper on " + target
		if before == want {
			sum = "The beeper on " + target + " is already " + want + "; nothing would change"
		}
		ch := sdk.Change{Target: target + " beeper", Op: "instcmd " + cmd, After: mustJSON(map[string]string{"beeper": want})}
		if before != "" {
			ch.Before = mustJSON(map[string]string{"beeper": before})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{ch}}}, nil
	}
	if before == want {
		return sdk.JSON(map[string]any{"ups": u.name, "beeper": before, "changed": false})
	}
	if err := c.instcmd(ctx, s, u.name, cmd); err != nil {
		return sdk.Result{}, err
	}
	after := ""
	if line, err := s.cmd("GET VAR " + u.name + " ups.beeper.status"); err == nil {
		if f, err := split(line); err == nil && len(f) >= 4 {
			after = f[3]
		}
	}
	out := map[string]any{"ups": u.name, "command": cmd, "changed": true}
	if after != "" {
		out["beeper"] = after
	}
	if before != "" {
		out["before"] = before
	}
	res, err := sdk.JSON(out)
	undoVerb := "Silence"
	if !enable {
		undoVerb = "Re-enable"
	}
	res.Undo = sdk.UndoWith(undo, map[string]string{"ups": u.name}, undoVerb+" the beeper on "+u.name)
	return res, err
}

// instcmd authenticates and runs an instant command, which must be one of
// the allowed beeper commands.
func (c *conn) instcmd(ctx context.Context, s *session, ups, cmd string) error {
	if err := refuseCommand(cmd); err != nil {
		return err
	}
	if !upsRe.MatchString(ups) {
		return errors.New("invalid UPS name")
	}
	if c.user == "" {
		return errors.New("instant commands need a upsd user: enter a username and password from upsd.users (with instcmds = beeper.disable, beeper.enable)")
	}
	// In auto mode a plain session means upsd (or someone on the path)
	// said there's no TLS; the password goes out in the clear only when
	// tls is explicitly off.
	if !s.secure && c.mode != "off" {
		return errors.New("upsd didn't offer STARTTLS, so the password isn't sent in plain text: set CERTFILE in upsd.conf, or set tls to off to allow a plain-text login")
	}
	pw, err := c.host.Secret(ctx, c.pass)
	if err != nil {
		return err
	}
	if hasControl(pw) {
		return errors.New("the stored password has control characters")
	}
	if _, err := s.cmd("USERNAME " + quote(c.user)); err != nil {
		return err
	}
	if _, err := s.cmd("PASSWORD " + quote(pw)); err != nil {
		return err
	}
	ans, err := s.cmd("INSTCMD " + ups + " " + cmd)
	if err != nil {
		return err
	}
	f := strings.Fields(ans)
	if len(f) == 3 && f[0] == "OK" && f[1] == "TRACKING" {
		return c.waitTracking(ctx, s, f[2])
	}
	if len(f) == 0 || f[0] != "OK" {
		return fmt.Errorf("unexpected answer from upsd: %q", ans)
	}
	return nil
}

var trackRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// waitTracking follows a command upsd tracks (TRACKING ON) until the
// driver reports it done.
func (c *conn) waitTracking(ctx context.Context, s *session, id string) error {
	if !trackRe.MatchString(id) {
		return nil
	}
	end := time.Now().Add(c.track)
	for {
		ans, err := s.cmd("GET TRACKING " + id)
		if err != nil {
			return err
		}
		switch strings.TrimSpace(ans) {
		case "SUCCESS":
			return nil
		case "FAILED":
			return errors.New("the UPS's driver reports the command failed")
		}
		if time.Now().After(end) {
			return nil // still pending; upsd accepted it
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
