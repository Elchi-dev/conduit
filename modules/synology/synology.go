// Package synology works with a Synology NAS through the DSM Web API:
// system information and load, volumes, storage pools and disks, packages,
// Container Manager containers, and shutdown or restart.
//
// It signs in with a DSM account (SYNO.API.Auth). When the account has
// two-step verification, the module computes the code from the TOTP secret
// kept in the vault and asks DSM for a device token, so later sign-ins
// don't need a code.
package synology

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/internal/totp"
	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one DSM.
type Config struct {
	URL      string `json:"url"`      // e.g. https://nas.lan:5001
	Account  string `json:"account"`  // DSM user name
	Password string `json:"password"` // secret://
	// OTPSecret (secret://) is the account's two-step verification (TOTP)
	// secret, for accounts that have it on.
	OTPSecret          string `json:"otpSecret"`
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	cfg  Config
	host sdk.Host
	base string
	http *http.Client

	mu  sync.Mutex
	sid string
	did string // device token after a two-step sign-in
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
	// Now is the clock for two-step codes (tests).
	Now func() time.Time
}

// New returns the Synology module.
func New() *Module { return &Module{} }

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "synology", Name: "Synology DSM", Version: "0.1.0", Category: "Storage", Icon: "disk",
		Description: "A Synology NAS: load, volumes and disks, packages and containers, and shutdown or restart.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","account","password"],"properties":{
			"url":{"type":"string","description":"The NAS address with its DSM port, e.g. https://nas.lan:5001"},
			"account":{"type":"string","description":"A DSM user (an administrator to see storage and restart the NAS)"},
			"password":{"type":"string","x-secret":true,"description":"The user's password"},
			"otpSecret":{"type":"string","x-secret":true,"description":"Only with two-step verification: the secret shown when you set it up (the text behind the QR code)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the NAS certificate, to trust DSM's own self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "system", Title: "System", Description: "Model, DSM version, uptime, temperature and memory.", Risk: sdk.RiskRead},
			{Name: "utilization", Title: "Load", Description: "CPU, memory, network and disk load right now.", Risk: sdk.RiskRead},
			{Name: "storage", Title: "Storage", Description: "Volumes with used space, storage pools and disks with their health and temperature.", Risk: sdk.RiskRead},
			{Name: "packages", Title: "Packages", Description: "Installed packages, running or stopped.", Risk: sdk.RiskRead},
			{Name: "containers", Title: "Containers", Description: "Container Manager (Docker) containers, when the package is installed.", Risk: sdk.RiskRead},
			{Name: "reboot", Title: "Restart the NAS", Description: "Everything on it is unavailable for a few minutes.", Risk: sdk.RiskDestructive, DryRun: true},
			{Name: "shutdown", Title: "Shut down the NAS", Description: "It stays off until someone powers it on (or Wake-on-LAN).", Risk: sdk.RiskDestructive, DryRun: true},
		},
		Resources: []sdk.ResourceSpec{
			{Kind: "volume", Title: "Volumes", ListAction: "storage", ViewHint: "table"},
			{Kind: "container", Title: "Containers", ListAction: "containers", ViewHint: "table"},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(c.URL), "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("the address is the NAS with its DSM port, like https://nas.lan:5001")
	}
	c.Account = strings.TrimSpace(c.Account)
	if c.Account == "" || len(c.Account) > 128 {
		return errors.New("enter the DSM user name")
	}
	if !strings.HasPrefix(c.Password, "secret://") || (c.OTPSecret != "" && !strings.HasPrefix(c.OTPSecret, "secret://")) {
		return errors.New("store the password (and two-step secret) in the vault and enter their secret:// references")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h)
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	// The password and session id must never follow a redirect elsewhere.
	client = rest.SameHostOnly(client)
	if old := m.set.Delete(id); old != nil {
		go old.logout()
	}
	m.set.Put(id, &conn{cfg: c, host: h, base: u.Scheme + "://" + u.Host, http: client})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error {
	if c := m.set.Delete(id); c != nil {
		c.logout()
	}
	return nil
}

// apiError is a DSM error code.
type apiError struct {
	API  string
	Code int
}

var commonErrors = map[int]string{
	100: "unknown error", 101: "a parameter is missing", 102: "this DSM doesn't have that API",
	103: "this DSM doesn't have that method", 104: "this DSM doesn't support that API version",
	105: "the account isn't allowed to do this", 106: "the session timed out",
	107: "the session ended because the account signed in elsewhere", 117: "the account needs administrator rights for this",
	119: "the session is unknown",
}

var authErrors = map[int]string{
	400: "DSM refused the user name or password", 401: "the DSM account is disabled",
	402: "the account isn't allowed to sign in", 403: "the account has two-step verification: add its secret (otpSecret) in the settings",
	404: "DSM refused the two-step code (check the secret and this computer's clock)", 406: "DSM requires this account to set up two-step verification first",
	407: "DSM has blocked this computer's address after failed sign-ins", 408: "the account's password has expired",
	409: "the account's password has expired", 410: "the account's password must be changed in DSM first",
}

func (e *apiError) Error() string {
	if e.API == "SYNO.API.Auth" {
		if s, ok := authErrors[e.Code]; ok {
			return s
		}
	}
	if s, ok := commonErrors[e.Code]; ok {
		return fmt.Sprintf("%s: %s (code %d)", e.API, s, e.Code)
	}
	return fmt.Sprintf("%s: DSM error %d", e.API, e.Code)
}

func isCode(err error, codes ...int) bool {
	var e *apiError
	if !errors.As(err, &e) {
		return false
	}
	for _, c := range codes {
		if e.Code == c {
			return true
		}
	}
	return false
}

// post sends one Web API request as a form (so the password and session id
// stay out of URLs and server logs) and decodes its data into out.
func (c *conn) post(ctx context.Context, api string, version int, method string, form url.Values, out any) error {
	if form == nil {
		form = url.Values{}
	}
	form.Set("api", api)
	form.Set("version", strconv.Itoa(version))
	form.Set("method", method)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/webapi/entry.cgi", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Conduit")
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("DSM answered %s", res.Status)
	}
	var env struct {
		Success bool            `json:"success"`
		Data    json.RawMessage `json:"data"`
		Error   struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("unexpected answer from DSM (is this the DSM port?): %w", err)
	}
	if !env.Success {
		return &apiError{API: api, Code: env.Error.Code}
	}
	if out != nil && len(bytes.TrimSpace(env.Data)) > 0 {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}

func (c *conn) now(m *Module) time.Time {
	if m != nil && m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// otp computes the current two-step code from the stored secret.
func (c *conn) otp(ctx context.Context, now time.Time) (string, error) {
	s, err := c.host.Secret(ctx, c.cfg.OTPSecret)
	if err != nil {
		return "", err
	}
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(s)))
	if u, err := url.Parse(s); err == nil && strings.EqualFold(u.Scheme, "otpauth") {
		s = strings.ToUpper(u.Query().Get("SECRET") + u.Query().Get("secret"))
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(s, "="))
	if err != nil || len(key) == 0 {
		return "", errors.New("the two-step secret isn't a base32 TOTP secret")
	}
	return totp.Code(key, totp.Step(now)), nil
}

// login signs in and keeps the session id. Callers hold c.mu.
func (c *conn) login(ctx context.Context, m *Module) error {
	pw, err := c.host.Secret(ctx, c.cfg.Password)
	if err != nil {
		return err
	}
	form := url.Values{"account": {c.cfg.Account}, "passwd": {pw}, "session": {"Conduit"}, "format": {"sid"}}
	if c.did != "" {
		form.Set("device_id", c.did)
		form.Set("device_name", "Conduit")
	}
	var out struct {
		SID string `json:"sid"`
		DID string `json:"did"`
	}
	err = c.post(ctx, "SYNO.API.Auth", 6, "login", form, &out)
	if isCode(err, 403) && c.cfg.OTPSecret != "" {
		code, oerr := c.otp(ctx, c.now(m))
		if oerr != nil {
			return oerr
		}
		form = url.Values{"account": {c.cfg.Account}, "passwd": {pw}, "session": {"Conduit"}, "format": {"sid"},
			"otp_code": {code}, "enable_device_token": {"yes"}, "device_name": {"Conduit"}}
		err = c.post(ctx, "SYNO.API.Auth", 6, "login", form, &out)
	}
	if err != nil {
		return err
	}
	if out.SID == "" {
		return errors.New("DSM signed in but returned no session")
	}
	c.sid = out.SID
	if out.DID != "" {
		c.did = out.DID
	}
	return nil
}

func (c *conn) logout() {
	c.mu.Lock()
	sid := c.sid
	c.sid = ""
	c.mu.Unlock()
	if sid == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.post(ctx, "SYNO.API.Auth", 6, "logout", url.Values{"session": {"Conduit"}, "_sid": {sid}}, nil)
}

// call runs an API with the session, signing in first and again once if
// the session expired.
func (c *conn) call(ctx context.Context, m *Module, api string, version int, method string, form url.Values, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for attempt := 0; ; attempt++ {
		if c.sid == "" {
			if err := c.login(ctx, m); err != nil {
				return err
			}
		}
		f := url.Values{}
		for k, v := range form {
			f[k] = v
		}
		f.Set("_sid", c.sid)
		err := c.post(ctx, api, version, method, f, out)
		if attempt == 0 && isCode(err, 106, 107, 119) {
			c.sid = ""
			continue
		}
		return err
	}
}

// num reads DSM's numbers, which come as JSON numbers or as strings.
type num float64

func (n *num) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		*n = 0
		return nil //nolint:nilerr // DSM sometimes puts text in numeric fields; treat as unknown
	}
	*n = num(f)
	return nil
}

// Info is the system summary.
type Info struct {
	Model       string `json:"model"`
	Version     string `json:"version"`
	UptimeSec   int64  `json:"uptimeSeconds"`
	Uptime      string `json:"uptime"`
	Temperature int    `json:"temperatureC,omitempty"`
	TempWarning bool   `json:"temperatureWarning,omitempty"`
	RAMMB       int64  `json:"ramMB,omitempty"`
	Time        string `json:"time,omitempty"`
}

func (c *conn) info(ctx context.Context, m *Module) (Info, error) {
	var r struct {
		Model         string `json:"model"`
		RAM           num    `json:"ram"`
		Temperature   num    `json:"temperature"`
		TempWarn      bool   `json:"temperature_warn"`
		Time          string `json:"time"`
		Uptime        num    `json:"uptime"`
		Version       string `json:"version"`
		VersionString string `json:"version_string"`
	}
	if err := c.call(ctx, m, "SYNO.DSM.Info", 2, "getinfo", nil, &r); err != nil {
		return Info{}, err
	}
	v := r.VersionString
	if v == "" {
		v = r.Version
	}
	up := time.Duration(int64(r.Uptime)) * time.Second
	return Info{Model: r.Model, Version: v, UptimeSec: int64(r.Uptime), Uptime: human(up), Temperature: int(r.Temperature), TempWarning: r.TempWarn, RAMMB: int64(r.RAM), Time: r.Time}, nil
}

func human(d time.Duration) string {
	days := int(d.Hours()) / 24
	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, int(d.Hours())%24)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

// Volume is one volume.
type Volume struct {
	ID          string  `json:"id"`
	Path        string  `json:"path"`
	Status      string  `json:"status"`
	FS          string  `json:"fs,omitempty"`
	TotalBytes  int64   `json:"totalBytes"`
	UsedBytes   int64   `json:"usedBytes"`
	UsedPercent float64 `json:"usedPercent"`
}

// Pool is one storage pool.
type Pool struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	RAID   string `json:"raid,omitempty"`
}

// Disk is one drive.
type Disk struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Model       string `json:"model,omitempty"`
	Status      string `json:"status"`
	Smart       string `json:"smart,omitempty"`
	Temperature int    `json:"temperatureC,omitempty"`
	SizeBytes   int64  `json:"sizeBytes,omitempty"`
}

// Storage is the storage overview.
type Storage struct {
	Volumes []Volume `json:"volumes"`
	Pools   []Pool   `json:"pools"`
	Disks   []Disk   `json:"disks"`
}

func (c *conn) storage(ctx context.Context, m *Module) (Storage, error) {
	var r struct {
		Volumes []struct {
			ID      string `json:"id"`
			VolPath string `json:"vol_path"`
			Status  string `json:"status"`
			FSType  string `json:"fs_type"`
			Size    struct {
				Total num `json:"total"`
				Used  num `json:"used"`
			} `json:"size"`
		} `json:"volumes"`
		Pools []struct {
			ID       string `json:"id"`
			Status   string `json:"status"`
			RaidType string `json:"raidType"`
			DevType  string `json:"device_type"`
		} `json:"storagePools"`
		Disks []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Model       string `json:"model"`
			Status      string `json:"status"`
			SmartStatus string `json:"smart_status"`
			Temp        num    `json:"temp"`
			SizeTotal   num    `json:"size_total"`
		} `json:"disks"`
	}
	if err := c.call(ctx, m, "SYNO.Storage.CGI.Storage", 1, "load_info", nil, &r); err != nil {
		return Storage{}, err
	}
	out := Storage{Volumes: []Volume{}, Pools: []Pool{}, Disks: []Disk{}}
	for _, v := range r.Volumes {
		x := Volume{ID: v.ID, Path: v.VolPath, Status: v.Status, FS: v.FSType, TotalBytes: int64(v.Size.Total), UsedBytes: int64(v.Size.Used)}
		if x.TotalBytes > 0 {
			x.UsedPercent = float64(int(float64(x.UsedBytes)/float64(x.TotalBytes)*1000)) / 10
		}
		out.Volumes = append(out.Volumes, x)
	}
	for _, p := range r.Pools {
		raid := p.RaidType
		if p.DevType != "" {
			raid = p.DevType
		}
		out.Pools = append(out.Pools, Pool{ID: p.ID, Status: p.Status, RAID: raid})
	}
	for _, d := range r.Disks {
		out.Disks = append(out.Disks, Disk{ID: d.ID, Name: d.Name, Model: strings.TrimSpace(d.Model), Status: d.Status, Smart: d.SmartStatus, Temperature: int(d.Temp), SizeBytes: int64(d.SizeTotal)})
	}
	return out, nil
}

// problems lists anything in storage that isn't healthy.
func (s Storage) problems() []string {
	var out []string
	for _, v := range s.Volumes {
		if v.Status != "" && v.Status != "normal" {
			out = append(out, fmt.Sprintf("%s is %s", v.Path, v.Status))
		} else if v.UsedPercent >= 95 {
			out = append(out, fmt.Sprintf("%s is %.0f%% full", v.Path, v.UsedPercent))
		}
	}
	for _, p := range s.Pools {
		if p.Status != "" && p.Status != "normal" {
			out = append(out, fmt.Sprintf("pool %s is %s", p.ID, p.Status))
		}
	}
	for _, d := range s.Disks {
		if d.Status != "" && d.Status != "normal" && d.Status != "not_use" {
			out = append(out, fmt.Sprintf("%s is %s", d.Name, d.Status))
		}
	}
	return out
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	in, err := c.info(ctx, m)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := strings.TrimSpace(in.Model + " · " + in.Version + " · up " + in.Uptime)
	if st, err := c.storage(ctx, m); err == nil {
		if p := st.problems(); len(p) > 0 {
			return sdk.Health{Status: "degraded", Message: strings.Join(p, "; ")}
		}
	}
	if in.TempWarning {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("running hot (%d °C) · %s", in.Temperature, msg)}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "system":
		in, err := c.info(ctx, m)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(in)

	case "utilization":
		var r struct {
			CPU struct {
				User   num `json:"user_load"`
				System num `json:"system_load"`
				Other  num `json:"other_load"`
				Load1  num `json:"1min_load"`
				Load5  num `json:"5min_load"`
				Load15 num `json:"15min_load"`
			} `json:"cpu"`
			Memory struct {
				RealUsage num `json:"real_usage"`
				TotalReal num `json:"total_real"` // KB
				AvailReal num `json:"avail_real"` // KB
			} `json:"memory"`
			Network []struct {
				Device string `json:"device"`
				RX     num    `json:"rx"`
				TX     num    `json:"tx"`
			} `json:"network"`
			Disk struct {
				Total struct {
					Utilization num `json:"utilization"`
					ReadByte    num `json:"read_byte"`
					WriteByte   num `json:"write_byte"`
				} `json:"total"`
			} `json:"disk"`
		}
		if err := c.call(ctx, m, "SYNO.Core.System.Utilization", 1, "get", nil, &r); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{
			"cpuPercent":    float64(r.CPU.User + r.CPU.System + r.CPU.Other),
			"load":          []float64{float64(r.CPU.Load1) / 100, float64(r.CPU.Load5) / 100, float64(r.CPU.Load15) / 100},
			"memoryPercent": float64(r.Memory.RealUsage),
			"memoryTotalMB": int64(r.Memory.TotalReal) / 1024,
			"memoryFreeMB":  int64(r.Memory.AvailReal) / 1024,
			"diskPercent":   float64(r.Disk.Total.Utilization),
			"diskReadBps":   int64(r.Disk.Total.ReadByte),
			"diskWriteBps":  int64(r.Disk.Total.WriteByte),
		}
		for _, n := range r.Network {
			if n.Device == "total" {
				out["netRxBps"], out["netTxBps"] = int64(n.RX), int64(n.TX)
			}
		}
		return sdk.JSON(out)

	case "storage":
		st, err := c.storage(ctx, m)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(st)

	case "packages":
		var r struct {
			Packages []struct {
				ID         string `json:"id"`
				Name       string `json:"name"`
				Version    string `json:"version"`
				Additional struct {
					Status string `json:"status"`
				} `json:"additional"`
			} `json:"packages"`
		}
		if err := c.call(ctx, m, "SYNO.Core.Package", 2, "list", url.Values{"additional": {`["status"]`}}, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]string{}
		for _, p := range r.Packages {
			out = append(out, map[string]string{"id": p.ID, "name": p.Name, "version": p.Version, "status": p.Additional.Status})
		}
		sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]["name"]) < strings.ToLower(out[j]["name"]) })
		return sdk.JSON(out)

	case "containers":
		var r struct {
			Containers []struct {
				Name   string `json:"name"`
				Image  string `json:"image"`
				Status string `json:"status"`
				State  struct {
					Status    string `json:"Status"`
					StartedAt string `json:"StartedAt"`
				} `json:"State"`
			} `json:"containers"`
		}
		err := c.call(ctx, m, "SYNO.Docker.Container", 1, "list", url.Values{"limit": {"-1"}, "offset": {"0"}, "type": {`"all"`}}, &r)
		if isCode(err, 102, 103) {
			return sdk.Result{}, errors.New("Container Manager (Docker) isn't installed on this NAS")
		}
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]string{}
		for _, x := range r.Containers {
			st := x.Status
			if st == "" {
				st = x.State.Status
			}
			out = append(out, map[string]string{"name": x.Name, "image": x.Image, "status": st, "started": x.State.StartedAt})
		}
		return sdk.JSON(out)

	case "reboot", "shutdown":
		in, err := c.info(ctx, m)
		if err != nil {
			return sdk.Result{}, err
		}
		target := strings.TrimSpace(in.Model + " at " + c.base)
		if call.DryRun {
			verb, op := "Restart", "restart"
			if call.Action == "shutdown" {
				verb, op = "Shut down", "shutdown"
			}
			before, _ := json.Marshal(map[string]any{"version": in.Version, "uptime": in.Uptime})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s %s (up %s)", verb, target, in.Uptime),
				Changes: []sdk.Change{{Target: target, Op: op, Before: before}}}}, nil
		}
		if err := c.call(ctx, m, "SYNO.Core.System", 1, call.Action, url.Values{"force": {"false"}, "local": {"true"}}, nil); err != nil {
			return sdk.Result{}, err
		}
		c.mu.Lock()
		c.sid = "" // the session dies with the system
		c.mu.Unlock()
		return sdk.JSON(map[string]string{call.Action: target})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
