package synology

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/internal/totp"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const seed = "JBSWY3DPEHPK3PXP"

type fakeDSM struct {
	mu       sync.Mutex
	otp      bool // the account has two-step verification
	sid      string
	logins   int
	calls    []string
	rebooted bool
	expire   bool // the next call reports a timed-out session
	noDocker bool
	now      time.Time
}

func (f *fakeDSM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != http.MethodPost || r.URL.Path != "/webapi/entry.cgi" || r.URL.RawQuery != "" {
		w.WriteHeader(404)
		return
	}
	_ = r.ParseForm()
	api, method := r.PostForm.Get("api"), r.PostForm.Get("method")
	ok := func(data string) { fmt.Fprintf(w, `{"success":true,"data":%s}`, data) }
	fail := func(code int) { fmt.Fprintf(w, `{"success":false,"error":{"code":%d}}`, code) }
	if api == "SYNO.API.Auth" {
		switch method {
		case "login":
			if r.PostForm.Get("account") != "admin" || r.PostForm.Get("passwd") != "pw" {
				fail(400)
				return
			}
			if f.otp && r.PostForm.Get("device_id") != "dev1" {
				code := r.PostForm.Get("otp_code")
				if code == "" {
					fail(403)
					return
				}
				key, _ := totpKey()
				if code != totp.Code(key, totp.Step(f.now)) || r.PostForm.Get("enable_device_token") != "yes" {
					fail(404)
					return
				}
			}
			f.logins++
			f.sid = fmt.Sprintf("sid%d", f.logins)
			ok(`{"sid":"` + f.sid + `","did":"dev1"}`)
		case "logout":
			f.sid = ""
			ok(`{}`)
		}
		return
	}
	if r.PostForm.Get("_sid") != f.sid || f.sid == "" {
		fail(119)
		return
	}
	if f.expire {
		f.expire = false
		f.sid = ""
		fail(106)
		return
	}
	f.calls = append(f.calls, api+"."+method)
	switch api + "." + method {
	case "SYNO.DSM.Info.getinfo":
		ok(`{"model":"DS920+","ram":4096,"temperature":41,"temperature_warn":false,"uptime":266400,"version_string":"DSM 7.2.1-69057 Update 5"}`)
	case "SYNO.Core.System.Utilization.get":
		ok(`{"cpu":{"user_load":7,"system_load":3,"other_load":1,"1min_load":45,"5min_load":30,"15min_load":20},"memory":{"real_usage":38,"total_real":3887000,"avail_real":2400000},"network":[{"device":"total","rx":1200,"tx":800},{"device":"eth0","rx":1200,"tx":800}],"disk":{"total":{"utilization":4,"read_byte":1000,"write_byte":2000}}}`)
	case "SYNO.Storage.CGI.Storage.load_info":
		ok(`{"volumes":[{"id":"volume_1","vol_path":"/volume1","status":"normal","fs_type":"btrfs","size":{"total":"1000000000","used":"970000000"}}],"storagePools":[{"id":"reuse_1","status":"normal","device_type":"shr_with_1_disk_protect"}],"disks":[{"id":"sata1","name":"Drive 1","model":"WD40EFRX ","status":"normal","smart_status":"normal","temp":33,"size_total":"4000787030016"}]}`)
	case "SYNO.Core.Package.list":
		if r.PostForm.Get("additional") != `["status"]` {
			fail(101)
			return
		}
		ok(`{"packages":[{"id":"Plex","name":"Plex Media Server","version":"1.40","additional":{"status":"running"}},{"id":"ContainerManager","name":"Container Manager","version":"24.0","additional":{"status":"running"}}],"total":2}`)
	case "SYNO.Docker.Container.list":
		if f.noDocker {
			fail(102)
			return
		}
		ok(`{"containers":[{"name":"homeassistant","image":"ghcr.io/home-assistant/home-assistant:stable","status":"running","State":{"Status":"running","StartedAt":"2026-11-01T10:00:00Z"}}],"total":1}`)
	case "SYNO.Core.System.reboot":
		f.rebooted = true
		ok(`{}`)
	default:
		fail(102)
	}
}

func totpKey() ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(seed)
}

func setup(t *testing.T, f *fakeDSM, cfg Config) *Module {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	m.Now = func() time.Time { return f.now }
	cfg.URL = srv.URL
	raw, _ := json.Marshal(cfg)
	host := fakehost.New(map[string]string{"secret://pw": "pw", "secret://bad": "nope", "secret://otp": "jbsw y3dp ehpk 3pxp"})
	if err := m.Configure(context.Background(), host, "nas", raw); err != nil {
		t.Fatal(err)
	}
	return m
}

func invoke(m *Module, action string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "nas", Action: action, DryRun: dry})
}

func TestSynology(t *testing.T) {
	f := &fakeDSM{now: time.Unix(1_800_000_000, 0)}
	m := setup(t, f, Config{Account: "admin", Password: "secret://pw"})

	h := m.Health(context.Background(), "nas")
	if h.Status != "degraded" || !strings.Contains(h.Message, "/volume1 is 97% full") {
		t.Fatalf("%+v", h)
	}
	for action, want := range map[string]string{
		"system":      `"uptime":"3d 2h"`,
		"utilization": `"cpuPercent":11`,
		"storage":     `"usedPercent":97`,
		"packages":    `"name":"Container Manager"`,
		"containers":  `"name":"homeassistant"`,
	} {
		r, err := invoke(m, action, false)
		if err != nil || !strings.Contains(string(r.Output), want) {
			t.Fatalf("%s: %s %v", action, r.Output, err)
		}
	}
	if f.logins != 1 {
		t.Fatalf("signed in %d times", f.logins)
	}

	// An expired session signs in again once.
	f.expire = true
	if _, err := invoke(m, "system", false); err != nil || f.logins != 2 {
		t.Fatalf("relogin: %v %d", err, f.logins)
	}

	r, err := invoke(m, "reboot", true)
	if err != nil || r.Plan == nil || !strings.HasPrefix(r.Plan.Summary, "Restart DS920+ at http://") || f.rebooted {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "reboot", false); err != nil || !f.rebooted {
		t.Fatal("not rebooted", err)
	}

	f.noDocker = true
	if _, err := invoke(m, "containers", false); err == nil || !strings.Contains(err.Error(), "isn't installed") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "format_volume", false); err == nil {
		t.Fatal("accepted an unknown action")
	}
	_ = m.Close("nas")
	if f.sid != "" {
		t.Fatal("Close didn't sign out")
	}
}

func TestSynologyTwoStep(t *testing.T) {
	f := &fakeDSM{otp: true, now: time.Unix(1_800_000_000, 0)}
	m := setup(t, f, Config{Account: "admin", Password: "secret://pw"})
	if h := m.Health(context.Background(), "nas"); h.Status != "down" || !strings.Contains(h.Message, "two-step") {
		t.Fatalf("%+v", h)
	}

	m = setup(t, f, Config{Account: "admin", Password: "secret://pw", OTPSecret: "secret://otp"})
	if _, err := invoke(m, "system", false); err != nil {
		t.Fatal(err)
	}
	// The device token lets the next sign-in skip the code, even when the
	// clock has moved on.
	c, _ := m.set.Get("nas")
	if c.did != "dev1" {
		t.Fatalf("device token %q", c.did)
	}
	f.now = f.now.Add(time.Hour)
	m.Now = func() time.Time { return time.Unix(0, 0) }
	f.expire = true
	if _, err := invoke(m, "system", false); err != nil {
		t.Fatal(err)
	}
}

func TestSynologyValidation(t *testing.T) {
	f := &fakeDSM{}
	bad := setup(t, f, Config{Account: "admin", Password: "secret://bad"})
	if h := bad.Health(context.Background(), "nas"); h.Status != "down" || !strings.Contains(h.Message, "user name or password") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []Config{
		{URL: "https://nas:5001", Account: "admin", Password: "pw"},
		{URL: "https://nas:5001", Account: "", Password: "secret://pw"},
		{URL: "nas.lan:5001", Account: "admin", Password: "secret://pw"},
		{URL: "https://nas:5001/webapi", Account: "admin", Password: "secret://pw"},
		{URL: "https://nas:5001", Account: "admin", Password: "secret://pw", OTPSecret: "123456"},
		{URL: "https://nas:5001", Account: "admin", Password: "secret://pw", Fingerprint: "zz"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}

func TestSynologyRefusesRedirect(t *testing.T) {
	var leaked bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/webapi/entry.cgi", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Account: "admin", Password: "secret://pw"})
	_ = m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw"}), "nas", raw)
	if _, err := invoke(m, "system", false); err == nil || leaked {
		t.Fatalf("followed the redirect: %v", err)
	}
}
