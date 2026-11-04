// Package syncthing works with a Syncthing instance through its REST API
// and the GUI's API key: status and recent errors, folders with their sync
// state, completion and errors, devices and their connections, pending
// devices and folders, pausing and resuming a folder or device, and
// rescans. It reads only what it shows: never the GUI settings (with the
// API key and GUI password) or folder encryption passwords.
package syncthing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Syncthing.
type Config struct {
	URL                string `json:"url"`    // e.g. https://nas.local:8384
	APIKey             string `json:"apiKey"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Syncthing module.
func New() *Module { return &Module{} }

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	deviceRe = regexp.MustCompile(`^[A-Z2-7]{7}(-[A-Z2-7]{7}){7}$`)
)

// maxDetails caps the folders and devices whose details are fetched one by
// one.
const maxDetails = 50

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	target := `{"type":"object","properties":{"folder":{"type":"string","description":"Folder id or label"},"device":{"type":"string","description":"Device id or name"}}}`
	return sdk.Manifest{
		ID: "syncthing", Name: "Syncthing", Version: "0.1.0", Category: "Storage", Icon: "folder",
		Description: "Syncthing: status, folders with completion and errors, connected devices, pending requests, pause/resume and rescans.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"Syncthing's GUI address, e.g. https://nas.local:8384 or http://127.0.0.1:8384"},
			"apiKey":{"type":"string","x-secret":true,"description":"The API key from Actions → Settings → General"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the GUI's certificate, to trust Syncthing's self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Status", Description: "This device's id, version, uptime, discovery and listener status, and recent errors.", Risk: sdk.RiskRead},
			{Name: "folders", Title: "Folders", Description: "Each folder with its state (idle, scanning, syncing, error), paused, completion across devices, what's left to sync and its errors.", Risk: sdk.RiskRead},
			{Name: "devices", Title: "Devices", Description: "The remote devices with paused, connected, address, client version, traffic and how complete they are.", Risk: sdk.RiskRead},
			{Name: "pending", Title: "Pending", Description: "Devices asking to connect and folders other devices offer, waiting to be accepted.", Risk: sdk.RiskRead},
			{Name: "pause", Title: "Pause", Description: "Pauses syncing a folder or with a device. Undo resumes it.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true, Input: sdk.Schema(target)},
			{Name: "resume", Title: "Resume", Description: "Resumes a paused folder or device. Undo pauses it again.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true, Input: sdk.Schema(target)},
			{Name: "rescan", Title: "Rescan", Description: "Scans a folder (or every folder) for changes now.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{"folder":{"type":"string","description":"Folder id or label; all folders when left out"}}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://nas.local:8384")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h) // through the instance's network, if any
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	ref := c.APIKey
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/rest"), func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-API-Key", strings.TrimSpace(k))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Syncthing refused the API key")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("no Syncthing REST API at this address (or this Syncthing is too old for it)")
	}
	return err
}

type sysStatus struct {
	MyID             string  `json:"myID"`
	Uptime           int64   `json:"uptime"`
	StartTime        string  `json:"startTime"`
	DiscoveryEnabled bool    `json:"discoveryEnabled"`
	DiscoveryErrors  any     `json:"discoveryErrors"`
	CPUPercent       float64 `json:"cpuPercent"`
	Goroutines       int     `json:"goroutines"`
	Alloc            int64   `json:"alloc"`
	Listeners        map[string]struct {
		Error *string `json:"error"`
	} `json:"connectionServiceStatus"`
}

type version struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var ping struct {
		Ping string `json:"ping"`
	}
	if err := c.do(ctx, http.MethodGet, "/rest/system/ping", nil, nil, &ping); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if ping.Ping != "pong" {
		return sdk.Health{Status: "down", Message: "unexpected answer: is this Syncthing?"}
	}
	var v version
	msg := "reachable"
	if c.do(ctx, http.MethodGet, "/rest/system/version", nil, nil, &v) == nil && v.Version != "" {
		msg = "Syncthing " + v.Version
	}
	var errs struct {
		Errors []struct{} `json:"errors"`
	}
	if c.do(ctx, http.MethodGet, "/rest/system/error", nil, nil, &errs) == nil && len(errs.Errors) > 0 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%s · %d recent error(s)", msg, len(errs.Errors))}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type folderConfig struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Path    string `json:"path"`
	Type    string `json:"type"`
	Paused  bool   `json:"paused"`
	Devices []struct {
		DeviceID string `json:"deviceID"`
		// encryptionPassword is deliberately not decoded.
	} `json:"devices"`
}

func (f folderConfig) name() string {
	if f.Label != "" {
		return f.Label
	}
	return f.ID
}

type deviceConfig struct {
	DeviceID  string   `json:"deviceID"`
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	Paused    bool     `json:"paused"`
}

func (d deviceConfig) label() string {
	if d.Name != "" {
		return d.Name
	}
	return d.DeviceID[:7]
}

func (c *conn) folderList(ctx context.Context) ([]folderConfig, error) {
	var fs []folderConfig
	err := c.do(ctx, http.MethodGet, "/rest/config/folders", nil, nil, &fs)
	return fs, err
}

func (c *conn) deviceList(ctx context.Context) ([]deviceConfig, string, error) {
	var ds []deviceConfig
	if err := c.do(ctx, http.MethodGet, "/rest/config/devices", nil, nil, &ds); err != nil {
		return nil, "", err
	}
	var st sysStatus
	if err := c.do(ctx, http.MethodGet, "/rest/system/status", nil, nil, &st); err != nil {
		return nil, "", err
	}
	return ds, st.MyID, nil
}

// safeID checks an id taken from Syncthing before it goes in a URL path.
func safeID(id string) bool {
	if id == "" || len(id) > 256 || id == "." || id == ".." || strings.ContainsAny(id, "/\\") {
		return false
	}
	for _, r := range id {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func checkRef(ref, what string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || len(ref) > 256 {
		return "", fmt.Errorf("enter the %s", what)
	}
	for _, r := range ref {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("the %s has control characters", what)
		}
	}
	return ref, nil
}

func (c *conn) findFolder(ctx context.Context, ref string) (folderConfig, error) {
	ref, err := checkRef(ref, "folder's id or label")
	if err != nil {
		return folderConfig{}, err
	}
	fs, err := c.folderList(ctx)
	if err != nil {
		return folderConfig{}, err
	}
	var match *folderConfig
	for i := range fs {
		if fs[i].ID == ref {
			match = &fs[i]
			break
		}
	}
	if match == nil {
		for i := range fs {
			if strings.EqualFold(fs[i].Label, ref) {
				if match != nil {
					return folderConfig{}, fmt.Errorf("more than one folder is labelled %s; use its id", ref)
				}
				match = &fs[i]
			}
		}
	}
	if match == nil {
		have := []string{}
		for _, f := range fs {
			have = append(have, f.name())
		}
		return folderConfig{}, fmt.Errorf("there's no folder %s (folders: %s)", ref, strings.Join(have, ", "))
	}
	if !safeID(match.ID) {
		return folderConfig{}, fmt.Errorf("the folder id %q can't be used in a request", match.ID)
	}
	return *match, nil
}

func (c *conn) findDevice(ctx context.Context, ref string) (deviceConfig, error) {
	ref, err := checkRef(ref, "device's id or name")
	if err != nil {
		return deviceConfig{}, err
	}
	ds, self, err := c.deviceList(ctx)
	if err != nil {
		return deviceConfig{}, err
	}
	var match *deviceConfig
	for i := range ds {
		if ds[i].DeviceID == strings.ToUpper(ref) {
			match = &ds[i]
			break
		}
	}
	if match == nil {
		for i := range ds {
			if strings.EqualFold(ds[i].Name, ref) && ds[i].DeviceID != self {
				if match != nil {
					return deviceConfig{}, fmt.Errorf("more than one device is named %s; use its id", ref)
				}
				match = &ds[i]
			}
		}
	}
	if match == nil {
		have := []string{}
		for _, d := range ds {
			if d.DeviceID != self {
				have = append(have, d.label())
			}
		}
		return deviceConfig{}, fmt.Errorf("there's no device %s (devices: %s)", ref, strings.Join(have, ", "))
	}
	if match.DeviceID == self {
		return deviceConfig{}, errors.New("that's this device; pause its folders instead")
	}
	if !deviceRe.MatchString(match.DeviceID) {
		return deviceConfig{}, errors.New("unexpected device id from Syncthing")
	}
	return *match, nil
}

type completion struct {
	Completion  float64 `json:"completion"`
	NeedBytes   int64   `json:"needBytes"`
	NeedItems   int64   `json:"needItems"`
	GlobalBytes int64   `json:"globalBytes"`
	RemoteState string  `json:"remoteState"`
}

func pct(f float64) float64 { return float64(int(f*10)) / 10 }

type input struct {
	Folder string `json:"folder"`
	Device string `json:"device"`
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
	case "status":
		var st sysStatus
		if err := c.do(ctx, http.MethodGet, "/rest/system/status", nil, nil, &st); err != nil {
			return sdk.Result{}, err
		}
		var v version
		if err := c.do(ctx, http.MethodGet, "/rest/system/version", nil, nil, &v); err != nil {
			return sdk.Result{}, err
		}
		var errs struct {
			Errors []struct {
				When    string `json:"when"`
				Message string `json:"message"`
			} `json:"errors"`
		}
		if err := c.do(ctx, http.MethodGet, "/rest/system/error", nil, nil, &errs); err != nil {
			return sdk.Result{}, err
		}
		listeners := map[string]string{}
		for addr, l := range st.Listeners {
			listeners[addr] = "ok"
			if l.Error != nil && *l.Error != "" {
				listeners[addr] = *l.Error
			}
		}
		recent := []map[string]string{}
		for _, e := range errs.Errors {
			recent = append(recent, map[string]string{"when": e.When, "message": e.Message})
		}
		return sdk.JSON(map[string]any{"deviceId": st.MyID, "version": v.Version, "os": v.OS, "arch": v.Arch, "uptimeSeconds": st.Uptime, "started": st.StartTime,
			"discovery": st.DiscoveryEnabled, "listeners": listeners, "memoryBytes": st.Alloc, "errors": recent})

	case "folders":
		return c.folders(ctx)

	case "devices":
		return c.devices(ctx)

	case "pending":
		var devs map[string]struct {
			Time    string `json:"time"`
			Name    string `json:"name"`
			Address string `json:"address"`
		}
		if err := c.do(ctx, http.MethodGet, "/rest/cluster/pending/devices", nil, nil, &devs); err != nil {
			return sdk.Result{}, err
		}
		var folders map[string]struct {
			OfferedBy map[string]struct {
				Time             string `json:"time"`
				Label            string `json:"label"`
				ReceiveEncrypted bool   `json:"receiveEncrypted"`
				RemoteEncrypted  bool   `json:"remoteEncrypted"`
			} `json:"offeredBy"`
		}
		if err := c.do(ctx, http.MethodGet, "/rest/cluster/pending/folders", nil, nil, &folders); err != nil {
			return sdk.Result{}, err
		}
		pd := []map[string]any{}
		for id, d := range devs {
			pd = append(pd, map[string]any{"deviceId": id, "name": d.Name, "address": d.Address, "since": d.Time})
		}
		sort.Slice(pd, func(i, j int) bool { return pd[i]["deviceId"].(string) < pd[j]["deviceId"].(string) })
		pf := []map[string]any{}
		for id, f := range folders {
			for by, o := range f.OfferedBy {
				e := map[string]any{"folderId": id, "label": o.Label, "offeredBy": by, "since": o.Time}
				if o.ReceiveEncrypted || o.RemoteEncrypted {
					e["encrypted"] = true
				}
				pf = append(pf, e)
			}
		}
		sort.Slice(pf, func(i, j int) bool {
			if pf[i]["folderId"] != pf[j]["folderId"] {
				return pf[i]["folderId"].(string) < pf[j]["folderId"].(string)
			}
			return pf[i]["offeredBy"].(string) < pf[j]["offeredBy"].(string)
		})
		return sdk.JSON(map[string]any{"devices": pd, "folders": pf})

	case "pause", "resume":
		return c.setPaused(ctx, call, p, call.Action == "pause")

	case "rescan":
		q := url.Values{}
		target := "every folder"
		if p.Folder != "" {
			f, err := c.findFolder(ctx, p.Folder)
			if err != nil {
				return sdk.Result{}, err
			}
			if f.Paused {
				return sdk.Result{}, fmt.Errorf("%s is paused; resume it first", f.name())
			}
			q.Set("folder", f.ID)
			target = "folder " + f.name()
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Rescan " + target, Changes: []sdk.Change{{Target: target, Op: "scan"}}}}, nil
		}
		if err := c.do(ctx, http.MethodPost, "/rest/db/scan", q, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"rescanning": target})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) setPaused(ctx context.Context, call sdk.Call, p input, pause bool) (sdk.Result, error) {
	if (p.Folder == "") == (p.Device == "") {
		return sdk.Result{}, errors.New("name a folder or a device (one of them)")
	}
	verb := map[bool]string{true: "Pause", false: "Resume"}[pause]
	undoAction := map[bool]string{true: "resume", false: "pause"}[pause]
	var kind, name, path string
	var was bool
	var undoIn map[string]string
	if p.Folder != "" {
		f, err := c.findFolder(ctx, p.Folder)
		if err != nil {
			return sdk.Result{}, err
		}
		kind, name, was = "folder", f.name(), f.Paused
		path = "/rest/config/folders/" + url.PathEscape(f.ID)
		undoIn = map[string]string{"folder": f.ID}
	} else {
		d, err := c.findDevice(ctx, p.Device)
		if err != nil {
			return sdk.Result{}, err
		}
		kind, name, was = "device", d.label(), d.Paused
		path = "/rest/config/devices/" + d.DeviceID
		undoIn = map[string]string{"device": d.DeviceID}
	}
	if call.DryRun {
		sum := verb + " " + kind + " " + name
		if was == pause {
			sum = strings.ToUpper(kind[:1]) + kind[1:] + " " + name + " is already " + map[bool]string{true: "paused", false: "running"}[was] + "; nothing would change"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: kind + " " + name, Op: strings.ToLower(verb),
			Before: mustJSON(map[string]bool{"paused": was}), After: mustJSON(map[string]bool{"paused": pause})}}}}, nil
	}
	if was == pause {
		return sdk.JSON(map[string]any{kind: name, "paused": was, "changed": false})
	}
	if err := c.do(ctx, http.MethodPatch, path, nil, map[string]bool{"paused": pause}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{kind: name, "paused": pause, "changed": true})
	res.Undo = sdk.UndoWith(undoAction, undoIn, map[bool]string{true: "Resume ", false: "Pause "}[pause]+kind+" "+name)
	return res, err
}

func (c *conn) folders(ctx context.Context) (sdk.Result, error) {
	fs, err := c.folderList(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	sort.SliceStable(fs, func(i, j int) bool { return strings.ToLower(fs[i].name()) < strings.ToLower(fs[j].name()) })
	out := []map[string]any{}
	for i, f := range fs {
		e := map[string]any{"id": f.ID, "label": f.Label, "path": f.Path, "type": f.Type, "paused": f.Paused, "devices": len(f.Devices)}
		if i >= maxDetails || !safeID(f.ID) {
			out = append(out, e)
			continue
		}
		q := url.Values{"folder": {f.ID}}
		var st struct {
			State        string `json:"state"`
			StateChanged string `json:"stateChanged"`
			Error        string `json:"error"`
			GlobalBytes  int64  `json:"globalBytes"`
			GlobalFiles  int64  `json:"globalFiles"`
			LocalBytes   int64  `json:"localBytes"`
			NeedBytes    int64  `json:"needBytes"`
			NeedFiles    int64  `json:"needFiles"`
			NeedDeletes  int64  `json:"needDeletes"`
			PullErrors   int    `json:"pullErrors"`
			Errors       int    `json:"errors"`
		}
		if err := c.do(ctx, http.MethodGet, "/rest/db/status", q, nil, &st); err != nil {
			return sdk.Result{}, err
		}
		e["state"], e["since"], e["globalBytes"], e["globalFiles"], e["localBytes"] = st.State, st.StateChanged, st.GlobalBytes, st.GlobalFiles, st.LocalBytes
		if st.NeedBytes > 0 || st.NeedFiles > 0 || st.NeedDeletes > 0 {
			e["needBytes"], e["needFiles"], e["needDeletes"] = st.NeedBytes, st.NeedFiles, st.NeedDeletes
		}
		if st.Error != "" {
			e["error"] = st.Error
		}
		var cp completion
		if err := c.do(ctx, http.MethodGet, "/rest/db/completion", q, nil, &cp); err == nil {
			e["completion"] = pct(cp.Completion)
		}
		if n := st.PullErrors + st.Errors; n > 0 {
			var fe struct {
				Errors []struct {
					Path  string `json:"path"`
					Error string `json:"error"`
				} `json:"errors"`
			}
			if err := c.do(ctx, http.MethodGet, "/rest/folder/errors", url.Values{"folder": {f.ID}, "page": {"1"}, "perpage": {"10"}}, nil, &fe); err == nil {
				list := []map[string]string{}
				for _, x := range fe.Errors {
					list = append(list, map[string]string{"path": x.Path, "error": x.Error})
				}
				e["fileErrors"], e["fileErrorCount"] = list, n
			}
		}
		out = append(out, e)
	}
	return sdk.JSON(out)
}

func (c *conn) devices(ctx context.Context) (sdk.Result, error) {
	ds, self, err := c.deviceList(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	var conns struct {
		Connections map[string]struct {
			Connected     bool   `json:"connected"`
			Paused        bool   `json:"paused"`
			Address       string `json:"address"`
			ClientVersion string `json:"clientVersion"`
			Type          string `json:"type"`
			InBytesTotal  int64  `json:"inBytesTotal"`
			OutBytesTotal int64  `json:"outBytesTotal"`
			At            string `json:"at"`
		} `json:"connections"`
	}
	if err := c.do(ctx, http.MethodGet, "/rest/system/connections", nil, nil, &conns); err != nil {
		return sdk.Result{}, err
	}
	var seen map[string]struct {
		LastSeen string `json:"lastSeen"`
	}
	_ = c.do(ctx, http.MethodGet, "/rest/stats/device", nil, nil, &seen) // optional
	sort.SliceStable(ds, func(i, j int) bool { return strings.ToLower(ds[i].label()) < strings.ToLower(ds[j].label()) })
	out := []map[string]any{}
	n := 0
	for _, d := range ds {
		if d.DeviceID == self || !deviceRe.MatchString(d.DeviceID) {
			continue
		}
		e := map[string]any{"id": d.DeviceID, "name": d.Name, "paused": d.Paused}
		if cn, ok := conns.Connections[d.DeviceID]; ok {
			e["connected"] = cn.Connected
			if cn.Connected {
				e["address"], e["clientVersion"], e["connectionType"], e["inBytes"], e["outBytes"] = cn.Address, cn.ClientVersion, cn.Type, cn.InBytesTotal, cn.OutBytesTotal
			}
		} else {
			e["connected"] = false
		}
		if s, ok := seen[d.DeviceID]; ok && s.LastSeen != "" && !strings.HasPrefix(s.LastSeen, "1970-") {
			e["lastSeen"] = s.LastSeen
		}
		if n < maxDetails {
			var cp completion
			if err := c.do(ctx, http.MethodGet, "/rest/db/completion", url.Values{"device": {d.DeviceID}}, nil, &cp); err == nil {
				e["completion"] = pct(cp.Completion)
				if cp.NeedBytes > 0 {
					e["needBytes"] = cp.NeedBytes
				}
			}
		}
		n++
		out = append(out, e)
	}
	return sdk.JSON(out)
}
