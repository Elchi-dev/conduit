// Package truenas watches and manages a TrueNAS SCALE system through its
// REST API: pools, datasets, alerts, snapshots, scrubs, apps and VMs.
package truenas

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one TrueNAS connection.
type Config struct {
	URL    string `json:"url"`    // https://truenas.lan
	APIKey string `json:"apiKey"` // secret:// API key
	// Fingerprint pins the server certificate (SHA-256), for TrueNAS's
	// default self-signed certificate. Preferred over skipping checks.
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	cfg Config
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client (tests).
	HTTP *http.Client
}

// New returns the TrueNAS module.
func New() *Module { return &Module{} }

var (
	poolRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	datasetRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.: /-]{0,250}$`)
	snapRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$`)
)

func validDataset(s string) bool {
	return datasetRe.MatchString(s) && !strings.Contains(s, "..") && !strings.Contains(s, "//") && !strings.HasSuffix(s, "/")
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	ds := `"dataset":{"type":"string","description":"e.g. tank/media"}`
	return sdk.Manifest{
		ID: "truenas", Name: "TrueNAS", Version: "0.1.0", Category: "Storage", Icon: "disk",
		Description: "Pools, datasets, alerts and snapshots of a TrueNAS SCALE system, plus its apps and VMs.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","format":"uri","description":"e.g. https://truenas.lan"},
			"apiKey":{"type":"string","x-secret":true,"description":"An API key (top-right user menu, API Keys)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, to trust TrueNAS's own self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "system", Title: "System", Description: "Version, hostname, uptime and memory.", Risk: sdk.RiskRead},
			{Name: "pools", Title: "Pools", Description: "Status, health and space of each pool.", Risk: sdk.RiskRead},
			{Name: "datasets", Title: "Datasets", Description: "Used and available space of each dataset.", Risk: sdk.RiskRead},
			{Name: "alerts", Title: "Alerts", Description: "Alerts that haven't been dismissed.", Risk: sdk.RiskRead},
			{Name: "snapshots", Title: "Snapshots", Risk: sdk.RiskRead, Input: sdk.Schema(`{"type":"object","required":["dataset"],"properties":{` + ds + `}}`)},
			{Name: "snapshot", Title: "Take a snapshot", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["dataset","name"],"properties":{` + ds + `,"name":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$"}}}`)},
			{Name: "delete_snapshot", Title: "Delete a snapshot", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["dataset","name"],"properties":{` + ds + `,"name":{"type":"string"}}}`)},
			{Name: "scrub", Title: "Start a scrub", Description: "Checks every block of a pool; heavy disk activity for hours.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["pool"],"properties":{"pool":{"type":"string"}}}`)},
			{Name: "apps", Title: "Apps", Risk: sdk.RiskRead},
			{Name: "vms", Title: "Virtual machines", Risk: sdk.RiskRead},
		},
	}
}

func normFingerprint(s string) (string, error) {
	h := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s)))
	if b, err := hex.DecodeString(h); err != nil || len(b) != sha256.Size {
		return "", errors.New("the fingerprint is a SHA-256 fingerprint: 32 bytes in hex, like AB:CD:…")
	}
	return h, nil
}

func pinned(fp string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // replaced by the pin check below
		VerifyPeerCertificate: func(certs [][]byte, _ [][]*x509.Certificate) error {
			if len(certs) == 0 {
				return errors.New("truenas: no certificate")
			}
			sum := sha256.Sum256(certs[0])
			if hex.EncodeToString(sum[:]) != fp {
				return errors.New("truenas: the server certificate doesn't match the pinned fingerprint")
			}
			return nil
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("the address is like https://truenas.lan")
	}
	if c.APIKey == "" {
		return errors.New("add an API key (stored in the vault)")
	}
	key := c.APIKey
	api := rest.New(u.Scheme+"://"+u.Host+"/api/v2.0", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, key)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k))
		return nil
	})
	switch {
	case m.HTTP != nil:
		api.HTTP = m.HTTP
	case c.Fingerprint != "":
		fp, err := normFingerprint(c.Fingerprint)
		if err != nil {
			return err
		}
		api.HTTP = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: pinned(fp)}}
	case c.InsecureSkipVerify:
		api.HTTP = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}} //nolint:gosec // opt-in, documented
	}
	m.set.Put(id, &conn{cfg: c, api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var info struct {
		Version  string `json:"version"`
		Hostname string `json:"hostname"`
	}
	if _, err := c.api.Do(ctx, "GET", "/system/info", nil, nil, &info); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var alerts []alert
	_, _ = c.api.Do(ctx, "GET", "/alert/list", nil, nil, &alerts)
	crit := 0
	for _, a := range alerts {
		if !a.Dismissed && (a.Level == "CRITICAL" || a.Level == "ALERT" || a.Level == "EMERGENCY" || a.Level == "ERROR") {
			crit++
		}
	}
	if crit > 0 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%s: %d serious alert(s)", info.Hostname, crit)}
	}
	return sdk.Health{Status: "ok", Message: info.Hostname + ", " + info.Version}
}

type alert struct {
	UUID      string `json:"uuid"`
	Level     string `json:"level"`
	Formatted string `json:"formatted"`
	Dismissed bool   `json:"dismissed"`
	Datetime  struct {
		Date int64 `json:"$date"`
	} `json:"datetime"`
}

type parsed struct {
	Parsed int64 `json:"parsed"`
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Dataset string `json:"dataset"`
		Name    string `json:"name"`
		Pool    string `json:"pool"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	api := c.api
	switch call.Action {
	case "system":
		var info map[string]any
		if _, err := api.Do(ctx, "GET", "/system/info", nil, nil, &info); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{}
		for _, k := range []string{"version", "hostname", "uptime_seconds", "physmem", "cores", "model", "system_product"} {
			if v, ok := info[k]; ok {
				out[k] = v
			}
		}
		return sdk.JSON(out)

	case "pools":
		var pools []struct {
			Name      string `json:"name"`
			Status    string `json:"status"`
			Healthy   bool   `json:"healthy"`
			Size      int64  `json:"size"`
			Allocated int64  `json:"allocated"`
			Free      int64  `json:"free"`
			Scan      *struct {
				Function string `json:"function"`
				State    string `json:"state"`
			} `json:"scan"`
		}
		if _, err := api.Do(ctx, "GET", "/pool", nil, nil, &pools); err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			Name    string `json:"name"`
			Status  string `json:"status"`
			Healthy bool   `json:"healthy"`
			Size    int64  `json:"sizeBytes"`
			Used    int64  `json:"usedBytes"`
			Free    int64  `json:"freeBytes"`
			Scan    string `json:"scan,omitempty"`
		}
		out := []row{}
		for _, x := range pools {
			r := row{Name: x.Name, Status: x.Status, Healthy: x.Healthy, Size: x.Size, Used: x.Allocated, Free: x.Free}
			if x.Scan != nil && x.Scan.State != "" {
				r.Scan = strings.ToLower(x.Scan.Function + " " + x.Scan.State)
			}
			out = append(out, r)
		}
		return sdk.JSON(out)

	case "datasets":
		var dss []struct {
			ID        string `json:"id"`
			Used      parsed `json:"used"`
			Available parsed `json:"available"`
		}
		if _, err := api.Do(ctx, "GET", "/pool/dataset", url.Values{"limit": {"500"}}, nil, &dss); err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			Dataset   string `json:"dataset"`
			Used      int64  `json:"usedBytes"`
			Available int64  `json:"availableBytes"`
		}
		out := []row{}
		for _, d := range dss {
			out = append(out, row{d.ID, d.Used.Parsed, d.Available.Parsed})
		}
		return sdk.JSON(out)

	case "alerts":
		var alerts []alert
		if _, err := api.Do(ctx, "GET", "/alert/list", nil, nil, &alerts); err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			Level   string `json:"level"`
			Message string `json:"message"`
			At      string `json:"at,omitempty"`
		}
		out := []row{}
		for _, a := range alerts {
			if a.Dismissed {
				continue
			}
			r := row{Level: strings.ToLower(a.Level), Message: a.Formatted}
			if a.Datetime.Date > 0 {
				r.At = time.UnixMilli(a.Datetime.Date).UTC().Format(time.RFC3339)
			}
			out = append(out, r)
		}
		return sdk.JSON(out)

	case "snapshots":
		if !validDataset(p.Dataset) {
			return sdk.Result{}, errors.New("a dataset is a path like tank/media")
		}
		var snaps []struct {
			Name       string `json:"name"`
			Dataset    string `json:"dataset"`
			Properties struct {
				Creation struct {
					Parsed any `json:"parsed"`
				} `json:"creation"`
				Used parsed `json:"used"`
			} `json:"properties"`
		}
		if _, err := api.Do(ctx, "GET", "/zfs/snapshot", url.Values{"dataset": {p.Dataset}}, nil, &snaps); err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			Name    string `json:"name"`
			Created any    `json:"created,omitempty"`
			Used    int64  `json:"usedBytes"`
		}
		out := []row{}
		for _, s := range snaps {
			if s.Dataset != "" && s.Dataset != p.Dataset {
				continue
			}
			out = append(out, row{Name: s.Name, Created: s.Properties.Creation.Parsed, Used: s.Properties.Used.Parsed})
		}
		return sdk.JSON(out)

	case "snapshot", "delete_snapshot":
		if !validDataset(p.Dataset) {
			return sdk.Result{}, errors.New("a dataset is a path like tank/media")
		}
		if !snapRe.MatchString(p.Name) {
			return sdk.Result{}, errors.New("a snapshot name is letters, digits, dot, colon, dash and underscore")
		}
		full := p.Dataset + "@" + p.Name
		if call.DryRun {
			op := map[string]string{"snapshot": "create", "delete_snapshot": "delete"}[call.Action]
			verb := map[string]string{"create": "Take snapshot ", "delete": "Delete snapshot "}[op]
			return sdk.Result{Plan: &sdk.Plan{Summary: verb + full, Changes: []sdk.Change{{Target: full, Op: op}}}}, nil
		}
		if call.Action == "snapshot" {
			if _, err := api.Do(ctx, "POST", "/zfs/snapshot", nil, map[string]any{"dataset": p.Dataset, "name": p.Name}, nil); err != nil {
				return sdk.Result{}, err
			}
			r, _ := sdk.JSON(map[string]string{"snapshot": full})
			r.Undo = sdk.UndoWith("delete_snapshot", map[string]string{"dataset": p.Dataset, "name": p.Name}, "Delete the snapshot")
			return r, nil
		}
		if _, err := api.Do(ctx, "DELETE", "/zfs/snapshot/id/"+url.PathEscape(full), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": full})

	case "scrub":
		if !poolRe.MatchString(p.Pool) {
			return sdk.Result{}, errors.New("a pool name is letters, digits, dot, dash and underscore")
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Start a scrub of " + p.Pool, Changes: []sdk.Change{{Target: "pool " + p.Pool, Op: "scrub"}}}}, nil
		}
		if _, err := api.Do(ctx, "POST", "/pool/scrub/run", nil, map[string]any{"name": p.Pool, "threshold": 0}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"scrubbing": p.Pool})

	case "apps":
		var apps []struct {
			Name    string `json:"name"`
			State   string `json:"state"`
			Version string `json:"version"`
		}
		if _, err := api.Do(ctx, "GET", "/app", nil, nil, &apps); err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			Name    string `json:"name"`
			State   string `json:"state"`
			Version string `json:"version,omitempty"`
		}
		out := []row{}
		for _, a := range apps {
			out = append(out, row{a.Name, strings.ToLower(a.State), a.Version})
		}
		return sdk.JSON(out)

	case "vms":
		var vms []struct {
			ID     int    `json:"id"`
			Name   string `json:"name"`
			Status struct {
				State string `json:"state"`
			} `json:"status"`
			Memory int64 `json:"memory"`
			VCPUs  int   `json:"vcpus"`
		}
		if _, err := api.Do(ctx, "GET", "/vm", nil, nil, &vms); err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			ID     int    `json:"id"`
			Name   string `json:"name"`
			State  string `json:"state"`
			Memory int64  `json:"memoryMiB"`
			VCPUs  int    `json:"vcpus"`
		}
		out := []row{}
		for _, v := range vms {
			out = append(out, row{v.ID, v.Name, strings.ToLower(v.Status.State), v.Memory, v.VCPUs})
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
