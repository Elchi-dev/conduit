// Package proxmoxbackup works with a Proxmox Backup Server through its API
// and an API token: datastores and their usage, backup groups and
// snapshots (counts, last backup, verify state), tasks, and starting a
// verify job. Pruning, deleting and task logs are not offered.
package proxmoxbackup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Proxmox Backup Server.
type Config struct {
	URL         string `json:"url"`         // https://pbs.lan:8007
	TokenID     string `json:"tokenId"`     // user@realm!name
	TokenSecret string `json:"tokenSecret"` // secret:// token value
	// Fingerprint pins the server certificate by its SHA-256 fingerprint,
	// for the self-signed certificate PBS uses by default.
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Proxmox Backup Server module.
func New() *Module { return &Module{} }

var (
	tokenRe = regexp.MustCompile(`^[A-Za-z0-9._@-]+@[A-Za-z0-9._-]+![A-Za-z0-9._-]+$`)
	// Patterns from the PBS API schema.
	storeRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{2,31}$`)
	idRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	nsRe    = regexp.MustCompile(`^(?:[A-Za-z0-9_][A-Za-z0-9._-]{0,31}/){0,7}[A-Za-z0-9_][A-Za-z0-9._-]{0,31}$`)
	upidRe  = regexp.MustCompile(`^UPID:[A-Za-z0-9._:@!-]{1,400}$`)
	pathRe  = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	types   = map[string]bool{"vm": true, "ct": true, "host": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	scope := `"store":{"type":"string","description":"Datastore name (from datastores)"},"ns":{"type":"string","description":"Namespace, e.g. site1/hosts (empty for the root)"}`
	group := `,"type":{"type":"string","enum":["vm","ct","host"],"description":"Backup type"},"id":{"type":"string","description":"Backup id, e.g. 101 or a host name"}`
	return sdk.Manifest{
		ID: "proxmoxbackup", Name: "Proxmox Backup Server", Version: "0.1.0", Category: "Storage", Icon: "archive",
		Description: "Proxmox Backup Server: datastores and usage, backup groups and snapshots with verify state, tasks, and verify jobs.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","tokenId","tokenSecret"],"properties":{
			"url":{"type":"string","format":"uri","description":"e.g. https://pbs.lan:8007"},
			"tokenId":{"type":"string","description":"API token id, user@realm!name (Configuration, Access Control, API Token)"},
			"tokenSecret":{"type":"string","x-secret":true,"description":"The token's secret"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate (Dashboard, Show Fingerprint), to trust PBS's own self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "datastores", Title: "Datastores", Description: "Each datastore with total, used and free space, the estimated date it fills up, mount and maintenance state.", Risk: sdk.RiskRead},
			{Name: "groups", Title: "Backup groups", Description: "Backup groups of a datastore: type, id, number of snapshots, last backup, owner and comment.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["store"],"properties":{` + scope + `}}`)},
			{Name: "snapshots", Title: "Backup snapshots", Description: "Snapshots, newest first: time, size, verify state, protected, encrypted and comment. Never the encryption key's fingerprint.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["store"],"properties":{` + scope + group + `,"limit":{"type":"integer","minimum":1,"maximum":1000,"default":100}}}`)},
			{Name: "tasks", Title: "Tasks", Description: "Recent tasks (backups, verifies, prunes, garbage collection, syncs), newest first, with their result. Task logs are never read.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"store":{"type":"string","description":"Only this datastore's tasks"},"running":{"type":"boolean"},"errors":{"type":"boolean","description":"Only failed tasks"},"limit":{"type":"integer","minimum":1,"maximum":500,"default":50}}}`)},
			{Name: "verify", Title: "Start a verify job", Description: "Reads back and checks every chunk of the chosen snapshots: a whole datastore, a namespace, one group or one snapshot. Heavy disk activity; nothing is changed or deleted.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["store"],"properties":{` + scope + group + `,
					"time":{"type":"integer","minimum":1,"description":"One snapshot's backup time (Unix seconds, from snapshots); needs type and id"},
					"ignoreVerified":{"type":"boolean","default":true,"description":"Skip snapshots already verified"},
					"outdatedAfter":{"type":"integer","minimum":1,"description":"Verify again when the last verification is older than this many days"}}}`)},
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
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://pbs.lan:8007")
	}
	if !tokenRe.MatchString(c.TokenID) {
		return errors.New("the token id looks like root@pam!conduit")
	}
	if !strings.HasPrefix(c.TokenSecret, "secret://") {
		return errors.New("store the token secret in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	tokenID, ref := c.TokenID, c.TokenSecret
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api2/json")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api2/json", func(ctx context.Context, r *http.Request) error {
		s, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "PBSAPIToken="+tokenID+":"+strings.TrimSpace(s))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Proxmox Backup Server refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the API token isn't allowed to do this (check its permissions, and the user's: a token never has more)")
	}
	return err
}

// do calls the API; PBS wraps every answer in {"data": …}.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if _, err := c.api.Do(ctx, method, path, q, body, &env); err != nil {
		return friendly(err)
	}
	if out == nil || len(env.Data) == 0 || string(env.Data) == "null" {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("proxmoxbackup: unexpected answer: %w", err)
	}
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		Version string `json:"version"`
		Release string `json:"release"`
	}
	if err := c.do(ctx, http.MethodGet, "/version", nil, nil, &v); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Proxmox Backup Server API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if v.Version == "" {
		return sdk.Health{Status: "down", Message: "no Proxmox Backup Server API at this address"}
	}
	ver := v.Version
	if v.Release != "" {
		ver += "." + v.Release
	}
	msg := "Proxmox Backup Server " + ver
	var us []usage
	if c.do(ctx, http.MethodGet, "/status/datastore-usage", nil, nil, &us) == nil {
		msg += fmt.Sprintf(", %d datastores", len(us))
		for _, u := range us {
			if u.Error != "" {
				return sdk.Health{Status: "degraded", Message: msg + "; " + u.Store + ": " + clip(rest.Redact(u.Error))}
			}
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type usage struct {
	Store         string `json:"store"`
	Total         int64  `json:"total"`
	Used          int64  `json:"used"`
	Avail         int64  `json:"avail"`
	EstimatedFull *int64 `json:"estimated-full-date"`
	Error         string `json:"error"`
	MountStatus   string `json:"mount-status"`
	Backend       string `json:"backend-type"`
}

type params struct {
	Store          string `json:"store"`
	NS             string `json:"ns"`
	Type           string `json:"type"`
	ID             string `json:"id"`
	Time           int64  `json:"time"`
	Limit          int    `json:"limit"`
	Running        bool   `json:"running"`
	Errors         bool   `json:"errors"`
	IgnoreVerified *bool  `json:"ignoreVerified"`
	OutdatedAfter  int    `json:"outdatedAfter"`
}

// check validates the datastore, namespace and group before any request.
func (p *params) check(needStore bool) error {
	p.Store, p.NS, p.ID = strings.TrimSpace(p.Store), strings.Trim(strings.TrimSpace(p.NS), "/"), strings.TrimSpace(p.ID)
	if (needStore || p.Store != "") && !storeRe.MatchString(p.Store) {
		return errors.New("a datastore name has 3 to 32 letters, digits, '.', '_' and '-' (see datastores)")
	}
	if p.NS != "" && (len(p.NS) > 256 || !nsRe.MatchString(p.NS)) {
		return errors.New("a namespace is up to 8 names separated by '/', each of letters, digits, '.', '_' and '-'")
	}
	if p.Type != "" && !types[p.Type] {
		return errors.New("the backup type is vm, ct or host")
	}
	if p.ID != "" && !idRe.MatchString(p.ID) {
		return errors.New("a backup id has letters, digits, '.', '_' and '-' (see groups)")
	}
	if p.ID != "" && p.Type == "" {
		return errors.New("give the backup type (vm, ct or host) with the id")
	}
	if p.Time < 0 || (p.Time > 0 && (p.Type == "" || p.ID == "")) {
		return errors.New("a snapshot is given by type, id and time")
	}
	if p.Limit < 0 || p.OutdatedAfter < 0 {
		return errors.New("limit and outdatedAfter are positive numbers")
	}
	return nil
}

func (p *params) query() url.Values {
	q := url.Values{}
	if p.NS != "" {
		q.Set("ns", p.NS)
	}
	if p.Type != "" {
		q.Set("backup-type", p.Type)
	}
	if p.ID != "" {
		q.Set("backup-id", p.ID)
	}
	return q
}

func gib(b int64) float64 { return float64(b>>20) / 1024 }

func pct(a, b int64) float64 {
	if b <= 0 {
		return 0
	}
	return float64(int(float64(a)/float64(b)*1000)) / 10
}

func when(t int64) string {
	if t <= 0 {
		return ""
	}
	return time.Unix(t, 0).UTC().Format(time.RFC3339)
}

// clip keeps server text (task results, datastore errors) to one short
// line; it's redacted before the cut.
func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 200 {
		return string(r[:200]) + "…"
	}
	return s
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p params
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "datastores":
		return c.datastores(ctx)
	case "groups":
		if err := p.check(true); err != nil {
			return sdk.Result{}, err
		}
		return c.groups(ctx, p)
	case "snapshots":
		if err := p.check(true); err != nil {
			return sdk.Result{}, err
		}
		if p.Limit == 0 {
			p.Limit = 100
		}
		return c.listSnapshots(ctx, p)
	case "tasks":
		if err := p.check(false); err != nil {
			return sdk.Result{}, err
		}
		return c.tasks(ctx, p)
	case "verify":
		if err := p.check(true); err != nil {
			return sdk.Result{}, err
		}
		return c.verify(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) datastores(ctx context.Context) (sdk.Result, error) {
	var list []struct {
		Store       string `json:"store"`
		Comment     string `json:"comment"`
		Maintenance string `json:"maintenance"`
	}
	if err := c.do(ctx, http.MethodGet, "/admin/datastore", nil, nil, &list); err != nil {
		return sdk.Result{}, err
	}
	var us []usage
	if err := c.do(ctx, http.MethodGet, "/status/datastore-usage", nil, nil, &us); err != nil {
		return sdk.Result{}, err
	}
	by := map[string]usage{}
	for _, u := range us {
		by[u.Store] = u
	}
	out := []map[string]any{}
	for _, d := range list {
		row := map[string]any{"store": d.Store}
		if d.Comment != "" {
			row["comment"] = d.Comment
		}
		if d.Maintenance != "" {
			row["maintenance"] = clip(rest.Redact(d.Maintenance))
		}
		if u, ok := by[d.Store]; ok {
			row["totalGiB"], row["usedGiB"], row["usedPercent"] = gib(u.Total), gib(u.Used), pct(u.Used, u.Total)
			if u.Avail >= 0 {
				row["freeGiB"] = gib(u.Avail)
			}
			if u.EstimatedFull != nil && *u.EstimatedFull > 0 {
				row["estimatedFull"] = when(*u.EstimatedFull)
			}
			if u.MountStatus != "" {
				row["mountStatus"] = u.MountStatus
			}
			if u.Backend != "" {
				row["backend"] = u.Backend
			}
			if u.Error != "" {
				row["error"] = clip(rest.Redact(u.Error))
			}
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

func (c *conn) groups(ctx context.Context, p params) (sdk.Result, error) {
	var gs []struct {
		Type       string `json:"backup-type"`
		ID         string `json:"backup-id"`
		Count      int    `json:"backup-count"`
		LastBackup int64  `json:"last-backup"`
		Owner      string `json:"owner"`
		Comment    string `json:"comment"`
	}
	q := url.Values{}
	if p.NS != "" {
		q.Set("ns", p.NS)
	}
	if err := c.do(ctx, http.MethodGet, "/admin/datastore/"+url.PathEscape(p.Store)+"/groups", q, nil, &gs); err != nil {
		return sdk.Result{}, notFound(err, p.Store)
	}
	sort.Slice(gs, func(i, j int) bool {
		if gs[i].Type != gs[j].Type {
			return gs[i].Type < gs[j].Type
		}
		return gs[i].ID < gs[j].ID
	})
	out := []map[string]any{}
	for _, g := range gs {
		row := map[string]any{"type": g.Type, "id": g.ID, "snapshots": g.Count, "lastBackup": when(g.LastBackup), "owner": g.Owner}
		if g.Comment != "" {
			row["comment"] = g.Comment
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

type snapshot struct {
	Type         string `json:"backup-type"`
	ID           string `json:"backup-id"`
	Time         int64  `json:"backup-time"`
	Size         int64  `json:"size"`
	Protected    bool   `json:"protected"`
	Comment      string `json:"comment"`
	Owner        string `json:"owner"`
	Fingerprint  string `json:"fingerprint"` // the encryption key's: only whether it's set is shown
	Verification *struct {
		State string `json:"state"`
	} `json:"verification"`
	Files []json.RawMessage `json:"files"`
}

func (s snapshot) verifyState() string {
	if s.Verification == nil || s.Verification.State == "" {
		return "none"
	}
	return s.Verification.State
}

func (s snapshot) label() string {
	return s.Type + "/" + s.ID + "/" + when(s.Time)
}

func notFound(err error, store string) error {
	if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusBadRequest) {
		return fmt.Errorf("no datastore, namespace or group like that on %s (%v)", store, err)
	}
	return err
}

func (c *conn) snapshots(ctx context.Context, p params) ([]snapshot, error) {
	var ss []snapshot
	if err := c.do(ctx, http.MethodGet, "/admin/datastore/"+url.PathEscape(p.Store)+"/snapshots", p.query(), nil, &ss); err != nil {
		return nil, notFound(err, p.Store)
	}
	if p.Time > 0 {
		kept := ss[:0]
		for _, s := range ss {
			if s.Time == p.Time {
				kept = append(kept, s)
			}
		}
		ss = kept
	}
	sort.Slice(ss, func(i, j int) bool { return ss[i].Time > ss[j].Time })
	return ss, nil
}

func (c *conn) listSnapshots(ctx context.Context, p params) (sdk.Result, error) {
	ss, err := c.snapshots(ctx, p)
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for i, s := range ss {
		if i >= p.Limit {
			break
		}
		row := map[string]any{"type": s.Type, "id": s.ID, "time": s.Time, "taken": when(s.Time), "sizeGiB": gib(s.Size), "sizeBytes": s.Size,
			"verify": s.verifyState(), "protected": s.Protected, "encrypted": s.Fingerprint != "", "files": len(s.Files), "owner": s.Owner}
		if s.Comment != "" {
			row["comment"] = s.Comment
		}
		out = append(out, row)
	}
	return sdk.JSON(map[string]any{"total": len(ss), "snapshots": out})
}

type task struct {
	UPID       string `json:"upid"`
	Type       string `json:"worker_type"`
	WorkerID   string `json:"worker_id"`
	User       string `json:"user"`
	Start      int64  `json:"starttime"`
	End        int64  `json:"endtime"`
	Status     string `json:"status"`
	ExitStatus string `json:"exitstatus"`
}

func (c *conn) tasks(ctx context.Context, p params) (sdk.Result, error) {
	limit := p.Limit
	if limit == 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if p.Store != "" {
		q.Set("store", p.Store)
	}
	if p.Running {
		q.Set("running", "1")
	}
	if p.Errors {
		q.Set("errors", "1")
	}
	var ts []task
	if err := c.do(ctx, http.MethodGet, "/nodes/localhost/tasks", q, nil, &ts); err != nil {
		return sdk.Result{}, err
	}
	sort.SliceStable(ts, func(i, j int) bool { return ts[i].Start > ts[j].Start })
	out := []map[string]any{}
	for _, t := range ts {
		row := map[string]any{"type": t.Type, "target": t.WorkerID, "user": t.User, "started": when(t.Start)}
		if t.End > 0 {
			row["ended"] = when(t.End)
			row["result"] = clip(rest.Redact(t.Status))
		} else {
			row["result"] = "running"
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

func (c *conn) verify(ctx context.Context, call sdk.Call, p params) (sdk.Result, error) {
	ignore := p.IgnoreVerified == nil || *p.IgnoreVerified
	ss, err := c.snapshots(ctx, p)
	if err != nil {
		return sdk.Result{}, err
	}
	if p.Time > 0 && len(ss) == 0 {
		return sdk.Result{}, fmt.Errorf("there's no snapshot %s/%s at %s in %s", p.Type, p.ID, when(p.Time), p.Store)
	}
	pending := 0
	states := map[string]int{}
	for _, s := range ss {
		states[s.verifyState()]++
		if !ignore || s.verifyState() != "ok" {
			pending++
		}
	}
	target := "datastore " + p.Store
	if p.NS != "" {
		target += ", namespace " + p.NS
	}
	switch {
	case p.Time > 0:
		target += ", snapshot " + ss[0].label()
	case p.ID != "":
		target += ", group " + p.Type + "/" + p.ID
	case p.Type != "":
		target += ", every " + p.Type + " group"
	}
	if pending == 0 && p.OutdatedAfter == 0 {
		return sdk.JSON(map[string]any{"target": target, "snapshots": len(ss), "verify": states, "changed": false, "note": "nothing to change: every snapshot is verified"})
	}
	if call.DryRun {
		before, _ := json.Marshal(map[string]any{"snapshots": len(ss), "verify": states})
		after, _ := json.Marshal(map[string]any{"toVerify": pending, "ignoreVerified": ignore, "outdatedAfterDays": p.OutdatedAfter})
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Verify %s (%d of %d snapshots)", target, pending, len(ss)),
			Changes: []sdk.Change{{Target: target, Op: "verify", Before: before, After: after}}}}, nil
	}
	body := map[string]any{"ignore-verified": ignore}
	if p.NS != "" {
		body["ns"] = p.NS
	}
	if p.Type != "" {
		body["backup-type"] = p.Type
	}
	if p.ID != "" {
		body["backup-id"] = p.ID
	}
	if p.Time > 0 {
		body["backup-time"] = p.Time
	}
	if p.OutdatedAfter > 0 {
		body["outdated-after"] = p.OutdatedAfter
	}
	var upid string
	if err := c.do(ctx, http.MethodPost, "/admin/datastore/"+url.PathEscape(p.Store)+"/verify", nil, body, &upid); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"target": target, "toVerify": pending, "changed": true}
	if !upidRe.MatchString(upid) {
		out["note"] = "the verify job started; follow it with tasks"
		return sdk.JSON(out)
	}
	// Read the job back: PBS may refuse it right away (another verify
	// holds the datastore, say).
	var st task
	if err := c.do(ctx, http.MethodGet, "/nodes/localhost/tasks/"+url.PathEscape(upid)+"/status", nil, nil, &st); err == nil {
		if st.Status == "stopped" && st.ExitStatus != "" && st.ExitStatus != "OK" {
			return sdk.Result{}, fmt.Errorf("the verify job ended at once: %s", clip(rest.Redact(st.ExitStatus)))
		}
		out["status"] = st.Status
		if st.ExitStatus != "" {
			out["result"] = clip(rest.Redact(st.ExitStatus))
		}
	}
	return sdk.JSON(out)
}
