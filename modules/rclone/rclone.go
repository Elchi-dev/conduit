// Package rclone works with an rclone remote-control server (rclone rcd, or
// rclone with --rc) through its HTTP API and basic auth: remotes, transfer
// stats, jobs, folder listings, and sync and copy as background jobs after
// a preview from rclone's own dry run.
//
// Only a fixed list of rc methods is ever called. Nothing that reads or
// changes rclone's configuration (which holds every remote's credentials)
// is on it, except the list of remote names; nor anything that runs a
// command, a backend command, or sets options.
package rclone

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
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

// Config is one rclone remote-control server.
type Config struct {
	URL      string `json:"url"`      // default http://localhost:5572
	User     string `json:"user"`     // --rc-user
	Password string `json:"password"` // secret:// --rc-pass
	// AllowedRemotes, when set, limits every action to these remotes.
	AllowedRemotes []string `json:"allowedRemotes"`
	// LocalRoots are the local folders (absolute) that paths without a
	// remote may be in. Empty: local paths are refused.
	LocalRoots         []string `json:"localRoots"`
	Fingerprint        string   `json:"fingerprint"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
}

type conn struct {
	cfg   Config
	api   *rest.Client
	roots []string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the rclone module.
func New() *Module { return &Module{} }

// allowed is every rc method this module calls. config/listremotes returns
// remote names only; config/dump, config/get and the rest of config/* are
// never called, nor core/command, backend/command, options/set,
// operations/purge or operations/delete*.
var allowed = map[string]bool{
	"core/version":       true,
	"core/stats":         true,
	"config/listremotes": true,
	"job/list":           true,
	"job/status":         true,
	"job/stop":           true,
	"operations/list":    true,
	"sync/sync":          true,
	"sync/copy":          true,
}

var (
	basePathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	userRe     = regexp.MustCompile(`^[^\x00-\x1f\x7f:]{1,128}$`)
	remoteRe   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_. +@-]{0,63}$`)
	driveRe    = regexp.MustCompile(`^[A-Za-z]:[\\/]`)
	versionRe  = regexp.MustCompile(`^v?(\d{1,4})\.(\d{1,4})(\.\d{1,6})?([-.+][A-Za-z0-9.+-]{0,40})?$`)
)

// Timing of a sync or copy preview. Variables so tests can shorten them.
var (
	previewWait = 20 * time.Second
	pollEvery   = 250 * time.Millisecond
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	job := `{"type":"object","required":["job"],"properties":{"job":{"type":"integer","minimum":1,"description":"Job id (from jobs, sync or copy)"}}}`
	transfer := `{"type":"object","required":["source","destination"],"properties":{
		"source":{"type":"string","description":"remote:path, or a local folder under one of the configured local roots"},
		"destination":{"type":"string","description":"remote:path, or a local folder under one of the configured local roots"}}}`
	return sdk.Manifest{
		ID: "rclone", Name: "rclone", Version: "0.1.0", Category: "Storage", Icon: "cloud",
		Description: "An rclone remote-control server: remotes, transfer stats, jobs, folder listings, and sync or copy as background jobs after a dry-run preview.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["user","password"],"properties":{
			"url":{"type":"string","default":"http://localhost:5572","description":"The address rclone rcd listens on (--rc-addr)"},
			"user":{"type":"string","description":"--rc-user"},
			"password":{"type":"string","x-secret":true,"description":"--rc-pass"},
			"allowedRemotes":{"type":"array","items":{"type":"string"},"description":"Only these remotes (empty: every configured remote)"},
			"localRoots":{"type":"array","items":{"type":"string"},"description":"Local folders (absolute paths) that paths without a remote may be in; empty refuses local paths"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "remotes", Title: "Remotes", Description: "The names of the configured remotes, and whether this instance may use each. Never their settings or credentials.", Risk: sdk.RiskRead},
			{Name: "stats", Title: "Transfer stats", Description: "Bytes, speed, ETA, transfers, checks, deletes, renames and errors, for the server or one job. File names are left out.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"job":{"type":"integer","minimum":1,"description":"Only this job"}}}`)},
			{Name: "jobs", Title: "Jobs", Description: "Background jobs, newest first: id, running or finished, success, start, duration and error.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":20,"maximum":100}}}`)},
			{Name: "job_status", Title: "Job status", Description: "One job: running or finished, success, start, end, duration, error, and its transfer stats.", Risk: sdk.RiskRead, Input: sdk.Schema(job)},
			{Name: "list", Title: "List a folder", Description: "Files and folders at remote:path: name, path, size, modified, folder or not.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["location"],"properties":{"location":{"type":"string","description":"remote:path, or a local folder under one of the configured local roots"},"recursive":{"type":"boolean"},"limit":{"type":"integer","default":500,"maximum":5000}}}`)},
			{Name: "sync", Title: "Sync", Description: "Makes the destination match the source as a background job, deleting files at the destination that aren't in the source. The preview runs rclone's own dry run and reports what would be copied and deleted.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(transfer)},
			{Name: "copy", Title: "Copy", Description: "Copies files from the source that are new or changed to the destination as a background job, replacing changed files there; nothing is deleted. The preview runs rclone's own dry run.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(transfer)},
			{Name: "stop_job", Title: "Stop a job", Description: "Stops a running job. Files already transferred stay; the rest isn't done.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(job)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if strings.TrimSpace(c.URL) == "" {
		c.URL = "http://localhost:5572"
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !basePathRe.MatchString(u.Path) {
		return errors.New("the address is like http://localhost:5572")
	}
	if !userRe.MatchString(c.User) {
		return errors.New("enter the rc user name (--rc-user)")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the rc password in the vault and enter its secret:// reference")
	}
	for _, r := range c.AllowedRemotes {
		if !remoteRe.MatchString(r) {
			return fmt.Errorf("%q isn't a remote name", r)
		}
	}
	var roots []string
	for _, r := range c.LocalRoots {
		n, ok := localPath(r)
		if !ok || hasDotDot(r) {
			return fmt.Errorf("local root %q isn't an absolute path", r)
		}
		roots = append(roots, n)
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
	ref, user := c.Password, c.User
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/"), func(ctx context.Context, r *http.Request) error {
		pw, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.SetBasicAuth(user, strings.TrimRight(pw, "\r\n"))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{cfg: c, api: api, roots: roots})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// rc calls one allowed rc method.
func (c *conn) rc(ctx context.Context, method string, in, out any) error {
	if !allowed[method] {
		return fmt.Errorf("rc method %s isn't one this module calls", method)
	}
	if in == nil {
		in = map[string]any{}
	}
	_, err := c.api.Do(ctx, http.MethodPost, "/"+method, nil, in, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("rclone refused the rc user name or password")
	case rest.IsStatus(err, http.StatusNotFound) && method == "core/version":
		return errors.New("no rclone remote-control API at this address")
	}
	return err
}

// localPath reports whether s is an absolute local path (Unix, or a
// Windows drive), and returns it cleaned with forward slashes.
func localPath(s string) (string, bool) {
	s = strings.TrimSpace(s)
	switch {
	case driveRe.MatchString(s):
		p := path.Clean(strings.ReplaceAll(s, "\\", "/"))
		return strings.ToLower(p[:1]) + p[1:], true
	case strings.HasPrefix(s, "/"):
		return path.Clean(s), true
	}
	return "", false
}

func hasDotDot(s string) bool {
	for _, seg := range strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return true
		}
	}
	return false
}

// location is a checked remote:path, or a local folder.
type location struct {
	remote string // "" for a local path
	path   string
}

func (l location) String() string {
	if l.remote == "" {
		return l.path
	}
	return l.remote + ":" + l.path
}

// parse checks a location without asking the server. Connection-string
// remotes (:s3,key=…: or remote,param=…:) are refused: they carry settings
// and credentials and reach anywhere.
func (c *conn) parse(s string) (location, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 2048 || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return location{}, errors.New("give a location like remote:path/to/folder")
	}
	if hasDotDot(s) {
		return location{}, errors.New("a location can't contain .. parts")
	}
	if p, ok := localPath(s); ok {
		for _, r := range c.roots {
			if p == r || strings.HasPrefix(p, strings.TrimRight(r, "/")+"/") {
				return location{path: p}, nil
			}
		}
		if len(c.roots) == 0 {
			return location{}, errors.New("local paths are off for this instance (set localRoots to allow some folders)")
		}
		return location{}, errors.New("that local path isn't under one of the configured local roots")
	}
	i := strings.Index(s, ":")
	if i < 0 {
		return location{}, errors.New("give remote:path, or an absolute local path")
	}
	name, p := s[:i], s[i+1:]
	if hasDotDot(p) {
		return location{}, errors.New("a location can't contain .. parts")
	}
	if !remoteRe.MatchString(name) {
		return location{}, errors.New("that isn't a configured remote's name (connection strings and on-the-fly remotes aren't allowed)")
	}
	if len(c.cfg.AllowedRemotes) > 0 {
		ok := false
		for _, a := range c.cfg.AllowedRemotes {
			ok = ok || a == name
		}
		if !ok {
			return location{}, fmt.Errorf("remote %s isn't one this instance may use", name)
		}
	}
	return location{remote: name, path: p}, nil
}

func (c *conn) remotes(ctx context.Context) ([]string, error) {
	var out struct {
		Remotes []string `json:"remotes"`
	}
	if err := c.rc(ctx, "config/listremotes", nil, &out); err != nil {
		return nil, err
	}
	sort.Strings(out.Remotes)
	return out.Remotes, nil
}

// resolve parses a location and checks its remote is configured.
func (c *conn) resolve(ctx context.Context, s string) (location, error) {
	l, err := c.parse(s)
	if err != nil || l.remote == "" {
		return l, err
	}
	rs, err := c.remotes(ctx)
	if err != nil {
		return l, err
	}
	for _, r := range rs {
		if r == l.remote {
			return l, nil
		}
	}
	return l, fmt.Errorf("rclone has no remote named %s", l.remote)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := c.rc(ctx, "core/version", nil, &v); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "rclone " + v.Version
	var s stats
	if c.rc(ctx, "core/stats", nil, &s) == nil && s.Transferring > 0 {
		msg += fmt.Sprintf(", %d transfers running", s.Transferring)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type stats struct {
	Bytes          int64   `json:"bytes"`
	TotalBytes     int64   `json:"totalBytes"`
	Speed          float64 `json:"speed"`
	ETA            *int64  `json:"eta"`
	Transfers      int64   `json:"transfers"`
	TotalTransfers int64   `json:"totalTransfers"`
	Checks         int64   `json:"checks"`
	TotalChecks    int64   `json:"totalChecks"`
	Deletes        int64   `json:"deletes"`
	DeletedDirs    int64   `json:"deletedDirs"`
	Renames        int64   `json:"renames"`
	Errors         int64   `json:"errors"`
	FatalError     bool    `json:"fatalError"`
	Elapsed        float64 `json:"elapsedTime"`
	Transferring   int     `json:"-"`
	// transferring and checking list file names; lastError can quote paths.
}

func (s *stats) UnmarshalJSON(b []byte) error {
	type plain stats
	var aux struct {
		plain
		Transferring []json.RawMessage `json:"transferring"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*s = stats(aux.plain)
	s.Transferring = len(aux.Transferring)
	return nil
}

func (s stats) row() map[string]any {
	r := map[string]any{"bytes": s.Bytes, "totalBytes": s.TotalBytes, "bytesPerSecond": int64(s.Speed), "transfers": s.Transfers, "totalTransfers": s.TotalTransfers,
		"checks": s.Checks, "totalChecks": s.TotalChecks, "deletes": s.Deletes, "deletedDirs": s.DeletedDirs, "renames": s.Renames, "errors": s.Errors,
		"transferring": s.Transferring, "elapsedSeconds": int64(s.Elapsed)}
	if s.ETA != nil {
		r["etaSeconds"] = *s.ETA
	}
	if s.FatalError {
		r["fatalError"] = true
	}
	return r
}

type jobStatus struct {
	ID       int64   `json:"id"`
	Group    string  `json:"group"`
	Finished bool    `json:"finished"`
	Success  bool    `json:"success"`
	Error    string  `json:"error"`
	Start    string  `json:"startTime"`
	End      string  `json:"endTime"`
	Duration float64 `json:"duration"`
	// output (a job's result) isn't decoded.
}

func (j jobStatus) row() map[string]any {
	r := map[string]any{"id": j.ID, "finished": j.Finished, "start": j.Start, "durationSeconds": int64(j.Duration)}
	if j.Finished {
		r["success"] = j.Success
		r["end"] = j.End
	}
	if j.Error != "" {
		e := rest.Redact(j.Error)
		if len(e) > 300 {
			e = e[:300] + "…"
		}
		r["error"] = e
	}
	return r
}

func (c *conn) job(ctx context.Context, id int64) (jobStatus, error) {
	var j jobStatus
	err := c.rc(ctx, "job/status", map[string]any{"jobid": id}, &j)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "job not found") {
		return j, fmt.Errorf("there's no rclone job %d", id)
	}
	return j, err
}

type input struct {
	Job         int64  `json:"job"`
	Limit       int    `json:"limit"`
	Location    string `json:"location"`
	Recursive   bool   `json:"recursive"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
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
	case "remotes":
		rs, err := c.remotes(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, r := range rs {
			_, err := c.parse(r + ":")
			out = append(out, map[string]any{"name": r, "allowed": err == nil})
		}
		return sdk.JSON(out)
	case "stats":
		in := map[string]any{}
		if p.Job < 0 || p.Job > 1e12 {
			return sdk.Result{}, errors.New("job is a job id")
		}
		if p.Job > 0 {
			in["group"] = fmt.Sprintf("job/%d", p.Job)
		}
		var s stats
		if err := c.rc(ctx, "core/stats", in, &s); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(s.row())
	case "jobs":
		return c.jobs(ctx, p.Limit)
	case "job_status":
		if p.Job < 1 || p.Job > 1e12 {
			return sdk.Result{}, errors.New("job is a job id from jobs")
		}
		j, err := c.job(ctx, p.Job)
		if err != nil {
			return sdk.Result{}, err
		}
		r := j.row()
		var s stats
		if c.rc(ctx, "core/stats", map[string]any{"group": fmt.Sprintf("job/%d", p.Job)}, &s) == nil {
			r["stats"] = s.row()
		}
		return sdk.JSON(r)
	case "list":
		l, err := c.resolve(ctx, p.Location)
		if err != nil {
			return sdk.Result{}, err
		}
		n := p.Limit
		if n <= 0 {
			n = 500
		}
		if n > 5000 {
			n = 5000
		}
		return c.list(ctx, l, p.Recursive, n)
	case "sync", "copy":
		if _, err := c.parse(p.Source); err != nil {
			return sdk.Result{}, fmt.Errorf("source: %w", err)
		}
		if _, err := c.parse(p.Destination); err != nil {
			return sdk.Result{}, fmt.Errorf("destination: %w", err)
		}
		src, err := c.resolve(ctx, p.Source)
		if err != nil {
			return sdk.Result{}, fmt.Errorf("source: %w", err)
		}
		dst, err := c.resolve(ctx, p.Destination)
		if err != nil {
			return sdk.Result{}, fmt.Errorf("destination: %w", err)
		}
		if src.String() == dst.String() {
			return sdk.JSON(map[string]any{"note": "nothing to change: the source and the destination are the same"})
		}
		return c.transfer(ctx, call, src, dst)
	case "stop_job":
		if p.Job < 1 || p.Job > 1e12 {
			return sdk.Result{}, errors.New("job is a job id from jobs")
		}
		return c.stop(ctx, call, p.Job)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) jobs(ctx context.Context, n int) (sdk.Result, error) {
	if n <= 0 {
		n = 20
	}
	if n > 100 {
		n = 100
	}
	var l struct {
		IDs []int64 `json:"jobids"`
	}
	if err := c.rc(ctx, "job/list", nil, &l); err != nil {
		return sdk.Result{}, err
	}
	sort.Slice(l.IDs, func(i, j int) bool { return l.IDs[i] > l.IDs[j] })
	out := []map[string]any{}
	for _, id := range l.IDs {
		if len(out) >= n {
			break
		}
		j, err := c.job(ctx, id)
		if err != nil {
			continue // finished jobs expire while listing
		}
		out = append(out, j.row())
	}
	return sdk.JSON(out)
}

func (c *conn) list(ctx context.Context, l location, recursive bool, n int) (sdk.Result, error) {
	var out struct {
		List []struct {
			Path    string `json:"Path"`
			Name    string `json:"Name"`
			Size    int64  `json:"Size"`
			ModTime string `json:"ModTime"`
			IsDir   bool   `json:"IsDir"`
		} `json:"list"`
	}
	opt := map[string]any{"recurse": recursive, "noMimeType": true, "showHash": false}
	if err := c.rc(ctx, "operations/list", map[string]any{"fs": l.String(), "remote": "", "opt": opt}, &out); err != nil {
		if strings.Contains(err.Error(), "directory not found") {
			return sdk.Result{}, errors.New("there's no folder at that location")
		}
		return sdk.Result{}, err
	}
	list := []map[string]any{}
	for _, e := range out.List {
		if len(list) >= n {
			break
		}
		r := map[string]any{"name": e.Name, "path": e.Path, "modified": e.ModTime}
		if e.IsDir {
			r["type"] = "folder"
		} else {
			r["type"] = "file"
			r["size"] = e.Size
		}
		list = append(list, r)
	}
	res := map[string]any{"location": l.String(), "entries": list}
	if len(out.List) > n {
		res["more"] = true
	}
	return sdk.JSON(res)
}

// dryRunVersion checks the server is rclone v1.55 or later, the first to
// take _config on an rc call. An older one ignores _config, so a preview
// sent to it would run the sync or copy for real; and since a dry run counts
// what it would transfer and delete in the job's stats, the stats can't
// tell the two apart afterwards.
func (c *conn) dryRunVersion(ctx context.Context) error {
	var v struct {
		Version    string  `json:"version"`
		Decomposed []int64 `json:"decomposed"`
	}
	if err := c.rc(ctx, "core/version", nil, &v); err != nil {
		return err
	}
	var major, minor int64
	if len(v.Decomposed) >= 2 {
		major, minor = v.Decomposed[0], v.Decomposed[1]
	} else if m := versionRe.FindStringSubmatch(strings.TrimSpace(v.Version)); m != nil {
		major, _ = strconv.ParseInt(m[1], 10, 64)
		minor, _ = strconv.ParseInt(m[2], 10, 64)
	} else {
		return errors.New("rclone didn't say its version, so a dry-run preview can't be trusted to be one (it needs v1.55 or later)")
	}
	if major < 1 || major == 1 && minor < 55 {
		return fmt.Errorf("rclone v%d.%d is too old for a dry-run preview: before v1.55 it ignores the dry-run setting and would run the transfer for real; upgrade rclone", major, minor)
	}
	return nil
}

func (c *conn) transfer(ctx context.Context, call sdk.Call, src, dst location) (sdk.Result, error) {
	method := "sync/" + call.Action
	verb := "Sync"
	if call.Action == "copy" {
		verb = "Copy"
	}
	body := map[string]any{"srcFs": src.String(), "dstFs": dst.String(), "_async": true}
	if call.DryRun {
		if err := c.dryRunVersion(ctx); err != nil {
			return sdk.Result{}, err
		}
		body["_config"] = map[string]any{"DryRun": true}
	}
	var started struct {
		JobID int64 `json:"jobid"`
	}
	if err := c.rc(ctx, method, body, &started); err != nil {
		return sdk.Result{}, err
	}
	if started.JobID <= 0 {
		return sdk.Result{}, errors.New("rclone didn't start a job")
	}
	if !call.DryRun {
		return sdk.JSON(map[string]any{"job": started.JobID, "source": src.String(), "destination": dst.String(),
			"note": "started in the background; follow it with job_status, stop it with stop_job"})
	}
	return c.preview(ctx, verb, src, dst, started.JobID)
}

// preview waits for rclone's dry-run job and turns its stats into a Plan.
func (c *conn) preview(ctx context.Context, verb string, src, dst location, id int64) (sdk.Result, error) {
	deadline := time.Now().Add(previewWait)
	var j jobStatus
	for {
		var err error
		if j, err = c.job(ctx, id); err != nil {
			return sdk.Result{}, err
		}
		if j.Finished || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			_ = c.rc(context.WithoutCancel(ctx), "job/stop", map[string]any{"jobid": id}, nil)
			return sdk.Result{}, ctx.Err()
		case <-time.After(pollEvery):
		}
	}
	var s stats
	if err := c.rc(ctx, "core/stats", map[string]any{"group": fmt.Sprintf("job/%d", id)}, &s); err != nil {
		return sdk.Result{}, err
	}
	target := src.String() + " → " + dst.String()
	what := fmt.Sprintf("copy or update %d files (%d bytes)", s.Transfers, s.Bytes)
	if verb == "Sync" {
		what += fmt.Sprintf(" and delete %d files and %d folders at the destination", s.Deletes, s.DeletedDirs)
	}
	var summary string
	switch {
	case !j.Finished:
		_ = c.rc(ctx, "job/stop", map[string]any{"jobid": id}, nil)
		summary = fmt.Sprintf("%s %s: rclone's dry run didn't finish within %s; so far it would %s", verb, target, previewWait, what)
	case !j.Success:
		e := rest.Redact(j.Error)
		if len(e) > 300 {
			e = e[:300] + "…"
		}
		return sdk.Result{}, fmt.Errorf("rclone's dry run failed: %s", e)
	case s.Transfers == 0 && s.Deletes == 0 && s.DeletedDirs == 0 && s.Renames == 0:
		summary = fmt.Sprintf("%s %s: nothing to change, rclone's dry run found the destination up to date", verb, target)
	default:
		summary = fmt.Sprintf("%s %s: rclone's dry run would %s", verb, target, what)
	}
	after, _ := json.Marshal(s.row())
	op := strings.ToLower(verb)
	return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: dst.String(), Op: op, After: after}}}}, nil
}

func (c *conn) stop(ctx context.Context, call sdk.Call, id int64) (sdk.Result, error) {
	j, err := c.job(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	if j.Finished {
		return sdk.JSON(map[string]any{"job": id, "finished": true, "note": "nothing to change: the job already finished"})
	}
	if call.DryRun {
		var s stats
		_ = c.rc(ctx, "core/stats", map[string]any{"group": fmt.Sprintf("job/%d", id)}, &s)
		b, _ := json.Marshal(s.row())
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Stop rclone job %d, running since %s; what it transferred so far stays, the rest isn't done", id, j.Start),
			Changes: []sdk.Change{{Target: fmt.Sprintf("job %d", id), Op: "stop", Before: b}}}}, nil
	}
	if err := c.rc(ctx, "job/stop", map[string]any{"jobid": id}, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"job": id, "stopped": true})
}
