// Package kopia works with a Kopia repository server (kopia server start)
// through its API: snapshot sources and their state, snapshots, policies,
// repository and maintenance status, and starting a snapshot of a source.
package kopia

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Kopia server.
type Config struct {
	URL                string `json:"url"`      // e.g. https://backup.example.com:51515
	Username           string `json:"username"` // --server-username, default kopia
	Password           string `json:"password"` // secret:// --server-password
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	http   *http.Client
	origin string
	user   string
	pass   string // secret:// reference
	host   sdk.Host

	mu      sync.Mutex
	cookies []*http.Cookie
	csrf    string
	fetched bool
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Kopia module.
func New() *Module { return &Module{} }

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	userRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)
	srcRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$`)
	csrfMeta = regexp.MustCompile(`<meta\s+name="kopia-csrf-token"\s+content="([A-Za-z0-9._~+/=-]{1,200})"`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	source := `"userName":{"type":"string","description":"The source's user (from sources)"},"host":{"type":"string","description":"The source's host"},"path":{"type":"string","description":"The source's path"}`
	return sdk.Manifest{
		ID: "kopia", Name: "Kopia", Version: "0.1.0", Category: "Storage", Icon: "archive",
		Description: "A Kopia repository server: sources and their last and next snapshot, snapshots, policies, repository and maintenance status; start a snapshot.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","password"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://backup.example.com:51515"},
			"username":{"type":"string","default":"kopia","description":"The server's UI user (--server-username)"},
			"password":{"type":"string","x-secret":true,"description":"The UI user's password (--server-password)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate (kopia server start --tls-generate-cert prints it)"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Repository status", Description: "Whether the server is connected to a repository, its storage, format, encryption and description, and whether it's read-only.", Risk: sdk.RiskRead},
			{Name: "sources", Title: "Sources", Description: "What's backed up: each source's state (idle, uploading, paused, failed), its last snapshot (time, size, files, errors), next scheduled snapshot and upload progress.", Risk: sdk.RiskRead},
			{Name: "snapshots", Title: "Snapshots", Description: "Snapshots of one source, or of every source: start and end time, size, files, errors, retention reasons and pins.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + source + `,"limit":{"type":"integer","default":20,"minimum":1,"maximum":500,"description":"Newest snapshots per source"}}}`)},
			{Name: "policies", Title: "Policies", Description: "Policies by target: retention, schedule, compression, file rules, error handling and upload settings. Before and after snapshot actions (commands) are left out.", Risk: sdk.RiskRead},
			{Name: "maintenance", Title: "Maintenance status", Description: "The server's recent maintenance runs (quick and full): when, how long, and whether they succeeded.", Risk: sdk.RiskRead},
			{Name: "start_snapshot", Title: "Snapshot a source now", Description: "Starts a snapshot of one source; old snapshots expire by its policy as usual.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["userName","host","path"],"properties":{` + source + `}}`)},
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
		return errors.New("the address is like https://backup.example.com:51515")
	}
	if c.Username == "" {
		c.Username = "kopia"
	}
	if !userRe.MatchString(c.Username) {
		return errors.New("the username is letters, digits and . _ @ -")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the server password in the vault and enter its secret:// reference")
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
	client = rest.SameHostOnly(client)
	origin := u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/")
	cn := &conn{http: client, origin: origin, user: c.Username, pass: c.Password, host: h}
	cn.api = rest.New(origin+"/api/v1", cn.auth)
	cn.api.HTTP = client
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) basic(ctx context.Context, r *http.Request) error {
	pw, err := c.host.Secret(ctx, c.pass)
	if err != nil {
		return err
	}
	r.SetBasicAuth(c.user, strings.TrimRight(pw, "\r\n"))
	return nil
}

// auth signs a request in: basic auth, and the session cookie and CSRF
// token the server's API wants with it (taken from its web page).
func (c *conn) auth(ctx context.Context, r *http.Request) error {
	if err := c.basic(ctx, r); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.fetched {
		if err := c.session(ctx); err != nil {
			return err
		}
	}
	for _, ck := range c.cookies {
		r.AddCookie(ck)
	}
	if c.csrf != "" {
		r.Header.Set("X-Kopia-Csrf-Token", c.csrf)
	}
	return nil
}

// session loads the web page, which sets the session cookie and carries
// the CSRF token tied to it. A server started without its UI has neither,
// and is called without them. Called with c.mu held.
func (c *conn) session(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/", nil)
	if err != nil {
		return err
	}
	if err := c.basic(ctx, req); err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Conduit")
	res, err := c.http.Do(req)
	if err != nil {
		return rest.TransportError(err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return errors.New("Kopia refused the username or password")
	}
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	c.cookies = nil
	for _, ck := range res.Cookies() {
		// Kopia-Auth is a one-minute token for the browser; basic auth
		// is sent each time instead.
		if ck.Name != "Kopia-Auth" {
			c.cookies = append(c.cookies, &http.Cookie{Name: ck.Name, Value: ck.Value})
		}
	}
	c.csrf = ""
	if mm := csrfMeta.FindSubmatch(body); mm != nil {
		c.csrf = string(mm[1])
	}
	c.fetched = true
	return nil
}

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Kopia refused the username or password")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Kopia refused the request (the user may not be the server's UI user)")
	}
	return err
}

// do calls the API, getting a new session once when the server turns the
// old one down (it restarted, and the CSRF token changed).
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusForbidden) {
		c.mu.Lock()
		c.fetched = false
		c.mu.Unlock()
		_, err = c.api.Do(ctx, method, path, q, body, out)
	}
	return friendly(err)
}

type source struct {
	Host     string `json:"host"`
	UserName string `json:"userName"`
	Path     string `json:"path"`
}

func (s source) String() string { return s.UserName + "@" + s.Host + ":" + s.Path }

type summary struct {
	Size      int64 `json:"size"`
	Files     int64 `json:"files"`
	Dirs      int64 `json:"dirs"`
	Errors    int   `json:"errors"`
	NumFailed int   `json:"numFailed"`
}

type sourceInfo struct {
	Source       source `json:"source"`
	Status       string `json:"status"`
	LastSnapshot *struct {
		StartTime string `json:"startTime"`
		EndTime   string `json:"endTime"`
		Stats     struct {
			TotalSize  int64 `json:"totalSize"`
			FileCount  int64 `json:"fileCount"`
			ErrorCount int   `json:"errorCount"`
		} `json:"stats"`
		RootEntry *struct {
			Summ summary `json:"summ"`
		} `json:"rootEntry"`
		IncompleteReason string `json:"incomplete"`
	} `json:"lastSnapshot"`
	NextSnapshotTime string `json:"nextSnapshotTime"`
	CurrentTask      string `json:"currentTask"`
	Upload           *struct {
		HashedBytes   int64 `json:"hashedBytes"`
		HashedFiles   int64 `json:"hashedFiles"`
		UploadedBytes int64 `json:"uploadedBytes"`
		EstimatedB    int64 `json:"estimatedBytes"`
	} `json:"upload"`
}

func (c *conn) sources(ctx context.Context) ([]sourceInfo, error) {
	var res struct {
		Sources []sourceInfo `json:"sources"`
	}
	err := c.do(ctx, http.MethodGet, "/sources", nil, nil, &res)
	return res.Sources, err
}

type repoStatus struct {
	Connected   bool   `json:"connected"`
	Storage     string `json:"storage"`
	Description string `json:"description"`
	Format      int    `json:"formatVersion"`
	Hash        string `json:"hash"`
	Encryption  string `json:"encryption"`
	ECC         string `json:"ecc"`
	Splitter    string `json:"splitter"`
	ReadOnly    bool   `json:"readonly"`
	Username    string `json:"username"`
	Hostname    string `json:"hostname"`
	// configFile and apiServerURL aren't decoded: a path on the server
	// and an address with its own credentials.
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var st repoStatus
	if err := c.do(ctx, http.MethodGet, "/repo/status", nil, nil, &st); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Kopia server API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if !st.Connected {
		return sdk.Health{Status: "degraded", Message: "the server isn't connected to a repository"}
	}
	ss, err := c.sources(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var failed []string
	for _, s := range ss {
		if s.Status == "FAILED" || (s.LastSnapshot != nil && s.LastSnapshot.Stats.ErrorCount > 0) {
			failed = append(failed, s.Source.Path)
		}
	}
	if len(failed) > 0 {
		sort.Strings(failed)
		return sdk.Health{Status: "degraded", Message: "last snapshot failed or had errors: " + strings.Join(failed, ", ")}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d sources · %s repository", len(ss), st.Storage)}
}

type input struct {
	source
	Limit *int `json:"limit"`
}

// check validates a source given in an input; all three parts or none.
func (s source) check() (bool, error) {
	if s.UserName == "" && s.Host == "" && s.Path == "" {
		return false, nil
	}
	if !srcRe.MatchString(s.UserName) || !srcRe.MatchString(s.Host) {
		return false, errors.New("a source is its userName, host and path, as sources lists them")
	}
	if len(s.Path) > 4096 || strings.ContainsAny(s.Path, "\r\n\x00") || !(strings.HasPrefix(s.Path, "/") || filepath.IsAbs(s.Path) || (len(s.Path) > 2 && s.Path[1] == ':')) {
		return false, errors.New("the source's path is absolute, as sources lists it")
	}
	return true, nil
}

func (s source) query() url.Values {
	return url.Values{"userName": {s.UserName}, "host": {s.Host}, "path": {s.Path}}
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
		var st repoStatus
		if err := c.do(ctx, http.MethodGet, "/repo/status", nil, nil, &st); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(st)
	case "sources":
		ss, err := c.sources(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range ss {
			out = append(out, sourceRow(s))
		}
		return sdk.JSON(out)
	case "snapshots":
		return c.snapshots(ctx, p)
	case "policies":
		return c.policies(ctx)
	case "maintenance":
		return c.maintenance(ctx)
	case "start_snapshot":
		ok, err := p.source.check()
		if err != nil {
			return sdk.Result{}, err
		}
		if !ok {
			// Without a source, Kopia would snapshot every source.
			return sdk.Result{}, errors.New("name the source: its userName, host and path, as sources lists them")
		}
		ss, err := c.sources(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		known := false
		for _, s := range ss {
			known = known || s.Source == p.source
		}
		if !known {
			return sdk.Result{}, fmt.Errorf("%s isn't one of the server's sources", p.source)
		}
		var res struct {
			Sources map[string]struct {
				Success bool   `json:"success"`
				Error   string `json:"error"`
			} `json:"sources"`
		}
		if err := c.do(ctx, http.MethodPost, "/sources/upload", p.source.query(), map[string]any{}, &res); err != nil {
			return sdk.Result{}, err
		}
		for _, r := range res.Sources {
			if !r.Success {
				msg := "Kopia didn't start the snapshot"
				if r.Error != "" {
					msg += ": " + rest.Redact(r.Error)
				}
				return sdk.Result{}, errors.New(msg)
			}
		}
		return sdk.JSON(map[string]any{"started": p.source.String()})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func sourceRow(s sourceInfo) map[string]any {
	row := map[string]any{"userName": s.Source.UserName, "host": s.Source.Host, "path": s.Source.Path, "status": strings.ToLower(s.Status)}
	if s.NextSnapshotTime != "" {
		row["nextSnapshot"] = s.NextSnapshotTime
	}
	if l := s.LastSnapshot; l != nil {
		last := map[string]any{"start": l.StartTime, "end": l.EndTime, "bytes": l.Stats.TotalSize, "files": l.Stats.FileCount, "errors": l.Stats.ErrorCount}
		if l.RootEntry != nil {
			last["bytes"], last["files"], last["dirs"] = l.RootEntry.Summ.Size, l.RootEntry.Summ.Files, l.RootEntry.Summ.Dirs
			if l.RootEntry.Summ.Errors > last["errors"].(int) {
				last["errors"] = l.RootEntry.Summ.Errors
			}
		}
		if l.IncompleteReason != "" {
			last["incomplete"] = l.IncompleteReason
		}
		row["lastSnapshot"] = last
	}
	if u := s.Upload; u != nil && s.Status == "UPLOADING" {
		row["upload"] = map[string]any{"hashedBytes": u.HashedBytes, "hashedFiles": u.HashedFiles, "uploadedBytes": u.UploadedBytes, "estimatedBytes": u.EstimatedB}
	}
	return row
}

func (c *conn) snapshots(ctx context.Context, p input) (sdk.Result, error) {
	limit := 20
	if p.Limit != nil {
		limit = *p.Limit
	}
	if limit < 1 || limit > 500 {
		return sdk.Result{}, errors.New("limit is 1 to 500")
	}
	one, err := p.source.check()
	if err != nil {
		return sdk.Result{}, err
	}
	var srcs []source
	if one {
		srcs = []source{p.source}
	} else {
		ss, err := c.sources(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		for _, s := range ss {
			srcs = append(srcs, s.Source)
		}
	}
	out := []map[string]any{}
	for _, s := range srcs {
		var res struct {
			Snapshots []struct {
				ID          string   `json:"id"`
				Description string   `json:"description"`
				StartTime   string   `json:"startTime"`
				EndTime     string   `json:"endTime"`
				Incomplete  string   `json:"incomplete"`
				Summary     summary  `json:"summary"`
				Retention   []string `json:"retention"`
				Pins        []string `json:"pins"`
			} `json:"snapshots"`
		}
		if err := c.do(ctx, http.MethodGet, "/snapshots", s.query(), nil, &res); err != nil {
			return sdk.Result{}, err
		}
		sn := res.Snapshots
		sort.Slice(sn, func(i, j int) bool { return sn[i].StartTime > sn[j].StartTime })
		if len(sn) > limit {
			sn = sn[:limit]
		}
		list := []map[string]any{}
		for _, x := range sn {
			row := map[string]any{"id": x.ID, "start": x.StartTime, "end": x.EndTime, "bytes": x.Summary.Size, "files": x.Summary.Files, "dirs": x.Summary.Dirs,
				"errors": x.Summary.Errors, "retention": nonNil(x.Retention)}
			if x.Description != "" {
				row["description"] = x.Description
			}
			if len(x.Pins) > 0 {
				row["pins"] = x.Pins
			}
			if x.Incomplete != "" {
				row["incomplete"] = x.Incomplete
			}
			list = append(list, row)
		}
		out = append(out, map[string]any{"source": s.String(), "snapshots": list})
	}
	return sdk.JSON(out)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (c *conn) policies(ctx context.Context) (sdk.Result, error) {
	var res struct {
		Policies []struct {
			Target source                     `json:"target"`
			Policy map[string]json.RawMessage `json:"policy"`
		} `json:"policies"`
	}
	if err := c.do(ctx, http.MethodGet, "/policies", nil, nil, &res); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, p := range res.Policies {
		t := p.Target
		target := "global"
		switch {
		case t.Path != "":
			target = t.String()
		case t.UserName != "":
			target = t.UserName + "@" + t.Host
		case t.Host != "":
			target = "@" + t.Host
		}
		row := map[string]any{"target": target}
		// actions (commands run before and after snapshots) and
		// notification settings stay out: they can hold credentials.
		for _, k := range []string{"retention", "scheduling", "compression", "files", "errorHandling", "upload", "splitter", "logging"} {
			if v, ok := p.Policy[k]; ok && len(v) > 0 && string(v) != "{}" {
				row[k] = v
			}
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

func (c *conn) maintenance(ctx context.Context) (sdk.Result, error) {
	var res struct {
		Tasks []struct {
			ID           string `json:"id"`
			Kind         string `json:"kind"`
			Description  string `json:"description"`
			Status       string `json:"status"`
			StartTime    string `json:"startTime"`
			EndTime      string `json:"endTime"`
			ErrorMessage string `json:"errorMessage"`
		} `json:"tasks"`
	}
	if err := c.do(ctx, http.MethodGet, "/tasks", nil, nil, &res); err != nil {
		return sdk.Result{}, err
	}
	runs := []map[string]any{}
	for _, t := range res.Tasks {
		if !strings.Contains(strings.ToLower(t.Kind), "maintenance") {
			continue
		}
		row := map[string]any{"id": t.ID, "description": t.Description, "status": strings.ToLower(t.Status), "start": t.StartTime}
		if t.EndTime != "" {
			row["end"] = t.EndTime
			if a, err1 := time.Parse(time.RFC3339Nano, t.StartTime); err1 == nil {
				if b, err2 := time.Parse(time.RFC3339Nano, t.EndTime); err2 == nil {
					row["seconds"] = int(b.Sub(a).Seconds())
				}
			}
		}
		if t.ErrorMessage != "" {
			row["error"] = rest.Redact(t.ErrorMessage)
		}
		runs = append(runs, row)
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i]["start"].(string) > runs[j]["start"].(string) })
	if len(runs) > 20 {
		runs = runs[:20]
	}
	out := map[string]any{"runs": runs}
	if len(runs) == 0 {
		out["note"] = "no maintenance has run since the server started (it runs only on the repository's maintenance owner)"
	} else {
		out["lastStatus"] = runs[0]["status"]
	}
	return sdk.JSON(out)
}
