// Package restic works with a restic repository by running the restic
// program installed on this computer: snapshots, repository stats,
// integrity checks, and forgetting and pruning old snapshots after a
// preview of what would go.
//
// The repository and its password reach restic through its environment
// (RESTIC_REPOSITORY, RESTIC_PASSWORD), never its arguments, which other
// users of the machine can read in the process list. restic is run
// directly with explicit arguments, never through a shell.
package restic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one restic repository.
type Config struct {
	Repository string            `json:"repository"` // e.g. /srv/backup, sftp:host:/repo, s3:s3.amazonaws.com/bucket, rest:https://host/
	Password   string            `json:"password"`   // secret:// repository password
	Env        map[string]string `json:"env"`        // backend credentials, e.g. AWS_SECRET_ACCESS_KEY: secret://…
	Binary     string            `json:"binary"`     // absolute path; default restic from PATH
	// TimeoutMinutes bounds check, forget and prune (default 120).
	TimeoutMinutes int `json:"timeoutMinutes"`
	// WarnAfterHours makes health degraded when the newest snapshot is
	// older (0, the default, turns it off).
	WarnAfterHours int `json:"warnAfterHours"`
}

type conn struct {
	cfg  Config
	host sdk.Host
	// busy is held by the commands that take restic's exclusive lock or
	// run long (check, forget, prune), so two don't queue up.
	busy sync.Mutex
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	now func() time.Time
}

// New returns the restic module.
func New() *Module { return &Module{now: time.Now} }

// Limits on a run. Variables so tests can shorten them.
var (
	readTimeout  = 5 * time.Minute  // snapshots, version, cat config
	statsTimeout = 30 * time.Minute // stats walks the snapshots
	maxStdout    = 32 << 20         // JSON from snapshots or forget
	maxStderr    = 64 << 10
	// waitDelay is how long restic gets to release its lock after an
	// interrupt before it's killed.
	waitDelay = 30 * time.Second
)

var (
	hostRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)
	tagRe     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._:=@+-]{0,99}$`)
	snapRe    = regexp.MustCompile(`^[0-9a-f]{8,64}$`)
	withinRe  = regexp.MustCompile(`^([0-9]{1,4}y)?([0-9]{1,4}m)?([0-9]{1,5}d)?([0-9]{1,6}h)?$`)
	percentRe = regexp.MustCompile(`^(10|[1-9])(\.[0-9])?%$|^0\.[1-9]%$`)
	partRe    = regexp.MustCompile(`^([1-9][0-9]{0,3})/([1-9][0-9]{0,3})$`)
	envNameRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)
	secretish = regexp.MustCompile(`KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|PASS$`)
)

// envPrefixes are the backend settings an instance may pass to restic.
// Anything else (LD_PRELOAD, PATH, RESTIC_PASSWORD_COMMAND) is refused: it
// would change what runs or where the password comes from.
var envPrefixes = []string{"AWS_", "B2_", "AZURE_", "GOOGLE_", "OS_", "ST_", "RCLONE_"}

var envExact = map[string]bool{"RESTIC_REST_USERNAME": true, "RESTIC_REST_PASSWORD": true, "RESTIC_COMPRESSION": true, "RESTIC_PACK_SIZE": true, "RESTIC_HOST": true}

// passEnv is what restic gets from Conduit's own environment: enough to
// find its cache and temporary space.
var passEnv = []string{"PATH", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TMPDIR", "TEMP", "TMP", "XDG_CACHE_HOME", "SystemRoot", "LANG"}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	filter := `"host":{"type":"string","description":"Only snapshots of this host"},"tag":{"type":"string","description":"Only snapshots with this tag"},"path":{"type":"string","description":"Only snapshots of this path"}`
	keep := `"keepLast":{"type":"integer","minimum":1},"keepHourly":{"type":"integer","minimum":1},"keepDaily":{"type":"integer","minimum":1},"keepWeekly":{"type":"integer","minimum":1},
		"keepMonthly":{"type":"integer","minimum":1},"keepYearly":{"type":"integer","minimum":1},"keepWithin":{"type":"string","description":"Keep everything this recent, e.g. 30d or 1y6m"},
		"keepTags":{"type":"array","items":{"type":"string"},"description":"Keep snapshots with any of these tags"}`
	return sdk.Manifest{
		ID: "restic", Name: "restic", Version: "0.1.0", Category: "Storage", Icon: "archive",
		Description: "A restic repository, through the restic program on this computer: snapshots, size, integrity checks, and forgetting and pruning old snapshots.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["repository","password"],"properties":{
			"repository":{"type":"string","description":"The repository, as restic -r takes it: /srv/backup, sftp:user@host:/srv/restic, s3:s3.amazonaws.com/bucket, b2:bucket:path, rest:https://host:8000/"},
			"password":{"type":"string","x-secret":true,"description":"The repository's password"},
			"env":{"type":"object","additionalProperties":{"type":"string"},"description":"Backend settings such as AWS_ACCESS_KEY_ID, B2_ACCOUNT_KEY, AZURE_ACCOUNT_KEY, RESTIC_REST_PASSWORD. Credentials must be secret:// references"},
			"binary":{"type":"string","description":"Full path to restic; empty to find it on PATH"},
			"timeoutMinutes":{"type":"integer","default":120,"minimum":1,"maximum":1440,"description":"How long check, forget and prune may run"},
			"warnAfterHours":{"type":"integer","default":0,"minimum":0,"description":"Health warns when the newest snapshot is older than this (0: never)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "snapshots", Title: "Snapshots", Description: "Snapshots, newest first: id, time, host, paths, tags and what each backup added.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + filter + `,"limit":{"type":"integer","default":50,"minimum":1,"maximum":1000}}}`)},
			{Name: "stats", Title: "Repository size", Description: "Size of the repository as stored (raw-data, the default) or restored (restore-size), file and snapshot counts and compression. Can take a while on a large repository.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"mode":{"type":"string","enum":["raw-data","restore-size"],"default":"raw-data"},"snapshot":{"type":"string","description":"One snapshot id, or latest; all when empty"}}}`)},
			{Name: "check", Title: "Check integrity", Description: "Checks the repository's structure, and with readData also reads back a small share of the data (at most 10%). Takes the repository's lock and can run for a long time.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","properties":{"readData":{"type":"string","description":"Read back this share of the data: a percentage up to 10% (2.5%) or a part n/t (1/20)"}}}`)},
			{Name: "forget", Title: "Forget snapshots", Description: "Removes snapshots by a keep policy, or by id. The preview lists every snapshot that would go. The data stays until prune.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + keep + `,` + filter + `,"ids":{"type":"array","items":{"type":"string"},"description":"Or exactly these snapshots"}}}`)},
			{Name: "prune", Title: "Prune unused data", Description: "Deletes data no snapshot uses any more, after forget. The preview shows how much would be deleted and repacked.", Risk: sdk.RiskDestructive, DryRun: true},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	c.Repository = strings.TrimSpace(c.Repository)
	if c.Repository == "" || len(c.Repository) > 2048 || strings.ContainsAny(c.Repository, "\r\n\x00") {
		return errors.New("enter the repository, as restic -r takes it")
	}
	if userPassword(c.Repository) {
		return errors.New("keep the password out of the repository address: put it in env as RESTIC_REST_PASSWORD (or the backend's own setting) with a secret:// reference")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the repository password in the vault and enter its secret:// reference")
	}
	for k, v := range c.Env {
		if !envNameRe.MatchString(k) || !allowedEnv(k) {
			return fmt.Errorf("%s isn't a backend setting restic is given (allowed: %s…, RESTIC_REST_USERNAME, RESTIC_REST_PASSWORD, RESTIC_COMPRESSION, RESTIC_PACK_SIZE, RESTIC_HOST)", k, strings.Join(envPrefixes, "…, "))
		}
		if strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("%s is one line", k)
		}
		if secretish.MatchString(k) && !strings.HasPrefix(v, "secret://") {
			return fmt.Errorf("%s holds a credential: store it in the vault and enter its secret:// reference", k)
		}
	}
	if c.Binary != "" && !filepath.IsAbs(c.Binary) {
		return errors.New("the restic binary is a full path, like /usr/bin/restic")
	}
	if c.TimeoutMinutes == 0 {
		c.TimeoutMinutes = 120
	}
	if c.TimeoutMinutes < 1 || c.TimeoutMinutes > 1440 {
		return errors.New("timeoutMinutes is 1 to 1440")
	}
	if c.WarnAfterHours < 0 {
		return errors.New("warnAfterHours is 0 or more")
	}
	m.set.Put(id, &conn{cfg: c, host: h})
	return nil
}

// userPassword reports whether a repository address carries user:password@.
func userPassword(repo string) bool {
	i := strings.Index(repo, "://")
	if i < 0 {
		return false
	}
	rest := repo[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	at := strings.LastIndex(rest, "@")
	return at >= 0 && strings.Contains(rest[:at], ":")
}

func allowedEnv(k string) bool {
	if envExact[k] {
		return true
	}
	for _, p := range envPrefixes {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) binary() (string, error) {
	if c.cfg.Binary != "" {
		if st, err := os.Stat(c.cfg.Binary); err != nil || st.IsDir() {
			return "", fmt.Errorf("restic isn't installed at %s", c.cfg.Binary)
		}
		return c.cfg.Binary, nil
	}
	p, err := exec.LookPath("restic")
	if err != nil {
		return "", errors.New("restic isn't installed on this computer (or not on PATH); install it or set its full path")
	}
	return p, nil
}

// env builds restic's environment from scratch.
func (c *conn) env(ctx context.Context) ([]string, error) {
	var env []string
	for _, k := range passEnv {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	pw, err := c.host.Secret(ctx, c.cfg.Password)
	if err != nil {
		return nil, err
	}
	env = append(env, "RESTIC_REPOSITORY="+c.cfg.Repository, "RESTIC_PASSWORD="+strings.TrimRight(pw, "\r\n"))
	keys := make([]string, 0, len(c.cfg.Env))
	for k := range c.cfg.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := c.cfg.Env[k]
		if strings.HasPrefix(v, "secret://") {
			s, err := c.host.Secret(ctx, v)
			if err != nil {
				return nil, err
			}
			v = strings.TrimRight(s, "\r\n")
		}
		env = append(env, k+"="+v)
	}
	return env, nil
}

// capped keeps the first n bytes written to it and notes whether more came.
type capped struct {
	buf  bytes.Buffer
	n    int
	over bool
}

func (w *capped) Write(p []byte) (int, error) {
	if room := w.n - w.buf.Len(); room > 0 {
		if len(p) > room {
			w.buf.Write(p[:room])
			w.over = true
		} else {
			w.buf.Write(p)
		}
	} else if len(p) > 0 {
		w.over = true
	}
	return len(p), nil
}

// run runs restic with args and returns its standard output.
func (c *conn) run(ctx context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	bin, err := c.binary()
	if err != nil {
		return nil, err
	}
	env, err := c.env(ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	cmd.Stdin = nil
	if runtime.GOOS != "windows" {
		// An interrupt lets restic remove its lock before it exits.
		cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	}
	cmd.WaitDelay = waitDelay
	out, errb := &capped{n: maxStdout}, &capped{n: maxStderr}
	cmd.Stdout, cmd.Stderr = out, errb
	err = cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("restic %s didn't finish within %s", args[0], timeout)
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return out.buf.Bytes(), &runError{code: ee.ExitCode(), err: exitError(args[0], ee.ExitCode(), errb.buf.String()), stderr: errb.buf.String()}
		}
		return nil, fmt.Errorf("couldn't run restic: %v", err)
	}
	if out.over {
		return nil, fmt.Errorf("restic %s printed more than %d MB; narrow it down", args[0], maxStdout>>20)
	}
	return out.buf.Bytes(), nil
}

// runError is restic exiting with an error.
type runError struct {
	code   int
	err    error
	stderr string
}

func (e *runError) Error() string { return e.err.Error() }

// exitError explains restic's exit codes, with the end of what it printed
// (redacted: backends quote their URLs and settings).
func exitError(cmd string, code int, stderr string) error {
	low := strings.ToLower(stderr)
	switch {
	case code == 12 || strings.Contains(low, "wrong password"):
		return errors.New("restic refused the repository password")
	case code == 10 || strings.Contains(low, "repository does not exist") || strings.Contains(low, "unable to open config file"):
		return errors.New("there's no restic repository at this address (or the backend credentials are wrong)")
	case code == 11 || strings.Contains(low, "unable to create lock") || strings.Contains(low, "repository is already locked"):
		return errors.New("the repository is locked by another restic process; if that's stale, run restic unlock")
	}
	msg := lastLines(stderr, 3)
	if msg == "" {
		return fmt.Errorf("restic %s failed (exit %d)", cmd, code)
	}
	return fmt.Errorf("restic %s failed (exit %d): %s", cmd, code, msg)
}

// lastLines returns the last n non-empty lines of s, redacted and cut to
// a sensible length.
func lastLines(s string, n int) string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := rest.Redact(strings.Join(lines, "; "))
	if len(out) > 600 {
		out = out[:600] + "…"
	}
	return out
}

type snapshot struct {
	ID       string    `json:"id"`
	ShortID  string    `json:"short_id"`
	Time     time.Time `json:"time"`
	Hostname string    `json:"hostname"`
	Username string    `json:"username"`
	Paths    []string  `json:"paths"`
	Tags     []string  `json:"tags"`
	Program  string    `json:"program_version"`
	Summary  *struct {
		FilesNew      int   `json:"files_new"`
		FilesChanged  int   `json:"files_changed"`
		DataAdded     int64 `json:"data_added"`
		DataAddedPack int64 `json:"data_added_packed"`
		TotalFiles    int   `json:"total_files_processed"`
		TotalBytes    int64 `json:"total_bytes_processed"`
	} `json:"summary"`
	// Excludes aren't decoded: they can name private paths.
}

func (s snapshot) short() string {
	if s.ShortID != "" {
		return s.ShortID
	}
	if len(s.ID) > 8 {
		return s.ID[:8]
	}
	return s.ID
}

func (s snapshot) row() map[string]any {
	r := map[string]any{"id": s.short(), "time": s.Time.UTC().Format(time.RFC3339), "host": s.Hostname, "user": s.Username, "paths": nonNil(s.Paths), "tags": nonNil(s.Tags)}
	if s.Summary != nil {
		r["filesNew"], r["filesChanged"], r["bytesAdded"], r["files"], r["bytes"] = s.Summary.FilesNew, s.Summary.FilesChanged, s.Summary.DataAdded, s.Summary.TotalFiles, s.Summary.TotalBytes
	}
	return r
}

func (s snapshot) label() string {
	return fmt.Sprintf("snapshot %s (%s:%s, %s)", s.short(), s.Hostname, strings.Join(s.Paths, ","), s.Time.UTC().Format("2006-01-02 15:04"))
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type filter struct {
	Host string `json:"host"`
	Tag  string `json:"tag"`
	Path string `json:"path"`
}

func (f filter) args() ([]string, error) {
	var a []string
	if f.Host != "" {
		if !hostRe.MatchString(f.Host) {
			return nil, errors.New("host is a host name")
		}
		a = append(a, "--host="+f.Host)
	}
	if f.Tag != "" {
		if !tagRe.MatchString(f.Tag) {
			return nil, errors.New("tag is letters, digits and . _ : = @ + -")
		}
		a = append(a, "--tag="+f.Tag)
	}
	if f.Path != "" {
		if err := checkPath(f.Path); err != nil {
			return nil, err
		}
		a = append(a, "--path="+f.Path)
	}
	return a, nil
}

func checkPath(p string) error {
	if len(p) > 1024 || strings.ContainsAny(p, "\r\n\x00") || !(strings.HasPrefix(p, "/") || filepath.IsAbs(p)) {
		return errors.New("path is an absolute path, as the snapshots list it")
	}
	return nil
}

func (c *conn) snapshots(ctx context.Context, f filter) ([]snapshot, error) {
	fa, err := f.args()
	if err != nil {
		return nil, err
	}
	out, err := c.run(ctx, readTimeout, append([]string{"snapshots", "--json", "--no-lock"}, fa...)...)
	if err != nil {
		return nil, err
	}
	var ss []snapshot
	if err := json.Unmarshal(bytes.TrimSpace(out), &ss); err != nil {
		return nil, errors.New("restic printed something other than the snapshot list")
	}
	sort.Slice(ss, func(i, j int) bool { return ss[i].Time.After(ss[j].Time) })
	return ss, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ss, err := c.snapshots(ctx, filter{})
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if len(ss) == 0 {
		if c.cfg.WarnAfterHours > 0 {
			return sdk.Health{Status: "degraded", Message: "no snapshots yet"}
		}
		return sdk.Health{Status: "ok", Message: "no snapshots yet"}
	}
	newest := ss[0]
	age := m.now().Sub(newest.Time)
	msg := fmt.Sprintf("%d snapshots, newest %s (%s)", len(ss), newest.Time.UTC().Format("2006-01-02 15:04"), newest.Hostname)
	if c.cfg.WarnAfterHours > 0 && age > time.Duration(c.cfg.WarnAfterHours)*time.Hour {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("newest snapshot is %.0f hours old; ", age.Hours()) + msg}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	filter
	Limit       *int     `json:"limit"`
	Mode        string   `json:"mode"`
	Snapshot    string   `json:"snapshot"`
	ReadData    string   `json:"readData"`
	KeepLast    int      `json:"keepLast"`
	KeepHourly  int      `json:"keepHourly"`
	KeepDaily   int      `json:"keepDaily"`
	KeepWeekly  int      `json:"keepWeekly"`
	KeepMonthly int      `json:"keepMonthly"`
	KeepYearly  int      `json:"keepYearly"`
	KeepWithin  string   `json:"keepWithin"`
	KeepTags    []string `json:"keepTags"`
	IDs         []string `json:"ids"`
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
	long := time.Duration(c.cfg.TimeoutMinutes) * time.Minute
	switch call.Action {
	case "snapshots":
		limit := 50
		if p.Limit != nil {
			limit = *p.Limit
		}
		if limit < 1 || limit > 1000 {
			return sdk.Result{}, errors.New("limit is 1 to 1000")
		}
		ss, err := c.snapshots(ctx, p.filter)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for i, s := range ss {
			if i == limit {
				break
			}
			out = append(out, s.row())
		}
		return sdk.JSON(map[string]any{"total": len(ss), "snapshots": out})

	case "stats":
		mode := p.Mode
		if mode == "" {
			mode = "raw-data"
		}
		if mode != "raw-data" && mode != "restore-size" {
			return sdk.Result{}, errors.New("mode is raw-data or restore-size")
		}
		args := []string{"stats", "--json", "--no-lock", "--mode=" + mode}
		if p.Snapshot != "" {
			if p.Snapshot != "latest" && !snapRe.MatchString(p.Snapshot) {
				return sdk.Result{}, errors.New("snapshot is an id from snapshots, or latest")
			}
			args = append(args, p.Snapshot)
		}
		out, err := c.run(ctx, statsTimeout, args...)
		if err != nil {
			return sdk.Result{}, err
		}
		var st map[string]any
		if err := json.Unmarshal(lastJSON(out), &st); err != nil {
			return sdk.Result{}, errors.New("restic printed something other than stats")
		}
		res := map[string]any{"mode": mode}
		for k, name := range map[string]string{"total_size": "bytes", "total_uncompressed_size": "uncompressedBytes", "total_file_count": "files",
			"total_blob_count": "blobs", "snapshots_count": "snapshots", "compression_ratio": "compressionRatio", "compression_space_saving": "compressionSavingPercent"} {
			if v, ok := st[k]; ok {
				res[name] = v
			}
		}
		return sdk.JSON(res)

	case "check":
		args := []string{"check"}
		if d := strings.TrimSpace(p.ReadData); d != "" {
			if err := checkSubset(d); err != nil {
				return sdk.Result{}, err
			}
			args = append(args, "--read-data-subset="+d)
		}
		if !c.busy.TryLock() {
			return sdk.Result{}, errors.New("another check, forget or prune from Conduit is running on this repository")
		}
		defer c.busy.Unlock()
		out, err := c.run(ctx, long, args...)
		var re *runError
		if errors.As(err, &re) && re.code == 1 {
			// Exit 1 after a completed check: the repository has errors.
			return sdk.JSON(map[string]any{"ok": false, "readData": p.ReadData, "summary": lastLines(string(out)+"\n"+re.stderr, 8)})
		}
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"ok": true, "readData": p.ReadData, "summary": lastLines(string(out), 3)})

	case "forget":
		return c.forget(ctx, call, p, long)

	case "prune":
		if !c.busy.TryLock() {
			return sdk.Result{}, errors.New("another check, forget or prune from Conduit is running on this repository")
		}
		defer c.busy.Unlock()
		args := []string{"prune"}
		if call.DryRun {
			args = append(args, "--dry-run")
		}
		out, err := c.run(ctx, long, args...)
		if err != nil {
			return sdk.Result{}, err
		}
		sum := pruneSummary(string(out))
		if call.DryRun {
			plan := &sdk.Plan{Summary: "Prune unused data from the repository"}
			if d, ok := sum["to delete"]; ok {
				plan.Summary += ": delete " + d
			}
			for _, k := range []string{"to delete", "to repack", "this removes", "total prune", "remaining", "unused size after prune"} {
				if v, ok := sum[k]; ok {
					a, _ := json.Marshal(v)
					op := "delete"
					switch k {
					case "to repack":
						op = "repack"
					case "remaining", "unused size after prune":
						op = "keep"
					}
					plan.Changes = append(plan.Changes, sdk.Change{Target: k, Op: op, After: a})
				}
			}
			if len(plan.Changes) == 0 {
				a, _ := json.Marshal(lastLines(string(out), 6))
				plan.Changes = []sdk.Change{{Target: "unused data", Op: "delete", After: a}}
			}
			return sdk.Result{Plan: plan}, nil
		}
		return sdk.JSON(map[string]any{"pruned": true, "summary": sum})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// checkSubset allows a small share of the data: up to 10%, or n/t with
// n/t ≤ 1/10.
func checkSubset(d string) error {
	if percentRe.MatchString(d) {
		return nil
	}
	if m := partRe.FindStringSubmatch(d); m != nil {
		n, _ := strconv.Atoi(m[1])
		t, _ := strconv.Atoi(m[2])
		if n <= t && n*10 <= t {
			return nil
		}
	}
	return errors.New("readData is a percentage up to 10% (like 2.5%) or a part n/t of at most a tenth (like 1/20)")
}

// lastJSON returns the last line that looks like a JSON object: restic can
// print status lines before it.
func lastJSON(out []byte) []byte {
	lines := bytes.Split(bytes.TrimSpace(out), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		if l := bytes.TrimSpace(lines[i]); bytes.HasPrefix(l, []byte("{")) {
			return l
		}
	}
	return out
}

var pruneLine = regexp.MustCompile(`^(to repack|this removes|to delete|total prune|remaining|unused size after prune|to keep|unused packs|repack|keep):\s+(.+)$`)

func pruneSummary(out string) map[string]string {
	sum := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if mm := pruneLine.FindStringSubmatch(strings.TrimSpace(l)); mm != nil {
			sum[mm[1]] = strings.Join(strings.Fields(mm[2]), " ")
		}
	}
	return sum
}

type forgetGroup struct {
	Host   string     `json:"host"`
	Paths  []string   `json:"paths"`
	Tags   []string   `json:"tags"`
	Keep   []snapshot `json:"keep"`
	Remove []snapshot `json:"remove"`
}

func (c *conn) forget(ctx context.Context, call sdk.Call, p input, timeout time.Duration) (sdk.Result, error) {
	var policy []string
	for _, k := range []struct {
		flag string
		n    int
	}{{"last", p.KeepLast}, {"hourly", p.KeepHourly}, {"daily", p.KeepDaily}, {"weekly", p.KeepWeekly}, {"monthly", p.KeepMonthly}, {"yearly", p.KeepYearly}} {
		if k.n < 0 || k.n > 100000 {
			return sdk.Result{}, fmt.Errorf("keep%s is 1 to 100000", strings.ToUpper(k.flag[:1])+k.flag[1:])
		}
		if k.n > 0 {
			policy = append(policy, "--keep-"+k.flag+"="+strconv.Itoa(k.n))
		}
	}
	if w := strings.TrimSpace(p.KeepWithin); w != "" {
		if !withinRe.MatchString(w) {
			return sdk.Result{}, errors.New("keepWithin is a duration like 30d, 6m or 1y6m")
		}
		policy = append(policy, "--keep-within="+w)
	}
	for _, t := range p.KeepTags {
		if !tagRe.MatchString(t) {
			return sdk.Result{}, errors.New("keepTags are tags: letters, digits and . _ : = @ + -")
		}
		policy = append(policy, "--keep-tag="+t)
	}
	fa, err := p.filter.args()
	if err != nil {
		return sdk.Result{}, err
	}
	for _, id := range p.IDs {
		if !snapRe.MatchString(id) {
			return sdk.Result{}, errors.New("ids are snapshot ids from snapshots")
		}
	}
	switch {
	case len(p.IDs) > 0 && (len(policy) > 0 || len(fa) > 0):
		return sdk.Result{}, errors.New("give either snapshot ids or a keep policy, not both")
	case len(p.IDs) == 0 && len(policy) == 0:
		return sdk.Result{}, errors.New("say what to keep (keepLast, keepDaily, keepWithin, …) or which snapshots to forget (ids)")
	case len(p.IDs) > 100:
		return sdk.Result{}, errors.New("at most 100 snapshots at a time")
	}
	if !c.busy.TryLock() {
		return sdk.Result{}, errors.New("another check, forget or prune from Conduit is running on this repository")
	}
	defer c.busy.Unlock()

	if len(p.IDs) > 0 {
		return c.forgetIDs(ctx, call, p.IDs, timeout)
	}
	args := append(append([]string{"forget", "--json"}, policy...), fa...)
	if call.DryRun {
		args = append(args, "--dry-run")
	}
	out, err := c.run(ctx, timeout, args...)
	if err != nil {
		return sdk.Result{}, err
	}
	var groups []forgetGroup
	if err := json.Unmarshal(lastJSONArray(out), &groups); err != nil {
		return sdk.Result{}, errors.New("restic printed something other than the forget plan")
	}
	var remove []snapshot
	kept := 0
	for _, g := range groups {
		remove = append(remove, g.Remove...)
		kept += len(g.Keep)
	}
	if call.DryRun {
		plan := &sdk.Plan{Summary: fmt.Sprintf("Forget %d snapshots, keeping %d", len(remove), kept)}
		for _, s := range remove {
			b, _ := json.Marshal(s.row())
			plan.Changes = append(plan.Changes, sdk.Change{Target: s.label(), Op: "delete", Before: b})
		}
		return sdk.Result{Plan: plan}, nil
	}
	ids := []string{}
	for _, s := range remove {
		ids = append(ids, s.short())
	}
	res := map[string]any{"forgotten": ids, "kept": kept, "note": "run prune to free the space"}
	if len(ids) == 0 {
		res["note"] = "the policy keeps every snapshot"
	}
	return sdk.JSON(res)
}

// lastJSONArray finds the JSON array restic forget prints.
func lastJSONArray(out []byte) []byte {
	lines := bytes.Split(bytes.TrimSpace(out), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		if l := bytes.TrimSpace(lines[i]); bytes.HasPrefix(l, []byte("[")) {
			return l
		}
	}
	return bytes.TrimSpace(out)
}

func (c *conn) forgetIDs(ctx context.Context, call sdk.Call, ids []string, timeout time.Duration) (sdk.Result, error) {
	all, err := c.snapshots(ctx, filter{})
	if err != nil {
		return sdk.Result{}, err
	}
	var hit []snapshot
	for _, id := range ids {
		var found []snapshot
		for _, s := range all {
			if strings.HasPrefix(s.ID, id) {
				found = append(found, s)
			}
		}
		switch len(found) {
		case 0:
			return sdk.Result{}, fmt.Errorf("there's no snapshot %s", id)
		case 1:
			hit = append(hit, found[0])
		default:
			return sdk.Result{}, fmt.Errorf("%s matches several snapshots; give more of its id", id)
		}
	}
	if call.DryRun {
		plan := &sdk.Plan{Summary: fmt.Sprintf("Forget %d of %d snapshots", len(hit), len(all))}
		for _, s := range hit {
			b, _ := json.Marshal(s.row())
			plan.Changes = append(plan.Changes, sdk.Change{Target: s.label(), Op: "delete", Before: b})
		}
		return sdk.Result{Plan: plan}, nil
	}
	args := []string{"forget"}
	for _, s := range hit {
		args = append(args, s.ID)
	}
	if _, err := c.run(ctx, timeout, args...); err != nil {
		return sdk.Result{}, err
	}
	out := []string{}
	for _, s := range hit {
		out = append(out, s.short())
	}
	return sdk.JSON(map[string]any{"forgotten": out, "kept": len(all) - len(hit), "note": "run prune to free the space"})
}
