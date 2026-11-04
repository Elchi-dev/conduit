// Package backblaze works with Backblaze B2 through its native API (v3):
// buckets, file listings and per-bucket usage, hiding files and deleting
// file versions. (B2's S3-compatible API is covered by the s3 module; this
// one sees versions, hide markers and what an application key may do.)
package backblaze

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// DefaultAPI is where accounts are authorized.
const DefaultAPI = "https://api.backblazeb2.com"

// Config is one application key.
type Config struct {
	KeyID string `json:"keyId"`
	Key   string `json:"applicationKey"` // secret://
	API   string `json:"api"`            // default DefaultAPI (tests)
}

type session struct {
	accountID string
	api       *rest.Client
	bucketID  string // set when the key is limited to one bucket
	bucket    string
	caps      []string
}

type conn struct {
	cfg  Config
	host sdk.Host
	http *http.Client

	mu sync.Mutex
	s  *session
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Backblaze B2 module.
func New() *Module { return &Module{} }

var (
	bucketRe = regexp.MustCompile(`^[A-Za-z0-9-]{6,63}$`)
	fileIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{10,200}$`)
	keyIDRe  = regexp.MustCompile(`^[A-Za-z0-9]{12,40}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	bucket := `"bucket":{"type":"string","description":"Bucket name"}`
	file := `"fileName":{"type":"string"},"fileId":{"type":"string","description":"The version's file id (from files with versions)"}`
	return sdk.Manifest{
		ID: "backblaze", Name: "Backblaze B2", Version: "0.1.0", Category: "Storage", Icon: "cloud",
		Description: "Backblaze B2 buckets, files and their versions, and how much each bucket holds.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["keyId","applicationKey"],"properties":{
			"keyId":{"type":"string","description":"The application key's keyID (App Keys in the B2 web console)"},
			"applicationKey":{"type":"string","x-secret":true,"description":"The application key itself (shown once when you create it)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "buckets", Title: "Buckets", Risk: sdk.RiskRead},
			{Name: "files", Title: "Files", Description: "One folder level at a time (or every version with versions on), up to 1000 per page.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["bucket"],"properties":{` + bucket + `,
					"prefix":{"type":"string","description":"Folder or name prefix, e.g. photos/2024/"},
					"recursive":{"type":"boolean","default":false,"description":"List everything under the prefix instead of one level"},
					"versions":{"type":"boolean","default":false,"description":"Every version and hide marker, with file ids"},
					"limit":{"type":"integer","default":200,"maximum":1000},
					"startFileName":{"type":"string","description":"From a previous page's next"},
					"startFileId":{"type":"string","description":"From a previous page's next (versions only)"}}}`)},
			{Name: "usage", Title: "Usage", Description: "Files, versions and bytes per bucket, counted from the listings (up to maxFiles versions per bucket).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + bucket + `,"maxFiles":{"type":"integer","default":100000,"maximum":1000000}}}`)},
			{Name: "hide_file", Title: "Hide a file", Description: "Adds a hide marker so the file disappears from listings and downloads; its versions are kept. Undo removes the marker.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["bucket","fileName"],"properties":{` + bucket + `,"fileName":{"type":"string"}}}`)},
			{Name: "delete_file_version", Title: "Delete a file version", Description: "Removes one version for good (or a hide marker, which unhides the file).", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["fileName","fileId"],"properties":{` + file + `}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "bucket", Title: "Buckets", ListAction: "buckets", ViewHint: "table"}},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	c.KeyID = strings.TrimSpace(c.KeyID)
	if !keyIDRe.MatchString(c.KeyID) {
		return errors.New("the keyID is the short id shown next to the application key")
	}
	if !strings.HasPrefix(c.Key, "secret://") {
		return errors.New("store the application key in the vault and enter its secret:// reference")
	}
	if c.API == "" {
		c.API = DefaultAPI
	}
	if err := rest.ValidBase(c.API); err != nil {
		return err
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 60*time.Second)
	}
	m.set.Put(id, &conn{cfg: c, host: h, http: rest.SameHostOnly(client)})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// authorize gets an account authorization token (valid for 24 hours).
// Callers hold c.mu.
func (c *conn) authorize(ctx context.Context) (*session, error) {
	key, err := c.host.Secret(ctx, c.cfg.Key)
	if err != nil {
		return nil, err
	}
	auth := rest.New(c.cfg.API, func(_ context.Context, r *http.Request) error {
		r.SetBasicAuth(c.cfg.KeyID, strings.TrimSpace(key))
		return nil
	})
	auth.HTTP = c.http
	var r struct {
		AccountID string `json:"accountId"`
		Token     string `json:"authorizationToken"`
		APIInfo   struct {
			Storage struct {
				APIURL     string   `json:"apiUrl"`
				BucketID   string   `json:"bucketId"`
				BucketName string   `json:"bucketName"`
				Caps       []string `json:"capabilities"`
			} `json:"storageApi"`
		} `json:"apiInfo"`
	}
	if _, err := auth.Do(ctx, http.MethodGet, "/b2api/v3/b2_authorize_account", nil, nil, &r); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) {
			return nil, errors.New("Backblaze refused the key id or application key")
		}
		return nil, err
	}
	st := r.APIInfo.Storage
	u, err := url.Parse(st.APIURL)
	base, _ := url.Parse(c.cfg.API)
	// The API host comes from Backblaze; insist on https unless the
	// configured authorization address itself is plain http (tests).
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && base.Scheme == "http")) || r.Token == "" {
		return nil, errors.New("unexpected authorization answer from Backblaze")
	}
	tok := r.Token
	api := rest.New(u.Scheme+"://"+u.Host, func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", tok)
		return nil
	})
	api.HTTP = c.http
	return &session{accountID: r.AccountID, api: api, bucketID: st.BucketID, bucket: st.BucketName, caps: st.Caps}, nil
}

func (c *conn) sess(ctx context.Context, fresh bool) (*session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.s != nil && !fresh {
		return c.s, nil
	}
	s, err := c.authorize(ctx)
	if err != nil {
		return nil, err
	}
	c.s = s
	return s, nil
}

// call posts to one API operation, authorizing again once when the token
// has expired.
func (c *conn) call(ctx context.Context, op string, body, out any) (*session, error) {
	s, err := c.sess(ctx, false)
	if err != nil {
		return nil, err
	}
	_, err = s.api.Do(ctx, http.MethodPost, "/b2api/v3/"+op, nil, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		if s, err = c.sess(ctx, true); err != nil {
			return nil, err
		}
		_, err = s.api.Do(ctx, http.MethodPost, "/b2api/v3/"+op, nil, body, out)
	}
	if rest.IsStatus(err, http.StatusUnauthorized) {
		return s, fmt.Errorf("the application key isn't allowed to do this (%s): %w", op, err)
	}
	return s, err
}

// Bucket is a bucket row.
type Bucket struct {
	Name     string `json:"name"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	FileLock bool   `json:"fileLock,omitempty"`
	Rules    int    `json:"lifecycleRules"`
}

func (c *conn) buckets(ctx context.Context, name string) ([]Bucket, error) {
	s, err := c.sess(ctx, false)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"accountId": s.accountID}
	if s.bucketID != "" {
		body["bucketId"] = s.bucketID
	}
	if name != "" {
		body["bucketName"] = name
	}
	var r struct {
		Buckets []struct {
			ID    string `json:"bucketId"`
			Name  string `json:"bucketName"`
			Type  string `json:"bucketType"`
			Rules []any  `json:"lifecycleRules"`
			Lock  struct {
				Value struct {
					Enabled bool `json:"isFileLockEnabled"`
				} `json:"value"`
			} `json:"fileLockConfiguration"`
		} `json:"buckets"`
	}
	if _, err := c.call(ctx, "b2_list_buckets", body, &r); err != nil {
		return nil, err
	}
	out := []Bucket{}
	for _, b := range r.Buckets {
		out = append(out, Bucket{Name: b.Name, ID: b.ID, Type: b.Type, FileLock: b.Lock.Value.Enabled, Rules: len(b.Rules)})
	}
	return out, nil
}

func (c *conn) bucketID(ctx context.Context, name string) (string, error) {
	if !bucketRe.MatchString(name) {
		return "", errors.New("the bucket is its name: 6 to 63 letters, digits and dashes")
	}
	bs, err := c.buckets(ctx, name)
	if err != nil {
		return "", err
	}
	for _, b := range bs {
		if b.Name == name {
			return b.ID, nil
		}
	}
	return "", fmt.Errorf("no bucket %s (or the key can't see it)", name)
}

func validFileName(s string) error {
	if s == "" || len(s) > 1024 || strings.HasPrefix(s, "/") {
		return errors.New("the file name is the full path in the bucket, like photos/cat.jpg (no leading /)")
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return errors.New("the file name can't contain control characters")
		}
	}
	return nil
}

type file struct {
	FileName  string `json:"fileName"`
	FileID    string `json:"fileId"`
	Action    string `json:"action"`
	Size      int64  `json:"contentLength"`
	Uploaded  int64  `json:"uploadTimestamp"`
	Type      string `json:"contentType"`
	BucketID  string `json:"bucketId"`
	SHA1      string `json:"contentSha1"`
	Retention any    `json:"fileRetention,omitempty"`
}

func (f file) row(versions bool) map[string]any {
	r := map[string]any{"name": f.FileName, "action": f.Action}
	if f.Action == "folder" {
		return r
	}
	r["size"] = f.Size
	if f.Uploaded > 0 {
		r["uploaded"] = time.UnixMilli(f.Uploaded).UTC().Format(time.RFC3339)
	}
	if versions {
		r["fileId"] = f.FileID
	}
	return r
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	s, err := c.sess(ctx, true)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	has := map[string]bool{}
	for _, k := range s.caps {
		has[k] = true
	}
	var missing []string
	for _, k := range []string{"listBuckets", "listFiles"} {
		if !has[k] {
			missing = append(missing, k)
		}
	}
	msg := "account " + s.accountID
	if s.bucket != "" {
		msg = "key for bucket " + s.bucket
	}
	if len(missing) > 0 {
		return sdk.Health{Status: "degraded", Message: msg + "; the key lacks " + strings.Join(missing, ", ")}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Bucket        string `json:"bucket"`
		Prefix        string `json:"prefix"`
		Recursive     bool   `json:"recursive"`
		Versions      bool   `json:"versions"`
		Limit         int    `json:"limit"`
		StartFileName string `json:"startFileName"`
		StartFileID   string `json:"startFileId"`
		MaxFiles      int    `json:"maxFiles"`
		FileName      string `json:"fileName"`
		FileID        string `json:"fileId"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "buckets":
		bs, err := c.buckets(ctx, "")
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(bs)

	case "files":
		bid, err := c.bucketID(ctx, p.Bucket)
		if err != nil {
			return sdk.Result{}, err
		}
		if p.StartFileID != "" && !fileIDRe.MatchString(p.StartFileID) {
			return sdk.Result{}, errors.New("startFileId isn't a file id")
		}
		limit := p.Limit
		if limit <= 0 {
			limit = 200
		}
		if limit > 1000 {
			limit = 1000
		}
		body := map[string]any{"bucketId": bid, "maxFileCount": limit}
		if p.Prefix != "" {
			body["prefix"] = p.Prefix
		}
		if !p.Recursive {
			body["delimiter"] = "/"
		}
		if p.StartFileName != "" {
			body["startFileName"] = p.StartFileName
		}
		op := "b2_list_file_names"
		if p.Versions {
			op = "b2_list_file_versions"
			if p.StartFileID != "" {
				body["startFileId"] = p.StartFileID
			}
		}
		var r struct {
			Files    []file  `json:"files"`
			NextName *string `json:"nextFileName"`
			NextID   *string `json:"nextFileId"`
		}
		if _, err := c.call(ctx, op, body, &r); err != nil {
			return sdk.Result{}, err
		}
		rows := []map[string]any{}
		for _, f := range r.Files {
			rows = append(rows, f.row(p.Versions))
		}
		out := map[string]any{"bucket": p.Bucket, "files": rows}
		if r.NextName != nil {
			next := map[string]string{"startFileName": *r.NextName}
			if r.NextID != nil {
				next["startFileId"] = *r.NextID
			}
			out["next"] = next
		}
		return sdk.JSON(out)

	case "usage":
		maxN := p.MaxFiles
		if maxN <= 0 {
			maxN = 100000
		}
		if maxN > 1_000_000 {
			maxN = 1_000_000
		}
		var bs []Bucket
		if p.Bucket != "" {
			id, err := c.bucketID(ctx, p.Bucket)
			if err != nil {
				return sdk.Result{}, err
			}
			bs = []Bucket{{Name: p.Bucket, ID: id}}
		} else if bs, err = c.buckets(ctx, ""); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, b := range bs {
			u, err := c.usage(ctx, b, maxN)
			if err != nil {
				return sdk.Result{}, err
			}
			out = append(out, u)
		}
		return sdk.JSON(out)

	case "hide_file":
		if err := validFileName(p.FileName); err != nil {
			return sdk.Result{}, err
		}
		bid, err := c.bucketID(ctx, p.Bucket)
		if err != nil {
			return sdk.Result{}, err
		}
		var cur struct {
			Files []file `json:"files"`
		}
		if _, err := c.call(ctx, "b2_list_file_names", map[string]any{"bucketId": bid, "startFileName": p.FileName, "maxFileCount": 1}, &cur); err != nil {
			return sdk.Result{}, err
		}
		if len(cur.Files) == 0 || cur.Files[0].FileName != p.FileName {
			return sdk.Result{}, fmt.Errorf("no visible file %s in %s", p.FileName, p.Bucket)
		}
		target := p.Bucket + "/" + p.FileName
		if call.DryRun {
			before, _ := json.Marshal(cur.Files[0].row(false))
			return sdk.Result{Plan: &sdk.Plan{Summary: "Hide " + target + " (its versions stay)",
				Changes: []sdk.Change{{Target: target, Op: "hide", Before: before}}}}, nil
		}
		var marker file
		if _, err := c.call(ctx, "b2_hide_file", map[string]any{"bucketId": bid, "fileName": p.FileName}, &marker); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"hidden": target, "markerId": marker.FileID})
		res.Undo = sdk.UndoWith("delete_file_version", map[string]any{"fileName": p.FileName, "fileId": marker.FileID}, "Unhide "+p.FileName)
		return res, err

	case "delete_file_version":
		if err := validFileName(p.FileName); err != nil {
			return sdk.Result{}, err
		}
		if !fileIDRe.MatchString(p.FileID) {
			return sdk.Result{}, errors.New("enter the version's file id (from files with versions on)")
		}
		var f file
		if _, err := c.call(ctx, "b2_get_file_info", map[string]any{"fileId": p.FileID}, &f); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusBadRequest) {
				return sdk.Result{}, fmt.Errorf("no file version %s", p.FileID)
			}
			return sdk.Result{}, err
		}
		if f.FileName != p.FileName {
			return sdk.Result{}, fmt.Errorf("version %s belongs to %s, not %s", p.FileID, f.FileName, p.FileName)
		}
		if call.DryRun {
			what := "Delete a version of " + f.FileName
			if f.Action == "hide" {
				what = "Remove the hide marker on " + f.FileName + " (the file shows again)"
			}
			before, _ := json.Marshal(f.row(true))
			return sdk.Result{Plan: &sdk.Plan{Summary: what, Changes: []sdk.Change{{Target: f.FileName + " @ " + f.FileID, Op: "delete", Before: before}}}}, nil
		}
		if _, err := c.call(ctx, "b2_delete_file_version", map[string]any{"fileName": p.FileName, "fileId": p.FileID}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": p.FileName, "fileId": p.FileID})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// usage pages through a bucket's versions, counting.
func (c *conn) usage(ctx context.Context, b Bucket, maxN int) (map[string]any, error) {
	var files, versions, hidden, seen int
	var bytes, current int64
	var startName, startID *string
	last := ""
	for seen < maxN {
		n := 10000
		if maxN-seen < n {
			n = maxN - seen
		}
		body := map[string]any{"bucketId": b.ID, "maxFileCount": n}
		if startName != nil {
			body["startFileName"] = *startName
		}
		if startID != nil {
			body["startFileId"] = *startID
		}
		var r struct {
			Files    []file  `json:"files"`
			NextName *string `json:"nextFileName"`
			NextID   *string `json:"nextFileId"`
		}
		if _, err := c.call(ctx, "b2_list_file_versions", body, &r); err != nil {
			return nil, err
		}
		for _, f := range r.Files {
			seen++
			newest := f.FileName != last // versions come newest first per name
			last = f.FileName
			switch f.Action {
			case "upload":
				versions++
				bytes += f.Size
				if newest {
					files++
					current += f.Size
				}
			case "hide":
				// A hidden file isn't counted as a file, but its older
				// versions still take space.
				hidden++
			case "start":
				versions++
				bytes += f.Size
			}
		}
		if r.NextName == nil || len(r.Files) == 0 {
			startName = nil
			break
		}
		startName, startID = r.NextName, r.NextID
	}
	return map[string]any{
		"bucket": b.Name, "files": files, "versions": versions, "hidden": hidden,
		"bytes": bytes, "currentBytes": current, "truncated": startName != nil,
	}, nil
}
