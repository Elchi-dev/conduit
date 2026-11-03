// Package s3 works with S3-compatible object storage (MinIO, Cloudflare R2,
// Backblaze B2, Wasabi, Garage, AWS S3): buckets, objects, usage, download
// links and deletes. Requests are signed with SigV4 (modules/aws).
package s3

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/aws"
	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one S3-compatible endpoint.
type Config struct {
	Endpoint    string `json:"endpoint"`    // e.g. https://s3.eu-central-1.amazonaws.com, https://<account>.r2.cloudflarestorage.com
	Region      string `json:"region"`      // default us-east-1 (R2: auto)
	AccessKeyID string `json:"accessKeyId"` // not secret on its own
	SecretKey   string `json:"secretKey"`   // secret:// secret access key
	// VirtualHost addresses buckets as <bucket>.<host> instead of
	// <host>/<bucket> (path style, the default, which MinIO and Garage need).
	VirtualHost bool `json:"virtualHost"`
}

type conn struct {
	cfg  Config
	base *url.URL
	host sdk.Host
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
	now  func() time.Time
}

// New returns the S3 module.
func New() *Module { return &Module{} }

var (
	bucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	keyIDRe  = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{3,128}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	b := `"bucket":{"type":"string","description":"Bucket name"}`
	k := `"key":{"type":"string","description":"Object key, e.g. backups/2026-11-03.tar"}`
	return sdk.Manifest{
		ID: "s3", Name: "Object storage (S3)", Version: "0.1.0", Category: "Storage", Icon: "box",
		Description: "Buckets and files in S3-compatible storage: MinIO, Cloudflare R2, Backblaze B2, Wasabi, Garage or AWS S3.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["endpoint","accessKeyId","secretKey"],"properties":{
			"endpoint":{"type":"string","description":"The S3 address, e.g. https://minio.home.lan:9000 or https://<account>.r2.cloudflarestorage.com"},
			"region":{"type":"string","default":"us-east-1","description":"Region; Cloudflare R2 uses auto"},
			"accessKeyId":{"type":"string","description":"Access key id"},
			"secretKey":{"type":"string","x-secret":true,"description":"Secret access key"},
			"virtualHost":{"type":"boolean","default":false,"description":"Address buckets as bucket.host (AWS); off for MinIO and Garage"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "buckets", Title: "Buckets", Risk: sdk.RiskRead},
			{Name: "objects", Title: "Files", Description: "Objects in a bucket, optionally under a prefix (at most 1000).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["bucket"],"properties":{` + b + `,"prefix":{"type":"string"},"limit":{"type":"integer","default":200,"maximum":1000}}}`)},
			{Name: "info", Title: "File details", Description: "Size, type and last change of one object.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["bucket","key"],"properties":{` + b + `,` + k + `}}`)},
			{Name: "usage", Title: "Bucket usage", Description: "Counts objects and adds up their sizes (stops after 50,000 objects).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["bucket"],"properties":{` + b + `,"prefix":{"type":"string"}}}`)},
			{Name: "link", Title: "Download link", Description: "A link anyone can use to download the file until it expires (at most 7 days).", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["bucket","key"],"properties":{` + b + `,` + k + `,"hours":{"type":"integer","default":24,"minimum":1,"maximum":168}}}`)},
			{Name: "delete", Title: "Delete a file", Description: "Removes the object. Without versioning on the bucket it's gone for good.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["bucket","key"],"properties":{` + b + `,` + k + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimRight(c.Endpoint, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return errors.New("the endpoint is an address like https://minio.example.com:9000, without a path")
	}
	if u.Scheme == "http" && !isLocal(u.Hostname()) {
		return errors.New("use https for storage that isn't on this machine (the signing key's requests would otherwise travel in the clear)")
	}
	u.Path = ""
	if !keyIDRe.MatchString(c.AccessKeyID) {
		return errors.New("enter the access key id")
	}
	if !strings.HasPrefix(c.SecretKey, "secret://") {
		return errors.New("store the secret access key in the vault and enter its secret:// reference")
	}
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	if !regexp.MustCompile(`^[a-z0-9-]{2,32}$`).MatchString(c.Region) {
		return errors.New("the region looks like us-east-1, eu-central-1 or auto")
	}
	m.set.Put(id, &conn{cfg: c, base: u, host: h})
	return nil
}

func isLocal(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasSuffix(h, ".localhost")
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (m *Module) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

func (m *Module) client() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// validKey refuses keys that a server might normalize into another path.
func validKey(k string) error {
	if k == "" || len(k) > 1024 {
		return errors.New("the key is 1 to 1024 characters")
	}
	for _, r := range k {
		if r < 0x20 || r == 0x7f {
			return errors.New("the key contains control characters")
		}
	}
	for _, seg := range strings.Split(k, "/") {
		if seg == "." || seg == ".." {
			return errors.New("keys can't contain . or .. segments")
		}
	}
	return nil
}

// objectURL is the address of a bucket (key "") or object.
func (c *conn) objectURL(bucket, key string) *url.URL {
	u := *c.base
	esc := uriEncode(key, true)
	if c.cfg.VirtualHost {
		u.Host = bucket + "." + u.Host
		u.Path = "/" + key
		u.RawPath = "/" + esc
	} else {
		u.Path = "/" + bucket
		u.RawPath = "/" + bucket
		if key != "" {
			u.Path += "/" + key
			u.RawPath += "/" + esc
		}
	}
	return &u
}

func (m *Module) creds(ctx context.Context, c *conn) (aws.Credentials, error) {
	sk, err := c.host.Secret(ctx, c.cfg.SecretKey)
	if err != nil {
		return aws.Credentials{}, err
	}
	return aws.Credentials{AccessKeyID: c.cfg.AccessKeyID, SecretAccessKey: strings.TrimSpace(sk)}, nil
}

type s3Error struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// do sends a signed request and returns the body (capped) and headers.
func (m *Module) do(ctx context.Context, c *conn, method string, u *url.URL) ([]byte, http.Header, error) {
	cr, err := m.creds(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	aws.Sign(req, nil, cr, c.cfg.Region, "s3", m.clock())
	res, err := m.client().Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return nil, nil, err
	}
	if res.StatusCode >= 300 {
		var e s3Error
		if xml.Unmarshal(body, &e) == nil && e.Code != "" {
			msg := e.Code
			if e.Message != "" {
				msg += ": " + e.Message
			}
			return nil, res.Header, fmt.Errorf("%s", msg)
		}
		if res.StatusCode == http.StatusNotFound {
			return nil, res.Header, errors.New("not found")
		}
		return nil, res.Header, fmt.Errorf("the storage answered %s", res.Status)
	}
	return body, res.Header, nil
}

type bucket struct {
	Name    string `json:"name"`
	Created string `json:"created"`
}

func (m *Module) buckets(ctx context.Context, c *conn) ([]bucket, error) {
	u := *c.base
	u.Path = "/"
	body, _, err := m.do(ctx, c, http.MethodGet, &u)
	if err != nil {
		return nil, err
	}
	var r struct {
		Buckets []struct {
			Name         string `xml:"Name"`
			CreationDate string `xml:"CreationDate"`
		} `xml:"Buckets>Bucket"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("unexpected answer: %w", err)
	}
	out := []bucket{}
	for _, b := range r.Buckets {
		out = append(out, bucket{Name: b.Name, Created: b.CreationDate})
	}
	return out, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	bs, err := m.buckets(ctx, c)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d buckets", len(bs))}
}

type object struct {
	Key      string `json:"key"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
}

type listResult struct {
	Contents []struct {
		Key          string `xml:"Key"`
		Size         int64  `xml:"Size"`
		LastModified string `xml:"LastModified"`
	} `xml:"Contents"`
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
}

func (m *Module) list(ctx context.Context, c *conn, bkt, prefix, token string, max int) (listResult, error) {
	u := c.objectURL(bkt, "")
	q := url.Values{"list-type": {"2"}, "max-keys": {strconv.Itoa(max)}}
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	if token != "" {
		q.Set("continuation-token", token)
	}
	u.RawQuery = q.Encode()
	var r listResult
	body, _, err := m.do(ctx, c, http.MethodGet, u)
	if err != nil {
		return r, err
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return r, fmt.Errorf("unexpected answer: %w", err)
	}
	return r, nil
}

func (m *Module) head(ctx context.Context, c *conn, bkt, key string) (map[string]any, error) {
	_, h, err := m.do(ctx, c, http.MethodHead, c.objectURL(bkt, key))
	if err != nil {
		return nil, err
	}
	size, _ := strconv.ParseInt(h.Get("Content-Length"), 10, 64)
	return map[string]any{"bucket": bkt, "key": key, "size": size, "type": h.Get("Content-Type"),
		"modified": h.Get("Last-Modified"), "etag": strings.Trim(h.Get("ETag"), `"`), "storageClass": h.Get("X-Amz-Storage-Class")}, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Bucket string `json:"bucket"`
		Key    string `json:"key"`
		Prefix string `json:"prefix"`
		Limit  int    `json:"limit"`
		Hours  int    `json:"hours"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if call.Action != "buckets" && !bucketRe.MatchString(p.Bucket) {
		return sdk.Result{}, errors.New("bucket names are 3 to 63 lowercase letters, digits, dots and dashes")
	}
	if len(p.Prefix) > 1024 {
		return sdk.Result{}, errors.New("the prefix is too long")
	}
	switch call.Action {
	case "info", "link", "delete":
		if err := validKey(p.Key); err != nil {
			return sdk.Result{}, err
		}
	}
	switch call.Action {
	case "buckets":
		bs, err := m.buckets(ctx, c)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(bs)

	case "objects":
		limit := p.Limit
		if limit <= 0 {
			limit = 200
		}
		if limit > 1000 {
			limit = 1000
		}
		r, err := m.list(ctx, c, p.Bucket, p.Prefix, "", limit)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []object{}
		for _, o := range r.Contents {
			out = append(out, object{Key: o.Key, Size: o.Size, Modified: o.LastModified})
		}
		return sdk.JSON(map[string]any{"objects": out, "more": r.IsTruncated})

	case "info":
		info, err := m.head(ctx, c, p.Bucket, p.Key)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(info)

	case "usage":
		const maxObjects = 50000
		var count, size int64
		token := ""
		complete := true
		for {
			r, err := m.list(ctx, c, p.Bucket, p.Prefix, token, 1000)
			if err != nil {
				return sdk.Result{}, err
			}
			for _, o := range r.Contents {
				count++
				size += o.Size
			}
			if !r.IsTruncated || r.NextContinuationToken == "" {
				break
			}
			if count >= maxObjects {
				complete = false
				break
			}
			token = r.NextContinuationToken
		}
		return sdk.JSON(map[string]any{"bucket": p.Bucket, "prefix": p.Prefix, "objects": count, "bytes": size, "complete": complete})

	case "link":
		hours := p.Hours
		if hours <= 0 {
			hours = 24
		}
		if hours > 168 {
			return sdk.Result{}, errors.New("links last at most 7 days (168 hours)")
		}
		cr, err := m.creds(ctx, c)
		if err != nil {
			return sdk.Result{}, err
		}
		link := Presign(c.objectURL(p.Bucket, p.Key), cr, c.cfg.Region, time.Duration(hours)*time.Hour, m.clock())
		return sdk.JSON(map[string]any{"url": link, "expires": m.clock().Add(time.Duration(hours) * time.Hour).UTC().Format(time.RFC3339)})

	case "delete":
		info, err := m.head(ctx, c, p.Bucket, p.Key)
		if err != nil {
			return sdk.Result{}, err
		}
		target := p.Bucket + "/" + p.Key
		if call.DryRun {
			before, _ := json.Marshal(info)
			return sdk.Result{Plan: &sdk.Plan{Summary: "Delete " + target, Changes: []sdk.Change{{Target: target, Op: "delete", Before: before}}}}, nil
		}
		if _, _, err := m.do(ctx, c, http.MethodDelete, c.objectURL(p.Bucket, p.Key)); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": target, "size": info["size"]})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// --- presigned URLs (SigV4 query-string signing) -----------------------------

func uriEncode(s string, path bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' || (path && c == '/') {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
	}
	return b.String()
}

func hmacSHA256(key []byte, s string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(s))
	return h.Sum(nil)
}

// Presign returns a GET link for u that works without credentials until it
// expires (S3 caps this at 7 days).
func Presign(u *url.URL, c aws.Credentials, region string, expires time.Duration, now time.Time) string {
	t := now.UTC()
	amz := t.Format("20060102T150405Z")
	day := t.Format("20060102")
	scope := day + "/" + region + "/s3/aws4_request"
	q := url.Values{
		"X-Amz-Algorithm":     {"AWS4-HMAC-SHA256"},
		"X-Amz-Credential":    {c.AccessKeyID + "/" + scope},
		"X-Amz-Date":          {amz},
		"X-Amz-Expires":       {strconv.Itoa(int(expires.Seconds()))},
		"X-Amz-SignedHeaders": {"host"},
	}
	if c.SessionToken != "" {
		q.Set("X-Amz-Security-Token", c.SessionToken)
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var cq bytes.Buffer
	for i, k := range keys {
		if i > 0 {
			cq.WriteByte('&')
		}
		cq.WriteString(uriEncode(k, false) + "=" + uriEncode(q.Get(k), false))
	}
	path := u.EscapedPath()
	if p, err := url.PathUnescape(path); err == nil {
		path = uriEncode(p, true)
	}
	if path == "" {
		path = "/"
	}
	creq := strings.Join([]string{"GET", path, cq.String(), "host:" + u.Host + "\n", "host", "UNSIGNED-PAYLOAD"}, "\n")
	sum := sha256.Sum256([]byte(creq))
	sts := strings.Join([]string{"AWS4-HMAC-SHA256", amz, scope, hex.EncodeToString(sum[:])}, "\n")
	k := hmacSHA256([]byte("AWS4"+c.SecretAccessKey), day)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, "s3")
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, sts))
	out := *u
	out.RawQuery = cq.String() + "&X-Amz-Signature=" + sig
	return out.String()
}
