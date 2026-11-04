// Package ocis works with ownCloud Infinite Scale through its Graph API and
// WebDAV, with an app token or an OIDC access token from the vault: spaces
// (personal, project, shares) and their quotas, and folder listings.
package ocis

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one oCIS account.
type Config struct {
	URL string `json:"url"` // e.g. https://ocis.example.com
	// User, when set, signs in with Basic auth and Token is an app token
	// (auth-app); empty, Token is sent as an OIDC bearer token.
	User               string `json:"user"`
	Token              string `json:"token"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api      *rest.Client
	basePath string // the server address's path, for reading WebDAV hrefs
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the oCIS module.
func New() *Module { return &Module{} }

var (
	basePathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	userRe     = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,128}$`)
	part       = `[A-Za-z0-9._-]{1,100}`
	driveRe    = regexp.MustCompile(`^` + part + `(\$` + part + `)?(!` + part + `)?$`)
	typeRe     = regexp.MustCompile(`^[a-z]{1,32}$`)
)

// maxPropfind bounds a WebDAV answer; maxEntries the rows it gives.
var (
	maxPropfind int64 = 8 << 20
	maxEntries        = 5000
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	drive := `"drive":{"type":"string","description":"Space id (from drives)"}`
	return sdk.Manifest{
		ID: "ocis", Name: "ownCloud Infinite Scale", Version: "0.1.0", Category: "Storage", Icon: "cloud",
		Description: "ownCloud Infinite Scale (oCIS): spaces and their quotas, and folder listings.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Your oCIS, e.g. https://ocis.example.com"},
			"user":{"type":"string","description":"For an app token: the user name it belongs to. Leave empty for an OIDC access token"},
			"token":{"type":"string","x-secret":true,"description":"An app token (ocis auth-app create, or the account page), or an OIDC access token"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "drives", Title: "Spaces", Description: "Spaces you can reach (every space for an admin with all): id, name, type (personal, project, virtual, mountpoint), quota used, total, remaining and state, last change, and whether it's disabled.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"all":{"type":"boolean","description":"Every space on the server (needs an admin)"},"type":{"type":"string","description":"Only this type, e.g. project"}}}`)},
			{Name: "quota", Title: "Quota", Description: "Used, total and remaining space and the quota state (normal, nearing, critical, exceeded) of your personal space, or of one space.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + drive + `}}`)},
			{Name: "list", Title: "List a folder", Description: "Files and folders in a folder of a space: name, path, type, size, modified, MIME type.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["drive"],"properties":{` + drive + `,"path":{"type":"string","default":"/","description":"Folder path in the space (default: the top)"},"limit":{"type":"integer","default":500,"maximum":5000}}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !basePathRe.MatchString(u.Path) {
		return errors.New("the address is like https://ocis.example.com")
	}
	c.User = strings.TrimSpace(c.User)
	if c.User != "" && !userRe.MatchString(c.User) {
		return errors.New("the user is a user name, like alice")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the token in the vault and enter its secret:// reference")
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
	ref, user := c.Token, c.User
	bp := strings.TrimRight(u.Path, "/")
	api := rest.New(u.Scheme+"://"+u.Host+bp, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		if user != "" {
			r.SetBasicAuth(user, t)
		} else {
			r.Header.Set("Authorization", "Bearer "+t)
		}
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, basePath: bp})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("oCIS refused the token (an OIDC access token expires within minutes; an app token lasts)")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the token's user isn't allowed to do this in oCIS")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("there's nothing at that path in oCIS")
	}
	return err
}

func (c *conn) get(ctx context.Context, p string, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, p, nil, nil, out)
	return friendly(err)
}

type quota struct {
	Remaining *int64 `json:"remaining"`
	Total     *int64 `json:"total"`
	Used      *int64 `json:"used"`
	State     string `json:"state"`
}

func (q quota) row() map[string]any {
	r := map[string]any{}
	if q.Used != nil {
		r["usedBytes"] = *q.Used
	}
	if q.Total != nil && *q.Total > 0 {
		r["totalBytes"] = *q.Total
		if q.Used != nil {
			r["percent"] = float64(int(float64(*q.Used)/float64(*q.Total)*1000)) / 10
		}
	}
	if q.Remaining != nil {
		r["remainingBytes"] = *q.Remaining
	}
	if typeRe.MatchString(q.State) {
		r["state"] = q.State
	}
	return r
}

type drive struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"driveType"`
	Alias    string `json:"driveAlias"`
	Modified string `json:"lastModifiedDateTime"`
	Quota    quota  `json:"quota"`
	Root     struct {
		Deleted *struct {
			State string `json:"state"`
		} `json:"deleted"`
	} `json:"root"`
	// The owner and permissions (people's ids and names) aren't decoded.
}

func (d drive) row() map[string]any {
	r := map[string]any{"id": d.ID, "name": d.Name, "type": d.Type, "modified": d.Modified, "quota": d.Quota.row()}
	if d.Alias != "" {
		r["alias"] = d.Alias
	}
	if d.Root.Deleted != nil && d.Root.Deleted.State != "" {
		r["disabled"] = true
	}
	return r
}

func (c *conn) drives(ctx context.Context, all bool) ([]drive, error) {
	p := "/graph/v1.0/me/drives"
	if all {
		p = "/graph/v1.0/drives"
	}
	var out struct {
		Value []drive `json:"value"`
	}
	if err := c.get(ctx, p, &out); err != nil {
		return nil, err
	}
	return out.Value, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		DisplayName string `json:"displayName"`
	}
	if err := c.get(ctx, "/graph/v1.0/me", &me); err != nil {
		if strings.HasPrefix(err.Error(), "there's nothing") {
			return sdk.Health{Status: "down", Message: "no oCIS Graph API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	ds, err := c.drives(ctx, false)
	if err != nil {
		return sdk.Health{Status: "degraded", Message: "signed in, but listing spaces failed: " + err.Error()}
	}
	msg := fmt.Sprintf("signed in as %s; %d spaces", me.DisplayName, len(ds))
	for _, d := range ds {
		if d.Type == "personal" && (d.Quota.State == "critical" || d.Quota.State == "exceeded") {
			return sdk.Health{Status: "degraded", Message: msg + "; personal space quota " + d.Quota.State}
		}
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
		All   bool   `json:"all"`
		Type  string `json:"type"`
		Drive string `json:"drive"`
		Path  string `json:"path"`
		Limit int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "drives":
		if p.Type != "" && !typeRe.MatchString(p.Type) {
			return sdk.Result{}, errors.New("type is a space type like personal or project")
		}
		ds, err := c.drives(ctx, p.All)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range ds {
			if p.Type == "" || d.Type == p.Type {
				out = append(out, d.row())
			}
		}
		return sdk.JSON(out)
	case "quota":
		if p.Drive != "" {
			id := strings.TrimSpace(p.Drive)
			if !driveRe.MatchString(id) {
				return sdk.Result{}, errors.New("a space is its id from drives")
			}
			var d drive
			if err := c.get(ctx, "/graph/v1.0/drives/"+url.PathEscape(id), &d); err != nil {
				return sdk.Result{}, err
			}
			r := d.Quota.row()
			r["type"] = d.Type
			return sdk.JSON(r)
		}
		ds, err := c.drives(ctx, false)
		if err != nil {
			return sdk.Result{}, err
		}
		for _, d := range ds {
			if d.Type == "personal" {
				r := d.Quota.row()
				r["type"] = d.Type
				return sdk.JSON(r)
			}
		}
		return sdk.Result{}, errors.New("this account has no personal space")
	case "list":
		id := strings.TrimSpace(p.Drive)
		if !driveRe.MatchString(id) {
			return sdk.Result{}, errors.New("a space is its id from drives")
		}
		segs, err := checkPath(p.Path)
		if err != nil {
			return sdk.Result{}, err
		}
		n := p.Limit
		if n <= 0 {
			n = 500
		}
		if n > maxEntries {
			n = maxEntries
		}
		return c.list(ctx, id, segs, n)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// checkPath validates a folder path in a space and returns its parts.
func checkPath(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "/" {
		return nil, nil
	}
	if !strings.HasPrefix(s, "/") || len(s) > 1024 || strings.Contains(s, "//") || strings.Contains(s, "\\") || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return nil, errors.New("a path starts with / and has no empty parts, backslashes or control characters, like /Documents")
	}
	segs := strings.Split(strings.TrimRight(s[1:], "/"), "/")
	for _, seg := range segs {
		if seg == "." || seg == ".." {
			return nil, errors.New("a path can't contain . or .. parts")
		}
	}
	return segs, nil
}

const propfindBody = `<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
<d:prop><d:resourcetype/><d:getcontentlength/><d:getlastmodified/><d:getcontenttype/><oc:size/><oc:fileid/></d:prop>
</d:propfind>`

type multistatus struct {
	Responses []struct {
		Href     string `xml:"DAV: href"`
		Propstat []struct {
			Status string `xml:"DAV: status"`
			Prop   struct {
				ResourceType struct {
					Collection *struct{} `xml:"DAV: collection"`
				} `xml:"DAV: resourcetype"`
				Length      string `xml:"DAV: getcontentlength"`
				Modified    string `xml:"DAV: getlastmodified"`
				ContentType string `xml:"DAV: getcontenttype"`
				Size        string `xml:"http://owncloud.org/ns size"`
				FileID      string `xml:"http://owncloud.org/ns fileid"`
			} `xml:"DAV: prop"`
		} `xml:"DAV: propstat"`
	} `xml:"DAV: response"`
}

func (c *conn) list(ctx context.Context, id string, segs []string, n int) (sdk.Result, error) {
	esc := make([]string, len(segs))
	for i, s := range segs {
		esc[i] = url.PathEscape(s)
	}
	prefix := "/dav/spaces/" + url.PathEscape(id)
	p := prefix + "/"
	if len(esc) > 0 {
		p += strings.Join(esc, "/") + "/"
	}
	res, err := c.api.Send(ctx, "PROPFIND", p, nil, strings.NewReader(propfindBody),
		http.Header{"Depth": {"1"}, "Content-Type": {"application/xml; charset=utf-8"}})
	if err != nil {
		return sdk.Result{}, friendly(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusMultiStatus {
		return sdk.Result{}, fmt.Errorf("oCIS answered %s to the folder listing", res.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxPropfind+1))
	if err != nil {
		return sdk.Result{}, rest.TransportError(err)
	}
	if int64(len(raw)) > maxPropfind {
		return sdk.Result{}, fmt.Errorf("the folder listing is larger than %d MB; list a smaller folder", maxPropfind>>20)
	}
	var ms multistatus
	if err := xml.NewDecoder(bytes.NewReader(raw)).Decode(&ms); err != nil {
		return sdk.Result{}, errors.New("unexpected answer from oCIS WebDAV")
	}
	self := "/" + strings.Join(segs, "/")
	davRoot := c.basePath + prefix
	list := []map[string]any{}
	more := false
	for _, r := range ms.Responses {
		href := r.Href
		if u, err := url.Parse(href); err == nil {
			href = u.Path // an absolute href, or one already unescaped
		}
		rel, ok := strings.CutPrefix(href, davRoot)
		if !ok {
			continue
		}
		rel = "/" + strings.Trim(rel, "/")
		if rel == self {
			continue
		}
		if len(list) >= n {
			more = true
			break
		}
		row := map[string]any{"name": path.Base(rel), "path": rel}
		for _, ps := range r.Propstat {
			if !strings.Contains(ps.Status, " 200") {
				continue
			}
			pr := ps.Prop
			if pr.ResourceType.Collection != nil {
				row["type"] = "folder"
			} else {
				row["type"] = "file"
				if pr.ContentType != "" && len(pr.ContentType) < 128 {
					row["mime"] = pr.ContentType
				}
			}
			size := pr.Size
			if size == "" {
				size = pr.Length
			}
			if v, err := strconv.ParseInt(strings.TrimSpace(size), 10, 64); err == nil {
				row["size"] = v
			}
			if t, err := http.ParseTime(pr.Modified); err == nil {
				row["modified"] = t.UTC().Format(time.RFC3339)
			}
			if pr.FileID != "" && len(pr.FileID) <= 300 {
				row["id"] = pr.FileID
			}
		}
		if _, ok := row["type"]; !ok {
			row["type"] = "file"
		}
		list = append(list, row)
	}
	out := map[string]any{"path": self, "entries": list}
	if more {
		out["more"] = true
	}
	return sdk.JSON(out)
}
