// Package sops lists the SOPS-encrypted files in a folder on this machine and
// reads their metadata without decrypting anything: the key names (and
// whether each value is encrypted), the recipients each file is encrypted to
// (age, PGP, AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault transit),
// when SOPS last changed it, its settings, and the creation rules of
// .sops.yaml. It has no decryption keys and no way to use one, never returns
// a value (encrypted or left in the clear by unencrypted_suffix and the
// like), and never writes.
package sops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one folder.
type Config struct {
	Folder string `json:"folder"` // absolute path
}

type instance struct {
	folder string
}

// Module implements sdk.Module.
type Module struct {
	mu   sync.Mutex
	inst map[string]*instance
}

// New returns the SOPS module.
func New() *Module { return &Module{inst: map[string]*instance{}} }

const (
	maxFileSize = 1 << 20
	maxEntries  = 20000
	maxFiles    = 1000
	maxWalk     = 8 // folder levels below the root
	maxKeys     = 1000
	// A scan reads at most scanBytes and spends at most scanTime; one file
	// gets at most fileTime of parsing. Past them the file is skipped, or
	// the scan stops and says it's truncated.
	scanBytes = 64 << 20
	scanTime  = 20 * time.Second
	fileTime  = 2 * time.Second
)

// skipDirs are never descended into.
var skipDirs = map[string]bool{".git": true, ".hg": true, ".svn": true, "node_modules": true, ".terraform": true, "vendor": true, ".venv": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "sops", Name: "SOPS files", Version: "0.1.0", Category: "Security", Icon: "key",
		Description: "SOPS-encrypted files in a folder: key names, recipients, last change and settings, without decrypting anything. Read-only.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["folder"],"properties":{
			"folder":{"type":"string","description":"Absolute path of the folder to look in (a repository, say); sub-folders are included up to 8 levels"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "files", Title: "Encrypted files", Description: "Each SOPS file under the folder: path, format, SOPS version, last change, number of keys and recipients by type. Never values.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"olderThanDays":{"type":"integer","minimum":1,"description":"Only files SOPS last changed more than this many days ago"}}}`)},
			{Name: "file", Title: "File metadata", Description: "One SOPS file: its key names and whether each value is encrypted, its recipients (with key groups), last change, MAC presence and settings. Never values.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["path"],"properties":{"path":{"type":"string","description":"Path relative to the folder, e.g. secrets/prod.yaml"}}}`)},
			{Name: "recipients", Title: "Recipients", Description: "Every recipient (age key, PGP fingerprint, KMS key …) with the files encrypted to it, and files with none: what to re-encrypt when a key is retired.", Risk: sdk.RiskRead},
			{Name: "rules", Title: "Creation rules", Description: "The creation rules of the folder's .sops.yaml: path pattern, recipients and which keys get encrypted.", Risk: sdk.RiskRead},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, _ sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	f := strings.TrimSpace(c.Folder)
	if f == "" || !filepath.IsAbs(f) {
		return errors.New("the folder is an absolute path, like /home/me/infra")
	}
	m.mu.Lock()
	m.inst[id] = &instance{folder: filepath.Clean(f)}
	m.mu.Unlock()
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error {
	m.mu.Lock()
	delete(m.inst, id)
	m.mu.Unlock()
	return nil
}

func (m *Module) get(id string) (*instance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if in := m.inst[id]; in != nil {
		return in, nil
	}
	return nil, errors.New("this instance isn't set up")
}

func (in *instance) open() (*os.Root, error) {
	r, err := os.OpenRoot(in.folder)
	if err != nil {
		return nil, fmt.Errorf("can't open the folder %s: %w", in.folder, errors.Unwrap(err))
	}
	return r, nil
}

type recipient struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Created string `json:"created,omitempty"`
	Group   *int   `json:"group,omitempty"` // key group, for files using key_groups
}

type keyInfo struct {
	Key       string `json:"key"`
	Encrypted bool   `json:"encrypted"`
}

type fileInfo struct {
	Path         string            `json:"path"`
	Format       string            `json:"format"`
	Version      string            `json:"version,omitempty"`
	LastModified string            `json:"lastModified,omitempty"`
	MAC          bool              `json:"mac"`
	Settings     map[string]string `json:"settings,omitempty"`
	Recipients   []recipient       `json:"recipients"`
	Keys         []keyInfo         `json:"keys"`
	KeysCapped   bool              `json:"keysTruncated,omitempty"`
	Documents    int               `json:"documents,omitempty"`
	Size         int64             `json:"size"`
	FileModified time.Time         `json:"fileModified"`
}

func (f fileInfo) summary() map[string]any {
	by := map[string]int{}
	for _, r := range f.Recipients {
		by[r.Type]++
	}
	enc := 0
	for _, k := range f.Keys {
		if k.Encrypted {
			enc++
		}
	}
	e := map[string]any{"path": f.Path, "format": f.Format, "version": f.Version, "lastModified": f.LastModified, "keys": len(f.Keys), "encryptedKeys": enc,
		"recipients": by, "size": f.Size, "fileModified": f.FileModified.UTC().Format(time.RFC3339)}
	if !f.MAC {
		e["mac"] = false
	}
	return e
}

// format guesses the SOPS store from the name and content.
func format(name string, b []byte) string {
	switch strings.ToLower(path.Ext(name)) {
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".env":
		return "dotenv"
	case ".ini":
		return "ini"
	}
	t := bytes.TrimSpace(b)
	switch {
	case bytes.HasPrefix(t, []byte("{")):
		return "json" // SOPS's binary store is JSON too
	case bytes.Contains(b, []byte("sops_version=")) || bytes.Contains(b, []byte("sops_mac=")):
		return "dotenv"
	case bytes.HasPrefix(t, []byte("sops:")) || bytes.Contains(b, []byte("\nsops:")):
		return "yaml"
	}
	return ""
}

// inspect reads one file's SOPS metadata; ok is false for a file SOPS
// didn't encrypt, or one too costly to read.
func inspect(rel string, b []byte) (fileInfo, bool) {
	return inspectCtx(context.Background(), rel, b)
}

// inspectCtx is inspect stopping when ctx ends or after fileTime.
func inspectCtx(ctx context.Context, rel string, b []byte) (fileInfo, bool) {
	if !bytes.Contains(b, []byte("sops")) {
		return fileInfo{}, false
	}
	lim := newLimits(ctx, fileTime)
	fi := fileInfo{Path: rel, Format: format(rel, b)}
	var docs []ymap
	var meta ymap
	switch fi.Format {
	case "yaml":
		vs, err := parseYAML(b, lim)
		if err != nil {
			return fileInfo{}, false
		}
		for _, v := range vs {
			if d, ok := v.(ymap); ok {
				docs = append(docs, d)
			}
		}
	case "json":
		v, err := parseJSON(b, lim)
		if err != nil {
			return fileInfo{}, false
		}
		if d, ok := v.(ymap); ok {
			docs = append(docs, d)
		}
	case "dotenv", "ini":
		var d ymap
		if fi.Format == "dotenv" {
			d, meta = parseDotenv(b, lim)
		} else {
			d, meta = parseINI(b, lim)
		}
		if meta == nil {
			return fileInfo{}, false
		}
		meta = derefLists(meta).(ymap)
		docs = append(docs, d)
	default:
		return fileInfo{}, false
	}
	for _, d := range docs {
		if s, ok := d["sops"].(ymap); ok && meta == nil {
			meta = s
		}
	}
	if meta == nil || (str(meta["version"]) == "" && str(meta["mac"]) == "" && str(meta["lastmodified"]) == "") {
		return fileInfo{}, false
	}
	fi.Version, fi.LastModified, fi.MAC = str(meta["version"]), str(meta["lastmodified"]), str(meta["mac"]) != ""
	for _, k := range []string{"unencrypted_suffix", "encrypted_suffix", "unencrypted_regex", "encrypted_regex", "unencrypted_comment_regex", "encrypted_comment_regex", "mac_only_encrypted", "shamir_threshold"} {
		if v := str(meta[k]); v != "" {
			if fi.Settings == nil {
				fi.Settings = map[string]string{}
			}
			fi.Settings[k] = v
		}
	}
	fi.Recipients = recipients(meta, nil)
	if groups, ok := meta["key_groups"].([]any); ok {
		for i, g := range groups {
			if gm, ok := g.(ymap); ok {
				n := i
				fi.Recipients = append(fi.Recipients, recipients(gm, &n)...)
			}
		}
	}
	if len(docs) > 1 {
		fi.Documents = len(docs)
	}
	fi.Keys = []keyInfo{}
	for i, d := range docs {
		prefix := ""
		if len(docs) > 1 {
			prefix = "doc" + strconv.Itoa(i+1) + ":"
		}
		for _, k := range d.keys() {
			if k == "sops" && fi.Format != "dotenv" && fi.Format != "ini" {
				continue
			}
			walk(&fi, prefix+escKey(k), d[k], 0)
		}
	}
	return fi, true
}

func str(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func escKey(k string) string {
	if strings.ContainsAny(k, ".[]") {
		return strconv.Quote(k)
	}
	return k
}

// walk records the leaf key paths under v; values are looked at only to
// see whether they're ENC[…].
func walk(fi *fileInfo, p string, v any, depth int) {
	if len(fi.Keys) >= maxKeys {
		fi.KeysCapped = true
		return
	}
	switch t := v.(type) {
	case ymap:
		if len(t.keys()) == 0 || depth > maxDepth {
			fi.Keys = append(fi.Keys, keyInfo{Key: p})
			return
		}
		for _, k := range t.keys() {
			walk(fi, p+"."+escKey(k), t[k], depth+1)
		}
	case []any:
		if len(t) == 0 || depth > maxDepth {
			fi.Keys = append(fi.Keys, keyInfo{Key: p})
			return
		}
		for i, e := range t {
			walk(fi, p+"["+strconv.Itoa(i)+"]", e, depth+1)
		}
	default:
		s, _ := v.(string)
		fi.Keys = append(fi.Keys, keyInfo{Key: p, Encrypted: strings.HasPrefix(strings.TrimSpace(s), "ENC[")})
	}
}

// recipients reads the master keys of a sops section or key group. The
// encrypted data keys ("enc") stay where they are.
func recipients(m ymap, group *int) []recipient {
	out := []recipient{}
	each := func(name string, id func(ymap) string, typ string) {
		list, _ := m[name].([]any)
		for _, e := range list {
			if s := str(e); s != "" {
				// .sops.yaml key groups list age and PGP keys as plain strings.
				out = append(out, recipient{Type: typ, ID: s, Group: group})
				continue
			}
			em, ok := e.(ymap)
			if !ok {
				continue
			}
			if v := id(em); v != "" {
				out = append(out, recipient{Type: typ, ID: v, Created: str(em["created_at"]), Group: group})
			}
		}
	}
	each("age", func(e ymap) string { return str(e["recipient"]) }, "age")
	each("pgp", func(e ymap) string { return str(e["fp"]) }, "pgp")
	each("kms", func(e ymap) string { return str(e["arn"]) }, "aws_kms")
	each("gcp_kms", func(e ymap) string { return str(e["resource_id"]) }, "gcp_kms")
	each("azure_kv", func(e ymap) string {
		if str(e["vault_url"]) == "" {
			return ""
		}
		return strings.TrimRight(str(e["vault_url"]), "/") + "/keys/" + str(e["name"]) + "/" + str(e["version"])
	}, "azure_kv")
	each("hc_vault", func(e ymap) string {
		if str(e["vault_address"]) == "" {
			return ""
		}
		return strings.TrimRight(str(e["vault_address"]), "/") + "/v1/" + strings.Trim(str(e["engine_path"]), "/") + "/keys/" + str(e["key_name"])
	}, "hc_vault")
	return out
}

// read opens a regular file inside the root, refusing symlinks and big files.
// The file is opened non-blocking (openFlags) and checked again once open,
// so one swapped for a FIFO or device after the Lstat is never waited on
// or read.
func read(r *os.Root, rel string) ([]byte, fs.FileInfo, error) {
	st, err := r.Lstat(rel)
	if err != nil {
		return nil, nil, fmt.Errorf("there's no file %s in the folder", rel)
	}
	if !st.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s isn't a regular file", rel)
	}
	if st.Size() > maxFileSize {
		return nil, nil, fmt.Errorf("%s is over %d MiB", rel, maxFileSize>>20)
	}
	f, err := r.OpenFile(rel, openFlags, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("can't open %s", rel)
	}
	defer f.Close()
	st, err = f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s isn't a regular file", rel)
	}
	if st.Size() > maxFileSize {
		return nil, nil, fmt.Errorf("%s is over %d MiB", rel, maxFileSize>>20)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, nil, fmt.Errorf("can't read %s", rel)
	}
	if len(b) > maxFileSize {
		return nil, nil, fmt.Errorf("%s is over %d MiB", rel, maxFileSize>>20)
	}
	return b, st, nil
}

// scan walks the folder and returns its SOPS files.
func (in *instance) scan(ctx context.Context) ([]fileInfo, bool, error) {
	r, err := in.open()
	if err != nil {
		return nil, false, err
	}
	defer r.Close()
	var files []fileInfo
	entries, truncated := 0, false
	bytesRead, until := 0, time.Now().Add(scanTime)
	err = fs.WalkDir(r.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == "." {
				return err
			}
			return nil // unreadable sub-folder: skip it
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		entries++
		if entries > maxEntries || len(files) >= maxFiles || bytesRead >= scanBytes || time.Now().After(until) {
			truncated = true
			return fs.SkipAll
		}
		if d.IsDir() {
			if p != "." && (skipDirs[d.Name()] || strings.Count(p, "/") >= maxWalk) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // symlinks and devices are never followed
		}
		b, st, err := read(r, p)
		if err != nil {
			return nil
		}
		bytesRead += len(b)
		if fi, ok := inspectCtx(ctx, p, b); ok {
			fi.Size, fi.FileModified = st.Size(), st.ModTime()
			files = append(files, fi)
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, truncated, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	in, err := m.get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	files, truncated, err := in.scan(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("%d encrypted file(s)", len(files))
	if truncated {
		msg = "at least " + msg
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Path          string `json:"path"`
	OlderThanDays int    `json:"olderThanDays"`
}

// localPath checks a path relative to the folder.
func localPath(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 4096 || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) || strings.Contains(s, `\`) {
		return "", errors.New("the path is relative to the folder, like secrets/prod.yaml")
	}
	s = path.Clean(strings.TrimPrefix(s, "./"))
	if !filepath.IsLocal(s) || strings.HasPrefix(s, "/") {
		return "", errors.New("the path is relative to the folder and stays inside it")
	}
	return s, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	in, err := m.get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p input
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "files":
		if p.OlderThanDays < 0 {
			return sdk.Result{}, errors.New("olderThanDays is 1 or more")
		}
		files, truncated, err := in.scan(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, f := range files {
			if p.OlderThanDays > 0 {
				t, err := time.Parse(time.RFC3339, f.LastModified)
				if err == nil && time.Since(t) < time.Duration(p.OlderThanDays)*24*time.Hour {
					continue
				}
			}
			list = append(list, f.summary())
		}
		out := map[string]any{"folder": in.folder, "files": list}
		if truncated {
			out["truncated"] = true
		}
		return sdk.JSON(out)

	case "file":
		rel, err := localPath(p.Path)
		if err != nil {
			return sdk.Result{}, err
		}
		r, err := in.open()
		if err != nil {
			return sdk.Result{}, err
		}
		defer r.Close()
		b, st, err := read(r, rel)
		if err != nil {
			return sdk.Result{}, err
		}
		fi, ok := inspectCtx(ctx, rel, b)
		if !ok {
			return sdk.Result{}, fmt.Errorf("%s isn't a SOPS-encrypted file (no sops metadata)", rel)
		}
		fi.Size, fi.FileModified = st.Size(), st.ModTime().UTC()
		return sdk.JSON(fi)

	case "recipients":
		files, truncated, err := in.scan(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		type entry struct {
			Type  string   `json:"type"`
			ID    string   `json:"id"`
			Files []string `json:"files"`
		}
		by := map[string]*entry{}
		none := []string{}
		for _, f := range files {
			if len(f.Recipients) == 0 {
				none = append(none, f.Path)
			}
			seen := map[string]bool{}
			for _, r := range f.Recipients {
				k := r.Type + " " + r.ID
				if seen[k] {
					continue
				}
				seen[k] = true
				if by[k] == nil {
					by[k] = &entry{Type: r.Type, ID: r.ID}
				}
				by[k].Files = append(by[k].Files, f.Path)
			}
		}
		list := []*entry{}
		for _, e := range by {
			list = append(list, e)
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Type != list[j].Type {
				return list[i].Type < list[j].Type
			}
			return list[i].ID < list[j].ID
		})
		out := map[string]any{"recipients": list, "withoutRecipients": none, "files": len(files)}
		if truncated {
			out["truncated"] = true
		}
		return sdk.JSON(out)

	case "rules":
		r, err := in.open()
		if err != nil {
			return sdk.Result{}, err
		}
		defer r.Close()
		var b []byte
		name := ""
		for _, n := range []string{".sops.yaml", ".sops.yml"} {
			if b, _, err = read(r, n); err == nil {
				name = n
				break
			}
		}
		if name == "" {
			return sdk.Result{}, errors.New("the folder has no .sops.yaml")
		}
		docs, err := parseYAML(b, newLimits(ctx, fileTime))
		if err != nil || len(docs) == 0 {
			return sdk.Result{}, fmt.Errorf("%s isn't YAML this module can read", name)
		}
		d, _ := docs[0].(ymap)
		rules := []map[string]any{}
		list, _ := d["creation_rules"].([]any)
		for _, e := range list {
			em, ok := e.(ymap)
			if !ok {
				continue
			}
			rule := map[string]any{}
			for _, k := range []string{"path_regex", "filename_regex", "age", "pgp", "kms", "gcp_kms", "azure_keyvault", "hc_vault_transit_uri", "aws_profile",
				"encrypted_regex", "unencrypted_regex", "encrypted_suffix", "unencrypted_suffix", "encrypted_comment_regex", "unencrypted_comment_regex", "mac_only_encrypted", "shamir_threshold"} {
				switch v := em[k].(type) {
				case string:
					if s := strings.TrimSpace(v); s != "" {
						rule[k] = s
					}
				case []any:
					var ss []string
					for _, x := range v {
						if s := str(x); s != "" {
							ss = append(ss, s)
						}
					}
					if len(ss) > 0 {
						rule[k] = strings.Join(ss, ",")
					}
				}
			}
			if kg, ok := em["key_groups"].([]any); ok {
				groups := [][]recipient{}
				for i, g := range kg {
					if gm, ok := g.(ymap); ok {
						n := i
						groups = append(groups, recipients(gm, &n))
					}
				}
				rule["key_groups"] = groups
			}
			rules = append(rules, rule)
		}
		return sdk.JSON(map[string]any{"file": name, "creationRules": rules})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
