// Package notes keeps Markdown notes in a folder, so people and agents can
// write things down: runbooks, findings, to-dos. Every change can be undone.
package notes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// InstanceID is the single notes instance.
const InstanceID = "notes"

const maxNote = 1 << 20

// Config is the notes settings.
type Config struct {
	Folder string `json:"folder"` // default: <data>/notes
}

// Module implements sdk.Module.
type Module struct {
	Default string // folder used when none is configured
	mu      sync.Mutex
	dir     string
}

// New returns the notes module storing in defaultDir unless configured.
func New(defaultDir string) *Module { return &Module{Default: defaultDir} }

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	name := `"name":{"type":"string","description":"e.g. runbooks/db-failover (\".md\" is added)"}`
	return sdk.Manifest{
		ID: "notes", Name: "Notes", Version: "0.1.0", Category: "Productivity", Icon: "note",
		Description: "Markdown notes in a folder on this computer, for you and your agents. Every change can be undone.",
		Presets:     []string{"developer", "gamer", "homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"folder":{"type":"string","description":"Folder for the notes; any existing folder of .md files works (an Obsidian vault, say)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "list", Title: "All notes", Risk: sdk.RiskRead},
			{Name: "read", Title: "Read a note", Risk: sdk.RiskRead, Input: sdk.Schema(`{"type":"object","required":["name"],"properties":{` + name + `}}`)},
			{Name: "search", Title: "Search notes", Risk: sdk.RiskRead, Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string"}}}`)},
			{Name: "write", Title: "Write a note", Description: "Creates or replaces a note.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["name","content"],"properties":{` + name + `,"content":{"type":"string","format":"textarea"}}}`)},
			{Name: "append", Title: "Add to a note", Description: "Appends a line or section; creates the note if needed.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["name","text"],"properties":{` + name + `,"text":{"type":"string","format":"textarea"}}}`)},
			{Name: "delete", Title: "Delete a note", Risk: sdk.RiskDestructive, Reversible: true, Input: sdk.Schema(`{"type":"object","required":["name"],"properties":{` + name + `}}`)},
			{Name: "restore", Title: "Restore a note", Description: "Puts back an earlier version (used by undo).", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["name"],"properties":{` + name + `,"content":{"type":"string"},"absent":{"type":"boolean"}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "note", Title: "Notes", ListAction: "list", GetAction: "read", ViewHint: "table"}},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, _ sdk.Host, _ string, raw json.RawMessage) error {
	var c Config
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("invalid settings: %w", err)
		}
	}
	dir := c.Folder
	if dir == "" {
		dir = m.Default
	}
	if dir == "" {
		return errors.New("choose a folder for notes")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("can't use %s: %w", dir, err)
	}
	m.mu.Lock()
	m.dir = dir
	m.mu.Unlock()
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(string) error { return nil }

// Health implements sdk.Module.
func (m *Module) Health(context.Context, string) sdk.Health {
	d := m.folder()
	if d == "" {
		return sdk.Health{Status: "unconfigured", Message: "No folder"}
	}
	n := 0
	_ = filepath.WalkDir(d, func(_ string, e fs.DirEntry, err error) error {
		if err == nil && !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			n++
		}
		return nil
	})
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d notes", n)}
}

func (m *Module) folder() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dir
}

var nameRe = regexp.MustCompile(`^[\p{L}\p{N} _.,()'&+-]+(/[\p{L}\p{N} _.,()'&+-]+)*$`)

// path resolves a note name inside the folder; it never leaves it.
func (m *Module) path(name string) (string, string, error) {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, "/") || strings.Contains(name, `\`) {
		return "", "", fmt.Errorf("%q isn't a usable note name; use names like runbooks/db", name)
	}
	name = strings.TrimSuffix(strings.TrimRight(name, "/"), ".md")
	if name == "" || !nameRe.MatchString(name) || strings.Contains(name, "..") || strings.HasPrefix(name, ".") {
		return "", "", fmt.Errorf("%q isn't a usable note name", name)
	}
	d := m.folder()
	if d == "" {
		return "", "", errors.New("notes aren't set up")
	}
	return filepath.Join(d, filepath.FromSlash(name)+".md"), name, nil
}

// Note is a note listing row.
type Note struct {
	Name     string `json:"name"`
	Title    string `json:"title"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
}

func title(content, name string) string {
	for _, l := range strings.Split(content, "\n") {
		if t := strings.TrimSpace(strings.TrimLeft(l, "#")); strings.HasPrefix(l, "#") && t != "" {
			return t
		}
	}
	return filepath.Base(name)
}

func (m *Module) all() ([]Note, map[string]string, error) {
	d := m.folder()
	out := []Note{}
	bodies := map[string]string{}
	err := filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if e.IsDir() && strings.HasPrefix(e.Name(), ".") && p != d {
			return filepath.SkipDir // .obsidian, .git, .trash
		}
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			return nil
		}
		info, err := e.Info()
		if err != nil || info.Size() > maxNote {
			return nil
		}
		rel, _ := filepath.Rel(d, p)
		name := strings.TrimSuffix(filepath.ToSlash(rel), ".md")
		b, _ := os.ReadFile(p)
		bodies[name] = string(b)
		out = append(out, Note{Name: name, Title: title(string(b), name), Size: info.Size(), Modified: info.ModTime().UTC().Format(time.RFC3339)})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Modified > out[j].Modified })
	return out, bodies, err
}

// prior captures a note's state for undo.
func prior(path, name string) map[string]any {
	b, err := os.ReadFile(path)
	if err != nil {
		return map[string]any{"name": name, "absent": true}
	}
	return map[string]any{"name": name, "content": string(b)}
}

func save(path, content string) error {
	if len(content) > maxNote {
		return errors.New("a note can be at most 1 MiB")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(_ context.Context, c sdk.Call) (sdk.Result, error) {
	var p struct {
		Name    string `json:"name"`
		Content string `json:"content"`
		Text    string `json:"text"`
		Query   string `json:"query"`
		Absent  bool   `json:"absent"`
	}
	if err := sdk.Decode(c, &p); err != nil {
		return sdk.Result{}, err
	}
	switch c.Action {
	case "list":
		ns, _, err := m.all()
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(ns)
	case "search":
		q := strings.ToLower(strings.TrimSpace(p.Query))
		if q == "" {
			return sdk.Result{}, errors.New("search for something")
		}
		ns, bodies, err := m.all()
		if err != nil {
			return sdk.Result{}, err
		}
		type hit struct {
			Name    string `json:"name"`
			Title   string `json:"title"`
			Excerpt string `json:"excerpt"`
		}
		out := []hit{}
		for _, n := range ns {
			b := bodies[n.Name]
			i := strings.Index(strings.ToLower(b), q)
			if i < 0 && !strings.Contains(strings.ToLower(n.Name), q) {
				continue
			}
			ex := ""
			if i >= 0 {
				s, e := max(0, i-60), min(len(b), i+len(q)+60)
				ex = strings.Join(strings.Fields(b[s:e]), " ")
			}
			out = append(out, hit{Name: n.Name, Title: n.Title, Excerpt: ex})
		}
		return sdk.JSON(out)
	}

	path, name, err := m.path(p.Name)
	if err != nil {
		return sdk.Result{}, err
	}
	switch c.Action {
	case "read":
		b, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			return sdk.Result{}, fmt.Errorf("there's no note %s", name)
		}
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"name": name, "content": string(b)})

	case "write", "append":
		before := prior(path, name)
		content := p.Content
		if c.Action == "append" {
			old, _ := before["content"].(string)
			if strings.TrimSpace(p.Text) == "" {
				return sdk.Result{}, errors.New("nothing to add")
			}
			if old != "" && !strings.HasSuffix(old, "\n") {
				old += "\n"
			}
			content = old + p.Text
			if !strings.HasSuffix(content, "\n") {
				content += "\n"
			}
		}
		if err := save(path, content); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"name": name, "size": len(content)})
		desc := "Restore the previous " + name
		if before["absent"] == true {
			desc = "Remove " + name
		}
		r.Undo = sdk.UndoWith("restore", before, desc)
		return r, nil

	case "delete":
		before := prior(path, name)
		if before["absent"] == true {
			return sdk.Result{}, fmt.Errorf("there's no note %s", name)
		}
		if err := os.Remove(path); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"deleted": name})
		r.Undo = sdk.UndoWith("restore", before, "Bring back "+name)
		return r, nil

	case "restore":
		before := prior(path, name)
		if p.Absent {
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return sdk.Result{}, err
			}
		} else if err := save(path, p.Content); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"restored": name})
		r.Undo = sdk.UndoWith("restore", before, "Redo the change to "+name)
		return r, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}
