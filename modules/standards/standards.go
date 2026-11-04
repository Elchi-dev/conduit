// Package standards keeps the owner's standards for AI work (how frontends
// should look, writing tone, code style, review checklists, commit rules,
// design tokens) and hands the right ones to every connected AI: as tools
// (for_task), as MCP resources and as one MCP prompt per toolkit.
package standards

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// InstanceID is the single standards instance.
const InstanceID = "standards"

// Config is the module's settings.
type Config struct {
	Folder string `json:"folder"` // default: <data>/standards
}

// Module implements sdk.Module and sdk.AgentContext.
type Module struct {
	Default string // folder used when none is configured

	mu sync.Mutex
	st *store
}

// New returns the module storing in defaultDir unless configured.
func New(defaultDir string) *Module { return &Module{Default: defaultDir} }

var (
	_ sdk.Module       = (*Module)(nil)
	_ sdk.AgentContext = (*Module)(nil)
)

const standardSchema = `{"type":"object","required":["title"],"properties":{
	"id":{"type":"string","description":"lowercase-with-dashes; made from the title when empty. Saving an existing id replaces it."},
	"title":{"type":"string"},
	"icon":{"type":"string","description":"palette, layout, type, pen, code, git, check, shield, eye, box, compass, book, sparkle, ruler, flag, heart, terminal, mail, star, layers, rocket, bolt"},
	"category":{"type":"string","enum":["frontend","design","writing","code","git","review","security","product","custom"]},
	"summary":{"type":"string"},
	"tags":{"type":"array","items":{"type":"string"}},
	"appliesTo":{"type":"array","items":{"type":"string"},"description":"Globs (*.tsx, src/**/*.go), project:<name>, or task kinds (frontend, email, writing, code, git, review, security, design, accessibility, product); * for always. Empty: applies when the task is of the standard's category."},
	"priority":{"type":"integer","minimum":0,"maximum":100,"default":50,"description":"Higher wins when standards disagree"},
	"enabled":{"type":"boolean","default":true},
	"sections":{"type":"array","description":"Ordered blocks. kind: principles|checklist (items), dodont (pairs {do,dont}), rules (rules {level: must|should|may, text, why}), examples (examples {title,note,lang,good,bad}), tokens (groups {name, kind: color|type|spacing|radius|shadow|motion|other, tokens [{key,value,note}]}), references (links {title,url,note}), notes (markdown).",
		"items":{"type":"object","required":["kind"],"properties":{"kind":{"type":"string"},"title":{"type":"string"}}}}}}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	id := `"id":{"type":"string"}`
	format := `"format":{"type":"string","enum":["markdown","json"],"default":"markdown"}`
	return sdk.Manifest{
		ID: "standards", Name: "Standards", Version: "0.1.0", Category: "Knowledge", Icon: "ruler",
		Description: "Your standards and toolkits for AI work: design, writing, code, commits, reviews. Every connected AI gets them.",
		Presets:     []string{"developer", "gamer", "homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"folder":{"type":"string","description":"Folder for the standards (one JSON file each, so it can be kept in git)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "for_task", Title: "Standards for a task", Risk: sdk.RiskRead,
				Description: "Call before frontend, design, writing, code, commit or review work: returns the owner's enabled standards that apply, merged by priority as Markdown to follow.",
				Input: sdk.Schema(`{"type":"object","properties":{
					"task":{"type":"string","description":"What you are about to do, in a sentence"},
					"paths":{"type":"array","items":{"type":"string"},"description":"Files you will touch"},
					"project":{"type":"string","description":"Project or repository name"},
					"kinds":{"type":"array","items":{"type":"string"},"description":"Optional: frontend, design, writing, email, code, git, review, security, accessibility, product"},
					"toolkit":{"type":"string","description":"Optional: use exactly this toolkit's standards"}}}`)},
			{Name: "list", Title: "All standards", Description: "Standards and toolkits, highest priority first.", Risk: sdk.RiskRead},
			{Name: "get", Title: "Read a standard", Description: "A standard as compact Markdown to follow; format full also returns its structure (to edit and save it).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `,"format":{"type":"string","enum":["markdown","full"],"default":"markdown"}}}`)},
			{Name: "search", Title: "Search standards", Risk: sdk.RiskRead, Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string"}}}`)},
			{Name: "toolkit", Title: "Toolkit", Description: "A toolkit's standards merged as Markdown; without an id, all toolkits.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + id + `,"task":{"type":"string"}}}`)},
			{Name: "history", Title: "Versions", Description: "Earlier versions (the last 20); with a version, that version.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `,"kind":{"type":"string","enum":["standard","toolkit"],"default":"standard"},"version":{"type":"string"}}}`)},
			{Name: "export", Title: "Export", Description: "One standard, one toolkit or the whole library as Markdown with front matter, or as JSON.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + id + `,"toolkit":{"type":"string"},` + format + `}}`)},
			{Name: "save", Title: "Save a standard", Description: "Creates or replaces a standard (send all of it; get it with format full first). Undo restores the previous version.",
				Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(standardSchema)},
			{Name: "save_toolkit", Title: "Save a toolkit", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["title"],"properties":{` + id + `,"title":{"type":"string"},"icon":{"type":"string"},"summary":{"type":"string"},"standards":{"type":"array","items":{"type":"string"}}}}`)},
			{Name: "import", Title: "Import", Description: "Markdown (one or more documents with front matter) or JSON (a standard, a list, or a library). Existing ids are replaced; undo puts them back.",
				Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["content"],"properties":{"content":{"type":"string","format":"textarea","x-multiline":true},"format":{"type":"string","enum":["auto","markdown","json"],"default":"auto"}}}`)},
			{Name: "delete", Title: "Delete a standard", Risk: sdk.RiskDestructive, Reversible: true, Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `}}`)},
			{Name: "delete_toolkit", Title: "Delete a toolkit", Risk: sdk.RiskDestructive, Reversible: true, Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `}}`)},
			{Name: "restore", Title: "Restore a version", Description: "Puts back an earlier version (also used by undo).", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + id + `,"kind":{"type":"string","enum":["standard","toolkit"]},"version":{"type":"string"},
					"steps":{"type":"array","items":{"type":"object","properties":{"kind":{"type":"string"},"id":{"type":"string"},"version":{"type":"string"},"absent":{"type":"boolean"}}}}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "standard", Title: "Standards", ListAction: "list", GetAction: "get", ViewHint: "detail"}},
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
		return errors.New("choose a folder for standards")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("can't use %s: %w", dir, err)
	}
	st := &store{dir: dir}
	if err := seed(st); err != nil {
		return err
	}
	m.mu.Lock()
	m.st = st
	m.mu.Unlock()
	return nil
}

// seed writes the starter standards into a library that never had any.
func seed(st *store) error {
	marker := filepath.Join(st.dir, ".seeded")
	if _, err := os.Stat(marker); err == nil {
		return nil
	}
	if have, _ := st.all(kStandard); len(have) == 0 {
		now := time.Now().UTC().Format(time.RFC3339)
		for _, s := range seedStandards() {
			if err := s.Normalize(); err != nil {
				return fmt.Errorf("starter %s: %w", s.ID, err)
			}
			s.Updated = now
			if _, err := st.put(kStandard, s.ID, s); err != nil {
				return err
			}
		}
		for _, k := range seedToolkits() {
			_ = k.Normalize()
			k.Updated = now
			if _, err := st.put(kToolkit, k.ID, k); err != nil {
				return err
			}
		}
	}
	return os.WriteFile(marker, []byte("Starter standards were written once; delete this file to get them again.\n"), 0o600)
}

// Close implements sdk.Module.
func (m *Module) Close(string) error { return nil }

// Health implements sdk.Module.
func (m *Module) Health(context.Context, string) sdk.Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil {
		return sdk.Health{Status: "unconfigured", Message: "No folder"}
	}
	ss, err := m.st.standards()
	if err != nil {
		return sdk.Health{Status: "degraded", Message: err.Error()}
	}
	ks, _ := m.st.toolkits()
	on := 0
	for _, s := range ss {
		if s.Enabled {
			on++
		}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d standards (%d on), %d toolkits", len(ss), on, len(ks))}
}

// AgentContext implements sdk.AgentContext: one resource per enabled
// standard, one prompt per toolkit, and a line for the MCP instructions.
func (m *Module) AgentContext(_ context.Context, _ string) sdk.AgentContextSpec {
	m.mu.Lock()
	defer m.mu.Unlock()
	spec := sdk.AgentContextSpec{
		Instructions: "The owner keeps standards for how work should be done (frontend design, accessibility, writing, code style, commits, reviews). " +
			"Before frontend, design, writing, code, commit or review work, call standards__for_task with the task, the file paths and the project, and follow what it returns; MUST rules are not optional. " +
			"Each standard is also a resource (conduit://standards/<id>), and each toolkit a prompt.",
	}
	if m.st == nil {
		return spec
	}
	ss, _ := m.st.standards()
	for _, s := range ss {
		if !s.Enabled {
			continue
		}
		in, _ := json.Marshal(map[string]string{"id": s.ID})
		spec.Resources = append(spec.Resources, sdk.AgentResource{
			URI: "conduit://standards/" + s.ID, Name: s.ID, Title: s.Title, Description: s.Summary,
			MimeType: "text/markdown", Action: "get", Input: in,
		})
	}
	spec.Prompts = append(spec.Prompts, sdk.AgentPrompt{
		Name: "for-task", Title: "Standards for a task", Description: "The owner's standards that apply to a task, merged by priority.",
		Arguments: []sdk.AgentPromptArgument{{Name: "task", Description: "What you're about to do", Required: true}, {Name: "project", Description: "Project or repository"}},
		Action:    "for_task",
	})
	ks, _ := m.st.toolkits()
	for _, k := range ks {
		in, _ := json.Marshal(map[string]string{"id": k.ID})
		desc := k.Summary
		if desc == "" {
			desc = "The " + k.Title + " standards, merged by priority."
		}
		spec.Prompts = append(spec.Prompts, sdk.AgentPrompt{
			Name: k.ID, Title: k.Title, Description: desc,
			Arguments: []sdk.AgentPromptArgument{{Name: "task", Description: "What you're about to do (optional)"}},
			Action:    "toolkit", Input: in,
		})
	}
	return spec
}

// Row is a standard in listings.
type Row struct {
	ID        string         `json:"id"`
	Title     string         `json:"title"`
	Icon      string         `json:"icon,omitempty"`
	Category  string         `json:"category"`
	Summary   string         `json:"summary,omitempty"`
	Tags      []string       `json:"tags"`
	AppliesTo []string       `json:"appliesTo"`
	Priority  int            `json:"priority"`
	Enabled   bool           `json:"enabled"`
	Updated   string         `json:"updated,omitempty"`
	Counts    map[string]int `json:"counts"`
}

func rowOf(s Standard) Row {
	c := map[string]int{}
	for _, sec := range s.Sections {
		c[sec.Kind] += len(sec.Items) + len(sec.Pairs) + len(sec.Rules) + len(sec.Examples) + len(sec.Links)
		for _, g := range sec.Groups {
			c[sec.Kind] += len(g.Tokens)
		}
		if sec.Kind == "notes" && sec.Markdown != "" {
			c[sec.Kind]++
		}
	}
	return Row{ID: s.ID, Title: s.Title, Icon: s.Icon, Category: s.Category, Summary: s.Summary, Tags: nonNil(s.Tags),
		AppliesTo: nonNil(s.AppliesTo), Priority: s.Priority, Enabled: s.Enabled, Updated: s.Updated, Counts: c}
}

type input struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Format  string `json:"format"`
	Query   string `json:"query"`
	Version string `json:"version"`
	Toolkit string `json:"toolkit"`
	Task    string `json:"task"`
	Content string `json:"content"`
	Steps   []Step `json:"steps"`
}

func undoOf(steps []Step, desc string) *sdk.Undo {
	return sdk.UndoWith("restore", map[string]any{"steps": steps}, desc)
}

func mdString(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(_ context.Context, c sdk.Call) (sdk.Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.st
	if st == nil {
		return sdk.Result{}, errors.New("standards aren't set up")
	}
	var p input
	switch c.Action {
	case "save", "save_toolkit", "for_task":
		// decoded below into their own shapes
	default:
		if err := sdk.Decode(c, &p); err != nil {
			return sdk.Result{}, err
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)

	switch c.Action {
	case "list":
		ss, err := st.standards()
		if err != nil {
			return sdk.Result{}, err
		}
		ks, _ := st.toolkits()
		rows := make([]Row, 0, len(ss))
		for _, s := range ss {
			rows = append(rows, rowOf(s))
		}
		return sdk.JSON(map[string]any{"standards": rows, "toolkits": ks})

	case "get":
		s, err := st.getStandard(p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"id": s.ID, "title": s.Title, "markdown": Render(s)}
		if p.Format == "full" || p.Format == "json" {
			out["standard"] = s
		}
		return sdk.JSON(out)

	case "for_task":
		var t Task
		if err := sdk.Decode(c, &t); err != nil {
			return sdk.Result{}, err
		}
		ss, err := st.standards()
		if err != nil {
			return sdk.Result{}, err
		}
		ks, _ := st.toolkits()
		ms, kinds, err := MatchTask(ss, ks, t)
		if err != nil {
			return sdk.Result{}, err
		}
		type hit struct {
			ID       string   `json:"id"`
			Title    string   `json:"title"`
			Priority int      `json:"priority"`
			Reasons  []string `json:"reasons"`
		}
		hits := []hit{}
		for _, mt := range ms {
			hits = append(hits, hit{mt.Standard.ID, mt.Standard.Title, mt.Standard.Priority, mt.Reasons})
		}
		return sdk.JSON(map[string]any{"matched": hits, "kinds": kinds, "markdown": Merge("Standards for this task", ms)})

	case "search":
		q := strings.ToLower(strings.TrimSpace(p.Query))
		if q == "" {
			return sdk.Result{}, errors.New("search for something")
		}
		ss, err := st.standards()
		if err != nil {
			return sdk.Result{}, err
		}
		type hit struct {
			ID      string `json:"id"`
			Title   string `json:"title"`
			Excerpt string `json:"excerpt"`
		}
		out := []hit{}
		for _, s := range ss {
			body := Render(s) + " " + strings.Join(s.Tags, " ")
			i := strings.Index(strings.ToLower(body), q)
			if i < 0 {
				continue
			}
			a, b := max(0, i-60), min(len(body), i+len(q)+60)
			out = append(out, hit{ID: s.ID, Title: s.Title, Excerpt: strings.Join(strings.Fields(body[a:b]), " ")})
		}
		return sdk.JSON(out)

	case "toolkit":
		ks, err := st.toolkits()
		if err != nil {
			return sdk.Result{}, err
		}
		if p.ID == "" {
			return sdk.JSON(ks)
		}
		ss, _ := st.standards()
		ms, _, err := MatchTask(ss, ks, Task{Toolkit: p.ID})
		if err != nil {
			return sdk.Result{}, err
		}
		k, _ := st.getToolkit(p.ID)
		heading := k.Title
		if p.Task != "" {
			heading += ": " + line(p.Task)
		}
		return sdk.JSON(map[string]any{"toolkit": k, "markdown": Merge(heading, ms)})

	case "history":
		kind := kStandard
		if p.Kind == "toolkit" {
			kind = kToolkit
		}
		if !idRe.MatchString(p.ID) {
			return sdk.Result{}, fmt.Errorf("%q isn't a usable id", p.ID)
		}
		if p.Version != "" {
			b, err := st.version(kind, p.ID, p.Version)
			if err != nil {
				return sdk.Result{}, err
			}
			out := map[string]any{"id": p.ID, "version": p.Version, "replacedAt": versionTime(p.Version)}
			if kind == kStandard {
				var s Standard
				if err := json.Unmarshal(b, &s); err != nil {
					return sdk.Result{}, err
				}
				out["standard"], out["markdown"] = s, Render(s)
			} else {
				var k Toolkit
				_ = json.Unmarshal(b, &k)
				out["toolkit"], out["markdown"] = k, ExportToolkitMarkdown(k)
			}
			return sdk.JSON(out)
		}
		vs, err := st.versions(kind, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		type ver struct {
			Version    string `json:"version"`
			ReplacedAt string `json:"replacedAt"`
			Updated    string `json:"updated,omitempty"`
			Title      string `json:"title"`
			Sections   int    `json:"sections"`
			Enabled    bool   `json:"enabled"`
		}
		list := []ver{}
		for _, v := range vs {
			b, err := st.version(kind, p.ID, v)
			if err != nil {
				continue
			}
			var s Standard
			_ = json.Unmarshal(b, &s)
			list = append(list, ver{Version: v, ReplacedAt: versionTime(v), Updated: s.Updated, Title: s.Title, Sections: len(s.Sections), Enabled: s.Enabled})
		}
		_, err = os.Stat(st.path(kind, p.ID))
		return sdk.JSON(map[string]any{"id": p.ID, "exists": err == nil, "versions": list})

	case "export":
		return m.export(st, p)

	case "save":
		s := Standard{Enabled: true, Priority: 50}
		if err := sdk.Decode(c, &s); err != nil {
			return sdk.Result{}, err
		}
		if err := s.Normalize(); err != nil {
			return sdk.Result{}, err
		}
		before, berr := st.getStandard(s.ID)
		exists := berr == nil
		s.Updated = now
		if c.DryRun {
			ch := sdk.Change{Target: "standard " + s.ID, Op: "create", After: mdString(Render(s))}
			if exists {
				ch.Op, ch.Before = "update", mdString(Render(before))
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s the standard %q", map[bool]string{true: "Update", false: "Create"}[exists], s.Title), Changes: []sdk.Change{ch}}}, nil
		}
		step, err := st.put(kStandard, s.ID, s)
		if err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"id": s.ID, "title": s.Title, "created": !exists, "updated": s.Updated})
		desc := "Restore the previous " + s.Title
		if !exists {
			desc = "Remove " + s.Title
		}
		r.Undo = undoOf([]Step{step}, desc)
		return r, nil

	case "save_toolkit":
		var k Toolkit
		if err := sdk.Decode(c, &k); err != nil {
			return sdk.Result{}, err
		}
		if err := k.Normalize(); err != nil {
			return sdk.Result{}, err
		}
		for _, id := range k.Standards {
			if _, err := st.getStandard(id); err != nil {
				return sdk.Result{}, err
			}
		}
		before, berr := st.getToolkit(k.ID)
		exists := berr == nil
		k.Updated = now
		if c.DryRun {
			ch := sdk.Change{Target: "toolkit " + k.ID, Op: "create", After: mdString(ExportToolkitMarkdown(k))}
			if exists {
				ch.Op, ch.Before = "update", mdString(ExportToolkitMarkdown(before))
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: "Save the toolkit " + k.Title, Changes: []sdk.Change{ch}}}, nil
		}
		step, err := st.put(kToolkit, k.ID, k)
		if err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"id": k.ID, "title": k.Title, "created": !exists})
		r.Undo = undoOf([]Step{step}, map[bool]string{true: "Restore the previous ", false: "Remove "}[exists]+k.Title)
		return r, nil

	case "delete", "delete_toolkit":
		kind, label := kStandard, ""
		if c.Action == "delete_toolkit" {
			kind = kToolkit
			k, err := st.getToolkit(p.ID)
			if err != nil {
				return sdk.Result{}, err
			}
			label = k.Title
		} else {
			s, err := st.getStandard(p.ID)
			if err != nil {
				return sdk.Result{}, err
			}
			label = s.Title
		}
		step, err := st.remove(kind, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"deleted": p.ID})
		r.Undo = undoOf([]Step{step}, "Bring back "+label)
		return r, nil

	case "import":
		return m.importAll(st, c, p, now)

	case "restore":
		steps := p.Steps
		if len(steps) == 0 {
			if p.ID == "" || p.Version == "" {
				return sdk.Result{}, errors.New("say which version to restore")
			}
			k := p.Kind
			if k == "" {
				k = "standard"
			}
			steps = []Step{{Kind: k, ID: p.ID, Version: p.Version}}
		}
		var back []Step
		for _, s := range steps {
			b, err := st.apply(s)
			if err != nil {
				return sdk.Result{}, err
			}
			back = append([]Step{b}, back...)
		}
		r, _ := sdk.JSON(map[string]any{"restored": len(steps)})
		r.Undo = undoOf(back, "Redo the change")
		return r, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}

func versionTime(v string) string {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return ""
	}
	return time.Unix(0, n).UTC().Format(time.RFC3339)
}

func (m *Module) export(st *store, p input) (sdk.Result, error) {
	format := p.Format
	if format == "" {
		format = "markdown"
	}
	if format != "markdown" && format != "json" {
		return sdk.Result{}, fmt.Errorf("format must be markdown or json")
	}
	var ss []Standard
	var ks []Toolkit
	name := "standards"
	switch {
	case p.ID != "":
		s, err := st.getStandard(p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		ss, name = []Standard{s}, s.ID
	case p.Toolkit != "":
		k, err := st.getToolkit(p.Toolkit)
		if err != nil {
			return sdk.Result{}, err
		}
		ks, name = []Toolkit{k}, k.ID
		for _, id := range k.Standards {
			if s, err := st.getStandard(id); err == nil {
				ss = append(ss, s)
			}
		}
	default:
		var err error
		if ss, err = st.standards(); err != nil {
			return sdk.Result{}, err
		}
		ks, _ = st.toolkits()
	}
	var content string
	if format == "json" {
		var v any = map[string]any{"version": 1, "standards": nonNilS(ss), "toolkits": nonNilK(ks)}
		if p.ID != "" {
			v = ss[0]
		}
		b, _ := json.MarshalIndent(v, "", "  ")
		content = string(b) + "\n"
		name += ".json"
	} else {
		var parts []string
		for _, s := range ss {
			parts = append(parts, ExportMarkdown(s))
		}
		for _, k := range ks {
			parts = append(parts, ExportToolkitMarkdown(k))
		}
		content = strings.Join(parts, "\n")
		name += ".md"
	}
	return sdk.JSON(map[string]any{"filename": name, "format": format, "content": content, "standards": len(ss), "toolkits": len(ks)})
}

func nonNilS(s []Standard) []Standard {
	if s == nil {
		return []Standard{}
	}
	return s
}

func nonNilK(k []Toolkit) []Toolkit {
	if k == nil {
		return []Toolkit{}
	}
	return k
}

func (m *Module) importAll(st *store, c sdk.Call, p input, now string) (sdk.Result, error) {
	if strings.TrimSpace(p.Content) == "" {
		return sdk.Result{}, errors.New("nothing to import")
	}
	format := p.Format
	if format == "" || format == "auto" {
		format = "markdown"
		if t := strings.TrimSpace(p.Content); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
			format = "json"
		}
	}
	var parsed Parsed
	var err error
	if format == "json" {
		parsed, err = ParseJSON([]byte(p.Content))
	} else {
		parsed, err = ParseMarkdown(p.Content)
	}
	if err != nil {
		return sdk.Result{}, err
	}
	known := map[string]bool{}
	if have, _ := st.standards(); have != nil {
		for _, s := range have {
			known[s.ID] = true
		}
	}
	for i := range parsed.Standards {
		if err := parsed.Standards[i].Normalize(); err != nil {
			return sdk.Result{}, fmt.Errorf("%s: %w", parsed.Standards[i].Title, err)
		}
		known[parsed.Standards[i].ID] = true
	}
	for i := range parsed.Toolkits {
		if err := parsed.Toolkits[i].Normalize(); err != nil {
			return sdk.Result{}, err
		}
		var keep []string
		for _, id := range parsed.Toolkits[i].Standards {
			if known[id] {
				keep = append(keep, id)
			}
		}
		parsed.Toolkits[i].Standards = nonNil(keep)
	}
	if c.DryRun {
		var ch []sdk.Change
		for _, s := range parsed.Standards {
			x := sdk.Change{Target: "standard " + s.ID, Op: "create", After: mdString(Render(s))}
			if b, err := st.getStandard(s.ID); err == nil {
				x.Op, x.Before = "update", mdString(Render(b))
			}
			ch = append(ch, x)
		}
		for _, k := range parsed.Toolkits {
			x := sdk.Change{Target: "toolkit " + k.ID, Op: "create", After: mdString(ExportToolkitMarkdown(k))}
			if b, err := st.getToolkit(k.ID); err == nil {
				x.Op, x.Before = "update", mdString(ExportToolkitMarkdown(b))
			}
			ch = append(ch, x)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Import %d standards and %d toolkits", len(parsed.Standards), len(parsed.Toolkits)), Changes: ch}}, nil
	}
	var steps []Step
	ids, kids := []string{}, []string{}
	fail := func(err error) (sdk.Result, error) {
		// Put back what was written before the failure.
		for i := len(steps) - 1; i >= 0; i-- {
			_, _ = st.apply(steps[i])
		}
		return sdk.Result{}, err
	}
	for _, s := range parsed.Standards {
		if s.Updated == "" {
			s.Updated = now
		}
		step, err := st.put(kStandard, s.ID, s)
		if err != nil {
			return fail(err)
		}
		steps = append(steps, step)
		ids = append(ids, s.ID)
	}
	for _, k := range parsed.Toolkits {
		if k.Updated == "" {
			k.Updated = now
		}
		step, err := st.put(kToolkit, k.ID, k)
		if err != nil {
			return fail(err)
		}
		steps = append(steps, step)
		kids = append(kids, k.ID)
	}
	rev := make([]Step, len(steps))
	for i, s := range steps {
		rev[len(steps)-1-i] = s
	}
	r, _ := sdk.JSON(map[string]any{"standards": ids, "toolkits": kids})
	r.Undo = undoOf(rev, fmt.Sprintf("Undo the import of %d standards and %d toolkits", len(ids), len(kids)))
	return r, nil
}
