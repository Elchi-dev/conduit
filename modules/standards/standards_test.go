package standards

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

func newModule(t *testing.T) (*Module, string) {
	t.Helper()
	dir := t.TempDir()
	m := New(dir)
	if err := m.Configure(context.Background(), nil, InstanceID, nil); err != nil {
		t.Fatal(err)
	}
	return m, dir
}

func call(t *testing.T, m *Module, action string, in any, dry ...bool) sdk.Result {
	t.Helper()
	r, err := try(m, action, in, dry...)
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	return r
}

func try(m *Module, action string, in any, dry ...bool) (sdk.Result, error) {
	b, _ := json.Marshal(in)
	return m.Invoke(context.Background(), sdk.Call{Instance: InstanceID, Action: action, Input: b, DryRun: len(dry) > 0 && dry[0]})
}

func undo(t *testing.T, m *Module, r sdk.Result) sdk.Result {
	t.Helper()
	if r.Undo == nil {
		t.Fatal("no undo token")
	}
	out, err := m.Invoke(context.Background(), sdk.Call{Instance: InstanceID, Action: r.Undo.Action, Input: r.Undo.Input})
	if err != nil {
		t.Fatalf("undo: %v", err)
	}
	return out
}

func decode[T any](t *testing.T, r sdk.Result) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(r.Output, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

type forTaskOut struct {
	Matched []struct {
		ID       string   `json:"id"`
		Priority int      `json:"priority"`
		Reasons  []string `json:"reasons"`
	} `json:"matched"`
	Kinds    []string `json:"kinds"`
	Markdown string   `json:"markdown"`
}

func ids(o forTaskOut) []string {
	out := []string{}
	for _, m := range o.Matched {
		out = append(out, m.ID)
	}
	return out
}

func TestSeedsAreWrittenOnce(t *testing.T) {
	m, dir := newModule(t)
	l := decode[struct {
		Standards []Row     `json:"standards"`
		Toolkits  []Toolkit `json:"toolkits"`
	}](t, call(t, m, "list", nil))
	if len(l.Standards) != 5 || len(l.Toolkits) != 2 {
		t.Fatalf("seeded %d standards, %d toolkits", len(l.Standards), len(l.Toolkits))
	}
	if l.Standards[0].ID != "accessibility" {
		t.Fatalf("highest priority first, got %s", l.Standards[0].ID)
	}
	call(t, m, "delete", map[string]string{"id": "git-commits"})
	if err := m.Configure(context.Background(), nil, InstanceID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "standards", "git-commits.json")); !os.IsNotExist(err) {
		t.Fatal("a deleted starter came back")
	}
}

func TestForTaskMatching(t *testing.T) {
	m, _ := newModule(t)

	// A .tsx path pulls in the frontend standards, highest priority first.
	o := decode[forTaskOut](t, call(t, m, "for_task", Task{Task: "Add a settings panel", Paths: []string{"web/src/pages/Settings.tsx"}}))
	got := ids(o)
	if len(got) < 3 || got[0] != "accessibility" || got[1] != "frontend-design" {
		t.Fatalf("tsx task matched %v", got)
	}
	if strings.Contains(strings.Join(got, ","), "git-commits") {
		t.Fatalf("git standard matched a UI task: %v", got)
	}
	if !strings.Contains(o.Markdown, "## Required everywhere here") || !strings.Contains(o.Markdown, "accessible name") {
		t.Fatalf("MUST rules not hoisted:\n%s", o.Markdown)
	}
	if strings.Index(o.Markdown, "## Accessibility") > strings.Index(o.Markdown, "## Frontend design principles") {
		t.Fatal("merged brief isn't ordered by priority")
	}

	// Task kind from the words.
	o = decode[forTaskOut](t, call(t, m, "for_task", Task{Task: "Write the commit message for this change"}))
	if g := ids(o); len(g) == 0 || g[0] != "git-commits" {
		t.Fatalf("commit task matched %v", g)
	}
	// Task kind from a file name.
	o = decode[forTaskOut](t, call(t, m, "for_task", Task{Paths: []string{".git/COMMIT_EDITMSG"}}))
	if g := ids(o); len(g) != 1 || g[0] != "git-commits" {
		t.Fatalf("COMMIT_EDITMSG matched %v", g)
	}
	// Explicit kinds.
	o = decode[forTaskOut](t, call(t, m, "for_task", Task{Kinds: []string{"review"}}))
	if g := ids(o); len(g) != 1 || g[0] != "code-review" {
		t.Fatalf("review matched %v", g)
	}

	// Globs with folders, projects, and priority over the starters.
	call(t, m, "save", Standard{ID: "go-style", Title: "Go style", Category: "code", Priority: 95, Enabled: true,
		AppliesTo: []string{"internal/**/*.go"},
		Sections:  []Section{{Kind: "rules", Rules: []Rule{{Level: "must", Text: "Return errors, don't panic."}}}}})
	call(t, m, "save", Standard{ID: "acme-brand", Title: "Acme brand", Category: "design", Priority: 80, Enabled: true,
		AppliesTo: []string{"project:acme-*"}})
	call(t, m, "save", Standard{ID: "off", Title: "Switched off", Category: "code", Priority: 99, Enabled: false, AppliesTo: []string{"*"}})

	o = decode[forTaskOut](t, call(t, m, "for_task", Task{Task: "refactor", Paths: []string{"/repo/internal/ai/mcp.go"}, Project: "acme-web"}))
	g := ids(o)
	if len(g) < 2 || g[0] != "go-style" || g[1] != "acme-brand" {
		t.Fatalf("glob/project matched %v", g)
	}
	for _, id := range g {
		if id == "off" {
			t.Fatal("a disabled standard matched")
		}
	}
	o = decode[forTaskOut](t, call(t, m, "for_task", Task{Paths: []string{"cmd/main.go"}}))
	if strings.Contains(strings.Join(ids(o), ","), "go-style") {
		t.Fatal("internal/**/*.go matched cmd/main.go")
	}

	// A toolkit picks exactly its standards.
	o = decode[forTaskOut](t, call(t, m, "for_task", Task{Toolkit: "shipping-kit"}))
	if g := ids(o); !reflect.DeepEqual(g, []string{"code-review", "git-commits"}) {
		t.Fatalf("toolkit gave %v", g)
	}
	if _, err := try(m, "for_task", Task{Toolkit: "nope"}); err == nil {
		t.Fatal("unknown toolkit accepted")
	}
}

func TestGlobs(t *testing.T) {
	for _, c := range []struct {
		pat, path string
		want      bool
	}{
		{"*.tsx", "web/src/App.tsx", true},
		{"*.tsx", "web/src/App.ts", false},
		{".tsx", "App.tsx", true},
		{"src/**/*.go", "/x/src/a/b/c.go", true},
		{"src/**/*.go", "src/c.go", true},
		{"src/*.go", "src/a/c.go", false},
		{"*.{css,scss}", "a/b.scss", true},
		{"docs/*.md", "docs/README.md", true},
		{"docs/*.md", "web/docs/x.md", true},
		{"Dockerfile", "deploy/Dockerfile", true},
	} {
		if got := GlobMatch(c.pat, c.path); got != c.want {
			t.Errorf("GlobMatch(%q, %q) = %v", c.pat, c.path, got)
		}
	}
}

func tricky() Standard {
	return Standard{
		ID: "tricky", Title: "Tricky: quotes \"and\" colons", Icon: "code", Category: "code",
		Summary: "Has – unicode, `ticks` and a # hash", Tags: []string{"a, b", "c"}, AppliesTo: []string{"*.go", "project:x", "email"},
		Priority: 42, Enabled: false, Updated: "2026-11-04T10:00:00Z",
		Sections: []Section{
			{Kind: "principles", Title: "Beliefs", Items: []string{"One", "Two: with colon"}},
			{Kind: "dodont", Pairs: []Pair{{Do: "a"}, {Dont: "b"}, {Do: "c", Dont: "d"}}},
			{Kind: "rules", Rules: []Rule{{Level: "must", Text: "M", Why: "because: reasons"}, {Level: "may", Text: "Maybe"}}},
			{Kind: "examples", Examples: []Example{
				{Title: "Fences", Note: "Contains ``` inside", Lang: "md", Good: "```go\nx := 1\n```", Bad: "## not a heading\n<!-- section: rules -->"},
				{Good: "plain text only"},
			}},
			{Kind: "tokens", Groups: []TokenGroup{
				{Name: "Brand", Kind: "color", Tokens: []Token{{Key: "primary", Value: "#4f46e5", Note: "main — accent"}, {Key: "bg", Value: "rgb(0 0 0 / 50%)"}}},
				{Name: "Scale", Kind: "type", Tokens: []Token{{Key: "h1", Value: "32px / 1.2 / 700"}}},
			}},
			{Kind: "checklist", Items: []string{"[x] looks like a box", "done"}},
			{Kind: "references", Links: []Link{{Title: "Wiki [x]", URL: "https://en.wikipedia.org/wiki/Foo_(bar)", Note: "n"}, {Title: "Plain", URL: "https://example.com"}}},
			{Kind: "notes", Title: "Free notes", Markdown: "Some **notes**.\n\n---\n\n## A heading inside notes\n\n- list"},
		},
	}
}

func TestMarkdownRoundTrip(t *testing.T) {
	all := append(seedStandards(), tricky())
	for _, s := range all {
		if err := s.Normalize(); err != nil {
			t.Fatal(err)
		}
		md := ExportMarkdown(s)
		p, err := ParseMarkdown(md)
		if err != nil {
			t.Fatalf("%s: %v", s.ID, err)
		}
		if len(p.Standards) != 1 {
			t.Fatalf("%s: parsed %d standards", s.ID, len(p.Standards))
		}
		got := p.Standards[0]
		if err := got.Normalize(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, s) {
			a, _ := json.MarshalIndent(s, "", " ")
			b, _ := json.MarshalIndent(got, "", " ")
			t.Fatalf("%s did not survive Markdown:\nwant %s\ngot  %s\n---\n%s", s.ID, a, b, md)
		}
	}
}

func TestLibraryExportImport(t *testing.T) {
	m, _ := newModule(t)
	call(t, m, "save", tricky())
	for _, format := range []string{"markdown", "json"} {
		ex := decode[struct {
			Content  string `json:"content"`
			Filename string `json:"filename"`
		}](t, call(t, m, "export", map[string]string{"format": format}))
		m2, _ := newModule(t)
		for _, s := range seedStandards() {
			call(t, m2, "delete", map[string]string{"id": s.ID})
		}
		for _, k := range seedToolkits() {
			call(t, m2, "delete_toolkit", map[string]string{"id": k.ID})
		}
		plan := call(t, m2, "import", map[string]string{"content": ex.Content}, true)
		if plan.Plan == nil || len(plan.Plan.Changes) != 8 {
			t.Fatalf("%s: import preview %+v", format, plan.Plan)
		}
		imp := call(t, m2, "import", map[string]string{"content": ex.Content})
		ex2 := decode[struct {
			Content string `json:"content"`
		}](t, call(t, m2, "export", map[string]string{"format": format}))
		if ex2.Content != ex.Content {
			t.Fatalf("%s: library changed through export and import:\n%s\n---\n%s", format, ex.Content, ex2.Content)
		}
		undo(t, m2, imp)
		l := decode[struct {
			Standards []Row `json:"standards"`
		}](t, call(t, m2, "list", nil))
		if len(l.Standards) != 0 {
			t.Fatalf("%s: undo of import left %d standards", format, len(l.Standards))
		}
	}
	// A hand-written Markdown file without front matter or markers.
	p, err := ParseMarkdown("# House style\n\nShort and kind.\n\n## Rules\n\n- MUST: Be brief.\n- Avoid jargon.\n\n## Do and don't\n\n- Do: Use verbs\n- Don't: Shout\n\n## Background\n\nWhy we care.\n")
	if err != nil {
		t.Fatal(err)
	}
	s := p.Standards[0]
	if err := s.Normalize(); err != nil {
		t.Fatal(err)
	}
	if s.ID != "house-style" || s.Summary != "Short and kind." || len(s.Sections) != 3 ||
		s.Sections[0].Rules[0].Level != "must" || s.Sections[0].Rules[1].Level != "should" ||
		s.Sections[1].Pairs[0] != (Pair{Do: "Use verbs", Dont: "Shout"}) || s.Sections[2].Kind != "notes" || s.Sections[2].Title != "Background" {
		t.Fatalf("hand-written import: %+v", s)
	}
}

func TestSaveHistoryUndo(t *testing.T) {
	m, _ := newModule(t)
	base := Standard{Title: "Tone", Category: "writing", Priority: 50, Enabled: true,
		Sections: []Section{{Kind: "principles", Items: []string{"v1"}}}}

	created := call(t, m, "save", base)
	if decode[map[string]any](t, created)["id"] != "tone" {
		t.Fatal("id not made from the title")
	}
	base.ID = "tone"
	base.Sections[0].Items = []string{"v2"}
	plan := call(t, m, "save", base, true)
	if plan.Plan == nil || plan.Plan.Changes[0].Op != "update" || !strings.Contains(string(plan.Plan.Changes[0].Before), "v1") || !strings.Contains(string(plan.Plan.Changes[0].After), "v2") {
		t.Fatalf("preview %+v", plan.Plan)
	}
	updated := call(t, m, "save", base)
	get := func() string {
		return decode[map[string]string](t, call(t, m, "get", map[string]string{"id": "tone"}))["markdown"]
	}
	if !strings.Contains(get(), "- v2") {
		t.Fatal("save didn't save")
	}
	redo := undo(t, m, updated)
	if !strings.Contains(get(), "- v1") {
		t.Fatal("undo of save didn't restore v1")
	}
	undo(t, m, redo)
	if !strings.Contains(get(), "- v2") {
		t.Fatal("redo didn't bring v2 back")
	}

	deleted := call(t, m, "delete", map[string]string{"id": "tone"})
	if _, err := try(m, "get", map[string]string{"id": "tone"}); err == nil {
		t.Fatal("still there after delete")
	}
	undo(t, m, deleted)
	if !strings.Contains(get(), "- v2") {
		t.Fatal("undo of delete didn't bring it back")
	}
	undo(t, m, created)
	if _, err := try(m, "get", map[string]string{"id": "tone"}); err == nil {
		t.Fatal("undo of create didn't remove it")
	}

	// History keeps the last 20 versions, newest first, each readable and restorable.
	for i := range 25 {
		base.Sections[0].Items = []string{"rev " + string(rune('a'+i))}
		call(t, m, "save", base)
	}
	h := decode[struct {
		Versions []struct {
			Version string `json:"version"`
		} `json:"versions"`
	}](t, call(t, m, "history", map[string]string{"id": "tone"}))
	if len(h.Versions) != Keep {
		t.Fatalf("kept %d versions", len(h.Versions))
	}
	v := decode[struct {
		Markdown string `json:"markdown"`
	}](t, call(t, m, "history", map[string]string{"id": "tone", "version": h.Versions[0].Version}))
	if !strings.Contains(v.Markdown, "rev x") {
		t.Fatalf("newest kept version should be the one before the current one:\n%s", v.Markdown)
	}
	call(t, m, "restore", map[string]string{"id": "tone", "version": h.Versions[0].Version})
	if !strings.Contains(get(), "rev x") {
		t.Fatal("restore didn't restore")
	}

	// Bad input.
	for _, bad := range []any{
		Standard{Title: ""},
		Standard{ID: "../x", Title: "x"},
		Standard{Title: "x", Category: "nope"},
		Standard{Title: "x", Sections: []Section{{Kind: "rules", Rules: []Rule{{Level: "always", Text: "x"}}}}},
	} {
		if _, err := try(m, "save", bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if _, err := try(m, "save_toolkit", Toolkit{Title: "Kit", Standards: []string{"missing"}}); err == nil {
		t.Error("toolkit with an unknown standard accepted")
	}
}

func TestAgentContext(t *testing.T) {
	m, _ := newModule(t)
	call(t, m, "save", Standard{ID: "hidden", Title: "Hidden", Category: "custom", Enabled: false})
	spec := m.AgentContext(context.Background(), InstanceID)
	if !strings.Contains(spec.Instructions, "standards__for_task") {
		t.Fatal("instructions don't mention for_task")
	}
	uris := map[string]bool{}
	for _, r := range spec.Resources {
		uris[r.URI] = true
	}
	if !uris["conduit://standards/accessibility"] || uris["conduit://standards/hidden"] {
		t.Fatalf("resources %v", uris)
	}
	prompts := map[string]string{}
	for _, p := range spec.Prompts {
		prompts[p.Name] = p.Action
	}
	if prompts["frontend-kit"] != "toolkit" || prompts["shipping-kit"] != "toolkit" || prompts["for-task"] != "for_task" {
		t.Fatalf("prompts %v", prompts)
	}
	// Every action an agent context names is a read.
	reads := map[string]bool{}
	for _, a := range m.Manifest().Actions {
		reads[a.Name] = a.Risk == sdk.RiskRead
	}
	for _, p := range spec.Prompts {
		if !reads[p.Action] {
			t.Errorf("prompt %s uses %s", p.Name, p.Action)
		}
	}
	out := decode[map[string]any](t, call(t, m, "toolkit", map[string]string{"id": "frontend-kit", "task": "build a form"}))
	if md, _ := out["markdown"].(string); !strings.HasPrefix(md, "# Frontend kit: build a form") || !strings.Contains(md, "Writing for UI") {
		t.Fatalf("toolkit markdown:\n%s", md)
	}
}
