package standards

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
)

// Task describes work an AI is about to do (the for_task input).
type Task struct {
	Task    string   `json:"task"`
	Paths   []string `json:"paths"`
	Project string   `json:"project"`
	Kinds   []string `json:"kinds"`
	Toolkit string   `json:"toolkit"`
}

// Match is a standard that applies, with why.
type Match struct {
	Standard Standard `json:"standard"`
	Reasons  []string `json:"reasons"`
}

// kindWords are words in a task description that suggest a kind of task.
var kindWords = map[string][]string{
	"frontend":      {"frontend", "front end", "front-end", "ui", "ux", "react", "vue", "svelte", "angular", "css", "html", "tailwind", "component", "components", "page", "pages", "layout", "landing page", "dashboard", "website", "web app", "screen", "button", "form", "modal"},
	"design":        {"design", "visual", "colour", "color", "colors", "palette", "typography", "font", "fonts", "icon", "icons", "mockup", "figma", "theme", "dark mode", "styling"},
	"writing":       {"write", "writing", "copy", "copywriting", "microcopy", "text", "docs", "documentation", "blog", "article", "readme", "release notes", "announcement", "changelog", "wording", "tone"},
	"email":         {"email", "e-mail", "mail", "newsletter", "reply"},
	"code":          {"code", "coding", "implement", "refactor", "function", "bug", "fix", "feature", "api", "backend", "test", "tests", "script", "library", "endpoint"},
	"git":           {"git", "commit", "commits", "commit message", "branch", "rebase", "merge", "pull request", "pr", "changelog"},
	"review":        {"review", "code review", "pull request", "pr", "audit", "feedback"},
	"security":      {"security", "auth", "authentication", "password", "secret", "secrets", "token", "vulnerability", "crypto", "permissions", "xss", "csrf", "injection"},
	"accessibility": {"accessibility", "accessible", "a11y", "wcag", "screen reader", "aria", "keyboard", "contrast"},
	"product":       {"product", "spec", "roadmap", "prd", "user story", "requirements", "feature request"},
}

// extKinds maps file extensions to kinds of task.
var extKinds = map[string][]string{
	".tsx": {"frontend", "code"}, ".jsx": {"frontend", "code"}, ".vue": {"frontend", "code"}, ".svelte": {"frontend", "code"},
	".css": {"frontend", "design"}, ".scss": {"frontend", "design"}, ".less": {"frontend", "design"}, ".html": {"frontend"},
	".svg": {"design"}, ".fig": {"design"},
	".ts": {"code"}, ".js": {"code"}, ".mjs": {"code"}, ".go": {"code"}, ".py": {"code"}, ".rs": {"code"}, ".java": {"code"},
	".kt": {"code"}, ".swift": {"code"}, ".rb": {"code"}, ".php": {"code"}, ".c": {"code"}, ".h": {"code"}, ".cpp": {"code"},
	".cs": {"code"}, ".sh": {"code"}, ".sql": {"code"},
	".md": {"writing"}, ".mdx": {"writing", "frontend"}, ".txt": {"writing"}, ".eml": {"email", "writing"},
}

var nonWord = regexp.MustCompile(`[^\p{L}\p{N}]+`)

func words(s string) string {
	return " " + strings.TrimSpace(nonWord.ReplaceAllString(strings.ToLower(s), " ")) + " "
}

func hasPhrase(text, phrase string) bool {
	p := strings.TrimSpace(words(phrase))
	return p != "" && strings.Contains(text, " "+p+" ")
}

// inferKinds guesses what kinds of task this is from its words and paths.
func inferKinds(t Task) []string {
	kinds := []string{}
	add := func(k string) {
		k = strings.ToLower(strings.TrimSpace(k))
		if k != "" && !slices.Contains(kinds, k) {
			kinds = append(kinds, k)
		}
	}
	for _, k := range t.Kinds {
		add(k)
	}
	text := words(t.Task)
	for k, ws := range kindWords {
		for _, w := range ws {
			if hasPhrase(text, w) {
				add(k)
				break
			}
		}
	}
	for _, p := range t.Paths {
		base := path.Base(strings.ReplaceAll(p, `\`, "/"))
		if base == "COMMIT_EDITMSG" {
			add("git")
		}
		for _, k := range extKinds[strings.ToLower(path.Ext(base))] {
			add(k)
		}
	}
	slices.Sort(kinds)
	return kinds
}

// globRe compiles a path glob: ** crosses folders, * and ? don't, {a,b}
// alternates. A pattern without a slash matches the file name; one with a
// slash matches the end of the path.
func globRe(pat string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString(`(?i)(^|/)`)
	pat = strings.TrimPrefix(pat, "./")
	depth := 0
	for i := 0; i < len(pat); i++ {
		c := pat[i]
		switch c {
		case '*':
			if i+1 < len(pat) && pat[i+1] == '*' {
				i++
				if i+1 < len(pat) && pat[i+1] == '/' {
					i++
					b.WriteString(`(.*/)?`)
				} else {
					b.WriteString(`.*`)
				}
			} else {
				b.WriteString(`[^/]*`)
			}
		case '?':
			b.WriteString(`[^/]`)
		case '{':
			depth++
			b.WriteString(`(`)
		case '}':
			if depth > 0 {
				depth--
				b.WriteString(`)`)
			} else {
				b.WriteString(`\}`)
			}
		case ',':
			if depth > 0 {
				b.WriteString(`|`)
			} else {
				b.WriteString(`,`)
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(`$`)
	return regexp.Compile(b.String())
}

func isGlob(p string) bool {
	return strings.ContainsAny(p, "*?/{[") || strings.HasPrefix(p, ".")
}

// GlobMatch reports whether a path matches an applies-to glob.
func GlobMatch(pat, p string) bool {
	if strings.HasPrefix(pat, ".") && !strings.ContainsAny(pat, "*?/{") {
		pat = "*" + pat // ".tsx" means "*.tsx"
	}
	re, err := globRe(pat)
	if err != nil {
		return false
	}
	return re.MatchString(strings.ReplaceAll(p, `\`, "/"))
}

// matchOne reports why a standard applies to a task, or nil.
func matchOne(s Standard, t Task, kinds []string, text string) []string {
	var why []string
	if len(s.AppliesTo) == 0 {
		if slices.Contains(kinds, s.Category) {
			why = append(why, "category "+s.Category)
		}
		return why
	}
	for _, raw := range s.AppliesTo {
		p := strings.TrimSpace(raw)
		low := strings.ToLower(p)
		switch {
		case low == "*" || low == "always" || low == "all":
			why = append(why, "always")
		case strings.HasPrefix(low, "project:"):
			want := strings.TrimSpace(p[len("project:"):])
			if t.Project != "" && (strings.EqualFold(want, t.Project) || GlobMatch(want, t.Project)) {
				why = append(why, "project "+t.Project)
			}
		case strings.HasPrefix(low, "kind:"), strings.HasPrefix(low, "task:"):
			_, k, _ := strings.Cut(low, ":")
			k = strings.TrimSpace(k)
			if slices.Contains(kinds, k) || hasPhrase(text, k) {
				why = append(why, k+" task")
			}
		case strings.HasPrefix(low, "path:") || isGlob(p):
			g := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(p, "path:"), "PATH:"))
			for _, fp := range t.Paths {
				if GlobMatch(g, fp) {
					why = append(why, g+" ("+path.Base(strings.ReplaceAll(fp, `\`, "/"))+")")
					break
				}
			}
		default:
			switch {
			case slices.Contains(kinds, low):
				why = append(why, low+" task")
			case t.Project != "" && strings.EqualFold(p, t.Project):
				why = append(why, "project "+t.Project)
			case hasPhrase(text, p):
				why = append(why, "mentions \""+p+"\"")
			}
		}
	}
	return uniq(why)
}

// MatchTask returns the enabled standards that apply to a task, highest
// priority first. With a toolkit, every enabled standard in it applies.
func MatchTask(all []Standard, kits []Toolkit, t Task) ([]Match, []string, error) {
	kinds := inferKinds(t)
	text := words(t.Task + " " + t.Project)
	out := []Match{}
	var kit *Toolkit
	if t.Toolkit != "" {
		for i := range kits {
			if kits[i].ID == t.Toolkit || strings.EqualFold(kits[i].Title, t.Toolkit) {
				kit = &kits[i]
			}
		}
		if kit == nil {
			return nil, kinds, fmt.Errorf("there's no toolkit %q", t.Toolkit)
		}
	}
	for _, s := range all {
		if !s.Enabled {
			continue
		}
		var why []string
		if kit != nil {
			if !slices.Contains(kit.Standards, s.ID) {
				continue
			}
			why = append(why, "in "+kit.Title)
		} else {
			why = matchOne(s, t, kinds, text)
		}
		if len(why) > 0 {
			out = append(out, Match{Standard: s, Reasons: why})
		}
	}
	sortByPriority(out)
	return out, kinds, nil
}

func sortByPriority(ms []Match) {
	slices.SortStableFunc(ms, func(a, b Match) int {
		if a.Standard.Priority != b.Standard.Priority {
			return b.Standard.Priority - a.Standard.Priority
		}
		return strings.Compare(a.Standard.Title, b.Standard.Title)
	})
}

// Merge renders matched standards as one Markdown brief: the MUST rules of
// all of them first, then each standard by priority. Items repeated in a
// lower-priority standard are left out there.
func Merge(heading string, ms []Match) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", heading)
	if len(ms) == 0 {
		b.WriteString("No standards apply. Use your judgment, and ask the owner if a standard should exist for this kind of work.\n")
		return b.String()
	}
	b.WriteString("These are the owner's standards for this work. Follow them. They are listed by priority: where two disagree, the one listed first wins. MUST is required, SHOULD needs a good reason to break, MAY is optional.\n\n")
	for _, m := range ms {
		fmt.Fprintf(&b, "- **%s** (priority %d; %s)\n", m.Standard.Title, m.Standard.Priority, strings.Join(m.Reasons, ", "))
	}
	b.WriteString("\n")

	seen := map[string]bool{}
	key := func(kind, s string) string { return kind + "\x00" + strings.ToLower(s) }
	var musts []string
	for _, m := range ms {
		for _, sec := range m.Standard.Sections {
			for _, r := range sec.Rules {
				if r.Level == "must" && !seen[key("rule", r.Text)] {
					seen[key("rule", r.Text)] = true
					l := fmt.Sprintf("- **MUST** %s _(%s)_", r.Text, m.Standard.Title)
					if r.Why != "" {
						l += "\n  Why: " + r.Why
					}
					musts = append(musts, l)
				}
			}
		}
	}
	if len(musts) > 0 {
		b.WriteString("## Required everywhere here\n\n" + strings.Join(musts, "\n") + "\n\n")
	}
	for _, m := range ms {
		s := m.Standard
		secs := make([]Section, 0, len(s.Sections))
		for _, sec := range s.Sections {
			c := sec
			c.Items = nil
			for _, it := range sec.Items {
				if !seen[key(sec.Kind, it)] {
					seen[key(sec.Kind, it)] = true
					c.Items = append(c.Items, it)
				}
			}
			c.Pairs = nil
			for _, p := range sec.Pairs {
				if !seen[key("pair", p.Do+"|"+p.Dont)] {
					seen[key("pair", p.Do+"|"+p.Dont)] = true
					c.Pairs = append(c.Pairs, p)
				}
			}
			c.Rules = nil
			for _, r := range sec.Rules {
				if r.Level != "must" && !seen[key("rule", r.Text)] {
					seen[key("rule", r.Text)] = true
					c.Rules = append(c.Rules, r)
				}
			}
			secs = append(secs, c)
		}
		s.Sections = secs
		b.WriteString(render(s, renderOpts{level: 2}))
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}
