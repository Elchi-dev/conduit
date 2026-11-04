package standards

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// renderOpts controls how a standard becomes Markdown.
type renderOpts struct {
	level   int  // heading level of the standard's title (1 = "#")
	markers bool // write <!-- section: kind --> markers so it parses back
	meta    bool // write the category / priority / applies-to line
}

func hashes(n int) string { return strings.Repeat("#", min(n, 6)) }

// fence picks a code fence longer than any backtick run in s.
func fence(s string) string {
	run, best := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			best = max(best, run)
		} else {
			run = 0
		}
	}
	return strings.Repeat("`", max(3, best+1))
}

func escLink(s string) string { return strings.NewReplacer(`\`, `\\`, `]`, `\]`, `[`, `\[`).Replace(s) }

func linkURL(u string) string {
	if strings.ContainsAny(u, " ()<>") {
		return "<" + strings.NewReplacer("<", "%3C", ">", "%3E").Replace(u) + ">"
	}
	return u
}

// Render is the compact Markdown an AI follows (the get action).
func Render(s Standard) string {
	return render(s, renderOpts{level: 1, meta: true})
}

func render(s Standard, o renderOpts) string {
	var b strings.Builder
	h := o.level
	fmt.Fprintf(&b, "%s %s\n\n", hashes(h), s.Title)
	if o.meta {
		meta := []string{"Category: " + s.Category, "Priority: " + strconv.Itoa(s.Priority)}
		if len(s.AppliesTo) > 0 {
			meta = append(meta, "Applies to: "+strings.Join(s.AppliesTo, ", "))
		}
		if !s.Enabled {
			meta = append(meta, "Disabled")
		}
		fmt.Fprintf(&b, "_%s_\n\n", strings.Join(meta, " · "))
	}
	if s.Summary != "" {
		b.WriteString(s.Summary + "\n\n")
	}
	for _, sec := range s.Sections {
		if sectionEmpty(sec) && !o.markers {
			continue
		}
		fmt.Fprintf(&b, "%s %s\n", hashes(h+1), sec.TitleOf())
		if o.markers {
			fmt.Fprintf(&b, "<!-- section: %s -->\n", sec.Kind)
		}
		b.WriteString("\n")
		renderSection(&b, sec, h+2, o)
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func sectionEmpty(sec Section) bool {
	return len(sec.Items) == 0 && len(sec.Pairs) == 0 && len(sec.Rules) == 0 && len(sec.Examples) == 0 &&
		len(sec.Groups) == 0 && len(sec.Links) == 0 && strings.TrimSpace(sec.Markdown) == ""
}

func renderSection(b *strings.Builder, sec Section, h int, o renderOpts) {
	switch sec.Kind {
	case "principles":
		for _, it := range sec.Items {
			fmt.Fprintf(b, "- %s\n", it)
		}
	case "checklist":
		for _, it := range sec.Items {
			fmt.Fprintf(b, "- [ ] %s\n", it)
		}
	case "dodont":
		for _, p := range sec.Pairs {
			switch {
			case p.Do != "" && p.Dont != "":
				fmt.Fprintf(b, "- Do: %s\n  Don't: %s\n", p.Do, p.Dont)
			case p.Do != "":
				fmt.Fprintf(b, "- Do: %s\n", p.Do)
			default:
				fmt.Fprintf(b, "- Don't: %s\n", p.Dont)
			}
		}
	case "rules":
		for _, r := range sec.Rules {
			fmt.Fprintf(b, "- **%s** %s\n", strings.ToUpper(r.Level), r.Text)
			if r.Why != "" {
				fmt.Fprintf(b, "  Why: %s\n", r.Why)
			}
		}
	case "examples":
		for i, e := range sec.Examples {
			if i > 0 {
				b.WriteString("\n")
			}
			t := e.Title
			if t == "" {
				t = "Example"
			}
			fmt.Fprintf(b, "%s %s\n\n", hashes(h), t)
			if e.Note != "" {
				b.WriteString(e.Note + "\n\n")
			}
			lang := e.Lang
			if lang == "" {
				lang = "text"
			}
			for _, side := range []struct{ label, body string }{{"Good", e.Good}, {"Bad", e.Bad}} {
				if side.body == "" {
					continue
				}
				f := fence(side.body)
				fmt.Fprintf(b, "**%s**\n\n%s%s\n%s\n%s\n\n", side.label, f, lang, side.body, f)
			}
		}
	case "tokens":
		for i, g := range sec.Groups {
			if i > 0 {
				b.WriteString("\n")
			}
			if o.markers {
				fmt.Fprintf(b, "%s %s\n<!-- tokens: %s -->\n\n", hashes(h), g.Name, g.Kind)
			} else {
				fmt.Fprintf(b, "%s %s (%s)\n\n", hashes(h), g.Name, g.Kind)
			}
			for _, t := range g.Tokens {
				fmt.Fprintf(b, "- `%s`: `%s`", t.Key, t.Value)
				if t.Note != "" {
					fmt.Fprintf(b, " — %s", t.Note)
				}
				b.WriteString("\n")
			}
		}
	case "references":
		for _, l := range sec.Links {
			fmt.Fprintf(b, "- [%s](%s)", escLink(l.Title), linkURL(l.URL))
			if l.Note != "" {
				fmt.Fprintf(b, " — %s", l.Note)
			}
			b.WriteString("\n")
		}
	case "notes":
		if sec.Markdown != "" {
			b.WriteString(sec.Markdown + "\n")
		}
	}
	b.WriteString("\n")
}

// --- export -----------------------------------------------------------------

func fmValue(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimSpace(buf.String())
}

// ExportMarkdown writes a standard as Markdown with YAML front matter; it
// parses back to the same standard.
func ExportMarkdown(s Standard) string {
	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "id: %s\nkind: standard\n", s.ID)
	fmt.Fprintf(&b, "title: %s\n", fmValue(s.Title))
	if s.Icon != "" {
		fmt.Fprintf(&b, "icon: %s\n", fmValue(s.Icon))
	}
	fmt.Fprintf(&b, "category: %s\n", s.Category)
	if s.Summary != "" {
		fmt.Fprintf(&b, "summary: %s\n", fmValue(s.Summary))
	}
	fmt.Fprintf(&b, "tags: %s\n", fmValue(nonNil(s.Tags)))
	fmt.Fprintf(&b, "appliesTo: %s\n", fmValue(nonNil(s.AppliesTo)))
	fmt.Fprintf(&b, "priority: %d\nenabled: %t\n", s.Priority, s.Enabled)
	if s.Updated != "" {
		fmt.Fprintf(&b, "updated: %s\n", fmValue(s.Updated))
	}
	b.WriteString("---\n\n")
	b.WriteString(render(s, renderOpts{level: 1, markers: true}))
	return b.String()
}

// ExportToolkitMarkdown writes a toolkit as front matter plus its summary.
func ExportToolkitMarkdown(k Toolkit) string {
	var b strings.Builder
	fmt.Fprintf(&b, "---\nid: %s\nkind: toolkit\ntitle: %s\n", k.ID, fmValue(k.Title))
	if k.Icon != "" {
		fmt.Fprintf(&b, "icon: %s\n", fmValue(k.Icon))
	}
	fmt.Fprintf(&b, "standards: %s\n", fmValue(nonNil(k.Standards)))
	if k.Updated != "" {
		fmt.Fprintf(&b, "updated: %s\n", fmValue(k.Updated))
	}
	b.WriteString("---\n\n")
	fmt.Fprintf(&b, "# %s\n\n", k.Title)
	if k.Summary != "" {
		b.WriteString(k.Summary + "\n")
	}
	return b.String()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// --- import -----------------------------------------------------------------

var (
	markerRe   = regexp.MustCompile(`^<!--\s*section:\s*([a-z]+)\s*-->$`)
	tokMarker  = regexp.MustCompile(`^<!--\s*tokens:\s*([a-z]+)\s*-->$`)
	ruleRe     = regexp.MustCompile(`(?i)^(?:\*\*)?(must|should|may)(?:\*\*)?:?\s+(.+)$`)
	tokenRe    = regexp.MustCompile("^`([^`]*)`\\s*:\\s*`([^`]*)`(?:\\s+—\\s+(.*))?$")
	tokenLoose = regexp.MustCompile(`^([^:]+):\s*(.+?)(?:\s+—\s+(.*))?$`)
	linkRe     = regexp.MustCompile(`^\[((?:\\.|[^\]\\])*)\]\((<[^>]*>|.*?)\)(?:\s+—\s+(.*))?$`)
	fenceRe    = regexp.MustCompile("^(`{3,}|~{3,})\\s*([A-Za-z0-9_+.#-]*)\\s*$")
	groupKind  = regexp.MustCompile(`^(.*?)\s*\((color|type|spacing|radius|shadow|motion|other)\)$`)
	listRe     = regexp.MustCompile(`^(?:[-*+]|\d+[.)])\s+(.*)$`)
)

// Parsed is what an import found.
type Parsed struct {
	Standards []Standard
	Toolkits  []Toolkit
}

// ParseMarkdown reads one or more documents, each optionally starting with
// YAML front matter. A later document starts at a "---" line followed by an
// "id:" line. Documents without section markers are read by their "##"
// headings; unknown headings become notes.
func ParseMarkdown(src string) (Parsed, error) {
	src = strings.TrimPrefix(strings.ReplaceAll(src, "\r\n", "\n"), "\uFEFF")
	ls := strings.Split(src, "\n")
	first := 0
	for first < len(ls) && strings.TrimSpace(ls[first]) == "" {
		first++
	}
	var starts []int
	for i := first; i < len(ls); i++ {
		if strings.TrimSpace(ls[i]) != "---" {
			continue
		}
		if i == first || (i+1 < len(ls) && strings.HasPrefix(ls[i+1], "id:")) {
			starts = append(starts, i)
		}
	}
	if len(starts) == 0 || starts[0] != first {
		starts = append([]int{first}, starts...)
	}
	var out Parsed
	for n, st := range starts {
		end := len(ls)
		if n+1 < len(starts) {
			end = starts[n+1]
		}
		doc := ls[st:end]
		if len(strings.TrimSpace(strings.Join(doc, ""))) == 0 {
			continue
		}
		fm := map[string]any{}
		body := doc
		if strings.TrimSpace(doc[0]) == "---" {
			closeAt := -1
			for i := 1; i < len(doc); i++ {
				if strings.TrimSpace(doc[i]) == "---" {
					closeAt = i
					break
				}
			}
			if closeAt < 0 {
				return out, fmt.Errorf("document %d: front matter isn't closed with ---", n+1)
			}
			fm = parseFrontMatter(doc[1:closeAt])
			body = doc[closeAt+1:]
		}
		if str(fm["kind"]) == "toolkit" {
			k := Toolkit{ID: str(fm["id"]), Title: str(fm["title"]), Icon: str(fm["icon"]), Standards: list(fm["standards"]), Updated: str(fm["updated"])}
			k.Summary = str(fm["summary"])
			if k.Summary == "" {
				k.Summary = line(strings.Join(dropHeading(body), " "))
			}
			if k.Title == "" {
				k.Title = headingTitle(body)
			}
			out.Toolkits = append(out.Toolkits, k)
			continue
		}
		s := parseStandard(fm, body)
		out.Standards = append(out.Standards, s)
	}
	if len(out.Standards) == 0 && len(out.Toolkits) == 0 {
		return out, errors.New("nothing to import")
	}
	return out, nil
}

func dropHeading(body []string) []string {
	out := []string{}
	for _, l := range body {
		if !strings.HasPrefix(l, "# ") {
			out = append(out, l)
		}
	}
	return out
}

func headingTitle(body []string) string {
	for _, l := range body {
		if strings.HasPrefix(l, "# ") {
			return strings.TrimSpace(l[2:])
		}
	}
	return ""
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func list(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case string:
		if x == "" {
			return nil
		}
		return []string{x}
	}
	return nil
}

func unquote(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, `"`) {
		var s string
		if json.Unmarshal([]byte(v), &s) == nil {
			return s
		}
	}
	if len(v) >= 2 && strings.HasPrefix(v, "'") && strings.HasSuffix(v, "'") {
		return strings.ReplaceAll(v[1:len(v)-1], "''", "'")
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v
}

// parseFrontMatter reads the YAML subset Conduit writes and people write by
// hand: "key: scalar", "key: [a, b]" and block lists ("- a").
func parseFrontMatter(ls []string) map[string]any {
	fm := map[string]any{}
	var listKey string
	for _, l := range ls {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if listKey != "" && strings.HasPrefix(t, "- ") {
			fm[listKey] = append(list(fm[listKey]), unquote(t[2:]))
			continue
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		k = strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(k))
		listKey = ""
		switch {
		case v == "":
			listKey = k
			fm[k] = []string{}
		case strings.HasPrefix(v, "["):
			var arr []string
			if json.Unmarshal([]byte(v), &arr) != nil {
				arr = nil
				for _, p := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(v, "["), "]"), ",") {
					if p = unquote(p); p != "" {
						arr = append(arr, p)
					}
				}
			}
			fm[k] = arr
		default:
			fm[k] = unquote(v)
		}
	}
	return fm
}

func parseStandard(fm map[string]any, body []string) Standard {
	s := Standard{ID: str(fm["id"]), Title: str(fm["title"]), Icon: str(fm["icon"]), Category: str(fm["category"]),
		Summary: str(fm["summary"]), Tags: list(fm["tags"]), AppliesTo: list(fm["appliesto"]), Enabled: true, Updated: str(fm["updated"])}
	if p, err := strconv.Atoi(str(fm["priority"])); err == nil {
		s.Priority = p
	} else {
		s.Priority = 50
	}
	if e := strings.ToLower(str(fm["enabled"])); e == "false" || e == "no" {
		s.Enabled = false
	}
	marked := slices.ContainsFunc(body, func(l string) bool { return markerRe.MatchString(strings.TrimSpace(l)) })

	type chunk struct {
		kind, title string
		lines       []string
	}
	var chunks []chunk
	var preamble []string
	inFence := ""
	for i := 0; i < len(body); i++ {
		l := body[i]
		if f := fenceRe.FindStringSubmatch(strings.TrimSpace(l)); f != nil {
			switch {
			case inFence == "":
				inFence = f[1]
			case strings.TrimSpace(l) == inFence:
				inFence = ""
			}
		}
		if inFence == "" && strings.HasPrefix(l, "## ") {
			title := strings.TrimSpace(l[3:])
			if marked {
				if i+1 < len(body) {
					if m := markerRe.FindStringSubmatch(strings.TrimSpace(body[i+1])); m != nil {
						chunks = append(chunks, chunk{kind: m[1], title: title})
						i++
						continue
					}
				}
			} else {
				chunks = append(chunks, chunk{kind: guessKind(title), title: title})
				continue
			}
		}
		if len(chunks) == 0 {
			preamble = append(preamble, l)
		} else {
			chunks[len(chunks)-1].lines = append(chunks[len(chunks)-1].lines, l)
		}
	}
	// The preamble holds "# Title", the meta line and the summary.
	var loose []string
	for _, l := range preamble {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "# "):
			if s.Title == "" {
				s.Title = strings.TrimSpace(t[2:])
			}
		case t == "" || (strings.HasPrefix(t, "_") && strings.HasSuffix(t, "_") && strings.Contains(t, "Category:")):
		default:
			loose = append(loose, t)
		}
	}
	if s.Summary == "" && len(loose) > 0 {
		s.Summary = line(strings.Join(loose, " "))
	}
	for _, c := range chunks {
		sec := Section{Kind: c.kind, Title: c.title}
		if !slices.Contains(SectionKinds, sec.Kind) {
			sec.Kind = "notes"
		}
		parseSection(&sec, c.lines, marked)
		if sec.Title == defaultTitle(sec.Kind) {
			sec.Title = ""
		}
		s.Sections = append(s.Sections, sec)
	}
	if s.Sections == nil {
		s.Sections = []Section{}
	}
	return s
}

func guessKind(title string) string {
	t := strings.ToLower(strings.NewReplacer("’", "'", "&", "and", "/", " and ").Replace(title))
	t = strings.Join(strings.Fields(t), " ")
	switch t {
	case "principles", "guiding principles":
		return "principles"
	case "do and don't", "dos and don'ts", "do's and don'ts", "do and dont", "dos and donts":
		return "dodont"
	case "rules":
		return "rules"
	case "examples":
		return "examples"
	case "tokens", "design tokens":
		return "tokens"
	case "checklist":
		return "checklist"
	case "references", "links":
		return "references"
	}
	return "notes"
}

func bullet(l string) (string, bool) {
	m := listRe.FindStringSubmatch(strings.TrimSpace(l))
	if m == nil {
		return "", false
	}
	return m[1], true
}

func cutPrefixFold(s, p string) (string, bool) {
	if len(s) >= len(p) && strings.EqualFold(s[:len(p)], p) {
		return strings.TrimSpace(s[len(p):]), true
	}
	return s, false
}

// parseSection reads one section's lines. marked is true for Conduit's own
// export, where the layout is exact; hand-written files are read loosely.
func parseSection(sec *Section, ls []string, marked bool) {
	switch sec.Kind {
	case "principles":
		for _, l := range ls {
			if t, ok := bullet(l); ok {
				sec.Items = append(sec.Items, t)
			}
		}
	case "checklist":
		for _, l := range ls {
			if t, ok := bullet(l); ok {
				if marked {
					t = strings.TrimPrefix(t, "[ ] ")
				} else {
					for _, p := range []string{"[ ] ", "[x] ", "[X] "} {
						t = strings.TrimPrefix(t, p)
					}
				}
				sec.Items = append(sec.Items, t)
			}
		}
	case "dodont":
		for _, l := range ls {
			t := strings.TrimSpace(l)
			b, isBullet := bullet(l)
			if isBullet {
				t = b
			}
			t = strings.ReplaceAll(t, "’", "'")
			if v, ok := cutPrefixFold(t, "Do:"); ok {
				sec.Pairs = append(sec.Pairs, Pair{Do: v})
			} else if v, ok := cutPrefixFold(t, "Don't:"); ok {
				// In an export a pair's Don't is an indented continuation line
				// and "- Don't:" is a pair of its own; by hand, either pairs up.
				attach := !marked || !isBullet
				if n := len(sec.Pairs); attach && n > 0 && sec.Pairs[n-1].Do != "" && sec.Pairs[n-1].Dont == "" {
					sec.Pairs[n-1].Dont = v
				} else {
					sec.Pairs = append(sec.Pairs, Pair{Dont: v})
				}
			}
		}
	case "rules":
		for _, l := range ls {
			t := strings.TrimSpace(l)
			if v, ok := cutPrefixFold(t, "Why:"); ok && !strings.HasPrefix(t, "-") {
				if n := len(sec.Rules); n > 0 {
					sec.Rules[n-1].Why = v
				}
				continue
			}
			b, ok := bullet(l)
			if !ok {
				continue
			}
			if m := ruleRe.FindStringSubmatch(b); m != nil {
				sec.Rules = append(sec.Rules, Rule{Level: strings.ToLower(m[1]), Text: m[2]})
			} else {
				sec.Rules = append(sec.Rules, Rule{Level: "should", Text: b})
			}
		}
	case "examples":
		var cur *Example
		target := ""
		for i := 0; i < len(ls); i++ {
			t := strings.TrimSpace(ls[i])
			if strings.HasPrefix(t, "### ") {
				title := strings.TrimSpace(t[4:])
				if title == "Example" {
					title = ""
				}
				sec.Examples = append(sec.Examples, Example{Title: title})
				cur, target = &sec.Examples[len(sec.Examples)-1], ""
				continue
			}
			if cur == nil {
				if t == "" {
					continue
				}
				sec.Examples = append(sec.Examples, Example{})
				cur = &sec.Examples[len(sec.Examples)-1]
			}
			switch strings.ToLower(strings.Trim(t, "*_: ")) {
			case "good", "do":
				target = "good"
				continue
			case "bad", "don't", "avoid":
				target = "bad"
				continue
			}
			if m := fenceRe.FindStringSubmatch(t); m != nil {
				var code []string
				j := i + 1
				for ; j < len(ls); j++ {
					if strings.TrimSpace(ls[j]) == m[1] {
						break
					}
					code = append(code, ls[j])
				}
				i = j
				if m[2] != "" && m[2] != "text" {
					cur.Lang = strings.ToLower(m[2])
				}
				body := strings.Join(code, "\n")
				if target == "bad" {
					cur.Bad = body
				} else {
					cur.Good = body
				}
				continue
			}
			if t != "" && target == "" {
				cur.Note = line(cur.Note + " " + t)
			}
		}
	case "tokens":
		var g *TokenGroup
		for _, l := range ls {
			t := strings.TrimSpace(l)
			if strings.HasPrefix(t, "### ") {
				name, kind := strings.TrimSpace(t[4:]), "other"
				if m := groupKind.FindStringSubmatch(name); m != nil {
					name, kind = m[1], m[2]
				}
				sec.Groups = append(sec.Groups, TokenGroup{Name: name, Kind: kind, Tokens: []Token{}})
				g = &sec.Groups[len(sec.Groups)-1]
				continue
			}
			if m := tokMarker.FindStringSubmatch(t); m != nil && g != nil {
				g.Kind = m[1]
				continue
			}
			b, ok := bullet(l)
			if !ok {
				continue
			}
			if g == nil {
				sec.Groups = append(sec.Groups, TokenGroup{Name: "Tokens", Kind: "other", Tokens: []Token{}})
				g = &sec.Groups[0]
			}
			if m := tokenRe.FindStringSubmatch(b); m != nil {
				g.Tokens = append(g.Tokens, Token{Key: m[1], Value: m[2], Note: m[3]})
			} else if m := tokenLoose.FindStringSubmatch(b); m != nil {
				g.Tokens = append(g.Tokens, Token{Key: strings.Trim(m[1], "` "), Value: strings.Trim(m[2], "` "), Note: m[3]})
			}
		}
	case "references":
		for _, l := range ls {
			b, ok := bullet(l)
			if !ok {
				continue
			}
			if m := linkRe.FindStringSubmatch(b); m != nil {
				u := m[2]
				if strings.HasPrefix(u, "<") {
					u = strings.NewReplacer("%3C", "<", "%3E", ">").Replace(strings.TrimSuffix(strings.TrimPrefix(u, "<"), ">"))
				}
				title := strings.NewReplacer(`\]`, `]`, `\[`, `[`, `\\`, `\`).Replace(m[1])
				sec.Links = append(sec.Links, Link{Title: title, URL: u, Note: m[3]})
			} else if strings.HasPrefix(b, "http") {
				sec.Links = append(sec.Links, Link{Title: b, URL: b})
			}
		}
	default:
		sec.Markdown = strings.Trim(strings.Join(ls, "\n"), "\n")
	}
}

// ParseJSON reads a standard, a list of standards, a toolkit or a whole
// library ({"standards": [...], "toolkits": [...]}).
func ParseJSON(src []byte) (Parsed, error) {
	var out Parsed
	src = bytes.TrimSpace(src)
	if len(src) > 0 && src[0] == '[' {
		if err := json.Unmarshal(src, &out.Standards); err != nil {
			return out, fmt.Errorf("not a list of standards: %w", err)
		}
		return out, nil
	}
	var probe struct {
		Standards []json.RawMessage `json:"standards"`
		Toolkits  []json.RawMessage `json:"toolkits"`
		Sections  json.RawMessage   `json:"sections"`
	}
	if err := json.Unmarshal(src, &probe); err != nil {
		return out, fmt.Errorf("not JSON: %w", err)
	}
	objects := len(probe.Standards) > 0 && bytes.HasPrefix(bytes.TrimSpace(probe.Standards[0]), []byte("{"))
	switch {
	case probe.Toolkits != nil || objects:
		var lib struct {
			Standards []Standard `json:"standards"`
			Toolkits  []Toolkit  `json:"toolkits"`
		}
		if err := json.Unmarshal(src, &lib); err != nil {
			return out, err
		}
		out.Standards, out.Toolkits = lib.Standards, lib.Toolkits
	case probe.Standards != nil && probe.Sections == nil:
		var k Toolkit
		if err := json.Unmarshal(src, &k); err != nil {
			return out, err
		}
		out.Toolkits = []Toolkit{k}
	default:
		s := Standard{Enabled: true, Priority: 50}
		if err := json.Unmarshal(src, &s); err != nil {
			return out, err
		}
		out.Standards = []Standard{s}
	}
	return out, nil
}
