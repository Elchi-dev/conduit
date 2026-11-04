package standards

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Categories a standard can be filed under.
var Categories = []string{"frontend", "design", "writing", "code", "git", "review", "security", "product", "custom"}

// Section kinds, in the order the editor offers them.
var SectionKinds = []string{"principles", "dodont", "rules", "examples", "tokens", "checklist", "references", "notes"}

// Rule levels (RFC 2119).
var Levels = []string{"must", "should", "may"}

// Token group kinds; "color" groups get swatches, "type" a type-scale preview.
var TokenKinds = []string{"color", "type", "spacing", "radius", "shadow", "motion", "other"}

// Standard is one set of guidance an AI should follow.
type Standard struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Icon      string    `json:"icon,omitempty"`
	Category  string    `json:"category"`
	Summary   string    `json:"summary,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	AppliesTo []string  `json:"appliesTo,omitempty"`
	Priority  int       `json:"priority"`
	Enabled   bool      `json:"enabled"`
	Sections  []Section `json:"sections"`
	Updated   string    `json:"updated,omitempty"`
}

// Section is one block of a standard. Which fields are used depends on Kind.
type Section struct {
	Kind     string       `json:"kind"`
	Title    string       `json:"title,omitempty"`
	Items    []string     `json:"items,omitempty"`    // principles, checklist
	Pairs    []Pair       `json:"pairs,omitempty"`    // dodont
	Rules    []Rule       `json:"rules,omitempty"`    // rules
	Examples []Example    `json:"examples,omitempty"` // examples
	Groups   []TokenGroup `json:"groups,omitempty"`   // tokens
	Links    []Link       `json:"links,omitempty"`    // references
	Markdown string       `json:"markdown,omitempty"` // notes
}

// Pair is one Do / Don't row; either side may be empty.
type Pair struct {
	Do   string `json:"do,omitempty"`
	Dont string `json:"dont,omitempty"`
}

// Rule is one rule with its strength.
type Rule struct {
	Level string `json:"level"`
	Text  string `json:"text"`
	Why   string `json:"why,omitempty"`
}

// Example is a good / bad pair; Lang is a code language or empty for text.
type Example struct {
	Title string `json:"title,omitempty"`
	Note  string `json:"note,omitempty"`
	Lang  string `json:"lang,omitempty"`
	Good  string `json:"good,omitempty"`
	Bad   string `json:"bad,omitempty"`
}

// TokenGroup is a named set of design tokens.
type TokenGroup struct {
	Name   string  `json:"name"`
	Kind   string  `json:"kind"`
	Tokens []Token `json:"tokens"`
}

// Token is one key / value design token.
type Token struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
}

// Link is a reference.
type Link struct {
	Title string `json:"title"`
	URL   string `json:"url"`
	Note  string `json:"note,omitempty"`
}

// Toolkit bundles standards, e.g. "My frontend kit".
type Toolkit struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Icon      string   `json:"icon,omitempty"`
	Summary   string   `json:"summary,omitempty"`
	Standards []string `json:"standards"`
	Updated   string   `json:"updated,omitempty"`
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Slug turns a title into an id.
func Slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case r == 'ä':
			b.WriteString("ae")
		case r == 'ö':
			b.WriteString("oe")
		case r == 'ü':
			b.WriteString("ue")
		case r == 'ß':
			b.WriteString("ss")
		default:
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 64 {
		out = strings.Trim(out[:64], "-")
	}
	return out
}

func line(s string) string { return strings.Join(strings.Fields(s), " ") }

func lines(in []string) []string {
	out := []string{}
	for _, s := range in {
		if s = line(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func uniq(in []string) []string {
	out := []string{}
	for _, s := range lines(in) {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// Normalize cleans a standard in place and checks it. Single-line fields
// lose their line breaks so the Markdown form stays parseable.
func (s *Standard) Normalize() error {
	s.Title = line(s.Title)
	if s.Title == "" {
		return errors.New("give the standard a title")
	}
	if s.ID == "" {
		s.ID = Slug(s.Title)
	}
	if !idRe.MatchString(s.ID) {
		return fmt.Errorf("%q isn't a usable id; use lowercase letters, digits and dashes", s.ID)
	}
	s.Icon = line(s.Icon)
	s.Category = strings.ToLower(line(s.Category))
	if s.Category == "" {
		s.Category = "custom"
	}
	if !slices.Contains(Categories, s.Category) {
		return fmt.Errorf("unknown category %q (one of %s)", s.Category, strings.Join(Categories, ", "))
	}
	s.Summary = line(s.Summary)
	s.Tags = uniq(s.Tags)
	s.AppliesTo = uniq(s.AppliesTo)
	s.Priority = max(0, min(100, s.Priority))
	if s.Sections == nil {
		s.Sections = []Section{}
	}
	for i := range s.Sections {
		if err := s.Sections[i].normalize(); err != nil {
			return fmt.Errorf("section %d: %w", i+1, err)
		}
	}
	return nil
}

func (sec *Section) normalize() error {
	sec.Kind = strings.ToLower(line(sec.Kind))
	if !slices.Contains(SectionKinds, sec.Kind) {
		return fmt.Errorf("unknown section kind %q", sec.Kind)
	}
	sec.Title = line(sec.Title)
	if sec.Title == defaultTitle(sec.Kind) {
		sec.Title = ""
	}
	// Keep only the fields this kind uses.
	items, pairs, rules, exs, groups, links, md := sec.Items, sec.Pairs, sec.Rules, sec.Examples, sec.Groups, sec.Links, sec.Markdown
	*sec = Section{Kind: sec.Kind, Title: sec.Title}
	switch sec.Kind {
	case "principles", "checklist":
		sec.Items = lines(items)
	case "dodont":
		for _, p := range pairs {
			p.Do, p.Dont = line(p.Do), line(p.Dont)
			if p.Do != "" || p.Dont != "" {
				sec.Pairs = append(sec.Pairs, p)
			}
		}
	case "rules":
		for _, r := range rules {
			r.Level, r.Text, r.Why = strings.ToLower(line(r.Level)), line(r.Text), line(r.Why)
			if r.Text == "" {
				continue
			}
			if r.Level == "" {
				r.Level = "should"
			}
			if !slices.Contains(Levels, r.Level) {
				return fmt.Errorf("rule level %q must be must, should or may", r.Level)
			}
			sec.Rules = append(sec.Rules, r)
		}
	case "examples":
		for _, e := range exs {
			e.Title, e.Note, e.Lang = line(e.Title), line(e.Note), strings.ToLower(line(e.Lang))
			if e.Lang == "text" {
				e.Lang = ""
			}
			e.Good, e.Bad = strings.Trim(e.Good, "\n"), strings.Trim(e.Bad, "\n")
			if e.Good != "" || e.Bad != "" {
				sec.Examples = append(sec.Examples, e)
			}
		}
	case "tokens":
		for _, g := range groups {
			g.Name, g.Kind = line(g.Name), strings.ToLower(line(g.Kind))
			if g.Kind == "" {
				g.Kind = "other"
			}
			if !slices.Contains(TokenKinds, g.Kind) {
				g.Kind = "other"
			}
			if g.Name == "" {
				g.Name = strings.ToUpper(g.Kind[:1]) + g.Kind[1:]
			}
			toks := []Token{}
			for _, t := range g.Tokens {
				t.Key, t.Value, t.Note = line(strings.ReplaceAll(t.Key, "`", "")), line(strings.ReplaceAll(t.Value, "`", "'")), line(t.Note)
				if t.Key != "" {
					toks = append(toks, t)
				}
			}
			g.Tokens = toks
			sec.Groups = append(sec.Groups, g)
		}
	case "references":
		for _, l := range links {
			l.Title, l.URL, l.Note = line(l.Title), line(l.URL), line(l.Note)
			if l.URL == "" {
				continue
			}
			if l.Title == "" {
				l.Title = l.URL
			}
			sec.Links = append(sec.Links, l)
		}
	case "notes":
		sec.Markdown = strings.Trim(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	}
	return nil
}

// Normalize cleans a toolkit in place and checks it.
func (k *Toolkit) Normalize() error {
	k.Title = line(k.Title)
	if k.Title == "" {
		return errors.New("give the toolkit a title")
	}
	if k.ID == "" {
		k.ID = Slug(k.Title)
	}
	if !idRe.MatchString(k.ID) {
		return fmt.Errorf("%q isn't a usable id", k.ID)
	}
	k.Icon, k.Summary = line(k.Icon), line(k.Summary)
	k.Standards = uniq(k.Standards)
	return nil
}

func defaultTitle(kind string) string {
	switch kind {
	case "principles":
		return "Principles"
	case "dodont":
		return "Do and don't"
	case "rules":
		return "Rules"
	case "examples":
		return "Examples"
	case "tokens":
		return "Tokens"
	case "checklist":
		return "Checklist"
	case "references":
		return "References"
	case "notes":
		return "Notes"
	}
	return kind
}

// TitleOf is a section's heading.
func (sec Section) TitleOf() string {
	if sec.Title != "" {
		return sec.Title
	}
	return defaultTitle(sec.Kind)
}
