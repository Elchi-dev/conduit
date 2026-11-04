package sops

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// A parsed document is a tree of map[string]any (with its keys' order in
// "\x00order"), []any and string. Only what SOPS writes needs to parse:
// block-style YAML, JSON, dotenv and INI. Values are kept only long enough
// to see whether they're ENC[…]; nothing here returns one.

const orderKey = "\x00order"

type ymap map[string]any

func (m ymap) set(k string, v any) {
	if _, ok := m[k]; !ok {
		ord, _ := m[orderKey].([]string)
		m[orderKey] = append(ord, k)
	}
	m[k] = v
}

func (m ymap) keys() []string {
	if ord, ok := m[orderKey].([]string); ok {
		return ord
	}
	var out []string
	for k := range m {
		if k != orderKey {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// --- YAML (the block subset SOPS emits) ---

type yline struct {
	indent int
	text   string // without indentation; "" for blank and comment lines
	raw    bool   // blank or comment
}

const maxDepth = 64

var errYAML = errors.New("not YAML this module can read")

func parseYAML(b []byte) ([]any, error) {
	var docs [][]yline
	var cur []yline
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := strings.TrimRight(sc.Text(), " \t\r")
		if l == "---" || strings.HasPrefix(l, "--- ") {
			docs = append(docs, cur)
			cur = nil
			continue
		}
		if l == "..." {
			continue
		}
		t := strings.TrimLeft(l, " ")
		if strings.HasPrefix(t, "\t") {
			return nil, errYAML
		}
		if t == "" || strings.HasPrefix(t, "#") {
			cur = append(cur, yline{indent: len(l) - len(t), raw: true})
			continue
		}
		cur = append(cur, yline{indent: len(l) - len(t), text: t})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	docs = append(docs, cur)
	var out []any
	for _, d := range docs {
		p := &yparser{lines: d}
		p.skip()
		if p.i >= len(p.lines) {
			continue
		}
		v, err := p.block(p.lines[p.i].indent, 0)
		if err != nil {
			return nil, err
		}
		p.skip()
		if p.i < len(p.lines) {
			return nil, fmt.Errorf("%w (unexpected indentation)", errYAML)
		}
		out = append(out, v)
	}
	return out, nil
}

type yparser struct {
	lines []yline
	i     int
}

func (p *yparser) skip() {
	for p.i < len(p.lines) && p.lines[p.i].raw {
		p.i++
	}
}

func isSeq(t string) bool { return t == "-" || strings.HasPrefix(t, "- ") }

// block parses the mapping or sequence whose lines start at indent.
func (p *yparser) block(indent, depth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("%w (nested too deep)", errYAML)
	}
	p.skip()
	if p.i >= len(p.lines) {
		return "", nil
	}
	if isSeq(p.lines[p.i].text) {
		return p.seq(indent, depth)
	}
	return p.mapping(indent, depth)
}

func (p *yparser) seq(indent, depth int) (any, error) {
	list := []any{}
	for {
		p.skip()
		if p.i >= len(p.lines) || p.lines[p.i].indent != indent || !isSeq(p.lines[p.i].text) {
			return list, nil
		}
		rest := strings.TrimPrefix(p.lines[p.i].text, "-")
		inner := strings.TrimLeft(rest, " ")
		if inner == "" {
			// "-" alone: the item is the block below.
			p.i++
			p.skip()
			if p.i < len(p.lines) && p.lines[p.i].indent > indent {
				v, err := p.block(p.lines[p.i].indent, depth+1)
				if err != nil {
					return nil, err
				}
				list = append(list, v)
			} else {
				list = append(list, "")
			}
			continue
		}
		// Rewrite "- x" as "x" one level in, so a mapping item's next keys
		// (indented under x) belong to it.
		sub := indent + 1 + (len(rest) - len(inner))
		if isSeq(inner) || isMapLine(inner) {
			p.lines[p.i] = yline{indent: sub, text: inner}
			v, err := p.block(sub, depth+1)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
			continue
		}
		v, err := p.scalarAt(indent, inner)
		if err != nil {
			return nil, err
		}
		list = append(list, v)
	}
}

var keyRe = regexp.MustCompile(`^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^"'#\s][^:]*?)\s*:(\s|$)`)

func isMapLine(t string) bool { return keyRe.MatchString(t) }

func (p *yparser) mapping(indent, depth int) (any, error) {
	m := ymap{}
	for {
		p.skip()
		if p.i >= len(p.lines) || p.lines[p.i].indent != indent {
			if p.i < len(p.lines) && p.lines[p.i].indent > indent {
				return nil, fmt.Errorf("%w (unexpected indentation)", errYAML)
			}
			return m, nil
		}
		t := p.lines[p.i].text
		loc := keyRe.FindStringSubmatchIndex(t)
		if loc == nil {
			if len(m) == 0 {
				// A lone scalar document.
				return p.scalarAt(indent-1, t)
			}
			return nil, fmt.Errorf("%w (expected key: value)", errYAML)
		}
		key := unquote(strings.TrimSpace(t[loc[2]:loc[3]]))
		rest := strings.TrimSpace(t[loc[1]:])
		if strings.HasPrefix(rest, "&") || strings.HasPrefix(rest, "!") {
			// Anchors and tags: drop the marker, keep what follows.
			if sp := strings.IndexByte(rest, ' '); sp > 0 {
				rest = strings.TrimSpace(rest[sp:])
			} else {
				rest = ""
			}
		}
		if rest == "" || strings.HasPrefix(rest, "#") {
			p.i++
			p.skip()
			switch {
			case p.i < len(p.lines) && p.lines[p.i].indent > indent:
				v, err := p.block(p.lines[p.i].indent, depth+1)
				if err != nil {
					return nil, err
				}
				m.set(key, v)
			case p.i < len(p.lines) && p.lines[p.i].indent == indent && isSeq(p.lines[p.i].text):
				// "key:" followed by "- item" at the same indentation.
				v, err := p.seq(indent, depth+1)
				if err != nil {
					return nil, err
				}
				m.set(key, v)
			default:
				m.set(key, "")
			}
			continue
		}
		v, err := p.scalarAt(indent, rest)
		if err != nil {
			return nil, err
		}
		m.set(key, v)
	}
}

// scalarAt reads the value after "key:" (or "- ") on the current line,
// with a block scalar's lines (indented beyond indent) when it's | or >.
func (p *yparser) scalarAt(indent int, v string) (any, error) {
	p.i++
	if strings.HasPrefix(v, "|") || strings.HasPrefix(v, ">") {
		var b strings.Builder
		for p.i < len(p.lines) && (p.lines[p.i].raw || p.lines[p.i].indent > indent) {
			b.WriteString(p.lines[p.i].text)
			b.WriteByte('\n')
			p.i++
		}
		return b.String(), nil
	}
	switch v {
	case "[]":
		return []any{}, nil
	case "{}":
		return ymap{}, nil
	}
	if strings.HasPrefix(v, `"`) || strings.HasPrefix(v, "'") {
		// A quoted scalar may continue on the next lines.
		q := v[0]
		for !closedQuote(v, q) && p.i < len(p.lines) {
			v += " " + p.lines[p.i].text
			p.i++
		}
		return unquote(stripQuotedComment(v)), nil
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	// A plain scalar may continue on more-indented lines.
	for p.i < len(p.lines) && !p.lines[p.i].raw && p.lines[p.i].indent > indent && !isMapLine(p.lines[p.i].text) && !isSeq(p.lines[p.i].text) {
		v += " " + p.lines[p.i].text
		p.i++
	}
	return v, nil
}

func closedQuote(v string, q byte) bool {
	for i := 1; i < len(v); i++ {
		switch {
		case q == '"' && v[i] == '\\':
			i++
		case v[i] == q:
			if q == '\'' && i+1 < len(v) && v[i+1] == '\'' {
				i++
				continue
			}
			return true
		}
	}
	return false
}

func stripQuotedComment(v string) string {
	q := v[0]
	for i := 1; i < len(v); i++ {
		switch {
		case q == '"' && v[i] == '\\':
			i++
		case v[i] == q:
			if q == '\'' && i+1 < len(v) && v[i+1] == '\'' {
				i++
				continue
			}
			return v[:i+1]
		}
	}
	return v
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if u, err := strconv.Unquote(s); err == nil {
			return u
		}
		return s[1 : len(s)-1]
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	return s
}

// --- JSON ---

func parseJSON(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return fromJSON(v, 0), nil
}

func fromJSON(v any, depth int) any {
	if depth > maxDepth {
		return ""
	}
	switch t := v.(type) {
	case map[string]any:
		m := ymap{}
		ks := make([]string, 0, len(t))
		for k := range t {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			m.set(k, fromJSON(t[k], depth+1))
		}
		return m
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = fromJSON(e, depth+1)
		}
		return out
	case string:
		return t
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

// --- dotenv and INI: SOPS flattens its metadata into keys like
// sops_age__list_0__map_recipient. ---

func parseDotenv(b []byte) (ymap, ymap) {
	data, meta := ymap{}, ymap{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		l = strings.TrimPrefix(l, "export ")
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if strings.HasPrefix(k, "sops_") {
			unflatten(meta, strings.TrimPrefix(k, "sops_"), v)
			continue
		}
		data.set(k, v)
	}
	return data, meta
}

func parseINI(b []byte) (ymap, ymap) {
	data, meta := ymap{}, ymap{}
	section := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			section = strings.TrimSpace(l[1 : len(l)-1])
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if section == "sops" {
			unflatten(meta, k, v)
			continue
		}
		sec, _ := data[section].(ymap)
		if sec == nil {
			sec = ymap{}
			data.set(section, sec)
		}
		sec.set(k, v)
	}
	return data, meta
}

// unflatten puts "age__list_0__map_recipient" = v into m as
// m["age"][0]["recipient"] = v.
func unflatten(m ymap, key, v string) {
	parts := strings.Split(key, "__")
	var cur any = m
	for i, part := range parts {
		last := i == len(parts)-1
		name := part
		isList := false
		if strings.HasPrefix(part, "list_") {
			isList = true
		} else {
			name = strings.TrimPrefix(part, "map_")
		}
		switch c := cur.(type) {
		case ymap:
			if isList {
				return
			}
			if last {
				c.set(name, v)
				return
			}
			nextIsList := strings.HasPrefix(parts[i+1], "list_")
			child, ok := c[name]
			if !ok {
				if nextIsList {
					child = &[]any{}
				} else {
					child = ymap{}
				}
				c.set(name, child)
			}
			cur = child
		case *[]any:
			if !isList {
				return
			}
			n, err := strconv.Atoi(strings.TrimPrefix(part, "list_"))
			if err != nil || n < 0 || n > 1000 {
				return
			}
			for len(*c) <= n {
				*c = append(*c, ymap{})
			}
			if last {
				(*c)[n] = v
				return
			}
			if _, ok := (*c)[n].(ymap); !ok {
				(*c)[n] = ymap{}
			}
			cur = (*c)[n]
		default:
			return
		}
	}
}

// derefLists turns the *[]any unflatten builds into []any.
func derefLists(v any) any {
	switch t := v.(type) {
	case *[]any:
		out := make([]any, len(*t))
		for i, e := range *t {
			out[i] = derefLists(e)
		}
		return out
	case ymap:
		for _, k := range t.keys() {
			t[k] = derefLists(t[k])
		}
		return t
	}
	return v
}
