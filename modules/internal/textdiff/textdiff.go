// Package textdiff summarises a change to a text for an edit's preview: how
// many lines are added and removed, and the first lines that change. Only
// lines of the new text are quoted; removed lines are named by number, since
// a page's old content is private and previews are kept in approvals.
package textdiff

import "strings"

// Line is one changed line in a Summary.
type Line struct {
	Op   string `json:"op"`             // "+" or "-"
	Line int    `json:"line"`           // 1-based, in the new text for "+", in the old for "-"
	Text string `json:"text,omitempty"` // only for "+"
}

// Summary is what an edit changes.
type Summary struct {
	Added   int    `json:"added"`
	Removed int    `json:"removed"`
	First   []Line `json:"first,omitempty"`
	// Approximate is set when the texts were too far apart to compare line
	// by line within the budget; the counts then come from which lines
	// appear in one text and not the other.
	Approximate bool `json:"approximate,omitempty"`
}

const (
	maxFirst = 5
	maxText  = 200
	budget   = 4_000_000 // cells of the line-by-line comparison (16 MB)
)

// Lines splits a text into lines, ignoring one final newline.
func Lines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(strings.ReplaceAll(s, "\r\n", "\n"), "\n"), "\n")
}

func clip(s string) string {
	r := []rune(s)
	if len(r) <= maxText {
		return s
	}
	return string(r[:maxText]) + "…"
}

// Diff summarises the change from old to new.
func Diff(old, new string) Summary {
	a, b := Lines(old), Lines(new)
	// Trim the common start and end.
	p := 0
	for p < len(a) && p < len(b) && a[p] == b[p] {
		p++
	}
	s := 0
	for s < len(a)-p && s < len(b)-p && a[len(a)-1-s] == b[len(b)-1-s] {
		s++
	}
	am, bm := a[p:len(a)-s], b[p:len(b)-s]
	var sum Summary
	if len(am) == 0 && len(bm) == 0 {
		return sum
	}
	var ops []Line
	if len(am)*len(bm) <= budget {
		ops = script(am, bm, p)
		for _, o := range ops {
			if o.Op == "+" {
				sum.Added++
			} else {
				sum.Removed++
			}
		}
	} else {
		sum.Approximate = true
		count := map[string]int{}
		for _, l := range am {
			count[l]++
		}
		for i, l := range bm {
			if count[l] > 0 {
				count[l]--
				continue
			}
			sum.Added++
			ops = append(ops, Line{Op: "+", Line: p + i + 1, Text: l})
		}
		for _, n := range count {
			sum.Removed += n
		}
		if len(ops) == 0 && sum.Removed > 0 {
			ops = append(ops, Line{Op: "-", Line: p + 1})
		}
	}
	for _, o := range ops {
		if len(sum.First) == maxFirst {
			break
		}
		if o.Op == "+" {
			o.Text = clip(o.Text)
		} else {
			o.Text = ""
		}
		sum.First = append(sum.First, o)
	}
	return sum
}

// Unquoted is s without the added lines' text: only counts and line
// numbers. Use it when the new text isn't what the caller wrote, such as an
// undo putting back an earlier version, whose lines are the page's own
// (private) content.
func (s Summary) Unquoted() Summary {
	if len(s.First) == 0 {
		return s
	}
	first := make([]Line, len(s.First))
	for i, l := range s.First {
		first[i] = Line{Op: l.Op, Line: l.Line}
	}
	s.First = first
	return s
}

// script returns the removed and added lines of a against b, in order, by
// a longest-common-subsequence table; off is the number of lines before a
// and b in their texts.
func script(a, b []string, off int) []Line {
	n, m := len(a), len(b)
	// lcs[i][j] is the LCS of a[i:] and b[j:], kept as one flat slice of
	// uint32 (the budget caps its size).
	w := m + 1
	lcs := make([]uint32, (n+1)*w)
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case a[i] == b[j]:
				lcs[i*w+j] = lcs[(i+1)*w+j+1] + 1
			case lcs[(i+1)*w+j] >= lcs[i*w+j+1]:
				lcs[i*w+j] = lcs[(i+1)*w+j]
			default:
				lcs[i*w+j] = lcs[i*w+j+1]
			}
		}
	}
	var out []Line
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i] == b[j]:
			i++
			j++
		case i < n && (j == m || lcs[(i+1)*w+j] >= lcs[i*w+j+1]):
			out = append(out, Line{Op: "-", Line: off + i + 1})
			i++
		default:
			out = append(out, Line{Op: "+", Line: off + j + 1, Text: b[j]})
			j++
		}
	}
	return out
}
