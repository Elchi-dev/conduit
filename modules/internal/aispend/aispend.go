// Package aispend holds what the AI provider usage modules (anthropic,
// openai) share: a bounded range of whole UTC days, exact money sums as
// decimal strings, and checked group-by choices.
package aispend

import (
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"
)

// MaxDays is the longest range a usage or cost report may cover.
const MaxDays = 93

var dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// Range is a span of whole UTC days; From is the first day's midnight and
// End the midnight after the last day.
type Range struct{ From, End time.Time }

// Days is the number of days in the range.
func (r Range) Days() int { return int(r.End.Sub(r.From).Hours() / 24) }

func day(s string) (time.Time, error) {
	if !dateRe.MatchString(s) {
		return time.Time{}, errors.New("dates are YYYY-MM-DD")
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, errors.New("dates are YYYY-MM-DD")
	}
	return t, nil
}

// ParseRange reads from and to (YYYY-MM-DD, both included). Empty to is
// today (UTC); empty from is six days before to. The range may not end
// after today or cover more than MaxDays days.
func ParseRange(from, to string, now time.Time) (Range, error) {
	today := now.UTC().Truncate(24 * time.Hour)
	last := today
	if to != "" {
		t, err := day(to)
		if err != nil {
			return Range{}, err
		}
		last = t
	}
	first := last.AddDate(0, 0, -6)
	if from != "" {
		f, err := day(from)
		if err != nil {
			return Range{}, err
		}
		first = f
	}
	if last.After(today) {
		return Range{}, errors.New("the range can't end after today (UTC)")
	}
	if first.After(last) {
		return Range{}, errors.New("from is after to")
	}
	r := Range{From: first, End: last.AddDate(0, 0, 1)}
	if r.Days() > MaxDays {
		return Range{}, fmt.Errorf("the range is at most %d days", MaxDays)
	}
	return r, nil
}

// Amount parses a decimal amount ("123.78912", "0.06", "1e-5") exactly.
func Amount(s string) (*big.Rat, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 {
		return nil, errors.New("invalid amount")
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, errors.New("invalid amount")
	}
	return r, nil
}

// Format writes an amount with at least two and at most six decimals.
func Format(r *big.Rat) string {
	s := r.FloatString(6)
	s = strings.TrimRight(s, "0")
	if i := strings.IndexByte(s, '.'); i >= 0 {
		for len(s)-i-1 < 2 {
			s += "0"
		}
	}
	if s == "-0.00" {
		s = "0.00"
	}
	return s
}

// Sums adds amounts by key.
type Sums struct {
	m     map[string]*big.Rat
	order []string
}

// Add adds v to key.
func (s *Sums) Add(key string, v *big.Rat) {
	if s.m == nil {
		s.m = map[string]*big.Rat{}
	}
	cur, ok := s.m[key]
	if !ok {
		cur = new(big.Rat)
		s.m[key] = cur
		s.order = append(s.order, key)
	}
	cur.Add(cur, v)
}

// Get returns key's sum (zero when absent).
func (s *Sums) Get(key string) *big.Rat {
	if v, ok := s.m[key]; ok {
		return v
	}
	return new(big.Rat)
}

// Keys returns the keys in the order they were first added.
func (s *Sums) Keys() []string { return append([]string(nil), s.order...) }

// Strings returns every sum formatted.
func (s *Sums) Strings() map[string]string {
	out := map[string]string{}
	for k, v := range s.m {
		out[k] = Format(v)
	}
	return out
}

// Groups checks group-by choices against allowed (the name a caller uses
// mapped to the vendor's) and returns the vendor names. Empty means def.
func Groups(in []string, allowed map[string]string, def []string) ([]string, error) {
	if len(in) == 0 {
		in = def
	}
	if len(in) > len(allowed) {
		return nil, errors.New("too many groupBy values")
	}
	seen := map[string]bool{}
	out := []string{}
	for _, g := range in {
		v, ok := allowed[g]
		if !ok {
			names := make([]string, 0, len(allowed))
			for k := range allowed {
				names = append(names, k)
			}
			sort.Strings(names)
			return nil, fmt.Errorf("groupBy is any of %s", strings.Join(names, ", "))
		}
		if !seen[g] {
			out = append(out, v)
		}
		seen[g] = true
	}
	return out, nil
}

// Has reports whether vendor group g is in gs.
func Has(gs []string, g string) bool {
	for _, x := range gs {
		if x == g {
			return true
		}
	}
	return false
}
