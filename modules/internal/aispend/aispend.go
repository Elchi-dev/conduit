// Package aispend holds what the AI provider modules (anthropic, openai,
// mistral, groq) share: a bounded range of whole UTC days, exact money
// sums as decimal strings, checked group-by choices and currencies, and
// vendor-reported names made fit to show.
package aispend

import (
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
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

// amountRe is a plain decimal with an optional short exponent. big.Rat
// alone would also take fractions ("1/3"), hex, octal and binary ("0x10",
// "010", "0b11"), underscores and exponents of a million digits.
var amountRe = regexp.MustCompile(`^[-+]?[0-9]{1,30}(\.[0-9]{1,30})?([eE][-+]?[0-9]{1,2})?$`)

// Amount parses a decimal amount ("123.78912", "0.06", "1e-5") exactly.
func Amount(s string) (*big.Rat, error) {
	s = strings.TrimSpace(s)
	if len(s) > 64 || !amountRe.MatchString(s) {
		return nil, errors.New("invalid amount")
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, errors.New("invalid amount")
	}
	return r, nil
}

// maxDecimals is the most decimals Format writes. Sums of amounts Amount
// accepts (and those divided by 100) are exact within it in practice;
// anything longer is rounded.
const maxDecimals = 12

// Format writes an amount exactly, with at least two decimals (rounded
// only beyond maxDecimals).
func Format(r *big.Rat) string {
	n, exact := r.FloatPrec()
	if !exact || n > maxDecimals {
		n = maxDecimals
	}
	s := r.FloatString(max(n, 2))
	if i := strings.IndexByte(s, '.'); i >= 0 {
		for len(s)-i-1 > 2 && s[len(s)-1] == '0' {
			s = s[:len(s)-1]
		}
	}
	if strings.Trim(s, "-0.") == "" {
		s = "0.00"
	}
	return s
}

var currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)

// Currency checks a vendor's currency code (ISO 4217, any case); empty is
// USD. Amounts are summed per currency, never across.
func Currency(s string) (string, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return "USD", nil
	}
	if !currencyRe.MatchString(s) {
		return "", errors.New("invalid currency")
	}
	return s, nil
}

// maxLabel is the longest name Label passes on, in bytes.
const maxLabel = 120

// personalRe matches what shouldn't reach an answer from a vendor's name
// for a model, cost line or owner: email addresses, API keys (sk-...,
// gsk_...) and account, user and key ids (user_01..., user-..., apikey_...).
var personalRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+|\b(sk|gsk|xai)[-_][A-Za-z0-9_-]{8,}|\b(user|usr|apikey|api_key|key|account|acct)[-_][A-Za-z0-9]{8,}`)

// Label makes a name a vendor reports (a model, a cost line, a service
// tier, an organization) fit to show: one line of at most maxLabel bytes,
// cut after email addresses, keys and user or key ids are replaced.
func Label(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	s = personalRe.ReplaceAllString(s, "[redacted]")
	if len(s) <= maxLabel {
		return s
	}
	cut := maxLabel
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

var idOwnerRe = regexp.MustCompile(`(?i)^(user|org|organization|proj|project|key|acct|account)[-_][A-Za-z0-9]{6,}$|^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$`)

// Owner is a model's owner as shown: a vendor or provider name passes
// (through Label); a user, organization or project id, which fine-tuned
// models carry, becomes "your organization".
func Owner(s string) string {
	s = strings.TrimSpace(s)
	if idOwnerRe.MatchString(s) {
		return "your organization"
	}
	if l := Label(s); !strings.Contains(l, "[redacted]") {
		return l
	}
	return "your organization"
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
