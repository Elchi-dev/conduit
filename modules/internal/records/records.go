// Package records is shared by the modules that read and write the records
// of app backends (PocketBase, Appwrite, Directus, Strapi, NocoDB): filters
// given as structured conditions and checked before any request (each module
// renders them in its backend's syntax, quoting values itself, so agent text
// is never spliced into a filter expression), record data checked field by
// field, and caps on how much is returned.
package records

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode"
)

// Cond is one condition of a filter. Conditions are combined with AND.
type Cond struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value any    `json:"value"`
}

// Ops are the operators a condition takes.
var Ops = []string{"eq", "ne", "gt", "gte", "lt", "lte", "contains", "empty", "notempty"}

// MaxConds is the most conditions a filter takes.
const MaxConds = 10

// MaxValue is the longest string value a condition takes.
const MaxValue = 500

// WhereSchema is the JSON schema property for a "where" input.
const WhereSchema = `"where":{"type":"array","maxItems":10,"description":"Conditions, all of which must hold: field, op (eq, ne, gt, gte, lt, lte, contains, empty, notempty) and value (a string, number or true/false; none for empty and notempty)","items":{"type":"object","required":["field","op"],"properties":{"field":{"type":"string"},"op":{"type":"string","enum":["eq","ne","gt","gte","lt","lte","contains","empty","notempty"]},"value":{"type":["string","number","boolean"]}}}}`

// NeedsValue says whether an operator compares with a value.
func NeedsValue(op string) bool { return op != "empty" && op != "notempty" }

// Check validates conditions before anything is sent: each field must be one
// known allows, each operator one of Ops, and each value a string (at most
// MaxValue characters, no control characters and none of forbid), a finite
// number or true/false. contains takes a string.
func Check(cs []Cond, known func(string) bool, forbid string) error {
	if len(cs) > MaxConds {
		return fmt.Errorf("at most %d conditions", MaxConds)
	}
	for _, c := range cs {
		if c.Field == "" || !known(c.Field) {
			return fmt.Errorf("can't filter on %q: it isn't one of the collection's fields (or it's a hidden one)", Short(c.Field))
		}
		if !valid(c.Op) {
			return fmt.Errorf("unknown op %q: use one of %s", Short(c.Op), strings.Join(Ops, ", "))
		}
		if !NeedsValue(c.Op) {
			if c.Value != nil {
				return fmt.Errorf("%s takes no value", c.Op)
			}
			continue
		}
		switch v := c.Value.(type) {
		case string:
			if err := CheckString(v, forbid); err != nil {
				return fmt.Errorf("%s: %w", c.Field, err)
			}
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return fmt.Errorf("%s: not a number", c.Field)
			}
			if c.Op == "contains" {
				return errors.New("contains takes text")
			}
		case bool:
			if c.Op != "eq" && c.Op != "ne" {
				return fmt.Errorf("%s compares true/false with eq or ne only", c.Field)
			}
		case nil:
			return fmt.Errorf("%s needs a value (use empty or notempty for none)", c.Op)
		default:
			return fmt.Errorf("%s: a value is a string, number or true/false", c.Field)
		}
	}
	return nil
}

// CheckString checks a string value of a condition.
func CheckString(v, forbid string) error {
	if len(v) > MaxValue {
		return fmt.Errorf("a value is at most %d characters", MaxValue)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return errors.New("a value can't contain control characters")
		}
		if strings.ContainsRune(forbid, r) {
			return fmt.Errorf("a value can't contain %q here", r)
		}
	}
	return nil
}

func valid(op string) bool {
	for _, o := range Ops {
		if o == op {
			return true
		}
	}
	return false
}

// Number formats a number for a filter expression.
func Number(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

// Short cuts text a caller gave for an error message.
func Short(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}

// MaxFields is the most fields one create or update sets.
const MaxFields = 100

// MaxBody is the largest encoded record a create or update sends.
const MaxBody = 256 << 10

// Data checks a record's fields for a create or update: at least one, at
// most MaxFields, each one allowed (allow says why not), and at most MaxBody
// encoded.
func Data(d map[string]json.RawMessage, allow func(string) error) error {
	if len(d) == 0 {
		return errors.New("give the fields to set in data")
	}
	if len(d) > MaxFields {
		return fmt.Errorf("at most %d fields at a time", MaxFields)
	}
	size := 0
	for k, v := range d {
		if err := allow(k); err != nil {
			return err
		}
		size += len(k) + len(v)
	}
	if size > MaxBody {
		return fmt.Errorf("the record is larger than %d KB", MaxBody>>10)
	}
	return nil
}

// Keys returns a map's keys, sorted.
func Keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Same says whether a stored value equals the one a caller gave.
func Same(have any, want json.RawMessage) bool {
	var w any
	if json.Unmarshal(want, &w) != nil {
		return false
	}
	a, _ := json.Marshal(have)
	b, _ := json.Marshal(w)
	return bytes.Equal(a, b)
}

// MaxString is the longest string value returned; longer ones are cut.
const MaxString = 4000

// Clip shortens long strings in a decoded JSON value, at any depth.
func Clip(v any) any {
	switch x := v.(type) {
	case string:
		if len(x) > MaxString {
			return strings.ToValidUTF8(x[:MaxString], "") + "… (cut)"
		}
	case map[string]any:
		for k, e := range x {
			x[k] = Clip(e)
		}
	case []any:
		for i, e := range x {
			x[i] = Clip(e)
		}
	}
	return v
}

// MaxOutput is the most bytes of records one call returns.
const MaxOutput = 512 << 10

// Fit keeps rows from the start while they fit in MaxOutput bytes encoded,
// and says whether any were left out.
func Fit(rows []map[string]any) ([]map[string]any, bool) {
	size := 0
	for i, r := range rows {
		b, _ := json.Marshal(r)
		size += len(b) + 1
		if size > MaxOutput {
			return rows[:i], true
		}
	}
	return rows, false
}

// Limit returns n if it's between 1 and max, otherwise def.
func Limit(n, def, max int) int {
	if n < 1 || n > max {
		return def
	}
	return n
}

// MaxPage is the highest page number asked for, so an offset worked out
// from it (page × limit) can't overflow.
const MaxPage = 100000

// Page returns a page number between 1 and MaxPage.
func Page(n int) int {
	if n < 1 {
		return 1
	}
	return min(n, MaxPage)
}

// Sort reads a sort input: a field, with "-" in front for descending.
func Sort(s string, known func(string) bool) (field string, desc bool, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false, nil
	}
	if strings.HasPrefix(s, "-") {
		s, desc = s[1:], true
	}
	if !known(s) {
		return "", false, fmt.Errorf("can't sort by %q: it isn't one of the collection's fields", Short(s))
	}
	return s, desc, nil
}

// SortSchema is the JSON schema property for a "sort" input.
const SortSchema = `"sort":{"type":"string","description":"A field to sort by; put - in front for descending, e.g. -created"}`

// DataSchema is the JSON schema property for a "data" input.
const DataSchema = `"data":{"type":"object","description":"Field name to value"}`

// Raw encodes a value for a plan.
func Raw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
