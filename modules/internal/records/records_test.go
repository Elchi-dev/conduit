package records

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	known := func(s string) bool { return s == "a" }
	for _, cs := range [][]Cond{
		{{Field: "a", Op: "eq", Value: "x"}},
		{{Field: "a", Op: "gt", Value: 1.5}},
		{{Field: "a", Op: "ne", Value: false}},
		{{Field: "a", Op: "empty"}},
	} {
		if err := Check(cs, known, `\`); err != nil {
			t.Errorf("%+v: %v", cs, err)
		}
	}
	for _, cs := range [][]Cond{
		{{Field: "b", Op: "eq", Value: "x"}},
		{{Field: "a", Op: "like", Value: "x"}},
		{{Field: "a", Op: "eq"}},
		{{Field: "a", Op: "empty", Value: "x"}},
		{{Field: "a", Op: "eq", Value: `x\`}},
		{{Field: "a", Op: "eq", Value: "x\ny"}},
		{{Field: "a", Op: "eq", Value: strings.Repeat("x", MaxValue+1)}},
		{{Field: "a", Op: "eq", Value: []any{"x"}}},
		{{Field: "a", Op: "gt", Value: true}},
		{{Field: "a", Op: "contains", Value: 1.0}},
		make([]Cond, MaxConds+1),
	} {
		if err := Check(cs, known, `\`); err == nil {
			t.Errorf("accepted %+v", cs)
		}
	}
}

func TestPage(t *testing.T) {
	if Page(0) != 1 || Page(3) != 3 || Page(int(^uint(0)>>1)) != MaxPage {
		t.Fatal(Page(0), Page(3))
	}
}

func TestClipFit(t *testing.T) {
	v := Clip(map[string]any{"a": []any{strings.Repeat("é", MaxString)}}).(map[string]any)
	s := v["a"].([]any)[0].(string)
	if len(s) > MaxString+20 || !strings.HasSuffix(s, "(cut)") {
		t.Fatal(len(s))
	}
	rows := []map[string]any{}
	for i := 0; i < 400; i++ {
		rows = append(rows, map[string]any{"x": strings.Repeat("y", 2000)})
	}
	got, cut := Fit(rows)
	if !cut || len(got) == 0 || len(got) == len(rows) {
		t.Fatal(len(got), cut)
	}
	if !Same(map[string]any{"b": 1.0, "a": "x"}, json.RawMessage(`{"a":"x","b":1}`)) || Same("1", json.RawMessage(`1`)) {
		t.Fatal("Same")
	}
}
