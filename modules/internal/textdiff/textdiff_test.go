package textdiff

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDiff(t *testing.T) {
	for _, c := range []struct{ old, new, want string }{
		{"a\nb\nc\n", "a\nb\nc", `{"added":0,"removed":0}`},
		{"a\nb\nc", "a\nB\nc\nd", `{"added":2,"removed":1,"first":[{"op":"-","line":2},{"op":"+","line":2,"text":"B"},{"op":"+","line":4,"text":"d"}]}`},
		{"", "x", `{"added":1,"removed":0,"first":[{"op":"+","line":1,"text":"x"}]}`},
		{"secret\nkeep", "keep", `{"added":0,"removed":1,"first":[{"op":"-","line":1}]}`},
	} {
		b, _ := json.Marshal(Diff(c.old, c.new))
		if string(b) != c.want {
			t.Errorf("%q → %q: %s", c.old, c.new, b)
		}
	}
	// Removed lines are never quoted.
	if b, _ := json.Marshal(Diff("password: hunter2\n", "nothing\n")); strings.Contains(string(b), "hunter2") {
		t.Fatal(string(b))
	}
	// Too far apart for the table: counted by line, approximately.
	var a, b strings.Builder
	for i := 0; i < 3000; i++ {
		a.WriteString("a" + strings.Repeat("x", i%50) + "\n")
		b.WriteString("b" + strings.Repeat("y", i%50) + "\n")
	}
	s := Diff(a.String(), b.String())
	if !s.Approximate || s.Added != 3000 || s.Removed != 3000 || len(s.First) != 5 {
		t.Fatalf("%+v", s)
	}
}
