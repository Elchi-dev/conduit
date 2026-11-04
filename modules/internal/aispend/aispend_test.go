package aispend

import (
	"testing"
	"time"
)

func TestParseRange(t *testing.T) {
	now := time.Date(2026, 11, 4, 15, 0, 0, 0, time.UTC)
	r, err := ParseRange("", "", now)
	if err != nil || r.Days() != 7 || r.From.Format("2006-01-02") != "2026-10-29" || r.End.Format("2006-01-02") != "2026-11-05" {
		t.Fatal(r, err)
	}
	if r, err := ParseRange("2026-08-04", "2026-11-04", now); err != nil || r.Days() != 93 {
		t.Fatal(r, err)
	}
	for _, c := range [][2]string{{"2026-08-03", "2026-11-04"}, {"2026-11-03", "2026-11-02"}, {"", "2026-11-05"}, {"2026-13-01", ""}, {"yesterday", ""}, {"2026-1-1", ""}} {
		if _, err := ParseRange(c[0], c[1], now); err == nil {
			t.Fatalf("%v accepted", c)
		}
	}
}

func TestMoney(t *testing.T) {
	var s Sums
	for _, a := range []string{"123.78912", "0.06", "1e-5", "100"} {
		v, err := Amount(a)
		if err != nil {
			t.Fatal(err)
		}
		s.Add("USD", v)
	}
	if got := Format(s.Get("USD")); got != "223.84913" {
		t.Fatal(got)
	}
	if got := Format(s.Get("EUR")); got != "0.00" {
		t.Fatal(got)
	}
	for _, a := range []string{"", "abc", "1/0"} {
		if _, err := Amount(a); err == nil {
			t.Fatalf("%q accepted", a)
		}
	}
}

func TestGroups(t *testing.T) {
	allowed := map[string]string{"model": "model", "workspace": "workspace_id"}
	if g, err := Groups(nil, allowed, []string{"model"}); err != nil || len(g) != 1 || g[0] != "model" {
		t.Fatal(g, err)
	}
	if g, err := Groups([]string{"workspace", "model"}, allowed, nil); err != nil || g[0] != "workspace_id" {
		t.Fatal(g, err)
	}
	if _, err := Groups([]string{"api_key_id"}, allowed, nil); err == nil {
		t.Fatal("accepted")
	}
}
