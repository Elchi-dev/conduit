package aispend

import (
	"math/big"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
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

func TestAmountStrict(t *testing.T) {
	// big.Rat alone takes all of these, some as other numbers than meant.
	for _, a := range []string{"1/3", "0x10", "0b11", "0o7", "1_000", "0x1p-2", "1e100000", "1e-999", ".5", "1.", "Inf"} {
		if _, err := Amount(a); err == nil {
			t.Errorf("%q accepted", a)
		}
	}
	for a, want := range map[string]string{"010.5": "10.50", "-0.25": "-0.25", "+3": "3.00", "1.5E+2": "150.00", "1.2345678e-5": "0.000012345678"} {
		v, err := Amount(a)
		if err != nil || Format(v) != want {
			t.Errorf("%q: %v %v", a, v, err)
		}
	}
}

func TestFormatExact(t *testing.T) {
	// Anthropic reports cents with five decimals; in dollars that's seven.
	v, _ := Amount("123.78912")
	v.Quo(v, big.NewRat(100, 1))
	if got := Format(v); got != "1.2378912" {
		t.Fatal(got)
	}
	if got := Format(big.NewRat(1, 3)); got != "0.333333333333" {
		t.Fatal(got)
	}
	if got := Format(big.NewRat(-1, 10_000_000_000_000)); got != "0.00" {
		t.Fatal(got)
	}
}

func TestCurrency(t *testing.T) {
	if c, err := Currency(" usd "); err != nil || c != "USD" {
		t.Fatal(c, err)
	}
	if c, err := Currency(""); err != nil || c != "USD" {
		t.Fatal(c, err)
	}
	for _, c := range []string{"US Dollars", "€", "USDX", "jane@example.com"} {
		if _, err := Currency(c); err == nil {
			t.Errorf("%q accepted", c)
		}
	}
}

func TestLabel(t *testing.T) {
	for in, want := range map[string]string{
		"Claude Sonnet 4 Usage - Input Tokens":     "Claude Sonnet 4 Usage - Input Tokens",
		"claude-sonnet-4-5-20250929":               "claude-sonnet-4-5-20250929",
		"ft:gpt-4o-mini-2024-07-18:acme::9xQzAbCd": "ft:gpt-4o-mini-2024-07-18:acme::9xQzAbCd",
		"usage by jane.doe@example.com":            "usage by [redacted]",
		"key sk-ant-api03-abcdefghijklmnop leaked": "key [redacted] leaked",
		"for user_01WCz1FkmYMm4gnmykNKUu3Q":        "for [redacted]",
		"apikey_01Rj2N8SVvo6BePZj99NhmiT, input":   "[redacted], input",
		"two\nlines‮\x00":                          "two lines",
	} {
		if got := Label(in); got != want {
			t.Errorf("Label(%q) = %q", in, got)
		}
	}
	if got := Label(strings.Repeat("é", 200)); len(got) > maxLabel+len("…") || !utf8.ValidString(got) {
		t.Fatal(len(got))
	}
}

func TestOwner(t *testing.T) {
	for in, want := range map[string]string{
		"openai": "openai", "Meta": "Meta", "mistralai": "mistralai", "system": "system", "organization-owner": "organization-owner",
		"user-abcdefghijklmnop": "your organization", "org-AbCdEf123456": "your organization",
		"0b7c3e1a-9f2d-4c1b-8a6e-5d4f3c2b1a09": "your organization", "jane@example.com": "your organization",
	} {
		if got := Owner(in); got != want {
			t.Errorf("Owner(%q) = %q", in, got)
		}
	}
}
