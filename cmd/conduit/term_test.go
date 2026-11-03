package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"plain text\twith tab\n":                "plain text\twith tab\n",
		"Ünïcode ✓ 日本":                          "Ünïcode ✓ 日本",
		"\x1b]0;pwned\x07title":                 `\x1b]0;pwned\x07title`,
		"\x1b[2J\x1b[Hclear":                    `\x1b[2J\x1b[Hclear`,
		"\x1b]52;c;ZXZpbA==\x07":                `\x1b]52;c;ZXZpbA==\x07`,
		"back\rover":                            `back\x0dover`,
		"bell\x07 del\x7f nul\x00":              `bell\x07 del\x7f nul\x00`,
		"c1 \u009b2J and \u0085":                `c1 \u009b2J and \u0085`,
		"raw \x9b byte":                         `raw \x9b byte`,
		"bidi \u202egnp.exe":                    `bidi \u202egnp.exe`,
		"\x1b[31mred\x1b[0m \x1b[1mbold\x1b[0m": "\x1b[31mred\x1b[0m \x1b[1mbold\x1b[0m",
		"\x1b[8mhidden\x1b[0m":                  `\x1b[8mhidden` + "\x1b[0m",
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
	var b bytes.Buffer
	n, err := termWriter{&b}.Write([]byte("motd \x1b]0;x\x07"))
	if err != nil || n != len("motd \x1b]0;x\x07") || strings.ContainsRune(b.String(), 0x1b) {
		t.Fatalf("write %d %v %q", n, err, b.String())
	}
}

func TestPlainHTTPWarning(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1:7600", "http://localhost:7600", "http://[::1]:7600", "https://conduit.example.com", "https://10.0.0.5:7600", "http://app.localhost"} {
		if w := plainHTTPWarning(u); w != "" {
			t.Errorf("%s: unexpected warning %q", u, w)
		}
	}
	for _, u := range []string{"http://10.0.0.5:7600", "http://conduit.example.com", "HTTP://192.168.1.2"} {
		if w := plainHTTPWarning(u); !strings.Contains(w, "plain http") {
			t.Errorf("%s: no warning", u)
		}
	}
}

// The warning reaches stderr when a command connects over plain http.
func TestConnectWarnsOnPlainHTTP(t *testing.T) {
	var stderr bytes.Buffer
	e := &env{stderr: &stderr, url: "http://192.0.2.10:7600", key: "cdt_x", getenv: func(string) string { return "" }}
	if _, err := e.connect(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "warning") || !strings.Contains(stderr.String(), "192.0.2.10:7600") {
		t.Fatalf("stderr %q", stderr.String())
	}
	stderr.Reset()
	e.url = "http://127.0.0.1:7600"
	if _, err := e.connect(); err != nil || stderr.Len() != 0 {
		t.Fatalf("loopback: %v %q", err, stderr.String())
	}
}
