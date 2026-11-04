package mail

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// An attachment's type is parsed and written out again, so nothing the
// caller sends reaches the MIME header raw.
func TestAttachmentTypeCantInjectHeaders(t *testing.T) {
	a := &account{cfg: Config{Email: "me@example.com"}, maxAttach: 1 << 20}
	data := base64.StdEncoding.EncodeToString([]byte("x"))
	for _, bad := range []string{
		"text/plain\r\nBcc: hidden@evil.example\r\nX-Injected: 1",
		"text/plain\nX-Injected: 1",
		"text/plain; name=\"a\r\nX: 1\"",
		"not a type",
		"text/",
	} {
		c := &Compose{To: []string{"you@example.com"}, Subject: "hi", Body: "b", Attachments: []AttachmentIn{{Name: "a.txt", Base64: data, Type: bad}}}
		if err := a.resolve(c); err == nil {
			t.Errorf("type %q accepted", bad)
		}
	}
	for in, want := range map[string]string{
		"":                            "text/plain; charset=utf-8",
		"TEXT/Plain":                  "text/plain",
		`application/pdf; name="x y"`: `application/pdf; name="x y"`,
		" application/octet-stream ":  "application/octet-stream",
	} {
		c := &Compose{To: []string{"you@example.com"}, Subject: "hi", Body: "b", Attachments: []AttachmentIn{{Name: "a.txt", Base64: data, Type: in}}}
		if err := a.resolve(c); err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got := c.files[0].Type; got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
	// No type and no known extension: octet-stream.
	c := &Compose{To: []string{"you@example.com"}, Subject: "hi", Body: "b",
		Attachments: []AttachmentIn{{Name: "a\r\nX-Name-Injected: 1\".zzunknown", Base64: data}}}
	if err := a.resolve(c); err != nil {
		t.Fatal(err)
	}
	if c.files[0].Type != "application/octet-stream" {
		t.Fatalf("default type %q", c.files[0].Type)
	}
	msg, err := a.build(c, false)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := raw(msg)
	if strings.Contains(string(b), "\r\nX-Name-Injected: 1") {
		t.Fatalf("name injected a header:\n%s", b)
	}
}

// Message ids taken from a received message are cleaned before they go into
// In-Reply-To and References.
func TestReplyHeadersStripLineBreaks(t *testing.T) {
	for in, want := range map[string]string{
		"abc@example.com":                         "<abc@example.com>",
		"<abc@example.com>":                       "<abc@example.com>",
		"abc@example.com>\r\nBcc: x@evil.example": "<abc@example.comBcc:x@evil.example>",
		"a\nb\rc\x00d e":                          "<abcde>",
	} {
		if got := bracket(in); got != want {
			t.Errorf("bracket(%q) = %q, want %q", in, got, want)
		}
	}
	a := &account{cfg: Config{Email: "me@example.com"}, maxAttach: 1 << 20}
	c := &Compose{To: []string{"you@example.com"}, Subject: "Re: hi", Body: "b",
		inReplyTo: "id@x\r\nX-Injected: 1", references: []string{"r1@x\r\nX-Injected: 2", "\r\n", "r2@x"}}
	msg, err := a.build(c, false)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := raw(msg)
	s := string(b)
	if strings.Contains(s, "\r\nX-Injected") || !strings.Contains(s, "<r2@x>") || strings.Contains(s, "<>") {
		t.Fatalf("headers:\n%s", s)
	}
}

func TestTrustCertificateIsDestructive(t *testing.T) {
	for _, a := range New().Manifest().Actions {
		if a.Name == "trust_certificate" && (a.Risk != sdk.RiskDestructive || !a.DryRun) {
			t.Fatalf("%+v", a)
		}
	}
}
