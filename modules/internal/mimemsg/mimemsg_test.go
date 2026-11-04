package mimemsg

import (
	"bytes"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func TestRefusesHeaderInjection(t *testing.T) {
	for _, m := range []Message{
		{To: []string{"a@example.com\r\nBcc: evil@example.net"}, Subject: "hi"},
		{To: []string{"a@example.com"}, Cc: []string{"b@example.com\nX: 1"}, Subject: "hi"},
		{To: []string{"a@example.com"}, Subject: "hi\r\nBcc: evil@example.net"},
		{To: []string{"a@example.com"}, Subject: "hi\nthere"},
		{To: []string{"\"Evil\r\nX: 1\" <a@example.com>"}, Subject: "hi"},
		{To: []string{"not an address"}, Subject: "hi"},
		{Subject: "no recipients"},
		{To: []string{"a@example.com"}},
		{From: "me@example.com\r\nX: 1", To: []string{"a@example.com"}, Subject: "hi"},
	} {
		if _, err := m.Check(); err == nil {
			t.Errorf("accepted %+v", m)
		}
	}
	many := make([]string, MaxRecipients+1)
	for i := range many {
		many[i] = "x@example.com"
	}
	if _, err := (Message{To: many, Subject: "hi"}).Check(); err == nil {
		t.Error("recipient cap not enforced")
	}
}

func TestBuild(t *testing.T) {
	c, err := Message{From: "Me <me@example.com>", To: []string{"Jürgen <j@example.com>"}, Bcc: []string{"hidden@example.com"},
		Subject: "Grüße", Text: "line one\nline two ünïcode"}.Check()
	if err != nil {
		t.Fatal(err)
	}
	raw := c.Build(time.Unix(0, 0))
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	dec := new(mime.WordDecoder)
	if s, _ := dec.DecodeHeader(msg.Header.Get("Subject")); s != "Grüße" {
		t.Errorf("subject %q", s)
	}
	if msg.Header.Get("Bcc") != "<hidden@example.com>" {
		t.Errorf("bcc %q", msg.Header.Get("Bcc"))
	}
	body, _ := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if !strings.Contains(string(body), "ünïcode") {
		t.Errorf("body %q", body)
	}
	c.omitBcc = true
	if strings.Contains(string(c.Build(time.Now())), "hidden@") {
		t.Error("bcc header written when omitted")
	}
	if c.Summary() != `Send "Grüße" to 2 recipients` {
		t.Error(c.Summary())
	}
}
