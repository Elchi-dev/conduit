package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

type lit struct {
	*bytes.Reader
}

func (l lit) Size() int64 { return int64(l.Len()) }

type host struct{}

func (host) Secret(_ context.Context, ref string) (string, error) {
	if ref == "secret://pw" {
		return "pw", nil
	}
	return "", errors.New("nope")
}
func (host) Publish(context.Context, sdk.Event) {}
func (host) Log(string, string, ...any)         {}

const sample = "From: Ada <ada@example.com>\r\nTo: me@example.com\r\nSubject: Server bill\r\nMessage-ID: <abc@example.com>\r\nDate: Mon, 02 Nov 2026 10:00:00 +0000\r\n" +
	"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
	"--b\r\nContent-Type: text/html\r\n\r\n<p>Your bill is <b>12 EUR</b>.</p><script>x()</script>\r\n" +
	"--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=bill.pdf\r\n\r\nPDFDATA\r\n--b--\r\n"

func memServer(t *testing.T) string {
	t.Helper()
	mem := imapmemserver.New()
	u := imapmemserver.NewUser("me@example.com", "pw")
	for _, mb := range []string{"INBOX", "Archive", "Drafts"} {
		if err := u.Create(mb, nil); err != nil && mb != "INBOX" {
			t.Fatal(err)
		}
	}
	if _, err := u.Append("INBOX", lit{bytes.NewReader([]byte(sample))}, &imap.AppendOptions{Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	mem.AddUser(u)
	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		Caps:         imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapIMAP4rev2: {}},
		InsecureAuth: true,
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func TestMailRoundTrip(t *testing.T) {
	addr := memServer(t)
	m := New()
	m.dial = func(ctx context.Context, a *account) (*imapclient.Client, error) {
		c, err := imapclient.DialInsecure(addr, nil)
		if err != nil {
			return nil, err
		}
		pw, _ := a.host.Secret(ctx, a.cfg.Password)
		return c, c.Login(a.cfg.Username, pw).Wait()
	}
	ctx := context.Background()
	cfg, _ := json.Marshal(map[string]string{"provider": "other", "email": "me@example.com", "password": "secret://pw", "imapHost": "x", "smtpHost": "y"})
	if err := m.Configure(ctx, host{}, "m1", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "m1"); h.Status != "ok" || h.Message != "1 unread" {
		t.Fatalf("health = %+v", h)
	}

	r, err := m.Invoke(ctx, sdk.Call{Instance: "m1", Action: "inbox"})
	if err != nil {
		t.Fatal(err)
	}
	var list []Summary
	_ = json.Unmarshal(r.Output, &list)
	if len(list) != 1 || list[0].Subject != "Server bill" || !list[0].Unread || !strings.Contains(list[0].From, "ada@example.com") {
		t.Fatalf("inbox = %+v", list)
	}
	uid := list[0].UID
	in, _ := json.Marshal(map[string]any{"uid": uid})

	r, err = m.Invoke(ctx, sdk.Call{Instance: "m1", Action: "read", Input: in})
	if err != nil {
		t.Fatal(err)
	}
	var msg Message
	_ = json.Unmarshal(r.Output, &msg)
	if msg.Text != "Your bill is 12 EUR." || len(msg.Attachments) != 1 || msg.Attachments[0].Name != "bill.pdf" {
		t.Fatalf("read = %+v", msg)
	}
	if h := m.Health(ctx, "m1"); h.Message != "1 unread" {
		t.Fatal("reading must not mark the message read")
	}

	r, err = m.Invoke(ctx, sdk.Call{Instance: "m1", Action: "mark_read", Input: in})
	if err != nil || r.Undo == nil || r.Undo.Action != "mark_unread" {
		t.Fatalf("mark_read: %v", err)
	}
	if h := m.Health(ctx, "m1"); h.Message != "0 unread" {
		t.Fatalf("after mark_read: %+v", h)
	}

	search, _ := json.Marshal(map[string]any{"text": "bill"})
	r, _ = m.Invoke(ctx, sdk.Call{Instance: "m1", Action: "search", Input: search})
	if !strings.Contains(string(r.Output), "Server bill") {
		t.Fatalf("search: %s", r.Output)
	}

	mv, _ := json.Marshal(map[string]any{"uid": uid, "to": "Archive"})
	r, err = m.Invoke(ctx, sdk.Call{Instance: "m1", Action: "move", Input: mv})
	if err != nil {
		t.Fatal(err)
	}
	if r.Undo == nil {
		t.Fatalf("move should be undoable: %s", r.Output)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "m1", Action: r.Undo.Action, Input: r.Undo.Input}); err != nil {
		t.Fatalf("undo move: %v", err)
	}
	r, _ = m.Invoke(ctx, sdk.Call{Instance: "m1", Action: "inbox"})
	if !strings.Contains(string(r.Output), "Server bill") {
		t.Fatal("message not back in INBOX after undo")
	}

	draft, _ := json.Marshal(map[string]any{"to": []string{"ada@example.com"}, "subject": "Bill", "body": "Paid.", "replyToUid": 0})
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "m1", Action: "draft", Input: draft}); err != nil {
		t.Fatalf("draft: %v", err)
	}
	plan, err := m.Invoke(ctx, sdk.Call{Instance: "m1", Action: "send", Input: draft, DryRun: true})
	if err != nil || plan.Plan == nil || !strings.Contains(plan.Plan.Summary, "Bill") {
		t.Fatalf("send dry run: %v", err)
	}
}

func TestHTMLToText(t *testing.T) {
	got := htmlToText("<style>p{}</style><p>Hi&nbsp;there</p><p>Line<br>two</p>")
	if got != "Hi there\nLine\ntwo" {
		t.Fatalf("got %q", got)
	}
}
