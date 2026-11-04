package mail

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// deliver sends c, or saves it as a draft, or (dry run) describes that.
// after runs once a message was sent.
func (m *Module) deliver(ctx context.Context, a *account, c *Compose, asDraft, dryRun bool, after func()) (sdk.Result, error) {
	if err := a.resolve(c); err != nil {
		return sdk.Result{}, err
	}
	rcpts := strings.Join(append(append(append([]string{}, c.To...), c.CC...), c.BCC...), ", ")
	if dryRun {
		verb, summary := "send", fmt.Sprintf("Send %q from %s to %s", c.Subject, a.cfg.Email, rcpts)
		if asDraft {
			verb, summary = "draft", fmt.Sprintf("Save the draft %q in Drafts", c.Subject)
		}
		target := rcpts
		if target == "" {
			target = "Drafts"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: target, Op: verb, After: mustJSON(a.preview(c, verb))}}}}, nil
	}
	if asDraft {
		msg, err := a.build(c, true)
		if err != nil {
			return sdk.Result{}, err
		}
		b, err := raw(msg)
		if err != nil {
			return sdk.Result{}, err
		}
		drafts := m.drafts(ctx, a)
		uid, err := m.appendTo(ctx, a, drafts, b, []imap.Flag{imap.FlagDraft, imap.FlagSeen})
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"saved": true, "folder": drafts, "uid": uid, "subject": c.Subject})
	}
	if len(c.To)+len(c.CC)+len(c.BCC) == 0 {
		return sdk.Result{}, errors.New("add at least one recipient")
	}
	out, err := m.send(ctx, a, c)
	if err != nil {
		return sdk.Result{}, err
	}
	if after != nil {
		after()
	}
	return sdk.JSON(out)
}

// threadUnder makes c a reply to f (used by send with replyToUid).
func threadUnder(c *Compose, f *fetched) {
	e := f.buf.Envelope
	if e == nil || e.MessageID == "" {
		return
	}
	p, _ := parseRaw(f.raw, false, 0)
	c.inReplyTo = e.MessageID
	c.references = references(p, e.MessageID)
	if c.Subject == "" {
		c.Subject = e.Subject
	}
	c.Subject = replySubject(c.Subject)
}

// references is the References header for a reply to p: its own
// References (or In-Reply-To), then its Message-ID, at most 20 ids.
func references(p *parsed, id string) []string {
	var refs []string
	if p.Header.Len() > 0 {
		refs, _ = p.Header.MsgIDList("References")
		if len(refs) == 0 {
			refs, _ = p.Header.MsgIDList("In-Reply-To")
		}
	}
	refs = append(refs, id)
	if len(refs) > 20 {
		refs = append(refs[:1], refs[len(refs)-19:]...) // keep the root
	}
	return refs
}

func (m *Module) respond(ctx context.Context, a *account, call sdk.Call) (sdk.Result, error) {
	var in struct {
		UID                uint32         `json:"uid"`
		Mailbox            string         `json:"mailbox"`
		Body               string         `json:"body"`
		HTML               string         `json:"html"`
		To                 []string       `json:"to"`
		CC                 []string       `json:"cc"`
		BCC                []string       `json:"bcc"`
		Quote              *bool          `json:"quote"`
		Draft              bool           `json:"draft"`
		IncludeAttachments *bool          `json:"includeAttachments"`
		Attachments        []AttachmentIn `json:"attachments"`
	}
	if err := sdk.Decode(call, &in); err != nil {
		return sdk.Result{}, err
	}
	mailbox := orInbox(in.Mailbox)
	f, err := m.fetch(ctx, a, mailbox, in.UID)
	if err != nil {
		return sdk.Result{}, err
	}
	forward := call.Action == "forward"
	withFiles := forward && (in.IncludeAttachments == nil || *in.IncludeAttachments)
	p, _ := parseRaw(f.raw, withFiles, a.maxAttach)
	orig, _ := toMessage(f.buf, mailbox, f.raw)
	text, _ := p.body()
	c := &Compose{BCC: in.BCC, HTML: in.HTML, Attachments: in.Attachments}

	if forward {
		if len(in.To)+len(in.CC)+len(in.BCC) == 0 {
			return sdk.Result{}, errors.New("who should it go to?")
		}
		c.To, c.CC = in.To, in.CC
		c.Subject = forwardSubject(orig.Subject)
		var b strings.Builder
		if strings.TrimSpace(in.Body) != "" {
			b.WriteString(strings.TrimRight(in.Body, "\n") + "\n\n")
		}
		b.WriteString("---------- Forwarded message ---------\n")
		fmt.Fprintf(&b, "From: %s\n", orig.From)
		if orig.Date != "" {
			fmt.Fprintf(&b, "Date: %s\n", orig.Date)
		}
		fmt.Fprintf(&b, "Subject: %s\n", orig.Subject)
		fmt.Fprintf(&b, "To: %s\n", orig.To)
		if orig.CC != "" {
			fmt.Fprintf(&b, "Cc: %s\n", orig.CC)
		}
		b.WriteString("\n" + text + "\n")
		c.Body = b.String()
		if withFiles {
			for _, at := range p.Attachments {
				if at.Data == nil {
					return sdk.Result{}, fmt.Errorf("the attachment %s is over the %d MB limit; forward without attachments", at.Name, a.maxAttach>>20)
				}
				c.files = append(c.files, at)
			}
		}
		return m.deliver(ctx, a, c, in.Draft, call.DryRun, nil)
	}

	// reply, reply_all
	from := headerAddrs(p.Header, "Reply-To")
	if len(from) == 0 {
		from = headerAddrs(p.Header, "From")
	}
	origTo := headerAddrs(p.Header, "To")
	origCC := headerAddrs(p.Header, "Cc")
	fromMe := false
	for _, x := range headerAddrs(p.Header, "From") {
		if sameAddr(x, a.cfg.Email) {
			fromMe = true
		}
	}
	if fromMe {
		from = origTo // replying to something I sent: go to its recipients
	}
	c.To = dedupe(from)
	if call.Action == "reply_all" {
		others := origCC
		if !fromMe {
			others = append(append([]string{}, origTo...), origCC...)
		}
		c.CC = dedupe(others, append(append([]string{}, c.To...), a.cfg.Email)...)
	}
	c.CC = dedupe(append(c.CC, in.CC...), append(append([]string{}, c.To...), a.cfg.Email)...)
	if len(c.To) == 0 {
		return sdk.Result{}, errors.New("the message has no sender to reply to")
	}
	c.Subject = replySubject(orig.Subject)
	if id := orig.MessageID; id != "" {
		c.inReplyTo = id
		c.references = references(p, id)
	}
	c.Body = in.Body
	if in.Quote == nil || *in.Quote {
		c.Body = strings.TrimRight(in.Body, "\n") + "\n\n" + quote(text, orig.From, orig.Date)
	}
	answered := func() {
		_ = m.with(ctx, a, func(cl *imapclient.Client) error {
			if _, err := cl.Select(mailbox, nil).Wait(); err != nil {
				return err
			}
			return cl.Store(imap.UIDSetNum(imap.UID(in.UID)), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagAnswered}}, nil).Close()
		})
	}
	return m.deliver(ctx, a, c, in.Draft, call.DryRun, answered)
}

// draftCompose turns a saved draft back into a Compose.
func draftCompose(p *parsed) *Compose {
	c := &Compose{To: headerAddrs(p.Header, "To"), CC: headerAddrs(p.Header, "Cc"), BCC: headerAddrs(p.Header, "Bcc"), HTML: p.HTML}
	c.Subject, _ = p.Header.Subject()
	c.Body = strings.TrimRight(strings.ReplaceAll(p.Text, "\r\n", "\n"), "\n")
	if ids, _ := p.Header.MsgIDList("In-Reply-To"); len(ids) > 0 {
		c.inReplyTo = ids[0]
	}
	c.references, _ = p.Header.MsgIDList("References")
	for _, at := range p.Attachments {
		if at.Data != nil {
			c.files = append(c.files, at)
		}
	}
	return c
}

func (m *Module) draftOp(ctx context.Context, a *account, call sdk.Call) (sdk.Result, error) {
	var in struct {
		UID             uint32         `json:"uid"`
		To              *[]string      `json:"to"`
		CC              *[]string      `json:"cc"`
		BCC             *[]string      `json:"bcc"`
		Subject         *string        `json:"subject"`
		Body            *string        `json:"body"`
		HTML            *string        `json:"html"`
		Attachments     []AttachmentIn `json:"attachments"`
		KeepAttachments *bool          `json:"keepAttachments"`
	}
	if err := sdk.Decode(call, &in); err != nil {
		return sdk.Result{}, err
	}
	drafts := m.drafts(ctx, a)
	f, err := m.fetch(ctx, a, drafts, in.UID)
	if err != nil {
		return sdk.Result{}, err
	}
	p, _ := parseRaw(f.raw, true, a.maxAttach)
	c := draftCompose(p)
	removeOld := func() error {
		return m.with(ctx, a, func(cl *imapclient.Client) error {
			if _, err := cl.Select(drafts, nil).Wait(); err != nil {
				return err
			}
			return erase(cl, []imap.UID{imap.UID(in.UID)})
		})
	}
	switch call.Action {
	case "delete_draft":
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete the draft %q", c.Subject),
				Changes: []sdk.Change{{Target: drafts, Op: "delete", Before: mustJSON(a.preview(c, "draft"))}}}}, nil
		}
		if err := removeOld(); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": in.UID, "subject": c.Subject})

	case "send_draft":
		r, err := m.deliver(ctx, a, c, false, call.DryRun, nil)
		if err != nil || call.DryRun {
			return r, err
		}
		if err := removeOld(); err != nil {
			a.log("warn", "sent the draft but could not remove it from Drafts", "err", err)
		}
		return r, nil
	}

	// update_draft
	if in.To != nil {
		c.To = *in.To
	}
	if in.CC != nil {
		c.CC = *in.CC
	}
	if in.BCC != nil {
		c.BCC = *in.BCC
	}
	if in.Subject != nil {
		c.Subject = *in.Subject
	}
	if in.Body != nil {
		c.Body = *in.Body
	}
	if in.HTML != nil {
		c.HTML = *in.HTML
	}
	if in.KeepAttachments != nil && !*in.KeepAttachments {
		c.files = nil
	}
	c.Attachments = in.Attachments
	r, err := m.deliver(ctx, a, c, true, call.DryRun, nil)
	if err != nil || call.DryRun {
		return r, err
	}
	if err := removeOld(); err != nil {
		return sdk.Result{}, fmt.Errorf("saved the new version but could not remove the old one: %w", err)
	}
	var out map[string]any
	_ = json.Unmarshal(r.Output, &out)
	out["replaced"] = in.UID
	return sdk.JSON(out)
}

// thread collects a conversation across this folder, Sent and Archive.
func (m *Module) thread(ctx context.Context, a *account, call sdk.Call) (sdk.Result, error) {
	var in sel
	if err := sdk.Decode(call, &in); err != nil {
		return sdk.Result{}, err
	}
	f, err := m.fetch(ctx, a, in.mailbox(), in.UID)
	if err != nil {
		return sdk.Result{}, err
	}
	p, _ := parseRaw(f.raw, false, 0)
	ids := map[string]bool{}
	if e := f.buf.Envelope; e != nil && e.MessageID != "" {
		ids[e.MessageID] = true
	}
	if p.Header.Len() > 0 {
		for _, k := range []string{"References", "In-Reply-To"} {
			l, _ := p.Header.MsgIDList(k)
			for _, id := range l {
				ids[id] = true
			}
		}
	}
	boxes := []string{in.mailbox()}
	add := func(b string) {
		for _, x := range boxes {
			if strings.EqualFold(x, b) {
				return
			}
		}
		boxes = append(boxes, b)
	}
	add("INBOX")
	if sent, ok := m.findFolder(ctx, a, imap.MailboxAttrSent, "Sent", "Sent Items", "Sent Messages"); ok {
		add(sent)
	}
	if arch, ok := m.findFolder(ctx, a, imap.MailboxAttrArchive, "Archive", "Archives"); ok {
		add(arch)
	}
	found := map[string]Summary{} // by Message-ID (or mailbox/uid)
	err = m.with(ctx, a, func(cl *imapclient.Client) error {
		for pass := 0; pass < 2; pass++ {
			before := len(ids)
			crit := idCriteria(ids)
			if crit == nil {
				return nil
			}
			for _, box := range boxes {
				if _, err := cl.Select(box, &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
					continue // a folder that doesn't exist here
				}
				res, err := cl.UIDSearch(crit, nil).Wait()
				if err != nil {
					return err
				}
				uids := res.AllUIDs()
				if len(uids) == 0 {
					continue
				}
				if len(uids) > 200 {
					uids = uids[len(uids)-200:]
				}
				envs, err := envelopes(cl, uids, box)
				if err != nil {
					return err
				}
				for _, e := range envs {
					key := e.MessageID
					if key == "" {
						key = fmt.Sprintf("%s/%d", box, e.UID)
					}
					if _, dup := found[key]; !dup {
						found[key] = e
					}
					if e.MessageID != "" {
						ids[e.MessageID] = true
					}
					if e.InReplyTo != "" {
						ids[e.InReplyTo] = true
					}
				}
			}
			if len(ids) == before {
				break
			}
		}
		return nil
	})
	if err != nil {
		return sdk.Result{}, err
	}
	list := make([]Summary, 0, len(found))
	for _, s := range found {
		list = append(list, s)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Date != list[j].Date {
			return list[i].Date < list[j].Date
		}
		return list[i].UID < list[j].UID
	})
	return sdk.JSON(map[string]any{"count": len(list), "messages": list})
}

// idCriteria matches any message whose Message-ID, In-Reply-To or
// References names one of ids.
func idCriteria(ids map[string]bool) *imap.SearchCriteria {
	var keys []string
	for id := range ids {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	if len(keys) > 30 {
		keys = keys[len(keys)-30:]
	}
	var leaves []imap.SearchCriteria
	for _, id := range keys {
		for _, h := range []string{"Message-ID", "In-Reply-To", "References"} {
			leaves = append(leaves, imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: h, Value: id}}})
		}
	}
	if len(leaves) == 0 {
		return nil
	}
	for len(leaves) > 1 {
		var next []imap.SearchCriteria
		for i := 0; i < len(leaves); i += 2 {
			if i+1 == len(leaves) {
				next = append(next, leaves[i])
				continue
			}
			next = append(next, imap.SearchCriteria{Or: [][2]imap.SearchCriteria{{leaves[i], leaves[i+1]}}})
		}
		leaves = next
	}
	return &leaves[0]
}

func (m *Module) tlsStatus(ctx context.Context, a *account) (sdk.Result, error) {
	out := map[string]any{}
	for _, ep := range []struct {
		name, host, sec string
		port            int
	}{{"imap", a.cfg.IMAPHost, a.imapSec, a.cfg.IMAPPort}, {"smtp", a.cfg.SMTPHost, a.smtpSec, a.cfg.SMTPPort}} {
		info := a.pinInfo(ep.name)
		info["server"] = fmt.Sprintf("%s:%d", ep.host, ep.port)
		info["security"] = ep.sec
		if ep.sec == secNone {
			info["note"] = "unencrypted; allowed only because the server is on this machine"
			out[ep.name] = info
			continue
		}
		cert, err := probe(ctx, ep.name, ep.host, ep.port, ep.sec)
		if err != nil {
			info["error"] = err.Error()
			out[ep.name] = info
			continue
		}
		if cert == nil {
			info["error"] = "no certificate"
			out[ep.name] = info
			continue
		}
		fp := Fingerprint(cert.Raw)
		info["presented"] = fp
		info["subject"] = cert.Subject.String()
		info["issuer"] = cert.Issuer.String()
		info["notAfter"] = cert.NotAfter.UTC().Format(time.RFC3339)
		info["selfSigned"] = cert.Issuer.String() == cert.Subject.String()
		if a.trust == trustPinned {
			if pinned, _ := info["pinned"].(string); pinned != "" {
				info["matches"] = pinned == fp
			}
		} else {
			_, verr := cert.Verify(x509.VerifyOptions{DNSName: ep.host})
			info["trustedBySystem"] = verr == nil
			if verr != nil {
				info["verifyError"] = verr.Error()
			}
		}
		out[ep.name] = info
	}
	return sdk.JSON(out)
}

func (m *Module) trustCertificate(a *account, call sdk.Call) (sdk.Result, error) {
	var in struct {
		Endpoint    string            `json:"endpoint"`
		Fingerprint *string           `json:"fingerprint"`
		Pins        map[string]string `json:"pins"`
	}
	if err := sdk.Decode(call, &in); err != nil {
		return sdk.Result{}, err
	}
	if a.trust != trustPinned {
		return sdk.Result{}, errors.New("this mailbox trusts the system's certificate authorities; set Certificate trust to Pinned first")
	}
	if a.configPin != "" {
		return sdk.Result{}, errors.New("the pinned certificate comes from this mailbox's settings; change it there")
	}
	want := in.Pins
	if want == nil {
		if in.Fingerprint == nil {
			return sdk.Result{}, errors.New("give the fingerprint to trust (from tls_status), or an empty one to forget the pin")
		}
		eps := []string{"imap", "smtp"}
		switch in.Endpoint {
		case "imap", "smtp":
			eps = []string{in.Endpoint}
		case "", "both":
		default:
			return sdk.Result{}, errors.New("endpoint is imap, smtp or both")
		}
		want = map[string]string{}
		for _, ep := range eps {
			want[ep] = *in.Fingerprint
		}
	}
	norm := map[string]string{}
	for ep, fp := range want {
		if ep != "imap" && ep != "smtp" {
			return sdk.Result{}, errors.New("endpoint is imap or smtp")
		}
		if fp == "" {
			norm[ep] = ""
			continue
		}
		n, err := normFingerprint(fp)
		if err != nil {
			return sdk.Result{}, err
		}
		norm[ep] = n
	}
	prev := map[string]string{}
	err := a.state.update(func(d *stateData) {
		for ep, fp := range norm {
			prev[ep] = d.Pins[ep].Fingerprint
			if fp == "" {
				delete(d.Pins, ep)
			} else {
				d.Pins[ep] = pin{Fingerprint: fp, Since: time.Now().UTC().Format(time.RFC3339), Subject: "set by trust_certificate"}
			}
		}
	})
	if err != nil {
		return sdk.Result{}, err
	}
	// Drop the open connection so the next call checks the new pin.
	a.mu.Lock()
	if a.conn != nil {
		_ = a.conn.Close()
		a.conn = nil
	}
	a.mu.Unlock()
	r, err := sdk.JSON(map[string]any{"pins": norm})
	r.Undo = sdk.UndoWith("trust_certificate", map[string]any{"pins": prev}, "Restore the previously pinned certificate")
	return r, err
}
