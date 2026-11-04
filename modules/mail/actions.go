package mail

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// sel picks messages: one uid, several, or (for undo without UIDPLUS) the
// Message-IDs to look up.
type sel struct {
	UID        uint32   `json:"uid,omitempty"`
	UIDs       []uint32 `json:"uids,omitempty"`
	Mailbox    string   `json:"mailbox,omitempty"`
	MessageIDs []string `json:"messageIds,omitempty"`
	To         string   `json:"to,omitempty"`
	Label      string   `json:"label,omitempty"`
	Create     bool     `json:"create,omitempty"`
	Permanent  bool     `json:"permanent,omitempty"`
}

func (s *sel) mailbox() string {
	if s.Mailbox == "" {
		return "INBOX"
	}
	return s.Mailbox
}

func (s *sel) list() []uint32 {
	out := append([]uint32{}, s.UIDs...)
	if s.UID != 0 {
		out = append(out, s.UID)
	}
	return out
}

func toUIDs(list []uint32) []imap.UID {
	out := make([]imap.UID, len(list))
	for i, u := range list {
		out[i] = imap.UID(u)
	}
	return out
}

// resolveSel selects the mailbox and returns the uids, looking up
// Message-IDs when no uids are given.
func resolveSel(cl *imapclient.Client, s *sel, readOnly bool) ([]imap.UID, error) {
	if _, err := cl.Select(s.mailbox(), &imap.SelectOptions{ReadOnly: readOnly}).Wait(); err != nil {
		return nil, err
	}
	uids := toUIDs(s.list())
	if len(uids) == 0 && len(s.MessageIDs) > 0 {
		for _, id := range s.MessageIDs {
			found, err := byMessageID(cl, id)
			if err != nil {
				return nil, err
			}
			uids = append(uids, found...)
		}
		if len(uids) == 0 {
			return nil, userErr("the message is no longer in %s", s.mailbox())
		}
	}
	if len(uids) == 0 {
		return nil, userErr("uid is required")
	}
	if len(uids) > 500 {
		return nil, userErr("at most 500 messages at once")
	}
	return uids, nil
}

func byMessageID(cl *imapclient.Client, id string) ([]imap.UID, error) {
	id = strings.Trim(id, "<> ")
	if id == "" {
		return nil, nil
	}
	res, err := cl.UIDSearch(&imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: id}}}, nil).Wait()
	if err != nil {
		return nil, err
	}
	return res.AllUIDs(), nil
}

func hasUIDPlus(cl *imapclient.Client) bool {
	caps := cl.Caps()
	return caps.Has(imap.CapUIDPlus) || caps.Has(imap.CapIMAP4rev2)
}

// erase marks messages deleted and expunges just them where the server can.
func erase(cl *imapclient.Client, uids []imap.UID) error {
	set := imap.UIDSetNum(uids...)
	if err := cl.Store(set, &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Close(); err != nil {
		return err
	}
	if hasUIDPlus(cl) {
		return cl.UIDExpunge(set).Close()
	}
	return cl.Expunge().Close()
}

func uidList(set imap.NumSet) []uint32 {
	us, ok := set.(imap.UIDSet)
	if !ok {
		return nil
	}
	nums, ok := us.Nums()
	if !ok {
		return nil
	}
	out := make([]uint32, len(nums))
	for i, n := range nums {
		out[i] = uint32(n)
	}
	return out
}

// envelopes fetches the summaries of uids in the selected mailbox.
func envelopes(cl *imapclient.Client, uids []imap.UID, mailbox string) ([]Summary, error) {
	msgs, err := cl.Fetch(imap.UIDSetNum(uids...), listFetch()).Collect()
	if err != nil {
		return nil, err
	}
	return summarize(msgs, mailbox), nil
}

// folderInfo is one LIST entry.
type folderInfo struct {
	Name  string
	Attrs []imap.MailboxAttr
}

func (m *Module) folders(ctx context.Context, a *account) ([]folderInfo, error) {
	var out []folderInfo
	err := m.with(ctx, a, func(cl *imapclient.Client) error {
		list, err := cl.List("", "*", nil).Collect()
		if err != nil {
			return err
		}
		out = out[:0]
		for _, l := range list {
			out = append(out, folderInfo{l.Mailbox, l.Attrs})
		}
		return nil
	})
	return out, err
}

// findFolder returns the folder with a special-use role, or the first that
// exists of the usual names.
func (m *Module) findFolder(ctx context.Context, a *account, role imap.MailboxAttr, names ...string) (string, bool) {
	list, err := m.folders(ctx, a)
	if err != nil {
		return "", false
	}
	for _, f := range list {
		for _, at := range f.Attrs {
			if at == role {
				return f.Name, true
			}
		}
	}
	for _, n := range names {
		for _, f := range list {
			if strings.EqualFold(f.Name, n) {
				return f.Name, true
			}
		}
	}
	return "", false
}

// folder is findFolder with a fallback name.
func (m *Module) folder(ctx context.Context, a *account, role imap.MailboxAttr, names ...string) string {
	if n, ok := m.findFolder(ctx, a, role, names...); ok {
		return n
	}
	return names[0]
}

func (m *Module) drafts(ctx context.Context, a *account) string {
	return m.folder(ctx, a, imap.MailboxAttrDrafts, "Drafts", "Draft", "[Gmail]/Drafts")
}

func (m *Module) trash(ctx context.Context, a *account) string {
	return m.folder(ctx, a, imap.MailboxAttrTrash, "Trash", "Deleted Items", "Deleted Messages", "[Gmail]/Trash", "Bin")
}

func (m *Module) appendTo(ctx context.Context, a *account, mailbox string, raw []byte, flags []imap.Flag) (uint32, error) {
	var uid uint32
	err := m.with(ctx, a, func(cl *imapclient.Client) error {
		cmd := cl.Append(mailbox, int64(len(raw)), &imap.AppendOptions{Flags: flags, Time: time.Now()})
		if _, err := cmd.Write(raw); err != nil {
			return err
		}
		if err := cmd.Close(); err != nil {
			return err
		}
		d, err := cmd.Wait()
		if d != nil {
			uid = uint32(d.UID)
		}
		return err
	})
	return uid, err
}

// fetched is one message with its raw content.
type fetched struct {
	buf *imapclient.FetchMessageBuffer
	raw []byte
}

const maxMessage = 25 << 20

func fetchOne(cl *imapclient.Client, mailbox string, uid uint32) (*fetched, error) {
	if _, err := cl.Select(mailbox, &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
		return nil, err
	}
	set := imap.UIDSetNum(imap.UID(uid))
	head, err := cl.Fetch(set, &imap.FetchOptions{UID: true, RFC822Size: true}).Collect()
	if err != nil {
		return nil, err
	}
	if len(head) == 0 {
		return nil, errNoMessage(uid, mailbox)
	}
	if head[0].RFC822Size > maxMessage {
		return nil, errTooBig
	}
	sec := &imap.FetchItemBodySection{Peek: true}
	msgs, err := cl.Fetch(set, &imap.FetchOptions{UID: true, Flags: true, Envelope: true, RFC822Size: true, BodySection: []*imap.FetchItemBodySection{sec}}).Collect()
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, errNoMessage(uid, mailbox)
	}
	return &fetched{buf: msgs[0], raw: msgs[0].FindBodySection(sec)}, nil
}

func (m *Module) fetch(ctx context.Context, a *account, mailbox string, uid uint32) (*fetched, error) {
	if uid == 0 {
		return nil, userErr("uid is required")
	}
	var f *fetched
	err := m.with(ctx, a, func(cl *imapclient.Client) error {
		var err error
		f, err = fetchOne(cl, mailbox, uid)
		return err
	})
	return f, err
}

func orInbox(s string) string {
	if s == "" {
		return "INBOX"
	}
	return s
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	a, err := m.account(c.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	switch c.Action {
	case "inbox", "search", "drafts":
		return m.search(ctx, a, c)
	case "read":
		var in sel
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		f, err := m.fetch(ctx, a, in.mailbox(), in.UID)
		if err != nil {
			return sdk.Result{}, err
		}
		msg, err := toMessage(f.buf, in.mailbox(), f.raw)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(msg)
	case "thread":
		return m.thread(ctx, a, c)
	case "download_attachment":
		return m.download(ctx, a, c)
	case "mailboxes", "unread_counts":
		return m.mailboxes(ctx, a, c.Action == "unread_counts")
	case "mark_read", "mark_unread", "flag", "unflag":
		return m.flags(ctx, a, c)
	case "move", "copy", "archive":
		return m.relocate(ctx, a, c)
	case "label", "unlabel":
		return m.label(ctx, a, c)
	case "delete":
		return m.delete(ctx, a, c)
	case "send", "draft":
		var in Compose
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		if c.Action == "send" && (len(in.To)+len(in.CC)+len(in.BCC) == 0 || in.Subject == "") {
			return sdk.Result{}, errors.New("to and subject are required")
		}
		if in.ReplyToUID != 0 {
			if f, err := m.fetch(ctx, a, "INBOX", in.ReplyToUID); err == nil {
				threadUnder(&in, f)
			}
		}
		return m.deliver(ctx, a, &in, c.Action == "draft", c.DryRun, nil)
	case "reply", "reply_all", "forward":
		return m.respond(ctx, a, c)
	case "update_draft", "send_draft", "delete_draft":
		return m.draftOp(ctx, a, c)
	case "tls_status":
		return m.tlsStatus(ctx, a)
	case "trust_certificate":
		return m.trustCertificate(a, c)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}

func (m *Module) search(ctx context.Context, a *account, c sdk.Call) (sdk.Result, error) {
	var in struct {
		Mailbox    string `json:"mailbox"`
		Limit      int    `json:"limit"`
		UnreadOnly bool   `json:"unreadOnly"`
		Unread     *bool  `json:"unread"`
		Flagged    *bool  `json:"flagged"`
		Text       string `json:"text"`
		Body       string `json:"body"`
		From       string `json:"from"`
		To         string `json:"to"`
		CC         string `json:"cc"`
		Subject    string `json:"subject"`
		Since      string `json:"since"`
		Before     string `json:"before"`
		SinceDays  int    `json:"sinceDays"`
	}
	if err := sdk.Decode(c, &in); err != nil {
		return sdk.Result{}, err
	}
	if c.Action == "drafts" {
		in.Mailbox = m.drafts(ctx, a)
	}
	in.Mailbox = orInbox(in.Mailbox)
	if in.Limit <= 0 || in.Limit > 200 {
		in.Limit = 30
		if c.Action == "search" {
			in.Limit = 50
		}
	}
	crit := &imap.SearchCriteria{}
	if in.UnreadOnly || (in.Unread != nil && *in.Unread) {
		crit.NotFlag = append(crit.NotFlag, imap.FlagSeen)
	} else if in.Unread != nil {
		crit.Flag = append(crit.Flag, imap.FlagSeen)
	}
	if in.Flagged != nil {
		if *in.Flagged {
			crit.Flag = append(crit.Flag, imap.FlagFlagged)
		} else {
			crit.NotFlag = append(crit.NotFlag, imap.FlagFlagged)
		}
	}
	if in.Text != "" {
		crit.Text = []string{in.Text}
	}
	if in.Body != "" {
		crit.Body = []string{in.Body}
	}
	for k, v := range map[string]string{"From": in.From, "To": in.To, "Cc": in.CC, "Subject": in.Subject} {
		if v != "" {
			crit.Header = append(crit.Header, imap.SearchCriteriaHeaderField{Key: k, Value: v})
		}
	}
	sort.Slice(crit.Header, func(i, j int) bool { return crit.Header[i].Key < crit.Header[j].Key })
	if in.SinceDays > 0 {
		crit.Since = m.now().AddDate(0, 0, -in.SinceDays)
	}
	for _, d := range []struct {
		s   string
		dst *time.Time
	}{{in.Since, &crit.Since}, {in.Before, &crit.Before}} {
		if d.s == "" {
			continue
		}
		t, err := time.Parse("2006-01-02", d.s)
		if err != nil {
			return sdk.Result{}, fmt.Errorf("dates are YYYY-MM-DD, not %q", d.s)
		}
		*d.dst = t
	}
	list := []Summary{}
	err := m.with(ctx, a, func(cl *imapclient.Client) error {
		if _, err := cl.Select(in.Mailbox, &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
			return err
		}
		res, err := cl.UIDSearch(crit, nil).Wait()
		if err != nil {
			return err
		}
		uids := res.AllUIDs()
		if len(uids) == 0 {
			return nil
		}
		sort.Slice(uids, func(i, j int) bool { return uids[i] > uids[j] })
		if len(uids) > in.Limit {
			uids = uids[:in.Limit]
		}
		list, err = envelopes(cl, uids, "")
		return err
	})
	if err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(list)
}

func (m *Module) mailboxes(ctx context.Context, a *account, unreadOnly bool) (sdk.Result, error) {
	type row struct {
		Name     string  `json:"name"`
		Role     string  `json:"role,omitempty"`
		Kind     string  `json:"kind"` // folder, label, system
		Label    string  `json:"label,omitempty"`
		Messages *uint32 `json:"messages,omitempty"`
		Unread   *uint32 `json:"unread,omitempty"`
	}
	var rows []row
	err := m.with(ctx, a, func(cl *imapclient.Client) error {
		rows = rows[:0]
		listStatus := cl.Caps().Has(imap.CapListStatus) || cl.Caps().Has(imap.CapIMAP4rev2)
		opts := &imap.ListOptions{}
		so := &imap.StatusOptions{NumMessages: true, NumUnseen: true}
		if listStatus {
			opts.ReturnStatus = so
		}
		list, err := cl.List("", "*", opts).Collect()
		if err != nil {
			return err
		}
		for _, l := range list {
			r := row{Name: l.Mailbox, Kind: "folder"}
			noSelect := false
			for _, attr := range l.Attrs {
				if s := specialUse(attr); s != "" {
					r.Role, r.Kind = s, "system"
				}
				if attr == imap.MailboxAttrNoSelect || attr == imap.MailboxAttrNonExistent {
					noSelect = true
				}
			}
			if strings.EqualFold(l.Mailbox, "INBOX") {
				r.Role, r.Kind = "inbox", "system"
			}
			if a.labelMode == "folders" && a.labelPrefix != "" && strings.HasPrefix(l.Mailbox, a.labelPrefix) {
				r.Kind, r.Label = "label", strings.TrimPrefix(l.Mailbox, a.labelPrefix)
			}
			st := l.Status
			if st == nil && !noSelect {
				st, _ = cl.Status(l.Mailbox, so).Wait()
			}
			if st != nil {
				r.Messages, r.Unread = st.NumMessages, st.NumUnseen
			}
			if noSelect && r.Messages == nil {
				continue
			}
			rows = append(rows, r)
		}
		return nil
	})
	if err != nil {
		return sdk.Result{}, err
	}
	if !unreadOnly {
		if rows == nil {
			rows = []row{}
		}
		return sdk.JSON(rows)
	}
	out := map[string]any{"inbox": 0}
	folders := []map[string]any{}
	var total uint32
	for _, r := range rows {
		if r.Unread == nil || *r.Unread == 0 {
			continue
		}
		if r.Role == "inbox" {
			out["inbox"] = *r.Unread
		}
		if r.Role == "junk" || r.Role == "trash" || r.Role == "all" {
			continue // not mail anyone is waiting to read
		}
		total += *r.Unread
		folders = append(folders, map[string]any{"name": r.Name, "unread": *r.Unread})
	}
	out["total"], out["folders"] = total, folders
	return sdk.JSON(out)
}

func specialUse(a imap.MailboxAttr) string {
	switch a {
	case imap.MailboxAttrSent:
		return "sent"
	case imap.MailboxAttrDrafts:
		return "drafts"
	case imap.MailboxAttrTrash:
		return "trash"
	case imap.MailboxAttrArchive:
		return "archive"
	case imap.MailboxAttrJunk:
		return "junk"
	case imap.MailboxAttrAll:
		return "all"
	case imap.MailboxAttrFlagged:
		return "flagged"
	}
	return ""
}

func (m *Module) flags(ctx context.Context, a *account, c sdk.Call) (sdk.Result, error) {
	var in sel
	if err := sdk.Decode(c, &in); err != nil {
		return sdk.Result{}, err
	}
	flag, op, inverse := imap.FlagSeen, imap.StoreFlagsAdd, "mark_unread"
	switch c.Action {
	case "mark_unread":
		op, inverse = imap.StoreFlagsDel, "mark_read"
	case "flag":
		flag, inverse = imap.FlagFlagged, "unflag"
	case "unflag":
		flag, op, inverse = imap.FlagFlagged, imap.StoreFlagsDel, "flag"
	}
	var uids []imap.UID
	err := m.with(ctx, a, func(cl *imapclient.Client) error {
		var err error
		if uids, err = resolveSel(cl, &in, false); err != nil {
			return err
		}
		return cl.Store(imap.UIDSetNum(uids...), &imap.StoreFlags{Op: op, Silent: true, Flags: []imap.Flag{flag}}, nil).Close()
	})
	if err != nil {
		return sdk.Result{}, err
	}
	done := fromUIDs(uids)
	r, err := sdk.JSON(map[string]any{"uids": done, "done": c.Action})
	r.Undo = sdk.UndoWith(inverse, sel{UIDs: done, Mailbox: in.mailbox()}, "Undo "+strings.ReplaceAll(c.Action, "_", " "))
	return r, err
}

func fromUIDs(u []imap.UID) []uint32 {
	out := make([]uint32, len(u))
	for i, x := range u {
		out[i] = uint32(x)
	}
	return out
}

// relocate moves or copies messages and returns an undo that reverses it.
func (m *Module) relocate(ctx context.Context, a *account, c sdk.Call) (sdk.Result, error) {
	var in sel
	if err := sdk.Decode(c, &in); err != nil {
		return sdk.Result{}, err
	}
	if c.Action == "archive" {
		dest, ok := m.findFolder(ctx, a, imap.MailboxAttrArchive, "Archive", "Archives")
		if !ok {
			dest, ok = m.findFolder(ctx, a, imap.MailboxAttrAll, "All Mail", "[Gmail]/All Mail")
		}
		if !ok {
			return sdk.Result{}, errors.New("this mailbox has no Archive folder; use move with a folder name")
		}
		in.To = dest
	}
	if in.To == "" {
		return sdk.Result{}, errors.New("to (the folder) is required")
	}
	if in.To == in.mailbox() {
		return sdk.Result{}, fmt.Errorf("the messages are already in %s", in.To)
	}
	newUIDs, ids, err := m.transfer(ctx, a, &in, in.To, c.Action == "copy")
	if err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"uids": in.list(), "to": in.To, "newUids": newUIDs}
	if c.Action == "copy" {
		r, err := sdk.JSON(out)
		if len(newUIDs) > 0 || len(ids) > 0 {
			r.Undo = sdk.UndoWith("delete", sel{UIDs: newUIDs, MessageIDs: ids, Mailbox: in.To, Permanent: true}, "Remove the copy from "+in.To)
		}
		return r, err
	}
	out["movedTo"] = in.To
	r, err := sdk.JSON(out)
	back := sel{UIDs: newUIDs, Mailbox: in.To, To: in.mailbox()}
	if len(newUIDs) == 0 {
		back.MessageIDs = ids
	}
	if len(back.UIDs) > 0 || len(back.MessageIDs) > 0 {
		r.Undo = sdk.UndoWith("move", back, "Move back to "+in.mailbox())
	}
	return r, err
}

// transfer moves or copies the selected messages to dest. It returns their
// uids there (when the server reports them) and their Message-IDs.
func (m *Module) transfer(ctx context.Context, a *account, in *sel, dest string, copyOnly bool) ([]uint32, []string, error) {
	var newUIDs []uint32
	var ids []string
	err := m.with(ctx, a, func(cl *imapclient.Client) error {
		uids, err := resolveSel(cl, in, false)
		if err != nil {
			return err
		}
		in.UID, in.UIDs = 0, fromUIDs(uids)
		if envs, err := envelopes(cl, uids, ""); err == nil {
			for _, e := range envs {
				if e.MessageID != "" {
					ids = append(ids, e.MessageID)
				}
			}
		}
		set := imap.UIDSetNum(uids...)
		if copyOnly {
			d, err := cl.Copy(set, dest).Wait()
			if err != nil {
				return err
			}
			if d != nil {
				newUIDs = uidList(d.DestUIDs)
			}
			return nil
		}
		d, err := cl.Move(set, dest).Wait()
		if err != nil {
			return err
		}
		if d != nil && d.DestUIDs != nil {
			newUIDs = uidList(d.DestUIDs)
		}
		return nil
	})
	return newUIDs, ids, err
}

var keywordRe = func(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func (m *Module) label(ctx context.Context, a *account, c sdk.Call) (sdk.Result, error) {
	var in sel
	if err := sdk.Decode(c, &in); err != nil {
		return sdk.Result{}, err
	}
	in.Label = strings.TrimSpace(in.Label)
	if in.Label == "" {
		return sdk.Result{}, errors.New("label is required")
	}
	add := c.Action == "label"
	inverse := "unlabel"
	if !add {
		inverse = "label"
	}
	if a.labelMode == "keywords" {
		if !keywordRe(in.Label) {
			return sdk.Result{}, errors.New("on this server labels are IMAP keywords: letters, digits, _ - and . only")
		}
		op := imap.StoreFlagsAdd
		if !add {
			op = imap.StoreFlagsDel
		}
		var uids []imap.UID
		err := m.with(ctx, a, func(cl *imapclient.Client) error {
			var err error
			if uids, err = resolveSel(cl, &in, false); err != nil {
				return err
			}
			return cl.Store(imap.UIDSetNum(uids...), &imap.StoreFlags{Op: op, Silent: true, Flags: []imap.Flag{imap.Flag(in.Label)}}, nil).Close()
		})
		if err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(map[string]any{"uids": fromUIDs(uids), "label": in.Label, "done": c.Action})
		r.Undo = sdk.UndoWith(inverse, sel{UIDs: fromUIDs(uids), Mailbox: in.mailbox(), Label: in.Label}, "Undo "+c.Action)
		return r, err
	}

	folder := a.labelPrefix + strings.TrimPrefix(in.Label, a.labelPrefix)
	if add {
		if _, ok := m.findFolder(ctx, a, "", folder); !ok {
			if !in.Create {
				return sdk.Result{}, fmt.Errorf("there is no label %q; pass create to make it, or see mailboxes for the labels there are", in.Label)
			}
			if err := m.with(ctx, a, func(cl *imapclient.Client) error { return cl.Create(folder, nil).Wait() }); err != nil {
				return sdk.Result{}, err
			}
		}
		_, ids, err := m.transfer(ctx, a, &in, folder, true)
		if err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(map[string]any{"uids": in.list(), "label": in.Label, "done": "label"})
		r.Undo = sdk.UndoWith("unlabel", sel{UIDs: in.list(), MessageIDs: ids, Mailbox: in.mailbox(), Label: in.Label}, "Remove the label "+in.Label)
		return r, err
	}
	// Remove: erase the message's copy in the label folder, found by its
	// Message-ID (Proton removes the label; the message stays everywhere
	// else).
	ids := in.MessageIDs
	var removed int
	err := m.with(ctx, a, func(cl *imapclient.Client) error {
		if in.mailbox() != folder && len(in.list()) > 0 {
			uids, err := resolveSel(cl, &sel{UIDs: in.list(), Mailbox: in.mailbox()}, true)
			if err != nil {
				return err
			}
			envs, err := envelopes(cl, uids, "")
			if err != nil {
				return err
			}
			ids = ids[:0]
			for _, e := range envs {
				if e.MessageID != "" {
					ids = append(ids, e.MessageID)
				}
			}
		}
		var target []imap.UID
		if in.mailbox() == folder && len(in.list()) > 0 {
			if _, err := cl.Select(folder, nil).Wait(); err != nil {
				return err
			}
			target = toUIDs(in.list())
		} else {
			if _, err := cl.Select(folder, nil).Wait(); err != nil {
				return err
			}
			for _, id := range ids {
				u, err := byMessageID(cl, id)
				if err != nil {
					return err
				}
				target = append(target, u...)
			}
		}
		if len(target) == 0 {
			return userErr("those messages don't have the label %q", in.Label)
		}
		removed = len(target)
		return erase(cl, target)
	})
	if err != nil {
		return sdk.Result{}, err
	}
	r, err := sdk.JSON(map[string]any{"removed": removed, "label": in.Label, "done": "unlabel"})
	if in.mailbox() != folder {
		r.Undo = sdk.UndoWith("label", sel{UIDs: in.list(), Mailbox: in.mailbox(), Label: in.Label}, "Label again with "+in.Label)
	}
	return r, err
}

func (m *Module) delete(ctx context.Context, a *account, c sdk.Call) (sdk.Result, error) {
	var in sel
	if err := sdk.Decode(c, &in); err != nil {
		return sdk.Result{}, err
	}
	trash := m.trash(ctx, a)
	permanent := in.Permanent || strings.EqualFold(in.mailbox(), trash)
	var envs []Summary
	err := m.with(ctx, a, func(cl *imapclient.Client) error {
		uids, err := resolveSel(cl, &in, true)
		if err != nil {
			return err
		}
		in.UID, in.UIDs, in.MessageIDs = 0, fromUIDs(uids), nil
		envs, err = envelopes(cl, uids, in.mailbox())
		return err
	})
	if err != nil {
		return sdk.Result{}, err
	}
	if len(envs) == 0 {
		return sdk.Result{}, userErr("those messages aren't in %s any more", in.mailbox())
	}
	if c.DryRun {
		op, summary := "trash", fmt.Sprintf("Move %d message(s) from %s to %s", len(envs), in.mailbox(), trash)
		if permanent {
			op, summary = "delete", fmt.Sprintf("Erase %d message(s) from %s for good", len(envs), in.mailbox())
		}
		plan := &sdk.Plan{Summary: summary}
		for _, e := range envs {
			plan.Changes = append(plan.Changes, sdk.Change{Target: fmt.Sprintf("%q from %s", e.Subject, e.From), Op: op,
				Before: mustJSON(map[string]any{"uid": e.UID, "mailbox": in.mailbox(), "date": e.Date})})
		}
		return sdk.Result{Plan: plan}, nil
	}
	if permanent {
		err := m.with(ctx, a, func(cl *imapclient.Client) error {
			if _, err := cl.Select(in.mailbox(), nil).Wait(); err != nil {
				return err
			}
			return erase(cl, toUIDs(in.list()))
		})
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"erased": len(envs), "mailbox": in.mailbox()})
	}
	newUIDs, ids, err := m.transfer(ctx, a, &in, trash, false)
	if err != nil {
		return sdk.Result{}, err
	}
	r, err := sdk.JSON(map[string]any{"trashed": len(envs), "from": in.mailbox(), "to": trash, "newUids": newUIDs})
	back := sel{UIDs: newUIDs, Mailbox: trash, To: in.mailbox()}
	if len(newUIDs) == 0 {
		back.MessageIDs = ids
	}
	r.Undo = sdk.UndoWith("move", back, fmt.Sprintf("Restore %d message(s) from %s", len(envs), trash))
	return r, err
}

func (m *Module) download(ctx context.Context, a *account, c sdk.Call) (sdk.Result, error) {
	var in struct {
		UID     uint32 `json:"uid"`
		Mailbox string `json:"mailbox"`
		Index   *int   `json:"index"`
		Name    string `json:"name"`
		MaxMB   int    `json:"maxMB"`
	}
	if err := sdk.Decode(c, &in); err != nil {
		return sdk.Result{}, err
	}
	if in.Index == nil && in.Name == "" {
		return sdk.Result{}, errors.New("give the attachment's index or name (from read)")
	}
	if in.MaxMB <= 0 || in.MaxMB > 25 {
		in.MaxMB = 10
	}
	f, err := m.fetch(ctx, a, orInbox(in.Mailbox), in.UID)
	if err != nil {
		return sdk.Result{}, err
	}
	limit := int64(in.MaxMB) << 20
	p, _ := parseRaw(f.raw, true, limit)
	for _, at := range p.Attachments {
		if (in.Index != nil && at.Index == *in.Index) || (in.Index == nil && at.Name == in.Name) {
			if at.Data == nil {
				return sdk.Result{}, fmt.Errorf("%s is %d KB, over the %d MB limit; raise maxMB (up to 25)", at.Name, at.SizeKB, in.MaxMB)
			}
			return sdk.JSON(map[string]any{"name": at.Name, "type": at.Type, "size": len(at.Data), "base64": b64(at.Data)})
		}
	}
	return sdk.Result{}, errors.New("no such attachment; read the message for its list")
}
