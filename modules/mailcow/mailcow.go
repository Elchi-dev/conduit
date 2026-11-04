// Package mailcow works with a mailcow: dockerized mail server through its
// API and an API key: domains, mailboxes with their quota use, aliases, the
// quarantine and the mail queue (counts and domains, never messages),
// flushing the queue, and disabling or enabling mailboxes.
package mailcow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one mailcow server.
type Config struct {
	URL    string `json:"url"`    // e.g. https://mail.example.com
	APIKey string `json:"apiKey"` // secret:// API key
	// AllowAdminAccounts lets disable_mailbox and enable_mailbox act on
	// postmaster@, abuse@, admin@ and the like.
	AllowAdminAccounts bool   `json:"allowAdminAccounts"`
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api        *rest.Client
	allowAdmin bool
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the mailcow module.
func New() *Module { return &Module{} }

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$`)
	localRe  = regexp.MustCompile(`^[a-z0-9._%+=-]{1,64}$`)
	// Role accounts that mail standards or the server's own reports rely on.
	protected = map[string]bool{"postmaster": true, "abuse": true, "admin": true, "administrator": true, "root": true, "hostmaster": true, "webmaster": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	box := `{"type":"object","required":["mailbox"],"properties":{"mailbox":{"type":"string","description":"The mailbox address, e.g. jane@example.com"}}}`
	enable := `{"type":"object","required":["mailbox"],"properties":{"mailbox":{"type":"string","description":"The mailbox address, e.g. jane@example.com"},"signIn":{"type":"boolean","default":true,"description":"Let it sign in (false: it receives mail but can't sign in)"}}}`
	dom := `{"type":"object","properties":{"domain":{"type":"string","description":"Only this domain"}}}`
	return sdk.Manifest{
		ID: "mailcow", Name: "mailcow", Version: "0.1.0", Category: "Communication", Icon: "mail",
		Description: "mailcow: domains, mailboxes and their quota use, aliases, quarantine and queue counts, flushing the queue, and disabling or enabling mailboxes.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://mail.example.com"},
			"apiKey":{"type":"string","x-secret":true,"description":"An API key (System, Configuration, Access, API). Read-only is enough for the listings; flushing the queue and disabling mailboxes need read-write. Allow Conduit's IP address for the key"},
			"allowAdminAccounts":{"type":"boolean","default":false,"description":"Let Conduit disable or enable postmaster@, abuse@, admin@, administrator@, root@, hostmaster@ and webmaster@ mailboxes"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Version and containers", Description: "The mailcow version and each container's state and image.", Risk: sdk.RiskRead},
			{Name: "domains", Title: "Domains", Description: "Domains with active, mailbox and alias counts and limits, storage used and allowed, message count, and backup MX or relay settings.", Risk: sdk.RiskRead},
			{Name: "mailboxes", Title: "Mailboxes", Description: "Mailboxes with name, active, quota, storage used and percent, and message count. Addresses and names are personal data, so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"domain":{"type":"string","description":"Only this domain"},"active":{"type":"boolean","description":"Only active (true) or disabled (false) mailboxes"}}}`)},
			{Name: "aliases", Title: "Aliases", Description: "Aliases with their destinations, active and catch-all. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true, Input: sdk.Schema(dom)},
			{Name: "quarantine", Title: "Quarantine", Description: "How many messages are held, how many for viruses, and counts by sender and recipient domain, with each item's id, time, spam score and domains. Never subjects, addresses or content.", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "queue", Title: "Mail queue", Description: "How many messages wait in the Postfix queue, by queue, their total size and the oldest, and counts by sender and recipient domain. Never addresses or content.", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "flush_queue", Title: "Flush the queue", Description: "Asks Postfix to try delivering every deferred message now (postqueue -f). Nothing is deleted; held messages stay held.", Risk: sdk.RiskWrite, DryRun: true},
			{Name: "disable_mailbox", Title: "Disable a mailbox", Description: "Sets a mailbox inactive: it can't sign in and mailcow stops accepting its mail. Mail already stored stays. Refused for a mailbox a role address (postmaster@ and the like) delivers to, unless allowed. Undo puts back the state it had.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(box)},
			{Name: "enable_mailbox", Title: "Enable a mailbox", Description: "Sets a mailbox active, so it can sign in and receive mail (with signIn false: receive only). Undo puts back the state it had.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(enable)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://mail.example.com")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	ref := c.APIKey
	p := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1")
	api := rest.New(u.Scheme+"://"+u.Host+p+"/api/v1", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-API-Key", strings.TrimSpace(k))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, allowAdmin: c.AllowAdminAccounts})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("mailcow refused the API key (check the key and that Conduit's IP address is allowed for it)")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the API key isn't allowed to do this in mailcow (a read-only key can only read)")
	}
	return err
}

// clip keeps a server's text to one short line, redacted before it's cut.
func clip(s string) string {
	s = strings.Join(strings.Fields(rest.Redact(s)), " ")
	if len(s) > 200 {
		s = strings.ToValidUTF8(s[:200], "") + "…"
	}
	return s
}

// apiError is mailcow's {"type":"error","msg":...} answer, which can come
// with status 200.
type apiError struct {
	Type string `json:"type"`
	Msg  any    `json:"msg"`
}

func (e apiError) failed() bool { return e.Type == "error" || e.Type == "danger" }

func (e apiError) err() error {
	msg := ""
	switch v := e.Msg.(type) {
	case string:
		msg = v
	case []any:
		var parts []string
		for _, p := range v {
			if s, ok := p.(string); ok {
				parts = append(parts, s)
			}
		}
		msg = strings.Join(parts, " ")
	}
	if msg == "" {
		return errors.New("mailcow refused the request")
	}
	if strings.Contains(strings.ToLower(msg), "authentication failed") || strings.Contains(strings.ToLower(msg), "access denied") {
		return errors.New("mailcow refused the API key (check the key and that Conduit's IP address is allowed for it)")
	}
	return errors.New("mailcow: " + clip(msg))
}

// list reads a GET answer that is a list, a single object, {} for none, or
// an error object.
func (c *conn) list(ctx context.Context, path string, out any) error {
	var raw json.RawMessage
	if _, err := c.api.Do(ctx, http.MethodGet, path, nil, nil, &raw); err != nil {
		return friendly(err)
	}
	t := strings.TrimSpace(string(raw))
	switch {
	case t == "" || t == "null" || t == "{}" || t == "[]":
		return json.Unmarshal([]byte("[]"), out)
	case strings.HasPrefix(t, "["):
		return json.Unmarshal(raw, out)
	case strings.HasPrefix(t, "{"):
		var e apiError
		if json.Unmarshal(raw, &e) == nil && e.failed() {
			return e.err()
		}
		return json.Unmarshal([]byte("["+t+"]"), out)
	}
	return errors.New("unexpected answer from mailcow")
}

// flex reads a value mailcow sends as a string or a number.
type flex string

func (f *flex) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*f = flex(s)
		return nil
	}
	var n json.Number
	if json.Unmarshal(b, &n) == nil {
		*f = flex(n.String())
		return nil
	}
	var v bool
	if json.Unmarshal(b, &v) == nil {
		if v {
			*f = "1"
		} else {
			*f = "0"
		}
	}
	return nil
}

func (f flex) int() int64 {
	n, _ := strconv.ParseFloat(string(f), 64)
	return int64(n)
}

func (f flex) on() bool { return f != "" && f != "0" }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		Version string `json:"version"`
		Type    string `json:"type"`
		Msg     any    `json:"msg"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/get/status/version", nil, nil, &v); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no mailcow API at this address"}
		}
		return sdk.Health{Status: "down", Message: friendly(err).Error()}
	}
	if e := (apiError{Type: v.Type, Msg: v.Msg}); e.failed() {
		return sdk.Health{Status: "down", Message: e.err().Error()}
	}
	if v.Version == "" {
		return sdk.Health{Status: "down", Message: "no mailcow API at this address"}
	}
	msg := "mailcow " + v.Version
	var ds []domain
	if c.list(ctx, "/get/domain/all", &ds) == nil {
		msg += fmt.Sprintf(" · %d domains", len(ds))
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Domain  string `json:"domain"`
	Active  *bool  `json:"active"`
	Mailbox string `json:"mailbox"`
	SignIn  *bool  `json:"signIn"`
}

func cleanDomain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if len(s) > 253 || !domainRe.MatchString(s) {
		return "", errors.New("the domain is a name like example.com")
	}
	return s, nil
}

func cleanAddress(s string) (local, dom string, err error) {
	s = strings.ToLower(strings.TrimSpace(s))
	i := strings.LastIndexByte(s, '@')
	if i <= 0 || len(s) > 254 {
		return "", "", errors.New("the mailbox is an address like jane@example.com")
	}
	local = s[:i]
	if !localRe.MatchString(local) || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return "", "", errors.New("the mailbox is an address like jane@example.com")
	}
	if dom, err = cleanDomain(s[i+1:]); err != nil {
		return "", "", errors.New("the mailbox is an address like jane@example.com")
	}
	return local, dom, nil
}

// domainOf is the domain part of an address, or "" (for <> and the like).
func domainOf(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		return strings.ToLower(strings.Trim(addr[i+1:], "> "))
	}
	return ""
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p input
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if strings.TrimSpace(p.Domain) != "" {
		if p.Domain, err = cleanDomain(p.Domain); err != nil {
			return sdk.Result{}, err
		}
	}
	switch call.Action {
	case "status":
		return c.status(ctx)
	case "domains":
		return c.domains(ctx)
	case "mailboxes":
		return c.mailboxes(ctx, p)
	case "aliases":
		return c.aliases(ctx, p)
	case "quarantine":
		return c.quarantine(ctx)
	case "queue":
		return c.queue(ctx)
	case "flush_queue":
		return c.flush(ctx, call)
	case "disable_mailbox", "enable_mailbox":
		local, dom, err := cleanAddress(p.Mailbox)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.setActive(ctx, call, p, local, dom)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) status(ctx context.Context) (sdk.Result, error) {
	var v struct {
		Version string `json:"version"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/get/status/version", nil, nil, &v); err != nil {
		return sdk.Result{}, friendly(err)
	}
	out := map[string]any{"version": v.Version}
	var cs map[string]struct {
		Container string `json:"container"`
		Image     string `json:"image"`
		State     string `json:"state"`
		StartedAt string `json:"started_at"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/get/status/containers", nil, nil, &cs); err == nil {
		list := []map[string]any{}
		running := 0
		for name, x := range cs {
			if x.State == "running" {
				running++
			}
			list = append(list, map[string]any{"name": name, "image": x.Image, "state": x.State, "startedAt": x.StartedAt})
		}
		sort.Slice(list, func(i, j int) bool { return list[i]["name"].(string) < list[j]["name"].(string) })
		out["containers"], out["running"] = list, running
	}
	return sdk.JSON(out)
}

type domain struct {
	Name           string `json:"domain_name"`
	Description    string `json:"description"`
	Active         flex   `json:"active"`
	BackupMX       flex   `json:"backupmx"`
	RelayAll       flex   `json:"relay_all_recipients"`
	Mailboxes      flex   `json:"mboxes_in_domain"`
	MaxMailboxes   flex   `json:"max_num_mboxes_for_domain"`
	Aliases        flex   `json:"aliases_in_domain"`
	MaxAliases     flex   `json:"max_num_aliases_for_domain"`
	QuotaUsed      flex   `json:"quota_used_in_domain"`
	MaxQuota       flex   `json:"max_quota_for_domain"`
	MaxMailboxSize flex   `json:"max_quota_for_mbox"`
	Messages       flex   `json:"msgs_total"`
	Bytes          flex   `json:"bytes_total"`
}

func (c *conn) domains(ctx context.Context) (sdk.Result, error) {
	var ds []domain
	if err := c.list(ctx, "/get/domain/all", &ds); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, d := range ds {
		row := map[string]any{"domain": d.Name, "active": d.Active.on(), "mailboxes": d.Mailboxes.int(), "maxMailboxes": d.MaxMailboxes.int(),
			"aliases": d.Aliases.int(), "maxAliases": d.MaxAliases.int(), "quotaUsedBytes": d.QuotaUsed.int(), "maxQuotaBytes": d.MaxQuota.int(),
			"maxMailboxBytes": d.MaxMailboxSize.int(), "messages": d.Messages.int(), "storedBytes": d.Bytes.int(), "backupMx": d.BackupMX.on(), "relayAllRecipients": d.RelayAll.on()}
		if d.Description != "" {
			row["description"] = d.Description
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

type mailbox struct {
	Username  string `json:"username"`
	Name      string `json:"name"`
	Domain    string `json:"domain"`
	LocalPart string `json:"local_part"`
	Active    flex   `json:"active"`
	ActiveInt flex   `json:"active_int"`
	Quota     flex   `json:"quota"`
	QuotaUsed flex   `json:"quota_used"`
	Percent   flex   `json:"percent_in_use"`
	Messages  flex   `json:"messages"`
	// Password hashes, app passwords, sender ACLs and attributes aren't
	// decoded.
}

// level is the mailbox's active value: "0" disabled, "1" active, "2"
// receives mail but can't sign in. active_int is preferred, since some
// mailcow versions send "active" as display text.
func (b mailbox) level() string {
	v := b.ActiveInt
	if v == "" {
		v = b.Active
	}
	switch v {
	case "0", "1", "2":
		return string(v)
	}
	return ""
}

func stateOf(level string) string {
	switch level {
	case "0":
		return "disabled"
	case "1":
		return "active"
	case "2":
		return "active, sign-in disallowed"
	}
	return "unknown"
}

func (b mailbox) state() string { return stateOf(b.level()) }

func (b mailbox) on() bool { l := b.level(); return l == "1" || l == "2" }

func (c *conn) mailboxes(ctx context.Context, p input) (sdk.Result, error) {
	path := "/get/mailbox/all"
	if p.Domain != "" {
		path += "/" + url.PathEscape(p.Domain)
	}
	var bs []mailbox
	if err := c.list(ctx, path, &bs); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, b := range bs {
		if p.Domain != "" && !strings.EqualFold(b.Domain, p.Domain) {
			continue
		}
		if p.Active != nil && b.on() != *p.Active {
			continue
		}
		row := map[string]any{"address": b.Username, "name": b.Name, "domain": b.Domain, "active": b.on(), "state": b.state(),
			"quotaBytes": b.Quota.int(), "usedBytes": b.QuotaUsed.int(), "percentUsed": b.Percent.int(), "messages": b.Messages.int()}
		out = append(out, row)
	}
	return sdk.JSON(map[string]any{"total": len(out), "mailboxes": out})
}

func (c *conn) aliases(ctx context.Context, p input) (sdk.Result, error) {
	var as []struct {
		ID       flex   `json:"id"`
		Address  string `json:"address"`
		Goto     string `json:"goto"`
		Domain   string `json:"domain"`
		Active   flex   `json:"active"`
		CatchAll flex   `json:"is_catch_all"`
	}
	if err := c.list(ctx, "/get/alias/all", &as); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, a := range as {
		if p.Domain != "" && !strings.EqualFold(a.Domain, p.Domain) {
			continue
		}
		var to []string
		for _, g := range strings.Split(a.Goto, ",") {
			if g = strings.TrimSpace(g); g != "" {
				to = append(to, g)
			}
		}
		out = append(out, map[string]any{"id": a.ID.int(), "address": a.Address, "domain": a.Domain, "goto": to, "active": a.Active.on(), "catchAll": a.CatchAll.on()})
	}
	return sdk.JSON(map[string]any{"total": len(out), "aliases": out})
}

func top(counts map[string]int, n int) []map[string]any {
	type kv struct {
		k string
		v int
	}
	var l []kv
	for k, v := range counts {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool { return l[i].v > l[j].v || (l[i].v == l[j].v && l[i].k < l[j].k) })
	out := []map[string]any{}
	for i, x := range l {
		if i == n {
			break
		}
		out = append(out, map[string]any{"domain": x.k, "count": x.v})
	}
	return out
}

func (c *conn) quarantine(ctx context.Context) (sdk.Result, error) {
	// Decoded field by field: subjects and the addresses are never kept.
	var qs []struct {
		ID      flex   `json:"id"`
		Created flex   `json:"created"`
		Score   flex   `json:"score"`
		Virus   flex   `json:"virus_flag"`
		Sender  string `json:"sender"`
		Rcpt    string `json:"rcpt"`
	}
	if err := c.list(ctx, "/get/quarantine/all", &qs); err != nil {
		return sdk.Result{}, err
	}
	senders, rcpts := map[string]int{}, map[string]int{}
	items := []map[string]any{}
	virus := 0
	for _, q := range qs {
		if q.Virus.on() {
			virus++
		}
		sd, rd := domainOf(q.Sender), domainOf(q.Rcpt)
		if sd != "" {
			senders[sd]++
		}
		if rd != "" {
			rcpts[rd]++
		}
		if len(items) < 100 {
			score, _ := strconv.ParseFloat(string(q.Score), 64)
			it := map[string]any{"id": q.ID.int(), "score": score, "virus": q.Virus.on(), "senderDomain": sd, "recipientDomain": rd}
			if t := q.Created.int(); t > 0 {
				it["created"] = time.Unix(t, 0).UTC().Format(time.RFC3339)
			}
			items = append(items, it)
		}
	}
	return sdk.JSON(map[string]any{"total": len(qs), "virus": virus, "bySenderDomain": top(senders, 20), "byRecipientDomain": top(rcpts, 20), "items": items})
}

// queued is one queued message; its id is never passed on, nor anything
// but the domains of its addresses.
type queued struct {
	Arrival    flex   `json:"arrival_time"`
	Size       flex   `json:"message_size"`
	Queue      string `json:"queue_name"`
	Sender     string `json:"sender"`
	Recipients []any  `json:"recipients"`
}

func (c *conn) readQueue(ctx context.Context) ([]queued, error) {
	var qs []queued
	err := c.list(ctx, "/get/mailq/all", &qs)
	return qs, err
}

func (c *conn) queue(ctx context.Context) (sdk.Result, error) {
	qs, err := c.readQueue(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	byQueue, senders, rcpts := map[string]int{}, map[string]int{}, map[string]int{}
	var size, oldest int64
	for _, q := range qs {
		byQueue[q.Queue]++
		size += q.Size.int()
		if t := q.Arrival.int(); t > 0 && (oldest == 0 || t < oldest) {
			oldest = t
		}
		if d := domainOf(q.Sender); d != "" {
			senders[d]++
		}
		for _, r := range q.Recipients {
			// A recipient is an address, or {"address":…,"delay_reason":…}.
			var a string
			switch v := r.(type) {
			case string:
				a = v
			case map[string]any:
				a, _ = v["address"].(string)
			}
			if d := domainOf(a); d != "" {
				rcpts[d]++
			}
		}
	}
	out := map[string]any{"total": len(qs), "byQueue": byQueue, "totalBytes": size, "bySenderDomain": top(senders, 20), "byRecipientDomain": top(rcpts, 20)}
	if oldest > 0 {
		out["oldest"] = time.Unix(oldest, 0).UTC().Format(time.RFC3339)
	}
	return sdk.JSON(out)
}

// result checks the answer to an add/edit/delete call: a list of
// {"type":"success"|"danger"|"error","msg":…}.
func result(raw json.RawMessage) error {
	var list []apiError
	if json.Unmarshal(raw, &list) != nil {
		var one apiError
		if json.Unmarshal(raw, &one) != nil {
			return errors.New("unexpected answer from mailcow")
		}
		list = []apiError{one}
	}
	if len(list) == 0 {
		return errors.New("mailcow didn't confirm the change")
	}
	for _, e := range list {
		if e.failed() || e.Type != "success" {
			return e.err()
		}
	}
	return nil
}

// flushBody is what /edit/mailq reads: mailcow's API takes an edit's
// fields from "attr" (a bare {"action":"flush"}, as its API page shows,
// reaches the queue code without an action and flushes nothing).
var flushBody = map[string]any{"items": []string{}, "attr": map[string]string{"action": "flush"}}

func (c *conn) flush(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	qs, err := c.readQueue(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	deferred := 0
	for _, q := range qs {
		if q.Queue != "hold" {
			deferred++
		}
	}
	if deferred == 0 {
		return sdk.JSON(map[string]any{"queued": len(qs), "note": "nothing to change"})
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]int{"queued": len(qs)})
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Try delivering %d queued messages now", deferred),
			Changes: []sdk.Change{{Target: "Postfix queue", Op: "flush", Before: b}}}}, nil
	}
	var raw json.RawMessage
	if _, err := c.api.Do(ctx, http.MethodPost, "/edit/mailq", nil, flushBody, &raw); err != nil {
		return sdk.Result{}, friendly(err)
	}
	if err := result(raw); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"before": len(qs)}
	if after, err := c.readQueue(ctx); err == nil {
		out["after"] = len(after)
	}
	return sdk.JSON(out)
}

func (c *conn) getMailbox(ctx context.Context, addr string) (mailbox, error) {
	var bs []mailbox
	// "+" is escaped too: mailcow hands the path to PHP as a query
	// parameter, where a bare "+" would read as a space.
	if err := c.list(ctx, "/get/mailbox/"+strings.ReplaceAll(url.PathEscape(addr), "+", "%2B"), &bs); err != nil {
		return mailbox{}, err
	}
	for _, b := range bs {
		if strings.EqualFold(b.Username, addr) {
			return b, nil
		}
	}
	return mailbox{}, fmt.Errorf("there's no mailbox %s", addr)
}

// roleLocal reports whether a local part is a role account, also with a
// +tag (postmaster+x@ reaches postmaster@).
func roleLocal(local string) bool {
	base, _, _ := strings.Cut(local, "+")
	return protected[local] || protected[base]
}

// roleAliasTo returns a role address (postmaster@ and the like) that
// delivers to addr, or "".
func (c *conn) roleAliasTo(ctx context.Context, addr string) (string, error) {
	var as []struct {
		Address string `json:"address"`
		Goto    string `json:"goto"`
	}
	if err := c.list(ctx, "/get/alias/all", &as); err != nil {
		return "", err
	}
	for _, a := range as {
		local, _, ok := strings.Cut(strings.ToLower(strings.TrimSpace(a.Address)), "@")
		if !ok || !roleLocal(local) {
			continue
		}
		for _, g := range strings.Split(a.Goto, ",") {
			if strings.EqualFold(strings.TrimSpace(g), addr) {
				return strings.ToLower(strings.TrimSpace(a.Address)), nil
			}
		}
	}
	return "", nil
}

func (c *conn) setActive(ctx context.Context, call sdk.Call, p input, local, dom string) (sdk.Result, error) {
	enabling := call.Action == "enable_mailbox"
	addr := local + "@" + dom
	if roleLocal(local) && !c.allowAdmin {
		return sdk.Result{}, fmt.Errorf("%s is a role account; turn on allowAdminAccounts in the settings to change it", addr)
	}
	want := "0"
	if enabling {
		want = "1"
		if p.SignIn != nil && !*p.SignIn {
			want = "2"
		}
	} else if p.SignIn != nil {
		return sdk.Result{}, errors.New("signIn is only for enable_mailbox")
	}
	b, err := c.getMailbox(ctx, addr)
	if err != nil {
		return sdk.Result{}, err
	}
	before := b.level()
	if before == "" {
		// Without the exact state, undo couldn't put it back.
		return sdk.Result{}, fmt.Errorf("mailcow didn't say whether %s is active; nothing was changed", addr)
	}
	if before == want {
		return sdk.JSON(map[string]any{"mailbox": addr, "state": b.state(), "note": "nothing to change"})
	}
	if !c.allowAdmin {
		role, err := c.roleAliasTo(ctx, addr)
		if err != nil {
			return sdk.Result{}, fmt.Errorf("couldn't check whether a role address delivers to %s, so nothing was changed: %w", addr, err)
		}
		if role != "" {
			return sdk.Result{}, fmt.Errorf("%s receives the mail of %s, a role account; turn on allowAdminAccounts in the settings to change it", addr, role)
		}
	}
	verb := "Disable"
	if enabling {
		verb = "Enable"
	}
	if call.DryRun {
		bf, _ := json.Marshal(map[string]string{"state": stateOf(before)})
		af, _ := json.Marshal(map[string]string{"state": stateOf(want)})
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " " + addr, Changes: []sdk.Change{{Target: "mailbox " + addr, Op: strings.ToLower(verb), Before: bf, After: af}}}}, nil
	}
	var raw json.RawMessage
	body := map[string]any{"items": []string{addr}, "attr": map[string]string{"active": want}}
	if _, err := c.api.Do(ctx, http.MethodPost, "/edit/mailbox", nil, body, &raw); err != nil {
		return sdk.Result{}, friendly(err)
	}
	if err := result(raw); err != nil {
		return sdk.Result{}, err
	}
	after, err := c.getMailbox(ctx, addr)
	if err != nil {
		return sdk.Result{}, err
	}
	if after.level() != want {
		return sdk.Result{}, fmt.Errorf("mailcow answered, but %s is still %s", addr, after.state())
	}
	res, err := sdk.JSON(map[string]any{"mailbox": addr, "active": after.on(), "state": after.state()})
	// Undo puts back exactly the state it had.
	switch before {
	case "0":
		res.Undo = sdk.UndoWith("disable_mailbox", map[string]string{"mailbox": addr}, "Disable "+addr+" again")
	case "1":
		res.Undo = sdk.UndoWith("enable_mailbox", map[string]string{"mailbox": addr}, "Enable "+addr+" again")
	default:
		res.Undo = sdk.UndoWith("enable_mailbox", map[string]any{"mailbox": addr, "signIn": false}, "Set "+addr+" back to receiving mail without sign-in")
	}
	return res, err
}
