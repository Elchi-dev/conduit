// Package stalwart works with a Stalwart mail server through its JMAP
// management API, with an API key or an administrator's name and password:
// domains, accounts (users and groups) with their storage use, and a
// summary of the outgoing queue (counts and domains, never messages).
package stalwart

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Stalwart server.
type Config struct {
	URL      string `json:"url"`      // e.g. https://mail.example.com
	Token    string `json:"token"`    // secret:// API key (or OAuth access token)
	Username string `json:"username"` // or an administrator's name…
	Password string `json:"password"` // …and secret:// password
	// Fingerprint pins a self-signed certificate.
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Stalwart module.
func New() *Module { return &Module{} }

const capManage = "urn:stalwart:jmap"

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	idRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	userRe = regexp.MustCompile(`^[^\s:]{1,254}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "stalwart", Name: "Stalwart", Version: "0.1.0", Category: "Communication", Icon: "mail",
		Description: "Stalwart mail server: domains, accounts and groups with their storage use, and a summary of the outgoing queue.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://mail.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API key (Account, API keys in the web admin), or leave empty and use a name and password. It needs the sysDomain, sysAccount and sysQueuedMessage Get and Query permissions"},
			"username":{"type":"string","description":"An administrator's account name, instead of an API key"},
			"password":{"type":"string","x-secret":true,"description":"That account's password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "domains", Title: "Domains", Description: "Domains with their alias names, enabled, created, and how DKIM, certificates and DNS are managed. Never keys.", Risk: sdk.RiskRead},
			{Name: "accounts", Title: "Accounts", Description: "Users and groups: name, address, domain, role, storage used and allowed, alias addresses and group count. Never credentials. Addresses are personal data, so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Text in the name or address"},"type":{"type":"string","enum":["user","group"]},"limit":{"type":"integer","default":200,"minimum":1,"maximum":1000}}}`)},
			{Name: "queue", Title: "Outgoing queue", Description: "How many messages wait for delivery, by queue and recipient status, their total size, the oldest and the next retry, and counts by sender and recipient domain. Never addresses or content.", Risk: sdk.RiskRead, Sensitive: true},
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
	c.Username = strings.TrimSpace(c.Username)
	switch {
	case c.Token != "" && (c.Username != "" || c.Password != ""):
		return errors.New("use an API key or a name and password, not both")
	case c.Token != "":
		if !strings.HasPrefix(c.Token, "secret://") {
			return errors.New("store the API key in the vault and enter its secret:// reference")
		}
	case c.Username != "":
		if !userRe.MatchString(c.Username) {
			return errors.New("the account name is one word without colons")
		}
		if !strings.HasPrefix(c.Password, "secret://") {
			return errors.New("store the password in the vault and enter its secret:// reference")
		}
	default:
		return errors.New("enter an API key, or an administrator's name and password")
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
	tok, user, pw := c.Token, c.Username, c.Password
	p := strings.TrimRight(u.Path, "/")
	for _, s := range []string{"/jmap", "/admin", "/login"} {
		p = strings.TrimSuffix(p, s)
	}
	api := rest.New(u.Scheme+"://"+u.Host+p, func(ctx context.Context, r *http.Request) error {
		if tok != "" {
			t, err := h.Secret(ctx, tok)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
			return nil
		}
		s, err := h.Secret(ctx, pw)
		if err != nil {
			return err
		}
		r.SetBasicAuth(user, s)
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Stalwart refused the credentials")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the account isn't allowed to do this in Stalwart")
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

type session struct {
	Username        string                     `json:"username"`
	Capabilities    map[string]json.RawMessage `json:"capabilities"`
	PrimaryAccounts map[string]string          `json:"primaryAccounts"`
}

func (c *conn) session(ctx context.Context) (session, error) {
	var s session
	_, err := c.api.Do(ctx, http.MethodGet, "/jmap/session", nil, nil, &s)
	if rest.IsStatus(err, http.StatusNotFound) {
		_, err = c.api.Do(ctx, http.MethodGet, "/.well-known/jmap", nil, nil, &s)
	}
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return s, errors.New("no Stalwart JMAP server at this address")
		}
		return s, friendly(err)
	}
	if _, ok := s.Capabilities[capManage]; !ok {
		return s, errors.New("this server has no Stalwart management over JMAP (it came with Stalwart 0.16)")
	}
	if s.account() == "" {
		return s, errors.New("Stalwart's session names no account to manage")
	}
	return s, nil
}

// account is the id management calls are made for: the session's primary
// account for the management capability.
func (s session) account() string {
	for _, k := range []string{capManage, "urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"} {
		if a := s.PrimaryAccounts[k]; idRe.MatchString(a) {
			return a
		}
	}
	return ""
}

type jmap struct {
	c       *conn
	account string
}

// call makes one JMAP method call and decodes its arguments into out.
func (j jmap) call(ctx context.Context, method string, args map[string]any, out any) error {
	args["accountId"] = j.account
	body := map[string]any{
		"using":       []string{"urn:ietf:params:jmap:core", capManage},
		"methodCalls": []any{[]any{method, args, "c0"}},
	}
	var res struct {
		MethodResponses [][]json.RawMessage `json:"methodResponses"`
	}
	if _, err := j.c.api.Do(ctx, http.MethodPost, "/jmap/", nil, body, &res); err != nil {
		return friendly(err)
	}
	if len(res.MethodResponses) == 0 || len(res.MethodResponses[0]) < 2 {
		return errors.New("unexpected answer from Stalwart")
	}
	var name string
	_ = json.Unmarshal(res.MethodResponses[0][0], &name)
	if name == "error" {
		var e struct {
			Type        string `json:"type"`
			Description string `json:"description"`
		}
		_ = json.Unmarshal(res.MethodResponses[0][1], &e)
		switch e.Type {
		case "forbidden":
			obj := strings.TrimSuffix(strings.TrimPrefix(method, "x:"), "/get")
			obj = strings.TrimSuffix(obj, "/query")
			return fmt.Errorf("the account isn't allowed to read %s objects in Stalwart (it needs sys%sGet and sys%sQuery)", obj, obj, obj)
		case "unknownMethod":
			return errors.New("this server has no Stalwart management over JMAP (it came with Stalwart 0.16)")
		}
		msg := "Stalwart refused " + method
		if e.Type != "" {
			msg += ": " + clip(e.Type)
		}
		if e.Description != "" {
			msg += " (" + clip(e.Description) + ")"
		}
		return errors.New(msg)
	}
	if name != method {
		return errors.New("unexpected answer from Stalwart")
	}
	return json.Unmarshal(res.MethodResponses[0][1], out)
}

// all queries an object type and gets the listed properties of up to limit
// of them.
func (j jmap) all(ctx context.Context, obj string, filter map[string]any, limit int, props []string, out func(json.RawMessage) error) (int, error) {
	q := map[string]any{"calculateTotal": true, "limit": limit}
	if filter != nil {
		q["filter"] = filter
	}
	var qr struct {
		IDs   []string `json:"ids"`
		Total *int     `json:"total"`
	}
	if err := j.call(ctx, "x:"+obj+"/query", q, &qr); err != nil {
		return 0, err
	}
	total := len(qr.IDs)
	if qr.Total != nil {
		total = *qr.Total
	}
	ids := qr.IDs
	if len(ids) > limit {
		ids = ids[:limit]
	}
	for len(ids) > 0 {
		n := min(len(ids), 100)
		var gr struct {
			List []json.RawMessage `json:"list"`
		}
		if err := j.call(ctx, "x:"+obj+"/get", map[string]any{"ids": ids[:n], "properties": props}, &gr); err != nil {
			return 0, err
		}
		for _, x := range gr.List {
			if err := out(x); err != nil {
				return 0, err
			}
		}
		ids = ids[n:]
	}
	return total, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	s, err := c.session(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	j := jmap{c: c, account: s.account()}
	var qr struct {
		Total *int `json:"total"`
	}
	if err := j.call(ctx, "x:Domain/query", map[string]any{"calculateTotal": true, "limit": 1}, &qr); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + clip(s.Username)
	if qr.Total != nil {
		msg += fmt.Sprintf(" · %d domains", *qr.Total)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Search string `json:"search"`
	Type   string `json:"type"`
	Limit  *int   `json:"limit"`
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
	switch call.Action {
	case "domains", "accounts", "queue":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	// Inputs are checked before anything is sent.
	limit := 200
	if call.Action == "accounts" {
		p.Search = strings.TrimSpace(p.Search)
		if len(p.Search) > 200 || strings.ContainsAny(p.Search, "\r\n\x00") {
			return sdk.Result{}, errors.New("the search is one line of at most 200 characters")
		}
		if p.Type != "" && p.Type != "user" && p.Type != "group" {
			return sdk.Result{}, errors.New("type is user or group")
		}
		if p.Limit != nil {
			if *p.Limit < 1 || *p.Limit > 1000 {
				return sdk.Result{}, errors.New("limit is 1 to 1000")
			}
			limit = *p.Limit
		}
	}
	s, err := c.session(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	j := jmap{c: c, account: s.account()}
	switch call.Action {
	case "domains":
		return j.domains(ctx)
	case "accounts":
		return j.accounts(ctx, p, limit)
	default:
		return j.queue(ctx)
	}
}

// strSet is a JMAP set: Stalwart sends {"value": true, …}; a list is
// read too.
type strSet []string

func (s *strSet) UnmarshalJSON(b []byte) error {
	var l []string
	if json.Unmarshal(b, &l) == nil {
		*s = l
		return nil
	}
	var m map[string]bool
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	l = []string{}
	for k, on := range m {
		if on {
			l = append(l, k)
		}
	}
	sort.Strings(l)
	*s = l
	return nil
}

// list is a Stalwart list: an object keyed by position ({"0": …}); a JSON
// array is read too.
type list[T any] []T

func (l *list[T]) UnmarshalJSON(b []byte) error {
	var a []T
	if json.Unmarshal(b, &a) == nil {
		*l = a
		return nil
	}
	var m map[string]T
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) < len(keys[j])
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		a = append(a, m[k])
	}
	*l = a
	return nil
}

type typed struct {
	Type string `json:"@type"`
}

type domain struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Aliases     strSet `json:"aliases"`
	Enable      *bool  `json:"enable"`
	CreatedAt   string `json:"createdAt"`
	Description string `json:"description"`
	DKIM        typed  `json:"dkimManagement"`
	Certs       typed  `json:"certificateManagement"`
	DNS         typed  `json:"dnsManagement"`
	CatchAll    string `json:"catchAllAddress"`
	Relaying    bool   `json:"allowRelaying"`
	// The DNS zone file and anything key-related aren't requested.
}

var domainProps = []string{"id", "name", "aliases", "enable", "createdAt", "description", "dkimManagement", "certificateManagement", "dnsManagement", "catchAllAddress", "allowRelaying"}

func (j jmap) domainList(ctx context.Context) ([]domain, int, error) {
	var ds []domain
	total, err := j.all(ctx, "Domain", nil, 1000, domainProps, func(raw json.RawMessage) error {
		var d domain
		if err := json.Unmarshal(raw, &d); err != nil {
			return errors.New("unexpected domain from Stalwart")
		}
		ds = append(ds, d)
		return nil
	})
	return ds, total, err
}

func (j jmap) domains(ctx context.Context) (sdk.Result, error) {
	ds, total, err := j.domainList(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, d := range ds {
		row := map[string]any{"id": d.ID, "domain": d.Name, "aliases": append([]string{}, d.Aliases...), "enabled": d.Enable == nil || *d.Enable,
			"createdAt": d.CreatedAt, "dkim": d.DKIM.Type, "certificates": d.Certs.Type, "dns": d.DNS.Type, "catchAll": d.CatchAll != "", "allowRelaying": d.Relaying}
		if d.Description != "" {
			row["description"] = d.Description
		}
		out = append(out, row)
	}
	return sdk.JSON(map[string]any{"total": total, "domains": out})
}

var accountProps = []string{"id", "@type", "name", "domainId", "emailAddress", "usedDiskQuota", "quotas", "roles", "aliases", "memberGroupIds", "description", "createdAt"}

func (j jmap) accounts(ctx context.Context, p input, limit int) (sdk.Result, error) {
	ds, _, err := j.domainList(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	names := map[string]string{}
	for _, d := range ds {
		names[d.ID] = d.Name
	}
	var filter map[string]any
	if p.Search != "" {
		filter = map[string]any{"text": p.Search}
	}
	out := []map[string]any{}
	total, err := j.all(ctx, "Account", filter, limit, accountProps, func(raw json.RawMessage) error {
		// Field by field: credentials (password hashes, app passwords,
		// API keys, TOTP) are neither requested nor read.
		var a struct {
			ID          string           `json:"id"`
			Type        string           `json:"@type"`
			Name        string           `json:"name"`
			DomainID    string           `json:"domainId"`
			Email       string           `json:"emailAddress"`
			Used        int64            `json:"usedDiskQuota"`
			Quotas      map[string]int64 `json:"quotas"`
			Roles       typed            `json:"roles"`
			Description string           `json:"description"`
			CreatedAt   string           `json:"createdAt"`
			Groups      strSet           `json:"memberGroupIds"`
			Aliases     list[struct {
				Name     string `json:"name"`
				DomainID string `json:"domainId"`
				Enable   *bool  `json:"enable"`
			}] `json:"aliases"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return errors.New("unexpected account from Stalwart")
		}
		kind := strings.ToLower(a.Type)
		if p.Type != "" && kind != p.Type {
			return nil
		}
		row := map[string]any{"id": a.ID, "type": kind, "name": a.Name, "email": a.Email, "domain": names[a.DomainID], "role": a.Roles.Type,
			"usedBytes": a.Used, "groups": len(a.Groups), "createdAt": a.CreatedAt}
		if q, ok := a.Quotas["maxDiskQuota"]; ok && q > 0 {
			row["quotaBytes"] = q
			row["percentUsed"] = a.Used * 100 / q
		}
		var al []string
		for _, x := range a.Aliases {
			if x.Enable != nil && !*x.Enable {
				continue
			}
			d := names[x.DomainID]
			if d == "" {
				d = names[a.DomainID]
			}
			al = append(al, x.Name+"@"+d)
		}
		if al != nil {
			row["aliases"] = al
		}
		if a.Description != "" {
			row["description"] = a.Description
		}
		out = append(out, row)
		return nil
	})
	if err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"total": total, "accounts": out})
}

func domainOf(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		return strings.ToLower(strings.Trim(addr[i+1:], "<> "))
	}
	return ""
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

// queueProps leaves out the message itself (blobId), the submitting IP and
// the envelope id.
var queueProps = []string{"id", "createdAt", "nextRetry", "returnPath", "recipients", "size", "priority"}

func (j jmap) queue(ctx context.Context) (sdk.Result, error) {
	byQueue, byStatus, senders, rcpts := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	var size int64
	var oldest, next string
	total, err := j.all(ctx, "QueuedMessage", nil, 1000, queueProps, func(raw json.RawMessage) error {
		var q struct {
			CreatedAt  string `json:"createdAt"`
			NextRetry  string `json:"nextRetry"`
			ReturnPath string `json:"returnPath"`
			Size       int64  `json:"size"`
			Recipients map[string]struct {
				Queue  string `json:"queueName"`
				Status typed  `json:"status"`
			} `json:"recipients"`
		}
		if err := json.Unmarshal(raw, &q); err != nil {
			return errors.New("unexpected queued message from Stalwart")
		}
		size += q.Size
		if q.CreatedAt != "" && (oldest == "" || q.CreatedAt < oldest) {
			oldest = q.CreatedAt
		}
		if q.NextRetry != "" && (next == "" || q.NextRetry < next) {
			next = q.NextRetry
		}
		if d := domainOf(q.ReturnPath); d != "" {
			senders[d]++
		}
		for addr, r := range q.Recipients {
			if r.Queue != "" {
				byQueue[r.Queue]++
			}
			st := r.Status.Type
			if st == "" {
				st = "Scheduled"
			}
			byStatus[st]++
			if d := domainOf(addr); d != "" {
				rcpts[d]++
			}
		}
		return nil
	})
	if err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"total": total, "recipientsByQueue": byQueue, "recipientsByStatus": byStatus, "totalBytes": size,
		"bySenderDomain": top(senders, 20), "byRecipientDomain": top(rcpts, 20)}
	if total > 1000 {
		out["note"] = "the counts cover the first 1000 messages"
	}
	if oldest != "" {
		out["oldest"] = oldest
	}
	if next != "" {
		out["nextRetry"] = next
	}
	return sdk.JSON(out)
}
