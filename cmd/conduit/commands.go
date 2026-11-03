package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// --- output ------------------------------------------------------------------

func printJSON(e *env, v any) error {
	enc := json.NewEncoder(e.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func table(e *env, header []string, rows [][]string) {
	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	if len(header) > 0 {
		fmt.Fprintln(tw, strings.Join(header, "\t"))
	}
	// A tab inside a cell would break the columns; the terminal writer
	// handles the rest of what a cell may hold.
	for _, r := range rows {
		cells := make([]string, len(r))
		for i, c := range r {
			cells[i] = strings.NewReplacer("\t", " ", "\n", " ").Replace(c)
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	tw.Flush()
}

// paint colours text on terminals unless NO_COLOR is set.
func (e *env) paint(code, s string) string {
	if !e.isTTY || e.getenv("NO_COLOR") != "" || e.json {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (e *env) risk(r string) string {
	switch r {
	case "destructive":
		return e.paint("31", r)
	case "write":
		return e.paint("33", r)
	}
	return r
}

func short(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

func when(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

// --- account -----------------------------------------------------------------

func prompt(e *env, r *bufio.Reader, label, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(e.stderr, "%s [%s]: ", label, def)
	} else {
		fmt.Fprintf(e.stderr, "%s: ", label)
	}
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		line = def
	}
	return line, nil
}

type me struct {
	User struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		Role  string `json:"role"`
	} `json:"user"`
	Actor struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"actor"`
	Scopes []string `json:"scopes"`
}

func cmdLogin(e *env, a *args) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	name := e.profileName(cfg)
	old := cfg.Profiles[name]
	in := bufio.NewReader(e.stdin)
	url := e.url
	if url == "" {
		def := old.URL
		if def == "" {
			def = "http://127.0.0.1:7600"
		}
		if url, err = prompt(e, in, "Conduit address", def); err != nil {
			return err
		}
	}
	key := e.key
	if key == "" {
		fmt.Fprintln(e.stderr, "Create a key in Conduit under API keys (an agent key for AI tools, a live key for scripts).")
		if key, err = prompt(e, in, "API key", ""); err != nil {
			return err
		}
	}
	if !strings.HasPrefix(key, "cdt_") {
		return usageError{"API keys start with cdt_"}
	}
	if w := plainHTTPWarning(url); w != "" {
		fmt.Fprintln(e.stderr, w)
	}
	var who me
	if _, err := newClient(url, key).do(e.ctx, http.MethodGet, "/me", nil, nil, &who); err != nil {
		return fmt.Errorf("that didn't work: %w", err)
	}
	cfg.Profiles[name] = profile{URL: strings.TrimRight(url, "/"), Key: key}
	if cfg.Default == "" {
		cfg.Default = name
	}
	path, err := saveConfig(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "Signed in to %s as %s (%s, key of %s). Saved to %s as profile %q.\n", url, who.Actor.Name, who.Actor.Kind, who.User.Email, path, name)
	return nil
}

func cmdLogout(e *env, _ *args) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	name := e.profileName(cfg)
	if _, ok := cfg.Profiles[name]; !ok {
		fmt.Fprintf(e.stdout, "No saved profile %q.\n", name)
		return nil
	}
	delete(cfg.Profiles, name)
	if cfg.Default == name {
		cfg.Default = ""
	}
	if _, err := saveConfig(cfg); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "Forgot profile %q. The key itself still works until you revoke it in Conduit.\n", name)
	return nil
}

func cmdWhoami(e *env, _ *args) error {
	c, err := e.connect()
	if err != nil {
		return err
	}
	var who me
	if _, err := c.do(e.ctx, http.MethodGet, "/me", nil, nil, &who); err != nil {
		return err
	}
	if e.json {
		return printJSON(e, who)
	}
	fmt.Fprintf(e.stdout, "%s (%s) at %s\nAccount: %s <%s>, %s\nScopes: %s\n", who.Actor.Name, who.Actor.Kind, c.base,
		who.User.Name, who.User.Email, who.User.Role, strings.Join(who.Scopes, " "))
	return nil
}

// --- modules -----------------------------------------------------------------

type actionSpec struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
	Reversible  bool   `json:"reversible"`
	DryRun      bool   `json:"dryRun"`
}

type manifest struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Description string       `json:"description"`
	Category    string       `json:"category"`
	Actions     []actionSpec `json:"actions"`
}

type instance struct {
	ID      string `json:"id"`
	Module  string `json:"module"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

func cmdModules(e *env, _ *args) error {
	c, err := e.connect()
	if err != nil {
		return err
	}
	var list []manifest
	if _, err := c.do(e.ctx, http.MethodGet, "/modules", nil, nil, &list); err != nil {
		return err
	}
	if e.json {
		return printJSON(e, list)
	}
	rows := [][]string{}
	for _, m := range list {
		rows = append(rows, []string{m.ID, m.Name, m.Category, strconv.Itoa(len(m.Actions)), short(m.Description, 60)})
	}
	table(e, []string{"ID", "NAME", "CATEGORY", "ACTIONS", "DESCRIPTION"}, rows)
	return nil
}

func instances(e *env, c *client, module string) ([]instance, error) {
	q := url.Values{}
	if module != "" {
		q.Set("module", module)
	}
	var list []instance
	_, err := c.do(e.ctx, http.MethodGet, "/instances", q, nil, &list)
	return list, err
}

func cmdInstances(e *env, a *args) error {
	c, err := e.connect()
	if err != nil {
		return err
	}
	list, err := instances(e, c, a.val("module"))
	if err != nil {
		return err
	}
	if e.json {
		return printJSON(e, list)
	}
	rows := [][]string{}
	for _, in := range list {
		state := "on"
		if !in.Enabled {
			state = "off"
		}
		rows = append(rows, []string{in.ID, in.Module, in.Name, state})
	}
	table(e, []string{"ID", "MODULE", "NAME", "STATE"}, rows)
	return nil
}

// resolveInstance accepts an instance id, or a module id when that module
// has exactly one instance (so `conduit run vault list` works).
func resolveInstance(e *env, c *client, ref string) (instance, error) {
	list, err := instances(e, c, "")
	if err != nil {
		return instance{}, err
	}
	var byModule []instance
	for _, in := range list {
		if in.ID == ref {
			return in, nil
		}
		if in.Module == ref || strings.EqualFold(in.Name, ref) {
			byModule = append(byModule, in)
		}
	}
	switch len(byModule) {
	case 1:
		return byModule[0], nil
	case 0:
		return instance{}, fmt.Errorf("no instance %q (see `conduit instances`)", ref)
	}
	ids := []string{}
	for _, in := range byModule {
		ids = append(ids, in.ID)
	}
	return instance{}, fmt.Errorf("%q matches several instances; use one of: %s", ref, strings.Join(ids, ", "))
}

func cmdActions(e *env, a *args) error {
	if len(a.pos) != 1 {
		return usageError{"name one instance"}
	}
	c, err := e.connect()
	if err != nil {
		return err
	}
	in, err := resolveInstance(e, c, a.pos[0])
	if err != nil {
		return err
	}
	var m manifest
	if _, err := c.do(e.ctx, http.MethodGet, "/modules/"+url.PathEscape(in.Module), nil, nil, &m); err != nil {
		return err
	}
	if e.json {
		return printJSON(e, m.Actions)
	}
	rows := [][]string{}
	for _, ac := range m.Actions {
		extra := []string{}
		if ac.Reversible {
			extra = append(extra, "undo")
		}
		if ac.DryRun {
			extra = append(extra, "dry-run")
		}
		rows = append(rows, []string{ac.Name, e.risk(ac.Risk), strings.Join(extra, ","), short(ac.Title, 50)})
	}
	table(e, []string{"ACTION", "RISK", "SUPPORTS", "TITLE"}, rows)
	return nil
}

// --- run -----------------------------------------------------------------------

// parseValue turns a command-line value into JSON: numbers, true/false,
// null, and JSON objects, arrays and quoted strings are taken as JSON;
// anything else is a string.
func parseValue(s string) any {
	switch s {
	case "true":
		return true
	case "false":
		return false
	case "null":
		return nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && !strings.ContainsAny(s, "xXeE_") && (len(s) == 1 || s[0] != '0' || strings.HasPrefix(s, "0.")) {
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i
		}
		return f
	}
	if len(s) > 0 && (s[0] == '{' || s[0] == '[' || s[0] == '"') {
		var v any
		if json.Unmarshal([]byte(s), &v) == nil {
			return v
		}
	}
	return s
}

// buildInput turns key=value pairs into an object; dotted keys nest
// (a.b=1 → {"a":{"b":1}}). key:=raw always takes raw as JSON.
func buildInput(pairs []string) (map[string]any, error) {
	out := map[string]any{}
	for _, p := range pairs {
		raw := false
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			return nil, usageError{fmt.Sprintf("%q isn't key=value", p)}
		}
		if strings.HasSuffix(k, ":") {
			raw, k = true, strings.TrimSuffix(k, ":")
		}
		if k == "" {
			return nil, usageError{fmt.Sprintf("%q has no key", p)}
		}
		var val any
		if raw {
			if err := json.Unmarshal([]byte(v), &val); err != nil {
				return nil, usageError{fmt.Sprintf("%s:= needs JSON: %v", k, err)}
			}
		} else {
			val = parseValue(v)
		}
		parts := strings.Split(k, ".")
		m := out
		for _, part := range parts[:len(parts)-1] {
			next, ok := m[part].(map[string]any)
			if !ok {
				next = map[string]any{}
				m[part] = next
			}
			m = next
		}
		m[parts[len(parts)-1]] = val
	}
	return out, nil
}

type outcome struct {
	Result struct {
		Output json.RawMessage `json:"output"`
		Plan   json.RawMessage `json:"plan"`
		Undo   *struct {
			Description string `json:"description"`
		} `json:"undo"`
	} `json:"result"`
	Audit struct {
		Seq    int64  `json:"seq"`
		Status string `json:"status"`
	} `json:"audit"`
	Approval *struct {
		ID        string    `json:"id"`
		ExpiresAt time.Time `json:"expiresAt"`
	} `json:"approval"`
}

func cmdRun(e *env, a *args) error {
	if len(a.pos) < 2 {
		return usageError{"name an instance and an action"}
	}
	var input any
	pairs := a.pos[2:]
	if f := a.val("input"); f != "" {
		if len(pairs) > 0 {
			return usageError{"use either --input or key=value pairs"}
		}
		var r io.Reader
		if f == "-" {
			r = e.stdin
		} else {
			fh, err := os.Open(f)
			if err != nil {
				return err
			}
			defer fh.Close()
			r = fh
		}
		b, err := io.ReadAll(io.LimitReader(r, 16<<20))
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &input); err != nil {
			return usageError{"--input must be JSON: " + err.Error()}
		}
	} else {
		m, err := buildInput(pairs)
		if err != nil {
			return err
		}
		input = m
	}
	c, err := e.connect()
	if err != nil {
		return err
	}
	in, err := resolveInstance(e, c, a.pos[0])
	if err != nil {
		return err
	}
	body := map[string]any{"input": input, "dryRun": a.bools["dry-run"], "wait": a.bools["wait"]}
	var raw json.RawMessage
	status, err := c.do(e.ctx, http.MethodPost, "/instances/"+url.PathEscape(in.ID)+"/actions/"+url.PathEscape(a.pos[1]), nil, body, &raw)
	if err != nil {
		return err
	}
	var out outcome
	_ = json.Unmarshal(raw, &out)
	if status == http.StatusAccepted && out.Approval != nil {
		if e.json {
			_ = printJSON(e, raw)
		} else {
			fmt.Fprintf(e.stdout, "Waiting for approval %s (expires %s). A person approves it in Conduit; it then runs by itself.\n", out.Approval.ID, when(out.Approval.ExpiresAt))
			fmt.Fprintf(e.stdout, "Check with: conduit approvals --pending\n")
		}
		return exitErr{code: exitPending}
	}
	if e.json {
		return printJSON(e, raw)
	}
	switch {
	case len(out.Result.Plan) > 0 && string(out.Result.Plan) != "null":
		fmt.Fprintln(e.stdout, "Preview (nothing changed):")
		printValue(e, out.Result.Plan)
	case len(out.Result.Output) > 0 && string(out.Result.Output) != "null":
		printValue(e, out.Result.Output)
	default:
		fmt.Fprintln(e.stdout, "Done.")
	}
	if out.Audit.Seq > 0 && !e.json {
		note := fmt.Sprintf("audit entry %d", out.Audit.Seq)
		if out.Result.Undo != nil {
			note += fmt.Sprintf("; undo with: conduit undo %d", out.Audit.Seq)
		}
		fmt.Fprintln(e.stderr, e.paint("2", note))
	}
	return nil
}

// printValue prints strings plainly and everything else as indented JSON.
func printValue(e *env, raw json.RawMessage) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		fmt.Fprintln(e.stdout, s)
		return
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		fmt.Fprintln(e.stdout, string(raw))
		return
	}
	_ = printJSON(e, v)
}

// --- approvals -------------------------------------------------------------------

type approval struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	Actor     struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	} `json:"actor"`
	Module   string `json:"module"`
	Instance string `json:"instance"`
	Action   string `json:"action"`
	Risk     string `json:"risk"`
	Status   string `json:"status"`
}

func cmdApprovals(e *env, a *args) error {
	c, err := e.connect()
	if err != nil {
		return err
	}
	q := url.Values{}
	if a.bools["pending"] {
		q.Set("status", "pending")
	}
	var list []approval
	if _, err := c.do(e.ctx, http.MethodGet, "/approvals", q, nil, &list); err != nil {
		return err
	}
	if e.json {
		return printJSON(e, list)
	}
	if len(list) == 0 {
		fmt.Fprintln(e.stdout, "Nothing here.")
		return nil
	}
	rows := [][]string{}
	for _, ap := range list {
		who := ap.Actor.Name
		if who == "" {
			who = ap.Actor.ID
		}
		rows = append(rows, []string{ap.ID, ap.Status, who, ap.Module + "." + ap.Action, e.risk(ap.Risk), when(ap.CreatedAt)})
	}
	table(e, []string{"ID", "STATUS", "WHO", "ACTION", "RISK", "ASKED"}, rows)
	return nil
}

func cmdDecide(approve bool) func(*env, *args) error {
	return func(e *env, a *args) error {
		if len(a.pos) != 1 {
			return usageError{"name one approval id"}
		}
		c, err := e.connect()
		if err != nil {
			return err
		}
		verb := "deny"
		if approve {
			verb = "approve"
		}
		if _, err := c.do(e.ctx, http.MethodPost, "/approvals/"+url.PathEscape(a.pos[0])+"/"+verb, nil, nil, nil); err != nil {
			var ae *apiError
			if errors.As(err, &ae) && ae.Status == http.StatusForbidden {
				return exitErr{code: exitDenied, msg: "conduit: only a signed-in person can decide approvals, in the app or on the phone; API keys can't. (" + ae.Error() + ")"}
			}
			return err
		}
		fmt.Fprintf(e.stdout, "%sd %s.\n", strings.ToUpper(verb[:1])+verb[1:], a.pos[0])
		return nil
	}
}

// --- audit -----------------------------------------------------------------------

type auditEntry struct {
	Seq   int64     `json:"seq"`
	At    time.Time `json:"at"`
	Actor struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"actor"`
	Module   string `json:"module"`
	Instance string `json:"instance"`
	Action   string `json:"action"`
	Risk     string `json:"risk"`
	Status   string `json:"status"`
	Error    string `json:"error"`
	Undo     any    `json:"undo"`
	UndoneBy *int64 `json:"undoneBy"`
}

func (e *env) auditRow(x auditEntry) []string {
	who := x.Actor.Name
	if who == "" {
		who = x.Actor.Kind + ":" + x.Actor.ID
	}
	status := x.Status
	switch x.Status {
	case "error", "denied":
		status = e.paint("31", x.Status)
	}
	note := short(x.Error, 50)
	if x.UndoneBy != nil {
		note = fmt.Sprintf("undone by %d", *x.UndoneBy)
	} else if x.Undo != nil && note == "" {
		note = "can undo"
	}
	return []string{strconv.FormatInt(x.Seq, 10), when(x.At), who, x.Module + "." + x.Action, status, note}
}

func cmdAudit(e *env, a *args) error {
	c, err := e.connect()
	if err != nil {
		return err
	}
	q := url.Values{}
	if m := a.val("module"); m != "" {
		q.Set("module", m)
	}
	limit := a.val("limit")
	if limit == "" {
		limit = "30"
	}
	if n, err := strconv.Atoi(limit); err != nil || n < 1 {
		return usageError{"--limit is a positive number"}
	}
	q.Set("limit", limit)
	var list []auditEntry
	if _, err := c.do(e.ctx, http.MethodGet, "/audit", q, nil, &list); err != nil {
		return err
	}
	header := []string{"SEQ", "AT", "WHO", "ACTION", "STATUS", "NOTE"}
	if !a.bools["follow"] {
		if e.json {
			return printJSON(e, list)
		}
		rows := [][]string{}
		for _, x := range list {
			rows = append(rows, e.auditRow(x))
		}
		table(e, header, rows)
		return nil
	}
	// Follow: oldest first, then new entries as they appear.
	var last int64
	for i := len(list) - 1; i >= 0; i-- {
		e.printAudit(list[i])
		last = max(last, list[i].Seq)
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return nil
		case <-t.C:
		}
		q.Set("limit", "200")
		var fresh []auditEntry
		if _, err := c.do(e.ctx, http.MethodGet, "/audit", q, nil, &fresh); err != nil {
			if e.ctx.Err() != nil {
				return nil
			}
			fmt.Fprintf(e.stderr, "conduit: %s (retrying)\n", err)
			continue
		}
		for i := len(fresh) - 1; i >= 0; i-- {
			if fresh[i].Seq > last {
				e.printAudit(fresh[i])
				last = fresh[i].Seq
			}
		}
	}
}

func (e *env) printAudit(x auditEntry) {
	if e.json {
		b, _ := json.Marshal(x)
		fmt.Fprintln(e.stdout, string(b))
		return
	}
	fmt.Fprintln(e.stdout, strings.Join(e.auditRow(x), "  "))
}

func cmdUndo(e *env, a *args) error {
	if len(a.pos) != 1 {
		return usageError{"name one audit entry number"}
	}
	if _, err := strconv.ParseInt(a.pos[0], 10, 64); err != nil {
		return usageError{"audit entries are numbers"}
	}
	c, err := e.connect()
	if err != nil {
		return err
	}
	var raw json.RawMessage
	status, err := c.do(e.ctx, http.MethodPost, "/audit/"+a.pos[0]+"/undo", nil, nil, &raw)
	if err != nil {
		return err
	}
	var out outcome
	_ = json.Unmarshal(raw, &out)
	if e.json {
		_ = printJSON(e, raw)
	}
	if status == http.StatusAccepted && out.Approval != nil {
		if !e.json {
			fmt.Fprintf(e.stdout, "Waiting for approval %s.\n", out.Approval.ID)
		}
		return exitErr{code: exitPending}
	}
	if !e.json {
		fmt.Fprintf(e.stdout, "Undone (audit entry %d).\n", out.Audit.Seq)
	}
	return nil
}

// --- events ----------------------------------------------------------------------

func cmdEvents(e *env, a *args) error {
	c, err := e.connect()
	if err != nil {
		return err
	}
	if !e.json {
		fmt.Fprintf(e.stderr, "Following events from %s (Ctrl-C to stop)\n", c.base)
	}
	return c.stream(e.ctx, a.val("type"), func(ev sseEvent) { e.printEvent(ev) }, func(err error, wait time.Duration) {
		fmt.Fprintf(e.stderr, "conduit: %s; reconnecting in %s\n", err, wait)
	})
}

func (e *env) printEvent(ev sseEvent) {
	if e.json {
		fmt.Fprintln(e.stdout, ev.Data)
		return
	}
	var env struct {
		Type     string          `json:"type"`
		Module   string          `json:"module"`
		Instance string          `json:"instance"`
		At       time.Time       `json:"at"`
		Data     json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal([]byte(ev.Data), &env)
	typ := env.Type
	if typ == "" {
		typ = ev.Type
	}
	at := env.At
	if at.IsZero() {
		at = time.Now()
	}
	data := strings.TrimSpace(string(env.Data))
	if data == "null" {
		data = ""
	}
	fmt.Fprintf(e.stdout, "%s  %s  %s  %s\n", at.Local().Format("15:04:05"), e.paint("1", typ), env.Module, short(data, 160))
}

// --- vault, automations, panic -------------------------------------------------------

func cmdVault(e *env, a *args) error {
	if len(a.pos) != 1 || a.pos[0] != "list" {
		return usageError{"the only vault command is `conduit vault list`; values are never shown here"}
	}
	c, err := e.connect()
	if err != nil {
		return err
	}
	in, err := resolveInstance(e, c, "vault")
	if err != nil {
		return err
	}
	var out outcome
	status, err := c.do(e.ctx, http.MethodPost, "/instances/"+url.PathEscape(in.ID)+"/actions/list", nil, map[string]any{"input": map[string]any{}}, &out)
	if err != nil {
		return err
	}
	if status == http.StatusAccepted {
		return exitErr{code: exitPending, msg: "Listing secrets is waiting for approval."}
	}
	var secrets []struct {
		Name        string `json:"name"`
		Kind        string `json:"kind"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(out.Result.Output, &secrets)
	if e.json {
		return printJSON(e, secrets)
	}
	rows := [][]string{}
	for _, s := range secrets {
		rows = append(rows, []string{s.Name, s.Kind, short(s.Description, 60)})
	}
	table(e, []string{"NAME", "KIND", "DESCRIPTION"}, rows)
	return nil
}

func cmdAutomations(e *env, a *args) error {
	if len(a.pos) == 0 {
		a.pos = []string{"list"}
	}
	c, err := e.connect()
	if err != nil {
		return err
	}
	switch a.pos[0] {
	case "list":
		var list []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
			Trusted bool   `json:"trusted"`
			Trigger struct {
				Kind string `json:"kind"`
			} `json:"trigger"`
		}
		if _, err := c.do(e.ctx, http.MethodGet, "/automations", nil, nil, &list); err != nil {
			return err
		}
		if e.json {
			return printJSON(e, list)
		}
		rows := [][]string{}
		for _, x := range list {
			state := "on"
			if !x.Enabled {
				state = "off"
			}
			rows = append(rows, []string{x.ID, x.Name, x.Trigger.Kind, state})
		}
		table(e, []string{"ID", "NAME", "TRIGGER", "STATE"}, rows)
		return nil
	case "run":
		if len(a.pos) != 2 {
			return usageError{"name one automation id"}
		}
		var run json.RawMessage
		if _, err := c.do(e.ctx, http.MethodPost, "/automations/"+url.PathEscape(a.pos[1])+"/run", nil, map[string]any{}, &run); err != nil {
			return err
		}
		if e.json {
			return printJSON(e, run)
		}
		var r struct {
			ID     string `json:"id"`
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		_ = json.Unmarshal(run, &r)
		fmt.Fprintf(e.stdout, "Run %s: %s %s\n", r.ID, r.Status, r.Error)
		if r.Status == "error" {
			return exitErr{code: exitError}
		}
		if r.Status == "denied" {
			return exitErr{code: exitDenied}
		}
		return nil
	}
	return usageError{"automations list | automations run <id>"}
}

func cmdPanic(e *env, a *args) error {
	c, err := e.connect()
	if err != nil {
		return err
	}
	if !a.bools["yes"] {
		fmt.Fprint(e.stderr, "This freezes every agent, key and automation, denies everything waiting, and revokes the key you're using. Type yes to go on: ")
		line, _ := bufio.NewReader(e.stdin).ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			return exitErr{code: exitError, msg: "Nothing was changed."}
		}
	}
	var out map[string]any
	if _, err := c.do(e.ctx, http.MethodPost, "/panic", nil, map[string]any{}, &out); err != nil {
		return err
	}
	if e.json {
		return printJSON(e, out)
	}
	fmt.Fprintln(e.stdout, "Emergency stop is on. A signed-in person lifts it in Conduit.")
	return nil
}
