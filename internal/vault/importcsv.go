package vault

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Imported is one entry read from a password manager's CSV export.
type Imported struct {
	Name     string // vault name, e.g. "bitwarden/github/password"
	Kind     Kind
	Value    string
	Title    string // the entry's title in the export
	Username string
	URL      string
}

// Header aliases across the common exports: Bitwarden, 1Password, KeePass
// and KeePassXC, LastPass, Proton Pass, Chrome, Edge, Firefox and Safari.
var csvAliases = map[string][]string{
	"title":    {"name", "title", "account", "item name"},
	"url":      {"login_uri", "url", "website", "web site", "origin", "urls"},
	"username": {"login_username", "username", "login name", "user name", "email"},
	"password": {"login_password", "password"},
	"notes":    {"notes", "note", "comments", "extra"},
	"totp":     {"login_totp", "totp", "otpauth", "one-time password", "otp", "two-factor secret"},
	"type":     {"type"},
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s string) string {
	s = strings.Trim(slugRe.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > 48 {
		s = strings.Trim(s[:48], "-")
	}
	return s
}

// ParseCSVExport reads a password manager's CSV export and returns the
// secrets to store under prefix: one "password" per login, a "totp" where a
// two-factor secret is present, and a "note" for secure notes. Usernames and
// addresses go into the descriptions, never into values.
func ParseCSVExport(r io.Reader, prefix string) ([]Imported, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	head, err := cr.Read()
	if err != nil {
		return nil, errors.New("that isn't a CSV file with a header row")
	}
	col := map[string]int{}
	for i, h := range head {
		h = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\uFEFF")))
		for field, names := range csvAliases {
			for _, n := range names {
				if h == n {
					if _, seen := col[field]; !seen {
						col[field] = i
					}
				}
			}
		}
	}
	if _, ok := col["password"]; !ok {
		if _, ok := col["notes"]; !ok {
			return nil, errors.New("no password or notes column found; export as CSV from Bitwarden, 1Password, KeePass, LastPass, Proton Pass or your browser")
		}
	}
	prefix = strings.Trim(strings.ToLower(prefix), "/")
	if prefix == "" {
		prefix = "imported"
	}
	get := func(rec []string, field string) string {
		if i, ok := col[field]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}
	used := map[string]int{}
	var out []Imported
	line := 1
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		line++
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		title, user, url := get(rec, "title"), get(rec, "username"), get(rec, "url")
		pw, notes, totp := get(rec, "password"), get(rec, "notes"), get(rec, "totp")
		base := slug(title)
		if base == "" {
			base = slug(strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://"))
		}
		if base == "" {
			base = "entry"
		}
		used[base]++
		if n := used[base]; n > 1 {
			base = fmt.Sprintf("%s-%d", base, n)
		}
		mk := func(leaf string, k Kind, v string) Imported {
			return Imported{Name: prefix + "/" + base + "/" + leaf, Kind: k, Value: v, Title: title, Username: user, URL: url}
		}
		isNote := strings.EqualFold(get(rec, "type"), "note") || strings.EqualFold(get(rec, "type"), "securenote")
		switch {
		case pw != "":
			out = append(out, mk("password", KindPassword, pw))
		case isNote && notes != "":
			out = append(out, mk("note", KindNote, notes))
		}
		if totp != "" {
			out = append(out, mk("totp", KindToken, totp))
		}
	}
	return out, nil
}

// Description is the human line stored with an imported secret.
func (i Imported) Description() string {
	parts := []string{}
	if i.Title != "" {
		parts = append(parts, i.Title)
	}
	if i.Username != "" {
		parts = append(parts, "user "+i.Username)
	}
	if i.URL != "" {
		parts = append(parts, i.URL)
	}
	return strings.Join(parts, ", ")
}
