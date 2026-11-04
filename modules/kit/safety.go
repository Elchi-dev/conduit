package kit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"strings"
)

// Authored newsletter HTML is refused when it holds something that runs
// code where the email is shown. Mail clients don't run scripts, but the
// web version of a campaign (its archive page, "view in browser") opens in
// a browser. What's refused: script, iframe, object, embed and applet
// elements; on… event handler attributes; and javascript:, vbscript: and
// data: URLs (other than data:image/…) in URL attributes. Everything else
// in authored HTML (styles, tables, images, links, forms) is kept.
var (
	activeTagRe = regexp.MustCompile(`(?i)<\s*/?\s*(script|iframe|object|embed|applet)\b`)
	// tagRe finds a start tag: its name, then everything up to the closing
	// >, where a quoted value may itself hold a >.
	tagRe = regexp.MustCompile(`(?i)<([a-z][^\s/>"']*)((?:[^>"']|"[^"]*"|'[^']*')*)`)
	// attrRe reads one attribute of a tag and its value, if any.
	attrRe = regexp.MustCompile(`([^\s"'>/=]+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s"'>]+))?`)
	// shaRe is a content fingerprint as previews show it.
	shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// urlAttrs are the attributes whose value a browser follows as a URL.
var urlAttrs = map[string]bool{"href": true, "src": true, "action": true, "formaction": true, "background": true, "poster": true,
	"xlink:href": true, "data": true, "lowsrc": true, "dynsrc": true, "codebase": true, "cite": true, "longdesc": true, "usemap": true}

// unsafeHTML says what in s would run code in a browser, or "" when nothing
// would.
func unsafeHTML(s string) string {
	if m := activeTagRe.FindStringSubmatch(s); m != nil {
		return "a " + strings.ToLower(m[1]) + " tag"
	}
	for _, t := range tagRe.FindAllStringSubmatch(s, -1) {
		for _, a := range attrRe.FindAllStringSubmatch(t[2], -1) {
			name := strings.ToLower(a[1])
			if strings.HasPrefix(name, "on") {
				return "an event handler (" + clip(name, 40) + ")"
			}
			if urlAttrs[name] && scriptURL(a[2]) {
				return "a script link (" + name + ")"
			}
		}
	}
	return ""
}

// scriptURL reports whether an attribute value is a URL that runs code, the
// way a browser reads it: entities decoded, quotes off, and the spaces and
// control characters it skips removed.
func scriptURL(v string) bool {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	v = strings.ToLower(strings.Map(func(r rune) rune {
		if r <= ' ' || r == 0x7f {
			return -1
		}
		return r
	}, html.UnescapeString(v)))
	return strings.HasPrefix(v, "javascript:") || strings.HasPrefix(v, "vbscript:") || (strings.HasPrefix(v, "data:") && !strings.HasPrefix(v, "data:image/"))
}

// fingerprint is the sha256 of what a send delivers (the fields in order),
// shown in the preview and required to send: the content approved is the
// content sent.
func fingerprint(fields ...any) string {
	b, _ := json.Marshal(fields)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// checkSHA validates a given fingerprint before anything is sent.
func checkSHA(s string) error {
	if s != "" && !shaRe.MatchString(s) {
		return fmt.Errorf("sha256 is the 64 lowercase hex digits from the preview")
	}
	return nil
}

// sameContent refuses to send when no fingerprint was given or when the
// content has changed since the one given.
func sameContent(what, given, now string) error {
	switch {
	case given == "":
		return fmt.Errorf("give the %s's sha256 from the preview (%s now), so that what's sent is what was approved", what, now)
	case given != now:
		return fmt.Errorf("the %s changed since it was previewed (its sha256 is %s now, not %s), so this is refused; preview it again", what, now, given)
	}
	return nil
}

// changedNote is added to a preview whose given fingerprint no longer matches.
func changedNote(what, given, now string) string {
	if given != "" && given != now {
		return fmt.Sprintf(" The %s changed since sha256 %s was taken, so running this call will be refused.", what, given)
	}
	return ""
}
