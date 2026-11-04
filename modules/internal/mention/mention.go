// Package mention finds the @-mentions in a chat message, so a module can
// refuse wildcard mentions (which notify a whole room) and name the people
// a message reaches in its preview. It reads the forms Rocket.Chat,
// Nextcloud Talk and Zulip use: @name, @"name with spaces", @**Full
// Name**, @**Name|id**, @_**silent**, and @*user group*.
package mention

import (
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// wildcards notify everyone in a room, channel, stream or topic.
var wildcards = map[string]bool{
	"all": true, "here": true, "channel": true, "everyone": true, "stream": true, "topic": true,
}

// Found is what a message mentions.
type Found struct {
	// Wildcard is the first wildcard mention (@all, @here, @**all**, …) as
	// written, or "".
	Wildcard string
	// Names are the other people and groups mentioned, as written (@bob,
	// @**Kim Lee**, @*support*), sorted and without repeats.
	Names []string
}

// Find reads the mentions in text. An @ right after a letter, digit or one
// of _ . - (an e-mail address) isn't a mention.
func Find(text string) Found {
	var f Found
	seen := map[string]bool{}
	for i := 0; i < len(text); i++ {
		if text[i] != '@' {
			continue
		}
		if i > 0 {
			r, _ := utf8.DecodeLastRuneInString(text[:i])
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.' || r == '-' {
				continue
			}
		}
		name, raw := read(text[i+1:])
		if name == "" {
			continue
		}
		written := "@" + raw
		key := strings.ToLower(strings.TrimSpace(name))
		if j := strings.LastIndex(key, "|"); j >= 0 { // @**Name|id**
			key = strings.TrimSpace(key[:j])
		}
		if wildcards[key] {
			if f.Wildcard == "" {
				f.Wildcard = written
			}
			continue
		}
		if !seen[written] {
			seen[written] = true
			f.Names = append(f.Names, written)
		}
	}
	sort.Strings(f.Names)
	return f
}

// read takes the mention after an @: its name and the text as written.
func read(s string) (name, raw string) {
	// Zulip: @**name**, @_**name** (silent), @*group*, @_*group*.
	t := strings.TrimPrefix(s, "_")
	for _, d := range []string{"**", "*"} {
		if strings.HasPrefix(t, d) {
			rest := t[len(d):]
			if j := strings.Index(rest, d); j > 0 && !strings.Contains(rest[:j], "\n") {
				n := len(s) - len(t) + len(d) + j + len(d)
				return rest[:j], s[:n]
			}
		}
	}
	// Talk: @"name with spaces", @"group/id".
	if strings.HasPrefix(s, `"`) {
		if j := strings.Index(s[1:], `"`); j > 0 && !strings.Contains(s[1:1+j], "\n") {
			return s[1 : 1+j], s[:j+2]
		}
	}
	// @name: letters, digits and _ . -, plus / : for Talk's guest/ and
	// federated ids; a trailing . or - ends the sentence.
	j := 0
	for j < len(s) {
		r, n := utf8.DecodeRuneInString(s[j:])
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("_.-/:", r)) {
			break
		}
		j += n
	}
	n := strings.TrimRight(s[:j], ".-:/")
	return n, n
}

// Preview is a sentence naming who the message notifies, for a dry run's
// summary, or "".
func (f Found) Preview() string {
	if len(f.Names) == 0 {
		return ""
	}
	names := f.Names
	more := ""
	if len(names) > 20 {
		more = " and " + strconv.Itoa(len(names)-20) + " more"
		names = names[:20]
	}
	return "mentions " + strings.Join(names, ", ") + more + " (they're notified)"
}
