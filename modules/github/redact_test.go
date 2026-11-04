package github

import (
	"strings"
	"testing"
)

// A commit message is free text: a credential pasted in it is redacted.
func TestCommitRowRedactsMessage(t *testing.T) {
	var c ghCommit
	c.Commit.Message = "rotate key\n\nold: Bearer abcdefghijklmnopqrstuvwxyz0123"
	if m := c.row()["message"].(string); strings.Contains(m, "abcdefghij") || !strings.HasPrefix(m, "rotate key") {
		t.Fatalf("message = %q", m)
	}
}
