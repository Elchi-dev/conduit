package woodpecker

import (
	"strings"
	"testing"
)

// Commit messages and step errors are free text from the CI server, and
// some quote a credential: firstLine redacts it.
func TestFirstLineRedacts(t *testing.T) {
	got := firstLine("deploy with token=ghp_fake_abcdefghijklmnopqrstuvwxyz0 \nsecond line")
	if strings.Contains(got, "ghp_") || strings.Contains(got, "second") || !strings.HasPrefix(got, "deploy with ") {
		t.Fatalf("firstLine = %q", got)
	}
}
