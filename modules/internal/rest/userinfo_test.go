package rest

import "testing"

func TestStripUserinfo(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/org/repo.git":                 "https://github.com/org/repo.git",
		"https://user:ghp_secret@github.com/org/repo.git": "https://github.com/org/repo.git",
		"https://ghp_secret@gitlab.com/x":                 "https://gitlab.com/x",
		"git@github.com:org/repo.git":                     "github.com:org/repo.git",
		"https://u:p%zz@host/x":                           "https://host/x",
		"oci://registry.example.com/charts":               "oci://registry.example.com/charts",
		"":                                                "",
	} {
		if got := StripUserinfo(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}
