package mention

import (
	"reflect"
	"testing"
)

func TestFind(t *testing.T) {
	for _, c := range []struct {
		text     string
		wildcard string
		names    []string
	}{
		{"hi @bob and @alice.", "", []string{"@alice", "@bob"}},
		{"@bob @bob", "", []string{"@bob"}},
		{"mail bob@example.com", "", nil},
		{"@all please look", "@all", nil},
		{"hey @HERE", "@HERE", nil},
		{"(@channel)", "@channel", nil},
		{"@everyone", "@everyone", nil},
		{"cc @**all**", "@**all**", nil},
		{"cc @**everyone**", "@**everyone**", nil},
		{"cc @**channel**", "@**channel**", nil},
		{"cc @**stream**", "@**stream**", nil},
		{"cc @**topic**", "@**topic**", nil},
		{"cc @_**all**", "@_**all**", nil},
		{`cc @"all"`, `@"all"`, nil},
		{"cc @**Kim Lee** and @**Sam|12** and @*support*", "", []string{"@**Kim Lee**", "@**Sam|12**", "@*support*"}},
		{`ping @"Kim Lee" @"group/admins"`, "", []string{`@"Kim Lee"`, `@"group/admins"`}},
		{"a @ b", "", nil},
	} {
		f := Find(c.text)
		if f.Wildcard != c.wildcard || !reflect.DeepEqual(f.Names, c.names) {
			t.Errorf("%q: %+v", c.text, f)
		}
	}
	if p := Find("@bob").Preview(); p != "mentions @bob (they're notified)" {
		t.Fatal(p)
	}
}
