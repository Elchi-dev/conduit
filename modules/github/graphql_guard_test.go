package github

import (
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// graphql_read must accept only documents whose operations are all queries,
// judged by a real parser: block strings and comments can't hide a mutation.
func TestGraphQLReadQueryOnly(t *testing.T) {
	refused := []string{
		// The review's proof of concept: a block-string marker in comments.
		"# \"\"\"\nmutation { addStar(input: {starrableId: \"R_1\"}) { clientMutationId } }\n# \"\"\"",
		"#\"\"\"\nmutation{deleteRepository:addStar(input:{starrableId:$id}){clientMutationId}}#\"\"\"",
		"mutation { addStar(input:{starrableId:\"x\"}) { clientMutationId } }",
		"query Q { viewer { login } }\nmutation M { x }",
		"subscription S { x }",
		"{ a(s: \"\"\"\n\"\"\") }\nmutation { x }",
		"{ a(s: \"\\\"\") } mutation { x }",
		// Unparseable documents are refused rather than guessed at.
		"{ viewer { login }",
		"",
		"fragment F on User { login }",
		"\"\"\" \"\"\" mutation { x }",
	}
	for _, q := range refused {
		if err := queryOnly(q); err == nil {
			t.Errorf("accepted %q", q)
		}
	}
	allowed := []string{
		"{ viewer { login } }",
		"query { viewer { login } } # mutation { x }",
		"query Q($q: String!) { search(query: $q, type: REPOSITORY, first: 1) { repositoryCount } }",
		`{ search(query: "mutation", type: REPOSITORY, first: 1) { repositoryCount } }`,
		"{ a(s: \"\"\"\nmutation { x }\n\"\"\") }",
		"query A { ...F } query B { viewer { id } } fragment F on Query { viewer { login } }",
		"# \"\"\"\n{ viewer { login } }\n# \"\"\"",
	}
	for _, q := range allowed {
		if err := queryOnly(q); err != nil {
			t.Errorf("refused %q: %v", q, err)
		}
	}
}

func TestGraphQLReadRefusesHiddenMutationEndToEnd(t *testing.T) {
	m, f := setupFake(t, false)
	n := len(f.calls)
	q := "# \"\"\"\nmutation { addStar(input: {starrableId: \"R_1\"}) { clientMutationId } }\n# \"\"\""
	if _, err := invoke(t, m, "graphql_read", map[string]any{"query": q}, false); err == nil || !strings.Contains(err.Error(), "graphql_mutate") {
		t.Fatalf("graphql_read ran it: %v", err)
	}
	if len(f.calls) != n {
		t.Fatalf("sent %v", f.calls[n:])
	}
}

// The generic writes reach merges, transfers, visibility and branch
// protection, which the dedicated actions rate destructive.
func TestGenericWritesAreDestructive(t *testing.T) {
	m := New()
	for _, name := range []string{"api_write", "api_delete", "graphql_mutate"} {
		s, ok := findSpec(m, name)
		if !ok || s.Risk != sdk.RiskDestructive {
			t.Errorf("%s: %+v", name, s)
		}
	}
}
