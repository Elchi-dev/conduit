package sops

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// As SOPS 3.9 writes it (4-space indentation).
const prodYAML = `# managed by sops
db:
    user: ENC[AES256_GCM,data:dXNlcg==,iv:aaaa,tag:bbbb,type:str]
    password: ENC[AES256_GCM,data:c2VjcmV0,iv:cccc,tag:dddd,type:str]
    port_unencrypted: "5432"
replicas:
    - host: ENC[AES256_GCM,data:aG9zdA==,iv:eeee,tag:ffff,type:str]
    - host: ENC[AES256_GCM,data:aG9zdDI=,iv:gggg,tag:hhhh,type:str]
tokens:
    - ENC[AES256_GCM,data:dG9r,iv:iiii,tag:jjjj,type:str]
"weird.key": ENC[AES256_GCM,data:eA==,iv:kkkk,tag:llll,type:str]
sops:
    kms:
        - arn: arn:aws:kms:eu-west-1:123456789012:key/abcd
          created_at: "2026-01-01T00:00:00Z"
          enc: AQICAHhKMSDATAKEYplaintextmustnotleak
          aws_profile: ""
    gcp_kms: []
    azure_kv: []
    hc_vault: []
    age:
        - recipient: age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBBR0VEQVRBS0VZ
            -----END AGE ENCRYPTED FILE-----
    lastmodified: "2026-02-03T04:05:06Z"
    mac: ENC[AES256_GCM,data:bWFj,iv:mmmm,tag:nnnn,type:str]
    pgp:
        - created_at: "2026-01-01T00:00:00Z"
          enc: |-
            -----BEGIN PGP MESSAGE-----

            wcBMA0PGPDATAKEY
            -----END PGP MESSAGE-----
          fp: 85D77543B3D624B63CEA9E6DBC17301B491B3F21
    unencrypted_suffix: _unencrypted
    version: 3.9.1
`

// Older SOPS (2-space indentation, list items flush with their key) with
// key groups.
const oldYAML = `api_key: ENC[AES256_GCM,data:YQ==,iv:a,tag:b,type:str]
sops:
  key_groups:
  - age:
    - recipient: age1groupkeygroupkeygroupkeygroupkeygroupkeygroupkeygroupk
      enc: |
        -----BEGIN AGE ENCRYPTED FILE-----
        R1JPVVBEQVRBS0VZ
        -----END AGE ENCRYPTED FILE-----
  - pgp:
    - fp: 1111222233334444555566667777888899990000
      created_at: '2020-01-01T00:00:00Z'
      enc: "-----BEGIN PGP MESSAGE-----\nQUOTEDDATAKEY\n-----END PGP MESSAGE-----"
  shamir_threshold: 2
  lastmodified: '2020-01-02T00:00:00Z'
  mac: ENC[AES256_GCM,data:bQ==,iv:a,tag:b,type:str]
  version: 3.5.0
`

const appJSON = `{
	"stripe": {"key": "ENC[AES256_GCM,data:c2s=,iv:a,tag:b,type:str]", "mode_unencrypted": "live"},
	"sops": {"kms": null, "age": [{"recipient": "age1jsonjsonjsonjsonjsonjsonjsonjsonjsonjsonjsonjsonjsonjso", "enc": "-----BEGIN AGE ENCRYPTED FILE-----\nSlNPTkRBVEFLRVk=\n-----END AGE ENCRYPTED FILE-----\n"}],
		"lastmodified": "2026-03-01T00:00:00Z", "mac": "ENC[AES256_GCM,data:bQ==,iv:a,tag:b,type:str]", "version": "3.9.0"}
}`

const dotenv = `DB_PASSWORD=ENC[AES256_GCM,data:cA==,iv:a,tag:b,type:str]
PLAIN_unencrypted=visible-plaintext-value
sops_age__list_0__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\nRU5WREFUQUtFWQ==\n-----END AGE ENCRYPTED FILE-----\n
sops_age__list_0__map_recipient=age1envenvenvenvenvenvenvenvenvenvenvenvenvenvenvenvenvenve
sops_lastmodified=2026-04-01T00:00:00Z
sops_mac=ENC[AES256_GCM,data:bQ==,iv:a,tag:b,type:str]
sops_unencrypted_suffix=_unencrypted
sops_version=3.9.1
`

const ini = `[database]
password = ENC[AES256_GCM,data:cA==,iv:a,tag:b,type:str]

[sops]
pgp__list_0__map_fp = AAAABBBBCCCCDDDDEEEEFFFF0000111122223333
pgp__list_0__map_enc = PGPINIDATAKEY
lastmodified = 2026-05-01T00:00:00Z
mac = ENC[AES256_GCM,data:bQ==,iv:a,tag:b,type:str]
version = 3.9.1
`

const sopsConfig = `creation_rules:
  - path_regex: secrets/prod\.yaml$
    encrypted_regex: ^(password|user)$
    age: >-
      age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq,
      age1other
  - path_regex: .*
    key_groups:
      - age:
          - age1groupkeygroupkeygroupkeygroupkeygroupkeygroupkeygroupk
        pgp:
          - 1111222233334444555566667777888899990000
`

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func setup(t *testing.T) (*Module, string) {
	dir := t.TempDir()
	write(t, dir, "secrets/prod.yaml", prodYAML)
	write(t, dir, "legacy/old.yml", oldYAML)
	write(t, dir, "app.enc.json", appJSON)
	write(t, dir, ".env", dotenv)
	write(t, dir, "conf/app.ini", ini)
	write(t, dir, "plain.yaml", "sops_is_mentioned: but this isn't encrypted\nkey: plaintext-value\n")
	write(t, dir, ".git/objects/x.yaml", prodYAML)
	write(t, dir, ".sops.yaml", sopsConfig)
	outside := t.TempDir()
	write(t, outside, "elsewhere.yaml", prodYAML)
	if err := os.Symlink(filepath.Join(outside, "elsewhere.yaml"), filepath.Join(dir, "link.yaml")); err != nil {
		t.Fatal(err)
	}
	m := New()
	raw, _ := json.Marshal(Config{Folder: dir})
	if err := m.Configure(context.Background(), fakehost.New(nil), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, dir
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in)})
}

// noValues fails when output carries anything from a value or data key.
func noValues(t *testing.T, out string) {
	t.Helper()
	for _, s := range []string{"ENC[", "dXNlcg", "c2VjcmV0", "5432", "DATAKEY", "BEGIN AGE", "BEGIN PGP", "visible-plaintext-value", "plaintext-value", `"live"`, "AQICAH"} {
		if strings.Contains(out, s) {
			t.Fatalf("output leaks %s: %s", s, out)
		}
	}
}

func TestSopsFiles(t *testing.T) {
	m, _ := setup(t)
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "5 encrypted file(s)" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "files", `{}`)
	out := string(r.Output)
	if err != nil {
		t.Fatal(err)
	}
	noValues(t, out)
	for _, want := range []string{`"path":".env"`, `"format":"dotenv"`, `"path":"app.enc.json"`, `"path":"conf/app.ini"`, `"format":"ini"`, `"path":"legacy/old.yml"`, `"path":"secrets/prod.yaml"`, `"aws_kms":1`, `"version":"3.9.1"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s: %s", want, out)
		}
	}
	for _, not := range []string{"plain.yaml", ".git", "link.yaml", ".sops.yaml"} {
		if strings.Contains(out, not) {
			t.Fatalf("listed %s: %s", not, out)
		}
	}
	r, _ = invoke(m, "files", `{"olderThanDays":365}`)
	if !strings.Contains(string(r.Output), "legacy/old.yml") || strings.Contains(string(r.Output), "prod.yaml") {
		t.Fatal(string(r.Output))
	}
}

func TestSopsFileMetadata(t *testing.T) {
	m, _ := setup(t)
	for _, c := range []struct {
		path string
		want []string
	}{
		{"secrets/prod.yaml", []string{`{"key":"db.user","encrypted":true}`, `{"key":"db.port_unencrypted","encrypted":false}`, `"key":"replicas[1].host"`, `"key":"tokens[0]"`, `"key":"\"weird.key\""`,
			`{"type":"age","id":"age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq"}`, `"type":"pgp","id":"85D77543B3D624B63CEA9E6DBC17301B491B3F21"`,
			`"id":"arn:aws:kms:eu-west-1:123456789012:key/abcd","created":"2026-01-01T00:00:00Z"`, `"lastModified":"2026-02-03T04:05:06Z"`, `"mac":true`, `"unencrypted_suffix":"_unencrypted"`}},
		{"legacy/old.yml", []string{`"group":0`, `"type":"pgp","id":"1111222233334444555566667777888899990000","created":"2020-01-01T00:00:00Z","group":1`, `"shamir_threshold":"2"`, `"version":"3.5.0"`}},
		{"./app.enc.json", []string{`"key":"stripe.key","encrypted":true`, `"key":"stripe.mode_unencrypted","encrypted":false`, `"format":"json"`}},
		{".env", []string{`"key":"DB_PASSWORD","encrypted":true`, `"key":"PLAIN_unencrypted","encrypted":false`, `"type":"age","id":"age1envenv`}},
		{"conf/app.ini", []string{`"key":"database.password","encrypted":true`, `"id":"AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"`}},
	} {
		r, err := invoke(m, "file", `{"path":"`+c.path+`"}`)
		out := string(r.Output)
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		noValues(t, out)
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Fatalf("%s: missing %s in %s", c.path, w, out)
			}
		}
		if strings.Contains(out, `"key":"sops`) {
			t.Fatalf("%s: listed the metadata as data: %s", c.path, out)
		}
	}
	for _, in := range []string{`{"path":"../etc/passwd"}`, `{"path":"/etc/passwd"}`, `{"path":"secrets/../../x"}`, `{"path":"link.yaml"}`, `{"path":"plain.yaml"}`, `{"path":""}`, `{"path":"a\nb"}`, `{"path":"nope.yaml"}`, `{"path":"secrets"}`} {
		if _, err := invoke(m, "file", in); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
}

func TestSopsRecipientsAndRules(t *testing.T) {
	m, dir := setup(t)
	write(t, dir, "norecip.yaml", "a: ENC[AES256_GCM,data:YQ==,iv:a,tag:b,type:str]\nsops:\n    lastmodified: \"2026-01-01T00:00:00Z\"\n    mac: ENC[x]\n    version: 3.9.1\n")
	r, err := invoke(m, "recipients", `{}`)
	out := string(r.Output)
	if err != nil || !strings.Contains(out, `"id":"age1groupkeygroupkeygroupkeygroupkeygroupkeygroupkeygroupk","files":["legacy/old.yml"]`) || !strings.Contains(out, `"withoutRecipients":["norecip.yaml"]`) {
		t.Fatalf("%s %v", out, err)
	}
	noValues(t, out)
	r, err = invoke(m, "rules", `{}`)
	out = string(r.Output)
	if err != nil || !strings.Contains(out, `"path_regex":"secrets/prod\\.yaml$"`) || !strings.Contains(out, `"encrypted_regex":"^(password|user)$"`) || !strings.Contains(out, `"group":0`) || !strings.Contains(out, "age1other") {
		t.Fatalf("%s %v", out, err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead || a.Sensitive {
			t.Fatalf("%s must be a plain read", a.Name)
		}
	}
}

func TestSopsConfig(t *testing.T) {
	for _, c := range []Config{{}, {Folder: "relative/dir"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	m := New()
	raw, _ := json.Marshal(Config{Folder: filepath.Join(t.TempDir(), "missing")})
	if err := m.Configure(context.Background(), fakehost.New(nil), "s", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "s"); h.Status != "down" {
		t.Fatalf("%+v", h)
	}
}

// A dotenv file whose flattened sops_… keys would build a huge tree (deep
// nesting, big list indexes, many nodes) is ignored, cheaply.
func TestSopsDotenvBombIgnored(t *testing.T) {
	deep := func(levels, index int) []byte {
		var b strings.Builder
		b.WriteString("sops_version=3.9.0\nsops_a")
		for i := 0; i < levels; i++ {
			b.WriteString("__list_" + strconv.Itoa(index) + "__map_x")
		}
		b.WriteString("=v\n")
		return []byte(b.String())
	}
	wide := func() []byte {
		var b strings.Builder
		b.WriteString("sops_version=3.9.0\n")
		for i := 0; i < 400; i++ {
			for j := 0; j < 60; j++ {
				b.WriteString("sops_k" + strconv.Itoa(i) + "__list_" + strconv.Itoa(j) + "__map_x=v\n")
			}
		}
		return []byte(b.String())
	}
	for name, b := range map[string][]byte{"deep": deep(3000, 10), "index": deep(1, 64), "nodes": wide()} {
		start := time.Now()
		if _, ok := inspect("x.env", b); ok {
			t.Errorf("%s: read a file over the caps", name)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("%s: took %v", name, d)
		}
	}
	for _, b := range [][]byte{deep(3, 63), []byte("sops_version=3.9.0\nsops_age__list_0__map_recipient=age1abc\n")} {
		if _, ok := inspect("x.env", b); !ok {
			t.Errorf("refused a file within the caps: %s", b)
		}
	}
	if _, meta := parseINI([]byte("[sops]\nversion=3.9.0\nk__list_64__map_x=v\n"), nil); meta != nil {
		t.Error("INI over the list cap read")
	}
}

// Long quoted and plain multi-line scalars parse in linear time.
func TestSopsYAMLLongScalars(t *testing.T) {
	for _, c := range []struct {
		name, first, line string
		n                 int
	}{
		{"quoted", "a: \"\n", " " + strings.Repeat("b", 100) + "\n", 9000},
		{"single", "a: '\n", " " + strings.Repeat("b", 100) + "\n", 9000},
		{"quoted, many lines", "a: \"\n", "b\n", 100000},
		{"plain, many lines", "a: x\n", " b\n", 100000},
	} {
		b := "sops:\n    version: 3.9.0\n" + c.first + strings.Repeat(c.line, c.n)
		start := time.Now()
		inspect("x.yaml", []byte(b))
		if d := time.Since(start); d > time.Second {
			t.Errorf("%s: took %v", c.name, d)
		}
	}
	// The incremental quote state reads escapes and continuation lines as before.
	docs, err := parseYAML([]byte("a: \"x \\\" y\n  z\" # c\nb: 'it''s\n  ok'\nc: 'x'\nd: \"\\\\\"\ne: plain\n  more\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	d := docs[0].(ymap)
	for k, want := range map[string]string{"a": `x " y z`, "b": "it's ok", "c": "x", "d": `\`, "e": "plain more"} {
		if d[k] != want {
			t.Errorf("%s = %q, want %q", k, d[k], want)
		}
	}
	// A scalar spanning more than maxContinuation lines makes the file unreadable.
	if _, err := parseYAML([]byte("a: \""+strings.Repeat("x\n", maxContinuation+2)), nil); err == nil {
		t.Error("read a scalar over the continuation cap")
	}
	// A cancelled call stops parsing.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := parseYAML([]byte(strings.Repeat("k: v\n", 5000)), newLimits(ctx, time.Minute)); err == nil {
		t.Error("parsed on after the context ended")
	}
}
