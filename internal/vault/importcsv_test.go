package vault

import (
	"strings"
	"testing"
)

func TestParseCSVExport(t *testing.T) {
	bitwarden := "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
		",1,login,GitHub,,,0,https://github.com,octo,hunter22,JBSWY3DPEHPK3PXP\n" +
		",,note,Wi-Fi,\"SSID home, pass x\",,0,,,,\n" +
		",,login,GitHub,,,0,https://github.com,second,pw2,\n"
	got, err := ParseCSVExport(strings.NewReader(bitwarden), "bw")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]Imported{}
	for _, g := range got {
		names[g.Name] = g
	}
	if p := names["bw/github/password"]; p.Value != "hunter22" || p.Kind != KindPassword || p.Description() != "GitHub, user octo, https://github.com" {
		t.Fatalf("%+v", p)
	}
	if names["bw/github/totp"].Value != "JBSWY3DPEHPK3PXP" {
		t.Fatal("totp missing")
	}
	if names["bw/wi-fi/note"].Kind != KindNote {
		t.Fatal("note missing")
	}
	if names["bw/github-2/password"].Value != "pw2" {
		t.Fatalf("duplicate titles: %v", names)
	}

	chrome := "name,url,username,password,note\nexample.com,https://example.com/login,me@x.io,s3cret,\n"
	got, err = ParseCSVExport(strings.NewReader("\uFEFF"+chrome), "")
	if err != nil || len(got) != 1 || got[0].Name != "imported/example-com/password" {
		t.Fatalf("%+v %v", got, err)
	}

	onepw := "Title,Url,Username,Password,OTPAuth,Notes\nAWS root,https://aws.amazon.com,root@x.io,pw,otpauth://totp/AWS?secret=ABC,\n"
	got, _ = ParseCSVExport(strings.NewReader(onepw), "1p")
	if len(got) != 2 || got[1].Name != "1p/aws-root/totp" {
		t.Fatalf("%+v", got)
	}

	keepass := `"Account","Login Name","Password","Web Site","Comments"` + "\n" + `"Router","admin","pw","http://192.168.1.1",""` + "\n"
	got, _ = ParseCSVExport(strings.NewReader(keepass), "kp")
	if len(got) != 1 || got[0].Username != "admin" {
		t.Fatalf("%+v", got)
	}

	if _, err := ParseCSVExport(strings.NewReader("a,b\n1,2\n"), "x"); err == nil {
		t.Fatal("a CSV without password or notes accepted")
	}
}
