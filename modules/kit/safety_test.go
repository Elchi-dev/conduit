package kit

import "testing"

func TestUnsafeHTML(t *testing.T) {
	for _, s := range []string{
		`<script>alert(1)</script>`, `<SCRIPT src=x></SCRIPT>`, `<scr<script>ipt>alert(1)</script>`, `< script>`, `<svg><script>x</script></svg>`,
		`<iframe src="https://x.test"></iframe>`, `<object data=x>`, `<embed src=x>`,
		`<img src=x onerror=alert(1)>`, `<img/onerror=alert(1) src=x>`, `<body ONLOAD="x()">`, `<a title=">" onclick="x()">t</a>`, `<div onmouseover = 'x'>`,
		`<a href="javascript:alert(1)">x</a>`, `<a href=JavaScript:alert(1)>x</a>`, `<a href=" java&#x09;script:alert(1)">x</a>`,
		`<a href="&#106;avascript:alert(1)">x</a>`, `<a href='vbscript:msgbox(1)'>x</a>`, `<a href="data:text/html;base64,PHNjcmlwdD4=">x</a>`,
		`<form action="javascript:x()"><button formaction=javascript:y>b</button></form>`, `<svg><a xlink:href="javascript:x">t</a></svg>`,
	} {
		if unsafeHTML(s) == "" {
			t.Errorf("accepted %s", s)
		}
	}
	for _, s := range []string{
		`<h1>Hi</h1><p>All the news</p>`, `<a href="https://example.test/?q=javascript:">read</a>`, `<p>JavaScript: the good parts, on sale</p>`,
		`<img src="data:image/png;base64,iVBORw0KGgo=" alt="logo">`, `<p style="color:red">it's 5 > 3 and 2 < 4</p>`, `<a href="mailto:hi@example.test">mail</a>`,
		`<table><tr><td class="online">x</td></tr></table>`, `<meta charset="utf-8"><p>Hello, "friends"</p>`,
	} {
		if bad := unsafeHTML(s); bad != "" {
			t.Errorf("refused %s: %s", s, bad)
		}
	}
}
