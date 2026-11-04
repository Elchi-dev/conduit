package rest

import "testing"

func TestShortURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://shop.example.com":                                           "https://shop.example.com",
		"https://shop.example.com/":                                          "https://shop.example.com",
		"https://u:p@shop.example.com/?t=1":                                  "https://shop.example.com?…",
		"https://api.example.com/health?key=s3cr3t":                          "https://api.example.com/health?…",
		"https://api.example.com/v1/status/abc":                              "https://api.example.com/v1/…",
		"https://hc-ping.com/11111111-2222-4333-8444-555555555551":           "https://hc-ping.com/…",
		"https://example.com/AbCdEf0123456789xyz/hook":                       "https://example.com/…/…",
		"https://example.com/#frag":                                          "https://example.com?…",
		"http://10.0.0.5:8080/metrics":                                       "http://10.0.0.5:8080/metrics",
		"192.168.1.1":                                                        "192.168.1.1",
		"router.lan/admin?pw=x":                                              "router.lan/…",
		"user:pw@db.example.com":                                             "db.example.com",
		"a1b2c3d4e5f6a7b8c9d0":                                               "…",
		"https://example.com/a-very-long-segment-name-that-is-over-40-chars": "https://example.com/…",
	} {
		if got := ShortURL(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
