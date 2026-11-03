package aws

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

var exampleCreds = Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}

// "get-vanilla" from the AWS Signature Version 4 test suite.
func TestSigV4GetVanilla(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	Sign(r, nil, exampleCreds, "us-east-1", "service", time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := r.Header.Get("Authorization"); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// "get-vanilla-query-order-key-case" from the same suite: query parameters
// are sorted by key.
func TestSigV4QueryOrder(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://example.amazonaws.com/?Param2=value2&Param1=value1", nil)
	Sign(r, nil, exampleCreds, "us-east-1", "service", time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))
	if !strings.HasSuffix(r.Header.Get("Authorization"), "Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500") {
		t.Fatalf("got %s", r.Header.Get("Authorization"))
	}
}

func TestURIEncode(t *testing.T) {
	if got := uriEncode("a b/c~d*", false); got != "a%20b%2Fc~d%2A" {
		t.Fatal(got)
	}
	if got := canonicalQuery(url.Values{"b": {"2"}, "a": {"x y"}}); got != "a=x%20y&b=2" {
		t.Fatal(got)
	}
}
