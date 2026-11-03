package aws

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Credentials sign requests.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // temporary credentials only
}

const sigAlgorithm = "AWS4-HMAC-SHA256"

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, s string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return m.Sum(nil)
}

// uriEncode is RFC 3986 percent-encoding as SigV4 wants it: unreserved
// characters stay, everything else (space included) becomes %XX; "/" stays
// when encoding a path.
func uriEncode(s string, path bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' || (path && c == '/') {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, uriEncode(k, false)+"="+uriEncode(v, false))
		}
	}
	return strings.Join(parts, "&")
}

// Sign adds SigV4 headers (X-Amz-Date, the security token when present,
// and Authorization) to r. body is the exact request body. S3 also needs
// X-Amz-Content-Sha256, which Sign adds for service "s3".
func Sign(r *http.Request, body []byte, c Credentials, region, service string, now time.Time) {
	t := now.UTC()
	amzDate := t.Format("20060102T150405Z")
	day := t.Format("20060102")
	payload := sha256Hex(body)
	r.Header.Set("X-Amz-Date", amzDate)
	if c.SessionToken != "" {
		r.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}
	if service == "s3" {
		r.Header.Set("X-Amz-Content-Sha256", payload)
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	// Signed headers: host, content-type and every x-amz-* header.
	hdrs := map[string]string{"host": host}
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		if lk == "content-type" || strings.HasPrefix(lk, "x-amz-") {
			hdrs[lk] = strings.Join(strings.Fields(strings.Join(v, ",")), " ")
		}
	}
	names := make([]string, 0, len(hdrs))
	for k := range hdrs {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, k := range names {
		ch.WriteString(k + ":" + hdrs[k] + "\n")
	}
	signed := strings.Join(names, ";")

	path := r.URL.EscapedPath()
	if p, err := url.PathUnescape(path); err == nil {
		path = uriEncode(p, true)
		if service != "s3" {
			// Every service but S3 encodes the path a second time.
			path = uriEncode(path, true)
		}
	}
	if path == "" {
		path = "/"
	}
	creq := strings.Join([]string{r.Method, path, canonicalQuery(r.URL.Query()), ch.String(), signed, payload}, "\n")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	sts := strings.Join([]string{sigAlgorithm, amzDate, scope, sha256Hex([]byte(creq))}, "\n")

	k := hmacSHA256([]byte("AWS4"+c.SecretAccessKey), day)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, sts))
	r.Header.Set("Authorization", sigAlgorithm+" Credential="+c.AccessKeyID+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}
