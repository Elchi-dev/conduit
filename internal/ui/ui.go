// Package ui serves the web app. Release builds embed it with the "ui" build
// tag (`make daemon` copies web/dist here first); without the tag the daemon
// serves a short page explaining how to run the UI in development.
package ui

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// Handler serves the single-page app: real files when they exist, index.html
// for every other path so client-side routes work on reload.
func Handler() http.Handler {
	files := assets()
	if files == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(devPage))
		})
	}
	fileServer := http.FileServerFS(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(files, p); err != nil {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; frame-src 'self' https:; frame-ancestors 'self'")
		fileServer.ServeHTTP(w, r)
	})
}

const devPage = `<!doctype html><meta charset="utf-8"><title>Conduit</title>
<body style="font:15px system-ui;background:#23262a;color:#e6e3dc;display:grid;place-content:center;height:100vh;margin:0">
<p>This conduitd build has no embedded UI. Run <code>cd web &amp;&amp; pnpm dev</code> and open http://localhost:5173,<br>
or build with <code>make daemon</code>.</p>`
