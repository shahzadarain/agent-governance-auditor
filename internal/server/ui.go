// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

// immutableAssetPrefix is the bundle directory whose files carry a content
// hash in their names (the Vite default). Only these get a long cache
// lifetime; every other file is revalidated.
const immutableAssetPrefix = "assets/"

// serveUI serves the dashboard bundle with a single-page-application
// fallback. API paths never reach it.
func (a *App) serveUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		return
	}
	if isAPIPath(r.URL.Path) {
		// Reached only for a known operational path with a wrong method.
		writeError(w, http.StatusNotFound, "not_found", "The requested resource does not exist.")
		return
	}
	if a.cfg.UI == nil {
		a.serveBuiltinPage(w, r)
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	if fs.ValidPath(name) {
		if data, err := fs.ReadFile(a.cfg.UI, name); err == nil {
			a.writeAsset(w, r, name, data)
			return
		}
	}
	// A missing file with an extension is a missing asset. Everything else
	// is a client-side route.
	if path.Ext(name) != "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	data, err := fs.ReadFile(a.cfg.UI, "index.html")
	if err != nil {
		a.serveBuiltinPage(w, r)
		return
	}
	a.writeAsset(w, r, "index.html", data)
}

func (a *App) writeAsset(w http.ResponseWriter, r *http.Request, name string, data []byte) {
	ctype := mime.TypeByExtension(path.Ext(name))
	switch path.Ext(name) {
	case ".html":
		ctype = "text/html; charset=utf-8"
	case ".js", ".mjs":
		ctype = "text/javascript; charset=utf-8"
	case ".css":
		ctype = "text/css; charset=utf-8"
	case ".json", ".map":
		ctype = "application/json; charset=utf-8"
	case ".svg":
		ctype = "image/svg+xml"
	}
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ctype)
	if strings.HasPrefix(name, immutableAssetPrefix) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(data))
}

var builtinPage = template.Must(template.New("builtin").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentGov Auditor server</title>
<style>
body { font-family: system-ui, sans-serif; background: #F8FAFC; color: #0B1220; margin: 0; padding: 2rem 1rem; }
main { max-width: 40rem; margin: 0 auto; background: #FFFFFF; border: 1px solid #CBD5E1; border-radius: 8px; padding: 1.5rem; }
h1 { font-size: 1.25rem; margin-top: 0; }
dt { font-weight: 600; margin-top: 0.75rem; }
dd { margin: 0.25rem 0 0 0; }
code { background: #F1F5F9; padding: 0.1rem 0.3rem; border-radius: 4px; }
</style>
</head>
<body>
<main>
<h1>AgentGov Auditor server</h1>
<p>The dashboard bundle is not included in this build. The API is available.</p>
<dl>
<dt>API status</dt><dd>{{if .Ready}}Ready: the database responds and migrations are applied.{{else}}Not ready: the database check failed.{{end}}</dd>
<dt>Version</dt><dd>{{.Version}}</dd>
<dt>First-run setup</dt><dd>{{if .SetupRequired}}Required. Use the bootstrap token from the server console with <code>POST /api/v1/setup</code>.{{else}}Complete.{{end}}</dd>
<dt>Health endpoints</dt><dd><code>GET /healthz</code>, <code>GET /readyz</code>, <code>GET /api/v1/version</code></dd>
</dl>
<p>See <code>docs/self-hosting.md</code> for setup and upload instructions.</p>
</main>
</body>
</html>
`))

// serveBuiltinPage renders a static status page. It has no script, so it
// works under the strict Content-Security-Policy. html/template escapes
// every value.
func (a *App) serveBuiltinPage(w http.ResponseWriter, r *http.Request) {
	n, err := a.store.CountUsers(r.Context())
	data := struct {
		Ready         bool
		Version       string
		SetupRequired bool
	}{Ready: a.ready(r), Version: a.cfg.Version, SetupRequired: err == nil && n == 0}
	var buf bytes.Buffer
	if err := builtinPage.Execute(&buf, data); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "Internal server error.")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	if r.URL.Path != "/" && path.Ext(r.URL.Path) != "" {
		w.WriteHeader(http.StatusNotFound)
	}
	_, _ = w.Write(buf.Bytes())
}
