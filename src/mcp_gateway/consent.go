// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

// scopeDescriptions explains each scope on the consent page in user terms.
var scopeDescriptions = map[string]string{
	ScopeRead:  "List sessions and read files and status",
	ScopeWrite: "Create sessions, run commands, write files, renew and destroy",
}

// oauthRedirect sends a 302 to a pre-validated redirect_uri with the given
// params merged into its query. Callers must only pass URIs that exactly
// matched the client's registration.
func (s *Server) oauthRedirect(w http.ResponseWriter, r *http.Request, redirectURI string, params url.Values) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		s.authorizeErrorPage(w, "bad redirect target")
		return
	}
	q := u.Query()
	for k, vs := range params {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// authorizeErrorPage answers failures that must not redirect (unknown client,
// redirect mismatch): a direct 400 with the reason. The message is templated,
// never interpolated, so client-influenced text cannot inject markup.
func (s *Server) authorizeErrorPage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusBadRequest)
	_ = errorTmpl.Execute(w, msg)
}

var errorTmpl = template.Must(template.New("err").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Sandbox MCP — authorization error</title></head>
<body><h1>Authorization failed</h1><p>{{.}}</p></body></html>`))

type consentData struct {
	ClientName string
	Scopes     []string
	ReqID      string
	Error      string
}

func (s *Server) renderConsent(w http.ResponseWriter, client *Client, scope, reqid, formErr string) {
	name := client.Name
	if name == "" {
		name = client.ID
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = consentTmpl.Execute(w, consentData{
		ClientName: name,
		Scopes:     strings.Fields(scope),
		ReqID:      reqid,
		Error:      formErr,
	})
}

var consentTmpl = template.Must(template.New("consent").Funcs(template.FuncMap{
	"describe": func(scope string) string {
		if d, ok := scopeDescriptions[scope]; ok {
			return d
		}
		return scope
	},
}).Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Sandbox MCP — authorize</title></head>
<body>
<h1>Authorize {{.ClientName}}</h1>
<p><b>{{.ClientName}}</b> asks to drive your sandbox sessions with these permissions:</p>
<ul>{{range .Scopes}}<li><code>{{.}}</code> — {{describe .}}</li>{{end}}</ul>
{{if .Error}}<p><b>Error:</b> {{.Error}}</p>{{end}}
<form method="post" action="/oauth/authorize">
<input type="hidden" name="reqid" value="{{.ReqID}}">
<label>Sandbox API token: <input type="password" name="api_token" autocomplete="off"></label>
<p>This proves you own the sessions the client will act on. It is checked once and never stored.</p>
<button type="submit" name="decision" value="approve">Approve</button>
<button type="submit" name="decision" value="deny">Deny</button>
</form>
</body></html>`))
