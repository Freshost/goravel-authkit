package oidc

import (
	"context"
	"html/template"
	"net/http"
	"net/url"

	protocol "github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type validatedClientKey struct{}

// authorize composes SDK parsing/validation/storage primitives so both successful
// and failed authorization responses honor the negotiated response mode.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	req, err := op.ParseAuthorizeRequest(r, p.protocol.Decoder())
	if err != nil {
		p.authorizationError(w, r, nil, err)
		return
	}
	client, err := p.storage.GetClientByClientID(r.Context(), req.ClientID)
	if err != nil || !registeredRedirect(client.RedirectURIs(), req.RedirectURI, client.ApplicationType() == op.ApplicationTypeNative) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("<!doctype html><html lang=\"en\"><title>Authorization failed</title><h1>Invalid client or redirect URI</h1></html>"))
		return
	}
	subject, err := p.validateAuthRequest(r.Context(), req, client)
	if err != nil {
		p.authorizationError(w, r, req, err)
		return
	}
	if req.RequestParam != "" {
		p.authorizationError(w, r, req, protocol.ErrRequestNotSupported())
		return
	}
	ctx := context.WithValue(r.Context(), validatedClientKey{}, client.(*clientSnapshot).row.Version)
	stored, err := p.storage.CreateAuthRequest(ctx, req, subject)
	if err != nil {
		p.authorizationError(w, r, req, err)
		return
	}
	op.RedirectToLogin(stored.GetID(), client, w, r)
}

func (p *Provider) authorizationResponse(w http.ResponseWriter, r *http.Request, req *requestSnapshot) {
	response, err := op.BuildAuthResponseCodeResponsePayload(r.Context(), req, p.protocol)
	if err != nil {
		p.authorizationError(w, r, req, err)
		return
	}
	if req.GetResponseMode() == protocol.ResponseModeFormPost {
		p.formPost(w, r, req.GetRedirectURI(), response)
		return
	}
	location, err := op.AuthResponseURL(req.GetRedirectURI(), req.GetResponseType(), req.GetResponseMode(), response, p.protocol.Encoder())
	if err != nil {
		op.RequestError(w, r, protocol.ErrServerError(), nil)
		return
	}
	http.Redirect(w, r, location, http.StatusFound)
}

func (p *Provider) authorizationError(w http.ResponseWriter, r *http.Request, req op.ErrAuthRequest, err error) {
	err = protocolError(err)
	if req != nil {
		if mode, ok := req.(interface{ GetResponseMode() protocol.ResponseMode }); ok && mode.GetResponseMode() == protocol.ResponseModeFormPost {
			e := *protocol.DefaultToServerError(err, "Authorization failed")
			e.State = req.GetState()
			p.formPost(w, r, req.GetRedirectURI(), &e)
			return
		}
	}
	op.AuthRequestError(w, r, req, err, p.protocol)
}

// This is the standard OAuth Form Post Response Mode HTML transport. The SDK's
// legacy success-only template omits error fields, so render its encoded values
// through a complete escaped form for both code and error responses.
var formPostPage = template.Must(template.New("form-post").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Continue sign-in</title><form method="post" action="{{.URI}}">{{range $name,$values := .Fields}}{{range $values}}<input type="hidden" name="{{$name}}" value="{{.}}">{{end}}{{end}}<button type="submit">Continue</button></form><script nonce="{{.Nonce}}">document.forms[0].submit();</script></html>`))

func (p *Provider) formPost(w http.ResponseWriter, r *http.Request, uri string, response any) {
	u, err := url.Parse(uri)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		op.RequestError(w, r, protocol.ErrInvalidRequest(), nil)
		return
	}
	fields := url.Values{}
	if err := p.protocol.Encoder().Encode(response, fields); err != nil {
		op.RequestError(w, r, protocol.ErrServerError(), nil)
		return
	}
	nonce, err := randomValue()
	if err != nil {
		op.RequestError(w, r, protocol.ErrServerError(), nil)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; form-action "+u.Scheme+"://"+u.Host+"; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	_ = formPostPage.Execute(w, struct {
		URI, Nonce string
		Fields     url.Values
	}{uri, nonce, fields})
}
