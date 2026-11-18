package oidc

import (
	"encoding/json"
	"mime"
	"net/http"
	"strings"

	protocol "github.com/zitadel/oidc/v3/pkg/oidc"
)

// UserInfo uses the same live token checks as API authorization and returns the
// RFC 6750 challenges required by OIDC Core 5.3.3, including after revocation.
func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Has("access_token") {
		userinfoError(w, 400, "invalid_request")
		return
	}
	value := ""
	header := r.Header.Get("Authorization")
	if header != "" {
		parts := strings.Fields(header)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || r.PostForm.Has("access_token") {
			userinfoError(w, 400, "invalid_request")
			return
		}
		value = parts[1]
	} else if r.PostForm.Has("access_token") {
		kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if r.Method != http.MethodPost || err != nil || kind != "application/x-www-form-urlencoded" {
			userinfoError(w, 400, "invalid_request")
			return
		}
		value = r.PostForm.Get("access_token")
	}
	if value == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oidc"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	plain, err := p.protocol.Crypto().Decrypt(value)
	parts := strings.Split(plain, ":")
	if err != nil || len(parts) != 2 {
		userinfoError(w, 401, "invalid_token")
		return
	}
	token, _, user, err := p.Service.access(r.Context(), parts[0], parts[1])
	if err != nil {
		if IsAuthenticationError(err) {
			userinfoError(w, 401, "invalid_token")
		} else {
			userinfoError(w, 503, "temporarily_unavailable")
		}
		return
	}
	info := new(protocol.UserInfo)
	setUserinfo(info, user, token.Scopes)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

func userinfoError(w http.ResponseWriter, status int, code string) {
	if status != http.StatusServiceUnavailable {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oidc", error="`+code+`"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
