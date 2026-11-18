package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	clientoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// Exercise real HTTPS discovery, code exchange, JWKS verification, UserInfo and
// refresh through an independent OIDC client, with no Authkit client adapter.
func TestIndependentOIDCClient(t *testing.T) {
	for _, method := range []string{"none", "client_secret_basic"} {
		t.Run(method, func(t *testing.T) {
			base, b, users := testProvider(t)
			var provider *Provider
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Browser authentication is supplied by the host, outside the protocol.
				if strings.HasSuffix(r.URL.Path, "/authorize") || strings.HasSuffix(r.URL.Path, "/interaction") {
					r = r.WithContext(WithBrowser(r.Context(), b))
				}
				provider.ServeHTTP(w, r)
			}))
			config := base.Service.config
			config.Issuer = "https://" + server.Listener.Addr().String() + "/oidc"
			var err error
			provider, err = New(config, newMemoryStore(), users, testHasher{})
			require.NoError(t, err)
			client, err := base.Service.client(context.Background(), "public")
			require.NoError(t, err)
			client.AuthMethod = method
			secret := ""
			if method == "client_secret_basic" {
				secret = strings.Repeat("s", 43)
			}
			require.NoError(t, provider.Service.RegisterClient(context.Background(), *client, secret))
			server.StartTLS()
			t.Cleanup(server.Close)
			ctx := clientoidc.ClientContext(context.Background(), server.Client())
			discovered, err := clientoidc.NewProvider(ctx, provider.Issuer())
			require.NoError(t, err)
			oauth := oauth2.Config{ClientID: client.ID, ClientSecret: secret, RedirectURL: client.RedirectURIs[0], Endpoint: discovered.Endpoint(), Scopes: []string{"openid", "profile", "email", "offline_access", "api:read"}}
			if method == "none" {
				oauth.Endpoint.AuthStyle = oauth2.AuthStyleInParams
			} else {
				oauth.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
			}
			browser := *server.Client()
			browser.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
				if r.URL.Host != server.Listener.Addr().String() {
					return http.ErrUseLastResponse
				}
				return nil
			}
			verifier := oauth2.GenerateVerifier()
			response, err := browser.Get(oauth.AuthCodeURL("client-state", oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", "client-nonce")))
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.Equal(t, http.StatusFound, response.StatusCode)
			callback, err := url.Parse(response.Header.Get("Location"))
			require.NoError(t, err)
			require.Equal(t, "client-state", callback.Query().Get("state"))
			require.NotEmpty(t, callback.Query().Get("code"))
			token, err := oauth.Exchange(ctx, callback.Query().Get("code"), oauth2.VerifierOption(verifier))
			require.NoError(t, err)
			rawID, ok := token.Extra("id_token").(string)
			require.True(t, ok)
			verified, err := discovered.Verifier(&clientoidc.Config{ClientID: client.ID}).Verify(ctx, rawID)
			require.NoError(t, err)
			require.Equal(t, users.user.ID.String(), verified.Subject)
			require.Equal(t, "client-nonce", verified.Nonce)
			require.NoError(t, verified.VerifyAccessToken(token.AccessToken))
			info, err := discovered.UserInfo(ctx, oauth2.StaticTokenSource(token))
			require.NoError(t, err)
			require.Equal(t, verified.Subject, info.Subject)
			require.Equal(t, users.user.Email, info.Email)
			fresh, err := oauth.TokenSource(ctx, &oauth2.Token{AccessToken: "expired", RefreshToken: token.RefreshToken, Expiry: time.Now().Add(-time.Minute)}).Token()
			require.NoError(t, err)
			require.NotEmpty(t, fresh.RefreshToken)
			require.NotEqual(t, token.RefreshToken, fresh.RefreshToken)
			rawID, ok = fresh.Extra("id_token").(string)
			require.True(t, ok)
			verified, err = discovered.Verifier(&clientoidc.Config{ClientID: client.ID}).Verify(ctx, rawID)
			require.NoError(t, err)
			require.NoError(t, verified.VerifyAccessToken(fresh.AccessToken))
		})
	}
}
