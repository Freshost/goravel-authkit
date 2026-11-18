// Command conformance hosts the real Goravel/Authkit integration for the OIDF
// suite. It is a separate CI executable, never part of the demo's normal server.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"

	"github.com/freshost/goravel-authkit/models"
	"github.com/freshost/goravel-authkit/oidc"
	"github.com/freshost/goravel-authkit/repositories"
	authroutes "github.com/freshost/goravel-authkit/routes"
	"github.com/freshost/goravel-authkit/services"
	"github.com/go-jose/go-jose/v4"
	"github.com/goravel/framework/facades"

	"goravel/bootstrap"
)

const issuer = "https://localhost.emobix.co.uk:9443/oidc"
const secret = "oidf-isolated-client-secret-not-for-production"

var loginPage = template.Must(template.New("login").Parse(`<!doctype html><html lang="en"><title>Authkit sign-in</title><h1>Sign-in</h1><form method="post" action="/conformance/login"><input type="hidden" name="return_to" value="{{.}}"><label>Email <input name="email" type="email" required></label><label>Password <input name="password" type="password" required></label><button name="submit" type="submit">Sign in</button></form></html>`))

func main() {
	if os.Getenv("CI") != "true" || os.Getenv("APP_ENV") != "testing" {
		log.Fatal("the conformance fixture requires CI=true and APP_ENV=testing")
	}
	bootstrap.Boot()
	if err := prepare(context.Background()); err != nil {
		log.Fatal("conformance fixture initialization failed")
	}
	server := &http.Server{Addr: "127.0.0.1:9443", Handler: http.HandlerFunc(serve)}
	log.Fatal(server.ListenAndServeTLS(os.Getenv("OIDF_TLS_CERT"), os.Getenv("OIDF_TLS_KEY")))
}

func prepare(ctx context.Context) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	keys, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key, KeyID: "oidf-ci", Algorithm: "RS256", Use: "sig"}}})
	if err != nil {
		return err
	}
	encryption := make([]byte, 32)
	if _, err = rand.Read(encryption); err != nil {
		return err
	}
	facades.Config().Add("authkit.oidc.provider", map[string]any{
		"enabled": true, "guard": "client", "issuer": issuer, "login_url": "/conformance/login",
		"signing_key_id": "oidf-ci", "signing_keys": string(keys), "encryption_key_id": "oidf-ci",
		"encryption_keys": map[string]any{"oidf-ci": base64.StdEncoding.EncodeToString(encryption)},
	})
	for _, migration := range oidc.Migrations() {
		if err = migration.Up(); err != nil {
			return err
		}
	}
	users := services.NewUsers(repositories.NewUsersWithTable("client_users"), services.NewFacadeHasher(), 12, []string{"user"}, []string{"admin"}, nil, true)
	if _, err = users.Create(ctx, "oidf@example.test", "Conformance User", "isolated-conformance-password", "user"); err != nil {
		return err
	}
	p, err := authroutes.NewOIDCProvider()
	if err != nil {
		return err
	}
	optionalPKCE := false
	for _, id := range []string{"basic", "second", "post", "public"} {
		method := "client_secret_basic"
		if id == "post" {
			method = "client_secret_post"
		}
		if id == "public" {
			method = "none"
		}
		client := oidc.Client{ID: "oidf-" + id, Name: "OIDF " + id, ApplicationType: "web", AuthMethod: method,
			RedirectURIs: models.StringSlice{"https://localhost.emobix.co.uk:8443/test/a/authkit/callback"},
			Scopes:       models.StringSlice{"openid", "profile", "email", "offline_access"}, Audience: models.StringSlice{"https://api.example.test"}, AllowRefresh: true, SkipConsent: true}
		clientSecret := secret
		if method == "none" {
			clientSecret = ""
		} else {
			client.RequirePKCE = &optionalPKCE
		}
		if err = p.Service.RegisterClient(ctx, client, clientSecret); err != nil {
			return err
		}
	}
	authroutes.RegisterOIDC(facades.Route())
	return nil
}

func serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/conformance/login" {
		facades.Route().ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid login request", 400)
		return
	}
	continuation := r.Form.Get("return_to")
	u, err := url.Parse(continuation)
	if err != nil || u.Scheme != "https" || u.Host != "localhost.emobix.co.uk:9443" || u.Path != "/oidc/interaction" || u.User != nil || u.Fragment != "" || u.Query().Get("id") == "" {
		http.Error(w, "Invalid continuation", 400)
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = loginPage.Execute(w, continuation)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	// Translate the host's HTML form to the existing Authkit login endpoint.
	// The actual controller, password verification, session and CSRF chain run.
	body, _ := json.Marshal(map[string]string{"email": r.PostForm.Get("email"), "password": r.PostForm.Get("password")})
	login := r.Clone(r.Context())
	login.URL = &url.URL{Scheme: r.URL.Scheme, Host: r.URL.Host, Path: "/api/client/v1/auth/login"}
	login.RequestURI = login.URL.RequestURI()
	login.Body = io.NopCloser(strings.NewReader(string(body)))
	login.ContentLength = int64(len(body))
	login.Header.Set("Content-Type", "application/json")
	login.Form, login.PostForm = nil, nil
	result := httptest.NewRecorder()
	facades.Route().ServeHTTP(result, login)
	for _, cookie := range result.Result().Cookies() {
		http.SetCookie(w, cookie)
	}
	if result.Code != http.StatusOK {
		http.Error(w, fmt.Sprintf("Sign-in failed (%d)", result.Code), result.Code)
		return
	}
	http.Redirect(w, r, continuation, http.StatusFound)
}
