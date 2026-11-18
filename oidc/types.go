// Package oidc implements Authkit's optional OpenID Connect provider. It is part
// of the Authkit Go module; external OIDC login is a separate, future feature.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/freshost/goravel-authkit/models"
	"github.com/google/uuid"
)

var (
	ErrInvalidGrant    = errors.New("invalid grant")
	ErrInvalidClient   = errors.New("invalid client")
	ErrValidation      = errors.New("invalid OIDC configuration or input")
	ErrLoginRequired   = errors.New("login required")
	ErrForbidden       = errors.New("authorization forbidden")
	ErrConsentRequired = errors.New("consent required")
)

// Config configures the provider, not an outbound OIDC client. Keys are JSON
// Web Keys / base64-encoded AES keys supplied by the host's secret store.
type Config struct {
	Enabled                 bool
	Issuer                  string
	Guard                   string
	LoginURL                string
	SigningKeyID            string
	SigningKeysJSON         string
	EncryptionKeyID         string
	EncryptionKeys          map[string]string
	Scopes                  []string
	AllowedOrigins          []string
	AccessTokenLifetime     time.Duration
	IDTokenLifetime         time.Duration
	CodeLifetime            time.Duration
	RequestLifetime         time.Duration
	RefreshIdleLifetime     time.Duration
	RefreshAbsoluteLifetime time.Duration
	AllowInsecureLoopback   bool
	Audit                   AuditFunc
}

func (c Config) defaults() Config {
	if c.AccessTokenLifetime == 0 {
		c.AccessTokenLifetime = 5 * time.Minute
	}
	if c.IDTokenLifetime == 0 {
		c.IDTokenLifetime = 5 * time.Minute
	}
	if c.CodeLifetime == 0 {
		c.CodeLifetime = 2 * time.Minute
	}
	if c.RequestLifetime == 0 {
		c.RequestLifetime = 10 * time.Minute
	}
	if c.RefreshIdleLifetime == 0 {
		c.RefreshIdleLifetime = 30 * 24 * time.Hour
	}
	if c.RefreshAbsoluteLifetime == 0 {
		c.RefreshAbsoluteLifetime = 90 * 24 * time.Hour
	}
	c.Scopes = slices.Compact(slices.Sorted(slices.Values(append([]string{"openid", "profile", "email", "offline_access"}, c.Scopes...))))
	return c
}

func (c Config) validate() error {
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(c.Issuer, "/") {
		return ErrValidation
	}
	if u.Scheme != "https" && !(c.AllowInsecureLoopback && u.Scheme == "http" && loopback(u.Hostname())) {
		return ErrValidation
	}
	login, err := url.Parse(c.LoginURL)
	if err != nil || c.LoginURL == "" || login.User != nil || login.Fragment != "" || login.RawQuery != "" || (login.Host != "" && login.Scheme != "https" && !(c.AllowInsecureLoopback && login.Scheme == "http" && loopback(login.Hostname()))) || (login.Host == "" && (!strings.HasPrefix(c.LoginURL, "/") || strings.HasPrefix(c.LoginURL, "//"))) {
		return ErrValidation
	}
	if c.Guard == "" || c.SigningKeyID == "" || c.EncryptionKeyID == "" {
		return ErrValidation
	}
	for _, d := range []time.Duration{c.AccessTokenLifetime, c.IDTokenLifetime, c.CodeLifetime, c.RequestLifetime, c.RefreshIdleLifetime, c.RefreshAbsoluteLifetime} {
		if d <= 0 {
			return ErrValidation
		}
	}
	if c.CodeLifetime > 10*time.Minute || c.RefreshIdleLifetime > c.RefreshAbsoluteLifetime {
		return ErrValidation
	}
	for _, scope := range c.Scopes {
		if !validScope(scope) {
			return ErrValidation
		}
	}
	for _, origin := range c.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(c.AllowInsecureLoopback && u.Scheme == "http" && loopback(u.Hostname()))) {
			return ErrValidation
		}
	}
	return nil
}

// Client is a registered downstream application. Native, browser and server
// applications use the same code flow. SecretHash is never returned to callers.
type Client struct {
	ID              string             `gorm:"primaryKey" json:"client_id"`
	Issuer          string             `gorm:"primaryKey" json:"-"`
	Name            string             `json:"client_name"`
	ApplicationType string             `json:"application_type"`
	AuthMethod      string             `json:"token_endpoint_auth_method"`
	SecretHash      string             `json:"-"`
	RedirectURIs    models.StringSlice `json:"redirect_uris"`
	Scopes          models.StringSlice `json:"scopes"`
	Audience        models.StringSlice `json:"audience"`
	AllowRefresh    bool               `json:"allow_refresh"`
	SkipConsent     bool               `json:"skip_consent"`
	Disabled        bool               `json:"disabled"`
	Version         int64              `json:"-"`
}

type authorization struct {
	ID              string `gorm:"primaryKey"`
	Issuer          string
	ClientID        string
	ClientVersion   int64
	Payload         string
	BindingHash     string
	InitialEvent    string
	HintSubject     string
	ConsentUserID   uuid.UUID
	ConsentEvent    string
	ConsentHash     string
	UserID          uuid.UUID
	CredentialStamp time.Time
	TwoFactorStamp  string
	AuthTime        time.Time
	AMR             models.StringSlice
	Scopes          models.StringSlice
	Audience        models.StringSlice
	Approved        bool
	CodeHash        *string
	CodeExpiresAt   *time.Time
	ConsumedAt      *time.Time
	GrantID         string
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

// Connection is one independently revocable authorization grant. Its ID is not
// a credential and does not identify or authenticate a physical device.
type Connection struct {
	ID              string             `gorm:"primaryKey" json:"id"`
	Issuer          string             `json:"-"`
	ClientID        string             `json:"clientId"`
	ClientVersion   int64              `json:"-"`
	UserID          uuid.UUID          `json:"-"`
	CredentialStamp time.Time          `json:"-"`
	TwoFactorStamp  string             `json:"-"`
	AuthTime        time.Time          `json:"-"`
	AMR             models.StringSlice `json:"-"`
	Scopes          models.StringSlice `json:"scopes"`
	Audience        models.StringSlice `json:"audience"`
	CreatedAt       time.Time          `json:"createdAt"`
	ExpiresAt       time.Time          `json:"expiresAt"`
	RevokedAt       *time.Time         `json:"revokedAt,omitempty"`
}

type token struct {
	ID         string `gorm:"primaryKey"`
	Issuer     string
	GrantID    string
	Kind       string
	Hash       *string
	Scopes     models.StringSlice
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

// Browser is supplied only by the trusted HTTP/session adapter. Request input
// must never be bound directly to it.
type Browser struct {
	Binding         string
	UserID          uuid.UUID
	CredentialStamp time.Time
	AuthTime        time.Time
	AuthEvent       string
	AMR             []string
	TwoFactorStamp  string
	Impersonating   bool
}

type Identity struct {
	UserID       uuid.UUID
	ClientID     string
	ConnectionID string
	Scopes       []string
	Audience     []string
}

type UserStore interface {
	FindByID(context.Context, uuid.UUID) (*models.User, error)
}
type PasswordHasher interface {
	Make(string) (string, error)
	Check(string, string) bool
}

func randomValue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func twoFactorStamp(u *models.User) string {
	return u.TwoFactorCredentialStamp()
}
func validScope(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}
func loopback(host string) bool { return host == "127.0.0.1" || host == "::1" }
func subset(values, allowed []string) bool {
	for _, v := range values {
		if !slices.Contains(allowed, v) {
			return false
		}
	}
	return true
}
