package oidc

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/freshost/goravel-authkit/models"
	"github.com/google/uuid"
)

// Service owns client policy, authorization grants and credential lifecycle.
// Protocol adapters cannot bypass its account, client or revocation checks.
type Service struct {
	config Config
	store  Store
	users  UserStore
	hasher PasswordHasher
	now    func() time.Time
}

func newService(c Config, store Store, users UserStore, hasher PasswordHasher) *Service {
	return &Service{config: c, store: store, users: users, hasher: hasher, now: func() time.Time { return time.Now().UTC() }}
}

// RegisterClient creates or updates an administratively registered client. Any
// update advances its version and invalidates previous grants. Public clients
// must not have a secret. Confidential clients supply a high-entropy secret via
// the host's secret management; only its password hash is stored.
func (s *Service) RegisterClient(ctx context.Context, client Client, secret string) error {
	if client.ID == "" || len(client.ID) > 200 || strings.TrimSpace(client.Name) == "" || len(client.Name) > 200 {
		return ErrValidation
	}
	if client.ApplicationType != "web" && client.ApplicationType != "native" {
		return ErrValidation
	}
	if client.AuthMethod != "none" && client.AuthMethod != "client_secret_basic" && client.AuthMethod != "client_secret_post" {
		return ErrValidation
	}
	if client.ApplicationType == "native" && client.AuthMethod != "none" {
		return ErrValidation
	}
	if client.AuthMethod == "none" && secret != "" {
		return ErrValidation
	}
	if client.AuthMethod == "none" && client.RequirePKCE != nil && !*client.RequirePKCE {
		return ErrValidation
	}
	if client.AuthMethod != "none" && (len(secret) < 32 || len(secret) > 72) {
		return ErrValidation
	}
	if len(client.RedirectURIs) == 0 || len(client.Audience) == 0 || !slices.Contains(client.Scopes, "openid") || !subset(client.Scopes, s.config.Scopes) {
		return ErrValidation
	}
	for _, uri := range client.RedirectURIs {
		u, err := url.Parse(uri)
		if err != nil || u.Scheme == "" || u.Fragment != "" || u.User != nil || strings.ContainsAny(uri, "*\r\n") || u.String() != uri {
			return ErrValidation
		}
		if client.ApplicationType == "web" {
			if u.Scheme != "https" || u.Host == "" {
				return ErrValidation
			}
		} else {
			if u.Scheme == "http" {
				if !loopback(u.Hostname()) {
					return ErrValidation
				}
			} else if u.Scheme == "https" {
				if u.Host == "" {
					return ErrValidation
				}
			} else if !strings.Contains(u.Scheme, ".") {
				return ErrValidation
			}
		}
	}
	for _, v := range client.Audience {
		if strings.TrimSpace(v) == "" {
			return ErrValidation
		}
	}
	client.SecretHash = ""
	if secret != "" {
		hash, err := s.hasher.Make(secret)
		if err != nil {
			return err
		}
		client.SecretHash = hash
	}
	err := s.store.Transaction(ctx, func(tx Store) error {
		old, err := tx.Client(ctx, client.ID, true)
		if err != nil {
			return err
		}
		client.Version = 1
		if old == nil {
			return tx.CreateClient(ctx, &client)
		}
		client.Version = old.Version + 1
		return tx.SaveClient(ctx, &client)
	})
	if err == nil {
		s.emit(ctx, Event{Action: "oidc.client_registered", ClientID: client.ID})
	}
	return err
}

func (s *Service) client(ctx context.Context, id string) (*Client, error) {
	c, err := s.store.Client(ctx, id, false)
	if err != nil {
		return nil, err
	}
	if c == nil || c.Disabled {
		return nil, ErrInvalidClient
	}
	return c, nil
}

func (s *Service) DisableClient(ctx context.Context, id string) error {
	err := s.store.Transaction(ctx, func(tx Store) error {
		c, err := tx.Client(ctx, id, true)
		if err != nil {
			return err
		}
		if c == nil {
			return ErrInvalidClient
		}
		c.Disabled = true
		c.Version++
		return tx.SaveClient(ctx, c)
	})
	if err == nil {
		s.emit(ctx, Event{Action: "oidc.client_disabled", ClientID: id})
	}
	return err
}

func (s *Service) Connections(ctx context.Context, user uuid.UUID) ([]Connection, error) {
	if user == uuid.Nil {
		return nil, ErrForbidden
	}
	items, err := s.store.Connections(ctx, user)
	if err != nil {
		return nil, err
	}
	active := make([]Connection, 0, len(items))
	for _, g := range items {
		if err = s.liveGrant(ctx, s.store, &g); err == nil {
			active = append(active, g)
		} else if !isProtocolError(err) {
			return nil, err
		}
	}
	return active, nil
}

func (s *Service) RevokeConnection(ctx context.Context, user uuid.UUID, id string) error {
	if user == uuid.Nil {
		return ErrForbidden
	}
	err := s.store.Transaction(ctx, func(tx Store) error {
		g, err := tx.Grant(ctx, id, true)
		if err != nil {
			return err
		}
		if g == nil || g.UserID != user {
			return ErrInvalidGrant
		}
		now := s.now()
		g.RevokedAt = &now
		return tx.SaveGrant(ctx, g)
	})
	if err == nil {
		s.emit(ctx, Event{Action: "oidc.connection_revoked", UserID: user, ConnectionID: id})
	}
	return err
}

func (s *Service) RevokeAll(ctx context.Context, user uuid.UUID) error {
	if user == uuid.Nil {
		return ErrForbidden
	}
	err := s.store.RevokeUser(ctx, user, s.now())
	if err == nil {
		s.emit(ctx, Event{Action: "oidc.connections_revoked", UserID: user})
	}
	return err
}

func (s *Service) Prune(ctx context.Context) error {
	return s.store.Prune(ctx, s.now().Add(-30*24*time.Hour))
}

func (s *Service) liveUser(ctx context.Context, id uuid.UUID, stamp time.Time, twoFactor string) (*models.User, error) {
	u, err := s.users.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if u == nil || u.IsDisabled() || !u.PasswordChangedAt.Equal(stamp) || twoFactorStamp(u) != twoFactor {
		return nil, ErrInvalidGrant
	}
	return u, nil
}

func (s *Service) liveGrant(ctx context.Context, tx Store, g *Connection) error {
	if g == nil || g.RevokedAt != nil || !s.now().Before(g.ExpiresAt) {
		return ErrInvalidGrant
	}
	c, err := tx.Client(ctx, g.ClientID, false)
	if err != nil {
		return err
	}
	if c == nil || c.Disabled || c.Version != g.ClientVersion {
		return ErrInvalidGrant
	}
	_, err = s.liveUser(ctx, g.UserID, g.CredentialStamp, g.TwoFactorStamp)
	return err
}

// Issue performs the final atomic transition after the protocol library has
// checked client binding, redirect_uri and the PKCE verifier. Invalid requests
// must never consume a code or revoke another client's grant.
func (s *Service) issue(ctx context.Context, requestID, refresh string, scopes []string, wantRefresh bool) (accessID, newRefresh string, expires time.Time, err error) {
	accessID, err = randomValue()
	if err != nil {
		return
	}
	var refreshID string
	if wantRefresh {
		newRefresh, err = randomValue()
		if err != nil {
			return
		}
		refreshID, err = randomValue()
		if err != nil {
			return
		}
	}
	var now time.Time
	replay := false
	var event Event
	err = s.store.Transaction(ctx, func(tx Store) error {
		var g *Connection
		if refresh != "" {
			// Always lock the grant before the refresh row, including revocation.
			old, lookupErr := tx.Refresh(ctx, digest(refresh), false)
			if lookupErr != nil {
				return lookupErr
			}
			if old == nil {
				return ErrInvalidGrant
			}
			g, lookupErr = tx.Grant(ctx, old.GrantID, true)
			if lookupErr != nil {
				return lookupErr
			}
			old, lookupErr = tx.Refresh(ctx, digest(refresh), true)
			if lookupErr != nil {
				return lookupErr
			}
			if old == nil {
				return ErrInvalidGrant
			}
			if err := s.liveGrant(ctx, tx, g); err != nil {
				return err
			}
			now = s.now()
			if old.ConsumedAt != nil {
				g.RevokedAt = &now
				replay = true
				event = Event{Action: "oidc.refresh_reuse", UserID: g.UserID, ClientID: g.ClientID, ConnectionID: g.ID}
				return tx.SaveGrant(ctx, g)
			}
			if !now.Before(old.ExpiresAt) || !subset(scopes, old.Scopes) {
				return ErrInvalidGrant
			}
			old.ConsumedAt = &now
			if err := tx.SaveToken(ctx, old); err != nil {
				return err
			}
		} else {
			a, lookupErr := tx.Request(ctx, requestID, true)
			if lookupErr != nil {
				return lookupErr
			}
			if a == nil || !a.Approved || a.CodeHash == nil || a.CodeExpiresAt == nil {
				return ErrInvalidGrant
			}
			if a.ConsumedAt != nil {
				g, lookupErr = tx.Grant(ctx, a.GrantID, true)
				if lookupErr != nil {
					return lookupErr
				}
				if g != nil {
					now = s.now()
					g.RevokedAt = &now
					replay = true
					event = Event{Action: "oidc.code_reuse", UserID: g.UserID, ClientID: g.ClientID, ConnectionID: g.ID}
					return tx.SaveGrant(ctx, g)
				}
				return ErrInvalidGrant
			}
			c, lookupErr := tx.Client(ctx, a.ClientID, false)
			if lookupErr != nil {
				return lookupErr
			}
			if c == nil || c.Disabled || c.Version != a.ClientVersion {
				return ErrInvalidGrant
			}
			if _, err := s.liveUser(ctx, a.UserID, a.CredentialStamp, a.TwoFactorStamp); err != nil {
				return err
			}
			now = s.now()
			if !now.Before(*a.CodeExpiresAt) || !now.Before(a.ExpiresAt) || !subset(scopes, a.Scopes) {
				return ErrInvalidGrant
			}
			grantID, err := randomValue()
			if err != nil {
				return err
			}
			g = &Connection{ID: grantID, ClientID: a.ClientID, ClientVersion: a.ClientVersion, UserID: a.UserID, CredentialStamp: a.CredentialStamp, TwoFactorStamp: a.TwoFactorStamp, AuthTime: a.AuthTime, AMR: a.AMR, Scopes: a.Scopes, Audience: a.Audience, CreatedAt: now, ExpiresAt: now.Add(s.config.RefreshAbsoluteLifetime)}
			if err := tx.SaveGrant(ctx, g); err != nil {
				return err
			}
			a.ConsumedAt = &now
			a.GrantID = grantID
			if err := tx.SaveRequest(ctx, a); err != nil {
				return err
			}
		}
		event = Event{Action: "oidc.tokens_issued", UserID: g.UserID, ClientID: g.ClientID, ConnectionID: g.ID}
		expires = now.Add(s.config.AccessTokenLifetime)
		if g.ExpiresAt.Before(expires) {
			expires = g.ExpiresAt
		}
		if err := tx.SaveToken(ctx, &token{ID: accessID, GrantID: g.ID, Kind: "access", Scopes: slices.Clone(scopes), CreatedAt: now, ExpiresAt: expires}); err != nil {
			return err
		}
		if wantRefresh {
			idle := now.Add(s.config.RefreshIdleLifetime)
			if g.ExpiresAt.Before(idle) {
				idle = g.ExpiresAt
			}
			hash := digest(newRefresh)
			return tx.SaveToken(ctx, &token{ID: refreshID, GrantID: g.ID, Kind: "refresh", Hash: &hash, Scopes: slices.Clone(scopes), CreatedAt: now, ExpiresAt: idle})
		}
		return nil
	})
	if err == nil {
		s.emit(ctx, event)
	}
	// Returning ErrInvalidGrant from inside the transaction would roll back the
	// replay revocation. Commit that state first, then report the protocol error.
	if err == nil && replay {
		err = ErrInvalidGrant
	}
	if err != nil {
		accessID = ""
		newRefresh = ""
		expires = time.Time{}
	}
	return
}

func (s *Service) access(ctx context.Context, id, subject string) (*token, *Connection, *models.User, error) {
	t, err := s.store.Token(ctx, id, false)
	if err != nil {
		return nil, nil, nil, err
	}
	if t == nil || t.Kind != "access" || !s.now().Before(t.ExpiresAt) {
		return nil, nil, nil, ErrInvalidGrant
	}
	g, err := s.store.Grant(ctx, t.GrantID, false)
	if err != nil {
		return nil, nil, nil, err
	}
	if err = s.liveGrant(ctx, s.store, g); err != nil {
		return nil, nil, nil, err
	}
	if g.UserID.String() != subject {
		return nil, nil, nil, ErrInvalidGrant
	}
	u, err := s.liveUser(ctx, g.UserID, g.CredentialStamp, g.TwoFactorStamp)
	return t, g, u, err
}

func (s *Service) revokeToken(ctx context.Context, id, subject, clientID string) error {
	return s.store.Transaction(ctx, func(tx Store) error {
		var t *token
		var err error
		if subject == "" {
			t, err = tx.Refresh(ctx, digest(id), false)
		} else {
			t, err = tx.Token(ctx, id, false)
		}
		if err != nil || t == nil {
			return err
		}
		g, err := tx.Grant(ctx, t.GrantID, true)
		if err != nil {
			return err
		}
		if g == nil || g.ClientID != clientID || (subject != "" && g.UserID.String() != subject) {
			return nil
		}
		now := s.now()
		g.RevokedAt = &now
		return tx.SaveGrant(ctx, g)
	})
}

func isProtocolError(err error) bool {
	return errors.Is(err, ErrInvalidGrant) || errors.Is(err, ErrInvalidClient) || errors.Is(err, ErrValidation) || errors.Is(err, ErrLoginRequired) || errors.Is(err, ErrForbidden)
}
