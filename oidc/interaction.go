package oidc

import (
	"context"
	"slices"
	"time"

	"github.com/freshost/goravel-authkit/models"
)

type interactionResult struct {
	request *requestSnapshot
	client  *Client
	user    *models.User
	next    string
	csrf    string
}

// interaction applies the same authorization policy to browser and host-owned
// integrations. The HTTP adapter only renders the resulting interaction.
func (s *Service) interaction(ctx context.Context, id string, b Browser, posted bool, decision, csrf string) (*interactionResult, error) {
	a, err := s.store.Request(ctx, id, false)
	if err != nil {
		return nil, err
	}
	if a == nil || b.Binding == "" || a.BindingHash != digest(b.Binding) || a.CodeHash != nil || !s.now().Before(a.ExpiresAt) {
		return nil, ErrValidation
	}
	req, err := snapshot(a)
	if err != nil {
		return nil, err
	}
	result := &interactionResult{request: req}
	if b.Impersonating {
		return result, ErrForbidden
	}
	c, err := s.client(ctx, a.ClientID)
	if err != nil {
		return result, err
	}
	if c.Version != a.ClientVersion {
		return result, ErrInvalidGrant
	}
	result.client = c
	u, err := s.users.FindByID(ctx, b.UserID)
	if err != nil {
		return result, err
	}
	result.user = u
	needsLogin := u == nil || u.IsDisabled() || !u.PasswordChangedAt.Equal(b.CredentialStamp) || b.AuthTime.IsZero() || b.AuthEvent == "" || b.AuthTime.After(s.now().Add(time.Minute))
	if u != nil && u.TwoFactorEnabled() && !slices.Contains(b.AMR, "mfa") {
		needsLogin = true
	}
	if u != nil && b.TwoFactorStamp != twoFactorStamp(u) {
		needsLogin = true
	}
	if a.HintSubject != "" && a.HintSubject != b.UserID.String() {
		needsLogin = true
	}
	if req.original.MaxAge != nil {
		if *req.original.MaxAge == 0 {
			needsLogin = needsLogin || b.AuthEvent == a.InitialEvent
		} else {
			needsLogin = needsLogin || s.now().Sub(b.AuthTime).Seconds() > float64(*req.original.MaxAge)
		}
	}
	if slices.Contains(req.original.Prompt, "select_account") {
		needsLogin = needsLogin || b.AuthEvent == a.InitialEvent
	}
	if needsLogin {
		if slices.Contains(req.original.Prompt, "none") {
			return result, ErrLoginRequired
		}
		result.next = "login"
		return result, nil
	}
	approved := false
	if posted {
		if a.ConsentHash == "" || digest(csrf) != a.ConsentHash || a.ConsentUserID != b.UserID || a.ConsentEvent != b.AuthEvent {
			return nil, ErrForbidden
		}
		if decision == "deny" {
			err = s.store.Transaction(ctx, func(tx Store) error {
				current, err := tx.Request(ctx, id, true)
				if err != nil {
					return err
				}
				if current == nil || current.BindingHash != a.BindingHash || current.CodeHash != nil {
					return ErrInvalidGrant
				}
				current.ExpiresAt = s.now()
				return tx.SaveRequest(ctx, current)
			})
			if err != nil {
				return result, err
			}
			return result, ErrForbidden
		}
		if decision != "approve" {
			return nil, ErrValidation
		}
		approved = true
	} else if !slices.Contains(req.original.Prompt, "consent") {
		approved = c.SkipConsent
		if !approved {
			connections, err := s.Connections(ctx, u.ID)
			if err != nil {
				return result, err
			}
			for _, g := range connections {
				if g.ClientID != c.ID || g.ClientVersion != c.Version || !subset(a.Scopes, g.Scopes) {
					continue
				}
				approved = true
				break
			}
		}
	}
	if !approved {
		if slices.Contains(req.original.Prompt, "none") {
			return result, ErrConsentRequired
		}
		csrf, err := randomValue()
		if err != nil {
			return result, err
		}
		err = s.store.Transaction(ctx, func(tx Store) error {
			current, err := tx.Request(ctx, id, true)
			if err != nil {
				return err
			}
			if current == nil || current.CodeHash != nil || current.BindingHash != a.BindingHash || !s.now().Before(current.ExpiresAt) {
				return ErrInvalidGrant
			}
			current.ConsentUserID = b.UserID
			current.ConsentEvent = b.AuthEvent
			current.ConsentHash = digest(csrf)
			return tx.SaveRequest(ctx, current)
		})
		if err != nil {
			return result, err
		}
		result.next = "consent"
		result.csrf = csrf
		return result, nil
	}
	err = s.store.Transaction(ctx, func(tx Store) error {
		locked, err := tx.Request(ctx, id, true)
		if err != nil {
			return err
		}
		if locked == nil || locked.CodeHash != nil || locked.BindingHash != digest(b.Binding) || !s.now().Before(locked.ExpiresAt) {
			return ErrInvalidGrant
		}
		if posted && (locked.ConsentHash != digest(csrf) || locked.ConsentUserID != b.UserID || locked.ConsentEvent != b.AuthEvent) {
			return ErrForbidden
		}
		current, err := tx.Client(ctx, a.ClientID, false)
		if err != nil {
			return err
		}
		if current == nil || current.Disabled || current.Version != a.ClientVersion {
			return ErrInvalidGrant
		}
		if _, err = s.liveUser(ctx, u.ID, b.CredentialStamp, twoFactorStamp(u)); err != nil {
			return err
		}
		locked.Approved = true
		locked.UserID = u.ID
		locked.CredentialStamp = b.CredentialStamp
		locked.TwoFactorStamp = twoFactorStamp(u)
		locked.AuthTime = b.AuthTime
		locked.AMR = slices.Clone(b.AMR)
		if err = tx.SaveRequest(ctx, locked); err != nil {
			return err
		}
		result.request.row = locked
		return nil
	})
	result.next = "authorized"
	return result, err
}
