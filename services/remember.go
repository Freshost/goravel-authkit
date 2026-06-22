package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/freshost/goravel-authkit/models"
	"github.com/freshost/goravel-authkit/repositories"
)

// DefaultRememberLifetime is the fallback validity window for a remember cookie.
const DefaultRememberLifetime = 30 * 24 * time.Hour

const (
	rememberSelectorBytes  = 12 // -> 16 base64url chars
	rememberValidatorBytes = 32 // -> 43 base64url chars
	// rememberGraceWindow is how long the just-superseded validator stays
	// acceptable after a rotation, so concurrent requests carrying it are not
	// mistaken for theft.
	rememberGraceWindow = 60 * time.Second
)

// Remember implements persistent "remember me" login via the selector-validator
// pattern. The cookie value is "selector:validator"; the store keeps the
// selector in clear (indexed) and only a SHA-256 hash of the validator. The
// validator is rotated on every successful use.
type Remember struct {
	repo  repositories.RememberRepository
	ttl   time.Duration
	grace time.Duration
}

// NewRemember builds the remember service. ttl <= 0 falls back to
// DefaultRememberLifetime.
func NewRemember(repo repositories.RememberRepository, ttl time.Duration) *Remember {
	if ttl <= 0 {
		ttl = DefaultRememberLifetime
	}
	return &Remember{repo: repo, ttl: ttl, grace: rememberGraceWindow}
}

// Issue creates a new remember token for the user and returns the cookie value
// ("selector:validator") to set on the response.
func (s *Remember) Issue(ctx context.Context, userID uuid.UUID) (string, error) {
	selector, err := randomToken(rememberSelectorBytes)
	if err != nil {
		return "", errors.Join(ErrInternal, err)
	}
	validator, err := randomToken(rememberValidatorBytes)
	if err != nil {
		return "", errors.Join(ErrInternal, err)
	}

	token := &models.RememberToken{
		ID:            uuid.New(),
		UserID:        userID,
		Selector:      selector,
		ValidatorHash: hashValidator(validator),
		ExpiresAt:     time.Now().Add(s.ttl).UTC(),
	}
	if err := s.repo.Create(ctx, token); err != nil {
		return "", errors.Join(ErrInternal, err)
	}
	return joinToken(selector, validator), nil
}

// Resolve validates a remember cookie value and returns the user id plus, when
// the validator was rotated, a fresh cookie value the caller must set (empty
// means "leave the cookie unchanged"). Behaviour:
//
//   - current validator → rotate via an atomic compare-and-set and return the
//     new cookie value. If a concurrent request rotated first (0 rows updated),
//     authenticate anyway but issue no new cookie (the other response set it).
//   - the just-superseded validator within the grace window → accept (a
//     concurrent request still carrying it), without rotating or revoking.
//   - anything else (unknown/expired/wrong/too-old) → ErrInvalidRememberToken;
//     a known selector with a stale-beyond-grace validator is treated as theft
//     and revokes the user's whole token family.
func (s *Remember) Resolve(ctx context.Context, cookieValue string) (uuid.UUID, string, error) {
	selector, validator, ok := splitToken(cookieValue)
	if !ok {
		return uuid.Nil, "", ErrInvalidRememberToken
	}

	token, err := s.repo.FindBySelector(ctx, selector)
	if err != nil {
		return uuid.Nil, "", errors.Join(ErrInternal, err)
	}
	if token == nil {
		return uuid.Nil, "", ErrInvalidRememberToken
	}
	now := time.Now().UTC()
	if now.After(token.ExpiresAt) {
		_ = s.repo.Delete(ctx, token.ID)
		return uuid.Nil, "", ErrInvalidRememberToken
	}

	presented := hashValidator(validator)

	// Current validator: rotate it (compare-and-set on the old hash).
	if subtle.ConstantTimeCompare([]byte(presented), []byte(token.ValidatorHash)) == 1 {
		newValidator, err := randomToken(rememberValidatorBytes)
		if err != nil {
			return uuid.Nil, "", errors.Join(ErrInternal, err)
		}
		rows, err := s.repo.RotateValidator(ctx, token.ID, token.ValidatorHash,
			hashValidator(newValidator), token.ValidatorHash, now, now.Add(s.ttl))
		if err != nil {
			return uuid.Nil, "", errors.Join(ErrInternal, err)
		}
		if rows == 0 {
			// Lost the race: a concurrent request already rotated. Authenticate
			// but don't overwrite the cookie the winning response set.
			return token.UserID, "", nil
		}
		return token.UserID, joinToken(token.Selector, newValidator), nil
	}

	// Just-superseded validator within the grace window: a concurrent request
	// carrying the previous value. Accept without rotating or revoking.
	if token.PreviousValidatorHash != "" && token.RotatedAt != nil &&
		now.Sub(*token.RotatedAt) <= s.grace &&
		subtle.ConstantTimeCompare([]byte(presented), []byte(token.PreviousValidatorHash)) == 1 {
		return token.UserID, "", nil
	}

	// Neither current nor a recent previous: likely a stolen/stale cookie. Revoke
	// the whole family as a precaution.
	_ = s.repo.DeleteByUser(ctx, token.UserID)
	return uuid.Nil, "", ErrInvalidRememberToken
}

// Revoke deletes the token identified by the cookie value's selector (logout of
// this device). A malformed value or unknown selector is a no-op.
func (s *Remember) Revoke(ctx context.Context, cookieValue string) error {
	selector, _, ok := splitToken(cookieValue)
	if !ok {
		return nil
	}
	token, err := s.repo.FindBySelector(ctx, selector)
	if err != nil {
		return errors.Join(ErrInternal, err)
	}
	if token == nil {
		return nil
	}
	if err := s.repo.Delete(ctx, token.ID); err != nil {
		return errors.Join(ErrInternal, err)
	}
	return nil
}

// RevokeAllForUser deletes every remember token for a user (e.g. on a password
// change, to force re-authentication everywhere).
func (s *Remember) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	if err := s.repo.DeleteByUser(ctx, userID); err != nil {
		return errors.Join(ErrInternal, err)
	}
	return nil
}

// PruneExpired deletes every remember token whose expiry has passed. Intended to
// be run periodically (a scheduled task / the auth:prune-remember-tokens command)
// since abandoned cookies are otherwise only cleaned up lazily on access.
func (s *Remember) PruneExpired(ctx context.Context) error {
	if err := s.repo.DeleteExpired(ctx, time.Now().UTC()); err != nil {
		return errors.Join(ErrInternal, err)
	}
	return nil
}

// TTL is the configured validity window (used by the controller to size the
// cookie's Max-Age).
func (s *Remember) TTL() time.Duration { return s.ttl }

func joinToken(selector, validator string) string {
	return selector + ":" + validator
}

func splitToken(value string) (selector, validator string, ok bool) {
	selector, validator, found := strings.Cut(value, ":")
	if !found || selector == "" || validator == "" {
		return "", "", false
	}
	return selector, validator, true
}

func hashValidator(validator string) string {
	sum := sha256.Sum256([]byte(validator))
	return hex.EncodeToString(sum[:])
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
